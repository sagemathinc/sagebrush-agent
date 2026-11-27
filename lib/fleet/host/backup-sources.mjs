// Host backup (design: agent-autonomous-host-backup.md r3.3 §3, §6): what a run reads, and what it reports about it.
//
// - **Sources are an allowlist** built per run from the registry, exactly §3's left column:
//   - a live agent (any state but deleted): its home, its sessions and its config tree;
//   - a deleted agent: its archive and its config archive;
//   - a tag: its shared folder, with the tag's member agents (frozen together with it).
//   Nothing else is ever a source: not var-tmp, not profiles, not keys, not the host store (copied separately, under
//   its own lock, into a staging directory that becomes its own source).
// - **Forbidden roots (T4):** every login-profile root and profile storage path, host-secrets and secrets. If any is at
//   or beneath a source, or a source is at or beneath one, the run is refused. Checked on the paths as given AND as
//   resolved (symlinks), so a link can't smuggle one in.
// - **One bounded walk per source set** (lstat only, never following a link, never crossing a filesystem):
//   - **unrestorable entries (T3):** an entry whose owner isn't one the set allows (the agent's uid; for a tag, any
//     member's uid) is counted and the first few are listed, to be shown to the person;
//   - **the change fingerprint (§6, change-aware):** entry count, total size, the newest mtime and the newest ctime.
//     Any write changes a ctime, which a process can't set back, so an equal fingerprint means "no change since".
//   - entries on another filesystem (a mount below a source) aren't read, and are reported.

import * as fs from "node:fs";
import { join } from "node:path";
import { isId, refuse } from "../bytes.mjs";
import { agentArchive, agentConfigArchive, agentConfigDir, agentHome, agentSessions, tagDir } from "./names.mjs";
import { profileForbiddenRoots } from "./profile-life.mjs";

/**
 * The roots no source may contain or sit in, whatever the harness registry adds (backupSources' `forbidden`): the
 * profiles root as profile-life.mjs names it (every harness sign-in lives beneath it, so none is ever backed up), then
 * the host's secrets, the backup's own state and the broker's.
 */
export const FIXED_FORBIDDEN = Object.freeze([
  ...profileForbiddenRoots(), "/var/lib/sagebrush/host-secrets", "/var/lib/sagebrush/secrets",
  "/var/lib/sagebrush/backup", "/var/lib/sagebrush-broker",
]);
/** A walk stops (and the set is refused) past this many entries: the same bound as the restore's fill. */
export const MAX_ENTRIES = 2_000_000;
/** How many unrestorable paths are listed (all are counted). */
export const LIST_MAX = 20;

const absNorm = (p) => typeof p === "string" && p.startsWith("/") && p.length > 1 && !p.endsWith("/") && !p.includes("\0")
  && !p.split("/").slice(1).some((s) => s === "" || s === "." || s === "..");
/** Is `a` at or beneath `b` (both normalized absolute paths)? */
export const within = (a, b) => a === b || a.startsWith(b + "/");

/**
 * The source sets of one run, from the registry's closed shape (registry.mjs). Each set is
 * { kind: "agent" | "archive" | "tag", id, sources, uids, members }:
 * - "agent": a live agent; uids [its uid]; members [its id];
 * - "archive": a deleted agent's archive; uids [its uid]; members [];
 * - "tag": a tag's folder; uids every live member's uid; members the live members (frozen together).
 * Sorted by kind, then id, so runs are reproducible.
 */
export function backupSources(registry) {
  if (registry === null || typeof registry !== "object" || typeof registry.agents !== "object" || typeof registry.tags !== "object") {
    refuse("bad_form", "backup sources: not a registry");
  }
  const sets = [];
  const live = Object.entries(registry.agents).filter(([, a]) => a.state !== "deleted");
  for (const [id, a] of Object.entries(registry.agents)) {
    if (!isId(id)) refuse("bad_form", "backup sources: bad agent id");
    if (a.state === "deleted") sets.push({ kind: "archive", id, sources: [agentArchive(id), agentConfigArchive(id)], uids: [a.uid], members: [] });
    else sets.push({ kind: "agent", id, sources: [agentHome(id), agentSessions(id), agentConfigDir(id)], uids: [a.uid], members: [id] });
  }
  for (const tag of Object.keys(registry.tags)) {
    if (!isId(tag)) refuse("bad_form", "backup sources: bad tag id");
    const members = live.filter(([, a]) => a.tags.includes(tag)).map(([id]) => id).sort();
    const uids = members.map((m) => registry.agents[m].uid);
    sets.push({ kind: "tag", id: tag, sources: [tagDir(tag)], uids, members });
  }
  const order = { agent: 0, archive: 1, tag: 2 };
  return sets.sort((x, y) => order[x.kind] - order[y.kind] || (x.id < y.id ? -1 : x.id > y.id ? 1 : 0));
}

/**
 * Refuse (not_granted) if any forbidden root is at or beneath a source, or a source at or beneath a forbidden root,
 * on the paths as given and as resolved by `real` (realpath; a path that doesn't exist resolves to itself).
 * `forbidden`: FIXED_FORBIDDEN plus every login-profile root of every harness in the pinned harness registry and
 * every profile record's storage path (the caller's).
 */
export function checkForbidden(sources, forbidden, { real = realOrSelf } = {}) {
  for (const p of [...sources, ...forbidden]) if (!absNorm(p)) refuse("bad_form", "backup sources: paths must be normalized and absolute");
  const pairs = (xs) => xs.flatMap((x) => [x, real(x)]);
  const src = pairs(sources), bad = pairs(forbidden);
  for (const s of src) for (const f of bad) {
    if (within(f, s) || within(s, f)) refuse("not_granted", "backup sources: a source contains or sits in a forbidden path (logins and secrets are never backed up)");
  }
}

/**
 * A path as resolved: the deepest ancestor that exists, through its symlinks (realpath), with the rest of the path
 * (which doesn't exist yet) appended as written. So a link anywhere above a missing tail is still followed. Any
 * error but ENOENT throws: unknown is never "not forbidden".
 */
export function realOrSelf(p, { realpath = (x) => fs.realpathSync(x) } = {}) {
  const parts = p.split("/").slice(1);
  for (let n = parts.length; n >= 0; n -= 1) {
    const head = "/" + parts.slice(0, n).join("/");
    let real;
    try { real = realpath(head); } catch (e) { if (e?.code === "ENOENT" || e?.code === "ENOTDIR") continue; throw e; }
    const tail = parts.slice(n);
    return tail.length === 0 ? real : (real === "/" ? "" : real) + "/" + tail.join("/");
  }
  return p;
}

/**
 * Walk one source set (lstat only; no link followed; no other filesystem entered). Returns
 * { fingerprint: { entries, bytes, mtime_ns, ctime_ns }, unrestorable: { count, paths }, other_fs: [paths], missing: [sources] }.
 * Refuses (limit) past maxEntries. A source that doesn't exist is reported in `missing` (an agent's sessions may
 * not exist yet), never an error. Times are BigInt nanoseconds, given as decimal strings.
 */
export function walkSources(set, { fsx = fs, maxEntries = MAX_ENTRIES, listMax = LIST_MAX } = {}) {
  const allowed = new Set(set.uids);
  let entries = 0, bytes = 0n, mtime = 0n, ctime = 0n, count = 0;
  const paths = [], otherFs = [], missing = [];
  const visit = (p, st) => {
    entries += 1;
    if (entries > maxEntries) refuse("limit", "backup sources: more entries than a run takes");
    if (st.isFile()) bytes += st.size;
    if (st.mtimeNs > mtime) mtime = st.mtimeNs;
    if (st.ctimeNs > ctime) ctime = st.ctimeNs;
    if (!allowed.has(Number(st.uid))) { count += 1; if (paths.length < listMax) paths.push(p); }
  };
  for (const top of set.sources) {
    let st;
    try { st = fsx.lstatSync(top, { bigint: true }); } catch (e) { if (e?.code === "ENOENT") { missing.push(top); continue; } throw e; }
    const dev = st.dev;
    const walk = (p, s) => {
      visit(p, s);
      if (!s.isDirectory()) return;
      for (const name of fsx.readdirSync(p).sort()) {
        const child = join(p, name);
        const cs = fsx.lstatSync(child, { bigint: true });
        if (cs.dev !== dev) { otherFs.push(child); continue; }
        walk(child, cs);
      }
    };
    walk(top, st);
  }
  return {
    fingerprint: { entries, bytes: String(bytes), mtime_ns: String(mtime), ctime_ns: String(ctime) },
    unrestorable: { count, paths },
    other_fs: otherFs,
    missing,
  };
}

/** Change-aware (§6): a set is skipped only when its fingerprint equals the one of its last good snapshot. */
export function unchanged(fingerprint, last) {
  return last !== null && last !== undefined && ["entries", "bytes", "mtime_ns", "ctime_ns"].every((k) => fingerprint[k] === last[k]);
}

/** Exclude globs for a set (the agent config's backup.exclude, when the config carries it): closed and bounded. */
export function checkExcludes(globs) {
  if (!Array.isArray(globs) || globs.length > 256 || !globs.every((g) => typeof g === "string" && g.length > 0 && g.length <= 256 && !/[\0\n,]/.test(g))) {
    refuse("bad_form", "backup sources: excludes are at most 256 globs, each one line without commas");
  }
  return globs;
}
