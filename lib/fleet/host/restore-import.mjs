// Host backup (design: agent-autonomous-host-backup.md r3.3 §5 step 5, §3): bringing a restored host store's copy
// into a FRESH host, registry first. This is a part of a restore, not all of it: only the registry is imported.
//
// The input is the host store's snapshot, already restored into a root-only directory (`copy`), and the restore's
// plan with the manifest it binds. Per entry of the copy (backup-hoststore.mjs's HOSTSTORE_INCLUDE):
// - **registry: imported,** through its own typed importer (Registry.importRestored), only onto a registry that has
//   never recorded anything, and only if the copy is exactly the registry the manifest binds (its canonical sha256 is
//   the manifest's registry hash). uids, gids, tombstones, states and life are kept; start failures are cleared; a
//   live agent's grant generation is reset to 0 (no grant on this host yet; a revoked or deleted one keeps its own).
//   Fences aren't in a backup, but run states are: an agent `running` behind the old host's `all` fence would start
//   on the new host's first grant. So, once a read-only preflight has shown this registry fresh (or already exactly
//   this import), and BEFORE the registry is written:
//   - every live agent's `restore` fence is raised (durably, under the fence lock): no restored agent starts until
//     the person's resume of its validated restore lowers it;
//   - every deleted agent gets a fresh done deprovision record (DeprovisionRecords.restoredDone): recovery never runs
//     a deprovision pass on the new host, where nothing of the agent exists but its restored archive.
// - **grant: provenance only.** Its bytes go read-only to <RESTORE_DIR>/provenance/grant/, to show what the old host
//   ran under. It is never attached as the grant state: a restored host waits for a fresh grant from the service.
// - **audit: history.** The old stream goes read-only, as plain bytes, to <root>/audit/restored-<host>-<date>/
//   (the manifest's host and day); the new host's stream is its own.
// - **state** (the grant's application state): never imported, by rule: a restored host waits for a fresh grant.
// - **config** (the host's own configuration, the installer's output): never imported: it is per host.
// - **harness-sessions, harness-turns: kept in the backup, not restored (no importer)** until the advisor's
//   implementation brings their typed importers (in-flight turns ended (restored); session records re-validated,
//   profile bindings cleared). Until then the report lists them and nothing of them reaches the host.
// Anything else in the copy refuses: the backup copies only the allowlist.
// Read-only copies refuse links and anything but regular files and directories, are written whole into a temporary
// directory and renamed into place; a copy already in place must be identical (a retry), or it refuses.

import * as fs from "node:fs";
import { dirname, join } from "node:path";
import { refuse } from "../bytes.mjs";
import { FENCE_DIR, RESTORE_DIR } from "./names.mjs";
import { raiseFence, withFenceLock } from "./fence.mjs";
import { HOSTSTORE_INCLUDE } from "./backup-hoststore.mjs";
import { canonical, sha256 } from "./backup-manifest.mjs";
import { checkRegistry } from "./registry.mjs";
import { checkPlan } from "./restore-plan.mjs";
import { realIo } from "./store.mjs";

/** The report's words for an entry that isn't restored, by why. */
export const NOT_RESTORED = "kept in the backup, not restored (no importer)";
export const BY_RULE = "not restored (by rule: a restored host waits for a fresh grant)";
export const PER_HOST = "not restored (per host)";
/** What happens to each host-store entry of a restored copy. */
export const DISPOSITION = Object.freeze({
  registry: "restored", grant: "provenance", audit: "archived",
  state: BY_RULE, "harness-sessions": NOT_RESTORED, "harness-turns": NOT_RESTORED, config: PER_HOST,
});
const HOST = /^[A-Za-z0-9-]{1,64}$/;
const MAX_FILES = 200_000;

/** Every regular file and directory under `dir` (relative paths, sorted), refusing links and anything else. */
function walk(dir, fsx = fs) {
  const out = [];
  const go = (rel) => {
    const st = fsx.lstatSync(rel ? join(dir, rel) : dir);
    if (st.isDirectory()) {
      if (rel) out.push({ rel, dir: true });
      for (const name of fsx.readdirSync(rel ? join(dir, rel) : dir).sort()) go(rel ? join(rel, name) : name);
    } else if (st.isFile()) out.push({ rel, dir: false, size: st.size });
    else refuse("bad_form", "restore import: only regular files and directories");
    if (out.length > MAX_FILES) refuse("limit", "restore import: larger than an import takes");
  };
  go("");
  return out;
}

/** Are two trees the same: the same entries, types and bytes? */
function sameTree(a, b) {
  const x = walk(a), y = walk(b);
  if (x.length !== y.length) return false;
  return x.every((e, i) => e.rel === y[i].rel && e.dir === y[i].dir
    && (e.dir || fs.readFileSync(join(a, e.rel)).equals(fs.readFileSync(join(b, e.rel)))));
}

/** Remove a tree this module wrote (it may be read-only), never following a link. */
function removeOurs(p) {
  let st;
  try { st = fs.lstatSync(p); } catch (e) { if (e?.code === "ENOENT") return; throw e; }
  if (st.isDirectory()) {
    fs.chmodSync(p, 0o700);
    for (const name of fs.readdirSync(p)) removeOurs(join(p, name));
    fs.rmdirSync(p);
  } else fs.unlinkSync(p);
}

const fsyncPath = (p, io) => { const fd = io.open(p, "r"); try { io.fsync(fd); } finally { io.close(fd); } };

/** Write all of `buf` to `fd`: a short write continues, a zero or impossible count is an error (never a short file). */
function writeAll(fd, buf, io) {
  for (let off = 0; off < buf.length;) {
    const n = io.write(fd, buf, off, buf.length - off);
    if (!Number.isSafeInteger(n) || n <= 0 || n > buf.length - off) throw Object.assign(new Error("short write"), { code: "EIO" });
    off += n;
  }
}

/** Is every entry of a copy in place read-only: files 0400, directories (its top included) 0500? */
function readOnly(dst, entries) {
  return (fs.lstatSync(dst).mode & 0o7777) === 0o500
    && entries.every((e) => (fs.lstatSync(join(dst, e.rel)).mode & 0o7777) === (e.dir ? 0o500 : 0o400));
}

/** Flush a copy in place: every file and directory, deepest first, then the copy's top and its parent. */
function flush(dst, entries, io) {
  for (const e of [...entries].reverse()) fsyncPath(join(dst, e.rel), io);
  fsyncPath(dst, io);
  fsyncPath(dirname(dst), io);
}

/**
 * Copy the tree `src` to `dst`, read-only (files 0400, directories 0500), whole or not at all: into `dst`.partial
 * (a leftover of an interrupted copy is removed first), each file written whole, made read-only deepest first, every
 * file and directory fsynced, renamed into place, then its parent fsynced. If `dst` already exists (a retry) it must be the same tree,
 * byte for byte, AND read-only exactly so (else refused, not_granted); it is then flushed again, every file and
 * directory and its parent, before it counts: an earlier attempt may have failed after the rename, before its flush.
 * `io`: the filesystem steps (store.mjs's realIo), replaced by tests to inject failures.
 */
export function copyReadOnly(src, dst, { io = realIo } = {}) {
  const entries = walk(src);
  try { fs.lstatSync(dst); } catch (e) {
    if (e?.code !== "ENOENT") throw e;
    const tmp = `${dst}.partial`;
    fs.mkdirSync(dirname(dst), { recursive: true, mode: 0o700 });
    removeOurs(tmp);
    fs.mkdirSync(tmp, { mode: 0o700 });
    for (const e of entries) {
      if (e.dir) { fs.mkdirSync(join(tmp, e.rel), { mode: 0o700 }); continue; }
      const fd = io.open(join(tmp, e.rel), "wx", 0o600);
      try { writeAll(fd, fs.readFileSync(join(src, e.rel)), io); } finally { io.close(fd); }
    }
    for (const e of [...entries].reverse()) fs.chmodSync(join(tmp, e.rel), e.dir ? 0o500 : 0o400);
    fs.chmodSync(tmp, 0o500);
    flush(tmp, entries, io);
    io.rename(tmp, dst);
    fsyncPath(dirname(dst), io);
    return "copied";
  }
  if (!sameTree(src, dst) || !readOnly(dst, entries)) refuse("not_granted", "restore import: a different copy is already in place");
  flush(dst, entries, io);
  return "present";
}

/**
 * Import the host store's restored copy (`copy`) into the fresh host (`guard()`, the caller's lock check, runs before
 * every effect and refuses to stop it: no effect follows a lost lock): `store` the open HostStore, `root` its root
 * directory, `plan` the restore plan, `manifest` the plan's manifest (bound by its sha256), `restoreDir` the restore's
 * state directory, `fenceDir` the fence directory. Registry first (after its agents' fences and records): if it can't
 * be imported, nothing else is done. Resolves to the report:
 * { entries: { <name>: disposition } } for every entry present in the copy.
 */
export async function importHostStore({ copy, store, root, plan, manifest, restoreDir = RESTORE_DIR, fenceDir = FENCE_DIR, guard = () => {} }) {
  checkPlan(plan);
  if (sha256(canonical(manifest) + "\n") !== plan.sha256) refuse("not_granted", "restore import: not the plan's manifest");
  if (!HOST.test(manifest.host) || typeof manifest.time !== "string" || Number.isNaN(Date.parse(manifest.time))) refuse("bad_form", "restore import: bad manifest");
  const present = fs.readdirSync(copy).sort();
  for (const name of present) if (!HOSTSTORE_INCLUDE.includes(name)) refuse("bad_form", "restore import: an entry the backup never copies");
  if (!present.includes("registry")) refuse("not_found", "restore import: the copy has no registry");

  // The registry: exactly the manifest's, through its typed importer, onto an empty registry.
  let text;
  try { text = fs.readFileSync(join(copy, "registry", "registry.json"), "utf8"); } catch { refuse("not_found", "restore import: the copy has no registry file"); }
  let reg;
  try { reg = JSON.parse(text); } catch { refuse("bad_form", "restore import: the registry isn't JSON"); }
  checkRegistry(reg);
  if (sha256(canonical(reg)) !== manifest.registry.hash) refuse("not_granted", "restore import: the registry isn't the one the manifest binds");
  // Read only, before any effect: this registry must be fresh, or already exactly this import (a retry). A restore that
  // can't be imported here fences nothing and writes no record. importRestored checks again at its write.
  store.registry.importPreflight(reg);
  guard();
  // Before the registry exists on this host: fence every live agent, and close every deleted agent's deprovision.
  const live = Object.keys(reg.agents).filter((id) => reg.agents[id].state !== "deleted").sort();
  const dead = Object.keys(reg.agents).filter((id) => reg.agents[id].state === "deleted").sort();
  await withFenceLock(() => { for (const id of live) { guard(); raiseFence("restore", id, { dir: fenceDir }); } }, { dir: fenceDir });
  for (const id of dead) { guard(); store.deprovision.restoredDone(id, reg.agents[id]); }
  guard();
  store.registry.importRestored(reg);

  const entries = { registry: DISPOSITION.registry };
  if (present.includes("grant")) { guard(); copyReadOnly(join(copy, "grant"), join(restoreDir, "provenance", "grant")); entries.grant = DISPOSITION.grant; }
  if (present.includes("audit")) {
    guard();
    copyReadOnly(join(copy, "audit"), join(root, "audit", `restored-${manifest.host}-${new Date(manifest.time).toISOString().slice(0, 10)}`));
    entries.audit = DISPOSITION.audit;
  }
  for (const name of present) if (!Object.hasOwn(entries, name)) entries[name] = DISPOSITION[name];
  return { entries };
}
