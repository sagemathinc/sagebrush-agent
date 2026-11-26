// Host restore, end to end (design: agent-autonomous-host-restore-e2e.md r1.7 §1, §2, §5): the exclusion with backup,
// the person's `begin` with its continuation after a crash, and `close`. Pure of the CLI: every outside effect is a
// dependency, so each branch is tested against fakes and real temporary directories.
//
// - **The exclusion (§1):** BACKUP_RESTORE_LOCK, a root 0600 regular file in a root-only directory, flock(2) EXCLUSIVE,
//   OUTERMOST in every lock order that includes it (this lock, then the restore lock or the backup run lock, then the
//   host-store lock, then the fence lock). Every holder only TRIES it; a loser has read and written nothing.
// - **An open restore (§1):** `begin.json` exists AND (there is no plan, OR the plan isn't closed). A `begin.json` or a
//   plan that can't be read or isn't well formed counts as open. A backup run and `host backup init` refuse while one is.
// - **begin (§2):** its first durable write is `begin.json` = {v, snapshot, manifest_sha256, run, state: "begun"}: the
//   restore's immutable binding. Then, each durable before the next: the plan (createPlan; the same bytes again are a
//   retry), the host store's snapshot restored into a fresh copy and imported (importHostStore: fences first, the
//   registry last; "already exactly this import" is a retry), one request per set (created only if missing, never
//   replaced), and `begin.json` rewritten with state "done". A continuation after a crash is accepted only for the SAME
//   snapshot with the supervisor stopped; a missing plan is rebuilt with the RECORDED run from a manifest whose text
//   hashes to the recorded sha256, so it is byte-identical. "done" refuses any further begin.
// - **close (§5):** every set terminal-for-close (an agent validated AND resumed, i.e. its restore fence gone, or
//   abandoned; an archive or a tag folder validated or abandoned; a set with an abandon intent whose record isn't
//   abandoned yet is not). Its ONE commit point is the plan's `closed`. Then, idempotently, the plan, `begin.json`,
//   every record, fill report and abandon intent are copied read-only to closed/<run>/, and the requests and the host
//   store's copy are removed. A crash after the commit is finished by closing again; before it, the restore stays open.
// - **Paths:** every directory this module creates, writes into or removes under the restore directory is first proven a
//   real directory (never a link) owned by the owner and writable by no one else, component by component from the
//   restore directory down; nothing is created or removed recursively through an unproven path. A tree is removed
//   entry by entry with lstat, so a link inside it is unlinked, never followed. Only the owner can write a proven
//   directory, so nothing can swap a component between the proof and its use.
// - **The locks:** the exclusion and the restore lock are each held by a flock child that can die on its own. Before
//   and after every await and before every durable effect, both must still be held; the first time either isn't,
//   the operation stops with outcome_unknown and does nothing more.

import * as fs from "node:fs";
import { join } from "node:path";
import { refuse } from "../bytes.mjs";
import { BACKUP_RESTORE_LOCK, FENCE_DIR, RESTORE_DIR } from "./names.mjs";
import { ABANDON_DIR, CLASSES, RESTORE_RUN, fillReportName, readRecord, readRegular } from "./restore-record.mjs";
import { attestationName, auditPair } from "./restore-sidecars.mjs";
import { PLAN, checkPlan, closePlan, createPlan, newPlan, readPlan, withRestoreLock } from "./restore-plan.mjs";
import { exactKeys, lockFile, realIo, writeDurable, writeExclusive } from "./store.mjs";

export const BEGIN = "begin.json";
export const REQUESTS = "requests";
export const ABANDON = ABANDON_DIR;
export const CLOSED = "closed";
/** How long a holder tries the exclusion (restore e2e §1: a 5 s try, then it gives up). */
export const EXCLUSION_TRY_MS = 5000;
const HEX64 = /^[0-9a-f]{64}$/;
const KEY = /^(agent|archive|tag)-([a-z2-7]{25}[aeimquy4])$/;
const MAX_BEGIN = 4096;

/** `begin.json`'s closed shape. Returns it, or refuses (bad_form). */
export function checkBegin(b) {
  const ok = exactKeys(b, ["v", "snapshot", "manifest_sha256", "run", "state"]) && b.v === 1
    && typeof b.snapshot === "string" && HEX64.test(b.snapshot) && typeof b.manifest_sha256 === "string" && HEX64.test(b.manifest_sha256)
    && typeof b.run === "string" && RESTORE_RUN.test(b.run) && ["begun", "done"].includes(b.state);
  if (!ok) refuse("bad_form", "restore begin: not a valid begin record");
  return b;
}

/** `begin.json`: null when there is none; anything present but unreadable or invalid throws. */
export function readBegin({ dir = RESTORE_DIR, fsx = fs } = {}) {
  const bytes = readRegular(join(dir, BEGIN), MAX_BEGIN, "the begin record", fsx, { tries: 3 });
  if (bytes === null) return null;
  let b;
  try { b = JSON.parse(bytes.toString("utf8")); } catch { refuse("bad_form", "restore begin: not JSON"); }
  return checkBegin(b);
}

/**
 * Is a restore OPEN (§1)? `begin.json` exists AND (no plan, OR the plan isn't closed). A `begin.json` or a plan that
 * can't be read or isn't well formed counts as open; only a closed plan, or no `begin.json` at all, is not.
 */
export function restoreOpen({ dir = RESTORE_DIR, fsx = fs } = {}) {
  let b;
  try { b = readBegin({ dir, fsx }); } catch { return true; }
  if (b === null) return false;
  let p;
  try { p = readPlan({ dir, fsx }); } catch { return true; }
  return p === null || !Object.hasOwn(p, "closed");
}

/**
 * Run `fn` holding the exclusion (§1), tried for at most `waitMs`. The lock file must be a regular file owned by
 * `uid` with no group or other access (created 0600 when missing), in a directory owned by `uid` that only it can
 * write; anything else refuses (not_granted) before the lock is tried. A held lock refuses `in_progress` (busy).
 */
export async function withExclusion(fn, { path = BACKUP_RESTORE_LOCK, waitMs = EXCLUSION_TRY_MS, lock = lockFile, uid = 0, fsx = fs } = {}) {
  const dir = path.slice(0, path.lastIndexOf("/")) || "/";
  const d = fsx.lstatSync(dir);
  if (!d.isDirectory() || d.uid !== uid || (d.mode & 0o022) !== 0) refuse("not_granted", "restore exclusion: the lock's directory isn't private");
  let st = null;
  try { st = fsx.lstatSync(path); } catch (e) { if (e?.code !== "ENOENT") throw e; }
  if (st === null) {
    try { fsx.closeSync(fsx.openSync(path, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600)); } catch (e) { if (e?.code !== "EEXIST") throw e; }
    st = fsx.lstatSync(path);
  }
  if (!st.isFile() || st.uid !== uid || (st.mode & 0o077) !== 0) refuse("not_granted", "restore exclusion: the lock file isn't a private regular file");
  const held = await lock(path, { waitMs });
  try { return await fn(held); } finally { await held.release(); }
}

/**
 * Prove `path` (at or beneath the trusted `root`) a real directory, component by component from `root` down: each
 * lstat'd (never followed), a directory, owned by `uid`, with no group or other write. A missing component is created
 * (mode 0700, one level, never recursively) when `create`, then proven like the others. Returns the path, or refuses
 * (not_granted) at the first component that isn't one.
 */
export function provenDir(root, rel, { uid = 0, create = false, fsx = fs } = {}) {
  const check = (p) => {
    let st;
    try { st = fsx.lstatSync(p); } catch (e) {
      if (e?.code !== "ENOENT" || !create) throw e;
      fsx.mkdirSync(p, { mode: 0o700 });
      st = fsx.lstatSync(p);
    }
    if (!st.isDirectory() || st.uid !== uid || (st.mode & 0o022) !== 0) refuse("not_granted", `restore: ${p} isn't a private directory`);
  };
  check(root);
  let p = root;
  for (const part of rel.split("/").filter((x) => x !== "")) {
    if (part === "." || part === "..") refuse("bad_form", "restore: a path component may not be . or ..");
    p = join(p, part);
    check(p);
  }
  return p;
}

/**
 * Remove `name` beneath the PROVEN directory `parent`, link-safely and by handle, all the way down (as openat would):
 * - each directory level is opened O_DIRECTORY|O_NOFOLLOW, its handle fstat'd and required to be the very object
 *   lstat saw (device and inode); then, through that HANDLE, it is made `uid`'s and private (fchown, fchmod 0700), so
 *   from then on nobody else can add, rename or replace an entry in it; only then are its entries read and removed,
 *   through /proc/self/fd/<handle>, which names the opened directory itself, never the path again;
 * - a link or any other non-directory is unlinked itself (never followed);
 * - a directory entry replaced between its lstat and its open (by a link, or another object) is refused (not_granted),
 *   and nothing outside is touched.
 * Missing is fine. `onEntry(dirPath, name)`: a test seam between an entry's lstat and its use.
 */
export function removeBeneath(parent, name, { fsx = fs, uid = process.getuid?.() ?? 0, onEntry = () => {} } = {}) {
  if (name === "" || name.includes("/") || name === "." || name === "..") refuse("bad_form", "restore: bad entry name");
  const pfd = fsx.openSync(parent, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
  try { removeAt(pfd, name, { fsx, uid, onEntry }); } finally { fsx.closeSync(pfd); }
}

function removeAt(dfd, name, o) {
  const { fsx, uid, onEntry } = o;
  const here = `/proc/self/fd/${dfd}`;
  const p = join(here, name);
  let st;
  try { st = fsx.lstatSync(p); } catch (e) { if (e?.code === "ENOENT") return; throw e; }
  onEntry(here, name);
  if (!st.isDirectory()) { fsx.unlinkSync(p); return; }
  let fd;
  try { fd = fsx.openSync(p, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW); } catch (e) {
    if (["ELOOP", "ENOTDIR", "ENOENT"].includes(e?.code)) refuse("not_granted", "restore: a directory was replaced while it was removed");
    throw e;
  }
  try {
    const f = fsx.fstatSync(fd);
    if (!f.isDirectory() || f.dev !== st.dev || f.ino !== st.ino) refuse("not_granted", "restore: a directory was replaced while it was removed");
    // Through the handle: this level is ours and private before any entry of it is read.
    if (f.uid !== uid) fsx.fchownSync(fd, uid, f.gid);
    fsx.fchmodSync(fd, 0o700); // no group or other access: the group can't matter
    for (const e of fsx.readdirSync(`/proc/self/fd/${fd}`)) removeAt(fd, e, o);
  } finally { fsx.closeSync(fd); }
  // The name, in the parent's handle: rmdir never follows it; a non-directory swapped in there fails, never followed.
  fsx.rmdirSync(p);
}

/** A restore-owned directory that may be absent: null when it is, else proven like provenDir. */
function optionalDir(root, name, uid) {
  try { fs.lstatSync(join(root, name)); } catch (e) { if (e?.code === "ENOENT") return null; throw e; }
  return provenDir(root, name, { uid });
}

/** The two locks' guard: refuses outcome_unknown once either isn't held. */
const guardOf = (...locks) => () => {
  for (const l of locks) if (!l || typeof l.held !== "function" || !l.held()) refuse("outcome_unknown", "restore: a lock was lost; nothing more is done");
};

/** A set's request file: requests/<kind>-<id>, exactly {"run": <run>}. */
export const requestText = (run) => JSON.stringify({ run }) + "\n";
export const parseKey = (k) => { const m = KEY.exec(k); if (!m) refuse("bad_form", "restore: bad set key"); return { kind: m[1], id: m[2] }; };

/** Create a set's request if missing; an existing one must be exactly this run's (never replaced). */
/**
 * The person's new request for a set (`host restore retry`, R6-d1 §2): its request REPLACED by `run`'s, durably. Only
 * under the restore lock, after the plan was re-planned to `run` (begin's own requests are created once, never replaced).
 */
export function replaceRequest(key, run, { dir = RESTORE_DIR, io = realIo, uid = 0 } = {}) {
  parseKey(key);
  const rdir = provenDir(dir, REQUESTS, { uid, create: true });
  writeDurable(rdir, key, requestText(run), io);
}

export function writeRequest(key, run, { dir = RESTORE_DIR, io = realIo, uid = 0 } = {}) {
  parseKey(key);
  const rdir = provenDir(dir, REQUESTS, { uid, create: true });
  try { writeExclusive(rdir, key, requestText(run), io); } catch (e) {
    if (e?.code === "EEXIST") refuse("not_granted", "restore begin: a set's request is another run's");
    throw e;
  }
}

/**
 * The person's `host restore begin <snapshot>` (§2), run under the exclusion, then the restore lock. `deps`:
 * - supervisorStopped(): true only while the supervisor's unit is inactive and the host-store lock is free;
 * - registryFresh(): true only for a registry that has never recorded anything (a new begin);
 * - backupEnabled(): whether `backup/enabled` exists;
 * - choose(snapshot): chooseManifest's result for a fresh listing ({ manifest, snapshot, sha256 }), or { error };
 * - newRun(): a new restore run;
 * - stageHostStore(chosen, { run, guard }): the manifest's host-store snapshot staged by the launcher (A2 r3.14 r2,
 *   restore-hoststage.mjs), resolving to the staged copy's path, read in place; after a crash it is the same marked
 *   attempt again;
 * - importHostStore({ copy, plan, manifest }): restore-import's importHostStore with the open store bound.
 * Resolves to { run, sets } once `begin.json` says done.
 */
export async function begin(snapshot, deps, { dir = RESTORE_DIR, io = realIo, exclusion = {}, uid = exclusion.uid ?? 0, onStep = () => {} } = {}) {
  if (typeof snapshot !== "string" || !HEX64.test(snapshot)) refuse("bad_form", "restore begin: bad snapshot");
  return withExclusion((ex) => {
    // The restore directory itself, proven (created when missing, one level) BEFORE the restore lock is taken in it.
    provenDir(dir, "", { uid, create: true });
    return withRestoreLock(async (rl) => {
    const guard = guardOf(ex, rl);
    // A step boundary: the test seam first, then the locks proven before anything more is done.
    const at = async (name) => { guard(); await onStep(name); guard(); };
    await at("begin:locked");
    if (deps.supervisorStopped() !== true) refuse("in_progress", "restore begin: the supervisor is running; stop it first");
    let b = readBegin({ dir });
    let chosen;
    if (b === null) {
      // A new begin: nothing of a restore here, a fresh registry, no backup set up.
      if (readPlan({ dir }) !== null) refuse("in_progress", "restore begin: a restore plan is already here");
      if (deps.registryFresh() !== true) refuse("not_granted", "restore begin: this host's registry isn't fresh");
      if (deps.backupEnabled() !== false) refuse("in_progress", "restore begin: backup is enabled on this host");
      chosen = await deps.choose(snapshot);
      guard();
      if (!chosen || chosen.error) refuse("not_granted", `restore begin: the manifest can't be used (${chosen?.error ?? "none"})`);
      b = checkBegin({ v: 1, snapshot, manifest_sha256: chosen.sha256, run: deps.newRun(), state: "begun" });
      writeExclusive(dir, BEGIN, JSON.stringify(b) + "\n", io);
      await at("begin:bound");
    } else {
      if (b.state === "done") refuse("in_progress", "restore begin: this host's restore has begun; use status, retry or close");
      if (b.snapshot !== snapshot) refuse("not_granted", "restore begin: another snapshot than the restore that began");
      chosen = await deps.choose(snapshot);
      guard();
      if (!chosen || chosen.error) refuse("not_granted", `restore begin: the manifest can't be used (${chosen?.error ?? "none"})`);
      if (chosen.sha256 !== b.manifest_sha256) refuse("not_granted", "restore begin: the store's manifest changed since the restore began");
    }
    // The plan: rebuilt with the RECORDED run when missing (byte-identical to the crashed begin's); a present one must
    // be this restore's.
    let p = readPlan({ dir });
    if (p === null) {
      p = newPlan(chosen, b.run);
      createPlan(p, { dir, io });
    } else if (p.manifest !== b.snapshot || p.sha256 !== b.manifest_sha256 || Object.hasOwn(p, "closed")
      || JSON.stringify(p) !== JSON.stringify(newPlan(chosen, b.run))) {
      refuse("not_granted", "restore begin: the plan here is another restore's");
    }
    await at("begin:planned");
    // The host store: staged by the launcher (the hoststore class, A2 r3.14 r2), its marked attempt read in place; an
    // unmarked attempt a crash left is removed and staged again, never read.
    await at("begin:copying");
    const copy = await deps.stageHostStore(chosen, { run: b.run, guard });
    await at("begin:copied");
    await deps.importHostStore({ copy, plan: p, manifest: chosen.manifest, guard });
    await at("begin:imported");
    // One request per set, created only if missing (read through a no-follow handle).
    const rdir = provenDir(dir, REQUESTS, { uid, create: true });
    for (const [k, v] of Object.entries(p.sets).sort(([x], [y]) => (x < y ? -1 : 1))) {
      const have = readRegular(join(rdir, k), MAX_BEGIN, "a request");
      guard();
      if (have === null) writeRequest(k, v.run, { dir, io, uid });
      else if (have.toString("utf8") !== requestText(v.run)) refuse("not_granted", "restore begin: a set's request is another run's");
    }
    await at("begin:requested");
    const done = { ...b, state: "done" };
    writeDurable(dir, BEGIN, JSON.stringify(done) + "\n", io);
    return { run: b.run, sets: Object.keys(p.sets).sort() };
    }, { dir });
  }, exclusion);
}

/** Why each set isn't terminal-for-close (§5, §7's table); an empty list when every one is. */
export function closeBlockers(p, { dir = RESTORE_DIR, restoreRaised, uid = 0 }) {
  checkPlan(p);
  const restoreRun = readBegin({ dir })?.run; // (an abandoned set's intent must be this restore's: §3.8)
  const abandon = optionalDir(dir, ABANDON, uid);
  const out = [];
  for (const k of Object.keys(p.sets).sort()) {
    const { kind, id } = parseKey(k);
    const r = readRecord(kind, id, { dir });
    const state = r === null ? "none" : r.state;
    if (abandon !== null && readRegular(join(abandon, `${k}.json`), MAX_BEGIN, "an abandon intent") !== null && state !== "abandoned") { out.push(`${k}: abandoning`); continue; }
    // An abandoned record is terminal only with its audit pair complete (R5-d2 §3.8): else it is corrupt, never closed.
    if (state === "abandoned") {
      try { auditPair(r, abandon, { restoreRun }); } catch (e) { out.push(`${k}: abandoned, but corrupt (${e?.message ?? e})`); }
      continue;
    }
    if (state !== "validated") { out.push(`${k}: ${state}`); continue; }
    if (kind === "agent" && restoreRaised(id) !== false) out.push(`${k}: validated, not resumed`);
  }
  return out;
}

/**
 * Copy `src` read-only to `name` in the PROVEN directory `dstDir` (temp, fsync, rename, 0400). An existing entry must be
 * a regular file (read through a no-follow handle), owned by `uid`, mode 0400 and byte-identical; anything else refuses.
 */
function archiveFile(src, dstDir, name, io, uid) {
  const bytes = readRegular(src, 64 * 2 ** 20, "an archived file");
  if (bytes === null) return;
  const dst = join(dstDir, name);
  let st = null;
  try { st = fs.lstatSync(dst); } catch (e) { if (e?.code !== "ENOENT") throw e; }
  if (st !== null) {
    if (!st.isFile() || st.uid !== uid || (st.mode & 0o777) !== 0o400) refuse("not_granted", "restore close: an archived entry isn't a private read-only file");
    const have = readRegular(dst, 64 * 2 ** 20, "an archived file");
    if (have === null || !have.equals(bytes)) refuse("not_granted", "restore close: an archived file differs");
    return;
  }
  writeDurable(dstDir, name, bytes, io, 0o400);
}

/**
 * The person's `host restore close` (§5), under the exclusion, then the restore lock. `restoreRaised(agent)`: whether
 * the agent's restore fence is still raised (only resume-restored lowers it). `removeHostStage(run)`: the host-store
 * stage's removal (restore-hoststage.mjs; the launcher's remove-tree of each hoststore attempt), after the commit.
 * Refuses (not_granted), naming each set, while any set isn't terminal-for-close. Resolves to { closed: at }.
 */
export async function close({ now, restoreRaised = (id) => fs.existsSync(join(FENCE_DIR, "restore", id)), removeHostStage }, { dir = RESTORE_DIR, io = realIo, exclusion = {}, uid = exclusion.uid ?? 0, onStep = () => {} } = {}) {
  if (typeof removeHostStage !== "function") refuse("bad_form", "restore close: the host-store stage's removal is required");
  return withExclusion((ex) => {
    try { fs.lstatSync(dir); } catch (e) { if (e?.code === "ENOENT") refuse("not_found", "restore close: no restore here"); throw e; }
    provenDir(dir, "", { uid });
    return withRestoreLock(async (rl) => {
    const guard = guardOf(ex, rl);
    const at = async (name) => { guard(); await onStep(name); guard(); };
    await at("close:locked");
    const b = readBegin({ dir });
    const p0 = readPlan({ dir });
    if (b === null || p0 === null) refuse("not_found", "restore close: no restore here");
    if (b.state !== "done") refuse("in_progress", "restore close: begin hasn't finished; run begin again first");
    let p = p0;
    if (!Object.hasOwn(p, "closed")) {
      const blockers = closeBlockers(p, { dir, restoreRaised, uid });
      if (blockers.length > 0) refuse("not_granted", `restore close: not every set is done: ${blockers.join("; ")}`);
      const at_ms = now();
      await at("close:checked");
      p = closePlan(at_ms, { dir, io }); // the commit point
    }
    await at("close:committed");
    // Idempotent from here: the archive, then the requests and the host store's copy removed (each link-safely).
    const into = provenDir(provenDir(dir, CLOSED, { uid, create: true }), b.run, { uid, create: true });
    const archive = (src, name) => { guard(); archiveFile(src, into, name, io, uid); };
    const abandon = optionalDir(dir, ABANDON, uid);
    archive(join(dir, PLAN), PLAN);
    archive(join(dir, BEGIN), BEGIN);
    for (const k of Object.keys(p.sets).sort()) {
      const { kind, id } = parseKey(k);
      archive(join(dir, `${k}.json`), `${k}.json`);
      for (const cls of CLASSES[kind]) {
        const r = readRecord(kind, id, { dir });
        if (r !== null) archive(join(dir, fillReportName(r, cls)), fillReportName(r, cls));
      }
      if (abandon !== null) {
        archive(join(abandon, `${k}.json`), `${k}.abandon.json`);
        archive(join(abandon, attestationName(kind, id)), `${k}.abandon.cleaned`);
      }
    }
    await at("close:archived");
    removeBeneath(dir, REQUESTS, { uid });
    guard();
    await removeHostStage(b.run);
    return { closed: p.closed.at };
    }, { dir });
  }, exclusion);
}
