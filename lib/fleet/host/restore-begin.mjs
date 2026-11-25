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

import * as fs from "node:fs";
import { join } from "node:path";
import { refuse } from "../bytes.mjs";
import { BACKUP_RESTORE_LOCK, FENCE_DIR, RESTORE_DIR } from "./names.mjs";
import { CLASSES, RESTORE_RUN, fillReportName, readRecord, readRegular } from "./restore-record.mjs";
import { PLAN, checkPlan, closePlan, createPlan, newPlan, readPlan, withRestoreLock } from "./restore-plan.mjs";
import { exactKeys, lockFile, realIo, writeDurable, writeExclusive } from "./store.mjs";

export const BEGIN = "begin.json";
export const REQUESTS = "requests";
export const ABANDON = "abandon";
export const CLOSED = "closed";
export const HOSTSTORE_COPY = "hoststore-copy";
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
  try { return await fn(); } finally { await held.release(); }
}

/** A set's request file: requests/<kind>-<id>, exactly {"run": <run>}. */
const requestText = (run) => JSON.stringify({ run }) + "\n";
const parseKey = (k) => { const m = KEY.exec(k); if (!m) refuse("bad_form", "restore: bad set key"); return { kind: m[1], id: m[2] }; };

/** Create a set's request if missing; an existing one must be exactly this run's (never replaced). */
export function writeRequest(key, run, { dir = RESTORE_DIR, io = realIo } = {}) {
  parseKey(key);
  const rdir = join(dir, REQUESTS);
  fs.mkdirSync(rdir, { recursive: true, mode: 0o700 });
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
 * - restoreHostStore(chosen, intoDir): restore the manifest's host-store snapshot into the empty directory intoDir;
 * - importHostStore({ copy, plan, manifest }): restore-import's importHostStore with the open store bound.
 * Resolves to { run, sets } once `begin.json` says done.
 */
export async function begin(snapshot, deps, { dir = RESTORE_DIR, io = realIo, exclusion = {} } = {}) {
  if (typeof snapshot !== "string" || !HEX64.test(snapshot)) refuse("bad_form", "restore begin: bad snapshot");
  return withExclusion(() => withRestoreLock(async () => {
    if (deps.supervisorStopped() !== true) refuse("in_progress", "restore begin: the supervisor is running; stop it first");
    let b = readBegin({ dir });
    let chosen;
    if (b === null) {
      // A new begin: nothing of a restore here, a fresh registry, no backup set up.
      if (readPlan({ dir }) !== null) refuse("in_progress", "restore begin: a restore plan is already here");
      if (deps.registryFresh() !== true) refuse("not_granted", "restore begin: this host's registry isn't fresh");
      if (deps.backupEnabled() !== false) refuse("in_progress", "restore begin: backup is enabled on this host");
      chosen = await deps.choose(snapshot);
      if (!chosen || chosen.error) refuse("not_granted", `restore begin: the manifest can't be used (${chosen?.error ?? "none"})`);
      b = checkBegin({ v: 1, snapshot, manifest_sha256: chosen.sha256, run: deps.newRun(), state: "begun" });
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
      writeExclusive(dir, BEGIN, JSON.stringify(b) + "\n", io);
    } else {
      if (b.state === "done") refuse("in_progress", "restore begin: this host's restore has begun; use status, retry or close");
      if (b.snapshot !== snapshot) refuse("not_granted", "restore begin: another snapshot than the restore that began");
      chosen = await deps.choose(snapshot);
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
    // The host store: a fresh copy each time (a partial one from a crash is discarded first), then the import.
    const copy = join(dir, HOSTSTORE_COPY, b.run);
    fs.rmSync(copy, { recursive: true, force: true });
    fs.mkdirSync(copy, { recursive: true, mode: 0o700 });
    await deps.restoreHostStore(chosen, copy);
    await deps.importHostStore({ copy, plan: p, manifest: chosen.manifest });
    // One request per set, created only if missing.
    for (const [k, v] of Object.entries(p.sets).sort(([x], [y]) => (x < y ? -1 : 1))) {
      const have = (() => { try { return fs.readFileSync(join(dir, REQUESTS, k), "utf8"); } catch { return null; } })();
      if (have === null) writeRequest(k, v.run, { dir, io });
      else if (have !== requestText(v.run)) refuse("not_granted", "restore begin: a set's request is another run's");
    }
    const done = { ...b, state: "done" };
    writeDurable(dir, BEGIN, JSON.stringify(done) + "\n", io);
    return { run: b.run, sets: Object.keys(p.sets).sort() };
  }, { dir }), exclusion);
}

/** Why each set isn't terminal-for-close (§5, §7's table); an empty list when every one is. */
export function closeBlockers(p, { dir = RESTORE_DIR, restoreRaised }) {
  checkPlan(p);
  const out = [];
  for (const k of Object.keys(p.sets).sort()) {
    const { kind, id } = parseKey(k);
    const r = readRecord(kind, id, { dir });
    const state = r === null ? "none" : r.state;
    if (fs.existsSync(join(dir, ABANDON, `${k}.json`)) && state !== "abandoned") { out.push(`${k}: abandoning`); continue; }
    if (state === "abandoned") continue;
    if (state !== "validated") { out.push(`${k}: ${state}`); continue; }
    if (kind === "agent" && restoreRaised(id) !== false) out.push(`${k}: validated, not resumed`);
  }
  return out;
}

/** Copy `src` read-only to `dst` (temp, fsync, rename); an existing `dst` must be byte-identical. */
function archiveFile(src, dstDir, name, io) {
  const bytes = readRegular(src, 64 * 2 ** 20, "an archived file");
  if (bytes === null) return;
  const dst = join(dstDir, name);
  if (fs.existsSync(dst)) {
    if (!fs.readFileSync(dst).equals(bytes)) refuse("not_granted", "restore close: an archived file differs");
    return;
  }
  writeDurable(dstDir, name, bytes, io, 0o400);
}

/**
 * The person's `host restore close` (§5), under the exclusion, then the restore lock. `restoreRaised(agent)`: whether
 * the agent's restore fence is still raised (only resume-restored lowers it). Refuses (not_granted), naming each set,
 * while any set isn't terminal-for-close. Resolves to { closed: at }.
 */
export async function close({ now, restoreRaised = (id) => fs.existsSync(join(FENCE_DIR, "restore", id)) }, { dir = RESTORE_DIR, io = realIo, exclusion = {} } = {}) {
  return withExclusion(() => withRestoreLock(async () => {
    const b = readBegin({ dir });
    const p0 = readPlan({ dir });
    if (b === null || p0 === null) refuse("not_found", "restore close: no restore here");
    if (b.state !== "done") refuse("in_progress", "restore close: begin hasn't finished; run begin again first");
    let p = p0;
    if (!Object.hasOwn(p, "closed")) {
      const blockers = closeBlockers(p, { dir, restoreRaised });
      if (blockers.length > 0) refuse("not_granted", `restore close: not every set is done: ${blockers.join("; ")}`);
      p = closePlan(now(), { dir, io }); // the commit point
    }
    // Idempotent from here: the archive, then the requests and the host store's copy removed.
    const into = join(dir, CLOSED, b.run);
    fs.mkdirSync(into, { recursive: true, mode: 0o700 });
    archiveFile(join(dir, PLAN), into, PLAN, io);
    archiveFile(join(dir, BEGIN), into, BEGIN, io);
    for (const k of Object.keys(p.sets).sort()) {
      const { kind, id } = parseKey(k);
      archiveFile(join(dir, `${k}.json`), into, `${k}.json`, io);
      for (const cls of CLASSES[kind]) {
        const r = readRecord(kind, id, { dir });
        if (r !== null) archiveFile(join(dir, fillReportName(r, cls)), into, fillReportName(r, cls), io);
      }
      archiveFile(join(dir, ABANDON, `${k}.json`), into, `${k}.abandon.json`, io);
    }
    fs.rmSync(join(dir, REQUESTS), { recursive: true, force: true });
    fs.rmSync(join(dir, HOSTSTORE_COPY), { recursive: true, force: true });
    return { closed: p.closed.at };
  }, { dir }), exclusion);
}
