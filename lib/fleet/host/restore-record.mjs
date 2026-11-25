// Host backup (design: agent-autonomous-host-backup.md r3.3 §5, T3, T5, H2): a restore's durable per-set record and
// its recovery. Nothing here restores anything: it is the state the restore's fill (later) moves through, so that a
// crash, a kill or a full disk at any point leaves a record that says exactly what recovery must do.
//
// One record per source set (backup-sources.mjs: an agent, a deleted agent's archive, a tag folder), at
// <RESTORE_DIR>/<kind>-<id>.json, written atomically and durably. States:
//   staging → staged → filling → published → validated
// with two stops, not_fitting (a quota hit, reason "limit") and failed (any other permanent failure), and a retry back
// to staging in a new attempt. Each step is written BEFORE it acts. The record binds the restore's run, the set's
// snapshot (by its full id) and the attempt.
//
// Staging and its markers are the launcher's (amendment A2 §2-§4): each CLASS of a set (an agent's home and
// sessions, an archive, a tag folder) is staged by one `restore-stage` call at
// <RESTORE_STAGING>/<run>/<owner>/<class>/<attempt>/data, the owner `a-<id>` (an agent or an archive) or `t-<id>` (a
// tag), and the launcher alone writes the completion marker <attempt>/.complete, after the data is durable, holding
// exactly that name; `fill-home` unlinks it before its first move. This side never writes or removes a marker: it
// reads them. A restore's run is the launcher's 16 characters of [a-z2-7]; newRestoreRun puts the time in its first
// ten, and runs are ordered by that decoded time (runTime), never by comparing the strings.
//
// Fill moves entries out of staging, so staging is consumed (T5):
// - `filling` is written before the first `fill-home`, which unlinks the class's marker before its first move. From
//   then on that attempt is never filled again, whatever is left in it: recovery of a filling record is always a new
//   attempt.
// - `dirty` says the destination may hold a partial fill (set by filling; kept by every way out of filling but
//   published; set again by any retry once a destination was ever recorded). A dirty record is cleaned first: the
//   destination's contents removed under its recorded identity, and every other attempt's staging discarded. Nothing
//   is staged or filled while dirty.
// - Automatic retries (a crash, a kill, a transient ENOSPC) are bounded by MAX_ATTEMPTS per run; past that, failed.
// - A stop (not_fitting, failed) is never retried automatically (H2): only a new restore request from the person
//   (retryRecord, a new run) starts again, at attempt 1.
// - validated is the only state from which the person's resume lowers the agent's restore fence (restoreReady).
//
// Validation's binding (launcher amendment A2 r3.8.3 §4b): each class's restore-stage reports the SHA-256 of the digest
// list it wrote beside the class (data/digests.json), and `digests` records it, class by class, as each class stages
// (still staging, before the next class starts). staged and everything after it need every class's hash: a crash
// after the last marker but before its hash was written is a retry, never a promote, since a list whose hash was
// never recorded is never used. A new attempt starts with none.

import * as fs from "node:fs";
import { join } from "node:path";
import { isId, refuse } from "../bytes.mjs";
import { RESTORE_DIR, RESTORE_STAGING } from "./names.mjs";
import { randomBytes } from "node:crypto";
import { exactKeys, realIo, writeDurable } from "./store.mjs";
import { rawPath } from "./restore-validate.mjs";

export const STATES = Object.freeze(["staging", "staged", "filling", "published", "validated", "not_fitting", "failed"]);
export const KINDS = Object.freeze(["agent", "archive", "tag"]);
/** The destination classes a set's fill places (§5 step 8), each recorded by identity before the first move. */
export const CLASSES = Object.freeze({ agent: ["home", "sessions"], archive: ["archive"], tag: ["tag"] });
/** Why a set failed, from schema/fleet/reasons.json; not_fitting is always "limit". */
export const FAILED_REASONS = Object.freeze(["bad_form", "not_found", "outcome_unknown"]);
/** Automatic attempts per run (a crash, a kill, a transient ENOSPC each start one); the next is failed. */
export const MAX_ATTEMPTS = 3;
const KEYS = ["v", "kind", "id", "run", "snapshot", "attempt", "state", "dest", "digests", "dirty", "reason"];
/** A restore's run: the launcher's 16 characters of [a-z2-7] (A2 §2). */
export const RESTORE_RUN = /^[a-z2-7]{16}$/;
const RUN = RESTORE_RUN;
const B32 = "abcdefghijklmnopqrstuvwxyz234567";
const SNAP = /^[0-9a-f]{64}$/;
const NUM = /^(0|[1-9][0-9]{0,19})$/;
const STOPS = ["not_fitting", "failed"];

const identity = (x) => exactKeys(x, ["dev", "ino"]) && typeof x.dev === "string" && NUM.test(x.dev)
  && typeof x.ino === "string" && NUM.test(x.ino);
const checkDest = (kind, d) => exactKeys(d, CLASSES[kind]) && CLASSES[kind].every((c) => identity(d[c]));
const sameDest = (kind, a, b) => CLASSES[kind].every((c) => a[c].dev === b[c].dev && a[c].ino === b[c].ino);
const HEX64 = /^[0-9a-f]{64}$/;
/** A record's digest hashes: null (none yet), or some of the set's classes, each 64 lower-case hex. */
const checkDigests = (kind, d) => d === null || (d !== null && typeof d === "object" && !Array.isArray(d)
  && Object.getPrototypeOf(d) === Object.prototype && Object.keys(d).length > 0
  && Object.keys(d).every((c) => CLASSES[kind].includes(c) && typeof d[c] === "string" && HEX64.test(d[c])));
/** Every class of the set has its digest list's hash. */
export const digestsWhole = (r) => r.digests !== null && CLASSES[r.kind].every((c) => Object.hasOwn(r.digests, c));

/** The record's closed shape and its invariants. Returns the record, or refuses. */
export function checkRecord(r) {
  const ok = exactKeys(r, KEYS) && r.v === 1 && KINDS.includes(r.kind) && isId(r.id)
    && typeof r.run === "string" && RUN.test(r.run) && typeof r.snapshot === "string" && SNAP.test(r.snapshot)
    && Number.isSafeInteger(r.attempt) && r.attempt >= 1 && r.attempt <= MAX_ATTEMPTS && STATES.includes(r.state)
    && (r.dest === null || checkDest(r.kind, r.dest)) && checkDigests(r.kind, r.digests) && typeof r.dirty === "boolean"
    // staged and after it, every class's list is bound by its hash.
    && (!["staged", "filling", "published", "validated"].includes(r.state) || digestsWhole(r))
    // A destination is recorded before anything is filled, and dirty only names a recorded one.
    && (r.dest !== null || !["filling", "published", "validated"].includes(r.state)) && (!r.dirty || r.dest !== null)
    // filling is always dirty; staged, published and validated never are.
    && (r.state !== "filling" || r.dirty) && (!["staged", "published", "validated"].includes(r.state) || !r.dirty)
    && (r.state === "not_fitting" ? r.reason === "limit" : r.state === "failed" ? FAILED_REASONS.includes(r.reason) : r.reason === null);
  if (!ok) refuse("bad_form", "restore record: not a valid record");
  return r;
}

/** A set's first record of a run: staging, attempt 1, nothing recorded at the destination. */
export function newRecord({ kind, id, run, snapshot }) {
  return checkRecord({ v: 1, kind, id, run, snapshot, attempt: 1, state: "staging", dest: null, digests: null, dirty: false, reason: null });
}

/**
 * The next record: exactly one allowed step, refused otherwise. The caller writes it (writeRecord) before it acts.
 * - "digest": from staging, not dirty, with `cls` and `sha256`: one class's digest list hash, as its restore-stage
 *   reported it; once per class per attempt (a second report for a class is refused, never replaced).
 * - "staged": from staging, not dirty, with every class's hash (the marker is written first, by the staging step).
 * - "filling": from staged, with `dest` (the classes' identities); a run's destination never changes.
 * - "published": from filling (every class placed). "validated": from published.
 * - "not_fitting": from staging or filling (a quota hit). "failed": from staging, staged, filling or published, with
 *   `reason` (FAILED_REASONS). Either keeps dirty as it was: a stop out of filling is still cleaned.
 * - "retry": from staging, staged or filling, a new automatic attempt (staging, attempt + 1, dirty once a destination
 *   was recorded). Past MAX_ATTEMPTS it refuses (limit): the caller records failed instead.
 * - "clean": a dirty record whose destination was cleaned and other attempts discarded: the same state, not dirty.
 *   Only from staging or a stop (filling is left first, by a retry or a stop).
 */
export function step(r, to, { dest, reason, cls, sha256 } = {}) {
  checkRecord(r);
  const no = () => refuse("not_granted", `restore record: ${r.state} can't go to ${to}`);
  const next = (o) => checkRecord({ ...r, ...o });
  switch (to) {
    case "digest":
      if (r.state !== "staging" || r.dirty) no();
      if (!CLASSES[r.kind].includes(cls) || typeof sha256 !== "string" || !HEX64.test(sha256)) refuse("bad_form", "restore record: not a class's digest hash");
      if (r.digests !== null && Object.hasOwn(r.digests, cls)) refuse("not_granted", "restore record: the class's digest hash is already recorded");
      return next({ digests: { ...(r.digests ?? {}), [cls]: sha256 } });
    case "staged":
      if (r.state !== "staging" || r.dirty) no();
      return next({ state: "staged" });
    case "filling":
      if (r.state !== "staged") no();
      if (!checkDest(r.kind, dest) || (r.dest !== null && !sameDest(r.kind, r.dest, dest))) refuse("bad_form", "restore record: not this set's destination");
      return next({ state: "filling", dest: structuredClone(dest), dirty: true });
    case "published":
      if (r.state !== "filling") no();
      return next({ state: "published", dirty: false });
    case "validated":
      if (r.state !== "published") no();
      return next({ state: "validated" });
    case "not_fitting":
      if (!["staging", "filling"].includes(r.state)) no();
      return next({ state: "not_fitting", reason: "limit" });
    case "failed":
      if (!["staging", "staged", "filling", "published"].includes(r.state)) no();
      if (!FAILED_REASONS.includes(reason)) refuse("bad_form", "restore record: not a failure reason");
      return next({ state: "failed", reason });
    case "retry":
      if (!["staging", "staged", "filling"].includes(r.state)) no();
      if (r.attempt >= MAX_ATTEMPTS) refuse("limit", "restore record: no automatic attempts left");
      return next({ state: "staging", attempt: r.attempt + 1, digests: null, dirty: r.dest !== null });
    case "clean":
      if (!r.dirty || !["staging", ...STOPS].includes(r.state)) no();
      return next({ dirty: false });
    default:
      refuse("bad_form", "restore record: unknown step");
  }
}

/**
 * A new restore request from the person for a set that stopped (not_fitting or failed): a new run, possibly another
 * snapshot, attempt 1, dirty once a destination was ever recorded. The only way out of a stop (H2).
 */
export function retryRecord(r, { run, snapshot }) {
  checkRecord(r);
  if (!STOPS.includes(r.state)) refuse("not_granted", "restore record: only a stopped set is restored again");
  if (typeof run !== "string" || !RUN.test(run) || runTime(run) <= runTime(r.run)) refuse("bad_form", "restore record: a new request is a newer run");
  return checkRecord({ ...r, run, snapshot, attempt: 1, state: "staging", digests: null, dirty: r.dest !== null, reason: null });
}

/**
 * A new restore run: the time in ms as 10 base32 digits (most significant first, zero-padded with "a"), then 6 random
 * base32 characters. 50 bits of milliseconds; 30 random bits keep runs of the same millisecond apart.
 */
export function newRestoreRun(now, rand = randomBytes) {
  if (!Number.isSafeInteger(now) || now < 0 || now >= 2 ** 50) refuse("bad_form", "restore record: bad time");
  let t = "";
  for (let i = 9, v = now; i >= 0; i--) { t = B32[v % 32] + t; v = Math.floor(v / 32); }
  const r = rand(6);
  return t + Array.from(r, (b) => B32[b & 31]).join("");
}

/**
 * A run's time (ms), decoded from its first ten characters. Runs are ordered by this, never as strings: in [a-z2-7]
 * the digits 2-7 (values 26-31) sort before the letters, so string order isn't time order.
 */
export function runTime(run) {
  if (typeof run !== "string" || !RUN.test(run)) refuse("bad_form", "restore record: bad run");
  let v = 0;
  for (const ch of run.slice(0, 10)) v = v * 32 + B32.indexOf(ch);
  return v;
}

/** A record's file, and its staging paths: the set's directory, an attempt's directory and its completion marker. */
export const recordName = (kind, id) => {
  if (!KINDS.includes(kind) || !isId(id)) refuse("bad_form", "restore record: bad set");
  return `${kind}-${id}.json`;
};
/** The launcher's owner name for a set: `t-<id>` for a tag folder, `a-<id>` for an agent or a deleted agent's archive. */
export const ownerOf = (kind, id) => {
  recordName(kind, id);
  return `${kind === "tag" ? "t" : "a"}-${id}`;
};
/** One class's attempt, as the launcher names it: `<run>/<owner>/<class>/<attempt>` (also its marker's content). */
export function stagingName(r, cls) {
  checkRecord(r);
  if (!CLASSES[r.kind].includes(cls)) refuse("bad_form", "restore record: not a class of this set");
  return `${r.run}/${ownerOf(r.kind, r.id)}/${cls}/${r.attempt}`;
}
export const stagingDir = (r, cls, root = RESTORE_STAGING) => join(root, stagingName(r, cls));
export const markerPath = (r, cls, root = RESTORE_STAGING) => join(stagingDir(r, cls, root), ".complete");

/**
 * The first step after a restart, from the record and what is on disk: `markers` is each of the set's classes'
 * completion marker as read (readMarker: its text, or null when absent), `begun` whether ANY class's attempt
 * directory exists. The attempt is whole only when every class's marker is exactly that class's name.
 * - "start": no record (the caller writes newRecord, then stages);
 * - "clean": dirty: clean the destination under its recorded identity, discard every other staging, then step clean;
 * - "stage": staging whose attempt was never begun (or was discarded by a clean): discard every other staging of the
 *   set, then restore the whole snapshot into this attempt;
 * - "promote": staging whose markers are this attempt's, every class's digest hash recorded: step staged (markers
 *   without every hash: retry, the lists can't be trusted);
 * - "fill": staged with this attempt's marker: fill from it;
 * - "retry": anything begun and not whole, a staged record without its marker, or ANY filling record (its staging is
 *   consumed: never filled again); step retry (the next "stage" discards the old attempt), or failed
 *   (outcome_unknown) once no attempts are left;
 * - "validate": published; "none": validated, or a clean stop (only the person restarts it).
 */
export function recoveryStep(r, { markers, begun }) {
  if (r === null) return "start";
  checkRecord(r);
  if (r.dirty && r.state !== "filling") return "clean";
  const m = markers !== null && typeof markers === "object" ? markers : {};
  const whole = CLASSES[r.kind].every((c) => Object.hasOwn(m, c) && m[c] === stagingName(r, c));
  switch (r.state) {
    case "staging": return whole && digestsWhole(r) ? "promote" : begun || whole ? "retry" : "stage";
    case "staged": return whole ? "fill" : "retry";
    case "filling": return "retry";
    case "published": return "validate";
    default: return "none";
  }
}

/** Read a set's record: null when there is none; a present but unreadable or invalid file throws (never "none"). */
export function readRecord(kind, id, { dir = RESTORE_DIR, fsx = fs } = {}) {
  let text;
  try { text = fsx.readFileSync(join(dir, recordName(kind, id)), "utf8"); } catch (e) { if (e?.code === "ENOENT") return null; throw e; }
  let r;
  try { r = JSON.parse(text); } catch { refuse("bad_form", "restore record: not JSON"); }
  checkRecord(r);
  if (r.kind !== kind || r.id !== id) refuse("bad_form", "restore record: not this set's");
  return r;
}

/** Write a set's record durably (temp, fsync, rename, directory fsync). Throws on any failure. */
export function writeRecord(r, { dir = RESTORE_DIR, io = realIo } = {}) {
  checkRecord(r);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  writeDurable(dir, recordName(r.kind, r.id), JSON.stringify(r) + "\n", io);
}

/**
 * Read one class's completion marker, written by the launcher: its text, or null when absent. Its content is checked
 * by the caller (recoveryStep): a torn or foreign marker is not this attempt's.
 */
export function readMarker(r, cls, { root = RESTORE_STAGING, fsx = fs } = {}) {
  try { return fsx.readFileSync(markerPath(r, cls, root), "utf8"); } catch (e) { if (e?.code === "ENOENT") return null; throw e; }
}

/**
 * The agent's restore state for its resume (lowerFence's `restoreState`): "validated" only when the agent's own record
 * and the record of every tag folder it is a member of are validated AND each is bound to exactly the run and snapshot
 * the current restore expects for that set. `tags`: the agent's tags in the restored registry. `expected`: the
 * authoritative binding of the current restore (its plan, from the chosen manifest and the latest request per set),
 * { "<kind>-<id>": { run, snapshot } }, with an entry for every required set.
 * - a required set without an entry, or an entry not of that shape: refused (bad_form);
 * - a record bound to another run or snapshot (an older restore, a mixed one): refused (not_granted), never resumed;
 * - otherwise the first state found that isn't validated (a missing record is "none").
 */
export function restoreReady(agent, tags, expected, { dir = RESTORE_DIR } = {}) {
  if (!isId(agent) || !Array.isArray(tags) || !tags.every(isId)) refuse("bad_form", "restore record: bad agent");
  if (expected === null || typeof expected !== "object" || Array.isArray(expected)) refuse("bad_form", "restore record: no expected binding");
  const sets = [["agent", agent], ...tags.map((t) => ["tag", t])];
  for (const [kind, id] of sets) {
    const want = Object.hasOwn(expected, `${kind}-${id}`) ? expected[`${kind}-${id}`] : undefined;
    if (!exactKeys(want, ["run", "snapshot"]) || typeof want.run !== "string" || !RUN.test(want.run)
      || typeof want.snapshot !== "string" || !SNAP.test(want.snapshot)) refuse("bad_form", "restore record: no expected binding for a required set");
  }
  for (const [kind, id] of sets) {
    const r = readRecord(kind, id, { dir });
    if (r === null) return "none";
    const want = expected[`${kind}-${id}`];
    if (r.run !== want.run || r.snapshot !== want.snapshot) refuse("not_granted", "restore record: a set's record is from another restore");
    if (r.state !== "validated") return r.state;
  }
  return "validated";
}

/**
 * fill-home's report of one class (A2 §4 step 6), kept for validation: what stayed in staging, refused (owned by
 * nobody of the class) or unexpected (a special file), as the launcher listed them. Saved durably, bound to the run and
 * attempt, BEFORE the record steps to published, so a validation after a crash still subtracts exactly what fill
 * refused; a report of another run or attempt is never used. Paths are in A2 §4b's codec, as in the listings (at most
 * 4096 raw bytes), so they are subtracted from the digest list as they are.
 */
export const MAX_REPORTED = 1000;
const REPORT_KEYS = ["v", "run", "attempt", "cls", "refused", "unexpected", "truncated"];
const SPECIAL = ["fifo", "socket", "char", "block"];
const reportedPath = (p) => {
  const raw = typeof p === "string" ? rawPath(p) : null;
  return raw !== null && raw.length > 0 && raw.length <= 4096 && !raw.includes(0)
    && p.split("/").every((s) => s !== "" && s !== "." && s !== "..");
};
const u32 = (n) => Number.isSafeInteger(n) && n >= 0 && n < 2 ** 32;

/** The closed shape of a saved fill report. Returns it, or refuses. */
export function checkFillReport(x) {
  const ok = exactKeys(x, REPORT_KEYS) && x.v === 1 && typeof x.run === "string" && RUN.test(x.run)
    && Number.isSafeInteger(x.attempt) && x.attempt >= 1 && x.attempt <= MAX_ATTEMPTS && Object.values(CLASSES).flat().includes(x.cls)
    && Array.isArray(x.refused) && x.refused.length <= MAX_REPORTED
    && x.refused.every((e) => exactKeys(e, ["path", "uid", "gid", "entries"]) && reportedPath(e.path) && u32(e.uid) && u32(e.gid)
      && Number.isSafeInteger(e.entries) && e.entries >= 0)
    && Array.isArray(x.unexpected) && x.unexpected.length <= MAX_REPORTED
    && x.unexpected.every((e) => exactKeys(e, ["path", "type"]) && reportedPath(e.path) && SPECIAL.includes(e.type))
    && typeof x.truncated === "boolean";
  if (!ok) refuse("bad_form", "restore record: not a valid fill report");
  return x;
}

export const fillReportName = (r, cls) => {
  stagingName(r, cls);
  return `${r.kind}-${r.id}.${cls}.fill.json`;
};

/**
 * A saved report's longest form: 1000 refused and 1000 unexpected paths, each at most 4096 raw bytes, every byte
 * written at most 6 characters (a control byte as \u00xx), with its keys.
 */
export const MAX_REPORT_BYTES = 64 * 2 ** 20;

/**
 * A file the supervisor (or the launcher) wrote, read back whole: its bytes, or null when there is none. Race-safe:
 * lstat first, then an open that never follows a link and never blocks, then fstat of that handle, which must be the
 * SAME object (dev and ino) as the lstat, a regular file of at most `max` bytes. Anything demonstrably not one (a link,
 * a directory, a FIFO, a socket, a device, another object swapped in, an oversized file, or an open refused for the
 * object's type: ELOOP, ENXIO) is permanent: bad_form. Any other error (EIO, EACCES) throws as it is: an interruption.
 */
export function readRegular(path, max, what, fsx = fs) {
  const notOne = (why) => refuse("bad_form", `restore record: ${what} ${why}`);
  let before;
  try { before = fsx.lstatSync(path); } catch (e) { if (e?.code === "ENOENT") return null; throw e; }
  if (!before.isFile()) notOne("isn't a regular file");
  let fd;
  try { fd = fsx.openSync(path, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK); } catch (e) {
    if (e?.code === "ENOENT") return null;
    if (["ELOOP", "ENXIO", "EISDIR", "ENODEV"].includes(e?.code)) notOne("changed into something that isn't a regular file");
    throw e;
  }
  try {
    const st = fsx.fstatSync(fd);
    if (!st.isFile() || st.dev !== before.dev || st.ino !== before.ino) notOne("isn't the file that was looked at");
    if (st.size > max) notOne("is longer than it can be");
    const buf = Buffer.alloc(st.size);
    for (let off = 0; off < buf.length;) {
      const k = fsx.readSync(fd, buf, off, buf.length - off, off);
      if (k <= 0) notOne("changed while read");
      off += k;
    }
    return buf;
  } finally { fsx.closeSync(fd); }
}

/** Save one class's fill report ({ refused, unexpected, truncated }, fill-home's) for the record's attempt. */
export function writeFillReport(r, cls, { refused, unexpected, truncated }, { dir = RESTORE_DIR, io = realIo } = {}) {
  const x = checkFillReport({ v: 1, run: r.run, attempt: r.attempt, cls, refused, unexpected, truncated });
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  writeDurable(dir, fillReportName(r, cls), JSON.stringify(x) + "\n", io);
}

/** Read one class's fill report for the record's attempt: null when there is none, or it is another attempt's. */
export function readFillReport(r, cls, { dir = RESTORE_DIR, fsx = fs } = {}) {
  const bytes = readRegular(join(dir, fillReportName(r, cls)), MAX_REPORT_BYTES, "the fill report", fsx);
  if (bytes === null) return null;
  const text = bytes.toString("utf8");
  let x;
  try { x = JSON.parse(text); } catch { refuse("bad_form", "restore record: the fill report isn't JSON"); }
  checkFillReport(x);
  return x.run === r.run && x.attempt === r.attempt && x.cls === cls ? x : null;
}
