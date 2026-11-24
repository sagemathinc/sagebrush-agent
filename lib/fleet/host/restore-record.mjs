// Host backup (design: agent-autonomous-host-backup.md r3.3 §5, T3, T5, H2): a restore's durable per-set record and
// its recovery. Nothing here restores anything: it is the state the restore's fill (later) moves through, so that a
// crash, a kill or a full disk at any point leaves a record that says exactly what recovery must do.
//
// One record per source set (backup-sources.mjs: an agent, a deleted agent's archive, a tag folder), at
// <RESTORE_DIR>/<kind>-<id>.json, written atomically and durably. States:
//   staging → staged → filling → published → validated
// with two stops, not_fitting (a quota hit, reason "limit") and failed (any other permanent failure), and a retry back
// to staging in a new attempt. Each step is written BEFORE it acts. The record binds the restore's run, the set's
// snapshot (by its full id) and the attempt; staging is <RESTORE_STAGING>/<run>/<kind>-<id>/<attempt>/, and its
// completion marker <attempt>.complete beside it, written only once the whole bound snapshot is restored.
//
// Fill moves entries out of staging, so staging is consumed (T5):
// - `filling` is written before the marker is invalidated, and the marker before the first move. From then on that
//   attempt is never filled again, whatever is left in it: recovery of a filling record is always a new attempt.
// - `dirty` says the destination may hold a partial fill (set by filling; kept by every way out of filling but
//   published; set again by any retry once a destination was ever recorded). A dirty record is cleaned first: the
//   destination's contents removed under its recorded identity, and every other attempt's staging discarded. Nothing
//   is staged or filled while dirty.
// - Automatic retries (a crash, a kill, a transient ENOSPC) are bounded by MAX_ATTEMPTS per run; past that, failed.
// - A stop (not_fitting, failed) is never retried automatically (H2): only a new restore request from the person
//   (retryRecord, a new run) starts again, at attempt 1.
// - validated is the only state from which the person's resume lowers the agent's restore fence (restoreReady).

import * as fs from "node:fs";
import { join } from "node:path";
import { isId, refuse } from "../bytes.mjs";
import { RESTORE_DIR, RESTORE_STAGING } from "./names.mjs";
import { exactKeys, realIo, writeDurable } from "./store.mjs";

export const STATES = Object.freeze(["staging", "staged", "filling", "published", "validated", "not_fitting", "failed"]);
export const KINDS = Object.freeze(["agent", "archive", "tag"]);
/** The destination classes a set's fill places (§5 step 8), each recorded by identity before the first move. */
export const CLASSES = Object.freeze({ agent: ["home", "sessions"], archive: ["archive"], tag: ["tag"] });
/** Why a set failed, from schema/fleet/reasons.json; not_fitting is always "limit". */
export const FAILED_REASONS = Object.freeze(["bad_form", "not_found", "outcome_unknown"]);
/** Automatic attempts per run (a crash, a kill, a transient ENOSPC each start one); the next is failed. */
export const MAX_ATTEMPTS = 3;
const KEYS = ["v", "kind", "id", "run", "snapshot", "attempt", "state", "dest", "dirty", "reason"];
const RUN = /^[0-9]{8}T[0-9]{6}Z-[a-z2-7]{8}$/;
const SNAP = /^[0-9a-f]{64}$/;
const NUM = /^(0|[1-9][0-9]{0,19})$/;
const STOPS = ["not_fitting", "failed"];

const identity = (x) => exactKeys(x, ["dev", "ino"]) && typeof x.dev === "string" && NUM.test(x.dev)
  && typeof x.ino === "string" && NUM.test(x.ino);
const checkDest = (kind, d) => exactKeys(d, CLASSES[kind]) && CLASSES[kind].every((c) => identity(d[c]));
const sameDest = (kind, a, b) => CLASSES[kind].every((c) => a[c].dev === b[c].dev && a[c].ino === b[c].ino);

/** The record's closed shape and its invariants. Returns the record, or refuses. */
export function checkRecord(r) {
  const ok = exactKeys(r, KEYS) && r.v === 1 && KINDS.includes(r.kind) && isId(r.id)
    && typeof r.run === "string" && RUN.test(r.run) && typeof r.snapshot === "string" && SNAP.test(r.snapshot)
    && Number.isSafeInteger(r.attempt) && r.attempt >= 1 && r.attempt <= MAX_ATTEMPTS && STATES.includes(r.state)
    && (r.dest === null || checkDest(r.kind, r.dest)) && typeof r.dirty === "boolean"
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
  return checkRecord({ v: 1, kind, id, run, snapshot, attempt: 1, state: "staging", dest: null, dirty: false, reason: null });
}

/**
 * The next record: exactly one allowed step, refused otherwise. The caller writes it (writeRecord) before it acts.
 * - "staged": from staging, not dirty (the marker is written first, by the staging step).
 * - "filling": from staged, with `dest` (the classes' identities); a run's destination never changes.
 * - "published": from filling (every class placed). "validated": from published.
 * - "not_fitting": from staging or filling (a quota hit). "failed": from staging, staged, filling or published, with
 *   `reason` (FAILED_REASONS). Either keeps dirty as it was: a stop out of filling is still cleaned.
 * - "retry": from staging, staged or filling, a new automatic attempt (staging, attempt + 1, dirty once a destination
 *   was recorded). Past MAX_ATTEMPTS it refuses (limit): the caller records failed instead.
 * - "clean": a dirty record whose destination was cleaned and other attempts discarded: the same state, not dirty.
 *   Only from staging or a stop (filling is left first, by a retry or a stop).
 */
export function step(r, to, { dest, reason } = {}) {
  checkRecord(r);
  const no = () => refuse("not_granted", `restore record: ${r.state} can't go to ${to}`);
  const next = (o) => checkRecord({ ...r, ...o });
  switch (to) {
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
      return next({ state: "staging", attempt: r.attempt + 1, dirty: r.dest !== null });
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
  if (run === r.run) refuse("bad_form", "restore record: a new request is a new run");
  return checkRecord({ ...r, run, snapshot, attempt: 1, state: "staging", dirty: r.dest !== null, reason: null });
}

/** A record's file, and its staging paths: the set's directory, an attempt's directory and its completion marker. */
export const recordName = (kind, id) => {
  if (!KINDS.includes(kind) || !isId(id)) refuse("bad_form", "restore record: bad set");
  return `${kind}-${id}.json`;
};
export const stagingSetDir = (run, kind, id, root = RESTORE_STAGING) => {
  if (typeof run !== "string" || !RUN.test(run)) refuse("bad_form", "restore record: bad run");
  return join(root, run, recordName(kind, id).slice(0, -".json".length));
};
export const stagingDir = (r, root = RESTORE_STAGING) => join(stagingSetDir(r.run, r.kind, r.id, root), String(r.attempt));
export const markerPath = (r, root = RESTORE_STAGING) => join(stagingSetDir(r.run, r.kind, r.id, root), `${r.attempt}.complete`);
/** The marker's filesystem steps: the durable-write steps plus unlink; tests replace single steps. */
export const markerIo = Object.freeze({ ...realIo, unlink: (p) => fs.unlinkSync(p) });
/** What a completion marker holds: exactly the record's binding. */
const markerOf = (r) => ({ v: 1, run: r.run, kind: r.kind, id: r.id, snapshot: r.snapshot, attempt: r.attempt });

/**
 * The first step after a restart, from the record and what is on disk: `marker` is the attempt's completion marker
 * as read (readMarker; null when absent or not whole), `attemptExists` whether the attempt's staging directory exists.
 * - "start": no record (the caller writes newRecord, then stages);
 * - "clean": dirty: clean the destination under its recorded identity, discard every other staging, then step clean;
 * - "stage": staging whose attempt was never begun (or was discarded by a clean): discard every other staging of the
 *   set, then restore the whole snapshot into this attempt;
 * - "promote": staging whose marker is this attempt's: the restore finished; step staged;
 * - "fill": staged with this attempt's marker: fill from it;
 * - "retry": anything begun and not whole, a staged record without its marker, or ANY filling record (its staging is
 *   consumed: never filled again); step retry (the next "stage" discards the old attempt), or failed
 *   (outcome_unknown) once no attempts are left;
 * - "validate": published; "none": validated, or a clean stop (only the person restarts it).
 */
export function recoveryStep(r, { marker, attemptExists }) {
  if (r === null) return "start";
  checkRecord(r);
  if (r.dirty && r.state !== "filling") return "clean";
  const whole = marker !== null && marker !== undefined && JSON.stringify(marker) === JSON.stringify(markerOf(r));
  switch (r.state) {
    case "staging": return whole ? "promote" : attemptExists ? "retry" : "stage";
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
 * Write the attempt's completion marker, durably, once the whole bound snapshot is restored into it. The record must
 * be staging, not dirty. Exclusive: a marker is never rewritten.
 */
export function writeMarker(r, { root = RESTORE_STAGING, io = markerIo } = {}) {
  checkRecord(r);
  if (r.state !== "staging" || r.dirty) refuse("not_granted", "restore record: a marker is written only while staging");
  const path = markerPath(r, root);
  const fd = io.open(path, "wx", 0o600);
  try {
    const buf = Buffer.from(JSON.stringify(markerOf(r)) + "\n");
    for (let off = 0; off < buf.length;) {
      const n = io.write(fd, buf, off, buf.length - off);
      if (!Number.isSafeInteger(n) || n <= 0 || n > buf.length - off) throw Object.assign(new Error("short write"), { code: "EIO" });
      off += n;
    }
    io.fsync(fd);
  } finally { io.close(fd); }
  const dfd = io.open(stagingSetDir(r.run, r.kind, r.id, root), "r");
  try { io.fsync(dfd); } finally { io.close(dfd); }
}

/** Read the attempt's marker: its contents when whole and valid JSON, else null (absent or torn: not complete). */
export function readMarker(r, { root = RESTORE_STAGING, fsx = fs } = {}) {
  let text;
  try { text = fsx.readFileSync(markerPath(r, root), "utf8"); } catch (e) { if (e?.code === "ENOENT") return null; throw e; }
  try { return JSON.parse(text); } catch { return null; }
}

/**
 * Invalidate the attempt's marker durably (unlink, directory fsync), the first act of a fill, once the record says
 * filling and before the first move. Refuses unless the record is filling.
 */
export function invalidateMarker(r, { root = RESTORE_STAGING, io = markerIo } = {}) {
  checkRecord(r);
  if (r.state !== "filling") refuse("not_granted", "restore record: the marker is invalidated only by a fill");
  try { io.unlink(markerPath(r, root)); } catch (e) { if (e?.code !== "ENOENT") throw e; }
  const dfd = io.open(stagingSetDir(r.run, r.kind, r.id, root), "r");
  try { io.fsync(dfd); } finally { io.close(dfd); }
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
