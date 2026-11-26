// Host restore, end to end (design: agent-autonomous-host-restore-e2e.md r1.7 §3, §5, §7): the restore WORKER, one per
// set, and its short dispatch. The fill itself is restore-fill.mjs's whole-set driver; this module owns who may run it,
// when, and under what proof. Every outside effect is a dependency (the real adapters are wired separately), so each
// branch is tested against fakes and real temporary directories with real locks.
//
// - **The worker** (`runWorker`) runs outside the executor's queue, in its own transient scope under sagebrush.slice
//   (never an agent's slice: the lease's and the system-sleep hook's kills of the agents' slices don't reach it). It
//   holds the set's lock, <restore>/<kind>-<id>.lock, for its whole life, so a second worker for the same set can't
//   start and a stale one can't write once a new one has begun. Before anything, under that lock: the restore has begun
//   (`begin.json` done), its plan is open, the set is the plan's at exactly the run it was started for, and its request
//   says that run; an abandon intent for the set ends the worker at once, writing nothing.
// - **Admission is the worker's, authoritative, under its lock, immediately before the first effect** (§3): a record
//   with a bound destination must still be exactly that identity (else the set fails, nothing touched); a set with no
//   bound destination is admitted at the bind itself (the fill driver's `admit` hook): every class's destination must
//   be EXACTLY the trusted provisioned object (device, inode, owner, group, mode, project: another empty directory
//   with the same owner and mode is refused) and EMPTY, or nothing is recorded or touched.
// - **An abandon intent vetoes the final publication** (the fill driver's `veto` hook, before an archive's or a tag
//   folder's validated; an agent's validated is its imports', which check it too).
// - **A lost lock aborts the fill**: the fill driver's signal is aborted the first time the lock isn't held, and the
//   worker refuses outcome_unknown once it returns.
// - **Dispatch** (`dispatchOnce`, the executor's short `restore-dispatch` op) is ADVISORY: it starts at most one worker
//   per host, only while the restore has begun and is open and the suspend gate is open, for the first set (in key
//   order) that has its request, isn't terminal, has no intent, has no live worker and passes the caller's advisory
//   admission; it starts the worker's scope and returns at once, never awaiting it.
// - **Ownership is the set lock, both ways** (`holdSets`): the executor's delete, purge, requalify and provision of an
//   agent TAKE the locks of the agent's sets (its own, its archive, each tag folder of its current and incoming tags)
//   and hold them through their effects, or are refused while any is held. A worker started by a dispatch that hasn't
//   taken its lock yet then finds it held and exits busy, touching nothing; so no lifecycle effect ever overlaps a
//   worker, whatever the order of the dispatch's return and the worker's start.

import { existsSync } from "node:fs";
import { join } from "node:path";
import { isId, newId, refuse } from "../bytes.mjs";
import { RESTORE_DIR } from "./names.mjs";
import { CLASSES, RESTORE_RUN, readRecord, readRegular, sameDest, sameIdentity, step, writeRecord } from "./restore-record.mjs";
import { readPlan } from "./restore-plan.mjs";
import { ABANDON, REQUESTS, parseKey, provenDir, readBegin, requestText } from "./restore-begin.mjs";
import { destOf } from "./restore-fill.mjs";
import { readInput, removeInputs, writeInput } from "./restore-inputs.mjs";
import { lockFile } from "./store.mjs";

/** The slice the workers run in: the host's own, never the agents'. */
export const WORKER_SLICE = "sagebrush.slice";
/** How long a worker tries its set's lock before it exits busy: not at all (a held set is a lifecycle op's or another
 * worker's; the next dispatch tries again). */
export const SET_LOCK_TRY_MS = 0;
/** How often a running fill checks that the set lock is still held. */
export const HELD_POLL_MS = 500;
/** States the dispatch never starts a worker for: done, stopped, given up; an agent's files_validated waits for its imports. */
const SETTLED = ["validated", "not_fitting", "failed", "abandoned"];

const keyOf = (kind, id) => {
  if (!Object.hasOwn(CLASSES, kind) || !isId(id)) refuse("bad_form", "restore worker: bad set");
  return `${kind}-${id}`;
};

/** A worker's scope: one per set, so a second start of the same set is refused by systemd too. */
export const workerScope = (kind, id) => `sagebrush-restore-${keyOf(kind, id)}.scope`;

/** The argv that starts a set's worker in its own scope under the host's slice, never a shell; `nonce` binds it to its
 * dispatch's input (d2 §2). */
export function workerArgv(kind, id, run, nonce, { node = process.execPath, main, mount = "/" }) {
  keyOf(kind, id);
  if (typeof main !== "string" || !main.startsWith("/")) refuse("bad_form", "restore worker: the main must be absolute");
  if (typeof run !== "string" || !RESTORE_RUN.test(run)) refuse("bad_form", "restore worker: bad run");
  if (!isId(nonce)) refuse("bad_form", "restore worker: bad nonce");
  if (typeof mount !== "string" || !mount.startsWith("/") || !/^[A-Za-z0-9._/-]+$/.test(mount)) refuse("bad_form", "restore worker: bad mount");
  return ["systemd-run", "--scope", "--quiet", "--collect", `--slice=${WORKER_SLICE}`, `--unit=${workerScope(kind, id)}`,
    "--", node, main, "restore-worker", kind, id, run, nonce, mount];
}

/** The set's lock file, in the restore directory. */
export const setLockPath = (dir, kind, id) => join(dir, `${keyOf(kind, id)}.lock`);

/** The set's abandon intent: its bytes, or null when there is none (read through a no-follow handle, its directory proven). */
export function readIntent(kind, id, { dir = RESTORE_DIR, uid = 0 } = {}) {
  const key = keyOf(kind, id);
  let abandon;
  try { abandon = provenDir(dir, ABANDON, { uid }); } catch (e) { if (e?.code === "ENOENT") return null; throw e; }
  return readRegular(join(abandon, `${key}.json`), 64 * 1024, "an abandon intent");
}

/** Is the set's request exactly `run`'s? (No requests directory, or no request: no.) Read link-safely, its directory proven. */
function requested(key, run, { dir, uid }) {
  let rdir;
  try { rdir = provenDir(dir, REQUESTS, { uid }); } catch (e) { if (e?.code === "ENOENT") return false; throw e; }
  const req = readRegular(join(rdir, key), 4096, "a request");
  return req !== null && req.toString("utf8") === requestText(run);
}

/** Is a worker live for the set: its lock held now? (A try that takes it is released at once.) */
export async function workerLive(kind, id, { dir = RESTORE_DIR, lock = lockFile } = {}) {
  const path = setLockPath(dir, kind, id);
  // A worker creates its lock file before anything else: no file, no worker has ever run for the set (and no file is
  // left behind by asking).
  if (!existsSync(path)) return false;
  let held;
  try { held = await lock(path, { waitMs: 0 }); } catch (e) { if (e?.code === "in_progress") return true; throw e; }
  await held.release();
  return false;
}

/**
 * Admission at the bind (§3 case 1): every class's identified destination must be EXACTLY the trusted provisioned
 * object (`provisioned(kind, id, cls)` → { dev, ino, uid, gid, mode, projid }, in the record's form: the identity the
 * provisioning recorded) and empty (`isEmpty(kind, id, cls, identified)`). Refuses not_granted otherwise; nothing has
 * been recorded or touched.
 */
export async function admitBind(r, ids, dest, { provisioned, isEmpty }) {
  for (const cls of CLASSES[r.kind]) {
    const want = await provisioned(r.kind, r.id, cls);
    const got = dest[cls];
    // (every field compared: a trusted identity missing one never equals the identified destination)
    if (want === null || typeof want !== "object" || !sameIdentity(want, got)) {
      refuse("not_granted", `restore worker: ${r.kind}-${r.id}'s ${cls} isn't the provisioned destination`);
    }
    if ((await isEmpty(r.kind, r.id, cls, ids[cls])) !== true) refuse("not_granted", `restore worker: ${r.kind}-${r.id}'s ${cls} isn't empty`);
  }
}

/**
 * One set's worker (§3). `nonce`: its dispatch's (its argv's). `deps`:
 * - filler(hooks, input) → fillSet: restore-fill.mjs's restoreFiller bound to the real adapters over the set's INPUT
 *   (d2), with `hooks` = { admit, veto };
 * - identifyDest(kind, id, cls): the launcher's identity of a class's destination now;
 * - isEmpty(kind, id, cls, identified): admitBind's.
 * The trusted provisioned identities are the input's (the records', copied by the dispatch), never deps'. Resolves to
 * { status, record }: status "abandoning" (an intent: nothing written), or the record's state after the fill.
 */
export async function runWorker(kind, id, run, nonce, deps, { dir = RESTORE_DIR, uid = 0, lock = lockFile, waitMs = SET_LOCK_TRY_MS, pollMs = HELD_POLL_MS } = {}) {
  const key = keyOf(kind, id);
  provenDir(dir, "", { uid });
  const held = await lock(setLockPath(dir, kind, id), { waitMs }); // busy: in_progress, another worker has the set
  const guard = () => { if (!held.held()) refuse("outcome_unknown", "restore worker: the set's lock was lost; nothing more is done"); };
  const ac = new AbortController();
  const poll = setInterval(() => { if (!held.held()) ac.abort(); }, pollMs);
  try {
    // The restore and the set, bound exactly.
    const b = readBegin({ dir });
    if (b === null) refuse("not_found", "restore worker: no restore here");
    if (b.state !== "done") refuse("in_progress", "restore worker: begin hasn't finished");
    const p = readPlan({ dir });
    if (p === null) refuse("not_found", "restore worker: no plan");
    if (Object.hasOwn(p, "closed")) refuse("not_granted", "restore worker: the restore is closed");
    if (!Object.hasOwn(p.sets, key)) refuse("not_found", "restore worker: not a set of this restore");
    if (p.sets[key].run !== run) refuse("not_granted", "restore worker: another run of this set");
    if (!requested(key, run, { dir, uid })) refuse("not_granted", "restore worker: the set's request isn't this run");
    // Its dispatch's input (d2 §3), read under the lock: missing (invalidated, d2 §4), another dispatch's or another
    // run's refuses, with nothing written.
    const input = readInput(kind, id, { dir, uid });
    if (input === null || input.run !== run || input.nonce !== nonce) refuse("not_granted", "restore worker: not this dispatch's input");
    // An abandon intent ends the worker before anything.
    if (readIntent(kind, id, { dir, uid }) !== null) return { status: "abandoning", record: readRecord(kind, id, { dir }) };
    // A bound destination must still be exactly that identity (§3 case 2): else failed, nothing touched.
    const r = readRecord(kind, id, { dir });
    if (r !== null && r.dest !== null && !["validated", "not_fitting", "failed", "abandoned"].includes(r.state)) {
      const now = {};
      for (const cls of CLASSES[kind]) now[cls] = await deps.identifyDest(kind, id, cls);
      guard();
      const dest = Object.fromEntries(CLASSES[kind].map((c) => [c, destOf(now[c].object)]));
      if (!sameDest(kind, r.dest, dest)) {
        const failed = step(r, "failed", { reason: "outcome_unknown" });
        writeRecord(failed, { dir });
        return { status: "failed", record: failed };
      }
    }
    guard();
    const provisioned = async (k, i, cls) => destOf(input.classes[cls].dest.object);
    const fillSet = deps.filler({
      admit: async (rec, ids, dest) => {
        guard();
        // The recorded identity is of this epoch and filesystem, or nothing is admitted (requalify first).
        for (const cls of CLASSES[kind]) {
          const want = input.classes[cls].dest, got = ids[cls];
          if (got?.fsid !== want.fsid || got?.epoch?.boot_id !== want.epoch.boot_id || got?.epoch?.mnt_id !== want.epoch.mnt_id) {
            refuse("not_granted", `restore worker: ${kind}-${id}'s ${cls} is recorded in another epoch`);
          }
        }
        await admitBind(rec, ids, dest, { provisioned, isEmpty: deps.isEmpty });
        guard();
      },
      veto: async () => { guard(); return readIntent(kind, id, { dir, uid }) !== null; },
    }, input);
    const out = await fillSet(kind, id, p, { signal: ac.signal });
    guard();
    return { status: out.state, record: out };
  } finally {
    clearInterval(poll);
    await held.release();
  }
}

/**
 * The executor's short `restore-dispatch` (§3), advisory. `deps`:
 * - gateOpen(): the suspend gate open now (lease.mjs's readGate);
 * - admitted(kind, id): the caller's advisory admission (the agent provisioned, restore raised, its slice empty;
 *   an archive's destination present; a tag's members admitted);
 * - inputOf(kind, id, run, nonce): the set's input built from the store (restore-inputs.mjs buildInput), or null when a
 *   trusted identity is missing (no record, or another epoch): no input and no worker then (d2 §2);
 * - start(argv): start the worker's scope, resolving once systemd accepted it (never awaiting the worker);
 * - main: the worker's main module (absolute); newNonce() (a test seam).
 * The input is written durably BEFORE the start; a settled set's input is removed. Resolves to { dispatched: key } or
 * { dispatched: null, why } (and `no_identity`: the sets skipped for want of a trusted identity).
 */
export async function dispatchOnce(deps, { dir = RESTORE_DIR, uid = 0, lock = lockFile } = {}) {
  let b, p;
  try { b = readBegin({ dir }); p = readPlan({ dir }); } catch { return { dispatched: null, why: "unreadable" }; }
  if (b === null || p === null) return { dispatched: null, why: "no_restore" };
  if (b.state !== "done") return { dispatched: null, why: "begun" };
  if (Object.hasOwn(p, "closed")) return { dispatched: null, why: "closed" };
  if (!(await deps.gateOpen())) return { dispatched: null, why: "suspended" };
  const keys = Object.keys(p.sets).sort();
  // One worker per host: any live worker and none is started.
  for (const k of keys) { const { kind, id } = parseKey(k); if (await workerLive(kind, id, { dir, lock })) return { dispatched: null, why: "busy" }; }
  const noIdentity = [];
  for (const k of keys) {
    const { kind, id } = parseKey(k);
    const run = p.sets[k].run;
    if (!requested(k, run, { dir, uid })) continue;
    if (readIntent(kind, id, { dir, uid }) !== null) continue;
    const r = readRecord(kind, id, { dir });
    // A settled set needs no input any more: removed here, by the queue (never by a worker).
    if (r !== null && SETTLED.includes(r.state)) { removeInputs([k], { dir, uid }); continue; }
    if (r !== null && r.state === "files_validated") continue;
    if ((await deps.admitted(kind, id)) !== true) continue;
    const nonce = deps.newNonce ? deps.newNonce() : newId();
    const input = await deps.inputOf(kind, id, run, nonce);
    if (input === null) { noIdentity.push(k); continue; }
    if (input.kind !== kind || input.id !== id || input.run !== run || input.nonce !== nonce) refuse("bad_form", "restore worker: an input for another set");
    // Durable before the start: a write or sync that fails starts nothing.
    writeInput(input, { dir, uid });
    await deps.start(workerArgv(kind, id, run, nonce, { main: deps.main, ...(deps.node ? { node: deps.node } : {}), ...(deps.mount ? { mount: deps.mount } : {}) }));
    return { dispatched: k };
  }
  return { dispatched: null, why: "idle", ...(noIdentity.length ? { no_identity: noIdentity } : {}) };
}

/**
 * Take and hold the locks of every set that touches `agent` (its own, its archive, a tag folder of `tags`) for a
 * lifecycle op's effects (§3): resolves to { release() } holding them all, or null (taking none) when any is held, by
 * a worker or another holder; `invalidate()` removes those sets' inputs (d2 §4). Only sets of an OPEN plan can have a worker (a worker refuses anything else before any
 * effect, and no plan begins while the supervisor runs), so only their locks are taken; with no open restore here the
 * holder holds nothing.
 */
export async function holdSets(agent, tags, { dir = RESTORE_DIR, uid = 0, lock = lockFile } = {}) {
  if (!isId(agent) || !Array.isArray(tags) || !tags.every(isId)) refuse("bad_form", "restore worker: bad agent");
  const none = { release: async () => {}, invalidate: () => {} };
  let b, p;
  try { b = readBegin({ dir }); p = readPlan({ dir }); } catch (e) {
    // No restore directory at all: nothing to hold. Anything else unreadable: refused, as a held set (fail closed).
    if (e?.code === "ENOENT") return none;
    return null;
  }
  if (b === null || p === null || Object.hasOwn(p, "closed")) return none;
  const keys = [...new Set([`agent-${agent}`, `archive-${agent}`, ...tags.map((t) => `tag-${t}`)])].filter((k) => Object.hasOwn(p.sets, k)).sort();
  const held = [];
  const release = async () => { for (const h of held.splice(0).reverse()) await h.release(); };
  try {
    for (const k of keys) {
      const { kind, id } = parseKey(k);
      held.push(await lock(setLockPath(dir, kind, id), { waitMs: 0 }));
    }
  } catch (e) {
    await release();
    if (e?.code === "in_progress") return null;
    throw e;
  }
  // d2 §4: remove the held sets' inputs, durably, before the caller changes a fact they copy.
  return { release, invalidate: () => removeInputs(keys, { dir, uid }) };
}

/**
 * Stop a set's worker and prove it gone (§3: a person stop, close or abandon): kill its scope, then wait, bounded,
 * for systemd to report the scope gone. `sys`: { killScope(unit), scopeGone(unit) }. Resolves true once proven.
 */
export async function stopWorker(kind, id, { sys, wait = (ms) => new Promise((r) => setTimeout(r, ms)), tries = 50, ms = 100 }) {
  const unit = workerScope(kind, id);
  try { await sys.killScope(unit); } catch { /* the proof decides */ }
  for (let i = 0; i < tries; i++) {
    if (await sys.scopeGone(unit)) return true;
    await wait(ms);
  }
  return false;
}
