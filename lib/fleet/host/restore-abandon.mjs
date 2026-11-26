// Host restore e2e r1.7 §5, delta R5-d2 §3.2–§3.5: an accepted abandon's FINISH. Its input is the durable intent
// (restore-sidecars.mjs), the authority of an abandon once accepted; the signed op that writes it is R5b's, behind G3.
// Nothing here creates an intent.
//
// - **The binding, `boundIntent`,** before the kill, before the first destructive effect, and again under the three
//   locks before the terminal write: the typed intent names this set; begin is done and its run is the intent's
//   restore_run; the plan is open and holds the set at exactly the intent's set_run and set_snapshot; the record is
//   absent or at that set run and snapshot. Anything else refuses with NO kill and NO cleanup.
// - **The order:** the kill (the set's worker scope, proven gone; the set lock is never tried first); then under the
//   set lock alone: the FINAL record re-read, every bound destination emptied whatever the state (validated included),
//   all of the set's staging discarded, its validation copies removed, and the attestation written; then, in §1's order,
//   §1's lock, the restore lock and the set lock: the binding, the attestation equal to the record, every bound
//   destination live and empty, the staging gone, and only then `abandoned`.
// - **An accepted intent is final (§3.3):** a set that reached validated after its intent was accepted is finished like
//   any other, by `step(r, "abandoned", { accepted_intent: true })`, from this terminal write alone.
// - **Recovery (`finishOnce`, the host op on the restore tick):** every set of the open plan with an intent whose record
//   isn't abandoned, in key order. One set's stale or malformed sidecar is reported and skipped: it never stops another.

import { isId, refuse } from "../bytes.mjs";
import { RESTORE_DIR } from "./names.mjs";
import { KINDS, newRecord, readRecord, step, writeRecord } from "./restore-record.mjs";
import { readPlan } from "./restore-plan.mjs";
import { ABANDON, parseKey, provenDir, readBegin } from "./restore-begin.mjs";
import { attestationName, attestationText, attests, auditPair, readAttestationFile, readIntentFile } from "./restore-sidecars.mjs";
import { realIo, writeDurable } from "./store.mjs";

const keyOf = (kind, id) => {
  if (!KINDS.includes(kind) || !isId(id)) refuse("bad_form", "restore abandon: bad set");
  return `${kind}-${id}`;
};
/** The proven abandon directory, or null when there is none. */
function abandonDirOf(dir, uid) {
  try { return provenDir(dir, ABANDON, { uid }); } catch (e) { if (e?.code === "ENOENT") return null; throw e; }
}

/**
 * The set's accepted intent, bound to this restore now (R5-d2 §3.2): { intent, record }. Refuses not_granted (stale:
 * another restore, a plan binding that moved, a record of another set run or snapshot, a set not in the plan, a closed
 * or unbegun restore) or bad_form (malformed); not_found when there is no intent.
 */
export function boundIntent(kind, id, { dir = RESTORE_DIR, uid = 0 } = {}) {
  const key = keyOf(kind, id);
  const adir = abandonDirOf(dir, uid);
  const found = adir === null ? null : readIntentFile(adir, kind, id);
  if (found === null) refuse("not_found", "restore abandon: no intent for the set");
  const { intent } = found;
  const stale = (why) => refuse("not_granted", `restore abandon: ${key}'s intent is stale (${why})`);
  const b = readBegin({ dir });
  if (b === null || b.state !== "done") stale("no begun restore");
  if (b.run !== intent.restore_run) stale("another restore");
  const p = readPlan({ dir });
  if (p === null || Object.hasOwn(p, "closed")) stale("the restore isn't open");
  if (!Object.hasOwn(p.sets, key)) stale("not a set of the plan");
  if (p.sets[key].run !== intent.set_run || p.sets[key].snapshot !== intent.set_snapshot) stale("the plan's binding moved");
  const record = readRecord(kind, id, { dir });
  if (record !== null && (record.run !== intent.set_run || record.snapshot !== intent.set_snapshot)) stale("the record is another run's");
  return { intent, record, abandonDir: adir, restoreRun: b.run };
}

/**
 * An already-abandoned set is done only with its audit pair complete (R5-d2 §3.8): the finish's success, never a
 * silent one. A missing, malformed or mismatching intent or attestation refuses (not_granted: corrupt).
 */
function doneIfAudited(r, bound) {
  auditPair(r, bound.abandonDir, { restoreRun: bound.restoreRun });
  return { status: "abandoned" };
}

/**
 * Finish one set's accepted abandon. `deps`:
 * - stop(kind, id): kill the set's worker scope and prove it gone → true (restore-worker.mjs stopWorker);
 * - lockSet(kind, id): take the set lock now → { release() }, or refuse in_progress (held);
 * - withLocks(fn): run fn under §1's lock, then the restore lock (both only tried: a loser refuses in_progress);
 * - cleanDest(r), isEmpty(r, cls) (the class's bound object identified live, that identity, and empty),
 *   discardAll(r), stagingGone(r), removeCopies(r): the launcher's (restore-adapters.mjs destTools, stagingRemover);
 * - now(): ms.
 * Resolves to { status }: "abandoned" (written now, or already), "unproven" (the kill not proven), "busy" (the set or
 * the outer locks held), or "reproof_failed" (nothing written; the next tick runs it again). A stale or malformed
 * intent refuses before any effect.
 */
export async function finishAbandon(kind, id, deps, { dir = RESTORE_DIR, uid = 0, io = realIo } = {}) {
  keyOf(kind, id);
  // 1. The binding, then the kill.
  const first = boundIntent(kind, id, { dir, uid });
  if (first.record?.state === "abandoned") return doneIfAudited(first.record, first);
  if ((await deps.stop(kind, id)) !== true) return { status: "unproven" };
  // 2. Under the set lock alone: clean from the FINAL record, then attest.
  let held;
  try { held = await deps.lockSet(kind, id); } catch (e) { if (e?.code === "in_progress") return { status: "busy" }; throw e; }
  try {
    const bound = boundIntent(kind, id, { dir, uid });
    const { intent, abandonDir } = bound;
    let r = readRecord(kind, id, { dir });
    if (r === null) {
      // (a set that never started: its record, at the intent's binding, so the terminal write has one to step)
      r = newRecord({ kind, id, run: intent.set_run, snapshot: intent.set_snapshot });
      writeRecord(r, { dir, io });
    }
    if (r.state === "abandoned") return doneIfAudited(r, bound);
    if (r.dest !== null) await deps.cleanDest(r);
    await deps.discardAll(r);
    await deps.removeCopies(r);
    writeDurable(abandonDir, attestationName(kind, id), attestationText(r, deps.now()), io);
  } finally {
    await held.release();
  }
  // 3. §1's lock, the restore lock, then the set lock: the re-proof and the terminal write.
  let out;
  try {
    out = await deps.withLocks(async () => {
      const set = await deps.lockSet(kind, id);
      try {
        const bound = boundIntent(kind, id, { dir, uid });
        const { record: r, abandonDir } = bound;
        if (r === null) return { status: "reproof_failed" };
        if (r.state === "abandoned") return doneIfAudited(r, bound);
        const a = readAttestationFile(abandonDir, kind, id);
        if (a === null || !attests(a.attestation, r)) return { status: "reproof_failed" };
        if (r.dest !== null) {
          for (const cls of Object.keys(r.dest)) if ((await deps.isEmpty(r, cls)) !== true) return { status: "reproof_failed" };
        }
        if ((await deps.stagingGone(r)) !== true) return { status: "reproof_failed" };
        // (a set that reached validated after its intent was accepted: the finish's own transition, §3.3)
        const done = step(r, "abandoned", r.state === "validated" ? { accepted_intent: true } : {});
        writeRecord(done, { dir, io });
        return { status: "abandoned" };
      } finally {
        await set.release();
      }
    });
  } catch (e) {
    if (e?.code === "in_progress") return { status: "busy" };
    throw e;
  }
  return out;
}

/**
 * The host's `restore-abandon-finish` op (§3.4): every set of the open plan with an intent, in key order. One whose
 * record isn't abandoned is finished; an abandoned one is audited (its pair complete, this restore's) and reported
 * `corrupt` when it isn't, never skipped silently. `depsOf(kind, id)` → finishAbandon's deps. A set whose finish
 * refuses (a stale or malformed intent, an I/O error) is reported and the next is still finished. Resolves to
 * { sets: { key: result } }: a set already abandoned and audited is not listed (nothing changed).
 */
export async function finishOnce(depsOf, { dir = RESTORE_DIR, uid = 0, io = realIo, signal } = {}) {
  let b, p;
  try { b = readBegin({ dir }); p = readPlan({ dir }); } catch { return { sets: {}, why: "unreadable" }; }
  if (b === null || p === null || b.state !== "done" || Object.hasOwn(p, "closed")) return { sets: {} };
  const adir = abandonDirOf(dir, uid);
  if (adir === null) return { sets: {} };
  const out = {};
  for (const k of Object.keys(p.sets).sort()) {
    if (signal?.aborted) break;
    const { kind, id } = parseKey(k);
    let r;
    try {
      if (readIntentPresent(adir, kind, id) === false) continue;
      r = readRecord(kind, id, { dir });
    } catch (e) { out[k] = { status: "refused", reason: e?.code ?? "unreadable" }; continue; }
    if (r?.state === "abandoned") {
      try { auditPair(r, adir, { restoreRun: b.run }); } catch (e) { out[k] = { status: "corrupt", reason: e?.code ?? "unreadable" }; }
      continue;
    }
    try { out[k] = await finishAbandon(kind, id, depsOf(kind, id), { dir, uid, io }); } catch (e) {
      out[k] = { status: "refused", reason: e?.code ?? "host-side failure" };
    }
  }
  return { sets: out };
}

/** Is there an intent file for the set (present, whatever its content: a malformed one is the finish's refusal)? */
function readIntentPresent(adir, kind, id) {
  try { return readIntentFile(adir, kind, id) !== null; } catch (e) { if (e?.code === "bad_form" || e?.code === "not_granted") return true; throw e; }
}
