// Host backup (design: agent-autonomous-host-backup.md r3.3 §4): the backup of one source set, with the consistent
// pass as a journaled state machine (backup-journal.mjs). Nothing schedules this yet; the scheduler does, later.
//
// For an agent or a tag (its live members frozen together):
//   1. warm pass, live, never restorable: the journal's intent record first (it names the run, so a crash leaves a
//      warm snapshot that recovery forgets), then a backup tagged sb-state=warm and sb-run=<run>;
//   2. fenced: each member's backup fence, so admission stops before anything waits;
//   3. idle: up to 10 minutes for the members' active turns to reach zero (the injected lease interface). If they
//      don't, the pass goes on and the snapshot says consistency=crash;
//   4. frozen: every member's slice frozen and read back `frozen 1`;
//   5. confirmed: the consistent backup, with the warm snapshot as its parent, tagged sb-state=good;
//   6. thawed: the worker's scope proven empty, every slice thawed and read back `frozen 0`;
//   7. released: only the members' backup fences lowered;
//   then the good snapshot is read back from the store, the warm one forgotten, and the journal cleared.
// Each step is written to the journal before it acts. Every time the run takes the journal lock again after waiting
// (the warm pass, the idle wait, the read-back), it re-reads the journal and goes on only if it is still THIS run, in
// the step it left, not aborted: a recovery (a lease stop, a sleep) may have ended it meanwhile, or another run may
// have started, and the run never overwrites or clears a journal that isn't its own. Steps 4 to 7 run while THIS
// process holds the journal lock:
// the worker is started and the slices frozen only under it (backup-journal.mjs's rule), and a standalone recovery
// (a lease stop, a sleep) then re-proves everything under that lock before it lowers a fence.
// **The freeze cap, 5 minutes** from the freeze: past it, or on any failure from step 2 on, the pass is abandoned in
// the recovery order (abortHeld): nothing new is kept, and the previous good snapshot stays.
// **Any error thrown** after the intent record (a fence, freeze or thaw step, the binary, the disk) is caught here
// and goes through the standalone recovery order (recoverBackup) before backupSet returns: a partial tag fence or
// freeze is never left behind by a throw.
// A deleted agent's archive is never live, so it is backed up directly (no fence, no freeze), and so is the host
// store's staging copy.
//
// **sb-state=good is a candidate tag only, never authority.** rustic tags are written when the snapshot is made, so
// a good pass's snapshot carries sb-state=good before it is read back, and also when its run is abandoned later.
// Listing and restore never trust that tag: the host manifest, committed last and read back (backup-manifest.mjs),
// is the ONLY authority for what is listed and what can be restored.

import { spawn } from "node:child_process";
import { isId, refuse } from "../bytes.mjs";
import { raiseFence, withFenceLock } from "./fence.mjs";
import {
  abortHeld, advance, clearJournal, freezeSlice, newJournal, readJournal, realCgroup, reapScope, recoverBackup, thawSlice, withJournalLock,
  writeJournal,
} from "./backup-journal.mjs";
import { BACKUP_DIR, BACKUP_SLICE, FENCE_DIR, agentSliceCgroup, backupScopeCgroup } from "./names.mjs";

export const LIMITS = Object.freeze({
  idleMs: 10 * 60 * 1000, // step 3
  capMs: 5 * 60 * 1000, // from the freeze to the thaw
  warmMs: 6 * 60 * 60 * 1000, // the live pass (it reads most of the data)
  readbackMs: 60 * 60 * 1000,
  freezeMs: 10 * 1000, thawMs: 10 * 1000, reapMs: 10 * 1000, lockWaitMs: 10 * 1000, pollMs: 1000,
});
const RUN = /^[0-9]{8}T[0-9]{6}Z-[a-z2-7]{8}$/;
const KINDS = Object.freeze(["agent", "tag", "archive", "hoststore"]);

/** The scope a run's worker runs in (in BACKUP_SLICE, outside every agent slice). */
export const workerUnit = (run) => `sagebrush-backup-${run}`;

/**
 * The argv prefix that puts a command in the run's worker scope: `systemd-run --scope` runs it in place (the same
 * process, so the caller's process-group kill still reaches it) under the given unit name, in BACKUP_SLICE.
 */
export function scopedArgv(run, bin, argv) {
  if (!RUN.test(run)) refuse("bad_form", "backup run: bad run id");
  return ["/usr/bin/systemd-run", ["--scope", "--quiet", "--collect", `--unit=${workerUnit(run)}`, `--slice=${BACKUP_SLICE}`, "--", bin, ...argv]];
}

/** backup-binary's spawnFn for one run: the binary, in the run's worker scope. */
export const scopedSpawn = (run, spawnFn = spawn) => (bin, argv, opts) => {
  const [cmd, args] = scopedArgv(run, bin, argv);
  return spawnFn(cmd, args, opts);
};

const tagsOf = (set, run, state, consistency) => {
  const t = [`sb-run=${run}`, `sb-state=${state}`, `sb-kind=${set.kind}`];
  if (set.kind === "agent") t.push(`agent=${set.id}`);
  if (set.kind === "archive") t.push(`archive=${set.id}`);
  if (set.kind === "tag") t.push(`tag=${set.id}`);
  if (consistency) t.push(`consistency=${consistency}`);
  return t;
};

/**
 * Back up one source set. `set`: from backupSources (or { kind: "hoststore", id: null, sources, members: [] }).
 * `deps`:
 * - binary(req, { ms, run }): the backup binary (backup-binary.runBackupOp with the run's scoped spawn); resolves to
 *   { ok, value } or { ok: false, code, message };
 * - lease.activeTurns(agent): the agent's active turn leases (a number; it may reject: then not idle);
 * - host: this host's id for the snapshot; parent: the set's last good snapshot id or null; excludes: globs;
 * - cg, dir, fenceDir, now, sleep, limits: for tests.
 * Resolves to { outcome: "good" | "failed" | "abandoned", snapshot, consistency, warm, code, recovered }, where
 * `recovered` is the recovery-order result when the pass was abandoned (with the fence still up if it couldn't
 * prove the thaw: the caller raises the high-priority item and retries recovery).
 */
export async function backupSet(set, run, deps) {
  if (!KINDS.includes(set?.kind) || !Array.isArray(set.sources) || set.sources.length === 0) refuse("bad_form", "backup run: bad source set");
  if (!RUN.test(run)) refuse("bad_form", "backup run: bad run id");
  const L = { ...LIMITS, ...(deps.limits ?? {}) };
  const env = { cg: deps.cg ?? realCgroup, now: deps.now ?? Date.now, sleep: deps.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms))) };
  const dir = deps.dir ?? BACKUP_DIR, fenceDir = deps.fenceDir ?? FENCE_DIR;
  const backupReq = (state, parent, consistency) => ({
    op: "backup", sources: set.sources, host: deps.host, tags: tagsOf(set, run, state, consistency),
    ...(parent ? { parent } : {}), ...(deps.excludes?.length ? { excludes: deps.excludes } : {}),
  });

  // Not live: one backup, read back.
  if (set.kind === "archive" || set.kind === "hoststore" || set.members.length === 0) {
    const r = await deps.binary(backupReq("good", deps.parent ?? null, null), { ms: L.warmMs, run });
    if (!r.ok) return { outcome: "failed", snapshot: null, consistency: null, warm: null, code: r.code, recovered: null };
    return readBack(r.value.snapshot.id, null, null, deps, L, run);
  }
  if (!set.members.every(isId)) refuse("bad_form", "backup run: bad member id");

  /** The journal is still this run's, at `state`, not aborted. */
  const ours = (cur, state) => cur !== null && cur.run === run && cur.state === state && !cur.aborted;
  const recovered = () => ({ outcome: "abandoned", snapshot: null, consistency: null, warm: null, code: "recovered", recovered: null });

  // 1. Intent, then the warm pass (live).
  let j = newJournal(run, set.members);
  await withJournalLock(async () => {
    if (readJournal({ dir }) !== null) refuse("in_progress", "backup run: another run's journal is present");
    writeJournal(j, { dir });
  }, { dir, waitMs: L.lockWaitMs });
  let warmId = null;
  try {
    return await consistentPass();
  } catch {
    // A throw from any step: the recovery order, standalone (it takes the journal lock itself, which this run no
    // longer holds once the throw has left withJournalLock).
    const rec = await recoverBackup(set.members[0], { dir, fenceDir, lockWaitMs: L.lockWaitMs, reapMs: L.reapMs, thawMs: L.thawMs, ...env });
    return { outcome: "abandoned", snapshot: null, consistency: null, warm: warmId, code: "error", recovered: rec };
  }

  async function consistentPass() {
  const warm = await deps.binary(backupReq("warm", deps.parent ?? null, null), { ms: L.warmMs, run });
  if (!warm.ok) {
    await withJournalLock(() => { if (readJournal({ dir })?.run === run) clearJournal({ dir }); }, { dir, waitMs: L.lockWaitMs });
    return { outcome: "failed", snapshot: null, consistency: null, warm: null, code: warm.code, recovered: null };
  }
  warmId = warm.value.snapshot.id;

  // 2. Fenced: written first, then raised; only if the run is still ours at intent.
  let gone = false;
  await withJournalLock(async () => {
    const cur = readJournal({ dir });
    if (!ours(cur, "intent")) {
      // Ended meanwhile: if it was this run, name its warm snapshot in the record so cleanup forgets it.
      if (cur?.run === run && cur.warm === null) writeJournal({ ...cur, warm: warmId }, { dir });
      gone = true; return;
    }
    j = advance({ ...cur, warm: warmId }, "fenced"); writeJournal(j, { dir });
    await withFenceLock(() => { for (const a of j.agents) raiseFence("backup", a, { dir: fenceDir }); }, { dir: fenceDir, waitMs: L.lockWaitMs });
    // 3. Idle is written in the same hold (no window between the two), then waited for with no lock held: a stop
    // must be able to recover while the run waits.
    j = advance(j, "idle"); writeJournal(j, { dir });
  }, { dir, waitMs: L.lockWaitMs });
  if (gone) return { ...recovered(), warm: warmId };
  const idle = await untilIdle(j.agents, deps.lease, L, env);
  const consistency = idle ? "turn" : "crash";

  // 4-7 under the journal lock, with the cap.
  let result = null;
  await withJournalLock(async () => {
    const cur = readJournal({ dir });
    // A recovery (a lease stop, a sleep) may have ended this run while it waited: then there is nothing to freeze.
    if (!ours(cur, "idle")) { result = { outcome: "abandoned", code: "recovered", recovered: null }; return; }
    const t0 = env.now();
    const abandon = async (code) => {
      const now = readJournal({ dir });
      const recovered = await abortHeld(now, { reapMs: L.reapMs, thawMs: L.thawMs, dir, fenceDir, fenceWaitMs: L.lockWaitMs, ...env });
      result = { outcome: "abandoned", code, recovered };
    };
    j = advance(cur, "frozen"); writeJournal(j, { dir });
    for (const a of j.agents) {
      if (!(await freezeSlice(agentSliceCgroup(a), L.freezeMs, env))) { await abandon("freeze_failed"); return; }
    }
    const left = L.capMs - (env.now() - t0);
    if (left <= 0) { await abandon("cap"); return; }
    const good = await deps.binary(backupReq("good", j.warm, consistency), { ms: left, run });
    if (!good.ok) { await abandon(good.code === "timed_out" ? "cap" : good.code); return; }
    j = advance(j, "confirmed"); writeJournal(j, { dir });
    j = advance(j, "thawed"); writeJournal(j, { dir });
    let thawed = await reapScope(backupScopeCgroup(j.scope), L.reapMs, env);
    if (thawed) for (const a of j.agents) if (!(await thawSlice(agentSliceCgroup(a), L.thawMs, env))) thawed = false;
    if (!thawed) { await abandon("thaw_failed"); return; } // the fence stays unless the recovery order proves the thaw
    j = advance(j, "released"); writeJournal(j, { dir });
    // The release lowers only the members' backup fences, after the same proofs again (reaped, thawed).
    const released = await abortHeld(j, { reapMs: L.reapMs, thawMs: L.thawMs, dir, fenceDir, fenceWaitMs: L.lockWaitMs, ...env, finish: true });
    if (released.state !== "released" || !released.reaped || !released.thawed) { result = { outcome: "abandoned", code: "thaw_failed", recovered: released }; return; }
    result = { outcome: "frozen-done", snapshot: good.value.snapshot.id };
  }, { dir, waitMs: L.lockWaitMs });

  if (result.outcome !== "frozen-done") {
    return { outcome: "abandoned", snapshot: null, consistency: null, warm: j.warm, code: result.code, recovered: result.recovered };
  }
  return readBack(result.snapshot, consistency, j.warm, deps, L, run, dir);
  }
}

/**
 * Every member idle (no active turn) within idleMs, ONE deadline for the whole wait: each lease read gets only what
 * is left of it, and a read that fails, or doesn't answer in that time, counts as not idle. So a hung lease read
 * can't keep the members fenced past idleMs.
 */
async function untilIdle(agents, lease, L, env) {
  const t0 = env.now();
  const left = () => L.idleMs - (env.now() - t0);
  const TIMEOUT = Symbol("timeout");
  for (;;) {
    let idle = true;
    for (const a of agents) {
      if (left() <= 0) { idle = false; break; }
      let n, timer;
      const bound = new Promise((r) => { timer = setTimeout(() => r(TIMEOUT), Math.max(0, left())); });
      try { n = await Promise.race([Promise.resolve().then(() => lease.activeTurns(a)), bound]); } catch { n = null; } finally { clearTimeout(timer); }
      if (n !== 0) idle = false;
    }
    if (idle) return true;
    if (env.now() - t0 >= L.idleMs) return false;
    await env.sleep(Math.min(L.pollMs, L.idleMs - (env.now() - t0)));
  }
}

/**
 * Read the good snapshot back from the store (success is only this), then forget the warm one and clear the journal.
 * A read-back failure leaves the snapshot unconfirmed: the outcome is failed and nothing references it.
 */
async function readBack(snapshot, consistency, warm, deps, L, run, dir = null) {
  const rb = await deps.binary({ op: "readback", snapshot }, { ms: L.readbackMs, run });
  if (warm) await deps.binary({ op: "forget", snapshots: [warm] }, { ms: L.readbackMs, run }); // best effort: recovery forgets what's left
  if (dir) {
    // The run's record must still be its own, released, not aborted: a recovery may have ended it meanwhile, or
    // another run started. Only then is it cleared and the outcome good; otherwise the record is left as it is.
    let still = false;
    await withJournalLock(() => {
      const cur = readJournal({ dir });
      still = cur !== null && cur.run === run && cur.state === "released" && !cur.aborted;
      if (still) clearJournal({ dir });
    }, { dir, waitMs: L.lockWaitMs });
    if (!still) return { outcome: "abandoned", snapshot: null, consistency: null, warm, code: "recovered", recovered: null };
  }
  if (!rb.ok || rb.value.findings !== 0) {
    return { outcome: "failed", snapshot: null, consistency, warm, code: rb.ok ? "check_failed" : rb.code, recovered: null };
  }
  return { outcome: "good", snapshot, consistency, warm, code: null, recovered: null };
}
