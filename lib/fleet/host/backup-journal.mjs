// Host backup (design: agent-autonomous-host-backup.md r3.3 §4): the consistent pass's journal and its recovery.
//
// A run's consistent pass is a journaled state machine, one journal per host at <BACKUP_DIR>/run.json:
//   intent → fenced → idle → frozen → confirmed → thawed → released
// Each step is written (atomically, durably) BEFORE it acts, so after a crash the journal names at least as much as was
// done. A run covers one agent, or every member agent of a tag folder (frozen together); its worker runs in
// <run's scope>, in BACKUP_SLICE, outside every agent's slice.
//
// Recovery, from any state, always in this order (§4: "kill and reap the backup worker's scope, then thaw, then lower
// only the backup fence"):
//   1. kill the worker's scope (cgroup.kill) and prove it empty;
//   2. thaw every member's slice (cgroup.freeze 0) and read back `frozen 0` from cgroup.events;
//   3. only if 1 and 2 are proven for every member: take the journal lock and, holding it, prove 1 and 2 AGAIN for the
//      same run, immediately before lowering ONLY the members' `backup` fences; then mark the journal released and
//      aborted (the warm snapshot is forgotten later, by the run's own cleanup).
// The fence is never lowered while a member's slice may still be frozen, nor while the worker may still be running.
// The proofs are repeated under the lock because the run itself starts its worker and freezes only while holding that
// same lock: a proof taken before the lock could be undone by a supervisor that held it meanwhile.
//
// recoverBackup is STANDALONE (the lease watchdog and the system-sleep hook call it, lease r3.10 §2.1 step 6): it
// takes no supervisor lock; steps 1 and 2 go straight to the cgroup files and need no lock at all, each within its own
// deadline; only step 3 needs the journal lock, which it tries for at most `lockWaitMs`. When that lock is busy (a hung
// supervisor), `backup` simply stays raised, a stop-only fence that the supervisor's recovery reconciles later.

import * as fs from "node:fs";
import { join } from "node:path";
import { isId, refuse } from "../bytes.mjs";
import { lowerFence } from "./fence.mjs";
import { BACKUP_DIR, BACKUP_SLICE_CGROUP, FENCE_DIR, agentSliceCgroup, backupScopeCgroup } from "./names.mjs";
import { exactKeys, lockDir, realIo, writeDurable } from "./store.mjs";

export const STATES = Object.freeze(["intent", "fenced", "idle", "frozen", "confirmed", "thawed", "released"]);
export const JOURNAL = "run.json";
const KEYS = ["v", "run", "agents", "scope", "state", "warm", "aborted"];
const RUN = /^[0-9]{8}T[0-9]{6}Z-[a-z2-7]{8}$/;
const SCOPE = (run) => `sagebrush-backup-${run}.scope`;
/** A tag folder's members are frozen together; a run never names more agents than this. */
export const MAX_AGENTS = 64;

/** The journal's closed shape. Returns the journal, or refuses. */
export function checkJournal(j) {
  const ok = exactKeys(j, KEYS) && j.v === 1 && typeof j.run === "string" && RUN.test(j.run)
    && Array.isArray(j.agents) && j.agents.length >= 1 && j.agents.length <= MAX_AGENTS && j.agents.every(isId)
    && new Set(j.agents).size === j.agents.length
    && j.scope === SCOPE(j.run) && STATES.includes(j.state)
    && (j.warm === null || (typeof j.warm === "string" && /^[0-9a-f]{64}$/.test(j.warm)))
    && typeof j.aborted === "boolean" && (!j.aborted || j.state === "released");
  if (!ok) refuse("bad_form", "backup journal: not a valid journal");
  return j;
}

/** A new journal in state `intent`. `run`: "<UTC stamp>-<8 base32 chars>"; `agents`: one agent, or a tag's members. */
export function newJournal(run, agents) {
  return checkJournal({ v: 1, run, agents: [...agents], scope: SCOPE(run), state: "intent", warm: null, aborted: false });
}

/**
 * Read the journal: null when there is none (no run), the journal when it is whole and valid. A file that is present
 * but unreadable or invalid throws: it is never "no run".
 */
export function readJournal({ dir = BACKUP_DIR, fsx = fs } = {}) {
  let text;
  try { text = fsx.readFileSync(join(dir, JOURNAL), "utf8"); } catch (e) { if (e?.code === "ENOENT") return null; throw e; }
  let j;
  try { j = JSON.parse(text); } catch { refuse("bad_form", "backup journal: not JSON"); }
  return checkJournal(j);
}

/** Write the journal durably (temp, fsync, rename, directory fsync). Throws on any failure. */
export function writeJournal(j, { dir = BACKUP_DIR, io = realIo } = {}) {
  checkJournal(j);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  writeDurable(dir, JOURNAL, JSON.stringify(j) + "\n", io);
}

/**
 * The next journal: exactly one step forward, never back or past a step. The caller writes it (writeJournal) before
 * it acts on it.
 */
export function advance(j, next) {
  checkJournal(j);
  if (j.aborted) refuse("not_granted", "backup journal: an aborted run doesn't advance");
  const i = STATES.indexOf(j.state);
  if (STATES[i + 1] !== next) refuse("not_granted", `backup journal: ${j.state} can't go to ${next}`);
  return { ...j, state: next };
}

/** Remove the journal (the run is over and cleaned up), durably. */
export function clearJournal({ dir = BACKUP_DIR } = {}) {
  try { fs.unlinkSync(join(dir, JOURNAL)); } catch (e) { if (e?.code !== "ENOENT") throw e; }
  const dfd = fs.openSync(dir, "r");
  try { fs.fsyncSync(dfd); } finally { fs.closeSync(dfd); }
}

/** Run `fn` under the journal lock, <dir>/.lock, waited for at most waitMs. Refuses with in_progress when busy. */
export async function withJournalLock(fn, { dir = BACKUP_DIR, waitMs = 0 } = {}) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const lock = await lockDir(dir, { waitMs });
  try { return await fn(lock); } finally { await lock.release(); }
}

/**
 * The cgroup files, directly (no systemd, no lock). Paths are cgroup directories.
 * - kill(cg): write 1 to cgroup.kill (works on frozen tasks too). A cgroup that doesn't exist is already empty.
 * - procs(cg): the processes in the whole tree; 0 for a cgroup that doesn't exist; throws when unreadable.
 * - freeze(cg, on): write 1 or 0 to cgroup.freeze.
 * - frozen(cg): cgroup.events' `frozen` as a boolean; false for a cgroup that doesn't exist (nothing is frozen);
 *   throws when unreadable or when the line is missing.
 */
export const realCgroup = Object.freeze({
  kill: (cg) => { try { fs.writeFileSync(join(cg, "cgroup.kill"), "1"); } catch (e) { if (e?.code !== "ENOENT") throw e; } },
  procs: (cg) => {
    let n = 0;
    const walk = (d, top) => {
      let entries;
      try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch (e) { if (e?.code === "ENOENT" && top) return; throw e; }
      n += fs.readFileSync(join(d, "cgroup.procs"), "utf8").split("\n").filter(Boolean).length;
      for (const e of entries) if (e.isDirectory()) walk(join(d, e.name), false);
    };
    walk(cg, true);
    return n;
  },
  freeze: (cg, on) => { fs.writeFileSync(join(cg, "cgroup.freeze"), on ? "1" : "0"); },
  frozen: (cg) => {
    let text;
    try { text = fs.readFileSync(join(cg, "cgroup.events"), "utf8"); } catch (e) { if (e?.code === "ENOENT") return false; throw e; }
    const m = /^frozen ([01])$/m.exec(text);
    if (!m) throw Object.assign(new Error("cgroup.events has no frozen line"), { code: "EIO" });
    return m[1] === "1";
  },
});

const sleepMs = (ms) => new Promise((r) => setTimeout(r, ms));

/** Poll `check` (true when done; a throw counts as not done) until it holds or `ms` passes. */
async function until(check, ms, { now, sleep }) {
  const t0 = now();
  for (;;) {
    let ok = false;
    try { ok = check(); } catch { ok = false; }
    if (ok) return true;
    if (now() - t0 >= ms) return false;
    await sleep(Math.min(50, Math.max(1, ms - (now() - t0))));
  }
}

/** Kill and reap a worker scope: true only when the scope's tree is proven empty within ms. */
async function reap(scopeCg, ms, { cg, now, sleep }) {
  try { cg.kill(scopeCg); } catch { /* proven or not by the count below */ }
  return until(() => cg.procs(scopeCg) === 0, ms, { now, sleep });
}

/** Thaw one slice: true only when `frozen 0` is read back within ms. */
async function thaw(sliceCg, ms, { cg, now, sleep }) {
  return until(() => { if (cg.frozen(sliceCg)) cg.freeze(sliceCg, false); return cg.frozen(sliceCg) === false; }, ms, { now, sleep });
}

/** The backup fence of one agent, as a path. */
const backupFence = (fenceDir, agent) => join(fenceDir, "backup", agent);

/**
 * Abort the run that holds `agent`, in the recovery order (header). Standalone: no supervisor lock; the reap and the
 * thaw need no lock; only the fence lowering takes the journal lock, tried for at most lockWaitMs, and the fence lock,
 * within what remains of it.
 *
 * Options: { lockWaitMs = 2000, reapMs = 5000, thawMs = 5000, dir, fenceDir, cg, now, sleep }.
 * Returns { run, reaped, thawed, backupLowered, state }:
 * - no journal, or a run that doesn't name `agent`: a no-op, { run: null, reaped: true, thawed: true,
 *   backupLowered: <no backup fence of agent's is up>, state: null };
 * - a journal that can't be read: the whole backup slice is killed and `agent`'s own slice thawed (nothing else is
 *   known), and the fence stays: { run: null, reaped, thawed, backupLowered: false, state: "unknown" };
 * - otherwise, the run's whole tag (every member) is recovered; `state` is the journal's state afterwards
 *   ("released" once the fences are lowered, else what it was). `reaped` and `thawed` are the LAST proofs taken: the
 *   ones under the journal lock when it was held for the same run, else the ones before it.
 */
export async function recoverBackup(agent, {
  lockWaitMs = 2000, reapMs = 5000, thawMs = 5000, dir = BACKUP_DIR, fenceDir = FENCE_DIR, cg = realCgroup,
  now = Date.now, sleep = sleepMs,
} = {}) {
  if (!isId(agent)) refuse("bad_form", "backup recovery: bad agent id");
  const env = { cg, now, sleep };
  let j;
  try { j = readJournal({ dir }); } catch {
    const reaped = await reap(BACKUP_SLICE_CGROUP, reapMs, env); // the whole backup slice: which run is unknown
    const thawed = await thaw(agentSliceCgroup(agent), thawMs, env);
    return { run: null, reaped, thawed, backupLowered: false, state: "unknown" };
  }
  if (j === null || !j.agents.includes(agent)) {
    return { run: null, reaped: true, thawed: true, backupLowered: !fs.existsSync(backupFence(fenceDir, agent)), state: null };
  }

  // 1. The worker, then 2. every member's slice. Both without any lock.
  let reaped = await reap(backupScopeCgroup(j.scope), reapMs, env);
  let thawed = true;
  for (const a of j.agents) if (!(await thaw(agentSliceCgroup(a), thawMs, env))) thawed = false;
  if (!reaped || !thawed) return { run: j.run, reaped, thawed, backupLowered: false, state: j.state };

  // 3. The fences, under the journal lock, within lockWaitMs in all (the fence lock gets what remains).
  const t0 = now();
  const left = () => Math.max(1, lockWaitMs - (now() - t0));
  let state = j.state;
  try {
    let proven = true;
    await withJournalLock(async () => {
      const cur = readJournal({ dir });
      if (cur === null || cur.run !== j.run) { state = cur?.state ?? null; return; } // the run ended meanwhile
      // The proofs again, holding the lock, right before any fence comes down. These are what the result reports:
      // the earlier ones may have been undone while the lock was held elsewhere.
      reaped = await reap(backupScopeCgroup(cur.scope), reapMs, env);
      thawed = true;
      for (const a of cur.agents) if (!(await thaw(agentSliceCgroup(a), thawMs, env))) thawed = false;
      proven = reaped && thawed;
      if (!proven) { state = cur.state; return; }
      for (const a of cur.agents) await lowerFence("backup", a, "backup-recovery", { dir: fenceDir, waitMs: left() });
      if (cur.state !== "released" || !cur.aborted) writeJournal({ ...cur, state: "released", aborted: true }, { dir });
      state = "released";
    }, { dir, waitMs: lockWaitMs });
    if (!proven) return { run: j.run, reaped, thawed, backupLowered: false, state };
  } catch {
    return { run: j.run, reaped, thawed, backupLowered: false, state: readStateOr(dir, j.state) };
  }
  return { run: j.run, reaped, thawed, backupLowered: j.agents.every((a) => !fs.existsSync(backupFence(fenceDir, a))), state };
}

function readStateOr(dir, fallback) {
  try { return readJournal({ dir })?.state ?? null; } catch { return fallback; }
}
