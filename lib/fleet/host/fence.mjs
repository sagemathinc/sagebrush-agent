// Host supervisor (design: agent-autonomous-host-supervisor-freeze-r3.1.md §3.3, §3.4, §7): the stop fences and the stop
// sequence. It runs without the supervisor (the local `stop-all` uses it directly), so a hung or crashed supervisor
// can't keep agents running or bring them back.
//
// Fences, one file per cause under /var/lib/sagebrush/fence/ (root 0700); each is lowered ONLY by its own cause:
//   all          raised by stop-all, or a stop/revoke of all     lowered by a person-signed resume of all
//   <agent id>   raised by a stop/revoke/delete of that agent    lowered by a person-signed resume of that agent
//                                                               (never for a revoked or deleted agent)
//   expiry       raised when the grant expires                  lowered by a newer valid grant
//   backup/<id>  raised by a backup run before it freezes the    lowered only by the backup's own journal path
//                agent (host backup §4)                         (backup-journal.mjs), never while the slice is frozen
//   lease/<id>   raised at supervisor start, at a lease's        lowered ONLY by the lease activation helper (lease.mjs),
//                expiry and by its watchdog (execution lease §2) never through lowerFence here
// Every agent unit carries ConditionPathExists=! for its fence files (unit.mjs), so systemd itself skips a fenced start.
// A backup fence never runs the stop sequence: the backup freezes the agent's slice instead.
//
// The stop sequence: (1) write the fence durably; (2) stop the slice or unit; (3) cancel start jobs for the affected
// units and re-stop any that became active, at most 5 rounds within the deadline (a start that passed its condition
// check before the fence existed is not stopped by the fence alone); (4) check the cgroup is empty; (5) report
// "stopped and fenced" only when the fence is durable and the tree is empty. If the fence can't be written, steps 2–4
// still run and the result is "killed, not durable": nothing claims a durable no-restart then. Audit is the caller's,
// after this returns, best effort (a stop never waits on audit).
//
// Root agents (§4.5): a root agent can act outside its cgroup (units, timers, processes elsewhere) and can remove fences,
// so no stop is proven complete on a host where one is installed. Every result then carries best_effort: true, whatever
// its status; also when the installed units couldn't be read. Only a host with no root agent unit gets best_effort: false.

import { execFileSync } from "node:child_process";
import * as fs from "node:fs";
import { dirname, join } from "node:path";
import { isId, refuse } from "../bytes.mjs";
import { AGENT_SLICE, FENCE_DIR, UNIT_DIR, agentSlice, agentUnit } from "./names.mjs";
import { lockDir, realIo } from "./store.mjs";

export const CAUSES = Object.freeze(["all", "agent", "expiry", "backup", "lease"]);
/** Which authority may lower which fence here (`lease` is lowered only by the activation helper, lease.mjs). */
const LOWERED_BY = Object.freeze({ all: "resume-all", agent: "resume-agent", expiry: "newer-grant", backup: "backup-recovery" });
/** The causes a stop sequence may raise (backup isn't one: a backup freezes, it never stops). */
const STOP_CAUSES = Object.freeze(["all", "agent", "expiry", "lease"]);
/** The stop causes that fence one agent (the others fence all). */
const STOP_PER_AGENT = Object.freeze(["agent", "lease"]);
const AGENT_UNIT = /^sagebrush-agent-[a-z2-7]{25}[aeimquy4]\.service$/;

function fenceName(cause, agent) {
  if (!CAUSES.includes(cause)) refuse("bad_form", "fence: unknown cause");
  if (cause === "agent" || cause === "backup" || cause === "lease") {
    if (!isId(agent)) refuse("bad_form", "fence: bad agent id");
    return cause === "agent" ? agent : `${cause}/${agent}`;
  }
  return cause;
}

/**
 * Every fence change (raise, lower) and the whole stop sequence hold ONE interprocess lock, <fence dir>/.lock, shared
 * by the local stop-all, the supervisor's stops and expiry, and every lower. The supervisor's start path takes it too
 * (withFenceLock) while it checks the fences and issues a start, so no start can slip between a raise and a drain.
 */
export async function withFenceLock(fn, { dir = FENCE_DIR, waitMs = 5000 } = {}) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const lock = await lockDir(dir, { waitMs });
  try { return await fn(lock); } finally { await lock.release(); }
}

/**
 * Raise a fence durably, under the fence lock the caller holds: create (or keep) the file, fsync it, fsync the
 * directory, then confirm it is still there. Throws on any failure.
 */
export function raiseFence(cause, agent, { dir = FENCE_DIR, io = realIo } = {}) {
  const name = fenceName(cause, agent);
  const parent = dirname(join(dir, name));
  fs.mkdirSync(parent, { recursive: true, mode: 0o700 });
  const fd = io.open(join(dir, name), "a", 0o600);
  try { io.fsync(fd); } finally { io.close(fd); }
  // The file's directory, then (for a cause in its own subdirectory) the fence directory that holds that one.
  for (const d of parent === dir ? [dir] : [parent, dir]) {
    const dfd = io.open(d, "r");
    try { io.fsync(dfd); } finally { io.close(dfd); }
  }
  if (!fs.existsSync(join(dir, name))) throw Object.assign(new Error("the fence vanished"), { code: "EIO" });
}

/** Is any of an agent's fences up? (The supervisor's own check before every start and step.) */
export function fenced(agent, { dir = FENCE_DIR } = {}) {
  if (!isId(agent)) refuse("bad_form", "fence: bad agent id");
  return ["all", agent, "expiry", `backup/${agent}`, `lease/${agent}`].some((n) => fs.existsSync(join(dir, n)));
}

/** The registry states from which an agent may be resumed (its own fence lowered). Anything else fails closed. */
const RESUMABLE = Object.freeze(["provisioned", "running", "paused", "stopped"]);

/**
 * Lower a fence, only by its own cause's authority: "resume-all" lowers all, "resume-agent" lowers the agent's,
 * "newer-grant" lowers expiry. For the agent's own fence, `agentState` must be the agent's authoritative registry
 * state and one of RESUMABLE: missing, unknown, revoked or deleted refuses. Under the fence lock; durable (unlink,
 * fsync the directory).
 */
export async function lowerFence(cause, agent, authority, { dir = FENCE_DIR, agentState, waitMs = 5000 } = {}) {
  const name = fenceName(cause, agent);
  if (cause === "lease") refuse("not_granted", "fence: only the lease activation helper lowers lease");
  if (LOWERED_BY[cause] !== authority) refuse("not_granted", "fence: only its own cause lowers a fence");
  if (cause === "agent" && !RESUMABLE.includes(agentState)) refuse("not_granted", "fence: no authoritative resumable state for this agent");
  await withFenceLock(() => {
    try { fs.unlinkSync(join(dir, name)); } catch (e) { if (e.code !== "ENOENT") throw e; }
    let dfd;
    try { dfd = fs.openSync(dirname(join(dir, name)), "r"); } catch (e) { if (e.code === "ENOENT") return; throw e; } // never raised
    try { fs.fsyncSync(dfd); } finally { fs.closeSync(dfd); }
  }, { dir, waitMs });
}

/**
 * Count the processes in a cgroup tree. A cgroup that doesn't exist at the top is proven absent (0); any other error
 * (an unreadable directory or cgroup.procs, a subtree that vanished mid-walk) throws: unknown is never "empty".
 */
export function countProcs(top, fsx = fs) {
  let n = 0;
  const walk = (d, isTop) => {
    let entries;
    try { entries = fsx.readdirSync(d, { withFileTypes: true }); } catch (e) {
      if (e?.code === "ENOENT" && isTop) return;
      throw e;
    }
    n += fsx.readFileSync(join(d, "cgroup.procs"), "utf8").split("\n").filter(Boolean).length;
    for (const e of entries) if (e.isDirectory()) walk(join(d, e.name), false);
  };
  walk(top, true);
  return n;
}

/** The agent units in a unit directory that run as root (User=root in the generated file). Throws if it can't tell. */
export function rootUnitsIn(dir, fsx = fs) {
  return fsx.readdirSync(dir).filter((n) => AGENT_UNIT.test(n)).filter((n) => /^User=root$/m.test(fsx.readFileSync(join(dir, n), "utf8")));
}

/**
 * The real systemd, by argv (never a shell). Every call takes the time it may use (`ms`), never more. procCount
 * distinguishes a cgroup that doesn't exist (the unit is gone: 0) from one it couldn't read (it throws), so an
 * unreadable tree is never reported empty.
 */
export const realSystemd = Object.freeze({
  stop: (unit, ms) => { execFileSync("systemctl", ["stop", unit], { stdio: "ignore", timeout: ms }); },
  jobs: (ms) => String(execFileSync("systemctl", ["list-jobs", "--no-legend", "--plain"], { timeout: ms })).trim().split("\n").filter(Boolean)
    .map((l) => { const [id, unit, type] = l.trim().split(/\s+/); return { id: Number(id), unit, type }; }),
  cancel: (id, ms) => { execFileSync("systemctl", ["cancel", String(id)], { stdio: "ignore", timeout: ms }); },
  activeAgentUnits: (ms) => String(execFileSync("systemctl", ["list-units", "--no-legend", "--plain", "--state=active,activating,deactivating,reloading", "sagebrush-agent-*.service"], { timeout: ms }))
    .trim().split("\n").filter(Boolean).map((l) => l.trim().split(/\s+/)[0]),
  rootUnits: (ms, dir = UNIT_DIR) => rootUnitsIn(dir),
  procCount: (unit, ms) => {
    const cg = String(execFileSync("systemctl", ["show", "-p", "ControlGroup", "--value", unit], { timeout: ms })).trim();
    if (!cg) return 0; // systemd reports no cgroup: the unit has none
    return countProcs(join("/sys/fs/cgroup", cg));
  },
});

/**
 * Steps 2-4 of the stop sequence, with no fence and no lock of its own: stop the slice or unit, cancel start jobs and
 * re-stop anything active until a round proves the drain (at most maxRounds), then read the process count. Everything
 * fits in the time `left()` reports. Returns { drained, empty, count, rounds }; count is null when unknown.
 */
async function drainWithin(unit, affected, { sys, left, maxRounds, barrier }) {
  const tryStop = (u) => { if (left() <= 0) return false; try { sys.stop(u, left()); return true; } catch { return false; } };
  tryStop(unit);
  await barrier("after_slice_stop", { unit });
  let rounds = 0, drained = false;
  while (rounds < maxRounds && left() > 0) {
    rounds += 1;
    let pending, active, ok = true;
    try { pending = sys.jobs(left()).filter((j) => j.type === "start" && affected(j.unit)); } catch { ok = false; pending = null; }
    if (pending) for (const j of pending) {
      if (left() <= 0) { ok = false; break; }
      try { sys.cancel(j.id, left()); } catch { ok = false; }
    }
    await barrier("after_job_cancel", { round: rounds });
    if (left() <= 0) break;
    try { active = sys.activeAgentUnits(left()).filter(affected); } catch { ok = false; active = null; }
    if (active) for (const u of active) if (!tryStop(u)) ok = false;
    if (ok && pending && active && pending.length === 0 && active.length === 0) { drained = true; break; }
  }
  let count = null;
  if (left() > 0) { try { count = sys.procCount(unit, left()); } catch { count = null; } }
  if (left() < 0) count = null; // a read that overran the budget proves nothing
  return { drained, empty: count === 0, count, rounds };
}

/**
 * The drain of one agent's unit (steps 2-4) for a caller that already holds the fence lock and decides itself about a
 * fence (the executor containing a failed start, pause or revocation). Its own budget, deadlineMs.
 */
export async function drainAgent(agent, { sys = realSystemd, deadlineMs = 15000, maxRounds = 5, now = Date.now, barrier = async () => {} } = {}) {
  if (!isId(agent)) refuse("bad_form", "drain: bad agent id");
  const unit = agentUnit(agent), t0 = now();
  return drainWithin(unit, (u) => u === unit, { sys, left: () => deadlineMs - (now() - t0), maxRounds, barrier });
}

/**
 * Stop with a fence. `target`: { all: true } or { agent: <id> }; `cause`: "all" | "agent" | "expiry" (expiry stops all)
 * | "lease" (one agent: its whole slice is stopped, the unit and every turn scope; execution lease §2).
 * Options: { sys = realSystemd, dir, io, deadlineMs = 15000, maxRounds = 5, now = Date.now, barrier } (barrier: a test
 * hook, awaited after the fence write, the first stop and each cancel round; production passes none).
 * The whole sequence, every command and the final observation included, fits in deadlineMs: each command is given
 * only the time that remains, and nothing starts once it is spent.
 * Returns { status, reason, fenced, drained, empty, rounds, best_effort } (best_effort: a root agent unit is installed,
 * or that couldn't be read or the budget was spent before it was; see the header):
 * - "stopped and fenced": the fence is durable, a round PROVED the drain (the job list and the active-unit list were
 *   both read and showed nothing for the affected units) and the process count was read as 0;
 * - "killed, not durable" (reason "fence"): drained and empty were proven, but the fence couldn't be written;
 * - "not empty" (reason "not empty"): the count was read and isn't 0, whatever happened to the fence: never a kill;
 * - "not durable": nothing proven to be stopped (reason "drain": a failed or timed-out read, a failed cancel, the
 *   rounds or budget spent; reason "count": the process count couldn't be read within the budget).
 */
export async function stop(target, cause, { sys = realSystemd, dir = FENCE_DIR, io = realIo, deadlineMs = 15000, maxRounds = 5, now = Date.now, barrier = async () => {} } = {}) {
  if (!STOP_CAUSES.includes(cause)) refuse("bad_form", "stop: unknown cause"); // before any effect
  const all = target?.all === true;
  if (!all && !isId(target?.agent)) refuse("bad_form", "stop: a target is all or one agent");
  if (STOP_PER_AGENT.includes(cause) && all) refuse("bad_form", "stop: the agent and lease causes fence one agent");
  if (!STOP_PER_AGENT.includes(cause) && !all) refuse("bad_form", "stop: only the agent and lease causes fence one agent");
  const unit = all ? AGENT_SLICE : cause === "lease" ? agentSlice(target.agent) : agentUnit(target.agent);
  const affected = (u) => AGENT_UNIT.test(u) && (all || u === agentUnit(target.agent));
  const t0 = now();
  const left = () => deadlineMs - (now() - t0);

  // (0) The fence lock, waited for at most a third of the budget. Without it the stop still runs (a stop is never
  // blocked), but nothing it does can be durable.
  let lock = null;
  try { fs.mkdirSync(dir, { recursive: true, mode: 0o700 }); lock = await lockDir(dir, { waitMs: Math.max(1, Math.floor(left() / 3)) }); } catch { lock = null; }
  try {

  // (1) The fence first. A failure here is reported, never a reason not to kill.
  let fencedOk = lock !== null;
  try { raiseFence(cause, all ? null : target.agent, { dir, io }); } catch { fencedOk = false; }
  await barrier("after_fence_write", { cause });

  // (2)-(4) Stop, cancel and drain, then read the tree.
  const { drained, empty, count, rounds } = await drainWithin(unit, affected, { sys, left, maxRounds, barrier });

  // (5) Report. The fence counts only if the lock was held from before the raise until now.
  if (lock && !lock.held()) fencedOk = false;
  let status, reason;
  if (count !== null && count > 0) { status = "not empty"; reason = "not empty"; }
  else if (!drained) { status = "not durable"; reason = "drain"; }
  else if (!empty) { status = "not durable"; reason = "count"; }
  else if (!fencedOk) { status = "killed, not durable"; reason = "fence"; }
  else { status = "stopped and fenced"; reason = null; }
  let bestEffort = true;
  if (left() > 0) { try { bestEffort = sys.rootUnits(left()).length > 0; } catch { bestEffort = true; } }
  if (left() <= 0) bestEffort = true; // false only for an empty scan that finished within the budget
  return { status, reason, fenced: fencedOk, drained, empty, rounds, best_effort: bestEffort };
  } finally { if (lock) await lock.release(); }
}
