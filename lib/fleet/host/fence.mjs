// Host supervisor (design: agent-autonomous-host-supervisor-freeze-r3.1.md §3.3, §3.4, §7): the stop fences and the stop
// sequence. It runs without the supervisor (the local `stop-all` uses it directly), so a hung or crashed supervisor
// can't keep agents running or bring them back.
//
// Fences, one file per cause under /var/lib/sagebrush/fence/ (root 0700); each is lowered ONLY by its own cause:
//   all          raised by stop-all, or a stop/revoke of all     lowered by a person-signed resume of all
//   <agent id>   raised by a stop/revoke/delete of that agent    lowered by a person-signed resume of that agent
//                                                               (never for a revoked or deleted agent)
//   expiry       raised when the grant expires                  lowered by a newer valid grant
// Every agent unit carries ConditionPathExists=! for its three files (unit.mjs), so systemd itself skips a fenced start.
//
// The stop sequence: (1) write the fence durably; (2) stop the slice or unit; (3) cancel start jobs for the affected
// units and re-stop any that became active, at most 5 rounds within the deadline (a start that passed its condition
// check before the fence existed is not stopped by the fence alone); (4) check the cgroup is empty; (5) report
// "stopped and fenced" only when the fence is durable and the tree is empty. If the fence can't be written, steps 2–4
// still run and the result is "killed, not durable": nothing claims a durable no-restart then. Audit is the caller's,
// after this returns, best effort (a stop never waits on audit).

import { execFileSync } from "node:child_process";
import * as fs from "node:fs";
import { join } from "node:path";
import { isId, refuse } from "../bytes.mjs";
import { AGENT_SLICE, FENCE_DIR, agentUnit } from "./names.mjs";
import { realIo } from "./store.mjs";

export const CAUSES = Object.freeze(["all", "agent", "expiry"]);
/** Which authority may lower which fence. */
const LOWERED_BY = Object.freeze({ all: "resume-all", agent: "resume-agent", expiry: "newer-grant" });
const AGENT_UNIT = /^sagebrush-agent-[a-z2-7]{25}[aeimquy4]\.service$/;

function fenceName(cause, agent) {
  if (!CAUSES.includes(cause)) refuse("bad_form", "fence: unknown cause");
  if (cause === "agent") { if (!isId(agent)) refuse("bad_form", "fence: bad agent id"); return agent; }
  return cause;
}

/** Raise a fence durably: create (or keep) the file, fsync it, fsync the directory. Throws on any failure. */
export function raiseFence(cause, agent, { dir = FENCE_DIR, io = realIo } = {}) {
  const name = fenceName(cause, agent);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const fd = io.open(join(dir, name), "a", 0o600);
  try { io.fsync(fd); } finally { io.close(fd); }
  const dfd = io.open(dir, "r");
  try { io.fsync(dfd); } finally { io.close(dfd); }
}

/** Is any of an agent's three fences up? (The supervisor's own check before every start and step.) */
export function fenced(agent, { dir = FENCE_DIR } = {}) {
  if (!isId(agent)) refuse("bad_form", "fence: bad agent id");
  return ["all", agent, "expiry"].some((n) => fs.existsSync(join(dir, n)));
}

/**
 * Lower a fence, only by its own cause's authority: "resume-all" lowers all, "resume-agent" lowers the agent's (and
 * never for a revoked or deleted agent: pass `agentState`), "newer-grant" lowers expiry. Durable (unlink, fsync dir).
 */
export function lowerFence(cause, agent, authority, { dir = FENCE_DIR, agentState = null } = {}) {
  const name = fenceName(cause, agent);
  if (LOWERED_BY[cause] !== authority) refuse("not_granted", "fence: only its own cause lowers a fence");
  if (cause === "agent" && (agentState === "revoked" || agentState === "deleted")) refuse("not_granted", "fence: a revoked or deleted agent stays fenced");
  try { fs.unlinkSync(join(dir, name)); } catch (e) { if (e.code !== "ENOENT") throw e; }
  const dfd = fs.openSync(dir, "r");
  try { fs.fsyncSync(dfd); } finally { fs.closeSync(dfd); }
}

/** The real systemd, by argv (never a shell). Each method is small so tests can replace it with a fake. */
export const realSystemd = Object.freeze({
  stop: (unit) => { execFileSync("systemctl", ["stop", unit], { stdio: "ignore", timeout: 15000 }); },
  jobs: () => String(execFileSync("systemctl", ["list-jobs", "--no-legend", "--plain"], { timeout: 5000 })).trim().split("\n").filter(Boolean)
    .map((l) => { const [id, unit, type] = l.trim().split(/\s+/); return { id: Number(id), unit, type }; }),
  cancel: (id) => { execFileSync("systemctl", ["cancel", String(id)], { stdio: "ignore", timeout: 5000 }); },
  activeAgentUnits: () => String(execFileSync("systemctl", ["list-units", "--no-legend", "--plain", "--state=active,activating,deactivating", "sagebrush-agent-*.service"], { timeout: 5000 }))
    .trim().split("\n").filter(Boolean).map((l) => l.trim().split(/\s+/)[0]),
  procCount: (unit) => {
    const cg = String(execFileSync("systemctl", ["show", "-p", "ControlGroup", "--value", unit], { timeout: 5000 })).trim();
    if (!cg) return 0;
    let n = 0;
    const walk = (d) => {
      let entries; try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
      try { n += fs.readFileSync(join(d, "cgroup.procs"), "utf8").split("\n").filter(Boolean).length; } catch {}
      for (const e of entries) if (e.isDirectory()) walk(join(d, e.name));
    };
    walk(join("/sys/fs/cgroup", cg));
    return n;
  },
});

/**
 * Stop with a fence. `target`: { all: true } or { agent: <id> }; `cause`: "all" | "agent" | "expiry" (expiry stops all).
 * Options: { sys = realSystemd, dir, deadlineMs = 15000, maxRounds = 5, now = Date.now }.
 * Returns { status: "stopped and fenced" | "killed, not durable" | "not empty", fenced, empty, rounds }.
 */
export function stop(target, cause, { sys = realSystemd, dir = FENCE_DIR, io = realIo, deadlineMs = 15000, maxRounds = 5, now = Date.now } = {}) {
  const all = target?.all === true;
  if (!all && !isId(target?.agent)) refuse("bad_form", "stop: a target is all or one agent");
  if (cause === "agent" && all) refuse("bad_form", "stop: the agent cause fences one agent");
  if (cause !== "agent" && !all) refuse("bad_form", "stop: only the agent cause fences one agent");
  const unit = all ? AGENT_SLICE : agentUnit(target.agent);
  const affected = (u) => AGENT_UNIT.test(u) && (all || u === unit);

  // (1) The fence first. A failure here is reported, never a reason not to kill.
  let fencedOk = true;
  try { raiseFence(cause, all ? null : target.agent, { dir, io }); } catch { fencedOk = false; }

  // (2) Stop. (3) Cancel start jobs and re-stop anything that became active, bounded.
  const t0 = now();
  let rounds = 0;
  const tryStop = (u) => { try { sys.stop(u); } catch { /* the empty check below decides */ } };
  tryStop(unit);
  while (rounds < maxRounds && now() - t0 <= deadlineMs) {
    rounds += 1;
    let pending = [];
    try { pending = sys.jobs().filter((j) => j.type === "start" && affected(j.unit)); } catch {}
    for (const j of pending) { try { sys.cancel(j.id); } catch {} }
    let active = [];
    try { active = sys.activeAgentUnits().filter(affected); } catch {}
    for (const u of active) tryStop(u);
    if (pending.length === 0 && active.length === 0) break;
  }

  // (4) The tree must be empty.
  let empty = false;
  try { empty = sys.procCount(unit) === 0; } catch { empty = false; }

  // (5) Report.
  const status = !fencedOk ? "killed, not durable" : empty ? "stopped and fenced" : "not empty";
  return { status, fenced: fencedOk, empty, rounds };
}
