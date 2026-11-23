// Host supervisor freeze r3.1 §3.3, §3.4, §7: the stop fences and the stop sequence, against a fake systemd that models
// start jobs both before and after their condition check. A stop raises its fence first under the one fence lock,
// stops, cancels and drains start jobs, and checks the tree; success needs a durable fence AND a proven drain AND a
// readable empty tree, all within one end-to-end budget; each fence is lowered only by its own cause, under the lock.
import assert from "node:assert/strict";
import { mkdtempSync, existsSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "./host-linux-only.mjs";
import { FleetError, newId } from "../lib/fleet/index.mjs";
import { stop, raiseFence, lowerFence, fenced, countProcs, rootUnitsIn, realSystemd } from "../lib/fleet/host/fence.mjs";
import { lockDir, realIo } from "../lib/fleet/host/store.mjs";

const refused = (fn, code) => assert.throws(fn, (e) => e instanceof FleetError && e.code === code, code);
const rejects = (p, code) => assert.rejects(p, (e) => e instanceof FleetError && e.code === code, code);
const unitOf = (a) => `sagebrush-agent-${a}.service`;
const fresh = () => join(mkdtempSync(join(tmpdir(), "sb-fence-")), "fence");

/**
 * A fake systemd. `units`: name -> { active, procs }. `jobs`: pending start jobs { id, unit, type, passed, ticks }:
 * `passed` means the job already passed its ConditionPathExists check (a fence written now can't stop it); `ticks` is
 * how many looks it stays pending before it activates. Pending jobs progress whenever the stopper looks at the system.
 */
function fakeSystemd(dir, { units = {}, jobs = [], stubborn = false, roots = [] } = {}) {
  const calls = [];
  const fenceUp = (unit) => { const a = unit.slice(16, 42); return ["all", a, "expiry"].some((n) => existsSync(join(dir, n))); };
  const progress = () => {
    for (const j of [...jobs]) {
      if (j.type !== "start") continue;
      if (!j.passed && fenceUp(j.unit)) { jobs.splice(jobs.indexOf(j), 1); continue; } // condition fails: skipped
      if (j.ticks-- > 0) continue;
      jobs.splice(jobs.indexOf(j), 1);
      units[j.unit] = { active: true, procs: 3 };
    }
  };
  return {
    calls, units, jobs,
    stop: (u) => {
      calls.push(["stop", u]);
      for (const [name, st] of Object.entries(units)) if (u === name || u === "sagebrush-agents.slice") { st.active = stubborn; st.procs = stubborn ? 1 : 0; }
    },
    jobs: () => { progress(); return jobs.map((j) => ({ id: j.id, unit: j.unit, type: j.type })); },
    cancel: (id) => { calls.push(["cancel", id]); const i = jobs.findIndex((j) => j.id === id); if (i >= 0) jobs.splice(i, 1); },
    activeAgentUnits: () => { progress(); return Object.entries(units).filter(([, s]) => s.active).map(([n]) => n); },
    rootUnits: () => roots,
    procCount: (u) => Object.entries(units).filter(([n]) => u === n || u === "sagebrush-agents.slice").reduce((s, [, st]) => s + st.procs, 0),
  };
}

test("stop-all: fence first, then stop; a queued start is skipped by its condition and a past-condition start is cancelled", async () => {
  const dir = fresh();
  const [a, b, c] = [newId(), newId(), newId()];
  const sys = fakeSystemd(dir, {
    units: { [unitOf(a)]: { active: true, procs: 4 } },
    jobs: [{ id: 1, unit: unitOf(b), type: "start", passed: false, ticks: 0 }, { id: 2, unit: unitOf(c), type: "start", passed: true, ticks: 1 }],
  });
  const r = await stop({ all: true }, "all", { sys, dir });
  assert.deepEqual([r.status, r.reason, r.fenced, r.drained, r.empty], ["stopped and fenced", null, true, true, true]);
  assert.ok(existsSync(join(dir, "all")));
  assert.deepEqual(sys.calls[0], ["stop", "sagebrush-agents.slice"]);
  assert.ok(sys.calls.some((x) => x[0] === "cancel" && x[1] === 2), "the past-condition start was cancelled");
  assert.equal(sys.units[unitOf(c)], undefined, "it never became active");
  assert.equal(sys.units[unitOf(b)], undefined, "the queued start was skipped by its condition");
});

test("a past-condition start that becomes active before it can be cancelled is stopped again", async () => {
  const dir = fresh();
  const c = newId();
  const sys = fakeSystemd(dir, { jobs: [{ id: 7, unit: unitOf(c), type: "start", passed: true, ticks: 0 }] });
  const r = await stop({ all: true }, "all", { sys, dir });
  assert.equal(r.status, "stopped and fenced");
  assert.equal(sys.units[unitOf(c)].active, false);
  assert.ok(sys.calls.filter((x) => x[0] === "stop").length >= 2);
});

test("one agent: its own fence and unit only; other agents and their jobs untouched", async () => {
  const dir = fresh();
  const [a, other] = [newId(), newId()];
  const sys = fakeSystemd(dir, {
    units: { [unitOf(a)]: { active: true, procs: 2 }, [unitOf(other)]: { active: true, procs: 2 } },
    jobs: [{ id: 3, unit: unitOf(other), type: "start", passed: true, ticks: 5 }],
  });
  const r = await stop({ agent: a }, "agent", { sys, dir });
  assert.equal(r.status, "stopped and fenced");
  assert.ok(existsSync(join(dir, a)));
  assert.ok(!existsSync(join(dir, "all")));
  assert.equal(sys.units[unitOf(other)].active, true);
  assert.ok(!sys.calls.some((x) => x[0] === "cancel"));
  assert.deepEqual(sys.calls[0], ["stop", unitOf(a)]);
});

test("only start jobs are cancelled: a stop job for an agent unit is left alone", async () => {
  const dir = fresh();
  const a = newId();
  const sys = fakeSystemd(dir, { units: { [unitOf(a)]: { active: true, procs: 1 } }, jobs: [{ id: 9, unit: unitOf(a), type: "stop", passed: true, ticks: 0 }] });
  await stop({ all: true }, "all", { sys, dir });
  assert.ok(!sys.calls.some((x) => x[0] === "cancel" && x[1] === 9));
});

test("expiry fences all, as a separate file from a manual stop", async () => {
  const dir = fresh();
  await stop({ all: true }, "expiry", { sys: fakeSystemd(dir), dir });
  assert.ok(existsSync(join(dir, "expiry")));
  assert.ok(!existsSync(join(dir, "all")));
});

// ---- outcomes: success only with a durable fence, a proven drain and a readable empty tree

test("a fence that can't be written: the kill still runs; proven drained and empty -> killed, not durable", async () => {
  const root = mkdtempSync(join(tmpdir(), "sb-fence-"));
  const dir = join(root, "fence");
  const a = newId();
  const sys = fakeSystemd(dir, { units: { [unitOf(a)]: { active: true, procs: 3 } } });
  const failing = { ...realIo, fsync: () => { throw Object.assign(new Error("EIO"), { code: "EIO" }); } };
  const r = await stop({ all: true }, "all", { sys, dir, io: failing });
  assert.deepEqual([r.status, r.reason, r.fenced, r.empty], ["killed, not durable", "fence", false, true]);
  assert.equal(sys.units[unitOf(a)].active, false);
});

test("a fence that can't be written and a tree that won't empty: not empty, never a kill", async () => {
  const dir = fresh();
  const a = newId();
  const sys = fakeSystemd(dir, { units: { [unitOf(a)]: { active: true, procs: 1 } }, stubborn: true });
  const failing = { ...realIo, fsync: () => { throw Object.assign(new Error("EIO"), { code: "EIO" }); } };
  const r = await stop({ all: true }, "all", { sys, dir, io: failing });
  assert.deepEqual([r.status, r.reason, r.fenced], ["not empty", "not empty", false]);
});

test("a tree that won't empty: bounded rounds, not empty", async () => {
  const dir = fresh();
  const a = newId();
  const sys = fakeSystemd(dir, { units: { [unitOf(a)]: { active: true, procs: 1 } }, stubborn: true });
  const r = await stop({ all: true }, "all", { sys, dir, maxRounds: 5 });
  assert.deepEqual([r.status, r.reason, r.rounds], ["not empty", "not empty", 5]);
});

test("a passed-condition start that stays pending while cancel keeps failing is never reported stopped", async () => {
  const dir = fresh();
  const c = newId();
  const sys = fakeSystemd(dir, { jobs: [{ id: 5, unit: unitOf(c), type: "start", passed: true, ticks: 1000 }] });
  sys.cancel = () => { throw new Error("cancel failed"); };
  const r = await stop({ all: true }, "all", { sys, dir });
  assert.deepEqual([r.status, r.reason, r.drained], ["not durable", "drain", false]);
  assert.equal(sys.procCount("sagebrush-agents.slice"), 0, "(even though the snapshot is empty)");
});

test("a cancel that reports failure is not a proven drain, even if the job then disappears", async () => {
  const dir = fresh();
  const c = newId();
  const sys = fakeSystemd(dir, { jobs: [{ id: 6, unit: unitOf(c), type: "start", passed: true, ticks: 1000 }] });
  const realCancel = sys.cancel;
  let first = true;
  sys.cancel = (id) => { realCancel(id); if (first) { first = false; throw new Error("cancel reported failure"); } };
  const r = await stop({ all: true }, "all", { sys, dir, maxRounds: 1 });
  assert.deepEqual([r.status, r.reason], ["not durable", "drain"]);
});

test("a jobs() or activeAgentUnits() that throws is never an empty list", async () => {
  for (const broken of ["jobs", "activeAgentUnits"]) {
    const dir = fresh();
    const sys = fakeSystemd(dir);
    sys[broken] = () => { throw new Error("systemctl failed"); };
    const r = await stop({ all: true }, "all", { sys, dir });
    assert.deepEqual([r.status, r.reason], ["not durable", "drain"], broken);
  }
});

test("an unreadable process count is never empty", async () => {
  const dir = fresh();
  const sys = fakeSystemd(dir);
  sys.procCount = () => { throw Object.assign(new Error("EIO"), { code: "EIO" }); };
  const r = await stop({ all: true }, "all", { sys, dir });
  assert.deepEqual([r.status, r.reason, r.empty], ["not durable", "count", false]);
});

test("countProcs: a missing cgroup is proven absent; anything unreadable throws, never 0", () => {
  const err = (code) => () => { throw Object.assign(new Error(code), { code }); };
  const dirent = (name) => ({ name, isDirectory: () => true });
  const tree = { "/cg": [dirent("child")], "/cg/child": [] };
  const procs = { "/cg/cgroup.procs": "1\n2\n", "/cg/child/cgroup.procs": "3\n4\n5\n" };
  const ok = { readdirSync: (d) => { if (!(d in tree)) throw Object.assign(new Error("ENOENT"), { code: "ENOENT" }); return tree[d]; }, readFileSync: (f) => procs[f] };
  assert.equal(countProcs("/cg", ok), 5);
  assert.equal(countProcs("/gone", ok), 0);
  assert.throws(() => countProcs("/cg", { ...ok, readdirSync: err("EIO") }), /EIO/);
  assert.throws(() => countProcs("/cg", { ...ok, readFileSync: err("EIO") }), /EIO/);
  assert.throws(() => countProcs("/cg", { ...ok, readdirSync: (d) => { if (d === "/cg/child") throw Object.assign(new Error("ENOENT"), { code: "ENOENT" }); return tree[d]; } }), /ENOENT/);
});

// ---- one end-to-end budget

test("the budget starts before the first operation and bounds every command: worst-case adapters stay within it", async () => {
  const dir = fresh();
  const a = newId();
  let clock = 0;
  const given = [];
  const sys = fakeSystemd(dir, { units: { [unitOf(a)]: { active: true, procs: 1 } }, stubborn: true });
  for (const k of ["stop", "jobs", "cancel", "activeAgentUnits", "procCount"]) {
    const f = sys[k];
    sys[k] = (...args) => { const ms = args.find((x) => typeof x === "number" && x > 50) ?? args.at(-1); given.push([k, ms]); clock += Math.max(0, ms); return f(...args); };
  }
  const r = await stop({ all: true }, "all", { sys, dir, deadlineMs: 15000, now: () => clock });
  assert.ok(clock <= 15000, `elapsed ${clock} ms within the 15 s budget`);
  assert.equal(r.status, "not durable");
  assert.deepEqual(given.map(([k]) => k), ["stop"]);
  assert.ok(given.every(([, ms]) => ms > 0 && ms <= 15000));
});

test("a budget already spent runs no command at all, and is never success", async () => {
  const dir = fresh();
  const sys = fakeSystemd(dir);
  let clock = 0;
  const r = await stop({ all: true }, "all", { sys, dir, deadlineMs: 10, now: () => (clock += 20) });
  assert.deepEqual(sys.calls, []);
  assert.notEqual(r.status, "stopped and fenced");
});

test("a final count that overruns the budget proves nothing", async () => {
  const dir = fresh();
  let clock = 0;
  const sys = fakeSystemd(dir);
  sys.procCount = () => { clock += 20000; return 0; };
  const r = await stop({ all: true }, "all", { sys, dir, deadlineMs: 15000, now: () => clock });
  assert.deepEqual([r.status, r.reason], ["not durable", "count"]);
});

// ---- the one fence lock

test("while another holds the fence lock, a stop still kills but is not durable; a lower refuses", async () => {
  const dir = fresh();
  raiseFence("all", null, { dir });
  const held = await lockDir(dir);
  try {
    const a = newId();
    const sys = fakeSystemd(dir, { units: { [unitOf(a)]: { active: true, procs: 1 } } });
    // (A budget that leaves room for the lock wait, a third of it, even on a loaded machine.)
    const r = await stop({ all: true }, "all", { sys, dir, deadlineMs: 3000 });
    assert.equal(sys.units[unitOf(a)].active, false, "the kill ran");
    assert.deepEqual([r.status, r.reason, r.fenced], ["killed, not durable", "fence", false]);
    await rejects(lowerFence("all", null, "resume-all", { dir, waitMs: 100 }), "in_progress");
    assert.ok(existsSync(join(dir, "all")), "the fence stayed up");
  } finally { await held.release(); }
  await lowerFence("all", null, "resume-all", { dir });
  assert.ok(!existsSync(join(dir, "all")));
});

test("raise vs lower, both orders: a lower can't run inside a stop, and a stop after a lower re-raises the fence", async () => {
  const dir = fresh();
  const sys = fakeSystemd(dir);
  // Stop first, lower requested while the stop holds the lock: the lower waits, then runs after the stop finished.
  // The lower is requested from inside the stop's first systemctl call, so the stop already holds the lock (requesting
  // both at once would leave which one gets the lock first to the scheduler).
  let lowerDone = false, q = null;
  sys.stop = ((orig) => (...a) => {
    q ??= lowerFence("all", null, "resume-all", { dir, waitMs: 5000 }).then(() => { lowerDone = true; });
    return orig(...a);
  })(sys.stop);
  sys.jobs = ((orig) => () => { if (!lowerDone) assert.ok(existsSync(join(dir, "all")), "the fence is up for the whole stop"); return orig(); })(sys.jobs);
  const r = await stop({ all: true }, "all", { sys, dir });
  assert.ok(q, "the lower was requested during the stop");
  await q;
  assert.equal(r.status, "stopped and fenced");
  assert.ok(!existsSync(join(dir, "all")));
  // Lower first, then stop: the stop raises the fence again.
  const r2 = await stop({ all: true }, "all", { sys: fakeSystemd(dir), dir });
  assert.equal(r2.status, "stopped and fenced");
  assert.ok(existsSync(join(dir, "all")));
});

// ---- causes and authority

test("each fence is lowered only by its own cause; the agent's needs a known resumable state", async () => {
  const dir = fresh();
  const a = newId();
  raiseFence("all", null, { dir }); raiseFence("agent", a, { dir }); raiseFence("expiry", null, { dir });
  await rejects(lowerFence("all", null, "newer-grant", { dir }), "not_granted");
  await rejects(lowerFence("expiry", null, "resume-all", { dir }), "not_granted");
  await rejects(lowerFence("agent", a, "resume-all", { dir }), "not_granted");
  for (const agentState of [undefined, null, "", "unknown", "revoked", "deleted", "RUNNING"]) {
    await rejects(lowerFence("agent", a, "resume-agent", { dir, agentState }), "not_granted");
  }
  assert.equal(fenced(a, { dir }), true);
  await lowerFence("expiry", null, "newer-grant", { dir });
  assert.equal(fenced(a, { dir }), true, "a renewal doesn't lower a manual stop");
  await lowerFence("all", null, "resume-all", { dir });
  assert.equal(fenced(a, { dir }), true, "the agent's own fence is still up");
  await lowerFence("agent", a, "resume-agent", { dir, agentState: "stopped" });
  assert.equal(fenced(a, { dir }), false);
  await lowerFence("all", null, "resume-all", { dir }); // lowering an absent fence is fine
  for (const agentState of ["provisioned", "running", "paused", "stopped"]) {
    raiseFence("agent", a, { dir });
    await lowerFence("agent", a, "resume-agent", { dir, agentState });
    assert.equal(fenced(a, { dir }), false, agentState);
  }
});

test("an agent is fenced by any one of its three fences, expiry included", () => {
  for (const which of ["all", "agent", "expiry"]) {
    const dir = fresh();
    const a = newId();
    raiseFence(which, which === "agent" ? a : null, { dir });
    assert.equal(fenced(a, { dir }), true, which);
    assert.equal(fenced(newId(), { dir }), which !== "agent", `${which}, another agent`);
  }
});

test("the fence is durable before the stop: the fence file and its directory are fsynced first", async () => {
  const dir = fresh();
  const order = [];
  const fds = new Map();
  const io = { ...realIo, open: (p, f, m) => { const fd = realIo.open(p, f, m); fds.set(fd, p); return fd; }, fsync: (fd) => { order.push(["fsync", fds.get(fd)]); return realIo.fsync(fd); } };
  const sys = fakeSystemd(dir);
  const origStop = sys.stop;
  sys.stop = (u) => { order.push(["stop", u]); return origStop(u); };
  await stop({ all: true }, "all", { sys, dir, io });
  const firstStop = order.findIndex((x) => x[0] === "stop");
  const fsyncFile = order.findIndex((x) => x[0] === "fsync" && x[1] === join(dir, "all"));
  assert.ok(fsyncFile >= 0 && fsyncFile < firstStop);
  assert.ok(order.findIndex((x) => x[0] === "fsync" && x[1] === dir) < firstStop);
});

test("refused before any effect: an unknown cause, a bad target, a cause that doesn't fit the target", async () => {
  const dir = fresh();
  const sys = fakeSystemd(dir);
  await rejects(stop({ all: true }, "pause", { sys, dir }), "bad_form");
  await rejects(stop({ agent: "worker-1" }, "agent", { sys, dir }), "bad_form");
  await rejects(stop({ all: true }, "agent", { sys, dir }), "bad_form");
  await rejects(stop({ agent: newId() }, "all", { sys, dir }), "bad_form");
  await rejects(stop({}, "all", { sys, dir }), "bad_form");
  assert.deepEqual(sys.calls, []);
  assert.ok(!existsSync(join(dir, "all")));
  refused(() => raiseFence("pause", null, { dir }), "bad_form");
  refused(() => raiseFence("agent", "x", { dir }), "bad_form");
  refused(() => fenced("x", { dir }), "bad_form");
});

test("the fence lock is lost during the stop (its holder dies): the fence no longer counts", async () => {
  const dir = fresh();
  const sys = fakeSystemd(dir);
  const { execFileSync } = await import("node:child_process");
  const { readFileSync } = await import("node:fs");
  const orig = sys.jobs;
  let killed = false;
  sys.jobs = () => {
    if (!killed) {
      killed = true;
      const pids = String(execFileSync("pgrep", ["-f", join(dir, ".lock")])).trim().split("\n").filter(Boolean).map(Number);
      for (const p of pids) { try { process.kill(p, "SIGKILL"); } catch {} }
      const gone = (p) => { try { const st = readFileSync(`/proc/${p}/stat`, "utf8"); const c = st[st.lastIndexOf(")") + 2]; return c === "Z" || c === "X"; } catch { return true; } };
      const t = Date.now(); while (!pids.every(gone) && Date.now() - t < 5000) { /* spin */ }
    }
    return orig();
  };
  const r = await stop({ all: true }, "all", { sys, dir });
  assert.equal(r.fenced, false);
  assert.notEqual(r.status, "stopped and fenced");
});

test("a fence that vanishes during its own sync is not raised", async () => {
  const dir = fresh();
  const { unlinkSync } = await import("node:fs");
  const fds = new Map();
  const io = { ...realIo, open: (p, f, m) => { const fd = realIo.open(p, f, m); fds.set(fd, p); return fd; },
    fsync: (fd) => { if (fds.get(fd) === dir) { try { unlinkSync(join(dir, "all")); } catch {} } return realIo.fsync(fd); } };
  const r = await stop({ all: true }, "all", { sys: fakeSystemd(dir), dir, io });
  assert.deepEqual([r.status, r.fenced], ["killed, not durable", false]);
});

test("nothing runs once the budget is spent between commands: no active-unit read after a slow job list, no cancel after it", async () => {
  // A job list that uses up the budget: neither its cancels nor the active-unit read may run.
  const dir = fresh();
  const c = newId();
  let clock = 0;
  const sys = fakeSystemd(dir, { jobs: [{ id: 4, unit: unitOf(c), type: "start", passed: true, ticks: 1000 }] });
  const calls = [];
  const jobs = sys.jobs;
  sys.jobs = (ms) => { calls.push("jobs"); clock += 15000; return jobs(ms); };
  for (const k of ["cancel", "activeAgentUnits", "procCount"]) { const f = sys[k]; sys[k] = (...a) => { calls.push(k); return f(...a); }; }
  const r = await stop({ all: true }, "all", { sys, dir, deadlineMs: 15000, now: () => clock });
  assert.deepEqual(calls, ["jobs"]);
  assert.notEqual(r.status, "stopped and fenced");
});

// §4.5: a root agent can act outside its cgroup and remove fences, so no stop is proven complete on a host with one.
test("best_effort: false with no root agent unit installed; true whenever one is, whatever the status", async () => {
  const a = newId(), r = newId();
  const plain = await stop({ agent: a }, "agent", { sys: fakeSystemd(fresh(), { units: { [unitOf(a)]: { active: true, procs: 1 } } }), dir: fresh() });
  assert.equal(plain.status, "stopped and fenced");
  assert.equal(plain.best_effort, false);
  for (const target of [{ agent: a }, { agent: r }]) {
    const dir = fresh();
    const sys = fakeSystemd(dir, { units: { [unitOf(a)]: { active: true, procs: 1 }, [unitOf(r)]: { active: true, procs: 1 } }, roots: [unitOf(r)] });
    const res = await stop(target, "agent", { sys, dir });
    assert.equal(res.status, "stopped and fenced", "the cgroup result is still reported");
    assert.equal(res.best_effort, true);
  }
  const dir = fresh();
  const all = await stop({ all: true }, "all", { sys: fakeSystemd(dir, { roots: [unitOf(r)] }), dir });
  assert.equal(all.best_effort, true);
  const stuck = await stop({ all: true }, "all", { sys: fakeSystemd(dir, { units: { [unitOf(a)]: { active: true, procs: 1 } }, stubborn: true, roots: [unitOf(r)] }), dir, deadlineMs: 200 });
  assert.notEqual(stuck.status, "stopped and fenced");
  assert.equal(stuck.best_effort, true);
});

test("best_effort: true when the installed units can't be read, the budget is spent before they are, or the read overruns it", async () => {
  const dir = fresh();
  const sys = fakeSystemd(dir);
  sys.rootUnits = () => { throw Object.assign(new Error("EACCES"), { code: "EACCES" }); };
  const r1 = await stop({ all: true }, "all", { sys, dir });
  assert.equal(r1.status, "stopped and fenced");
  assert.equal(r1.best_effort, true);
  let clock = 0, looked = false;
  const sys2 = fakeSystemd(dir);
  sys2.procCount = () => { clock += 20000; return 0; };
  sys2.rootUnits = () => { looked = true; return []; };
  const r2 = await stop({ all: true }, "all", { sys: sys2, dir, now: () => clock });
  assert.equal(r2.best_effort, true);
  assert.equal(looked, false, "nothing runs once the budget is spent");
  // A read that overruns the budget proves nothing, even when it says "no root unit".
  clock = 0;
  const sys3 = fakeSystemd(dir);
  sys3.rootUnits = () => { clock += 20000; return []; };
  const r3 = await stop({ all: true }, "all", { sys: sys3, dir, now: () => clock });
  assert.equal(r3.best_effort, true);
});

test("rootUnitsIn: only generated agent units with User=root; other files and non-root units don't count", () => {
  const d = mkdtempSync(join(tmpdir(), "sb-units-"));
  const a = newId(), r = newId();
  writeFileSync(join(d, unitOf(a)), "[Service]\nUser=sb-" + a + "\n");
  writeFileSync(join(d, unitOf(r)), "# ROOT AGENT\n[Service]\nUser=root\n");
  writeFileSync(join(d, "other.service"), "[Service]\nUser=root\n");
  writeFileSync(join(d, unitOf(newId())), "[Service]\n# User=root\nUser=rooted\n");
  mkdirSync(join(d, "multi-user.target.wants"));
  assert.deepEqual(rootUnitsIn(d), [unitOf(r)]);
  assert.deepEqual(realSystemd.rootUnits(1000, d), [unitOf(r)], "the real systemd uses it");
  assert.throws(() => rootUnitsIn(join(d, "missing")));
});
