// Host supervisor freeze r3.1 §3.3, §3.4, §7: the stop fences and the stop sequence, against a fake systemd that models
// start jobs both before and after their condition check. A stop always raises its fence first, stops, cancels and
// drains start jobs, and checks the tree is empty; a fence that can't be written still kills and says so; each fence
// is lowered only by its own cause.
import assert from "node:assert/strict";
import { mkdtempSync, existsSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { FleetError, newId } from "../lib/fleet/index.mjs";
import { stop, raiseFence, lowerFence, fenced } from "../lib/fleet/host/fence.mjs";
import { realIo } from "../lib/fleet/host/store.mjs";

const refused = (fn, code) => assert.throws(fn, (e) => e instanceof FleetError && e.code === code, code);
const unitOf = (a) => `sagebrush-agent-${a}.service`;
const fresh = () => join(mkdtempSync(join(tmpdir(), "sb-fence-")), "fence");

/**
 * A fake systemd. `units`: name -> { active, procs }. `jobs`: pending start jobs { id, unit, type, passed, ticks }:
 * `passed` means the job already passed its ConditionPathExists check (a fence written now can't stop it); `ticks` is
 * how many looks it stays pending before it activates. Pending jobs progress whenever the stopper looks at the system.
 */
function fakeSystemd(dir, { units = {}, jobs = [], stubborn = false } = {}) {
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
    procCount: (u) => Object.entries(units).filter(([n]) => u === n || u === "sagebrush-agents.slice").reduce((s, [, st]) => s + st.procs, 0),
  };
}

test("stop-all: fence first, then stop; a queued start is skipped by its condition and a past-condition start is cancelled; empty", () => {
  const dir = fresh();
  const [a, b, c] = [newId(), newId(), newId()];
  const sys = fakeSystemd(dir, {
    units: { [unitOf(a)]: { active: true, procs: 4 } },
    jobs: [{ id: 1, unit: unitOf(b), type: "start", passed: false, ticks: 0 }, { id: 2, unit: unitOf(c), type: "start", passed: true, ticks: 1 }],
  });
  const r = stop({ all: true }, "all", { sys, dir });
  assert.deepEqual([r.status, r.fenced, r.empty], ["stopped and fenced", true, true]);
  assert.ok(existsSync(join(dir, "all")));
  assert.deepEqual(sys.calls[0], ["stop", "sagebrush-agents.slice"]);
  assert.ok(sys.calls.some((x) => x[0] === "cancel" && x[1] === 2), "the past-condition start was cancelled");
  assert.equal(sys.units[unitOf(c)], undefined, "it never became active");
  assert.equal(sys.units[unitOf(b)], undefined, "the queued start was skipped by its condition");
});

test("a past-condition start that becomes active before it can be cancelled is stopped again", () => {
  const dir = fresh();
  const c = newId();
  const sys = fakeSystemd(dir, { jobs: [{ id: 7, unit: unitOf(c), type: "start", passed: true, ticks: 0 }] });
  const r = stop({ all: true }, "all", { sys, dir });
  assert.equal(r.status, "stopped and fenced");
  assert.equal(sys.units[unitOf(c)].active, false);
  assert.ok(sys.calls.filter((x) => x[0] === "stop").length >= 2);
});

test("one agent: its own fence and unit only; other agents and their jobs untouched", () => {
  const dir = fresh();
  const [a, other] = [newId(), newId()];
  const sys = fakeSystemd(dir, {
    units: { [unitOf(a)]: { active: true, procs: 2 }, [unitOf(other)]: { active: true, procs: 2 } },
    jobs: [{ id: 3, unit: unitOf(other), type: "start", passed: true, ticks: 5 }],
  });
  const r = stop({ agent: a }, "agent", { sys, dir });
  assert.equal(r.status, "stopped and fenced");
  assert.ok(existsSync(join(dir, a)));
  assert.ok(!existsSync(join(dir, "all")));
  assert.equal(sys.units[unitOf(other)].active, true);
  assert.ok(!sys.calls.some((x) => x[0] === "cancel"));
  assert.deepEqual(sys.calls[0], ["stop", unitOf(a)]);
});

test("a fence that can't be written: the kill still runs, and the result says killed, not durable", () => {
  const root = mkdtempSync(join(tmpdir(), "sb-fence-"));
  const dir = join(root, "fence");
  writeFileSync(dir, "not a directory");
  const a = newId();
  const sys = fakeSystemd(dir, { units: { [unitOf(a)]: { active: true, procs: 3 } } });
  const r = stop({ all: true }, "all", { sys, dir });
  assert.deepEqual([r.status, r.fenced, r.empty], ["killed, not durable", false, true]);
  assert.equal(sys.units[unitOf(a)].active, false);
});

test("a tree that won't empty: bounded rounds, reported not empty (never stopped and fenced)", () => {
  const dir = fresh();
  const a = newId();
  const sys = fakeSystemd(dir, { units: { [unitOf(a)]: { active: true, procs: 1 } }, stubborn: true });
  const r = stop({ all: true }, "all", { sys, dir, maxRounds: 5 });
  assert.equal(r.status, "not empty");
  assert.equal(r.rounds, 5);
  let t = 0;
  const r2 = stop({ all: true }, "all", { sys, dir, deadlineMs: 10, now: () => (t += 20) });
  assert.equal(r2.status, "not empty");
  assert.ok(r2.rounds <= 1, "the deadline bounds the rounds");
});

test("expiry fences all, as a separate file from a manual stop", () => {
  const dir = fresh();
  const sys = fakeSystemd(dir);
  stop({ all: true }, "expiry", { sys, dir });
  assert.ok(existsSync(join(dir, "expiry")));
  assert.ok(!existsSync(join(dir, "all")));
});

test("each fence is lowered only by its own cause; a revoked or deleted agent stays fenced", () => {
  const dir = fresh();
  const a = newId();
  raiseFence("all", null, { dir }); raiseFence("agent", a, { dir }); raiseFence("expiry", null, { dir });
  refused(() => lowerFence("all", null, "newer-grant", { dir }), "not_granted");
  refused(() => lowerFence("expiry", null, "resume-all", { dir }), "not_granted");
  refused(() => lowerFence("agent", a, "resume-all", { dir }), "not_granted");
  refused(() => lowerFence("agent", a, "resume-agent", { dir, agentState: "revoked" }), "not_granted");
  refused(() => lowerFence("agent", a, "resume-agent", { dir, agentState: "deleted" }), "not_granted");
  assert.equal(fenced(a, { dir }), true);
  lowerFence("expiry", null, "newer-grant", { dir });
  assert.equal(fenced(a, { dir }), true, "a renewal doesn't lower a manual stop");
  lowerFence("all", null, "resume-all", { dir });
  assert.equal(fenced(a, { dir }), true, "the agent's own fence is still up");
  lowerFence("agent", a, "resume-agent", { dir, agentState: "stopped" });
  assert.equal(fenced(a, { dir }), false);
  lowerFence("all", null, "resume-all", { dir }); // lowering an absent fence is fine
});

test("refused: bad targets and causes", () => {
  const dir = fresh();
  const sys = fakeSystemd(dir);
  refused(() => stop({ agent: "worker-1" }, "agent", { sys, dir }), "bad_form");
  refused(() => stop({ all: true }, "agent", { sys, dir }), "bad_form");
  refused(() => stop({ agent: newId() }, "all", { sys, dir }), "bad_form");
  refused(() => stop({}, "all", { sys, dir }), "bad_form");
  refused(() => raiseFence("pause", null, { dir }), "bad_form");
  refused(() => raiseFence("agent", "x", { dir }), "bad_form");
  refused(() => fenced("x", { dir }), "bad_form");
});

test("only start jobs are cancelled: a stop job for an agent unit is left alone", () => {
  const dir = fresh();
  const a = newId();
  const sys = fakeSystemd(dir, { units: { [unitOf(a)]: { active: true, procs: 1 } }, jobs: [{ id: 9, unit: unitOf(a), type: "stop", passed: true, ticks: 0 }] });
  stop({ all: true }, "all", { sys, dir });
  assert.ok(!sys.calls.some((x) => x[0] === "cancel" && x[1] === 9));
});

test("the fence is durable before the stop: the fence file and its directory are fsynced first", () => {
  const dir = fresh();
  const order = [];
  const fds = new Map();
  const io = { ...realIo, open: (p, f, m) => { const fd = realIo.open(p, f, m); fds.set(fd, p); return fd; }, fsync: (fd) => { order.push(["fsync", fds.get(fd)]); return realIo.fsync(fd); } };
  const sys = fakeSystemd(dir);
  const origStop = sys.stop;
  sys.stop = (u) => { order.push(["stop", u]); return origStop(u); };
  stop({ all: true }, "all", { sys, dir, io });
  const firstStop = order.findIndex((x) => x[0] === "stop");
  assert.ok(order.findIndex((x) => x[0] === "fsync" && x[1] === join(dir, "all")) >= 0 && order.findIndex((x) => x[0] === "fsync" && x[1] === join(dir, "all")) < firstStop);
  assert.ok(order.findIndex((x) => x[0] === "fsync" && x[1] === dir) < firstStop);
  // An fsync that fails means the fence is not durable: killed, not durable.
  const failing = { ...realIo, fsync: () => { throw Object.assign(new Error("EIO"), { code: "EIO" }); } };
  assert.equal(stop({ all: true }, "all", { sys: fakeSystemd(dir), dir, io: failing }).status, "killed, not durable");
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
