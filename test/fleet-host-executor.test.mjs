// Host supervisor freeze r3.1 §3.2–§3.4, §7, and the part-7 rulings: the executor against a fake systemd, broker and
// audit. One queue, emergencies first; the plan's steps in order with durable progress; narrowing; agent-side and
// host-side failures; expiry; the lifecycle ops and who may submit them; recovery; and a crash at every barrier.
import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "./host-linux-only.mjs";
import { FleetError, newId, sha256b64 } from "../lib/fleet/index.mjs";
import { Supervisor } from "../lib/fleet/host/executor.mjs";
import { raiseFence } from "../lib/fleet/host/fence.mjs";
import { HostStore } from "../lib/fleet/host/host-store.mjs";
import { planGrant, parseStep } from "../lib/fleet/host/plan.mjs";
import { STATES } from "../lib/fleet/host/registry.mjs";
import { STEPS } from "../lib/fleet/host/deprovision-record.mjs";

const rejects = (p, code) => assert.rejects(p, (e) => e instanceof FleetError && e.code === code, code);
const tmp = (n) => join(mkdtempSync(join(tmpdir(), "sb-exec-")), n);

// ---- a grant is JSON here; `verify` stands in for the §3.2 check (tested in grant.mjs)
const bytesOf = (body) => Buffer.from(JSON.stringify(body));
const verify = (bytes) => {
  const body = JSON.parse(String(bytes));
  if (body.expired) throw new FleetError("grant_expired", "expired");
  return { body, digest: sha256b64(bytes) };
};
const bodyOf = (bytes) => JSON.parse(String(bytes));
const entry = (agent, { tags = [], x = 1 } = {}) => ({ agent, tags, config: { x } });
const grant = (gen, agents, extra = {}) => bytesOf({ gen, agents, ...extra });

/** The fake effects: units by agent id ({ active, masked, frozen, unit }), and a log of every call in order. */
function fakeFx(over = {}) {
  const units = {}, log = [], audits = [], intents = [], acks = [];
  const u = (id) => (units[id] ??= { active: false, masked: false, frozen: false, unit: null });
  const idOf = (unit) => unit.slice(16, 42);
  const fx = {
    units, log, audits, intents, acks, u,
    appendIntent: async (r) => { log.push(["intent", r.kind ?? r.op]); intents.push(r); },
    audit: (r) => { audits.push(r); },
    brokerGen: async (g) => { log.push(["broker-gen", g]); },
    brokerRevoke: async (id) => { log.push(["broker-revoke", id]); },
    stopUnit: async (id) => { log.push(["stop", id]); u(id).active = false; u(id).frozen = false; },
    procCount: async (id) => (u(id).active ? 1 : 0),
    mask: async (id) => { log.push(["mask", id]); u(id).masked = true; },
    unmask: async (id) => { log.push(["unmask", id]); u(id).masked = false; },
    provision: async (id, uid) => { log.push(["provision", id, uid]); },
    writeUnit: async (id, uid, ga) => { log.push(["unit", id]); u(id).unit = JSON.stringify(ga.config); },
    daemonReload: async () => { log.push(["daemon-reload"]); },
    // Like systemctl start: a masked unit refuses; a fenced one is skipped by its ConditionPathExists.
    start: async (id) => { log.push(["start", id]); if (u(id).masked) throw new Error("masked"); if (!fx.fenced(id)) u(id).active = true; },
    fenced: (id) => fx.fenceDir !== undefined && ["all", id, "expiry"].some((n) => existsSync(join(fx.fenceDir, n))),
    isActive: async (id) => u(id).active,
    publishMap: async (g, map) => { log.push(["map", g, map.map((m) => m.agent)]); },
    sendAck: async (g, ack) => { acks.push([g, ack]); },
    freeze: async (id) => { log.push(["freeze", id]); u(id).frozen = true; },
    // A deprovision pass: `dpResult` picks the outcome; a done pass completes the real record (as deprovision.mjs does).
    deprovision: async (id, ms) => {
      log.push(["deprovision", id, ms]);
      const d = fx.dpResult?.(id) ?? { status: "done", step: null, reason: null };
      if (d instanceof Error) throw d;
      if (d.status === "done") {
        const dp = fx.store.deprovision, rec = dp.ensure(id, fx.store.registry.agent(id));
        for (const step of STEPS.slice(rec.steps_done.length)) dp.markStep(id, step);
      }
      return d;
    },
    // The local host commands (deprovision part 3): `hostResult` picks the outcome.
    purge: async (id, ms) => { log.push(["purge", id, ms]); const d = fx.hostResult?.("purge", id) ?? { status: "purged" }; if (d instanceof Error) throw d; return d; },
    requalify: async (id, ms) => { log.push(["requalify", id, ms]); const d = fx.hostResult?.("requalify", id) ?? { status: "requalified", rebound: ["home"] }; if (d instanceof Error) throw d; return d; },
    thaw: async (id) => { if (!u(id).frozen || !u(id).active) throw new Error("not frozen"); log.push(["thaw", id]); u(id).frozen = false; },
    sys: {
      stop: (unit) => { log.push(["sys-stop", unit]); for (const [id, s] of Object.entries(units)) if (unit === "sagebrush-agents.slice" || idOf(unit) === id) s.active = false; },
      jobs: () => [], cancel: () => {}, rootUnits: () => [],
      activeAgentUnits: () => Object.entries(units).filter(([, s]) => s.active).map(([id]) => `sagebrush-agent-${id}.service`),
      procCount: (unit) => Object.entries(units).filter(([id, s]) => s.active && (unit === "sagebrush-agents.slice" || idOf(unit) === id)).length,
    },
  };
  return Object.assign(fx, over);
}

async function setup({ fx = fakeFx(), root = tmp("state"), fenceDir = tmp("fence"), deadlines = {}, barrier } = {}) {
  const store = await HostStore.open(root);
  fx.fenceDir = fenceDir;
  fx.store = store;
  const sup = new Supervisor({ store, fx, verify, bodyOf, fenceDir, deadlines, barrier });
  return { sup, store, fx, root, fenceDir, close: () => store.close() };
}

const A = newId(), B = newId(), C = newId(), T = newId();
const kinds = (log) => log.map((l) => l[0]);

// ---- the planner

test("plan: first grant; then only what changed is stopped, masked, regenerated and restarted (any change narrows)", () => {
  const reg = { agent: () => null };
  const p1 = planGrant(null, { agents: [entry(B), entry(A, { tags: [T] })] }, reg);
  const [x, y] = [A, B].sort(); // ids are random: the plan orders them
  assert.deepEqual(p1.steps, ["broker-gen", `provision:${x}`, `provision:${y}`, `unit:${x}`, `unit:${y}`, "daemon-reload", `start:${x}`, `start:${y}`, "map"]);
  const known = { agent: (id) => ({ state: "running", start_failed: null, id }) };
  const prev = { agents: [entry(A, { tags: [T] }), entry(B), entry(C)] };
  // B widens (x changes), C is removed, A untouched.
  const p2 = planGrant(prev, { agents: [entry(A, { tags: [T] }), entry(B, { x: 2 })] }, known);
  assert.deepEqual(p2.steps, ["broker-gen", `retire:${C}`, `stop:${C}`, `mask:${C}`, `stop:${B}`, `mask:${B}`, `unit:${B}`, "daemon-reload", `start:${B}`, "map"]);
  // B joins tag T: A's tag membership moved, so A restarts too.
  const p3 = planGrant(prev, { agents: [entry(A, { tags: [T] }), entry(B, { tags: [T] }), entry(C)] }, known);
  assert.deepEqual(p3.changed, [A, B].sort());
  // Nothing changed: no unit, no reload, no start.
  assert.deepEqual(planGrant(prev, prev, known).steps, ["broker-gen", "map"]);
  // A start failure on record, or expiry (all): restarted although unchanged.
  const failed = { agent: (id) => ({ state: "running", start_failed: id === A ? "unit_failed" : null }) };
  assert.deepEqual(planGrant(prev, prev, failed).changed, [A]);
  assert.deepEqual(planGrant(prev, prev, known, { all: true }).changed, [A, B, C].sort());
  // A deleted agent is never planned again, whatever the grant says.
  const gone = { agent: (id) => ({ state: id === B ? "deleted" : "running", start_failed: null }) };
  assert.ok(!planGrant(prev, { agents: [entry(A, { tags: [T] }), entry(B, { x: 3 }), entry(C)] }, gone).steps.some((s) => s.endsWith(B)));
});

test("plan: refused input; parseStep accepts only planner step names", () => {
  assert.throws(() => planGrant(null, { agents: [entry(A), entry(A)] }, { agent: () => null }), /listed twice/);
  assert.throws(() => planGrant(null, { agents: [entry("x")] }, { agent: () => null }));
  assert.deepEqual(parseStep(`start:${A}`), { kind: "start", agent: A });
  assert.deepEqual(parseStep("map"), { kind: "map", agent: null });
  for (const bad of ["start:", `boot:${A}`, `start:${A}x`, "map ", `start:${A.toUpperCase()}`]) assert.throws(() => parseStep(bad));
});

// ---- applying grants

test("first grant: intent before any effect; steps in order; registry running; applied(N); ack lists the restarts", async () => {
  const { sup, store, fx, close } = await setup();
  const r = await sup.submit({ kind: "grant", bytes: grant(1, [entry(A, { tags: [T] }), entry(B)]) });
  assert.equal(r.status, "applied");
  assert.deepEqual(r.ack, { narrowed: false, restarted: [A, B].sort() });
  assert.deepEqual(fx.acks, [[1, r.ack]]);
  const k = kinds(fx.log);
  assert.equal(k[0], "intent", "the durable intent comes first");
  assert.ok(k.indexOf("broker-gen") < k.indexOf("provision") && k.indexOf("provision") < k.indexOf("unit"));
  assert.ok(k.lastIndexOf("unit") < k.indexOf("daemon-reload") && k.indexOf("daemon-reload") < k.indexOf("start") && k.lastIndexOf("start") < k.indexOf("map"));
  for (const id of [A, B]) {
    assert.equal(store.registry.agent(id).state, "running");
    assert.equal(fx.units[id].active, true);
  }
  assert.ok(store.registry.tag(T));
  assert.deepEqual(store.grants.pending(), { phase: "applied", gen: 1, remaining: [] });
  assert.ok(fx.audits.some((a) => a.kind === "agent.start" && a.phase === "succeeded" && !("reason" in a)));
  await close();
});

test("a changed agent is stopped and masked BEFORE its unit is regenerated; an unchanged one is not touched", async () => {
  const { sup, fx, close } = await setup();
  await sup.submit({ kind: "grant", bytes: grant(1, [entry(A), entry(B)]) });
  fx.log.length = 0;
  const r = await sup.submit({ kind: "grant", bytes: grant(2, [entry(A, { x: 2 }), entry(B)]) });
  assert.deepEqual(r.ack, { narrowed: true, restarted: [A] });
  const mine = fx.log.filter((l) => l[1] === A).map((l) => l[0]);
  assert.deepEqual(mine, ["stop", "mask", "unit", "unmask", "start"]);
  assert.ok(!fx.log.some((l) => l[1] === B), "B untouched");
  assert.equal(fx.units[A].unit, JSON.stringify({ x: 2 }));
  await close();
});

test("byte-identical re-apply: no effect, the same acknowledgement again; lower or equal-but-different refused", async () => {
  const { sup, fx, close } = await setup();
  const g1 = grant(1, [entry(A)]);
  const r1 = await sup.submit({ kind: "grant", bytes: g1 });
  fx.log.length = 0;
  const r2 = await sup.submit({ kind: "grant", bytes: g1 });
  assert.equal(r2.status, "reapplied");
  assert.deepEqual(r2.ack, r1.ack);
  assert.deepEqual(fx.log, [], "no effect at all");
  assert.equal(fx.acks.length, 2);
  await sup.submit({ kind: "grant", bytes: grant(2, [entry(A)]) });
  await rejects(sup.submit({ kind: "grant", bytes: grant(1, [entry(A)]) }), "stale_generation");
  await rejects(sup.submit({ kind: "grant", bytes: grant(2, [entry(A, { x: 9 })]) }), "stale_generation");
  await rejects(sup.submit({ kind: "grant", bytes: grant(3, [entry(A)], { expired: true }) }), "grant_expired");
  await close();
});

test("an agent missing from grant N is retired: stopped (no op counted), stopped and masked; back only when listed AND resumed", async () => {
  const { sup, store, fx, close } = await setup();
  await sup.submit({ kind: "grant", bytes: grant(1, [entry(A), entry(B)]) });
  const life = store.registry.agent(B).life;
  const r = await sup.submit({ kind: "grant", bytes: grant(2, [entry(A)]) });
  assert.deepEqual(r.ack, { narrowed: true, restarted: [] });
  assert.equal(store.registry.agent(B).state, "stopped");
  assert.equal(store.registry.agent(B).life, life, "no lifecycle op counted");
  assert.deepEqual([fx.units[B].active, fx.units[B].masked], [false, true]);
  await rejects(sup.submit({ kind: "resume", authority: "person", agent: B }), "not_granted"); // not in the current grant
  // Listed again: its unit is regenerated, but it doesn't start (stopped needs a person's resume).
  const r3 = await sup.submit({ kind: "grant", bytes: grant(3, [entry(A), entry(B)]) });
  assert.deepEqual(r3.ack.restarted, []);
  assert.equal(fx.units[B].active, false);
  await rejects(sup.submit({ kind: "resume", authority: "service", agent: B }), "not_granted");
  const r4 = await sup.submit({ kind: "resume", authority: "person", agent: B });
  assert.equal(r4.started, true);
  assert.equal(fx.units[B].active, true);
  await close();
});

// ---- failures, by cause

for (const [code, phase] of [["preflight_missing", "refused"], ["landlock_abi", "refused"], ["unit_failed", "unknown_effect"]]) {
  test(`agent-side start failure (${code}): recorded, left stopped and masked, others go on, applied(N), absent from restarted`, async () => {
    const fx = fakeFx();
    fx.start = async (id) => { fx.log.push(["start", id]); if (id === A) throw new FleetError(code, "no"); fx.u(id).active = true; };
    const { sup, store, close } = await setup({ fx });
    const r = await sup.submit({ kind: "grant", bytes: grant(1, [entry(A), entry(B)]) });
    assert.equal(r.status, "applied");
    assert.deepEqual(r.ack, { narrowed: false, restarted: [B] });
    assert.equal(store.registry.agent(A).start_failed, code);
    assert.equal(store.registry.agent(A).state, "stopped", "a failed start leaves the agent stopped");
    assert.deepEqual([fx.units[A].active, fx.units[A].masked], [false, true]);
    const rec = fx.audits.find((a) => a.kind === "agent.start" && a.agent === A);
    assert.equal(rec.phase, phase);
    if (phase === "refused") assert.equal(rec.reason, code); else assert.ok(!("reason" in rec), "unknown_effect carries no reason");
    await close();
  });
}

/** An effect that stays pending until its signal aborts, then rejects: it settles at the deadline. */
const untilAborted = (signal) => new Promise((_, rej) => signal.addEventListener("abort", () => rej(new Error("aborted")), { once: true }));

test("a start past its deadline that settles is start_timeout (agent-side): stopped, contained, no fence; a resume retries it", async () => {
  const fx = fakeFx();
  let hang = true;
  fx.start = async (id, ms, signal) => { if (id === A && hang) await untilAborted(signal); fx.u(id).active = true; };
  const root = tmp("state"), fenceDir = tmp("fence");
  let s = await setup({ fx, root, fenceDir, deadlines: { start: 100 } });
  const r = await s.sup.submit({ kind: "grant", bytes: grant(1, [entry(A), entry(B)]) });
  assert.equal(r.status, "applied");
  assert.deepEqual(r.ack.restarted, [B]);
  const a = s.store.registry.agent(A);
  assert.deepEqual([a.start_failed, a.state, a.life], ["start_timeout", "stopped", 0], "stopped, no lifecycle op counted");
  assert.deepEqual([fx.units[A].active, fx.units[A].masked, existsSync(join(fenceDir, A))], [false, true, false]);
  assert.equal(s.sup.unsettled, 0);
  await s.close();
  // Recovery: B starts again, A does not.
  for (const u of Object.values(fx.units)) u.active = false;
  s = await setup({ fx, root, fenceDir });
  assert.deepEqual((await s.sup.recover()).started, [B]);
  assert.equal(fx.units[A].active, false);
  // The next grant clears start_failed but doesn't start a stopped agent; a person's resume does.
  hang = false;
  const r2 = await s.sup.submit({ kind: "grant", bytes: grant(2, [entry(A), entry(B)]) });
  assert.ok(!r2.ack.restarted.includes(A));
  assert.equal(s.store.registry.agent(A).start_failed, null);
  const r3 = await s.sup.submit({ kind: "resume", authority: "person", agent: A });
  assert.equal(r3.started, true);
  assert.equal(fx.units[A].active, true);
  await s.close();
});

test("host-side failure: applying(N) stays, no ack, the step's agent stopped and masked; the next input redoes it first", async () => {
  const fx = fakeFx();
  let fail = true;
  fx.daemonReload = async () => { if (fail) throw Object.assign(new Error("EIO"), { code: "EIO" }); fx.log.push(["daemon-reload"]); };
  const { sup, store, close } = await setup({ fx });
  const r = await sup.submit({ kind: "grant", bytes: grant(1, [entry(A)]) });
  assert.equal(r.status, "failed");
  assert.equal(r.step, "daemon-reload");
  assert.equal(store.grants.pending().phase, "applying");
  assert.deepEqual(fx.acks, []);
  assert.equal(fx.units[A]?.active ?? false, false);
  assert.ok(fx.audits.some((a) => a.kind === "grant.apply" && a.phase === "failed_no_effect"));
  // Still failing: a newer grant is refused while N can't finish.
  const r2 = await sup.submit({ kind: "grant", bytes: grant(2, [entry(A)]) });
  assert.deepEqual([r2.status, r2.reason], ["refused", "in_progress"]);
  fail = false;
  const r3 = await sup.submit({ kind: "grant", bytes: grant(2, [entry(A), entry(B)]) });
  assert.equal(r3.status, "applied");
  assert.equal(r3.gen, 2);
  assert.deepEqual(fx.acks.map((a) => a[0]), [1, 2], "N acknowledged once finished, then N+1");
  await close();
});

test("a host-side step past its deadline is unknown_effect, its agent quiesced; a not-empty cgroup after stop is a host failure", async () => {
  const fx = fakeFx();
  fx.writeUnit = async () => new Promise(() => {});
  const { sup, store, close } = await setup({ fx, deadlines: { unit: 80 } });
  const r = await sup.submit({ kind: "grant", bytes: grant(1, [entry(A)]) });
  assert.deepEqual([r.status, r.step, r.reason], ["failed", `unit:${A}`, "step_deadline"]);
  assert.ok(fx.audits.some((a) => a.kind === "grant.apply" && a.phase === "unknown_effect"));
  assert.equal(fx.units[A].masked, true);
  assert.equal(store.grants.pending().phase, "applying");
  await close();

  const fx2 = fakeFx();
  const s2 = await setup({ fx: fx2 });
  await s2.sup.submit({ kind: "grant", bytes: grant(1, [entry(A)]) });
  fx2.procCount = async () => 1;
  const r2 = await s2.sup.submit({ kind: "grant", bytes: grant(2, [entry(A, { x: 2 })]) });
  assert.deepEqual([r2.status, r2.reason], ["failed", "not_empty"]);
  await s2.close();
});

// ---- emergencies, expiry, fences

test("an emergency preempts at the next step boundary, runs, then the application continues; starts skip a raised fence", async () => {
  let sup;
  const order = [];
  const [first, second] = [A, B].sort();
  const barrier = async (name, d) => {
    order.push(name);
    if (name === "after_unit_write" && d.agent === first) {
      order.push("stop-all queued");
      sup.submit({ kind: "stop-all", authority: "local" }).then((r) => order.push(`stop-all: ${r.status}`));
    }
  };
  const s = await setup({ barrier });
  sup = s.sup;
  const g1 = grant(1, [entry(A), entry(B)]);
  const r = await sup.submit({ kind: "grant", bytes: g1 });
  assert.deepEqual([r.status, r.step], ["preempted", `unit:${second}`]);
  // An input queued now runs after the emergency and after the continued application.
  assert.equal((await sup.submit({ kind: "grant", bytes: g1 })).status, "reapplied");
  const iPre = order.indexOf("emergency_preempt"), iStop = order.findIndex((x) => x.startsWith("stop-all:"));
  assert.ok(iPre > 0 && iStop > iPre, "the stop ran at the boundary");
  assert.equal(s.store.grants.pending().phase, "applied", "continued after the emergency");
  assert.equal(s.fx.units[A].active, false, "fence all: no start");
  assert.equal(s.fx.units[B].active ?? false, false);
  assert.deepEqual(s.fx.acks.at(-1), [1, { narrowed: false, restarted: [] }]);
  await s.close();
});

test("expiry: fence, stop all, mask; the application stays applying(N); a newer grant lowers it and restarts every agent", async () => {
  const { sup, store, fx, fenceDir, close } = await setup();
  await sup.submit({ kind: "grant", bytes: grant(1, [entry(A), entry(B)]) });
  const r = await sup.submit({ kind: "expiry", authority: "host" });
  assert.equal(r.status, "stopped and fenced");
  assert.ok(existsSync(join(fenceDir, "expiry")));
  assert.deepEqual([fx.units[A].active, fx.units[A].masked, fx.units[B].masked], [false, true, true]);
  assert.ok(fx.audits.some((a) => a.kind === "grant.expire" && a.phase === "expired" && a.reason === "grant_expired"));
  // A resume can't lower expiry, and a start under it is skipped.
  await sup.submit({ kind: "resume-all", authority: "person" });
  assert.equal(fx.units[A].active, false);
  // The same grant again (byte-identical) is not newer: nothing restarts.
  await sup.submit({ kind: "grant", bytes: grant(1, [entry(A), entry(B)]) });
  assert.ok(existsSync(join(fenceDir, "expiry")));
  const r2 = await sup.submit({ kind: "grant", bytes: grant(2, [entry(A), entry(B)]) });
  assert.ok(!existsSync(join(fenceDir, "expiry")));
  assert.deepEqual(r2.ack.restarted, [A, B].sort());
  assert.equal(store.registry.agent(A).state, "running");
  await close();
});

test("a start never passes a fence: the agent's own, all or expiry, checked under the fence lock", async () => {
  for (const cause of ["agent", "all", "expiry"]) {
    const { sup, fx, fenceDir, close } = await setup();
    raiseFence(cause, cause === "agent" ? A : null, { dir: fenceDir });
    const r = await sup.submit({ kind: "grant", bytes: grant(1, [entry(A)]) });
    if (cause === "expiry") { assert.equal(r.status, "applied"); assert.equal(fx.units[A].active, true, "a newer grant lowers expiry"); }
    else { assert.deepEqual(r.ack.restarted, []); assert.equal(fx.units[A]?.active ?? false, false); assert.ok(!fx.log.some((l) => l[0] === "start")); }
    await close();
  }
});

// ---- lifecycle ops and authority

test("who may do what: the service and the local CLI only narrow; a person also resumes and deletes", async () => {
  const { sup, close } = await setup();
  await sup.submit({ kind: "grant", bytes: grant(1, [entry(A)]) });
  for (const [authority, kind] of [["service", "resume"], ["service", "delete"], ["service", "resume-all"], ["local", "pause"], ["local", "resume"], ["host", "stop"], ["agent", "stop"], [undefined, "stop"], ["person", "expiry"], ["person", "revoke"], ["person", "boot"]]) {
    await rejects(sup.submit({ kind, authority, agent: A }), "not_granted");
  }
  await close();
});

test("stop of one agent: state stopped with the op counted, fence up, masked; resume lowers its fence and starts it", async () => {
  const { sup, store, fx, fenceDir, close } = await setup();
  await sup.submit({ kind: "grant", bytes: grant(1, [entry(A), entry(B)]) });
  const r = await sup.submit({ kind: "stop", authority: "service", agent: A });
  assert.equal(r.status, "stopped and fenced");
  assert.deepEqual([store.registry.agent(A).state, store.registry.agent(A).life], ["stopped", 1]);
  assert.ok(existsSync(join(fenceDir, A)));
  assert.deepEqual([fx.units[A].active, fx.units[A].masked, fx.units[B].active], [false, true, true]);
  // A later grant that changes A regenerates it but doesn't start it.
  await sup.submit({ kind: "grant", bytes: grant(2, [entry(A, { x: 2 }), entry(B)]) });
  assert.equal(fx.units[A].active, false);
  const r2 = await sup.submit({ kind: "resume", authority: "person", agent: A });
  assert.equal(r2.started, true);
  assert.ok(!existsSync(join(fenceDir, A)));
  assert.deepEqual([store.registry.agent(A).state, store.registry.agent(A).life], ["running", 2]);
  await close();
});

test("pause freezes (op counted); resume thaws it; a paused agent becomes stopped and masked at recovery, never run", async () => {
  const root = tmp("state"), fenceDir = tmp("fence"), fx = fakeFx();
  let s = await setup({ fx, root, fenceDir });
  await s.sup.submit({ kind: "grant", bytes: grant(1, [entry(A), entry(B)]) });
  await s.sup.submit({ kind: "pause", authority: "service", agent: A });
  assert.deepEqual([s.store.registry.agent(A).state, fx.units[A].frozen], ["paused", true]);
  const r = await s.sup.submit({ kind: "resume", authority: "person", agent: A });
  assert.deepEqual([r.thawed, fx.units[A].frozen, s.store.registry.agent(A).life], [true, false, 2]);
  await s.sup.submit({ kind: "pause", authority: "person", agent: B });
  await s.close();
  for (const u of Object.values(fx.units)) { u.active = false; u.frozen = false; }
  s = await setup({ fx, root, fenceDir });
  const rec = await s.sup.recover();
  assert.deepEqual(rec.started, [A]);
  assert.deepEqual([s.store.registry.agent(B).state, fx.units[B].active, fx.units[B].masked], ["stopped", false, true]);
  // Resumed after recovery: not frozen any more, so it is started with the current grant.
  const r2 = await s.sup.submit({ kind: "resume", authority: "person", agent: B });
  assert.equal(r2.started, true);
  await s.close();
});

test("revoke-caps (§7): op counted, broker revokes, narrowing restart; state unchanged, no fence; no permanent revoke in v1", async () => {
  const { sup, store, fx, fenceDir, close } = await setup();
  await sup.submit({ kind: "grant", bytes: grant(1, [entry(A)]) });
  fx.log.length = 0;
  const r = await sup.submit({ kind: "revoke-caps", authority: "service", agent: A });
  assert.deepEqual(r, { status: "revoked-caps", started: true });
  // The old unit is gone (masked, drained, proven empty) BEFORE the broker revokes; then regenerate and start.
  assert.deepEqual(kinds(fx.log).filter((k) => k !== "intent"), ["mask", "sys-stop", "broker-revoke", "unit", "daemon-reload", "unmask", "start"]);
  assert.deepEqual([store.registry.agent(A).state, store.registry.agent(A).life], ["running", 1]);
  assert.ok(!existsSync(join(fenceDir, A)));
  await rejects(sup.submit({ kind: "revoke", authority: "person", agent: A }), "not_granted");
  await close();
});

test("delete: state deleted (op counted), fence up, stopped and masked; never planned or started again", async () => {
  const { sup, store, fx, close } = await setup();
  await sup.submit({ kind: "grant", bytes: grant(1, [entry(A), entry(B)]) });
  await sup.submit({ kind: "delete", authority: "person", agent: A });
  assert.deepEqual([store.registry.agent(A).state, fx.units[A].active, fx.units[A].masked], ["deleted", false, true]);
  fx.log.length = 0;
  await sup.submit({ kind: "grant", bytes: grant(2, [entry(A, { x: 5 }), entry(B)]) });
  assert.ok(!fx.log.some((l) => l[1] === A));
  await rejects(sup.submit({ kind: "resume", authority: "person", agent: A }), "not_granted");
  await close();
});

test("delete: a proven stop runs one deprovision pass, audited; a pending or failing pass is no error for the caller", async () => {
  const { sup, store, fx, close } = await setup();
  await sup.submit({ kind: "grant", bytes: grant(1, [entry(A), entry(B), entry(C)]) });
  const dps = () => fx.log.filter((l) => l[0] === "deprovision");
  const dpAudit = (id) => fx.audits.filter((r) => r.kind === "agent.deprovision" && r.agent === id).map(({ phase, step, reason }) => [phase, step, reason]);
  await sup.submit({ kind: "delete", authority: "person", agent: A });
  assert.deepEqual(dps(), [["deprovision", A, 120000]]);
  // After the stop and mask: never before the proof.
  const k = kinds(fx.log);
  assert.ok(k.lastIndexOf("mask") < k.indexOf("deprovision"));
  assert.deepEqual(dpAudit(A), [["succeeded", undefined, undefined]]);
  assert.equal(store.deprovision.record(A).done, true);
  fx.dpResult = (id) => (id === B ? { status: "pending", step: "accounts", reason: "uid still in use" } : new Error("EIO"));
  await sup.submit({ kind: "delete", authority: "person", agent: B });
  await sup.submit({ kind: "delete", authority: "person", agent: C });
  assert.deepEqual(dpAudit(B), [["pending", "accounts", "uid still in use"]]);
  assert.deepEqual(dpAudit(C), [["unknown_effect", undefined, undefined]]);
  assert.deepEqual([B, C].map((id) => store.registry.agent(id).state), ["deleted", "deleted"]);
  await close();
});

test("purge and requalify: the local authority only, for a deleted agent only; owned under the deprovision deadline; audited", async () => {
  const { sup, fx, close } = await setup();
  await sup.submit({ kind: "grant", bytes: grant(1, [entry(A), entry(B)]) });
  const host = () => fx.log.filter((l) => l[0] === "purge" || l[0] === "requalify");
  // Never a remote op: the person, the service and the host refuse; only the local CLI may submit them.
  for (const kind of ["purge", "requalify"]) {
    for (const authority of ["person", "service", "host"]) await rejects(sup.submit({ kind, authority, agent: A }), "not_granted");
  }
  // Only a deleted agent: a live one is refused, with no effect.
  assert.deepEqual(await sup.submit({ kind: "purge", authority: "local", agent: A }), { status: "refused", reason: "not_deleted" });
  assert.deepEqual(host(), []);
  await sup.submit({ kind: "delete", authority: "person", agent: A });
  assert.deepEqual(await sup.submit({ kind: "requalify", authority: "local", agent: A }), { status: "requalified", rebound: ["home"] });
  assert.deepEqual(await sup.submit({ kind: "purge", authority: "local", agent: A }), { status: "purged" });
  assert.deepEqual(host(), [["requalify", A, 120000], ["purge", A, 120000]]);
  const aud = (kind) => fx.audits.filter((r) => r.kind === kind && r.agent === A).map(({ phase, reason, rebound }) => [phase, reason, rebound]);
  assert.deepEqual(aud("agent.requalify"), [["succeeded", undefined, ["home"]]]);
  assert.deepEqual(aud("agent.purge"), [["succeeded", undefined, undefined]]);
  // Pending and failing: audited, no error for the caller.
  fx.hostResult = (cmd) => (cmd === "purge" ? { status: "pending", step: null, reason: "home: a stale epoch (requalify)" } : new Error("EIO"));
  assert.equal((await sup.submit({ kind: "purge", authority: "local", agent: A })).status, "pending");
  assert.equal((await sup.submit({ kind: "requalify", authority: "local", agent: A })).reason, "host-side failure");
  assert.deepEqual(aud("agent.purge").at(-1), ["pending", "home: a stale epoch (requalify)", undefined]);
  assert.deepEqual(aud("agent.requalify").at(-1), ["unknown_effect", undefined, undefined]);
  await close();
});

test("a hung purge is owned: aborted at its deadline, abandoned after the grace, ordinary input refused meanwhile", async () => {
  const fx = fakeFx();
  const { sup, close } = await setup({ fx, deadlines: { deprovision: 40, grace: 20 } });
  await sup.submit({ kind: "grant", bytes: grant(1, [entry(A), entry(B)]) });
  await sup.submit({ kind: "delete", authority: "person", agent: A });
  let settle, seen;
  fx.purge = (id, ms, signal) => { seen = { ms, signal }; return new Promise((r) => { settle = r; }); };
  const r = await sup.submit({ kind: "purge", authority: "local", agent: A });
  assert.deepEqual([r.status, r.reason], ["pending", "step_deadline"]);
  assert.deepEqual([seen.ms, seen.signal.aborted], [40, true]);
  assert.equal(sup.unsettled, 1);
  assert.deepEqual(fx.audits.filter((a) => a.kind === "agent.purge").map((a) => a.phase), ["unknown_effect"]);
  // Meanwhile: ordinary input, and another host command, refused; an emergency still runs.
  assert.equal((await sup.submit({ kind: "requalify", authority: "local", agent: A })).reason, "in_progress");
  await sup.submit({ kind: "stop-all", authority: "local" });
  settle({ status: "purged" });
  for (let i = 0; i < 250 && sup.unsettled > 0; i++) await new Promise((res) => setTimeout(res, 20));
  assert.equal(sup.unsettled, 0);
  await close();
});

test("delete: an unproven stop runs no deprovision pass; recovery runs it once the stop is proven", async () => {
  const root = tmp("state"), fenceDir = tmp("fence"), fx = fakeFx();
  let s = await setup({ fx, root, fenceDir });
  await s.sup.submit({ kind: "grant", bytes: grant(1, [entry(A), entry(B)]) });
  const sysStop = fx.sys.stop, stopUnit = fx.stopUnit;
  fx.sys.stop = (u) => { if (u.includes(A)) throw new Error("EIO"); return sysStop(u); };
  fx.stopUnit = async (id) => { if (id === A) throw new Error("EIO"); return stopUnit(id); };
  await s.sup.submit({ kind: "delete", authority: "person", agent: A }).catch(() => {});
  assert.equal(s.store.registry.agent(A).state, "deleted");
  assert.ok(!fx.log.some((l) => l[0] === "deprovision"));
  assert.equal(s.store.deprovision.record(A), null);
  await s.close();
  // Still unproven at recovery: no pass.
  s = await setup({ fx, root, fenceDir });
  const r1 = await s.sup.recover();
  assert.deepEqual([r1.unproven, r1.deprovisioning], [[A], undefined]);
  assert.ok(!fx.log.some((l) => l[0] === "deprovision"));
  await s.close();
  fx.sys.stop = sysStop; fx.stopUnit = stopUnit;
  s = await setup({ fx, root, fenceDir });
  const r2 = await s.sup.recover();
  assert.deepEqual([r2.unproven, r2.deprovisioning], [undefined, undefined]);
  assert.deepEqual(fx.log.filter((l) => l[0] === "deprovision").map((l) => l[1]), [A]);
  assert.equal(s.store.deprovision.record(A).done, true);
  await s.close();
});

test("recovery: every deleted agent not done gets a pass, from the registry (even out of the grant); done ones never again", async () => {
  const root = tmp("state"), fenceDir = tmp("fence"), fx = fakeFx();
  let s = await setup({ fx, root, fenceDir });
  await s.sup.submit({ kind: "grant", bytes: grant(1, [entry(A), entry(B), entry(C)]) });
  fx.dpResult = (id) => (id === C ? undefined : { status: "pending", step: "home", reason: "parked" });
  for (const id of [A, B, C]) await s.sup.submit({ kind: "delete", authority: "person", agent: id });
  // The next grant no longer names A or C.
  await s.sup.submit({ kind: "grant", bytes: grant(2, [entry(B)]) });
  await s.close();
  const passes = () => fx.log.filter((l) => l[0] === "deprovision").map((l) => l[1]);
  fx.log.length = 0;
  s = await setup({ fx, root, fenceDir });
  const r1 = await s.sup.recover();
  assert.deepEqual(r1.deprovisioning, [A, B].sort());
  assert.deepEqual(passes().sort(), [A, B].sort()); // C is done: no pass
  await s.close();
  fx.log.length = 0;
  fx.dpResult = (id) => (id === B ? { status: "pending", step: "accounts", reason: "uid in use" } : undefined);
  s = await setup({ fx, root, fenceDir });
  assert.deepEqual((await s.sup.recover()).deprovisioning, [B]);
  await s.close();
  fx.log.length = 0;
  fx.dpResult = undefined;
  s = await setup({ fx, root, fenceDir });
  assert.equal((await s.sup.recover()).deprovisioning, undefined);
  assert.deepEqual(passes(), [B]);
  await s.close();
  fx.log.length = 0;
  s = await setup({ fx, root, fenceDir });
  await s.sup.recover();
  assert.deepEqual(passes(), []);
  await s.close();
});

test("recovery's deprovision lane needs no grant: gen 0, an invalid grant, an applying one invalid, held by expiry or continued; each proves the agent down first and starts nothing it shouldn't", async () => {
  const passes = (fx) => fx.log.filter((l) => l[0] === "deprovision").map((l) => l[1]);
  // The deleted agent's proof comes before its pass: its mask and drain, then the pass.
  const provedFirst = (fx, id) => {
    const i = fx.log.findIndex((l) => l[0] === "deprovision" && l[1] === id);
    return i > 0 && fx.log.slice(0, i).some((l) => l[0] === "mask" && l[1] === id) && fx.log.slice(0, i).some((l) => l[0] === "sys-stop" && l[1].includes(id));
  };
  // gen 0: a registry agent recorded deleted with nothing else (as after a crash before any grant settled).
  {
    const root = tmp("state"), fenceDir = tmp("fence"), fx = fakeFx();
    let s = await setup({ fx, root, fenceDir });
    s.store.registry.addAgent(A, 1);
    s.store.registry.setState(A, "deleted", "delete");
    await s.close();
    fx.dpResult = () => ({ status: "pending", step: "channels", reason: "parked" });
    s = await setup({ fx, root, fenceDir });
    assert.deepEqual(await s.sup.recover(), { status: "empty", deprovisioning: [A] });
    fx.dpResult = undefined;
    assert.deepEqual(await s.sup.recover(), { status: "empty" });
    assert.deepEqual(passes(fx), [A, A]);
    assert.ok(provedFirst(fx, A));
    assert.equal(s.store.deprovision.record(A).done, true);
    await s.close();
  }
  // The others: A deleted with its pass pending, then grant 2 crashes mid-application (applying), or is applied.
  for (const mode of ["applied-invalid", "applying-invalid", "applying-expired", "applying-continue"]) {
    const root = tmp("state"), fenceDir = tmp("fence"), fx = fakeFx();
    fx.dpResult = () => ({ status: "pending", step: "accounts", reason: "parked" });
    let crash = false;
    let s = await setup({ fx, root, fenceDir, barrier: async (n) => { if (crash && n === "after_unit_write") { crash = false; throw new Error("crash"); } } });
    await s.sup.submit({ kind: "grant", bytes: grant(1, [entry(A), entry(B)]) });
    await s.sup.submit({ kind: "delete", authority: "person", agent: A });
    crash = mode.startsWith("applying");
    await s.sup.submit({ kind: "grant", bytes: grant(2, [entry(B, { x: 2 })]) }).catch(() => {});
    assert.equal(s.store.grants.pending().phase, mode.startsWith("applying") ? "applying" : "applied", mode);
    await s.close();
    for (const u of Object.values(fx.units)) u.active = false;
    if (mode === "applying-expired") raiseFence("expiry", null, { dir: fenceDir });
    fx.dpResult = undefined;
    fx.log.length = 0;
    s = await setup({ fx, root, fenceDir });
    if (mode.endsWith("invalid")) s.sup.verify = () => { throw new FleetError("grant_expired", "expired"); };
    const r = await s.sup.recover();
    assert.deepEqual(passes(fx), [A], mode);
    assert.ok(provedFirst(fx, A), `${mode}: proven down before its pass`);
    assert.equal(s.store.deprovision.record(A).done, true, mode);
    if (mode === "applying-continue") assert.equal(r.status, "applied", mode);
    else {
      assert.deepEqual([r.status, r.reason], { "applied-invalid": ["not_started", "grant_not_valid"], "applying-invalid": ["not_started", "grant_not_valid"], "applying-expired": ["held", "expired"] }[mode], mode);
      assert.ok(!fx.log.some((l) => l[0] === "start" || l[0] === "unit"), `${mode}: nothing started or written`);
    }
    await s.close();
  }
});

test("recovery proves an out-of-grant deleted agent afresh (a crash between \"deleted\" and its stop left no pending proof): masked, drained, proven, then the pass; a failed proof means no pass", async () => {
  for (const proofFails of [false, true]) {
    const root = tmp("state"), fenceDir = tmp("fence"), fx = fakeFx();
    let s = await setup({ fx, root, fenceDir });
    await s.sup.submit({ kind: "grant", bytes: grant(1, [entry(A), entry(B)]) });
    await s.sup.submit({ kind: "grant", bytes: grant(2, [entry(B)]) }); // A retired: out of the grant
    // The crash seam: `deleted` committed, then the supervisor died before #stopProved; something of A runs.
    s.store.registry.setState(A, "deleted", "delete");
    assert.ok(!s.store.grants.pendingProofs().includes(A), "no pending-proof marker");
    await s.close();
    fx.units[A].active = true;
    fx.units[A].masked = false;
    const sysStop = fx.sys.stop;
    if (proofFails) fx.sys.stop = (u) => { if (u.includes(A)) throw new Error("EIO"); return sysStop(u); };
    fx.log.length = 0;
    s = await setup({ fx, root, fenceDir });
    const r = await s.sup.recover();
    const dp = fx.log.findIndex((l) => l[0] === "deprovision" && l[1] === A);
    if (proofFails) {
      assert.equal(dp, -1, "no pass without a proof");
      assert.deepEqual([r.unproven, r.deprovisioning], [[A], undefined]);
      assert.equal(s.store.deprovision.record(A), null);
    } else {
      assert.ok(dp > 0);
      const before = fx.log.slice(0, dp);
      assert.ok(before.some((l) => l[0] === "mask" && l[1] === A) && before.some((l) => l[0] === "sys-stop" && l[1].includes(A)));
      assert.deepEqual([fx.units[A].active, fx.units[A].masked], [false, true]);
      assert.equal(r.unproven, undefined);
    }
    fx.sys.stop = sysStop;
    await s.close();
  }
});

test("a deprovision pass is owned: past its deadline its signal aborts; one that never settles is abandoned, normal input is refused meanwhile, and the agent is contained again when it settles", async () => {
  const fx = fakeFx();
  let settle, seen;
  const { sup, store, close } = await setup({ fx, deadlines: { deprovision: 60, grace: 30 } });
  await sup.submit({ kind: "grant", bytes: grant(1, [entry(A), entry(B)]) });
  fx.deprovision = (id, ms, signal) => { seen = { id, ms, signal }; return new Promise((r) => { settle = r; }); };
  const t0 = Date.now();
  await sup.submit({ kind: "delete", authority: "person", agent: A }); // returns: the pass is abandoned
  assert.ok(Date.now() - t0 < 5000);
  assert.deepEqual([seen.id, seen.ms, seen.signal.aborted], [A, 60, true]);
  assert.deepEqual(fx.audits.filter((r) => r.kind === "agent.deprovision").map((r) => r.phase), ["unknown_effect"]);
  assert.equal(sup.unsettled, 1);
  assert.equal(store.registry.agent(A).state, "deleted");
  // Meanwhile: ordinary input refused; an emergency still runs.
  assert.equal((await sup.submit({ kind: "pause", authority: "service", agent: B })).reason, "in_progress");
  await sup.submit({ kind: "stop-all", authority: "local" });
  // It settles late: A is contained again (mask, drain) ahead of anything else, and normal input runs again.
  fx.log.length = 0;
  settle({ status: "done", step: null, reason: null });
  // Bounded polling, not a fixed sleep: a loaded run may take longer than a few ms to recontain.
  const masked = () => fx.log.some((l) => l[0] === "mask" && l[1] === A);
  for (const end = Date.now() + 5000; !masked() && Date.now() < end;) await new Promise((r) => setTimeout(r, 10));
  assert.ok(masked(), "recontained");
  assert.equal(sup.unsettled, 0);
  assert.notEqual((await sup.submit({ kind: "pause", authority: "service", agent: B })).reason, "in_progress");
  await close();
});

test("no pass starts while an effect is abandoned: a delete whose own mask hangs runs no pass; recovery runs it later", async () => {
  const fx = fakeFx();
  const { sup, store, close } = await setup({ fx, deadlines: { mask: 40, grace: 20 } });
  await sup.submit({ kind: "grant", bytes: grant(1, [entry(A), entry(B)]) });
  let release;
  const mask = fx.mask;
  fx.mask = (id, ms, signal) => (id === A ? new Promise((r) => { release = r; }) : mask(id, ms, signal));
  await sup.submit({ kind: "delete", authority: "person", agent: A });
  assert.equal(sup.unsettled, 1);
  assert.ok(!fx.log.some((l) => l[0] === "deprovision"), "no pass while the mask is abandoned");
  assert.equal(store.deprovision.record(A), null);
  fx.mask = mask;
  release();
  await new Promise((r) => setTimeout(r, 50));
  assert.equal(sup.unsettled, 0);
  const r = await sup.recover();
  assert.deepEqual(fx.log.filter((l) => l[0] === "deprovision").map((l) => l[1]), [A]);
  assert.equal(r.deprovisioning, undefined);
  await close();
});

// ---- recovery and crashes

test("recovery from applied(N): only running agents the grant allows; none when the grant no longer verifies", async () => {
  const root = tmp("state"), fenceDir = tmp("fence"), fx = fakeFx();
  let s = await setup({ fx, root, fenceDir });
  await s.sup.submit({ kind: "grant", bytes: grant(1, [entry(A), entry(B)], { expires: 1 }) });
  await s.sup.submit({ kind: "stop", authority: "service", agent: B });
  await s.close();
  for (const u of Object.values(fx.units)) u.active = false;
  s = await setup({ fx, root, fenceDir });
  assert.deepEqual((await s.sup.recover()).started, [A]);
  await s.close();
  for (const u of Object.values(fx.units)) u.active = false;
  s = await setup({ fx, root, fenceDir });
  s.sup.verify = () => { throw new FleetError("grant_expired", "expired"); };
  assert.deepEqual(await s.sup.recover(), { status: "not_started", reason: "grant_not_valid" });
  assert.equal(fx.units[A].active, false);
  await s.close();
});

test("recovery reconciles an open intent (AU07): highwater below it proves no effect", async () => {
  const fx = fakeFx({ openIntents: async () => [5] });
  const { sup, close } = await setup({ fx });
  await sup.submit({ kind: "grant", bytes: grant(1, [entry(A)]) });
  await sup.recover();
  assert.ok(fx.audits.some((a) => a.kind === "grant.apply" && a.gen === 5 && a.phase === "reconciled_no_effect"));
  await close();
});

const BARRIERS = ["after_verify", "after_intent", "after_highwater_persist", "after_broker_gen", "after_unit_write", "after_daemon_reload", "before_runstate_record", "before_start", "after_start", "after_map_publish", "after_applied_persist", "after_ack_send"];

test("every barrier is reached, in order, on a first grant", async () => {
  const seen = [];
  const { sup, close } = await setup({ barrier: async (n) => { if (!seen.includes(n)) seen.push(n); } });
  await sup.submit({ kind: "grant", bytes: grant(1, [entry(A)]) });
  assert.deepEqual(seen, BARRIERS);
  await close();
});

for (const at of BARRIERS) {
  test(`a crash at ${at}: recovery (and the grant sent again) reaches applied(1) with the agent running, exactly once`, async () => {
    const root = tmp("state"), fenceDir = tmp("fence"), fx = fakeFx();
    let s = await setup({ fx, root, fenceDir, barrier: async (n) => { if (n === at) throw new Error(`crash at ${n}`); } });
    const g1 = grant(1, [entry(A), entry(B)]);
    await assert.rejects(s.sup.submit({ kind: "grant", bytes: g1 }), /crash at/);
    await s.close();
    s = await setup({ fx, root, fenceDir });
    await s.sup.recover();
    const r = await s.sup.submit({ kind: "grant", bytes: g1 });
    if (at === "after_verify" || at === "after_intent") assert.equal(r.status, "applied"); // nothing accepted before the crash
    else assert.equal(r.status, "reapplied");
    assert.equal(s.store.grants.pending().phase, "applied");
    for (const id of [A, B]) {
      assert.equal(s.store.registry.agent(id).state, "running");
      assert.equal(fx.units[id].active, true, `${id} running`);
    }
    assert.equal(new Set(fx.log.filter((l) => l[0] === "provision").map((l) => l[2])).size, 2, "uids stable across the crash");
    await s.close();
  });
}

test("the narrowing barriers: after_stop, after_mask on a change; the stop-sequence barriers on a stop", async () => {
  const seen = [];
  const { sup, close } = await setup({ barrier: async (n) => { seen.push(n); } });
  await sup.submit({ kind: "grant", bytes: grant(1, [entry(A)]) });
  seen.length = 0;
  await sup.submit({ kind: "grant", bytes: grant(2, [entry(A, { x: 2 })]) });
  assert.ok(seen.indexOf("after_stop") >= 0 && seen.indexOf("after_stop") < seen.indexOf("after_mask") && seen.indexOf("after_mask") < seen.indexOf("after_unit_write"));
  seen.length = 0;
  await sup.submit({ kind: "stop", authority: "local", agent: A });
  assert.deepEqual(seen.slice(0, 4), ["before_runstate_record", "after_fence_write", "after_slice_stop", "after_job_cancel"]);
  await close();
});

test("step_deadline is reached when a step overruns; a crash there leaves applying(N), and recovery finishes it", async () => {
  const root = tmp("state"), fenceDir = tmp("fence"), fx = fakeFx();
  let slow = true;
  fx.daemonReload = async () => { if (slow) await new Promise((r) => setTimeout(r, 300)); };
  let s = await setup({ fx, root, fenceDir, deadlines: { "daemon-reload": 50 }, barrier: async (n) => { if (n === "step_deadline") throw new Error("crash at step_deadline"); } });
  await assert.rejects(s.sup.submit({ kind: "grant", bytes: grant(1, [entry(A)]) }), /crash at step_deadline/);
  await s.close();
  slow = false;
  s = await setup({ fx, root, fenceDir });
  assert.equal(s.store.grants.pending().phase, "applying");
  const r = await s.sup.recover();
  assert.equal(r.status, "applied");
  assert.equal(fx.units[A].active, true);
  await s.close();
});

test("a crash at before_runstate_record of a stop: the run state wasn't written and nothing was stopped; a stop again works", async () => {
  const root = tmp("state"), fenceDir = tmp("fence"), fx = fakeFx();
  let armed = false;
  let s = await setup({ fx, root, fenceDir, barrier: async (n) => { if (armed && n === "before_runstate_record") throw new Error("crash"); } });
  await s.sup.submit({ kind: "grant", bytes: grant(1, [entry(A)]) });
  armed = true;
  await assert.rejects(s.sup.submit({ kind: "stop", authority: "service", agent: A }), /crash/);
  assert.deepEqual([s.store.registry.agent(A).state, fx.units[A].active], ["running", true]);
  await s.close();
  s = await setup({ fx, root, fenceDir });
  assert.equal((await s.sup.submit({ kind: "stop", authority: "service", agent: A })).status, "stopped and fenced");
  assert.equal(s.store.registry.agent(A).state, "stopped");
  await s.close();
});

test("after a preemption the application continues by itself, with no further input", async () => {
  let sup, stopDone;
  const [first] = [A, B].sort();
  const s = await setup({ barrier: async (n, d) => { if (n === "after_unit_write" && d.agent === first) stopDone = sup.submit({ kind: "stop-all", authority: "local" }); } });
  sup = s.sup;
  assert.equal((await sup.submit({ kind: "grant", bytes: grant(1, [entry(A), entry(B)]) })).status, "preempted");
  await stopDone;
  for (let i = 0; i < 100 && s.store.grants.pending().phase !== "applied"; i++) await new Promise((r) => setTimeout(r, 20));
  assert.equal(s.store.grants.pending().phase, "applied");
  await s.close();
});

test("restarted holds only what systemd shows running: a running agent whose restart a fence skipped is absent", async () => {
  const { sup, fx, fenceDir, close } = await setup();
  await sup.submit({ kind: "grant", bytes: grant(1, [entry(A), entry(B)]) });
  raiseFence("all", null, { dir: fenceDir });
  fx.units[A].active = false; fx.units[B].active = false;
  const r = await sup.submit({ kind: "grant", bytes: grant(2, [entry(A, { x: 2 }), entry(B, { x: 2 })]) });
  assert.deepEqual(r.ack, { narrowed: true, restarted: [] });
  await close();
});

test("an agent deleted while an application is unfinished only gets stopped and masked when it is redone", async () => {
  const fx = fakeFx();
  let fail = true;
  const wu = fx.writeUnit;
  fx.writeUnit = async (id, ...rest) => { if (fail && id === A) throw Object.assign(new Error("EIO"), { code: "EIO" }); return wu(id, ...rest); };
  const { sup, store, close } = await setup({ fx });
  fail = false;
  await sup.submit({ kind: "grant", bytes: grant(1, [entry(A), entry(B)]) });
  fail = true;
  const r = await sup.submit({ kind: "grant", bytes: grant(2, [entry(A, { x: 2 }), entry(B)]) });
  assert.deepEqual([r.status, r.step], ["failed", `unit:${A}`]);
  await sup.submit({ kind: "delete", authority: "person", agent: A });
  const r3 = await sup.submit({ kind: "grant", bytes: grant(3, [entry(B)]) });
  assert.equal(r3.status, "applied", "the redo skips the deleted agent's unit and start");
  assert.equal(store.registry.agent(A).state, "deleted");
  assert.equal(fx.units[A].active, false);
  await close();
});

// ---- the review holds: abandoned effects, pause and revoke-caps failures, recovery from applying, expiry holds

/** An effect that ignores its signal and completes `late` ms after its deadline, running `then` when it does. */
const lateBy = (late, then) => new Promise((res) => setTimeout(() => { then?.(); res(); }, late));

test("SEC H1 / TESTS T1: a start that completes after its deadline can't start the unit; it is fenced; inputs wait for it", async () => {
  const fx = fakeFx();
  let release;
  const gate = new Promise((r) => { release = r; });
  const unmask = fx.unmask;
  fx.unmask = async (id, ...rest) => { if (id === A) await gate; return unmask(id, ...rest); }; // ignores the abort
  const { sup, store, fenceDir, close } = await setup({ fx, deadlines: { start: 50, grace: 50 } });
  const r = await sup.submit({ kind: "grant", bytes: grant(1, [entry(A)]) });
  assert.deepEqual([r.status, r.step, r.settled], ["failed", `start:${A}`, false]);
  assert.ok(existsSync(join(fenceDir, A)), "an unsettled start fences its agent");
  assert.deepEqual([store.registry.agent(A).state, fx.units[A].masked, fx.units[A].active], ["stopped", true, false]);
  assert.ok(fx.audits.some((x) => x.kind === "agent.start" && x.phase === "unknown_effect" && !("reason" in x)));
  // While it is pending: normal inputs are refused; an emergency still runs.
  assert.equal(sup.unsettled, 1);
  assert.deepEqual((await sup.submit({ kind: "grant", bytes: grant(2, [entry(A)]) })).reason, "in_progress");
  assert.equal((await sup.submit({ kind: "stop-all", authority: "local" })).status, "stopped and fenced");
  // It completes late (its unmask lands): the closure sees its abort and never calls start, and the agent is
  // contained again (masked, drained) before any normal input runs.
  release();
  await new Promise((r) => setTimeout(r, 30));
  assert.equal(sup.unsettled, 0);
  for (let i = 0; i < 50 && !fx.units[A].masked; i++) await new Promise((r) => setTimeout(r, 10));
  assert.equal(fx.units[A].masked, true, "contained again after the late unmask");
  assert.equal(fx.units[A].active, false);
  assert.ok(!fx.log.some((l) => l[0] === "start"), "no start after the deadline");
  await close();
});

test("SEC H1: a unit write that completes late can't leave its stale unit to be started: resume regenerates it", async () => {
  const fx = fakeFx();
  const { sup, fenceDir, close } = await setup({ fx, deadlines: { unit: 50, grace: 50 } });
  await sup.submit({ kind: "grant", bytes: grant(1, [entry(A)]) });
  const write = fx.writeUnit;
  fx.writeUnit = async (id, uid, ga, ...rest) => { await lateBy(150); return write(id, uid, ga, ...rest); }; // ignores the abort
  const r = await sup.submit({ kind: "grant", bytes: grant(2, [entry(A, { x: 2 })]) });
  assert.deepEqual([r.status, r.step, r.settled], ["failed", `unit:${A}`, false]);
  assert.ok(existsSync(join(fenceDir, A)));
  await new Promise((res) => setTimeout(res, 200)); // the late write lands: { x: 2 } from the abandoned attempt
  fx.writeUnit = write;
  fx.units[A].unit = JSON.stringify({ x: "stale" });
  assert.equal((await sup.submit({ kind: "grant", bytes: grant(3, [entry(A, { x: 3 })]) })).status, "applied");
  assert.equal(fx.units[A].active, false, "fenced: the grant doesn't start it");
  fx.units[A].unit = JSON.stringify({ x: "left behind" }); // whatever an abandoned effect left on disk
  const rr = await sup.submit({ kind: "resume", authority: "person", agent: A });
  assert.equal(rr.started, true);
  assert.equal(fx.units[A].unit, JSON.stringify({ x: 3 }), "started from a unit regenerated from the current grant");
  await close();
});

for (const [how, freeze] of [
  ["throws", async () => { throw Object.assign(new Error("EIO"), { code: "EIO" }); }],
  ["times out", async (id, ms, signal) => untilAborted(signal)],
  ["completes late", async (id) => lateBy(150)],
]) {
  test(`SEC H2: a freeze that ${how} leaves the agent fenced, stopped and masked (state paused), never running`, async () => {
    const fx = fakeFx();
    const { sup, store, fenceDir, close } = await setup({ fx, deadlines: { freeze: 50, grace: 50 } });
    await sup.submit({ kind: "grant", bytes: grant(1, [entry(A)]) });
    fx.freeze = freeze;
    const r = await sup.submit({ kind: "pause", authority: "service", agent: A });
    assert.deepEqual([r.status, r.fenced, r.proven], ["failed", true, true]);
    assert.deepEqual([store.registry.agent(A).state, fx.units[A].active, fx.units[A].masked], ["paused", false, true]);
    assert.ok(existsSync(join(fenceDir, A)));
    await new Promise((res) => setTimeout(res, 200));
    assert.equal(fx.units[A].active, false);
    const rr = await sup.submit({ kind: "resume", authority: "person", agent: A });
    assert.deepEqual([rr.started, rr.thawed ?? false], [true, false], "not frozen: regenerated and started");
    await close();
  });
}

for (const [how, revoke] of [
  ["throws", async () => { throw Object.assign(new Error("EIO"), { code: "EIO" }); }],
  ["times out", async (id, ms, signal) => untilAborted(signal)],
  ["completes late", async (id) => lateBy(150)],
]) {
  test(`SEC H3: a broker revocation that ${how} leaves the old unit stopped (first) and the agent fenced; nothing revives it`, async () => {
    const fx = fakeFx();
    const { sup, store, fenceDir, close } = await setup({ fx, deadlines: { "broker-gen": 50, grace: 50 } });
    await sup.submit({ kind: "grant", bytes: grant(1, [entry(A)]) });
    fx.brokerRevoke = revoke;
    fx.log.length = 0;
    const r = await sup.submit({ kind: "revoke-caps", authority: "service", agent: A });
    assert.deepEqual([r.status, r.fenced], ["failed", true]);
    assert.ok(kinds(fx.log).indexOf("sys-stop") >= 0, "the old unit was stopped before the broker was asked");
    assert.deepEqual([store.registry.agent(A).state, store.registry.agent(A).life, fx.units[A].active], ["stopped", 1, false]);
    assert.ok(existsSync(join(fenceDir, A)));
    await new Promise((res) => setTimeout(res, 200));
    assert.equal(fx.units[A].active, false, "a late broker completion revives nothing");
    assert.ok(!fx.log.some((l) => l[0] === "start"));
    await close();
  });
}

test("TESTS T2: recovery from applying(N) re-verifies grant N and fails closed when it doesn't verify", async () => {
  const root = tmp("state"), fenceDir = tmp("fence"), fx = fakeFx();
  let s = await setup({ fx, root, fenceDir, barrier: async (n) => { if (n === "after_highwater_persist") throw new Error("crash"); } });
  await assert.rejects(s.sup.submit({ kind: "grant", bytes: grant(1, [entry(A)]) }), /crash/);
  await s.close();
  s = await setup({ fx, root, fenceDir });
  let calls = 0;
  s.sup.verify = () => { calls += 1; throw new FleetError("grant_expired", "expired"); };
  assert.deepEqual(await s.sup.recover(), { status: "not_started", reason: "grant_not_valid" });
  assert.ok(calls >= 1, "verified");
  assert.ok(!fx.log.some((l) => ["start", "unit", "provision", "broker-gen"].includes(l[0])), "no effect at all");
  assert.equal(s.store.grants.pending().phase, "applying");
  await s.close();
});

test("TESTS T3: after unit_failed the agent is stopped; a person's resume clears start_failed and retries it", async () => {
  const fx = fakeFx();
  let fail = true;
  const start = fx.start;
  fx.start = async (id, ...rest) => { if (fail) throw new FleetError("unit_failed", "exited"); return start(id, ...rest); };
  const { sup, store, close } = await setup({ fx });
  await sup.submit({ kind: "grant", bytes: grant(1, [entry(A)]) });
  assert.deepEqual([store.registry.agent(A).state, store.registry.agent(A).start_failed], ["stopped", "unit_failed"]);
  fail = false;
  const r = await sup.submit({ kind: "resume", authority: "person", agent: A });
  assert.equal(r.started, true);
  assert.deepEqual([store.registry.agent(A).state, store.registry.agent(A).start_failed, fx.units[A].active], ["running", null, true]);
  await close();
});

test("TESTS T4: expiry preempting an application holds it at applying(N): no continue, no ack; a newer grant supersedes it", async () => {
  let sup;
  const [first] = [A, B].sort();
  let armed = true;
  const s = await setup({ barrier: async (n, d) => { if (armed && n === "after_unit_write" && d.agent === first) { armed = false; sup.submit({ kind: "expiry", authority: "host" }); } } });
  sup = s.sup;
  const g1 = grant(1, [entry(A), entry(B)]);
  assert.equal((await sup.submit({ kind: "grant", bytes: g1 })).status, "preempted");
  // The same grant again: held, nothing done.
  assert.deepEqual((await sup.submit({ kind: "grant", bytes: g1 })).status, "held");
  await new Promise((r) => setTimeout(r, 50));
  assert.equal(s.store.grants.pending().phase, "applying", "held at applying(N)");
  assert.deepEqual(s.fx.acks, [], "no acknowledgement");
  assert.ok(!s.fx.log.some((l) => l[0] === "start"));
  // A stale one is refused; a newer valid grant lowers expiry and supersedes N, planning every listed agent.
  await rejects(sup.submit({ kind: "grant", bytes: grant(1, [entry(A)]) }), "stale_generation");
  const r = await sup.submit({ kind: "grant", bytes: grant(2, [entry(A), entry(B)]) });
  assert.equal(r.status, "applied");
  assert.deepEqual(r.ack.restarted, [A, B].sort());
  assert.deepEqual(s.fx.acks.map((x) => x[0]), [2]);
  await s.close();
});

test("an applying(N) whose grant no longer verifies is held too, and a newer grant supersedes it", async () => {
  const fx = fakeFx();
  let fail = true;
  fx.daemonReload = async () => { if (fail) throw Object.assign(new Error("EIO"), { code: "EIO" }); };
  const s = await setup({ fx });
  assert.equal((await s.sup.submit({ kind: "grant", bytes: grant(1, [entry(A)]) })).status, "failed");
  fail = false;
  const verify0 = s.sup.verify;
  s.sup.verify = (bytes) => { const v = verify0(bytes); if (v.body.gen === 1) throw new FleetError("grant_expired", "expired"); return v; };
  const r = await s.sup.submit({ kind: "grant", bytes: grant(2, [entry(A)]) });
  assert.equal(r.status, "applied");
  assert.deepEqual(r.ack.restarted, [A]);
  await s.close();
});

test("recovery from an applying(N) held by expiry stays held: nothing continues or starts after a restart", async () => {
  const root = tmp("state"), fenceDir = tmp("fence"), fx = fakeFx();
  let sup, armed = true, expiry = null;
  const [first] = [A, B].sort();
  let s = await setup({ fx, root, fenceDir, barrier: async (n, d) => { if (armed && n === "after_unit_write" && d.agent === first) { armed = false; expiry = sup.submit({ kind: "expiry", authority: "host" }); } } });
  sup = s.sup;
  // The expiry's masks are slow, so it is still running when the held grant resolves: the store is closed only after
  // the expiry it preempted with has finished (closing earlier would refuse its later writes).
  const mask = fx.mask;
  fx.mask = async (...a) => { await new Promise((r) => setTimeout(r, 100)); return mask(...a); };
  await sup.submit({ kind: "grant", bytes: grant(1, [entry(A), entry(B)]) });
  assert.ok(expiry, "the expiry was submitted during the application");
  assert.equal((await expiry).status, "stopped and fenced");
  fx.mask = mask;
  await s.close();
  s = await setup({ fx, root, fenceDir });
  assert.deepEqual(await s.sup.recover(), { status: "held", reason: "expired" });
  assert.equal(s.store.grants.pending().phase, "applying");
  assert.ok(!fx.log.some((l) => l[0] === "start"));
  await s.close();
});

test("containment raises the fence when it can't mask, or can't prove the cgroup empty", async () => {
  for (const broken of ["mask", "proof"]) {
    const fx = fakeFx();
    fx.start = async () => { throw new FleetError("unit_failed", "exited"); };
    if (broken === "mask") fx.mask = async () => { throw Object.assign(new Error("EIO"), { code: "EIO" }); };
    else fx.sys.procCount = () => 1;
    const { sup, fenceDir, close } = await setup({ fx });
    await sup.submit({ kind: "grant", bytes: grant(1, [entry(A)]) });
    assert.ok(existsSync(join(fenceDir, A)), `${broken}: fenced`);
    await close();
  }
});

// ---- second review round: no authority-giving effect after an unsettled one; an unproven containment is host-side

test("a thaw that doesn't settle stops the resume there: contained with a fence, nothing written or started after it", async () => {
  const fx = fakeFx();
  const { sup, store, fenceDir, close } = await setup({ fx, deadlines: { freeze: 20, grace: 20 } });
  await sup.submit({ kind: "grant", bytes: grant(1, [entry(A)]) });
  await sup.submit({ kind: "pause", authority: "service", agent: A });
  // (the thaw settles only when this test says so, never by a timer: the resume's own time under load can't race it)
  let settle;
  fx.thaw = () => new Promise((res) => { settle = res; }); // ignores its abort
  fx.log.length = 0;
  const r = await sup.submit({ kind: "resume", authority: "person", agent: A });
  assert.deepEqual([r.status, r.settled, r.fenced], ["failed", false, true]);
  assert.ok(!fx.log.some((l) => ["unit", "daemon-reload", "unmask", "start"].includes(l[0])), "no widening effect after the unsettled thaw");
  assert.deepEqual([store.registry.agent(A).state, fx.units[A].active, existsSync(join(fenceDir, A))], ["stopped", false, true]);
  // Until it settles, an authority-giving effect is refused even inside an emergency's own sequence.
  assert.equal(sup.unsettled, 1);
  settle();
  // (settled: the count falls to 0, polled within a bound rather than after a fixed sleep)
  for (const t0 = Date.now(); sup.unsettled !== 0 && Date.now() - t0 < 5000;) await new Promise((res) => setTimeout(res, 10));
  assert.equal(sup.unsettled, 0);
  await close();
});

test("a failed start whose containment can't prove the cgroup empty is host-side: applying(N) stays, no ack", async () => {
  const fx = fakeFx();
  fx.start = async (id) => { fx.u(id).active = true; throw new FleetError("unit_failed", "exited"); };
  fx.sys.stop = () => { throw new Error("EIO"); };
  fx.sys.procCount = () => 1;
  const { sup, store, fenceDir, close } = await setup({ fx });
  const r = await sup.submit({ kind: "grant", bytes: grant(1, [entry(A)]) });
  assert.deepEqual([r.status, r.step, r.reason], ["failed", `start:${A}`, "not_empty"]);
  assert.equal(store.grants.pending().phase, "applying");
  assert.deepEqual(fx.acks, []);
  assert.ok(existsSync(join(fenceDir, A)), "fenced");
  await close();
});

test("after any effect goes unsettled, the running operation does no authority-giving effect (revoke-caps with a hung mask)", async () => {
  const fx = fakeFx();
  const { sup, fenceDir, close } = await setup({ fx, deadlines: { mask: 20, grace: 20 } });
  await sup.submit({ kind: "grant", bytes: grant(1, [entry(A)]) });
  const mask = fx.mask;
  // The mask ignores its abort and settles only when the test releases it, after the assertions: never by a clock,
  // so a stalled runner can't let it settle within the grace.
  let release;
  const held = new Promise((res) => { release = res; });
  fx.mask = async (id, ...rest) => { await held; return mask(id, ...rest); };
  fx.log.length = 0;
  const r = await sup.submit({ kind: "revoke-caps", authority: "service", agent: A });
  assert.equal(r.status, "failed");
  assert.ok(!fx.log.some((l) => ["unit", "daemon-reload", "unmask", "start"].includes(l[0])), "no unit write, reload or start");
  assert.ok(existsSync(join(fenceDir, A)));
  assert.equal(fx.units[A].active, false);
  // Teardown: a mask that works again, then wait for the late one to settle and its re-containment to finish (it
  // would otherwise reschedule itself for ever, keeping an unforced test run alive).
  fx.mask = mask;
  release();
  for (let i = 0; i < 250 && sup.unsettled > 0; i++) await new Promise((res) => setTimeout(res, 20));
  assert.equal(sup.unsettled, 0);
  await sup.submit({ kind: "resume-all", authority: "person" }); // a normal input: runs after the queued re-containment
  await close();
});

test("SEC H3-new: a grant is verified again after the previous application finishes, and after its intent; never carried", async () => {
  // astra4b's probe: N+1 verifies; N's remaining work then flips N+1 to expired; N+1 must not be accepted.
  for (const where of ["redo", "intent"]) {
    const fx = fakeFx();
    let g2valid = true, failMap = true;
    fx.publishMap = async (g) => { if (failMap) { failMap = false; throw new Error("first map fails"); } if (where === "redo") g2valid = false; };
    if (where === "intent") { const ai = fx.appendIntent; fx.appendIntent = async (r) => { await ai(r); if (r.gen === 2) g2valid = false; }; failMap = false; }
    const { sup, store, close } = await setup({ fx });
    sup.verify = (b) => { const v = verify(b); if (v.body.gen === 2 && !g2valid) throw new FleetError("grant_expired", "expired"); return v; };
    await sup.submit({ kind: "grant", bytes: grant(1, [entry(A)]) });
    await rejects(sup.submit({ kind: "grant", bytes: grant(2, [entry(A, { x: 2 })]) }), "grant_expired");
    assert.equal(store.grants.highwater.gen, 1, `${where}: N+1 not accepted`);
    assert.equal(store.grants.pending().phase, "applied");
    await close();
  }
});

test("SEC H3-new: a grant that expires while its own unfinished application is redone is refused, not re-applied", async () => {
  const fx = fakeFx();
  let valid = true, failMap = true;
  fx.publishMap = async () => { if (failMap) { failMap = false; throw new Error("first map fails"); } valid = false; };
  const { sup, close } = await setup({ fx });
  sup.verify = (b) => { const v = verify(b); if (!valid) throw new FleetError("grant_expired", "expired"); return v; };
  const g1 = grant(1, [entry(A)]);
  assert.equal((await sup.submit({ kind: "grant", bytes: g1 })).status, "failed");
  // Verified again after the redo: refused, not "reapplied" with a re-sent acknowledgement.
  await rejects(sup.submit({ kind: "grant", bytes: g1 }), "grant_expired");
  await close();
});

// ---- third review round: a failed containment stays a pending proof through every retry

for (const count of ["positive", "unreadable"]) {
  test(`an unproven containment (count ${count}) is never cleared by a retry: same grant, next grant, restart and recovery`, async () => {
    const root = tmp("state"), fenceDir = tmp("fence"), fx = fakeFx();
    let stuck = true;
    fx.start = async (id) => { fx.u(id).active = true; throw new FleetError("unit_failed", "exited"); };
    const sysStop = fx.sys.stop, sysCount = fx.sys.procCount;
    fx.sys.stop = (u) => { if (stuck) throw new Error("EIO"); return sysStop(u); };
    fx.sys.procCount = (u) => { if (stuck) { if (count === "unreadable") throw new Error("EIO"); return 1; } return sysCount(u); };
    let s = await setup({ fx, root, fenceDir });
    const g1 = grant(1, [entry(A)]);
    assert.deepEqual([(await s.sup.submit({ kind: "grant", bytes: g1 })).reason], ["not_empty"]);
    // The same grant again: the start step is redone and still can't prove the agent down.
    const r2 = await s.sup.submit({ kind: "grant", bytes: g1 });
    assert.deepEqual([r2.status, r2.reason], ["refused", "in_progress"]);
    assert.equal(r2.previous.reason, "not_empty");
    // The next grant: refused while N can't finish.
    assert.equal((await s.sup.submit({ kind: "grant", bytes: grant(2, [entry(A)]) })).reason, "in_progress");
    assert.equal(s.store.grants.pending().phase, "applying");
    assert.deepEqual(fx.acks, [], "never applied, never acknowledged");
    await s.close();
    // A restart: recovery redoes the step and still fails closed.
    s = await setup({ fx, root, fenceDir });
    const rec = await s.sup.recover();
    assert.deepEqual([rec.status, rec.reason], ["failed", "not_empty"]);
    assert.deepEqual(fx.acks, []);
    await s.close();
    // Once the count really reaches 0, recovery proves it and finishes N; the agent stays stopped.
    stuck = false;
    s = await setup({ fx, root, fenceDir });
    assert.equal((await s.sup.recover()).status, "applied");
    assert.deepEqual(fx.acks.map((a) => a[0]), [1]);
    assert.deepEqual([fx.units[A].active, s.store.registry.agent(A).state], [false, "stopped"]);
    await s.close();
  });
}

test("recovery from applied(N) proves every agent it doesn't start; an unproven one is reported", async () => {
  const root = tmp("state"), fenceDir = tmp("fence"), fx = fakeFx();
  let s = await setup({ fx, root, fenceDir });
  await s.sup.submit({ kind: "grant", bytes: grant(1, [entry(A), entry(B)]) });
  await s.sup.submit({ kind: "stop", authority: "service", agent: B });
  await s.close();
  fx.units[B].active = true; // something of B outlived the supervisor
  const sysStop = fx.sys.stop;
  fx.sys.stop = (u) => { if (u.includes(B)) throw new Error("EIO"); return sysStop(u); };
  s = await setup({ fx, root, fenceDir });
  const r = await s.sup.recover();
  assert.deepEqual(r.unproven, [B]);
  fx.sys.stop = sysStop;
  await s.close();
  s = await setup({ fx, root, fenceDir });
  const r2 = await s.sup.recover();
  assert.equal(r2.unproven, undefined);
  assert.equal(fx.units[B].active, false);
  await s.close();
});

// ---- fourth review round: a start step completes only by a real start or a passed proof, whatever the state


/**
 * Leave applying(1) with A's start step pending and A's cgroup stuck (count positive or unreadable), then put A's
 * registry record in `state`. provisioned: a crash before the start step; every other state: a failed start whose
 * containment couldn't be proven, then registry moves.
 */
async function stuckAt(state, count) {
  const root = tmp("state"), fenceDir = tmp("fence"), fx = fakeFx();
  const stuck = { on: true };
  fx.start = async (id) => { fx.u(id).active = true; throw new FleetError("unit_failed", "exited"); };
  const sysStop = fx.sys.stop, sysCount = fx.sys.procCount;
  fx.sys.stop = (u) => { if (stuck.on) throw new Error("EIO"); return sysStop(u); };
  fx.sys.procCount = (u) => { if (stuck.on) { if (count === "unreadable") throw new Error("EIO"); return 1; } return sysCount(u); };
  const g1 = grant(1, [entry(A)]);
  let s;
  if (state === "provisioned") {
    s = await setup({ fx, root, fenceDir, barrier: async (n) => { if (n === "after_daemon_reload") throw new Error("crash"); } });
    await assert.rejects(s.sup.submit({ kind: "grant", bytes: g1 }), /crash/);
    fx.u(A).active = true; // something of A runs anyway (a leftover)
  } else {
    s = await setup({ fx, root, fenceDir });
    assert.equal((await s.sup.submit({ kind: "grant", bytes: g1 })).reason, "not_empty");
    const path = { stopped: [], running: ["running"], paused: ["running", "paused"], revoked: ["revoked"], deleted: ["deleted"] }[state];
    for (const st of path) s.store.registry.setState(A, st);
  }
  assert.equal(s.store.registry.agent(A).state, state);
  await s.close();
  return { root, fenceDir, fx, g1, stuck };
}

for (const state of STATES) {
  for (const count of ["positive", "unreadable"]) {
    test(`structural: registry state ${state}, count ${count}: the start step never completes, no applied, no ack`, async () => {
      const { root, fenceDir, fx, g1, stuck } = await stuckAt(state, count);
      let s = await setup({ fx, root, fenceDir });
      const r = await s.sup.submit({ kind: "grant", bytes: g1 }); // the same grant: redo
      assert.notEqual(r.status, "reapplied");
      assert.notEqual(r.status, "applied");
      assert.equal(s.store.grants.pending().phase, "applying");
      await s.close();
      s = await setup({ fx, root, fenceDir });
      const rec = await s.sup.recover();
      assert.notEqual(rec.status, "applied");
      assert.equal(s.store.grants.pending().phase, "applying");
      assert.deepEqual(fx.acks, [], "never acknowledged while the count isn't a proven 0");
      await s.close();
      // A proof that really passes completes it (or a real start does, for a state that may start).
      stuck.on = false;
      fx.start = async (id) => { if (!fx.u(id).masked && !fx.fenced(id)) fx.u(id).active = true; else if (fx.u(id).masked) throw new Error("masked"); };
      s = await setup({ fx, root, fenceDir });
      assert.equal((await s.sup.recover()).status, "applied");
      assert.equal(fx.acks.length, 1);
      await s.close();
    });
  }
}

test("SEC r4 (astra4b): a person's delete while the proof is pending doesn't let the same grant finish", async () => {
  const fx = fakeFx();
  fx.start = async (id) => { fx.u(id).active = true; throw new FleetError("unit_failed", "exited"); };
  fx.sys.stop = () => { throw new Error("stop failed"); };
  const { sup, store, close } = await setup({ fx, deadlines: { stop: 100 } });
  const g1 = grant(1, [entry(A)]);
  assert.equal((await sup.submit({ kind: "grant", bytes: g1 })).reason, "not_empty");
  const del = await sup.submit({ kind: "delete", authority: "person", agent: A });
  assert.notEqual(del.status, "stopped and fenced");
  assert.equal(store.registry.agent(A).state, "deleted");
  const r = await sup.submit({ kind: "grant", bytes: g1 });
  assert.deepEqual([r.status, r.reason], ["refused", "in_progress"]);
  assert.equal(store.grants.pending().phase, "applying");
  assert.deepEqual(fx.acks, []);
  assert.equal(fx.units[A].active, true, "(the fake's cgroup really is still populated)");
  await close();
});

// ---- fifth review round: a pending proof survives supersession

for (const listed of [true, false]) {
  test(`supersede carries the pending proof (agent ${listed ? "listed" : "absent"} in the new grant, deleted): no applied, no ack until a real 0`, async () => {
    const root = tmp("state"), fenceDir = tmp("fence"), fx = fakeFx();
    let stuck = true, g1valid = true;
    fx.start = async (id) => { fx.u(id).active = true; throw new FleetError("unit_failed", "exited"); };
    const sysStop = fx.sys.stop, sysCount = fx.sys.procCount;
    fx.sys.stop = (u) => { if (stuck) throw new Error("EIO"); return sysStop(u); };
    fx.sys.procCount = (u) => (stuck ? 1 : sysCount(u));
    const v = (b) => { const r = verify(b); if (r.body.gen === 1 && !g1valid) throw new FleetError("grant_expired", "expired"); return r; };
    let s = await setup({ fx, root, fenceDir });
    s.sup.verify = v;
    assert.equal((await s.sup.submit({ kind: "grant", bytes: grant(1, [entry(A)]) })).reason, "not_empty");
    await s.sup.submit({ kind: "delete", authority: "person", agent: A });
    g1valid = false; // grant 1 expires: grant 2 supersedes the held application
    const g2 = grant(2, listed ? [entry(A), entry(B)] : [entry(B)]);
    const r = await s.sup.submit({ kind: "grant", bytes: g2 });
    assert.deepEqual([r.status, r.step, r.reason], ["failed", `prove:${A}`, "not_empty"]);
    assert.equal(s.store.grants.highwater.gen, 2);
    assert.equal(s.store.grants.steps()[0], `prove:${A}`, "carried durably as the new plan's first step");
    assert.deepEqual(s.store.grants.pendingProofs(), [A], "the host-level pending proof");
    assert.deepEqual(fx.acks, []);
    await s.close();
    // Recovery: still pending while the count is 1.
    s = await setup({ fx, root, fenceDir }); s.sup.verify = v;
    assert.equal((await s.sup.recover()).reason, "not_empty");
    assert.deepEqual(fx.acks, []);
    await s.close();
    // A real 0 completes it.
    stuck = false;
    fx.start = async (id) => { if (fx.u(id).masked) throw new Error("masked"); if (!fx.fenced(id)) fx.u(id).active = true; };
    s = await setup({ fx, root, fenceDir }); s.sup.verify = v;
    const rec = await s.sup.recover();
    assert.equal(rec.status, "applied");
    assert.deepEqual(fx.acks.map((x) => x[0]), [2]);
    assert.equal(fx.units[A].active, false);
    assert.deepEqual(s.store.grants.pendingProofs(), [], "cleared only by the passing proof");
    await s.close();
  });
}

test("plan: prove steps parse; the planner itself never makes one", () => {
  assert.deepEqual(parseStep(`prove:${A}`), { kind: "prove", agent: A });
  const p = planGrant({ agents: [entry(A)] }, { agents: [entry(B)] }, { agent: (id) => (id === A ? { state: "running", start_failed: null } : null) });
  assert.ok(!p.steps.some((x) => x.startsWith("prove:")));
});

test("pendingProof: a failed containment anywhere (here revoke-caps) blocks every later applied and ack until proven", async () => {
  const fx = fakeFx();
  const { sup, store, close } = await setup({ fx });
  const g1 = grant(1, [entry(A), entry(B)]);
  await sup.submit({ kind: "grant", bytes: g1 });
  let stuck = true;
  const sysStop = fx.sys.stop, sysCount = fx.sys.procCount;
  fx.sys.stop = (u) => { if (stuck && u.includes(A)) throw new Error("EIO"); return sysStop(u); };
  fx.sys.procCount = (u) => (stuck && u.includes(A) ? 1 : sysCount(u));
  const r = await sup.submit({ kind: "revoke-caps", authority: "service", agent: A });
  assert.equal(r.status, "failed");
  assert.deepEqual(store.grants.pendingProofs(), [A]);
  // The same grant again: no re-sent acknowledgement while a proof is pending.
  const re = await sup.submit({ kind: "grant", bytes: g1 });
  assert.deepEqual([re.status, re.reason], ["refused", "in_progress"]);
  // A next grant that doesn't touch A (or lists only B) still starts with A's proof and can't finish.
  const acks = fx.acks.length;
  fx.log.length = 0;
  const r2 = await sup.submit({ kind: "grant", bytes: grant(2, [entry(B), entry(C)]) });
  assert.deepEqual([r2.status, r2.step], ["failed", `prove:${A}`]);
  assert.equal(r2.step, store.grants.steps()[0], "the pending proof is the new plan's FIRST step");
  assert.ok(!fx.log.some((l) => ["provision", "start", "broker-gen"].includes(l[0])), "nothing of the new plan ran before it");
  assert.equal(fx.acks.length, acks);
  stuck = false;
  const r3 = await sup.submit({ kind: "grant", bytes: grant(3, [entry(B), entry(C)]) });
  assert.equal(r3.status, "applied");
  assert.deepEqual(store.grants.pendingProofs(), []);
  await close();
});

test("pendingProof raised DURING an application (a preempting revoke-caps) blocks that application's applied and ack", async () => {
  const fx = fakeFx();
  let sup, stuck = false, armed = false;
  const sysStop = fx.sys.stop, sysCount = fx.sys.procCount;
  fx.sys.stop = (u) => { if (stuck && u.includes(A)) throw new Error("EIO"); return sysStop(u); };
  fx.sys.procCount = (u) => (stuck && u.includes(A) ? 1 : sysCount(u));
  const s = await setup({ fx, barrier: async (n) => { if (armed && n === "after_broker_gen") { armed = false; sup.submit({ kind: "revoke-caps", authority: "service", agent: A }); } } });
  sup = s.sup;
  await sup.submit({ kind: "grant", bytes: grant(1, [entry(A), entry(B)]) });
  stuck = true; armed = true;
  const g2 = grant(2, [entry(A), entry(B, { x: 2 })]);
  assert.equal((await sup.submit({ kind: "grant", bytes: g2 })).status, "preempted");
  // The continued application can't finish: A's proof is pending.
  const r = await sup.submit({ kind: "grant", bytes: g2 });
  assert.equal(r.status, "refused");
  // Refused at the first widening step for A after the proof became pending (here the map publish), else at finish.
  assert.ok(["daemon-reload", "map", `prove:${A}`].includes(r.previous.step), r.previous.step);
  assert.equal(r.previous.reason, "not_empty");
  assert.equal(s.store.grants.pending().phase, "applying");
  assert.deepEqual(fx.acks.map((x) => x[0]), [1]);
  stuck = false;
  // The same grant again: the held application is finished first (now proven), then it is a re-apply.
  assert.equal((await sup.submit({ kind: "grant", bytes: g2 })).status, "reapplied");
  assert.equal(s.store.grants.pending().phase, "applied");
  assert.deepEqual(fx.acks.map((x) => x[0]), [1, 2, 2]);
  assert.deepEqual(s.store.grants.pendingProofs(), []);
  await s.close();
});

// ---- sixth review round: the pending-proof mark lives in the one stop primitive, so every lifecycle op gets it

const OPS = [
  ["stop (service)", (sup) => sup.submit({ kind: "stop", authority: "service", agent: A })],
  ["stop (local)", (sup) => sup.submit({ kind: "stop", authority: "local", agent: A })],
  ["stop-all (local)", (sup) => sup.submit({ kind: "stop-all", authority: "local" })],
  ["expiry", (sup) => sup.submit({ kind: "expiry", authority: "host" })],
  ["delete (person)", (sup) => sup.submit({ kind: "delete", authority: "person", agent: A })],
  ["revoke-caps (service)", (sup) => sup.submit({ kind: "revoke-caps", authority: "service", agent: A })],
  ["pause with a failing freeze", (sup, fx) => { fx.freeze = async () => { throw Object.assign(new Error("EIO"), { code: "EIO" }); }; return sup.submit({ kind: "pause", authority: "service", agent: A }); }],
  ["resume with a failing start", async (sup, fx, store) => {
    store.registry.setState(A, "stopped");
    fx.start = async (id) => { fx.u(id).active = true; throw new FleetError("unit_failed", "exited"); };
    return sup.submit({ kind: "resume", authority: "person", agent: A });
  }],
];

for (const [name, op] of OPS) {
  test(`every lifecycle op marks the pending proof when its stop fails: ${name}; no ack, fresh or re-sent, until a real 0`, async () => {
    const root = tmp("state"), fenceDir = tmp("fence"), fx = fakeFx();
    let s = await setup({ fx, root, fenceDir });
    const g1 = grant(1, [entry(A)]);
    await s.sup.submit({ kind: "grant", bytes: g1 });
    const acks = fx.acks.length;
    let stuck = true;
    const sysStop = fx.sys.stop, sysCount = fx.sys.procCount;
    fx.sys.stop = (u) => { if (stuck) throw new Error("EIO"); return sysStop(u); };
    fx.sys.procCount = (u) => (stuck ? 1 : sysCount(u));
    fx.u(A).active = true;
    await op(s.sup, fx, s.store);
    assert.ok(s.store.grants.pendingProofs().includes(A), `${name}: A is a pending proof`);
    const re = await s.sup.submit({ kind: "grant", bytes: g1 });
    assert.deepEqual([re.status, re.reason], ["refused", "in_progress"], `${name}: no re-sent acknowledgement`);
    assert.equal(fx.acks.length, acks);
    await s.close();
    // Only a passing proof clears it (here recovery's, once the count really reaches 0).
    stuck = false;
    s = await setup({ fx, root, fenceDir });
    await s.sup.recover();
    assert.deepEqual(s.store.grants.pendingProofs(), []);
    await s.close();
  });
}

test("TESTS r6 (astra2): a person's stop or delete that can't prove the cgroup empty marks the proof; the same grant isn't re-acknowledged", async () => {
  for (const kind of ["stop", "delete"]) {
    const fx = fakeFx();
    const { sup, store, close } = await setup({ fx });
    const g1 = grant(1, [entry(A)]);
    await sup.submit({ kind: "grant", bytes: g1 });
    fx.sys.stop = () => { throw new Error("EIO"); };
    fx.sys.procCount = () => 1;
    const r = await sup.submit({ kind, authority: "person", agent: A });
    assert.equal(r.status, "not empty");
    assert.deepEqual(store.grants.pendingProofs(), [A]);
    const re = await sup.submit({ kind: "grant", bytes: g1 });
    assert.equal(re.status, "refused");
    assert.deepEqual(fx.acks.map((x) => x[0]), [1], "only the original acknowledgement");
    await close();
  }
});

// ---- seventh review round: a pending agent never starts, whoever asks; recovery proves every pending agent first


for (const count of ["positive", "unreadable"]) {
  test(`SEC r7: a failed stop-all with no durable fence (count ${count}), then a restart: recovery proves first and starts nothing`, async () => {
    const root = tmp("state"), fenceDir = tmp("fence"), fx = fakeFx();
    let s = await setup({ fx, root, fenceDir });
    await s.sup.submit({ kind: "grant", bytes: grant(1, [entry(A)]) });
    let stuck = true;
    const sysStop = fx.sys.stop, sysCount = fx.sys.procCount;
    fx.sys.stop = (u) => { if (stuck) throw new Error("EIO"); return sysStop(u); };
    fx.sys.procCount = (u) => { if (stuck) { if (count === "unreadable") throw new Error("EIO"); return 1; } return sysCount(u); };
    chmodSync(fenceDir, 0o500); // the fence can't be written
    const r = await s.sup.submit({ kind: "stop-all", authority: "local" });
    chmodSync(fenceDir, 0o700);
    assert.notEqual(r.status, "stopped and fenced");
    assert.equal(r.fenced, false);
    assert.deepEqual(s.store.grants.pendingProofs(), [A]);
    assert.equal(s.store.registry.agent(A).state, "running");
    // Still running in the registry and with no fence: only the guard in #start keeps a person's resume-all from
    // starting it.
    fx.log.length = 0;
    assert.deepEqual((await s.sup.submit({ kind: "resume-all", authority: "person" })).started, []);
    assert.ok(!fx.log.some((l) => l[0] === "start"), "the #start guard");
    await s.close();
    fx.u(A).active = true;
    fx.log.length = 0;
    s = await setup({ fx, root, fenceDir });
    const rec = await s.sup.recover();
    assert.deepEqual([rec.started, rec.unproven], [[], [A]]);
    assert.ok(!fx.log.some((l) => l[0] === "start" || l[0] === "unmask"), "no start for a pending agent");
    assert.deepEqual(s.store.grants.pendingProofs(), [A]);
    // Nor through a person's resume-all, or a resume.
    assert.deepEqual((await s.sup.submit({ kind: "resume-all", authority: "person" })).started, []);
    assert.ok(!fx.log.some((l) => l[0] === "start"));
    await s.close();
    // A real 0: recovery proves it and clears the pending proof. The failed proof had escalated (state stopped, A's own
    // fence), so A stays down until a person resumes it, and then it starts.
    stuck = false;
    s = await setup({ fx, root, fenceDir });
    const rec2 = await s.sup.recover();
    assert.deepEqual([rec2.started, rec2.unproven], [[], undefined]);
    assert.deepEqual(s.store.grants.pendingProofs(), []);
    assert.equal(s.store.registry.agent(A).state, "stopped");
    assert.equal((await s.sup.submit({ kind: "resume", authority: "person", agent: A })).started, true);
    assert.equal(fx.u(A).active, true);
    await s.close();
  });
}

test("SEC r7: recovery proves EVERY pending agent first, also one the current grant no longer lists", async () => {
  const root = tmp("state"), fenceDir = tmp("fence"), fx = fakeFx();
  let s = await setup({ fx, root, fenceDir });
  await s.sup.submit({ kind: "grant", bytes: grant(1, [entry(A)]) });
  await s.sup.submit({ kind: "grant", bytes: grant(2, [entry(B)]) }); // A retired
  let stuck = true;
  const sysStop = fx.sys.stop, sysCount = fx.sys.procCount;
  fx.sys.stop = (u) => { if (stuck) throw new Error("EIO"); return sysStop(u); };
  fx.sys.procCount = (u) => (stuck ? 1 : sysCount(u));
  await s.sup.submit({ kind: "stop-all", authority: "local" });
  assert.deepEqual(s.store.grants.pendingProofs(), [A, B].sort());
  await s.close();
  stuck = false;
  s = await setup({ fx, root, fenceDir });
  await s.sup.recover();
  assert.deepEqual(s.store.grants.pendingProofs(), [], "A too, though grant 2 doesn't list it");
  await s.close();
});

// ---- eighth review round: ONE widening gate; nothing widens a pending agent before a passing proof

/** Grant 1 applied with A running; then a failed stop leaves A pending (count stuck). Returns helpers. */
async function pendingA({ via = "stop", fx = fakeFx() } = {}) {
  const root = tmp("state"), fenceDir = tmp("fence");
  const s = await setup({ fx, root, fenceDir });
  await s.sup.submit({ kind: "grant", bytes: grant(1, [entry(A)]) });
  const stuck = { on: true };
  const sysStop = fx.sys.stop, sysCount = fx.sys.procCount;
  fx.sys.stop = (u) => { if (stuck.on) throw new Error("EIO"); return sysStop(u); };
  fx.sys.procCount = (u) => (stuck.on ? 1 : sysCount(u));
  if (via === "stop") await s.sup.submit({ kind: "stop", authority: "service", agent: A });
  if (via === "stop-all") await s.sup.submit({ kind: "stop-all", authority: "local" });
  if (via === "pause") {
    fx.freeze = async (id) => { fx.u(id).frozen = true; throw Object.assign(new Error("EIO"), { code: "EIO" }); }; // takes effect, then throws
    await s.sup.submit({ kind: "pause", authority: "service", agent: A });
  }
  assert.deepEqual(s.store.grants.pendingProofs(), [A]);
  const snapshot = () => ({
    fences: ["all", A, "expiry"].filter((n) => existsSync(join(fenceDir, n))),
    state: s.store.registry.agent(A).state,
    widened: fx.log.filter((l) => ["unit", "daemon-reload", "unmask", "start", "thaw", "map", "provision", "broker-gen"].includes(l[0])).length,
    active: fx.u(A).active, frozen: fx.u(A).frozen, masked: fx.u(A).masked,
  });
  return { ...s, fx, root, fenceDir, stuck, snapshot };
}

test("SEC r8 (astra4b): a pending, paused, frozen agent: a person's resume is refused before any fence, state or thaw", async () => {
  const p = await pendingA({ via: "pause" });
  assert.equal(p.store.registry.agent(A).state, "paused");
  const before = p.snapshot();
  const r = await p.sup.submit({ kind: "resume", authority: "person", agent: A });
  assert.deepEqual([r.status, r.reason, r.started], ["refused", "pending_proof", false]);
  assert.deepEqual(p.snapshot(), before, "nothing changed: no fence lowered, no state change, no thaw");
  // At a real 0 the same resume proves it first, then goes on.
  p.stuck.on = false;
  const r2 = await p.sup.submit({ kind: "resume", authority: "person", agent: A });
  assert.equal(r2.status, "resumed");
  assert.deepEqual(p.store.grants.pendingProofs(), []);
  await p.close();
});

test("SEC r8: a stopped pending agent: resume is refused with no fence lowering, state change or unit write before the proof", async () => {
  const p = await pendingA({ via: "stop" });
  assert.equal(p.store.registry.agent(A).state, "stopped");
  assert.ok(p.snapshot().fences.includes(A));
  const before = p.snapshot();
  const r = await p.sup.submit({ kind: "resume", authority: "person", agent: A });
  assert.deepEqual([r.status, r.reason], ["refused", "pending_proof"]);
  assert.deepEqual(p.snapshot(), before);
  await p.close();
});

test("SEC r8: every widening effect, called for a pending agent, is refused with nothing changed", async () => {
  // Ops: resume, resume-all, revoke-caps' restart, and a grant whose plan widens A, plus recovery.
  const p = await pendingA({ via: "stop-all" });
  const before = p.snapshot();
  const ops = [
    ["resume", () => p.sup.submit({ kind: "resume", authority: "person", agent: A })],
    ["resume-all", () => p.sup.submit({ kind: "resume-all", authority: "person" })],
    ["revoke-caps", () => p.sup.submit({ kind: "revoke-caps", authority: "service", agent: A })],
    ["a grant widening A", () => p.sup.submit({ kind: "grant", bytes: grant(2, [entry(A, { x: 2 })]) })],
    ["recovery", () => p.sup.recover()],
  ];
  for (const [name, op] of ops) {
    try { await op(); } catch (e) { assert.ok(e instanceof FleetError, `${name}: ${e?.message}`); } // a refusal either way
    const now = p.snapshot();
    // Nothing widened: no fence lowered (a failed proof may RAISE the agent's own fence: that only narrows), no
    // widening effect, the agent not started.
    for (const f of before.fences) assert.ok(now.fences.includes(f), `${name}: fence ${f} still up`);
    assert.deepEqual([now.widened, now.active === true && !before.active], [before.widened, false], name);
    assert.ok(!["running"].includes(now.state) || before.state === "running", `${name}: no registry move toward running`);
  }
  assert.deepEqual(p.fx.acks.map((x) => x[0]), [1], "no acknowledgement");
  // The plan steps' own gates: each widening step of a plan refuses a pending agent before its effect.
  await p.close();
});

for (const step of ["unit", "start", "map"]) {
  test(`SEC r8: a plan's ${step} step refuses an agent that became pending mid-application, before its effect`, async () => {
    const fx = fakeFx();
    let sup, store, armed = false;
    const at = { unit: "after_broker_gen", start: "after_daemon_reload", map: "after_start" }[step];
    let stuck = false;
    const sysStop = fx.sys.stop, sysCount = fx.sys.procCount;
    fx.sys.stop = (u) => { if (stuck) throw new Error("EIO"); return sysStop(u); };
    fx.sys.procCount = (u) => (stuck ? 1 : sysCount(u));
    const s = await setup({ fx, barrier: async (n) => { if (armed && n === at) { armed = false; stuck = true; store.grants.markProof(A); } } });
    sup = s.sup; store = s.store;
    await sup.submit({ kind: "grant", bytes: grant(1, [entry(A)]) });
    armed = true;
    fx.log.length = 0;
    const r = await sup.submit({ kind: "grant", bytes: grant(2, [entry(A, { x: 2 })]) });
    assert.equal(r.status, "failed");
    const effect = { unit: "unit", start: "start", map: "map" }[step];
    assert.ok(!fx.log.some((l) => l[0] === effect && (l[1] === A || effect === "map")), `no ${effect} for the pending agent`);
    assert.deepEqual(fx.acks.map((x) => x[0]), [1]);
    // Liveness: once the count is really 0, the redo proves A at that same step and finishes.
    stuck = false;
    const r2 = await sup.submit({ kind: "grant", bytes: grant(2, [entry(A, { x: 2 })]) });
    assert.ok(["applied", "reapplied"].includes(r2.status), r2.status);
    assert.deepEqual(store.grants.pendingProofs(), []);
    await s.close();
  });
}

test("SEC r8: lowering the expiry fence is a gated step (unexpire): refused while any proof is pending", async () => {
  const p = await pendingA({ via: "stop" });
  await p.sup.submit({ kind: "expiry", authority: "host" });
  assert.ok(existsSync(join(p.fenceDir, "expiry")));
  const r = await p.sup.submit({ kind: "grant", bytes: grant(2, [entry(A)]) });
  assert.equal(r.status, "failed");
  assert.ok(existsSync(join(p.fenceDir, "expiry")), "the expiry fence stays up");
  p.stuck.on = false;
  const r2 = await p.sup.submit({ kind: "grant", bytes: grant(2, [entry(A)]) });
  assert.ok(["applied", "reapplied"].includes(r2.status), r2.status);
  assert.ok(!existsSync(join(p.fenceDir, "expiry")), "lowered once proven");
  await p.close();
});

test("SEC r8: revoke-caps for a pending agent proves it first: refused while stuck, restarts once the count is really 0", async () => {
  const p = await pendingA({ via: "stop-all" });
  await p.sup.submit({ kind: "resume-all", authority: "person" }).catch(() => {});
  p.fx.log.length = 0;
  const r = await p.sup.submit({ kind: "revoke-caps", authority: "service", agent: A });
  assert.equal(r.status, "failed");
  assert.ok(!p.fx.log.some((l) => ["unit", "unmask", "start"].includes(l[0]) && l[1] === A));
  await p.close();
  // At a real 0, with A pending, running and unfenced (a stop-all that couldn't write its fence): revoke-caps itself
  // proves A, then regenerates and restarts it.
  const fx = fakeFx();
  const root = tmp("state"), fenceDir = tmp("fence");
  const q = await setup({ fx, root, fenceDir });
  await q.sup.submit({ kind: "grant", bytes: grant(1, [entry(A)]) });
  let stuck = true;
  const sysStop = fx.sys.stop, sysCount = fx.sys.procCount;
  fx.sys.stop = (u) => { if (stuck) throw new Error("EIO"); return sysStop(u); };
  fx.sys.procCount = (u) => (stuck ? 1 : sysCount(u));
  chmodSync(fenceDir, 0o500);
  await q.sup.submit({ kind: "stop-all", authority: "local" });
  chmodSync(fenceDir, 0o700);
  assert.deepEqual([q.store.grants.pendingProofs(), q.store.registry.agent(A).state], [[A], "running"]);
  stuck = false;
  fx.log.length = 0;
  const r2 = await q.sup.submit({ kind: "revoke-caps", authority: "service", agent: A });
  assert.deepEqual([r2.status, r2.started], ["revoked-caps", true]);
  assert.deepEqual(q.store.grants.pendingProofs(), []);
  await q.close();
});

test("SEC r8: an emergency between the proofs and unexpire: the unexpire step's gate keeps the expiry fence up", async () => {
  const fx = fakeFx();
  let sup, store, armed = false, stuck = false;
  const sysStop = fx.sys.stop, sysCount = fx.sys.procCount;
  fx.sys.stop = (u) => { if (stuck) throw new Error("EIO"); return sysStop(u); };
  fx.sys.procCount = (u) => (stuck ? 1 : sysCount(u));
  const s = await setup({ fx, barrier: async (n) => {
    if (armed && n === "after_contain") { armed = false; stuck = true; sup.submit({ kind: "stop-all", authority: "local" }); }
  } });
  sup = s.sup; store = s.store;
  await sup.submit({ kind: "grant", bytes: grant(1, [entry(A)]) });
  // A pending proof, then expiry: grant 2's plan is prove:A, unexpire, …
  stuck = true;
  await sup.submit({ kind: "stop", authority: "service", agent: A });
  await sup.submit({ kind: "expiry", authority: "host" });
  stuck = false;
  armed = true; // during prove:A (it passes), a failing stop-all arrives and marks A pending again
  await sup.submit({ kind: "grant", bytes: grant(2, [entry(A)]) });
  await sup.submit({ kind: "grant", bytes: grant(2, [entry(A)]) }).catch(() => {});
  assert.ok(store.grants.pendingProofs().includes(A));
  assert.ok(existsSync(join(s.fenceDir, "expiry")), "expiry not lowered while a proof is pending");
  await s.close();
});

// ---- ninth review round: the host-wide form of the gate (broker generation and every agentless widening effect)

test("SEC r9: an emergency between the proof and broker-gen: brokerGen isn't called while a proof is pending; it is once proven", async () => {
  const fx = fakeFx();
  let sup, store, armed = false, stuck = false;
  const sysStop = fx.sys.stop, sysCount = fx.sys.procCount;
  fx.sys.stop = (u) => { if (stuck) throw new Error("EIO"); return sysStop(u); };
  fx.sys.procCount = (u) => (stuck ? 1 : sysCount(u));
  const s = await setup({ fx, barrier: async (n) => {
    if (armed && n === "after_contain") { armed = false; stuck = true; sup.submit({ kind: "stop-all", authority: "local" }); }
  } });
  sup = s.sup; store = s.store;
  await sup.submit({ kind: "grant", bytes: grant(1, [entry(A), entry(B)]) });
  stuck = true;
  await sup.submit({ kind: "stop", authority: "service", agent: A }); // A pending
  stuck = false;
  armed = true; // during grant 2's prove:A (it passes), a failing stop-all arrives: A and B pending again
  fx.log.length = 0;
  await sup.submit({ kind: "grant", bytes: grant(2, [entry(A), entry(B)]) });
  const g2 = grant(2, [entry(A), entry(B)]);
  const r = await sup.submit({ kind: "grant", bytes: g2 });
  assert.notEqual(r.status, "applied");
  assert.ok(store.grants.pendingProofs().length > 0);
  assert.ok(!fx.log.some((l) => l[0] === "broker-gen" && l[1] === 2), "no broker generation 2 while a proof is pending");
  stuck = false;
  const r2 = await sup.submit({ kind: "grant", bytes: g2 });
  assert.ok(["applied", "reapplied"].includes(r2.status), r2.status);
  assert.ok(fx.log.some((l) => l[0] === "broker-gen" && l[1] === 2), "broker generation 2 once proven");
  await s.close();
});

test("SEC r9: an agentless widening effect (here a healthy agent's resume, which reloads systemd) is refused while another agent is pending, nothing changed", async () => {
  const fx = fakeFx();
  const { sup, store, fenceDir, close } = await setup({ fx });
  await sup.submit({ kind: "grant", bytes: grant(1, [entry(A), entry(B)]) });
  await sup.submit({ kind: "stop", authority: "service", agent: B }); // B healthy, stopped, fenced
  fx.sys.stop = () => { throw new Error("EIO"); };
  const sysCount = fx.sys.procCount;
  fx.sys.procCount = (u) => (u.includes(A) ? 1 : sysCount(u));
  await sup.submit({ kind: "stop", authority: "service", agent: A }); // A pending
  assert.deepEqual(store.grants.pendingProofs(), [A]);
  fx.log.length = 0;
  const r = await sup.submit({ kind: "resume", authority: "person", agent: B });
  assert.deepEqual([r.status, r.reason], ["refused", "pending_proof"]);
  assert.ok(existsSync(join(fenceDir, B)), "B's fence stays up");
  assert.equal(store.registry.agent(B).state, "stopped");
  assert.ok(!fx.log.some((l) => ["daemon-reload", "unit", "unmask", "start", "broker-gen", "map"].includes(l[0])));
  await close();
});
