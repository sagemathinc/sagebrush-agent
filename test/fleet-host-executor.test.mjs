// Host supervisor freeze r3.1 §3.2–§3.4, §7, and the part-7 rulings: the executor against a fake systemd, broker and
// audit. One queue, emergencies first; the plan's steps in order with durable progress; narrowing; agent-side and
// host-side failures; expiry; the lifecycle ops and who may submit them; recovery; and a crash at every barrier.
import assert from "node:assert/strict";
import { existsSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "./host-linux-only.mjs";
import { FleetError, newId, sha256b64 } from "../lib/fleet/index.mjs";
import { Supervisor } from "../lib/fleet/host/executor.mjs";
import { raiseFence } from "../lib/fleet/host/fence.mjs";
import { HostStore } from "../lib/fleet/host/host-store.mjs";
import { planGrant, parseStep } from "../lib/fleet/host/plan.mjs";
import { STATES } from "../lib/fleet/host/registry.mjs";

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
  let sup, armed = true;
  const [first] = [A, B].sort();
  let s = await setup({ fx, root, fenceDir, barrier: async (n, d) => { if (armed && n === "after_unit_write" && d.agent === first) { armed = false; sup.submit({ kind: "expiry", authority: "host" }); } } });
  sup = s.sup;
  await sup.submit({ kind: "grant", bytes: grant(1, [entry(A), entry(B)]) });
  await new Promise((r) => setTimeout(r, 50));
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
  fx.thaw = async () => lateBy(150); // ignores its abort
  fx.log.length = 0;
  const r = await sup.submit({ kind: "resume", authority: "person", agent: A });
  assert.deepEqual([r.status, r.settled, r.fenced], ["failed", false, true]);
  assert.ok(!fx.log.some((l) => ["unit", "daemon-reload", "unmask", "start"].includes(l[0])), "no widening effect after the unsettled thaw");
  assert.deepEqual([store.registry.agent(A).state, fx.units[A].active, existsSync(join(fenceDir, A))], ["stopped", false, true]);
  // Until it settles, an authority-giving effect is refused even inside an emergency's own sequence.
  assert.equal(sup.unsettled, 1);
  await new Promise((res) => setTimeout(res, 200));
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
  fx.mask = async (id, ...rest) => { await lateBy(150); return mask(id, ...rest); }; // ignores its abort
  fx.log.length = 0;
  const r = await sup.submit({ kind: "revoke-caps", authority: "service", agent: A });
  assert.equal(r.status, "failed");
  assert.ok(!fx.log.some((l) => ["unit", "daemon-reload", "unmask", "start"].includes(l[0])), "no unit write, reload or start");
  assert.ok(existsSync(join(fenceDir, A)));
  assert.equal(fx.units[A].active, false);
  // Teardown: a mask that works again, then wait for the late one to settle and its re-containment to finish (it
  // would otherwise reschedule itself for ever, keeping an unforced test run alive).
  fx.mask = mask;
  for (let i = 0; i < 100 && sup.unsettled > 0; i++) await new Promise((res) => setTimeout(res, 20));
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
  assert.equal(r.previous.step, `prove:${A}`);
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
