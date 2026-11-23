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
    start: async (id) => { log.push(["start", id]); if (u(id).masked) throw new Error("masked"); u(id).active = true; },
    isActive: async (id) => u(id).active,
    publishMap: async (g, map) => { log.push(["map", g, map.map((m) => m.agent)]); },
    sendAck: async (g, ack) => { acks.push([g, ack]); },
    freeze: async (id) => { log.push(["freeze", id]); u(id).frozen = true; },
    thaw: async (id) => { if (!u(id).frozen) throw new Error("not frozen"); log.push(["thaw", id]); u(id).frozen = false; },
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
    assert.deepEqual([fx.units[A].active, fx.units[A].masked], [false, true]);
    const rec = fx.audits.find((a) => a.kind === "agent.start" && a.agent === A);
    assert.equal(rec.phase, phase);
    if (phase === "refused") assert.equal(rec.reason, code); else assert.ok(!("reason" in rec), "unknown_effect carries no reason");
    await close();
  });
}

test("a start past its deadline is start_timeout (agent-side); recovery never retries it; the next grant clears and retries it", async () => {
  const fx = fakeFx();
  let hang = true;
  fx.start = async (id) => { if (id === A && hang) await new Promise(() => {}); fx.u(id).active = true; };
  const root = tmp("state"), fenceDir = tmp("fence");
  let s = await setup({ fx, root, fenceDir, deadlines: { start: 100 } });
  const r = await s.sup.submit({ kind: "grant", bytes: grant(1, [entry(A), entry(B)]) });
  assert.equal(r.status, "applied");
  assert.equal(s.store.registry.agent(A).start_failed, "start_timeout");
  await s.close();
  // Recovery: B starts again, A does not.
  for (const u of Object.values(fx.units)) u.active = false;
  s = await setup({ fx, root, fenceDir });
  const rec = await s.sup.recover();
  assert.deepEqual(rec.started, [B]);
  assert.equal(fx.units[A].active, false);
  // The next grant (A itself unchanged) clears the failure and retries it.
  hang = false;
  const r2 = await s.sup.submit({ kind: "grant", bytes: grant(2, [entry(A), entry(B)]) });
  assert.ok(r2.ack.restarted.includes(A));
  assert.equal(s.store.registry.agent(A).start_failed, null);
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
  assert.deepEqual(kinds(fx.log).filter((k) => k !== "intent"), ["broker-revoke", "stop", "mask", "unit", "daemon-reload", "unmask", "start"]);
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
