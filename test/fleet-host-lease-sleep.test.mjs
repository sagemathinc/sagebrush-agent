// Lease-on r1.5 §6.1.1, §6.4, §6.5 (S2): the system-sleep hook and the supervisor's reopen, against a fake systemd and
// cgroup, a fake clock and fake activation locks, over real temporary directories. PRE closes the gate first (C9's
// generation rule with SEC's r1.4 bounds), reaches a fixed point, and never thaws; post only completes; the reopen acts
// only on a finished, unacknowledged suspend (C8a), contains again, thaws and acknowledges; neither touches restore
// state (C2, C8c); the gate's own health reasons have exact, same-clock bounds (C8b, T4).
import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "./host-linux-only.mjs";
import { FleetError, newId } from "../lib/fleet/index.mjs";
import {
  G_MAX, REOPEN_FILE, SLEEP_FILE, STUCK_MS, gateFiles, leaseSleep, postRecord, preRecord, readGate, readTombstone,
  reopenAfterSleep, sleepHealth, sleepHook, writeRecord,
} from "../lib/fleet/host/lease.mjs";
import { withGateHealth } from "../lib/fleet/host/host-state.mjs";

const MAX = 2 ** 53 - 1;
const A = newId(), B = newId(), C = newId();
const S = (gen, phase = "post", ok = true, at = 0) => JSON.stringify({ gen, phase, pre_ok: ok, pre_at: at });
const R = (gen) => JSON.stringify({ gen });
const read = (t) => (t === null ? { state: "missing" } : { state: "ok", text: t });

function world() {
  const root = mkdtempSync(join(tmpdir(), "sb-sleep-"));
  const t = {
    root, dir: join(root, "run"), fenceDir: join(root, "fence", "lease"), unitDir: join(root, "units"),
    agentsCgroup: join(root, "cg"), restore: join(root, "restore"), logs: [],
  };
  for (const d of [t.dir, t.unitDir, t.agentsCgroup, t.restore]) mkdirSync(d, { recursive: true, mode: 0o755 });
  chmodSync(t.dir, 0o755);
  return t;
}
const unit = (t, id) => writeFileSync(join(t.unitDir, `sagebrush-agent-${id}.service`), "[Unit]\n");
const slice = (t, id) => mkdirSync(join(t.agentsCgroup, `sagebrush-agents-${id}.slice`), { recursive: true });
const record = (t, id, lg) => writeRecord(id, { lease_id: "L", lg, expiry_tick: 9e12, gen: 1, sg: 0 }, { dir: t.dir });
const gate = (t, sleep, reopen) => {
  for (const [n, x] of [[SLEEP_FILE, sleep], [REOPEN_FILE, reopen]]) {
    const f = join(t.dir, n);
    rmSync(f, { force: true });
    if (x !== null) { writeFileSync(f, x, { mode: 0o644 }); chmodSync(f, 0o644); }
  }
};

/** A fake systemd and cgroup for the hook: the parent cgroup is t.agentsCgroup; kill() empties it unless `stubborn`. */
function fakeSys(t, { stubborn = false, maskFail = false, onMask = null } = {}) {
  const s = {
    calls: [], freeze: "0", procs: 1,
    cgroup: (d) => (d === t.agentsCgroup ? d : null),
    kill: () => { s.calls.push("kill"); if (!stubborn) s.procs = 0; },
    empty: () => s.procs === 0,
    freezeRead: () => s.freeze,
    freezeWrite: (_d, v) => { s.calls.push(`freeze=${v}`); s.freeze = v; },
    maskAll: async (units) => { s.calls.push(`mask:${units.length}`); if (onMask) await onMask(); if (maskFail) throw new Error("mask"); },
  };
  return s;
}
/** Activation locks: records every path taken; `busyOnce` makes the first take of a path refuse in_progress. */
function fakeLocks({ busyOnce = new Set() } = {}) {
  const m = {
    taken: [],
    lock: async (path) => {
      m.taken.push(path);
      if (busyOnce.has(path)) { busyOnce.delete(path); throw new FleetError("in_progress", "busy"); }
      return { release: async () => {} };
    },
  };
  return m;
}
const clock = { boot: () => 1_000_000, mono: () => 5_000_000_000 };
const advancing = () => { let x = 0; return () => (x += 500); };
const opts = (t, sys, locks, more = {}) => ({
  dir: t.dir, fenceDir: t.fenceDir, unitDir: t.unitDir, agentsCgroup: t.agentsCgroup, sys, lock: locks.lock, clock,
  log: (l) => t.logs.push(l), now: advancing(), wait: async () => {}, ...more,
});

// ---- the record choosers (C9, SEC's r1.4 bounds)

test("PRE's first write: generation 1 only from a trusted both-absent state; otherwise n+1 only below every published reopen", () => {
  const parsed = (sleep, reopen, dirOk = true) => gateFilesLike({ dirOk, sleep: read(sleep), reopen: read(reopen) });
  const cases = [
    ["both absent", null, null, true, 1],
    ["both absent, untrusted directory", null, null, false, null],
    ["post n, reopen n (open)", S(4), R(4), true, 5],
    ["post n, reopen n-1", S(4), R(3), true, 5],
    ["pre n, reopen n-1 (stuck pre advances)", S(4, "pre"), R(3), true, 5],
    ["pre n, reopen n: nothing (strict for pre)", S(4, "pre"), R(4), true, null],
    ["reopen ahead of post: nothing (SEC collision)", S(4), R(5), true, null],
    ["reopen ahead of pre: nothing", S(4, "pre"), R(5), true, null],
    ["sleep alone (one-sided)", S(1, "pre"), null, true, null],
    ["reopen alone (one-sided)", null, R(1), true, null],
    ["malformed sleep", '{"gen":4}', R(4), true, null],
    ["duplicate key", '{"gen":4,"gen":4,"phase":"post","pre_ok":true,"pre_at":0}', R(4), true, null],
    ["overflow: the terminal generation can't advance", S(MAX), R(MAX - 1), true, null],
    ["from G_max: advances to the terminal generation", S(G_MAX), R(G_MAX), true, MAX],
  ];
  for (const [label, sleep, reopen, dirOk, want] of cases) {
    const r = preRecord(parsed(sleep, reopen, dirOk), 777);
    assert.equal(r === null ? null : r.gen, want, label);
    if (r !== null) assert.deepEqual([r.phase, r.pre_ok, r.pre_at], ["pre", false, 777], label);
  }
});

/** gateFiles' shape from texts, for the pure choosers. */
function gateFilesLike(x) {
  const t = world();
  if (x.sleep.state === "ok") writeFileSync(join(t.dir, SLEEP_FILE), x.sleep.text, { mode: 0o644 });
  if (x.reopen.state === "ok") writeFileSync(join(t.dir, REOPEN_FILE), x.reopen.text, { mode: 0o644 });
  if (!x.dirOk) chmodSync(t.dir, 0o777);
  return gateFiles({ dir: t.dir });
}

test("post's write: completes only the exact pre record below reopen; post-from-post only while the gate is OPEN at it (SEC r1.4)", () => {
  const cases = [
    ["the exact pre, reopen below", S(4, "pre", false, 9), R(3), { gen: 4, phase: "post", pre_ok: false, pre_at: 9 }],
    ["the exact pre, reopen absent (a first suspend)", S(1, "pre", true, 9), null, { gen: 1, phase: "post", pre_ok: true, pre_at: 9 }],
    ["pre with reopen equal: nothing", S(4, "pre"), R(4), null],
    ["both absent: a failed first generation", null, null, { gen: 1, phase: "post", pre_ok: false, pre_at: 777 }],
    ["post n, OPEN at n: n+1, pre_ok false", S(4), R(4), { gen: 5, phase: "post", pre_ok: false, pre_at: 777 }],
    ["post n, reopen n+1 (closed): nothing (the collision)", S(4), R(5), null],
    ["post n, reopen n-1 (closed): nothing", S(4), R(3), null],
    ["post at G_max, open: advances to the terminal generation", S(G_MAX), R(G_MAX), { gen: MAX, phase: "post", pre_ok: false, pre_at: 777 }],
    ["post at the terminal generation (never open): nothing", S(MAX), R(MAX), null],
    ["malformed reopen", S(4, "pre"), '{"gen":4.0}', null],
  ];
  for (const [label, sleep, reopen, want] of cases) {
    const x = gateFilesLike({ dirOk: true, sleep: read(sleep), reopen: read(reopen) });
    assert.deepEqual(postRecord(x, 777), want, label);
  }
});

// ---- PRE and post

test("PRE: closes first, contains every agent (raise, mask, freeze and kill the parent, spend, prove), sets pre_ok, and NEVER thaws", async () => {
  const t = world(), sys = fakeSys(t), locks = fakeLocks();
  unit(t, A); slice(t, B); record(t, C, 7); record(t, A, 3);
  const r = await leaseSleep("pre", opts(t, sys, locks));
  assert.equal(r.ok, true);
  assert.equal(r.pre_ok, true);
  const sl = JSON.parse(readFileSync(join(t.dir, SLEEP_FILE), "utf8"));
  assert.deepEqual(sl, { gen: 1, phase: "pre", pre_ok: true, pre_at: 1_000_010 });
  for (const id of [A, B, C]) assert.ok(existsSync(join(t.fenceDir, id)), `lease raised for ${id}`);
  assert.ok(readTombstone(C, { dir: t.dir }) >= 7 && readTombstone(A, { dir: t.dir }) >= 3, "every record spent");
  assert.equal(sys.freeze, "1", "the parent stays frozen: PRE never thaws");
  assert.ok(!sys.calls.includes("freeze=0"));
  assert.ok(sys.calls.indexOf("mask:3") < sys.calls.indexOf("freeze=1") && sys.calls.indexOf("freeze=1") < sys.calls.indexOf("kill"));
  assert.equal(readGate({ dir: t.dir, clock }).open, false, "the gate reads closed");
  assert.ok(t.logs.some((l) => l.step === "close") && t.logs.some((l) => l.step === "done"), "the evidence log");
  // It takes no lock but the agents' activation locks (C3: no supervisor, host-store, executor, journal or fence lock).
  assert.ok(locks.taken.every((p) => p.startsWith(t.dir) && p.endsWith(".lock")), JSON.stringify(locks.taken));
});

test("PRE's fixed point: an agent (and its record) appearing after the first discovery is covered by the next round", async () => {
  const t = world(), locks = fakeLocks();
  unit(t, A); record(t, A, 2);
  let first = true;
  const sys = fakeSys(t, { onMask: async () => { if (first) { first = false; unit(t, B); record(t, B, 5); } } });
  const r = await leaseSleep("pre", opts(t, sys, locks));
  assert.equal(r.ok, true);
  assert.ok(r.rounds >= 2, `rounds ${r.rounds}`);
  assert.ok(existsSync(join(t.fenceDir, B)) && readTombstone(B, { dir: t.dir }) >= 5, "the late agent raised and spent");
});

test("PRE's failures keep pre_ok false and the parent frozen: unreadable discovery, a failed mask, a failed proof", async () => {
  for (const [label, setup, sysOpts] of [
    ["unreadable unit directory", (t) => chmodSync(t.unitDir, 0o000), {}],
    ["mask read-back fails", () => {}, { maskFail: true }],
    ["the proof never holds", () => {}, { stubborn: true }],
  ]) {
    const t = world(), locks = fakeLocks();
    unit(t, A); record(t, A, 2); setup(t);
    const sys = fakeSys(t, sysOpts);
    const r = await leaseSleep("pre", opts(t, sys, locks));
    chmodSync(t.unitDir, 0o755);
    assert.equal(r.ok, false, label);
    assert.equal(JSON.parse(readFileSync(join(t.dir, SLEEP_FILE), "utf8")).pre_ok, false, `${label}: pre_ok stays false`);
    assert.notEqual(sys.freeze, "0", `${label}: never thawed`);
    assert.equal(readGate({ dir: t.dir, clock }).open, false, `${label}: closed`);
  }
});

test("PRE spends under the activation lock, killing the parent and retrying when a holder has it (never waiting unbounded)", async () => {
  const t = world();
  unit(t, A); record(t, A, 9);
  const locks = fakeLocks({ busyOnce: new Set([join(t.dir, `${A}.lock`)]) });
  const sys = fakeSys(t);
  const r = await leaseSleep("pre", opts(t, sys, locks));
  assert.equal(r.ok, true);
  assert.ok(readTombstone(A, { dir: t.dir }) >= 9);
  assert.ok(sys.calls.filter((c) => c === "kill").length >= 2, "killed again before the retry");
});

test("C2: PRE and post leave restore state byte-identical and add only `lease`", async () => {
  const t = world(), sys = fakeSys(t), locks = fakeLocks();
  unit(t, A);
  const restoreFence = join(t.fenceDir, "..", "restore", A);
  mkdirSync(join(t.fenceDir, "..", "restore"), { recursive: true }); writeFileSync(restoreFence, "");
  const files = { [join(t.restore, "agent-" + A + ".json")]: '{"state":"validated"}', [join(t.restore, "pairs-" + A)]: "pair-bytes" };
  for (const [f, b] of Object.entries(files)) writeFileSync(f, b);
  await leaseSleep("pre", opts(t, sys, locks));
  await leaseSleep("post", opts(t, sys, locks));
  for (const [f, b] of Object.entries(files)) assert.equal(readFileSync(f, "utf8"), b, f);
  assert.ok(existsSync(restoreFence), "restore still raised");
  assert.ok(existsSync(join(t.fenceDir, A)), "lease added");
});

test("post completes PRE's record; a suspend without PRE is a failed generation; collisions write nothing", async () => {
  const t = world(), sys = fakeSys(t), locks = fakeLocks();
  await leaseSleep("pre", opts(t, sys, locks));
  await leaseSleep("post", opts(t, sys, locks));
  assert.equal(JSON.parse(readFileSync(join(t.dir, SLEEP_FILE), "utf8")).phase, "post");
  const u = world();
  await leaseSleep("post", opts(u, fakeSys(u), fakeLocks()));
  assert.deepEqual(JSON.parse(readFileSync(join(u.dir, SLEEP_FILE), "utf8")), { gen: 1, phase: "post", pre_ok: false, pre_at: 1_000_010 });
  const v = world();
  gate(v, S(4), R(5));
  await leaseSleep("post", opts(v, fakeSys(v), fakeLocks()));
  assert.equal(readFileSync(join(v.dir, SLEEP_FILE), "utf8"), S(4), "the collision: post writes nothing");
  await leaseSleep("pre", opts(v, fakeSys(v), fakeLocks()));
  assert.equal(readFileSync(join(v.dir, SLEEP_FILE), "utf8"), S(4), "the collision: PRE writes nothing");
});

// ---- the reopen (C8a, C8c)

test("C8a: the reopen is a NO-OP unless a trusted post is unacknowledged: both absent, open, pre, reopen ahead, exhausted", async () => {
  for (const [label, sleep, reopen] of [
    ["both absent", null, null], ["open", S(3), R(3)], ["pre", S(3, "pre"), R(2)], ["reopen ahead", S(3), R(4)],
    ["exhausted", S(MAX), R(MAX - 1)], ["malformed", '{"gen":3}', R(2)],
  ]) {
    const t = world(), sys = fakeSys(t), locks = fakeLocks();
    unit(t, A); record(t, A, 1);
    gate(t, sleep, reopen);
    let acted = false;
    const r = await reopenAfterSleep({ ...opts(t, sys, locks), onAct: () => { acted = true; } });
    assert.deepEqual(r, { acted: false, ok: true, gen: null }, label);
    assert.equal(acted, false, `${label}: no void`);
    assert.deepEqual(sys.calls, [], `${label}: no mask, freeze or kill`);
    assert.ok(!existsSync(join(t.fenceDir, A)), `${label}: nothing raised`);
  }
});

test("the reopen after a finished suspend: void, contain, thaw, acknowledge; a failure stays closed and frozen", async () => {
  const t = world(), sys = fakeSys(t), locks = fakeLocks();
  unit(t, A); record(t, A, 4);
  gate(t, S(2, "post", false), R(1));
  sys.freeze = "1"; // as PRE left it
  let voided = 0;
  const r = await reopenAfterSleep({ ...opts(t, sys, locks), onAct: () => { voided++; } });
  assert.deepEqual(r, { acted: true, ok: true, gen: 2 });
  assert.equal(voided, 1);
  assert.equal(sys.freeze, "0", "thawed after its own proof");
  assert.equal(readFileSync(join(t.dir, REOPEN_FILE), "utf8"), R(2));
  assert.deepEqual(readGate({ dir: t.dir, clock }), { open: true, g: 2 });
  assert.ok(existsSync(join(t.fenceDir, A)), "lease stays raised: only a fresh lease's helper lowers it");
  assert.ok(readTombstone(A, { dir: t.dir }) >= 4, "the pre-suspend record spent again");
  // the proof fails: no thaw, no acknowledgement
  const u = world(), su = fakeSys(u, { stubborn: true });
  unit(u, A); gate(u, S(2), R(1)); su.freeze = "1";
  const f = await reopenAfterSleep(opts(u, su, fakeLocks()));
  assert.deepEqual(f, { acted: true, ok: false, gen: 2 });
  assert.equal(su.freeze, "1");
  assert.equal(readFileSync(join(u.dir, REOPEN_FILE), "utf8"), R(1), "not acknowledged: reopen still at 1");
  assert.equal(readGate({ dir: u.dir, clock }).open, false);
});

test("C8c: the reopen leaves restore state byte-identical; an agent fenced {restore} ends {lease, restore}", async () => {
  const t = world(), sys = fakeSys(t), locks = fakeLocks();
  unit(t, A); gate(t, S(1), null);
  const restoreDir = join(t.fenceDir, "..", "restore");
  mkdirSync(restoreDir, { recursive: true }); writeFileSync(join(restoreDir, A), "");
  const pair = join(t.restore, "pair"); writeFileSync(pair, "PAIR");
  const r = await reopenAfterSleep(opts(t, sys, locks));
  assert.equal(r.ok, true);
  assert.ok(existsSync(join(restoreDir, A)) && existsSync(join(t.fenceDir, A)));
  assert.equal(readFileSync(pair, "utf8"), "PAIR");
});

// ---- the gate's health (C8b, T4)

test("C8b: stuck at pre past its budget plus 5 minutes (strictly), by CLOCK_BOOTTIME from pre_at; reopen ahead; exhausted", () => {
  const t = world();
  const at = (boot) => ({ boot: () => boot - 10, mono: () => 0 }); // bootNow adds 10 ms
  gate(t, S(3, "pre", false, 1000), R(2));
  assert.deepEqual(sleepHealth({ dir: t.dir, clock: at(1000 + STUCK_MS) }), [], "exactly at the bound: not stuck");
  assert.deepEqual(sleepHealth({ dir: t.dir, clock: at(1001 + STUCK_MS) }), ["suspend_gate_stuck"], "1 ms over: stuck");
  gate(t, S(4, "pre", false, 1001 + STUCK_MS), R(3));
  assert.deepEqual(sleepHealth({ dir: t.dir, clock: at(1001 + STUCK_MS) }), [], "a new generation resets the age");
  gate(t, S(3), R(4));
  assert.deepEqual(sleepHealth({ dir: t.dir, clock: at(5000) }), ["suspend_gate_stuck"], "reopen ahead");
  gate(t, S(MAX), R(MAX));
  assert.deepEqual(sleepHealth({ dir: t.dir, clock: at(5000) }), ["suspend_gate_exhausted"]);
  gate(t, S(3), R(3));
  assert.deepEqual(sleepHealth({ dir: t.dir, clock: at(5000) }), [], "open: healthy");
  assert.deepEqual(withGateHealth({ state: "ok", reasons: [] }, ["suspend_gate_stuck"]), { state: "fail_closed", reasons: ["suspend_gate_stuck"] });
  assert.deepEqual(withGateHealth({ state: "qualify_required", reasons: ["qualify_required"] }, ["suspend_gate_exhausted"]),
    { state: "qualify_required", reasons: ["qualify_required", "suspend_gate_exhausted"] });
  assert.deepEqual(withGateHealth({ state: "ok", reasons: [] }, []), { state: "ok", reasons: [] });
});

test("the hook's file: a two-line shim for pre or post only, rendered for a plain absolute release", () => {
  const h = sleepHook("/opt/sagebrush/r1");
  assert.match(h, /^#!\/bin\/sh\n/);
  assert.ok(h.includes('exec /usr/bin/env node "/opt/sagebrush/r1/lib/fleet/host/lease-main.mjs" lease-sleep "$1"'));
  assert.ok(h.includes("pre|post)") && h.trimEnd().endsWith("exit 0"));
  for (const bad of ["rel", "/a b", "/a$x", '/a"b', null]) assert.throws(() => sleepHook(bad), (e) => e.code === "bad_form", String(bad));
});
