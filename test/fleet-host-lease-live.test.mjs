// Host supervisor (execution lease r3.12, lease part 2): liveLease, activeTurns, and the lock order (an activation lock
// or a helper launch is refused while this process holds the fence lock).
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "./host-linux-only.mjs";
import { newId } from "../lib/fleet/index.mjs";
import { withFenceLock, holdsFenceLock } from "../lib/fleet/host/fence.mjs";
import { activationLock, runHelper, watchdogTimer, writeRecord, MARGIN_MS } from "../lib/fleet/host/lease.mjs";
import { activeTurns, liveLease, turnScopePattern } from "../lib/fleet/host/lease-live.mjs";

const A = newId();
const tmp = (n) => mkdtempSync(join(tmpdir(), `sb-lease-live-${n}-`));
const T = (i) => i.toString(16).padStart(32, "0");

/** A clock at boot B ms (CLOCK_BOOTTIME) and monotonic M µs; a systemd whose one watchdog timer is waiting. */
function world({ boot = 1_000_000, timer = { active: "active", sub: "waiting", next: 9e15 } } = {}) {
  const dir = tmp("lease");
  const clock = { boot: () => boot, mono: () => 5_000_000_000 };
  const timers = {};
  const sys = { timer: async (unit) => { if (!(unit in timers)) throw new Error("no such unit"); return timers[unit]; } };
  const publish = (rec) => { writeRecord(A, rec, { dir }); timers[watchdogTimer(A, rec.lg)] = timer; };
  return { dir, clock, sys, timers, publish, opts: { dir, sys, clock } };
}

test("liveLease: the published record when liveCheck passes, with gen a number; null otherwise", async () => {
  const w = world();
  const rec = { lease_id: "L1", lg: 4, expiry_tick: 1_000_000 + 600_000, gen: 7 };
  assert.equal(await liveLease(A, w.opts), null, "no record");
  w.publish(rec);
  const live = await liveLease(A, w.opts);
  assert.deepEqual(live, rec);
  assert.equal(typeof live.gen, "number");
  // Spent: the tombstone at its lg.
  writeFileSync(join(w.dir, `${A}.spent`), "4\n");
  assert.equal(await liveLease(A, w.opts), null, "spent");
  writeFileSync(join(w.dir, `${A}.spent`), "3\n");
  assert.deepEqual(await liveLease(A, w.opts), rec, "a tombstone below lg");
  writeFileSync(join(w.dir, `${A}.spent`), "x\n");
  assert.equal(await liveLease(A, w.opts), null, "an unreadable tombstone");
});

test("liveLease: null at and past the effective end (expiry_tick - 30 s), without a waiting timer, or for a malformed record", async () => {
  const rec = (expiry) => ({ lease_id: "L1", lg: 4, expiry_tick: expiry, gen: 7 });
  // bootNow adds /proc/uptime's 10 ms resolution: now = boot + 10.
  const at = (boot, expiry) => { const w = world({ boot }); w.publish(rec(expiry)); return liveLease(A, w.opts); };
  assert.notEqual(await at(1_000_000, 1_000_000 + 10 + MARGIN_MS + 1), null, "1 ms before the effective end");
  assert.equal(await at(1_000_000, 1_000_000 + 10 + MARGIN_MS), null, "exactly at the effective end");
  assert.equal(await at(1_000_000, 1_000_000), null, "past it");
  for (const [what, timer] of [["elapsed", { active: "active", sub: "elapsed", next: 9e15 }], ["inactive", { active: "inactive", sub: "dead", next: 9e15 }], ["no next elapse", { active: "active", sub: "waiting", next: 0 }]]) {
    const w = world({ timer });
    w.publish(rec(9e12));
    assert.equal(await liveLease(A, w.opts), null, what);
  }
  const w = world();
  w.publish(rec(9e12));
  delete w.timers[watchdogTimer(A, 4)];
  assert.equal(await liveLease(A, w.opts), null, "the timer can't be read");
  for (const bad of [{ lease_id: "L1", lg: 4, expiry_tick: 9e12 }, { lease_id: "L1", lg: 4, expiry_tick: 9e12, gen: 0 }, "{not json"]) {
    const v = world();
    v.publish(rec(9e12));
    writeFileSync(join(v.dir, A), typeof bad === "string" ? bad : JSON.stringify(bad));
    assert.equal(await liveLease(A, v.opts), null, JSON.stringify(bad));
  }
});

/** A temp directory standing in for the agent's slice cgroup; `scopes` maps a child name to its cgroup.events (or null: a file). */
function slice(scopes) {
  const dir = tmp("slice");
  for (const [name, events] of Object.entries(scopes)) {
    if (events === null) { writeFileSync(join(dir, name), ""); continue; }
    mkdirSync(join(dir, name));
    if (events !== undefined) writeFileSync(join(dir, name, "cgroup.events"), events);
  }
  return { sys: { cgroup: () => dir } };
}

test("activeTurns: the agent's populated turn scopes only; a missing slice is 0", async () => {
  const s = slice({
    [`sagebrush-turn-${A}-${T(1)}.scope`]: "populated 1\nfrozen 0\n",
    [`sagebrush-turn-${A}-${T(2)}.scope`]: "populated 1\nfrozen 0\n",
    [`sagebrush-turn-${A}-${T(3)}.scope`]: "populated 0\nfrozen 0\n", // ended, not yet collected
    [`sagebrush-agent-${A}.service`]: "populated 1\n", // the unit is no turn
    [`sagebrush-lease-activate-${A}.scope`]: "populated 1\n", // nor is the helper
    [`sagebrush-turn-${newId()}-${T(4)}.scope`]: "populated 1\n", // another agent's name
    [`sagebrush-turn-${A}-${T(5)}x.scope`]: "populated 1\n", // not a turn id
    "cgroup.procs": null,
  });
  assert.equal(await activeTurns(A, s), 2);
  assert.equal(await activeTurns(A, { sys: { cgroup: () => null } }), 0, "no slice: nothing of the agent runs");
  assert.ok(turnScopePattern(A).test(`sagebrush-turn-${A}-${T(9)}.scope`));
});

test("activeTurns REJECTS, never 0, when it can't read the tree or doesn't recognize it", async () => {
  const cases = [
    ["the slice isn't a cgroup", { sys: { cgroup: () => { throw Object.assign(new Error("not a cgroup"), { code: "EIO" }); } } }],
    ["a turn scope without cgroup.events", slice({ [`sagebrush-turn-${A}-${T(1)}.scope`]: undefined })],
    ["a turn scope's events without a populated line", slice({ [`sagebrush-turn-${A}-${T(1)}.scope`]: "frozen 0\n" })],
    ["a turn scope that is a file", slice({ [`sagebrush-turn-${A}-${T(1)}.scope`]: null })],
    ["an unlistable slice", { sys: { cgroup: () => join(tmp("gone"), "missing") } }],
  ];
  for (const [what, opts] of cases) await assert.rejects(activeTurns(A, opts), (e) => e instanceof Error, what);
});

test("the lock order: no activation lock and no helper launch while holding the fence lock", async () => {
  const fenceDir = tmp("fence"), leaseDir = tmp("lease");
  const runs = [];
  const run = async (argv) => { runs.push(argv); return { code: 0, stdout: "", stderr: "" }; };
  const fakeLock = async () => ({ release: async () => {} });
  const lockOrder = (e) => e?.code === "lock_order";
  // Outside the fence lock: both proceed.
  assert.equal(holdsFenceLock(), false);
  await runHelper(["true"], { run });
  await (await activationLock(A, { dir: leaseDir, lock: fakeLock })).release();
  assert.equal(runs.length, 1);
  // Inside it: both refused, before anything runs.
  await withFenceLock(async () => {
    assert.equal(holdsFenceLock(), true);
    await assert.rejects(runHelper(["true"], { run }), lockOrder);
    assert.throws(() => activationLock(A, { dir: leaseDir, lock: fakeLock }), lockOrder);
    // Still inside after an await: the mark follows the async context.
    await new Promise((r) => setTimeout(r, 5));
    await assert.rejects(runHelper(["true"], { run }), lockOrder);
  }, { dir: fenceDir });
  assert.equal(runs.length, 1, "nothing ran under the lock");
  // After it: allowed again.
  assert.equal(holdsFenceLock(), false);
  await runHelper(["true"], { run });
  assert.equal(runs.length, 2);
});

test("the lock order is per async context: work running concurrently, outside the fence lock, isn't refused", async () => {
  const fenceDir = tmp("fence");
  let release;
  const held = new Promise((r) => { release = r; });
  let inside = false;
  const locked = withFenceLock(async () => { inside = true; await held; }, { dir: fenceDir });
  while (!inside) await new Promise((r) => setTimeout(r, 1));
  // Another chain, started outside: it may launch a helper even while the first chain holds the lock.
  assert.equal(holdsFenceLock(), false);
  const r = await runHelper(["true"], { run: async () => ({ code: 0, stdout: "", stderr: "" }) });
  assert.equal(r.code, 0);
  release();
  await locked;
});
