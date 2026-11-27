// Execution lease r3.11 §2, §2.1: the root primitives, against a fake systemd and cgroup, a fake clock, and a fake
// activation lock whose holders can be killed with the slice (as the kernel's cgroup.kill does). The watchdog acts
// unless the record holds a strictly newer lg, never waits on a lock holder, keeps the tombstone an atomic max, and
// only ever stops; the helper lowers the fence only when every check holds under the lock; the deadline is converted
// to the monotonic domain and read back.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, statSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "./host-linux-only.mjs";
import { FleetError, newId } from "../lib/fleet/index.mjs";
import {
  G_MAX, MARGIN_MS, REOPEN_FILE, SLEEP_FILE, activationArgv, parseGateJson, parseReopen, parseSleep, armArgv, armWatchdog, bootNow, gateOf, leaseActivate, leaseExpire,
  liveCheck, monotonicDeadline, parseArgs, publish, readGate, readGateFile, readRecord, readTombstone, realSystem, unitObjectPath,
  watchdogTimer, writeRecord,
} from "../lib/fleet/host/lease.mjs";
import { realIo } from "../lib/fleet/host/store.mjs";
import { chmodSync, symlinkSync } from "node:fs";
import * as fsReal from "node:fs";
import { fenced, lowerFence, raiseFence, stop } from "../lib/fleet/host/fence.mjs";
import { lockFile } from "../lib/fleet/host/store.mjs";

// The fixtures here are made with the default modes, and the code under test refuses anything group- or
// world-writable, as it must. So the file's own umask is fixed (a host's services run with 022): the rows then
// mean the same under a login shell's 002.
process.umask(0o022);

const A = newId();
const refused = (fn, code) => assert.throws(fn, (e) => e instanceof FleetError && e.code === code, code);
const rejects = (p, code) => assert.rejects(p, (e) => (code === "lease_unverified" || e instanceof FleetError) && e.code === code, code);

function env() {
  const root = mkdtempSync(join(tmpdir(), "sb-lease-"));
  const dir = join(root, "run"), fenceDir = join(root, "fence", "lease"), slice = join(root, "cg", `sagebrush-agents-${A}.slice`);
  return { root, dir, fenceDir, slice, fence: join(fenceDir, A) };
}

/** A clock: mono in µs, boot in ms, each advanced explicitly. offsetMs: boot - mono (grown by earlier suspends). */
function fakeClock({ monoUs = 5_000_000_000, offsetMs = 0 } = {}) {
  const c = { monoUs, offsetMs, mono: () => c.monoUs, boot: () => Math.floor(c.monoUs / 1000) + c.offsetMs, advance: (ms) => { c.monoUs += ms * 1000; } };
  return c;
}

/**
 * A fake activation lock: exclusive and shared holders per path; a conflicting take refuses `in_progress` at once
 * (standing in for the 5 s try). killAll() ends every holder, as their death releases a real flock.
 */
function fakeLocks() {
  const held = new Map(); // path -> [{ shared, owner }]
  const m = {
    takes: [],
    lock: async (path, { shared = false } = {}) => {
      const hs = held.get(path) ?? [];
      m.takes.push({ path, shared });
      if (hs.length && (!shared || hs.some((h) => !h.shared))) throw new FleetError("in_progress", "busy");
      const h = { shared, killable: m.nextKillable ?? false };
      m.nextKillable = false;
      hs.push(h); held.set(path, hs);
      return { release: async () => { const l = held.get(path) ?? []; const i = l.indexOf(h); if (i >= 0) l.splice(i, 1); }, held: () => (held.get(path) ?? []).includes(h) };
    },
    /** A holder inside the slice (a turn launcher, the helper): killed with the slice. */
    holdInSlice: async (path, shared) => { m.nextKillable = true; return m.lock(path, { shared }); },
    killSliceHolders: () => { for (const [p, l] of held) held.set(p, l.filter((h) => !h.killable)); },
    count: (path) => (held.get(path) ?? []).length,
  };
  return m;
}

/** A fake systemd and cgroup. `procs`: the slice's process count; kill() empties it unless `stubborn`. */
function fakeSys(e, { procs = 2, stubborn = false, timers = {}, locks = null, armFails = false, readBack = null } = {}) {
  const s = {
    calls: [], procs, sliceExists: true, timers,
    arm: async (argv) => {
      s.calls.push(["arm", argv]);
      if (armFails) throw new Error("systemd-run failed");
      const unit = argv.find((a) => a.startsWith("--unit=")).slice(7) + ".timer";
      const at = Number(/^--on-boot=([0-9]+)us$/.exec(argv.find((a) => a.startsWith("--on-boot=")))[1]);
      s.timers[unit] = { active: "active", sub: "waiting", next: readBack ? readBack(at) : at };
    },
    timer: async (unit) => { s.calls.push(["timer", unit]); const t = s.timers[unit]; if (!t) return { active: "inactive", sub: "dead", next: 0 }; return { ...t }; },
    mask: async (unit) => { s.calls.push(["mask", unit]); s.masked = true; },
    unmask: async (unit) => { s.calls.push(["unmask", unit]); s.masked = false; },
    start: async (unit) => { s.calls.push(["start", unit]); s.started = (s.started ?? 0) + 1; },
    stop: async (unit) => { s.calls.push(["stop", unit]); if (!stubborn) s.procs = 0; },
    cgroup: (d) => { if (d !== e.slice) throw new Error("wrong cgroup"); return s.sliceExists ? d : null; },
    kill: (d) => { s.calls.push(["kill", d]); locks?.killSliceHolders(); if (!stubborn) s.procs = 0; },
    empty: () => s.procs === 0,
    selfCgroup: () => s.self ?? `/sagebrush.slice/sagebrush-agents.slice/sagebrush-agents-${A}.slice/sagebrush-lease-activate-${A}.scope`,
  };
  return s;
}

const noWait = async () => {};
const opts = (e, sys, locks, more = {}) => ({ dir: e.dir, fenceDir: e.fenceDir, sys, lock: locks.lock, cgroupOf: () => e.slice, wait: noWait, ...more });
const kinds = (sys) => sys.calls.map((c) => c[0]);

test("arguments: only an id, a lease id and a positive decimal lg; the watchdog's names and D-Bus path", () => {
  assert.deepEqual(parseArgs(A, "L-1_x", "7"), { agent: A, leaseId: "L-1_x", lg: 7 });
  for (const bad of [["x", "L", "1"], [A, "", "1"], [A, "a b", "1"], [A, "L", "0"], [A, "L", "01"], [A, "L", "-1"], [A, "L", "1e3"], [A, "x".repeat(65), "1"]]) {
    refused(() => parseArgs(...bad), "bad_form");
  }
  assert.equal(watchdogTimer(A, 3), `sagebrush-lease-${A}-3.timer`);
  assert.equal(unitObjectPath("sagebrush-lease-a-1.timer"), "/org/freedesktop/systemd1/unit/sagebrush_2dlease_2da_2d1_2etimer");
});

test("T2e: the deadline is converted to CLOCK_MONOTONIC from the smallest-gap pair, conservatively, also after suspends", () => {
  for (const offsetMs of [0, 3_600_000, 86_400_123]) { // none, one earlier suspend, repeated suspends
    const c = fakeClock({ offsetMs });
    const expiry = c.boot() + 600_000;
    const m = monotonicDeadline(expiry, c);
    // the exact point is mono + (expiry - boot - 30 s); the rounding of /proc/uptime moves it at most 10 ms earlier
    const exact = c.mono() + (expiry - c.boot() - MARGIN_MS) * 1000;
    assert.ok(m <= exact && m >= exact - 10_000, `${offsetMs}: ${m} vs ${exact}`);
  }
  // three samples; the pair with the smallest gap wins
  const seq = [[100, 50, 900], [1000, 60, 1010], [2000, 70, 2500]];
  let i = 0, k = 0;
  const c = { mono: () => seq[i][k++ === 0 ? 0 : 2], boot: () => seq[i][1] };
  const wrapped = { mono: () => { const v = c.mono(); if (k > 1) { k = 0; i++; } return v; }, boot: c.boot };
  assert.equal(monotonicDeadline(100_000, wrapped), 1000 + (100_000 - 70 - MARGIN_MS) * 1000);
});

test("arming: an absolute OnBootSec timer, AccuracySec=1s, running lease-expire outside the agent slice", () => {
  const argv = armArgv(A, "L1", 4, 123456789, { node: "/n", main: "/m.mjs" });
  assert.deepEqual(argv, ["systemd-run", "--quiet", `--unit=sagebrush-lease-${A}-4`, "--on-boot=123456789us", "--timer-property=AccuracySec=1s",
    "--property=Type=exec", "--", "/n", "/m.mjs", "lease-expire", A, "L1", "4"]);
  assert.ok(!argv.some((a) => a.startsWith("--slice")), "the watchdog is never inside an agent slice");
  assert.deepEqual(activationArgv(A, "L1", 4, { node: "/n", main: "/m.mjs" }), ["systemd-run", "--scope", "--quiet", "--collect",
    `--slice=sagebrush-agents-${A}.slice`, `--unit=sagebrush-lease-activate-${A}.scope`, "--", "/n", "/m.mjs", "lease-activate", A, "L1", "4"]);
});

test("armWatchdog: verified only when active, waiting, and elapsing at or before m*; else lease_unverified", async () => {
  const e = env(), c = fakeClock();
  const rec = { lease_id: "L1", lg: 1, expiry_tick: c.boot() + 600_000, gen: 3, sg: 0 };
  const ok = await armWatchdog(A, rec, { sys: fakeSys(e), clock: c });
  assert.equal(ok.timer, watchdogTimer(A, 1));
  await rejects(armWatchdog(A, rec, { sys: fakeSys(e, { armFails: true }), clock: c }), "lease_unverified");
  // a read-back later than m* (T2e mismatch, or an elapse after expiry_tick) refuses activation
  await rejects(armWatchdog(A, rec, { sys: fakeSys(e, { readBack: (at) => at + 1 }), clock: c }), "lease_unverified");
  await rejects(armWatchdog(A, rec, { sys: fakeSys(e, { readBack: () => 0 }), clock: c }), "lease_unverified");
  // a deadline already inside the margin: refused before anything is armed
  const late = fakeSys(e);
  await rejects(armWatchdog(A, { ...rec, expiry_tick: c.boot() + MARGIN_MS, gen: 3, sg: 0 }, { sys: late, clock: c }), "lease_unverified");
  assert.deepEqual(late.calls, []);
});

test("publish (re-arm step 2) and SEC H1: nothing is published once now >= expiry_tick - 30 s, or for a spent or elapsed timer", async () => {
  const e = env(), c = fakeClock(), sys = fakeSys(e);
  const rec = { lease_id: "L1", lg: 2, expiry_tick: c.boot() + 600_000, gen: 3, sg: 0 };
  await armWatchdog(A, rec, { sys, clock: c });
  const o = { dir: e.dir, sys, clock: c };
  // inside the margin but before the signed expiry: treated as expired
  const c2 = fakeClock({ monoUs: c.monoUs + (600_000 - MARGIN_MS) * 1000 });
  assert.equal(await liveCheck(A, rec, { ...o, clock: c2 }), "expired");
  assert.equal(await publish(A, rec, { ...o, clock: c2 }), false);
  // a tombstone at this lg (a watchdog already acted): never revived
  mkdirSync(e.dir, { recursive: true }); writeFileSync(join(e.dir, `${A}.spent`), "2\n");
  assert.equal(await publish(A, rec, o), false);
  writeFileSync(join(e.dir, `${A}.spent`), "garbage");
  assert.equal(await liveCheck(A, rec, o), "tombstone_unreadable");
  writeFileSync(join(e.dir, `${A}.spent`), "1\n");
  // an elapsed timer
  sys.timers[watchdogTimer(A, 2)].sub = "elapsed";
  assert.equal(await publish(A, rec, o), false);
  assert.equal(readRecord(A, { dir: e.dir }).state, "missing");
  sys.timers[watchdogTimer(A, 2)].sub = "waiting";
  assert.equal(await publish(A, rec, o), true);
  assert.deepEqual(readRecord(A, { dir: e.dir }), { state: "ok", rec });
  assert.equal(statSync(join(e.dir, A)).mode & 0o777, 0o644);
});

test("the record's gen (execution lease r3.12): written, read back as a number, required, and refused out of range", () => {
  const e = env();
  const rec = { lease_id: "L1", lg: 5, expiry_tick: 100000, gen: 7, sg: 0 };
  writeRecord(A, rec, { dir: e.dir });
  assert.equal(readFileSync(join(e.dir, A), "utf8"), '{"lease_id":"L1","lg":5,"expiry_tick":100000,"gen":7,"sg":0}');
  const got = readRecord(A, { dir: e.dir });
  assert.deepEqual(got, { state: "ok", rec });
  assert.equal(typeof got.rec.gen, "number", "a number: the restore-resume helper compares it with ===");
  for (const gen of [undefined, 0, -1, 1.5, "7", 2 ** 53, null]) {
    assert.throws(() => writeRecord(A, { ...rec, gen }, { dir: e.dir }), (x) => x.code === "bad_form", String(gen));
    writeFileSync(join(e.dir, A), JSON.stringify(gen === undefined ? { lease_id: "L1", lg: 5, expiry_tick: 100000 } : { ...rec, gen }));
    assert.deepEqual(readRecord(A, { dir: e.dir }), { state: "bad" }, `read ${String(gen)}`);
  }
  for (const gen of [1, 2 ** 53 - 1]) {
    writeRecord(A, { ...rec, gen }, { dir: e.dir });
    assert.equal(readRecord(A, { dir: e.dir }).rec.gen, gen);
  }
});

test("the helper activates alike whatever the record's gen", async () => {
  for (const gen of [1, 7]) {
    const e = env(), c = fakeClock(), locks = fakeLocks(), sys = fakeSys(e, { locks });
    const rec = { lease_id: "L", lg: 1, expiry_tick: c.boot() + 600_000, gen, sg: 0 };
    await armWatchdog(A, rec, { sys, clock: c });
    assert.equal(await publish(A, rec, { dir: e.dir, sys, clock: c }), true);
    raiseFence("lease", A, { dir: join(e.fenceDir, "..") });
    const r = await leaseActivate(A, "L", 1, { dir: e.dir, fenceDir: e.fenceDir, sys, clock: c, lock: locks.lock });
    assert.deepEqual(r, { activated: true, reason: null, lowered: true }, `gen ${gen}`);
  }
});

test("the watchdog is a no-op only for a strictly newer lg: same, older, missing and unreadable records all act", async () => {
  for (const [label, setup, acts] of [
    ["newer", (e) => writeRecord(A, { lease_id: "L", lg: 6, expiry_tick: 1, gen: 3, sg: 0 }, { dir: e.dir }), false],
    ["same", (e) => writeRecord(A, { lease_id: "L", lg: 5, expiry_tick: 1, gen: 3, sg: 0 }, { dir: e.dir }), true],
    ["older", (e) => writeRecord(A, { lease_id: "L", lg: 4, expiry_tick: 1, gen: 3, sg: 0 }, { dir: e.dir }), true],
    ["missing", () => {}, true],
    ["unreadable", (e) => { mkdirSync(e.dir, { recursive: true }); writeFileSync(join(e.dir, A), "{not json"); }, true],
    ["malformed", (e) => { mkdirSync(e.dir, { recursive: true }); writeFileSync(join(e.dir, A), JSON.stringify({ lease_id: "L", lg: 9, expiry_tick: 1, gen: 3, x: 1 })); }, true],
    // r3.12: gen changes nothing here; the old three-key shape is malformed, so the watchdog acts on it.
    ["newer, another gen", (e) => writeRecord(A, { lease_id: "L", lg: 6, expiry_tick: 1, gen: 7, sg: 0 }, { dir: e.dir }), false],
    ["same, another gen", (e) => writeRecord(A, { lease_id: "L", lg: 5, expiry_tick: 1, gen: 9, sg: 0 }, { dir: e.dir }), true],
    ["the old shape, newer lg", (e) => { mkdirSync(e.dir, { recursive: true }); writeFileSync(join(e.dir, A), JSON.stringify({ lease_id: "L", lg: 9, expiry_tick: 1 })); }, true],
  ]) {
    const e = env(), locks = fakeLocks(), sys = fakeSys(e, { locks });
    setup(e);
    const r = await leaseExpire(A, "L", 5, opts(e, sys, locks));
    assert.equal(r.acted, acts, label);
    if (!acts) { assert.deepEqual(sys.calls, [], label); assert.equal(existsSync(e.fence), false); assert.equal(readTombstone(A, { dir: e.dir }), 0); continue; }
    assert.equal(r.proven, true, label);
    assert.equal(r.state, "stopped", label);
    assert.equal(existsSync(e.fence), true, `${label}: the durable lease fence`);
    assert.equal(readTombstone(A, { dir: e.dir }), 5, label);
    assert.equal(sys.masked, true, label);
    assert.ok(sys.calls.some((c) => c[0] === "stop" && c[1] === `sagebrush-agents-${A}.slice`), `${label}: the whole slice is stopped`);
    assert.ok(!kinds(sys).includes("unmask") && !kinds(sys).includes("start"), `${label}: it only ever stops`);
    assert.equal(JSON.parse(readFileSync(join(e.dir, `${A}.health`), "utf8")).state, "stopped");
  }
});

test("the order: tombstone, then fence, then mask, then the stop", async () => {
  const e = env(), locks = fakeLocks(), sys = fakeSys(e, { locks }), seen = [];
  await leaseExpire(A, "L", 1, opts(e, sys, locks, { barrier: async (n) => seen.push([n, readTombstone(A, { dir: e.dir }), existsSync(e.fence), sys.masked ?? false]) }));
  assert.deepEqual(seen, [["after_tombstone", 1, false, false], ["after_fence", 1, true, false], ["after_mask", 1, true, true]]);
});

test("the tombstone is an atomic max: an older watchdog never lowers it, concurrent watchdogs end at the max either way", async () => {
  const e = env(), locks = fakeLocks(), sys = fakeSys(e, { locks });
  await leaseExpire(A, "L", 7, opts(e, sys, locks));
  await leaseExpire(A, "L", 5, opts(e, sys, locks));
  assert.equal(readTombstone(A, { dir: e.dir }), 7);
  for (const order of [[5, 6], [6, 5]]) {
    const e2 = env(), l2 = fakeLocks(), s2 = fakeSys(e2, { locks: l2 });
    await Promise.all(order.map((lg) => leaseExpire(A, "L", lg, opts(e2, s2, l2, { maxLockRetries: 50 }))));
    assert.equal(readTombstone(A, { dir: e2.dir }), 6, String(order));
  }
});

test("T2g: shared holders inside the slice never block the watchdog: raise and mask first, kill the slice, then the tombstone", async () => {
  for (const holders of [1, 2]) {
    const e = env(), locks = fakeLocks(), sys = fakeSys(e, { locks });
    mkdirSync(e.dir, { recursive: true });
    for (let i = 0; i < holders; i++) await locks.holdInSlice(join(e.dir, `${A}.lock`), true);
    const seen = [];
    const r = await leaseExpire(A, "L", 3, opts(e, sys, locks, { barrier: async (n) => seen.push([n, existsSync(e.fence), sys.masked ?? false, locks.count(join(e.dir, `${A}.lock`))]) }));
    assert.deepEqual(seen[0], ["after_busy_kill", true, true, 0], "fenced and masked before the kill; the kill released every holder");
    assert.equal(readTombstone(A, { dir: e.dir }), 3);
    assert.equal(r.proven, true);
    // the fence and mask came before the first kill
    const k = kinds(sys);
    assert.ok(k.indexOf("mask") < k.indexOf("kill"));
  }
});

test("a watchdog never kills outside the slice, never by pid: a busy lock held OUTSIDE the slice still ends fenced, masked and stopped", async () => {
  const e = env(), locks = fakeLocks(), sys = fakeSys(e, { locks });
  mkdirSync(e.dir, { recursive: true });
  writeFileSync(join(e.dir, `${A}.lock.pid`), "1\n"); // a reused pid: nothing reads it to kill
  await locks.lock(join(e.dir, `${A}.lock`), {}); // not killable by the slice kill
  const r = await leaseExpire(A, "L", 3, opts(e, sys, locks, { maxLockRetries: 3 }));
  assert.equal(r.tombstone, false);
  assert.equal(existsSync(e.fence), true);
  assert.equal(sys.masked, true);
  assert.equal(r.proven, true);
  assert.ok(sys.calls.filter((c) => c[0] === "kill").every((c) => c[1] === e.slice));
});

test("a record renewed while the watchdog waited for the lock: it is stale after all and stops nothing", async () => {
  const e = env(), locks = fakeLocks(), sys = fakeSys(e, { locks });
  writeRecord(A, { lease_id: "L", lg: 3, expiry_tick: 1, gen: 3, sg: 0 }, { dir: e.dir });
  const lock = async (p, o) => { writeRecord(A, { lease_id: "M", lg: 4, expiry_tick: 2, gen: 3, sg: 0 }, { dir: e.dir }); return locks.lock(p, o); };
  const r = await leaseExpire(A, "L", 3, { ...opts(e, sys, locks), lock });
  assert.equal(r.acted, false);
  assert.equal(existsSync(e.fence), false);
  assert.deepEqual(sys.calls, []);
  assert.equal(readTombstone(A, { dir: e.dir }), 3);
});

test("a proof failure: the agent stays fenced and masked, the kill and proof are retried, and the health record says so", async () => {
  const e = env(), locks = fakeLocks(), sys = fakeSys(e, { locks, stubborn: true });
  let waits = 0;
  const r = await leaseExpire(A, "L", 2, opts(e, sys, locks, { maxProofRetries: 3, wait: async (ms) => { if (ms === 10000) waits++; } }));
  assert.equal(r.proven, false);
  assert.equal(r.state, "proof_failed");
  assert.equal(waits, 3);
  assert.ok(sys.calls.filter((c) => c[0] === "kill").length >= 4);
  assert.equal(existsSync(e.fence), true);
  assert.equal(sys.masked, true);
  assert.equal(JSON.parse(readFileSync(join(e.dir, `${A}.health`), "utf8")).state, "proof_failed");
  assert.ok(!kinds(sys).includes("unmask") && !kinds(sys).includes("start"));
});

test("a proof failure: before each retry, the unit's stop, best effort, always after a kill and never before the first", async () => {
  const e = env(), locks = fakeLocks(), sys = fakeSys(e, { locks, stubborn: true });
  const r = await leaseExpire(A, "L", 2, opts(e, sys, locks, { maxProofRetries: 2 }));
  assert.equal(r.proven, false);
  const ks = kinds(sys).filter((k) => k === "kill" || k === "stop");
  // kill, stop, kill, stop, kill, then the final stop after the last proof
  assert.deepEqual(ks, ["kill", "stop", "kill", "stop", "kill", "stop"]);
  // A stop that fails, or one that ends the stubbornness, is handled: the next proof decides.
  const s2 = fakeSys(e, { locks, stubborn: true });
  s2.stop = async (unit) => { s2.calls.push(["stop", unit]); throw new Error("systemctl stop: timed out"); };
  const r2 = await leaseExpire(A, "L", 3, opts(e, s2, locks, { maxProofRetries: 1 }));
  assert.equal(r2.proven, false);
  assert.equal(kinds(s2).filter((k) => k === "kill").length, 2, "the retry still kills and proves");
  const s3 = fakeSys(e, { locks, stubborn: true });
  s3.stop = async (unit) => { s3.calls.push(["stop", unit]); s3.procs = 0; }; // (the slice yields to systemd's stop)
  const r3 = await leaseExpire(A, "L", 4, opts(e, s3, locks, { maxProofRetries: 5 }));
  assert.equal(r3.proven, true, "the retry after the stop proves the slice empty");
  assert.deepEqual(kinds(s3).filter((k) => k === "kill" || k === "stop"), ["kill", "stop", "stop"], "proven at the second look: no second kill needed");
});

test("the unit's stop is bounded by STOP_MS (systemctl through the bounded runner)", async () => {
  const seen = [];
  const sys = realSystem({ run: async (argv, o) => { seen.push([argv.join(" "), o.ms]); return { code: 0, stdout: "", stderr: "" }; } });
  await sys.stop("sagebrush-agents-x.slice");
  assert.deepEqual(seen, [["systemctl stop sagebrush-agents-x.slice", 10000]]);
});

test("an absent slice is proven empty; an unreadable one is never", async () => {
  const e = env(), locks = fakeLocks(), sys = fakeSys(e, { locks });
  sys.sliceExists = false;
  assert.equal((await leaseExpire(A, "L", 1, opts(e, sys, locks))).proven, true);
  const s2 = fakeSys(e, { locks });
  s2.empty = () => { throw new Error("EIO"); };
  assert.equal((await leaseExpire(A, "L", 2, opts(e, s2, locks, { maxProofRetries: 0 }))).proven, false);
});

function activated(e, c, lg = 1, more = {}) {
  const locks = fakeLocks(), sys = fakeSys(e, { locks, ...more });
  return { locks, sys, run: async () => {
    const rec = { lease_id: "L", lg, expiry_tick: c.boot() + 600_000, gen: 3, sg: 0 };
    await armWatchdog(A, rec, { sys, clock: c });
    assert.equal(await publish(A, rec, { dir: e.dir, sys, clock: c }), true);
    raiseFence("lease", A, { dir: join(e.fenceDir, "..") });
    return rec;
  } };
}

test("the helper: inside its scope, under the lock, every check passing: lowers, unmasks, queues the start", async () => {
  const e = env(), c = fakeClock(), { locks, sys, run } = activated(e, c);
  await run();
  const r = await leaseActivate(A, "L", 1, { dir: e.dir, fenceDir: e.fenceDir, sys, clock: c, lock: locks.lock });
  assert.deepEqual(r, { activated: true, reason: null, lowered: true });
  assert.equal(existsSync(e.fence), false);
  assert.deepEqual(kinds(sys).filter((k) => k === "unmask" || k === "start"), ["unmask", "start"]);
  assert.equal(existsSync(join(e.dir, `${A}.lock.pid`)), false);
  assert.equal(locks.count(join(e.dir, `${A}.lock`)), 0, "released last");
});

test("the helper refuses, changing nothing: outside the slice, busy, unpublished or mismatched, spent, elapsed, inside the margin", async () => {
  const cases = [
    ["outside_slice", (k) => { k.sys.self = "/system.slice/x.service"; }],
    ["busy", async (k, e) => { await k.locks.lock(join(e.dir, `${A}.lock`), {}); }],
    ["not_published", (k, e) => writeRecord(A, { lease_id: "OTHER", lg: 1, expiry_tick: 9e12, gen: 3, sg: 0 }, { dir: e.dir })],
    // r3.12: the same lease in the old three-key shape is malformed, so it isn't published either
    ["not_published", (k, e) => writeFileSync(join(e.dir, A), JSON.stringify({ lease_id: "L", lg: 1, expiry_tick: 9e12 }))],
    ["spent", (k, e) => writeFileSync(join(e.dir, `${A}.spent`), "1\n")],
    ["timer_not_waiting", (k) => { k.sys.timers[watchdogTimer(A, 1)].sub = "elapsed"; }],
    ["expired", (k, e, c) => c.advance(600_000 - MARGIN_MS)],
  ];
  for (const [reason, spoil] of cases) {
    const e = env(), c = fakeClock(), k = activated(e, c);
    await k.run();
    await spoil(k, e, c);
    const r = await leaseActivate(A, "L", 1, { dir: e.dir, fenceDir: e.fenceDir, sys: k.sys, clock: c, lock: k.locks.lock });
    assert.deepEqual(r, { activated: false, reason, lowered: false }, reason);
    assert.equal(existsSync(e.fence), true, `${reason}: the fence stays`);
    assert.ok(!kinds(k.sys).includes("unmask") && !kinds(k.sys).includes("start"), reason);
  }
});

test("a watchdog at every activation seam: no lease fence ends lowered after a watchdog commit for that lg", async () => {
  const seams = ["before", "after_pid", "after_checks", "after_lower", "after_unmask", "after_start", "after"];
  for (const seam of seams) {
    const e = env(), c = fakeClock(), k = activated(e, c);
    await k.run();
    const wd = () => leaseExpire(A, "L", 1, { ...opts(e, k.sys, k.locks), maxLockRetries: 5 });
    let killed = false;
    k.sys.kill = (d) => { k.sys.calls.push(["kill", d]); killed = true; k.locks.killSliceHolders(); k.sys.procs = 0; };
    if (seam === "before") await wd();
    const barrier = async (n) => {
      if (n !== seam) return;
      await wd(); // the helper holds the lock here: the watchdog raises, masks and kills the slice (and the helper)
      if (killed) throw new Error("killed with the slice");
    };
    k.locks.nextKillable = true; // the helper runs inside the slice
    await leaseActivate(A, "L", 1, { dir: e.dir, fenceDir: e.fenceDir, sys: k.sys, clock: c, lock: k.locks.lock, barrier }).catch(() => {});
    if (seam === "after") await wd();
    assert.equal(existsSync(e.fence), true, `${seam}: the fence is up at the end`);
    assert.equal(readTombstone(A, { dir: e.dir }), 1, seam);
    assert.equal(k.sys.masked, true, seam);
    // a helper starting after the commit refuses
    const again = await leaseActivate(A, "L", 1, { dir: e.dir, fenceDir: e.fenceDir, sys: k.sys, clock: c, lock: k.locks.lock });
    assert.equal(again.activated, false, seam);
  }
});

test("T2d: arm, then both watchdogs fire before publication; publication 10 s before the signed expiry finds the lg spent", async () => {
  for (const first of [true, false]) {
    const e = env(), c = fakeClock(), locks = fakeLocks(), sys = fakeSys(e, { locks });
    if (!first) { const old = { lease_id: "O", lg: 1, expiry_tick: c.boot() + 60_000, gen: 3, sg: 0 }; await armWatchdog(A, old, { sys, clock: c }); await publish(A, old, { dir: e.dir, sys, clock: c }); }
    const lg = first ? 1 : 2;
    const rec = { lease_id: "N", lg, expiry_tick: c.boot() + 120_000, gen: 3, sg: 0 };
    await armWatchdog(A, rec, { sys, clock: c });
    // the supervisor is stopped here; both timers fire
    if (!first) await leaseExpire(A, "O", 1, opts(e, sys, locks));
    sys.timers[watchdogTimer(A, lg)].sub = "elapsed";
    await leaseExpire(A, "N", lg, opts(e, sys, locks));
    c.advance(120_000 - 10_000);
    assert.equal(await publish(A, rec, { dir: e.dir, sys, clock: c }), false);
    const r = await leaseActivate(A, "N", lg, { dir: e.dir, fenceDir: e.fenceDir, sys, clock: c, lock: locks.lock });
    assert.equal(r.activated, false);
    assert.equal(existsSync(e.fence), true);
    assert.ok(!kinds(sys).includes("unmask") && !kinds(sys).includes("start"));
  }
});

test("realSystem reads the timer through busctl's raw values, and checks the slice is a cgroup v2 directory", async () => {
  const calls = [];
  const run = async (argv) => {
    calls.push(argv);
    if (argv.includes("org.freedesktop.systemd1.Unit")) return { code: 0, stdout: 's "active"\ns "waiting"\n', stderr: "" };
    return { code: 0, stdout: "t 1234567\n", stderr: "" };
  };
  const sys = realSystem({ run });
  assert.deepEqual(await sys.timer(watchdogTimer(A, 1)), { active: "active", sub: "waiting", next: 1234567 });
  assert.equal(calls[0][3], unitObjectPath(watchdogTimer(A, 1)));
  const bad = realSystem({ run: async () => ({ code: 0, stdout: "garbage\n", stderr: "" }) });
  await assert.rejects(bad.timer("x.timer"));
  const e = env();
  assert.equal(sys.cgroup(join(e.root, "nope")), null);
  mkdirSync(e.slice, { recursive: true });
  assert.throws(() => sys.cgroup(e.slice), /isn't a cgroup/, "a plain directory (not cgroup2) is refused");
});

test("fence.mjs: lease is a per-agent cause that fences and stops the whole slice, and lowerFence never lowers it", async () => {
  const e = env(), dir = join(e.fenceDir, "..");
  raiseFence("lease", A, { dir });
  assert.equal(existsSync(join(dir, "lease", A)), true);
  assert.equal(fenced(A, { dir }), true);
  await rejects(lowerFence("lease", A, "lease-activate", { dir }), "not_granted");
  await rejects(stop({ all: true }, "lease", { dir }), "bad_form");
  const calls = [];
  const sys = { stop: (u) => calls.push(u), jobs: () => [], cancel() {}, activeAgentUnits: () => [], rootUnits: () => [], procCount: () => 0 };
  const r = await stop({ agent: A }, "lease", { dir, sys });
  assert.equal(r.status, "stopped and fenced");
  assert.deepEqual(calls, [`sagebrush-agents-${A}.slice`]);
});

test("lease-main: bad arguments exit 2 before anything runs", () => {
  const main = new URL("../lib/fleet/host/lease-main.mjs", import.meta.url).pathname;
  for (const args of [[], ["lease-expire", A, "L"], ["lease-start", A, "L", "1"], ["lease-expire", "bad", "L", "1"], ["lease-activate", A, "L", "0"]]) {
    const r = spawnSync(process.execPath, [main, ...args], { encoding: "utf8", timeout: 20000 });
    assert.equal(r.status, 2, args.join(" "));
  }
});

test("the real flock: a shared holder and the exclusive watchdog lock exclude each other; two shared holders coexist", async () => {
  const e = env(); mkdirSync(e.dir, { recursive: true });
  const p = join(e.dir, `${A}.lock`); writeFileSync(p, "");
  const s1 = await lockFile(p, { shared: true }), s2 = await lockFile(p, { shared: true });
  await rejects(lockFile(p, { waitMs: 200 }), "in_progress");
  await s1.release(); await s2.release();
  const x = await lockFile(p, { waitMs: 200 });
  await rejects(lockFile(p, { shared: true }), "in_progress");
  await x.release();
});

test("a watchdog that had to kill the slice for the lock completes its stop even if a newer record appeared", async () => {
  const e = env(), locks = fakeLocks(), sys = fakeSys(e, { locks });
  mkdirSync(e.dir, { recursive: true });
  await locks.holdInSlice(join(e.dir, `${A}.lock`), true);
  const kill = sys.kill;
  sys.kill = (d) => { kill(d); writeRecord(A, { lease_id: "M", lg: 9, expiry_tick: 2, gen: 3, sg: 0 }, { dir: e.dir }); };
  const r = await leaseExpire(A, "L", 3, opts(e, sys, locks));
  assert.equal(r.acted, true);
  assert.equal(r.proven, true);
  assert.equal(existsSync(e.fence), true);
});

test("the helper holds the exclusive lock at every seam, until after the start is queued", async () => {
  const e = env(), c = fakeClock(), k = activated(e, c);
  await k.run();
  const seen = [];
  await leaseActivate(A, "L", 1, { dir: e.dir, fenceDir: e.fenceDir, sys: k.sys, clock: c, lock: k.locks.lock,
    barrier: async (n) => seen.push([n, k.locks.count(join(e.dir, `${A}.lock`)), existsSync(join(e.dir, `${A}.lock.pid`))]) });
  assert.deepEqual(seen, ["after_pid", "after_checks", "after_lower", "after_unmask", "after_start"].map((n) => [n, 1, true]));
});

test("realSystem.empty: every cgroup.procs in the tree, recursively, and the slice's populated 0", () => {
  const e = env(), sys = realSystem();
  const mk = (d, procs, events) => { mkdirSync(d, { recursive: true }); writeFileSync(join(d, "cgroup.procs"), procs); if (events) writeFileSync(join(d, "cgroup.events"), events); };
  mk(e.slice, "", "populated 0\nfrozen 0\n");
  mk(join(e.slice, "u.service"), "");
  mk(join(e.slice, "t.scope", "inner"), "");
  writeFileSync(join(e.slice, "t.scope", "cgroup.procs"), "");
  assert.equal(sys.empty(e.slice), true);
  writeFileSync(join(e.slice, "t.scope", "inner", "cgroup.procs"), "4242\n");
  assert.equal(sys.empty(e.slice), false, "a process deep in a turn scope");
  writeFileSync(join(e.slice, "t.scope", "inner", "cgroup.procs"), "");
  writeFileSync(join(e.slice, "cgroup.events"), "populated 1\nfrozen 0\n");
  assert.equal(sys.empty(e.slice), false, "populated 1 (a thread-only or zombie-held cgroup)");
});

test("realSystem.mask: the runtime mask counts only when is-enabled then says masked or masked-runtime", async () => {
  for (const [state, ok] of [["masked-runtime", true], ["masked", true], ["static", false], ["enabled", false], ["linked-runtime", false], ["", false]]) {
    const calls = [];
    const run = async (argv) => { calls.push(argv); return argv[1] === "is-enabled" ? { code: state.startsWith("masked") ? 1 : 0, stdout: `${state}\n`, stderr: "" } : { code: 0, stdout: "", stderr: "" }; };
    const p = realSystem({ run }).mask(`sagebrush-agent-${A}.service`);
    if (ok) await p; else await assert.rejects(p, /the mask isn't effective/, state || "(empty)");
    assert.deepEqual(calls.map((c) => c.slice(0, 3)), [["systemctl", "mask", "--runtime"], ["systemctl", "is-enabled", `sagebrush-agent-${A}.service`]]);
  }
  // a failing mask command refuses before any is-enabled
  await assert.rejects(realSystem({ run: async () => ({ code: 1, stdout: "", stderr: "" }) }).mask("u.service"));
});

test("realSystem.cgroup: only a real directory on cgroup2: a symlink, a file or another fs type is refused, even when statfs says cgroup2", () => {
  const CG2 = 0x63677270;
  const mk = (kind, type) => realSystem({ fsx: {
    lstatSync: () => ({ isDirectory: () => kind === "dir", isSymbolicLink: () => kind === "symlink", isFile: () => kind === "file" }),
    statfsSync: () => ({ type }),
  } });
  assert.equal(mk("dir", CG2).cgroup("/sys/fs/cgroup/x.slice"), "/sys/fs/cgroup/x.slice");
  for (const kind of ["symlink", "file"]) assert.throws(() => mk(kind, CG2).cgroup("/sys/fs/cgroup/x.slice"), /isn't a cgroup/, kind);
  assert.throws(() => mk("dir", 0xef53).cgroup("/sys/fs/cgroup/x.slice"), /isn't a cgroup/, "ext4");
  const gone = realSystem({ fsx: { lstatSync: () => { throw Object.assign(new Error("ENOENT"), { code: "ENOENT" }); } } });
  assert.equal(gone.cgroup("/sys/fs/cgroup/x.slice"), null);
  const eacces = realSystem({ fsx: { lstatSync: () => { throw Object.assign(new Error("EACCES"), { code: "EACCES" }); } } });
  assert.throws(() => eacces.cgroup("/sys/fs/cgroup/x.slice"), /EACCES/);
});

test("cross-language fixture: lease.mjs reads the runtime files exactly as the fixture's js column (the launcher pins rust)", () => {
  const fx = JSON.parse(readFileSync(new URL("./fixtures/host/lease-files.json", import.meta.url), "utf8"));
  const e = env(); mkdirSync(e.dir, { recursive: true });
  for (const t of fx.tombstones) {
    writeFileSync(join(e.dir, `${A}.spent`), t.text);
    assert.equal(readTombstone(A, { dir: e.dir }), t.js, JSON.stringify(t.text));
    if (t.rust !== null && t.js !== null) assert.equal(t.rust, t.js);
  }
  for (const r of fx.records) {
    writeFileSync(join(e.dir, A), r.text);
    assert.equal(readRecord(A, { dir: e.dir }).state === "ok", r.js, r.text);
    assert.ok(!r.rust || r.js, `rust is never more lenient: ${r.text}`);
  }
});

// ---- the suspend gate (lease-on r1.5 §6.1-6.3) -------------------------------------------------------------------------

const MAX = 2 ** 53 - 1;
const sleepText = (gen, phase = "post", preOk = true, preAt = 0) => JSON.stringify({ gen, phase, pre_ok: preOk, pre_at: preAt });
const reopenText = (gen) => JSON.stringify({ gen });
/** Write the gate files (null removes one), root-style: this process's uid, 0644. */
function gateFiles(dir, sleep, reopen) {
  mkdirSync(dir, { recursive: true, mode: 0o755 });
  for (const [name, text] of [[SLEEP_FILE, sleep], [REOPEN_FILE, reopen]]) {
    const f = join(dir, name);
    try { spawnSync("rm", ["-f", f]); } catch { /* none */ }
    if (text !== null) { writeFileSync(f, text, { mode: 0o644 }); chmodSync(f, 0o644); }
  }
}

test("the gate, cross-language: gateOf decides every fixture row exactly as its js column, and rust is pinned equal", () => {
  const fx = JSON.parse(readFileSync(new URL("./fixtures/host/lease-files.json", import.meta.url), "utf8"));
  assert.ok(fx.gate.length >= 20);
  for (const row of fx.gate) {
    const read = (t) => (t === null ? { state: "missing" } : { state: "ok", text: t });
    const g = gateOf(read(row.sleep), read(row.reopen), row.now);
    assert.equal(g.open ? g.g : null, row.js, row.name);
    assert.equal(row.rust, row.js, `rust and js agree: ${row.name}`);
    if (!g.open) assert.equal(typeof g.why, "string", row.name);
  }
  assert.equal(G_MAX, MAX - 1, "2^53 - 1 is the terminal generation, never opened");
});

test("the gate reads trusted files only: a group- or other-writable file, a link, an unreadable one, or an untrusted directory reads CLOSED", () => {
  const e = env(), c = fakeClock();
  gateFiles(e.dir, sleepText(3), reopenText(3));
  assert.deepEqual(readGate({ dir: e.dir, clock: c }), { open: true, g: 3 });
  chmodSync(join(e.dir, SLEEP_FILE), 0o666);
  assert.equal(readGate({ dir: e.dir, clock: c }).open, false, "other-writable sleep");
  chmodSync(join(e.dir, SLEEP_FILE), 0o644);
  spawnSync("rm", ["-f", join(e.dir, REOPEN_FILE)]); symlinkSync(join(e.dir, SLEEP_FILE), join(e.dir, REOPEN_FILE));
  assert.equal(readGate({ dir: e.dir, clock: c }).open, false, "a link");
  gateFiles(e.dir, sleepText(3), reopenText(3));
  chmodSync(e.dir, 0o775);
  assert.equal(readGate({ dir: e.dir, clock: c }).why, "untrusted", "a group-writable lease directory");
  chmodSync(e.dir, 0o755);
  assert.equal(readGateFile(e.dir, SLEEP_FILE, { uid: process.getuid() + 1 }).state, "bad", "another owner");
  // no lease directory at all: both absent, open at 0
  assert.deepEqual(readGate({ dir: join(e.root, "nothing"), clock: c }), { open: true, g: 0 });
  gateFiles(e.dir, sleepText(3), null);
  assert.deepEqual(readGate({ dir: e.dir, clock: c }), { open: false, why: "one_sided" });
});

test("liveCheck refuses `suspended` unless the gate is open at exactly the record's sg, before any other check", async () => {
  const e = env(), c = fakeClock(), sys = fakeSys(e);
  const rec = { lease_id: "L1", lg: 2, expiry_tick: c.boot() + 600_000, gen: 3, sg: 4 };
  await armWatchdog(A, rec, { sys, clock: c });
  const o = { dir: e.dir, sys, clock: c };
  gateFiles(e.dir, sleepText(4), reopenText(4));
  assert.equal(await liveCheck(A, rec, o), null, "open at 4: live");
  gateFiles(e.dir, sleepText(5, "pre"), reopenText(4));
  assert.equal(await liveCheck(A, rec, o), "suspended", "closed (a PRE)");
  gateFiles(e.dir, sleepText(5), reopenText(5));
  assert.equal(await liveCheck(A, rec, o), "suspended", "open at a NEWER generation: the old lease never passes again");
  gateFiles(e.dir, null, null);
  assert.equal(await liveCheck(A, rec, o), "suspended", "open at 0, the record's sg is 4");
  const calls = sys.calls.length;
  gateFiles(e.dir, sleepText(5, "pre"), reopenText(4));
  await liveCheck(A, rec, o);
  assert.equal(sys.calls.length, calls, "the gate is checked first: no timer read on a closed gate");
});

test("T4, exhaustion: open at G_max with a live lease; the terminal generation closes it for good, in every reader", async () => {
  const e = env(), c = fakeClock(), sys = fakeSys(e);
  const rec = { lease_id: "L1", lg: 2, expiry_tick: c.boot() + 600_000, gen: 3, sg: G_MAX };
  await armWatchdog(A, rec, { sys, clock: c });
  gateFiles(e.dir, sleepText(G_MAX), reopenText(G_MAX));
  assert.equal(await liveCheck(A, rec, { dir: e.dir, sys, clock: c }), null, "open at G_max, live");
  gateFiles(e.dir, sleepText(MAX, "pre"), reopenText(G_MAX));
  assert.equal(await liveCheck(A, rec, { dir: e.dir, sys, clock: c }), "suspended", "a PRE to 2^53 - 1");
  gateFiles(e.dir, sleepText(MAX), reopenText(G_MAX));
  assert.equal(readGate({ dir: e.dir, clock: c }).why, "unacknowledged");
  gateFiles(e.dir, sleepText(MAX), reopenText(MAX));
  assert.deepEqual(readGate({ dir: e.dir, clock: c }), { open: false, why: "exhausted" }, "even acknowledged, 2^53 - 1 never opens");
  for (const sg of [G_MAX, MAX]) assert.equal(await liveCheck(A, { ...rec, sg }, { dir: e.dir, sys, clock: c }), "suspended", `sg ${sg}`);
  // a late publication for the old generation, and one claiming the terminal generation: neither is published
  for (const sg of [G_MAX, MAX]) {
    assert.equal(await publish(A, { ...rec, lg: 9, sg }, { dir: e.dir, sys, clock: c }), false, `publish sg ${sg}`);
  }
});

test("publish (§6.3): under the exclusive activation lock; the gate closing between its write and its re-read spends the lease", async () => {
  const e = env(), c = fakeClock(), sys = fakeSys(e);
  const rec = { lease_id: "L1", lg: 7, expiry_tick: c.boot() + 600_000, gen: 3, sg: 2 };
  await armWatchdog(A, rec, { sys, clock: c });
  gateFiles(e.dir, sleepText(2), reopenText(2));
  // A PRE that closes the gate right after the record's rename (the crossing §6.3 linearizes).
  const crossing = { ...realIo, rename: (a, b) => { realIo.rename(a, b); if (b === join(e.dir, A)) writeFileSync(join(e.dir, SLEEP_FILE), sleepText(3, "pre", false, 0)); } };
  assert.equal(await publish(A, rec, { dir: e.dir, sys, clock: c, io: crossing }), false);
  assert.ok(readTombstone(A, { dir: e.dir }) >= rec.lg, "spent by publish itself, under the lock");
  assert.equal(readRecord(A, { dir: e.dir }).state, "ok", "the record was written");
  assert.equal(await liveCheck(A, rec, { dir: e.dir, sys, clock: c }), "suspended", "and no reader passes it");
  // gate already closed: nothing is written
  const e2 = env(); await armWatchdog(A, rec, { sys: fakeSys(e2), clock: c });
  gateFiles(e2.dir, sleepText(3, "pre"), reopenText(2));
  assert.equal(await publish(A, rec, { dir: e2.dir, sys: fakeSys(e2), clock: c }), false);
  assert.equal(readRecord(A, { dir: e2.dir }).state, "missing");
  // a busy activation lock: not published, nothing written, never waiting unbounded
  const e3 = env(), locks = fakeLocks(), sys3 = fakeSys(e3, { locks });
  await armWatchdog(A, rec, { sys: sys3, clock: c });
  gateFiles(e3.dir, sleepText(2), reopenText(2));
  await locks.lock(join(e3.dir, `${A}.lock`), {});
  assert.equal(await publish(A, rec, { dir: e3.dir, sys: sys3, clock: c, lock: locks.lock }), false);
  assert.equal(readRecord(A, { dir: e3.dir }).state, "missing");
  // the happy path holds the lock while it writes
  const e4 = env(), l4 = fakeLocks(), s4 = fakeSys(e4, { locks: l4 });
  await armWatchdog(A, rec, { sys: s4, clock: c });
  gateFiles(e4.dir, sleepText(2), reopenText(2));
  assert.equal(await publish(A, rec, { dir: e4.dir, sys: s4, clock: c, lock: l4.lock }), true);
  assert.deepEqual(l4.takes.map((t) => t.shared), [false], "one exclusive take");
  assert.equal(l4.count(join(e4.dir, `${A}.lock`)), 0, "released");
});

test("the helpers refuse a lease from another gate generation (`suspended`), lowering nothing", async () => {
  const e = env(), c = fakeClock(), locks = fakeLocks(), sys = fakeSys(e, { locks });
  const rec = { lease_id: "L", lg: 1, expiry_tick: c.boot() + 600_000, gen: 3, sg: 1 };
  await armWatchdog(A, rec, { sys, clock: c });
  gateFiles(e.dir, sleepText(1), reopenText(1));
  assert.equal(await publish(A, rec, { dir: e.dir, sys, clock: c, lock: locks.lock }), true);
  raiseFence("lease", A, { dir: join(e.fenceDir, "..") });
  gateFiles(e.dir, sleepText(2), reopenText(2)); // a suspend and its reopen happened since
  const r = await leaseActivate(A, "L", 1, { dir: e.dir, fenceDir: e.fenceDir, sys, clock: c, lock: locks.lock });
  assert.deepEqual(r, { activated: false, reason: "suspended", lowered: false });
  assert.ok(existsSync(e.fence), "lease stays raised");
});

test("readGateFile reads the SAME object it looked at, through a handle that never follows a link", () => {
  const e = env();
  gateFiles(e.dir, sleepText(3), reopenText(3));
  const real = (k) => (...a) => (fsReal[k])(...a);
  // lstat answers for another object (a swap between the look and the open): bad, so the gate reads closed.
  const swapped = { ...fsReal, lstatSync: (p) => { const st = fsReal.lstatSync(p); return Object.assign(Object.create(Object.getPrototypeOf(st)), st, { ino: st.ino + 1 }); } };
  assert.equal(readGateFile(e.dir, SLEEP_FILE, { fsx: swapped }).state, "bad");
  assert.equal(readGateFile(e.dir, SLEEP_FILE, { fsx: { ...fsReal, openSync: real("openSync") } }).state, "ok");
  // an open refused for the object's type (a link swapped in: ELOOP): bad
  const eloop = { ...fsReal, openSync: () => { throw Object.assign(new Error("ELOOP"), { code: "ELOOP" }); } };
  assert.equal(readGateFile(e.dir, SLEEP_FILE, { fsx: eloop }).state, "bad");
});

test("SEC on S1: the gate files are parsed strictly, as the launcher parses them; JSON.parse's leniency never opens the gate", () => {
  const probe = '{"gen":2,"phase":"pre","phase":"post","pre_ok":true,"pre_at":0}';
  assert.equal(parseSleep(probe), null, "a duplicate phase is malformed");
  assert.deepEqual(gateOf({ state: "ok", text: probe }, { state: "ok", text: '{"gen":2}' }, 1000), { open: false, why: "malformed" });
  for (const t of ['{"gen":2.0}', '{"gen":2e0}', '{"gen":02}', '{"gen":-2}', '{"gen":2,"gen":2}', '{"gen":2} x']) assert.equal(parseReopen(t), null, t);
  assert.deepEqual(parseReopen(' { "\\u0067en" : 2 } '), { gen: 2 }, "escapes and whitespace decode as in Rust");
  assert.equal(parseGateJson('{"a":1,"a":1}'), null);
  assert.equal(parseGateJson('{"a":9007199254740992}').a, Infinity, "above the safe range: kept out of range");
});
