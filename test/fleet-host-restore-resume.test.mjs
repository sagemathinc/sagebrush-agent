// Backup r3.3 §5 step 11, the first-lease rule r2.1, schemas r2.4 §3.7.3: the restore resume. The supervisor checks
// what only it can read (validated, the transfer receipt over the host records, recording a pair new here before
// anything is launched, the live lease for the current entry_gen) and launches the helper; the helper, inside the
// agent's slice under the exclusive activation lock, re-checks what can change (validated, the published lease is the
// argv's and live, its gen, `lease` down), lowers `restore` and queues the start. Every other case refuses with its
// reason and changes no fence. Against a fake systemd, clock and lock (as the lease's own tests), and fakes for the
// shared core's verifiers and the supervisor's host records.
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, readdirSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "./host-linux-only.mjs";
import { FleetError, newId } from "../lib/fleet/index.mjs";
import { armWatchdog, leaseExpire, publish, raiseLeaseFence, readTombstone, watchdogTimer } from "../lib/fleet/host/lease.mjs";
import { raiseFence } from "../lib/fleet/host/fence.mjs";
import { REASONS, requestResume, resumeArgv, resumeCgroup, resumeRestored } from "../lib/fleet/host/restore-resume.mjs";
import { writeRecord } from "../lib/fleet/host/lease.mjs";
import { restoreResumeScope } from "../lib/fleet/host/names.mjs";
import { liveLease } from "../lib/fleet/host/lease-live.mjs";

const A = newId();
const refused = (fn, code) => assert.throws(fn, (e) => e instanceof FleetError && e.code === code, code);

function fakeClock({ monoUs = 5_000_000_000, offsetMs = 0 } = {}) {
  const c = { monoUs, offsetMs, mono: () => c.monoUs, boot: () => Math.floor(c.monoUs / 1000) + c.offsetMs, advance: (ms) => { c.monoUs += ms * 1000; } };
  return c;
}

/** A fake activation lock (as the lease tests'): conflicting takes refuse at once; slice holders die with the slice. */
function fakeLocks() {
  const held = new Map();
  const m = {
    takes: [],
    lock: async (path, { shared = false } = {}) => {
      const hs = held.get(path) ?? [];
      m.takes.push({ path, shared });
      if (hs.length && (!shared || hs.some((h) => !h.shared))) throw new FleetError("in_progress", "busy");
      const h = { shared, killable: m.nextKillable ?? false };
      m.nextKillable = false;
      hs.push(h); held.set(path, hs);
      return { release: async () => { const l = held.get(path) ?? []; const i = l.indexOf(h); if (i >= 0) l.splice(i, 1); } };
    },
    killSliceHolders: () => { for (const [p, l] of held) held.set(p, l.filter((h) => !h.killable)); },
    count: (path) => (held.get(path) ?? []).length,
    shared: (path) => (held.get(path) ?? []).every((h) => h.shared),
  };
  return m;
}

function fakeSys(e, { locks }) {
  const s = {
    calls: [], procs: 2, timers: {},
    arm: async (argv) => {
      const unit = argv.find((a) => a.startsWith("--unit=")).slice(7) + ".timer";
      const at = Number(/^--on-boot=([0-9]+)us$/.exec(argv.find((a) => a.startsWith("--on-boot=")))[1]);
      s.timers[unit] = { active: "active", sub: "waiting", next: at };
    },
    timer: async (unit) => { const t = s.timers[unit]; return t ? { ...t } : { active: "inactive", sub: "dead", next: 0 }; },
    mask: async (unit) => { s.calls.push(["mask", unit]); s.masked = true; },
    unmask: async (unit) => { s.calls.push(["unmask", unit]); },
    start: async (unit) => { s.calls.push(["start", unit]); },
    stop: async (unit) => { s.calls.push(["stop", unit]); s.procs = 0; },
    cgroup: (d) => d,
    kill: (d) => { s.calls.push(["kill", d]); locks.killSliceHolders(); s.procs = 0; s.killed = true; },
    empty: () => s.procs === 0,
    selfCgroup: () => s.self ?? resumeCgroup(A),
  };
  return s;
}

/**
 * A host where agent A was restored and validated, its first lease (lease_id L, lg 1, entry_gen 5) armed and
 * published (the record carries its gen, as lease.mjs writes it), `lease` down and `restore` up: the helper's world,
 * read through lease.mjs's own readRecord. `over` replaces any option.
 */
async function world(over = {}) {
  const root = mkdtempSync(join(tmpdir(), "sb-resume-"));
  const e = { root, dir: join(root, "run"), fenceDir: join(root, "fence"), leaseFenceDir: join(root, "fence", "lease"), slice: join(root, "cg") };
  const c = fakeClock(), locks = fakeLocks(), sys = fakeSys(e, { locks });
  const rec = { lease_id: "L", lg: 1, expiry_tick: c.boot() + 600_000, gen: 5, sg: 0 };
  await armWatchdog(A, rec, { sys, clock: c });
  assert.equal(await publish(A, rec, { dir: e.dir, sys, clock: c }), true);
  raiseFence("restore", A, { dir: e.fenceDir });
  /** Republish the same lease with another gen (the same lease_id, lg and expiry: only gen differs). */
  const withGen = (g) => writeRecord(A, { ...rec, gen: g }, { dir: e.dir });
  const deps = {
    restoreState: () => "validated",
    dir: e.dir, fenceDir: e.fenceDir, leaseFenceDir: e.leaseFenceDir, sys, clock: c, lock: locks.lock,
    cgroupOf: () => resumeCgroup(A), pid: 4242,
    ...over,
  };
  const restoreUp = () => existsSync(join(e.fenceDir, "restore", A));
  const fences = () => {
    const out = [];
    const walk = (d, rel) => { for (const n of existsSync(d) ? readdirSync(d, { withFileTypes: true }) : []) { if (n.isDirectory()) walk(join(d, n.name), `${rel}${n.name}/`); else out.push(`${rel}${n.name}`); } };
    walk(e.fenceDir, "");
    return out.filter((n) => !n.includes(".tmp") && !n.endsWith(".lock")).sort(); // (the fence lock's own file is no fence)
  };
  const lockPath = join(e.dir, `${A}.lock`);
  return { e, c, locks, sys, rec, deps, withGen, restoreUp, fences, lockPath, resume: (d = deps, gen = 5, leaseId = "L", lg = 1) => resumeRestored(A, gen, leaseId, lg, d) };
}

/** The supervisor's world: fakes for the verifiers and the host records, recording every call in order. */
function supervisor(over = {}) {
  const log = [];
  const PAIR = { transfer: "T-envelope", receipt: "R-envelope" };
  const verified = { transfer: { agent: A }, receipt: { agent: A, gen: 5, nonce: "N" }, transferHash: "H" };
  const host = {
    entryGen: (a) => { log.push(["entryGen", a]); return 5; },
    recordTransfer: (a, t) => { log.push(["recordTransfer", a, t]); },
  };
  const opts = {
    restoreState: (a) => { log.push(["state", a]); return "validated"; },
    tagsOf: () => [T1],
    pairOf: (a) => { log.push(["pair", a]); return PAIR; },
    verifyTransferReceipt: (p, ctx) => { log.push(["verify", p, ctx]); return verified; },
    checkTransferForHost: (v, h) => { log.push(["check", v, h === host]); return { first: false }; },
    verifyCtx: { fleet: "F" },
    host,
    // async, as the real one is
    liveLease: async (a) => { log.push(["live", a]); return { gen: 5, lease_id: "L", lg: 1, expiry_tick: 9 }; },
    run: async (argv, o) => { log.push(["run", argv, o.ms]); return { code: 0, stdout: '{"resumed":true,"reason":null,"lowered":true}\n' }; },
    node: "/n", main: "/m",
    ...over,
  };
  return { log, opts, PAIR, verified, host, kinds: () => log.map((l) => l[0]) };
}
const T1 = newId();

test("names and argv: the helper's scope inside the agent's slice, carrying the supervisor's live lease and the agent's tags", () => {
  assert.equal(restoreResumeScope(A), `sagebrush-restore-resume-${A}.scope`);
  assert.equal(resumeCgroup(A), `/sagebrush.slice/sagebrush-agents.slice/sagebrush-agents-${A}.slice/sagebrush-restore-resume-${A}.scope`);
  assert.deepEqual(resumeArgv(A, { gen: 5, lease_id: "L-1", lg: 3 }, [T1], { node: "/n", main: "/m.mjs" }), [
    "systemd-run", "--scope", "--quiet", "--collect", `--slice=sagebrush-agents-${A}.slice`, `--unit=sagebrush-restore-resume-${A}.scope`,
    "--", "/n", "/m.mjs", "resume-restored", A, "5", "L-1", "3", T1]);
  for (const live of [null, {}, { gen: 0, lease_id: "L", lg: 1 }, { gen: 5, lease_id: "a b", lg: 1 }, { gen: 5, lease_id: "L", lg: 0 }, { gen: 5, lease_id: "L", lg: "1" }, { gen: 1.5, lease_id: "L", lg: 1 }]) {
    refused(() => resumeArgv(A, live, []), "bad_form");
  }
  for (const tags of [null, ["nope"], [T1, T1], "x"]) refused(() => resumeArgv(A, { gen: 5, lease_id: "L", lg: 1 }, tags), "bad_form");
  refused(() => resumeArgv("nope", { gen: 5, lease_id: "L", lg: 1 }, []), "bad_form");
});

test("the supervisor: validated, then the receipt, then the live lease for the current entry_gen; then the helper, once", async () => {
  const s = supervisor();
  assert.deepEqual(await requestResume(A, s.opts), { resumed: true, reason: null });
  assert.deepEqual(s.kinds(), ["state", "pair", "verify", "check", "live", "entryGen", "run"]);
  assert.deepEqual(s.log.find((l) => l[0] === "verify").slice(1), [s.PAIR, { fleet: "F" }]);
  assert.deepEqual(s.log.find((l) => l[0] === "check").slice(1), [s.verified, true], "the verified pair, this host's records");
  const [, argv, ms] = s.log.find((l) => l[0] === "run");
  assert.deepEqual(argv, resumeArgv(A, { gen: 5, lease_id: "L", lg: 1 }, [T1], { node: "/n", main: "/m" }));
  assert.ok(ms > 0);
  assert.ok(!s.kinds().includes("recordTransfer"), "an already accepted pair isn't recorded again");
});

test("the supervisor: a pair new here is recorded durably before anything is launched; never when the resume can't run", async () => {
  const s = supervisor({ checkTransferForHost: () => ({ first: true }) });
  await requestResume(A, s.opts);
  assert.deepEqual(s.kinds().slice(-2), ["recordTransfer", "run"]);
  assert.deepEqual(s.log.find((l) => l[0] === "recordTransfer").slice(1), [A, { gen: 5, nonce: "N", transfer: "H" }]);
  // No live lease, or another entry_gen: refused before the record.
  for (const over of [{ liveLease: () => null }, { liveLease: () => ({ gen: 4, lease_id: "L", lg: 1 }) }]) {
    const t = supervisor({ checkTransferForHost: () => ({ first: true }), ...over });
    const r = await requestResume(A, t.opts);
    assert.equal(r.resumed, false);
    assert.ok(!t.kinds().includes("recordTransfer") && !t.kinds().includes("run"), JSON.stringify(r));
  }
  // A malformed live lease or tag list: the helper's argv fails its checks BEFORE the record, so nothing is recorded
  // and nothing launched.
  for (const over of [{ tagsOf: () => ["nope"] }, { tagsOf: () => [T1, T1] }, { tagsOf: () => null }, { tagsOf: undefined },
    { liveLease: () => ({ gen: 5, lease_id: "a b", lg: 1 }) }, { liveLease: () => ({ gen: 5, lease_id: "L", lg: "1" }) },
    { liveLease: () => ({ gen: 5, lease_id: "L" }) }, { liveLease: () => ({ gen: 5, lease_id: "L", lg: 0 }) }]) {
    const t = supervisor({ checkTransferForHost: () => ({ first: true }), ...over });
    await assert.rejects(requestResume(A, t.opts), (e) => e.code === "bad_form", JSON.stringify(Object.keys(over)));
    assert.ok(!t.kinds().includes("recordTransfer") && !t.kinds().includes("run"), JSON.stringify(Object.keys(over)));
  }
  // A recording that fails launches nothing.
  const f = supervisor({ checkTransferForHost: () => ({ first: true }) });
  f.host.recordTransfer = () => { throw new Error("EIO"); };
  await assert.rejects(requestResume(A, f.opts), /EIO/);
  assert.ok(!f.kinds().includes("run"));
});

test("the supervisor refuses, launching nothing: each condition in its order, with its reason", async () => {
  const fe = (code) => () => { throw new FleetError(code, "x"); };
  const cases = [
    ["not_validated", { restoreState: () => "published" }],
    ["not_validated", { restoreState: () => { throw new FleetError("not_granted", "another restore"); } }],
    ["no_verifier", { verifyTransferReceipt: undefined }],
    ["no_verifier", { checkTransferForHost: null }],
    ["no_host_records", { host: null }],
    ["no_host_records", { host: { entryGen: () => 5 } }],
    ["no_receipt", { pairOf: () => null }],
    ["no_receipt", { pairOf: undefined }],
    ["receipt", { verifyTransferReceipt: fe("bad_signature") }, "bad_signature"],
    ["receipt", { verifyTransferReceipt: fe("device_tier") }, "device_tier"],
    ["receipt", { checkTransferForHost: fe("not_granted") }, "not_granted"],
    ["receipt", { checkTransferForHost: fe("stale_generation") }, "stale_generation"],
    ["receipt", { checkTransferForHost: fe("replay") }, "replay"],
    ["receipt", { checkTransferForHost: () => ({}) }, "bad_form"],
    // a valid pair for ANOTHER agent authorizes nothing here (the transfer's or the receipt's agent)
    ["receipt", { verifyTransferReceipt: () => ({ transfer: { agent: newId() }, receipt: { agent: A, gen: 5, nonce: "N" }, transferHash: "H" }) }, "not_granted"],
    ["receipt", { verifyTransferReceipt: () => ({ transfer: { agent: A }, receipt: { agent: newId(), gen: 5, nonce: "N" }, transferHash: "H" }) }, "not_granted"],
    ["waiting_for_lease", { liveLease: () => null }],
    ["waiting_for_lease", { liveLease: undefined }],
    ["not_this_lease", { liveLease: () => ({ gen: 4, lease_id: "L", lg: 1 }) }],
    ["waiting_for_lease", { liveLease: async () => null }],
    ["not_this_lease", { liveLease: async () => ({ gen: 4, lease_id: "L", lg: 1, expiry_tick: 9 }) }],
    ["not_this_lease", { host: { entryGen: () => null, recordTransfer: () => {} } }],
    ["not_this_lease", { host: { entryGen: () => { throw new Error("x"); }, recordTransfer: () => {} } }],
  ];
  for (const [reason, over, code] of cases) {
    const s = supervisor(over);
    const r = await requestResume(A, s.opts);
    assert.deepEqual(r, { resumed: false, reason, ...(code ? { code } : {}) }, `${reason} ${code ?? ""}`);
    assert.ok(REASONS.includes(reason));
    assert.ok(!s.kinds().includes("run") && !s.kinds().includes("recordTransfer"), reason);
  }
  // The order: an unvalidated restore is reported before a missing receipt or lease.
  const s = supervisor({ restoreState: () => "staged", pairOf: () => null, liveLease: () => null });
  assert.equal((await requestResume(A, s.opts)).reason, "not_validated");
  // A verifier that fails without a verdict (a bug, an I/O error) isn't swallowed; nothing launches.
  const b = supervisor({ verifyTransferReceipt: () => { throw new Error("EIO"); } });
  await assert.rejects(requestResume(A, b.opts), /EIO/);
  assert.ok(!b.kinds().includes("run"));
  // The helper's answer: its reason, or helper_failed for anything that isn't its one JSON line.
  for (const [stdout, want] of [['{"resumed":false,"reason":"lease_not_live","lowered":false}\n', { resumed: false, reason: "lease_not_live" }],
    ['{"resumed":false,"reason":"anything","lowered":false}\n', { resumed: false, reason: "helper_failed" }],
    ["", { resumed: false, reason: "helper_failed" }], ["x", { resumed: false, reason: "helper_failed" }], ["null", { resumed: false, reason: "helper_failed" }],
    ['{"resumed":"yes"}', { resumed: false, reason: "helper_failed" }]]) {
    const t = supervisor({ run: async () => ({ code: 3, stdout }) });
    assert.deepEqual(await requestResume(A, t.opts), want, stdout);
  }
  // Resumed, but the start couldn't be queued: the person is told (never reported as a plain success).
  const sf = supervisor({ run: async () => ({ code: 0, stdout: '{"resumed":true,"reason":"start_failed","lowered":true}\n' }) });
  assert.deepEqual(await requestResume(A, sf.opts), { resumed: true, reason: "start_failed" });
  const odd = supervisor({ run: async () => ({ code: 0, stdout: '{"resumed":true,"reason":"anything","lowered":true}\n' }) });
  assert.deepEqual(await requestResume(A, odd.opts), { resumed: true, reason: null });
  // ... and "start_failed" with resumed false is no answer the helper gives: helper_failed.
  const neg = supervisor({ run: async () => ({ code: 3, stdout: '{"resumed":false,"reason":"start_failed","lowered":false}\n' }) });
  assert.deepEqual(await requestResume(A, neg.opts), { resumed: false, reason: "helper_failed" });
});

test("the helper's happy path: under the EXCLUSIVE lock, restore lowered durably, then the unit's start queued", async () => {
  const w = await world();
  let atChecks = null;
  const r = await w.resume({ ...w.deps, barrier: async (n) => { if (n === "after_checks") atChecks = [w.locks.count(w.lockPath), existsSync(join(w.e.dir, `${A}.lock.pid`))]; } });
  assert.deepEqual(r, { resumed: true, reason: null, lowered: true });
  assert.equal(w.restoreUp(), false, "restore lowered");
  assert.deepEqual(w.fences(), [], "no other fence touched (lease stays down, nothing raised)");
  assert.deepEqual(atChecks, [1, true], "every check under the lock, its pid written");
  assert.deepEqual(w.locks.takes.map((t) => t.shared), [false], "the activation lock, exclusive");
  assert.equal(w.locks.count(w.lockPath), 0, "released");
  assert.equal(existsSync(join(w.e.dir, `${A}.lock.pid`)), false);
  assert.deepEqual(w.sys.calls.filter((c) => c[0] === "start"), [["start", `sagebrush-agent-${A}.service`]]);
  // A start that fails after the durable lowering: reported, the fence stays down (the lease alone gates now).
  const f = await world();
  f.sys.start = async () => { throw new Error("systemctl failed"); };
  assert.deepEqual(await f.resume(), { resumed: true, reason: "start_failed", lowered: true });
  assert.equal(f.restoreUp(), false);
});

test("the helper refuses, lowering nothing and changing no fence", async () => {
  const cases = [
    ["outside_slice", (w) => { w.sys.self = "/system.slice/sagebrush.service"; }],
    ["outside_slice", (w) => { w.sys.self = `/sagebrush.slice/sagebrush-agents.slice/sagebrush-agents-${A}.slice/sagebrush-lease-activate-${A}.scope`; }],
    ["busy", async (w) => { await w.locks.lock(w.lockPath, { shared: true }); }], // even a shared holder: the helper takes it exclusive
    ["not_validated", () => ({ restoreState: () => "published" })],
    ["not_validated", () => ({ restoreState: () => { throw new FleetError("not_granted", "another restore"); } })],
    ["no_record", (w) => { writeFileSync(join(w.e.dir, A), "not json"); }],
    ["not_this_lease", () => ({}), { leaseId: "OTHER" }],
    ["not_this_lease", () => ({}), { lg: 2 }],
    ["not_this_lease", () => ({}), { gen: 6 }], // a newer entry_gen than the lease's
    ["not_this_lease", (w) => { w.withGen(4); }], // the published lease is for another gen
    ["no_record", (w) => { writeFileSync(join(w.e.dir, A), JSON.stringify({ lease_id: "L", lg: 1, expiry_tick: w.rec.expiry_tick })); }], // the old three-key record: refused
    ["lease_not_live", (w) => { writeFileSync(join(w.e.dir, `${A}.spent`), "1\n"); }],
    ["lease_not_live", (w) => { w.c.advance(600_000 - 30_000); }],
    ["lease_not_live", (w) => { w.sys.timers[watchdogTimer(A, 1)].sub = "elapsed"; }],
    ["lease_raised", (w) => { raiseLeaseFence(A, { fenceDir: w.e.leaseFenceDir }); }],
  ];
  for (const [reason, spoil, args = {}] of cases) {
    const w = await world();
    const deps = (await spoil(w)) ?? {};
    const before = w.fences();
    const r = await w.resume({ ...w.deps, ...deps }, args.gen ?? 5, args.leaseId ?? "L", args.lg ?? 1);
    assert.deepEqual(r, { resumed: false, reason, lowered: false }, `${reason} ${JSON.stringify(args)}`);
    assert.ok(REASONS.includes(reason));
    assert.equal(w.restoreUp(), true, `${reason}: restore stays raised`);
    assert.deepEqual(w.fences(), before, `${reason}: no fence changed`);
    assert.ok(!w.sys.calls.some((c) => c[0] === "start"), `${reason}: nothing started`);
    if (reason !== "busy") assert.equal(w.locks.count(w.lockPath), 0, `${reason}: the lock released`);
  }
  // Order: still validated is checked before the lease.
  const w = await world();
  writeFileSync(join(w.e.dir, `${A}.spent`), "1\n");
  assert.equal((await w.resume({ ...w.deps, restoreState: () => "staged" })).reason, "not_validated");
  // Bad arguments throw before anything.
  for (const [gen, leaseId, lg] of [[0, "L", 1], [5, "a b", 1], [5, "L", 0], ["5", "L", 1], [5, "L", "1"]]) {
    await assert.rejects(resumeRestored(A, gen, leaseId, lg, w.deps), (e) => e.code === "bad_form");
  }
  // The real lowerFence check: without the scope (this test process's own cgroup), the lowering itself refuses.
  const x = await world();
  const { cgroupOf: _c, ...noSeam } = x.deps;
  await assert.rejects(x.resume(noSeam), (e) => e.code === "not_granted");
  assert.equal(x.restoreUp(), true);
  assert.equal(x.locks.count(x.lockPath), 0, "released even then");
});

test("after resume, the lease alone gates: an expiry raises lease and restore stays down; a restart before the lease waits", async () => {
  const w = await world();
  assert.equal((await w.resume()).resumed, true);
  await leaseExpire(A, "L", 1, { dir: w.e.dir, fenceDir: w.e.leaseFenceDir, sys: w.sys, lock: w.locks.lock, cgroupOf: () => w.e.slice, wait: async () => {}, clock: w.c });
  assert.equal(existsSync(join(w.e.leaseFenceDir, A)), true, "lease raised by the watchdog");
  assert.equal(w.restoreUp(), false, "restore stays down");
  // A supervisor restart (or a reboot) between the lease and the resume: no in-memory lease, so nothing runs.
  const s = supervisor({ liveLease: () => null });
  assert.deepEqual(await requestResume(A, s.opts), { resumed: false, reason: "waiting_for_lease" });
  assert.ok(!s.kinds().includes("run"));
});

test("S2, the deadline at the seam: the watchdog expires while the helper holds the lock; no turn is admitted", async () => {
  for (const seam of ["after_lock", "after_checks", "after_lower", "after_start"]) {
    const w = await world();
    const wd = () => leaseExpire(A, "L", 1, { dir: w.e.dir, fenceDir: w.e.leaseFenceDir, sys: w.sys, lock: w.locks.lock, cgroupOf: () => w.e.slice, wait: async () => {}, clock: w.c, maxLockRetries: 5 });
    const barrier = async (n) => {
      if (n !== seam) return;
      await wd(); // the helper holds the lock: the watchdog raises lease, masks, kills the slice (the helper with it)
      if (w.sys.killed) throw new Error("killed with the slice");
    };
    w.locks.nextKillable = true; // the helper runs inside the slice
    await w.resume({ ...w.deps, barrier }).catch(() => {});
    assert.equal(existsSync(join(w.e.leaseFenceDir, A)), true, `${seam}: lease is up`);
    assert.equal(w.sys.masked, true, `${seam}: masked`);
    assert.equal(readTombstone(A, { dir: w.e.dir }), 1, `${seam}: tombstoned`);
    // If restore's unlink wasn't yet durable, restore stays raised; if it was, it may stay down, because lease is up.
    assert.equal(w.restoreUp(), seam === "after_lock" || seam === "after_checks", seam);
    // A resume after the commit refuses (the lease is spent), whatever restore's state.
    w.sys.killed = false;
    if (w.restoreUp()) assert.equal((await w.resume()).reason, "lease_not_live", seam);
  }
});

test("the supervisor with the REAL verifiers (the shared vectors): accepted once and recorded, a retry passes, a bad receipt refuses", async () => {
  const { readFileSync } = await import("node:fs");
  const core = await import("../lib/fleet/index.mjs");
  const F = JSON.parse(readFileSync(new URL("./fixtures/fleet-fixtures.json", import.meta.url), "utf8"));
  const X = F.transfers;
  const enc = (s) => new TextEncoder().encode(s);
  const ctx = { aud: F.aud, fleet: F.ids.fleet };
  const chain = await core.replayChain(X.chain.map(enc), ctx);
  const removed = await core.replayChain(X.chain_removed.map(enc), ctx);
  const byName = (n) => X.receipts.find((c) => c.name === n);
  const honest = byName("a transfer and its receipt");
  const t = JSON.parse(honest.transfer).body;
  // This host's records, as the grant path keeps them: the grant at gen listing the agent, listed since gen, no
  // transfer accepted yet; recordTransfer writes the accepted pair and its nonce (what checkTransferForHost reads).
  const accepted = {}, nonces = {}, recorded = [];
  const host = {
    id: t.to_host, fingerprint: t.to_host_key,
    grantHashAt: (g) => (g === t.gen ? t.grant : null),
    grantListsAgent: (g, a) => g === t.gen && a === t.agent,
    listedSince: (a) => (a === t.agent ? t.gen : null),
    entryGen: (a) => (a === t.agent ? t.gen : null),
    acceptedTransfer: (a) => accepted[a] ?? null,
    nonceSeen: (n) => nonces[n] ?? null,
    recordTransfer: (a, rec) => { recorded.push([a, rec]); accepted[a] = rec; nonces[rec.nonce] = rec.transfer; },
  };
  const runs = [];
  const opts = (pairSrc, chainState = chain) => ({
    restoreState: () => "validated", tagsOf: () => [],
    pairOf: () => ({ transfer: enc(pairSrc.transfer), receipt: enc(pairSrc.receipt) }),
    verifyTransferReceipt: core.verifyTransferReceipt, checkTransferForHost: core.checkTransferForHost,
    verifyCtx: { ...ctx, chain: chainState }, host,
    liveLease: () => ({ gen: t.gen, lease_id: "L", lg: 1 }),
    run: async (argv) => { runs.push(argv); return { stdout: '{"resumed":true,"reason":null,"lowered":true}\n' }; },
  });
  // The first resume accepts the pair: recorded (by its hash, gen and nonce) before the launch.
  assert.deepEqual(await requestResume(t.agent, opts(honest)), { resumed: true, reason: null });
  assert.equal(recorded.length, 1);
  assert.deepEqual(recorded[0][1], { gen: t.gen, nonce: t.nonce, transfer: recorded[0][1].transfer });
  assert.match(recorded[0][1].transfer, /^[A-Za-z0-9_-]{43}$/);
  // A retry of the same pair passes again (first: false), recording nothing more.
  assert.deepEqual(await requestResume(t.agent, opts(honest)), { resumed: true, reason: null });
  assert.equal(recorded.length, 1);
  assert.equal(runs.length, 2);
  // The honest pair, but a resume requested for ANOTHER agent: refused, nothing recorded or launched.
  const other = newId();
  const fresh = { ...opts(honest) };
  const recBefore = recorded.length, runsBefore = runs.length;
  delete accepted[t.agent]; // (as if not yet accepted: a swapped request must not accept it either)
  assert.deepEqual(await requestResume(other, fresh), { resumed: false, reason: "receipt", code: "not_granted" });
  assert.equal(recorded.length, recBefore);
  assert.equal(runs.length, runsBefore);
  accepted[t.agent] = recorded[0][1];
  // Refusing vectors: the verifier's own codes, nothing recorded or launched.
  for (const [name, code, st] of [["a receipt for another audience", "bad_audience"], ["the old key at the new key's chain_seq", "bad_signature"],
    ["the receipt's gen differs, both signatures valid", "bad_form"], ["a transfer whose signer was removed at the pinned head", "device_removed", removed]]) {
    const c = byName(name);
    assert.ok(c, name);
    const r = await requestResume(t.agent, opts(c, st ?? chain));
    assert.deepEqual(r, { resumed: false, reason: "receipt", code }, name);
  }
  assert.equal(recorded.length, 1);
  assert.equal(runs.length, 2);
});

test("the supervisor with the REAL liveLease: a published, live record for the current entry_gen resumes; anything else waits or refuses", async () => {
  // The lease module's own reader over a real published record, with a fake systemd (the watchdog timer) and clock.
  const real = ({ rec, timer = { active: "active", sub: "waiting", next: 9e15 }, spent = null }) => {
    const dir = mkdtempSync(join(tmpdir(), "sb-resume-live-"));
    const timers = {};
    if (rec !== null) { writeRecord(A, rec, { dir }); timers[watchdogTimer(A, rec.lg)] = timer; }
    if (spent !== null) writeFileSync(join(dir, `${A}.spent`), `${spent}\n`);
    const sys = { timer: async (unit) => { if (!(unit in timers)) throw new Error("no such unit"); return timers[unit]; } };
    const clock = { boot: () => 1_000_000, mono: () => 5_000_000_000 };
    return (a) => liveLease(a, { dir, sys, clock });
  };
  const rec = (gen) => ({ lease_id: "L7", lg: 3, expiry_tick: 1_000_000 + 600_000, gen, sg: 0 });
  // Live, gen = entry_gen (5): the helper is launched with the record's lease_id, lg and gen.
  const ok = supervisor({ liveLease: real({ rec: rec(5) }), checkTransferForHost: () => ({ first: true }) });
  assert.deepEqual(await requestResume(A, ok.opts), { resumed: true, reason: null });
  assert.deepEqual(ok.kinds().slice(-2), ["recordTransfer", "run"]);
  const argv = ok.log.find((l) => l[0] === "run")[1];
  assert.deepEqual(argv.slice(-5), [A, "5", "L7", "3", T1]);
  // Anything else launches and records nothing.
  const cases = [
    ["not_this_lease", { rec: rec(4) }],
    ["waiting_for_lease", { rec: null }],
    ["waiting_for_lease", { rec: rec(5), spent: 3 }],
    ["waiting_for_lease", { rec: rec(5), timer: { active: "active", sub: "elapsed", next: 9e15 } }],
    ["waiting_for_lease", { rec: { ...rec(5), expiry_tick: 1_000_000 } }],
  ];
  for (const [reason, w] of cases) {
    const s = supervisor({ liveLease: real(w), checkTransferForHost: () => ({ first: true }) });
    assert.deepEqual(await requestResume(A, s.opts), { resumed: false, reason }, JSON.stringify(w));
    assert.ok(!s.kinds().includes("recordTransfer") && !s.kinds().includes("run"), reason);
  }
});

// ---- SR1 (restore owner on S1): a lease from another suspend-gate generation never resumes a restored agent

const gateWrite = (dir, sleep, reopen) => {
  for (const [name, text] of [["sleep", sleep], ["reopen", reopen]]) {
    const f = join(dir, name);
    if (existsSync(f)) unlinkSync(f);
    if (text !== null) writeFileSync(f, text, { mode: 0o644 });
  }
};
const S = (gen, phase = "post") => JSON.stringify({ gen, phase, pre_ok: true, pre_at: 0 });
const R = (gen) => JSON.stringify({ gen });

test("C7' (ii): the helper refuses a lease from another gate generation, and while the gate is closed: lease_not_live, restore raised, the record byte-identical", async () => {
  const w = await world();
  gateWrite(w.e.dir, S(1), R(1));
  writeRecord(A, { ...w.rec, sg: 1 }, { dir: w.e.dir }); // the lease, published under gate (1, 1)
  const before = readFileSync(join(w.e.dir, A));
  assert.deepEqual(await w.resume(), { resumed: true, reason: null, lowered: true }, "open at its generation: resumes (the control)");
  // Again, from the start, for the two refusals.
  for (const [label, sleep, reopen] of [["the gate moved to (2, 2)", S(2), R(2)], ["the gate closed (pre at 2)", S(2, "pre"), R(1)]]) {
    const v = await world();
    gateWrite(v.e.dir, S(1), R(1));
    writeRecord(A, { ...v.rec, sg: 1 }, { dir: v.e.dir });
    const rec = readFileSync(join(v.e.dir, A));
    gateWrite(v.e.dir, sleep, reopen);
    assert.deepEqual(await v.resume(), { resumed: false, reason: "lease_not_live", lowered: false }, label);
    assert.equal(v.restoreUp(), true, `${label}: restore still raised`);
    assert.deepEqual(readFileSync(join(v.e.dir, A)), rec, `${label}: the record byte-identical`);
  }
  assert.ok(before.length > 0);
});

test("C7' (i): requestResume with the REAL liveLease over a closed gate, or one open at another generation, launches and records nothing", async () => {
  const dirFor = (sleep, reopen, sg) => {
    const dir = mkdtempSync(join(tmpdir(), "sb-resume-gate-"));
    writeRecord(A, { lease_id: "L7", lg: 3, expiry_tick: 1_000_000 + 600_000, gen: 5, sg }, { dir });
    gateWrite(dir, sleep, reopen);
    const timers = { [watchdogTimer(A, 3)]: { active: "active", sub: "waiting", next: 9e15 } };
    const sys = { timer: async (unit) => timers[unit] };
    return (a) => liveLease(a, { dir, sys, clock: { boot: () => 1_000_000, mono: () => 5_000_000_000 } });
  };
  const open = supervisor({ liveLease: dirFor(S(2), R(2), 2), checkTransferForHost: () => ({ first: true }) });
  assert.deepEqual(await requestResume(A, open.opts), { resumed: true, reason: null }, "open at its generation (the control)");
  for (const [label, live] of [["closed (pre)", dirFor(S(3, "pre"), R(2), 2)], ["open at another generation", dirFor(S(3), R(3), 2)], ["no gate files, lease at sg 2", dirFor(null, null, 2)]]) {
    const s = supervisor({ liveLease: live, checkTransferForHost: () => ({ first: true }) });
    assert.deepEqual(await requestResume(A, s.opts), { resumed: false, reason: "waiting_for_lease" }, label);
    assert.ok(!s.kinds().includes("recordTransfer") && !s.kinds().includes("run"), `${label}: nothing launched or recorded`);
  }
});

// ---- C7 (restore owner on lease-on r1.1/r1.5): the system-sleep hook against a REAL resume helper held at each seam

test("C7: PRE with the real resume helper held at after_lock, after_checks and after_lower: killed with the slice, the lease spent, nothing started", async () => {
  const { leaseSleep, reopenAfterSleep } = await import("../lib/fleet/host/lease.mjs");
  for (const seam of ["after_lock", "after_checks", "after_lower"]) {
    const w = await world();
    const before = readFileSync(join(w.e.dir, A));
    let reached = false;
    w.locks.nextKillable = true; // the helper runs in its scope inside the slice: killed with it
    const helper = w.resume({ ...w.deps, barrier: async (n) => { if (n === seam) { reached = true; await new Promise(() => {}); } } });
    helper.catch(() => {});
    // (lowering restore takes the real fence lock: a real-time wait, bounded at 5 s)
    for (let i = 0; i < 500 && !reached; i++) await new Promise((r) => setTimeout(r, 10));
    assert.ok(reached, `${seam}: the helper is held`);
    const cg = mkdtempSync(join(tmpdir(), "sb-c7-cg-")), units = mkdtempSync(join(tmpdir(), "sb-c7-units-"));
    writeFileSync(join(units, `sagebrush-agent-${A}.service`), "");
    const ss = { calls: [], freeze: "0", procs: 1, cgroup: (d) => (d === cg ? d : null),
      kill: () => { ss.calls.push("kill"); w.locks.killSliceHolders(); ss.procs = 0; }, empty: () => ss.procs === 0,
      freezeRead: () => ss.freeze, freezeWrite: (_d, v) => { ss.freeze = v; }, maskAll: async () => { ss.calls.push("mask"); } };
    const o = { dir: w.e.dir, fenceDir: w.e.leaseFenceDir, unitDir: units, agentsCgroup: cg, sys: ss, lock: w.locks.lock, clock: w.c,
      log: () => {}, now: (() => { let x = 0; return () => (x += 100); })(), wait: async () => {} };
    const r = await leaseSleep("pre", o);
    assert.equal(r.ok, true, seam);
    assert.ok(readTombstone(A, { dir: w.e.dir }) >= w.rec.lg, `${seam}: the lease spent`);
    assert.ok(existsSync(join(w.e.leaseFenceDir, A)), `${seam}: lease raised`);
    assert.ok(ss.calls.includes("mask"), `${seam}: masked`);
    assert.deepEqual(readFileSync(join(w.e.dir, A)), before, `${seam}: the record byte-identical`);
    assert.equal(w.restoreUp(), seam !== "after_lower", `${seam}: restore ${seam === "after_lower" ? "already lowered by the held helper" : "still raised"}`);
    assert.ok(!w.sys.calls.some((c) => c[0] === "start"), `${seam}: nothing started`);
    if (seam !== "after_lock") continue;
    // The old lease never passes again; a FRESH lease after the reopen resumes (the positive control).
    await leaseSleep("post", o);
    assert.deepEqual(await reopenAfterSleep(o), { acted: true, ok: true, gen: 1 });
    const old = await w.resume(w.deps);
    assert.deepEqual(old, { resumed: false, reason: "lease_not_live", lowered: false }, "the pre-suspend lease refuses first (spent, and another gate generation)");
    const fresh = { lease_id: "L2", lg: 2, expiry_tick: w.c.boot() + 600_000, gen: 5, sg: 1 };
    await armWatchdog(A, fresh, { sys: w.sys, clock: w.c });
    assert.equal(await publish(A, fresh, { dir: w.e.dir, sys: w.sys, clock: w.c, lock: w.locks.lock }), true);
    unlinkSync(join(w.e.leaseFenceDir, A)); // as the fresh lease's activation helper lowers it
    assert.deepEqual(await w.resume(w.deps, 5, "L2", 2), { resumed: true, reason: null, lowered: true });
    // and the pre-suspend lease, presented directly, refuses
    const w2 = await world();
    writeFileSync(join(w2.e.dir, "sleep"), JSON.stringify({ gen: 1, phase: "post", pre_ok: true, pre_at: 0 }), { mode: 0o644 });
    writeFileSync(join(w2.e.dir, "reopen"), JSON.stringify({ gen: 1 }), { mode: 0o644 });
    assert.deepEqual(await w2.resume(), { resumed: false, reason: "lease_not_live", lowered: false });
  }
});
