// Backup r3.3 §5 step 11, the first-lease rule r2.1, schemas r2.4 §3.7.3: the restore resume. The supervisor checks
// what only it can read (validated, the transfer receipt over the host records, recording a pair new here before
// anything is launched, the live lease for the current entry_gen) and launches the helper; the helper, inside the
// agent's slice under the exclusive activation lock, re-checks what can change (validated, the published lease is the
// argv's and live, its gen, `lease` down), lowers `restore` and queues the start. Every other case refuses with its
// reason and changes no fence. Against a fake systemd, clock and lock (as the lease's own tests), and fakes for the
// shared core's verifiers and the supervisor's host records.
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "./host-linux-only.mjs";
import { FleetError, newId } from "../lib/fleet/index.mjs";
import { armWatchdog, leaseExpire, publish, raiseLeaseFence, readTombstone, watchdogTimer } from "../lib/fleet/host/lease.mjs";
import { raiseFence } from "../lib/fleet/host/fence.mjs";
import { REASONS, requestResume, resumeArgv, resumeCgroup, resumeRestored } from "../lib/fleet/host/restore-resume.mjs";
import { readRecord } from "../lib/fleet/host/lease.mjs";
import { restoreResumeScope } from "../lib/fleet/host/names.mjs";

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
 * published, `lease` down and `restore` up: the helper's world. The published record carries `gen` as lease part 2
 * will publish it (readLease adds it; lease.mjs's own readRecord doesn't know it yet). `over` replaces any option.
 */
async function world(over = {}) {
  const root = mkdtempSync(join(tmpdir(), "sb-resume-"));
  const e = { root, dir: join(root, "run"), fenceDir: join(root, "fence"), leaseFenceDir: join(root, "fence", "lease"), slice: join(root, "cg") };
  const c = fakeClock(), locks = fakeLocks(), sys = fakeSys(e, { locks });
  const rec = { lease_id: "L", lg: 1, expiry_tick: c.boot() + 600_000 };
  await armWatchdog(A, rec, { sys, clock: c });
  assert.equal(await publish(A, rec, { dir: e.dir, sys, clock: c }), true);
  raiseFence("restore", A, { dir: e.fenceDir });
  const withGen = (g) => (a, o) => { const r = readRecord(a, o); return r.state === "ok" ? { state: "ok", rec: { ...r.rec, gen: g } } : r; };
  const deps = {
    restoreState: () => "validated",
    dir: e.dir, fenceDir: e.fenceDir, leaseFenceDir: e.leaseFenceDir, sys, clock: c, lock: locks.lock,
    readLease: withGen(5), cgroupOf: () => resumeCgroup(A), pid: 4242,
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
    liveLease: (a) => { log.push(["live", a]); return { gen: 5, lease_id: "L", lg: 1 }; },
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
    ["waiting_for_lease", { liveLease: () => null }],
    ["waiting_for_lease", { liveLease: undefined }],
    ["not_this_lease", { liveLease: () => ({ gen: 4, lease_id: "L", lg: 1 }) }],
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
    ["not_this_lease", (w) => ({ readLease: w.withGen(4) })],
    ["not_this_lease", () => ({ readLease: readRecord })], // lease.mjs's record has no gen until part 2: fails closed
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
