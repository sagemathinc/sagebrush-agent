// Host supervisor (execution lease r3.12 §2, §3, §3.1; lease wire type r3 §2.4): the renewal state machine in the
// executor's queue, against a fake systemd (timers, units), a fake clock on CLOCK_BOOTTIME and a fake service, with the
// real lease primitives (lease.mjs: arm, publish, the activation helper's code, the record, the tombstone) and real
// fence files. One row runs the REAL verifier (core verifyExecutionLease) on leases the test signs with the fixtures'
// lease key. The rows that need the real systemd (§5 "without the supervisor", T2a-T2g, suspend) are listed at the end,
// deferred to the qualification VM.
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "./host-linux-only.mjs";
import { FleetError, keyFromSeed, newId, sha256b64 } from "../lib/fleet/index.mjs";
import * as core from "../lib/fleet/core/index.mjs";
import { Supervisor } from "../lib/fleet/host/executor.mjs";
import { fenceCauses, fenced, holdsFenceLock, raiseFence } from "../lib/fleet/host/fence.mjs";
import { HostStore } from "../lib/fleet/host/host-store.mjs";
import { MARGIN_MS, helperScope, leaseActivate, leaseThaw, readGate, readRecord, readTombstone, thawScope, watchdogTimer } from "../lib/fleet/host/lease.mjs";
import { readRecord as readRestore, writeRecord as writeRestore } from "../lib/fleet/host/restore-record.mjs";
import { RESUME_HELPER_MS, requestResume, resumeCgroup, resumeRestored } from "../lib/fleet/host/restore-resume.mjs";
import { IGNORED, LeaseMachine, MAX_TTL_MS, RENEW_MS } from "../lib/fleet/host/lease-machine.mjs";
import { agentSlice } from "../lib/fleet/host/names.mjs";

const tmp = (n) => mkdtempSync(join(tmpdir(), `sb-lm-${n}-`));
const A = newId(), B = newId();
const BOOT_ID = "0f6c2b5e-8d3a-4c1e-9b7f-2a4d6e8f0a1c";

// ---- grants, as in the executor's tests: JSON bytes, `verify` standing in for the §3.2 check
const bytesOf = (body) => Buffer.from(JSON.stringify(body));
const grantVerify = (bytes) => { const body = JSON.parse(String(bytes)); return { body, digest: sha256b64(bytes), hash: sha256b64(Buffer.concat([Buffer.from("signed:"), bytes])) }; };
const bodyOf = (bytes) => JSON.parse(String(bytes));
const entry = (agent, x = 1) => ({ agent, tags: [], config: { x } });
const grant = (gen, agents) => bytesOf({ gen, agents });

/** Agent ids out of unit names: sagebrush-agent-<id>.service, sagebrush-agents-<id>.slice. */
const idOf = (unit) => /^sagebrush-agents?-([a-z2-7]{26})\.(service|slice)$/.exec(unit)?.[1] ?? null;

/** The executor's effects (units by agent id) with systemd's fence condition: a start of a fenced unit is skipped. */
function fakeFx(fenceDir) {
  const units = {}, log = [], audits = [];
  const u = (id) => (units[id] ??= { active: false, masked: false });
  const fx = {
    units, log, audits, u,
    appendIntent: async (r) => { log.push(["intent", r.kind ?? r.op]); },
    audit: (r) => { audits.push(r); },
    brokerGen: async () => {}, brokerRevoke: async () => {},
    stopUnit: async (id) => { log.push(["stop", id]); u(id).active = false; u(id).frozen = false; },
    freeze: async (id) => { log.push(["freeze", id]); u(id).frozen = true; },
    thaw: async (id) => { if (!u(id).frozen || !u(id).active) throw new Error("not frozen"); log.push(["thaw", id]); u(id).frozen = false; },
    procCount: async (id) => (u(id).active ? 1 : 0),
    mask: async (id) => { log.push(["mask", id]); u(id).masked = true; },
    unmask: async (id) => { log.push(["unmask", id]); u(id).masked = false; },
    provision: async () => {}, writeUnit: async () => {}, daemonReload: async () => {},
    systemdVersion: async () => "systemd 255 (255.4-1ubuntu8.19)\n",
    start: async (id) => { log.push(["start", id]); if (u(id).masked) throw new Error("masked"); if (!fenced(id, { dir: fenceDir })) u(id).active = true; },
    isActive: async (id) => u(id).active,
    publishMap: async () => {}, sendAck: async () => {},
    sys: {
      stop: (unit) => { log.push(["sys-stop", unit]); for (const [id, s] of Object.entries(units)) if (unit === "sagebrush-agents.slice" || idOf(unit) === id) { if (!s.stuck) { s.active = false; s.frozen = false; } } },
      jobs: () => [], cancel: () => {}, rootUnits: () => [],
      activeAgentUnits: () => Object.entries(units).filter(([, s]) => s.active).map(([id]) => `sagebrush-agent-${id}.service`),
      procCount: (unit) => Object.entries(units).filter(([id, s]) => s.active && (unit === "sagebrush-agents.slice" || idOf(unit) === id)).length,
    },
  };
  return fx;
}

/**
 * One host: a HostStore, the executor, a LeaseMachine and its fakes.
 * - clock: CLOCK_BOOTTIME `w.b` ms, CLOCK_MONOTONIC in µs moving with it.
 * - lsys: the lease's systemd: arm (from systemd-run's argv) makes a waiting timer at its OnBootSec point, which reads
 *   back elapsed once the monotonic clock passes it; disarm stops it.
 * - the activation helper runs lease.mjs's leaseActivate in process (its scope faked), against the same files.
 * - timers: fake; `fire(kind)` runs the due ones ("expiry": the lease timers, "renew": the cadence).
 * - the service: `respond(reqBytes, over)` answers a request as the service would; `send` defaults to it.
 */
async function world({ verifier = "fake", root = tmp("state"), fenceDir = tmp("fence"), leaseDir = tmp("lease"), restoreDir = tmp("restore"), b = 1_000_000, resumeOp = null, sleepOpts = null } = {}) {
  const w = { b, fenceDir, leaseDir, restoreDir, root, helperRuns: [], sent: [], pending: [] };
  const clock = { boot: () => w.b, mono: () => w.b * 1000 + 7_000_000_000 };
  w.clock = clock;
  w.advance = (ms) => { w.b += ms; };
  const timers = {}, lsysLog = [];
  w.timers = timers; w.lsysLog = lsysLog;
  const lsys = {
    arm: async (argv) => {
      if (w.armFail) throw new Error("systemd-run failed");
      const unit = argv.find((a) => a.startsWith("--unit=")).slice(7);
      const at = Number(argv.find((a) => a.startsWith("--on-boot=")).slice(10, -2));
      timers[`${unit}.timer`] = { active: "active", sub: "waiting", next: w.armLate ? at + 1 : at };
      lsysLog.push(["arm", unit]);
    },
    timer: async (unit) => {
      if (!(unit in timers)) throw new Error("no such unit");
      const t = timers[unit];
      return t.sub === "waiting" && clock.mono() >= t.next ? { ...t, sub: "elapsed" } : { ...t };
    },
    disarm: async (unit) => { lsysLog.push(["disarm", unit]); timers[unit] = { active: "inactive", sub: "dead", next: 0 }; },
  };
  w.lsys = lsys;
  const fx = fakeFx(fenceDir);
  w.fx = fx;
  // The helper: lease.mjs's own leaseActivate, run as its scope would be, its unmask and start through the executor's
  // fake units. `w.helperCode` overrides its exit; `w.helperHook` runs first.
  const run = async (argv) => {
    const cmd = argv.find((a) => a === "lease-activate" || a === "lease-thaw");
    const [agent, leaseId, lg] = argv.slice(argv.indexOf(cmd) + 1);
    w.helperRuns.push({ cmd, agent, leaseId, lg: Number(lg), underFenceLock: holdsFenceLock(), slice: argv.find((a) => a.startsWith("--slice=")) });
    if (w.helperHook) await w.helperHook(agent, cmd);
    if (w.helperCode !== undefined) return { code: w.helperCode, stdout: "" };
    const hsys = {
      ...lsys,
      selfCgroup: () => `/sagebrush.slice/sagebrush-agents.slice/${agentSlice(agent)}/${cmd === "lease-thaw" ? thawScope(agent) : helperScope(agent)}`,
      thaw: async (unit) => fx.thaw(idOf(unit)),
      unmask: async (unit) => fx.unmask(idOf(unit)),
      // systemctl start --no-block: systemd skips it while any fence file of the unit's conditions exists.
      start: async (unit) => { const id = idOf(unit); fx.log.push(["helper-start", id]); if (!fx.u(id).masked && !fenced(id, { dir: fenceDir })) fx.u(id).active = true; },
    };
    const opts = { dir: leaseDir, fenceDir: join(fenceDir, "lease"), sys: hsys, clock };
    const r = cmd === "lease-thaw" ? await leaseThaw(agent, leaseId, Number(lg), opts) : await leaseActivate(agent, leaseId, Number(lg), opts);
    w.helperRuns.at(-1).result = r;
    return { code: (r.activated ?? r.thawed) ? 0 : 3, stdout: JSON.stringify(r) };
  };
  const fakeTimers = {
    set: (ms, fn) => { const h = { at: w.b + ms, ms, fn }; w.pending.push(h); return h; },
    clear: (h) => { w.pending = w.pending.filter((x) => x !== h); },
  };
  // Run every pending timer of a kind due by now: "expiry" (a lease timer: its delay isn't 0 or RENEW_MS) or "renew".
  w.fire = async (kind) => {
    const isRenew = (h) => h.ms === 0 || h.ms === RENEW_MS;
    const due = w.pending.filter((h) => (kind === "renew" ? isRenew(h) : !isRenew(h)) && h.at <= w.b);
    w.pending = w.pending.filter((h) => !due.includes(h));
    for (const h of due) await h.fn();
    await w.settle();
  };
  // Let queued work (renewals, ops) run.
  w.settle = async () => { for (let i = 0; i < 50; i++) await new Promise((r) => setImmediate(r)); };

  let sign, verify, ctx, respond;
  if (verifier === "real") ({ sign, verify, ctx, respond } = await realService(w));
  else ({ sign, verify, ctx, respond } = fakeService(w));
  w.respond = respond;
  w.ctx = ctx;
  const store = await HostStore.open(root);
  w.store = store;
  let sup;
  const machine = new LeaseMachine({
    verify, sign, context: () => ctx, submit: (op) => sup.submit(op),
    send: async (bytes) => { w.sent.push(bytes); return w.send ? w.send(bytes) : respond(bytes); },
    dir: leaseDir, sys: lsys, clock, run, timers: fakeTimers, bootId: () => w.bootId ?? BOOT_ID,
    nonce: () => Buffer.from(newId().slice(0, 16)).toString("base64url"), wall: () => 1_800_000_000_000,
  });
  sup = new Supervisor({ store, fx, verify: grantVerify, bodyOf, fenceDir, lease: machine, barrier: async (n, d) => { if (w.barrier) await w.barrier(n, d); },
    restoreState: (id) => readRestore("agent", id, { dir: restoreDir })?.state ?? null, restoreResume: resumeOp ? resumeOp(w) : null,
    ...(sleepOpts ? { sleepOpts: sleepOpts(w) } : {}) });
  Object.assign(w, { sup, machine, close: () => store.close() });
  w.leaseUp = (id) => existsSync(join(fenceDir, "lease", id));
  w.record = (id) => readRecord(id, { dir: leaseDir });
  return w;
}

/**
 * The stand-in service and verifier, mirroring verifyExecutionLease's interface: a "lease" is JSON { sig, body };
 * verify refuses a bad signature, another host or host key, and any echoed field that isn't the outstanding request's
 * (the request by the hash of its SIGNED bytes, which `sign` computes and the envelope never equals).
 */
function fakeService() {
  const ctx = { aud: "https://dev.sagebrush.space", fleet: newId(), chain: {}, host: newId(), hostKey: "K".repeat(43) };
  const signedHash = (body) => sha256b64(Buffer.from(`signed:${JSON.stringify(body)}`));
  const sign = async (body) => ({ bytes: Buffer.from(JSON.stringify(body)), hash: signedHash(body) });
  const verify = async (bytes, c) => {
    const { sig, body } = JSON.parse(String(bytes));
    if (sig !== "ok") throw new FleetError("bad_signature", "signature");
    if (body.host !== c.host || body.host_key !== c.hostKey || body.fleet !== c.fleet || body.aud !== c.aud) throw new FleetError("not_granted", "not this host");
    const o = c.outstanding;
    if (!o || ["request", "agent", "gen", "nonce", "boot_id"].some((k) => body[k] !== o[k])) throw new FleetError("not_granted", "not the outstanding request");
    if (!(body.ttl_ms > 0 && body.ttl_ms <= MAX_TTL_MS)) throw new FleetError("bad_form", "ttl");
    return { body, hash: "h" };
  };
  const respond = (reqBytes, over = {}) => {
    const rq = JSON.parse(String(reqBytes));
    const body = { fleet: rq.fleet, aud: rq.aud, agent: rq.agent, host: rq.host, host_key: ctx.hostKey, gen: rq.gen, lease_id: newId(), ttl_ms: 600_000,
      nonce: rq.nonce, boot_id: rq.boot_id, request: signedHash(rq), chain_seq: 1, ...over };
    return Buffer.from(JSON.stringify({ sig: over.sig ?? "ok", body }));
  };
  return { sign, verify, ctx, respond };
}

/** The real thing: the fixtures' leased chain, host certificate and keys; requests sealed by the host key, leases by the lease key. */
async function realService() {
  const F = JSON.parse(readFileSync(new URL("./fixtures/fleet-fixtures.json", import.meta.url), "utf8"));
  const enc = (s) => new TextEncoder().encode(s);
  const E = F.leases;
  const base = { aud: F.aud, fleet: F.ids.fleet };
  const chain = await core.replayChain(E.chain.map(enc), base);
  const cert = await core.verifyHostCert(enc(E.host_cert), { ...base, chain });
  const H = keyFromSeed(Buffer.from(F.keys.host.seed, "hex"));
  const L2 = keyFromSeed(Buffer.from(F.keys["lease-2"].seed, "hex"));
  const hs = { kind: "host", id: E.host, alg: "ed25519", key: H.key };
  const ok = JSON.parse(E.leases.find((c) => c.expect === "ok").bytes);
  const sign = async (body) => ({ bytes: core.seal("sb.lease-request.v1", hs, body, H), hash: sha256b64(core.signedBytes("sb.lease-request.v1", hs, body)) });
  const ctx = { ...base, chain, host: E.host, hostKey: E.host_key };
  // The service's side, its own way: the request verified against the certificate, its hash as verifyLeaseRequest gives it.
  const respond = async (reqBytes, over = {}) => {
    const { body: rq, hash } = await core.verifyLeaseRequest(reqBytes, { ...base, cert });
    const body = { fleet: rq.fleet, aud: rq.aud, agent: rq.agent, host: rq.host, host_key: E.host_key, gen: rq.gen, lease_id: newId(), ttl_ms: 600_000,
      nonce: rq.nonce, boot_id: rq.boot_id, request: over.envelopeHash ? sha256b64(reqBytes) : hash, chain_seq: ok.body.chain_seq };
    return core.seal("sb.execution-lease.v1", ok.signer, body, L2);
  };
  return { sign, verify: core.verifyExecutionLease, ctx, respond, agent: F.ids.agent };
}

/** Recovery, then grant 1 listing `agents`, applied: every agent provisioned and held by its `lease` fence. */
async function granted(w, agents, gen = 1) {
  await w.sup.recover();
  const r = await w.sup.submit({ kind: "grant", bytes: grant(gen, agents.map((a) => entry(a))) });
  assert.equal(r.status, "applied", JSON.stringify(r));
  return r;
}

// ---- the first lease

test("nothing of a granted agent starts before its first lease; the first accepted lease arms, publishes, then the helper lowers lease and it starts", async () => {
  const w = await world();
  await granted(w, [A]);
  assert.equal(w.leaseUp(A), true, "lease raised in the grant's op");
  assert.equal(w.fx.u(A).active, false);
  assert.ok(!w.fx.log.some((l) => l[0] === "start"), "no start effect at all");
  assert.equal(w.record(A).state, "missing");
  // The grant's start step found no lease and asked for one: the renewal runs.
  await w.fire("renew");
  assert.equal(w.sent.length, 1);
  const rq = JSON.parse(String(w.sent[0]));
  assert.deepEqual(Object.keys(rq).sort(), ["agent", "at_ms", "aud", "boot_id", "fleet", "gen", "host", "nonce"]);
  assert.equal(rq.gen, w.store.grants.record(A).entry_gen);
  const rec = w.record(A);
  assert.equal(rec.state, "ok");
  assert.equal(rec.rec.gen, 1);
  assert.equal(rec.rec.expiry_tick, 1_000_000 + 600_000, "from the tick it was SENT at");
  assert.deepEqual(w.lsysLog.map((l) => l[0]), ["arm"]);
  assert.equal(w.helperRuns.length, 1);
  assert.equal(w.helperRuns[0].underFenceLock, false, "the helper never runs under the fence lock");
  assert.equal(w.helperRuns[0].slice, `--slice=${agentSlice(A)}`);
  assert.equal(w.leaseUp(A), false);
  assert.equal(w.fx.u(A).active, true);
  assert.equal(w.store.registry.agent(A).state, "running");
  // The order: arm, then publish, then the helper (whose start precedes the executor's own, idempotent, start).
  assert.deepEqual(w.machine.current(A), { ...rec.rec });
  await w.close();
});

test("the REAL verifier: a lease signed by the lease key for the host's own signed request is accepted; one naming the envelope's hash is not", async () => {
  const w = await world({ verifier: "real" });
  const F = JSON.parse(readFileSync(new URL("./fixtures/fleet-fixtures.json", import.meta.url), "utf8"));
  const X = F.ids.agent;
  await granted(w, [X]);
  await w.fire("renew");
  assert.equal(w.record(X).state, "ok", JSON.stringify(w.machine.counts));
  assert.equal(w.fx.u(X).active, true);
  // The service hashing the envelope instead of the signed bytes (a protocol hash is over the signed bytes): refused.
  const before = w.record(X).rec;
  const bytes = await w.machine.request(X, 1);
  const r = await w.sup.submit({ kind: "lease-response", authority: "host", agent: X, bytes: await w.respond(bytes, { envelopeHash: true }) });
  assert.deepEqual(r, { status: "ignored", reason: "refused" });
  assert.deepEqual(w.record(X).rec, before);
  // The same request answered properly is still accepted: the refused copy didn't void it.
  const ok = await w.sup.submit({ kind: "lease-response", authority: "host", agent: X, bytes: await w.respond(bytes) });
  assert.equal(ok.status, "renewed");
  await w.close();
});

// ---- freshness (§3, §5 T1, SEC H1)

/** A world with A granted and a request outstanding (not answered); returns its bytes. */
async function asked(w, agents = [A]) {
  w.send = async () => null;
  await granted(w, agents);
  await w.fire("renew");
  delete w.send;
  return w.sent.at(-1);
}

test("expired on arrival, at the EFFECTIVE end: sent_tick + ttl - 30 s <= now is ignored before any accept, lower or start", async () => {
  for (const [ttl, after, accepted] of [
    [600_000, 600_000, false], // sent_tick + ttl == now (T1)
    [600_000, 600_001, false], // past it
    [600_000, 600_000 - MARGIN_MS - 10, false], // exactly at the effective end (bootNow rounds up 10 ms)
    [600_000, 600_000 - MARGIN_MS - 11, true], // 1 ms before it
    [MARGIN_MS, 0, false], // a TTL no longer than the margin is dead on arrival
    [60_000, 20_000, true],
  ]) {
    const w = await world();
    const req = await asked(w);
    w.advance(after);
    const r = await w.sup.submit({ kind: "lease-response", authority: "host", agent: A, bytes: w.respond(req, { ttl_ms: ttl }) });
    assert.equal(r.status === "accepted", accepted, `${ttl}/${after}: ${JSON.stringify(r)}`);
    if (!accepted) {
      assert.deepEqual(r, { status: "ignored", reason: "expired" });
      assert.equal(w.record(A).state, "missing");
      assert.equal(w.leaseUp(A), true);
      assert.equal(w.fx.u(A).active, false);
      assert.equal(w.helperRuns.length, 0);
      assert.equal(w.lsysLog.length, 0, "nothing armed");
    } else {
      assert.equal(w.record(A).rec.expiry_tick, 1_000_000 + ttl, "sent_tick + ttl, never the arrival");
    }
    await w.close();
  }
});

test("replayed, superseded, reordered, foreign and malformed responses are ignored and counted; a forged copy never voids the real request", async () => {
  const w = await world();
  const req = await asked(w);
  const resp = (over) => w.sup.submit({ kind: "lease-response", authority: "host", agent: A, bytes: w.respond(req, over) });
  for (const over of [
    { sig: "bad" }, { agent: B }, { host: newId() }, { host_key: "Z".repeat(43) }, { nonce: "AAAAAAAAAAAAAAAAAAAAAA" },
    { boot_id: "11111111-2222-4333-8444-555555555555" }, { gen: 2 }, { request: "x".repeat(43) }, { ttl_ms: 0 }, { ttl_ms: MAX_TTL_MS + 1 },
  ]) assert.deepEqual(await resp(over), { status: "ignored", reason: "refused" }, JSON.stringify(over));
  assert.equal(w.machine.counts.refused, 10);
  assert.ok(w.machine.outstanding(A), "still outstanding");
  const good = w.respond(req);
  assert.equal((await w.sup.submit({ kind: "lease-response", authority: "host", agent: A, bytes: good })).status, "accepted");
  // Replayed: the request was cleared by the acceptance; counted once.
  assert.deepEqual(await w.sup.submit({ kind: "lease-response", authority: "host", agent: A, bytes: good }), { status: "ignored", reason: "no_request" });
  // Superseded: two requests; only the second (outstanding) one's answer counts, whatever the order of arrival.
  const r1 = await w.machine.request(A, 1), r2 = await w.machine.request(A, 1);
  assert.deepEqual(await w.sup.submit({ kind: "lease-response", authority: "host", agent: A, bytes: w.respond(r1) }), { status: "ignored", reason: "refused" });
  assert.equal((await w.sup.submit({ kind: "lease-response", authority: "host", agent: A, bytes: w.respond(r2) })).status, "renewed");
  // A previous boot: the request carries this boot's id, so a lease echoing another boot's is refused by the verifier.
  assert.deepEqual(Object.keys(w.machine.counts).sort(), [...IGNORED, "not_published", "unverified"].sort());
  await w.close();
});

test("a TTL the verifier let through but out of range is still refused here, and the boundary 10 minutes is accepted", async () => {
  const w = await world();
  const req = await asked(w);
  // A verifier that checks nothing about the TTL: the machine's own bound still holds.
  const loose = w.machine.verify;
  w.machine.verify = async (bytes, c) => { const { body } = JSON.parse(String(bytes)); await loose(Buffer.from(JSON.stringify({ sig: "ok", body: { ...body, ttl_ms: 1 } })), c); return { body, hash: "h" }; };
  for (const ttl of [0, -1, MAX_TTL_MS + 1, 1.5]) {
    const bytes = await w.machine.request(A, 1);
    assert.deepEqual(await w.sup.submit({ kind: "lease-response", authority: "host", agent: A, bytes: w.respond(bytes, { ttl_ms: ttl }) }), { status: "ignored", reason: "ttl" }, String(ttl));
  }
  const bytes = await w.machine.request(A, 1);
  assert.equal((await w.sup.submit({ kind: "lease-response", authority: "host", agent: A, bytes: w.respond(bytes, { ttl_ms: MAX_TTL_MS }) })).status, "accepted");
  void req;
  await w.close();
});

// ---- the re-arm (§2.1) and its refusals

test("renewal of a running agent: arm the new watchdog, publish the newer lg, stop the old timer; no helper, the fence stays down", async () => {
  const w = await world();
  await granted(w, [A]);
  await w.fire("renew");
  const first = w.record(A).rec;
  w.advance(RENEW_MS);
  await w.fire("renew");
  const second = w.record(A).rec;
  assert.ok(second.lg > first.lg);
  assert.equal(second.expiry_tick, 1_000_000 + RENEW_MS + 600_000);
  assert.deepEqual(w.lsysLog, [["arm", `sagebrush-lease-${A}-${first.lg}`], ["arm", `sagebrush-lease-${A}-${second.lg}`], ["disarm", watchdogTimer(A, first.lg)]]);
  assert.equal(w.helperRuns.length, 1, "only the first lease needed the helper");
  assert.equal(w.leaseUp(A), false);
  assert.equal(w.fx.u(A).active, true);
  // One lease timer: the old one was cleared.
  assert.equal(w.pending.filter((h) => h.ms !== 0 && h.ms !== RENEW_MS).length, 1);
  await w.close();
});

test("an arming that fails or doesn't verify, or a spent watchdog: nothing published, nothing lowered; a renewal keeps the old lease", async () => {
  for (const fault of ["armFail", "armLate", "spent"]) {
    const w = await world();
    const req = await asked(w);
    if (fault === "spent") writeFileSync(join(w.leaseDir, `${A}.spent`), `${w.machine.lg(A) + 1}\n`);
    else w[fault] = true;
    const r = await w.sup.submit({ kind: "lease-response", authority: "host", agent: A, bytes: w.respond(req) });
    assert.deepEqual(r, { status: "ignored", reason: fault === "spent" ? "not_published" : "unverified" }, fault);
    assert.equal(w.record(A).state, "missing");
    assert.equal(w.leaseUp(A), true);
    assert.equal(w.helperRuns.length, 0);
    assert.equal(w.fx.u(A).active, false);
    assert.equal(w.machine.current(A), null);
    await w.close();
  }
  // A renewal that fails to arm: the old record, its timer and the running agent are untouched.
  const w = await world();
  await granted(w, [A]);
  await w.fire("renew");
  const old = w.record(A).rec;
  w.armFail = true;
  w.advance(RENEW_MS);
  await w.fire("renew");
  assert.deepEqual(w.record(A).rec, old);
  assert.deepEqual(w.machine.current(A), old);
  assert.ok(!w.lsysLog.some((l) => l[0] === "disarm"));
  assert.equal(w.fx.u(A).active, true);
  await w.close();
});

test("a restart before the first lease: recovery asks for every agent's lease, and a provisioned agent comes up", async () => {
  const w = await world();
  w.send = async () => null; // the first request goes unanswered
  await granted(w, [A]);
  await w.fire("renew");
  delete w.send;
  assert.equal(w.store.registry.agent(A).state, "provisioned");
  const n = w.sent.length;
  await w.sup.recover();
  await w.fire("renew");
  assert.equal(w.sent.length, n + 1, "asked at start");
  assert.equal(w.fx.u(A).active, true);
  await w.close();
});

test("a request that fails (the signer throws) keeps the cadence: the next renewal still runs", async () => {
  const w = await world();
  await granted(w, [A]);
  const sign = w.machine.sign;
  w.machine.sign = async () => { throw new Error("no host key"); };
  await w.fire("renew");
  assert.equal(w.sent.length, 0);
  w.machine.sign = sign;
  w.advance(RENEW_MS);
  await w.fire("renew");
  assert.equal(w.sent.length, 1);
  assert.equal(w.fx.u(A).active, true);
  await w.close();
});

test("a restarted supervisor never reuses an lg: it starts above the tombstone and the published record", async () => {
  const w = await world();
  await granted(w, [A]);
  writeFileSync(join(w.leaseDir, `${A}.spent`), "41\n");
  await w.sup.recover();
  await w.fire("renew");
  assert.equal(w.record(A).rec.lg, 42);
  assert.equal(readTombstone(A, { dir: w.leaseDir }), 41);
  await w.close();
});

// ---- expiry and bound timers (§3, §3.1)

test("expiry: the bound timer raises lease and stops, masks and proves the slice; a stale timer does nothing", async () => {
  const w = await world();
  await granted(w, [A]);
  w.send = async () => null; // offline from now on
  await w.fire("renew");
  delete w.send;
  const req = w.sent.at(-1);
  assert.equal((await w.sup.submit({ kind: "lease-response", authority: "host", agent: A, bytes: w.respond(req) })).status, "accepted");
  const rec = w.record(A).rec;
  w.send = async () => null;
  // A timer for another lease_id or lg is stale.
  assert.deepEqual(await w.sup.submit({ kind: "lease-timer", authority: "host", agent: A, lease_id: "other", lg: rec.lg }), { status: "stale" });
  assert.deepEqual(await w.sup.submit({ kind: "lease-timer", authority: "host", agent: A, lease_id: rec.lease_id, lg: rec.lg - 1 }), { status: "stale" });
  assert.equal(w.fx.u(A).active, true);
  w.advance(600_000 - MARGIN_MS);
  w.fx.log.length = 0;
  await w.fire("expiry");
  assert.equal(w.leaseUp(A), true);
  assert.equal(w.fx.u(A).active, false);
  assert.equal(w.fx.u(A).masked, true);
  assert.deepEqual(w.fx.log.filter((l) => l[0] === "sys-stop"), [["sys-stop", agentSlice(A)]], "the whole slice, not just the unit");
  assert.equal(w.machine.current(A), null);
  assert.ok(w.machine.lg(A) > rec.lg, "lg moved on");
  assert.deepEqual(w.fx.audits.at(-1), { kind: "agent.lease", agent: A, phase: "expired" });
  // The same timer again: stale now.
  assert.deepEqual(await w.sup.submit({ kind: "lease-timer", authority: "host", agent: A, lease_id: rec.lease_id, lg: rec.lg }), { status: "stale" });
  // Nothing comes back without a fresh lease: the record is still published but no longer this process's lease.
  w.advance(10);
  assert.equal(await w.machine.live(A), null);
  assert.equal(w.fx.u(A).active, false);
  await w.close();
});

test("a renewal queued behind an expiry's stop waits for it, is re-checked, and is accepted only if still fresh", async () => {
  for (const late of [false, true]) {
    const w = await world();
    await granted(w, [A]);
    await w.fire("renew");
    const rec = w.record(A).rec;
    w.send = async () => null;
    w.advance(RENEW_MS);
    await w.fire("renew"); // a renewal request goes out, unanswered for now
    const req = w.sent.at(-1);
    delete w.send;
    w.advance(600_000 - MARGIN_MS - RENEW_MS);
    const order = [];
    let release, reached;
    const gate = new Promise((r) => { release = r; }), atFence = new Promise((r) => { reached = r; });
    w.barrier = async (name) => { if (name === "after_fence_write") { order.push("fence"); reached(); await gate; } };
    const expiry = w.sup.submit({ kind: "lease-timer", authority: "host", agent: A, lease_id: rec.lease_id, lg: rec.lg }).then((r) => { order.push("stop done"); return r; });
    await atFence; // mid-stop: the fence is written, the stop and its proof aren't done
    if (late) w.advance(600_000); // the renewal expired while it waited
    const resp = w.sup.submit({ kind: "lease-response", authority: "host", agent: A, bytes: w.respond(req) }).then((r) => { order.push("response"); return r; });
    await new Promise((r) => setTimeout(r, 100));
    assert.deepEqual(order, ["fence"], "the response waits behind the stop");
    release();
    const [e, r] = await Promise.all([expiry, resp]);
    delete w.barrier;
    assert.equal(e.status, "stopped and fenced");
    assert.deepEqual(order, ["fence", "stop done", "response"]);
    if (late) {
      assert.deepEqual(r, { status: "ignored", reason: "expired" });
      assert.equal(w.leaseUp(A), true);
      assert.equal(w.fx.u(A).active, false);
    } else {
      assert.equal(r.status, "accepted");
      assert.equal(r.started, true);
      assert.equal(w.leaseUp(A), false);
    }
    await w.close();
  }
});

test("a response while a stop's proof is unfinished: the gate proves it first; if the proof fails, nothing is accepted or lowered", async () => {
  const w = await world();
  const req = await asked(w);
  w.fx.u(A).active = true; w.fx.u(A).stuck = true; // a process that survives every stop
  w.store.grants.markProof(A);
  const r = await w.sup.submit({ kind: "lease-response", authority: "host", agent: A, bytes: w.respond(req) });
  assert.deepEqual(r, { status: "refused", reason: "pending_proof" });
  assert.equal(w.record(A).state, "missing");
  assert.equal(w.leaseUp(A), true);
  assert.ok(w.machine.outstanding(A), "the request is kept: the same response may still be accepted once proven");
  w.fx.u(A).stuck = false;
  const ok = await w.sup.submit({ kind: "lease-response", authority: "host", agent: A, bytes: w.respond(req) });
  assert.equal(ok.status, "accepted");
  assert.equal(w.store.grants.pendingProofs().length, 0);
  await w.close();
});

// ---- grants (§3.1)

test("a grant changing an agent's generation voids its lease and request, raises lease before the plan's stop, and asks again with the new gen", async () => {
  const w = await world();
  await granted(w, [A, B]);
  await w.fire("renew");
  assert.equal(w.fx.u(A).active && w.fx.u(B).active, true);
  const old = w.record(A).rec;
  // A request in flight for A's old generation.
  w.send = async () => null;
  const stale = await w.machine.request(A, 1);
  delete w.send;
  const seen = [];
  w.barrier = async (name, d) => {
    if (name === "after_lease_raise") seen.push(["raised", w.leaseUp(A), w.leaseUp(B), w.fx.u(A).active]);
    if (name === "after_stop") seen.push(["stop", d.agent]);
  };
  const r = await w.sup.submit({ kind: "grant", bytes: grant(2, [entry(A, 2), entry(B)]) });
  delete w.barrier;
  assert.equal(r.status, "applied");
  assert.deepEqual(seen[0], ["raised", true, false, true], "raised for A only, before its stop");
  assert.deepEqual(seen[1], ["stop", A]);
  assert.equal(w.fx.u(A).active, false);
  assert.equal(w.fx.u(B).active, true, "B's entry didn't change: its lease and run are untouched");
  assert.equal(w.machine.current(A), null);
  assert.equal(w.machine.outstanding(A), null);
  assert.ok(w.machine.lg(A) > old.lg);
  // The old generation's response: no request for it any more.
  assert.deepEqual(await w.sup.submit({ kind: "lease-response", authority: "host", agent: A, bytes: w.respond(stale) }), { status: "ignored", reason: "no_request" });
  assert.equal(w.fx.u(A).active, false);
  // Its start step asked for a lease again: the next request carries gen 2, and A comes back under it.
  await w.fire("renew");
  const rq = JSON.parse(String(w.sent.at(-1)));
  assert.equal(rq.gen, 2);
  assert.equal(w.record(A).rec.gen, 2);
  assert.equal(w.fx.u(A).active, true);
  // B's entry didn't change in grant 2: it keeps renewing at ITS entry generation, 1, not the grant's.
  const bBefore = w.record(B).rec;
  w.advance(RENEW_MS);
  await w.fire("renew");
  const bReq = w.sent.map((x) => JSON.parse(String(x))).filter((x) => x.agent === B).at(-1);
  assert.equal(bReq.gen, 1);
  assert.ok(w.record(B).rec.lg > bBefore.lg, "B's renewal was accepted");
  assert.equal(w.record(B).rec.gen, 1);
  await w.close();
});

test("an expiry timer is an emergency: it runs before a response queued ahead of it", async () => {
  const w = await world();
  await granted(w, [A]);
  await w.fire("renew");
  const rec = w.record(A).rec;
  w.send = async () => null;
  await w.machine.renew(A);
  const req = w.sent.at(-1);
  // Hold the queue: a person's stop of A, gated mid-stop.
  let release, reached;
  const gate = new Promise((r) => { release = r; }), held = new Promise((r) => { reached = r; });
  w.barrier = async (name) => { if (name === "after_fence_write") { reached(); await gate; } };
  const order = [];
  const first = w.sup.submit({ kind: "stop", authority: "person", agent: A }).then(() => order.push("stop"));
  await held;
  delete w.barrier;
  const resp = w.sup.submit({ kind: "lease-response", authority: "host", agent: A, bytes: w.respond(req) }).then((r) => { order.push("response"); return r; });
  w.advance(600_000 - MARGIN_MS - 1000);
  const timer = w.sup.submit({ kind: "lease-timer", authority: "host", agent: A, lease_id: rec.lease_id, lg: rec.lg }).then((r) => { order.push("timer"); return r; });
  release();
  await Promise.all([first, resp, timer]);
  assert.deepEqual(order, ["stop", "timer", "response"]);
  await w.close();
});

test("a response for the old generation, answered after the grant moved on, is ignored (stale_gen) and voids the request", async () => {
  const w = await world();
  const req = await asked(w);
  // The grant moves A's entry while this op hasn't run: simulated by the generation the executor passes.
  const r = await w.machine.accept(A, w.respond(req), 2);
  assert.deepEqual(r, { accepted: false, reason: "stale_gen" });
  assert.equal(w.machine.outstanding(A), null);
  await w.close();
});

test("an agent a grant adds after start has lease raised before any start; recovery raises every agent's lease before anything", async () => {
  const w = await world();
  await granted(w, [A]);
  await w.fire("renew");
  let startedB = false;
  w.barrier = async (name, d) => { if (name === "before_start" && d.agent === B) startedB = true; if (name === "before_activate" && d.agent === B) startedB = true; };
  await w.sup.submit({ kind: "grant", bytes: grant(2, [entry(A), entry(B)]) });
  delete w.barrier;
  assert.equal(w.leaseUp(B), true);
  assert.equal(startedB, false);
  assert.equal(w.fx.u(B).active, false);
  // A supervisor restart: every agent fenced, the running one stopped and proven, nothing started, no lease kept.
  const w2sup = new Supervisor({ store: w.store, fx: w.fx, verify: grantVerify, bodyOf, fenceDir: w.fenceDir, lease: w.machine });
  const old = w.sent.at(-1);
  w.fx.log.length = 0;
  const r = await w2sup.recover();
  assert.equal(r.status, "recovered");
  assert.deepEqual(r.started, []);
  assert.equal(w.leaseUp(A) && w.leaseUp(B), true);
  assert.equal(w.fx.u(A).active, false);
  assert.equal(w.machine.current(A), null);
  assert.equal(w.machine.outstanding(A), null);
  assert.ok(!w.fx.log.some((l) => l[0] === "start"));
  // A response captured before the restart: ignored.
  assert.deepEqual(await w2sup.submit({ kind: "lease-response", authority: "host", agent: A, bytes: w.respond(old) }), { status: "ignored", reason: "no_request" });
  await w.close();
});

// ---- who gets a lease, and what a lease may lower

test("no request for an agent not listed, ended, or stopped by a person; a resume asks again", async () => {
  const w = await world();
  await granted(w, [A]);
  await w.fire("renew");
  assert.deepEqual(await w.sup.submit({ kind: "lease-request", authority: "host", agent: B }), { status: "skipped", reason: "not_listed" });
  await w.sup.submit({ kind: "stop", authority: "person", agent: A });
  assert.deepEqual(await w.sup.submit({ kind: "lease-request", authority: "host", agent: A }), { status: "skipped", reason: "stopped" });
  // The cadence stops for it.
  w.advance(RENEW_MS);
  const n = w.sent.length;
  await w.fire("renew");
  assert.equal(w.sent.length, n);
  // Its lease expires meanwhile (the bound timer still runs): lease up, still stopped.
  w.advance(600_000);
  await w.fire("expiry");
  assert.equal(w.leaseUp(A), true);
  // A person's resume: the start finds no lease and asks for one now; the fresh lease brings it back.
  const r = await w.sup.submit({ kind: "resume", authority: "person", agent: A });
  assert.deepEqual([r.started, r.why], [false, "no_lease"]);
  assert.equal(w.fx.u(A).active, false);
  await w.fire("renew");
  assert.equal(w.fx.u(A).active, true);
  assert.equal(w.leaseUp(A), false);
  // all fences every agent.
  raiseFence("all", null, { dir: w.fenceDir });
  assert.equal((await w.sup.submit({ kind: "lease-request", authority: "host", agent: A })).status, "skipped");
  await w.close();
});

test("a transferred agent (execution lease §4): no lease is ever requested for it again, and nothing starts it", async () => {
  const w = await world();
  await granted(w, [A]);
  await w.fire("renew");
  assert.equal(w.fx.u(A).active, true);
  raiseFence("transferred", A, { dir: w.fenceDir });
  assert.deepEqual(await w.sup.submit({ kind: "lease-request", authority: "host", agent: A }), { status: "skipped", reason: "transferred" });
  // Even with a person's own fence lowered and no other cause up: still skipped, and a resume starts nothing.
  const n = w.sent.length;
  w.advance(RENEW_MS);
  await w.fire("renew");
  assert.equal(w.sent.length, n, "the cadence asks nothing for it");
  await w.close();
});

test("a lease lowers only lease: with agent, backup or an unvalidated restore up, the helper never runs, and nothing else is lowered", async () => {
  for (const other of ["restore", "agent", "backup"]) {
    const w = await world();
    const req = await asked(w);
    raiseFence(other, A, { dir: w.fenceDir });
    const r = await w.sup.submit({ kind: "lease-response", authority: "host", agent: A, bytes: w.respond(req) });
    assert.equal(r.status, "accepted", other);
    assert.equal(r.started, false);
    assert.equal(w.helperRuns.length, 0, other);
    assert.deepEqual(fenceCauses(A, { dir: w.fenceDir }), ["agent", "backup", "lease", "restore"].filter((c) => c === other || c === "lease"));
    assert.equal(w.fx.u(A).active, false);
    await w.close();
  }
});

/** A real restore record for the agent in `state` (validated: a restored agent waiting for the person's resume). */
function restoreRecord(w, id, state) {
  const reason = state === "failed" ? "not_found" : state === "not_fitting" ? "limit" : null;
  writeRestore({ v: 1, kind: "agent", id, run: "aaaaaaaaaaaaaaaa", snapshot: "a".repeat(64), attempt: 1, state, reason, dirty: false,
    dest: { home: { dev: "1", ino: "2" }, sessions: { dev: "1", ino: "3" } }, digests: { home: "b".repeat(64), sessions: "c".repeat(64) } }, { dir: w.restoreDir });
}

test("a restored agent waiting for its resume (restore up, record validated): the helper lowers lease, systemd skips its start, and nothing else starts it", async () => {
  const w = await world();
  const req = await asked(w);
  raiseFence("restore", A, { dir: w.fenceDir });
  restoreRecord(w, A, "validated");
  const r = await w.sup.submit({ kind: "lease-response", authority: "host", agent: A, bytes: w.respond(req) });
  assert.equal(r.status, "accepted");
  assert.equal(r.started, false);
  assert.deepEqual(w.helperRuns.map((h) => h.cmd), ["lease-activate"]);
  assert.equal(w.helperRuns[0].underFenceLock, false);
  assert.equal(w.leaseUp(A), false, "lease lowered: the resume helper requires it down");
  assert.deepEqual(fenceCauses(A, { dir: w.fenceDir }), ["restore"]);
  assert.ok(w.fx.log.some((l) => l[0] === "helper-start" && l[1] === A), "the helper queued its start");
  assert.ok(!w.fx.log.some((l) => l[0] === "start"), "no start effect from the executor itself");
  assert.equal(w.fx.u(A).active, false, "systemd skipped it: restore is still up");
  assert.equal(w.store.registry.agent(A).state, "provisioned", "the run state waits for the resume");
  await w.close();
});

test("then the REAL resume: resumeRestored passes after the activation and lowers restore; validated only after the publish, it refuses lease_raised until the next renewal activates", async () => {
  const resume = (w, live, started) => resumeRestored(A, live.gen, live.lease_id, live.lg, {
    restoreState: (id) => readRestore("agent", id, { dir: w.restoreDir })?.state, dir: w.leaseDir, fenceDir: w.fenceDir,
    leaseFenceDir: join(w.fenceDir, "lease"), clock: w.clock, cgroupOf: () => resumeCgroup(A),
    sys: { ...w.lsys, selfCgroup: () => resumeCgroup(A), start: async (unit) => { started.push(unit); } },
  });
  for (const early of [true, false]) {
    const w = await world();
    const req = await asked(w);
    raiseFence("restore", A, { dir: w.fenceDir });
    restoreRecord(w, A, early ? "validated" : "published");
    await w.sup.submit({ kind: "lease-response", authority: "host", agent: A, bytes: w.respond(req) });
    const started = [];
    if (!early) {
      // Validated only after the lease was published: lease is still up, so the resume refuses and changes nothing.
      restoreRecord(w, A, "validated");
      const refused = await resume(w, await w.machine.live(A), started);
      assert.deepEqual([refused.resumed, refused.reason], [false, "lease_raised"]);
      assert.deepEqual(fenceCauses(A, { dir: w.fenceDir }), ["lease", "restore"]);
      // The next renewal finds lease up and starts it: the helper lowers lease (restore still holds the unit).
      w.advance(RENEW_MS);
      await w.fire("renew");
      assert.deepEqual(fenceCauses(A, { dir: w.fenceDir }), ["restore"]);
    }
    const live = await w.machine.live(A);
    const resumed = await resume(w, live, started);
    assert.equal(resumed.resumed, true, JSON.stringify(resumed));
    assert.deepEqual(fenceCauses(A, { dir: w.fenceDir }), []);
    assert.equal(started.length, 1, "the resume queued the start");
    await w.close();
  }
});

test("restore up without a validated record, or with another fence, or the agent stopped or failed to start: the helper never runs", async () => {
  for (const [state, extra] of [["published", null], ["failed", null], ["not_fitting", null], [null, null], ["garbage", null],
    ["validated", "agent"], ["validated", "all"], ["validated", "backup"], ["validated", "stopped"], ["validated", "start_failed"]]) {
    const w = await world();
    const req = await asked(w);
    raiseFence("restore", A, { dir: w.fenceDir });
    if (state === "garbage") writeFileSync(join(w.restoreDir, `agent-${A}.json`), "{not json");
    else if (state !== null) restoreRecord(w, A, state);
    if (extra === "agent" || extra === "backup") raiseFence(extra, A, { dir: w.fenceDir });
    if (extra === "all") raiseFence("all", null, { dir: w.fenceDir });
    if (extra === "stopped") w.store.registry.setState(A, "stopped");
    if (extra === "start_failed") w.store.registry.setStartFailed(A, "unit_failed");
    const r = await w.sup.submit({ kind: "lease-response", authority: "host", agent: A, bytes: w.respond(req) });
    const what = `${state}/${extra}`;
    assert.equal(r.status, "accepted", what);
    assert.equal(r.started, false, what);
    assert.equal(w.helperRuns.length, 0, what);
    assert.equal(w.leaseUp(A), true, what);
    assert.equal(w.fx.u(A).active, false, what);
    await w.close();
  }
});

// ---- a paused agent's resume: the thaw under the activation lock

/** A running agent with a live lease, then paused (frozen). */
async function paused(w) {
  await granted(w, [A]);
  await w.fire("renew");
  assert.equal(w.fx.u(A).active, true);
  assert.equal((await w.sup.submit({ kind: "pause", authority: "person", agent: A })).status, "paused");
  assert.equal(w.fx.u(A).frozen, true);
  w.helperRuns.length = 0;
}

test("a paused agent's resume with its live lease: thawed by the thaw helper, in its scope, outside the fence lock", async () => {
  const w = await world();
  await paused(w);
  const r = await w.sup.submit({ kind: "resume", authority: "person", agent: A });
  assert.deepEqual(r, { status: "resumed", started: true, thawed: true });
  assert.deepEqual(w.helperRuns.map((h) => [h.cmd, h.underFenceLock, h.slice]), [["lease-thaw", false, `--slice=${agentSlice(A)}`]]);
  assert.equal(w.fx.u(A).frozen, false);
  assert.equal(w.store.registry.agent(A).state, "running");
  assert.deepEqual(w.helperRuns[0].result, { thawed: true, reason: null }, "the helper itself thawed it, under the lock");
  await w.close();
});

test("a paused agent's resume once the effective end has passed but before the timer fired: refused, nothing changes, a renewal is asked for", async () => {
  const w = await world();
  await paused(w);
  w.send = async () => null;
  const exp = w.record(A).rec.expiry_tick;
  w.advance(exp - MARGIN_MS - 10 - w.b); // bootNow = the effective end exactly; the lease timer hasn't run
  const r = await w.sup.submit({ kind: "resume", authority: "person", agent: A });
  assert.deepEqual(r, { status: "refused", reason: "no_lease", started: false });
  assert.equal(w.helperRuns.length, 0);
  assert.equal(w.fx.u(A).frozen, true, "not thawed");
  assert.equal(w.store.registry.agent(A).state, "paused");
  assert.ok(w.pending.some((h) => h.ms === 0), "a renewal is due now");
  await w.close();
});

test("an expiry at the thaw seam wins: the thaw helper's checks under the lock refuse, and the agent is contained with its own fence", async () => {
  const w = await world();
  await paused(w);
  // The watchdog commits (tombstone at the lease's lg) just as the thaw helper starts.
  w.helperHook = (agent, cmd) => { if (cmd === "lease-thaw") writeFileSync(join(w.leaseDir, `${agent}.spent`), `${w.record(agent).rec.lg}\n`); };
  const r = await w.sup.submit({ kind: "resume", authority: "person", agent: A });
  assert.equal(r.status, "failed");
  assert.equal(r.reason, "lease");
  assert.equal(w.helperRuns[0].result.reason, "spent");
  assert.equal(w.fx.u(A).active, false, "contained: stopped");
  assert.ok(fenceCauses(A, { dir: w.fenceDir }).includes("agent"), "its own fence: a person resumes it again");
  assert.ok(!w.fx.log.some((l) => l[0] === "thaw"));
  await w.close();
});

test("a raised lease can't be bypassed by a resume: refused before anything changes; the thaw helper refuses lease up on its own too", async () => {
  const w = await world();
  await paused(w);
  raiseFence("lease", A, { dir: w.fenceDir });
  const r = await w.sup.submit({ kind: "resume", authority: "person", agent: A });
  assert.deepEqual(r, { status: "refused", reason: "lease_raised", started: false });
  assert.equal(w.helperRuns.length, 0);
  assert.equal(w.fx.u(A).frozen, true);
  // The helper itself, with a live published lease but lease up: refuses.
  const rec = w.record(A).rec;
  const hsys = { ...w.lsys, selfCgroup: () => `/sagebrush.slice/sagebrush-agents.slice/${agentSlice(A)}/${thawScope(A)}`, thaw: async () => { throw new Error("must not thaw"); } };
  assert.deepEqual(await leaseThaw(A, rec.lease_id, rec.lg, { dir: w.leaseDir, fenceDir: join(w.fenceDir, "lease"), sys: hsys, clock: w.clock }), { thawed: false, reason: "lease_raised" });
  // Outside its scope, or for another lease: refused.
  assert.equal((await leaseThaw(A, rec.lease_id, rec.lg, { dir: w.leaseDir, fenceDir: join(w.fenceDir, "lease"), sys: { ...hsys, selfCgroup: () => "/" }, clock: w.clock })).reason, "outside_slice");
  assert.equal((await leaseThaw(A, "other", rec.lg, { dir: w.leaseDir, fenceDir: join(w.fenceDir, "lease"), sys: hsys, clock: w.clock })).reason, "not_published");
  await w.close();
});

test("a helper that refuses: not started, lease still up; the executor never starts the unit itself", async () => {
  const w = await world();
  const req = await asked(w);
  w.helperCode = 3;
  const r = await w.sup.submit({ kind: "lease-response", authority: "host", agent: A, bytes: w.respond(req) });
  assert.equal(r.status, "accepted");
  assert.equal(r.started, false);
  assert.equal(w.leaseUp(A), true);
  assert.ok(!w.fx.log.some((l) => l[0] === "start"));
  assert.equal(w.fx.u(A).active, false);
  await w.close();
});

test("a helper that exits 0 but leaves lease up (a watchdog committed first): not started", async () => {
  const w = await world();
  const req = await asked(w);
  w.helperCode = 0; // claims success without lowering
  const r = await w.sup.submit({ kind: "lease-response", authority: "host", agent: A, bytes: w.respond(req) });
  assert.equal(r.started, false);
  assert.equal(w.leaseUp(A), true);
  assert.ok(!w.fx.log.some((l) => l[0] === "start"));
  await w.close();
});

test("a watchdog that commits while the helper is about to run: the helper's own checks refuse, nothing is lowered or started", async () => {
  const w = await world();
  const req = await asked(w);
  // At the helper's start the watchdog has written the tombstone for this lg (it fired early: the slow-host seam).
  w.helperHook = (agent) => { writeFileSync(join(w.leaseDir, `${agent}.spent`), `${w.machine.current(agent).lg}\n`); };
  const r = await w.sup.submit({ kind: "lease-response", authority: "host", agent: A, bytes: w.respond(req) });
  assert.equal(r.started, false);
  assert.equal(w.leaseUp(A), true);
  assert.equal(w.fx.u(A).active, false);
  await w.close();
});

test("only the host may submit lease ops, and only to a supervisor with a lease machine; the expiry op is an emergency", async () => {
  const w = await world();
  for (const authority of ["service", "person", "local"]) {
    await assert.rejects(w.sup.submit({ kind: "lease-response", authority, agent: A, bytes: Buffer.from("{}") }), (e) => e.code === "not_granted");
  }
  const store = await HostStore.open(tmp("plain"));
  const plain = new Supervisor({ store, fx: fakeFx(tmp("f")), verify: grantVerify, bodyOf, fenceDir: tmp("f2") });
  for (const kind of ["lease-request", "lease-response", "lease-timer"]) await assert.rejects(plain.submit({ kind, authority: "host", agent: A }), (e) => e.code === "bad_form");
  // Without a lease machine, recovery raises no lease fence and a grant starts its agents as before.
  await plain.recover();
  const r = await plain.submit({ kind: "grant", bytes: grant(1, [entry(A)]) });
  assert.equal(r.status, "applied");
  assert.deepEqual(r.ack.restarted, [A]);
  await store.close();
  await w.close();
});

test("the cadence: at start, every 2 minutes, and right away when a start finds no lease; an unanswered renewal lets the lease expire", async () => {
  const w = await world();
  await granted(w, [A]);
  await w.fire("renew");
  assert.equal(w.sent.length, 1);
  w.advance(RENEW_MS - 1);
  await w.fire("renew");
  assert.equal(w.sent.length, 1, "not before 2 minutes");
  w.advance(1);
  await w.fire("renew");
  assert.equal(w.sent.length, 2);
  // Offline: renewals go unanswered; the lease from the second renewal expires at its effective end.
  w.send = async () => null;
  for (let t = 0; t < 4; t++) { w.advance(RENEW_MS); await w.fire("renew"); }
  w.advance(600_000);
  await w.fire("expiry");
  assert.equal(w.leaseUp(A), true);
  assert.equal(w.fx.u(A).active, false);
  // Back online: the next renewal brings it back.
  delete w.send;
  w.advance(RENEW_MS);
  await w.fire("renew");
  assert.equal(w.fx.u(A).active, true);
  assert.equal(w.leaseUp(A), false);
  await w.close();
});

test("the record the machine publishes is exactly the accepted lease, and a live lease needs the record AND this process's acceptance", async () => {
  const w = await world();
  await granted(w, [A]);
  await w.fire("renew");
  const rec = w.record(A).rec;
  assert.deepEqual(await w.machine.live(A), rec);
  // A record this process didn't publish (another lease id), even if well formed and with a waiting timer: not live.
  writeFileSync(join(w.leaseDir, A), JSON.stringify({ ...rec, lease_id: "someoneelse" }));
  assert.equal(await w.machine.live(A), null);
  await w.close();
});

// The rows that need the real systemd, the kernel's cgroups and a real suspend, written here and run on the
// qualification VM (lease part 2's deferred rows; no production enablement until they pass): §5 "without the
// supervisor" (SIGKILL, SIGSTOP and a supervisor kept from restarting past the TTL; the re-arm seams; T2d; the
// activation seams; T2f; a turn launch holding the shared lock; T2g; a hung helper; concurrent watchdogs; a reused
// pid; T2e after real suspends; the 30-second margin; the backup-frozen slice; the new host's first lease), suspend
// across the expiry, and "a crash with the fence file written but the stop unfinished".
for (const name of ["T2: SIGKILL/SIGSTOP of the supervisor; kept from restarting past the TTL", "T2: the re-arm seams with a crash at each", "T2d", "T2: a watchdog at each activation seam", "T2f", "T2g", "T2e: after real suspends", "suspend across the expiry and within the lease", "the backup-frozen slice at expiry", "the new host's first lease"]) {
  test(`(deferred to the qualification VM) ${name}`, { skip: "real systemd and kernel cgroups: lease part 2's VM rows" }, () => {});
}

// ---- the person's resume of a restored agent, wired: resume-restored (restore-resume.mjs requestResume, then the run state)

/**
 * The supervisor's restore resume over a world: requestResume with fakes for the shared core's verifiers and the host
 * records, and the REAL resume helper (resumeRestored) run in process as its scope would be, its start through the
 * executor's fake units (systemd's fence condition included). `w.resumeHook` replaces the whole request; `w.helperStart`
 * replaces the helper's start; `w.requests` counts the calls and keeps the live lease each was given.
 */
const resumeOp = (w) => ({
  request: async (agent, extra) => {
    (w.requests ??= []).push({ agent, live: await extra.liveLease(agent) });
    if (w.resumeHook) return w.resumeHook(agent, extra);
    return requestResume(agent, {
      restoreState: (id) => readRestore("agent", id, { dir: w.restoreDir })?.state ?? null,
      tagsOf: () => [],
      pairOf: () => ({ transfer: "T", receipt: "R" }),
      verifyTransferReceipt: async () => ({ transfer: { agent }, receipt: { agent, gen: 1, nonce: "N" }, transferHash: "H" }),
      checkTransferForHost: () => ({ first: false }),
      host: { entryGen: () => w.entryGen ?? 1, recordTransfer: () => {} },
      node: "/n", main: "/m",
      run: async (argv) => {
        const at = argv.indexOf("resume-restored");
        const [id, gen, leaseId, lg] = argv.slice(at + 1);
        const r = await resumeRestored(id, Number(gen), leaseId, Number(lg), {
          restoreState: (x) => readRestore("agent", x, { dir: w.restoreDir })?.state, dir: w.leaseDir, fenceDir: w.fenceDir,
          leaseFenceDir: join(w.fenceDir, "lease"), clock: w.clock, cgroupOf: () => resumeCgroup(id), barrier: w.helperBarrier,
          sys: { ...w.lsys, selfCgroup: () => resumeCgroup(id), start: w.helperStart ?? (async () => {
            w.fx.log.push(["resume-start", id]);
            if (!w.fx.u(id).masked && !fenced(id, { dir: w.fenceDir })) w.fx.u(id).active = true;
          }) },
        });
        return { code: r.resumed ? 0 : 3, stdout: JSON.stringify(r) };
      },
      ...extra,
    });
  },
});

/** A restored agent waiting for its resume: granted, restore up, its record validated, its first lease accepted. */
async function restored(w) {
  const req = await asked(w);
  raiseFence("restore", A, { dir: w.fenceDir });
  restoreRecord(w, A, "validated");
  const r = await w.sup.submit({ kind: "lease-response", authority: "host", agent: A, bytes: w.respond(req) });
  assert.equal(r.status, "accepted");
  assert.deepEqual(fenceCauses(A, { dir: w.fenceDir }), ["restore"]);
  assert.equal(w.store.registry.agent(A).state, "provisioned");
}
const resumeRestoredOp = (w, agent = A) => w.sup.submit({ kind: "resume-restored", authority: "person", agent });
const audits = (w) => w.fx.audits.filter((x) => x.kind === "agent.resume").map((x) => x.reason ? `${x.phase}:${x.reason}` : x.phase);

test("resume-restored: the REAL requestResume and helper lower restore and start it; only then is the agent running", async () => {
  const w = await world({ resumeOp });
  await restored(w);
  // Only a person may: the service, the local CLI and the host can't submit it (refused before anything runs).
  for (const authority of ["service", "local", "host"]) {
    await assert.rejects(w.sup.submit({ kind: "resume-restored", authority, agent: A }), (e) => e.code === "not_granted", authority);
  }
  assert.equal((w.requests ?? []).length, 0);
  assert.deepEqual(fenceCauses(A, { dir: w.fenceDir }), ["restore"]);
  const live = await w.machine.live(A);
  w.barrier = async (n) => { if (n === "before_restore_resume") assert.equal(w.store.registry.agent(A).state, "provisioned", "not running before the helper"); };
  assert.deepEqual(await resumeRestoredOp(w), { status: "resumed", started: true });
  assert.deepEqual(w.requests.map((q) => q.live), [live], "given the lease MACHINE's live lease");
  assert.deepEqual(fenceCauses(A, { dir: w.fenceDir }), []);
  assert.equal(w.fx.u(A).active, true);
  assert.equal(w.store.registry.agent(A).state, "running");
  assert.deepEqual(audits(w), ["succeeded"]);
  await w.close();
});

test("resume-restored refuses, with nothing changed and nothing launched, unless the agent is a granted, validated restore whose only fence is restore", async () => {
  const cases = {
    "no restore resume on this host": { op: false },
    "not listed by the grant": { agent: B },
    "restore not validated": { prep: (w) => restoreRecord(w, A, "published") },
    "no restore record": { prep: (w) => { writeFileSync(join(w.restoreDir, `agent-${A}.json`), "{not json"); } },
    "restore not up": { prep: (w) => { w.store.registry.agent(A); } , lower: true },
    "another fence (agent)": { prep: (w) => raiseFence("agent", A, { dir: w.fenceDir }) },
    "another fence (backup)": { prep: (w) => raiseFence("backup", A, { dir: w.fenceDir }) },
    "start failed": { prep: (w) => w.store.registry.setStartFailed(A, "unit_failed") },
    "deleted": { prep: (w) => w.store.registry.setState(A, "deleted") },
  };
  for (const [what, c] of Object.entries(cases)) {
    const w = await world(c.op === false ? {} : { resumeOp });
    await restored(w);
    if (c.lower) await resumeRestoredOp(w); // restore lowered by a resume: a second one has nothing to do
    if (c.prep) c.prep(w);
    const before = { fences: fenceCauses(A, { dir: w.fenceDir }), state: w.store.registry.agent(A).state, n: (w.requests ?? []).length, log: w.fx.log.length };
    await assert.rejects(resumeRestoredOp(w, c.agent ?? A), (e) => e.code === "not_granted", what);
    assert.deepEqual({ fences: fenceCauses(A, { dir: w.fenceDir }), state: w.store.registry.agent(A).state, n: (w.requests ?? []).length, log: w.fx.log.length }, before, what);
    await w.close();
  }
});

test("resume-restored with lease up, or with a published record the lease machine has voided: waiting_for_lease, nothing launched or changed", async () => {
  // lease up (no lease accepted yet): refused before any launch.
  {
    const w = await world({ resumeOp });
    await asked(w);
    raiseFence("restore", A, { dir: w.fenceDir });
    restoreRecord(w, A, "validated");
    assert.deepEqual(await resumeRestoredOp(w), { status: "refused", reason: "waiting_for_lease", started: false });
    assert.equal((w.requests ?? []).length, 0, "nothing launched");
    assert.deepEqual(fenceCauses(A, { dir: w.fenceDir }), ["lease", "restore"]);
    await w.close();
  }
  // A record still published on disk, but voided in the machine (a supervisor restart or a gen change does this).
  for (const voidIt of ["invalidate", "init"]) {
    const w = await world({ resumeOp });
    await restored(w);
    assert.notEqual(w.record(A).state === "ok" ? w.record(A).rec : null, null, "still published");
    w.machine[voidIt](A);
    assert.deepEqual(await resumeRestoredOp(w), { status: "refused", reason: "waiting_for_lease", started: false }, voidIt);
    assert.deepEqual(w.requests.map((q) => q.live), [null], voidIt);
    assert.deepEqual(fenceCauses(A, { dir: w.fenceDir }), ["restore"], voidIt);
    assert.equal(w.store.registry.agent(A).state, "provisioned", voidIt);
    assert.equal(w.fx.u(A).active, false, voidIt);
    await w.close();
  }
});

test("resume-restored refused by requestResume or its helper: the reason, and nothing changes", async () => {
  // Another entry_gen than the live lease's: not_this_lease, before any launch.
  const w = await world({ resumeOp });
  await restored(w);
  w.entryGen = 9;
  assert.deepEqual(await resumeRestoredOp(w), { status: "refused", reason: "not_this_lease", started: false });
  assert.deepEqual(fenceCauses(A, { dir: w.fenceDir }), ["restore"]);
  assert.equal(w.store.registry.agent(A).state, "provisioned");
  assert.deepEqual(audits(w), ["refused:not_this_lease"]);
  await w.close();
});

test("resume-restored with an unknown outcome (a throw, a timeout, an unreadable answer): stopped and contained with a fence, never left provisioned", async () => {
  for (const how of ["throw", "timeout", "helper_failed", "garbage"]) {
    const w = await world({ resumeOp });
    await restored(w);
    w.resumeHook = async () => {
      if (how === "throw") throw new Error("EIO");
      if (how === "timeout") throw Object.assign(new Error("helper timed out"), { code: "step_deadline" });
      if (how === "helper_failed") return { resumed: false, reason: "helper_failed" };
      return "nonsense";
    };
    const r = await resumeRestoredOp(w);
    assert.deepEqual([r.status, r.reason, r.started], ["failed", "helper_unknown", false], how);
    assert.equal(w.store.registry.agent(A).state, "stopped", how);
    assert.ok(fenceCauses(A, { dir: w.fenceDir }).includes("agent"), `${how}: contained with its own fence`);
    assert.equal(w.fx.u(A).active, false, how);
    assert.deepEqual(audits(w), ["unknown_effect"], how);
    await w.close();
  }
});

test("resume-restored whose start couldn't be queued after the lowering: running recorded, then stopped with start_failed, contained with a fence", async () => {
  const w = await world({ resumeOp });
  await restored(w);
  w.helperStart = async () => { throw new Error("systemctl start failed"); };
  const r = await resumeRestoredOp(w);
  assert.deepEqual([r.status, r.reason, r.started], ["failed", "start_failed", false]);
  assert.equal(w.store.registry.agent(A).state, "stopped");
  assert.equal(w.store.registry.agent(A).start_failed, "unit_failed");
  assert.deepEqual(fenceCauses(A, { dir: w.fenceDir }), ["agent"], "restore lowered; its own fence raised");
  assert.deepEqual(audits(w), ["unknown_effect"]);
  // A person's plain resume then retries it (start_failed cleared), under a fresh lease.
  const again = await w.sup.submit({ kind: "resume", authority: "person", agent: A });
  assert.equal(again.status, "resumed");
  assert.equal(w.store.registry.agent(A).start_failed, null);
  await w.close();
});

test("recovery reconciles a crash between the helper's lowering and the run state: running, then started under a fresh lease; restore still up stays provisioned", async () => {
  for (const crashAt of ["after_restore_resume", "before_restore_resume"]) {
    const dirs = { root: tmp("state"), fenceDir: tmp("fence"), leaseDir: tmp("lease"), restoreDir: tmp("restore") };
    const w = await world({ resumeOp, ...dirs });
    await restored(w);
    w.barrier = async (n) => { if (n === crashAt) throw new Error("crash"); };
    await assert.rejects(resumeRestoredOp(w));
    assert.equal(w.store.registry.agent(A).state, "provisioned", crashAt);
    await w.close();
    const w2 = await world({ resumeOp, ...dirs });
    const r = await w2.sup.recover();
    assert.equal(r.status, "recovered", crashAt);
    if (crashAt === "after_restore_resume") {
      assert.equal(w2.store.registry.agent(A).state, "running", "its resume happened");
      assert.deepEqual(fenceCauses(A, { dir: w2.fenceDir }), ["lease"], "recovery raised lease; restore stays down");
      // Its start waits for a fresh lease, then runs.
      await w2.fire("renew");
      assert.equal(w2.fx.u(A).active, true);
      assert.deepEqual(fenceCauses(A, { dir: w2.fenceDir }), []);
    } else {
      assert.equal(w2.store.registry.agent(A).state, "provisioned", "restore still up: not resumed");
      assert.deepEqual(fenceCauses(A, { dir: w2.fenceDir }), ["lease", "restore"]);
    }
    await w2.close();
  }
});

test("recovery's reconciliation goes through the widening gate: with its proof unfinished the agent is never moved to running (contained instead); a person's resume then brings it back", async () => {
  const dirs = { root: tmp("state"), fenceDir: tmp("fence"), leaseDir: tmp("lease"), restoreDir: tmp("restore") };
  const w = await world({ resumeOp, ...dirs });
  await restored(w);
  w.barrier = async (n) => { if (n === "after_restore_resume") throw new Error("crash"); };
  await assert.rejects(resumeRestoredOp(w));
  // A process that survives every stop, and the agent's proof pending: recovery can't prove it down.
  w.fx.u(A).active = true; w.fx.u(A).stuck = true;
  w.store.grants.markProof(A);
  w.barrier = null;
  const r = await w.sup.recover();
  assert.ok((r.unproven ?? []).includes(A), JSON.stringify(r));
  assert.notEqual(w.store.registry.agent(A).state, "running", "never moved to running while its proof is unfinished");
  assert.ok(fenceCauses(A, { dir: w.fenceDir }).includes("agent"), "contained with its own fence");
  await w.close();
  // The next start, with the process gone: proven, and left as containment left it; a person's resume brings it back.
  const w2 = await world({ resumeOp, ...dirs });
  const r2 = await w2.sup.recover();
  assert.ok(!(r2.unproven ?? []).includes(A), JSON.stringify(r2));
  assert.equal(w2.store.registry.agent(A).state, "stopped");
  const again = await w2.sup.submit({ kind: "resume", authority: "person", agent: A });
  assert.equal(again.status, "resumed", JSON.stringify(again));
  await w2.fire("renew");
  assert.equal(w2.store.registry.agent(A).state, "running");
  assert.equal(w2.fx.u(A).active, true);
  await w2.close();
});

test("resume-restored cut short by the executor's close: the op ends at once with Closing, a pending proof is durable, and the next start proves the agent down before the reconciliation records its resume", async () => {
  for (const late of [true, false]) {
    const dirs = { root: tmp("state"), fenceDir: tmp("fence"), leaseDir: tmp("lease"), restoreDir: tmp("restore") };
    const w = await world({ resumeOp, ...dirs });
    await restored(w);
    // The helper hangs: the request never answers (a stuck systemd-run, a lock wait).
    let held;
    w.resumeHook = (agent, extra) => { held = { agent, extra }; return new Promise(() => {}); };
    const op = resumeRestoredOp(w);
    for (let i = 0; i < 50 && !held; i++) await new Promise((r) => setImmediate(r));
    assert.ok(held, "the request is in flight");
    const closed = await Promise.race([w.sup.close().then(() => true), new Promise((r) => setTimeout(() => r(false), 2000))]);
    assert.ok(closed, "the close ended within 2 s, not after the helper's wait");
    await assert.rejects(op, /closing/, "the op ends with Closing, like a crash there");
    assert.equal(w.store.registry.agent(A).state, "provisioned", "nothing recorded about an outcome it never saw");
    assert.ok(w.store.grants.pendingProofs().includes(A), "a durable pending proof: the helper may still act");
    // The helper finishes after the close (it lowers restore and queues the start), or never does.
    if (late) {
      delete w.resumeHook;
      const r = await resumeOp(w).request(A, held.extra);
      assert.equal(r.resumed, true, JSON.stringify(r));
      assert.deepEqual(fenceCauses(A, { dir: w.fenceDir }), []);
    }
    await w.close();
    // The next start: the pending proof first (masked, proven down), then the reconciliation (restore down: resumed).
    const w2 = await world({ resumeOp, ...dirs });
    const rec = await w2.sup.recover();
    assert.equal(rec.status, "recovered", JSON.stringify(rec));
    assert.ok(!w2.store.grants.pendingProofs().includes(A), "proven down");
    const firstMask = w2.fx.log.findIndex((l) => l[0] === "mask" && l[1] === A);
    const firstStart = w2.fx.log.findIndex((l) => (l[0] === "start" || l[0] === "helper-start") && l[1] === A);
    assert.ok(firstMask >= 0 && (firstStart === -1 || firstMask < firstStart), JSON.stringify(w2.fx.log));
    if (late) {
      assert.equal(w2.store.registry.agent(A).state, "running", "its resume happened: recorded now");
      assert.deepEqual(fenceCauses(A, { dir: w2.fenceDir }), ["lease"]);
      await w2.fire("renew");
      assert.equal(w2.fx.u(A).active, true, "started again under a fresh lease");
    } else {
      assert.equal(w2.store.registry.agent(A).state, "provisioned", "restore still up: not resumed");
      assert.deepEqual(fenceCauses(A, { dir: w2.fenceDir }), ["lease", "restore"]);
    }
    await w2.close();
  }
});

test("resume-restored closed before its helper is launched: nothing is launched, and the op ends with Closing", async () => {
  const w = await world({ resumeOp });
  await restored(w);
  let closing;
  w.barrier = async (n) => { if (n === "before_restore_resume") closing = w.sup.close(); };
  await assert.rejects(resumeRestoredOp(w), /closing/);
  await closing;
  assert.equal((w.requests ?? []).length, 0, "no helper launched after the close");
  assert.deepEqual(fenceCauses(A, { dir: w.fenceDir }), ["restore"]);
  assert.equal(w.store.registry.agent(A).state, "provisioned");
  await w.close();
});

test("the restore resume's helper wait is RESUME_HELPER_MS (10 s) by default, inside the supervisor's stop timeout", async () => {
  assert.equal(RESUME_HELPER_MS, 10_000);
  let seen;
  await requestResume(A, {
    restoreState: () => "validated", tagsOf: () => [], pairOf: () => ({ transfer: "T", receipt: "R" }),
    verifyTransferReceipt: async () => ({ transfer: { agent: A }, receipt: { agent: A, gen: 1, nonce: "N" }, transferHash: "H" }),
    checkTransferForHost: () => ({ first: false }), host: { entryGen: () => 1, recordTransfer: () => {} },
    liveLease: async () => ({ gen: 1, lease_id: newId(), lg: 1 }), node: "/n", main: "/m",
    run: async (argv, o) => { seen = o.ms; return { code: 0, stdout: '{"resumed":true,"reason":null}' }; },
  });
  assert.equal(seen, RESUME_HELPER_MS);
});

// ---- the suspend gate (lease-on r1.5 §6.2): requests and responses are bound to the gate's generation

const gateWrite = (w, sleep, reopen) => {
  for (const [name, text] of [["sleep", sleep], ["reopen", reopen]]) {
    const f = join(w.leaseDir, name);
    rmSync(f, { force: true });
    if (text !== null) writeFileSync(f, text, { mode: 0o644 });
  }
};
const S = (gen, phase = "post") => JSON.stringify({ gen, phase, pre_ok: true, pre_at: 0 });
const R = (gen) => JSON.stringify({ gen });

test("the gate: no request while it is closed, and the renewal keeps its schedule; the record carries the gate's generation", async () => {
  const w = await world();
  await granted(w, [A]);
  gateWrite(w, S(1, "pre"), null); // a PRE ran (sleep without reopen: closed)
  await w.fire("renew");
  assert.equal(w.sent.length, 0, "no request while the gate is closed");
  assert.equal(w.record(A).state, "missing");
  assert.ok(w.pending.some((h) => h.ms === RENEW_MS), "the next renewal is scheduled");
  gateWrite(w, S(1), R(1)); // post, then the supervisor's reopen
  w.advance(RENEW_MS);
  await w.fire("renew");
  assert.equal(w.sent.length, 1);
  assert.equal(w.record(A).rec.sg, 1, "published under the generation the request was made in");
  assert.equal(w.fx.u(A).active, true);
  await w.close();
});

test("the gate: a response to a request made before a suspend is ignored after it (`suspended`), counted, and its request consumed", async () => {
  const w = await world();
  await granted(w, [A]);
  let held = null;
  w.send = async (bytes) => { held = bytes; return null; }; // the response is delayed
  await w.fire("renew");
  assert.ok(held, "a request went out at generation 0");
  delete w.send;
  gateWrite(w, S(1), R(1)); // a suspend and its reopen happened meanwhile: open at 1
  const r = await w.sup.submit({ kind: "lease-response", authority: "host", agent: A, bytes: await w.respond(held) });
  assert.deepEqual(r, { status: "ignored", reason: "suspended" });
  assert.equal(w.machine.counts.suspended, 1);
  assert.equal(w.machine.outstanding(A), null, "a response counts at most once");
  assert.equal(w.record(A).state, "missing", "nothing published");
  assert.equal(w.fx.u(A).active, false);
  // a request made AFTER the reopen succeeds (the positive control)
  w.advance(RENEW_MS);
  await w.fire("renew");
  assert.equal(w.record(A).rec.sg, 1);
  assert.equal(w.fx.u(A).active, true);
  await w.close();
});

test("the gate: with no gate files at all the gate is open at 0, so a real host before any suspend behaves as before", async () => {
  const w = await world();
  await granted(w, [A]);
  await w.fire("renew");
  assert.equal(w.record(A).rec.sg, 0);
  assert.equal(w.fx.u(A).active, true);
  await w.close();
});

// ---- the reopen as an executor op (lease-on r1.5 §6.5, S2): void, contain, thaw, acknowledge, then fresh leases

/** The reopen's seams over the world: a parent cgroup that a kill empties; locks that never block. */
const reopenSeams = (w) => {
  const cg = tmp("cg"), units = tmp("units");
  w.sleepSys = { calls: [], freeze: "1", procs: 1,
    cgroup: (d) => (d === cg ? d : null), kill: () => { w.sleepSys.calls.push("kill"); w.sleepSys.procs = 0; }, empty: () => w.sleepSys.procs === 0,
    freezeRead: () => w.sleepSys.freeze, freezeWrite: (_d, v) => { w.sleepSys.calls.push(`freeze=${v}`); w.sleepSys.freeze = v; },
    maskAll: async (u) => { w.sleepSys.calls.push(`mask:${u.length}`); } };
  return { dir: w.leaseDir, fenceDir: join(w.fenceDir, "lease"), unitDir: units, agentsCgroup: cg, sys: w.sleepSys,
    lock: async () => ({ release: async () => {} }), now: (() => { let x = 0; return () => (x += 100); })(), wait: async () => {}, log: () => {} };
};

test("sleep-reopen with no suspend is a NO-OP: the running agent's lease and unit are untouched (C8a)", async () => {
  const w = await world({ sleepOpts: reopenSeams });
  await granted(w, [A]);
  await w.fire("renew");
  const before = w.machine.current(A);
  assert.deepEqual(await w.sup.submit({ kind: "sleep-reopen", authority: "host" }), { status: "noop", gen: null });
  assert.deepEqual(w.machine.current(A), before);
  assert.equal(w.fx.u(A).active, true);
  assert.deepEqual(w.sleepSys.calls, []);
  await w.close();
});

test("sleep-reopen after a finished suspend: the machine voids, the agent is contained, the gate opens, and only a FRESH lease restarts it", async () => {
  const w = await world({ sleepOpts: reopenSeams });
  await granted(w, [A]);
  await w.fire("renew");
  const old = w.machine.current(A);
  assert.equal(old.sg, 0);
  gateWrite(w, S(1), null); // the hook's post for generation 1 (its PRE would have fenced and frozen already)
  const r = await w.sup.submit({ kind: "sleep-reopen", authority: "host" });
  assert.deepEqual(r, { status: "reopened", gen: 1 });
  assert.equal(w.machine.current(A), null, "voided: nothing from before the suspend is used again");
  assert.equal(w.leaseUp(A), true, "lease raised by the contain");
  assert.ok(readTombstone(A, { dir: w.leaseDir }) >= old.lg, "the old record spent");
  assert.equal(w.sleepSys.freeze, "0", "thawed after the proof");
  assert.equal(readFileSync(join(w.leaseDir, "reopen"), "utf8"), R(1));
  // the fresh renewal (due right away) gets a lease under generation 1
  await w.fire("renew");
  assert.equal(w.record(A).rec.sg, 1);
  assert.ok(w.record(A).rec.lg > old.lg);
  await w.close();
});

test("sleep-reopen is a host op only; the person, service and local authorities can't submit it", async () => {
  const w = await world({ sleepOpts: reopenSeams });
  for (const authority of ["person", "service", "local"]) {
    await assert.rejects(w.sup.submit({ kind: "sleep-reopen", authority }), (e) => e.code === "not_granted", authority);
  }
  await w.close();
});

test("C7' (iii): a reopen queued behind an in-flight resume-restored starts only after that op ends", async () => {
  const w = await world({ resumeOp, sleepOpts: reopenSeams });
  await restored(w);
  let release;
  const held = new Promise((r) => { release = r; });
  const order = [];
  w.resumeHook = async () => { order.push("resume-start"); await held; order.push("resume-end"); return { resumed: false, reason: "lease_not_live" }; };
  const resume = resumeRestoredOp(w);
  for (let i = 0; i < 200 && !order.includes("resume-start"); i++) await new Promise((r) => setImmediate(r));
  gateWrite(w, S(1), null);
  const reopen = w.sup.submit({ kind: "sleep-reopen", authority: "host" }).then((r) => { order.push("reopen"); return r; });
  for (let i = 0; i < 200; i++) await new Promise((r) => setImmediate(r));
  assert.deepEqual(w.sleepSys.calls, [], "nothing of the reopen ran while the resume op is in flight");
  release();
  await resume;
  assert.deepEqual((await reopen).status, "reopened");
  assert.deepEqual(order, ["resume-start", "resume-end", "reopen"]);
  await w.close();
});

test("C7' (iii), the REAL helper held at after_checks: a queued reopen does nothing until the resume op's result, then contains the agent", async () => {
  const w = await world({ resumeOp, sleepOpts: reopenSeams });
  await restored(w);
  const old = w.machine.current(A);
  let release, atChecks = false;
  const held = new Promise((r) => { release = r; });
  w.helperBarrier = async (n) => { if (n === "after_checks") { atChecks = true; await held; } };
  const order = [];
  let atResult;
  const resume = resumeRestoredOp(w).then((r) => {
    order.push("resume");
    atResult = { causes: fenceCauses(A, { dir: w.fenceDir }), calls: [...w.sleepSys.calls], reopen: existsSync(join(w.leaseDir, "reopen")) };
    return r;
  });
  // the helper's locks are real flocks: a real-time wait, bounded
  for (const end = Date.now() + 5000; !atChecks && Date.now() < end;) await new Promise((r) => setTimeout(r, 5));
  assert.ok(atChecks, "the helper is held at after_checks");
  gateWrite(w, S(1), null); // the hook's post for generation 1
  const reopen = w.sup.submit({ kind: "sleep-reopen", authority: "host" }).then((r) => { order.push("reopen"); return r; });
  await new Promise((r) => setTimeout(r, 200)); // the reopen's chance to run, were it not queued behind the resume
  // Nothing of the reopen before the resume op's result: no containment, kill, freeze, mask, void or reopen write.
  assert.deepEqual(w.sleepSys.calls, []);
  assert.equal(existsSync(join(w.leaseDir, "reopen")), false);
  assert.equal(w.leaseUp(A), false, "lease not raised");
  assert.deepEqual(w.machine.current(A), old, "not voided");
  assert.deepEqual(fenceCauses(A, { dir: w.fenceDir }), ["restore"]);
  assert.deepEqual(order, []);
  release();
  const r = await resume;
  assert.equal(r.status, "resumed");
  assert.deepEqual(atResult, { causes: [], calls: [], reopen: false }, "at the op's result: restore lowered, nothing of the reopen yet");
  assert.deepEqual(await reopen, { status: "reopened", gen: 1 });
  assert.deepEqual(order, ["resume", "reopen"]);
  // Then the reopen contains it: voided, `lease` raised, the record spent, killed, thawed after the proof, acknowledged.
  assert.equal(w.machine.current(A), null);
  assert.deepEqual(fenceCauses(A, { dir: w.fenceDir }), ["lease"]);
  assert.ok(readTombstone(A, { dir: w.leaseDir }) >= old.lg);
  assert.ok(w.sleepSys.calls.includes("kill"));
  assert.equal(w.sleepSys.freeze, "0");
  assert.equal(readFileSync(join(w.leaseDir, "reopen"), "utf8"), R(1));
  await w.close();
});

// ---- TESTS H2 (#168): the reopen is close-aware: close() cuts it short, and nothing of it runs after the close

const held = () => { let release; const p = new Promise((r) => { release = r; }); return { p, release }; };
const realWait = async (fn, ms = 5000) => { for (const end = Date.now() + ms; !fn() && Date.now() < end;) await new Promise((r) => setTimeout(r, 5)); return fn(); };

test("TESTS H2: close() during a reopen whose mask is held returns at once; the op ends Closing; the late mask never leads to a freeze, kill, thaw or acknowledgement", async () => {
  const w = await world({ sleepOpts: reopenSeams });
  await granted(w, [A]);
  await w.fire("renew");
  gateWrite(w, S(1), null);
  const h = held();
  let masked = false;
  w.sleepSys.maskAll = async () => { w.sleepSys.calls.push("mask"); masked = true; await h.p; };
  const op = w.sup.submit({ kind: "sleep-reopen", authority: "host" }).then(() => "resolved", (e) => e?.message);
  assert.ok(await realWait(() => masked), "the reopen is at its mask");
  const closing = w.sup.close();
  assert.equal(await Promise.race([closing.then(() => "closed"), new Promise((r) => setTimeout(() => r("held"), 100))]), "closed", "close isn't held by the mask");
  assert.equal(await op, "closing");
  h.release();
  await new Promise((r) => setTimeout(r, 50));
  assert.deepEqual(w.sleepSys.calls, ["mask"], "nothing after the late mask: no freeze, kill or thaw");
  assert.equal(w.sleepSys.freeze, "1", "the parent stays frozen");
  assert.equal(existsSync(join(w.leaseDir, "reopen")), false, "never acknowledged");
  assert.equal(readGate({ dir: w.leaseDir, clock: w.clock }).open, false, "the gate stays closed, for the next start's reopen");
  await w.close();
});

test("TESTS H2: close() while the reopen waits for an activation lock: the op ends Closing, a lock granted after the close is released, nothing is spent, thawed or acknowledged", async () => {
  const w = await world({ sleepOpts: reopenSeams });
  await granted(w, [A]);
  await w.fire("renew");
  const lg = w.machine.current(A).lg;
  gateWrite(w, S(1), null);
  const h = held();
  let asked = false, released = 0;
  w.sup.sleepOpts.lock = async () => { asked = true; await h.p; return { release: async () => { released++; } }; };
  const op = w.sup.submit({ kind: "sleep-reopen", authority: "host" }).then(() => "resolved", (e) => e?.message);
  assert.ok(await realWait(() => asked), "the reopen waits for the lock");
  assert.equal(await Promise.race([w.sup.close().then(() => "closed"), new Promise((r) => setTimeout(() => r("held"), 1000))]), "closed", "close isn't held by the lock");
  assert.equal(await op, "closing");
  h.release();
  assert.ok(await realWait(() => released === 1), "the late lock was released");
  assert.ok(!(readTombstone(A, { dir: w.leaseDir }) >= lg), "nothing spent after the close");
  assert.ok(!w.sleepSys.calls.includes("freeze=0"), "never thawed");
  assert.equal(existsSync(join(w.leaseDir, "reopen")), false, "never acknowledged");
  await w.close();
});
