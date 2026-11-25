// The fleet Worker's execution-lease endpoint (lib/fleet/core/lease-service.mjs; r2.5 §3.8, the lease-wire note r3 §2.3)
// against an in-memory store that follows the module's contract: one serialized decision per call, the nonce first, the
// conditions re-read inside it, the grant clock only on success. A fake can't prove the real store's atomicity: the
// contract is what the Worker's D1 batch is reviewed against. Every lease the route returns is checked by the HOST's
// verifier, with the request hash the host computes itself (the SHA-256 of the request's signed bytes).
import assert from "node:assert/strict";
import { test } from "node:test";
import { FleetError, b64, enc, newId, keyFromSeed, seal, sha256b64, signedBytes, hostFingerprint, applyChainEntry as apply } from "../lib/fleet/index.mjs";
import { verifyExecutionLease } from "../lib/fleet/verify.mjs";
import {
  LEASE_BODY_MAX, LEASE_GATE_MARGIN_MS, LEASE_RATE_HOST, LEASE_RATE_SOURCE, LEASE_ROUTE, LEASE_SKEW_MS, LEASE_TTL_MS, firstLeaseGateOpen, handleLease, nextExpiry,
} from "../lib/fleet/core/lease-service.mjs";

const AUD = "https://dev.sagebrush.space";
const NOW = 1_800_000_000_000;
const BOOT = "0f6c2b5e-8d3a-4c1e-9b7f-2a4d6e8f0a1c";
const text = (b) => new TextDecoder().decode(b);
let n = 100;
const key = () => keyFromSeed(new Uint8Array(32).fill(n++));
const errorOf = (r) => (r.body.length ? JSON.parse(text(r.body)).error : null);

/** A fleet as the Worker holds it, a store following lease-service.mjs's contract, and a host to call from. */
async function world({ pinLease = true } = {}) {
  const fleet = newId(), agent = newId(), hostA = newId(), hostB = newId();
  const N = key(), nId = newId(), rec = key(), L = key(), lId = newId();
  const sN = { kind: "device", id: nId, alg: "ed25519", key: N.key };
  const entry = (seq, prev, op, extra) => seal("sb.device-chain.v1", sN, { fleet, aud: AUD, seq, prev, op, at_ms: 1, auth_time_ms: 1, ...extra }, N);
  let r = await apply(null, entry(0, "", "genesis", { device: { id: nId, alg: "ed25519", key: b64(N.raw), name: "mac", tier: "native" }, recovery_key: { alg: "ed25519", key: b64(rec.raw) } }), { aud: AUD, fleet });
  let chain = r.state;
  if (pinLease) chain = (await apply(chain, entry(1, chain.head, "lease-key", { lease_key: { id: lId, alg: "ed25519", key: b64(L.raw) } }), { aud: AUD, fleet })).state;
  const hosts = {};
  for (const h of [hostA, hostB]) {
    const H = key();
    const encRaw = new Uint8Array(32).fill(n++);
    hosts[h] = { H, fingerprint: b64(await hostFingerprint(h, H.raw, encRaw)) };
  }
  const st = {
    now: NOW,
    hosts: new Map(Object.entries(hosts).map(([h, v]) => [h, { fleet, sign_key: v.H.raw, fingerprint: v.fingerprint, revoked: false }])),
    agentRevoked: new Set(), bound: new Map([[agent, hostA]]), entryGen: new Map([[`${agent}/${hostA}`, 3]]),
    nonces: new Set(), records: new Map(), pending: new Map(), counts: new Map(), issues: 0, failIssue: false, failSign: false,
  };
  const store = {
    // (one decision at a time, like the real batch; the nonce first, then the conditions, then the clock)
    issue: async (d) => {
      st.issues++;
      if (st.failIssue) throw new Error("the batch failed");
      const nk = `${d.host}/${d.nonce}`;
      if (st.nonces.has(nk)) return { refused: "replay" };
      st.nonces.add(nk);
      const h = st.hosts.get(d.host);
      if (!h) return { refused: "unknown_host" };
      if (h.revoked) return { refused: "host_revoked" };
      if (h.fingerprint !== d.host_key) return { refused: "not_granted" };
      if (st.agentRevoked.has(d.agent)) return { refused: "agent_revoked" };
      if (st.bound.get(d.agent) !== d.host) return { refused: "not_granted" };
      if (st.entryGen.get(`${d.agent}/${d.host}`) !== d.gen) return { refused: "stale_generation" };
      const p = st.pending.get(d.agent);
      if (p && p.to === d.host) {
        const old = st.records.get(`${d.agent}/${p.from}`);
        if (!firstLeaseGateOpen({ expiresAt: old?.expires_at ?? null, acked: p.acked }, d.now)) return { refused: "not_granted" };
        st.pending.delete(d.agent);
      }
      const k = `${d.agent}/${d.host}`, prev = st.records.get(k);
      st.records.set(k, { expires_at: nextExpiry(prev?.expires_at ?? null, d.now, d.ttl_ms), lease_id: d.lease_id, gen: d.gen, request: d.request });
      return { ok: true };
    },
  };
  /** A transfer's apply, as its own serialized decision on the same rows. */
  const transfer = (to, gen) => { const from = st.bound.get(agent); st.bound.set(agent, to); st.entryGen.set(`${agent}/${to}`, gen); st.pending.set(agent, { from, to, acked: false }); };
  const ctx = (over = {}) => ({
    aud: AUD, get now() { return st.now; },
    host: async (h) => st.hosts.get(h) ?? null,
    chain: async (f) => (f === fleet ? chain : null),
    leaseKey: { id: lId, raw: L.raw, sign: (b) => { if (st.failSign) throw new Error("no signature"); return L.sign(b); } },
    bucket: async (k, limit) => { const c = (st.counts.get(k) ?? 0) + 1; st.counts.set(k, c); return c <= limit; },
    leases: store,
    ...over,
  });
  /** A host's request: its bytes and the outstanding entry it keeps, with the hash computed the host's way. */
  const request = (h = hostA, extra = {}, signWith = null) => {
    const hs = { kind: "host", id: h, alg: "ed25519", key: hosts[h].H.key };
    const body = { fleet, aud: AUD, agent, host: h, gen: 3, nonce: b64(new Uint8Array(16).fill(n++ & 255)), boot_id: BOOT, at_ms: st.now, ...extra };
    const bytes = seal("sb.lease-request.v1", hs, body, signWith ?? hosts[h].H);
    const outstanding = { request: sha256b64(signedBytes("sb.lease-request.v1", hs, body)), agent, gen: body.gen, nonce: body.nonce, boot_id: BOOT };
    return { bytes, body, outstanding };
  };
  const send = (bytes, c = ctx(), over = {}) => handleLease({ method: "POST", target: LEASE_ROUTE, scheme: "https", source: "198.51.100.7", body: bytes, ...over }, c);
  /** The host's own check of an answer. */
  const hostAccepts = async (r, q, h = hostA) => {
    assert.equal(r.status, 200, `status ${r.status} ${text(r.body)}`);
    return verifyExecutionLease(r.body, { aud: AUD, fleet, chain, host: h, hostKey: hosts[h].fingerprint, outstanding: q.outstanding });
  };
  return { fleet, agent, hostA, hostB, hosts, st, ctx, request, send, hostAccepts, transfer, L, chain };
}

test("a renewal: the host's own verifier accepts the lease, the grant clock is NOW + ttl, and the nonce is spent", async () => {
  const w = await world();
  const q = w.request();
  const v = await w.hostAccepts(await w.send(q.bytes), q);
  assert.equal(v.body.ttl_ms, LEASE_TTL_MS);
  assert.equal(v.body.request, q.outstanding.request, "the request named by the hash the host computed");
  assert.equal(v.body.host_key, w.hosts[w.hostA].fingerprint);
  assert.deepEqual(w.st.records.get(`${w.agent}/${w.hostA}`), { expires_at: NOW + LEASE_TTL_MS, lease_id: v.body.lease_id, gen: 3, request: q.outstanding.request });
  assert.equal(w.st.nonces.size, 1);
});

test("transport: another route, method or scheme, and a body over 4 KiB, each refused before anything is read or written", async () => {
  const w = await world();
  const q = w.request();
  assert.equal((await w.send(q.bytes, w.ctx(), { target: "/api/fleet/v1/host/leases" })).status, 404);
  assert.equal((await w.send(q.bytes, w.ctx(), { method: "GET" })).status, 405);
  assert.equal((await w.send(q.bytes, w.ctx(), { scheme: "http" })).status, 403);
  const big = await w.send(new Uint8Array(LEASE_BODY_MAX + 1), w.ctx());
  assert.deepEqual([big.status, errorOf(big)], [413, "limit"]);
  assert.equal(w.st.counts.size + w.st.nonces.size + w.st.records.size + w.st.issues, 0, "no bucket, nonce, record or decision");
});

test("rate limits: per source before authentication, per host after it; over either is 429 and writes nothing else", async () => {
  const w = await world();
  w.st.counts.set("lease-src:198.51.100.7", LEASE_RATE_SOURCE.limit);
  let r = await w.send(w.request().bytes);
  assert.deepEqual([r.status, errorOf(r)], [429, "rate"]);
  assert.equal(w.st.counts.has(`lease-host:${w.hostA}`), false, "the host's bucket isn't reached before authentication");
  w.st.counts.clear();
  w.st.counts.set(`lease-host:${w.hostA}`, LEASE_RATE_HOST.limit);
  r = await w.send(w.request().bytes);
  assert.deepEqual([r.status, errorOf(r)], [429, "rate"]);
  assert.equal(w.st.nonces.size + w.st.records.size + w.st.issues, 0);
});

test("before the transaction: form, audience, window, signature and host refusals consume no nonce and move no clock", async () => {
  const w = await world();
  const cases = [
    ["not canonical JSON", enc("{\"v\": 1}"), "bad_form"],
    ["another audience", w.request(w.hostA, { aud: "https://sagebrush.space" }).bytes, "bad_audience"],
    ["another type", seal("sb.grant-ack.v1", { kind: "host", id: w.hostA, alg: "ed25519", key: w.hosts[w.hostA].H.key }, { fleet: w.fleet, aud: AUD, host: w.hostA, gen: 1, at_ms: NOW }, w.hosts[w.hostA].H), "bad_form"],
    ["gen 0", w.request(w.hostA, { gen: 0 }).bytes, "bad_form"],
    ["at_ms 1 ms past the window", w.request(w.hostA, { at_ms: NOW + LEASE_SKEW_MS + 1 }).bytes, "clock_skew"],
    ["at_ms 1 ms before the window", w.request(w.hostA, { at_ms: NOW - LEASE_SKEW_MS - 1 }).bytes, "clock_skew"],
    ["signed by another key", w.request(w.hostA, {}, key()).bytes, "bad_signature"],
    ["an unpaired host", (() => { const H = key(), h = newId(); return seal("sb.lease-request.v1", { kind: "host", id: h, alg: "ed25519", key: H.key }, { fleet: w.fleet, aud: AUD, agent: w.agent, host: h, gen: 3, nonce: b64(new Uint8Array(16)), boot_id: BOOT, at_ms: NOW }, H); })(), "unknown_host"],
  ];
  for (const [name, bytes, code] of cases) assert.equal(errorOf(await w.send(bytes)), code, name);
  const skew = await w.send(w.request(w.hostA, { at_ms: NOW + LEASE_SKEW_MS + 1 }).bytes);
  assert.deepEqual(JSON.parse(text(skew.body)), { error: "clock_skew", service_time_ms: NOW, skew_ms: LEASE_SKEW_MS + 1 });
  w.st.hosts.get(w.hostA).revoked = true;
  assert.equal(errorOf(await w.send(w.request().bytes)), "host_revoked");
  assert.equal(w.st.nonces.size + w.st.records.size + w.st.issues, 0);
  w.st.hosts.get(w.hostA).revoked = false;
  for (const at of [NOW + LEASE_SKEW_MS, NOW - LEASE_SKEW_MS]) {
    const q = w.request(w.hostA, { at_ms: at });
    await w.hostAccepts(await w.send(q.bytes), q);
  }
});

test("the fleet's chain must pin this lease key at its head: none, or another, and nothing is signed or written", async () => {
  const none = await world({ pinLease: false });
  assert.equal(errorOf(await none.send(none.request().bytes)), "not_granted");
  assert.equal(none.st.issues + none.st.nonces.size, 0);
  const other = await world();
  const K = key();
  const r = await other.send(other.request().bytes, other.ctx({ leaseKey: { id: newId(), raw: K.raw, sign: (b) => K.sign(b) } }));
  assert.equal(errorOf(r), "not_granted");
  assert.equal(other.st.issues, 0);
});

test("the transaction's refusals: each spends the nonce, never moves the grant clock, and a copy is then replay", async () => {
  const w = await world();
  const before = () => JSON.stringify([...w.st.records]);
  const refusals = [
    ["stale generation", () => w.st.entryGen.set(`${w.agent}/${w.hostA}`, 4), () => w.st.entryGen.set(`${w.agent}/${w.hostA}`, 3), "stale_generation"],
    ["agent revoked", () => w.st.agentRevoked.add(w.agent), () => w.st.agentRevoked.clear(), "agent_revoked"],
    ["re-paired between the signature check and the batch", () => {}, () => {}, "not_granted"],
  ];
  const q0 = w.request();
  await w.hostAccepts(await w.send(q0.bytes), q0);
  for (const [name, set, unset, code] of refusals) {
    set();
    const snapshot = before(), q = w.request();
    // (the third: the store sees another fingerprint than the one verified, as after a re-pairing in between)
    const c = name.startsWith("re-paired") ? w.ctx({ leases: { issue: (d) => w.ctx().leases.issue({ ...d, host_key: b64(new Uint8Array(32).fill(1)) }) } }) : w.ctx();
    const r = await w.send(q.bytes, c);
    assert.deepEqual([r.status, errorOf(r)], [code === "stale_generation" ? 409 : 403, code], name);
    assert.equal(before(), snapshot, `${name}: no clock moved`);
    unset();
    assert.equal(errorOf(await w.send(q.bytes)), "replay", `${name}: its copy`);
    assert.equal(before(), snapshot);
  }
});

test("two concurrent copies of one request: exactly one lease and one clock update", async () => {
  const w = await world();
  const q = w.request();
  const rs = await Promise.all([w.send(q.bytes), w.send(q.bytes)]);
  assert.deepEqual(rs.map((r) => r.status).sort(), [200, 409]);
  assert.equal(errorOf(rs.find((r) => r.status === 409)), "replay");
  assert.equal(w.st.records.size, 1);
  await w.hostAccepts(rs.find((r) => r.status === 200), q);
});

test("the grant clock keeps the max: a later lease moves it forward, and a shorter one never pulls it back", async () => {
  assert.equal(nextExpiry(null, NOW, 600_000), NOW + 600_000);
  assert.equal(nextExpiry(NOW + 600_000, NOW + 1, 100), NOW + 600_000, "a shorter lease after a longer one");
  assert.equal(nextExpiry(NOW + 600_000, NOW + 120_000, 600_000), NOW + 720_000);
  const w = await world();
  await w.send(w.request().bytes);
  w.st.now = NOW + 120_000;
  await w.send(w.request().bytes);
  assert.equal(w.st.records.get(`${w.agent}/${w.hostA}`).expires_at, NOW + 120_000 + LEASE_TTL_MS);
});

test("the first-lease gate is strict: closed at expires_at + 5 min, open 1 ms after, or once a fence ack is recorded", async () => {
  const e = NOW + LEASE_TTL_MS;
  assert.equal(firstLeaseGateOpen({ expiresAt: e, acked: false }, e + LEASE_GATE_MARGIN_MS - 1), false);
  assert.equal(firstLeaseGateOpen({ expiresAt: e, acked: false }, e + LEASE_GATE_MARGIN_MS), false, "equality is closed");
  assert.equal(firstLeaseGateOpen({ expiresAt: e, acked: false }, e + LEASE_GATE_MARGIN_MS + 1), true);
  assert.equal(firstLeaseGateOpen({ expiresAt: e, acked: true }, NOW), true, "a valid fence ack");
  assert.equal(firstLeaseGateOpen({ expiresAt: null, acked: false }, NOW), true, "the old host never held a lease");
});

test("renewal first, then the transfer: the record is there, and the new host's first lease waits on it, strictly", async () => {
  const w = await world();
  await w.send(w.request().bytes);
  w.transfer(w.hostB, 7);
  const e = NOW + LEASE_TTL_MS;
  for (const [at, ok] of [[e + LEASE_GATE_MARGIN_MS - 1, false], [e + LEASE_GATE_MARGIN_MS, false], [e + LEASE_GATE_MARGIN_MS + 1, true]]) {
    w.st.now = at;
    const q = w.request(w.hostB, { gen: 7, at_ms: at });
    const r = await w.send(q.bytes);
    if (ok) await w.hostAccepts(r, q, w.hostB);
    else assert.equal(errorOf(r), "not_granted", `at ${at - e}`);
  }
  // (the old host's renewals after the move: not_granted, and its clock never moves again)
  const old = w.st.records.get(`${w.agent}/${w.hostA}`).expires_at;
  assert.equal(errorOf(await w.send(w.request(w.hostA, { at_ms: w.st.now }).bytes)), "not_granted");
  assert.equal(w.st.records.get(`${w.agent}/${w.hostA}`).expires_at, old);
});

test("the transfer first, then the old host's renewal: not_granted, its nonce spent, no clock written", async () => {
  const w = await world();
  w.transfer(w.hostB, 7);
  const q = w.request();
  assert.equal(errorOf(await w.send(q.bytes)), "not_granted");
  assert.equal(w.st.records.size, 0);
  assert.equal(errorOf(await w.send(q.bytes)), "replay");
  // (no lease ever granted to the old host: the new host's first lease isn't held back by one)
  const qb = w.request(w.hostB, { gen: 7 });
  await w.hostAccepts(await w.send(qb.bytes), qb, w.hostB);
});

test("the batch failing: 503 and nothing signed; signing failing after the commit: 503, and the record still gates a move", async () => {
  const w = await world();
  w.st.failIssue = true;
  let r = await w.send(w.request().bytes);
  assert.deepEqual([r.status, r.body.length], [503, 0]);
  w.st.failIssue = false;
  w.st.failSign = true;
  r = await w.send(w.request().bytes);
  assert.deepEqual([r.status, r.body.length], [503, 0]);
  w.st.failSign = false;
  assert.equal(w.st.records.get(`${w.agent}/${w.hostA}`).expires_at, NOW + LEASE_TTL_MS, "committed, never sent: the record stands");
  w.transfer(w.hostB, 7);
  w.st.now = NOW + LEASE_TTL_MS + LEASE_GATE_MARGIN_MS;
  assert.equal(errorOf(await w.send(w.request(w.hostB, { gen: 7, at_ms: w.st.now }).bytes)), "not_granted", "the unsent lease still holds the gate");
});

test("a refused request never reaches the host as a lease: the answer is unsigned, and a lease the host didn't ask for fails its check", async () => {
  const w = await world();
  const q = w.request(), other = w.request();
  const r = await w.send(q.bytes);
  await assert.rejects(() => w.hostAccepts(r, other), (e) => e instanceof FleetError && e.code === "not_granted");
});

test("the service clock is sampled twice: the window check and its refusal agree, and the grant clock is the issue-time sample", async () => {
  const w = await world();
  // (a clock that moves on every read, as a stepping provider could)
  const reads = [];
  // (defined on the ctx itself: spreading a getter into an object would read it once)
  const moving = (start, step) => { let t = start; return Object.defineProperty(w.ctx(), "now", { get() { const v = t; t += step; reads.push(v); return v; } }); };
  const q = w.request(w.hostA, { at_ms: NOW + LEASE_SKEW_MS + 1 });
  const r = await w.send(q.bytes, moving(NOW, 1000));
  assert.deepEqual(JSON.parse(text(r.body)), { error: "clock_skew", service_time_ms: NOW, skew_ms: LEASE_SKEW_MS + 1 }, "one sample for the comparison and both fields");
  assert.equal(reads.length, 1);
  reads.length = 0;
  let seen = null;
  const c = moving(NOW, 1000);
  const inner = c.leases.issue;
  c.leases = { issue: (d) => { seen = d.now; return inner(d); } };
  const q2 = w.request();
  await w.hostAccepts(await w.send(q2.bytes, c), q2);
  assert.equal(reads.length, 2, "read exactly twice");
  assert.equal(seen, reads[1], "the decision gets the second sample");
  assert.equal(w.st.records.get(`${w.agent}/${w.hostA}`).expires_at, reads[1] + LEASE_TTL_MS);
  // (a clock that isn't a finite safe integer fails closed: nothing decided, nothing signed)
  const issues = w.st.issues;
  for (const bad of [NaN, Infinity, -1, 1.5]) assert.equal((await w.send(w.request().bytes, w.ctx({ now: bad }))).status, 500, String(bad));
  assert.equal(w.st.issues, issues);
});
