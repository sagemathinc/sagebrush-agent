// Host supervisor (lease wire type r3 §2.3, §2.4): the lease client, the LeaseMachine's real seams. Against the shared
// fixtures' leased chain, host certificate and keys, and the service's REAL handler (core/lease-service.mjs
// handleLease) run in process behind a fake fetch: the host's request, the service's lease, the host's verification and
// the machine's acceptance, end to end. Plus the transport's limits and the chain-behind path.
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "./host-linux-only.mjs";
import { FleetError, keyFromSeed, newId, sha256b64 } from "../lib/fleet/index.mjs";
import * as core from "../lib/fleet/core/index.mjs";
import { LEASE_ROUTE, handleLease } from "../lib/fleet/core/lease-service.mjs";
import { RESPONSE_MAX, SEND_CLASSES, leaseDeps } from "../lib/fleet/host/lease-client.mjs";
import { LeaseMachine } from "../lib/fleet/host/lease-machine.mjs";
import { readRecord } from "../lib/fleet/host/lease.mjs";

const F = JSON.parse(readFileSync(new URL("./fixtures/fleet-fixtures.json", import.meta.url), "utf8"));
const E = F.leases;
const enc = (s) => new TextEncoder().encode(s);
const base = { aud: F.aud, fleet: F.ids.fleet };
const H = keyFromSeed(Buffer.from(F.keys.host.seed, "hex"));
const L2 = keyFromSeed(Buffer.from(F.keys["lease-2"].seed, "hex"));
const OTHER = keyFromSeed(new Uint8Array(32).fill(5));
const ORIGIN = "https://dev.sagebrush.space";
const NOW = 1_800_000_000_000;
const BOOT = "0f6c2b5e-8d3a-4c1e-9b7f-2a4d6e8f0a1c";

const full = await core.replayChain(E.chain.map(enc), base);
const cert = await core.verifyHostCert(enc(E.host_cert), { ...base, chain: full });

/** The service: the real handler, with an in-memory ctx over the fixtures (the lease key pinned at the chain's head). */
function service({ chain = full, issue = async () => ({ ok: true }) } = {}) {
  const calls = [];
  const ctx = {
    aud: F.aud, now: NOW,
    host: async (h) => (h === cert.body.host ? { fleet: F.ids.fleet, sign_key: cert.signRaw, fingerprint: cert.body.fingerprint, revoked: false } : null),
    chain: async () => chain,
    leaseKey: { id: F.ids.lease_2, raw: L2.raw, sign: (b) => L2.sign(b) },
    bucket: async () => true,
    leases: { issue: async (d) => { calls.push(d); return issue(d); } },
  };
  const fetch = async (url, init) => {
    calls.push({ url, redirect: init.redirect, method: init.method });
    const r = await handleLease({ method: init.method, target: new URL(url).pathname, scheme: new URL(url).protocol.slice(0, -1), source: "test", body: init.body }, ctx);
    return new Response(r.body, { status: r.status, headers: r.headers });
  };
  return { fetch, calls };
}

const deps = (over = {}) => leaseDeps({ ...base, signer: H, cert, chain: () => full, origin: ORIGIN, fetch: service().fetch, ...over });
const reqBody = (over = {}) => ({ ...base, agent: F.ids.agent, host: cert.body.host, gen: 3, nonce: Buffer.from(newId().slice(0, 16)).toString("base64url"), boot_id: BOOT, at_ms: NOW, ...over });
const outstandingOf = (body, hash) => ({ request: hash, agent: body.agent, gen: body.gen, nonce: body.nonce, boot_id: body.boot_id });

test("construction binds the signing key to the verified certificate, and takes an https origin only", () => {
  assert.ok(deps());
  for (const [what, over] of [
    ["another key", { signer: OTHER }],
    ["the right raw key under another key id", { signer: { ...H, key: OTHER.key } }],
    ["the right key id with another raw key", { signer: { ...OTHER, key: H.key } }],
    ["no certificate's sign key", { cert: { body: cert.body } }],
    ["a certificate without a host", { cert: { ...cert, body: { ...cert.body, host: "nope" } } }],
    ["http", { origin: "http://dev.sagebrush.space" }],
    ["a path", { origin: `${ORIGIN}/api` }],
    ["credentials", { origin: "https://u:p@dev.sagebrush.space" }],
    ["a query", { origin: `${ORIGIN}/?x=1` }],
    ["no chain getter", { chain: null }],
  ]) assert.throws(() => deps(over), (e) => e instanceof FleetError && e.code === "bad_form", what);
});

test("context: this host's certified id and fingerprint, and the host's OWN chain, read afresh at every call", () => {
  let reads = 0;
  const d = deps({ chain: () => { reads++; return full; } });
  const c1 = d.context(), c2 = d.context();
  assert.equal(reads, 2);
  assert.deepEqual({ ...c1, chain: null }, { ...base, chain: null, host: cert.body.host, hostKey: cert.body.fingerprint });
  assert.equal(c2.chain, full);
});

test("sign: the host's envelope, hashed over its SIGNED bytes (the service's verifyLeaseRequest agrees); never another host's body", async () => {
  const d = deps();
  const body = reqBody();
  const { bytes, hash } = await d.sign(body);
  const v = await core.verifyLeaseRequest(bytes, { ...base, cert });
  assert.equal(hash, v.hash);
  assert.notEqual(hash, sha256b64(bytes), "not the envelope's hash");
  await assert.rejects(d.sign({ ...body, host: newId() }), (e) => e.code === "bad_form");
  await assert.rejects(d.sign({ ...body, fleet: newId() }), (e) => e.code === "bad_form");
});

test("interop end to end: the host's request, the service's REAL handler, the host's verification, the machine's acceptance", async () => {
  // The bare exchange: the lease names the request by the hash the host computed.
  const svc = service();
  const d = deps({ fetch: svc.fetch });
  const body = reqBody();
  const { bytes, hash } = await d.sign(body);
  const resp = await d.send(bytes);
  assert.ok(resp instanceof Uint8Array, JSON.stringify(d.counts));
  assert.deepEqual(svc.calls[0], { url: `${ORIGIN}${LEASE_ROUTE}`, redirect: "error", method: "POST" });
  assert.equal(svc.calls[1].request, hash, "the service's request hash is the host's");
  const v = await d.verify(resp, { ...d.context(), outstanding: outstandingOf(body, hash) });
  assert.equal(v.body.request, hash);
  assert.equal(v.body.host_key, cert.body.fingerprint);
  // Through the LeaseMachine: request, send, accept, arm and publish.
  const dir = mkdtempSync(join(tmpdir(), "sb-lc-")), timers = {};
  const clock = { boot: () => 1_000_000, mono: () => 1_000_000_000 + 7_000_000_000 };
  const sys = {
    arm: async (argv) => { const unit = argv.find((a) => a.startsWith("--unit=")).slice(7); timers[`${unit}.timer`] = { active: "active", sub: "waiting", next: Number(argv.find((a) => a.startsWith("--on-boot=")).slice(10, -2)) }; },
    timer: async (u) => timers[u], disarm: async () => {},
  };
  const m = new LeaseMachine({ ...d, submit: async () => ({}), dir, sys, clock, timers: { set: () => ({}), clear: () => {} },
    bootId: () => BOOT, wall: () => NOW });
  const rq = await m.request(F.ids.agent, 3);
  const r = await m.accept(F.ids.agent, await d.send(rq), 3);
  assert.equal(r.accepted, true, JSON.stringify(r));
  assert.deepEqual(readRecord(F.ids.agent, { dir }).rec, r.rec);
  assert.equal(r.rec.expiry_tick, 1_000_000 + 600_000);
});

test("the response cap is the largest VALID execution lease exactly: that one is read, one byte more is refused", async () => {
  // The largest valid lease: every integer at its maximum, the longer audience; sealed by the real lease key.
  const body = { fleet: F.ids.fleet, aud: "https://dev.sagebrush.space", agent: F.ids.agent, host: cert.body.host, host_key: cert.body.fingerprint,
    gen: Number.MAX_SAFE_INTEGER, lease_id: newId(), ttl_ms: 600_000, nonce: "A".repeat(22), boot_id: BOOT, request: "A".repeat(43), chain_seq: Number.MAX_SAFE_INTEGER };
  const signer = { kind: "lease", id: F.ids.lease_2, alg: "ed25519", key: L2.key };
  const big = core.seal ? await core.seal("sb.execution-lease.v1", signer, body, L2) : null;
  assert.equal(big.length, RESPONSE_MAX, "derived from the schema, it equals the largest real envelope");
  const serve = (bytes, chunk) => async () => new Response(new ReadableStream({
    start(c) { for (let i = 0; i < bytes.length; i += chunk) c.enqueue(bytes.slice(i, i + chunk)); c.close(); },
  }), { status: 200 });
  const ok = deps({ fetch: serve(big, 100) });
  assert.deepEqual(await ok.send(enc("x")), big);
  const over = new Uint8Array(RESPONSE_MAX + 1).fill(65);
  let cancelled = false;
  const d = deps({ fetch: async () => new Response(new ReadableStream({
    start(c) { for (let i = 0; i < over.length; i += 64) c.enqueue(over.slice(i, i + 64)); },
    cancel() { cancelled = true; },
  }), { status: 200 }) });
  assert.equal(await d.send(enc("x")), null);
  assert.equal(d.counts.oversize, 1);
  assert.equal(cancelled, true, "the stream was cancelled at the cap, never read whole");
});

test("non-200, redirects and network failures: null, counted by class, and an unread body is cancelled", async () => {
  let cancelled = 0;
  const stream = () => new ReadableStream({ start(c) { c.enqueue(enc("{\"error\":\"x\"}")); }, cancel() { cancelled++; } });
  const d1 = deps({ fetch: async () => new Response(stream(), { status: 403 }) });
  assert.equal(await d1.send(enc("x")), null);
  assert.equal(d1.counts.status, 1);
  await new Promise((r) => setTimeout(r, 10)); // (the cancel is never awaited by send)
  assert.equal(cancelled, 1, "the refusal's body was cancelled, never read");
  const d2 = deps({ fetch: async () => new Response(stream(), { status: 302, headers: { location: "https://evil.example/" } }) });
  assert.equal(await d2.send(enc("x")), null);
  assert.equal(d2.counts.redirect, 1);
  // fetch with redirect: "error" throws on a redirect.
  const d3 = deps({ fetch: async (_u, init) => { assert.equal(init.redirect, "error"); throw new TypeError("fetch failed", { cause: new Error("unexpected redirect") }); } });
  assert.equal(await d3.send(enc("x")), null);
  assert.equal(d3.counts.redirect, 1);
  const d4 = deps({ fetch: async () => { throw new TypeError("fetch failed", { cause: new Error("ECONNREFUSED") }); } });
  assert.equal(await d4.send(enc("x")), null);
  assert.equal(d4.counts.network, 1);
  // The real handler's refusal (a request for an unknown host's key) comes back as a status: null.
  const svc = service();
  const d5 = deps({ fetch: svc.fetch });
  const { bytes } = await d5.sign(reqBody({ at_ms: NOW - 3_600_000 }));
  assert.equal(await d5.send(bytes), null);
  assert.equal(d5.counts.status, 1);
});

test("the deadline is absolute: a body that stalls after its headers, and a fetch that ignores the abort, both end at it", { timeout: 10000 }, async () => {
  let cancelled = false;
  const stall = deps({ sendMs: 50, fetch: async () => new Response(new ReadableStream({
    start(c) { c.enqueue(enc("{")); }, cancel() { cancelled = true; },
  }), { status: 200 }) });
  const t0 = Date.now();
  assert.equal(await stall.send(enc("x")), null);
  assert.equal(stall.counts.timeout, 1);
  assert.ok(Date.now() - t0 < 2000);
  await new Promise((r) => setTimeout(r, 10));
  assert.equal(cancelled, true, "the stalled reader was cancelled");
  // A fetch that never settles and never looks at its signal.
  const deaf = deps({ sendMs: 50, fetch: () => new Promise(() => {}) });
  const t1 = Date.now();
  assert.equal(await deaf.send(enc("x")), null);
  assert.equal(deaf.counts.timeout, 1);
  assert.ok(Date.now() - t1 < 2000);
  // A body read that ignores the abort (its stream never ends, never errors).
  const deafBody = deps({ sendMs: 50, fetch: async () => new Response(new ReadableStream({ pull() { return new Promise(() => {}); } }), { status: 200 }) });
  assert.equal(await deafBody.send(enc("x")), null);
  assert.equal(deafBody.counts.timeout, 1);
});

test("a response that arrives AFTER the deadline is released unread: its body cancelled, no reader left on it", { timeout: 10000 }, async () => {
  let resolveFetch, cancelled = 0;
  const d = deps({ sendMs: 20, fetch: () => new Promise((r) => { resolveFetch = r; }) });
  assert.equal(await d.send(enc("x")), null);
  assert.equal(d.counts.timeout, 1);
  const stream = new ReadableStream({ pull() {}, cancel() { cancelled++; } });
  resolveFetch(new Response(stream, { status: 200 }));
  await new Promise((r) => setTimeout(r, 30));
  assert.equal(cancelled, 1, "the late body was cancelled");
  assert.equal(stream.locked, false, "no abandoned reader holds it");
  assert.equal(d.counts.ok, 0);
});

test("a busy event loop can't stretch the deadline: an answer available only after it is refused, on the monotonic clock", async () => {
  // The fetch blocks the loop past the deadline, so the timer can't fire before its answer resolves.
  const busy = deps({ sendMs: 10, fetch: async () => { const end = performance.now() + 60; while (performance.now() < end) { /* busy */ } return new Response(enc("{}"), { status: 200 }); } });
  assert.equal(await busy.send(enc("x")), null);
  assert.equal(busy.counts.timeout, 1);
  assert.equal(busy.counts.ok, 0);
  // ... and its body is released unread: checked right after the fetch, before any reader is opened on it.
  let cancelled = 0;
  const stream = new ReadableStream({ pull() {}, cancel() { cancelled++; } });
  const busyBody = deps({ sendMs: 10, fetch: async () => { const end = performance.now() + 60; while (performance.now() < end) { /* busy */ } return new Response(stream, { status: 200 }); } });
  assert.equal(await busyBody.send(enc("x")), null);
  await new Promise((r) => setTimeout(r, 10));
  assert.equal(cancelled, 1);
  assert.equal(stream.locked, false, "never read: no reader was opened on it");
  // The same check with an injected monotonic clock: past the deadline at acceptance is a timeout, at any status.
  let t = 0;
  const late = deps({ sendMs: 1000, mono: () => t, fetch: async () => { t = 1000; return new Response(enc("{}"), { status: 200 }); } });
  assert.equal(await late.send(enc("x")), null);
  assert.equal(late.counts.timeout, 1);
  t = 0;
  const inTime = deps({ sendMs: 1000, mono: () => t, fetch: async () => { t = 999; return new Response(enc("{}"), { status: 200 }); } });
  assert.deepEqual(await inTime.send(enc("x")), enc("{}"));
  // A response in time whose BODY ends at the deadline: refused at acceptance; 1 ms before it: accepted.
  // (highWaterMark 0: the stream pulls only when the body is read, not when it is made)
  const slowBody = (end) => () => new Response(new ReadableStream({ pull(c) { t = end; c.enqueue(enc("{}")); c.close(); } }, { highWaterMark: 0 }), { status: 200 });
  t = 0;
  const atEnd = deps({ sendMs: 1000, mono: () => t, fetch: async () => slowBody(1000)() });
  assert.equal(await atEnd.send(enc("x")), null);
  assert.equal(atEnd.counts.timeout, 1);
  t = 0;
  const justIn = deps({ sendMs: 1000, mono: () => t, fetch: async () => slowBody(999)() });
  assert.deepEqual(await justIn.send(enc("x")), enc("{}"));
});

test("device_unknown (the service's chain ahead of the host's): a chain sync is asked for, coalesced, and the lease still refused", { timeout: 10000 }, async () => {
  // The host pinned the chain before its last entry; the service signs at its own head, past the host's.
  const behind = await core.replayChain(E.chain.slice(0, -1).map(enc), base);
  const svc = service();
  let asks = 0, release;
  const pending = new Promise((r) => { release = r; });
  const d = deps({ fetch: svc.fetch, chain: () => behind, onChainBehind: () => { asks++; return pending; } });
  const lease = async () => { const body = reqBody(); const { bytes, hash } = await d.sign(body); return { resp: await d.send(bytes), out: outstandingOf(body, hash) }; };
  const a = await lease(), b = await lease();
  await assert.rejects(d.verify(a.resp, { ...d.context(), outstanding: a.out }), (e) => e.code === "device_unknown");
  await assert.rejects(d.verify(b.resp, { ...d.context(), outstanding: b.out }), (e) => e.code === "device_unknown");
  await new Promise((r) => setTimeout(r, 10));
  assert.equal(asks, 1, "coalesced while one ask is outstanding");
  assert.equal(d.counts.chain_behind, 2);
  release();
  await new Promise((r) => setTimeout(r, 10));
  // A failing callback (it throws) changes nothing: still refused, nothing unhandled.
  const unhandled = [];
  const onU = (e) => unhandled.push(e);
  process.on("unhandledRejection", onU);
  const d2 = deps({ fetch: svc.fetch, chain: () => behind, onChainBehind: () => { throw new Error("sync down"); } });
  const body = reqBody();
  const { bytes, hash } = await d2.sign(body);
  await assert.rejects(d2.verify(await d2.send(bytes), { ...d2.context(), outstanding: outstandingOf(body, hash) }), (e) => e.code === "device_unknown");
  await new Promise((r) => setTimeout(r, 20));
  process.off("unhandledRejection", onU);
  assert.deepEqual(unhandled, []);
});

test("any other refusal never asks for a sync: a bad signature, another host's key, a request not outstanding", async () => {
  const svc = service();
  let asks = 0;
  const d = deps({ fetch: svc.fetch, onChainBehind: () => { asks++; } });
  const body = reqBody();
  const { bytes, hash } = await d.sign(body);
  const resp = await d.send(bytes);
  const env = JSON.parse(new TextDecoder().decode(resp));
  const forged = enc(JSON.stringify({ ...env, sig: env.sig.replace(/^./, env.sig[0] === "A" ? "B" : "A") }));
  for (const [what, bytesX, ctx] of [
    ["a bad signature", forged, { ...d.context(), outstanding: outstandingOf(body, hash) }],
    ["another host key", resp, { ...d.context(), hostKey: "A".repeat(43), outstanding: outstandingOf(body, hash) }],
    ["another request", resp, { ...d.context(), outstanding: outstandingOf(body, "A".repeat(43)) }],
  ]) {
    await assert.rejects(d.verify(bytesX, ctx), (e) => e instanceof FleetError && e.code !== "device_unknown", what);
  }
  await new Promise((r) => setTimeout(r, 10));
  assert.equal(asks, 0);
  assert.equal(d.counts.chain_behind, 0);
});

test("health: a fixed set of numeric classes, nothing of a request or a lease", async () => {
  const d = deps();
  const body = reqBody();
  const { bytes } = await d.sign(body);
  await d.send(bytes);
  assert.deepEqual(Object.keys(d.counts).sort(), [...SEND_CLASSES, "chain_behind"].sort());
  assert.ok(Object.values(d.counts).every((v) => Number.isSafeInteger(v)));
});
