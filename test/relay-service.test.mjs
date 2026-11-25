// The browser relay's HTTP side (lib/fleet/relay/service.mjs), end to end on loopback with real WebSockets and a fake
// fleet Worker: a full open-handshake-commit-forward flow; ingress refusals that make no control-plane call; replay,
// including across a restart; the limits before admission; facts that aren't the query's; a late admit answer after a
// revocation; the feed's availability; raw-frame ingress (sizes from the frame header, fragments, RSV bits, no
// compression, interleaved pings with no automatic pong); and logs with no secret values.
// (Not named fleet-*: CI's fleet-node22 job installs no dependencies, and this file needs `ws`, a pinned dependency
//  of the agent that the main test jobs install. The relay's other test files need nothing and stay in that set.)

import assert from "node:assert/strict";
import { test } from "node:test";
import { connect } from "node:net";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { WebSocket, WebSocketServer } from "ws";
import { openTarget, COMMIT_ROUTE, RECORD_HEADER_MAX } from "../lib/fleet/core/relay.mjs";
import { controlKey } from "../lib/fleet/core/control.mjs";
import { openStore } from "../lib/fleet/relay/store.mjs";
import { controlClient } from "../lib/fleet/relay/control.mjs";
import { Slots, CODES } from "../lib/fleet/relay/slots.mjs";
import { Feed } from "../lib/fleet/relay/feed.mjs";
import { createRelayServer, INGRESS, SOURCE_HEADER, APP_RECORD_MAX_MS } from "../lib/fleet/relay/service.mjs";
import { CONSUMED_MS } from "../lib/fleet/relay/store.mjs";
import { manualClock, FakeWorker, ids, rid, settle, KEY_TEXT } from "./fleet-relay-harness.mjs";

const KEY = controlKey(KEY_TEXT());

async function relay({ store = openStore(":memory:"), ingress = INGRESS, worker = new FakeWorker(KEY), wallNow = () => Date.now() } = {}) {
  const clock = manualClock(), log = [];
  const control = controlClient({ transport: worker.transport, key: KEY, wallNow });
  const slots = new Slots({ clock, wallNow, log: (o) => log.push(o) });
  const feed = new Feed({ control, store, slots, clock, log: (o) => log.push(o) });
  const { server, stats } = createRelayServer({ control, store, slots, feed, clock, log: (o) => log.push(o), ingress, wallNow, WebSocketServer });
  feed.start(); await settle();
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const port = server.address().port;
  const live = new Set();
  return {
    clock, log, worker, slots, feed, store, port, server, live, stats,
    async close() { for (const w of live) w.terminate(); feed.stop(); slots.closeAll(1001, "test over"); server.closeAllConnections(); await new Promise((r) => server.close(r)); },
  };
}

const fields = (role, t, over = {}) => ({ role, fleet: t.fleet, session: t.session, agent: t.agent, browser_gen: 1, host_gen: 1, resume_n: 0, ...over });
/** Open a WebSocket as `role`; resolves { ws } or { status }. */
function open(r, role, t, { over = {}, headers = {}, nonce = rid(), request = rid() } = {}) {
  const roleHeaders = role === "host" ? { "sagebrush-sig": `host=${t.host};gen=${over.host_gen ?? 1};nonce=${nonce}` }
    : { "sagebrush-browser-record": t.host, "sagebrush-request": request, "sagebrush-relay-token": r.worker.issueToken(t.account) };
  const ws = new WebSocket(`ws://127.0.0.1:${r.port}${openTarget(fields(role, t, over))}`, { headers: Object.fromEntries(Object.entries({ ...roleHeaders, ...headers }).filter(([, v]) => v !== undefined)), perMessageDeflate: false });
  r.live.add(ws);
  return new Promise((resolve) => {
    ws.on("open", () => resolve({ ws, nonce, request }));
    ws.on("unexpected-response", (_req, res) => { resolve({ status: res.statusCode }); res.resume(); });
    ws.on("error", () => resolve({ status: "error" }));
  });
}
const nextMessage = (ws) => new Promise((r) => ws.once("message", (d) => r(Buffer.from(d))));
const closed = (ws) => new Promise((r) => (ws.readyState === 3 ? r(null) : ws.once("close", (code) => r(code))));
async function commit(r, t, h, a, { gen = 1, nonce = rid() } = {}) {
  const body = Buffer.from(JSON.stringify({ fleet: t.fleet, session: t.session, agent: t.agent, browser_gen: 1, resume_n: 0, host_nonce: h.nonce, app_request: a.request }));
  const res = await fetch(`http://127.0.0.1:${r.port}${COMMIT_ROUTE}`, { method: "POST", body, headers: { "sagebrush-sig": `host=${t.host};gen=${gen};nonce=${nonce}`, "content-type": "application/json" } });
  return { status: res.status, body: await res.json() };
}

test("a full flow: host and app open, the handshake passes, the commit switches, and binary messages flow both ways", async () => {
  const r = await relay(), t = ids();
  try {
    const h = await open(r, "host", t), a = await open(r, "app", t);
    assert.ok(h.ws && a.ws);
    a.ws.send(Buffer.from("noise-1"));
    assert.equal(String(await nextMessage(h.ws)), "noise-1");
    h.ws.send(Buffer.from("noise-2"));
    assert.equal(String(await nextMessage(a.ws)), "noise-2");
    const nonce = rid();
    assert.deepEqual(await commit(r, t, h, a, { nonce }), { status: 200, body: { code: "ok" } });
    assert.deepEqual(await commit(r, t, h, a, { nonce }), { status: 409, body: { code: "replay" } }, "the same authorization again");
    assert.deepEqual(await commit(r, t, h, a), { status: 404, body: { code: "not_found" } }, "another authorization for a pair already active");
    a.ws.send(Buffer.from("cmd"));
    assert.equal(String(await nextMessage(h.ws)), "cmd");
    h.ws.send(Buffer.from("res"));
    assert.equal(String(await nextMessage(a.ws)), "res");
    a.ws.send("text");
    assert.equal(await closed(h.ws), CODES.binaryOnly);
  } finally { await r.close(); }
});

test("ingress refusals happen before any control-plane call: the query, the role's headers and their sizes, the header block", async () => {
  const r = await relay(), t = ids();
  try {
    const target = openTarget(fields("app", t));
    const bad = [
      ["a field missing", { url: target.replace(/&resume_n=0$/, "") }],
      ["a field out of order", { url: target.replace("role=app&fleet", "fleet=x&role=app") }],
      ["a record over 87,252", { headers: { "sagebrush-browser-record": "A".repeat(RECORD_HEADER_MAX + 1) } }],
      ["a record that isn't base64url", { headers: { "sagebrush-browser-record": "AA+A" } }],
      ["a bad request id", { headers: { "sagebrush-request": "short" } }],
    ];
    for (const [what, o] of bad) {
      const ws = new WebSocket(`ws://127.0.0.1:${r.port}${o.url ?? target}`, { headers: { "sagebrush-browser-record": t.host, "sagebrush-request": rid(), "sagebrush-relay-token": r.worker.issueToken("x"), ...o.headers } });
      r.live.add(ws);
      const status = await new Promise((res) => { ws.on("unexpected-response", (_q, s) => { res(s.statusCode); s.resume(); }); ws.on("error", () => res("error")); });
      assert.equal(status, 400, what);
    }
    const big = await open(r, "app", t, { headers: { "x-pad": "a".repeat(98_304) } });
    assert.equal(big.status, 431, "the header block over 98,304 bytes");
    // (the relay token, A1 §3: no token, or one out of its exact form, is 401 before any control-plane call; a session
    //  cookie is never read on this route, so one without a token is refused the same)
    assert.equal((await open(r, "app", t, { headers: { "sagebrush-relay-token": undefined } })).status, 401, "no relay token");
    assert.equal((await open(r, "app", t, { headers: { "sagebrush-relay-token": undefined, cookie: `__Host-sb_session=${t.account}` } })).status, 401, "a session cookie, no token");
    for (const bad of [`rt2.${"A".repeat(43)}`, `rt1.${"A".repeat(42)}B`, `rt1.${"A".repeat(44)}`, "rt1."])
      assert.equal((await open(r, "app", t, { headers: { "sagebrush-relay-token": bad } })).status, 401, `a token out of form: ${bad.slice(0, 6)}`);
    assert.equal(r.worker.calls.admit, 0, "no control-plane call for any of them");
    const atCap = await open(r, "app", t, { headers: { "sagebrush-browser-record": t.host + "A".repeat(RECORD_HEADER_MAX - t.host.length) } });
    assert.ok(atCap.ws, `a record of exactly 87,252 characters passes ingress (${atCap.status})`);
    assert.equal(r.worker.calls.admit, 1);
    // (a token in form that the service never issued, or already took: the Worker's unauthenticated, 401)
    const unknown = `rt1.${randomBytes(32).toString("base64url")}`;
    assert.equal((await open(r, "app", t, { headers: { "sagebrush-relay-token": unknown } })).status, 401, "a token never issued");
    assert.equal(r.worker.calls.admit, 2, "asked the Worker");
  } finally { await r.close(); }
});

test("replay: a host nonce or an app request id is consumed once, and stays consumed after a restart on the same store", async () => {
  const dir = mkdtempSync(join(tmpdir(), "relay-svc-")), path = join(dir, "relay.sqlite");
  try {
    const t = ids(), worker = new FakeWorker(KEY); // (the same Worker: its cursor is ahead of the stored one)
    let r = await relay({ store: openStore(path), worker });
    const h = await open(r, "host", t), a = await open(r, "app", t);
    assert.ok(h.ws && a.ws);
    await r.close(); r.store.close();
    r = await relay({ store: openStore(path), worker });
    try {
      assert.equal((await open(r, "host", t, { nonce: h.nonce })).status, 409);
      assert.equal((await open(r, "app", t, { request: a.request })).status, 409);
      assert.ok((await open(r, "host", t)).ws, "a fresh nonce is admitted");
    } finally { await r.close(); r.store.close(); }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("limits before admission are global and per source only: spoofed identities from one source, the final global call slot, release after the deadline", async () => {
  const r = await relay({ ingress: { ...INGRESS, opensPerSourcePerMinute: 3, controlCalls: 2, controlPerSource: 1 } });
  try {
    for (let i = 0; i < 3; i++) assert.ok((await open(r, "host", ids())).ws, `open ${i}`);
    assert.equal((await open(r, "host", ids())).status, 429, "the 4th open a minute from this source, whatever identities it claims");
    assert.equal(r.worker.calls.admit, 3);
    for (let i = 0; i < 120; i++) { r.clock.advance(500); await settle(); } // (a minute, with the feed answering)
    let release;
    r.worker.hold = new Promise((res) => { release = res; });
    const s1 = open(r, "host", ids(), { headers: { [SOURCE_HEADER]: "198.51.100.1" } });
    const s2 = open(r, "host", ids(), { headers: { [SOURCE_HEADER]: "198.51.100.2" } });
    await settle(20);
    assert.equal((await open(r, "host", ids(), { headers: { [SOURCE_HEADER]: "198.51.100.3" } })).status, 429, "the final global slot is taken");
    r.clock.advance(5000); // (the admit deadline)
    assert.equal((await s1).status, 503);
    assert.equal((await s2).status, 503);
    r.worker.hold = null; release();
    assert.ok((await open(r, "host", ids(), { headers: { [SOURCE_HEADER]: "198.51.100.4" } })).ws, "both slots were released");
  } finally { await r.close(); }
});

test("an answer whose facts aren't the query's, a refusal, an unavailable feed, and a late answer after a revocation are all refused, and nothing opens", async () => {
  const r = await relay(), t = ids();
  try {
    const real = r.worker.decide;
    r.worker.decide = (p) => ({ ...real(p), session: ids().session });
    assert.equal((await open(r, "host", t)).status, 403, "another session");
    r.worker.decide = () => ({ result: "refused", code: "not_granted" });
    assert.equal((await open(r, "host", t)).status, 403);
    r.worker.decide = real;
    // (a late answer: the admit is held while the feed records a change for the agent)
    let release;
    r.worker.hold = new Promise((res) => { release = res; });
    const pending = open(r, "host", t);
    await settle(20);
    r.worker.hold = null;
    r.worker.feedQueue.push((since) => r.worker.empty(since, { agents: [{ id: t.agent, epoch: 1 }] }));
    r.clock.advance(5000); await settle(20);
    release();
    assert.equal((await pending).status, 503, "the held call met its deadline");
    r.worker.epochOf = () => 0; // (a Worker answering from before the change)
    assert.equal((await open(r, "host", t)).status, 403, "its epochs are no longer current");
    assert.equal(r.slots.sockets, 0);
    for (let i = 0; i < 20; i++) r.worker.feedQueue.push(() => { throw new Error("down"); });
    for (let i = 0; i < 70; i++) { r.clock.advance(500); await settle(); }
    assert.equal(r.feed.available, false);
    const before = r.worker.calls.admit;
    assert.equal((await open(r, "host", ids())).status, 503);
    assert.equal(r.worker.calls.admit, before, "no control call while unavailable");
  } finally { await r.close(); }
});

// ---- raw frames

function rawOpen(r, role, t) {
  return new Promise((resolve) => {
    const s = connect(r.port, "127.0.0.1");
    const head = [`GET ${openTarget(fields(role, t))} HTTP/1.1`, "Host: x", "Upgrade: websocket", "Connection: Upgrade", "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
      "Sec-WebSocket-Version: 13", "Sec-WebSocket-Extensions: permessage-deflate", `sagebrush-sig: host=${t.host};gen=1;nonce=${rid()}`, "", ""].join("\r\n");
    let buf = "";
    s.on("data", function onData(c) {
      buf += c.toString("latin1");
      const end = buf.indexOf("\r\n\r\n");
      if (end < 0) return;
      s.off("data", onData);
      resolve({ s, head: buf.slice(0, end) });
    });
    s.write(head);
  });
}
/** A masked client frame. `declared` overrides the length field (with no payload sent). */
function frame(opcode, payload = Buffer.alloc(0), { fin = true, rsv = 0, declared } = {}) {
  const len = declared ?? payload.length, mask = randomBytes(4);
  const ext = len < 126 ? Buffer.alloc(0) : len < 65536 ? Buffer.from([len >> 8, len & 255]) : (() => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(len)); return b; })();
  const b0 = (fin ? 0x80 : 0) | (rsv << 4) | opcode, b1 = 0x80 | (len < 126 ? len : len < 65536 ? 126 : 127);
  const masked = Buffer.from(payload.map((x, i) => x ^ mask[i % 4]));
  return Buffer.concat([Buffer.from([b0, b1]), ext, mask, declared === undefined ? masked : Buffer.alloc(0)]);
}
const serverWs = (r) => { const s = [...r.slots.slots.values()][0]; return s.host.ws; };
const closeCode = (s) => new Promise((res) => { let b = Buffer.alloc(0); s.on("data", (c) => { b = Buffer.concat([b, c]); if (b.length >= 4 && (b[0] & 15) === 8) res(b.readUInt16BE(2)); }); s.on("close", () => res(null)); });

test("raw-frame ingress: sizes from the frame header before buffering, fragments counted together, RSV bits, no compression, pings with no automatic pong", async () => {
  const r = await relay();
  try {
    const { s, head } = await rawOpen(r, "host", ids());
    assert.match(head, /^HTTP\/1\.1 101/);
    assert.doesNotMatch(head.toLowerCase(), /sec-websocket-extensions/, "compression isn't negotiated");
    const ws = serverWs(r);
    const code = closeCode(s);
    s.write(frame(2, undefined, { declared: 65536 })); // (a header declaring 65,536 bytes, and no body)
    assert.equal(await code, 1009);
    assert.ok(ws._receiver._bufferedBytes <= 14, "nothing past the frame header was buffered");
  } finally { await r.close(); }
  for (const [what, frames, want] of [
    ["a fragmented message over 65,535 in all", [frame(2, Buffer.alloc(40_000), { fin: false }), frame(0, Buffer.alloc(30_000))], 1009],
    ["RSV1 without an extension", [frame(2, Buffer.from("x"), { rsv: 4 })], 1002],
  ]) {
    const r2 = await relay();
    try {
      const { s } = await rawOpen(r2, "host", ids());
      const code = closeCode(s);
      for (const f of frames) s.write(f);
      assert.equal(await code, want, what);
    } finally { await r2.close(); }
  }
  const r3 = await relay();
  try {
    const t = ids();
    const { s } = await rawOpen(r3, "host", t);
    const got = [];
    s.on("data", (c) => got.push(c));
    s.write(frame(9, Buffer.from("ping"))); // (a ping: no automatic pong)
    await settle(20);
    assert.equal(Buffer.concat(got).length, 0, "no pong");
    assert.equal(r3.slots.sockets, 1, "still open");
    s.destroy();
  } finally { await r3.close(); }
});

test("logs carry metadata only: no record, relay token, signature, nonce, request id or message bytes", async () => {
  const r = await relay(), t = ids();
  try {
    const nonce = rid(), request = rid(), payload = "CANARY" + randomBytes(6).toString("hex");
    const record = t.host + "CANARYREC" + randomBytes(4).toString("hex");
    const h = await open(r, "host", t, { nonce });
    const token = r.worker.issueToken(t.account);
    const a = await open(r, "app", t, { request, headers: { "sagebrush-browser-record": record, "sagebrush-relay-token": token } });
    a.ws.send(Buffer.from(payload));
    await nextMessage(h.ws);
    assert.equal((await open(r, "host", t, { nonce })).status, 409);
    a.ws.close();
    await settle(20);
    assert.ok(r.log.length > 3);
    const logs = JSON.stringify(r.log);
    for (const secret of [nonce, request, "CANARY", "sagebrush-sig", "host=", token, token.slice(4), "rt1."]) assert.ok(!logs.includes(secret), secret.slice(0, 8));
  } finally { await r.close(); }
});

test("a commit held while the agent is revoked: its late answer switches nothing, and the pair is closed", async () => {
  const r = await relay(), t = ids();
  try {
    const h = await open(r, "host", t), a = await open(r, "app", t);
    a.ws.send(Buffer.from("m1")); await nextMessage(h.ws);
    h.ws.send(Buffer.from("m2")); await nextMessage(a.ws);
    const hostClosed = closed(h.ws);
    let release;
    r.worker.hold = new Promise((res) => { release = res; });
    const pending = commit(r, t, h, a);
    await settle(20);
    r.worker.hold = null;
    r.worker.feedQueue.push((since) => r.worker.empty(since, { agents: [{ id: t.agent, epoch: 1 }] }));
    r.clock.advance(5000); await settle(20); // (the feed's change closes the candidate; the held commit meets its deadline)
    release();
    assert.equal((await pending).status, 503);
    assert.equal(await hostClosed, CODES.revoked);
    assert.equal(r.slots.sockets, 0);
  } finally { await r.close(); }
});

test("the configuration: exactly its fields, loopback only, a key of 32 bytes or more; refusals never echo a value", async () => {
  const { readConfig } = await import("../lib/fleet/relay/main.mjs");
  const { writeFileSync } = await import("node:fs");
  const dir = mkdtempSync(join(tmpdir(), "relay-cfg-"));
  try {
    const keyFile = join(dir, "k"), cfg = join(dir, "c.json");
    writeFileSync(keyFile, randomBytes(32).toString("base64url"));
    const base = { listen: { host: "127.0.0.1", port: 8788 }, origin: "https://fleet.example", keyFile, dbPath: join(dir, "db") };
    writeFileSync(cfg, JSON.stringify(base));
    assert.equal(readConfig(cfg).key.length, 32);
    for (const [what, c] of [["a public listen address", { ...base, listen: { host: "0.0.0.0", port: 8788 } }], ["an extra field", { ...base, extra: "SECRETVALUE" }],
      ["a low port", { ...base, listen: { host: "127.0.0.1", port: 80 } }], ["no key file", { ...base, keyFile: join(dir, "none") }]]) {
      writeFileSync(cfg, JSON.stringify(c));
      assert.throws(() => readConfig(cfg), (e) => !/SECRETVALUE|fleet\.example/.test(e.message), what);
    }
    writeFileSync(keyFile, randomBytes(16).toString("base64url"));
    writeFileSync(cfg, JSON.stringify(base));
    assert.throws(() => readConfig(cfg), /43 base64url/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("consumption comes before any slot change: a store that can't record the id refuses the open (503) and touches no slot", async () => {
  const r = await relay(), t = ids();
  try {
    const real = r.store.consume;
    r.store.consume = () => { throw new Error("disk full"); };
    assert.equal((await open(r, "host", t)).status, 503);
    assert.equal(r.slots.sockets, 0);
    r.store.consume = real;
    assert.ok((await open(r, "host", t)).ws);
    assert.equal(r.slots.sockets, 1);
  } finally { await r.close(); }
});

// ---- replay-id retention (the #58 ruling): an app request id is kept until min(record end, session expiry) + 60 s

/** A relay and fake Worker on one movable wall clock (the relay's may run ahead by `skew`). */
async function timed({ skew = 0, store } = {}) {
  let wall = Date.now();
  const worker = new FakeWorker(KEY, { wallNow: () => wall });
  const r = await relay({ worker, wallNow: () => wall + skew, ...(store ? { store } : {}) });
  return { r, at: (t) => { wall = t; }, now: () => wall };
}

test("retention: an app request id is kept until min(record end, session expiry) + 60 s, from the app answer alone (no host answer); a replay is refused before that, and the Worker refuses it after", async () => {
  for (const [what, recordIn, sessionIn] of [["the session expires first", 2 * 3600_000, 3600_000], ["the record ends first", 3600_000, 2 * 3600_000]]) {
    const { r, at, now } = await timed(), t = ids(), t0 = now();
    try {
      r.worker.app = { not_after_ms: t0 + recordIn, session_ms: t0 + sessionIn };
      const request = rid();
      assert.ok((await open(r, "app", t, { request })).ws, what);
      const end = Math.min(recordIn, sessionIn) + 60_000 + t0;
      at(t0 + CONSUMED_MS + 60_000); r.store.prune(t0 + CONSUMED_MS + 60_000);
      assert.equal((await open(r, "app", t, { request })).status, 409, `${what}: still refused after 11 min`);
      at(end - 1); r.store.prune(end - 1);
      assert.equal(r.store.consumed("app", request), true, `${what}: kept until its end`);
      r.worker.app.checkWindow = false; // (show the relay's own refusal just before the end)
      at(Math.min(recordIn, sessionIn) + t0 - 1);
      assert.equal((await open(r, "app", t, { request })).status, 409, `${what}: replay just inside the window`);
      r.worker.app.checkWindow = true;
      at(end + 1); r.store.prune(end + 1);
      assert.equal(r.store.consumed("app", request), false, `${what}: pruned after its end`);
      assert.equal((await open(r, "app", t, { request })).status, 403, `${what}: the Worker refuses it then (grant_expired)`);
    } finally { await r.close(); }
  }
});

test("retention: host nonces keep the 10-minute rule; a restart keeps an app id's retention; the relay's clock 60 s ahead still covers the window", async () => {
  { const { r, now } = await timed(), t = ids(), t0 = now(), nonce = rid();
    try {
      assert.ok((await open(r, "host", t, { nonce })).ws);
      r.store.prune(t0 + CONSUMED_MS - 1);
      assert.equal(r.store.consumed("host", nonce), true);
      r.store.prune(t0 + CONSUMED_MS + 1000);
      assert.equal(r.store.consumed("host", nonce), false);
    } finally { await r.close(); } }
  { const dir = mkdtempSync(join(tmpdir(), "relay-ret-")), path = join(dir, "r.sqlite");
    try {
      const t0 = Date.now(), request = rid(), t = ids();
      const a = await timed({ store: openStore(path) });
      a.r.worker.app = { not_after_ms: t0 + 2 * 3600_000, session_ms: t0 + 2 * 3600_000 };
      assert.ok((await open(a.r, "app", t, { request })).ws);
      await a.r.close(); a.r.store.close();
      const s = openStore(path);
      s.prune(t0 + 3600_000);
      assert.equal(s.consumed("app", request), true, "after a restart, an hour later");
      s.close();
    } finally { rmSync(dir, { recursive: true, force: true }); } }
  { const { r, at, now } = await timed({ skew: 60_000 }), t = ids(), t0 = now(), request = rid();
    try {
      r.worker.app = { not_after_ms: t0 + 3600_000, session_ms: t0 + 3600_000 };
      assert.ok((await open(r, "app", t, { request })).ws);
      at(t0 + 3600_000 - 1); r.store.prune(t0 + 3600_000 - 1 + 60_000); // (the relay prunes on its own clock, 60 s ahead)
      assert.ok([403, 409].includes((await open(r, "app", t, { request })).status), "refused at the last moment the Worker would still accept it");
      assert.equal(r.store.consumed("app", request), true, "the id is still kept: the relay's 60 s lead is inside the margin");
    } finally { await r.close(); } }
});

test("retention: the record's remaining window must be within (0, 12 h]: an overlong or ended record is refused before anything is consumed; exactly 12 h is admitted and kept to its end", async () => {
  const { r, now } = await timed(), t0 = now();
  try {
    for (const [what, notAfter] of [["over 12 h", t0 + APP_RECORD_MAX_MS + 1], ["already ended", t0]]) {
      const request = rid();
      r.worker.app = { not_after_ms: notAfter, session_ms: t0 + 24 * 3600_000, checkWindow: false }; // (a verified answer the relay must still refuse)
      assert.equal((await open(r, "app", ids(), { request })).status, 403, what);
      assert.equal(r.store.consumed("app", request), false, `${what}: nothing consumed`);
    }
    assert.equal(r.slots.sockets, 0);
    const request = rid();
    r.worker.app = { not_after_ms: t0 + APP_RECORD_MAX_MS, session_ms: t0 + 24 * 3600_000 };
    assert.ok((await open(r, "app", ids(), { request })).ws, "exactly 12 h");
    r.store.prune(t0 + APP_RECORD_MAX_MS + 60_000 - 1);
    assert.equal(r.store.consumed("app", request), true, "kept to its end");
  } finally { await r.close(); }
});

test("retention: concurrent duplicate opens both verify, and exactly one insert wins; storage stays bounded after many valid app opens", async () => {
  const { r, now } = await timed(), t0 = now();
  try {
    const t = ids(), request = rid();
    const [a, b] = await Promise.all([open(r, "app", t, { request }), open(r, "app", { ...t, session: ids().session }, { request })]);
    assert.deepEqual([a.ws ? "open" : a.status, b.ws ? "open" : b.status].sort(), [409, "open"].sort());
    r.worker.app = { not_after_ms: t0 + 3600_000, session_ms: t0 + 3600_000 };
    for (let i = 0; i < 25; i++) { const o = await open(r, "app", ids()); assert.ok(o.ws, `open ${i}: ${o.status}`); o.ws.close(); }
    await settle(20);
    assert.equal(r.store.count(), 26);
    r.store.prune(t0 + 3600_000 + 60_000 - 1);
    assert.equal(r.store.count(), 26, "every id is kept to its window's end");
    r.store.prune(t0 + 3600_000 + 60_000 + 10_000);
    assert.equal(r.store.count(), 0, "every window passes: nothing is kept");
  } finally { await r.close(); }
});

test("memory before admission is bounded: after the global cap fills, fresh sources are refused and allocate nothing", async () => {
  const clock0 = { opensPerMinute: 5, opensPerSourcePerMinute: 30, controlCalls: 16, controlPerSource: 2 };
  const r = await relay({ ingress: { ...INGRESS, ...clock0 } });
  try {
    for (let i = 0; i < 5; i++) assert.ok((await open(r, "host", ids(), { headers: { [SOURCE_HEADER]: `2001:db8::${i + 1}` } })).ws);
    for (let i = 0; i < 300; i++) assert.equal((await open(r, "host", ids(), { headers: { [SOURCE_HEADER]: `2001:db8:1::${(i + 1).toString(16)}` } })).status, 429);
    const s = r.stats();
    assert.ok(s.rateKeys <= 5 && s.rateEvents <= 5 && s.inflight === 0, JSON.stringify(s));
  } finally { await r.close(); }
});
