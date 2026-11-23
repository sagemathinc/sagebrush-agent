// The browser lane's sidecar frames (browser-lane3-runtime.md, "The two sidecars and their IPC" and SEC §1): exact
// framing, canonical heads, one closed schema per kind on its one path, bodies only on the four kinds that carry one,
// and a decoder that is dead after its first error.

import assert from "node:assert/strict";
import { test } from "node:test";
import { createEncoder, createDecoder, FrameError, KINDS, LIMITS, isAnswer } from "../lib/fleet/browser/frames.mjs";

const SENDERS = { "net.start": "rust", "net.record": "rust", "net.policy": "rust", "net.takeover": "rust", "net.resume": "rust", "net.retire": "rust", "rust.net_hello": "net", "rust.net_state": "net", "cdp.start": "rust", "cdp.proxy_auth": "rust", "cdp.takeover": "rust", "cdp.resume": "rust", "cdp.retire": "rust", "rust.cdp_state": "cdp", "rust.takeover_done": "cdp", "rust.takeover_failed": "cdp", "cdp.command": "net", "net.result": "cdp", "net.event": "cdp", "net.refused": "cdp" };
const BODY = new Set(["cdp.command", "net.result", "net.event", "net.record"]);

/** One valid head for each kind. */
const SAMPLE = {
  "net.start": { session: "s-1", browser_gen: 3, host_static_pub: "x".repeat(43), relay_url: "wss://relay.example/s" },
  "net.record": {},
  "net.policy": { exceptions: [] },
  "net.takeover": { reason: "the person took over" },
  "net.resume": {},
  "net.retire": { reason: "done" },
  "rust.net_hello": { app_session_pub: "k".repeat(43), proxy_port: 50123, proxy_username: "u1", proxy_password: "p".repeat(128) },
  "rust.net_state": { state: "open" },
  "cdp.start": { chrome_pid: 4242 },
  "cdp.proxy_auth": { username: "u1", password: "pw", proxy_port: 50123 },
  "cdp.takeover": {},
  "cdp.resume": {},
  "cdp.retire": { reason: "budget spent" },
  "rust.cdp_state": { state: "ended", reason: "pipe ended" },
  "rust.takeover_done": {},
  "rust.takeover_failed": { reason: "drain timed out" },
  "cdp.command": { seq: 0 },
  "net.result": { seq: 9007199254740991 },
  "net.event": {},
  "net.refused": { seq: 7, reason: "takeover" },
};
const to = (kind) => kind.split(".")[0];
const head = (kind, extra = {}) => ({ to: to(kind), kind, ...SAMPLE[kind], ...extra });

/** A frame built by hand (no encoder checks): `head` as raw text or an object (JSON.stringify). */
function raw(h, body = Buffer.alloc(0), { total, headLen } = {}) {
  const hb = Buffer.from(typeof h === "string" ? h : JSON.stringify(h), "utf8");
  const out = Buffer.alloc(8 + hb.length + body.length);
  out.writeUInt32BE(total ?? 4 + hb.length + body.length, 0);
  out.writeUInt32BE(headLen ?? hb.length, 4);
  hb.copy(out, 8);
  Buffer.from(body).copy(out, 8 + hb.length);
  return out;
}
/** A canonical head's text (keys sorted). */
const canonical = (o) => JSON.stringify(Object.fromEntries(Object.entries(o).sort(([a], [b]) => (a < b ? -1 : 1))));
const codeOf = (fn) => { try { fn(); } catch (e) { if (e instanceof FrameError) return e.code; throw e; } return "ok"; };

test("frames: the tables are the doc's: 20 kinds, each with one sender and one receiver, bodies on exactly four", () => {
  assert.deepEqual(Object.keys(KINDS).sort(), Object.keys(SENDERS).sort());
  for (const [kind, k] of Object.entries(KINDS)) {
    assert.equal(k.from, SENDERS[kind], kind);
    assert.equal(k.body, BODY.has(kind), kind);
    assert.notEqual(k.from, to(kind), kind);
  }
  assert.equal(LIMITS.headBytes, 64 * 1024);
  assert.equal(LIMITS.totalBytes, 64 * 1024 * 1024 + 64 * 1024);
});

test("frames: every kind round-trips from its sender to its receiver, with and without the sender named", () => {
  for (const kind of Object.keys(KINDS)) {
    const body = kind === "net.result" ? Buffer.from('{"result":{"x":1}}') : BODY.has(kind) ? Buffer.from(`{"x":"${kind}"}`) : Buffer.alloc(0);
    const bytes = createEncoder({ from: SENDERS[kind] })(head(kind), body);
    for (const d of [createDecoder({ to: to(kind), from: SENDERS[kind] }), createDecoder({ to: to(kind) })]) {
      const [f, ...more] = d.push(bytes);
      assert.equal(more.length, 0);
      assert.deepEqual({ ...f.head }, head(kind), kind);
      assert.deepEqual(f.body, body, kind);
      d.end();
    }
    // (the head on the wire is canonical: sorted keys, no whitespace)
    const hl = bytes.readUInt32BE(4);
    assert.equal(bytes.subarray(8, 8 + hl).toString(), canonical(head(kind)), kind);
    assert.equal(bytes.readUInt32BE(0), bytes.length - 4, kind);
  }
  // (an empty body is fine where a body is allowed)
  const d = createDecoder({ to: "net" });
  assert.equal(d.push(createEncoder({ from: "cdp" })(head("net.event"))).length, 1);
});

test("frames: any chunking gives the same frames, in order, and bodies are copies", () => {
  const enc = createEncoder({ from: "rust" });
  const frames = [head("cdp.proxy_auth"), head("cdp.start"), head("cdp.takeover"), head("cdp.resume", { reason: "é✓" }), head("cdp.retire")];
  const stream = Buffer.concat([...frames.map((h) => enc(h)), createEncoder({ from: "net" })(head("cdp.command"), Buffer.from("{\"method\":\"Page.reload\"}"))]);
  for (const step of [1, 2, 3, 7, 64, stream.length]) {
    const d = createDecoder({ to: "cdp" });
    const got = [];
    const copy = Buffer.from(stream);
    for (let i = 0; i < copy.length; i += step) got.push(...d.push(copy.subarray(i, i + step)));
    d.end();
    copy.fill(0); // (the reader's chunks, reused: a body that aliased them would change)
    assert.deepEqual(got.map((f) => f.head.kind), [...frames.map((h) => h.kind), "cdp.command"], `step ${step}`);
    assert.equal(got[3].head.reason, "é✓");
    assert.equal(got[5].body.toString(), "{\"method\":\"Page.reload\"}", "a body never aliases the reader's chunk");
  }
});

test("frames: exact framing: lengths are checked from the first 4 bytes, before anything is kept", () => {
  const d = () => createDecoder({ to: "cdp" });
  const len = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
  assert.equal(codeOf(() => d().push(len(5))), "short");
  assert.equal(codeOf(() => d().push(len(0))), "short");
  assert.equal(codeOf(() => d().push(len(LIMITS.totalBytes + 1))), "oversize");
  assert.equal(codeOf(() => d().push(len(0xffffffff))), "oversize");
  assert.equal(codeOf(() => d().push(len(LIMITS.totalBytes))), "ok", "at the limit: waits for the rest");
  // (the length arriving in pieces is checked once its 4th byte is in)
  const x = d();
  assert.deepEqual(x.push(len(LIMITS.totalBytes + 1).subarray(0, 3)), []);
  assert.equal(codeOf(() => x.push(len(LIMITS.totalBytes + 1).subarray(3))), "oversize");
  // (head_len: at least 2, within the frame, at most 64 KiB)
  const h = canonical(head("cdp.start"));
  assert.equal(codeOf(() => d().push(raw(h, undefined, { headLen: 1 }))), "short");
  assert.equal(codeOf(() => d().push(raw(h, undefined, { headLen: h.length + 1 }))), "short");
  assert.equal(codeOf(() => d().push(raw(h, Buffer.alloc(70000), { headLen: LIMITS.headBytes + 1 }))), "oversize");
  // (total_len that doesn't match: the next frame's bytes are read as this one's, so its head or the next length fails)
  assert.notEqual(codeOf(() => d().push(Buffer.concat([raw(h, undefined, { total: 4 + h.length + 3 }), raw(h)]))), "ok");
});

test("frames: the head must be canonical JSON: no whitespace, sorted keys, no duplicate key, nothing after it, UTF-8", () => {
  const d = () => createDecoder({ to: "cdp" });
  const good = canonical(head("cdp.start"));
  assert.equal(codeOf(() => d().push(raw(good))), "ok");
  for (const bad of [
    JSON.stringify({ to: "cdp", kind: "cdp.start", chrome_pid: 1 }), // (unsorted)
    good.replace(",", ", "), // (whitespace)
    '{"chrome_pid":1,"kind":"cdp.start","kind":"cdp.start","to":"cdp"}', // (a duplicate key)
    '{"chrome_pid":1,"chrome_pid":2,"kind":"cdp.start","to":"cdp"}',
    good + " ", // (trailing bytes)
    good + "{}",
    "﻿" + good, // (a byte-order mark)
    '{"chrome_pid":1.0,"kind":"cdp.start","to":"cdp"}', // (a float)
    '{"chrome_pid":1,"kind":"cdp.st\\u0061rt","to":"cdp"}', // (an escaped plain character)
  ]) assert.equal(codeOf(() => d().push(raw(bad))), "head", bad);
  assert.equal(codeOf(() => d().push(raw(Buffer.from([0x7b, 0xff, 0x7d]).toString("latin1")))), "head");
  const inv = raw("{}");
  inv[8] = 0xff;
  assert.equal(codeOf(() => d().push(inv)), "head");
  // (well-formed JSON that isn't an object)
  for (const notObject of ["[1]", "\"x\"", "12", "null"]) assert.equal(codeOf(() => d().push(raw(notObject))), "head", notObject);
});

test("frames: unknown kinds and kinds off their path are refused", () => {
  const cdp = () => createDecoder({ to: "cdp" });
  assert.equal(codeOf(() => cdp().push(raw(canonical({ to: "cdp", kind: "cdp.open" })))), "kind");
  assert.equal(codeOf(() => cdp().push(raw(canonical({ to: "cdp", kind: "toString" })))), "kind");
  assert.equal(codeOf(() => cdp().push(raw(canonical({ to: "cdp", kind: "__proto__" })))), "kind");
  assert.equal(codeOf(() => cdp().push(raw(canonical({ to: "cdp" })))), "kind");
  // (another party's kind, or `to` that isn't the kind's receiver)
  assert.equal(codeOf(() => cdp().push(raw(canonical(head("net.start"))))), "route");
  assert.equal(codeOf(() => cdp().push(raw(canonical({ ...head("cdp.start"), to: "net" })))), "route");
  assert.equal(codeOf(() => cdp().push(raw(canonical({ ...head("net.result"), to: "cdp" })))), "route");
  // (Rust reading cdp's stdout: cdp may send only its own kinds)
  const rustFromCdp = () => createDecoder({ to: "rust", from: "cdp" });
  assert.equal(codeOf(() => rustFromCdp().push(raw(canonical(head("rust.net_hello"))))), "route", "net's hello, from cdp");
  assert.equal(codeOf(() => rustFromCdp().push(raw(canonical(head("rust.cdp_state"))))), "ok");
  const rustFromNet = () => createDecoder({ to: "rust", from: "net" });
  assert.equal(codeOf(() => rustFromNet().push(raw(canonical(head("rust.takeover_done"))))), "route");
  // (Rust reading net's stdout: what net sends cdp goes through Rust, as net's kind)
  assert.equal(codeOf(() => createDecoder({ to: "cdp", from: "net" }).push(raw(canonical(head("cdp.command"))))), "ok");
  assert.equal(codeOf(() => createDecoder({ to: "cdp", from: "net" }).push(raw(canonical(head("cdp.start"))))), "route");
});

test("frames: closed schemas: a missing field, an extra field, or a value out of bounds is refused", () => {
  const dec = (kind, h) => codeOf(() => createDecoder({ to: to(kind) }).push(raw(canonical(h))));
  for (const kind of Object.keys(KINDS)) {
    assert.equal(dec(kind, head(kind)), "ok", kind);
    assert.equal(dec(kind, head(kind, { extra: 1 })), "schema", `${kind} extra`);
    for (const f of Object.keys(KINDS[kind].fields)) {
      const h = head(kind);
      delete h[f];
      assert.equal(dec(kind, h), "schema", `${kind} without ${f}`);
    }
  }
  const out = [
    ["net.start", { session: "" }], ["net.start", { session: "s".repeat(65) }], ["net.start", { browser_gen: -1 }],
    ["net.start", { relay_url: "ws://relay.example/" }], ["net.start", { relay_url: "https://relay.example/" }],
    ["net.start", { relay_url: "wss://" + "r".repeat(2043) }], ["net.start", { relay_url: "wss://a b" }], ["net.start", { relay_url: 5 }],
    ["net.policy", { exceptions: ["10.0.0.0/8"] }], ["net.policy", { exceptions: {} }],
    ["rust.net_hello", { proxy_port: 1023 }], ["rust.net_hello", { proxy_port: 65536 }], ["rust.net_hello", { proxy_port: "50000" }],
    ["rust.net_hello", { proxy_password: "" }], ["rust.net_hello", { proxy_password: "p".repeat(129) }], ["rust.net_hello", { proxy_username: "é".repeat(65) }],
    ["rust.net_state", { state: "closed" }], ["rust.net_state", { reason: "r".repeat(257) }], ["rust.net_state", { reason: "" }],
    ["cdp.start", { chrome_pid: 0 }], ["cdp.start", { chrome_pid: 2 ** 31 }], ["cdp.start", { chrome_pid: -5 }],
    ["cdp.proxy_auth", { username: "" }], ["cdp.proxy_auth", { password: null }],
    ["cdp.proxy_auth", { proxy_port: 1023 }], ["cdp.proxy_auth", { proxy_port: 65536 }], ["cdp.proxy_auth", { proxy_port: "50123" }], ["cdp.proxy_auth", { proxy_port: 0 }],
    ["rust.cdp_state", { state: "READY" }], ["cdp.takeover", { reason: 1 }],
    ["cdp.command", { seq: -1 }], ["cdp.command", { seq: "1" }], ["net.result", { seq: true }],
    ["net.refused", { reason: "filter" }], ["net.refused", { reason: "credits" }], ["net.refused", { reason: "bad " }], ["net.refused", { reason: "Abandoned" }], ["net.refused", { reason: "unknown" }],
  ];
  for (const [kind, x] of out) assert.equal(dec(kind, head(kind, x)), "schema", `${kind} ${JSON.stringify(x).slice(0, 60)}`);
  // (at the caps: accepted)
  for (const [kind, x] of [["net.start", { session: "s".repeat(64) }], ["net.start", { relay_url: "wss://" + "r".repeat(2042) }], ["rust.net_hello", { proxy_port: 1024 }], ["rust.net_hello", { proxy_port: 65535 }], ["cdp.proxy_auth", { proxy_port: 1024 }], ["cdp.proxy_auth", { proxy_port: 65535 }], ["rust.net_state", { reason: "r".repeat(256) }], ["cdp.start", { chrome_pid: 2 ** 31 - 1 }], ["net.refused", { reason: "bad" }], ["net.refused", { reason: "takeover" }], ["net.refused", { reason: "abandoned" }]]) {
    assert.equal(dec(kind, head(kind, x)), "ok", `${kind} ${JSON.stringify(x).slice(0, 60)}`);
  }
});

test("frames: a body only on cdp.command, net.result, net.event and net.record", () => {
  for (const kind of Object.keys(KINDS)) {
    const got = codeOf(() => createDecoder({ to: to(kind) }).push(raw(canonical(head(kind)), Buffer.from("x"))));
    assert.equal(got, BODY.has(kind) ? "ok" : "body", kind);
    const b = kind === "net.result" ? Buffer.from('{"result":{}}') : Buffer.from("x");
    assert.equal(codeOf(() => createEncoder({ from: SENDERS[kind] })(head(kind), b)), BODY.has(kind) ? "ok" : "body", kind);
  }
});

test("frames: the size limit, exactly: a frame at 64 MiB + 64 KiB passes, one byte more doesn't (both directions)", () => {
  const h = canonical(head("net.result"));
  const fit = LIMITS.totalBytes - 4 - Buffer.byteLength(h);
  const answer = (n) => { const b = Buffer.alloc(n, 0x61); b.write('{"result":{"s":"', 0, "latin1"); b.write('"}}', n - 3, "latin1"); return b; };
  const at = createEncoder({ from: "cdp" })(head("net.result"), answer(fit));
  assert.equal(at.readUInt32BE(0), LIMITS.totalBytes);
  const [f] = createDecoder({ to: "net" }).push(at);
  assert.equal(f.body.length, fit);
  assert.equal(codeOf(() => createEncoder({ from: "cdp" })(head("net.result"), answer(fit + 1))), "oversize");
  assert.equal(codeOf(() => createDecoder({ to: "net" }).push(raw(h, Buffer.alloc(fit + 1)))), "oversize");
});

test("frames: a frame dripped in tiny pieces is held in one buffer: memory is bounded by bytes, not by pieces", async () => {
  const v8 = await import("node:v8");
  const vm = await import("node:vm");
  v8.setFlagsFromString("--expose-gc");
  const gc = vm.runInNewContext("gc");
  const n = 1 << 21;
  const frame = createEncoder({ from: "cdp" })(head("net.event"), Buffer.alloc(n, 0x62));
  const d = createDecoder({ to: "net" });
  gc();
  const before = process.memoryUsage().heapUsed;
  for (let i = 0; i < frame.length - 1; i++) assert.equal(d.push(frame.subarray(i, i + 1)).length, 0);
  gc();
  const grew = process.memoryUsage().heapUsed - before;
  assert.ok(grew < 32 * 1024 * 1024, `heap grew ${grew} bytes holding one ${frame.length}-byte frame`);
  const [f] = d.push(frame.subarray(frame.length - 1));
  assert.equal(f.body.length, n);
});

test("frames: after an error the decoder is dead; end() inside a frame is an error, between frames it isn't", () => {
  const enc = createEncoder({ from: "rust" });
  const d = createDecoder({ to: "cdp" });
  assert.equal(codeOf(() => d.push(raw(canonical({ to: "cdp", kind: "cdp.nope" })))), "kind");
  assert.equal(codeOf(() => d.push(enc(head("cdp.start")))), "dead");
  assert.equal(codeOf(() => d.end()), "dead");
  const e = createDecoder({ to: "cdp" });
  const f = enc(head("cdp.start"));
  e.push(f);
  e.end();
  const g = createDecoder({ to: "cdp" });
  g.push(f.subarray(0, 5));
  assert.equal(codeOf(() => g.end()), "truncated");
  assert.equal(codeOf(() => g.push(f)), "dead");
  // (an error in the middle of a chunk drops the frames before it too: the session ends either way)
  const h = createDecoder({ to: "cdp" });
  assert.equal(codeOf(() => h.push(Buffer.concat([f, raw("[]")]))), "head");
});

test("frames: an encoder sends only its own party's kinds, and only well-formed heads", () => {
  const cdp = createEncoder({ from: "cdp" });
  for (const kind of ["net.start", "rust.net_hello", "cdp.command", "cdp.start", "net.policy"]) assert.equal(codeOf(() => cdp(head(kind))), "route", kind);
  assert.equal(codeOf(() => cdp({ ...head("net.result"), to: "rust" })), "route");
  assert.equal(codeOf(() => cdp(head("net.refused", { reason: "filter" }))), "schema");
  assert.equal(codeOf(() => cdp({ kind: "net.result" })), "route");
  assert.equal(codeOf(() => cdp(null)), "head");
  assert.throws(() => cdp(head("net.event"), "not bytes"), TypeError);
  assert.throws(() => createEncoder({ from: "chrome" }), TypeError);
  assert.throws(() => createDecoder({ to: "cdp", from: "cdp" }), TypeError);
});

test("frames: error messages are fixed strings: no head or body bytes in them", () => {
  const secret = "SECRET-proxy-password";
  const cases = [
    raw(canonical(head("rust.net_hello", { proxy_password: secret + "x".repeat(200) }))),
    raw(canonical({ ...head("rust.net_hello", { proxy_password: secret }), extra: secret })),
    raw(`{"kind":"${secret}","to":"rust"}`),
    raw(`{"kind":"rust.net_hello","to":"${secret}"}`),
    raw(`{"${secret}":1}`),
  ];
  for (const c of cases) {
    try { createDecoder({ to: "rust", from: "net" }).push(c); assert.fail("refused"); } catch (e) {
      assert.ok(e instanceof FrameError);
      assert.ok(!e.message.includes("SECRET"), e.message);
    }
  }
});

test("frames: a net.result body is the session's answer: {result: object} or {error: {code, message}}, nothing else", () => {
  const enc = createEncoder({ from: "cdp" });
  for (const ok of ['{"result":{}}', '{"result":{"frameId":"F"}}', '{"error":{"code":-32000,"message":"stale handle"}}', '{"error":{"message":"blocked: account site (claude.ai)","code":-32000}}', ' {"result":{}} ']) {
    assert.ok(isAnswer(Buffer.from(ok)), ok);
    assert.equal(codeOf(() => enc(head("net.result"), Buffer.from(ok))), "ok", ok);
  }
  for (const bad of ["", "x", "{}", "[]", "null", '{"result":null}', '{"result":[]}', '{"result":1}', '{"result":{},"error":{"code":1,"message":"m"}}',
    '{"error":{"code":1}}', '{"error":{"code":"1","message":"m"}}', '{"error":{"code":1.5,"message":"m"}}', '{"error":{"code":1,"message":"m","data":"d"}}',
    '{"error":null}', '{"other":{}}', '{"result":{}}x', `{"error":{"code":1,"message":"${"m".repeat(1025)}"}}`]) {
    assert.ok(!isAnswer(Buffer.from(bad)), bad.slice(0, 40));
    assert.equal(codeOf(() => enc(head("net.result"), Buffer.from(bad))), "body", bad.slice(0, 40));
  }
  assert.ok(!isAnswer(Buffer.from([0x7b, 0xff, 0x7d])));
});

test("frames: net.refused's reasons are exactly takeover (not run), bad (not run) and abandoned (may have run)", () => {
  const enc = createEncoder({ from: "cdp" }), dec = () => createDecoder({ to: "net", from: "cdp" });
  for (const reason of ["takeover", "bad", "abandoned"]) {
    const [f] = dec().push(enc(head("net.refused", { reason })));
    assert.equal(f.head.reason, reason);
  }
  for (const reason of ["filter", "credits", "unknown", "abandon", "ABANDONED", "", "takeover,abandoned"]) {
    assert.equal(codeOf(() => enc(head("net.refused", { reason }))), "schema", JSON.stringify(reason));
  }
});
