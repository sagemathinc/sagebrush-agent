// The net sidecar's makeChannel (lib/fleet/browser/channel-net.mjs) against a real broker session over a real
// WebSocket: a local server stands in for the relay and the host (it checks the open, answers the handshake as the
// responder, and attaches the broker session to the socket). The blocked-Writable rows stop the server reading, so
// the app's socket writes are really withheld (design r4.2 §7 (c)).

import assert from "node:assert/strict";
import { test } from "node:test";
import { WebSocketServer } from "ws";
import { responder, x25519Generate } from "../lib/fleet/channel/noise.mjs";
import { prologueBytes } from "../lib/fleet/channel/accept.mjs";
import { parseOpenTarget } from "../lib/fleet/core/relay.mjs";
import { brokerSession } from "../lib/fleet/channel/broker.mjs";
import { canonBytes } from "../lib/fleet/canonical.mjs";
import { newId } from "../lib/fleet/bytes.mjs";
import { netChannel, wsSink, wsOpen, recordFields, relayBase, relayOrigin, RELAY_TOKEN } from "../lib/fleet/browser/channel-net.mjs";
import { randomBytes } from "node:crypto";
import { appSession } from "../lib/fleet/channel/app.mjs";
import { NetSidecar, channelKey } from "../lib/fleet/browser/sidecar-net.mjs";

/** The real transport, for the loopback stand-in only: no test (nor a regression under test) reaches a real relay. */
function loopbackOpen(url, headers) {
  if (!/^ws:\/\/127\.0\.0\.1:[0-9]+\//.test(url)) throw new Error(`a test open outside loopback: ${new URL(url).host}`);
  return wsOpen(url, headers);
}

/** A relay token in its A1 form. */
const token = () => `rt1.${randomBytes(32).toString("base64url")}`;

const tick = (ms = 0) => new Promise((r) => setTimeout(r, ms));
async function until(cond, ms = 3000, what = "the condition") {
  const end = Date.now() + ms;
  while (!cond()) { if (Date.now() > end) throw new Error(`timed out waiting for ${what}`); await tick(5); }
}

/** A session's fixed parts: the host's key, the app's key, the record (its body is what the wrapper reads). */
function fixture() {
  const hostKey = x25519Generate();
  const key = channelKey();
  const body = { fleet: newId(), aud: "https://sagebrush.space", session: newId(), host: newId(), agent: newId(), browser_gen: 2, host_gen: 1, app_session_pub: key.pub };
  const record = Buffer.from(JSON.stringify({ v: 1, type: "browser-session", body, sig: "test" }));
  return { hostKey, key, body, record };
}

/**
 * The relay and host in one: each connection is checked, answered as the responder at its resume_n, and attached to
 * one broker session. `opens` records what each open carried; `sockets` the server's side of each.
 */
async function host(fx, { brokerOpts = {} } = {}) {
  const wss = new WebSocketServer({ host: "127.0.0.1", port: 0, perMessageDeflate: false });
  await new Promise((r) => wss.once("listening", r));
  const events = [];
  const broker = brokerSession({ onEvent: (e) => events.push(e), ...brokerOpts });
  const h = { wss, broker, events, opens: [], sockets: [], links: [], url: `ws://127.0.0.1:${wss.address().port}/` };
  wss.on("connection", (socket, req) => {
    const f = parseOpenTarget(req.url);
    h.opens.push({ f, headers: req.headers });
    h.sockets.push(socket);
    const R = responder({ s: fx.hostKey, prologue: prologueBytes({ ...recordFields(fx.record), resume_n: f.resume_n }) });
    let link = null;
    socket.on("message", (data) => {
      const bytes = new Uint8Array(data);
      if (!link) {
        const m1 = R.readMessage1(bytes);
        assert.deepEqual(Buffer.from(m1.payload), fx.record, "message 1 carries the record");
        const m2 = R.writeMessage2(new Uint8Array(0));
        socket.send(m2.message, { binary: true });
        link = broker.attach({ cipher: { send: m2.send, receive: m2.receive }, sink: wsSink(socket) });
        h.links.push(link);
        return;
      }
      link.deliver(bytes);
    });
    socket.on("close", () => link?.lost("closed"));
  });
  h.close = () => new Promise((r) => { try { broker.end("test over"); } catch { /* (ended) */ } for (const s of h.sockets) s.terminate(); wss.close(() => r()); });
  return h;
}

/** The wrapper on its own, with NetSidecar's callbacks recorded. */
function channel(fx, h, opts = {}) {
  const commands = [], states = [];
  const asked = [];
  const tokens = [];
  const make = netChannel({ allowLoopback: true, open: loopbackOpen, retryMs: 20, handshakeMs: 2000, authToken: async (open) => { asked.push(open); const t = token(); tokens.push(t); return t; }, ...opts });
  const start = { session: fx.body.session, browserGen: 2, hostStaticPub: Buffer.from(fx.hostKey.raw).toString("base64url"), relayUrl: h.url };
  const c = make({ start, record: fx.record, key: fx.key, policy: { exceptions: [] }, onCommand: (seq, bytes) => commands.push({ seq, bytes }), onState: (s, reason) => states.push(reason ? `${s}:${reason}` : s) });
  return { c, commands, states, asked, tokens };
}

test("the open: role=app with the record's fields, the record's exact bytes, a fresh request id, and the token asked for exactly that open", async () => {
  const fx = fixture(), h = await host(fx);
  const { c, states, asked, tokens } = channel(fx, h);
  try {
    await until(() => states.includes("open"), 3000, "open");
    const o = h.opens[0];
    assert.equal(o.f.role, "app");
    for (const k of ["fleet", "session", "agent", "browser_gen", "host_gen"]) assert.equal(o.f[k], fx.body[k], k);
    assert.equal(o.f.resume_n, 0);
    assert.equal(o.headers["sagebrush-browser-record"], fx.record.toString("base64url"));
    assert.match(o.headers["sagebrush-request"], /^[A-Za-z0-9_-]{21}[AQgw]$/);
    assert.equal(o.headers["sagebrush-relay-token"], tokens[0]);
    assert.deepEqual({ ...asked[0] }, { fleet: fx.body.fleet, host: fx.body.host, agent: fx.body.agent, browser_gen: 2, session: fx.body.session, host_gen: 1, resume_n: 0, request: o.headers["sagebrush-request"] }, "the token is asked for this open's tuple and request id");
    assert.equal(o.headers["sec-websocket-extensions"], undefined, "no compression offered");
  } finally { c.close(); await h.close(); }
});

test("a record that isn't this session's, or a host key that isn't 32 bytes, makes no channel", async () => {
  const fx = fixture(), h = await host(fx);
  try {
    const make = netChannel({ allowLoopback: true, open: loopbackOpen, authToken: token });
    const base = { record: fx.record, key: fx.key, policy: {}, onCommand() {}, onState() {} };
    const start = { session: fx.body.session, browserGen: 2, hostStaticPub: Buffer.from(fx.hostKey.raw).toString("base64url"), relayUrl: h.url };
    assert.throws(() => make({ ...base, start: { ...start, session: newId() } }), /this session's/);
    assert.throws(() => make({ ...base, start: { ...start, hostStaticPub: "AAAA" } }), /32 bytes/);
    assert.throws(() => make({ ...base, start, record: Buffer.from("not json") }), /JSON/);
    // (open injected: even a regression here can't reach a real relay)
    assert.throws(() => netChannel({ authToken: token, open: () => { throw new Error("must not open"); } })({ ...base, start }), /audience's/, "a ws: relay outside the tests");
    assert.equal(h.opens.length, 0);
  } finally { await h.close(); }
});

test("a command goes out as its canonical bytes, and its result comes back to the broker", async () => {
  const fx = fixture(), h = await host(fx);
  const { c, commands, states } = channel(fx, h);
  try {
    await until(() => states.includes("open"));
    const out = h.broker.submit({ method: "Page.navigate", params: { url: "https://example.com/" } });
    await until(() => commands.length === 1, 3000, "the command");
    assert.equal(commands[0].seq, 1);
    assert.deepEqual(Buffer.from(commands[0].bytes), Buffer.from(canonBytes({ method: "Page.navigate", params: { url: "https://example.com/" } })));
    c.result(1, Buffer.from(JSON.stringify({ frameId: "F1" })));
    assert.deepEqual(await out, { outcome: "result", answer: { frameId: "F1" } });
  } finally { c.close(); await h.close(); }
});

test("an abandoned command is unknown to the broker, and its late result is discarded", async () => {
  const fx = fixture(), h = await host(fx);
  const { c, commands, states } = channel(fx, h);
  try {
    await until(() => states.includes("open"));
    const out = h.broker.submit({ n: 1 });
    await until(() => commands.length === 1);
    c.refused(1, "abandoned");
    assert.deepEqual(await out, { outcome: "unknown", reason: "abandoned" });
    c.result(1, Buffer.from("{}")); // (late: no second outcome, nothing thrown)
    const next = h.broker.submit({ n: 2 });
    await until(() => commands.length === 2);
    c.result(2, Buffer.from("{\"ok\":true}"));
    assert.deepEqual(await next, { outcome: "result", answer: { ok: true } });
  } finally { c.close(); await h.close(); }
});

test("a takeover refusal while not paused is unknown (abandon), never not run, with or without refuseUnsent in the build", async () => {
  const fx = fixture(), h = await host(fx);
  const { c, commands, states } = channel(fx, h);
  try {
    await until(() => states.includes("open"));
    const a = h.broker.submit({ n: 1 });
    await until(() => commands.length === 1);
    c.refused(1, "takeover"); // (not paused: refuseUnsent, where the session has it, refuses the call)
    assert.deepEqual(await a, { outcome: "unknown", reason: "abandoned" });
  } finally { c.close(); await h.close(); }
});

test("takeover pauses: a command after it is refused paused (not run) and never reaches onCommand; resume admits again", async () => {
  const fx = fixture(), h = await host(fx);
  const { c, commands, states } = channel(fx, h);
  try {
    await until(() => states.includes("open"));
    c.takeover();
    assert.deepEqual(await h.broker.submit({ n: 1 }), { outcome: "not_run", reason: "paused" });
    assert.equal(commands.length, 0);
    c.resume();
    const out = h.broker.submit({ n: 2 });
    await until(() => commands.length === 1);
    c.result(commands[0].seq, Buffer.from("{\"n\":2}"));
    assert.deepEqual(await out, { outcome: "result", answer: { n: 2 } });
  } finally { c.close(); await h.close(); }
});

test("a lost transport resumes on a new one at resume_n 1: resuming, then open, and the session carries on", async () => {
  const fx = fixture(), h = await host(fx);
  const { c, commands, states, tokens } = channel(fx, h);
  try {
    await until(() => states.includes("open"));
    const first = h.broker.submit({ n: 1 });
    await until(() => commands.length === 1);
    h.sockets[0].terminate(); // (the relay drops the pair)
    await until(() => states.includes("resuming"), 3000, "resuming");
    await until(() => h.opens.length === 2 && states.filter((s) => s === "open").length === 2, 3000, "the second open");
    assert.equal(h.opens[1].f.resume_n, 1);
    assert.notEqual(h.opens[1].headers["sagebrush-request"], h.opens[0].headers["sagebrush-request"], "a fresh request id per open");
    assert.equal(h.opens[1].headers["sagebrush-relay-token"], tokens[1], "a fresh token per open");
    assert.notEqual(tokens[1], tokens[0]);
    c.result(1, Buffer.from("{\"n\":1}")); // (answered after the resume: delivered once on the new transport)
    assert.deepEqual(await first, { outcome: "result", answer: { n: 1 } });
    assert.equal(commands.length, 1, "the command ran once");
  } finally { c.close(); await h.close(); }
});

test("a text message on the transport loses it (binary only, §5.4): the channel resumes on a new one", async () => {
  const fx = fixture(), h = await host(fx);
  const { c, states } = channel(fx, h);
  try {
    await until(() => states.includes("open"));
    h.sockets[0].send("hello", { binary: false });
    await until(() => h.opens.length === 2 && states.filter((s) => s === "open").length === 2, 3000, "the resume after a text message");
    assert.equal(h.opens[1].f.resume_n, 1);
    assert.ok(states.includes("resuming"));
  } finally { c.close(); await h.close(); }
});

test("blocked Writable: the host stops reading; writes are withheld, reading pauses, and the cap ends the session synchronously with a bounded close", async () => {
  const fx = fixture(), h = await host(fx);
  const cap = 256 * 1024, reserve = 2048;
  const { c, states } = channel(fx, h, { sinkHighWater: 32 * 1024, sessionOptions: { linkOptions: { cap, reserve, closeMs: 200 } } });
  try {
    await until(() => states.includes("open"));
    await tick(50);
    // (the server's socket stops reading: the app's socket writes are really held in the OS and in ws)
    h.sockets[0]._socket.pause();
    const sock = c.socket;
    const big = { data: "x".repeat(30000) };
    let i = 0;
    for (; i < 1000 && !states.some((s) => s.startsWith("ended")); i++) c.event(Buffer.from(JSON.stringify(big)));
    // (the session ended inside the event() call that would have passed cap - reserve: synchronously, with "limit")
    assert.ok(states.some((s) => s === "ended:limit"), `ended by the cap (${states.join(",")})`);
    assert.ok(i < 1000, "the flood was cut off, not absorbed");
    assert.ok(i * 30000 < cap + 2 * 30000, `no more than the cap was accepted (${i} events)`);
    assert.equal(c.session.ended, "limit");
    // (the bounded close: the socket is gone within closeMs and the wrapper's own shutdown)
    await until(() => sock.readyState === 3, 2000, "the socket closed");
    const before = states.length;
    c.event(Buffer.from("{}"));
    c.result(1, Buffer.from("{}"));
    assert.equal(states.length, before, "nothing after the end");
  } finally { c.close(); await h.close(); }
});

test("blocked Writable: while the writer must drain, the app stops reading the socket, and resumes at the drain", async () => {
  const fx = fixture(), h = await host(fx);
  const { c, states } = channel(fx, h, { sinkHighWater: 16 * 1024, sessionOptions: { linkOptions: { cap: 4 * 1024 * 1024, reserve: 2048 } } });
  try {
    await until(() => states.includes("open"));
    await tick(50);
    h.sockets[0]._socket.pause();
    for (let i = 0; i < 40; i++) c.event(Buffer.from(JSON.stringify({ data: "y".repeat(20000) })));
    await until(() => c.socket.isPaused, 2000, "reading paused");
    assert.ok(!states.some((s) => s.startsWith("ended")), "under the cap the session lives");
    h.sockets[0]._socket.resume();
    await until(() => !c.socket.isPaused, 3000, "reading resumed at the drain");
    await until(() => h.events.length > 0, 3000, "events arrived once the host read again");
  } finally { c.close(); await h.close(); }
});

test("refuseUnsent: takeover and bad refusals go to the session's refuseUnsent first; abandoned never does; a refused call falls back to abandon", async () => {
  // (the session's call is the channel's; here a wrapper around the real appSession records what the channel asks of it)
  const calls = [];
  const makeSession = (opts) => {
    const real = appSession(opts);
    let accept = true;
    const w = {};
    for (const k of Reflect.ownKeys(real)) {
      const d = Object.getOwnPropertyDescriptor(real, k);
      if (d.get) Object.defineProperty(w, k, { get: () => real[k] });
      else w[k] = real[k];
    }
    w.refuseUnsent = (seq, reason) => { calls.push(["refuseUnsent", seq, reason]); return accept; };
    w.abandon = (seq) => { calls.push(["abandon", seq]); return real.abandon(seq); };
    w.setAccept = (v) => { accept = v; };
    return w;
  };
  const fx = fixture(), h = await host(fx);
  const { c, commands, states } = channel(fx, h, { makeSession });
  try {
    await until(() => states.includes("open"));
    h.broker.submit({ n: 1 });
    await until(() => commands.length === 1);
    c.refused(1, "bad");
    assert.deepEqual(calls, [["refuseUnsent", 1, "bad"]], "bad: refuseUnsent, and no abandon");
    calls.length = 0;
    c.session.setAccept(false);
    c.refused(1, "takeover");
    assert.deepEqual(calls, [["refuseUnsent", 1, "takeover"], ["abandon", 1]], "a refused refuseUnsent falls back to abandon");
    calls.length = 0;
    c.refused(1, "abandoned");
    assert.deepEqual(calls, [["abandon", 1]], "abandoned: abandon only");
  } finally { c.close(); await h.close(); }
});

test("an authToken failure ends the session before any open", async () => {
  const fx = fixture(), h = await host(fx);
  const { c, states } = channel(fx, h, { authToken: async () => { throw new Error("no token"); } });
  try {
    await until(() => states.some((s) => s.startsWith("ended")), 2000, "ended");
    assert.deepEqual(states, ["ended:the relay open couldn't be made"]);
    assert.equal(h.opens.length, 0);
  } finally { c.close(); await h.close(); }
});

test("close(): the socket is terminated, no callback follows, and the host sees the transport lost", async () => {
  const fx = fixture(), h = await host(fx);
  const { c, states } = channel(fx, h);
  try {
    await until(() => states.includes("open"));
    const n = states.length;
    c.close();
    await until(() => h.sockets[0].readyState === 3, 2000, "the server side closed");
    await tick(100);
    assert.equal(states.length, n, "close() is quiet");
    assert.equal(h.opens.length, 1, "no reconnect after close");
  } finally { await h.close(); }
});

test("through NetSidecar: record -> connecting -> open; a command reaches cdp as its bytes; net.result reaches the broker", async () => {
  const fx = fixture(), h = await host(fx);
  const sent = [];
  const sidecar = new NetSidecar({
    send: (head, body) => { sent.push({ head, body }); return true; },
    makeProxy: async () => ({ port: 50200, close() {} }),
    makeChannel: netChannel({ allowLoopback: true, open: loopbackOpen, retryMs: 20, authToken: token }),
    key: fx.key,
  });
  try {
    await sidecar.begin();
    sidecar.frame({ kind: "net.start", session: fx.body.session, browser_gen: 2, host_static_pub: Buffer.from(fx.hostKey.raw).toString("base64url"), relay_url: h.url });
    sidecar.frame({ kind: "net.record" }, fx.record);
    const states = () => sent.filter((f) => f.head.kind === "rust.net_state").map((f) => f.head.state);
    await until(() => states().includes("open"), 3000, "open");
    assert.deepEqual(states(), ["connecting", "open"]);
    const out = h.broker.submit({ n: 7 });
    await until(() => sent.some((f) => f.head.kind === "cdp.command"), 3000, "cdp.command");
    const cmd = sent.find((f) => f.head.kind === "cdp.command");
    assert.deepEqual(Buffer.from(cmd.body), Buffer.from(canonBytes({ n: 7 })));
    sidecar.frame({ kind: "net.result", seq: cmd.head.seq }, Buffer.from("{\"done\":7}"));
    assert.deepEqual(await out, { outcome: "result", answer: { done: 7 } });
  } finally { sidecar.fail("test over"); await h.close(); }
});

test("no relay token source, no channel: netChannel without authToken throws and nothing opens", async () => {
  const fx = fixture(), h = await host(fx);
  try {
    assert.throws(() => netChannel(), /no relay token source/);
    assert.throws(() => netChannel({ allowLoopback: true }), /no relay token source/);
    assert.throws(() => netChannel({ allowLoopback: true, authToken: "rt1.not-a-function" }), /no relay token source/);
    await tick(50);
    assert.equal(h.opens.length, 0);
  } finally { await h.close(); }
});

test("anything but one relay token in its form ends the session with no socket opened", async () => {
  const good = token();
  const bad = [
    undefined, null, "", " ", {}, [good], 42,
    { "Sagebrush-Relay-Token": good }, { "sagebrush-relay-token": good, Cookie: "x" },
    { "Sagebrush-Request": "A".repeat(22), "Sagebrush-Relay-Token": good },
    "rt1.short", `rt2.${good.slice(4)}`, `${good} `, ` ${good}`, `${good}\r\nCookie: x`, `${good},${token()}`,
    `${good.slice(0, -1)}B`, // (the last character carries 4 bits and 2 zero bits: B can't end 32 bytes)
    `rt1.${randomBytes(33).toString("base64url")}`, `rt1.${randomBytes(32).toString("base64")}`,
  ];
  for (const t of bad) {
    const fx = fixture(), h = await host(fx);
    const opened = [];
    const { c, states } = channel(fx, h, { authToken: async () => t, open: (url, headers) => { opened.push(url); throw new Error("must not open"); } });
    try {
      await until(() => states.some((s) => s.startsWith("ended")), 2000, `ended for ${JSON.stringify(t)}`);
      assert.deepEqual(states, ["ended:the relay token isn't valid"], JSON.stringify(t));
      assert.equal(opened.length, 0, JSON.stringify(t));
      assert.equal(h.opens.length, 0, JSON.stringify(t));
    } finally { c.close(); await h.close(); }
  }
  assert.match(good, RELAY_TOKEN);
});

test("the open carries exactly one Sagebrush-Relay-Token, and only the wrapper's own Sagebrush headers; the token is in no trace or URL", async () => {
  const fx = fixture(), h = await host(fx);
  const traces = [];
  const { c, states, tokens } = channel(fx, h, { onTrace: (e) => traces.push(JSON.stringify(e)) });
  try {
    await until(() => states.includes("open"));
    const req = h.opens[0];
    const names = Object.keys(req.headers).filter((k) => k.startsWith("sagebrush-")).sort();
    assert.deepEqual(names, ["sagebrush-browser-record", "sagebrush-relay-token", "sagebrush-request"]);
    assert.equal(req.headers.cookie, undefined);
    assert.equal(req.headers.authorization, undefined);
    assert.equal(req.headers["sagebrush-relay-token"], tokens[0], "one value, not a list");
    for (const t of traces) assert.ok(!t.includes(tokens[0].slice(4)), "no token in a trace");
    assert.ok(!traces.join("").includes("rt1."), "no token in a trace");
  } finally { c.close(); await h.close(); }
});

test("relayBase: only the record's trusted audience's relay origin; another host, a lookalike, a port, userinfo, a fragment, a query or a path is refused", () => {
  const aud = "https://sagebrush.space";
  assert.equal(relayOrigin(aud), "wss://sagebrush.space");
  assert.equal(relayOrigin("https://dev.sagebrush.space"), "wss://dev.sagebrush.space");
  assert.equal(relayBase("wss://sagebrush.space", aud).href, "wss://sagebrush.space/");
  assert.equal(relayBase("wss://sagebrush.space/", aud).href, "wss://sagebrush.space/");
  assert.equal(relayBase("wss://dev.sagebrush.space/", "https://dev.sagebrush.space").href, "wss://dev.sagebrush.space/");
  const refused = [
    "wss://evil.example/", "wss://sagebrush.space.evil.example/", "wss://evilsagebrush.space/", "wss://dev.sagebrush.space/",
    "wss://sagebrush.space:443/", "wss://sagebrush.space:8443/", "wss://u@sagebrush.space/", "wss://u:p@sagebrush.space/",
    "wss://evil.example@sagebrush.space/", "wss://sagebrush.space@evil.example/", "wss://sagebrush.space/#", "wss://sagebrush.space#x",
    "wss://sagebrush.space/?", "wss://sagebrush.space/?a=1", "wss://sagebrush.space/api/", "wss://sagebrush.space//", "wss://sagebrush.space/.",
    "wss://SAGEBRUSH.space/", "wss://sagebrush.space./", " wss://sagebrush.space/", "wss://sagebrush.space/ ", "ws://sagebrush.space/",
    "https://sagebrush.space/", "wss:sagebrush.space", "wss:\\\\sagebrush.space\\", "ws://127.0.0.1:8080/", "", undefined, null,
  ];
  for (const u of refused) assert.throws(() => relayBase(u, aud), /audience's/, JSON.stringify(u));
  for (const a of ["https://evil.example", "https://sagebrush.space/", "https://sagebrush.space:443", "http://sagebrush.space", "relay.example", undefined]) {
    assert.throws(() => relayBase("wss://sagebrush.space/", a), /trusted/, JSON.stringify(a));
  }
  assert.equal(relayBase("wss://evil.example/", "https://evil.example", { audiences: ["https://evil.example"] }).href, "wss://evil.example/", "a configured audience");
  for (const a of ["https://evil.example:8443", "https://u@evil.example", "https://evil.example/x", "https://evil.example/?a", "https://evil.example/#x"]) {
    assert.throws(() => relayOrigin(a, [a]), /trusted/, `a configured audience in another form: ${a}`);
  }
  // (the test loopback: only with allowLoopback, only ws://127.0.0.1:<port>[/], and the audience still trusted)
  assert.equal(relayBase("ws://127.0.0.1:8080/", aud, { allowLoopback: true }).href, "ws://127.0.0.1:8080/");
  for (const u of ["ws://u@127.0.0.1:8080/", "ws://127.0.0.1:8080/#x", "ws://127.0.0.1:8080/?a", "ws://127.0.0.1:8080/x", "ws://127.0.0.1/", "ws://localhost:8080/", "ws://127.0.0.1.evil.example:8080/", "wss://evil.example/ws://127.0.0.1:8080/", "xws://127.0.0.1:8080/"]) {
    assert.throws(() => relayBase(u, aud, { allowLoopback: true }), /audience's/, u);
  }
  assert.throws(() => relayBase("ws://127.0.0.1:8080/", "https://evil.example", { allowLoopback: true }), /trusted/);
});

test("a relay that isn't the audience's makes no channel: no token is asked for and no socket opened", async () => {
  const fx = fixture();
  const asked = [], opened = [];
  const make = netChannel({ authToken: (o) => { asked.push(o); return token(); }, open: (u) => { opened.push(u); throw new Error("must not open"); }, retryMs: 5 });
  const start = { session: fx.body.session, browserGen: 2, hostStaticPub: Buffer.from(fx.hostKey.raw).toString("base64url") };
  const base = { record: fx.record, key: fx.key, policy: {}, onCommand() {}, onState() {} };
  for (const relayUrl of ["wss://evil.example/", "wss://sagebrush.space.evil.example/", "wss://sagebrush.space:8443/", "wss://u@sagebrush.space/", "wss://sagebrush.space/#x"]) {
    assert.throws(() => make({ ...base, start: { ...start, relayUrl } }), /audience's/, relayUrl);
  }
  const untrusted = Buffer.from(JSON.stringify({ v: 1, type: "browser-session", body: { ...fx.body, aud: "https://evil.example" }, sig: "test" }));
  assert.throws(() => make({ ...base, record: untrusted, start: { ...start, relayUrl: "wss://evil.example/" } }), /trusted/);
  await tick(50);
  assert.equal(asked.length, 0, "no token asked for");
  assert.equal(opened.length, 0, "no socket");
});
