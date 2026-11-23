// The browser lane's net sidecar (browser-lane3-runtime.md, the net rows of "The two sidecars and their IPC"): its
// frames in and out, driven through its process entry over real encoded frames, with a fake channel (the channel is
// auth's, O11 §7) and, in one row, the real local proxy.

import assert from "node:assert/strict";
import { test } from "node:test";
import { EventEmitter } from "node:events";
import { PassThrough, Writable } from "node:stream";
import { connect as tcpConnect } from "node:net";
import { createEncoder, createDecoder } from "../lib/fleet/browser/frames.mjs";
import { main, createWriter, LIMITS } from "../lib/fleet/browser/sidecar-net-main.mjs";

const fromRust = createEncoder({ from: "rust" });
const fromCdp = createEncoder({ from: "cdp" });
const START = { to: "net", kind: "net.start", session: "s-1", browser_gen: 2, host_static_pub: "h".repeat(43), relay_url: "wss://relay.example/s" };
const tick = () => new Promise((r) => setImmediate(r));

/** A fake stdout: keeps every byte; `writableLength` grows until `drain()`; `end(cb)` calls back unless `hang`. */
function fakeStdout({ hang = false } = {}) {
  const out = new EventEmitter();
  out.chunks = [];
  out.writableLength = 0;
  out.held = true;
  out.write = (b) => { out.chunks.push(Buffer.from(b)); if (out.held) out.writableLength += b.length; return true; };
  out.end = (cb) => { out.ended = true; if (!hang) setImmediate(cb); };
  /** Every frame written, decoded as Rust and as cdp would (split by length, decoded by its own `to`). */
  out.frames = () => {
    const all = Buffer.concat(out.chunks), frames = [];
    for (let i = 0; i < all.length; ) {
      const n = 4 + all.readUInt32BE(i), one = all.subarray(i, i + n);
      const to = JSON.parse(one.subarray(8, 8 + one.readUInt32BE(4)).toString()).to;
      frames.push(...createDecoder({ to, from: "net" }).push(one));
      i += n;
    }
    return frames;
  };
  out.kinds = () => out.frames().map((f) => f.head.kind + (f.head.state ? `:${f.head.state}` : ""));
  return out;
}

/** A fake channel (auth's, later): records what net gives it; the test drives onCommand and onState. */
function fakeChannel() {
  const c = { made: null, calls: [] };
  c.make = (args) => {
    c.made = args;
    return {
      result: (seq, body) => c.calls.push(["result", seq, Buffer.from(body).toString()]),
      refused: (seq, reason) => c.calls.push(["refused", seq, reason]),
      event: (body) => c.calls.push(["event", Buffer.from(body).toString()]),
      takeover: () => c.calls.push(["takeover"]),
      resume: () => c.calls.push(["resume"]),
      close: () => c.calls.push(["close"]),
    };
  };
  return c;
}

/** A net sidecar on fake stdio, a fake proxy and (optionally) a fake channel. */
async function run({ channel = fakeChannel(), stdout = fakeStdout(), limits, makeProxy, withChannel = true } = {}) {
  const stdin = new PassThrough();
  const exits = [];
  const proxy = { closed: false };
  const sidecar = main({
    stdin, stdout, stderr: { write: () => {} }, exit: (code) => exits.push(code), limits,
    makeChannel: withChannel ? channel.make : null,
    makeProxy: makeProxy ?? (async () => ({ port: 50123, close: () => { proxy.closed = true; } })),
  });
  await tick();
  const push = (bytes) => { stdin.write(bytes); return tick(); };
  return { sidecar, stdin, stdout, exits, proxy, channel, push };
}
const ended = (t) => t.stdout.frames().filter((f) => f.head.kind === "rust.net_state" && f.head.state === "ended").map((f) => f.head.reason);

test("net sidecar: says hello first, with its own channel key and fresh proxy credentials", async () => {
  const a = await run(), b = await run();
  const [h] = a.stdout.frames();
  assert.equal(h.head.kind, "rust.net_hello");
  assert.equal(h.head.proxy_port, 50123);
  assert.equal(Buffer.from(h.head.app_session_pub, "base64url").length, 32);
  for (const k of ["proxy_username", "proxy_password"]) assert.match(h.head[k], /^[A-Za-z0-9_-]{22}$/);
  const [h2] = b.stdout.frames();
  assert.notEqual(h.head.app_session_pub, h2.head.app_session_pub, "a new key per session");
  assert.notEqual(h.head.proxy_password, h2.head.proxy_password, "new credentials per session");
});

test("net sidecar: start, policy and record make the channel; commands go to cdp and answers back to the channel", async () => {
  const t = await run();
  await t.push(fromRust({ ...START }));
  await t.push(fromRust({ to: "net", kind: "net.policy", exceptions: [] }));
  await t.push(fromRust({ to: "net", kind: "net.record" }, Buffer.from("signed record bytes")));
  const m = t.channel.made;
  assert.deepEqual(m.start, { session: "s-1", browserGen: 2, hostStaticPub: "h".repeat(43), relayUrl: "wss://relay.example/s" });
  assert.equal(m.record.toString(), "signed record bytes");
  assert.equal(m.key.privateKey.asymmetricKeyType, "x25519");
  assert.equal(m.key.privateKey.type, "private");
  assert.equal(m.key.pub, t.stdout.frames()[0].head.app_session_pub);
  assert.deepEqual(m.policy, { exceptions: [] });
  m.onState("open");
  m.onCommand(1, Buffer.from('{"method":"Page.reload"}'));
  m.onCommand(2, Buffer.from('{"method":"Runtime.evaluate"}'));
  await tick();
  await t.push(fromCdp({ to: "net", kind: "net.event" }, Buffer.from('{"method":"Page.loadEventFired"}')));
  await t.push(fromCdp({ to: "net", kind: "net.result", seq: 1 }, Buffer.from('{"result":{}}')));
  await t.push(fromCdp({ to: "net", kind: "net.refused", seq: 2, reason: "takeover" }));
  await t.push(fromRust({ to: "net", kind: "net.takeover" }));
  await t.push(fromRust({ to: "net", kind: "net.resume" }));
  await t.push(fromRust({ to: "net", kind: "net.retire" }));
  await tick();
  assert.deepEqual(t.stdout.kinds(), ["rust.net_hello", "rust.net_state:connecting", "rust.net_state:open", "cdp.command", "cdp.command", "rust.net_state:ended"]);
  const cmds = t.stdout.frames().filter((f) => f.head.kind === "cdp.command");
  assert.deepEqual(cmds.map((f) => [f.head.seq, f.body.toString()]), [[1, '{"method":"Page.reload"}'], [2, '{"method":"Runtime.evaluate"}']]);
  assert.deepEqual(t.channel.calls, [["event", '{"method":"Page.loadEventFired"}'], ["result", 1, '{"result":{}}'], ["refused", 2, "takeover"], ["takeover"], ["resume"], ["close"]]);
  assert.deepEqual(ended(t), ["retired by the app"]);
  assert.equal(t.proxy.closed, true);
  assert.deepEqual(t.exits, [0]);
});

test("net sidecar: frames out of order end it, each with its own reason", async () => {
  const cases = [
    [[fromRust({ ...START }), fromRust({ ...START })], "a second start"],
    [[fromRust({ to: "net", kind: "net.record" }, Buffer.from("r"))], "a record before start"],
    [[fromRust({ ...START }), fromRust({ to: "net", kind: "net.record" }, Buffer.from("r")), fromRust({ to: "net", kind: "net.record" }, Buffer.from("r"))], "a second record"],
    [[fromRust({ ...START }), fromRust({ to: "net", kind: "net.record" })], "an empty record"],
    [[fromRust({ to: "net", kind: "net.takeover" })], "takeover before the channel"],
    [[fromRust({ to: "net", kind: "net.resume" })], "resume before the channel"],
    [[fromCdp({ to: "net", kind: "net.result", seq: 1 }, Buffer.from('{"result":{}}'))], "an answer for no open command"],
    [[fromCdp({ to: "net", kind: "net.refused", seq: 0, reason: "bad" })], "an answer for no open command"],
  ];
  for (const [frames, reason] of cases) {
    const t = await run();
    for (const f of frames) await t.push(f);
    assert.deepEqual(ended(t), [reason], reason);
    assert.deepEqual(t.exits, [0], reason);
  }
  // (a start before the hello: the proxy hasn't started yet)
  let release;
  const t = await run({ makeProxy: () => new Promise((r) => { release = () => r({ port: 50124, close() {} }); }) });
  await t.push(fromRust({ ...START }));
  assert.deepEqual(ended(t), ["start before the hello"]);
  release();
  await tick();
  assert.deepEqual(t.stdout.kinds(), ["rust.net_state:ended"], "no hello after the end");
  // (no channel yet in this build: the session ends at its record)
  const n = await run({ withChannel: false });
  await n.push(fromRust({ ...START }));
  await n.push(fromRust({ to: "net", kind: "net.record" }, Buffer.from("r")));
  assert.deepEqual(ended(n), ["no channel in this build"]);
});

test("net sidecar: one answer per command, seqs only go up, and an oversize command never reaches cdp", async () => {
  const live = async () => {
    const t = await run();
    await t.push(fromRust({ ...START }));
    await t.push(fromRust({ to: "net", kind: "net.record" }, Buffer.from("r")));
    return t;
  };
  let t = await live();
  t.channel.made.onCommand(5, Buffer.from("{}"));
  await tick();
  await t.push(fromCdp({ to: "net", kind: "net.result", seq: 5 }, Buffer.from('{"result":{}}')));
  await t.push(fromCdp({ to: "net", kind: "net.result", seq: 5 }, Buffer.from('{"result":{}}')));
  assert.deepEqual(ended(t), ["an answer for no open command"], "a second answer");
  for (const seqs of [[3, 3], [4, 2], [-1]]) {
    t = await live();
    for (const s of seqs) t.channel.made.onCommand(s, Buffer.from("{}"));
    await tick();
    assert.deepEqual(ended(t), ["a repeated or out-of-order seq from the channel"], String(seqs));
  }
  t = await live();
  t.channel.made.onCommand(1, Buffer.alloc(1048577, 0x61));
  t.channel.made.onCommand(2, Buffer.alloc(0));
  t.channel.made.onCommand(3, Buffer.from("{}"));
  await tick();
  assert.deepEqual(t.channel.calls, [["refused", 1, "bad"], ["refused", 2, "bad"]]);
  assert.deepEqual(t.stdout.frames().filter((f) => f.head.kind === "cdp.command").map((f) => f.head.seq), [3]);
});

test("net sidecar: the channel's end and unknown states end it with a fixed reason", async () => {
  for (const [state, reason] of [["ended", "the channel ended"], ["weird", "the channel said something unknown"]]) {
    const t = await run();
    await t.push(fromRust({ ...START }));
    await t.push(fromRust({ to: "net", kind: "net.record" }, Buffer.from("r")));
    t.channel.made.onState(state, "the host's own words <script>");
    await tick();
    assert.deepEqual(ended(t), [reason]);
    assert.ok(!JSON.stringify(t.stdout.frames().map((f) => f.head)).includes("host's own words"));
  }
});

test("net sidecar: the app's channel: garbage, a misrouted frame, a truncated frame and a plain end each end it once", async () => {
  const cdpFrame = createEncoder({ from: "rust" })({ to: "cdp", kind: "cdp.retire" });
  const whole = fromRust({ ...START });
  for (const [input, close, reason] of [
    [Buffer.from("garbage!"), false, "a bad frame from the app"],
    [cdpFrame, false, "a bad frame from the app"],
    [whole.subarray(0, 10), true, "the app's channel ended inside a frame"],
    [Buffer.alloc(0), true, "the app closed the channel"],
  ]) {
    const t = await run();
    if (input.length) await t.push(input);
    if (close) { t.stdin.end(); await tick(); await tick(); }
    await t.push(fromRust({ to: "net", kind: "net.retire" })).catch(() => {});
    assert.deepEqual(ended(t), [reason], reason);
    assert.deepEqual(t.exits, [0], reason);
  }
  // (a broken stdout, as when the app is gone)
  const t = await run();
  t.stdout.emit("error", Object.assign(new Error("EPIPE"), { code: "EPIPE" }));
  await tick();
  assert.deepEqual(ended(t), ["the app's channel failed"]);
  assert.deepEqual(t.exits, [0]);
});

test("net sidecar: one writer with a cap and a reserve: a data frame past the cap ends it, and 'ended' is still said", async () => {
  const limits = { outBytes: 2000, reserveBytes: 512, flushMs: 1000 };
  const stdout = blockedStdout(1 << 20); // (a real Writable that never finishes a write)
  const t = await run({ limits, stdout });
  await t.push(fromRust({ ...START }));
  await t.push(fromRust({ to: "net", kind: "net.record" }, Buffer.from("r")));
  t.channel.made.onCommand(1, Buffer.alloc(800, 0x61));
  t.channel.made.onCommand(2, Buffer.alloc(800, 0x62));
  t.channel.made.onCommand(3, Buffer.alloc(800, 0x63)); // (past 2000 unwritten bytes: not written)
  // (ended at once, in the same call: no more admissions, the channel closed, the proxy stopped)
  assert.equal(t.sidecar.state, "ended");
  assert.deepEqual(t.channel.calls, [["close"]]);
  assert.equal(t.proxy.closed, true);
  t.channel.made.onCommand(4, Buffer.from("{}"));
  await tick();
  assert.deepEqual(stdout.frames().filter((f) => f.head.kind === "cdp.command").map((f) => f.head.seq), [1, 2]);
  assert.deepEqual(stdout.frames().filter((f) => f.head.state === "ended").map((f) => f.head.reason), ["the app isn't reading"], "exactly one terminal frame, in the reserve");
  // (the writer alone: a control frame may use the reserve, nothing may pass it)
  const out = fakeStdout();
  const write = createWriter(out, limits);
  assert.equal(write(Buffer.alloc(2000)), true);
  assert.equal(write(Buffer.alloc(1)), false);
  assert.equal(write(Buffer.alloc(512), { terminal: true }), true);
  assert.equal(write(Buffer.alloc(1), { terminal: true }), false);
  assert.deepEqual(LIMITS, { outBytes: 8 * 1024 * 1024, reserveBytes: 64 * 1024, flushMs: 2000 });
});

test("net sidecar: the flush deadline: it exits even if the app never reads the rest", async () => {
  const t = await run({ stdout: blockedStdout(1 << 20), limits: { ...LIMITS, flushMs: 150 } }); // (end() never finishes)
  await t.push(fromRust({ to: "net", kind: "net.retire" }));
  assert.deepEqual(t.exits, []);
  await new Promise((r) => setTimeout(r, 250));
  assert.deepEqual(t.exits, [0]);
});

test("net sidecar: the real proxy: listening with the hello's credentials, refusing an account origin, closed on retire", { timeout: 20000 }, async () => {
  const stdin = new PassThrough(), stdout = fakeStdout(), logs = [];
  const exits = [];
  main({ stdin, stdout, stderr: { write: (s) => logs.push(s) }, exit: (c) => exits.push(c) });
  for (let i = 0; i < 50 && stdout.chunks.length === 0; i++) await new Promise((r) => setTimeout(r, 20));
  const h = stdout.frames()[0].head;
  const ask = (lines) => new Promise((resolve) => {
    const s = tcpConnect(h.proxy_port, "127.0.0.1", () => s.write(lines.join("\r\n") + "\r\n\r\n"));
    let got = "";
    s.on("data", (c) => { got += c; });
    s.on("error", () => resolve("refused"));
    s.on("close", () => resolve(got));
  });
  const auth = `Proxy-Authorization: Basic ${Buffer.from(`${h.proxy_username}:${h.proxy_password}`).toString("base64")}`;
  assert.match(await ask(["CONNECT example.com:443 HTTP/1.1"]), /^HTTP\/1\.1 407 /);
  assert.match(await ask(["CONNECT claude.ai:443 HTTP/1.1", auth]), /^HTTP\/1\.1 403 /);
  assert.ok(logs.some((l) => JSON.parse(l).proxy?.why === "account"));
  assert.ok(!logs.join("").includes(h.proxy_password));
  stdin.write(createEncoder({ from: "rust" })({ to: "net", kind: "net.retire" }));
  await new Promise((r) => setTimeout(r, 100));
  assert.equal(await ask(["CONNECT example.com:443 HTTP/1.1", auth]), "refused", "the proxy is closed");
  assert.deepEqual(exits, [0]);
});

test("net sidecar: the real process: hello on stdout, retire on stdin, 'ended' said, exit 0", { timeout: 20000 }, async () => {
  const { spawn } = await import("node:child_process");
  const { fileURLToPath } = await import("node:url");
  const child = spawn(process.execPath, [fileURLToPath(new URL("../lib/fleet/browser/sidecar-net-main.mjs", import.meta.url))], { stdio: ["pipe", "pipe", "pipe"] });
  const decoder = createDecoder({ to: "rust", from: "net" });
  const got = [];
  child.stdout.on("data", (c) => got.push(...decoder.push(c)));
  for (let i = 0; i < 100 && got.length === 0; i++) await new Promise((r) => setTimeout(r, 20));
  assert.equal(got[0]?.head.kind, "rust.net_hello");
  child.stdin.write(fromRust({ to: "net", kind: "net.retire" }));
  const code = await new Promise((r) => child.on("exit", r));
  assert.equal(code, 0);
  assert.deepEqual(got.slice(1).map((f) => [f.head.kind, f.head.state, f.head.reason]), [["rust.net_state", "ended", "retired by the app"]]);
});

/** A real Writable that never finishes a write (highWaterMark 1, callback withheld): everything after the first chunk
 *  stays queued, as when the app stops reading. `seen` keeps every frame handed to write(). */
function blockedStdout(highWaterMark = 1) {
  const out = new Writable({ highWaterMark, write(_chunk, _enc, _cb) { /* (never called back) */ } });
  out.seen = [];
  const write = out.write.bind(out);
  out.write = (b) => { out.seen.push(Buffer.from(b)); return write(b); };
  out.frames = () => {
    const all = Buffer.concat(out.seen), frames = [];
    for (let i = 0; i < all.length; ) {
      const n = 4 + all.readUInt32BE(i), one = all.subarray(i, i + n);
      const to = JSON.parse(one.subarray(8, 8 + one.readUInt32BE(4)).toString()).to;
      frames.push(...createDecoder({ to, from: "net" }).push(one));
      i += n;
    }
    return frames;
  };
  return out;
}

test("net sidecar, a real blocked stdout: stdin pauses while stdout needs to drain, and resumes when it drains", async () => {
  let release;
  const out = new Writable({ highWaterMark: 1, write(_c, _e, cb) { release = cb; } });
  out.frames = () => [];
  const stdin = new PassThrough();
  const sidecar = main({ stdin, stdout: out, stderr: { write() {} }, exit() {}, makeChannel: fakeChannel().make, makeProxy: async () => ({ port: 50125, close() {} }) });
  await tick();
  assert.equal(out.writableNeedDrain, true, "the hello filled the blocked stdout");
  assert.equal(stdin.isPaused(), true, "no more frames are taken from the app");
  stdin.write(fromRust({ ...START }));
  await tick();
  assert.equal(sidecar.state, "hello", "the start waits in stdin, unread");
  release();
  await tick(); await tick();
  assert.equal(stdin.isPaused(), false, "resumed on drain");
  assert.equal(sidecar.state, "started", "and the start was read");
});

test("net sidecar, a real blocked stdout: state frames share the normal budget; the reserve keeps 'ended' writable", async () => {
  // (writes never complete, and the high-water mark is above the cap, so the budget fills without a drain pause)
  const stdout = blockedStdout(1 << 20);
  const t = await run({ stdout, limits: { outBytes: 2500, reserveBytes: 200, flushMs: 100 } });
  await t.push(fromRust({ ...START }));
  await t.push(fromRust({ to: "net", kind: "net.record" }, Buffer.from("r")));
  // (the channel says "open" over and over: each a non-terminal state frame, until the budget is spent)
  for (let i = 0; i < 100 && t.sidecar.state !== "ended"; i++) t.channel.made.onState("open");
  assert.equal(t.sidecar.state, "ended", "ended in the call that hit the cap");
  const states = stdout.frames().filter((f) => f.head.kind === "rust.net_state");
  assert.deepEqual(states.at(-1).head, { to: "rust", kind: "rust.net_state", state: "ended", reason: "the app isn't reading" }, "the terminal frame was written");
  assert.ok(stdout.writableLength > 2500, "the terminal frame used the reserve");
  assert.ok(stdout.writableLength <= 2700);
  assert.deepEqual(t.channel.calls, [["close"]]);
  assert.equal(t.proxy.closed, true);
  await new Promise((r) => setTimeout(r, 200));
  assert.deepEqual(t.exits, [0], "and it exits by the flush deadline though nothing was read");
});

test("net sidecar: a channel that ends while it is being made is closed exactly once, and nothing follows", async () => {
  for (const [name, during, reason] of [
    ["ends", (a) => a.onState("ended", "gone"), "the channel ended"],
    ["commands", (a) => a.onCommand(1, Buffer.from("{}")), "the channel spoke before it was made"],
    ["opens", (a) => a.onState("open"), "the channel spoke before it was made"],
  ]) {
    let closes = 0;
    const t = await run({ channel: { make: (a) => { during(a); return { close: () => { closes++; }, result() {}, refused() {}, event() {}, takeover() {}, resume() {} }; } } });
    await t.push(fromRust({ ...START }));
    await t.push(fromRust({ to: "net", kind: "net.record" }, Buffer.from("r")));
    await t.push(fromRust({ to: "net", kind: "net.retire" }));
    assert.equal(closes, 1, name);
    assert.deepEqual(ended(t), [reason], name);
    assert.deepEqual(t.stdout.kinds(), ["rust.net_hello", "rust.net_state:connecting", "rust.net_state:ended"], name);
    assert.deepEqual(t.exits, [0], name);
  }
});
