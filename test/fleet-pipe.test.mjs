// The browser lane's CDP pipe client (browser-lane3-runtime.md, "The cdp interface"): NUL-delimited JSON on Chrome's
// debugging pipe. Most rows drive it in-process through fake pipe ends that deliver bytes synchronously, so "in pipe
// order, as each message is parsed" can be checked exactly; the last rows run a fake Chrome as a child process on real
// fds 3 and 4, as Rust will launch the real one.

import assert from "node:assert/strict";
import { test } from "node:test";
import { EventEmitter } from "node:events";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { openPipe, Cdp, CdpError, CdpClosed, LIMITS } from "../lib/fleet/browser/pipe.mjs";

const REASONS = new Set(["message over the size limit", "malformed message", "unmatched reply", "listener threw", "pipe ended", "pipe read error", "pipe write error", "Browser.getVersion failed"]);

/** Fake pipe ends: `chrome.say(...)` delivers bytes to the client at once; `chrome.sent` is what the client wrote. */
function fakeEnds() {
  const read = new EventEmitter();
  const write = new EventEmitter();
  const chrome = { sent: [], destroyed: { read: false, write: false } };
  read.destroy = () => { chrome.destroyed.read = true; };
  write.destroy = () => { chrome.destroyed.write = true; };
  write.write = (buf) => {
    if (chrome.writeThrows) throw new Error("EPIPE (synchronous)");
    assert.equal(buf[buf.length - 1], 0, "every message ends with one NUL");
    chrome.sent.push(JSON.parse(buf.subarray(0, -1).toString("utf8")));
    return true;
  };
  chrome.raw = (bytes) => read.emit("data", Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes, "utf8"));
  chrome.say = (...msgs) => chrome.raw(msgs.map((m) => JSON.stringify(m) + "\0").join(""));
  chrome.end = () => read.emit("end");
  chrome.last = () => chrome.sent[chrome.sent.length - 1];
  return { read, write, chrome };
}

/** An open client on fake ends (Browser.getVersion answered). */
async function open() {
  const { read, write, chrome } = fakeEnds();
  const p = openPipe({ read, write, pid: 4242 });
  assert.equal(chrome.last().method, "Browser.getVersion");
  chrome.say({ id: chrome.last().id, result: { product: "HeadlessChrome/158.0.8127.36" } });
  return { cdp: await p, chrome };
}

const reasonOf = async (cdp) => (await cdp.closed).reason;

test("pipe: opens once Browser.getVersion answers, and exposes Rust's pid", async () => {
  const { cdp, chrome } = await open();
  assert.ok(cdp instanceof Cdp);
  assert.equal(cdp.pid, 4242);
  assert.deepEqual(chrome.sent, [{ id: 1, method: "Browser.getVersion", params: {} }]);
});

test("pipe: openPipe checks its arguments", async () => {
  const { read, write } = fakeEnds();
  await assert.rejects(openPipe({ read: null, write, pid: 1 }), TypeError);
  await assert.rejects(openPipe({ read, write: {}, pid: 1 }), TypeError);
  for (const pid of [0, -1, 1.5, "1", undefined]) await assert.rejects(openPipe({ read, write, pid }), TypeError);
});

test("pipe: openPipe rejects with CdpClosed if the pipe ends first, or if Browser.getVersion fails", async () => {
  let { read, write, chrome } = fakeEnds();
  let p = openPipe({ read, write, pid: 1 });
  chrome.end();
  await assert.rejects(p, (e) => e instanceof CdpClosed && e.reason === "pipe ended");
  ({ read, write, chrome } = fakeEnds());
  p = openPipe({ read, write, pid: 1 });
  chrome.say({ id: 1, error: { code: -32000, message: "no" } });
  await assert.rejects(p, (e) => e instanceof CdpClosed && e.reason === "Browser.getVersion failed");
  assert.deepEqual(chrome.destroyed, { read: true, write: true });
});

test("pipe: send writes the command (params default to {}, sessionId only when given) and resolves with result", async () => {
  const { cdp, chrome } = await open();
  const a = cdp.send("Page.navigate", { url: "https://example.com/" }, "S1");
  assert.deepEqual(chrome.last(), { id: 2, method: "Page.navigate", params: { url: "https://example.com/" }, sessionId: "S1" });
  const b = cdp.send("Target.getTargets");
  assert.deepEqual(chrome.last(), { id: 3, method: "Target.getTargets", params: {} });
  chrome.say({ id: 3 }, { id: 2, result: { frameId: "F" }, sessionId: "S1" });
  assert.deepEqual(await b, {}, "a reply with no result resolves with {}");
  assert.deepEqual(await a, { frameId: "F" });
});

test("pipe: send checks its arguments, and refuses a message over the limit without closing", async () => {
  const { cdp } = await open();
  await assert.rejects(cdp.send(""), TypeError);
  await assert.rejects(cdp.send("X", []), TypeError);
  await assert.rejects(cdp.send("X", null), TypeError);
  await assert.rejects(cdp.send("X", {}, 7), TypeError);
  await assert.rejects(cdp.send("X", { s: "a".repeat(LIMITS.messageBytes) }), RangeError);
  const live = await Promise.race([cdp.closed.then(() => false), new Promise((r) => setImmediate(() => r(true)))]);
  assert.ok(live, "an oversized send doesn't close the pipe");
});

test("pipe: a CDP error rejects that send with CdpError { code, message, data }", async () => {
  const { cdp, chrome } = await open();
  const a = cdp.send("DOM.getDocument");
  const b = cdp.send("DOM.getDocument");
  chrome.say({ id: 2, error: { code: -32000, message: "No node", data: "detail" } }, { id: 3, error: { code: -32601, message: "nope" } });
  await assert.rejects(a, (e) => e instanceof CdpError && e.code === -32000 && e.message === "No node" && e.data === "detail");
  await assert.rejects(b, (e) => e instanceof CdpError && e.code === -32601 && !("data" in e));
});

test("pipe: a reply is matched by id AND sessionId; anything unmatched closes the pipe", async () => {
  for (const reply of [{ id: 2, result: {} }, { id: 2, result: {}, sessionId: "S2" }, { id: 99, result: {}, sessionId: "S1" }]) {
    const { cdp, chrome } = await open();
    const a = cdp.send("Runtime.evaluate", { expression: "1" }, "S1");
    chrome.say(reply);
    await assert.rejects(a, (e) => e instanceof CdpClosed && e.reason === "unmatched reply");
    assert.equal(await reasonOf(cdp), "unmatched reply");
  }
  const { cdp, chrome } = await open();
  const a = cdp.send("X");
  chrome.say({ id: 2, result: {} });
  await a;
  chrome.say({ id: 2, result: {} });
  assert.equal(await reasonOf(cdp), "unmatched reply", "a second reply to the same id is unmatched");
});

test("pipe: events arrive in pipe order, synchronously as each is parsed, across any chunking", async () => {
  const { cdp, chrome } = await open();
  const seen = [];
  cdp.on((ev) => seen.push(ev));
  chrome.say({ method: "A.one", params: { n: 1 } }, { method: "A.two", sessionId: "S1" });
  assert.deepEqual(seen, [{ method: "A.one", params: { n: 1 } }, { method: "A.two", params: {}, sessionId: "S1" }], "delivered before say() returned");
  const bytes = Buffer.from(JSON.stringify({ method: "B.split", params: { s: "é✓" } }) + "\0" + JSON.stringify({ method: "B.next" }) + "\0");
  for (let i = 0; i < bytes.length; i++) chrome.raw(bytes.subarray(i, i + 1)); // (byte by byte, through a multi-byte character)
  assert.deepEqual(seen.slice(2), [{ method: "B.split", params: { s: "é✓" } }, { method: "B.next", params: {} }]);
  // An event and a reply in one chunk: the event is delivered before the send settles.
  const order = [];
  cdp.on((ev) => order.push(ev.method));
  const p = cdp.send("C.cmd").then(() => order.push("reply"));
  chrome.say({ method: "C.before" }, { id: 2, result: {} }, { method: "C.after" });
  await p;
  assert.deepEqual(order, ["C.before", "C.after", "reply"]);
});

test("pipe: on() returns an unsubscribe; each subscription is its own", async () => {
  const { cdp, chrome } = await open();
  const seen = [];
  const f = (ev) => seen.push(ev.method);
  const off1 = cdp.on(f);
  cdp.on(f);
  chrome.say({ method: "E.one" });
  off1();
  chrome.say({ method: "E.two" });
  assert.deepEqual(seen, ["E.one", "E.one", "E.two"]);
  assert.throws(() => cdp.on("nope"), TypeError);
});

test("pipe: a listener that throws closes the pipe, and later messages in the same chunk aren't delivered", async () => {
  const { cdp, chrome } = await open();
  const seen = [];
  cdp.on((ev) => { seen.push(ev.method); if (ev.method === "Bad") throw new Error("listener bug"); });
  const a = cdp.send("X");
  chrome.say({ method: "Ok" }, { method: "Bad" }, { method: "Never" }, { id: 2, result: {} });
  assert.deepEqual(seen, ["Ok", "Bad"]);
  await assert.rejects(a, (e) => e instanceof CdpClosed && e.reason === "listener threw");
  assert.equal(await reasonOf(cdp), "listener threw");
});

test("pipe: malformed messages close the pipe (never parsed into a reply or an event)", async () => {
  const bad = [
    "{not json", "[1,2]", "null", "42", "\"str\"", "{}",
    JSON.stringify({ method: 7 }), JSON.stringify({ method: "" }), JSON.stringify({ method: "A", params: [] }),
    JSON.stringify({ method: "A", params: null }), JSON.stringify({ method: "A", sessionId: 5 }),
    JSON.stringify({ id: "2", result: {} }), JSON.stringify({ id: 2.5, result: {} }), JSON.stringify({ id: 2, result: [] }),
    JSON.stringify({ id: 2, result: null }), JSON.stringify({ id: 2, error: "boom" }), JSON.stringify({ id: 2, error: { code: "x", message: "m" } }),
    JSON.stringify({ id: 2, error: { code: 1 } }), JSON.stringify({ id: 2, result: {}, sessionId: 9 }),
  ];
  for (const text of bad) {
    const { cdp, chrome } = await open();
    const a = cdp.send("X");
    chrome.raw(text + "\0");
    await assert.rejects(a, (e) => e instanceof CdpClosed && e.reason === "malformed message", text);
    assert.equal(await reasonOf(cdp), "malformed message", text);
  }
  const { cdp, chrome } = await open();
  chrome.raw(Buffer.from([0x7b, 0xff, 0x7d, 0])); // (invalid UTF-8)
  assert.equal(await reasonOf(cdp), "malformed message");
});

test("pipe: one message is at most 64 MiB; a larger one closes the pipe before its NUL arrives", async () => {
  assert.equal(LIMITS.messageBytes, 64 * 1024 * 1024);
  // Exactly at the limit: delivered.
  {
    const { cdp, chrome } = await open();
    const head = '{"method":"Big","params":{"s":"', tail = '"}}';
    const msg = Buffer.alloc(LIMITS.messageBytes, 0x61);
    msg.write(head, 0, "latin1");
    msg.write(tail, msg.length - tail.length, "latin1");
    let got = 0;
    cdp.on((ev) => { got = ev.params.s.length; });
    chrome.raw(msg.subarray(0, 1000));
    chrome.raw(Buffer.concat([msg.subarray(1000), Buffer.from([0])]));
    assert.equal(got, LIMITS.messageBytes - head.length - tail.length);
  }
  // One byte over, in pieces and with no NUL yet: closed.
  {
    const { cdp, chrome } = await open();
    const a = cdp.send("X");
    const piece = Buffer.alloc(LIMITS.messageBytes / 4, 0x61);
    for (let i = 0; i < 4; i++) chrome.raw(piece);
    const live = await Promise.race([cdp.closed.then(() => false), new Promise((r) => setImmediate(() => r(true)))]);
    assert.ok(live, "exactly 64 MiB so far is still within the limit");
    chrome.raw("a");
    await assert.rejects(a, (e) => e instanceof CdpClosed && e.reason === "message over the size limit");
    assert.equal(await reasonOf(cdp), "message over the size limit");
  }
});

test("pipe: on close every pending send rejects at once, later sends reject, and both ends are released", async () => {
  const { cdp, chrome } = await open();
  const sends = [cdp.send("A"), cdp.send("B", {}, "S1"), cdp.send("C")];
  chrome.end();
  for (const s of sends) await assert.rejects(s, (e) => e instanceof CdpClosed && e.reason === "pipe ended");
  assert.deepEqual(await cdp.closed, { reason: "pipe ended" });
  assert.deepEqual(chrome.destroyed, { read: true, write: true });
  await assert.rejects(cdp.send("D"), (e) => e instanceof CdpClosed && e.reason === "pipe ended");
  chrome.say({ method: "Late" }); // (ignored once closed)
});

test("pipe: read and write errors close the pipe with their own fixed reasons", async () => {
  let { cdp, chrome } = await open();
  void chrome;
  const r = fakeEnds();
  let p = openPipe({ read: r.read, write: r.write, pid: 1 });
  r.chrome.say({ id: 1, result: {} });
  cdp = await p;
  r.read.emit("error", new Error("EIO secret-path"));
  assert.equal(await reasonOf(cdp), "pipe read error");
  const w = fakeEnds();
  p = openPipe({ read: w.read, write: w.write, pid: 1 });
  w.chrome.say({ id: 1, result: {} });
  cdp = await p;
  w.write.emit("error", new Error("EPIPE"));
  assert.equal(await reasonOf(cdp), "pipe write error");
});

test("pipe: a write that throws closes the pipe: that send and every other pending one reject, both ends released", async () => {
  const { cdp, chrome } = await open();
  const earlier = cdp.send("A");
  chrome.writeThrows = true;
  const failed = cdp.send("B");
  await assert.rejects(failed, (e) => e instanceof CdpClosed && e.reason === "pipe write error");
  await assert.rejects(earlier, (e) => e instanceof CdpClosed && e.reason === "pipe write error");
  assert.deepEqual(await cdp.closed, { reason: "pipe write error" });
  assert.deepEqual(chrome.destroyed, { read: true, write: true });
  await assert.rejects(cdp.send("C"), (e) => e instanceof CdpClosed);
});

test("pipe: a message dripped in tiny fragments is held in one buffer: memory is bounded by bytes, not by fragments", async () => {
  // (2^21 one-byte fragments: one retained object per fragment would hold well over 64 MB of heap until the NUL)
  const { cdp, chrome } = await open();
  const v8 = await import("node:v8");
  const vm = await import("node:vm");
  v8.setFlagsFromString("--expose-gc");
  const gc = vm.runInNewContext("gc");
  const n = 1 << 21;
  const head = '{"method":"Drip","params":{"s":"', tail = '"}}';
  const msg = Buffer.alloc(n, 0x61);
  msg.write(head, 0, "latin1");
  msg.write(tail, n - tail.length, "latin1");
  let got = -1;
  cdp.on((ev) => { got = ev.params.s.length; });
  gc();
  const before = process.memoryUsage().heapUsed;
  for (let i = 0; i < n; i++) chrome.raw(msg.subarray(i, i + 1));
  gc();
  const grew = process.memoryUsage().heapUsed - before;
  assert.ok(grew < 32 * 1024 * 1024, `heap grew ${grew} bytes holding one ${n}-byte message`);
  chrome.raw(Buffer.from([0]));
  assert.equal(got, n - head.length - tail.length);
  // (and the exact byte limit still holds across fragments: 64 MiB in 4 KiB fragments is delivered, one more byte closes)
  const big = Buffer.alloc(LIMITS.messageBytes, 0x61);
  big.write(head, 0, "latin1");
  big.write(tail, big.length - tail.length, "latin1");
  for (let i = 0; i < big.length; i += 4096) chrome.raw(big.subarray(i, i + 4096));
  chrome.raw(Buffer.from([0]));
  assert.equal(got, LIMITS.messageBytes - head.length - tail.length);
  for (let i = 0; i < big.length; i += 4096) chrome.raw(big.subarray(i, i + 4096));
  chrome.raw("a");
  assert.equal(await reasonOf(cdp), "message over the size limit");
});

test("pipe: close() sends Browser.close and resolves once Chrome ends the pipe", async () => {
  const { cdp, chrome } = await open();
  let done = false;
  const p = cdp.close().then(() => { done = true; });
  assert.equal(chrome.last().method, "Browser.close");
  await new Promise((r) => setImmediate(r));
  assert.equal(done, false, "close() waits for the pipe to end");
  chrome.say({ id: chrome.last().id, result: {} });
  chrome.end();
  await p;
  assert.equal(await reasonOf(cdp), "pipe ended");
  await cdp.close(); // (again: resolves, sends nothing)
  assert.equal(chrome.sent.filter((m) => m.method === "Browser.close").length, 1);
});

test("pipe: close reasons are fixed strings, never Chrome's bytes", async () => {
  const { cdp, chrome } = await open();
  chrome.raw('{"method":"REAL-secret", oops}\0');
  const reason = await reasonOf(cdp);
  assert.ok(REASONS.has(reason));
  assert.ok(!reason.includes("REAL-"));
});

// A fake Chrome on real fds 3 (it reads) and 4 (it writes), as Rust launches the real one.
function fakeChrome(mode) {
  const child = spawn(process.execPath, [fileURLToPath(new URL("./fixtures/fake-chrome-pipe.mjs", import.meta.url)), mode], { stdio: ["ignore", "inherit", "inherit", "pipe", "pipe"] });
  const exited = new Promise((r) => child.on("exit", (code) => r(code)));
  return { ends: { read: child.stdio[4], write: child.stdio[3], pid: child.pid }, exited, child };
}

test("pipe: against a fake Chrome on fds 3 and 4: commands, sessions, events, and close()", async () => {
  const { ends, exited } = fakeChrome("echo");
  const cdp = await openPipe(ends);
  const seen = [];
  cdp.on((ev) => seen.push(ev));
  assert.deepEqual(await cdp.send("Target.getTargets"), { echo: "Target.getTargets" });
  assert.deepEqual(await cdp.send("Runtime.evaluate", { expression: "1" }, "S1"), { echo: "Runtime.evaluate" });
  await cdp.close();
  assert.equal(await exited, 0);
  assert.deepEqual(seen.map((e) => e.params.after), [2, 3]);
  assert.equal((await cdp.closed).reason, "pipe ended");
});

test("pipe: against a fake Chrome: garbage closes the pipe; an early exit rejects openPipe", async () => {
  const g = fakeChrome("garbage");
  const cdp = await openPipe(g.ends);
  assert.equal(await reasonOf(cdp), "malformed message");
  g.child.kill();
  await g.exited;
  const e = fakeChrome("exit");
  await assert.rejects(openPipe(e.ends), (err) => err instanceof CdpClosed && err.reason === "pipe ended");
  assert.equal(await e.exited, 0);
});
