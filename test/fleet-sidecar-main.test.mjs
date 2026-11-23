// The cdp sidecar's process (lib/fleet/browser/sidecar-cdp-main.mjs), wired end to end: Rust's frames on stdin and
// stdout through the real codec (./frames.mjs), Chrome's pipe through the real pipe client (./pipe.mjs), the real
// session driver, Filter and hardening. In-process with injected streams, and once as a spawned process on real fds.

import assert from "node:assert/strict";
import { test, afterEach } from "node:test";
import { PassThrough, Writable } from "node:stream";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { readFileSync } from "node:fs";
import { createEncoder, LIMITS } from "../lib/fleet/browser/frames.mjs";
import { main, OUT_MAX, OUT_RESERVE, FLUSH_MS, STALL_MS } from "../lib/fleet/browser/sidecar-cdp-main.mjs";
import { pinnedPermissions } from "../lib/fleet/browser/harden.mjs";
import { PINS } from "../lib/fleet/browser/pins.mjs";

const settle = async (n = 20) => { for (let i = 0; i < n; i++) await new Promise((r) => setImmediate(r)); };
const fromRust = createEncoder({ from: "rust" }), fromNet = createEncoder({ from: "net" });
const BUILD = "158.0.8127.36";
const LIST = { build: BUILD, descriptors: [{ name: "geolocation" }] };
const auth = () => fromRust({ to: "cdp", kind: "cdp.proxy_auth", username: "sess-user", password: "sess-pass", proxy_port: 40123 });
const start = () => fromRust({ to: "cdp", kind: "cdp.start", chrome_pid: 4242 });
const command = (seq, cmd) => fromNet({ to: "cdp", kind: "cdp.command", seq }, Buffer.from(JSON.stringify(cmd)));

// A minimal reader of what cdp writes (both its Rust and its net frames), for the test only.
function frameReader(stream) {
  const frames = [];
  let buf = Buffer.alloc(0);
  stream.on("data", (c) => {
    buf = Buffer.concat([buf, c]);
    while (buf.length >= 4) {
      const total = buf.readUInt32BE(0);
      if (buf.length < 4 + total) break;
      const h = buf.readUInt32BE(4);
      frames.push({ head: JSON.parse(buf.subarray(8, 8 + h).toString("utf8")), body: buf.subarray(8 + h, 4 + total).toString("utf8") });
      buf = buf.subarray(4 + total);
    }
  });
  return frames;
}
// A fake Chrome on two in-memory streams: answers every command, and lets the test send events.
function fakeChrome({ build = BUILD } = {}) {
  const toChrome = new PassThrough(), fromChrome = new PassThrough(), seen = [];
  let buf = Buffer.alloc(0);
  const out = (m) => fromChrome.write(JSON.stringify(m) + "\0");
  toChrome.on("data", (c) => {
    buf = Buffer.concat([buf, c]);
    for (let i; (i = buf.indexOf(0)) !== -1; buf = buf.subarray(i + 1)) {
      const m = JSON.parse(buf.subarray(0, i).toString("utf8"));
      seen.push(m);
      const result = m.method === "Browser.getVersion" ? { product: `HeadlessChrome/${build}`, protocolVersion: "1.3" }
        : m.method === "Target.createBrowserContext" ? { browserContextId: "REAL-CTX" }
        : m.method === "Target.closeTarget" ? { success: true } : {};
      out(m.sessionId ? { id: m.id, result, sessionId: m.sessionId } : { id: m.id, result });
    }
  });
  return { chromeRead: () => fromChrome, chromeWrite: () => toChrome, seen, event: (method, params, sessionId) => out({ method, params, ...(sessionId ? { sessionId } : {}) }) };
}
function run(opts = {}) {
  const stdin = new PassThrough(), stdout = opts.stdout ?? new PassThrough(), chrome = fakeChrome(opts.chrome), exits = [], logs = [];
  const frames = opts.stdout ? null : frameReader(stdout);
  const sidecar = main({
    stdin, stdout, chromeRead: chrome.chromeRead, chromeWrite: chrome.chromeWrite, permissions: opts.permissions ?? (() => LIST),
    exit: (c) => exits.push(c), log: (l) => logs.push(l), ...(opts.clock ? { clock: opts.clock } : {}), ...(opts.outMax ? { outMax: opts.outMax } : {}),
  });
  live.push({ sidecar, stdout });
  return { stdin, stdout, frames, chrome, exits, logs, sidecar };
}
// Every sidecar a test started ends with it (and a held stdout lets go), so no session timer outlives the test.
const live = [];
afterEach(() => {
  for (const { sidecar, stdout } of live.splice(0)) {
    if (sidecar.state !== "ended") sidecar.fail("the test is over");
    stdout.release?.();
  }
});
// A real Writable (highWaterMark 1) that takes no chunk until the test releases it: a stalled app. Every chunk it
// was handed is kept, so the test can read the frames the app would have seen, in order.
function heldStdout({ holding = true } = {}) {
  const pending = [], chunks = [];
  const take = (cb) => (holding ? pending.push(cb) : cb());
  const w = new Writable({ highWaterMark: 1, write(chunk, _enc, cb) { chunks.push(chunk); take(cb); }, final(cb) { take(cb); } });
  w.hold = () => { holding = true; };
  w.release = () => { while (pending.length) pending.shift()(); };
  w.frames = () => { const r = new PassThrough(), out = frameReader(r); r.write(Buffer.concat(chunks)); return out; };
  return w;
}
async function drainAll(w) { for (let i = 0; i < 200; i++) { w.release(); await settle(2); } }
function manualClock() {
  let now = 0;
  const timers = new Set();
  return {
    setTimeout: (f, ms) => { const h = { f, at: now + ms }; timers.add(h); return h; },
    clearTimeout: (h) => { timers.delete(h); },
    advance(ms) { now += ms; for (const h of [...timers]) if (h.at <= now) { timers.delete(h); h.f(); } },
    pending: () => timers.size,
  };
}
const loadEvent = () => ({ method: "Page.loadEventFired", params: { timestamp: 1 } });
const states = (frames) => frames.filter((f) => f.head.kind === "rust.cdp_state").map((f) => f.head.state + (f.head.reason ? `:${f.head.reason}` : ""));

test("wired end to end: credentials and start over real frames; Chrome's pipe opens and the context is hardened; a command's answer and a page's event go to net; retire ends and exits 0", async () => {
  const t = run();
  t.stdin.write(Buffer.concat([auth(), start()]));
  await settle();
  assert.deepEqual(states(t.frames), ["starting", "ready"]);
  const methods = t.chrome.seen.map((m) => m.method);
  assert.deepEqual(methods.slice(0, 4), ["Browser.getVersion", "Target.createBrowserContext", "Browser.getVersion", "Browser.setDownloadBehavior"]);
  assert.ok(methods.includes("Browser.setPermission") && methods.includes("Target.setAutoAttach"));
  t.chrome.event("Target.attachedToTarget", { sessionId: "SESS-A", targetInfo: { targetId: "REAL-TA", type: "page", title: "", url: "about:blank", attached: true, browserContextId: "REAL-CTX" }, waitingForDebugger: true });
  await settle();
  const created = t.frames.find((f) => f.head.kind === "net.event");
  assert.equal(JSON.parse(created.body).method, "Target.targetCreated");
  assert.ok(t.chrome.seen.some((m) => m.method === "Fetch.enable" && m.sessionId === "SESS-A"));
  t.stdin.write(command(1, { method: "Target.getTargets" }));
  await settle();
  const r = t.frames.find((f) => f.head.kind === "net.result" && f.head.seq === 1);
  assert.equal(JSON.parse(r.body).result.targetInfos.length, 1);
  assert.ok(!JSON.stringify(t.frames).includes("REAL-") && !JSON.stringify(t.frames).includes("sess-pass"));
  t.stdin.write(fromRust({ to: "cdp", kind: "cdp.retire" }));
  await settle();
  assert.equal(states(t.frames).at(-1), "ended:retired by the app");
  assert.deepEqual(t.exits, [0]);
});

test("the app's channel: a bad frame, a stream that ends inside a frame, or a plain end all end the sidecar (and nothing after)", async () => {
  for (const [what, feed, reason] of [
    ["garbage", (s) => s.write(Buffer.from([0, 0, 0, 3, 0, 0, 0])), "a bad frame from the app"],
    ["a frame for net", (s) => s.write(fromRust({ to: "net", kind: "net.retire" })), "a bad frame from the app"],
    ["a truncated frame", (s) => { const f = auth(); s.write(f.subarray(0, f.length - 3)); s.end(); }, "the app's channel ended inside a frame"],
    ["a plain end", (s) => s.end(), "the app closed the channel"],
  ]) {
    const t = run();
    feed(t.stdin);
    await settle();
    assert.equal(states(t.frames).at(-1), `ended:${reason}`, what);
    assert.deepEqual(t.exits, [0], what);
    const n = t.frames.length;
    if (!t.stdin.writableEnded) t.stdin.write(Buffer.concat([auth(), start()]));
    await settle();
    assert.equal(t.frames.length, n, what);
  }
});

test("the app's output: if stdout breaks (Rust is gone), the session retires and the process exits 0, once", async () => {
  const t = run();
  t.stdin.write(Buffer.concat([auth(), start()]));
  await settle();
  assert.deepEqual(states(t.frames), ["starting", "ready"]);
  t.stdout.destroy(Object.assign(new Error("write EPIPE"), { code: "EPIPE" }));
  await settle();
  assert.equal(t.sidecar.state, "ended");
  assert.deepEqual(t.exits, [0]);
  t.stdin.write(command(1, { method: "Target.getTargets" }));
  await settle();
  assert.ok(!t.chrome.seen.some((m) => m.method === "Target.getTargets"));
});

test("the bounds: the cap holds two of the largest answers the spec allows, and its reserve holds the largest terminal frame", () => {
  const spec = JSON.parse(readFileSync(new URL("../schema/fleet/browser/o11-cdp.json", import.meta.url)));
  let largest = 0;
  const walk = (o) => { if (o && typeof o === "object") { if (typeof o.maxBytes === "number") largest = Math.max(largest, o.maxBytes); for (const k in o) walk(o[k]); } };
  walk(spec);
  assert.equal(largest, 8 * 1024 * 1024);
  const answer = 8 + LIMITS.headBytes + `{"result":}`.length + largest; // (a frame: lengths, a head, the answer's JSON)
  assert.ok(OUT_MAX - OUT_RESERVE >= 2 * answer, "two of the largest answers fit outside the reserve");
  const ended = createEncoder({ from: "cdp" })({ to: "rust", kind: "rust.cdp_state", state: "ended", reason: "r".repeat(LIMITS.reasonBytes) });
  assert.ok(ended.length <= OUT_RESERVE);
  assert.equal(FLUSH_MS, 5000);
  assert.equal(STALL_MS, 30000);
});

test("a stalled app that also closes stdin (its end behind unread commands): the stall deadline ends the sidecar, and the flush deadline exits 0", async () => {
  const clock = manualClock(), out = heldStdout(), t = run({ stdout: out, clock });
  for (let i = 0; i < 25000; i++) t.stdin.write(command(i + 1, { method: "Target.getTargets" }));
  t.stdin.end();
  await settle();
  assert.equal(t.sidecar.state, "waiting");
  assert.ok(out.writableLength < 1024, `queued ${out.writableLength}`);
  clock.advance(STALL_MS - 1);
  await settle();
  assert.equal(t.sidecar.state, "waiting");
  clock.advance(1);
  await settle();
  assert.equal(t.sidecar.state, "ended");
  assert.ok(out.writableLength < 1024 + OUT_RESERVE);
  assert.deepEqual(t.exits, []);
  clock.advance(FLUSH_MS);
  assert.deepEqual(t.exits, [0]);
  await drainAll(out);
  const frames = out.frames();
  assert.deepEqual(frames.at(-1).head, { to: "rust", kind: "rust.cdp_state", state: "ended", reason: "the app isn't reading its channel" });
  assert.ok(frames.length <= 3);
});

test("a drain within STALL_MS clears the stall deadline", async () => {
  const clock = manualClock(), out = heldStdout(), t = run({ stdout: out, clock });
  t.stdin.write(Buffer.concat([auth(), start()]));
  await settle();
  assert.equal(clock.pending(), 1);
  clock.advance(STALL_MS - 1);
  await drainAll(out);
  assert.equal(t.sidecar.state, "ready");
  assert.equal(clock.pending(), 0);
  clock.advance(STALL_MS);
  await settle();
  assert.equal(t.sidecar.state, "ready");
});

test("repeated backpressure cycles leave one stall timer at a time, and each drain clears it", async () => {
  const clock = manualClock(), out = heldStdout(), t = run({ stdout: out, clock });
  t.stdin.write(Buffer.concat([auth(), start()]));
  await settle();
  for (let seq = 1; seq <= 5; seq++) {
    assert.equal(out.writableNeedDrain, true, `cycle ${seq}`);
    assert.equal(clock.pending(), 1, `cycle ${seq}: one timer`);
    await drainAll(out);
    assert.equal(clock.pending(), 0, `cycle ${seq}: cleared`);
    t.stdin.write(command(seq, { method: "Target.getTargets" }));
    await settle();
  }
  clock.advance(STALL_MS - 1);
  await settle();
  assert.equal(t.sidecar.state, "ready");
});

test("the stall deadline's end: one terminal frame, nothing after it, exit 0 at the flush deadline; a late drain after the end does nothing", async () => {
  const clock = manualClock(), out = heldStdout(), t = run({ stdout: out, clock });
  t.stdin.write(Buffer.concat([auth(), start()]));
  await settle();
  clock.advance(STALL_MS);
  assert.equal(t.sidecar.state, "ended", "stopped synchronously at the bound");
  t.chrome.event("Page.loadEventFired", { timestamp: 1 }, "SESS-A");
  t.stdin.write(command(1, { method: "Target.getTargets" }));
  await settle();
  clock.advance(FLUSH_MS);
  assert.deepEqual(t.exits, [0]);
  await drainAll(out); // (the late drain)
  assert.equal(t.stdin.isPaused(), true);
  assert.deepEqual(t.exits, [0]);
  const frames = out.frames();
  assert.equal(frames.filter((f) => f.head.kind === "rust.cdp_state" && f.head.state === "ended").length, 1);
  assert.deepEqual(frames.at(-1).head, { to: "rust", kind: "rust.cdp_state", state: "ended", reason: "the app isn't reading its channel" });
  assert.ok(!frames.some((f) => f.head.to === "net"), "no answer or event after the stop");
});

test("backpressure: while stdout wants a drain no input is read, so no command reaches Chrome; the drain resumes it", async () => {
  const out = heldStdout(), t = run({ stdout: out });
  t.stdin.write(Buffer.concat([auth(), start()]));
  await settle();
  assert.equal(out.writableNeedDrain, true);
  assert.equal(t.stdin.isPaused(), true);
  const cmd = command(1, { method: "Target.getTargets" });
  t.stdin.write(cmd);
  await settle();
  assert.equal(t.stdin.readableLength, cmd.length, "not read while the app isn't reading");
  await drainAll(out);
  assert.equal(t.stdin.readableLength, 0, "read after the drain");
  assert.equal(t.stdin.isPaused(), false);
  const frames = out.frames();
  assert.deepEqual(states(frames), ["starting", "ready"]);
  assert.equal(JSON.parse(frames.find((f) => f.head.kind === "net.result" && f.head.seq === 1).body).result.targetInfos.length, 0);
  assert.equal(t.sidecar.state, "ready");
});

test("the cap: commands before start (each answered) against a stalled app end the sidecar; the queue stays bounded; the terminal frame is last", async () => {
  const outMax = 256 * 1024, out = heldStdout(), t = run({ stdout: out, outMax });
  const many = Buffer.concat(Array.from({ length: 5000 }, (_, i) => command(i + 1, { method: "Target.getTargets" })));
  t.stdin.write(many);
  assert.ok(out.writableLength <= outMax - OUT_RESERVE, `queued ${out.writableLength}`);
  await settle();
  assert.equal(t.sidecar.state, "ended");
  assert.ok(out.writableLength <= outMax, `queued ${out.writableLength}`);
  t.stdin.write(many); // (more while ended: nothing is taken)
  await settle();
  assert.ok(out.writableLength <= outMax);
  await drainAll(out);
  const frames = out.frames();
  assert.ok(frames.length < 5000);
  assert.deepEqual(frames.at(-1).head, { to: "rust", kind: "rust.cdp_state", state: "ended", reason: "the app isn't reading its channel" });
  assert.equal(frames.filter((f) => f.head.kind === "rust.cdp_state").length, 1);
  assert.deepEqual(t.exits, [0]);
});

test("the cap: Chrome's events go through the same writer; a stalled app ends the sidecar, and later events send nothing", async () => {
  const outMax = 256 * 1024, out = heldStdout(), t = run({ stdout: out, outMax });
  t.stdin.write(Buffer.concat([auth(), start()]));
  await settle();
  t.chrome.event("Target.attachedToTarget", { sessionId: "SESS-A", targetInfo: { targetId: "REAL-TA", type: "page", title: "", url: "about:blank", attached: true, browserContextId: "REAL-CTX" }, waitingForDebugger: true });
  await settle();
  assert.equal(t.sidecar.state, "ready");
  for (let i = 0; i < 5000 && t.sidecar.state !== "ended"; i++) { const e = loadEvent(); t.chrome.event(e.method, e.params, "SESS-A"); if (i % 100 === 0) { await settle(2); assert.ok(out.writableLength <= outMax); } }
  await settle();
  assert.equal(t.sidecar.state, "ended");
  const queued = out.writableLength;
  assert.ok(queued <= outMax, `queued ${queued}`);
  for (let i = 0; i < 1000; i++) { const e = loadEvent(); t.chrome.event(e.method, e.params, "SESS-A"); }
  await settle();
  assert.equal(out.writableLength, queued, "nothing after the end");
  await drainAll(out);
  const frames = out.frames();
  assert.ok(frames.filter((f) => f.head.kind === "net.event").length > 100);
  assert.deepEqual(frames.at(-1).head, { to: "rust", kind: "rust.cdp_state", state: "ended", reason: "the app isn't reading its channel" });
  assert.deepEqual(t.exits, [0]);
});

test("the final flush has a deadline: a stalled app (on retire, or on stdin's end) still gets an exit 0 at FLUSH_MS, never before; a flush that finishes exits at once", async () => {
  for (const [what, finish] of [
    ["retire", (t) => t.stdin.write(fromRust({ to: "cdp", kind: "cdp.retire" }))],
    ["stdin's end", (t) => t.stdin.end()],
  ]) {
    const clock = manualClock(), out = heldStdout({ holding: false }), t = run({ stdout: out, clock });
    t.stdin.write(Buffer.concat([auth(), start()]));
    await settle();
    assert.equal(t.sidecar.state, "ready", what);
    out.hold(); // (the app stops reading now)
    finish(t);
    await settle();
    assert.equal(t.sidecar.state, "ended", what);
    clock.advance(FLUSH_MS - 1);
    await settle();
    assert.deepEqual(t.exits, [], what);
    clock.advance(1);
    assert.deepEqual(t.exits, [0], what);
    assert.deepEqual(t.logs, ["cdp sidecar: the final flush didn't finish in time"], what);
    await drainAll(out); // (a late flush changes nothing)
    assert.deepEqual(t.exits, [0], what);
    assert.equal(out.frames().at(-1).head.state, "ended", what);
  }
  const clock = manualClock(), out = heldStdout(), t = run({ stdout: out, clock });
  t.stdin.write(fromRust({ to: "cdp", kind: "cdp.retire" }));
  await settle();
  await drainAll(out);
  assert.deepEqual(t.exits, [0]);
  assert.equal(clock.pending(), 0, "the deadline is cleared");
  assert.deepEqual(t.logs, []);
});

test("the permission list must be the pinned one for the running build: none pinned (today's PINS), another build or tampered bytes end the session before anything attaches", async () => {
  assert.deepEqual(PINS.permissions, {}); // (until §9.1 adds 158's list)
  const none = run({ permissions: (b) => pinnedPermissions(b) });
  none.stdin.write(Buffer.concat([auth(), start()]));
  await settle();
  assert.equal(states(none.frames).at(-1), "ended:the browser context couldn't be set up and hardened");
  assert.ok(!none.chrome.seen.some((m) => m.method === "Target.setAutoAttach"));
  const bytes = Buffer.from(JSON.stringify(LIST));
  const sha = (await import("node:crypto")).createHash("sha256").update(bytes).digest("hex");
  assert.deepEqual(pinnedPermissions(BUILD, { pinned: { [BUILD]: sha }, read: () => bytes }), LIST);
  assert.throws(() => pinnedPermissions(BUILD, { pinned: { [BUILD]: sha }, read: () => Buffer.from(JSON.stringify({ ...LIST, descriptors: [] })) }), /isn't the pinned one/); // (a shortened list)
  assert.throws(() => pinnedPermissions("149.0.7827.196", { pinned: { [BUILD]: sha }, read: () => bytes }), /no pinned permission list/);
  assert.throws(() => pinnedPermissions(undefined, { pinned: { [BUILD]: sha }, read: () => bytes }), /no pinned permission list/);
  const wrong = Buffer.from(JSON.stringify({ ...LIST, build: "149.0.7827.196" }));
  const wsha = (await import("node:crypto")).createHash("sha256").update(wrong).digest("hex");
  assert.throws(() => pinnedPermissions(BUILD, { pinned: { [BUILD]: wsha }, read: () => wrong }), /for another build/);
});

test("as a process on real fds: Chrome's pipe on fds 3 and 4, frames on stdin and stdout; with no pinned list it ends the session and exits 0", async () => {
  const child = spawn(process.execPath, [fileURLToPath(new URL("../lib/fleet/browser/sidecar-cdp-main.mjs", import.meta.url))], { stdio: ["pipe", "pipe", "inherit", "pipe", "pipe"] });
  const frames = frameReader(child.stdout);
  const seen = [];
  let buf = Buffer.alloc(0);
  for (const s of [child.stdio[3], child.stdio[4], child.stdin]) s.on("error", () => {}); // (the pipes reset when the child exits)
  child.stdio[3].on("data", (c) => { // (the sidecar writes fd 3: what Chrome reads)
    buf = Buffer.concat([buf, c]);
    for (let i; (i = buf.indexOf(0)) !== -1; buf = buf.subarray(i + 1)) {
      const m = JSON.parse(buf.subarray(0, i).toString("utf8"));
      seen.push(m.method);
      const result = m.method === "Browser.getVersion" ? { product: `HeadlessChrome/${BUILD}` } : m.method === "Target.createBrowserContext" ? { browserContextId: "C" } : {};
      child.stdio[4].write(JSON.stringify({ id: m.id, result }) + "\0"); // (Chrome writes fd 4)
    }
  });
  const exited = new Promise((r) => child.on("exit", (code) => r(code)));
  child.stdin.write(Buffer.concat([auth(), start()]));
  let timer;
  const code = await Promise.race([exited, new Promise((r) => { timer = setTimeout(() => r("timeout"), 15000); })]);
  clearTimeout(timer);
  if (code === "timeout") child.kill("SIGKILL");
  assert.equal(code, 0);
  assert.deepEqual(states(frames), ["starting", "ended:the browser context couldn't be set up and hardened"]);
  assert.ok(seen.includes("Browser.getVersion") && !seen.includes("Target.setAutoAttach"));
});
