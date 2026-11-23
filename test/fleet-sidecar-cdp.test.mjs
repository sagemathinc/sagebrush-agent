// The cdp sidecar's frame handling (lib/fleet/browser/sidecar-cdp.mjs): the order Rust must follow, exactly one
// answer per command while the session lives, takeover and resume, and nothing after the end. The session and the
// pipe are fakes the test drives; every frame the sidecar sends is recorded.

import assert from "node:assert/strict";
import { test } from "node:test";
import { CdpSidecar, parseCommand, COMMAND_BYTES } from "../lib/fleet/browser/sidecar-cdp.mjs";

const settle = async () => { for (let i = 0; i < 5; i++) await new Promise((r) => setImmediate(r)); };
const bytes = (v) => Buffer.from(typeof v === "string" ? v : JSON.stringify(v), "utf8");

// A fake session: start() and command() answer when the test says so.
class FakeSession {
  state = "new"; commands = []; retiredWith = null; takeovers = 0; handbacks = 0;
  startResult = true; takeoverResult = { paused: true };
  constructor(sink) { this.sink = sink; }
  async start() { this.state = this.startResult ? "running" : "retired"; return this.startResult; }
  calls = []; // (every command the session was handed: the effect counter)
  command(cmd) { this.calls.push(cmd); return new Promise((resolve) => this.commands.push({ cmd, resolve })); }
  async takeover() { this.takeovers++; this.state = "paused"; const r = this.takeoverResult; for (const c of this.commands.splice(0)) c.resolve({ unknown: true }); return r; }
  handback() { this.handbacks++; this.state = "running"; return true; }
  retire(reason) { this.retiredWith = reason; this.state = "retired"; }
}

function setup({ startResult = true, pipeFails = false } = {}) {
  const frames = [], made = [];
  const sidecar = new CdpSidecar({
    send: (head, body) => frames.push({ head, body: body ? body.toString("utf8") : undefined }),
    openPipe: async ({ pid }) => { if (pipeFails) throw new Error("no pipe"); return { pid, close: async () => {} }; },
    makeSession: ({ cdp, credentials, sink }) => { const s = new FakeSession(sink); s.startResult = startResult; s.credentials = credentials; s.cdp = cdp; made.push(s); return s; },
  });
  return { sidecar, frames, made, session: () => made[0] };
}
const auth = { kind: "cdp.proxy_auth", to: "cdp", username: "u", password: "p", proxy_port: 40123 };
async function ready(t) {
  t.sidecar.frame(auth);
  t.sidecar.frame({ kind: "cdp.start", to: "cdp", chrome_pid: 4242 });
  await settle();
  assert.equal(t.sidecar.state, "ready");
}
const states = (frames) => frames.filter((f) => f.head.kind === "rust.cdp_state").map((f) => f.head.state + (f.head.reason ? `:${f.head.reason}` : ""));
const toNet = (frames) => frames.filter((f) => f.head.to === "net");

test("start: proxy credentials, then start: starting, then ready; the session gets the credentials and the pipe", async () => {
  const t = setup();
  await ready(t);
  assert.deepEqual(states(t.frames), ["starting", "ready"]);
  assert.deepEqual(t.session().credentials, { username: "u", password: "p", proxyPort: 40123 });
  assert.equal(t.session().cdp.pid, 4242);
  assert.ok(!JSON.stringify(t.frames).includes('"p"')); // (the password never goes out)
});

test("start: out of order or malformed ends the sidecar with a fixed reason, and nothing starts", async () => {
  for (const [what, frames, reason] of [
    ["start without credentials", [{ kind: "cdp.start", chrome_pid: 1 }], "no proxy credentials"],
    ["a second proxy_auth", [auth, auth], "a second proxy_auth"],
    ["a second start", [auth, { kind: "cdp.start", chrome_pid: 1 }, { kind: "cdp.start", chrome_pid: 1 }], "a second start"],
    ["proxy_auth after start (a second one)", [auth, { kind: "cdp.start", chrome_pid: 1 }, auth], "a second proxy_auth"],
    ["a port below 1024", [{ ...auth, proxy_port: 80 }], "bad proxy port"],
    ["no port", [{ ...auth, proxy_port: undefined }], "bad proxy port"],
    ["an empty password", [{ ...auth, password: "" }], "bad proxy credentials"],
    ["an unknown kind", [{ kind: "cdp.something" }], "unexpected frame"],
    ["takeover before ready", [{ kind: "cdp.takeover" }], "takeover before the session was ready"],
    ["resume while not paused", [auth, { kind: "cdp.start", chrome_pid: 1 }], null],
  ]) {
    const t = setup();
    for (const f of frames) t.sidecar.frame(f);
    await settle();
    if (reason === null) { t.sidecar.frame({ kind: "cdp.resume" }); assert.equal(states(t.frames).at(-1), "ended:resume while not paused"); continue; }
    assert.equal(t.sidecar.state, "ended", what);
    assert.equal(states(t.frames).at(-1), `ended:${reason}`, what);
  }
  const p = setup({ pipeFails: true });
  p.sidecar.frame(auth); p.sidecar.frame({ kind: "cdp.start", chrome_pid: 1 });
  await settle();
  assert.deepEqual(states(p.frames), ["starting", "ended:the browser pipe didn't open"]);
  const s = setup({ startResult: false });
  s.sidecar.frame(auth); s.sidecar.frame({ kind: "cdp.start", chrome_pid: 1 });
  await settle();
  assert.equal(states(s.frames).at(-1), "ended:the session didn't start");
});

test("commands: exactly one net.result per seq with the session's answer (results and errors alike); bad bytes are refused 'bad'", async () => {
  const t = setup();
  await ready(t);
  t.sidecar.frame({ kind: "cdp.command", seq: 1 }, bytes({ method: "Page.reload", params: {}, sessionId: "pg_0000000000000000" }));
  t.sidecar.frame({ kind: "cdp.command", seq: 2 }, bytes({ method: "DOM.getDocument", sessionId: "pg_0000000000000000" }));
  await settle();
  assert.deepEqual(t.session().commands.map((c) => c.cmd.method), ["Page.reload", "DOM.getDocument"]);
  t.session().commands[1].resolve({ error: { code: -32000, message: "stale handle" } }); // (answers in any order)
  t.session().commands[0].resolve({ result: {} });
  await settle();
  assert.deepEqual(toNet(t.frames).map((f) => [f.head.kind, f.head.seq, f.body]), [["net.result", 2, '{"error":{"code":-32000,"message":"stale handle"}}'], ["net.result", 1, '{"result":{}}']]);
  for (const [seq, body] of [[3, "not json"], [4, "[1,2]"], [5, '{"method":"X","extra":1}'], [6, '{"params":{}}'], [7, '{"method":"X","params":[]}'], [8, '{"method":"X","sessionId":5}'], [9, ""], [10, "\xff\xfe"]]) {
    t.sidecar.frame({ kind: "cdp.command", seq }, Buffer.from(body, seq === 10 ? "latin1" : "utf8"));
  }
  await settle();
  assert.deepEqual(toNet(t.frames).slice(2).map((f) => [f.head.kind, f.head.seq, f.head.reason]), [3, 4, 5, 6, 7, 8, 9, 10].map((s) => ["net.refused", s, "bad"]));
  assert.equal(t.session().commands.length, 2);
  assert.equal(parseCommand(Buffer.alloc(COMMAND_BYTES + 1, 32)), null); // (over 1 MiB)
  assert.deepEqual(parseCommand(bytes({ method: "Page.reload" })), { method: "Page.reload" });
});

test("commands: a seq must be greater than every one before it; a repeat ends the sidecar, and net settles the rest", async () => {
  const t = setup();
  await ready(t);
  t.sidecar.frame({ kind: "cdp.command", seq: 5 }, bytes({ method: "Page.reload" }));
  t.sidecar.frame({ kind: "cdp.command", seq: 5 }, bytes({ method: "Page.reload" }));
  await settle();
  assert.equal(states(t.frames).at(-1), "ended:a repeated or out-of-order seq");
  assert.equal(t.session().retiredWith, "a repeated or out-of-order seq");
  t.session().commands[0].resolve({ result: {} }); // (its answer after the end: nothing is sent)
  await settle();
  assert.equal(toNet(t.frames).length, 0);
  for (const seq of [-1, 1.5, "7", undefined]) {
    const u = setup(); await ready(u);
    u.sidecar.frame({ kind: "cdp.command", seq }, bytes({ method: "Page.reload" }));
    assert.equal(states(u.frames).at(-1), "ended:bad seq", String(seq));
  }
});

test("takeover: a new command is refused 'takeover' and never reaches the session; one the session reports unknown during the drain is 'abandoned', once; then takeover_done and paused; resume makes it ready", async () => {
  const t = setup();
  await ready(t);
  t.sidecar.frame({ kind: "cdp.command", seq: 1 }, bytes({ method: "Runtime.evaluate", params: { expression: "x" } }));
  await settle();
  t.sidecar.frame({ kind: "cdp.takeover" });
  t.sidecar.frame({ kind: "cdp.command", seq: 2 }, bytes({ method: "Page.reload" })); // (during the drain)
  await settle();
  assert.deepEqual(toNet(t.frames).map((f) => [f.head.kind, f.head.seq, f.head.reason]), [["net.refused", 2, "takeover"], ["net.refused", 1, "abandoned"]]);
  assert.deepEqual(t.session().calls.map((c) => c.method), ["Runtime.evaluate"]); // (seq 2 never reached the session: not run)
  assert.deepEqual(t.frames.filter((f) => f.head.to === "rust").map((f) => f.head.kind + (f.head.state ? `:${f.head.state}` : "")), ["rust.cdp_state:starting", "rust.cdp_state:ready", "rust.takeover_done", "rust.cdp_state:paused"]);
  t.sidecar.frame({ kind: "cdp.takeover" }); // (again while paused: done again, nothing else)
  assert.equal(t.frames.at(-1).head.kind, "rust.takeover_done");
  t.sidecar.frame({ kind: "cdp.resume" });
  assert.equal(t.session().handbacks, 1);
  assert.equal(states(t.frames).at(-1), "ready");
  t.sidecar.frame({ kind: "cdp.command", seq: 3 }, bytes({ method: "Page.reload" }));
  await settle();
  t.session().commands[0].resolve({ result: {} });
  await settle();
  assert.deepEqual(toNet(t.frames).at(-1).head, { to: "net", kind: "net.result", seq: 3 });
  const seqs = toNet(t.frames).map((f) => f.head.seq);
  assert.equal(new Set(seqs).size, seqs.length); // (one answer per seq)
});

test("takeover that fails: takeover_failed, then ended; an unknown outcome outside takeover ends the session too", async () => {
  const t = setup();
  await ready(t);
  t.session().takeoverResult = { retired: true };
  t.sidecar.frame({ kind: "cdp.takeover" });
  await settle();
  assert.deepEqual(t.frames.filter((f) => f.head.to === "rust").map((f) => f.head.kind).slice(-2), ["rust.takeover_failed", "rust.cdp_state"]);
  assert.equal(states(t.frames).at(-1), "ended:takeover failed");
  const u = setup();
  await ready(u);
  u.sidecar.frame({ kind: "cdp.command", seq: 1 }, bytes({ method: "Page.reload" }));
  await settle();
  u.session().commands[0].resolve({ unknown: true }); // (the pipe closed mid-command, say)
  await settle();
  assert.equal(states(u.frames).at(-1), "ended:a command's outcome can't be known");
  assert.equal(toNet(u.frames).length, 0); // (net settles that seq itself)
});

test("events go to net; the session retiring ends the sidecar; after the end nothing more is sent, whatever arrives", async () => {
  const t = setup();
  await ready(t);
  t.session().sink.event({ method: "Page.loadEventFired", params: { timestamp: 1 }, sessionId: "pg_0000000000000000" });
  assert.deepEqual(toNet(t.frames)[0], { head: { to: "net", kind: "net.event" }, body: '{"method":"Page.loadEventFired","params":{"timestamp":1},"sessionId":"pg_0000000000000000"}' });
  t.session().sink.retired("the session's handle or object-group budget is spent");
  assert.equal(states(t.frames).at(-1), "ended:the session's handle or object-group budget is spent");
  const n = t.frames.length;
  t.session().sink.event({ method: "Page.loadEventFired", params: {} });
  t.sidecar.frame({ kind: "cdp.command", seq: 9 }, bytes({ method: "Page.reload" }));
  t.sidecar.frame({ kind: "cdp.takeover" });
  t.sidecar.frame({ kind: "cdp.retire" });
  t.sidecar.fail("bad frame");
  await settle();
  assert.equal(t.frames.length, n);
  const r = setup();
  await ready(r);
  r.sidecar.frame({ kind: "cdp.retire" });
  assert.equal(r.session().retiredWith, "retired by the app");
  assert.equal(states(r.frames).at(-1), "ended:retired by the app");
  const f = setup();
  f.sidecar.fail("bad frame");
  assert.deepEqual(states(f.frames), ["ended:bad frame"]);
});

test("takeover: a command the session hasn't settled is swept by the drain as 'abandoned', once, by the sidecar itself; its late answer after resume is never sent", async () => {
  const t = setup();
  await ready(t);
  t.session().takeover = async function () { this.takeovers++; this.state = "paused"; return { paused: true }; }; // (settles nothing)
  t.sidecar.frame({ kind: "cdp.command", seq: 1 }, bytes({ method: "Runtime.evaluate", params: { expression: "x" } }));
  await settle();
  t.sidecar.frame({ kind: "cdp.takeover" });
  await settle();
  assert.deepEqual(toNet(t.frames).map((f) => [f.head.kind, f.head.seq, f.head.reason]), [["net.refused", 1, "abandoned"]]);
  t.sidecar.frame({ kind: "cdp.resume" });
  t.session().commands[0].resolve({ result: { late: true } }); // (the late answer)
  await settle();
  assert.deepEqual(toNet(t.frames).map((f) => f.head.seq), [1]); // (exactly one answer for seq 1)
});

test("takeover in progress: duplicate takeovers wait for the same drain and each get one takeover_done after it; resume during the drain ends the sidecar; commands are refused at once", async () => {
  const held = () => { let release; const p = new Promise((r) => { release = r; }); return { p, release }; };
  const t = setup();
  await ready(t);
  const gate = held();
  let drains = 0;
  t.session().takeover = async function () { drains++; this.state = "paused"; await gate.p; return { paused: true }; };
  t.sidecar.frame({ kind: "cdp.takeover" });
  t.sidecar.frame({ kind: "cdp.takeover" }); // (a duplicate during the drain)
  t.sidecar.frame({ kind: "cdp.command", seq: 1 }, bytes({ method: "Page.reload" }));
  await settle();
  assert.equal(t.sidecar.state, "pausing");
  assert.equal(drains, 1);
  assert.equal(t.frames.filter((f) => f.head.kind === "rust.takeover_done").length, 0); // (nothing before the drain ends)
  assert.deepEqual(toNet(t.frames).map((f) => [f.head.seq, f.head.reason]), [[1, "takeover"]]);
  assert.equal(t.session().calls.length, 0); // (refused before the session: not run)
  gate.release();
  await settle();
  assert.equal(t.frames.filter((f) => f.head.kind === "rust.takeover_done").length, 2); // (one per takeover frame)
  assert.deepEqual(states(t.frames).slice(-1), ["paused"]);
  assert.equal(states(t.frames).filter((s) => s === "paused").length, 1);
  t.sidecar.frame({ kind: "cdp.resume" });
  assert.equal(states(t.frames).at(-1), "ready");

  const r = setup(); // (resume during the drain)
  await ready(r);
  const g2 = held();
  r.session().takeover = async function () { this.state = "paused"; await g2.p; return { paused: true }; };
  r.sidecar.frame({ kind: "cdp.takeover" });
  await settle();
  r.sidecar.frame({ kind: "cdp.resume" });
  assert.equal(states(r.frames).at(-1), "ended:resume during takeover");
  assert.equal(r.session().handbacks, 0);
  g2.release();
  await settle();
  assert.equal(r.frames.filter((f) => f.head.kind === "rust.takeover_done").length, 0); // (ended: nothing after)

  const f = setup(); // (a drain that fails, with a duplicate waiting on it)
  await ready(f);
  const g3 = held();
  f.session().takeover = async function () { await g3.p; return { retired: true }; };
  f.sidecar.frame({ kind: "cdp.takeover" });
  f.sidecar.frame({ kind: "cdp.takeover" });
  await settle();
  g3.release();
  await settle();
  assert.deepEqual(f.frames.filter((x) => x.head.to === "rust").map((x) => x.head.kind + (x.head.state ? `:${x.head.state}` : "")).slice(-2), ["rust.takeover_failed", "rust.cdp_state:ended"]);
  assert.equal(f.frames.filter((x) => x.head.kind === "rust.takeover_done").length, 0);
  assert.equal(f.frames.filter((x) => x.head.kind === "rust.takeover_failed").length, 1);
});

// ---- the same takeover rules on the real BrowserSession and Filter, over a fake pipe and a manual clock ----

import { readFileSync } from "node:fs";
import { BrowserSession, DRAIN } from "../lib/fleet/browser/session.mjs";
import { Filter } from "../lib/fleet/browser/filter.mjs";
import { loadProgram } from "../lib/fleet/browser/rewrite.mjs";
import { PINS } from "../lib/fleet/browser/pins.mjs";
import { compileCommands } from "../lib/fleet/browser/params.mjs";
import { accountOrigins, DEFAULT_ACCOUNT_ORIGINS } from "../lib/fleet/browser/urls.mjs";

const readRepo = (f) => readFileSync(new URL(`../${f}`, import.meta.url));
const SPEC = JSON.parse(readRepo(PINS.spec.file)), PROGRAM = loadProgram(readRepo(PINS.program.file), PINS.program.sha256), COMMANDS = compileCommands(SPEC);
class ManualClock {
  now = 0; #t = []; #n = 1;
  setTimeout(fn, ms) { const h = this.#n++; this.#t.push({ h, at: this.now + ms, fn }); return h; }
  clearTimeout(h) { this.#t = this.#t.filter((t) => t.h !== h); }
  async advance(ms) { const end = this.now + ms; for (;;) { await settle(); const d = this.#t.filter((t) => t.at <= end).sort((a, b) => a.at - b.at)[0]; if (!d) break; this.#t = this.#t.filter((t) => t !== d); this.now = d.at; d.fn(); } this.now = end; await settle(); }
}
class Pipe {
  calls = []; listeners = new Set();
  auto = new Set(["Target.createBrowserContext", "Target.setDiscoverTargets", "Target.setAutoAttach", "Runtime.runIfWaitingForDebugger", "Target.closeTarget", "Runtime.releaseObjectGroup"]);
  closed = new Promise(() => {});
  send(method, params = {}, sessionId) {
    const c = { method, params, sessionId }; c.promise = new Promise((ok, fail) => { c.ok = ok; c.fail = fail; }); this.calls.push(c);
    if (this.auto.has(method)) Promise.resolve().then(() => c.ok(method === "Target.createBrowserContext" ? { browserContextId: "REAL-CTX" } : method === "Target.closeTarget" ? { success: true } : {}));
    return c.promise;
  }
  on(l) { this.listeners.add(l); return () => this.listeners.delete(l); }
  emit(method, params, sessionId) { for (const l of [...this.listeners]) l({ method, params, ...(sessionId ? { sessionId } : {}) }); }
  async close() {}
  find(m) { return this.calls.filter((c) => c.method === m); }
}

async function realSetup() {
  const pipe = new Pipe(), clock = new ManualClock(), frames = [];
  let session;
  const sidecar = new CdpSidecar({
    send: (head, body) => frames.push({ head, body: body ? body.toString("utf8") : undefined }),
    openPipe: async () => pipe,
    makeSession: ({ cdp, sink }) => (session = new BrowserSession({ cdp, filter: new Filter({ spec: SPEC, program: PROGRAM, commands: COMMANDS, origins: accountOrigins(DEFAULT_ACCOUNT_ORIGINS) }), hooks: { harden: async () => {}, privileged: () => {} }, sink, clock })),
  });
  sidecar.frame(auth); sidecar.frame({ kind: "cdp.start", chrome_pid: 1 });
  await settle();
  pipe.emit("Target.attachedToTarget", { sessionId: "SESS-A", targetInfo: { targetId: "REAL-TA", type: "page", title: "", url: "about:blank", attached: true, browserContextId: "REAL-CTX" }, waitingForDebugger: true });
  await settle();
  const pg = JSON.parse(frames.find((f) => f.head.kind === "net.event").body).params.targetInfo.targetId;
  sidecar.frame({ kind: "cdp.command", seq: 1 }, bytes({ method: "Runtime.evaluate", params: { expression: "new Promise(()=>{})", awaitPromise: true }, sessionId: pg }));
  await settle();
  assert.equal(pipe.find("Runtime.evaluate").length, 1);
  return { pipe, clock, frames, sidecar, session: () => session, pg };
}
const kinds = (frames, kind) => frames.filter((f) => f.head.kind === kind).length;

test("real session: a duplicate takeover during the drain gets no done before the drain; the drain terminates the busy page; then one done per takeover", async () => {
  const t = await realSetup();
  t.sidecar.frame({ kind: "cdp.takeover" });
  await t.clock.advance(500);
  t.sidecar.frame({ kind: "cdp.takeover" }); // (before 2 s)
  await settle();
  assert.equal(kinds(t.frames, "rust.takeover_done"), 0);
  assert.equal(t.pipe.find("Runtime.terminateExecution").length, 0);
  await t.clock.advance(DRAIN.waitMs - 500);
  assert.equal(t.pipe.find("Runtime.terminateExecution").length, 1);
  assert.equal(kinds(t.frames, "rust.takeover_done"), 0);
  t.pipe.find("Runtime.terminateExecution")[0].ok({});
  await t.clock.advance(DRAIN.terminateMs);
  assert.equal(kinds(t.frames, "rust.takeover_done"), 2);
  assert.equal(t.session().state, "paused");
  assert.equal(t.session().inflight, 0);
  assert.deepEqual(toNet(t.frames).filter((f) => f.head.seq === 1).map((f) => [f.head.kind, f.head.reason]), [["net.refused", "abandoned"]]); // (Chrome had it: it may have run)
  assert.equal(t.pipe.find("Runtime.evaluate").length, 1);
  t.sidecar.frame({ kind: "cdp.command", seq: 2 }, bytes({ method: "Runtime.evaluate", params: { expression: "y" } })); // (while paused)
  await settle();
  assert.deepEqual(toNet(t.frames).filter((f) => f.head.seq === 2).map((f) => [f.head.kind, f.head.reason]), [["net.refused", "takeover"]]);
  assert.equal(t.pipe.find("Runtime.evaluate").length, 1, "nothing more reached Chrome");
  t.sidecar.frame({ kind: "cdp.resume" });
  assert.equal(states(t.frames).at(-1), "ready");
  assert.equal(t.session().state, "running");
});

test("real session: a resume during the drain is refused by ending the sidecar; nothing is handed back with a command in flight", async () => {
  const t = await realSetup();
  t.sidecar.frame({ kind: "cdp.takeover" });
  await t.clock.advance(500);
  t.sidecar.frame({ kind: "cdp.resume" });
  await settle();
  assert.equal(states(t.frames).at(-1), "ended:resume during takeover");
  assert.equal(t.session().state, "retired");
  assert.notEqual(t.session().state, "running");
  await t.clock.advance(DRAIN.waitMs + DRAIN.terminateMs);
  assert.equal(kinds(t.frames, "rust.takeover_done"), 0);
});

test("real session: a drain whose terminate never answers fails closed: takeover_failed then ended at 5 s, never paused, never resumed", async () => {
  const t = await realSetup();
  t.sidecar.frame({ kind: "cdp.takeover" });
  t.sidecar.frame({ kind: "cdp.takeover" });
  await t.clock.advance(DRAIN.waitMs + DRAIN.terminateMs - 1);
  assert.equal(t.sidecar.state, "pausing");
  await t.clock.advance(1);
  assert.equal(kinds(t.frames, "rust.takeover_failed"), 1);
  assert.equal(kinds(t.frames, "rust.takeover_done"), 0);
  assert.equal(states(t.frames).at(-1), "ended:takeover: the browser didn't stop the agent's script in time"); // (the session's own reason)
  assert.ok(!states(t.frames).includes("paused"));
  assert.equal(t.session().state, "retired");
  const n = t.frames.length;
  t.sidecar.frame({ kind: "cdp.resume" });
  assert.equal(t.frames.length, n);
});

test("every async step fails closed: makeSession throwing, start rejecting, takeover rejecting or answering anything but { paused: true }, handback throwing", async () => {
  const throwing = setup();
  throwing.sidecar = new CdpSidecar({ send: (h, b) => throwing.frames.push({ head: h, body: b }), openPipe: async () => ({ close: async () => {} }), makeSession: () => { throw new Error("no"); } });
  throwing.sidecar.frame(auth); throwing.sidecar.frame({ kind: "cdp.start", chrome_pid: 1 });
  await settle();
  assert.equal(states(throwing.frames).at(-1), "ended:the session couldn't be made");

  const rejecting = setup();
  rejecting.sidecar = new CdpSidecar({ send: (h, b) => rejecting.frames.push({ head: h, body: b }), openPipe: async () => ({ close: async () => {} }), makeSession: ({ sink }) => { const s = new FakeSession(sink); s.start = async () => { throw new Error("no"); }; return s; } });
  rejecting.sidecar.frame(auth); rejecting.sidecar.frame({ kind: "cdp.start", chrome_pid: 1 });
  await settle();
  assert.equal(states(rejecting.frames).at(-1), "ended:the session didn't start");

  for (const [what, takeover] of [
    ["a rejected takeover", async () => { throw new Error("no"); }],
    ["{ paused: \"yes\" }", async () => ({ paused: "yes" })],
    ["{}", async () => ({})],
    ["{ paused: true, extra }", async () => ({ paused: true, retired: true })],
    ["null", async () => null],
  ]) {
    const t = setup();
    await ready(t);
    t.session().takeover = takeover;
    t.sidecar.frame({ kind: "cdp.takeover" });
    await settle();
    assert.equal(t.sidecar.state, "ended", what);
    assert.equal(t.frames.filter((f) => f.head.kind === "rust.takeover_failed").length, 1, what);
    assert.equal(t.frames.filter((f) => f.head.kind === "rust.takeover_done").length, 0, what);
    assert.ok(!states(t.frames).includes("paused"), what);
    assert.equal(t.session().retiredWith, "takeover failed", what);
  }

  const h = setup();
  await ready(h);
  h.sidecar.frame({ kind: "cdp.takeover" });
  await settle();
  h.session().handback = () => { throw new Error("no"); };
  h.sidecar.frame({ kind: "cdp.resume" });
  assert.equal(states(h.frames).at(-1), "ended:handback failed");
  const f = setup();
  await ready(f);
  f.sidecar.frame({ kind: "cdp.takeover" });
  await settle();
  f.session().handback = () => false;
  f.sidecar.frame({ kind: "cdp.resume" });
  assert.equal(states(f.frames).at(-1), "ended:handback failed");
});
