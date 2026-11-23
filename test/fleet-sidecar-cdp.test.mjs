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
  command(cmd) { return new Promise((resolve) => this.commands.push({ cmd, resolve })); }
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

test("takeover: new commands are refused 'takeover'; commands the drain abandons are refused 'takeover' once each; then takeover_done and paused; resume makes it ready", async () => {
  const t = setup();
  await ready(t);
  t.sidecar.frame({ kind: "cdp.command", seq: 1 }, bytes({ method: "Runtime.evaluate", params: { expression: "x" } }));
  await settle();
  t.sidecar.frame({ kind: "cdp.takeover" });
  t.sidecar.frame({ kind: "cdp.command", seq: 2 }, bytes({ method: "Page.reload" })); // (during the drain)
  await settle();
  assert.deepEqual(toNet(t.frames).map((f) => [f.head.kind, f.head.seq, f.head.reason]), [["net.refused", 2, "takeover"], ["net.refused", 1, "takeover"]]);
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

test("takeover: a command the session hasn't settled is answered 'takeover' once by the sidecar itself; its late answer after resume is never sent", async () => {
  const t = setup();
  await ready(t);
  t.session().takeover = async function () { this.takeovers++; this.state = "paused"; return { paused: true }; }; // (settles nothing)
  t.sidecar.frame({ kind: "cdp.command", seq: 1 }, bytes({ method: "Runtime.evaluate", params: { expression: "x" } }));
  await settle();
  t.sidecar.frame({ kind: "cdp.takeover" });
  await settle();
  assert.deepEqual(toNet(t.frames).map((f) => [f.head.kind, f.head.seq, f.head.reason]), [["net.refused", 1, "takeover"]]);
  t.sidecar.frame({ kind: "cdp.resume" });
  t.session().commands[0].resolve({ result: { late: true } }); // (the late answer)
  await settle();
  assert.deepEqual(toNet(t.frames).map((f) => f.head.seq), [1]); // (exactly one answer for seq 1)
});
