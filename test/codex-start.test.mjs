// Codex's start-up and ending, in-process: an --stdio AgentServer whose CodexBackend spawns a scripted stand-in for
// `codex app-server` (spawnFn), so a row can hold any request, answer late, exit, or ignore SIGTERM.
// A Stop while Codex starts sends no turn/start; a Stop while turn/start's answer is held interrupts that turn once it
// is known; Codex exiting fails what waits on it at once, with its reason; after a restart a conversation gets a new
// thread; close() kills a Codex that ignores SIGTERM; and the words the person sees for each case.
import { test } from "node:test";
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough, Writable } from "node:stream";
import { AgentServer } from "../lib/server.mjs";
import { CodexBackend, CODEX_TEXT, CODEX_VERSION } from "../lib/codex.mjs";
import { fakeCreateServer } from "../lib/fake.mjs";

const F = 64 * 1024;

// A stand-in child process: records each message written to it; answers by `answer(m)` unless the method is held.
function scriptedChild({ answer, ignoreTerm = false } = {}) {
  const child = new EventEmitter();
  child.got = [];
  child.held = new Map(); // method -> [message]
  child.hold = new Set();
  child.signals = [];
  child.exitCode = null;
  child.signalCode = null;
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  let buf = "";
  child.stdin = new Writable({
    write(chunk, _e, cb) {
      buf += chunk.toString("utf8");
      let nl;
      while ((nl = buf.indexOf("\n")) >= 0) {
        const m = JSON.parse(buf.slice(0, nl));
        buf = buf.slice(nl + 1);
        child.got.push(m);
        if (m.method && m.id !== undefined && child.hold.has(m.method)) { child.held.set(m.method, [...(child.held.get(m.method) ?? []), m]); continue; }
        if (m.method && m.id !== undefined) { const r = (answer ?? defaultAnswer)(m, child); if (r !== undefined) child.reply(m.id, r); }
      }
      cb();
    },
  });
  child.reply = (id, result) => child.stdout.write(JSON.stringify({ id, result }) + "\n");
  child.notify = (method, params) => child.stdout.write(JSON.stringify({ method, params }) + "\n");
  // (several messages in one write: one read for the agent, as a pipe may deliver them)
  child.chunk = (...msgs) => child.stdout.write(msgs.map((m) => JSON.stringify(m) + "\n").join(""));
  child.answers = (id) => child.got.filter((m) => m.id === id && !m.method);
  child.release = (method, result) => { for (const m of child.held.get(method) ?? []) child.reply(m.id, result ?? (answer ?? defaultAnswer)(m, child)); child.held.delete(method); child.hold.delete(method); };
  child.exit = (code, signal = null, stderr = "") => {
    if (child.exitCode !== null || child.signalCode !== null) return;
    if (stderr) child.stderr.write(stderr);
    child.exitCode = code; child.signalCode = signal;
    setImmediate(() => { child.stdout.end(); child.emit("close", code, signal); });
  };
  child.kill = (sig) => { child.signals.push(sig); if (sig === "SIGKILL" || !ignoreTerm) child.exit(null, sig); return true; };
  child.sent = (method) => child.got.filter((m) => m.method === method);
  return child;
}
let threads = 0;
function defaultAnswer(m) {
  switch (m.method) {
    case "initialize": return { userAgent: `sagebrush-agent/${CODEX_VERSION} (Test; x86_64)`, platformFamily: "unix", platformOs: "linux" };
    case "account/read": return { account: { type: "chatgpt" }, requiresOpenaiAuth: true };
    case "config/read": return { config: {} };
    case "thread/start": return { thread: { id: `thr-${++threads}`, ephemeral: true }, approvalPolicy: "on-request" };
    case "turn/start": return { turn: { id: `tu-${m.params.threadId}-${Math.random().toString(36).slice(2, 6)}` } };
    case "turn/interrupt": return {};
    default: return {};
  }
}

function harness({ children, spawnErr, selfTest = async () => [] } = {}) {
  const scratch = mkdtempSync(join(tmpdir(), "runner-cwd-"));
  const logs = [];
  const server = new AgentServer({ log: (s) => logs.push(s), stdio: true, runnerCwd: scratch, name: "Codex", client: "codex-app-server" });
  server.createServer = fakeCreateServer;
  const spawned = [];
  server.backend = new CodexBackend(server, {
    command: ["codex", "app-server"],
    // (these rows are about the app-server's lifetime; the self-test has its own: test/codex-selftest.test.mjs)
    selfTest,
    spawnFn: () => {
      // (a command that isn't there: the error, and nothing answered)
      if (spawnErr) { const c = scriptedChild({ answer: () => undefined }); setImmediate(() => c.emit("error", spawnErr)); spawned.push(c); return c; }
      const c = children.shift() ?? scriptedChild();
      spawned.push(c);
      return c;
    },
  });
  const input = new PassThrough();
  const lines = [];
  let buf = "";
  const output = new Writable({ write(chunk, _e, cb) { buf += chunk.toString("utf8"); let nl; while ((nl = buf.indexOf("\n")) >= 0) { lines.push(JSON.parse(buf.slice(0, nl))); buf = buf.slice(nl + 1); } cb(); } });
  server.serveStdio({ input, output, fatal: () => {} });
  const send = (o) => input.write(Buffer.from(JSON.stringify(o) + "\n"));
  send({ relay: { start: { frame: F, protocol: 1, epoch: 0 } } });
  send({ jsonrpc: "2.0", method: "grant.changed", params: { folders: ["/"], write: true, native: true } });
  let n = 0;
  const events = (c) => lines.filter((m) => m.method === "turn.event" && m.params.conversation === c).map((m) => m.params.event);
  return {
    server, scratch, logs, spawned, lines, events,
    say: (c, text) => send({ jsonrpc: "2.0", method: "chat.message", params: { conversation: c, id: `${c}-${n++}`, text, author: "person" } }),
    stop: (c) => send({ jsonrpc: "2.0", method: "chat.interrupt", params: { conversation: c } }),
    finished: (c) => events(c).filter((e) => e.type === "turn_finished"),
    until: async (f, what, ms = 8000) => { const t = Date.now(); while (!f()) { if (Date.now() - t > ms) throw new Error("timed out: " + what); await new Promise((r) => setTimeout(r, 5)); } },
    close: async () => { input.end(); await server.close().catch(() => {}); rmSync(scratch, { recursive: true, force: true }); },
  };
}
const complete = (child, threadId, turnId, status = "completed") => child.notify("turn/completed", { threadId, turn: { id: turnId, status } });

for (const held of ["initialize", "thread/start"]) {
  test(`a Stop while Codex is starting (${held} held): no turn/start is ever sent, and the turn ends interrupted`, { timeout: 20000 }, async () => {
    const child = scriptedChild();
    child.hold.add(held);
    const h = harness({ children: [child] });
    try {
      h.say("c1", "hello");
      await h.until(() => child.held.has(held), `${held} sent`);
      h.stop("c1");
      await h.until(() => h.finished("c1").length === 1, "the turn's end");
      child.release(held);
      await new Promise((r) => setTimeout(r, 100));
      assert.equal(h.finished("c1")[0].outcome, "interrupted");
      assert.equal(child.sent("turn/start").length, 0);
    } finally { await h.close(); }
  });
}

test("a Stop while turn/start's answer is held: once the answer comes, exactly one turn/interrupt for that turn", { timeout: 20000 }, async () => {
  const child = scriptedChild();
  child.hold.add("turn/start");
  const h = harness({ children: [child] });
  try {
    h.say("c1", "hello");
    await h.until(() => child.held.has("turn/start"), "turn/start sent");
    h.stop("c1");
    await new Promise((r) => setTimeout(r, 50));
    assert.equal(child.sent("turn/interrupt").length, 0, "no interrupt before the id is known");
    const threadId = child.held.get("turn/start")[0].params.threadId;
    child.release("turn/start", { turn: { id: "tu-held" } });
    await h.until(() => child.sent("turn/interrupt").length === 1, "the interrupt");
    assert.deepEqual(child.sent("turn/interrupt")[0].params, { threadId, turnId: "tu-held" });
    complete(child, threadId, "tu-held", "interrupted");
    await h.until(() => h.finished("c1").length === 1, "the turn's end");
    assert.equal(h.finished("c1")[0].outcome, "interrupted");
    assert.equal(child.sent("turn/interrupt").length, 1, "once");
  } finally { await h.close(); }
});

test("Codex exits while turn/start is unanswered: the turn fails at once, with Codex's last stderr line", { timeout: 20000 }, async () => {
  const child = scriptedChild();
  child.hold.add("turn/start");
  const h = harness({ children: [child] });
  try {
    h.say("c1", "hello");
    await h.until(() => child.held.has("turn/start"), "turn/start sent");
    const t0 = Date.now();
    child.exit(1, null, "warming up\nfatal: the model went away\n");
    await h.until(() => h.finished("c1").length === 1, "the turn's end", 3000);
    assert.ok(Date.now() - t0 < 3000, "at once, not after the request timeout");
    const err = h.events("c1").find((e) => e.type === "turn_error");
    assert.equal(err.message, "Codex stopped: exit 1: fatal: the model went away");
  } finally { await h.close(); }
});

test("after Codex restarts, the same conversation gets a new thread in the new app-server (logged); the old thread id is never sent there", { timeout: 20000 }, async () => {
  const a = scriptedChild(), b = scriptedChild();
  const h = harness({ children: [a, b] });
  try {
    h.say("c1", "first");
    await h.until(() => a.sent("turn/start").length === 1, "the first turn/start");
    const t1 = a.sent("turn/start")[0].params.threadId;
    await new Promise((r) => setTimeout(r, 20));
    // (the answer's turn id is random: complete the turn by the id the backend holds)
    complete(a, t1, h.server.backend.turns.get(t1).codexTurnId);
    await h.until(() => h.finished("c1").length === 1, "the first turn's end");
    a.exit(0);
    await h.until(() => h.server.backend.app === null, "the app-server gone");
    h.say("c1", "second");
    await h.until(() => b.sent("turn/start").length === 1, "the second turn/start");
    const t2 = b.sent("turn/start")[0].params.threadId;
    assert.equal(b.sent("thread/start").length, 1, "a new thread");
    assert.notEqual(t2, t1);
    assert.ok(!b.got.some((m) => JSON.stringify(m.params ?? {}).includes(t1)), "the old thread id never reaches the new app-server");
    assert.ok(h.logs.includes(CODEX_TEXT.restarted), "the restart logged");
  } finally { await h.close(); }
});

test("close() kills a Codex that ignores SIGTERM, and says so", { timeout: 20000 }, async () => {
  const child = scriptedChild({ ignoreTerm: true });
  const h = harness({ children: [child] });
  try {
    h.say("c1", "hello");
    await h.until(() => child.sent("turn/start").length === 1, "a turn under way");
    const problems = await h.server.backend.close(200);
    assert.deepEqual(problems, ["Codex didn't stop in time and was killed"]);
    assert.deepEqual(child.signals, ["SIGTERM", "SIGKILL"]);
  } finally { await h.close(); }
});

test("no `codex` on this computer: the turn says how to install it", { timeout: 20000 }, async () => {
  const h = harness({ spawnErr: Object.assign(new Error("spawn codex ENOENT"), { code: "ENOENT" }) });
  try {
    h.say("c1", "hello");
    await h.until(() => h.finished("c1").length === 1, "the turn's end");
    assert.deepEqual(h.events("c1").find((e) => e.type === "turn_error"), { type: "turn_error", code: "codex_missing", message: CODEX_TEXT.notFound });
  } finally { await h.close(); }
});

test("an API-key login (no account, requiresOpenaiAuth false) runs; config/read is asked for the runner's folder", { timeout: 20000 }, async () => {
  const child = scriptedChild({ answer: (m) => (m.method === "account/read" ? { account: null, requiresOpenaiAuth: false } : defaultAnswer(m)) });
  const h = harness({ children: [child] });
  try {
    h.say("c1", "hello");
    await h.until(() => child.sent("turn/start").length === 1, "the turn starts");
    assert.equal(child.sent("config/read")[0].params.cwd, h.scratch);
    assert.equal(child.sent("thread/start")[0].params.cwd, h.scratch);
  } finally { await h.close(); }
});

test("a Stop while the thread starts, then the same conversation's next message: it waits for that same start (no second thread), and every later turn stays in that thread", { timeout: 20000 }, async () => {
  const child = scriptedChild({ answer: (m) => (m.method === "thread/start" ? { thread: { id: "thread-A", ephemeral: true }, approvalPolicy: "on-request" } : defaultAnswer(m)) });
  child.hold.add("thread/start");
  const h = harness({ children: [child] });
  try {
    h.say("c1", "first");
    await h.until(() => child.held.has("thread/start"), "thread/start A");
    h.stop("c1");
    await h.until(() => h.finished("c1").length === 1, "the first turn's end");
    h.say("c1", "second");
    await new Promise((r) => setTimeout(r, 100));
    assert.equal(child.sent("thread/start").length, 1, "no second thread/start while the first is under way");
    child.release("thread/start");
    await h.until(() => child.sent("turn/start").length === 1, "the second turn's start");
    assert.equal(child.sent("turn/start")[0].params.threadId, "thread-A");
    complete(child, "thread-A", h.server.backend.turns.get("thread-A").codexTurnId);
    await h.until(() => h.finished("c1").length === 2, "the second turn's end");
    h.say("c1", "third");
    await h.until(() => child.sent("turn/start").length === 2, "the third turn's start");
    assert.equal(child.sent("turn/start")[1].params.threadId, "thread-A", "still the same thread");
    assert.equal(child.sent("thread/start").length, 1);
  } finally { await h.close(); }
});

test("a thread start in an app-server that exits meanwhile sets nothing; the conversation's next thread is the new app-server's", { timeout: 20000 }, async () => {
  const a = scriptedChild();
  a.hold.add("thread/start");
  const b = scriptedChild({ answer: (m) => (m.method === "thread/start" ? { thread: { id: "thread-B", ephemeral: true }, approvalPolicy: "on-request" } : defaultAnswer(m)) });
  const h = harness({ children: [a, b] });
  try {
    h.say("c1", "first");
    await h.until(() => a.held.has("thread/start"), "thread/start in A");
    h.stop("c1");
    await h.until(() => h.finished("c1").length === 1, "the first turn's end");
    a.exit(1);
    await h.until(() => h.server.backend.app === null, "A gone");
    h.say("c1", "second");
    await h.until(() => b.sent("turn/start").length === 1, "the second turn's start, in B");
    assert.equal(b.sent("turn/start")[0].params.threadId, "thread-B");
    complete(b, "thread-B", h.server.backend.turns.get("thread-B").codexTurnId);
    await h.until(() => h.finished("c1").length === 2, "the second turn's end");
    h.say("c1", "third");
    await h.until(() => b.sent("turn/start").length === 2, "the third turn's start");
    assert.equal(b.sent("turn/start")[1].params.threadId, "thread-B");
  } finally { await h.close(); }
});

// (a request from Codex and its serverRequest/resolved in one read: the request is taken first, so the resolution finds it)
const cardsOf = (h, c) => h.events(c).filter((e) => e.type === "attention");
// (the cards still open: each card's last state; one withdrawn at once shows "open" then "denied")
const stillOpen = (h, c) => { const last = new Map(); for (const e of cardsOf(h, c)) last.set(e.id, e.state); return [...last.values()].filter((s) => s === "open").length; };
async function runningTurn(h, child) {
  h.say("c1", "hello");
  await h.until(() => child.sent("turn/start").length === 1, "the turn's start");
  await h.until(() => h.server.backend.turns.size === 1 && [...h.server.backend.turns.values()][0].codexTurnId, "the turn's id");
  const [threadId, active] = [...h.server.backend.turns.entries()][0];
  return { threadId, turnId: active.codexTurnId };
}

test("one read with a command approval and its serverRequest/resolved: no card stays open, and it's never accepted", { timeout: 20000 }, async () => {
  const child = scriptedChild();
  const h = harness({ children: [child] });
  try {
    const { threadId, turnId } = await runningTurn(h, child);
    child.chunk(
      { id: 501, method: "item/commandExecution/requestApproval", params: { threadId, turnId, kind: "command", itemId: "x", command: "echo benign", cwd: "/tmp" } },
      { method: "serverRequest/resolved", params: { threadId, requestId: 501 } },
    );
    await h.until(() => child.answers(501).length === 1, "the answer");
    assert.notEqual(child.answers(501)[0].result.decision, "accept");
    assert.equal(stillOpen(h, "c1"), 0, "no card left open for a resolved request");
    assert.equal(h.server.permissions.size, 0);
  } finally { await h.close(); }
});

test("one read with a workspace rename call and its serverRequest/resolved: no card, no rename sent to the page", { timeout: 20000 }, async () => {
  const child = scriptedChild();
  const h = harness({ children: [child] });
  try {
    const { threadId, turnId } = await runningTurn(h, child);
    child.chunk(
      { id: 502, method: "item/tool/call", params: { threadId, turnId, callId: "k", namespace: null, tool: "workspace_rename", arguments: { from: "/a.md", to: "/b.md" } } },
      { method: "serverRequest/resolved", params: { threadId, requestId: 502 } },
    );
    await h.until(() => child.answers(502).length === 1, "the answer");
    assert.equal(child.answers(502)[0].result.success, false);
    assert.equal(stillOpen(h, "c1"), 0);
    assert.ok(!h.lines.some((m) => m.method === "workspace.rename"), "nothing sent to the page");
  } finally { await h.close(); }
});

test("one read, while turn/start's answer is held, with an approval for this turn and its resolution: after the answer, no card and no accept", { timeout: 20000 }, async () => {
  const child = scriptedChild();
  child.hold.add("turn/start");
  const h = harness({ children: [child] });
  try {
    h.say("c1", "hello");
    await h.until(() => child.held.has("turn/start"), "turn/start sent");
    const threadId = child.held.get("turn/start")[0].params.threadId;
    child.chunk(
      { id: 503, method: "item/commandExecution/requestApproval", params: { threadId, turnId: "tu-held", kind: "command", itemId: "x", command: "echo benign", cwd: "/tmp" } },
      { method: "serverRequest/resolved", params: { threadId, requestId: 503 } },
    );
    await new Promise((r) => setTimeout(r, 20));
    child.release("turn/start", { turn: { id: "tu-held" } });
    await h.until(() => child.answers(503).length === 1, "the answer");
    assert.notEqual(child.answers(503)[0].result.decision, "accept");
    assert.equal(stillOpen(h, "c1"), 0);
  } finally { await h.close(); }
});

test("one read with an approval and then a later, unrelated notification: the card still opens (resolution only ends its own request)", { timeout: 20000 }, async () => {
  const child = scriptedChild();
  const h = harness({ children: [child] });
  try {
    const { threadId, turnId } = await runningTurn(h, child);
    child.chunk(
      { id: 504, method: "item/commandExecution/requestApproval", params: { threadId, turnId, kind: "command", itemId: "x", command: "echo benign", cwd: "/tmp" } },
      { method: "serverRequest/resolved", params: { threadId, requestId: 999 } },
    );
    await h.until(() => cardsOf(h, "c1").some((c) => c.state === "open"), "the card");
    const [q] = [...h.server.permissions.values()];
    q.done(true);
    await h.until(() => child.answers(504).length === 1, "the answer");
    assert.equal(child.answers(504)[0].result.decision, "accept", "a live request's Allow still accepts");
  } finally { await h.close(); }
});

test("a self-test that fails with words of its own: the person sees fixed words only ('it failed'), never those", async () => {
  const h = harness({ children: [scriptedChild()], selfTest: async () => { throw new Error("SECRET token=sk-x in /home/x/.codex/config.toml"); } });
  try {
    h.say("c1", "hello");
    await h.until(() => h.finished("c1").length, "the refused turn");
    const err = h.events("c1").find((e) => e.type === "turn_error");
    assert.equal(err.code, "codex_incompatible");
    assert.equal(err.message, CODEX_TEXT.noSchema("it failed"));
    assert.ok(!h.logs.join("\n").includes("SECRET"), "nor in the log");
  } finally { await h.close(); }
});

test("a self-test with many problems: at most 5 named, each at most 120 characters", async () => {
  const many = ["x".repeat(500), ...Array.from({ length: 7 }, (_, i) => `no request m${i}`)];
  const h = harness({ children: [scriptedChild()], selfTest: async () => many });
  try {
    h.say("c1", "hello");
    await h.until(() => h.finished("c1").length, "the refused turn");
    const err = h.events("c1").find((e) => e.type === "turn_error");
    assert.equal(err.code, "codex_incompatible");
    assert.equal(err.message, CODEX_TEXT.incompatible(["x".repeat(120), "no request m0", "no request m1", "no request m2", "no request m3"].join("; ")));
  } finally { await h.close(); }
});
