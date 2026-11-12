// The detach and attach boundary, in process: the server's own counters and the writer's queue, looked at between
// the runner's control lines (the end-to-end rows in stdio.test.mjs can only see what reaches the page).
import { test } from "node:test";
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { fakeCreateServer, fakeQuery } from "../lib/fake.mjs";
import { AgentServer, TEXT } from "../lib/server.mjs";

const F = 64 * 1024;

// A stdout stand-in: write() returns false once its buffer passes the high-water mark; drain() empties it.
class Out extends EventEmitter {
  constructor(highWater = 1 << 20) { super(); this.writableHighWaterMark = highWater; this.writableLength = 0; this.chunks = []; this.held = false; }
  write(b) { this.chunks.push(Buffer.from(b)); this.writableLength += b.length; if (!this.held) queueMicrotask(() => this.drain()); return this.writableLength < this.writableHighWaterMark; }
  drain() { if (!this.writableLength) return; this.writableLength = 0; this.emit("drain"); }
  lines() { return Buffer.concat(this.chunks).toString("utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)); }
}

async function harness({ out = new Out() } = {}) {
  const logs = [];
  const server = new AgentServer({ query: fakeQuery, log: (m) => logs.push(m), stdio: true });
  server.createServer = fakeCreateServer;
  const input = new EventEmitter();
  const fatal = [];
  server.serveStdio({ input, output: out, fatal: (t) => fatal.push(t) });
  const send = (o) => input.emit("data", Buffer.from(JSON.stringify(o) + "\n"));
  send({ relay: { start: { frame: F, protocol: 1, epoch: 0 } } });
  // (a page that answers the workspace verbs as they come)
  const seen = new Set();
  const iv = setInterval(() => {
    if (out.held) return;
    for (const m of out.lines()) if (typeof m.id === "string" && m.method && !seen.has(m.id)) { seen.add(m.id); send({ jsonrpc: "2.0", id: m.id, result: m.method === "workspace.stat" ? { entry: null } : { entries: [], rev: 1 } }); }
  }, 5);
  const close = async () => { clearInterval(iv); await server.close(); };
  return { server, out, send, logs, fatal, close, grant: () => send({ jsonrpc: "2.0", method: "grant.changed", params: { folders: ["/"], write: true } }) };
}

const until = async (f, what, ms = 8000) => {
  const t = Date.now();
  while (!f()) { if (Date.now() - t > ms) throw new Error(`timed out: ${what}`); await new Promise((r) => setTimeout(r, 5)); }
};
const say = (h, conversation, text, id) => h.send({ jsonrpc: "2.0", method: "chat.message", params: { conversation, id: id ?? `${conversation}-${Math.random()}`, text, author: "person" } });

test("detached alone ends the binding at once: no running turn, no open question, no pending request", async () => {
  const h = await harness();
  try {
    h.grant(); say(h, "c1", "please search");
    await until(() => h.server.permissions.size === 1, "the open question");
    assert.equal(h.server.counters().running, 1);
    h.send({ relay: { page: "detached", epoch: 1 } });
    // (before any attach: the binding is gone and everything under it settled)
    assert.equal(h.server.binding, null);
    assert.equal(h.server.permissions.size, 0, "the open question is denied at the detach");
    await until(() => h.server.counters().running === 0, "the old turn ended, with no page attached");
    assert.deepEqual([h.server.counters().attached, h.server.counters().epoch], [false, 1]);
  } finally { await h.close(); }
});

test("a question with no abort signal is still denied at the detach (the binding's own cancel, not only the turn's)", async () => {
  const h = await harness();
  try {
    h.grant();
    const binding = h.server.binding;
    const verdict = h.server.askPerson(binding, () => {}, "WebSearch", { query: "x" }, {}, "c1");
    assert.equal(h.server.permissions.size, 1);
    h.send({ relay: { page: "detached", epoch: 1 } });
    const settled = await Promise.race([verdict, new Promise((r) => setTimeout(() => r("still open 2 s after the detach"), 2000))]);
    assert.deepEqual(settled, { behavior: "deny", message: "The person said no." });
  } finally { await h.close(); }
});

test("attached(n) with no detached(n) closes the old page first: its queued lines are dropped, nothing of it written after", async () => {
  const out = new Out(64);
  const h = await harness({ out });
  try {
    h.grant(); say(h, "c1", "slow");
    await until(() => out.lines().some((m) => m.method === "turn.event" && m.params.event.type === "text_delta"), "streaming");
    out.held = true; // (the runner stops reading: the agent's lines queue up)
    await until(() => h.server.writer.counters().queued > 3, "lines queued for the old page");
    const oldSocket = h.server.sock;
    h.send({ relay: { page: "attached", epoch: 1 } });
    assert.equal(oldSocket.readyState, 3, "the old page's socket is closed");
    assert.notEqual(h.server.sock, oldSocket, "the new page has its own socket");
    const queued = h.server.writer.queue.map((q) => JSON.parse(q.buf.toString("utf8")));
    assert.deepEqual(queued.map((m) => m.method), ["agent.ready"], "only the new page's first line is queued");
    out.held = false; out.drain();
    await until(() => h.server.counters().running === 0, "the old turn ended");
  } finally { await h.close(); }
});

test("at a detach, nothing is written for the old page: its queued chat messages are dropped without a chat.rejected", async () => {
  const h = await harness();
  try {
    h.grant(); say(h, "c1", "slow"); say(h, "c1", "queued behind it", "q1");
    await until(() => h.server.counters().queued === 1, "one message queued");
    const before = h.out.lines().length;
    h.send({ relay: { page: "detached", epoch: 1 } });
    await new Promise((r) => setTimeout(r, 50));
    const after = h.out.lines().slice(before);
    assert.deepEqual(after.map((m) => m.method), [], "no line for a page that is gone");
    assert.equal(h.server.counters().queued, 0);
  } finally { await h.close(); }
});

test("sessions retire with their conversations: real turns past 64 conversations keep at most 64 ids, delete the rest, log a failure, and an old chat starts anew", async () => {
  const deleted = [], logs = [];
  const server = new AgentServer({ query: fakeQuery, log: (m) => logs.push(m), stdio: true,
    deleteSession: async (id) => { deleted.push(id); if (deleted.length === 1) throw new Error("disk says no"); } });
  server.createServer = fakeCreateServer;
  const input = new EventEmitter(), out = new Out();
  server.serveStdio({ input, output: out, fatal: () => {} });
  const send = (o) => input.emit("data", Buffer.from(JSON.stringify(o) + "\n"));
  send({ relay: { start: { frame: F, protocol: 1, epoch: 0 } } });
  const seen = new Set();
  const iv = setInterval(() => { for (const m of out.lines()) if (typeof m.id === "string" && m.method && !seen.has(m.id)) { seen.add(m.id); send({ jsonrpc: "2.0", id: m.id, result: m.method === "workspace.stat" ? { entry: null } : { entries: [], rev: 1 } }); } }, 2);
  try {
    send({ jsonrpc: "2.0", method: "grant.changed", params: { folders: ["/"], write: true } });
    const done = (conv) => out.lines().filter((m) => m.method === "turn.event" && m.params.conversation === conv && m.params.event.type === "turn_finished").length;
    const firstSession = new Map();
    for (let i = 0; i < 66; i++) {
      say({ send }, `c${i}`, "big 1");
      await until(() => done(`c${i}`) === 1, `turn ${i}`);
      firstSession.set(`c${i}`, server.conversations.get(`c${i}`)?.sessionId);
      assert.ok(server.counters().sessions <= 64, `sessions ${server.counters().sessions} after ${i + 1} conversations`);
    }
    await until(() => server.counters().retiring === 0, "the retirements done");
    assert.deepEqual([server.counters().conversations, server.counters().sessions], [64, 64]);
    assert.deepEqual(deleted, [firstSession.get("c0"), firstSession.get("c1")], "the two evicted chats' sessions deleted, in order");
    assert.ok(logs.some((l) => l === TEXT.transcriptLeft(server.transcriptPath(firstSession.get("c0")))), "the failed deletion logged with its path");
    // (c0 comes back: a new conversation and a new session; the oldest idle one, c2, goes)
    say({ send }, "c0", "big 1");
    await until(() => done("c0") === 2, "c0 again");
    const again = server.conversations.get("c0").sessionId;
    assert.ok(again && again !== firstSession.get("c0"), "a new session, not a resume of the deleted one");
    await until(() => server.counters().retiring === 0, "c2 retired");
    assert.equal(deleted.at(-1), firstSession.get("c2"));
    assert.ok(server.counters().sessions <= 64);
  } finally { clearInterval(iv); await server.close(); }
});

test("a session a conversation replaces (the SDK gave a new id) is retired at once; the current one is kept", async () => {
  const deleted = [];
  let n = 0;
  // (a query that hands back a new session id on every turn, as the SDK may)
  const query = () => (async function* () { yield { type: "system", subtype: "init", session_id: `s${++n}` }; yield { type: "result", subtype: "success", is_error: false, result: "ok", usage: {} }; })();
  const server = new AgentServer({ query, log: () => {}, stdio: true, deleteSession: async (id) => { deleted.push(id); } });
  server.createServer = fakeCreateServer;
  const input = new EventEmitter(), out = new Out();
  server.serveStdio({ input, output: out, fatal: () => {} });
  const send = (o) => input.emit("data", Buffer.from(JSON.stringify(o) + "\n"));
  send({ relay: { start: { frame: F, protocol: 1, epoch: 0 } } });
  send({ jsonrpc: "2.0", method: "grant.changed", params: { folders: ["/"], write: true } });
  const done = () => out.lines().filter((m) => m.method === "turn.event" && m.params.event.type === "turn_finished").length;
  try {
    for (let i = 1; i <= 3; i++) { say({ send }, "c1", `turn ${i}`); await until(() => done() === i, `turn ${i}`); }
    await until(() => server.counters().retiring === 0, "retired");
    assert.deepEqual(deleted, ["s1", "s2"]);
    assert.deepEqual([...server.sessions], ["s3"]);
    assert.equal(server.conversations.get("c1").sessionId, "s3");
  } finally { await server.close(); }
  assert.deepEqual(deleted, ["s1", "s2", "s3"], "and the current one at close");
});
