// r4: the process-wide budget for kept notebook reads, and bounded session retirement (a held or stalled deletion).
import { test } from "node:test";
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { fakeCreateServer, fakeQuery } from "../lib/fake.mjs";
import { AgentServer, TEXT } from "../lib/server.mjs";

const F = 64 * 1024;
const until = async (f, what, ms = 15000) => {
  const t = Date.now();
  while (!f()) { if (Date.now() - t > ms) throw new Error(`timed out: ${what}`); await new Promise((r) => setTimeout(r, 2)); }
};

// A server whose notebook reads the test feeds: each notebook has `cells` cells with ids of `idLen` characters.
function readsServer() {
  const server = new AgentServer({ query: fakeQuery, log: () => {}, stdio: true });
  server.createServer = fakeCreateServer;
  const binding = { ws: { readyState: 1, send() { return "ok"; } }, grant: { folders: ["/"], write: true }, features: ["notebook.edit"] };
  server.binding = binding; server.sock = binding.ws;
  let shape = { cells: 10, idLen: 8 };
  server.request = async (_b, _m, params) => ({ ref: `r-${params.path}`, rev: 1, content: { json: { cells: Array.from({ length: shape.cells }, (_, i) => ({ id: `${params.path}:${i}:`.padEnd(shape.idLen, "x"), cell_type: "code", source: "1" })), metadata: {}, nbformat: 4, nbformat_minor: 5 } } });
  const read = (conv, path) => server.workspaceTools(conv, server.conversation(conv), binding, undefined).handlers.workspace_read({ path });
  const sum = () => [...server.reads.values()].reduce((n, r) => n + r.bytes, 0);
  return { server, read, sum, setShape: (s) => { shape = s; } };
}

test("kept notebook reads: one process-wide byte budget (8 MiB as counted); past it the oldest go, in any conversation; the count is the reads kept", async () => {
  const { server, read, sum, setShape } = readsServer();
  try {
    setShape({ cells: 2000, idLen: 200 }); // (about 2000 x (96 + 2 x (200 + 64)) = 1.2 MB each, as counted)
    for (let i = 0; i < 12; i++) await read(`c${i % 4}`, `/n${i}.ipynb`);
    const c = server.counters();
    assert.ok(c.readsBytes <= 8 * 1024 * 1024, `kept ${c.readsBytes} bytes`);
    assert.equal(c.readsBytes, sum(), "the count is the reads kept");
    assert.ok(c.reads < 12, "some were dropped");
    // (the oldest went first, across conversations: /n0 in c0, then /n1 in c1, ...)
    assert.equal(server.conversations.get("c0").reads.has("/n0.ipynb"), false);
    assert.ok(server.conversations.get("c3").reads.has("/n11.ipynb"), "the newest kept");
    // (every read the conversations hold is in the process-wide count, and nothing else)
    let held = 0;
    for (const x of server.conversations.values()) for (const byRev of x.reads?.values() ?? []) held += byRev.size;
    assert.equal(held, c.reads);
  } finally { await server.close(); }
});

test("kept notebook reads: one bigger than the whole budget isn't kept (and nothing else is dropped for it); dropping a conversation gives its bytes back", async () => {
  const { server, read, sum, setShape } = readsServer();
  try {
    setShape({ cells: 5, idLen: 10 });
    await read("small", "/a.ipynb");
    const before = server.counters().readsBytes;
    setShape({ cells: 40000, idLen: 60 }); // (over 8 MiB as counted)
    await read("big", "/huge.ipynb");
    assert.equal(server.conversations.get("big").reads?.has("/huge.ipynb") ?? false, false);
    assert.equal(server.counters().readsBytes, before, "nothing dropped, nothing added");
    // (a conversation dropped by the 64 cap takes its reads with it)
    for (let i = 0; i < 64; i++) server.conversation(`fill${i}`);
    assert.equal(server.conversations.has("small"), false);
    assert.deepEqual([server.counters().readsBytes, sum()], [0, 0]);
  } finally { await server.close(); }
});

// An in-process stdio harness with real scheduled turns of the fake model and a page that answers.
function churn({ deleteSession }) {
  const logs = [];
  const server = new AgentServer({ query: fakeQuery, log: (m) => logs.push(m), stdio: true, deleteSession });
  server.createServer = fakeCreateServer;
  const input = new EventEmitter();
  const lines = [];
  const out = Object.assign(new EventEmitter(), { writableHighWaterMark: 1 << 20, writableLength: 0, write(b, cb) { for (const l of b.toString("utf8").split("\n").filter(Boolean)) lines.push(JSON.parse(l)); cb?.(); return true; } });
  server.serveStdio({ input, output: out, fatal: () => {} });
  const send = (o) => input.emit("data", Buffer.from(JSON.stringify(o) + "\n"));
  send({ relay: { start: { frame: F, protocol: 1, epoch: 0 } } });
  send({ jsonrpc: "2.0", method: "grant.changed", params: { folders: ["/"], write: true } });
  const seen = new Set();
  const iv = setInterval(() => { for (const m of lines) if (typeof m.id === "string" && m.method && !seen.has(m.id)) { seen.add(m.id); send({ jsonrpc: "2.0", id: m.id, result: m.method === "workspace.stat" ? { entry: null } : { entries: [], rev: 1 } }); } }, 2);
  const say = (conv) => send({ jsonrpc: "2.0", method: "chat.message", params: { conversation: conv, id: `${conv}-${lines.length}`, text: "big 1", author: "person" } });
  const finished = (conv) => lines.filter((m) => m.method === "turn.event" && m.params.conversation === conv && m.params.event.type === "turn_finished").length;
  const started = (conv) => lines.filter((m) => m.method === "turn.event" && m.params.conversation === conv && m.params.event.type === "turn_started").length;
  return { server, logs, say, finished, started, stop: () => clearInterval(iv) };
}

test("a held transcript deletion: at 8 retirements outstanding no turn starts and nothing more is dropped; released, they finish in order and turns resume", async () => {
  let release;
  const gate = new Promise((r) => { release = r; });
  const deleted = [];
  const h = churn({ deleteSession: async (id) => { await gate; deleted.push(id); } });
  try {
    const sessions = [];
    for (let i = 0; i < 64 + 7; i++) {
      h.say(`c${i}`);
      await until(() => h.finished(`c${i}`) === 1, `turn ${i}`);
      sessions.push(h.server.conversations.get(`c${i}`)?.sessionId);
    }
    // (64 kept, 7 retirements outstanding: the first is held at the gate)
    assert.equal(h.server.counters().retiring, 7);
    assert.ok(h.server.counters().sessions <= 64);
    // (one more chat: its eviction makes the 8th retirement, and then retirement is full)
    h.say("c71");
    await until(() => h.server.counters().retiring === 8, "the 8th retirement");
    // (a new chat now: its message waits; no turn starts while retirement is full, and no conversation is dropped)
    h.say("late");
    await new Promise((r) => setTimeout(r, 200));
    assert.equal(h.started("late"), 0, "no turn started while retirement is full");
    assert.equal(h.server.counters().retiring, 8, "nothing more retired");
    assert.equal(h.started("c71"), 0);
    assert.equal(h.server.counters().conversations, 65, "kept over the cap until there is room");
    release();
    await until(() => h.finished("late") === 1 && h.finished("c71") === 1, "the waiting turns, once there is room");
    await until(() => h.server.counters().retiring === 0, "retirements done");
    assert.deepEqual(deleted.slice(0, 8), sessions.slice(0, 8), "deleted in the order retired");
    assert.ok(h.server.counters().conversations <= 64, "trimmed back to the cap");
  } finally { h.stop(); await h.server.close(); }
});

test("a deletion that never finishes: close still ends within its wait and reports what is left, by path", async () => {
  const h = churn({ deleteSession: () => new Promise(() => {}) }); // (stalled for good)
  try {
    for (let i = 0; i < 66; i++) { h.say(`c${i}`); await until(() => h.finished(`c${i}`) === 1, `turn ${i}`); }
    assert.equal(h.server.counters().retiring, 2);
  } finally { h.stop(); }
  const t = Date.now();
  const leftA = h.server.retireActive, leftB = h.server.retireQueue[0];
  // (close() also tries the 64 kept sessions; each of those stalls too, so it is given its own deadline)
  const problems = await Promise.race([h.server.close(), new Promise((r) => setTimeout(() => r("close did not end"), 20000))]);
  assert.notEqual(problems, "close did not end");
  assert.ok(problems.includes(TEXT.transcriptLeft(h.server.transcriptPath(leftA))), "the stalled one reported");
  assert.ok(problems.includes(TEXT.transcriptLeft(h.server.transcriptPath(leftB))), "the queued one reported");
  assert.ok(Date.now() - t < 2000, `close took ${Date.now() - t} ms: within the runner's 2 s`);
});
