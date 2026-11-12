// r7: rows that pin what r5 and r6 already do: a trim keeps conversations with a waiting message, one init a turn,
// a sessionless conversation goes at once even with retirement full, close() stops waiting when retirements settle,
// and a kept read is counted exactly, once.
import { test } from "node:test";
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { fakeCreateServer } from "../lib/fake.mjs";
import { AgentServer } from "../lib/server.mjs";

const F = 64 * 1024;
const until = async (f, what, ms = 15000) => {
  const t = Date.now();
  while (!f()) { if (Date.now() - t > ms) throw new Error(`timed out: ${what}`); await new Promise((r) => setTimeout(r, 2)); }
};

// A server on the stdio driver; each turn yields what turns() returns for it (by default one init with a new session id).
function harness({ deleteSession, turns } = {}) {
  let n = 0;
  const query = () => (async function* () {
    const k = ++n;
    for (const id of turns ? turns(k) : [`s${k}`]) yield { type: "system", subtype: "init", session_id: id };
    yield { type: "result", subtype: "success", is_error: false, result: "ok", usage: {} };
  })();
  const server = new AgentServer({ query, log: () => {}, stdio: true, deleteSession });
  server.createServer = fakeCreateServer;
  const input = new EventEmitter();
  const lines = [];
  const out = Object.assign(new EventEmitter(), { writableHighWaterMark: 1 << 20, writableLength: 0, write(b, cb) { for (const l of b.toString("utf8").split("\n").filter(Boolean)) lines.push(JSON.parse(l)); cb?.(); return true; } });
  server.serveStdio({ input, output: out, fatal: () => {} });
  const send = (o) => input.emit("data", Buffer.from(JSON.stringify(o) + "\n"));
  send({ relay: { start: { frame: F, protocol: 1, epoch: 0 } } });
  send({ jsonrpc: "2.0", method: "grant.changed", params: { folders: ["/"], write: true } });
  const say = (conv) => send({ jsonrpc: "2.0", method: "chat.message", params: { conversation: conv, id: `${conv}-${lines.length}-${Math.random()}`, text: "x", author: "person" } });
  const finished = (conv) => lines.filter((m) => m.method === "turn.event" && m.params.conversation === conv && m.params.event.type === "turn_finished").length;
  return { server, say, finished };
}

// Deletions held until released; once open, new ones settle at once.
function heldDeletions() {
  const settle = new Map();
  let open = false;
  const deleted = [];
  const deleteSession = (id) => new Promise((r) => {
    const done = () => { deleted.push(id); r(); };
    if (open) done(); else settle.set(id, done);
  });
  const release = (id) => { const f = settle.get(id); settle.delete(id); f?.(); };
  const openAll = () => { open = true; for (const id of [...settle.keys()]) release(id); };
  return { deleteSession, settle, release, openAll, deleted };
}

test("a trim after a deletion settles keeps every conversation with a waiting message: none is dropped, all run", async () => {
  const d = heldDeletions();
  const h = harness({ deleteSession: d.deleteSession });
  try {
    for (let i = 0; i < 64; i++) { const c = h.server.conversation(`k${i}`); c.sessionId = `sk${i}`; h.server.sessions.add(`sk${i}`); }
    for (let i = 0; i < 8; i++) { h.server.sessions.add(`x${i}`); h.server.retire(`x${i}`); }
    assert.equal(h.server.counters().retiring, 8);
    const fresh = ["n0", "n1", "n2", "n3"];
    for (const c of fresh) h.say(c);
    assert.equal(h.server.counters().conversations, 68, "retirement full: the new ones go over the cap");
    assert.equal(h.server.counters().queued, 4);
    // (one place frees: the trim drops the oldest with a session, which fills retirement again, and nothing else)
    await until(() => d.settle.has("x0"), "the first deletion under way");
    d.release("x0");
    await until(() => !h.server.conversations.has("k0"), "the trim ran");
    assert.equal(h.server.counters().conversations, 67);
    assert.equal(h.server.counters().queued, 4, "every waiting message is still there");
    for (const c of fresh) assert.ok(h.server.conversations.has(c), `${c} kept`);
    d.openAll();
    await until(() => fresh.every((c) => h.finished(c) === 1), "every waiting message ran");
  } finally { d.openAll(); await h.server.close(); }
});

test("one init a turn: a second init with another id neither replaces the session nor retires it again", async () => {
  const d = heldDeletions();
  d.openAll();
  const h = harness({ deleteSession: d.deleteSession, turns: (k) => (k === 1 ? ["s1"] : ["s2", "s3"]) });
  try {
    h.say("a");
    await until(() => h.finished("a") === 1, "first turn");
    h.say("a");
    await until(() => h.finished("a") === 2, "second turn");
    await until(() => h.server.counters().retiring === 0, "retirement done");
    assert.deepEqual(d.deleted, ["s1"], "exactly one retirement: the replaced s1");
    assert.equal(h.server.conversations.get("a").sessionId, "s2", "the second init's id isn't adopted");
    assert.deepEqual([...h.server.sessions], ["s2"]);
  } finally { await h.server.close(); }
});

test("with retirement full, a sessionless conversation goes at once for a new one: the map stays at 64", async () => {
  const d = heldDeletions();
  const h = harness({ deleteSession: d.deleteSession });
  try {
    for (let i = 0; i < 64; i++) h.server.conversation(`k${i}`);
    for (let i = 0; i < 8; i++) { h.server.sessions.add(`x${i}`); h.server.retire(`x${i}`); }
    assert.equal(h.server.counters().retiring, 8);
    h.say("new");
    assert.equal(h.server.counters().conversations, 64, "64 right away, not after a trim");
    assert.ok(!h.server.conversations.has("k0"), "the oldest sessionless one went");
    assert.ok(h.server.conversations.has("new"));
  } finally { d.openAll(); await h.server.close(); }
});

test("close() stops waiting as soon as retirements settle: deletions of about 50 ms, close well under its deadline", async () => {
  const deleted = [];
  const h = harness({ deleteSession: (id) => new Promise((r) => setTimeout(() => { deleted.push(id); r(); }, 50)) });
  for (let i = 0; i < 3; i++) { h.server.sessions.add(`x${i}`); h.server.retire(`x${i}`); }
  const t = Date.now();
  const problems = await h.server.close();
  const ms = Date.now() - t;
  assert.deepEqual(problems, []);
  assert.deepEqual(deleted, ["x0", "x1", "x2"]);
  assert.ok(ms < 500, `close took ${ms} ms (its deadline with --stdio is 1500 ms)`);
});

test("a kept read is counted exactly: 256 + 2 a unit for its keys and ref, plus 96 + 2 a unit for each cell's id and hash", async () => {
  const server = new AgentServer({ query: () => (async function* () {})(), log: () => {}, stdio: true });
  server.createServer = fakeCreateServer;
  const conv = "conv", path = "/n.ipynb", ref = "ref-1";
  const hashes = new Map([["cell-a", "hash-aa"], ["b", "hhh"]]);
  const key = JSON.stringify([conv, path, 1]);
  const want = 256 + 2 * (key.length + path.length + ref.length) + (96 + 2 * (6 + 7)) + (96 + 2 * (1 + 3));
  const c = server.conversation(conv);
  assert.equal(server.keepRead(c, conv, path, 1, { ref, hashes }), true);
  assert.equal(server.counters().readsBytes, want);
  assert.equal(server.counters().reads, 1);
  await server.close();
});

test("the same revision read twice is counted once: readsBytes and the reads kept are unchanged", async () => {
  const server = new AgentServer({ query: () => (async function* () {})(), log: () => {}, stdio: true });
  server.createServer = fakeCreateServer;
  const hashes = new Map([["a", "h"]]);
  const c = server.conversation("c");
  assert.equal(server.keepRead(c, "c", "/p", 7, { ref: "r", hashes }), true);
  const once = server.counters();
  assert.equal(server.keepRead(c, "c", "/p", 7, { ref: "r", hashes }), true);
  assert.equal(server.counters().readsBytes, once.readsBytes);
  assert.equal(server.counters().reads, once.reads);
  assert.equal(c.reads.get("/p").size, 1);
  await server.close();
});
