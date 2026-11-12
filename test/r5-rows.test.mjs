// r5: retirement capacity is reserved for running turns, sessionless placeholders don't outlive a rebind, and a
// timed-out deletion still counts until it settles.
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

// A server on the stdio driver with a query that hands back a new session id each turn, its init held at a gate.
function harness({ deleteSession, retireTimeoutMs } = {}) {
  let n = 0, initGate = null;
  const query = () => (async function* () {
    if (initGate) await initGate;
    yield { type: "system", subtype: "init", session_id: `s${++n}` };
    yield { type: "result", subtype: "success", is_error: false, result: "ok", usage: {} };
  })();
  const server = new AgentServer({ query, log: () => {}, stdio: true, deleteSession, ...(retireTimeoutMs ? { retireTimeoutMs } : {}) });
  server.createServer = fakeCreateServer;
  const input = new EventEmitter();
  const lines = [];
  const out = Object.assign(new EventEmitter(), { writableHighWaterMark: 1 << 20, writableLength: 0, write(b, cb) { for (const l of b.toString("utf8").split("\n").filter(Boolean)) lines.push(JSON.parse(l)); cb?.(); return true; } });
  server.serveStdio({ input, output: out, fatal: () => {} });
  const send = (o) => input.emit("data", Buffer.from(JSON.stringify(o) + "\n"));
  send({ relay: { start: { frame: F, protocol: 1, epoch: 0 } } });
  const grant = () => send({ jsonrpc: "2.0", method: "grant.changed", params: { folders: ["/"], write: true } });
  grant();
  const say = (conv, id = `${conv}-${lines.length}-${Math.random()}`) => send({ jsonrpc: "2.0", method: "chat.message", params: { conversation: conv, id, text: "x", author: "person" } });
  const finished = (conv) => lines.filter((m) => m.method === "turn.event" && m.params.conversation === conv && m.params.event.type === "turn_finished").length;
  const started = (conv) => lines.filter((m) => m.method === "turn.event" && m.params.conversation === conv && m.params.event.type === "turn_started").length;
  return { server, send, grant, say, finished, started, setInitGate: (g) => { initGate = g; } };
}

test("retirement capacity is reserved for running turns: 7 held and 4 resumed turns that replace their sessions never pass 8", async () => {
  let release;
  const gate = new Promise((r) => { release = r; });
  const deleted = [];
  const h = harness({ deleteSession: async (id) => { await gate; deleted.push(id); } });
  let max = 0;
  const watch = setInterval(() => { max = Math.max(max, h.server.counters().retiring); }, 1);
  try {
    for (const c of ["a", "b", "c", "d"]) { h.say(c); await until(() => h.finished(c) === 1, `first turn of ${c}`); }
    const first = ["a", "b", "c", "d"].map((c) => h.server.conversations.get(c).sessionId);
    // (7 retirements outstanding, held at the gate)
    for (let i = 0; i < 7; i++) { h.server.sessions.add(`x${i}`); h.server.retire(`x${i}`); }
    assert.equal(h.server.counters().retiring, 7);
    // (the four resume at once; each would replace its session)
    for (const c of ["a", "b", "c", "d"]) h.say(c);
    await new Promise((r) => setTimeout(r, 100));
    max = Math.max(max, h.server.counters().retiring);
    assert.equal(["a", "b", "c", "d"].reduce((k, c) => k + h.started(c), 0), 4 + 1, "one resumed turn started: 7 + 1 = 8");
    assert.equal(h.server.counters().retiring, 8, "its replaced session is the 8th");
    assert.ok(max <= 8, `never past 8 (${max})`);
    release();
    await until(() => ["a", "b", "c", "d"].every((c) => h.finished(c) === 2), "all four resumed turns, as room returns");
    await until(() => h.server.counters().retiring === 0, "retirements done");
    assert.ok(max <= 8, `never past 8 (${max})`);
    for (const id of first) assert.ok(deleted.includes(id), `the replaced ${id} deleted`);
  } finally { clearInterval(watch); release(); await h.server.close(); }
});

test("sessionless placeholders don't outlive a rebind: detach/attach churn with retirement full keeps the map bounded", async () => {
  const h = harness({ deleteSession: () => new Promise(() => {}) });
  try {
    // (64 conversations with a session, then retirement full: 8 held)
    for (let i = 0; i < 64; i++) { const c = h.server.conversation(`k${i}`); c.sessionId = `sk${i}`; h.server.sessions.add(`sk${i}`); }
    for (let i = 0; i < 8; i++) { h.server.sessions.add(`x${i}`); h.server.retire(`x${i}`); }
    assert.equal(h.server.counters().retiring, 8);
    let epoch = 0, max = 0;
    for (let round = 0; round < 4; round++) {
      for (let i = 0; i < 16; i++) h.say(`new-${round}-${i}`);
      max = Math.max(max, h.server.counters().conversations);
      assert.ok(h.server.counters().conversations <= 64 + 16 + 4, `round ${round}: ${h.server.counters().conversations}`);
      epoch++;
      h.send({ relay: { page: "detached", epoch } });
      h.send({ relay: { page: "attached", epoch } });
      h.grant();
      assert.equal(h.server.counters().conversations, 64, `round ${round}: back to 64 after the rebind`);
      assert.equal(h.server.counters().queued, 0);
    }
    assert.equal(max, 80);
  } finally { await h.server.close(); }
});

test("a timed-out deletion still counts until it settles: the SDK's call isn't cancelled, so it holds its place", async () => {
  const settle = [];
  const h = harness({ retireTimeoutMs: 30, deleteSession: () => new Promise((r) => settle.push(r)) });
  try {
    for (let i = 0; i < 3; i++) { h.server.sessions.add(`x${i}`); h.server.retire(`x${i}`); }
    await until(() => settle.length === 3, "all three started, each after the one before timed out");
    assert.equal(h.server.counters().retiring, 3, "timed out, not settled: still counted");
    settle[0]();
    await until(() => h.server.counters().retiring === 2, "one settled");
    settle[1](); settle[2]();
    await until(() => h.server.counters().retiring === 0, "all settled");
  } finally { for (const r of settle) r(); await h.server.close(); }
});

test("one place freed starts one waiting turn, not every waiting one: the place is checked per turn", async () => {
  const settle = new Map();
  const h = harness({ deleteSession: (id) => new Promise((r) => settle.set(id, r)) });
  try {
    for (const c of ["a", "b", "c", "d"]) { h.say(c); await until(() => h.finished(c) === 1, `first turn of ${c}`); }
    // (retirement full: 8 held)
    for (let i = 0; i < 8; i++) { h.server.sessions.add(`x${i}`); h.server.retire(`x${i}`); }
    for (const c of ["a", "b", "c", "d"]) h.say(c);
    await new Promise((r) => setTimeout(r, 50));
    assert.equal(["a", "b", "c", "d"].reduce((k, c) => k + h.started(c), 0), 4, "none of the four started");
    // (exactly one place frees: one deletion settles)
    await until(() => settle.has("x0"), "the first deletion under way");
    settle.get("x0")();
    await until(() => h.server.counters().retiring <= 8 && ["a", "b", "c", "d"].reduce((k, c) => k + h.started(c), 0) >= 5, "one turn started");
    await new Promise((r) => setTimeout(r, 50));
    assert.equal(["a", "b", "c", "d"].reduce((k, c) => k + h.started(c), 0), 5, "exactly one");
    assert.ok(h.server.counters().retiring <= 8);
  } finally { for (const r of settle.values()) r(); await h.server.close(); }
});

test("a kept read's index keys count against the reads budget: a long conversation id or path uses it up like anything else", async () => {
  const server = new AgentServer({ query: () => (async function* () {})(), log: () => {}, stdio: true });
  server.createServer = fakeCreateServer;
  const hashes = new Map([["a", "h"]]);
  const short = AgentServer.readBytes("r", hashes, JSON.stringify(["c", "/p", 1]), "/p");
  const longPath = "/" + "p".repeat(100000);
  const longConv = "c".repeat(100000);
  const long = AgentServer.readBytes("r", hashes, JSON.stringify([longConv, longPath, 1]), longPath);
  // (the conversation once, the path twice: in the index key and as the conversation's own key, at 2 bytes a unit)
  assert.ok(long - short >= 2 * (100000 + 2 * 100000) - 64, `the keys count: ${long - short}`);
  // (through keepRead: the counted total includes them, and one whose keys alone pass the budget isn't kept)
  const c = server.conversation(longConv);
  assert.equal(server.keepRead(c, longConv, longPath, 1, { ref: "r", hashes }), true);
  assert.equal(server.counters().readsBytes, long);
  const huge = "/" + "q".repeat(3 * 1024 * 1024);
  assert.equal(server.keepRead(c, longConv, huge, 1, { ref: "r", hashes }), false, "keys over 8 MiB as counted: not kept");
  assert.equal(server.counters().readsBytes, long);
  await server.close();
});
