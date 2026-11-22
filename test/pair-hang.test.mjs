// A Pair turn whose SDK stream hangs (its next() and return() never settle, the abort ignored) still ends for its page:
// Stop, a revoke or the agent closing end it at once (turn_finished, interrupted). Its unsettled work keeps the turn's
// running place (RUNNING_MAX and the retirement room every running turn reserves) until it settles, given back exactly
// once; the conversation itself goes on. A scripted model over a real loopback WebSocket; no Anthropic calls.
import assert from "node:assert/strict";
import { test } from "node:test";
import WebSocket from "ws";
import { fakeCreateServer, promptText } from "../lib/fake.mjs";
import { AgentServer } from "../lib/server.mjs";

const ORIGIN = "https://agents.sagebrush.cloud";
const GRANT = { folders: ["/"], write: true };
const until = async (f, what = "", ms = 10000) => { const t = Date.now(); while (!f()) { if (Date.now() - t > ms) throw new Error(`timed out ${what}`); await new Promise((r) => setTimeout(r, 10)); } };

// (the model: "hang" yields its init, then next() and return() never settle until `release()`; anything else answers)
function model() {
  const m = { releases: [], returns: 0, started: 0 };
  let n = 0;
  m.query = ({ prompt, options }) => {
    m.started++;
    const session = options.resume ?? `pair-${++n}`;
    let text = null, first = true, ended = false;
    const hold = () => new Promise((r) => { const f = () => r({ done: true, value: undefined }); f.session = session; m.releases.push(f); });
    return {
      [Symbol.asyncIterator]() { return this; },
      async next() {
        if (ended) return { done: true, value: undefined };
        if (text === null) text = await promptText(prompt);
        if (first) { first = false; return { done: false, value: { type: "system", subtype: "init", session_id: session, model: "fake", tools: [] } }; }
        if (text === "hang") return hold();
        ended = true;
        return { done: false, value: { type: "result", subtype: "success", is_error: false, result: "ok", usage: { input_tokens: 1, output_tokens: 1 }, session_id: session } };
      },
      return() { m.returns++; return text === "hang" ? hold() : Promise.resolve({ done: true, value: undefined }); },
    };
  };
  m.release = () => { for (const r of m.releases.splice(0)) r(); };
  // (one turn's work, all of it: its next() and its return())
  m.releaseSession = (session) => { for (const r of m.releases.filter((f) => f.session === session)) { m.releases.splice(m.releases.indexOf(r), 1); r(); } };
  return m;
}

async function setup() {
  const m = model();
  const logs = [];
  const server = new AgentServer({ query: m.query, deleteSession: async () => {}, retireTimeoutMs: 100, log: (s) => logs.push(String(s)) });
  server.createServer = fakeCreateServer;
  const port = await server.listen();
  const ws = new WebSocket(`ws://127.0.0.1:${port}/sagebrush`, { origin: ORIGIN });
  const events = [];
  let hello;
  ws.on("message", (d) => {
    const msg = JSON.parse(d.toString());
    if (msg.id === "p1") return hello?.(msg);
    if (msg.method === "turn.event") events.push(msg.params);
  });
  await new Promise((r, j) => { ws.on("open", r); ws.on("error", j); });
  await new Promise((r) => { hello = r; ws.send(JSON.stringify({ jsonrpc: "2.0", id: "p1", method: "hello", params: { protocol: 1, page: { origin: ORIGIN, path: "/agents/" }, code: server.newCode() } })); });
  const notify = (method, params) => ws.send(JSON.stringify({ jsonrpc: "2.0", method, params }));
  notify("grant.changed", GRANT);
  await until(() => server.binding?.grant, "the grant");
  let k = 0;
  const say = (conversation, text) => notify("chat.message", { conversation, id: `m${++k}`, author: "person", text });
  const finished = (conversation, outcome) => events.filter((e) => e.conversation === conversation && e.event.type === "turn_finished" && (!outcome || e.event.outcome === outcome)).length;
  const started = (conversation) => events.filter((e) => e.conversation === conversation && e.event.type === "turn_started").length;
  return { m, server, ws, logs, notify, say, finished, started, done: async () => { m.release(); await server.close(); } };
}

test("Stop ends a hung turn for its page at once; its running place is kept until the work settles, then given back once; the conversation goes on", async () => {
  const h = await setup();
  try {
    h.say("c1", "hang");
    await until(() => h.server.conversations.get("c1")?.running && h.m.releases.length === 1, "the hung turn");
    const t0 = Date.now();
    h.notify("chat.interrupt", { conversation: "c1" });
    await until(() => h.finished("c1", "interrupted") === 1, "the page told");
    assert.ok(Date.now() - t0 < 2000, `${Date.now() - t0} ms`);
    // (the turn has ended for the page and the conversation; its place is kept while its work is unsettled)
    await until(() => !h.server.conversations.get("c1").running, "the conversation free");
    assert.equal(h.server.counters().running, 1);
    assert.ok(h.logs.some((l) => /a turn didn't end: its Claude Code work may still be running/.test(l)));
    assert.equal(h.m.returns, 1, "the stream was closed");
    // (the conversation takes its next message)
    h.say("c1", "hello");
    await until(() => h.finished("c1", "completed") === 1, "the next turn");
    assert.equal(h.server.counters().running, 1, "still the hung one's place");
    // (the work settles, late: the place comes back once)
    h.m.release();
    await until(() => h.server.counters().running === 0, "the place given back");
    h.m.release();
    await new Promise((r) => setTimeout(r, 50));
    assert.equal(h.server.counters().running, 0);
  } finally { await h.done(); }
});

test("a revoke ends a hung turn for its page too (interrupted), with the same accounting", async () => {
  const h = await setup();
  try {
    h.say("c1", "hang");
    await until(() => h.m.releases.length === 1, "the hung turn");
    h.notify("grant.changed", null);
    await until(() => h.finished("c1", "interrupted") === 1, "the page told");
    await until(() => !h.server.conversations.get("c1").running, "the conversation free");
    assert.equal(h.server.counters().running, 1);
    h.m.release();
    await until(() => h.server.counters().running === 0, "given back");
  } finally { await h.done(); }
});

test("four hung turns hold RUNNING_MAX: a fifth conversation's message waits, and runs when one settles", async () => {
  const h = await setup();
  try {
    for (const c of ["c1", "c2", "c3", "c4"]) h.say(c, "hang");
    await until(() => h.m.releases.length === 4, "four hung");
    for (const c of ["c1", "c2", "c3", "c4"]) h.notify("chat.interrupt", { conversation: c });
    await until(() => ["c1", "c2", "c3", "c4"].every((c) => h.finished(c, "interrupted") === 1), "all four told");
    await until(() => ["c1", "c2", "c3", "c4"].every((c) => !h.server.conversations.get(c).running), "all four free");
    assert.equal(h.server.counters().running, 4);
    h.say("c5", "hello");
    await new Promise((r) => setTimeout(r, 300));
    assert.equal(h.started("c5"), 0, "c5 waits: no running place");
    assert.equal(h.m.releases.length, 8, "each hung turn holds its next() and its return()");
    h.m.releaseSession(h.server.conversations.get("c1").sessionId); // (one hung turn's work settles; the others still hold theirs)
    await until(() => h.finished("c5", "completed") === 1, "c5 ran in the freed place");
    await until(() => h.server.counters().running === 3, "three still held after c5 ended");
  } finally { await h.done(); }
});

test("closing the agent reports a turn whose work hadn't settled", async () => {
  const h = await setup();
  let problems;
  try {
    h.say("c1", "hang");
    await until(() => h.m.releases.length === 1, "the hung turn");
    h.notify("chat.interrupt", { conversation: "c1" });
    await until(() => h.server.hungTurns.size === 1, "the hung turn kept");
    problems = await h.server.close();
  } finally { h.m.release(); }
  assert.ok(problems.some((p) => /a turn didn't end: its Claude Code work may still be running/.test(p)), JSON.stringify(problems));
});
