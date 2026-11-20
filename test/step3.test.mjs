// Step 3, Steer: a message the person sends while a Claude turn runs goes into that turn, taken at Claude's next step
// ("next"), with receipts: "steering" when it went in, "delivered" when a message of Claude's names it as taken, and
// "queued" (with why) when it runs next instead. The daemon end to end with a fake page and a scripted model that
// reads the turn's input stream as the SDK's CLI does.
import assert from "node:assert/strict";
import { test } from "node:test";
import WebSocket from "ws";
import { fakeCreateServer } from "../lib/fake.mjs";
import { AgentServer, sameGrant, scopeOf } from "../lib/server.mjs";

const ORIGIN = "https://agents.sagebrush.cloud";
const gates = new Map();
const gate = (name) => {
  let open;
  const p = new Promise((r) => (open = r));
  gates.set(name, { p, open });
  return () => open();
};
const textOf = (m) => (typeof m?.message?.content === "string" ? m.message.content : "");

// The scripted model: the first input message is steps separated by ";":
// "wait NAME" (until the test opens that gate), "take" (the next input message: an assistant message names it as
// taken, then "GOT <its text>"), "more" (a result saying one more send waits, as the CLI does between batched turns).
const priorities = [];
function scriptedQuery({ prompt, options }) {
  const signal = options.abortController?.signal;
  const it = prompt[Symbol.asyncIterator]();
  let index = 0;
  const say = (t, extra = {}) => {
    const i = index++;
    return [
      { type: "stream_event", parent_tool_use_id: null, event: { type: "content_block_start", index: i, content_block: { type: "text", text: "" } }, ...extra },
      { type: "stream_event", parent_tool_use_id: null, event: { type: "content_block_delta", index: i, delta: { type: "text_delta", text: t } } },
      { type: "stream_event", parent_tool_use_id: null, event: { type: "content_block_stop", index: i } },
    ];
  };
  const aborted = () => new Promise((_, reject) => signal?.addEventListener("abort", () => reject(Object.assign(new Error("aborted"), { name: "AbortError" })), { once: true }));
  async function* run() {
    const first = (await it.next()).value;
    const consumed = [first.uuid];
    yield { type: "system", subtype: "init", session_id: `s-${Math.random().toString(36).slice(2)}`, model: "fake", tools: [] };
    for (const step of textOf(first).split(";").map((x) => x.trim())) {
      const [cmd, arg] = step.split(" ");
      if (cmd === "wait") await Promise.race([gates.get(arg).p, aborted()]);
      else if (cmd === "take") {
        const { value } = await Promise.race([it.next(), aborted()]);
        priorities.push(value.priority);
        consumed.push(value.uuid);
        yield* say(`GOT ${textOf(value)}`, { user_message_uuids: [...consumed] });
      } else if (cmd === "more") {
        yield { type: "result", subtype: "success", is_error: false, result: "part", queued_turn_count: 1, user_message_uuids: [...consumed], session_id: "s" };
        yield* say("AFTER");
      }
    }
    yield { type: "result", subtype: "success", is_error: false, result: "done", usage: { input_tokens: 1, output_tokens: 1 }, user_message_uuids: consumed, session_id: "s" };
  }
  return run();
}

async function start(opts = {}) {
  const server = new AgentServer({ query: scriptedQuery, log: () => {}, ...opts });
  server.createServer = fakeCreateServer;
  const port = await server.listen();
  return { server, port, code: server.newCode() };
}
const G1 = { folders: ["/"], write: true, run: false, expires: null, id: "grant-one" };
async function paired(port, code, grant = G1) {
  const ws = new WebSocket(`ws://127.0.0.1:${port}/sagebrush`, { origin: ORIGIN });
  const msgs = [];
  let onHello;
  ws.on("message", (d) => {
    const m = JSON.parse(d.toString());
    if (m.id === "p1") return onHello?.(m);
    msgs.push(m);
  });
  await new Promise((resolve, reject) => { ws.on("open", resolve); ws.on("error", reject); });
  const notify = (method, params) => ws.send(JSON.stringify({ jsonrpc: "2.0", method, params }));
  const hello = await new Promise((resolve) => {
    onHello = resolve;
    ws.send(JSON.stringify({ jsonrpc: "2.0", id: "p1", method: "hello", params: { protocol: 1, page: { origin: ORIGIN, path: "/agents/" }, code } }));
  });
  notify("page.features", { features: ["permission.digest"] });
  notify("grant.changed", grant);
  return { ws, msgs, notify, hello };
}
const until = async (f, ms = 8000) => {
  const t = Date.now();
  while (!f()) {
    if (Date.now() - t > ms) throw new Error("timed out");
    await new Promise((r) => setTimeout(r, 20));
  }
};
const logOf = (server, c) => server.logs.since(c, 0).events;
const texts = (server, c) => logOf(server, c).filter((e) => e.method === "turn.event" && e.params.event.type === "text_delta").map((e) => e.params.event.text).join("|");
const finished = (server, c) => logOf(server, c).filter((e) => e.method === "turn.event" && e.params.event.type === "turn_finished").map((e) => e.params.event.outcome);
const started = (server, c) => logOf(server, c).filter((e) => e.method === "turn.event" && e.params.event.type === "turn_started").length;
const receipts = (msgs, id) => msgs.filter((m) => m.method === "chat.receipt" && m.params.id === id).map((m) => m.params.state + (m.params.reason ? `:${m.params.reason}` : ""));

test("the hello offers chat.steer", async () => {
  const { server, port, code } = await start();
  const ws = new WebSocket(`ws://127.0.0.1:${port}/sagebrush`, { origin: ORIGIN });
  await new Promise((r) => ws.on("open", r));
  const hello = await new Promise((resolve) => {
    ws.on("message", (d) => { const m = JSON.parse(d.toString()); if (m.id === "p1") resolve(m); });
    ws.send(JSON.stringify({ jsonrpc: "2.0", id: "p1", method: "hello", params: { protocol: 1, page: { origin: ORIGIN, path: "/agents/" }, code } }));
  });
  assert.ok(hello.result.features.includes("chat.steer"));
  ws.close();
  server.close();
});

test("a steer goes into the running turn at its next step: steering, then delivered; one turn, no second", async () => {
  const { server, port, code } = await start();
  const openA = gate("A");
  const p = await paired(port, code);
  p.notify("chat.message", { conversation: "c1", id: "u1", author: "person", text: "wait A; take" });
  await until(() => server.counters().running === 1);
  p.notify("chat.message", { conversation: "c1", id: "u2", author: "person", text: "go left", steer: true });
  await until(() => receipts(p.msgs, "u2").length === 1);
  assert.deepEqual(receipts(p.msgs, "u2"), ["steering"]);
  assert.equal(server.counters().queued, 1, "it counts as waiting until Claude takes it");
  openA();
  await until(() => finished(server, "c1").length === 1);
  assert.deepEqual(receipts(p.msgs, "u2"), ["steering", "delivered"]);
  assert.equal(p.msgs.find((m) => m.method === "chat.receipt" && m.params.state === "delivered").params.turn_id, p.msgs.find((m) => m.method === "chat.receipt").params.turn_id);
  assert.match(texts(server, "c1"), /GOT go left/);
  assert.deepEqual(finished(server, "c1"), ["completed"]);
  assert.equal(started(server, "c1"), 1);
  assert.equal(priorities.at(-1), "next", "Claude takes it at its next step, never cutting off what it writes");
  assert.equal(server.counters().queued, 0);
  // (the person's message and both receipts are in the log, for another page or a reload)
  assert.deepEqual(logOf(server, "c1").filter((e) => e.method === "chat.receipt").map((e) => e.params.state), ["steering", "delivered"]);
  assert.ok(logOf(server, "c1").some((e) => e.method === "chat.message" && e.params.id === "u2" && e.params.steer === true), "logged as a steer");
  p.ws.close();
  server.close();
});

test("a steer the turn ends without taking: queued (ended), and it runs next as its own turn", async () => {
  const { server, port, code } = await start();
  const openA = gate("A");
  const p = await paired(port, code);
  p.notify("chat.message", { conversation: "c1", id: "u1", author: "person", text: "wait A" });
  await until(() => server.counters().running === 1);
  p.notify("chat.message", { conversation: "c1", id: "u2", author: "person", text: "wait B", steer: true });
  await until(() => receipts(p.msgs, "u2").length === 1);
  const openB = gate("B");
  openA();
  await until(() => started(server, "c1") === 2);
  await until(() => receipts(p.msgs, "u2").length === 2);
  assert.deepEqual(receipts(p.msgs, "u2"), ["steering", "queued:ended"]);
  openB();
  await until(() => finished(server, "c1").length === 2);
  assert.deepEqual(finished(server, "c1"), ["completed", "completed"]);
  assert.equal(server.counters().queued, 0);
  p.ws.close();
  server.close();
});

test("a steer with no turn running: queued (idle), and it starts a turn; without steer, no receipt, as before", async () => {
  const { server, port, code } = await start();
  const p = await paired(port, code);
  p.notify("chat.message", { conversation: "c1", id: "u1", author: "person", text: "hello", steer: true });
  await until(() => finished(server, "c1").length === 1);
  assert.deepEqual(receipts(p.msgs, "u1"), ["queued:idle"]);
  p.notify("chat.message", { conversation: "c1", id: "u2", author: "person", text: "again" });
  await until(() => finished(server, "c1").length === 2);
  assert.deepEqual(receipts(p.msgs, "u2"), []);
  p.ws.close();
  server.close();
});

test("a result with more sends waiting isn't the turn's end: one turn_finished, after the rest", async () => {
  const { server, port, code } = await start();
  const p = await paired(port, code);
  p.notify("chat.message", { conversation: "c1", id: "u1", author: "person", text: "more" });
  await until(() => finished(server, "c1").length === 1);
  await new Promise((r) => setTimeout(r, 50));
  assert.deepEqual(finished(server, "c1"), ["completed"]);
  assert.match(texts(server, "c1"), /AFTER/);
  p.ws.close();
  server.close();
});

test("Stop with a steer not yet taken: the turn ends interrupted, and the steer runs next (queued, ended)", async () => {
  const { server, port, code } = await start();
  gate("A");
  const p = await paired(port, code);
  p.notify("chat.message", { conversation: "c1", id: "u1", author: "person", text: "wait A" });
  await until(() => server.counters().running === 1);
  p.notify("chat.message", { conversation: "c1", id: "u2", author: "person", text: "hello", steer: true });
  await until(() => receipts(p.msgs, "u2").length === 1);
  p.notify("chat.interrupt", { conversation: "c1" });
  await until(() => finished(server, "c1").length === 2);
  assert.deepEqual(finished(server, "c1"), ["interrupted", "completed"]);
  await until(() => receipts(p.msgs, "u2").length === 2); // (the log has it first; the socket a moment later)
  assert.deepEqual(receipts(p.msgs, "u2"), ["steering", "queued:ended"]);
  p.ws.close();
  server.close();
});

test("a turn run by another agent (Codex) isn't steered: queued (codex), and it runs after", async () => {
  const { server, port, code } = await start();
  let release;
  const held = new Promise((r) => (release = r));
  const ran = [];
  server.backend = {
    close: async () => [],
    async runTurn(conversation, c, m, binding) {
      c.running = { binding, turnId: `codex-${ran.length}`, cancel() {} };
      ran.push(m.text);
      if (ran.length === 1) await held;
      c.running = null;
      queueMicrotask(() => server.schedule());
    },
  };
  const p = await paired(port, code);
  assert.ok(!p.hello.result.features.includes("chat.steer"), "an agent running Codex never says it steers (K1)");
  assert.ok(p.hello.result.features.includes("chat.resume"));
  p.notify("chat.message", { conversation: "c1", id: "u1", author: "person", text: "first" });
  await until(() => ran.length === 1);
  p.notify("chat.message", { conversation: "c1", id: "u2", author: "person", text: "second", steer: true });
  await until(() => receipts(p.msgs, "u2").length === 1);
  assert.deepEqual(receipts(p.msgs, "u2"), ["queued:codex"]);
  release();
  await until(() => ran.length === 2);
  assert.deepEqual(ran, ["first", "second"]);
  p.ws.close();
  server.close();
});

test("steers count against the waiting cap: past it, one more is refused as busy, nothing steered", async () => {
  const { server, port, code } = await start();
  gate("A");
  const p = await paired(port, code);
  p.notify("chat.message", { conversation: "c1", id: "u0", author: "person", text: "wait A" });
  await until(() => server.counters().running === 1);
  for (let i = 1; i <= 17; i++) p.notify("chat.message", { conversation: "c1", id: `s${i}`, author: "person", text: `s${i}`, steer: true });
  await until(() => p.msgs.some((m) => m.method === "chat.rejected" && m.params.id === "s17"));
  assert.equal(p.msgs.find((m) => m.method === "chat.rejected" && m.params.id === "s17").params.reason.code, "busy");
  assert.deepEqual(receipts(p.msgs, "s17"), []);
  assert.equal(server.counters().queued, 16);
  p.notify("chat.interrupt", { conversation: "c1" });
  p.ws.close();
  server.close();
});

// SEC-STEER-1: a turn's tools are fixed at its start, so a change of native, either way, is another grant: the turn
// ends, and a steer sent after it never enters the old turn's input; it starts a turn under the new grant.
test("sameGrant: native must be exactly as it was, in either direction", () => {
  assert.equal(sameGrant(scopeOf({ id: "g", folders: ["/"], native: true }), { id: "g", folders: ["/"], native: false }), false);
  assert.equal(sameGrant(scopeOf({ id: "g", folders: ["/"], native: true }), { id: "g", folders: ["/"] }), false);
  assert.equal(sameGrant(scopeOf({ id: "g", folders: ["/"] }), { id: "g", folders: ["/"], native: true }), false);
  assert.equal(sameGrant(scopeOf({ id: "g", folders: ["/"], native: true }), { id: "g", folders: ["/"], native: true }), true);
});

test("a native turn, then the same grant id with native off: the turn ends; a steer then runs as a new turn, never in the old one", async () => {
  const seen = [];
  const { server, port, code } = await start({ query: (o) => { seen.push(o.options); return scriptedQuery(o); } });
  gate("A");
  const p = await paired(port, code, { ...G1, native: true });
  p.notify("chat.message", { conversation: "c1", id: "u1", author: "person", text: "wait A; take" });
  await until(() => server.counters().running === 1);
  p.notify("grant.changed", { ...G1, native: false });
  await until(() => finished(server, "c1").length === 1);
  assert.deepEqual(finished(server, "c1"), ["interrupted"]);
  p.notify("chat.message", { conversation: "c1", id: "u2", author: "person", text: "after", steer: true });
  await until(() => finished(server, "c1").length === 2);
  assert.deepEqual(receipts(p.msgs, "u2"), ["queued:idle"], "it never entered the old turn");
  assert.doesNotMatch(texts(server, "c1"), /GOT after/);
  assert.equal(seen.length, 2);
  assert.deepEqual(seen[1].settingSources, [], "the new turn's query is tools-only, not native");
  p.ws.close();
  server.close();
});

// SEC-STEER-2: steers a turn never took are refused, as queued messages are (D7), when the turn ends for another
// grant, a revoke or the grant's expiry; they run next only after the turn's own end or the person's Stop.
for (const [what, change] of [
  ["another grant", (p) => p.notify("grant.changed", { ...G1, id: "grant-two" })],
  ["a revoke", (p) => p.notify("grant.changed", {})],
  ["the grant's expiry", null],
]) {
  test(`a steer not yet taken when the turn ends for ${what}: refused (cancelled), never run, not counted`, async () => {
    const ran = [];
    const { server, port, code } = await start({ query: (o) => { ran.push(o); return scriptedQuery(o); } });
    gate("A");
    const p = await paired(port, code, change ? G1 : { ...G1, expires: Date.now() + 600 });
    p.notify("chat.message", { conversation: "c1", id: "u1", author: "person", text: "wait A" });
    await until(() => server.counters().running === 1);
    p.notify("chat.message", { conversation: "c1", id: "u2", author: "person", text: "steer me", steer: true });
    await until(() => receipts(p.msgs, "u2").length === 1);
    change?.(p);
    await until(() => p.msgs.some((m) => m.method === "chat.rejected" && m.params.id === "u2"), 5000);
    assert.equal(p.msgs.find((m) => m.method === "chat.rejected" && m.params.id === "u2").params.reason.code, "cancelled");
    assert.deepEqual(receipts(p.msgs, "u2"), ["steering"], "no queued receipt");
    assert.equal(server.counters().queued, 0);
    if (change) p.notify("grant.changed", G1); // (the first grant back: still nothing runs)
    await new Promise((r) => setTimeout(r, 200));
    assert.equal(ran.length, 1, "the steer never started a turn");
    p.ws.close();
    server.close();
  });
}

// A grant's end wins over a Stop (astra): Stop and another grant back to back, in either order, and the untaken steer
// is refused and never runs, even after the first grant comes back.
for (const order of ["Stop, then another grant", "another grant, then Stop"]) {
  test(`${order}, with a steer not yet taken: refused, never run`, async () => {
    const ran = [];
    const { server, port, code } = await start({ query: (o) => { ran.push(o); return scriptedQuery(o); } });
    gate("A");
    const p = await paired(port, code);
    p.notify("chat.message", { conversation: "c1", id: "u1", author: "person", text: "wait A" });
    await until(() => server.counters().running === 1);
    p.notify("chat.message", { conversation: "c1", id: "u2", author: "person", text: "steer me", steer: true });
    await until(() => receipts(p.msgs, "u2").length === 1);
    const stop = () => p.notify("chat.interrupt", { conversation: "c1" });
    const other = () => p.notify("grant.changed", { ...G1, id: "grant-two" });
    if (order.startsWith("Stop")) { stop(); other(); } else { other(); stop(); }
    await until(() => p.msgs.some((m) => m.method === "chat.rejected" && m.params.id === "u2"), 5000);
    assert.equal(p.msgs.find((m) => m.method === "chat.rejected" && m.params.id === "u2").params.reason.code, "cancelled");
    p.notify("grant.changed", G1);
    await new Promise((r) => setTimeout(r, 300));
    assert.equal(ran.length, 1, "the steer never started a turn");
    assert.equal(server.counters().queued, 0);
    p.ws.close();
    server.close();
  });
}

test("K1: with --codex (a backend), features() (what the hello and agent.ready send) has no chat.steer; with Claude it does", async () => {
  const { CodexBackend } = await import("../lib/codex.mjs");
  const server = new AgentServer({ log: () => {} });
  assert.ok(server.features().includes("chat.steer"));
  server.backend = new CodexBackend(server, { command: "/nonexistent-codex" });
  assert.ok(!server.features().includes("chat.steer"));
  assert.deepEqual(server.features(), ["notebook.edit", "permission.digest", "run.context", "chat.resume", "edit.turn", "chat.resume.tag"]); // (a replay tag is the log's, any backend)
  await server.backend.close?.(Date.now() + 1000);
  server.close();
});
