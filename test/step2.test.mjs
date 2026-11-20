// Step 2: a turn started under a grant with an id outlives its page. It goes on while no page is there, a workspace
// call waits (bounded) for a page with that grant, and a page that comes back with that same grant (not wider) carries
// it on; another grant, a wider one, a revoke, the grant's expiry or the turn's limit ends it. Queued messages wait
// while no page is there and start only under their grant. The daemon end to end with fake pages and a scripted model.
import assert from "node:assert/strict";
import { test } from "node:test";
import WebSocket from "ws";
import { fakeCreateServer } from "../lib/fake.mjs";
import { AgentServer, sameGrant, scopeOf } from "../lib/server.mjs";

const ORIGIN = "https://agents.sagebrush.cloud";

// A scripted model: its prompt is steps separated by ";": "wait NAME" (until the test opens that gate), "list"
// (workspace_list, its outcome said as text), "ask" (WebFetch through the permission callback, its verdict said).
const gates = new Map();
const gate = (name) => {
  let open;
  const p = new Promise((r) => (open = r));
  gates.set(name, { p, open });
  return () => open();
};
function scriptedQuery({ prompt, options }) {
  const tools = options.mcpServers.sagebrush.handlers;
  const signal = options.abortController?.signal;
  let index = 0;
  const say = (t) => {
    const i = index++;
    return [
      { type: "stream_event", parent_tool_use_id: null, event: { type: "content_block_start", index: i, content_block: { type: "text", text: "" } } },
      { type: "stream_event", parent_tool_use_id: null, event: { type: "content_block_delta", index: i, delta: { type: "text_delta", text: t } } },
      { type: "stream_event", parent_tool_use_id: null, event: { type: "content_block_stop", index: i } },
    ];
  };
  const aborted = () => new Promise((_, reject) => signal?.addEventListener("abort", () => reject(Object.assign(new Error("aborted"), { name: "AbortError" })), { once: true }));
  async function* run() {
    yield { type: "system", subtype: "init", session_id: `s-${Math.random().toString(36).slice(2)}`, model: "fake", tools: [] };
    for (const step of prompt.split(";").map((x) => x.trim())) {
      const [cmd, arg] = step.split(" ");
      if (cmd === "wait") await Promise.race([gates.get(arg).p, aborted()]);
      else if (cmd === "list") {
        const r = await tools.workspace_list({ folder: "/" });
        yield* say(`LIST ${r.isError ? r.content[0].text : "ok"}`);
      } else if (cmd === "run") {
        const r = await tools.workspace_run_notebook({ path: "/a.ipynb" });
        yield* say(`RUN ${r.isError ? r.content[0].text : "ok"}`);
      } else if (cmd === "ask") {
        const v = await options.canUseTool("WebFetch", { url: "https://example.com", prompt: "x" }, { signal });
        yield* say(`ASK ${v.behavior}`);
      }
    }
    yield { type: "result", subtype: "success", is_error: false, result: "done", usage: { input_tokens: 1, output_tokens: 1 }, session_id: "s" };
  }
  return run();
}

async function start(opts = {}) {
  const server = new AgentServer({ query: scriptedQuery, log: () => {}, ...opts });
  server.createServer = fakeCreateServer;
  const port = await server.listen();
  return { server, port, code: server.newCode() };
}

// A fake page: answers workspace.list (or holds every request, `hold`), keeps every message it gets.
function page(port, { hold = false } = {}) {
  const ws = new WebSocket(`ws://127.0.0.1:${port}/sagebrush`, { origin: ORIGIN });
  const msgs = [], requests = [];
  let onHello;
  ws.on("message", (d) => {
    const m = JSON.parse(d.toString());
    if (m.id === "p1") return onHello?.(m);
    msgs.push(m);
    if (typeof m.id === "string" && m.method) {
      requests.push(m);
      if (hold) return;
      ws.send(JSON.stringify({ jsonrpc: "2.0", id: m.id, result: m.method === "workspace.list" ? { entries: [] } : {} }));
    }
  });
  const hello = (params) => new Promise((resolve) => {
    onHello = resolve;
    ws.send(JSON.stringify({ jsonrpc: "2.0", id: "p1", method: "hello", params: { protocol: 1, page: { origin: ORIGIN, path: "/agents/" }, ...params } }));
  });
  const notify = (method, params) => ws.send(JSON.stringify({ jsonrpc: "2.0", method, params }));
  const open = new Promise((resolve, reject) => { ws.on("open", resolve); ws.on("error", reject); });
  const closed = new Promise((resolve) => ws.on("close", resolve));
  return { ws, msgs, requests, hello, notify, open, closed };
}

const until = async (f, ms = 8000) => {
  const t = Date.now();
  while (!f()) {
    if (Date.now() - t > ms) throw new Error("timed out");
    await new Promise((r) => setTimeout(r, 20));
  }
};
const G1 = { folders: ["/"], write: true, run: false, expires: null, id: "grant-one" };
/** Everything the agent said about a conversation (its log), as a page that asks gets it. */
const logOf = (server, conversation) => server.logs.since(conversation, 0).events;
const texts = (server, conversation) => logOf(server, conversation).filter((e) => e.method === "turn.event" && e.params.event.type === "text_delta").map((e) => e.params.event.text).join("");
const finished = (server, conversation) => logOf(server, conversation).filter((e) => e.method === "turn.event" && e.params.event.type === "turn_finished").map((e) => e.params.event.outcome);

async function paired(port, code, grant = G1) {
  const a = page(port);
  await a.open;
  const h = await a.hello({ code });
  a.notify("grant.changed", grant);
  return { a, session: h.result.session };
}
async function again(port, session, grant = G1, opts) {
  const b = page(port, opts);
  await b.open;
  await b.hello({ session });
  if (grant !== undefined) b.notify("grant.changed", grant);
  return b;
}

test("sameGrant: the same id, and no wider; a scope is frozen at the turn's start", () => {
  const start = scopeOf({ id: "g", folders: ["/notes"], write: false, run: false });
  assert.equal(sameGrant(start, { id: "g", folders: ["/notes"], write: false }), true);
  assert.equal(sameGrant(start, { id: "g", folders: ["/notes/sub"], write: false }), true); // (narrower)
  assert.equal(sameGrant(start, { id: "g", folders: ["/"], write: false }), false); // (wider: Everything)
  assert.equal(sameGrant(start, { id: "g", folders: ["/notesX"], write: false }), false); // (a sibling, not within)
  assert.equal(sameGrant(start, { id: "g", folders: ["/notes"], write: true }), false); // (write newly on)
  assert.equal(sameGrant(start, { id: "g", folders: ["/notes"], run: true }), false); // (run newly on)
  assert.equal(sameGrant(start, { id: "g", folders: ["/notes"], native: true }), false);
  assert.equal(sameGrant(start, { id: "h", folders: ["/notes"] }), false); // (another grant)
  assert.equal(sameGrant(scopeOf({ folders: ["/"] }), { folders: ["/"] }), false); // (no id: never)
  assert.ok(Object.isFrozen(start) && Object.isFrozen(start.folders));
});

test("detached mid-turn: the turn goes on, a call waits for the page, and the page back with the same grant carries it", async () => {
  const { server, port, code } = await start();
  const openA = gate("A1");
  const { a, session } = await paired(port, code);
  a.notify("chat.message", { conversation: "c1", id: "u1", author: "person", text: "wait A1; list" });
  await until(() => server.counters().running === 1);
  a.ws.close();
  await a.closed;
  await new Promise((r) => setTimeout(r, 100));
  assert.equal(server.counters().running, 1, "the turn goes on without a page");
  openA(); // (the model calls workspace_list now: no page holds the grant, so it waits)
  await new Promise((r) => setTimeout(r, 150));
  assert.equal(server.waiterCount, 1, "the call waits for a page");
  const b = await again(port, session);
  await until(() => finished(server, "c1").length === 1);
  assert.deepEqual(finished(server, "c1"), ["completed"]);
  assert.match(texts(server, "c1"), /LIST ok/);
  assert.ok(b.requests.some((r) => r.method === "workspace.list"), "the call went to the new page");
  // (and the replay names no running turn now; while it ran, it named it: the next test)
  b.ws.close();
  server.close();
});

test("the page back with another grant, a wider one, or a revoke: the turn ends, its waiting call refused", async () => {
  for (const [what, next] of [["another id", { ...G1, id: "grant-two" }], ["wider (run newly on)", { ...G1, run: true }], ["a revoke", {}]]) {
    const { server, port, code } = await start();
    const openA = gate("A2");
    const { a, session } = await paired(port, code, { ...G1, run: false });
    a.notify("chat.message", { conversation: "c1", id: "u1", author: "person", text: "wait A2; list" });
    await until(() => server.counters().running === 1);
    a.ws.close();
    await a.closed;
    openA();
    await new Promise((r) => setTimeout(r, 100));
    const b = await again(port, session, next);
    await until(() => finished(server, "c1").length === 1);
    assert.deepEqual(finished(server, "c1"), ["interrupted"], what);
    assert.ok(!b.requests.some((r) => r.method === "workspace.list"), `${what}: nothing went to the new page`);
    assert.equal(server.waiterCount, 0, `${what}: no call left waiting`);
    b.ws.close();
    server.close();
  }
});

test("no page in time: the call is refused as the page being closed; the turn itself goes on and ends as the model says", async () => {
  const { server, port, code } = await start({ rebindWaitMs: 300 });
  const openA = gate("A3");
  const { a } = await paired(port, code);
  a.notify("chat.message", { conversation: "c1", id: "u1", author: "person", text: "wait A3; list" });
  await until(() => server.counters().running === 1);
  a.ws.close();
  await a.closed;
  openA();
  await until(() => finished(server, "c1").length === 1, 5000);
  assert.deepEqual(finished(server, "c1"), ["completed"]);
  assert.match(texts(server, "c1"), /LIST refused: the page is closed/);
  assert.equal(server.waiterCount, 0);
  server.close();
});

test("a call in flight when the page goes: it fails then, and never comes back through the next page (D4)", async () => {
  const { server, port, code } = await start();
  const a = page(port, { hold: true });
  await a.open;
  const h = await a.hello({ code });
  a.notify("grant.changed", G1);
  a.notify("chat.message", { conversation: "c1", id: "u1", author: "person", text: "list" });
  await until(() => a.requests.some((r) => r.method === "workspace.list"));
  const id = a.requests.find((r) => r.method === "workspace.list").id;
  a.ws.close();
  await until(() => finished(server, "c1").length === 1);
  assert.match(texts(server, "c1"), /LIST refused: the page disconnected/);
  const b = await again(port, h.result.session);
  // (an answer to the old request through the new page goes nowhere)
  b.ws.send(JSON.stringify({ jsonrpc: "2.0", id, result: { entries: [{ path: "/late" }] } }));
  await new Promise((r) => setTimeout(r, 100));
  assert.doesNotMatch(texts(server, "c1"), /late/);
  b.ws.close();
  server.close();
});

test("the grant's expiry and the turn's limit end a detached turn on the agent's own clock (D2)", async () => {
  for (const [what, opts, grant] of [["expiry", {}, { ...G1, expires: Date.now() + 400 }], ["the turn's limit", { turnMaxMs: 400 }, G1]]) {
    const { server, port, code } = await start(opts);
    gate("A4");
    const { a } = await paired(port, code, grant);
    a.notify("chat.message", { conversation: "c1", id: "u1", author: "person", text: "wait A4; list" });
    await until(() => server.counters().running === 1);
    a.ws.close();
    await a.closed;
    await until(() => finished(server, "c1").length === 1, 5000);
    assert.deepEqual(finished(server, "c1"), ["interrupted"], what);
    assert.equal(server.links.size, 0, `${what}: the turn's link is gone`);
    server.close();
  }
});

test("queued messages wait while no page is there and start only under their grant (D7); another grant rejects them", async () => {
  for (const [what, next, starts] of [["the same grant", G1, true], ["another grant", { ...G1, id: "grant-two" }, false]]) {
    const { server, port, code } = await start();
    const openA = gate("A5");
    const { a, session } = await paired(port, code);
    a.notify("chat.message", { conversation: "c1", id: "u1", author: "person", text: "wait A5" });
    a.notify("chat.message", { conversation: "c1", id: "u2", author: "person", text: "list" });
    await until(() => server.counters().running === 1 && server.counters().queued === 1);
    a.ws.close();
    await a.closed;
    openA();
    await until(() => finished(server, "c1").length === 1);
    await new Promise((r) => setTimeout(r, 150));
    assert.equal(server.counters().running, 0, `${what}: the next one doesn't start while no page is there`);
    assert.equal(server.counters().queued, 1);
    const b = await again(port, session, next);
    if (starts) {
      await until(() => finished(server, "c1").length === 2);
      assert.match(texts(server, "c1"), /LIST ok/, what);
    } else {
      await until(() => logOf(server, "c1").some((e) => e.method === "chat.rejected" && e.params.id === "u2"));
      assert.equal(server.counters().queued, 0, what);
    }
    b.ws.close();
    server.close();
  }
});

test("an open card across a detach: answered from the page back with the same grant (D6)", async () => {
  const { server, port, code } = await start();
  const { a, session } = await paired(port, code);
  a.notify("chat.message", { conversation: "c1", id: "u1", author: "person", text: "ask" });
  await until(() => server.permissions.size === 1);
  const [id] = [...server.permissions.keys()];
  a.ws.close();
  await a.closed;
  await new Promise((r) => setTimeout(r, 50));
  assert.equal(server.permissions.size, 1, "the card stays open while no page is there");
  const b = await again(port, session);
  await until(() => [...server.permissions.values()][0]?.binding === server.binding);
  b.notify("chat.permission", { request_id: id, behavior: "allow" });
  await until(() => finished(server, "c1").length === 1);
  assert.match(texts(server, "c1"), /ASK allow/);
  b.ws.close();
  server.close();
});

test("a replay names the conversation's running turn; and a turn under a grant without an id ends with its page, as before", async () => {
  {
    const { server, port, code } = await start();
    gate("A6");
    const { a } = await paired(port, code);
    a.notify("chat.message", { conversation: "c1", id: "u1", author: "person", text: "wait A6" });
    await until(() => server.counters().running === 1);
    a.notify("chat.resume", { conversation: "c1", after: 0 });
    await until(() => a.msgs.some((m) => m.method === "chat.replay"));
    const r = a.msgs.find((m) => m.method === "chat.replay").params;
    const turnId = logOf(server, "c1").find((e) => e.method === "turn.event").params.turn_id;
    assert.deepEqual(r.running, [turnId]);
    a.ws.close();
    server.close();
  }
  {
    const { server, port, code } = await start();
    gate("A7");
    const { id, ...noId } = G1;
    const { a } = await paired(port, code, noId);
    a.notify("chat.message", { conversation: "c1", id: "u1", author: "person", text: "wait A7" });
    await until(() => server.counters().running === 1);
    a.ws.close();
    await until(() => finished(server, "c1").length === 1);
    assert.deepEqual(finished(server, "c1"), ["interrupted"]);
    server.close();
  }
});

test("Stop while a call waits for the page: the wait ends with the turn, nothing left waiting", async () => {
  const { server, port, code } = await start();
  const openA = gate("A8");
  const { a, session } = await paired(port, code);
  a.notify("chat.message", { conversation: "c1", id: "u1", author: "person", text: "wait A8; list" });
  await until(() => server.counters().running === 1);
  a.ws.close();
  await a.closed;
  openA();
  await until(() => server.waiterCount === 1);
  // (the person's Stop, from a page that paired again without its grant yet: Stop is the paired page's to send)
  const b = await again(port, session, undefined);
  b.notify("chat.interrupt", { conversation: "c1" });
  await until(() => finished(server, "c1").length === 1);
  assert.deepEqual(finished(server, "c1"), ["interrupted"]);
  assert.equal(server.waiterCount, 0);
  assert.equal(server.links.size, 0);
  b.ws.close();
  server.close();
});

test("a card asked while no page is there: it waits in the log, and the page back with the grant answers it", async () => {
  const { server, port, code } = await start();
  const openA = gate("A9");
  const { a, session } = await paired(port, code);
  a.notify("chat.message", { conversation: "c1", id: "u1", author: "person", text: "wait A9; ask" });
  await until(() => server.counters().running === 1);
  a.ws.close();
  await a.closed;
  openA();
  await until(() => server.permissions.size === 1);
  assert.ok(logOf(server, "c1").some((e) => e.method === "turn.event" && e.params.event.type === "attention" && e.params.event.state === "open"), "the card is in the conversation's log");
  const [id] = [...server.permissions.keys()];
  const b = await again(port, session);
  await until(() => [...server.permissions.values()][0]?.binding === server.binding);
  b.notify("chat.permission", { request_id: id, behavior: "deny" });
  await until(() => finished(server, "c1").length === 1);
  assert.match(texts(server, "c1"), /ASK deny/);
  b.ws.close();
  server.close();
});

test("run.context is decided on the page the run goes to, after the wait: with it, the turn's context; without it, none", async () => {
  for (const [what, features, has] of [["a page that offers run.context", ["run.context"], true], ["an older page that doesn't", [], false]]) {
    const { server, port, code } = await start();
    const openA = gate("B1");
    const { a, session } = await paired(port, code);
    a.notify("page.features", { features: ["run.context"] });
    a.notify("chat.message", { conversation: "c1", id: "u1", author: "person", text: "wait B1; run" });
    await until(() => server.counters().running === 1);
    a.ws.close();
    await a.closed;
    openA();
    await until(() => server.waiterCount === 1);
    const b = await again(port, session);
    b.notify("page.features", { features });
    await until(() => b.requests.some((r) => r.method === "workspace.run_notebook"));
    const p = b.requests.find((r) => r.method === "workspace.run_notebook").params;
    assert.equal("conversation" in p && "turn_id" in p, has, `${what}: ${JSON.stringify(p)}`);
    if (has) assert.equal(p.conversation, "c1");
    await until(() => finished(server, "c1").length === 1);
    b.ws.close();
    server.close();
  }
});

test("a turn whose grant ends with a card open: the card is resolved (denied) and none is left open", async () => {
  const { server, port, code } = await start();
  const { a } = await paired(port, code);
  a.notify("chat.message", { conversation: "c1", id: "u1", author: "person", text: "ask" });
  await until(() => server.permissions.size === 1);
  a.notify("grant.changed", {}); // (a revoke)
  await until(() => finished(server, "c1").length === 1);
  assert.deepEqual(finished(server, "c1"), ["interrupted"]);
  assert.equal(server.permissions.size, 0);
  const states = logOf(server, "c1").filter((e) => e.method === "turn.event" && e.params.event.type === "attention").map((e) => e.params.event.state);
  assert.deepEqual(states, ["open", "denied"]);
  a.ws.close();
  server.close();
});
