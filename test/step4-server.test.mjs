// Step 4 in the server: the egress decision outside the model (S5–S8 and the wire pins). A web request or a search
// goes at once where the turn holds a grant for it, else one card; the card shows the request sanitized and binds the
// exact one; "allow" and "allow_turn" each need their own digest; a turn's grants die with the turn or its binding;
// the built-in WebFetch is denied; a server of the person's named like ours ends the turn. Rows named "egress: …".
import assert from "node:assert/strict";
import { test } from "node:test";
import { fakeCreateServer } from "../lib/fake.mjs";
import { AgentServer, LINK, scopeOf } from "../lib/server.mjs";
import { permissionDigest } from "../lib/canon.mjs";
import { summaryOf } from "../lib/turns.mjs";

const WF = "mcp__sagebrush_page__web_fetch";
const G1 = { folders: ["/"], write: true, run: false, expires: null, id: "grant-one" };

// A server with a page bound (its features as given), the cards it sends, and the page's answer.
function setup({ features = ["permission.digest", "egress.turn"], native = false } = {}) {
  const server = new AgentServer({ log: () => {} });
  server.createServer = fakeCreateServer;
  const ws = { readyState: 1, send() {} };
  server.sock = ws;
  const grant = native ? { ...G1, native: true } : G1;
  const binding = { ws, grant, gen: 1, features };
  server.binding = binding;
  const link = { [LINK]: true, binding, scope: scopeOf(grant), turnId: "t1", waiters: new Set(), ended: false, cancel() {} };
  const cards = [];
  const send = (drafts) => { for (const d of drafts) if (d.type === "attention" && d.state === "open") cards.push(d); };
  const ask = (tool, input, native = false) => server.decide(AgentServer.linkOf(link), send, tool, input, {}, "c1", native);
  const digest = (card, action = card.action) => permissionDigest({ child: server.child, conversation: "c1", request: card.request_id, tool: action.tool, input: action.input });
  const answer = (card, behavior, d) => server.notification("chat.permission", { request_id: card.request_id, behavior, ...(d !== undefined ? { digest: d } : {}) });
  return { server, binding, link, cards, ask, digest, answer };
}
const tick = () => new Promise((r) => setImmediate(r));
const plain = (v) => JSON.parse(JSON.stringify(v)); // (as the page gets it)

test("egress: the built-in WebFetch is denied (the backstop to its absence); the cardless verbs need no card", async () => {
  const s = setup();
  assert.equal((await s.ask("WebFetch", { url: "https://example.org/", prompt: "x" })).behavior, "deny");
  // (native mode asks the person about any tool its rules leave open: the built-in WebFetch is still never asked about)
  const n = setup({ native: true });
  const r = await Promise.race([n.ask("WebFetch", { url: "https://example.org/", prompt: "x" }, true), new Promise((res) => setTimeout(() => res("a card is pending"), 300))]);
  assert.equal(r?.behavior, "deny", JSON.stringify(r));
  assert.equal(n.cards.length, 0, "no card for it");
  for (const t of ["repo_read", "repo_list", "sagebrush_docs"]) assert.equal((await s.ask(`mcp__sagebrush_page__${t}`, { path: "/llms.txt" })).behavior, "allow");
  assert.equal(s.cards.length, 0);
});

test("egress: a web_fetch card shows {origin, path, reason} only, never the query, and carries turn_action where the page offers egress.turn", async () => {
  const s = setup();
  const v = s.ask(WF, { url: "https://Docs.Example.org/a/b?token=hunter2#frag", reason: "read the docs" });
  await tick();
  const c = s.cards[0];
  assert.deepEqual(plain(c.action), { tool: WF, input: { origin: "https://docs.example.org", path: "/a/b", reason: "read the docs" } });
  assert.deepEqual(c.turn_action, { tool: "egress.turn", input: { origin: "https://docs.example.org" } });
  assert.equal(c.summary, "https://docs.example.org/a/b");
  assert.ok(!JSON.stringify(c).includes("hunter2") && !JSON.stringify(c).includes("frag"), "no query or fragment anywhere on the card");
  s.answer(c, "deny");
  assert.equal((await v).behavior, "deny");
  assert.equal(summaryOf(WF, { url: "https://docs.example.org/a?token=hunter2" }), "https://docs.example.org/a", "the tool row too (S6)");
  assert.equal(summaryOf("WebSearch", { query: "secret terms" }), "Anthropic's web search");
});

test("egress: a page without egress.turn gets no turn_action, and allow_turn from it is denied", async () => {
  const s = setup({ features: ["permission.digest"] });
  const v = s.ask(WF, { url: "https://example.org/x" });
  await tick();
  assert.equal(s.cards[0].turn_action, undefined);
  s.answer(s.cards[0], "allow_turn", s.digest(s.cards[0], { tool: "egress.turn", input: { origin: "https://example.org" } }));
  assert.equal((await v).behavior, "deny");
});

test("egress: allow and allow_turn each need their own digest; neither stands in for the other (S7)", async () => {
  const s = setup();
  const v1 = s.ask(WF, { url: "https://example.org/x" });
  await tick();
  s.answer(s.cards[0], "allow", s.digest(s.cards[0], s.cards[0].turn_action));
  assert.equal((await v1).behavior, "deny", "allow with the turn's digest");
  const v2 = s.ask(WF, { url: "https://example.org/x" });
  await tick();
  s.answer(s.cards[1], "allow_turn", s.digest(s.cards[1]));
  assert.equal((await v2).behavior, "deny", "allow_turn with the request's digest");
  assert.equal(s.link.egress.origins.size, 0, "no grant was installed");
});

test("egress: allow_turn installs the origin for this turn: the next request there goes at once, another origin asks", async () => {
  const s = setup();
  const v = s.ask(WF, { url: "https://example.org/x?q=1" });
  await tick();
  s.answer(s.cards[0], "allow_turn", s.digest(s.cards[0], s.cards[0].turn_action));
  const r = await v;
  assert.equal(r.behavior, "allow");
  assert.equal(r.updatedInput.url, "https://example.org/x?q=1", "the exact request it was bound to");
  assert.equal((await s.ask(WF, { url: "https://example.org/other?z=2" })).behavior, "allow", "same origin: no card");
  assert.equal(s.cards.length, 1);
  const v3 = s.ask(WF, { url: "https://elsewhere.example/" });
  await tick();
  assert.equal(s.cards.length, 2, "another origin asks");
  s.answer(s.cards[1], "deny");
  await v3;
});

test("egress: two concurrent requests with the same displayed origin, path and reason, and different queries: an answer releases only its own (P1)", async () => {
  const s = setup();
  const a = s.ask(WF, { url: "https://example.org/p?id=A", reason: "r" });
  const b = s.ask(WF, { url: "https://example.org/p?id=B", reason: "r" });
  await tick();
  assert.equal(s.cards.length, 2);
  assert.deepEqual(plain(s.cards[0].action), plain(s.cards[1].action), "identical displayed actions");
  let bDone = false;
  b.then(() => (bDone = true));
  s.answer(s.cards[0], "allow", s.digest(s.cards[0]));
  const ra = await a;
  assert.equal(ra.updatedInput.url, "https://example.org/p?id=A");
  await tick();
  assert.equal(bDone, false, "B is still waiting: A's answer never released it");
  s.answer(s.cards[0], "allow", s.digest(s.cards[0]));
  await tick();
  assert.equal(bDone, false, "a second answer to A (single consumption) does nothing to B");
  s.answer(s.cards[1], "deny");
  assert.equal((await b).behavior, "deny");
});

test("egress: a turn grant dies on the page's rebind (adopt), and with the turn; an answer after the turn ended grants nothing (S5)", async () => {
  const s = setup();
  const v = s.ask(WF, { url: "https://example.org/" });
  await tick();
  s.answer(s.cards[0], "allow_turn", s.digest(s.cards[0], s.cards[0].turn_action));
  await v;
  assert.ok(s.link.egress.origins.has("https://example.org"));
  s.server.adopt(s.link, s.binding);
  const v2 = s.ask(WF, { url: "https://example.org/" });
  await tick();
  assert.equal(s.cards.length, 2, "after the rebind it asks again");
  s.link.ended = true;
  s.answer(s.cards[1], "allow_turn", s.digest(s.cards[1], s.cards[1].turn_action));
  assert.equal((await v2).behavior, "deny", "the turn had ended: no grant, and the request isn't released");
  assert.equal(s.link.egress?.origins.size ?? 0, 0);
});

test("egress: WebSearch: a card naming the provider, never the terms; allow_turn allows searches for the rest of the turn", async () => {
  const s = setup();
  const v = s.ask("WebSearch", { query: "my secret project name" });
  await tick();
  const c = s.cards[0];
  assert.deepEqual(plain(c.action), { tool: "WebSearch", input: { provider: "Anthropic", reason: "" } });
  assert.deepEqual(c.turn_action, { tool: "egress.turn", input: { provider: "Anthropic" } });
  assert.ok(!JSON.stringify(c).includes("secret project"));
  s.answer(c, "allow_turn", s.digest(c, c.turn_action));
  const r = await v;
  assert.equal(r.updatedInput.query, "my secret project name", "the search the model asked for, as it was");
  assert.equal((await s.ask("WebSearch", { query: "another" })).behavior, "allow");
  assert.equal(s.cards.length, 1);
});

test("egress: a URL that isn't https to a name on the default port is refused without a card", async () => {
  const s = setup();
  for (const url of ["http://example.org/", "https://127.0.0.1/", "https://u:p@example.org/", "https://example.org:8443/", "https://example.org./"])
    assert.equal((await s.ask(WF, { url })).behavior, "deny", url);
  assert.equal(s.cards.length, 0);
});

test("egress: native mode: our own ask rules for remove and rename, and no built-in WebFetch; a server of the person's named like ours ends the turn before any tool (S8)", async () => {
  let opts;
  const server = new AgentServer({ log: () => {}, stdio: true, runnerCwd: "/tmp", resolver: { resolveSettings: async () => ({ effective: {}, sources: [] }), filterEscalatingDefaultMode: (r) => r.effective },
    query: (o) => { opts = o.options; return (async function* () { yield { type: "system", subtype: "init", session_id: "s1", tools: ["mcp__sagebrush_page__workspace_list", "mcp__sagebrush_page__evil_tool"] }; yield { type: "assistant", message: { content: [{ type: "text", text: "SHOULD NOT" }] } }; })(); } });
  server.createServer = fakeCreateServer;
  const sent = [];
  const ws = { readyState: 1, send: (s) => sent.push(JSON.parse(s)), room: () => true };
  server.sock = ws;
  server.binding = { ws, grant: { ...G1, native: true }, gen: 1, features: [] };
  await server.runTurn("c1", server.conversation("c1"), { id: "u1", text: "hi", scope: null }, server.binding);
  assert.deepEqual(opts.settings.permissions.ask, ["mcp__sagebrush_page__workspace_rename", "mcp__sagebrush_page__workspace_remove"]);
  assert.deepEqual(opts.disallowedTools, ["WebFetch"]);
  const events = sent.filter((m) => m.method === "turn.event").map((m) => m.params.event);
  assert.ok(events.some((e) => e.type === "turn_error" && /named sagebrush_page/.test(e.message)), JSON.stringify(events));
  assert.ok(!JSON.stringify(events).includes("SHOULD NOT"), "nothing after the init ran");
  server.close();
});

test("egress: a page that stops offering egress.turn after the card was shown can't answer allow_turn", async () => {
  const s = setup();
  const v = s.ask(WF, { url: "https://example.org/x" });
  await tick();
  s.binding.features = ["permission.digest"]; // (its page.features said so since)
  s.answer(s.cards[0], "allow_turn", s.digest(s.cards[0], s.cards[0].turn_action));
  assert.equal((await v).behavior, "deny");
  assert.equal(s.link.egress.origins.size, 0);
});

test("egress: a query never reaches any sink: the conversation's log, the page's messages, the agent's own log lines (S6)", async () => {
  const { default: WebSocket } = await import("ws");
  const logs = [];
  let seen;
  const server = new AgentServer({
    log: (m) => logs.push(String(m)),
    query: ({ prompt, options }) => (async function* () {
      yield { type: "system", subtype: "init", session_id: "s1", tools: [] };
      const i = 0;
      yield { type: "stream_event", parent_tool_use_id: null, event: { type: "content_block_start", index: i, content_block: { type: "tool_use", id: "toolu_1", name: WF, input: {} } } };
      yield { type: "stream_event", parent_tool_use_id: null, event: { type: "content_block_delta", index: i, delta: { type: "input_json_delta", partial_json: JSON.stringify({ url: "https://example.org/p?token=hunter2", reason: "token=hunter2" }) } } };
      yield { type: "stream_event", parent_tool_use_id: null, event: { type: "content_block_stop", index: i } };
      seen = await options.canUseTool(WF, { url: "https://example.org/p?token=hunter2", reason: "token=hunter2" }, { signal: options.abortController.signal });
      yield { type: "result", subtype: "success", is_error: false, result: "done", usage: { input_tokens: 1, output_tokens: 1 }, session_id: "s1" };
    })(),
  });
  server.createServer = fakeCreateServer;
  const port = await server.listen();
  const code = server.newCode();
  const ws = new WebSocket(`ws://127.0.0.1:${port}/sagebrush`, { origin: "https://agents.sagebrush.cloud" });
  const msgs = [];
  ws.on("message", (d) => {
    msgs.push(d.toString());
    const m = JSON.parse(d.toString());
    if (m.method === "turn.event" && m.params.event.type === "attention" && m.params.event.state === "open") ws.send(JSON.stringify({ jsonrpc: "2.0", method: "chat.permission", params: { request_id: m.params.event.request_id, behavior: "deny" } }));
  });
  await new Promise((r) => ws.on("open", r));
  ws.send(JSON.stringify({ jsonrpc: "2.0", id: "p1", method: "hello", params: { protocol: 1, page: { origin: "https://agents.sagebrush.cloud", path: "/agents/" }, code } }));
  await new Promise((r) => setTimeout(r, 100));
  ws.send(JSON.stringify({ jsonrpc: "2.0", method: "grant.changed", params: G1 }));
  ws.send(JSON.stringify({ jsonrpc: "2.0", method: "chat.message", params: { conversation: "c1", id: "u1", author: "person", text: "go" } }));
  for (let t = Date.now(); !msgs.some((m) => m.includes('"turn_finished"')) && Date.now() - t < 5000; ) await new Promise((r) => setTimeout(r, 20));
  assert.equal(seen?.behavior, "deny");
  assert.ok(msgs.some((m) => m.includes('"attention"')), "a card was shown");
  const sinks = { pageMessages: msgs.join("\n"), conversationLog: JSON.stringify(server.logs.since("c1", 0)), agentLog: logs.join("\n") };
  for (const [name, text] of Object.entries(sinks)) assert.ok(!text.includes("hunter2"), `${name} holds the query`);
  assert.ok(sinks.conversationLog.includes("https://example.org/p"), "the origin and path are there");
  ws.close();
  server.close();
});
