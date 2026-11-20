// W3: turn_info, the model and thinking level a turn runs with, exactly as the backend reports them: Claude's model at
// the query's system/init and its effort in a hook's input (said again only if it changes; the hook decides nothing);
// Codex's both at thread start, said by the turn that started the thread. Only well-formed fields; none, no event;
// never copied from an earlier turn. Rows named "turn_info: …".
import assert from "node:assert/strict";
import { test } from "node:test";
import { fakeCreateServer } from "../lib/fake.mjs";
import { AgentServer } from "../lib/server.mjs";
import { turnInfo } from "../lib/turn-info.mjs";

test("turn_info: only the well-formed fields given, nothing else; none, null", () => {
  assert.deepEqual(turnInfo({ model: "claude-opus-5-5", effort: "high" }), { type: "turn_info", model: "claude-opus-5-5", effort: "high" });
  assert.deepEqual(turnInfo({ model: "gpt-5.1-codex" }), { type: "turn_info", model: "gpt-5.1-codex" });
  assert.deepEqual(turnInfo({ effort: "xhigh" }), { type: "turn_info", effort: "xhigh" });
  for (const bad of [{}, { model: "" }, { model: "a b" }, { model: "<b>" }, { model: 5 }, { effort: "High" }, { effort: "x".repeat(17) }, { effort: 3 }, { effort: null }])
    assert.equal(turnInfo(bad), null, JSON.stringify(bad));
  assert.deepEqual(turnInfo({ model: "ok-1", effort: "bad level" }), { type: "turn_info", model: "ok-1" }, "a bad field is left out, the good one kept");
  assert.deepEqual(Object.keys(turnInfo({ model: "m", effort: "low", extra: "x" })).sort(), ["effort", "model", "type"]);
  // (real ids with a context suffix or a provider's path are kept as given)
  for (const id of ["claude-opus-5-5[1m]", "us.anthropic.claude-sonnet-5-5-v1:0", "publishers/anthropic/models/claude-haiku-5-5@001"])
    assert.deepEqual(turnInfo({ model: id }), { type: "turn_info", model: id }, id);
  assert.equal(turnInfo({ model: "x".repeat(129) }), null);
});

// A Claude turn through runTurn with a scripted query: `script(options)` yields its messages (and may call its hooks).
async function claudeTurn(script) {
  let opts;
  const server = new AgentServer({ log: () => {}, query: ({ options }) => { opts = options; return script(options); } });
  server.createServer = fakeCreateServer;
  const sent = [];
  const ws = { readyState: 1, send: (s) => sent.push(JSON.parse(s)), room: () => true };
  server.sock = ws;
  server.binding = { ws, grant: { folders: ["/"], write: true, run: false, expires: null }, gen: 1, features: [] };
  await server.runTurn("c1", server.conversation("c1"), { id: "u1", text: "hi", scope: null }, server.binding);
  server.close();
  return { opts, events: sent.filter((m) => m.method === "turn.event").map((m) => m.params.event) };
}
const done = { type: "result", subtype: "success", is_error: false, result: "ok", usage: { input_tokens: 1, output_tokens: 1 }, session_id: "s1" };

test("turn_info: Claude's model at system/init, its effort from a hook's input, once, and again only when it changes; the hook returns no decision", async () => {
  const outs = [];
  const { opts, events } = await claudeTurn((options) => (async function* () {
    yield { type: "system", subtype: "init", session_id: "s1", model: "claude-opus-5-5", tools: [] };
    const pre = options.hooks.PreToolUse[0].hooks[0], stop = options.hooks.Stop[0].hooks[0];
    outs.push(await pre({ hook_event_name: "PreToolUse", effort: { level: "high" } }, "toolu_1", { signal: options.abortController.signal }));
    outs.push(await pre({ hook_event_name: "PreToolUse", effort: { level: "high" } }, "toolu_2", { signal: options.abortController.signal }));
    outs.push(await pre({ hook_event_name: "PreToolUse" }, "toolu_3", { signal: options.abortController.signal })); // (a model without effort)
    outs.push(await stop({ hook_event_name: "Stop", effort: { level: "low" } }, undefined, { signal: options.abortController.signal }));
    yield done;
  })());
  assert.deepEqual(Object.keys(opts.hooks).sort(), ["PreToolUse", "Stop"]);
  assert.ok(outs.every((o) => JSON.stringify(o) === "{}"), `every hook answers {} (no decision, no change): ${JSON.stringify(outs)}`);
  const infos = events.filter((e) => e.type === "turn_info");
  assert.deepEqual(infos, [{ type: "turn_info", model: "claude-opus-5-5" }, { type: "turn_info", effort: "high" }, { type: "turn_info", effort: "low" }]);
  assert.ok(events.findIndex((e) => e.type === "turn_started") < events.findIndex((e) => e.type === "turn_info"), "after turn_started");
});

test("turn_info: nothing reported, or nothing well-formed, means no turn_info at all", async () => {
  for (const init of [{}, { model: "not a model id" }, { model: 42 }]) {
    const { events } = await claudeTurn((options) => (async function* () {
      yield { type: "system", subtype: "init", session_id: "s1", tools: [], ...init };
      await options.hooks.Stop[0].hooks[0]({ hook_event_name: "Stop", effort: { level: "Very High" } }, undefined, { signal: options.abortController.signal });
      yield done;
    })());
    assert.equal(events.filter((e) => e.type === "turn_info").length, 0, JSON.stringify(init));
  }
});

test("turn_info: each turn says only what its own query reports (nothing carried over from the turn before)", async () => {
  let n = 0;
  const server = new AgentServer({ log: () => {}, query: ({ options }) => (async function* () {
    n++;
    yield { type: "system", subtype: "init", session_id: "s1", tools: [], ...(n === 1 ? { model: "claude-haiku-5-5" } : {}) };
    yield done;
  })() });
  server.createServer = fakeCreateServer;
  const sent = [];
  const ws = { readyState: 1, send: (s) => sent.push(JSON.parse(s)), room: () => true };
  server.sock = ws;
  server.binding = { ws, grant: { folders: ["/"], write: true, run: false, expires: null }, gen: 1, features: [] };
  const c = server.conversation("c1");
  await server.runTurn("c1", c, { id: "u1", text: "one", scope: null }, server.binding);
  await server.runTurn("c1", c, { id: "u2", text: "two", scope: null }, server.binding);
  server.close();
  const byTurn = new Map();
  for (const m of sent.filter((m) => m.method === "turn.event")) {
    const l = byTurn.get(m.params.turn_id) ?? [];
    l.push(m.params.event);
    byTurn.set(m.params.turn_id, l);
  }
  const [t1, t2] = [...byTurn.values()];
  assert.deepEqual(t1.filter((e) => e.type === "turn_info"), [{ type: "turn_info", model: "claude-haiku-5-5" }]);
  assert.deepEqual(t2.filter((e) => e.type === "turn_info"), [], "the second turn's query reported no model: none said");
});

test("turn_info: a hook from inside a subagent is not this turn's effort; a hook answered after the turn ended says nothing", async () => {
  let stop;
  const { events } = await claudeTurn((options) => (async function* () {
    yield { type: "system", subtype: "init", session_id: "s1", model: "claude-opus-5-5", tools: [] };
    const pre = options.hooks.PreToolUse[0].hooks[0];
    stop = options.hooks.Stop[0].hooks[0];
    await pre({ hook_event_name: "PreToolUse", agent_id: "sub-1", agent_type: "general-purpose", effort: { level: "low" } }, "toolu_s", { signal: options.abortController.signal });
    await pre({ hook_event_name: "PreToolUse", effort: { level: "high" } }, "toolu_1", { signal: options.abortController.signal });
    yield done;
  })());
  const before = events.filter((e) => e.type === "turn_info");
  assert.deepEqual(before, [{ type: "turn_info", model: "claude-opus-5-5" }, { type: "turn_info", effort: "high" }], "the subagent's effort is left out");
  // (the turn is over: a late Stop hook's answer adds nothing, and still decides nothing)
  const out = await stop({ hook_event_name: "Stop", effort: { level: "max" } }, undefined, { signal: new AbortController().signal });
  assert.deepEqual(out, {});
  assert.equal(events.filter((e) => e.type === "turn_info").length, 2, "nothing after the turn");
});

test("turn_info: with the hooks registered, every tool call still goes through canUseTool (a refused one is refused)", async () => {
  let decision;
  await claudeTurn((options) => (async function* () {
    yield { type: "system", subtype: "init", session_id: "s1", model: "claude-opus-5-5", tools: [] };
    const hookOut = await options.hooks.PreToolUse[0].hooks[0]({ hook_event_name: "PreToolUse", tool_name: "WebFetch", tool_input: { url: "https://example.org/" }, effort: { level: "high" } }, "toolu_1", { signal: options.abortController.signal });
    assert.deepEqual(hookOut, {}, "the hook gives no permission decision");
    decision = await options.canUseTool("WebFetch", { url: "https://example.org/", prompt: "x" }, { signal: options.abortController.signal });
    yield done;
  })());
  assert.equal(decision?.behavior, "deny", JSON.stringify(decision));
});
