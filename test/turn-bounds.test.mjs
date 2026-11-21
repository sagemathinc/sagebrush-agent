// The chat turn events a task records, conformed to the page's bounds (lib/turn-bounds.mjs). The table below is a copy
// of the page's own (web/workspace/tasks-schema.ts, TURN and its helpers: the protocol §6.1 table): every conformed
// event must pass a re-implementation of the page's check, and the host's own (tasks.mjs eventProblem).
import assert from "node:assert/strict";
import { test } from "node:test";
import { conformTurnEvent, cut, pageId, split } from "../lib/turn-bounds.mjs";
import { eventProblem } from "../lib/tasks.mjs";

// ---- the page's check, ported line for line from web/workspace/tasks-schema.ts (TURN, turnEvent and their helpers:
// keys, isObj, text, wellFormed, idStr, oneOf, int); each refusal throws, as the page's TaskShapeError does
const bad = (m) => { throw new Error(m); };
const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v) && Object.getPrototypeOf(v) === Object.prototype;
function keys(v, want, what, optional = []) {
  if (!isObj(v)) return bad(`${what} isn't an object`);
  for (const k of Object.keys(v)) if (!want.includes(k) && !optional.includes(k)) bad(`${what}: unknown field ${JSON.stringify(k.slice(0, 40))}`);
  for (const k of want) if (!Object.hasOwn(v, k)) bad(`${what}: missing ${k}`);
  return v;
}
const LONE_SURROGATE = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/;
const wellFormed = (v, what) => (LONE_SURROGATE.test(v) || v.includes("\u0000") ? bad(`${what} isn't well-formed text`) : v);
const text = (v, max, what) => (typeof v === "string" && Buffer.byteLength(v) <= max ? wellFormed(v, what) : bad(`${what} isn't text of at most ${max} bytes`));
const int = (v, min, what) => (typeof v === "number" && Number.isSafeInteger(v) && v >= min ? v : bad(`${what} isn't an integer of at least ${min}`));
const SHORT = 400, ID = 128, BIG = 4 * 2 ** 20, TEXT = 192 * 1024;
const idStr = (v, what) => (typeof v === "string" && v.length >= 1 && v.length <= ID && /^[\x21-\x7e]+$/.test(v) ? v : bad(`${what} isn't an id`));
const oneOf = (v, set, what) => (set.includes(v) ? v : bad(`${what} isn't one of ${set.join(", ")}`));
const T = (max) => (v, what) => text(v, max, what);
const N = (v, what) => int(v, 0, what);
const I = idStr;
const PAGE_TURN = {
  turn_started: [{}, {}],
  turn_state: [{ state: T(SHORT) }, {}],
  message_revised: [{ message: I, revision: N }, {}],
  text_delta: [{ message: I, revision: N, text: T(TEXT) }, {}],
  message_truncated: [{ message: I, revision: N }, {}],
  thinking_delta: [{ text: T(TEXT) }, {}],
  tool_call_started: [{ call: I, tool: T(SHORT) }, { name: T(SHORT), summary: T(SHORT) }],
  tool_output: [{ call: I, text: T(TEXT) }, {}],
  tool_call_finished: [
    { call: I, status: T(SHORT), duration_ms: N },
    {
      summary: T(SHORT), body: T(BIG), body_cut: (v, w) => (v === true ? v : bad(`${w} isn't true`)),
      diff: (v, w) => { const o = keys(v, ["path", "before", "after"], w); return { path: text(o.path, 1024, `${w}.path`), before: text(o.before, BIG, `${w}.before`), after: text(o.after, BIG, `${w}.after`) }; },
    },
  ],
  attention: [{ id: I, kind: T(SHORT), state: (v, w) => oneOf(v, ["open", "approved", "denied"], w), title: T(SHORT) }, { summary: T(SHORT), detail: T(64 * 1024), instance: I }],
  artifact: [{ id: I, kind: (v, w) => oneOf(v, ["markdown", "code", "diff", "notebook", "board"], w), title: T(SHORT), body: T(BIG) }, { lang: T(64), path: T(1024) }],
  turn_usage: [{ usage: (v, w) => { const o = keys(v, ["input_tokens", "output_tokens"], w); return { input_tokens: int(o.input_tokens, 0, `${w}.input_tokens`), output_tokens: int(o.output_tokens, 0, `${w}.output_tokens`) }; } }, {}],
  turn_info: [{}, { model: T(SHORT), effort: T(64) }],
  turn_error: [{ code: T(64), message: T(64 * 1024) }, {}],
  turn_finished: [{ outcome: (v, w) => oneOf(v, ["completed", "interrupted", "error"], w) }, { code: T(64) }],
};
function turnEvent(v, what) {
  const [req, opt] = PAGE_TURN[v.type];
  const o = keys(v, ["type", ...Object.keys(req)], what, [...Object.keys(opt), "turn_id"]);
  const out = { type: o.type };
  for (const [k, f] of Object.entries(req)) out[k] = f(o[k], `${what}.${k}`);
  for (const [k, f] of Object.entries(opt)) if (o[k] !== undefined) out[k] = f(o[k], `${what}.${k}`);
  if (o.turn_id !== undefined) out.turn_id = idStr(o.turn_id, `${what}.turn_id`);
  return out;
}
const pageAccepts = (e) => { if (!isObj(e) || !Object.hasOwn(PAGE_TURN, e.type)) return false; try { turnEvent(e, "event"); return true; } catch { return false; } };

test("the copied check is the page's own, not a looser one: a tool call's diff is a closed {path, before, after} of bounded, well-formed text; usage is a closed pair", () => {
  const fin = (diff) => ({ type: "tool_call_finished", call: "c1", status: "ok", duration_ms: 1, diff });
  for (const diff of [null, "oops", {}, { path: "p", before: "a", after: "b", extra: true }, { path: "p", before: "a" }, { path: "p", before: "a", after: 42 }, { path: "p\u0000", before: "a", after: "b" }]) {
    assert.equal(pageAccepts(fin(diff)), false, JSON.stringify(diff));
  }
  assert.equal(pageAccepts(fin({ path: "p", before: "a", after: "b" })), true);
  assert.equal(pageAccepts({ type: "turn_usage", usage: { input_tokens: 1, output_tokens: 2, extra: 3 } }), false);
  assert.equal(pageAccepts({ type: "turn_usage", usage: Object.create({ input_tokens: 1, output_tokens: 2 }) }), false);
  assert.equal(pageAccepts({ type: "turn_usage", usage: { input_tokens: 1, output_tokens: 2 } }), true);
});

const long = (n, ch = "é") => ch.repeat(n);
const wide = "日本語".repeat(70000); // (3-byte characters: about 615 KB)

test("every event over the page's bounds is made to fit, and passes both the page's check and the host's", () => {
  const drafts = [
    { type: "message_revised", message: "m".repeat(150), revision: 1 },
    { type: "text_delta", message: "msg with spaces", revision: 2, text: wide },
    { type: "thinking_delta", text: long(200 * 1024) },
    { type: "tool_call_started", call: "callé-not-ascii", tool: "workspace_read", name: "workspace_read", summary: long(3000) },
    { type: "tool_call_started", call: "c2", tool: "t".repeat(60), name: long(300) },
    { type: "turn_error", code: "x", message: long(5000) },
    { type: "tool_call_finished", call: "c".repeat(200), status: "ok", duration_ms: 5, body: "x" },
    { type: "turn_error", code: "e".repeat(150), message: "it broke" },
    { type: "turn_finished", outcome: "error", code: long(100) },
    { type: "artifact", id: "a".repeat(600), kind: "markdown", title: long(900), path: "notes/a.md", body: "# hi", lang: "markdown-long-language-name-that-goes-past-sixty-four-bytes-easily" },
  ];
  for (const d of drafts) {
    const out = conformTurnEvent(d);
    assert.ok(out.length >= 1, d.type);
    for (const e of out) {
      assert.ok(pageAccepts(e), `the page refuses ${d.type}: ${JSON.stringify(e).slice(0, 300)}`);
      assert.equal(eventProblem(e), null, `the host refuses ${d.type}`);
    }
  }
});

test("nothing lost where it can be kept: long deltas split at character boundaries and join back; a cut ends in \"…\" within the bound", () => {
  const out = conformTurnEvent({ type: "text_delta", message: "m1", revision: 3, text: wide });
  assert.ok(out.length > 1);
  assert.equal(out.map((e) => e.text).join(""), wide);
  assert.ok(out.every((e) => Buffer.byteLength(e.text) <= TEXT && e.message === "m1" && e.revision === 3));
  assert.deepEqual(split("ab", 1), ["a", "b"]);
  assert.equal(split("é".repeat(3), 3).join(""), "ééé");
  const c = cut(long(500), SHORT);
  assert.ok(Buffer.byteLength(c) <= SHORT && c.endsWith("…"));
  assert.equal(cut("short", SHORT), "short");
  // (a text that fits is one delta, as it was)
  assert.deepEqual(conformTurnEvent({ type: "thinking_delta", text: "hm" }), [{ type: "thinking_delta", text: "hm" }]);
});

test("ids: kept when they are the page's kind; else the same stable id for the same original, so a message's deltas and revisions still match", () => {
  assert.equal(pageId("toolu_01ABC"), "toolu_01ABC");
  const a = pageId("message with spaces"), b = pageId("message with spaces");
  assert.equal(a, b);
  assert.match(a, /^h[0-9a-f]{32}$/);
  assert.notEqual(pageId("x".repeat(129)), pageId("x".repeat(130)));
  const [rev] = conformTurnEvent({ type: "message_revised", message: "message with spaces", revision: 1 });
  const [delta] = conformTurnEvent({ type: "text_delta", message: "message with spaces", revision: 1, text: "hi" });
  assert.equal(rev.message, delta.message);
});

test("an artifact of a kind the page doesn't show is not recorded, and the agent's log says so", () => {
  const logged = [];
  assert.deepEqual(conformTurnEvent({ type: "artifact", id: "a1", kind: "spreadsheet", title: "t", path: "p", body: "b" }, (m) => logged.push(m)), []);
  assert.match(logged[0], /"spreadsheet" isn't one the page shows: not recorded/);
});

test("a task's turn records its events conformed: a tool call whose id the page wouldn't take is recorded under its stable id", async () => {
  const { mkdtempSync, rmSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const { TaskStore } = await import("../lib/tasks.mjs");
  const { TaskTurns, TASK_SERVER } = await import("../lib/task-turns.mjs");
  const { checkRequest } = await import("../lib/tasks-schema.mjs");
  const { fakeCreateServer } = await import("../lib/fake.mjs");
  const dir = mkdtempSync(join(tmpdir(), "sb-bounds-"));
  try {
    const store = new TaskStore({ root: join(dir, "tasks"), scope: "install-1" }).init();
    const task = store.start(checkRequest("tasks.start", { title: "t", prompt: "p", target: "local", run: false, docs: [{ path: "a.txt", kind: "file", content: "x" }] })).task;
    const odd = "call id with spaces";
    const query = ({ options }) => (async function* () {
      yield { type: "system", subtype: "init", session_id: "s", tools: [], mcp_servers: [] };
      yield { type: "stream_event", parent_tool_use_id: null, event: { type: "content_block_start", index: 0, content_block: { type: "tool_use", id: odd, name: `mcp__${TASK_SERVER}__workspace_list`, input: {} } } };
      yield { type: "stream_event", parent_tool_use_id: null, event: { type: "content_block_stop", index: 0 } };
      await options.mcpServers[TASK_SERVER].handlers.propose({ summary: "done" });
      yield { type: "result", subtype: "success", is_error: false, result: "ok", usage: {} };
    })();
    const turns = new TaskTurns({ store, query, createServer: fakeCreateServer, free: () => 1e12 });
    turns.begin(task, "start");
    const t0 = Date.now();
    while (store.state(task).status !== "proposal" && Date.now() - t0 < 10000) await new Promise((r) => setTimeout(r, 10));
    const events = store.get({ task, after: 0 }).events.map((e) => e.event);
    const started = events.filter((e) => e.type === "tool_call_started");
    assert.ok(started.length >= 1, JSON.stringify(events.map((e) => e.type)));
    assert.equal(started[0].call, pageId(odd));
    for (const e of events.filter((e) => e.type in PAGE_TURN)) assert.ok(pageAccepts(e), JSON.stringify(e).slice(0, 200));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
