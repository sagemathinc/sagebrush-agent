// The chat turn events a task records, conformed to the page's bounds (lib/turn-bounds.mjs). The table below is a copy
// of the page's own (web/workspace/tasks-schema.ts, TURN and its helpers: the protocol §6.1 table): every conformed
// event must pass a re-implementation of the page's check, and the host's own (tasks.mjs eventProblem).
import assert from "node:assert/strict";
import { test } from "node:test";
import { conformTurnEvent, cut, pageId, split } from "../lib/turn-bounds.mjs";
import { eventProblem } from "../lib/tasks.mjs";

// ---- the page's check, re-implemented from web/workspace/tasks-schema.ts
const SHORT = 400, ID = 128, BIG = 4 * 2 ** 20, TEXT = 192 * 1024;
const NOT_WELL = /\u0000|[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/;
const T = (max) => (v) => typeof v === "string" && Buffer.byteLength(v) <= max && !NOT_WELL.test(v);
const I = (v) => typeof v === "string" && v.length >= 1 && v.length <= ID && /^[\x21-\x7e]+$/.test(v);
const N = (v) => Number.isSafeInteger(v) && v >= 0;
const oneOf = (set) => (v) => set.includes(v);
const PAGE_TURN = {
  turn_started: [{}, {}],
  turn_state: [{ state: T(SHORT) }, {}],
  message_revised: [{ message: I, revision: N }, {}],
  text_delta: [{ message: I, revision: N, text: T(TEXT) }, {}],
  message_truncated: [{ message: I, revision: N }, {}],
  thinking_delta: [{ text: T(TEXT) }, {}],
  tool_call_started: [{ call: I, tool: T(SHORT) }, { name: T(SHORT), summary: T(SHORT) }],
  tool_output: [{ call: I, text: T(TEXT) }, {}],
  tool_call_finished: [{ call: I, status: T(SHORT), duration_ms: N }, { summary: T(SHORT), body: T(BIG), body_cut: (v) => v === true, diff: () => true }],
  attention: [{ id: I, kind: T(SHORT), state: oneOf(["open", "approved", "denied"]), title: T(SHORT) }, { summary: T(SHORT), detail: T(64 * 1024), instance: I }],
  artifact: [{ id: I, kind: oneOf(["markdown", "code", "diff", "notebook", "board"]), title: T(SHORT), body: T(BIG) }, { lang: T(64), path: T(1024) }],
  turn_usage: [{ usage: (v) => !!v && N(v.input_tokens) && N(v.output_tokens) && Object.keys(v).length === 2 }, {}],
  turn_info: [{}, { model: T(SHORT), effort: T(64) }],
  turn_error: [{ code: T(64), message: T(64 * 1024) }, {}],
  turn_finished: [{ outcome: oneOf(["completed", "interrupted", "error"]) }, { code: T(64) }],
};
function pageAccepts(e) {
  const k = PAGE_TURN[e.type];
  if (!k) return false;
  const [req, opt] = k;
  for (const key of Object.keys(e)) if (key !== "type" && !(key in req) && !(key in opt) && key !== "turn_id") return false;
  for (const [key, f] of Object.entries(req)) if (!(key in e) || !f(e[key])) return false;
  for (const [key, f] of Object.entries(opt)) if (key in e && !f(e[key])) return false;
  return e.turn_id === undefined || I(e.turn_id);
}

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
