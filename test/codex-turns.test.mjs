// codex-turns.mjs, pure: Codex's notifications as the chat's events. An error's hint for the person; a retried error
// isn't the turn's; token usage adds up; a call announced twice is shown once; a command that exits nonzero is an
// error; a failed write is no artifact; nothing is fed after the turn's end.
import { test } from "node:test";
import assert from "node:assert/strict";
import { CodexTurn, HINTS } from "../lib/codex-turns.mjs";

const base = { threadId: "th", turnId: "tu" };
const turn = () => new CodexTurn("t1", () => 1000);

test("a failed turn's codexErrorInfo gives the person its hint", () => {
  const t = turn();
  const out = t.feed("turn/completed", { threadId: "th", turn: { id: "tu", status: "failed", error: { message: "raw words", codexErrorInfo: "usageLimitExceeded" } } });
  assert.deepEqual(out.find((e) => e.type === "turn_error"), { type: "turn_error", code: "usageLimitExceeded", message: HINTS.usageLimitExceeded });
});

test("an error Codex will retry isn't the turn's error; the last one it won't retry is", () => {
  const t = turn();
  t.feed("error", { ...base, willRetry: true, error: { message: "retrying", codexErrorInfo: "serverOverloaded" } });
  let out = t.feed("turn/completed", { threadId: "th", turn: { id: "tu", status: "failed", error: null } });
  assert.notEqual(out.find((e) => e.type === "turn_error").code, "serverOverloaded");
  const u = turn();
  u.feed("error", { ...base, willRetry: false, error: { message: "gone", codexErrorInfo: "serverOverloaded" } });
  out = u.feed("turn/completed", { threadId: "th", turn: { id: "tu", status: "failed", error: null } });
  assert.equal(out.find((e) => e.type === "turn_error").message, HINTS.serverOverloaded);
});

test("token usage adds up across updates", () => {
  const t = turn();
  for (const [i, o] of [[100, 10], [250, 40]]) t.feed("thread/tokenUsage/updated", { ...base, tokenUsage: { last: { inputTokens: i, outputTokens: o } } });
  const out = t.feed("turn/completed", { threadId: "th", turn: { id: "tu", status: "completed" } });
  assert.deepEqual(out.find((e) => e.type === "turn_usage").usage, { input_tokens: 350, output_tokens: 50 });
});

test("a call announced twice is shown once", () => {
  const t = turn();
  const item = { type: "commandExecution", id: "c1", command: "ls" };
  const a = t.feed("item/started", { ...base, item });
  const b = t.feed("item/started", { ...base, item });
  assert.equal(a.filter((e) => e.type === "tool_call_started").length, 1);
  assert.deepEqual(b, []);
});

test("a command that exits nonzero is an error, with its output", () => {
  const t = turn();
  const item = { type: "commandExecution", id: "c1", command: "false", status: "completed", exitCode: 1, aggregatedOutput: "nope\n", durationMs: 5 };
  const out = t.feed("item/completed", { ...base, item });
  assert.deepEqual(out.find((e) => e.type === "tool_call_finished"), { type: "tool_call_finished", call: "c1", status: "error", duration_ms: 5, body: "nope\n" });
  const ok = turn().feed("item/completed", { ...base, item: { ...item, exitCode: 0 } });
  assert.equal(ok.find((e) => e.type === "tool_call_finished").status, "ok");
});

test("a workspace write that failed is no artifact; one that worked is", () => {
  const item = (success) => ({ type: "dynamicToolCall", id: "d1", tool: "workspace_write", arguments: { path: "/notes/a.md", text: "# A" }, success, contentItems: [{ type: "inputText", text: success ? "{}" : "refused: no" }], durationMs: 1 });
  assert.equal(turn().feed("item/completed", { ...base, item: item(false) }).filter((e) => e.type === "artifact").length, 0);
  const art = turn().feed("item/completed", { ...base, item: item(true) }).find((e) => e.type === "artifact");
  assert.deepEqual(art, { type: "artifact", id: "/notes/a.md", kind: "markdown", title: "a.md", path: "/notes/a.md", body: "# A" });
});

test("nothing is fed after the turn's end", () => {
  const t = turn();
  t.feed("turn/completed", { threadId: "th", turn: { id: "tu", status: "completed" } });
  assert.deepEqual(t.feed("item/agentMessage/delta", { ...base, itemId: "m", delta: "late" }), []);
  assert.deepEqual(t.feed("item/started", { ...base, item: { type: "commandExecution", id: "c9", command: "ls" } }), []);
  assert.deepEqual(t.interrupted(), []);
  assert.deepEqual(t.failed("x"), []);
});
