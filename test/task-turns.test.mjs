// A Delegate task's turns (lib/task-turns.mjs): Claude working on the task's own copy with no page, its tools over
// work/ only, through the store; scripted with a fake model that calls the real tool handlers, as the SDK would.
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { TaskStore } from "../lib/tasks.mjs";
import { TaskTurns, TASK_SERVER } from "../lib/task-turns.mjs";
import { checkRequest } from "../lib/tasks-schema.mjs";
import { fakeCreateServer } from "../lib/fake.mjs";

const NB = JSON.stringify({ cells: [{ cell_type: "code", id: "a", metadata: {}, source: "x = 1", outputs: [], execution_count: null }], metadata: {}, nbformat: 4, nbformat_minor: 5 });
const until = async (f, what, ms = 10000) => { const t = Date.now(); while (!f()) { if (Date.now() - t > ms) throw new Error(`timed out: ${what}`); await new Promise((r) => setTimeout(r, 5)); } };

// A fake model: each step is [tool, input] (called through the task server's real handler, with the SDK's message
// shapes around it), or a function (awaited: the test's hook); then a successful result.  Every call's options are kept.
function scripted(steps, seen = []) {
  return ({ prompt, options }) => {
    seen.push({ prompt, options });
    const tools = options.mcpServers[TASK_SERVER].handlers;
    let k = 0;
    return (async function* () {
      yield { type: "system", subtype: "init", session_id: "fake-session", tools: [], mcp_servers: [] };
      for (const step of steps) {
        if (typeof step === "function") { await step(options); continue; }
        const [name, input] = step, id = `toolu_${k}`, i = k++;
        const allowed = await options.canUseTool(`mcp__${TASK_SERVER}__${name}`, input, {});
        yield { type: "stream_event", parent_tool_use_id: null, event: { type: "content_block_start", index: i, content_block: { type: "tool_use", id, name: `mcp__${TASK_SERVER}__${name}`, input: {} } } };
        yield { type: "stream_event", parent_tool_use_id: null, event: { type: "content_block_delta", index: i, delta: { type: "input_json_delta", partial_json: JSON.stringify(input) } } };
        yield { type: "stream_event", parent_tool_use_id: null, event: { type: "content_block_stop", index: i } };
        const r = allowed.behavior === "allow" ? await tools[name](input) : { content: [{ type: "text", text: allowed.message }], isError: true };
        yield { type: "user", parent_tool_use_id: null, message: { role: "user", content: [{ type: "tool_result", tool_use_id: id, content: r.content, is_error: !!r.isError }] } };
      }
      yield { type: "result", subtype: "success", is_error: false, result: "ok", usage: { input_tokens: 1, output_tokens: 1 } };
    })();
  };
}
function setup({ steps, limits } = {}) {
  const dir = mkdtempSync(join(tmpdir(), "sb-turns-"));
  const store = new TaskStore({ root: join(dir, "tasks"), scope: "install-1" }).init();
  const seen = [];
  const turns = new TaskTurns({ store, query: scripted(steps ?? [], seen), createServer: fakeCreateServer, ...(limits ? { limits } : {}) });
  const start = () => store.start(checkRequest("tasks.start", { title: "Make x two", prompt: "x should be 2", target: "local", run: false, docs: [{ path: "a.ipynb", kind: "notebook", content: NB }] })).task;
  const types = (task) => store.get({ task, after: 0 }).events.map((e) => e.event.type);
  return { dir, store, turns, seen, start, types, done: () => rmSync(dir, { recursive: true, force: true }) };
}

test("a turn edits the task's copy and proposes: the round's diff, the turn's events, and the task in proposal", async () => {
  const h = setup({ steps: [["workspace_read", { path: "a.ipynb" }], ["workspace_write_notebook", { path: "a.ipynb", mode: "python", cells: [{ type: "code", source: "x = 2" }] }], ["propose", { summary: "x is two" }]] });
  const task = h.start();
  h.turns.begin(task, "start");
  await until(() => h.store.state(task).status === "proposal", "the proposal");
  await until(() => !h.turns.isRunning(task), "the turn over");
  const t = h.store.state(task);
  const d = h.store.diff({ task, commit: t.proposals[0] });
  assert.deepEqual(d.files.map((f) => [f.path, f.change]), [["a.ipynb", "modified"]]);
  assert.match(JSON.parse(h.store.file({ task, commit: t.proposals[0], path: "a.ipynb" }).content).cells[0].source, /x = 2/);
  const ty = h.types(task);
  assert.ok(ty.includes("turn_started") && ty.includes("tool_call_started") && ty.includes("tool_call_finished") && ty.includes("proposal"), ty.join(","));
  assert.equal(ty.at(-1), "task_status");
  h.done();
});

test("the SDK runs with no settings, no native tools, only the task's server, in the task's own sdk folder; other tools are refused", async () => {
  const h = setup({ steps: [async (o) => {
    const deny = await o.canUseTool("Bash", { command: "id" }, {});
    const page = await o.canUseTool("mcp__sagebrush_page__workspace_write", {}, {});
    assert.equal(deny.behavior, "deny");
    assert.equal(page.behavior, "deny");
  }, ["propose", { summary: "s" }]] });
  const task = h.start();
  h.turns.begin(task, "start");
  await until(() => h.store.state(task).status === "proposal", "the proposal");
  const o = h.seen[0].options;
  assert.deepEqual(o.settingSources, []);
  assert.deepEqual(o.tools, []);
  assert.equal(o.strictMcpConfig, true);
  assert.deepEqual(Object.keys(o.mcpServers), [TASK_SERVER]);
  assert.equal(o.hooks, undefined);
  assert.equal(o.cwd, join(h.store.dir(task), "sdk"));
  assert.ok(existsSync(o.cwd));
  h.done();
});

test("a turn that ends without proposing leaves the task interrupted, saying why; only a Resume goes on", async () => {
  const h = setup({ steps: [["workspace_list", {}]] });
  const task = h.start();
  h.turns.begin(task, "start");
  await until(() => h.store.state(task).status === "interrupted", "interrupted");
  assert.match(h.store.state(task).reason, /ended without a proposal/);
  h.done();
});

test("the tools stay in the copy and its rules: running code is refused for now; bad paths and .git are refused; nothing outside changes", async () => {
  const results = [];
  const h = setup({ steps: [
    ["notebook_run", { path: "a.ipynb" }],
    ["workspace_write", { path: ".git/config", text: "x" }],
    ["workspace_write", { path: "../escape.txt", text: "x" }],
    ["workspace_write", { path: "CON.txt", text: "x" }],
    ["workspace_write", { path: "A.IPYNB", text: "{}" }],
    ["workspace_write", { path: "b.ipynb", text: "not a notebook" }],
    ["workspace_read", { path: "../tasks.json" }],
    async () => {},
  ] });
  const task = h.start();
  h.turns.begin(task, "start");
  await until(() => h.store.state(task).status === "interrupted", "the turn over");
  const finished = h.store.get({ task, after: 0 }).events.filter((e) => e.event.type === "tool_call_finished").map((e) => [e.event.status, e.event.body]);
  assert.equal(finished.length, 7);
  for (const [status, body] of finished) assert.equal(status, "error", body);
  assert.match(finished[0][1], /running code isn't available/);
  assert.ok(!existsSync(join(h.dir, "tasks", "escape.txt")));
  h.done();
});

test("stop: a running turn ends at once, interrupted; at most `running` turns at once, the next waits its turn", async () => {
  let release;
  const gate = new Promise((r) => (release = r));
  const h = setup({ steps: [async () => { await gate; }, ["propose", { summary: "s" }]], limits: { running: 1, queued: 1, turnMs: 60000, readBytes: 1024 } });
  const a = h.start(), b = h.start(), c = h.start();
  h.turns.begin(a, "start");
  assert.deepEqual(h.turns.begin(b, "start"), { queued: true });
  assert.throws(() => h.turns.begin(c, "start"), (e) => e.code === "busy");
  await until(() => h.turns.isRunning(a), "a running");
  assert.ok(!h.turns.isRunning(b));
  const stopping = h.turns.stop(a);
  release();
  await stopping;
  await until(() => h.store.state(a).status === "interrupted", "a interrupted");
  await until(() => h.store.state(b).status === "proposal", "b ran after a");
  h.done();
});

test("a stop is bounded: a model that ignores the abort can't hold it; the task is still stopped", async () => {
  const h = setup({ steps: [async () => { await new Promise(() => {}); }], limits: { running: 4, queued: 16, turnMs: 60000, readBytes: 1024, stopMs: 200 } });
  const task = h.start();
  h.turns.begin(task, "start");
  await until(() => h.turns.isRunning(task), "running");
  const t0 = Date.now();
  await h.turns.stop(task);
  assert.ok(Date.now() - t0 < 2000);
  assert.deepEqual(await h.store.stop({ task }), { status: "interrupted" });
  h.done();
});

test("the installation id: made once, private, kept; a file that isn't one is refused", async () => {
  const { installationId } = await import("../lib/installation.mjs");
  const home = mkdtempSync(join(tmpdir(), "sb-inst-"));
  const a = installationId(home), b = installationId(home);
  assert.match(a, /^[0-9a-f]{32}$/);
  assert.equal(a, b);
  const { writeFileSync, statSync } = await import("node:fs");
  assert.equal(statSync(join(home, ".sagebrush")).mode & 0o077, 0);
  writeFileSync(join(home, ".sagebrush", "installation"), "not an id\n");
  assert.throws(() => installationId(home));
  rmSync(home, { recursive: true, force: true });
});
