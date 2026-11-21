// Delegate tasks on the pairing (server.mjs + task-rpc.mjs): a fake page over a real loopback WebSocket asks the
// agent by id (§6.1), the task's turn runs with no page at all (a scripted model), and the switch is checked on
// every call.  No Anthropic calls.
import assert from "node:assert/strict";
import { test } from "node:test";
import WebSocket from "ws";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fakeCreateServer, fakeQuery } from "../lib/fake.mjs";
import { AgentServer } from "../lib/server.mjs";
import { TaskStore } from "../lib/tasks.mjs";
import { TaskTurns, TASK_SERVER } from "../lib/task-turns.mjs";
import { TaskRpc } from "../lib/task-rpc.mjs";

const ORIGIN = "https://agents.sagebrush.cloud";
const NB = JSON.stringify({ cells: [{ cell_type: "code", id: "a", metadata: {}, source: "x = 1", outputs: [], execution_count: null }], metadata: {}, nbformat: 4, nbformat_minor: 5 });
const until = async (f, what = "", ms = 10000) => { const t = Date.now(); while (!f()) { if (Date.now() - t > ms) throw new Error(`timed out ${what}`); await new Promise((r) => setTimeout(r, 10)); } };

// (the task's model: waits for `gate` if given, then writes the notebook and proposes)
function taskModel(gate) {
  return ({ options }) => {
    const tools = options.mcpServers[TASK_SERVER].handlers;
    return (async function* () {
      yield { type: "system", subtype: "init", session_id: "fake-task", tools: [], mcp_servers: [] };
      // (the gate, or the turn's abort, as the SDK heeds it)
      if (gate) await Promise.race([gate, new Promise((r) => options.abortController.signal.addEventListener("abort", r, { once: true }))]);
      if (options.abortController.signal.aborted) return;
      await tools.workspace_write_notebook({ path: "a.ipynb", mode: "python", cells: [{ type: "code", source: "x = 2" }] });
      await tools.propose({ summary: "x is two" });
      yield { type: "result", subtype: "success", is_error: false, result: "ok", usage: {} };
    })();
  };
}

async function setup({ gate } = {}) {
  const dir = mkdtempSync(join(tmpdir(), "sb-tsrv-"));
  const server = new AgentServer({ query: fakeQuery, log: () => {} });
  server.createServer = fakeCreateServer;
  const store = new TaskStore({ root: join(dir, "tasks"), scope: "install-1" }).init();
  const turns = new TaskTurns({ store, query: taskModel(gate), createServer: fakeCreateServer });
  server.setTasks({ store, turns, rpc: new TaskRpc({ store, turns }) });
  const port = await server.listen();
  return { dir, server, store, turns, port, code: server.newCode() };
}
function page(port) {
  const ws = new WebSocket(`ws://127.0.0.1:${port}/sagebrush`, { origin: ORIGIN });
  const answers = new Map(), events = [], answersNull = [];
  let n = 1;
  ws.on("message", (d) => {
    const m = JSON.parse(d.toString());
    if (m.method === "task.event") return events.push(m.params);
    if (typeof m.id === "string" && ("result" in m || "error" in m)) answers.get(m.id)?.(m);
    if (m.id === null && "error" in m) answersNull.shift()?.(m);
  });
  const call = (method, params, id = `p${++n}`) => new Promise((resolve) => { answers.set(id, resolve); ws.send(JSON.stringify({ jsonrpc: "2.0", id, method, params })); });
  const hello = (code) => call("hello", { protocol: 1, page: { origin: ORIGIN, path: "/agents/" }, code }, "p1");
  const notify = (method, params) => ws.send(JSON.stringify({ jsonrpc: "2.0", method, params }));
  const open = new Promise((resolve, reject) => { ws.on("open", resolve); ws.on("error", reject); });
  return { ws, call, hello, notify, open, events, answersNull };
}
const START = { title: "Make x two", prompt: "x should be 2", target: "local", run: false, docs: [{ path: "a.ipynb", kind: "notebook", content: NB }] };
const code = (a) => a.error?.data?.code;

test("the hello offers delegate.1 over the loopback; without the Delegate switch every tasks request is refused forbidden", async () => {
  const h = await setup();
  const p = page(h.port);
  await p.open;
  const hello = await p.hello(h.code);
  assert.ok(hello.result.features.includes("delegate.1"));
  assert.equal(code(await p.call("tasks.list", {})), "forbidden", "no grant yet");
  p.notify("grant.changed", { folders: ["/"], write: true });
  await new Promise((r) => setTimeout(r, 50));
  assert.equal(code(await p.call("tasks.list", {})), "forbidden", "a Pair grant isn't the Delegate switch");
  p.notify("grant.changed", { folders: ["/"], write: true, delegate: true });
  await new Promise((r) => setTimeout(r, 50));
  assert.deepEqual((await p.call("tasks.list", {})).result, { tasks: [] });
  // (an id that isn't p<n>: refused, answered with id null, since it can't be the page's own)
  const nullAnswer = new Promise((resolve) => p.answersNull.push(resolve));
  p.ws.send(JSON.stringify({ jsonrpc: "2.0", id: "x7", method: "tasks.list", params: {} }));
  assert.equal(code(await nullAnswer), "bad_request");
  assert.equal(code(await p.call("tasks.nope", {})), "bad_request");
  p.ws.close();
  await h.server.close();
  rmSync(h.dir, { recursive: true, force: true });
});

test("a task runs with no page: start, close the page, the proposal arrives meanwhile, a new page reads it and merges", async () => {
  let release;
  const gate = new Promise((r) => (release = r));
  const h = await setup({ gate });
  let p = page(h.port);
  await p.open;
  await p.hello(h.code);
  p.notify("grant.changed", { folders: ["/"], write: true, delegate: true });
  await new Promise((r) => setTimeout(r, 50));
  const s = await p.call("tasks.start", START);
  const task = s.result.task;
  // (the page goes away while the turn waits: nothing stops)
  p.ws.close();
  await until(() => !h.server.sock, "the page gone");
  release();
  await until(() => h.store.state(task).status === "proposal", "the proposal, with no page");
  // (a page again, with a new code)
  p = page(h.port);
  await p.open;
  await p.hello(h.server.newCode());
  p.notify("grant.changed", { folders: ["/"], write: true, delegate: true });
  await new Promise((r) => setTimeout(r, 50));
  const got = await p.call("tasks.get", { task, after: 0 });
  const prop = got.result.events.find((e) => e.event.type === "proposal").event;
  const d = await p.call("tasks.diff", { task, commit: prop.commit });
  assert.deepEqual(d.result.files.map((f) => f.change), ["modified"]);
  const f = await p.call("tasks.file", { task, commit: prop.commit, path: "a.ipynb" });
  assert.match(f.result.content, /x = 2/);
  const { blobId } = await import("../lib/task-git.mjs");
  const m = await p.call("tasks.merged", { task, proposal: prop.commit, seq: got.result.task.seq, merge_id: "1".repeat(32), files: [{ path: "a.ipynb", kind: "notebook", proposal_blob: f.result.blob, mine: { blob: blobId(Buffer.from(NB)), content: NB }, merged: { blob: f.result.blob, content: f.result.content } }] });
  assert.equal(m.result.recorded, "merge");
  p.ws.close();
  await h.server.close();
  rmSync(h.dir, { recursive: true, force: true });
});

test("turning the Delegate switch off: the capability goes at once, the running turn stops, its task is interrupted (not closed)", async () => {
  const h = await setup({ gate: new Promise(() => {}) });
  const p = page(h.port);
  await p.open;
  await p.hello(h.code);
  p.notify("grant.changed", { folders: ["/"], write: true, delegate: true });
  await new Promise((r) => setTimeout(r, 50));
  const task = (await p.call("tasks.start", START)).result.task;
  await until(() => h.turns.isRunning(task), "running");
  p.notify("grant.changed", { folders: ["/"], write: true });
  await until(() => h.store.state(task).status === "interrupted", "interrupted");
  assert.match(h.store.state(task).reason, /switch was turned off|turn was stopped/);
  assert.equal(code(await p.call("tasks.list", {})), "forbidden");
  p.ws.close();
  await h.server.close();
  rmSync(h.dir, { recursive: true, force: true });
});

test("task.event goes only to a page holding the switch; stop and revoke act on the turn and the task", async () => {
  const h = await setup({ gate: new Promise(() => {}) });
  const p = page(h.port);
  await p.open;
  await p.hello(h.code);
  p.notify("grant.changed", { folders: ["/"], write: true, delegate: true });
  await new Promise((r) => setTimeout(r, 50));
  const a = (await p.call("tasks.start", START)).result.task;
  await until(() => p.events.some((e) => e.task === a && e.event.type === "turn_started"), "turn events to the page");
  assert.deepEqual((await p.call("tasks.stop", { task: a })).result, { status: "interrupted" });
  assert.ok(!h.turns.isRunning(a));
  assert.deepEqual((await p.call("tasks.revoke", { task: a })).result, { status: "closed" });
  assert.equal(code(await p.call("tasks.resume", { task: a })), "final");
  p.ws.close();
  await h.server.close();
  rmSync(h.dir, { recursive: true, force: true });
});

test("over the runner's stdio there are no tasks: no delegate.1, and requests are refused unavailable", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sb-tsrv-"));
  const server = new AgentServer({ query: fakeQuery, log: () => {}, stdio: true });
  const store = new TaskStore({ root: join(dir, "tasks"), scope: "install-1" }).init();
  const turns = new TaskTurns({ store, query: taskModel(), createServer: fakeCreateServer });
  server.setTasks({ store, turns, rpc: new TaskRpc({ store, turns }) });
  assert.ok(!server.features().includes("delegate.1"));
  rmSync(dir, { recursive: true, force: true });
});

test("a failure of the task host that isn't a refusal: answered unavailable, its detail only in the agent's log", async () => {
  const h = await setup();
  const logged = [];
  h.server.log = (m) => logged.push(m);
  h.server.tasks.rpc.call = async () => { throw new Error("EIO: i/o error, open '/home/someone/.sagebrush/tasks/x/task.json'"); };
  const p = page(h.port);
  await p.open;
  await p.hello(h.code);
  p.notify("grant.changed", { folders: ["/"], write: true, delegate: true });
  await new Promise((r) => setTimeout(r, 50));
  const a = await p.call("tasks.list", {});
  assert.equal(code(a), "unavailable");
  assert.doesNotMatch(a.error.message, /EIO|\/home/);
  assert.ok(logged.some((m) => /EIO/.test(m)));
  p.ws.close();
  await h.server.close();
  rmSync(h.dir, { recursive: true, force: true });
});

test("the switch off after a reconnect: a new page's grant without delegate stops the old task's turn at once, and its model's late work is refused; a disconnect alone changes nothing", async () => {
  let release;
  const gate = new Promise((r) => (release = r));
  const h = await setup({ gate });
  let p = page(h.port);
  await p.open;
  await p.hello(h.code);
  p.notify("grant.changed", { folders: ["/"], write: true, delegate: true });
  await new Promise((r) => setTimeout(r, 50));
  const { task } = (await p.call("tasks.start", START)).result;
  await until(() => h.turns.isRunning(task), "running");
  p.ws.close();
  await new Promise((r) => setTimeout(r, 100));
  assert.ok(h.turns.isRunning(task), "a page going away leaves the task running");
  assert.equal(h.store.state(task).status, "working");
  p = page(h.port);
  await p.open;
  await p.hello(h.server.newCode());
  p.notify("grant.changed", { folders: ["/"], write: true, delegate: false });
  await until(() => h.store.state(task).status === "interrupted" && !h.turns.isRunning(task), "switched off");
  assert.match(h.store.state(task).reason, /switch was turned off|turn was stopped/);
  release();
  await new Promise((r) => setTimeout(r, 100));
  assert.equal(h.store.state(task).status, "interrupted");
  assert.equal(h.store.state(task).proposals.length, 0);
  assert.equal(code(await p.call("tasks.list", {})), "forbidden");
  p.ws.close();
  await h.server.close();
  rmSync(h.dir, { recursive: true, force: true });
});
