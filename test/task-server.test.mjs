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
// (Delegate is refused on Windows in this version: its rows here are declared skips there, never silent passes)
const WIN_DELEGATE = process.platform === "win32" ? { skip: "Delegate refused on win32 in this version" } : {};

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

test("the hello offers delegate.1 over the loopback; without the Delegate switch every tasks request is refused forbidden", WIN_DELEGATE, async () => {
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

test("a task runs with no page: start, close the page, the proposal arrives meanwhile, a new page reads it and merges", WIN_DELEGATE, async () => {
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

test("turning the Delegate switch off: the capability goes at once, the running turn stops, its task is interrupted (not closed)", WIN_DELEGATE, async () => {
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

test("task.event goes only to a page holding the switch; stop and revoke act on the turn and the task", WIN_DELEGATE, async () => {
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

test("over the runner's stdio there are no tasks: no delegate.1, and requests are refused unavailable", WIN_DELEGATE, async () => {
  const dir = mkdtempSync(join(tmpdir(), "sb-tsrv-"));
  const server = new AgentServer({ query: fakeQuery, log: () => {}, stdio: true });
  const store = new TaskStore({ root: join(dir, "tasks"), scope: "install-1" }).init();
  const turns = new TaskTurns({ store, query: taskModel(), createServer: fakeCreateServer });
  server.setTasks({ store, turns, rpc: new TaskRpc({ store, turns }) });
  assert.ok(!server.features().includes("delegate.1"));
  rmSync(dir, { recursive: true, force: true });
});

test("a failure of the task host that isn't a refusal: answered unavailable, its detail only in the agent's log", WIN_DELEGATE, async () => {
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

test("a new pairing's first grant without delegate turns nothing off: the running task goes on, tasks.* is refused until the page turns the switch on, then its proposal is there", WIN_DELEGATE, async () => {
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
  // (the page again, paired with a new code: its first grant has the switch off, as a new pairing starts)
  p = page(h.port);
  await p.open;
  await p.hello(h.server.newCode());
  p.notify("grant.changed", { folders: ["/"], write: true });
  await new Promise((r) => setTimeout(r, 100));
  assert.ok(h.turns.isRunning(task), "still running after the new pairing's grant");
  assert.equal(h.store.state(task).status, "working");
  assert.equal(code(await p.call("tasks.list", {})), "forbidden", "no tasks.* without the switch");
  release();
  await until(() => h.store.state(task).status === "proposal", "the proposal, while the page has the switch off");
  p.notify("grant.changed", { folders: ["/"], write: true, delegate: true });
  await new Promise((r) => setTimeout(r, 50));
  const got = await p.call("tasks.get", { task, after: 0 });
  assert.ok(got.result.events.some((e) => e.event.type === "proposal"));
  p.ws.close();
  await h.server.close();
  rmSync(h.dir, { recursive: true, force: true });
});

test("the switch off after a reconnect: on the new pairing, turned on then off, the old task's turn stops at once and its model's late work is refused", WIN_DELEGATE, async () => {
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
  await until(() => !h.server.sock, "the page gone");
  p = page(h.port);
  await p.open;
  await p.hello(h.server.newCode());
  p.notify("grant.changed", { folders: ["/"], write: true });
  p.notify("grant.changed", { folders: ["/"], write: true, delegate: true });
  await new Promise((r) => setTimeout(r, 100));
  assert.ok(h.turns.isRunning(task));
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

test("the pairing's revoke turns Delegate off: the running task is interrupted, also from a new pairing that never had the switch", WIN_DELEGATE, async () => {
  for (const repair of [false, true]) {
    const h = await setup({ gate: new Promise(() => {}) });
    let p = page(h.port);
    await p.open;
    await p.hello(h.code);
    p.notify("grant.changed", { folders: ["/"], write: true, delegate: true });
    await new Promise((r) => setTimeout(r, 50));
    const { task } = (await p.call("tasks.start", START)).result;
    await until(() => h.turns.isRunning(task), "running");
    if (repair) {
      p.ws.close();
      await until(() => !h.server.sock, "the page gone");
      p = page(h.port);
      await p.open;
      await p.hello(h.server.newCode());
      p.notify("grant.changed", { folders: ["/"], write: true });
      await new Promise((r) => setTimeout(r, 100));
      assert.ok(h.turns.isRunning(task), "the new pairing's grant left it running");
    }
    p.notify("grant.changed", {});
    await until(() => h.store.state(task).status === "interrupted" && !h.turns.isRunning(task), `revoked (re-paired: ${repair})`);
    assert.match(h.store.state(task).reason, /switch was turned off|turn was stopped/);
    assert.equal(code(await p.call("tasks.list", {})), "forbidden");
    p.ws.close();
    await h.server.close();
    rmSync(h.dir, { recursive: true, force: true });
  }
});

test("delegate.run: offered only where a task's notebooks can run here (runs on, a platform where runs are on, its pins); the task's system prompt says which", WIN_DELEGATE, async () => {
  const { TaskRunner } = await import("../lib/task-runner.mjs");
  const { RUN_FEATURE } = await import("../lib/server.mjs");
  const { taskSystem } = await import("../lib/task-turns.mjs");
  assert.equal(RUN_FEATURE, "delegate.run");
  const dir = mkdtempSync(join(tmpdir(), "sb-tsrv-"));
  const offer = (runner, stdio = false) => {
    const server = new AgentServer({ query: fakeQuery, log: () => {}, stdio });
    const store = new TaskStore({ root: join(dir, `tasks-${Math.random().toString(36).slice(2)}`), scope: "install-1" }).init();
    const turns = new TaskTurns({ store, query: taskModel(), createServer: fakeCreateServer, runner: runner?.(store) ?? null });
    server.setTasks({ store, turns, rpc: new TaskRpc({ store, turns }) });
    return server.features();
  };
  const linux = (store) => new TaskRunner({ store, platform: "linux-x64" });
  assert.ok(offer(linux).includes("delegate.run"), "runs on, pins for this platform");
  assert.ok(offer(linux).includes("delegate.1"));
  assert.ok(!offer((store) => new TaskRunner({ store, enabled: false, platform: "linux-x64" })).includes("delegate.run"), "runs off");
  assert.ok(!offer((store) => new TaskRunner({ store, platform: null })).includes("delegate.run"), "no pins for this platform");
  assert.ok(offer((store) => new TaskRunner({ store, platform: "darwin-arm64" })).includes("delegate.run"), "macOS: offered");
  assert.ok(!offer((store) => new TaskRunner({ store, platform: "darwin-arm64", runPlatforms: ["linux-x64"] })).includes("delegate.run"), "a platform not in the list: not offered");
  assert.ok(!offer(null).includes("delegate.run"), "no runner");
  assert.ok(!offer(linux, true).includes("delegate.run"), "never over the runner's stdio, where there are no tasks");
  // (the prompt: what it says about running code follows whether this task can run it)
  assert.match(taskSystem(true), /You can run a notebook of your copy with notebook_run to check your work: its code reads and writes only your copy, with no network\./);
  assert.doesNotMatch(taskSystem(true), /isn't available/);
  assert.match(taskSystem(false), /Running code isn't available for this task: check your work by reading it\./);
  rmSync(dir, { recursive: true, force: true });
});
