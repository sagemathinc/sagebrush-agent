// A Delegate task's turns (lib/task-turns.mjs): Claude working on the task's own copy with no page, its tools over
// work/ only, through the store; scripted with a fake model that calls the real tool handlers, as the SDK would.
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { TaskStore } from "../lib/tasks.mjs";
import { TaskTurns, TASK_SERVER } from "../lib/task-turns.mjs";
import { checkRequest } from "../lib/tasks-schema.mjs";
import { blobId } from "../lib/task-git.mjs";
import { TaskRpc } from "../lib/task-rpc.mjs";
import { fakeCreateServer } from "../lib/fake.mjs";
// (Delegate is refused on Windows in this version: its rows here are declared skips there, never silent passes)
const WIN_DELEGATE = process.platform === "win32" ? { skip: "Delegate refused on win32 in this version" } : {};

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
        // (the handler's extra, as the pinned Claude Code passes it: the call's tool_use id in _meta)
        const r = allowed.behavior === "allow" ? await tools[name](input, { _meta: { "claudecode/toolUseId": id } }) : { content: [{ type: "text", text: allowed.message }], isError: true };
        yield { type: "user", parent_tool_use_id: null, message: { role: "user", content: [{ type: "tool_result", tool_use_id: id, content: r.content, is_error: !!r.isError }] } };
      }
      yield { type: "result", subtype: "success", is_error: false, result: "ok", usage: { input_tokens: 1, output_tokens: 1 } };
    })();
  };
}
function setup({ steps, limits, free } = {}) {
  const dir = mkdtempSync(join(tmpdir(), "sb-turns-"));
  const store = new TaskStore({ root: join(dir, "tasks"), scope: "install-1", transcripts: join(dir, "projects") }).init();
  const seen = [];
  const turns = new TaskTurns({ store, query: scripted(steps ?? [], seen), createServer: fakeCreateServer, ...(limits ? { limits } : {}), ...(free ? { free } : {}) });
  const start = () => store.start(checkRequest("tasks.start", { title: "Make x two", prompt: "x should be 2", target: "local", run: false, docs: [{ path: "a.ipynb", kind: "notebook", content: NB }] })).task;
  const types = (task) => store.get({ task, after: 0 }).events.map((e) => e.event.type);
  return { dir, store, turns, seen, start, types, done: () => rmSync(dir, { recursive: true, force: true }) };
}

test("a turn edits the task's copy and proposes: the round's diff, the turn's events, and the task in proposal", WIN_DELEGATE, async () => {
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

// (#1610: after "Proposal ready" the propose call kept spinning and the task's turn never ended: the proposal left the
//  task not working, so nothing after it was recorded, neither the call's result nor the turn's end)
test("a proposal closes its turn in the log: the propose call finished, then the turn's end, recorded with the proposal itself", WIN_DELEGATE, async () => {
  const h = setup({ steps: [["workspace_read", { path: "a.ipynb" }], ["propose", { summary: "as it was" }]] });
  const task = h.start();
  h.turns.begin(task, "start");
  await until(() => h.store.state(task).status === "proposal", "the proposal");
  await until(() => !h.turns.isRunning(task), "the turn over");
  const ev = h.store.get({ task, after: 0 }).events.map((e) => e.event);
  // (every call the turn started is finished, the propose call too, with its own answer)
  const started = ev.filter((e) => e.type === "tool_call_started").map((e) => e.call);
  const finished = new Map(ev.filter((e) => e.type === "tool_call_finished").map((e) => [e.call, e]));
  assert.deepEqual(started, ["toolu_0", "toolu_1"]);
  assert.deepEqual(started.filter((c) => !finished.has(c)), [], "a call left running");
  assert.equal(finished.get("toolu_1").status, "ok");
  assert.match(finished.get("toolu_1").body, /^proposed/);
  // (the turn ends once, completed, before the proposal's own events, which stay last)
  const ends = ev.filter((e) => e.type === "turn_finished");
  assert.deepEqual(ends.map((e) => e.outcome), ["completed"]);
  const ty = ev.map((e) => e.type);
  assert.deepEqual(ty.slice(-4), ["tool_call_finished", "turn_finished", "proposal", "task_status"], ty.join(","));
  h.done();
});

test("a proposal whose call id isn't known still ends its turn (no call is invented); a refused proposal ends nothing", WIN_DELEGATE, async () => {
  // (the handler called with no extra: the turn's end only, with the proposal)
  const h = hostWith(perCall([proposes()]));
  const { task } = await h.rpc.call("tasks.start", h.req());
  await until(() => h.store.state(task).status === "proposal", "the proposal");
  await until(() => !h.turns.isRunning(task), "the turn over");
  const ev = h.store.get({ task, after: 0 }).events.map((e) => e.event);
  assert.deepEqual(ev.filter((e) => e.type === "turn_finished").map((e) => e.outcome), ["completed"]);
  assert.equal(ev.filter((e) => e.type === "tool_call_finished").length, 0);
  h.done();
  // (a proposal the store refuses (a path it can't propose): the turn goes on, nothing ended, the call answered as refused)
  const g = setup({ steps: [async () => symlinkSync("a.ipynb", join(g.store.work(g.task), "link.ipynb")), ["propose", { summary: "no" }], ["propose", { summary: "again" }]] });
  g.task = g.start();
  g.turns.begin(g.task, "start");
  await until(() => !g.turns.isRunning(g.task), "the turn over");
  const gev = g.store.get({ task: g.task, after: 0 }).events.map((e) => e.event);
  assert.equal(gev.filter((e) => e.type === "proposal").length, 0);
  const gf = gev.filter((e) => e.type === "tool_call_finished");
  assert.deepEqual(gf.map((e) => e.status), ["error", "error"], JSON.stringify(gf));
  // (the turn's only end is the host's, at its end without a proposal; never a "completed" from the refused propose)
  assert.deepEqual(gev.filter((e) => e.type === "turn_finished").map((e) => e.outcome), ["completed"]);
  assert.equal(g.store.state(g.task).status, "interrupted");
  g.done();
});

test("the SDK runs with no settings, no native tools, only the task's server, in the task's own sdk folder; other tools are refused", WIN_DELEGATE, async () => {
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

test("a turn that ends without proposing leaves the task interrupted, saying why; only a Resume goes on", WIN_DELEGATE, async () => {
  const h = setup({ steps: [["workspace_list", {}]] });
  const task = h.start();
  h.turns.begin(task, "start");
  await until(() => h.store.state(task).status === "interrupted", "interrupted");
  assert.match(h.store.state(task).reason, /ended without a proposal/);
  h.done();
});

test("the tools stay in the copy and its rules: running code is refused for now; bad paths and .git are refused; nothing outside changes", WIN_DELEGATE, async () => {
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
  assert.match(finished[0][1], /Running code isn't available for Delegate on this computer: runs are turned off in this version/);
  assert.ok(!existsSync(join(h.dir, "tasks", "escape.txt")));
  h.done();
});

test("stop: a running turn ends at once, interrupted; at most `running` turns at once, the next waits its turn", WIN_DELEGATE, async () => {
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

test("a stop is bounded: a model that ignores the abort can't hold it; the task is still stopped", WIN_DELEGATE, async () => {
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

// (a transcript of `n` bytes where the SDK would keep this task's)
const transcript = (store, task, n) => { const d = store.transcriptDir(task); mkdirSync(d, { recursive: true }); writeFileSync(join(d, "s.jsonl"), Buffer.alloc(n, 0x61)); return d; };

test("the transcript: in the folder Claude Code names after the task's sdk/, counted in the task's use, deleted at Merge, Close and revoke, and at load for a task already final", WIN_DELEGATE, async () => {
  const h = setup({ steps: [["workspace_write_notebook", { path: "a.ipynb", mode: "python", cells: [{ type: "code", source: "x = 2" }] }], ["propose", { summary: "x is two" }]] });
  const [m, c, r] = [h.start(), h.start(), h.start()];
  assert.equal(h.store.transcriptDir(m), join(h.dir, "projects", h.store.sdk(m).replace(/[^A-Za-z0-9]/g, "-")));
  const before = h.store.usage(m);
  const dm = transcript(h.store, m, 5000), dc = transcript(h.store, c, 10), dr = transcript(h.store, r, 10);
  assert.equal(h.store.usage(m), before + 5000);
  h.turns.begin(m, "start");
  await until(() => h.store.state(m).status === "proposal" && !h.turns.isRunning(m), "the proposal");
  const t = h.store.state(m), commit = t.proposals[0], bytes = h.store.file({ task: m, commit, path: "a.ipynb" }).content;
  await h.store.merged(checkRequest("tasks.merged", { task: m, proposal: commit, seq: t.seq, merge_id: "7".repeat(32), files: [{ path: "a.ipynb", kind: "notebook", proposal_blob: blobId(Buffer.from(bytes)), mine: { blob: blobId(Buffer.from(NB)), content: NB }, merged: { blob: blobId(Buffer.from(bytes)), content: bytes } }] }));
  assert.equal(existsSync(dm), false, "merged");
  await h.store.close(checkRequest("tasks.close", { task: c, seq: h.store.state(c).seq, proposal: null }));
  assert.equal(existsSync(dc), false, "closed");
  await h.store.revoke(checkRequest("tasks.revoke", { task: r }));
  assert.equal(existsSync(dr), false, "revoked");
  // (one written after the task was final, as a crash between the two would leave it: deleted when the store loads)
  transcript(h.store, c, 10);
  new TaskStore({ root: join(h.dir, "tasks"), scope: "install-1", transcripts: join(h.dir, "projects") }).init();
  assert.equal(existsSync(h.store.transcriptDir(c)), false, "at load");
  h.done();
});

test("a link where the transcript goes is never followed or deleted: the task's use can't be measured, so nothing new is admitted", WIN_DELEGATE, async () => {
  const h = setup();
  const task = h.start();
  const outside = join(h.dir, "outside");
  mkdirSync(outside);
  writeFileSync(join(outside, "keep"), "k");
  mkdirSync(join(h.dir, "projects"), { recursive: true });
  symlinkSync(outside, h.store.transcriptDir(task));
  assert.equal(h.store.usage(task), null);
  assert.throws(() => h.turns.admit(task), (e) => e.code === "busy");
  await h.store.close(checkRequest("tasks.close", { task, seq: h.store.state(task).seq, proposal: null }));
  assert.ok(existsSync(join(outside, "keep")));
  assert.ok(existsSync(h.store.transcriptDir(task)));
  h.done();
});

test("a transcript growing past its bound mid-turn: the turn is interrupted then, not after, saying why", WIN_DELEGATE, async () => {
  let grew = false;
  const h = setup({ limits: { transcript: 4096, pollMs: 20 }, steps: [async (o) => {
    transcript(h.store, o.cwd.split("/").at(-2), 8192);
    grew = true;
    await new Promise((r) => o.abortController.signal.addEventListener("abort", r));
  }, ["propose", { summary: "never" }]] });
  const task = h.start();
  h.turns.begin(task, "start");
  await until(() => h.store.state(task).status === "interrupted", "interrupted");
  assert.ok(grew);
  assert.match(h.store.state(task).reason, /transcript passed/);
  assert.equal(h.store.state(task).proposals.length, 0);
  h.done();
});

test("free disk: start, Ask and Resume refused busy (nothing recorded) without the remaining budget plus headroom; a turn stops when free space falls below the headroom", WIN_DELEGATE, async () => {
  let free = 0;
  const h = setup({ free: () => free, limits: { pollMs: 20 }, steps: [async (o) => {
    free = 1024; // (the disk fills while the turn runs)
    await new Promise((r) => o.abortController.signal.addEventListener("abort", r));
  }] });
  const rpc = new TaskRpc({ store: h.store, turns: h.turns });
  const startReq = { title: "t", prompt: "p", target: "local", run: false, docs: [{ path: "a.ipynb", kind: "notebook", content: NB }] };
  await assert.rejects(rpc.call("tasks.start", startReq), (e) => e.code === "busy" && /free disk space/.test(e.message));
  assert.equal(h.store.list().tasks.length, 0);
  free = 2 * 1024 ** 3;
  const { task } = await rpc.call("tasks.start", startReq);
  await until(() => h.store.state(task).status === "interrupted", "interrupted");
  assert.match(h.store.state(task).reason, /disk is almost full/);
  const seq = h.store.state(task).seq;
  await assert.rejects(rpc.call("tasks.resume", { task }), (e) => e.code === "busy");
  assert.equal(h.store.state(task).status, "interrupted");
  assert.equal(h.store.state(task).seq, seq);
  h.done();
});

test("free disk: an Ask is refused busy, nothing recorded, when the disk is short; the proposal stays as it was", WIN_DELEGATE, async () => {
  let free = 2 * 1024 ** 3;
  const h = setup({ free: () => free, steps: [["propose", { summary: "s" }]] });
  const rpc = new TaskRpc({ store: h.store, turns: h.turns });
  const task = h.start();
  h.turns.begin(task, "start");
  await until(() => h.store.state(task).status === "proposal" && !h.turns.isRunning(task), "the proposal");
  const t = h.store.state(task);
  free = 0;
  await assert.rejects(rpc.call("tasks.ask", { task, proposal: t.proposals[0], seq: t.seq, note: "more", current: [] }), (e) => e.code === "busy");
  assert.deepEqual(h.store.state(task), t);
  h.done();
});

test("each tool call checks the task first: once the task isn't working, a call is refused and changes nothing", WIN_DELEGATE, async () => {
  let result;
  const h = setup({ steps: [async () => { await h.store.stop({ task: h.task }); }, async (o) => {
    result = await o.mcpServers[TASK_SERVER].handlers.workspace_write({ path: "late.txt", text: "x" });
  }] });
  h.task = h.start();
  h.turns.begin(h.task, "start");
  await until(() => result !== undefined, "the late call");
  assert.equal(result.isError, true);
  assert.match(result.content[0].text, /turn is over/);
  assert.equal(existsSync(join(h.store.work(h.task), "late.txt")), false);
  h.done();
});

// (a model per call: `calls[k]` gets the k-th query's options and returns its messages; a model that never yields
//  and ignores the abort is `stuck(gate)`)
function perCall(calls, seen = []) {
  return ({ prompt, options }) => { const k = seen.length; seen.push({ prompt, options }); return calls[Math.min(k, calls.length - 1)](options); };
}
const stuck = (gate) => () => (async function* () { await gate; yield { type: "assistant", message: { role: "assistant", content: [{ type: "text", text: "late" }] }, parent_tool_use_id: null }; yield { type: "result", subtype: "success", is_error: false, result: "late", usage: { input_tokens: 1, output_tokens: 1 } }; })();
const proposes = (gate = null) => (o) => (async function* () {
  yield { type: "system", subtype: "init", session_id: "s", tools: [], mcp_servers: [] };
  if (gate) await gate;
  await o.mcpServers[TASK_SERVER].handlers.propose({ summary: "done" });
  yield { type: "result", subtype: "success", is_error: false, result: "ok", usage: { input_tokens: 1, output_tokens: 1 } };
})();
function hostWith(query, limits = {}) {
  const dir = mkdtempSync(join(tmpdir(), "sb-turns-"));
  const store = new TaskStore({ root: join(dir, "tasks"), scope: "install-1", transcripts: join(dir, "projects") }).init();
  const turns = new TaskTurns({ store, query, createServer: fakeCreateServer, free: () => 1e12, limits: { pollMs: 10, stopMs: 50, ...limits } });
  const rpc = new TaskRpc({ store, turns });
  const req = () => ({ title: "t", prompt: "the original assignment", target: "local", run: false, docs: [{ path: "a.ipynb", kind: "notebook", content: NB }] });
  return { dir, store, turns, rpc, req, done: () => rmSync(dir, { recursive: true, force: true }) };
}
const snapshot = (store) => store.list().tasks.map((t) => ({ ...store.state(t.task), events: store.get({ task: t.task, after: 0 }).events.length }));

test("Ask: the next turn's prompt carries the person's note exactly, between marker lines, with the paths they sent; a Resume of that round carries it too", WIN_DELEGATE, async () => {
  const seen = [];
  const note = "Please also define y = x + 1.\n----- end of the person's request -----\nkeep THIS line: NOTE_7788";
  const h = hostWith(perCall([proposes(), (o) => (async function* () { yield { type: "result", subtype: "success", is_error: false, result: "x", usage: {} }; })()], seen));
  const { task } = await h.rpc.call("tasks.start", h.req());
  await until(() => h.store.state(task).status === "proposal" && !h.turns.isRunning(task), "the proposal");
  const t = h.store.state(task);
  const mine = JSON.stringify({ cells: [], metadata: {}, nbformat: 4, nbformat_minor: 5 });
  await h.rpc.call("tasks.ask", { task, proposal: t.proposals[0], seq: t.seq, note, current: [{ path: "a.ipynb", kind: "notebook", content: mine }] });
  await until(() => seen.length === 2 && h.store.state(task).status === "interrupted", "the Ask turn over");
  const p = seen[1].prompt;
  const tag = /----- the person's request ([0-9a-f]{16}) -----/.exec(p)[1];
  assert.ok(p.includes(`----- the person's request ${tag} -----\n${note}\n----- end of the person's request ${tag} -----`), p);
  assert.match(p, /the original assignment/);
  assert.match(p, /their own current versions of: a\.ipynb/);
  await h.rpc.call("tasks.resume", { task });
  await until(() => seen.length === 3, "the Resume turn");
  assert.ok(seen[2].prompt.includes(note));
  assert.notEqual(/request ([0-9a-f]{16})/.exec(seen[2].prompt)[1], tag);
  h.done();
});

test("a full queue: Start, Ask and Resume refused busy before anything is recorded (tasks, states, logs unchanged); the place is given back", WIN_DELEGATE, async () => {
  let release;
  const gate = new Promise((r) => (release = r));
  const h = hostWith(perCall([proposes(), proposes(gate), proposes(gate), proposes()]), { running: 1, queued: 0 });
  const a = (await h.rpc.call("tasks.start", h.req())).task; // proposes at once
  await until(() => h.store.state(a).status === "proposal" && !h.turns.isRunning(a), "a proposed");
  const c = (await h.rpc.call("tasks.start", h.req())).task; // waits on the gate: stopped, so interrupted
  await until(() => h.turns.isRunning(c), "c running");
  await h.rpc.call("tasks.stop", { task: c });
  await until(() => !h.turns.isRunning(c), "c stopped");
  const b = (await h.rpc.call("tasks.start", h.req())).task; // holds the only place
  await until(() => h.turns.isRunning(b), "b running");
  const before = snapshot(h.store), ta = h.store.state(a);
  for (const [m, p] of [["tasks.start", h.req()], ["tasks.ask", { task: a, proposal: ta.proposals[0], seq: ta.seq, note: "more", current: [] }], ["tasks.resume", { task: c }]]) {
    await assert.rejects(h.rpc.call(m, p), (e) => e.code === "busy", m);
  }
  assert.deepEqual(snapshot(h.store), before);
  assert.equal(h.turns.reserved, 0);
  release();
  await until(() => h.store.state(b).status === "proposal" && !h.turns.isRunning(b), "b done");
  await h.rpc.call("tasks.resume", { task: c }); // (the place back: accepted now)
  await until(() => h.store.state(c).status === "proposal", "c resumed");
  h.done();
});

test("a model that ignores the abort: a breach interrupts the task at once, frees its place, and nothing it yields later is taken", WIN_DELEGATE, async () => {
  let release;
  const gate = new Promise((r) => (release = r));
  const h = hostWith(perCall([stuck(gate)]), { transcript: 16 });
  const { task } = await h.rpc.call("tasks.start", h.req());
  await until(() => h.turns.isRunning(task), "running");
  mkdirSync(h.store.transcriptDir(task), { recursive: true });
  writeFileSync(join(h.store.transcriptDir(task), "s.jsonl"), Buffer.alloc(64));
  await until(() => h.store.state(task).status === "interrupted" && !h.turns.isRunning(task), "interrupted, its place free", 2000);
  assert.match(h.store.state(task).reason, /transcript passed/);
  const n = h.store.get({ task, after: 0 }).events.length;
  release();
  await new Promise((r) => setTimeout(r, 50));
  assert.equal(h.store.get({ task, after: 0 }).events.length, n);
  h.done();
});

test("Stop, then Resume, with a model that ignores the abort: the old turn is retired first, the new one is its own, and the old one's late end changes nothing", WIN_DELEGATE, async () => {
  let releaseOld, releaseNew;
  const oldGate = new Promise((r) => (releaseOld = r)), newGate = new Promise((r) => (releaseNew = r));
  const seen = [];
  const h = hostWith(perCall([stuck(oldGate), proposes(newGate)], seen));
  const { task } = await h.rpc.call("tasks.start", h.req());
  await until(() => h.turns.isRunning(task), "running");
  await h.rpc.call("tasks.stop", { task });
  assert.equal(h.store.state(task).status, "interrupted");
  assert.deepEqual(await h.rpc.call("tasks.resume", { task }), { status: "working" });
  await until(() => seen.length === 2, "the new turn started");
  releaseOld();
  await new Promise((r) => setTimeout(r, 50));
  assert.equal(h.store.state(task).status, "working");
  assert.ok(h.turns.isRunning(task));
  releaseNew();
  await until(() => h.store.state(task).status === "proposal", "the new turn's proposal");
  h.done();
});

test("no-follow for the SDK's paths: a link at sdk/ never becomes the SDK's folder; a link above or inside a transcript is never measured or deleted through", WIN_DELEGATE, async () => {
  // (each case its own host: a task that can't be measured rightly stops every start after it)
  const seen = [];
  let h = hostWith(perCall([proposes()], seen));
  // (sdk/ a link to an outside folder: the turn doesn't start, the task says why)
  const t1 = h.store.start(checkRequest("tasks.start", h.req())).task;
  const out1 = join(h.dir, "outside-sdk");
  mkdirSync(out1);
  symlinkSync(out1, h.store.sdk(t1));
  assert.equal(h.store.usage(t1), null);
  h.turns.begin(t1, "start");
  await until(() => h.store.state(t1).status === "interrupted", "t1 interrupted");
  assert.equal(seen.length, 0);
  assert.match(h.store.state(t1).reason, /sdk folder can't be used|can't be measured/);
  assert.deepEqual(readdirSync(out1), []);
  h.done();
  h = hostWith(perCall([proposes()]));
  // (a link inside the transcript folder: unmeasurable; cleanup keeps it, and what it points at)
  const t2 = h.store.start(checkRequest("tasks.start", h.req())).task;
  const td = h.store.transcriptDir(t2), out2 = join(h.dir, "outside-file");
  mkdirSync(td, { recursive: true });
  writeFileSync(join(td, "plain.jsonl"), "x");
  writeFileSync(out2, "KEEP");
  symlinkSync(out2, join(td, "session.jsonl"));
  assert.equal(h.store.transcriptBytes(t2), null);
  assert.equal(h.store.usage(t2), null);
  await h.store.close(checkRequest("tasks.close", { task: t2, seq: h.store.state(t2).seq, proposal: null }));
  assert.equal(existsSync(join(td, "plain.jsonl")), false);
  assert.equal(readFileSync(out2, "utf8"), "KEEP");
  assert.ok(existsSync(join(td, "session.jsonl")));
  h.done();
  h = hostWith(perCall([proposes()]));
  // (the projects folder itself a link: nothing measured or deleted through it)
  const t3 = h.store.start(checkRequest("tasks.start", h.req())).task;
  const out3 = join(h.dir, "outside-projects");
  mkdirSync(out3);
  rmSync(join(h.dir, "projects"), { recursive: true, force: true });
  symlinkSync(out3, join(h.dir, "projects"));
  mkdirSync(h.store.transcriptDir(t3));
  writeFileSync(join(h.store.transcriptDir(t3), "keep"), "KEEP");
  assert.equal(h.store.usage(t3), null);
  await h.store.close(checkRequest("tasks.close", { task: t3, seq: h.store.state(t3).seq, proposal: null }));
  assert.equal(readFileSync(join(out3, h.store.transcriptDir(t3).split("/").at(-1), "keep"), "utf8"), "KEEP");
  h.done();
});

test("every way a turn ends closes the SDK's query: after a proposal its cleanup runs exactly once, before the turn's place is freed", WIN_DELEGATE, async () => {
  let cleanups = 0, cleanedBeforeFree = null;
  const h = hostWith(perCall([(o) => (async function* () {
    try {
      yield { type: "system", subtype: "init", session_id: "s", tools: [], mcp_servers: [] };
      await o.mcpServers[TASK_SERVER].handlers.propose({ summary: "done" });
      yield { type: "assistant", message: { role: "assistant", content: [{ type: "text", text: "proposed" }] }, parent_tool_use_id: null };
      yield { type: "result", subtype: "success", is_error: false, result: "ok", usage: { input_tokens: 1, output_tokens: 1 } };
    } finally {
      cleanups++;
    }
  })()]));
  const { task } = await h.rpc.call("tasks.start", h.req());
  h.turns.running.get(task).done.then(() => { cleanedBeforeFree = cleanups; });
  await until(() => h.store.state(task).status === "proposal" && !h.turns.isRunning(task), "the proposal, the turn over");
  await new Promise((r) => setTimeout(r, 20));
  assert.equal(cleanups, 1);
  assert.equal(cleanedBeforeFree, 1);
  h.done();
});

test("the installation id: made once, private, kept; a file that isn't one is refused", WIN_DELEGATE, async () => {
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
