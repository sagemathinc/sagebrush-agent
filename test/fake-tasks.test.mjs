// The stand-in Delegate host (lib/fake-tasks.mjs) the page's tests use: a whole task through its JSON-RPC frames,
// start to merge, with the scripted agent's proposal; and its refusals as the protocol words them.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fakeTasks } from "../lib/fake-tasks.mjs";
import { blobId } from "../lib/task-git.mjs";

const NB = JSON.stringify({ cells: [{ cell_type: "code", id: "a", metadata: {}, source: "x = 1", outputs: [], execution_count: null }], metadata: {}, nbformat: 4, nbformat_minor: 5 });
let n = 0;
const req = (method, params) => JSON.stringify({ jsonrpc: "2.0", id: `p${++n}`, method, params });

test("a task end to end through frames: start, the scripted proposal, diff, file, merged; task.event notifications", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sb-fake-"));
  const host = await fakeTasks({ root: join(dir, "tasks") });
  const seen = [];
  host.onNotify((m) => seen.push(m.params.event.type));
  const s = await host.handle(req("tasks.start", { title: "t", prompt: "p", target: "local", run: false, docs: [{ path: "a.ipynb", kind: "notebook", content: NB }] }));
  assert.ok(s.result?.task, JSON.stringify(s));
  await host.settled();
  const g = await host.handle(req("tasks.get", { task: s.result.task, after: 0 }));
  const prop = g.result.events.find((e) => e.event.type === "proposal").event;
  assert.equal(g.result.task.status, "proposal");
  const d = await host.handle(req("tasks.diff", { task: s.result.task, commit: prop.commit }));
  assert.equal(d.result.files[0].change, "modified");
  const f = await host.handle(req("tasks.file", { task: s.result.task, commit: prop.commit, path: "a.ipynb" }));
  assert.equal(blobId(Buffer.from(f.result.content)), f.result.blob);
  assert.match(f.result.content, /Proposed by the stand-in agent/);
  const m = await host.handle(req("tasks.merged", { task: s.result.task, proposal: prop.commit, seq: g.result.task.seq, merge_id: "9".repeat(32), files: [{ path: "a.ipynb", kind: "notebook", proposal_blob: f.result.blob, mine: { blob: blobId(Buffer.from(NB)), content: NB }, merged: { blob: f.result.blob, content: f.result.content } }] }));
  assert.equal(m.result.recorded, "merge");
  assert.deepEqual(seen, ["task_status", "proposal", "task_status", "merged", "task_status"]);
  rmSync(dir, { recursive: true, force: true });
});

test("refusals as the protocol words them: bad frames, unknown methods and fields, not_found, remote targets", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sb-fake-"));
  const host = await fakeTasks({ root: join(dir, "tasks") });
  const code = (a) => a.error?.data?.code;
  assert.equal(code(await host.handle("{")), "bad_request");
  assert.equal(code(await host.handle(JSON.stringify({ jsonrpc: "2.0", id: 7, method: "tasks.list", params: {} }))), "bad_request");
  assert.equal(code(await host.handle(req("tasks.nope", {}))), "bad_request");
  assert.equal(code(await host.handle(req("tasks.list", { extra: 1 }))), "bad_request");
  assert.equal(code(await host.handle(req("tasks.get", { task: "a".repeat(32), after: 0 }))), "not_found");
  assert.equal(code(await host.handle(req("tasks.start", { title: "t", prompt: "", target: "remote", run: false, docs: [] }))), "unavailable");
  assert.equal(code(await host.handle("x".repeat(4 * 1024 * 1024 + 1))), "too_large");
  assert.deepEqual((await host.handle(req("tasks.list", {}))).result, { tasks: [] });
  rmSync(dir, { recursive: true, force: true });
});
