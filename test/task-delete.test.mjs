// A Delegate task's workspace_delete (#1503): only a file the task itself created (never one of the documents it
// started with), never a folder, inside the copy, through the store's checked paths. A scripted model in place of Claude.
import assert from "node:assert/strict";
import { test } from "node:test";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fakeCreateServer } from "../lib/fake.mjs";
import { TaskStore } from "../lib/tasks.mjs";
import { TaskTurns } from "../lib/task-turns.mjs";
import { checkRequest } from "../lib/tasks-schema.mjs";

const WIN_DELEGATE = process.platform === "win32" ? { skip: "Delegate refused on win32 in this version" } : {};
const until = async (f, ms = 10000) => { const t = Date.now(); while (!f()) { if (Date.now() - t > ms) throw new Error("timed out"); await new Promise((r) => setTimeout(r, 20)); } };
const NB = JSON.stringify({ cells: [{ cell_type: "code", id: "a", metadata: {}, source: "x = 1", outputs: [], execution_count: null }], metadata: {}, nbformat: 4, nbformat_minor: 5 });

test("workspace_delete: a file the task created goes; a starting document, a folder, a missing file, an escape and the base's folder are refused", WIN_DELEGATE, async () => {
  const dir = mkdtempSync(join(tmpdir(), "sb-task-delete-"));
  const got = [];
  let store, task;
  const query = ({ options }) => (async function* () {
    const tools = options.mcpServers.sagebrush_task.handlers;
    yield { type: "system", subtype: "init", session_id: "s", model: "x", tools: [] };
    const run = async (name, input) => { const r = await tools[name](input); got.push([name, input.path, r.isError ? "refused" : "ok", r.content[0].text]); return r; };
    await run("workspace_write", { path: "scratch.md", text: "temp" });
    await run("workspace_write", { path: "sub/new.md", text: "n" });
    await run("workspace_delete", { path: "scratch.md" });
    await run("workspace_delete", { path: "a.ipynb" });
    await run("workspace_delete", { path: "docs/b.md" });
    await run("workspace_delete", { path: "docs" });
    await run("workspace_delete", { path: "sub" });
    await run("workspace_delete", { path: "gone.md" });
    await run("workspace_delete", { path: "../outside.md" });
    await run("propose", { summary: "x" });
    yield { type: "result", subtype: "success", is_error: false, result: "x", usage: {}, session_id: "s" };
  })();
  try {
    writeFileSync(join(dir, "outside.md"), "keep");
    store = new TaskStore({ root: join(dir, "tasks"), scope: "install-1" }).init();
    const turns = new TaskTurns({ store, query, createServer: fakeCreateServer, free: () => 1e12 });
    task = store.start(checkRequest("tasks.start", { title: "t", prompt: "p", target: "local", run: false, docs: [{ path: "a.ipynb", kind: "notebook", content: NB }, { path: "docs/b.md", kind: "file", content: "b" }] })).task;
    turns.begin(task, "start");
    await until(() => store.state(task).status === "proposal" && !turns.isRunning(task));
    const outcome = Object.fromEntries(got.filter(([n]) => n === "workspace_delete").map(([, p, r, t]) => [p, [r, t]]));
    assert.deepEqual(outcome["scratch.md"], ["ok", "deleted scratch.md"]);
    assert.match(outcome["a.ipynb"][1], /^refused: a\.ipynb is one of the documents the task started with: a task deletes only files it created$/);
    assert.match(outcome["docs/b.md"][1], /one of the documents the task started with/);
    assert.match(outcome["docs"][1], /^refused: docs is a folder: a task deletes only files$/);
    assert.match(outcome["sub"][1], /^refused: sub isn't a file in your copy$/);
    assert.match(outcome["gone.md"][1], /^refused: gone\.md isn't a file in your copy$/);
    assert.equal(outcome["../outside.md"][0], "refused");
    assert.ok(existsSync(join(dir, "outside.md")), "nothing outside the copy");
    // (the proposal: the created file that stayed, nothing deleted from the start, the deleted one never there)
    const t = store.state(task);
    assert.deepEqual(store.diff({ task, commit: t.proposals[0] }).files.map((f) => [f.path, f.change]), [["sub/new.md", "added"]]);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
