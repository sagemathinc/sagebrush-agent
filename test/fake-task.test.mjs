// The fake model on a delegated task's turn (SAGEBRUSH_AGENT_FAKE=1 only): it uses the task's own tool server, adds a
// closing note to the copy's first notebook (or writes a note), and proposes; what an end-to-end case against the
// packed agent can watch, with no model.
import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fakeCreateServer, fakeQuery } from "../lib/fake.mjs";
import { TaskStore } from "../lib/tasks.mjs";
import { TaskTurns } from "../lib/task-turns.mjs";
import { checkRequest } from "../lib/tasks-schema.mjs";
// (Delegate is refused on Windows in this version: its rows here are declared skips there, never silent passes)
const WIN_DELEGATE = process.platform === "win32" ? { skip: "Delegate refused on win32 in this version" } : {};

const NB = JSON.stringify({ cells: [{ cell_type: "code", id: "a", metadata: {}, source: "x = 1", outputs: [], execution_count: null }], metadata: {}, nbformat: 4, nbformat_minor: 5 });
const until = async (f, ms = 10000) => { const t = Date.now(); while (!f()) { if (Date.now() - t > ms) throw new Error("timed out"); await new Promise((r) => setTimeout(r, 20)); } };

for (const [what, docs, changed] of [["a notebook: a closing note added", [{ path: "a.ipynb", kind: "notebook", content: NB }], ["a.ipynb", "modified"]], ["no notebook: a note written", [{ path: "notes.md", kind: "file", content: "hi" }], ["fake-delegate.md", "added"]]]) {
  test(`the fake model on a task's turn: ${what}, then a proposal`, WIN_DELEGATE, async () => {
    const dir = mkdtempSync(join(tmpdir(), "sb-fake-task-"));
    try {
      const store = new TaskStore({ root: join(dir, "tasks"), scope: "install-1" }).init();
      const turns = new TaskTurns({ store, query: fakeQuery, createServer: fakeCreateServer, free: () => 1e12 });
      const task = store.start(checkRequest("tasks.start", { title: "t", prompt: "do it", target: "local", run: false, docs })).task;
      turns.begin(task, "start");
      await until(() => store.state(task).status === "proposal" && !turns.isRunning(task));
      const t = store.state(task);
      assert.deepEqual(store.diff({ task, commit: t.proposals[0] }).files.map((f) => [f.path, f.change]), [changed]);
      if (changed[0] === "a.ipynb") assert.equal(JSON.parse(store.file({ task, commit: t.proposals[0], path: "a.ipynb" }).content).cells.at(-1).source, "Done by the fake model, for this task.");
      const types = store.get({ task, after: 0 }).events.map((e) => e.event.type);
      assert.ok(types.includes("tool_call_started") && types.includes("proposal"), types.join(","));
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
}
