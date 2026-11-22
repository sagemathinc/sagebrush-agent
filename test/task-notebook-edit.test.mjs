// A Delegate task's workspace_edit_notebook (#1503): edits by cell id in the copy's .ipynb, every other cell, its outputs
// and its id kept byte for byte (in nbformat's layouts); and the tool through the task's own tool server.
import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { editIpynb } from "../lib/task-notebook-edit.mjs";
import { fakeCreateServer } from "../lib/fake.mjs";
import { TaskStore } from "../lib/tasks.mjs";
import { TaskTurns } from "../lib/task-turns.mjs";
import { checkRequest } from "../lib/tasks-schema.mjs";

const WIN_DELEGATE = process.platform === "win32" ? { skip: "Delegate refused on win32 in this version" } : {};
const PNG = Buffer.alloc(9000, 3).toString("base64");
const nb = () => ({
  cells: [
    { cell_type: "markdown", id: "m1", metadata: {}, source: ["# Plot\n", "of sin"] },
    { cell_type: "code", execution_count: 3, id: "c1", metadata: { tags: ["x"] }, outputs: [{ data: { "image/png": PNG, "text/plain": ["<Figure>"] }, metadata: {}, output_type: "display_data" }], source: "plot(sin)" },
    { cell_type: "code", execution_count: 4, id: "c2", metadata: {}, outputs: [{ name: "stdout", output_type: "stream", text: ["é 1\n"] }], source: "print(1)" },
  ],
  metadata: { kernelspec: { display_name: "Python 3", language: "python", name: "python3" } }, nbformat: 4, nbformat_minor: 5,
});
let n = 0;
const ids = () => `new${++n}`;

test("editIpynb: set, insert and remove by id; the cells it doesn't name keep their bytes, in each nbformat layout", () => {
  for (const [indent, nl] of [[1, "\n"], [2, ""], [undefined, "\n"]]) {
    const text = JSON.stringify(nb(), null, indent) + nl;
    n = 0;
    const r = editIpynb(text, { set: [{ id: "c2", source: "print(2)" }], insert: [{ after: "c1", type: "markdown", source: "Asked: more" }, { after: null, source: "import math" }], remove: [] }, ids);
    assert.ok(!(r instanceof Error), String(r));
    assert.deepEqual(r.inserted, ["new1", "new2"]);
    const j = JSON.parse(r.text);
    assert.deepEqual(j.cells.map((c) => c.id), ["new2", "m1", "c1", "new1", "c2"]);
    assert.equal(j.cells[4].source, "print(2)");
    assert.deepEqual(j.cells[4].outputs, nb().cells[2].outputs, "set keeps the cell's outputs");
    assert.deepEqual(j.cells[3], { cell_type: "markdown", id: "new1", metadata: {}, source: "Asked: more" });
    assert.deepEqual(j.cells[0], { cell_type: "code", execution_count: null, id: "new2", metadata: {}, outputs: [], source: "import math" });
    // (the untouched cells, byte for byte, and the whole file in the layout it had)
    const before = JSON.parse(text).cells, after = j.cells;
    for (const id of ["m1", "c1"]) assert.equal(JSON.stringify(after.find((c) => c.id === id)), JSON.stringify(before.find((c) => c.id === id)), id);
    // (both files are their JSON in one layout, so equal cells, keys in the same order, are equal bytes)
    assert.equal(text, JSON.stringify(JSON.parse(text), null, indent) + nl);
    assert.equal(r.text, JSON.stringify(j, null, indent) + nl, "the same layout and trailing newline");
  }
});

test("editIpynb: remove, and a type change gives the cell what its type has", () => {
  const text = JSON.stringify(nb(), null, 1) + "\n";
  const r = editIpynb(text, { remove: ["m1"], set: [{ id: "c2", type: "markdown" }, { id: "c1", source: "plot(cos)" }] }, ids);
  const j = JSON.parse(r.text);
  assert.deepEqual(j.cells.map((c) => c.id), ["c1", "c2"]);
  assert.equal(j.cells[0].source, "plot(cos)");
  assert.equal(j.cells[0].outputs[0].data["image/png"], PNG, "the picture kept");
  assert.equal(j.cells[1].cell_type, "markdown");
  assert.ok(!("outputs" in j.cells[1]) && !("execution_count" in j.cells[1]));
  const back = JSON.parse(editIpynb(r.text, { set: [{ id: "c2", type: "code" }] }, ids).text).cells[1];
  assert.deepEqual([back.cell_type, back.outputs, back.execution_count], ["code", [], null]);
});

test("editIpynb: what isn't allowed is refused, and nothing changes", () => {
  const text = JSON.stringify(nb(), null, 1) + "\n";
  for (const [edit, re] of [
    [{ set: [{ id: "zz", source: "x" }] }, /no cell "zz"/],
    [{ remove: ["c1", "c1"] }, /named twice/],
    [{ set: [{ id: "c1", source: "x" }], remove: ["c1"] }, /named twice/],
    [{ insert: [{ after: "c2", source: "x" }], remove: ["c2"] }, /after one this edit removes/],
    [{ insert: [{ after: "nope", source: "x" }] }, /no cell "nope"/],
    [{}, /at least one cell/],
  ]) assert.match(String(editIpynb(text, edit, ids)), re, JSON.stringify(edit));
  for (const t of ["not json", "{}", "[]"]) assert.match(String(editIpynb(t, { remove: ["c1"] })), /isn't a notebook's JSON/);
});

test("workspace_edit_notebook in a task: by cell, outputs kept; the proposal changes that notebook only", WIN_DELEGATE, async () => {
  const dir = mkdtempSync(join(tmpdir(), "sb-task-edit-"));
  const got = [];
  const until = async (f, ms = 10000) => { const t = Date.now(); while (!f()) { if (Date.now() - t > ms) throw new Error("timed out"); await new Promise((r) => setTimeout(r, 20)); } };
  const query = ({ options }) => (async function* () {
    const tools = options.mcpServers.sagebrush_task.handlers;
    yield { type: "system", subtype: "init", session_id: "s", model: "x", tools: [] };
    got.push(await tools.workspace_edit_notebook({ path: "a.ipynb", insert: [{ after: "c2", type: "markdown", source: "Done." }] }));
    got.push(await tools.workspace_edit_notebook({ path: "a.ipynb", set: [{ id: "gone", source: "x" }] }));
    got.push(await tools.workspace_edit_notebook({ path: "notes.md", remove: ["c1"] }));
    await tools.propose({ summary: "x" });
    yield { type: "result", subtype: "success", is_error: false, result: "x", usage: {}, session_id: "s" };
  })();
  try {
    const store = new TaskStore({ root: join(dir, "tasks"), scope: "install-1" }).init();
    const turns = new TaskTurns({ store, query, createServer: fakeCreateServer, free: () => 1e12 });
    const content = JSON.stringify(nb(), null, 1) + "\n";
    const task = store.start(checkRequest("tasks.start", { title: "t", prompt: "p", target: "local", run: false, docs: [{ path: "a.ipynb", kind: "notebook", content }, { path: "notes.md", kind: "file", content: "hi" }] })).task;
    turns.begin(task, "start");
    await until(() => store.state(task).status === "proposal" && !turns.isRunning(task));
    assert.match(got[0].content[0].text, /^edited a\.ipynb: 0 set, 1 inserted \(new ids: c[0-9a-f]{12}\), 0 removed$/);
    assert.match(got[1].content[0].text, /^refused: a\.ipynb: no cell "gone" in the notebook$/);
    assert.match(got[2].content[0].text, /^refused: a notebook's path ends in \.ipynb$/);
    const t = store.state(task);
    assert.deepEqual(store.diff({ task, commit: t.proposals[0] }).files.map((f) => [f.path, f.change]), [["a.ipynb", "modified"]]);
    const after = JSON.parse(store.file({ task, commit: t.proposals[0], path: "a.ipynb" }).content);
    assert.deepEqual(after.cells.slice(0, 3), JSON.parse(content).cells, "every cell before it as it was, outputs and ids");
    assert.equal(after.cells[3].source, "Done.");
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
