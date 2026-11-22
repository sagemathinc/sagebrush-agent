// A Delegate task's workspace_read (#1503): a notebook in the copy reads in the shared format (test/fixtures/nb-read/),
// as Pair's does; {cell} and {from}; other files as text, cut and said so in numbers. Through the task's own tool
// server, with a scripted model in place of Claude.
import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fakeCreateServer } from "../lib/fake.mjs";
import { TaskStore } from "../lib/tasks.mjs";
import { TaskTurns } from "../lib/task-turns.mjs";
import { checkRequest } from "../lib/tasks-schema.mjs";
import { notebookRead, ipynbDoc } from "../lib/notebook-read.mjs";

const WIN_DELEGATE = process.platform === "win32" ? { skip: "Delegate refused on win32 in this version" } : {};
const until = async (f, ms = 10000) => { const t = Date.now(); while (!f()) { if (Date.now() - t > ms) throw new Error("timed out"); await new Promise((r) => setTimeout(r, 20)); } };
const PNG = Buffer.alloc(300000, 7).toString("base64");
const NB = JSON.stringify({
  cells: [
    { cell_type: "markdown", id: "m", metadata: {}, source: ["# Plot"] },
    { cell_type: "code", id: "c", metadata: {}, source: "plot(x)", execution_count: 1, outputs: [{ output_type: "stream", name: "stdout", text: ["y".repeat(1000)] }, { output_type: "display_data", data: { "image/png": PNG, "text/plain": ["<Figure>"] }, metadata: {} }] },
  ],
  metadata: { kernelspec: { name: "python3", display_name: "Python 3", language: "python" } }, nbformat: 4, nbformat_minor: 5,
});

// (a turn whose model makes the given reads, in order, and keeps what each returned)
async function reads(docs, calls, limits) {
  const dir = mkdtempSync(join(tmpdir(), "sb-task-read-"));
  const got = [];
  const query = ({ options }) => (async function* () {
    const tools = options.mcpServers.sagebrush_task.handlers;
    yield { type: "system", subtype: "init", session_id: "s", model: "x", tools: [] };
    for (const c of calls) got.push(await tools.workspace_read(c));
    yield { type: "result", subtype: "success", is_error: false, result: "x", usage: {}, session_id: "s" };
  })();
  try {
    const store = new TaskStore({ root: join(dir, "tasks"), scope: "install-1" }).init();
    const turns = new TaskTurns({ store, query, createServer: fakeCreateServer, free: () => 1e12, ...(limits ? { limits } : {}) });
    const task = store.start(checkRequest("tasks.start", { title: "t", prompt: "p", target: "local", run: false, docs })).task;
    turns.begin(task, "start");
    await until(() => got.length === calls.length && !turns.isRunning(task));
    return got;
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

test("Delegate's read of a notebook: the shared format, the same bytes as Pair's for the same notebook; no picture data", WIN_DELEGATE, async () => {
  const [whole, one, from] = await reads([{ path: "a.ipynb", kind: "notebook", content: NB }], [{ path: "a.ipynb" }, { path: "a.ipynb", cell: 1 }, { path: "a.ipynb", from: 1 }]);
  const doc = ipynbDoc(NB);
  assert.equal(whole.content[0].text, notebookRead(doc, { path: "a.ipynb" }));
  assert.equal(one.content[0].text, notebookRead(doc, { path: "a.ipynb", cell: 1 }));
  assert.equal(from.content[0].text, notebookRead(doc, { path: "a.ipynb", from: 1 }));
  const r = JSON.parse(whole.content[0].text);
  assert.deepEqual(r.cells[1].outputs.map((o) => o.kind), ["stream", "image"]);
  assert.equal(r.cells[1].outputs[1].bytes, 300000);
  assert.equal(r.cells[1].outputs[0].cut, true);
  assert.ok(!whole.content[0].text.includes(PNG.slice(0, 64)), "no picture data");
  assert.equal(JSON.parse(one.content[0].text).cell.outputs[0].text, "y".repeat(1000), "one cell's text in full");
});

test("Delegate's read: cell and from only for notebooks; a long text file is cut, said in numbers", WIN_DELEGATE, async () => {
  const [bad, long] = await reads([{ path: "notes.md", kind: "file", content: "z".repeat(5000) }], [{ path: "notes.md", cell: 0 }, { path: "notes.md" }], { readBytes: 1000 });
  assert.equal(bad.isError, true);
  assert.match(bad.content[0].text, /^refused: cell and from are for notebooks \(\.ipynb\) only$/);
  assert.equal(long.content[0].text, `${"z".repeat(1000)}\n[cut: notes.md is 5000 bytes; a read returns at most 1000, so only its start is shown]`);
});

test("Delegate's read of a hostile notebook (the oversize fixture as an .ipynb): whole, from and cell each bounded at 48 KiB, valid JSON, the same as the shared format gives", WIN_DELEGATE, async () => {
  const { readFileSync } = await import("node:fs");
  const big = JSON.parse(readFileSync(new URL("./fixtures/nb-read/oversize.json", import.meta.url), "utf8"));
  const ipynb = JSON.stringify({ cells: big.cells.map((c) => ({ cell_type: c.type === "markdown" ? "markdown" : "code", id: c.id, metadata: {}, source: c.code, ...(c.type === "markdown" ? {} : { outputs: c.outputs ?? [], execution_count: null }) })), metadata: { kernelspec: { name: "python3" } }, nbformat: 4, nbformat_minor: 5 });
  const calls = [{ path: "big.ipynb" }, { path: "big.ipynb", from: 1 }, { path: "big.ipynb", from: 3 }, { path: "big.ipynb", cell: 0 }, { path: "big.ipynb", cell: 1 }, { path: "big.ipynb", cell: 3 }, { path: "big.ipynb", cell: 4 }];
  const got = await reads([{ path: "big.ipynb", kind: "notebook", content: ipynb }], calls);
  const doc = ipynbDoc(ipynb);
  for (const [i, c] of calls.entries()) {
    const t = got[i].content[0].text;
    assert.equal(t, notebookRead(doc, c), JSON.stringify(c));
    assert.ok(Buffer.byteLength(t) <= 49152, `${JSON.stringify(c)}: ${Buffer.byteLength(t)}`);
    JSON.parse(t);
  }
  const whole = JSON.parse(got[0].content[0].text);
  assert.equal(whole.cells[0].cut, true, "the escaped first cell cut to fit");
  assert.match(whole.note, /Cells 1-4 not shown: read them with \{path, from: 1\}\./);
  assert.ok(JSON.parse(got[4].content[0].text).cell.outputs_not_shown > 0, "a cell's outputs left out are counted");
});
