// The fake model on a delegated task's turn (SAGEBRUSH_AGENT_FAKE=1 only): it uses the task's own tool server, adds a
// closing note to the copy's first notebook (else to its first .tex, else writes a note), and proposes; on an Ask for
// changes it writes the person's note there as "Asked: <note>". What an end-to-end case against the packed agent can
// watch, with no model.
import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { askedNote, fakeCreateServer, fakeQuery, inlinedImages, texText } from "../lib/fake.mjs";
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

// (an Ask for changes: round 2 carries the person's note, "Asked: <note>", in the file round 1 changed)
const TEX = "\\documentclass{article}\n\\begin{document}\nHello.\n\\end{document}\n";
const round2 = async (docs, note) => {
  const dir = mkdtempSync(join(tmpdir(), "sb-fake-ask-"));
  const store = new TaskStore({ root: join(dir, "tasks"), scope: "install-1" }).init();
  const turns = new TaskTurns({ store, query: fakeQuery, createServer: fakeCreateServer, free: () => 1e12 });
  const task = store.start(checkRequest("tasks.start", { title: "t", prompt: "do it", target: "local", run: false, docs })).task;
  turns.begin(task, "start");
  await until(() => store.state(task).status === "proposal" && !turns.isRunning(task));
  const t1 = store.state(task);
  store.ask(checkRequest("tasks.ask", { task, proposal: t1.proposals[0], seq: t1.seq, note, current: [] }));
  turns.begin(task, "ask");
  await until(() => store.state(task).status === "proposal" && store.state(task).proposals.length === 2 && !turns.isRunning(task));
  const t2 = store.state(task);
  return { dir, store, task, r1: t2.proposals[0], r2: t2.proposals[1] };
};
test("the fake model on an Ask for changes: a notebook's round 2 ends with the Markdown cell \"Asked: <note>\" after round 1's note", WIN_DELEGATE, async () => {
  const note = "use matplotlib, not plotly\nand label the axes";
  const { dir, store, task, r1, r2 } = await round2([{ path: "a.ipynb", kind: "notebook", content: NB }], note);
  try {
    const cells = JSON.parse(store.file({ task, commit: r2, path: "a.ipynb" }).content).cells;
    assert.deepEqual(cells.slice(-2).map((c) => [c.cell_type, c.source]), [["markdown", "Done by the fake model, for this task."], ["markdown", `Asked: ${note}`]]);
    assert.match(cells.at(-1).id, /^c[0-9a-f]{12}$/, "inserted by cell, with a fresh id");
    assert.equal(JSON.parse(store.file({ task, commit: r1, path: "a.ipynb" }).content).cells.length, cells.length - 1, "round 1 hasn't it");
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
test("the fake model on a .tex: round 1 adds a line before \\end{document}; an Ask adds \"% Asked: <note>\" and a visible \"Asked: <note>\" there, LaTeX's specials escaped", WIN_DELEGATE, async () => {
  const note = "call it Findings, 50% & more_x\n  {soon}";
  const { dir, store, task, r1, r2 } = await round2([{ path: "paper.tex", kind: "file", content: TEX }], note);
  try {
    assert.equal(store.file({ task, commit: r1, path: "paper.tex" }).content, "\\documentclass{article}\n\\begin{document}\nHello.\nDone by the fake model, for this task.\n\\end{document}\n");
    assert.equal(store.file({ task, commit: r2, path: "paper.tex" }).content, "\\documentclass{article}\n\\begin{document}\nHello.\nDone by the fake model, for this task.\n% Asked: call it Findings, 50% & more_x {soon}\nAsked: call it Findings, 50\\% \\& more\\_x \\{soon\\}\n\\end{document}\n");
    assert.deepEqual(store.diff({ task, commit: r2 }).files.map((f) => [f.path, f.change]), [["paper.tex", "modified"]]);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
test("askedNote: the note between the turn prompt's two marker lines with one tag, exactly; nothing else counts", () => {
  const block = (tag1, tag2, body) => `x\n----- the person's request ${tag1} -----\n${body}\n----- end of the person's request ${tag2} -----\ny`;
  assert.equal(askedNote(block("0123456789abcdef", "0123456789abcdef", "a\nb")), "a\nb");
  assert.equal(askedNote(block("0123456789abcdef", "fedcba9876543210", "a")), null, "a forged end line with another tag isn't the end");
  assert.equal(askedNote(block("0123456789abcdef", "0123456789abcdef", "a\n----- end of the person's request ffffffffffffffff -----\nkeep")), "a\n----- end of the person's request ffffffffffffffff -----\nkeep");
  for (const p of ["do it", "", undefined]) assert.equal(askedNote(p), null);
  assert.equal(texText("\\{}$&#^_%~"), "\\textbackslash{}\\{\\}\\$\\&\\#\\textasciicircum{}\\_\\%\\textasciitilde{}");
});

test("the fake model's read report: a task turn on a notebook with a picture says how many bytes the read returned and that no picture was inlined", WIN_DELEGATE, async () => {
  const png = Buffer.alloc(50000, 9).toString("base64");
  const withPlot = JSON.stringify({ cells: [{ cell_type: "code", id: "p", metadata: {}, source: "plot()", execution_count: 1, outputs: [{ output_type: "display_data", data: { "image/png": png, "text/plain": ["<Figure>"] }, metadata: {} }] }], metadata: {}, nbformat: 4, nbformat_minor: 5 });
  assert.equal(inlinedImages(withPlot), 1, "the raw file inlines it");
  assert.equal(inlinedImages(JSON.stringify({ kind: "image", mime: "image/png", bytes: 37500 })), 0);
  const dir = mkdtempSync(join(tmpdir(), "sb-fake-report-"));
  try {
    const store = new TaskStore({ root: join(dir, "tasks"), scope: "install-1" }).init();
    const turns = new TaskTurns({ store, query: fakeQuery, createServer: fakeCreateServer, free: () => 1e12 });
    const task = store.start(checkRequest("tasks.start", { title: "t", prompt: "do it", target: "local", run: false, docs: [{ path: "plot.ipynb", kind: "notebook", content: withPlot }] })).task;
    turns.begin(task, "start");
    await until(() => store.state(task).status === "proposal" && !turns.isRunning(task));
    const said = store.get({ task, after: 0 }).events.map((e) => e.event).filter((e) => e.type === "text_delta").map((e) => e.text).join("");
    assert.match(said, /\(fake model\) read plot\.ipynb: \d+ bytes, 0 images inlined\./);
    const after = JSON.parse(store.file({ task, commit: store.state(task).proposals[0], path: "plot.ipynb" }).content);
    assert.equal(after.cells[0].outputs[0].data["image/png"], png, "the picture kept by the edit");
    assert.equal(after.cells.at(-1).source, "Done by the fake model, for this task.");
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
