// A Delegate task's workspace_delete: any file of its copy, the documents it started with included, or a folder with
// everything in it; never through or to a link, never outside the copy, through the store's checked paths. The deletion
// is part of the proposal the person reviews, and the base commit keeps what was deleted. A scripted model in place of
// Claude.
import assert from "node:assert/strict";
import { test } from "node:test";
import { spawnSync } from "node:child_process";
import { existsSync, linkSync, mkdirSync, mkdtempSync, readdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fakeCreateServer } from "../lib/fake.mjs";
import { TaskStore } from "../lib/tasks.mjs";
import { TaskTurns } from "../lib/task-turns.mjs";
import { checkRequest } from "../lib/tasks-schema.mjs";
import { blobId } from "../lib/task-git.mjs";
import { removeTaskPath, UnsafePath } from "../lib/task-paths.mjs";

const WIN_DELEGATE = process.platform === "win32" ? { skip: "Delegate refused on win32 in this version" } : {};
const until = async (f, ms = 10000) => { const t = Date.now(); while (!f()) { if (Date.now() - t > ms) throw new Error("timed out"); await new Promise((r) => setTimeout(r, 20)); } };
const NB = JSON.stringify({ cells: [{ cell_type: "code", id: "a", metadata: {}, source: "x = 1", outputs: [], execution_count: null }], metadata: {}, nbformat: 4, nbformat_minor: 5 });

// (a task whose scripted model runs `steps` with its tools, then proposes; the tool answers and the store, after it)
async function runTask(dir, docs, steps) {
  const got = [];
  const query = ({ options }) => (async function* () {
    const tools = options.mcpServers.sagebrush_task.handlers;
    yield { type: "system", subtype: "init", session_id: "s", model: "x", tools: [] };
    const run = async (name, input) => { const r = await tools[name](input); got.push([name, input.path, r.isError ? "refused" : "ok", r.content[0].text]); return r; };
    await steps(run);
    await run("propose", { summary: "x" });
    yield { type: "result", subtype: "success", is_error: false, result: "x", usage: {}, session_id: "s" };
  })();
  const store = new TaskStore({ root: join(dir, "tasks"), scope: "install-1" }).init();
  const turns = new TaskTurns({ store, query, createServer: fakeCreateServer, free: () => 1e12 });
  const task = store.start(checkRequest("tasks.start", { title: "t", prompt: "p", target: "local", run: false, docs })).task;
  turns.begin(task, "start");
  await until(() => store.state(task).status === "proposal" && !turns.isRunning(task));
  const deletes = Object.fromEntries(got.filter(([n]) => n === "workspace_delete").map(([, p, r, t]) => [p, [r, t]]));
  return { store, task, got, deletes };
}

test("workspace_delete: consolidate tmp1.py and tmp2.py into lib.py; both starting documents deleted, the base keeps them, Merge records it", WIN_DELEGATE, async () => {
  const dir = mkdtempSync(join(tmpdir(), "sb-task-delete-"));
  try {
    const T1 = "def one():\n    return 1\n", T2 = "def two():\n    return 2\n";
    const { store, task, got, deletes } = await runTask(dir, [{ path: "tmp1.py", kind: "file", content: T1 }, { path: "tmp2.py", kind: "file", content: T2 }, { path: "a.ipynb", kind: "notebook", content: NB }], async (run) => {
      const a = await run("workspace_read", { path: "tmp1.py" }), b = await run("workspace_read", { path: "tmp2.py" });
      await run("workspace_write", { path: "lib.py", text: a.content[0].text + b.content[0].text });
      await run("workspace_delete", { path: "tmp1.py" });
      await run("workspace_delete", { path: "tmp2.py" });
    });
    assert.deepEqual(got.filter(([n]) => n === "workspace_read").map(([, , r]) => r), ["ok", "ok"]);
    assert.deepEqual(deletes, { "tmp1.py": ["ok", "deleted tmp1.py"], "tmp2.py": ["ok", "deleted tmp2.py"] });
    const t = store.state(task), proposal = t.proposals[0];
    const files = store.diff({ task, commit: proposal }).files;
    assert.deepEqual(files.map((f) => [f.path, f.change]), [["lib.py", "added"], ["tmp1.py", "deleted"], ["tmp2.py", "deleted"]]);
    assert.equal(store.file({ task, commit: proposal, path: "lib.py" }).content, T1 + T2);
    // (the base commit still has both: git keeps what a task deleted)
    assert.equal(store.file({ task, commit: t.base, path: "tmp1.py" }).content, T1);
    assert.equal(store.file({ task, commit: t.base, path: "tmp2.py" }).content, T2);
    assert.throws(() => store.file({ task, commit: proposal, path: "tmp1.py" }), (e) => e.code === "not_found");
    // (the page's Merge of it: mine unchanged, merged = the proposal; the merge commit has lib.py and no tmp files)
    const lib = Buffer.from(T1 + T2);
    const side = (s) => ({ blob: blobId(Buffer.from(s)), content: s });
    const req = checkRequest("tasks.merged", { task, proposal, seq: t.seq, merge_id: "2".repeat(32), files: [
      { path: "lib.py", kind: "file", proposal_blob: blobId(lib), mine: { absent: true }, merged: side(T1 + T2) },
      { path: "tmp1.py", kind: "file", proposal_blob: null, mine: side(T1), merged: { absent: true } },
      { path: "tmp2.py", kind: "file", proposal_blob: null, mine: side(T2), merged: { absent: true } },
    ] });
    const m = await store.merged(req);
    assert.equal(m.recorded, "merge");
    const ls = spawnSync("git", ["--git-dir", store.gitdir(task), "ls-tree", "--name-only", m.commit], { encoding: "utf8" });
    assert.deepEqual(ls.stdout.trim().split("\n"), ["a.ipynb", "lib.py"]);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("workspace_delete: a folder goes with everything in it, starting documents and new files; nothing outside it", WIN_DELEGATE, async () => {
  const dir = mkdtempSync(join(tmpdir(), "sb-task-delete-"));
  try {
    const { store, task, deletes } = await runTask(dir, [{ path: "a.ipynb", kind: "notebook", content: NB }, { path: "docs/b.md", kind: "file", content: "b" }, { path: "docs/deep/c.md", kind: "file", content: "c" }, { path: "keep/d.md", kind: "file", content: "d" }], async (run) => {
      await run("workspace_write", { path: "docs/deep/new.md", text: "n" });
      await run("workspace_write", { path: "scratch/x.md", text: "x" });
      await run("workspace_delete", { path: "docs" });
      await run("workspace_delete", { path: "scratch" });
      await run("workspace_delete", { path: "docs/b.md" });
    });
    assert.deepEqual(deletes.docs, ["ok", "deleted docs: 3 files, 2 folders"]);
    assert.deepEqual(deletes.scratch, ["ok", "deleted scratch: 1 file, 1 folder"]);
    assert.match(deletes["docs/b.md"][1], /^refused: docs\/b\.md isn't in your copy$/);
    assert.deepEqual(readdirSync(store.work(task)).sort(), ["a.ipynb", "keep"]);
    const files = store.diff({ task, commit: store.state(task).proposals[0] }).files;
    assert.deepEqual(files.map((f) => [f.path, f.change]), [["docs/b.md", "deleted"], ["docs/deep/c.md", "deleted"]]);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("workspace_delete: a missing path, an escape and a bad path are refused; nothing outside the copy is touched", WIN_DELEGATE, async () => {
  const dir = mkdtempSync(join(tmpdir(), "sb-task-delete-"));
  try {
    writeFileSync(join(dir, "outside.md"), "keep");
    const { deletes } = await runTask(dir, [{ path: "a.ipynb", kind: "notebook", content: NB }], async (run) => {
      await run("workspace_write", { path: "n.md", text: "n" });
      for (const path of ["gone.md", "no/such/file.md", "../outside.md", "/etc/hostname", "", ".git", ".sagebrush/x", "a/./b"]) await run("workspace_delete", { path });
    });
    assert.match(deletes["gone.md"][1], /^refused: gone\.md isn't in your copy$/);
    assert.match(deletes["no/such/file.md"][1], /^refused: no\/such\/file\.md isn't in your copy$/);
    for (const p of ["../outside.md", "/etc/hostname", "", ".git", ".sagebrush/x", "a/./b"]) assert.equal(deletes[p][0], "refused", p);
    assert.ok(existsSync(join(dir, "outside.md")), "nothing outside the copy");
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("deleteWork: a link, a path through a link, a hard-linked file and a folder holding a link are refused, nothing removed", WIN_DELEGATE, async () => {
  const dir = mkdtempSync(join(tmpdir(), "sb-task-delete-"));
  try {
    const out = join(dir, "outside");
    mkdirSync(out);
    writeFileSync(join(out, "o.md"), "keep");
    const store = new TaskStore({ root: join(dir, "tasks"), scope: "install-1" }).init();
    const task = store.start(checkRequest("tasks.start", { title: "t", prompt: "p", target: "local", run: false, docs: [{ path: "f/a.md", kind: "file", content: "a" }, { path: "g/b.md", kind: "file", content: "b" }] })).task;
    const w = store.work(task);
    symlinkSync(join(out, "o.md"), join(w, "link.md"));
    symlinkSync(out, join(w, "dirlink"));
    symlinkSync(out, join(w, "f", "inner"));
    linkSync(join(out, "o.md"), join(w, "g", "hard.md"));
    const refused = async (path, re) => assert.rejects(store.deleteWork(task, path), (e) => e.code === "forbidden" && re.test(e.message), path);
    await refused("link.md", /^link\.md is a link$/);
    await refused("dirlink", /^dirlink is a link$/);
    await refused("dirlink/o.md", /^dirlink is not a plain folder$/);
    await refused("f", /^f\/inner is a link$/);
    await refused("g/hard.md", /^g\/hard\.md is a file with more than one link$/);
    await refused("g", /^g\/hard\.md is a file with more than one link$/);
    assert.ok(existsSync(join(w, "f", "a.md")) && existsSync(join(w, "g", "b.md")), "a refused folder keeps all it holds");
    assert.deepEqual(readdirSync(out), ["o.md"]);
    // (not working: stale)
    await store.close({ task, seq: store.state(task).seq, proposal: null });
    await assert.rejects(store.deleteWork(task, "f/a.md"), (e) => e.code === "stale");
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("removeTaskPath: a folder over the entry bound is refused whole, before anything is removed", { skip: process.platform === "win32" ? "POSIX rows" : false }, () => {
  const dir = mkdtempSync(join(tmpdir(), "sb-task-delete-"));
  try {
    mkdirSync(join(dir, "big", "sub"), { recursive: true });
    for (const n of ["1", "2", "3"]) writeFileSync(join(dir, "big", "sub", n), n);
    assert.throws(() => removeTaskPath(dir, "big", 3), (e) => e instanceof UnsafePath && e.message === "big holds more than 3 entries");
    assert.deepEqual(readdirSync(join(dir, "big", "sub")).sort(), ["1", "2", "3"]);
    assert.deepEqual(removeTaskPath(dir, "big", 4), { files: 3, folders: 2 });
    assert.ok(!existsSync(join(dir, "big")));
    writeFileSync(join(dir, "one"), "1");
    assert.deepEqual(removeTaskPath(dir, "one"), { files: 1, folders: 0 });
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
