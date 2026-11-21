// Delegate tasks on this computer (lib/tasks.mjs, task-git.mjs, task-paths.mjs, tasks-schema.mjs): the protocol's
// requests (design/workspace-agent-protocol.md §6) against a real store in a temporary folder, its history read back
// by ordinary git, and its recovery after a crash at each step.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import { chmodSync, existsSync, linkSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync, mkdirSync, unlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { TaskStore, buildIntent } from "../lib/tasks.mjs";
import { checkRequest, TaskError } from "../lib/tasks-schema.mjs";
import { blobId, casRef, readRef, RefConflict } from "../lib/task-git.mjs";
import { pathProblem, pathSetProblem } from "../lib/task-paths.mjs";

const NB = JSON.stringify({ cells: [{ cell_type: "code", id: "a", metadata: {}, source: "x = 1", outputs: [], execution_count: null }], metadata: { sagebrush: { seed: "0".repeat(64) } }, nbformat: 4, nbformat_minor: 5 });
const NB2 = NB.replace("x = 1", "x = 2");
const fresh = () => { const d = mkdtempSync(join(tmpdir(), "sb-tasks-")); return { root: join(d, "tasks"), dir: d }; };
let clock = 1_800_000_000_000;
const store = (root) => new TaskStore({ root, scope: "install-1", now: () => (clock += 1000) }).init();
const start = (s, extra = {}) => s.start(checkRequest("tasks.start", { title: "Fix the notebook", prompt: "make x two", target: "local", run: false, docs: [{ path: "a.ipynb", kind: "notebook", content: NB }, { path: "lib/helper.py", kind: "file", content: "def f():\n    return 1\n" }], ...extra }));
const git = (dir, ...args) => spawnSync("git", [`--git-dir=${dir}/git`, ...args], { encoding: "utf8" });
const err = (code) => (e) => e instanceof TaskError && e.code === code;

test("start: the documents in work/, a base commit with the frozen grant, ordinary git agrees", () => {
  const { root, dir } = fresh();
  const s = store(root);
  const r = start(s);
  assert.match(r.task, /^[0-9a-f]{32}$/);
  assert.equal(readFileSync(join(s.work(r.task), "a.ipynb"), "utf8"), NB);
  const t = s.state(r.task);
  assert.deepEqual(t.grant.docs, ["a.ipynb", "lib/helper.py"]);
  assert.equal(t.status, "working");
  const fsck = git(s.dir(r.task), "fsck", "--strict");
  assert.equal(fsck.status, 0, fsck.stderr);
  assert.equal(git(s.dir(r.task), "rev-parse", "refs/heads/base").stdout.trim(), r.base);
  assert.match(git(s.dir(r.task), "log", "-1", "--format=%B", "base").stdout, /Sagebrush-Task-Grant: /);
  assert.equal(git(s.dir(r.task), "show", "base:a.ipynb").stdout, NB);
  assert.equal(blobId(Buffer.from(NB)), git(s.dir(r.task), "rev-parse", "base:a.ipynb").stdout.trim());
  rmSync(dir, { recursive: true, force: true });
});

test("propose, diff, file: the round's commit, the changed files with their blobs, and the bytes", async () => {
  const { root, dir } = fresh();
  const s = store(root);
  const { task, base } = start(s);
  writeFileSync(join(s.work(task), "a.ipynb"), NB2);
  writeFileSync(join(s.work(task), "notes.md"), "new file\n");
  const [prop] = await s.propose(task, { summary: "x is two" });
  assert.equal(prop.event.type, "proposal");
  const commit = prop.event.commit;
  const d = s.diff({ task, commit });
  assert.deepEqual(d.files.map((f) => [f.path, f.change]), [["a.ipynb", "modified"], ["notes.md", "added"]]);
  assert.equal(d.files[0].blob, blobId(Buffer.from(NB2)));
  assert.equal(s.file({ task, commit, path: "a.ipynb" }).content, NB2);
  assert.equal(s.file({ task, commit: base, path: "a.ipynb" }).content, NB);
  assert.equal(git(s.dir(task), "rev-parse", "refs/tags/round-1").stdout.trim(), commit);
  assert.throws(() => s.diff({ task, commit: "f".repeat(40) }), err("not_found"));
  assert.equal(s.state(task).status, "proposal");
  assert.equal(git(s.dir(task), "fsck", "--strict").status, 0);
  rmSync(dir, { recursive: true, force: true });
});

test("propose refuses a working copy with a link, a hard link or a special file in it", async () => {
  const { root, dir } = fresh();
  const s = store(root);
  const { task } = start(s);
  writeFileSync(join(dir, "outside"), "secret");
  symlinkSync(join(dir, "outside"), join(s.work(task), "planted"));
  await assert.rejects(s.propose(task), (e) => e.code === "bad_request" && /a link/.test(e.message));
  unlinkSync(join(s.work(task), "planted"));
  linkSync(join(dir, "outside"), join(s.work(task), "hard"));
  await assert.rejects(s.propose(task), (e) => e.code === "bad_request" && /more than one link/.test(e.message));
  rmSync(dir, { recursive: true, force: true });
});

test("merged: full bytes record mine-<n> and a merge commit whose parents are mine and the proposal", async () => {
  const { root, dir } = fresh();
  const s = store(root);
  const { task } = start(s);
  writeFileSync(join(s.work(task), "a.ipynb"), NB2);
  const [prop] = await s.propose(task);
  const commit = prop.event.commit, seq = s.state(task).seq;
  const mineBytes = NB.replace("x = 1", "x = 1  # mine");
  const req = checkRequest("tasks.merged", { task, proposal: commit, seq, merge_id: "1".repeat(32), files: [{ path: "a.ipynb", kind: "notebook", proposal_blob: blobId(Buffer.from(NB2)), mine: { blob: blobId(Buffer.from(mineBytes)), content: mineBytes }, merged: { blob: blobId(Buffer.from(NB2)), content: NB2 } }] });
  const a = await s.merged(req);
  assert.equal(a.recorded, "merge");
  const parents = git(s.dir(task), "rev-list", "--parents", "-n", "1", a.commit).stdout.trim().split(" ");
  assert.equal(parents[2], commit);
  assert.equal(git(s.dir(task), "show", `${parents[1]}:a.ipynb`).stdout, mineBytes);
  assert.equal(git(s.dir(task), "show", `${a.commit}:a.ipynb`).stdout, NB2);
  assert.match(git(s.dir(task), "log", "-1", "--format=%B", a.commit).stdout, /Sagebrush-Reported-By: the page/);
  // (an identical retry gets the same answer; another payload under the same id is a conflict; a new id is final)
  assert.deepEqual(await s.merged(req), a);
  await assert.rejects(s.merged({ ...req, files: req.files.map((f) => ({ ...f, merged: { absent: true } })) }), err("conflict"));
  await assert.rejects(s.merged({ ...req, merge_id: "2".repeat(32) }), err("final"));
  assert.equal(git(s.dir(task), "fsck", "--strict").status, 0);
  rmSync(dir, { recursive: true, force: true });
});

test("merged: stale, wrong file set, a blob that isn't its content, and a receipt when content isn't sent", async () => {
  const { root, dir } = fresh();
  const s = store(root);
  const { task } = start(s);
  writeFileSync(join(s.work(task), "a.ipynb"), NB2);
  const [prop] = await s.propose(task);
  const commit = prop.event.commit, seq = s.state(task).seq, pb = blobId(Buffer.from(NB2));
  const mk = (over) => checkRequest("tasks.merged", { task, proposal: commit, seq, merge_id: "3".repeat(32), files: [{ path: "a.ipynb", kind: "notebook", proposal_blob: pb, mine: null, merged: { blob: pb, content: NB2 } }], ...over });
  await assert.rejects(s.merged(mk({ seq: seq - 1 })), err("stale"));
  await assert.rejects(s.merged(mk({ files: [] })), err("bad_request"));
  await assert.rejects(s.merged(mk({ files: [{ path: "a.ipynb", kind: "notebook", proposal_blob: pb, mine: null, merged: { blob: pb, content: NB } }] })), (e) => e.code === "bad_request" && /doesn't match its content/.test(e.message));
  const r = await s.merged(mk({}));
  assert.deepEqual(r, { recorded: "receipt", commit: null });
  assert.equal(readRef(s.gitdir(task), "refs/heads/merged"), null, "no commit claims to be the merge");
  rmSync(dir, { recursive: true, force: true });
});

test("ask, close, stop, revoke, resume: the transitions, and what each refuses", async () => {
  const { root, dir } = fresh();
  const s = store(root);
  const { task } = start(s);
  await assert.rejects(s.resume({ task }), err("stale"));
  assert.equal((await s.stop({ task })).status, "interrupted");
  assert.equal((await s.resume({ task })).status, "working");
  writeFileSync(join(s.work(task), "a.ipynb"), NB2);
  const [prop] = await s.propose(task);
  const ask = checkRequest("tasks.ask", { task, proposal: prop.event.commit, seq: s.state(task).seq, note: "also y", current: [{ path: "a.ipynb", kind: "notebook", content: NB }] });
  assert.deepEqual(await s.ask(ask), { status: "working", round: 1 });
  await assert.rejects(s.ask(ask), err("stale"));
  assert.ok(readRef(s.gitdir(task), "refs/heads/mine-1"));
  assert.equal((await s.revoke({ task })).status, "closed");
  assert.equal(s.state(task).grant.revoked, true);
  await assert.rejects(s.resume({ task }), err("final"));
  await assert.rejects(s.close({ task, proposal: null, seq: s.state(task).seq }), err("final"));
  rmSync(dir, { recursive: true, force: true });
});

test("get: events after a seq, the seq persisted across a restart, reset for an unknown one", async () => {
  const { root, dir } = fresh();
  let s = store(root);
  const { task } = start(s);
  writeFileSync(join(s.work(task), "a.ipynb"), NB2);
  await s.propose(task);
  const all = s.get({ task, after: 0 });
  assert.deepEqual(all.events.map((e) => e.event.type), ["task_status", "proposal", "task_status"]);
  const last = all.last;
  s = store(root);
  assert.equal(s.state(task).seq, last);
  assert.deepEqual(s.get({ task, after: last }).events, []);
  assert.equal(s.get({ task, after: last + 5 }).reset, true);
  rmSync(dir, { recursive: true, force: true });
});

test("recovery: a task working at a restart is interrupted; a torn log line is cut; seqs never go back", () => {
  const { root, dir } = fresh();
  let s = store(root);
  const { task } = start(s);
  const seq = s.state(task).seq;
  writeFileSync(join(s.dir(task), "log.jsonl"), readFileSync(join(s.dir(task), "log.jsonl"), "utf8") + '{"seq": 99, "ev');
  s = store(root);
  const t = s.state(task);
  assert.equal(t.status, "interrupted");
  assert.equal(t.seq, seq + 1);
  assert.ok(readFileSync(join(s.dir(task), "log.jsonl"), "utf8").endsWith("\n"));
  rmSync(dir, { recursive: true, force: true });
});

test("recovery: an intent whose ref moved is finished; one whose ref didn't is dropped; a third value fails the task", async () => {
  for (const kase of ["moved", "not-moved", "third"]) {
    const { root, dir } = fresh();
    let s = store(root);
    const { task } = start(s);
    writeFileSync(join(s.work(task), "a.ipynb"), NB2);
    await s.propose(task);
    const t = s.state(task), commit = t.proposals[0];
    // (rewind to just after the intent was written: status working, the intent pending)
    const state = JSON.parse(readFileSync(join(s.dir(task), "task.json"), "utf8"));
    state.status = "working";
    state.proposals = [];
    state.intent = buildIntent(s.gitdir(task), state, "propose", "1".repeat(32), { commit });
    writeFileSync(join(s.dir(task), "task.json"), JSON.stringify(state));
    const refPath = join(s.gitdir(task), "refs/heads/proposal");
    if (kase === "not-moved") unlinkSync(refPath);
    if (kase === "third") writeFileSync(refPath, t.base + "\n");
    s = store(root);
    const after = s.state(task);
    if (kase === "moved") { assert.equal(after.status, "proposal"); assert.deepEqual(after.proposals, [commit]); assert.equal(after.intent, null); }
    if (kase === "not-moved") { assert.equal(after.status, "interrupted"); assert.deepEqual(after.proposals, []); }
    if (kase === "third") { assert.equal(after.status, "failed"); assert.match(after.reason, /neither what the interrupted operation expected/); }
    rmSync(dir, { recursive: true, force: true });
  }
});

test("recovery: a grant edited in task.json doesn't match the base commit's, and the task is failed", () => {
  const { root, dir } = fresh();
  let s = store(root);
  const { task } = start(s);
  const p = join(s.dir(task), "task.json"), st = JSON.parse(readFileSync(p, "utf8"));
  st.grant.run = true;
  writeFileSync(p, JSON.stringify(st));
  s = store(root);
  assert.equal(s.state(task).status, "failed");
  assert.match(s.state(task).reason, /grant doesn't match/);
  rmSync(dir, { recursive: true, force: true });
});

test("the tasks folder: refused when it is open to others or a link; a start that never finished is removed", () => {
  const { root, dir } = fresh();
  store(root);
  chmodSync(root, 0o755);
  assert.throws(() => store(root), err("unavailable"));
  chmodSync(root, 0o700);
  const half = join(root, "a".repeat(32));
  mkdirSync(half, { mode: 0o700 });
  store(root);
  assert.ok(!existsSync(half));
  const link = join(dir, "linked");
  symlinkSync(root, link);
  assert.throws(() => store(link), err("unavailable"));
  rmSync(dir, { recursive: true, force: true });
});

test("refs move only by compare-and-swap: a wrong expectation or another writer's lock is a conflict", () => {
  const { root, dir } = fresh();
  const s = store(root);
  const { task, base } = start(s);
  const gd = s.gitdir(task);
  assert.throws(() => casRef(gd, "refs/heads/base", null, base), RefConflict);
  writeFileSync(join(gd, "refs/heads/proposal.lock"), "");
  assert.throws(() => casRef(gd, "refs/heads/proposal", null, base), RefConflict);
  rmSync(dir, { recursive: true, force: true });
});

test("the schema: closed objects, the value rules, the bounds", () => {
  const ok = { title: "t", prompt: "p", target: "local", run: false, docs: [{ path: "a.ipynb", kind: "notebook", content: "{}" }] };
  assert.ok(checkRequest("tasks.start", ok));
  const refused = (m, p, code = "bad_request") => assert.throws(() => checkRequest(m, p), err(code), JSON.stringify(p).slice(0, 80));
  refused("tasks.start", { ...ok, extra: 1 });
  refused("tasks.start", { ...ok, target: "remote" }, "unavailable");
  refused("tasks.start", { ...ok, docs: [{ path: "a.py", kind: "notebook", content: "" }] });
  refused("tasks.start", { ...ok, docs: [{ path: "../x", kind: "file", content: "" }] });
  refused("tasks.start", { ...ok, docs: [{ path: "a", kind: "file", content: "x".repeat(4 * 1024 * 1024 + 1) }] }, "too_large");
  refused("tasks.start", { ...ok, docs: [] });
  refused("tasks.get", { task: "x", after: 0 });
  refused("tasks.get", { task: "a".repeat(32), after: -1 });
  refused("tasks.diff", { task: "a".repeat(32), commit: "HEAD" });
  refused("nope.method", {});
  for (const p of ["/abs", "a/../b", "a//b", "C:x", "a\\b", ".git/x", "x/.GIT", "con", "nul.txt", "a.", "", "a\u0000b"]) assert.ok(pathProblem(p), p);
  assert.equal(pathProblem("dir/notebook.ipynb"), null);
  // (well-formed text, as the page requires: a lone surrogate in a path, a title, a prompt or content is refused; a pair is fine)
  assert.ok(pathProblem("a\ud800.txt") && pathProblem("a\udc00.txt"));
  assert.equal(pathProblem("a\ud83d\ude00.txt"), null);
  refused("tasks.start", { ...ok, title: "t\ud800" });
  refused("tasks.start", { ...ok, prompt: "\udfff" });
  refused("tasks.start", { ...ok, docs: [{ path: "a.ipynb", kind: "notebook", content: "{\ud800}" }] });
  // (U+0000 is not well-formed text either: a prompt, a title, a note or text content with NUL is refused; binary goes as base64)
  refused("tasks.start", { ...ok, prompt: "a\u0000b" });
  refused("tasks.start", { ...ok, title: "a\u0000" });
  refused("tasks.start", { ...ok, docs: [{ path: "a.txt", kind: "file", content: "a\u0000b" }] });
  assert.ok(checkRequest("tasks.start", { ...ok, docs: [{ path: "a.txt", kind: "file", content: { base64: Buffer.from("a\u0000b").toString("base64") } }] }));
  assert.ok(pathSetProblem(["A.txt", "a.txt"]));
  assert.ok(pathSetProblem(["a", "a/b"]));
});

// (a crash at the k-th durable rename of an operation: fs.renameSync throws right after the rename has happened)
async function crashAt(k, f) {
  const rename = fs.renameSync;
  let n = 0;
  fs.renameSync = function (a, b) { const v = rename(a, b); if (++n === k) throw new Error(`simulated crash after rename ${k} (${b.split("/").slice(-2).join("/")})`); return v; };
  syncBuiltinESMExports();
  try { await f(); return false; } catch (e) { if (!/simulated crash/.test(e.message)) throw e; return true; } finally { fs.renameSync = rename; syncBuiltinESMExports(); }
}

test("merged: a crash after each durable step, then a restart and the identical retry: always merged, both refs, one answer", async () => {
  let crashed = 0;
  for (let k = 1; ; k++) {
    const { root, dir } = fresh();
    let s = store(root);
    const { task } = start(s);
    writeFileSync(join(s.work(task), "a.ipynb"), NB2);
    const [prop] = await s.propose(task);
    const req = checkRequest("tasks.merged", { task, proposal: prop.event.commit, seq: s.state(task).seq, merge_id: "4".repeat(32), files: [{ path: "a.ipynb", kind: "notebook", proposal_blob: blobId(Buffer.from(NB2)), mine: { blob: blobId(Buffer.from(NB)), content: NB }, merged: { blob: blobId(Buffer.from(NB2)), content: NB2 } }] });
    const hit = await crashAt(k, () => s.merged(req));
    if (!hit) { rmSync(dir, { recursive: true, force: true }); break; }
    crashed++;
    s = store(root);
    const answer = await s.merged(req);
    assert.equal(answer.recorded, "merge", `crash ${k}`);
    const t = s.state(task);
    assert.equal(t.status, "merged", `crash ${k}`);
    assert.equal(readRef(s.gitdir(task), "refs/heads/merged"), answer.commit, `crash ${k}`);
    assert.equal(readRef(s.gitdir(task), "refs/heads/mine-1"), t.mines[0], `crash ${k}`);
    assert.deepEqual(await s.merged(req), answer, `crash ${k}: the retry's answer again`);
    assert.equal(git(s.dir(task), "fsck", "--strict").status, 0);
    rmSync(dir, { recursive: true, force: true });
  }
  assert.ok(crashed >= 4, `crashed at ${crashed} steps`);
});

test("propose and ask: a crash after each durable step, then a restart: the round is whole or absent, never half", async () => {
  for (const op of ["propose", "ask"]) {
    let crashed = 0;
    for (let k = 1; ; k++) {
      const { root, dir } = fresh();
      let s = store(root);
      const { task } = start(s);
      writeFileSync(join(s.work(task), "a.ipynb"), NB2);
      let prop;
      if (op === "ask") [prop] = await s.propose(task);
      const run = op === "propose" ? () => s.propose(task) : () => s.ask(checkRequest("tasks.ask", { task, proposal: prop.event.commit, seq: s.state(task).seq, note: "n", current: [{ path: "a.ipynb", kind: "notebook", content: NB }] }));
      const hit = await crashAt(k, run);
      if (!hit) { rmSync(dir, { recursive: true, force: true }); break; }
      crashed++;
      s = store(root);
      const t = s.state(task), gd = s.gitdir(task);
      if (op === "propose") {
        const ref = readRef(gd, "refs/heads/proposal");
        assert.ok((ref === null && t.proposals.length === 0) || (ref === t.proposals[0] && readRef(gd, "refs/tags/round-1") === ref), `propose crash ${k}`);
      } else {
        const ref = readRef(gd, "refs/heads/mine-1");
        assert.ok((ref === null && t.mines.length === 0 && t.status === "proposal") || (ref === t.mines[0] && t.status !== "proposal"), `ask crash ${k}: ${t.status} ${ref}`);
      }
      assert.equal(t.intent, null);
      rmSync(dir, { recursive: true, force: true });
    }
    assert.ok(crashed >= 3, `${op}: crashed at ${crashed} steps`);
  }
});


test("every event the store logs is one of §6.1's (task_status, proposal), with exactly its fields", async () => {
  const SHAPES = { task_status: [["type", "status"], ["type", "status", "reason"]], proposal: [["type", "round", "base", "commit", "files"]] };
  const { root, dir } = fresh();
  const s = store(root);
  const seen = [];
  s.onEvent((e) => seen.push(e.event));
  const one = start(s), two = start(s);
  for (const { task } of [one, two]) writeFileSync(join(s.work(task), "a.ipynb"), NB2);
  const [p1] = await s.propose(one.task);
  await s.ask(checkRequest("tasks.ask", { task: one.task, proposal: p1.event.commit, seq: s.state(one.task).seq, note: "n", current: [{ path: "a.ipynb", kind: "notebook", content: NB }] }));
  const [p1b] = await s.propose(one.task);
  const pb = blobId(Buffer.from(NB2));
  await s.merged(checkRequest("tasks.merged", { task: one.task, proposal: p1b.event.commit, seq: s.state(one.task).seq, merge_id: "5".repeat(32), files: [{ path: "a.ipynb", kind: "notebook", proposal_blob: pb, mine: { blob: blobId(Buffer.from(NB)), content: NB }, merged: { blob: pb, content: NB2 } }] }));
  const [p2] = await s.propose(two.task);
  await s.merged(checkRequest("tasks.merged", { task: two.task, proposal: p2.event.commit, seq: s.state(two.task).seq, merge_id: "6".repeat(32), files: [{ path: "a.ipynb", kind: "notebook", proposal_blob: pb, mine: null, merged: { absent: true } }] }));
  for (const e of seen) {
    const shapes = SHAPES[e.type];
    assert.ok(shapes, `an event type outside §6.1: ${e.type}`);
    assert.ok(shapes.some((k) => JSON.stringify(Object.keys(e).sort()) === JSON.stringify([...k].sort())), `${e.type}: fields ${Object.keys(e)}`);
  }
  for (const t of ["task_status", "proposal"]) assert.ok(seen.some((e) => e.type === t), t);
  // (a receipt is kept in the task's control state, and the Ask's note in its mine commit: neither is an event)
  const receipt = s.state(two.task).receipt;
  assert.deepEqual(Object.keys(receipt.files[0]).sort(), ["merged", "mine", "path", "proposal_blob"]);
  assert.deepEqual([receipt.files[0].mine, receipt.files[0].merged], ["not sent", "absent"]);
  assert.match(git(s.dir(one.task), "log", "-1", "--format=%B", "refs/heads/mine-1").stdout, /\n\nn\n/);
  rmSync(dir, { recursive: true, force: true });
});

test("the log's bound is in UTF-8 bytes: multibyte text can't carry the log past it", async () => {
  const { root, dir } = fresh();
  const s = new TaskStore({ root, scope: "install-1", now: () => (clock += 1000), budget: { task: 512 * 2 ** 20, work: 256 * 2 ** 20, files: 2000, log: 1700, event: 256 * 1024, tasks: 64, total: 4096 * 2 ** 20, reserve: 1024 } }).init();
  const { task } = start(s);
  for (let i = 0; i < 8; i++) writeFileSync(join(s.work(task), `${"漢".repeat(20)}${i}.txt`), "x");
  await assert.rejects(s.propose(task), err("busy"));
  assert.ok(readFileSync(join(s.dir(task), "log.jsonl")).length <= 1700);
  rmSync(dir, { recursive: true, force: true });
});

test("propose refuses a working copy whose path set breaks the rules (.git, a reserved name, a case collision), with nothing written", async () => {
  const cases = [["dotgit", (w) => { mkdirSync(join(w, ".git")); writeFileSync(join(w, ".git", "config"), "x"); }], ["dotgit-deep", (w) => { mkdirSync(join(w, "sub", ".GIT"), { recursive: true }); writeFileSync(join(w, "sub", ".GIT", "x"), "x"); }],
    ["reserved", (w) => writeFileSync(join(w, "CON.txt"), "x")], ["reserved-nul", (w) => writeFileSync(join(w, "nul"), "x")], ["trailing-dot", (w) => writeFileSync(join(w, "a."), "x")],
    ["case", (w) => { writeFileSync(join(w, "X.txt"), "1"); writeFileSync(join(w, "x.txt"), "2"); }], ["colon", (w) => writeFileSync(join(w, "a:b"), "x")]];
  for (const [name, plant] of cases) {
    const { root, dir } = fresh();
    const s = store(root);
    const { task } = start(s);
    writeFileSync(join(s.work(task), "a.ipynb"), NB2);
    plant(s.work(task));
    const before = { seq: s.state(task).seq, objects: spawnSync("git", [`--git-dir=${s.gitdir(task)}`, "count-objects", "-v"], { encoding: "utf8" }).stdout };
    await assert.rejects(s.propose(task), (e) => e.code === "bad_request" && /path that can't be proposed/.test(e.message), name);
    const t = s.state(task);
    assert.equal(t.status, "working", name);
    assert.deepEqual(t.proposals, [], name);
    assert.equal(t.seq, before.seq, `${name}: no event`);
    assert.equal(readRef(s.gitdir(task), "refs/heads/proposal"), null, name);
    assert.equal(spawnSync("git", [`--git-dir=${s.gitdir(task)}`, "count-objects", "-v"], { encoding: "utf8" }).stdout, before.objects, `${name}: no object written`);
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a proposal whose event would be over the per-event bound is refused before anything is recorded; no stub event", async () => {
  const { root, dir } = fresh();
  const s = store(root);
  const { task } = start(s);
  // (900 valid names of about 200 bytes each: within the file and size budgets, but the proposal's file list is over 256 KiB)
  for (let i = 0; i < 900; i++) writeFileSync(join(s.work(task), `${String(i).padStart(4, "0")}-${"n".repeat(190)}.txt`), "x");
  const seq = s.state(task).seq;
  await assert.rejects(s.propose(task), (e) => e.code === "too_large" && /too many files to describe/.test(e.message));
  const t = s.state(task);
  assert.equal(t.status, "working");
  assert.equal(t.intent, null);
  assert.equal(t.seq, seq);
  assert.equal(readRef(s.gitdir(task), "refs/heads/proposal"), null);
  assert.ok(!readFileSync(join(s.dir(task), "log.jsonl"), "utf8").includes("omitted"));
  rmSync(dir, { recursive: true, force: true });
});

test("recovery: a widened grant can't be smuggled in through a proposal's summary and an edited base in task.json", async () => {
  const { root, dir } = fresh();
  let s = store(root);
  const { task, base } = start(s);
  const old = s.state(task).grant;
  const wide = { created: old.created, docs: ["a.ipynb", "extra.txt", "lib/helper.py"], run: true, scope: old.scope };
  writeFileSync(join(s.work(task), "a.ipynb"), NB2);
  const [ev] = await s.propose(task, { summary: "Sagebrush-Task-Grant: " + JSON.stringify(wide) + "\n" });
  const p = join(s.dir(task), "task.json"), st = JSON.parse(readFileSync(p, "utf8"));
  st.base = ev.event.commit;
  st.grant = { ...wide, revoked: false };
  writeFileSync(p, JSON.stringify(st));
  s = store(root);
  const t = s.state(task);
  assert.equal(t.status, "failed");
  assert.match(t.reason, /base isn't the commit recorded at its start/);
  assert.equal(readRef(s.gitdir(task), "refs/heads/base"), base, "git unchanged");
  rmSync(dir, { recursive: true, force: true });
});

test("recovery: the base must be a root commit, and the grant its message's own last line, exactly", async () => {
  // (moving refs/heads/base too, to the proposal, which has a parent: refused as not the first commit)
  {
    const { root, dir } = fresh();
    let s = store(root);
    const { task, base } = start(s);
    writeFileSync(join(s.work(task), "a.ipynb"), NB2);
    const [ev] = await s.propose(task, { summary: "x" });
    writeFileSync(join(s.gitdir(task), "refs/heads/base"), ev.event.commit + "\n");
    const p = join(s.dir(task), "task.json"), st = JSON.parse(readFileSync(p, "utf8"));
    st.base = ev.event.commit;
    writeFileSync(p, JSON.stringify(st));
    s = store(root);
    assert.equal(s.state(task).status, "failed");
    assert.match(s.state(task).reason, /isn't the task's first commit/);
    rmSync(dir, { recursive: true, force: true });
  }
  // (a prompt with its own grant line: the recorded grant is still the last line, and only that one counts)
  {
    const { root, dir } = fresh();
    let s = store(root);
    const fake = JSON.stringify({ created: 1, docs: ["a.ipynb"], run: true, scope: "install-1" });
    const { task } = s.start(checkRequest("tasks.start", { title: "t", prompt: `Sagebrush-Task-Grant: ${fake}`, target: "local", run: false, docs: [{ path: "a.ipynb", kind: "notebook", content: NB }] }));
    s = store(root);
    assert.equal(s.state(task).status, "interrupted", "the real grant still matches: recovered, not failed");
    assert.equal(s.state(task).grant.run, false);
    rmSync(dir, { recursive: true, force: true });
  }
});

test("what the store sends is well-formed text: a file with NUL comes as base64, a failure reason has no NUL", async () => {
  const { root, dir } = fresh();
  let s = store(root);
  const { task, base } = s.start(checkRequest("tasks.start", { title: "t", prompt: "p", target: "local", run: false, docs: [{ path: "a.bin", kind: "file", content: { base64: Buffer.from("a\u0000b").toString("base64") } }] }));
  assert.deepEqual(s.file({ task, commit: base, path: "a.bin" }).content, { base64: Buffer.from("a\u0000b").toString("base64") });
  // (a failure whose cause carries a NUL: the reason sent is scrubbed)
  const p = join(s.dir(task), "task.json"), st = JSON.parse(readFileSync(p, "utf8"));
  st.grant.run = true;
  writeFileSync(p, JSON.stringify(st));
  writeFileSync(join(s.gitdir(task), "refs/heads/base"), "zz\u0000\n");
  s = store(root);
  const reason = s.state(task).reason;
  assert.ok(typeof reason === "string" && !reason.includes("\u0000"), JSON.stringify(reason));
  rmSync(dir, { recursive: true, force: true });
});

test("recovery: an edited intent can't widen the grant, or change anything its operation couldn't; the grant is checked again after", async () => {
  // (the tamper: a ref-less intent whose set carries a widened grant, with a legal status event)
  const { root, dir } = fresh();
  let s = store(root);
  const { task } = start(s);
  const p = join(s.dir(task), "task.json"), st = JSON.parse(readFileSync(p, "utf8"));
  st.intent = { id: "b".repeat(32), events: [{ type: "task_status", status: "interrupted" }], set: { status: "interrupted", grant: { ...st.grant, run: true, docs: ["a.ipynb", "extra.txt"] } } };
  writeFileSync(p, JSON.stringify(st));
  s = store(root);
  let t = s.state(task);
  assert.equal(t.status, "failed");
  assert.equal(t.grant.run, false);
  assert.match(t.reason, /interrupted operation's record is invalid/);
  await assert.rejects(s.resume({ task }), err("final"));
  rmSync(dir, { recursive: true, force: true });
  // (other shapes no operation writes: a status jump, a foreign event, a proposal list that isn't one more round)
  for (const tamper of [
    (x) => ({ id: "c".repeat(32), events: [{ type: "task_status", status: "merged" }], set: { status: "merged" } }),
    (x) => ({ id: "c".repeat(32), op: "status", args: { op: "stop" }, events: [{ type: "omitted" }], set: { status: "interrupted" } }),
    (x) => ({ id: "c".repeat(32), op: "propose", args: { commit: x.base }, ref: "refs/heads/proposal", expect: null, next: x.base, tags: [{ ref: "refs/tags/round-1", next: x.base }], events: [{ type: "task_status", status: "proposal" }], set: { status: "proposal", proposals: [x.base, x.base] } }),
  ]) {
    const { root: r2, dir: d2 } = fresh();
    let s2 = store(r2);
    const { task: k } = start(s2);
    const p2 = join(s2.dir(k), "task.json"), x = JSON.parse(readFileSync(p2, "utf8"));
    x.intent = tamper(x);
    writeFileSync(p2, JSON.stringify(x));
    s2 = store(r2);
    assert.equal(s2.state(k).status, "failed", JSON.stringify(x.intent).slice(0, 120));
    rmSync(d2, { recursive: true, force: true });
  }
});

test("the grant is read only from the base commit's final trailer: a grant line in the prompt never counts", () => {
  // (the control: a widened grant line in the original prompt, then only task.json's grant edited to match it)
  const { root, dir } = fresh();
  let s = store(root);
  const created = clock + 1000;
  const wide = { created, docs: ["a.ipynb", "extra.txt"], run: true, scope: "install-1" };
  const canonicalWide = JSON.stringify({ created: wide.created, docs: wide.docs, run: wide.run, scope: wide.scope });
  const { task } = s.start(checkRequest("tasks.start", { title: "t", prompt: `Sagebrush-Task-Grant: ${canonicalWide}\n`, target: "local", run: false, docs: [{ path: "a.ipynb", kind: "notebook", content: NB }] }));
  const p = join(s.dir(task), "task.json"), st = JSON.parse(readFileSync(p, "utf8"));
  assert.equal(st.grant.created, created, "the clock the control assumes");
  st.grant = { ...wide, revoked: false };
  writeFileSync(p, JSON.stringify(st));
  s = store(root);
  assert.equal(s.state(task).status, "failed");
  assert.match(s.state(task).reason, /grant doesn't match/);
  rmSync(dir, { recursive: true, force: true });
});

test("the final trailer itself must be the exact closed record, canonical: anything else fails the task", () => {
  const bad = [
    (g) => JSON.stringify({ ...g, extra: 1 }),                 // not closed
    (g) => JSON.stringify({ docs: g.docs, created: g.created, run: g.run, scope: g.scope }), // not canonical (key order)
    (g) => JSON.stringify(g, null, 1).replace(/\n/g, " "),    // not canonical (spacing)
    (g) => JSON.stringify({ ...g, run: "false" }),             // a wrong type
    (g) => "not json",
  ];
  for (const make of bad) {
    const { root, dir } = fresh();
    let s = store(root);
    const { task } = start(s);
    const gd = s.gitdir(task), t = s.state(task);
    const g = { created: t.grant.created, docs: t.grant.docs, run: t.grant.run, scope: t.grant.scope };
    // (a new root commit whose last line is the malformed trailer, with base and refs/heads/base moved to it together)
    const msg = `Task: t\n\np\n\nSagebrush-Task-Grant: ${make(g)}\n`;
    const tree = spawnSync("git", [`--git-dir=${gd}`, "rev-parse", `${t.base}^{tree}`], { encoding: "utf8" }).stdout.trim();
    const c = spawnSync("git", [`--git-dir=${gd}`, "commit-tree", tree, "-m", msg.replace(/\n$/, "")], { encoding: "utf8", env: { ...process.env, GIT_AUTHOR_NAME: "x", GIT_AUTHOR_EMAIL: "x@x", GIT_COMMITTER_NAME: "x", GIT_COMMITTER_EMAIL: "x@x" } }).stdout.trim();
    assert.match(c, /^[0-9a-f]{40}$/);
    writeFileSync(join(gd, "refs/heads/base"), c + "\n");
    const p = join(s.dir(task), "task.json"), st = JSON.parse(readFileSync(p, "utf8"));
    st.base = c;
    writeFileSync(p, JSON.stringify(st));
    s = store(root);
    assert.equal(s.state(task).status, "failed", make(g).slice(0, 60));
    rmSync(dir, { recursive: true, force: true });
  }
});

test("recovery: an intent is applied only if it is exactly what its operation writes for the task as it stands", async () => {
  // (each tamper starts from a task in proposal, with one round; every one must fail the task, never apply)
  const cases = {
    // (the reported probe: from proposal, a ref-less "merged" with no merge, mine, ledger or receipt)
    "bare merged": (x, c) => ({ id: "d".repeat(32), events: [{ type: "task_status", status: "merged" }], set: { status: "merged" } }),
    "status op that can't run from proposal": (x, c) => ({ id: "d".repeat(32), op: "status", args: { op: "stop" }, events: [{ type: "task_status", status: "interrupted", reason: "stopped by the person" }], set: { status: "interrupted", reason: "stopped by the person" } }),
    "proposal with a negative round": (x, c) => ({ ...c.prop, events: [{ ...c.prop.events[0], round: -1 }, c.prop.events[1]] }),
    "proposal whose files aren't its commit's": (x, c) => ({ ...c.prop, events: [{ ...c.prop.events[0], files: [{ path: "x", kind: "file", change: "added", base_blob: null, blob: "e".repeat(40) }] }, c.prop.events[1]] }),
    "receipt with a wrong answer": (x, c) => ({ ...c.receipt, ledger: { ...c.receipt.ledger, answer: { recorded: "merge", commit: x.base } } }),
    "receipt whose files carry an extra field": (x, c) => ({ ...c.receipt, args: { ...c.receipt.args, files: c.receipt.args.files.map((f) => ({ ...f, extra: 1 })) } }),
    "status change with a reason that isn't well formed": (x, c) => ({ id: "d".repeat(32), op: "status", args: { op: "close" }, events: [{ type: "task_status", status: "closed", reason: "a\u0000" }], set: { status: "closed", reason: "a\u0000" } }),
    "close with a reason other than its own": (x, c) => ({ id: "d".repeat(32), op: "status", args: { op: "close" }, events: [{ type: "task_status", status: "closed", reason: "x".repeat(600) }], set: { status: "closed", reason: "x".repeat(600) } }),
  };
  for (const [name, tamper] of Object.entries(cases)) {
    const { root, dir } = fresh();
    let s = store(root);
    const { task } = start(s);
    writeFileSync(join(s.work(task), "a.ipynb"), NB2);
    const [ev] = await s.propose(task);
    const p = join(s.dir(task), "task.json"), x = JSON.parse(readFileSync(p, "utf8"));
    // (genuine intents to start from, built by the store's own builders: a next round's shape, and a receipt)
    const gd = s.gitdir(task);
    const pre = { ...x, status: "working", proposals: [] };
    const c = {
      prop: buildIntent(gd, pre, "propose", "d".repeat(32), { commit: ev.event.commit }),
      receipt: buildIntent(gd, x, "receipt", "d".repeat(32), { merge_id: "7".repeat(32), hash: "8".repeat(64), files: [{ path: "a.ipynb", proposal_blob: blobId(Buffer.from(NB2)), mine: "not sent", merged: "absent" }] }),
    };
    x.intent = tamper(x, c);
    writeFileSync(p, JSON.stringify(x));
    s = store(root);
    const t = s.state(task);
    assert.equal(t.status, "failed", name);
    assert.equal(t.merged, null, name);
    assert.deepEqual(t.mines, [], name);
    rmSync(dir, { recursive: true, force: true });
  }
});

test("recovery: a genuine receipt intent, interrupted, is finished exactly as written", async () => {
  const { root, dir } = fresh();
  let s = store(root);
  const { task } = start(s);
  writeFileSync(join(s.work(task), "a.ipynb"), NB2);
  await s.propose(task);
  const p = join(s.dir(task), "task.json"), x = JSON.parse(readFileSync(p, "utf8"));
  x.intent = buildIntent(s.gitdir(task), x, "receipt", "9".repeat(32), { merge_id: "7".repeat(32), hash: "8".repeat(64), files: [{ path: "a.ipynb", proposal_blob: blobId(Buffer.from(NB2)), mine: "not sent", merged: "absent" }] });
  writeFileSync(p, JSON.stringify(x));
  s = store(root);
  const t = s.state(task);
  assert.equal(t.status, "merged");
  assert.equal(t.receipt.merge_id, "7".repeat(32));
  assert.deepEqual(t.ledger["7".repeat(32)].answer, { recorded: "receipt", commit: null });
  rmSync(dir, { recursive: true, force: true });
});

