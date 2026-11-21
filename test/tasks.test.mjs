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
import { TaskStore } from "../lib/tasks.mjs";
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
    state.intent = { id: "i".repeat(32), ref: "refs/heads/proposal", expect: null, next: commit, tags: [{ ref: "refs/tags/round-1", next: commit }], events: [{ type: "proposal", round: 1, commit }, { type: "task_status", status: "proposal" }], set: { status: "proposal", proposals: [commit] } };
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

