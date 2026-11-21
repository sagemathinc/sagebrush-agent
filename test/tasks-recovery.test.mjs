// The task store's recovery and storage contract against corrupted or planted on-disk state (the consolidated review's
// H1 to H5): nothing acknowledged is ever deleted; every persisted record is loaded by one strict schema and reconciled
// with the others; the log is checked whole; no link is followed; and no write is acknowledged before every byte, and
// every fsync, is done.
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { existsSync, mkdtempSync, readFileSync, rmSync, symlinkSync, unlinkSync, writeFileSync, renameSync } from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { TaskStore, canonical } from "../lib/tasks.mjs";
import { checkRequest } from "../lib/tasks-schema.mjs";
import * as git from "../lib/task-git.mjs";

let clock = 1_800_000_000_000;
const open = (root, scope = "probe") => new TaskStore({ root, scope, now: () => (clock += 1000) }).init();
function fresh() {
  const dir = mkdtempSync(join(tmpdir(), "sb-rec-")), root = join(dir, "tasks");
  const s = open(root);
  const { task } = s.start(checkRequest("tasks.start", { title: "test", prompt: "", target: "local", run: false, docs: [{ path: "a.txt", kind: "file", content: "base" }] }));
  return { dir, root, s, task, tdir: s.dir(task), state: join(s.dir(task), "task.json"), log: join(s.dir(task), "log.jsonl") };
}
const edit = (c, f) => { const t = JSON.parse(readFileSync(c.state, "utf8")); f(t); writeFileSync(c.state, canonical(t)); };
const done = (c) => rmSync(c.dir, { recursive: true, force: true });
const failedKept = (c, s) => {
  assert.equal(s.state(c.task).status, "failed");
  assert.ok(existsSync(join(c.tdir, "work", "a.txt")) && existsSync(join(c.tdir, "git", "refs", "heads", "base")), "the task's data kept");
};
async function withProposal(c) { writeFileSync(join(c.s.work(c.task), "a.txt"), "proposal"); return (await c.s.propose(c.task))[0].event.commit; }

test("H1: unreadable or missing control state never deletes a task: it is failed in place, its work and history kept", () => {
  for (const kase of ["invalid json", "missing", "a link"]) {
    const c = fresh();
    if (kase === "invalid json") writeFileSync(c.state, "{");
    if (kase === "missing") unlinkSync(c.state);
    if (kase === "a link") { const outside = join(c.dir, "outside.json"); writeFileSync(outside, readFileSync(c.state)); unlinkSync(c.state); symlinkSync(outside, c.state); }
    const s = open(c.root);
    assert.equal(s.list().tasks.length, 1, kase);
    failedKept(c, s);
    done(c);
  }
});

test("H2: each persisted field has its closed schema; a bad one fails the task, its data kept", () => {
  const cases = {
    "title with NUL": (t) => { t.title = "a\u0000"; },
    "title too long": (t) => { t.title = "x".repeat(201); },
    "prompt with a lone surrogate": (t) => { t.prompt = "\ud800"; },
    "reason an object": (t) => { t.reason = {}; },
    "created an object": (t) => { t.created = {}; },
    "negative bytes": (t) => { t.bytes = -1e12; },
    "mines not ids": (t) => { t.mines = ["x"]; },
    "ledger an array": (t) => { t.ledger = []; },
    "a grant with an extra key": (t) => { t.grant.extra = 1; },
    "intent false": (t) => { t.intent = false; },
    "missing created": (t) => { delete t.created; },
    "an unknown field": (t) => { t.extra = 1; },
  };
  for (const [name, f] of Object.entries(cases)) {
    const c = fresh();
    edit(c, f);
    const s = open(c.root);
    assert.equal(s.state(c.task).status, "failed", name);
    failedKept(c, s);
    done(c);
  }
});

test("H2: records reconciled: a revocation can't be rolled back; merged needs its merge or receipt; the ledger's answer is the merge's; another installation's task isn't taken", async () => {
  // (a real revocation, then task.json edited back to interrupted and unrevoked)
  { const c = fresh(); await c.s.revoke({ task: c.task }); edit(c, (t) => { t.status = "interrupted"; t.grant.revoked = false; delete t.reason; });
    const s = open(c.root); assert.equal(s.state(c.task).status, "failed"); await assert.rejects(s.resume({ task: c.task }), (e) => e.code === "final"); done(c); }
  // (status merged with nothing behind it; proposal with no round)
  for (const st of ["merged", "proposal"]) { const c = fresh(); edit(c, (t) => { t.status = st; }); const s = open(c.root); assert.equal(s.state(c.task).status, "failed", st); done(c); }
  // (a real merge, then its ledger answer changed: the retry never returns it)
  { const c = fresh(); const commit = await withProposal(c);
    const p = checkRequest("tasks.merged", { task: c.task, proposal: commit, seq: c.s.state(c.task).seq, merge_id: "a".repeat(32), files: [{ path: "a.txt", kind: "file", proposal_blob: git.blobId("proposal"), mine: { blob: git.blobId("mine"), content: "mine" }, merged: { blob: git.blobId("merged"), content: "merged" } }] });
    await c.s.merged(p);
    edit(c, (t) => { t.ledger["a".repeat(32)].answer = { recorded: "merge", commit: "f".repeat(40) }; });
    const s = open(c.root); assert.equal(s.state(c.task).status, "failed");
    await assert.rejects(s.merged(p), (e) => e.code === "final" || e.code === "conflict"); done(c); }
  // (opened by another installation's store)
  { const c = fresh(); const s = open(c.root, "another"); assert.equal(s.state(c.task).status, "failed"); assert.match(s.state(c.task).reason, /installation/); done(c); }
});

test("H3: the log is checked whole: a bad event, a repeated or skipped seq, unknown keys or an unsafe seq fail the task, and nothing is served from it", async () => {
  const lines = {
    "an unknown event": { seq: 2, at: new Date().toISOString(), event: { type: "nope" } },
    "a bad proposal": { seq: 2, at: new Date().toISOString(), event: { type: "proposal", round: -1, base: "0".repeat(40), commit: "0".repeat(40), files: ["bad"] } },
    "a repeated seq": { seq: 1, at: new Date().toISOString(), event: { type: "task_status", status: "working" } },
    "unknown keys": { seq: 2, at: new Date().toISOString(), event: { type: "task_status", status: "working" }, extra: 1 },
    "an unsafe seq": { seq: Number.MAX_SAFE_INTEGER + 2, at: new Date().toISOString(), event: { type: "task_status", status: "working" } },
  };
  for (const [name, line] of Object.entries(lines)) {
    const c = fresh();
    writeFileSync(c.log, readFileSync(c.log, "utf8") + canonical(line) + "\n");
    const s = open(c.root);
    assert.equal(s.state(c.task).status, "failed", name);
    assert.throws(() => s.get({ task: c.task, after: 0 }), (e) => e.code === "conflict", name);
    failedKept(c, s);
    done(c);
  }
  // (a torn final fragment is cut, and the task recovers normally)
  { const c = fresh(); writeFileSync(c.log, readFileSync(c.log, "utf8") + '{"seq":2,"at"'); const s = open(c.root); assert.equal(s.state(c.task).status, "interrupted"); done(c); }
  // (a persisted seq beyond the log's: failed, never incremented past safe integers)
  { const c = fresh(); edit(c, (t) => { t.seq = Number.MAX_SAFE_INTEGER; }); const s = open(c.root); assert.equal(s.state(c.task).status, "failed"); done(c); }
});

test("H3: an interrupted operation whose events were only partly logged is completed with exactly its missing events", async () => {
  const c = fresh();
  const t = c.s.state(c.task), gd = c.s.gitdir(c.task);
  const commit = git.writeCommit(gd, { tree: git.writeTree(gd, new Map([["a.txt", git.writeObject(gd, "blob", "proposal")]])), parents: [t.base], message: "proposal", time: 123 });
  const { buildIntent } = await import("../lib/tasks.mjs");
  const intent = buildIntent(gd, t, "propose", "b".repeat(32), { commit });
  edit(c, (x) => { x.intent = intent; });
  git.casRef(gd, intent.ref, intent.expect, intent.next);
  // (the first event logged, the second torn)
  writeFileSync(c.log, readFileSync(c.log, "utf8") + canonical({ seq: 2, at: new Date().toISOString(), event: intent.events[0], intent: intent.id }) + '\n{"seq":3');
  const s = open(c.root);
  assert.equal(s.state(c.task).status, "proposal");
  const evs = s.get({ task: c.task, after: 0 }).events;
  assert.deepEqual(evs.map((e) => e.event.type), ["task_status", "proposal", "task_status"]);
  assert.equal(evs.at(-1).event.status, "proposal");
  done(c);
});

test("H4: no link is followed: a work folder that is a link, a log that is a link, a ref that is a link", async () => {
  // (work/ replaced by a link to a sibling holding a secret: never read, never committed)
  { const c = fresh(); const sib = join(c.dir, "sibling"); fs.mkdirSync(sib); writeFileSync(join(sib, "secret.txt"), "DUMMY-SENTINEL");
    renameSync(join(c.tdir, "work"), join(c.dir, "work-moved")); symlinkSync(sib, join(c.tdir, "work"));
    await assert.rejects(c.s.propose(c.task), (e) => e.code === "bad_request");
    const s = open(c.root); assert.equal(s.state(c.task).status, "failed"); done(c); }
  // (log.jsonl a link to an outside file with an unfinished line: the outside file is never cut or written)
  { const c = fresh(); const outside = join(c.dir, "outside.log"); writeFileSync(outside, "DUMMY-UNFINISHED-LOG");
    unlinkSync(c.log); symlinkSync(outside, c.log);
    const s = open(c.root); assert.equal(readFileSync(outside, "utf8"), "DUMMY-UNFINISHED-LOG"); assert.equal(s.state(c.task).status, "failed"); done(c); }
  // (a ref that is a link)
  { const c = fresh(); const r = join(c.tdir, "git", "refs", "heads", "base"); const outside = join(c.dir, "ref"); writeFileSync(outside, readFileSync(r)); unlinkSync(r); symlinkSync(outside, r);
    const s = open(c.root); assert.equal(s.state(c.task).status, "failed"); done(c); }
});

test("H5: a short write is continued, no progress is an error with nothing acknowledged, and a failed folder fsync fails the operation", async () => {
  const original = fs.writeSync;
  // (every write cut to at most 7 bytes: the loops finish it; the state is whole)
  { const c = fresh();
    fs.writeSync = function (fd, data, off = 0, len, pos) { const b = Buffer.isBuffer(data) ? data : Buffer.from(String(data)); const o = typeof off === "number" ? off : 0; const l = Math.min(7, (typeof len === "number" ? len : b.length - o)); return original.call(this, fd, b, o, l, pos); };
    syncBuiltinESMExports();
    try { assert.deepEqual(await c.s.stop({ task: c.task }), { status: "interrupted" }); } finally { fs.writeSync = original; syncBuiltinESMExports(); }
    JSON.parse(readFileSync(c.state, "utf8"));
    assert.equal(open(c.root).state(c.task).status, "interrupted"); done(c); }
  // (a write that makes no progress: the operation fails, nothing acknowledged, the old state kept)
  { const c = fresh();
    fs.writeSync = function () { return 0; };
    syncBuiltinESMExports();
    try { await assert.rejects(c.s.stop({ task: c.task })); } finally { fs.writeSync = original; syncBuiltinESMExports(); }
    const s = open(c.root); assert.notEqual(s.state(c.task).status, "failed"); done(c); }
  // (a folder's fsync fails: the operation fails)
  { const c = fresh(); const fsync = fs.fsyncSync, fstat = fs.fstatSync;
    fs.fsyncSync = function (fd) { if (fstat(fd).isDirectory()) throw Object.assign(new Error("EIO: injected"), { code: "EIO" }); return fsync(fd); };
    syncBuiltinESMExports();
    try { await assert.rejects(c.s.stop({ task: c.task }), /EIO/); } finally { fs.fsyncSync = fsync; syncBuiltinESMExports(); }
    done(c); }
});

test("H2 quota: a broken task's storage still counts, measured from disk; a task whose storage can't be measured blocks new starts", () => {
  const budget = { task: 512 * 2 ** 20, work: 256 * 2 ** 20, files: 2000, log: 16 * 2 ** 20, event: 256 * 1024, tasks: 64, total: 2 * 2 ** 20, reserve: 1024 };
  const big = "x".repeat(1100 * 1024);
  const startBig = (s) => s.start(checkRequest("tasks.start", { title: "t", prompt: "", target: "local", run: false, docs: [{ path: "a.txt", kind: "file", content: big }] }));
  // (one task, then its task.json made unreadable: reopened, it is broken, yet its folder still counts)
  { const dir = mkdtempSync(join(tmpdir(), "sb-rec-")), root = join(dir, "tasks");
    let s = new TaskStore({ root, scope: "probe", budget }).init();
    const { task } = startBig(s);
    writeFileSync(join(s.dir(task), "task.json"), "{");
    s = new TaskStore({ root, scope: "probe", budget }).init();
    assert.equal(s.state(task).status, "failed");
    assert.throws(() => startBig(s), (e) => e.code === "busy");
    rmSync(dir, { recursive: true, force: true }); }
  // (a kept task whose folder can't be read: its use is unknown, so nothing new is admitted)
  { const dir = mkdtempSync(join(tmpdir(), "sb-rec-")), root = join(dir, "tasks");
    let s = new TaskStore({ root, scope: "probe", budget }).init();
    const { task } = s.start(checkRequest("tasks.start", { title: "t", prompt: "", target: "local", run: false, docs: [{ path: "a.txt", kind: "file", content: "a" }] }));
    fs.chmodSync(join(s.dir(task), "work"), 0o000);
    try {
      s = new TaskStore({ root, scope: "probe", budget }).init();
      assert.throws(() => s.start(checkRequest("tasks.start", { title: "t", prompt: "", target: "local", run: false, docs: [{ path: "b.txt", kind: "file", content: "b" }] })), (e) => e.code === "busy" && /can't be measured/.test(e.message));
    } finally { fs.chmodSync(join(s.dir(task), "work"), 0o700); }
    rmSync(dir, { recursive: true, force: true }); }
});

test("H3: every logged proposal is exactly its commit's, rebuilt from git: a changed round number or a changed file entry fails the task", async () => {
  for (const tamper of [(ev) => { ev.round = 999; }, (ev) => { ev.files[0].change = "added"; }]) {
    const c = fresh();
    await withProposal(c);
    const lines = readFileSync(c.log, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
    const k = lines.findIndex((l) => l.event.type === "proposal");
    tamper(lines[k].event);
    writeFileSync(c.log, lines.map((l) => canonical(l)).join("\n") + "\n");
    const s = open(c.root);
    assert.equal(s.state(c.task).status, "failed");
    assert.match(s.state(c.task).reason, /round 1's event isn't its commit's/);
    // (and nothing is served from its records: no event list carrying the changed event, no diff, no file)
    assert.throws(() => s.get({ task: c.task, after: 0 }), (e) => e.code === "conflict");
    assert.throws(() => s.diff({ task: c.task, commit: JSON.parse(readFileSync(c.state, "utf8")).proposals[0] }), (e) => e.code === "conflict");
    done(c);
  }
});

test("H3: a record that isn't in the exact form the store writes (a repeated key, reordered keys, extra spacing) isn't one of its records", () => {
  // (in the log)
  for (const bad of [(l) => l.replace('"seq":1', '"seq":1,"seq":1'), (l) => l.replace("{", "{ "), (l) => { const o = JSON.parse(l); return JSON.stringify({ seq: o.seq, at: o.at, event: o.event }); }]) {
    const c = fresh();
    const [first, ...rest] = readFileSync(c.log, "utf8").split("\n");
    writeFileSync(c.log, [bad(first), ...rest].join("\n"));
    const s = open(c.root);
    assert.equal(s.state(c.task).status, "failed");
    done(c);
  }
  // (in task.json: a repeated key)
  { const c = fresh(); const raw = readFileSync(c.state, "utf8"); writeFileSync(c.state, raw.replace('"title":"test"', '"title":"test","title":"other"'));
    const s = open(c.root); assert.equal(s.state(c.task).status, "failed"); done(c); }
});

test("H4: an objects fan-out folder that is a link isn't read through; a FIFO at task.json doesn't stall the store", async () => {
  { const c = fresh(); const gd = join(c.tdir, "git"); const base = readFileSync(join(gd, "refs", "heads", "base"), "utf8").trim();
    const fan = join(gd, "objects", base.slice(0, 2)), moved = join(c.dir, "fan-outside");
    renameSync(fan, moved); symlinkSync(moved, fan);
    const s = open(c.root); assert.equal(s.state(c.task).status, "failed"); done(c); }
  { const c = fresh(); unlinkSync(c.state);
    const { spawnSync } = await import("node:child_process");
    spawnSync("mkfifo", [c.state]);
    const t0 = Date.now(); const s = open(c.root);
    assert.ok(Date.now() - t0 < 5000);
    assert.equal(s.state(c.task).status, "failed"); done(c); }
});

test("a task failed while its records were checked stays failed and unserved after another restart, its state file still its schema's", async () => {
  const c = fresh();
  await withProposal(c);
  const lines = readFileSync(c.log, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
  lines.find((l) => l.event.type === "proposal").event.round = 999;
  writeFileSync(c.log, lines.map((l) => canonical(l)).join("\n") + "\n");
  open(c.root);
  const s = open(c.root);
  assert.equal(s.state(c.task).status, "failed");
  assert.ok(!Object.hasOwn(JSON.parse(readFileSync(c.state, "utf8")), "unserved"));
  assert.throws(() => s.get({ task: c.task, after: 0 }), (e) => e.code === "conflict");
  done(c);
});
