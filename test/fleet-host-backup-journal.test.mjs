// Host backup r3.3 §4 and lease r3.10 §2.1 step 6: the backup fence cause, the run journal, and the standalone recovery
// (kill and reap the worker, thaw every member, then lower only the backup fences, under the journal lock), against a
// fake cgroup tree that records every operation in order.
import assert from "node:assert/strict";
import * as nodeFs from "node:fs";
import { existsSync, mkdtempSync, mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "./host-linux-only.mjs";
import { FleetError, newId } from "../lib/fleet/index.mjs";
import { CAUSES, fenced, lowerFence, raiseFence, stop } from "../lib/fleet/host/fence.mjs";
import { BACKUP_SLICE_CGROUP, agentSliceCgroup, backupScopeCgroup, fenceFiles } from "../lib/fleet/host/names.mjs";
import { STATES, advance, checkJournal, clearJournal, newJournal, readJournal, recoverBackup, withJournalLock, writeJournal } from "../lib/fleet/host/backup-journal.mjs";

const refused = (fn, code) => assert.throws(fn, (e) => e instanceof FleetError && e.code === code, code);
const rejects = (p, code) => assert.rejects(p, (e) => e instanceof FleetError && e.code === code, code);
const RUN = "20261124T013000Z-abcdefgh";
const SCOPE = `sagebrush-backup-${RUN}.scope`;

function dirs() {
  const root = mkdtempSync(join(tmpdir(), "sb-backup-"));
  const dir = join(root, "backup"), fenceDir = join(root, "fence");
  mkdirSync(dir, { mode: 0o700 }); mkdirSync(fenceDir, { mode: 0o700 });
  return { dir, fenceDir };
}

/**
 * A fake cgroup tree. `groups`: path -> { procs, frozen, dies (kill empties it), thaws (freeze 0 works), unreadable }.
 * A path not in the map doesn't exist (0 procs, not frozen). `ops` records [op, path] in order; `fences` (optional)
 * is called at every op, so a test can see which fences were up at that moment.
 */
function fakeCgroup(groups, { onOp = () => {} } = {}) {
  const ops = [];
  const g = (p) => groups[p];
  return {
    ops,
    kill: (p) => { ops.push(["kill", p]); onOp(); if (g(p)?.dies !== false && g(p)) g(p).procs = 0; },
    procs: (p) => { if (g(p)?.unreadable) throw Object.assign(new Error("EIO"), { code: "EIO" }); return g(p)?.procs ?? 0; },
    freeze: (p, on) => { ops.push([on ? "freeze" : "thaw", p]); onOp(); if (g(p) && (on || g(p).thaws !== false)) g(p).frozen = on; },
    frozen: (p) => { if (g(p)?.unreadable) throw Object.assign(new Error("EIO"), { code: "EIO" }); return g(p)?.frozen ?? false; },
  };
}

/** A clock that advances by what each sleep asks for, so bounded waits end at once in tests. */
function clock() {
  let t = 0;
  return { now: () => t, sleep: async (ms) => { t += ms; } };
}

/** A run frozen with its worker alive, the journal at `state`, and the members' backup fences up. */
function frozenRun({ dir, fenceDir }, agents, state = "frozen") {
  let j = newJournal(RUN, agents);
  for (const s of STATES.slice(1, STATES.indexOf(state) + 1)) j = advance(j, s);
  writeJournal(j, { dir });
  for (const a of agents) raiseFence("backup", a, { dir: fenceDir });
  const groups = { [backupScopeCgroup(SCOPE)]: { procs: 3, frozen: false } };
  for (const a of agents) groups[agentSliceCgroup(a)] = { procs: 5, frozen: true };
  return groups;
}

test("the backup fence: per agent at fence/backup/<id>, lowered only by backup-recovery, never a stop cause", async () => {
  const { fenceDir } = dirs();
  const a = newId(), b = newId();
  assert.ok(CAUSES.includes("backup"));
  assert.equal(fenceFiles(a).backup, `/var/lib/sagebrush/fence/backup/${a}`);
  raiseFence("backup", a, { dir: fenceDir });
  assert.ok(existsSync(join(fenceDir, "backup", a)));
  assert.equal(fenced(a, { dir: fenceDir }), true);
  assert.equal(fenced(b, { dir: fenceDir }), false, "one agent's backup fence fences only that agent");
  for (const auth of ["resume-agent", "resume-all", "newer-grant"]) {
    await rejects(lowerFence("backup", a, auth, { dir: fenceDir }), "not_granted");
  }
  assert.ok(existsSync(join(fenceDir, "backup", a)));
  await lowerFence("backup", a, "backup-recovery", { dir: fenceDir });
  assert.equal(fenced(a, { dir: fenceDir }), false);
  await lowerFence("backup", b, "backup-recovery", { dir: fenceDir }); // never raised: fine
  refused(() => raiseFence("backup", "nope", { dir: fenceDir }), "bad_form");
  await rejects(stop({ agent: a }, "backup", { dir: fenceDir }), "bad_form");
});

test("raising a backup fence fsyncs the file, its directory and the fence directory", () => {
  const { fenceDir } = dirs();
  const a = newId();
  const synced = [], paths = new Map();
  const io = {
    open: (p, f, m) => { const fd = nodeFs.openSync(p, f, m); paths.set(fd, p); return fd; },
    fsync: (fd) => { synced.push(paths.get(fd)); nodeFs.fsyncSync(fd); },
    close: (fd) => nodeFs.closeSync(fd),
  };
  raiseFence("backup", a, { dir: fenceDir, io });
  assert.deepEqual(synced, [join(fenceDir, "backup", a), join(fenceDir, "backup"), fenceDir]);
});

test("the journal: closed shape, one step forward at a time, durable round trip, absent is no run", () => {
  const { dir } = dirs();
  const a = newId(), b = newId();
  assert.equal(readJournal({ dir }), null);
  let j = newJournal(RUN, [a, b]);
  assert.deepEqual(j, { v: 1, run: RUN, agents: [a, b], scope: SCOPE, state: "intent", warm: null, aborted: false });
  for (const s of STATES.slice(1)) {
    for (const wrong of STATES.filter((x) => x !== s)) refused(() => advance(j, wrong), "not_granted");
    j = advance(j, s);
    writeJournal(j, { dir });
    assert.deepEqual(readJournal({ dir }), j);
  }
  refused(() => advance(j, "intent"), "not_granted");
  for (const bad of [
    { ...j, v: 2 }, { ...j, run: "x" }, { ...j, agents: [] }, { ...j, agents: [a, a] }, { ...j, agents: ["nope"] },
    { ...j, scope: "sagebrush-backup-other.scope" }, { ...j, state: "thawing" }, { ...j, warm: "abc" },
    { ...j, state: "frozen", aborted: true }, { ...j, extra: 1 }, (({ warm, ...r }) => r)(j),
  ]) refused(() => checkJournal(bad), "bad_form");
  writeFileSync(join(dir, "run.json"), "{");
  refused(() => readJournal({ dir }), "bad_form");
  clearJournal({ dir });
  assert.equal(readJournal({ dir }), null);
});

test("recovery from every journal state: reap the worker, thaw, then lower only backup; never a fence while frozen", async () => {
  for (const state of STATES) {
    const d = dirs();
    const a = newId();
    raiseFence("agent", a, { dir: d.fenceDir }); // another cause's fence: never touched
    const groups = frozenRun(d, [a], state);
    const seen = [];
    const cg = fakeCgroup(groups, { onOp: () => seen.push(existsSync(join(d.fenceDir, "backup", a))) });
    const r = await recoverBackup(a, { dir: d.dir, fenceDir: d.fenceDir, cg, ...clock() });
    assert.deepEqual(r, { run: RUN, reaped: true, thawed: true, backupLowered: true, state: "released" }, state);
    assert.deepEqual(cg.ops, [["kill", backupScopeCgroup(SCOPE)], ["thaw", agentSliceCgroup(a)]], state);
    assert.ok(seen.every(Boolean), `${state}: the backup fence was up at every cgroup step`);
    assert.equal(existsSync(join(d.fenceDir, "backup", a)), false, state);
    assert.ok(existsSync(join(d.fenceDir, a)), `${state}: the agent cause's fence is untouched`);
    const j = readJournal({ dir: d.dir });
    assert.equal(j.state, "released"); assert.equal(j.aborted, true);
  }
});

test("a thaw that doesn't read back frozen 0: the fence stays up, thawed false", async () => {
  const d = dirs();
  const a = newId();
  const groups = frozenRun(d, [a]);
  groups[agentSliceCgroup(a)].thaws = false;
  const r = await recoverBackup(a, { dir: d.dir, fenceDir: d.fenceDir, cg: fakeCgroup(groups), ...clock() });
  assert.deepEqual(r, { run: RUN, reaped: true, thawed: false, backupLowered: false, state: "frozen" });
  assert.ok(existsSync(join(d.fenceDir, "backup", a)));
});

test("an unreadable cgroup.events is never thawed, and a worker that won't die is never reaped: the fence stays", async () => {
  {
    const d = dirs();
    const a = newId();
    const groups = frozenRun(d, [a]);
    groups[agentSliceCgroup(a)].unreadable = true;
    const r = await recoverBackup(a, { dir: d.dir, fenceDir: d.fenceDir, cg: fakeCgroup(groups), ...clock() });
    assert.equal(r.thawed, false); assert.equal(r.backupLowered, false);
  }
  {
    const d = dirs();
    const a = newId();
    const groups = frozenRun(d, [a]);
    groups[backupScopeCgroup(SCOPE)].dies = false;
    const cg = fakeCgroup(groups);
    const r = await recoverBackup(a, { dir: d.dir, fenceDir: d.fenceDir, cg, ...clock() });
    assert.equal(r.reaped, false); assert.equal(r.thawed, true, "the slice is still thawed, so a stop can proceed");
    assert.equal(r.backupLowered, false);
    assert.ok(existsSync(join(d.fenceDir, "backup", a)));
    assert.deepEqual(cg.ops.map((o) => o[0]), ["kill", "thaw"], "kill first, then thaw");
  }
});

test("the journal lock busy (a hung supervisor): reap and thaw still happen, backup stays raised, within lockWaitMs", async () => {
  const d = dirs();
  const a = newId();
  const groups = frozenRun(d, [a]);
  let r, t0;
  await withJournalLock(async () => {
    t0 = Date.now();
    r = await recoverBackup(a, { dir: d.dir, fenceDir: d.fenceDir, cg: fakeCgroup(groups), lockWaitMs: 300 });
  }, { dir: d.dir });
  const took = Date.now() - t0;
  assert.deepEqual(r, { run: RUN, reaped: true, thawed: true, backupLowered: false, state: "frozen" });
  assert.equal(groups[agentSliceCgroup(a)].frozen, false);
  assert.ok(existsSync(join(d.fenceDir, "backup", a)));
  assert.ok(took < 2000, `bounded by lockWaitMs (took ${took} ms)`);
});

test("no run, or a run that doesn't name the agent: a no-op that touches nothing", async () => {
  const d = dirs();
  const a = newId(), b = newId();
  const cg = fakeCgroup({});
  assert.deepEqual(await recoverBackup(a, { dir: d.dir, fenceDir: d.fenceDir, cg, ...clock() }),
    { run: null, reaped: true, thawed: true, backupLowered: true, state: null });
  raiseFence("backup", a, { dir: d.fenceDir }); // a stale fence with no run: reported, not lowered here
  assert.deepEqual(await recoverBackup(a, { dir: d.dir, fenceDir: d.fenceDir, cg, ...clock() }),
    { run: null, reaped: true, thawed: true, backupLowered: false, state: null });
  frozenRun(d, [b]);
  const r = await recoverBackup(a, { dir: d.dir, fenceDir: d.fenceDir, cg, ...clock() });
  assert.equal(r.run, null);
  assert.deepEqual(cg.ops, []);
  assert.equal(readJournal({ dir: d.dir }).state, "frozen", "another agent's run is untouched");
});

test("a tag-folder run: recovering one member reaps the worker and thaws and unfences every member", async () => {
  const d = dirs();
  const [a, b, c] = [newId(), newId(), newId()];
  const groups = frozenRun(d, [a, b, c]);
  const cg = fakeCgroup(groups);
  const r = await recoverBackup(b, { dir: d.dir, fenceDir: d.fenceDir, cg, ...clock() });
  assert.deepEqual(r, { run: RUN, reaped: true, thawed: true, backupLowered: true, state: "released" });
  assert.deepEqual(cg.ops, [["kill", backupScopeCgroup(SCOPE)], ...[a, b, c].map((x) => ["thaw", agentSliceCgroup(x)])]);
  for (const x of [a, b, c]) assert.equal(existsSync(join(d.fenceDir, "backup", x)), false);
});

test("a tag-folder run with one member that won't thaw: no member's fence is lowered", async () => {
  const d = dirs();
  const [a, b] = [newId(), newId()];
  const groups = frozenRun(d, [a, b]);
  groups[agentSliceCgroup(b)].thaws = false;
  const r = await recoverBackup(a, { dir: d.dir, fenceDir: d.fenceDir, cg: fakeCgroup(groups), ...clock() });
  assert.equal(r.thawed, false); assert.equal(r.backupLowered, false);
  for (const x of [a, b]) assert.ok(existsSync(join(d.fenceDir, "backup", x)));
});

test("an unreadable journal: the whole backup slice is killed and this agent thawed, the fence stays", async () => {
  const d = dirs();
  const a = newId();
  writeFileSync(join(d.dir, "run.json"), "not json");
  raiseFence("backup", a, { dir: d.fenceDir });
  const groups = { [BACKUP_SLICE_CGROUP]: { procs: 2 }, [agentSliceCgroup(a)]: { procs: 4, frozen: true } };
  const cg = fakeCgroup(groups);
  const r = await recoverBackup(a, { dir: d.dir, fenceDir: d.fenceDir, cg, ...clock() });
  assert.deepEqual(r, { run: null, reaped: true, thawed: true, backupLowered: false, state: "unknown" });
  assert.deepEqual(cg.ops, [["kill", BACKUP_SLICE_CGROUP], ["thaw", agentSliceCgroup(a)]]);
  assert.ok(existsSync(join(d.fenceDir, "backup", a)));
});

test("recovery is idempotent: a second call after a released run lowers nothing new and keeps it released", async () => {
  const d = dirs();
  const a = newId();
  const groups = frozenRun(d, [a]);
  const opts = { dir: d.dir, fenceDir: d.fenceDir, cg: fakeCgroup(groups), ...clock() };
  await recoverBackup(a, opts);
  const before = readFileSync(join(d.dir, "run.json"), "utf8");
  assert.deepEqual(await recoverBackup(a, opts), { run: RUN, reaped: true, thawed: true, backupLowered: true, state: "released" });
  assert.equal(readFileSync(join(d.dir, "run.json"), "utf8"), before);
  refused(() => advance(readJournal({ dir: d.dir }), "released"), "not_granted");
});

test("a bad agent id is refused before any effect", async () => {
  const d = dirs();
  const cg = fakeCgroup({});
  await rejects(recoverBackup("nope", { dir: d.dir, fenceDir: d.fenceDir, cg }), "bad_form");
  assert.deepEqual(cg.ops, []);
});
