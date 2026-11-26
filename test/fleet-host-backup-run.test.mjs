// Host backup r3.3 §4: one source set's backup, with the consistent pass journaled (intent, fenced, idle, frozen,
// confirmed, thawed, released), the 5-minute cap and every failure going through the recovery order, against a fake
// binary that records what was frozen and fenced at each call, a fake turn-lease interface and a fake cgroup tree.
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "./host-linux-only.mjs";
import { FleetError, newId } from "../lib/fleet/index.mjs";
import { agentSliceCgroup, backupScopeCgroup } from "../lib/fleet/host/names.mjs";
import { newJournal, readJournal, recoverBackup, writeJournal } from "../lib/fleet/host/backup-journal.mjs";
import { backupSet, checkedParent, scopedArgv, scopedSpawn, workerUnit } from "../lib/fleet/host/backup-run.mjs";
import { STRICT_MARK } from "../lib/fleet/host/backup-binary.mjs";

const RUN = "20261124T030000Z-abcdefgh";
const SCOPE = `sagebrush-backup-${RUN}.scope`;
const W = "1".repeat(64), G = "2".repeat(64), P = "3".repeat(64);

function dirs() {
  const root = mkdtempSync(join(tmpdir(), "sb-brun-"));
  const dir = join(root, "backup"), fenceDir = join(root, "fence");
  mkdirSync(dir, { mode: 0o700 }); mkdirSync(fenceDir, { mode: 0o700 });
  return { dir, fenceDir };
}

/** A fake cgroup tree: path -> { procs, frozen, freezes, thaws }. */
function fakeCgroup(groups) {
  const g = (p) => (groups[p] ??= { procs: 0, frozen: false });
  return {
    kill: (p) => { if (g(p).dies !== false) g(p).procs = 0; },
    procs: (p) => g(p).procs,
    freeze: (p, on) => { if (on ? g(p).freezes !== false : g(p).thaws !== false) g(p).frozen = on; },
    frozen: (p) => g(p).frozen,
  };
}

/**
 * The fake binary. `answers`: op/state -> result (a function of the request, or a value). Records each call with the
 * members' fence and freeze state at that moment.
 */
function fakeBinary(d, groups, members, answers = {}) {
  const calls = [];
  const fn = async (req, opts) => {
    const state = req.op === "backup" ? req.tags.find((t) => t.startsWith("sb-state=")).slice(9) : req.op;
    calls.push({ req, opts, state,
      fenced: members.map((a) => existsSync(join(d.fenceDir, "backup", a))),
      frozen: members.map((a) => groups[agentSliceCgroup(a)]?.frozen === true),
      journal: readJournal({ dir: d.dir })?.state ?? null });
    const a = answers[state];
    if (typeof a === "function") return a(req);
    if (a) return a;
    if (state === "warm") return { ok: true, value: { snapshot: { id: W } } };
    if (state === "good") return { ok: true, value: { snapshot: { id: G } } };
    if (state === "readback") return { ok: true, value: { snapshot: { id: req.snapshot }, findings: 0 } };
    if (state === "forget") return { ok: true, value: { forgotten: 1 } };
    throw new Error(`unexpected ${state}`);
  };
  fn.calls = calls;
  return fn;
}

function clock() { let t = 0; return { now: () => t, sleep: async (ms) => { t += ms; }, tick: (ms) => { t += ms; } }; }

function setup(kind = "agent", n = 1, answers = {}, lease = { activeTurns: async () => 0 }) {
  const d = dirs();
  const members = Array.from({ length: n }, () => newId());
  const groups = { [backupScopeCgroup(SCOPE)]: { procs: 0, frozen: false } };
  for (const a of members) groups[agentSliceCgroup(a)] = { procs: 3, frozen: false };
  const binary = fakeBinary(d, groups, members, answers);
  const set = kind === "archive"
    ? { kind, id: members[0], sources: ["/srv/sagebrush/archive/x"], uids: [70000], members: [] }
    : { kind, id: kind === "tag" ? newId() : members[0], sources: ["/srv/sagebrush/agents/x/home"], uids: [70000], members };
  const deps = { binary, lease, host: "h1", parent: P, cg: fakeCgroup(groups), dir: d.dir, fenceDir: d.fenceDir, ...clock() };
  return { d, members, groups, binary, set, deps };
}

test("an agent's pass: warm live, then fenced and frozen for the good backup, thawed and unfenced before the read-back", async () => {
  const { d, members: [a], groups, binary, set, deps } = setup();
  const r = await backupSet(set, RUN, deps);
  assert.deepEqual(r, { outcome: "good", snapshot: G, consistency: "turn", warm: W, code: null, recovered: null });
  assert.deepEqual(binary.calls.map((c) => [c.state, c.fenced[0], c.frozen[0]]), [
    ["warm", false, false], ["good", true, true], ["readback", false, false], ["forget", false, false],
  ]);
  const [warm, good, rb, fg] = binary.calls.map((c) => c.req);
  assert.equal(warm.parent, P, "the warm pass's parent is the last good snapshot");
  assert.equal(good.parent, W, "the good pass's parent is the warm one");
  assert.deepEqual(good.tags, [`sb-run=${RUN}`, "sb-state=good", "sb-kind=agent", `agent=${a}`, "consistency=turn"]);
  assert.deepEqual(warm.tags, [`sb-run=${RUN}`, "sb-state=warm", "sb-kind=agent", `agent=${a}`]);
  assert.deepEqual(rb, { op: "readback", snapshot: G }); assert.deepEqual(fg, { op: "forget", snapshots: [W] });
  assert.equal(binary.calls[0].journal, "intent", "the intent is written before the warm pass");
  assert.equal(binary.calls[1].journal, "frozen", "frozen is written before the good pass");
  assert.equal(groups[agentSliceCgroup(a)].frozen, false);
  assert.equal(existsSync(join(d.fenceDir, "backup", a)), false);
  assert.equal(readJournal({ dir: d.dir }), null, "the journal is cleared at the end");
});

test("the journal says frozen, and the fences are up, before any slice is frozen", async () => {
  const { d, members, set, deps } = setup("tag", 2);
  const seen = [];
  const freeze = deps.cg.freeze;
  deps.cg.freeze = (p, on) => {
    if (on) seen.push({ journal: readJournal({ dir: d.dir })?.state, fenced: members.map((a) => existsSync(join(d.fenceDir, "backup", a))) });
    return freeze(p, on);
  };
  assert.equal((await backupSet(set, RUN, deps)).outcome, "good");
  assert.equal(seen.length, 2);
  for (const x of seen) { assert.equal(x.journal, "frozen"); assert.deepEqual(x.fenced, [true, true]); }
});

test("turns that don't end within 10 minutes, or a lease read that fails: the pass goes on as consistency=crash", async () => {
  for (const lease of [{ activeTurns: async () => 1 }, { activeTurns: async () => { throw new Error("advisor down"); } }]) {
    const { binary, set, deps } = setup("agent", 1, {}, lease);
    const r = await backupSet(set, RUN, deps);
    assert.equal(r.outcome, "good"); assert.equal(r.consistency, "crash");
    assert.ok(binary.calls[1].req.tags.includes("consistency=crash"));
  }
});

test("a tag: every member fenced and frozen together for the one good pass", async () => {
  const { d, members, groups, binary, set, deps } = setup("tag", 3);
  const r = await backupSet(set, RUN, deps);
  assert.equal(r.outcome, "good");
  const good = binary.calls.find((c) => c.state === "good");
  assert.deepEqual(good.fenced, [true, true, true]); assert.deepEqual(good.frozen, [true, true, true]);
  assert.ok(good.req.tags.includes(`tag=${set.id}`));
  for (const a of members) { assert.equal(groups[agentSliceCgroup(a)].frozen, false); assert.equal(existsSync(join(d.fenceDir, "backup", a)), false); }
});

test("the cap, or the good pass failing (a quota): abandoned in the recovery order, nothing new kept, fences lowered after the thaw", async () => {
  for (const [answer, code] of [[{ ok: false, code: "timed_out", message: "" }, "cap"], [{ ok: false, code: "quota_exceeded", message: "" }, "quota_exceeded"]]) {
    const { d, members: [a], groups, binary, set, deps } = setup("agent", 1, { good: answer });
    const r = await backupSet(set, RUN, deps);
    assert.equal(r.outcome, "abandoned"); assert.equal(r.code, code); assert.equal(r.snapshot, null); assert.equal(r.warm, W);
    assert.deepEqual(r.recovered, { reaped: true, thawed: true, state: "released" });
    assert.equal(groups[agentSliceCgroup(a)].frozen, false);
    assert.equal(existsSync(join(d.fenceDir, "backup", a)), false);
    const j = readJournal({ dir: d.dir });
    assert.equal(j.state, "released"); assert.equal(j.aborted, true); assert.equal(j.warm, W, "the warm snapshot stays named for recovery to forget");
    assert.ok(!binary.calls.some((c) => c.state === "readback"), "nothing is confirmed");
  }
});

test("the good pass gets only what is left of the 5-minute cap, counted from the freeze", async () => {
  const { binary, set, deps } = setup();
  const c = clock();
  const freeze = deps.cg.freeze;
  deps.cg.freeze = (p, on) => { if (on) c.tick(1000); return freeze(p, on); }; // the freeze takes a second
  await backupSet(set, RUN, { ...deps, now: c.now, sleep: c.sleep, limits: { capMs: 5000 } });
  assert.equal(binary.calls.find((x) => x.state === "good").opts.ms, 4000);
});

test("a freeze that uses up the whole cap: abandoned as cap, no good pass", async () => {
  const { binary, set, deps } = setup();
  const c = clock();
  const freeze = deps.cg.freeze;
  deps.cg.freeze = (p, on) => { if (on) c.tick(6000); return freeze(p, on); };
  const r = await backupSet(set, RUN, { ...deps, now: c.now, sleep: c.sleep, limits: { capMs: 5000 } });
  assert.equal(r.outcome, "abandoned"); assert.equal(r.code, "cap");
  assert.ok(!binary.calls.some((x) => x.state === "good"));
});

test("a slice that won't freeze: abandoned, every member thawed and unfenced, no good pass", async () => {
  const { d, members, groups, binary, set, deps } = setup("tag", 2);
  groups[agentSliceCgroup(members[1])].freezes = false;
  const r = await backupSet(set, RUN, deps);
  assert.equal(r.outcome, "abandoned"); assert.equal(r.code, "freeze_failed");
  assert.ok(!binary.calls.some((c) => c.state === "good"));
  for (const a of members) { assert.equal(groups[agentSliceCgroup(a)].frozen, false); assert.equal(existsSync(join(d.fenceDir, "backup", a)), false); }
});

test("a slice that won't thaw at the end: abandoned, and the fence stays up", async () => {
  const { d, members: [a], groups, set, deps } = setup("agent", 1, {
    good: () => { groups[agentSliceCgroup(a)].thaws = false; return { ok: true, value: { snapshot: { id: G } } }; },
  });
  const r = await backupSet(set, RUN, deps);
  assert.equal(r.outcome, "abandoned"); assert.equal(r.code, "thaw_failed");
  assert.equal(r.recovered.thawed, false);
  assert.ok(existsSync(join(d.fenceDir, "backup", a)), "never a fence down on a frozen slice");
});

test("a warm pass that fails: failed, the journal cleared, no fence ever raised", async () => {
  const { d, members: [a], binary, set, deps } = setup("agent", 1, { warm: { ok: false, code: "destination_unavailable", message: "" } });
  const r = await backupSet(set, RUN, deps);
  assert.equal(r.outcome, "failed"); assert.equal(r.code, "destination_unavailable");
  assert.equal(binary.calls.length, 1);
  assert.equal(readJournal({ dir: d.dir }), null);
  assert.equal(existsSync(join(d.fenceDir, "backup", a)), false);
});

/** S5: the warm pass failed by churn (backup_failed), with the set's checked parent `parent`. */
async function churned(parent) {
  const ctx = setup("agent", 1, { warm: { ok: false, code: "backup_failed", message: "Strict backup failed" } });
  ctx.deps.parent = parent;
  return { ...ctx, r: await backupSet(ctx.set, RUN, ctx.deps) };
}

test("d2r9 S5, T2(a): no prior good snapshot: a warm pass failed by churn, then the frozen pass with NO parent, and the set is good", async () => {
  const { d, members: [a], binary, r } = await churned(null);
  assert.deepEqual(r, { outcome: "good", snapshot: G, consistency: "turn", warm: null, code: null, recovered: null });
  assert.deepEqual(binary.calls.map((c) => [c.state, c.fenced[0], c.frozen[0]]), [["warm", false, false], ["good", true, true], ["readback", false, false]], "no warm snapshot to forget");
  assert.equal(Object.hasOwn(binary.calls[1].req, "parent"), false, "no parent at all");
  assert.equal(readJournal({ dir: d.dir }), null, "the journal is cleared");
  assert.equal(existsSync(join(d.fenceDir, "backup", a)), false);
});

test("d2r9 S5, T2(b): a checked prior good snapshot: the frozen pass after churn takes it as its parent, and the set is good", async () => {
  const { binary, r } = await churned(P);
  assert.equal(r.outcome, "good");
  assert.equal(binary.calls[1].state, "good");
  assert.equal(binary.calls[1].req.parent, P);
});

for (const code of ["destination_unavailable", "no_space", "quota_exceeded", "timed_out", "bad_result"]) {
  test(`d2r9 S5, T2: a warm pass failing ${code} (not churn) fails the set with that code: no frozen pass, nothing fenced`, async () => {
    const { d, members: [a], binary, set, deps } = setup("agent", 1, { warm: { ok: false, code, message: "" } });
    const r = await backupSet(set, RUN, deps);
    assert.deepEqual([r.outcome, r.code, binary.calls.length], ["failed", code, 1]);
    assert.equal(readJournal({ dir: d.dir }), null);
    assert.equal(existsSync(join(d.fenceDir, "backup", a)), false);
  });
}

test("a read-back with findings, or that fails: failed, never good", async () => {
  for (const answer of [{ ok: true, value: { findings: 2 } }, { ok: false, code: "readback_failed", message: "" }]) {
    const { set, deps } = setup("agent", 1, { readback: answer });
    const r = await backupSet(set, RUN, deps);
    assert.equal(r.outcome, "failed"); assert.equal(r.snapshot, null);
  }
});

test("a recovery while the run waited for idle (a lease stop): the run sees it and never freezes", async () => {
  let ctx;
  const lease = { activeTurns: async (a) => { await recoverBackup(a, { dir: ctx.d.dir, fenceDir: ctx.d.fenceDir, cg: ctx.deps.cg, ...clock() }); return 0; } };
  ctx = setup("agent", 1, {}, lease);
  const r = await backupSet(ctx.set, RUN, ctx.deps);
  assert.equal(r.outcome, "abandoned"); assert.equal(r.code, "recovered");
  assert.ok(!ctx.binary.calls.some((c) => c.state === "good"));
  assert.equal(ctx.groups[agentSliceCgroup(ctx.members[0])].frozen, false);
});

test("a recovery during the warm pass: the run doesn't come back, its warm snapshot is named for cleanup, nothing is fenced or frozen", async () => {
  let ctx;
  ctx = setup("agent", 1, { warm: async () => {
    await recoverBackup(ctx.members[0], { dir: ctx.d.dir, fenceDir: ctx.d.fenceDir, cg: ctx.deps.cg, ...clock() });
    return { ok: true, value: { snapshot: { id: W } } };
  } });
  const r = await backupSet(ctx.set, RUN, ctx.deps);
  assert.equal(r.outcome, "abandoned"); assert.equal(r.code, "recovered"); assert.equal(r.warm, W);
  assert.deepEqual(ctx.binary.calls.map((c) => c.state), ["warm"], "no good pass, no read-back");
  const j = readJournal({ dir: ctx.d.dir });
  assert.equal(j.state, "released"); assert.equal(j.aborted, true); assert.equal(j.warm, W, "the warm snapshot stays named, to be forgotten");
  assert.equal(existsSync(join(ctx.d.fenceDir, "backup", ctx.members[0])), false);
  assert.equal(ctx.groups[agentSliceCgroup(ctx.members[0])].frozen, false);
});

test("another run's journal written meanwhile is never overwritten or cleared: during a failed or a good warm pass, the idle wait, the read-back", async () => {
  const B = () => newJournal("20261124T040000Z-bbbbbbbb", [newId()]);
  const cases = {
    "a failed warm pass": (ctx) => ({ warm: () => { ctx.b = B(); writeJournal(ctx.b, { dir: ctx.d.dir }); return { ok: false, code: "destination_unavailable", message: "" }; } }),
    "a good warm pass": (ctx) => ({ warm: () => { ctx.b = B(); writeJournal(ctx.b, { dir: ctx.d.dir }); return { ok: true, value: { snapshot: { id: W } } }; } }),
    "the read-back": (ctx) => ({ readback: (req) => { ctx.b = B(); writeJournal(ctx.b, { dir: ctx.d.dir }); return { ok: true, value: { snapshot: { id: req.snapshot }, findings: 0 } }; } }),
  };
  for (const [name, answersFor] of Object.entries(cases)) {
    const ctx = {};
    Object.assign(ctx, setup("agent", 1, answersFor(ctx))); // the answers run later, once ctx.d is set
    const r = await backupSet(ctx.set, RUN, ctx.deps);
    assert.deepEqual(readJournal({ dir: ctx.d.dir }), ctx.b, `${name}: B's journal is exactly as B wrote it`);
    if (name !== "a failed warm pass") assert.notEqual(r.outcome, "good", `${name}: A is never good once B replaced its record`);
    if (name === "a good warm pass") {
      assert.equal(r.code, "recovered");
      assert.ok(!ctx.binary.calls.some((c) => c.state === "good"), `${name}: nothing is frozen for a run that isn't ours`);
      assert.equal(existsSync(join(ctx.d.fenceDir, "backup", ctx.members[0])), false);
    }
  }
  // during the idle wait
  const ctx = {};
  Object.assign(ctx, setup("agent", 1, {}, { activeTurns: async () => { if (!ctx.b) { ctx.b = B(); writeJournal(ctx.b, { dir: ctx.d.dir }); } return 0; } }));
  const r = await backupSet(ctx.set, RUN, ctx.deps);
  assert.equal(r.code, "recovered"); assert.deepEqual(readJournal({ dir: ctx.d.dir }), ctx.b);
  assert.ok(!ctx.binary.calls.some((c) => c.state === "good"));
});

test("the SAME agent's journal replaced by run B, then A throws (in the warm pass or the read-back): B stays exact, A is never good", async () => {
  for (const when of ["warm", "readback"]) {
    const ctx = {};
    Object.assign(ctx, setup("agent", 1, { [when]: () => {
      ctx.b = newJournal("20261124T050000Z-cccccccc", [ctx.members[0]]);
      writeJournal(ctx.b, { dir: ctx.d.dir });
      throw new Error("killed");
    } }));
    const r = await backupSet(ctx.set, RUN, ctx.deps);
    assert.notEqual(r.outcome, "good", when); assert.equal(r.code, "error", when);
    assert.deepEqual(readJournal({ dir: ctx.d.dir }), ctx.b, `${when}: B's journal is exactly as B wrote it`);
    assert.equal(r.recovered.run, null, `${when}: the recovery didn't act on B`);
  }
});

test("an archive (never live): one good backup and its read-back, no fence and no freeze", async () => {
  const { d, binary, set, deps } = setup("archive", 1);
  const r = await backupSet(set, RUN, deps);
  assert.equal(r.outcome, "good"); assert.equal(r.consistency, null);
  assert.deepEqual(binary.calls.map((c) => c.state), ["good", "readback"]);
  assert.deepEqual(binary.calls[0].req.tags, [`sb-run=${RUN}`, "sb-state=good", "sb-kind=archive", `archive=${set.id}`]);
  assert.equal(readJournal({ dir: d.dir }), null);
});

test("another run's journal present: refused before anything runs", async () => {
  const { d, binary, set, deps } = setup();
  writeJournal(newJournal("20261124T020000Z-bbbbbbbb", [newId()]), { dir: d.dir });
  await assert.rejects(backupSet(set, RUN, deps), (e) => e instanceof FleetError && e.code === "in_progress");
  assert.equal(binary.calls.length, 0);
});

test("a throw in the good pass (the binary call itself fails): caught, and the recovery order thaws, then unfences", async () => {
  const { d, members: [a], groups, set, deps } = setup("agent", 1, { good: () => { throw new Error("killed"); } });
  const r = await backupSet(set, RUN, deps);
  assert.equal(r.outcome, "abandoned"); assert.equal(r.code, "error"); assert.equal(r.warm, W);
  assert.deepEqual(r.recovered, { run: RUN, reaped: true, thawed: true, backupLowered: true, state: "released" });
  assert.equal(groups[agentSliceCgroup(a)].frozen, false);
  assert.equal(existsSync(join(d.fenceDir, "backup", a)), false);
});

test("a throw in the warm pass: caught, the run released by the recovery order, nothing fenced", async () => {
  const { d, members: [a], set, deps } = setup("agent", 1, { warm: () => { throw new Error("killed"); } });
  const r = await backupSet(set, RUN, deps);
  assert.equal(r.outcome, "abandoned"); assert.equal(r.code, "error"); assert.equal(r.recovered.state, "released");
  assert.equal(existsSync(join(d.fenceDir, "backup", a)), false);
});

test("a throw while freezing one tag member: every member thawed and unfenced, no partial freeze or fence left", async () => {
  const { d, members, groups, set, deps } = setup("tag", 3);
  const freeze = deps.cg.freeze;
  deps.cg.freeze = (p, on) => { if (on && p === agentSliceCgroup(members[1])) throw Object.assign(new Error("EIO"), { code: "EIO" }); return freeze(p, on); };
  const r = await backupSet(set, RUN, deps);
  assert.equal(r.outcome, "abandoned"); assert.ok(["error", "freeze_failed"].includes(r.code), r.code);
  for (const a of members) { assert.equal(groups[agentSliceCgroup(a)].frozen, false); assert.equal(existsSync(join(d.fenceDir, "backup", a)), false); }
});

test("a thaw that keeps throwing: the recovery order can't prove it, so the fence stays up", async () => {
  const { d, members: [a], groups, set, deps } = setup("agent", 1, {
    good: () => { deps.cg.freeze = (p, on) => { if (!on) throw Object.assign(new Error("EIO"), { code: "EIO" }); groups[p].frozen = on; }; return { ok: true, value: { snapshot: { id: G } } }; },
  });
  const r = await backupSet(set, RUN, deps);
  assert.equal(r.outcome, "abandoned");
  assert.equal(groups[agentSliceCgroup(a)].frozen, true);
  assert.ok(existsSync(join(d.fenceDir, "backup", a)), "never a fence down on a frozen slice");
});

test("a lease read that never answers: the one idle deadline still holds, and the pass goes on as consistency=crash", { timeout: 10000 }, async () => {
  const { d, members: [a], set, deps } = setup("agent", 1, {}, { activeTurns: () => new Promise(() => {}) });
  const t0 = Date.now();
  const r = await backupSet(set, RUN, { ...deps, limits: { idleMs: 300, pollMs: 50 } });
  const took = Date.now() - t0;
  assert.equal(r.outcome, "good"); assert.equal(r.consistency, "crash");
  assert.ok(took < 3000, `bounded by the idle deadline (took ${took} ms)`);
  assert.equal(existsSync(join(d.fenceDir, "backup", a)), false);
});

test("a recovery of the same run during the read-back: not good, and its released record is left for cleanup", async () => {
  let ctx;
  ctx = setup("agent", 1, { readback: async (req) => {
    await recoverBackup(ctx.members[0], { dir: ctx.d.dir, fenceDir: ctx.d.fenceDir, cg: ctx.deps.cg, ...clock() });
    return { ok: true, value: { snapshot: { id: req.snapshot }, findings: 0 } };
  } });
  const r = await backupSet(ctx.set, RUN, ctx.deps);
  assert.equal(r.outcome, "abandoned"); assert.equal(r.code, "recovered"); assert.equal(r.snapshot, null);
  const j = readJournal({ dir: ctx.d.dir });
  assert.equal(j.run, RUN); assert.equal(j.aborted, true);
});

test("the worker scope: the binary runs in place under systemd-run --scope, in the backup slice", () => {
  assert.deepEqual(scopedArgv(RUN, "/opt/sagebrush/bin/sagebrush-agent-backup", ["--state", "/s"]), [
    "/usr/bin/systemd-run",
    ["--scope", "--quiet", "--collect", `--unit=${workerUnit(RUN)}`, "--slice=sagebrush-backup.slice", "--", "/opt/sagebrush/bin/sagebrush-agent-backup", "--state", "/s"],
  ]);
  const seen = [];
  scopedSpawn(RUN, (cmd, args, opts) => { seen.push([cmd, args, opts]); return null; })("/b", ["x"], { env: {} });
  assert.equal(seen[0][0], "/usr/bin/systemd-run"); assert.deepEqual(seen[0][2], { env: {} });
  assert.throws(() => scopedArgv("bad", "/b", []), (e) => e.code === "bad_form");
});

// ---- wiring r0.4 §4 Q1 and init-run d6 §6.1 A1 ----

test("an explicitly absent turn-lease provider (lease: null): no wait at all, the pass is consistency=crash", async () => {
  const { set, deps } = setup();
  let slept = 0;
  const r = await backupSet(set, RUN, { ...deps, lease: null, sleep: async (ms) => { slept += ms; deps.tick?.(ms); } });
  assert.deepEqual([r.outcome, r.consistency], ["good", "crash"]);
  assert.equal(slept, 0, "never waited for an idle that can't be proven");
  // The control: a configured provider that fails still waits its bound, and is never an idle proof.
  const c = setup(undefined, undefined, undefined, { activeTurns: async () => { throw new Error("down"); } });
  let waited = 0;
  const rc = await backupSet(c.set, RUN, { ...c.deps, sleep: async (ms) => { waited += ms; c.deps.tick?.(ms); }, limits: { idleMs: 3000, pollMs: 1000 } });
  assert.equal(rc.consistency, "crash");
  assert.ok(waited > 0, "a configured provider's failure is waited out");
});

test("A1: a lock lost at ANY guard point stops the pass there: lock_lost, no recovery, no later call, cgroup op, journal or fence change; a later recovery restores everything", async () => {
  let points = 0;
  for (let k = 1; ; k += 1) {
    const { d, members: [a], groups, binary, set, deps } = setup();
    let n = 0, lostAt = null;
    const guard = () => { n += 1; if (n >= k) { lostAt ??= { calls: binary.calls.length, journal: readJournal({ dir: d.dir }), fenced: existsSync(join(d.fenceDir, "backup", a)), frozen: groups[agentSliceCgroup(a)].frozen }; throw Object.assign(new Error("lost"), { code: "lock_lost" }); } };
    const cgOps = [];
    const cg = Object.fromEntries(Object.entries(deps.cg).map(([op, f]) => [op, (...x) => { cgOps.push({ op, lost: lostAt !== null }); return f(...x); }]));
    let out;
    try { out = await backupSet(set, RUN, { ...deps, cg, guard }); } catch (e) { out = e; }
    if (lostAt === null) { assert.equal(out.outcome, "good"); break; } // (k past the last guard point: the pass completes)
    points += 1;
    assert.equal(out?.code, "lock_lost", `k=${k}: rejects lock_lost (never an abandon through recovery)`);
    assert.equal(binary.calls.length, lostAt.calls, `k=${k}: no binary call after the loss`);
    assert.deepEqual(cgOps.filter((o) => o.lost), [], `k=${k}: no cgroup operation after the loss`);
    assert.deepEqual(readJournal({ dir: d.dir }), lostAt.journal, `k=${k}: the journal kept as it stood`);
    assert.equal(existsSync(join(d.fenceDir, "backup", a)), lostAt.fenced, `k=${k}: no fence change`);
    // The next run's recovery (recoverLeftover's order) reaps, thaws and lowers.
    if (lostAt.journal !== null) {
      const rec = await recoverBackup(a, { dir: d.dir, fenceDir: d.fenceDir, cg: deps.cg, now: deps.now, sleep: deps.sleep });
      assert.equal(rec.state, "released", `k=${k}`);
      assert.equal(groups[agentSliceCgroup(a)].frozen, false);
      assert.equal(existsSync(join(d.fenceDir, "backup", a)), false);
    }
  }
  assert.ok(points >= 15, `every guard point lost once (${points})`);
});

for (const [flow, answers, end] of [["a pass that succeeds", {}, "good"], ["a pass that abandons (its good backup fails)", { good: { ok: false, code: "backup_failed" } }, "abandoned"]]) test(`A1: a lock lost right after ANY cgroup operation (a freeze, a thaw, a reap) in ${flow}: the next cgroup operation, fence change or journal write never runs`, async () => {
  let points = 0;
  for (let k = 1; ; k += 1) {
    const { d, set, deps } = setup("agent", 1, answers);
    let ops = 0, isLost = false, after = 0, atLoss = null;
    const guard = () => { if (isLost) throw Object.assign(new Error("lost"), { code: "lock_lost" }); };
    const cg = Object.fromEntries(Object.entries(deps.cg).map(([op, f]) => [op, (...x) => {
      if (isLost) after += 1;
      const r = f(...x);
      ops += 1;
      if (ops === k) { // (lost while that operation ran: before the next one)
        isLost = true;
        atLoss = { fence: existsSync(join(d.fenceDir, "backup", set.members[0])), journal: JSON.stringify(readJournal({ dir: d.dir })) };
      }
      return r;
    }]));
    let out;
    try { out = await backupSet(set, RUN, { ...deps, cg, guard }); } catch (e) { out = e; }
    if (!isLost) { assert.equal(out.outcome, end); break; }
    points += 1;
    assert.equal(out?.code, "lock_lost", `k=${k}`);
    assert.equal(after, 0, `k=${k}: no cgroup operation after the loss`);
    assert.equal(existsSync(join(d.fenceDir, "backup", set.members[0])), atLoss.fence, `k=${k}: no fence change after the loss (the release's and an abandon's included)`);
    assert.equal(JSON.stringify(readJournal({ dir: d.dir })), atLoss.journal, `k=${k}: no journal write after the loss`);
    assert.ok(readJournal({ dir: d.dir }) !== null || k === 0);
  }
  assert.ok(points >= 4, `every cgroup operation lost after once (${points})`);
});

test("d2r10 P1: a set's parent is its recorded last good snapshot only as the store's listing shows it: good, strict-marked, this set's own tags, the same paths; anything else is no parent", () => {
  const id = newId(), other = newId();
  const agent = { kind: "agent", id, sources: ["/srv/sagebrush/agents/x/home", "/srv/sagebrush/agents/x/sessions", "/srv/sagebrush/agent-config/x"], members: [id] };
  const R = "a".repeat(64);
  const rec = (o = {}) => ({ id: R, tree: "b".repeat(64), host: "h1", paths: [...agent.sources].reverse(), tags: ["sb-run=r", "sb-state=good", "sb-kind=agent", `agent=${id}`, "consistency=turn", STRICT_MARK], summary: null, time: "t", ...o });
  const newer = { ...rec(), id: "c".repeat(64), tags: ["sb-run=r2", "sb-state=good", "sb-kind=agent", `agent=${id}`] }; // (newest, unmarked)
  const warm = { ...rec(), id: "d".repeat(64), tags: ["sb-run=r3", "sb-state=warm", "sb-kind=agent", `agent=${id}`, STRICT_MARK] };
  const otherSet = { ...rec(), id: "e".repeat(64), tags: ["sb-run=r4", "sb-state=good", "sb-kind=agent", `agent=${other}`, STRICT_MARK] };
  assert.equal(checkedParent(agent, R, [warm, otherSet, newer, rec()]), R, "the recorded good one, whatever is newer");
  for (const [what, listed, want] of [
    ["unmarked", [rec({ tags: rec().tags.filter((t) => t !== STRICT_MARK) })], null],
    ["a mark-like tag", [rec({ tags: [...rec().tags.filter((t) => t !== STRICT_MARK), "sagebrush.walk=strictX"] })], null],
    ["not good (warm)", [rec({ tags: rec().tags.map((t) => (t === "sb-state=good" ? "sb-state=warm" : t)) })], null],
    ["another agent's tags", [rec({ tags: rec().tags.map((t) => (t === `agent=${id}` ? `agent=${other}` : t)) })], null],
    ["another class (an archive of the same id)", [rec({ tags: rec().tags.map((t) => (t === "sb-kind=agent" ? "sb-kind=archive" : t === `agent=${id}` ? `archive=${id}` : t)) })], null],
    ["fewer paths", [rec({ paths: agent.sources.slice(1) })], null],
    ["other paths", [rec({ paths: [...agent.sources.slice(1), "/srv/sagebrush/agents/y/home"] })], null],
    ["a path with a trailing slash", [rec({ paths: [...agent.sources.slice(1), `${agent.sources[0]}/`] })], null],
    ["not listed", [newer, warm, otherSet], null],
    ["no listing (it failed)", null, null],
  ]) assert.equal(checkedParent(agent, R, listed), want, what);
  assert.equal(checkedParent(agent, null, [rec()]), null, "nothing recorded: no parent, never a listed one");
  // The other classes' own tags.
  const tag = { kind: "tag", id, sources: ["/srv/sagebrush/tags/x"], members: [] };
  assert.equal(checkedParent(tag, R, [rec({ paths: tag.sources, tags: ["sb-state=good", "sb-kind=tag", `tag=${id}`, STRICT_MARK] })]), R);
  assert.equal(checkedParent(tag, R, [rec({ paths: tag.sources, tags: ["sb-state=good", "sb-kind=tag", `agent=${id}`, STRICT_MARK] })]), null);
  const arch = { kind: "archive", id, sources: ["/srv/sagebrush/archive/x", "/srv/sagebrush/archive-config/x"], members: [] };
  assert.equal(checkedParent(arch, R, [rec({ paths: arch.sources, tags: ["sb-state=good", "sb-kind=archive", `archive=${id}`, STRICT_MARK] })]), R);
});
