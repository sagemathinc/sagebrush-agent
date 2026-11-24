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
import { backupSet, scopedArgv, scopedSpawn, workerUnit } from "../lib/fleet/host/backup-run.mjs";

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
