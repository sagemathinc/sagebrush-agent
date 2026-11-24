// Host backup r3.3 §6: the scheduler. Off unless set up (a root-owned 0600 destination and enabled flag in the root
// 0700 backup directory); one run at a time; change-aware; a left-over run recovered first; the manifest committed
// only when every part is good, and the state written only after it; retention, the weekly prune and the day's data
// check after it; the cache's fixed image and its trim; the status the person sees; the systemd units.
import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync, lstatSync, readdirSync, utimesSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "./host-linux-only.mjs";
import { FleetError, newId } from "../lib/fleet/index.mjs";
import { advance, newJournal, readJournal, writeJournal } from "../lib/fleet/host/backup-journal.mjs";
import { raiseFence } from "../lib/fleet/host/fence.mjs";
import { agentSliceCgroup } from "../lib/fleet/host/names.mjs";
import {
  ROOT_RESERVE, backupEnabled, backupUnits, buildStatus, cacheEffects, emptyState, failClosedLease, newRunId, planRun,
  readState, recoverLeftover, runOnce, setKey, trimPlan, withRunLock, writeState,
} from "../lib/fleet/host/backup-scheduler.mjs";

const refused = (fn, code) => assert.throws(fn, (e) => e instanceof FleetError && e.code === code, code);
const rejects = (p, code) => assert.rejects(p, (e) => e instanceof FleetError && e.code === code, code);
const hex = (n) => n.toString(16).padStart(64, "0");
const me = process.getuid();

function setupDir() {
  const dir = join(mkdtempSync(join(tmpdir(), "sb-sched-")), "backup");
  mkdirSync(dir, { mode: 0o700 }); chmodSync(dir, 0o700);
  for (const f of ["dest.json", "enabled"]) { writeFileSync(join(dir, f), "{}", { mode: 0o600 }); chmodSync(join(dir, f), 0o600); }
  return dir;
}

test("enabled only with a root 0700 directory holding a root-owned 0600 dest.json and enabled flag, never links", () => {
  const dir = setupDir();
  assert.deepEqual(backupEnabled({ dir, rootUid: me }), { enabled: true });
  assert.equal(backupEnabled({ dir: join(dir, "nope"), rootUid: me }).enabled, false);
  assert.equal(backupEnabled({ dir, rootUid: me + 1 }).enabled, false, "owned by someone else than root");
  { const d = setupDir(); chmodSync(join(d, "enabled"), 0o644); assert.equal(backupEnabled({ dir: d, rootUid: me }).enabled, false, "a group- or world-readable flag"); }
  { const d = setupDir(); chmodSync(d, 0o755); assert.equal(backupEnabled({ dir: d, rootUid: me }).enabled, false, "a readable directory"); }
  { const d = setupDir(); const t = join(d, "..", "flag"); writeFileSync(t, "x", { mode: 0o600 }); chmodSync(t, 0o600); rmSync(join(d, "enabled")); symlinkSync(t, join(d, "enabled")); assert.equal(backupEnabled({ dir: d, rootUid: me }).enabled, false, "a link is never the flag"); }
  { const d = setupDir(); rmSync(join(d, "dest.json")); assert.deepEqual(backupEnabled({ dir: d, rootUid: me }), { enabled: false, why: "not set up" }); }
  { const d = setupDir(); rmSync(join(d, "enabled")); mkdirSync(join(d, "enabled"), { mode: 0o600 }); chmodSync(join(d, "enabled"), 0o600); assert.equal(backupEnabled({ dir: d, rootUid: me }).enabled, false, "a 0600 directory is not the flag file"); }
});

test("run ids: the UTC second and 8 base32 characters", () => {
  const id = newRunId(Date.parse("2026-11-24T03:00:07.123Z"), () => Buffer.from([0, 1, 2, 3, 31, 32, 63, 255]));
  assert.equal(id, "20261124T030007Z-abcd7a77");
  assert.match(newRunId(Date.now()), /^[0-9]{8}T[0-9]{6}Z-[a-z2-7]{8}$/);
});

const set = (kind, id) => ({ kind, id, sources: [`/srv/${kind}/${id}`], uids: [70000], members: kind === "agent" ? [id] : [] });
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

test("the plan: a set whose fingerprint matches its last good snapshot keeps it; any other is backed up, with that snapshot as parent", () => {
  const [a, b, c] = [newId(), newId(), newId()];
  const state = { ...emptyState(), sets: {
    [`agent:${a}`]: { fingerprint: { e: 1 }, snapshot: hex(1), tree: hex(11), since: null },
    [`agent:${b}`]: { fingerprint: { e: 1 }, snapshot: hex(2), tree: hex(12), since: null },
  } };
  const fps = new Map([[`agent:${a}`, { e: 1 }], [`agent:${b}`, { e: 2 }], [`agent:${c}`, { e: 1 }]]);
  const plan = planRun([set("agent", a), set("agent", b), set("agent", c)], fps, state, same);
  assert.deepEqual(plan.map((p) => [p.back_up, p.parent, p.keep]), [
    [false, hex(1), { snapshot: hex(1), tree: hex(11) }], [true, hex(2), null], [true, null, null],
  ]);
});

test("the cache trim: the least recently used first, down to the target", () => {
  const files = [{ path: "a", size: 5, atime: 3 }, { path: "b", size: 5, atime: 1 }, { path: "c", size: 5, atime: 2 }];
  assert.deepEqual(trimPlan(files, 10), ["b"]);
  assert.deepEqual(trimPlan(files, 4), ["b", "c", "a"]);
  assert.deepEqual(trimPlan(files, 15), []);
});

test("status: not set up, or ok / failing with the last success and the oldest change not yet backed up", () => {
  assert.equal(buildStatus({ enabled: { enabled: false, why: "not set up" }, state: emptyState() }).state, "not set up");
  const state = { ...emptyState(), last_success: 100, sets: { x: { fingerprint: null, snapshot: null, tree: null, since: 50 }, y: { fingerprint: null, snapshot: null, tree: null, since: 70 } } };
  assert.deepEqual(buildStatus({ enabled: { enabled: true }, state, lastRun: { status: "failed" } }), { state: "failing", last_success: 100, debt_since: 50, sets: 2 });
  assert.equal(buildStatus({ enabled: { enabled: true }, state: { ...state, sets: {} } }).debt_since, null);
});

test("the units: a oneshot in the backup slice, and a daily 03:00 timer that catches up a missed run", () => {
  const u = backupUnits("/opt/sagebrush/release-1");
  assert.match(u.service, /^ExecStart=\/opt\/sagebrush\/release-1\/bin\/sagebrush-agent host backup run$/m);
  assert.match(u.service, /^Type=oneshot$/m); assert.match(u.service, /^Slice=sagebrush-backup\.slice$/m);
  assert.match(u.timer, /^OnCalendar=\*-\*-\* 03:00:00$/m); assert.match(u.timer, /^Persistent=true$/m);
  for (const bad of ["rel", "/a/../b", "/a b", "/a;b"]) refused(() => backupUnits(bad), "bad_form");
});

test("the state file round-trips and refuses anything not its closed shape", () => {
  const dir = setupDir();
  assert.deepEqual(readState({ dir }), emptyState());
  const s = { ...emptyState(), last_success: 1, sets: { k: { fingerprint: { e: 1 }, snapshot: hex(1), tree: hex(2), since: null } } };
  writeState(s, { dir });
  assert.deepEqual(readState({ dir }), s);
  writeFileSync(join(dir, "state.json"), JSON.stringify({ ...s, extra: 1 }));
  refused(() => readState({ dir }), "bad_form");
});

/** Fakes for runOnce: records every call in order. */
function fakes({ enabled = { enabled: true }, free = 10 * ROOT_RESERVE, sets = null, fingerprints = {}, state = emptyState(), outcomes = {}, commit = { ok: true, snapshot: hex(900) }, prunePast = true } = {}) {
  const [a, b] = [newId(), newId()];
  const registry = { v: 1, next_uid: 70002, next_gid: 80000, agents: {
    [a]: { uid: 70000, state: "running", life: 0, gen: 1, tags: [], start_failed: null },
    [b]: { uid: 70001, state: "running", life: 0, gen: 1, tags: [], start_failed: null } }, tags: {} };
  const theSets = sets ?? [set("agent", a), set("agent", b)];
  const calls = [];
  let written = null, n = 0;
  const deps = {
    enabled: () => enabled,
    withRunLock: async (fn) => { calls.push("lock"); return fn(); },
    freeBytes: () => free,
    ensureCache: async () => { calls.push("cache"); },
    trimCache: async () => { calls.push("trim"); },
    recoverLeftover: async () => { calls.push("recover"); },
    registry: () => registry,
    configHash: (id) => hex(500 + Object.keys(registry.agents).indexOf(id)),
    forbidden: () => ["/srv/sagebrush/claude-profiles"],
    sources: () => theSets,
    checkForbidden: () => { calls.push("forbidden"); },
    walk: (s) => ({ fingerprint: fingerprints[setKey(s)] ?? { e: 1 }, unrestorable: { count: 0, paths: [] } }),
    unchanged: same,
    backupSet: async (s, run, { parent }) => {
      calls.push(`backup:${setKey(s)}:${parent ?? "none"}`);
      const o = outcomes[setKey(s)] ?? { outcome: "good", snapshot: hex(100 + n++) };
      return o;
    },
    copyHostStore: async (staging) => { calls.push("hoststore-copy"); return staging; },
    binary: async (req) => {
      calls.push(`binary:${req.op}`);
      if (req.op === "snapshots") return { ok: true, value: { snapshots: Array.from({ length: 300 }, (_, i) => ({ id: hex(i), tree: hex(1000 + i) })) } };
      if (req.op === "prune") return { ok: true, value: { stats: "" } };
      if (req.op === "check-data") return { ok: true, value: { part: req.part, of: req.of, findings: 0 } };
      throw new Error(req.op);
    },
    buildManifest: (args) => { calls.push("build"); deps.lastManifest = args; return { args }; },
    commitManifest: async () => { calls.push("commit"); return commit; },
    retention: async () => { calls.push("retention"); return { kept: [], roots: [], forgotten: [] }; },
    pruneDue: () => prunePast,
    checkDataPart: () => ({ part: 7, of: 30 }),
    state: { read: () => state, write: (s) => { calls.push("state"); written = s; } },
    host: "h1", now: () => Date.parse("2026-11-24T03:00:00Z"), stagingDir: (name) => `/var/lib/sagebrush/backup/${name}`,
  };
  return { deps, calls, a, b, written: () => written };
}

test("not set up, or the root reserve short: nothing runs", async () => {
  {
    const f = fakes({ enabled: { enabled: false, why: "not set up" } });
    assert.deepEqual(await runOnce(f.deps), { status: "not set up", why: "not set up" });
    assert.deepEqual(f.calls, []);
  }
  {
    const f = fakes({ free: ROOT_RESERVE - 1 });
    assert.deepEqual(await runOnce(f.deps), { status: "skipped", why: "root_reserve" });
    assert.deepEqual(f.calls, ["lock"]);
  }
});

test("a full run: cache, a left-over run recovered, forbidden roots checked, each set, the host store, then the manifest, the state, retention, prune and the data check", async () => {
  const f = fakes();
  const r = await runOnce(f.deps);
  assert.equal(r.status, "ok"); assert.equal(r.manifest, hex(900));
  assert.deepEqual(f.calls, ["lock", "cache", "recover", "forbidden",
    `backup:agent:${f.a}:none`, `backup:agent:${f.b}:none`, "hoststore-copy", "backup:hoststore:host:none",
    "binary:snapshots", "build", "commit", "retention", "binary:prune", "binary:check-data", "state", "trim"]);
  const w = f.written();
  assert.equal(w.last_success, Date.parse("2026-11-24T03:00:00Z"));
  assert.equal(w.last_check_day, Math.floor(Date.parse("2026-11-24T03:00:00Z") / 86400000));
  assert.equal(w.sets[`agent:${f.a}`].since, null);
  assert.deepEqual(Object.keys(f.deps.lastManifest.config).sort(), [f.a, f.b].sort(), "a config hash per live agent");
  assert.ok(f.deps.lastManifest.sets.every((s) => /^[0-9a-f]{64}$/.test(s.tree)), "trees from the store's listing");
});

test("change-aware: an unchanged set keeps its last good snapshot in the manifest and isn't backed up", async () => {
  const f0 = fakes();
  const state = { ...emptyState(), sets: { [`agent:${f0.a}`]: { fingerprint: { e: 1 }, snapshot: hex(5), tree: hex(55), since: null } } };
  const f = fakes({ state, sets: f0.deps.sources(), fingerprints: {} });
  f.deps.registry = f0.deps.registry; f.a = f0.a; f.b = f0.b;
  const r = await runOnce(f.deps);
  assert.equal(r.status, "ok");
  assert.ok(!f.calls.includes(`backup:agent:${f0.a}:none`) && !f.calls.some((c) => c.startsWith(`backup:agent:${f0.a}`)), "the unchanged set isn't backed up");
  const kept = f.deps.lastManifest.sets.find((s) => s.id === f0.a);
  assert.deepEqual([kept.snapshot, kept.tree], [hex(5), hex(55)]);
});

test("a set that fails: no host store, no manifest; the state records the debt, not a success", async () => {
  const f0 = fakes();
  const f = fakes({ sets: f0.deps.sources(), outcomes: { [`agent:${f0.b}`]: { outcome: "abandoned", code: "cap" } } });
  f.deps.registry = f0.deps.registry;
  const r = await runOnce(f.deps);
  assert.equal(r.status, "failed"); assert.deepEqual(r.failures, [{ key: `agent:${f0.b}`, code: "cap" }]);
  assert.ok(!f.calls.includes("commit") && !f.calls.includes("hoststore-copy"));
  const w = f.written();
  assert.equal(w.last_success, null);
  assert.equal(w.sets[`agent:${f0.b}`].since, Date.parse("2026-11-24T03:00:00Z"));
});

test("a manifest that doesn't commit: not a success, and retention never runs", async () => {
  const f = fakes({ commit: { ok: false, code: "readback_failed" } });
  const r = await runOnce(f.deps);
  assert.equal(r.status, "failed");
  assert.ok(!f.calls.includes("retention"));
  assert.equal(f.written().last_success, null);
});

test("the prune only when due, the data check once a day", async () => {
  const day = Math.floor(Date.parse("2026-11-24T03:00:00Z") / 86400000);
  const f = fakes({ prunePast: false, state: { ...emptyState(), last_check_day: day } });
  await runOnce(f.deps);
  assert.ok(!f.calls.includes("binary:prune") && !f.calls.includes("binary:check-data"));
});

test("the turn-lease stand-in fails closed", async () => {
  await assert.rejects(failClosedLease.activeTurns(newId()));
});

test("a left-over run: recovered in order (scoped to it), its warm snapshot forgotten, its record cleared", async () => {
  const root = mkdtempSync(join(tmpdir(), "sb-left-"));
  const dir = join(root, "backup"), fenceDir = join(root, "fence");
  mkdirSync(dir, { mode: 0o700 }); mkdirSync(fenceDir, { mode: 0o700 });
  const a = newId(), run = "20261124T020000Z-abcdefgh";
  writeJournal({ ...advance(advance(advance(newJournal(run, [a]), "fenced"), "idle"), "frozen"), warm: hex(77) }, { dir });
  raiseFence("backup", a, { dir: fenceDir });
  const groups = { [agentSliceCgroup(a)]: { frozen: true } };
  const cg = { kill: () => {}, procs: () => 0, freeze: (p, on) => { groups[p].frozen = on; }, frozen: (p) => groups[p]?.frozen ?? false };
  const forgets = [];
  const binary = async (req) => { forgets.push(req); return { ok: true, value: { forgotten: 1 } }; };
  const clock = (() => { let t = 0; return { now: () => t, sleep: async (ms) => { t += ms; } }; })();
  assert.deepEqual(await recoverLeftover({ binary, dir, fenceDir, cg, ...clock }), { ok: true, recovered: run });
  assert.equal(groups[agentSliceCgroup(a)].frozen, false);
  assert.equal(existsSync(join(fenceDir, "backup", a)), false);
  assert.deepEqual(forgets, [{ op: "forget", snapshots: [hex(77)] }]);
  assert.equal(readJournal({ dir }), null);
  assert.deepEqual(await recoverLeftover({ binary, dir, fenceDir, cg, ...clock }), { ok: true, recovered: null });
});

test("a left-over run that can't be recovered, an unreadable journal, or a warm forget that fails: refused, nothing cleared", async () => {
  const mk = () => { const root = mkdtempSync(join(tmpdir(), "sb-left-")); const dir = join(root, "backup"), fenceDir = join(root, "fence"); mkdirSync(dir, { mode: 0o700 }); mkdirSync(fenceDir, { mode: 0o700 }); return { dir, fenceDir }; };
  const clock = () => { let t = 0; return { now: () => t, sleep: async (ms) => { t += ms; } }; };
  {
    const { dir, fenceDir } = mk(); const a = newId();
    writeJournal(advance(advance(advance(newJournal("20261124T020000Z-abcdefgh", [a]), "fenced"), "idle"), "frozen"), { dir });
    const cg = { kill: () => {}, procs: () => 0, freeze: () => {}, frozen: () => true }; // never thaws
    await rejects(recoverLeftover({ binary: async () => ({ ok: true }), dir, fenceDir, cg, ...clock() }), "outcome_unknown");
    assert.equal(readJournal({ dir }).state, "frozen");
  }
  {
    const { dir, fenceDir } = mk();
    writeFileSync(join(dir, "run.json"), "garbage");
    await rejects(recoverLeftover({ binary: async () => ({ ok: true }), dir, fenceDir }), "outcome_unknown");
  }
  {
    const { dir, fenceDir } = mk(); const a = newId();
    writeJournal({ ...newJournal("20261124T020000Z-abcdefgh", [a]), state: "released", aborted: true, warm: hex(77) }, { dir });
    await rejects(recoverLeftover({ binary: async () => ({ ok: false, code: "destination_unavailable" }), dir, fenceDir, ...clock() }), "outcome_unknown");
    assert.ok(readJournal({ dir }), "the record stays for the next try");
  }
});

test("the cache image: created sparse and formatted once, mounted nosuid,nodev,noexec; trimmed least recently used first", async () => {
  const root = mkdtempSync(join(tmpdir(), "sb-cache-"));
  const image = join(root, "cache.img"), mountpoint = join(root, "cache");
  const calls = [];
  let mounted = false;
  const run = async (argv) => {
    calls.push(argv);
    if (argv[0].endsWith("findmnt")) return { code: mounted ? 0 : 1, stdout: mounted ? "/dev/loop0\n" : "" };
    if (argv[0].endsWith("truncate")) { writeFileSync(image, ""); return { code: 0, stdout: "" }; }
    if (argv[0].endsWith("mount")) { mounted = true; return { code: 0, stdout: "" }; }
    return { code: 0, stdout: "" };
  };
  const c = cacheEffects({ run, image, mountpoint, bytes: 4096, trimTo: 10 });
  await c.ensureCache();
  assert.deepEqual(calls.map((x) => x[0].split("/").pop()), ["findmnt", "truncate", "mkfs.ext4", "mount"]);
  assert.deepEqual(calls[3].slice(1, 3), ["-o", "loop,nosuid,nodev,noexec"]);
  assert.equal(lstatSync(image).mode & 0o777, 0o600);
  await c.ensureCache();
  assert.equal(calls.length, 5, "already mounted: only the check");
  mkdirSync(join(mountpoint, "d"), { recursive: true });
  for (const [n, t] of [["old", 1000], ["mid", 2000], ["new", 3000]]) { writeFileSync(join(mountpoint, "d", n), "x".repeat(6)); utimesSync(join(mountpoint, "d", n), t, t); }
  assert.deepEqual(await c.trimCache(), { removed: 2 });
  assert.deepEqual(readdirSync(join(mountpoint, "d")), ["new"]);
  const bad = cacheEffects({ run: async (argv) => ({ code: argv[0].endsWith("findmnt") ? 1 : 2, stdout: "" }), image: join(root, "x.img"), mountpoint: join(root, "m") });
  await rejects(bad.ensureCache(), "preflight_missing");
});

test("one run at a time: a second run while one holds the run lock is refused", async () => {
  const dir = join(mkdtempSync(join(tmpdir(), "sb-runlock-")), "run");
  let second;
  await withRunLock(async () => { second = withRunLock(async () => "ran", { dir }); await assert.rejects(second, (e) => e.code === "in_progress"); }, { dir });
  assert.equal(await withRunLock(async () => "ran", { dir }), "ran", "free again afterwards");
});
