// Host restore e2e r1.7 §3 and delta d2: the restore worker's real wiring. The detached start resolves only once the
// scope is active (never waiting for the worker); the supervisor's seam builds the input from the store's RECORDED
// identities of this epoch (another epoch, or no record, gives no input and no worker), admits by the registry and
// the fences, and starts the worker with the host's mount; the worker's deps build the adapters from its input; the
// stop proof is asked live; the worker's main prints one line with its exit code.
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { existsSync, mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "./host-linux-only.mjs";
import { FleetError, newId } from "../lib/fleet/index.mjs";
import { raiseFence } from "../lib/fleet/host/fence.mjs";
import { createPlan } from "../lib/fleet/host/restore-plan.mjs";
import { newRestoreRun } from "../lib/fleet/host/restore-record.mjs";
import { BEGIN, writeRequest } from "../lib/fleet/host/restore-begin.mjs";
import { INPUTS, readInput } from "../lib/fleet/host/restore-inputs.mjs";
import { EMPTY_LISTING } from "../lib/fleet/host/restore-adapters.mjs";
import { liveStop, restoreWorkerSeam, startDetached, workerDeps } from "../lib/fleet/host/restore-wiring.mjs";
import { parseWorkerArgv, workerMain } from "../lib/fleet/host/restore-worker-main.mjs";
import { workerScope } from "../lib/fleet/host/restore-worker.mjs";

const UID = typeof process.getuid === "function" ? process.getuid() : -1;
const rejects = (p, code) => assert.rejects(p, (e) => (e instanceof FleetError || e?.code) && e.code === code, code);
const RUN = newRestoreRun(1795500000000, () => Buffer.alloc(6));
const hex = (c) => c.repeat(64);
const EPOCH = { boot_id: "00000000-0000-4000-8000-000000000000", mnt_id: 7 }, FSID = "0123456789abcdef";
const obj = (over = {}) => ({ type: "dir", mode: 0o700, uid: 70000, gid: 70000, dev: [8, 1], ino: 4242, gen: 1, mnt_id: 7, projid: 70000, inherit: true, ...over });
const line = (x) => JSON.stringify(x) + "\n";

/** A fake child process: emits exit when told. */
function fakeSpawn() {
  const spawned = [];
  const spawn = (cmd, args, opts) => { const c = new EventEmitter(); c.unref = () => { c.unrefd = true; }; spawned.push({ cmd, args, opts, c }); return c; };
  return { spawned, spawn };
}
const workerArgvFor = (unit) => ["systemd-run", "--scope", "--quiet", "--collect", "--slice=sagebrush.slice", `--unit=${unit}`, "--", "/n", "/m", "restore-worker"];

test("startDetached: spawned detached and unreferenced; resolves once the scope is active, never waiting for the worker", async () => {
  const unit = workerScope("agent", newId());
  const f = fakeSpawn();
  let asks = 0;
  await startDetached(workerArgvFor(unit), unit, { spawn: f.spawn, isActive: async () => (++asks >= 3), poll: 1 });
  assert.equal(f.spawned.length, 1);
  assert.deepEqual([f.spawned[0].cmd, f.spawned[0].opts.detached, f.spawned[0].opts.stdio, f.spawned[0].c.unrefd], ["systemd-run", true, "ignore", true]);
  assert.equal(asks, 3, "resolved at the first active answer; the child never exited");
  // The scope ended before it was active: refused.
  const g = fakeSpawn();
  const p = startDetached(workerArgvFor(unit), unit, { spawn: g.spawn, isActive: async () => false, poll: 1, ms: 600_000 });
  await new Promise((r) => setImmediate(r));
  g.spawned[0].c.emit("exit", 1, null);
  // Refused at once on the exit, not at the (long) deadline.
  const quick = await Promise.race([p.then(() => "resolved", (e) => e.code), new Promise((r) => setTimeout(() => r("stuck"), 500))]);
  assert.equal(quick, "effect_failed");
  // Never active in time: refused.
  let t = 0;
  await rejects(startDetached(workerArgvFor(unit), unit, { spawn: fakeSpawn().spawn, isActive: async () => false, now: () => (t += 1000), ms: 3000, sleep: async () => {} }), "effect_failed");
  // Not a worker's argv: refused before anything is spawned.
  const h = fakeSpawn();
  assert.throws(() => startDetached(["sh", "-c", "x"], unit, { spawn: h.spawn, isActive: async () => true }), (e) => e.code === "bad_form");
  assert.throws(() => startDetached(workerArgvFor(unit), workerScope("tag", newId()), { spawn: h.spawn, isActive: async () => true }), (e) => e.code === "bad_form");
  assert.equal(h.spawned.length, 0);
});

/** An open restore with agent A's set requested, and a fence directory. */
function world({ sets }) {
  const base = mkdtempSync(join(tmpdir(), "sb-wiring-"));
  const dir = join(base, "restore"), fenceDir = join(base, "fence");
  mkdirSync(dir, { mode: 0o700 });
  mkdirSync(fenceDir, { mode: 0o700 });
  writeFileSync(join(dir, BEGIN), JSON.stringify({ v: 1, snapshot: hex("1"), manifest_sha256: hex("2"), run: RUN, state: "done" }) + "\n", { mode: 0o600 });
  createPlan({ v: 1, host: "old", manifest: hex("1"), sha256: hex("2"), hoststore: hex("3"), sets: Object.fromEntries(sets.map((k) => [k, { run: RUN, snapshot: hex("1"), tree: hex("4") }])) }, { dir });
  for (const k of sets) writeRequest(k, RUN, { dir, uid: UID });
  return { base, dir, fenceDir };
}
function storeOf(a, { state = "running", recorded = true, epoch = EPOCH } = {}) {
  const registry = { v: 1, next_uid: 70010, next_gid: 80010, agents: { [a]: { uid: 70000, state, life: 1, gen: 1, tags: [], start_failed: null } }, tags: {} };
  return {
    registry: { agent: (x) => registry.agents[x] ?? null, tag: () => null, snapshot: () => structuredClone(registry) },
    provisioned: { record: (x) => (x === a && recorded ? { uid: 70000, quota: true, home: { epoch, fsid: FSID, dir: obj({ uid: 0, gid: 0, projid: 70000 }), entries: { home: obj({ ino: 1 }), "var-tmp": obj({ ino: 2 }), sessions: obj({ ino: 3 }) } } } : null) },
  };
}
const launcher = (epoch = EPOCH) => async (args) => {
  if (args[0] === "inspect-home") return { code: 0, stdout: line({ epoch, fsid: FSID, dir: obj({ uid: 0, gid: 0 }), entries: { home: obj({ ino: 1 }), "var-tmp": obj({ ino: 2 }), sessions: obj({ ino: 3 }) } }) };
  return { code: 0, stdout: EMPTY_LISTING };
};

test("the supervisor's seam: an input from the RECORDED identities of this epoch, the worker started with the host's mount; no record or another epoch, no worker", async () => {
  const a = newId(), key = `agent-${a}`;
  const w = world({ sets: [key] });
  raiseFence("restore", a, { dir: w.fenceDir });
  const started = [];
  const seam = (over = {}) => restoreWorkerSeam({ store: storeOf(a), launch: launcher(), mount: "/srv/quota", main: "/opt/r/restore-worker-main.mjs", node: "/n",
    isActive: async () => true, dir: w.dir, uid: UID, fenceDir: w.fenceDir, gateOpen: async () => true, start: async (argv) => { started.push(argv); }, ...over });
  const out = await seam().dispatch(1000, new AbortController().signal);
  assert.deepEqual(out, { dispatched: key });
  const argv = started[0];
  assert.deepEqual(argv.slice(-6), ["restore-worker", "agent", a, RUN, argv.at(-2), "/srv/quota"]);
  const input = readInput("agent", a, { dir: w.dir, uid: UID });
  assert.equal(input.nonce, argv.at(-2));
  assert.deepEqual(input.classes.home.dest.object, obj({ ino: 1 }), "the provisioning's record, not a fresh read");
  assert.deepEqual(input.classes.sessions.dest.object, obj({ ino: 3 }));
  assert.deepEqual(input.classes.home.unrestorable, []);
  // The record in another epoch than the destination's now: no input, no worker.
  for (const s of [storeOf(a, { epoch: { ...EPOCH, mnt_id: 8 } }), storeOf(a, { recorded: false })]) {
    const w2 = world({ sets: [key] });
    raiseFence("restore", a, { dir: w2.fenceDir });
    started.length = 0;
    const o = await restoreWorkerSeam({ store: s, launch: launcher(), mount: "/", main: "/m", isActive: async () => true, dir: w2.dir, uid: UID, fenceDir: w2.fenceDir,
      gateOpen: async () => true, start: async (x) => { started.push(x); } }).dispatch(1000);
    assert.deepEqual([o.dispatched, o.no_identity, started.length, existsSync(join(w2.dir, INPUTS, `${key}.json`))], [null, [key], 0, false]);
  }
  // Advisory admission: an agent without its restore fence, or deleted, isn't started.
  const w3 = world({ sets: [key] });
  started.length = 0;
  assert.equal((await restoreWorkerSeam({ store: storeOf(a), launch: launcher(), mount: "/", main: "/m", isActive: async () => true, dir: w3.dir, uid: UID, fenceDir: w3.fenceDir,
    gateOpen: async () => true, start: async (x) => { started.push(x); } }).dispatch(1000)).dispatched, null, "no restore fence");
  // An archive set with no creation record yet: no input, no worker.
  const w4 = world({ sets: [`archive-${a}`] });
  const o4 = await restoreWorkerSeam({ store: storeOf(a, { state: "deleted" }), launch: launcher(), mount: "/", main: "/m", isActive: async () => true, dir: w4.dir, uid: UID,
    fenceDir: w4.fenceDir, gateOpen: async () => true, start: async (x) => { started.push(x); } }).dispatch(1000);
  assert.deepEqual([o4.no_identity, started.length], [[`archive-${a}`], 0]);
  // The gate closed: nothing.
  assert.deepEqual(await seam({ gateOpen: async () => false }).dispatch(1000), { dispatched: null, why: "suspended" });
  // hold: R3a's, over the same restore directory.
  const held = await seam().hold(a, []);
  assert.equal(typeof held.invalidate, "function");
  await held.release();
});

test("the worker's deps: identify without an input; the adapters (and isEmpty) only from the input runWorker read", async () => {
  const a = newId();
  const deps = workerDeps({ launch: launcher(), mount: "/", fenceRaised: async () => true, sliceEmpty: async () => true });
  assert.deepEqual((await deps.identifyDest("agent", a, "sessions")).object, obj({ ino: 3 }));
  await rejects(deps.isEmpty("agent", a, "home", {}), "outcome_unknown");
  const input = { v: 1, kind: "agent", id: a, run: RUN, nonce: newId(), members: [{ agent: a, uid: 70000 }],
    classes: Object.fromEntries(["home", "sessions"].map((c, i) => [c, { dest: { epoch: EPOCH, fsid: FSID, object: obj({ ino: i + 1 }) }, owners: { uids: [70000], gid: 70000, projid: 70000 }, unrestorable: [] }])) };
  const fillSet = deps.filler({ admit: async () => {}, veto: async () => false }, input);
  assert.equal(typeof fillSet, "function", "the fill driver over the adapters");
  const expectDir = join(mkdtempSync(join(tmpdir(), "sb-wiring-x-")), "expect");
  const d2 = workerDeps({ launch: launcher(), mount: "/", fenceRaised: async () => true, sliceEmpty: async () => true, adapterOpts: { expectDir, rootUid: UID, rootGid: process.getgid() } });
  d2.filler({ admit: async () => {}, veto: async () => false }, input);
  assert.equal(await d2.isEmpty("agent", a, "home", { epoch: EPOCH, fsid: FSID, object: obj({ ino: 1 }) }), true, "the empty listing");
});

test("the live stop proof: the restore fence raised and the agent's slice empty, asked now; an unreadable slice is never empty", async () => {
  const a = newId();
  const fenceDir = mkdtempSync(join(tmpdir(), "sb-wiring-f-"));
  let count = 0;
  const asked = [];
  const sys = { procCount: (unit) => { asked.push(unit); if (count === null) throw new Error("EIO"); return count; } };
  const s = liveStop({ sys, fenceDir });
  assert.equal(await s.fenceRaised(a), false);
  raiseFence("restore", a, { dir: fenceDir });
  assert.equal(await s.fenceRaised(a), true);
  assert.equal(await s.sliceEmpty(a), true);
  assert.deepEqual(asked, [`sagebrush-agents-${a}.slice`]);
  count = 2;
  assert.equal(await s.sliceEmpty(a), false);
  count = null;
  assert.equal(await s.sliceEmpty(a), false);
});

test("the worker's main: exactly its argv; one line; 0 when it ran, 3 refused, 1 anything else, 2 bad arguments", async () => {
  const a = newId(), n = newId();
  assert.deepEqual(parseWorkerArgv(["restore-worker", "agent", a, RUN, n, "/"]), { kind: "agent", id: a, run: RUN, nonce: n, mount: "/" });
  for (const bad of [[], ["restore-worker", "home", a, RUN, n, "/"], ["restore-worker", "agent", a, RUN, n], ["restore-worker", "agent", a, RUN, n, "/", "x"],
    ["restore-worker", "agent", a, "bad", n, "/"], ["restore-worker", "agent", a, RUN, "nope", "/"], ["restore-worker", "agent", a, RUN, n, "rel"], ["other", "agent", a, RUN, n, "/"]]) {
    assert.equal(parseWorkerArgv(bad), null, JSON.stringify(bad));
    assert.equal((await workerMain(bad, { run: async () => { throw new Error("never"); } })).code, 2);
  }
  const args = ["restore-worker", "tag", a, RUN, n, "/"];
  const seen = [];
  const ok = await workerMain(args, { depsOf: (x) => { seen.push(x); return { d: 1 }; }, run: async (...x) => { seen.push(x); return { status: "validated" }; } });
  assert.deepEqual(ok, { code: 0, line: { v: 1, set: `tag-${a}`, status: "validated" } });
  assert.deepEqual(seen[1].slice(0, 5), ["tag", a, RUN, n, { d: 1 }]);
  assert.deepEqual(await workerMain(args, { depsOf: () => ({}), run: async () => { throw new FleetError("in_progress", "busy"); } }), { code: 3, line: { v: 1, set: `tag-${a}`, refused: "in_progress" } });
  assert.deepEqual(await workerMain(args, { depsOf: () => ({}), run: async () => { throw new Error("boom"); } }), { code: 1, line: { v: 1, set: `tag-${a}`, failed: true } });
});

test("composed for real: runWorker -> workerDeps -> the fill driver -> the adapters; not empty stops at admission, empty binds the input's identity before the first stage", async () => {
  const { runWorker } = await import("../lib/fleet/host/restore-worker.mjs");
  const { readRecord } = await import("../lib/fleet/host/restore-record.mjs");
  const { writeInput } = await import("../lib/fleet/host/restore-inputs.mjs");
  for (const empty of [false, true]) {
    const a = newId(), key = `archive-${a}`;
    const w = world({ sets: [key] });
    const dest = obj({ uid: 0, gid: 0, projid: 70000 });
    const nonce = newId();
    writeInput({ v: 1, kind: "archive", id: a, run: RUN, nonce, members: [],
      classes: { archive: { dest: { epoch: EPOCH, fsid: FSID, object: dest }, owners: { uids: [70000], gid: 70000, projid: 70000 }, unrestorable: [] } } }, { dir: w.dir, uid: UID });
    const calls = [];
    const launch = async (args) => {
      calls.push(args[0]);
      if (args[0] === "identify") return { code: 0, stdout: line({ epoch: EPOCH, fsid: FSID, object: args.includes("/srv/sagebrush/archive") ? dest : null }) };
      if (args[0] === "tree-digest") return { code: 0, stdout: empty ? EMPTY_LISTING : '{"v":1}\n{"path":"x","type":"file","size":1,"mode":420,"sha256":"' + "0".repeat(64) + '"}\n{"count":1,"total_bytes":1}\n' };
      if (args[0] === "restore-stage") return { code: 73, stdout: "" }; // stop at the first stage: a permanent failure
      return { code: 0, stdout: "" };
    };
    const staging = join(w.base, "staging");
    const deps = workerDeps({ launch, mount: "/", fenceRaised: async () => true, sliceEmpty: async () => true, dir: w.dir,
      adapterOpts: { expectDir: join(w.base, "expect"), staging, copies: join(w.base, "copies"), rootUid: UID, rootGid: process.getgid() } });
    if (!empty) {
      await rejects(runWorker("archive", a, RUN, nonce, deps, { dir: w.dir, uid: UID }), "not_granted");
      const r = readRecord("archive", a, { dir: w.dir });
      assert.deepEqual([r.state, r.dest], ["staging", null], "nothing bound");
      assert.ok(!calls.includes("restore-stage"), "nothing staged");
    } else {
      const out = await runWorker("archive", a, RUN, nonce, deps, { dir: w.dir, uid: UID });
      assert.deepEqual([out.status, out.record.reason], ["failed", "outcome_unknown"]);
      assert.deepEqual(out.record.dest.archive, { dev: String(8 * 2 ** 20 + 1), ino: "4242", uid: 0, gid: 0, mode: 0o700, projid: 70000 }, "bound to the input's recorded object");
      assert.ok(calls.indexOf("tree-digest") < calls.indexOf("restore-stage"), "admitted empty before the first stage");
    }
  }
});
