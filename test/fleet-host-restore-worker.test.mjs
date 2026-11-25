// Host restore e2e r1.7 §3, §5: the restore worker and its dispatch, with a fake filler and launcher, real temporary
// restore directories and real flocks. The worker holds its set's lock for its whole life; it runs only for an open,
// begun restore, for exactly the plan's run of its set and that run's request; an abandon intent ends it before
// anything and vetoes the final publication; a bound destination that changed fails the set untouched; an unbound one
// is admitted at the bind only as the provisioned identity, empty; a lost lock aborts. Dispatch is advisory: one
// worker per host, while the gate is open, for the first eligible set.
import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "./host-linux-only.mjs";
import { FleetError, newId } from "../lib/fleet/index.mjs";
import { lockFile } from "../lib/fleet/host/store.mjs";
import { createPlan, closePlan } from "../lib/fleet/host/restore-plan.mjs";
import { newRecord, newRestoreRun, readRecord, step, writeRecord } from "../lib/fleet/host/restore-record.mjs";
import { ABANDON, BEGIN, writeRequest } from "../lib/fleet/host/restore-begin.mjs";
import {
  WORKER_SLICE, admitBind, agentBusy, dispatchOnce, readIntent, runWorker, setLockPath, stopWorker, workerArgv, workerLive, workerScope,
} from "../lib/fleet/host/restore-worker.mjs";

const refused = (fn, code) => assert.throws(fn, (e) => e instanceof FleetError && e.code === code, code);
const rejects = (p, code) => assert.rejects(p, (e) => e instanceof FleetError && e.code === code, code);
const UID = typeof process.getuid === "function" ? process.getuid() : -1; // (Linux-only rows; off Linux the file only loads)
const hex = (c) => c.repeat(64);
const RUN = newRestoreRun(1795500000000, () => Buffer.alloc(6)), RUN2 = newRestoreRun(1795600000000, () => Buffer.alloc(6, 1));
const SNAP = hex("1");
const settle = () => new Promise((r) => setTimeout(r, 200));
const OBJ = { type: "dir", mode: 0o700, uid: 70000, gid: 70000, dev: [8, 1], ino: 4242, gen: 1, mnt_id: 7, projid: 70000, inherit: true };
const PROV = { uid: 70000, gid: 70000, mode: 0o700, projid: 70000 };

/** A restore directory: begin.json (`state`), the plan of `sets` (key → run), each set's request (unless `noRequest`). */
function host({ sets, state = "done", noRequest = [], closed = false } = {}) {
  const base = mkdtempSync(join(tmpdir(), "sb-worker-"));
  const dir = join(base, "restore");
  mkdirSync(dir, { mode: 0o700 });
  writeFileSync(join(dir, BEGIN), JSON.stringify({ v: 1, snapshot: SNAP, manifest_sha256: hex("2"), run: RUN, state }) + "\n", { mode: 0o600 });
  const plan = { v: 1, host: "old-host", manifest: hex("1"), sha256: hex("2"), hoststore: hex("3"),
    sets: Object.fromEntries(Object.entries(sets).map(([k, run]) => [k, { run, snapshot: SNAP, tree: hex("4") }])) };
  createPlan(plan, { dir });
  if (closed) closePlan(1795500001000, { dir });
  for (const [k, run] of Object.entries(sets)) if (!noRequest.includes(k)) writeRequest(k, run, { dir, uid: UID });
  return { base, dir, plan };
}
const intent = (dir, key) => {
  mkdirSync(join(dir, ABANDON), { mode: 0o700, recursive: true });
  writeFileSync(join(dir, ABANDON, `${key}.json`), "{}\n", { mode: 0o600 });
};
/** A fake filler: records the hooks and every call; `body(hooks, kind, id, plan, opts)` is the fill. */
function filler(body = async () => ({ state: "validated" })) {
  const calls = [];
  let hooks;
  return { calls, get hooks() { return hooks; }, filler: (h) => { hooks = h; return async (kind, id, plan, opts) => { calls.push([kind, id]); return body(h, kind, id, plan, opts); }; } };
}
const deps = (f, over = {}) => ({
  filler: f.filler, identifyDest: async () => ({ object: OBJ }), provisioned: async () => PROV, isEmpty: async () => true, ...over,
});
const bound = (kind, id, run = RUN, dest = { dev: String(8 * 2 ** 20 + 1), ino: "4242", ...PROV }) => {
  const r = newRecord({ kind, id, run, snapshot: SNAP });
  const classes = { agent: ["home", "sessions"], archive: ["archive"], tag: ["tag"] }[kind];
  return step(r, "bind", { dest: Object.fromEntries(classes.map((c) => [c, dest])) });
};
const filesValidated = (kind, id) => {
  let r = bound(kind, id);
  for (const cls of ["home", "sessions"]) r = step(r, "digest", { cls, sha256: hex("5") });
  r = step(step(r, "staged"), "filling", { dest: r.dest });
  return step(step(r, "published"), "files_validated");
};
function killHolder(path) {
  let n = 0;
  for (const pid of readdirSync("/proc").filter((p) => /^[0-9]+$/.test(p))) {
    let cmd;
    try { cmd = readFileSync(`/proc/${pid}/cmdline`, "utf8").split("\0"); } catch { continue; }
    if (cmd[0].endsWith("flock") && cmd.includes(path)) { process.kill(Number(pid), "SIGKILL"); n += 1; }
  }
  assert.ok(n > 0, `a holder of ${path} was found`);
}

test("workerArgv: its own scope under the host's slice, never a shell; bad sets, runs and mains refused", () => {
  const id = newId();
  assert.equal(WORKER_SLICE, "sagebrush.slice");
  assert.equal(workerScope("agent", id), `sagebrush-restore-agent-${id}.scope`);
  assert.deepEqual(workerArgv("tag", id, RUN, { node: "/usr/bin/node", main: "/opt/sagebrush/main.mjs" }), [
    "systemd-run", "--scope", "--quiet", "--collect", "--slice=sagebrush.slice", `--unit=sagebrush-restore-tag-${id}.scope`,
    "--", "/usr/bin/node", "/opt/sagebrush/main.mjs", "restore-worker", "tag", id, RUN,
  ]);
  refused(() => workerArgv("home", id, RUN, { main: "/m" }), "bad_form");
  refused(() => workerArgv("agent", "nope", RUN, { main: "/m" }), "bad_form");
  refused(() => workerArgv("agent", id, "x; rm -rf /", { main: "/m" }), "bad_form");
  refused(() => workerArgv("agent", id, RUN, { main: "rel/main.mjs" }), "bad_form");
  assert.equal(setLockPath("/r", "archive", id), `/r/archive-${id}.lock`);
});

test("a worker holds its set's lock for its whole life: live while it runs, a second worker for the set refused, free after", async () => {
  const id = newId(), key = `agent-${id}`;
  const h = host({ sets: { [key]: RUN } });
  const seen = [];
  const f = filler(async () => {
    seen.push(await workerLive("agent", id, { dir: h.dir }));
    await rejects(runWorker("agent", id, RUN, deps(filler()), { dir: h.dir, uid: UID, waitMs: 0 }), "in_progress");
    return { state: "files_validated" };
  });
  assert.equal(await workerLive("agent", id, { dir: h.dir }), false);
  assert.equal(existsSync(setLockPath(h.dir, "agent", id)), false, "asking leaves no lock file");
  const out = await runWorker("agent", id, RUN, deps(f), { dir: h.dir, uid: UID });
  assert.deepEqual([out.status, seen, f.calls], ["files_validated", [true], [["agent", id]]]);
  assert.equal(await workerLive("agent", id, { dir: h.dir }), false, "released at the end");
  // Released on a refusal too.
  const g = filler(async () => { throw new FleetError("outcome_unknown", "boom"); });
  await rejects(runWorker("agent", id, RUN, deps(g), { dir: h.dir, uid: UID }), "outcome_unknown");
  assert.equal(await workerLive("agent", id, { dir: h.dir }), false);
});

test("a worker runs only for a begun, open restore, exactly its set's run and request: otherwise nothing is filled", async () => {
  const id = newId(), key = `archive-${id}`;
  const cases = [
    ["no begin", () => { const h = host({ sets: { [key]: RUN } }); writeFileSync(join(h.dir, BEGIN), ""); return h; }, null],
    ["begin not done", () => host({ sets: { [key]: RUN }, state: "begun" }), "in_progress"],
    ["plan closed", () => host({ sets: { [key]: RUN }, closed: true }), "not_granted"],
    ["not a set", () => host({ sets: { [`archive-${newId()}`]: RUN } }), "not_found"],
    ["another run", () => host({ sets: { [key]: RUN2 } }), "not_granted"],
    ["no request", () => host({ sets: { [key]: RUN }, noRequest: [key] }), "not_granted"],
  ];
  for (const [label, make, code] of cases) {
    const h = make();
    const f = filler();
    if (label === "no begin") {
      // An empty begin.json is malformed (bad_form); a missing one is not_found.
      await rejects(runWorker("archive", id, RUN, deps(f), { dir: h.dir, uid: UID }), "bad_form");
      const { rmSync } = await import("node:fs");
      rmSync(join(h.dir, BEGIN));
      await rejects(runWorker("archive", id, RUN, deps(f), { dir: h.dir, uid: UID }), "not_found");
    } else {
      await rejects(runWorker("archive", id, RUN, deps(f), { dir: h.dir, uid: UID }), code);
    }
    assert.deepEqual(f.calls, [], `${label}: nothing filled`);
    assert.equal(readRecord("archive", id, { dir: h.dir }), null, `${label}: nothing recorded`);
  }
  // A request of another run (rewritten under the plan's back) is refused too.
  const h = host({ sets: { [key]: RUN } });
  writeFileSync(join(h.dir, "requests", key), JSON.stringify({ run: RUN2 }) + "\n");
  await rejects(runWorker("archive", id, RUN, deps(filler()), { dir: h.dir, uid: UID }), "not_granted");
  // The request says this worker's run but the plan's set is another run's: refused on the plan alone.
  const hp = host({ sets: { [key]: RUN2 }, noRequest: [key] });
  writeRequest(key, RUN, { dir: hp.dir, uid: UID });
  const fp = filler();
  await rejects(runWorker("archive", id, RUN, deps(fp), { dir: hp.dir, uid: UID }), "not_granted");
  assert.deepEqual(fp.calls, []);
  // A restore directory that isn't private is refused before any lock file is made in it.
  const p = host({ sets: { [key]: RUN } });
  chmodSync(p.dir, 0o777);
  await rejects(runWorker("archive", id, RUN, deps(filler()), { dir: p.dir, uid: UID }), "not_granted");
  assert.equal(existsSync(setLockPath(p.dir, "archive", id)), false);
});

test("an abandon intent ends the worker before anything: no fill, the record untouched", async () => {
  for (const withRecord of [false, true]) {
    const id = newId(), key = `agent-${id}`;
    const h = host({ sets: { [key]: RUN } });
    if (withRecord) writeRecord(bound("agent", id), { dir: h.dir });
    const before = withRecord ? readFileSync(join(h.dir, `agent-${id}.json`), "utf8") : null;
    intent(h.dir, key);
    const f = filler();
    let identified = 0;
    const out = await runWorker("agent", id, RUN, deps(f, { identifyDest: async () => { identified += 1; return { object: OBJ }; } }), { dir: h.dir, uid: UID });
    assert.equal(out.status, "abandoning");
    assert.deepEqual([f.calls, identified], [[], 0]);
    assert.equal(withRecord ? readFileSync(join(h.dir, `agent-${id}.json`), "utf8") : readRecord("agent", id, { dir: h.dir }), before);
  }
  // An intent read through a link is refused, never followed.
  const id = newId(), key = `agent-${id}`;
  const h = host({ sets: { [key]: RUN } });
  const elsewhere = join(h.base, "elsewhere");
  mkdirSync(elsewhere, { mode: 0o700 });
  writeFileSync(join(elsewhere, `${key}.json`), "{}\n");
  symlinkSync(elsewhere, join(h.dir, ABANDON));
  await rejects(runWorker("agent", id, RUN, deps(filler()), { dir: h.dir, uid: UID }), "not_granted");
  refused(() => readIntent("agent", id, { dir: h.dir, uid: UID }), "not_granted");
});

test("a bound destination must still be exactly its identity: any field changed fails the set, nothing filled", async () => {
  for (const field of [null, "ino", "dev", "uid", "gid", "mode", "projid"]) {
    const id = newId(), key = `agent-${id}`;
    const h = host({ sets: { [key]: RUN } });
    writeRecord(bound("agent", id), { dir: h.dir });
    const obj = field === null ? OBJ : { ...OBJ, [field]: field === "dev" ? [8, 2] : field === "mode" ? 0o755 : OBJ[field] + 1 };
    const f = filler(async () => ({ state: "files_validated" }));
    const out = await runWorker("agent", id, RUN, deps(f, { identifyDest: async (k, i, cls) => ({ object: cls === "sessions" ? obj : OBJ }) }), { dir: h.dir, uid: UID });
    const r = readRecord("agent", id, { dir: h.dir });
    if (field === null) {
      assert.deepEqual([out.status, f.calls.length, r.state], ["files_validated", 1, "staging"], "unchanged: the fill runs");
    } else {
      assert.deepEqual([out.status, f.calls.length, r.state, r.reason], ["failed", 0, "failed", "outcome_unknown"], field);
    }
  }
});

test("admission at the bind: the provisioned identity, empty, for every class; anything else is refused", async () => {
  const id = newId();
  const r = newRecord({ kind: "agent", id, run: RUN, snapshot: SNAP });
  const dest = { home: { dev: "1", ino: "2", ...PROV }, sessions: { dev: "1", ino: "3", ...PROV } };
  const ids = { home: { object: OBJ }, sessions: { object: OBJ } };
  await admitBind(r, ids, dest, { provisioned: async () => PROV, isEmpty: async () => true });
  for (const k of ["uid", "gid", "mode", "projid"]) {
    await rejects(admitBind(r, ids, { ...dest, sessions: { ...dest.sessions, [k]: 1 } }, { provisioned: async () => PROV, isEmpty: async () => true }), "not_granted");
  }
  await rejects(admitBind(r, ids, dest, { provisioned: async () => null, isEmpty: async () => true }), "not_granted");
  const asked = [];
  await rejects(admitBind(r, ids, dest, { provisioned: async () => PROV, isEmpty: async (k, i, cls, x) => { asked.push([cls, x]); return cls !== "sessions"; } }), "not_granted");
  assert.deepEqual(asked, [["home", ids.home], ["sessions", ids.sessions]], "each class's own identified object");
  // A truthy non-true answer isn't empty.
  await rejects(admitBind(r, ids, dest, { provisioned: async () => PROV, isEmpty: async () => "yes" }), "not_granted");
});

test("the worker's hooks: admission through the provisioned deps; the veto reads the intent now", async () => {
  const id = newId(), key = `archive-${id}`;
  const h = host({ sets: { [key]: RUN } });
  const r = newRecord({ kind: "archive", id, run: RUN, snapshot: SNAP });
  const dest = { archive: { dev: "1", ino: "2", ...PROV } };
  const got = [];
  const f = filler(async (hooks) => {
    await hooks.admit(r, { archive: { object: OBJ } }, dest);
    got.push(await hooks.veto(r));
    intent(h.dir, key);
    got.push(await hooks.veto(r));
    await rejects(hooks.admit(r, { archive: { object: OBJ } }, { archive: { ...dest.archive, uid: 0 } }), "not_granted");
    return { state: "files_validated" };
  });
  await runWorker("archive", id, RUN, deps(f), { dir: h.dir, uid: UID });
  assert.deepEqual(got, [false, true]);
  const e = filler(async (hooks) => { await hooks.admit(r, { archive: { object: OBJ } }, dest); return { state: "validated" }; });
  const h2 = host({ sets: { [key]: RUN } });
  await rejects(runWorker("archive", id, RUN, deps(e, { isEmpty: async () => false }), { dir: h2.dir, uid: UID }), "not_granted");
});

test("a lost set lock aborts the fill and refuses outcome_unknown; the hooks refuse once it is gone", async () => {
  const id = newId(), key = `agent-${id}`;
  const h = host({ sets: { [key]: RUN } });
  let aborted = null;
  const f = filler(async (hooks, kind, i, plan, opts) => {
    killHolder(setLockPath(h.dir, "agent", id));
    await settle();
    await new Promise((r) => setTimeout(r, 100));
    aborted = opts.signal.aborted;
    await rejects(hooks.veto(), "outcome_unknown");
    await rejects(hooks.admit(newRecord({ kind: "agent", id, run: RUN, snapshot: SNAP }), {}, {}), "outcome_unknown");
    return { state: "files_validated" };
  });
  await rejects(runWorker("agent", id, RUN, deps(f), { dir: h.dir, uid: UID, pollMs: 50 }), "outcome_unknown");
  assert.equal(aborted, true, "the fill's signal was aborted");
  // Lost while a bound destination is checked: nothing is written.
  const h2 = host({ sets: { [key]: RUN } });
  writeRecord(bound("agent", id), { dir: h2.dir });
  const before = readFileSync(join(h2.dir, `agent-${id}.json`), "utf8");
  let killed = false;
  const kill = async () => { if (!killed) { killed = true; killHolder(setLockPath(h2.dir, "agent", id)); await settle(); } return { object: { ...OBJ, uid: 1 } }; };
  await rejects(runWorker("agent", id, RUN, deps(filler(), { identifyDest: kill }), { dir: h2.dir, uid: UID }), "outcome_unknown");
  assert.equal(readFileSync(join(h2.dir, `agent-${id}.json`), "utf8"), before, "no failed written after the loss");
});

test("dispatch: only a begun, open restore with the gate open; one worker per host; the first eligible set in key order", async () => {
  const a = newId(), b = newId(), c = newId();
  const keys = [`agent-${a}`, `archive-${b}`, `tag-${c}`];
  const mk = (over = {}) => host({ sets: Object.fromEntries(keys.map((k) => [k, RUN])), ...over });
  const run = async (h, over = {}) => {
    const started = [];
    const out = await dispatchOnce({ gateOpen: async () => true, admitted: async () => true, start: async (argv) => { started.push(argv); }, main: "/opt/m.mjs", node: "/n", ...over }, { dir: h.dir, uid: UID });
    return { out, started };
  };
  // The happy one: the first key.
  let h = mk();
  let { out, started } = await run(h);
  assert.deepEqual(out, { dispatched: keys[0] });
  assert.deepEqual(started, [workerArgv("agent", a, RUN, { node: "/n", main: "/opt/m.mjs" })]);
  // Refusals, nothing started.
  for (const [why, hh, over] of [
    ["begun", mk({ state: "begun" }), {}],
    ["closed", mk({ closed: true }), {}],
    ["suspended", mk(), { gateOpen: async () => false }],
  ]) {
    ({ out, started } = await run(hh, over));
    assert.deepEqual([out, started], [{ dispatched: null, why }, []], why);
  }
  const empty = mkdtempSync(join(tmpdir(), "sb-worker-none-"));
  out = await dispatchOnce({ gateOpen: async () => true }, { dir: empty, uid: UID });
  assert.deepEqual(out, { dispatched: null, why: "no_restore" });
  // A live worker for any set: none started.
  h = mk();
  const held = await lockFile(setLockPath(h.dir, "tag", c));
  ({ out, started } = await run(h));
  await held.release();
  assert.deepEqual([out, started], [{ dispatched: null, why: "busy" }, []]);
  // Skips: settled, an agent's files_validated (its imports), an intent, no request, not admitted.
  const skipped = (prep, over = {}) => async () => { const hh = mk(); prep(hh); return run(hh, over); };
  for (const [label, go, want] of [
    ["agent validated", skipped((hh) => writeRecord(filesValidated("agent", a), { dir: hh.dir })), keys[1]],
    ["agent failed", skipped((hh) => writeRecord(step(bound("agent", a), "failed", { reason: "not_found" }), { dir: hh.dir })), keys[1]],
    ["agent intent", skipped((hh) => intent(hh.dir, keys[0])), keys[1]],
    ["agent not admitted", skipped(() => {}, { admitted: async (k) => k !== "agent" }), keys[1]],
    ["nothing admitted", skipped(() => {}, { admitted: async () => "yes" }), null],
  ]) {
    ({ out, started } = await go());
    assert.equal(out.dispatched, want, label);
    assert.equal(started.length, want === null ? 0 : 1, label);
  }
  ({ out } = await (async () => { const hh = host({ sets: Object.fromEntries(keys.map((k) => [k, RUN])), noRequest: [keys[0]] }); return run(hh); })());
  assert.equal(out.dispatched, keys[1], "no request: skipped");
});

test("agentBusy: an agent's own set, its archive or a tag set it belongs to with a live worker", async () => {
  const a = newId(), t = newId();
  const h = host({ sets: { [`agent-${a}`]: RUN } });
  const opts = { dir: h.dir, tagsOf: () => [t] };
  assert.equal(await agentBusy(a, opts), false);
  for (const [kind, id] of [["agent", a], ["archive", a], ["tag", t]]) {
    const held = await lockFile(setLockPath(h.dir, kind, id));
    assert.equal(await agentBusy(a, opts), true, kind);
    await held.release();
    assert.equal(await agentBusy(a, opts), false, `${kind} released`);
  }
  await rejects(agentBusy("nope", opts), "bad_form");
  // No restore directory at all: nothing is busy.
  assert.equal(await agentBusy(a, { dir: join(h.base, "missing") }), false);
});

test("stopWorker: kills the scope, then proves it gone, bounded", async () => {
  const id = newId();
  const log = [];
  let gone = 2;
  const sys = { killScope: async (u) => { log.push(["kill", u]); }, scopeGone: async (u) => { log.push(["gone?", u]); return --gone <= 0; } };
  assert.equal(await stopWorker("agent", id, { sys, wait: async () => {} }), true);
  const unit = `sagebrush-restore-agent-${id}.scope`;
  assert.deepEqual(log, [["kill", unit], ["gone?", unit], ["gone?", unit]]);
  // A kill that throws still proves; never gone is false.
  const never = { killScope: async () => { throw new Error("no such unit"); }, scopeGone: async () => false };
  assert.equal(await stopWorker("agent", id, { sys: never, wait: async () => {}, tries: 3 }), false);
  const already = { killScope: async () => { throw new Error("no such unit"); }, scopeGone: async () => true };
  assert.equal(await stopWorker("agent", id, { sys: already, wait: async () => {} }), true);
});
