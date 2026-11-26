// Host restore e2e r1.7 §3, §5: the restore worker and its dispatch, with a fake filler and launcher, real temporary
// restore directories and real flocks. The worker holds its set's lock for its whole life; it runs only for an open,
// begun restore, for exactly the plan's run of its set and that run's request; an abandon intent ends it before
// anything and vetoes the final publication; a bound destination that changed fails the set untouched; an unbound one
// is admitted at the bind only as the provisioned identity, empty; a lost lock aborts. Dispatch is advisory: one
// worker per host, while the gate is open, for the first eligible set.
import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "./host-linux-only.mjs";
import { FleetError, newId } from "../lib/fleet/index.mjs";
import { lockFile } from "../lib/fleet/host/store.mjs";
import { createPlan, closePlan } from "../lib/fleet/host/restore-plan.mjs";
import { CLASSES, newRecord, newRestoreRun, readRecord, step, writeRecord } from "../lib/fleet/host/restore-record.mjs";
import { ABANDON, BEGIN, writeRequest } from "../lib/fleet/host/restore-begin.mjs";
import { INPUTS, readInput, writeInput } from "../lib/fleet/host/restore-inputs.mjs";
import {
  WORKER_SLICE, admitBind, dispatchOnce, holdSets, readIntent, runWorker, setLockPath, stopWorker, workerArgv, workerLive, workerScope,
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
const EPOCH = { boot_id: "00000000-0000-4000-8000-000000000000", mnt_id: 7 }, FSID = "0123456789abcdef";
/** OBJ as the launcher identifies it now (this epoch). */
const ID = { epoch: EPOCH, fsid: FSID, object: OBJ };
/** Every input in this file is written with this nonce, and every worker started with it. */
const NONCE = newId(), MEMBER = newId();
/** OBJ's identity in the record's form: what the provisioning recorded for it. */
const EXACT = { dev: String(8 * 2 ** 20 + 1), ino: "4242", ...PROV };

/** A restore directory: begin.json (`state`), the plan of `sets` (key → run), each set's request (unless `noRequest`). */
function host({ sets, state = "done", noRequest = [], noInput = [], closed = false } = {}) {
  const base = mkdtempSync(join(tmpdir(), "sb-worker-"));
  const dir = join(base, "restore");
  mkdirSync(dir, { mode: 0o700 });
  writeFileSync(join(dir, BEGIN), JSON.stringify({ v: 1, snapshot: SNAP, manifest_sha256: hex("2"), run: RUN, state }) + "\n", { mode: 0o600 });
  const plan = { v: 1, host: "old-host", manifest: hex("1"), sha256: hex("2"), hoststore: hex("3"),
    sets: Object.fromEntries(Object.entries(sets).map(([k, run]) => [k, { run, snapshot: SNAP, tree: hex("4") }])) };
  createPlan(plan, { dir });
  if (closed) closePlan(1795500001000, { dir });
  for (const [k, run] of Object.entries(sets)) if (!noRequest.includes(k)) writeRequest(k, run, { dir, uid: UID });
  for (const [k, run] of Object.entries(sets)) if (!noInput.includes(k)) { const [kind, id] = k.split("-"); writeInput(inputOf(kind, id, run, NONCE), { dir, uid: UID }); }
  return { base, dir, plan };
}
/** A set's input as a dispatch writes it: OBJ recorded for every class, owned by uid 70000. */
function inputOf(kind, id, run, nonce) {
  const classes = Object.fromEntries(CLASSES[kind]
    .map((c) => [c, { dest: { ...ID }, owners: { uids: [70000], gid: 70000, projid: 70000 }, unrestorable: [] }]));
  const members = kind === "agent" ? [{ agent: id, uid: 70000 }] : kind === "tag" ? [{ agent: MEMBER, uid: 70000 }] : [];
  return { v: 1, kind, id, run, nonce, classes, members };
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
const deps2 = (f, over = {}) => deps(f, over);
const deps = (f, over = {}) => ({
  filler: f.filler, identifyDest: async () => ({ ...ID }), isEmpty: async () => true, ...over,
});
const bound = (kind, id, run = RUN, dest = { dev: String(8 * 2 ** 20 + 1), ino: "4242", ...PROV }) => {
  const r = newRecord({ kind, id, run, snapshot: SNAP });
  const classes = CLASSES[kind];
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
  assert.deepEqual(workerArgv("tag", id, RUN, NONCE, { node: "/usr/bin/node", main: "/opt/sagebrush/main.mjs" }), [
    "systemd-run", "--scope", "--quiet", "--collect", "--slice=sagebrush.slice", `--unit=sagebrush-restore-tag-${id}.scope`,
    "--", "/usr/bin/node", "/opt/sagebrush/main.mjs", "restore-worker", "tag", id, RUN, NONCE, "/",
  ]);
  refused(() => workerArgv("home", id, RUN, NONCE, { main: "/m" }), "bad_form");
  refused(() => workerArgv("agent", "nope", RUN, NONCE, { main: "/m" }), "bad_form");
  refused(() => workerArgv("agent", id, "x; rm -rf /", NONCE, { main: "/m" }), "bad_form");
  refused(() => workerArgv("agent", id, RUN, NONCE, { main: "rel/main.mjs" }), "bad_form");
  refused(() => workerArgv("agent", id, RUN, "nope", { main: "/m" }), "bad_form");
  assert.equal(workerArgv("agent", id, RUN, NONCE, { main: "/m", mount: "/srv/quota" }).at(-1), "/srv/quota", "the quota mount, the supervisor's");
  for (const mount of ["rel", "/a b", "/a;b", ""]) refused(() => workerArgv("agent", id, RUN, NONCE, { main: "/m", mount }), "bad_form");
  assert.equal(setLockPath("/r", "archive", id), `/r/archive-${id}.lock`);
});

test("a worker holds its set's lock for its whole life: live while it runs, a second worker for the set refused, free after", async () => {
  const id = newId(), key = `agent-${id}`;
  const h = host({ sets: { [key]: RUN } });
  const seen = [];
  const f = filler(async () => {
    seen.push(await workerLive("agent", id, { dir: h.dir }));
    await rejects(runWorker("agent", id, RUN, NONCE, deps(filler()), { dir: h.dir, uid: UID, waitMs: 0 }), "in_progress");
    return { state: "files_validated" };
  });
  assert.equal(await workerLive("agent", id, { dir: h.dir }), false);
  assert.equal(existsSync(setLockPath(h.dir, "agent", id)), false, "asking leaves no lock file");
  const out = await runWorker("agent", id, RUN, NONCE, deps(f), { dir: h.dir, uid: UID });
  assert.deepEqual([out.status, seen, f.calls], ["files_validated", [true], [["agent", id]]]);
  assert.equal(await workerLive("agent", id, { dir: h.dir }), false, "released at the end");
  // Released on a refusal too.
  const g = filler(async () => { throw new FleetError("outcome_unknown", "boom"); });
  await rejects(runWorker("agent", id, RUN, NONCE, deps(g), { dir: h.dir, uid: UID }), "outcome_unknown");
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
      await rejects(runWorker("archive", id, RUN, NONCE, deps(f), { dir: h.dir, uid: UID }), "bad_form");
      const { rmSync } = await import("node:fs");
      rmSync(join(h.dir, BEGIN));
      await rejects(runWorker("archive", id, RUN, NONCE, deps(f), { dir: h.dir, uid: UID }), "not_found");
    } else {
      await rejects(runWorker("archive", id, RUN, NONCE, deps(f), { dir: h.dir, uid: UID }), code);
    }
    assert.deepEqual(f.calls, [], `${label}: nothing filled`);
    assert.equal(readRecord("archive", id, { dir: h.dir }), null, `${label}: nothing recorded`);
  }
  // A request of another run (rewritten under the plan's back) is refused too.
  const h = host({ sets: { [key]: RUN } });
  writeFileSync(join(h.dir, "requests", key), JSON.stringify({ run: RUN2 }) + "\n");
  await rejects(runWorker("archive", id, RUN, NONCE, deps(filler()), { dir: h.dir, uid: UID }), "not_granted");
  // The request says this worker's run but the plan's set is another run's: refused on the plan alone.
  const hp = host({ sets: { [key]: RUN2 }, noRequest: [key] });
  writeRequest(key, RUN, { dir: hp.dir, uid: UID });
  const fp = filler();
  await rejects(runWorker("archive", id, RUN, NONCE, deps(fp), { dir: hp.dir, uid: UID }), "not_granted");
  assert.deepEqual(fp.calls, []);
  // A restore directory that isn't private is refused before any lock file is made in it.
  const p = host({ sets: { [key]: RUN } });
  chmodSync(p.dir, 0o777);
  await rejects(runWorker("archive", id, RUN, NONCE, deps(filler()), { dir: p.dir, uid: UID }), "not_granted");
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
    const out = await runWorker("agent", id, RUN, NONCE, deps(f, { identifyDest: async () => { identified += 1; return { ...ID }; } }), { dir: h.dir, uid: UID });
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
  await rejects(runWorker("agent", id, RUN, NONCE, deps(filler()), { dir: h.dir, uid: UID }), "not_granted");
  refused(() => readIntent("agent", id, { dir: h.dir, uid: UID }), "not_granted");
});

test("a bound destination must still be exactly its identity: any field changed fails the set, nothing filled", async () => {
  for (const field of [null, "ino", "dev", "uid", "gid", "mode", "projid"]) {
    const id = newId(), key = `agent-${id}`;
    const h = host({ sets: { [key]: RUN } });
    writeRecord(bound("agent", id), { dir: h.dir });
    const obj = field === null ? OBJ : { ...OBJ, [field]: field === "dev" ? [8, 2] : field === "mode" ? 0o755 : OBJ[field] + 1 };
    const f = filler(async () => ({ state: "files_validated" }));
    const out = await runWorker("agent", id, RUN, NONCE, deps(f, { identifyDest: async (k, i, cls) => ({ ...ID, object: cls === "sessions" ? obj : OBJ }) }), { dir: h.dir, uid: UID });
    const r = readRecord("agent", id, { dir: h.dir });
    if (field === null) {
      assert.deepEqual([out.status, f.calls.length, r.state], ["files_validated", 1, "staging"], "unchanged: the fill runs");
    } else {
      assert.deepEqual([out.status, f.calls.length, r.state, r.reason], ["failed", 0, "failed", "outcome_unknown"], field);
    }
  }
});

test("admission at the bind: EXACTLY the provisioned object (every identity field), empty, for every class; anything else is refused", async () => {
  const id = newId();
  const r = newRecord({ kind: "agent", id, run: RUN, snapshot: SNAP });
  const dest = { home: { dev: "1", ino: "2", ...PROV }, sessions: { dev: "1", ino: "3", ...PROV } };
  const ids = { home: { ...ID }, sessions: { ...ID } };
  const provisioned = async (k, i, cls) => ({ ...dest[cls] });
  await admitBind(r, ids, dest, { provisioned, isEmpty: async () => true });
  // Each field changed alone, in either class: device and inode (another directory with the same owner and mode),
  // owner, group, mode, project.
  for (const cls of ["home", "sessions"]) {
    for (const [k, v] of [["dev", "9"], ["ino", "99"], ["uid", 1], ["gid", 1], ["mode", 0o755], ["projid", 1]]) {
      await rejects(admitBind(r, ids, { ...dest, [cls]: { ...dest[cls], [k]: v } }, { provisioned, isEmpty: async () => true }), "not_granted");
    }
  }
  // The trusted identity must be whole: missing, or missing any field, refuses.
  await rejects(admitBind(r, ids, dest, { provisioned: async () => null, isEmpty: async () => true }), "not_granted");
  for (const k of ["dev", "ino", "uid", "gid", "mode", "projid"]) {
    await rejects(admitBind(r, ids, dest, { provisioned: async (kk, i, cls) => { const x = { ...dest[cls] }; delete x[k]; return x; }, isEmpty: async () => true }), "not_granted");
  }
  const asked = [];
  await rejects(admitBind(r, ids, dest, { provisioned, isEmpty: async (k, i, cls, x) => { asked.push([cls, x]); return cls !== "sessions"; } }), "not_granted");
  assert.deepEqual(asked, [["home", ids.home], ["sessions", ids.sessions]], "each class's own identified object");
  // A truthy non-true answer isn't empty.
  await rejects(admitBind(r, ids, dest, { provisioned, isEmpty: async () => "yes" }), "not_granted");
});

test("through the real fill driver: the destination replaced by another EMPTY directory with the same owner, mode and project fails before any bind or launch", async () => {
  for (const kind of ["agent", "archive"]) {
    const id = newId(), key = `${kind}-${id}`;
    const h = host({ sets: { [key]: RUN } });
    const launched = [], touched = [];
    const never = (what) => async () => { touched.push(what); throw new Error(`${what} must not run`); };
    const { restoreFiller } = await import("../lib/fleet/host/restore-fill.mjs");
    const real = (hooks) => restoreFiller({
      launch: async (args) => { launched.push(args); throw new Error("no launch"); },
      mount: "/srv/sagebrush", root: join(h.base, "staging"), dir: h.dir,
      // Identified now: another inode than the provisioned one, every other field the same.
      identifyDest: async () => ({ ...ID, object: { ...OBJ, ino: OBJ.ino + 1 } }),
      expectOf: never("expectOf"), projidOf: () => 70000, cleanDest: never("cleanDest"), discardStaging: never("discardStaging"),
      stopped: never("stopped"), unrestorableOf: () => [], removeCopies: never("removeCopies"), ...hooks,
    });
    await rejects(runWorker(kind, id, RUN, NONCE, { ...deps(filler()), filler: real }, { dir: h.dir, uid: UID }), "not_granted");
    const r = readRecord(kind, id, { dir: h.dir });
    assert.deepEqual([r.state, r.dest, r.attempt], ["staging", null, 1], `${kind}: nothing bound`);
    assert.deepEqual([launched, touched], [[], []], `${kind}: nothing launched, cleaned or discarded`);
  }
});

test("the worker's hooks: admission through the provisioned deps; the veto reads the intent now", async () => {
  const id = newId(), key = `archive-${id}`;
  const h = host({ sets: { [key]: RUN } });
  const r = newRecord({ kind: "archive", id, run: RUN, snapshot: SNAP });
  const dest = { archive: EXACT, "archive-config": EXACT };
  const got = [];
  const f = filler(async (hooks) => {
    await hooks.admit(r, { archive: { ...ID }, "archive-config": { ...ID } }, dest);
    got.push(await hooks.veto(r));
    intent(h.dir, key);
    got.push(await hooks.veto(r));
    await rejects(hooks.admit(r, { archive: { ...ID }, "archive-config": { ...ID } }, { ...dest, archive: { ...dest.archive, uid: 0 } }), "not_granted");
    return { state: "files_validated" };
  });
  await runWorker("archive", id, RUN, NONCE, deps(f), { dir: h.dir, uid: UID });
  assert.deepEqual(got, [false, true]);
  const e = filler(async (hooks) => { await hooks.admit(r, { archive: { ...ID }, "archive-config": { ...ID } }, dest); return { state: "validated" }; });
  const h2 = host({ sets: { [key]: RUN } });
  await rejects(runWorker("archive", id, RUN, NONCE, deps(e, { isEmpty: async () => false }), { dir: h2.dir, uid: UID }), "not_granted");
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
  await rejects(runWorker("agent", id, RUN, NONCE, deps(f), { dir: h.dir, uid: UID, pollMs: 50 }), "outcome_unknown");
  assert.equal(aborted, true, "the fill's signal was aborted");
  // Lost while a bound destination is checked: nothing is written.
  const h2 = host({ sets: { [key]: RUN } });
  writeRecord(bound("agent", id), { dir: h2.dir });
  const before = readFileSync(join(h2.dir, `agent-${id}.json`), "utf8");
  let killed = false;
  const kill = async () => { if (!killed) { killed = true; killHolder(setLockPath(h2.dir, "agent", id)); await settle(); } return { object: { ...OBJ, uid: 1 } }; };
  await rejects(runWorker("agent", id, RUN, NONCE, deps(filler(), { identifyDest: kill }), { dir: h2.dir, uid: UID }), "outcome_unknown");
  assert.equal(readFileSync(join(h2.dir, `agent-${id}.json`), "utf8"), before, "no failed written after the loss");
});

test("dispatch: only a begun, open restore with the gate open; one worker per host; the first eligible set in key order", async () => {
  const a = newId(), b = newId(), c = newId();
  const keys = [`agent-${a}`, `archive-${b}`, `tag-${c}`];
  const mk = (over = {}) => host({ sets: Object.fromEntries(keys.map((k) => [k, RUN])), ...over });
  const run = async (h, over = {}) => {
    const started = [];
    const out = await dispatchOnce({ gateOpen: async () => true, anyWorker: async () => false, admitted: async () => true, start: async (argv) => { started.push(argv); }, main: "/opt/m.mjs", node: "/n", newNonce: () => NONCE, inputOf: async (k, i, r, n) => inputOf(k, i, r, n), ...over }, { dir: h.dir, uid: UID });
    return { out, started };
  };
  // The happy one: the first key.
  let h = mk();
  let { out, started } = await run(h);
  assert.deepEqual(out, { dispatched: keys[0] });
  assert.deepEqual(started, [workerArgv("agent", a, RUN, NONCE, { node: "/n", main: "/opt/m.mjs" })]);
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
  out = await dispatchOnce({ gateOpen: async () => true, anyWorker: async () => false }, { dir: empty, uid: UID });
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

test("holdSets: every lock of an agent's sets in an OPEN plan, held until released; refused, holding none, while any is held", async () => {
  const a = newId(), t = newId(), other = newId();
  const keys = { agent: `agent-${a}`, archive: `archive-${a}`, tag: `tag-${t}` };
  const h = host({ sets: { [keys.agent]: RUN, [keys.archive]: RUN, [keys.tag]: RUN, [`agent-${other}`]: RUN } });
  const free = async (kind, id) => { const l = await lockFile(setLockPath(h.dir, kind, id), { waitMs: 0 }); await l.release(); };
  const held = await holdSets(a, [t], { dir: h.dir });
  for (const [kind, id] of [["agent", a], ["archive", a], ["tag", t]]) {
    await rejects(lockFile(setLockPath(h.dir, kind, id), { waitMs: 0 }), "in_progress");
    // A worker for that set can't start: it exits busy, filling nothing.
    const f = filler();
    await rejects(runWorker(kind, id, RUN, NONCE, deps(f), { dir: h.dir, uid: UID }), "in_progress");
    assert.deepEqual(f.calls, [], `${kind}: nothing filled`);
  }
  await free("agent", other); // another agent's set isn't held
  await held.release();
  for (const [kind, id] of [["agent", a], ["archive", a], ["tag", t]]) await free(kind, id);
  // Any one held by a worker: null, and none of the others stays held.
  for (const [kind, id] of [["agent", a], ["archive", a], ["tag", t]]) {
    const w = await lockFile(setLockPath(h.dir, kind, id), { waitMs: 0 });
    assert.equal(await holdSets(a, [t], { dir: h.dir }), null, kind);
    await w.release();
    for (const [k2, i2] of [["agent", a], ["archive", a], ["tag", t]]) await free(k2, i2);
  }
  // A tag the caller names (the current or the incoming ones) is held; one it doesn't name isn't.
  const w = await lockFile(setLockPath(h.dir, "tag", t), { waitMs: 0 });
  const without = await holdSets(a, [], { dir: h.dir });
  assert.notEqual(without, null);
  await without.release();
  assert.equal(await holdSets(a, [t, t], { dir: h.dir }), null);
  await w.release();
  await rejects(holdSets("nope", [], { dir: h.dir }), "bad_form");
  // No restore here, or a closed one: nothing to hold (and no lock file made).
  const none = await holdSets(a, [t], { dir: join(h.base, "missing") });
  await none.release();
  const c = host({ sets: { [keys.agent]: RUN }, closed: true });
  const nc = await holdSets(a, [t], { dir: c.dir });
  await nc.release();
  assert.equal(existsSync(setLockPath(c.dir, "agent", a)), false);
  // An unreadable plan: refused, as held (fail closed).
  const u = host({ sets: { [keys.agent]: RUN } });
  writeFileSync(join(u.dir, "plan.json"), "{");
  assert.equal(await holdSets(a, [t], { dir: u.dir }), null);
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

test("dispatch writes its input durably BEFORE the start, with the argv's nonce; no trusted identity, no input and no worker", async () => {
  const a = newId(), key = `agent-${a}`;
  const h = host({ sets: { [key]: RUN }, noInput: [key] });
  let atStart = null;
  const nonces = [newId(), newId()];
  const deps = {
    gateOpen: async () => true, anyWorker: async () => false, admitted: async () => true, main: "/opt/m.mjs", node: "/n", newNonce: () => nonces.shift(),
    inputOf: async (k, i, r, n) => inputOf(k, i, r, n),
    start: async (argv) => { atStart = { argv, input: readInput("agent", a, { dir: h.dir, uid: UID }), mode: statSync(join(h.dir, INPUTS, `${key}.json`)).mode & 0o777 }; },
  };
  const first = nonces[0];
  assert.deepEqual(await dispatchOnce(deps, { dir: h.dir, uid: UID }), { dispatched: key });
  assert.equal(atStart.argv.at(-2), first, "the argv carries the nonce");
  assert.deepEqual([atStart.input.nonce, atStart.input.run, atStart.mode], [first, RUN, 0o600], "durable and private before the start");
  // The worker of that dispatch admits its input; after a second dispatch, the first nonce refuses and the second admits.
  const second = nonces[0];
  await dispatchOnce(deps, { dir: h.dir, uid: UID });
  assert.equal(atStart.argv.at(-2), second);
  await rejects(runWorker("agent", a, RUN, first, deps2(filler()), { dir: h.dir, uid: UID }), "not_granted");
  const f = filler(async () => ({ state: "files_validated" }));
  assert.equal((await runWorker("agent", a, RUN, second, deps2(f), { dir: h.dir, uid: UID })).status, "files_validated");
  // No trusted identity: no input written, nothing started, the set reported.
  const b = newId(), kb = `agent-${b}`;
  const hb = host({ sets: { [kb]: RUN }, noInput: [kb] });
  let started = 0;
  const out = await dispatchOnce({ ...deps, newNonce: () => newId(), inputOf: async () => null, start: async () => { started++; } }, { dir: hb.dir, uid: UID });
  assert.deepEqual([out, started, existsSync(join(hb.dir, INPUTS, `${kb}.json`))], [{ dispatched: null, why: "idle", no_identity: [kb] }, 0, false]);
  // An input for another set (or another nonce) is refused before anything is written or started.
  await rejects(dispatchOnce({ ...deps, newNonce: () => newId(), inputOf: async (k, i, r) => inputOf(k, i, r, newId()), start: async () => { started++; } }, { dir: hb.dir, uid: UID }), "bad_form");
  assert.deepEqual([started, existsSync(join(hb.dir, INPUTS, `${kb}.json`))], [0, false]);
});

test("a write that can't be made durable starts nothing; a settled set's input is removed by the dispatch, never by a worker", async () => {
  const a = newId(), key = `agent-${a}`;
  const h = host({ sets: { [key]: RUN }, noInput: [key] });
  // The inputs directory a link elsewhere: the write refuses, and no worker is started.
  const other = join(h.base, "other");
  mkdirSync(other, { mode: 0o700 });
  symlinkSync(other, join(h.dir, INPUTS));
  let started = 0;
  const deps = { gateOpen: async () => true, anyWorker: async () => false, admitted: async () => true, main: "/opt/m.mjs", newNonce: () => NONCE, inputOf: async (k, i, r, n) => inputOf(k, i, r, n), start: async () => { started++; } };
  await rejects(dispatchOnce(deps, { dir: h.dir, uid: UID }), "not_granted");
  assert.deepEqual([started, readdirSync(other)], [0, []]);
  // Settled (failed here): the next dispatch removes its input, and starts nothing for it.
  const s = newId(), ks = `agent-${s}`;
  const hs = host({ sets: { [ks]: RUN } });
  assert.ok(existsSync(join(hs.dir, INPUTS, `${ks}.json`)));
  writeRecord(step(bound("agent", s), "failed", { reason: "not_found" }), { dir: hs.dir });
  const out = await dispatchOnce({ ...deps, start: async () => { started++; } }, { dir: hs.dir, uid: UID });
  assert.deepEqual([out.dispatched, started, existsSync(join(hs.dir, INPUTS, `${ks}.json`))], [null, 0, false]);
  // A worker that ends (here: refused on an intent) leaves the input where it is.
  const v = newId(), kv = `agent-${v}`;
  const hv = host({ sets: { [kv]: RUN } });
  intent(hv.dir, kv);
  assert.equal((await runWorker("agent", v, RUN, NONCE, deps2(filler()), { dir: hv.dir, uid: UID })).status, "abandoning");
  assert.ok(existsSync(join(hv.dir, INPUTS, `${kv}.json`)), "the worker never removes an input");
});

test("the worker's trusted identities are its input's, of this epoch: another epoch or filesystem is refused at the bind", async () => {
  for (const change of [{ epoch: { ...EPOCH, mnt_id: 8 } }, { epoch: { ...EPOCH, boot_id: "11111111-1111-4111-8111-111111111111" } }, { fsid: "fedcba9876543210" }]) {
    const id = newId(), key = `archive-${id}`;
    const h = host({ sets: { [key]: RUN } });
    const got = [];
    const f = filler(async (hooks) => {
      const r = newRecord({ kind: "archive", id, run: RUN, snapshot: SNAP });
      await rejects(hooks.admit(r, { archive: { ...ID, ...change }, "archive-config": { ...ID } }, { archive: EXACT, "archive-config": EXACT }), "not_granted");
      await hooks.admit(r, { archive: { ...ID }, "archive-config": { ...ID } }, { archive: EXACT, "archive-config": EXACT }); // the same identity in this epoch admits
      got.push("admitted");
      return { state: "validated" };
    });
    await runWorker("archive", id, RUN, NONCE, deps(f), { dir: h.dir, uid: UID });
    assert.deepEqual(got, ["admitted"], JSON.stringify(change));
  }
});

test("an input of another run is refused even with the right nonce", async () => {
  const id = newId(), key = `archive-${id}`;
  const h = host({ sets: { [key]: RUN }, noInput: [key] });
  writeInput(inputOf("archive", id, RUN2, NONCE), { dir: h.dir, uid: UID });
  const f = filler();
  await rejects(runWorker("archive", id, RUN, NONCE, deps(f), { dir: h.dir, uid: UID }), "not_granted");
  assert.deepEqual([f.calls, readRecord("archive", id, { dir: h.dir })], [[], null]);
});

test("dispatch requires the host-wide worker check: without it, refused before anything", async () => {
  const id = newId(), key = `agent-${id}`;
  const h = host({ sets: { [key]: RUN } });
  let started = 0;
  await rejects(dispatchOnce({ gateOpen: async () => true, admitted: async () => true, inputOf: async () => { throw new Error("never"); }, start: async () => { started++; }, main: "/m" }, { dir: h.dir, uid: UID }), "bad_form");
  assert.equal(started, 0);
});
