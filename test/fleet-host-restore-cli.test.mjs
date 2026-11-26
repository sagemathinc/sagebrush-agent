// Host restore e2e r1.7, delta R6-d1 (R6a): the root console's restore commands over real temporary restore
// directories: status's document, retry's refusals and its crash continuation, close, and the command line's codes.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "./host-linux-only.mjs";
import { FleetError, newId } from "../lib/fleet/index.mjs";
import { lockFile } from "../lib/fleet/host/store.mjs";
import { CLASSES, newRecord, newRestoreRun, readRecord, runTime, step, writeRecord } from "../lib/fleet/host/restore-record.mjs";
import { createPlan, readPlan, replanSet, updatePlan } from "../lib/fleet/host/restore-plan.mjs";
import { ABANDON, BEGIN, REQUESTS, requestText, writeRequest } from "../lib/fleet/host/restore-begin.mjs";
import { setLockPath } from "../lib/fleet/host/restore-worker.mjs";
import { attestationName, attestationText, intentName } from "../lib/fleet/host/restore-sidecars.mjs";
import { restoreCommand, restoreRetry, restoreStatus } from "../lib/fleet/host/restore-cli.mjs";

const UID = typeof process.getuid === "function" ? process.getuid() : -1; // (Linux-only rows; off Linux the file only loads)
const hex = (c) => c.repeat(64);
const T0 = 1795500000000;
const RUN = newRestoreRun(T0, () => Buffer.alloc(6));
const SNAP = hex("a");
const rejects = (p, code) => assert.rejects(p, (e) => e instanceof FleetError && e.code === code, code);
const private_ = (p) => { mkdirSync(p, { recursive: true, mode: 0o700 }); chmodSync(p, 0o700); return p; };
const ident = (ino) => ({ dev: "2049", ino, uid: 70000, gid: 70000, mode: 0o700, projid: 70000 });

function reach(kind, id, target, run = RUN) {
  let r = newRecord({ kind, id, run, snapshot: SNAP });
  if (target === "staging") return r;
  const dest = Object.fromEntries(CLASSES[kind].map((c, i) => [c, ident(String(130 + i))]));
  r = step(r, "bind", { dest });
  for (const c of CLASSES[kind]) r = step(r, "digest", { cls: c, sha256: hex("d") });
  r = step(step(r, "staged"), "filling", { dest });
  if (target === "not_fitting") return step(r, "not_fitting");
  if (target === "failed") return step(r, "failed", { reason: "outcome_unknown" });
  r = step(step(r, "published"), "files_validated");
  if (r.imports !== null) for (const which of ["config", "context"]) for (const phase of ["pending", "done"]) r = step(r, "import", { which, phase, sha256: hex("c") });
  return step(r, "validated");
}

/** A begun, open restore with sets agent-A, archive-D, tag-T, their requests, a fence directory and the exclusion. */
function world({ state = "done" } = {}) {
  const base = private_(mkdtempSync(join(tmpdir(), "sb-rcli-")));
  const dir = private_(join(base, "restore")), fenceDir = private_(join(base, "fence"));
  const exclusion = { path: join(private_(join(base, "lib")), "backup-restore.lock"), waitMs: 0, uid: UID };
  const a = newId(), d = newId(), t = newId();
  writeFileSync(join(dir, BEGIN), JSON.stringify({ v: 1, snapshot: hex("1"), manifest_sha256: hex("2"), run: RUN, state }) + "\n", { mode: 0o600 });
  const keys = [`agent-${a}`, `archive-${d}`, `tag-${t}`];
  createPlan({ v: 1, host: "old", manifest: hex("1"), sha256: hex("2"), hoststore: hex("3"),
    sets: Object.fromEntries(keys.map((k) => [k, { run: RUN, snapshot: SNAP, tree: hex("4") }])), config: { [a]: hex("5") } }, { dir });
  for (const k of keys) writeRequest(k, RUN, { dir, uid: UID });
  return { base, dir, fenceDir, exclusion, a, d, t };
}
const opts = (w, over = {}) => ({ dir: w.dir, uid: UID, exclusion: w.exclusion, now: () => T0 + 3600000, ...over });
function writeIntent(w, kind, id, over = {}) {
  private_(join(w.dir, ABANDON));
  writeFileSync(join(w.dir, ABANDON, intentName(kind, id)), JSON.stringify({ v: 1, kind, id, restore_run: RUN, set_run: RUN, set_snapshot: SNAP, account: newId(), person: newId(),
    by: "device-1", at: 1, reason: "", envelope_sha256: hex("e"), nonce: Buffer.alloc(16, 7).toString("base64url"), ...over }) + "\n", { mode: 0o600 });
}
/** Everything retry could change: the plan, the request, the record. */
const snapshotOf = (w, key) => {
  const [kind, id] = [key.slice(0, key.indexOf("-")), key.slice(key.indexOf("-") + 1)];
  let req = null;
  try { req = readFileSync(join(w.dir, REQUESTS, key), "utf8"); } catch { /* none */ }
  return JSON.stringify([readPlan({ dir: w.dir }), req, readRecord(kind, id, { dir: w.dir })]);
};

test("status: none; then every set's plan run, state, request, abandon state and resume, in key order", async () => {
  const empty = private_(join(private_(mkdtempSync(join(tmpdir(), "sb-rcli-"))), "restore"));
  assert.deepEqual(restoreStatus({ dir: empty, uid: UID }), { v: 1, restore: "none", sets: [] });
  const w = world();
  writeRecord(reach("agent", w.a, "validated"), { dir: w.dir });
  writeRecord(reach("tag", w.t, "failed"), { dir: w.dir });
  private_(join(w.fenceDir, "restore"));
  writeFileSync(join(w.fenceDir, "restore", w.a), "");
  let s = restoreStatus({ dir: w.dir, uid: UID, fenceDir: w.fenceDir });
  assert.deepEqual(s.restore, { run: RUN, snapshot: hex("1"), manifest_sha256: hex("2"), state: "done", open: true, closed_at: null });
  assert.deepEqual(s.sets.map((x) => x.key), [`agent-${w.a}`, `archive-${w.d}`, `tag-${w.t}`]);
  const [ag, ar, tg] = s.sets;
  assert.deepEqual([ag.state, ag.imports, ag.request, ag.abandon, ag.resumed], ["validated", { config: "done", context: "done" }, "current", null, false]);
  assert.deepEqual([ar.state, ar.attempt, ar.dirty, ar.reason, ar.imports, ar.resumed], ["none", null, null, null, null, null]);
  assert.deepEqual([tg.state, tg.reason, tg.attempt], ["failed", "outcome_unknown", 1]);
  // The agent resumed (its restore fence gone); a stale request; a missing one.
  rmSync(join(w.fenceDir, "restore", w.a));
  writeFileSync(join(w.dir, REQUESTS, `tag-${w.t}`), requestText(newRestoreRun(T0 + 1, () => Buffer.alloc(6, 2))));
  rmSync(join(w.dir, REQUESTS, `archive-${w.d}`));
  s = restoreStatus({ dir: w.dir, uid: UID, fenceDir: w.fenceDir });
  assert.deepEqual(s.sets.map((x) => [x.request, x.resumed]), [["current", true], ["missing", null], ["stale", null]]);
  // Abandon states: abandoning (a bound intent), stale (an intent of another set run), abandoned (its pair complete),
  // corrupt (the attestation missing).
  writeIntent(w, "tag", w.t);
  assert.equal(restoreStatus({ dir: w.dir, uid: UID, fenceDir: w.fenceDir }).sets[2].abandon, "abandoning");
  writeIntent(w, "tag", w.t, { set_run: newRestoreRun(T0 + 5, () => Buffer.alloc(6, 3)) });
  assert.equal(restoreStatus({ dir: w.dir, uid: UID, fenceDir: w.fenceDir }).sets[2].abandon, "stale");
  writeIntent(w, "tag", w.t);
  const ab = step(reach("tag", w.t, "failed"), "abandoned");
  writeRecord(ab, { dir: w.dir });
  writeFileSync(join(w.dir, ABANDON, attestationName("tag", w.t)), attestationText(ab, 2), { mode: 0o600 });
  assert.equal(restoreStatus({ dir: w.dir, uid: UID, fenceDir: w.fenceDir }).sets[2].abandon, "abandoned");
  rmSync(join(w.dir, ABANDON, attestationName("tag", w.t)));
  assert.equal(restoreStatus({ dir: w.dir, uid: UID, fenceDir: w.fenceDir }).sets[2].abandon, "corrupt");
});

test("retry: a stopped set gets a newer run, the plan re-planned, then its request replaced; the record untouched", async () => {
  for (const target of ["failed", "not_fitting"]) {
    const w = world();
    const r0 = reach("archive", w.d, target);
    writeRecord(r0, { dir: w.dir });
    const out = await restoreRetry(`archive-${w.d}`, opts(w));
    assert.equal(out.key, `archive-${w.d}`);
    assert.ok(runTime(out.run) > runTime(RUN), "a newer run");
    assert.equal(readPlan({ dir: w.dir }).sets[`archive-${w.d}`].run, out.run);
    assert.equal(readFileSync(join(w.dir, REQUESTS, `archive-${w.d}`), "utf8"), requestText(out.run));
    assert.deepEqual(readRecord("archive", w.d, { dir: w.dir }), r0, "the record itself is never edited");
    assert.equal(readPlan({ dir: w.dir }).sets[`agent-${w.a}`].run, RUN, "no other set re-planned");
  }
  // A crash between the re-plan and the request: the plan is newer than the stopped record; retry rewrites the request
  // for the plan's run, with no second re-plan.
  const c = world();
  writeRecord(reach("archive", c.d, "failed"), { dir: c.dir });
  const RUN2 = newRestoreRun(T0 + 1800000, () => Buffer.alloc(6, 4));
  updatePlan(replanSet(readPlan({ dir: c.dir }), "archive", c.d, RUN2), { dir: c.dir });
  const out = await restoreRetry(`archive-${c.d}`, opts(c));
  assert.deepEqual(out, { key: `archive-${c.d}`, run: RUN2 });
  assert.equal(readFileSync(join(c.dir, REQUESTS, `archive-${c.d}`), "utf8"), requestText(RUN2));
  assert.equal(readPlan({ dir: c.dir }).sets[`archive-${c.d}`].run, RUN2);
});

test("retry's refusals, each with no effect: no begun restore, closed, not in the plan, an intent, no record, any other state, a held set", async () => {
  const cases = [
    ["begin not done", (w) => writeFileSync(join(w.dir, BEGIN), JSON.stringify({ v: 1, snapshot: hex("1"), manifest_sha256: hex("2"), run: RUN, state: "begun" }) + "\n"), "not_found"],
    ["closed", (w) => { const p = readPlan({ dir: w.dir }); writeFileSync(join(w.dir, "plan.json"), JSON.stringify({ ...p, closed: { at: 1 } }) + "\n", { mode: 0o600 }); }, "not_granted"],
    ["an abandon intent", (w) => writeIntent(w, "archive", w.d), "not_granted"],
    ["no record", (w) => rmSync(join(w.dir, `archive-${w.d}.json`)), "not_found"],
    ["validated", (w) => writeRecord(reach("archive", w.d, "validated"), { dir: w.dir }), "not_granted"],
    ["abandoned", (w) => writeRecord(step(reach("archive", w.d, "failed"), "abandoned"), { dir: w.dir }), "not_granted"],
    ["staging", (w) => writeRecord(reach("archive", w.d, "staging"), { dir: w.dir }), "in_progress"],
  ];
  for (const [what, plant, code] of cases) {
    const w = world();
    writeRecord(reach("archive", w.d, "failed"), { dir: w.dir });
    plant(w);
    const before = snapshotOf(w, `archive-${w.d}`);
    await rejects(restoreRetry(`archive-${w.d}`, opts(w)), code);
    assert.equal(snapshotOf(w, `archive-${w.d}`), before, `${what}: nothing changed`);
  }
  // Not a set of the plan; a bad key.
  const n = world();
  await rejects(restoreRetry(`archive-${newId()}`, opts(n)), "not_found");
  await rejects(restoreRetry("nope", opts(n)), "bad_form");
  // A worker holding the set: busy, nothing changed.
  const h = world();
  writeRecord(reach("archive", h.d, "failed"), { dir: h.dir });
  const held = await lockFile(setLockPath(h.dir, "archive", h.d), { waitMs: 0 });
  try {
    const before = snapshotOf(h, `archive-${h.d}`);
    await rejects(restoreRetry(`archive-${h.d}`, opts(h)), "in_progress");
    assert.equal(snapshotOf(h, `archive-${h.d}`), before);
  } finally { await held.release(); }
  // The exclusion held (a backup or close): busy.
  const { withExclusion } = await import("../lib/fleet/host/restore-begin.mjs");
  const x = world();
  writeRecord(reach("archive", x.d, "failed"), { dir: x.dir });
  await withExclusion(async () => { await rejects(restoreRetry(`archive-${x.d}`, opts(x)), "in_progress"); }, x.exclusion);
});

test("the command line: argument errors are 2; not root is refused; each command's one line carries only codes", async () => {
  const w = world();
  writeRecord(reach("archive", w.d, "failed"), { dir: w.dir });
  const deps = { dir: w.dir, fenceDir: w.fenceDir, exclusion: w.exclusion, uid: () => UID, rootUid: UID, now: () => T0 + 3600000 };
  for (const argv of [[], ["status", "x"], ["retry"], ["retry", "a", "b"], ["close", "now"], ["begin", hex("1")], ["list"], ["nope"]]) {
    const out = await restoreCommand(argv, deps);
    assert.equal(out.code, 2, JSON.stringify(argv));
    assert.match(out.usage, /^usage: sagebrush-agent host restore status \| retry <kind>-<id> \| close$/);
  }
  assert.deepEqual(await restoreCommand(["status"], { ...deps, uid: () => UID + 1 }), { code: 1, line: { v: 1, refused: "not_granted" } }, "not root");
  const st = await restoreCommand(["status"], deps);
  assert.equal(st.code, 0);
  assert.equal(st.line.sets.length, 3);
  const rt = await restoreCommand(["retry", `archive-${w.d}`], deps);
  assert.equal(rt.code, 0);
  assert.equal(rt.line.retried, `archive-${w.d}`);
  // A refusal: only its code (no message, path or value).
  const again = await restoreCommand(["retry", `agent-${w.a}`], deps);
  assert.deepEqual(again, { code: 1, line: { v: 1, refused: "not_found" } });
  // close: refused while a set isn't terminal; then closes.
  assert.deepEqual(await restoreCommand(["close"], deps), { code: 1, line: { v: 1, refused: "not_granted" } });
  for (const [kind, id] of [["agent", w.a], ["archive", w.d], ["tag", w.t]]) writeRecord(reach(kind, id, "validated"), { dir: w.dir });
  const closed = await restoreCommand(["close"], { ...deps, restoreRaised: () => false });
  assert.deepEqual(closed, { code: 0, line: { v: 1, closed: T0 + 3600000 } });
  const after = restoreStatus({ dir: w.dir, uid: UID, fenceDir: w.fenceDir });
  assert.deepEqual([after.restore.open, after.restore.closed_at], [false, T0 + 3600000]);
});

test("the entrypoint: `sagebrush-agent host restore` dispatches through host-main (usage 2; a non-root caller refused)", { skip: UID === 0 }, () => {
  const bin = fileURLToPath(new URL("../bin/sagebrush-agent.mjs", import.meta.url));
  const usage = spawnSync(process.execPath, [bin, "host", "restore"], { encoding: "utf8" });
  assert.equal(usage.status, 2);
  assert.match(usage.stderr, /usage: sagebrush-agent host restore/);
  const st = spawnSync(process.execPath, [bin, "host", "restore", "status"], { encoding: "utf8" });
  assert.deepEqual([st.status, st.stdout], [1, '{"v":1,"refused":"not_granted"}\n']);
});
