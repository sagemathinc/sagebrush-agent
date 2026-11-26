// Host restore e2e r1.7 §5, delta R5-d2 §3.2–§3.8 (R5a): an accepted abandon's finish, against the real record, plan,
// begin, set locks, exclusion and restore lock on real temporary directories, with the launcher's removals modelled
// (a destination is a set of entries, staging a set of attempts). A lock-order checker fails any §1 inversion.
import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "./host-linux-only.mjs";
import { FleetError, newId } from "../lib/fleet/index.mjs";
import { lockFile } from "../lib/fleet/host/store.mjs";
import { ABANDON_DIR, CLASSES, newRecord, newRestoreRun, readRecord, restoreReady, step, writeRecord } from "../lib/fleet/host/restore-record.mjs";
import { createPlan, readPlan, replanSet, updatePlan, withRestoreLock } from "../lib/fleet/host/restore-plan.mjs";
import { ABANDON, BEGIN, withExclusion } from "../lib/fleet/host/restore-begin.mjs";
import { setLockPath } from "../lib/fleet/host/restore-worker.mjs";
import { attestationName, auditPair, canonicalNonce, checkIntent, intentName } from "../lib/fleet/host/restore-sidecars.mjs";
import { boundIntent, finishAbandon, finishOnce } from "../lib/fleet/host/restore-abandon.mjs";

const UID = typeof process.getuid === "function" ? process.getuid() : -1; // (Linux-only rows; off Linux the file only loads)
const hex = (c) => c.repeat(64);
const RUN = newRestoreRun(1795500000000, () => Buffer.alloc(6)), RUN2 = newRestoreRun(1795600000000, () => Buffer.alloc(6, 1));
const SNAP = hex("a");
const rejects = (p, code) => assert.rejects(p, (e) => e instanceof FleetError && e.code === code, code);
const refused = (fn, code) => assert.throws(fn, (e) => e instanceof FleetError && e.code === code, code);
const private_ = (p) => { mkdirSync(p, { recursive: true, mode: 0o700 }); chmodSync(p, 0o700); return p; };
const ident = (ino) => ({ dev: "2049", ino, uid: 70000, gid: 70000, mode: 0o700, projid: 70000 });

/** A record of `kind` reaching `target` (none: no record; staging, filling, published, files_validated, validated, failed). */
function reach(kind, id, target, run = RUN) {
  let r = newRecord({ kind, id, run, snapshot: SNAP });
  if (target === "staging") return r;
  const dest = Object.fromEntries(CLASSES[kind].map((c, i) => [c, ident(String(130 + i))]));
  r = step(r, "bind", { dest });
  for (const c of CLASSES[kind]) r = step(r, "digest", { cls: c, sha256: hex("d") });
  r = step(r, "staged");
  r = step(r, "filling", { dest });
  if (target === "filling") return r;
  if (target === "failed") return step(r, "failed", { reason: "outcome_unknown" });
  r = step(r, "published");
  if (target === "published") return r;
  r = step(r, "files_validated");
  if (target === "files_validated") return r;
  if (r.imports !== null) for (const which of ["config", "context"]) for (const phase of ["pending", "done"]) r = step(r, "import", { which, phase, sha256: hex("c") });
  return step(r, "validated");
}

/** An open restore on real directories with sets agent-A, archive-D and tag-T, and the exclusion's lock. */
function world() {
  const base = private_(mkdtempSync(join(tmpdir(), "sb-abandon-")));
  const dir = private_(join(base, "restore"));
  const exclusion = { path: join(private_(join(base, "lib")), "backup-restore.lock"), waitMs: 0, uid: UID };
  const a = newId(), d = newId(), t = newId();
  writeFileSync(join(dir, BEGIN), JSON.stringify({ v: 1, snapshot: hex("1"), manifest_sha256: hex("2"), run: RUN, state: "done" }) + "\n", { mode: 0o600 });
  const sets = { [`agent-${a}`]: { run: RUN, snapshot: SNAP, tree: hex("4") }, [`archive-${d}`]: { run: RUN, snapshot: SNAP, tree: hex("4") }, [`tag-${t}`]: { run: RUN, snapshot: SNAP, tree: hex("4") } };
  createPlan({ v: 1, host: "old", manifest: hex("1"), sha256: hex("2"), hoststore: hex("3"), sets, config: { [a]: hex("5") } }, { dir });
  return { base, dir, exclusion, a, d, t };
}
/** The accepted intent of a set, as the abandon op writes it (R5-d2 §3.1). */
function intentOf(kind, id, over = {}) {
  return { v: 1, kind, id, restore_run: RUN, set_run: RUN, set_snapshot: SNAP, account: newId(), person: newId(), by: "device-1", at: 1795500000000,
    reason: "the backup's copy is enough", envelope_sha256: hex("e"), nonce: Buffer.alloc(16, 7).toString("base64url"), ...over };
}
function writeIntent(w, kind, id, over = {}, { raw } = {}) {
  private_(join(w.dir, ABANDON));
  writeFileSync(join(w.dir, ABANDON, intentName(kind, id)), raw ?? JSON.stringify(intentOf(kind, id, over)) + "\n", { mode: 0o600 });
}

/**
 * The finish's deps over a model of the launcher's removals, with real locks and a lock-order checker: the exclusion
 * may never be taken while a set lock is held. `on[name]` hooks run at each effect (a barrier, a crash, a plant).
 */
function model(w, r0, { on = {} } = {}) {
  const m = { calls: [], dests: {}, staging: new Set(["1"]), copies: true, setHeld: 0, inversions: 0 };
  if (r0?.dest) for (const c of Object.keys(r0.dest)) m.dests[c] = new Set(["restored"]);
  const hook = async (name, ...a) => { m.calls.push(name); if (on[name]) await on[name](...a); };
  m.deps = {
    stop: async () => { await hook("stop"); return true; },
    lockSet: async (k, i) => {
      const held = await lockFile(setLockPath(w.dir, k, i), { waitMs: 0 });
      m.setHeld++;
      return { release: async () => { m.setHeld--; await held.release(); } };
    },
    withLocks: (fn) => {
      if (m.setHeld > 0) { m.inversions++; throw new Error("lock order inverted: the exclusion while a set lock is held"); }
      return withExclusion(() => withRestoreLock(fn, { dir: w.dir }), w.exclusion);
    },
    cleanDest: async (r) => { await hook("clean", r); for (const c of Object.keys(r.dest)) (m.dests[c] ??= new Set()).clear(); },
    isEmpty: async (r, cls) => (m.dests[cls]?.size ?? 0) === 0,
    discardAll: async (r) => { await hook("discard", r); m.staging.clear(); },
    stagingGone: async () => m.staging.size === 0,
    removeCopies: async (r) => { await hook("copies", r); m.copies = false; },
    now: () => 1795500002000,
  };
  return m;
}
const opts = (w) => ({ dir: w.dir, uid: UID });

test("the finish: the kill, then under the set lock the final record's destinations emptied, all staging and the copies removed, the attestation; then the re-proof under the three locks and abandoned", async () => {
  for (const [kind, target] of [["archive", "failed"], ["archive", "published"], ["archive", "files_validated"], ["tag", "filling"], ["agent", "files_validated"], ["agent", "staging"]]) {
    const w = world();
    const id = kind === "agent" ? w.a : kind === "archive" ? w.d : w.t;
    const r0 = reach(kind, id, target);
    writeRecord(r0, { dir: w.dir });
    writeIntent(w, kind, id);
    const m = model(w, r0);
    assert.deepEqual(await finishAbandon(kind, id, m.deps, opts(w)), { status: "abandoned" }, `${kind} ${target}`);
    const r = readRecord(kind, id, { dir: w.dir });
    assert.deepEqual([r.state, r.dirty, r.run, r.attempt], ["abandoned", false, RUN, r0.attempt]);
    assert.deepEqual(m.calls, r0.dest ? ["stop", "clean", "discard", "copies"] : ["stop", "discard", "copies"], `${kind} ${target}: the order`);
    assert.ok(Object.values(m.dests).every((s) => s.size === 0), "every bound destination emptied, whatever the state");
    assert.equal(m.staging.size, 0, "all staging discarded");
    assert.equal(m.inversions, 0);
    // The audit pair reads back complete, and the finish again is a no-op.
    auditPair(r, join(w.dir, ABANDON));
    assert.deepEqual(await finishAbandon(kind, id, model(w, r).deps, opts(w)), { status: "abandoned" });
  }
  // A set that never started (no record): a record at the intent's binding, then abandoned.
  const w = world();
  writeIntent(w, "tag", w.t);
  assert.deepEqual(await finishAbandon("tag", w.t, model(w, null).deps, opts(w)), { status: "abandoned" });
  assert.deepEqual([readRecord("tag", w.t, { dir: w.dir }).state, readRecord("tag", w.t, { dir: w.dir }).dest], ["abandoned", null]);
  // Never another set, never a fence: the other records are untouched.
  assert.equal(readRecord("agent", w.a, { dir: w.dir }), null);
});

test("T1: a set validated after its intent was accepted is finished to abandoned by the finish's own transition; generic abandon of validated stays refused", async () => {
  // The archive's fill read veto false, the intent was accepted at files_validated, then its validated save landed
  // before the kill: the final re-read sees validated.
  for (const kind of ["archive", "tag", "agent"]) {
    const w = world();
    const id = kind === "agent" ? w.a : kind === "archive" ? w.d : w.t;
    const fv = reach(kind, id, "files_validated");
    writeRecord(fv, { dir: w.dir });
    writeIntent(w, kind, id);
    const late = kind === "agent" ? reach(kind, id, "validated") : step(fv, "validated");
    const m = model(w, fv, { on: { stop: () => writeRecord(late, { dir: w.dir }) } });
    // In the window: resume refuses (abandoning), close's blockers name it.
    assert.equal(restoreReady(kind === "agent" ? id : w.a, kind === "tag" ? [id] : [], { [`agent-${w.a}`]: { run: RUN, snapshot: SNAP }, [`tag-${w.t}`]: { run: RUN, snapshot: SNAP } }, { dir: w.dir }) === "abandoning" || kind === "archive", true);
    assert.deepEqual(await finishAbandon(kind, id, m.deps, opts(w)), { status: "abandoned" }, kind);
    assert.equal(readRecord(kind, id, { dir: w.dir }).state, "abandoned");
    assert.ok(Object.values(m.dests).every((s) => s.size === 0), `${kind}: the validated contents emptied too`);
  }
  // The transition: refused from validated without accepted_intent, allowed with it; a boolean only.
  const v = reach("archive", newId(), "validated");
  refused(() => step(v, "abandoned"), "not_granted");
  assert.equal(step(v, "abandoned", { accepted_intent: true }).state, "abandoned");
  refused(() => step(v, "abandoned", { accepted_intent: "yes" }), "bad_form");
  refused(() => step(step(v, "abandoned", { accepted_intent: true }), "abandoned", { accepted_intent: true }), "not_granted");
});

test("T2: a stale, malformed or wrong-set intent refuses before the kill, with no cleanup", async () => {
  const cases = [
    ["another restore", (w) => writeIntent(w, "archive", w.d, { restore_run: RUN2 })],
    ["another set run", (w) => writeIntent(w, "archive", w.d, { set_run: RUN2 })],
    ["another set snapshot", (w) => writeIntent(w, "archive", w.d, { set_snapshot: hex("b") })],
    ["another set's intent at this path", (w) => writeIntent(w, "archive", w.d, { kind: "tag", id: w.t })],
    ["another id, the same runs", (w) => writeIntent(w, "archive", w.d, { id: newId() })],
    ["malformed", (w) => writeIntent(w, "archive", w.d, {}, { raw: "{}\n" })],
    ["non-canonical", (w) => writeIntent(w, "archive", w.d, {}, { raw: JSON.stringify(intentOf("archive", w.d), null, 1) + "\n" })],
    ["a record of another run", (w) => { writeIntent(w, "archive", w.d); writeRecord(reach("archive", w.d, "failed", RUN2), { dir: w.dir }); }],
  ];
  for (const [what, plant] of cases) {
    const w = world();
    writeRecord(reach("archive", w.d, "failed"), { dir: w.dir });
    plant(w);
    const m = model(w, reach("archive", w.d, "failed"));
    await assert.rejects(finishAbandon("archive", w.d, m.deps, opts(w)), (e) => e instanceof FleetError && ["not_granted", "bad_form"].includes(e.code), what);
    assert.deepEqual(m.calls, [], `${what}: no kill, no cleanup`);
    assert.ok(Object.values(m.dests).every((s) => s.size === 1));
  }
  // A closed restore, a set not in the plan, no intent.
  const c = world();
  writeIntent(c, "archive", c.d);
  const p = readPlan({ dir: c.dir });
  writeFileSync(join(c.dir, "plan.json"), JSON.stringify({ ...p, closed: { at: 1 } }) + "\n", { mode: 0o600 });
  await rejects(finishAbandon("archive", c.d, model(c, null).deps, opts(c)), "not_granted");
  const n = world();
  const stray = newId();
  writeIntent(n, "archive", stray);
  await rejects(finishAbandon("archive", stray, model(n, null).deps, opts(n)), "not_granted");
  await rejects(finishAbandon("archive", n.d, model(n, null).deps, opts(n)), "not_found");
});

test("T2: a binding changed AFTER the pre-kill check stops before the cleanup; one changed after the cleanup stops the terminal write", async () => {
  // (the barrier: the plan's set run moves inside the kill, after the first check, so only the set-lock check sees it)
  const replan = (w) => {
    const p = readPlan({ dir: w.dir });
    writeFileSync(join(w.dir, "plan.json"), JSON.stringify({ ...p, sets: { ...p.sets, [`archive-${w.d}`]: { ...p.sets[`archive-${w.d}`], run: RUN2 } } }) + "\n", { mode: 0o600 });
  };
  const w = world();
  const r0 = reach("archive", w.d, "failed");
  writeRecord(r0, { dir: w.dir });
  writeIntent(w, "archive", w.d);
  const m = model(w, r0, { on: { stop: () => replan(w) } });
  await rejects(finishAbandon("archive", w.d, m.deps, opts(w)), "not_granted");
  assert.deepEqual(m.calls, ["stop"], "nothing removed after the binding moved");
  assert.ok(Object.values(m.dests).every((s) => s.size === 1));
  // After the cleanup: the record moves to another set run (planted) once the copies are removed: the final check refuses.
  const v = world();
  const r1 = reach("archive", v.d, "failed");
  writeRecord(r1, { dir: v.dir });
  writeIntent(v, "archive", v.d);
  const n = model(v, r1, { on: { copies: () => replan(v) } });
  await rejects(finishAbandon("archive", v.d, n.deps, opts(v)), "not_granted");
  assert.equal(readRecord("archive", v.d, { dir: v.dir }).state, "failed", "no terminal write");
  assert.ok(existsSync(join(v.dir, ABANDON, attestationName("archive", v.d))), "(the cleanup was attested before the move)");
});

test("the re-proof: a planted entry, leftover staging or a mismatched attestation writes nothing; the next finish cleans again and commits", async () => {
  for (const what of ["entry", "staging", "attestation"]) {
    const w = world();
    const r0 = reach("archive", w.d, "failed");
    writeRecord(r0, { dir: w.dir });
    writeIntent(w, "archive", w.d);
    const aPath = join(w.dir, ABANDON, attestationName("archive", w.d));
    const m = model(w, r0, { on: { copies: () => {} } });
    const plant = {
      entry: () => m.dests.archive.add("planted"),
      staging: () => m.staging.add("2"),
      attestation: () => {}, // (planted after the attestation is written: see below)
    }[what];
    // Plant between the cleanup and the re-proof: wrap withLocks.
    const withLocks = m.deps.withLocks;
    m.deps.withLocks = (fn) => {
      plant();
      if (what === "attestation") writeFileSync(aPath, readFileSync(aPath, "utf8").replace('"attempt":1', '"attempt":2'));
      return withLocks(fn);
    };
    assert.deepEqual(await finishAbandon("archive", w.d, m.deps, opts(w)), { status: "reproof_failed" }, what);
    assert.equal(readRecord("archive", w.d, { dir: w.dir }).state, "failed", `${what}: nothing written`);
    m.deps.withLocks = withLocks;
    assert.deepEqual(await finishAbandon("archive", w.d, m.deps, opts(w)), { status: "abandoned" }, `${what}: the next finish`);
  }
});

test("a crash at each durable boundary: the next tick finishes to abandoned; close refuses meanwhile", async () => {
  for (const at of ["stop", "clean", "discard", "copies"]) {
    const w = world();
    const r0 = reach("archive", w.d, "published");
    writeRecord(r0, { dir: w.dir });
    writeIntent(w, "archive", w.d);
    const m = model(w, r0, { on: { [at]: () => { throw Object.assign(new Error("crash"), { crash: true }); } } });
    await assert.rejects(finishAbandon("archive", w.d, m.deps, opts(w)), (e) => e.crash === true, at);
    assert.notEqual(readRecord("archive", w.d, { dir: w.dir }).state, "abandoned");
    // The next tick (the host op): finished, with the same model of the disk.
    const again = model(w, r0);
    again.dests = m.dests; again.staging = m.staging;
    const out = await finishOnce(() => again.deps, opts(w));
    assert.deepEqual(out.sets[`archive-${w.d}`], { status: "abandoned" }, at);
  }
});

test("lock order: the finish and a holder of the exclusion, in both orders: busy, never an inversion or a hang", async () => {
  const w = world();
  const r0 = reach("archive", w.d, "failed");
  writeRecord(r0, { dir: w.dir });
  writeIntent(w, "archive", w.d);
  // The exclusion held (as close or a backup holds it): the finish's final step is busy, nothing written.
  const m = model(w, r0);
  await withExclusion(async () => {
    assert.deepEqual(await finishAbandon("archive", w.d, m.deps, opts(w)), { status: "busy" });
  }, w.exclusion);
  assert.equal(readRecord("archive", w.d, { dir: w.dir }).state, "failed");
  // The set lock held (a worker or a lifecycle op): busy before any removal.
  const n = model(w, r0);
  const held = await lockFile(setLockPath(w.dir, "archive", w.d), { waitMs: 0 });
  try { assert.deepEqual(await finishAbandon("archive", w.d, n.deps, opts(w)), { status: "busy" }); } finally { await held.release(); }
  assert.deepEqual(n.calls, ["stop"]);
  assert.equal(m.inversions + n.inversions, 0);
  // Then it finishes.
  assert.deepEqual(await finishAbandon("archive", w.d, model(w, r0).deps, opts(w)), { status: "abandoned" });
  // An unproven kill: nothing more.
  const u = world();
  writeRecord(reach("archive", u.d, "failed"), { dir: u.dir });
  writeIntent(u, "archive", u.d);
  const um = model(u, reach("archive", u.d, "failed"));
  um.deps.stop = async () => false;
  assert.deepEqual(await finishAbandon("archive", u.d, um.deps, opts(u)), { status: "unproven" });
  assert.equal(readRecord("archive", u.d, { dir: u.dir }).state, "failed");
});

test("the host op: every intent of the open plan in key order; abandoned and intent-less sets skipped; one malformed intent never stops another", async () => {
  const w = world();
  for (const [kind, id] of [["archive", w.d], ["tag", w.t]]) writeRecord(reach(kind, id, "failed"), { dir: w.dir });
  writeIntent(w, "archive", w.d, {}, { raw: "not json\n" });
  writeIntent(w, "tag", w.t);
  const seen = [];
  const out = await finishOnce((kind, id) => { seen.push(`${kind}-${id}`); return model(w, reach(kind, id, "failed")).deps; }, opts(w));
  assert.deepEqual(out.sets[`archive-${w.d}`], { status: "refused", reason: "bad_form" });
  assert.deepEqual(out.sets[`tag-${w.t}`], { status: "abandoned" });
  assert.ok(!Object.hasOwn(out.sets, `agent-${w.a}`), "no intent: not looked at");
  // Again: the abandoned tag is skipped; the malformed one is still reported.
  const again = await finishOnce(() => model(w, null).deps, opts(w));
  assert.deepEqual(Object.keys(again.sets), [`archive-${w.d}`]);
  // Idle: no abandon directory, a closed or unbegun restore.
  const e = world();
  assert.deepEqual(await finishOnce(() => assert.fail("no deps"), opts(e)), { sets: {} });
  writeFileSync(join(e.dir, BEGIN), JSON.stringify({ v: 1, snapshot: hex("1"), manifest_sha256: hex("2"), run: RUN, state: "begun" }) + "\n", { mode: 0o600 });
  writeIntent(e, "tag", e.t);
  assert.deepEqual(await finishOnce(() => assert.fail("no deps"), opts(e)), { sets: {} });
});

test("the gates: restoreReady is abandoning for a required set with an intent; a re-plan of such a set refuses", async () => {
  const w = world();
  for (const [kind, id] of [["agent", w.a], ["tag", w.t]]) writeRecord(reach(kind, id, "validated"), { dir: w.dir });
  const expected = { [`agent-${w.a}`]: { run: RUN, snapshot: SNAP }, [`tag-${w.t}`]: { run: RUN, snapshot: SNAP } };
  assert.equal(restoreReady(w.a, [w.t], expected, { dir: w.dir }), "validated");
  writeIntent(w, "tag", w.t);
  assert.equal(restoreReady(w.a, [w.t], expected, { dir: w.dir }), "abandoning", "a tag set's intent, its record still validated");
  rmSync(join(w.dir, ABANDON, intentName("tag", w.t)));
  writeIntent(w, "agent", w.a);
  assert.equal(restoreReady(w.a, [w.t], expected, { dir: w.dir }), "abandoning", "the agent's own");
  assert.equal(ABANDON, ABANDON_DIR);
  // Re-plan: refused for the set with the intent, fine for another.
  const p = readPlan({ dir: w.dir });
  refused(() => updatePlan(replanSet(p, "agent", w.a, RUN2), { dir: w.dir }), "not_granted");
  assert.equal(readPlan({ dir: w.dir }).sets[`agent-${w.a}`].run, RUN);
  updatePlan(replanSet(p, "archive", w.d, RUN2), { dir: w.dir });
  assert.equal(readPlan({ dir: w.dir }).sets[`archive-${w.d}`].run, RUN2);
  // A late re-plan attempt (the intent accepted, then the re-plan): refused, so the finish still binds and ends abandoned.
  writeRecord(reach("agent", w.a, "files_validated"), { dir: w.dir });
  refused(() => updatePlan(replanSet(readPlan({ dir: w.dir }), "agent", w.a, RUN2), { dir: w.dir }), "not_granted");
  assert.deepEqual(await finishAbandon("agent", w.a, model(w, reach("agent", w.a, "files_validated")).deps, opts(w)), { status: "abandoned" });
});

test("the sidecars' closed shapes: the intent's fields, its reason bound, its nonce canonical; the set its path names", () => {
  const id = newId();
  const good = intentOf("archive", id);
  assert.deepEqual(checkIntent(good, "archive", id), good);
  assert.equal(canonicalNonce(Buffer.alloc(16, 1).toString("base64url")), true);
  for (const n of [Buffer.alloc(15).toString("base64url"), Buffer.alloc(17).toString("base64url"), Buffer.alloc(16).toString("base64"), "A".repeat(21) + "B", null]) {
    assert.equal(canonicalNonce(n), false, String(n));
  }
  assert.equal(checkIntent({ ...good, reason: "é".repeat(250) }, "archive", id).reason.length, 250); // (500 bytes)
  for (const bad of [{ ...good, reason: "é".repeat(250) + "x" }, { ...good, extra: 1 }, (({ nonce, ...x }) => x)(good), { ...good, v: 2 }, { ...good, at: -1 },
    { ...good, at: 2 ** 53 }, { ...good, set_run: "x" }, { ...good, envelope_sha256: "A".repeat(64) }, { ...good, by: "" }, { ...good, nonce: "x" }]) {
    refused(() => checkIntent(bad, "archive", id), "bad_form");
  }
  refused(() => checkIntent(good, "tag", id), "not_granted");
  refused(() => checkIntent(good, "archive", newId()), "not_granted");
});
