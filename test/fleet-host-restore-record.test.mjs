// Host backup r3.3 §5, T3, T5, H2: the restore fence and a restore's per-set record. The record moves one step at a
// time, each written before it acts; a filling record is never filled again (its staging is consumed); a dirty
// destination is cleaned before anything is staged or filled; a stop is never retried but by the person's new request;
// only a validated restore lowers the restore fence. The last rows crash a model fill at every point and recover.
import assert from "node:assert/strict";
import * as fs from "node:fs";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "./host-linux-only.mjs";
import { FleetError, newId } from "../lib/fleet/index.mjs";
import { CAUSES, fenced, lowerFence, raiseFence, stop } from "../lib/fleet/host/fence.mjs";
import { RESTORE_DIR, RESTORE_STAGING, fenceFiles } from "../lib/fleet/host/names.mjs";
import { realIo } from "../lib/fleet/host/store.mjs";
import {
  CLASSES, FAILED_REASONS, KINDS, MAX_ATTEMPTS, STATES, checkRecord, invalidateMarker, markerIo, markerPath, newRecord, readMarker,
  readRecord, recordName, recoveryStep, restoreReady, retryRecord, stagingDir, stagingSetDir, step, writeMarker, writeRecord,
} from "../lib/fleet/host/restore-record.mjs";

const refused = (fn, code) => assert.throws(fn, (e) => e instanceof FleetError && e.code === code, code);
const rejects = (p, code) => assert.rejects(p, (e) => e instanceof FleetError && e.code === code, code);
const RUN = "20261124T013000Z-abcdefgh", RUN2 = "20261125T013000Z-bcdefghi";
const SNAP = "a".repeat(64), SNAP2 = "b".repeat(64);
const DEST = { home: { dev: "2049", ino: "131" }, sessions: { dev: "2049", ino: "132" } };
const fresh = () => mkdtempSync(join(tmpdir(), "sb-restore-"));

/** A record in `state`, reached by the steps themselves (never hand-built), for kind "agent". */
function at(state, { attempt = 1, id = newId() } = {}) {
  let r = newRecord({ kind: "agent", id, run: RUN, snapshot: SNAP });
  for (let i = 1; i < attempt; i++) r = step(r, "retry");
  const path = {
    staging: [], staged: ["staged"], filling: ["staged", "filling"], published: ["staged", "filling", "published"],
    validated: ["staged", "filling", "published", "validated"], not_fitting: ["not_fitting"], failed: ["failed"],
  }[state];
  for (const s of path) r = step(r, s, { dest: DEST, reason: "outcome_unknown" });
  return r;
}

test("the restore fence: per agent at fence/restore/<id>, lowered only by a resume of a validated restore, never a stop cause", async () => {
  const dir = join(fresh(), "fence");
  const a = newId(), b = newId();
  assert.ok(CAUSES.includes("restore"));
  assert.equal(fenceFiles(a).restore, `/var/lib/sagebrush/fence/restore/${a}`);
  raiseFence("restore", a, { dir });
  assert.ok(existsSync(join(dir, "restore", a)));
  assert.equal(fenced(a, { dir }), true);
  assert.equal(fenced(b, { dir }), false, "one agent's restore fence fences only that agent");
  for (const auth of ["resume-agent", "resume-all", "newer-grant", "backup-recovery"]) {
    await rejects(lowerFence("restore", a, auth, { dir, restoreState: "validated" }), "not_granted");
  }
  for (const restoreState of [undefined, null, "", "none", "VALIDATED", true, ...STATES.filter((s) => s !== "validated")]) {
    await rejects(lowerFence("restore", a, "resume-restored", { dir, restoreState }), "not_granted");
  }
  // Nor does the agent's own resume, with a resumable registry state, lower it.
  await rejects(lowerFence("restore", a, "resume-agent", { dir, agentState: "stopped" }), "not_granted");
  assert.ok(existsSync(join(dir, "restore", a)));
  // The restore fence lowers no other fence, and no other cause's lowering touches it.
  raiseFence("agent", a, { dir }); raiseFence("backup", a, { dir });
  await lowerFence("agent", a, "resume-agent", { dir, agentState: "stopped" });
  await lowerFence("backup", a, "backup-recovery", { dir });
  assert.equal(fenced(a, { dir }), true, "the restore fence is still up");
  await lowerFence("restore", a, "resume-restored", { dir, restoreState: "validated" });
  assert.equal(fenced(a, { dir }), false);
  await lowerFence("restore", b, "resume-restored", { dir, restoreState: "validated" }); // never raised: fine
  refused(() => raiseFence("restore", "nope", { dir }), "bad_form");
  await rejects(stop({ agent: a }, "restore", { dir }), "bad_form");
});

test("names: records under RESTORE_DIR by set, staging under RESTORE_STAGING by run, set and attempt", () => {
  const id = newId();
  assert.equal(RESTORE_DIR, "/var/lib/sagebrush/restore");
  assert.equal(RESTORE_STAGING, "/srv/sagebrush/.restore");
  assert.equal(recordName("tag", id), `tag-${id}.json`);
  const r = step(newRecord({ kind: "archive", id, run: RUN, snapshot: SNAP }), "retry");
  assert.equal(stagingSetDir(RUN, "archive", id), `/srv/sagebrush/.restore/${RUN}/archive-${id}`);
  assert.equal(stagingDir(r), `/srv/sagebrush/.restore/${RUN}/archive-${id}/2`);
  assert.equal(markerPath(r), `/srv/sagebrush/.restore/${RUN}/archive-${id}/2.complete`);
  for (const [kind, i] of [["agents", id], ["host", id], ["agent", "nope"], ["agent", "../x"]]) refused(() => recordName(kind, i), "bad_form");
  for (const run of ["", "x", `${RUN}/..`, "20261124T013000Z-ABCDEFGH"]) refused(() => stagingSetDir(run, "agent", id), "bad_form");
  assert.deepEqual(KINDS, ["agent", "archive", "tag"]);
  assert.deepEqual(CLASSES, { agent: ["home", "sessions"], archive: ["archive"], tag: ["tag"] });
});

test("the record's closed shape: a new record, and every invariant refused", () => {
  const id = newId();
  const r = newRecord({ kind: "agent", id, run: RUN, snapshot: SNAP });
  assert.deepEqual(r, { v: 1, kind: "agent", id, run: RUN, snapshot: SNAP, attempt: 1, state: "staging", dest: null, dirty: false, reason: null });
  const f = at("filling");
  const bad = [
    [r, { v: 2 }], [r, { kind: "host" }], [r, { id: "nope" }], [r, { run: "x" }], [r, { snapshot: "A".repeat(64) }],
    [r, { snapshot: SNAP.slice(1) }], [r, { attempt: 0 }], [r, { attempt: MAX_ATTEMPTS + 1 }], [r, { attempt: 1.5 }],
    [r, { attempt: "1" }], [r, { state: "done" }], [r, { dirty: 0 }], [r, { reason: "limit" }], [r, { extra: 1 }],
    // a destination is the kind's exact classes, each a decimal identity
    [f, { dest: { home: DEST.home } }], [f, { dest: { ...DEST, archive: DEST.home } }], [f, { dest: { ...DEST, home: { dev: 1, ino: "2" } } }],
    [f, { dest: { ...DEST, home: { dev: "01", ino: "2" } } }], [f, { dest: { ...DEST, home: { dev: "1", ino: "2", x: 1 } } }],
    [f, { dest: { tag: DEST.home } }],
    // filling, published and validated need a destination; dirty needs one; filling is dirty; staged/published/validated aren't
    [f, { dest: null }], [at("published"), { dest: null, dirty: false }], [at("validated"), { dest: null }],
    [r, { dirty: true }], [f, { dirty: false }], [at("published"), { dirty: true }], [at("validated"), { dirty: true }],
    [at("staged"), { dest: DEST, dirty: true }],
    // reasons: not_fitting is limit, failed one of FAILED_REASONS, every other state none
    [at("not_fitting"), { reason: "outcome_unknown" }], [at("not_fitting"), { reason: null }], [at("failed"), { reason: "limit" }],
    [at("failed"), { reason: null }], [at("failed"), { reason: "in_progress" }], [at("published"), { reason: "bad_form" }],
  ];
  for (const [base, change] of bad) refused(() => checkRecord({ ...base, ...change }), "bad_form");
  for (const k of Object.keys(r)) { const x = { ...r }; delete x[k]; refused(() => checkRecord(x), "bad_form"); }
  refused(() => checkRecord(null), "bad_form");
  refused(() => checkRecord([r]), "bad_form");
  // Each state reached by its own steps is valid.
  for (const s of STATES) assert.equal(checkRecord(at(s)).state, s);
});

test("steps: exactly the allowed ones, from exactly the allowed states", () => {
  const allowed = {
    staged: ["staging"], filling: ["staged"], published: ["filling"], validated: ["published"],
    not_fitting: ["staging", "filling"], failed: ["staging", "staged", "filling", "published"],
    retry: ["staging", "staged", "filling"], clean: [],
  };
  for (const [to, from] of Object.entries(allowed)) {
    for (const s of STATES) {
      const r = at(s);
      const go = () => step(r, to, { dest: DEST, reason: "bad_form" });
      if (from.includes(s)) assert.ok(go(), `${s} -> ${to}`);
      else refused(go, "not_granted");
    }
  }
  refused(() => step(at("staging"), "done"), "bad_form");
  refused(() => step({ ...at("staging"), v: 0 }, "staged"), "bad_form");
});

test("steps: filling records the destination, once per run; a stop out of filling stays dirty; clean only when dirty", () => {
  const r = at("staged");
  refused(() => step(r, "filling"), "bad_form");
  refused(() => step(r, "filling", { dest: { home: DEST.home } }), "bad_form");
  refused(() => step(r, "filling", { dest: { tag: DEST.home } }), "bad_form");
  const f = step(r, "filling", { dest: DEST });
  assert.deepEqual([f.state, f.dirty, f.dest], ["filling", true, DEST]);
  assert.notEqual(f.dest, DEST, "the record keeps its own copy");
  // A later attempt fills the same destination only.
  const again = step(step(f, "retry"), "clean");
  assert.deepEqual([again.state, again.attempt, again.dirty, again.dest], ["staging", 2, false, DEST]);
  const staged2 = step(again, "staged");
  refused(() => step(staged2, "filling", { dest: { ...DEST, home: { dev: "2049", ino: "999" } } }), "bad_form");
  assert.equal(step(staged2, "filling", { dest: structuredClone(DEST) }).attempt, 2);
  // published clears dirty; validated keeps the destination.
  const p = step(f, "published");
  assert.deepEqual([p.dirty, step(p, "validated").dest], [false, DEST]);
  // A stop keeps dirty as it was.
  for (const to of ["not_fitting", "failed"]) {
    const s = step(f, to, { reason: "outcome_unknown" });
    assert.deepEqual([s.state, s.dirty], [to, true]);
    const c = step(s, "clean");
    assert.deepEqual([c.state, c.dirty, c.reason], [to, false, s.reason]);
    refused(() => step(c, "clean"), "not_granted");
  }
  assert.equal(step(at("staging"), "not_fitting").reason, "limit");
  for (const st of ["staging", "not_fitting", "failed", "published", "validated", "staged"]) refused(() => step(at(st), "clean"), "not_granted");
});

test("steps: a failure names one of FAILED_REASONS, all in the closed reasons list", () => {
  const names = JSON.parse(readFileSync(new URL("../schema/fleet/reasons.json", import.meta.url), "utf8")).reasons.map((r) => r.name);
  for (const n of [...FAILED_REASONS, "limit"]) assert.ok(names.includes(n), n);
  for (const reason of FAILED_REASONS) assert.equal(step(at("staging"), "failed", { reason }).reason, reason);
  for (const reason of [undefined, null, "limit", "in_progress", "nope"]) refused(() => step(at("staging"), "failed", { reason }), "bad_form");
});

test("steps: automatic retries are a new attempt each, dirty once a destination was recorded, at most MAX_ATTEMPTS", () => {
  let r = at("staging");
  assert.equal(MAX_ATTEMPTS, 3);
  r = step(r, "retry");
  assert.deepEqual([r.state, r.attempt, r.dirty], ["staging", 2, false], "nothing was ever filled: nothing to clean");
  r = step(r, "retry");
  assert.equal(r.attempt, MAX_ATTEMPTS);
  refused(() => step(r, "retry"), "limit");
  const f = at("filling", { attempt: 2 });
  const r3 = step(f, "retry");
  assert.deepEqual([r3.attempt, r3.dirty, r3.dest], [3, true, DEST]);
  refused(() => step(r3, "staged"), "not_granted"); // nothing is staged while dirty
  refused(() => step(step(step(r3, "clean"), "staged"), "retry"), "limit");
});

test("a stop is restarted only by the person's new request: a new run, attempt 1, dirty when filled before", () => {
  for (const s of STATES.filter((x) => !["not_fitting", "failed"].includes(x))) refused(() => retryRecord(at(s), { run: RUN2, snapshot: SNAP }), "not_granted");
  const nf = step(at("filling", { attempt: 3 }), "not_fitting");
  refused(() => retryRecord(nf, { run: RUN, snapshot: SNAP }), "bad_form");
  refused(() => retryRecord(nf, { run: "x", snapshot: SNAP }), "bad_form");
  const r = retryRecord(nf, { run: RUN2, snapshot: SNAP2 });
  assert.deepEqual([r.run, r.snapshot, r.attempt, r.state, r.dirty, r.dest, r.reason], [RUN2, SNAP2, 1, "staging", true, DEST, null]);
  const clean = retryRecord(at("not_fitting"), { run: RUN2, snapshot: SNAP });
  assert.deepEqual([clean.dirty, clean.dest], [false, null]);
  assert.equal(retryRecord(at("failed"), { run: RUN2, snapshot: SNAP }).reason, null);
});

test("recovery's first step: from every record state and every disk state", () => {
  const whole = (r) => ({ v: 1, run: r.run, kind: r.kind, id: r.id, snapshot: r.snapshot, attempt: r.attempt });
  assert.equal(recoveryStep(null, { marker: null, attemptExists: false }), "start");
  const s = at("staging");
  assert.equal(recoveryStep(s, { marker: null, attemptExists: false }), "stage");
  assert.equal(recoveryStep(s, { marker: null, attemptExists: true }), "retry");
  assert.equal(recoveryStep(s, { marker: whole(s), attemptExists: true }), "promote");
  // A marker for anything else than this exact binding is not this attempt's.
  for (const k of ["v", "run", "kind", "id", "snapshot", "attempt"]) {
    const m = { ...whole(s), [k]: k === "attempt" || k === "v" ? 2 : k === "run" ? RUN2 : k === "kind" ? "tag" : k === "id" ? newId() : SNAP2 };
    assert.equal(recoveryStep(s, { marker: m, attemptExists: true }), "retry", k);
  }
  assert.equal(recoveryStep(s, { marker: { ...whole(s), extra: 1 }, attemptExists: true }), "retry");
  const st = at("staged");
  assert.equal(recoveryStep(st, { marker: whole(st), attemptExists: true }), "fill");
  assert.equal(recoveryStep(st, { marker: null, attemptExists: true }), "retry");
  // A filling record is never filled again, even with its marker still there (a crash before the invalidation).
  const f = at("filling");
  for (const marker of [null, whole(f)]) for (const attemptExists of [true, false]) assert.equal(recoveryStep(f, { marker, attemptExists }), "retry");
  // Dirty records are cleaned first, whatever is on disk.
  const d = step(f, "retry");
  for (const marker of [null, whole(d)]) assert.equal(recoveryStep(d, { marker, attemptExists: true }), "clean");
  for (const to of ["not_fitting", "failed"]) {
    const x = step(f, to, { reason: "bad_form" });
    assert.equal(recoveryStep(x, { marker: null, attemptExists: false }), "clean", to);
    assert.equal(recoveryStep(step(x, "clean"), { marker: null, attemptExists: false }), "none", `${to}, cleaned: only the person restarts it`);
  }
  assert.equal(recoveryStep(at("published"), { marker: null, attemptExists: false }), "validate");
  assert.equal(recoveryStep(at("validated"), { marker: null, attemptExists: false }), "none");
  refused(() => recoveryStep({ ...s, state: "x" }, { marker: null, attemptExists: false }), "bad_form");
});

test("records on disk: durable, 0600 in a 0700 directory, absent is null, anything invalid or another set's throws", () => {
  const dir = join(fresh(), "restore");
  const r = at("filling");
  assert.equal(readRecord("agent", r.id, { dir: join(dir, "none") }), null);
  writeRecord(r, { dir });
  assert.deepEqual(readRecord("agent", r.id, { dir }), r);
  assert.equal(statSync(dir).mode & 0o777, 0o700);
  assert.equal(statSync(join(dir, recordName("agent", r.id))).mode & 0o777, 0o600);
  assert.equal(readRecord("agent", newId(), { dir }), null);
  refused(() => writeRecord({ ...r, dirty: false }, { dir }), "bad_form");
  assert.deepEqual(readRecord("agent", r.id, { dir }), r, "a refused write leaves the record");
  // A failed fsync throws, and the old record stays whole.
  const io = { ...realIo, fsync: () => { throw Object.assign(new Error("EIO"), { code: "EIO" }); } };
  assert.throws(() => writeRecord(step(r, "published"), { dir, io }), /EIO/);
  assert.deepEqual(readRecord("agent", r.id, { dir }), r);
  const file = join(dir, recordName("agent", r.id));
  for (const text of ["", "{", "null", JSON.stringify({ ...r, state: "done" })]) {
    writeFileSync(file, text);
    refused(() => readRecord("agent", r.id, { dir }), "bad_form");
  }
  // Another set's record under this name is refused, never taken for this set's.
  writeFileSync(file, JSON.stringify({ ...r, id: newId() }));
  refused(() => readRecord("agent", r.id, { dir }), "bad_form");
  writeFileSync(file, JSON.stringify({ ...r, kind: "archive", dest: { archive: DEST.home } }));
  refused(() => readRecord("agent", r.id, { dir }), "bad_form");
  rmSync(file);
  mkdirSync(file);
  assert.throws(() => readRecord("agent", r.id, { dir }), (e) => e.code === "EISDIR");
});

test("markers: written once, only while staging and clean; torn is not complete; invalidated only by a fill", () => {
  const root = fresh();
  const r = at("staging");
  mkdirSync(stagingDir(r, root), { recursive: true });
  assert.equal(readMarker(r, { root }), null);
  for (const s of ["staged", "filling", "published", "not_fitting"]) refused(() => writeMarker({ ...at(s), id: r.id }, { root }), "not_granted");
  refused(() => writeMarker(step(at("filling"), "retry"), { root }), "not_granted"); // dirty
  writeMarker(r, { root });
  assert.deepEqual(readMarker(r, { root }), { v: 1, run: RUN, kind: "agent", id: r.id, snapshot: SNAP, attempt: 1 });
  assert.equal(statSync(markerPath(r, root)).mode & 0o777, 0o600);
  assert.equal(recoveryStep(r, { marker: readMarker(r, { root }), attemptExists: true }), "promote");
  assert.throws(() => writeMarker(r, { root }), (e) => e.code === "EEXIST", "a marker is never rewritten");
  // A torn marker reads as none.
  writeFileSync(markerPath(r, root), "{\"v\":1,\"run\"");
  assert.equal(readMarker(r, { root }), null);
  assert.equal(recoveryStep(r, { marker: readMarker(r, { root }), attemptExists: true }), "retry");
  // Invalidation: only a filling record, durable, idempotent.
  const st = step(r, "staged");
  refused(() => invalidateMarker(st, { root }), "not_granted");
  const f = step(st, "filling", { dest: DEST });
  invalidateMarker(f, { root });
  assert.equal(existsSync(markerPath(f, root)), false);
  invalidateMarker(f, { root });
  // Another attempt's marker is a different file.
  const r2 = step(f, "retry");
  assert.notEqual(markerPath(r2, root), markerPath(f, root));
});

/** A markerIo that records each step as [op, path] (fds mapped back to their paths) and fails `fail` = [op, path]. */
function spyIo(fail = null) {
  const ops = [], fds = new Map();
  const check = (op, p) => { ops.push([op, p]); if (fail && fail[0] === op && fail[1] === p) throw Object.assign(new Error(`injected ${op}`), { code: "EIO" }); };
  return {
    ops,
    io: {
      ...markerIo,
      open: (p, f, m) => { const fd = markerIo.open(p, f, m); fds.set(fd, p); ops.push(["open", p]); return fd; },
      write: (fd, b, o, l) => { check("write", fds.get(fd)); return markerIo.write(fd, b, o, l); },
      fsync: (fd) => { check("fsync", fds.get(fd)); return markerIo.fsync(fd); },
      close: (fd) => { ops.push(["close", fds.get(fd)]); return markerIo.close(fd); },
      unlink: (p) => { check("unlink", p); return markerIo.unlink(p); },
    },
  };
}

test("markers are durable in order: the whole write, then the file's fsync, then its directory's; each failure throws", () => {
  const root = fresh();
  const r = at("staging");
  mkdirSync(stagingDir(r, root), { recursive: true });
  const file = markerPath(r, root), set = stagingSetDir(r.run, r.kind, r.id, root);
  const { ops, io } = spyIo();
  writeMarker(r, { root, io });
  assert.deepEqual(ops, [["open", file], ["write", file], ["fsync", file], ["close", file], ["open", set], ["fsync", set], ["close", set]]);
  assert.deepEqual(readMarker(r, { root }), { v: 1, run: RUN, kind: "agent", id: r.id, snapshot: SNAP, attempt: 1 });
  // A short write is completed before the flush; a zero-byte write is an error, never a whole marker.
  const r2 = step(r, "retry");
  mkdirSync(stagingDir(r2, root), { recursive: true });
  const f2 = markerPath(r2, root);
  const short = spyIo();
  writeMarker(r2, { root, io: { ...short.io, write: (fd, b, o, l) => short.io.write(fd, b, o, Math.min(l, 5)) } });
  const writes = short.ops.filter(([op]) => op === "write").length;
  assert.ok(writes > 1, `${writes} writes`);
  assert.ok(short.ops.findIndex(([op]) => op === "fsync") > short.ops.findLastIndex(([op]) => op === "write"), "the flush follows the last write");
  assert.deepEqual(readMarker(r2, { root }).attempt, 2);
  rmSync(f2);
  assert.throws(() => writeMarker(r2, { root, io: { ...markerIo, write: () => 0 } }), (e) => e.code === "EIO");
  for (const fail of [["fsync", f2], ["fsync", set], ["write", f2]]) {
    rmSync(f2, { force: true });
    assert.throws(() => writeMarker(r2, { root, io: spyIo(fail).io }), (e) => e.code === "EIO", fail.join(" "));
  }
});

test("invalidating a marker is durable in order: the unlink, then its directory's fsync; each failure throws", () => {
  const root = fresh();
  const r = at("staging");
  mkdirSync(stagingDir(r, root), { recursive: true });
  writeMarker(r, { root });
  const f = step(step(r, "staged"), "filling", { dest: DEST });
  const file = markerPath(f, root), set = stagingSetDir(f.run, f.kind, f.id, root);
  assert.throws(() => invalidateMarker(f, { root, io: spyIo(["fsync", set]).io }), (e) => e.code === "EIO", "the directory's flush");
  writeFileSync(file, "x");
  assert.throws(() => invalidateMarker(f, { root, io: spyIo(["unlink", file]).io }), (e) => e.code === "EIO", "the unlink");
  assert.ok(existsSync(file));
  const { ops, io } = spyIo();
  invalidateMarker(f, { root, io });
  assert.deepEqual(ops, [["unlink", file], ["open", set], ["fsync", set], ["close", set]]);
  assert.equal(existsSync(file), false);
  // Already gone (a crash after the unlink): the directory is still flushed.
  const again = spyIo();
  invalidateMarker(f, { root, io: again.io });
  assert.deepEqual(again.ops, [["unlink", file], ["open", set], ["fsync", set], ["close", set]]);
});

test("restoreReady: validated only when the agent's record and each of its tags' records are", () => {
  const dir = join(fresh(), "restore");
  const a = newId(), t1 = newId(), t2 = newId();
  const want = { [`agent-${a}`]: { run: RUN, snapshot: SNAP }, [`tag-${t1}`]: { run: RUN, snapshot: SNAP }, [`tag-${t2}`]: { run: RUN, snapshot: SNAP } };
  assert.equal(restoreReady(a, [], want, { dir }), "none");
  const va = at("validated", { id: a });
  writeRecord(va, { dir });
  assert.equal(restoreReady(a, [], want, { dir }), "validated");
  assert.equal(restoreReady(a, [t1], want, { dir }), "none", "a tag folder not restored yet");
  writeRecord(tag(t1, ["staged", "filling", "published"]), { dir });
  assert.equal(restoreReady(a, [t1], want, { dir }), "published");
  writeRecord(tag(t1, ["staged", "filling", "published", "validated"]), { dir });
  writeRecord(tag(t2, ["not_fitting"]), { dir });
  assert.equal(restoreReady(a, [t1], want, { dir }), "validated");
  assert.equal(restoreReady(a, [t1, t2], want, { dir }), "not_fitting");
  writeRecord(step(at("published", { id: a }), "failed", { reason: "bad_form" }), { dir });
  assert.equal(restoreReady(a, [t1], want, { dir }), "failed");
  for (const [x, tags] of [["nope", []], [a, "x"], [a, ["nope"]]]) refused(() => restoreReady(x, tags, want, { dir }), "bad_form");
});

test("restoreReady: every record is bound to the current restore's run and snapshot; a mixed or stale restore is refused", () => {
  const dir = join(fresh(), "restore");
  const a = newId(), t = newId();
  const bind = (agentRun, agentSnap, tagRun, tagSnap) => ({ [`agent-${a}`]: { run: agentRun, snapshot: agentSnap }, [`tag-${t}`]: { run: tagRun, snapshot: tagSnap } });
  // The agent's set was restored again by the person's new request (RUN2); its tag folder's record is from RUN.
  writeRecord(tag(t, ["staged", "filling", "published", "validated"]), { dir });
  let r = retryRecord(step(at("staging", { id: a }), "not_fitting"), { run: RUN2, snapshot: SNAP2 });
  for (const s of ["staged", "filling", "published", "validated"]) r = step(r, s, { dest: DEST });
  writeRecord(r, { dir });
  assert.equal(restoreReady(a, [t], bind(RUN2, SNAP2, RUN, SNAP), { dir }), "validated", "per-set bindings may differ by run when the plan says so");
  // A mixed run: the plan expects the tag folder from RUN2 too, but its record is RUN's.
  refused(() => restoreReady(a, [t], bind(RUN2, SNAP2, RUN2, SNAP), { dir }), "not_granted");
  // A stale snapshot: the same run, another snapshot (the plan's manifest changed).
  refused(() => restoreReady(a, [t], bind(RUN2, SNAP2, RUN, SNAP2), { dir }), "not_granted");
  refused(() => restoreReady(a, [t], bind(RUN2, SNAP, RUN, SNAP), { dir }), "not_granted");
  refused(() => restoreReady(a, [t], bind(RUN, SNAP2, RUN, SNAP), { dir }), "not_granted");
  // A record from another restore is refused even when it isn't validated, so it never reads as progress.
  writeRecord(tag(t, ["staged"]), { dir });
  refused(() => restoreReady(a, [t], bind(RUN2, SNAP2, RUN2, SNAP2), { dir }), "not_granted");
  // The binding is required for every set, in its closed shape.
  const good = bind(RUN2, SNAP2, RUN, SNAP);
  for (const expected of [
    undefined, null, [], {}, { [`agent-${a}`]: good[`agent-${a}`] }, { ...good, [`tag-${t}`]: { run: RUN } },
    { ...good, [`tag-${t}`]: { run: RUN, snapshot: SNAP, extra: 1 } }, { ...good, [`tag-${t}`]: { run: "x", snapshot: SNAP } },
    { ...good, [`tag-${t}`]: { run: RUN, snapshot: "A".repeat(64) } }, { ...good, [`tag-${t}`]: null },
    Object.assign(Object.create({ [`tag-${t}`]: { run: RUN, snapshot: SNAP } }), { [`agent-${a}`]: good[`agent-${a}`] }),
  ]) refused(() => restoreReady(a, [t], expected, { dir }), "bad_form");
  // The binding is checked before any record is read: an absent record set still refuses a bad binding.
  refused(() => restoreReady(newId(), [], {}, { dir }), "bad_form");
});

const tag = (id, path) => { let r = newRecord({ kind: "tag", id, run: RUN, snapshot: SNAP }); for (const s of path) r = step(r, s, { dest: { tag: DEST.home } }); return r; };

/**
 * A model fill on a real directory tree, with a crash injected at the `crashAt`-th effect: staging writes files then
 * the marker; a fill writes `filling`, invalidates the marker, then MOVES each file into the destination (consuming
 * staging). A quota hit (`quotaAt`: the quotaAt-th move of every fill fails) is not_fitting; `crashOnMove` crashes
 * every fill at that move. Recovery follows
 * recoveryStep only. `fills` records every attempt a durable `filling` was written for; `effects` counts the effects done.
 */
function model(root, id, { crashAt = Infinity, quotaAt = null, crashOnMove = null } = {}) {
  const dir = join(root, "restore"), stage = join(root, "staging"), home = join(root, "home"), sessions = join(root, "sessions");
  for (const d of [dir, stage, home, sessions]) mkdirSync(d, { recursive: true });
  const ident = (p) => { const s = statSync(p, { bigint: true }); return { dev: String(s.dev), ino: String(s.ino) }; };
  const dest = { home: ident(home), sessions: ident(sessions) };
  const m = { fills: [], effects: 0, home, stage, dir };
  const effect = () => { if (++m.effects === crashAt) throw Object.assign(new Error("crash"), { crash: true }); };
  const save = (r) => { effect(); writeRecord(r, { dir }); return r; };
  const others = (r) => { // every other staging of the set: other runs' and other attempts', with their markers
    for (const run of readdirSync(stage)) {
      const set = stagingSetDir(run, r.kind, r.id, stage);
      if (!existsSync(set)) continue;
      for (const e of readdirSync(set)) if (run !== r.run || (e !== String(r.attempt) && e !== `${r.attempt}.complete`)) { effect(); rmSync(join(set, e), { recursive: true }); }
    }
  };
  const ops = {
    stage(r) {
      others(r);
      const d = stagingDir(r, stage);
      effect(); mkdirSync(d, { recursive: true });
      for (const [k, v] of Object.entries(SNAPSHOT)) { effect(); writeFileSync(join(d, k), v); }
      effect(); writeMarker(r, { root: stage });
      return save(step(r, "staged"));
    },
    fill(r) {
      r = save(step(r, "filling", { dest }));
      m.fills.push(`${r.run}/${r.attempt}`); // only once filling is durable: before it, nothing is consumed
      effect(); invalidateMarker(r, { root: stage });
      let i = 0;
      for (const k of readdirSync(stagingDir(r, stage)).sort()) {
        if (++i === quotaAt) return save(step(r, "not_fitting"));
        if (i === crashOnMove) throw Object.assign(new Error("crash"), { crash: true });
        effect(); fs.renameSync(join(stagingDir(r, stage), k), join(home, k));
      }
      return save(step(r, "published"));
    },
    clean(r) {
      for (const e of readdirSync(home)) { effect(); rmSync(join(home, e)); }
      others(r);
      if (r.state === "staging") { const d = stagingDir(r, stage); if (existsSync(d)) { effect(); rmSync(d, { recursive: true }); } }
      return save(step(r, "clean"));
    },
    validate(r) {
      return save(JSON.stringify(tree(home)) === JSON.stringify(SNAPSHOT) ? step(r, "validated") : step(r, "failed", { reason: "bad_form" }));
    },
  };
  m.recover = ({ run = RUN } = {}) => {
    for (let guard = 0; guard < 50; guard++) {
      const r = readRecord("agent", id, { dir });
      const s = recoveryStep(r, r === null ? { marker: null, attemptExists: false } : { marker: readMarker(r, { root: stage }), attemptExists: existsSync(stagingDir(r, stage)) });
      if (s === "none") return r;
      if (s === "start") ops.stage(save(newRecord({ kind: "agent", id, run, snapshot: SNAP })));
      else if (s === "stage") ops.stage(r);
      else if (s === "promote") save(step(r, "staged"));
      else if (s === "fill") ops.fill(r);
      else if (s === "clean") ops.clean(r);
      else if (s === "validate") ops.validate(r);
      else if (s === "retry") { try { save(step(r, "retry")); } catch (e) { if (e.code !== "limit") throw e; save(step(r, "failed", { reason: "outcome_unknown" })); } }
    }
    throw new Error("recovery doesn't settle");
  };
  return m;
}
const SNAPSHOT = { a: "1", b: "22", c: "333", d: "4444" };
const tree = (d) => Object.fromEntries(readdirSync(d).sort().map((k) => [k, readFileSync(join(d, k), "utf8")]));

test("T5: a crash at any effect of a restore recovers to exactly the snapshot, never filling a consumed attempt", () => {
  const whole = model(fresh(), newId());
  assert.equal(whole.recover().state, "validated");
  assert.deepEqual(tree(whole.home), SNAPSHOT);
  assert.ok(whole.effects > 15, `${whole.effects} effects`);
  for (let crashAt = 1; crashAt <= whole.effects; crashAt++) {
    const root = fresh(), id = newId();
    const m = model(root, id, { crashAt });
    assert.throws(() => m.recover(), (e) => e.crash === true, `crash at ${crashAt}`);
    const after = model(root, id); // the restart: no crash this time
    const r = after.recover();
    assert.equal(r.state, "validated", `crash at ${crashAt}`);
    assert.deepEqual(tree(after.home), SNAPSHOT, `crash at ${crashAt}`);
    const fills = [...m.fills, ...after.fills];
    assert.equal(new Set(fills).size, fills.length, `crash at ${crashAt}: an attempt filled twice: ${fills}`);
    assert.ok(r.attempt <= 2, `crash at ${crashAt}: one crash costs at most one attempt (${r.attempt})`);
    // Only the validated attempt's staging (consumed, empty) is left; its marker is gone.
    const set = stagingSetDir(RUN, "agent", id, after.stage);
    assert.deepEqual(readdirSync(set), [String(r.attempt)], `crash at ${crashAt}`);
    assert.deepEqual(readdirSync(join(set, String(r.attempt))), []);
  }
});

test("H2: a quota hit in the fill is cleaned once and stops, through any crash; only the person's new request retries", () => {
  const whole = model(fresh(), newId(), { quotaAt: 3 });
  const r0 = whole.recover();
  assert.deepEqual([r0.state, r0.reason, r0.dirty, r0.attempt], ["not_fitting", "limit", false, 1]);
  assert.deepEqual(tree(whole.home), {}, "the partial fill is removed");
  for (let crashAt = 1; crashAt <= whole.effects; crashAt++) {
    const root = fresh(), id = newId();
    const m = model(root, id, { crashAt, quotaAt: 3 });
    assert.throws(() => m.recover(), (e) => e.crash === true, `crash at ${crashAt}`);
    const after = model(root, id, { quotaAt: 3 });
    const r = after.recover();
    assert.deepEqual([r.state, r.dirty], ["not_fitting", false], `crash at ${crashAt}`);
    assert.deepEqual(tree(after.home), {}, `crash at ${crashAt}`);
    // Once not_fitting is written, nothing fills again: a restart after it does nothing.
    const again = model(root, id, { quotaAt: 3 });
    assert.equal(again.recover().state, "not_fitting");
    assert.deepEqual([again.fills, again.effects], [[], 0], `crash at ${crashAt}: a stop is not retried`);
  }
  // The person's new request: a new run from attempt 1, which now fits.
  const root = fresh(), id = newId();
  const m = model(root, id, { quotaAt: 2 });
  const nf = m.recover();
  writeRecord(retryRecord(nf, { run: RUN2, snapshot: SNAP }), { dir: m.dir });
  const later = model(root, id);
  const r = later.recover();
  assert.deepEqual([r.state, r.run, r.attempt], ["validated", RUN2, 1]);
  assert.deepEqual(tree(later.home), SNAPSHOT);
  assert.deepEqual(readdirSync(later.stage), [RUN, RUN2].sort());
  assert.deepEqual(readdirSync(stagingSetDir(RUN, "agent", id, later.stage)), [], "the old run's staging is discarded");
});

test("automatic retries stop at MAX_ATTEMPTS: a set that crashes in every fill fails (outcome_unknown), cleaned", () => {
  const root = fresh(), id = newId();
  for (let i = 1; i <= MAX_ATTEMPTS; i++) {
    const m = model(root, id, { crashOnMove: 2 });
    assert.throws(() => m.recover(), (e) => e.crash === true, `attempt ${i}`);
    assert.deepEqual(m.fills, [`${RUN}/${i}`]);
  }
  const after = model(root, id);
  const r = after.recover();
  assert.deepEqual([r.state, r.reason, r.attempt, r.dirty], ["failed", "outcome_unknown", MAX_ATTEMPTS, false]);
  assert.deepEqual([after.fills, tree(after.home)], [[], {}], "never filled again; the partial fill removed");
  assert.equal(model(root, id).recover().state, "failed", "and it stays failed: only the person restarts it");
});
