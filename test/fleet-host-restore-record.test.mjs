// Host backup r3.3 §5, T3, T5, H2: the restore fence and a restore's per-set record. The record moves one step at a
// time, each written before it acts; a filling record is never filled again (its staging is consumed); a dirty
// destination is cleaned before anything is staged or filled; a stop is never retried but by the person's new request;
// only a validated restore lowers the restore fence. The last rows crash a model fill at every point and recover.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
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
  CLASSES, FAILED_REASONS, KINDS, MAX_ATTEMPTS, RESTORE_RUN, STATES, checkRecord, markerPath, newRecord, newRestoreRun, ownerOf,
  readMarker, readRecord, recordName, recoveryStep, restoreReady, retryRecord, runTime, stagingDir, stagingName, step as rawStep,
  writeRecord, digestsWhole, checkFillReport, readFillReport, writeFillReport, readRegular, MAX_RECORD_BYTES,
} from "../lib/fleet/host/restore-record.mjs";

const refused = (fn, code) => assert.throws(fn, (e) => e instanceof FleetError && e.code === code, code);
const rejects = (p, code) => assert.rejects(p, (e) => e instanceof FleetError && e.code === code, code);
const T1 = 1795400000000;
const RUN = newRestoreRun(T1, () => Buffer.alloc(6)), RUN2 = newRestoreRun(T1 + 86400000, () => Buffer.alloc(6, 1));
const SNAP = "a".repeat(64), SNAP2 = "b".repeat(64);
const DEST = { home: { dev: "2049", ino: "131" }, sessions: { dev: "2049", ino: "132" } };
const fresh = () => mkdtempSync(join(tmpdir(), "sb-restore-"));
/** A class's digest list hash, as its restore-stage would report it (distinct per class and attempt). */
const H = (r, cls) => String(CLASSES[r.kind].indexOf(cls) + 1).repeat(2) + r.attempt + "f".repeat(61);
/** Every class's hash not yet recorded, recorded (the "digest" step), as a whole staging records them. */
const dig = (r) => CLASSES[r.kind].reduce((x, c) => (x.digests !== null && Object.hasOwn(x.digests, c) ? x : rawStep(x, "digest", { cls: c, sha256: H(x, c) })), r);
/** The steps, where reaching staged first records every class's hash (as the fill does). */
const step = (r, to, o) => (to === "staged" && !r.dirty && r.state === "staging" && !digestsWhole(r) ? rawStep(dig(r), "staged", o) : rawStep(r, to, o));

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

test("names: records under RESTORE_DIR by set; staging is the launcher's, one directory per class, under RESTORE_STAGING", () => {
  const id = newId();
  assert.equal(RESTORE_DIR, "/var/lib/sagebrush/restore");
  assert.equal(RESTORE_STAGING, "/srv/sagebrush/.restore");
  assert.equal(recordName("tag", id), `tag-${id}.json`);
  assert.deepEqual([ownerOf("agent", id), ownerOf("archive", id), ownerOf("tag", id)], [`a-${id}`, `a-${id}`, `t-${id}`]);
  for (const [kind, i] of [["agents", id], ["host", id], ["agent", "nope"], ["tag", `${id}/..`]]) refused(() => ownerOf(kind, i), "bad_form");
  const ar = step(newRecord({ kind: "archive", id, run: RUN, snapshot: SNAP }), "retry");
  assert.equal(stagingName(ar, "archive"), `${RUN}/a-${id}/archive/2`);
  assert.equal(stagingDir(ar, "archive"), `/srv/sagebrush/.restore/${RUN}/a-${id}/archive/2`);
  assert.equal(markerPath(ar, "archive"), `/srv/sagebrush/.restore/${RUN}/a-${id}/archive/2/.complete`);
  const ag = newRecord({ kind: "agent", id, run: RUN, snapshot: SNAP });
  assert.deepEqual(CLASSES.agent.map((c) => stagingName(ag, c)), [`${RUN}/a-${id}/home/1`, `${RUN}/a-${id}/sessions/1`]);
  assert.equal(stagingName(newRecord({ kind: "tag", id, run: RUN, snapshot: SNAP }), "tag"), `${RUN}/t-${id}/tag/1`);
  for (const [r, c] of [[ag, "archive"], [ag, "tag"], [ar, "home"], [ar, "x"]]) refused(() => stagingName(r, c), "bad_form");
  for (const [kind, i] of [["agents", id], ["host", id], ["agent", "nope"], ["agent", "../x"]]) refused(() => recordName(kind, i), "bad_form");
  assert.deepEqual(KINDS, ["agent", "archive", "tag"]);
  assert.deepEqual(CLASSES, { agent: ["home", "sessions"], archive: ["archive"], tag: ["tag"] });
});

test("restore runs: the launcher's 16 characters of [a-z2-7], ordered by their decoded time, never as strings", () => {
  assert.ok(RESTORE_RUN.test(RUN) && RESTORE_RUN.test(RUN2));
  assert.equal(runTime(RUN), T1);
  assert.equal(RUN.length, 16);
  assert.equal(newRestoreRun(0, () => Buffer.alloc(6)), "aaaaaaaaaaaaaaaa");
  assert.equal(runTime(newRestoreRun(2 ** 50 - 1, () => Buffer.alloc(6))), 2 ** 50 - 1);
  for (const t of [-1, 1.5, 2 ** 50, NaN, "1"]) refused(() => newRestoreRun(t), "bad_form");
  for (const run of ["", "x", "a".repeat(15), "a".repeat(17), "A".repeat(16), "1".repeat(16), "aaaaaaaaaaaaaaa8"]) refused(() => runTime(run), "bad_form");
  // Random runs of one millisecond differ.
  const many = new Set(Array.from({ length: 200 }, () => newRestoreRun(T1)));
  assert.equal(many.size, 200);
  for (const r of many) assert.equal(runTime(r), T1);
  // A pair where the string order and the time order disagree: the digit '2' (26) sorts before the letter 'z' (25).
  const t = T1 - (T1 % 32) + 25;
  const older = newRestoreRun(t, () => Buffer.alloc(6)), newer = newRestoreRun(t + 1, () => Buffer.alloc(6));
  assert.deepEqual([older[9], newer[9]], ["z", "2"]);
  assert.ok(newer < older && runTime(newer) > runTime(older), "string order isn't time order");
  // retryRecord orders by time: the later run (the lower string) is accepted, the earlier refused.
  let stop = step(newRecord({ kind: "agent", id: newId(), run: older, snapshot: SNAP }), "not_fitting");
  assert.equal(retryRecord(stop, { run: newer, snapshot: SNAP }).run, newer);
  stop = step(newRecord({ kind: "agent", id: newId(), run: newer, snapshot: SNAP }), "not_fitting");
  refused(() => retryRecord(stop, { run: older, snapshot: SNAP }), "bad_form");
  // The same millisecond is not newer, whatever its random part.
  refused(() => retryRecord(stop, { run: newRestoreRun(t + 1, () => Buffer.alloc(6, 9)), snapshot: SNAP }), "bad_form");
});

test("the record's closed shape: a new record, and every invariant refused", () => {
  const id = newId();
  const r = newRecord({ kind: "agent", id, run: RUN, snapshot: SNAP });
  assert.deepEqual(r, { v: 1, kind: "agent", id, run: RUN, snapshot: SNAP, attempt: 1, state: "staging", dest: null, digests: null, dirty: false, reason: null });
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
  refused(() => retryRecord(nf, { run: "20261125T013000Z-bcdefghi", snapshot: SNAP }), "bad_form"); // the backup's run format isn't a restore's
  const r = retryRecord(nf, { run: RUN2, snapshot: SNAP2 });
  assert.deepEqual([r.run, r.snapshot, r.attempt, r.state, r.dirty, r.dest, r.reason], [RUN2, SNAP2, 1, "staging", true, DEST, null]);
  const clean = retryRecord(at("not_fitting"), { run: RUN2, snapshot: SNAP });
  assert.deepEqual([clean.dirty, clean.dest], [false, null]);
  assert.equal(retryRecord(at("failed"), { run: RUN2, snapshot: SNAP }).reason, null);
});

test("digest list hashes (A2 r3.8.3): recorded class by class while staging, once each; staged and after need all", () => {
  const s = at("staging");
  const h = rawStep(s, "digest", { cls: "home", sha256: H(s, "home") });
  assert.deepEqual([h.state, h.digests], ["staging", { home: H(s, "home") }]);
  refused(() => rawStep(h, "digest", { cls: "home", sha256: "e".repeat(64) }), "not_granted"); // never replaced
  refused(() => rawStep(h, "staged"), "bad_form"); // sessions' hash is missing
  refused(() => rawStep(s, "staged"), "bad_form");
  const both = rawStep(h, "digest", { cls: "sessions", sha256: H(s, "sessions") });
  assert.deepEqual(rawStep(both, "staged").digests, { home: H(s, "home"), sessions: H(s, "sessions") });
  for (const [cls, sha256] of [["archive", H(s, "home")], ["tag", H(s, "home")], ["x", H(s, "home")], [undefined, H(s, "home")],
    ["home", "A".repeat(64)], ["home", "a".repeat(63)], ["home", "a".repeat(65)], ["home", 7], ["home", undefined]]) {
    refused(() => rawStep(s, "digest", { cls, sha256 }), "bad_form");
  }
  // Only while staging and not dirty: never after staged, never into a dirty attempt.
  for (const st of ["staged", "filling", "published", "validated", "not_fitting", "failed"]) {
    refused(() => rawStep(at(st), "digest", { cls: "home", sha256: H(s, "home") }), "not_granted");
  }
  refused(() => rawStep(step(at("filling"), "retry"), "digest", { cls: "home", sha256: H(s, "home") }), "not_granted");
  // A new attempt (automatic or the person's) starts with none; a stop keeps them, a clean too.
  assert.equal(step(both, "retry").digests, null);
  assert.equal(step(at("filling"), "retry").digests, null);
  assert.equal(retryRecord(step(at("filling"), "failed", { reason: "bad_form" }), { run: RUN2, snapshot: SNAP }).digests, null);
  assert.deepEqual(step(at("published"), "failed", { reason: "bad_form" }).digests, at("published").digests);
  // The shape: some of the kind's classes, each 64 lower-case hex; none is null, never {}.
  for (const digests of [{}, { home: "A".repeat(64) }, { archive: "a".repeat(64) }, { home: "a".repeat(64), x: "a".repeat(64) }, [], "x", { home: null }]) {
    refused(() => checkRecord({ ...s, digests }), "bad_form");
  }
  for (const st of ["staged", "filling", "published", "validated"]) {
    refused(() => checkRecord({ ...at(st), digests: { home: H(s, "home") } }), "bad_form");
    refused(() => checkRecord({ ...at(st), digests: null }), "bad_form");
  }
  const tg = newRecord({ kind: "tag", id: newId(), run: RUN, snapshot: SNAP });
  refused(() => rawStep(tg, "digest", { cls: "home", sha256: H(s, "home") }), "bad_form");
  assert.equal(rawStep(rawStep(tg, "digest", { cls: "tag", sha256: H(tg, "tag") }), "staged").state, "staged");
});

test("fill reports: bound to the run, attempt and class; paths in A2 §4b's codec; at most 1000 per list", () => {
  const dir = join(fresh(), "restore");
  const r1 = at("filling");
  const rep = { refused: [{ path: "x%25%FF/y", uid: 1, gid: 2, entries: 1 }], unexpected: [{ path: "p", type: "fifo" }], truncated: false };
  writeFillReport(r1, "home", rep, { dir });
  assert.deepEqual(readFillReport(r1, "home", { dir }), { v: 1, run: r1.run, attempt: 1, cls: "home", ...rep });
  assert.equal(readFillReport(r1, "sessions", { dir }), null, "another class's");
  const r2 = step(r1, "retry");
  assert.equal(readFillReport(r2, "home", { dir }), null, "another attempt's report is never used");
  assert.equal(readFillReport({ ...r1, run: RUN2 }, "home", { dir }), null, "another run's");
  writeFileSync(join(dir, `agent-${r1.id}.home.fill.json`), "{");
  refused(() => readFillReport(r1, "home", { dir }), "bad_form");
  const base = { v: 1, run: RUN, attempt: 1, cls: "home", refused: [], unexpected: [], truncated: false };
  const one = (path) => ({ ...base, refused: [{ path, uid: 0, gid: 0, entries: 1 }] });
  for (const path of ["x%25", "%FF", "a/b", "x%E2%82", "\u00e9"]) checkFillReport(one(path));
  for (const path of ["x%", "x%2", "%ff", "%41", "/a", "a/", "a//b", ".", "a/..", "", "a\u0000b", "x".repeat(4097)]) refused(() => checkFillReport(one(path)), "bad_form");
  checkFillReport({ ...base, refused: Array.from({ length: 1000 }, (_, i) => ({ path: `f${i}`, uid: 0, gid: 0, entries: 1 })) });
  refused(() => checkFillReport({ ...base, refused: Array.from({ length: 1001 }, (_, i) => ({ path: `f${i}`, uid: 0, gid: 0, entries: 1 })) }), "bad_form");
  refused(() => checkFillReport({ ...base, unexpected: Array.from({ length: 1001 }, (_, i) => ({ path: `f${i}`, type: "fifo" })) }), "bad_form");
  for (const bad of [{ ...base, x: 1 }, { ...base, truncated: 0 }, { ...base, cls: "x" }, { ...base, attempt: 0 }, { ...base, unexpected: [{ path: "p", type: "door" }] },
    { ...base, refused: [{ path: "a", uid: -1, gid: 0, entries: 1 }] }, { ...base, refused: [{ path: "a", uid: 0, gid: 0, entries: 1.5 }] }]) refused(() => checkFillReport(bad), "bad_form");
});

test("recovery's first step: from every record state and every disk state, every class's marker exactly its name", () => {
  const whole = (r) => Object.fromEntries(CLASSES[r.kind].map((c) => [c, stagingName(r, c)]));
  assert.equal(recoveryStep(null, { markers: {}, begun: false }), "start");
  const s = at("staging");
  assert.equal(recoveryStep(s, { markers: {}, begun: false }), "stage");
  assert.equal(recoveryStep(s, { markers: {}, begun: true }), "retry");
  // Every marker but not every class's digest list hash: the lists can't be trusted, so a retry, never a promote.
  assert.equal(recoveryStep(s, { markers: whole(s), begun: true }), "retry");
  assert.equal(recoveryStep(rawStep(s, "digest", { cls: "home", sha256: H(s, "home") }), { markers: whole(s), begun: true }), "retry");
  assert.equal(recoveryStep(s, { markers: whole(s), begun: false }), "retry", "(markers without the directory: not a stage over them)");
  assert.equal(recoveryStep(dig(s), { markers: whole(s), begun: true }), "promote");
  // One class whole is not the set whole; a marker of any other name (another class, attempt, run or owner), a torn
  // one, or one with a trailing newline is not this class's.
  const other = step(s, "retry");
  for (const markers of [
    { home: whole(s).home }, { sessions: whole(s).sessions }, { home: whole(s).home, sessions: null },
    { home: whole(s).sessions, sessions: whole(s).home }, { ...whole(s), home: whole(other).home },
    { ...whole(s), home: whole(s).home.replace(RUN, RUN2) }, { ...whole(s), home: whole(s).home.replace("a-", "t-") },
    { ...whole(s), home: whole(s).home.slice(0, -1) }, { ...whole(s), home: whole(s).home + "\n" },
    Object.assign(Object.create(whole(s)), {}), null, undefined,
  ]) assert.equal(recoveryStep(dig(s), { markers, begun: true }), "retry", JSON.stringify(markers));
  // Extra classes' markers don't matter; only the set's classes do.
  assert.equal(recoveryStep(dig(s), { markers: { ...whole(s), tag: "x" }, begun: true }), "promote");
  const st = at("staged");
  assert.equal(recoveryStep(st, { markers: whole(st), begun: true }), "fill");
  assert.equal(recoveryStep(st, { markers: { home: whole(st).home }, begun: true }), "retry");
  // A filling record is never filled again, even with every marker still there (a crash before fill-home began).
  const f = at("filling");
  for (const markers of [{}, whole(f)]) for (const begun of [true, false]) assert.equal(recoveryStep(f, { markers, begun }), "retry");
  // Dirty records are cleaned first, whatever is on disk.
  const d = step(f, "retry");
  for (const markers of [{}, whole(d)]) assert.equal(recoveryStep(d, { markers, begun: true }), "clean");
  for (const to of ["not_fitting", "failed"]) {
    const x = step(f, to, { reason: "bad_form" });
    assert.equal(recoveryStep(x, { markers: {}, begun: false }), "clean", to);
    assert.equal(recoveryStep(step(x, "clean"), { markers: {}, begun: false }), "none", `${to}, cleaned: only the person restarts it`);
  }
  assert.equal(recoveryStep(at("published"), { markers: {}, begun: false }), "validate");
  assert.equal(recoveryStep(at("validated"), { markers: {}, begun: false }), "none");
  refused(() => recoveryStep({ ...s, state: "x" }, { markers: {}, begun: false }), "bad_form");
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
  refused(() => readRecord("agent", r.id, { dir }), "bad_form");
});

test("records are read as one regular file: a link, a FIFO, a socket or an oversized file is refused, never followed or waited on", () => {
  const dir = join(fresh(), "restore");
  const r = at("filling");
  writeRecord(r, { dir });
  const file = join(dir, recordName("agent", r.id));
  const real = join(dir, "real");
  fs.renameSync(file, real);
  // A link to a valid record is still refused (never followed).
  fs.symlinkSync(real, file);
  refused(() => readRecord("agent", r.id, { dir }), "bad_form");
  rmSync(file);
  // A FIFO: refused at once, the read never blocks on it.
  execFileSync("mkfifo", [file]);
  refused(() => readRecord("agent", r.id, { dir }), "bad_form");
  rmSync(file);
  execFileSync("python3", ["-I", "-c", "import socket,sys; s=socket.socket(socket.AF_UNIX); s.bind(sys.argv[1])", file]);
  refused(() => readRecord("agent", r.id, { dir }), "bad_form");
  rmSync(file);
  // Longer than any record can be, even when it starts as a valid one.
  writeFileSync(file, JSON.stringify(r) + " ".repeat(MAX_RECORD_BYTES));
  refused(() => readRecord("agent", r.id, { dir }), "bad_form");
  writeFileSync(file, JSON.stringify(r) + " ".repeat(MAX_RECORD_BYTES - JSON.stringify(r).length));
  assert.deepEqual(readRecord("agent", r.id, { dir }), r, "exactly the bound is read");
  // An I/O error is an interruption, thrown as it is.
  for (const code of ["EIO", "EACCES"]) {
    const x = { ...fs, openSync: () => { throw Object.assign(new Error(code), { code }); } };
    assert.throws(() => readRecord("agent", r.id, { dir, fsx: x }), (e) => e.code === code, code);
  }
});

test("a record replaced by rename while read is read again, not called malformed; one that keeps changing is refused", () => {
  const dir = join(fresh(), "restore");
  const r = at("filling");
  writeRecord(r, { dir });
  const st = fs.statSync(join(dir, recordName("agent", r.id)));
  // The first look meets another object (a write renamed over it between lstat and open); the next looks are whole.
  const swapped = (times) => {
    let n = 0;
    return { ...fs, fstatSync: (fd) => {
      const s = fs.fstatSync(fd);
      return n++ < times ? Object.assign(Object.create(Object.getPrototypeOf(s)), s, { ino: st.ino + 1 }) : s;
    } };
  };
  for (const times of [1, 2]) assert.deepEqual(readRecord("agent", r.id, { dir, fsx: swapped(times) }), r, `${times}`);
  refused(() => readRecord("agent", r.id, { dir, fsx: swapped(3) }), "bad_form");
  // Another type swapped in is refused at once, never looked at again.
  let looks = 0;
  const fifo = { ...fs, fstatSync: (fd) => { looks++; const s = fs.fstatSync(fd); return Object.assign(Object.create(Object.getPrototypeOf(s)), s, { mode: 0o10600 }); } };
  refused(() => readRecord("agent", r.id, { dir, fsx: fifo }), "bad_form");
  assert.equal(looks, 1);
  // The fill report keeps one look: it is written once, never replaced.
  refused(() => readRegular(join(dir, recordName("agent", r.id)), 1000, "it", swapped(1)), "bad_form");
});

test("markers are the launcher's: read per class, exactly as written; this side never writes or removes one", async () => {
  const mod = await import("../lib/fleet/host/restore-record.mjs");
  for (const name of ["writeMarker", "invalidateMarker", "markerIo"]) assert.equal(Object.hasOwn(mod, name), false, name);
  const root = fresh();
  const r = at("staging");
  assert.equal(readMarker(r, "home", { root }), null);
  mkdirSync(stagingDir(r, "home", root), { recursive: true });
  assert.equal(readMarker(r, "home", { root }), null);
  // As the launcher writes it: the name, no newline.
  writeFileSync(markerPath(r, "home", root), stagingName(r, "home"));
  assert.equal(readMarker(r, "home", { root }), stagingName(r, "home"));
  assert.equal(readMarker(r, "sessions", { root }), null);
  refused(() => readMarker(r, "tag", { root }), "bad_form");
  // A marker path that isn't a file is an error, never "absent".
  mkdirSync(markerPath(r, "sessions", root), { recursive: true });
  assert.throws(() => readMarker(r, "sessions", { root }), (e) => e.code === "EISDIR");
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
 * A model restore on a real directory tree, with a crash injected at the `crashAt`-th effect, the launcher's part
 * played as the launcher does it: staging each class writes its files into <attempt>/data, then its marker (the
 * class's name); a fill writes `filling`, then per class unlinks the marker and MOVES each file into the class's
 * destination (consuming staging). A quota hit (`quotaAt`: the quotaAt-th move of every fill fails) is not_fitting;
 * `crashOnMove` crashes every fill at that move. Recovery follows recoveryStep only. `fills` records every attempt a
 * durable `filling` was written for; `effects` counts the effects done.
 */
function model(root, id, { crashAt = Infinity, quotaAt = null, crashOnMove = null } = {}) {
  const dir = join(root, "restore"), stage = join(root, "staging"), home = join(root, "home"), sessions = join(root, "sessions");
  for (const d of [dir, stage, home, sessions]) mkdirSync(d, { recursive: true });
  const ident = (p) => { const s = statSync(p, { bigint: true }); return { dev: String(s.dev), ino: String(s.ino) }; };
  const dest = { home: ident(home), sessions: ident(sessions) };
  const into = { home, sessions };
  const m = { fills: [], effects: 0, home, sessions, stage, dir };
  const effect = () => { if (++m.effects === crashAt) throw Object.assign(new Error("crash"), { crash: true }); };
  const save = (r) => { effect(); writeRecord(r, { dir }); return r; };
  const others = (r) => { // every other staging of the set, any run: <run>/<owner>/<class>/<attempt>
    for (const run of readdirSync(stage)) for (const c of CLASSES.agent) {
      const cd = join(stage, run, ownerOf("agent", id), c);
      if (!existsSync(cd)) continue;
      for (const n of readdirSync(cd)) if (run !== r.run || n !== String(r.attempt)) { effect(); rmSync(join(cd, n), { recursive: true }); }
    }
  };
  const ops = {
    stage(r) {
      others(r);
      for (const c of CLASSES.agent) {
        const d = stagingDir(r, c, stage);
        effect(); mkdirSync(join(d, "data"), { recursive: true });
        for (const [k, v] of Object.entries(SNAPSHOT[c])) { effect(); writeFileSync(join(d, "data", k), v); }
        effect(); writeFileSync(markerPath(r, c, stage), stagingName(r, c), { flag: "wx" }); // the launcher's marker
      }
      return save(step(r, "staged"));
    },
    fill(r) {
      r = save(step(r, "filling", { dest }));
      m.fills.push(`${r.run}/${r.attempt}`); // only once filling is durable: before it, nothing is consumed
      let i = 0;
      for (const c of CLASSES.agent) {
        effect(); rmSync(markerPath(r, c, stage)); // fill-home's first act
        for (const k of readdirSync(join(stagingDir(r, c, stage), "data")).sort()) {
          if (++i === quotaAt) return save(step(r, "not_fitting"));
          if (i === crashOnMove) throw Object.assign(new Error("crash"), { crash: true });
          effect(); fs.renameSync(join(stagingDir(r, c, stage), "data", k), join(into[c], k));
        }
      }
      return save(step(r, "published"));
    },
    clean(r) {
      for (const c of CLASSES.agent) for (const e of readdirSync(into[c])) { effect(); rmSync(join(into[c], e)); }
      others(r);
      if (r.state === "staging") for (const c of CLASSES.agent) { const d = stagingDir(r, c, stage); if (existsSync(d)) { effect(); rmSync(d, { recursive: true }); } }
      return save(step(r, "clean"));
    },
    validate(r) {
      const ok = CLASSES.agent.every((c) => JSON.stringify(tree(into[c])) === JSON.stringify(SNAPSHOT[c]));
      return save(ok ? step(r, "validated") : step(r, "failed", { reason: "bad_form" }));
    },
  };
  m.recover = ({ run = RUN } = {}) => {
    for (let guard = 0; guard < 50; guard++) {
      const r = readRecord("agent", id, { dir });
      const disk = r === null ? { markers: {}, begun: false } : {
        markers: Object.fromEntries(CLASSES.agent.map((c) => [c, readMarker(r, c, { root: stage })])),
        begun: CLASSES.agent.some((c) => existsSync(stagingDir(r, c, stage))),
      };
      const s = recoveryStep(r, disk);
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
const SNAPSHOT = { home: { a: "1", b: "22", c: "333" }, sessions: { d: "4444", e: "55555" } };
const tree = (d) => Object.fromEntries(readdirSync(d).sort().map((k) => [k, readFileSync(join(d, k), "utf8")]));
const filled = (m) => ({ home: tree(m.home), sessions: tree(m.sessions) });
const EMPTY = { home: {}, sessions: {} };
/** What is left of a run's staging for the set: class -> its attempts. */
const left = (m, run, id) => Object.fromEntries(CLASSES.agent.map((c) => {
  const cd = join(m.stage, run, `a-${id}`, c);
  return [c, existsSync(cd) ? readdirSync(cd).sort() : []];
}));

test("T5: a crash at any effect of a restore recovers to exactly the snapshot, never filling a consumed attempt", () => {
  const whole = model(fresh(), newId());
  assert.equal(whole.recover().state, "validated");
  assert.deepEqual(filled(whole), SNAPSHOT);
  assert.ok(whole.effects > 15, `${whole.effects} effects`);
  for (let crashAt = 1; crashAt <= whole.effects; crashAt++) {
    const root = fresh(), id = newId();
    const m = model(root, id, { crashAt });
    assert.throws(() => m.recover(), (e) => e.crash === true, `crash at ${crashAt}`);
    const after = model(root, id); // the restart: no crash this time
    const r = after.recover();
    assert.equal(r.state, "validated", `crash at ${crashAt}`);
    assert.deepEqual(filled(after), SNAPSHOT, `crash at ${crashAt}`);
    const fills = [...m.fills, ...after.fills];
    assert.equal(new Set(fills).size, fills.length, `crash at ${crashAt}: an attempt filled twice: ${fills}`);
    assert.ok(r.attempt <= 2, `crash at ${crashAt}: one crash costs at most one attempt (${r.attempt})`);
    // Only the validated attempt's staging (consumed: an empty data, no marker) is left, per class.
    assert.deepEqual(left(after, RUN, id), { home: [String(r.attempt)], sessions: [String(r.attempt)] }, `crash at ${crashAt}`);
    for (const c of CLASSES.agent) {
      assert.deepEqual(readdirSync(stagingDir(r, c, after.stage)), ["data"], `crash at ${crashAt}`);
      assert.deepEqual(readdirSync(join(stagingDir(r, c, after.stage), "data")), []);
    }
  }
});

test("H2: a quota hit in the fill is cleaned once and stops, through any crash; only the person's new request retries", () => {
  const whole = model(fresh(), newId(), { quotaAt: 3 });
  const r0 = whole.recover();
  assert.deepEqual([r0.state, r0.reason, r0.dirty, r0.attempt], ["not_fitting", "limit", false, 1]);
  assert.deepEqual(filled(whole), EMPTY, "the partial fill is removed");
  for (let crashAt = 1; crashAt <= whole.effects; crashAt++) {
    const root = fresh(), id = newId();
    const m = model(root, id, { crashAt, quotaAt: 3 });
    assert.throws(() => m.recover(), (e) => e.crash === true, `crash at ${crashAt}`);
    const after = model(root, id, { quotaAt: 3 });
    const r = after.recover();
    assert.deepEqual([r.state, r.dirty], ["not_fitting", false], `crash at ${crashAt}`);
    assert.deepEqual(filled(after), EMPTY, `crash at ${crashAt}`);
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
  assert.deepEqual(filled(later), SNAPSHOT);
  assert.deepEqual(left(later, RUN, id), { home: [], sessions: [] }, "the old run's staging is discarded");
  assert.deepEqual(left(later, RUN2, id), { home: ["1"], sessions: ["1"] });
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
  assert.deepEqual([after.fills, filled(after)], [[], EMPTY], "never filled again; the partial fill removed");
  assert.equal(model(root, id).recover().state, "failed", "and it stays failed: only the person restarts it");
});

test("readRegular: lstat, a no-follow open, fstat of the SAME object; anything demonstrably not a regular file is bad_form, I/O errors throw", () => {
  const dir = fresh();
  const p = join(dir, "f");
  writeFileSync(p, "hello");
  assert.equal(readRegular(p, 100, "it").toString(), "hello");
  assert.equal(readRegular(join(dir, "none"), 100, "it"), null);
  refused(() => readRegular(p, 4, "it"), "bad_form"); // longer than it can be
  // Through fsx stubs, each seam alone:
  const st = fs.lstatSync(p);
  const like = (o) => Object.assign(Object.create(Object.getPrototypeOf(st)), st, o);
  const swapped = { ...fs, fstatSync: (fd) => like({ ino: st.ino + 1 }) };
  refused(() => readRegular(p, 100, "it", swapped), "bad_form"); // another object behind the open
  const otherDev = { ...fs, fstatSync: (fd) => like({ dev: st.dev + 1 }) };
  refused(() => readRegular(p, 100, "it", otherDev), "bad_form");
  for (const code of ["ENXIO", "ELOOP", "EISDIR", "ENODEV"]) {
    const x = { ...fs, openSync: () => { throw Object.assign(new Error(code), { code }); } };
    refused(() => readRegular(p, 100, "it", x), "bad_form"); // it changed type between lstat and open
  }
  for (const code of ["EIO", "EACCES", "EMFILE"]) {
    const x = { ...fs, openSync: () => { throw Object.assign(new Error(code), { code }); } };
    assert.throws(() => readRegular(p, 100, "it", x), (e) => e.code === code, code); // an interruption, as it is
    const y = { ...fs, lstatSync: () => { throw Object.assign(new Error(code), { code }); } };
    assert.throws(() => readRegular(p, 100, "it", y), (e) => e.code === code, code);
  }
  const short = { ...fs, readSync: () => 0 };
  refused(() => readRegular(p, 100, "it", short), "bad_form");
  // Real objects that aren't regular files: a link, a directory, a FIFO, a socket.
  fs.symlinkSync(p, join(dir, "l"));
  fs.mkdirSync(join(dir, "d"));
  execFileSync("mkfifo", [join(dir, "q")]);
  execFileSync("python3", ["-I", "-c", "import socket,sys; s=socket.socket(socket.AF_UNIX); s.bind(sys.argv[1])", join(dir, "s")]);
  for (const n of ["l", "d", "q", "s"]) refused(() => readRegular(join(dir, n), 100, "it"), "bad_form");
});
