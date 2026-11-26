// Host restore e2e §1, §2, §5: the exclusion with backup, an open restore, the person's begin with its continuation
// after a crash at every durable effect, and close with its one commit point. Real temporary directories and the real
// flock; the store's listing, the host store's copy and its import are fakes that record what they were given.
import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, renameSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "./host-linux-only.mjs";
import { FleetError, newId } from "../lib/fleet/index.mjs";
import { lockFile } from "../lib/fleet/host/store.mjs";
import { CLASSES, newRecord, newRestoreRun, step, writeRecord } from "../lib/fleet/host/restore-record.mjs";
import { PLAN, closePlan, newPlan, readPlan, replanSet, updatePlan } from "../lib/fleet/host/restore-plan.mjs";
import { ABANDON, BEGIN, CLOSED, HOSTSTORE_COPY, REQUESTS, begin, close, closeBlockers, readBegin, removeBeneath, restoreOpen, withExclusion } from "../lib/fleet/host/restore-begin.mjs";

const refused = (fn, code) => assert.throws(fn, (e) => e instanceof FleetError && e.code === code, code);
const rejects = (p, code) => assert.rejects(p, (e) => e instanceof FleetError && e.code === code, code);
const UID = typeof process.getuid === "function" ? process.getuid() : -1; // (Linux-only rows; off Linux the file only loads)
const hex = (c) => c.repeat(64);
const RUN = newRestoreRun(1795500000000, () => Buffer.alloc(6)), RUN2 = newRestoreRun(1795600000000, () => Buffer.alloc(6, 1));
const SNAP = hex("1");

/** A manifest of one live agent, one deleted agent's archive and one tag, as chooseManifest returns it. */
function chosenOf({ sha256 = hex("2"), snapshot = SNAP } = {}) {
  const a = newId(), d = newId(), t = newId();
  const manifest = { host: "old-host", time: "2026-11-24T03:10:00.000Z", hoststore: hex("3"), registry: { hash: hex("4") },
    sets: [{ kind: "agent", id: a, snapshot: hex("5"), tree: hex("6") }, { kind: "archive", id: d, snapshot: hex("7"), tree: hex("8") },
      { kind: "tag", id: t, snapshot: hex("9"), tree: hex("a") }] };
  return { chosen: { manifest, snapshot, sha256 }, a, d, t };
}

/** A host: a private lock directory, a restore directory, and fakes that record every outside effect. */
function host(over = {}) {
  const root = mkdtempSync(join(tmpdir(), "sb-begin-"));
  chmodSync(root, 0o700);
  const dir = join(root, "restore"), lockDir = join(root, "lib");
  mkdirSync(lockDir, { mode: 0o700 });
  const m = chosenOf(over.choose);
  const calls = [];
  const deps = {
    supervisorStopped: () => true, registryFresh: () => true, backupEnabled: () => false,
    choose: async (snapshot) => { calls.push(["choose", snapshot]); return snapshot === m.chosen.snapshot ? m.chosen : { error: "not_found" }; },
    newRun: () => RUN,
    restoreHostStore: async (chosen, into) => { calls.push(["restoreHostStore", into]); writeFileSync(join(into, "registry.json"), "{}"); },
    importHostStore: async ({ copy, plan, manifest }) => { calls.push(["importHostStore", copy, plan.sets, manifest.hoststore]); assert.ok(existsSync(join(copy, "registry.json")), "the copy is whole before the import"); },
    ...over.deps,
  };
  const exclusion = { path: join(lockDir, "backup-restore.lock"), uid: UID, waitMs: 0 };
  return { root, dir, lockDir, deps, calls, exclusion, m, run: () => begin(SNAP, deps, { dir, exclusion }) };
}

/** Everything begin leaves: begin.json, the plan, each request, as text (absent: null). */
const state = (h) => {
  const read = (p) => (existsSync(p) ? readFileSync(p, "utf8") : null);
  const reqDir = join(h.dir, REQUESTS);
  return { begin: read(join(h.dir, BEGIN)), plan: read(join(h.dir, PLAN)),
    requests: existsSync(reqDir) ? Object.fromEntries(readdirSync(reqDir).sort().map((k) => [k, read(join(reqDir, k))])) : null };
};

test("begin: begin.json first, then the plan, the host store's copy and import, one request per set, then done", async () => {
  const h = host();
  const r = await h.run();
  assert.deepEqual(r.run, RUN);
  const s = state(h);
  assert.deepEqual(JSON.parse(s.begin), { v: 1, snapshot: SNAP, manifest_sha256: hex("2"), run: RUN, state: "done" });
  assert.deepEqual(JSON.parse(s.plan), newPlan(h.m.chosen, RUN));
  assert.deepEqual(Object.keys(s.requests), [`agent-${h.m.a}`, `archive-${h.m.d}`, `tag-${h.m.t}`].sort());
  for (const v of Object.values(s.requests)) assert.equal(v, JSON.stringify({ run: RUN }) + "\n");
  assert.deepEqual(h.calls.map((c) => c[0]), ["choose", "restoreHostStore", "importHostStore"]);
  assert.equal(h.calls[1][1], join(h.dir, HOSTSTORE_COPY, RUN));
  // done: any later begin refuses, writing nothing.
  await rejects(h.run(), "in_progress");
  assert.deepEqual(state(h), s);
});

test("begin's refusals write nothing: the supervisor running, a plan here, a registry that isn't fresh, backup enabled, an unusable manifest", async () => {
  for (const [label, over, code] of [
    ["supervisor", { supervisorStopped: () => false }, "in_progress"],
    ["registry", { registryFresh: () => false }, "not_granted"],
    ["backup", { backupEnabled: () => true }, "in_progress"],
    ["manifest", { choose: async () => ({ error: "check_failed" }) }, "not_granted"],
  ]) {
    const h = host({ deps: over });
    await rejects(h.run(), code);
    assert.deepEqual(state(h), { begin: null, plan: null, requests: null }, label);
  }
  // A plan already here, with no begin.json: refused, the plan untouched.
  const h = host();
  mkdirSync(h.dir, { recursive: true, mode: 0o700 });
  writeFileSync(join(h.dir, PLAN), JSON.stringify(newPlan(h.m.chosen, RUN2)) + "\n");
  const before = state(h);
  await rejects(h.run(), "in_progress");
  assert.deepEqual(state(h), before);
});

test("begin's continuation: a crash after each durable effect, each request included, ends in the exact uncrashed state", async () => {
  const ref = host();
  await ref.run();
  const want = state(ref);
  const keys = Object.keys(want.requests);
  // Each crash point, as the durable state it leaves: begin.json only; + the plan; + the copy; + 0..n-1 requests.
  const points = [
    ["after begin.json", { plan: false, requests: 0 }],
    ["after the plan", { plan: true, requests: 0 }],
    ...keys.map((_, i) => [`after ${i} request(s)`, { plan: true, requests: i }]),
    ["after every request, before done", { plan: true, requests: keys.length }],
  ];
  for (const [label, at] of points) {
    const h = host();
    h.m.chosen = ref.m.chosen; Object.assign(h.m, { a: ref.m.a, d: ref.m.d, t: ref.m.t });
    mkdirSync(h.dir, { recursive: true, mode: 0o700 });
    writeFileSync(join(h.dir, BEGIN), JSON.stringify({ v: 1, snapshot: SNAP, manifest_sha256: hex("2"), run: RUN, state: "begun" }) + "\n");
    if (at.plan) writeFileSync(join(h.dir, PLAN), want.plan);
    mkdirSync(join(h.dir, REQUESTS), { recursive: true, mode: 0o700 });
    for (const k of keys.slice(0, at.requests)) writeFileSync(join(h.dir, REQUESTS, k), want.requests[k]);
    // A partial copy left by the crash is discarded first, never imported as it is.
    mkdirSync(join(h.dir, HOSTSTORE_COPY, RUN), { recursive: true });
    writeFileSync(join(h.dir, HOSTSTORE_COPY, RUN, "partial"), "x");
    // The continuation uses the RECORDED run, never a new one.
    h.deps.newRun = () => RUN2;
    await h.run();
    assert.deepEqual(state(h), want, label);
    assert.ok(!existsSync(join(h.dir, HOSTSTORE_COPY, RUN, "partial")), `${label}: the partial copy was discarded`);
    assert.deepEqual(h.calls.map((c) => c[0]), ["choose", "restoreHostStore", "importHostStore"], label);
  }
});

test("begin's continuation is bound exactly: another snapshot, a changed store, a foreign plan, a running supervisor each refuse, writing nothing", async () => {
  const setup = (over) => {
    const h = host(over);
    mkdirSync(h.dir, { recursive: true, mode: 0o700 });
    writeFileSync(join(h.dir, BEGIN), JSON.stringify({ v: 1, snapshot: SNAP, manifest_sha256: hex("2"), run: RUN, state: "begun" }) + "\n");
    return h;
  };
  // Another snapshot than the one that began.
  let h = setup();
  let before = state(h);
  await rejects(begin(hex("e"), h.deps, { dir: h.dir, exclusion: h.exclusion }), "not_granted");
  assert.deepEqual(state(h), before);
  // The store's manifest for that snapshot no longer hashes to the recorded sha256.
  h = setup({ choose: { sha256: hex("f") } });
  before = state(h);
  await rejects(h.run(), "not_granted");
  assert.deepEqual(state(h), before, "no plan rebuilt from a changed manifest");
  // A plan of another run (or another manifest) already here.
  h = setup();
  writeFileSync(join(h.dir, PLAN), JSON.stringify(newPlan(h.m.chosen, RUN2)) + "\n");
  before = state(h);
  await rejects(h.run(), "not_granted");
  assert.deepEqual(state(h), before);
  // The supervisor running.
  h = setup({ deps: { supervisorStopped: () => false } });
  before = state(h);
  await rejects(h.run(), "in_progress");
  assert.deepEqual(state(h), before);
  // A set's request already there with another run: never replaced.
  h = setup();
  writeFileSync(join(h.dir, PLAN), JSON.stringify(newPlan(h.m.chosen, RUN)) + "\n");
  mkdirSync(join(h.dir, REQUESTS), { recursive: true });
  writeFileSync(join(h.dir, REQUESTS, `agent-${h.m.a}`), JSON.stringify({ run: RUN2 }) + "\n");
  await rejects(h.run(), "not_granted");
  assert.equal(readFileSync(join(h.dir, REQUESTS, `agent-${h.m.a}`), "utf8"), JSON.stringify({ run: RUN2 }) + "\n");
  assert.equal(JSON.parse(readFileSync(join(h.dir, BEGIN), "utf8")).state, "begun", "not done");
  // A malformed begin.json is never a continuation.
  h = setup();
  writeFileSync(join(h.dir, BEGIN), "{");
  await rejects(h.run(), "bad_form");
  // The control: with the UNCONDITIONAL new-begin refusals (a plan here, a non-fresh registry), the crash rows above
  // could never complete; here the plan is there and the registry not fresh, and the exact continuation completes.
  h = setup({ deps: { registryFresh: () => false } });
  writeFileSync(join(h.dir, PLAN), JSON.stringify(newPlan(h.m.chosen, RUN)) + "\n");
  await h.run();
  assert.equal(JSON.parse(state(h).begin).state, "done");
});

test("an open restore: begin.json AND (no plan, or a plan not closed); unreadable or malformed counts as open", () => {
  const dir = join(mkdtempSync(join(tmpdir(), "sb-open-")), "restore");
  mkdirSync(dir, { recursive: true });
  const { chosen } = chosenOf();
  const b = JSON.stringify({ v: 1, snapshot: SNAP, manifest_sha256: hex("2"), run: RUN, state: "begun" }) + "\n";
  const plan = JSON.stringify(newPlan(chosen, RUN)) + "\n";
  const set = (beginText, planText) => {
    for (const [n, t] of [[BEGIN, beginText], [PLAN, planText]]) { rmSync(join(dir, n), { force: true, recursive: true }); if (t !== null) writeFileSync(join(dir, n), t); }
  };
  const cases = [
    ["nothing", null, null, false],
    ["a plan alone (no begin.json)", null, plan, false],
    ["begin.json, no plan (a half-begun restore)", b, null, true],
    ["begin.json, an open plan", b, plan, true],
    ["begin.json, a malformed plan", b, "{", true],
    ["a malformed begin.json", "{", plan, true],
  ];
  for (const [label, bt, pt, want] of cases) { set(bt, pt); assert.equal(restoreOpen({ dir }), want, label); }
  set(b, plan);
  closePlan(1, { dir });
  assert.equal(restoreOpen({ dir }), false, "closed");
  // A begin.json that is a directory or a link: unreadable, open.
  rmSync(join(dir, BEGIN)); mkdirSync(join(dir, BEGIN));
  assert.equal(restoreOpen({ dir }), true);
  rmSync(join(dir, BEGIN), { recursive: true }); symlinkSync(join(dir, PLAN), join(dir, BEGIN));
  assert.equal(restoreOpen({ dir }), true);
});

test("the exclusion: a held lock refuses begin and close (busy) before anything is read or written; an untrusted lock file refuses", async () => {
  const h = host();
  await withExclusion(async () => {}, h.exclusion); // the lock file, created private (as every holder does)
  const held = await lockFile(h.exclusion.path); // another holder: a backup run
  try {
    await rejects(h.run(), "in_progress");
    assert.deepEqual(state(h), { begin: null, plan: null, requests: null });
    assert.equal(h.calls.length, 0, "nothing was asked of the store");
    await rejects(close({ now: () => 1 }, { dir: h.dir, exclusion: h.exclusion }), "in_progress");
  } finally { await held.release(); }
  await h.run(); // free again: it begins
  // The lock file: a private regular file in a private directory, else refused before it is tried.
  for (const [label, prep] of [
    ["group-readable file", (p) => { writeFileSync(p, ""); chmodSync(p, 0o640); }],
    ["a link", (p) => symlinkSync("/etc/hostname", p)],
    ["a directory", (p) => mkdirSync(p)],
  ]) {
    const x = host();
    prep(x.exclusion.path);
    await rejects(withExclusion(async () => assert.fail("ran"), x.exclusion), "not_granted");
    assert.ok(label);
  }
  const y = host();
  chmodSync(y.lockDir, 0o777);
  await rejects(withExclusion(async () => assert.fail("ran"), y.exclusion), "not_granted");
  // Created 0600 when missing.
  const z = host();
  await withExclusion(async () => {}, z.exclusion);
  assert.equal(statSync(z.exclusion.path).mode & 0o777, 0o600);
});

/** Records for the restored host's sets, each in `states[kind]`. */
function records(h, states) {
  const ident = (ino) => ({ dev: "1", ino, uid: 70000, gid: 70000, mode: 0o700, projid: 70000 });
  const reach = (kind, id, target) => {
    let r = newRecord({ kind, id, run: RUN, snapshot: SNAP });
    if (target === "staging") return r;
    if (target === "abandoned") return step(r, "abandoned");
    const cls = CLASSES[kind];
    const dest = Object.fromEntries(cls.map((c, i) => [c, ident(String(10 + i))]));
    r = step(r, "bind", { dest });
    for (const c of cls) r = step(r, "digest", { cls: c, sha256: hex("d") });
    for (const s of ["staged", "filling", "published", "files_validated"]) r = step(r, s, { dest });
    if (target === "files_validated") return r;
    if (r.imports !== null) for (const which of ["config", "context"]) for (const phase of ["pending", "done"]) r = step(r, "import", { which, phase, sha256: hex("c") });
    return step(r, "validated");
  };
  for (const [kind, id] of [["agent", h.m.a], ["archive", h.m.d], ["tag", h.m.t]]) writeRecord(reach(kind, id, states[kind]), { dir: h.dir });
}

test("close: every set terminal-for-close, per kind; anything else refuses, naming each set; nothing is written", async () => {
  const h = host();
  await h.run();
  const raised = new Set([h.m.a]);
  const restoreRaised = (id) => raised.has(id);
  const attempt = () => close({ now: () => 7, restoreRaised }, { dir: h.dir, exclusion: h.exclusion });
  // No records yet: each set named.
  await assert.rejects(attempt(), (e) => e.code === "not_granted" && /agent-.*: none/.test(e.message) && /archive-.*: none/.test(e.message));
  // The agent validated but not resumed (its restore fence still up): refused.
  records(h, { agent: "validated", archive: "validated", tag: "validated" });
  await assert.rejects(attempt(), (e) => e.code === "not_granted" && /validated, not resumed/.test(e.message));
  assert.ok(!Object.hasOwn(readPlan({ dir: h.dir }), "closed"), "still open");
  // An archive files_validated (not validated), a tag stepping: refused.
  raised.delete(h.m.a);
  records(h, { agent: "validated", archive: "files_validated", tag: "staging" });
  await assert.rejects(attempt(), (e) => e.code === "not_granted" && /archive-.*: files_validated/.test(e.message) && /tag-.*: staging/.test(e.message));
  // An abandon intent whose record isn't abandoned yet: refused (the cleanup isn't proven).
  records(h, { agent: "validated", archive: "validated", tag: "staging" });
  mkdirSync(join(h.dir, ABANDON), { recursive: true });
  writeFileSync(join(h.dir, ABANDON, `tag-${h.m.t}.json`), "{}");
  assert.deepEqual(closeBlockers(readPlan({ dir: h.dir }), { dir: h.dir, restoreRaised, uid: UID }), [`tag-${h.m.t}: abandoning`]);
  await rejects(attempt(), "not_granted");
  // Abandoned: closes. Requests and the host store's copy are removed; restoreOpen is false; the archive is read-only.
  records(h, { agent: "validated", archive: "validated", tag: "abandoned" });
  assert.deepEqual(await attempt(), { closed: 7 });
  assert.equal(restoreOpen({ dir: h.dir }), false);
  assert.ok(!existsSync(join(h.dir, REQUESTS)) && !existsSync(join(h.dir, HOSTSTORE_COPY)));
  const into = join(h.dir, CLOSED, RUN);
  const archived = readdirSync(into).sort();
  assert.ok(archived.includes(PLAN) && archived.includes(BEGIN) && archived.includes(`tag-${h.m.t}.json`) && archived.includes(`tag-${h.m.t}.abandon.json`));
  for (const f of archived) assert.equal(statSync(join(into, f)).mode & 0o777, 0o400, f);
  assert.deepEqual(readFileSync(join(into, PLAN)), readFileSync(join(h.dir, PLAN)));
  // Closing again: the same, nothing changed.
  assert.deepEqual(await attempt(), { closed: 7 });
  // A closed restore is never re-planned.
  const p = readPlan({ dir: h.dir });
  const { closed: _c, ...open } = p;
  refused(() => updatePlan(replanSet(open, "agent", h.m.a, RUN2), { dir: h.dir }), "not_granted");
});

test("close: a crash after the commit, and after each archived file, is finished by closing again; before the commit the restore stays open", async () => {
  const h = host();
  await h.run();
  records(h, { agent: "validated", archive: "abandoned", tag: "validated" });
  const restoreRaised = () => false;
  // Before the commit (a refusal), nothing is closed.
  await rejects(close({ now: () => 7, restoreRaised: () => true }, { dir: h.dir, exclusion: h.exclusion }), "not_granted");
  assert.equal(restoreOpen({ dir: h.dir }), true);
  // The commit, then a crash: simulated by an archived file planted with other bytes, so close stops after its commit.
  const into = join(h.dir, CLOSED, RUN);
  mkdirSync(into, { recursive: true });
  writeFileSync(join(into, `agent-${h.m.a}.json`), "other");
  await rejects(close({ now: () => 7, restoreRaised }, { dir: h.dir, exclusion: h.exclusion }), "not_granted");
  assert.equal(restoreOpen({ dir: h.dir }), false, "the commit is durable: the restore is closed");
  assert.ok(existsSync(join(h.dir, REQUESTS)), "the cleanup didn't run yet");
  rmSync(join(into, `agent-${h.m.a}.json`));
  // Closing again finishes it, with the SAME close time (the commit isn't redone).
  assert.deepEqual(await close({ now: () => 99, restoreRaised }, { dir: h.dir, exclusion: h.exclusion }), { closed: 7 });
  assert.ok(!existsSync(join(h.dir, REQUESTS)));
  assert.deepEqual(readFileSync(join(into, `agent-${h.m.a}.json`)), readFileSync(join(h.dir, `agent-${h.m.a}.json`)));
});

test("close refuses a restore whose begin hasn't finished, and a host with no restore", async () => {
  const h = host();
  await rejects(close({ now: () => 1 }, { dir: h.dir, exclusion: h.exclusion }), "not_found");
  await h.run();
  const b = readBegin({ dir: h.dir });
  writeFileSync(join(h.dir, BEGIN), JSON.stringify({ ...b, state: "begun" }) + "\n");
  await rejects(close({ now: () => 1, restoreRaised: () => false }, { dir: h.dir, exclusion: h.exclusion }), "in_progress");
});

test("closePlan: the one commit point, durable and idempotent; a closed plan's shape", () => {
  const dir = join(mkdtempSync(join(tmpdir(), "sb-close-")), "restore");
  mkdirSync(dir, { recursive: true });
  refused(() => closePlan(1, { dir }), "not_found");
  writeFileSync(join(dir, PLAN), JSON.stringify(newPlan(chosenOf().chosen, RUN)) + "\n");
  refused(() => closePlan(-1, { dir }), "bad_form");
  const p = closePlan(5, { dir });
  assert.deepEqual(p.closed, { at: 5 });
  assert.deepEqual(closePlan(9, { dir }).closed, { at: 5 }, "closed once: the first time stays");
  for (const closed of [{}, { at: "5" }, { at: 5, x: 1 }, null]) {
    writeFileSync(join(dir, PLAN), JSON.stringify({ ...p, closed }) + "\n");
    refused(() => readPlan({ dir }), "bad_form");
  }
});

// ---- Paths: every restore-owned directory proven a real private directory; nothing followed through a link ---------

/** An outside directory with a file in it, and a way to see it untouched. */
function outside(h, run = RUN) {
  const ext = join(h.root, "outside");
  mkdirSync(join(ext, run), { recursive: true });
  writeFileSync(join(ext, run, "keep"), "outside bytes");
  writeFileSync(join(ext, "keep"), "outside bytes");
  return { ext, intact: () => readFileSync(join(ext, run, "keep"), "utf8") === "outside bytes" && readFileSync(join(ext, "keep"), "utf8") === "outside bytes" && readdirSync(ext).sort().join() === [run, "keep"].sort().join() };
}

test("begin never follows a link at the host store's copy or the requests: refused, the outside untouched", async () => {
  for (const at of [HOSTSTORE_COPY, REQUESTS]) {
    const h = host();
    mkdirSync(h.dir, { recursive: true, mode: 0o700 });
    const o = outside(h);
    symlinkSync(o.ext, join(h.dir, at));
    await rejects(h.run(), "not_granted");
    assert.ok(o.intact(), `${at}: the outside is byte-identical`);
    assert.ok(!existsSync(join(o.ext, `agent-${h.m.a}`)), `${at}: no request written outside`);
    if (at === HOSTSTORE_COPY) assert.ok(!h.calls.some((c) => c[0] === "restoreHostStore"), "nothing restored");
  }
  // The restore directory itself a link: refused.
  const h = host();
  const o = outside(h);
  symlinkSync(o.ext, h.dir);
  await assert.rejects(h.run());
  assert.ok(o.intact());
});

test("a partial copy holding a link to the outside: discarded link by link, the outside untouched, then begin completes", async () => {
  const h = host();
  mkdirSync(join(h.dir, HOSTSTORE_COPY, RUN, "sub"), { recursive: true, mode: 0o700 });
  const o = outside(h);
  symlinkSync(o.ext, join(h.dir, HOSTSTORE_COPY, RUN, "dirlink"));
  symlinkSync(join(o.ext, "keep"), join(h.dir, HOSTSTORE_COPY, RUN, "sub", "filelink"));
  await h.run();
  assert.ok(o.intact(), "the links were unlinked, never followed");
  assert.deepEqual(readdirSync(join(h.dir, HOSTSTORE_COPY, RUN)), ["registry.json"], "the copy is the fresh one");
});

test("close never follows a link: at closed/, at an archived entry, at abandon/, and its cleanup unlinks links in place", async () => {
  const ready = async () => {
    const h = host();
    await h.run();
    records(h, { agent: "validated", archive: "validated", tag: "validated" });
    return h;
  };
  const attempt = (h) => close({ now: () => 7, restoreRaised: () => false }, { dir: h.dir, exclusion: h.exclusion, uid: UID });
  // closed/ a link to the outside: refused after the commit, the outside untouched; once it is a real directory, close finishes.
  let h = await ready();
  let o = outside(h);
  symlinkSync(o.ext, join(h.dir, CLOSED));
  await rejects(attempt(h), "not_granted");
  assert.ok(o.intact());
  rmSync(join(h.dir, CLOSED));
  assert.deepEqual(await attempt(h), { closed: 7 });
  // An archived entry already there as a link, or not 0400: refused.
  for (const plant of [(p) => symlinkSync(join(o.ext, "keep"), p), (p) => writeFileSync(p, readFileSync(join(h.dir, PLAN)), { mode: 0o644 })]) {
    h = await ready();
    o = outside(h);
    mkdirSync(join(h.dir, CLOSED, RUN), { recursive: true, mode: 0o700 });
    plant(join(h.dir, CLOSED, RUN, PLAN));
    await rejects(attempt(h), "not_granted");
    assert.ok(o.intact());
  }
  // abandon/ a link to an outside directory: refused BEFORE the commit (the done check proves the directory), with
  // nothing read through it. With no intent outside, only the directory proof stops it before the commit.
  h = await ready();
  o = outside(h);
  symlinkSync(o.ext, join(h.dir, ABANDON));
  await rejects(attempt(h), "not_granted");
  assert.equal(restoreOpen({ dir: h.dir }), true, "not committed");
  assert.ok(o.intact());
  // The cleanup: a link planted inside requests/ and the copy is unlinked, never followed.
  h = await ready();
  o = outside(h);
  symlinkSync(o.ext, join(h.dir, REQUESTS, "zz-link"));
  symlinkSync(join(o.ext, "keep"), join(h.dir, HOSTSTORE_COPY, RUN, "filelink"));
  assert.deepEqual(await attempt(h), { closed: 7 });
  assert.ok(o.intact() && !existsSync(join(h.dir, REQUESTS)) && !existsSync(join(h.dir, HOSTSTORE_COPY)));
});

// ---- The locks: losing either holder stops the operation at once; nothing more is done -----------------------------

/** Kill the real flock holding `path` (its child process), as an OOM kill or a crash would. */
function killHolder(path) {
  let n = 0;
  for (const pid of readdirSync("/proc").filter((p) => /^[0-9]+$/.test(p))) {
    let cmd;
    try { cmd = readFileSync(`/proc/${pid}/cmdline`, "utf8").split("\0"); } catch { continue; }
    if (cmd[0].endsWith("flock") && cmd.includes(path)) { process.kill(Number(pid), "SIGKILL"); n += 1; }
  }
  assert.ok(n > 0, `a holder of ${path} was found`);
}
const settle = () => new Promise((r) => setTimeout(r, 200));

test("begin: the exclusion's or the restore lock's holder killed at each step: outcome_unknown, nothing more done, a backup can't overlap", async () => {
  const steps = ["begin:locked", "begin:bound", "begin:planned", "begin:copying", "begin:copied", "begin:imported", "begin:requested"];
  for (const which of ["exclusion", "restore"]) {
    for (const step of steps) {
      const h = host();
      const path = which === "exclusion" ? h.exclusion.path : join(h.dir, ".lock");
      const onStep = async (name) => { if (name === step) { killHolder(path); await settle(); } };
      await rejects(begin(SNAP, h.deps, { dir: h.dir, exclusion: h.exclusion, onStep }), "outcome_unknown");
      const s = state(h);
      const label = `${which} lost at ${step}`;
      // Nothing after the step: the effects the step's successors make are all absent.
      const i = steps.indexOf(step);
      if (i < 1) assert.equal(s.begin, null, label);
      if (i < 2) assert.equal(s.plan, null, label);
      if (i < 4) assert.ok(!h.calls.some((c) => c[0] === "restoreHostStore"), label);
      if (i < 5) assert.ok(!h.calls.some((c) => c[0] === "importHostStore"), label);
      if (i < 6) assert.ok(s.requests === null || Object.keys(s.requests).length === 0, label);
      assert.notEqual(s.begin === null ? null : JSON.parse(s.begin).state, "done", label);
      // The exclusion is free (its holder is gone); a backup takes it, and begin writes nothing more meanwhile.
      if (which === "exclusion") {
        const backup = await lockFile(h.exclusion.path);
        const before = JSON.stringify(state(h));
        await settle();
        assert.equal(JSON.stringify(state(h)), before, `${label}: nothing written while the backup holds it`);
        await backup.release();
      }
    }
  }
});

test("close: a holder killed before the commit leaves the restore open; after it, nothing more is archived or removed, and close again finishes", async () => {
  for (const [step, committed] of [["close:locked", false], ["close:checked", false], ["close:committed", true], ["close:archived", true]]) {
    const h = host();
    await h.run();
    records(h, { agent: "validated", archive: "validated", tag: "validated" });
    const onStep = async (name) => { if (name === step) { killHolder(h.exclusion.path); await settle(); } };
    await rejects(close({ now: () => 7, restoreRaised: () => false }, { dir: h.dir, exclusion: h.exclusion, uid: UID, onStep }), "outcome_unknown");
    assert.equal(restoreOpen({ dir: h.dir }), !committed, step);
    assert.ok(existsSync(join(h.dir, REQUESTS)), `${step}: the requests weren't removed`);
    if (step !== "close:archived") assert.ok(!existsSync(join(h.dir, CLOSED, RUN, PLAN)), `${step}: nothing archived`);
    // Close again (the locks fresh): it finishes, with the first close time when it had committed.
    assert.deepEqual(await close({ now: () => 9, restoreRaised: () => false }, { dir: h.dir, exclusion: h.exclusion, uid: UID }), { closed: committed ? 7 : 9 });
  }
});

// ---- SEC r2 narrowing: a replaced nested entry, and lock loss inside the copy and the import ------------------------

test("removeBeneath walks by handle: a nested directory replaced by a link before its open, or moved away after it, never reaches the outside", async () => {
  const mk = () => {
    const root = mkdtempSync(join(tmpdir(), "sb-rm-"));
    chmodSync(root, 0o700);
    const top = join(root, "top"), ext = join(root, "outside");
    mkdirSync(join(top, "run", "sub", "deeper"), { recursive: true });
    writeFileSync(join(top, "run", "sub", "deeper", "f"), "ours");
    // entries named like the outside's, so a walk that re-resolved the name would reach (and remove) the outside's
    for (const n of ["a", "g", "keep", "z"]) writeFileSync(join(top, "run", "sub", n), "ours");
    mkdirSync(ext); writeFileSync(join(ext, "keep"), "outside bytes");
    chmodSync(join(top, "run", "sub"), 0o777); // a level someone else could write: made private through its handle first
    const intact = () => readFileSync(join(ext, "keep"), "utf8") === "outside bytes" && readdirSync(ext).join() === "keep";
    return { root, top, ext, intact };
  };
  // Replaced between its lstat and its open: refused, the outside untouched.
  let t = mk();
  let swapped = false;
  const before = (here, name) => {
    if (name === "sub" && !swapped) { swapped = true; renameSync(join(here, "sub"), join(t.root, "moved")); symlinkSync(t.ext, join(here, "sub")); }
  };
  assert.throws(() => removeBeneath(t.top, "run", { uid: UID, onEntry: before }), (e) => e.code === "not_granted");
  assert.ok(swapped && t.intact(), "the outside is untouched");
  // Replaced between its lstat and its open by a DIFFERENT REAL directory (no link: O_NOFOLLOW alone lets it through):
  // the handle isn't the object looked at, so it is refused before that directory is re-owned, made private or emptied.
  t = mk();
  swapped = false;
  const other = join(t.root, "other");
  mkdirSync(join(other, "inner"), { recursive: true });
  for (const n of ["a", "keep"]) writeFileSync(join(other, n), "theirs");
  chmodSync(other, 0o755);
  const swapReal = (here, name) => {
    if (name === "sub" && !swapped) { swapped = true; renameSync(join(here, "sub"), join(t.root, "moved")); renameSync(other, join(here, "sub")); }
  };
  assert.throws(() => removeBeneath(t.top, "run", { uid: UID, onEntry: swapReal }), (e) => e.code === "not_granted");
  const there = join(t.top, "run", "sub");
  assert.ok(swapped, "swapped");
  assert.deepEqual(readdirSync(there).sort(), ["a", "inner", "keep"], "its entries all kept");
  assert.deepEqual(["a", "keep"].map((n) => readFileSync(join(there, n), "utf8")), ["theirs", "theirs"]);
  assert.equal(statSync(there).mode & 0o777, 0o755, "its mode unchanged: not made private through a handle");
  assert.equal(readdirSync(join(t.root, "moved")).length > 0, true, "the moved original isn't reached either");
  // Moved away and replaced by a link AFTER it was opened (while its entries are removed): the walk stays on the
  // opened directory; the outside is untouched, and the link left at the name is never followed.
  t = mk();
  swapped = false;
  // At the FIRST entry of sub visited (sub already opened and listed), so every later entry would be re-resolved by a
  // pathname walk through the link: "keep" among them.
  const during = (here, name) => {
    if (["a", "deeper", "g", "keep", "z"].includes(name) && !swapped) {
      swapped = true;
      renameSync(join(t.top, "run", "sub"), join(t.root, "moved"));
      symlinkSync(t.ext, join(t.top, "run", "sub"));
    }
  };
  assert.throws(() => removeBeneath(t.top, "run", { uid: UID, onEntry: during }));
  assert.ok(swapped && t.intact(), "the outside is untouched");
  assert.deepEqual(readdirSync(join(t.root, "moved")), [], "the opened directory itself was emptied");
  assert.equal(statSync(join(t.root, "moved")).mode & 0o777, 0o700, "the writable level was made private through its handle before its entries were read");
  // No race: the whole tree goes, the writable level included.
  t = mk();
  removeBeneath(t.top, "run", { uid: UID });
  assert.deepEqual(readdirSync(t.top), []);
  assert.ok(t.intact());
});

test("a lock lost INSIDE the host store's copy or import (the real holder killed mid-step): the step's next effect never happens", async () => {
  for (const [which, inside] of [["exclusion", "restoreHostStore"], ["exclusion", "importHostStore"], ["restore", "restoreHostStore"], ["restore", "importHostStore"]]) {
    const effects = [];
    const h = host();
    const path = which === "exclusion" ? h.exclusion.path : join(h.dir, ".lock");
    // A step with three effects, each behind the guard it is given, the holder killed after the first.
    const step = async (guard) => {
      for (let i = 0; i < 3; i++) {
        guard();
        effects.push(i);
        if (i === 0) { killHolder(path); await settle(); }
      }
    };
    h.deps[inside] = inside === "restoreHostStore"
      ? async (chosen, into, { guard }) => { await step(guard); writeFileSync(join(into, "registry.json"), "{}"); }
      : async ({ guard }) => { await step(guard); };
    await rejects(h.run(), "outcome_unknown");
    assert.deepEqual(effects, [0], `${which} lost inside ${inside}: only the first effect`);
    assert.notEqual(JSON.parse(state(h).begin).state, "done");
  }
});

test("close: the RESTORE lock's holder killed at each step, as the exclusion's: the same stop, and close again finishes", async () => {
  for (const [step, committed] of [["close:locked", false], ["close:checked", false], ["close:committed", true], ["close:archived", true]]) {
    const h = host();
    await h.run();
    records(h, { agent: "validated", archive: "validated", tag: "validated" });
    const onStep = async (name) => { if (name === step) { killHolder(join(h.dir, ".lock")); await settle(); } };
    await rejects(close({ now: () => 7, restoreRaised: () => false }, { dir: h.dir, exclusion: h.exclusion, uid: UID, onStep }), "outcome_unknown");
    assert.equal(restoreOpen({ dir: h.dir }), !committed, step);
    assert.ok(existsSync(join(h.dir, REQUESTS)), `${step}: the requests weren't removed`);
    assert.deepEqual(await close({ now: () => 9, restoreRaised: () => false }, { dir: h.dir, exclusion: h.exclusion, uid: UID }), { closed: committed ? 7 : 9 });
  }
});
