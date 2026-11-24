// Host backup r3.3 §5 steps 7-8, T5, H2: the per-set fill driver, against a fake launcher that stages and fills on a
// real temporary tree exactly as A2 does (the class's data under <attempt>/data, the marker written last with the
// class's name; fill-home unlinks the marker first, then moves). Exit codes are scripted per call, so every branch
// runs: a quota hit stops as not_fitting, out of space and partial steps retry in a new attempt, anything else fails;
// filling is written before the first fill-home, and a filling record is never filled again.
import assert from "node:assert/strict";
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, renameSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "./host-linux-only.mjs";
import { FleetError, newId } from "../lib/fleet/index.mjs";
import { EXIT, classPaths, fillExpect, outcomeOf, ownersOf, restoreFiller, writeExpectFile } from "../lib/fleet/host/restore-fill.mjs";
import { realIo } from "../lib/fleet/host/store.mjs";
import { MAX_ATTEMPTS, newRestoreRun, readRecord, retryRecord, writeRecord } from "../lib/fleet/host/restore-record.mjs";

const rejects = (p, code) => assert.rejects(p, (e) => e instanceof FleetError && e.code === code, code);
const RUN = newRestoreRun(1795500000000, () => Buffer.alloc(6)), RUN2 = newRestoreRun(1795600000000, () => Buffer.alloc(6));
const SNAP = "a".repeat(64);
const hex = (c) => c.repeat(64);
const DATA = { home: { "a.txt": "A", "b.txt": "BB" }, sessions: { "s.db": "SSS" }, archive: { "old.txt": "O" }, tag: { "shared.txt": "T" } };
const tree = (d) => (existsSync(d) ? Object.fromEntries(readdirSync(d).sort().map((k) => [k, readFileSync(join(d, k), "utf8")])) : null);

const planOf = (kind, id, run = RUN) => ({ v: 1, host: "old-host", manifest: hex("1"), sha256: hex("2"), hoststore: hex("3"), sets: { [`${kind}-${id}`]: { run, snapshot: SNAP, tree: hex("4") } } });

/**
 * A fake launcher on a real tree. `script(op, cls, attempt)` returns an exit code (default 0); a non-zero restore-stage
 * leaves a partial attempt (some data, no marker), a non-zero fill-home moves the first file only. `calls` records every
 * argv; `onCall(args)` runs first (the test sees the record as it is at that moment).
 */
function world(kind, { script = () => 0, onCall = () => {} } = {}) {
  const base = mkdtempSync(join(tmpdir(), "sb-fill-"));
  const stage = join(base, "staging"), dir = join(base, "restore");
  const dests = {};
  for (const c of { agent: ["home", "sessions"], archive: ["archive"], tag: ["tag"] }[kind]) { dests[c] = join(base, "dest", c); mkdirSync(dests[c], { recursive: true }); }
  const calls = [], cleaned = [], discarded = [];
  const flag = (args, f) => args[args.indexOf(`--${f}`) + 1];
  const launch = async (args) => {
    calls.push(args);
    onCall(args);
    const [cmd] = args;
    const [run, owner, cls, attempt] = ["run", "owner", "class", "attempt"].map((f) => flag(args, f));
    const att = join(stage, run, owner, cls, attempt);
    const name = `${run}/${owner}/${cls}/${attempt}`;
    const code = script(cmd, cls, Number(attempt));
    const leaf = { home: "home", sessions: "sessions" }[cls] ?? owner.slice(2);
    if (cmd === "restore-stage") {
      if (existsSync(att)) return { code: EXIT.exists, stdout: "", stderr: "" };
      mkdirSync(join(att, "data", leaf), { recursive: true });
      const files = Object.entries(DATA[cls]);
      for (const [k, v] of code === 0 ? files : files.slice(0, 1)) writeFileSync(join(att, "data", leaf, k), v);
      if (code === 0) writeFileSync(join(att, ".complete"), name);
      return { code, stdout: "", stderr: "" };
    }
    if (cmd === "fill-home") {
      if (!existsSync(join(att, ".complete")) || readFileSync(join(att, ".complete"), "utf8") !== name) return { code: 73, stdout: "", stderr: "" };
      rmSync(join(att, ".complete"));
      assert.equal(flag(args, "source"), `data/${leaf}`);
      const src = join(att, "data", leaf);
      const names = readdirSync(src).sort();
      for (const k of code === 0 ? names : names.slice(0, 1)) renameSync(join(src, k), join(dests[cls], k));
      return { code, stdout: "", stderr: "" };
    }
    throw new Error(`unexpected launcher call ${cmd}`);
  };
  const identifyDest = async (k, id, cls) => ({ epoch: { boot_id: "00000000-0000-4000-8000-000000000000", mnt_id: 7 }, fsid: "0123456789abcdef", object: { type: "dir", mode: 0o700, uid: 70000, gid: 70000, dev: [8, 1], ino: statSync(dests[cls]).ino, gen: 1, mnt_id: 7, projid: 70000, inherit: true } });
  const expectOf = async (k, id, cls) => join(base, "expect", `${cls}.json`);
  const cleanDest = async (r) => { cleaned.push(r.attempt); for (const d of Object.values(dests)) for (const e of readdirSync(d)) rmSync(join(d, e)); };
  const discardStaging = async (r) => {
    discarded.push(r.attempt);
    if (!existsSync(stage)) return;
    for (const run of readdirSync(stage)) for (const owner of readdirSync(join(stage, run))) for (const cls of readdirSync(join(stage, run, owner))) {
      for (const n of readdirSync(join(stage, run, owner, cls))) if (r.state !== "staging" || run !== r.run || n !== String(r.attempt)) rmSync(join(stage, run, owner, cls, n), { recursive: true });
    }
  };
  const fill = restoreFiller({ launch, mount: "/srv/sagebrush", identifyDest, expectOf, projidOf: () => 70000, cleanDest, discardStaging, dir, root: stage });
  return { fill, calls, cleaned, discarded, dests, dir, stage, base };
}

test("classPaths: the class directory itself is restored, landing at data/<leaf> (A2 r3.5); outcomeOf: what each exit means", () => {
  const id = newId();
  assert.deepEqual(classPaths("agent", id, "home"), { path: `srv/sagebrush/agents/${id}/home`, source: "data/home" });
  assert.deepEqual(classPaths("agent", id, "sessions"), { path: `srv/sagebrush/agents/${id}/sessions`, source: "data/sessions" });
  assert.deepEqual(classPaths("archive", id, "archive"), { path: `srv/sagebrush/archive/${id}`, source: `data/${id}` });
  assert.deepEqual(classPaths("tag", id, "tag"), { path: `srv/sagebrush/tags/${id}`, source: `data/${id}` });
  for (const [k, c] of [["agent", "tag"], ["tag", "home"], ["archive", "home"], ["agent", "x"]]) assert.throws(() => classPaths(k, id, c), (e) => e.code === "bad_form");
  assert.throws(() => classPaths("agent", "nope", "home"), (e) => e.code === "bad_form");
  assert.deepEqual([0, 76, 77, 75, 74, 73, 72, 65, 64, 66, 1, -1].map(outcomeOf),
    ["ok", "not_fitting", "retry", "retry", "retry", "failed", "failed", "failed", "failed", "failed", "failed", "failed"]);
});

test("an agent restored: each class staged then filled, by exactly these launcher calls; filling written before the first fill", async () => {
  const id = newId();
  const seen = [];
  const w = world("agent", { onCall: (args) => { if (args[0] === "fill-home") seen.push(readRecord("agent", id, { dir: w.dir })?.state); } });
  const r = await w.fill("agent", id, planOf("agent", id));
  assert.deepEqual([r.state, r.attempt, r.dirty], ["published", 1, false]);
  assert.deepEqual(w.calls, [
    ["restore-stage", "--mount", "/srv/sagebrush", "--owner", `a-${id}`, "--class", "home", "--run", RUN, "--attempt", "1", "--projid", "70000", "--snapshot", SNAP, "--path", `srv/sagebrush/agents/${id}/home`],
    ["restore-stage", "--mount", "/srv/sagebrush", "--owner", `a-${id}`, "--class", "sessions", "--run", RUN, "--attempt", "1", "--projid", "70000", "--snapshot", SNAP, "--path", `srv/sagebrush/agents/${id}/sessions`],
    ["fill-home", "--mount", "/srv/sagebrush", "--owner", `a-${id}`, "--class", "home", "--run", RUN, "--attempt", "1", "--source", "data/home", "--expect", join(w.base, "expect", "home.json")],
    ["fill-home", "--mount", "/srv/sagebrush", "--owner", `a-${id}`, "--class", "sessions", "--run", RUN, "--attempt", "1", "--source", "data/sessions", "--expect", join(w.base, "expect", "sessions.json")],
  ]);
  assert.deepEqual(seen, ["filling", "filling"], "the record says filling before every fill-home");
  assert.deepEqual([tree(w.dests.home), tree(w.dests.sessions)], [DATA.home, DATA.sessions]);
  assert.deepEqual(r.dest.home, { dev: String(8 * 2 ** 20 + 1), ino: String(statSync(w.dests.home).ino) });
  // Settled: calling again does nothing more (validation is the next step's).
  const n = w.calls.length;
  assert.equal((await w.fill("agent", id, planOf("agent", id))).state, "published");
  assert.equal(w.calls.length, n);
});

test("an archive and a tag folder: one class each, the a- and t- owners", async () => {
  for (const kind of ["archive", "tag"]) {
    const id = newId();
    const w = world(kind);
    const r = await w.fill(kind, id, planOf(kind, id));
    assert.equal(r.state, "published", kind);
    assert.deepEqual(w.calls.map((a) => [a[0], a[4], a[6]]), [["restore-stage", `${kind === "tag" ? "t" : "a"}-${id}`, kind], ["fill-home", `${kind === "tag" ? "t" : "a"}-${id}`, kind]]);
    assert.deepEqual(tree(w.dests[kind]), DATA[kind]);
  }
});

test("a quota hit (76) is permanent: not_fitting, cleaned once if it hit in the fill, and never retried automatically", async () => {
  // In staging: stopped before any fill.
  let id = newId();
  let w = world("agent", { script: (op, cls) => (op === "restore-stage" && cls === "sessions" ? EXIT.quota : 0) });
  let r = await w.fill("agent", id, planOf("agent", id));
  assert.deepEqual([r.state, r.reason, r.dirty], ["not_fitting", "limit", false]);
  assert.equal(w.calls.filter((a) => a[0] === "fill-home").length, 0);
  // In the fill: the partial destination is cleaned, then it stops.
  id = newId();
  w = world("agent", { script: (op, cls) => (op === "fill-home" && cls === "sessions" ? EXIT.quota : 0) });
  r = await w.fill("agent", id, planOf("agent", id));
  assert.deepEqual([r.state, r.dirty], ["not_fitting", false], "cleaned");
  assert.deepEqual(w.cleaned, [1]);
  assert.deepEqual([tree(w.dests.home), tree(w.dests.sessions)], [{}, {}], "nothing published past the limit");
  assert.deepEqual(["home", "sessions"].map((c) => readdirSync(join(w.stage, RUN, `a-${id}`, c))), [[], []], "the consumed attempt is discarded with the cleanup");
  const n = w.calls.length;
  assert.equal((await w.fill("agent", id, planOf("agent", id))).state, "not_fitting");
  assert.equal(w.calls.length, n, "no launcher call: only the person's new request restarts it");
  // The person's new request (a new run, in the plan and the record): it runs again, from attempt 1, cleaning first.
  writeRecord(retryRecord(readRecord("agent", id, { dir: w.dir }), { run: RUN2, snapshot: SNAP }), { dir: w.dir });
  const again = await w.fill("agent", id, planOf("agent", id, RUN2));
  assert.deepEqual([again.run, again.attempt, again.state], [RUN2, 1, "not_fitting"], "the capacity is unchanged here, so it stops again");
  assert.ok(w.calls.slice(n).some((a) => a[0] === "restore-stage" && a.includes(RUN2)), "it was restaged under the new run");
});

test("out of space (77), a partial step (75) and an existing attempt (74) retry in a new attempt, in staging or in the fill", async () => {
  for (const code of [EXIT.no_space, EXIT.partial, EXIT.exists]) {
    for (const where of ["restore-stage", "fill-home"]) {
      const id = newId();
      const w = world("agent", { script: (op, cls, attempt) => (op === where && cls === "home" && attempt === 1 ? code : 0) });
      const r = await w.fill("agent", id, planOf("agent", id));
      assert.deepEqual([r.state, r.attempt], ["published", 2], `${code} in ${where}`);
      assert.deepEqual([tree(w.dests.home), tree(w.dests.sessions)], [DATA.home, DATA.sessions], `${code} in ${where}`);
      // Attempt 1 is never filled after attempt 2 began; a fill failure cleaned the destination before re-staging.
      const fills = w.calls.filter((a) => a[0] === "fill-home").map((a) => `${a[6]}:${a[10]}`);
      assert.equal(new Set(fills).size, fills.length, "no class filled twice from one attempt");
      if (where === "fill-home") assert.deepEqual(w.cleaned, [2], "the partial fill removed before the next attempt");
      // Only the attempt that was published is left: the first one is discarded whichever way it failed.
      assert.deepEqual(["home", "sessions"].map((c) => readdirSync(join(w.stage, RUN, `a-${id}`, c))), [["2"], ["2"]], `${code} in ${where}`);
    }
  }
});

test("any other exit stops the set as failed (outcome_unknown); automatic attempts stop at MAX_ATTEMPTS", async () => {
  for (const code of [73, 72, 70, 65, 64, 66]) {
    const id = newId();
    const w = world("agent", { script: (op) => (op === "restore-stage" ? code : 0) });
    const r = await w.fill("agent", id, planOf("agent", id));
    assert.deepEqual([r.state, r.reason], ["failed", "outcome_unknown"], String(code));
    const n = w.calls.length;
    await w.fill("agent", id, planOf("agent", id));
    assert.equal(w.calls.length, n, "a failed set isn't retried automatically");
  }
  const id = newId();
  const w = world("agent", { script: (op) => (op === "restore-stage" ? EXIT.partial : 0) });
  const r = await w.fill("agent", id, planOf("agent", id));
  assert.deepEqual([r.state, r.reason, r.attempt], ["failed", "outcome_unknown", MAX_ATTEMPTS]);
  assert.equal(w.calls.length, MAX_ATTEMPTS, "one staging call per attempt, then stopped");
});

test("a staged attempt without every marker exactly its name is never filled: a new attempt", async () => {
  const id = newId();
  const w = world("agent");
  // As a lying or interrupted launcher would leave it: both classes' data present, the sessions marker another attempt's.
  writeRecord({ v: 1, kind: "agent", id, run: RUN, snapshot: SNAP, attempt: 1, state: "staging", dest: null, dirty: false, reason: null }, { dir: w.dir });
  for (const cls of ["home", "sessions"]) {
    const att = join(w.stage, RUN, `a-${id}`, cls, "1");
    mkdirSync(join(att, "data", cls), { recursive: true });
    writeFileSync(join(att, ".complete"), cls === "home" ? `${RUN}/a-${id}/home/1` : `${RUN}/a-${id}/sessions/2`);
  }
  const r = await w.fill("agent", id, planOf("agent", id));
  assert.deepEqual([r.state, r.attempt], ["published", 2], "the torn attempt was retried");
  assert.ok(!w.calls.some((a) => a[0] === "fill-home" && a[10] === "1"), "never filled");
  // And a launcher that exits 0 but leaves a wrong marker: checked before the record steps to staged.
  const id2 = newId();
  const w2 = world("agent", { onCall: (args) => {
    if (args[0] === "fill-home") return;
    if (args[0] === "restore-stage" && args[6] === "sessions" && args[10] === "1") {
      // after the fake writes it, the launcher's marker is overwritten with another class's name
      queueMicrotask(() => writeFileSync(join(w2.stage, RUN, `a-${id2}`, "sessions", "1", ".complete"), `${RUN}/a-${id2}/home/1`));
    }
  } });
  const r2 = await w2.fill("agent", id2, planOf("agent", id2));
  assert.deepEqual([r2.state, r2.attempt], ["published", 2]);
  assert.ok(!w2.calls.some((a) => a[0] === "fill-home" && a[10] === "1"));
});

test("a crash after filling is written: the next call never refills that attempt; it cleans, re-stages and fills anew", async () => {
  const id = newId();
  let crash = true;
  const w = world("agent", { onCall: (args) => {
    if (args[0] === "fill-home" && args[6] === "sessions" && crash) { crash = false; throw Object.assign(new Error("killed"), { code: "EIO" }); }
  } });
  await assert.rejects(w.fill("agent", id, planOf("agent", id)), /killed/);
  assert.deepEqual([readRecord("agent", id, { dir: w.dir }).state, readRecord("agent", id, { dir: w.dir }).attempt], ["filling", 1]);
  const r = await w.fill("agent", id, planOf("agent", id));
  assert.deepEqual([r.state, r.attempt], ["published", 2]);
  assert.deepEqual(w.cleaned, [2], "the partly filled destination emptied first");
  const fills = w.calls.filter((a) => a[0] === "fill-home").map((a) => `${a[6]}:${a[10]}`);
  assert.deepEqual(fills, ["home:1", "sessions:1", "home:2", "sessions:2"]);
  assert.deepEqual([tree(w.dests.home), tree(w.dests.sessions)], [DATA.home, DATA.sessions]);
  // The consumed attempt 1 is discarded.
  assert.deepEqual(readdirSync(join(w.stage, RUN, `a-${id}`, "home")), ["2"]);
});

test("refusals: a set not in the plan, a record of another restore, missing adapters, an aborted call", async () => {
  const id = newId();
  const w = world("agent");
  await rejects(w.fill("agent", newId(), planOf("agent", id)), "not_found");
  writeRecord({ v: 1, kind: "agent", id, run: RUN2, snapshot: SNAP, attempt: 1, state: "staging", dest: null, dirty: false, reason: null }, { dir: w.dir });
  await rejects(w.fill("agent", id, planOf("agent", id)), "not_granted");
  const ac = new AbortController();
  ac.abort();
  await rejects(w.fill("tag", id, { ...planOf("tag", id) }, { signal: ac.signal }), "outcome_unknown");
  const ok = { launch: async () => ({ code: 0 }), mount: "/srv/sagebrush", identifyDest: async () => ({}), expectOf: async () => "x", projidOf: () => 1, cleanDest: async () => {}, discardStaging: async () => {} };
  for (const k of ["launch", "identifyDest", "expectOf", "projidOf", "cleanDest", "discardStaging"]) {
    assert.throws(() => restoreFiller({ ...ok, [k]: undefined }), (e) => e.code === "bad_form", k);
  }
  assert.throws(() => restoreFiller({ ...ok, mount: "srv" }), (e) => e.code === "bad_form");
  await rejects(w.fill("agent", id, { ...planOf("agent", id), v: 2 }), "bad_form");
});

test("ownersOf: from the restored registry; an agent's and an archive's uid, a tag's live members and gid", () => {
  const [a, b, c, dead, t, lonely] = [newId(), newId(), newId(), newId(), newId(), newId()];
  const registry = {
    v: 1, next_uid: 70010, next_gid: 80003,
    agents: {
      [a]: { uid: 70005, state: "running", life: 0, gen: 1, tags: [t], start_failed: null },
      [b]: { uid: 70001, state: "stopped", life: 0, gen: 1, tags: [t], start_failed: null },
      [c]: { uid: 70002, state: "revoked", life: 0, gen: 1, tags: [], start_failed: null },
      [dead]: { uid: 70003, state: "deleted", life: 1, gen: 1, tags: [t], start_failed: null },
    },
    tags: { [t]: { gid: 80001 }, [lonely]: { gid: 80002 } },
  };
  assert.deepEqual(ownersOf("agent", a, registry), { uids: [70005], gid: 70005, projid: 70005 });
  assert.deepEqual(ownersOf("archive", dead, registry), { uids: [70003], gid: 70003, projid: 70003 });
  assert.deepEqual(ownersOf("tag", t, registry), { uids: [70001, 70005], gid: 80001, projid: 80001 }, "live members only, sorted");
  for (const [kind, id, code] of [["agent", dead, "not_found"], ["archive", a, "not_found"], ["agent", newId(), "not_found"], ["tag", newId(), "not_found"], ["tag", lonely, "not_found"], ["agent", "nope", "bad_form"]]) {
    assert.throws(() => ownersOf(kind, id, registry), (e) => e.code === code, `${kind} ${id}`);
  }
  assert.throws(() => ownersOf("agent", a, { ...registry, extra: 1 }), (e) => e.code === "bad_form");
});

test("fillExpect: the launcher's identity of the destination plus the class's owners, a closed shape; writeExpectFile: durable and private", () => {
  const object = { type: "dir", mode: 0o700, uid: 70005, gid: 70005, dev: [8, 1], ino: 42, gen: 3, mnt_id: 7, projid: 70005, inherit: true };
  const identity = { epoch: { boot_id: "00000000-0000-4000-8000-000000000000", mnt_id: 7 }, fsid: "0123456789abcdef", object };
  const owners = { uids: [70005], gid: 70005, projid: 70005 };
  assert.deepEqual(fillExpect(identity, owners), { epoch: identity.epoch, fsid: identity.fsid, dest: object, uids: [70005], gid: 70005, projid: 70005 });
  assert.throws(() => fillExpect({ ...identity, extra: 1 }, owners), (e) => e.code === "bad_form");
  assert.throws(() => fillExpect({ ...identity, object: { ...object, dev: 2049 } }, owners), (e) => e.code === "bad_form");
  assert.throws(() => fillExpect({ ...identity, object: { ...object, type: "file" } }, owners), (e) => e.code === "not_granted");
  assert.throws(() => fillExpect({ ...identity, object: { ...object, projid: 70006 } }, owners), (e) => e.code === "not_granted");
  // The test seam: this process's uid and gid stand for root's (the real caller passes 0 and 0).
  const me = { rootUid: typeof process.getuid === "function" ? process.getuid() : -1, rootGid: typeof process.getgid === "function" ? process.getgid() : -1 };
  const dir = join(mkdtempSync(join(tmpdir(), "sb-expect-")), "expect");
  const id = newId();
  assert.throws(() => writeExpectFile(dir, `agent-${id}-home.json`, {}), (e) => e.code === "not_granted", "by default only root's directory");
  const p = writeExpectFile(dir, `agent-${id}-home.json`, fillExpect(identity, owners), me);
  assert.equal(p, join(dir, `agent-${id}-home.json`));
  assert.deepEqual(JSON.parse(readFileSync(p, "utf8")), fillExpect(identity, owners));
  assert.deepEqual([statSync(dir).mode & 0o777, statSync(p).mode & 0o777], [0o700, 0o600]);
  for (const name of ["x.json", `agent-${id}-home`, `../agent-${id}-home.json`, `agent-nope-home.json`]) assert.throws(() => writeExpectFile(dir, name, {}, me), (e) => e.code === "bad_form", name);
  // The directory: root's, its group root's, nobody else's mode, never a link.
  const open = join(mkdtempSync(join(tmpdir(), "sb-expect-")), "expect");
  mkdirSync(open, { mode: 0o755 });
  assert.throws(() => writeExpectFile(open, `agent-${id}-home.json`, {}, me), (e) => e.code === "not_granted", "a readable directory");
  assert.throws(() => writeExpectFile(dir, `agent-${id}-home.json`, {}, { ...me, rootUid: me.rootUid + 1 }), (e) => e.code === "not_granted", "another owner");
  assert.throws(() => writeExpectFile(dir, `agent-${id}-home.json`, {}, { ...me, rootGid: me.rootGid + 1 }), (e) => e.code === "not_granted", "another group");
  const linkDir = join(mkdtempSync(join(tmpdir(), "sb-expect-")), "expect");
  symlinkSync(dir, linkDir);
  assert.throws(() => writeExpectFile(linkDir, `agent-${id}-home.json`, {}, me), (e) => e.code === "not_granted", "a link to the directory");
  // A link planted at the name is replaced, never written through; the temp name is fresh and created exclusively.
  const outside = join(mkdtempSync(join(tmpdir(), "sb-outside-")), "victim");
  writeFileSync(outside, "untouched");
  symlinkSync(outside, join(dir, `agent-${id}-sessions.json`));
  const opened = [];
  writeExpectFile(dir, `agent-${id}-sessions.json`, { v: 1 }, { ...me, io: { ...realIo, open: (q, f, m) => { opened.push([q, f]); return realIo.open(q, f, m); } } });
  assert.equal(readFileSync(outside, "utf8"), "untouched");
  assert.ok(lstatSync(join(dir, `agent-${id}-sessions.json`)).isFile());
  assert.ok(opened.some(([q, f]) => f === "wx" && /\/\.agent-[a-z2-7]+-sessions\.json\.[0-9a-f]{16}\.tmp$/.test(q)), "an exclusive, fresh temp name");
  // A failed flush throws, and no temp file is left behind.
  const io = { ...realIo, fsync: () => { throw Object.assign(new Error("EIO"), { code: "EIO" }); } };
  assert.throws(() => writeExpectFile(dir, `agent-${id}-tag.json`, {}, { ...me, io }), (e) => e.code === "EIO");
  assert.deepEqual(readdirSync(dir).filter((n) => n.endsWith(".tmp")), []);
});
