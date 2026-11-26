// Host backup r3.3 §5 steps 7-8, T5, H2: the per-set fill driver, against a fake launcher that stages and fills on a
// real temporary tree exactly as A2 does (the class's data under <attempt>/data, the marker written last with the
// class's name; fill-home unlinks the marker first, then moves). Exit codes are scripted per call, so every branch
// runs: a quota hit stops as not_fitting, out of space and partial steps retry in a new attempt, anything else fails;
// filling is written before the first fill-home, and a filling record is never filled again. restore-stage writes a
// real §4b digest list beside the class and reports its hash; tree-digest lists the real destination; validation
// compares the two, so a published set settles as validated, and every tamper of the tree, the list or the reports fails.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, readlinkSync, renameSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "./host-linux-only.mjs";
import { FleetError, newId, refuse } from "../lib/fleet/index.mjs";
import { EXIT, classOwners, classPaths, destOf, fillExpect, outcomeOf, ownersOf, restoreFiller, writeExpectFile } from "../lib/fleet/host/restore-fill.mjs";
import { realIo } from "../lib/fleet/host/store.mjs";
import { STAGED, CLASSES, MAX_ATTEMPTS, newRecord, newRestoreRun, ownerOf, readFillReport, readRecord, retryRecord, writeRecord } from "../lib/fleet/host/restore-record.mjs";
import { copyKey, encodePath, quote } from "../lib/fleet/host/restore-validate.mjs";

const rejects = (p, code) => assert.rejects(p, (e) => e instanceof FleetError && e.code === code, code);
const RUN = newRestoreRun(1795500000000, () => Buffer.alloc(6)), RUN2 = newRestoreRun(1795600000000, () => Buffer.alloc(6));
const SNAP = "a".repeat(64);
const hex = (c) => c.repeat(64);
const DATA = { home: { "a.txt": "A", "b.txt": "BB" }, sessions: { "s.db": "SSS" }, archive: { "old.txt": "O" }, tag: { "shared.txt": "T" },
  // (A2 r3.13: an agent's config, staged only; a deleted agent's config archive, filled)
  config: { "current": "gen-1\n" }, "archive-config": { "gen-1.txt": "G" } };
const tree = (d) => (existsSync(d) ? Object.fromEntries(readdirSync(d).sort().map((k) => [k, readFileSync(join(d, k), "utf8")])) : null);

const sha = (b) => createHash("sha256").update(b).digest("hex");

/**
 * A real tree's §4b listing (as the binary writes data/digests.json, or, `observed`, as tree-digest lists): every entry
 * under `root` (not root itself), sorted by raw path bytes; EXPECTED modes with set-id cleared, OBSERVED as they are.
 */
function listing(root, { observed = false, copies = new Map() } = {}) {
  const out = [];
  const walk = (dir, rel) => {
    for (const nm of readdirSync(dir, { encoding: "buffer" })) {
      const raw = rel.length ? Buffer.concat([rel, Buffer.from("/"), nm]) : nm;
      const full = Buffer.concat([Buffer.isBuffer(dir) ? dir : Buffer.from(dir), Buffer.from("/"), nm]);
      const st = lstatSync(full);
      const mode = st.mode & (observed ? 0o7777 : 0o7777 & ~0o6000);
      if (st.isDirectory()) { out.push([raw, `{"path":${quote(encodePath(raw))},"type":"dir","size":0,"mode":${mode}}`, 0]); walk(full, raw); }
      else if (st.isSymbolicLink()) { const t = readlinkSync(full, { encoding: "buffer" }); out.push([raw, `{"path":${quote(encodePath(raw))},"type":"symlink","size":${t.length},"mode":511,"target":${quote(encodePath(t))}}`, 0]); }
      else if (st.isFile()) { const b = readFileSync(full); const c = copies.get(encodePath(raw)); out.push([raw, `{"path":${quote(encodePath(raw))},"type":"file","size":${b.length},"mode":${mode},"sha256":"${sha(b)}"${c ? `,"copy":"${c}"` : ""}}`, b.length]); }
      else out.push([raw, `{"unexpected":${quote(encodePath(raw))},"type":"fifo"}`, -1]);
    }
  };
  walk(root, Buffer.alloc(0));
  out.sort((a, b) => Buffer.compare(a[0], b[0]));
  const entries = out.filter((e) => e[2] >= 0);
  return `{"v":1}\n${out.map((e) => e[1] + "\n").join("")}{"count":${entries.length},"total_bytes":${entries.reduce((n, e) => n + e[2], 0)}}\n`;
}
/**
 * tree-digest's --copy-sqlite, on a real tree: every regular file starting "SQLite format 3\0" is copied into `dir` as
 * <h>.db, with its X-wal and X-journal siblings as <h>.db-wal and <h>.db-journal (h = copyKey of the main's path);
 * returns the copy names by encoded path, for the listing's `copy` keys. `skip(path)` leaves a copy out (a mutant).
 */
function copySqlite(root, dir, skip = () => false) {
  const names = new Map();
  const walk = (d, rel) => {
    for (const n of readdirSync(d).sort()) {
      const full = join(d, n), path = rel ? `${rel}/${n}` : n, st = lstatSync(full);
      if (st.isDirectory()) { walk(full, path); continue; }
      if (!st.isFile() || !readFileSync(full).subarray(0, 16).equals(Buffer.from("SQLite format 3\0", "latin1"))) continue;
      const h = copyKey(encodePath(Buffer.from(path)));
      for (const [x, name] of [["", `${h}.db`], ["-wal", `${h}.db-wal`], ["-journal", `${h}.db-journal`]]) {
        if (!existsSync(full + x) || skip(path + x)) continue;
        writeFileSync(join(dir, name), readFileSync(full + x), { flag: "wx", mode: 0o600 });
        names.set(path + x, name);
      }
    }
  };
  walk(root, "");
  return names;
}
const okStage = (digest) => `{"ok":true,"snapshot":"${SNAP}","skipped_special":0,"digests_sha256":"${digest}"}\n`;
const okFill = (report = {}) => JSON.stringify({ placed: { dirs: 0, files: 1, symlinks: 0 }, refused: [], unexpected: [], truncated: false, ...report }) + "\n";

const planOf = (kind, id, run = RUN) => ({ v: 1, host: "old-host", manifest: hex("1"), sha256: hex("2"), hoststore: hex("3"), sets: { [`${kind}-${id}`]: { run, snapshot: SNAP, tree: hex("4") } } });

/**
 * A fake launcher on a real tree. `script(op, cls, attempt)` returns an exit code (default 0); a non-zero restore-stage
 * leaves a partial attempt (some data, no marker), a non-zero fill-home moves the first file only. A successful
 * restore-stage writes data/digests.json (the class's real listing) and prints the closed success line with its hash;
 * fill-home prints its report (`report(cls)`, default nothing refused); tree-digest prints the destination's real
 * observed listing, or what `observe(cls, text)` makes of it. `stdout(op, cls, text)` may replace any success line.
 * `calls` records every argv; `onCall(args)` runs first (the test sees the record as it is at that moment).
 */
function world(kind, { script = () => 0, onCall = () => {}, failDiscards = 0, report = () => ({}), observe = (c, t) => t,
  stdout = (op, cls, t) => t, stopped = async () => true, unrestorable = () => [], beforeDigest = () => {}, seed = () => {},
  listOf = (c, t) => t, identify = (c, o) => o, skipCopy = () => false, afterCopy = () => {}, hooks = {} } = {}) {
  const base = mkdtempSync(join(tmpdir(), "sb-fill-"));
  const stage = join(base, "staging"), dir = join(base, "restore");
  const dests = {};
  for (const c of CLASSES[kind]) { dests[c] = join(base, "dest", c); mkdirSync(dests[c], { recursive: true }); }
  const calls = [], cleaned = [], discarded = [], copiesRemoved = [];
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
    if (cmd === "tree-digest") {
      assert.equal(args.includes("--copy-sqlite"), cls === "sessions");
      beforeDigest(cls, dests[cls]);
      if (code !== 0) return { code, stdout: "", stderr: "" };
      let copies = new Map();
      if (cls === "sessions") {
        const cdir = join(base, "copies", flag(args, "run"), owner);
        if (existsSync(cdir)) return { code: EXIT.exists, stdout: "", stderr: "" };
        mkdirSync(cdir, { recursive: true, mode: 0o700 });
        copies = copySqlite(dests[cls], cdir, skipCopy);
        afterCopy(cdir, copies);
      }
      return { code, stdout: observe(cls, listing(dests[cls], { observed: true, copies })), stderr: "" };
    }
    if (cmd === "restore-stage") {
      if (existsSync(att)) return { code: EXIT.exists, stdout: "", stderr: "" };
      mkdirSync(join(att, "data", leaf), { recursive: true });
      const files = Object.entries(DATA[cls]);
      for (const [k, v] of code === 0 ? files : files.slice(0, 1)) writeFileSync(join(att, "data", leaf, k), v);
      if (code !== 0) return { code, stdout: "", stderr: "" };
      seed(cls, join(att, "data", leaf));
      const list = listOf(cls, listing(join(att, "data", leaf)));
      writeFileSync(join(att, "data", "digests.json"), list);
      writeFileSync(join(att, ".complete"), name);
      return { code, stdout: stdout(cmd, cls, okStage(sha(list))), stderr: "" };
    }
    if (cmd === "fill-home") {
      if (!existsSync(join(att, ".complete")) || readFileSync(join(att, ".complete"), "utf8") !== name) return { code: 73, stdout: "", stderr: "" };
      rmSync(join(att, ".complete"));
      assert.equal(flag(args, "source"), `data/${leaf}`);
      const src = join(att, "data", leaf);
      // (names as bytes, as the launcher moves them: a name that isn't UTF-8 is moved as it is)
      const names = readdirSync(src, { encoding: "buffer" }).sort(Buffer.compare);
      const under = (d, k) => Buffer.concat([Buffer.from(d + "/"), k]);
      for (const k of code === 0 ? names : names.slice(0, 1)) renameSync(under(src, k), under(dests[cls], k));
      return { code, stdout: code === 0 ? stdout(cmd, cls, okFill(report(cls))) : "", stderr: "" };
    }
    throw new Error(`unexpected launcher call ${cmd}`);
  };
  const identifyDest = async (k, id, cls) => ((x) => ({ ...x, object: identify(cls, x.object) }))({ epoch: { boot_id: "00000000-0000-4000-8000-000000000000", mnt_id: 7 }, fsid: "0123456789abcdef", object: { type: "dir", mode: 0o700, uid: 70000, gid: 70000, dev: [8, 1], ino: statSync(dests[cls]).ino, gen: 1, mnt_id: 7, projid: 70000, inherit: true } });
  const expectOf = async (k, id, cls) => join(base, "expect", `${cls}.json`);
  const cleanDest = async (r) => { cleaned.push(r.attempt); for (const d of Object.values(dests)) for (const e of readdirSync(d, { encoding: "buffer" })) rmSync(Buffer.concat([Buffer.from(d + "/"), e]), { recursive: true }); };
  let discardFailures = failDiscards;
  const discardStaging = async (r) => {
    if (discardFailures > 0 && r.state !== "staging") { discardFailures -= 1; throw new Error("crash in discard"); }
    discarded.push(r.attempt);
    if (!existsSync(stage)) return;
    for (const run of readdirSync(stage)) for (const owner of readdirSync(join(stage, run))) for (const cls of readdirSync(join(stage, run, owner))) {
      for (const n of readdirSync(join(stage, run, owner, cls))) if (!["staging", "published"].includes(r.state) || run !== r.run || n !== String(r.attempt)) rmSync(join(stage, run, owner, cls, n), { recursive: true });
    }
  };
  const removeCopies = async (r) => { copiesRemoved.push(r.attempt); rmSync(join(base, "copies", r.run, ownerOf(r.kind, r.id)), { recursive: true, force: true }); };
  const fill = restoreFiller({ launch, mount: "/srv/sagebrush", identifyDest, expectOf, projidOf: () => 70000, cleanDest, discardStaging, dir, root: stage,
    stopped, unrestorableOf: (k, id, cls) => unrestorable(cls), removeCopies, copies: join(base, "copies"), ...hooks });
  return { fill, calls, cleaned, discarded, copiesRemoved, dests, dir, stage, base };
}

test("classPaths: the class directory itself is restored, landing at data/<leaf> (A2 r3.5); outcomeOf: what each exit means", () => {
  const id = newId();
  assert.deepEqual(classPaths("agent", id, "home"), { path: `srv/sagebrush/agents/${id}/home`, source: "data/home" });
  assert.deepEqual(classPaths("agent", id, "sessions"), { path: `srv/sagebrush/agents/${id}/sessions`, source: "data/sessions" });
  assert.deepEqual(classPaths("archive", id, "archive"), { path: `srv/sagebrush/archive/${id}`, source: `data/${id}` });
  assert.deepEqual(classPaths("tag", id, "tag"), { path: `srv/sagebrush/tags/${id}`, source: `data/${id}` });
  assert.deepEqual(classPaths("agent", id, "config"), { path: `srv/sagebrush/agent-config/${id}`, source: `data/${id}` });
  assert.deepEqual(classPaths("archive", id, "archive-config"), { path: `srv/sagebrush/archive-config/${id}`, source: `data/${id}` });
  for (const [k, c] of [["agent", "tag"], ["tag", "home"], ["archive", "home"], ["agent", "x"], ["agent", "archive-config"], ["archive", "config"], ["tag", "config"], ["tag", "archive-config"]]) assert.throws(() => classPaths(k, id, c), (e) => e.code === "bad_form");
  assert.throws(() => classPaths("agent", "nope", "home"), (e) => e.code === "bad_form");
  assert.deepEqual([0, 76, 77, 75, 74, 73, 72, 65, 64, 66, 1, -1].map(outcomeOf),
    ["ok", "not_fitting", "retry", "retry", "retry", "failed", "failed", "failed", "failed", "failed", "failed", "failed"]);
});

test("an agent restored: each class staged then filled, by exactly these launcher calls; filling written before the first fill", async () => {
  const id = newId();
  const seen = [];
  const w = world("agent", { onCall: (args) => { if (args[0] === "fill-home") seen.push(readRecord("agent", id, { dir: w.dir })?.state); } });
  const r = await w.fill("agent", id, planOf("agent", id));
  assert.deepEqual([r.state, r.attempt, r.dirty], ["files_validated", 1, false]);
  assert.deepEqual(w.calls, [
    ["restore-stage", "--mount", "/srv/sagebrush", "--owner", `a-${id}`, "--class", "home", "--run", RUN, "--attempt", "1", "--projid", "70000", "--snapshot", SNAP, "--path", `srv/sagebrush/agents/${id}/home`],
    ["restore-stage", "--mount", "/srv/sagebrush", "--owner", `a-${id}`, "--class", "sessions", "--run", RUN, "--attempt", "1", "--projid", "70000", "--snapshot", SNAP, "--path", `srv/sagebrush/agents/${id}/sessions`],
    // (A2 r3.13: the agent's config tree, staged for the config import, never filled or listed)
    ["restore-stage", "--mount", "/srv/sagebrush", "--owner", `a-${id}`, "--class", "config", "--run", RUN, "--attempt", "1", "--projid", "70000", "--snapshot", SNAP, "--path", `srv/sagebrush/agent-config/${id}`],
    ["fill-home", "--mount", "/srv/sagebrush", "--owner", `a-${id}`, "--class", "home", "--run", RUN, "--attempt", "1", "--source", "data/home", "--expect", join(w.base, "expect", "home.json")],
    ["fill-home", "--mount", "/srv/sagebrush", "--owner", `a-${id}`, "--class", "sessions", "--run", RUN, "--attempt", "1", "--source", "data/sessions", "--expect", join(w.base, "expect", "sessions.json")],
    ["tree-digest", "--mount", "/srv/sagebrush", "--owner", `a-${id}`, "--class", "home", "--expect", join(w.base, "expect", "home.json")],
    ["tree-digest", "--mount", "/srv/sagebrush", "--owner", `a-${id}`, "--class", "sessions", "--expect", join(w.base, "expect", "sessions.json"), "--copy-sqlite", "--run", RUN],
  ]);
  assert.deepEqual(seen, ["filling", "filling"], "the record says filling before every fill-home");
  assert.deepEqual([tree(w.dests.home), tree(w.dests.sessions)], [DATA.home, DATA.sessions]);
  assert.deepEqual(r.dest.home, { dev: String(8 * 2 ** 20 + 1), ino: String(statSync(w.dests.home).ino), uid: 70000, gid: 70000, mode: 0o700, projid: 70000 });
  // Settled: calling again does nothing more.
  const n = w.calls.length;
  assert.equal((await w.fill("agent", id, planOf("agent", id))).state, "files_validated");
  assert.equal(w.calls.length, n);
});

test("the destination is bound, durably, BEFORE the first effect: every class's identity in the record before any launch", async () => {
  const id = newId();
  const atFirst = [];
  const w = world("agent", { onCall: (args) => { if (atFirst.length === 0) atFirst.push(readRecord("agent", id, { dir: w.dir })); } });
  const r = await w.fill("agent", id, planOf("agent", id));
  assert.equal(r.state, "files_validated");
  const [first] = atFirst;
  assert.equal(w.calls[0][0], "restore-stage");
  assert.deepEqual([first.state, first.attempt, first.digests], ["staging", 1, null], "read back from disk at the first launch");
  for (const cls of ["home", "sessions"]) {
    assert.deepEqual(first.dest[cls], { dev: String(8 * 2 ** 20 + 1), ino: String(statSync(w.dests[cls]).ino), uid: 70000, gid: 70000, mode: 0o700, projid: 70000 }, cls);
  }
  assert.deepEqual(r.dest, first.dest, "the bound destination never changes");
  // An agent's files validated is settled for this driver: calling again never writes validated (its imports aren't done).
  const n = w.calls.length;
  assert.equal((await w.fill("agent", id, planOf("agent", id))).state, "files_validated");
  assert.equal(w.calls.length, n);
  assert.equal(readRecord("agent", id, { dir: w.dir }).state, "files_validated");
});

test("a crash between the record and its bind: the next call binds first, then stages", async () => {
  const id = newId();
  const seen = [];
  const w = world("agent", { onCall: () => { if (seen.length === 0) seen.push(readRecord("agent", id, { dir: w.dir })); } });
  writeRecord(newRecord({ kind: "agent", id, run: RUN, snapshot: SNAP }), { dir: w.dir }); // the crash: created, never bound
  const r = await w.fill("agent", id, planOf("agent", id));
  assert.equal(r.state, "files_validated");
  assert.deepEqual([seen[0].state, seen[0].attempt], ["staging", 1], "the same record, attempt 1: an unbound record isn't a crashed attempt");
  assert.notEqual(seen[0].dest, null, "bound before the first launch");
  assert.deepEqual(w.calls.map((a) => a[0]).slice(0, 2), ["restore-stage", "restore-stage"]);
});

test("a destination that is no longer the bound one when filling starts fails the set: nothing is moved into it", async () => {
  for (const field of ["ino", "uid", "gid", "mode", "projid"]) {
    const id = newId();
    let staged = false;
    const w = world("agent", {
      onCall: (args) => { if (args[0] === "restore-stage") staged = true; },
      // After staging (the bind came before it), home's identity changes in one field: replaced, re-owned, re-moded.
      identify: (cls, o) => (staged && cls === "home" ? { ...o, [field]: field === "ino" ? o.ino + 1 : field === "mode" ? 0o755 : o[field] + 1 } : o),
    });
    const r = await w.fill("agent", id, planOf("agent", id));
    assert.deepEqual([r.state, r.reason], ["failed", "outcome_unknown"], field);
    assert.ok(!w.calls.some((a) => a[0] === "fill-home"), `${field}: no fill-home`);
    assert.deepEqual([tree(w.dests.home), tree(w.dests.sessions)], [{}, {}], `${field}: both destinations untouched`);
    assert.equal(r.dirty, false, `${field}: never filling, so nothing to clean`);
  }
});

test("an archive (its tree and its config archive) and a tag folder (one class), the a- and t- owners", async () => {
  for (const kind of ["archive", "tag"]) {
    const id = newId();
    const w = world(kind);
    const r = await w.fill(kind, id, planOf(kind, id));
    assert.equal(r.state, "validated", kind, "no imports: its files validated is the set validated");
    const o = `${kind === "tag" ? "t" : "a"}-${id}`;
    const classes = CLASSES[kind];
    assert.deepEqual(w.calls.map((a) => [a[0], a[4], a[6]]), ["restore-stage", "fill-home", "tree-digest"].flatMap((op) => classes.map((c) => [op, o, c])));
    for (const c of classes) assert.deepEqual(tree(w.dests[c]), DATA[c], c);
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
      assert.deepEqual([r.state, r.attempt], ["files_validated", 2], `${code} in ${where}`);
      assert.deepEqual([tree(w.dests.home), tree(w.dests.sessions)], [DATA.home, DATA.sessions], `${code} in ${where}`);
      // Attempt 1 is never filled after attempt 2 began; a fill failure cleaned the destination before re-staging.
      const fills = w.calls.filter((a) => a[0] === "fill-home").map((a) => `${a[6]}:${a[10]}`);
      assert.equal(new Set(fills).size, fills.length, "no class filled twice from one attempt");
      if (where === "fill-home") assert.deepEqual(w.cleaned, [2], "the partial fill removed before the next attempt");
      // Nothing is left: the first attempt is discarded whichever way it failed, the filled one once it is validated.
      assert.deepEqual(["home", "sessions"].map((c) => readdirSync(join(w.stage, RUN, `a-${id}`, c))), [[], []], `${code} in ${where}`);
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
  writeRecord({ v: 1, kind: "agent", id, run: RUN, snapshot: SNAP, attempt: 1, state: "staging", dest: null, digests: null, dirty: false, reason: null, imports: { config: { state: "none" }, context: { state: "none" } } }, { dir: w.dir });
  for (const cls of ["home", "sessions"]) {
    const att = join(w.stage, RUN, `a-${id}`, cls, "1");
    mkdirSync(join(att, "data", cls), { recursive: true });
    writeFileSync(join(att, ".complete"), cls === "home" ? `${RUN}/a-${id}/home/1` : `${RUN}/a-${id}/sessions/2`);
  }
  const r = await w.fill("agent", id, planOf("agent", id));
  assert.deepEqual([r.state, r.attempt], ["files_validated", 2], "the torn attempt was retried");
  // Only the stage-only config's attempt begun (no marker anywhere): begun all the same, so a new attempt, never a
  // stage over attempt 1.
  const id3 = newId();
  const w3 = world("agent");
  writeRecord({ v: 1, kind: "agent", id: id3, run: RUN, snapshot: SNAP, attempt: 1, state: "staging", dest: null, digests: null, dirty: false, reason: null, imports: { config: { state: "none" }, context: { state: "none" } } }, { dir: w3.dir });
  mkdirSync(join(w3.stage, RUN, `a-${id3}`, "config", "1", "data"), { recursive: true });
  const r3 = await w3.fill("agent", id3, planOf("agent", id3));
  assert.deepEqual([r3.state, r3.attempt], ["files_validated", 2]);
  assert.ok(!w3.calls.some((a) => a[0] === "restore-stage" && a[10] === "1"), "nothing staged in the begun attempt");
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
  assert.deepEqual([r2.state, r2.attempt], ["files_validated", 2]);
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
  assert.deepEqual([r.state, r.attempt], ["files_validated", 2]);
  assert.deepEqual(w.cleaned, [2], "the partly filled destination emptied first");
  const fills = w.calls.filter((a) => a[0] === "fill-home").map((a) => `${a[6]}:${a[10]}`);
  assert.deepEqual(fills, ["home:1", "sessions:1", "home:2", "sessions:2"]);
  assert.deepEqual([tree(w.dests.home), tree(w.dests.sessions)], [DATA.home, DATA.sessions]);
  // The consumed attempt 1 is discarded, and so is attempt 2 once the set is validated.
  assert.deepEqual(readdirSync(join(w.stage, RUN, `a-${id}`, "home")), []);
});

test("the caller's admission at the bind: a refusal records no destination and launches nothing", async () => {
  const id = newId();
  const seen = [];
  const w = world("agent", { hooks: { admit: async (r, ids, dest) => { seen.push([r.state, r.dest, Object.keys(ids), dest.home.ino]); refuse("not_granted", "not the provisioned destination"); } } });
  await rejects(w.fill("agent", id, planOf("agent", id)), "not_granted");
  assert.deepEqual(seen, [["staging", null, ["home", "sessions"], String(statSync(w.dests.home).ino)]], "asked once, with every class's identity, before the bind");
  const r = readRecord("agent", id, { dir: w.dir });
  assert.deepEqual([r.state, r.dest, r.attempt], ["staging", null, 1], "nothing bound");
  assert.deepEqual(w.calls, [], "nothing launched");
  assert.deepEqual([tree(w.dests.home), tree(w.dests.sessions)], [{}, {}]);
});

test("the caller's veto before an archive's or a tag folder's validated: the set stays files_validated, nothing published", async () => {
  for (const kind of ["archive", "tag"]) {
    const id = newId();
    let vetoed = true;
    const asked = [];
    const w = world(kind, { hooks: { veto: async (r) => { asked.push(r.state); return vetoed; } } });
    await rejects(w.fill(kind, id, planOf(kind, id)), "not_granted");
    assert.deepEqual(asked, ["files_validated"], kind);
    assert.equal(readRecord(kind, id, { dir: w.dir }).state, "files_validated", kind);
    vetoed = false;
    assert.equal((await w.fill(kind, id, planOf(kind, id))).state, "validated", `${kind}: without the intent it completes`);
  }
});

test("an agent's files_validated is never vetoed here: its validated is its imports'", async () => {
  const id = newId();
  let asked = 0;
  const w = world("agent", { hooks: { veto: async () => { asked += 1; return true; } } });
  assert.equal((await w.fill("agent", id, planOf("agent", id))).state, "files_validated");
  assert.equal(asked, 0);
});

test("refusals: a set not in the plan, a record of another restore, missing adapters, an aborted call", async () => {
  const id = newId();
  const w = world("agent");
  await rejects(w.fill("agent", newId(), planOf("agent", id)), "not_found");
  writeRecord({ v: 1, kind: "agent", id, run: RUN2, snapshot: SNAP, attempt: 1, state: "staging", dest: null, digests: null, dirty: false, reason: null, imports: { config: { state: "none" }, context: { state: "none" } } }, { dir: w.dir });
  await rejects(w.fill("agent", id, planOf("agent", id)), "not_granted");
  const ac = new AbortController();
  ac.abort();
  await rejects(w.fill("tag", id, { ...planOf("tag", id) }, { signal: ac.signal }), "outcome_unknown");
  const ok = { launch: async () => ({ code: 0 }), mount: "/srv/sagebrush", identifyDest: async () => ({}), expectOf: async () => "x", projidOf: () => 1, cleanDest: async () => {}, discardStaging: async () => {},
    stopped: async () => true, unrestorableOf: () => [], removeCopies: async () => {} };
  for (const k of ["launch", "identifyDest", "expectOf", "projidOf", "cleanDest", "discardStaging", "stopped", "unrestorableOf", "removeCopies"]) {
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
  // A class's owners: root alone for an agent's config and an archive's config archive, in the set's project.
  assert.deepEqual(classOwners("agent", a, "config", registry), { uids: [0], gid: 0, projid: 70005 });
  assert.deepEqual(classOwners("archive", dead, "archive-config", registry), { uids: [0], gid: 0, projid: 70003 });
  for (const cls of ["home", "sessions"]) assert.deepEqual(classOwners("agent", a, cls, registry), ownersOf("agent", a, registry));
  assert.deepEqual(classOwners("archive", dead, "archive", registry), ownersOf("archive", dead, registry));
  assert.deepEqual(classOwners("tag", t, "tag", registry), ownersOf("tag", t, registry));
  assert.throws(() => classOwners("agent", dead, "config", registry), (e) => e.code === "not_found", "the set's owner still has to be known");
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
  assert.throws(() => fillExpect({ ...identity, object: { ...object, inherit: false } }, owners), (e) => e.code === "not_granted", "no inherit flag");
  // destOf pins the device encoding: [major, minor] as major * 2^20 + minor.
  assert.deepEqual(destOf({ ...object, dev: [8, 1], ino: 42 }), { dev: "8388609", ino: "42", uid: 70005, gid: 70005, mode: 0o700, projid: 70005 });
  assert.deepEqual(destOf({ ...object, dev: [259, 3], ino: 7 }), { dev: String(259 * 1048576 + 3), ino: "7", uid: 70005, gid: 70005, mode: 0o700, projid: 70005 });
  // Permission bits only (the type bits never), and the owner, group and project as identified.
  assert.equal(destOf({ ...object, mode: 0o40755 }).mode, 0o755);
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

test("a stop discards the set's staging before it is reported: nothing stays charged (a quota hit in staging, a failure)", async () => {
  for (const [code, state] of [[EXIT.quota, "not_fitting"], [73, "failed"]]) {
    const id = newId();
    const w = world("agent", { script: (op, cls) => (op === "restore-stage" && cls === "sessions" ? code : 0) });
    const r = await w.fill("agent", id, planOf("agent", id));
    assert.equal(r.state, state);
    for (const cls of ["home", "sessions"]) {
      assert.equal(existsSync(join(w.stage, RUN, `a-${id}`, cls, "1")), false, `${state}: ${cls}'s attempt (complete or partial) discarded`);
    }
    assert.equal(w.calls.filter((a) => a[0] === "fill-home").length, 0);
  }
});

test("a stopped set's next call only discards what a crash left; it never restages or refills", async () => {
  // Every stage of attempt 1 hits the quota; the first discard after the stop dies (a crash right after the stop's write).
  const id = newId();
  const w = world("agent", { script: () => EXIT.quota, failDiscards: 1 });
  await assert.rejects(w.fill("agent", id, planOf("agent", id)), /crash in discard/);
  assert.equal(readRecord("agent", id, { dir: w.dir }).state, "not_fitting", "the stop was written first");
  assert.ok(existsSync(join(w.stage, RUN, `a-${id}`, "home", "1")), "its staging survived the crash");
  const before = w.calls.length;
  const r = await w.fill("agent", id, planOf("agent", id));
  assert.equal(r.state, "not_fitting");
  assert.equal(w.calls.length, before, "no restore-stage, no fill-home");
  assert.equal(existsSync(join(w.stage, RUN, `a-${id}`, "home", "1")), false, "the leftover is discarded now");
  // And again: idempotent, still nothing staged.
  assert.equal((await w.fill("agent", id, planOf("agent", id))).state, "not_fitting");
  assert.equal(w.calls.length, before);
});

test("a validated set's consumed staging is discarded only after validated is durable, on every call, a crash repaired", async () => {
  const id = newId();
  const w = world("agent");
  const r = await w.fill("agent", id, planOf("agent", id));
  assert.equal(r.state, "files_validated");
  // The staged copies (directories, symlinks, the emptied data) don't stay charged: nothing of the set is left.
  for (const cls of ["home", "sessions"]) assert.deepEqual(readdirSync(join(w.stage, RUN, `a-${id}`, cls)), [], cls);
  // A crash in that discard: the next call repairs it, with no launcher call.
  const id2 = newId();
  const w2 = world("agent", { failDiscards: 1 });
  await assert.rejects(w2.fill("agent", id2, planOf("agent", id2)), /crash in discard/);
  assert.equal(readRecord("agent", id2, { dir: w2.dir }).state, "files_validated");
  assert.ok(existsSync(join(w2.stage, RUN, `a-${id2}`, "home", "1")), "left by the crash");
  const n = w2.calls.length;
  assert.equal((await w2.fill("agent", id2, planOf("agent", id2))).state, "files_validated");
  assert.equal(w2.calls.length, n, "no launcher call");
  assert.equal(existsSync(join(w2.stage, RUN, `a-${id2}`, "home", "1")), false, "discarded now");
});

test("a new attempt is staged only after every earlier one is discarded: two attempts are never charged at once", async () => {
  const id = newId();
  const seen = [];
  const w = world("agent", {
    script: (op, cls, attempt) => (op === "restore-stage" && cls === "home" && attempt === 1 ? EXIT.partial : 0),
    onCall: (args) => {
      if (args[0] === "restore-stage" && args[10] === "2") {
        seen.push(STAGED.agent.map((c) => existsSync(join(w.stage, RUN, `a-${id}`, c, "1"))));
      }
    },
  });
  const r = await w.fill("agent", id, planOf("agent", id));
  assert.deepEqual([r.state, r.attempt], ["files_validated", 2]);
  assert.deepEqual(seen, STAGED.agent.map(() => STAGED.agent.map(() => false)), "attempt 1's partial staging is gone before attempt 2 stages any class");
});

// ---- validation (A2 r3.8.3 / r3.9 §4a, §4b): the digest list bound by its recorded hash, the filled tree listed by
// tree-digest, the compare less exactly fill's refused and the manifest's unrestorable entries, the SQLite copies.

/** One agent set through validation, with `opts` for the world. Returns the world, the record and the id. */
async function settle(opts = {}) {
  const id = newId();
  const w = world("agent", opts);
  const r = await w.fill("agent", id, planOf("agent", id));
  return { w, r, id };
}
const attemptDir = (w, id, cls, attempt = 1) => join(w.stage, RUN, `a-${id}`, cls, String(attempt));
const failedAs = async (opts, reason, what) => {
  const { w, r, id } = await settle(opts);
  assert.deepEqual([r.state, r.reason], ["failed", reason], what);
  assert.equal(w.calls.filter((a) => a[0] === "restore-stage").length, STAGED.agent.length, `${what}: never re-staged`);
  // A failed validation stays failed: the next call makes no launcher call, and the attempt is discarded.
  const n = w.calls.length;
  assert.equal((await w.fill("agent", id, planOf("agent", id))).state, "failed", what);
  assert.equal(w.calls.length, n, `${what}: nothing retried automatically`);
  assert.equal(existsSync(attemptDir(w, id, "home")), false, `${what}: the attempt is discarded once the stop is written`);
  return { w, r, id };
};

test("validation: each class's hash is recorded as it stages, then the filled tree is the list's, and only then validated", async () => {
  const seen = [];
  const id = newId();
  const w = world("agent", { onCall: (args) => { if (args[0] === "tree-digest") seen.push(readRecord("agent", id, { dir: w.dir })); } });
  const r = await w.fill("agent", id, planOf("agent", id));
  assert.equal(r.state, "files_validated");
  // The record held both hashes from staging on, each the hash of the list the class's restore-stage wrote.
  assert.deepEqual(Object.keys(r.digests), ["home", "sessions"]);
  for (const cls of ["home", "sessions"]) assert.match(r.digests[cls], /^[0-9a-f]{64}$/);
  assert.notEqual(r.digests.home, r.digests.sessions);
  // tree-digest ran while the record was published, with the attempt (and its lists) still staged.
  assert.deepEqual(seen.map((x) => x.state), ["published", "published"]);
  // The fill reports were saved for the attempt; validated is durable before the attempt is discarded.
  assert.deepEqual(readFillReport(r, "home", { dir: w.dir }), { v: 1, run: RUN, attempt: 1, cls: "home", refused: [], unexpected: [], truncated: false });
  assert.equal(readRecord("agent", id, { dir: w.dir }).state, "files_validated");
  assert.equal(existsSync(attemptDir(w, id, "home")), false);
  // The sessions listing's copy directory is fresh each run and removed after it.
  assert.deepEqual(w.copiesRemoved, [1, 1]);
  assert.equal(existsSync(join(w.base, "copies", RUN, `a-${id}`)), false);
});

test("validation: a changed filled tree fails: a same-size byte change, missing, extra, type, size, mode, set-id, link target", async () => {
  const seed = (cls, d) => { if (cls === "home") { symlinkSync("a.txt", join(d, "ln")); mkdirSync(join(d, "sub")); writeFileSync(join(d, "sub", "c.txt"), "C"); } };
  const ok = await settle({ seed });
  assert.equal(ok.r.state, "files_validated", "the seeded tree validates as filled");
  const rows = {
    "a same-size byte change": (d) => writeFileSync(join(d, "a.txt"), "Z"),
    "a missing file": (d) => rmSync(join(d, "b.txt")),
    "a missing directory": (d) => rmSync(join(d, "sub"), { recursive: true }),
    "an extra file": (d) => writeFileSync(join(d, "extra"), ""),
    "an extra empty directory": (d) => mkdirSync(join(d, "more")),
    "a file turned into a directory": (d) => { rmSync(join(d, "a.txt")); mkdirSync(join(d, "a.txt")); },
    "a size change": (d) => writeFileSync(join(d, "b.txt"), "BBB"),
    "a mode change": (d) => chmodSync(join(d, "a.txt"), 0o600),
    "a set-id bit fill failed to strip": (d) => chmodSync(join(d, "a.txt"), 0o2644),
    "a directory's mode": (d) => chmodSync(join(d, "sub"), 0o700),
    "a link's target": (d) => { rmSync(join(d, "ln")); symlinkSync("b.txt", join(d, "ln")); },
    "a link replaced by its target's copy": (d) => { rmSync(join(d, "ln")); writeFileSync(join(d, "ln"), "A"); },
  };
  for (const [what, change] of Object.entries(rows)) {
    await failedAs({ seed, beforeDigest: (cls, d) => { if (cls === "home") change(d); } }, "bad_form", what);
  }
  // A special file or a mount in the destination is an `unexpected` line: failed, whatever else matches.
  const special = (cls, t) => (cls === "home" ? t.replace(/\{"count"/, '{"unexpected":"zz","type":"fifo"}\n{"count"') : t);
  await failedAs({ observe: special }, "bad_form", "an unexpected entry");
});

test("validation: the digest list is used only when its bytes hash to the recorded value; a missing one is not_found", async () => {
  const list = (w, id, cls) => join(attemptDir(w, id, cls), "data", "digests.json");
  let ref;
  // (after the last fill-home, before validation reads the lists)
  const tamper = (f) => ({ onCall: (args) => { if (args[0] === "fill-home" && args[6] === "sessions") f(list(ref.w, ref.id, "home")); } });
  const rows = {
    "a byte changed": (p) => { const b = readFileSync(p); b[b.length - 3] ^= 1; writeFileSync(p, b); },
    "truncated": (p) => writeFileSync(p, readFileSync(p).subarray(0, 20)),
    "a well-formed substitute (the list of another tree)": (p) => writeFileSync(p, '{"v":1}\n{"count":0,"total_bytes":0}\n'),
    "an extra line appended": (p) => writeFileSync(p, Buffer.concat([readFileSync(p), Buffer.from("\n")])),
    // The tree changed after the fill AND the list replaced by the changed tree's own exact listing: well-formed and
    // matching, so only the recorded hash catches it.
    "a matching substitute for a changed tree": (p) => { writeFileSync(join(ref.w.dests.home, "a.txt"), "Z"); writeFileSync(p, listing(ref.w.dests.home)); },
  };
  for (const [what, f] of Object.entries(rows)) {
    const id = newId();
    const w = world("agent", tamper(f));
    ref = { w, id };
    const r = await w.fill("agent", id, planOf("agent", id));
    assert.deepEqual([r.state, r.reason], ["failed", "bad_form"], what);
  }
  const id = newId();
  const w = world("agent", tamper((p) => rmSync(p)));
  ref = { w, id };
  const r = await w.fill("agent", id, planOf("agent", id));
  assert.deepEqual([r.state, r.reason], ["failed", "not_found"], "a missing list");
  // A link planted in its place is never followed.
  const id2 = newId();
  const w2 = world("agent", tamper((p) => { const real = p + ".real"; renameSync(p, real); symlinkSync(real, p); }));
  ref = { w: w2, id: id2 };
  const linked = await w2.fill("agent", id2, planOf("agent", id2));
  assert.deepEqual([linked.state, linked.reason], ["failed", "bad_form"], "a link is never a list: a durable stop");
  assert.equal(readRecord("agent", id2, { dir: w2.dir }).state, "failed");
  const n2 = w2.calls.length;
  assert.equal((await w2.fill("agent", id2, planOf("agent", id2))).state, "failed");
  assert.equal(w2.calls.length, n2, "no launch, no revalidation, no re-stage after it");
});

test("validation: a malformed list fails even when the binary reported its exact hash (the format, not only the binding)", async () => {
  const lines = (t) => t.split("\n").slice(0, -1);
  const rows = {
    "a duplicate path": (t) => { const l = lines(t); l.splice(2, 0, l[1]); return l.join("\n") + "\n"; },
    "an extra field": (t) => t.replace('"type":"file"', '"type":"file","x":1'),
    "the count off by one": (t) => t.replace(/"count":(\d+)/, (m, n) => `"count":${Number(n) + 1}`),
    "the total off by one": (t) => t.replace(/"total_bytes":(\d+)/, (m, n) => `"total_bytes":${Number(n) + 1}`),
    "no trailer": (t) => lines(t).slice(0, -1).join("\n") + "\n",
    "no header": (t) => lines(t).slice(1).join("\n") + "\n",
    "out of order": (t) => { const l = lines(t); [l[1], l[2]] = [l[2], l[1]]; return l.join("\n") + "\n"; },
    "a set-id mode in the expected list": (t) => t.replace(/"mode":420/, '"mode":2468'),
    "a blank line": (t) => t.replace("\n", "\n\n"),
    "JSON.stringify's quoting": (t) => t.replace('"a.txt"', '"a\\u002etxt"'),
    "an observed-only key": (t) => t.replace(/("sha256":"[0-9a-f]{64}")/, '$1,"copy":"x.db"'),
  };
  for (const [what, f] of Object.entries(rows)) {
    await failedAs({ listOf: (cls, t) => (cls === "home" ? f(t) : t) }, "bad_form", what);
  }
});

test("validation subtracts exactly the manifest's unrestorable entries and fill's refused subtrees; nothing else is excused", async () => {
  // The manifest's unrestorable b.txt, absent after the fill: validated. Another omission besides it: failed.
  const gone = (...names) => (cls, d) => { if (cls === "home") for (const n of names) rmSync(join(d, n), { recursive: true }); };
  assert.equal((await settle({ unrestorable: (c) => (c === "home" ? ["b.txt"] : []), beforeDigest: gone("b.txt") })).r.state, "files_validated");
  await failedAs({ unrestorable: (c) => (c === "home" ? ["b.txt"] : []), beforeDigest: gone("b.txt", "a.txt") }, "bad_form", "an additional omission");
  await failedAs({ unrestorable: (c) => (c === "home" ? ["b.txt"] : []) }, "bad_form", "an unrestorable entry that is present anyway");
  await failedAs({ unrestorable: (c) => (c === "home" ? ["nope"] : []) }, "bad_form", "an unrestorable path the list doesn't hold");
  // fill refused a directory (another owner's) with 2 files: entries 3, the directory itself included (A2 r3.9).
  const seed = (cls, d) => { if (cls === "home") { mkdirSync(join(d, "x%é")); writeFileSync(join(d, "x%é", "1"), "1"); writeFileSync(join(d, "x%é", "2"), "2"); } };
  const refusedDir = (entries, path = "x%25é") => ({ seed, beforeDigest: gone("x%é"), report: (c) => (c === "home" ? { refused: [{ path, uid: 0, gid: 0, entries }] } : {}) });
  assert.equal((await settle(refusedDir(3))).r.state, "files_validated", "the refused subtree, by its encoded path");
  for (const n of [2, 4, 0]) await failedAs(refusedDir(n), "bad_form", `a refused directory counted ${n}`);
  // A refused path not in the codec's form ("%" unencoded): fill's line isn't the closed shape, so every attempt is
  // unusable, and the set fails once they are spent; never validated.
  const raw = await settle(refusedDir(3, "x%é"));
  assert.deepEqual([raw.r.state, raw.r.reason, raw.r.attempt], ["failed", "outcome_unknown", MAX_ATTEMPTS]);
  // The subtree is matched on path + "/": a neighbour sharing the prefix ("x%é2", "x%é.txt") is not excused.
  const neighbours = (cls, d) => { seed(cls, d); if (cls === "home") { writeFileSync(join(d, "x%é2"), "n"); writeFileSync(join(d, "x%é.txt"), "n"); } };
  assert.equal((await settle({ ...refusedDir(3), seed: neighbours })).r.state, "files_validated", "the neighbours stay, compared as placed");
  await failedAs({ ...refusedDir(3), seed: neighbours, beforeDigest: gone("x%é", "x%é2") }, "bad_form", "a neighbour missing is not excused");
  // A refused empty directory is entries 1.
  const empty = (entries) => ({ seed: (c, d) => { if (c === "home") mkdirSync(join(d, "e")); }, beforeDigest: gone("e"), report: (c) => (c === "home" ? { refused: [{ path: "e", uid: 0, gid: 0, entries }] } : {}) });
  assert.equal((await settle(empty(1))).r.state, "files_validated");
  await failedAs(empty(0), "bad_form", "a refused empty directory counted 0");
  // Exactly 1000 refused entries (the report's bound) still validate; 1001 can't be reported (the line row, below).
  const many = Array.from({ length: 1000 }, (_, i) => `r${String(i).padStart(4, "0")}`);
  const thousand = await settle({
    seed: (c, d) => { if (c === "home") for (const n of many) writeFileSync(join(d, n), ""); },
    beforeDigest: (c, d) => { if (c === "home") for (const n of many) rmSync(join(d, n)); },
    report: (c) => (c === "home" ? { refused: many.map((path) => ({ path, uid: 0, gid: 0, entries: 1 })) } : {}),
  });
  assert.equal(thousand.r.state, "files_validated", "1000 refused");
  await failedAs(refusedDir(3, "y"), "bad_form", "a refused path the list doesn't hold");
  // ... even when nothing else differs (fill names an entry the backup never had).
  await failedAs({ report: (c) => (c === "home" ? { refused: [{ path: "y", uid: 0, gid: 0, entries: 1 }] } : {}) }, "bad_form", "only an unknown refused path");
  // A refused file is entries 1; refused, yet present in the destination, is extra.
  const file = (entries, keep = false) => ({ beforeDigest: keep ? undefined : gone("a.txt"), report: (c) => (c === "home" ? { refused: [{ path: "a.txt", uid: 0, gid: 0, entries }] } : {}) });
  assert.equal((await settle(file(1))).r.state, "files_validated");
  await failedAs(file(0), "bad_form", "a refused file counted 0");
  await failedAs(file(1, true), "bad_form", "a refused file that is placed anyway");
  // A report that is truncated, or lists anything unexpected, is never excused.
  await failedAs({ report: (c) => (c === "home" ? { truncated: true } : {}) }, "bad_form", "a truncated report");
  await failedAs({ report: (c) => (c === "sessions" ? { unexpected: [{ path: "p", type: "fifo" }] } : {}) }, "bad_form", "an unexpected entry in fill");
});

test("validation needs the set stopped and fenced; tree-digest's transient exits are retried a bounded number of times", async () => {
  // Not stopped: nothing is validated or changed; the record stays published, its attempt kept.
  const id = newId();
  let stoppedNow = false;
  const w = world("agent", { stopped: async () => stoppedNow });
  await rejects(w.fill("agent", id, planOf("agent", id)), "not_granted");
  assert.equal(readRecord("agent", id, { dir: w.dir }).state, "published");
  assert.ok(!w.calls.some((a) => a[0] === "tree-digest"));
  assert.ok(existsSync(attemptDir(w, id, "home")));
  stoppedNow = true;
  assert.equal((await w.fill("agent", id, planOf("agent", id))).state, "files_validated");
  for (const v of [false, undefined, 1, "true"]) {
    const i = newId(), x = world("agent", { stopped: async () => v });
    await rejects(x.fill("agent", i, planOf("agent", i)), "not_granted");
  }
  // 75 (a read error mid-walk) twice, then 0: validated, the class listed three times.
  let n = 0;
  const flaky = await settle({ script: (op, cls) => (op === "tree-digest" && cls === "home" && ++n <= 2 ? EXIT.partial : 0) });
  assert.equal(flaky.r.state, "files_validated");
  assert.equal(flaky.w.calls.filter((a) => a[0] === "tree-digest" && a[6] === "home").length, 3);
  // Transient every time: failed after DIGEST_TRIES, never re-staged.
  const always = await failedAs({ script: (op, cls) => (op === "tree-digest" && cls === "home" ? EXIT.partial : 0) }, "outcome_unknown", "75 every time");
  assert.equal(always.w.calls.filter((a) => a[0] === "tree-digest").length, 3);
  // 74 (a stale copy directory): removed before each sessions listing, so a leftover from a crash is cleared.
  const left = await settle({ seed: () => {}, onCall: () => {} });
  assert.equal(left.r.state, "files_validated");
  const id3 = newId();
  const w3 = world("agent", { onCall: (args) => { if (args[0] === "tree-digest" && args[6] === "home") mkdirSync(join(w3.base, "copies", RUN, `a-${id3}`), { recursive: true }); } });
  assert.equal((await w3.fill("agent", id3, planOf("agent", id3))).state, "files_validated", "a leftover copy directory removed first");
  // Usage or limit (64) is bad_form; the root guard, an identity or anything else is outcome_unknown.
  await failedAs({ script: (op) => (op === "tree-digest" ? 64 : 0) }, "bad_form", "64");
  for (const code of [66, 72, 73]) await failedAs({ script: (op) => (op === "tree-digest" ? code : 0) }, "outcome_unknown", String(code));
  // The destination is not the one the record names (another object now): failed before tree-digest runs.
  let asked = 0; // (the fill identifies each class once; validation's second look at sessions finds another object)
  const moved = await failedAs({ identify: (cls, o) => (cls === "sessions" && ++asked === 2 ? { ...o, ino: o.ino + 1 } : o) }, "outcome_unknown", "another destination");
  assert.ok(!moved.w.calls.some((a) => a[0] === "tree-digest" && a[6] === "sessions"));
});

test("validation: tree-digest gets its scope (unit, MemoryMax=1G, the deadline); no listing is a failure", async () => {
  const id = newId();
  const scopes = [];
  const w = world("agent");
  const fill = restoreFiller({
    launch: async (args, opts) => { if (args[0] === "tree-digest") scopes.push(opts.scope); return { code: 1, stdout: "", stderr: "" }; },
    mount: "/srv/sagebrush", identifyDest: async () => ({}), expectOf: async () => "x", projidOf: () => 70000, cleanDest: async () => {},
    discardStaging: async () => {}, stopped: async () => true, unrestorableOf: () => [], removeCopies: async () => {}, dir: w.dir, root: w.stage, validateSeconds: 900,
  });
  // (a published record, reached through the real world's fill, then validated by the scoped launcher)
  const ww = world("agent", { stopped: async () => false });
  await rejects(ww.fill("agent", id, planOf("agent", id)), "not_granted");
  const scoped = restoreFiller({
    launch: async (args, opts) => { scopes.push([args[0], opts.scope]); return { code: 1, stdout: "", stderr: "" }; },
    mount: "/srv/sagebrush", identifyDest: async (k, i, cls) => ({ epoch: { boot_id: "00000000-0000-4000-8000-000000000000", mnt_id: 7 }, fsid: "0123456789abcdef", object: { type: "dir", mode: 0o700, uid: 70000, gid: 70000, dev: [8, 1], ino: statSync(ww.dests[cls]).ino, gen: 1, mnt_id: 7, projid: 70000, inherit: true } }),
    expectOf: async () => "x", projidOf: () => 70000, cleanDest: async () => {}, discardStaging: async () => {}, stopped: async () => true,
    unrestorableOf: () => [], removeCopies: async () => {}, dir: ww.dir, root: ww.stage, validateSeconds: 900,
  });
  const r = await scoped("agent", id, planOf("agent", id));
  assert.deepEqual([r.state, r.reason], ["failed", "outcome_unknown"]);
  assert.deepEqual(scopes, [["tree-digest", { unit: `sagebrush-validate-a-${id}.scope`, memoryMax: "1G", runtimeMaxSec: 900 }]]);
  void fill;
});

test("validation: a crash at any point repeats it against the same recorded hashes and attempt; never a false validated", async () => {
  // Killed during validation (in each class's tree-digest): published, the attempt kept; the next call validates.
  for (const at of ["home", "sessions"]) {
    let crash = true;
    const id = newId();
    const w = world("agent", { onCall: (args) => { if (args[0] === "tree-digest" && args[6] === at && crash) { crash = false; throw Object.assign(new Error("killed"), { code: "EIO" }); } } });
    await assert.rejects(w.fill("agent", id, planOf("agent", id)), /killed/);
    const mid = readRecord("agent", id, { dir: w.dir });
    assert.equal(mid.state, "published", at);
    assert.ok(existsSync(join(attemptDir(w, id, "home"), "data", "digests.json")), `${at}: the lists survive until validated`);
    const r = await w.fill("agent", id, planOf("agent", id));
    assert.deepEqual([r.state, r.attempt, r.digests], ["files_validated", 1, mid.digests], at);
    assert.equal(w.calls.filter((a) => a[0] === "restore-stage").length, STAGED.agent.length, `${at}: not re-staged`);
  }
  // Killed right after published was written (before validation began): the same.
  let crash = true;
  const id = newId();
  const w = world("agent", { stopped: async () => { if (crash) { crash = false; throw new Error("killed"); } return true; } });
  await assert.rejects(w.fill("agent", id, planOf("agent", id)), /killed/);
  assert.equal((await w.fill("agent", id, planOf("agent", id))).state, "files_validated");
  // The tree changed between the crash and the retry: the retry fails it (the same hashes, the same list).
  let crash2 = true, broken = false;
  const id2 = newId();
  const w2 = world("agent", { onCall: (args) => { if (args[0] === "tree-digest" && crash2) { crash2 = false; throw new Error("killed"); } },
    beforeDigest: (cls, d) => { if (broken && cls === "home") writeFileSync(join(d, "a.txt"), "Z"); } });
  await assert.rejects(w2.fill("agent", id2, planOf("agent", id2)), /killed/);
  broken = true;
  assert.deepEqual((await w2.fill("agent", id2, planOf("agent", id2))).state, "failed");
  // A fill report lost with the crash (removed by hand here): never validated without it.
  const id3 = newId();
  let once = true;
  const w3 = world("agent", { onCall: (args) => { if (args[0] === "fill-home" && args[6] === "sessions" && once) { once = false; rmSync(join(w3.dir, `agent-${id3}.home.fill.json`)); } } });
  const r3 = await w3.fill("agent", id3, planOf("agent", id3));
  assert.deepEqual([r3.state, r3.reason], ["failed", "not_found"]);
});

test("restore-stage's and fill-home's lines: exactly the closed success shapes, else the attempt is unusable (a retry)", async () => {
  const good = (t) => t;
  const stageRows = {
    "another snapshot": (t) => t.replace(SNAP, "b".repeat(64)),
    "no digests_sha256": (t) => t.replace(/,"digests_sha256":"[0-9a-f]{64}"/, ""),
    "an extra key": (t) => t.replace("}\n", ',"x":1}\n'),
    "upper-case hex": (t) => t.replace(/"digests_sha256":"([0-9a-f]{64})"/, (m, h) => `"digests_sha256":"${h.toUpperCase()}"`),
    "ok false": (t) => t.replace('"ok":true', '"ok":false'),
    "two lines": (t) => t + t,
    "no newline": (t) => t.slice(0, -1),
    "empty": () => "",
  };
  for (const [what, f] of Object.entries(stageRows)) {
    let first = true;
    const { r, w } = await settle({ stdout: (op, cls, t) => (op === "restore-stage" && cls === "sessions" && first ? ((first = false), f(t)) : good(t)) });
    assert.deepEqual([r.state, r.attempt], ["files_validated", 2], what);
    assert.ok(!w.calls.some((a) => a[0] === "fill-home" && a[10] === "1"), `${what}: attempt 1 never filled`);
  }
  const fillRows = {
    "no placed": (t) => t.replace(/"placed":\{[^}]*\},/, ""),
    "a refused path absolute": (t) => t.replace('"refused":[]', '"refused":[{"path":"/x","uid":0,"gid":0,"entries":1}]'),
    "an unknown special type": (t) => t.replace('"unexpected":[]', '"unexpected":[{"path":"x","type":"door"}]'),
    "truncated not a boolean": (t) => t.replace('"truncated":false', '"truncated":0'),
    "1001 refused": (t) => t.replace('"refused":[]', `"refused":[${Array.from({ length: 1001 }, (_, i) => `{"path":"f${i}","uid":0,"gid":0,"entries":1}`).join(",")}]`),
  };
  for (const [what, f] of Object.entries(fillRows)) {
    let first = true;
    const { r } = await settle({ stdout: (op, cls, t) => (op === "fill-home" && cls === "home" && first ? ((first = false), f(t)) : t) });
    assert.deepEqual([r.state, r.attempt], ["files_validated", 2], what);
  }
});

test("validation of sessions: each SQLite database's private copy passes quick_check; corruption, an omitted or changed copy fail", async (t) => {
  let sqlite;
  try { sqlite = await import("node:sqlite"); } catch { return t.skip("node:sqlite is unavailable"); }
  const make = (path, { wal = false } = {}) => {
    const db = new sqlite.DatabaseSync(path);
    db.exec(`PRAGMA journal_mode=${wal ? "WAL" : "DELETE"}; PRAGMA wal_autocheckpoint=0; CREATE TABLE t (k INTEGER PRIMARY KEY, v TEXT); CREATE INDEX tv ON t (v);`);
    const ins = db.prepare("INSERT INTO t (v) VALUES (?)");
    db.exec("BEGIN");
    for (let i = 0; i < 2000; i++) ins.run(`row ${i} ${"x".repeat(50)}`);
    db.exec("COMMIT");
    return db;
  };
  // A session store with a plain database and a WAL one, copied as the backup holds them (main and -wal).
  const src = mkdtempSync(join(tmpdir(), "sb-sess-"));
  make(join(src, "plain.db")).close();
  const live = make(join(src, "live.db"), { wal: true });
  live.exec("BEGIN");
  for (let i = 0; i < 300; i++) live.prepare("INSERT INTO t (v) VALUES (?)").run(`late ${i}`);
  live.exec("COMMIT");
  const files = { "plain.db": readFileSync(join(src, "plain.db")), "live.db": readFileSync(join(src, "live.db")), "live.db-wal": readFileSync(join(src, "live.db-wal")) };
  live.close();
  const seedWith = (over = {}) => (cls, d) => { if (cls === "sessions") for (const [n, b] of Object.entries({ ...files, ...over })) writeFileSync(join(d, n), b); };
  const opts = (o = {}) => ({ seed: seedWith(o.over), skipCopy: o.skipCopy, afterCopy: o.afterCopy });
  // Sound: validated; the copies were made and removed.
  const ok = await settle(opts());
  assert.equal(ok.r.state, "files_validated");
  // Corruption already in the backup (so the list matches the tree): quick_check catches it.
  const bad = Buffer.from(files["plain.db"]);
  for (let i = bad.length - 8192; i < bad.length - 4096; i++) bad[i] = 0x5a;
  await failedAs(opts({ over: { "plain.db": bad } }), "bad_form", "a corrupt database");
  // An omitted sidecar copy: refused by completeness, though the main alone would pass.
  await failedAs(opts({ skipCopy: (p) => p === "live.db-wal" }), "bad_form", "an omitted -wal copy");
  // A copy whose bytes aren't its entry's: refused before SQLite opens it.
  await failedAs(opts({ afterCopy: (dir, names) => { const p = join(dir, names.get("live.db-wal")); const b = readFileSync(p); b[200] ^= 1; writeFileSync(p, b); } }), "bad_form", "a changed copy");
  // A damaged WAL in the destination (a fill fault): the hash compare fails it, whatever SQLite would replay.
  await failedAs({ ...opts(), beforeDigest: (cls, d) => { if (cls === "sessions") { const b = readFileSync(join(d, "live.db-wal")); b[40] ^= 1; writeFileSync(join(d, "live.db-wal"), b); } } }, "bad_form", "a damaged WAL in the destination");
});

/** A Unix socket bound at `path` and left there (its listener gone): an open of it gives ENXIO. */
const unixSocket = (path) => execFileSync("python3", ["-I", "-c", "import socket,sys; s=socket.socket(socket.AF_UNIX); s.bind(sys.argv[1])", path]);

test("permanent list or report faults are a durable failed; an interruption stays published and is validated again", async () => {
  const list = (w, id, cls) => join(attemptDir(w, id, cls), "data", "digests.json");
  const report = (w, id, cls) => join(w.dir, `agent-${id}.${cls}.fill.json`);
  const rows = {
    "the list replaced by a directory": (w, id) => { rmSync(list(w, id, "home")); mkdirSync(list(w, id, "home")); writeFileSync(join(list(w, id, "home"), "x"), "{}"); },
    "the list replaced by a link": (w, id) => { const p = list(w, id, "home"); renameSync(p, p + ".x"); symlinkSync(p + ".x", p); },
    "a report that isn't JSON": (w, id) => writeFileSync(report(w, id, "sessions"), "{"),
    "a report of another shape": (w, id) => writeFileSync(report(w, id, "home"), '{"v":1}\n'),
    // (not empty: an empty directory has size 0 on some filesystems, and would fail as malformed JSON anyway)
    "a report replaced by a directory": (w, id) => { rmSync(report(w, id, "home")); mkdirSync(report(w, id, "home")); writeFileSync(join(report(w, id, "home"), "x"), "{}"); },
    "a report replaced by a link": (w, id) => { const p = report(w, id, "sessions"); renameSync(p, p + ".x"); symlinkSync(p + ".x", p); },
    "the list replaced by a socket": (w, id) => { rmSync(list(w, id, "home")); unixSocket(list(w, id, "home")); },
    "a report replaced by a socket": (w, id) => { rmSync(report(w, id, "sessions")); unixSocket(report(w, id, "sessions")); },
    "a report replaced by a FIFO": (w, id) => { rmSync(report(w, id, "home")); execFileSync("mkfifo", [report(w, id, "home")]); },
    "a report replaced by another attempt's": (w, id) => { const x = JSON.parse(readFileSync(report(w, id, "home"), "utf8")); writeFileSync(report(w, id, "home"), JSON.stringify({ ...x, attempt: 2 }) + "\n"); },
  };
  for (const [what, f] of Object.entries(rows)) {
    const id = newId();
    // (tampered after the last fill-home's report is saved: at validation's first look, before any tree-digest)
    const once = { done: false };
    const w = world("agent", { stopped: async () => { if (!once.done) { once.done = true; f(w, id); } return true; } });
    const r = await w.fill("agent", id, planOf("agent", id));
    assert.equal(r.state, "failed", what);
    assert.ok(["bad_form", "not_found"].includes(r.reason), `${what}: ${r.reason}`);
    assert.ok(!w.calls.some((a) => a[0] === "tree-digest"), `${what}: nothing listed`);
    const n = w.calls.length;
    assert.equal((await w.fill("agent", id, planOf("agent", id))).state, "failed", what);
    assert.equal(w.calls.length, n, `${what}: no launch, no revalidation, no re-stage`);
  }
  // An interruption (the list unreadable for a moment: EIO from the read) is not a verdict: still published, and the
  // next call validates from the start, against the same hashes.
  const id = newId();
  let fault = true;
  const w = world("agent", { stopped: async () => { if (fault) { fault = false; throw Object.assign(new Error("EIO"), { code: "EIO" }); } return true; } });
  await assert.rejects(w.fill("agent", id, planOf("agent", id)), /EIO/);
  assert.equal(readRecord("agent", id, { dir: w.dir }).state, "published");
  assert.equal((await w.fill("agent", id, planOf("agent", id))).state, "files_validated");
  // The same for the report: unreadable for a moment (EACCES) is no verdict.
  if (process.getuid?.() !== 0) {
    const id3 = newId();
    let q = null;
    const w3 = world("agent", { stopped: async () => { if (q === null) { q = join(w3.dir, `agent-${id3}.home.fill.json`); chmodSync(q, 0); } return true; } });
    await assert.rejects(w3.fill("agent", id3, planOf("agent", id3)), (e) => e.code === "EACCES");
    assert.equal(readRecord("agent", id3, { dir: w3.dir }).state, "published");
    chmodSync(q, 0o600);
    assert.equal((await w3.fill("agent", id3, planOf("agent", id3))).state, "files_validated");
  }
  // A read of the list that fails for another reason than its form (here EACCES, standing in for an I/O error) is
  // the same: thrown, still published, validated once it reads.
  if (process.getuid?.() !== 0) {
    const id2 = newId();
    let p = null;
    const w2 = world("agent", { stopped: async () => { if (p === null) { p = join(attemptDir(w2, id2, "home"), "data", "digests.json"); chmodSync(p, 0); } return true; } });
    await assert.rejects(w2.fill("agent", id2, planOf("agent", id2)), (e) => e.code === "EACCES");
    assert.equal(readRecord("agent", id2, { dir: w2.dir }).state, "published");
    chmodSync(p, 0o600);
    assert.equal((await w2.fill("agent", id2, planOf("agent", id2))).state, "files_validated");
  }
});

test("names through the whole restore: a literal %, bytes that aren't UTF-8, UTF-8 and nested names, in raw order", async () => {
  const B = (s) => Buffer.from(s, "latin1");
  const seed = (cls, d) => {
    if (cls !== "home") return;
    for (const n of [Buffer.from("%"), Buffer.from("z"), Buffer.from("é"), B("\xe2\x82"), B("\xff")]) writeFileSync(Buffer.concat([Buffer.from(d + "/"), n]), n);
    mkdirSync(join(d, "d"));
    writeFileSync(Buffer.concat([Buffer.from(d + "/d/"), B("\xff")]), "x");
    writeFileSync(join(d, "d", "%x"), "y");
  };
  const ok = await settle({ seed });
  assert.equal(ok.r.state, "files_validated");
  // The list the binary wrote is in raw order (the paths as encoded, in that order).
  let seen = null;
  await settle({ seed, listOf: (cls, t) => { if (cls === "home") seen = t; return t; } });
  const paths = seen.split("\n").filter((l) => l.startsWith('{"path"')).map((l) => JSON.parse(l).path);
  assert.deepEqual(paths, ["%25", "a.txt", "b.txt", "d", "d/%25x", "d/%FF", "z", "é", "%E2%82", "%FF"]);
  // Controls: either side in the ENCODED order (the old bug) is refused, even with the list's exact hash.
  const encodedOrder = (t) => {
    const l = t.split("\n").slice(0, -1);
    const body = l.slice(1, -1).sort((a, b) => Buffer.compare(Buffer.from(JSON.parse(a).path), Buffer.from(JSON.parse(b).path)));
    return [l[0], ...body, l[l.length - 1]].join("\n") + "\n";
  };
  await failedAs({ seed, listOf: (cls, t) => (cls === "home" ? encodedOrder(t) : t) }, "bad_form", "the binary's list in encoded order");
  await failedAs({ seed, observe: (cls, t) => (cls === "home" ? encodedOrder(t) : t) }, "bad_form", "tree-digest's listing in encoded order");
  // And a changed byte inside a name that isn't UTF-8 is a different path: missing plus extra.
  await failedAs({ seed, beforeDigest: (cls, d) => { if (cls === "home") renameSync(Buffer.concat([Buffer.from(d + "/"), B("\xff")]), Buffer.concat([Buffer.from(d + "/"), B("\xfe")])); } }, "bad_form", "0xff renamed 0xfe");
});
