// Host restore e2e r1.7 delta R4-d2b §2 and §5: an agent's two imports as the executor's restore-import step. Real
// temporary trees (owned by the test's uid in place of root), real set locks, the record's own steps; a crash is an
// injected failure at the k-th durable effect, and the next step must end where an uncrashed one does.
import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "./host-linux-only.mjs";
import { FleetError, newId } from "../lib/fleet/index.mjs";
import { realIo, lockFile } from "../lib/fleet/host/store.mjs";
import { EMPTY_CONFIG_HASH, configHash, readConfigTree } from "../lib/fleet/host/agent-config.mjs";
import { BEGIN, HOSTSTORE_COPY, writeRequest } from "../lib/fleet/host/restore-begin.mjs";
import { closePlan, createPlan } from "../lib/fleet/host/restore-plan.mjs";
import { newRecord, newRestoreRun, readRecord, stagingDir, stagingName, step, writeRecord } from "../lib/fleet/host/restore-record.mjs";
import { holdSets, setLockPath, workerLive } from "../lib/fleet/host/restore-worker.mjs";
import { EMPTY_CONTEXT, IMPORTER_MISSING, configExpected, expectedHash, harnessRecordsOf, importAgentSet, importOnce } from "../lib/fleet/host/restore-agent-imports.mjs";

const UID = process.getuid();
const hex = (c) => c.repeat(64);
const RUN = newRestoreRun(1795500000000, () => Buffer.alloc(6));
const RUN2 = newRestoreRun(1795600000000, () => Buffer.alloc(6, 1));
const SNAP = hex("a");
const rejects = (p, code) => assert.rejects(p, (e) => e instanceof FleetError && e.code === code, code);
const GEN1 = { "manifest.json": '{"v":1}\n', "instructions.md": "be kind\n", skills: null, "skills/a": null, "skills/a/SKILL.md": "x" };
const GEN2 = { "manifest.json": '{"v":2}\n', "instructions.md": "be kinder\n" };

const private_ = (p) => { mkdirSync(p, { recursive: true, mode: 0o700 }); chmodSync(p, 0o700); return p; };
/** A generation directory from { path: content | null (a directory) }, every mode exact. */
function writeGen(dir, files) {
  private_(dir);
  for (const [p, c] of Object.entries(files).sort()) {
    const full = join(dir, p);
    if (c === null) private_(full); else { writeFileSync(full, c, { mode: 0o600 }); chmodSync(full, 0o600); }
  }
}
const writeCurrent = (root, n) => { writeFileSync(join(root, "current"), `gen-${n}\n`, { mode: 0o600 }); chmodSync(join(root, "current"), 0o600); };
/** A config tree at `root`: `gens` { n: files }, `current` n or null. */
function writeTree(root, gens, current) {
  private_(root);
  for (const [n, files] of Object.entries(gens)) writeGen(join(root, `gen-${n}`), files);
  if (current !== null) writeCurrent(root, current);
}
/** The launcher's [major, minor] of a path's device, and its inode: the provisioning's recorded identity. */
function identityOf(p) {
  const st = statSync(p);
  const major = Number((BigInt(st.dev) >> 8n) & 0xfffn) | Number((BigInt(st.dev) >> 32n) & ~0xfffn);
  const minor = Number(BigInt(st.dev) & 0xffn) | Number((BigInt(st.dev) >> 12n) & ~0xffn);
  return { dev: [major, minor], ino: st.ino };
}
/** A tree's whole content: each path's type and bytes. */
function snapshot(root) {
  const out = {};
  const go = (rel) => {
    for (const n of readdirSync(rel ? join(root, rel) : root).sort()) {
      const r = rel ? `${rel}/${n}` : n, st = statSync(join(root, r));
      if (st.isDirectory()) { out[r] = null; go(r); } else out[r] = readFileSync(join(root, r), "utf8");
    }
  };
  go("");
  return out;
}

/** The staged config's hash as the manifest records it: the hash of its current generation's listing (or empty). */
function hashOfStaged(gens, current) {
  const t = join(mkdtempSync(join(tmpdir(), "sb-aih-")), "t");
  writeTree(t, gens, current);
  return configHash(readConfigTree(t, { uid: UID }));
}

/**
 * A host with one agent set at files_validated: the restore begun and open, its plan (the agent's config hash the
 * manifest's, `config` to override), the staged config attempt (`staged`: { gens, current }, its marker exactly its
 * name unless `marker`), the live tree (`live`), the host store copy (`harness`: { dir: [names] }).
 */
function world({ staged = { gens: { 1: GEN1, 2: GEN2 }, current: "2" }, live = { gens: {}, current: null }, config, marker, harness = {}, others = [] } = {}) {
  const base = private_(mkdtempSync(join(tmpdir(), "sb-aimp-")));
  const dir = private_(join(base, "restore")), staging = private_(join(base, "staging"));
  const id = newId(), key = `agent-${id}`;
  writeFileSync(join(dir, BEGIN), JSON.stringify({ v: 1, snapshot: hex("1"), manifest_sha256: hex("2"), run: RUN, state: "done" }) + "\n", { mode: 0o600 });
  const keys = [key, ...others];
  const cfg = config ?? hashOfStaged(staged.gens, staged.current);
  const plan = { v: 1, host: "old", manifest: hex("1"), sha256: hex("2"), hoststore: hex("3"),
    sets: Object.fromEntries(keys.map((k) => [k, { run: RUN, snapshot: SNAP, tree: hex("4") }])),
    config: Object.fromEntries(keys.filter((k) => k.startsWith("agent-")).map((k) => [k.slice(6), k === key ? cfg : hex("5")])) };
  createPlan(plan, { dir });
  for (const k of keys) writeRequest(k, RUN, { dir, uid: UID });
  const r = filesValidated(id);
  writeRecord(r, { dir });
  // The staged config attempt: <staging>/<run>/a-<id>/config/<attempt>/{.complete, data/<id>}.
  const att = stagingDir(r, "config", staging);
  for (let p = staging, parts = stagingName(r, "config").split("/"), i = 0; i < parts.length; i++) private_(p = join(p, parts[i]));
  private_(join(att, "data"));
  writeTree(join(att, "data", id), staged.gens, staged.current);
  writeFileSync(join(att, ".complete"), marker ?? stagingName(r, "config"));
  // The live tree, provisioned: root:root 0700, its identity recorded.
  const liveRoot = join(private_(join(base, "agent-config")), id);
  writeTree(liveRoot, live.gens, live.current);
  // The host store copy.
  const copy = private_(join(dir, HOSTSTORE_COPY, RUN));
  for (const [h, names] of Object.entries(harness)) { private_(join(copy, h)); for (const n of names) writeFileSync(join(copy, h, n), "{}\n", { mode: 0o600 }); }
  const discarded = [];
  const deps = (over = {}) => ({
    hold: () => holdSets(id, [], { dir, uid: UID }),
    liveConfig: async () => ({ root: liveRoot, identity: identityOf(liveRoot) }),
    hasContext: async ({ run }) => harnessRecordsOf(id, { dir, uid: UID, run }),
    discard: async (rec) => { discarded.push(rec.state); },
    ...over,
  });
  return { base, dir, staging, id, key, liveRoot, att, deps, discarded, record: () => readRecord("agent", id, { dir }), cfg };
}
function filesValidated(id, run = RUN) {
  const ID = { dev: "2049", ino: "131", uid: 70000, gid: 70000, mode: 0o700, projid: 70000 };
  const dest = { home: ID, sessions: { ...ID, ino: "132" } };
  let r = step(newRecord({ kind: "agent", id, run, snapshot: SNAP }), "bind", { dest });
  for (const cls of ["home", "sessions"]) r = step(r, "digest", { cls, sha256: hex("5") });
  r = step(step(r, "staged"), "filling", { dest });
  return step(step(r, "published"), "files_validated");
}
const opts = (w, over = {}) => ({ dir: w.dir, uid: UID, staging: w.staging, ...over });
/** An io that fails at its `at`-th fsync (a crash there: the effect may or may not have reached the disk before it). */
function crashingIo(at) {
  let n = 0;
  return { ...realIo, fsync: (fd) => { if (++n === at) throw Object.assign(new Error("crash"), { crash: true }); return realIo.fsync(fd); }, get count() { return n; } };
}

test("an agent's imports: pending before the first write, the config imported generation by generation with current last, done with the same hash; then validated, the staging discarded", async () => {
  const w = world();
  const seen = [];
  const out = await importAgentSet(w.id, w.deps({
    // (each generation's import and current's write: what the record said at that moment)
    liveConfig: async () => { seen.push(w.record().imports.config.state); return { root: w.liveRoot, identity: identityOf(w.liveRoot) }; },
  }), opts(w));
  assert.deepEqual(out, { status: "validated" });
  assert.deepEqual(seen, ["pending"], "pending was durable before the live tree was touched");
  const r = w.record();
  const want = configExpected(readConfigTree(join(w.att, "data", w.id), { uid: UID }));
  assert.equal(r.state, "validated");
  assert.deepEqual(r.imports, { config: { state: "done", sha256: expectedHash(want) }, context: { state: "done", sha256: expectedHash(EMPTY_CONTEXT) } });
  assert.deepEqual(snapshot(w.liveRoot), snapshot(join(w.att, "data", w.id)), "the live tree is exactly the staged one");
  assert.equal(configHash(readConfigTree(w.liveRoot, { uid: UID })), w.cfg, "its configuration is the manifest's");
  assert.deepEqual(w.discarded, ["validated"], "the staging is discarded once validated is durable");
});

test("a crash at every durable effect re-runs to the same tree and record; current never precedes a generation", async () => {
  const ref = world();
  await importAgentSet(ref.id, ref.deps(), opts(ref));
  const total = (() => { const w = world(); const io = crashingIo(Infinity); return importAgentSet(w.id, w.deps(), opts(w, { io })).then(() => io.count); })();
  const n = await total;
  assert.ok(n >= 8, `every write is fsynced (${n})`);
  for (let at = 1; at <= n; at++) {
    const w = world();
    await assert.rejects(importAgentSet(w.id, w.deps(), opts(w, { io: crashingIo(at) })), (e) => e.crash === true, `crash at ${at}`);
    // What the crash left: current only with every generation in place.
    const left = snapshot(w.liveRoot);
    if (Object.hasOwn(left, "current")) assert.ok(Object.hasOwn(left, "gen-1") && Object.hasOwn(left, "gen-2"), `crash at ${at}: current before a generation`);
    // The next op (a crash after validated's rename leaves it validated: the op only discards then).
    const out = await importOnce(() => w.deps(), opts(w));
    assert.ok([JSON.stringify({ sets: { [w.key]: { status: "validated" } } }), JSON.stringify({ sets: {} })].includes(JSON.stringify(out)), `crash at ${at}: ${JSON.stringify(out)}`);
    assert.equal(w.record().state, "validated", `crash at ${at}`);
    assert.deepEqual(snapshot(w.liveRoot), snapshot(ref.liveRoot), `crash at ${at}: the same tree`);
    assert.deepEqual(w.record().imports, ref.record().imports, `crash at ${at}: the same hashes`);
  }
});

test("the step holds the set: a worker started during it finds the set busy; a held set is skipped, nothing touched", async () => {
  const w = world();
  let during = null;
  await importAgentSet(w.id, w.deps({ hasContext: async ({ run }) => { during = await workerLive("agent", w.id, { dir: w.dir }); return harnessRecordsOf(w.id, { dir: w.dir, uid: UID, run }); } }), opts(w));
  assert.equal(during, true, "the set's lock is held through the step");
  assert.equal(await workerLive("agent", w.id, { dir: w.dir }), false, "and released after");
  // A worker holds it: busy, the record and the tree untouched.
  const v = world();
  const held = await lockFile(setLockPath(v.dir, "agent", v.id), { waitMs: 0 });
  try {
    const before = readFileSync(join(v.dir, `agent-${v.id}.json`));
    assert.deepEqual(await importAgentSet(v.id, v.deps(), opts(v)), { status: "busy" });
    assert.ok(readFileSync(join(v.dir, `agent-${v.id}.json`)).equals(before));
    assert.deepEqual(snapshot(v.liveRoot), {});
  } finally { await held.release(); }
});

test("an abandon intent appearing between two effects stops the step with nothing more written", async () => {
  // After pending: the intent is written when the live tree is first asked for, before any generation.
  const w = world();
  const intent = () => { private_(join(w.dir, "abandon")); writeFileSync(join(w.dir, "abandon", `${w.key}.json`), "{}\n", { mode: 0o600 }); };
  const out = await importAgentSet(w.id, w.deps({ liveConfig: async () => { intent(); return { root: w.liveRoot, identity: identityOf(w.liveRoot) }; } }), opts(w));
  assert.deepEqual(out, { status: "abandoning" });
  assert.deepEqual([w.record().state, w.record().imports.config.state], ["files_validated", "pending"]);
  assert.deepEqual(snapshot(w.liveRoot), {}, "no generation written");
  assert.deepEqual(w.discarded, []);
  // An intent before the step: nothing at all.
  const v = world();
  private_(join(v.dir, "abandon")); writeFileSync(join(v.dir, "abandon", `${v.key}.json`), "{}\n", { mode: 0o600 });
  const before = readFileSync(join(v.dir, `${v.key}.json`));
  assert.deepEqual(await importAgentSet(v.id, v.deps(), opts(v)), { status: "abandoning" });
  assert.ok(readFileSync(join(v.dir, `${v.key}.json`)).equals(before));
});

test("a record that moved (another run, another state) or a closed restore refuses before any effect", async () => {
  const w = world();
  writeRecord(filesValidated(w.id, RUN2), { dir: w.dir });
  await rejects(importAgentSet(w.id, w.deps(), opts(w)), "not_granted");
  assert.deepEqual(snapshot(w.liveRoot), {});
  const v = world();
  writeRecord(step(filesValidated(v.id), "failed", { reason: "bad_form" }), { dir: v.dir });
  await rejects(importAgentSet(v.id, v.deps(), opts(v)), "not_granted");
  const c = world();
  closePlan(1795500001000, { dir: c.dir });
  await rejects(importAgentSet(c.id, c.deps(), opts(c)), "not_granted");
  // Moved mid-step (after pending): refused, nothing more written.
  const m = world();
  await rejects(importAgentSet(m.id, m.deps({ liveConfig: async () => { writeRecord(filesValidated(m.id, RUN2), { dir: m.dir }); return { root: m.liveRoot, identity: identityOf(m.liveRoot) }; } }), opts(m)), "not_granted");
  assert.deepEqual(snapshot(m.liveRoot), {});
  assert.equal(m.record().run, RUN2);
});

test("config: a partial live tree that is a prefix continues; anything else fails the set, the tree left as it was", async () => {
  // A crash's prefix: gen-1 only, no current (accepted only by the import's own read while pending).
  const p = world({ live: { gens: { 1: GEN1 }, current: null } });
  // (pending first, as the crashed step wrote it)
  const want = configExpected(readConfigTree(join(p.att, "data", p.id), { uid: UID }));
  writeRecord(step(p.record(), "import", { which: "config", phase: "pending", sha256: expectedHash(want) }), { dir: p.dir });
  assert.deepEqual(await importAgentSet(p.id, p.deps(), opts(p)), { status: "validated" });
  assert.deepEqual(snapshot(p.liveRoot), snapshot(join(p.att, "data", p.id)));
  // Not a prefix: another gen-1, gen-2 without gen-1, a generation expected doesn't have, current at another generation.
  for (const live of [
    { gens: { 1: { "manifest.json": "other\n" } }, current: null },
    { gens: { 2: GEN2 }, current: null },
    { gens: { 1: GEN1, 2: GEN2, 3: GEN2 }, current: null },
    { gens: { 1: GEN1 }, current: "1" },
  ]) {
    const w = world({ live });
    const before = snapshot(w.liveRoot);
    const out = await importAgentSet(w.id, w.deps(), opts(w));
    assert.deepEqual(out, { status: "failed", reason: "outcome_unknown" }, JSON.stringify(live));
    assert.deepEqual([w.record().state, w.record().reason], ["failed", "outcome_unknown"]);
    assert.deepEqual(snapshot(w.liveRoot), before, "nothing written over it");
  }
  // A foreign entry in the live tree: the reader refuses, the set fails.
  const f = world();
  writeFileSync(join(f.liveRoot, "stray"), "x", { mode: 0o600 });
  assert.deepEqual(await importAgentSet(f.id, f.deps(), opts(f)), { status: "failed", reason: "outcome_unknown" });
  // A substitute live tree (another directory than the recorded one) refuses before any write.
  const s = world();
  const other = private_(join(s.base, "elsewhere"));
  assert.deepEqual(await importAgentSet(s.id, s.deps({ liveConfig: async () => ({ root: s.liveRoot, identity: identityOf(other) }) }), opts(s)), { status: "failed", reason: "outcome_unknown" });
  assert.deepEqual(snapshot(s.liveRoot), {});
  // No provisioning record of the tree: not_found.
  const n = world();
  assert.deepEqual(await importAgentSet(n.id, n.deps({ liveConfig: async () => null }), opts(n)), { status: "failed", reason: "not_found" });
});

test("config: the manifest binds it; an unconfigured agent's empty tree is EMPTY_CONFIG_HASH; a staged tree with generations but no current fails", async () => {
  // The staged configuration isn't the manifest's: failed, nothing written, not even pending.
  const w = world({ config: hex("9") });
  assert.deepEqual(await importAgentSet(w.id, w.deps(), opts(w)), { status: "failed", reason: "bad_form" });
  assert.deepEqual([w.record().imports.config.state, snapshot(w.liveRoot)], ["none", {}]);
  // Unconfigured: an empty staged tree imports as nothing, and its hash is EMPTY_CONFIG_HASH.
  const e = world({ staged: { gens: {}, current: null } });
  assert.equal(e.cfg, EMPTY_CONFIG_HASH);
  assert.deepEqual(await importAgentSet(e.id, e.deps(), opts(e)), { status: "validated" });
  assert.deepEqual(snapshot(e.liveRoot), {});
  assert.equal(e.record().imports.config.sha256, expectedHash({ v: 1, current: null, generations: [] }));
  // The same empty tree where the manifest says it was configured: failed.
  const x = world({ staged: { gens: {}, current: null }, config: hex("9") });
  assert.deepEqual(await importAgentSet(x.id, x.deps(), opts(x)), { status: "failed", reason: "bad_form" });
  // A staged tree with generations and no current: refused by the staged read, the set fails.
  const g = world({ staged: { gens: { 1: GEN1 }, current: null }, config: hex("9") });
  assert.deepEqual(await importAgentSet(g.id, g.deps(), opts(g)), { status: "failed", reason: "outcome_unknown" });
  assert.deepEqual(snapshot(g.liveRoot), {});
  // A staged attempt whose marker isn't exactly its name: failed.
  const m = world({ marker: "another" });
  assert.deepEqual(await importAgentSet(m.id, m.deps(), opts(m)), { status: "failed", reason: "outcome_unknown" });
  // A pending import bound to another hash: failed (not this expected).
  const h = world();
  writeRecord(step(h.record(), "import", { which: "config", phase: "pending", sha256: hex("e") }), { dir: h.dir });
  assert.deepEqual(await importAgentSet(h.id, h.deps(), opts(h)), { status: "failed", reason: "outcome_unknown" });
  assert.deepEqual(snapshot(h.liveRoot), {});
});

test("context: no record of this agent is the import of nothing; any record of it waits for its importer, nothing written", async () => {
  const other = newId();
  for (const harness of [{}, { "harness-sessions": [] }, { "harness-sessions": [`${other}.json`], "harness-turns": [`${other}.journal`] }]) {
    const w = world({ harness });
    assert.deepEqual(await importAgentSet(w.id, w.deps(), opts(w)), { status: "validated" }, JSON.stringify(harness));
    assert.deepEqual(w.record().imports.context, { state: "done", sha256: expectedHash(EMPTY_CONTEXT) });
  }
  for (const h of ["harness-sessions", "harness-turns"]) {
    const w = world({ harness: { [h]: [] } });
    writeFileSync(join(w.dir, HOSTSTORE_COPY, RUN, h, h === "harness-sessions" ? `${w.id}.json` : `${w.id}.journal`), "{}\n", { mode: 0o600 });
    const before = readFileSync(join(w.dir, `${w.key}.json`));
    assert.deepEqual(await importAgentSet(w.id, w.deps(), opts(w)), { status: "files_validated", reason: IMPORTER_MISSING }, h);
    assert.ok(readFileSync(join(w.dir, `${w.key}.json`)).equals(before), `${h}: no import state changed`);
    assert.deepEqual(snapshot(w.liveRoot), {}, `${h}: nothing imported`);
    assert.deepEqual(w.discarded, []);
  }
  // A pending import of nothing that now finds a record: failed.
  const p = world();
  writeRecord(step(p.record(), "import", { which: "context", phase: "pending", sha256: expectedHash(EMPTY_CONTEXT) }), { dir: p.dir });
  private_(join(p.dir, HOSTSTORE_COPY, RUN, "harness-turns"));
  writeFileSync(join(p.dir, HOSTSTORE_COPY, RUN, "harness-turns", `${p.id}.journal`), "x");
  assert.deepEqual(await importAgentSet(p.id, p.deps(), opts(p)), { status: "failed", reason: "outcome_unknown" });
  // A harness directory that isn't a private directory refuses (never read through).
  const l = world({ harness: { "harness-sessions": [] } });
  chmodSync(join(l.dir, HOSTSTORE_COPY, RUN, "harness-sessions"), 0o777);
  await rejects(importAgentSet(l.id, l.deps(), opts(l)), "not_granted");
});

test("the step's op: every files_validated agent set in key order; a validated one's staging discarded again; others, intents and other runs untouched", async () => {
  const w = world();
  const t = newId();
  // (a second, unrelated set of the plan: a tag folder, never an import's)
  const v = world({ others: [`tag-${t}`] });
  const calls = [];
  const depsOf = (x) => (id) => { calls.push(id); return x.deps(); };
  const out = await importOnce(depsOf(w), opts(w));
  assert.deepEqual(out, { sets: { [w.key]: { status: "validated" } } });
  // Again: validated, its staging discarded again (under the hold), nothing imported.
  const again = await importOnce(depsOf(w), opts(w));
  assert.deepEqual([again, w.discarded], [{ sets: {} }, ["validated", "validated"]]);
  // A tag folder of the plan is never looked at.
  await importOnce(depsOf(v), opts(v));
  assert.ok(!calls.includes(t));
  // An intent, another run: skipped.
  const i = world();
  private_(join(i.dir, "abandon")); writeFileSync(join(i.dir, "abandon", `${i.key}.json`), "{}\n", { mode: 0o600 });
  assert.deepEqual(await importOnce(depsOf(i), opts(i)), { sets: {} });
  const o = world();
  writeRecord(filesValidated(o.id, RUN2), { dir: o.dir });
  assert.deepEqual(await importOnce(depsOf(o), opts(o)), { sets: {} });
  // A closed or unbegun restore: idle.
  const c = world();
  closePlan(1795500001000, { dir: c.dir });
  assert.deepEqual(await importOnce(depsOf(c), opts(c)), { sets: {} });
  const u = world();
  writeFileSync(join(u.dir, BEGIN), JSON.stringify({ v: 1, snapshot: hex("1"), manifest_sha256: hex("2"), run: RUN, state: "begun" }) + "\n", { mode: 0o600 });
  assert.deepEqual(await importOnce(depsOf(u), opts(u)), { sets: {} });
  // A refusal of one set is reported, not thrown.
  const r = world();
  const bad = await importOnce(() => r.deps({ liveConfig: async () => { throw new FleetError("outcome_unknown", "x"); } }), opts(r));
  assert.deepEqual(bad, { sets: { [r.key]: { status: "refused", reason: "outcome_unknown" } } });
});

test("an aborted signal stops the step before its next effect", async () => {
  const w = world();
  const ac = new AbortController();
  await rejects(importAgentSet(w.id, w.deps({ liveConfig: async () => { ac.abort(); return { root: w.liveRoot, identity: identityOf(w.liveRoot) }; } }), opts(w, { signal: ac.signal })), "outcome_unknown");
  assert.deepEqual(snapshot(w.liveRoot), {});
  assert.equal(w.record().imports.config.state, "pending");
});
