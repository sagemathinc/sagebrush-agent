// Host backup, wiring r0.4 + init-run d6 §6 (A1), on a host whose store has no live owner: `host backup run` and
// `status` over runOnce's REAL dependencies (realRunDeps), real temporary directories, a real HostStore, the real
// exclusion (a real flock holder) and the real restore check, against a file-backed fake store (the binary's ops).
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import * as fs from "node:fs";
import { chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { test } from "./host-linux-only.mjs";
import { FleetError } from "../lib/fleet/index.mjs";
import { HostStore } from "../lib/fleet/host/host-store.mjs";
import { backupCommand, realRunDeps } from "../lib/fleet/host/backup-cli.mjs";
import { backupHostId, backupUnits, runOnce } from "../lib/fleet/host/backup-scheduler.mjs";
import { readRequest, readResult, runSnapshot, takeSnapshot } from "../lib/fleet/host/backup-snapshot.mjs";
import { parseManifest } from "../lib/fleet/host/backup-manifest.mjs";
import { chooseManifest, listManifests } from "../lib/fleet/host/restore-plan.mjs";
import { withExclusion } from "../lib/fleet/host/restore-begin.mjs";

const UID = typeof process.getuid === "function" ? process.getuid() : -1; // (Linux-only rows; off Linux the file only loads)
const T0 = Date.parse("2026-11-26T03:00:00Z");
const hex = (s) => createHash("sha256").update(String(s)).digest("hex");
const rejects = (p, code) => assert.rejects(p, (e) => e?.code === code, code);
const refused = (fn, code) => assert.throws(fn, (e) => e instanceof FleetError && e.code === code, code);
const private_ = (p) => { mkdirSync(p, { recursive: true, mode: 0o700 }); chmodSync(p, 0o700); return p; };

/**
 * The fake store, kept in a JSON file (so a later process sees it): every snapshot with its tags, paths and host, and
 * a committed manifest's text (read from its staging directory when backed up). `hooks[op](req)` runs after the op.
 */
function fakeStore(file) {
  const load = () => (existsSync(file) ? JSON.parse(readFileSync(file, "utf8")) : { snaps: [], n: 0, ops: [] });
  const strip = ({ text, ...x }) => x;
  const bin = async (req) => {
    const s = load();
    s.ops.push(req.op);
    let out;
    if (req.op === "backup") {
      const id = hex(`snap-${s.n}`), tree = hex(`tree-${s.n}`);
      s.n += 1;
      const mf = join(req.sources[0], "manifest.json");
      s.snaps.push({ id, time: new Date(T0 + s.n * 1000).toISOString(), tree, host: req.host, paths: req.sources, tags: req.tags, summary: null,
        text: existsSync(mf) ? readFileSync(mf, "utf8") : null });
      out = { ok: true, value: { snapshot: strip(s.snaps.at(-1)), cache_full: false } };
    } else if (req.op === "readback") {
      const x = s.snaps.find((y) => y.id === req.snapshot);
      out = x ? { ok: true, value: { snapshot: strip(x), findings: 0 } } : { ok: false, code: "snapshot_missing" };
    } else if (req.op === "snapshots") out = { ok: true, value: { snapshots: s.snaps.map(strip) } };
    else if (req.op === "dump") {
      const x = s.snaps.find((y) => y.id === req.snapshot);
      out = x?.text ? { ok: true, value: { text: x.text } } : { ok: false, code: "dump_failed" };
    } else if (req.op === "forget") {
      const before = s.snaps.length;
      s.snaps = s.snaps.filter((y) => !req.snapshots.includes(y.id));
      out = { ok: true, value: { forgotten: before - s.snaps.length } };
    } else if (req.op === "prune") out = { ok: true, value: { stats: "" } };
    else if (req.op === "check-data") out = { ok: true, value: { part: req.part, of: req.of, findings: 0 } };
    else out = { ok: false, code: "request_invalid" };
    fs.writeFileSync(file, JSON.stringify(s));
    await bin.hooks?.[req.op]?.(req);
    return out;
  };
  bin.ops = () => load().ops;
  bin.snaps = () => load().snaps;
  return bin;
}

/**
 * A set-up host: backup/ with state/dest.json and enabled (root's 0600 in 0700 directories), an empty host store, no
 * restore, the exclusion's private directory. `deps()`: realRunDeps over all of it (the cache and the disk's free
 * space faked: no loop image or 5 GiB in CI).
 */
function host() {
  const base = mkdtempSync(join(tmpdir(), "sb-wiring-"));
  const dir = private_(join(base, "backup"));
  private_(join(dir, "state"));
  writeFileSync(join(dir, "state", "dest.json"), "{}\n", { mode: 0o600 });
  writeFileSync(join(dir, "enabled"), "", { mode: 0o600 });
  const storeRoot = join(base, "store"), restoreDir = join(base, "restore");
  const exclusion = { path: join(private_(join(base, "lib")), "backup-restore.lock"), uid: UID };
  const store = fakeStore(join(base, "store.json"));
  const fenceDir = private_(join(base, "fence"));
  const deps = (more = {}) => ({
    ...realRunDeps({ dir, storeRoot, uid: UID, exclusion, restoreDir, fenceDir, binary: store, run: async () => ({ code: 0, stdout: "" }) }),
    freeBytes: () => 64 * 1024 ** 3, ensureCache: async () => {}, trimCache: async () => {}, now: () => T0, ...more,
  });
  const cmd = (argv, more = {}) => backupCommand(argv, { uid: () => UID, rootUid: UID, dir, now: () => T0, run: deps(more) });
  return { base, dir, storeRoot, restoreDir, exclusion, store, deps, cmd };
}

/** Every entry under `p` (directories too) with its mode and a file's bytes: "nothing written" compares these. */
function tree(p) {
  const out = {};
  const go = (d, rel) => {
    for (const n of readdirSync(d).sort()) {
      const q = join(d, n), r = rel ? `${rel}/${n}` : n;
      const st = lstatSync(q);
      if (st.isDirectory()) { out[r] = { dir: st.mode & 0o7777 }; go(q, r); } else out[r] = { bytes: readFileSync(q).toString("base64"), mode: st.mode & 0o7777 };
    }
  };
  if (existsSync(p)) go(p, "");
  return out;
}

// ---- the commands, end to end (r0.4 §5 row 11: an unpaired fresh host) ----

test("an unpaired host: `host backup run` snapshots the store itself, commits a manifest with no sets that restore lists as usable and begin can choose; status after it", async () => {
  const h = host();
  const out = await h.cmd(["run"]);
  assert.equal(out.code, 0, JSON.stringify(out));
  assert.equal(out.line.status, "ok");
  assert.match(out.line.manifest, /^[0-9a-f]{64}$/);
  assert.deepEqual(out.line.retention, { kept: 1, forgotten: 0 });
  // The committed manifest, as the store holds it: this install's host id, no sets, the host store's snapshot.
  const hostId = readFileSync(join(h.dir, "host-id"), "utf8").trim();
  assert.match(hostId, /^local-[a-z2-7]{26}$/);
  const committed = h.store.snaps().find((s) => s.id === out.line.manifest);
  const m = parseManifest(committed.text);
  assert.equal(m.host, hostId);
  assert.deepEqual([m.sets, m.config, m.registry.agents, m.registry.tags], [[], {}, {}, {}]);
  const hs = h.store.snaps().find((s) => s.id === m.hoststore);
  assert.ok(hs.tags.includes("sb-kind=hoststore") && hs.paths[0].startsWith(join(h.dir, "snapshot")), "the host store's copy from the run's own snapshot");
  for (const s of h.store.snaps()) assert.equal(s.host, hostId, "every snapshot is this install's");
  // Restore, on any host reaching the store: listed as usable, and begin's choice accepts it.
  const listed = await listManifests({ binary: h.store });
  assert.deepEqual(listed.manifests.map((x) => x.snapshot), [out.line.manifest]);
  assert.deepEqual(listed.unusable, []);
  const chosen = await chooseManifest({ binary: h.store }, out.line.manifest);
  assert.equal(chosen.error, undefined, JSON.stringify(chosen));
  // Status: ok, with the run's success; the host id is reused by the next run.
  const st = await h.cmd(["status"]);
  assert.deepEqual(st, { code: 0, line: { v: 1, state: "ok", last_success: T0, debt_since: null, sets: 0 } });
  const again = await h.cmd(["run"], { now: () => T0 + 86400000 });
  assert.equal(again.line.status, "ok");
  assert.equal(readFileSync(join(h.dir, "host-id"), "utf8").trim(), hostId);
  assert.equal(parseManifest(h.store.snaps().find((s) => s.id === again.line.manifest).text).host, hostId);
});

test("the commands: only their argv (else 2, nothing done); root only; exit 0 for ok, not set up and skipped, 3 for failed; status reads the last run", async () => {
  const h = host();
  for (const argv of [[], ["run", "x"], ["status", "--json"], ["runs"]]) {
    const out = await backupCommand(argv, { uid: () => UID, rootUid: UID, dir: h.dir, run: h.deps() });
    assert.equal(out.code, 2, JSON.stringify(argv));
  }
  assert.deepEqual(h.store.ops(), []);
  assert.deepEqual(await backupCommand(["run"], { uid: () => UID + 1, rootUid: UID, dir: h.dir, run: h.deps() }), { code: 1, line: { v: 1, refused: "not_granted" } });
  // Not set up: 0, nothing done.
  const bare = host();
  fs.unlinkSync(join(bare.dir, "enabled"));
  assert.deepEqual(await bare.cmd(["run"]), { code: 0, line: { v: 1, status: "not set up", why: "not set up" } });
  assert.deepEqual(bare.store.ops(), []);
  // Failed: 3, recorded; status then says failing.
  const f = await h.cmd(["run"], { snapshot: async () => { throw Object.assign(new Error("EIO"), { code: "EIO" }); } });
  assert.deepEqual(f, { code: 3, line: { v: 1, status: "failed", why: "outcome_unknown" } });
  assert.equal((await h.cmd(["status"])).line.state, "failing");
  assert.equal((await h.cmd(["run"])).code, 0);
  assert.equal((await h.cmd(["status"])).line.state, "ok");
  // Skipped (an open restore): 0, and not recorded as a run.
  private_(h.restoreDir);
  writeFileSync(join(h.restoreDir, "begin.json"), "{", { mode: 0o600 });
  const before = readFileSync(join(h.dir, "last-run.json"), "utf8");
  assert.deepEqual(await h.cmd(["run"]), { code: 0, line: { v: 1, status: "skipped", why: "restore_open" } });
  assert.equal(readFileSync(join(h.dir, "last-run.json"), "utf8"), before);
});

test("the unit: the whole run's budget, TimeoutStartSec=10h, TimeoutStopSec=60s, KillMode=control-group", () => {
  const u = backupUnits("/opt/sagebrush-agent");
  for (const line of ["TimeoutStartSec=10h", "TimeoutStopSec=60s", "KillMode=control-group", "Type=oneshot"]) assert.match(u.service, new RegExp(`^${line}$`, "m"));
});

// ---- the exclusion with restore (r0.4 §2) and W1 ----

test("the exclusion, both crossing orders: held by restore, the run is skipped busy having written nothing; a run holding it, restore's begin refuses busy", async () => {
  // (A) restore holds the exclusion.
  {
    const h = host();
    const before = tree(h.base);
    const out = await withExclusion(() => h.cmd(["run"]), { ...h.exclusion, waitMs: 0 });
    assert.deepEqual(out, { code: 0, line: { v: 1, status: "skipped", why: "busy" } });
    assert.deepEqual(h.store.ops(), []);
    const after = tree(h.base);
    delete after["lib/backup-restore.lock"]; delete before["lib/backup-restore.lock"];
    assert.deepEqual(after, before, "nothing written (the state, the debt, the snapshot directory)");
  }
  // (B) a run holds it, between its plan and its commit: restore's begin (its exclusion first) refuses busy.
  {
    const h = host();
    let seen = null;
    h.store.hooks = { readback: async () => {
      if (seen !== null) return;
      const { begin } = await import("../lib/fleet/host/restore-begin.mjs");
      seen = await begin("a".repeat(64), {}, { dir: h.restoreDir, exclusion: { ...h.exclusion, waitMs: 0 } }).then(() => "begun", (e) => e.code);
    } };
    assert.equal((await h.cmd(["run"])).line.status, "ok");
    assert.equal(seen, "in_progress");
    assert.equal(existsSync(h.restoreDir), false, "begin wrote nothing");
  }
});

test("W1, under the exclusion: a begun restore with no plan, a malformed begin.json, a malformed plan, a plan not closed: each skipped restore_open, nothing written; after close, the run proceeds", async () => {
  const { createPlan, closePlan } = await import("../lib/fleet/host/restore-plan.mjs");
  const { newRestoreRun } = await import("../lib/fleet/host/restore-record.mjs");
  const { readBegin } = await import("../lib/fleet/host/restore-begin.mjs");
  const begun = (h) => {
    private_(h.restoreDir);
    writeFileSync(join(h.restoreDir, "begin.json"), JSON.stringify({ v: 1, snapshot: "1".repeat(64), manifest_sha256: "2".repeat(64), run: newRestoreRun(T0, () => Buffer.alloc(6)), state: "done" }) + "\n", { mode: 0o600 });
    assert.notEqual(readBegin({ dir: h.restoreDir }), null, "a well-formed begin.json (so the open cases are open for their own reason)");
  };
  const plan = (h) => createPlan({ v: 1, host: "old", manifest: "1".repeat(64), sha256: "2".repeat(64), hoststore: "3".repeat(64), sets: {}, config: {} }, { dir: h.restoreDir });
  const cases = {
    "begun, no plan (a begin that crashed before its plan)": (h) => begun(h),
    "a malformed begin.json": (h) => { private_(h.restoreDir); writeFileSync(join(h.restoreDir, "begin.json"), "{", { mode: 0o600 }); },
    "a malformed plan": (h) => { begun(h); writeFileSync(join(h.restoreDir, "plan.json"), "{", { mode: 0o600 }); },
    "a plan not closed": (h) => { begun(h); plan(h); },
  };
  for (const [what, set] of Object.entries(cases)) {
    const h = host();
    set(h);
    const before = tree(h.dir);
    assert.deepEqual(await h.cmd(["run"]), { code: 0, line: { v: 1, status: "skipped", why: "restore_open" } }, what);
    assert.deepEqual(tree(h.dir), before, `${what}: nothing written`);
    assert.deepEqual(h.store.ops(), [], `${what}: nothing read from the store`);
  }
  const h = host();
  begun(h); plan(h);
  assert.equal((await h.cmd(["run"])).line.why, "restore_open");
  closePlan(T0, { dir: h.restoreDir });
  assert.equal((await h.cmd(["run"])).line.status, "ok", "after close, the run proceeds");
});

// ---- the snapshot (r0.4 §1.1) ----

test("the snapshot, no owner: the run opens the store itself, copies it and binds the registry from one locked view, then releases the lock", async () => {
  const h = host();
  const s = await HostStore.open(h.storeRoot);
  s.registry.addAgent("a".repeat(26), 1);
  await s.close();
  const dir = private_(join(h.base, "snap"));
  const r = await runSnapshot("20261126T030000Z-abcdefgh", { dir, root: h.storeRoot, openStore: () => HostStore.open(h.storeRoot), uid: UID });
  assert.equal(r.ok, true);
  assert.deepEqual(Object.keys(r.registry.agents), ["a".repeat(26)]);
  assert.ok(existsSync(join(r.hoststore, "registry")), "the host store's copy");
  const again = await HostStore.open(h.storeRoot); // (the lock released before any backup work)
  await again.close();
});

test("the snapshot, a live owner that serves it (the daemon's side, takeSnapshot under its lock); a live owner that doesn't: snapshot_unavailable within the wait, nothing more written", async () => {
  const h = host();
  const owner = await HostStore.open(h.storeRoot);
  try {
    const dir = private_(join(h.base, "snap"));
    const RUN = "20261126T030000Z-abcdefgh";
    // Unserved: the 60 s wait (shortened here) ends it, and the store was never read by the runner.
    let t = 0;
    const r = await runSnapshot(RUN, { dir, root: h.storeRoot, openStore: () => HostStore.open(h.storeRoot), uid: UID, waitMs: 3000, pollMs: 1000, now: () => t, sleep: async (ms) => { t += ms; } });
    assert.deepEqual(r, { ok: false, why: "snapshot_unavailable" });
    assert.deepEqual(readdirSync(dir), ["request.json"], "no result, only its request");
    // Served: the owner sees the request and answers it under its own lock.
    const served = runSnapshot(RUN, { dir, root: h.storeRoot, openStore: () => HostStore.open(h.storeRoot), uid: UID, waitMs: 5000, pollMs: 20 });
    let req = null;
    for (let i = 0; i < 200 && req === null; i += 1) { await new Promise((ok) => { setTimeout(ok, 10); }); req = readRequest(dir, { uid: UID }); }
    assert.deepEqual(takeSnapshot(owner, req, { dir, root: h.storeRoot, uid: UID }), { done: true });
    const got = await served;
    assert.equal(got.ok, true);
  } finally { await owner.close(); }
  // The control: a runner whose read path is a second HostStore.open fails against the live owner.
  const owner2 = await HostStore.open(h.storeRoot);
  try { await rejects(HostStore.open(h.storeRoot), "in_progress"); } finally { await owner2.close(); }
});

test("a slow or late owner: a replaced request makes it remove its own result and write no done; a late done of another nonce is never accepted, and the next run removes it", async () => {
  const h = host();
  const owner = await HostStore.open(h.storeRoot);
  const dir = private_(join(h.base, "snap"));
  const old = { run: "20261126T030000Z-aaaaaaaa", nonce: "A".repeat(22) };
  try {
    writeFileSync(join(dir, "request.json"), JSON.stringify({ v: 1, run: "20261126T040000Z-bbbbbbbb", nonce: "B".repeat(22) }) + "\n", { mode: 0o600 });
    assert.deepEqual(takeSnapshot(owner, old, { dir, root: h.storeRoot, uid: UID }), { done: false });
    assert.equal(existsSync(join(dir, old.run)), false, "its own result removed");
    // Slower still: its done landed anyway, but it names the old nonce: never this run's.
    writeFileSync(join(dir, "request.json"), JSON.stringify({ v: 1, ...old }) + "\n", { mode: 0o600 });
    assert.deepEqual(takeSnapshot(owner, old, { dir, root: h.storeRoot, uid: UID }), { done: true });
    assert.equal(readResult(dir, { run: old.run, nonce: "C".repeat(22) }, { uid: UID }), null);
  } finally { await owner.close(); }
  const r = await runSnapshot("20261126T050000Z-cccccccc", { dir, root: h.storeRoot, openStore: () => HostStore.open(h.storeRoot), uid: UID });
  assert.equal(r.ok, true);
  assert.deepEqual(readdirSync(dir).sort(), ["20261126T050000Z-cccccccc", "request.json"], "every other entry removed first");
});

test("the snapshot's files: root's 0600 regular files, read no-follow, closed-shape; a link, another mode or a registry hash that doesn't match refuses", async () => {
  const h = host();
  const dir = private_(join(h.base, "snap"));
  const RUN = "20261126T030000Z-abcdefgh";
  const ok = await runSnapshot(RUN, { dir, root: h.storeRoot, openStore: () => HostStore.open(h.storeRoot), uid: UID });
  const nonce = readRequest(dir, { uid: UID }).nonce;
  const binding = join(dir, RUN, "binding.json");
  const text = readFileSync(binding, "utf8");
  assert.equal(ok.ok, true);
  chmodSync(binding, 0o644);
  refused(() => readResult(dir, { run: RUN, nonce }, { uid: UID }), "not_granted");
  fs.unlinkSync(binding);
  writeFileSync(join(h.base, "elsewhere"), text, { mode: 0o600 });
  symlinkSync(join(h.base, "elsewhere"), binding);
  refused(() => readResult(dir, { run: RUN, nonce }, { uid: UID }), "not_granted");
  fs.unlinkSync(binding);
  const x = JSON.parse(text);
  writeFileSync(binding, JSON.stringify({ ...x, registry_hash: "0".repeat(64) }) + "\n", { mode: 0o600 });
  refused(() => readResult(dir, { run: RUN, nonce }, { uid: UID }), "bad_form");
});

// ---- the install's backup host id (r0.4 §4, amended) ----

test("the host id: made once (local- and 26 base32, root 0600, exclusive), then reused; a link, another mode or other content refuses; a lost guard writes nothing", () => {
  const d = private_(mkdtempSync(join(tmpdir(), "sb-hostid-")));
  const id = backupHostId({ dir: d, uid: UID });
  assert.match(id, /^local-[a-z2-7]{26}$/);
  assert.equal(lstatSync(join(d, "host-id")).mode & 0o7777, 0o600);
  assert.equal(backupHostId({ dir: d, uid: UID }), id);
  assert.notEqual(backupHostId({ dir: private_(mkdtempSync(join(tmpdir(), "sb-hostid-"))), uid: UID }), id, "random per install");
  chmodSync(join(d, "host-id"), 0o644);
  refused(() => backupHostId({ dir: d, uid: UID }), "not_granted");
  fs.unlinkSync(join(d, "host-id"));
  writeFileSync(join(d, "target"), `${id}\n`, { mode: 0o600 });
  symlinkSync(join(d, "target"), join(d, "host-id"));
  refused(() => backupHostId({ dir: d, uid: UID }), "not_granted");
  fs.unlinkSync(join(d, "host-id"));
  writeFileSync(join(d, "host-id"), "local-x\n", { mode: 0o600 });
  refused(() => backupHostId({ dir: d, uid: UID }), "bad_form");
  fs.unlinkSync(join(d, "host-id"));
  assert.throws(() => backupHostId({ dir: d, uid: UID, guard: () => { throw Object.assign(new Error("lost"), { code: "lock_lost" }); } }), /lost/);
  assert.equal(existsSync(join(d, "host-id")), false);
});

// ---- A1: the run proves its locks for its whole life ----

/** Kill the flock child holding `path` (the run's real exclusion) and wait until it is dead. */
function killHolderNow(path) {
  const pids = [];
  for (const pid of readdirSync("/proc").filter((p) => /^[0-9]+$/.test(p))) {
    let cmd;
    try { cmd = readFileSync(`/proc/${pid}/cmdline`, "utf8").split("\0"); } catch { continue; }
    if (cmd[0].endsWith("flock") && cmd.includes(path)) { process.kill(Number(pid), "SIGKILL"); pids.push(pid); }
  }
  assert.ok(pids.length > 0, `a holder of ${path} was found`);
  // (its child inherited the locked file: killed too, so the lock is really free once this returns)
  for (const pid of readdirSync("/proc").filter((p) => /^[0-9]+$/.test(p))) {
    let st;
    try { st = readFileSync(`/proc/${pid}/stat`, "utf8"); } catch { continue; }
    if (pids.includes(st.slice(st.lastIndexOf(")") + 2).split(" ")[1])) { try { process.kill(Number(pid), "SIGKILL"); pids.push(pid); } catch { /* gone */ } }
  }
  const dead = (pid) => { try { return /\) [ZX] /.test(readFileSync(`/proc/${pid}/stat`, "utf8")); } catch { return true; } };
  const until = Date.now() + 5000;
  while (!pids.every(dead)) if (Date.now() > until) assert.fail("the holder didn't die");
}

// The exclusion's REAL holder killed inside each await class (the call itself answering normally): failed lock_lost
// (exit 3), no later binary call, the state as it stood; the next run proceeds.
for (const [where, op, nth] of [
  ["the host store's backup call", "backup", 0], ["its read-back", "readback", 0], ["the store's listing", "snapshots", 0],
  ["the manifest commit", "backup", 1], ["retention", "readback", 2], ["prune", "prune", 0], ["the data check", "check-data", 0],
]) {
  test(`A1: the exclusion lost inside ${where}: failed lock_lost, nothing after it; the next run proceeds`, async () => {
    const h = host();
    let n = 0, callsAtLoss = null, stateAtLoss = null;
    h.store.hooks = { [op]: async () => {
      if (n++ !== nth) return;
      killHolderNow(h.exclusion.path);
      callsAtLoss = h.store.ops().length;
      stateAtLoss = existsSync(join(h.dir, "state.json")) ? readFileSync(join(h.dir, "state.json"), "utf8") : null;
    } };
    const out = await h.cmd(["run"]);
    assert.deepEqual(out, { code: 3, line: { v: 1, status: "failed", why: "lock_lost" } }, where);
    assert.equal(h.store.ops().length, callsAtLoss, `${where}: no binary call after it`);
    assert.equal(existsSync(join(h.dir, "state.json")) ? readFileSync(join(h.dir, "state.json"), "utf8") : null, stateAtLoss, `${where}: no state written after it`);
    h.store.hooks = {};
    assert.equal((await h.cmd(["run"])).line.status, "ok", `${where}: the next run proceeds`);
  });
}

test("A1: the exclusion lost while the run waits for the snapshot (an owner that never serves): failed lock_lost at the next poll", async () => {
  const h = host();
  const owner = await HostStore.open(h.storeRoot);
  try {
    let polls = 0;
    const out = await h.cmd(["run"], { snapshot: (run, g) => runSnapshot(run, { dir: join(h.dir, "snapshot"), root: h.storeRoot, openStore: () => HostStore.open(h.storeRoot), uid: UID, guard: g,
      pollMs: 10, sleep: async () => { polls += 1; if (polls === 2) killHolderNow(h.exclusion.path); await new Promise((r) => { setTimeout(r, 10); }); } }) });
    assert.deepEqual(out.line, { v: 1, status: "failed", why: "lock_lost" });
    assert.equal(polls, 2, "stopped at the poll after the loss");
  } finally { await owner.close(); }
});

test("A1, each layer alone (a fake guard): lost right after a call with no effect after it (the cache trim), and right after one durable effect (the debt) before the next", async () => {
  const lost = () => Object.assign(new Error("lost"), { code: "lock_lost" });
  // The last await, the cache trim: only the check after it reports the loss.
  {
    const h = host();
    let isLost = false;
    const d = h.deps({ trimCache: async () => { isLost = true; } });
    const r = await runOnce({ ...d, withExclusion: (fn) => fn(() => { if (isLost) throw lost(); }) });
    assert.deepEqual(r, { status: "failed", why: "lock_lost" });
  }
  // Lost once the debt is durable: no backup call follows.
  {
    const h = host();
    let isLost = false;
    const d = h.deps();
    const write = d.state.write;
    const r = await runOnce({ ...d, state: { ...d.state, write: (s) => { write(s); isLost = true; } }, withExclusion: (fn) => fn(() => { if (isLost) throw lost(); }) });
    assert.deepEqual(r, { status: "failed", why: "lock_lost" });
    assert.equal(h.store.ops().includes("backup"), false, "no backup after the lost guard");
  }
});

test("the lock order: the exclusion, then the run lock, then the host-store lock; no path takes them in another order", async () => {
  const h = host();
  const order = [];
  const d = h.deps();
  const r = await runOnce({ ...d,
    withExclusion: (fn) => { order.push("exclusion"); return d.withExclusion(fn); },
    withRunLock: (fn) => { order.push("run"); return d.withRunLock(fn); },
    snapshot: (run, g) => runSnapshot(run, { dir: join(h.dir, "snapshot"), root: h.storeRoot, uid: UID, guard: g, openStore: () => { order.push("hoststore"); return HostStore.open(h.storeRoot); } }) });
  assert.equal(r.status, "ok");
  assert.deepEqual(order, ["exclusion", "run", "hoststore"]);
});

// ---- crash seams (r0.4 §5): the run's process killed; the kernel frees the locks; the next run recovers first ----

const crashDriver = (repo, seam) => `import { backupCommand, realRunDeps } from "${repo}lib/fleet/host/backup-cli.mjs";
import * as fs from "node:fs";
const [base, uid] = [process.argv[2], process.getuid()];
const cfg = JSON.parse(fs.readFileSync(base + "/cfg.json", "utf8"));
const { fakeStoreModule } = await import(base + "/store.mjs");
const store = fakeStoreModule(base + "/store.json");
const deps = realRunDeps({ dir: cfg.dir, storeRoot: cfg.storeRoot, uid, exclusion: cfg.exclusion, restoreDir: cfg.restoreDir, fenceDir: cfg.fenceDir, binary: store, run: async () => ({ code: 0, stdout: "" }) });
const die = () => process.kill(process.pid, "SIGKILL");
const run = { ...deps, freeBytes: () => 64 * 1024 ** 3, ensureCache: async () => {}, trimCache: async () => {}, now: () => ${T0},
  ${seam === "after the lock" ? "restoreOpen: () => { die(); }," : ""}
  ${seam === "after the debt" ? "state: { ...deps.state, write: (s) => { deps.state.write(s); die(); } }," : ""}
  ${seam === "after the commit" ? "commitManifest: async (m, st, g) => { const c = await deps.commitManifest(m, st, g); die(); return c; }," : ""} };
await backupCommand(["run"], { uid: () => uid, rootUid: uid, dir: cfg.dir, run });
`;

for (const seam of ["after the lock", "after the debt", "after the commit"]) {
  test(`a crash ${seam}: the exclusion is free within 2 s (its holder exits with the run), and the next run completes`, async () => {
    const h = host();
    const repo = pathToFileURL(fileURLToPath(new URL("..", import.meta.url))).href.replace(/\/?$/, "/");
    const helpers = mkdtempSync(join(tmpdir(), "sb-wiring-crash-"));
    writeFileSync(join(h.base, "cfg.json"), JSON.stringify({ dir: h.dir, storeRoot: h.storeRoot, exclusion: h.exclusion, restoreDir: h.restoreDir, fenceDir: join(h.base, "fence") }));
    writeFileSync(join(h.base, "store.mjs"), `import * as fs from "node:fs";\nimport { existsSync, readFileSync } from "node:fs";\nimport { join } from "node:path";\nimport { createHash } from "node:crypto";\nconst T0 = ${T0};\nconst hex = (s) => createHash("sha256").update(String(s)).digest("hex");\nexport ${fakeStore.toString().replace("function fakeStore", "function fakeStoreModule")}\n`);
    writeFileSync(join(helpers, "driver.mjs"), crashDriver(repo, seam));
    const r = spawnSync(process.execPath, [join(helpers, "driver.mjs"), h.base], { encoding: "utf8", timeout: 60_000 });
    assert.equal(r.signal, "SIGKILL", `${seam}: died there (${r.stderr})`);
    // The run's death frees the exclusion promptly: its flock child (the real holder) sees its stdin close and exits.
    const t0 = Date.now();
    let free = null;
    while (free === null && Date.now() - t0 < 2000) free = await withExclusion(async () => "free", { ...h.exclusion, waitMs: 0 }).catch(() => null);
    assert.equal(free, "free", `${seam}: free within 2 s (${Date.now() - t0} ms)`);
    const next = await h.cmd(["run"], { now: () => T0 + 3600000 });
    assert.equal(next.line.status, "ok", `${seam}: ${JSON.stringify(next)}`);
  });
}

test("A1: the run lock lost (its own held() false) is the same loss: failed lock_lost, nothing after it", async () => {
  const h = host();
  const d = h.deps();
  let isLost = false;
  h.store.hooks = { backup: async () => { isLost = true; } };
  const r = await runOnce({ ...d, withRunLock: (fn) => d.withRunLock((lock) => fn({ held: () => lock.held() && !isLost })) });
  assert.deepEqual(r, { status: "failed", why: "lock_lost" });
  assert.deepEqual(h.store.ops(), ["backup"], "nothing after the first call that saw it");
});

test("a store owned by a live owner that doesn't serve: skipped snapshot_unavailable, no debt and no store op", async () => {
  const h = host();
  const owner = await HostStore.open(h.storeRoot);
  try {
    let t = 0;
    const out = await h.cmd(["run"], { snapshot: (run, g) => runSnapshot(run, { dir: join(h.dir, "snapshot"), root: h.storeRoot, openStore: () => HostStore.open(h.storeRoot), uid: UID, guard: g,
      waitMs: 3000, pollMs: 1000, now: () => t, sleep: async (ms) => { t += ms; } }) });
    assert.deepEqual(out, { code: 0, line: { v: 1, status: "skipped", why: "snapshot_unavailable" } });
    assert.equal(existsSync(join(h.dir, "state.json")), false, "no debt written");
    assert.deepEqual(h.store.ops(), []);
  } finally { await owner.close(); }
});

// ---- T1 (r0.4 §5): a REAL live owner in another process serves the run's snapshot (the daemon's side, 4b) ----

/**
 * An owner process: it holds a real HostStore (the store's lock) and serves the snapshot request as the daemon does,
 * through the real ticker and serveSnapshot in one queue. It answers "ping" on stdin with "pong" (a concurrent op on
 * the owner). With `slow`, each file of the copy takes 400 ms (so a test can kill it mid-copy).
 */
const ownerScript = (repo) => `import * as fs from "node:fs";
import { HostStore } from "${repo}lib/fleet/host/host-store.mjs";
import { serveSnapshot, snapshotPending } from "${repo}lib/fleet/host/backup-snapshot.mjs";
import { snapshotTicker } from "${repo}lib/fleet/host/host-main.mjs";
const [root, dir, slow] = process.argv.slice(2);
const uid = process.getuid();
const store = await HostStore.open(root);
const pause = (ms) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
const fsx = slow === "slow" ? { ...fs, readFileSync: (...a) => { pause(400); return fs.readFileSync(...a); } } : fs;
let queue = Promise.resolve();
const submit = () => (queue = queue.then(() => serveSnapshot(store, { dir, root, uid, fsx })).then((r) => { process.stdout.write(JSON.stringify(r) + "\\n"); return r; }));
setInterval(snapshotTicker(() => snapshotPending(dir, { uid }), submit), 20);
process.stdin.on("data", (b) => { for (const l of String(b).split("\\n")) if (l === "ping") queue = queue.then(() => process.stdout.write("pong\\n")); });
process.stdout.write("ready\\n");
`;

async function owner(h, slow = "") {
  const { spawn } = await import("node:child_process");
  const repo = pathToFileURL(fileURLToPath(new URL("..", import.meta.url))).href.replace(/\/?$/, "/");
  const helpers = mkdtempSync(join(tmpdir(), "sb-owner-"));
  writeFileSync(join(helpers, "owner.mjs"), ownerScript(repo));
  const child = spawn(process.execPath, [join(helpers, "owner.mjs"), h.storeRoot, join(h.dir, "snapshot"), slow], { stdio: ["pipe", "pipe", "pipe"] });
  let out = "", err = "";
  child.stdout.on("data", (b) => { out += b; });
  child.stderr.on("data", (b) => { err += b; });
  const exited = new Promise((r) => child.on("exit", r));
  const waitFor = async (f, ms = 10_000) => { const t0 = Date.now(); while (!f() && Date.now() - t0 < ms) await new Promise((r) => { setTimeout(r, 10); }); return f(); };
  assert.ok(await waitFor(() => out.includes("ready\n")), `the owner started (${err})`);
  return { child, lines: () => out.split("\n").filter(Boolean), waitFor, kill: async () => { child.kill("SIGKILL"); await exited; }, stop: async () => { child.stdin.end(); child.kill("SIGTERM"); await exited; } };
}

test("T1: a live owner in another process serves the run's snapshot under its own lock, while it stays responsive; the run commits from it", async () => {
  const h = host();
  mkdirSync(join(h.dir, "snapshot"), { mode: 0o700 });
  const o = await owner(h);
  try {
    // The runner can't open the store (the owner holds it): it asks, and waits for the owner's answer.
    const run = h.cmd(["run"]);
    o.child.stdin.write("ping\n");
    assert.ok(await o.waitFor(() => o.lines().includes("pong")), "a concurrent op on the owner completes");
    const out = await run;
    assert.equal(out.line.status, "ok", JSON.stringify(out));
    assert.ok(o.lines().some((l) => l.startsWith('{"status":"served"')), "served by the owner");
    // The manifest's host store is the owner's copy, from the run's own snapshot.
    const m = parseManifest(h.store.snaps().find((s) => s.id === out.line.manifest).text);
    assert.ok(h.store.snaps().find((s) => s.id === m.hoststore).paths[0].startsWith(join(h.dir, "snapshot")));
  } finally { await o.stop(); }
});

test("T1: the owner killed mid-copy: the run is skipped snapshot_unavailable with nothing written; the next run, with a new owner, succeeds and removes the stale result", async () => {
  const h = host();
  mkdirSync(join(h.dir, "snapshot"), { mode: 0o700 });
  // A store with files to copy (each one slow in the owner); no agents (an unpaired host has none).
  const s = await HostStore.open(h.storeRoot);
  await s.close();
  private_(join(h.storeRoot, "config"));
  for (let i = 0; i < 4; i += 1) writeFileSync(join(h.storeRoot, "config", `f${i}`), "x", { mode: 0o600 });
  const slow = await owner(h, "slow");
  const killer = (async () => {
    const snap = join(h.dir, "snapshot");
    await slow.waitFor(() => existsSync(snap) && readdirSync(snap).some((n) => n !== "request.json" && existsSync(join(snap, n, "hoststore"))));
    await slow.kill();
  })();
  let t = 0;
  const first = await h.cmd(["run"], { snapshot: (run, g) => runSnapshot(run, { dir: join(h.dir, "snapshot"), root: h.storeRoot, openStore: () => HostStore.open(h.storeRoot), uid: UID, guard: g,
    waitMs: 60_000, pollMs: 1000, now: () => t, sleep: async (ms) => { await killer; t += ms; } }) });
  await killer;
  assert.deepEqual(first, { code: 0, line: { v: 1, status: "skipped", why: "snapshot_unavailable" } });
  assert.equal(existsSync(join(h.dir, "state.json")), false, "no debt");
  assert.deepEqual(h.store.ops(), [], "nothing read from or written to the store");
  const stale = readdirSync(join(h.dir, "snapshot")).filter((n) => n !== "request.json");
  assert.equal(stale.length, 1, "the dead owner's partial result is there");
  // The retry: a new owner (a restarted daemon), a new run.
  const o = await owner(h);
  try {
    const next = await h.cmd(["run"]);
    assert.equal(next.line.status, "ok", JSON.stringify(next));
    assert.equal(existsSync(join(h.dir, "snapshot", stale[0])), false, "the stale result removed by the next run first");
  } finally { await o.stop(); }
});

test("the daemon's 5-second check: pending only for a well-formed request with no done yet", async () => {
  const { snapshotPending } = await import("../lib/fleet/host/backup-snapshot.mjs");
  const h = host();
  const dir = private_(join(h.dir, "snapshot"));
  assert.equal(snapshotPending(dir, { uid: UID }), false, "no request");
  writeFileSync(join(dir, "request.json"), "{", { mode: 0o600 });
  assert.equal(snapshotPending(dir, { uid: UID }), false, "a malformed one is ignored");
  const req = { run: "20261126T030000Z-abcdefgh", nonce: "N".repeat(22) };
  writeFileSync(join(dir, "request.json"), JSON.stringify({ v: 1, ...req }) + "\n", { mode: 0o600 });
  assert.equal(snapshotPending(dir, { uid: UID }), true);
  const o = await HostStore.open(h.storeRoot);
  try { takeSnapshot(o, req, { dir, root: h.storeRoot, uid: UID }); } finally { await o.close(); }
  assert.equal(snapshotPending(dir, { uid: UID }), false, "served: not pending");
  assert.equal(snapshotPending(join(h.base, "missing"), { uid: UID }), false, "no directory");
});
