// Deprovision design r3.2 §2, §3 (and amendment L1): one pass of a deleted agent's deprovision, against a fake
// launcher that models the objects (identify, inspect-home, archive-home, remove-tree) and a real host store.
// - nothing runs unless BOTH proofs hold; the steps run in order, each verify-act-mark;
// - an object's identity is recorded before it is removed; another object, a stale epoch or a refusal PARKS;
// - the archive follows the retry table; the accounts park while the agent is in a pool; done only after all.
import assert from "node:assert/strict";
import fs from "node:fs";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "./host-linux-only.mjs";
import { newId } from "../lib/fleet/index.mjs";
import { HostStore } from "../lib/fleet/host/host-store.mjs";
import { STEPS } from "../lib/fleet/host/deprovision-record.mjs";
import { deprovisioner } from "../lib/fleet/host/deprovision.mjs";

const BOOT = "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0", FSID = "0000abcd00001234";
const LAUNCH = "/opt/sagebrush/1/bin/sagebrush-agent-launch";
const obj = (x = {}) => ({ type: "dir", mode: 0o700, uid: 0, gid: 0, dev: [8, 1], ino: 5, gen: 1, mnt_id: 30, projid: 0, inherit: false, ...x });

/** The fake host: a store with a deleted agent, a provisioned record, and a launcher over a small object model. */
async function setup({ procs = 0, uidEmpty = true, pool = false } = {}) {
  const root = mkdtempSync(join(tmpdir(), "sb-deprov-"));
  const h = await HostStore.open(join(root, "state"));
  const A = newId();
  const uid = h.registry.addAgent(A, 1);
  h.registry.setState(A, "deleted", "delete");
  const epoch = { boot_id: BOOT, mnt_id: 30 };
  const homeTree = { epoch, fsid: FSID, dir: obj({ mode: 0o755, ino: 11 }), entries: { home: obj({ uid, gid: uid, ino: 12, projid: uid, inherit: true }), "var-tmp": obj({ uid, gid: uid, ino: 13, projid: uid, inherit: true }), sessions: obj({ uid, gid: uid, ino: 14, projid: uid, inherit: true }) } };
  const cfgTree = { epoch, fsid: FSID, dir: obj({ ino: 20, projid: uid, inherit: true }), entries: { "gen-1": obj({ mode: 0o755, ino: 21 }) } };
  h.provisioned.adopt(A, uid, true, homeTree, cfgTree);
  // The object model the fake launcher serves: anchors' objects, and the trees (live or archived).
  const objects = new Map([
    [`/run/sagebrush/binds/${A}`, obj({ ino: 31 })], [`/run/sagebrush/broker/${A}`, obj({ ino: 32, gid: uid, mode: 0o710 })],
    [`/var/lib/sagebrush/creds/${A}`, obj({ ino: 33 })], [`/var/lib/sagebrush/contract/${A}.json`, obj({ type: "file", mode: 0o644, ino: 34 })],
    [`/var/lib/sagebrush/resolv/${A}.conf`, obj({ type: "file", mode: 0o644, ino: 35 })], [`/var/lib/sagebrush/managed/${A}`, obj({ ino: 36 })],
  ]);
  const trees = { home: { live: homeTree, archive: null }, config: { live: cfgTree, archive: null } };
  // syncFail[cmd]: how many of cmd's next syncs fail (a 75 after its effect); syncs: every successful sync, in order.
  const m = { objects, trees, epoch, calls: [], refuse: {}, syncFail: {}, syncs: [], A, uid, unitFile: null };
  const run = async (argv) => {
    m.calls.push(argv);
    if (argv[0] === LAUNCH) return launcher(m, argv.slice(1));
    if (argv[0] === "getent") {
      const [, db, key] = argv;
      const ents = { passwd: m.users ?? [[`sb-${A}`, "x", String(uid), String(uid), "", "", ""]], group: m.groups ?? [[`sb-${A}`, "x", String(uid), ""]] }[db];
      const hit = ents.find((e) => e[0] === key || e[2] === key);
      return hit ? { code: 0, stdout: `${hit.join(":")}\n`, stderr: "" } : { code: 2, stdout: "", stderr: "" };
    }
    if (argv[0] === "userdel") { m.users = []; return { code: 0, stdout: "", stderr: "" }; }
    if (argv[0] === "groupdel") { m.groups = []; return { code: 0, stdout: "", stderr: "" }; }
    if (argv[0] === "mountpoint") return { code: 1, stdout: "", stderr: "" };
    return { code: 0, stdout: "", stderr: "" };
  };
  const unitDir = join(root, "usr/local/lib/systemd/system");
  fs.mkdirSync(unitDir, { recursive: true });
  fs.writeFileSync(join(unitDir, `sagebrush-agent-${A}.service`), "[Unit]\n");
  const effects = [];
  const fsx = { ...fs, lstatSync: (p, o) => Object.assign(Object.create(fs.Stats.prototype), fs.lstatSync(p, o), { uid: 0 }) };
  const dp = deprovisioner({
    store: h, run, launcher: LAUNCH, mount: "/", fsx, root, rootUid: 0,
    procCount: async () => m.procs ?? procs,
    uidProof: async () => ({ empty: m.uidEmpty ?? uidEmpty, holders: (m.uidEmpty ?? uidEmpty) ? [] : ["pid 9"] }),
    daemonReload: async () => { effects.push("daemon-reload"); },
    removeNetwork: async () => { effects.push("network"); },
    brokerRevoke: async () => { effects.push("broker-revoke"); },
    inPool: () => m.pool ?? pool,
  });
  return { h, A, uid, m, dp, effects, root, run, fsx, close: () => h.close() };
}

/** The fake launcher's four subcommands over the model. */
function launcher(m, args) {
  const ok = (o) => ({ code: 0, stdout: JSON.stringify(o), stderr: "" });
  const flag = (n) => args[args.indexOf(`--${n}`) + 1];
  const head = { epoch: m.epoch, fsid: FSID };
  /** After the effect: the syncs, or a 75 when one fails. */
  const sync = (cmd, dirs) => {
    if (m.syncFail[cmd] > 0) { m.syncFail[cmd]--; return { code: 75, stdout: "", stderr: "partial" }; }
    m.syncs.push(...dirs.map((d) => `${cmd} ${d}`));
    return { code: 0, stdout: "", stderr: "" };
  };
  switch (args[0]) {
    case "identify": return ok({ ...head, object: m.objects.get(`${flag("anchor")}/${flag("name")}`) ?? null });
    case "remove-tree": {
      if (m.refuse["remove-tree"]) return { code: m.refuse["remove-tree"], stdout: "", stderr: "x" };
      const p = `${flag("anchor")}/${flag("name")}`;
      const x = JSON.parse(fs.readFileSync(join(m.root, flag("expect")), "utf8"));
      if (JSON.stringify(x.epoch) !== JSON.stringify(m.epoch)) return { code: 73, stdout: "", stderr: "stale epoch" };
      if (m.objects.has(p) && JSON.stringify(m.objects.get(p)) !== JSON.stringify(x.root)) return { code: 73, stdout: "", stderr: "differs" };
      m.objects.delete(p); // (absent already: nothing removed, the anchor still synced)
      return sync("remove-tree", [flag("anchor")]);
    }
    case "inspect-home": {
      const t = m.trees[flag("tree")];
      const v = args.includes("--archive") ? t.archive : t.live;
      return v ? ok(v) : { code: 73, stdout: "", stderr: "sagebrush-agent-launch: identity: the tree is absent" };
    }
    case "archive-home": {
      if (m.refuse["archive-home"]) return { code: m.refuse["archive-home"], stdout: "", stderr: "x" };
      const t = m.trees[flag("tree")];
      const x = JSON.parse(fs.readFileSync(join(m.root, flag("expect")), "utf8"));
      const parents = flag("tree") === "home" ? ["archive", "agents"] : ["archive-config", "agent-config"];
      if (JSON.stringify(x.epoch) !== JSON.stringify(m.epoch)) return { code: 73, stdout: "", stderr: "stale epoch" };
      if (args.includes("--finish")) {
        // No rename: the archive exactly the expected tree, the source absent; then both parents synced again.
        if (t.live || JSON.stringify(t.archive) !== JSON.stringify(x)) return { code: 73, stdout: "", stderr: "differs" };
        return sync("archive-home", parents);
      }
      if (t.archive) return { code: 74, stdout: "", stderr: "exists" };
      if (JSON.stringify(t.live) !== JSON.stringify(x)) return { code: 73, stdout: "", stderr: "differs" };
      t.archive = t.live; t.live = null;
      return sync("archive-home", parents);
    }
    default: return { code: 64, stdout: "", stderr: "usage" };
  }
}

const go = (s) => { s.m.root = s.root; return s.dp.pass(s.A, 10000); };

test("a full pass: every step in order, each object identified then removed, the trees archived, the accounts removed", async () => {
  const s = await setup();
  assert.deepEqual(await go(s), { status: "done", step: null, reason: null });
  const rec = s.h.deprovision.record(s.A);
  assert.deepEqual(rec.steps_done, [...STEPS]);
  assert.equal(rec.done, true);
  assert.deepEqual(s.effects, ["broker-revoke", "daemon-reload", "network"]);
  assert.equal(s.m.objects.size, 0, "every host object removed");
  assert.ok(s.m.trees.home.archive && !s.m.trees.home.live && s.m.trees.config.archive && !s.m.trees.config.live);
  assert.ok(!fs.existsSync(join(s.root, `usr/local/lib/systemd/system/sagebrush-agent-${s.A}.service`)), "the unit file is gone");
  assert.deepEqual(s.m.users, []); assert.deepEqual(s.m.groups, []);
  // Every removal went through identify FIRST, then remove-tree with that identity.
  const order = s.m.calls.filter((c) => c[0] === LAUNCH).map((c) => `${c[1]} ${c.includes("--anchor") ? c[c.indexOf("--anchor") + 1] : c[c.indexOf("--tree") + 1]}`);
  assert.equal(order.indexOf("identify /var/lib/sagebrush/creds") + 1, order.indexOf("remove-tree /var/lib/sagebrush/creds"));
  // The identities recorded before acting.
  for (const k of ["binds", "broker", "creds", "contract", "resolv", "managed", "home", "config"]) assert.ok(rec.identities[k], k);
  // A second pass: already done, nothing runs.
  const n = s.m.calls.length;
  assert.equal((await go(s)).status, "done");
  assert.equal(s.m.calls.length, n);
  await s.close();
});

test("no step runs unless BOTH proofs hold: a process in the cgroup, or the uid held anywhere", async () => {
  for (const o of [{ procs: 1 }, { uidEmpty: false }]) {
    const s = await setup(o);
    const r = await go(s);
    assert.equal(r.status, "pending");
    assert.equal(r.step, "channels");
    assert.deepEqual(s.effects, [], JSON.stringify(o));
    assert.ok(!s.m.calls.some((c) => c[0] === LAUNCH), "the launcher isn't called");
    assert.deepEqual(s.h.deprovision.record(s.A).steps_done, []);
    await s.close();
  }
});

test("another object at a path, a stale epoch, or a launcher refusal parks the step; nothing guessed; the next pass resumes", async () => {
  const s = await setup();
  // The contract file was replaced (another ino) after its identity was recorded? First: record by running until files.
  s.m.refuse["remove-tree"] = 73;
  let r = await go(s);
  assert.deepEqual([r.status, r.step], ["pending", "runtime"]);
  assert.deepEqual(s.h.deprovision.record(s.A).steps_done, ["channels", "unit", "network"]);
  // The recorded identity now differs from what is there: parked, not removed.
  delete s.m.refuse["remove-tree"];
  s.m.objects.set(`/run/sagebrush/binds/${s.A}`, obj({ ino: 99 }));
  r = await go(s);
  assert.match(r.reason, /another object than the recorded one/);
  assert.ok(s.m.objects.has(`/run/sagebrush/binds/${s.A}`));
  // Back to the recorded object, but the epoch moved (a reboot): parked for requalify.
  s.m.objects.set(`/run/sagebrush/binds/${s.A}`, obj({ ino: 31 }));
  s.m.epoch = { boot_id: "11111111-2222-3333-4444-555555555555", mnt_id: 30 };
  r = await go(s);
  assert.match(r.reason, /stale epoch/);
  // The epoch back: it resumes where it parked and finishes.
  s.m.epoch = { boot_id: BOOT, mnt_id: 30 };
  assert.equal((await go(s)).status, "done");
  await s.close();
});

test("a partial removal (75) leaves the step pending; the next pass retries and converges", async () => {
  const s = await setup();
  s.m.refuse["remove-tree"] = 75;
  assert.match((await go(s)).reason, /partly removed/);
  delete s.m.refuse["remove-tree"];
  assert.equal((await go(s)).status, "done");
  await s.close();
});

test("the archive's retry table: moved before its mark; both present; neither; a source that isn't the provisioned tree", async () => {
  // A crash right after the rename: the next pass finds the exact recorded object in the archive and marks it.
  const s = await setup();
  s.m.syncFail["archive-home"] = 1; // the move happened; a sync after it failed (75)
  let r = await go(s);
  assert.equal(r.step, "home");
  assert.ok(s.m.trees.home.archive && !s.m.trees.home.live, "moved");
  assert.equal((await go(s)).status, "done");
  await s.close();
  // Moved before its mark, but the archive isn't the recorded object (a substitute in the archive): parked.
  const d = await setup();
  d.m.refuse["archive-home"] = 75;
  await go(d);
  const moved = structuredClone(d.m.trees.home.live); moved.entries.sessions.gen = 42;
  d.m.trees.home.archive = moved; d.m.trees.home.live = null; delete d.m.refuse["archive-home"];
  assert.match((await go(d)).reason, /the archive differs from the recorded identity/);
  assert.ok(!d.h.deprovision.record(d.A).steps_done.includes("home"));
  await d.close();
  // Both present: parked, nothing moved.
  const b = await setup();
  b.m.trees.home.archive = structuredClone(b.m.trees.home.live);
  assert.match((await go(b)).reason, /both the source and the archive exist/);
  await b.close();
  // Neither (after the identity was recorded): parked, never taken as success.
  const n = await setup();
  n.m.refuse["archive-home"] = 73;
  await go(n);
  delete n.m.refuse["archive-home"];
  n.m.trees.home.live = null;
  assert.match((await go(n)).reason, /neither the source nor the archive exists/);
  await n.close();
  // A source that isn't the provisioned tree (a substitute): parked before anything is recorded.
  const x = await setup();
  x.m.trees.home.live = structuredClone(x.m.trees.home.live); x.m.trees.home.live.entries.home.ino = 999;
  assert.match((await go(x)).reason, /not the provisioned tree/);
  assert.equal(x.h.deprovision.record(x.A).identities.home, undefined);
  await x.close();
});

test("an archive moved with a 75 at a sync: done only after archive-home --finish syncs both parents again; a failing finish stays pending", async () => {
  const s = await setup();
  s.m.syncFail["archive-home"] = 1;
  assert.match((await go(s)).reason, /home: moved, not yet confirmed/);
  // The next two finishes fail at their own syncs: still pending, never marked.
  s.m.syncFail["archive-home"] = 2;
  for (let i = 0; i < 2; i++) {
    const r = await go(s);
    assert.deepEqual([r.step, /not yet confirmed durable/.test(r.reason)], ["home", true]);
    assert.ok(!s.h.deprovision.record(s.A).steps_done.includes("home"));
  }
  s.m.syncs.length = 0;
  assert.equal((await go(s)).status, "done");
  const finishes = s.m.calls.filter((c) => c[1] === "archive-home" && c.includes("--finish"));
  assert.equal(finishes.length, 3, "every retry of a moved tree goes through --finish");
  assert.deepEqual(s.m.syncs.slice(0, 2), ["archive-home archive", "archive-home agents"], "both parents synced before the mark");
  await s.close();
  // A finish in another epoch (a reboot after the move): parked (requalify), not marked.
  const e = await setup();
  e.m.syncFail["archive-home"] = 1;
  await go(e);
  e.m.epoch = { boot_id: BOOT, mnt_id: 31 };
  e.m.trees.home.archive = { ...e.m.trees.home.archive, epoch: e.m.epoch };
  assert.match((await go(e)).reason, /stale epoch/);
  assert.ok(!e.h.deprovision.record(e.A).steps_done.includes("home"));
  await e.close();
});

test("a 75 at remove-tree's final sync, then the object is absent: the recorded identity still goes to the launcher, which syncs the anchor; a stale epoch parks", async () => {
  const s = await setup();
  s.m.syncFail["remove-tree"] = 2; // the first object's remove-tree, then its first retry
  const r1 = await go(s);
  assert.match(r1.reason, /partly removed/);
  const first = r1.reason.split(":")[0];
  assert.ok(s.h.deprovision.record(s.A).identities[first], "its identity recorded");
  // Absent now, with a recorded identity: remove-tree is still called (and fails its sync again): pending.
  const before = s.m.calls.filter((c) => c[1] === "remove-tree").length;
  assert.match((await go(s)).reason, /partly removed/);
  assert.equal(s.m.calls.filter((c) => c[1] === "remove-tree").length, before + 1);
  assert.equal((await go(s)).status, "done");
  await s.close();
  // Removed with a 75, then a reboot: the absent object's stale recorded epoch parks; never marked.
  const t = await setup();
  t.m.syncFail["remove-tree"] = 1;
  const r = await go(t);
  const key = r.reason.split(":")[0];
  t.m.epoch = { boot_id: "11111111-2222-3333-4444-555555555555", mnt_id: 30 };
  const p = await go(t);
  assert.match(p.reason, new RegExp(`${key}: remove-tree refused \\(73\\)`));
  assert.equal(t.h.deprovision.record(t.A).steps_done.length, STEPS.indexOf(r.step));
  await t.close();
  // Never recorded and absent: nothing to do, no remove-tree for it.
  const n = await setup();
  n.m.objects.delete(`/var/lib/sagebrush/creds/${n.A}`);
  assert.equal((await go(n)).status, "done");
  assert.ok(!n.m.calls.some((c) => c[1] === "remove-tree" && c.includes("/var/lib/sagebrush/creds")));
  await n.close();
});

test("every seam takes the pass's remaining time and its signal; an aborted signal ends a hung proof or broker revoke, with nothing marked", async () => {
  const s = await setup();
  s.m.root = s.root;
  const seen = [];
  const ac = new AbortController();
  const note = (name) => (...a) => { const sig = a.at(-1); const ms = a.at(-2); seen.push([name, sig === ac.signal, typeof ms === "number" && ms > 0 && ms <= 10000]); };
  const wrap = (name, f) => async (...a) => { note(name)(...a); return f(...a); };
  // Re-make the pass with recording seams (the same model).
  const { deprovisioner: mk } = await import("../lib/fleet/host/deprovision.mjs");
  const effects = [];
  const run0 = async (argv, o) => { seen.push([`run ${argv[0] === LAUNCH ? argv[1] : argv[0]}`, o.signal === ac.signal, typeof o.ms === "number" && o.ms > 0]); return s.run(argv, o); };
  const dp = mk({
    store: s.h, run: run0, launcher: LAUNCH, mount: "/", fsx: s.fsx, root: s.root, rootUid: 0,
    procCount: wrap("procCount", async () => 0),
    uidProof: wrap("uidProof", async () => ({ empty: true, holders: [] })),
    daemonReload: wrap("daemonReload", async () => { effects.push("daemon-reload"); }),
    removeNetwork: async (agent, uid, left, signal) => { seen.push(["removeNetwork", signal === ac.signal, left() > 0]); },
    brokerRevoke: wrap("brokerRevoke", async () => {}),
    inPool: () => false,
  });
  assert.equal((await dp.pass(s.A, 10000, ac.signal)).status, "done");
  for (const [name, sig, ms] of seen) assert.ok(sig && ms, `${name}: signal ${sig}, time ${ms}`);
  for (const k of ["procCount", "uidProof", "daemonReload", "removeNetwork", "brokerRevoke", "run identify", "run remove-tree", "run archive-home", "run inspect-home", "run getent", "run userdel"]) {
    assert.ok(seen.some((x) => x[0] === k), k);
  }
  await s.close();
  // A hung broker revoke and a hung proof, each honouring only its signal: the abort ends the pass, nothing marked.
  for (const hung of ["brokerRevoke", "procCount", "uidProof"]) {
    const t = await setup();
    t.m.root = t.root;
    const a2 = new AbortController();
    const wait = (sig) => new Promise((_, rej) => sig.addEventListener("abort", () => rej(new Error("aborted")), { once: true }));
    const seams = {
      procCount: async () => 0, uidProof: async () => ({ empty: true, holders: [] }), brokerRevoke: async () => {},
      [hung]: async (...a) => wait(a.at(-1)),
    };
    const dp2 = mk({ store: t.h, run: t.run, launcher: LAUNCH, mount: "/", fsx: t.fsx, root: t.root, rootUid: 0, ...seams, daemonReload: async () => {}, removeNetwork: async () => {}, inPool: () => false });
    setTimeout(() => a2.abort(), 30);
    const r = await dp2.pass(t.A, 10000, a2.signal).then((x) => x, (e) => ({ threw: e.message }));
    assert.ok(r.threw || r.status === "pending", `${hung}: ${JSON.stringify(r)}`);
    assert.deepEqual(t.h.deprovision.record(t.A).steps_done, [], hung);
    await t.close();
  }
});

test("an adapter that settles AFTER the abort: nothing after it runs: no mark, no unit unlinked, no daemon-reload; an already-aborted pass doesn't even make its record", async () => {
  const { deprovisioner: mk } = await import("../lib/fleet/host/deprovision.mjs");
  const unitOf = (t) => join(t.root, `usr/local/lib/systemd/system/sagebrush-agent-${t.A}.service`);
  // Each adapter ignores the signal and returns after the abort.
  for (const late of ["brokerRevoke", "procCount", "uidProof", "removeNetwork"]) {
    const t = await setup();
    t.m.root = t.root;
    const ac = new AbortController();
    const effects = [];
    const lateFn = async () => { await new Promise((r) => setTimeout(r, 40)); return late === "procCount" ? 0 : late === "uidProof" ? { empty: true, holders: [] } : undefined; };
    const seams = { procCount: async () => 0, uidProof: async () => ({ empty: true, holders: [] }), brokerRevoke: async () => {}, removeNetwork: async () => {}, [late]: lateFn };
    // removeNetwork comes after channels and unit: let those run first, then abort while it is in flight.
    const dp = mk({ store: t.h, run: t.run, launcher: LAUNCH, mount: "/", fsx: t.fsx, root: t.root, rootUid: 0, ...seams,
      daemonReload: async () => { effects.push("daemon-reload"); }, inPool: () => false });
    setTimeout(() => ac.abort(), 10);
    const r = await dp.pass(t.A, 10000, ac.signal).then((x) => x, (e) => ({ threw: e.message, aborted: e.aborted }));
    assert.equal(r.aborted, true, `${late}: ${JSON.stringify(r)}`);
    const done = t.h.deprovision.record(t.A).steps_done;
    if (late === "removeNetwork") {
      assert.deepEqual(done, ["channels", "unit"], "the steps before the abort stay marked; network is never marked");
    } else {
      assert.deepEqual(done, [], `${late}: nothing marked after a late settlement`);
      assert.ok(fs.existsSync(unitOf(t)), `${late}: the unit file was not unlinked`);
      assert.deepEqual(effects, [], `${late}: no daemon-reload`);
    }
    const before = t.m.calls.length;
    await new Promise((r) => setTimeout(r, 60)); // anything still pending would now run: nothing does
    assert.equal(t.m.calls.length, before, `${late}: no launcher call after the abort`);
    await t.close();
  }
  // A pass admitted with an already-aborted signal, or with no time left: no record, no proof, no effect.
  for (const [name, signal, ms] of [["aborted", AbortSignal.abort(), 10000], ["no time", undefined, 0]]) {
    const t = await setup();
    t.m.root = t.root;
    let proofs = 0;
    const dp = mk({ store: t.h, run: t.run, launcher: LAUNCH, mount: "/", fsx: t.fsx, root: t.root, rootUid: 0,
      procCount: async () => { proofs++; return 0; }, uidProof: async () => ({ empty: true, holders: [] }),
      brokerRevoke: async () => {}, removeNetwork: async () => {}, daemonReload: async () => {}, inPool: () => false });
    await assert.rejects(dp.pass(t.A, ms, signal), (e) => e.aborted === true, name);
    assert.equal(t.h.deprovision.record(t.A), null, `${name}: no record made`);
    assert.equal(proofs, 0, `${name}: no proof taken`);
    assert.equal(t.m.calls.length, 0, `${name}: no launcher call`);
    await t.close();
  }
});

test("an abort or the deadline at EVERY point of a pass: after it, no effect starts and no step is marked", async () => {
  // A sweep over the pass's points: each adapter or command settling (an abort, or the deadline passing, while it was in
  // flight), and each synchronous filesystem read or store write (the deadline passing during slow I/O). After the
  // trigger, nothing with an effect may start: no command, no adapter, no record, identity or mark, no file made,
  // written, renamed, unlinked or removed (expect files included). An expect file already being written is finished
  // whole, so the read inside that write is not a point.
  const { deprovisioner: mk } = await import("../lib/fleet/host/deprovision.mjs");
  const realNow = Date.now;
  let skew = 0;
  Date.now = () => realNow() + skew;
  try {
    const make = async (trigger) => {
      const t = await setup();
      t.m.root = t.root;
      const ac = new AbortController();
      const log = { points: 0, fired: false, after: [] };
      const point = (name, sync) => {
        log.points++;
        if (log.points !== trigger?.at) return;
        log.fired = name;
        if (sync || trigger.kind === "deadline") skew += 1e7; else ac.abort();
      };
      const effect = (name) => { if (log.fired) log.after.push(name); };
      const seam = (name, f, isEffect = true) => async (...a) => { if (isEffect) effect(name); const v = await f(...a); point(name); return v; };
      const run = seam("run", async (argv, o) => t.run(argv, o));
      const inExpect = (p) => String(p).endsWith("/run/sagebrush/deprovision");
      const fsx = { ...t.fsx };
      for (const k of ["unlinkSync", "rmSync", "renameSync", "mkdirSync", "writeFileSync"]) {
        fsx[k] = (p, ...a) => { effect(`${k} ${p}`); return t.fsx[k](p, ...a); };
      }
      fsx.openSync = (p, flags, ...a) => { if (flags !== "r") effect(`openSync ${p}`); return t.fsx.openSync(p, flags, ...a); };
      for (const k of ["lstatSync", "readdirSync", "readFileSync"]) {
        fsx[k] = (...a) => { const v = t.fsx[k](...a); if (!inExpect(a[0])) point(`${k} ${a[0]}`, true); return v; };
      }
      const dpr = t.h.deprovision;
      for (const k of ["ensure", "recordIdentity", "markStep"]) {
        const f = dpr[k].bind(dpr);
        dpr[k] = (...a) => { effect(k); const v = f(...a); point(k, true); return v; };
      }
      const dp = mk({ store: t.h, run, launcher: LAUNCH, mount: "/", fsx, root: t.root, rootUid: 0,
        procCount: seam("procCount", async () => 0), uidProof: seam("uidProof", async () => ({ empty: true, holders: [] })),
        brokerRevoke: seam("brokerRevoke", async () => {}), removeNetwork: seam("removeNetwork", async () => {}),
        daemonReload: seam("daemonReload", async () => {}), inPool: () => false });
      return { t, ac, log, dp };
    };
    const base = await make(null);
    assert.equal((await base.dp.pass(base.t.A, 10000, base.ac.signal)).status, "done");
    const n = base.log.points;
    await base.t.close();
    assert.ok(n > 40, `the sweep covers the pass (${n} points)`);
    let rejected = 0;
    for (let at = 1; at <= n; at++) {
      for (const kind of ["abort", "deadline"]) {
        skew = 0;
        const { t, ac, log, dp } = await make({ at, kind });
        const marked = () => t.h.deprovision.record(t.A)?.steps_done.length ?? 0;
        let r;
        try { r = await dp.pass(t.A, 10000, ac.signal); } catch (e) { r = { threw: e.message, aborted: e.aborted }; }
        const what = `point ${at} (${log.fired}, ${kind}): ${JSON.stringify(r)}`;
        assert.ok(log.fired, what);
        assert.deepEqual(log.after, [], `${what}: effects after the trigger`);
        if (r.threw) { assert.equal(r.aborted, true, what); rejected++; } else assert.equal(r.status, "done", what);
        if (r.threw) assert.ok(marked() < STEPS.length, `${what}: not all marked`);
        await t.close();
      }
    }
    assert.ok(rejected >= 2 * n - 4, `nearly every point ends the pass aborted (${rejected} of ${2 * n})`);
  } finally {
    Date.now = realNow;
  }
});

test("the accounts step parks while the agent is in a harness pool; another uid on the name is refused", async () => {
  const s = await setup({ pool: true });
  const r = await go(s);
  assert.deepEqual([r.status, r.step], ["pending", "accounts"]);
  assert.match(r.reason, /pool/);
  assert.ok(!s.m.calls.some((c) => c[0] === "userdel"));
  s.m.pool = false;
  s.m.users = [[`sb-${s.A}`, "x", "70999", "70999", "", "", ""]];
  assert.match((await go(s)).reason, /another uid/);
  assert.ok(!s.m.calls.some((c) => c[0] === "userdel"));
  await s.close();
});

test("only a deleted agent; a record bound to another life is refused", async () => {
  const s = await setup();
  const B = newId();
  s.h.registry.addAgent(B, 1);
  await assert.rejects(s.dp.pass(B, 1000), /only a deleted agent/);
  await s.close();
});
