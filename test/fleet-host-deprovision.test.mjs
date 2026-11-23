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
  const m = { objects, trees, epoch, calls: [], refuse: {}, A, uid, unitFile: null };
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
  return { h, A, uid, m, dp, effects, root, close: () => h.close() };
}

/** The fake launcher's four subcommands over the model. */
function launcher(m, args) {
  const ok = (o) => ({ code: 0, stdout: JSON.stringify(o), stderr: "" });
  const flag = (n) => args[args.indexOf(`--${n}`) + 1];
  const head = { epoch: m.epoch, fsid: FSID };
  switch (args[0]) {
    case "identify": return ok({ ...head, object: m.objects.get(`${flag("anchor")}/${flag("name")}`) ?? null });
    case "remove-tree": {
      if (m.refuse["remove-tree"]) return { code: m.refuse["remove-tree"], stdout: "", stderr: "x" };
      const p = `${flag("anchor")}/${flag("name")}`;
      const x = JSON.parse(fs.readFileSync(join(m.root, flag("expect")), "utf8"));
      if (JSON.stringify(x.epoch) !== JSON.stringify(m.epoch)) return { code: 73, stdout: "", stderr: "stale epoch" };
      if (m.objects.has(p) && JSON.stringify(m.objects.get(p)) !== JSON.stringify(x.root)) return { code: 73, stdout: "", stderr: "differs" };
      m.objects.delete(p);
      return { code: 0, stdout: "", stderr: "" };
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
      if (t.archive) return { code: 74, stdout: "", stderr: "exists" };
      if (JSON.stringify(t.live) !== JSON.stringify(x)) return { code: 73, stdout: "", stderr: "differs" };
      t.archive = t.live; t.live = null;
      return { code: 0, stdout: "", stderr: "" };
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
  s.m.refuse["archive-home"] = 75; // the move happened but wasn't confirmed
  let r = await go(s);
  assert.equal(r.step, "home");
  s.m.trees.home.archive = s.m.trees.home.live; s.m.trees.home.live = null; delete s.m.refuse["archive-home"];
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
