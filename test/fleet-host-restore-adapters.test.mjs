// Host backup r3.3 §5 steps 6-9 (launcher amendments A1 r2.6, A2 r3.10): restore-fill's real adapters, each a thin call
// into the launcher or the host's helpers, against a scripted launcher and a temporary root. Identities come only from
// the launcher; tree-digest runs in its bounded scope; what isn't in the launcher yet is refused, never improvised.
import assert from "node:assert/strict";
import fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "./host-linux-only.mjs";
import { FleetError, newId } from "../lib/fleet/index.mjs";
import { EXPECT_DIR, archiveLimits, restoreAdapters } from "../lib/fleet/host/restore-adapters.mjs";
import { RESTORE_STAGING, VALIDATE_DIR, fenceFiles } from "../lib/fleet/host/names.mjs";
import { newRestoreRun } from "../lib/fleet/host/restore-record.mjs";
import { needOf } from "../lib/fleet/host/restore-space.mjs";
import { uidEmpty } from "../lib/fleet/host/uid-proof.mjs";

const LAUNCHER = "/usr/lib/sagebrush/sagebrush-agent-launch";
const refused = (p, code) => assert.rejects(p, (e) => e instanceof FleetError && e.code === code, code);
const hostSide = (p) => assert.rejects(p, (e) => !(e instanceof FleetError) && e.code === "effect_failed");
const ME = { uid: process.getuid(), gid: process.getgid() };
const RUN = newRestoreRun(1795500000000, () => Buffer.alloc(6)), RUN2 = newRestoreRun(1795600000000, () => Buffer.alloc(6, 1));
const EPOCH = { boot_id: "00000000-0000-4000-8000-000000000000", mnt_id: 7 };
const FSID = "0123456789abcdef";
const obj = (over = {}) => ({ type: "dir", mode: 0o700, uid: 70001, gid: 70001, dev: [8, 1], ino: 100, gen: 1, mnt_id: 7, projid: 70001, inherit: true, ...over });
const inspectOut = (over = {}) => ({ epoch: EPOCH, fsid: FSID, dir: obj({ uid: 0, gid: 0, mode: 0o755, ino: 99 }),
  entries: { home: obj({ ino: 101 }), sessions: obj({ ino: 102 }), "var-tmp": obj({ ino: 103 }) }, ...over });
const identified = (o = obj({ uid: 0, gid: 0, mode: 0o755, ino: 200 })) => ({ epoch: EPOCH, fsid: FSID, object: o });
const USAGE = { block_size: 4096, blocks_upper: 10, inodes: 6, peak_blocks_upper: 14, peak_inodes: 9 };

/**
 * A world: a temporary root, a restored registry (two live members of one tag, one deleted agent), the provisioned
 * records (`provisioned(ids)`: by default the live agent `a`'s), and a scripted launcher (`script(argv)` may answer).
 */
function world({ script = () => null, provisioned = (ids) => ({ [ids.a]: { uid: 70001, quota: true, home: inspectOut(), config: {} } }),
  procs = () => 0, proofs = () => ({ empty: true }) } = {}) {
  const root = fs.mkdtempSync(join(tmpdir(), "sb-adapt-"));
  fs.mkdirSync(join(root, "var/lib/sagebrush"), { recursive: true });
  const ids = { a: newId(), b: newId(), dead: newId(), t: newId() };
  const registry = { v: 1, next_uid: 70010, next_gid: 80002, tags: { [ids.t]: { gid: 80001 } }, agents: {
    [ids.a]: { uid: 70001, state: "stopped", life: 0, gen: 0, tags: [ids.t], start_failed: null },
    [ids.b]: { uid: 70002, state: "stopped", life: 0, gen: 0, tags: [ids.t], start_failed: null },
    [ids.dead]: { uid: 70003, state: "deleted", life: 1, gen: 0, tags: [], start_failed: null },
  } };
  const recs = provisioned(ids);
  const calls = [], reports = [], archived = [], procAsked = [], proofAsked = [], proofPairs = [];
  const run = async (argv, { ms }) => {
    assert.ok(ms > 0);
    calls.push(argv);
    const s = script(argv, ids);
    if (s) return { stdout: "", stderr: "", ...s };
    const args = argv[0] === LAUNCHER ? argv.slice(1) : argv;
    if (args[0] === "inspect-home") return { code: 0, stdout: JSON.stringify(inspectOut()), stderr: "" };
    if (args[0] === "identify") return { code: 0, stdout: JSON.stringify(identified()), stderr: "" };
    return { code: 0, stdout: "", stderr: "" };
  };
  const store = { provisioned: { record: (id) => (Object.hasOwn(recs, id) ? structuredClone(recs[id]) : null) } };
  const provisioner = { archive: async (...x) => { archived.push(x); } };
  const ad = restoreAdapters({
    run, launcher: LAUNCHER, mount: "/srv/sagebrush", store, registry: () => registry, provisioner,
    usageOf: async () => USAGE, unrestorable: (k, i, c) => [`${k}/${c}`],
    procCount: async (x) => { procAsked.push(x); return procs(x); }, uidProof: async (u, agent) => { proofAsked.push(u); proofPairs.push([agent, u]); return proofs(u, agent); },
    report: (e) => reports.push(e), root, rootUid: ME.uid, rootGid: ME.gid, ms: 5000,
  });
  const mk = (p) => fs.mkdirSync(join(root, p), { recursive: true });
  return { root, ad, calls, reports, archived, procAsked, proofAsked, proofPairs, ids, registry, mk };
}
const launcherCalls = (w, sub) => w.calls.filter((c) => c[0] === LAUNCHER && c[1] === sub);

test("launch: the launcher by argv; tree-digest in its transient scope, exactly; any other scope refused", async () => {
  const w = world();
  await w.ad.launch(["fill-home", "--mount", "/srv/sagebrush"]);
  assert.deepEqual(w.calls.at(-1), [LAUNCHER, "fill-home", "--mount", "/srv/sagebrush"]);
  const unit = `sagebrush-validate-a-${w.ids.a}.scope`;
  await w.ad.launch(["tree-digest", "--class", "home"], { scope: { unit, memoryMax: "1G", runtimeMaxSec: 900 } });
  assert.deepEqual(w.calls.at(-1), ["systemd-run", "--scope", "--quiet", "--collect", `--unit=${unit}`, "--property=MemoryMax=1G",
    "--property=RuntimeMaxSec=900", "--", LAUNCHER, "tree-digest", "--class", "home"]);
  await w.ad.launch(["tree-digest"], { scope: { unit: `sagebrush-validate-t-${w.ids.t}.scope`, memoryMax: "1G", runtimeMaxSec: 1 } });
  const n = w.calls.length;
  for (const scope of [null, {}, { unit: "x.scope", memoryMax: "1G", runtimeMaxSec: 9 }, { unit, memoryMax: "2G", runtimeMaxSec: 9 },
    { unit, memoryMax: "1G", runtimeMaxSec: 0 }, { unit, memoryMax: "1G", runtimeMaxSec: 1.5 }, { unit, memoryMax: "1G", runtimeMaxSec: 86401 },
    { unit: `${unit} --property=MemoryMax=infinity`, memoryMax: "1G", runtimeMaxSec: 9 }, { unit: `sagebrush-validate-x-${w.ids.a}.scope`, memoryMax: "1G", runtimeMaxSec: 9 }]) {
    assert.throws(() => w.ad.launch(["tree-digest"], { scope }), (e) => e.code === "bad_form", JSON.stringify(scope));
  }
  assert.throws(() => w.ad.launch("tree-digest"), (e) => e.code === "bad_form");
  assert.throws(() => w.ad.launch(["tree-digest", 1]), (e) => e.code === "bad_form");
  assert.equal(w.calls.length, n, "nothing ran");
});

test("ready and identifyDest: a live agent needs this host's provisioning, the same objects, and empty trees", async () => {
  // Never provisioned here (no grant yet): waiting, and nothing asked of the launcher.
  const fresh = world({ provisioned: () => ({}) });
  assert.deepEqual(await fresh.ad.ready("agent", fresh.ids.a), { ready: false, why: "waiting for this host's grant" });
  await refused(fresh.ad.identifyDest("agent", fresh.ids.a, "home"), "not_found");
  assert.deepEqual(fresh.calls, []);
  // Provisioned, the same objects, both trees empty: ready; the identity is the launcher's entry, in this epoch.
  const w = world();
  for (const c of ["home", "sessions"]) w.mk(`srv/sagebrush/agents/${w.ids.a}/${c}`);
  assert.deepEqual(await w.ad.ready("agent", w.ids.a), { ready: true });
  assert.deepEqual(await w.ad.identifyDest("agent", w.ids.a, "sessions"), { epoch: EPOCH, fsid: FSID, object: obj({ ino: 102 }) });
  assert.deepEqual(await w.ad.identifyDest("agent", w.ids.a, "home"), { epoch: EPOCH, fsid: FSID, object: obj({ ino: 101 }) });
  assert.deepEqual(launcherCalls(w, "inspect-home").at(-1), [LAUNCHER, "inspect-home", "--mount", "/srv/sagebrush", "--agent", w.ids.a, "--tree", "home"]);
  // Another epoch, the same durable objects (a reboot): still the provisioned trees.
  const later = world({ script: (argv) => (argv[1] === "inspect-home" ? { code: 0, stdout: JSON.stringify(inspectOut({ epoch: { ...EPOCH, mnt_id: 9 } })) } : null) });
  assert.deepEqual((await later.ad.identifyDest("agent", later.ids.a, "home")).epoch, { ...EPOCH, mnt_id: 9 });
  // Not empty, either tree: not ready (fill-home would refuse it anyway).
  for (const c of ["sessions", "home"]) {
    const p = join(w.root, `srv/sagebrush/agents/${w.ids.a}/${c}/x`);
    fs.writeFileSync(p, "");
    assert.deepEqual(await w.ad.ready("agent", w.ids.a), { ready: false, why: "its provisioned trees aren't empty" }, c);
    fs.rmSync(p);
  }
  // Another object than the provisioned one (a substitute): refused, for ready and identifyDest alike.
  const subst = (argv) => (argv[1] === "inspect-home" ? { code: 0, stdout: JSON.stringify(inspectOut({ entries: { ...inspectOut().entries, home: obj({ ino: 999 }) } })) } : null);
  const s = world({ script: subst });
  await refused(s.ad.ready("agent", s.ids.a), "not_granted");
  await refused(s.ad.identifyDest("agent", s.ids.a, "home"), "not_granted");
  // The launcher refusing, or printing something else: host-side, never an identity.
  for (const out of [{ code: 73 }, { code: 0, stdout: "x" }, { code: 0, stdout: JSON.stringify({ epoch: EPOCH }) }]) {
    const x = world({ script: (argv) => (argv[1] === "inspect-home" ? out : null) });
    await hostSide(x.ad.identifyDest("agent", x.ids.a, "home"));
  }
  await refused(w.ad.identifyDest("agent", w.ids.a, "archive"), "bad_form");
  await refused(w.ad.identifyDest("agent", w.ids.a, "var-tmp"), "bad_form");
});

test("a tag folder: identified on the read-only tags anchor (A1 r2.7); ready once a member's grant provisioned it, empty", async () => {
  const w = world();
  assert.deepEqual(await w.ad.identifyDest("tag", w.ids.t, "tag"), identified());
  assert.deepEqual(launcherCalls(w, "identify").at(-1), [LAUNCHER, "identify", "--anchor", "/srv/sagebrush/tags", "--name", w.ids.t]);
  w.mk(`srv/sagebrush/tags/${w.ids.t}`);
  assert.deepEqual(await w.ad.ready("tag", w.ids.t), { ready: true });
  fs.writeFileSync(join(w.root, `srv/sagebrush/tags/${w.ids.t}/x`), "");
  assert.deepEqual(await w.ad.ready("tag", w.ids.t), { ready: false, why: "its provisioned folder isn't empty" });
  // Not there yet: waiting for the grant that provisions it.
  const g = world({ script: (argv) => (argv[1] === "identify" ? { code: 0, stdout: JSON.stringify({ epoch: EPOCH, fsid: FSID, object: null }) } : null) });
  assert.deepEqual(await g.ad.ready("tag", g.ids.t), { ready: false, why: "waiting for this host's grant" });
  await refused(g.ad.identifyDest("tag", g.ids.t, "tag"), "not_found");
  // A launcher without the tags row (64), or odd output: host-side, never started.
  for (const out of [{ code: 64 }, { code: 0, stdout: JSON.stringify({ object: null }) }, { code: 0, stdout: "{" }]) {
    const x = world({ script: (argv) => (argv[1] === "identify" ? out : null) });
    await hostSide(x.ad.ready("tag", x.ids.t));
    await hostSide(x.ad.identifyDest("tag", x.ids.t, "tag"));
  }
  await refused(w.ad.identifyDest("tag", w.ids.t, "home"), "bad_form");
  await refused(w.ad.ready("tag", "../x"), "bad_form");
});

test("archives: provisioned by restore under exactly the measured need; identified by the launcher's archive anchor", async () => {
  // The limit: needOf's project bounds for the class (4 KiB blocks, inodes at the larger phase) plus the config
  // archive's own directory, in setquota's units.
  const n = needOf([USAGE]).project;
  assert.deepEqual(archiveLimits(USAGE), { kib: (n.blocks + 1) * 4, inodes: n.inodesMax + 1 });
  assert.deepEqual(archiveLimits(USAGE), { kib: (Math.max(10 + 3, 14 + 2) + 1) * 4, inodes: Math.max(6 + 4, 9 + 3) + 1 });
  assert.throws(() => archiveLimits({ ...USAGE, block_size: 1024 }), (e) => e.code === "bad_form");
  const w = world();
  await w.ad.provisionArchive(w.ids.dead);
  assert.deepEqual(w.archived.map((x) => x.slice(0, 3)), [[w.ids.dead, 70003, archiveLimits(USAGE)]]);
  for (const id of [w.ids.a, newId()]) await refused(w.ad.provisionArchive(id), "not_found");
  // Identified through identify on the archive anchor; absent is "not provisioned".
  assert.deepEqual(await w.ad.ready("archive", w.ids.dead), { ready: true });
  assert.deepEqual(await w.ad.identifyDest("archive", w.ids.dead, "archive"), identified());
  assert.deepEqual(launcherCalls(w, "identify").at(-1), [LAUNCHER, "identify", "--anchor", "/srv/sagebrush/archive", "--name", w.ids.dead]);
  const gone = world({ script: (argv) => (argv[1] === "identify" ? { code: 0, stdout: JSON.stringify({ epoch: EPOCH, fsid: FSID, object: null }) } : null) });
  assert.deepEqual(await gone.ad.ready("archive", gone.ids.dead), { ready: false, why: "the archive isn't provisioned" });
  await refused(gone.ad.identifyDest("archive", gone.ids.dead, "archive"), "not_found");
  const odd = world({ script: (argv) => (argv[1] === "identify" ? { code: 0, stdout: JSON.stringify({ epoch: EPOCH, fsid: "x", object: obj() }) } : null) });
  await hostSide(odd.ad.identifyDest("archive", odd.ids.dead, "archive"));
});

test("expectOf and projidOf: fill-home's closed expect from the launcher's identity and the restored registry, root-only", async () => {
  const w = world();
  const id = { epoch: EPOCH, fsid: FSID, object: obj({ ino: 101 }) };
  const p = await w.ad.expectOf("agent", w.ids.a, "home", id);
  assert.equal(p, join(w.root, EXPECT_DIR, `agent-${w.ids.a}-home.json`));
  assert.deepEqual(JSON.parse(fs.readFileSync(p, "utf8")), { epoch: EPOCH, fsid: FSID, dest: obj({ ino: 101 }), uids: [70001], gid: 70001, projid: 70001 });
  assert.equal(fs.statSync(p).mode & 0o777, 0o600);
  assert.equal(fs.statSync(join(w.root, EXPECT_DIR)).mode & 0o777, 0o700);
  // A tag's owners are its live members; an archive's the deleted agent's uid.
  assert.equal(w.ad.projidOf("tag", w.ids.t), 80001);
  assert.equal(w.ad.projidOf("archive", w.ids.dead), 70003);
  await refused(w.ad.expectOf("agent", w.ids.a, "home", { ...id, object: obj({ projid: 70002 }) }), "not_granted");
});

test("cleanDest: the pinned destination emptied by remove-tree --contents, its proofs taken afresh before every call", async () => {
  const fence = (w, x) => { const p = join(w.root, fenceFiles(x).restore); fs.mkdirSync(join(p, ".."), { recursive: true }); fs.writeFileSync(p, ""); };
  const dev = String(8 * 2 ** 20 + 1);
  const agentSet = (w, over = {}) => ({ kind: "agent", id: w.ids.a, run: RUN, attempt: 2, state: "staging", dirty: true,
    dest: { home: { dev, ino: "101" }, sessions: { dev, ino: "102" } }, ...over });
  // Each launcher call sees how many proofs were taken before it.
  const seen = [];
  const w = world({ script: (argv) => { if (argv[2] === "--contents") seen.push([argv[6], w.procAsked.length, w.proofAsked.length]); return null; } });
  fence(w, w.ids.a);
  await w.ad.cleanDest(agentSet(w));
  const rms = launcherCalls(w, "remove-tree");
  assert.deepEqual(rms.map((c) => c.slice(1, 7)), [
    ["remove-tree", "--contents", "--anchor", "/srv/sagebrush/agents", "--name", `${w.ids.a}/home`],
    ["remove-tree", "--contents", "--anchor", "/srv/sagebrush/agents", "--name", `${w.ids.a}/sessions`],
  ]);
  assert.deepEqual(JSON.parse(fs.readFileSync(rms[0][8], "utf8")), { epoch: EPOCH, fsid: FSID, root: obj({ ino: 101 }), owners: [0, 70001] });
  assert.deepEqual(seen, [[`${w.ids.a}/home`, 1, 1], [`${w.ids.a}/sessions`, 2, 2]], "fresh proofs before EACH call");
  // A tag folder: every member fenced and proven; owners root plus the members.
  const t = world();
  for (const x of [t.ids.a, t.ids.b]) fence(t, x);
  await t.ad.cleanDest({ kind: "tag", id: t.ids.t, run: RUN, attempt: 1, state: "staging", dirty: true, dest: { tag: { dev, ino: "200" } } });
  const trm = launcherCalls(t, "remove-tree")[0];
  assert.deepEqual(trm.slice(3, 7), ["--anchor", "/srv/sagebrush/tags", "--name", t.ids.t]);
  assert.deepEqual(JSON.parse(fs.readFileSync(trm[8], "utf8")).owners, [0, 70001, 70002]);
  assert.deepEqual(t.proofPairs, [t.ids.a, t.ids.b].sort().map((x) => [x, t.registry.agents[x].uid]));
  // One member's user still lingers (a proof that depends on the agent asked for): refused, nothing removed; then,
  // once it's gone, the retry proves again and empties the folder.
  let lingering = true;
  const lg = world({ proofs: (u, agent) => ({ empty: !(lingering && agent === lg.ids.b) }) });
  for (const x of [lg.ids.a, lg.ids.b]) fence(lg, x);
  const tagSet = { kind: "tag", id: lg.ids.t, run: RUN, attempt: 1, state: "staging", dirty: true, dest: { tag: { dev, ino: "200" } } };
  await refused(lg.ad.cleanDest(tagSet), "not_granted");
  assert.deepEqual(launcherCalls(lg, "remove-tree"), []);
  lingering = false;
  await lg.ad.cleanDest(tagSet);
  assert.equal(launcherCalls(lg, "remove-tree").length, 1);
  // An archive: the deleted agent's uid proven; no fence (it has no live agent).
  const a = world();
  await a.ad.cleanDest({ kind: "archive", id: a.ids.dead, run: RUN, attempt: 1, state: "staging", dirty: true, dest: { archive: { dev, ino: "200" } } });
  assert.deepEqual(launcherCalls(a, "remove-tree")[0].slice(3, 7), ["--anchor", "/srv/sagebrush/archive", "--name", a.ids.dead]);
  assert.deepEqual(a.proofPairs, [[a.ids.dead, 70003]]);
  // Refused with NO launcher removal: another object than the pinned one; no fence; a process; a held uid; a proof
  // that fails; a tag with one member unfenced.
  const none = async (x, set, what) => { await refused(x.ad.cleanDest(set), "not_granted"); assert.deepEqual(launcherCalls(x, "remove-tree"), [], what); };
  const moved = world(); fence(moved, moved.ids.a);
  await none(moved, agentSet(moved, { dest: { home: { dev, ino: "999" }, sessions: { dev, ino: "102" } } }), "another object");
  const nofence = world();
  await none(nofence, agentSet(nofence), "no restore fence");
  for (const over of [{ procs: () => 1 }, { proofs: () => ({ empty: false }) }, { proofs: () => { throw new Error("x"); } }]) {
    const x = world(over); fence(x, x.ids.a);
    await none(x, agentSet(x), JSON.stringify(Object.keys(over)));
  }
  const half = world(); fence(half, half.ids.a);
  await none(half, { kind: "tag", id: half.ids.t, run: RUN, attempt: 1, state: "staging", dirty: true, dest: { tag: { dev, ino: "200" } } }, "a member unfenced");
  // A partial removal (75) or another refusal throws: the record stays dirty; the retry takes its proofs again.
  let first = true;
  const p = world({ script: (argv) => (argv[2] === "--contents" && first ? ((first = false), { code: 75 }) : null) });
  fence(p, p.ids.a);
  await hostSide(p.ad.cleanDest(agentSet(p)));
  const asked = p.proofAsked.length;
  await p.ad.cleanDest(agentSet(p));
  assert.ok(p.proofAsked.length > asked, "proofs taken again");
  assert.equal(launcherCalls(p, "remove-tree").filter((c) => c[6] === `${p.ids.a}/home`).length, 2, "retried with the same target");
  const r73 = world({ script: (argv) => (argv[2] === "--contents" ? { code: 73 } : null) }); fence(r73, r73.ids.a);
  await hostSide(r73.ad.cleanDest(agentSet(r73)));
  await refused(w.ad.cleanDest({ kind: "agent", id: w.ids.a, dest: null }), "bad_form");
});

test("stopped: every agent of the set fenced for restore, its slice empty and its uid proven empty, afresh; else false", async () => {
  const fence = (w, x) => { const p = join(w.root, fenceFiles(x).restore); fs.mkdirSync(join(p, ".."), { recursive: true }); fs.writeFileSync(p, ""); };
  const set = (w, kind, id) => ({ kind, id, run: RUN, attempt: 1, state: "published" });
  const w = world();
  assert.equal(await w.ad.stopped(set(w, "agent", w.ids.a)), false, "no restore fence");
  assert.deepEqual(w.procAsked, [], "no proof asked without the fence");
  fence(w, w.ids.a);
  assert.equal(await w.ad.stopped(set(w, "agent", w.ids.a)), true);
  assert.deepEqual([w.procAsked, w.proofAsked], [[w.ids.a], [70001]]);
  // A tag: every live member, each fenced and proven (the deleted agent isn't a member that runs).
  assert.equal(await w.ad.stopped(set(w, "tag", w.ids.t)), false, "b isn't fenced");
  fence(w, w.ids.b);
  w.procAsked.length = 0; w.proofAsked.length = 0;
  assert.equal(await w.ad.stopped(set(w, "tag", w.ids.t)), true);
  assert.deepEqual([w.procAsked, w.proofAsked], [[w.ids.a, w.ids.b].sort(), [w.ids.a, w.ids.b].sort().map((x) => w.registry.agents[x].uid)]);
  // Each uid proven WITH ITS OWN AGENT (the proof checks that agent's user, its linger), never the tag's id.
  assert.deepEqual(w.proofPairs.slice(-2), [w.ids.a, w.ids.b].sort().map((x) => [x, w.registry.agents[x].uid]));
  // An archive: the deleted agent's uid proven empty.
  w.proofAsked.length = 0;
  assert.equal(await w.ad.stopped(set(w, "archive", w.ids.dead)), true);
  assert.deepEqual(w.proofAsked, [70003]);
  assert.deepEqual(w.proofPairs.at(-1), [w.ids.dead, 70003]);
  // A proof that depends on the agent it's asked for (one member's user still lingers): a tag isn't stopped.
  const lin = world({ proofs: (u, agent) => ({ empty: agent !== lin.ids.b }) });
  fence(lin, lin.ids.a); fence(lin, lin.ids.b);
  assert.equal(await lin.ad.stopped(set(lin, "tag", lin.ids.t)), false, "member b's user lingers");
  assert.equal(await lin.ad.stopped(set(lin, "agent", lin.ids.a)), true, "a alone is proven");
  // A process in the slice, a held uid, a proof that throws or answers anything else: false, never true.
  for (const over of [{ procs: () => 1 }, { proofs: () => ({ empty: false }) }, { proofs: () => { throw new Error("x"); } }, { procs: () => { throw new Error("x"); } },
    { proofs: () => ({ empty: "yes" }) }, { proofs: () => null }]) {
    const x = world(over);
    fence(x, x.ids.a);
    assert.equal(await x.ad.stopped(set(x, "agent", x.ids.a)), false, JSON.stringify(Object.keys(over)));
  }
});

test("discardStaging: every other attempt of the set removed by the launcher by identity; the current one kept while staging or published", async () => {
  const w = world();
  const own = `a-${w.ids.a}`;
  for (const [run, cls, att] of [[RUN, "home", "1"], [RUN, "home", "2"], [RUN, "sessions", "2"], [RUN2, "home", "1"]]) w.mk(`${RESTORE_STAGING}/${run}/${own}/${cls}/${att}`);
  w.mk(`${RESTORE_STAGING}/${RUN}/a-${w.ids.b}/home/1`); // another set's: never touched
  w.mk(`${RESTORE_STAGING}/${RUN}/${own}/archive/1`); // not a class of an agent: never touched
  w.mk(`${RESTORE_STAGING}/${RUN}/${own}/home/01`); // not an attempt's name: never touched
  w.mk(`${RESTORE_STAGING}/notarun/${own}/home/1`);
  const removed = () => launcherCalls(w, "remove-tree").map((c) => c[5]);
  await w.ad.discardStaging({ kind: "agent", id: w.ids.a, run: RUN, attempt: 2, state: "published" });
  assert.deepEqual(removed().sort(), [`${RUN}/${own}/home/1`, `${RUN2}/${own}/home/1`].sort());
  // Each by the identity identify gave, with owners exactly [0] (A1 r2.8 §5b), under the staging anchor.
  const rm = launcherCalls(w, "remove-tree")[0];
  assert.deepEqual(rm.slice(1, 4), ["remove-tree", "--anchor", RESTORE_STAGING]);
  assert.deepEqual(JSON.parse(fs.readFileSync(rm[7], "utf8")), { epoch: EPOCH, fsid: FSID, root: identified().object, owners: [0] });
  // Validated (or stopped): nothing kept.
  w.calls.length = 0;
  await w.ad.discardStaging({ kind: "agent", id: w.ids.a, run: RUN, attempt: 2, state: "validated" });
  assert.ok(removed().includes(`${RUN}/${own}/home/2`) && removed().includes(`${RUN}/${own}/sessions/2`));
  // An attempt already gone (identify: null) needs no removal.
  const g = world({ script: (argv) => (argv[1] === "identify" ? { code: 0, stdout: JSON.stringify({ epoch: EPOCH, fsid: FSID, object: null }) } : null) });
  g.mk(`${RESTORE_STAGING}/${RUN}/a-${g.ids.a}/home/1`);
  await g.ad.discardStaging({ kind: "agent", id: g.ids.a, run: RUN, attempt: 1, state: "failed" });
  assert.deepEqual(launcherCalls(g, "remove-tree"), []);
  // One the launcher won't remove (73, or 75 partly): reported, kept, the rest still removed, no throw.
  const k = world({ script: (argv) => (argv[1] === "remove-tree" && argv[5].endsWith("/home/1") ? { code: 73 } : null) });
  const ko = `a-${k.ids.a}`;
  for (const cls of ["home", "sessions"]) k.mk(`${RESTORE_STAGING}/${RUN}/${ko}/${cls}/1`);
  await k.ad.discardStaging({ kind: "agent", id: k.ids.a, run: RUN, attempt: 1, state: "failed" });
  assert.deepEqual(k.reports, [{ kind: "restore.staging_kept", set: `agent-${k.ids.a}`, attempt: `${RUN}/${ko}/home/1`, code: 73 }]);
  assert.equal(launcherCalls(k, "remove-tree").length, 2);
  // No staging at all: nothing to do.
  const e = world();
  await e.ad.discardStaging({ kind: "agent", id: e.ids.a, run: RUN, attempt: 1, state: "failed" });
  assert.deepEqual(e.calls, []);
});

test("the validate anchor and the copies: made root 0700 (or refused unless exactly that); the set's copy directory removed by identity", async () => {
  const w = world();
  const set = { kind: "agent", id: w.ids.a, run: RUN, attempt: 1, state: "published" };
  await w.ad.removeCopies(set);
  const st = fs.lstatSync(join(w.root, VALIDATE_DIR));
  assert.deepEqual([st.isDirectory(), st.mode & 0o7777], [true, 0o700]);
  const rm = launcherCalls(w, "remove-tree")[0];
  assert.deepEqual(rm.slice(1, 6), ["remove-tree", "--anchor", VALIDATE_DIR, "--name", `${RUN}/a-${w.ids.a}`]);
  assert.deepEqual(JSON.parse(fs.readFileSync(rm[7], "utf8")).owners, [0]);
  // Absent: nothing removed. A refusal: thrown (the driver doesn't list over stale copies).
  const g = world({ script: (argv) => (argv[1] === "identify" ? { code: 0, stdout: JSON.stringify({ epoch: EPOCH, fsid: FSID, object: null }) } : null) });
  await g.ad.removeCopies({ ...set, id: g.ids.a });
  assert.deepEqual(launcherCalls(g, "remove-tree"), []);
  const r = world({ script: (argv) => (argv[1] === "remove-tree" ? { code: 75 } : null) });
  await hostSide(r.ad.removeCopies({ ...set, id: r.ids.a }));
  // An anchor that isn't exactly root's 0700 directory: refused before any launcher call.
  // (each wrong in one way only: a 0700 file, a link to a 0700 directory)
  for (const bad of [(p) => { fs.mkdirSync(p); fs.chmodSync(p, 0o755); }, (p) => { fs.writeFileSync(p, ""); fs.chmodSync(p, 0o700); },
    (p) => { fs.mkdirSync(`${p}.real`, { mode: 0o700 }); fs.chmodSync(`${p}.real`, 0o700); fs.symlinkSync(`${p}.real`, p); }]) {
    const x = world();
    bad(join(x.root, VALIDATE_DIR));
    await refused(x.ad.removeCopies({ ...set, id: x.ids.a }), "not_granted");
    assert.deepEqual(x.calls, []);
  }
});

test("unrestorableOf is the manifest's list as given; the constructor refuses missing adapters", () => {
  const w = world();
  assert.deepEqual(w.ad.unrestorableOf("agent", w.ids.a, "home"), ["agent/home"]);
  const base = { run: async () => ({}), launcher: LAUNCHER, mount: "/srv", store: {}, registry: () => ({}), provisioner: {}, usageOf: async () => USAGE,
    unrestorable: () => [], procCount: async () => 0, uidProof: async () => ({ empty: true }) };
  for (const k of ["run", "registry", "usageOf", "unrestorable", "procCount", "uidProof", "launcher", "mount", "store", "provisioner"]) {
    assert.throws(() => restoreAdapters({ ...base, [k]: undefined }), (e) => e.code === "bad_form", k);
  }
  assert.throws(() => restoreAdapters({ ...base, launcher: "sagebrush-agent-launch" }), (e) => e.code === "bad_form");
});

test("the REAL uid-empty proof, per member: a tag whose second member's user lingers is neither stopped nor emptied, until it's gone", async () => {
  // uidEmpty against the test root: no process holds the uid, no user manager, no session; only a linger file.
  const quiet = async (argv) => (argv[0] === "systemctl" ? { code: 3, stdout: "inactive\n" } : { code: 0, stdout: "" });
  let w;
  w = world({ proofs: (u, agent) => uidEmpty(u, agent, { root: w.root, run: quiet, ms: 5000 }) });
  fs.mkdirSync(join(w.root, "proc"));
  for (const x of [w.ids.a, w.ids.b]) { const f = join(w.root, fenceFiles(x).restore); fs.mkdirSync(join(f, ".."), { recursive: true }); fs.writeFileSync(f, ""); }
  const linger = join(w.root, "var/lib/systemd/linger", `sb-${w.ids.b}`);
  fs.mkdirSync(join(linger, ".."), { recursive: true });
  fs.writeFileSync(linger, "");
  const dev = String(8 * 2 ** 20 + 1);
  const tagSet = { kind: "tag", id: w.ids.t, run: RUN, attempt: 1, state: "staging", dirty: true, dest: { tag: { dev, ino: "200" } } };
  assert.equal(await w.ad.stopped(tagSet), false, "b's user lingers");
  await refused(w.ad.cleanDest(tagSet), "not_granted");
  assert.deepEqual(launcherCalls(w, "remove-tree"), [], "nothing removed");
  assert.equal(await w.ad.stopped({ kind: "agent", id: w.ids.a, run: RUN, attempt: 1, state: "published" }), true, "a alone is empty");
  fs.rmSync(linger);
  assert.equal(await w.ad.stopped(tagSet), true);
  await w.ad.cleanDest(tagSet);
  assert.equal(launcherCalls(w, "remove-tree").length, 1, "emptied once every member is proven");
});
