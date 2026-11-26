// Host backup r3.3 §5 step 4: what a restore restores from. Listing every committed manifest of every host (each read
// back, its text bound to its own sb-manifest tag, parsed, bound to its snapshot's host and run; a bad one is listed as
// unusable, never offered), choosing one against a fresh listing (every reference verified and read back), and the
// restore plan: the authority for each set's run and snapshot (restoreReady's expected), created once, moved only by
// a set's new request. Against a fake store that records every call.
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "./host-linux-only.mjs";
import { FleetError, newId } from "../lib/fleet/index.mjs";
import { buildManifest, canonical, sha256 } from "../lib/fleet/host/backup-manifest.mjs";
import { PLAN, checkPlan, chooseManifest, createPlan, expectedOf, listManifests, newPlan, readPlan, replanSet, updatePlan, withRestoreLock } from "../lib/fleet/host/restore-plan.mjs";
import { realIo } from "../lib/fleet/host/store.mjs";
import { CLASSES, newRecord, newRestoreRun, restoreReady, retryRecord, runTime, step, writeRecord } from "../lib/fleet/host/restore-record.mjs";

const refused = (fn, code) => assert.throws(fn, (e) => e instanceof FleetError && e.code === code, code);
const rejects = (p, code) => assert.rejects(p, (e) => e instanceof FleetError && e.code === code, code);
let n = 0;
const hex = () => (++n).toString(16).padStart(64, "0");
const RUN = "20261124T030000Z-abcdefgh", RUN2 = "20261125T030000Z-bcdefghi"; // backup runs
const T0 = 1795500000000;
const zeros = () => Buffer.alloc(6);
/** A restore run at T0 + `ms`. */
const rrun = (ms, rand = zeros) => newRestoreRun(T0 + ms, rand);
const RRUN = rrun(0), RRUN2 = rrun(3600000);
const fresh = () => join(mkdtempSync(join(tmpdir(), "sb-plan-")), "restore");

/**
 * One host's committed backup in a fake store: its set snapshots, its host store snapshot and its manifest snapshot,
 * with the tags a real run gives them. Returns { snapshots (listing entries), texts (manifest id -> text), m, mid, ... }.
 */
function backup(host, run, time, { agents = 2 } = {}) {
  const t = newId(), ids = Array.from({ length: agents }, () => newId()), dead = newId();
  const registry = { v: 1, next_uid: 70010, next_gid: 80001, tags: { [t]: { gid: 80000 } }, agents: {} };
  ids.forEach((id, i) => { registry.agents[id] = { uid: 70000 + i, state: "running", life: i, gen: 1, tags: i === 0 ? [t] : [], start_failed: null }; });
  registry.agents[dead] = { uid: 70009, state: "deleted", life: 9, gen: 1, tags: [], start_failed: null };
  const sets = [...ids.map((id) => ({ kind: "agent", id })), { kind: "archive", id: dead }, { kind: "tag", id: t }]
    .map((s) => ({ ...s, snapshot: hex(), tree: hex(), unrestorable: { count: 0, paths: [] } }));
  const hoststore = hex();
  const m = buildManifest({ host, run, time, registry, sets, config: Object.fromEntries(ids.map((id) => [id, hex()])), hoststore });
  const text = canonical(m) + "\n";
  const mid = hex();
  const entry = (id, tags, tree = hex()) => ({ id, time, tree, host, paths: ["/var/lib/sagebrush/backup/staging"], tags, summary: null });
  const snapshots = [
    ...sets.map((s) => entry(s.snapshot, [`sb-run=${run}`, "sb-state=good", `sb-kind=${s.kind}`, `${s.kind}=${s.id}`], s.tree)),
    entry(hoststore, [`sb-run=${run}`, "sb-state=good", "sb-kind=hoststore"]),
    entry(mid, [`sb-run=${run}`, "sb-state=good", "sb-kind=manifest", `sb-manifest=${sha256(text)}`]),
  ];
  return { snapshots, texts: new Map([[mid, text]]), m, mid, text, sha: sha256(text), ids, dead, t };
}

/** A fake store over some backups. `findings`/`failReadback`/`failDump`: id -> value; `edit(list)` changes the listing. */
function store(backups, { findings = {}, failReadback = {}, failDump = {}, texts = {}, edit = (l) => l, failList = null } = {}) {
  const calls = [];
  const all = backups.flatMap((b) => b.snapshots);
  const text = new Map([...backups.flatMap((b) => [...b.texts]), ...Object.entries(texts)]);
  return {
    calls,
    binary: async (req) => {
      calls.push(req.op === "snapshots" ? ["snapshots"] : [req.op, req.snapshot]);
      if (req.op === "snapshots") return failList ? { ok: false, code: failList } : { ok: true, value: { snapshots: edit(structuredClone(all)) } };
      if (req.op === "readback") {
        if (failReadback[req.snapshot]) return { ok: false, code: failReadback[req.snapshot] };
        return { ok: true, value: { snapshot: all.find((s) => s.id === req.snapshot), findings: findings[req.snapshot] ?? 0 } };
      }
      if (req.op === "dump") {
        if (failDump[req.snapshot]) return { ok: false, code: failDump[req.snapshot] };
        assert.equal(req.path, "var/lib/sagebrush/backup/staging/manifest.json");
        return { ok: true, value: { text: text.get(req.snapshot) } };
      }
      throw new Error(`unexpected op ${req.op}`);
    },
  };
}

test("listing: every committed manifest of every host, newest first, with what each restores", async () => {
  const a = backup("old-host", RUN, "2026-11-24T03:10:00.000Z");
  const b = backup("old-host", RUN2, "2026-11-25T03:10:00.000Z", { agents: 3 });
  const c = backup("other", RUN, "2026-11-24T04:00:00.000Z", { agents: 1 });
  const foreign = { id: hex(), time: "2026-11-25T00:00:00.000Z", tree: hex(), host: "old-host", paths: ["/x"], tags: ["something"], summary: null };
  const s = store([a, b, c], { edit: (l) => [...l, foreign] });
  const r = await listManifests(s);
  assert.deepEqual(r.manifests, [
    { snapshot: b.mid, host: "old-host", run: RUN2, time: "2026-11-25T03:10:00.000Z", agents: 3, deleted: 1, tags: 1 },
    { snapshot: c.mid, host: "other", run: RUN, time: "2026-11-24T04:00:00.000Z", agents: 1, deleted: 1, tags: 1 },
    { snapshot: a.mid, host: "old-host", run: RUN, time: "2026-11-24T03:10:00.000Z", agents: 2, deleted: 1, tags: 1 },
  ]);
  assert.deepEqual(r.unusable, []);
  assert.equal(r.skipped, 1, "the one snapshot with none of a backup's tags is counted, not read");
  // Only manifests are read: one readback and one dump each, nothing else.
  assert.deepEqual(s.calls.filter(([op]) => op !== "snapshots").map(([op, id]) => `${op}:${id}`).sort(),
    [a.mid, b.mid, c.mid].flatMap((id) => [`readback:${id}`, `dump:${id}`]).sort());
});

test("listing: a store of snapshots made by other means lists no manifest and counts them as skipped; a backup's set snapshots aren't counted", async () => {
  const other = (n) => ({ id: hex(), time: "2026-11-25T00:00:00.000Z", tree: hex(), host: "old-host", paths: [`/x${n}`], tags: n ? ["mine"] : [], summary: null });
  const only = await listManifests(store([], { edit: (l) => [...l, other(0), other(1)] }));
  assert.deepEqual(only, { manifests: [], unusable: [], skipped: 2 });
  const b = backup("old-host", RUN, "2026-11-24T03:10:00.000Z");
  const r = await listManifests(store([b]));
  assert.equal(r.manifests.length, 1);
  assert.equal(r.skipped, 0, "a backup's own set and host-store snapshots are not skipped ones");
});

test("listing: a manifest that fails any check is unusable, with why, and the others are still offered", async () => {
  const good = backup("h", RUN2, "2026-11-25T03:10:00.000Z");
  const cases = [
    ["not the committed bytes", (b) => ({ texts: { [b.mid]: b.text.replace("old", "odd") + " " } }), "bad_manifest"],
    ["a valid manifest, but not the bytes its tag binds", (b) => ({ texts: { [b.mid]: canonical({ ...b.m, time: "2026-11-24T03:11:00.000Z" }) + "\n" } }), "bad_manifest"],
    ["the right sha but not canonical", (b) => { const t = JSON.stringify(b.m) + "\n"; return { texts: { [b.mid]: t }, edit: tagged(b, t) }; }, "bad_manifest"],
    ["readback findings", (b) => ({ findings: { [b.mid]: 2 } }), "check_failed"],
    ["readback fails", (b) => ({ failReadback: { [b.mid]: "readback_failed" } }), "readback_failed"],
    ["dump fails", (b) => ({ failDump: { [b.mid]: "dump_failed" } }), "dump_failed"],
    ["content of another host", (b) => { const t = canonical({ ...b.m, host: "elsewhere" }) + "\n"; return { texts: { [b.mid]: t }, edit: tagged(b, t) }; }, "bad_manifest"],
    ["content of another run", (b) => { const t = canonical({ ...b.m, run: RUN2 }) + "\n"; return { texts: { [b.mid]: t }, edit: tagged(b, t) }; }, "bad_manifest"],
    ["two paths", (b) => ({ edit: (l) => l.map((x) => (x.id === b.mid ? { ...x, paths: ["/a", "/b"] } : x)) }), "bad_manifest"],
  ];
  for (const [why, opts, error] of cases) {
    const bad = backup("h", RUN, "2026-11-24T03:10:00.000Z");
    const r = await listManifests(store([bad, good], opts(bad)));
    assert.deepEqual(r.manifests.map((x) => x.snapshot), [good.mid], why);
    assert.deepEqual(r.unusable, [{ snapshot: bad.mid, host: "h", error }], why);
  }
  // A listing that can't be trusted is an error, never a short list.
  const b = backup("h", RUN, "2026-11-24T03:10:00.000Z");
  assert.deepEqual(await listManifests(store([b], { edit: (l) => [...l, l[0]] })), { error: "bad_result", snapshot: b.snapshots[0].id });
  assert.deepEqual(await listManifests(store([b], { failList: "list_failed" })), { error: "list_failed" });
});

/** A listing edit that re-tags the manifest of `b` with the sha of `text` (a well-bound but other text). */
const tagged = (b, text) => (l) => l.map((x) => (x.id === b.mid ? { ...x, tags: x.tags.map((t) => (t.startsWith("sb-manifest=") ? `sb-manifest=${sha256(text)}` : t)) } : x));

test("choosing: checked against a fresh listing; every referenced snapshot verified and read back", async () => {
  const b = backup("old-host", RUN, "2026-11-24T03:10:00.000Z");
  const s = store([b]);
  const chosen = await chooseManifest(s, b.mid);
  assert.deepEqual(chosen, { manifest: b.m, snapshot: b.mid, sha256: b.sha });
  const refs = [...b.m.sets.map((x) => x.snapshot), b.m.hoststore];
  assert.deepEqual(s.calls, [["snapshots"], ["readback", b.mid], ["dump", b.mid], ...refs.map((id) => ["readback", id])]);
  await assert.rejects(chooseManifest(s, "nope"), (e) => e instanceof FleetError && e.code === "bad_form");
  const agentSet = b.m.sets.find((x) => x.kind === "agent");
  const cases = [
    ["not in the store", store([b]), hex(), "not_found", null],
    ["not a manifest", store([b]), agentSet.snapshot, "bad_manifest", agentSet.snapshot],
    ["tampered since the listing", store([b], { texts: { [b.mid]: b.text + " " } }), b.mid, "bad_manifest", b.mid],
    ["a referenced snapshot gone", store([b], { edit: (l) => l.filter((x) => x.id !== agentSet.snapshot) }), b.mid, "not_found", agentSet.snapshot],
    ["a referenced snapshot of another kind", store([b], { edit: (l) => l.map((x) => (x.id === agentSet.snapshot ? { ...x, tags: x.tags.map((t) => t.replace("sb-kind=agent", "sb-kind=tag").replace(/^agent=/, "tag=")) } : x)) }), b.mid, "bad_manifest", agentSet.snapshot],
    ["a referenced snapshot with another tree", store([b], { edit: (l) => l.map((x) => (x.id === agentSet.snapshot ? { ...x, tree: hex() } : x)) }), b.mid, "bad_manifest", agentSet.snapshot],
    ["a referenced snapshot that reads back with findings", store([b], { findings: { [b.m.hoststore]: 1 } }), b.mid, "check_failed", b.m.hoststore],
    ["a referenced snapshot that doesn't read back", store([b], { failReadback: { [agentSet.snapshot]: "readback_failed" } }), b.mid, "readback_failed", agentSet.snapshot],
    ["the manifest reads back with findings", store([b], { findings: { [b.mid]: 1 } }), b.mid, "check_failed", b.mid],
    ["a duplicate id in the listing", store([b], { edit: (l) => [...l, l.find((x) => x.id === b.mid)] }), b.mid, "bad_result", b.mid],
  ];
  for (const [why, st, id, error, snapshot] of cases) {
    const r = await chooseManifest(st, id);
    assert.equal(r.error, error, why);
    if (snapshot !== null) assert.equal(r.snapshot, snapshot, why);
    assert.equal(r.manifest, undefined, why);
  }
});

test("the plan: every set of the chosen manifest bound to the restore's run, its snapshot and tree; a closed shape", async () => {
  const b = backup("old-host", RUN, "2026-11-24T03:10:00.000Z");
  const chosen = await chooseManifest(store([b]), b.mid);
  const p = newPlan(chosen, RRUN);
  assert.deepEqual(Object.keys(p), ["v", "host", "manifest", "sha256", "hoststore", "sets", "config"]);
  // Each agent set's config hash, the manifest's; only the agents' (an archive's or a tag's has none).
  const agents = b.m.sets.filter((s) => s.kind === "agent");
  assert.ok(agents.length > 0);
  assert.deepEqual(p.config, Object.fromEntries(agents.map((s) => [s.id, b.m.config[s.id]])));
  assert.deepEqual([p.host, p.manifest, p.sha256, p.hoststore], ["old-host", b.mid, b.sha, b.m.hoststore]);
  assert.deepEqual(p.sets, Object.fromEntries(b.m.sets.map((s) => [`${s.kind}-${s.id}`, { run: RRUN, snapshot: s.snapshot, tree: s.tree }])));
  assert.deepEqual(expectedOf(p), Object.fromEntries(b.m.sets.map((s) => [`${s.kind}-${s.id}`, { run: RRUN, snapshot: s.snapshot }])));
  refused(() => newPlan(chosen, "x"), "bad_form");
  refused(() => newPlan(chosen, RUN), "bad_form"); // a backup's run format isn't a restore's
  refused(() => checkPlan({ ...p, sets: Object.fromEntries(Object.entries(p.sets).map(([k, v]) => [k, { ...v, run: RUN }])) }), "bad_form");
  // A manifest with no sets still needs a valid run.
  const empty = { ...chosen, manifest: { ...chosen.manifest, sets: [] } };
  assert.deepEqual([newPlan(empty, RRUN).sets, newPlan(empty, RRUN).config], [{}, {}]);
  refused(() => newPlan({ ...chosen, manifest: { ...chosen.manifest, config: {} } }, RRUN), "bad_form"); // an agent with no hash
  refused(() => newPlan(empty, "x"), "bad_form");
  const k = Object.keys(p.sets)[0];
  for (const bad of [
    { ...p, v: 2 }, { ...p, extra: 1 }, { ...p, host: "bad host" }, { ...p, manifest: "x" }, { ...p, sha256: "A".repeat(64) }, { ...p, hoststore: null },
    { ...p, sets: [] }, { ...p, sets: null }, { ...p, sets: { ...p.sets, "host-x": p.sets[k] } }, { ...p, sets: { ...p.sets, [`agent-nope`]: p.sets[k] } },
    { ...p, sets: { ...p.sets, [k]: { ...p.sets[k], run: "x" } } }, { ...p, sets: { ...p.sets, [k]: { ...p.sets[k], snapshot: "x" } } },
    { ...p, sets: { ...p.sets, [k]: { ...p.sets[k], tree: undefined } } }, { ...p, sets: { ...p.sets, [k]: { ...p.sets[k], extra: 1 } } },
    (({ config, ...rest }) => rest)(p), { ...p, config: null }, { ...p, config: [] }, { ...p, config: {} },
    { ...p, config: { ...p.config, [newId()]: hex() } }, { ...p, config: Object.fromEntries(Object.keys(p.config).map((id) => [id, "A".repeat(64)])) },
    { ...p, config: Object.fromEntries(Object.keys(p.config).map((id) => [id, null])) },
  ]) refused(() => checkPlan(bad), "bad_form");
});

test("the plan is restoreReady's authority: records of the plan's run and snapshot resume; a set re-planned needs its new record", async () => {
  const b = backup("old-host", RUN, "2026-11-24T03:10:00.000Z");
  const p = newPlan(await chooseManifest(store([b]), b.mid), RRUN);
  const dir = fresh();
  const agent = b.ids[0], tag = b.t;
  const rec = (kind, id, run, dest) => {
    let r = step(newRecord({ kind, id, run, snapshot: p.sets[`${kind}-${id}`].snapshot }), "bind", { dest });
    for (const cls of CLASSES[kind]) r = step(r, "digest", { cls, sha256: "d".repeat(64) });
    for (const s of ["staged", "filling", "published", "files_validated"]) r = step(r, s, { dest });
    // An agent's imports, each pending then done; an archive or a tag folder has none.
    if (r.imports !== null) for (const which of ["config", "context"]) for (const phase of ["pending", "done"]) r = step(r, "import", { which, phase, sha256: "c".repeat(64) });
    return step(r, "validated");
  };
  const ident = (ino) => ({ dev: "1", ino, uid: 70000, gid: 70000, mode: 0o700, projid: 70000 });
  const home = { home: ident("2"), sessions: ident("3") };
  writeRecord(rec("agent", agent, RRUN, home), { dir });
  writeRecord(rec("tag", tag, RRUN, { tag: ident("4") }), { dir });
  assert.equal(restoreReady(agent, [tag], expectedOf(p), { dir }), "validated");
  // The person's new request for the tag folder: re-planned to RRUN2; the old record no longer resumes anything.
  const p2 = replanSet(p, "tag", tag, RRUN2);
  refused(() => restoreReady(agent, [tag], expectedOf(p2), { dir }), "not_granted");
  writeRecord(rec("tag", tag, RRUN2, { tag: ident("4") }), { dir });
  assert.equal(restoreReady(agent, [tag], expectedOf(p2), { dir }), "validated");
  // The record for the new request starts from the stopped one (retryRecord) on the plan's new run.
  const stopped = step(newRecord({ kind: "agent", id: agent, run: RRUN, snapshot: p.sets[`agent-${agent}`].snapshot }), "not_fitting");
  assert.equal(retryRecord(stopped, { run: replanSet(p, "agent", agent, RRUN2).sets[`agent-${agent}`].run, snapshot: p.sets[`agent-${agent}`].snapshot }).run, RRUN2);
});

test("re-planning a set: only a set of this restore, only to a run newer by decoded time, nothing else changes", async () => {
  const b = backup("old-host", RUN, "2026-11-24T03:10:00.000Z");
  const p = newPlan(await chooseManifest(store([b]), b.mid), RRUN);
  const k = `agent-${b.ids[1]}`;
  const p2 = replanSet(p, "agent", b.ids[1], RRUN2);
  assert.deepEqual(p2, { ...p, sets: { ...p.sets, [k]: { ...p.sets[k], run: RRUN2 } } });
  refused(() => replanSet(p, "agent", newId(), RRUN2), "not_found");
  refused(() => replanSet(p, "tag", b.ids[1], RRUN2), "not_found");
  refused(() => replanSet(p, "agent", b.ids[1], RRUN), "bad_form"); // the same run
  refused(() => replanSet(p2, "agent", b.ids[1], RRUN), "bad_form"); // an older one: its old records would count again
  refused(() => replanSet(p2, "agent", b.ids[1], rrun(3600000, () => Buffer.alloc(6, 7))), "bad_form"); // the same ms
  refused(() => replanSet(p, "agent", b.ids[1], "20261126T020000Z-aaaaaaaa"), "bad_form"); // a backup's run format
  // Order is by decoded time, not by the strings: a later run whose string sorts lower is newer, and the reverse not.
  const t = 3600000 - ((T0 + 3600000) % 32) + 25 + 32;
  const older = rrun(t), later = rrun(t + 1);
  assert.ok(later < older && runTime(later) > runTime(older), "the later run's string sorts lower");
  const q = replanSet(p, "agent", b.ids[1], older);
  assert.equal(replanSet(q, "agent", b.ids[1], later).sets[k].run, later);
  refused(() => replanSet(replanSet(q, "agent", b.ids[1], later), "agent", b.ids[1], older), "bad_form");
  refused(() => replanSet(p, "agent", b.ids[1], "x"), "bad_form");
  refused(() => replanSet({ ...p, v: 0 }, "agent", b.ids[1], RRUN2), "bad_form");
});

test("the plan on disk: created once (0600, exclusive; the same plan again is fine), updated only forward, read strictly", async () => {
  const b = backup("old-host", RUN, "2026-11-24T03:10:00.000Z");
  const chosen = await chooseManifest(store([b]), b.mid);
  const p = newPlan(chosen, RRUN);
  const dir = fresh();
  assert.equal(readPlan({ dir }), null);
  refused(() => updatePlan(p, { dir }), "not_found");
  createPlan(p, { dir });
  assert.deepEqual(readPlan({ dir }), p);
  assert.equal(statSync(join(dir, PLAN)).mode & 0o777, 0o600);
  assert.equal(statSync(dir).mode & 0o777, 0o700);
  createPlan(p, { dir }); // a retry after a crash
  refused(() => createPlan(newPlan(chosen, RRUN2), { dir }), "in_progress");
  const other = backup("old-host", RUN2, "2026-11-25T03:10:00.000Z");
  const otherPlan = newPlan(await chooseManifest(store([other]), other.mid), RRUN);
  refused(() => createPlan(otherPlan, { dir }), "in_progress");
  assert.deepEqual(readPlan({ dir }), p, "a refused create leaves the plan");
  const k = Object.keys(p.sets)[0];
  const [kind, id] = [k.split("-")[0], k.slice(k.indexOf("-") + 1)];
  const p2 = replanSet(p, kind, id, RRUN2);
  updatePlan(p2, { dir });
  assert.deepEqual(readPlan({ dir }), p2);
  updatePlan(p2, { dir }); // the same update again: a retry, no-op
  assert.deepEqual(readPlan({ dir }), p2);
  // Exactly one set's new request: two sets moved at once refuse, and so does one set's request with anything else
  // of the plan changed too.
  const [k2] = Object.keys(p2.sets).filter((x) => x !== k);
  const [kind2, id2] = [k2.split("-")[0], k2.slice(k2.indexOf("-") + 1)];
  const two = replanSet(replanSet(p2, kind, id, rrun(7200000)), kind2, id2, rrun(7200000));
  const step3 = replanSet(p2, kind, id, rrun(7200000));
  const alsoChanged = [
    { ...step3, manifest: hex() }, { ...step3, sha256: hex() }, { ...step3, hoststore: hex() }, { ...step3, host: "elsewhere" },
    { ...step3, sets: { ...step3.sets, [k]: { ...step3.sets[k], snapshot: hex() } } },
    { ...step3, sets: { ...step3.sets, [k]: { ...step3.sets[k], tree: hex() } } },
    { ...step3, sets: { ...step3.sets, [k2]: { ...step3.sets[k2], tree: hex() } } },
    { ...step3, config: Object.fromEntries(Object.keys(step3.config).map((id) => [id, hex()])) }, // (a config hash with it)
  ];
  // The same millisecond, or a run whose string sorts higher but whose time is older, is not newer.
  const extra = newId();
  const sameMs = { ...p2, sets: { ...p2.sets, [k]: { ...p2.sets[k], run: rrun(3600000, () => Buffer.alloc(6, 5)) } } };
  for (const bad of [
    two, ...alsoChanged, sameMs,
    p, // backwards
    { ...p2, manifest: hex() }, { ...p2, sha256: hex() }, { ...p2, hoststore: hex() }, { ...p2, host: "elsewhere" },
    { ...p2, sets: { ...p2.sets, [k]: { ...p2.sets[k], snapshot: hex() } } }, { ...p2, sets: { ...p2.sets, [k]: { ...p2.sets[k], tree: hex() } } },
    { ...p2, sets: Object.fromEntries(Object.entries(p2.sets).filter(([x]) => x !== k2)), config: Object.fromEntries(Object.entries(p2.config).filter(([id]) => `agent-${id}` !== k2)) }, { ...p2, sets: { ...p2.sets, [`agent-${extra}`]: p2.sets[k] }, config: { ...p2.config, [extra]: hex() } },
    { ...p2, config: Object.fromEntries(Object.keys(p2.config).map((id) => [id, hex()])) },
  ]) refused(() => updatePlan(bad, { dir }), "not_granted");
  assert.deepEqual(readPlan({ dir }), p2);
  // The next single request is fine, including a later one whose string sorts lower.
  const base = 3600000 + 32 - ((T0 + 3600000) % 32) + 25;
  const a1 = replanSet(p2, kind, id, rrun(base));
  updatePlan(a1, { dir });
  const a2 = replanSet(a1, kind, id, rrun(base + 1));
  assert.ok(a2.sets[k].run < a1.sets[k].run, "its string sorts lower");
  updatePlan(a2, { dir });
  assert.deepEqual(readPlan({ dir }), a2);
  refused(() => updatePlan(a1, { dir }), "not_granted"); // and back is refused
  for (const text of ["", "{", "null", JSON.stringify({ ...p2, v: 2 })]) {
    writeFileSync(join(dir, PLAN), text);
    refused(() => readPlan({ dir }), "bad_form");
  }
});

test("an identical update is a retry: it makes the plan durable again (file, then directory) and reads it back", async () => {
  const b = backup("old-host", RUN, "2026-11-24T03:10:00.000Z");
  const p = newPlan(await chooseManifest(store([b]), b.mid), RRUN);
  const dir = fresh();
  createPlan(p, { dir });
  const k = Object.keys(p.sets)[0];
  const p2 = replanSet(p, k.split("-")[0], k.slice(k.indexOf("-") + 1), RRUN2);
  // An io that records [op, path] and can fail one fsync, by path.
  const spy = (failAt = null) => {
    const ops = [], fds = new Map();
    return {
      ops,
      io: {
        ...realIo,
        open: (q, f, m) => { const fd = realIo.open(q, f, m); fds.set(fd, q); return fd; },
        fsync: (fd) => { ops.push(["fsync", fds.get(fd)]); if (fds.get(fd) === failAt) throw Object.assign(new Error("EIO"), { code: "EIO" }); return realIo.fsync(fd); },
        rename: (a, c) => { ops.push(["rename", c]); return realIo.rename(a, c); },
      },
    };
  };
  // The update's directory fsync fails after its rename: the new plan is visible, but not yet known durable.
  await assert.rejects(async () => updatePlan(p2, { dir, io: spy(dir).io }), (e) => e.code === "EIO");
  assert.deepEqual(readPlan({ dir }), p2);
  // The identical retry flushes the file, then its directory, and only then succeeds; a failure there still throws.
  await assert.rejects(async () => updatePlan(p2, { dir, io: spy(dir).io }), (e) => e.code === "EIO");
  await assert.rejects(async () => updatePlan(p2, { dir, io: spy(join(dir, PLAN)).io }), (e) => e.code === "EIO");
  const ok = spy();
  updatePlan(p2, { dir, io: ok.io });
  assert.deepEqual(ok.ops, [["fsync", join(dir, PLAN)], ["fsync", dir]], "the file, then its directory; no rewrite");
  // A plan on disk that isn't what it claims to be is never reported durable.
  const text = readFileSync(join(dir, PLAN), "utf8");
  const tampered = spy();
  tampered.io.fsync = (fd) => { writeFileSync(join(dir, PLAN), text.replace("}", " }")); return realIo.fsync(fd); };
  refused(() => updatePlan(p2, { dir, io: tampered.io }), "outcome_unknown");
});

test("one restore at a time: the restore lock", async () => {
  const dir = fresh();
  let inside = false;
  await withRestoreLock(async () => {
    inside = true;
    await rejects(withRestoreLock(async () => assert.fail("entered twice"), { dir }), "in_progress");
  }, { dir });
  assert.ok(inside);
  assert.equal(await withRestoreLock(async () => 7, { dir }), 7, "released after use");
  await assert.rejects(withRestoreLock(async () => { throw new Error("boom"); }, { dir }), /boom/);
  assert.equal(await withRestoreLock(async () => 8, { dir }), 8, "released after a throw");
});
