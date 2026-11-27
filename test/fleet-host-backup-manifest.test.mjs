// Host backup r3.3 §4 (the host manifest) and §6 (retention over manifests): building a manifest consistent with the
// run's registry copy, its canonical bytes, committing it (read back, dumped and compared), and retention: which
// manifests are kept, the roots they define, what forget may remove, and one pass against a fake store.
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "./host-linux-only.mjs";
import { FleetError, newId } from "../lib/fleet/index.mjs";
import { buildManifest, canonical, checkManifest, commitManifest, parseManifest, referenced, sha256 } from "../lib/fleet/host/backup-manifest.mjs";
import { checkDataPart, classify, forgetPlan, isoWeek, keepManifests, pruneDue, retentionPass, rootsOf, snapshotTime } from "../lib/fleet/host/backup-retention.mjs";

const refused = (fn, code) => assert.throws(fn, (e) => e instanceof FleetError && e.code === code, code);
const hex = (n) => n.toString(16).padStart(64, "0");
const RUN = "20261124T030000Z-abcdefgh";

function fixture() {
  const [a, b, c] = [newId(), newId(), newId()];
  const t = newId();
  const registry = {
    v: 1, next_uid: 70003, next_gid: 80001,
    agents: {
      [a]: { uid: 70000, state: "running", life: 0, gen: 1, tags: [t], start_failed: null },
      [b]: { uid: 70001, state: "stopped", life: 1, gen: 2, tags: [], start_failed: null },
      [c]: { uid: 70002, state: "deleted", life: 2, gen: 1, tags: [], start_failed: null },
    },
    tags: { [t]: { gid: 80000 } },
  };
  const sets = [
    { kind: "agent", id: a, snapshot: hex(1), tree: hex(11), unrestorable: { count: 2, paths: ["/x", "/y"] } },
    { kind: "agent", id: b, snapshot: hex(2), tree: hex(12), unrestorable: { count: 0, paths: [] } },
    { kind: "archive", id: c, snapshot: hex(3), tree: hex(13), unrestorable: { count: 0, paths: [] } },
    { kind: "tag", id: t, snapshot: hex(4), tree: hex(14), unrestorable: { count: 0, paths: [] } },
  ];
  return { a, b, c, t, registry, sets, args: { host: "h1", run: RUN, time: "2026-11-24T03:10:00Z", registry, sets, config: { [a]: hex(21), [b]: hex(22) }, hoststore: hex(5) } };
}

test("a manifest binds the registry copy, every set's snapshot and tree, the config hashes, the host store and the unrestorable list", () => {
  const { a, c, t, registry, args } = fixture();
  const m = buildManifest(args);
  assert.equal(m.registry.hash, sha256(canonical(registry)));
  assert.deepEqual(Object.keys(m.registry.agents).sort(), Object.keys(registry.agents).sort());
  assert.equal(m.registry.agents[c].state, "deleted", "the tombstone is kept");
  assert.deepEqual(m.registry.tags, { [t]: { gid: 80000 } });
  assert.equal(m.sets.length, 4);
  assert.deepEqual(m.unrestorable, [{ kind: "agent", id: a, count: 2, paths: ["/x", "/y"] }]);
  assert.deepEqual(referenced(m).sort(), [hex(1), hex(2), hex(3), hex(4), hex(5)]);
  // the same content with its keys in another order gives the same bytes and hash
  const shuffled = { ...args, registry: { tags: registry.tags, agents: Object.fromEntries(Object.entries(registry.agents).reverse()), next_gid: registry.next_gid, next_uid: registry.next_uid, v: 1 }, sets: [...args.sets].reverse() };
  assert.equal(canonical(buildManifest(shuffled)), canonical(m), "canonical bytes don't depend on key or set order");
  assert.equal(parseManifest(canonical(m) + "\n").run, RUN);
});

test("a manifest inconsistent with the registry copy is refused: a missing set, an extra one, archive vs agent, a duplicate", () => {
  const { a, c, args } = fixture();
  refused(() => buildManifest({ ...args, sets: args.sets.filter((s) => s.id !== a) }), "not_granted");
  refused(() => buildManifest({ ...args, sets: [...args.sets, { kind: "agent", id: newId(), snapshot: hex(9), tree: hex(19) }] }), "not_granted");
  refused(() => buildManifest({ ...args, sets: args.sets.map((s) => (s.id === c ? { ...s, kind: "agent" } : s)) }), "not_granted");
  refused(() => buildManifest({ ...args, sets: [...args.sets, args.sets[0]] }), "not_granted");
});

test("the config hashes are exactly the live agents': a missing one, an extra one, a deleted agent's are refused, built or parsed", () => {
  const { a, b, c, args } = fixture();
  refused(() => buildManifest({ ...args, config: {} }), "not_granted");
  refused(() => buildManifest({ ...args, config: { [a]: hex(21) } }), "not_granted");
  refused(() => buildManifest({ ...args, config: { ...args.config, [newId()]: hex(23) } }), "not_granted");
  refused(() => buildManifest({ ...args, config: { ...args.config, [c]: hex(23) } }), "not_granted");
  refused(() => buildManifest({ ...args, config: { [newId()]: hex(21), [b]: hex(22) } }), "not_granted"); // same size, a live agent swapped out
  const m = buildManifest(args);
  assert.deepEqual(Object.keys(m.config).sort(), [a, b].sort());
  for (const config of [{}, { [a]: hex(21) }, { ...m.config, [c]: hex(23) }, { ...m.config, [newId()]: hex(23) }]) {
    refused(() => parseManifest(canonical({ ...m, config }) + "\n"), "bad_form");
  }
  // and a parsed manifest's sets must match its registry copy too
  refused(() => parseManifest(canonical({ ...m, sets: m.sets.slice(1) }) + "\n"), "bad_form");
});

test("the manifest's shape is closed, and only its canonical text parses", () => {
  const m = buildManifest(fixture().args);
  for (const bad of [{ ...m, v: 2 }, { ...m, extra: 1 }, { ...m, hoststore: "x" }, { ...m, run: "r" }, { ...m, sets: [{ ...m.sets[0], snapshot: "short" }] },
    { ...m, unrestorable: [{ kind: "agent", id: newId(), count: 0, paths: [] }] }]) refused(() => checkManifest(bad), "bad_form");
  refused(() => parseManifest(JSON.stringify(m, null, 2) + "\n"), "bad_form");
  refused(() => parseManifest("{"), "bad_form");
});

/** A fake binary for the commit: the backup gets snapshot S, the dump answers with `text` (or the file as written). */
function commitBinary({ readback = { ok: true, value: { findings: 0 } }, text = null } = {}) {
  const calls = [];
  let written = null;
  const fn = async (req) => {
    calls.push(req);
    if (req.op === "backup") { written = (await import("node:fs")).readFileSync(join("/", req.sources[0], "manifest.json"), "utf8"); return { ok: true, value: { snapshot: { id: hex(77) } } }; }
    if (req.op === "readback") return readback;
    if (req.op === "dump") return { ok: true, value: { text: text ?? written } };
    if (req.op === "forget") return { ok: true, value: { forgotten: 1 } };
    throw new Error(req.op);
  };
  fn.calls = calls;
  return fn;
}

test("commit: backed up as sb-kind=manifest, read back, dumped and compared byte for byte; any failure forgets it", async () => {
  const m = buildManifest(fixture().args);
  {
    const binary = commitBinary();
    const staging = join(mkdtempSync(join(tmpdir(), "sb-man-")), "staging");
    const r = await commitManifest(m, staging, { binary });
    assert.deepEqual(r, { ok: true, snapshot: hex(77), sha256: sha256(canonical(m) + "\n") });
    assert.deepEqual(binary.calls.map((c) => c.op), ["backup", "readback", "dump"]);
    assert.deepEqual(binary.calls[0].tags, [`sb-run=${RUN}`, "sb-state=good", "sb-kind=manifest", `sb-manifest=${sha256(canonical(m) + "\n")}`]);
    assert.equal(binary.calls[2].path, `${staging.slice(1)}/manifest.json`);
  }
  for (const [name, opts] of [["a dump that differs", { text: "{}\n" }], ["read-back findings", { readback: { ok: true, value: { findings: 1 } } }], ["a read-back failure", { readback: { ok: false, code: "readback_failed" } }]]) {
    const binary = commitBinary(opts);
    const r = await commitManifest(m, join(mkdtempSync(join(tmpdir(), "sb-man-")), "staging"), { binary });
    assert.equal(r.ok, false, name);
    assert.deepEqual(binary.calls.at(-1), { op: "forget", snapshots: [hex(77)] }, `${name}: the failed manifest is forgotten`);
  }
});

const DAY = 86400000;
const T0 = Date.parse("2026-11-24T03:00:00Z");

test("ISO weeks, and the rotating data check and the weekly prune", () => {
  assert.equal(isoWeek(Date.parse("2026-01-01T00:00:00Z")), "2026-W01");
  assert.equal(isoWeek(Date.parse("2027-01-01T00:00:00Z")), "2026-W53");
  assert.equal(isoWeek(Date.parse("2024-12-30T00:00:00Z")), "2025-W01");
  const parts = new Set(Array.from({ length: 30 }, (_, i) => checkDataPart(T0 + i * DAY).part));
  assert.equal(parts.size, 30); assert.equal(checkDataPart(T0).of, 30);
  assert.ok([...parts].every((p) => p >= 1 && p <= 30), "parts are 1..30, as the binary takes them");
  assert.equal(checkDataPart(T0 + 30 * DAY).part, checkDataPart(T0).part);
  assert.equal(pruneDue(null, T0), true); assert.equal(pruneDue(T0 - 6 * DAY, T0), false); assert.equal(pruneDue(T0 - 7 * DAY, T0), true);
});

test("kept manifests: always the last, the newest of each of 7 days, 4 weeks and 6 months", () => {
  const ms = Array.from({ length: 400 }, (_, i) => ({ snapshot: hex(1000 + i), time: T0 - i * DAY }));
  ms.push({ snapshot: hex(5000), time: T0 - 2 * 3600000 }); // a second manifest today, older than the first
  const kept = keepManifests(ms);
  assert.ok(kept.has(hex(1000)), "the last");
  assert.ok(!kept.has(hex(5000)), "only the newest of a day");
  for (let i = 0; i < 7; i++) assert.ok(kept.has(hex(1000 + i)), `day ${i}`);
  assert.ok(!kept.has(hex(1000 + 7)) || isoWeek(T0 - 7 * DAY) !== isoWeek(T0 - 6 * DAY), "no 8th daily unless it's a week's newest");
  assert.ok(kept.size <= 1 + 7 + 4 + 6 && kept.size >= 12, `size ${kept.size}`);
  const oldest = Math.min(...[...kept].map((id) => ms.find((m) => m.snapshot === id).time));
  assert.ok(T0 - oldest < 200 * DAY && T0 - oldest > 120 * DAY, "the 6th month back is kept, nothing older");
  assert.deepEqual([...keepManifests([])], []);
  assert.deepEqual([...keepManifests(ms, { daily: 0, weekly: 0, monthly: 0 })], [hex(1000)], "the last is kept whatever the policy");
});

test("kept manifests, exactly, on a sparse calendar: 7 days, the newest of 4 ISO weeks, 6 months; an 8th day and a 7th month go", () => {
  const dates = ["2026-11-24", "2026-11-23", "2026-11-22", "2026-11-21", "2026-11-20", "2026-11-19", "2026-11-18", "2026-11-17",
    "2026-11-12", "2026-11-05", "2026-10-29", "2026-09-15", "2026-08-15", "2026-07-15", "2026-06-15", "2026-05-15"];
  const ms = dates.map((d) => ({ snapshot: d, time: Date.parse(`${d}T03:00:00Z`) }));
  // daily: 11-24 .. 11-18 (7); weekly: W48 11-24, W47 11-22, W46 11-12, W45 11-05 (4); monthly: Nov 11-24, Oct 10-29,
  // Sep, Aug, Jul, Jun (6). Not kept: 11-17 (an 8th day, not its week's newest) and 05-15 (a 7th month).
  assert.deepEqual([...keepManifests(ms)].sort(), [
    "2026-06-15", "2026-07-15", "2026-08-15", "2026-09-15", "2026-10-29", "2026-11-05", "2026-11-12",
    "2026-11-18", "2026-11-19", "2026-11-20", "2026-11-21", "2026-11-22", "2026-11-23", "2026-11-24",
  ]);
  assert.equal(isoWeek(Date.parse("2026-11-05T03:00:00Z")), "2026-W45", "11-05 is kept only as the 4th week's newest");
});

test("the data check's part at fixed UTC days: day 0 is part 1, day 29 part 30, day 30 part 1 again", () => {
  const D = 86400000;
  assert.deepEqual([0, 1, 2, 29, 30, 31, 59, 60].map((d) => checkDataPart(d * D + 3 * 3600000).part), [1, 2, 3, 30, 1, 2, 30, 1]);
  assert.equal(checkDataPart(Date.parse("2026-11-24T03:00:00Z")).part, 22, "day 20781: 20781 mod 30 = 21, so part 22");
  assert.equal(checkDataPart(Date.parse("2026-11-24T23:59:59Z")).part, 22, "the same UTC day, the same part");
});

const HOST = "h1";
const snap = (id, time, tags, host = HOST, tree = hex(0)) => ({ id, time, tags, host, tree });
/** Our tags for a snapshot: kind, state, run, and the id tag its kind needs (or the manifest hash). */
const T = (kind, state, run = RUN, extra = null) => {
  const t = [`sb-kind=${kind}`, `sb-state=${state}`, `sb-run=${run}`];
  if (["agent", "archive", "tag"].includes(kind)) t.push(`${kind}=${extra ?? newId()}`);
  if (kind === "manifest") t.push(`sb-manifest=${extra ?? hex(999)}`);
  return t;
};

test("classify is strict: exactly one of each tag, the run grammar, the id or hash its kind needs, this host", () => {
  const id = newId();
  assert.deepEqual(classify(snap(hex(1), 0, T("agent", "good", RUN, id)), HOST), { kind: "agent", state: "good", run: RUN, id, manifest: null });
  for (const [name, s] of [
    ["another host", snap(hex(1), 0, T("agent", "good"), "other")],
    ["two kinds", snap(hex(1), 0, [...T("agent", "good"), "sb-kind=tag"])],
    ["two states", snap(hex(1), 0, [...T("agent", "warm"), "sb-state=good"])],
    ["a bad run", snap(hex(1), 0, T("agent", "good", "run-1"))],
    ["no id tag", snap(hex(1), 0, ["sb-kind=agent", "sb-state=good", `sb-run=${RUN}`])],
    ["two id tags", snap(hex(1), 0, [...T("agent", "good"), `agent=${newId()}`])],
    ["a manifest without its hash", snap(hex(1), 0, ["sb-kind=manifest", "sb-state=good", `sb-run=${RUN}`])],
    ["a warm manifest", snap(hex(1), 0, T("manifest", "warm"))],
    ["no tags", snap(hex(1), 0, ["user=1"])],
    ["an agent with another kind's identity too", snap(hex(1), 0, [...T("agent", "good"), `archive=${newId()}`])],
    ["an agent whose only identity is another kind's", snap(hex(1), 0, ["sb-kind=agent", "sb-state=good", `sb-run=${RUN}`, `tag=${newId()}`])],
    ["a host store with an identity tag", snap(hex(1), 0, [...T("hoststore", "good"), `agent=${newId()}`])],
    ["a manifest with an identity tag", snap(hex(1), 0, [...T("manifest", "good"), `tag=${newId()}`])],
    ["an agent with a manifest hash", snap(hex(1), 0, [...T("agent", "good"), `sb-manifest=${hex(5)}`])],
    ["a host store with a manifest hash", snap(hex(1), 0, [...T("hoststore", "good"), `sb-manifest=${hex(5)}`])],
  ]) assert.equal(classify(s, HOST), null, name);
});

test("roots: kept manifests and all they reference (an unchanged agent's old snapshot included), and good snapshots newer than the last manifest", () => {
  const mOld = hex(100), mNew = hex(101), oldAgent = hex(1), fresh = hex(2), orphan = hex(3);
  const snaps = [snap(mOld, T0 - 60 * DAY, T("manifest", "good")), snap(mNew, T0 - DAY, T("manifest", "good")),
    snap(oldAgent, T0 - 90 * DAY, T("agent", "good")), snap(orphan, T0 - 30 * DAY, T("agent", "good")), snap(fresh, T0, T("agent", "good"))];
  const contents = new Map([[mOld, [oldAgent]], [mNew, [oldAgent]]]);
  const roots = rootsOf(new Set([mOld, mNew]), contents, snaps, T0 - DAY, HOST);
  assert.deepEqual([...roots].sort(), [oldAgent, fresh, mOld, mNew].sort());
  refused(() => rootsOf(new Set([mOld]), new Map(), snaps, T0, HOST), "not_found");
});

test("forget: never a root, nothing not unambiguously ours, nothing of the active run (good or warm, however old)", () => {
  const roots = new Set([hex(1)]);
  const snaps = [
    snap(hex(1), T0 - 100 * DAY, T("agent", "good")), // root
    snap(hex(2), T0 - 10 * DAY, T("agent", "good", "20261101T030000Z-dddddddd")), // unreferenced, old
    snap(hex(3), T0 - 10 * DAY, ["user=1"]), // not ours
    snap(hex(4), T0 - 2 * DAY, T("agent", "warm", "20261122T030000Z-aaaaaaaa")), // stale warm
    snap(hex(5), T0 - 3600000, T("agent", "warm", "20261124T020000Z-bbbbbbbb")), // young warm of an ended run
    snap(hex(6), T0 - 3 * DAY, T("agent", "warm", RUN)), // the active run's warm
    snap(hex(7), T0 - 3600000, T("agent", "warm", "20261124T010000Z-cccccccc")), // young warm, run unknown: kept for now
    snap(hex(8), T0 - 20 * DAY, T("manifest", "good", "20261101T030000Z-dddddddd")), // a manifest not kept
    snap(hex(9), T0 - 30 * DAY, T("agent", "good", RUN)), // the active run's GOOD, older than anything
    snap(hex(10), T0 - 30 * DAY, T("agent", "good", "20261101T030000Z-dddddddd"), "other-host"), // another host's
    snap(hex(11), T0 - 30 * DAY, [...T("agent", "good", "20261101T030000Z-dddddddd"), "sb-state=warm"]), // ambiguous
  ];
  const plan = forgetPlan(snaps, roots, { now: T0, host: HOST, activeRun: RUN, endedRuns: new Set(["20261124T020000Z-bbbbbbbb"]) });
  assert.deepEqual(plan, [hex(2), hex(4), hex(5), hex(8)]);
  refused(() => forgetPlan(snaps, roots, {}), "bad_form");
});

/** A fake store for retentionPass: `snapshots` as the binary lists them; `manifests`: id -> manifest text. */
function store(snapshots, manifests, { failDump = null, failReadback = null } = {}) {
  const calls = [];
  const fn = async (req) => {
    calls.push(req);
    if (req.op === "snapshots") return { ok: true, value: { snapshots } };
    if (req.op === "readback") return failReadback === req.snapshot ? { ok: false, code: "readback_failed" } : { ok: true, value: { findings: 0 } };
    if (req.op === "dump") return failDump === req.snapshot ? { ok: false, code: "destination_unavailable" } : { ok: true, value: { text: manifests.get(req.snapshot) } };
    if (req.op === "forget") return { ok: true, value: { forgotten: req.snapshots.length } };
    throw new Error(req.op);
  };
  fn.calls = calls;
  return fn;
}
/** A time as the backup binary lists it (rustic's zoned timestamp: nanoseconds, an offset, a zone name). */
const binaryTime = (ms) => `${new Date(ms).toISOString().slice(0, 23)}123456+00:00[Etc/UTC]`;
const listed = (id, time, tags, { host = HOST, tree = hex(0) } = {}) => ({ id, time: binaryTime(time), tree, host, paths: ["/var/lib/sagebrush/backup/staging-x"], tags, summary: null });

/** A store holding one committed manifest and exactly the snapshots it references, plus `extra` listings. */
function committedStore(extra = [], { text = null, tag = null, edit = (x) => x } = {}) {
  const f = fixture();
  const m = buildManifest(f.args);
  const mtext = canonical(m) + "\n";
  const mid = hex(500);
  const refs = m.sets.map((set) => listed(set.snapshot, T0 - 2 * DAY, T(set.kind, "good", RUN, set.id), { tree: set.tree }));
  const snapshots = edit.call(m, [listed(mid, T0 - DAY, T("manifest", "good", RUN, tag ?? sha256(mtext))), ...refs, listed(m.hoststore, T0 - 2 * DAY, T("hoststore", "good")), ...extra]);
  return { binary: store(snapshots, new Map([[mid, text ?? mtext]])), mid, m };
}
const pass = (binary) => retentionPass({ binary }, { now: T0, host: HOST, parse: parseManifest, sha256, batch: 1 });

test("a snapshot's time as the binary prints it (RFC 9557: nanoseconds, an offset, a zone name), to ms; anything else NaN", () => {
  const ms = Date.parse("2026-11-26T19:14:23.438Z");
  assert.equal(snapshotTime("2026-11-26T19:14:23.438876374+00:00[Etc/UTC]"), ms, "the binary's own form (seen on a real store)");
  assert.equal(snapshotTime("2026-11-26T19:14:23.438Z"), ms);
  assert.equal(snapshotTime("2026-11-26T19:14:23.4388+00:00"), ms, "truncated, never rounded");
  assert.equal(snapshotTime("2026-11-26T11:14:23.438-08:00[America/Los_Angeles]"), ms, "an offset and its zone");
  assert.equal(snapshotTime("2026-11-26T19:14:23Z"), Date.parse("2026-11-26T19:14:23Z"), "no fraction");
  for (const bad of ["", "2026-11-26", "2026-11-26T19:14:23", "2026-11-26T19:14:23.1234567890Z", "2026-11-26T19:14:23Z[", "2026-11-26T19:14:23Z[Etc/UTC] x", null, 5]) {
    assert.ok(Number.isNaN(snapshotTime(bad)), JSON.stringify(bad));
  }
});

test("a snapshot time's fields are each in range, never normalized: impossible ones are NaN, each beside its valid twin", () => {
  for (const [bad, twin] of [
    ["2026-02-30T19:14:23.438876374+00:00[Etc/UTC]", "2026-02-28T19:14:23.438876374+00:00[Etc/UTC]"], // (Feb 30 isn't Mar 2)
    ["2026-02-29T00:00:00Z", "2028-02-29T00:00:00Z"], // (2026 isn't a leap year; 2028 is)
    ["2026-04-31T00:00:00Z", "2026-04-30T00:00:00Z"],
    ["2026-13-01T00:00:00Z", "2026-12-01T00:00:00Z"],
    ["2026-00-10T00:00:00Z", "2026-01-10T00:00:00Z"],
    ["2026-11-00T00:00:00Z", "2026-11-01T00:00:00Z"],
    ["2026-11-26T24:00:00+00:00[Etc/UTC]", "2026-11-26T23:00:00+00:00[Etc/UTC]"], // (hour 24 isn't the next midnight)
    ["2026-11-26T19:60:00Z", "2026-11-26T19:59:00Z"],
    ["2026-11-26T19:14:60Z", "2026-11-26T19:14:59Z"],
    ["2026-11-26T19:14:23+24:00", "2026-11-26T19:14:23+23:00"],
    ["2026-11-26T19:14:23+05:60", "2026-11-26T19:14:23+05:59"],
    ["0099-11-26T19:14:23Z", "2026-11-26T19:14:23Z"],
  ]) {
    assert.ok(Number.isNaN(snapshotTime(bad)), `${bad} refused`);
    assert.ok(Number.isFinite(snapshotTime(twin)), `${twin} accepted`);
  }
  assert.equal(snapshotTime("2028-02-29T00:00:00Z"), Date.parse("2028-02-29T00:00:00Z"));
  assert.equal(snapshotTime("2026-11-26T19:14:23.1+05:30[Asia/Kolkata]"), Date.parse("2026-11-26T13:44:23.100Z"));
  assert.equal(snapshotTime("2026-11-26T19:14:23.12-03:30"), Date.parse("2026-11-26T22:44:23.120Z"));
});

for (const [time, twin] of [["2026-02-30T19:14:23.438876374+00:00[Etc/UTC]", "2026-02-28T19:14:23.438876374+00:00[Etc/UTC]"], ["2026-11-20T24:00:00+00:00[Etc/UTC]", "2026-11-20T23:00:00+00:00[Etc/UTC]"]]) {
  test(`an impossible listing time stops the pass before any forget (${time}); its valid twin is forgotten as usual`, async () => {
    const at = (x) => ({ ...listed(hex(6), T0 - 2 * DAY, T("agent", "good", "20261101T030000Z-dddddddd")), time: x });
    const { binary } = committedStore([at(time)]);
    const r = await pass(binary);
    assert.equal(r.error, "bad_result");
    assert.equal(binary.calls.filter((c) => c.op === "forget").length, 0);
    const ok = committedStore([at(twin)]);
    const r2 = await pass(ok.binary);
    assert.deepEqual(r2.forgotten, [hex(6)], "the twin: an ordinary stale snapshot, forgotten");
  });
}

test("a listing time the binary wouldn't print stops the pass (bad_result), nothing forgotten", async () => {
  const { binary } = committedStore([{ ...listed(hex(6), T0 - 2 * DAY, T("agent", "good", "20261101T030000Z-dddddddd")), time: "yesterday" }]);
  const r = await pass(binary);
  assert.equal(r.error, "bad_result");
  assert.equal(binary.calls.filter((c) => c.op === "forget").length, 0);
});

test("a retention pass: the manifest checked against its bound hash, its references against the listing; forget only outside, in batches", async () => {
  const extra = [listed(hex(6), T0 - 2 * DAY, T("agent", "good", "20261101T030000Z-dddddddd")), listed(hex(7), T0 - 2 * DAY, T("agent", "warm", "20261122T030000Z-aaaaaaaa"))];
  const { binary, mid } = committedStore(extra);
  const r = await pass(binary);
  assert.deepEqual(r.kept, [mid]);
  assert.deepEqual(r.forgotten, [hex(6), hex(7)]);
  assert.deepEqual(binary.calls.filter((c) => c.op === "forget"), [{ op: "forget", snapshots: [hex(6)] }, { op: "forget", snapshots: [hex(7)] }]);
});

test("a manifest whose content names another host (its hash tag and listing local and valid): the pass stops, nothing forgotten", async () => {
  const s0 = committedStore([listed(hex(6), T0 - 2 * DAY, T("agent", "good", "20261101T030000Z-dddddddd"))]);
  const text = canonical({ ...s0.m, host: "other" }) + "\n";
  const list = (await s0.binary({ op: "snapshots" })).value.snapshots.map((x) => (x.id === s0.mid ? { ...x, tags: T("manifest", "good", RUN, sha256(text)) } : x));
  const b = store(list, new Map([[s0.mid, text]]));
  const r = await pass(b);
  assert.equal(r.error, "bad_manifest");
  assert.ok(!b.calls.some((c) => c.op === "forget"));
});

test("a manifest whose content is another run's than its sb-run tag (its hash valid): the pass stops, nothing forgotten", async () => {
  const s0 = committedStore([listed(hex(6), T0 - 2 * DAY, T("agent", "good", "20261101T030000Z-dddddddd"))]);
  const text = canonical(s0.m) + "\n"; // run RUN
  const list = (await s0.binary({ op: "snapshots" })).value.snapshots.map((x) => (x.id === s0.mid ? { ...x, tags: T("manifest", "good", "20261123T030000Z-eeeeeeee", sha256(text)) } : x));
  const b = store(list, new Map([[s0.mid, text]]));
  const r = await pass(b);
  assert.equal(r.error, "bad_manifest");
  assert.ok(!b.calls.some((c) => c.op === "forget"));
});

test("a retention pass with any doubt forgets nothing", async () => {
  const stale = listed(hex(6), T0 - 2 * DAY, T("agent", "good", "20261101T030000Z-dddddddd"));
  const variants = [
    ["a dump failure", committedStore([stale]), { failDump: true }],
    ["a read-back failure", committedStore([stale]), { failReadback: true }],
    ["an unparsable manifest", committedStore([stale], { text: "{}\n", tag: sha256("{}\n") })],
    ["text that isn't the bound hash", committedStore([stale], { tag: hex(4242) })],
    ["a referenced snapshot missing", committedStore([stale], { edit: (l) => l.filter((x) => x.id !== hex(2)) })],
    ["a referenced snapshot with another tree", committedStore([stale], { edit: (l) => l.map((x) => (x.id === hex(1) ? { ...x, tree: hex(99) } : x)) })],
    // the archive's own id, listed under another kind: only the kind is wrong
    ["a referenced snapshot of another kind", committedStore([stale], { edit: function (l) { const c = this.sets.find((x) => x.kind === "archive"); return l.map((x) => (x.id === c.snapshot ? { ...x, tags: T("agent", "good", RUN, c.id) } : x)); } })],
    ["the host store missing", committedStore([stale], { edit: (l) => l.filter((x) => x.id !== hex(5)) })],
    // only the id tag is wrong (same kind and tree), or only the state (the same snapshot listed as warm)
    ["a referenced snapshot with another id", committedStore([stale], { edit: function (l) { const a = this.sets.find((x) => x.kind === "agent"); return l.map((x) => (x.id === a.snapshot ? { ...x, tags: T("agent", "good", RUN, newId()) } : x)); } })],
    ["a referenced snapshot that is warm", committedStore([stale], { edit: function (l) { const a = this.sets.find((x) => x.kind === "agent"); return l.map((x) => (x.id === a.snapshot ? { ...x, tags: T("agent", "warm", RUN, a.id) } : x)); } })],
    ["a duplicate snapshot id", committedStore([stale, { ...stale }])],
  ];
  for (const [name, s, fail] of variants) {
    let binary = s.binary;
    if (fail?.failDump || fail?.failReadback) {
      const inner = s.binary;
      binary = async (req, o) => {
        if (fail.failDump && req.op === "dump" && req.snapshot === s.mid) return { ok: false, code: "destination_unavailable" };
        if (fail.failReadback && req.op === "readback" && req.snapshot === s.mid) return { ok: false, code: "readback_failed" };
        return inner(req, o);
      };
      binary.calls = inner.calls;
    }
    const r = await pass(binary);
    assert.ok(r.error, `${name}: an error`);
    assert.ok(!(binary.calls ?? []).some((c) => c.op === "forget"), `${name}: nothing forgotten`);
  }
  // the same store without any doubt does forget the stale snapshot (so the rows above test the doubt, not the store)
  const ok = await pass(committedStore([stale]).binary);
  assert.deepEqual(ok.forgotten, [hex(6)]);
});
