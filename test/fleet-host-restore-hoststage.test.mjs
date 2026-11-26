// Launcher contract A2 r3.14 r2 §2–§3, R6-d2 §4: begin's host-store stage over a fake launcher, binary and setquota on
// real temporary staging: the quota first, the stage, the marker, a crash's marked attempt re-imported in place and an
// unmarked one removed by its exact name, every refusal with no stage after it; close's removal by exact names.
import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "./host-linux-only.mjs";
import { FleetError, newId } from "../lib/fleet/index.mjs";
import { newRestoreRun } from "../lib/fleet/host/restore-record.mjs";
import { HOSTSTORE_BLOCKS_KB, HOSTSTORE_INODES, HOSTSTORE_PROJID, hostAttempts, removeHostStage, stageHostStore, stagedHostCopy } from "../lib/fleet/host/restore-hoststage.mjs";

const UID = typeof process.getuid === "function" ? process.getuid() : -1; // (Linux-only rows; off Linux the file only loads)
const RUN = newRestoreRun(1795500000000, () => Buffer.alloc(6));
const SNAP = "c".repeat(64);
const rejects = (p, code) => assert.rejects(p, (e) => e instanceof FleetError && e.code === code, code);
const refused = (fn, code) => assert.throws(fn, (e) => e instanceof FleetError && e.code === code, code);
const private_ = (p) => { mkdirSync(p, { recursive: true, mode: 0o700 }); chmodSync(p, 0o700); return p; };
const att = (staging, n) => join(staging, RUN, "host", "hoststore", String(n));

/** An attempt as the launcher leaves it: data/<leaf> (with the digest list beside it), the marker when `marked`. */
function plantAttempt(staging, n, { marked = true, leaf = "run1", marker } = {}) {
  for (const p of [join(staging, RUN), join(staging, RUN, "host"), join(staging, RUN, "host", "hoststore"), att(staging, n), join(att(staging, n), "data"), join(att(staging, n), "data", leaf)]) private_(p);
  writeFileSync(join(att(staging, n), "data", "digests.json"), "{}\n", { mode: 0o600 });
  if (marked) writeFileSync(join(att(staging, n), ".complete"), marker ?? `${RUN}/host/hoststore/${n}`);
}

/** The fakes: the binary (listing and usage), setquota, the launcher (its stage writes the attempt), removeUnder. */
function world({ usage = {}, quotaCode = 0, stageCode = 0, stageMarks = true, inStore = true } = {}) {
  const staging = private_(join(mkdtempSync(join(tmpdir(), "sb-hs-")), "staging"));
  const calls = [];
  const deps = {
    mount: "/srv/sagebrush",
    binary: async (req) => {
      calls.push(["binary", req.op]);
      if (req.op === "snapshots") return { ok: true, value: { snapshots: inStore ? [{ id: SNAP, paths: ["/var/lib/sagebrush/backup/hs-staging/run1"] }] : [] } };
      return { ok: true, value: { snapshot: SNAP, entries: 3, inodes: 3, blocks_upper: 3, peak_inodes: 3, peak_blocks_upper: 3, block_size: 4096, ...usage } };
    },
    setquota: async (args) => { calls.push(["setquota", ...args]); return { code: quotaCode }; },
    launch: async (args) => {
      calls.push(["launch", ...args]);
      const n = args[args.indexOf("--attempt") + 1];
      plantAttempt(staging, n, { marked: stageCode === 0 && stageMarks });
      return { code: stageCode };
    },
    removeUnder: async (anchor, name, tag) => { calls.push(["remove", anchor, name, tag]); },
  };
  return { staging, calls, deps, stage: (over = {}) => stageHostStore({ manifest: { hoststore: SNAP } }, { run: RUN, staging, uid: UID, ...over }, deps) };
}

test("a fresh stage: the quota first (110000, its block and inode limits), then restore-stage of the snapshot's path, marked, read in place", async () => {
  const w = world();
  const copy = await w.stage();
  assert.equal(copy, join(att(w.staging, 1), "data", "run1"));
  assert.deepEqual(w.calls, [
    ["binary", "snapshots"], ["binary", "usage"],
    ["setquota", "setquota", "-P", "110000", "0", String(HOSTSTORE_BLOCKS_KB), "0", String(HOSTSTORE_INODES), "/srv/sagebrush"],
    ["launch", "restore-stage", "--mount", "/srv/sagebrush", "--owner", "host", "--class", "hoststore", "--run", RUN, "--attempt", "1", "--projid", String(HOSTSTORE_PROJID), "--snapshot", SNAP, "--path", "var/lib/sagebrush/backup/hs-staging/run1"],
  ]);
  assert.equal(HOSTSTORE_BLOCKS_KB, (4 * 1024 + 64) * 1024, "4 GiB + 64 MiB, in KiB");
  // A crash after the stage: the same MARKED attempt is the copy again, with nothing re-run.
  const again = world();
  plantAttempt(again.staging, 3);
  assert.equal(await again.stage(), join(att(again.staging, 3), "data", "run1"));
  assert.deepEqual(again.calls, [], "no listing, quota or stage");
});

test("an unmarked attempt is never read: removed by its exact name, then a new attempt is staged", async () => {
  const w = world();
  plantAttempt(w.staging, 1, { marked: false });
  plantAttempt(w.staging, 2, { marked: true, marker: "another name" }); // (a marker that isn't its name: not marked)
  const copy = await w.stage();
  assert.equal(copy, join(att(w.staging, 3), "data", "run1"));
  assert.deepEqual(w.calls.filter((c) => c[0] === "remove"), [["remove", w.staging, `${RUN}/host/hoststore/1`, "hoststage"], ["remove", w.staging, `${RUN}/host/hoststore/2`, "hoststage"]]);
  assert.ok(w.calls.findIndex((c) => c[0] === "remove") < w.calls.findIndex((c) => c[0] === "launch"), "removed before the stage");
});

test("refusals: over the bound, no quota, a quota hit, another failure, an unmarked stage, a snapshot not in the store; no stage after any", async () => {
  // Over the bound by blocks or by inodes: limit, before the quota and the stage.
  for (const usage of [{ peak_blocks_upper: (HOSTSTORE_BLOCKS_KB * 1024) / 4096 + 1 }, { peak_inodes: HOSTSTORE_INODES + 1 }]) {
    const w = world({ usage });
    await rejects(w.stage(), "limit");
    assert.ok(!w.calls.some((c) => c[0] === "setquota" || c[0] === "launch"), JSON.stringify(usage));
  }
  // Exactly at the bound: staged.
  const edge = world({ usage: { peak_blocks_upper: (HOSTSTORE_BLOCKS_KB * 1024) / 4096, peak_inodes: HOSTSTORE_INODES } });
  assert.ok(await edge.stage());
  // The quota can't be set: no stage.
  const q = world({ quotaCode: 1 });
  await rejects(q.stage(), "outcome_unknown");
  assert.ok(!q.calls.some((c) => c[0] === "launch"));
  // The stage hits the quota (76): limit, the attempt removed; any other exit: outcome_unknown, removed; exit 0 with no
  // marker: outcome_unknown, removed.
  for (const [over, code] of [[{ stageCode: 76 }, "limit"], [{ stageCode: 73 }, "outcome_unknown"], [{ stageMarks: false }, "outcome_unknown"]]) {
    const w = world(over);
    await rejects(w.stage(), code);
    assert.deepEqual(w.calls.at(-1), ["remove", w.staging, `${RUN}/host/hoststore/1`, "hoststage"], JSON.stringify(over));
  }
  // The snapshot isn't in the store: not_found, before anything.
  const n = world({ inStore: false });
  await rejects(n.stage(), "not_found");
  assert.ok(!n.calls.some((c) => c[0] === "setquota"));
  // A lost lock (the guard throws) before the quota: nothing more.
  const g = world();
  let i = 0;
  await assert.rejects(g.stage({ guard: () => { if (++i === 1) throw Object.assign(new Error("lost"), { code: "outcome_unknown" }); } }));
  assert.ok(!g.calls.some((c) => c[0] === "setquota" || c[0] === "launch"));
});

test("the copy is found only as one marked attempt with one leaf, every ancestor a private directory", () => {
  const staging = private_(join(mkdtempSync(join(tmpdir(), "sb-hs-")), "staging"));
  assert.equal(stagedHostCopy(RUN, { staging, uid: UID }), null);
  plantAttempt(staging, 1, { marked: false });
  assert.equal(stagedHostCopy(RUN, { staging, uid: UID }), null, "unmarked: none");
  plantAttempt(staging, 2);
  assert.equal(stagedHostCopy(RUN, { staging, uid: UID }), join(att(staging, 2), "data", "run1"));
  plantAttempt(staging, 4);
  refused(() => stagedHostCopy(RUN, { staging, uid: UID }), "not_granted"); // (two marked)
  const two = private_(join(mkdtempSync(join(tmpdir(), "sb-hs-")), "staging"));
  plantAttempt(two, 1);
  private_(join(att(two, 1), "data", "other"));
  refused(() => stagedHostCopy(RUN, { staging: two, uid: UID }), "not_granted"); // (two leaves)
  // An ancestor that isn't a private directory (group or other writable): refused (moved from the context rows).
  for (const level of [join(RUN), join(RUN, "host"), join(RUN, "host", "hoststore")]) {
    const s = private_(join(mkdtempSync(join(tmpdir(), "sb-hs-")), "staging"));
    plantAttempt(s, 1);
    chmodSync(join(s, level), 0o777);
    // (an unmarked/unlisted path is never reached; a marked one under a writable ancestor refuses)
    assert.throws(() => stagedHostCopy(RUN, { staging: s, uid: UID }), (e) => e instanceof FleetError && e.code === "not_granted", level);
  }
  assert.deepEqual(hostAttempts(RUN, { staging }), [1, 2, 4]);
});

test("close's removal: every hoststore attempt of the run by its exact name; begin's close requires it, before the commit", async () => {
  const staging = private_(join(mkdtempSync(join(tmpdir(), "sb-hs-")), "staging"));
  plantAttempt(staging, 1, { marked: false });
  plantAttempt(staging, 2);
  const removed = [];
  await removeHostStage(RUN, { staging }, { removeUnder: async (a, n, t) => { removed.push([a, n, t]); } });
  assert.deepEqual(removed, [[staging, `${RUN}/host/hoststore/1`, "hoststage"], [staging, `${RUN}/host/hoststore/2`, "hoststage"]]);
  // close without the removal: refused before anything (bad_form), nothing committed.
  const { close } = await import("../lib/fleet/host/restore-begin.mjs");
  const dir = private_(join(mkdtempSync(join(tmpdir(), "sb-hs-")), "restore"));
  await rejects(close({ now: () => 1, restoreRaised: () => false }, { dir }), "bad_form");
  assert.equal(existsSync(join(dir, "plan.json")), false);
  void newId;
});

test("isolation: every set's staging discard (the fill's, and the abandon finish's `all`) and its gone-proof never list or remove host/, which stays byte-identical", async () => {
  const { readdirSync, readFileSync, rmSync, lstatSync } = await import("node:fs");
  const { stagingRemover } = await import("../lib/fleet/host/restore-adapters.mjs");
  const { STAGED, ownerOf } = await import("../lib/fleet/host/restore-record.mjs");
  const tree = (p) => (lstatSync(p).isDirectory()
    ? Object.fromEntries(readdirSync(p).sort().map((n) => [n, tree(join(p, n))]))
    : readFileSync(p).toString("base64"));
  for (const kind of ["agent", "archive", "tag"]) {
    for (const all of [false, true]) {
      const staging = private_(join(mkdtempSync(join(tmpdir(), "sb-hs-iso-")), "staging"));
      plantAttempt(staging, 1);
      plantAttempt(staging, 2, { marked: false });
      const id = newId();
      const owner = ownerOf(kind, id);
      for (const cls of STAGED[kind]) for (const n of ["1", "2"]) private_(join(staging, RUN, owner, cls, n));
      const host = tree(join(staging, RUN, "host"));
      const named = [];
      const launch = async (args) => {
        const name = args[args.indexOf("--name") + 1];
        named.push(name);
        if (args[0] === "identify") return { code: 0, stdout: `${JSON.stringify({ epoch: "e", fsid: "f", object: { dev: "1", ino: "2" } })}\n` };
        rmSync(join(staging, name), { recursive: true });
        return { code: 0 };
      };
      const { discardStaging, stagingGone } = stagingRemover(kind, id, { launch, staging, expect: () => "/x" });
      await discardStaging({ state: "failed", run: RUN, attempt: 1 }, { all });
      assert.ok(named.length > 0 && named.every((n) => n.startsWith(`${RUN}/${owner}/`)), `${kind}: only the set's own names`);
      assert.equal(stagingGone(), true, `${kind}: the set's staging is gone`);
      assert.deepEqual(tree(join(staging, RUN, "host")), host, `${kind} (all ${all}): host/ byte-identical`);
    }
  }
});
