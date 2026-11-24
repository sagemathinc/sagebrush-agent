// Host backup (design: agent-autonomous-host-backup.md r3.3 §5 step 4, §4 "The host manifest"): what a restore
// restores from. Nothing here restores anything.
//
// - **Listing:** every committed manifest in the store, of every host (a restore runs on a fresh host, so the
//   manifests are another host's). Each is read back, dumped, its text's sha256 checked against its own sb-manifest
//   tag (bound when it was committed), parsed (exactly canonical, closed shape) and bound to its snapshot's host and
//   run. A manifest that fails any of these is listed as unusable, with why, and never offered; the others still are.
// - **Choosing:** the chosen manifest is checked again against a FRESH listing before anything else: it must be one
//   the listing offered, every snapshot it references must be in the store exactly once and be what it says
//   (verifyReferences), and each must read back with no findings. Any doubt refuses the choice.
// - **The plan** (<RESTORE_DIR>/plan.json, root 0600): the restore's authority from then on. It binds the chosen
//   manifest (its snapshot id and its text's sha256) and, per source set, the run and snapshot its restore record
//   must carry (restoreReady's `expected`). It is created once; a set's new restore request (the person's, after a
//   stop) gives that set a new run, and nothing else changes it.
// - **One restore at a time:** every restore step runs under <RESTORE_DIR>/.lock.

import * as fs from "node:fs";
import { join } from "node:path";
import { isId, refuse } from "../bytes.mjs";
import { RESTORE_DIR } from "./names.mjs";
import { classify, verifyReferences } from "./backup-retention.mjs";
import { MANIFEST_FILE, parseManifest, sha256 } from "./backup-manifest.mjs";
import { RESTORE_RUN, runTime } from "./restore-record.mjs";
import { exactKeys, lockDir, realIo, writeDurable, writeExclusive } from "./store.mjs";

export const PLAN = "plan.json";
const RUN = RESTORE_RUN;
const HEX64 = /^[0-9a-f]{64}$/;
const HOST = /^[A-Za-z0-9-]{1,64}$/;
const KINDS = ["agent", "archive", "tag"];
const MS = 30 * 60 * 1000;

/** List the store's snapshots, each id exactly once. Resolves to { snapshots, byId } or { error, snapshot? }. */
async function listing(deps, ms) {
  const list = await deps.binary({ op: "snapshots" }, { ms });
  if (!list.ok) return { error: list.code };
  const byId = new Map();
  for (const s of list.value.snapshots) {
    if (byId.has(s.id)) return { error: "bad_result", snapshot: s.id }; // a duplicate id: nothing is certain
    byId.set(s.id, s);
  }
  return { snapshots: list.value.snapshots, byId };
}

/**
 * Read one manifest snapshot back: readback with no findings, dump its file, check the text against its sb-manifest
 * tag, parse it, and bind its content to the snapshot's host and run. Resolves to { manifest, sha256 } or { error }.
 */
async function readManifest(deps, s, ms) {
  const c = classify(s, s.host);
  if (!c || c.kind !== "manifest") return { error: "bad_manifest" };
  if (s.paths.length !== 1) return { error: "bad_manifest" };
  const rb = await deps.binary({ op: "readback", snapshot: s.id }, { ms });
  if (!rb.ok) return { error: rb.code };
  if (rb.value.findings !== 0) return { error: "check_failed" };
  const d = await deps.binary({ op: "dump", snapshot: s.id, path: `${s.paths[0].slice(1)}/${MANIFEST_FILE}` }, { ms });
  if (!d.ok) return { error: d.code };
  if (sha256(d.value.text) !== c.manifest) return { error: "bad_manifest" }; // not the bytes it committed
  let m;
  try { m = parseManifest(d.value.text); } catch { return { error: "bad_manifest" }; }
  if (m.host !== s.host || m.run !== c.run) return { error: "bad_manifest" }; // its content must be its snapshot's
  return { manifest: m, sha256: c.manifest };
}

/**
 * Every committed manifest in the store, newest first by the manifest's own time (then snapshot id). Resolves to
 * { manifests: [{ snapshot, host, run, time, agents, deleted, tags }], unusable: [{ snapshot, host, error }] }, or
 * { error, snapshot? } when the listing itself can't be trusted. Only snapshots that classify as a manifest of their
 * own host are read; anything else in the store is not a manifest and isn't listed.
 */
export async function listManifests(deps, { ms = MS } = {}) {
  const l = await listing(deps, ms);
  if (l.error) return l;
  const manifests = [], unusable = [];
  for (const s of l.snapshots) {
    if (classify(s, s.host)?.kind !== "manifest") continue;
    const r = await readManifest(deps, s, ms);
    if (r.error) { unusable.push({ snapshot: s.id, host: s.host, error: r.error }); continue; }
    const agents = Object.values(r.manifest.registry.agents);
    manifests.push({
      snapshot: s.id, host: r.manifest.host, run: r.manifest.run, time: r.manifest.time,
      agents: agents.filter((a) => a.state !== "deleted").length, deleted: agents.filter((a) => a.state === "deleted").length,
      tags: Object.keys(r.manifest.registry.tags).length,
    });
  }
  manifests.sort((a, b) => Date.parse(b.time) - Date.parse(a.time) || (a.snapshot < b.snapshot ? -1 : 1));
  unusable.sort((a, b) => (a.snapshot < b.snapshot ? -1 : 1));
  return { manifests, unusable };
}

/**
 * Check the chosen manifest (by its snapshot id) before any restore step, against a fresh listing: it is read again
 * as listManifests reads it, every snapshot it references is verified against the listing and read back with no
 * findings. Resolves to { manifest, snapshot, sha256 } or { error, snapshot? } (the first problem).
 */
export async function chooseManifest(deps, snapshot, { ms = MS } = {}) {
  if (typeof snapshot !== "string" || !HEX64.test(snapshot)) refuse("bad_form", "restore plan: not a snapshot id");
  const l = await listing(deps, ms);
  if (l.error) return l;
  const s = l.byId.get(snapshot);
  if (!s) return { error: "not_found", snapshot };
  const r = await readManifest(deps, s, ms); // a snapshot that isn't a manifest is bad_manifest here
  if (r.error) return { error: r.error, snapshot };
  const problem = verifyReferences(r.manifest, l.byId, r.manifest.host);
  if (problem) return problem;
  for (const ref of [...r.manifest.sets.map((x) => x.snapshot), r.manifest.hoststore]) {
    const rb = await deps.binary({ op: "readback", snapshot: ref }, { ms });
    if (!rb.ok) return { error: rb.code, snapshot: ref };
    if (rb.value.findings !== 0) return { error: "check_failed", snapshot: ref };
  }
  return { manifest: r.manifest, snapshot, sha256: r.sha256 };
}

const setKey = (kind, id) => `${kind}-${id}`;
const KEY = /^(agent|archive|tag)-([a-z2-7]{25}[aeimquy4])$/;

/** The plan's closed shape. Returns it, or refuses (bad_form). */
export function checkPlan(p) {
  const bad = () => refuse("bad_form", "restore plan: not a valid plan");
  if (!exactKeys(p, ["v", "host", "manifest", "sha256", "hoststore", "sets"]) || p.v !== 1) bad();
  if (typeof p.host !== "string" || !HOST.test(p.host) || typeof p.manifest !== "string" || !HEX64.test(p.manifest)
    || typeof p.sha256 !== "string" || !HEX64.test(p.sha256) || typeof p.hoststore !== "string" || !HEX64.test(p.hoststore)) bad();
  if (p.sets === null || typeof p.sets !== "object" || Array.isArray(p.sets)) bad();
  for (const [k, v] of Object.entries(p.sets)) {
    if (!KEY.test(k) || !exactKeys(v, ["run", "snapshot", "tree"]) || typeof v.run !== "string" || !RUN.test(v.run)
      || typeof v.snapshot !== "string" || !HEX64.test(v.snapshot) || typeof v.tree !== "string" || !HEX64.test(v.tree)) bad();
  }
  return p;
}

/**
 * A new plan from a chosen manifest (chooseManifest's result) and the restore's run: every set of the manifest, each
 * bound to `run` and the manifest's snapshot and tree for it.
 */
export function newPlan(chosen, run) {
  if (typeof run !== "string" || !RUN.test(run)) refuse("bad_form", "restore plan: bad run");
  const m = chosen.manifest;
  const sets = {};
  for (const s of m.sets) {
    if (!KINDS.includes(s.kind) || !isId(s.id)) refuse("bad_form", "restore plan: bad set");
    sets[setKey(s.kind, s.id)] = { run, snapshot: s.snapshot, tree: s.tree };
  }
  return checkPlan({ v: 1, host: m.host, manifest: chosen.snapshot, sha256: chosen.sha256, hoststore: m.hoststore, sets });
}

/**
 * The plan after the person's new restore request for one set: that set's run becomes `run`, which must be NEWER than
 * its current run by decoded time (runTime; restore runs carry their millisecond, and strings of [a-z2-7] don't sort
 * by it), so it can never be a run the set had before. Its snapshot and tree stay the manifest's. Nothing else changes.
 */
export function replanSet(p, kind, id, run) {
  checkPlan(p);
  const k = setKey(kind, id);
  if (!Object.hasOwn(p.sets, k)) refuse("not_found", "restore plan: not a set of this restore");
  if (typeof run !== "string" || !RUN.test(run)) refuse("bad_form", "restore plan: bad run");
  if (runTime(run) <= runTime(p.sets[k].run)) refuse("bad_form", "restore plan: a new request is a newer run");
  return checkPlan({ ...p, sets: { ...p.sets, [k]: { ...p.sets[k], run } } });
}

/** restoreReady's `expected`: { "<kind>-<id>": { run, snapshot } } for every set of the plan. */
export function expectedOf(p) {
  checkPlan(p);
  return Object.fromEntries(Object.entries(p.sets).map(([k, v]) => [k, { run: v.run, snapshot: v.snapshot }]));
}

/** Read the plan: null when there is none; a present but unreadable or invalid file throws (never "none"). */
export function readPlan({ dir = RESTORE_DIR, fsx = fs } = {}) {
  let text;
  try { text = fsx.readFileSync(join(dir, PLAN), "utf8"); } catch (e) { if (e?.code === "ENOENT") return null; throw e; }
  let p;
  try { p = JSON.parse(text); } catch { refuse("bad_form", "restore plan: not JSON"); }
  return checkPlan(p);
}

/**
 * Create the plan, once: exclusive and durable. The same plan again is fine (a retry after a crash); any other plan
 * where one exists refuses (in_progress): a host restores from one manifest.
 */
export function createPlan(p, { dir = RESTORE_DIR, io = realIo } = {}) {
  checkPlan(p);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  try { writeExclusive(dir, PLAN, JSON.stringify(p) + "\n", io); } catch (e) {
    if (e?.code === "EEXIST") refuse("in_progress", "restore plan: this host already has another restore plan");
    throw e;
  }
}

/**
 * Write a re-planned set (replanSet's result) over the existing plan, durably: exactly ONE set's new request. Refuses
 * (not_granted) unless the existing plan is the same restore (host, manifest, sha256, host store, the same sets),
 * every other set is exactly as it was, and the one changed set keeps its snapshot and tree with a run newer by
 * decoded time. The same plan again (a retry after the write) writes nothing, but makes the plan durable again (the
 * file, then its directory) and reads it back before it counts.
 */
export function updatePlan(next, { dir = RESTORE_DIR, io = realIo } = {}) {
  checkPlan(next);
  const cur = readPlan({ dir });
  if (cur === null) refuse("not_found", "restore plan: no plan to update");
  // Already written (a retry): the earlier write may have failed after its rename, before its directory's fsync, so
  // the plan is made durable again (the file, then its directory) and read back before the update counts.
  if (JSON.stringify(cur) === JSON.stringify(next)) return flushPlan(dir, JSON.stringify(next) + "\n", io);
  const same = cur.host === next.host && cur.manifest === next.manifest && cur.sha256 === next.sha256 && cur.hoststore === next.hoststore
    && Object.keys(cur.sets).sort().join() === Object.keys(next.sets).sort().join();
  const changed = same ? Object.keys(next.sets).filter((k) => JSON.stringify(next.sets[k]) !== JSON.stringify(cur.sets[k])) : [];
  const was = cur.sets[changed[0]], now = next.sets[changed[0]];
  const one = changed.length === 1 && now.snapshot === was.snapshot && now.tree === was.tree && runTime(now.run) > runTime(was.run);
  if (!same || !one) refuse("not_granted", "restore plan: an update is exactly one set's new, newer run");
  writeDurable(dir, PLAN, JSON.stringify(next) + "\n", io);
}

/** fsync the plan file, then its directory, then read it back: it must be exactly `text`. Throws on any failure. */
function flushPlan(dir, text, io) {
  for (const p of [join(dir, PLAN), dir]) {
    const fd = io.open(p, "r");
    try { io.fsync(fd); } finally { io.close(fd); }
  }
  if (fs.readFileSync(join(dir, PLAN), "utf8") !== text) refuse("outcome_unknown", "restore plan: the plan read back differs");
}

/** Run `fn` under the restore lock, <dir>/.lock, waited for at most waitMs. Refuses with in_progress when busy. */
export async function withRestoreLock(fn, { dir = RESTORE_DIR, waitMs = 0 } = {}) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const lock = await lockDir(dir, { waitMs });
  try { return await fn(lock); } finally { await lock.release(); }
}
