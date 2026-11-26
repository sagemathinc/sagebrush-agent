// Host restore e2e r1.7, delta d2 (agent-autonomous-host-restore-worker-inputs-d1.md): the restore worker's INPUT,
// one file per set. The worker runs outside the executor and can't open the host store (the supervisor holds its one
// lock), so the dispatch, in the executor's queue with the store open, copies what the worker needs into
// <restore>/inputs/<kind>-<id>.json before it starts the worker:
//
//   { v: 1, kind, id, run, nonce,
//     classes: { <cls>: { dest: { epoch, fsid, object }, owners: { uids, gid, projid }, unrestorable: [<path>...] } },
//     members: [{ agent, uid }...] }
//
// - `classes` has exactly the kind's classes. Each class carries its OWN owners, and `dest` is the trusted identity
//   the provisioning (or the destination's creator) RECORDED, never a fresh read of the path.
// - `members` are the agents whose stop the set's validation proves: the agent itself; a tag's live members, sorted
//   by uid, whose uids are exactly the tag class's owner uids; none for an archive.
// - `nonce` is fresh per dispatch and also the worker's argv: a worker acts only on its own dispatch's input.
// - The file is root 0600 in a proven private directory, written durably, read back by a no-follow same-object read,
//   and checked whole: one over a cap, a missing, extra or duplicate key, or an identity that isn't one refuses.
// - Freshness (d2 §4): every executor step that can change a copied fact removes the affected sets' inputs, under
//   those sets' locks, BEFORE it makes the change (removeInputs); only executor steps ever remove an input.

import * as fs from "node:fs";
import { join } from "node:path";
import { isId, refuse } from "../bytes.mjs";
import { RESTORE_DIR } from "./names.mjs";
import { exactKeys, realIo, writeDurable } from "./store.mjs";
import { CLASSES, KINDS, RESTORE_RUN, readRegular } from "./restore-record.mjs";
import { ownersOf } from "./restore-fill.mjs";
import { parseKey, provenDir } from "./restore-begin.mjs";
import { checkObject } from "./deprovision-record.mjs";

/** The inputs' directory, beneath the restore directory. */
export const INPUTS = "inputs";
/** Caps (d2 §2). */
export const MAX_INPUT_BYTES = 2 ** 20;
export const MAX_MEMBERS = 64;
export const MAX_UNRESTORABLE = 1000;
export const MAX_PATH_BYTES = 4096;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const FSID = /^[0-9a-f]{16}$/;
const u32 = (n) => Number.isSafeInteger(n) && n >= 0 && n <= 0xffffffff;
const isMap = (o) => o !== null && typeof o === "object" && !Array.isArray(o);
const bad = (why) => refuse("bad_form", `restore input: ${why}`);
const ascending = (xs) => xs.every((x, i) => i === 0 || xs[i - 1] < x);

/** A destination's recorded identity: the launcher's { epoch, fsid, object }, the object a directory. */
export function checkDest(d) {
  return exactKeys(d, ["epoch", "fsid", "object"]) && isMap(d.epoch) && exactKeys(d.epoch, ["boot_id", "mnt_id"])
    && typeof d.epoch.boot_id === "string" && UUID.test(d.epoch.boot_id) && Number.isSafeInteger(d.epoch.mnt_id) && d.epoch.mnt_id >= 0
    && typeof d.fsid === "string" && FSID.test(d.fsid) && checkObject(d.object) && d.object.type === "dir";
}

const checkOwners = (o) => exactKeys(o, ["uids", "gid", "projid"]) && Array.isArray(o.uids) && o.uids.length >= 1 && o.uids.length <= MAX_MEMBERS
  && o.uids.every(u32) && ascending(o.uids) && u32(o.gid) && u32(o.projid);

const checkPaths = (ps) => Array.isArray(ps) && ps.length <= MAX_UNRESTORABLE && ps.every((p) => typeof p === "string" && p.length > 0
  && Buffer.byteLength(p, "utf8") <= MAX_PATH_BYTES) && new Set(ps).size === ps.length;

/** The whole closed shape (refuses anything else, bad_form). Returns the input. */
export function checkInput(x) {
  if (!exactKeys(x, ["v", "kind", "id", "run", "nonce", "classes", "members"]) || x.v !== 1) bad("not an input");
  if (!KINDS.includes(x.kind) || !isId(x.id) || typeof x.run !== "string" || !RESTORE_RUN.test(x.run) || !isId(x.nonce)) bad("bad set, run or nonce");
  if (!isMap(x.classes) || !exactKeys(x.classes, CLASSES[x.kind])) bad("not exactly the kind's classes");
  for (const cls of CLASSES[x.kind]) {
    const c = x.classes[cls];
    if (!exactKeys(c, ["dest", "owners", "unrestorable"]) || !checkDest(c.dest) || !checkOwners(c.owners) || !checkPaths(c.unrestorable)) bad(`bad class ${cls}`);
  }
  const m = x.members;
  if (!Array.isArray(m) || m.length > MAX_MEMBERS || !m.every((e) => exactKeys(e, ["agent", "uid"]) && isId(e.agent) && u32(e.uid))) bad("bad members");
  if (!ascending(m.map((e) => e.uid)) || new Set(m.map((e) => e.agent)).size !== m.length) bad("members not sorted or repeated");
  // The members' uid image is exactly the set's owners: the agent's own uid; a tag's live members; no one for an archive.
  const uids = m.map((e) => e.uid);
  const want = x.kind === "archive" ? [] : x.classes[CLASSES[x.kind][0]].owners.uids;
  if (uids.length !== want.length || uids.some((u, i) => u !== want[i])) bad("the members aren't the set's owners");
  if (x.kind === "agent" && (m.length !== 1 || m[0].agent !== x.id)) bad("an agent set's member is the agent");
  return x;
}

/**
 * Build a set's input from the store's facts at the dispatch: `registry` (the registry's snapshot, as ownersOf reads
 * it), `destOf(kind, id, cls)` (the RECORDED identity, { epoch, fsid, object }, or null), `unrestorableOf(kind, id,
 * cls)` (the manifest's paths). Resolves to the checked input, or null with no input when a trusted identity is missing
 * (no record, or a record of another epoch: the caller decides, and requalify or provisioning comes first).
 */
export function buildInput({ kind, id, run, nonce, registry, destOf, unrestorableOf }) {
  const classes = {};
  for (const cls of CLASSES[kind]) {
    const dest = destOf(kind, id, cls);
    if (dest === null || dest === undefined) return null;
    classes[cls] = { dest, owners: ownersOf(kind, id, registry), unrestorable: [...unrestorableOf(kind, id, cls)] };
  }
  let members = [];
  if (kind === "agent") members = [{ agent: id, uid: registry.agents[id].uid }];
  if (kind === "tag") {
    members = Object.entries(registry.agents).filter(([, a]) => a.state !== "deleted" && a.tags.includes(id))
      .map(([agent, a]) => ({ agent, uid: a.uid })).sort((p, q) => p.uid - q.uid);
  }
  return checkInput({ v: 1, kind, id, run, nonce, classes, members });
}

const key = (kind, id) => { if (!KINDS.includes(kind) || !isId(id)) bad("bad set"); return `${kind}-${id}`; };

/** Write a set's input, durably, root 0600, in the proven inputs directory (created private), replacing any earlier. */
export function writeInput(input, { dir = RESTORE_DIR, uid = 0, io = realIo } = {}) {
  checkInput(input);
  const text = JSON.stringify(input) + "\n";
  if (Buffer.byteLength(text) > MAX_INPUT_BYTES) bad("too long");
  writeDurable(provenDir(dir, INPUTS, { uid, create: true }), `${key(input.kind, input.id)}.json`, text, io);
}

/** A set's input, checked whole, or null when there is none (no inputs directory, or no file). */
export function readInput(kind, id, { dir = RESTORE_DIR, uid = 0 } = {}) {
  const k = key(kind, id);
  let idir;
  try { idir = provenDir(dir, INPUTS, { uid }); } catch (e) { if (e?.code === "ENOENT") return null; throw e; }
  const bytes = readRegular(join(idir, `${k}.json`), MAX_INPUT_BYTES, "an input", fs, { tries: 3 });
  if (bytes === null) return null;
  let x;
  try { x = JSON.parse(bytes.toString("utf8")); } catch { bad("not JSON"); }
  return checkInput(x);
}

/**
 * Remove the inputs of `keys` (set keys), durably: each name unlinked (whatever it is: a link is removed itself, never
 * followed), then the directory synced once. Missing is fine; no inputs directory, nothing to do.
 */
export function removeInputs(keys, { dir = RESTORE_DIR, uid = 0, io = realIo } = {}) {
  for (const k of keys) parseKey(k);
  let idir;
  try { idir = provenDir(dir, INPUTS, { uid }); } catch (e) { if (e?.code === "ENOENT") return; throw e; }
  let removed = false;
  for (const k of keys) {
    try { fs.unlinkSync(join(idir, `${k}.json`)); removed = true; } catch (e) { if (e?.code !== "ENOENT") throw e; }
  }
  if (!removed) return;
  const dfd = io.open(idir, "r");
  try { io.fsync(dfd); } finally { io.close(dfd); }
}
