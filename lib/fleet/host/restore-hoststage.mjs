// Host restore (launcher contract A2 r3.14 r2 §2, §3; R6-d2 §4): begin's host-store snapshot, staged by the launcher as
// the stage-only `hoststore` class of the owner `host`, and consumed IN PLACE.
//
// - **The bound:** before any stage, project 110000's hard limits are set (setquota -P): the host store's 4 GiB plus
//   64 MiB of headroom, and the agents' inode limit. The kernel charges every byte and inode the stage writes, during
//   the walk; concurrent attempts share the project. A quota hit (76) is permanent for the snapshot: refused (limit).
//   The binary's `usage` of the snapshot's path is an early refusal only.
// - **The attempt:** `<staging>/<run>/host/hoststore/<attempt>`, `<run>` the restore's. Its `.complete` marker, exactly
//   its name, is written last by the launcher. A MARKED attempt is the copy (after a crash, begin re-imports the same
//   one); an unmarked one is never read: it is removed (remove-tree, owners [0], its exact name) before a new stage.
// - **The copy** is the attempt's `data/<leaf>`: data/ holds exactly that directory and the digest list.
// - **Close** removes every hoststore attempt of the run, by the same exact names; nothing else touches `host/`.

import { join } from "node:path";
import * as fs from "node:fs";
import { refuse } from "../bytes.mjs";
import { RESTORE_STAGING } from "./names.mjs";
import { provenDir } from "./restore-begin.mjs";
import { QUOTA_INODES } from "./provision.mjs";

export const HOSTSTORE_PROJID = 110000;
/** The hard block limit in KiB (setquota's unit): the host store's own bound plus 64 MiB of headroom. */
export const HOSTSTORE_BLOCKS_KB = (4 * 1024 * 1024 * 1024 + 64 * 1024 * 1024) / 1024;
export const HOSTSTORE_INODES = QUOTA_INODES;
const ATTEMPT = /^[1-9][0-9]{0,5}$/;
const DIGESTS = "digests.json";

const attemptName = (run, n) => `${run}/host/hoststore/${n}`;
const names = (fsx, p) => { try { return fsx.readdirSync(p); } catch (e) { if (e?.code === "ENOENT") return []; throw e; } };

/** The run's hoststore attempt numbers, ascending. */
export function hostAttempts(run, { staging = RESTORE_STAGING, fsx = fs } = {}) {
  return names(fsx, join(staging, run, "host", "hoststore")).filter((n) => ATTEMPT.test(n)).map(Number).sort((a, b) => a - b);
}

/** Is the attempt marked: its `.complete` a regular file holding exactly its name? */
function marked(run, n, { staging, fsx }) {
  const p = join(staging, attemptName(run, n), ".complete");
  let st;
  try { st = fsx.lstatSync(p); } catch (e) { if (e?.code === "ENOENT") return false; throw e; }
  return st.isFile() && fsx.readFileSync(p, "utf8") === attemptName(run, n);
}

/**
 * The run's staged host-store copy: the path of the ONE marked attempt's `data/<leaf>` (each component proven a private
 * directory of `uid`), or null when there is none. Two marked attempts refuse (the launcher never leaves two).
 */
export function stagedHostCopy(run, { staging = RESTORE_STAGING, uid = 0, fsx = fs } = {}) {
  const done = hostAttempts(run, { staging, fsx }).filter((n) => marked(run, n, { staging, fsx }));
  if (done.length === 0) return null;
  if (done.length > 1) refuse("not_granted", "restore host store: more than one completed stage");
  const data = provenDir(staging, `${attemptName(run, done[0])}/data`, { uid, fsx });
  const leaves = names(fsx, data).filter((n) => n !== DIGESTS);
  if (leaves.length !== 1) refuse("not_granted", "restore host store: the stage isn't exactly one copy");
  return provenDir(data, leaves[0], { uid, fsx });
}

/**
 * Stage the manifest's host-store snapshot (begin's dep). `deps`: binary(req, { ms }) (the backup binary's runner),
 * launch(args, { ms }) (the launcher's), setquota(args) (resolves to { code }), mount (the quota mount),
 * removeUnder(anchor, name, tag) (restore-adapters' stagingRemover). Options: `run`, `guard()`, `staging`, `uid`.
 * Resolves to the copy's path (stagedHostCopy's).
 */
export async function stageHostStore(chosen, { run, guard = () => {}, staging = RESTORE_STAGING, uid = 0, fsx = fs, ms = 30 * 60 * 1000 }, deps) {
  // A marked attempt is the copy: after a crash, the same one is re-imported (A2 r3.14 r2 §3, H5).
  const have = stagedHostCopy(run, { staging, uid, fsx });
  if (have !== null) return have;
  // Unmarked attempts are never read: removed, by their exact names, before a new stage.
  for (const n of hostAttempts(run, { staging, fsx })) { guard(); await deps.removeUnder(staging, attemptName(run, n), "hoststage"); }
  // The snapshot's single path, from the store's listing.
  const snapshot = chosen?.manifest?.hoststore;
  const list = await deps.binary({ op: "snapshots" }, { ms });
  if (!list?.ok) refuse("outcome_unknown", "restore host store: the store can't be listed");
  const snap = list.value.snapshots.find((s) => s.id === snapshot);
  if (!snap || snap.paths.length !== 1) refuse("not_found", "restore host store: the host-store snapshot isn't in the store");
  const path = snap.paths[0].replace(/^\/+/, "");
  // The early refusal: the binary's usage of the path, against the quota.
  const usage = await deps.binary({ op: "usage", snapshot, path }, { ms });
  if (!usage?.ok) refuse("outcome_unknown", "restore host store: the snapshot's usage can't be read");
  if (usage.value.peak_blocks_upper * usage.value.block_size > HOSTSTORE_BLOCKS_KB * 1024 || usage.value.peak_inodes > HOSTSTORE_INODES) {
    refuse("limit", "restore host store: larger than the host store's bound");
  }
  // The bound itself: project 110000's hard limits, set before the stage.
  guard();
  const q = await deps.setquota(["setquota", "-P", String(HOSTSTORE_PROJID), "0", String(HOSTSTORE_BLOCKS_KB), "0", String(HOSTSTORE_INODES), deps.mount]);
  if (q?.code !== 0) refuse("outcome_unknown", "restore host store: the quota can't be set");
  const attempt = (hostAttempts(run, { staging, fsx }).at(-1) ?? 0) + 1;
  guard();
  const out = await deps.launch(["restore-stage", "--mount", deps.mount, "--owner", "host", "--class", "hoststore", "--run", run, "--attempt", String(attempt),
    "--projid", String(HOSTSTORE_PROJID), "--snapshot", snapshot, "--path", path], { ms });
  if (out?.code !== 0 || !marked(run, attempt, { staging, fsx })) {
    // (whatever the stage left is removed now, never read)
    await deps.removeUnder(staging, attemptName(run, attempt), "hoststage");
    refuse(out?.code === 76 ? "limit" : "outcome_unknown", `restore host store: the stage exited ${out?.code}`);
  }
  const copy = stagedHostCopy(run, { staging, uid, fsx });
  if (copy === null) refuse("outcome_unknown", "restore host store: the stage left no copy");
  return copy;
}

/** Close's removal of the run's host-store stage: every hoststore attempt, by its exact name (remove-tree, owners [0]). */
export async function removeHostStage(run, { staging = RESTORE_STAGING, fsx = fs }, { removeUnder }) {
  for (const n of hostAttempts(run, { staging, fsx })) await removeUnder(staging, attemptName(run, n), "hoststage");
}
