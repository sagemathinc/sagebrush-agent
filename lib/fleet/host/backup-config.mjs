// Host backup, wiring r0.4 §1.2 with amendment A3 (r1): each live agent's config entry in the manifest is PROVEN from
// the agent's COMMITTED snapshot, with the binary's read ops, never bound from the live tree alone. The tree holds
// immutable generations `gen-<n>` and `current` ("gen-<n>\n"; agent-config.mjs). A traversal can race the writer
// installing a new generation: the saved listing can predate `gen-<n+1>` while the saved `current` already names it,
// so a saved pointer proves nothing on its own. For an agent's committed snapshot:
//   1. `usage` of the saved `agent-config/<id>` (the path itself isn't counted). It must succeed: a path missing from
//      the save, or a usage that fails, is unbound. 0 entries: the saved tree is provably empty, EMPTY_CONFIG_HASH
//      (A3: the restore's own hash of a never-configured tree, so a restore compares it as it compares any entry);
//   2. otherwise `dump` of the saved `current` must be exactly "gen-<n>\n", and the LIVE tree (agent-config's own
//      no-follow reader) must hold the immutable `gen-<n>`;
//   3. `usage` of the saved `gen-<n>` must report exactly the live generation's entry count (nothing missing or extra),
//      and every live file must `dump` from the save to its exact bytes (its sha256 against the live listing's);
//   4. the entry is the live generation's hash, over the listing just proven equal in the save.
// Anything else (unreadable, malformed, partial, mismatched or changed) is `config_unbound`: the set fails and nothing
// is committed. A corrupt tree is never recorded as empty.

import * as fs from "node:fs";
import { createHash } from "node:crypto";
import { EMPTY_CONFIG_HASH, readConfigTree } from "./agent-config.mjs";
import { agentConfigDir } from "./names.mjs";

const CURRENT = /^gen-(0|[1-9][0-9]{0,7})\n$/;
const sha256 = (b) => createHash("sha256").update(b).digest("hex");

/** What a set fails with when its config isn't proven (a run's failure code, never a refusal line's). */
const unbound = (why) => { throw Object.assign(new Error(`backup config: ${why}`), { code: "config_unbound" }); };

/**
 * The config entry of agent `id` from its committed snapshot `snapshot`: EMPTY_CONFIG_HASH or a generation's hash, or
 * a throw with code config_unbound. `binary(req, { ms })`: the backup binary (the caller guards it); `root`: the live
 * tree (a test seam); `uid`: root's; `ms`: each call's deadline.
 */
export async function proveConfig(id, snapshot, { binary, root = agentConfigDir(id), uid = 0, fsx = fs, ms = 30 * 60 * 1000 }) {
  const rel = root.replace(/^\/+/, "");
  const call = async (req) => {
    let r;
    try { r = await binary(req, { ms }); } catch (e) { if (e?.code === "lock_lost") throw e; return null; }
    return r?.ok ? r.value : null;
  };
  const saved = await call({ op: "usage", snapshot, path: rel });
  if (saved === null || !Number.isSafeInteger(saved.entries)) unbound("the saved tree can't be measured");
  if (saved.entries === 0) return EMPTY_CONFIG_HASH;
  const cur = await call({ op: "dump", snapshot, path: `${rel}/current` });
  const m = cur === null ? null : CURRENT.exec(cur.text);
  if (m === null) unbound("the saved current is missing or malformed");
  let live;
  try { live = readConfigTree(root, { uid, fsx }); } catch { unbound("the live tree can't be read"); }
  const gen = Object.hasOwn(live.generations, m[1]) ? live.generations[m[1]] : null;
  if (gen === null) unbound("the saved current names a generation the live tree doesn't hold");
  const g = await call({ op: "usage", snapshot, path: `${rel}/gen-${m[1]}` });
  if (g === null || g.entries !== gen.entries.length) unbound("the saved generation isn't complete");
  for (const e of gen.entries) {
    if (e.type !== "file") continue;
    const d = await call({ op: "dump", snapshot, path: `${rel}/gen-${m[1]}/${e.path}` });
    if (d === null || sha256(Buffer.from(d.text, "utf8")) !== e.sha256) unbound("a saved file isn't the generation's");
  }
  return gen.hash;
}
