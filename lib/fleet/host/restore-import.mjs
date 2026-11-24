// Host backup (design: agent-autonomous-host-backup.md r3.3 §5 step 5, §3): bringing a restored host store's copy
// into a FRESH host, registry first. This is a part of a restore, not all of it: only the registry is imported.
//
// The input is the host store's snapshot, already restored into a root-only directory (`copy`), and the restore's
// plan with the manifest it binds. Per entry of the copy (backup-hoststore.mjs's HOSTSTORE_INCLUDE):
// - **registry: imported,** through its own typed importer (Registry.importRestored), only onto a registry that has
//   never recorded anything, and only if the copy is exactly the registry the manifest binds (its canonical sha256 is
//   the manifest's registry hash). uids, gids, tombstones, states, life and gen are kept; start failures are cleared.
// - **grant: provenance only.** Its bytes go read-only to <RESTORE_DIR>/provenance/grant/, to show what the old host
//   ran under. It is never attached as the grant state: a restored host waits for a fresh grant from the service.
// - **audit: history.** The old stream goes read-only, as plain bytes, to <root>/audit/restored-<host>-<date>/
//   (the manifest's host and day); the new host's stream is its own.
// - **state** (the grant's application state): never imported, by rule: a restored host waits for a fresh grant.
// - **config** (the host's own configuration, the installer's output): never imported: it is per host.
// - **harness-sessions, harness-turns: kept in the backup, not restored (no importer)** until the advisor's
//   implementation brings their typed importers (in-flight turns ended (restored); session records re-validated,
//   profile bindings cleared). Until then the report lists them and nothing of them reaches the host.
// Anything else in the copy refuses: the backup copies only the allowlist.
// Read-only copies refuse links and anything but regular files and directories, are written whole into a temporary
// directory and renamed into place; a copy already in place must be identical (a retry), or it refuses.

import * as fs from "node:fs";
import { dirname, join } from "node:path";
import { refuse } from "../bytes.mjs";
import { RESTORE_DIR } from "./names.mjs";
import { HOSTSTORE_INCLUDE } from "./backup-hoststore.mjs";
import { canonical, sha256 } from "./backup-manifest.mjs";
import { checkRegistry } from "./registry.mjs";
import { checkPlan } from "./restore-plan.mjs";

/** The report's words for an entry that isn't restored, by why. */
export const NOT_RESTORED = "kept in the backup, not restored (no importer)";
export const BY_RULE = "not restored (by rule: a restored host waits for a fresh grant)";
export const PER_HOST = "not restored (per host)";
/** What happens to each host-store entry of a restored copy. */
export const DISPOSITION = Object.freeze({
  registry: "restored", grant: "provenance", audit: "archived",
  state: BY_RULE, "harness-sessions": NOT_RESTORED, "harness-turns": NOT_RESTORED, config: PER_HOST,
});
const HOST = /^[A-Za-z0-9-]{1,64}$/;
const MAX_FILES = 200_000;

/** Every regular file and directory under `dir` (relative paths, sorted), refusing links and anything else. */
function walk(dir, fsx = fs) {
  const out = [];
  const go = (rel) => {
    const st = fsx.lstatSync(rel ? join(dir, rel) : dir);
    if (st.isDirectory()) {
      if (rel) out.push({ rel, dir: true });
      for (const name of fsx.readdirSync(rel ? join(dir, rel) : dir).sort()) go(rel ? join(rel, name) : name);
    } else if (st.isFile()) out.push({ rel, dir: false, size: st.size });
    else refuse("bad_form", "restore import: only regular files and directories");
    if (out.length > MAX_FILES) refuse("limit", "restore import: larger than an import takes");
  };
  go("");
  return out;
}

/** Are two trees the same: the same entries, types and bytes? */
function sameTree(a, b) {
  const x = walk(a), y = walk(b);
  if (x.length !== y.length) return false;
  return x.every((e, i) => e.rel === y[i].rel && e.dir === y[i].dir
    && (e.dir || fs.readFileSync(join(a, e.rel)).equals(fs.readFileSync(join(b, e.rel)))));
}

/** Remove a tree this module wrote (it may be read-only), never following a link. */
function removeOurs(p) {
  let st;
  try { st = fs.lstatSync(p); } catch (e) { if (e?.code === "ENOENT") return; throw e; }
  if (st.isDirectory()) {
    fs.chmodSync(p, 0o700);
    for (const name of fs.readdirSync(p)) removeOurs(join(p, name));
    fs.rmdirSync(p);
  } else fs.unlinkSync(p);
}

const fsyncPath = (p) => { const fd = fs.openSync(p, "r"); try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); } };

/**
 * Copy the tree `src` to `dst`, read-only (files 0400, directories 0500), whole or not at all: into `dst`.partial
 * (a leftover of an interrupted copy is removed first), then fsynced and renamed into place. If `dst` already exists
 * it must be the same tree (a retry): fine; anything else refuses (not_granted).
 */
export function copyReadOnly(src, dst) {
  const entries = walk(src);
  try { fs.lstatSync(dst); } catch (e) {
    if (e?.code !== "ENOENT") throw e;
    const tmp = `${dst}.partial`;
    fs.mkdirSync(dirname(dst), { recursive: true, mode: 0o700 });
    removeOurs(tmp);
    fs.mkdirSync(tmp, { mode: 0o700 });
    for (const e of entries) {
      if (e.dir) { fs.mkdirSync(join(tmp, e.rel), { mode: 0o700 }); continue; }
      const fd = fs.openSync(join(tmp, e.rel), "wx", 0o600);
      try { fs.writeSync(fd, fs.readFileSync(join(src, e.rel))); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    }
    // Read-only, deepest first, each directory fsynced once its entries are in it.
    for (const e of [...entries].reverse()) {
      fs.chmodSync(join(tmp, e.rel), e.dir ? 0o500 : 0o400);
      if (e.dir) fsyncPath(join(tmp, e.rel));
    }
    fs.chmodSync(tmp, 0o500);
    fsyncPath(tmp);
    fs.renameSync(tmp, dst);
    fsyncPath(dirname(dst));
    return "copied";
  }
  if (!sameTree(src, dst)) refuse("not_granted", "restore import: a different copy is already in place");
  return "present";
}

/**
 * Import the host store's restored copy (`copy`) into the fresh host: `store` the open HostStore, `root` its root
 * directory, `plan` the restore plan, `manifest` the plan's manifest (bound by its sha256), `restoreDir` the restore's
 * state directory. Registry first: if it can't be imported, nothing else is done. Returns the report:
 * { entries: { <name>: disposition } } for every entry present in the copy.
 */
export function importHostStore({ copy, store, root, plan, manifest, restoreDir = RESTORE_DIR }) {
  checkPlan(plan);
  if (sha256(canonical(manifest) + "\n") !== plan.sha256) refuse("not_granted", "restore import: not the plan's manifest");
  if (!HOST.test(manifest.host) || typeof manifest.time !== "string" || Number.isNaN(Date.parse(manifest.time))) refuse("bad_form", "restore import: bad manifest");
  const present = fs.readdirSync(copy).sort();
  for (const name of present) if (!HOSTSTORE_INCLUDE.includes(name)) refuse("bad_form", "restore import: an entry the backup never copies");
  if (!present.includes("registry")) refuse("not_found", "restore import: the copy has no registry");

  // The registry: exactly the manifest's, through its typed importer, onto an empty registry.
  let text;
  try { text = fs.readFileSync(join(copy, "registry", "registry.json"), "utf8"); } catch { refuse("not_found", "restore import: the copy has no registry file"); }
  let reg;
  try { reg = JSON.parse(text); } catch { refuse("bad_form", "restore import: the registry isn't JSON"); }
  checkRegistry(reg);
  if (sha256(canonical(reg)) !== manifest.registry.hash) refuse("not_granted", "restore import: the registry isn't the one the manifest binds");
  store.registry.importRestored(reg);

  const entries = { registry: DISPOSITION.registry };
  if (present.includes("grant")) { copyReadOnly(join(copy, "grant"), join(restoreDir, "provenance", "grant")); entries.grant = DISPOSITION.grant; }
  if (present.includes("audit")) {
    copyReadOnly(join(copy, "audit"), join(root, "audit", `restored-${manifest.host}-${new Date(manifest.time).toISOString().slice(0, 10)}`));
    entries.audit = DISPOSITION.audit;
  }
  for (const name of present) if (!Object.hasOwn(entries, name)) entries[name] = DISPOSITION[name];
  return { entries };
}
