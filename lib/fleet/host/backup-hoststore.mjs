// Host backup (design: agent-autonomous-host-backup.md r3.3 §3, §4): the host store's copy for a backup run.
//
// The host store is copied, while the caller holds the host-store lock (in the executor's queue), into a fresh
// root-only staging directory, which then becomes the run's `hoststore` source. Every store write is atomic (temp,
// rename), so each copied file is whole; the lock means none is mid-change. Only an allowlist of the store's
// entries is copied (HOSTSTORE_INCLUDE); a restore never restores an assignment, a host-specific identity, or a
// secret, so the pool policy, the profile bindings, the provisioning and deprovisioning records are never copied.
// Temp files (a leading "."), links and anything but regular files and directories are refused, never followed.
//
// **grant is copied as inert provenance only.** The grant's bytes are in the copy so a restore can show what the
// host ran under; a restore NEVER installs them as the live grant (an old grant could start agents a later grant or
// a revoke removed). A restored host comes up with no current grant and waits for a fresh one from the service.

import * as fs from "node:fs";
import { join } from "node:path";
import { refuse } from "../bytes.mjs";

/** The host store entries a backup copies (when present). */
export const HOSTSTORE_INCLUDE = Object.freeze(["registry", "grant", "state", "harness-sessions", "harness-turns", "audit", "config"]);
/** Bounds of one copy. */
export const MAX_FILES = 200_000;
export const MAX_BYTES = 4 * 1024 * 1024 * 1024;

/**
 * Copy the allowlisted entries of the host store at `root` into `staging` (which must not exist; created 0700).
 * `held()` must say the caller holds the host-store lock, before and after the copy (else it refuses not_granted,
 * and the staging copy is not to be used). Returns { files, bytes, entries: [the included names present] }.
 */
export function copyHostStore(root, staging, { held, fsx = fs, maxFiles = MAX_FILES, maxBytes = MAX_BYTES } = {}) {
  if (typeof held !== "function" || !held()) refuse("not_granted", "host store copy: the host-store lock isn't held");
  fsx.mkdirSync(staging, { mode: 0o700 }); // throws EEXIST: never into an existing directory
  let files = 0, bytes = 0;
  const present = [];
  const copy = (src, dst) => {
    const st = fsx.lstatSync(src);
    if (st.isDirectory()) {
      fsx.mkdirSync(dst, { mode: 0o700 });
      for (const name of fsx.readdirSync(src).sort()) {
        if (name.startsWith(".")) continue; // a temp file or the lock: never a whole record
        copy(join(src, name), join(dst, name));
      }
      return;
    }
    if (!st.isFile()) refuse("bad_form", "host store copy: only regular files and directories");
    files += 1; bytes += st.size;
    if (files > maxFiles || bytes > maxBytes) refuse("limit", "host store copy: larger than a copy takes");
    const data = fsx.readFileSync(src);
    const fd = fsx.openSync(dst, "wx", 0o600);
    try { fsx.writeSync(fd, data); fsx.fsyncSync(fd); } finally { fsx.closeSync(fd); }
  };
  for (const name of HOSTSTORE_INCLUDE) {
    const src = join(root, name);
    try { fsx.lstatSync(src); } catch (e) { if (e?.code === "ENOENT") continue; throw e; }
    present.push(name);
    copy(src, join(staging, name));
  }
  const dfd = fsx.openSync(staging, "r");
  try { fsx.fsyncSync(dfd); } finally { fsx.closeSync(dfd); }
  if (!held()) refuse("not_granted", "host store copy: the host-store lock was lost during the copy");
  return { files, bytes, entries: present };
}
