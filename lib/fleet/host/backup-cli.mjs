// Host backup, wiring r0.4 §1 and init-run d6 §6: the root commands `sagebrush-agent host backup run` (one runOnce
// with the real dependencies, r0.4 §4; the oneshot `sagebrush-backup.service` runs it daily) and `host backup status`
// (read only, no lock).
//
// - **run** prints one JSON line, the run's result: exit 0 for ok, not set up and skipped; 3 for failed. A throw out of
//   the run (an unreadable left-over journal, say) is failed with its code (a registered reason or a console code).
//   An ok or failed run is recorded in `backup/last-run.json` for status.
// - **status** prints buildStatus over the enabled check, the state file and the last run.
// - On a host whose store has no live owner (every host not PAIRED), the run takes the host store's one snapshot
//   itself (backup-snapshot.mjs). Until each agent's config is proven from its committed snapshot (r0.4 §1.2), a
//   live agent's set fails `config_unbound`: config is never bound any other way.
// - With no turn-lease provider (lease: null), every live pass is consistency=crash at once (r0.4 §4, Q1).

import * as fs from "node:fs";
import { join } from "node:path";
import { FleetError, refuse } from "../bytes.mjs";
import { exactKeys, writeDurable } from "./store.mjs";
import { BACKUP_DIR, HOST_STORE } from "./names.mjs";
import { HostStore } from "./host-store.mjs";
import { realBackupBinary } from "./backup-binary.mjs";
import { backupSet, scopedSpawn } from "./backup-run.mjs";
import { realCgroup } from "./backup-journal.mjs";
import { backupSources, checkForbidden, FIXED_FORBIDDEN, unchanged, walkSources } from "./backup-sources.mjs";
import { buildManifest, commitManifest, parseManifest, sha256 } from "./backup-manifest.mjs";
import { checkDataPart, pruneDue, retentionPass } from "./backup-retention.mjs";
import { runSnapshot } from "./backup-snapshot.mjs";
import {
  backupEnabled, backupHostId, buildStatus, cacheEffects, lockLost, readState, recoverLeftover, runOnce, withRunLock, writeState,
} from "./backup-scheduler.mjs";
import { restoreOpen, withExclusion } from "./restore-begin.mjs";
import { defaultRelease } from "./restore-cli.mjs";
import { runArgv } from "./effects.mjs";
import { readRegular } from "./restore-record.mjs";

export const SNAPSHOT_DIR = join(BACKUP_DIR, "snapshot");
export const STAGING_DIR = join(BACKUP_DIR, "staging");
export const LAST_RUN = "last-run.json";
const USAGE = "usage: sagebrush-agent host backup run | backup status";

/** `binary` with the run's guard before and after each call. */
const guardedBinary = (binary, g) => async (req, o) => { g(); const r = await binary(req, o); g(); return r; };
/** The cgroup operations with the run's guard before each. */
const guardedCg = (cg, g) => Object.fromEntries(Object.keys(cg).map((k) => [k, (...a) => { g(); return cg[k](...a); }]));

/**
 * runOnce's real dependencies (wiring r0.4 §4), for the release at `release`. Seams: `run` (the argv runner), `binary`
 * (the pinned runner, each run's calls in its worker scope), `dir`, `storeRoot`, `uid` (root's), `exclusion` (its path),
 * `restoreDir`, `cache` ({ image, mountpoint }: the cache image and its mount point).
 */
export function realRunDeps({ release = defaultRelease(), run = runArgv, binary = realBackupBinary(release, { spawnFor: (r) => scopedSpawn(r) }),
  dir = BACKUP_DIR, storeRoot = HOST_STORE, uid = 0, exclusion = {}, restoreDir = undefined, cache: cacheAt = {} } = {}) {
  const cache = cacheEffects({ run, ...cacheAt });
  return {
    withExclusion: (fn) => withExclusion((held) => fn(() => { if (!held.held()) throw lockLost(); }), { uid, ...exclusion, waitMs: 0 }),
    restoreOpen: () => restoreOpen(restoreDir === undefined ? {} : { dir: restoreDir }),
    enabled: () => backupEnabled({ dir, rootUid: uid }),
    withRunLock: (fn) => withRunLock(fn, { dir: join(dir, "run") }),
    freeBytes: (p) => { const s = fs.statfsSync(p); return s.bavail * s.bsize; },
    ensureCache: (g) => cache.ensureCache(g),
    trimCache: (g) => cache.trimCache(g),
    recoverLeftover: (g) => recoverLeftover({ binary: guardedBinary(binary, g), cg: guardedCg(realCgroup, g), dir, guard: g }),
    hostId: (g) => backupHostId({ dir, uid, guard: g }),
    snapshot: (r, g) => runSnapshot(r, { dir: join(dir, "snapshot"), root: storeRoot, openStore: () => HostStore.open(storeRoot), uid, guard: g }),
    // (r0.4 §1.2 is the next step: until then a live agent's config is never bound, so its run fails config_unbound)
    configHash: () => { throw Object.assign(new Error("backup run: config isn't proven from the committed snapshot yet"), { code: "config_unbound" }); },
    // (every profile record's storage is beneath FIXED_FORBIDDEN's profiles root)
    forbidden: () => [...FIXED_FORBIDDEN],
    sources: backupSources,
    checkForbidden,
    walk: (set) => walkSources(set),
    unchanged,
    backupSet: (set, r, { parent, guard, host }) => backupSet(set, r, { binary, lease: null, host, parent, guard, dir }),
    binary,
    buildManifest,
    commitManifest: (m, staging, g) => commitManifest(m, staging, { binary: guardedBinary(binary, g) }),
    retention: ({ now, host, activeRun, guard }) => retentionPass({ binary: guardedBinary(binary, guard) }, { now, host, activeRun, parse: parseManifest, sha256 }),
    pruneDue,
    checkDataPart,
    state: { read: () => readState({ dir }), write: (s) => writeState(s, { dir }) },
    now: Date.now,
    // The manifest's staging: a fresh directory per run, older runs' removed (they are in the store or never were).
    stagingDir: (name) => {
      const staging = join(dir, "staging");
      try { fs.mkdirSync(staging, { mode: 0o700 }); } catch (e) { if (e?.code !== "EEXIST") throw e; }
      const st = fs.lstatSync(staging);
      if (!st.isDirectory() || (st.mode & 0o7777) !== 0o700) refuse("not_granted", "backup run: the staging directory isn't private");
      for (const n of fs.readdirSync(staging)) if (n !== name) fs.rmSync(join(staging, n), { recursive: true, force: true });
      return join(staging, name);
    },
  };
}

/** The run's line: its result, with retention summarized (counts, not ids). */
function lineOf(r) {
  const out = { v: 1, status: r.status };
  for (const k of ["why", "run", "manifest", "failures", "prune", "check"]) if (r[k] !== undefined && r[k] !== null) out[k] = r[k];
  if (r.retention) out.retention = r.retention.error ? { error: r.retention.error } : { kept: r.retention.kept.length, forgotten: r.retention.forgotten.length };
  return out;
}

/** The last ok or failed run, for status: { v: 1, status, at } in `<dir>/last-run.json`, or null. */
export function readLastRun({ dir = BACKUP_DIR, uid = 0, fsx = fs } = {}) {
  const p = join(dir, LAST_RUN);
  let st;
  try { st = fsx.lstatSync(p); } catch (e) { if (e?.code === "ENOENT") return null; throw e; }
  if (!st.isFile() || st.uid !== uid || (st.mode & 0o7777) !== 0o600) refuse("not_granted", "backup status: the last run's record isn't root's 0600 file");
  let x;
  try { x = JSON.parse(readRegular(p, 1024, "the last run", fsx).toString("utf8")); } catch (e) { if (e instanceof FleetError) throw e; refuse("bad_form", "backup status: the last run's record isn't JSON"); }
  if (!exactKeys(x, ["v", "status", "at"]) || x.v !== 1 || !["ok", "failed"].includes(x.status) || !Number.isSafeInteger(x.at)) refuse("bad_form", "backup status: the last run's record is malformed");
  return x;
}

/**
 * `sagebrush-agent host backup run | status`, root only. Resolves to { code, line } or { code: 2, usage }. `deps`
 * (seams): uid(), rootUid, run (runOnce's deps), dir, now().
 */
export async function backupCommand(argv, deps = {}) {
  const { uid = () => process.getuid?.() ?? -1, rootUid = 0, dir = BACKUP_DIR, now = Date.now } = deps;
  if (argv.length !== 1 || !["run", "status"].includes(argv[0])) return { code: 2, line: null, usage: USAGE };
  if (uid() !== rootUid) return { code: 1, line: { v: 1, refused: "not_granted" } };
  if (argv[0] === "status") {
    try {
      const enabled = backupEnabled({ dir, rootUid });
      const state = enabled.enabled ? readState({ dir }) : null;
      return { code: 0, line: { v: 1, ...buildStatus({ enabled, state, lastRun: enabled.enabled ? readLastRun({ dir, uid: rootUid }) : null }) } };
    } catch (e) {
      return { code: 1, line: { v: 1, refused: e instanceof FleetError ? e.code : "outcome_unknown" } };
    }
  }
  let r;
  try { r = await runOnce(deps.run ?? realRunDeps({ dir })); } catch (e) {
    r = { status: "failed", why: e instanceof FleetError || e?.code === "config_unbound" ? e.code : "outcome_unknown" };
  }
  if (r.status === "ok" || r.status === "failed") {
    try { writeDurable(dir, LAST_RUN, JSON.stringify({ v: 1, status: r.status, at: now() }) + "\n"); } catch { /* (status then shows the one before) */ }
  }
  return { code: r.status === "failed" ? 3 : 0, line: lineOf(r) };
}
