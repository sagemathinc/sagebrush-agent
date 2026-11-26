// Host restore e2e r1.7, delta R6-d1 (R6a): the root console's restore commands, `sagebrush-agent host restore
// status | retry <kind>-<id> | close`. Root on the host's console only, never over the network. Each prints exactly one
// JSON line {"v": 1, ...}: 0 on success, 1 on a refusal ({"v":1,"refused":<code>}: the code only), 2 on bad arguments.
// - **list** (R6b): the store's manifests, usable or not, with why (listManifests over the backup binary).
// - **begin <snapshot>** (R6b): r1.7 §2's begin with its real deps: the supervisor stopped (its unit inactive, and the
//   host store's lock taken here), the registry fresh, backup not enabled, the manifest chosen over the binary, the
//   host-store snapshot staged by the launcher (restore-hoststage.mjs) and imported in place.
// The binary runs with the launcher's own context paths (state, secrets, cache: launcher restore.rs STATE, SECRETS,
// CACHE), which `host backup attach` writes; nothing here enables backup.
//
// - **status** (§3): read only, under no lock (every command re-reads under its own locks): the restore, then each set
//   in key order: its plan run, record state, request, abandon state (the shared validators: auditPair, boundIntent)
//   and, for an agent, whether it was resumed (its restore fence gone).
// - **retry** (§2): the person's new request for a stopped set (not_fitting or failed), under §1's exclusion and then
//   the restore lock: a newer run, the plan re-planned, then the request replaced. Refused with no effect for anything
//   else: no begun or an closed restore, a set not in the plan, an abandon intent, a record in any other state, a worker
//   holding the set.
// - **close**: r1.7 §5's close, with the live restore fences.

import * as fs from "node:fs";
import { join } from "node:path";
import { FleetError, refuse } from "../bytes.mjs";
import { FENCE_DIR, RESTORE_DIR } from "./names.mjs";
import { newRestoreRun, readRecord, readRegular } from "./restore-record.mjs";
import { readPlan, replanSet, updatePlan, withRestoreLock } from "./restore-plan.mjs";
import { ABANDON, REQUESTS, close, parseKey, provenDir, readBegin, replaceRequest, requestText, restoreOpen, withExclusion } from "./restore-begin.mjs";
import { auditPair, intentName } from "./restore-sidecars.mjs";
import { boundIntent } from "./restore-abandon.mjs";
import { readIntent, setLockPath } from "./restore-worker.mjs";
import { fenceCauses } from "./fence.mjs";
import { lockFile } from "./store.mjs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { HOST_STORE, SUPERVISOR_UNIT } from "./names.mjs";
import { begin } from "./restore-begin.mjs";
import { chooseManifest, listManifests } from "./restore-plan.mjs";
import { HostStore } from "./host-store.mjs";
import { realBackupBinary } from "./backup-binary.mjs";
import { backupEnabled } from "./backup-scheduler.mjs";
import { anchorRemover, expectWriter, pinnedLauncherRunner } from "./restore-adapters.mjs";
import { removeHostStage, stageHostStore } from "./restore-hoststage.mjs";
import { importHostStore } from "./restore-import.mjs";
import { runArgv } from "./effects.mjs";

/**
 * The real ops of the commands that reach the store and the launcher (list, begin, close's stage removal). `release`:
 * the installed release (its bin/ holds the launcher and the backup binary); `run`: the argv runner; `mount`: the
 * quota mount (as the restore worker's seam has it).
 */
/** The installed release's root (its bin/ holds the launcher and the backup binary). */
export function defaultRelease() {
  const release = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
  return release;
}

export function realRestoreOps({ release = defaultRelease(), run = runArgv, mount = "/", hostStore = HOST_STORE, enabled = backupEnabled, staging } = {}) {
  // The launcher checked against the release's pin before its first launch (once per command).
  const launch = pinnedLauncherRunner({ run, release });
  const binary = realBackupBinary(release);
  const removeUnder = anchorRemover({ launch, expect: expectWriter("host", {}) });
  return {
    list: () => listManifests({ binary }),
    begin: async (snapshot, { dir, exclusion }) => {
      // Everything here runs inside begin's exclusion and restore lock: a loser of either does no I/O. The supervisor
      // stopped: only `is-active`'s definite answer counts, exit 3 with exactly "inactive" or "failed" printed; active,
      // an error, a deadline or a malformed result counts as running. The host store is opened at its first use (its
      // lock: a running supervisor holds it, in_progress) and held until begin ends.
      let store = null;
      const opened = async () => { store ??= await HostStore.open(hostStore); return store; };
      try {
        return await begin(snapshot, {
          supervisorStopped: async () => {
            const r = await run(["systemctl", "is-active", SUPERVISOR_UNIT], { ms: 5000 }).catch(() => null);
            return r?.code === 3 && ["inactive\n", "failed\n"].includes(r.stdout);
          },
          registryFresh: async () => (await opened()).registry.fresh(),
          backupEnabled: () => enabled().enabled !== false, // (backupEnabled's answer is { enabled, why }: anything but a plain no counts as enabled)
          choose: (s) => chooseManifest({ binary }, s),
          newRun: () => newRestoreRun(Date.now()),
          stageHostStore: (chosen, o) => stageHostStore(chosen, o, { binary, launch, setquota: (argv) => run(argv, { ms: 15_000 }), mount, removeUnder }),
          importHostStore: async (o) => importHostStore({ ...o, store: await opened(), root: hostStore }),
        }, { dir, exclusion });
      } finally { if (store !== null) await store.close(); }
    },
    removeHostStage: (runId) => removeHostStage(runId, staging === undefined ? {} : { staging }, { removeUnder }),
  };
}

const optionalDir = (dir, name, uid) => { try { return provenDir(dir, name, { uid }); } catch (e) { if (e?.code === "ENOENT") return null; throw e; } };

/** One set's abandon state for status: null, abandoning, abandoned, corrupt (an abandoned record's pair) or stale. */
function abandonState(kind, id, r, { dir, uid, restoreRun }) {
  const adir = optionalDir(dir, ABANDON, uid);
  if (r?.state === "abandoned") {
    try { auditPair(r, adir, { restoreRun }); return "abandoned"; } catch { return "corrupt"; }
  }
  if (adir === null || readRegular(join(adir, intentName(kind, id)), 64 * 1024, "an abandon intent") === null) return null;
  try { boundIntent(kind, id, { dir, uid }); return "abandoning"; } catch { return "stale"; }
}

/** `status` (R6-d1 §3): the restore and every set of its plan, read only. */
export function restoreStatus({ dir = RESTORE_DIR, uid = 0, fenceDir = FENCE_DIR } = {}) {
  const b = readBegin({ dir });
  if (b === null) return { v: 1, restore: "none", sets: [] };
  const p = readPlan({ dir });
  const restore = { run: b.run, snapshot: b.snapshot, manifest_sha256: b.manifest_sha256, state: b.state, open: restoreOpen({ dir }),
    closed_at: p !== null && Object.hasOwn(p, "closed") ? p.closed.at : null };
  if (p === null) return { v: 1, restore, sets: [] };
  const rdir = optionalDir(dir, REQUESTS, uid);
  const sets = Object.keys(p.sets).sort().map((key) => {
    const { kind, id } = parseKey(key);
    const r = readRecord(kind, id, { dir });
    const req = rdir === null ? null : readRegular(join(rdir, key), 4096, "a request");
    return {
      key, kind, id, run: p.sets[key].run,
      state: r === null ? "none" : r.state, attempt: r?.attempt ?? null, dirty: r?.dirty ?? null, reason: r?.reason ?? null,
      imports: r?.imports ? { config: r.imports.config.state, context: r.imports.context.state } : null,
      request: req === null ? "missing" : req.toString("utf8") === requestText(p.sets[key].run) ? "current" : "stale",
      abandon: abandonState(kind, id, r, { dir, uid, restoreRun: b.run }),
      resumed: kind === "agent" ? !fenceCauses(id, { dir: fenceDir }).includes("restore") : null,
    };
  });
  return { v: 1, restore, sets };
}

/**
 * `retry <kind>-<id>` (R6-d1 §2). Options: `now()` (ms), `exclusion` (withExclusion's), `lock` (the set lock's taker).
 * Resolves to { key, run } (the set's run now requested).
 */
export async function restoreRetry(key, { dir = RESTORE_DIR, uid = 0, now = Date.now, exclusion = {}, lock = lockFile, onStep = async () => {} } = {}) {
  const { kind, id } = parseKey(key);
  return withExclusion(() => withRestoreLock(async () => {
    const b = readBegin({ dir });
    if (b === null || b.state !== "done") refuse("not_found", "restore retry: no begun restore");
    const p = readPlan({ dir });
    if (p === null) refuse("not_found", "restore retry: no plan");
    if (Object.hasOwn(p, "closed")) refuse("not_granted", "restore retry: the restore is closed");
    if (!Object.hasOwn(p.sets, key)) refuse("not_found", "restore retry: not a set of this restore");
    if (readIntent(kind, id, { dir, uid }) !== null) refuse("not_granted", "restore retry: the set is being abandoned");
    const r = readRecord(kind, id, { dir });
    if (r === null) refuse("not_found", "restore retry: the set has no record: nothing to retry");
    if (["validated", "abandoned"].includes(r.state)) refuse("not_granted", `restore retry: the set is ${r.state}`);
    if (!["not_fitting", "failed"].includes(r.state)) refuse("in_progress", `restore retry: the set is ${r.state}`);
    // The set lock, taken now and HELD through the re-plan and the request's durable writes: a worker (which takes only
    // the set lock) can't start between them on the old plan, request and input. Held by a worker: busy, nothing changed.
    let held;
    try { held = await lock(setLockPath(dir, kind, id), { waitMs: 0 }); } catch (e) { if (e?.code === "in_progress") refuse("in_progress", "restore retry: a worker holds the set"); throw e; }
    try {
      const cur = p.sets[key].run;
      await onStep("locked");
      // A crash after the re-plan and before the request: the plan is already at a newer run than the stopped record's,
      // so only the request is rewritten (the same run again).
      if (cur !== r.run) {
        replaceRequest(key, cur, { dir, uid });
        return { key, run: cur };
      }
      const run = newRestoreRun(now());
      updatePlan(replanSet(p, kind, id, run), { dir });
      await onStep("replanned");
      replaceRequest(key, run, { dir, uid });
      return { key, run };
    } finally {
      await held.release();
    }
  }, { dir }), exclusion);
}

const USAGE = "usage: sagebrush-agent host restore list | begin <snapshot> | status | retry <kind>-<id> | close";
const SNAPSHOT = /^[0-9a-f]{64}$/;

/**
 * The command line's runner: `argv` after "restore". `deps`: { uid() (the caller's), now(), dir, fenceDir, exclusion,
 * restoreRaised(agent) } (tests inject them). Resolves to { code, line } (line: the one JSON object).
 */
export async function restoreCommand(argv, deps = {}) {
  const { dir = RESTORE_DIR, fenceDir = FENCE_DIR, exclusion = {}, now = Date.now, uid = () => process.getuid?.() ?? -1, rootUid = 0 } = deps;
  const [cmd, ...rest] = argv;
  const ok = (["status", "close", "list"].includes(cmd) && rest.length === 0) || (cmd === "retry" && rest.length === 1)
    || (cmd === "begin" && rest.length === 1 && SNAPSHOT.test(rest[0]));
  if (!ok) return { code: 2, line: null, usage: USAGE };
  if (uid() !== rootUid) return { code: 1, line: { v: 1, refused: "not_granted" } };
  try {
    if (cmd === "status") return { code: 0, line: restoreStatus({ dir, uid: rootUid, fenceDir }) };
    if (cmd === "retry") {
      const out = await restoreRetry(rest[0], { dir, uid: rootUid, now, exclusion });
      return { code: 0, line: { v: 1, retried: out.key, run: out.run } };
    }
    // (the store and launcher ops, built only for the commands that need them)
    const ops = () => deps.ops ?? realRestoreOps();
    if (cmd === "list") {
      const out = await ops().list();
      if (out.error) return { code: 1, line: { v: 1, refused: out.error } };
      return { code: 0, line: { v: 1, manifests: out.manifests, unusable: out.unusable } };
    }
    if (cmd === "begin") {
      const out = await ops().begin(rest[0], { dir, exclusion });
      return { code: 0, line: { v: 1, begun: out.run, sets: out.sets } };
    }
    const restoreRaised = deps.restoreRaised ?? ((agent) => fs.existsSync(join(fenceDir, "restore", agent)));
    const out = await close({ now, restoreRaised, removeHostStage: deps.removeHostStage ?? ops().removeHostStage }, { dir, exclusion, uid: rootUid });
    return { code: 0, line: { v: 1, closed: out.closed } };
  } catch (e) {
    // (the code only: no path, value or message reaches the line)
    return { code: 1, line: { v: 1, refused: e instanceof FleetError ? e.code : "error" } };
  }
}
