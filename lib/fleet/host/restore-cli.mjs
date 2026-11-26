// Host restore e2e r1.7, delta R6-d1 (R6a): the root console's restore commands, `sagebrush-agent host restore
// status | retry <kind>-<id> | close`. Root on the host's console only, never over the network. Each prints exactly one
// JSON line {"v": 1, ...}: 0 on success, 1 on a refusal ({"v":1,"refused":<code>}: the code only), 2 on bad arguments.
// `list` and `begin` (R6b) wait for the store's connection on a fresh host and the host-store class (R6-d1 §4).
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
export async function restoreRetry(key, { dir = RESTORE_DIR, uid = 0, now = Date.now, exclusion = {}, lock = lockFile } = {}) {
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
    // A worker holding the set (it would be mid-stop): busy, nothing changed.
    let held;
    try { held = await lock(setLockPath(dir, kind, id), { waitMs: 0 }); } catch (e) { if (e?.code === "in_progress") refuse("in_progress", "restore retry: a worker holds the set"); throw e; }
    await held.release();
    const cur = p.sets[key].run;
    // A crash after the re-plan and before the request: the plan is already at a newer run than the stopped record's,
    // so only the request is rewritten (the same run again).
    if (cur !== r.run) {
      replaceRequest(key, cur, { dir, uid });
      return { key, run: cur };
    }
    const run = newRestoreRun(now());
    updatePlan(replanSet(p, kind, id, run), { dir });
    replaceRequest(key, run, { dir, uid });
    return { key, run };
  }, { dir }), exclusion);
}

const USAGE = "usage: sagebrush-agent host restore status | retry <kind>-<id> | close";

/**
 * The command line's runner: `argv` after "restore". `deps`: { uid() (the caller's), now(), dir, fenceDir, exclusion,
 * restoreRaised(agent) } (tests inject them). Resolves to { code, line } (line: the one JSON object).
 */
export async function restoreCommand(argv, deps = {}) {
  const { dir = RESTORE_DIR, fenceDir = FENCE_DIR, exclusion = {}, now = Date.now, uid = () => process.getuid?.() ?? -1, rootUid = 0 } = deps;
  const [cmd, ...rest] = argv;
  const ok = (cmd === "status" && rest.length === 0) || (cmd === "close" && rest.length === 0) || (cmd === "retry" && rest.length === 1);
  if (!ok) return { code: 2, line: null, usage: USAGE };
  if (uid() !== rootUid) return { code: 1, line: { v: 1, refused: "not_granted" } };
  try {
    if (cmd === "status") return { code: 0, line: restoreStatus({ dir, uid: rootUid, fenceDir }) };
    if (cmd === "retry") {
      const out = await restoreRetry(rest[0], { dir, uid: rootUid, now, exclusion });
      return { code: 0, line: { v: 1, retried: out.key, run: out.run } };
    }
    const restoreRaised = deps.restoreRaised ?? ((agent) => fs.existsSync(join(fenceDir, "restore", agent)));
    const out = await close({ now, restoreRaised }, { dir, exclusion, uid: rootUid });
    return { code: 0, line: { v: 1, closed: out.closed } };
  } catch (e) {
    // (the code only: no path, value or message reaches the line)
    return { code: 1, line: { v: 1, refused: e instanceof FleetError ? e.code : "error" } };
  }
}
