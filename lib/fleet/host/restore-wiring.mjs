// Host restore e2e r1.7 §3 and delta d2: the restore worker's real wiring, both sides.
//
// - **The supervisor's side** (`restoreWorkerSeam`): the executor's `restoreWorker` seam, { hold, dispatch }.
//   - hold: R3a's holdSets.
//   - dispatch: dispatchOnce over the gate, an advisory admission from the registry and the fences, the input built
//     from the store (restore-inputs.mjs, d2 §2), and a DETACHED start of the worker's scope.
//   - The start resolves once systemd reports the scope active, or refuses: it never waits for the worker itself.
// - **The worker's side** (`workerDeps`): runWorker's deps over the real adapters (restore-adapters.mjs), built from
//   the input the worker reads under its lock.

import { spawn as nodeSpawn } from "node:child_process";
import { isId, refuse } from "../bytes.mjs";
import { RESTORE_DIR, FENCE_DIR, agentSlice } from "./names.mjs";
import { CLASSES } from "./restore-record.mjs";
import { restoreFiller } from "./restore-fill.mjs";
import { buildInput } from "./restore-inputs.mjs";
import { destIdentifier, restoreAdapters } from "./restore-adapters.mjs";
import { dispatchOnce, holdSets, workerScope } from "./restore-worker.mjs";
import { fenceCauses } from "./fence.mjs";
import { readGate } from "./lease.mjs";

/** How long the start waits for systemd to report the worker's scope active. */
export const START_MS = 10_000;

/**
 * Start `argv` (workerArgv's: systemd-run --scope ... --unit=<unit> -- ...) detached, and resolve once `unit` is
 * active, never waiting for the worker. A start that doesn't become active (systemd-run exits first, the deadline
 * `ms` passes, or `signal` aborts: a close or the op's deadline) is ENDED before it is reported: the child's process
 * group is killed, the unit is killed, and both must be proven gone (the child exited, `isGone(unit)`) within `killMs`.
 * Then it refuses effect_failed: nothing can run. If that can't be proven, it refuses outcome_unknown, and the
 * dispatch's host-wide scope check keeps every later dispatch busy until the unit is gone.
 */
export function startDetached(argv, unit, { spawn = nodeSpawn, isActive, isGone, killUnit = async () => {}, killGroup = (pid) => process.kill(-pid, "SIGKILL"),
  ms = START_MS, killMs = 5000, poll = 50, now = Date.now, sleep = (t) => new Promise((r) => setTimeout(r, t)), signal } = {}) {
  if (!Array.isArray(argv) || argv[0] !== "systemd-run" || !argv.includes(`--unit=${unit}`)) refuse("bad_form", "restore start: not a worker's argv");
  if (typeof isActive !== "function" || typeof isGone !== "function") refuse("bad_form", "restore start: the systemd answers are required");
  return new Promise((resolve, reject) => {
    let exited = false;
    let child;
    try { child = spawn(argv[0], argv.slice(1), { detached: true, stdio: "ignore" }); } catch (e) { reject(e); return; }
    child.once("error", () => { exited = true; });
    child.once("exit", () => { exited = true; });
    child.unref?.();
    const fail = (code, why) => reject(Object.assign(new Error(`restore start: ${why}`), { code }));
    /** End the start and prove it ended: the child gone and the unit gone, within killMs. */
    const end = async (why) => {
      try { if (!exited && Number.isSafeInteger(child.pid)) killGroup(child.pid); } catch { /* the proof decides */ }
      try { await killUnit(unit); } catch { /* the proof decides */ }
      const until = now() + killMs;
      for (;;) {
        let gone = false;
        try { gone = exited && (await isGone(unit)) === true; } catch { gone = false; }
        if (gone) return fail("effect_failed", `${why}; ended, and nothing runs`);
        if (now() >= until) return fail("outcome_unknown", `${why}; it couldn't be proven ended`);
        await sleep(poll);
      }
    };
    const deadline = now() + ms;
    (async () => {
      for (;;) {
        if (signal?.aborted) return end("cut short");
        let active = false;
        try { active = (await isActive(unit)) === true; } catch { active = false; }
        if (active && !signal?.aborted) { resolve(); return; }
        if (exited) return end("the scope ended before it was active");
        if (now() >= deadline) return end("the scope isn't active in time");
        await sleep(poll);
      }
    })().catch(reject);
  });
}

/** Any restore worker scope systemd knows now (by list-units, every state): true, false, or true when unsure. */
export function anyRestoreScope({ run }) {
  return async () => {
    let r;
    try { r = await run(["systemctl", "list-units", "--all", "--plain", "--no-legend", "sagebrush-restore-*.scope"], { ms: 5000 }); } catch { return true; }
    if (r?.code !== 0) return true;
    return String(r.stdout ?? "").split("\n").some((l) => l.trim() !== "");
  };
}

/**
 * The executor's restoreWorker seam. `store`: the open HostStore (registry snapshot, provisioned records; `createdOf`
 * the creation records of archive and tag destinations, or none yet). `launch`, `mount`: the launcher runner and the
 * quota mount. `main`: the worker's main module. `isActive(unit)`: systemd's answer. Seams: `dir`, `uid`, `fenceDir`,
 * `gateOpen`, `start`.
 */
export function restoreWorkerSeam({ store, launch, mount, main, node = process.execPath, isActive, isGone, killUnit, anyWorker, createdOf = () => null,
  dir = RESTORE_DIR, uid = 0, fenceDir = FENCE_DIR, gateOpen = async () => readGate().open === true,
  start = (argv, { signal } = {}) => startDetached(argv, argv.find((a) => a.startsWith("--unit=")).slice(7), { isActive, isGone, killUnit, signal }) }) {
  if (typeof anyWorker !== "function") refuse("bad_form", "restore seam: the host-wide worker check is required");
  const identify = destIdentifier({ launch, mount });
  /** The recorded identity of a class, only if it is of this epoch and filesystem now; else null (requalify first). */
  const recorded = async (kind, id, cls) => {
    let rec = null;
    if (kind === "agent") {
      const p = store.provisioned.record(id);
      if (p && Object.hasOwn(p.home.entries, cls)) rec = { epoch: p.home.epoch, fsid: p.home.fsid, object: p.home.entries[cls] };
    } else rec = createdOf(kind, id, cls) ?? null;
    if (rec === null) return null;
    let now;
    try { now = await identify(kind, id, cls); } catch { return null; }
    const same = now.fsid === rec.fsid && now.epoch.boot_id === rec.epoch.boot_id && now.epoch.mnt_id === rec.epoch.mnt_id;
    return same ? rec : null;
  };
  /** Advisory (the worker's own checks are the authority): the registry and the fences say the set may run. */
  const admitted = async (kind, id) => {
    const reg = store.registry;
    if (kind === "tag") return reg.tag(id) !== null;
    const a = reg.agent(id);
    if (kind === "archive") return a !== null && a.state === "deleted";
    return a !== null && a.state !== "deleted" && fenceCauses(id, { dir: fenceDir }).includes("restore");
  };
  const inputOf = async (kind, id, run, nonce) => {
    const dests = {};
    for (const cls of CLASSES[kind]) {
      dests[cls] = await recorded(kind, id, cls);
      if (dests[cls] === null) return null;
    }
    // (the manifest's unrestorable lists are absolute host paths, at most 20 of them, kept for the person: none is a
    // validation input; what fill-home refuses is subtracted from its own report, so nothing is excused beyond that)
    return buildInput({ kind, id, run, nonce, registry: store.registry.snapshot(), destOf: (k, i, cls) => dests[cls], unrestorableOf: () => [] });
  };
  return {
    hold: (agent, tags) => holdSets(agent, tags, { dir, uid }),
    dispatch: (ms, signal) => dispatchOnce({ gateOpen, admitted, inputOf, start, main, node, mount, anyWorker }, { dir, uid, signal }),
  };
}

/**
 * runWorker's deps in the worker process (restore-worker-main.mjs). `launch`, `mount`; `fenceRaised(agent)` and
 * `sliceEmpty(agent)` (live); `dir` and `root` (the records' and the staging's, tests). The adapters are built from the
 * input runWorker read under its lock; identifyDest needs none of it.
 */
export function workerDeps({ launch, mount, fenceRaised, sliceEmpty, dir = RESTORE_DIR, adapterOpts = {} }) {
  let adapters = null;
  return {
    identifyDest: destIdentifier({ launch, mount }),
    isEmpty: async (...a) => { if (adapters === null) refuse("outcome_unknown", "restore worker: no input yet"); return adapters.isEmpty(...a); },
    filler: (hooks, input) => {
      adapters = restoreAdapters(input, { launch, mount, fenceRaised, sliceEmpty, ...adapterOpts });
      const { isEmpty, ...rest } = adapters;
      void isEmpty;
      return restoreFiller({ ...rest, dir, ...(adapterOpts.staging ? { root: adapterOpts.staging } : {}), ...hooks });
    },
  };
}

/** The real fence and slice answers for the stop proof: `restore` raised; the agent's slice holds no process. */
export function liveStop({ sys, fenceDir = FENCE_DIR, ms = 5000 }) {
  return {
    fenceRaised: async (agent) => isId(agent) && fenceCauses(agent, { dir: fenceDir }).includes("restore"),
    sliceEmpty: async (agent) => { try { return sys.procCount(agentSlice(agent), ms) === 0; } catch { return false; } },
  };
}
