// Host backup (design: agent-autonomous-host-backup.md r3.3 §5 steps 2, 11; the first-lease rule r2.1; schemas r2.4
// §3.7.3): the person's resume of a restored agent, the only way its `restore` fence comes down.
//
// Resume lowers `restore` once, when all of the first-lease rule's conditions hold. They are checked in two places,
// because the host records are the supervisor's alone (the host store is single-writer: only the supervisor, which
// holds its lock, can read the grants, entry_gen, listed_since and the transfer records):
// - THE SUPERVISOR (requestResume, in the executor's queue), before it launches anything:
//   1. validated: the agent's restore record, and each of its tag folders', against the current restore's binding;
//   2. the transfer receipt: the pair {transfer, receipt} the service handed out passes the schema's checks 1-3
//      (verifyTransferReceipt) and this host's checks 4-6 (checkTransferForHost, over the host records), both the shared
//      fleet core's, and must move THIS agent (the verified transfer's and receipt's `agent`). Check 6 is idempotent for
//      the pair this host already accepted; when the pair is new here (first), the supervisor records it durably
//      (recordTransfer) right before launching, after everything else (the lease, the helper's argv) has passed, so
//      "new" is enforced exactly once and a resume that can't run records nothing;
//   4. the live lease: liveLease(agent) (lease part 2, the supervisor's memory: a lease accepted on this boot) exists,
//      and its gen is the agent's CURRENT entry_gen.
//   Any refusal launches nothing.
// - THE HELPER (resumeRestored), a transient scope sagebrush-restore-resume-<id>.scope in the agent's slice, given
//   the live lease in argv. Under the agent's activation lock (EXCLUSIVE, as the lease's activation helper: it
//   serializes two resumes and any activation), it re-checks only what can change between the launch and the
//   lowering, from files it can read itself:
//   1. still validated: the agent's record and those of the tag folders the supervisor passes (the registry is the
//      host store's too; a change of the agent's tags is a change of its entry, which ends its lease, see 4);
//   3. the published lease record is the argv's lease (lease_id, lg) and liveCheck passes on it (live: not spent,
//      outside the margin, its watchdog waiting);
//   4. the record's gen (the lease's entry_gen, which lease part 2 publishes) is the argv's gen. A grant that changes
//      the agent's entry ENDS its lease, so (3) failing covers any entry_gen move since the supervisor's check;
//   5. `lease` is down (the activation helper lowered it after publishing). Resume never lowers `lease`.
//   Then lowerFence("restore", ..., "resume-restored"), which itself requires the caller to be this scope, and,
//   under the same lock, queues the agent unit's start (the lease helper's start was skipped while `restore` held).
// The watchdog's whole-slice kill reaches the helper, so the lease's proof holds unchanged: a deadline at the seam
// raises `lease`, masks and kills the slice; `restore` stays up unless its unlink was already durable, and then
// `lease` is up anyway. Lock order: the activation lock, then the fence lock (lowerFence's); nothing takes them the
// other way.

import * as fs from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { FleetError, isId, refuse } from "../bytes.mjs";
import { lowerFence } from "./fence.mjs";
import { LEASE_DIR, LEASE_FENCE_DIR, LOCK_TRY_MS, activationLock, liveCheck, parseArgs, readRecord, realClock, realSystem } from "./lease.mjs";
import { FENCE_DIR, agentScopeCgroup, agentSlice, agentUnit, restoreResumeScope } from "./names.mjs";
import { lockFile } from "./store.mjs";

const need = (agent) => { if (!isId(agent)) refuse("bad_form", "restore resume: not an agent id"); return agent; };
/** The cgroup the helper must find itself in. */
export const resumeCgroup = (agent) => agentScopeCgroup(agent, restoreResumeScope(agent));
/** The helper's command: this release's node and restore-resume-main.mjs. */
export const MAIN = fileURLToPath(new URL("./restore-resume-main.mjs", import.meta.url));
/**
 * How long the supervisor waits for the helper. The helper's own work is short (the activation lock is tried for at
 * most LOCK_TRY_MS, then a durable unlink and a queued start), and the wait must end well inside the supervisor unit's
 * stop timeout: the executor's close also cuts it short.
 */
export const RESUME_HELPER_MS = 10_000;

/** The fixed reasons a resume reports when it doesn't lower `restore`. */
export const REASONS = Object.freeze([
  // the supervisor's
  "not_validated", "no_verifier", "no_host_records", "no_receipt", "receipt", "waiting_for_lease", "not_this_lease", "helper_failed",
  // the helper's
  "outside_slice", "busy", "no_record", "lease_not_live", "lease_raised",
  // resumed, but the unit's start couldn't be queued (the fence is down; the person is told, and may start it)
  "start_failed",
]);

/**
 * The argv the supervisor runs the helper with: a transient scope inside the agent's slice, carrying the live lease
 * and the agent's tags (the restored registry's, for the helper's own validated check).
 */
export function resumeArgv(agent, live, tags, { node = process.execPath, main = MAIN } = {}) {
  need(agent);
  if (!Array.isArray(tags) || !tags.every(isId) || new Set(tags).size !== tags.length) refuse("bad_form", "restore resume: bad tags");
  if (!Number.isSafeInteger(live?.gen) || live.gen < 1 || !Number.isSafeInteger(live?.lg)) refuse("bad_form", "restore resume: bad live lease");
  const { leaseId, lg } = parseArgs(agent, live.lease_id, String(live.lg));
  return ["systemd-run", "--scope", "--quiet", "--collect", `--slice=${agentSlice(agent)}`, `--unit=${restoreResumeScope(agent)}`,
    "--", node, main, "resume-restored", agent, String(live.gen), leaseId, String(lg), ...tags];
}

/**
 * The supervisor's side: the person asked to resume `agent` (see the header). Options, all the supervisor's:
 * - `restoreState(agent)`: restoreReady's verdict against the current restore's binding; `tagsOf(agent)`: the
 *   agent's tags in the restored registry (passed to the helper);
 * - `pairOf(agent)`: the stored {transfer, receipt} the service handed out, or null;
 * - `verifyTransferReceipt(pair, ctx)` → the verified pair (with its bodies and transferHash), and
 *   `checkTransferForHost(verified, host)` → { first }: the shared fleet core's, each throwing a FleetError to refuse; `verifyCtx`;
 * - `host`: this host's records (the supervisor's: entryGen, recordTransfer, and what checkTransferForHost reads);
 * - `liveLease(agent)`: lease part 2's live lease {lease_id, lg, gen, expiry_tick}, or null (async, awaited);
 * - `run(argv, { ms })`: the argv runner; `node`, `main`, `ms` (RESUME_HELPER_MS by default).
 * Resolves to { resumed, reason } (and `code`, the verifier's, when the reason is "receipt"). A resume whose start
 * couldn't be queued after the durable lowering is { resumed: true, reason: "start_failed" }.
 */
export async function requestResume(agent, opts = {}) {
  const { restoreState, tagsOf, pairOf, verifyTransferReceipt, checkTransferForHost, verifyCtx = {}, host = null, liveLease, run, node, main, ms = RESUME_HELPER_MS } = opts;
  need(agent);
  const no = (reason, extra = {}) => ({ resumed: false, reason, ...extra });
  // 1. validated.
  let state;
  try { state = restoreState(agent); } catch { return no("not_validated"); }
  if (state !== "validated") return no("not_validated");
  // 2. the receipt (the dependencies that aren't there yet: refused, each with its own reason).
  if (typeof verifyTransferReceipt !== "function" || typeof checkTransferForHost !== "function") return no("no_verifier");
  if (host === null || typeof host !== "object" || typeof host.entryGen !== "function" || typeof host.recordTransfer !== "function") return no("no_host_records");
  const pair = typeof pairOf === "function" ? await pairOf(agent) : null; // (the intake's pairOf re-verifies: async)
  if (pair === null || pair === undefined) return no("no_receipt");
  let verified, checked;
  try {
    verified = await verifyTransferReceipt(pair, verifyCtx);
    // The pair must move THIS agent: a valid pair for another agent authorizes nothing here.
    if (verified?.transfer?.agent !== agent || verified?.receipt?.agent !== agent) return no("receipt", { code: "not_granted" });
    checked = checkTransferForHost(verified, host);
  } catch (e) {
    if (e instanceof FleetError) return no("receipt", { code: e.code });
    throw e;
  }
  // 4. the live lease, for the current entry_gen (checked before recording: a resume that can't run records nothing).
  // liveLease is async (it reads the published record and runs liveCheck): awaited, never read as a promise.
  const live = typeof liveLease === "function" ? await liveLease(agent) : null;
  if (live === null || live === undefined) return no("waiting_for_lease");
  let current;
  try { current = host.entryGen(agent); } catch { return no("not_this_lease"); }
  if (live.gen !== current) return no("not_this_lease");
  // The helper's argv, built (and every part of it checked: the live lease, the tags) BEFORE anything is recorded:
  // a malformed one throws here, with nothing recorded and nothing launched.
  const argv = resumeArgv(agent, live, typeof tagsOf === "function" ? tagsOf(agent) : null, { node, main });
  // A pair new here is recorded, durably, before anything is launched (check 6's "new", enforced once).
  if (checked?.first === true) {
    host.recordTransfer(agent, { gen: verified.receipt.gen, nonce: verified.receipt.nonce, transfer: verified.transferHash });
  } else if (checked?.first !== false) {
    return no("receipt", { code: "bad_form" });
  }
  const r = await run(argv, { ms });
  let out;
  try { out = JSON.parse(String(r?.stdout ?? "").trim().split("\n").at(-1)); } catch { return no("helper_failed"); }
  if (out === null || typeof out !== "object" || typeof out.resumed !== "boolean") return no("helper_failed");
  if (out.resumed) return { resumed: true, reason: out.reason === "start_failed" ? "start_failed" : null };
  return no(REASONS.includes(out.reason) && out.reason !== "start_failed" ? out.reason : "helper_failed");
}

/**
 * `resume-restored <agent> <gen> <lease_id> <lg>`, the helper (see the header), gen and lg as numbers. Options are its
 * dependencies and test seams: `restoreState(agent)`; `dir` (the lease directory), `fenceDir`, `leaseFenceDir`,
 * `fsx`, `sys` (selfCgroup, liveCheck's timer, start), `clock`, `lock`, `readLease` (lease.mjs's readRecord),
 * `cgroupOf` (lowerFence's test seam), `barrier`, `pid`. Resolves to { resumed, reason, lowered }.
 */
export async function resumeRestored(agent, gen, leaseId, lg, opts = {}) {
  const { restoreState, dir = LEASE_DIR, fenceDir = FENCE_DIR, leaseFenceDir = LEASE_FENCE_DIR, fsx = fs, sys = realSystem({ fsx }),
    clock = realClock, lock = lockFile, readLease = readRecord, cgroupOf, barrier = async () => {}, pid = process.pid } = opts;
  const no = (reason) => ({ resumed: false, reason, lowered: false });
  need(agent);
  if (!Number.isSafeInteger(gen) || gen < 1 || !Number.isSafeInteger(lg)) refuse("bad_form", "restore resume: bad gen or lg");
  parseArgs(agent, leaseId, String(lg));
  if (sys.selfCgroup() !== resumeCgroup(agent)) return no("outside_slice");
  let held;
  try { held = await activationLock(agent, { dir, fsx, lock, waitMs: LOCK_TRY_MS }); } catch { return no("busy"); }
  try {
    fsx.writeFileSync(join(dir, `${agent}.lock.pid`), `${pid}\n`, { mode: 0o644 });
    await barrier("after_lock", {});
    // 1. still validated.
    let state;
    try { state = restoreState(agent); } catch { return no("not_validated"); }
    if (state !== "validated") return no("not_validated");
    // 3. the argv's lease is the published one, and live.
    const r = readLease(agent, { dir, fsx });
    if (r.state !== "ok") return no("no_record");
    if (r.rec.lease_id !== leaseId || r.rec.lg !== lg) return no("not_this_lease");
    if ((await liveCheck(agent, r.rec, { dir, fsx, sys, clock })) !== null) return no("lease_not_live");
    // 4. for the argv's gen (the published record carries the lease's entry_gen: lease part 2).
    if (r.rec.gen !== gen) return no("not_this_lease");
    // 5. `lease` already down.
    if (fsx.existsSync(join(leaseFenceDir, agent))) return no("lease_raised");
    await barrier("after_checks", {});
    await lowerFence("restore", agent, "resume-restored", { dir: fenceDir, restoreState: "validated", ...(cgroupOf ? { cgroupOf } : {}) });
    await barrier("after_lower", {});
    // The start the lease helper's was skipped for while `restore` held: queued here, under the same lock.
    try { await sys.start(agentUnit(agent)); } catch { return { resumed: true, reason: "start_failed", lowered: true }; }
    await barrier("after_start", {});
    return { resumed: true, reason: null, lowered: true };
  } finally {
    try { fsx.unlinkSync(join(dir, `${agent}.lock.pid`)); } catch { /* gone */ }
    await held.release();
  }
}
