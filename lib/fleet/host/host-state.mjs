// Host supervisor: the host's state report for the fleet pages' `…/state` (agent-autonomous-pages-fleet §2.1: the host
// supervisor's fields; the restore stage comes from the restore records). Every field is a closed enum from shipped code, and
// nothing in it names a profile, subscription, conversation or path. The service relays it as an UNVERIFIED report and
// adds last_seen_ms itself (when it last heard from the host), so the host doesn't send that.
//
//   { host: { reported_at_ms, health: "ok" | "degraded" | "failing", health_reasons: [<host-owned reason codes>] },
//     agents: { <id>: { run, fences, lease: "live" | "none", lease_expires_at_ms, restore } } }
//
// - health: supervisor freeze r3.1 §8.1's state, coarsened: ok; degraded_audit and reserve_only are "degraded";
//   fail_closed and qualify_required are "failing". Until the audit health signal exists, only the qualification
//   latch is known: its qualify_required is reported, and otherwise the state is whatever the caller injects (ok).
// - lease_expires_at_ms: the lease's EFFECTIVE end (expiry_tick - 30 s, when its watchdog stops the agent) on the host's
//   wall clock, converted at report time from CLOCK_BOOTTIME: approximate, for display only.
// - Pure: it reads only through the functions it is given, and writes nothing.

import { refuse } from "../bytes.mjs";
import { CAUSES, fenceCauses } from "./fence.mjs";
import { MARGIN_MS, bootNow, realClock } from "./lease.mjs";
import { FENCE_DIR, RESTORE_DIR } from "./names.mjs";
import { STATES as RUN_STATES } from "./registry.mjs";
import { STATES as RESTORE_STATES, readRecord as readRestore } from "./restore-record.mjs";

/** §8.1's health states, as the page's three. */
export const HEALTH = Object.freeze({ ok: "ok", degraded_audit: "degraded", reserve_only: "degraded", fail_closed: "failing", qualify_required: "failing" });
/** The host-owned reason codes a health report may carry (§8.1's host-local codes; each registered in reasons.json). */
export const HEALTH_REASONS = Object.freeze(["audit_full", "audit_timeout", "audit_unavailable", "clone_detected", "qualify_required", "uid_exhausted"]);

const bad = (what) => refuse("bad_form", `host state: ${what}`);

/**
 * The report. `r`: { agentIds() -> ids, run(id) -> registry state, fences(id) -> CAUSES names, liveLease(id) ->
 * {expiry_tick} | null (async), restore(id) -> restore record state | null, qualification() -> "qualified" |
 * "qualify_required", health() -> { state, reasons } (§8.1; default ok, none), nowMs() (wall), bootNowMs() (CLOCK_BOOTTIME) }.
 */
export async function hostState(r) {
  const nowMs = r.nowMs(), boot = r.bootNowMs();
  if (!Number.isSafeInteger(nowMs) || !Number.isSafeInteger(boot)) bad("no clock");
  const h = r.health ? r.health() : { state: "ok", reasons: [] };
  if (!Object.hasOwn(HEALTH, h?.state) || !Array.isArray(h.reasons)) bad("an unknown health state");
  let state = h.state;
  const reasons = new Set(h.reasons);
  if (r.qualification() === "qualify_required") { state = HEALTH[state] === "failing" ? state : "qualify_required"; reasons.add("qualify_required"); }
  for (const x of reasons) if (!HEALTH_REASONS.includes(x)) bad("an unregistered health reason");
  if (HEALTH[state] === "ok" && reasons.size > 0) bad("reasons on an ok host");
  const agents = {};
  for (const id of r.agentIds()) {
    const run = r.run(id);
    if (!RUN_STATES.includes(run)) bad("an unknown run state");
    const fences = [...new Set(r.fences(id))].sort();
    if (!fences.every((c) => CAUSES.includes(c))) bad("an unknown fence cause");
    const live = await r.liveLease(id);
    const restore = r.restore(id);
    if (restore !== null && !RESTORE_STATES.includes(restore)) bad("an unknown restore state");
    agents[id] = {
      run, fences,
      lease: live ? "live" : "none",
      lease_expires_at_ms: live ? nowMs + (live.expiry_tick - MARGIN_MS - boot) : null,
      restore,
    };
  }
  return { host: { reported_at_ms: nowMs, health: HEALTH[state], health_reasons: [...reasons].sort() }, agents };
}

/**
 * The readers over an open HostStore. `liveLease` is lease-live.mjs's; with none given, no lease is
 * ever reported live. A restore record that can't be read throws, so the whole report fails rather than misreport.
 */
export function hostStateReaders(store, { liveLease = async () => null, health, fenceDir = FENCE_DIR, restoreDir = RESTORE_DIR, clock = realClock, wall = Date.now } = {}) {
  return {
    agentIds: () => store.registry.agentIds(),
    run: (id) => store.registry.agent(id).state,
    fences: (id) => fenceCauses(id, { dir: fenceDir }),
    liveLease,
    restore: (id) => readRestore("agent", id, { dir: restoreDir })?.state ?? null,
    qualification: () => store.qualification.state,
    health,
    nowMs: () => wall(),
    bootNowMs: () => bootNow(clock),
  };
}

