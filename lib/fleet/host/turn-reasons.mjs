// A turn's reasons (launcher contract amendment A5 §8.3): ONE closed mapping, from the launcher's failure record and
// the admission outcomes to the signed `harness.turn` event's phase and reason. Every reason named here is a host entry
// in schema/fleet/reasons.json; a pair outside this table is refused, so the audit writer can't record one.
//
// - The launcher's failure record: 73 is profile_identity; 67 is landlock_abi (its existing meaning); every other code
//   the launcher writes before exec (64, 65, 66, 68, 69, 71, 72) is turn_preflight. preflight_missing is NEVER a turn's:
//   it keeps the unit start's frozen meaning (effects.mjs's launcherExit). An unknown code has no reason: the caller
//   records unknown_effect, which carries none.
// - Admission refusals: no_profile, all_blocked, agent_fenced and source_unavailable are `refused` events. busy is never
//   an event, only the rate-limited refusal summary (A5 §8.4, H4).

/** The phases that carry a reason, each with exactly the reasons it may carry. */
export const TURN_REASONS = Object.freeze({
  failed_no_effect: Object.freeze(["profile_identity", "turn_preflight", "landlock_abi"]),
  refused: Object.freeze(["no_profile", "all_blocked", "agent_fenced", "source_unavailable"]),
});

/** The phases that carry no reason. */
export const TURN_PHASES_WITHOUT_REASON = Object.freeze(["authorized", "succeeded", "unknown_effect", "reconciled_no_effect", "reconciled_succeeded"]);

/** Reasons that never become an event: only the rate-limited refusal summary. */
export const SUMMARY_ONLY = Object.freeze(["busy"]);

const PREFLIGHT_CODES = Object.freeze([64, 65, 66, 68, 69, 71, 72]);

/** The audit reason for a complete, valid failure record's exit code; null for any other code (unknown_effect). */
export function launcherTurnReason(code) {
  if (code === 73) return "profile_identity";
  if (code === 67) return "landlock_abi";
  if (PREFLIGHT_CODES.includes(code)) return "turn_preflight";
  return null;
}

/**
 * Whether `reason` may go with `phase` (null for none). Anything outside the table is false, and so is any phase that
 * isn't a primitive string or any reason that isn't a primitive string or null: nothing is coerced.
 */
export function turnPairOk(phase, reason) {
  if (typeof phase !== "string" || (reason !== null && typeof reason !== "string")) return false;
  if (TURN_PHASES_WITHOUT_REASON.includes(phase)) return reason === null;
  return Object.hasOwn(TURN_REASONS, phase) && TURN_REASONS[phase].includes(reason);
}
