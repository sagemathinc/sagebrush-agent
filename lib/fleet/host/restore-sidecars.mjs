// Host restore e2e r1.7 §5, delta R5-d2 §3.1, §3.2 and §3.8: an abandon's two single-writer sidecars, beside the set's
// record in RESTORE_DIR/abandon/, and the audit pair that close and status require of an abandoned record.
//
// - **The intent** `<kind>-<id>.json`, written once by the abandon op (writeExclusive): exactly
//   {v: 1, kind, id, restore_run, set_run, set_snapshot, account, person, by, at, reason, envelope_sha256, nonce}.
//   `restore_run` is begin's (the restore's) run; `set_run` and `set_snapshot` are the plan's for the set at acceptance.
// - **The attestation** `<kind>-<id>.cleaned`, written by the finish once every bound destination is emptied and the
//   staging is gone: exactly {v: 1, set_run, set_snapshot, attempt, dest, staging_gone: true, at}, copied from the
//   final record the cleanup used.
// - **The audit pair:** an abandoned record is audit-complete only when both are present and well-formed, the intent
//   names this set, and both bind the record's set run, snapshot, attempt and destination. Anything else is corrupt.
// Every read is one regular file through a no-follow handle (readRegular), its directory proven; malformed refuses.

import { join } from "node:path";
import { isId, refuse } from "../bytes.mjs";
import { exactKeys } from "./store.mjs";
import { KINDS, RESTORE_RUN, checkRecordDest, readRegular } from "./restore-record.mjs";

export const MAX_SIDECAR = 64 * 1024;
export const MAX_REASON = 500;
const HEX64 = /^[0-9a-f]{64}$/;
const B64URL = /^[A-Za-z0-9_-]{22}$/;
const KEY_ID = /^[A-Za-z0-9_-]{1,128}$/;

export const intentName = (kind, id) => `${kind}-${id}.json`;
export const attestationName = (kind, id) => `${kind}-${id}.cleaned`;

/** A nonce's canonical form: base64url without padding, decoding to exactly 16 bytes and re-encoding to itself. */
export function canonicalNonce(n) {
  if (typeof n !== "string" || !B64URL.test(n)) return false;
  const b = Buffer.from(n, "base64url");
  return b.length === 16 && b.toString("base64url") === n;
}
const safeMs = (x) => Number.isSafeInteger(x) && x >= 0;
const utf8Bytes = (s) => Buffer.byteLength(s, "utf8");

/** The intent's closed shape, for the set `kind`/`id` (named by its path: the intent must name the same set). */
export function checkIntent(x, kind, id) {
  const bad = () => refuse("bad_form", "restore abandon: not a valid intent");
  if (!exactKeys(x, ["v", "kind", "id", "restore_run", "set_run", "set_snapshot", "account", "person", "by", "at", "reason", "envelope_sha256", "nonce"]) || x.v !== 1) bad();
  if (!KINDS.includes(x.kind) || !isId(x.id) || typeof x.restore_run !== "string" || !RESTORE_RUN.test(x.restore_run)
    || typeof x.set_run !== "string" || !RESTORE_RUN.test(x.set_run) || typeof x.set_snapshot !== "string" || !HEX64.test(x.set_snapshot)
    || !isId(x.account) || !isId(x.person) || typeof x.by !== "string" || !KEY_ID.test(x.by) || !safeMs(x.at)
    || typeof x.reason !== "string" || utf8Bytes(x.reason) > MAX_REASON || typeof x.envelope_sha256 !== "string" || !HEX64.test(x.envelope_sha256)
    || !canonicalNonce(x.nonce)) bad();
  // (the intent's own kind and id must be the set its path names, even when its runs and snapshot match)
  if (x.kind !== kind || x.id !== id) refuse("not_granted", "restore abandon: the intent names another set");
  return x;
}

/** The attestation's closed shape for a set of `kind`. */
export function checkAttestation(x, kind) {
  const bad = () => refuse("bad_form", "restore abandon: not a valid attestation");
  if (!exactKeys(x, ["v", "set_run", "set_snapshot", "attempt", "dest", "staging_gone", "at"]) || x.v !== 1) bad();
  if (typeof x.set_run !== "string" || !RESTORE_RUN.test(x.set_run) || typeof x.set_snapshot !== "string" || !HEX64.test(x.set_snapshot)
    || !Number.isSafeInteger(x.attempt) || x.attempt < 1 || !(x.dest === null || checkRecordDest(kind, x.dest)) || x.staging_gone !== true || !safeMs(x.at)) bad();
  return x;
}

const parse = (bytes, what) => {
  const text = bytes.toString("utf8");
  if (!text.endsWith("\n")) refuse("bad_form", `restore abandon: ${what} isn't one JSON line`);
  let x;
  try { x = JSON.parse(text); } catch { refuse("bad_form", `restore abandon: ${what} isn't JSON`); }
  // (exactly the canonical bytes this module writes: no other spelling of the same object is accepted)
  if (JSON.stringify(x) + "\n" !== text) refuse("bad_form", `restore abandon: ${what} isn't canonical`);
  return x;
};

/** The set's intent in the PROVEN abandon directory: null when there is none; a present one must be valid. */
export function readIntentFile(abandonDir, kind, id) {
  const bytes = readRegular(join(abandonDir, intentName(kind, id)), MAX_SIDECAR, "an abandon intent");
  return bytes === null ? null : { intent: checkIntent(parse(bytes, "the intent"), kind, id), bytes };
}

/** The set's attestation in the PROVEN abandon directory: null when there is none; a present one must be valid. */
export function readAttestationFile(abandonDir, kind, id) {
  const bytes = readRegular(join(abandonDir, attestationName(kind, id)), MAX_SIDECAR, "an abandon attestation");
  return bytes === null ? null : { attestation: checkAttestation(parse(bytes, "the attestation"), kind), bytes };
}

/** The attestation's bytes for a record just cleaned (its set run, snapshot, attempt and destination). */
export const attestationText = (r, at) => JSON.stringify(checkAttestation({ v: 1, set_run: r.run, set_snapshot: r.snapshot, attempt: r.attempt, dest: r.dest, staging_gone: true, at }, r.kind)) + "\n";

/** Does the attestation bind exactly this record (set run, snapshot, attempt and destination)? */
export function attests(att, r) {
  return att.set_run === r.run && att.set_snapshot === r.snapshot && att.attempt === r.attempt && JSON.stringify(att.dest) === JSON.stringify(r.dest);
}

/**
 * An abandoned record's audit pair (R5-d2 §3.8): refuses (not_granted) unless the intent and the attestation are both
 * present and well-formed, the intent names this set of THIS restore (`restoreRun`, begin's run) at the record's set
 * run and snapshot, and the attestation binds the record. The one validator of finish, the tick and close. Returns
 * { intent, attestation } (their bytes included) for the archive and status.
 */
export function auditPair(r, abandonDir, { restoreRun } = {}) {
  if (r.state !== "abandoned") refuse("bad_form", "restore abandon: not an abandoned record");
  if (typeof restoreRun !== "string") refuse("bad_form", "restore abandon: the audit needs the restore's run");
  const corrupt = (why) => refuse("not_granted", `restore abandon: ${r.kind}-${r.id} is abandoned, but ${why}`);
  if (abandonDir === null) corrupt("there is no abandon directory");
  let i, a;
  try { i = readIntentFile(abandonDir, r.kind, r.id); a = readAttestationFile(abandonDir, r.kind, r.id); } catch (e) { corrupt(`a sidecar is unreadable (${e?.code ?? "error"})`); }
  if (i === null) corrupt("its intent is missing");
  if (a === null) corrupt("its attestation is missing");
  if (i.intent.restore_run !== restoreRun) corrupt("its intent is another restore's");
  if (i.intent.set_run !== r.run || i.intent.set_snapshot !== r.snapshot) corrupt("its intent is another run's");
  if (!attests(a.attestation, r)) corrupt("its attestation doesn't match it");
  return { intent: i, attestation: a };
}
