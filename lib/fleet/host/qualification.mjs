// Host supervisor: the host's qualification state, durable in the host store (qualification.json). A host's
// qualification holds for the systemd it was qualified with: the agent unit's syscall policy is that systemd's own group
// expansion (schema/fleet/agent-seccomp-policy.json, launcher contract amendment A5 §3). When a start finds the host's
// systemd isn't the qualified one, the qualification is INVALIDATED here, and the invalidation LATCHES: every later
// start is refused (`qualify_required`) without asking systemd again, even if it would now answer correctly. Only
// accepting a fresh qualification report clears it, and that is a later reviewed change: nothing here clears it.
//
//   { v: 1, invalidated: null | { reason: "qualify_required", at_ms } }

import { refuse } from "../bytes.mjs";
import { DurableState, exactKeys, realIo } from "./store.mjs";

const FILE = "qualification.json";
const empty = () => ({ v: 1, invalidated: null });

/** The closed shape (refuses anything else, with bad_form). */
export function checkQualification(r) {
  const bad = () => refuse("bad_form", "qualification: corrupt");
  if (!exactKeys(r, ["v", "invalidated"]) || r.v !== 1) bad();
  const i = r.invalidated;
  if (i !== null && (!exactKeys(i, ["reason", "at_ms"]) || i.reason !== "qualify_required" || !Number.isSafeInteger(i.at_ms) || i.at_ms < 0)) bad();
  return true;
}

export class Qualification {
  #s;

  /** A view of the record in `dir`, under the host store's lock (host-store.mjs); it never locks by itself. */
  static attach(dir, lock, { io = realIo } = {}) {
    const q = new Qualification();
    q.#s = DurableState.attach(dir, FILE, { check: checkQualification, initial: empty, io, lock });
    return q;
  }

  /** The host's health as far as qualification goes: "qualified" or "qualify_required". */
  get state() { return this.#s.get().invalidated === null ? "qualified" : "qualify_required"; }

  /** Whether the qualification is invalidated (latched). */
  get latched() { return this.#s.get().invalidated !== null; }

  /** Invalidate it, durably; the first time is kept (idempotent). */
  invalidate(nowMs) {
    if (!Number.isSafeInteger(nowMs) || nowMs < 0) refuse("bad_form", "qualification: bad time");
    if (this.latched) return;
    this.#s.commit((r) => { r.invalidated = { reason: "qualify_required", at_ms: nowMs }; });
  }
}
