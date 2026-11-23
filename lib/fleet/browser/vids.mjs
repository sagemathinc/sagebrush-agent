// Fleet protocol, the browser lane (O11 draft 5 §4.3; the handles in schema/fleet/browser/o11-cdp.json): virtual
// handles. The agent never sees a real CDP id. Each real id it is shown becomes a vid "<kind>_<16 base36>", random per
// session; the same live real id gets the same vid; a revoked vid is never reused and never maps to a newer real id.
// Expiry rules (navigation, takeover) call revoke(); this module only keeps the map honest.

import { randomBytes } from "node:crypto";
import { refuse } from "../index.mjs";

export const KINDS = Object.freeze(["pg", "fr", "ld", "cx", "nd", "bn", "ax", "ob", "rq", "he"]);
export const VID = /^[a-z]{1,3}_[0-9a-z]{16}$/;
const ALPHA = "0123456789abcdefghijklmnopqrstuvwxyz";

export class Vids {
  #live = new Map(); // `${kind}\0${typeof real}:${real}` -> vid
  #byVid = new Map(); // vid -> { kind, real, revoked }
  #rand;
  /** `rand(n)`: n random bytes (tests may pass their own; the default is the CSPRNG). */
  constructor(rand = (n) => randomBytes(n)) { this.#rand = rand; }

  #fresh(kind) {
    for (;;) {
      let s = "";
      while (s.length < 16) for (const x of this.#rand(24)) if (x < 252 && s.length < 16) s += ALPHA[x % 36]; // (unbiased: 252 = 7 x 36)
      const v = `${kind}_${s}`;
      if (!this.#byVid.has(v)) return v; // (never reused, revoked ones included)
    }
  }

  /** The vid of a real id the agent is about to be shown (created on first sight). */
  out(kind, real) {
    if (!KINDS.includes(kind)) refuse("bad_kind", "unknown handle kind");
    if (typeof real !== "string" && !(typeof real === "number" && Number.isSafeInteger(real))) refuse("unmappable", "a handle is a string or a safe integer");
    const key = `${kind}\0${typeof real}:${real}`;
    const have = this.#live.get(key);
    if (have) return have;
    const v = this.#fresh(kind);
    this.#live.set(key, v);
    this.#byVid.set(v, { kind, real, revoked: false });
    return v;
  }

  /** The real id behind a vid the agent sent, which must be live and of this kind. */
  in(kind, vid) {
    const e = typeof vid === "string" && VID.test(vid) ? this.#byVid.get(vid) : undefined;
    if (!e || e.revoked || e.kind !== kind) refuse("stale_handle", "stale or foreign handle");
    return e.real;
  }

  /** Revoke every live handle that `pred(kind, real)` selects (all of them without one); returns how many. */
  revoke(pred = () => true) {
    let n = 0;
    for (const [key, v] of this.#live) {
      const e = this.#byVid.get(v);
      if (pred(e.kind, e.real)) { e.revoked = true; this.#live.delete(key); n++; }
    }
    return n;
  }

  get size() { return this.#live.size; }
}
