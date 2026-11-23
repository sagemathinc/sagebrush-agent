// Fleet protocol, the browser lane (O11 draft 5 §4.3; the handles in schema/fleet/browser/o11-cdp.json): virtual
// handles. The agent never sees a real CDP id. Each real id it is shown becomes a vid "<kind>_<16 base36>", random per
// session; the same live real id gets the same vid; a revoked vid is never reused and never maps to a newer real id.
// Expiry rules (navigation, takeover) call revoke(); this module only keeps the map honest.
//
// One Vids per agent session. Real ids other than pages are local to a CDP target (node, context and history ids are
// small integers that repeat from tab to tab), so every handle but `pg` is bound to the scope (the target's CDP session
// id) it was seen in, and is accepted only back in that scope. A page's TargetId is browser-wide: `pg` has no scope.
//
// The session's handles are bounded: at most HANDLE_BUDGET over its whole life, live and revoked together (the spec's
// handleBudget.issued; revoked vids are kept, as bare strings, so they're never reused). The allocation past it spends
// the instance: from then on it refuses every call with `handle_budget`, and the caller retires the session.

import { randomBytes } from "node:crypto";
import { refuse } from "../index.mjs";

export const KINDS = Object.freeze(["pg", "fr", "ld", "cx", "nd", "bn", "ax", "ob", "rq", "he"]);
export const UNSCOPED = Object.freeze(["pg"]);
export const VID = /^[a-z]{1,3}_[0-9a-z]{16}$/;
export const SCOPE = /^[\x21-\x7e]{1,128}$/;
export const HANDLE_BUDGET = 262144; // (= o11-cdp.json handleBudget.issued; the test checks)
const ALPHA = "0123456789abcdefghijklmnopqrstuvwxyz";

export class Vids {
  #live = new Map(); // `${kind}\0${scope}\0${typeof real}:${real}` -> vid
  #byVid = new Map(); // live vid -> { kind, scope, real }
  #dead = new Set(); // revoked vids
  #issued = 0;
  #spent = false;
  #rand;
  #budget;
  /** `rand(n)`: n random bytes (tests may pass their own; the default is the CSPRNG). `budget`: tests only. */
  constructor(rand = (n) => randomBytes(n), budget = HANDLE_BUDGET) {
    this.#rand = rand;
    this.#budget = budget;
  }

  #fresh(kind) {
    for (;;) {
      let s = "";
      while (s.length < 16) for (const x of this.#rand(24)) if (x < 252 && s.length < 16) s += ALPHA[x % 36]; // (unbiased: 252 = 7 x 36)
      const v = `${kind}_${s}`;
      if (!this.#byVid.has(v) && !this.#dead.has(v)) return v; // (never reused, revoked ones included)
    }
  }

  #scope(kind, scope) {
    if (!KINDS.includes(kind)) refuse("bad_kind", "unknown handle kind");
    if (UNSCOPED.includes(kind)) {
      if (scope !== undefined) refuse("bad_scope", "a page handle has no target scope");
      return "";
    }
    if (typeof scope !== "string" || !SCOPE.test(scope)) refuse("bad_scope", "a target-local handle needs its target's scope");
    return scope;
  }

  #check() { if (this.#spent) refuse("handle_budget", "the session's handle budget is spent; retire the session"); }

  /** The vid of a real id the agent is about to be shown in `scope` (created on first sight). */
  out(kind, real, scope) {
    this.#check();
    const sc = this.#scope(kind, scope);
    if (typeof real !== "string" && !(typeof real === "number" && Number.isSafeInteger(real))) refuse("unmappable", "a handle is a string or a safe integer");
    const key = `${kind}\0${sc}\0${typeof real}:${real}`;
    const have = this.#live.get(key);
    if (have) return have;
    if (this.#issued >= this.#budget) {
      this.#spent = true;
      this.#check();
    }
    const v = this.#fresh(kind);
    this.#live.set(key, v);
    this.#byVid.set(v, { kind, scope: sc, real });
    this.#issued++;
    return v;
  }

  /** The real id behind a vid the agent sent to `scope`, which must be live, of this kind and from this scope. */
  in(kind, vid, scope) {
    this.#check();
    const sc = this.#scope(kind, scope);
    const e = typeof vid === "string" && VID.test(vid) ? this.#byVid.get(vid) : undefined;
    if (!e || e.kind !== kind || e.scope !== sc) refuse("stale_handle", "stale or foreign handle");
    return e.real;
  }

  /** Revoke every live handle that `pred(kind, real, scope)` selects (all of them without one); returns how many. */
  revoke(pred = () => true) {
    let n = 0;
    for (const [key, v] of this.#live) {
      const e = this.#byVid.get(v);
      if (pred(e.kind, e.real, e.scope)) { this.#live.delete(key); this.#byVid.delete(v); this.#dead.add(v); n++; }
    }
    return n;
  }

  get size() { return this.#live.size; }
  get issued() { return this.#issued; }
  get spent() { return this.#spent; }
}
