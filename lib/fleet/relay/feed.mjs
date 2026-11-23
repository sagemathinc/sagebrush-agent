// Fleet protocol, the browser relay (design agent-autonomous-browser-relay.md r2.2 §5): the revocation feed.
// - A poll starts every FEED.pollMs (from the previous start) with since = the committed cursor (0 before the first);
//   each call is aborted at its own deadline (CONTROL.feedMs) on this clock, whatever the transport.
// - An answer (verified by the client: signed, bound to its call, closed schema, cursor ahead of its since, no
//   identity twice) is a success only if its since is the cursor this poll sent, no entry lists an epoch below one
//   already known for that identity, and its cursor is committed to the store. Anything else changes nothing.
// - On a success, every slot an agent, account or host change touches closes at once (no re-admission). `more: true`
//   polls again at once, at most FEED.morePolls times in a row.
// - cursor_expired (the Worker's signed refusal: a since it no longer has, or never issued) closes every slot and
//   resets the cursor, so the next poll starts from since=0. It isn't a success and never extends the fail-close.
// - The fail-close is an independent timer on the monotonic clock, restarted only by a success: at exactly
//   FEED.failMs without one, every slot closes, opens are refused, and the call in flight is aborted; its late answer
//   is ignored. Opens are admitted again after the next success (and not before the first one).

import { CODES } from "./slots.mjs";
import { CONTROL } from "./control.mjs";
import { CURSOR_EXPIRED } from "../core/control.mjs";

export const FEED = Object.freeze({ pollMs: 5000, failMs: 30_000, morePolls: 8 });
const LISTS = [["agents", "agent"], ["accounts", "account"], ["hosts", "host"]];

export class Feed {
  /** control: controlClient; store: openStore's; slots: Slots; clock: { now, setTimeout, clearTimeout }. */
  constructor({ control, store, slots, clock, log = () => {} }) {
    this.control = control; this.store = store; this.slots = slots; this.clock = clock; this.log = log;
    this.known = new Map(); // "agent:<id>" | "account:<id>" | "host:<id>" -> the highest epoch seen (feed or admit answers)
    this.available = false;
    this.gen = 0; this.controller = null; this.pollTimer = null; this.failTimer = null; this.stopped = false; this.more = 0;
  }

  start() { this.#armFail(); this.#poll(); }

  stop() {
    this.stopped = true;
    this.clock.clearTimeout(this.pollTimer); this.clock.clearTimeout(this.failTimer);
    this.gen++; this.controller?.abort();
  }

  /** Whether an admit answer's epochs ({ account, agent, host }) are still current; records them if they're newer. */
  current(epochs, ids) {
    const pairs = ["agent", "account", "host"].map((k) => [k, ids[k], epochs[k]]);
    for (const [kind, id, e] of pairs) if (e < (this.known.get(`${kind}:${id}`) ?? 0)) return false;
    for (const [kind, id, e] of pairs) if (e > (this.known.get(`${kind}:${id}`) ?? 0)) this.known.set(`${kind}:${id}`, e);
    return true;
  }

  #armFail() {
    this.clock.clearTimeout(this.failTimer);
    this.failTimer = this.clock.setTimeout(() => this.#failClose(), FEED.failMs);
  }

  #failClose() {
    this.failTimer = null;
    this.available = false;
    this.gen++; // (the call in flight is abandoned: its answer, whenever it comes, is ignored)
    this.controller?.abort();
    this.slots.closeAll(CODES.unavailable, "the revocation feed failed");
    this.log({ event: "feed_fail_close" });
  }

  async #poll({ immediate = false } = {}) {
    if (this.stopped) return;
    if (!immediate) this.more = 0;
    const g = ++this.gen;
    const controller = (this.controller = new AbortController());
    this.clock.clearTimeout(this.pollTimer);
    this.pollTimer = this.clock.setTimeout(() => this.#poll(), FEED.pollMs);
    const deadline = this.clock.setTimeout(() => controller.abort(), CONTROL.feedMs); // (the call's own deadline, on this clock)
    const since = Math.max(0, this.store.cursor());
    let a = null;
    try { a = await this.control.epochs(since, controller.signal); } catch (e) { this.log({ event: "feed_error", code: e?.code ?? "error" }); }
    this.clock.clearTimeout(deadline);
    if (g !== this.gen || this.stopped || a === null || controller.signal.aborted) return;
    this.#apply(a, since);
  }

  #apply(a, since) {
    if (a.since !== since) return this.log({ event: "feed_refused", code: "since" });
    if (a.result === "refused") {
      if (a.code !== CURSOR_EXPIRED) return this.log({ event: "feed_refused", code: "refusal" });
      this.slots.closeAll(CODES.unavailable, "the revocation feed's cursor expired");
      try { this.store.reset(); } catch { return this.log({ event: "feed_refused", code: "store" }); }
      return this.log({ event: "feed_cursor_expired" });
    }
    if (!(a.cursor > this.store.cursor())) return this.log({ event: "feed_refused", code: "cursor" });
    for (const [list, kind] of LISTS) for (const c of a[list]) if (c.epoch < (this.known.get(`${kind}:${c.id}`) ?? 0)) return this.log({ event: "feed_refused", code: "epoch" });
    let moved;
    try { moved = this.store.advance(a.cursor); } catch { return this.log({ event: "feed_refused", code: "store" }); }
    if (!moved) return this.log({ event: "feed_refused", code: "cursor" });
    for (const [list, kind] of LISTS) for (const c of a[list]) {
      this.known.set(`${kind}:${c.id}`, Math.max(c.epoch, this.known.get(`${kind}:${c.id}`) ?? 0));
      this.slots.revoke(kind, c.id);
    }
    this.available = true;
    this.#armFail();
    if (a.more && this.more < FEED.morePolls) { this.more++; this.#poll({ immediate: true }); }
  }
}
