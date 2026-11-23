// Fleet protocol, the browser relay (design agent-autonomous-browser-relay.md r2.1 §4, §5, §6; the channel note r4.1
// §5.4): slots, candidates, the switch and forwarding, with the same semantics as the channel's FakeRelay
// (lib/fleet/channel/relay.mjs), on real sockets.
// - Identity is the full authenticated tuple (fleet, host, agent, browser_gen, session), from the Worker's verified
//   answer only. Per tuple: at most one active pair and one candidate pair; per agent, at most two candidate pairs,
//   each closed SLOTS.pendingMs after it was made unless a commit made it active first.
// - A candidate pair passes only the handshake's two messages (app -> host, then host -> app). Anything else closes
//   the candidate, never the active pair.
// - A commit (verified, its authorization consumed) switches the one candidate pair it names, by full tuple, resume_n,
//   the signer's host_gen and its two opens, to active, once, and closes that agent's other sockets (its active pair,
//   the same tuple's other slots, and older browser_gen sessions).
// - Forwarding: binary only (text closes the slot, 1003); a send that would take the peer's queue past
//   SLOTS.queueMax closes the slot (1009); a socket with bytes queued and no progress for SLOTS.stallMs closes it
//   (4003): one timer per socket from the first send that leaves bytes queued, restarted when the queue shrinks from
//   its last observed size (every observation is recorded, growth included), cleared when it empties, polled every
//   SLOTS.pollMs and after each completed write.
// - Each side's ends close the slot at the earliest: the host's grant end (not_after_ms, null for a grant without one),
//   the app's record end (not_after_ms) and its account session's expiry. A null never removes another side's timer.
// - The feed's changes close every slot of an agent, an account (either side's) or a host.
// - Limits from verified facts only: sockets in all, per agent, per account and per host; admitted opens a minute per
//   host and per account.
// Nothing is kept: a message goes to the peer's socket and is dropped.

export const SLOTS = Object.freeze({ pendingMs: 30_000, queueMax: 1 << 20, stallMs: 30_000, pollMs: 1000, sockets: 2000, perAgent: 8, perAccount: 64, perHost: 64, opensPerMinute: 20, opensWindow: 600 });
export const CODES = Object.freeze({ ended: 1000, binaryOnly: 1003, handshake: 1008, tooLarge: 1009, replaced: 4000, revoked: 4001, expired: 4002, stalled: 4003, unavailable: 4004 });

import { MinuteWindow } from "./window.mjs";

export class RelayRefusal extends Error {
  constructor(code, status) { super(code); this.code = code; this.status = status; }
}
const refuse = (code, status) => { throw new RelayRefusal(code, status); };

const tupleKey = (t) => `${t.fleet}/${t.host}/${t.agent}/${t.browser_gen}/${t.session}`;
const agentKey = (t) => `${t.fleet}/${t.hostId ?? t.host}/${t.agent}`; // (a slot keeps its host id in hostId: its host is the host side)

export class Slots {
  /** clock: { now(), setTimeout, clearTimeout } (monotonic); wallNow(): wall ms (for record and session expiry). */
  constructor({ clock, wallNow = () => Date.now(), log = () => {}, limits = SLOTS }) {
    this.clock = clock; this.wallNow = wallNow; this.log = log; this.limits = limits;
    this.slots = new Map(); // id -> slot
    // (admitted opens a minute per verified host and account: one bounded queue, as for opens before admission)
    this.opens = new MinuteWindow({ clock, max: limits.opensWindow });
    this.n = 0;
  }

  /** Every socket in a live slot (attached or about to be). */
  get sockets() { let n = 0; for (const s of this.slots.values()) n += (s.host ? 1 : 0) + (s.app ? 1 : 0); return n; }

  #count(pred) { let n = 0; for (const s of this.slots.values()) for (const side of [s.host, s.app]) if (side && pred(s, side)) n++; return n; }

  /** Whether a live slot involves this agent, account or host (the feed keeps those identities' epochs). */
  holds(kind, id) {
    for (const s of this.slots.values()) {
      if (kind === "agent" ? s.agent === id : kind === "host" ? s.hostId === id : [s.host, s.app].some((side) => side?.account === id)) return true;
    }
    return false;
  }

  /**
   * Reserve a side for an admitted open (the Worker's facts). Returns { attach(ws), abort() }, or throws RelayRefusal.
   * The id is already consumed; a refusal here leaves it consumed.
   */
  reserve(facts) {
    const L = this.limits, role = facts.role;
    if (this.sockets >= L.sockets) refuse("limit", 503);
    if (this.#count((s) => agentKey(s) === agentKey(facts)) >= L.perAgent) refuse("limit", 429);
    if (this.#count((s) => s.hostId === facts.host) >= L.perHost) refuse("limit", 429);
    if (this.#count((s, side) => side.account === facts.account) >= L.perAccount) refuse("limit", 429);
    const key = tupleKey(facts);
    let slot = [...this.slots.values()].find((s) => s.key === key && s.state === "candidate");
    if (slot) {
      if (slot.resume_n !== facts.resume_n || slot.host_gen !== facts.host_gen) refuse("in_progress", 409);
      if (slot[role]) refuse("in_progress", 409);
    } else {
      const pending = [...this.slots.values()].filter((s) => s.state === "candidate" && agentKey(s) === agentKey(facts)).length;
      if (pending >= 2) refuse("limit", 429);
    }
    if (!this.opens.take([`host:${facts.host}`, `account:${facts.account}`], L.opensPerMinute)) refuse("limit", 429);
    if (!slot) {
      slot = { id: ++this.n, key, fleet: facts.fleet, hostId: facts.host, host: null, app: null, agent: facts.agent, browser_gen: facts.browser_gen,
        session: facts.session, resume_n: facts.resume_n, host_gen: facts.host_gen, state: "candidate", handshake: 0, ids: {}, timers: new Set() };
      this.slots.set(slot.id, slot);
      slot.pending = this.#timer(slot, this.limits.pendingMs, () => { if (slot.state === "candidate") this.close(slot, CODES.expired, "expired"); });
    }
    const side = { slot, role, ws: null, account: facts.account, queued: { timer: null, poll: null, last: 0 }, bytes: 0 };
    slot[role] = side;
    slot.ids[role] = role === "host" ? facts.nonce : facts.request;
    const ends = [facts.not_after_ms, ...(role === "app" ? [facts.account_session_expires_ms] : [])].filter((v) => Number.isSafeInteger(v));
    if (ends.length) {
      const until = Math.min(...ends) - this.wallNow();
      if (until <= 0) { this.close(slot, CODES.revoked, "expired"); refuse("grant_expired", 403); }
      this.#timer(slot, until, () => this.close(slot, CODES.revoked, "expired"));
    }
    this.log({ event: "open", role, fleet: slot.fleet, agent: slot.agent, session: slot.session, resume_n: slot.resume_n });
    return {
      attach: (ws) => this.#attach(side, ws),
      abort: () => { if (!side.ws) this.close(slot, CODES.ended, "the upgrade didn't complete"); },
    };
  }

  #timer(slot, ms, f) {
    const h = this.clock.setTimeout(() => { slot.timers.delete(h); f(); }, ms);
    slot.timers.add(h);
    return h;
  }

  #attach(side, ws) {
    const slot = side.slot;
    if (!this.slots.has(slot.id) || slot[side.role] !== side) { ws.close(CODES.ended, "closed"); return; }
    side.ws = ws;
    ws.on("message", (data, isBinary) => this.#message(side, data, isBinary));
    ws.on("close", () => this.close(slot, CODES.ended, "closed by an end"));
    ws.on("error", () => this.close(slot, CODES.ended, "socket error"));
  }

  #message(side, data, isBinary) {
    const slot = side.slot;
    if (!this.slots.has(slot.id)) return;
    if (!isBinary) return this.close(slot, CODES.binaryOnly, "binary only");
    const peer = slot[side.role === "host" ? "app" : "host"];
    if (slot.state === "candidate") {
      const expect = slot.handshake === 0 ? "app" : slot.handshake === 1 ? "host" : null;
      if (expect !== side.role || !peer?.ws) return this.close(slot, CODES.handshake, "outside the handshake");
      slot.handshake++;
    }
    if (!peer?.ws) return this.close(slot, CODES.handshake, "no peer");
    const buf = Buffer.isBuffer(data) ? data : Buffer.concat(Array.isArray(data) ? data : [Buffer.from(data)]);
    if (peer.ws.bufferedAmount + buf.length > this.limits.queueMax) return this.close(slot, CODES.tooLarge, "queue over 1 MiB");
    side.bytes += buf.length;
    peer.ws.send(buf, { binary: true }, () => this.#progress(peer));
    this.#progress(peer);
  }

  // The no-progress stall (§4): one deadline per socket while bytes are queued.
  #progress(side) {
    const slot = side.slot, q = side.queued;
    if (!this.slots.has(slot.id) || !side.ws) return;
    const b = side.ws.bufferedAmount;
    if (b === 0) { this.#stopStall(side); return; }
    if (q.timer === null) { q.last = b; this.#armStall(side); this.#poll(side); return; }
    // (every observed value is recorded: a decrease from the last one is progress, even after growth above an older low)
    if (b < q.last) { this.clock.clearTimeout(q.timer); slot.timers.delete(q.timer); this.#armStall(side); }
    q.last = b;
  }
  #armStall(side) { side.queued.timer = this.#timer(side.slot, this.limits.stallMs, () => { side.queued.timer = null; this.close(side.slot, CODES.stalled, "no progress"); }); }
  #poll(side) { side.queued.poll = this.#timer(side.slot, this.limits.pollMs, () => { side.queued.poll = null; this.#progress(side); if (side.queued.timer !== null && side.queued.poll === null) this.#poll(side); }); }
  #stopStall(side) {
    const q = side.queued;
    for (const k of ["timer", "poll"]) if (q[k] !== null) { this.clock.clearTimeout(q[k]); side.slot.timers.delete(q[k]); q[k] = null; }
  }

  /**
   * A verified commit (the Worker's facts; its authorization already consumed): switch the named candidate pair, once.
   * Throws RelayRefusal("not_found") if nothing matches.
   */
  commit(c) {
    const slot = this.match(c);
    if (!slot) refuse("not_found", 404);
    for (const other of [...this.slots.values()]) {
      if (other === slot || agentKey(other) !== agentKey(slot)) continue;
      if (other.state === "active" || other.key === slot.key || other.browser_gen < slot.browser_gen) this.close(other, CODES.replaced, "replaced");
    }
    slot.state = "active";
    this.clock.clearTimeout(slot.pending);
    slot.timers.delete(slot.pending);
    this.log({ event: "commit", fleet: slot.fleet, agent: slot.agent, session: slot.session, resume_n: slot.resume_n });
  }

  /** The candidate pair a commit names, by full tuple, resume_n, the signer's host_gen and its two opens, or null. */
  match(c) {
    return [...this.slots.values()].find((s) => s.state === "candidate" && s.key === tupleKey(c) && s.resume_n === c.resume_n
      && s.host_gen === c.host_gen && s.ids.host === c.host_nonce && s.ids.app === c.app_request && s.host?.ws && s.app?.ws) ?? null;
  }

  /** The feed reports a change for an agent, an account or a host: close every slot it touches (§5: no re-admission). */
  revoke(kind, id) {
    for (const s of [...this.slots.values()]) {
      const hit = kind === "agent" ? s.agent === id : kind === "host" ? s.hostId === id : [s.host, s.app].some((side) => side?.account === id);
      if (hit) this.close(s, CODES.revoked, "revoked");
    }
  }

  /** Close every slot (the feed's fail-close, or shutdown). */
  closeAll(code, why) { for (const s of [...this.slots.values()]) this.close(s, code, why); }

  /** Close a slot: both sockets, every timer; idempotent. */
  close(slot, code, why) {
    if (!this.slots.has(slot.id)) return;
    this.slots.delete(slot.id);
    for (const h of slot.timers) this.clock.clearTimeout(h);
    slot.timers.clear();
    for (const side of [slot.host, slot.app]) {
      if (!side) continue;
      side.queued.timer = side.queued.poll = null;
      if (side.ws && side.ws.readyState <= 1) { try { side.ws.close(code, why); } catch { side.ws.terminate?.(); } }
    }
    this.log({ event: "close", fleet: slot.fleet, agent: slot.agent, session: slot.session, resume_n: slot.resume_n, code, why,
      host_bytes: slot.host?.bytes ?? 0, app_bytes: slot.app?.bytes ?? 0 });
  }
}
