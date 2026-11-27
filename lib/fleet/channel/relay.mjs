// The browser channel's relay admission (design agent-autonomous-browser-channel.md r4 §5): the two authenticated
// opens' exact form and their verifier (auth's; the live relay service, space's, calls it), the replacement
// authorization a broker sends after its durable compare-and-set, and a fake relay that implements §5.4 exactly, for
// tests and for building the host end before the live relay exists. The forms and the post-signature checks are
// core/relay.mjs's; this face is synchronous where it can be and consumes nonces and request ids through its ctx.

import { refuse, unb64 } from "../index.mjs";
import { openByDevice } from "../core/verify.mjs";
import {
  APP_TOKEN, APP_TOKEN_MS, APP_TOKEN_ROUTE, COMMIT_ROUTE, HEADERS_MAX, RECORD_HEADER_MAX, ROUTE, appHeaders, appRecord, appTokenKey,
  appTokenRequest, checkAppTokenRow, checkHostSig, commitBody, headerBytes, openTarget, parseAppTokenRequest, parseCommit, parseOpenTarget,
} from "../core/relay.mjs";
import { b64, random } from "../core/bytes.mjs";
import { signRequest, verifyRequest } from "../request.mjs";
import { MAX_MESSAGE } from "./noise.mjs";

// (the forms are core/relay.mjs's, one source with the async verifiers a Worker runs)
export {
  APP_TOKEN, APP_TOKEN_MS, APP_TOKEN_ROUTE, COMMIT_ROUTE, HEADERS_MAX, RECORD_HEADER_MAX, ROUTE, appTokenKey, appTokenRequest, headerBytes, openTarget,
  parseAppTokenRequest, parseOpenTarget,
};
const EMPTY = new Uint8Array(0);

/**
 * The host's open (§5.2): an O6 §5.1-signed upgrade. ctx: verifyRequest's ({ aud, now, hostKey, currentGen,
 * consumeNonce }) and agentHasBrowser(host, agent). Returns the open's identity.
 */
export function verifyHostOpen({ target, headers }, ctx) {
  if (headerBytes(headers) > HEADERS_MAX) refuse("limit", "the request's headers");
  const f = parseOpenTarget(target);
  if (f.role !== "host") refuse("bad_form", "not a host open");
  const sig = verifyRequest({ header: headers["sagebrush-sig"], method: "GET", target, body: EMPTY }, ctx);
  checkHostSig(sig, f);
  if (!ctx.agentHasBrowser(sig.host, f.agent)) refuse("not_granted", "the agent has no browser in the current grant");
  return Object.freeze({ ...f, host: sig.host, nonce: sig.nonce });
}

/**
 * The app's open (§5.3 as addendum A1 amends it). ctx: { aud, now, consumeAppToken(key) -> the row taken and deleted,
 * or null (AppTokens.consume); sessionLive(account, account_session) -> true if live now; chainOf(fleet) -> the
 * fleet's chain state; currentGen(host); consumeRequest(id) -> true if new }. Returns the open's identity.
 */
export async function verifyAppOpen({ target, headers }, ctx) {
  if (headerBytes(headers) > HEADERS_MAX) refuse("limit", "the request's headers");
  const { token, rec, id } = appHeaders(headers);
  const f = parseOpenTarget(target);
  if (f.role !== "app") refuse("bad_form", "not an app open");
  const row = await checkAppTokenRow(await ctx.consumeAppToken(await appTokenKey(token)), f, id, ctx);
  const env = await openByDevice(unb64(rec), { aud: ctx.aud, fleet: f.fleet, chain: ctx.chainOf(f.fleet) }, "sb.browser-session.v1", "browser-session");
  const opened = appRecord(env, f, id, ctx, row);
  if (!ctx.consumeRequest(id)) refuse("replay", "this request id was used");
  return Object.freeze(opened);
}

// ---- the replacement authorization (§5.4): the broker, after its compare-and-set, names one candidate pair

/** The broker's side: { header, body } for POST COMMIT_ROUTE. */
export function signCommit(c, { aud, host, key, gen, ts, nonce }) {
  const body = commitBody(c);
  return { header: signRequest({ aud, method: "POST", target: COMMIT_ROUTE, body, host, key, fields: { gen, ts, nonce } }), body };
}

/** The relay's side: verify an authorization and return what it names. ctx as verifyRequest's. */
export function verifyCommit({ header, body }, ctx) {
  const sig = verifyRequest({ header, method: "POST", target: COMMIT_ROUTE, body }, ctx);
  const c = parseCommit(body);
  return Object.freeze({ ...c, host: sig.host, gen: Number(sig.gen) });
}

// ---- the relay tokens' store (addendum A1 §2): what the fleet Worker keeps, in memory

/**
 * The service's token rows, keyed by appTokenKey(token): issue() after the issuer's checks of the account session,
 * fleet, host, host_gen and grant (the caller's); consume() takes and deletes a row in one step, so of two presentations
 * exactly one gets it; logout() deletes an account session's rows; sweep() those past their expiry. The token itself is
 * returned once, by issue(), and kept nowhere.
 */
export class AppTokens {
  constructor({ now = () => Date.now(), ms = APP_TOKEN_MS } = {}) { this.now = now; this.ms = ms; this.rows = new Map(); }
  /** { account, account_session, body (the request's bytes) } -> { token, expires_ms }. */
  async issue({ account, account_session, body }) {
    const binding = parseAppTokenRequest(body);
    const token = `rt1.${b64(random(32))}`;
    const expires_ms = this.now() + this.ms;
    this.rows.set(await appTokenKey(token), Object.freeze({ account, account_session, ...binding, expires_ms }));
    return { token, expires_ms };
  }
  consume(key) {
    const row = this.rows.get(key) ?? null;
    this.rows.delete(key);
    return row;
  }
  logout(account_session) { for (const [k, r] of [...this.rows]) if (r.account_session === account_session) this.rows.delete(k); }
  sweep() { for (const [k, r] of [...this.rows]) if (!(this.now() < r.expires_ms)) this.rows.delete(k); }
}

// ---- the fake relay: §5.4 in memory

const sameAgent = (a, b) => a.fleet === b.fleet && (a.hostId ?? a.host) === (b.hostId ?? b.host) && a.agent === b.agent;

/** One end of a fake WebSocket: binary messages only, at most 65,535 bytes each, a bounded queue. */
function socket(relay, side) {
  const s = {
    side, closed: false, code: null, onmessage: null, onclose: null, queued: 0,
    send(data) {
      if (s.closed) return;
      if (!(data instanceof Uint8Array)) return relay._close(side.slot, 1003, "binary only");
      if (data.length > MAX_MESSAGE) return relay._close(side.slot, 1009, "over 65,535 bytes");
      relay._forward(side, data);
    },
    close() { relay._close(side.slot, 1000, "closed by an end"); },
  };
  return s;
}

// (a slot's identity is the full authenticated tuple, never a bare (fleet, session): r4.1)
const tupleKey = (t) => `${t.fleet}/${t.host}/${t.agent}/${t.browser_gen}/${t.session}`;

/**
 * A relay that implements §5.4: per (fleet, host, agent, browser_gen, session), at most one active pair and one
 * candidate pair. Admitted opens
 * are candidates; a candidate pair passes only the handshake's two messages and never touches the active pair; a
 * verified replacement authorization switches the named candidate pair to active, once, and closes the agent's other
 * sockets. Bounds: one candidate pair per session, two per agent, 30 s to live, 1 MiB queued per direction.
 */
export class FakeRelay {
  constructor({ now = () => Date.now(), pendingMs = 30_000, queueMax = 1 << 20 } = {}) {
    this.now = now; this.pendingMs = pendingMs; this.queueMax = queueMax;
    this.slots = new Map(); // key -> { key, agent, browser_gen, resume_n, state: "candidate" | "active", host, app, born, handshake }
    this.consumed = new Set();
    this.log = [];
  }

  /** An admitted open (the verifier's result). Returns its socket, or refuses with a §5.4 code. */
  open(admitted) {
    this.sweep();
    const key = tupleKey(admitted);
    const sideName = admitted.role;
    let slot = [...this.slots.values()].find((s) => s.key === key && s.state === "candidate");
    if (slot) {
      if (slot.resume_n !== admitted.resume_n || slot.host_gen !== admitted.host_gen) refuse("in_progress", "another candidate for this session is pending");
      if (slot[sideName]) refuse("in_progress", `the ${sideName} side is taken`);
    } else {
      const pendingForAgent = [...this.slots.values()].filter((s) => s.state === "candidate" && sameAgent(s, admitted)).length;
      if (pendingForAgent >= 2) refuse("limit", "two candidates pending for this agent");
      // (the candidate's host and host_gen: the app's record names its host, the host's open is signed by it)
      slot = { key, id: `${key}#${admitted.resume_n}#${this.log.length}`, fleet: admitted.fleet, hostId: admitted.host, agent: admitted.agent,
        browser_gen: admitted.browser_gen, resume_n: admitted.resume_n, host_gen: admitted.host_gen, state: "candidate", host: null, app: null,
        born: this.now(), handshake: 0, ids: {} };
      this.slots.set(slot.id, slot);
    }
    const side = { slot, name: sideName, queued: 0 };
    const s = socket(this, side);
    slot[sideName] = s;
    slot.ids[sideName] = sideName === "host" ? admitted.nonce : admitted.request;
    this.log.push(`open ${sideName} ${key} r${admitted.resume_n}`);
    return s;
  }

  /** A verified replacement authorization (verifyCommit's result): switch the named candidate pair, once. */
  commit(c) {
    this.sweep();
    const tag = `${c.host}/${c.host_nonce}/${c.app_request}`;
    if (this.consumed.has(tag)) refuse("replay", "this authorization was used");
    // (the full tuple, the signer's own host included; its host_gen; its resume_n; and its own two opens)
    const slot = [...this.slots.values()].find((s) => s.state === "candidate" && s.key === tupleKey({ ...c, host: c.host }) && s.resume_n === c.resume_n
      && s.host_gen === c.gen && s.ids.host === c.host_nonce && s.ids.app === c.app_request && s.host && s.app);
    if (!slot) refuse("not_found", "no such candidate pair");
    this.consumed.add(tag);
    for (const other of [...this.slots.values()]) {
      if (other === slot || !sameAgent(other, slot)) continue;
      if (other.state === "active" || other.key === slot.key || other.browser_gen < slot.browser_gen) this._close(other, 4000, "replaced");
    }
    slot.state = "active";
    this.log.push(`commit ${slot.key} r${slot.resume_n}`);
  }

  /** The relay learns of a revocation, a newer host_gen, a removed signer or an expiry: close the agent's sockets. */
  revoke(agent, code = 4001) {
    for (const s of [...this.slots.values()]) if (s.agent === agent) this._close(s, code, "revoked");
  }

  /** The active pair for a full tuple { fleet, host, agent, browser_gen, session }, or null. */

  /** Expire candidates past their time. */
  sweep() {
    for (const s of [...this.slots.values()]) if (s.state === "candidate" && this.now() - s.born >= this.pendingMs) this._close(s, 4002, "expired");
  }

  active(t) { return [...this.slots.values()].find((s) => s.key === tupleKey(t) && s.state === "active") ?? null; }

  _forward(side, data) {
    const slot = side.slot;
    const peer = slot[side.name === "host" ? "app" : "host"];
    if (slot.state === "candidate") {
      // (a candidate pair passes only the handshake's two messages: app -> host, then host -> app)
      const expect = slot.handshake === 0 ? "app" : slot.handshake === 1 ? "host" : null;
      if (expect !== side.name || !peer) return this._close(slot, 1008, "outside the handshake");
      slot.handshake++;
    }
    if (!peer) return this._close(slot, 1008, "no peer");
    side.queued += data.length;
    if (side.queued > this.queueMax) return this._close(slot, 1009, "queue over 1 MiB");
    const copy = Uint8Array.from(data);
    queueMicrotask(() => { side.queued -= copy.length; if (!peer.closed) peer.onmessage?.(copy); });
  }

  _close(slot, code, why) {
    if (!this.slots.has(slot.id)) return;
    this.slots.delete(slot.id);
    this.log.push(`close ${slot.key} r${slot.resume_n} ${code} ${why}`);
    for (const s of [slot.host, slot.app]) if (s && !s.closed) { s.closed = true; s.code = code; queueMicrotask(() => s.onclose?.(code, why)); }
  }
}
