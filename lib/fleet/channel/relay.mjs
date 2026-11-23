// The browser channel's relay admission (design agent-autonomous-browser-channel.md r4 §5): the two authenticated
// opens' exact form and their verifier (auth's; the live relay service, space's, calls it), the replacement
// authorization a broker sends after its durable compare-and-set, and a fake relay that implements §5.4 exactly, for
// tests and for building the host end before the live relay exists.

import { b64, canonText, enc, isId, refuse, unb64 } from "../index.mjs";
import { openByDevice } from "../core/verify.mjs";
import { signRequest, verifyRequest } from "../request.mjs";
import { MAX_MESSAGE } from "./noise.mjs";

export const ROUTE = "/api/fleet/v1/relay/browser";
export const COMMIT_ROUTE = `${ROUTE}/commit`;
export const RECORD_HEADER_MAX = 87252; // (the 65,439-byte record, base64url: ceil(65439 * 4 / 3))
export const HEADERS_MAX = 98304;       // (the whole header block, at the first parser)
const QUERY = ["role", "fleet", "session", "agent", "browser_gen", "host_gen", "resume_n"];
const COUNT = /^(0|[1-9][0-9]{0,15})$/;
const B22 = /^[A-Za-z0-9_-]{21}[AQgw]$/;
const B64 = /^[A-Za-z0-9_-]*$/;
const EMPTY = new Uint8Array(0);

/** The open's request target for these fields, in the one fixed order. */
export function openTarget(f) {
  return `${ROUTE}?${QUERY.map((k) => `${k}=${f[k]}`).join("&")}`;
}

/** The fields of an open's request target: exactly the route and its seven query fields, in order, each in its form. */
export function parseOpenTarget(target) {
  if (typeof target !== "string" || target.length > 512 || !target.startsWith(`${ROUTE}?`)) refuse("bad_form", "not the relay's route");
  const parts = target.slice(ROUTE.length + 1).split("&");
  if (parts.length !== QUERY.length) refuse("bad_form", "the relay route takes exactly its seven fields");
  const f = {};
  parts.forEach((p, i) => {
    const eq = p.indexOf("=");
    if (eq < 1 || p.slice(0, eq) !== QUERY[i]) refuse("bad_form", "a relay field out of place");
    f[QUERY[i]] = p.slice(eq + 1);
  });
  if (f.role !== "host" && f.role !== "app") refuse("bad_form", "the role is host or app");
  for (const k of ["fleet", "session", "agent"]) if (!isId(f[k])) refuse("bad_form", `${k} isn't an id`);
  for (const k of ["browser_gen", "host_gen", "resume_n"]) {
    if (!COUNT.test(f[k]) || !Number.isSafeInteger(Number(f[k]))) refuse("bad_form", `${k} isn't an exact count`);
    f[k] = Number(f[k]);
  }
  if (f.browser_gen < 1 || f.host_gen < 1) refuse("bad_form", "generations start at 1");
  return f;
}

/** The headers' total size as the first parser counts it (names, values, ": " and CRLF). */
export const headerBytes = (headers) => Object.entries(headers).reduce((n, [k, v]) => n + Buffer.byteLength(k) + Buffer.byteLength(String(v)) + 4, 0);

/**
 * The host's open (§5.2): an O6 §5.1-signed upgrade. ctx: verifyRequest's ({ aud, now, hostKey, currentGen,
 * consumeNonce }) and agentHasBrowser(host, agent). Returns the open's identity.
 */
export function verifyHostOpen({ target, headers }, ctx) {
  if (headerBytes(headers) > HEADERS_MAX) refuse("limit", "the request's headers");
  const f = parseOpenTarget(target);
  if (f.role !== "host") refuse("bad_form", "not a host open");
  const sig = verifyRequest({ header: headers["sagebrush-sig"], method: "GET", target, body: EMPTY }, ctx);
  if (sig.agent !== "-" || sig.cap !== "-" || sig.idem !== "-") refuse("bad_form", "a host operation carries no agent, capability or idem");
  if (Number(sig.gen) !== f.host_gen) refuse("stale_generation", "the signature's gen isn't the open's host_gen");
  if (!ctx.agentHasBrowser(sig.host, f.agent)) refuse("not_granted", "the agent has no browser in the current grant");
  return Object.freeze({ ...f, host: sig.host, nonce: sig.nonce });
}

/**
 * The app's open (§5.3). ctx: { aud, now, accountFleets() -> ids (the session's own account), chainOf(fleet) -> the
 * fleet's chain state, currentGen(host), consumeRequest(id) -> true if new }. Returns the open's identity.
 */
export async function verifyAppOpen({ target, headers }, ctx) {
  if (headerBytes(headers) > HEADERS_MAX) refuse("limit", "the request's headers");
  const rec = headers["sagebrush-browser-record"], id = headers["sagebrush-request"];
  if (typeof rec !== "string" || rec.length > RECORD_HEADER_MAX) refuse("limit", "the record header");
  if (!B64.test(rec)) refuse("bad_form", "the record header isn't base64url");
  if (typeof id !== "string" || !B22.test(id)) refuse("bad_form", "the request id");
  const f = parseOpenTarget(target);
  if (f.role !== "app") refuse("bad_form", "not an app open");
  if (!ctx.accountFleets().includes(f.fleet)) refuse("not_granted", "another account's fleet");
  const env = await openByDevice(unb64(rec), { aud: ctx.aud, fleet: f.fleet, chain: ctx.chainOf(f.fleet) }, "sb.browser-session.v1", "browser-session");
  const r = env.body;
  for (const k of ["fleet", "session", "agent", "browser_gen", "host_gen"]) if (r[k] !== f[k]) refuse("bad_form", `the record's ${k} isn't the open's`);
  if (ctx.now < r.not_before_ms || ctx.now >= r.not_after_ms) refuse("grant_expired", "outside the record's window");
  if (ctx.currentGen(r.host) !== f.host_gen) refuse("stale_generation");
  if (!ctx.consumeRequest(id)) refuse("replay", "this request id was used");
  return Object.freeze({ ...f, host: r.host, request: id, not_after_ms: r.not_after_ms, signer: env.signer.id });
}

// ---- the replacement authorization (§5.4): the broker, after its compare-and-set, names one candidate pair

const commitBody = (c) => enc(canonText({ fleet: c.fleet, session: c.session, agent: c.agent, browser_gen: c.browser_gen, resume_n: c.resume_n, host_nonce: c.host_nonce, app_request: c.app_request }));

/** The broker's side: { header, body } for POST COMMIT_ROUTE. */
export function signCommit(c, { aud, host, key, gen, ts, nonce }) {
  const body = commitBody(c);
  return { header: signRequest({ aud, method: "POST", target: COMMIT_ROUTE, body, host, key, fields: { gen, ts, nonce } }), body };
}

/** The relay's side: verify an authorization and return what it names. ctx as verifyRequest's. */
export function verifyCommit({ header, body }, ctx) {
  const sig = verifyRequest({ header, method: "POST", target: COMMIT_ROUTE, body }, ctx);
  let c;
  try { c = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(body)); } catch { refuse("bad_form", "the authorization's body"); }
  if (b64(commitBody(c)) !== b64(body)) refuse("bad_form", "the authorization's body isn't canonical");
  return Object.freeze({ ...c, host: sig.host, gen: Number(sig.gen) });
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
