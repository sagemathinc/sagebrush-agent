// Host supervisor (design: agent-autonomous-host-daemon r2.5 §5, §6): the chain sync. Fetching runs OUTSIDE the
// executor's queue and builds an immutable CANDIDATE state; adoption is the executor's `chain-adopt` emergency op, which
// calls the adopter here (chainAdopter) to judge the candidate and commit it.
//
// - Fetch (§6.1): GET /api/fleet/v1/host/chain?after=<pin.seq>, a §5.1 request signed with the host key (agent, cap,
//   idem, op "-"), at gen = the host store's durable highwater, or 1 when no grant was ever accepted (the route's own
//   floor; never derived from the certificate). HTTPS only, no redirects, one absolute deadline with the monotonic checks
//   at arrival and at acceptance, the body streamed and capped at CHAIN_PAGE_BYTES, parsed by core's parseChainPage.
// - Candidate: the page's entries applied in order from the current snapshot into a NEW state; the first entry that
//   fails stops the page, and the candidate is the last good state (a valid prefix, its narrowing included). A page
//   with no entries and a head below the pin is chain_fork: never adopted, counted for health.
// - The snapshot (§6.3): one immutable state object; replaced only by the adopter's commit, after the pin's durable
//   write. Every verifier reads it once per call (snapshot()).
// - When: sync() at start, on onChainBehind, and hourly; coalesced (one sync at a time).

import { randomBytes } from "node:crypto";
import { isId, refuse } from "../bytes.mjs";
import { applyChainEntry } from "../index.mjs";
import { signRequest } from "../request.mjs";
import { CHAIN_PAGE_BYTES, chainTarget, parseChainPage } from "../core/chain-service.mjs";
import { adoptWrite, markRevoked, verifyCertFor } from "./identity.mjs";

/** One page fetch's ABSOLUTE deadline. */
export const SYNC_MS = 15000;
/** The periodic sync. */
export const SYNC_EVERY_MS = 3_600_000;
/** Health classes. */
export const SYNC_CLASSES = Object.freeze(["ok", "status", "redirect", "oversize", "timeout", "network", "bad_page", "bad_entry", "chain_fork", "adopted", "not_adopted"]);

const isRedirect = (e) => /redirect/i.test(String(e?.message ?? "")) || /redirect/i.test(String(e?.cause?.message ?? ""));

/** Read a body as a stream within `max` bytes; past it: { cls: "oversize" }, the stream cancelled. */
async function readCapped(res, max, hold) {
  if (!res.body) return new Uint8Array(0);
  const reader = res.body.getReader();
  hold.reader = reader;
  const parts = [];
  let n = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    n += value.length;
    if (n > max) { try { await reader.cancel(); } catch { /* gone */ } throw Object.assign(new Error("oversize"), { cls: "oversize" }); }
    parts.push(value);
  }
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

/**
 * One bounded GET (the lease client's transport, for a read): no redirect, an absolute deadline that also holds when
 * fetch or the stream ignores its abort, the deadline re-checked on the monotonic clock when the response arrives and
 * before it is accepted, the body streamed and capped, an unread or late body released. Resolves { bytes } or { cls }.
 * `errorMax` (> 0): a non-200 answer's body is read too, within errorMax bytes, as { cls: "status", status, bytes }
 * (the grant reader's refusal codes); past errorMax it is { cls: "status", status } alone.
 */
export async function boundedGet(fetch, url, headers, { max, ms, mono = () => performance.now(), errorMax = 0 }) {
  const t0 = mono();
  const ac = new AbortController();
  let res = null, timer, dead = false;
  const hold = { reader: null };
  const release = () => {
    if (hold.reader) hold.reader.cancel().catch(() => {});
    else if (res?.body && !res.body.locked) res.body.cancel().catch(() => {});
  };
  const deadline = new Promise((resolve) => { timer = setTimeout(() => { dead = true; ac.abort(); resolve("timeout"); }, ms); });
  const exchange = (async () => {
    res = await fetch(url, { method: "GET", redirect: "error", signal: ac.signal, headers });
    if (dead || mono() - t0 >= ms) { release(); return "timeout"; }
    if (res.redirected || res.type === "opaqueredirect" || (res.status >= 300 && res.status < 400)) return "redirect";
    if (res.status !== 200) {
      if (!(errorMax > 0)) return "status";
      const status = res.status;
      const b = await readCapped(res, errorMax, hold).catch(() => null);
      return { status, bytes: b };
    }
    return readCapped(res, max, hold);
  })().catch((e) => (e?.cls === "oversize" ? "oversize" : ac.signal.aborted ? "timeout" : isRedirect(e) ? "redirect" : "network"));
  try {
    let r = await Promise.race([exchange, deadline]);
    if (r !== "timeout" && mono() - t0 >= ms) r = "timeout";
    if (r !== null && typeof r === "object" && !(r instanceof Uint8Array)) return { cls: "status", status: r.status, ...(r.bytes ? { bytes: r.bytes } : {}) };
    return r instanceof Uint8Array ? { bytes: r } : { cls: r };
  } finally {
    clearTimeout(timer);
    release();
  }
}

/** Apply `entries` in order from `state`; the first that fails stops. Resolves { state, entries } (the applied prefix). */
export async function buildCandidate(state, entries, ctx) {
  let s = state;
  const ok = [];
  for (const e of entries) {
    try { s = (await applyChainEntry(s, e, ctx)).state; } catch { break; }
    ok.push(e);
  }
  return { state: s, entries: ok };
}

export class ChainSync {
  #snap; #running = null; #timer = null; #life = 0;
  #counts = Object.fromEntries(SYNC_CLASSES.map((k) => [k, 0]));

  /**
   * `snapshot`: the pinned chain state now (classify's PAIRED chain). `aud`, `fleet`: the pin's. `host`: the
   * certificate's body.host; `signer`: the host's signing key (keyFromSeed's). `gen()`: the host store's durable
   * highwater (0 before any grant). `submit(op)`: the executor's. `origin`: the service (https only). Test seams:
   * { fetch, wall, mono, ms, timers, nonce }.
   */
  constructor({ snapshot, aud, fleet, host, signer, gen, submit, origin, fetch = globalThis.fetch, wall = Date.now, mono, ms = SYNC_MS,
    timers = { set: (t, fn) => { const h = setTimeout(fn, t); h.unref?.(); return h; }, clear: (h) => clearTimeout(h) }, nonce = () => randomBytes(16).toString("base64url") }) {
    if (!snapshot || !isId(fleet) || !isId(host) || typeof gen !== "function" || typeof submit !== "function" || typeof signer?.sign !== "function") refuse("bad_form", "chain sync: its parts are required");
    const u = new URL(origin);
    if (u.protocol !== "https:" || u.username || u.password || (u.pathname !== "/" && u.pathname !== "") || u.search || u.hash) refuse("bad_form", "chain sync: the origin must be https://host[:port] only");
    this.#snap = snapshot;
    Object.assign(this, { aud, fleet, host, signer, gen, submit, origin: u.origin, fetch, wall, mono, ms, timers, nonce });
  }

  /** The pinned chain state now: one immutable object, read once per verifier call. */
  snapshot() { return this.#snap; }

  /** Health counts (fixed numeric classes). */
  get counts() { return { ...this.#counts }; }

  /** Replace the snapshot: only the adopter's commit calls this, after the durable pin write. */
  swap(state) {
    if (!state || state.seq <= this.#snap.seq) refuse("bad_form", "chain sync: a swap must move forward");
    this.#snap = state;
  }

  /** One sync, coalesced: while one runs, a second call gets the same promise. */
  sync() {
    if (this.#running) return this.#running;
    this.#running = this.#syncOnce().finally(() => { this.#running = null; });
    return this.#running;
  }

  /**
   * The hourly sync; the first after `first` ms (now, by default). Each start begins a new lifetime and stop() ends it,
   * so a sync still running when stop() (or a later start()) is called never arms another timer for the old one.
   */
  start({ first = 0 } = {}) { this.#arm(++this.#life, first); }
  stop() { this.#life += 1; this.#clear(); }
  #clear() { if (this.#timer) this.timers.clear(this.#timer); this.#timer = null; }
  #arm(life, ms) {
    this.#clear();
    this.#timer = this.timers.set(ms, () => {
      this.#timer = null;
      this.sync().catch(() => {}).finally(() => { if (life === this.#life) this.#arm(life, SYNC_EVERY_MS); });
    });
  }

  async #fetchPage(after) {
    const target = chainTarget(after);
    const header = signRequest({ aud: this.aud, method: "GET", target, host: this.host, key: this.signer,
      fields: { gen: Math.max(1, this.gen()), ts: this.wall(), nonce: this.nonce() } });
    const r = await boundedGet(this.fetch, `${this.origin}${target}`, { "sagebrush-sig": header }, { max: CHAIN_PAGE_BYTES, ms: this.ms, ...(this.mono ? { mono: this.mono } : {}) });
    if (!r.bytes) { this.#counts[r.cls]++; return null; }
    try { const p = parseChainPage(r.bytes, after); this.#counts.ok++; return p; } catch { this.#counts.bad_page++; return null; }
  }

  async #syncOnce() {
    for (;;) {
      const snap = this.#snap, after = snap.seq;
      const page = await this.#fetchPage(after);
      if (page === null) return { status: "failed" };
      if (page.entries.length === 0) {
        if (page.head < after) { this.#counts.chain_fork++; return { status: "chain_fork" }; }
        return { status: "current" };
      }
      const cand = await buildCandidate(snap, page.entries, { aud: this.aud, fleet: this.fleet });
      if (cand.entries.length === 0) { this.#counts.bad_entry++; return { status: "bad_entry" }; }
      const r = await this.submit({ kind: "chain-adopt", authority: "host", candidate: Object.freeze({ state: cand.state, entries: cand.entries, fromSeq: after + 1 }) });
      if (!r || !["adopted", "expired"].includes(r.status)) { this.#counts.not_adopted++; return { status: "not_adopted", result: r }; }
      this.#counts.adopted++;
      // A bad entry stopped the page: the prefix is adopted, nothing after it, and no further page this time.
      if (cand.entries.length < page.entries.length) { this.#counts.bad_entry++; return { status: "prefix" }; }
      if (cand.state.seq >= page.head) return { status: "current" };
    }
  }
}

/**
 * The executor's `chain` seam (§6.2): judge a candidate and commit it. `paths`, `certBytes`, `keys`, `pin` (fleet, aud)
 * and the sync come from the daemon; `grantValidAt(state, bytes, now)` re-verifies the accepted grant against a chain
 * state with a FRESH clock sample (verifyGrant with resolveKey over that state). commit() writes the entries, then the
 * pin, durably, and only then swaps the snapshot.
 */
export function chainAdopter({ paths, certBytes, keys, pin, sync, grantValidAt, now = Date.now, io, rootUid = 0 }) {
  return Object.freeze({
    certValid: async (state) => { try { await verifyCertFor(certBytes, keys, pin, state); return true; } catch { return false; } },
    grantValid: async (state, bytes) => { try { await grantValidAt(state, bytes, now()); return true; } catch { return false; } },
    markRevoked: () => markRevoked(paths, io ? { io } : {}),
    commit: (cand) => {
      adoptWrite(paths, cand.entries, cand.fromSeq, { fleet: pin.fleet, aud: pin.aud, seq: cand.state.seq, hash: cand.state.head }, { rootUid, ...(io ? { io } : {}) });
      sync.swap(cand.state);
    },
  });
}
