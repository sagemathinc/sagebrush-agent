// Host supervisor: the host-local records a moved agent's resume is checked against (schemas r2.4 §3.7.3 checks 4-6,
// the first-lease rule's condition 4), read by checkTransferForHost through hostRecords() below. All of them are this
// host's own: never restored or imported, and never compared with another host's (§3.7.1).
//
// - Per agent, from the grant state (grant.mjs): entry_gen, listed_since, and each accepted grant's digest by gen.
// - Here, transfers.json: per agent, the transfer this host accepted for it ({ gen, nonce, transfer }), and every
//   transfer nonce it has ever accepted (nonce -> the transfer's SHA-256), kept after the agent is dropped. An accepted
//   transfer counts only while the agent's current listing began at or before its gen (check 5b made it so when it was
//   accepted): one from an earlier listing, before a drop, is never the agent's accepted transfer again.
//
//   { v: 1, accepted: { <agent>: { gen, nonce, transfer } }, nonces: { <nonce>: <transfer> } }
//
// A transfer is recorded by the supervisor's resume gate when checkTransferForHost says it is a first acceptance
// (first: true), durably, BEFORE anything acts on it. recordTransfer refuses what a first acceptance can't be, as a
// second line: an agent the accepted grant doesn't list, a generation not above the agent's accepted one, a nonce
// already used by another transfer. The same transfer again is a no-op (a retry). Reads happen in the supervisor only:
// the host store is single-writer, and its lock is the supervisor's.

import { isId, refuse } from "../bytes.mjs";
import { DurableState, exactKeys, realIo } from "./store.mjs";

const FILE = "transfers.json";
const HASH = /^[A-Za-z0-9_-]{43}$/;
const NONCE = /^[A-Za-z0-9_-]{22}$/;
/** Nonces kept: one per transfer this host ever accepted. Past this the host refuses further transfers. */
export const MAX_NONCES = 100_000;
const MAX_AGENTS = 4096;
const empty = () => ({ v: 1, accepted: {}, nonces: {} });
const isMap = (o) => o !== null && typeof o === "object" && !Array.isArray(o);
const isTransfer = (t) => exactKeys(t, ["gen", "nonce", "transfer"]) && Number.isSafeInteger(t.gen) && t.gen >= 1
  && typeof t.nonce === "string" && NONCE.test(t.nonce) && typeof t.transfer === "string" && HASH.test(t.transfer);

/** The closed shape (refuses anything else, with bad_form). Every accepted transfer's nonce is among the nonces. */
export function checkTransfers(r) {
  const bad = () => refuse("bad_form", "transfer records: corrupt");
  if (!exactKeys(r, ["v", "accepted", "nonces"]) || r.v !== 1 || !isMap(r.accepted) || !isMap(r.nonces)) bad();
  if (Object.keys(r.accepted).length > MAX_AGENTS || Object.keys(r.nonces).length > MAX_NONCES) bad();
  for (const [n, h] of Object.entries(r.nonces)) if (!NONCE.test(n) || typeof h !== "string" || !HASH.test(h)) bad();
  for (const [id, t] of Object.entries(r.accepted)) {
    if (!isId(id) || !isTransfer(t) || r.nonces[t.nonce] !== t.transfer) bad();
  }
  return true;
}

export class TransferRecords {
  #s;

  /** A view of the records in `dir`, under the host store's lock (host-store.mjs); it never locks by itself. */
  static attach(dir, lock, { io = realIo } = {}) {
    const t = new TransferRecords();
    t.#s = DurableState.attach(dir, FILE, { check: checkTransfers, initial: empty, io, lock });
    return t;
  }

  /**
   * The transfer accepted for `agent` ({ gen, nonce, transfer }) in its current listing, or null. `listedSince(id)` is
   * the accepted grant's listed_since, null when it doesn't list the agent.
   */
  accepted(agent, listedSince) {
    const a = this.#s.get().accepted, since = listedSince(agent);
    return since !== null && Object.hasOwn(a, agent) && a[agent].gen >= since ? a[agent] : null;
  }

  /** The transfer hash that used `nonce` here, or null. */
  nonce(n) { const m = this.#s.get().nonces; return typeof n === "string" && Object.hasOwn(m, n) ? m[n] : null; }

  /**
   * Record `t` ({ gen, nonce, transfer }) as `agent`'s accepted transfer, durably. `listedSince` as for accepted();
   * entries that no longer count (the agent not listed, or listed again since) are pruned; nonces stay. Refuses: not
   * listed since t.gen (not_granted); gen not above the agent's accepted one (stale_generation); a nonce another
   * transfer used (replay); the nonce store full (limit). The same transfer again changes nothing.
   */
  record(agent, t, listedSince) {
    if (!isId(agent) || !isTransfer(t)) refuse("bad_form", "transfer records: bad transfer");
    const since = listedSince(agent);
    if (since === null || since > t.gen) refuse("not_granted", "transfer records: the agent isn't listed since that generation");
    const cur = this.accepted(agent, listedSince);
    if (cur && cur.gen === t.gen && cur.nonce === t.nonce && cur.transfer === t.transfer) return;
    if (cur && t.gen <= cur.gen) refuse("stale_generation", "transfer records: not above the accepted transfer");
    const used = this.nonce(t.nonce);
    if (used !== null && used !== t.transfer) refuse("replay", "transfer records: the nonce was used");
    this.#s.commit((r) => {
      if (!Object.hasOwn(r.nonces, t.nonce) && Object.keys(r.nonces).length >= MAX_NONCES) refuse("limit", "transfer records: full");
      // Entries that no longer count (the agent dropped, or listed again since) go; their nonces stay.
      for (const [id, a] of Object.entries(r.accepted)) {
        const s = listedSince(id);
        if (s === null || a.gen < s) delete r.accepted[id];
      }
      r.accepted[agent] = { gen: t.gen, nonce: t.nonce, transfer: t.transfer };
      r.nonces[t.nonce] = t.transfer;
    });
  }
}

/**
 * The read interface checkTransferForHost and the first-lease rule use, over an open host store. `id` is this
 * host's id, `fingerprint` its own certificate's (both from the host's config, as the grant check uses them).
 * Synchronous; the supervisor's process only.
 */
export function hostRecords(store, { id, fingerprint }) {
  const g = store.grants;
  const rec = (agent) => (isId(agent) ? g.record(agent) : null);
  return Object.freeze({
    id,
    fingerprint,
    /**
     * The hash (base64url SHA-256 of the SIGNED bytes) of the grant this host accepted at `gen`, or null: the value a
     * transfer's `grant` carries (§3.7.2), never the envelope's digest.
     */
    grantHashAt: (gen) => g.hashAt(gen),
    /**
     * Whether the grant accepted at `gen` lists `agent`. Derived: listed_since <= gen <= the accepted generation. It is
     * exact because an agent's listed generations are one interval: a grant that drops it deletes its record, and the
     * registry never takes its id again.
     */
    grantListsAgent: (gen, agent) => {
      const r = rec(agent);
      return r !== null && Number.isSafeInteger(gen) && r.listed_since <= gen && gen <= g.highwater.gen;
    },
    listedSince: (agent) => rec(agent)?.listed_since ?? null,
    entryGen: (agent) => rec(agent)?.entry_gen ?? null,
    /** The transfer accepted for `agent` in its current listing, or null. */
    acceptedTransfer: (agent) => store.transfers.accepted(agent, (id) => rec(id)?.listed_since ?? null),
    nonceSeen: (nonce) => store.transfers.nonce(nonce),
    /**
     * The writer, bound to this store: recordTransfer below (the resume gate's, after checkTransferForHost). SYNCHRONOUS
     * on purpose: the gate launches the helper right after it, without awaiting, so the record must already be durable
     * when it returns. Never make it async.
     */
    recordTransfer: (agent, t) => recordTransfer(store, agent, t),
  });
}

/**
 * hostRecords for this host as its verified certificate names it (verifyHostCert's result): `id` is the certificate's
 * `host` and `fingerprint` its `fingerprint` field, the string the person compared and a transfer's to_host_key carries.
 */
export function hostRecordsFromCert(store, cert) {
  if (!isId(cert?.body?.host) || typeof cert.body.fingerprint !== "string") refuse("bad_form", "host records: not a verified certificate");
  return hostRecords(store, { id: cert.body.host, fingerprint: cert.body.fingerprint });
}

/**
 * Record `agent`'s first-accepted transfer (checkTransferForHost said first: true), before anything acts on it.
 * Synchronous: the record is durable when this returns (the resume gate relies on it; see hostRecords).
 */
export function recordTransfer(store, agent, t) {
  store.transfers.record(agent, t, (id) => (isId(id) ? store.grants.record(id)?.listed_since ?? null : null));
}
