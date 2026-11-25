// Host supervisor (lease wire type r3 §2.3, §2.4; schemas r2.5 §3.8): the execution lease's real seams for the
// LeaseMachine (lease-machine.mjs): how a request is signed and sent, and against what a lease is verified. Pure: it
// holds no file and starts nothing; the host daemon builds it from the host's identity and its pinned chain.
//
// leaseDeps({ aud, fleet, signer, cert, chain, origin, fetch, onChainBehind }) → { sign, send, context, verify, counts }
// - cert: this host's verified certificate (verifyHostCert's result). Its body.host is the ONLY host id used, and its
//   body.fingerprint the host key a lease must name. The signer (keyFromSeed's { raw, key, sign }) must BE the certified
//   signing key: its raw key equals the certificate's, and its key id is that key's. Anything else refuses construction.
// - context(): { aud, fleet, chain: chain() (the host's OWN pinned chain state, read afresh at every call), host,
//   hostKey }. Never a chain the service hands over.
// - sign(body): the request, sealed by the host's key; its hash is the SHA-256 of the SIGNED bytes, never the envelope's.
// - send(bytes): POST to the service's lease route, HTTPS only, never following a redirect, within one deadline that
//   covers the connection AND the whole body read, the body read as a stream and refused past RESPONSE_MAX bytes (it is
//   never buffered whole first). 200: the bytes. Anything else: null (the machine's request stays as it was), counted
//   by class. A refusal's body is never read or trusted beyond its status.
// - verify(bytes, ctx): core's verifyExecutionLease. On device_unknown (the lease key rotated past the host's pinned
//   head) it asks for a chain sync (onChainBehind, coalesced: at most one outstanding ask) and STILL refuses: the same
//   bytes are never verified again, as their request is spent. A failing callback changes nothing.
// - counts: the health classes, a fixed set of numbers; nothing here keeps or reports request or lease bytes.

import { readFileSync } from "node:fs";
import { isId, refuse } from "../bytes.mjs";
import { canonText } from "../core/canonical.mjs";
import { keyId } from "../ed25519.mjs";
import { seal, signedBytes } from "../envelope.mjs";
import { sha256b64, verifyExecutionLease } from "../index.mjs";
import { LEASE_ROUTE } from "../core/lease-service.mjs";

/**
 * The largest response read: exactly the canonical size of the largest VALID sb.execution-lease.v1 envelope, derived
 * from the schema's bounds (every string field there has a fixed length; aud is its longest value; the integers at
 * their maxima). A real lease is never refused by it, and nothing larger is ever read.
 */
export const RESPONSE_MAX = (() => {
  const defs = JSON.parse(readFileSync(new URL("../../../schema/fleet/fleet.schema.json", import.meta.url), "utf8")).$defs;
  const props = defs["execution-lease"].properties;
  const len = (d) => { const p = d.$ref ? defs[d.$ref.split("/").pop()] : d; return p; };
  const id = "a".repeat(defs.id.maxLength), b32 = "A".repeat(43), b16 = "A".repeat(22);
  const body = {
    fleet: id, aud: len(props.aud).enum.reduce((a, b) => (b.length > a.length ? b : a)), agent: id, host: id, host_key: b32,
    gen: len(props.gen).maximum, lease_id: id, ttl_ms: props.ttl_ms.maximum, nonce: b16, boot_id: "0".repeat(36),
    request: b32, chain_seq: len(props.chain_seq).maximum,
  };
  const signer = { kind: "lease", id, alg: "ed25519", key: b16 };
  return canonText({ v: 1, type: "sb.execution-lease.v1", signer, body, sig: "A".repeat(86) }).length;
})();
/** One send's ABSOLUTE deadline: the connection, the status and the whole body, whether or not fetch heeds an abort. */
export const SEND_MS = 15000;
/** The health classes. */
export const SEND_CLASSES = Object.freeze(["ok", "status", "redirect", "oversize", "timeout", "network"]);

const sameBytes = (a, b) => a instanceof Uint8Array && b instanceof Uint8Array && a.length === b.length && a.every((x, i) => x === b[i]);

/** The service's origin: https, no credentials, path, query or fragment. Refuses anything else. */
function checkOrigin(origin) {
  let u;
  try { u = new URL(origin); } catch { refuse("bad_form", "lease client: not an origin"); }
  if (u.protocol !== "https:" || u.username || u.password || (u.pathname !== "/" && u.pathname !== "") || u.search || u.hash) {
    refuse("bad_form", "lease client: the origin must be https://host[:port] only");
  }
  return u.origin;
}

/**
 * Read a response body as a stream within `max` bytes; throws { cls: "oversize" } past it (cancelling the stream).
 * `hold.reader` is the stream's reader, for the caller to cancel if the deadline ends the read first.
 */
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

/** fetch's refusal of a redirect (redirect: "error"): Node throws "fetch failed" with the reason as its cause. */
const isRedirect = (e) => /redirect/i.test(String(e?.message ?? "")) || /redirect/i.test(String(e?.cause?.message ?? ""));

export function leaseDeps({ aud, fleet, signer, cert, chain, origin, fetch = globalThis.fetch, onChainBehind = () => {}, sendMs = SEND_MS,
  mono = () => performance.now() }) {
  if (typeof aud !== "string" || !isId(fleet) || typeof chain !== "function" || typeof fetch !== "function" || typeof onChainBehind !== "function") {
    refuse("bad_form", "lease client: aud, fleet, chain, fetch and onChainBehind are required");
  }
  const host = cert?.body?.host, hostKey = cert?.body?.fingerprint;
  if (!isId(host) || typeof hostKey !== "string" || !(cert.signRaw instanceof Uint8Array)) refuse("bad_form", "lease client: not a verified host certificate");
  // The signer IS the certified signing key, not a key that merely came with it.
  if (!sameBytes(signer?.raw, cert.signRaw) || signer.key !== keyId("ed25519", cert.signRaw) || typeof signer.sign !== "function") {
    refuse("bad_form", "lease client: the signing key isn't the certified host key");
  }
  const url = `${checkOrigin(origin)}${LEASE_ROUTE}`;
  const hs = Object.freeze({ kind: "host", id: host, alg: "ed25519", key: signer.key });
  const counts = Object.fromEntries([...SEND_CLASSES, "chain_behind"].map((k) => [k, 0]));
  let syncAsked = false;

  const context = () => ({ aud, fleet, chain: chain(), host, hostKey });

  const sign = async (body) => {
    if (body?.host !== host || body?.fleet !== fleet || body?.aud !== aud) refuse("bad_form", "lease client: a request for another host or fleet");
    const bytes = seal("sb.lease-request.v1", hs, body, signer);
    return { bytes, hash: sha256b64(signedBytes("sb.lease-request.v1", hs, body)) };
  };

  const send = async (bytes) => {
    const t0 = mono();
    const ac = new AbortController();
    let res = null, timer, dead = false;
    const hold = { reader: null };
    // Release whatever the exchange holds: its reader once one is open, else the body unread. Never awaited (a stalled
    // stream can't hold the caller), and run again when a response arrives after the deadline.
    const release = () => {
      if (hold.reader) hold.reader.cancel().catch(() => {});
      else if (res?.body && !res.body.locked) res.body.cancel().catch(() => {});
    };
    // The whole exchange races one absolute deadline: an abort that fetch or the body stream ignores still ends it.
    const deadline = new Promise((resolve) => { timer = setTimeout(() => { dead = true; ac.abort(); resolve("timeout"); }, sendMs); });
    const exchange = (async () => {
      res = await fetch(url, { method: "POST", body: bytes, redirect: "error", signal: ac.signal, headers: { "content-type": "application/json" } });
      // A response that comes after the deadline (by the timer, or by the monotonic clock when the timer couldn't run)
      // is never read: its body is released unread.
      if (dead || mono() - t0 >= sendMs) { release(); return "timeout"; }
      if (res.redirected || res.type === "opaqueredirect" || (res.status >= 300 && res.status < 400)) return "redirect";
      if (res.status !== 200) return "status";
      return readCapped(res, RESPONSE_MAX, hold);
    })().catch((e) => (e?.cls === "oversize" ? "oversize" : ac.signal.aborted ? "timeout" : isRedirect(e) ? "redirect" : "network"));
    try {
      let r = await Promise.race([exchange, deadline]);
      // The deadline is checked on the monotonic clock too, before anything is accepted: a busy event loop can delay the
      // timer past the deadline, never stretch it.
      if (r !== "timeout" && mono() - t0 >= sendMs) r = "timeout";
      if (r instanceof Uint8Array) { counts.ok++; return r; }
      counts[r]++;
      return null;
    } finally {
      clearTimeout(timer);
      release();
    }
  };

  const verify = async (bytes, ctx) => {
    try {
      return await verifyExecutionLease(bytes, ctx);
    } catch (e) {
      if (e?.code === "device_unknown") {
        counts.chain_behind++;
        if (!syncAsked) {
          syncAsked = true;
          // Scheduled, never awaited here; its failure (or a throw) changes nothing about this refusal.
          queueMicrotask(() => { Promise.resolve().then(onChainBehind).catch(() => {}).finally(() => { syncAsked = false; }); });
        }
      }
      throw e;
    }
  };

  return { sign, send, context, verify, counts };
}
