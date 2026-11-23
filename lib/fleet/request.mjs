// Fleet protocol (r2.3 §5.1): the request signature a host's broker or supervisor puts on every request to the
// service, in the `Sagebrush-Sig` header. Node only (it signs with the host's key). The browser channel's relay opens
// and replacement authorizations use it (agent-autonomous-browser-channel.md r4 §5); the broker reuses it. The
// header's form and the signed bytes are core/request.mjs's (one source); a page or a Worker verifies with that
// file's async verifyRequest, which leaves the nonce to its caller.
//
//   Sagebrush-Sig: v1 host=<id>; agent=<id or ->; cap=<id or ->; gen=<n>; ts=<ms>; nonce=<22>; idem=<22 or ->; op=<ms or ->; sig=<86>
//   signed bytes: "sagebrush.req.v1\n" aud "\n" METHOD "\n" target "\n" sha256b64(body) "\n" host "\n" agent "\n" cap "\n"
//                 gen "\n" ts "\n" nonce "\n" idem "\n" op
//
// verifyRequest checks, in §5.1's order: the form, aud, ts within 5 minutes, the host (paired, not revoked, gen
// current: the caller's), the signature, the nonce (consumed: the caller's); agent and operation checks are the
// caller's after it.

import { b64, refuse, sha256b64, unb64 } from "./bytes.mjs";
import { verifyStrict } from "./ed25519.mjs";
import { AUDIENCES } from "./envelope.mjs";
import { SIG_KEYS, SKEW_MS, parseSig, requestBytes } from "./core/request.mjs";

export { parseSig };

const signedBytes = (aud, method, target, body, f) => requestBytes(aud, method, target, sha256b64(body), f);

/**
 * Sign a request as host `host` with its signing key (keyFromSeed's { sign }), returning the header's value.
 * `fields`: { agent, cap, gen, ts, nonce, idem, op } ("-" where absent).
 */
export function signRequest({ aud, method, target, body = new Uint8Array(0), host, key, fields }) {
  const f = { host, agent: "-", cap: "-", idem: "-", op: "-", ...fields, gen: String(fields.gen), ts: String(fields.ts) };
  const sig = key.sign(signedBytes(aud, method, target, body, f));
  const value = `v1 ${SIG_KEYS.map((k) => `${k}=${k === "sig" ? b64(sig) : f[k]}`).join("; ")}`;
  parseSig(value); // (what it signs is what a verifier will read)
  return value;
}

/**
 * Verify a request's signature. ctx: { aud, now, hostKey(host) -> 32-byte raw public key (refusing unknown_host or
 * host_revoked itself), currentGen(host) -> n, consumeNonce(host, nonce) -> true if new }. Returns the parsed fields.
 * The target is compared as raw bytes: what is checked is what was signed.
 */
export function verifyRequest({ header, method, target, body = new Uint8Array(0) }, ctx) {
  const f = parseSig(header);
  if (!AUDIENCES.includes(ctx.aud)) refuse("bad_audience");
  if (Math.abs(Number(f.ts) - ctx.now) > SKEW_MS) refuse("clock_skew");
  const raw = ctx.hostKey(f.host);
  if (Number(f.gen) !== ctx.currentGen(f.host)) refuse("stale_generation");
  if (!verifyStrict(raw, signedBytes(ctx.aud, method, target, body, f), unb64(f.sig, 64))) refuse("bad_signature");
  if (!ctx.consumeNonce(f.host, f.nonce)) refuse("replay");
  return f;
}
