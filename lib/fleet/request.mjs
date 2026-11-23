// Fleet protocol (r2.3 §5.1): the request signature a host's broker or supervisor puts on every request to the
// service, in the `Sagebrush-Sig` header. Node only (it signs with the host's key). The browser channel's relay opens
// and replacement authorizations use it (agent-autonomous-browser-channel.md r4 §5); the broker reuses it.
//
//   Sagebrush-Sig: v1 host=<id>; agent=<id or ->; cap=<id or ->; gen=<n>; ts=<ms>; nonce=<22>; idem=<22 or ->; op=<ms or ->; sig=<86>
//   signed bytes: "sagebrush.req.v1\n" aud "\n" METHOD "\n" target "\n" sha256b64(body) "\n" host "\n" agent "\n" cap "\n"
//                 gen "\n" ts "\n" nonce "\n" idem "\n" op
//
// verifyRequest checks, in §5.1's order: the form, aud, ts within 5 minutes, the host (paired, not revoked, gen
// current: the caller's), the signature, the nonce (consumed: the caller's); agent and operation checks are the
// caller's after it.

import { b64, enc, isId, refuse, sha256b64, unb64 } from "./bytes.mjs";
import { verifyStrict } from "./ed25519.mjs";
import { AUDIENCES } from "./envelope.mjs";

const KEYS = ["host", "agent", "cap", "gen", "ts", "nonce", "idem", "op", "sig"];
const SKEW_MS = 5 * 60_000;
const COUNT = /^(0|[1-9][0-9]{0,15})$/;
const B22 = /^[A-Za-z0-9_-]{21}[AQgw]$/;

const signedBytes = (aud, method, target, body, f) =>
  enc(["sagebrush.req.v1", aud, method, target, sha256b64(body), f.host, f.agent, f.cap, f.gen, f.ts, f.nonce, f.idem, f.op].join("\n"));

/** The header's fields, each in its fixed form, or a bad_form refusal. */
export function parseSig(header) {
  if (typeof header !== "string" || header.length > 1024 || !header.startsWith("v1 ")) refuse("bad_form", "not a Sagebrush-Sig v1 header");
  const parts = header.slice(3).split("; ");
  if (parts.length !== KEYS.length) refuse("bad_form", "a Sagebrush-Sig header has exactly its nine fields");
  const f = {};
  parts.forEach((p, i) => {
    const eq = p.indexOf("=");
    if (eq < 1 || p.slice(0, eq) !== KEYS[i]) refuse("bad_form", "a Sagebrush-Sig field out of place");
    f[KEYS[i]] = p.slice(eq + 1);
  });
  const idOrDash = (v) => v === "-" || isId(v);
  const num = (v) => COUNT.test(v) && Number.isSafeInteger(Number(v));
  if (!isId(f.host) || !idOrDash(f.agent) || !idOrDash(f.cap) || !num(f.gen) || f.gen === "0" || !num(f.ts) || !B22.test(f.nonce)
    || !(f.idem === "-" || B22.test(f.idem)) || !(f.op === "-" || num(f.op)) || (f.idem === "-") !== (f.op === "-")) refuse("bad_form", "a Sagebrush-Sig field's form");
  unb64(f.sig, 64);
  return f;
}

/**
 * Sign a request as host `host` with its signing key (keyFromSeed's { sign }), returning the header's value.
 * `fields`: { agent, cap, gen, ts, nonce, idem, op } ("-" where absent).
 */
export function signRequest({ aud, method, target, body = new Uint8Array(0), host, key, fields }) {
  const f = { host, agent: "-", cap: "-", idem: "-", op: "-", ...fields, gen: String(fields.gen), ts: String(fields.ts) };
  const sig = key.sign(signedBytes(aud, method, target, body, f));
  const value = `v1 ${KEYS.map((k) => `${k}=${k === "sig" ? b64(sig) : f[k]}`).join("; ")}`;
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
