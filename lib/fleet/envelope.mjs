// Node's synchronous face of core/envelope.mjs: the same form checks (parseEnvelope), with a resolveKey that answers
// directly and the strict verify of ./ed25519.mjs.

import { b64, enc, refuse } from "./bytes.mjs";
import { canonText } from "./core/canonical.mjs";
import { checkSigner, opened, parseEnvelope, signedBytes } from "./core/envelope.mjs";
import { verifyStrict } from "./ed25519.mjs";

export { AUDIENCES, TYPES, signedBytes, parseEnvelope, opened, checkSigner } from "./core/envelope.mjs";

export function open(bytes, ctx) {
  const p = parseEnvelope(bytes, ctx);
  const raw = ctx.resolveKey(p.env.signer, p.env.type, p.env.body);
  if (!verifyStrict(raw, p.signed, p.sig)) refuse("bad_signature");
  return opened(p);
}

export function seal(type, signer, body, key) {
  checkSigner(type, signer);
  return enc(canonText({ v: 1, type, signer, body, sig: b64(key.sign(signedBytes(type, signer, body))) }));
}

export function sealAdd(signer, body, key, newKey) {
  checkSigner("sb.device-chain.v1", signer);
  const bytes = signedBytes("sb.device-chain.v1", signer, body);
  return enc(canonText({ v: 1, type: "sb.device-chain.v1", signer, body, sig: b64(key.sign(bytes)), sig2: b64(newKey.sign(bytes)) }));
}
