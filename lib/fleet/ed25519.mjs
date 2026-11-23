// Node's synchronous face of core/ed25519.mjs: the same strict rules (strictShape) before node:crypto's own verify,
// and keys whose sign() returns the signature rather than a promise of it.

import { b64, refuse, sha256 } from "./bytes.mjs";
import { checkPublicKey, keyIdInput, strictShape } from "./core/ed25519.mjs";
import { nodeSync } from "./node-crypto.mjs";

export { canonicalPoint, smallOrder, checkPublicKey, keyIdInput, strictShape, enc } from "./core/ed25519.mjs";

export const keyId = (alg, raw) => b64(sha256(keyIdInput(alg, raw)).subarray(0, 16));

export function verifyStrict(raw, msg, sig) {
  if (!strictShape(raw, sig)) return false;
  return nodeSync.ed25519Verify(raw, msg, sig) === true;
}

export function keyFromSeed(seed) {
  if (seed?.length !== 32) refuse("bad_form", "a seed is 32 bytes");
  const k = nodeSync.ed25519FromSeed(seed);
  checkPublicKey(k.raw);
  return Object.freeze({ raw: k.raw, key: keyId("ed25519", k.raw), sign: k.sign });
}
