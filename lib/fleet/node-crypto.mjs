// The Node backend (core/crypto.mjs's interface) over node:crypto, installed when this module loads: every Node entry
// to the fleet package (index.mjs and the synchronous wrappers beside it) imports it. `nodeSync` is the same backend
// without promises, for those wrappers: bytes.mjs, ed25519.mjs and envelope.mjs keep the synchronous API the host
// stack was written against.

import { createHash, createPrivateKey, createPublicKey, hkdfSync, randomBytes, sign, verify } from "node:crypto";
import { useCrypto } from "./core/crypto.mjs";

// (an Ed25519 private key from its 32-byte seed: the RFC 8410 PKCS#8 prefix, then the seed)
const PKCS8 = Buffer.from("302e020100300506032b657004220420", "hex");
const spki = (raw) => createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: Buffer.from(raw).toString("base64url") }, format: "jwk" });

export const nodeSync = Object.freeze({
  sha256: (bytes) => new Uint8Array(createHash("sha256").update(bytes).digest()),
  ed25519Verify(raw, msg, sig) {
    try { return verify(null, msg, spki(raw), sig) === true; } catch { return false; }
  },
  ed25519FromSeed(seed) {
    const priv = createPrivateKey({ key: Buffer.concat([PKCS8, seed]), format: "der", type: "pkcs8" });
    const raw = new Uint8Array(Buffer.from(createPublicKey(priv).export({ format: "jwk" }).x, "base64url"));
    return { raw, sign: (msg) => new Uint8Array(sign(null, msg, priv)) };
  },
  hkdf: (ikm, salt, info, length) => new Uint8Array(hkdfSync("sha256", ikm, salt, info, length)),
  random: (n) => new Uint8Array(randomBytes(n)),
});

export const nodeCrypto = Object.freeze({
  sha256: async (bytes) => nodeSync.sha256(bytes),
  ed25519Verify: async (raw, msg, sig) => nodeSync.ed25519Verify(raw, msg, sig),
  async ed25519FromSeed(seed) {
    const k = nodeSync.ed25519FromSeed(seed);
    return { raw: k.raw, sign: async (msg) => k.sign(msg) };
  },
  hkdf: async (ikm, salt, info, length) => nodeSync.hkdf(ikm, salt, info, length),
  random: (n) => nodeSync.random(n),
});

useCrypto(nodeCrypto);
