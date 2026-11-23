// The Node backend (core/crypto.mjs's interface) over node:crypto, installed when this module loads: every Node entry
// to the fleet package (index.mjs and the synchronous wrappers beside it) imports it. `nodeSync` is the same backend
// without promises, for those wrappers: bytes.mjs, ed25519.mjs and envelope.mjs keep the synchronous API the host
// stack was written against.

import {
  createCipheriv, createDecipheriv, createHash, createHmac, createPrivateKey, createPublicKey, diffieHellman, generateKeyPairSync, hkdfSync,
  randomBytes, sign, verify,
} from "node:crypto";
import { useCrypto } from "./core/crypto.mjs";

// (an Ed25519 private key from its 32-byte seed: the RFC 8410 PKCS#8 prefix, then the seed)
const PKCS8 = Buffer.from("302e020100300506032b657004220420", "hex");
const PKCS8_X = Buffer.from("302e020100300506032b656e04220420", "hex");
const xPublic = (raw) => createPublicKey({ key: { kty: "OKP", crv: "X25519", x: Buffer.from(raw).toString("base64url") }, format: "jwk" });
// (an X25519 pair: dh is null where OpenSSL refuses the peer or the result; the core refuses an all-zero secret itself)
const xPair = (priv) => ({
  raw: new Uint8Array(Buffer.from(createPublicKey(priv).export({ format: "jwk" }).x, "base64url")),
  dh(peer) {
    try { return new Uint8Array(diffieHellman({ privateKey: priv, publicKey: xPublic(peer) })); } catch { return null; }
  },
});
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
  hmacSha256: (key, data) => new Uint8Array(createHmac("sha256", key).update(data).digest()),
  x25519Generate: () => xPair(generateKeyPairSync("x25519").privateKey),
  x25519FromPrivate(sk) {
    const der = Buffer.concat([PKCS8_X, sk]);
    try { return xPair(createPrivateKey({ key: der, format: "der", type: "pkcs8" })); } finally { der.fill(0); }
  },
  aes256gcmSeal(key, nonce, aad, pt) {
    const c = createCipheriv("aes-256-gcm", key, nonce, { authTagLength: 16 });
    c.setAAD(aad);
    return new Uint8Array(Buffer.concat([c.update(pt), c.final(), c.getAuthTag()]));
  },
  aes256gcmOpen(key, nonce, aad, ct) {
    if (ct.length < 16) return null;
    try {
      const d = createDecipheriv("aes-256-gcm", key, nonce, { authTagLength: 16 });
      d.setAAD(aad);
      d.setAuthTag(ct.subarray(ct.length - 16));
      return new Uint8Array(Buffer.concat([d.update(ct.subarray(0, ct.length - 16)), d.final()]));
    } catch { return null; }
  },
});

const asyncPair = (p) => ({ raw: p.raw, dh: async (peer) => p.dh(peer) });

export const nodeCrypto = Object.freeze({
  sha256: async (bytes) => nodeSync.sha256(bytes),
  ed25519Verify: async (raw, msg, sig) => nodeSync.ed25519Verify(raw, msg, sig),
  async ed25519FromSeed(seed) {
    const k = nodeSync.ed25519FromSeed(seed);
    return { raw: k.raw, sign: async (msg) => k.sign(msg) };
  },
  hkdf: async (ikm, salt, info, length) => nodeSync.hkdf(ikm, salt, info, length),
  random: (n) => nodeSync.random(n),
  hmacSha256: async (key, data) => nodeSync.hmacSha256(key, data),
  x25519Generate: async () => asyncPair(nodeSync.x25519Generate()),
  x25519FromPrivate: async (sk) => asyncPair(nodeSync.x25519FromPrivate(sk)),
  aes256gcmSeal: async (key, nonce, aad, pt) => nodeSync.aes256gcmSeal(key, nonce, aad, pt),
  aes256gcmOpen: async (key, nonce, aad, ct) => nodeSync.aes256gcmOpen(key, nonce, aad, ct),
});

useCrypto(nodeCrypto);
