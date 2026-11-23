// Fleet protocol (r2.2 §1.4): strict Ed25519. Node's own verify differs by version: Node 20 and 22 accept a
// signature (R = the identity, S = 0) under a small-order public key for any message; Node 26 refuses it. So the
// rules are checked here, before the library is asked, and never left to it:
//   - a public key, and R, must be canonical encodings (y < p, and no sign bit on a point whose x is 0);
//   - a public key must not be of small order (one of the eight torsion points, under either sign bit);
//   - S must be below the group order L.

import { createPrivateKey, createPublicKey, sign as nodeSign, verify as nodeVerify } from "node:crypto";
import { b64, enc, refuse, sha256, unb64 } from "./bytes.mjs";

const P = (1n << 255n) - 19n;
const L = (1n << 252n) + 27742317777372353535851937790883648493n;

const le = (b) => { let n = 0n; for (let i = b.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(b[i]); return n; };

// The y coordinates of the small-order points (torsion of order 1, 2, 4 and 8), compared with the sign bit cleared.
const SMALL_Y = new Set([
  1n, // order 1
  P - 1n, // order 2
  0n, // order 4
  le(Buffer.from("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", "hex")), // order 8
  le(Buffer.from("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", "hex")), // order 8
]);

function yOf(point) {
  const b = Uint8Array.from(point);
  const sign = b[31] >> 7;
  b[31] &= 0x7f;
  return { y: le(b), sign };
}

/** Whether 32 bytes are a canonical point encoding: y < p, and a sign bit only where x can be non-zero. */
export function canonicalPoint(point) {
  if (point.length !== 32) return false;
  const { y, sign } = yOf(point);
  if (y >= P) return false;
  if (sign && (y === 1n || y === P - 1n)) return false; // (x = 0 at y = ±1: a set sign bit is a second spelling)
  return true;
}

export const smallOrder = (point) => SMALL_Y.has(yOf(point).y % P);

/** A public key this protocol accepts (§1.4): canonical and not of small order. Refuses with bad_signature. */
export function checkPublicKey(raw) {
  if (!canonicalPoint(raw) || smallOrder(raw)) refuse("bad_signature", "an unacceptable public key");
  return raw;
}

/** The key id of a public key (§1.4): base64url of the first 16 bytes of SHA-256("sagebrush.key.v1\n" + alg + "\n" + key). */
export function keyId(alg, raw) {
  const h = sha256(Buffer.concat([Buffer.from(`sagebrush.key.v1\n${alg}\n`), Buffer.from(raw)]));
  return b64(h.subarray(0, 16));
}

const spki = (raw) => createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: b64(raw) }, format: "jwk" });

/** Strict verification of a 64-byte signature over `msg` by a 32-byte public key. True or false; never throws on bytes. */
export function verifyStrict(raw, msg, sig) {
  if (raw.length !== 32 || sig.length !== 64) return false;
  if (!canonicalPoint(raw) || smallOrder(raw)) return false;
  if (!canonicalPoint(sig.subarray(0, 32))) return false;
  if (le(sig.subarray(32)) >= L) return false;
  try { return nodeVerify(null, msg, spki(raw), sig); } catch { return false; }
}

// ---- signing, for the app, the host and the fixtures (a private key never leaves its holder)

/** A key from a 32-byte seed (fixtures and recovery, §2.5): { seed, raw, key: id, sign(msg) }. */
export function keyFromSeed(seed) {
  if (seed.length !== 32) refuse("bad_form", "a seed is 32 bytes");
  const d = b64(seed);
  const priv = createPrivateKey({ key: { kty: "OKP", crv: "Ed25519", d, x: b64(publicFromSeed(seed)) }, format: "jwk" });
  const raw = publicFromSeed(seed);
  return Object.freeze({ raw, key: keyId("ed25519", raw), sign: (msg) => new Uint8Array(nodeSign(null, msg, priv)) });
}

function publicFromSeed(seed) {
  // (Node derives the public half from a PKCS#8 seed: the RFC 8410 prefix plus the 32 seed bytes)
  const der = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.from(seed)]);
  const pub = createPublicKey(createPrivateKey({ key: der, format: "der", type: "pkcs8" }));
  return unb64(pub.export({ format: "jwk" }).x, 32);
}

export { enc };
