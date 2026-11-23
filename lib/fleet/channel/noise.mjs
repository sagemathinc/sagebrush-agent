// Noise_IK_25519_ChaChaPoly_SHA256 (Noise spec rev. 34), the one protocol of the browser channel (design
// agent-autonomous-browser-channel.md r4 §2; O11 §7.2): no PSK, no fallback, no options. Node only (ChaCha20-Poly1305
// isn't in WebCrypto); both ends use it: the initiator in the app's net sidecar, the responder in the host's broker.
//
// The rules carried over from the HPKE review:
//   - one role per object: an initiator handshake has only writeMessage1/readMessage2, a responder only
//     readMessage1/writeMessage2; each is single-use, and dead for good after any refusal;
//   - the split gives a sending CipherState (encrypt only) and a receiving one (decrypt only), each frozen;
//   - every operation is synchronous (Node's X25519 and ChaCha20-Poly1305 are), so no two can overlap on one state;
//   - the nonce is an exact counter, refused at 2^53 - 1, advanced only after success; a decrypt failure is final;
//   - an all-zero DH result is refused here, on every token (es, ss, ee, se), whatever the library returns.

import { createCipheriv, createDecipheriv, createHash, createHmac, createPrivateKey, createPublicKey, diffieHellman, generateKeyPairSync } from "node:crypto";
import { refuse } from "../bytes.mjs";

export const PROTOCOL = "Noise_IK_25519_ChaChaPoly_SHA256";
export const MAX_MESSAGE = 65535;
const DHLEN = 32, HASHLEN = 32, TAG = 16;
const NONCE_MAX = Number.MAX_SAFE_INTEGER;
const EMPTY = new Uint8Array(0);

const sha256 = (...parts) => { const h = createHash("sha256"); for (const p of parts) h.update(p); return new Uint8Array(h.digest()); };
const hmac = (key, ...parts) => { const h = createHmac("sha256", key); for (const p of parts) h.update(p); return new Uint8Array(h.digest()); };
const cat = (...parts) => { const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let at = 0; for (const p of parts) { out.set(p, at); at += p.length; } return out; };

function hkdf(ck, ikm) {
  const temp = hmac(ck, ikm);
  const o1 = hmac(temp, Uint8Array.of(1));
  return [o1, hmac(temp, o1, Uint8Array.of(2))];
}

// ---- X25519 keys: { raw (32 bytes), dh(peerRaw) -> 32 bytes or null }

const PKCS8_X = Uint8Array.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20]);
const xPublic = (raw) => createPublicKey({ key: { kty: "OKP", crv: "X25519", x: Buffer.from(raw).toString("base64url") }, format: "jwk" });

/** An X25519 key from a node:crypto private KeyObject (the net sidecar's session key, the host's stored key). */
export function x25519Key(privateKey) {
  if (privateKey?.asymmetricKeyType !== "x25519" || privateKey.type !== "private") throw new Error("an X25519 private KeyObject");
  const raw = new Uint8Array(Buffer.from(createPublicKey(privateKey).export({ format: "jwk" }).x, "base64url"));
  return Object.freeze({
    raw,
    dh(peer) {
      try { return new Uint8Array(diffieHellman({ privateKey, publicKey: xPublic(peer) })); } catch { return null; }
    },
  });
}

/** An X25519 key from its 32 private bytes (the fixtures and the Noise vectors). */
export function x25519KeyFromPrivate(sk) {
  const der = cat(PKCS8_X, sk);
  try { return x25519Key(createPrivateKey({ key: Buffer.from(der), format: "der", type: "pkcs8" })); } finally { der.fill(0); }
}

export const x25519Generate = () => x25519Key(generateKeyPairSync("x25519").privateKey);

// ---- CipherState (§5.1), split by role

function aead(encrypt, k, n, ad, data) {
  const nonce = new Uint8Array(12);
  new DataView(nonce.buffer).setBigUint64(4, BigInt(n), true); // (32 zero bits, then the 64-bit counter, little-endian)
  if (encrypt) {
    const c = createCipheriv("chacha20-poly1305", k, nonce, { authTagLength: TAG });
    c.setAAD(ad);
    return cat(c.update(data), c.final(), c.getAuthTag());
  }
  if (data.length < TAG) return null;
  try {
    const d = createDecipheriv("chacha20-poly1305", k, nonce, { authTagLength: TAG });
    d.setAAD(ad);
    d.setAuthTag(data.subarray(data.length - TAG));
    return cat(d.update(data.subarray(0, data.length - TAG)), d.final());
  } catch { return null; }
}

/** The transport's sending half: encrypt only. `start` is for the nonce cap's boundary test only. */
function sender(k, start = 0) {
  let n = start;
  return Object.freeze({
    encrypt(ad, pt) {
      if (n >= NONCE_MAX) refuse("limit", "this channel's nonce is used up");
      if (pt.length + TAG > MAX_MESSAGE) refuse("limit", "a Noise message over 65,535 bytes");
      const ct = aead(true, k, n, ad, pt);
      n++;
      return ct;
    },
    get nonce() { return n; },
  });
}

/** The transport's receiving half: decrypt only. A failure is final: the half refuses everything after it. */
function receiver(k, start = 0) {
  let n = start, dead = false;
  return Object.freeze({
    decrypt(ad, ct) {
      if (dead) refuse("bad_form", "this channel failed");
      if (n >= NONCE_MAX) refuse("limit", "this channel's nonce is used up");
      if (ct.length > MAX_MESSAGE) { dead = true; refuse("limit", "a Noise message over 65,535 bytes"); }
      const pt = aead(false, k, n, ad, ct);
      if (pt === null) { dead = true; refuse("bad_signature", "a Noise message that doesn't decrypt (a gap, a reorder or a forgery)"); }
      n++;
      return pt;
    },
    get nonce() { return n; },
  });
}

/** For the nonce cap's boundary test only (not exported from an index): transport halves starting at `start`. */
export const atNonce = Object.freeze({ sender, receiver });

// ---- SymmetricState (§5.2), private to a handshake

function symmetric(prologue) {
  const name = new TextEncoder().encode(PROTOCOL);
  let h = name.length <= HASHLEN ? cat(name, new Uint8Array(HASHLEN - name.length)) : sha256(name);
  let ck = h, k = null, n = 0;
  const s = {
    mixHash(data) { h = sha256(h, data); },
    mixKey(ikm) { const [c, t] = hkdf(ck, ikm); ck = c; k = t; n = 0; },
    encryptAndHash(pt) {
      const ct = k === null ? pt : aead(true, k, n++, h, pt);
      s.mixHash(ct);
      return ct;
    },
    decryptAndHash(ct) {
      const pt = k === null ? ct : aead(false, k, n++, h, ct);
      if (pt === null) refuse("bad_signature", "the handshake doesn't decrypt");
      s.mixHash(ct);
      return pt;
    },
    split: () => hkdf(ck, EMPTY),
    get h() { return h; },
  };
  s.mixHash(prologue);
  return s;
}

function dh(key, peer) {
  const z = key.dh(peer);
  if (!(z instanceof Uint8Array) || z.length !== DHLEN || z.every((x) => x === 0)) refuse("bad_signature", "an X25519 key that gives no shared secret");
  return z;
}

// (a handshake object runs its steps once, in order; any refusal kills it for good)
function once() {
  let at = 0, dead = false;
  return (i, fn) => {
    if (dead) refuse("bad_form", "this handshake failed");
    if (i !== at) refuse("bad_form", "a handshake step out of order, or again");
    try { const r = fn(); at++; return r; } catch (e) { dead = true; throw e; }
  };
}

/**
 * The initiator (the app's net sidecar). `s`: its static key ({ raw, dh }); `rs`: the responder's static public key
 * (32 bytes, its certified X25519 key); `prologue`: bytes. `ephemeral`: the fixtures and vectors only.
 */
export function initiator({ s, rs, prologue, ephemeral = null }) {
  if (rs?.length !== 32) refuse("bad_form", "a responder key is 32 bytes");
  const ss = symmetric(prologue);
  ss.mixHash(rs);
  const step = once();
  let e = null;
  return Object.freeze({
    writeMessage1: (payload) => step(0, () => {
      e = ephemeral ?? x25519Generate();
      ss.mixHash(e.raw);
      ss.mixKey(dh(e, rs));                  // es
      const encS = ss.encryptAndHash(s.raw); // s
      ss.mixKey(dh(s, rs));                  // ss
      const msg = cat(e.raw, encS, ss.encryptAndHash(payload));
      if (msg.length > MAX_MESSAGE) refuse("limit", "message 1 over 65,535 bytes");
      return msg;
    }),
    /** Returns { payload, send, receive, handshakeHash }. */
    readMessage2: (msg) => step(1, () => {
      if (msg.length < DHLEN + TAG || msg.length > MAX_MESSAGE) refuse("bad_form", "message 2's length");
      const re = msg.subarray(0, DHLEN);
      ss.mixHash(re);
      ss.mixKey(dh(e, re));                  // ee
      ss.mixKey(dh(s, re));                  // se
      const payload = ss.decryptAndHash(msg.subarray(DHLEN));
      const [k1, k2] = ss.split();
      return { payload, send: sender(k1), receive: receiver(k2), handshakeHash: ss.h };
    }),
  });
}

/** The responder (the host's broker). `s`: its static key, the certified X25519 key. `ephemeral`: fixtures only. */
export function responder({ s, prologue, ephemeral = null }) {
  const ss = symmetric(prologue);
  ss.mixHash(s.raw);
  const step = once();
  let re = null, rs = null;
  return Object.freeze({
    /** Returns { rs (the initiator's static key), payload }. */
    readMessage1: (msg) => step(0, () => {
      if (msg.length < DHLEN + DHLEN + TAG + TAG || msg.length > MAX_MESSAGE) refuse("bad_form", "message 1's length");
      re = msg.subarray(0, DHLEN);
      ss.mixHash(re);
      ss.mixKey(dh(s, re));                                               // es
      rs = ss.decryptAndHash(msg.subarray(DHLEN, DHLEN + DHLEN + TAG)); // s
      ss.mixKey(dh(s, rs));                                               // ss
      const payload = ss.decryptAndHash(msg.subarray(DHLEN + DHLEN + TAG));
      return { rs: Uint8Array.from(rs), payload };
    }),
    /** Returns { message, send, receive, handshakeHash }. */
    writeMessage2: (payload) => step(1, () => {
      const e = ephemeral ?? x25519Generate();
      ss.mixHash(e.raw);
      ss.mixKey(dh(e, re));                  // ee
      ss.mixKey(dh(e, rs));                  // se
      const msg = cat(e.raw, ss.encryptAndHash(payload));
      if (msg.length > MAX_MESSAGE) refuse("limit", "message 2 over 65,535 bytes");
      const [k1, k2] = ss.split();
      return { message: msg, send: sender(k2), receive: receiver(k1), handshakeHash: ss.h };
    }),
  });
}
