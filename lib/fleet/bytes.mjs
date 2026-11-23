// Fleet protocol (design: agent-autonomous-schemas.md r2.2 §1.1, §1.2): ids, canonical base64url, strict UTF-8 and
// SHA-256. Pure; every lane (the service, the page, the app, the host) uses these exact rules, and the Python
// reference verifier mirrors them against the same fixtures.

import { createHash, randomBytes } from "node:crypto";

export class FleetError extends Error {
  /** `code` is a name in schema/fleet/reasons.json; the message never echoes an untrusted value. */
  constructor(code, message = code) { super(message); this.code = code; }
}
export const refuse = (code, message) => { throw new FleetError(code, message); };

const B32 = "abcdefghijklmnopqrstuvwxyz234567";

/** An id (§1.1): 26 lowercase RFC 4648 base32 characters, 128 random bits and 2 zero bits. */
export const ID = /^[a-z2-7]{25}[aeimquy4]$/;
export const isId = (v) => typeof v === "string" && v.length === 26 && ID.test(v);

/** 16 bytes as an id (the recovery code uses the same form, §2.5). */
export function idOfBytes(b) {
  if (!(b instanceof Uint8Array) || b.length !== 16) refuse("bad_form", "an id is 16 bytes");
  let bits = 0, acc = 0, out = "";
  for (const x of b) {
    acc = (acc << 8) | x; bits += 8;
    while (bits >= 5) { out += B32[(acc >>> (bits - 5)) & 31]; bits -= 5; }
    acc &= (1 << bits) - 1;
  }
  return out + B32[(acc << (5 - bits)) & 31]; // (3 bits left, shifted up: the last 2 bits are zero)
}

/** An id's 16 bytes; refuses anything that isn't an id. */
export function bytesOfId(s) {
  if (!isId(s)) refuse("bad_form", "not an id");
  const out = new Uint8Array(16);
  let bits = 0, acc = 0, n = 0;
  for (const c of s) {
    acc = (acc << 5) | B32.indexOf(c); bits += 5;
    if (bits >= 8) { out[n++] = (acc >>> (bits - 8)) & 255; bits -= 8; acc &= (1 << bits) - 1; }
  }
  return out;
}

export const newId = () => idOfBytes(new Uint8Array(randomBytes(16)));

// ---- base64url, canonical (§1.2): no padding, the unused low bits of the last character zero, exact lengths

const B64 = /^[A-Za-z0-9_-]*$/;
/** The exact encoded lengths of the binary values in this protocol. */
export const B64LEN = Object.freeze({ 16: 22, 32: 43, 64: 86 });

export const b64 = (bytes) => Buffer.from(bytes).toString("base64url");

/** Decode base64url only if it is the one canonical spelling of `len` bytes (when given). */
export function unb64(s, len) {
  if (typeof s !== "string" || !B64.test(s) || s.length % 4 === 1) refuse("bad_form", "not base64url");
  if (len !== undefined && s.length !== B64LEN[len]) refuse("bad_form", "a binary value of the wrong length");
  const b = Buffer.from(s, "base64url");
  if (b.toString("base64url") !== s) refuse("bad_form", "a non-canonical base64url value"); // (non-zero pad bits)
  return new Uint8Array(b);
}

export const sha256 = (bytes) => new Uint8Array(createHash("sha256").update(bytes).digest());
export const sha256b64 = (bytes) => b64(sha256(bytes));

// (ignoreBOM keeps a leading U+FEFF in the text, so it can be refused rather than silently dropped)
const td = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
/** Received bytes as text, refusing invalid UTF-8 and a byte-order mark (no canonical text has one). */
export function utf8(bytes) {
  let s;
  try { s = td.decode(bytes); } catch { refuse("bad_form", "not UTF-8"); }
  if (s.charCodeAt(0) === 0xfeff) refuse("bad_form", "a byte-order mark");
  return s;
}
export const enc = (s) => new TextEncoder().encode(s);
