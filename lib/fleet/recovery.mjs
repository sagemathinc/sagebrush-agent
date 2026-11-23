// Fleet protocol (r2.3 §2.5): the recovery code and the key it derives. The code is 16 random bytes in the id form
// (26 base32 characters); the key's 32-byte seed is HKDF-SHA256(ikm = the 16 bytes, salt = UTF-8 of the fleet id,
// info = "sagebrush.recovery.v1"). The code is shown once and never sent anywhere.

import { hkdfSync, randomBytes } from "node:crypto";
import { bytesOfId, idOfBytes, isId, refuse } from "./bytes.mjs";
import { keyFromSeed } from "./ed25519.mjs";

/** A new code (shown once, in groups of four). */
export const newRecoveryCode = () => idOfBytes(new Uint8Array(randomBytes(16)));
export const showCode = (code) => code.match(/.{1,4}/g).join("-");

/** What a person typed, normalized: spaces and hyphens removed, lower-cased, refused unless it is a code. */
export function readCode(typed) {
  const c = String(typed).replace(/[\s-]/g, "").toLowerCase();
  if (!isId(c)) refuse("bad_form", "not a recovery code");
  return c;
}

/** The recovery key a code derives for a fleet. */
export function recoveryKey(code, fleet) {
  if (!isId(fleet)) refuse("bad_form", "not a fleet id");
  const seed = new Uint8Array(hkdfSync("sha256", bytesOfId(readCode(code)), Buffer.from(fleet, "utf8"), Buffer.from("sagebrush.recovery.v1"), 32));
  return keyFromSeed(seed);
}
