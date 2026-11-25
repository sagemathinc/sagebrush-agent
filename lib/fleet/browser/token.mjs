// Fleet protocol, the browser lane: the forms of the app-open relay token (design A1) and of an open's request id,
// shared by the frame codec (net.token's body), the net sidecar (its token requests) and the net channel (its opens).
// No dependencies, so any of them can import it.

/** The app-open relay token's one form (A1): rt1. and 32 CSPRNG bytes, base64url without padding (47 characters). */
export const RELAY_TOKEN = /^rt1\.[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/;
export const RELAY_TOKEN_BYTES = 47;

/** An open's Sagebrush-Request id: 128 random bits, base64url without padding (22 characters). */
export const REQUEST_ID = /^[A-Za-z0-9_-]{21}[AQgw]$/;

/** Whether `body` (bytes) is exactly one relay token in its form. */
export function isRelayTokenBody(body) {
  if (!(body instanceof Uint8Array) || body.length !== RELAY_TOKEN_BYTES) return false;
  for (const b of body) if (b < 0x21 || b > 0x7e) return false;
  return RELAY_TOKEN.test(Buffer.from(body.buffer, body.byteOffset, body.length).toString("latin1"));
}
