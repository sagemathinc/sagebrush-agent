// The fleet protocol package (design: agent-autonomous-schemas.md r2.3, sha256 db905c9d72ba5d4e…dddc7e3): one entry
// for every lane (service, page, app, host, browser). The browser lane's modules live beside it in ./browser/.

export const FREEZE = Object.freeze({ revision: "r2.3", sha256: "db905c9d72ba5d4e18620d3267ea9214992d3a82c735289dda4088970dddc7e3" });

export { FleetError, refuse, ID, isId, newId, idOfBytes, bytesOfId, b64, unb64, B64LEN, sha256, sha256b64, utf8, enc } from "./bytes.mjs";
export { canonText, canonBytes, parseCanonical, SIGNED_MAX, SIGNED_DEPTH } from "./canonical.mjs";
export { verifyStrict, checkPublicKey, canonicalPoint, smallOrder, keyId, keyFromSeed } from "./ed25519.mjs";
export { AUDIENCES, TYPES, signedBytes, seal, open } from "./envelope.mjs";
export { compile } from "./schema.mjs";
