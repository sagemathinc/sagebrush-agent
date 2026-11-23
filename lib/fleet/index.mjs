// The fleet protocol package (design: agent-autonomous-schemas.md r2.3, sha256 db905c9d72ba5d4e…dddc7e3) in Node: the
// pure core (./core/, which a page loads as it is) with Node's crypto backend and the schemas from disk installed.
// The byte, key and envelope functions here are synchronous (the host stack's API); the chain, the verifiers and
// recovery are the core's, async. The browser lane's modules live beside it in ./browser/, the host's in ./host/.

import "./node-crypto.mjs";
import "./schemas.mjs";

export { FREEZE } from "./core/schemas.mjs";
export { FleetError, refuse, ID, isId, newId, idOfBytes, bytesOfId, b64, unb64, B64LEN, sha256, sha256b64, utf8, enc, concat, bytesEqual } from "./bytes.mjs";
export { canonText, canonBytes, parseCanonical, SIGNED_MAX, SIGNED_DEPTH } from "./core/canonical.mjs";
export { verifyStrict, checkPublicKey, canonicalPoint, smallOrder, keyId, keyFromSeed } from "./ed25519.mjs";
export { AUDIENCES, TYPES, signedBytes, seal, sealAdd, open } from "./envelope.mjs";
export { compile } from "./schema.mjs";
export { FLEET_SCHEMA, REASONS, bodyValidator } from "./schemas.mjs";
export { apply as applyChainEntry, replay as replayChain, deviceKey, requireTier, serviceKeyAt } from "./core/chain.mjs";
export { newRecoveryCode, showCode, readCode, recoveryKey } from "./core/recovery.mjs";
export { canonicalPath, hostFingerprint, deviceFingerprint, showFingerprint, narrowsOnly, preimageHash, verifyHostCert, verifyGrant, verifyGrantAck, verifyHostOp, verifyRevocation, verifyApproval } from "./core/verify.mjs";
export { HPKE, deriveKeyPair, setupSender, setupRecipient, seal as hpkeSeal, open as hpkeOpen } from "./core/hpke.mjs";
export { encKeyId, sealPackage, verifyPackage, sealCap, openCap } from "./core/sealed.mjs";
