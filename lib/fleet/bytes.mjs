// Node's synchronous face of core/bytes.mjs (the host stack's): the same rules, with SHA-256 and random ids from
// node:crypto directly rather than through the backend's promises.

import { b64, idOfBytes } from "./core/bytes.mjs";
import { nodeSync } from "./node-crypto.mjs";

export { FleetError, refuse, ID, isId, idOfBytes, bytesOfId, B64LEN, b64, unb64, utf8, enc, concat, bytesEqual } from "./core/bytes.mjs";

export const sha256 = (bytes) => nodeSync.sha256(bytes);
export const sha256b64 = (bytes) => b64(sha256(bytes));
export const random = (n) => nodeSync.random(n);
export const newId = () => idOfBytes(random(16));
