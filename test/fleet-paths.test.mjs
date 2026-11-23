// Every lib/fleet path callers imported before the crypto split still resolves, with at least the names it exported
// then (main d0c632f7): the lanes (host, browser) import these paths directly, so a later split can't drop one. And every
// module under lib/fleet/ outside core/ loads, so a lane module importing a removed path fails here, not after merge.
import assert from "node:assert/strict";
import { readdirSync } from "node:fs";
import { test } from "node:test";

const PREVIOUS = {
  "bytes.mjs": ["B64LEN", "FleetError", "ID", "b64", "bytesOfId", "enc", "idOfBytes", "isId", "newId", "refuse", "sha256", "sha256b64", "unb64", "utf8"],
  "canonical.mjs": ["SIGNED_DEPTH", "SIGNED_MAX", "canonBytes", "canonText", "parseCanonical"],
  "chain.mjs": ["apply", "deviceKey", "replay", "requireTier", "serviceKeyAt"],
  "ed25519.mjs": ["canonicalPoint", "checkPublicKey", "enc", "keyFromSeed", "keyId", "smallOrder", "verifyStrict"],
  "envelope.mjs": ["AUDIENCES", "TYPES", "open", "seal", "sealAdd", "signedBytes"],
  "index.mjs": ["AUDIENCES", "B64LEN", "FLEET_SCHEMA", "FREEZE", "FleetError", "ID", "REASONS", "SIGNED_DEPTH", "SIGNED_MAX", "TYPES", "applyChainEntry", "b64", "bodyValidator", "bytesOfId", "canonBytes", "canonText", "canonicalPath", "canonicalPoint", "checkPublicKey", "compile", "deviceFingerprint", "deviceKey", "enc", "hostFingerprint", "idOfBytes", "isId", "keyFromSeed", "keyId", "narrowsOnly", "newId", "newRecoveryCode", "open", "parseCanonical", "preimageHash", "readCode", "recoveryKey", "refuse", "replayChain", "requireTier", "seal", "sealAdd", "serviceKeyAt", "sha256", "sha256b64", "showCode", "showFingerprint", "signedBytes", "smallOrder", "unb64", "utf8", "verifyApproval", "verifyGrant", "verifyGrantAck", "verifyHostCert", "verifyHostOp", "verifyRevocation", "verifyStrict"],
  "recovery.mjs": ["newRecoveryCode", "readCode", "recoveryKey", "showCode"],
  "schema.mjs": ["compile"],
  "schemas.mjs": ["FLEET_SCHEMA", "REASONS", "bodyValidator"],
  "verify.mjs": ["canonicalPath", "deviceFingerprint", "hostFingerprint", "narrowsOnly", "preimageHash", "showFingerprint", "verifyApproval", "verifyGrant", "verifyGrantAck", "verifyHostCert", "verifyHostOp", "verifyRevocation"]
};

test("every pre-split lib/fleet path resolves and keeps its exported names", async () => {
  for (const [path, names] of Object.entries(PREVIOUS)) {
    const m = await import(`../lib/fleet/${path}`);
    for (const n of names) assert.ok(n in m, `${path} exports ${n}`);
  }
});

test("every lib/fleet module outside core/ loads (the lanes' imports resolve)", async () => {
  const dir = new URL("../lib/fleet/", import.meta.url);
  const files = readdirSync(dir, { recursive: true }).map(String).filter((f) => f.endsWith(".mjs") && !f.startsWith("core"));
  assert.ok(files.length >= 15, files.join(" "));
  for (const f of files) await import(new URL(f.replaceAll("\\", "/"), dir).href);
});
