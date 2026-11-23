// The fleet core with the WebCrypto backend (lib/fleet/core/webcrypto.mjs, what a page, a Worker or the app's web view
// installs), on Node's globalThis.crypto: every shared vector, the backend installed once, and keys, hashes and
// derivations that agree with Node's backend byte for byte. This file loads only the pure core, never lib/fleet's Node
// entry, so nothing here runs on node:crypto's code path. fleet-webcrypto-browser.test.mjs runs the same cases in
// Chromium.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { checkFixtures } from "./fleet-fixture-cases.mjs";
import * as core from "../lib/fleet/core/index.mjs";

const read = (f) => JSON.parse(readFileSync(new URL(f, import.meta.url), "utf8"));
const F = read("./fixtures/fleet-fixtures.json");
const RECOVERY_KNOWN = ["QIgcRL3kWMdpVNtbHP7lkw", "8f8Zi-ibteyHFwp-PnAVfGC6-_75Je6BNI9mNkG6PM0"];
const backend = core.webCrypto();
const loader = (name) => read(`../schema/fleet/${name}`);

// (first: the tests after it use what it installs)
test("schemas of another revision are refused and install nothing; then the backend and the frozen schemas install", () => {
  const other = (n) => (n === "reasons.json" ? { ...loader(n), freeze: "0".repeat(64) } : loader(n));
  assert.throws(() => core.useSchemas(other), /frozen revision/);
  const otherSchema = (n) => (n === "fleet.schema.json" ? { ...loader(n), $comment: "r2.2" } : loader(n));
  assert.throws(() => core.useSchemas(otherSchema), /frozen revision/);
  assert.throws(() => core.bodyValidator("host-grant"), /no fleet schemas/);
  assert.throws(() => core.newId(), /no fleet crypto backend/);
  core.useCrypto(backend);
  core.useSchemas(loader);
  assert.equal(typeof core.bodyValidator("host-grant"), "function");
});

test("every case, through the core with the WebCrypto backend", async () => {
  const { bad, n } = await checkFixtures(core, F);
  assert.deepEqual(bad, []);
  assert.ok(n > 80, `${n} cases`);
});

test("one backend and one schema set per process: the same again is a no-op, any other is refused", () => {
  core.useCrypto(backend);
  core.useSchemas(loader);
  assert.throws(() => core.useCrypto(core.webCrypto()), /already installed/);
  assert.throws(() => core.useSchemas((n) => loader(n)), /already installed/);
});

test("keys, ids, recovery and sealing: the fixtures' known answers", async () => {
  // RFC 8032 test 1: the seed, its public key and its signature of the empty message
  const hex = (h) => Uint8Array.from(h.match(/../g), (x) => parseInt(x, 16));
  const k = await core.keyFromSeed(hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"));
  assert.equal(core.b64(k.raw), core.b64(hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")));
  const sig = await k.sign(new Uint8Array(0));
  assert.equal(core.b64(sig), core.b64(hex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")));
  assert.equal(await core.verifyStrict(k.raw, new Uint8Array(0), sig), true);
  // the recovery key a fixed code derives for the fixtures' fleet (HKDF-SHA256): fleet-chain.test.mjs pins the same
  // answer for Node's backend
  const fleet = F.ids.fleet, code = core.idOfBytes(new Uint8Array(16).fill(7));
  const rk = await core.recoveryKey(code, fleet);
  assert.deepEqual([rk.key, core.b64(rk.raw)], RECOVERY_KNOWN);
  // a sealed envelope opens; a byte changed in its signature doesn't
  const signer = { kind: "device", id: core.newId(), alg: "ed25519", key: k.key };
  const bytes = await core.seal("sb.revocation.v1", signer, { fleet, aud: F.aud, chain_seq: 0, what: "host", id: fleet, host: fleet, gen: 1, at_ms: 1 }, k);
  const opened = await core.open(bytes, { aud: F.aud, fleet, resolveKey: async () => k.raw });
  assert.equal(opened.body.gen, 1);
  const env = JSON.parse(new TextDecoder().decode(bytes));
  const flipped = core.unb64(env.sig, 64); flipped[5] ^= 1;
  const forged = new TextEncoder().encode(core.canonText({ ...env, sig: core.b64(flipped) }));
  await assert.rejects(core.open(forged, { aud: F.aud, fleet, resolveKey: () => k.raw }), (e) => e.code === "bad_signature");
});

test("the WebCrypto backend's verify is a boolean: false for bytes it can't use, never a throw", async () => {
  const k = await core.keyFromSeed(new Uint8Array(32).fill(5)), msg = new Uint8Array([1]), sig = await k.sign(msg);
  const offCurve = new Uint8Array(32); offCurve[0] = 2; // (y = 2 has no x on the curve: the strict rules pass it)
  assert.equal(core.strictShape(offCurve, sig), true);
  assert.equal(await core.verifyStrict(offCurve, msg, sig), false);
  for (const [raw, s] of [[k.raw.subarray(0, 31), sig], [k.raw, sig.subarray(0, 63)], [new Uint8Array(0), new Uint8Array(0)], [offCurve, sig]])
    assert.equal(await backend.ed25519Verify(raw, msg, s), false);
  assert.equal(await backend.ed25519Verify(k.raw, msg, sig), true);
});

test("random bytes and SHA-256: the sizes asked for, and a known hash", async () => {
  assert.equal(core.random(16).length, 16);
  assert.equal((await core.sha256(new Uint8Array(0))).length, 32);
  assert.equal(await core.sha256b64(new TextEncoder().encode("abc")), "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0");
});
