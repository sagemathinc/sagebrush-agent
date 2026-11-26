// The shared fleet vectors (test/fixtures/fleet-fixtures.json): the committed file is exactly what the generator
// builds (byte for byte), and this package gives every case its expected result: the core with Node's backend here,
// and Node's synchronous API on the cases it covers. fleet-webcrypto.test.mjs runs the same cases with the WebCrypto
// backend; other implementations (the page's mirror, the Python verifier) run the same file.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { build } from "./make-fleet-fixtures.mjs";
import { checkFixtures } from "./fleet-fixture-cases.mjs";
import { FleetError, FREEZE, REASONS, canonText, unb64, verifyStrict, open, replayChain, deviceKey } from "../lib/fleet/index.mjs";
import * as core from "../lib/fleet/core/index.mjs";

const FILE = new URL("./fixtures/fleet-fixtures.json", import.meta.url);
const text = readFileSync(FILE, "utf8");
const F = JSON.parse(text);
const enc = (s) => new TextEncoder().encode(s);
const result = (fn) => { try { fn(); return "ok"; } catch (e) { if (e instanceof FleetError) return e.code; throw e; } };
const ctx = { aud: F.aud, fleet: F.ids.fleet };

test("the committed fixtures are exactly what the generator builds, and pin the frozen design", async () => {
  assert.equal(text, canonText(await build(), 4 << 20) + "\n");
  assert.equal(F.freeze, FREEZE.sha256);
  // every expected result is "ok" or a registered reason code
  const codes = [];
  const walk = (v) => { if (Array.isArray(v)) v.forEach(walk); else if (v && typeof v === "object") { if (typeof v.expect === "string") codes.push(v.expect); Object.values(v).forEach(walk); } };
  walk(F);
  assert.ok(codes.length > 50, `${codes.length} cases`);
  for (const c of codes) assert.ok(c === "ok" || REASONS.includes(c), c);
});

test("every case, through the core with Node's backend", async () => {
  const { bad, n } = await checkFixtures(core, F);
  assert.deepEqual(bad, []);
  assert.ok(n > 80, `${n} cases`);
});

test("Node's synchronous API (the host stack's) agrees: strict Ed25519 and envelopes", async () => {
  for (const c of F.ed25519) assert.equal(verifyStrict(unb64(c.public, 32), unb64(c.msg_b64), unb64(c.sig, 64)), c.expect, c.name);
  const O = F.objects;
  const st = await replayChain(O.chain.map(enc), ctx);
  for (const c of O.envelopes) {
    const got = result(() => open(enc(c.bytes), { ...(c.ctx ?? ctx), resolveKey: (s, t, b) => deviceKey(st, s, b.chain_seq).raw }));
    assert.equal(got, c.expect, c.name);
  }
});

test("the fleet fingerprint vectors agree with an independent SHA-256 (node:crypto), and the first is the honest genesis", async () => {
  const { createHash } = await import("node:crypto");
  const sha = (b) => createHash("sha256").update(b).digest();
  assert.equal(F.fleet_fingerprints.length, 3);
  assert.equal(F.fleet_fingerprints[0].genesis, F.objects.chain[0]);
  assert.equal(F.fleet_fingerprints[0].fleet, F.ids.fleet);
  const fulls = new Set();
  for (const c of F.fleet_fingerprints) {
    const want = sha(Buffer.concat([Buffer.from("sagebrush.fp.v1\nfleet\n" + c.fleet + "\n"), sha(Buffer.from(c.genesis, "utf8"))]));
    assert.equal(c.full, want.toString("base64url"), c.name);
    assert.match(c.shown, /^[a-z2-7]{4}(-[a-z2-7]{4}){4}$/, c.name);
    fulls.add(c.full);
  }
  assert.equal(fulls.size, 3, "each case gives its own fingerprint");
});
