// The shared fleet vectors (test/fixtures/fleet-fixtures.json): the committed file is exactly what the generator
// builds (byte for byte), and this package gives every case its expected result. Other implementations (the page's
// mirror, the Python verifier) run the same file.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { build } from "./make-fleet-fixtures.mjs";
import { FleetError, isId, unb64 } from "../lib/fleet/bytes.mjs";
import { canonText, parseCanonical } from "../lib/fleet/canonical.mjs";
import { verifyStrict } from "../lib/fleet/ed25519.mjs";
import { open } from "../lib/fleet/envelope.mjs";
import { apply, deviceKey, replay, serviceKeyAt } from "../lib/fleet/chain.mjs";
import { verifyApproval, verifyGrant, verifyHostCert, verifyHostOp } from "../lib/fleet/verify.mjs";
import { FREEZE, REASONS } from "../lib/fleet/index.mjs";

const FILE = new URL("./fixtures/fleet-fixtures.json", import.meta.url);
const text = readFileSync(FILE, "utf8");
const F = JSON.parse(text);
const enc = (s) => new TextEncoder().encode(s);
const result = (fn) => { try { fn(); return "ok"; } catch (e) { if (e instanceof FleetError) return e.code; throw e; } };
const ctx = { aud: F.aud, fleet: F.ids.fleet };

test("the committed fixtures are exactly what the generator builds, and pin the frozen design", () => {
  assert.equal(text, canonText(build(), 4 << 20) + "\n");
  assert.equal(F.freeze, FREEZE.sha256);
  // every expected result is "ok" or a registered reason code
  const codes = [];
  const walk = (v) => { if (Array.isArray(v)) v.forEach(walk); else if (v && typeof v === "object") { if (typeof v.expect === "string") codes.push(v.expect); Object.values(v).forEach(walk); } };
  walk(F);
  assert.ok(codes.length > 50, `${codes.length} cases`);
  for (const c of codes) assert.ok(c === "ok" || REASONS.includes(c), c);
});

test("canonical bytes, base64url and ids", () => {
  for (const c of F.canonical) assert.equal(result(() => parseCanonical(unb64(c.bytes_b64))), c.expect, c.name);
  for (const c of F.base64url) assert.equal(result(() => unb64(c.value, c.len)), c.expect, c.name);
  for (const c of F.ids_cases) assert.equal(isId(c.value) ? "ok" : "bad_form", c.expect, c.value);
});

test("Ed25519, strictly", () => {
  for (const c of F.ed25519) assert.equal(verifyStrict(unb64(c.public, 32), unb64(c.msg_b64), unb64(c.sig, 64)), c.expect, c.name);
});

test("the device chain: replays, refused extensions, pins", () => {
  for (const c of F.chain.cases) {
    const got = result(() => {
      const st = replay(c.entries.map(enc), ctx, c.pin ?? null);
      if (c.append) apply(st, enc(c.append), ctx);
    });
    assert.equal(got, c.expect, c.name);
  }
});

test("service keys over half-open intervals", () => {
  const st = replay(F.service_keys.chain.map(enc), ctx);
  for (const c of F.service_keys.cases) assert.equal(result(() => serviceKeyAt(st, c.signer, c.chain_seq)), c.expect, c.name);
});

test("envelopes, grants, host ops and approvals against the honest chain", () => {
  const O = F.objects;
  const st = replay(O.chain.map(enc), ctx);
  const cert = verifyHostCert(enc(O.host_cert), { ...ctx, chain: st });
  for (const c of O.envelopes) {
    const got = result(() => open(enc(c.bytes), { ...(c.ctx ?? ctx), resolveKey: (s, t, b) => deviceKey(st, s, b.chain_seq).raw }));
    assert.equal(got, c.expect, c.name);
  }
  for (const c of O.grants) {
    const current = c.current && { gen: c.current.gen, bytes: enc(c.current.bytes), body: JSON.parse(c.current.bytes).body };
    assert.equal(result(() => verifyGrant(enc(c.bytes), { ...ctx, chain: st, cert, current, now: F.now_ms })), c.expect, c.name);
  }
  for (const c of O.host_ops)
    assert.equal(result(() => verifyHostOp(enc(c.bytes), { ...ctx, chain: st, host: F.ids.host, currentGen: c.current_gen, now: F.now_ms, seenOp: () => false })), c.expect, c.name);
  for (const c of O.approvals)
    assert.equal(result(() => verifyApproval(enc(c.bytes), { ...ctx, chain: st, now: F.now_ms, expect: c.expect_op, current: c.current, used: (a) => c.used.includes(a) })), c.expect, c.name);
});
