// Fleet protocol core (agent-autonomous-schemas.md r2.2 §1): ids, canonical base64url, strict UTF-8, the canonical
// bytes with their two signing restrictions, strict Ed25519 (with an independent curve-arithmetic oracle for the
// small-order list), and the envelope's type, signer, audience and fleet binding.
import assert from "node:assert/strict";
import { test } from "node:test";
import { B64LEN, FleetError, bytesOfId, idOfBytes, isId, newId, unb64, utf8 } from "../lib/fleet/bytes.mjs";
import { canonText, parseCanonical } from "../lib/fleet/index.mjs";
import { canonicalPoint, checkPublicKey, keyFromSeed, keyId, smallOrder, strictShape, verifyStrict } from "../lib/fleet/ed25519.mjs";
import { open, seal, signedBytes, TYPES } from "../lib/fleet/envelope.mjs";
import { nodeCrypto, nodeSync } from "../lib/fleet/node-crypto.mjs";

const code = (fn) => { try { fn(); } catch (e) { if (e instanceof FleetError) return e.code; throw e; } return "ok"; };
const enc = (s) => new TextEncoder().encode(s);
const hex = (s) => Uint8Array.from(Buffer.from(s, "hex"));

test("ids: 26 base32 characters, 128 bits and 2 zero bits; round trip; the grammar is exact", () => {
  for (let i = 0; i < 200; i++) { const id = newId(); assert.ok(isId(id), id); assert.equal(idOfBytes(bytesOfId(id)), id); }
  assert.equal(idOfBytes(new Uint8Array(16)), "a".repeat(26));
  assert.equal(idOfBytes(new Uint8Array(16).fill(255)), "7".repeat(25) + "4");
  for (const bad of ["a".repeat(25), "a".repeat(27), "A".repeat(26), "a".repeat(25) + "b", "a".repeat(25) + "7", "a".repeat(24) + "1a", 7, null])
    assert.equal(isId(bad), false, String(bad));
  assert.equal(code(() => bytesOfId("a".repeat(25) + "b")), "bad_form");
});

test("base64url: exact lengths, no padding, zero pad bits, one spelling", () => {
  assert.deepEqual(B64LEN, { 16: 22, 32: 43, 64: 86 });
  const z = "A".repeat(43);
  assert.equal(unb64(z, 32).length, 32);
  assert.equal(code(() => unb64("A".repeat(42) + "B", 32)), "bad_form"); // (a non-zero pad bit)
  assert.equal(code(() => unb64(z + "=", 32)), "bad_form");
  assert.equal(code(() => unb64("A".repeat(44), 32)), "bad_form");
  assert.equal(code(() => unb64("A".repeat(42) + "+", 32)), "bad_form");
  assert.equal(code(() => unb64("A".repeat(85) + "A", 64)), "ok");
  assert.equal(code(() => unb64("A".repeat(85) + "B", 64)), "bad_form");
});

test("UTF-8: invalid bytes and a byte-order mark are refused", () => {
  assert.equal(utf8(enc("é😀")), "é😀");
  for (const b of [[0xff], [0xc0, 0x80], [0xed, 0xa0, 0x80], [0xe2, 0x82], [0xef, 0xbb, 0xbf, 0x7b, 0x7d]])
    assert.equal(code(() => utf8(Uint8Array.from(b))), "bad_form", JSON.stringify(b));
});

test("canonical bytes: canon's form; lone surrogates refused; received bytes must be exactly canonical", () => {
  assert.equal(canonText({ b: 1, a: [true, null, "x"] }), '{"a":[true,null,"x"],"b":1}');
  // (UTF-16 order: an astral key sorts before U+FFFF; a naive code-point sort would put it after)
  assert.equal(canonText({ "￿": 1, "😀": 2 }), '{"😀":2,"￿":1}');
  assert.equal(code(() => canonText({ a: "\ud800" })), "bad_form");
  assert.equal(code(() => canonText({ ["\udc00"]: 1 })), "bad_form");
  assert.equal(code(() => canonText({ a: 1.5 })), "bad_form");
  assert.equal(code(() => canonText({ a: 2 ** 53 })), "bad_form");
  assert.equal(canonText({ a: 2 ** 53 - 1, b: -(2 ** 53 - 1) }), `{"a":${2 ** 53 - 1},"b":${-(2 ** 53 - 1)}}`);
  const ok = enc('{"a":1,"b":"x"}');
  assert.deepEqual(parseCanonical(ok), { a: 1, b: "x" });
  for (const t of ['{"b":"x","a":1}', '{"a":1, "b":"x"}', '{"a":1,"a":2}', '{"a":1,"\\u0061":2}', '{"a":1.0}', '{"a":1e0}', '{"a":-0}', '{"a":"\\u00e9"}', '{"a":"\\ud800"}'])
    assert.equal(code(() => parseCanonical(enc(t))), "bad_form", t);
  assert.equal(code(() => parseCanonical(enc('{"a":"' + "x".repeat(70000) + '"}'))), "limit");
});

// ---- an independent oracle: Edwards25519 arithmetic in BigInt, used only by the tests
const p = (1n << 255n) - 19n, d = (-121665n * inv(121666n)) % p;
function inv(a) { return pow(((a % p) + p) % p, p - 2n); }
function pow(b, e) { let r = 1n; b %= p; while (e > 0n) { if (e & 1n) r = (r * b) % p; b = (b * b) % p; e >>= 1n; } return r; }
function decode(b) {
  const bb = Uint8Array.from(b); const s = bb[31] >> 7; bb[31] &= 127;
  let y = 0n; for (let i = 31; i >= 0; i--) y = (y << 8n) | BigInt(bb[i]);
  if (y >= p) return null;
  const u = (y * y - 1n + p) % p, v = (d * y * y + 1n) % p;
  let x = (u * pow(v, 3n) % p) * pow(u * pow(v, 7n) % p, (p - 5n) / 8n) % p;
  if ((v * x * x - u) % p !== 0n) { x = (x * pow(2n, (p - 1n) / 4n)) % p; if (((v * x * x - u) % p + p) % p !== 0n) return null; }
  if (x === 0n && s) return null;
  if ((x & 1n) !== BigInt(s)) x = p - x;
  return [x, y];
}
function add([x1, y1], [x2, y2]) {
  const t = (d * x1 * x2 % p) * y1 * y2 % p;
  return [((x1 * y2 + y1 * x2) % p) * inv(1n + t) % p, ((y1 * y2 + x1 * x2) % p) * inv((1n - t + p) % p) % p];
}
const times8 = (P) => { let Q = P; for (let i = 0; i < 3; i++) Q = add(Q, Q); return Q; };
const enc32 = (y, s) => { const b = new Uint8Array(32); let n = y; for (let i = 0; i < 32; i++) { b[i] = Number(n & 255n); n >>= 8n; } if (s) b[31] |= 128; return b; };

test("Ed25519: the small-order list is exactly the torsion points (checked by curve arithmetic), and keys are canonical", () => {
  // every candidate from the list decodes to a point P with 8P = identity
  const ys = [1n, p - 1n, 0n,
    BigInt("0x" + Buffer.from(hex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05")).reverse().toString("hex")),
    BigInt("0x" + Buffer.from(hex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a")).reverse().toString("hex"))];
  let torsion = 0;
  for (const y of ys) for (const s of [0, 1]) {
    const P = decode(enc32(y, s));
    if (!P) { assert.equal(canonicalPoint(enc32(y, s)), false, `undecodable ${y} ${s} isn't canonical`); continue; }
    const Q = times8(P);
    assert.deepEqual(Q, [0n, 1n], `8P is the identity for y=${y}`);
    assert.equal(smallOrder(enc32(y, s)), true);
    torsion++;
  }
  assert.equal(torsion, 8, "exactly eight torsion points decode");
  // a real key is neither
  const k = keyFromSeed(hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"));
  assert.notDeepEqual(times8(decode(k.raw)), [0n, 1n]);
  assert.equal(smallOrder(k.raw), false);
  assert.equal(code(() => checkPublicKey(enc32(p, 0))), "bad_signature"); // y = p: non-canonical
  assert.equal(code(() => checkPublicKey(enc32(1n, 0))), "bad_signature");
  assert.equal(code(() => checkPublicKey(k.raw)), "ok");
});

test("Ed25519: RFC 8032 test 1; S + L, a small-order key's forgery, a non-canonical R are refused on every Node", () => {
  const k = keyFromSeed(hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"));
  assert.equal(Buffer.from(k.raw).toString("hex"), "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
  const sig = k.sign(new Uint8Array(0));
  assert.equal(Buffer.from(sig).toString("hex"),
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
  assert.equal(verifyStrict(k.raw, new Uint8Array(0), sig), true);
  const L = (1n << 252n) + 27742317777372353535851937790883648493n;
  let S = 0n; for (let i = 63; i >= 32; i--) S = (S << 8n) | BigInt(sig[i]);
  const big = Uint8Array.from(sig); let n = S + L; for (let i = 32; i < 64; i++) { big[i] = Number(n & 255n); n >>= 8n; }
  assert.equal(verifyStrict(k.raw, new Uint8Array(0), big), false, "S + L");
  const ident = enc32(1n, 0), forged = new Uint8Array(64); forged.set(ident, 0);
  assert.equal(verifyStrict(ident, enc("any message"), forged), false, "identity key, R = identity, S = 0");
  const badR = Uint8Array.from(sig); badR.set(enc32(p + 1n > (1n << 255n) - 1n ? p : p, 0), 0);
  assert.equal(verifyStrict(k.raw, new Uint8Array(0), badR), false, "non-canonical R");
  assert.equal(keyId("ed25519", k.raw).length, 22);
  // the strict rules alone, with no library: every Node and browser refuses some of these itself, and which ones
  // differs by version, so the rules are checked here directly
  assert.equal(strictShape(k.raw, sig), true);
  assert.equal(strictShape(k.raw, big), false, "S + L");
  assert.equal(strictShape(k.raw, badR), false, "non-canonical R");
  assert.equal(strictShape(ident, forged), false, "a small-order key");
  assert.equal(strictShape(enc32(p, 0), sig), false, "a non-canonical key (y = p)");
  assert.equal(strictShape(k.raw.subarray(0, 31), sig), false);
  assert.equal(strictShape(k.raw, sig.subarray(0, 63)), false);
});

test("the backend's verify (Node's, sync and async) is a boolean: false for bytes it can't use, never a throw", async () => {
  const k = keyFromSeed(SEEDS.device), msg = enc("m"), sig = k.sign(msg);
  // (a y with no x on the curve: the strict rules pass it, the library says no)
  const offCurve = enc32(2n, 0);
  assert.equal(strictShape(offCurve, sig), true);
  assert.equal(verifyStrict(offCurve, msg, sig), false);
  for (const [raw, s] of [[k.raw.subarray(0, 31), sig], [k.raw, sig.subarray(0, 63)], [new Uint8Array(0), new Uint8Array(0)], [offCurve, sig]]) {
    assert.equal(nodeSync.ed25519Verify(raw, msg, s), false);
    assert.equal(await nodeCrypto.ed25519Verify(raw, msg, s), false);
  }
  assert.equal(await nodeCrypto.ed25519Verify(k.raw, msg, sig), true);
});

const AUD = "https://dev.sagebrush.space";
const SEEDS = { device: hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"), host: hex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb") };

test("envelope: the type and signer are in the signed bytes; signer kinds per type; audience and fleet bound", () => {
  const fleet = newId(), dev = keyFromSeed(SEEDS.device), host = keyFromSeed(SEEDS.host);
  const signer = { kind: "device", id: newId(), alg: "ed25519", key: dev.key };
  const body = { fleet, aud: AUD, at_ms: 1 };
  const bytes = seal("sb.host-op.v1", signer, body, dev);
  const ctx = { aud: AUD, fleet, resolveKey: (s) => (s.key === dev.key ? dev.raw : host.raw) };
  assert.equal(open(bytes, ctx).type, "sb.host-op.v1");
  assert.equal(new TextDecoder().decode(signedBytes("sb.host-op.v1", signer, body)).split("\n")[0], "sagebrush.sig.v1");
  // a host can't sign a grant; a device can't sign an ack; the service signs only acks
  assert.equal(code(() => seal("sb.host-grant.v1", { ...signer, kind: "host" }, body, host)), "bad_signature");
  assert.equal(code(() => seal("sb.grant-ack.v1", signer, body, dev)), "bad_signature");
  assert.equal(code(() => seal("sb.host-cert.v1", { ...signer, kind: "service" }, body, dev)), "bad_signature");
  // the same signature can't be moved to another type, signer or body
  const env = JSON.parse(new TextDecoder().decode(bytes));
  const swap = (e) => enc(canonText(e));
  assert.equal(code(() => open(swap({ ...env, type: "sb.revocation.v1" }), ctx)), "bad_signature");
  assert.equal(code(() => open(swap({ ...env, signer: { ...signer, id: newId() } }), ctx)), "bad_signature");
  assert.equal(code(() => open(swap({ ...env, body: { ...body, at_ms: 2 } }), ctx)), "bad_signature");
  // audience and fleet
  assert.equal(code(() => open(bytes, { ...ctx, aud: "https://sagebrush.space" })), "bad_audience");
  assert.equal(code(() => open(bytes, { ...ctx, fleet: newId() })), "bad_form");
  // form: whitespace, an extra field, v 2
  assert.equal(code(() => open(enc(new TextDecoder().decode(bytes).replace(',"type"', ', "type"')), ctx)), "bad_form");
  assert.equal(code(() => open(swap({ ...env, extra: 1 }), ctx)), "bad_form");
  assert.equal(code(() => open(swap({ ...env, v: 2 }), ctx)), "bad_form");
  // sig2 exists only on a device-chain "add": another type whose body says op "add" can't carry one
  const addish = seal("sb.revocation.v1", signer, { ...body, op: "add" }, dev);
  const withSig2 = swap({ ...JSON.parse(new TextDecoder().decode(addish)), sig2: env.sig });
  assert.equal(code(() => open(addish, ctx)), "ok");
  assert.equal(code(() => open(withSig2, ctx)), "bad_form");
  assert.equal(Object.keys(TYPES).length, 16);
});
