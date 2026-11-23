// The browser channel's Noise (lib/fleet/channel/noise.mjs; design agent-autonomous-browser-channel.md r4 §2):
// Noise_IK_25519_ChaChaPoly_SHA256 against two independent implementations' known answers, one role per object,
// single-use handshakes, split transport halves, the exact nonce cap, and an all-zero DH result refused on every token.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import { FleetError } from "../lib/fleet/index.mjs";
import { PROTOCOL, MAX_MESSAGE, atNonce, initiator, responder, x25519Key, x25519KeyFromPrivate, x25519Generate } from "../lib/fleet/channel/noise.mjs";

const V = JSON.parse(readFileSync(new URL("./fixtures/noise-ik-25519-chachapoly-sha256.json", import.meta.url), "utf8")).vectors;
const hx = (h) => Uint8Array.from(Buffer.from(h, "hex")), toHex = (b) => Buffer.from(b).toString("hex");
const code = (fn) => { try { fn(); } catch (e) { if (e instanceof FleetError) return e.code; throw e; } return "ok"; };
const EMPTY = new Uint8Array(0), P = new TextEncoder().encode("prologue");

test("known answers: cacophony's and snow's vectors for exactly this protocol, every message, both roles, and the handshake hash", () => {
  assert.deepEqual(V.map((v) => v.source), ["cacophony", "snow"]);
  for (const v of V) {
    assert.equal(v.protocol_name, PROTOCOL);
    const I = initiator({ s: x25519KeyFromPrivate(hx(v.init_static)), rs: hx(v.init_remote_static), prologue: hx(v.init_prologue), ephemeral: x25519KeyFromPrivate(hx(v.init_ephemeral)) });
    const R = responder({ s: x25519KeyFromPrivate(hx(v.resp_static)), prologue: hx(v.resp_prologue), ephemeral: x25519KeyFromPrivate(hx(v.resp_ephemeral)) });
    const m = v.messages;
    const m1 = I.writeMessage1(hx(m[0].payload));
    assert.equal(toHex(m1), m[0].ciphertext, `${v.source}: message 1`);
    const r1 = R.readMessage1(m1);
    assert.equal(toHex(r1.payload), m[0].payload);
    assert.equal(toHex(r1.rs), toHex(x25519KeyFromPrivate(hx(v.init_static)).raw), "the responder learns the initiator's static key");
    const r2 = R.writeMessage2(hx(m[1].payload));
    assert.equal(toHex(r2.message), m[1].ciphertext, `${v.source}: message 2`);
    const i2 = I.readMessage2(r2.message);
    assert.equal(toHex(i2.payload), m[1].payload);
    if (v.handshake_hash) assert.deepEqual([toHex(i2.handshakeHash), toHex(r2.handshakeHash)], [v.handshake_hash, v.handshake_hash]);
    for (let j = 2; j < m.length; j++) {
      const [tx, rx] = j % 2 === 0 ? [i2.send, r2.receive] : [r2.send, i2.receive];
      const ct = tx.encrypt(EMPTY, hx(m[j].payload));
      assert.equal(toHex(ct), m[j].ciphertext, `${v.source}: transport ${j}`);
      assert.equal(toHex(rx.decrypt(EMPTY, ct)), m[j].payload);
    }
  }
});

function pair(extra = {}) {
  const si = x25519Generate(), sr = x25519Generate();
  const I = initiator({ s: si, rs: sr.raw, prologue: P, ...extra.i });
  const R = responder({ s: sr, prologue: P, ...extra.r });
  return { si, sr, I, R };
}

test("one role per object: an initiator writes 1 and reads 2, a responder reads 1 and writes 2; transport halves encrypt or decrypt", () => {
  const { I, R } = pair();
  assert.deepEqual(Object.keys(I).sort(), ["readMessage2", "writeMessage1"]);
  assert.deepEqual(Object.keys(R).sort(), ["readMessage1", "writeMessage2"]);
  assert.ok(Object.isFrozen(I) && Object.isFrozen(R));
  const m1 = I.writeMessage1(EMPTY);
  R.readMessage1(m1);
  const r2 = R.writeMessage2(EMPTY);
  const i2 = I.readMessage2(r2.message);
  for (const half of [i2.send, r2.send]) { assert.equal(typeof half.encrypt, "function"); assert.equal(half.decrypt, undefined); assert.ok(Object.isFrozen(half)); }
  for (const half of [i2.receive, r2.receive]) { assert.equal(typeof half.decrypt, "function"); assert.equal(half.encrypt, undefined); assert.ok(Object.isFrozen(half)); }
  assert.deepEqual(r2.receive.decrypt(EMPTY, i2.send.encrypt(EMPTY, Uint8Array.of(1))), Uint8Array.of(1));
  assert.deepEqual(i2.receive.decrypt(EMPTY, r2.send.encrypt(EMPTY, Uint8Array.of(2))), Uint8Array.of(2));
});

test("a handshake is single-use and in order, and an order error kills it like any refusal (a fresh pair per row)", () => {
  // the responder: message 2 first; then even the honest message 1 is refused
  { const { I, R } = pair(); const m1 = I.writeMessage1(EMPTY);
    assert.equal(code(() => R.writeMessage2(EMPTY)), "bad_form", "message 2 before message 1");
    assert.equal(code(() => R.readMessage1(m1)), "bad_form", "dead: the honest message 1");
    assert.equal(code(() => R.writeMessage2(EMPTY)), "bad_form", "dead: message 2 after it"); }
  // the initiator: reading message 2 first; then writing message 1 is refused
  { const { I } = pair();
    assert.equal(code(() => I.readMessage2(new Uint8Array(48))), "bad_form", "reading message 2 before writing message 1");
    assert.equal(code(() => I.writeMessage1(EMPTY)), "bad_form", "dead: message 1");
    assert.equal(code(() => I.readMessage2(new Uint8Array(48))), "bad_form", "dead: message 2 after it"); }
  // a repeated step: refused, and the next correct step too
  { const { I, R } = pair(); const m1 = I.writeMessage1(EMPTY);
    assert.equal(code(() => I.writeMessage1(EMPTY)), "bad_form", "message 1 again");
    R.readMessage1(m1);
    const m2 = R.writeMessage2(EMPTY).message;
    assert.equal(code(() => I.readMessage2(m2)), "bad_form", "dead: the honest message 2"); }
  { const { I, R } = pair(); R.readMessage1(I.writeMessage1(EMPTY));
    assert.equal(code(() => R.readMessage1(new Uint8Array(96))), "bad_form", "message 1 read again");
    assert.equal(code(() => R.writeMessage2(EMPTY)), "bad_form", "dead: message 2"); }
  { const { I, R } = pair(); R.readMessage1(I.writeMessage1(EMPTY)); R.writeMessage2(EMPTY);
    assert.equal(code(() => R.writeMessage2(EMPTY)), "bad_form", "message 2 again"); }
});

test("a refused message kills the handshake object: a tampered message 1, then the honest one, both refused", () => {
  const si = x25519Generate(), sr = x25519Generate();
  const I = initiator({ s: si, rs: sr.raw, prologue: P });
  const R = responder({ s: sr, prologue: P });
  const m1 = I.writeMessage1(EMPTY);
  const bad = Uint8Array.from(m1); bad[40] ^= 1;
  assert.equal(code(() => R.readMessage1(bad)), "bad_signature");
  assert.equal(code(() => R.readMessage1(m1)), "bad_form", "dead: the honest message is refused too");
  assert.equal(code(() => R.writeMessage2(EMPTY)), "bad_form");
  // the same on the initiator: a tampered message 2
  const R2 = responder({ s: sr, prologue: P });
  const I2 = initiator({ s: si, rs: sr.raw, prologue: P });
  R2.readMessage1(I2.writeMessage1(EMPTY));
  const r2 = R2.writeMessage2(EMPTY).message;
  const bad2 = Uint8Array.from(r2); bad2[r2.length - 1] ^= 1;
  assert.equal(code(() => I2.readMessage2(bad2)), "bad_signature");
  assert.equal(code(() => I2.readMessage2(r2)), "bad_form");
});

test("a mismatched prologue or responder key fails the handshake", () => {
  const si = x25519Generate(), sr = x25519Generate(), other = x25519Generate();
  assert.equal(code(() => responder({ s: sr, prologue: new TextEncoder().encode("other") }).readMessage1(initiator({ s: si, rs: sr.raw, prologue: P }).writeMessage1(EMPTY))), "bad_signature");
  assert.equal(code(() => responder({ s: other, prologue: P }).readMessage1(initiator({ s: si, rs: sr.raw, prologue: P }).writeMessage1(EMPTY))), "bad_signature");
});

test("transport: a gap, a reorder or a forged message is refused, and the receiving half is dead after it", () => {
  const { I, R } = pair();
  R.readMessage1(I.writeMessage1(EMPTY));
  const r2 = R.writeMessage2(EMPTY);
  const i2 = I.readMessage2(r2.message);
  const a = i2.send.encrypt(EMPTY, Uint8Array.of(1)), b = i2.send.encrypt(EMPTY, Uint8Array.of(2));
  assert.equal(code(() => r2.receive.decrypt(EMPTY, b)), "bad_signature", "b before a");
  assert.equal(code(() => r2.receive.decrypt(EMPTY, a)), "bad_form", "dead");
  const { I: I3, R: R3 } = pair();
  R3.readMessage1(I3.writeMessage1(EMPTY));
  const x2 = R3.writeMessage2(EMPTY), y2 = I3.readMessage2(x2.message);
  const c = y2.send.encrypt(EMPTY, Uint8Array.of(3)); c[0] ^= 1;
  assert.equal(code(() => x2.receive.decrypt(EMPTY, c)), "bad_signature", "forged");
  assert.equal(code(() => y2.send.encrypt(EMPTY, new Uint8Array(MAX_MESSAGE - 16 + 1))), "limit", "over 65,535 bytes");
  assert.equal(y2.send.encrypt(EMPTY, new Uint8Array(MAX_MESSAGE - 16)).length, MAX_MESSAGE, "exactly 65,535");
});

test("the nonce is an exact counter: the last allowed nonce works, the next is refused (limit), on both halves", () => {
  const k = new Uint8Array(32).fill(7), start = Number.MAX_SAFE_INTEGER - 1;
  const tx = atNonce.sender(k, start), rx = atNonce.receiver(k, start);
  const ct = tx.encrypt(EMPTY, Uint8Array.of(9));
  assert.equal(tx.nonce, Number.MAX_SAFE_INTEGER);
  assert.equal(code(() => tx.encrypt(EMPTY, Uint8Array.of(9))), "limit");
  assert.deepEqual(rx.decrypt(EMPTY, ct), Uint8Array.of(9));
  assert.equal(code(() => rx.decrypt(EMPTY, ct)), "limit");
  // the nonce's high bytes are exact: a message at 2^32 opens only at 2^32
  const a = atNonce.sender(k, 2 ** 32).encrypt(EMPTY, Uint8Array.of(1));
  assert.deepEqual(atNonce.receiver(k, 2 ** 32).decrypt(EMPTY, a), Uint8Array.of(1));
  assert.equal(code(() => atNonce.receiver(k, 2 ** 32 + 1).decrypt(EMPTY, a)), "bad_signature");
});

test("an all-zero DH result is refused on every token (es, ss, ee, se), on both sides, whatever the key returns", () => {
  const zero = new Uint8Array(32);
  // a key that answers all zeros for one peer, honestly for others
  const zeroFor = (key, peer) => ({ raw: key.raw, dh: (p) => (peer === "*" || Buffer.compare(Buffer.from(p), Buffer.from(peer)) === 0 ? zero : key.dh(p)) });
  const si = x25519Generate(), sr = x25519Generate(), ei = x25519Generate(), er = x25519Generate();
  const run = ({ is = si, rsK = sr, ie = ei, re = er }) => {
    const I = initiator({ s: is, rs: sr.raw, prologue: P, ephemeral: ie });
    const R = responder({ s: rsK, prologue: P, ephemeral: re });
    let m1, m2;
    try { m1 = I.writeMessage1(EMPTY); } catch (e) { return ["i1", e.code]; }
    try { R.readMessage1(m1); } catch (e) { return ["r1", e.code]; }
    try { m2 = R.writeMessage2(EMPTY).message; } catch (e) { return ["r2", e.code]; }
    try { I.readMessage2(m2); } catch (e) { return ["i2", e.code]; }
    return ["ok"];
  };
  assert.deepEqual(run({}), ["ok"]);
  assert.deepEqual(run({ ie: zeroFor(ei, sr.raw) }), ["i1", "bad_signature"], "es, initiator");
  assert.deepEqual(run({ is: zeroFor(si, sr.raw) }), ["i1", "bad_signature"], "ss, initiator");
  assert.deepEqual(run({ rsK: zeroFor(sr, ei.raw) }), ["r1", "bad_signature"], "es, responder");
  assert.deepEqual(run({ rsK: zeroFor(sr, si.raw) }), ["r1", "bad_signature"], "ss, responder");
  assert.deepEqual(run({ re: zeroFor(er, ei.raw) }), ["r2", "bad_signature"], "ee, responder");
  assert.deepEqual(run({ re: zeroFor(er, si.raw) }), ["r2", "bad_signature"], "se, responder");
  assert.deepEqual(run({ ie: zeroFor(ei, er.raw) }), ["i2", "bad_signature"], "ee, initiator");
  assert.deepEqual(run({ is: zeroFor(si, er.raw) }), ["i2", "bad_signature"], "se, initiator");
  // and a real all-zero point on the wire, as message 1's ephemeral key
  const I = initiator({ s: si, rs: sr.raw, prologue: P });
  const m1 = I.writeMessage1(EMPTY); m1.fill(0, 0, 32);
  assert.equal(code(() => responder({ s: sr, prologue: P }).readMessage1(m1)), "bad_signature");
});

test("X25519 keys: only an X25519 private KeyObject; the public half is derived, never taken on trust", () => {
  assert.throws(() => x25519Key(generateKeyPairSync("ed25519").privateKey), /X25519/);
  assert.throws(() => x25519Key(generateKeyPairSync("x25519").publicKey), /X25519/);
  const k = generateKeyPairSync("x25519");
  assert.equal(Buffer.from(x25519Key(k.privateKey).raw).toString("base64url"), k.publicKey.export({ format: "jwk" }).x);
});
