// The device chain (r2.3 §2, §1.7): tiers from the enrolled entry, the recovery key as native, recovery carrying its
// rotation, removal, policy, the predecessor rule for history, pins, forks and rollbacks, the removal rule for
// objects outside the chain, and service keys over half-open intervals.
import assert from "node:assert/strict";
import { test } from "node:test";
import {
  FleetError, b64, newId, idOfBytes, sha256b64, keyFromSeed, seal, sealAdd, applyChainEntry as apply, deviceKey, replayChain as replay, requireTier,
  serviceKeyAt, newRecoveryCode, readCode, recoveryKey, showCode,
} from "../lib/fleet/index.mjs";
import { seal as sealAsync } from "../lib/fleet/core/envelope.mjs";

const AUD = "https://dev.sagebrush.space";
const code = async (fn) => { try { await fn(); } catch (e) { if (e instanceof FleetError) return e.code; throw e; } return "ok"; };
let n = 1;
const key = () => keyFromSeed(new Uint8Array(32).fill(n++));

/** A small chain builder: each call signs the next entry against the current head. */
function chain() {
  const fleet = newId(), ctx = { aud: AUD, fleet };
  const entries = [];
  let state = null;
  const devs = new Map();
  const dev = (tier, name = tier) => { const k = key(); return { id: newId(), k, tier, entry: { id: null, alg: "ed25519", key: b64(k.raw), name, tier } }; };
  const body = (op, extra) => ({ fleet, aud: AUD, seq: state ? state.seq + 1 : 0, prev: state ? state.head : "", op, at_ms: 1000, auth_time_ms: 1000, ...extra });
  const signerOf = (d) => ({ kind: "device", id: d.id, alg: "ed25519", key: d.k.key });
  const push = async (bytes) => { const r = await apply(state, bytes, ctx); state = r.state; entries.push(bytes); return r; };
  const t = {
    fleet, ctx, entries, get state() { return state; }, devs,
    dev(tier) { const d = dev(tier); d.entry.id = d.id; return d; },
    genesis(d, rec) { devs.set(d.id, d); return push(seal("sb.device-chain.v1", signerOf(d), body("genesis", { device: d.entry, recovery_key: { alg: "ed25519", key: b64(rec.raw) } }), d.k)); },
    sign(by, op, extra) { return seal("sb.device-chain.v1", signerOf(by), body(op, extra), by.k); },
    // (the core's async seal: a recovery key from recoveryKey() signs through the backend)
    signRecovery(rec, op, extra) { return sealAsync("sb.device-chain.v1", { kind: "recovery", id: fleet, alg: "ed25519", key: rec.key }, body(op, extra), rec); },
    add(by, d, { badSig2 = false } = {}) {
      const nk = badSig2 ? key() : d.k;
      return sealAdd(signerOf(by), body("add", { device: d.entry }), by.k, nk);
    },
    push, signerOf,
  };
  return t;
}

test("recovery code: one form, normalized input, a deterministic key per fleet", async () => {
  const c = newRecoveryCode();
  assert.equal(readCode(showCode(c).toUpperCase().replace(/-/g, " - ")), c);
  const fleet = newId();
  assert.equal((await recoveryKey(c, fleet)).key, (await recoveryKey(showCode(c), fleet)).key);
  assert.notEqual((await recoveryKey(c, fleet)).key, (await recoveryKey(c, newId())).key, "the fleet id salts it");
  assert.equal(await code(() => readCode("not a code")), "bad_form");
  // a known answer, code 0x07 x 16 for the fixtures' fleet (fleet-webcrypto.test.mjs pins the same for WebCrypto)
  const known = await recoveryKey(idOfBytes(new Uint8Array(16).fill(7)), "d4tc2nb3ijevav26mvwhg6ubra");
  assert.deepEqual([known.key, b64(known.raw)], ["QIgcRL3kWMdpVNtbHP7lkw", "8f8Zi-ibteyHFwp-PnAVfGC6-_75Je6BNI9mNkG6PM0"]);
});

test("browser genesis, browser adds browser; a browser can't add a native device; the countersignature is checked", async () => {
  const c = chain(), b1 = c.dev("browser"), rec = key();
  await c.genesis(b1, rec);
  const b2 = c.dev("browser");
  await c.push(c.add(b1, b2));
  const nat = c.dev("native");
  assert.equal(await code(() => apply(c.state, c.add(b1, nat), c.ctx)), "device_tier");
  const b3 = c.dev("browser");
  assert.equal(await code(() => apply(c.state, c.add(b1, b3, { badSig2: true }), c.ctx)), "bad_signature");
  assert.equal(await code(() => apply(c.state, c.add(b1, b2), c.ctx)), "bad_form", "a device id twice");
});

test("genesis: the signer's key id must be its device key's, or the entry is refused before its signature counts", async () => {
  const c = chain(), d = c.dev("native"), rec = key(), other = key();
  const body = { fleet: c.fleet, aud: AUD, seq: 0, prev: "", op: "genesis", at_ms: 1000, auth_time_ms: 1000, device: d.entry, recovery_key: { alg: "ed25519", key: b64(rec.raw) } };
  // (signed by the device's own key, but naming another key's id as the signer's)
  const bytes = seal("sb.device-chain.v1", { ...c.signerOf(d), key: other.key }, body, d.k);
  assert.equal(await code(() => apply(null, bytes, c.ctx)), "bad_signature");
  assert.equal(await code(() => apply(null, seal("sb.device-chain.v1", c.signerOf(d), body, d.k), c.ctx)), "ok");
});

test("recovery: signed by the recovery key, enrolls a native device, carries its rotation; the old key is spent", async () => {
  const c = chain(), b1 = c.dev("browser"), rec = await recoveryKey(newRecoveryCode(), c.fleet);
  await c.genesis(b1, rec);
  const nat = c.dev("native"), rec2 = key();
  await c.push(await c.signRecovery(rec, "recover", { device: nat.entry, recovery_key: { alg: "ed25519", key: b64(rec2.raw) } }));
  assert.equal(c.state.devices.get(nat.id).tier, "native");
  // the old key again: refused
  const nat2 = c.dev("native"), rec3 = key();
  assert.equal(await code(async () => apply(c.state, await c.signRecovery(rec, "recover", { device: nat2.entry, recovery_key: { alg: "ed25519", key: b64(rec3.raw) } }), c.ctx)), "recovery_key_mismatch");
  // without a rotation: the schema refuses it; naming the same key: refused
  const bodyless = await c.signRecovery(rec2, "recover", { device: nat2.entry });
  assert.equal(await code(() => apply(c.state, bodyless, c.ctx)), "bad_form");
  assert.equal(await code(async () => apply(c.state, await c.signRecovery(rec2, "recover", { device: nat2.entry, recovery_key: { alg: "ed25519", key: b64(rec2.raw) } }), c.ctx)), "bad_form");
  // a browser recovery keeps the browser tier; a later rotate-recovery by that browser device is refused
  const b9 = c.dev("browser"), rec4 = key();
  await c.push(await c.signRecovery(rec2, "recover", { device: b9.entry, recovery_key: { alg: "ed25519", key: b64(rec4.raw) } }));
  assert.equal(c.state.devices.get(b9.id).tier, "browser");
  assert.equal(await code(() => apply(c.state, c.sign(b9, "rotate-recovery", { recovery_key: { alg: "ed25519", key: b64(key().raw) } }), c.ctx)), "device_tier");
  await c.push(c.sign(nat, "rotate-recovery", { recovery_key: { alg: "ed25519", key: b64(key().raw) } }));
  // only the recovery key signs a recover: an enrolled device (even native) can't enroll through it
  const nat3 = c.dev("native");
  assert.equal(await code(() => apply(c.state, c.sign(nat, "recover", { device: nat3.entry, recovery_key: { alg: "ed25519", key: b64(key().raw) } }), c.ctx)), "recovery_key_mismatch");
});

test("removal and policy: tiers rule; no self-removal; a removed device signs nothing more; history still replays", async () => {
  const c = chain(), nat = c.dev("native"), rec = key();
  await c.genesis(nat, rec);
  const b1 = c.dev("browser");
  await c.push(c.add(nat, b1));
  assert.equal(await code(() => apply(c.state, c.sign(b1, "remove", { remove: nat.id, regrants: [] }), c.ctx)), "device_tier");
  assert.equal(await code(() => apply(c.state, c.sign(b1, "remove", { remove: b1.id, regrants: [] }), c.ctx)), "bad_form");
  await c.push(c.sign(b1, "policy", { policy: { require_native_for_widening: true } }));
  assert.equal(await code(() => apply(c.state, c.sign(b1, "policy", { policy: { require_native_for_widening: false } }), c.ctx)), "device_tier");
  const regrant = { kind: "grant", host: newId(), gen: 7, sha256: sha256b64(new Uint8Array([9])) };
  const r = await c.push(c.sign(nat, "remove", { remove: b1.id, regrants: [regrant] }));
  assert.deepEqual(r.entry.regrants, [regrant]);
  assert.equal(await code(() => apply(c.state, c.sign(b1, "policy", { policy: { require_native_for_widening: true } }), c.ctx)), "device_unknown");
  // the removed device's own earlier entries still verify: history is checked at each predecessor
  assert.equal((await replay(c.entries, c.ctx)).seq, c.state.seq);
  await c.push(c.sign(nat, "policy", { policy: { require_native_for_widening: false } }));
});

test("objects outside the chain: enrolled at chain_seq and still at the head; removal revokes at once; tier policy", async () => {
  const c = chain(), nat = c.dev("native"), rec = key();
  await c.genesis(nat, rec);
  const b1 = c.dev("browser");
  await c.push(c.add(nat, b1));
  const atAdd = c.state.seq;
  assert.equal(deviceKey(c.state, c.signerOf(b1), atAdd).tier, "browser");
  assert.equal(await code(() => deviceKey(c.state, c.signerOf(b1), atAdd - 1)), "device_unknown", "not yet enrolled then");
  assert.equal(await code(() => deviceKey(c.state, c.signerOf(b1), atAdd + 5)), "device_unknown", "fetch first");
  assert.equal(await code(() => requireTier(c.state, c.state.devices.get(b1.id), true)), "ok", "policy off");
  await c.push(c.sign(nat, "policy", { policy: { require_native_for_widening: true } }));
  assert.equal(await code(() => requireTier(c.state, c.state.devices.get(b1.id), true)), "device_tier");
  assert.equal(await code(() => requireTier(c.state, c.state.devices.get(b1.id), false)), "ok", "narrowing needs no tier");
  await c.push(c.sign(nat, "remove", { remove: b1.id, regrants: [] }));
  assert.equal(await code(() => deviceKey(c.state, c.signerOf(b1), atAdd)), "device_removed", "a grant signed before the removal loses its force");
});

test("pins: a fork, a rollback, a skipped seq and a wrong prev are chain_fork; genesis first and once", async () => {
  const c = chain(), nat = c.dev("native"), rec = key();
  await c.genesis(nat, rec);
  await c.push(c.sign(nat, "policy", { policy: { require_native_for_widening: true } }));
  const pin = { seq: 1, hash: c.state.head };
  await c.push(c.sign(nat, "policy", { policy: { require_native_for_widening: false } }));
  assert.equal((await replay(c.entries, c.ctx, pin)).seq, 2);
  assert.equal(await code(() => replay(c.entries.slice(0, 1), c.ctx, pin)), "chain_fork", "rollback");
  // another entry at seq 1 (signed honestly, but a different body): a fork against the pin
  const c2 = { ...c };
  const forked = [c.entries[0]];
  let st = (await apply(null, c.entries[0], c.ctx)).state;
  const alt = seal("sb.device-chain.v1", c.signerOf(nat), { fleet: c.fleet, aud: AUD, seq: 1, prev: st.head, op: "policy", at_ms: 2000, auth_time_ms: 2000, policy: { require_native_for_widening: true } }, nat.k);
  forked.push(alt);
  assert.equal(await code(() => replay(forked, c.ctx, pin)), "chain_fork");
  const skip = seal("sb.device-chain.v1", c.signerOf(nat), { fleet: c.fleet, aud: AUD, seq: 5, prev: c.state.head, op: "policy", at_ms: 1, auth_time_ms: 1, policy: { require_native_for_widening: true } }, nat.k);
  assert.equal(await code(() => apply(c.state, skip, c.ctx)), "chain_fork");
  const wrongPrev = seal("sb.device-chain.v1", c.signerOf(nat), { fleet: c.fleet, aud: AUD, seq: 3, prev: pin.hash, op: "policy", at_ms: 1, auth_time_ms: 1, policy: { require_native_for_widening: true } }, nat.k);
  assert.equal(await code(() => apply(c.state, wrongPrev, c.ctx)), "chain_fork");
  assert.equal(await code(() => apply(null, c.entries[1], c.ctx)), "bad_form", "a chain starts with genesis");
  void c2;
});

test("service keys: half-open intervals by chain_seq; historical acks stay verifiable; a replaced key signs no newer ack", async () => {
  const c = chain(), nat = c.dev("native"), rec = key();
  await c.genesis(nat, rec);
  const s1 = key(), s2 = key(), id1 = newId(), id2 = newId();
  await c.push(c.sign(nat, "service-key", { service_key: { id: id1, alg: "ed25519", key: b64(s1.raw) } }));
  const k1seq = c.state.seq;
  await c.push(c.sign(nat, "policy", { policy: { require_native_for_widening: true } }));
  await c.push(c.sign(nat, "service-key", { service_key: { id: id2, alg: "ed25519", key: b64(s2.raw) } }));
  const k2seq = c.state.seq;
  const sv = (id, k) => ({ kind: "service", id, alg: "ed25519", key: k.key });
  // before and after the rotation (positive), an old ack after the rotation (positive)
  assert.deepEqual(serviceKeyAt(c.state, sv(id1, s1), k1seq + 1), s1.raw);
  assert.deepEqual(serviceKeyAt(c.state, sv(id2, s2), k2seq), s2.raw);
  assert.deepEqual(serviceKeyAt(c.state, sv(id1, s1), k1seq), s1.raw, "historical, after K2 came in");
  // the old key on an ack past its replacement (refused); before any key; a wrong id; past the head
  assert.equal(await code(() => serviceKeyAt(c.state, sv(id1, s1), k2seq)), "bad_signature");
  assert.equal(await code(() => serviceKeyAt(c.state, sv(id1, s1), k1seq - 1)), "bad_signature");
  assert.equal(await code(() => serviceKeyAt(c.state, sv(newId(), s2), k2seq)), "bad_signature");
  assert.equal(await code(() => serviceKeyAt(c.state, sv(id2, s2), k2seq + 1)), "device_unknown");
});

test("the service's auth_time check: a sign-in more than 5 minutes old is stale_auth", async () => {
  const c = chain(), nat = c.dev("native"), rec = key();
  await c.genesis(nat, rec);
  const e = c.sign(nat, "policy", { policy: { require_native_for_widening: true } });
  assert.equal(await code(() => apply(c.state, e, { ...c.ctx, checkAuthTime: true, now: 1000 + 5 * 60_000 })), "ok");
  assert.equal(await code(() => apply(c.state, e, { ...c.ctx, checkAuthTime: true, now: 1001 + 5 * 60_000 })), "stale_auth");
});

test("a chain is bound to its own fleet and audience: another context can't extend it, and the state is unchanged", async () => {
  const c = chain(), nat = c.dev("native"), rec = key();
  await c.genesis(nat, rec);
  const before = c.state;
  for (const other of [{ aud: AUD, fleet: newId() }, { aud: "https://sagebrush.space", fleet: c.fleet }]) {
    // a validly signed entry, made for the other context, extending this chain's head
    const body = { fleet: other.fleet, aud: other.aud, seq: 1, prev: before.head, op: "policy", at_ms: 1, auth_time_ms: 1, policy: { require_native_for_widening: true } };
    const bytes = seal("sb.device-chain.v1", c.signerOf(nat), body, nat.k);
    const got = await code(() => apply(before, bytes, other));
    assert.ok(got === "bad_audience" || got === "bad_form", got);
    assert.equal(before.seq, 0, "the state is unchanged");
    assert.equal(before.fleet, c.fleet);
  }
  // the matching context still extends it
  await c.push(c.sign(nat, "policy", { policy: { require_native_for_widening: true } }));
  assert.equal(c.state.seq, 1);
  // a pin of another chain refuses a replay
  assert.equal(await code(() => replay(c.entries, c.ctx, { fleet: newId(), aud: AUD, seq: 0, hash: c.state.hashes[0] })), "chain_fork");
  assert.equal(await code(() => replay(c.entries, c.ctx, { fleet: c.fleet, aud: "https://sagebrush.space", seq: 0, hash: c.state.hashes[0] })), "chain_fork");
  assert.equal((await replay(c.entries, c.ctx, { fleet: c.fleet, aud: AUD, seq: 1, hash: c.state.head })).seq, 1);
});
