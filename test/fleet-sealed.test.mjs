// Sealed packages (r2.3 §7) and the capability mint's sealed token (§5.2): HPKE to the host's certified X25519 key,
// the header bound into the encryption as well as the signature, and every recipient check in the design's order.
// Node's backend here; the RFC 9180 vector runs on both backends (here, fleet-webcrypto.test.mjs, and Chromium).
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import {
  FleetError, b64, enc, newId, keyId, keyFromSeed, seal, sealAdd, canonText, applyChainEntry as apply, hostFingerprint, verifyHostCert,
  encKeyId, sealPackage, verifyPackage, sealCap, openCap, hpkeSeal, HPKE,
} from "../lib/fleet/index.mjs";
import * as core from "../lib/fleet/core/index.mjs";
import { nodeCrypto } from "../lib/fleet/node-crypto.mjs";
import { atSequence } from "../lib/fleet/core/hpke.mjs";
import { checkHpkeFixtures, checkHpkeVector } from "./fleet-fixture-cases.mjs";
import { build } from "./make-fleet-hpke-fixtures.mjs";
import { CONTEXTS, LENGTHS, checkExportOracle } from "./hpke-export-oracle.mjs";

const V = JSON.parse(readFileSync(new URL("./fixtures/hpke-x25519-sha256-aes256gcm.json", import.meta.url), "utf8")).vector;
const FX_TEXT = readFileSync(new URL("./fixtures/fleet-hpke-fixtures.json", import.meta.url), "utf8");
const AUD = "https://dev.sagebrush.space";
const NOW = 1_800_000_000_000;
const code = async (fn) => { try { await fn(); } catch (e) { if (e instanceof FleetError) return e.code; throw e; } return "ok"; };
let n = 70;
const key = () => keyFromSeed(new Uint8Array(32).fill(n++));

/** A fleet with a native device N and a browser device B, and a host H with its certificate and X25519 pair. */
async function setup() {
  const fleet = newId(), ctx = { aud: AUD, fleet };
  const mk = (tier) => { const k = key(); const d = newId(); return { id: d, k, tier, entry: { id: d, alg: "ed25519", key: b64(k.raw), name: tier, tier }, signer: { kind: "device", id: d, alg: "ed25519", key: k.key } }; };
  const N = mk("native"), B = mk("browser"), rec = key();
  let chain = (await apply(null, seal("sb.device-chain.v1", N.signer, { fleet, aud: AUD, seq: 0, prev: "", op: "genesis", at_ms: 1, auth_time_ms: 1, device: N.entry, recovery_key: { alg: "ed25519", key: b64(rec.raw) } }, N.k), ctx)).state;
  chain = (await apply(chain, sealAdd(N.signer, { fleet, aud: AUD, seq: 1, prev: chain.head, op: "add", at_ms: 1, auth_time_ms: 1, device: B.entry }, N.k, B.k), ctx)).state;
  const host = newId(), hk = key(), encKey = await nodeCrypto.x25519FromPrivate(new Uint8Array(32).fill(n++));
  const fp = await hostFingerprint(host, hk.raw, encKey.raw);
  const certBytes = seal("sb.host-cert.v1", N.signer, { fleet, aud: AUD, chain_seq: chain.seq, host, sign_key: b64(hk.raw), enc_key: b64(encKey.raw), fingerprint: b64(fp), name: "lab-box", at_ms: 1 }, N.k);
  const cert = await verifyHostCert(certBytes, { ...ctx, chain });
  const sub = newId(), sub2 = newId();
  // (sub: a subscription no grant lists, as a Claude subscription never is; sub2: the grant's codex subscription)
  const grant = { host, subscriptions: [{ sub: sub2, provider: "codex", use: [], home: false }] };
  const s = {
    fleet, ctx, N, B, chain, host, hk, encKey, cert, sub, sub2, grant,
    async header(extra = {}) {
      return { fleet, aud: AUD, package: newId(), host, enc_key: await encKeyId(encKey.raw), fingerprint: cert.body.fingerprint, sub: sub2, provider: "codex", purpose: "codex-access-token", gen: 3, chain_seq: s.chain.seq, at_ms: NOW - 1000, not_after_ms: NOW + 3_600_000, ...extra };
    },
    plaintext: (extra = {}) => ({ v: 1, provider: "codex", purpose: "codex-access-token", secret: "test-mock-not-a-credential", issued_ms: NOW - 2000, ...extra }),
    vctx: (extra = {}) => ({ ...ctx, chain: s.chain, cert, hostRevoked: () => false, encKey, currentGen: 3, grant, now: NOW, revoked: () => false, opened: () => false, ...extra }),
  };
  return s;
}

test("HPKE: the RFC 9180 known-answer vector for §7's suite, with Node's backend", async () => {
  assert.deepEqual([V.mode, V.kem_id, V.kdf_id, V.aead_id], [0, HPKE.kem, HPKE.kdf, HPKE.aead]);
  const { bad, n } = await checkHpkeVector(core, V);
  assert.deepEqual(bad, []);
  assert.equal(n, 260);
});

test("the committed fleet HPKE vectors are exactly what the generator builds, and every case passes with Node's backend", async () => {
  assert.equal(FX_TEXT, canonText(await build(), 4 << 20) + "\n");
  const F = JSON.parse(FX_TEXT);
  assert.equal(F.freeze, core.FREEZE.sha256);
  const { bad, n } = await checkHpkeFixtures(core, F);
  assert.deepEqual(bad, []);
  assert.equal(n, 2 + F.packages.length + F.packages.filter((c) => c.plaintext).length + F.caps.length + 1, "every case and every plaintext and token");
});

test("the X25519 key id: alg \"x25519\" (ruled), pinned, and never the same id as the same bytes under ed25519", async () => {
  // (RFC 7748 §6.1's Alice public key)
  const alice = Uint8Array.from(Buffer.from("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", "hex"));
  assert.equal(await encKeyId(alice), "Phs1KDt3l_6bVT1o5rF_lQ");
  assert.equal(await encKeyId(alice), keyId("x25519", alice));
  assert.notEqual(await encKeyId(alice), keyId("ed25519", alice));
});

test("a sealed package opens for its host, with the plaintext the app sealed", async () => {
  const s = await setup();
  const bytes = await sealPackage(await s.header(), s.plaintext(), s.encKey.raw, s.N.signer, s.N.k);
  const body = JSON.parse(new TextDecoder().decode(bytes)).body;
  assert.equal(core.unb64(body.enc, 32).length, HPKE.nenc, "enc: 32 bytes, 43 characters");
  assert.equal(core.unb64(body.ct).length, enc(canonText(s.plaintext())).length + HPKE.ntag, "ct: the plaintext and a 16-byte tag");
  const r = await verifyPackage(bytes, s.vctx());
  assert.deepEqual(r.plaintext, s.plaintext());
  assert.equal(r.body.package, body.package);
});

test("the header is bound into the encryption: a ciphertext moved under another signed header doesn't open", async () => {
  const s = await setup();
  const h1 = await s.header(), h2 = { ...h1, not_after_ms: h1.not_after_ms - 1 };
  const one = JSON.parse(new TextDecoder().decode(await sealPackage(h1, s.plaintext(), s.encKey.raw, s.N.signer, s.N.k))).body;
  // (the device honestly signs header h2, carrying h1's enc and ct: the signature holds, the HPKE info doesn't)
  const moved = seal("sb.sealed-package.v1", s.N.signer, { ...h2, enc: one.enc, ct: one.ct }, s.N.k);
  assert.equal(await code(() => verifyPackage(moved, s.vctx())), "bad_form");
  // a changed byte of the signed header without re-signing: the signature fails first
  const env = JSON.parse(new TextDecoder().decode(await sealPackage(h1, s.plaintext(), s.encKey.raw, s.N.signer, s.N.k)));
  const edited = enc(canonText({ ...env, body: { ...env.body, gen: 4 } }));
  assert.equal(await code(() => verifyPackage(edited, s.vctx({ currentGen: 4 }))), "bad_signature");
});

test("package_stale: another generation (older or newer), expired, revoked, already opened", async () => {
  const s = await setup();
  const p = await sealPackage(await s.header(), s.plaintext(), s.encKey.raw, s.N.signer, s.N.k);
  assert.equal(await code(() => verifyPackage(p, s.vctx({ currentGen: 4 }))), "package_stale", "a newer generation");
  assert.equal(await code(() => verifyPackage(p, s.vctx({ currentGen: 2 }))), "package_stale");
  assert.equal(await code(() => verifyPackage(p, s.vctx({ now: NOW + 3_600_000 }))), "package_stale", "not_after_ms is out");
  assert.equal(await code(() => verifyPackage(p, s.vctx({ now: NOW + 3_599_999 }))), "ok");
  assert.equal(await code(() => verifyPackage(p, s.vctx({ revoked: () => true }))), "package_stale");
  assert.equal(await code(() => verifyPackage(p, s.vctx({ opened: () => true }))), "package_stale");
});

test("its own host, key and fingerprint; the subscription, provider and purpose in the current grant", async () => {
  const s = await setup();
  const ok = async (h, pt = s.plaintext(), v = {}) => code(async () => verifyPackage(await sealPackage(await s.header(h), pt, s.encKey.raw, s.N.signer, s.N.k), s.vctx(v)));
  // another host's certificate (same key, other host and fingerprint) and another X25519 key held by this host
  const other = await nodeCrypto.x25519FromPrivate(new Uint8Array(32).fill(200));
  const p = await sealPackage(await s.header(), s.plaintext(), s.encKey.raw, s.N.signer, s.N.k);
  assert.equal(await code(() => verifyPackage(p, s.vctx({ cert: { ...s.cert, body: { ...s.cert.body, host: newId() } } }))), "not_granted");
  assert.equal(await code(() => verifyPackage(p, s.vctx({ encKey: other }))), "not_granted", "the key held isn't the certified one");
  assert.equal(await code(() => verifyPackage(p, s.vctx({ cert: { ...s.cert, encRaw: other.raw }, encKey: other }))), "not_granted", "sealed to another key id");
  assert.equal(await ok({ sub: newId() }), "not_granted", "a subscription not in the grant");
  assert.equal(await ok({}, s.plaintext(), { grant: { ...s.grant, host: newId() } }), "not_granted", "a grant for another host");
  const codex = (purpose) => [{ purpose }, s.plaintext({ purpose })];
  assert.equal(await ok(...codex("codex-access-token")), "ok");
  assert.equal(await ok(...codex("codex-refresh-home")), "not_granted", "codex-refresh-home needs home: true");
  const homed = { ...s.grant, subscriptions: [{ ...s.grant.subscriptions[0], home: true }] };
  assert.equal(await ok(...codex("codex-refresh-home"), { grant: homed }), "ok");
  assert.equal(await ok({ sub: s.sub }), "not_granted", "a package for a subscription the grant doesn't list");
  // (signed anyway past the app's own refusal, then given to the host)
  const signedAnyway = async (extra) => {
    const h = await s.header(extra);
    const { enc: e, ct } = await hpkeSeal(s.encKey.raw, enc("sagebrush.seal.v1\n" + canonText(h)), new Uint8Array(0), enc(canonText(s.plaintext({ provider: h.provider, purpose: h.purpose }))));
    return seal("sb.sealed-package.v1", s.N.signer, { ...h, enc: b64(e), ct: b64(ct) }, s.N.k);
  };
  // a purpose of another provider is refused at sealing; signed anyway, the host refuses it too
  assert.equal(await code(async () => sealPackage(await s.header({ purpose: "claude-setup-token" }), s.plaintext({ purpose: "claude-setup-token" }), s.encKey.raw, s.N.signer, s.N.k)), "bad_form");
  assert.equal(await code(async () => verifyPackage(await signedAnyway({ purpose: "claude-setup-token" }), s.vctx())), "bad_form");
  // no Claude purpose at all: a Claude login is never sealed to a host. A claude-setup-token package is refused at
  // sealing, and, signed anyway, by the host
  const claude = { sub: s.sub, provider: "claude", purpose: "claude-setup-token" };
  assert.equal(await code(async () => sealPackage(await s.header(claude), s.plaintext({ provider: "claude", purpose: "claude-setup-token" }), s.encKey.raw, s.N.signer, s.N.k)), "bad_form", "sealing a Claude login");
  assert.equal(await code(async () => verifyPackage(await signedAnyway(claude), s.vctx())), "bad_form", "a Claude login, signed anyway");
  assert.equal(await code(async () => verifyPackage(await signedAnyway({ ...claude, purpose: "codex-access-token" }), s.vctx())), "bad_form", "a codex purpose under claude");
});

test("lifetime, plaintext schema and bounds, the encapsulated key, a removed signer", async () => {
  const s = await setup();
  assert.equal(await code(async () => sealPackage(await s.header({ not_after_ms: NOW - 1000 + 7 * 24 * 3600_000 + 1 }), s.plaintext(), s.encKey.raw, s.N.signer, s.N.k)), "bad_form", "past 7 days");
  assert.equal(await code(async () => sealPackage(await s.header({ not_after_ms: NOW - 1000 }), s.plaintext(), s.encKey.raw, s.N.signer, s.N.k)), "bad_form", "an empty lifetime");
  assert.equal(await code(async () => sealPackage(await s.header(), s.plaintext({ secret: "" }), s.encKey.raw, s.N.signer, s.N.k)), "bad_form");
  assert.equal(await code(async () => sealPackage(await s.header(), s.plaintext({ secret: "x".repeat(8193) }), s.encKey.raw, s.N.signer, s.N.k)), "bad_form", "a secret over 8 KiB");
  assert.equal(await code(async () => sealPackage(await s.header(), s.plaintext({ provider: "claude" }), s.encKey.raw, s.N.signer, s.N.k)), "bad_form", "the plaintext's provider isn't the header's");
  assert.equal(await code(async () => sealPackage(await s.header({ enc_key: b64(new Uint8Array(16)) }), s.plaintext(), s.encKey.raw, s.N.signer, s.N.k)), "bad_form", "enc_key isn't the key sealed to");
  // forged past the app's checks: a plaintext with an extra field, and one that isn't canonical, are refused when opened
  const h = await s.header();
  const forge = async (ptBytes, encOverride) => {
    const { enc: e, ct } = await hpkeSeal(s.encKey.raw, enc("sagebrush.seal.v1\n" + canonText(h)), new Uint8Array(0), ptBytes);
    return seal("sb.sealed-package.v1", s.N.signer, { ...h, enc: encOverride ?? b64(e), ct: b64(ct) }, s.N.k);
  };
  assert.equal(await code(async () => verifyPackage(await forge(enc(canonText({ ...s.plaintext(), extra: 1 }))), s.vctx())), "bad_form");
  assert.equal(await code(async () => verifyPackage(await forge(enc(JSON.stringify(s.plaintext(), null, 1))), s.vctx())), "bad_form");
  // a ciphertext past 16 KiB of plaintext is refused before it is opened (this one wouldn't open at all)
  const big = seal("sb.sealed-package.v1", s.N.signer, { ...h, enc: JSON.parse(new TextDecoder().decode(await forge(enc("{}")))).body.enc, ct: b64(new Uint8Array(16 * 1024 + 17)) }, s.N.k);
  assert.equal(await code(() => verifyPackage(big, s.vctx())), "limit");
  // an all-zero encapsulated key (a small-order point: no shared secret) is refused, whatever the backend says
  assert.equal(await code(async () => verifyPackage(await forge(enc(canonText(s.plaintext())), b64(new Uint8Array(32))), s.vctx())), "bad_form");
  // a package signed by a device removed since: no longer counts
  const p = await sealPackage(await s.header(), s.plaintext(), s.encKey.raw, s.B.signer, s.B.k);
  assert.equal(await code(() => verifyPackage(p, s.vctx())), "ok");
  s.chain = (await apply(s.chain, seal("sb.device-chain.v1", s.N.signer, { fleet: s.fleet, aud: AUD, seq: s.chain.seq + 1, prev: s.chain.head, op: "remove", at_ms: 1, auth_time_ms: 1, remove: s.B.id, regrants: [] }, s.N.k), s.ctx)).state;
  assert.equal(await code(() => verifyPackage(p, s.vctx())), "device_removed");
});

test("the capability mint: the token sealed to the host, bound to fleet, aud, host, agent, cap and gen", async () => {
  const s = await setup();
  const agent = newId(), cap = newId();
  const m = { fleet: s.fleet, aud: AUD, host: s.host, agent, cap, gen: 3, not_after_ms: NOW + 900_000, token: "sbc1.mockaccount.mockcap.mocksecret.mocktag" };
  const r = await sealCap(m, s.encKey.raw);
  assert.deepEqual(Object.keys(r).sort(), ["cap", "ct", "enc", "not_after_ms"]);
  assert.ok(!JSON.stringify(r).includes("mocksecret"), "no token in clear");
  const hctx = { fleet: s.fleet, aud: AUD, host: s.host, agent, gen: 3, encKey: s.encKey, now: NOW };
  assert.equal((await openCap(r, hctx)).token, m.token);
  // bound into the HPKE info: another agent, generation, host, fleet or audience doesn't open it
  for (const other of [{ agent: newId() }, { gen: 4 }, { host: newId() }, { fleet: newId() }, { aud: "https://sagebrush.space" }])
    assert.equal(await code(() => openCap(r, { ...hctx, ...other })), "bad_form", JSON.stringify(other));
  assert.equal(await code(() => openCap({ ...r, cap: newId() }, hctx)), "bad_form", "another cap id");
  assert.equal(await code(() => openCap({ ...r, not_after_ms: r.not_after_ms + 1 }, hctx)), "bad_form", "another expiry than the sealed one");
  assert.equal(await code(() => openCap(r, { ...hctx, now: m.not_after_ms })), "cap_invalid");
  const ct = core.unb64(r.ct); ct[0] ^= 1;
  assert.equal(await code(() => openCap({ ...r, ct: b64(ct) }, hctx)), "bad_form");
  assert.equal(await code(() => openCap({ ...r, enc: b64(new Uint8Array(31)) }, hctx)), "bad_form", "enc is 32 bytes");
  assert.equal(await code(() => sealCap({ ...m, token: "sbg1.not-a-cap" }, s.encKey.raw)), "bad_form", "the plaintext schema: an sbc1 token");
  // a dishonest or broken service: a plaintext sealed under the right header that names another cap, or carries more
  const info = enc("sagebrush.cap.v1\n" + canonText({ fleet: s.fleet, aud: AUD, host: s.host, agent, cap, gen: 3 }));
  const forged = async (p) => { const { enc: e, ct: c } = await hpkeSeal(s.encKey.raw, info, new Uint8Array(0), enc(canonText(p))); return { cap, not_after_ms: m.not_after_ms, enc: b64(e), ct: b64(c) }; };
  const good = { v: 1, token: m.token, cap, agent, gen: 3, not_after_ms: m.not_after_ms };
  assert.equal(await code(async () => openCap(await forged(good), hctx)), "ok");
  assert.equal(await code(async () => openCap(await forged({ ...good, cap: newId() }), hctx)), "bad_form", "a plaintext of another cap");
  assert.equal(await code(async () => openCap(await forged({ ...good, extra: 1 }), hctx)), "bad_form", "a plaintext with an extra field");
});

test("HPKE open: a changed tag, ciphertext, header or key never opens, and is refused rather than read as empty", async () => {
  const s = await setup();
  const info = enc("info"), aad = new Uint8Array(0);
  const { enc: e, ct } = await hpkeSeal(s.encKey.raw, info, aad, enc("secret"));
  const { hpkeOpen } = core;
  assert.equal(new TextDecoder().decode(await hpkeOpen(s.encKey, e, info, aad, ct)), "secret");
  const flipped = Uint8Array.from(ct); flipped[flipped.length - 1] ^= 1;
  for (const [name, args] of [["tag", [s.encKey, e, info, aad, flipped]], ["info", [s.encKey, e, enc("other"), aad, ct]], ["aad", [s.encKey, e, info, enc("x"), ct]],
    ["key", [await nodeCrypto.x25519FromPrivate(new Uint8Array(32).fill(201)), e, info, aad, ct]], ["short", [s.encKey, e, info, aad, ct.subarray(0, 15)]]])
    assert.equal(await code(() => hpkeOpen(...args)), "bad_form", name);
});

test("HPKE contexts have one role (RFC 9180 §5.2): a sender only seals, a recipient only opens", async () => {
  const R = await core.deriveKeyPair(new Uint8Array(32).fill(3));
  const S = await core.setupSender(R.raw, enc("i"));
  const O = await core.setupRecipient(R, S.enc, enc("i"));
  assert.deepEqual(Object.keys(S).sort(), ["enc", "export", "seal"]);
  assert.deepEqual(Object.keys(O).sort(), ["export", "open"]);
  assert.ok(Object.isFrozen(S) && Object.isFrozen(O), "and nothing can be added to either");
  assert.throws(() => { S.open = O.open; }, TypeError);
  assert.deepEqual(await O.open(new Uint8Array(0), await S.seal(new Uint8Array(0), enc("x"))), enc("x"));
});

test("HPKE export, every block of long outputs: an independent HKDF-Expand over Node's HMAC, up to the 8160-byte maximum", async () => {
  const { bad, n } = await checkExportOracle(core, V);
  assert.deepEqual(bad, []);
  assert.equal(n, LENGTHS.length * CONTEXTS.length * 4);
});

test("HPKE export (RFC 9180 §5.3): both sides agree, bound to the context and the exporter context, with no sequence", async () => {
  const R = await core.deriveKeyPair(new Uint8Array(32).fill(5)), info = enc("export"), x = enc("pop");
  const S = await core.setupSender(R.raw, info), O = await core.setupRecipient(R, S.enc, info);
  const a = await S.export(x, 32);
  assert.equal(a.length, 32);
  assert.deepEqual(await O.export(x, 32), a, "the recipient derives the sender's secret");
  assert.deepEqual(await S.export(x, 32), a, "the same arguments, the same secret");
  assert.notDeepEqual(await S.export(enc("pok"), 32), a, "another exporter context, another secret");
  assert.notDeepEqual(await S.export(x, 33).then((b) => b.subarray(0, 32)), a, "the length is bound (I2OSP(L) is in the label)");
  assert.notDeepEqual(await (await core.setupRecipient(R, S.enc, enc("exporu"))).export(x, 32), a, "another info, another secret");
  const S2 = await core.setupSender(R.raw, info);
  assert.notDeepEqual(await S2.export(x, 32), a, "another encapsulation, another secret");
  // (no claim and no counter: an export overlapping a seal runs, and the seal still takes sequence 0)
  const [ct, during] = await Promise.all([S.seal(new Uint8Array(0), enc("m")), S.export(x, 32)]);
  assert.deepEqual(during, a);
  assert.deepEqual(await O.open(new Uint8Array(0), ct), enc("m"));
  assert.deepEqual(await O.export(x, 32), a, "and a seal or open doesn't change it");
  // the length is 1 to 255 * 32 bytes, an integer; the exporter context is bytes
  assert.equal((await S.export(x, 8160)).length, 8160);
  for (const L of [0, -1, 8161, 1.5, NaN, "32", null]) assert.equal(await code(() => S.export(x, L)), "bad_form", `length ${String(L)}`);
  for (const c of ["pop", null, undefined, [1]]) assert.equal(await code(() => O.export(c, 32)), "bad_form", `context ${JSON.stringify(c)}`);
  // single-shot: the encapsulation and the secret, then the recipient's secret from enc alone
  const one = await core.hpkeSendExport(R.raw, info, x, 32);
  assert.equal(one.enc.length, 32);
  assert.deepEqual(await core.hpkeReceiveExport(R, one.enc, info, x, 32), one.secret);
  assert.notDeepEqual(await core.hpkeReceiveExport(R, one.enc, enc("other"), x, 32), one.secret);
  assert.equal(await code(() => core.hpkeSendExport(new Uint8Array(31), info, x, 32)), "bad_form");
  assert.equal(await code(() => core.hpkeReceiveExport(R, new Uint8Array(32), info, x, 32)), "bad_form", "an all-zero enc gives no shared secret");
});

test("the sequence is an exact counter: the last allowed seal and open work, the next is refused (limit), no nonce repeats", async () => {
  const R = await core.deriveKeyPair(new Uint8Array(32).fill(4)), info = enc("boundary"), aad = new Uint8Array(0), pt = enc("same plaintext");
  const start = Number.MAX_SAFE_INTEGER - 2;
  const S = await atSequence.sender(start, R.raw, info);
  const c1 = await S.seal(aad, pt), c2 = await S.seal(aad, pt); // (seq 2^53 - 3 and 2^53 - 2)
  assert.notDeepEqual(c1, c2, "two sequence numbers, two nonces: the same plaintext seals differently");
  assert.equal(await code(() => S.seal(aad, pt)), "limit", "2^53 - 1 is never used");
  assert.equal(await code(() => S.seal(aad, pt)), "limit", "and stays refused");
  // the recipient at the same start opens both, in order, then refuses; a refused call doesn't advance it
  const O = await atSequence.recipient(start, R, S.enc, info);
  assert.equal(await code(() => O.open(aad, c2)), "bad_form", "c2 isn't seq 2^53 - 3's");
  assert.deepEqual(await O.open(aad, c1), pt);
  assert.deepEqual(await O.open(aad, c2), pt);
  assert.equal(await code(() => O.open(aad, c2)), "limit");
  // just below 2^32 and 2^48: the nonce's higher bytes are exact (each ciphertext opens only at its own sequence)
  for (const at of [2 ** 32 - 1, 2 ** 48 - 1]) {
    const S2 = await atSequence.sender(at, R.raw, info);
    const a = await S2.seal(aad, pt), b = await S2.seal(aad, pt);
    const O2 = await atSequence.recipient(at, R, S2.enc, info);
    assert.deepEqual([await O2.open(aad, a), await O2.open(aad, b)], [pt, pt], String(at));
    assert.equal(await code(async () => (await atSequence.recipient(at + 1, R, S2.enc, info)).open(aad, a)), "bad_form", `${at}: not at the next`);
  }
});

test("a revoked own certificate: host_revoked before anything is opened (the X25519 key is never used)", async () => {
  const s = await setup();
  const p = await sealPackage(await s.header(), s.plaintext(), s.encKey.raw, s.N.signer, s.N.k);
  let used = 0;
  const watched = { raw: s.encKey.raw, dh: async (peer) => { used++; return s.encKey.dh(peer); } };
  const seen = [];
  assert.equal(await code(() => verifyPackage(p, s.vctx({ encKey: watched, hostRevoked: (c) => { seen.push(c); return true; } }))), "host_revoked");
  assert.equal(used, 0, "no DH, no open");
  assert.equal(seen[0], s.cert, "asked about its own certificate");
  // anything but an explicit false is revoked (fail closed)
  assert.equal(await code(() => verifyPackage(p, s.vctx({ encKey: watched, hostRevoked: () => undefined }))), "host_revoked");
  assert.equal(used, 0);
  assert.equal(await code(() => verifyPackage(p, s.vctx({ encKey: watched }))), "ok");
  assert.equal(used, 1);
});
