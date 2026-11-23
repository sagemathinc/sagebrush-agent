// Builds test/fixtures/fleet-hpke-fixtures.json: the sealed-package (r2.3 §7) and capability-mint (§5.2) vectors every
// implementation must pass (this package's backends, the page's mirror, the Python verifier), with the X25519 key-id
// vector that pins alg "x25519" (ruled). Deterministic: fixed seeds, ids, times, and HPKE ephemeral keys from
// deriveKeyPair over fixed input keying material, so a rebuild is byte-identical; test/fleet-sealed.test.mjs checks that.
//
//   node test/make-fleet-hpke-fixtures.mjs > test/fixtures/fleet-hpke-fixtures.json
//
// The host's X25519 key is deriveKeyPair(host_enc_ikm), so a verifier rebuilds it with the core alone. Every case gives
// its bytes and context, and "ok" or a reason code from schema/fleet/reasons.json.

import {
  b64, enc, idOfBytes, canonText, keyFromSeed, keyId, seal, sealAdd, FREEZE, hostFingerprint, deriveKeyPair, encKeyId, sealPackage,
  sealCap, hpkeSeal, sha256b64, signedBytes,
} from "../lib/fleet/index.mjs";

const AUD = "https://dev.sagebrush.space";
const NOW = 1_800_000_000_000;
const txt = (bytes) => new TextDecoder().decode(bytes);
const id = (n) => idOfBytes(Uint8Array.from({ length: 16 }, (_, i) => (n * 37 + i * 11) & 255));
const seed = (n) => Uint8Array.from({ length: 32 }, (_, i) => (n * 17 + i) & 255);
const ikm = (n) => Uint8Array.from({ length: 32 }, (_, i) => (n * 23 + i * 3) & 255);
const hex = (b) => Buffer.from(b).toString("hex");

export async function build() {
  // ---- the key-id vector (§1.4 with alg "x25519"): RFC 7748 §6.1's Alice public key, under both algs
  const alice = Uint8Array.from(Buffer.from("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", "hex"));
  const key_ids = [
    { name: "x25519 (ruled spelling)", alg: "x25519", raw: b64(alice), key_id: await encKeyId(alice) },
    { name: "the same bytes under ed25519: another id", alg: "ed25519", raw: b64(alice), key_id: keyId("ed25519", alice) },
  ];

  // ---- a fleet: a native device N, a browser device B, a host with its certificate and X25519 key
  const N = keyFromSeed(seed(1)), B = keyFromSeed(seed(2)), R = keyFromSeed(seed(3)), H = keyFromSeed(seed(4));
  const fleet = id(1), nId = id(2), bId = id(3), host = id(4), sub = id(5), sub2 = id(6), agent = id(7), cap = id(8), otherHost = id(9);
  const ids = { fleet, device_native: nId, device_browser: bId, host, sub_claude: sub, sub_codex: sub2, agent, cap };
  const signer = (k, did) => ({ kind: "device", id: did, alg: "ed25519", key: k.key });
  const dev = (k, did, tier) => ({ id: did, alg: "ed25519", key: b64(k.raw), name: tier, tier });
  const sN = signer(N, nId), sB = signer(B, bId);
  const g = seal("sb.device-chain.v1", sN, { fleet, aud: AUD, seq: 0, prev: "", op: "genesis", at_ms: 1, auth_time_ms: 1, device: dev(N, nId, "native"), recovery_key: { alg: "ed25519", key: b64(R.raw) } }, N);
  const genesis = JSON.parse(txt(g));
  const a = sealAdd(sN, { fleet, aud: AUD, seq: 1, prev: sha256b64(signedBytes(genesis.type, genesis.signer, genesis.body)), op: "add", at_ms: 1, auth_time_ms: 1, device: dev(B, bId, "browser") }, N, B);
  const chain = [txt(g), txt(a)];
  const host_enc_ikm = ikm(1);
  const E = await deriveKeyPair(host_enc_ikm);
  const fp = await hostFingerprint(host, H.raw, E.raw);
  const host_cert = txt(seal("sb.host-cert.v1", sN, { fleet, aud: AUD, chain_seq: 1, host, sign_key: b64(H.raw), enc_key: b64(E.raw), fingerprint: b64(fp), name: "lab-box", at_ms: 1 }, N));
  const grant = { host, subscriptions: [{ sub, provider: "claude", use: [agent], home: false }, { sub: sub2, provider: "codex", use: [agent], home: false }] };
  const ctx = { current_gen: 3, now_ms: NOW, revoked: [], opened: [] };

  let eph = 10;
  const ephemeral = () => deriveKeyPair(ikm(eph++));
  const header = async (n, extra = {}) => ({
    fleet, aud: AUD, package: id(100 + n), host, enc_key: await encKeyId(E.raw), fingerprint: b64(fp), sub, provider: "claude",
    purpose: "claude-setup-token", gen: 3, chain_seq: 1, at_ms: NOW - 1000, not_after_ms: NOW + 3_600_000, ...extra,
  });
  const plaintext = (extra = {}) => ({ v: 1, provider: "claude", purpose: "claude-setup-token", secret: "sk-mock-not-a-credential", issued_ms: NOW - 2000, ...extra });
  const sealed = async (h, pt, by = [sN, N]) => txt(await sealPackage(h, pt, E.raw, by[0], by[1], { ephemeral: await ephemeral() }));
  // (past the app's checks: a body signed honestly over a ciphertext the app would never make)
  const forged = async (h, ptBytes, { encOverride, info } = {}) => {
    const { enc: e, ct } = await hpkeSeal(E.raw, info ?? enc("sagebrush.seal.v1\n" + canonText(h)), new Uint8Array(0), ptBytes, await ephemeral());
    return txt(seal("sb.sealed-package.v1", sN, { ...h, enc: encOverride ?? b64(e), ct: b64(ct) }, N));
  };

  const h1 = await header(1);
  const p1 = await sealed(h1, plaintext());
  const packages = [
    { name: "a package for this host, signed by the native device", bytes: p1, ctx, expect: "ok", plaintext: plaintext() },
    { name: "signed by the browser device", bytes: await sealed(await header(2), plaintext(), [sB, B]), ctx, expect: "ok", plaintext: plaintext() },
    { name: "a codex package for a codex subscription", bytes: await sealed(await header(3, { sub: sub2, provider: "codex", purpose: "codex-access-token" }), plaintext({ provider: "codex", purpose: "codex-access-token" })), ctx, expect: "ok", plaintext: plaintext({ provider: "codex", purpose: "codex-access-token" }) },
    { name: "a newer generation than the package's", bytes: p1, ctx: { ...ctx, current_gen: 4 }, expect: "package_stale" },
    { name: "an older generation than the package's", bytes: p1, ctx: { ...ctx, current_gen: 2 }, expect: "package_stale" },
    { name: "now = not_after_ms", bytes: p1, ctx: { ...ctx, now_ms: NOW + 3_600_000 }, expect: "package_stale" },
    { name: "revoked", bytes: p1, ctx: { ...ctx, revoked: [h1.package] }, expect: "package_stale" },
    { name: "already opened", bytes: p1, ctx: { ...ctx, opened: [h1.package] }, expect: "package_stale" },
    { name: "a ciphertext moved under another signed header", bytes: await forged({ ...h1, not_after_ms: h1.not_after_ms - 1 }, enc(canonText(plaintext())), { info: enc("sagebrush.seal.v1\n" + canonText(h1)) }), ctx, expect: "bad_form" },
    { name: "an all-zero encapsulated key", bytes: await forged(await header(4), enc(canonText(plaintext())), { encOverride: b64(new Uint8Array(32)) }), ctx, expect: "bad_form" },
    { name: "a plaintext with an extra field", bytes: await forged(await header(5), enc(canonText({ ...plaintext(), extra: 1 }))), ctx, expect: "bad_form" },
    { name: "a plaintext that isn't canonical", bytes: await forged(await header(6), enc(JSON.stringify(plaintext(), null, 1))), ctx, expect: "bad_form" },
    { name: "a plaintext of another provider than the header's", bytes: await forged(await header(7), enc(canonText(plaintext({ provider: "codex", purpose: "codex-access-token" })))), ctx, expect: "bad_form" },
    { name: "a purpose of another provider", bytes: await forged(await header(8, { purpose: "codex-access-token" }), enc(canonText(plaintext({ purpose: "codex-access-token" })))), ctx, expect: "bad_form" },
    { name: "a lifetime past 7 days", bytes: await forged(await header(9, { not_after_ms: NOW - 1000 + 7 * 24 * 3600_000 + 1 }), enc(canonText(plaintext()))), ctx, expect: "bad_form" },
    { name: "a package for another host", bytes: await forged(await header(10, { host: otherHost }), enc(canonText(plaintext()))), ctx, expect: "not_granted" },
    { name: "a subscription not in the grant", bytes: await sealed(await header(11, { sub: id(50) }), plaintext()), ctx, expect: "not_granted" },
    { name: "codex-refresh-home without home: true", bytes: await sealed(await header(12, { sub: sub2, provider: "codex", purpose: "codex-refresh-home" }), plaintext({ provider: "codex", purpose: "codex-refresh-home" })), ctx, expect: "not_granted" },
  ];

  // ---- the capability mint's response (§5.2), sealed to the same host key
  const m = { fleet, aud: AUD, host, agent, cap, gen: 3, not_after_ms: NOW + 900_000, token: "sbc1.mockaccount.mockcap.mocksecret.mocktag" };
  const response = await sealCap(m, E.raw, { ephemeral: await ephemeral() });
  const flip = (s) => { const b = Buffer.from(s, "base64url"); b[0] ^= 1; return b.toString("base64url"); };
  const cctx = { fleet, aud: AUD, host, agent, gen: 3, now_ms: NOW };
  const capInfo = enc("sagebrush.cap.v1\n" + canonText({ fleet, aud: AUD, host, agent, cap, gen: 3 }));
  const forgedCap = async (p) => { const { enc: e, ct } = await hpkeSeal(E.raw, capInfo, new Uint8Array(0), enc(canonText(p)), await ephemeral()); return { cap, not_after_ms: m.not_after_ms, enc: b64(e), ct: b64(ct) }; };
  const good = { v: 1, token: m.token, cap, agent, gen: 3, not_after_ms: m.not_after_ms };
  const caps = [
    { name: "the host opens its token", response, ctx: cctx, expect: "ok", token: m.token },
    { name: "another agent", response, ctx: { ...cctx, agent: id(60) }, expect: "bad_form" },
    { name: "another generation", response, ctx: { ...cctx, gen: 4 }, expect: "bad_form" },
    { name: "another host", response, ctx: { ...cctx, host: otherHost }, expect: "bad_form" },
    { name: "another cap id in the response", response: { ...response, cap: id(61) }, ctx: cctx, expect: "bad_form" },
    { name: "a changed ciphertext byte", response: { ...response, ct: flip(response.ct) }, ctx: cctx, expect: "bad_form" },
    { name: "expired", response, ctx: { ...cctx, now_ms: m.not_after_ms }, expect: "cap_invalid" },
    { name: "a plaintext, under the right header, of another cap", response: await forgedCap({ ...good, cap: id(62) }), ctx: cctx, expect: "bad_form" },
    { name: "a plaintext with an extra field", response: await forgedCap({ ...good, extra: 1 }), ctx: cctx, expect: "bad_form" },
  ];

  return {
    $comment: "Fleet-protocol HPKE vectors (agent-autonomous-schemas.md r2.3 §7, §5.2; HPKE base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM). Built by test/make-fleet-hpke-fixtures.mjs. Mock data only: no real key, credential, device or host.",
    freeze: FREEZE.sha256, aud: AUD, now_ms: NOW, ids, key_ids, chain, host_cert, host_enc_ikm: hex(host_enc_ikm), grant, packages, caps,
  };
}

if (import.meta.url === `file://${process.argv[1]}`) process.stdout.write(canonText(await build(), 4 << 20) + "\n");
