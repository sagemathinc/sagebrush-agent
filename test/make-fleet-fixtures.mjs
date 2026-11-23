// Builds test/fixtures/fleet-fixtures.json: the shared vectors every fleet-protocol implementation (this package, the
// page's mirror, the Python verifier) must pass (design agent-autonomous-schemas.md r2.3 §9). Deterministic: fixed
// seeds, ids and times, so a rebuild is byte-identical; test/fleet-fixtures.test.mjs checks that and runs every case.
//
//   node test/make-fleet-fixtures.mjs > test/fixtures/fleet-fixtures.json
//
// Each case gives its inputs as exact bytes or JSON, and its expected result: "ok" or a reason code from
// schema/fleet/reasons.json. Stateful cases carry everything a verifier needs (the chain entries, the context).

import { b64, enc, idOfBytes } from "../lib/fleet/bytes.mjs";
import { canonText } from "../lib/fleet/canonical.mjs";
import { keyFromSeed } from "../lib/fleet/ed25519.mjs";
import { seal, sealAdd, signedBytes } from "../lib/fleet/envelope.mjs";
import { FREEZE } from "../lib/fleet/index.mjs";
import { hostFingerprint, preimageHash } from "../lib/fleet/verify.mjs";
import { sha256b64 } from "../lib/fleet/bytes.mjs";

const AUD = "https://dev.sagebrush.space";
const NOW = 1_800_000_000_000;
const txt = (bytes) => new TextDecoder().decode(bytes);
const id = (n) => idOfBytes(Uint8Array.from({ length: 16 }, (_, i) => (n * 31 + i * 7) & 255));
const seed = (n) => Uint8Array.from({ length: 32 }, (_, i) => (n * 13 + i) & 255);
const hex = (s) => Uint8Array.from(Buffer.from(s, "hex"));

export function build() {
  const keys = {};
  const key = (name, s) => {
    const k = keyFromSeed(s);
    keys[name] = { seed: Buffer.from(s).toString("hex"), public: b64(k.raw), key_id: k.key };
    return k;
  };
  const rfc = key("rfc8032-1", hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"));
  const N = key("device-native", seed(1)), B = key("device-browser", seed(2)), R = key("recovery", seed(3)), R2 = key("recovery-2", seed(4));
  const N2 = key("device-native-2", seed(5)), H = key("host", seed(6)), S1 = key("service-1", seed(7)), S2 = key("service-2", seed(8));
  const fleet = id(1), nId = id(2), bId = id(3), n2Id = id(4), host = id(5), agent = id(6), tag = id(7), s1Id = id(8), s2Id = id(9);
  const ids = { fleet, device_native: nId, device_browser: bId, device_native_2: n2Id, host, agent, tag, service_1: s1Id, service_2: s2Id };
  const ctx = { aud: AUD, fleet };
  const dev = (k, did, tier) => ({ id: did, alg: "ed25519", key: b64(k.raw), name: tier, tier });
  const signer = (k, did) => ({ kind: "device", id: did, alg: "ed25519", key: k.key });

  // ---- 1. canonical bytes (§1.2): received bytes must be exactly canon(JSON.parse(bytes))
  const canonical = [
    ["sorted keys", '{"a":1,"b":"x"}', "ok"],
    ["UTF-16 key order (astral before U+FFFF)", '{"😀":2,"￿":1}', "ok"],
    ["safe-integer endpoints", `{"a":${2 ** 53 - 1},"b":${-(2 ** 53 - 1)}}`, "ok"],
    ["supplementary-plane text", '{"a":"😀𝄞"}', "ok"],
    ["unsorted keys", '{"b":"x","a":1}', "bad_form"],
    ["whitespace", '{"a":1, "b":"x"}', "bad_form"],
    ["duplicate key", '{"a":1,"a":2}', "bad_form"],
    ["duplicate key by escape", '{"a":1,"\\u0061":2}', "bad_form"],
    ["a float", '{"a":1.5}', "bad_form"],
    ["an integer written as a float", '{"a":1.0}', "bad_form"],
    ["an exponent", '{"a":1e0}', "bad_form"],
    ["minus zero", '{"a":-0}', "bad_form"],
    ["one past the safe integers", `{"a":${2 ** 53}}`, "bad_form"],
    ["an escaped plain character", '{"a":"\\u00e9"}', "bad_form"],
    ["a lone surrogate", '{"a":"\\ud800"}', "bad_form"],
  ].map(([name, text, expect]) => ({ name, bytes_b64: b64(enc(text)), expect }));
  canonical.push({ name: "invalid UTF-8", bytes_b64: b64(Uint8Array.from([0x7b, 0x22, 0x61, 0x22, 0x3a, 0x22, 0xff, 0x22, 0x7d])), expect: "bad_form" });
  canonical.push({ name: "a byte-order mark", bytes_b64: b64(Uint8Array.from([0xef, 0xbb, 0xbf, ...enc('{"a":1}')])), expect: "bad_form" });

  // ---- 2. base64url and ids (§1.1, §1.2)
  const base64url = [
    { name: "32 bytes", value: "A".repeat(43), len: 32, expect: "ok" },
    { name: "a non-zero pad bit", value: "A".repeat(42) + "B", len: 32, expect: "bad_form" },
    { name: "padding", value: "A".repeat(43) + "=", len: 32, expect: "bad_form" },
    { name: "too long", value: "A".repeat(44), len: 32, expect: "bad_form" },
    { name: "standard base64", value: "A".repeat(42) + "+", len: 32, expect: "bad_form" },
    { name: "64 bytes", value: "A".repeat(86), len: 64, expect: "ok" },
    { name: "64 bytes, a non-zero pad bit", value: "A".repeat(85) + "B", len: 64, expect: "bad_form" },
    { name: "16 bytes", value: "A".repeat(22), len: 16, expect: "ok" },
  ];
  const idCases = [
    { value: "a".repeat(26), expect: "ok" }, { value: "7".repeat(25) + "4", expect: "ok" }, { value: id(42), expect: "ok" },
    { value: "a".repeat(25) + "b", expect: "bad_form" }, { value: "A".repeat(26), expect: "bad_form" }, { value: "a".repeat(27), expect: "bad_form" },
  ];

  // ---- 3. Ed25519 (§1.4): strict, the same answer on every runtime
  const L = (1n << 252n) + 27742317777372353535851937790883648493n;
  const sig0 = rfc.sign(new Uint8Array(0));
  let S = 0n; for (let i = 63; i >= 32; i--) S = (S << 8n) | BigInt(sig0[i]);
  const big = Uint8Array.from(sig0); { let n = S + L; for (let i = 32; i < 64; i++) { big[i] = Number(n & 255n); n >>= 8n; } }
  const ident = new Uint8Array(32); ident[0] = 1;
  const forged = new Uint8Array(64); forged.set(ident, 0);
  const pNoncanon = Uint8Array.from(new Uint8Array(32).fill(255)); pNoncanon[31] = 0x7f; pNoncanon[0] = 0xed; // (y = p: not canonical)
  const badR = Uint8Array.from(sig0); badR.set(pNoncanon, 0);
  const ed25519 = [
    { name: "RFC 8032 test 1", public: keys["rfc8032-1"].public, msg_b64: "", sig: b64(sig0), expect: true },
    { name: "S + L", public: keys["rfc8032-1"].public, msg_b64: "", sig: b64(big), expect: false },
    { name: "a small-order key's forgery (Node 20/22 accept it alone)", public: b64(ident), msg_b64: b64(enc("any message")), sig: b64(forged), expect: false },
    { name: "a non-canonical R", public: keys["rfc8032-1"].public, msg_b64: "", sig: b64(badR), expect: false },
    { name: "a non-canonical key (y = p)", public: b64(pNoncanon), msg_b64: "", sig: b64(sig0), expect: false },
    { name: "another message", public: keys["rfc8032-1"].public, msg_b64: b64(enc("x")), sig: b64(sig0), expect: false },
  ];

  // ---- 4. the device chain (§2): one honest chain, then refused extensions of it
  const entries = [];
  let head = "", seq = 0;
  const body = (op, extra) => ({ fleet, aud: AUD, seq, prev: head, op, at_ms: NOW, auth_time_ms: NOW, ...extra });
  const push = (bytes) => { entries.push(txt(bytes)); head = sha256b64(signedBytes("sb.device-chain.v1", JSON.parse(txt(bytes)).signer, JSON.parse(txt(bytes)).body)); seq++; return bytes; };
  push(seal("sb.device-chain.v1", signer(B, bId), body("genesis", { device: dev(B, bId, "browser"), recovery_key: { alg: "ed25519", key: b64(R.raw) } }), B));
  push(seal("sb.device-chain.v1", { kind: "recovery", id: fleet, alg: "ed25519", key: R.key }, body("recover", { device: dev(N, nId, "native"), recovery_key: { alg: "ed25519", key: b64(R2.raw) } }), R));
  push(sealAdd(signer(N, nId), body("add", { device: dev(N2, n2Id, "native") }), N, N2));
  push(seal("sb.device-chain.v1", signer(N, nId), body("service-key", { service_key: { id: s1Id, alg: "ed25519", key: b64(S1.raw) } }), N));
  const s1Seq = seq - 1;
  push(seal("sb.device-chain.v1", signer(N, nId), body("policy", { policy: { require_native_for_widening: true } }), N));
  push(seal("sb.device-chain.v1", signer(N, nId), body("service-key", { service_key: { id: s2Id, alg: "ed25519", key: b64(S2.raw) } }), N));
  const s2Seq = seq - 1;
  const honest = [...entries];
  const headAt = { seq: seq - 1, hash: head };
  const next = (by, byId, op, extra, kind = "device") => txt(seal("sb.device-chain.v1",
    kind === "recovery" ? { kind: "recovery", id: fleet, alg: "ed25519", key: by.key } : signer(by, byId), body(op, extra), by));
  const chain = [
    { name: "the honest chain replays", entries: honest, expect: "ok" },
    { name: "a browser device adds a native one", entries: honest, append: txt(sealAdd(signer(B, bId), body("add", { device: dev(key("x1", seed(20)), id(20), "native") }), B, keyFromSeed(seed(20)))), expect: "device_tier" },
    { name: "a browser device rotates the recovery key", entries: honest, append: next(B, bId, "rotate-recovery", { recovery_key: { alg: "ed25519", key: b64(keyFromSeed(seed(21)).raw) } }), expect: "device_tier" },
    { name: "a browser device turns the native policy off", entries: honest, append: next(B, bId, "policy", { policy: { require_native_for_widening: false } }), expect: "device_tier" },
    { name: "a browser device removes a native one", entries: honest, append: next(B, bId, "remove", { remove: nId, regrants: [] }), expect: "device_tier" },
    { name: "a device removes itself", entries: honest, append: next(N, nId, "remove", { remove: nId, regrants: [] }), expect: "bad_form" },
    { name: "the spent recovery key signs a recover", entries: honest, append: next(R, null, "recover", { device: dev(keyFromSeed(seed(22)), id(22), "native"), recovery_key: { alg: "ed25519", key: b64(keyFromSeed(seed(23)).raw) } }, "recovery"), expect: "recovery_key_mismatch" },
    { name: "a device signs a recover", entries: honest, append: next(N, nId, "recover", { device: dev(keyFromSeed(seed(24)), id(24), "native"), recovery_key: { alg: "ed25519", key: b64(keyFromSeed(seed(25)).raw) } }), expect: "recovery_key_mismatch" },
    { name: "a native device removes the browser one", entries: honest, append: next(N, nId, "remove", { remove: bId, regrants: [] }), expect: "ok" },
    { name: "a rollback behind the pin", entries: honest.slice(0, 3), pin: { fleet, aud: AUD, ...headAt }, expect: "chain_fork" },
    { name: "a pin of another fleet", entries: honest, pin: { fleet: id(99), aud: AUD, ...headAt }, expect: "chain_fork" },
    { name: "the matching pin", entries: honest, pin: { fleet, aud: AUD, ...headAt }, expect: "ok" },
  ];
  // (a skipped seq: an entry signed for seq + 1)
  { const save = seq; seq = save + 1; chain.push({ name: "a skipped seq", entries: honest, append: next(N, nId, "policy", { policy: { require_native_for_widening: true } }), expect: "chain_fork" }); seq = save; }

  // ---- 5. service keys over half-open intervals (§1.7)
  const sv = (sid, k) => ({ kind: "service", id: sid, alg: "ed25519", key: k.key });
  const service_keys = [
    { name: "key 1 inside its interval", chain_seq: s1Seq + 1, signer: sv(s1Id, S1), expect: "ok" },
    { name: "key 2 after the rotation", chain_seq: s2Seq, signer: sv(s2Id, S2), expect: "ok" },
    { name: "an old ack after the rotation", chain_seq: s1Seq, signer: sv(s1Id, S1), expect: "ok" },
    { name: "the old key past its replacement", chain_seq: s2Seq, signer: sv(s1Id, S1), expect: "bad_signature" },
    { name: "before any key", chain_seq: s1Seq - 1, signer: sv(s1Id, S1), expect: "bad_signature" },
    { name: "past the pinned head", chain_seq: s2Seq + 1, signer: sv(s2Id, S2), expect: "device_unknown" },
  ];

  // ---- 6. envelopes and objects outside the chain (§1.3, §3, §4), against the honest chain
  const encRaw = new Uint8Array(32).fill(9);
  const certBody = { fleet, aud: AUD, chain_seq: headAt.seq, host, sign_key: b64(H.raw), enc_key: b64(encRaw), fingerprint: b64(hostFingerprint(host, H.raw, encRaw)), name: "lab-box", at_ms: NOW };
  const cert = txt(seal("sb.host-cert.v1", signer(N, nId), certBody, N));
  const grantBody = (extra = {}) => ({
    fleet, aud: AUD, chain_seq: headAt.seq, host, gen: 1, cert: null, at_ms: NOW - 1000, not_before_ms: NOW - 1000, not_after_ms: NOW + 3_600_000, auth_time_ms: NOW,
    agents: [{ agent, name: "worker", client: "claude", root: false, tags: [tag], workspace: [{ path: "/Algebra", access: "write" }], broker: ["messages"], spend_cap_cents: 0, config_schema: 1, config: {} }],
    tags: [{ tag, name: "course" }], subscriptions: [], offline: { revocation_check_s: 900, horizon_s: 3600 }, ...extra,
  });
  const certHash = sha256b64(signedBytes("sb.host-cert.v1", signer(N, nId), certBody));
  const grant = (k, kid, extra) => txt(seal("sb.host-grant.v1", signer(k, kid), { ...grantBody(extra), cert: certHash }, k));
  const g1 = grant(N, nId, {});
  const a0 = grantBody().agents[0];
  const grants = [
    { name: "a grant", bytes: g1, current: null, expect: "ok" },
    { name: "the same bytes again", bytes: g1, current: { gen: 1, bytes: g1 }, expect: "ok" },
    { name: "the same generation, other bytes", bytes: grant(N, nId, { at_ms: NOW - 999 }), current: { gen: 1, bytes: g1 }, expect: "stale_generation" },
    { name: "an older generation", bytes: g1, current: { gen: 2, bytes: grant(N, nId, { gen: 2 }) }, expect: "stale_generation" },
    { name: "expired at exactly not_after", bytes: grant(N, nId, { not_after_ms: NOW }), current: null, expect: "grant_expired" },
    { name: "no expiry without the acknowledgement", bytes: grant(N, nId, { not_after_ms: null }), current: null, expect: "bad_form" },
    { name: "/.agents as a scope", bytes: grant(N, nId, { agents: [{ ...a0, workspace: [{ path: "/.agents", access: "read" }] }] }), current: null, expect: "not_granted" },
    { name: "a dot-dot alias into /.agents", bytes: grant(N, nId, { agents: [{ ...a0, workspace: [{ path: "/x/../.agents", access: "read" }] }] }), current: null, expect: "bad_form" },
    { name: "a double slash", bytes: grant(N, nId, { agents: [{ ...a0, workspace: [{ path: "//.agents", access: "read" }] }] }), current: null, expect: "bad_form" },
    { name: "a browser device widens under the native policy", bytes: grant(B, bId, {}), current: null, expect: "device_tier" },
    { name: "a tag the grant doesn't name", bytes: grant(N, nId, { agents: [{ ...a0, tags: [id(77)] }] }), current: null, expect: "bad_form" },
  ];
  const op = (k, kid, o, extra = {}) => txt(seal("sb.host-op.v1", signer(k, kid), { fleet, aud: AUD, chain_seq: headAt.seq, op_id: id(60 + Object.keys(extra).length), op: o, host, agent: "all", gen: 3, at_ms: NOW, not_after_ms: NOW + 600_000, ...extra }, k));
  const host_ops = [
    { name: "a pause", bytes: op(B, bId, "pause"), current_gen: 3, expect: "ok" },
    { name: "a resume from a browser device under the native policy", bytes: op(B, bId, "resume"), current_gen: 3, expect: "device_tier" },
    { name: "a resume from a native device", bytes: op(N, nId, "resume"), current_gen: 3, expect: "ok" },
    { name: "an old generation", bytes: op(N, nId, "stop", { gen: 2 }), current_gen: 3, expect: "stale_generation" },
    { name: "a life over 10 minutes", bytes: op(N, nId, "stop", { not_after_ms: NOW + 600_001 }), current_gen: 3, expect: "bad_form" },
  ];
  const subject = { agent, host, paths_hash: preimageHash(["/tmp/a", "/tmp/b"]), count: 2 };
  const approval = (k, kid, extra = {}) => txt(seal("sb.approval.v1", signer(k, kid), {
    fleet, aud: AUD, chain_seq: headAt.seq, approval: id(80), kind: "delete-outside", requester: { host, agent }, gen: 4, life: 2, question: id(81),
    subject, subject_hash: sha256b64(enc(canonText(subject))), at_ms: NOW, not_after_ms: NOW + 600_000, auth_time_ms: NOW, ...extra,
  }, k));
  const expectA = { kind: "delete-outside", subject, requester: { host, agent } };
  const approvals = [
    { name: "an approval", bytes: approval(N, nId), expect_op: expectA, current: { gen: 4, life: 2 }, used: [], expect: "ok" },
    { name: "used before", bytes: approval(N, nId), expect_op: expectA, current: { gen: 4, life: 2 }, used: [id(80)], expect: "approval_used" },
    { name: "a newer generation", bytes: approval(N, nId), expect_op: expectA, current: { gen: 5, life: 2 }, used: [], expect: "approval_stale" },
    { name: "a revoke-and-resume since", bytes: approval(N, nId), expect_op: expectA, current: { gen: 4, life: 3 }, used: [], expect: "approval_stale" },
    { name: "another operation", bytes: approval(N, nId), expect_op: { ...expectA, subject: { ...subject, count: 3 } }, current: { gen: 4, life: 2 }, used: [], expect: "approval_mismatch" },
    { name: "a subject_hash of another subject", bytes: approval(N, nId, { subject_hash: sha256b64(enc(canonText({ ...subject, count: 3 }))) }), expect_op: { ...expectA, subject: { ...subject, count: 3 } }, current: { gen: 4, life: 2 }, used: [], expect: "approval_mismatch" },
    { name: "a browser device under the native policy", bytes: approval(B, bId), expect_op: expectA, current: { gen: 4, life: 2 }, used: [], expect: "device_tier" },
  ];
  const envelopes = [
    { name: "a host op, as signed", bytes: host_ops[0].bytes, expect: "ok" },
    { name: "another audience", bytes: host_ops[0].bytes, ctx: { aud: "https://sagebrush.space", fleet }, expect: "bad_audience" },
    { name: "the type swapped (still well-formed; the signature no longer verifies)", bytes: txt(enc(canonText({ ...JSON.parse(host_ops[0].bytes), type: "sb.revocation.v1" }))), expect: "bad_signature" },
    { name: "an extra field", bytes: txt(enc(canonText({ ...JSON.parse(host_ops[0].bytes), extra: 1 }))), expect: "bad_form" },
    { name: "a host signing a grant", bytes: txt(enc(canonText({ ...JSON.parse(g1), signer: { kind: "host", id: host, alg: "ed25519", key: H.key } }))), expect: "bad_signature" },
  ];

  return {
    $comment: "Shared fleet-protocol vectors (agent-autonomous-schemas.md r2.3 §9). Built by test/make-fleet-fixtures.mjs; every implementation must agree with every case. Mock data only: no real key, device or host.",
    freeze: FREEZE.sha256,
    aud: AUD, now_ms: NOW, ids, keys,
    canonical, base64url, ids_cases: idCases, ed25519,
    chain: { entries_note: "envelope texts, in order", cases: chain },
    service_keys: { chain: honest, cases: service_keys },
    objects: { chain: honest, host_cert: cert, grants, host_ops, approvals, envelopes },
  };
}

if (import.meta.url === `file://${process.argv[1]}`) process.stdout.write(canonText(build(), 4 << 20) + "\n");
