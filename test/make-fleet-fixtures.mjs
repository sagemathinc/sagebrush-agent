// Builds test/fixtures/fleet-fixtures.json: the shared vectors every fleet-protocol implementation (this package, the
// page's mirror, the Python verifier) must pass (design agent-autonomous-schemas.md r2.4 §9). Deterministic: fixed
// seeds, ids and times, so a rebuild is byte-identical; test/fleet-fixtures.test.mjs checks that and runs every case.
//
//   node test/make-fleet-fixtures.mjs > test/fixtures/fleet-fixtures.json
//
// Each case gives its inputs as exact bytes or JSON, and its expected result: "ok" or a reason code from
// schema/fleet/reasons.json. Stateful cases carry everything a verifier needs (the chain entries, the context).

import { b64, enc, idOfBytes, canonText, keyFromSeed, seal, sealAdd, signedBytes, FREEZE, hostFingerprint, fleetFingerprint, showFingerprint, preimageHash, sha256b64 } from "../lib/fleet/index.mjs";

const AUD = "https://dev.sagebrush.space";
const NOW = 1_800_000_000_000;
const txt = (bytes) => new TextDecoder().decode(bytes);
const id = (n) => idOfBytes(Uint8Array.from({ length: 16 }, (_, i) => (n * 31 + i * 7) & 255));
const seed = (n) => Uint8Array.from({ length: 32 }, (_, i) => (n * 13 + i) & 255);
const hex = (s) => Uint8Array.from(Buffer.from(s, "hex"));

export async function build() {
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

  // ---- 5b. lease keys (r2.5 §1.7a): native devices only, never a service key's material or id, half-open as §1.7.
  // A chain of its own (the honest chain plus three entries), built without moving the honest chain's seq or head.
  const L1 = key("lease-1", seed(40)), L2 = key("lease-2", seed(41));
  const l1Id = id(40), l2Id = id(41);
  Object.assign(ids, { lease_1: l1Id, lease_2: l2Id });
  const saved = { seq, head, n: entries.length };
  const lk = (by, byId, lid, k) => seal("sb.device-chain.v1", signer(by, byId), body("lease-key", { lease_key: { id: lid, alg: "ed25519", key: b64(k.raw) } }), by);
  const sk = (lid, k) => next(N, nId, "service-key", { service_key: { id: lid, alg: "ed25519", key: b64(k.raw) } });
  const lease_chain = [
    // (on the honest chain, before any lease key)
    { name: "a browser device pins the first lease key", entries: honest, append: txt(lk(B, bId, id(42), keyFromSeed(seed(42)))), expect: "device_tier" },
    { name: "a native device pins the first lease key", entries: honest, append: txt(lk(N, nId, id(42), keyFromSeed(seed(42)))), expect: "ok" },
  ];
  push(lk(N, nId, l1Id, L1));
  const l1Seq = seq - 1;
  push(seal("sb.device-chain.v1", signer(N, nId), body("policy", { policy: { require_native_for_widening: true } }), N));
  push(lk(N2, n2Id, l2Id, L2));
  const l2Seq = seq - 1;
  const leased = [...entries];
  lease_chain.push(
    { name: "the leased chain replays", entries: leased, expect: "ok" },
    { name: "a browser device rotates a native-pinned lease key", entries: leased, append: txt(lk(B, bId, id(43), keyFromSeed(seed(43)))), expect: "device_tier" },
    { name: "a native device rotates the lease key", entries: leased, append: txt(lk(N, nId, id(43), keyFromSeed(seed(43)))), expect: "ok" },
    { name: "the recovery key signs a lease-key entry", entries: leased, append: txt(seal("sb.device-chain.v1", { kind: "recovery", id: fleet, alg: "ed25519", key: R2.key }, body("lease-key", { lease_key: { id: id(43), alg: "ed25519", key: b64(keyFromSeed(seed(43)).raw) } }), R2)), expect: "device_unknown" },
    { name: "a lease key that is a pinned service key", entries: leased, append: txt(lk(N, nId, id(44), S1)), expect: "bad_form" },
    { name: "a service key that is a pinned lease key", entries: leased, append: sk(id(45), L1), expect: "bad_form" },
    { name: "a lease key under a service key's id", entries: leased, append: txt(lk(N, nId, s1Id, keyFromSeed(seed(46)))), expect: "bad_form" },
    { name: "a service key under a lease key's id", entries: leased, append: sk(l1Id, keyFromSeed(seed(47))), expect: "bad_form" },
    { name: "a lease key id twice", entries: leased, append: txt(lk(N, nId, l2Id, keyFromSeed(seed(48)))), expect: "bad_form" },
  );
  const lv = (lid, k, kind = "lease") => ({ kind, id: lid, alg: "ed25519", key: k.key });
  const lease_keys = [
    { name: "key 1 inside its interval", lookup: "lease", chain_seq: l1Seq + 1, signer: lv(l1Id, L1), expect: "ok" },
    { name: "key 2 after the rotation", lookup: "lease", chain_seq: l2Seq, signer: lv(l2Id, L2), expect: "ok" },
    { name: "an old lease after the rotation", lookup: "lease", chain_seq: l1Seq, signer: lv(l1Id, L1), expect: "ok" },
    { name: "the old key past its replacement", lookup: "lease", chain_seq: l2Seq, signer: lv(l1Id, L1), expect: "bad_signature" },
    { name: "before any lease key", lookup: "lease", chain_seq: l1Seq - 1, signer: lv(l1Id, L1), expect: "bad_signature" },
    { name: "past the pinned head", lookup: "lease", chain_seq: l2Seq + 1, signer: lv(l2Id, L2), expect: "device_unknown" },
    { name: "signer kind service naming the lease key", lookup: "lease", chain_seq: l2Seq, signer: lv(l2Id, L2, "service"), expect: "bad_signature" },
    { name: "signer kind lease naming the service key", lookup: "lease", chain_seq: l2Seq, signer: lv(s2Id, S2), expect: "bad_signature" },
    { name: "the lease lookup before any lease key, naming the service key then in force", lookup: "lease", chain_seq: l1Seq - 1, signer: lv(s2Id, S2), expect: "bad_signature" },
    { name: "the service lookup never sees a lease key", lookup: "service", chain_seq: l2Seq, signer: lv(l2Id, L2, "service"), expect: "bad_signature" },
    { name: "the service key stays in force beside the lease keys", lookup: "service", chain_seq: l2Seq, signer: lv(s2Id, S2, "service"), expect: "ok" },
  ];
  entries.length = saved.n; seq = saved.seq; head = saved.head;

  // ---- 6. envelopes and objects outside the chain (§1.3, §3, §4), against the honest chain
  const encRaw = new Uint8Array(32).fill(9);
  const certBody = { fleet, aud: AUD, chain_seq: headAt.seq, host, sign_key: b64(H.raw), enc_key: b64(encRaw), fingerprint: b64(await hostFingerprint(host, H.raw, encRaw)), name: "lab-box", at_ms: NOW };
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
  // a lineage under the native policy (§3.2, the fleet page's anchored walk): the native first grant g1, then two
  // successive browser-signed narrowings, each verified against the one before it, as the host accepted them; on its
  // own (current null) a narrowing is a widening and refused; then a browser-signed widening of the last
  const n2 = grant(B, bId, { gen: 2, agents: [{ ...a0, workspace: [{ path: "/Algebra", access: "read" }] }] });
  const n3 = grant(B, bId, { gen: 3, not_after_ms: NOW + 1_800_000, agents: [{ ...a0, workspace: [{ path: "/Algebra", access: "read" }] }] });
  const w4 = grant(B, bId, { gen: 4, not_after_ms: NOW + 1_800_000, agents: [{ ...a0, workspace: [{ path: "/Algebra", access: "write" }] }] });
  grants.push(
    { name: "a lineage: a browser narrowing of the native first grant", bytes: n2, current: { gen: 1, bytes: g1 }, expect: "ok" },
    { name: "a lineage: a second browser narrowing, of the first narrowing", bytes: n3, current: { gen: 2, bytes: n2 }, expect: "ok" },
    { name: "a lineage: the first browser narrowing on its own", bytes: n2, current: null, expect: "device_tier" },
    { name: "a lineage: the second browser narrowing on its own", bytes: n3, current: null, expect: "device_tier" },
    { name: "a lineage: a browser widening of the second narrowing", bytes: w4, current: { gen: 3, bytes: n3 }, expect: "device_tier" },
  );
  const op = (k, kid, o, extra = {}) => txt(seal("sb.host-op.v1", signer(k, kid), { fleet, aud: AUD, chain_seq: headAt.seq, op_id: id(60 + Object.keys(extra).length), op: o, host, agent: "all", gen: 3, at_ms: NOW, not_after_ms: NOW + 600_000, ...extra }, k));
  const host_ops = [
    { name: "a pause", bytes: op(B, bId, "pause"), current_gen: 3, expect: "ok" },
    { name: "a resume from a browser device under the native policy", bytes: op(B, bId, "resume"), current_gen: 3, expect: "device_tier" },
    { name: "a resume from a native device", bytes: op(N, nId, "resume"), current_gen: 3, expect: "ok" },
    { name: "an old generation", bytes: op(N, nId, "stop", { gen: 2 }), current_gen: 3, expect: "stale_generation" },
    { name: "a life over 10 minutes", bytes: op(N, nId, "stop", { not_after_ms: NOW + 600_001 }), current_gen: 3, expect: "bad_form" },
  ];
  const subject = { agent, host, paths_hash: await preimageHash(["/tmp/a", "/tmp/b"]), count: 2 };
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
  // a host's acknowledgement of its grant (§3.3), against the certificate above, at current_gen 3
  const hostSigner = { kind: "host", id: host, alg: "ed25519", key: H.key };
  const ackBody = (extra = {}) => ({ fleet, aud: AUD, host, gen: 3, at_ms: NOW, narrowed: false, restarted: [], ...extra });
  const ack = (type, sg, body, k) => txt(seal(type, sg, body, k));
  const ack0 = ack("sb.grant-ack.v1", hostSigner, ackBody(), H);
  const grant_acks = [
    { name: "an ack of the current generation", bytes: ack0, current_gen: 3, expect: "ok" },
    { name: "an ack of an older generation", bytes: ack("sb.grant-ack.v1", hostSigner, ackBody({ gen: 2 }), H), current_gen: 3, expect: "ok" },
    { name: "an ack of the first grant", bytes: ack("sb.grant-ack.v1", hostSigner, ackBody({ gen: 1 }), H), current_gen: 1, expect: "ok" },
    { name: "an ack ahead of the grant", bytes: ack("sb.grant-ack.v1", hostSigner, ackBody({ gen: 4 }), H), current_gen: 3, expect: "stale_generation" },
    { name: "signed by a key other than the certified host's", bytes: ack("sb.grant-ack.v1", hostSigner, ackBody(), N2), current_gen: 3, expect: "bad_signature" },
    { name: "another host", bytes: ack("sb.grant-ack.v1", { ...hostSigner, id: agent }, ackBody({ host: agent }), H), current_gen: 3, expect: "bad_signature" },
    { name: "a device as an ack's signer (still well-formed; acks are signed by hosts)", bytes: txt(enc(canonText({ ...JSON.parse(ack0), signer: signer(N, nId) }))), current_gen: 3, expect: "bad_signature" },
    { name: "an ack's body under another type", bytes: ack("sb.audit-event.v1", hostSigner, ackBody(), H), current_gen: 3, expect: "bad_form" },
  ];
  const envelopes = [
    { name: "a host op, as signed", bytes: host_ops[0].bytes, expect: "ok" },
    { name: "another audience", bytes: host_ops[0].bytes, ctx: { aud: "https://sagebrush.space", fleet }, expect: "bad_audience" },
    { name: "the type swapped (still well-formed; the signature no longer verifies)", bytes: txt(enc(canonText({ ...JSON.parse(host_ops[0].bytes), type: "sb.revocation.v1" }))), expect: "bad_signature" },
    { name: "an extra field", bytes: txt(enc(canonText({ ...JSON.parse(host_ops[0].bytes), extra: 1 }))), expect: "bad_form" },
    { name: "a host signing a grant", bytes: txt(enc(canonText({ ...JSON.parse(g1), signer: { kind: "host", id: host, alg: "ed25519", key: H.key } }))), expect: "bad_signature" },
  ];

  // ---- 6b. agent messages (agent-messages r6 §2, with r7 to r10): a person->agent message signed by any enrolled
  // device of the fleet (no tier), and the host's signed records answering it; checked by verifyAgentMessage (against
  // the honest chain) and verifyAgentReply (against the certificate above). body_sha256 is over a ciphertext the
  // service never opens: here a fixed stand-in.
  const ct = sha256b64(enc("a sealed body"));
  const msgBody = (extra = {}) => ({ fleet, aud: AUD, host, agent, thread: id(90), id: id(91), in_reply_to: null, at_ms: NOW, chain_seq: headAt.seq, body_sha256: ct, ...extra });
  const msg = (k, sg, extra) => txt(seal("sb.agent-message.v1", sg, msgBody(extra), k));
  const repBody = (extra = {}) => ({ fleet, aud: AUD, host, agent, thread: id(90), id: id(92), in_reply_to: id(91), covers: [id(91)], turn: id(93), kind: "reply", reason: null, answer: null, at_ms: NOW, chain_seq: headAt.seq, body_sha256: ct, ...extra });
  const rep = (extra) => txt(seal("sb.agent-reply.v1", hostSigner, repBody(extra), H));
  // (a signer of a kind the type doesn't allow: seal() refuses to make one, so it is signed by hand, as an attacker would)
  const forge = async (type, sg, body, k) => txt(enc(canonText({ v: 1, type, signer: sg, body, sig: b64(await k.sign(signedBytes(type, sg, body))) })));
  const m0 = msg(B, signer(B, bId));
  const agent_messages = [
    { name: "a message from a browser device", bytes: m0, expect: "ok" },
    { name: "a message from a native device", bytes: msg(N, signer(N, nId)), expect: "ok" },
    { name: "a message answering another", bytes: msg(B, signer(B, bId), { in_reply_to: id(92) }), expect: "ok" },
    { name: "a message answering itself", bytes: msg(B, signer(B, bId), { in_reply_to: id(91) }), expect: "bad_form" },
    { name: "a message to another audience", bytes: m0, ctx: { aud: "https://sagebrush.space", fleet }, expect: "bad_audience" },
    { name: "a message with an extra field (a subject)", bytes: msg(B, signer(B, bId), { subject: "x" }), expect: "bad_form" },
    { name: "a message id that isn't a fleet id (B22-shaped)", bytes: msg(B, signer(B, bId), { id: "A".repeat(21) + "A" }), expect: "bad_form" },
    { name: "a message for another agent", bytes: msg(B, signer(B, bId), { agent: id(94) }), expect: "not_granted" },
    { name: "a message for another host", bytes: msg(B, signer(B, bId), { host: id(94) }), expect: "not_granted" },
    // (the device key's rules, on this type: enrolled at the record's chain_seq, not removed by then, and no chain_seq
    // past the head; chain "removed" is the transfers' chain_removed, the browser device removed at the next seq)
    { name: "a message from a device enrolled only after its chain_seq", bytes: msg(N2, signer(N2, n2Id), { chain_seq: 1 }), expect: "device_unknown" },
    { name: "a message from a device removed at or before its chain_seq", bytes: msg(B, signer(B, bId), { chain_seq: headAt.seq + 1 }), chain: "removed", expect: "device_unknown" },
    { name: "a message from a device enrolled at its chain_seq but removed by the head", bytes: msg(B, signer(B, bId)), chain: "removed", expect: "device_removed" },
    { name: "a message whose chain_seq is past the head", bytes: msg(B, signer(B, bId), { chain_seq: headAt.seq + 5 }), expect: "device_unknown" },
    { name: "a message signed by a host", bytes: await forge("sb.agent-message.v1", hostSigner, msgBody(), H), expect: "bad_signature" },
    { name: "a message's signer swapped to another device (the signature no longer verifies)", bytes: txt(enc(canonText({ ...JSON.parse(m0), signer: signer(N, nId) }))), expect: "bad_signature" },
  ];
  const agent_replies = [
    { name: "a reply", bytes: rep(), expect: "ok" },
    { name: "a reply covering three, in_reply_to the last", bytes: rep({ covers: [id(95), id(96), id(91)] }), expect: "ok" },
    { name: "a reply whose in_reply_to isn't the last of covers", bytes: rep({ covers: [id(91), id(95)] }), expect: "bad_form" },
    { name: "covers with a repeat", bytes: rep({ covers: [id(91), id(91)] }), expect: "bad_form" },
    { name: "covers of 64", bytes: rep({ covers: [...Array.from({ length: 63 }, (_, i) => id(100 + i)), id(91)] }), expect: "ok" },
    { name: "covers of 65", bytes: rep({ covers: [...Array.from({ length: 64 }, (_, i) => id(100 + i)), id(91)] }), expect: "bad_form" },
    { name: "a reply without a body", bytes: rep({ body_sha256: null }), expect: "bad_form" },
    { name: "a reply with a reason", bytes: rep({ reason: "crashed" }), expect: "bad_form" },
    { name: "a turn_failed: no body, a closed reason", bytes: rep({ kind: "turn_failed", reason: "crashed", body_sha256: null }), expect: "ok" },
    { name: "a turn_failed for a lost answer (C1)", bytes: rep({ kind: "turn_failed", reason: "answer_lost", body_sha256: null }), expect: "ok" },
    { name: "a turn_failed with a refused record's reason", bytes: rep({ kind: "turn_failed", reason: "replayed", body_sha256: null }), expect: "bad_form" },
    { name: "a turn_failed with a body", bytes: rep({ kind: "turn_failed", reason: "stalled" }), expect: "bad_form" },
    { name: "a refused record: no turn, no covers, no body", bytes: rep({ kind: "refused", reason: "not_granted", turn: null, covers: null, body_sha256: null }), expect: "ok" },
    { name: "a refused record with covers", bytes: rep({ kind: "refused", reason: "replayed", turn: null, body_sha256: null }), expect: "bad_form" },
    { name: "a refused record with a turn_failed's reason", bytes: rep({ kind: "refused", reason: "budget", turn: null, covers: null, body_sha256: null }), expect: "bad_form" },
    { name: "a covered record", bytes: rep({ kind: "covered", body_sha256: null }), expect: "ok" },
    { name: "a covered record naming the answer in another thread", bytes: rep({ kind: "covered", body_sha256: null, answer: { thread: id(97), id: id(98) } }), expect: "ok" },
    { name: "a covered record with a body", bytes: rep({ kind: "covered" }), expect: "bad_form" },
    { name: "an answer on a reply", bytes: rep({ answer: { thread: id(97), id: id(98) } }), expect: "bad_form" },
    { name: "a reply of kind message", bytes: rep({ kind: "message" }), expect: "bad_form" },
    { name: "a reason outside every closed set", bytes: rep({ kind: "turn_failed", reason: "because", body_sha256: null }), expect: "bad_form" },
    { name: "a reply signed by a device", bytes: await forge("sb.agent-reply.v1", signer(N, nId), repBody(), N), expect: "bad_signature" },
    { name: "a reply signed by a key other than the certified host's", bytes: txt(seal("sb.agent-reply.v1", hostSigner, repBody(), N2)), expect: "bad_signature" },
    { name: "the certified host's signature under another key id", bytes: txt(seal("sb.agent-reply.v1", { ...hostSigner, key: N2.key }, repBody(), H)), expect: "bad_signature" },
    { name: "the certified host's signature over a body naming another host", bytes: rep({ host: id(94) }), expect: "bad_signature" },
    { name: "a refused record with a turn but no covers", bytes: rep({ kind: "refused", reason: "replayed", covers: null, body_sha256: null }), expect: "bad_form" },
    { name: "a covered record without covers", bytes: rep({ kind: "covered", body_sha256: null, covers: null }), expect: "bad_form" },
    { name: "a turn_failed without a turn", bytes: rep({ kind: "turn_failed", reason: "crashed", body_sha256: null, turn: null }), expect: "bad_form" },
    { name: "answer_lost on a refused record (r11)", bytes: rep({ kind: "refused", reason: "answer_lost", turn: null, covers: null, body_sha256: null }), expect: "bad_form" },
    { name: "not_granted on a turn_failed (r11)", bytes: rep({ kind: "turn_failed", reason: "not_granted", body_sha256: null }), expect: "bad_form" },
    { name: "an answer on a turn_failed", bytes: rep({ kind: "turn_failed", reason: "crashed", body_sha256: null, answer: { thread: id(97), id: id(98) } }), expect: "bad_form" },
    { name: "an answer on a refused record", bytes: rep({ kind: "refused", reason: "replayed", turn: null, covers: null, body_sha256: null, answer: { thread: id(97), id: id(98) } }), expect: "bad_form" },
  ];

  // ---- 7. moving an agent (r2.4 §3.7): the receipt pair (checks 1-3), then the new host's own (checks 4-6)
  const tSigned = (type, sg, b) => sha256b64(signedBytes(type, sg, b));
  const g1Env = JSON.parse(g1);
  const grantHash = tSigned("sb.host-grant.v1", g1Env.signer, g1Env.body);
  const nonceT = b64(Uint8Array.from({ length: 16 }, (_, i) => 200 + i));
  const fromHost = id(30);
  const tBody = (extra = {}) => ({ fleet, aud: AUD, agent, from_host: fromHost, to_host: host, to_host_key: certBody.fingerprint, gen: 3, grant: grantHash, nonce: nonceT,
    chain_seq: headAt.seq, at_ms: NOW, not_after_ms: NOW + 600_000, auth_time_ms: NOW, ...extra });
  const tEnv = (k, sg, b, type = "sb.agent-transfer.v1") => ({ text: txt(seal(type, sg, b, k)), hash: tSigned(type, sg, b) });
  const T0 = tEnv(N, signer(N, nId), tBody());
  const rBody = (tHash, extra = {}) => ({ fleet, aud: AUD, agent, from_host: fromHost, to_host: host, to_host_key: certBody.fingerprint, gen: 3, nonce: nonceT,
    transfer: tHash, chain_seq: s2Seq, at_ms: NOW, ...extra });
  const rcpt = (k, sg, b, type = "sb.agent-transfer-receipt.v1") => txt(seal(type, sg, b, k));
  const R0 = rcpt(S2, sv(s2Id, S2), rBody(T0.hash));
  const withT = (t, extraR = {}) => ({ transfer: t.text, receipt: rcpt(S2, sv(s2Id, S2), rBody(t.hash, extraR)) });
  const removedChain = [...honest, next(N, nId, "remove", { remove: bId, regrants: [] })];
  const late = tEnv(N, signer(N, nId), tBody({ at_ms: NOW - 7_200_000, not_after_ms: NOW - 6_600_000, auth_time_ms: NOW - 7_200_000 }));
  const transfer_receipts = [
    { name: "a transfer and its receipt", ...withT(T0), expect: "ok" },
    { name: "the new key at the rotation's boundary", transfer: T0.text, receipt: R0, expect: "ok" },
    { name: "a receipt signed before the rotation, verified after it", transfer: T0.text, receipt: rcpt(S1, sv(s1Id, S1), rBody(T0.hash, { chain_seq: s1Seq })), expect: "ok" },
    { name: "the old key at the new key's chain_seq", transfer: T0.text, receipt: rcpt(S1, sv(s1Id, S1), rBody(T0.hash)), expect: "bad_signature" },
    { name: "a receipt past the pinned head", transfer: T0.text, receipt: rcpt(S2, sv(s2Id, S2), rBody(T0.hash, { chain_seq: s2Seq + 1 })), expect: "device_unknown" },
    { name: "a receipt for another fleet", transfer: T0.text, receipt: rcpt(S2, sv(s2Id, S2), rBody(T0.hash, { fleet: id(99) })), expect: "bad_form" },
    { name: "a receipt for another audience", transfer: T0.text, receipt: rcpt(S2, sv(s2Id, S2), rBody(T0.hash, { aud: "https://sagebrush.space" })), expect: "bad_audience" },
    { name: "a device as a receipt's signer (still well-formed; receipts are the service's)", transfer: T0.text, receipt: txt(enc(canonText({ ...JSON.parse(R0), signer: signer(N, nId) }))), expect: "bad_signature" },
    { name: "a receipt's body under another type", transfer: T0.text, receipt: rcpt(S2, sv(s2Id, S2), rBody(T0.hash), "sb.audit-ack.v1"), expect: "bad_form" },
    { name: "the service as a transfer's signer (still well-formed; transfers are a device's)", transfer: txt(enc(canonText({ ...JSON.parse(T0.text), signer: sv(s2Id, S2) }))), receipt: R0, expect: "bad_signature" },
    { name: "a transfer whose signer wasn't enrolled at its chain_seq", ...withT(tEnv(N2, signer(N2, n2Id), tBody({ chain_seq: 1 }))), expect: "device_unknown" },
    { name: "a transfer whose signer was removed at the pinned head", chain: "removed", ...withT(tEnv(B, signer(B, bId), tBody())), expect: "device_removed" },
    { name: "a browser device under the native policy (a transfer widens)", ...withT(tEnv(B, signer(B, bId), tBody())), expect: "device_tier" },
    { name: "a transfer past its not_after_ms at the resume (the window is the service's check)", ...withT(late), expect: "ok" },
    { name: "a transfer's body under another type", ...withT(tEnv(N, signer(N, nId), tBody(), "sb.host-op.v1")), expect: "bad_form" },
    { name: "the receipt names another transfer", transfer: T0.text, receipt: rcpt(S2, sv(s2Id, S2), rBody(late.hash)), expect: "bad_form" },
    ...["agent", "from_host", "to_host", "to_host_key", "gen", "nonce"].map((k) => ({
      name: `the receipt's ${k} differs, both signatures valid`, transfer: T0.text,
      receipt: rcpt(S2, sv(s2Id, S2), rBody(T0.hash, { [k]: k === "gen" ? 4 : k === "nonce" ? b64(new Uint8Array(16).fill(1)) : k === "to_host_key" ? b64(new Uint8Array(32).fill(2)) : id(40) })), expect: "bad_form" })),
  ];
  // checks 4-6 over the host's records (JSON: grants by gen with their hash and agents; listed_since, entry_gen,
  // accepted and nonces by key), for the verified pair above
  const pair0 = { transfer: tBody(), transferHash: T0.hash };
  const rec = (over = {}) => ({ id: host, fingerprint: certBody.fingerprint, grants: { 3: { hash: grantHash, agents: [agent] } }, listed_since: { [agent]: 3 },
    entry_gen: { [agent]: 3 }, accepted: {}, nonces: {}, ...over });
  const otherHash = b64(new Uint8Array(32).fill(5));
  const transfer_hosts = [
    { name: "the first acceptance", pair: pair0, host: rec(), expect: "ok", first: true },
    { name: "the accepted pair again (a resume retried)", pair: pair0, host: rec({ accepted: { [agent]: { gen: 3, nonce: nonceT, transfer: T0.hash } }, nonces: { [nonceT]: T0.hash } }), expect: "ok", first: false },
    { name: "to another host", pair: { ...pair0, transfer: tBody({ to_host: id(31) }) }, host: rec(), expect: "not_granted" },
    { name: "a to_host_key that isn't this host's fingerprint", pair: pair0, host: rec({ fingerprint: otherHash }), expect: "not_granted" },
    { name: "a grant hash this host never accepted", pair: pair0, host: rec({ grants: { 3: { hash: otherHash, agents: [agent] } } }), expect: "not_granted" },
    { name: "no grant accepted at that generation", pair: pair0, host: rec({ grants: {} }), expect: "not_granted" },
    { name: "a grant that doesn't list the agent", pair: pair0, host: rec({ grants: { 3: { hash: grantHash, agents: [] } } }), expect: "not_granted" },
    { name: "the agent not in the current grant", pair: pair0, host: rec({ listed_since: {}, entry_gen: {} }), expect: "not_granted" },
    { name: "the agent dropped and re-added after gen", pair: pair0, host: rec({ listed_since: { [agent]: 5 }, entry_gen: { [agent]: 5 } }), expect: "stale_generation" },
    { name: "an entry generation below gen", pair: pair0, host: rec({ entry_gen: { [agent]: 2 } }), expect: "stale_generation" },
    { name: "an entry that moved up since (the person edited it)", pair: pair0, host: rec({ entry_gen: { [agent]: 6 } }), expect: "ok", first: true },
    { name: "an unrelated later grant", pair: pair0, host: rec({ grants: { 3: { hash: grantHash, agents: [agent] }, 4: { hash: otherHash, agents: [agent, id(33)] } } }), expect: "ok", first: true },
    { name: "the next transfer of a multi-agent restore", pair: pair0, host: rec({ accepted: { [id(32)]: { gen: 3, nonce: b64(new Uint8Array(16).fill(3)), transfer: otherHash } } }), expect: "ok", first: true },
    { name: "a gen not above the transfer this host accepted", pair: pair0, host: rec({ accepted: { [agent]: { gen: 3, nonce: b64(new Uint8Array(16).fill(4)), transfer: otherHash } } }), expect: "stale_generation" },
    { name: "a newer move than the one accepted", pair: pair0, host: rec({ accepted: { [agent]: { gen: 2, nonce: b64(new Uint8Array(16).fill(4)), transfer: otherHash } } }), expect: "ok", first: true },
    { name: "a nonce this host saw for another transfer", pair: pair0, host: rec({ nonces: { [nonceT]: otherHash } }), expect: "replay" },
    { name: "the nonce seen for this same transfer", pair: pair0, host: rec({ nonces: { [nonceT]: T0.hash } }), expect: "ok", first: true },
  ];

  // ---- 8. execution-lease renewal (r2.5 §3.8.3), on the leased chain (§1.7a's keys), with the objects' host
  const hs = { kind: "host", id: host, alg: "ed25519", key: H.key };
  // (an envelope seal() refuses to make, for a signer kind the type doesn't accept)
  const rawSeal = (type, s, b, k) => txt(enc(canonText({ v: 1, type, signer: s, body: b, sig: b64(k.sign(signedBytes(type, s, b))) })));
  const BOOT = "0f6c2b5e-8d3a-4c1e-9b7f-2a4d6e8f0a1c";
  const lNonce = b64(new Uint8Array(16).fill(9));
  const reqBody = (extra = {}) => ({ fleet, aud: AUD, agent, host, gen: 3, nonce: lNonce, boot_id: BOOT, at_ms: NOW, ...extra });
  const rq = reqBody();
  const reqBytes = txt(seal("sb.lease-request.v1", hs, rq, H));
  const reqHash = sha256b64(signedBytes("sb.lease-request.v1", hs, rq));
  const H2 = keyFromSeed(seed(50));
  const lease_requests = [
    { name: "a request", bytes: reqBytes, expect: "ok", hash: reqHash },
    { name: "signed by a device", bytes: rawSeal("sb.lease-request.v1", signer(N, nId), rq, N), expect: "bad_signature" },
    { name: "signed by another host key under this host's id", bytes: txt(seal("sb.lease-request.v1", { ...hs, key: H2.key }, rq, H2)), expect: "bad_signature" },
    { name: "the certified key id with another key's signature", bytes: txt(seal("sb.lease-request.v1", hs, rq, H2)), expect: "bad_signature" },
    { name: "this host's signature under another key id", bytes: rawSeal("sb.lease-request.v1", { ...hs, key: H2.key }, rq, H), expect: "bad_signature" },
    { name: "a body naming another host, signed by this one", bytes: txt(seal("sb.lease-request.v1", hs, reqBody({ host: id(51) }), H)), expect: "bad_signature" },
    { name: "for another host id", bytes: txt(seal("sb.lease-request.v1", { ...hs, id: id(51) }, reqBody({ host: id(51) }), H)), expect: "bad_signature" },
    { name: "another fleet", bytes: txt(seal("sb.lease-request.v1", hs, reqBody({ fleet: id(52) }), H)), expect: "bad_form" },
    { name: "another audience", bytes: txt(seal("sb.lease-request.v1", hs, reqBody({ aud: "https://sagebrush.space" }), H)), expect: "bad_audience" },
    { name: "gen 0", bytes: txt(seal("sb.lease-request.v1", hs, reqBody({ gen: 0 }), H)), expect: "bad_form" },
    { name: "an extra field", bytes: txt(seal("sb.lease-request.v1", hs, reqBody({ ttl_ms: 1 }), H)), expect: "bad_form" },
  ];
  const ls = (k, lid, kind = "lease") => ({ kind, id: lid, alg: "ed25519", key: k.key });
  const leaseBody = (extra = {}) => ({ fleet, aud: AUD, agent, host, host_key: certBody.fingerprint, gen: 3, lease_id: id(53), ttl_ms: 600_000,
    nonce: lNonce, boot_id: BOOT, request: reqHash, chain_seq: l2Seq, ...extra });
  const lease = (extra, k = L2, s = ls(L2, l2Id)) => txt(seal("sb.execution-lease.v1", s, leaseBody(extra), k));
  const outstanding = { request: reqHash, agent, gen: 3, nonce: lNonce, boot_id: BOOT };
  const envelopeHash = sha256b64(enc(reqBytes));
  const leases = [
    { name: "a lease", bytes: lease({}), expect: "ok" },
    { name: "a lease under the old key, signed before the rotation", bytes: lease({ chain_seq: l1Seq + 1 }, L1, ls(L1, l1Id)), expect: "ok" },
    { name: "ttl_ms at its bound", bytes: lease({ ttl_ms: 600_000 }), expect: "ok" },
    { name: "the old key at the rotation's seq", bytes: lease({}, L1, ls(L1, l1Id)), expect: "bad_signature" },
    { name: "chain_seq past the pinned head", bytes: lease({ chain_seq: l2Seq + 1 }), expect: "device_unknown" },
    { name: "signed by the service key", bytes: txt(seal("sb.execution-lease.v1", { kind: "lease", id: s2Id, alg: "ed25519", key: S2.key }, leaseBody(), S2)), expect: "bad_signature" },
    { name: "signer kind service", bytes: rawSeal("sb.execution-lease.v1", ls(L2, l2Id, "service"), leaseBody(), L2), expect: "bad_signature" },
    { name: "signer kind host", bytes: rawSeal("sb.execution-lease.v1", hs, leaseBody(), H), expect: "bad_signature" },
    { name: "another fleet", bytes: lease({ fleet: id(54) }), expect: "bad_form" },
    { name: "another audience", bytes: lease({ aud: "https://sagebrush.space" }), expect: "bad_audience" },
    { name: "another host", bytes: lease({ host: id(55) }), expect: "not_granted" },
    { name: "another host key", bytes: lease({ host_key: b64(new Uint8Array(32).fill(7)) }), expect: "not_granted" },
    { name: "another request", bytes: lease({ request: b64(new Uint8Array(32).fill(8)) }), expect: "not_granted" },
    { name: "the request's envelope hash, not its signed bytes'", bytes: lease({ request: envelopeHash }), expect: "not_granted" },
    { name: "another agent", bytes: lease({ agent: id(56) }), expect: "not_granted" },
    { name: "another gen", bytes: lease({ gen: 4 }), expect: "not_granted" },
    { name: "another nonce", bytes: lease({ nonce: b64(new Uint8Array(16).fill(10)) }), expect: "not_granted" },
    { name: "another boot", bytes: lease({ boot_id: "1f6c2b5e-8d3a-4c1e-9b7f-2a4d6e8f0a1c" }), expect: "not_granted" },
    { name: "no request outstanding", bytes: lease({}), outstanding: null, expect: "not_granted" },
    { name: "ttl_ms 0", bytes: lease({ ttl_ms: 0 }), expect: "bad_form" },
    { name: "ttl_ms one past its bound", bytes: lease({ ttl_ms: 600_001 }), expect: "bad_form" },
  ].map((c) => ({ ...c, outstanding: c.outstanding === undefined ? outstanding : c.outstanding }));

  // ---- 9. the old host's fence acknowledgement (r2.4 §3.7.4): the envelope's check, by the host's certified key
  const fbody = (extra = {}) => ({ fleet, aud: AUD, agent, host, gen: 3, transfer: b64(new Uint8Array(32).fill(11)), boot_id: BOOT, proven_empty: true, at_ms: NOW, ...extra });
  const fb = fbody();
  const fence_acks = [
    { name: "an acknowledgement", bytes: txt(seal("sb.agent-fence-ack.v1", hs, fb, H)), expect: "ok", hash: sha256b64(signedBytes("sb.agent-fence-ack.v1", hs, fb)) },
    { name: "signed by a device", bytes: rawSeal("sb.agent-fence-ack.v1", signer(N, nId), fb, N), expect: "bad_signature" },
    { name: "another host key under this host's id", bytes: txt(seal("sb.agent-fence-ack.v1", { ...hs, key: H2.key }, fb, H2)), expect: "bad_signature" },
    { name: "this host's signature under another key id", bytes: rawSeal("sb.agent-fence-ack.v1", { ...hs, key: H2.key }, fb, H), expect: "bad_signature" },
    { name: "a body naming another host", bytes: txt(seal("sb.agent-fence-ack.v1", hs, fbody({ host: id(57) }), H)), expect: "bad_signature" },
    { name: "proven_empty false", bytes: txt(seal("sb.agent-fence-ack.v1", hs, fbody({ proven_empty: false }), H)), expect: "bad_form" },
    { name: "another fleet", bytes: txt(seal("sb.agent-fence-ack.v1", hs, fbody({ fleet: id(58) }), H)), expect: "bad_form" },
    { name: "another audience", bytes: txt(seal("sb.agent-fence-ack.v1", hs, fbody({ aud: "https://sagebrush.space" }), H)), expect: "bad_audience" },
    { name: "an extra field", bytes: txt(seal("sb.agent-fence-ack.v1", hs, fbody({ reason: "x" }), H)), expect: "bad_form" },
  ];

  // ---- the fleet fingerprint (host pairing's trust anchor): over the fleet id and the genesis entry's exact bytes
  const fp = async (name, f, genesis) => { const full = await fleetFingerprint(f, enc(genesis)); return { name, fleet: f, genesis, full: b64(full), shown: showFingerprint(full) }; };
  const fingerprints = [
    await fp("the honest chain's genesis", fleet, honest[0]),
    await fp("the same genesis under another fleet id", id(59), honest[0]),
    await fp("one byte more after the genesis's text: other bytes, another fingerprint", fleet, honest[0] + " "),
  ];

  return {
    $comment: "Shared fleet-protocol vectors (agent-autonomous-schemas.md r2.5 §9, §3.7.5, §3.8.3). Built by test/make-fleet-fixtures.mjs; every implementation must agree with every case. Mock data only: no real key, device or host.",
    freeze: FREEZE.sha256,
    aud: AUD, now_ms: NOW, ids, keys,
    canonical, base64url, ids_cases: idCases, ed25519,
    chain: { entries_note: "envelope texts, in order", cases: chain },
    service_keys: { chain: honest, cases: service_keys },
    lease_keys: { chain: leased, chain_cases: lease_chain, cases: lease_keys },
    fence_acks: { chain: honest, host_cert: cert, cases: fence_acks },
    leases: { chain: leased, host_cert: cert, host: host, host_key: certBody.fingerprint, requests: lease_requests, leases },
    objects: { chain: honest, host_cert: cert, grants, grant_acks, host_ops, approvals, envelopes, agent_messages, agent_replies },
    transfers: { chain: honest, chain_removed: removedChain, receipts: transfer_receipts, hosts: transfer_hosts },
    fleet_fingerprints: fingerprints,
  };
}

if (import.meta.url === `file://${process.argv[1]}`) process.stdout.write(canonText(await build(), 4 << 20) + "\n");
