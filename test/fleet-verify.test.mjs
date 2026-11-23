// Reference verifiers for objects outside the device chain (r2.3 §3, §4): host certificates (computed fingerprints),
// grants (generation and re-apply, cross-field rules, /.agents, tier when widening, the removal rule), the host's
// ack, person-signed host ops, revocations (which outlive their signer's removal) and typed approvals.
import assert from "node:assert/strict";
import { test } from "node:test";
import { FleetError, b64, enc, newId, sha256b64 } from "../lib/fleet/bytes.mjs";
import { canonText } from "../lib/fleet/canonical.mjs";
import { keyFromSeed } from "../lib/fleet/ed25519.mjs";
import { seal, sealAdd } from "../lib/fleet/envelope.mjs";
import { apply } from "../lib/fleet/chain.mjs";
import {
  hostFingerprint, narrowsOnly, preimageHash, showFingerprint, verifyApproval, verifyGrant, verifyGrantAck, verifyHostCert,
  verifyHostOp, verifyRevocation,
} from "../lib/fleet/verify.mjs";

const AUD = "https://dev.sagebrush.space";
const code = (fn) => { try { fn(); } catch (e) { if (e instanceof FleetError) return e.code; throw e; } return "ok"; };
let n = 40;
const key = () => keyFromSeed(new Uint8Array(32).fill(n++));
const NOW = 1_800_000_000_000;

/** A fleet with a native device N and a browser device B; helpers to sign as either. */
function fleet() {
  const id = newId(), ctx = { aud: AUD, fleet: id };
  const mk = (tier) => { const k = key(); const d = newId(); return { id: d, k, tier, entry: { id: d, alg: "ed25519", key: b64(k.raw), name: tier, tier }, signer: { kind: "device", id: d, alg: "ed25519", key: k.key } }; };
  const N = mk("native"), B = mk("browser"), rec = key();
  let state = apply(null, seal("sb.device-chain.v1", N.signer, { fleet: id, aud: AUD, seq: 0, prev: "", op: "genesis", at_ms: 1, auth_time_ms: 1, device: N.entry, recovery_key: { alg: "ed25519", key: b64(rec.raw) } }, N.k), ctx).state;
  state = apply(state, sealAdd(N.signer, { fleet: id, aud: AUD, seq: 1, prev: state.head, op: "add", at_ms: 1, auth_time_ms: 1, device: B.entry }, N.k, B.k), ctx).state;
  const f = {
    id, ctx, N, B, get state() { return state; },
    chainOp(by, op, extra) { state = apply(state, seal("sb.device-chain.v1", by.signer, { fleet: id, aud: AUD, seq: state.seq + 1, prev: state.head, op, at_ms: 1, auth_time_ms: 1, ...extra }, by.k), ctx).state; },
    sign(type, by, body) { return seal(type, by.signer, { fleet: id, aud: AUD, chain_seq: state.seq, ...body }, by.k); },
  };
  return f;
}

function hostOf(f, by = f.N) {
  const host = newId(), hk = key(), encRaw = new Uint8Array(32).fill(9);
  const fp = hostFingerprint(host, hk.raw, encRaw);
  const bytes = f.sign("sb.host-cert.v1", by, { host, sign_key: b64(hk.raw), enc_key: b64(encRaw), fingerprint: b64(fp), name: "lab-box", at_ms: 1 });
  const cert = verifyHostCert(bytes, { ...f.ctx, chain: f.state });
  return { host, hk, cert, bytes };
}

function grantBody(f, h, extra = {}) {
  const agent = extra.agent ?? newId(), tag = newId();
  return {
    host: h.host, gen: 1, cert: h.cert.hash, at_ms: NOW - 1000, not_before_ms: NOW - 1000, not_after_ms: NOW + 3_600_000, auth_time_ms: NOW,
    agents: [{ agent, name: "worker", client: "claude", root: false, tags: [tag], workspace: [{ path: "/Algebra", access: "write" }],
      broker: ["messages", "workspace"], spend_cap_cents: 0, config_schema: 1, config: {} }],
    tags: [{ tag, name: "course" }], subscriptions: [], offline: { revocation_check_s: 900, horizon_s: 3600 }, ...extra,
  };
}

test("fingerprints: the display is the first 100 bits, in groups of four; a host cert's fingerprint is recomputed", () => {
  const full = Uint8Array.from({ length: 32 }, (_, i) => i * 7);
  let bits = "";
  for (const x of full) bits += x.toString(2).padStart(8, "0");
  const A = "abcdefghijklmnopqrstuvwxyz234567";
  const expect = bits.slice(0, 100).match(/.{5}/g).map((c) => A[parseInt(c, 2)]).join("").match(/.{4}/g).join("-");
  assert.equal(showFingerprint(full), expect);
  const f = fleet(), h = hostOf(f);
  assert.equal(h.cert.body.host, h.host);
  const { fleet: _f, aud: _a, chain_seq: _c, ...certBody } = h.cert.body;
  const bad = f.sign("sb.host-cert.v1", f.N, { ...certBody, fingerprint: sha256b64(new Uint8Array([1])) });
  assert.equal(code(() => verifyHostCert(bad, { ...f.ctx, chain: f.state })), "bad_form");
  const zero = f.sign("sb.host-cert.v1", f.N, { host: h.host, sign_key: b64(h.hk.raw), enc_key: b64(new Uint8Array(32)), fingerprint: b64(hostFingerprint(h.host, h.hk.raw, new Uint8Array(32))), name: "x", at_ms: 1 });
  assert.equal(code(() => verifyHostCert(zero, { ...f.ctx, chain: f.state })), "bad_form", "an all-zero X25519 key");
});

test("grants: in force, for this host and cert; generation up only, with a byte-identical re-apply; stale refused", () => {
  const f = fleet(), h = hostOf(f);
  const ctx = (current) => ({ ...f.ctx, chain: f.state, cert: h.cert, current, now: NOW });
  const g1 = f.sign("sb.host-grant.v1", f.N, grantBody(f, h));
  const v1 = verifyGrant(g1, ctx(null));
  assert.equal(v1.reapply, false);
  const cur = { gen: 1, bytes: g1, body: v1.body };
  assert.equal(verifyGrant(g1, ctx(cur)).reapply, true, "the same bytes again");
  const g1b = f.sign("sb.host-grant.v1", f.N, grantBody(f, h, { at_ms: NOW - 999 }));
  assert.equal(code(() => verifyGrant(g1b, ctx(cur))), "stale_generation", "the same generation, other bytes");
  const g0 = f.sign("sb.host-grant.v1", f.N, { ...grantBody(f, h), gen: 1 });
  assert.equal(code(() => verifyGrant(g0, ctx({ ...cur, gen: 2 }))), "stale_generation");
  const other = hostOf(f);
  assert.equal(code(() => verifyGrant(g1, { ...ctx(null), cert: other.cert })), "not_granted");
  const expired = f.sign("sb.host-grant.v1", f.N, grantBody(f, h, { not_after_ms: NOW - 1 }));
  assert.equal(code(() => verifyGrant(expired, ctx(null))), "grant_expired");
  const early = f.sign("sb.host-grant.v1", f.N, grantBody(f, h, { not_before_ms: NOW + 1 }));
  assert.equal(code(() => verifyGrant(early, ctx(null))), "grant_expired");
  assert.equal(code(() => verifyGrant(f.sign("sb.host-grant.v1", f.N, grantBody(f, h, { not_after_ms: NOW })), ctx(null))), "grant_expired", "now = not_after is out");
});

test("grants: cross-field rules: no_expiry_ack exactly with null, known tags, no /.agents, unique ids, codex-only homes", () => {
  const f = fleet(), h = hostOf(f);
  const ctx = { ...f.ctx, chain: f.state, cert: h.cert, current: null, now: NOW };
  const base = grantBody(f, h);
  const g = (extra) => f.sign("sb.host-grant.v1", f.N, { ...base, ...extra });
  assert.equal(code(() => verifyGrant(g({ not_after_ms: null, no_expiry_ack: true }), ctx)), "ok");
  assert.equal(code(() => verifyGrant(g({ not_after_ms: null }), ctx)), "bad_form");
  assert.equal(code(() => verifyGrant(g({ no_expiry_ack: true }), ctx)), "bad_form");
  const a = base.agents[0];
  assert.equal(code(() => verifyGrant(g({ agents: [{ ...a, tags: [newId()] }] }), ctx)), "bad_form", "an unknown tag");
  for (const path of ["/.agents", "/.agents/x"]) assert.equal(code(() => verifyGrant(g({ agents: [{ ...a, workspace: [{ path, access: "read" }] }] }), ctx)), "not_granted", path);
  assert.equal(code(() => verifyGrant(g({ agents: [{ ...a, workspace: [{ path: "/.agentsx", access: "read" }] }] }), ctx)), "ok", "only the folder itself");
  // non-canonical paths are refused before any comparison: they would resolve into /.agents, or alias another path
  for (const path of ["/x/../.agents", "/x/../.agents/y", "//.agents", "/./.agents", "/Algebra/", "/Algebra//b", "/a/./b", "/a\u0001b", "/" + "a/".repeat(32) + "a", "/" + "n".repeat(256)])
    assert.equal(code(() => verifyGrant(g({ agents: [{ ...a, workspace: [{ path, access: "read" }] }] }), ctx)), "bad_form", JSON.stringify(path));
  assert.equal(code(() => verifyGrant(g({ agents: [{ ...a, workspace: [{ path: "/", access: "read" }] }] }), ctx)), "ok", "the root is canonical");
  assert.equal(code(() => verifyGrant(g({ agents: [{ ...a, workspace: [{ path: "/" + "n".repeat(255), access: "read" }] }] }), ctx)), "ok", "a 255-character name");
  assert.equal(code(() => verifyGrant(g({ agents: [a, a] }), ctx)), "bad_form");
  const sub = newId();
  assert.equal(code(() => verifyGrant(g({ subscriptions: [{ sub, provider: "claude", use: [a.agent], home: true }] }), ctx)), "bad_form");
  assert.equal(code(() => verifyGrant(g({ subscriptions: [{ sub, provider: "codex", use: [a.agent], home: true }] }), ctx)), "ok");
  assert.equal(code(() => verifyGrant(g({ subscriptions: [{ sub, provider: "codex", use: [newId()], home: false }] }), ctx)), "bad_form");
  assert.equal(code(() => verifyGrant(g({}), { ...ctx, checkAuthTime: true, now: NOW + 5 * 60_000 + 1 })), "stale_auth");
});

test("grants: under the native policy a browser device may only narrow; a removed signer's grant loses its force", () => {
  const f = fleet(), h = hostOf(f);
  const body1 = grantBody(f, h);
  const g1 = f.sign("sb.host-grant.v1", f.B, body1);
  const ctx = (current) => ({ ...f.ctx, chain: f.state, cert: h.cert, current, now: NOW });
  const v1 = verifyGrant(g1, ctx(null)); // (policy off: a browser may widen)
  f.chainOp(f.N, "policy", { policy: { require_native_for_widening: true } });
  const cur = { gen: 1, bytes: g1, body: v1.body };
  const a = body1.agents[0];
  const narrower = f.sign("sb.host-grant.v1", f.B, { ...body1, gen: 2, agents: [{ ...a, broker: ["messages"] }] });
  assert.equal(verifyGrant(narrower, ctx(cur)).widens, false);
  const wider = f.sign("sb.host-grant.v1", f.B, { ...body1, gen: 2, agents: [{ ...a, broker: ["messages", "workspace", "memory"] }] });
  assert.equal(code(() => verifyGrant(wider, ctx(cur))), "device_tier");
  const longer = f.sign("sb.host-grant.v1", f.B, { ...body1, gen: 2, not_after_ms: body1.not_after_ms + 1 });
  assert.equal(code(() => verifyGrant(longer, ctx(cur))), "device_tier", "a renewal widens");
  assert.equal(code(() => verifyGrant(f.sign("sb.host-grant.v1", f.N, { ...body1, gen: 2, not_after_ms: body1.not_after_ms + 1 }), ctx(cur))), "ok");
  // removal: the browser's grant, accepted before, no longer counts (even re-applied)
  f.chainOp(f.N, "remove", { remove: f.B.id, regrants: [] });
  assert.equal(code(() => verifyGrant(g1, ctx(cur))), "device_removed");
});

test("narrowsOnly: each widening dimension counts; pure narrowing doesn't", () => {
  const f = fleet(), h = hostOf(f);
  const p = grantBody(f, h);
  const a = p.agents[0];
  assert.equal(narrowsOnly(p, p), true);
  assert.equal(narrowsOnly(null, p), false);
  for (const next of [
    { ...p, agents: [{ ...a, root: true }] }, { ...p, agents: [{ ...a, client: "codex" }] }, { ...p, agents: [{ ...a, spend_cap_cents: 1 }] },
    { ...p, agents: [{ ...a, workspace: [{ path: "/Other", access: "read" }] }] }, { ...p, agents: [a, { ...a, agent: newId() }] },
    { ...p, tags: [...p.tags, { tag: newId(), name: "x" }] }, { ...p, not_after_ms: null }, { ...p, not_before_ms: p.not_before_ms - 1 },
    { ...p, offline: { revocation_check_s: 901, horizon_s: 3600 } }, { ...p, offline: { revocation_check_s: 900, horizon_s: 3601 } },
  ]) assert.equal(narrowsOnly(p, next), false, JSON.stringify(next).slice(0, 80));
  const writeToRead = { ...p, agents: [{ ...a, workspace: [{ path: "/Algebra", access: "read" }], tags: [] }], not_after_ms: p.not_after_ms - 1 };
  assert.equal(narrowsOnly(p, writeToRead), true);
});

test("the host's ack: signed by the certified host key, not ahead of the grant", () => {
  const f = fleet(), h = hostOf(f);
  const ack = (gen, k = h.hk, host = h.host) => seal("sb.grant-ack.v1", { kind: "host", id: host, alg: "ed25519", key: k.key }, { fleet: f.id, aud: AUD, host, gen, at_ms: 1, narrowed: false, restarted: [] }, k);
  const ctx = { ...f.ctx, cert: h.cert, currentGen: 2 };
  assert.equal(verifyGrantAck(ack(2), ctx).gen, 2);
  assert.equal(code(() => verifyGrantAck(ack(3), ctx)), "stale_generation");
  assert.equal(code(() => verifyGrantAck(ack(2, key()), ctx)), "bad_signature");
  assert.equal(code(() => verifyGrantAck(ack(2, h.hk, newId()), ctx)), "bad_signature");
});

test("host ops: this host and generation, a 10-minute life, once; resume and delete need the native tier under the policy", () => {
  const f = fleet(), h = hostOf(f);
  const seen = new Set();
  const op = (by, o, extra = {}) => f.sign("sb.host-op.v1", by, { op_id: newId(), op: o, host: h.host, agent: "all", gen: 3, at_ms: NOW, not_after_ms: NOW + 600_000, ...extra });
  const ctx = { ...f.ctx, chain: f.state, host: h.host, currentGen: 3, now: NOW, seenOp: (id) => seen.has(id) };
  const p = op(f.B, "pause");
  const v = verifyHostOp(p, ctx); seen.add(v.op_id);
  assert.equal(code(() => verifyHostOp(p, ctx)), "replay");
  assert.equal(code(() => verifyHostOp(op(f.N, "stop", { gen: 2 }), ctx)), "stale_generation");
  assert.equal(code(() => verifyHostOp(op(f.N, "stop", { host: newId() }), ctx)), "not_granted");
  assert.equal(code(() => verifyHostOp(op(f.N, "stop", { not_after_ms: NOW + 600_001 }), ctx)), "bad_form");
  assert.equal(code(() => verifyHostOp(op(f.N, "stop"), { ...ctx, now: NOW + 600_000 })), "grant_expired");
  f.chainOp(f.N, "policy", { policy: { require_native_for_widening: true } });
  const ctx2 = { ...ctx, chain: f.state };
  assert.equal(code(() => verifyHostOp(op(f.B, "resume"), ctx2)), "device_tier");
  assert.equal(code(() => verifyHostOp(op(f.B, "stop"), ctx2)), "ok", "narrowing needs no tier");
  assert.equal(code(() => verifyHostOp(op(f.N, "delete"), { ...ctx2, checkAuthTime: true, sessionAuthTimeMs: NOW - 5 * 60_000 - 1 })), "stale_auth");
  assert.equal(code(() => verifyHostOp(op(f.N, "delete"), { ...ctx2, checkAuthTime: true, sessionAuthTimeMs: NOW })), "ok");
});

test("revocations hold even after their signer is removed", () => {
  const f = fleet(), h = hostOf(f);
  const r = f.sign("sb.revocation.v1", f.B, { what: "host", id: h.host, host: h.host, gen: 1, at_ms: 1 });
  f.chainOp(f.N, "remove", { remove: f.B.id, regrants: [] });
  assert.equal(verifyRevocation(r, { ...f.ctx, chain: f.state }).id, h.host);
});

test("approvals: the subject's hash, the operation, the requester, gen and life, once, 10 minutes, tier", () => {
  const f = fleet();
  const host = newId(), agent = newId(), used = new Set();
  const subject = { agent, host, paths_hash: preimageHash(["/tmp/a", "/tmp/b"]), count: 2 };
  const ap = (by, extra = {}) => f.sign("sb.approval.v1", by, {
    approval: newId(), kind: "delete-outside", requester: { host, agent }, gen: 4, life: 2, question: newId(),
    subject, subject_hash: sha256b64(enc(canonText(subject))), at_ms: NOW, not_after_ms: NOW + 600_000, auth_time_ms: NOW, ...extra,
  });
  const ctx = { ...f.ctx, chain: f.state, now: NOW, expect: { kind: "delete-outside", subject, requester: { host, agent } }, current: { gen: 4, life: 2 }, used: (a) => used.has(a) };
  const a1 = ap(f.B);
  used.add(verifyApproval(a1, ctx).approval);
  assert.equal(code(() => verifyApproval(a1, ctx)), "approval_used");
  assert.equal(code(() => verifyApproval(ap(f.B, { subject_hash: sha256b64(new Uint8Array([1])) }), ctx)), "approval_mismatch");
  const otherSubject = { ...subject, count: 3 };
  // the subject the person saw must be the one hashed: a body whose subject_hash names another operation is refused,
  // even when that other operation is exactly the one about to run
  assert.equal(code(() => verifyApproval(ap(f.B, { subject_hash: sha256b64(enc(canonText(otherSubject))) }), { ...ctx, expect: { ...ctx.expect, subject: otherSubject } })), "approval_mismatch");
  assert.equal(code(() => verifyApproval(ap(f.B), { ...ctx, expect: { ...ctx.expect, subject: otherSubject } })), "approval_mismatch", "not the operation about to run");
  assert.equal(code(() => verifyApproval(ap(f.B), { ...ctx, expect: { ...ctx.expect, requester: { host, agent: newId() } } })), "approval_mismatch");
  assert.equal(code(() => verifyApproval(ap(f.B), { ...ctx, current: { gen: 5, life: 2 } })), "approval_stale", "a newer generation");
  assert.equal(code(() => verifyApproval(ap(f.B), { ...ctx, current: { gen: 4, life: 3 } })), "approval_stale", "a revoke-and-resume since");
  assert.equal(code(() => verifyApproval(ap(f.B, { not_after_ms: NOW + 600_001 }), ctx)), "bad_form");
  assert.equal(code(() => verifyApproval(ap(f.B), { ...ctx, now: NOW + 600_000 })), "approval_stale", "expired");
  // pairing a host needs a fresh sign-in (the service's check): at the 5-minute boundary, past it, and in the future
  const pairing = newId(), hk = key(), host2 = newId();
  const pairSubject = { host: host2, sign_key: b64(hk.raw), enc_key: b64(new Uint8Array(32).fill(3)), fingerprint: b64(hostFingerprint(host2, hk.raw, new Uint8Array(32).fill(3))), name: "new-box" };
  const pair = (auth) => f.sign("sb.approval.v1", f.N, { approval: newId(), kind: "host-pair", requester: { pairing }, subject: pairSubject,
    subject_hash: sha256b64(enc(canonText(pairSubject))), at_ms: NOW, not_after_ms: NOW + 600_000, auth_time_ms: auth });
  const pctx = { ...ctx, expect: { kind: "host-pair", subject: pairSubject, requester: { pairing } }, current: null, checkAuthTime: true };
  assert.equal(code(() => verifyApproval(pair(NOW - 5 * 60_000), pctx)), "ok", "exactly 5 minutes old");
  assert.equal(code(() => verifyApproval(pair(NOW - 5 * 60_000 - 1), pctx)), "stale_auth");
  assert.equal(code(() => verifyApproval(pair(NOW + 5 * 60_000 + 1), pctx)), "stale_auth", "a sign-in in the future");
  assert.equal(code(() => verifyApproval(pair(NOW - 3_600_000), { ...pctx, checkAuthTime: false })), "ok", "hosts can't check it");
  // other kinds need only a live session: an old auth_time doesn't refuse a spend-style approval
  assert.equal(code(() => verifyApproval(ap(f.B, { auth_time_ms: NOW - 3_600_000 }), { ...ctx, checkAuthTime: true })), "ok");
  f.chainOp(f.N, "policy", { policy: { require_native_for_widening: true } });
  assert.equal(code(() => verifyApproval(ap(f.B), { ...ctx, chain: f.state })), "device_tier");
  assert.equal(code(() => verifyApproval(ap(f.N), { ...ctx, chain: f.state })), "ok");
});
