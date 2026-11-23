// The fleet schema set (schema/fleet/fleet.schema.json, reasons.json, purpose-codes.json) against O6/O7 r2.3: every
// definition compiles; a valid body of each type passes and each kind of mistake is refused; the reason registry is
// closed and covers every code the library raises; the purpose codes agree with their display list.
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { test } from "node:test";
import { compile, FleetError, newId, keyFromSeed, sha256b64, FREEZE } from "../lib/fleet/index.mjs";

const read = (f) => JSON.parse(readFileSync(new URL(`../schema/fleet/${f}`, import.meta.url), "utf8"));
const doc = read("fleet.schema.json");
const body = (name) => compile({ $defs: doc.$defs, $ref: `#/$defs/${name}` });
const refused = (v, x) => { try { v(x); } catch (e) { if (e instanceof FleetError) return e.code === "bad_form"; throw e; } return false; };

const AUD = "https://dev.sagebrush.space";
const fleet = newId(), host = newId(), agent = newId(), tag = newId();
const k = keyFromSeed(new Uint8Array(32).fill(7));
const key32 = Buffer.from(k.raw).toString("base64url"), h = sha256b64(new Uint8Array([1]));

const samples = {
  "host-cert": { fleet, aud: AUD, host, sign_key: key32, enc_key: key32, fingerprint: h, name: "lab-box", chain_seq: 3, at_ms: 1 },
  "host-grant": {
    fleet, aud: AUD, host, gen: 1, cert: h, chain_seq: 3, at_ms: 1, not_before_ms: 1, not_after_ms: 2, auth_time_ms: 1,
    agents: [{ agent, name: "worker-1", client: "claude", root: false, tags: [tag], workspace: [{ path: "/Algebra", access: "write" }],
      broker: ["messages", "workspace"], spend_cap_cents: 0, config_schema: 1, config: {} }],
    tags: [{ tag, name: "course-1" }], subscriptions: [{ sub: newId(), provider: "claude", use: [agent], home: false }],
    offline: { revocation_check_s: 900, horizon_s: 3600 },
  },
  "grant-ack": { fleet, aud: AUD, host, gen: 2, at_ms: 1, narrowed: true, restarted: [agent] },
  "host-op": { fleet, aud: AUD, op_id: newId(), op: "pause", host, agent: "all", gen: 1, chain_seq: 3, at_ms: 1, not_after_ms: 2 },
  "revocation": { fleet, aud: AUD, what: "agent", id: agent, host, gen: 1, chain_seq: 3, at_ms: 1 },
  "approval": { fleet, aud: AUD, approval: newId(), kind: "spend", requester: { host, agent }, gen: 1, life: 0, question: newId(),
    subject: { agent, amount_cents: 500, currency: "USD", purpose_code: "cloud-compute", payee: { kind: "provider", id: "gcp" } },
    subject_hash: h, chain_seq: 3, at_ms: 1, not_after_ms: 2, auth_time_ms: 1 },
  "sealed-package": { fleet, aud: AUD, package: newId(), host, enc_key: "A".repeat(22), fingerprint: h, sub: newId(), provider: "claude",
    purpose: "claude-setup-token", gen: 1, chain_seq: 3, at_ms: 1, not_after_ms: 2, enc: key32, ct: "AAAA" },
  "device-chain": { fleet, aud: AUD, seq: 0, prev: "", op: "genesis", at_ms: 1, auth_time_ms: 1,
    device: { id: newId(), alg: "ed25519", key: key32, name: "William's laptop", tier: "browser" }, recovery_key: { alg: "ed25519", key: key32 } },
};

test("fleet.schema.json: pinned to r2.3; every definition compiles; one valid body of each type passes", () => {
  assert.ok(doc.$comment.includes(FREEZE.sha256));
  for (const t of Object.keys(doc.$defs)) body(t);
  for (const [t, x] of Object.entries(samples)) assert.equal(body(t)(x), true, t);
});

test("fleet bodies: an extra field, a missing one, a wrong id, a non-canonical value or a bound breach is refused", () => {
  const g = body("host-grant"), s = samples["host-grant"];
  const a0 = s.agents[0];
  for (const x of [
    { ...s, extra: 1 }, (({ cert, ...r }) => r)(s), { ...s, host: "X".repeat(26) }, { ...s, gen: 0 }, { ...s, cert: h.slice(0, 42) + "B" },
    { ...s, aud: "https://evil.example" }, { ...s, agents: [{ ...a0, config: { shell: "full" } }] }, { ...s, agents: [{ ...a0, config_schema: 2 }] },
    { ...s, agents: [{ ...a0, name: "own" }] }, { ...s, agents: [{ ...a0, tags: [tag, tag] }] }, { ...s, agents: [{ ...a0, workspace: [] }] },
    { ...s, agents: [{ ...a0, broker: ["root"] }] }, { ...s, agents: Array(65).fill(a0) }, { ...s, no_expiry_ack: false },
    { ...s, offline: { revocation_check_s: 0, horizon_s: 3600 } },
  ]) assert.ok(refused(g, x), JSON.stringify(x).slice(0, 120));
  assert.equal(g({ ...s, not_after_ms: null, no_expiry_ack: true }), true, "no expiry, acknowledged");
  const ap = body("approval"), A = samples.approval;
  assert.ok(refused(ap, { ...A, requester: { pairing: newId() } }), "a spend with a pairing requester");
  assert.ok(refused(ap, (({ gen, ...r }) => r)(A)), "an agent's approval without gen");
  assert.equal(ap({ fleet, aud: AUD, approval: newId(), kind: "host-pair", requester: { pairing: newId() },
    subject: { host, sign_key: key32, enc_key: key32, fingerprint: h, name: "lab-box" }, subject_hash: h, chain_seq: 3, at_ms: 1, not_after_ms: 2, auth_time_ms: 1 }), true);
  assert.ok(refused(ap, { ...A, subject: { ...A.subject, purpose_code: "gift" } }));
  const dc = body("device-chain"), G = samples["device-chain"];
  assert.ok(refused(dc, { ...G, op: "reset" }), "there is no service reset");
  assert.ok(refused(dc, { ...G, op: "recover", recovery_key: undefined }), "recover carries its rotation");
  assert.ok(refused(dc, { ...G, device: { ...G.device, tier: "keychain" } }));
  assert.ok(refused(dc, { ...G, prev: "x" }));
});

test("reasons.json: closed, unique, and every code the fleet library raises is in it", () => {
  const reg = read("reasons.json");
  assert.equal(reg.freeze, FREEZE.sha256);
  const names = reg.reasons.map((r) => r.name);
  assert.equal(new Set(names).size, names.length);
  for (const n of names) assert.match(n, /^[a-z][a-z0-9_]{0,47}$/);
  const dir = new URL("../lib/fleet/", import.meta.url);
  for (const f of readdirSync(dir).filter((f) => f.endsWith(".mjs"))) {
    for (const [, c] of readFileSync(new URL(f, dir), "utf8").matchAll(/refuse\("([a-z_]+)"/g)) assert.ok(names.includes(c), `${f}: ${c}`);
  }
  for (const c of ["not_found", "limit", "in_progress", "idem_expired", "device_tier", "browser_gen_stale", "preflight_missing", "audit_full"]) assert.ok(names.includes(c), c);
});

test("purpose codes: the schema's enum and the display list agree", () => {
  const list = read("purpose-codes.json").purpose_codes.map((p) => p.code);
  assert.deepEqual([...doc.$defs.purpose_code.enum].sort(), [...list].sort());
});
