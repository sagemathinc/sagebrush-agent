// Host supervisor freeze r3.1 §3.2–§3.4: verifying a signed host grant for this host, and the durable grant state:
// intent before highwater, the generation rule with byte-identical re-apply, plan steps, recovery and AU07.
import assert from "node:assert/strict";
import { mkdtempSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { FleetError, newId, keyFromSeed, seal, sha256b64 } from "../lib/fleet/index.mjs";
import { verifyGrant, GrantState } from "../lib/fleet/host/grant.mjs";

const refused = (fn, code) => assert.throws(fn, (e) => e instanceof FleetError && e.code === code, code);
const rejects = (p, code) => assert.rejects(p, (e) => e instanceof FleetError && e.code === code, code);

const AUD = "https://dev.sagebrush.space";
const fleet = newId(), host = newId(), device = newId(), agent = newId(), tag = newId();
const dev = keyFromSeed(new Uint8Array(32).fill(3));
const other = keyFromSeed(new Uint8Array(32).fill(4));
const cert = sha256b64(new Uint8Array([9]));
const signer = (k = dev) => ({ kind: "device", id: device, alg: "ed25519", key: k.key });
const resolveKey = (s) => { if (s.key === dev.key) return dev.raw; throw new FleetError("device_unknown"); };

const config = () => ({
  files: { rw: [], ro: [] }, network: { mode: "none", allow: [], lan_allow: [] }, programs: "run", mcp_allow: null, gpu: false,
  resources: { memory_max_mb: 1024, tasks_max: 1024, cpu_weight: 100, cpu_quota_pct: null, io_weight: 100, disk_gb: 10, nofile: 65536 },
  wakes: [], turns: { per_day: 10, wall_s: 7200 },
});
const body = (over = {}) => ({
  fleet, aud: AUD, host, gen: 1, cert, chain_seq: 1, at_ms: 1000, not_before_ms: 1000, not_after_ms: 10_000, auth_time_ms: 1000,
  agents: [{ agent, name: "worker-1", client: "claude", root: false, tags: [tag], workspace: [{ path: "/Course", access: "write" }],
    broker: ["messages"], spend_cap_cents: 0, config_schema: 1, config: config() }],
  tags: [{ tag, name: "course-1" }], subscriptions: [{ sub: newId(), provider: "claude", use: [agent], home: false }],
  offline: { revocation_check_s: 900, horizon_s: 3600 }, ...over,
});
const grant = (over, k = dev, type = "sb.host-grant.v1") => seal(type, signer(k), body(over), k);
const ctx = (over = {}) => ({ aud: AUD, fleet, host, cert, now: 5000, resolveKey, hostInfo: { ramMb: 8192, cpus: 4 }, ...over });

test("a valid grant for this host verifies, with its digest", () => {
  const bytes = grant();
  const { body: b, digest } = verifyGrant(bytes, ctx());
  assert.equal(b.gen, 1);
  assert.equal(digest, sha256b64(bytes));
  assert.equal(verifyGrant(grant({ not_after_ms: null, no_expiry_ack: true }), ctx()).body.not_after_ms, null);
});

test("refused: wrong signer, audience, fleet, type, host, host key, time window, expiry ack", () => {
  refused(() => verifyGrant(grant({}, other), ctx()), "device_unknown");
  refused(() => verifyGrant(grant(), ctx({ aud: "https://sagebrush.space" })), "bad_audience");
  refused(() => verifyGrant(grant(), ctx({ fleet: newId() })), "bad_form");
  refused(() => verifyGrant(grant({ host: newId() }), ctx()), "not_granted");
  refused(() => verifyGrant(grant({ cert: sha256b64(new Uint8Array([8])) }), ctx()), "not_granted");
  refused(() => verifyGrant(grant(), ctx({ now: 999 })), "grant_expired");
  refused(() => verifyGrant(grant(), ctx({ now: 10_001 })), "grant_expired");
  refused(() => verifyGrant(grant({ not_after_ms: null }), ctx()), "bad_form");
  refused(() => verifyGrant(grant({ no_expiry_ack: true }), ctx()), "bad_form");
  const revocation = seal("sb.revocation.v1", signer(), { fleet, aud: AUD, what: "agent", id: agent, host, gen: 1, chain_seq: 1, at_ms: 1 }, dev);
  refused(() => verifyGrant(revocation, ctx()), "bad_form");
  // A grant body signed under another device-signed type must not pass as a grant (the type is in the signature).
  refused(() => verifyGrant(grant({}, dev, "sb.host-op.v1"), ctx()), "bad_form");
  const tampered = Buffer.from(grant()); tampered[tampered.indexOf("worker-1") + 7] = "2".charCodeAt(0);
  refused(() => verifyGrant(tampered, ctx()), "bad_signature");
});

test("refused: cross-field rules and every agent's config_schema 1", () => {
  const b = body();
  refused(() => verifyGrant(grant({ agents: [{ ...b.agents[0], tags: [newId()] }] }), ctx()), "bad_form");
  refused(() => verifyGrant(grant({ agents: [b.agents[0], b.agents[0]] }), ctx()), "bad_form");
  refused(() => verifyGrant(grant({ tags: [b.tags[0], b.tags[0]] }), ctx()), "bad_form");
  refused(() => verifyGrant(grant({ subscriptions: [{ sub: newId(), provider: "claude", use: [newId()], home: false }] }), ctx()), "bad_form");
  refused(() => verifyGrant(grant({ agents: [{ ...b.agents[0], config: { ...config(), extra: 1 } }] }), ctx()), "bad_form");
  refused(() => verifyGrant(grant({ agents: [{ ...b.agents[0], config: { ...config(), files: { rw: ["/etc/x"], ro: [] } } }] }), ctx()), "bad_form");
  refused(() => verifyGrant(grant({ agents: [{ ...b.agents[0], config: {} }] }), ctx()), "bad_form");
  refused(() => verifyGrant(grant(), ctx({ hostInfo: { ramMb: 512 } })), "bad_form");
});

const fresh = () => join(mkdtempSync(join(tmpdir(), "sb-grant-")), "state");
const okIntent = () => { const log = []; const f = async (r) => { log.push(r); }; f.log = log; return f; };

test("begin: the intent first; then grant, highwater and applying(N); steps; applied(N)", async () => {
  const dir = fresh();
  const s = new GrantState(dir);
  const bytes = grant(); const digest = sha256b64(bytes);
  const intent = okIntent();
  await s.begin(1, bytes, digest, ["broker-gen", "start:a"], intent);
  assert.equal(intent.log.length, 1);
  assert.equal(intent.log[0].gen, 1);
  assert.deepEqual(new GrantState(dir).pending(), { phase: "applying", gen: 1, remaining: [0, 1] });
  s.done(0);
  assert.deepEqual(new GrantState(dir).pending(), { phase: "applying", gen: 1, remaining: [1] });
  refused(() => s.finish(), "bad_form");
  s.done(1); s.finish();
  const again = new GrantState(dir);
  assert.deepEqual(again.pending(), { phase: "applied", gen: 1, remaining: [] });
  assert.deepEqual([...again.currentBytes()], [...bytes]);
});

test("a failed intent changes nothing: no highwater, no grant file, N not accepted", async () => {
  const dir = fresh();
  const s = new GrantState(dir);
  const bytes = grant();
  await rejects(s.begin(1, bytes, sha256b64(bytes), ["x"], async () => { throw new FleetError("audit_unavailable"); }), "audit_unavailable");
  const again = new GrantState(dir);
  assert.equal(again.hw.gen, 0);
  assert.equal(existsSync(join(dir, "grants", "1")), false);
  assert.equal(again.reconcileIntent(1), "failed_no_effect");
});

test("the generation rule: lower or equal-but-different refused; byte-identical is a re-apply with no effects", async () => {
  const s = new GrantState(fresh());
  const g2 = grant({ gen: 2 });
  await s.begin(2, g2, sha256b64(g2), ["a"], okIntent());
  s.done(0); s.finish();
  assert.deepEqual(s.admit(2, sha256b64(g2)), { reapply: true });
  refused(() => s.admit(2, sha256b64(grant({ gen: 2, at_ms: 1001 }))), "stale_generation");
  refused(() => s.admit(1, sha256b64(grant())), "stale_generation");
  assert.deepEqual(s.admit(3, "x"), { reapply: false });
  await rejects(s.begin(2, g2, sha256b64(g2), ["a"], okIntent()), "bad_form");
  await rejects(s.begin(1, grant(), "d", ["a"], okIntent()), "stale_generation");
});

test("AU07: an intent whose highwater write never happened reconciles failed_no_effect; after it, accepted", async () => {
  const s = new GrantState(fresh());
  assert.equal(s.reconcileIntent(1), "failed_no_effect");
  const g = grant();
  await s.begin(1, g, sha256b64(g), ["a"], okIntent());
  assert.equal(s.reconcileIntent(1), "accepted");
});

test("corrupt grant state is refused, not replaced", async () => {
  const dir = fresh();
  const s = new GrantState(dir);
  const g = grant();
  await s.begin(1, g, sha256b64(g), ["a"], okIntent());
  writeFileSync(join(dir, "phase.json"), JSON.stringify({ phase: "applying", gen: 7, plan: [] }));
  refused(() => new GrantState(dir), "bad_form");
  writeFileSync(join(dir, "phase.json"), "{");
  refused(() => new GrantState(dir), "bad_form");
  assert.equal(readFileSync(join(dir, "phase.json"), "utf8"), "{");
});
