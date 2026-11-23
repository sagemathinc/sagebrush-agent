// Host supervisor freeze r3.1 §3.2–§3.4: verifying a signed host grant for this host, and the durable grant state:
// intent before highwater, the generation rule with byte-identical re-apply, plan steps, recovery and AU07.
import assert from "node:assert/strict";
import { mkdtempSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { realIo } from "../lib/fleet/host/store.mjs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { FleetError, newId, keyFromSeed, seal, sha256b64 } from "../lib/fleet/index.mjs";
import { verifyGrant } from "../lib/fleet/host/grant.mjs";
import { HostStore } from "../lib/fleet/host/host-store.mjs";

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
  refused(() => verifyGrant(grant({ not_after_ms: null }), ctx()), "bad_form");
  refused(() => verifyGrant(grant({ no_expiry_ack: true }), ctx()), "bad_form");
  const revocation = seal("sb.revocation.v1", signer(), { fleet, aud: AUD, what: "agent", id: agent, host, gen: 1, chain_seq: 1, at_ms: 1 }, dev);
  refused(() => verifyGrant(revocation, ctx()), "bad_form");
  // A grant body signed under another device-signed type must not pass as a grant (the type is in the signature).
  refused(() => verifyGrant(grant({}, dev, "sb.host-op.v1"), ctx()), "bad_form");
  const tampered = Buffer.from(grant()); tampered[tampered.indexOf("worker-1") + 7] = "2".charCodeAt(0);
  refused(() => verifyGrant(tampered, ctx()), "bad_signature");
});

test("exact time boundaries: in force while not_before <= now < not_after", () => {
  assert.ok(verifyGrant(grant(), ctx({ now: 1000 })));     // not_before
  assert.ok(verifyGrant(grant(), ctx({ now: 9_999 })));    // not_after - 1
  refused(() => verifyGrant(grant(), ctx({ now: 999 })), "grant_expired");
  refused(() => verifyGrant(grant(), ctx({ now: 10_000 })), "grant_expired"); // not_after
  refused(() => verifyGrant(grant(), ctx({ now: 10_001 })), "grant_expired");
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
const stateFile = (root) => join(root, "grant", "state.json");
const stateOnDisk = (root) => JSON.parse(readFileSync(stateFile(root), "utf8"));
/** Open the host store and return its grant view, with close() closing the store. */
const GrantState = { open: async (root, opts) => { const h = await HostStore.open(root, opts); const g = h.grants; g.close = () => h.close(); g.store = h; return g; } };
const g = (gen, over = {}) => { const bytes = grant({ gen, ...over }); return { bytes, digest: sha256b64(bytes) }; };

test("begin: the intent first; then grant bytes; then ONE atomic state commit; steps; applied(N)", async () => {
  const dir = fresh();
  const s = await GrantState.open(dir);
  const { bytes, digest } = g(1);
  const intent = okIntent();
  await s.begin(1, bytes, digest, ["broker-gen", "start:a"], intent);
  assert.equal(intent.log.length, 1);
  assert.equal(intent.log[0].gen, 1);
  assert.deepEqual(stateOnDisk(dir), { v: 1, gen: 1, digest, phase: "applying", plan: [{ step: "broker-gen", done: false }, { step: "start:a", done: false }] });
  s.done(0);
  assert.deepEqual(s.pending(), { phase: "applying", gen: 1, remaining: [1] });
  refused(() => s.finish(), "bad_form");
  s.done(1); s.finish();
  await s.close();
  const again = await GrantState.open(dir);
  assert.deepEqual(again.pending(), { phase: "applied", gen: 1, remaining: [] });
  assert.deepEqual([...again.currentBytes()], [...bytes]);
  await again.close();
});

test("a failed intent changes nothing: no highwater, no grant file, N not accepted", async () => {
  const dir = fresh();
  const s = await GrantState.open(dir);
  const { bytes, digest } = g(1);
  await rejects(s.begin(1, bytes, digest, ["x"], async () => { throw new FleetError("audit_unavailable"); }), "audit_unavailable");
  assert.equal(s.highwater.gen, 0);
  assert.equal(existsSync(join(dir, "grant", "grants", "1")), false);
  assert.equal(s.reconcileIntent(1), "failed_no_effect");
  await s.close();
});

test("the generation rule: lower or equal-but-different refused; byte-identical is a re-apply with no effects", async () => {
  const s = await GrantState.open(fresh());
  const g2 = g(2);
  await s.begin(2, g2.bytes, g2.digest, ["a"], okIntent());
  s.done(0); s.finish();
  assert.deepEqual(s.admit(2, g2.digest), { reapply: true });
  refused(() => s.admit(2, g(2, { at_ms: 1001 }).digest), "stale_generation");
  refused(() => s.admit(1, g(1).digest), "stale_generation");
  assert.deepEqual(s.admit(3, "x"), { reapply: false });
  await rejects(s.begin(2, g2.bytes, g2.digest, ["a"], okIntent()), "bad_form");
  await rejects(s.begin(1, g(1).bytes, g(1).digest, ["a"], okIntent()), "stale_generation");
  await rejects(s.begin(3, g(3).bytes, "not-the-digest", ["a"], okIntent()), "bad_form");
  await rejects(s.begin(3, g(3).bytes, g(3, { at_ms: 1002 }).digest, ["a"], okIntent()), "bad_form"); // well-formed, but of other bytes
  assert.equal(s.highwater.gen, 2);
  await s.close();
});

test("highwater only increases: astra2's sequence (gen 2 intent held, gen 3 begun, gen 2 released)", async () => {
  const dir = fresh();
  const s = await GrantState.open(dir);
  let release;
  const held = new Promise((r) => { release = r; });
  const g2 = g(2), g3 = g(3);
  const p2 = s.begin(2, g2.bytes, g2.digest, ["a"], async () => { await held; });
  await rejects(s.begin(3, g3.bytes, g3.digest, ["a"], okIntent()), "in_progress"); // admission is serialized
  release();
  await p2;
  assert.equal(stateOnDisk(dir).gen, 2);
  s.done(0); s.finish();
  await s.begin(3, g3.bytes, g3.digest, ["a"], okIntent());
  assert.equal(stateOnDisk(dir).gen, 3);
  await rejects(s.begin(2, g2.bytes, g2.digest, ["a"], okIntent()), "stale_generation"); // a stale release never lowers it
  assert.equal(stateOnDisk(dir).gen, 3);
  await s.close();
});

test("a new generation can't begin while another is applying", async () => {
  const s = await GrantState.open(fresh());
  const g1 = g(1), g2 = g(2);
  await s.begin(1, g1.bytes, g1.digest, ["a"], okIntent());
  const intent = okIntent();
  await rejects(s.begin(2, g2.bytes, g2.digest, ["a"], intent), "in_progress");
  assert.equal(intent.log.length, 0); // refused before any intent is written
  await s.close();
});

test("AU07: an intent whose state commit never happened reconciles failed_no_effect; after it, accepted", async () => {
  const s = await GrantState.open(fresh());
  assert.equal(s.reconcileIntent(1), "failed_no_effect");
  const g1 = g(1);
  await s.begin(1, g1.bytes, g1.digest, ["a"], okIntent());
  assert.equal(s.reconcileIntent(1), "accepted");
  await s.close();
});

// ---- failures at each step: the instance is poisoned; after a reload memory equals disk and the plan is recoverable

const failAt = (step, after = 0) => {
  let dirOpen = false, n = 0;
  const hit = (k) => k === step && n++ >= after;
  const boom = () => { throw Object.assign(new Error("ENOSPC"), { code: "ENOSPC" }); };
  return {
    ...realIo,
    open: (p, f, m) => { if (f === "w" && hit("open")) boom(); dirOpen = f === "r"; return realIo.open(p, f, m); },
    write: (fd, b, o, l) => { if (hit("write")) boom(); return realIo.write(fd, b, o, l); },
    fsync: (fd) => { if (!dirOpen && hit("fsync")) boom(); if (dirOpen && hit("dirfsync")) boom(); return realIo.fsync(fd); },
    rename: (a, b) => { if (hit("rename")) boom(); return realIo.rename(a, b); },
  };
};

for (const step of ["open", "write", "fsync", "rename", "dirfsync"]) {
  test(`a failure at ${step} while committing begin: poisoned; disk holds the old state or the whole new one`, async () => {
    const dir = fresh();
    // after: 3 skips creating the initial registry and grant state and writing the grant bytes: the failure hits the state commit.
    const s = await GrantState.open(dir, { io: failAt(step, 3) });
    const g1 = g(1);
    await assert.rejects(s.begin(1, g1.bytes, g1.digest, ["a", "b"], okIntent()), /ENOSPC/);
    assert.equal(s.poisoned, true);
    refused(() => s.pending(), "outcome_unknown");
    s.reload();
    const st = stateOnDisk(dir);
    assert.deepEqual(s.pending(), { phase: st.phase, gen: st.gen, remaining: st.plan.map((_, i) => i) });
    if (step === "dirfsync") assert.deepEqual([st.gen, st.phase], [1, "applying"]); // renamed: durable, all steps pending
    else assert.deepEqual([st.gen, st.phase], [0, "applied"]);                       // not renamed: N not accepted
    assert.equal(s.reconcileIntent(1), step === "dirfsync" ? "accepted" : "failed_no_effect");
    await s.close();
  });

  test(`a failure at ${step} while writing the grant bytes: nothing accepted, nothing poisoned`, async () => {
    const dir = fresh();
    const s = await GrantState.open(dir, { io: failAt(step, 2) });
    const g1 = g(1);
    await assert.rejects(s.begin(1, g1.bytes, g1.digest, ["a"], okIntent()), /ENOSPC/);
    assert.equal(s.poisoned, false);
    assert.deepEqual(s.pending(), { phase: "applied", gen: 0, remaining: [] });
    assert.deepEqual(stateOnDisk(dir), { v: 1, gen: 0, digest: null, phase: "applied", plan: [] });
    await s.close();
  });

  test(`a failure at ${step} while marking a step done: poisoned; the step stays pending after reload`, async () => {
    const dir = fresh();
    { const s = await GrantState.open(dir); const g1 = g(1); await s.begin(1, g1.bytes, g1.digest, ["a", "b"], okIntent()); await s.close(); }
    const s = await GrantState.open(dir, { io: failAt(step) });
    assert.throws(() => s.done(0), /ENOSPC/);
    refused(() => s.pending(), "outcome_unknown");
    refused(() => s.finish(), "outcome_unknown");
    s.reload();
    assert.deepEqual(s.pending().remaining, step === "dirfsync" ? [1] : [0, 1]);
    await s.close();
  });
}

test("one host store: registry and grant state open together; commit both; crash; reload; a second supervisor refused", async () => {
  const dir = fresh();
  const h = await HostStore.open(dir);
  const a = newId();
  h.registry.addAgent(a, 1); h.registry.setState(a, "running");
  const g1 = g(1);
  await h.grants.begin(1, g1.bytes, g1.digest, ["start:a"], okIntent());
  await rejects(HostStore.open(dir), "in_progress");   // a second supervisor
  // "Crash": a new process opens after this one is gone (simulated by closing without finishing the plan).
  await h.close();
  const h2 = await HostStore.open(dir);
  assert.deepEqual(h2.registry.runnable(), [a]);
  assert.deepEqual(h2.grants.pending(), { phase: "applying", gen: 1, remaining: [0] });
  h2.grants.done(0); h2.grants.finish();
  await h2.close();
});

test("a held intent across lock loss: the begin's commit refuses; highwater is unchanged on disk", async () => {
  const dir = fresh();
  const s = await GrantState.open(dir);
  let release;
  const held = new Promise((r) => { release = r; });
  const g1 = g(1);
  const p = s.begin(1, g1.bytes, g1.digest, ["a"], async () => { await held; });
  const { execFileSync } = await import("node:child_process");
  for (const pid of String(execFileSync("pgrep", ["-f", join(dir, ".lock")])).trim().split("\n").filter(Boolean)) {
    try { process.kill(Number(pid), "SIGKILL"); } catch {}
  }
  for (let i = 0; i < 50 && !s.poisoned; i++) await new Promise((r) => setTimeout(r, 50));
  release();
  await rejects(p, "outcome_unknown");
  assert.equal(stateOnDisk(dir).gen, 0);
  refused(() => s.pending(), "outcome_unknown");
});

test("anything but the exact closed state is refused at load and left as found", async () => {
  const d43 = "A".repeat(43);
  const variants = [
    "{",
    { v: 1, gen: 7, digest: null, phase: "applied", plan: [] },
    { v: 1, gen: 1, digest: d43, phase: "applying", plan: [{ step: "a", done: "false" }] },
    { v: 1, gen: 1, digest: d43, phase: "applying", plan: [{ step: "a", done: "yes" }] },
    { v: 1, gen: 1, digest: d43, phase: "applying", plan: [{ step: 12, done: false }] },
    { v: 1, gen: 1, digest: d43, phase: "applying", plan: [{ step: "a", done: false, extra: 1 }] },
    { v: 1, gen: 1, digest: d43, phase: "applying", plan: [{ step: "", done: false }] },
    { v: 1, gen: 1, digest: d43, phase: "applied", plan: [{ step: "a", done: true }] },
    { v: 1, gen: 0, digest: null, phase: "applying", plan: [] },
    { v: 1, gen: 1, digest: d43, phase: "applied", plan: [], extra: 1 },
    { v: 1, gen: 1, digest: "short", phase: "applied", plan: [] },
    { v: 2, gen: 1, digest: d43, phase: "applied", plan: [] },
    { v: 1, gen: -1, digest: null, phase: "applied", plan: [] },
    { v: 1, gen: 1, digest: d43, phase: "done", plan: [] },
  ];
  for (const v of variants) {
    const dir = fresh();
    await (await GrantState.open(dir)).close();
    const text = typeof v === "string" ? v : JSON.stringify(v);
    writeFileSync(stateFile(dir), text);
    await rejects(GrantState.open(dir), "bad_form");
    assert.equal(readFileSync(stateFile(dir), "utf8"), text);
  }
});
