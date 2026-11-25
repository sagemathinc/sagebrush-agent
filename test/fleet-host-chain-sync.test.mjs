// Host supervisor (host daemon r2.5 §5, §6): the chain sync and its adoption. Fetching against the service's REAL chain
// read handler (core/chain-service.mjs handleChainRead) run in process behind a fake fetch, over the shared fixtures'
// honest chain and lease-key extension; the candidate; the coalesced sync; chain_fork; the adopter with real certificate
// checks (a removal of the certificate's signing device); and the executor's chain-adopt emergency against fake units.
import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "./host-linux-only.mjs";
import { b64, hostFingerprint, keyFromSeed, replayChain, seal, sha256b64 } from "../lib/fleet/index.mjs";
import { handleChainRead } from "../lib/fleet/core/chain-service.mjs";
import { parseSig } from "../lib/fleet/request.mjs";
import { classify, firstBoot, hostPaths } from "../lib/fleet/host/identity.mjs";
import { ChainSync, buildCandidate, chainAdopter } from "../lib/fleet/host/chain-sync.mjs";
import { Supervisor } from "../lib/fleet/host/executor.mjs";
import { HostStore } from "../lib/fleet/host/host-store.mjs";
import { fenced } from "../lib/fleet/host/fence.mjs";

const F = JSON.parse(readFileSync(new URL("./fixtures/fleet-fixtures.json", import.meta.url), "utf8"));
const enc = (s) => new TextEncoder().encode(s);
const AUD = F.aud, FLEET = F.ids.fleet, HOST = F.ids.host, NOW = 1_800_000_000_000;
const N = keyFromSeed(Buffer.from(F.keys["device-native"].seed, "hex"));
const N2 = keyFromSeed(Buffer.from(F.keys["device-native-2"].seed, "hex"));
const HONEST = F.objects.chain.map(enc); // seq 0..5
const LEASED = F.leases.chain.map(enc); // the same 0..5, then 6..8 (lease keys and a policy)
const UID = process.getuid();
const tmp = () => mkdtempSync(join(tmpdir(), "sb-sync-"));
const machine = () => "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n";
const ctx = { aud: AUD, fleet: FLEET };

/** The honest chain extended by one entry signed by `by`: { op, extra } (e.g. the second native device removing the first). */
async function extend(entries, by, byId, op, extra) {
  const st = await replayChain(entries, ctx);
  const body = { fleet: FLEET, aud: AUD, seq: st.seq + 1, prev: st.head, op, at_ms: NOW, auth_time_ms: NOW, ...extra };
  return [...entries, seal("sb.device-chain.v1", { kind: "device", id: byId, alg: "ed25519", key: by.key }, body, by)];
}

/** A paired host on disk at the honest chain's head (seq 5), its certificate signed by the native device N. */
async function pairedHost() {
  const root = tmp(), p = hostPaths(root);
  firstBoot(p, { machineId: machine, brokerUid: UID });
  const fresh = await classify(p, { machineId: machine, brokerUid: UID, rootUid: UID });
  const chain = await replayChain(HONEST, ctx);
  const pin = { fleet: FLEET, aud: AUD, seq: chain.seq, hash: chain.head };
  const body = { fleet: FLEET, aud: AUD, chain_seq: chain.seq, host: HOST, sign_key: b64(fresh.keys.sign.raw), enc_key: b64(fresh.keys.enc.raw),
    fingerprint: b64(await hostFingerprint(HOST, fresh.keys.sign.raw, fresh.keys.enc.raw)), name: "t", at_ms: NOW };
  const certBytes = seal("sb.host-cert.v1", { kind: "device", id: F.ids.device_native, alg: "ed25519", key: N.key }, body, N);
  mkdirSync(join(p.identity, "chain"), { recursive: true, mode: 0o700 });
  chmodSync(p.identity, 0o700);
  HONEST.forEach((e, s) => writeFileSync(join(p.identity, "chain", String(s)), e, { mode: 0o600 }));
  writeFileSync(join(p.identity, "pin"), JSON.stringify(pin), { mode: 0o600 });
  writeFileSync(join(p.identity, "host-cert"), certBytes, { mode: 0o600 });
  const paired = await classify(p, { machineId: machine, brokerUid: UID, rootUid: UID });
  assert.equal(paired.state, "PAIRED", paired.why);
  return { root, p, keys: paired.keys, pin, chain: paired.chain, certBytes };
}

/** The service: the REAL chain read handler over `serverChain`, its ctx in memory; records each request's gen. */
function service(h, serverChain, { head } = {}) {
  const calls = [];
  const sctx = {
    aud: AUD, now: NOW,
    host: async (id) => (id === HOST ? { fleet: FLEET, sign_key: h.keys.sign.raw, revoked: false } : null),
    currentGen: async () => 9,
    bucket: async () => true,
    nonces: { spend: async () => true },
    chain: { page: async (_f, after, max) => ({ head: head ?? serverChain.length - 1, entries: serverChain.slice(after + 1, after + 1 + max).map((bytes, i) => ({ seq: after + 1 + i, bytes: Buffer.from(bytes).toString() })) }) },
  };
  const fetch = async (url, init) => {
    const u = new URL(url);
    calls.push({ target: u.pathname + u.search, gen: Number(parseSig(init.headers["sagebrush-sig"]).gen) });
    const r = await handleChainRead({ method: init.method, target: u.pathname + u.search, scheme: "https", source: "t", header: init.headers["sagebrush-sig"], body: new Uint8Array(0) }, sctx);
    return new Response(r.body, { status: r.status, headers: r.headers });
  };
  return { fetch, calls };
}

/** A ChainSync for host `h`, its submit committing through the real adopter (no executor), unless `submit` is given. */
function syncFor(h, fetch, { gen = () => 3, submit } = {}) {
  let sync;
  const adopter = () => chainAdopter({ paths: h.p, certBytes: h.certBytes, keys: h.keys, pin: h.pin, sync, rootUid: UID, grantValidAt: async () => true });
  const commits = [];
  sync = new ChainSync({ snapshot: h.chain, aud: AUD, fleet: FLEET, host: HOST, signer: h.keys.sign, gen, origin: "https://dev.sagebrush.space", fetch, wall: () => NOW,
    submit: submit ?? (async (op) => { commits.push(op.candidate); adopter().commit(op.candidate); return { status: "adopted" }; }) });
  return { sync, commits };
}

test("buildCandidate: the entries from the snapshot, in order; the first bad one stops the page and keeps the verified prefix", async () => {
  const honest = await replayChain(HONEST, ctx);
  const all = await buildCandidate(honest, LEASED.slice(6), ctx);
  assert.equal(all.state.seq, 8);
  assert.equal(all.entries.length, 3);
  const bad = [LEASED[6], Buffer.concat([LEASED[7], Buffer.from(" ")]), LEASED[8]];
  const prefix = await buildCandidate(honest, bad, ctx);
  assert.equal(prefix.state.seq, 6);
  assert.equal(prefix.entries.length, 1);
  assert.equal(honest.seq, 5, "the snapshot itself never changes");
});

test("a sync against the REAL chain read: a signed request from the pin, the candidate adopted, the entries then the pin on disk, then the snapshot", async () => {
  const h = await pairedHost();
  const svc = service(h, LEASED);
  const { sync, commits } = syncFor(h, svc.fetch);
  const r = await sync.sync();
  assert.equal(r.status, "current", JSON.stringify(sync.counts));
  assert.deepEqual(svc.calls.map((c) => c.target), ["/api/fleet/v1/host/chain?after=5"]);
  assert.equal(commits.length, 1);
  assert.equal(commits[0].fromSeq, 6);
  assert.equal(sync.snapshot().seq, 8);
  const again = await classify(h.p, { machineId: machine, brokerUid: UID, rootUid: UID });
  assert.equal(again.state, "PAIRED");
  assert.equal(again.chain.seq, 8, "the pin on disk moved");
  // Current: the next sync asks from 8 and adopts nothing.
  assert.equal((await sync.sync()).status, "current");
  assert.equal(commits.length, 1);
});

test("the request's gen: the durable highwater, or 1 when no grant was ever accepted (never from the certificate)", async () => {
  for (const [hw, want] of [[0, 1], [4, 4]]) {
    const h = await pairedHost();
    const svc = service(h, LEASED);
    const { sync } = syncFor(h, svc.fetch, { gen: () => hw });
    assert.equal((await sync.sync()).status, "current", String(hw));
    assert.equal(svc.calls[0].gen, want, String(hw));
  }
});

test("chain_fork: a page with no entries and a head below the pin is never adopted; a mid-page bad entry adopts only the prefix and stops", async () => {
  const h = await pairedHost();
  const fork = service(h, HONEST.slice(0, 4), { head: 3 });
  const a = syncFor(h, fork.fetch);
  assert.equal((await a.sync.sync()).status, "chain_fork");
  assert.equal(a.sync.counts.chain_fork, 1);
  assert.equal(a.commits.length, 0);
  assert.equal(a.sync.snapshot().seq, 5);
  const g = await pairedHost();
  const spoiled = [...LEASED.slice(0, 7), Buffer.concat([LEASED[7], Buffer.from(" ")]), LEASED[8]];
  const b = syncFor(g, service(g, spoiled).fetch);
  assert.equal((await b.sync.sync()).status, "prefix");
  assert.equal(b.sync.snapshot().seq, 6);
  assert.equal(b.commits[0].entries.length, 1);
});

test("one sync at a time: two calls share one fetch; a refused adoption changes nothing", async () => {
  const h = await pairedHost();
  const svc = service(h, LEASED);
  const { sync } = syncFor(h, svc.fetch);
  const [x, y] = [sync.sync(), sync.sync()];
  assert.equal(x, y);
  await x;
  assert.equal(svc.calls.length, 1);
  const g = await pairedHost();
  const n = syncFor(g, service(g, LEASED).fetch, { submit: async () => ({ status: "refused", reason: "revoked" }) });
  assert.equal((await n.sync.sync()).status, "not_adopted");
  assert.equal(n.sync.snapshot().seq, 5);
});

test("the adopter: a candidate that removes the certificate's signing device ends the certificate; the lease-key extension doesn't", async () => {
  const h = await pairedHost();
  const removed = await extend(HONEST, N2, F.ids.device_native_2, "remove", { remove: F.ids.device_native, regrants: [] });
  const candRemoved = await buildCandidate(h.chain, removed.slice(6), ctx);
  assert.equal(candRemoved.state.seq, 6);
  const a = chainAdopter({ paths: h.p, certBytes: h.certBytes, keys: h.keys, pin: h.pin, sync: null, rootUid: UID, grantValidAt: async () => true });
  assert.equal(await a.certValid(candRemoved.state), false);
  const candLeased = await buildCandidate(h.chain, LEASED.slice(6), ctx);
  assert.equal(await a.certValid(candLeased.state), true);
  // A grant check is the injected verifier's, with a FRESH clock at the call.
  const seen = [];
  let t = 100;
  const b = chainAdopter({ paths: h.p, certBytes: h.certBytes, keys: h.keys, pin: h.pin, sync: null, now: () => t++, grantValidAt: async (_s, _b, now) => { seen.push(now); throw new Error("expired"); } });
  assert.equal(await b.grantValid(candLeased.state, new Uint8Array(1)), false);
  assert.equal(await b.grantValid(candLeased.state, new Uint8Array(1)), false);
  assert.deepEqual(seen, [100, 101]);
});

// ---- the executor's chain-adopt (§6.2)

const entry = (agent) => ({ agent, tags: [], config: { x: 1 } });
const grantBytes = (gen, agents) => Buffer.from(JSON.stringify({ gen, agents: agents.map(entry) }));
const verify = (bytes) => { const body = JSON.parse(String(bytes)); return { body, digest: sha256b64(bytes), hash: sha256b64(Buffer.concat([Buffer.from("s"), bytes])) }; };
const bodyOf = (bytes) => JSON.parse(String(bytes));

/** The executor over fake units, with a fake chain seam recording its calls in `log`. */
async function exec({ certValid = true, grantValid = true } = {}) {
  const fenceDir = join(tmp(), "fence"), log = [], units = {};
  const u = (id) => (units[id] ??= { active: false, masked: false });
  const idOf = (unit) => /^sagebrush-agents?-([a-z2-7]{26})\.(service|slice)$/.exec(unit)?.[1] ?? null;
  const fx = {
    appendIntent: async () => {}, audit: () => {}, brokerGen: async () => {}, brokerRevoke: async () => {},
    stopUnit: async (id) => { log.push(["stop", id]); u(id).active = false; }, procCount: async (id) => (u(id).active ? 1 : 0),
    mask: async (id) => { u(id).masked = true; }, unmask: async (id) => { u(id).masked = false; },
    provision: async () => {}, writeUnit: async () => {}, daemonReload: async () => {}, systemdVersion: async () => "systemd 255 (255.4-1ubuntu8.19)\n",
    start: async (id) => { log.push(["start", id]); if (!u(id).masked && !fenced(id, { dir: fenceDir })) u(id).active = true; },
    isActive: async (id) => u(id).active, publishMap: async () => {}, sendAck: async () => {},
    sys: {
      stop: (unit) => { log.push(["sys-stop", unit]); for (const [id, s] of Object.entries(units)) if (unit === "sagebrush-agents.slice" || idOf(unit) === id) s.active = false; },
      jobs: () => [], cancel: () => {}, rootUnits: () => [],
      activeAgentUnits: () => Object.entries(units).filter(([, s]) => s.active).map(([id]) => `sagebrush-agent-${id}.service`),
      procCount: (unit) => Object.entries(units).filter(([id, s]) => s.active && (unit === "sagebrush-agents.slice" || idOf(unit) === id)).length,
    },
  };
  const chain = {
    certValid: async () => { log.push(["certValid"]); return certValid; },
    grantValid: async () => { log.push(["grantValid"]); return grantValid; },
    markRevoked: () => { log.push(["markRevoked"]); },
    commit: () => { log.push(["commit"]); },
  };
  const store = await HostStore.open(join(tmp(), "state"));
  const holder = { barrier: null };
  const sup = new Supervisor({ store, fx, verify, bodyOf, fenceDir, chain, barrier: async (n, d) => { log.push(["barrier", n]); if (holder.barrier) await holder.barrier(n, d); } });
  return { sup, store, log, units, u, fenceDir, holder };
}
const cand = { state: { seq: 6 }, entries: [new Uint8Array(1)], fromSeq: 6 };
const adopt = (sup) => sup.submit({ kind: "chain-adopt", authority: "host", candidate: cand });

test("chain-adopt, both still valid: only the commit; nothing stopped", async () => {
  const x = await exec();
  await x.sup.recover();
  await x.sup.submit({ kind: "grant", bytes: grantBytes(1, [F.ids.agent]) });
  x.log.length = 0;
  const r = await adopt(x.sup);
  assert.deepEqual(r, { status: "adopted", seq: 6 });
  assert.deepEqual(x.log.filter((l) => l[0] !== "barrier"), [["certValid"], ["grantValid"], ["commit"]]);
  assert.equal(x.u(F.ids.agent).active, true);
});

test("chain-adopt, the certificate ended: the revoked marker FIRST, then all raised and every agent stopped, then the commit; nothing is served after", async () => {
  const x = await exec({ certValid: false });
  await x.sup.recover();
  await x.sup.submit({ kind: "grant", bytes: grantBytes(1, [F.ids.agent]) });
  assert.equal(x.u(F.ids.agent).active, true);
  x.log.length = 0;
  const r = await adopt(x.sup);
  assert.equal(r.status, "revoked");
  const order = x.log.filter((l) => ["markRevoked", "sys-stop", "commit", "grantValid"].includes(l[0])).map((l) => l[0]);
  assert.deepEqual(order, ["markRevoked", "sys-stop", "commit"], "no grant check after the certificate failed");
  assert.equal(x.u(F.ids.agent).active, false);
  assert.ok(existsSync(join(x.fenceDir, "all")), "all raised");
  assert.equal(x.sup.revoked, true);
  // Nothing more is served: a grant, a person's resume, even another adoption.
  assert.deepEqual(await x.sup.submit({ kind: "grant", bytes: grantBytes(2, [F.ids.agent]) }), { status: "refused", reason: "revoked" });
  assert.deepEqual(await x.sup.submit({ kind: "resume-all", authority: "person" }), { status: "refused", reason: "revoked" });
  assert.deepEqual(await adopt(x.sup), { status: "refused", reason: "revoked" });
  assert.equal(x.u(F.ids.agent).active, false);
});

test("chain-adopt, the grant ended: the expiry stop before the commit; only a NEWER valid grant lowers expiry and restarts", async () => {
  const x = await exec({ grantValid: false });
  await x.sup.recover();
  await x.sup.submit({ kind: "grant", bytes: grantBytes(1, [F.ids.agent]) });
  x.log.length = 0;
  const r = await adopt(x.sup);
  assert.equal(r.status, "expired");
  const order = x.log.filter((l) => ["sys-stop", "commit"].includes(l[0])).map((l) => l[0]);
  assert.deepEqual(order, ["sys-stop", "commit"]);
  assert.ok(existsSync(join(x.fenceDir, "expiry")));
  assert.equal(x.u(F.ids.agent).active, false);
  // The same grant again: held, nothing starts. A newer one lowers expiry (unexpire) and starts it.
  const same = await x.sup.submit({ kind: "grant", bytes: grantBytes(1, [F.ids.agent]) });
  assert.notEqual(same.status, "applied");
  assert.equal(x.u(F.ids.agent).active, false);
  const newer = await x.sup.submit({ kind: "grant", bytes: grantBytes(2, [F.ids.agent]) });
  assert.equal(newer.status, "applied", JSON.stringify(newer));
  assert.equal(existsSync(join(x.fenceDir, "expiry")), false);
  assert.equal(x.u(F.ids.agent).active, true);
});

test("chain-adopt is an emergency: it runs before a QUEUED start, never preempting the op already running; host only; refused without the seam", async () => {
  const x = await exec({ certValid: false });
  await x.sup.recover();
  await x.sup.submit({ kind: "grant", bytes: grantBytes(1, [F.ids.agent]) });
  await x.sup.submit({ kind: "stop", authority: "person", agent: F.ids.agent });
  // Hold a running op (a person's stop of the agent, at its fence write), queue a resume, then the adoption.
  let release, reached;
  const gate = new Promise((r) => { release = r; }), at = new Promise((r) => { reached = r; });
  x.holder.barrier = async (n) => { if (n === "after_fence_write") { x.holder.barrier = null; reached(); await gate; } };
  const order = [];
  const running = x.sup.submit({ kind: "stop-all", authority: "person" }).then(() => order.push("running op"));
  await at;
  const resume = x.sup.submit({ kind: "resume", authority: "person", agent: F.ids.agent }).then((r) => { order.push(`resume:${r.status}`); });
  const adoption = adopt(x.sup).then((r) => { order.push(`adopt:${r.status}`); });
  release();
  await Promise.all([running, resume, adoption]);
  assert.deepEqual(order, ["running op", "adopt:revoked", "resume:refused"]);
  for (const authority of ["service", "person", "local"]) {
    await assert.rejects(x.sup.submit({ kind: "chain-adopt", authority, candidate: cand }), (e) => e.code === "not_granted");
  }
  const store = await HostStore.open(join(tmp(), "s2"));
  const plain = new Supervisor({ store, fx: {}, verify, bodyOf, fenceDir: join(tmp(), "f") });
  await assert.rejects(plain.submit({ kind: "chain-adopt", authority: "host", candidate: cand }), (e) => e.code === "bad_form");
});
