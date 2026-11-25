// Host supervisor: the host-local records the transfer checks read (schemas r2.4 §3.7.1, §3.7.3 checks 4-6): per agent
// entry_gen and listed_since, moved in the grant state's one highwater commit; each accepted grant's digest by gen;
// the accepted transfers and their nonces; and hostRecords, read by the real checkTransferForHost.
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "./host-linux-only.mjs";
import { FleetError, newId, sha256b64, b64, keyFromSeed, seal, signedBytes, applyChainEntry, hostFingerprint, verifyHostCert, verifyGrant as coreVerifyGrant } from "../lib/fleet/index.mjs";
import { x25519Generate } from "../lib/fleet/channel/noise.mjs";
import { checkTransferForHost } from "../lib/fleet/core/verify.mjs";
import { checkGrantState, entryDigest, nextRecords, verifyGrant as hostVerifyGrant } from "../lib/fleet/host/grant.mjs";
import { HostStore } from "../lib/fleet/host/host-store.mjs";
import { MAX_NONCES, checkTransfers, hostRecords, hostRecordsFromCert, recordTransfer } from "../lib/fleet/host/host-records.mjs";

const refused = (fn, code) => assert.throws(fn, (e) => e instanceof FleetError && e.code === code, code);
const rejects = (p, code) => assert.rejects(p, (e) => e instanceof FleetError && e.code === code, code);
const fresh = () => join(mkdtempSync(join(tmpdir(), "sb-records-")), "state");
const okIntent = async () => {};
const d = (s) => sha256b64(Buffer.from(String(s)));
const X = newId(), Y = newId(), Z = newId();
const HOST = newId(), FP = d("cert");

/**
 * Accept generation `gen` listing `entries` (agent id -> entry digest), and finish it. Returns its signed-bytes hash, a
 * stand-in distinct from the envelope digest (the real one is the last test's).
 */
async function accept(store, gen, entries) {
  const bytes = Buffer.from(`grant ${gen} ${JSON.stringify(entries)}`), digest = sha256b64(bytes);
  const hash = d(`signed ${gen} ${JSON.stringify(entries)}`);
  await store.grants.begin(gen, bytes, digest, ["a"], okIntent, { entries, hash });
  store.grants.done(0);
  store.grants.finish({ narrowed: false, restarted: [] });
  return hash;
}

test("nextRecords: added, changed, identical, dropped", () => {
  assert.deepEqual(nextRecords({}, { [X]: d(1) }, 1), { [X]: { entry: d(1), entry_gen: 1, listed_since: 1 } });
  const r1 = { [X]: { entry: d(1), entry_gen: 1, listed_since: 1 }, [Y]: { entry: d(2), entry_gen: 3, listed_since: 2 } };
  assert.deepEqual(nextRecords(r1, { [X]: d(1), [Y]: d(9), [Z]: d(3) }, 5), {
    [X]: { entry: d(1), entry_gen: 1, listed_since: 1 }, // identical: kept
    [Y]: { entry: d(9), entry_gen: 5, listed_since: 2 }, // changed: entry_gen moves, listed_since stays
    [Z]: { entry: d(3), entry_gen: 5, listed_since: 5 }, // added
  });
  assert.deepEqual(nextRecords(r1, { [Y]: d(2) }, 6), { [Y]: r1[Y] }); // X dropped
  // entryDigest is over canonical bytes: key order doesn't matter, any field does
  assert.equal(entryDigest({ a: 1, b: [2] }), entryDigest({ b: [2], a: 1 }));
  assert.notEqual(entryDigest({ a: 1, b: [2] }), entryDigest({ a: 1, b: [3] }));
});

test("records move with the highwater: entry_gen, listed_since, every accepted digest by gen", async () => {
  const root = fresh();
  const store = await HostStore.open(root);
  const g = store.grants;
  const d1 = await accept(store, 1, { [X]: d("x1") });
  const d2 = await accept(store, 2, { [X]: d("x1"), [Y]: d("y1") });
  const d4 = await accept(store, 4, { [X]: d("x2"), [Y]: d("y1") });
  assert.deepEqual(g.record(X), { entry: d("x2"), entry_gen: 4, listed_since: 1 });
  assert.deepEqual(g.record(Y), { entry: d("y1"), entry_gen: 2, listed_since: 2 });
  assert.equal(g.record(Z), null);
  assert.deepEqual([g.hashAt(1), g.hashAt(2), g.hashAt(3), g.hashAt(4), g.hashAt(5), g.hashAt(0), g.hashAt(-1), g.hashAt(1.5)],
    [d1, d2, null, d4, null, null, null, null]);
  // the current generation's digest is the state's; each earlier one is in accepted/<gen>
  const dir = join(root, "grant", "accepted");
  assert.deepEqual(readdirSync(dir).sort(), ["1", "2"]);
  assert.deepEqual([readFileSync(join(dir, "1"), "utf8"), readFileSync(join(dir, "2"), "utf8")], [d1, d2]);
  await store.close();
});

test("an earlier generation's digest is written before the next one is accepted; a failure leaves it unaccepted", async () => {
  const root = fresh();
  let store = await HostStore.open(root);
  const d1 = await accept(store, 1, { [X]: d("x1") });
  const dir = join(root, "grant", "accepted");
  assert.deepEqual(readdirSync(dir), []);
  // A different file already at accepted/1: the marker can't be written, so generation 2 is not accepted.
  writeFileSync(join(dir, "1"), d("other"));
  await assert.rejects(accept(store, 2, { [X]: d("x1") }), /different file/);
  assert.equal(store.grants.highwater.gen, 1);
  await store.close();
  rmSync(join(dir, "1"));
  store = await HostStore.open(root);
  await accept(store, 2, { [X]: d("x1") });
  assert.equal(readFileSync(join(dir, "1"), "utf8"), d1);
  assert.equal(store.grants.hashAt(1), d1);
  // A missing marker reads as null (the check then refuses); a corrupt one is refused.
  rmSync(join(dir, "1"));
  assert.equal(store.grants.hashAt(1), null);
  writeFileSync(join(dir, "1"), "not a digest");
  refused(() => store.grants.hashAt(1), "bad_form");
  await store.close();
});

test("begin without a valid signed-bytes hash is refused before the intent is appended or any byte written", async () => {
  const root = fresh();
  const store = await HostStore.open(root);
  const bytes = Buffer.from("g1");
  let intents = 0;
  const intent = async () => { intents++; };
  for (const hash of [undefined, null, "", "short", 7, sha256b64(bytes) + "x"]) {
    await rejects(store.grants.begin(1, bytes, sha256b64(bytes), ["a"], intent, { entries: { [X]: d(1) }, hash }), "bad_form");
  }
  assert.equal(intents, 0, "refused before the intent");
  assert.deepEqual(readdirSync(join(root, "grant", "grants")), [], "and before the grant bytes");
  assert.equal(store.grants.highwater.gen, 0);
  await store.close();
});

test("begin without records input is refused before anything is accepted", async () => {
  const store = await HostStore.open(fresh());
  const bytes = Buffer.from("g1");
  for (const entries of [undefined, null, [], { "not-an-id": d(1) }, { [X]: "short" }]) {
    await rejects(store.grants.begin(1, bytes, sha256b64(bytes), ["a"], okIntent, { entries, hash: d("h") }), "bad_form");
  }
  assert.equal(store.grants.highwater.gen, 0);
  await store.close();
});

test("v:1 grant state: empty becomes v:2; one that accepted a grant is refused at open, before any write", async () => {
  const v1 = (gen, digest) => ({ v: 1, gen, digest, phase: "applied", plan: [], ack: gen === 0 ? null : { narrowed: false, restarted: [] }, proof: {} });
  // empty: upgraded
  let root = fresh();
  mkdirSync(join(root, "grant"), { recursive: true });
  writeFileSync(join(root, "grant", "state.json"), JSON.stringify(v1(0, null)));
  let store = await HostStore.open(root);
  assert.equal(store.grants.highwater.gen, 0);
  assert.equal(JSON.parse(readFileSync(join(root, "grant", "state.json"), "utf8")).v, 2);
  await accept(store, 1, { [X]: d("x") });
  assert.equal(store.grants.record(X).entry_gen, 1);
  await store.close();
  // with an accepted grant: refused, the file unchanged, nothing created beside it
  root = fresh();
  mkdirSync(join(root, "grant"), { recursive: true });
  const text = JSON.stringify(v1(3, d("g3")));
  writeFileSync(join(root, "grant", "state.json"), text);
  await assert.rejects(HostStore.open(root), (e) => e instanceof FleetError && e.code === "bad_form" && /re-provision/.test(e.message));
  assert.equal(readFileSync(join(root, "grant", "state.json"), "utf8"), text);
  assert.deepEqual(readdirSync(join(root, "grant")), ["state.json"]);
  assert.equal(existsSync(join(root, "transfers")), false);
});

test("the grant state's records: closed shape", () => {
  const base = { v: 2, gen: 4, digest: d(4), hash: d("signed 4"), phase: "applied", plan: [], ack: { narrowed: false, restarted: [] }, proof: {} };
  assert.equal(checkGrantState({ ...base, records: { [X]: { entry: d(1), entry_gen: 4, listed_since: 1 } } }), true);
  for (const records of [null, [], { bad: { entry: d(1), entry_gen: 1, listed_since: 1 } },
    { [X]: { entry: "x", entry_gen: 1, listed_since: 1 } }, { [X]: { entry: d(1), entry_gen: 1 } },
    { [X]: { entry: d(1), entry_gen: 1, listed_since: 1, extra: 1 } }, { [X]: { entry: d(1), entry_gen: 1, listed_since: 2 } },
    { [X]: { entry: d(1), entry_gen: 5, listed_since: 1 } }, { [X]: { entry: d(1), entry_gen: 1, listed_since: 0 } }]) {
    refused(() => checkGrantState({ ...base, records }), "bad_form");
  }
  refused(() => checkGrantState({ ...base }), "bad_form");
  refused(() => checkGrantState({ ...base, v: 1, records: {} }), "bad_form");
});

// ---- transfers, and the real check over hostRecords

const T = (gen, nonce, transfer) => ({ gen, nonce, transfer });
const N = (i) => Buffer.alloc(16, i).toString("base64url");
/** A verified pair as verifyTransferReceipt returns it (checks 1-3 are auth's, tested there). */
const pair = (agent, gen, grant, nonce, transferHash, over = {}) => ({
  transfer: { agent, gen, grant, nonce, to_host: HOST, to_host_key: FP, ...over }, receipt: {}, transferHash,
});

test("checkTransferForHost over hostRecords: first, retry, newer, replay, stale, another host, another grant", async () => {
  const store = await HostStore.open(fresh());
  const host = hostRecords(store, { id: HOST, fingerprint: FP });
  const d1 = await accept(store, 1, { [X]: d("x1") });
  const d2 = await accept(store, 2, { [X]: d("x1"), [Y]: d("y1") });
  // X moved in at 1; the pair passes as a first acceptance, is recorded, then passes again as the retry
  const p1 = pair(X, 1, d1, N(1), d("t1"));
  assert.deepEqual(checkTransferForHost(p1, host), { first: true });
  recordTransfer(store, X, T(1, N(1), d("t1")));
  assert.deepEqual(checkTransferForHost(p1, host), { first: false });
  assert.deepEqual(host.acceptedTransfer(X), T(1, N(1), d("t1")));
  assert.equal(host.nonceSeen(N(1)), d("t1"));
  // the nonce reused by another transfer: replay; a gen not above the accepted one: stale_generation
  refused(() => checkTransferForHost(pair(Y, 2, d2, N(1), d("t9")), host), "replay");
  refused(() => checkTransferForHost(pair(X, 1, d1, N(2), d("t2")), host), "stale_generation");
  // another host or key; a grant this host didn't accept at that gen; a gen with no grant here
  refused(() => checkTransferForHost(pair(Y, 2, d2, N(3), d("t3"), { to_host: newId() }), host), "not_granted");
  refused(() => checkTransferForHost(pair(Y, 2, d2, N(3), d("t3"), { to_host_key: d("other") }), host), "not_granted");
  refused(() => checkTransferForHost(pair(Y, 2, d1, N(3), d("t3")), host), "not_granted");
  refused(() => checkTransferForHost(pair(Y, 3, d2, N(3), d("t3")), host), "not_granted");
  // Y listed from 2: a transfer dated 1 names a grant that didn't list it
  refused(() => checkTransferForHost(pair(Y, 1, d1, N(3), d("t3")), host), "not_granted");
  // the entry changed after the move: still valid (entry_gen above gen)
  await accept(store, 3, { [X]: d("x2"), [Y]: d("y1") });
  assert.deepEqual([host.entryGen(X), host.listedSince(X)], [3, 1]);
  assert.deepEqual(checkTransferForHost(p1, host), { first: false });
  await store.close();
});

test("a dropped agent: records and accepted transfer gone, nonces kept; a re-listing is a new interval", async () => {
  const root = fresh();
  const store = await HostStore.open(root);
  const host = hostRecords(store, { id: HOST, fingerprint: FP });
  const d1 = await accept(store, 1, { [X]: d("x1"), [Y]: d("y1") });
  recordTransfer(store, X, T(1, N(1), d("t1")));
  await accept(store, 2, { [Y]: d("y1") }); // X dropped
  assert.deepEqual([host.listedSince(X), host.entryGen(X), host.acceptedTransfer(X), host.grantListsAgent(1, X)], [null, null, null, false]);
  assert.equal(host.nonceSeen(N(1)), d("t1"));
  refused(() => checkTransferForHost(pair(X, 1, d1, N(1), d("t1")), host), "not_granted");
  // recording another agent's transfer prunes the dropped agent's entry; its nonce stays
  const accepted = () => Object.keys(JSON.parse(readFileSync(join(root, "transfers", "transfers.json"), "utf8")).accepted).sort();
  recordTransfer(store, Y, T(1, N(5), d("t5")));
  assert.deepEqual(accepted(), [Y]);
  assert.equal(host.nonceSeen(N(1)), d("t1"));
  // listed again at 3 (the registry refuses the id itself; the records show only the new interval): gen 1 no longer
  // counts as listing it, though that grant did
  await accept(store, 3, { [X]: d("x1"), [Y]: d("y1") });
  assert.deepEqual([host.listedSince(X), host.grantListsAgent(1, X), host.grantListsAgent(3, X), host.grantListsAgent(4, X)], [3, false, true, false]);
  assert.equal(host.acceptedTransfer(X), null);
  refused(() => checkTransferForHost(pair(X, 1, d1, N(2), d("t2")), host), "not_granted");
  // a transfer for the new listing is a first acceptance again; recording it replaces the old one
  const d3 = store.grants.hashAt(3);
  assert.deepEqual(checkTransferForHost(pair(X, 3, d3, N(6), d("t6")), host), { first: true });
  recordTransfer(store, X, T(3, N(6), d("t6")));
  assert.deepEqual(host.acceptedTransfer(X), T(3, N(6), d("t6")));
  assert.deepEqual(accepted(), [X, Y].sort());
  // the old nonce, from the earlier listing, still can't be used by another transfer
  const d4 = await accept(store, 4, { [X]: d("x2"), [Y]: d("y1") });
  refused(() => checkTransferForHost(pair(X, 4, d4, N(1), d("t7")), host), "replay");
  assert.deepEqual(checkTransferForHost(pair(X, 4, d4, N(8), d("t8")), host), { first: true });
  await store.close();
});

test("recordTransfer refuses what a first acceptance can't be; the same transfer again is a no-op", async () => {
  const store = await HostStore.open(fresh());
  await accept(store, 1, { [X]: d("x1") });
  await accept(store, 2, { [X]: d("x1"), [Y]: d("y1") });
  recordTransfer(store, X, T(1, N(1), d("t1")));
  recordTransfer(store, X, T(1, N(1), d("t1"))); // the retry
  refused(() => recordTransfer(store, Z, T(2, N(2), d("t2"))), "not_granted"); // not listed
  refused(() => recordTransfer(store, Y, T(1, N(2), d("t2"))), "not_granted"); // Y listed only from 2
  refused(() => recordTransfer(store, X, T(1, N(2), d("t2"))), "stale_generation");
  refused(() => recordTransfer(store, Y, T(2, N(1), d("t9"))), "replay");
  for (const bad of [T(0, N(3), d(3)), T(2, "short", d(3)), T(2, N(3), "short"), { gen: 2, nonce: N(3) }, null]) {
    refused(() => recordTransfer(store, Y, bad), "bad_form");
  }
  refused(() => recordTransfer(store, "nope", T(2, N(3), d(3))), "bad_form");
  recordTransfer(store, X, T(2, N(4), d("t4"))); // a newer one
  assert.deepEqual(hostRecords(store, { id: HOST, fingerprint: FP }).acceptedTransfer(X), T(2, N(4), d("t4")));
  assert.deepEqual([store.transfers.nonce(N(1)), store.transfers.nonce(N(4))], [d("t1"), d("t4")]);
  await store.close();
});

test("the transfer records: closed shape, durable across a reopen", async () => {
  const ok = { v: 1, accepted: { [X]: T(1, N(1), d(1)) }, nonces: { [N(1)]: d(1), [N(2)]: d(2) } };
  assert.equal(checkTransfers(ok), true);
  for (const r of [{ ...ok, v: 2 }, { ...ok, extra: 1 }, { v: 1, accepted: {} }, { ...ok, accepted: { bad: T(1, N(1), d(1)) } },
    { ...ok, accepted: { [X]: T(1, N(9), d(1)) } }, { ...ok, accepted: { [X]: T(1, N(1), d(2)) } }, { ...ok, nonces: { short: d(1) } },
    { ...ok, accepted: { [X]: { ...T(1, N(1), d(1)), x: 1 } } }]) {
    refused(() => checkTransfers(r), "bad_form");
  }
  assert.ok(MAX_NONCES >= 10_000);
  const root = fresh();
  let store = await HostStore.open(root);
  await accept(store, 1, { [X]: d("x1") });
  recordTransfer(store, X, T(1, N(1), d("t1")));
  await store.close();
  store = await HostStore.open(root);
  assert.deepEqual(hostRecords(store, { id: HOST, fingerprint: FP }).acceptedTransfer(X), T(1, N(1), d("t1")));
  await store.close();
});

test("hostRecords carries the writer, bound to its store: the resume gate's host.recordTransfer", async () => {
  const root = fresh();
  const store = await HostStore.open(root);
  await accept(store, 1, { [X]: d("x1") });
  const host = hostRecords(store, { id: HOST, fingerprint: FP });
  // The shape the resume gate checks before it uses the records (entryGen and recordTransfer are functions).
  assert.equal(typeof host.entryGen, "function");
  assert.equal(typeof host.recordTransfer, "function");
  assert.ok(Object.isFrozen(host));
  // Synchronous: no promise, and the record is on disk when it returns (the resume gate launches right after it).
  assert.equal(host.recordTransfer(X, T(1, N(1), d("t1"))), undefined);
  assert.deepEqual(JSON.parse(readFileSync(join(root, "transfers", "transfers.json"), "utf8")).accepted[X], T(1, N(1), d("t1")));
  assert.deepEqual(host.acceptedTransfer(X), T(1, N(1), d("t1")));
  assert.equal(host.nonceSeen(N(1)), d("t1"));
  // It refuses as the exported writer does.
  refused(() => host.recordTransfer(X, T(1, N(2), d("t2"))), "stale_generation");
  await store.close();
});

test("a re-listing with no record in between: the earlier listing's transfer, still on disk, doesn't count", async () => {
  const root = fresh();
  const store = await HostStore.open(root);
  const host = hostRecords(store, { id: HOST, fingerprint: FP });
  await accept(store, 1, { [X]: d("x1") });
  host.recordTransfer(X, T(1, N(1), d("t1")));
  await accept(store, 2, { [Y]: d("y1") }); // X dropped; nothing is recorded, so nothing prunes
  await accept(store, 3, { [X]: d("x1"), [Y]: d("y1") }); // X listed again from 3
  const onDisk = JSON.parse(readFileSync(join(root, "transfers", "transfers.json"), "utf8")).accepted;
  assert.deepEqual(onDisk[X], T(1, N(1), d("t1")), "the old entry is still in the file");
  assert.equal(host.acceptedTransfer(X), null, "but it belongs to the earlier listing");
  assert.equal(host.listedSince(X), 3);
  await store.close();
});

test("a stray marker past the highwater is never read: hashAt is null beyond the accepted generation", async () => {
  const root = fresh();
  const store = await HostStore.open(root);
  const d1 = await accept(store, 1, { [X]: d("x1") });
  await accept(store, 2, { [X]: d("x1") });
  // A file where a future generation's marker would go (planted: begin never writes one past the highwater).
  writeFileSync(join(root, "grant", "accepted", "5"), d1);
  assert.equal(store.grants.hashAt(5), null);
  assert.equal(store.grants.hashAt(3), null);
  assert.equal(store.grants.hashAt(1), d1);
  await store.close();
});

// ---- interoperability: the hash a real transfer carries, and the fingerprint from the real certificate

/** A fleet with a native device, this host's verified certificate, and a grant sealed by that device for `gen`. */
async function realFleet() {
  const AUD = "https://dev.sagebrush.space", fleet = newId(), host = newId();
  const N = keyFromSeed(new Uint8Array(32).fill(41)), rec = keyFromSeed(new Uint8Array(32).fill(42)), nId = newId();
  const sN = { kind: "device", id: nId, alg: "ed25519", key: N.key };
  const chain = (await applyChainEntry(null, seal("sb.device-chain.v1", sN, { fleet, aud: AUD, seq: 0, prev: "", op: "genesis", at_ms: 1, auth_time_ms: 1,
    device: { id: nId, alg: "ed25519", key: b64(N.raw), name: "mac", tier: "native" }, recovery_key: { alg: "ed25519", key: b64(rec.raw) } }, N), { aud: AUD, fleet })).state;
  const H = keyFromSeed(new Uint8Array(32).fill(43)), encKey = x25519Generate();
  const fp = await hostFingerprint(host, H.raw, encKey.raw);
  const cert = await verifyHostCert(seal("sb.host-cert.v1", sN, { fleet, aud: AUD, chain_seq: 0, host, sign_key: b64(H.raw), enc_key: b64(encKey.raw),
    fingerprint: b64(fp), name: "box", at_ms: 1 }, N), { aud: AUD, fleet, chain });
  const config = { files: { rw: [], ro: [] }, network: { mode: "none", allow: [], lan_allow: [] }, programs: "run", mcp_allow: null, gpu: false,
    resources: { memory_max_mb: 1024, tasks_max: 1024, cpu_weight: 100, cpu_quota_pct: null, io_weight: 100, disk_gb: 10, nofile: 65536 },
    wakes: [], turns: { per_day: 10, wall_s: 7200 } };
  const tag = newId();
  // The host checks a full config; the fleet schema (core) admits only {} until host r2-final is imported, so the core
  // path is exercised on a grant with config {} (`core: true`), the host path on one with the full config.
  const body = (gen, x, core) => ({ fleet, aud: AUD, host, gen, cert: cert.hash, chain_seq: 0, at_ms: 1000 + gen, not_before_ms: 1000, not_after_ms: 10_000,
    auth_time_ms: 1000, agents: [{ agent: X, name: `worker-${x}`, client: "claude", root: false, tags: [tag], workspace: [{ path: "/Course", access: "write" }],
      broker: ["messages"], spend_cap_cents: 0, config_schema: 1, config: core ? {} : config }],
    tags: [{ tag, name: "course-1" }], subscriptions: [], offline: { revocation_check_s: 900, horizon_s: 3600 } });
  const grant = (gen, x = 1, core = false) => { const b = body(gen, x, core); return { body: b, bytes: seal("sb.host-grant.v1", sN, b, N), signed: signedBytes("sb.host-grant.v1", sN, b) }; };
  const resolveKey = (sg) => { if (sg.key === N.key) return N.raw; throw new FleetError("device_unknown"); };
  const hostCtx = { aud: AUD, fleet, host, cert: cert.hash, now: 5000, resolveKey, hostInfo: { ramMb: 8192, cpus: 4 } };
  const coreCtx = (current) => ({ aud: AUD, fleet, chain, cert, current, now: 5000 });
  return { cert, grant, hostCtx, coreCtx };
}

/** Accept a real grant the way the executor does: the host's verify, its entries and its signed-bytes hash. */
async function acceptReal(store, g, ctx) {
  const v = hostVerifyGrant(g.bytes, ctx);
  await store.grants.begin(v.body.gen, g.bytes, v.digest, ["a"], okIntent, { entries: Object.fromEntries(v.body.agents.map((a) => [a.agent, entryDigest(a)])), hash: v.hash });
  store.grants.done(0);
  store.grants.finish({ narrowed: false, restarted: [] });
  return v;
}

test("the core check's grant hash is the SHA-256 of signedBytes(type, signer, body): the value a transfer carries", async () => {
  const { grant, coreCtx } = await realFleet();
  for (const [gen, cur] of [[1, null], [2, "prev"]]) {
    const g = grant(gen, gen, true), prev = grant(1, 1, true);
    const c = await coreVerifyGrant(g.bytes, coreCtx(cur && { gen: 1, bytes: prev.bytes, body: prev.body }));
    assert.equal(c.hash, sha256b64(g.signed), `gen ${gen}`);
    assert.notEqual(c.hash, sha256b64(g.bytes), "never the envelope's digest");
  }
});

test("the service's transfer passes 5a: a real signed grant accepted, historical and after a reopen", async () => {
  const { cert, grant, hostCtx } = await realFleet();
  const root = fresh();
  let store = await HostStore.open(root);
  const g1 = grant(1);
  // The service's value (the core check's `hash`, previous test): the SHA-256 of the grant's SIGNED bytes.
  const c1 = { hash: sha256b64(g1.signed) };
  const v1 = await acceptReal(store, g1, hostCtx);
  assert.equal(v1.hash, c1.hash, "the host stores the same hash the service computes");
  assert.notEqual(v1.digest, c1.hash, "and it isn't the envelope's digest");
  let host = hostRecordsFromCert(store, cert);
  const tr = (gen, grantHash, i) => ({ transfer: { agent: X, gen, grant: grantHash, nonce: N(i), to_host: cert.body.host, to_host_key: cert.body.fingerprint }, receipt: {}, transferHash: d(`t${i}`) });
  assert.equal(host.grantHashAt(1), c1.hash);
  assert.deepEqual(checkTransferForHost(tr(1, c1.hash, 1), host), { first: true });
  refused(() => checkTransferForHost(tr(1, v1.digest, 2), host), "not_granted"); // the envelope digest is no grant hash
  // gen 2 (X's entry changed): gen 1's hash is now served from its marker, gen 2's from the state.
  const g2 = grant(2, 2);
  const c2 = { hash: sha256b64(g2.signed) };
  await acceptReal(store, g2, hostCtx);
  assert.deepEqual([host.grantHashAt(1), host.grantHashAt(2)], [c1.hash, c2.hash]);
  assert.deepEqual(checkTransferForHost(tr(1, c1.hash, 3), host), { first: true });
  assert.deepEqual(checkTransferForHost(tr(2, c2.hash, 4), host), { first: true });
  // After a reopen: the same answers from disk.
  await store.close();
  store = await HostStore.open(root);
  host = hostRecordsFromCert(store, cert);
  assert.deepEqual([host.grantHashAt(1), host.grantHashAt(2)], [c1.hash, c2.hash]);
  assert.deepEqual(checkTransferForHost(tr(2, c2.hash, 5), host), { first: true });
  await store.close();
});

test("hostRecordsFromCert: the id and fingerprint are the verified certificate's own fields", async () => {
  const { cert } = await realFleet();
  const store = await HostStore.open(fresh());
  const host = hostRecordsFromCert(store, cert);
  assert.equal(host.id, cert.body.host);
  assert.equal(host.fingerprint, cert.body.fingerprint, "the string the person compared, and a transfer's to_host_key");
  for (const bad of [null, {}, { body: {} }, { body: { host: "x", fingerprint: cert.body.fingerprint } }, { body: { host: cert.body.host, fingerprint: 7 } }]) {
    refused(() => hostRecordsFromCert(store, bad), "bad_form");
  }
  await store.close();
});

