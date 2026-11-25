// Host supervisor: the host-local records the transfer checks read (schemas r2.4 §3.7.1, §3.7.3 checks 4-6): per agent
// entry_gen and listed_since, moved in the grant state's one highwater commit; each accepted grant's digest by gen;
// the accepted transfers and their nonces; and hostRecords, read by the real checkTransferForHost.
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "./host-linux-only.mjs";
import { FleetError, newId, sha256b64 } from "../lib/fleet/index.mjs";
import { checkTransferForHost } from "../lib/fleet/core/verify.mjs";
import { checkGrantState, entryDigest, nextRecords } from "../lib/fleet/host/grant.mjs";
import { HostStore } from "../lib/fleet/host/host-store.mjs";
import { MAX_NONCES, checkTransfers, hostRecords, recordTransfer } from "../lib/fleet/host/host-records.mjs";

const refused = (fn, code) => assert.throws(fn, (e) => e instanceof FleetError && e.code === code, code);
const rejects = (p, code) => assert.rejects(p, (e) => e instanceof FleetError && e.code === code, code);
const fresh = () => join(mkdtempSync(join(tmpdir(), "sb-records-")), "state");
const okIntent = async () => {};
const d = (s) => sha256b64(Buffer.from(String(s)));
const X = newId(), Y = newId(), Z = newId();
const HOST = newId(), FP = d("cert");

/** Accept generation `gen` listing `entries` (agent id -> entry digest), and finish it. Returns its digest. */
async function accept(store, gen, entries) {
  const bytes = Buffer.from(`grant ${gen} ${JSON.stringify(entries)}`), digest = sha256b64(bytes);
  await store.grants.begin(gen, bytes, digest, ["a"], okIntent, { entries });
  store.grants.done(0);
  store.grants.finish({ narrowed: false, restarted: [] });
  return digest;
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
  assert.deepEqual([g.digestAt(1), g.digestAt(2), g.digestAt(3), g.digestAt(4), g.digestAt(5), g.digestAt(0), g.digestAt(-1), g.digestAt(1.5)],
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
  assert.equal(store.grants.digestAt(1), d1);
  // A missing marker reads as null (the check then refuses); a corrupt one is refused.
  rmSync(join(dir, "1"));
  assert.equal(store.grants.digestAt(1), null);
  writeFileSync(join(dir, "1"), "not a digest");
  refused(() => store.grants.digestAt(1), "bad_form");
  await store.close();
});

test("begin without records input is refused before anything is accepted", async () => {
  const store = await HostStore.open(fresh());
  const bytes = Buffer.from("g1");
  for (const entries of [undefined, null, [], { "not-an-id": d(1) }, { [X]: "short" }]) {
    await rejects(store.grants.begin(1, bytes, sha256b64(bytes), ["a"], okIntent, { entries }), "bad_form");
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
  const base = { v: 2, gen: 4, digest: d(4), phase: "applied", plan: [], ack: { narrowed: false, restarted: [] }, proof: {} };
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
  const d3 = store.grants.digestAt(3);
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
  const store = await HostStore.open(fresh());
  await accept(store, 1, { [X]: d("x1") });
  const host = hostRecords(store, { id: HOST, fingerprint: FP });
  // The shape the resume gate checks before it uses the records (entryGen and recordTransfer are functions).
  assert.equal(typeof host.entryGen, "function");
  assert.equal(typeof host.recordTransfer, "function");
  assert.ok(Object.isFrozen(host));
  host.recordTransfer(X, T(1, N(1), d("t1")));
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

test("a stray marker past the highwater is never read: digestAt is null beyond the accepted generation", async () => {
  const root = fresh();
  const store = await HostStore.open(root);
  const d1 = await accept(store, 1, { [X]: d("x1") });
  await accept(store, 2, { [X]: d("x1") });
  // A file where a future generation's marker would go (planted: begin never writes one past the highwater).
  writeFileSync(join(root, "grant", "accepted", "5"), d1);
  assert.equal(store.grants.digestAt(5), null);
  assert.equal(store.grants.digestAt(3), null);
  assert.equal(store.grants.digestAt(1), d1);
  await store.close();
});
