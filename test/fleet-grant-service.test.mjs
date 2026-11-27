// The fleet Worker's grant read (lib/fleet/core/grant-service.mjs; the grant-read note r0.4) against an in-memory store
// that follows the module's contract: the nonce's prune and insert as one decision (SHARED with the chain read), and a
// grant with its stored result from one read. A fake can't prove the real store's single statement or its retention:
// the Worker's D1 rows do. Every answer is read by the HOST's reader (parseGrantRead), and its pairs are verified with
// the core's own verifyTransferReceipt over the shared fixtures, as the host's intake verifies them. Not here: the host
// intake's admission (no newly moved agent resumes without its durable pair), which is what makes a withheld pair safe.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { b64, enc, newId, keyFromSeed } from "../lib/fleet/index.mjs";
import { signRequest } from "../lib/fleet/request.mjs";
import * as core from "../lib/fleet/core/index.mjs";
import {
  GRANT_PAIRS_MAX, GRANT_RATE_HOST, GRANT_RATE_SOURCE, GRANT_READ_BYTES, GRANT_RESULT_MAX, GRANT_ROUTE, grantReadBody, grantTarget, handleGrantRead,
  parseGrantRead, parseGrantTarget,
} from "../lib/fleet/core/grant-service.mjs";
import { CHAIN_NONCE_KEEP_MS, chainTarget, handleChainRead } from "../lib/fleet/core/chain-service.mjs";
import { SIGNED_MAX, canonText } from "../lib/fleet/core/canonical.mjs";

const F = JSON.parse(readFileSync(new URL("./fixtures/fleet-fixtures.json", import.meta.url), "utf8"));
const AUD = "https://dev.sagebrush.space";
const NOW = 1_800_000_000_000;
const SKEW = 300_000;
const text = (b) => new TextDecoder().decode(b);
let n = 1;
const key = () => keyFromSeed(new Uint8Array(32).fill(n++ & 255));
const nonce = () => b64(new Uint8Array(16).fill(n++ & 255)).slice(0, 22);
const errorOf = (r) => (r.body.length ? JSON.parse(text(r.body)).error : null);
// (the stored result as the writer stores it: JSON.stringify of its pairs, transfer first)
const stored = (pairs) => JSON.stringify(pairs.map((p) => ({ transfer: p.transfer, receipt: p.receipt })));

// ---- the fixtures: a real grant and real { transfer, receipt } pairs, verified against the fixtures' honest chain
const GRANT = F.objects.grants.find((c) => c.name === "a grant").bytes;
// (valid pairs with DISTINCT transfers, so a receipt swapped between two of them names another transfer)
const OK_PAIRS = F.transfers.receipts.filter((c) => c.expect === "ok" && !c.chain).map((c) => ({ transfer: c.transfer, receipt: c.receipt }))
  .filter((p, i, all) => all.findIndex((q) => q.transfer === p.transfer) === i);
const fixtureCtx = { aud: F.aud, fleet: F.ids.fleet };
const honest = await core.replayChain(F.transfers.chain.map(enc), fixtureCtx);
const verifyPair = (p) => core.verifyTransferReceipt(p, { ...fixtureCtx, chain: honest });

/** A Worker's state as the handler's ctx sees it: hosts, generations, nonces (shared by both reads) and stored grants. */
function world() {
  const fleetA = newId(), fleetB = newId(), hostA = newId(), hostB = newId();
  const keys = { [hostA]: key(), [hostB]: key() };
  const st = {
    now: NOW,
    hosts: new Map([[hostA, { fleet: fleetA, sign_key: keys[hostA].raw, revoked: false }], [hostB, { fleet: fleetB, sign_key: keys[hostB].raw, revoked: false }]]),
    gens: new Map([[hostA, 3], [hostB, 1]]),
    nonces: new Map(), counts: new Map(),
    // (fleet/host -> gen -> { bytes, result }; `n` overrides the results count for the store-fault rows)
    grants: new Map(), n: null,
    spends: 0, reads: [], failSpend: false, failRead: false,
  };
  const put = (fleet, host, gen, bytes, pairs = null) => {
    const k = `${fleet}/${host}`;
    if (!st.grants.has(k)) st.grants.set(k, new Map());
    st.grants.get(k).set(gen, { bytes, result: pairs === null ? null : typeof pairs === "string" ? pairs : stored(pairs) });
  };
  const ctx = (over = {}) => ({
    aud: AUD, get now() { return st.now; },
    host: async (h) => st.hosts.get(h) ?? null,
    currentGen: async (_f, h) => st.gens.get(h),
    bucket: async (k, limit) => { const c = (st.counts.get(k) ?? 0) + 1; st.counts.set(k, c); return c <= limit; },
    nonces: {
      spend: async ({ fleet, host, nonce: nc, now }) => {
        st.spends++;
        if (st.failSpend) throw new Error("the batch failed");
        for (const [k, t] of st.nonces) if (k.startsWith(`${fleet}/${host}/`) && t < now - CHAIN_NONCE_KEEP_MS) st.nonces.delete(k);
        const k = `${fleet}/${host}/${nc}`;
        if (st.nonces.has(k)) return false;
        st.nonces.set(k, now);
        return true;
      },
    },
    grant: {
      read: async (fleet, host, gen) => {
        st.reads.push({ fleet, host, gen });
        if (st.failRead) throw new Error("the read failed");
        const m = st.grants.get(`${fleet}/${host}`);
        if (!m || m.size === 0) return null;
        const g = gen === null ? Math.max(...m.keys()) : gen;
        const row = m.get(g);
        if (!row) return null;
        return { gen: g, bytes: row.bytes, result: row.result, n: st.n ?? (row.result === null ? 0 : 1) };
      },
    },
    // (the chain read's own store, for the shared-nonce rows)
    chain: { page: async () => ({ head: -1, entries: [] }) },
    ...over,
  });
  const sig = (h = hostA, { gen: g = null, target = grantTarget(g), aud = AUD, method = "GET", hgen = st.gens.get(h) ?? 1, ts = st.now, nonce: nc = nonce(), signer = keys[h], ...fields } = {}) =>
    ({ target, header: signRequest({ aud, method, target, host: h, key: signer, fields: { gen: hgen, ts, nonce: nc, ...fields } }) });
  const send = (q, c = ctx(), over = {}) => handleGrantRead({ method: "GET", scheme: "https", source: "198.51.100.7", body: new Uint8Array(0), ...q, ...over }, c);
  const nothingSpent = () => assert.equal(st.spends + st.reads.length, 0, "no nonce spent and no grant read");
  return { fleetA, fleetB, hostA, hostB, keys, st, ctx, put, sig, send, nothingSpent };
}

test("row 1: the stored grant and its pairs, byte for byte, in request order, and each pair verifies as the host verifies it", async () => {
  assert.ok(OK_PAIRS.length >= 2, "the fixtures carry at least two valid pairs");
  const w = world();
  w.put(w.fleetA, w.hostA, 3, GRANT, OK_PAIRS.slice(0, 2));
  const r = await w.send(w.sig());
  assert.equal(r.status, 200);
  assert.equal(r.headers["cache-control"], "no-store");
  assert.equal(r.headers["content-type"], "application/json");
  const a = parseGrantRead(r.body, null);
  assert.equal(a.gen, 3);
  assert.equal(text(a.grant), GRANT);
  assert.deepEqual(a.pairs.map((p) => [text(p.transfer), text(p.receipt)]), OK_PAIRS.slice(0, 2).map((p) => [p.transfer, p.receipt]));
  for (const p of a.pairs) await verifyPair(p);
  // (a grant applied with no transfers: pairs [])
  w.put(w.fleetA, w.hostA, 4, GRANT);
  w.st.gens.set(w.hostA, 4);
  const r2 = await w.send(w.sig());
  assert.deepEqual(parseGrantRead(r2.body).pairs, []);
});

test("row 2: generations: the newest without gen, exactly gen with it, below the host's current one too, and the same bytes on every read", async () => {
  const w = world();
  for (const g of [1, 2, 3]) w.put(w.fleetA, w.hostA, g, GRANT, g === 2 ? OK_PAIRS.slice(0, 1) : null);
  assert.equal(parseGrantRead((await w.send(w.sig())).body).gen, 3);
  const two = await w.send(w.sig(w.hostA, { gen: 2 }));
  assert.equal(parseGrantRead(two.body, 2).gen, 2);
  // (the host at 3 reads 1: below its current generation)
  assert.equal(parseGrantRead((await w.send(w.sig(w.hostA, { gen: 1 }))).body, 1).gen, 1);
  // (each generation twice: byte-identical answers)
  for (const g of [1, 2, 3]) {
    const x = await w.send(w.sig(w.hostA, { gen: g })), y = await w.send(w.sig(w.hostA, { gen: g }));
    assert.deepEqual(x.body, y.body, `gen ${g} read twice`);
  }
  // (none at gen 4, and a host with no grant at all)
  const four = await w.send(w.sig(w.hostA, { gen: 4 }));
  assert.equal(four.status, 404);
  assert.equal(errorOf(four), "no_grant");
  assert.equal(errorOf(await w.send(w.sig(w.hostB))), "no_grant");
});

test("row 2: the target's grammar: anything else is bad_form, with nothing spent or read", async () => {
  assert.equal(parseGrantTarget(GRANT_ROUTE), null);
  assert.equal(parseGrantTarget(`${GRANT_ROUTE}?gen=9007199254740991`), 2 ** 53 - 1);
  for (const t of ["?gen=0", "?gen=01", "?gen=-1", "?gen=9007199254740992", "?gen=1&gen=2", "?gen=1&", "?gen=", "?after=1", "?gen=1.0", "?gen=+1"]) {
    const w = world();
    w.put(w.fleetA, w.hostA, 1, GRANT);
    const r = await w.send(w.sig(w.hostA, { target: `${GRANT_ROUTE}${t}` }));
    assert.equal(r.status, 400, t);
    assert.equal(errorOf(r), "bad_form", t);
    w.nothingSpent();
  }
  assert.throws(() => grantTarget(0), RangeError);
});

test("row 3: the header's generation: below the one read is served; above the host's current is stale_generation; 0 is bad_form", async () => {
  const w = world();
  w.put(w.fleetA, w.hostA, 3, GRANT);
  // (a host that accepted 1, fetching 3, signs with its own 1)
  const r = await w.send(w.sig(w.hostA, { gen: 3, hgen: 1 }));
  assert.equal(r.status, 200);
  const hi = await w.send(w.sig(w.hostA, { hgen: 4 }));
  assert.equal(errorOf(hi), "stale_generation");
  // (signRequest won't sign gen=0, so the header is rewritten after signing: its form is refused before its signature)
  const q = w.sig();
  const zeroed = { ...q, header: q.header.replace(/; gen=[0-9]+;/, "; gen=0;") };
  assert.notEqual(zeroed.header, q.header);
  assert.equal(errorOf(await w.send(zeroed)), "bad_form");
});

test("row 4: isolation: the fleet and host read are the signer's own, never anything from the target", async () => {
  const w = world();
  w.put(w.fleetA, w.hostA, 3, GRANT);
  w.put(w.fleetB, w.hostB, 1, GRANT, OK_PAIRS.slice(0, 1));
  // (a host whose own fleet holds nothing for it sees no_grant, whatever the other host has)
  w.st.hosts.set(w.hostB, { ...w.st.hosts.get(w.hostB), fleet: w.fleetA });
  assert.equal(errorOf(await w.send(w.sig(w.hostB))), "no_grant");
  const r = await w.send(w.sig(w.hostA));
  assert.equal(r.status, 200);
  assert.deepEqual(w.st.reads.at(-1), { fleet: w.fleetA, host: w.hostA, gen: null });
});

test("row 5: the request checks, in the chain read's order and codes, each spending nothing", async () => {
  const cases = [
    ["no header", (w) => ({ target: GRANT_ROUTE, header: undefined }), 400, "bad_form"],
    ["signed for another audience", (w) => w.sig(w.hostA, { aud: "https://sagebrush.space" }), 401, "bad_signature"],
    ["an unknown host", (w) => { w.st.hosts.delete(w.hostA); return w.sig(w.hostA); }, 401, "unknown_host"],
    ["a revoked host", (w) => { w.st.hosts.get(w.hostA).revoked = true; return w.sig(w.hostA); }, 403, "host_revoked"],
    ["a bad signature", (w) => w.sig(w.hostA, { signer: key() }), 401, "bad_signature"],
    ["ts 5 min + 1 ms ahead", (w) => w.sig(w.hostA, { ts: NOW + SKEW + 1 }), 401, "clock_skew"],
    ["ts 5 min + 1 ms behind", (w) => w.sig(w.hostA, { ts: NOW - SKEW - 1 }), 401, "clock_skew"],
  ];
  for (const [name, q, status, code] of cases) {
    const w = world();
    w.put(w.fleetA, w.hostA, 3, GRANT);
    const r = await w.send(q(w));
    assert.equal(r.status, status, name);
    assert.equal(errorOf(r), code, name);
    w.nothingSpent();
  }
  for (const ts of [NOW + SKEW, NOW - SKEW]) {
    const w = world();
    w.put(w.fleetA, w.hostA, 3, GRANT);
    assert.equal((await w.send(w.sig(w.hostA, { ts }))).status, 200, `exactly ${ts - NOW}`);
  }
  // (a service whose own audience isn't one of the fleet's: bad_audience, before the host's authority is read)
  {
    const v = world();
    v.put(v.fleetA, v.hostA, 3, GRANT);
    const r = await v.send(v.sig(), v.ctx({ aud: "https://example.com" }));
    assert.equal(errorOf(r), "bad_audience");
    v.nothingSpent();
  }
  const w = world();
  w.put(w.fleetA, w.hostA, 3, GRANT);
  assert.equal(errorOf(await w.send(w.sig(), w.ctx(), { body: enc("{}") })), "bad_form");
  assert.equal((await w.send(w.sig(), w.ctx(), { method: "POST" })).status, 405);
  assert.equal((await w.send(w.sig(), w.ctx(), { scheme: "http" })).status, 403);
  assert.equal((await w.send({ target: "/api/fleet/v1/host/grants", header: "x" })).status, 404);
  w.nothingSpent();
});

test("row 6: nonces: a replay, and a nonce spent on the chain read is a replay here and the reverse (one shared domain)", async () => {
  const w = world();
  w.put(w.fleetA, w.hostA, 3, GRANT);
  const q = w.sig();
  assert.equal((await w.send(q)).status, 200);
  assert.equal(errorOf(await w.send(q)), "replay");
  // (the chain read first, then the same nonce here)
  const nc = nonce();
  const chainQ = { target: chainTarget(), header: signRequest({ aud: AUD, method: "GET", target: chainTarget(), host: w.hostA, key: w.keys[w.hostA], fields: { gen: 3, ts: NOW, nonce: nc } }) };
  assert.equal((await handleChainRead({ method: "GET", scheme: "https", source: "s", body: new Uint8Array(0), ...chainQ }, w.ctx())).status, 200);
  assert.equal(errorOf(await w.send(w.sig(w.hostA, { nonce: nc }))), "replay");
  // (here first, then the chain read)
  const nc2 = nonce();
  assert.equal((await w.send(w.sig(w.hostA, { nonce: nc2 }))).status, 200);
  const chainQ2 = { target: chainTarget(), header: signRequest({ aud: AUD, method: "GET", target: chainTarget(), host: w.hostA, key: w.keys[w.hostA], fields: { gen: 3, ts: NOW, nonce: nc2 } }) };
  const r = await handleChainRead({ method: "GET", scheme: "https", source: "s", body: new Uint8Array(0), ...chainQ2 }, w.ctx());
  assert.equal(JSON.parse(text(r.body)).error, "replay");
  // (a refused request spends no nonce: a bad signature, then the same nonce correctly signed is served)
  const nc3 = nonce();
  assert.equal(errorOf(await w.send(w.sig(w.hostA, { nonce: nc3, signer: key() }))), "bad_signature");
  assert.equal((await w.send(w.sig(w.hostA, { nonce: nc3 }))).status, 200);
});

test("row 7: rates: the source's before authentication, the host's after, each with retry_after_s 60", async () => {
  const w = world();
  w.put(w.fleetA, w.hostA, 3, GRANT);
  w.put(w.fleetB, w.hostB, 1, GRANT);
  w.st.counts.set("grant-src:198.51.100.7", GRANT_RATE_SOURCE.limit);
  const r = await w.send(w.sig());
  assert.equal(r.status, 429);
  assert.deepEqual(JSON.parse(text(r.body)), { error: "rate", retry_after_s: 60 });
  w.nothingSpent();
  w.st.counts.clear();
  w.st.counts.set(`grant-host:${w.hostA}`, GRANT_RATE_HOST.limit);
  assert.deepEqual(JSON.parse(text((await w.send(w.sig())).body)), { error: "rate", retry_after_s: 60 });
  assert.equal((await w.send(w.sig(w.hostB))).status, 200, "another host is unaffected");
});

test("row 9: store faults: two results for one grant, a result out of form, a row at another generation: 500; a failing store: 503", async () => {
  const faults = [
    ["two stored results", (w) => { w.st.n = 2; }],
    ["an unparseable result", (w) => w.put(w.fleetA, w.hostA, 3, GRANT, "[{")],
    ["a pair with a third field", (w) => w.put(w.fleetA, w.hostA, 3, GRANT, JSON.stringify([{ transfer: "a", receipt: "b", x: 1 }]))],
    ["an empty pair text", (w) => w.put(w.fleetA, w.hostA, 3, GRANT, JSON.stringify([{ transfer: "", receipt: "b" }]))],
    ["65 pairs", (w) => w.put(w.fleetA, w.hostA, 3, GRANT, JSON.stringify(Array.from({ length: GRANT_PAIRS_MAX + 1 }, () => ({ transfer: "a", receipt: "b" }))))],
    ["a grant over SIGNED_MAX", (w) => w.put(w.fleetA, w.hostA, 3, "a".repeat(SIGNED_MAX + 1))],
  ];
  for (const [name, make] of faults) {
    const w = world();
    w.put(w.fleetA, w.hostA, 3, GRANT);
    make(w);
    const r = await w.send(w.sig());
    assert.equal(r.status, 500, name);
    assert.equal(r.body.length, 0, name);
  }
  // (a store that answers another generation than the one asked: never served)
  const w = world();
  assert.throws(() => grantReadBody({ gen: 2, bytes: GRANT, result: null }, 3));
  for (const k of ["failSpend", "failRead"]) {
    const v = world();
    v.put(v.fleetA, v.hostA, 3, GRANT);
    v.st[k] = true;
    const r = await v.send(v.sig());
    assert.equal(r.status, 503, k);
  }
  void w;
});

/** Canonical pairs text of exactly `size` bytes, as `count` synthetic pairs of ASCII strings. */
function pairsOfSize(size, count = GRANT_PAIRS_MAX) {
  const empty = enc(canonText(Array.from({ length: count }, () => ({ receipt: "r", transfer: "t" })), size * 2)).length;
  let left = size - empty;
  const pairs = Array.from({ length: count }, () => ({ receipt: "r", transfer: "t" }));
  for (const p of pairs) for (const f of ["receipt", "transfer"]) {
    const add = Math.min(left, SIGNED_MAX - 1);
    p[f] += "x".repeat(add);
    left -= add;
  }
  assert.equal(left, 0, "the pairs reach the size");
  return pairs;
}
// (a synthetic stored grant: canonical JSON of escaped quotes, exactly SIGNED_MAX bytes)
const ESCAPED_GRANT = canonText(['"'.repeat((SIGNED_MAX - 4) / 2)]);

test("row 10: the bound, on synthetic transport rows: the formula, the maximal answer served, and the controls that would refuse it", async () => {
  assert.equal(GRANT_READ_BYTES, 1_179_692);
  assert.equal(enc(ESCAPED_GRANT).length, SIGNED_MAX);
  const maxPairs = pairsOfSize(GRANT_RESULT_MAX);
  assert.equal(enc(canonText(maxPairs, GRANT_RESULT_MAX * 2)).length, GRANT_RESULT_MAX);
  const formula = (gen, grant, pairs) => 26 + String(gen).length + enc(JSON.stringify(grant)).length + enc(canonText(pairs, GRANT_RESULT_MAX * 2)).length;
  // (the maximal synthetic answer: served, its length the formula's, under the cap, and over both control caps)
  const w = world();
  const G = 2 ** 53 - 1;
  w.put(w.fleetA, w.hostA, G, ESCAPED_GRANT, stored(maxPairs));
  w.st.gens.set(w.hostA, G);
  const r = await w.send(w.sig(w.hostA, { gen: G }));
  assert.equal(r.status, 200);
  assert.equal(r.body.length, formula(G, ESCAPED_GRANT, maxPairs));
  assert.equal(r.body.length, 1_179_690);
  assert.ok(r.body.length <= GRANT_READ_BYTES);
  const a = parseGrantRead(r.body, G);
  assert.equal(a.pairs.length, GRANT_PAIRS_MAX);
  // (the controls: a cap without the envelope, or without gen's digits, refuses this answer)
  assert.ok(r.body.length > GRANT_RESULT_MAX + 2 * SIGNED_MAX, "the envelope-less cap (1,179,648) refuses it");
  assert.ok(r.body.length > GRANT_READ_BYTES - 16, "the cap without gen's digits refuses it");
  // (random rows: the formula, exactly)
  for (let i = 0; i < 40; i++) {
    const gen = 1 + Math.floor(Math.random() * 1e9);
    const grant = canonText({ s: '"\\'.repeat(Math.floor(Math.random() * 500)) + "é𝄞".repeat(Math.floor(Math.random() * 50)) });
    const pairs = pairsOfSize(200 + Math.floor(Math.random() * 5000), 1 + Math.floor(Math.random() * 5));
    const body = grantReadBody({ gen, bytes: grant, result: stored(pairs) }, null);
    assert.equal(body.length, formula(gen, grant, pairs));
  }
  // (the largest VALID answer the fixtures make: a real grant and real pairs, served and verified; its size recorded)
  const v = world();
  v.put(v.fleetA, v.hostA, 3, GRANT, OK_PAIRS);
  const rv = await v.send(v.sig());
  assert.equal(rv.status, 200);
  for (const p of parseGrantRead(rv.body).pairs) await verifyPair(p);
  assert.ok(rv.body.length < GRANT_READ_BYTES, `a valid fixture answer: ${rv.body.length} bytes`);
  // (the reader: one byte over the cap is refused before parsing)
  assert.equal(code(() => parseGrantRead(new Uint8Array(GRANT_READ_BYTES + 1))), "limit");
  // (a stored result over GRANT_RESULT_MAX: never served, even one that would fit once canonical, as with whitespace
  // the writer never stores)
  const o = world();
  o.put(o.fleetA, o.hostA, 3, GRANT, stored(pairsOfSize(GRANT_RESULT_MAX + 1)));
  assert.equal((await o.send(o.sig())).status, 500);
  const padded = stored(pairsOfSize(GRANT_RESULT_MAX - 10)).replace("[", "[" + " ".repeat(11));
  assert.equal(enc(padded).length, GRANT_RESULT_MAX + 1);
  const ow = world();
  ow.put(ow.fleetA, ow.hostA, 3, GRANT, padded);
  assert.equal((await ow.send(ow.sig())).status, 500);
});

function code(f) {
  try { f(); } catch (e) { return e.code ?? String(e); }
  return "ok";
}

test("row 11: the host's reader refuses each malformed answer", () => {
  const good = { gen: 3, grant: GRANT, pairs: OK_PAIRS.slice(0, 1).map((p) => ({ receipt: p.receipt, transfer: p.transfer })) };
  const bytes = (v) => enc(canonText(v, GRANT_READ_BYTES));
  assert.equal(code(() => parseGrantRead(bytes(good), 3)), "ok");
  assert.equal(code(() => parseGrantRead(bytes({ ...good, extra: 1 }))), "bad_form");
  assert.equal(code(() => parseGrantRead(bytes({ gen: 3, grant: GRANT }))), "bad_form");
  assert.equal(code(() => parseGrantRead(bytes(good), 2)), "bad_form", "another generation than the one requested");
  assert.equal(code(() => parseGrantRead(bytes({ ...good, gen: 0 }))), "bad_form");
  assert.equal(code(() => parseGrantRead(bytes({ ...good, grant: "" }))), "bad_form");
  assert.equal(code(() => parseGrantRead(bytes({ ...good, pairs: Array.from({ length: GRANT_PAIRS_MAX + 1 }, () => good.pairs[0]) }))), "bad_form");
  assert.equal(code(() => parseGrantRead(bytes({ ...good, pairs: [{ ...good.pairs[0], receipt: "" }] }))), "bad_form");
  assert.equal(code(() => parseGrantRead(bytes({ ...good, pairs: [{ ...good.pairs[0], x: "y" }] }))), "bad_form");
  assert.equal(code(() => parseGrantRead(enc(" " + text(bytes(good))))), "bad_form", "non-canonical");
});

test("row 12: tampering is refused by the core's verifiers; a DROPPED pair is not (withholding: it parses and verifies)", async () => {
  const [p0, p1] = OK_PAIRS;
  // (a receipt swapped onto another pair's transfer, and a byte changed in a transfer and in a receipt)
  assert.notEqual(await code2(() => verifyPair({ transfer: enc(p0.transfer), receipt: enc(p1.receipt) })), "ok");
  const flip = (s) => { const b = enc(s); b[b.length - 20] ^= 1; return b; };
  assert.notEqual(await code2(() => verifyPair({ transfer: flip(p0.transfer), receipt: enc(p0.receipt) })), "ok");
  assert.notEqual(await code2(() => verifyPair({ transfer: enc(p0.transfer), receipt: flip(p0.receipt) })), "ok");
  // (withholding: the same grant served with one pair omitted, and with []: both parse, and what's there verifies)
  for (const pairs of [[p0], []]) {
    const w = world();
    w.put(w.fleetA, w.hostA, 3, GRANT, pairs.length ? pairs : null);
    const a = parseGrantRead((await w.send(w.sig())).body);
    assert.equal(a.pairs.length, pairs.length);
    for (const p of a.pairs) await verifyPair(p);
  }
});

async function code2(f) {
  try { await f(); } catch (e) { return e.code ?? String(e); }
  return "ok";
}

test("row 13: missed generations: a pair applied at gen 2, a no-transfer gen 3: the newest has none, gen 2 has it byte-equal", async () => {
  const w = world();
  w.put(w.fleetA, w.hostA, 2, GRANT, OK_PAIRS.slice(0, 1));
  w.put(w.fleetA, w.hostA, 3, GRANT);
  assert.deepEqual(parseGrantRead((await w.send(w.sig())).body).pairs, []);
  const two = parseGrantRead((await w.send(w.sig(w.hostA, { gen: 2 }))).body, 2);
  assert.deepEqual(two.pairs.map((p) => [text(p.transfer), text(p.receipt)]), [[OK_PAIRS[0].transfer, OK_PAIRS[0].receipt]]);
  await verifyPair(two.pairs[0]);
});
