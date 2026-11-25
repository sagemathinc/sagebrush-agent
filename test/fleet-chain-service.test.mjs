// The fleet Worker's chain read (lib/fleet/core/chain-service.mjs; r2.5 §2.4, §5.1, §5.3, the chain-read note r1.2)
// against an in-memory store that follows the module's contract: the nonce's prune and insert as one decision, the
// page and its head from one snapshot. A fake can't prove the real store's atomicity: the Worker's D1 rows do. Every
// page the route serves is read by the HOST's reader (parseChainPage) and the chain replayed from the host's own pin.
import assert from "node:assert/strict";
import { test } from "node:test";
import { b64, enc, newId, keyFromSeed, seal, sha256b64, signedBytes, hostFingerprint, applyChainEntry as apply } from "../lib/fleet/index.mjs";
import { signRequest } from "../lib/fleet/request.mjs";
import { verifyExecutionLease } from "../lib/fleet/verify.mjs";
import {
  CHAIN_NONCE_KEEP_MS, CHAIN_PAGE_BYTES, CHAIN_PAGE_ENTRIES, CHAIN_RATE_HOST, CHAIN_RATE_SOURCE, CHAIN_ROUTE, chainPageBody, chainTarget, handleChainRead, parseChainPage,
  parseChainTarget,
} from "../lib/fleet/core/chain-service.mjs";
import { SIGNED_MAX } from "../lib/fleet/core/canonical.mjs";
import { LEASE_ROUTE, handleLease } from "../lib/fleet/core/lease-service.mjs";

const AUD = "https://dev.sagebrush.space";
const NOW = 1_800_000_000_000;
const SKEW = 300_000;
const text = (b) => new TextDecoder().decode(b);
let n = 1;
const key = () => keyFromSeed(new Uint8Array(32).fill(n++ & 255));
const nonce = () => b64(new Uint8Array(16).fill(n++ & 255)).slice(0, 22);
const errorOf = (r) => (r.body.length ? JSON.parse(text(r.body)).error : null);

/** A Worker's state as the handler's ctx sees it: hosts, generations, nonces and each fleet's stored entries. */
function world() {
  const fleetA = newId(), fleetB = newId(), hostA = newId(), hostB = newId(), hostC = newId();
  const keys = { [hostA]: key(), [hostB]: key(), [hostC]: key() };
  const st = {
    now: NOW,
    hosts: new Map([[hostA, { fleet: fleetA, sign_key: keys[hostA].raw, revoked: false }], [hostB, { fleet: fleetB, sign_key: keys[hostB].raw, revoked: false }],
      [hostC, { fleet: fleetA, sign_key: keys[hostC].raw, revoked: false }]]),
    gens: new Map([[hostA, 3], [hostB, 1], [hostC, 1]]),
    nonces: new Map(), entries: new Map([[fleetA, []], [fleetB, []]]), counts: new Map(),
    spends: 0, pages: 0, failSpend: false, failPage: false, page: null,
  };
  const ctx = (over = {}) => ({
    aud: AUD, get now() { return st.now; },
    host: async (h) => st.hosts.get(h) ?? null,
    currentGen: async (_f, h) => st.gens.get(h),
    bucket: async (k, limit) => { const c = (st.counts.get(k) ?? 0) + 1; st.counts.set(k, c); return c <= limit; },
    nonces: {
      // (the contract's one decision: this host's old nonces pruned, then the insert if absent)
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
    chain: {
      page: async (fleet, after, max) => {
        st.pages++;
        if (st.failPage) throw new Error("the read failed");
        if (st.page) return st.page(fleet, after, max);
        const all = st.entries.get(fleet) ?? [];
        return { head: all.length - 1, entries: all.slice(after + 1, after + 1 + max).map((bytes, i) => ({ seq: after + 1 + i, bytes })) };
      },
    },
    ...over,
  });
  /** A host's signed read: { header, target }, with any field overridden. */
  const sig = (h = hostA, { after = null, target = chainTarget(after), aud = AUD, method = "GET", gen = st.gens.get(h) ?? 1, ts = st.now, nonce: nc = nonce(), signer = keys[h], ...fields } = {}) =>
    ({ target, header: signRequest({ aud, method, target, host: h, key: signer, fields: { gen, ts, nonce: nc, ...fields } }) });
  const send = (q, c = ctx(), over = {}) => handleChainRead({ method: "GET", scheme: "https", source: "198.51.100.7", body: new Uint8Array(0), ...q, ...over }, c);
  const nothingSpent = () => assert.equal(st.spends + st.pages, 0, "no nonce spent and no page read");
  return { fleetA, fleetB, hostA, hostB, hostC, keys, st, ctx, sig, send, nothingSpent };
}

/** A device chain's author for `fleet`: entry() seals one and keeps its stored text. */
function deviceChain(fleet) {
  const N = key(), nId = newId(), rec = key();
  const sN = { kind: "device", id: nId, alg: "ed25519", key: N.key };
  const out = [];
  let prev = "";
  const entry = (seq, op, extra) => {
    const bytes = seal("sb.device-chain.v1", sN, { fleet, aud: AUD, seq, prev, op, at_ms: 1, auth_time_ms: 1, ...extra }, N);
    out.push(text(bytes));
    return bytes;
  };
  return { N, sN, out, entry, nId, rec, set prev(v) { prev = v; } };
}

async function realChain(fleet, count) {
  const c = deviceChain(fleet);
  let state = (await apply(null, c.entry(0, "genesis", { device: { id: c.nId, alg: "ed25519", key: b64(c.N.raw), name: "mac", tier: "native" }, recovery_key: { alg: "ed25519", key: b64(c.rec.raw) } }), { aud: AUD, fleet })).state;
  for (let seq = 1; seq < count; seq++) {
    c.prev = state.head;
    // (a recovery-key rotation per entry: any number of them, each a real entry the host must verify)
    state = (await apply(state, c.entry(seq, "rotate-recovery", { recovery_key: { alg: "ed25519", key: b64(key().raw) } }), { aud: AUD, fleet })).state;
  }
  return { entries: c.out, state, c };
}

/** The host's sync from `pin` (null: from genesis) to the head, page by page, verifying every entry from the pin. */
async function hostSync(w, fleet, pin, h = w.hostA) {
  let state = pin, after = pin ? pin.seq : -1, pages = 0;
  for (;;) {
    const r = await w.send(w.sig(h, { after: after < 0 ? null : after }));
    assert.equal(r.status, 200, `status ${r.status} ${text(r.body)}`);
    const p = parseChainPage(r.body, after);
    for (const e of p.entries) state = (await apply(state, e, { aud: AUD, fleet })).state;
    pages++;
    after = p.next;
    if (after >= p.head) return { state, pages, head: p.head };
  }
}

test("from genesis: the stored entries byte for byte, in order, and the host's replay reaches the store's head hash", async () => {
  const w = world();
  const { entries, state } = await realChain(w.fleetA, 5);
  w.st.entries.set(w.fleetA, entries);
  const r = await w.send(w.sig());
  assert.equal(r.status, 200);
  assert.equal(r.headers["cache-control"], "no-store");
  assert.equal(r.headers["content-type"], "application/json");
  const p = parseChainPage(r.body, -1);
  assert.deepEqual(p.entries.map(text), entries);
  assert.equal(p.head, 4);
  const synced = await hostSync(w, w.fleetA, null);
  assert.equal(synced.state.head, state.head, "the replayed head is the store's");
  assert.equal(synced.state.seq, 4);
  // (from a pin: only the entries after it)
  const r2 = await w.send(w.sig(w.hostA, { after: 2 }));
  assert.deepEqual(parseChainPage(r2.body, 2).entries.map(text), entries.slice(3));
});

test("paging: 300 entries are 256 then 44 with one head; the host's sync takes two pages", async () => {
  const w = world();
  const { entries, state } = await realChain(w.fleetA, 300);
  w.st.entries.set(w.fleetA, entries);
  const p1 = parseChainPage((await w.send(w.sig())).body, -1);
  assert.deepEqual([p1.entries.length, p1.head, p1.next], [CHAIN_PAGE_ENTRIES, 299, 255]);
  const p2 = parseChainPage((await w.send(w.sig(w.hostA, { after: 255 }))).body, 255);
  assert.deepEqual([p2.entries.length, p2.head, p2.next], [44, 299, 299]);
  const synced = await hostSync(w, w.fleetA, null);
  assert.deepEqual([synced.pages, synced.state.head], [2, state.head]);
});

test("the encoded cap: escape-heavy and multibyte entries stop the page by UTF-8 bytes, never by string length", async () => {
  const w = world();
  // (a control character is 6 bytes on the wire; é is 2 bytes and 1 UTF-16 unit; 𝄞 is 4 bytes and 2 units)
  const kinds = [["\u0001", 6], ["é", 2], ["𝄞", 4], ["a", 1]];
  for (const [ch, wire] of kinds) {
    const one = ch.repeat(Math.floor(SIGNED_MAX / enc(ch).length));
    w.st.entries.set(w.fleetA, Array.from({ length: 40 }, () => one));
    const r = await w.send(w.sig());
    assert.equal(r.status, 200, ch);
    assert.ok(r.body.length <= CHAIN_PAGE_BYTES, `${ch}: ${r.body.length} bytes`);
    const p = parseChainPage(r.body, -1);
    const per = one.length / ch.length * wire + 3; // (the entry's quotes and its comma)
    assert.equal(p.entries.length, Math.min(40, Math.floor((CHAIN_PAGE_BYTES - 24) / per)), `${ch}: the page holds what fits`);
    // (one more entry would not have fitted)
    if (p.entries.length < 40) assert.ok(r.body.length + per > CHAIN_PAGE_BYTES, ch);
  }
  // (a page of exactly CHAIN_PAGE_BYTES is served whole; one byte more and its last entry waits for the next page)
  const fixed = enc('{"entries":[],"head":16}').length;
  const sized = (extra) => {
    const room = CHAIN_PAGE_BYTES - fixed - 17 * 2 - 16 - 16 * 61676 + extra;
    return [...Array.from({ length: 16 }, () => "a".repeat(61676)), "b".repeat(room)];
  };
  w.st.entries.set(w.fleetA, sized(0));
  let full = await w.send(w.sig());
  assert.deepEqual([full.status, full.body.length, parseChainPage(full.body, -1).entries.length], [200, CHAIN_PAGE_BYTES, 17]);
  w.st.entries.set(w.fleetA, sized(1));
  full = await w.send(w.sig());
  assert.deepEqual([full.status, parseChainPage(full.body, -1).entries.length, parseChainPage(full.body, -1).head], [200, 16, 16]);
  // (a single maximal, worst-escaped entry still makes a page)
  w.st.entries.set(w.fleetA, ["\u0001".repeat(SIGNED_MAX)]);
  const r = await w.send(w.sig());
  assert.equal(r.status, 200);
  assert.equal(parseChainPage(r.body, -1).entries.length, 1);
});

test("the host's reader: exactly CHAIN_PAGE_BYTES accepted, one byte more refused; its form, head and entry bounds", () => {
  const page = (entries, head) => enc(JSON.stringify({ entries, head }));
  // (16 entries of SIGNED_MAX - 3 ASCII bytes and a last one making the page exactly the cap)
  const fill = Array.from({ length: 15 }, () => "a".repeat(SIGNED_MAX - 3));
  const used = page([...fill, ""], 15).length;
  const exact = [...fill, "b".repeat(CHAIN_PAGE_BYTES - used)];
  assert.equal(page(exact, 15).length, CHAIN_PAGE_BYTES);
  assert.equal(parseChainPage(page(exact, 15), -1).entries.length, 16);
  const over = [...fill, "b".repeat(CHAIN_PAGE_BYTES - used + 1)];
  assert.equal(page(over, 15).length, CHAIN_PAGE_BYTES + 1);
  assert.throws(() => parseChainPage(page(over, 15), -1), { code: "limit" });
  // (multibyte: the reader counts bytes, so a page of fewer characters than the cap can still be over it)
  const wide = [...fill, "é".repeat((CHAIN_PAGE_BYTES - used) / 2 + 1)];
  assert.ok(JSON.stringify({ entries: wide, head: 15 }).length < CHAIN_PAGE_BYTES);
  assert.throws(() => parseChainPage(page(wide, 15), -1), { code: "limit" });
  const bad = [
    ["not canonical", enc('{"head":0, "entries":[]}')],
    ["another field", enc('{"entries":[],"head":-1,"x":1}')],
    ["head below -1", page([], -2)],
    ["head not an integer", page([], 1.5)],
    ["an empty entry", page([""], 0)],
    ["a non-string entry", enc('{"entries":[1],"head":0}')],
    ["too many entries", page(Array.from({ length: CHAIN_PAGE_ENTRIES + 1 }, () => "a"), 300)],
    ["entries past the head", page(["a", "b"], 0)],
    ["empty below its head", page([], 5)],
  ];
  for (const [what, bytes] of bad) assert.throws(() => parseChainPage(bytes, -1), { code: "bad_form" }, what);
  assert.throws(() => parseChainPage(page(["a".repeat(SIGNED_MAX + 1)], 0), -1), { code: "limit" }, "an entry over SIGNED_MAX");
  // (a head at or below `after`, with no entries: caught up, or a shorter chain the host's pin judges)
  assert.deepEqual(parseChainPage(page([], 3), 3), { entries: [], head: 3, next: 3 });
  assert.deepEqual(parseChainPage(page([], 1), 3), { entries: [], head: 1, next: 3 });
});

test("after at or past the head, and before genesis: no entries and the true head", async () => {
  const w = world();
  w.st.entries.set(w.fleetA, ["x0", "x1", "x2"]);
  for (const [after, head] of [[2, 2], [7, 2]]) {
    const r = await w.send(w.sig(w.hostA, { after }));
    assert.deepEqual(JSON.parse(text(r.body)), { entries: [], head }, `after ${after}`);
  }
  const r = await w.send(w.sig(w.hostB));
  assert.deepEqual(JSON.parse(text(r.body)), { entries: [], head: -1 }, "a fleet with no entries yet");
});

test("fleet isolation: the fleet is the host's own pairing; another fleet's entries are never served", async () => {
  const w = world();
  w.st.entries.set(w.fleetA, ["a0", "a1", "a2"]);
  w.st.entries.set(w.fleetB, ["b0", "b1"]);
  const seen = [];
  for (const after of [null, 0, 1]) {
    seen.push(...JSON.parse(text((await w.send(w.sig(w.hostA, { after }))).body)).entries);
    seen.push(...JSON.parse(text((await w.send(w.sig(w.hostB, { after }))).body)).entries);
  }
  assert.deepEqual(seen.filter((e) => e.startsWith("a")).length + seen.filter((e) => e.startsWith("b")).length, seen.length);
  const a = JSON.parse(text((await w.send(w.sig(w.hostA))).body)).entries, b = JSON.parse(text((await w.send(w.sig(w.hostB))).body)).entries;
  assert.deepEqual([a, b], [["a0", "a1", "a2"], ["b0", "b1"]]);
  // (the store is asked for the host's fleet, whatever else the request says)
  const asked = [];
  const c = w.ctx({ chain: { page: async (f, after, max) => { asked.push(f); return { head: -1, entries: [] }; } } });
  await w.send(w.sig(w.hostB), c);
  assert.deepEqual(asked, [w.fleetB]);
});

test("the target's grammar, the body and a host read's fields: bad_form, with nothing spent", async () => {
  const w = world();
  const targets = [`${CHAIN_ROUTE}?after=01`, `${CHAIN_ROUTE}?after=-1`, `${CHAIN_ROUTE}?after=9007199254740992`, `${CHAIN_ROUTE}?after=1&after=2`,
    `${CHAIN_ROUTE}?after=1&x=1`, `${CHAIN_ROUTE}?after=`, `${CHAIN_ROUTE}?after=%31`, `${CHAIN_ROUTE}?`, `${CHAIN_ROUTE}?x=1`, `${CHAIN_ROUTE}?after=1#f`,
    `${CHAIN_ROUTE}?after=+1`, `${CHAIN_ROUTE}?after=1.0`];
  for (const target of targets) {
    const r = await w.send(w.sig(w.hostA, { target }));
    assert.deepEqual([r.status, errorOf(r)], [400, "bad_form"], target);
  }
  const fields = [{ agent: newId() }, { cap: newId() }, { idem: nonce(), op: String(NOW) }];
  for (const f of fields) {
    const r = await w.send(w.sig(w.hostA, f));
    assert.deepEqual([r.status, errorOf(r)], [400, "bad_form"], JSON.stringify(Object.keys(f)));
  }
  const withBody = await w.send(w.sig(), w.ctx(), { body: enc("{}") });
  assert.deepEqual([withBody.status, errorOf(withBody)], [400, "bad_form"], "a body");
  const noHeader = await w.send({ target: CHAIN_ROUTE, header: null });
  assert.deepEqual([noHeader.status, errorOf(noHeader)], [400, "bad_form"], "no header");
  w.nothingSpent();
  // (the grammar itself: the targets a host builds parse back; genesis is -1)
  assert.equal(parseChainTarget(CHAIN_ROUTE), -1);
  for (const a of [0, 1, 255, Number.MAX_SAFE_INTEGER]) assert.equal(parseChainTarget(chainTarget(a)), a);
  assert.throws(() => chainTarget(-1), RangeError);
});

test("authentication: the audience, the window at exactly 5 minutes, the host, its key and the signed target", async () => {
  const w = world();
  for (const d of [SKEW, -SKEW]) assert.equal((await w.send(w.sig(w.hostA, { ts: NOW + d }))).status, 200, `ts ${d}`);
  const spentBefore = w.st.spends;
  for (const d of [SKEW + 1, -SKEW - 1]) {
    const r = await w.send(w.sig(w.hostA, { ts: NOW + d }));
    assert.deepEqual([r.status, errorOf(r)], [401, "clock_skew"], `ts ${d}`);
    assert.deepEqual(JSON.parse(text(r.body)), { error: "clock_skew", service_time_ms: NOW, skew_ms: d });
  }
  const q = w.sig(w.hostA, { after: 1 });
  const cases = [
    ["another audience", w.sig(w.hostA, { aud: "https://sagebrush.space" }), "bad_signature"],
    ["an unknown host", w.sig(newId(), { signer: w.keys[w.hostA], gen: 1 }), "unknown_host"],
    ["another host's key", w.sig(w.hostA, { signer: w.keys[w.hostB] }), "bad_signature"],
    ["after changed after signing", { header: q.header, target: chainTarget(2) }, "bad_signature"],
    ["genesis signed, after sent", { header: w.sig().header, target: chainTarget(0) }, "bad_signature"],
    ["signed as POST", w.sig(w.hostA, { method: "POST" }), "bad_signature"],
  ];
  for (const [what, req, code] of cases) assert.equal(errorOf(await w.send(req)), code, what);
  w.st.hosts.get(w.hostC).revoked = true;
  assert.deepEqual(await w.send(w.sig(w.hostC)).then((r) => [r.status, errorOf(r)]), [403, "host_revoked"]);
  assert.equal(w.st.spends, spentBefore, "no refusal spends a nonce");
});

test("the generation (SEC's ruling): current or any older positive one is served; a future one is stale; zero is the header's bad_form", async () => {
  const w = world();
  for (const gen of [3, 2, 1]) assert.equal((await w.send(w.sig(w.hostA, { gen }))).status, 200, `gen ${gen}`);
  assert.equal((await w.send(w.sig(w.hostC, { gen: 1 }))).status, 200, "a host whose current generation is 1");
  const spent = w.st.spends;
  for (const gen of [4, Number.MAX_SAFE_INTEGER]) {
    const r = await w.send(w.sig(w.hostA, { gen }));
    assert.deepEqual([r.status, errorOf(r)], [409, "stale_generation"], `gen ${gen}`);
  }
  assert.deepEqual(await w.send(w.sig(w.hostC, { gen: 2 })).then(errorOf), "stale_generation");
  // (zero is refused by the header's form first, whatever else is also wrong)
  // (signRequest won't sign gen=0, so the header is rewritten after signing: its form is refused before its signature)
  const zeroed = (q) => ({ ...q, header: q.header.replace(/; gen=[0-9]+;/, "; gen=0;") });
  const zero = (over, h = w.hostA) => w.send(zeroed(w.sig(h, { gen: 1, ...over }))).then((r) => [r.status, errorOf(r)]);
  assert.deepEqual(await zero({}), [400, "bad_form"]);
  assert.deepEqual(await zero({ aud: "https://sagebrush.space" }), [400, "bad_form"]);
  assert.deepEqual(await zero({ ts: NOW + SKEW + 1 }), [400, "bad_form"]);
  assert.deepEqual(await zero({ signer: w.keys[w.hostA] }, newId()), [400, "bad_form"], "an unknown host");
  assert.equal(w.st.spends, spent, "neither spends a nonce");
  // (a store with no current generation for the host serves nothing)
  w.st.gens.delete(w.hostC);
  assert.equal(await w.send(w.sig(w.hostC, { gen: 1 })).then(errorOf), "stale_generation");
});

test("the nonce: a repeat is replay with nothing served; at the prune's edge it is still replay, then the window refuses it", async () => {
  const w = world();
  w.st.entries.set(w.fleetA, ["x0"]);
  const q = w.sig();
  assert.equal((await w.send(q)).status, 200);
  const pages = w.st.pages;
  const again = await w.send(q);
  assert.deepEqual([again.status, errorOf(again)], [409, "replay"]);
  assert.equal(w.st.pages, pages, "nothing served");
  // (two hosts may share a nonce: the key includes the host)
  const nc = nonce();
  assert.equal((await w.send(w.sig(w.hostA, { nonce: nc }))).status, 200);
  assert.equal((await w.send(w.sig(w.hostC, { nonce: nc }))).status, 200);
  // (the edge: a request at the furthest accepted future ts, spent at NOW, replayed 600,000 then 600,001 ms later)
  const edge = w.sig(w.hostA, { ts: NOW + SKEW });
  assert.equal((await w.send(edge)).status, 200);
  w.st.now = NOW + CHAIN_NONCE_KEEP_MS;
  assert.deepEqual(await w.send(edge).then((r) => [r.status, errorOf(r)]), [409, "replay"], "kept at equality");
  w.st.now = NOW + CHAIN_NONCE_KEEP_MS + 1;
  assert.deepEqual(await w.send(edge).then((r) => [r.status, errorOf(r)]), [401, "clock_skew"], "pruned, and outside the window");
  // (identical requests at once: exactly one is served)
  w.st.now = NOW;
  const race = w.sig();
  const rs = await Promise.all([w.send(race), w.send(race), w.send(race)]);
  assert.deepEqual(rs.map((r) => r.status).sort(), [200, 409, 409]);
});

test("rate limits: per source before authentication, per host after it; an unauthenticated flood never spends a host's budget", async () => {
  const w = world();
  for (let i = 0; i < CHAIN_RATE_HOST.limit; i++) assert.equal((await w.send(w.sig())).status, 200, `request ${i + 1}`);
  const spends = w.st.spends, pages = w.st.pages;
  const r = await w.send(w.sig());
  assert.equal(r.status, 429);
  assert.deepEqual(JSON.parse(text(r.body)), { error: "rate", retry_after_s: CHAIN_RATE_HOST.windowMs / 1000 }, "the host's branch carries retry_after_s");
  assert.ok(Number.isSafeInteger(JSON.parse(text(r.body)).retry_after_s) && JSON.parse(text(r.body)).retry_after_s > 0);
  assert.deepEqual([w.st.spends, w.st.pages], [spends, pages], "no nonce spent and no page read");
  const w2 = world();
  for (let i = 0; i < 20; i++) await w2.send(w2.sig(w2.hostA, { signer: w2.keys[w2.hostB] }));
  assert.equal(w2.st.counts.get(`chain-host:${w2.hostA}`) ?? 0, 0, "forged requests never reach the host's bucket");
  w2.st.counts.set("chain-src:198.51.100.7", CHAIN_RATE_SOURCE.limit);
  const s = await w2.send(w2.sig());
  assert.equal(s.status, 429);
  assert.deepEqual(JSON.parse(text(s.body)), { error: "rate", retry_after_s: CHAIN_RATE_SOURCE.windowMs / 1000 }, "the source's branch carries retry_after_s");
  assert.ok(Number.isSafeInteger(JSON.parse(text(s.body)).retry_after_s) && JSON.parse(text(s.body)).retry_after_s > 0);
  assert.equal(w2.st.spends + w2.st.pages, 0, "no nonce spent and no page read");
});

test("store faults: a gap, a page past its head or a page that can't fit is 500; a failed nonce or page read is 503; nothing served", async () => {
  const w = world();
  const faults = [
    ["a gap", (f, after) => ({ head: 5, entries: [{ seq: after + 1, bytes: "a" }, { seq: after + 3, bytes: "c" }] })],
    ["starts late", (f, after) => ({ head: 5, entries: [{ seq: after + 2, bytes: "b" }] })],
    ["past its head", () => ({ head: 0, entries: [{ seq: 0, bytes: "a" }, { seq: 1, bytes: "b" }] })],
    ["empty below its head", () => ({ head: 5, entries: [] })],
    ["an empty entry", () => ({ head: 0, entries: [{ seq: 0, bytes: "" }] })],
    ["an entry that can't fit", () => ({ head: 0, entries: [{ seq: 0, bytes: "\u0001".repeat(CHAIN_PAGE_BYTES / 4) }] })],
    ["no head", () => ({ entries: [] })],
    ["too many rows", (f, after) => ({ head: 999, entries: Array.from({ length: CHAIN_PAGE_ENTRIES + 1 }, (_, i) => ({ seq: after + 1 + i, bytes: "a" })) })],
  ];
  for (const [what, page] of faults) {
    w.st.page = page;
    const r = await w.send(w.sig());
    assert.deepEqual([r.status, r.body.length], [500, 0], what);
  }
  w.st.page = null;
  w.st.failPage = true;
  assert.equal((await w.send(w.sig())).status, 503);
  w.st.failPage = false;
  w.st.failSpend = true;
  const pages = w.st.pages;
  assert.equal((await w.send(w.sig())).status, 503);
  assert.equal(w.st.pages, pages, "no page read without a spent nonce");
});

test("the order: the audience and the window are checked on the one clock sample before the host's authority is read", async () => {
  const w = world();
  const calls = [];
  const watched = (over = {}) => w.ctx({
    host: async (h) => { calls.push("host"); return w.st.hosts.get(h) ?? null; },
    currentGen: async (_f, h) => { calls.push("currentGen"); return w.st.gens.get(h); },
    ...over,
  });
  const throwing = { currentGen: async () => { calls.push("currentGen"); throw new Error("the store failed"); }, host: async () => { calls.push("host"); throw new Error("the store failed"); } };
  for (const d of [SKEW + 1, -SKEW - 1]) {
    calls.length = 0;
    const r = await w.send(w.sig(w.hostA, { ts: NOW + d }), watched(throwing));
    assert.deepEqual([r.status, errorOf(r), calls], [401, "clock_skew", []], `ts ${d}: refused before any authority read, whatever the store would do`);
  }
  calls.length = 0;
  const aud = await w.send(w.sig(), watched({ ...throwing, aud: "https://elsewhere.example" }));
  assert.deepEqual([aud.status, errorOf(aud), calls], [401, "bad_audience", []], "a service audience that isn't ours");
  // (in the window, the reads happen in order; a store fault is a bare 500 with nothing spent, never a refusal)
  calls.length = 0;
  assert.equal((await w.send(w.sig(), watched())).status, 200);
  assert.deepEqual(calls, ["host", "currentGen"]);
  const spends = w.st.spends;
  for (const over of [{ host: throwing.host }, { currentGen: throwing.currentGen }]) {
    const r = await w.send(w.sig(), watched(over));
    assert.deepEqual([r.status, r.body.length], [500, 0]);
  }
  assert.equal(w.st.spends, spends, "a store fault spends no nonce");
});

test("a stored entry over SIGNED_MAX UTF-8 bytes is a store fault: 500 with nothing served, at the exact boundary", async () => {
  const w = world();
  const cases = [
    ["ASCII", "a".repeat(SIGNED_MAX), "a".repeat(SIGNED_MAX + 1)],
    ["two-byte", "é".repeat(SIGNED_MAX / 2), "é".repeat(SIGNED_MAX / 2) + "a"],
    ["four-byte", "𝄞".repeat(SIGNED_MAX / 4), "𝄞".repeat(SIGNED_MAX / 4) + "a"],
  ];
  for (const [what, fits, over] of cases) {
    assert.deepEqual([enc(fits).length, enc(over).length], [SIGNED_MAX, SIGNED_MAX + 1], what);
    w.st.entries.set(w.fleetA, [fits]);
    const r = await w.send(w.sig());
    assert.equal(r.status, 200, `${what}: exactly SIGNED_MAX is served`);
    assert.equal(text(parseChainPage(r.body, -1).entries[0]), fits);
    for (const entries of [[over], [fits, over]]) {
      w.st.entries.set(w.fleetA, entries);
      const bad = await w.send(w.sig());
      assert.deepEqual([bad.status, bad.body.length], [500, 0], `${what}: one byte over, entry ${entries.length}`);
    }
  }
});

test("transport: another route, method or scheme is refused before anything is read or written", async () => {
  const w = world();
  assert.equal((await w.send(w.sig(), w.ctx(), { target: "/api/fleet/v1/host/chains" })).status, 404);
  assert.equal((await w.send(w.sig(), w.ctx(), { target: LEASE_ROUTE })).status, 404);
  for (const method of ["POST", "PUT", "HEAD"]) assert.equal((await w.send(w.sig(w.hostA, { method }), w.ctx(), { method })).status, 405, method);
  assert.equal((await w.send(w.sig(), w.ctx(), { scheme: "http" })).status, 403);
  assert.equal(w.st.counts.size, 0, "no bucket");
  w.nothingSpent();
});

test("with the lease route: a lease past the host's pin is device_unknown; after the sync a NEW request's lease verifies", async () => {
  const w = world();
  const fleet = w.fleetA;
  // (the fleet's chain: genesis, then the lease key; the host is pinned at genesis)
  const c = deviceChain(fleet);
  const g = await apply(null, c.entry(0, "genesis", { device: { id: c.nId, alg: "ed25519", key: b64(c.N.raw), name: "mac", tier: "native" }, recovery_key: { alg: "ed25519", key: b64(c.rec.raw) } }), { aud: AUD, fleet });
  const pin = g.state;
  c.prev = pin.head;
  const L = key(), lId = newId();
  const full = (await apply(pin, c.entry(1, "lease-key", { lease_key: { id: lId, alg: "ed25519", key: b64(L.raw) } }), { aud: AUD, fleet })).state;
  w.st.entries.set(fleet, c.out);
  const H = w.keys[w.hostA], encRaw = new Uint8Array(32).fill(7), agent = newId();
  const fingerprint = b64(await hostFingerprint(w.hostA, H.raw, encRaw));
  const spent = new Set();
  const lctx = {
    aud: AUD, get now() { return w.st.now; },
    host: async (h) => (h === w.hostA ? { fleet, sign_key: H.raw, fingerprint, revoked: false } : null),
    chain: async () => full,
    leaseKey: { id: lId, raw: L.raw, sign: (b) => L.sign(b) },
    bucket: async () => true,
    leases: { issue: async (d) => (spent.has(d.nonce) ? { refused: "replay" } : (spent.add(d.nonce), { ok: true })) },
  };
  const hs = { kind: "host", id: w.hostA, alg: "ed25519", key: H.key };
  const ask = async () => {
    const body = { fleet, aud: AUD, agent, host: w.hostA, gen: 1, nonce: nonce(), boot_id: "0f6c2b5e-8d3a-4c1e-9b7f-2a4d6e8f0a1c", at_ms: w.st.now };
    const outstanding = { request: sha256b64(signedBytes("sb.lease-request.v1", hs, body)), agent, gen: 1, nonce: body.nonce, boot_id: body.boot_id };
    const r = await handleLease({ method: "POST", target: LEASE_ROUTE, scheme: "https", source: "198.51.100.7", body: seal("sb.lease-request.v1", hs, body, H) }, lctx);
    assert.equal(r.status, 200, text(r.body));
    return { bytes: r.body, outstanding };
  };
  const check = (q, chain) => verifyExecutionLease(q.bytes, { aud: AUD, fleet, chain, host: w.hostA, hostKey: fingerprint, outstanding: q.outstanding });
  const first = await ask();
  await assert.rejects(check(first, pin), { code: "device_unknown" });
  // (the chain sync, through this route, from the host's own pin)
  const synced = await hostSync(w, fleet, pin);
  assert.equal(synced.state.head, full.head);
  // (the host refused the first lease and asks again: a NEW outstanding request, whose lease verifies)
  const second = await ask();
  assert.notEqual(second.outstanding.nonce, first.outstanding.nonce);
  const v = await check(second, synced.state);
  assert.equal(v.body.chain_seq, 1);
});

test("chainPageBody is the route's own encoder: byte-identical to the handler's 200 body, and the same store faults", async () => {
  const w = world();
  const { entries } = await realChain(w.fleetA, 20);
  w.st.entries.set(w.fleetA, entries);
  for (const after of [-1, 0, 7, 19, 25]) {
    const r = await w.send(w.sig(w.hostA, { after: after < 0 ? null : after }));
    const page = { head: entries.length - 1, entries: entries.slice(after + 1, after + 1 + CHAIN_PAGE_ENTRIES).map((bytes, i) => ({ seq: after + 1 + i, bytes })) };
    assert.deepEqual(chainPageBody(page, after), r.body, `after ${after}`);
  }
  assert.throws(() => chainPageBody({ head: 5, entries: [{ seq: 0, bytes: "a" }, { seq: 2, bytes: "c" }] }, -1));
  assert.throws(() => chainPageBody({ head: 0, entries: [{ seq: 0, bytes: "a".repeat(SIGNED_MAX + 1) }] }, -1));
  assert.throws(() => chainPageBody({ head: 5, entries: [] }, -1));
});
