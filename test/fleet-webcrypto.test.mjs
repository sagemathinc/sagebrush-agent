// The fleet core with the WebCrypto backend (lib/fleet/core/webcrypto.mjs, what a page, a Worker or the app's web view
// installs), on Node's globalThis.crypto: every shared vector, the backend installed once, and keys, hashes and
// derivations that agree with Node's backend byte for byte. This file loads only the pure core, never lib/fleet's Node
// entry, so nothing here runs on node:crypto's code path. fleet-webcrypto-browser.test.mjs runs the same cases in
// Chromium.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { checkFixtures, checkHpkeFixtures, checkHpkeVector } from "./fleet-fixture-cases.mjs";
import { CONTEXTS, LENGTHS, checkExportOracle } from "./hpke-export-oracle.mjs";
import * as core from "../lib/fleet/core/index.mjs";

const read = (f) => JSON.parse(readFileSync(new URL(f, import.meta.url), "utf8"));
const F = read("./fixtures/fleet-fixtures.json");
const RECOVERY_KNOWN = ["QIgcRL3kWMdpVNtbHP7lkw", "8f8Zi-ibteyHFwp-PnAVfGC6-_75Je6BNI9mNkG6PM0"];
// (the installed backend is WebCrypto's, watched: the recovery rows see the HKDF output and can refuse the key import)
const real = core.webCrypto();
const spy = { hkdf: [], refuseImport: false, zeroDh: false, holdAead: false, held: [] };
const hold = () => (spy.holdAead ? new Promise((release) => spy.held.push(release)) : null);
const zeroable = (pair) => ({ raw: pair.raw, dh: async (peer) => (spy.zeroDh ? new Uint8Array(32) : pair.dh(peer)) });
const backend = {
  ...real,
  async hkdf(...args) { const out = await real.hkdf(...args); spy.hkdf.push(out); return out; },
  async ed25519FromSeed(seed) { if (spy.refuseImport) throw new Error("import refused"); return real.ed25519FromSeed(seed); },
  x25519FromPrivate: async (sk) => zeroable(await real.x25519FromPrivate(sk)),
  async aes256gcmSeal(...args) {
    await hold();
    if (spy.failSeal) { spy.failSeal = false; throw new Error("seal failed"); }
    return real.aes256gcmSeal(...args);
  },
  async aes256gcmOpen(...args) { await hold(); return real.aes256gcmOpen(...args); },
  x25519Generate: async () => zeroable(await real.x25519Generate()),
};
const loader = (name) => read(`../schema/fleet/${name}`);

// (first: the tests after it use what it installs)
test("schemas of another revision are refused and install nothing; then the backend and the frozen schemas install", () => {
  const other = (n) => (n === "reasons.json" ? { ...loader(n), freeze: "0".repeat(64) } : loader(n));
  assert.throws(() => core.useSchemas(other), /frozen revision/);
  const otherSchema = (n) => (n === "fleet.schema.json" ? { ...loader(n), $comment: "r2.2" } : loader(n));
  assert.throws(() => core.useSchemas(otherSchema), /frozen revision/);
  assert.throws(() => core.bodyValidator("host-grant"), /no fleet schemas/);
  assert.throws(() => core.newId(), /no fleet crypto backend/);
  core.useCrypto(backend);
  core.useSchemas(loader);
  // the installed schema can't be changed through what fleetSchema() hands out, before or after the first compile
  const doc = core.fleetSchema();
  assert.throws(() => { doc.$defs["host-grant"] = {}; }, TypeError);
  assert.throws(() => { doc.$defs["host-grant"].required = []; }, TypeError);
  assert.throws(() => { delete doc.$defs["host-grant"].additionalProperties; }, TypeError);
  assert.throws(() => { core.reasonNames().push("x"); }, TypeError);
  assert.throws(() => core.bodyValidator("host-grant")({}), (e) => e.code === "bad_form");
});

test("every case, through the core with the WebCrypto backend", async () => {
  const { bad, n } = await checkFixtures(core, F);
  assert.deepEqual(bad, []);
  assert.ok(n > 80, `${n} cases`);
});

test("HPKE with the WebCrypto backend: the RFC 9180 vector, and every fleet sealed-package and mint case", async () => {
  const v = await checkHpkeVector(core, read("./fixtures/hpke-x25519-sha256-aes256gcm.json").vector);
  assert.deepEqual(v.bad, []);
  assert.equal(v.n, 260);
  const f = await checkHpkeFixtures(core, read("./fixtures/fleet-hpke-fixtures.json"));
  assert.deepEqual(f.bad, []);
  assert.ok(f.n > 25, `${f.n} cases`);
});

test("HPKE export with the WebCrypto backend, every block of long outputs, against an independent HKDF-Expand", async () => {
  const { bad, n } = await checkExportOracle(core, read("./fixtures/hpke-x25519-sha256-aes256gcm.json").vector);
  assert.deepEqual(bad, []);
  assert.equal(n, LENGTHS.length * CONTEXTS.length * 4);
});

test("one operation in flight per HPKE context: while the backend holds a seal or open, another is refused at once and the nonce is never reused", async () => {
  const V = read("./fixtures/hpke-x25519-sha256-aes256gcm.json").vector;
  const hex = (h) => Uint8Array.from(Buffer.from(h, "hex")), toHex = (b) => Buffer.from(b).toString("hex");
  const R = await core.deriveKeyPair(hex(V.ikmR));
  const tick = () => new Promise((r) => setTimeout(r, 5));
  const within = (p, ms) => { let t; return Promise.race([p, new Promise((_, no) => { t = setTimeout(() => no(new Error(`no answer within ${ms} ms`)), ms); })]).finally(() => clearTimeout(t)); };
  const [e0, e1] = V.encryptions;
  for (const side of ["seal", "open"]) {
    const ctx = side === "seal" ? await core.setupSender(R.raw, hex(V.info), await core.deriveKeyPair(hex(V.ikmE))) : await core.setupRecipient(R, hex(V.enc), hex(V.info));
    const call = (e) => (side === "seal" ? ctx.seal(hex(e.aad), hex(e.pt)) : ctx.open(hex(e.aad), hex(e.ct)));
    const want = (e) => (side === "seal" ? e.ct : e.pt);
    spy.holdAead = true;
    try {
      const first = call(e0);
      await tick();
      assert.equal(spy.held.length, 1, `${side}: the first is at the backend, held`);
      // (started, not awaited: if they reached the backend they would wait on the hold, so count first, then await
      // their refusals against a short deadline; nothing here can wait on the suite's timeout)
      const overlapping = [call(e1), call(e0)];
      for (const p of overlapping) p.catch(() => {});
      await tick();
      assert.equal(spy.held.length, 1, `${side}: the overlapping calls never reached the backend`);
      for (const p of overlapping) await assert.rejects(within(p, 1000), (x) => x.code === "in_progress", `${side}: refused at once while the first is pending`);
      spy.held[0]();
      assert.equal(toHex(await first), want(e0), `${side}: the first completes with seq 0`);
      spy.holdAead = false;
      assert.equal(toHex(await call(e1)), want(e1), `${side}: the next call takes seq 1`);
      if (side === "seal") {
        // a seal the backend fails doesn't advance the sequence: the next seal takes the same one (RFC 9180 §5.2)
        const ctx2 = await core.setupSender(R.raw, hex(V.info), await core.deriveKeyPair(hex(V.ikmE)));
        spy.failSeal = true;
        await assert.rejects(ctx2.seal(hex(e0.aad), hex(e0.pt)), /seal failed/);
        assert.equal(toHex(await ctx2.seal(hex(e0.aad), hex(e0.pt))), e0.ct, "seq 0 again");
      }
    } finally {
      spy.holdAead = false;
      for (const release of spy.held.splice(0)) release();
    }
  }
});

test("a backend whose X25519 gives an all-zero secret is refused by the core itself, sending and receiving", async () => {
  const R = await core.deriveKeyPair(new Uint8Array(32).fill(1));
  const { enc: e, ct } = await core.hpkeSeal(R.raw, new Uint8Array(0), new Uint8Array(0), new Uint8Array([1]));
  spy.zeroDh = true;
  try {
    await assert.rejects(core.hpkeSeal(R.raw, new Uint8Array(0), new Uint8Array(0), new Uint8Array([1])), (x) => x.code === "bad_form");
    await assert.rejects(core.hpkeOpen(R, e, new Uint8Array(0), new Uint8Array(0), ct), (x) => x.code === "bad_form");
  } finally {
    spy.zeroDh = false;
  }
  assert.deepEqual(await core.hpkeOpen(R, e, new Uint8Array(0), new Uint8Array(0), ct), new Uint8Array([1]));
});

test("one backend and one schema set per process: the same again is a no-op, any other is refused", () => {
  core.useCrypto(backend);
  core.useSchemas(loader);
  assert.throws(() => core.useCrypto(core.webCrypto()), /already installed/);
  assert.throws(() => core.useSchemas((n) => loader(n)), /already installed/);
});

test("keys, ids, recovery and sealing: the fixtures' known answers", async () => {
  // RFC 8032 test 1: the seed, its public key and its signature of the empty message
  const hex = (h) => Uint8Array.from(h.match(/../g), (x) => parseInt(x, 16));
  const k = await core.keyFromSeed(hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"));
  assert.equal(core.b64(k.raw), core.b64(hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")));
  const sig = await k.sign(new Uint8Array(0));
  assert.equal(core.b64(sig), core.b64(hex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")));
  assert.equal(await core.verifyStrict(k.raw, new Uint8Array(0), sig), true);
  // the recovery key a fixed code derives for the fixtures' fleet (HKDF-SHA256): fleet-chain.test.mjs pins the same
  // answer for Node's backend
  const fleet = F.ids.fleet, code = core.idOfBytes(new Uint8Array(16).fill(7));
  const rk = await core.recoveryKey(code, fleet);
  assert.deepEqual([rk.key, core.b64(rk.raw)], RECOVERY_KNOWN);
  // a sealed envelope opens; a byte changed in its signature doesn't
  const signer = { kind: "device", id: core.newId(), alg: "ed25519", key: k.key };
  const bytes = await core.seal("sb.revocation.v1", signer, { fleet, aud: F.aud, chain_seq: 0, what: "host", id: fleet, host: fleet, gen: 1, at_ms: 1 }, k);
  const opened = await core.open(bytes, { aud: F.aud, fleet, resolveKey: async () => k.raw });
  assert.equal(opened.body.gen, 1);
  const env = JSON.parse(new TextDecoder().decode(bytes));
  const flipped = core.unb64(env.sig, 64); flipped[5] ^= 1;
  const forged = new TextEncoder().encode(core.canonText({ ...env, sig: core.b64(flipped) }));
  await assert.rejects(core.open(forged, { aud: F.aud, fleet, resolveKey: () => k.raw }), (e) => e.code === "bad_signature");
});

test("the WebCrypto backend's verify is a boolean: false for bytes it can't use, never a throw", async () => {
  const k = await core.keyFromSeed(new Uint8Array(32).fill(5)), msg = new Uint8Array([1]), sig = await k.sign(msg);
  const offCurve = new Uint8Array(32); offCurve[0] = 2; // (y = 2 has no x on the curve: the strict rules pass it)
  assert.equal(core.strictShape(offCurve, sig), true);
  assert.equal(await core.verifyStrict(offCurve, msg, sig), false);
  for (const [raw, s] of [[k.raw.subarray(0, 31), sig], [k.raw, sig.subarray(0, 63)], [new Uint8Array(0), new Uint8Array(0)], [offCurve, sig]])
    assert.equal(await backend.ed25519Verify(raw, msg, s), false);
  assert.equal(await backend.ed25519Verify(k.raw, msg, sig), true);
});

// (RFC 8032 §7.1's Ed25519 vectors, TEST 1, 2, 3 and SHA(abc): secret key, public key; SHA(abc)'s public key is the one
//  whose x sign bit is 1, so the probe's first guess is wrong and both branches run)
const RFC8032 = [
  ["9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"],
  ["4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb", "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"],
  ["c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7", "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"],
  ["833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42", "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf"],
];
// (RFC 7748 §6.1: Alice's and Bob's private keys, their public keys, and the shared secret)
const RFC7748 = [
  ["77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"],
  ["5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb", "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"],
];
const RFC7748_SHARED = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";
const hex = (h) => Uint8Array.from(Buffer.from(h, "hex"));
const toHex = (b) => Buffer.from(b).toString("hex");
// (WebCrypto watched: every buffer it was handed to import, with the algorithm and the extractable flag asked for, every
// digest it returned, every export and its format)
function watched() {
  const s = globalThis.crypto.subtle, seen = { imports: [], digests: [], exports: [] };
  const subtle = {
    importKey: (fmt, data, alg, extractable, ...rest) => {
      seen.imports.push({ fmt, data, alg: typeof alg === "string" ? alg : alg.name, extractable });
      return s.importKey(fmt, data, alg, extractable, ...rest);
    },
    async digest(alg, data) { const ab = await s.digest(alg, data); seen.digests.push(ab); return ab; },
    exportKey: (fmt, key) => { seen.exports.push(fmt); return s.exportKey(fmt, key); },
    deriveBits: (...a) => s.deriveBits(...a), sign: (...a) => s.sign(...a), verify: (...a) => s.verify(...a),
    encrypt: (...a) => s.encrypt(...a), decrypt: (...a) => s.decrypt(...a), generateKey: (...a) => s.generateKey(...a),
  };
  return { w: core.webCrypto({ subtle, getRandomValues: (b) => globalThis.crypto.getRandomValues(b) }), seen };
}

test("ed25519FromSeed: RFC 8032's public keys, derived without exporting any key; the key signs RFC 8032 TEST 1", async () => {
  for (const [sk, pk] of RFC8032) {
    const { w, seen } = watched();
    const k = await w.ed25519FromSeed(hex(sk));
    assert.equal(toHex(k.raw), pk, sk);
    assert.deepEqual(seen.exports, [], `${sk}: nothing exported, in any format`);
  }
  const k1 = await watched().w.ed25519FromSeed(hex(RFC8032[0][0]));
  assert.equal(toHex(await k1.sign(new Uint8Array(0))), "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
});

test("ed25519FromSeed: the sign bit is chosen by verifying, both ways (a key with x's sign bit 1, and three with 0)", async () => {
  const bits = RFC8032.map(([, pk]) => hex(pk)[31] >> 7);
  assert.deepEqual(bits, [0, 0, 0, 1], "the vectors cover both signs");
  for (const [sk, pk] of RFC8032) assert.equal(toHex((await core.webCrypto().ed25519FromSeed(hex(sk))).raw), pk);
});

test("x25519FromPrivate: RFC 7748's public keys, derived without exporting any key, and the shared secret", async () => {
  const pairs = [];
  for (const [sk, pk] of RFC7748) {
    const { w, seen } = watched();
    const p = await w.x25519FromPrivate(hex(sk));
    assert.equal(toHex(p.raw), pk, sk);
    assert.deepEqual(seen.exports, [], `${sk}: nothing exported, in any format`);
    pairs.push(p);
  }
  assert.equal(toHex(await pairs[0].dh(pairs[1].raw)), RFC7748_SHARED);
  assert.equal(toHex(await pairs[1].dh(pairs[0].raw)), RFC7748_SHARED);
});

test("ed25519FromSeed and x25519FromPrivate zero every copy of the secret they made, and leave the caller's", async () => {
  const seed = hex(RFC8032[0][0]), keep = toHex(seed);
  const e = watched();
  await e.w.ed25519FromSeed(seed);
  const secrets = e.seen.imports.filter((i) => i.fmt === "pkcs8");
  assert.equal(secrets.length, 2, "the Ed25519 key and the X25519 scalar, each imported once");
  assert.ok(secrets.every((i) => i.data.every((x) => x === 0)), "both PKCS#8 copies zeroed");
  assert.equal(e.seen.digests.length, 1);
  assert.ok(new Uint8Array(e.seen.digests[0]).every((x) => x === 0), "the SHA-512 of the seed zeroed");
  assert.equal(toHex(seed), keep, "the caller's seed is the caller's");
  const sk = hex(RFC7748[0][0]), keepSk = toHex(sk);
  const x = watched();
  await x.w.x25519FromPrivate(sk);
  const xs = x.seen.imports.filter((i) => i.fmt === "pkcs8");
  assert.ok(xs.length === 1 && xs[0].data.every((b) => b === 0), "the X25519 PKCS#8 copy zeroed");
  assert.equal(toHex(sk), keepSk, "the caller's private key is the caller's");
});

test("ed25519FromSeed and x25519FromPrivate import every private key non-extractable: no exportKey could ever take one out", async () => {
  const e = watched();
  await e.w.ed25519FromSeed(hex(RFC8032[0][0]));
  const x = watched();
  await x.w.x25519FromPrivate(hex(RFC7748[0][0]));
  const secrets = [...e.seen.imports, ...x.seen.imports].filter((i) => i.fmt === "pkcs8");
  assert.deepEqual(secrets.map((i) => i.alg), ["Ed25519", "X25519", "X25519"], "the signing key, the derived scalar's key, the X25519 key");
  for (const i of secrets) assert.equal(i.extractable, false, `${i.alg} pkcs8 imported with extractable=${i.extractable}`);
});

// (a WebCrypto that fails at one named step and records every buffer it was handed and every digest it returned)
function failing(failAt) {
  const s = globalThis.crypto.subtle, imports = [], digests = [];
  const subtle = {
    async digest(alg, data) { if (failAt === "digest") throw new Error(failAt); const ab = await s.digest(alg, data); digests.push(ab); return ab; },
    async importKey(fmt, data, alg, ...rest) {
      imports.push({ fmt, data });
      if (fmt === "pkcs8" && alg.name === "Ed25519" && failAt === "ed25519 import") throw new Error(failAt);
      if (fmt === "pkcs8" && alg.name === "X25519" && failAt === "x25519 import") throw new Error(failAt);
      if (fmt === "raw" && alg.name === "X25519" && failAt === "base point import") throw new Error(failAt);
      return s.importKey(fmt, data, alg, ...rest);
    },
    async deriveBits(...a) { if (failAt === "deriveBits") throw new Error(failAt); return s.deriveBits(...a); },
    sign: (...a) => s.sign(...a), verify: (...a) => s.verify(...a), exportKey: (...a) => s.exportKey(...a),
  };
  return { w: core.webCrypto({ subtle, getRandomValues: (b) => b }), imports, digests };
}

test("ed25519FromSeed clears every copy it made when any step fails (and leaves the caller's seed)", async () => {
  for (const failAt of ["ed25519 import", "digest", "x25519 import", "base point import", "deriveBits"]) {
    const { w, imports, digests } = failing(failAt);
    const seed = new Uint8Array(32).fill(7);
    await assert.rejects(w.ed25519FromSeed(seed), new RegExp(failAt));
    const pk = imports.filter((i) => i.fmt === "pkcs8");
    // (each secret copy made is handed to its import at once, so each one made is seen here)
    assert.ok(pk.length >= 1 && pk.every((i) => i.data.length === 48 && i.data.every((x) => x === 0)), `${failAt}: every PKCS#8 copy is cleared`);
    assert.ok(digests.every((ab) => new Uint8Array(ab).every((x) => x === 0)), `${failAt}: the seed's hash is cleared`);
    assert.ok(seed.every((x) => x === 7), `${failAt}: the caller's seed is the caller's`);
  }
});

test("x25519FromPrivate clears its copy when its import or the base-point multiplication fails (and leaves the caller's key)", async () => {
  for (const failAt of ["x25519 import", "base point import", "deriveBits"]) {
    const { w, imports } = failing(failAt);
    const sk = new Uint8Array(32).fill(5);
    await assert.rejects(w.x25519FromPrivate(sk), new RegExp(failAt));
    const pk = imports.filter((i) => i.fmt === "pkcs8");
    assert.ok(pk.length === 1 && pk[0].data.every((x) => x === 0), `${failAt}: the PKCS#8 copy is cleared`);
    assert.ok(sk.every((x) => x === 5), `${failAt}: the caller's key is the caller's`);
  }
});

test("ed25519FromSeed takes the key only from an encoding that verifies ALONE: both verifying goes to a second probe", async () => {
  // (a WebCrypto whose verify says yes to both encodings for the first probe only: the second decides, and the key
  //  is still RFC 8032's)
  const s = globalThis.crypto.subtle, probe1 = new TextEncoder().encode("sagebrush.fleet.public-key-probe.v1");
  const same = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
  let lied = 0;
  const subtle = {
    digest: (...a) => s.digest(...a), importKey: (...a) => s.importKey(...a), deriveBits: (...a) => s.deriveBits(...a), sign: (...a) => s.sign(...a), exportKey: (...a) => s.exportKey(...a),
    async verify(alg, key, sig, msg) { if (same(new Uint8Array(msg), probe1)) { lied++; return true; } return s.verify(alg, key, sig, msg); },
  };
  const w = core.webCrypto({ subtle, getRandomValues: (b) => b });
  for (const [sk, pk] of RFC8032) assert.equal(toHex((await w.ed25519FromSeed(hex(sk))).raw), pk, sk);
  assert.ok(lied >= 8, "the first probe was ambiguous each time");
  // (and one where no encoding ever verifies alone: refused, never a guess)
  const never = core.webCrypto({ subtle: { ...subtle, verify: async () => true }, getRandomValues: (b) => b });
  await assert.rejects(never.ed25519FromSeed(hex(RFC8032[0][0])), /no public key/);
});

test("recoveryKey clears the seed HKDF derived, when the key is made and when its import is refused", async () => {
  const code = core.idOfBytes(new Uint8Array(16).fill(7));
  spy.hkdf.length = 0;
  const k = await core.recoveryKey(code, F.ids.fleet);
  assert.equal(spy.hkdf.length, 1);
  assert.ok(spy.hkdf[0].every((x) => x === 0), "cleared after success");
  assert.deepEqual([k.key, core.b64(k.raw)], RECOVERY_KNOWN, "and the key still is the code's");
  assert.equal(await core.verifyStrict(k.raw, new Uint8Array(1), await k.sign(new Uint8Array(1))), true, "and still signs");
  spy.refuseImport = true;
  try {
    await assert.rejects(core.recoveryKey(code, F.ids.fleet), /import refused/);
  } finally {
    spy.refuseImport = false;
  }
  assert.equal(spy.hkdf.length, 2);
  assert.ok(spy.hkdf[1].every((x) => x === 0), "cleared after a refused import");
});

test("random bytes and SHA-256: the sizes asked for, and a known hash", async () => {
  assert.equal(core.random(16).length, 16);
  assert.equal((await core.sha256(new Uint8Array(0))).length, 32);
  assert.equal(await core.sha256b64(new TextEncoder().encode("abc")), "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0");
});
