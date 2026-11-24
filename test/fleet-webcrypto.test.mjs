// The fleet core with the WebCrypto backend (lib/fleet/core/webcrypto.mjs, what a page, a Worker or the app's web view
// installs), on Node's globalThis.crypto: every shared vector, the backend installed once, and keys, hashes and
// derivations that agree with Node's backend byte for byte. This file loads only the pure core, never lib/fleet's Node
// entry, so nothing here runs on node:crypto's code path. fleet-webcrypto-browser.test.mjs runs the same cases in
// Chromium.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { checkFixtures, checkHpkeFixtures, checkHpkeVector } from "./fleet-fixture-cases.mjs";
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

test("ed25519FromSeed clears its PKCS#8 copy of the seed when an import or the export fails (and leaves the caller's seed)", async () => {
  for (const failAt of ["first import", "export", "second import"]) {
    let der = null, imports = 0;
    const subtle = {
      async importKey(fmt, data) {
        imports++;
        if (imports === 1) der = data;
        if ((failAt === "first import" && imports === 1) || (failAt === "second import" && imports === 2)) throw new Error(failAt);
        return {};
      },
      async exportKey() {
        if (failAt === "export") throw new Error(failAt);
        return { x: core.b64(new Uint8Array(32).fill(9)) };
      },
    };
    const w = core.webCrypto({ subtle, getRandomValues: (b) => b });
    const seed = new Uint8Array(32).fill(7);
    await assert.rejects(w.ed25519FromSeed(seed), new RegExp(failAt));
    assert.equal(der.length, 48, failAt);
    assert.ok(der.every((x) => x === 0), `${failAt}: the PKCS#8 copy is cleared`);
    assert.ok(seed.every((x) => x === 7), `${failAt}: the caller's seed is the caller's`);
  }
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
