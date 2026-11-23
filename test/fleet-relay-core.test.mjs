// The relay admission's two faces agree (lib/fleet/core/request.mjs and core/relay.mjs, the pure core a Worker runs;
// lib/fleet/request.mjs and channel/relay.mjs, Node's): one corpus of host opens, app opens and replacement
// authorizations, valid and broken one way each, gives the same code and the same admitted fields through Node's face,
// through the core on Node's backend, and through the core alone on the WebCrypto backend in a process of its own
// (fleet-relay-core-child.mjs). The core consumes nothing: an open it admitted admits again; Node's face refuses the
// second as a replay. And an authorization's body is closed: exactly its seven fields, in form, canonical.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash, createHmac, randomBytes } from "node:crypto";
import { test } from "node:test";
import { FleetError, b64, enc, newId, keyFromSeed, seal, applyChainEntry as apply } from "../lib/fleet/index.mjs";
import { signRequest } from "../lib/fleet/request.mjs";
import * as nodeFace from "../lib/fleet/channel/relay.mjs";
import * as core from "../lib/fleet/core/relay.mjs";
import { verifyRequest as coreVerifyRequest } from "../lib/fleet/core/request.mjs";

const AUD = "https://dev.sagebrush.space";
const NOW = 1_800_000_000_000;
const nonce = () => b64(randomBytes(16));
const code = async (fn) => { try { await fn(); return "ok"; } catch (e) { if (e instanceof FleetError) return e.code; throw e; } };
let n = 160;
const key = () => keyFromSeed(new Uint8Array(32).fill(n++));

async function world() {
  const fleet = newId(), host = newId(), agent = newId();
  const N = key(), nId = newId(), rec = key(), H = key(), stranger = key();
  const sN = { kind: "device", id: nId, alg: "ed25519", key: N.key };
  const genesis = seal("sb.device-chain.v1", sN, { fleet, aud: AUD, seq: 0, prev: "", op: "genesis", at_ms: 1, auth_time_ms: 1,
    device: { id: nId, alg: "ed25519", key: b64(N.raw), name: "mac", tier: "native" }, recovery_key: { alg: "ed25519", key: b64(rec.raw) } }, N);
  const chain = (await apply(null, genesis, { aud: AUD, fleet })).state;
  const session = (extra = {}) => {
    const body = { fleet, aud: AUD, at_ms: NOW - 1000, not_before_ms: NOW - 1000, not_after_ms: NOW + 3_600_000, session: newId(), host, agent,
      browser_gen: 2, host_gen: 3, chain_seq: 0, app_session_pub: b64(new Uint8Array(32).fill(9)), account_origins_manifest_sha256: b64(new Uint8Array(32).fill(1)),
      exceptions_sha256: b64(new Uint8Array(32).fill(2)), ...extra };
    return { body, record: seal("sb.browser-session.v1", sN, body, N) };
  };
  return { fleet, host, agent, H, stranger, genesis, chain, session };
}

/** Every case: { kind, target, headers } or { kind: "commit", header, body }, with ctx differences, and why. */
function corpus(w) {
  const cases = [];
  const add = (why, k) => cases.push({ why, ...k });
  const fields = (s, role, extra = {}) => ({ role, fleet: w.fleet, session: s.body.session, agent: w.agent, browser_gen: s.body.browser_gen, host_gen: 3, resume_n: 0, ...extra });
  const sigFor = (target, method = "GET", body = new Uint8Array(0), { k = w.H, gen = 3, ts = NOW, ...more } = {}) =>
    signRequest({ aud: AUD, method, target, body, host: w.host, key: k, fields: { gen, ts, nonce: nonce(), ...more } });

  const s = w.session();
  const ht = core.openTarget(fields(s, "host"));
  add("host: valid", { kind: "host", target: ht, headers: { "sagebrush-sig": sigFor(ht) } });
  add("host: another target than signed", { kind: "host", target: core.openTarget(fields(s, "host", { resume_n: 1 })), headers: { "sagebrush-sig": sigFor(ht) } });
  const t4 = core.openTarget(fields(s, "host", { host_gen: 4 }));
  add("host: the target's host_gen isn't the signature's gen", { kind: "host", target: t4, headers: { "sagebrush-sig": sigFor(t4) } });
  add("host: the host's gen moved on", { kind: "host", target: ht, headers: { "sagebrush-sig": sigFor(ht) }, ctx: { gen: 4 } });
  add("host: an app target", { kind: "host", target: core.openTarget(fields(s, "app")), headers: { "sagebrush-sig": sigFor(core.openTarget(fields(s, "app"))) } });
  add("host: headers over 98,304 bytes", { kind: "host", target: ht, headers: { "sagebrush-sig": sigFor(ht), "x-filler": "a".repeat(core.HEADERS_MAX) } });
  add("host: headers over the cap in UTF-8 bytes, not characters", { kind: "host", target: ht, headers: { "sagebrush-sig": sigFor(ht), "x-filler": "é".repeat(core.HEADERS_MAX / 2) } });
  add("host: the agent has no browser", { kind: "host", target: ht, headers: { "sagebrush-sig": sigFor(ht) }, ctx: { granted: false } });
  add("host: signed by another key", { kind: "host", target: ht, headers: { "sagebrush-sig": sigFor(ht, "GET", undefined, { k: w.stranger }) } });
  add("host: outside the 5 minutes", { kind: "host", target: ht, headers: { "sagebrush-sig": sigFor(ht) }, ctx: { now: NOW + 300_001 } });
  add("host: signed as POST", { kind: "host", target: ht, headers: { "sagebrush-sig": sigFor(ht, "POST") } });
  add("host: carries an agent", { kind: "host", target: ht, headers: { "sagebrush-sig": sigFor(ht, "GET", undefined, { agent: w.agent }) } });
  add("host: no signature", { kind: "host", target: ht, headers: {} });
  add("host: the signature's form", { kind: "host", target: ht, headers: { "sagebrush-sig": sigFor(ht).replace("gen=3", "gen=03") } });

  const at = core.openTarget(fields(s, "app"));
  const app = (extra = {}, rec = s.record) => ({ "sagebrush-browser-record": b64(rec), "sagebrush-request": nonce(), ...extra });
  add("app: valid", { kind: "app", target: at, headers: app() });
  add("app: another account's fleet", { kind: "app", target: at, headers: app(), ctx: { fleets: [newId()] } });
  add("app: the record's session isn't the open's", { kind: "app", target: core.openTarget(fields(w.session(), "app")), headers: app() });
  add("app: the record's browser_gen isn't the open's", { kind: "app", target: core.openTarget(fields(s, "app", { browser_gen: 3 })), headers: app() });
  add("app: the record's host_gen isn't the open's", { kind: "app", target: core.openTarget(fields(s, "app", { host_gen: 4 })), headers: app(), ctx: { gen: 4 } });
  add("app: before the window", { kind: "app", target: at, headers: app(), ctx: { now: NOW - 1001 } });
  add("app: at the window's end", { kind: "app", target: at, headers: app(), ctx: { now: NOW + 3_600_000 } });
  add("app: the host's gen moved on", { kind: "app", target: at, headers: app(), ctx: { gen: 4 } });
  add("app: headers over 98,304 bytes", { kind: "app", target: at, headers: app({ "x-filler": "a".repeat(core.HEADERS_MAX - 100) }) });
  add("app: a request id out of form", { kind: "app", target: at, headers: app({ "sagebrush-request": "x" }) });
  add("app: a record header over 87,252", { kind: "app", target: at, headers: app({ "sagebrush-browser-record": "A".repeat(core.RECORD_HEADER_MAX + 1) }) });
  add("app: a record header that isn't base64url", { kind: "app", target: at, headers: app({ "sagebrush-browser-record": "a+b/" }) });
  add("app: a record of another type", { kind: "app", target: at, headers: app({}, seal("sb.device-chain.v1", { kind: "device", id: newId(), alg: "ed25519", key: w.H.key }, { x: 1 }, w.H)) });
  const tampered = Uint8Array.from(s.record); tampered[tampered.length - 5] ^= 1;
  add("app: a tampered record", { kind: "app", target: at, headers: app({}, tampered) });
  add("app: a host target", { kind: "app", target: ht, headers: app() });

  const body = { fleet: w.fleet, session: s.body.session, agent: w.agent, browser_gen: 2, resume_n: 0, host_nonce: nonce(), app_request: nonce() };
  const commit = (b) => ({ kind: "commit", header: sigFor(core.COMMIT_ROUTE, "POST", b), body: b64(b) });
  add("commit: valid", commit(core.commitBody(body)));
  add("commit: signed by another key", { ...commit(core.commitBody(body)), header: sigFor(core.COMMIT_ROUTE, "POST", core.commitBody(body), { k: w.stranger }) });
  add("commit: another body than signed", { ...commit(core.commitBody(body)), body: b64(core.commitBody({ ...body, resume_n: 1 })) });
  add("commit: not canonical", commit(enc(JSON.stringify(body, null, 1))));
  add("commit: an eighth field", commit(enc(JSON.stringify(Object.fromEntries(Object.entries({ ...body, extra: 1 }).sort())))));
  add("commit: a field missing", commit(enc(JSON.stringify(Object.fromEntries(Object.entries({ ...body, resume_n: undefined }).filter(([, v]) => v !== undefined).sort())))));
  add("commit: browser_gen 0", commit(core.commitBody({ ...body, browser_gen: 0 })));
  add("commit: resume_n a string", commit(enc(JSON.stringify(Object.fromEntries(Object.entries({ ...body, resume_n: "0" }).sort())))));
  add("commit: a nonce out of form", commit(core.commitBody({ ...body, host_nonce: "x" })));
  add("commit: null", commit(enc("null")));
  add("commit: an array", commit(enc("[1]")));
  add("commit: not UTF-8", commit(Uint8Array.of(0xff)));
  return cases;
}

const nodeCtx = (w, c = {}) => ({
  aud: AUD, now: c.now ?? NOW,
  hostKey: (h) => { if (h !== w.host) throw new FleetError("unknown_host"); return w.H.raw; },
  currentGen: () => c.gen ?? 3, agentHasBrowser: (h, a) => a === w.agent && c.granted !== false,
  accountFleets: () => c.fleets ?? [w.fleet], chainOf: () => w.chain, consumeNonce: () => true, consumeRequest: () => true,
});
const coreCtx = (w, c) => { const { consumeNonce, consumeRequest, ...rest } = nodeCtx(w, c); return rest; };

async function run(face, w, k, ctx) {
  try {
    let r;
    if (k.kind === "host") r = await face.verifyHostOpen({ target: k.target, headers: k.headers }, ctx);
    else if (k.kind === "app") r = await face.verifyAppOpen({ target: k.target, headers: k.headers }, ctx);
    else r = await face.verifyCommit({ header: k.header, body: new Uint8Array(Buffer.from(k.body, "base64url")) }, ctx);
    return { code: "ok", value: JSON.parse(JSON.stringify(r)) };
  } catch (e) {
    if (!(e instanceof FleetError)) throw e;
    return { code: e.code };
  }
}

test("the corpus: Node's face, the core on Node's backend and the core on WebCrypto alone give the same code and fields", async () => {
  const w = await world();
  const cases = corpus(w);
  const child = JSON.parse(execFileSync(process.execPath, [new URL("./fleet-relay-core-child.mjs", import.meta.url).pathname], {
    input: JSON.stringify({ AUD, NOW, fleet: w.fleet, host: w.host, agent: w.agent, hostRaw: b64(w.H.raw), genesis: b64(w.genesis), cases, control: CONTROL }),
    encoding: "utf8", maxBuffer: 1 << 22,
  })).out;
  assert.equal(child.length, cases.length);
  const valid = cases.filter((k) => k.why.endsWith(": valid")).length;
  assert.equal(valid, 3, "one valid case of each kind");
  for (const [i, k] of cases.entries()) {
    const viaNode = await run(nodeFace, w, k, nodeCtx(w, k.ctx));
    const viaCore = await run(core, w, k, coreCtx(w, k.ctx));
    if (k.why.endsWith(": valid")) assert.equal(viaNode.code, "ok", k.why); else assert.notEqual(viaNode.code, "ok", k.why);
    assert.equal(viaCore.code, viaNode.code, `core, Node's backend: ${k.why}`);
    assert.equal(child[i].code, viaNode.code, `core, WebCrypto: ${k.why}`);
    if (viaNode.code === "ok") {
      // (the core's commit also hands back its signature's nonce, for the caller to consume; Node's face consumed it)
      const { nonce: commitNonce, ...coreRest } = viaCore.value;
      const want = k.kind === "commit" ? coreRest : viaCore.value;
      if (k.kind === "commit") assert.match(commitNonce, core.B22);
      assert.deepEqual(want, viaNode.value, `core's fields: ${k.why}`);
      assert.deepEqual(child[i].value, viaCore.value, `WebCrypto's fields: ${k.why}`);
    }
  }
});

// (one control-plane call, for the WebCrypto backend's MACs; the oracle is node:crypto's HMAC over the documented strings)
const CONTROL = { key: b64(new Uint8Array(32).fill(3)), method: "POST", target: "/api/fleet/v1/relay/admit", body: b64(enc('{"v":1}')), ts: NOW, id: nonce() };

test("the control plane's MACs on the WebCrypto backend alone equal an independent HMAC of the documented strings", async () => {
  const w = await world();
  const r = JSON.parse(execFileSync(process.execPath, [new URL("./fleet-relay-core-child.mjs", import.meta.url).pathname], {
    input: JSON.stringify({ AUD, NOW, fleet: w.fleet, host: w.host, agent: w.agent, hostRaw: b64(w.H.raw), genesis: b64(w.genesis), cases: [], control: CONTROL }),
    encoding: "utf8",
  }));
  const key = Buffer.from(CONTROL.key, "base64url"), body = Buffer.from(CONTROL.body, "base64url");
  const sha = (b) => createHash("sha256").update(b).digest("base64url");
  const mac = (text) => createHmac("sha256", key).update(text).digest("base64url");
  assert.equal(r.control.header, `v1 ts=${NOW}; id=${CONTROL.id}; mac=${mac(`sagebrush.relay-control.request.v1\nPOST\n${CONTROL.target}\n${sha(body)}\n${NOW}\n${CONTROL.id}`)}`);
  const answerBody = Buffer.from(r.control.answer.body, "base64url");
  assert.equal(r.control.answer.header, `v1 mac=${mac(`sagebrush.relay-control.answer.v1\n200\n${sha(answerBody)}`)}`);
  assert.deepEqual(r.control.back, { v: 1, answer: "admit", call: CONTROL.id, call_sha256: sha(body), result: "refused", code: "not_granted" });
});

test("the core consumes nothing: what it admitted admits again, and it asks for no consume function; Node's face refuses the replay", async () => {
  const w = await world();
  const cases = corpus(w).filter((k) => k.why.endsWith(": valid"));
  for (const k of cases) {
    const ctx = coreCtx(w);
    assert.equal((await run(core, w, k, ctx)).code, "ok");
    assert.equal((await run(core, w, k, ctx)).code, "ok", `again: ${k.why}`);
    const seen = new Set();
    const once = (x) => (seen.has(x) ? false : (seen.add(x), true));
    const strict = { ...nodeCtx(w), consumeNonce: (h, x) => once(x), consumeRequest: once };
    assert.equal((await run(nodeFace, w, k, strict)).code, "ok");
    assert.equal((await run(nodeFace, w, k, strict)).code, "replay", `Node's face again: ${k.why}`);
  }
  const host = cases.find((k) => k.kind === "host");
  const r = await core.verifyHostOpen({ target: host.target, headers: host.headers }, coreCtx(w));
  assert.match(r.nonce, core.B22, "the host's nonce, for the relay to consume");
  const appCase = cases.find((k) => k.kind === "app");
  const a = await core.verifyAppOpen({ target: appCase.target, headers: appCase.headers }, coreCtx(w));
  assert.equal(a.request, appCase.headers["sagebrush-request"], "the app's request id, for the relay to consume");
});

test("the core's verifyRequest: §5.1's order, and the nonce returned, not consumed", async () => {
  const w = await world();
  const T = `${core.ROUTE}/x`;
  const h = signRequest({ aud: AUD, method: "POST", target: T, body: Uint8Array.of(1), host: w.host, key: w.H, fields: { gen: 3, ts: NOW, nonce: nonce() } });
  const ctx = coreCtx(w);
  const f = await coreVerifyRequest({ header: h, method: "POST", target: T, body: Uint8Array.of(1) }, ctx);
  assert.equal((await coreVerifyRequest({ header: h, method: "POST", target: T, body: Uint8Array.of(1) }, ctx)).nonce, f.nonce);
  // (order: a bad audience is reported before skew, skew before the host, the host before the signature)
  assert.equal(await code(() => coreVerifyRequest({ header: h, method: "POST", target: T, body: Uint8Array.of(2) }, { ...ctx, aud: "https://x", now: 0 })), "bad_audience");
  assert.equal(await code(() => coreVerifyRequest({ header: h, method: "POST", target: T, body: Uint8Array.of(2) }, { ...ctx, now: 0 })), "clock_skew");
  assert.equal(await code(() => coreVerifyRequest({ header: h, method: "POST", target: T, body: Uint8Array.of(2) }, { ...ctx, hostKey: () => { throw new FleetError("host_revoked"); }, currentGen: () => 4 })), "host_revoked");
  assert.equal(await code(() => coreVerifyRequest({ header: h, method: "POST", target: T, body: Uint8Array.of(2) }, { ...ctx, currentGen: () => 4 })), "stale_generation");
  assert.equal(await code(() => coreVerifyRequest({ header: h, method: "POST", target: T, body: Uint8Array.of(2) }, ctx)), "bad_signature");
});
