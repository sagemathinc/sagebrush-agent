// The relay admission's two faces agree (lib/fleet/core/request.mjs and core/relay.mjs, the pure core a Worker runs;
// lib/fleet/request.mjs and channel/relay.mjs, Node's): one corpus of host opens, app opens and replacement
// authorizations, valid and broken one way each, gives the same code and the same admitted fields through Node's face,
// through the core on Node's backend, and through the core alone on the WebCrypto backend in a process of its own
// (fleet-relay-core-child.mjs). The core consumes no nonce or request id: an open it admitted admits again; Node's face
// refuses the second as a replay. The app open's relay token (channel addendum A1) is consumed through ctx by both, before
// any other check; AppTokens, the service's store, takes a row once. And an authorization's body is closed: exactly its
// seven fields, in form, canonical.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash, createHmac, randomBytes } from "node:crypto";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { FleetError, b64, enc, newId, keyFromSeed, seal, applyChainEntry as apply } from "../lib/fleet/index.mjs";
import { signRequest } from "../lib/fleet/request.mjs";
import * as nodeFace from "../lib/fleet/channel/relay.mjs";
import * as core from "../lib/fleet/core/relay.mjs";
import { verifyRequest as coreVerifyRequest } from "../lib/fleet/core/request.mjs";

const AUD = "https://dev.sagebrush.space";
// (a file path on every platform: a URL's pathname is /D:/... on Windows)
const CHILD = fileURLToPath(new URL("./fleet-relay-core-child.mjs", import.meta.url));
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

const ACCOUNT = newId(), ACCOUNT_SESSION = newId();
const tokenKey = (t) => createHash("sha256").update(t, "utf8").digest("base64url");
const newToken = () => `rt1.${b64(randomBytes(32))}`;

/**
 * Every case: { kind, target, headers } or { kind: "commit", header, body }, with ctx differences, and why; and the
 * token rows the app cases were issued (by key), as the service would hold them.
 */
function corpus(w) {
  const cases = [], tokens = {};
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
  // (an app open's headers, with a token issued for exactly that open unless `row` says otherwise: null, none issued;
  // an object, fields of the row changed)
  const appOpen = (why, target, { extra = {}, rec = s.record, ctx, row = {}, token = newToken() } = {}) => {
    const id = nonce();
    if (row !== null) {
      const { role, ...f } = core.parseOpenTarget(target);
      tokens[tokenKey(token)] = { account: ACCOUNT, account_session: ACCOUNT_SESSION, ...f, host: w.host, request: id, expires_ms: NOW + core.APP_TOKEN_MS, ...row };
    }
    add(why, { kind: "app", target, ctx, headers: { "sagebrush-relay-token": token, "sagebrush-browser-record": b64(rec), "sagebrush-request": id, ...extra } });
  };
  appOpen("app: valid", at);
  appOpen("app: the record's session isn't the open's", core.openTarget(fields(w.session(), "app")));
  appOpen("app: the record's browser_gen isn't the open's", core.openTarget(fields(s, "app", { browser_gen: 3 })));
  appOpen("app: the record's host_gen isn't the open's", core.openTarget(fields(s, "app", { host_gen: 4 })), { ctx: { gen: 4 } });
  appOpen("app: before the window", at, { ctx: { now: NOW - 1001 } });
  appOpen("app: at the window's end", at, { ctx: { now: NOW + 3_600_000 }, row: { expires_ms: NOW + 3_600_001 } });
  appOpen("app: the host's gen moved on", at, { ctx: { gen: 4 } });
  appOpen("app: headers over 98,304 bytes", at, { extra: { "x-filler": "a".repeat(core.HEADERS_MAX - 100) } });
  appOpen("app: a request id out of form", at, { extra: { "sagebrush-request": "x" } });
  appOpen("app: a record header over 87,252", at, { extra: { "sagebrush-browser-record": "A".repeat(core.RECORD_HEADER_MAX + 1) } });
  appOpen("app: a record header that isn't base64url", at, { extra: { "sagebrush-browser-record": "a+b/" } });
  appOpen("app: a record of another type", at, { rec: seal("sb.device-chain.v1", { kind: "device", id: newId(), alg: "ed25519", key: w.H.key }, { x: 1 }, w.H) });
  const tampered = Uint8Array.from(s.record); tampered[tampered.length - 5] ^= 1;
  appOpen("app: a tampered record", at, { rec: tampered });
  appOpen("app: a host target", ht);
  // (the relay token, A1 §3: its form, its row, the row's expiry and session, and its binding to this exact open)
  appOpen("app: no relay token", at, { extra: { "sagebrush-relay-token": undefined } });
  appOpen("app: a relay token out of form", at, { token: `rt2.${b64(randomBytes(32))}` });
  appOpen("app: a relay token with a non-zero pad bit", at, { token: newToken().slice(0, -1) + "B" });
  appOpen("app: a relay token never issued", at, { row: null });
  appOpen("app: the token at its expiry", at, { ctx: { now: NOW + core.APP_TOKEN_MS } });
  appOpen("app: the token 1 ms before its expiry", at, { ctx: { now: NOW + core.APP_TOKEN_MS - 1 }, row: {} });
  appOpen("app: the account session ended", at, { ctx: { sessionDead: true } });
  for (const k of ["fleet", "agent", "session"]) appOpen(`app: the token's ${k} isn't the open's`, at, { row: { [k]: newId() } });
  for (const k of ["browser_gen", "host_gen", "resume_n"]) appOpen(`app: the token's ${k} isn't the open's`, at, { row: { [k]: 7 } });
  appOpen("app: the token's request id isn't the open's", at, { row: { request: nonce() } });
  appOpen("app: the token's host isn't the record's", at, { row: { host: newId() } });
  appOpen("app: another account's session (the token's), the record still valid", at, { row: { account: newId() } });
  for (const k of cases) if (k.headers?.["sagebrush-relay-token"] === undefined && k.kind === "app") delete k.headers["sagebrush-relay-token"];

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
  cases.tokens = tokens;
  return cases;
}

// (the token rows looked up, not taken: the parity runs each case through three verifiers; AppTokens' own rows take them)
const nodeCtx = (w, c = {}, tokens = {}) => ({
  aud: AUD, now: c.now ?? NOW,
  hostKey: (h) => { if (h !== w.host) throw new FleetError("unknown_host"); return w.H.raw; },
  currentGen: () => c.gen ?? 3, agentHasBrowser: (h, a) => a === w.agent && c.granted !== false,
  consumeAppToken: (key) => tokens[key] ?? null, sessionLive: (account, session) => account === ACCOUNT && session === ACCOUNT_SESSION && !c.sessionDead,
  chainOf: () => w.chain, consumeNonce: () => true, consumeRequest: () => true,
});
const coreCtx = (w, c, tokens) => { const { consumeNonce, consumeRequest, ...rest } = nodeCtx(w, c, tokens); return rest; };

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

// (the token's codes, A1 §3: one code for every missing, unknown, expired or session-ended token; bad_form for a binding)
const EXPECT = {
  "app: no relay token": "unauthenticated", "app: a relay token out of form": "unauthenticated", "app: a relay token with a non-zero pad bit": "unauthenticated",
  "app: a relay token never issued": "unauthenticated", "app: the token at its expiry": "unauthenticated", "app: the account session ended": "unauthenticated",
  "app: another account's session (the token's), the record still valid": "unauthenticated",
  "app: the token's fleet isn't the open's": "bad_form", "app: the token's agent isn't the open's": "bad_form", "app: the token's session isn't the open's": "bad_form",
  "app: the token's browser_gen isn't the open's": "bad_form", "app: the token's host_gen isn't the open's": "bad_form", "app: the token's resume_n isn't the open's": "bad_form",
  "app: the token's request id isn't the open's": "bad_form", "app: the token's host isn't the record's": "bad_form",
  "app: at the window's end": "grant_expired", "app: the host's gen moved on": "stale_generation",
};

test("the corpus: Node's face, the core on Node's backend and the core on WebCrypto alone give the same code and fields", async () => {
  const w = await world();
  const cases = corpus(w);
  const child = JSON.parse(execFileSync(process.execPath, [CHILD], {
    input: JSON.stringify({ AUD, NOW, fleet: w.fleet, host: w.host, agent: w.agent, hostRaw: b64(w.H.raw), genesis: b64(w.genesis), cases, tokens: cases.tokens, account: ACCOUNT, account_session: ACCOUNT_SESSION, control: CONTROL }),
    encoding: "utf8", maxBuffer: 1 << 22,
  })).out;
  assert.equal(child.length, cases.length);
  const valid = cases.filter((k) => k.why.endsWith(": valid")).length;
  assert.equal(valid, 3, "one valid case of each kind");
  const admitted = new Set(["app: the token 1 ms before its expiry"]);
  for (const why of [...Object.keys(EXPECT), ...admitted]) assert.ok(cases.some((k) => k.why === why), `a case named ${why}`);
  for (const [i, k] of cases.entries()) {
    const viaNode = await run(nodeFace, w, k, nodeCtx(w, k.ctx, cases.tokens));
    const viaCore = await run(core, w, k, coreCtx(w, k.ctx, cases.tokens));
    if (k.why.endsWith(": valid") || admitted.has(k.why)) assert.equal(viaNode.code, "ok", k.why); else assert.notEqual(viaNode.code, "ok", k.why);
    if (EXPECT[k.why]) assert.equal(viaNode.code, EXPECT[k.why], k.why);
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
  const r = JSON.parse(execFileSync(process.execPath, [CHILD], {
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

test("the core consumes no nonce or request id: what it admitted admits again (its token looked up, not taken); Node's face refuses the replay", async () => {
  const w = await world();
  const all = corpus(w), cases = all.filter((k) => k.why.endsWith(": valid"));
  for (const k of cases) {
    const ctx = coreCtx(w, {}, all.tokens);
    assert.equal((await run(core, w, k, ctx)).code, "ok");
    assert.equal((await run(core, w, k, ctx)).code, "ok", `again: ${k.why}`);
    const seen = new Set();
    const once = (x) => (seen.has(x) ? false : (seen.add(x), true));
    const strict = { ...nodeCtx(w, {}, all.tokens), consumeNonce: (h, x) => once(x), consumeRequest: once };
    assert.equal((await run(nodeFace, w, k, strict)).code, "ok");
    assert.equal((await run(nodeFace, w, k, strict)).code, "replay", `Node's face again: ${k.why}`);
  }
  const host = cases.find((k) => k.kind === "host");
  const r = await core.verifyHostOpen({ target: host.target, headers: host.headers }, coreCtx(w, {}, all.tokens));
  assert.match(r.nonce, core.B22, "the host's nonce, for the relay to consume");
  const appCase = cases.find((k) => k.kind === "app");
  const a = await core.verifyAppOpen({ target: appCase.target, headers: appCase.headers }, coreCtx(w, {}, all.tokens));
  assert.equal(a.request, appCase.headers["sagebrush-request"], "the app's request id, for the relay to consume");
  assert.deepEqual([a.account, a.account_session], [ACCOUNT, ACCOUNT_SESSION], "the token's account and session, for the relay's timers");
});

test("the core's verifyRequest: §5.1's order, and the nonce returned, not consumed", async () => {
  const w = await world();
  const T = `${core.ROUTE}/x`;
  const h = signRequest({ aud: AUD, method: "POST", target: T, body: Uint8Array.of(1), host: w.host, key: w.H, fields: { gen: 3, ts: NOW, nonce: nonce() } });
  const ctx = coreCtx(w, {}, {});
  const f = await coreVerifyRequest({ header: h, method: "POST", target: T, body: Uint8Array.of(1) }, ctx);
  assert.equal((await coreVerifyRequest({ header: h, method: "POST", target: T, body: Uint8Array.of(1) }, ctx)).nonce, f.nonce);
  // (order: a bad audience is reported before skew, skew before the host, the host before the signature)
  assert.equal(await code(() => coreVerifyRequest({ header: h, method: "POST", target: T, body: Uint8Array.of(2) }, { ...ctx, aud: "https://x", now: 0 })), "bad_audience");
  assert.equal(await code(() => coreVerifyRequest({ header: h, method: "POST", target: T, body: Uint8Array.of(2) }, { ...ctx, now: 0 })), "clock_skew");
  assert.equal(await code(() => coreVerifyRequest({ header: h, method: "POST", target: T, body: Uint8Array.of(2) }, { ...ctx, hostKey: () => { throw new FleetError("host_revoked"); }, currentGen: () => 4 })), "host_revoked");
  assert.equal(await code(() => coreVerifyRequest({ header: h, method: "POST", target: T, body: Uint8Array.of(2) }, { ...ctx, currentGen: () => 4 })), "stale_generation");
  assert.equal(await code(() => coreVerifyRequest({ header: h, method: "POST", target: T, body: Uint8Array.of(2) }, ctx)), "bad_signature");
});
