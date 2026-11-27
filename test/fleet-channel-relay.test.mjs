// The browser channel's relay admission (lib/fleet/channel/relay.mjs, lib/fleet/request.mjs; design
// agent-autonomous-browser-channel.md r4 §5): O6 §5.1 request signatures, the two authenticated opens with the H6
// header caps, the replacement authorization, and the fake relay's §5.4 rules: candidates never touch the active pair,
// the switch happens once after the compare-and-set, bounds, expiry and revocation. And one whole handshake through it.
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { createHash, randomBytes } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "./host-linux-only.mjs";
import { FleetError, b64, enc, newId, keyFromSeed, seal, applyChainEntry as apply, hostFingerprint, verifyHostCert } from "../lib/fleet/index.mjs";
import { parseSig, signRequest, verifyRequest } from "../lib/fleet/request.mjs";
import { canon } from "../lib/canon.mjs";
import { lockDir } from "../lib/fleet/host/store.mjs";
import { acceptMessage1, openChannelStore, prologueBytes } from "../lib/fleet/channel/accept.mjs";
import { initiator, x25519Generate } from "../lib/fleet/channel/noise.mjs";
import {
  APP_TOKEN, APP_TOKEN_MS, AppTokens, FakeRelay, appTokenKey, appTokenRequest, HEADERS_MAX, RECORD_HEADER_MAX, ROUTE, openTarget, parseOpenTarget, signCommit, verifyAppOpen, verifyCommit,
  verifyHostOpen,
} from "../lib/fleet/channel/relay.mjs";

const AUD = "https://dev.sagebrush.space";
const NOW = 1_800_000_000_000;
const code = async (fn) => { try { await fn(); } catch (e) { if (e instanceof FleetError) return e.code; throw e; } return "ok"; };
const nonce = () => b64(randomBytes(16));
const tick = () => new Promise((r) => setTimeout(r, 1));
let n = 120;
const key = () => keyFromSeed(new Uint8Array(32).fill(n++));

test("request signatures (O6 §5.1): the exact header form; a replay, a changed target or body, skew and a stale gen refuse", async () => {
  const k = key(), host = newId(), seen = new Set();
  const ctx = { aud: AUD, now: NOW, hostKey: () => k.raw, currentGen: () => 3, consumeNonce: (h, x) => (seen.has(x) ? false : (seen.add(x), true)) };
  const T = `${ROUTE}?x`;
  const h = signRequest({ aud: AUD, method: "POST", target: T, body: Uint8Array.of(1), host, key: k, fields: { gen: 3, ts: NOW, nonce: nonce() } });
  assert.equal((await code(() => verifyRequest({ header: h, method: "POST", target: T, body: Uint8Array.of(1) }, ctx))), "ok");
  assert.equal(await code(() => verifyRequest({ header: h, method: "POST", target: T, body: Uint8Array.of(1) }, ctx)), "replay");
  const loose = { ...ctx, consumeNonce: () => true };
  assert.equal(await code(() => verifyRequest({ header: h, method: "POST", target: T + "y", body: Uint8Array.of(1) }, loose)), "bad_signature", "target");
  assert.equal(await code(() => verifyRequest({ header: h, method: "POST", target: T, body: Uint8Array.of(2) }, loose)), "bad_signature", "body");
  assert.equal(await code(() => verifyRequest({ header: h, method: "GET", target: T, body: Uint8Array.of(1) }, loose)), "bad_signature", "method");
  assert.equal(await code(() => verifyRequest({ header: h, method: "POST", target: T, body: Uint8Array.of(1) }, { ...loose, now: NOW + 300_001 })), "clock_skew");
  assert.equal(await code(() => verifyRequest({ header: h, method: "POST", target: T, body: Uint8Array.of(1) }, { ...loose, currentGen: () => 4 })), "stale_generation");
  const idemOnly = h.replace("idem=-", `idem=${nonce()}`); // (an idem with no op: they come together or not at all)
  for (const bad of [h.replace("; agent=", ";  agent="), h.replace("v1 ", "v2 "), h.replace("gen=3", "gen=03"), h.replace("idem=-", "idem=x"), `${h}; extra=1`, idemOnly])
    assert.equal(await code(() => parseSig(bad)), "bad_form", bad.slice(0, 60));
});

test("open targets: exactly the route and its seven fields, in order, each in its form", async () => {
  const f = { role: "host", fleet: newId(), session: newId(), agent: newId(), browser_gen: 2, host_gen: 3, resume_n: 0 };
  assert.deepEqual(parseOpenTarget(openTarget(f)), f);
  const t = openTarget(f);
  for (const bad of [t.replace("role=host", "role=other"), t.replace("&agent=", "&agentx="), t + "&x=1", t.replace("resume_n=0", "resume_n=00"),
    t.replace("browser_gen=2", "browser_gen=0"), t.replace(ROUTE, "/other"), t.replace(`fleet=${f.fleet}`, "fleet=x")])
    assert.equal(await code(() => parseOpenTarget(bad)), "bad_form", bad.slice(-40));
  const swapped = `${ROUTE}?fleet=${f.fleet}&role=host&session=${f.session}&agent=${f.agent}&browser_gen=2&host_gen=3&resume_n=0`;
  assert.equal(await code(() => parseOpenTarget(swapped)), "bad_form", "fields out of order");
});

/** A fleet with a native device, a host (signing key, certified X25519 key), an agent, a channel store, a fake relay. */
async function world(t) {
  const fleet = newId(), host = newId(), agent = newId(), ctx = { aud: AUD, fleet };
  const N = key(), nId = newId(), rec = key();
  const sN = { kind: "device", id: nId, alg: "ed25519", key: N.key };
  const chain = (await apply(null, seal("sb.device-chain.v1", sN, { fleet, aud: AUD, seq: 0, prev: "", op: "genesis", at_ms: 1, auth_time_ms: 1,
    device: { id: nId, alg: "ed25519", key: b64(N.raw), name: "mac", tier: "native" }, recovery_key: { alg: "ed25519", key: b64(rec.raw) } }, N), ctx)).state;
  const H = key(), encKey = x25519Generate();
  const fp = await hostFingerprint(host, H.raw, encKey.raw);
  const cert = await verifyHostCert(seal("sb.host-cert.v1", sN, { fleet, aud: AUD, chain_seq: 0, host, sign_key: b64(H.raw), enc_key: b64(encKey.raw), fingerprint: b64(fp), name: "box", at_ms: 1 }, N), { ...ctx, chain });
  const dir = mkdtempSync(join(tmpdir(), "fleet-relay-"));
  const lock = await lockDir(dir);
  t.after(async () => { await lock.release(); rmSync(dir, { recursive: true, force: true }); });
  const store = openChannelStore(dir, lock);
  const nonces = new Set(), requests = new Set();
  let clock = NOW;
  const account = newId(), accountSession = newId(), tokens = new AppTokens({ now: () => clock });
  let sessionLive = true;
  const w = {
    fleet, host, agent, chain, cert, encKey, store, H, relay: new FakeRelay({ now: () => clock }),
    advance(ms) { clock += ms; },
    sig: { aud: AUD, get now() { return clock; }, hostKey: (h) => { if (h !== host) refuse(); return H.raw; }, currentGen: () => 3, consumeNonce: (h, x) => (nonces.has(x) ? false : (nonces.add(x), true)), agentHasBrowser: (h, a) => a === agent },
    tokens, account, accountSession, logout() { sessionLive = false; tokens.logout(accountSession); },
    app: { aud: AUD, get now() { return clock; }, consumeAppToken: (k) => tokens.consume(k), sessionLive: (a, s) => sessionLive && a === account && s === accountSession,
      chainOf: () => chain, currentGen: () => 3, consumeRequest: (id) => (requests.has(id) ? false : (requests.add(id), true)) },
    /** A token issued for an open's fields and request id, as the issuer would (synchronously: the row put in place). */
    mint(f, request, row = {}) {
      const token = `rt1.${b64(randomBytes(32))}`;
      const { role, ...b } = f;
      tokens.rows.set(createHash("sha256").update(token, "utf8").digest("base64url"), { account, account_session: accountSession, ...b, host, request, expires_ms: clock + APP_TOKEN_MS, ...row });
      return token;
    },
    session(extra = {}) {
      const app = x25519Generate();
      const body = { fleet, aud: AUD, at_ms: NOW - 1000, not_before_ms: NOW - 1000, not_after_ms: NOW + 3_600_000, session: newId(), host, agent,
        browser_gen: 1, host_gen: 3, chain_seq: 0, app_session_pub: b64(app.raw), account_origins_manifest_sha256: b64(new Uint8Array(32).fill(1)),
        exceptions_sha256: b64(new Uint8Array(32).fill(2)), ...extra };
      return { app, body, record: seal("sb.browser-session.v1", sN, body, N) };
    },
    tuple: (sess) => ({ fleet, host, agent, browser_gen: sess.body.browser_gen, session: sess.body.session }),
    fields: (sess, role, resume_n = 0) => ({ role, fleet, session: sess.body.session, agent, browser_gen: sess.body.browser_gen, host_gen: 3, resume_n }),
    hostOpen(sess, resume_n = 0, extra = {}) {
      const target = openTarget(w.fields(sess, "host", resume_n));
      return { target, headers: { "sagebrush-sig": signRequest({ aud: AUD, method: "GET", target, host, key: H, fields: { gen: 3, ts: clock, nonce: nonce() } }), ...extra } };
    },
    appOpen(sess, resume_n = 0, extra = {}, row = {}) {
      const f = w.fields(sess, "app", resume_n), request = nonce();
      return { target: openTarget(f), headers: { "sagebrush-relay-token": w.mint(f, request, row), "sagebrush-browser-record": b64(sess.record), "sagebrush-request": request, ...extra } };
    },
  };
  function refuse() { throw new FleetError("unknown_host"); }
  return w;
}

test("the host's open (§5.2): signed, its gen the open's host_gen, the agent granted the browser; the nonce consumed", async (t) => {
  const w = await world(t);
  const sess = w.session();
  const o = w.hostOpen(sess);
  const v = verifyHostOpen(o, w.sig);
  assert.deepEqual([v.role, v.host, v.session, v.resume_n], ["host", w.host, sess.body.session, 0]);
  assert.equal(await code(() => verifyHostOpen(o, w.sig)), "replay", "the same open again");
  assert.equal(await code(() => verifyHostOpen({ ...w.hostOpen(sess), target: openTarget({ ...w.fields(sess, "host"), resume_n: 1 }) }, w.sig)), "bad_signature", "another target than signed");
  assert.equal(await code(() => verifyHostOpen(w.hostOpen(sess), { ...w.sig, agentHasBrowser: () => false })), "not_granted");
  // a target naming another host_gen than the signature's gen (signed honestly, as gen 3)
  const t4 = openTarget({ ...w.fields(sess, "host"), host_gen: 4 });
  const signed4 = { target: t4, headers: { "sagebrush-sig": signRequest({ aud: AUD, method: "GET", target: t4, host: w.host, key: w.H, fields: { gen: 3, ts: NOW, nonce: nonce() } }) } };
  assert.equal(await code(() => verifyHostOpen(signed4, w.sig)), "stale_generation");
  assert.equal(await code(() => verifyHostOpen({ target: openTarget(w.fields(sess, "app")), headers: w.hostOpen(sess).headers }, w.sig)), "bad_form", "an app target");
  assert.equal(await code(() => verifyHostOpen(w.hostOpen(sess, 0, { "x-filler": "a".repeat(HEADERS_MAX) }), w.sig)), "limit", "headers over 98,304 bytes");
  const other = await world(t);
  assert.equal(await code(() => verifyHostOpen(other.hostOpen(other.session()), w.sig)), "unknown_host", "another host's key");
});

test("the app's open (§5.3, A1): its token taken once, the record verified and equal to the open, its window, the request id once, the H6 caps", async (t) => {
  const w = await world(t);
  const sess = w.session();
  const v = await verifyAppOpen(w.appOpen(sess), w.app);
  assert.deepEqual([v.role, v.host, v.session], ["app", w.host, sess.body.session]);
  const o = w.appOpen(sess);
  await verifyAppOpen(o, w.app);
  assert.equal(await code(() => verifyAppOpen(o, w.app)), "unauthenticated", "the same open again: its token was taken");
  const again = { ...o, headers: { ...o.headers, "sagebrush-relay-token": w.mint(w.fields(sess, "app"), o.headers["sagebrush-request"]) } };
  assert.equal(await code(() => verifyAppOpen(again, w.app)), "replay", "a fresh token, the same request id");
  const g9 = { ...w.fields(sess, "app"), browser_gen: 9 }, r9 = nonce();
  const o9 = { target: openTarget(g9), headers: { "sagebrush-relay-token": w.mint(g9, r9), "sagebrush-browser-record": b64(sess.record), "sagebrush-request": r9 } };
  assert.equal(await code(() => verifyAppOpen(o9, w.app)), "bad_form", "the record isn't the open (the token is)");
  assert.equal(await code(() => verifyAppOpen(w.appOpen(w.session({ not_after_ms: NOW })), w.app)), "grant_expired");
  assert.equal(await code(() => verifyAppOpen(w.appOpen(sess), { ...w.app, currentGen: () => 4 })), "stale_generation");
  // H6: the record header at 87,252 characters is read (and refused as a record); one over, or not base64url, is refused first
  assert.equal(await code(() => verifyAppOpen(w.appOpen(sess, 0, { "sagebrush-browser-record": "A".repeat(RECORD_HEADER_MAX) }), w.app)), "bad_form");
  assert.equal(await code(() => verifyAppOpen(w.appOpen(sess, 0, { "sagebrush-browser-record": "A".repeat(RECORD_HEADER_MAX + 1) }), w.app)), "limit");
  assert.equal(await code(() => verifyAppOpen(w.appOpen(sess, 0, { "sagebrush-browser-record": "A+B=" }), w.app)), "bad_form", "not base64url");
  const fill = HEADERS_MAX - 200;
  assert.equal(await code(() => verifyAppOpen(w.appOpen(sess, 0, { "x-filler": "a".repeat(fill) }), w.app)), "limit", "a header block filled by other headers");
  assert.equal(await code(() => verifyAppOpen(w.appOpen(sess, 0, { "sagebrush-request": "short" }), w.app)), "bad_form", "the request id's form");
});

test("the relay token (A1): issued for one open, taken once whatever the outcome, its expiry exact, the session read at use, never in a message", async (t) => {
  const w = await world(t);
  const sess = w.session();
  const seen = [];
  const codeOf = async (fn) => { try { await fn(); return "ok"; } catch (e) { if (!(e instanceof FleetError)) throw e; seen.push(String(e), e.message); return e.code; } };
  const open = (f, request, token) => ({ target: openTarget(f), headers: { "sagebrush-relay-token": token, "sagebrush-browser-record": b64(sess.record), "sagebrush-request": request } });
  const f0 = w.fields(sess, "app");
  // (the body as the app sends it: canonical bytes of exactly what it holds; `extra` adds or changes fields)
  const issue = async (f, request, extra = {}) => {
    const { role, ...b } = f;
    const body = Object.keys(extra).length ? enc(canon({ ...b, host: w.host, request, ...extra }).text) : appTokenRequest({ ...b, host: w.host, request });
    return (await w.tokens.issue({ account: w.account, account_session: w.accountSession, body })).token;
  };
  const tokensUsed = [];
  const fresh = async (f = f0) => { const r = nonce(); const tk = await issue(f, r); tokensUsed.push(tk); return { r, tk }; };

  // the issuer: its form; the token's form and lifetime; only the hash kept
  const a = await fresh();
  assert.match(a.tk, APP_TOKEN);
  const row = w.tokens.rows.get(await appTokenKey(a.tk));
  assert.equal(row.expires_ms, NOW + APP_TOKEN_MS);
  assert.ok(!JSON.stringify([...w.tokens.rows]).includes(a.tk.slice(4)), "the store keeps no token, only its hash");
  const size = w.tokens.rows.size;
  assert.equal(await codeOf(() => issue(f0, nonce(), { resume_n: 0 })), "ok", "the hand-built body, unchanged, is accepted (the control)");
  for (const bad of [{ extra: 1 }, { request: "x" }, { browser_gen: 0 }, { resume_n: -1 }, { host: "x" }])
    assert.equal(await codeOf(() => issue(f0, nonce(), bad)), "bad_form", JSON.stringify(bad));
  assert.equal(await codeOf(() => w.tokens.issue({ account: w.account, account_session: w.accountSession, body: enc(JSON.stringify({ ...f0, host: w.host, request: nonce() }, null, 1)) })), "bad_form", "not canonical");
  assert.equal(w.tokens.rows.size, size + 1, "nothing stored on a refusal (the control's one row)");

  // taken once: the open, then the same token again
  assert.equal(await codeOf(() => verifyAppOpen(open(f0, a.r, a.tk), w.app)), "ok");
  assert.equal(await codeOf(() => verifyAppOpen(open(f0, nonce(), a.tk), w.app)), "unauthenticated", "used");
  // a mismatch burns it: the right open after it finds nothing
  const b = await fresh();
  assert.equal(await codeOf(() => verifyAppOpen(open({ ...f0, resume_n: 1 }, b.r, b.tk), w.app)), "bad_form");
  assert.equal(await codeOf(() => verifyAppOpen(open(f0, b.r, b.tk), w.app)), "unauthenticated", "burned by the mismatch");
  // an invalid record burns it too (the record is checked independently, after the token)
  const c = await fresh();
  const tampered = open(f0, c.r, c.tk);
  tampered.headers["sagebrush-browser-record"] = b64(Uint8Array.from(sess.record, (x, i) => (i === sess.record.length - 5 ? x ^ 1 : x)));
  assert.notEqual(await codeOf(() => verifyAppOpen(tampered, w.app)), "ok");
  assert.equal(await codeOf(() => verifyAppOpen(open(f0, c.r, c.tk), w.app)), "unauthenticated", "burned by the bad record");
  // its expiry, exactly: now < expires_ms
  const d = await fresh(), e = await fresh();
  w.advance(APP_TOKEN_MS - 1);
  assert.equal(await codeOf(() => verifyAppOpen(open(f0, d.r, d.tk), w.app)), "ok", "1 ms before");
  w.advance(1);
  assert.equal(await codeOf(() => verifyAppOpen(open(f0, e.r, e.tk), w.app)), "unauthenticated", "at expires_ms, the row still there");
  const g = await fresh();
  w.advance(APP_TOKEN_MS);
  w.tokens.sweep();
  assert.equal(w.tokens.rows.has(await appTokenKey(g.tk)), false, "swept");
  assert.equal(await codeOf(() => verifyAppOpen(open(f0, g.r, g.tk), w.app)), "unauthenticated", "after its sweep: the same code");
  // another endpoint never takes it: a host open carrying the header leaves the row in place
  const h = await fresh();
  const ho = w.hostOpen(sess);
  ho.headers["sagebrush-relay-token"] = h.tk;
  verifyHostOpen(ho, w.sig);
  assert.equal(w.tokens.rows.has(await appTokenKey(h.tk)), true, "untouched by a host open");
  // two presentations at once: exactly one admitted, one row taken, one request id used
  const both = await Promise.all([codeOf(() => verifyAppOpen(open(f0, h.r, h.tk), w.app)), codeOf(() => verifyAppOpen(open(f0, h.r, h.tk), w.app))]);
  assert.deepEqual(both.sort(), ["ok", "unauthenticated"]);
  // an invalid first presenter burns it for the valid second one
  const k = await fresh();
  const pair = await Promise.all([codeOf(() => verifyAppOpen(open({ ...f0, resume_n: 1 }, k.r, k.tk), w.app)), codeOf(() => verifyAppOpen(open(f0, k.r, k.tk), w.app))]);
  assert.deepEqual(pair, ["bad_form", "unauthenticated"]);
  // the session, read at use: ended with the row still present, then with its rows deleted
  const m = await fresh(), q = await fresh();
  const live = w.app.sessionLive;
  w.app.sessionLive = () => false;
  assert.equal(w.tokens.rows.has(await appTokenKey(m.tk)), true);
  assert.equal(await codeOf(() => verifyAppOpen(open(f0, m.r, m.tk), w.app)), "unauthenticated", "a session ended, its row present");
  w.app.sessionLive = live;
  w.logout();
  assert.equal(w.tokens.rows.has(await appTokenKey(q.tk)), false, "logout deletes the session's rows");
  assert.equal(await codeOf(() => verifyAppOpen(open(f0, q.r, q.tk), w.app)), "unauthenticated", "after logout");
  // the canary: no refusal's text carries a token
  for (const tk of tokensUsed) assert.ok(seen.every((m) => !m.includes(tk) && !m.includes(tk.slice(4))), "a token in a refusal's text");
});

/** One whole handshake through the relay: opens, message 1, the compare-and-set, the authorization, message 2. */
async function connect(w, sess, resume_n = 0, { authorize = true } = {}) {
  const hv = verifyHostOpen(w.hostOpen(sess, resume_n), w.sig);
  const av = await verifyAppOpen(w.appOpen(sess, resume_n), w.app);
  const appSock = w.relay.open(av), hostSock = w.relay.open(hv);
  const p = { fleet: w.fleet, aud: AUD, session: sess.body.session, host: w.host, agent: w.agent, browser_gen: sess.body.browser_gen, host_gen: 3, resume_n };
  const I = initiator({ s: sess.app, rs: w.encKey.raw, prologue: prologueBytes(p) });
  const got = new Promise((ok) => { hostSock.onmessage = ok; });
  appSock.send(I.writeMessage1(sess.record));
  const m1 = await got;
  let a;
  try {
    a = await acceptMessage1(m1, { self: { host: w.host, aud: AUD, fleet: w.fleet }, prologue: p, encKey: w.encKey, cert: w.cert, chain: w.chain, store: w.store, now: NOW, live: () => {} });
  } catch (e) {
    hostSock.close(); // (as the host end does: a refused candidate is closed, which removes it and nothing else)
    throw e;
  }
  if (!authorize) return { appSock, hostSock, a, I, hv, av };
  const auth = signCommit({ fleet: w.fleet, session: sess.body.session, agent: w.agent, browser_gen: sess.body.browser_gen, resume_n, host_nonce: hv.nonce, app_request: av.request },
    { aud: AUD, host: w.host, key: w.H, gen: 3, ts: NOW, nonce: nonce() });
  w.relay.commit(verifyCommit(auth, w.sig));
  const r2 = a.reply();
  const back = new Promise((ok) => { appSock.onmessage = ok; });
  hostSock.send(r2.message);
  const i2 = I.readMessage2(await back);
  return { appSock, hostSock, a, I, i2, r2, auth };
}

test("through the fake relay: opens, message 1, the durable compare-and-set, the replacement authorization, then message 2", async (t) => {
  const w = await world(t);
  const sess = w.session({ browser_gen: 4 });
  const c = await connect(w, sess);
  assert.ok(w.relay.active(w.tuple(sess)), "switched to active once authorized");
  assert.deepEqual(JSON.parse(new TextDecoder().decode(c.i2.payload)), { browser_gen: 4, host_gen: 3, resume_n: 0 });
  // after the switch, transport messages pass both ways
  const got = new Promise((ok) => { c.hostSock.onmessage = ok; });
  c.appSock.send(c.i2.send.encrypt(new Uint8Array(0), Uint8Array.of(5)));
  assert.deepEqual(c.r2.receive.decrypt(new Uint8Array(0), await got), Uint8Array.of(5));
  assert.equal(await code(() => w.relay.commit(verifyCommit(c.auth, { ...w.sig, consumeNonce: () => true }))), "replay", "the authorization again: no effect");
});

test("H4: a candidate that fails Noise or loses the compare-and-set never closes or blocks the active pair; the winner switches once", async (t) => {
  const w = await world(t);
  const one = w.session({ browser_gen: 4 });
  const live = await connect(w, one);
  const closed = [];
  live.appSock.onclose = (code) => closed.push(code);
  // a higher-resume_n candidate whose message 1 fails Noise (a wrong app key)
  const hv = verifyHostOpen(w.hostOpen(one, 1), w.sig), av = await verifyAppOpen(w.appOpen(one, 1), w.app);
  const a1 = w.relay.open(av), h1 = w.relay.open(hv);
  const p1 = { fleet: w.fleet, aud: AUD, session: one.body.session, host: w.host, agent: w.agent, browser_gen: 4, host_gen: 3, resume_n: 1 };
  const got = new Promise((ok) => { h1.onmessage = ok; });
  a1.send(initiator({ s: x25519Generate(), rs: w.encKey.raw, prologue: prologueBytes(p1) }).writeMessage1(one.record));
  assert.equal(await code(async () => acceptMessage1(await got, { self: { host: w.host, aud: AUD, fleet: w.fleet }, prologue: p1, encKey: w.encKey, cert: w.cert, chain: w.chain, store: w.store, now: NOW, live: () => {} })), "bad_signature");
  h1.close(); // (the host end closes a refused candidate)
  await tick();
  assert.deepEqual(closed, [], "the active pair is untouched");
  assert.ok(w.relay.active(w.tuple(one)));
  // a higher-browser_gen candidate that loses the compare-and-set (the store already holds a higher one)
  w.store.commit((st) => { st.agents[w.agent].high = 9; });
  const two = w.session({ browser_gen: 6 });
  assert.equal(await code(() => connect(w, two)), "browser_gen_stale");
  await tick();
  assert.deepEqual(closed, [], "still untouched");
  // the winner: a higher browser_gen that commits, then is authorized: the old pair closes, once
  const three = w.session({ browser_gen: 10 });
  await connect(w, three);
  await tick();
  assert.deepEqual(closed, [4000], "replaced, once");
  assert.equal(w.relay.active(w.tuple(one)), null);
  assert.ok(w.relay.active(w.tuple(three)));
});

test("H1: only the candidate's own host, at its host_gen, can switch it: a genuine authorization from another host or gen changes nothing", async (t) => {
  const w = await world(t);
  const one = w.session({ browser_gen: 4 });
  const live = await connect(w, one);
  const closed = [];
  live.appSock.onclose = (x) => closed.push(x);
  // a candidate for the same agent (a higher browser_gen), up to its compare-and-set but not yet authorized
  const two = w.session({ browser_gen: 5 });
  const c = await connect(w, two, 0, { authorize: false });
  const body = { fleet: w.fleet, session: two.body.session, agent: w.agent, browser_gen: 5, resume_n: 0, host_nonce: c.hv.nonce, app_request: c.av.request };
  // another host: its own key, genuinely signed, accepted by the relay's signature check, naming this candidate
  const otherHost = newId(), otherKey = key();
  const otherSig = { ...w.sig, hostKey: (h) => (h === otherHost ? otherKey.raw : w.H.raw) };
  const foreign = signCommit(body, { aud: AUD, host: otherHost, key: otherKey, gen: 3, ts: NOW, nonce: nonce() });
  assert.equal(await code(() => w.relay.commit(verifyCommit(foreign, otherSig))), "not_found", "signed by another host");
  // the right host, but at another generation (its gen moved on since the candidate opened)
  const later = signCommit(body, { aud: AUD, host: w.host, key: w.H, gen: 4, ts: NOW, nonce: nonce() });
  assert.equal(await code(() => w.relay.commit(verifyCommit(later, { ...w.sig, currentGen: () => 4 }))), "not_found", "signed at another host_gen");
  // a field of the body that isn't the candidate's
  const wrongResume = signCommit({ ...body, resume_n: 1 }, { aud: AUD, host: w.host, key: w.H, gen: 3, ts: NOW, nonce: nonce() });
  assert.equal(await code(() => w.relay.commit(verifyCommit(wrongResume, w.sig))), "not_found", "another resume_n");
  await tick();
  assert.deepEqual(closed, [], "the active pair is untouched");
  assert.ok(w.relay.active(w.tuple(one)));
  // and the candidate's own host, at its gen, switches it
  w.relay.commit(verifyCommit(signCommit(body, { aud: AUD, host: w.host, key: w.H, gen: 3, ts: NOW, nonce: nonce() }), w.sig));
  await tick();
  assert.deepEqual(closed, [4000]);
  assert.ok(w.relay.active(w.tuple(two)));
});

test("r4.1: identity is the full tuple: another host's, agent's or host_gen's open never pairs with a candidate, and a commit never reaches it", async (t) => {
  const w = await world(t);
  const sess = w.session({ browser_gen: 3 });
  const av = await verifyAppOpen(w.appOpen(sess), w.app);
  w.relay.open(av);
  const hv = verifyHostOpen(w.hostOpen(sess), w.sig);
  const strays = [{ ...hv, host: newId() }, { ...hv, agent: newId() }];
  const socks = strays.map((x) => w.relay.open(x)); // (each lands in a slot of its own tuple)
  assert.equal(await code(() => w.relay.open({ ...hv, host_gen: 4 })), "in_progress", "the same tuple at another host_gen");
  const host = w.relay.open(hv);
  // the strays never pair: a message from one has no peer and closes only its own slot
  const strayClosed = [], candClosed = [];
  socks[0].onclose = (x) => strayClosed.push(x);
  host.onclose = (x) => candClosed.push(x);
  socks[0].send(Uint8Array.of(1));
  await tick();
  assert.deepEqual([strayClosed, candClosed], [[1008], []]);
  // a commit for another agent's tuple, signed by this host, names no candidate
  const body = { fleet: w.fleet, session: sess.body.session, agent: newId(), browser_gen: 3, resume_n: 0, host_nonce: hv.nonce, app_request: av.request };
  assert.equal(await code(() => w.relay.commit(verifyCommit(signCommit(body, { aud: AUD, host: w.host, key: w.H, gen: 3, ts: NOW, nonce: nonce() }), w.sig))), "not_found", "another agent");
  // an authorization naming an earlier candidate's opens, for the same tuple: nothing
  const earlier = { ...body, agent: w.agent, host_nonce: nonce() };
  assert.equal(await code(() => w.relay.commit(verifyCommit(signCommit(earlier, { aud: AUD, host: w.host, key: w.H, gen: 3, ts: NOW, nonce: nonce() }), w.sig))), "not_found", "another candidate's open");
  assert.equal(w.relay.active(w.tuple(sess)), null, "nothing switched");
});

test("a switch closes only that host's and agent's other sockets: another agent's active pair on the same host is untouched", async (t) => {
  const w = await world(t);
  const mine = await connect(w, w.session({ browser_gen: 2 }));
  // another agent of the same host and fleet, with its own active pair
  const otherAgent = newId();
  const w2 = { ...w, agent: otherAgent, sig: { ...w.sig, agentHasBrowser: () => true } };
  w2.fields = (sess, role, resume_n = 0) => ({ role, fleet: w.fleet, session: sess.body.session, agent: otherAgent, browser_gen: sess.body.browser_gen, host_gen: 3, resume_n });
  w2.hostOpen = (sess, resume_n = 0) => {
    const target = openTarget(w2.fields(sess, "host", resume_n));
    return { target, headers: { "sagebrush-sig": signRequest({ aud: AUD, method: "GET", target, host: w.host, key: w.H, fields: { gen: 3, ts: NOW, nonce: nonce() } }) } };
  };
  w2.appOpen = (sess, resume_n = 0) => {
    const f = w2.fields(sess, "app", resume_n), request = nonce();
    return { target: openTarget(f), headers: { "sagebrush-relay-token": w.mint(f, request), "sagebrush-browser-record": b64(sess.record), "sagebrush-request": request } };
  };
  const theirs = await connect(w2, w.session({ browser_gen: 2, agent: otherAgent }));
  const closed = [];
  theirs.appSock.onclose = (x) => closed.push(x);
  // this agent replaces its own session: its old pair closes, the other agent's stays
  const mineClosed = [];
  mine.appSock.onclose = (x) => mineClosed.push(x);
  await connect(w, w.session({ browser_gen: 3 }));
  await tick();
  assert.deepEqual([mineClosed, closed], [[4000], []]);
});

test("an authorization that fails after the commit: the lost-reply path, never a rollback", async (t) => {
  const w = await world(t);
  const sess = w.session({ browser_gen: 2 });
  const c = await connect(w, sess, 0, { authorize: false });
  assert.equal(await code(() => w.relay.commit({ fleet: w.fleet, session: sess.body.session, agent: w.agent, browser_gen: 2, resume_n: 0, host_nonce: "x".repeat(22), app_request: c.av.request, host: w.host })), "not_found", "an authorization naming no candidate");
  assert.equal(w.store.get().agents[w.agent].live.session, sess.body.session, "the commit stands");
  w.advance(30_000);
  w.relay.sweep();
  assert.equal(w.relay.active(w.tuple(sess)), null, "the candidate expired");
  const r = await connect(w, sess, 1);
  assert.deepEqual(JSON.parse(new TextDecoder().decode(r.i2.payload)).resume_n, 1, "the next attempt is the next resume_n");
});

test("candidates' bounds and the sockets' limits: one per session, two per agent, 30 s; binary only; 65,535 bytes; revocation closes", async (t) => {
  const w = await world(t);
  const a = w.session({ browser_gen: 2 }), b = w.session({ browser_gen: 3 }), c = w.session({ browser_gen: 4 });
  w.relay.open(verifyHostOpen(w.hostOpen(a), w.sig));
  assert.equal(await code(() => w.relay.open(verifyHostOpen(w.hostOpen(a), w.sig))), "in_progress", "a taken side");
  assert.equal(await code(() => w.relay.open(verifyHostOpen(w.hostOpen(a, 1), w.sig))), "in_progress", "another candidate for the session");
  w.relay.open(verifyHostOpen(w.hostOpen(b), w.sig));
  assert.equal(await code(() => w.relay.open(verifyHostOpen(w.hostOpen(c), w.sig))), "limit", "a third pending candidate for the agent");
  w.advance(30_000);
  assert.equal(await code(() => w.relay.open(verifyHostOpen(w.hostOpen(c), w.sig))), "ok", "after the first two expired");
  // a candidate pair passes only message 1 (app to host), then message 2 (host to app): nothing else, in no other order
  for (const misuse of ["host first", "a third message"]) {
    const sx = w.session({ browser_gen: 20 + (misuse === "host first" ? 0 : 1) });
    const hs = w.relay.open(verifyHostOpen(w.hostOpen(sx), w.sig)), as = w.relay.open(await verifyAppOpen(w.appOpen(sx), w.app));
    const closedWith = [];
    as.onclose = (x) => closedWith.push(x);
    if (misuse === "host first") hs.send(Uint8Array.of(1));
    else { as.send(Uint8Array.of(1)); hs.send(Uint8Array.of(2)); as.send(Uint8Array.of(3)); }
    await tick();
    assert.deepEqual(closedWith, [1008], misuse);
  }
  w.advance(30_000);
  // limits on an active pair
  const s1 = w.session({ browser_gen: 7 });
  const live = await connect(w, s1);
  const codes = [];
  live.appSock.onclose = (x) => codes.push(x);
  live.hostSock.send("text");
  await tick();
  assert.deepEqual(codes, [1003], "binary only");
  const s2 = w.session({ browser_gen: 8 });
  const live2 = await connect(w, s2);
  const codes2 = [];
  live2.hostSock.onclose = (x) => codes2.push(x);
  live2.appSock.send(new Uint8Array(65536));
  await tick();
  assert.deepEqual(codes2, [1009], "over 65,535 bytes");
  const s4 = w.session({ browser_gen: 10 });
  const live4 = await connect(w, s4);
  const codes4 = [];
  live4.hostSock.onclose = (x) => codes4.push(x);
  for (let i = 0; i < 17; i++) live4.appSock.send(new Uint8Array(65535)); // (sent before the peer can drain: over 1 MiB queued)
  await tick();
  assert.deepEqual(codes4, [1009], "more than 1 MiB queued in one direction");
  const s3 = w.session({ browser_gen: 11 });
  const live3 = await connect(w, s3);
  const codes3 = [];
  live3.appSock.onclose = (x) => codes3.push(x);
  w.relay.revoke(w.agent);
  await tick();
  assert.deepEqual(codes3, [4001], "a revocation closes both ends");
});
