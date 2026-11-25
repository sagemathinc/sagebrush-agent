// The fleet Worker's relay endpoints as pure handlers (lib/fleet/core/worker.mjs): the app-token issuer (channel
// addendum A1 §2), /relay/admit and /relay/epochs (relay design r2.2 §3, §5), against an in-memory state that follows
// the module's store contract. Every control answer is checked with the relay's own verifier (verifyControlAnswer),
// and every app open goes through a token the issuer gave. A fake can't prove the real store's atomicity: the contract
// in worker.mjs is what the Worker's store is reviewed against.
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { test } from "node:test";
import { FleetError, b64, enc, newId, keyFromSeed, seal, applyChainEntry as apply } from "../lib/fleet/index.mjs";
import { signRequest } from "../lib/fleet/request.mjs";
import { canonText } from "../lib/fleet/core/canonical.mjs";
import { ADMIT_ROUTE, AUTH_HEADER, epochsTarget, signControlRequest, verifyControlAnswer, verifyControlRequest } from "../lib/fleet/core/control.mjs";
import { APP_TOKEN, APP_TOKEN_MS, APP_TOKEN_ROUTE, COMMIT_ROUTE, appTokenKey, appTokenRequest, commitBody, openTarget } from "../lib/fleet/core/relay.mjs";
import { APP_TOKEN_RATE, handleAppToken, handleControl } from "../lib/fleet/core/worker.mjs";

const AUD = "https://dev.sagebrush.space";
const NOW = 1_800_000_000_000;
const KEY = new Uint8Array(32).map((_, i) => i + 3);
const nonce = () => b64(randomBytes(16));
const text = (b) => new TextDecoder().decode(b);
let n = 200;
const key = () => keyFromSeed(new Uint8Array(32).fill(n++));

/** A fleet's state as the Worker would hold it, in memory, following worker.mjs's contract; and helpers to call. */
async function world() {
  const fleet = newId(), host = newId(), agent = newId(), account = "acct-1", accountSession = "sess-1";
  const N = key(), nId = newId(), rec = key(), H = key();
  const sN = { kind: "device", id: nId, alg: "ed25519", key: N.key };
  const genesis = seal("sb.device-chain.v1", sN, { fleet, aud: AUD, seq: 0, prev: "", op: "genesis", at_ms: 1, auth_time_ms: 1,
    device: { id: nId, alg: "ed25519", key: b64(N.raw), name: "mac", tier: "native" }, recovery_key: { alg: "ed25519", key: b64(rec.raw) } }, N);
  const chain = (await apply(null, genesis, { aud: AUD, fleet })).state;
  const st = {
    now: NOW,
    sessions: new Map([[`${account}/${accountSession}`, { expires_ms: NOW + 3_600_000 }]]),
    fleets: new Map([[fleet, account]]),
    hosts: new Map([[host, { fleet, sign_key: H.raw, gen: 3, revoked: false, grant_not_after_ms: null }]]),
    agents: new Map([[`${host}/${agent}`, { browser: true, revoked: false }]]),
    rows: new Map(), calls: new Set(), counts: new Map(),
    feedAnswer: (since) => ({ cursor: since + 1, at_ms: NOW, more: false, agents: [], accounts: [], hosts: [] }),
  };
  const ctx = (over = {}) => ({
    aud: AUD, get now() { return st.now; }, controlKey: KEY,
    requestSession: { account, account_session: accountSession },
    session: async (a, s) => st.sessions.get(`${a}/${s}`) ?? null,
    accountOf: async (f) => st.fleets.get(f) ?? null,
    chain: async (f) => (f === fleet ? chain : null),
    host: async (h) => st.hosts.get(h) ?? null,
    agent: async (h, a) => st.agents.get(`${h}/${a}`) ?? null,
    epochs: async () => ({ account: 1, agent: 2, host: 3 }),
    feed: async (since) => st.feedAnswer(since),
    consumeCallId: async (id) => (st.calls.has(id) ? false : (st.calls.add(id), true)),
    tokens: {
      put: async (k, row) => (st.rows.has(k) ? false : (st.rows.set(k, row), true)),
      take: async (k) => { const r = st.rows.get(k) ?? null; st.rows.delete(k); return r; },
      dropSession: async (s) => { for (const [k, r] of [...st.rows]) if (r.account_session === s) st.rows.delete(k); },
      sweep: async (now) => { for (const [k, r] of [...st.rows]) if (r.expires_ms <= now) st.rows.delete(k); },
    },
    bucket: async (k, limit) => { const c = (st.counts.get(k) ?? 0) + 1; st.counts.set(k, c); return c <= limit; },
    ...over,
  });
  const session = (extra = {}) => {
    const body = { fleet, aud: AUD, at_ms: NOW - 1000, not_before_ms: NOW - 1000, not_after_ms: NOW + 600_000, session: newId(), host, agent,
      browser_gen: 1, host_gen: 3, chain_seq: 0, app_session_pub: b64(new Uint8Array(32).fill(9)), account_origins_manifest_sha256: b64(new Uint8Array(32).fill(1)),
      exceptions_sha256: b64(new Uint8Array(32).fill(2)), ...extra };
    return { body, record: seal("sb.browser-session.v1", sN, body, N) };
  };
  const fields = (s, role, resume_n = 0) => ({ role, fleet, session: s.body.session, agent, browser_gen: s.body.browser_gen, host_gen: 3, resume_n });
  /** The issuer, as the app calls it. */
  const issue = async (s, request, c = ctx(), over = {}) => {
    const { role, ...f } = fields(s, "app");
    return handleAppToken({ method: "POST", target: APP_TOKEN_ROUTE, body: appTokenRequest({ ...f, host, request, ...over }) }, c);
  };
  /** One control call, signed as the relay signs it; returns { status, value } with the answer verified as the relay does. */
  const call = async (method, target, bodyValue, c = ctx(), { ts = st.now, id = nonce(), keyUsed = KEY } = {}) => {
    const body = bodyValue === undefined ? new Uint8Array(0) : enc(canonText(bodyValue));
    const header = await signControlRequest({ key: keyUsed, method, target, body, ts, id });
    const r = await handleControl({ method, target, headers: { [AUTH_HEADER]: header }, body }, c);
    if (r.status !== 200) return { status: r.status, bodyText: text(r.body) };
    const verified = await verifyControlRequest({ header, method, target, body }, { key: KEY, now: st.now });
    const value = await verifyControlAnswer({ header: r.headers["sagebrush-relay-answer"], status: r.status, body: r.body }, { key: KEY, call: verified, answer: target === ADMIT_ROUTE ? "admit" : "epochs" });
    return { status: 200, value, headers: r.headers };
  };
  const appAdmit = async (s, token, request, c, resume_n = 0) =>
    call("POST", ADMIT_ROUTE, { v: 1, kind: "app", target: openTarget(fields(s, "app", resume_n)), record: b64(s.record), request, token }, c);
  const hostSig = (target, method = "GET", body = new Uint8Array(0), gen = 3) => signRequest({ aud: AUD, method, target, body, host, key: H, fields: { gen, ts: st.now, nonce: nonce() } });
  const hostAdmit = async (s, c, gen) => { const t = openTarget(fields(s, "host")); return call("POST", ADMIT_ROUTE, { v: 1, kind: "host", target: t, sig: hostSig(t, "GET", undefined, gen) }, c); };
  const commitAdmit = async (s, c) => {
    const b = commitBody({ fleet, session: s.body.session, agent, browser_gen: 1, resume_n: 0, host_nonce: nonce(), app_request: nonce() });
    return call("POST", ADMIT_ROUTE, { v: 1, kind: "commit", target: COMMIT_ROUTE, sig: hostSig(COMMIT_ROUTE, "POST", b), body: b64(b) }, c);
  };
  return { fleet, host, agent, account, accountSession, st, ctx, session, issue, call, appAdmit, hostAdmit, commitAdmit };
}

const err = (r) => JSON.parse(text(r.body)).error;

test("the issuer (A1 §2): a token for one open, its row under its hash only, no-store; each refusal in order, nothing stored", async () => {
  const w = await world();
  const s = w.session(), request = nonce();
  const r = await w.issue(s, request);
  assert.equal(r.status, 200);
  assert.equal(r.headers["cache-control"], "no-store");
  const { token, expires_ms } = JSON.parse(text(r.body));
  assert.deepEqual(Object.keys(JSON.parse(text(r.body))).sort(), ["expires_ms", "token"], "the answer is the token and its expiry, nothing else");
  assert.match(token, APP_TOKEN);
  assert.equal(expires_ms, NOW + APP_TOKEN_MS);
  const row = w.st.rows.get(await appTokenKey(token));
  assert.deepEqual(row, { account: w.account, account_session: w.accountSession, fleet: w.fleet, host: w.host, agent: w.agent, browser_gen: 1, session: s.body.session, host_gen: 3, resume_n: 0, request, expires_ms });
  assert.ok(![...w.st.rows.keys(), ...w.st.rows.values()].some((v) => JSON.stringify(v).includes(token.slice(4))), "the token itself is kept nowhere");
  assert.equal((await handleAppToken({ method: "POST", target: "/other", body: new Uint8Array(0) }, w.ctx())).status, 404);
  assert.equal((await handleAppToken({ method: "GET", target: APP_TOKEN_ROUTE, body: new Uint8Array(0) }, w.ctx())).status, 405);

  const before = w.st.rows.size, spent = JSON.stringify([...w.st.counts]);
  const refused = async (why, want, status, c = w.ctx(), over = {}, body) => {
    const x = body ? await handleAppToken({ method: "POST", target: APP_TOKEN_ROUTE, body }, c) : await w.issue(s, nonce(), c, over);
    assert.deepEqual([x.status, err(x)], [status, want], why);
    assert.equal(x.headers["cache-control"], "no-store", why);
  };
  await refused("no session", "unauthenticated", 401, w.ctx({ requestSession: null }));
  await refused("a session that isn't live", "unauthenticated", 401, w.ctx({ session: async () => null }));
  await refused("no session, and a bad body: the session first", "unauthenticated", 401, w.ctx({ requestSession: null }), {}, enc("{}"));
  await refused("an extra field", "bad_form", 400, w.ctx(), {}, enc(canonText({ ...JSON.parse(text(appTokenRequest({ fleet: w.fleet, host: w.host, agent: w.agent, browser_gen: 1, session: s.body.session, host_gen: 3, resume_n: 0, request: nonce() }))), extra: 1 })));
  await refused("not canonical", "bad_form", 400, w.ctx(), {}, enc(JSON.stringify({ fleet: w.fleet }, null, 1)));
  await refused("over 1 KiB", "bad_form", 400, w.ctx(), {}, new Uint8Array(1025).fill(32));
  await refused("another account's fleet", "not_granted", 403, w.ctx(), { fleet: newId() });
  await refused("an unpaired host", "unknown_host", 401, w.ctx(), { host: newId() });
  const other = newId();
  w.st.hosts.set(other, { fleet: newId(), sign_key: new Uint8Array(32), gen: 3, revoked: false, grant_not_after_ms: null });
  await refused("another fleet's host", "unknown_host", 401, w.ctx(), { host: other });
  w.st.hosts.get(w.host).revoked = true;
  await refused("a revoked host", "host_revoked", 403);
  w.st.hosts.get(w.host).revoked = false;
  await refused("a stale host_gen", "stale_generation", 409, w.ctx(), { host_gen: 2 });
  await refused("an agent not in the grant", "not_granted", 403, w.ctx(), { agent: newId() });
  w.st.agents.get(`${w.host}/${w.agent}`).browser = false;
  await refused("an agent without the browser", "not_granted", 403);
  w.st.agents.get(`${w.host}/${w.agent}`).browser = true;
  w.st.agents.get(`${w.host}/${w.agent}`).revoked = true;
  await refused("a revoked agent", "not_granted", 403);
  w.st.agents.get(`${w.host}/${w.agent}`).revoked = false;
  assert.equal(w.st.rows.size, before, "nothing stored on any refusal");
  assert.equal(JSON.stringify([...w.st.counts]), spent, "no bucket spent by a refusal before it");
  const boom = await w.issue(s, nonce(), w.ctx({ tokens: { put: async () => { throw new Error("db down: SECRET"); } } }));
  assert.deepEqual([boom.status, boom.body.length], [500, 0], "an internal error: a bare 500, no message");
});

test("the issuer's bucket: 30 a minute per account session, the 31st refused rate with nothing stored; another session unaffected", async () => {
  const w = await world();
  const s = w.session();
  for (let i = 0; i < APP_TOKEN_RATE.limit; i++) assert.equal((await w.issue(s, nonce())).status, 200, `token ${i + 1}`);
  const size = w.st.rows.size;
  const r = await w.issue(s, nonce());
  assert.deepEqual([r.status, err(r)], [429, "rate"]);
  assert.equal(w.st.rows.size, size);
  w.st.sessions.set(`${w.account}/sess-2`, { expires_ms: NOW + 1000 });
  assert.equal((await w.issue(s, nonce(), w.ctx({ requestSession: { account: w.account, account_session: "sess-2" } }))).status, 200);
});

test("control calls: the route, the method, the relay's MAC, the 60 s window and the call id once; each a bare status, nothing signed", async () => {
  const w = await world();
  const ok = await w.call("GET", epochsTarget(0), undefined);
  assert.equal(ok.status, 200);
  const bareOf = async (p) => { const r = await p; assert.equal(r.bodyText, "", "a bare status"); return r.status; };
  assert.equal(await bareOf(w.call("GET", "/api/fleet/v1/relay/other", undefined)), 404);
  assert.equal(await bareOf(w.call("GET", `${epochsTarget(0)}&x=1`, undefined)), 404);
  assert.equal(await bareOf(w.call("GET", ADMIT_ROUTE, undefined)), 405);
  assert.equal(await bareOf(w.call("POST", epochsTarget(0), {})), 405);
  assert.equal(await bareOf(w.call("GET", epochsTarget(0), undefined, w.ctx(), { keyUsed: new Uint8Array(32).fill(9) })), 401, "another key");
  assert.equal(await bareOf(w.call("GET", epochsTarget(0), undefined, w.ctx(), { ts: NOW - 60_001 })), 401, "61 s off");
  assert.equal((await w.call("GET", epochsTarget(0), undefined, w.ctx(), { ts: NOW - 60_000 })).status, 200, "60 s off, at the bound");
  const id = nonce();
  assert.equal((await w.call("GET", epochsTarget(0), undefined, w.ctx(), { id })).status, 200);
  assert.equal(await bareOf(w.call("GET", epochsTarget(0), undefined, w.ctx(), { id })), 401, "the same call id again");
  const r = await handleControl({ method: "GET", target: epochsTarget(0), headers: {}, body: new Uint8Array(0) }, w.ctx());
  assert.equal(r.status, 401, "no auth header");
  const big = await handleControl({ method: "POST", target: ADMIT_ROUTE, headers: {}, body: new Uint8Array(128 * 1024 + 1) }, w.ctx());
  assert.equal(big.status, 413, "a body over 128 KiB, before the MAC");
});

test("admit, app: issue then admit, the answer's facts; the token taken once; logout, a revoked agent or host, and a lost fleet each refuse", async () => {
  const w = await world();
  const s = w.session();
  const request = nonce();
  const { token } = JSON.parse(text((await w.issue(s, request)).body));
  const a = await w.appAdmit(s, token, request);
  assert.equal(a.status, 200);
  const { call, call_sha256, v, ...facts } = a.value;
  assert.deepEqual(Object.keys(facts).sort(), ["account", "account_session", "account_session_expires_ms", "agent", "answer", "browser_gen", "chain_seq", "epochs", "fleet", "host", "host_gen", "request", "result", "resume_n", "role", "session", "signer"].concat("not_after_ms").sort());
  assert.deepEqual([facts.result, facts.role, facts.host, facts.request, facts.account, facts.account_session, facts.account_session_expires_ms, facts.not_after_ms],
    ["ok", "app", w.host, request, w.account, w.accountSession, NOW + 3_600_000, NOW + 600_000]);
  const again = await w.appAdmit(s, token, request);
  assert.deepEqual([again.value.result, again.value.code], ["refused", "unauthenticated"], "the token again, in a new call");

  const sess = w.st.sessions.get(`${w.account}/${w.accountSession}`);
  // (the issuer checks the session too: these change the state after the issue, as a logout or a revocation does)
  const issuedThen = async (why, want, change, undo) => {
    const rq = nonce(); const { token: tk } = JSON.parse(text((await w.issue(s, rq)).body));
    change();
    const r = await w.appAdmit(s, tk, rq);
    undo();
    assert.deepEqual([r.value.result, r.value.code], ["refused", want], why);
    assert.equal(w.st.rows.has(await appTokenKey(tk)), false, `${why}: the token was taken`);
  };
  await issuedThen("logged out after the issue", "unauthenticated", () => w.st.sessions.delete(`${w.account}/${w.accountSession}`), () => w.st.sessions.set(`${w.account}/${w.accountSession}`, sess));
  const ag = w.st.agents.get(`${w.host}/${w.agent}`);
  await issuedThen("the agent revoked after the issue", "agent_revoked", () => { ag.revoked = true; }, () => { ag.revoked = false; });
  await issuedThen("the agent's browser removed after the issue", "not_granted", () => { ag.browser = false; }, () => { ag.browser = true; });
  const h = w.st.hosts.get(w.host);
  await issuedThen("the host revoked after the issue", "host_revoked", () => { h.revoked = true; }, () => { h.revoked = false; });
  await issuedThen("a newer host_gen after the issue", "stale_generation", () => { h.gen = 4; }, () => { h.gen = 3; });
  await issuedThen("the fleet now another account's", "not_granted", () => w.st.fleets.set(w.fleet, "acct-2"), () => w.st.fleets.set(w.fleet, w.account));
  await issuedThen("the token past its expiry", "unauthenticated", () => { w.st.now = NOW + APP_TOKEN_MS; }, () => { w.st.now = NOW; });
  const unknown = await w.appAdmit(s, `rt1.${b64(randomBytes(32))}`, nonce());
  assert.deepEqual([unknown.value.result, unknown.value.code], ["refused", "unauthenticated"], "a token never issued");
});

test("admit, app: two admits presenting one token at once: exactly one ok, one unauthenticated, and the row taken", async () => {
  const w = await world();
  const s = w.session(), request = nonce();
  const { token } = JSON.parse(text((await w.issue(s, request)).body));
  const both = await Promise.all([w.appAdmit(s, token, request), w.appAdmit(s, token, request)]);
  assert.deepEqual(both.map((b) => b.value.result === "ok" ? "ok" : b.value.code).sort(), ["ok", "unauthenticated"]);
  assert.equal(w.st.rows.size, 0);
});

test("admit, host and commit: the answer's facts; a revoked host or agent, a stale gen, another fleet's host refuse", async () => {
  const w = await world();
  const s = w.session();
  const h = await w.hostAdmit(s);
  assert.deepEqual([h.value.result, h.value.role, h.value.host, h.value.account, h.value.not_after_ms, h.value.host_gen], ["ok", "host", w.host, w.account, null, 3]);
  const c = await w.commitAdmit(s);
  assert.deepEqual([c.value.result, c.value.role, c.value.host, c.value.account, c.value.host_gen], ["ok", "commit", w.host, w.account, 3]);
  const code = (r) => (r.value.result === "ok" ? "ok" : r.value.code);
  const hs = w.st.hosts.get(w.host), ag = w.st.agents.get(`${w.host}/${w.agent}`);
  hs.revoked = true; assert.equal(code(await w.hostAdmit(s)), "host_revoked"); assert.equal(code(await w.commitAdmit(s)), "host_revoked"); hs.revoked = false;
  ag.revoked = true; assert.equal(code(await w.hostAdmit(s)), "agent_revoked"); assert.equal(code(await w.commitAdmit(s)), "agent_revoked"); ag.revoked = false;
  ag.browser = false; assert.equal(code(await w.hostAdmit(s)), "not_granted"); ag.browser = true;
  assert.equal(code(await w.hostAdmit(s, w.ctx(), 2)), "stale_generation", "signed at an older gen");
  hs.fleet = newId(); assert.equal(code(await w.hostAdmit(s)), "unknown_host", "the host is another fleet's");
  assert.equal(code(await w.commitAdmit(s)), "unknown_host", "a commit for a fleet the host isn't in"); hs.fleet = w.fleet;
  hs.grant_not_after_ms = NOW + 5; assert.equal((await w.hostAdmit(s)).value.not_after_ms, NOW + 5, "the grant's end"); hs.grant_not_after_ms = null;
  w.st.fleets.delete(w.fleet); assert.equal(code(await w.hostAdmit(s)), "not_granted", "a fleet without an account"); w.st.fleets.set(w.fleet, w.account);
});

test("epochs: the feed's answer, cursor_expired for a since not kept, and a store answer the schema refuses is a bare 500", async () => {
  const w = await world();
  const ok = await w.call("GET", epochsTarget(7), undefined);
  assert.deepEqual([ok.value.result, ok.value.since, ok.value.cursor], ["ok", 7, 8]);
  w.st.feedAnswer = () => null;
  const gone = await w.call("GET", epochsTarget(7), undefined);
  assert.deepEqual([gone.value.result, gone.value.code], ["refused", "cursor_expired"]);
  w.st.feedAnswer = (since) => ({ cursor: since, at_ms: NOW, more: false, agents: [], accounts: [], hosts: [] });
  assert.equal((await w.call("GET", epochsTarget(7), undefined)).status, 500, "a cursor not ahead of since: nothing signed");
  w.st.feedAnswer = () => { throw new Error("db down"); };
  assert.equal((await w.call("GET", epochsTarget(7), undefined)).status, 500);
});

test("admit: a refusal outside the admit list, or an internal error, is a bare 500; a malformed body is refused bad_form", async () => {
  const w = await world();
  const s = w.session();
  const thrown = await w.hostAdmit(s, w.ctx({ agent: async () => { throw new Error("db down"); } }));
  assert.equal(thrown.status, 500);
  const odd = await w.hostAdmit(s, w.ctx({ agent: async () => { throw new FleetError("rate"); } }));
  assert.equal(odd.status, 500, "rate isn't an admit refusal");
  const bad = await w.call("POST", ADMIT_ROUTE, { v: 1, kind: "app" });
  assert.deepEqual([bad.value.result, bad.value.code], ["refused", "bad_form"]);
});
