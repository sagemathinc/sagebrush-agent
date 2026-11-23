// The browser lane's hardening and privileged Fetch handler (lib/fleet/browser/harden.mjs; O11 draft 5.1 §2, §6),
// against a fake CDP. The rows SEC asked for: document navigation, a redirect to the account origin, an explicit port,
// a subdomain, a malformed URL, an auth-source mismatch and a silent handler, plus the rest of the retirement rules.
// (The same rules were run live on a local Chromium: /scratch notes, not part of this suite.)

import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync, readdirSync } from "node:fs";
import { createHardening, blockPatterns, HANDLER_MS, FETCH_PATTERNS, WORKERS } from "../lib/fleet/browser/harden.mjs";
import { accountOrigins, DEFAULT_ACCOUNT_ORIGINS } from "../lib/fleet/browser/urls.mjs";
import { DESCRIPTORS } from "../scripts/fleet-browser-permissions.mjs";
import { PINS } from "../lib/fleet/browser/pins.mjs";

const origins = accountOrigins(DEFAULT_ACCOUNT_ORIGINS);
const BUILD = "158.0.8127.36";
const permissions = { build: BUILD, descriptors: [{ name: "geolocation" }, { name: "camera" }, { name: "fullscreen", allowWithoutGesture: true }] };
const credentials = { username: "sess-user", password: "sess-pass", proxyPort: 40123 };
const PROXY = "http://127.0.0.1:40123";
const settle = async () => { for (let i = 0; i < 5; i++) await new Promise((r) => setImmediate(r)); };

class Clock {
  now = 0; #t = []; #n = 1;
  setTimeout(fn, ms) { const h = this.#n++; this.#t.push({ h, at: this.now + ms, fn }); return h; }
  clearTimeout(h) { this.#t = this.#t.filter((t) => t.h !== h); }
  async advance(ms) { const end = this.now + ms; for (;;) { await settle(); const d = this.#t.filter((t) => t.at <= end).sort((a, b) => a.at - b.at)[0]; if (!d) break; this.#t = this.#t.filter((t) => t !== d); this.now = d.at; d.fn(); } this.now = end; await settle(); }
}

// A fake CDP: `answers[method]` (a value, or a function of params) answers at once; absent, the call waits forever.
function fakeCdp(answers = {}) {
  const calls = [];
  return {
    calls,
    answers: { "Browser.getVersion": { product: `HeadlessChrome/${BUILD}`, protocolVersion: "1.3" }, ...answers },
    send(method, params = {}, sessionId) {
      calls.push({ method, params, sessionId });
      if (!Object.hasOwn(this.answers, method)) return new Promise(() => {});
      const a = this.answers[method];
      try { const v = typeof a === "function" ? a(params) : a; return v instanceof Error ? Promise.reject(v) : Promise.resolve(v); } catch (e) { return Promise.reject(e); }
    },
  };
}
const cdpErr = (code, message) => Object.assign(new Error(message), { code });
const EMPTY = {};
const ALL_EMPTY = { "Browser.setDownloadBehavior": EMPTY, "Browser.resetPermissions": EMPTY, "Browser.setPermission": EMPTY, "Page.setInterceptFileChooserDialog": EMPTY, "Fetch.enable": EMPTY, "Network.setBlockedURLs": EMPTY, "Fetch.continueRequest": EMPTY, "Fetch.failRequest": EMPTY, "Fetch.continueWithAuth": EMPTY };

function setup(answers = {}, opts = {}) {
  const cdp = fakeCdp({ ...ALL_EMPTY, ...answers }), clock = new Clock(), retired = [];
  const h = createHardening({ cdp, credentials, origins, permissions, clock, ...opts });
  h.bind({ retire: (r) => retired.push(r) });
  return { cdp, clock, h, retired };
}
const paused = (requestId, url, extra = {}) => ({ method: "Fetch.requestPaused", sessionId: "SESS-A", params: { requestId, request: { url, method: "GET", headers: {} }, frameId: "F1", resourceType: "Document", ...extra } });
const auth = (requestId, source, origin = PROXY) => ({ method: "Fetch.authRequired", sessionId: "SESS-A", params: { requestId, request: { url: "http://example.test/", method: "GET", headers: {} }, frameId: "F1", resourceType: "Document", authChallenge: { source, origin, scheme: "basic", realm: "sb" } } });
const last = (cdp) => cdp.calls.at(-1);

test("the browser context: downloads denied, permissions reset, every pinned descriptor denied, in order; anything off fails hardening", async () => {
  const { cdp, h } = setup();
  await h.harden({ kind: "browser_context", browserContextId: "CTX" });
  assert.deepEqual(cdp.calls.map((c) => c.method), ["Browser.getVersion", "Browser.setDownloadBehavior", "Browser.resetPermissions", "Browser.setPermission", "Browser.setPermission", "Browser.setPermission"]);
  assert.deepEqual(cdp.calls[1].params, { behavior: "deny", browserContextId: "CTX" });
  assert.deepEqual(cdp.calls.slice(3).map((c) => c.params), permissions.descriptors.map((d) => ({ permission: d, setting: "denied", browserContextId: "CTX" })));
  for (const [what, opts, answers] of [
    ["another build", {}, { "Browser.getVersion": { product: "HeadlessChrome/149.0.7827.196" } }],
    ["no list", { permissions: undefined }, {}],
    ["an empty list", { permissions: { build: BUILD, descriptors: [] } }, {}],
    ["a rejected name", {}, { "Browser.setPermission": (p) => (p.permission.name === "camera" ? cdpErr(-32000, "Invalid PermissionDescriptor name: camera") : EMPTY) }],
    ["a changed response", {}, { "Browser.resetPermissions": { surprise: true } }],
    ["downloads refused", {}, { "Browser.setDownloadBehavior": cdpErr(-32000, "no") }],
  ]) {
    const { h: g } = setup(answers, opts);
    await assert.rejects(g.harden({ kind: "browser_context", browserContextId: "CTX" }), undefined, what);
  }
});

test("page and frame targets: the chooser intercepted, Fetch at the request stage for every URL with auth, blocked URLs (origin and subdomains, any port) as defense in depth", async () => {
  for (const kind of ["page", "iframe"]) {
    const { cdp, h } = setup();
    await h.harden({ kind, sessionId: "SESS-A" });
    assert.deepEqual(cdp.calls.map((c) => [c.method, c.sessionId]), [["Page.setInterceptFileChooserDialog", "SESS-A"], ["Fetch.enable", "SESS-A"], ["Network.setBlockedURLs", "SESS-A"]]);
    assert.deepEqual(cdp.calls[0].params, { enabled: true });
    assert.deepEqual(cdp.calls[1].params, { patterns: [{ urlPattern: "*", requestStage: "Request" }], handleAuthRequests: true });
    assert.deepEqual(cdp.calls[2].params, { urlPatterns: blockPatterns(origins) });
  }
  assert.deepEqual(blockPatterns(["claude.ai"]).map((p) => p.urlPattern), ["*://claude.ai/*", "*://claude.ai:*/*", "*://*.claude.ai/*", "*://*.claude.ai:*/*"]);
  assert.deepEqual(FETCH_PATTERNS, [{ urlPattern: "*", requestStage: "Request" }]);
  for (const answers of [{ "Fetch.enable": cdpErr(-32602, "Can't specify empty patterns with handleAuth set") }, { "Network.setBlockedURLs": cdpErr(-32000, "no") }, { "Page.setInterceptFileChooserDialog": { x: 1 } }]) {
    const { h } = setup(answers);
    await assert.rejects(h.harden({ kind: "page", sessionId: "SESS-A" }));
  }
});

test("workers: blocked URLs where the class has Network (its absence is tolerated: the proxy is their layer); Fetch only for the classes §9 cleared; unknown types fail", async () => {
  assert.deepEqual(WORKERS, ["worker", "shared_worker", "service_worker"]);
  for (const kind of WORKERS) {
    const { cdp, h } = setup();
    await h.harden({ kind, sessionId: "SESS-W" });
    assert.deepEqual(cdp.calls.map((c) => c.method), ["Network.setBlockedURLs"]);
    const none = setup({ "Network.setBlockedURLs": cdpErr(-32601, "'Network.setBlockedURLs' wasn't found") });
    await none.h.harden({ kind, sessionId: "SESS-W" });
    const bad = setup({ "Network.setBlockedURLs": cdpErr(-32000, "no") });
    await assert.rejects(bad.h.harden({ kind, sessionId: "SESS-W" }), undefined, kind);
  }
  const cleared = setup({}, { fetchWorkers: ["service_worker"] });
  await cleared.h.harden({ kind: "service_worker", sessionId: "SESS-SW" });
  assert.deepEqual(cleared.cdp.calls.map((c) => c.method), ["Network.setBlockedURLs", "Fetch.enable"]);
  for (const kind of ["other", "browser", "tab", "auction_worklet", undefined]) await assert.rejects(setup().h.harden({ kind, sessionId: "X" }), undefined, String(kind));
});

test("Fetch: an account origin or its subdomain fails BlockedByClient at any scheme or port, document navigations and redirect hops included; everything else continues", async () => {
  const { cdp, h, retired } = setup();
  const cases = [
    ["J1.0", "https://claude.ai/", "fail"], // (a document navigation)
    ["J2.0", "http://CLAUDE.AI.:8443/x", "fail"], // (an explicit port, case, trailing dot)
    ["J3.0", "https://a.b.claude.ai/", "fail"], // (a subdomain)
    ["J4.0", "wss://chatgpt.com/socket", "fail"],
    ["J5.0", "https://claude.ai%2e/", "fail"],
    ["J6.0", "https://example.test/redir", "continue"],
    ["J6.1", "http://claude.ai:41000/landed", "fail", { redirectedRequestId: "J6.0" }], // (the redirect hop: a new id, checked again)
    ["J7.0", "https://claude.ai.evil.test/", "continue"],
    ["J8.0", "https://notclaude.ai/", "continue"],
    ["J9.0", "https://github.com/", "continue"],
  ];
  for (const [id, url, want, extra] of cases) {
    h.privileged(paused(id, url, extra));
    const c = last(cdp);
    assert.equal(c.params.requestId, id, url);
    assert.equal(c.sessionId, "SESS-A");
    if (want === "fail") assert.deepEqual([c.method, c.params.errorReason], ["Fetch.failRequest", "BlockedByClient"], url);
    else assert.deepEqual([c.method, Object.keys(c.params)], ["Fetch.continueRequest", ["requestId"]], url);
  }
  await settle();
  assert.deepEqual(retired, []);
});

test("Fetch: the session retires on a malformed URL, an unexpected scheme or stage, or a duplicate request id", async () => {
  for (const [what, ev] of [
    ["malformed", paused("M1.0", "http://exa mple.com/")],
    ["no URL", paused("M2.0", undefined)],
    ["file scheme", paused("M3.0", "file:///etc/passwd")],
    ["data scheme", paused("M4.0", "data:text/html,x")],
    ["an uncomparable host", paused("M5.0", "https://claude.ai../")],
    ["the response stage", paused("M6.0", "https://example.test/", { responseStatusCode: 200 })],
    ["no id", paused("", "https://example.test/")],
  ]) {
    const { cdp, h, retired } = setup();
    h.privileged(ev);
    assert.equal(retired.length, 1, what);
    assert.equal(cdp.calls.length, 0, what); // (nothing is answered: the request stays held until the session ends)
  }
  const { h, retired } = setup();
  h.privileged(paused("D1.0", "https://example.test/"));
  h.privileged(paused("D1.0", "https://example.test/again"));
  assert.deepEqual(retired, ["a duplicate request id"]);
});

test("Fetch auth: the session's credentials only to the configured proxy, once, for a request it continued; a server is cancelled; anything else retires", async () => {
  const ok = setup();
  ok.h.privileged(paused("A1.0", "http://example.test/"));
  ok.h.privileged(auth("A1.0", "Proxy"));
  assert.deepEqual(last(ok.cdp).params, { requestId: "A1.0", authChallengeResponse: { response: "ProvideCredentials", username: "sess-user", password: "sess-pass" } });
  ok.h.privileged(paused("A2.0", "http://example.test/private"));
  ok.h.privileged(auth("A2.0", "Server", "http://example.test"));
  assert.deepEqual(last(ok.cdp).params, { requestId: "A2.0", authChallengeResponse: { response: "CancelAuth" } });
  await settle();
  assert.deepEqual(ok.retired, []);
  for (const [what, steps] of [
    ["another proxy (an auth-source mismatch)", [paused("B1.0", "http://example.test/"), auth("B1.0", "Proxy", "http://127.0.0.1:40124")]],
    ["a remote proxy", [paused("B2.0", "http://example.test/"), auth("B2.0", "Proxy", "http://proxy.example:40123")]],
    ["an unknown source", [paused("B3.0", "http://example.test/"), auth("B3.0", "Origin")]],
    ["an unknown request", [auth("B4.0", "Proxy")]],
    ["a blocked request", [paused("B5.0", "https://claude.ai/"), auth("B5.0", "Proxy")]],
    ["a second challenge (credentials refused)", [paused("B6.0", "http://example.test/"), auth("B6.0", "Proxy"), auth("B6.0", "Proxy")]],
  ]) {
    const { cdp, h, retired } = setup();
    for (const ev of steps) h.privileged(ev);
    assert.equal(retired.length, 1, what);
    assert.ok(!cdp.calls.some((c) => c.method === "Fetch.continueWithAuth" && c.params.authChallengeResponse.response === "ProvideCredentials" && c.params.requestId !== "B6.0"), what);
    assert.ok(!JSON.stringify(retired).includes("sess-pass"), what); // (credentials never in a reason)
  }
});

test("Fetch: a silent handler retires at its deadline; a refused answer retires; a vanished target's session doesn't; nothing is handled after retirement", async () => {
  assert.equal(HANDLER_MS, 5000);
  const silent = setup({ "Fetch.continueRequest": undefined });
  delete silent.cdp.answers["Fetch.continueRequest"];
  silent.h.privileged(paused("S1.0", "https://example.test/"));
  await silent.clock.advance(HANDLER_MS - 1);
  assert.deepEqual(silent.retired, []);
  await silent.clock.advance(1);
  assert.deepEqual(silent.retired, ["the Fetch handler missed its deadline"]);
  const n = silent.cdp.calls.length;
  silent.h.privileged(paused("S2.0", "https://example.test/")); // (after retirement: nothing more)
  assert.equal(silent.cdp.calls.length, n);
  const refused = setup({ "Fetch.failRequest": cdpErr(-32000, "Invalid InterceptionId.") });
  refused.h.privileged(paused("R1.0", "https://claude.ai/"));
  await settle();
  assert.deepEqual(refused.retired, ["the browser refused the Fetch handler's answer"]);
  const gone = setup({ "Fetch.continueRequest": cdpErr(-32001, "Session with given id not found.") });
  gone.h.privileged(paused("G1.0", "https://example.test/"));
  await gone.clock.advance(HANDLER_MS);
  assert.deepEqual(gone.retired, []);
  const answered = setup(); // (an answer in time clears its deadline)
  answered.h.privileged(paused("T1.0", "https://example.test/"));
  await answered.clock.advance(HANDLER_MS * 2);
  assert.deepEqual(answered.retired, []);
});

test("retirement before the session is bound is kept and delivered at bind", async () => {
  const cdp = fakeCdp(ALL_EMPTY), clock = new Clock(), retired = [];
  const h = createHardening({ cdp, credentials, origins, permissions, clock });
  h.privileged(paused("E1.0", "file:///x"));
  h.bind({ retire: (r) => retired.push(r) });
  assert.deepEqual(retired, ["a request with an unexpected scheme"]);
});

test("the permission generator's mapping covers exactly the pinned protocol's PermissionType; each checked-in list is well formed", () => {
  const proto = JSON.parse(readFileSync(new URL(`../${PINS.protocol.file}`, import.meta.url)));
  const types = proto.domains.find((d) => d.domain === "Browser").types.find((t) => t.id === "PermissionType").enum;
  assert.deepEqual(Object.keys(DESCRIPTORS).sort(), [...types].sort());
  assert.deepEqual(DESCRIPTORS.automaticFullscreen, [{ name: "fullscreen", allowWithoutGesture: true }]);
  const dir = new URL("../schema/fleet/browser/", import.meta.url);
  const lists = readdirSync(dir).filter((f) => /^permissions-\d+\.\d+\.\d+\.\d+\.json$/.test(f));
  assert.ok(lists.length >= 1);
  const all = new Set(Object.values(DESCRIPTORS).flat().map((d) => JSON.stringify(d)));
  for (const f of lists) {
    const doc = JSON.parse(readFileSync(new URL(f, dir), "utf8"));
    assert.equal(`permissions-${doc.build}.json`, f);
    assert.ok(doc.descriptors.length > 0, f);
    for (const d of [...doc.descriptors, ...doc.refused]) assert.ok(all.has(JSON.stringify(d)), `${f}: ${JSON.stringify(d)}`);
    assert.equal(doc.descriptors.length + doc.refused.length, all.size, f); // (every descriptor tried, each accepted or refused)
  }
});

test("Fetch request ids are a session's own: the same id on two sessions is two requests; a challenge never borrows another session's request; no session at all retires", async () => {
  const two = setup();
  two.h.privileged(paused("X1.0", "https://example.test/a"));
  two.h.privileged({ ...paused("X1.0", "https://example.test/b"), sessionId: "SESS-B" });
  await settle();
  assert.deepEqual(two.retired, []);
  assert.deepEqual(two.cdp.calls.map((c) => [c.method, c.sessionId, c.params.requestId]), [["Fetch.continueRequest", "SESS-A", "X1.0"], ["Fetch.continueRequest", "SESS-B", "X1.0"]]);
  const cross = setup();
  cross.h.privileged(paused("X2.0", "http://example.test/")); // (continued on SESS-A)
  cross.h.privileged({ ...auth("X2.0", "Proxy"), sessionId: "SESS-B" }); // (the same id, on another session)
  assert.deepEqual(cross.retired, ["an auth challenge for an unknown request"]);
  assert.ok(!cross.cdp.calls.some((c) => c.method === "Fetch.continueWithAuth"));
  for (const sessionId of [undefined, ""]) {
    const n = setup();
    n.h.privileged({ ...paused("X3.0", "https://example.test/"), sessionId });
    assert.equal(n.retired.length, 1, String(sessionId));
    assert.equal(n.cdp.calls.length, 0);
    const m = setup();
    m.h.privileged(paused("X4.0", "http://example.test/"));
    m.h.privileged({ ...auth("X4.0", "Proxy"), sessionId });
    assert.equal(m.retired.length, 1, String(sessionId));
    assert.ok(!m.cdp.calls.some((c) => c.method === "Fetch.continueWithAuth"));
  }
});
