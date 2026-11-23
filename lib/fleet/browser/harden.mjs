// Fleet protocol, the browser lane (O11 draft 5.1 §2, §5, §6): hardening each target before it runs, and the
// privileged Fetch handler. session.mjs calls `harden` for the agent's browser context and for every target while it
// waits (waitForDebuggerOnStart), and gives `privileged` every CDP event first.
//
// - The browser context: downloads denied, permissions reset, then every W3C permission descriptor in the pinned
//   list denied. The list is keyed to the exact Chrome build: another build, a missing list, a rejected name or a
//   changed response fails hardening (and the session).
// - Page and frame targets: the file chooser intercepted (every chooser cancelled), Fetch at the request stage for every
//   URL with proxy authentication, and Network.setBlockedURLs as defense in depth only (it doesn't block navigations).
// - Workers: setBlockedURLs where the build has Network there (defense in depth). Their mandatory account-origin layer
//   is the proxy's, until §9 shows Fetch covers a worker class; for the classes it does, Fetch is enabled too.
// - The privileged Fetch handler answers each requestPaused and authRequired within HANDLER_MS:
//   - requestPaused: the URL's host, by the Filter's own routine (urls.mjs), that is an account origin or under one,
//     at any scheme or port, fails BlockedByClient; everything else continues. Each redirect hop pauses again.
//   - authRequired: credentials only to source Proxy from the configured proxy (http://127.0.0.1:<proxy_port>), for a
//     request it has seen paused, once; source Server is cancelled.
//   - The session retires on a malformed URL, an unexpected scheme or stage, an unknown challenge source, a challenge
//     from another proxy, a duplicate or unknown request id, a refused or failed answer, or a missed deadline.
// Reasons are fixed strings. Credentials are never logged or put in a reason.

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { normalHost, accountOriginOf } from "./urls.mjs";
import { PINS } from "./pins.mjs";

export const HANDLER_MS = 5000;
export const WORKERS = Object.freeze(["worker", "shared_worker", "service_worker"]);
export const FETCH_PATTERNS = Object.freeze([Object.freeze({ urlPattern: "*", requestStage: "Request" })]);
const SEEN_MAX = 8192; // (request ids remembered, for the duplicate and unknown-id checks)
const SCHEMES = new Set(["http:", "https:", "ws:", "wss:"]);
const REAL_CLOCK = Object.freeze({ setTimeout: (f, ms) => setTimeout(f, ms), clearTimeout: (h) => clearTimeout(h) });

/**
 * The reviewed permission list for an exact Chrome build: schema/fleet/browser/permissions-<build>.json, accepted only
 * if its sha256 is the one pinned for that build (PINS.permissions). An unknown build, a missing file or any other
 * bytes (a shortened list included) throw, which fails hardening. `read(path)` and `pinned` are injectable for tests.
 */
export function pinnedPermissions(build, { pinned = PINS.permissions, read = (f) => readFileSync(new URL(`../../../${f}`, import.meta.url)) } = {}) {
  if (typeof build !== "string" || !/^\d+\.\d+\.\d+\.\d+$/.test(build) || !Object.hasOwn(pinned, build)) throw new Error("no pinned permission list for this build");
  const file = `schema/fleet/browser/permissions-${build}.json`;
  const bytes = read(file);
  if (createHash("sha256").update(bytes).digest("hex") !== pinned[build]) throw new Error("the permission list isn't the pinned one");
  const list = JSON.parse(Buffer.from(bytes).toString("utf8"));
  if (list.build !== build) throw new Error("the permission list is for another build");
  return list;
}

/** setBlockedURLs' patterns for the account origins (defense in depth): each origin and its subdomains, any port. */
export function blockPatterns(origins) {
  return origins.flatMap((o) => [`*://${o}/*`, `*://${o}:*/*`, `*://*.${o}/*`, `*://*.${o}:*/*`]).map((urlPattern) => ({ urlPattern, block: true }));
}

const isEmpty = (v) => v !== null && typeof v === "object" && !Array.isArray(v) && Object.keys(v).length === 0;
async function expectEmpty(promise, what) {
  const v = await promise;
  if (!isEmpty(v)) throw new Error(`${what}: an unexpected answer`);
}

/**
 * The hooks for one session. `credentials`: { username, password, proxyPort } (cdp.proxy_auth). `permissions`:
 * { build: "158.0.8127.36", descriptors: [{ name, ... }] } (the pinned release manifest's list). `fetchWorkers`: the
 * worker classes §9 showed Fetch covers on the pinned build. Call bind(session) once the session exists.
 */
export function createHardening({ cdp, credentials, origins, permissions, fetchWorkers = [], clock = REAL_CLOCK }) {
  const proxyOrigin = `http://127.0.0.1:${credentials.proxyPort}`;
  const patterns = blockPatterns(origins);
  const seen = new Map(); // `${sessionId}\0${requestId}` -> "continued" | "failed" (insertion order: the oldest go first)
  const authed = new Set(); // `${sessionId}\0${requestId}`
  let session = null, pendingRetire = null, dead = false;

  const retire = (reason) => {
    if (dead) return;
    dead = true;
    if (session) session.retire(reason); else pendingRetire = reason;
  };

  // Answer one paused request within HANDLER_MS; a refusal or silence retires (a vanished target's session is fine).
  const answer = (method, params, sessionId) => {
    let done = false;
    const h = clock.setTimeout(() => { if (!done) { done = true; retire("the Fetch handler missed its deadline"); } }, HANDLER_MS);
    cdp.send(method, params, sessionId).then(
      () => { done = true; clock.clearTimeout(h); },
      (e) => { done = true; clock.clearTimeout(h); if (e?.code !== -32001) retire("the browser refused the Fetch handler's answer"); },
    );
  };

  const remember = (key, how) => {
    seen.set(key, how);
    if (seen.size > SEEN_MAX) seen.delete(seen.keys().next().value);
  };

  function paused(ev) {
    const p = ev.params ?? {}, id = p.requestId;
    if (typeof ev.sessionId !== "string" || ev.sessionId === "") return retire("a paused request without a session");
    if (typeof id !== "string" || id === "") return retire("a paused request without an id");
    const key = `${ev.sessionId}\0${id}`; // (ids are a target's own: the same id on two sessions is two requests)
    if (seen.has(key)) return retire("a duplicate request id");
    if (Object.hasOwn(p, "responseStatusCode") || Object.hasOwn(p, "responseErrorReason")) return retire("a request paused at the response stage");
    let u;
    try { u = new URL(p.request?.url); } catch { return retire("a malformed request URL"); }
    if (!SCHEMES.has(u.protocol)) return retire("a request with an unexpected scheme");
    const host = normalHost(u.hostname);
    if (!host) return retire("a request host that can't be compared");
    if (accountOriginOf(host, origins) !== null) {
      remember(key, "failed");
      return answer("Fetch.failRequest", { requestId: id, errorReason: "BlockedByClient" }, ev.sessionId);
    }
    remember(key, "continued");
    answer("Fetch.continueRequest", { requestId: id }, ev.sessionId);
  }

  function auth(ev) {
    const p = ev.params ?? {}, id = p.requestId, ch = p.authChallenge ?? {};
    if (typeof ev.sessionId !== "string" || ev.sessionId === "") return retire("an auth challenge without a session");
    const key = `${ev.sessionId}\0${id}`;
    if (typeof id !== "string" || seen.get(key) !== "continued") return retire("an auth challenge for an unknown request");
    if (authed.has(key)) return retire("the proxy refused the session's credentials");
    authed.add(key);
    if (authed.size > SEEN_MAX) authed.delete(authed.values().next().value);
    if (ch.source === "Server") return answer("Fetch.continueWithAuth", { requestId: id, authChallengeResponse: { response: "CancelAuth" } }, ev.sessionId);
    if (ch.source !== "Proxy") return retire("an auth challenge from an unknown source");
    if (ch.origin !== proxyOrigin) return retire("an auth challenge from another proxy");
    answer("Fetch.continueWithAuth", { requestId: id, authChallengeResponse: { response: "ProvideCredentials", username: credentials.username, password: credentials.password } }, ev.sessionId);
  }

  return {
    bind(s) { session = s; if (pendingRetire !== null) s.retire(pendingRetire); },

    privileged(ev) {
      if (dead) return;
      if (ev.method === "Fetch.requestPaused") paused(ev);
      else if (ev.method === "Fetch.authRequired") auth(ev);
    },

    async harden({ kind, sessionId, browserContextId }) {
      if (kind === "browser_context") {
        const v = await cdp.send("Browser.getVersion");
        const build = /\/(\d+\.\d+\.\d+\.\d+)$/.exec(v?.product ?? "")?.[1];
        const list = typeof permissions === "function" ? permissions(build) : permissions; // (the wiring: the pinned list for this build)
        if (!list || typeof list.build !== "string" || !Array.isArray(list.descriptors) || list.descriptors.length === 0) throw new Error("no permission list");
        if (build !== list.build) throw new Error("the permission list is for another build");
        await expectEmpty(cdp.send("Browser.setDownloadBehavior", { behavior: "deny", browserContextId }), "downloads");
        await expectEmpty(cdp.send("Browser.resetPermissions", { browserContextId }), "permissions");
        for (const d of list.descriptors) await expectEmpty(cdp.send("Browser.setPermission", { permission: d, setting: "denied", browserContextId }), "a permission");
        return;
      }
      if (kind === "page" || kind === "iframe") {
        await expectEmpty(cdp.send("Page.setInterceptFileChooserDialog", { enabled: true }, sessionId), "the file chooser");
        await expectEmpty(cdp.send("Fetch.enable", { patterns: FETCH_PATTERNS, handleAuthRequests: true }, sessionId), "Fetch");
        await expectEmpty(cdp.send("Network.setBlockedURLs", { urlPatterns: patterns }, sessionId), "blocked URLs");
        return;
      }
      if (WORKERS.includes(kind)) {
        try { await expectEmpty(cdp.send("Network.setBlockedURLs", { urlPatterns: patterns }, sessionId), "blocked URLs"); }
        catch (e) { if (e?.code !== -32601) throw e; } // (no Network on this worker class: the proxy is its layer)
        if (fetchWorkers.includes(kind)) await expectEmpty(cdp.send("Fetch.enable", { patterns: FETCH_PATTERNS, handleAuthRequests: true }, sessionId), "Fetch");
        return;
      }
      throw new Error("an unknown target type");
    },
  };
}
