// Fleet protocol, the browser relay (design agent-autonomous-browser-relay.md r2.1 §2, §3, §4, §6): the HTTP side.
// Caddy routes only the relay's two paths here (its max_header_size is HEADERS_MAX too); this server listens on
// loopback and is the first parser that allocates for us (maxHeaderSize = HEADERS_MAX: a larger header block is
// refused with 431 before our code runs).
//   GET  /api/fleet/v1/relay/browser?<seven fields>  a WebSocket open, host or app (the channel note §5.1-§5.3)
//   POST /api/fleet/v1/relay/browser/commit          a broker's replacement authorization (§5.4)
// Every open, in this order; each refusal is a fixed status with nothing else done:
//   1. ingress: the route and its seven fields (parseOpenTarget), the role's headers in their exact forms and sizes,
//      a WebSocket upgrade; the feed must be available (§5);
//   2. limits before admission, global and per source only (nothing about the caller is verified yet): opens a
//      minute, and control-plane calls in flight, a slot reserved before the call and released once however it ends;
//   3. /relay/admit (control.mjs): the verified facts, or a refusal;
//   4. the facts must be the query's, and their epochs still current (a late answer can't restore anything);
//   5. the nonce or request id is consumed (durable) before anything else changes;
//   6. the slot logic and the limits from verified facts (slots.mjs); then the upgrade.
// The WebSocket: binary messages of at most MAX_MESSAGE bytes, checked from the frame header before the payload is
// buffered (ws's maxPayload, fragments counted together); no compression; no automatic pongs.
// Logs: metadata only; never a record, relay token, signature, nonce, request id or message bytes.

import { createServer } from "node:http";
import { isIP } from "node:net";
import { APP_TOKEN, ROUTE, COMMIT_ROUTE, RECORD_HEADER_MAX, HEADERS_MAX, parseOpenTarget } from "../core/relay.mjs";
import { MAX_MESSAGE } from "../channel/noise.mjs";
import { RelayRefusal } from "./slots.mjs";
import { MinuteWindow } from "./window.mjs";
import { CONTROL } from "./control.mjs";
import { CONTROL_SKEW_MS } from "../core/control.mjs";

export const INGRESS = Object.freeze({ controlCalls: 16, controlPerSource: 2, opensPerSourcePerMinute: 30, opensPerMinute: 600, commitBodyMax: 4096, sigMax: 2048 });
/** The longest acceptance window the relay admits for an app open's record (its remaining not_after_ms - now). */
export const APP_RECORD_MAX_MS = 12 * 3600_000;
/** The header Caddy sets with the TCP peer's address; trusted only when the connection comes from loopback. */
export const SOURCE_HEADER = "sagebrush-relay-source";

const B22 = /^[A-Za-z0-9_-]{21}[AQgw]$/;
const B64 = /^[A-Za-z0-9_-]+$/;
const KEY = /^[A-Za-z0-9+/]{22}==$/;
const STATUS = { 400: "Bad Request", 403: "Forbidden", 404: "Not Found", 405: "Method Not Allowed", 409: "Conflict", 413: "Content Too Large", 429: "Too Many Requests", 503: "Service Unavailable" };
// (the Worker's closed refusal codes, ADMIT_REFUSALS: bad_form -> 400, limit -> 429, every other one -> 403)
const statusOf = (code) => ({ bad_form: 400, limit: 429, unauthenticated: 401 })[code] ?? 403;
const LOOPBACK = new Set(["127.0.0.1", "::1", "::ffff:127.0.0.1"]);

/**
 * The relay's HTTP server (not listening yet). control: controlClient; store: openStore's; slots: Slots; feed: Feed;
 * clock: { now } (monotonic); wallNow(); WebSocketServer: ws's (passed in, so this module loads with no dependency:
 * main.mjs imports ws when the relay starts). Returns { server, prune(), stats() }.
 */
export function createRelayServer({ control, store, slots, feed, clock, wallNow = () => Date.now(), log = () => {}, ingress = INGRESS, WebSocketServer }) {
  if (typeof WebSocketServer !== "function") throw new Error("the relay needs ws's WebSocketServer");
  const wss = new WebSocketServer({ noServer: true, maxPayload: MAX_MESSAGE, perMessageDeflate: false, autoPong: false, clientTracking: false });
  const server = createServer({ maxHeaderSize: HEADERS_MAX, requestTimeout: 10_000, headersTimeout: 10_000 }, (req, res) => onRequest(req, res).catch(() => answer(res, 503)));
  server.on("upgrade", (req, socket, head) => { socket.on("error", () => {}); onUpgrade(req, socket, head).catch(() => reject(socket, 503)); });

  // ---- limits before admission (§3): global and per source. Memory is bounded whatever sources callers present: the
  // minute's opens are one queue of at most opensPerMinute (MinuteWindow; nothing allocated once it's full), and the
  // in-flight map holds at most controlCalls sources.
  const opens = new MinuteWindow({ clock, max: ingress.opensPerMinute });
  const inflight = new Map(); // source -> calls in flight
  let calls = 0;
  function reserveCall(source) {
    if (calls >= ingress.controlCalls || (inflight.get(source) ?? 0) >= ingress.controlPerSource) return null;
    if (!opens.take([source], ingress.opensPerSourcePerMinute)) return null;
    calls++; inflight.set(source, (inflight.get(source) ?? 0) + 1);
    let released = false;
    return () => { if (released) return; released = true; calls--; const n = inflight.get(source) - 1; n ? inflight.set(source, n) : inflight.delete(source); };
  }
  /** One admit call, aborted at CONTROL.admitMs on this clock (whatever the transport); null on any failure. */
  async function admit(payload) {
    const controller = new AbortController();
    const deadline = clock.setTimeout(() => controller.abort(), CONTROL.admitMs);
    try { const a = await control.admit(payload, controller.signal); return controller.signal.aborted ? null : a; } catch { return null; } finally { clock.clearTimeout(deadline); }
  }
  const sourceOf = (req) => {
    const peer = req.socket.remoteAddress ?? "";
    const claimed = req.headers[SOURCE_HEADER];
    return LOOPBACK.has(peer) && typeof claimed === "string" && isIP(claimed) ? claimed : peer;
  };

  function reject(socket, status) {
    if (socket.destroyed) return;
    socket.end(`HTTP/1.1 ${status} ${STATUS[status] ?? "Refused"}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`);
    socket.destroySoon?.();
  }
  function answer(res, status, code = STATUS[status]) {
    if (res.headersSent) return;
    res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store", connection: "close" }).end(JSON.stringify({ code }));
  }

  // ---- an open
  async function onUpgrade(req, socket, head) {
    let f;
    try { f = parseOpenTarget(req.url); } catch { return reject(socket, 400); }
    if (req.method !== "GET" || (req.headers.upgrade ?? "").toLowerCase() !== "websocket" || req.headers["sec-websocket-version"] !== "13" || !KEY.test(req.headers["sec-websocket-key"] ?? "")) return reject(socket, 400);
    const h = req.headers;
    let payload;
    if (f.role === "host") {
      if (typeof h["sagebrush-sig"] !== "string" || h["sagebrush-sig"].length > ingress.sigMax) return reject(socket, 400);
      payload = { kind: "host", target: req.url, sig: h["sagebrush-sig"] };
    } else {
      const rec = h["sagebrush-browser-record"], id = h["sagebrush-request"];
      if (typeof rec !== "string" || rec.length > RECORD_HEADER_MAX || !B64.test(rec)) return reject(socket, 400);
      if (typeof id !== "string" || !B22.test(id)) return reject(socket, 400);
      // (the relay token, channel addendum A1 §3: its exact form, else 401 with no control-plane call; its value is
      //  forwarded as received, read nowhere else, and never logged. No cookie is read on this route.)
      const token = h["sagebrush-relay-token"];
      if (typeof token !== "string" || !APP_TOKEN.test(token)) return reject(socket, 401);
      payload = { kind: "app", target: req.url, record: rec, request: id, token };
    }
    if (!feed.available) return reject(socket, 503);
    const release = reserveCall(sourceOf(req));
    if (!release) return reject(socket, 429);
    let a;
    try { a = await admit(payload); } finally { release(); }
    if (a === null) return reject(socket, 503);
    if (a.result !== "ok") { log({ event: "refused", role: f.role, code: a.code }); return reject(socket, statusOf(a.code)); }
    const facts = a;
    for (const k of ["role", "fleet", "session", "agent", "browser_gen", "host_gen", "resume_n"]) if (facts[k] !== f[k]) return reject(socket, 403);
    if (!feed.available) return reject(socket, 503);
    if (!feed.current(facts.epochs, { agent: facts.agent, account: facts.account, host: facts.host })) return reject(socket, 403);
    if (socket.destroyed) return;
    // An app request id has no timestamp: it's kept until its record could no longer be accepted, the earlier of the
    // record's end and the account session's expiry, both verified facts of this answer, plus the control plane's
    // clock-skew margin. So the record's remaining window must be positive and at most APP_RECORD_MAX_MS, checked
    // before anything is consumed; an admitted id is never kept for less than its window.
    let until;
    if (f.role === "app") {
      const now = wallNow(), remaining = facts.not_after_ms - now;
      if (!(remaining > 0 && remaining <= APP_RECORD_MAX_MS)) { log({ event: "refused", role: f.role, code: "record_window" }); return reject(socket, 403); }
      until = Math.min(facts.not_after_ms, facts.account_session_expires_ms) + CONTROL_SKEW_MS;
      if (!(until > now)) { log({ event: "refused", role: f.role, code: "record_window" }); return reject(socket, 403); }
    }
    let fresh;
    try { fresh = store.consume(f.role, f.role === "host" ? facts.nonce : facts.request, wallNow(), until); } catch { return reject(socket, 503); }
    if (!fresh) { log({ event: "refused", role: f.role, code: "replay" }); return reject(socket, 409); }
    let side;
    try { side = slots.reserve(facts); } catch (e) {
      if (e instanceof RelayRefusal) { log({ event: "refused", role: f.role, code: e.code }); return reject(socket, e.status); }
      throw e;
    }
    socket.once("close", () => side.abort());
    wss.handleUpgrade(req, socket, head, (ws) => side.attach(ws));
  }

  // ---- a commit
  async function onRequest(req, res) {
    if (req.url !== COMMIT_ROUTE) return answer(res, req.url?.startsWith(ROUTE) ? 405 : 404);
    if (req.method !== "POST") return answer(res, 405);
    const len = Number(req.headers["content-length"]);
    if (!Number.isSafeInteger(len) || len < 1 || len > ingress.commitBodyMax || req.headers["transfer-encoding"] !== undefined) return answer(res, 413);
    const sig = req.headers["sagebrush-sig"];
    if (typeof sig !== "string" || sig.length > ingress.sigMax) return answer(res, 400);
    const chunks = []; let n = 0;
    for await (const c of req) { n += c.length; if (n > len) return answer(res, 413); chunks.push(c); }
    if (n !== len) return answer(res, 400);
    const body = Buffer.concat(chunks);
    if (!feed.available) return answer(res, 503);
    const release = reserveCall(sourceOf(req));
    if (!release) return answer(res, 429);
    let a;
    try { a = await admit({ kind: "commit", target: COMMIT_ROUTE, sig, body: body.toString("base64url") }); } finally { release(); }
    if (a === null) return answer(res, 503);
    if (a.result !== "ok") { log({ event: "refused", role: "commit", code: a.code }); return answer(res, statusOf(a.code), a.code); }
    const c = a;
    if (!feed.available) return answer(res, 503);
    if (!feed.current(c.epochs, { agent: c.agent, account: c.account, host: c.host })) return answer(res, 403);
    // (the authorization is its signature's nonce: consumed once, before the switch; replay is checked before matching)
    try {
      if (store.consumed("commit", c.nonce)) return answer(res, 409, "replay");
      if (!slots.match(c)) return answer(res, 404, "not_found");
      if (!store.consume("commit", c.nonce, wallNow())) return answer(res, 409, "replay");
    } catch { return answer(res, 503); }
    try { slots.commit(c); } catch (e) { if (e instanceof RelayRefusal) return answer(res, e.status, e.code); throw e; }
    return answer(res, 200, "ok");
  }

  return { server, wss, prune: () => store.prune(wallNow()), stats: () => ({ rateEvents: opens.size, rateKeys: opens.keys, inflight: inflight.size }) };
}
