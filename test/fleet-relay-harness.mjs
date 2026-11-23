// Test harness for the browser relay (lib/fleet/relay/): a manual clock, a fake fleet Worker that speaks the core's
// control contract (lib/fleet/core/control.mjs: the signed call, consumed once; the signed answer bound to it; the
// closed schemas), fake sockets for the slot logic, and helpers for facts in the answer's shape.

import { EventEmitter } from "node:events";
import { randomBytes } from "node:crypto";
import { newId, sha256b64 } from "../lib/fleet/index.mjs";
import { verifyControlRequest, signControlAnswer, parseAdmitRequest, parseEpochsTarget, ADMIT_ROUTE, EPOCHS_ROUTE, AUTH_HEADER, ANSWER_HEADER } from "../lib/fleet/core/control.mjs";

export const settle = async (n = 10) => { for (let i = 0; i < n; i++) await new Promise((r) => setImmediate(r)); };

/** A monotonic clock the test moves. advance(ms) fires every timer due, in order. */
export function manualClock() {
  let now = 0, seq = 0;
  const timers = new Map();
  return {
    now: () => now,
    setTimeout: (f, ms) => { const h = { id: ++seq }; timers.set(h, { f, at: now + Math.max(0, ms), seq: h.id }); return h; },
    clearTimeout: (h) => { if (h) timers.delete(h); },
    advance(ms) {
      const end = now + ms;
      for (;;) {
        let next = null;
        for (const [h, t] of timers) if (t.at <= end && (!next || t.at < next[1].at || (t.at === next[1].at && t.seq < next[1].seq))) next = [h, t];
        if (!next) break;
        timers.delete(next[0]);
        now = next[1].at;
        next[1].f();
      }
      now = end;
    },
    pending: () => timers.size,
  };
}

/** Move a manual clock by `ms` in steps, letting async work (calls, answers) run between them. */
export async function run(clock, ms, step = 500) {
  for (let t = 0; t < ms; t += step) { clock.advance(Math.min(step, ms - t)); await settle(); }
}

/** A fake WebSocket for the slot logic: binary sends with a test-controlled queue. */
export class FakeWs extends EventEmitter {
  constructor() { super(); this.readyState = 1; this.bufferedAmount = 0; this.sent = []; this.closed = null; this.callbacks = []; }
  send(buf, opts, cb) { this.sent.push(buf); this.bufferedAmount += buf.length; this.callbacks.push({ n: buf.length, cb }); }
  /** The peer takes `n` bytes (all by default): the queue shrinks and write callbacks fire. */
  take(n = Infinity) {
    while (this.callbacks.length && n > 0) {
      const c = this.callbacks[0];
      if (c.n > n) { c.n -= n; this.bufferedAmount -= n; return; }
      n -= c.n; this.bufferedAmount -= c.n; this.callbacks.shift(); c.cb?.();
    }
  }
  close(code, why) { if (this.readyState > 1) return; this.readyState = 3; this.closed = { code, why }; this.emit("close", code, why); }
  terminate() { this.close(1006, "terminated"); }
  /** The peer sends a message. */
  in(data, isBinary = true) { this.emit("message", Buffer.from(data), isBinary); }
}

/** A 128-bit id, base64url (an app open's request id, a host nonce, a control call's id). */
export const rid = () => randomBytes(16).toString("base64url");
export const ids = () => ({ fleet: newId(), host: newId(), agent: newId(), session: newId(), account: `acct-${randomBytes(6).toString("hex")}` });
export const KEY_TEXT = () => randomBytes(32).toString("base64url");

/** Verified facts as the Worker answers them (the admit answer's fields, without its call binding). */
export function facts(role, t, over = {}) {
  const tuple = { fleet: t.fleet, host: t.host, agent: t.agent, browser_gen: 1, session: t.session, host_gen: 1, resume_n: 0 };
  const epochs = { account: 0, agent: 0, host: 0 };
  if (role === "host") return { result: "ok", role, ...tuple, nonce: rid(), account: t.account, not_after_ms: null, epochs, ...over };
  return { result: "ok", role, ...tuple, request: rid(), account: t.account, account_session: "sess-1", account_session_expires_ms: Date.now() + 3_600_000,
    signer: newId(), chain_seq: 1, not_after_ms: Date.now() + 3_600_000, epochs, ...over };
}

/**
 * A fake fleet Worker on the control plane. Each call is verified (the core's verifyControlRequest) and its id consumed
 * once; each answer is signed and bound to its call (signControlAnswer). decide(payload, query) -> admit fields;
 * feedQueue: functions (since, signal) -> feed fields, or undefined for the default (an empty answer that advances).
 * `hold` (a promise) delays every answer until it resolves (or the call aborts). `calls` counts calls by route.
 */
export class FakeWorker {
  constructor(key, { wallNow = () => Date.now() } = {}) {
    this.key = key; this.wallNow = wallNow; this.seen = new Set(); this.calls = { admit: 0, epochs: 0, refusedAuth: 0 };
    this.hold = null; this.cursor = 0; this.feedQueue = []; this.epochOf = () => 0;
    this.decide = (p) => this.defaultDecide(p);
    this.transport = async ({ method, target, headers, body, signal }) => {
      let call;
      try { call = await verifyControlRequest({ header: headers[AUTH_HEADER], method, target, body }, { key, now: this.wallNow() }); } catch { this.calls.refusedAuth++; return { status: 401, headers: {}, body: new Uint8Array(0) }; }
      if (this.seen.has(call.id)) { this.calls.refusedAuth++; return { status: 401, headers: {}, body: new Uint8Array(0) }; } // (each service call id, once)
      this.seen.add(call.id);
      if (this.hold) await Promise.race([this.hold, new Promise((_, rej) => signal?.addEventListener("abort", () => rej(new Error("aborted"))))]);
      let answer, fields;
      if (method === "POST" && target === ADMIT_ROUTE) { this.calls.admit++; answer = "admit"; fields = this.decide(parseAdmitRequest(body)); }
      else if (method === "GET" && target.startsWith(EPOCHS_ROUTE)) {
        this.calls.epochs++; answer = "epochs";
        const since = parseEpochsTarget(target), next = this.feedQueue.shift();
        fields = next ? await next(since, signal) : this.empty(since);
      } else return { status: 404, headers: {}, body: new Uint8Array(0) };
      if (fields?.__raw) return fields.__raw(call);
      const a = await signControlAnswer({ key, call, answer, fields });
      return { status: a.status, headers: { [ANSWER_HEADER]: a.header }, body: a.body };
    };
  }

  /** An empty feed answer that advances the cursor past since. */
  empty(since, over = {}) {
    this.cursor = Math.max(this.cursor + 1, since + 1);
    return { result: "ok", since, cursor: this.cursor, at_ms: this.wallNow(), more: false, agents: [], accounts: [], hosts: [], ...over };
  }

  /** Facts from the request, as the real Worker would after its checks. Host sig: "host=..;gen=..;nonce=.."; app record: starts with the host id; cookie: the account. */
  defaultDecide(p) {
    const ep = (agent, account, host) => ({ agent: this.epochOf("agent", agent), account: this.epochOf("account", account), host: this.epochOf("host", host) });
    if (p.kind === "commit") {
      const c = JSON.parse(Buffer.from(p.body, "base64url").toString("utf8"));
      const sig = Object.fromEntries(p.sig.split(";").map((kv) => kv.split("=")));
      return { result: "ok", role: "commit", fleet: c.fleet, host: sig.host, agent: c.agent, browser_gen: c.browser_gen, session: c.session, host_gen: Number(sig.gen), resume_n: c.resume_n,
        nonce: sig.nonce, host_nonce: c.host_nonce, app_request: c.app_request, account: sig.acct ?? "acct-host", epochs: ep(c.agent, sig.acct ?? "acct-host", sig.host) };
    }
    const q = Object.fromEntries(new URL(p.target, "http://x").searchParams), n = (k) => Number(q[k]);
    const tuple = { fleet: q.fleet, agent: q.agent, browser_gen: n("browser_gen"), session: q.session, host_gen: n("host_gen"), resume_n: n("resume_n") };
    if (p.kind === "host") {
      const sig = Object.fromEntries(p.sig.split(";").map((kv) => kv.split("=")));
      return { result: "ok", role: "host", ...tuple, host: sig.host, nonce: sig.nonce, account: sig.acct ?? "acct-host", not_after_ms: null, epochs: ep(q.agent, sig.acct ?? "acct-host", sig.host) };
    }
    // (the record's end and the session's expiry: fixed by the test in `app`, else an hour from now; past either one,
    //  the Worker refuses grant_expired, as the real one does)
    const now = this.wallNow(), notAfter = this.app?.not_after_ms ?? now + 3_600_000, session = this.app?.session_ms ?? now + 3_600_000;
    if (this.app?.checkWindow !== false && (now >= notAfter || now >= session)) return { result: "refused", code: "grant_expired" };
    return { result: "ok", role: "app", ...tuple, host: p.record.slice(0, 26), request: p.request, account: p.cookie, account_session: "sess-1", account_session_expires_ms: session,
      signer: newId(), chain_seq: 1, not_after_ms: notAfter, epochs: ep(q.agent, p.cookie, p.record.slice(0, 26)) };
  }
}

export { sha256b64 };
