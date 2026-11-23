// Fleet protocol, the browser relay (design agent-autonomous-browser-relay.md r2.2 §3, §5): the relay's side of the
// control plane. The contract itself (the signed call, the signed answer bound to it, the closed schemas, the
// refusal codes) is the core's (../core/control.mjs), the same file the fleet Worker runs; this is the client:
// - one fixed HTTPS origin from the relay's reviewed configuration: verified TLS, no redirects, no proxy, no retries;
//   connect, response-header and total deadlines; the answer read with a byte cap (ANSWER_MAX);
// - each call gets a fresh 128-bit id and accepts one answer: the answer must verify for that call (its MAC, its call
//   id and body digest, its closed schema), and an unsigned or non-200 answer is a failed call;
// - any failure rejects with ControlError; the caller refuses (fail closed).

import { randomBytes } from "node:crypto";
import { request as httpsRequest, Agent } from "node:https";
import { canonText, enc, sha256b64 } from "../index.mjs";
import { ADMIT_ROUTE, AUTH_HEADER, ANSWER_HEADER, ANSWER_MAX, REQUEST_MAX, signControlRequest, verifyControlAnswer, epochsTarget } from "../core/control.mjs";

/** The relay's own deadlines for its calls (admit 5 s, the feed 3 s), and the transport's connect and header bounds. */
export const CONTROL = Object.freeze({ connectMs: 2000, headersMs: 4000, admitMs: 5000, feedMs: 3000 });
const EMPTY = new Uint8Array(0);

export class ControlError extends Error {
  constructor(code) { super(code); this.code = code; }
}

/** `p`, or a ControlError("deadline") as soon as `signal` aborts, whether or not the call itself honors the signal. */
export function untilAborted(p, signal) {
  if (!signal) return p;
  if (signal.aborted) return Promise.reject(new ControlError("deadline"));
  return new Promise((resolve, reject) => {
    const onAbort = () => reject(new ControlError("deadline"));
    signal.addEventListener("abort", onAbort, { once: true });
    p.then((v) => { signal.removeEventListener("abort", onAbort); resolve(v); }, (e) => { signal.removeEventListener("abort", onAbort); reject(e); });
  });
}

/**
 * The default transport: one HTTPS request to the fixed origin, with no proxy, no redirect and no retry. Resolves
 * { status, headers, body } (any status; the client decides) or rejects with ControlError ("deadline" | "too_large" |
 * "transport"). `ca`: the trust anchors for the origin (default: Node's own).
 */
export function httpsTransport({ origin, ca }) {
  const url = new URL(origin);
  if (url.protocol !== "https:" || url.pathname !== "/" || url.search || url.hash || url.username || url.password) throw new Error("the control plane's origin is one https origin");
  const agent = new Agent({ keepAlive: false, ...(ca ? { ca } : {}) });
  return ({ method, target, headers, body, totalMs, signal }) => new Promise((resolve, reject) => {
    const timers = [];
    let done = false, req = null;
    const finish = (err, value) => {
      if (done) return;
      done = true;
      for (const t of timers) clearTimeout(t);
      signal?.removeEventListener("abort", onAbort);
      if (err) { req?.destroy(); reject(err); } else resolve(value);
    };
    const onAbort = () => finish(new ControlError("deadline"));
    signal?.addEventListener("abort", onAbort, { once: true });
    timers.push(setTimeout(() => finish(new ControlError("deadline")), totalMs));
    const connect = setTimeout(() => finish(new ControlError("deadline")), CONTROL.connectMs), head = setTimeout(() => finish(new ControlError("deadline")), CONTROL.headersMs);
    timers.push(connect, head);
    req = httpsRequest({ host: url.hostname, port: url.port || 443, servername: url.hostname, method, path: target, agent,
      headers: { ...headers, ...(body.length ? { "content-type": "application/json" } : {}), "content-length": body.length } });
    req.on("socket", (s) => s.once("secureConnect", () => clearTimeout(connect)));
    req.on("error", () => finish(new ControlError("transport")));
    req.on("response", (res) => {
      clearTimeout(head); clearTimeout(connect);
      const chunks = []; let n = 0;
      res.on("data", (c) => { n += c.length; if (n > ANSWER_MAX) return finish(new ControlError("too_large")); chunks.push(c); });
      res.on("end", () => finish(null, { status: res.statusCode, headers: res.headers, body: new Uint8Array(Buffer.concat(chunks)) }));
      res.on("error", () => finish(new ControlError("transport")));
    });
    req.end(Buffer.from(body));
  });
}

/**
 * The relay's client. `transport` (httpsTransport's shape), `key` (the 32-byte service key, the core's controlKey()),
 * `wallNow()` for the timestamp. Resolves the verified answer's value; rejects with ControlError.
 */
export function controlClient({ transport, key, wallNow = () => Date.now(), newId = () => randomBytes(16).toString("base64url") }) {
  if (!(key instanceof Uint8Array) || key.length !== 32) throw new Error("the service key is 32 bytes");
  const pending = new Set(); // (each call accepts one answer)
  async function call(method, target, body, answer, totalMs, signal) {
    if (body.length > REQUEST_MAX) throw new ControlError("too_large");
    const id = newId(), digest = await sha256b64(body);
    const header = await signControlRequest({ key, method, target, body, ts: wallNow(), id });
    pending.add(id);
    let res;
    try { res = await untilAborted(transport({ method, target, headers: { [AUTH_HEADER]: header }, body, totalMs, signal }), signal); } catch (e) {
      pending.delete(id);
      throw e instanceof ControlError ? e : new ControlError("transport");
    }
    if (!pending.delete(id)) throw new ControlError("answer"); // (a second answer to one call)
    if (res?.status !== 200) throw new ControlError("status"); // (an unsigned 4xx/5xx: the call failed)
    const h = res.headers?.[ANSWER_HEADER];
    try { return await verifyControlAnswer({ header: Array.isArray(h) ? null : h, status: res.status, body: res.body }, { key, call: { id, digest }, answer }); }
    catch { throw new ControlError("answer"); }
  }
  return {
    /** Ask about an open or a commit: { kind: "host", target, sig } | { kind: "app", target, record, request, cookie } | { kind: "commit", target, sig, body }. */
    admit: (payload, signal) => {
      let body;
      try { body = enc(canonText({ v: 1, ...payload }, REQUEST_MAX)); } catch { return Promise.reject(new ControlError("too_large")); } // (canonText's own default cap is 64 KiB; a record alone may be 87,252)
      return call("POST", ADMIT_ROUTE, body, "admit", CONTROL.admitMs, signal);
    },
    /** The feed since `since` (0: from now). */
    epochs: (since, signal) => call("GET", epochsTarget(since), EMPTY, "epochs", CONTROL.feedMs, signal),
  };
}
