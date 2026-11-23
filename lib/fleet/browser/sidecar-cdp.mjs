// Fleet protocol, the browser lane: the cdp sidecar's frame handling. One process per browser session, on the app's
// pinned Node, with no network of its own. It talks only to the app (Rust), over framed stdio; Rust routes the net
// sidecar's frames to and from it. It holds Chrome's debugging pipe (macapp's pipe client), the session driver
// (./session.mjs) and the Filter, and nothing of the channel.
//
// Frames in:
// - from Rust: cdp.proxy_auth (once, before start), cdp.start (once), cdp.takeover, cdp.resume, cdp.retire;
// - from net: cdp.command { seq } with the agent's command bytes.
// Frames out:
// - to Rust: rust.cdp_state { state: starting | ready | paused | ended, reason? }, rust.takeover_done,
//   rust.takeover_failed;
// - to net: net.result { seq } (the JSON answer: { result } or { error: { code, message } }, every definitive
//   outcome, the Filter's refusals and "timed out" included), net.refused { seq, reason: takeover | bad }, net.event.
//
// While the session lives, every cdp.command gets exactly one net.result or net.refused. A seq must be greater than
// every seq before it. After rust.cdp_state ended, nothing more is sent for any seq: net settles them itself.
// Anything out of order (a start without proxy credentials, a second proxy_auth or start, an unknown kind, a frame
// the codec refuses) ends the sidecar. Reasons are fixed strings, never untrusted text.

import { Filter } from "./filter.mjs";
import { BrowserSession } from "./session.mjs";
import { createHardening } from "./harden.mjs";

export const COMMAND_BYTES = 1048576; // (O11 §7: at most 1 MiB of command bytes)
const COMMAND_KEYS = new Set(["method", "params", "sessionId"]);

/** The agent's command bytes as a command, or null if they aren't one JSON object { method, params?, sessionId? }. */
export function parseCommand(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0 || bytes.length > COMMAND_BYTES) return null;
  let v;
  try { v = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); } catch { return null; }
  if (v === null || typeof v !== "object" || Array.isArray(v) || Object.getPrototypeOf(v) !== Object.prototype) return null;
  for (const k of Object.keys(v)) if (!COMMAND_KEYS.has(k)) return null;
  if (typeof v.method !== "string" || v.method.length === 0 || v.method.length > 128) return null;
  if (Object.hasOwn(v, "params") && (v.params === null || typeof v.params !== "object" || Array.isArray(v.params))) return null;
  if (Object.hasOwn(v, "sessionId") && typeof v.sessionId !== "string") return null;
  return v;
}

export class CdpSidecar {
  #send; #openPipe; #makeSession; #state = "waiting"; // waiting, armed (credentials), starting, ready, paused, ended
  #credentials = null;
  #session = null;
  #lastSeq = -1;
  #open = new Set(); // seqs sent to the session and not yet answered

  /**
   * `send(head, body?)`: write one frame (the codec's encode, to stdout). `openPipe({ pid })`: Chrome's debugging pipe
   * (macapp's openPipe on fds 3 and 4), resolving a `cdp`. `makeSession({ cdp, credentials, sink })`: the session for
   * it (a BrowserSession over a Filter, hardened with these proxy credentials).
   */
  constructor({ send, openPipe, makeSession }) {
    this.#send = send; this.#openPipe = openPipe; this.#makeSession = makeSession;
  }

  get state() { return this.#state; }

  /** One decoded frame. A codec error is the caller's: it calls fail("bad frame"). */
  frame(head, body) {
    if (this.#state === "ended") return;
    switch (head?.kind) {
      case "cdp.proxy_auth": return this.#proxyAuth(head);
      case "cdp.start": return void this.#start(head);
      case "cdp.command": return void this.#command(head, body);
      case "cdp.takeover": return void this.#takeover();
      case "cdp.resume": return this.#resume();
      case "cdp.retire": return this.#end("retired by the app");
      default: return this.#end("unexpected frame");
    }
  }

  /** The input can't be trusted any more (a frame the codec refused, stdin closed): end. */
  fail(reason) { this.#end(reason); }

  #proxyAuth(head) {
    if (this.#state !== "waiting") return this.#end(this.#credentials ? "a second proxy_auth" : "proxy_auth after start");
    if (typeof head.username !== "string" || typeof head.password !== "string" || !head.username || !head.password) return this.#end("bad proxy credentials");
    if (!Number.isSafeInteger(head.proxy_port) || head.proxy_port < 1024 || head.proxy_port > 65535) return this.#end("bad proxy port");
    this.#credentials = Object.freeze({ username: head.username, password: head.password, proxyPort: head.proxy_port });
    this.#state = "armed";
  }

  async #start(head) {
    if (this.#state !== "armed") return this.#end(this.#state === "waiting" ? "no proxy credentials" : "a second start");
    this.#state = "starting";
    this.#send({ to: "rust", kind: "rust.cdp_state", state: "starting" });
    let cdp;
    try { cdp = await this.#openPipe({ pid: head.chrome_pid }); } catch { return this.#end("the browser pipe didn't open"); }
    if (this.#state === "ended") { cdp.close?.().catch?.(() => {}); return; }
    const sink = { event: (ev) => this.#event(ev), retired: (reason) => this.#end(reason) };
    this.#session = this.#makeSession({ cdp, credentials: this.#credentials, sink });
    const ok = await this.#session.start();
    if (!ok || this.#state === "ended") return this.#end("the session didn't start");
    this.#state = "ready";
    this.#send({ to: "rust", kind: "rust.cdp_state", state: "ready" });
  }

  async #command(head, body) {
    const seq = head.seq;
    if (!Number.isSafeInteger(seq) || seq < 0) return this.#end("bad seq");
    if (seq <= this.#lastSeq) return this.#end("a repeated or out-of-order seq");
    this.#lastSeq = seq;
    const cmd = parseCommand(body);
    if (!cmd) return this.#refuse(seq, "bad");
    if (this.#state === "paused") return this.#refuse(seq, "takeover");
    if (this.#state !== "ready") return this.#answer(seq, { error: { code: -32000, message: "session not ready" } });
    this.#open.add(seq);
    let r;
    try { r = await this.#session.command(cmd); } catch { return this.#end("the session failed"); }
    if (this.#state === "ended" || !this.#open.delete(seq)) return; // (ended meanwhile: net settles it)
    if (r?.unknown) {
      if (this.#state === "paused" || this.#session.state === "paused") return this.#refuse(seq, "takeover");
      return this.#end("a command's outcome can't be known"); // (outside takeover: the session can't vouch for it)
    }
    if (r && (Object.hasOwn(r, "result") || Object.hasOwn(r, "error"))) return this.#answer(seq, r);
    return this.#end("the session gave no answer");
  }

  #answer(seq, r) {
    if (this.#state === "ended") return;
    const body = Buffer.from(JSON.stringify(Object.hasOwn(r, "error") ? { error: r.error } : { result: r.result }), "utf8");
    this.#send({ to: "net", kind: "net.result", seq }, body);
  }

  #refuse(seq, reason) {
    if (this.#state === "ended") return;
    this.#open.delete(seq);
    this.#send({ to: "net", kind: "net.refused", seq, reason });
  }

  #event(ev) {
    if (this.#state === "ended") return;
    this.#send({ to: "net", kind: "net.event" }, Buffer.from(JSON.stringify(ev), "utf8"));
  }

  async #takeover() {
    if (this.#state === "paused") { this.#send({ to: "rust", kind: "rust.takeover_done" }); return; }
    if (this.#state !== "ready") return this.#end("takeover before the session was ready");
    this.#state = "paused"; // (from now, new commands are refused "takeover")
    const r = await this.#session.takeover();
    if (this.#state === "ended") return;
    if (r?.paused) {
      for (const seq of [...this.#open]) this.#refuse(seq, "takeover"); // (abandoned by the drain: they settle as unknown, then here)
      this.#send({ to: "rust", kind: "rust.takeover_done" });
      this.#send({ to: "rust", kind: "rust.cdp_state", state: "paused" });
      return;
    }
    this.#send({ to: "rust", kind: "rust.takeover_failed", reason: "the browser didn't stop the agent's script in time" });
    this.#end("takeover failed");
  }

  #resume() {
    if (this.#state !== "paused") return this.#end("resume while not paused");
    if (!this.#session.handback()) return this.#end("handback failed");
    this.#state = "ready";
    this.#send({ to: "rust", kind: "rust.cdp_state", state: "ready" });
  }

  #end(reason) {
    if (this.#state === "ended") return;
    this.#state = "ended";
    this.#open.clear();
    try { this.#send({ to: "rust", kind: "rust.cdp_state", state: "ended", reason }); } catch { /* (the output is gone too) */ }
    if (this.#session && this.#session.state !== "retired") this.#session.retire(reason);
  }
}

/** The session the sidecar runs: a BrowserSession over a Filter, hardened (./harden.mjs) with the proxy credentials. */
export function sessionFactory({ spec, program, commands, origins, permissions, fetchWorkers = [] }) {
  return ({ cdp, credentials, sink }) => {
    const hooks = createHardening({ cdp, credentials, origins, permissions, fetchWorkers });
    const session = new BrowserSession({ cdp, filter: new Filter({ spec, program, commands, origins }), hooks, sink });
    hooks.bind(session);
    return session;
  };
}
