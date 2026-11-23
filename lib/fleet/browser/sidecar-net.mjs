// Fleet protocol, the browser lane (browser-lane3-runtime.md, "The two sidecars and their IPC"): the net sidecar's
// frame handling. One process per browser session, on the app's pinned Node, beside the cdp sidecar. It holds the
// session's channel key (made here, never sent), the app-host channel and the local proxy, and never parses CDP: the
// agent's commands and the session's answers pass through it as bytes.
//
// Frames in:
// - from Rust: net.start (once, after net_hello), net.record (once, after start: the signed session record), net.policy,
//   net.takeover, net.resume, net.retire;
// - from cdp: net.result { seq } (the session's JSON answer), net.refused { seq, reason }, net.event.
// Frames out:
// - to Rust: rust.net_hello (once, first: the channel key's public half and the proxy's port and credentials, both
//   made for this session), rust.net_state { connecting | open | resuming | ended, reason? };
// - to cdp: cdp.command { seq } with the agent's command bytes, exactly as the channel delivered them.
//
// Every command net sends gets at most one answer: an answer or refusal for a seq net didn't send, or sent and already
// had answered, ends the sidecar; seqs only go up. The channel itself (O11 §7: Noise, the app-host stream, credits,
// resume) is auth's and comes through `makeChannel`; this file is the seam. Anything out of order (a start before the
// hello, a second start or record, a record before start, an unknown kind) ends the sidecar. Reasons are fixed strings.

import { generateKeyPairSync, randomBytes } from "node:crypto";

export const COMMAND_BYTES = 1048576; // (O11 §7: at most 1 MiB of command bytes, as the cdp sidecar)

/** The session's channel key: X25519, made here; only its public half leaves (in rust.net_hello). */
export function channelKey() {
  const { privateKey, publicKey } = generateKeyPairSync("x25519");
  const pub = publicKey.export({ format: "jwk" }).x; // (base64url, 43 characters)
  return Object.freeze({ privateKey, pub });
}

/** Fresh proxy credentials for one session: 128 random bits each, base64url. */
export function proxyCredentials() {
  return Object.freeze({ username: randomBytes(16).toString("base64url"), password: randomBytes(16).toString("base64url") });
}

export class NetSidecar {
  #send; #makeProxy; #makeChannel; #onEnd;
  #state = "new"; // new, hello (sent), started, live (record in, channel made), ended
  #key = null;
  #proxy = null;
  #start = null;
  #policy = { exceptions: [] };
  #channel = null;
  #lastSeq = -1;
  #open = new Set(); // seqs sent to cdp and not yet answered

  /**
   * `send(head, body?, { terminal })`: write one frame; returns true, or the fixed reason it couldn't (the output is
   * full, or the frame doesn't encode), and then the sidecar ends at once. Only the terminal frame (rust.net_state
   * ended) may use the writer's reserve.
   * `makeProxy({ username, password })`: the local proxy (./proxy.mjs createProxy), resolving { port, close() }.
   * `makeChannel({ start, record, key, policy, onCommand(seq, bytes), onState(state, reason) })`: the app-host
   * channel (auth's), returning { result(seq, body), refused(seq, reason), event(body), takeover(), resume(), close() };
   * null until there is one, which ends each session at its record ("no channel in this build").
   * `onEnd(reason)`: called once, when the sidecar ends.
   */
  constructor({ send, makeProxy, makeChannel = null, onEnd = () => {}, key = channelKey(), credentials = proxyCredentials() }) {
    this.#send = send; this.#makeProxy = makeProxy; this.#makeChannel = makeChannel; this.#onEnd = onEnd;
    this.#key = key;
    this.credentials = credentials;
  }

  get state() { return this.#state; }

  /** Start the proxy and say hello to Rust. */
  async begin() {
    if (this.#state !== "new") return;
    let proxy;
    try { proxy = await this.#makeProxy(this.credentials); } catch { return this.#end("the proxy didn't start"); }
    if (this.#state === "ended") { proxy.close?.(); return; }
    this.#proxy = proxy;
    this.#state = "hello";
    this.#emit({ to: "rust", kind: "rust.net_hello", app_session_pub: this.#key.pub, proxy_port: proxy.port, proxy_username: this.credentials.username, proxy_password: this.credentials.password });
  }

  /** Send one frame; if it isn't admitted, end now (no later frame, no deferred end). True if it went out. */
  #emit(head, body) {
    if (this.#state === "ended") return false;
    const r = this.#send(head, body, { terminal: false });
    if (r === true) return true;
    this.#end(typeof r === "string" ? r : "the app isn't reading");
    return false;
  }

  /** One decoded frame. A codec error is the caller's: it calls fail(). */
  frame(head, body) {
    if (this.#state === "ended") return;
    switch (head?.kind) {
      case "net.start": return this.#startFrame(head);
      case "net.record": return this.#record(body);
      case "net.policy": return this.#policyFrame(head);
      case "net.takeover": return this.#channel ? this.#channel.takeover() : this.#end("takeover before the channel");
      case "net.resume": return this.#channel ? this.#channel.resume() : this.#end("resume before the channel");
      case "net.retire": return this.#end("retired by the app");
      case "net.result": return this.#answer(head.seq, (c) => c.result(head.seq, body));
      case "net.refused": return this.#answer(head.seq, (c) => c.refused(head.seq, head.reason));
      case "net.event": return this.#channel ? this.#channel.event(body) : undefined; // (best effort: before the channel, dropped)
      default: return this.#end("unexpected frame");
    }
  }

  /** The input can't be trusted any more (a frame the codec refused, stdin closed, stdout broke): end. */
  fail(reason) { this.#end(reason); }

  #startFrame(head) {
    if (this.#state !== "hello") return this.#end(this.#state === "new" ? "start before the hello" : "a second start");
    this.#start = Object.freeze({ session: head.session, browserGen: head.browser_gen, hostStaticPub: head.host_static_pub, relayUrl: head.relay_url });
    this.#state = "started";
  }

  #policyFrame(head) {
    // (the codec admits only an empty exception list until §9 test 8 qualifies them; kept as given)
    this.#policy = Object.freeze({ exceptions: [...head.exceptions] });
  }

  #record(body) {
    if (this.#state !== "started") return this.#end(this.#state === "live" ? "a second record" : "a record before start");
    if (!body || body.length === 0) return this.#end("an empty record");
    if (!this.#makeChannel) return this.#end("no channel in this build");
    this.#state = "live";
    if (!this.#emit({ to: "rust", kind: "rust.net_state", state: "connecting" })) return;
    let channel;
    try {
      channel = this.#makeChannel({
        start: this.#start, record: Buffer.from(body), key: this.#key, policy: this.#policy,
        onCommand: (seq, bytes) => this.#command(seq, bytes),
        onState: (state, reason) => this.#channelState(state, reason),
      });
    } catch { return this.#end("the channel couldn't be made"); }
    // (the channel may call back before makeChannel returns: if that ended the sidecar, this channel is closed now,
    //  once, and never kept)
    if (this.#state === "ended") { try { channel?.close(); } catch { /* (ending either way) */ } return; }
    if (!channel) return this.#end("the channel couldn't be made");
    this.#channel = channel;
  }

  #command(seq, bytes) {
    if (this.#state !== "live") return;
    if (!this.#channel) return this.#end("the channel spoke before it was made"); // (no channel to answer through yet)
    if (!Number.isSafeInteger(seq) || seq < 0 || seq <= this.#lastSeq) return this.#end("a repeated or out-of-order seq from the channel");
    this.#lastSeq = seq;
    if (!(bytes instanceof Uint8Array) || bytes.length === 0 || bytes.length > COMMAND_BYTES) return this.#channel.refused(seq, "bad");
    this.#open.add(seq);
    this.#emit({ to: "cdp", kind: "cdp.command", seq }, Buffer.from(bytes));
  }

  #answer(seq, deliver) {
    if (!this.#open.delete(seq)) return this.#end("an answer for no open command");
    deliver(this.#channel);
  }

  #channelState(state) {
    if (this.#state !== "live") return;
    if (!this.#channel && state !== "ended") return this.#end("the channel spoke before it was made");
    if (state === "ended") return this.#end("the channel ended"); // (fixed: the channel's own reason may carry the host's words)
    if (state !== "open" && state !== "resuming") return this.#end("the channel said something unknown");
    this.#emit({ to: "rust", kind: "rust.net_state", state });
  }

  // Ending, all at once and in this order: no more admissions (every entry point checks the state, so the channel's
  // callbacks and the app's frames are ignored from here); the channel closed and forgotten; the proxy stopped; then
  // exactly one terminal frame attempted (it alone may use the writer's reserve); then the process flushes, within
  // its deadline, and exits.
  #end(reason) {
    if (this.#state === "ended") return;
    this.#state = "ended";
    this.#open.clear();
    const channel = this.#channel;
    this.#channel = null;
    try { channel?.close(); } catch { /* (ending either way) */ }
    try { this.#proxy?.close(); } catch { /* (ending either way) */ }
    try { this.#send({ to: "rust", kind: "rust.net_state", state: "ended", reason }, undefined, { terminal: true }); } catch { /* (the output is gone) */ }
    this.#onEnd(reason);
  }
}
