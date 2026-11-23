// Fleet protocol, the browser lane (O11 draft 5; the macOS app's runtime, browser-lane3-runtime.md): the CDP client on
// Chrome's debugging pipe, for the cdp sidecar. Rust launches Chrome with --remote-debugging-pipe and hands the sidecar
// the other ends of Chrome's fds 3 and 4; this module speaks CDP over them and nothing else. It holds no timers and no
// deadlines (those are the driver's, session.mjs) and never kills anything (Rust owns Chrome's process).
//
// The pipe carries JSON messages, each ended by one NUL byte. The client closes the pipe, settling `closed`, when:
// - one message would be over LIMITS.messageBytes (checked as bytes arrive, before any parsing);
// - a message isn't JSON, isn't an object, or is neither a well-formed reply nor a well-formed event;
// - a reply matches no pending send (by id and sessionId);
// - a listener throws;
// - the pipe ends or errors.
// Close reasons are fixed strings: nothing Chrome sent is ever copied into one.

export const LIMITS = Object.freeze({ messageBytes: 64 * 1024 * 1024 });

/** A CDP error response to one send. */
export class CdpError extends Error {
  constructor(code, message, data) {
    super(message);
    this.name = "CdpError";
    this.code = code;
    if (data !== undefined) this.data = data;
  }
}

/** The pipe closed before a send was answered (or before it was sent). */
export class CdpClosed extends Error {
  constructor(reason) {
    super(`CDP pipe closed: ${reason}`);
    this.name = "CdpClosed";
    this.reason = reason;
  }
}

const NUL = 0;
const INITIAL_BYTES = 64 * 1024; // (the read buffer's first size)
const utf8 = new TextDecoder("utf-8", { fatal: true });
const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const okSession = (v) => v === undefined || typeof v === "string";

/**
 * Opens the CDP client on Chrome's pipe.
 * @param {{ read: import("node:stream").Readable, write: import("node:stream").Writable, pid: number }} ends
 *   read: Chrome's fd 4 (Chrome writes); write: Chrome's fd 3 (Chrome reads); pid: Chrome's, from Rust, for
 *   information only.
 * @returns {Promise<Cdp>} once the pipe answers Browser.getVersion; rejects with CdpClosed if it closes first.
 */
export async function openPipe({ read, write, pid }) {
  if (!read || typeof read.on !== "function") throw new TypeError("openPipe: read must be a readable stream");
  if (!write || typeof write.write !== "function") throw new TypeError("openPipe: write must be a writable stream");
  if (!Number.isSafeInteger(pid) || pid <= 0) throw new TypeError("openPipe: pid must be a positive integer");
  const cdp = new Cdp(read, write, pid);
  try {
    await cdp.send("Browser.getVersion");
  } catch (e) {
    cdp._close(e instanceof CdpClosed ? e.reason : "Browser.getVersion failed");
    throw e instanceof CdpClosed ? e : new CdpClosed("Browser.getVersion failed");
  }
  return cdp;
}

export class Cdp {
  #read;
  #write;
  #nextId = 0;
  #pending = new Map(); // id -> { sessionId, resolve, reject }
  #listeners = new Set();
  // The bytes of the message being read, after the last NUL: copied into one buffer that grows by doubling (never past
  // LIMITS.messageBytes), so memory is bounded by the byte limit however finely the message arrives.
  #buf = Buffer.alloc(0);
  #size = 0;
  #reason = null;
  #settle;

  constructor(read, write, pid) {
    this.#read = read;
    this.#write = write;
    this.pid = pid;
    this.closed = new Promise((resolve) => { this.#settle = resolve; });
    read.on("data", (chunk) => this.#data(chunk));
    read.on("end", () => this._close("pipe ended"));
    read.on("close", () => this._close("pipe ended"));
    read.on("error", () => this._close("pipe read error"));
    write.on("error", () => this._close("pipe write error"));
    write.on("close", () => this._close("pipe ended"));
  }

  /** Sends one command; resolves with CDP's `result` object. */
  send(method, params = {}, sessionId) {
    if (typeof method !== "string" || method === "") return Promise.reject(new TypeError("send: method must be a non-empty string"));
    if (!isObject(params)) return Promise.reject(new TypeError("send: params must be an object"));
    if (!okSession(sessionId)) return Promise.reject(new TypeError("send: sessionId must be a string"));
    if (this.#reason !== null) return Promise.reject(new CdpClosed(this.#reason));
    const id = ++this.#nextId;
    const msg = sessionId === undefined ? { id, method, params } : { id, method, params, sessionId };
    const bytes = Buffer.from(JSON.stringify(msg), "utf8");
    if (bytes.length > LIMITS.messageBytes) return Promise.reject(new RangeError("send: message over the size limit"));
    const p = new Promise((resolve, reject) => { this.#pending.set(id, { sessionId, resolve, reject }); });
    try {
      this.#write.write(Buffer.concat([bytes, Buffer.from([NUL])]));
    } catch {
      this._close("pipe write error"); // (a write that throws closes the pipe: this send and every other one reject)
    }
    return p;
  }

  /** Every event, in pipe order, synchronously as it is parsed. Returns an unsubscribe function. */
  on(listener) {
    if (typeof listener !== "function") throw new TypeError("on: listener must be a function");
    const entry = { listener }; // (its own entry, so subscribing the same function twice delivers twice)
    this.#listeners.add(entry);
    return () => { this.#listeners.delete(entry); };
  }

  /** Browser.close, then waits for Chrome to end the pipe (Rust kills Chrome if it hasn't exited within 5 s). */
  async close() {
    if (this.#reason === null) this.send("Browser.close").catch(() => {});
    await this.closed;
  }

  #data(chunk) {
    if (this.#reason !== null) return;
    let start = 0;
    for (;;) {
      const end = chunk.indexOf(NUL, start);
      const piece = end === -1 ? chunk.subarray(start) : chunk.subarray(start, end);
      if (this.#size + piece.length > LIMITS.messageBytes) return this._close("message over the size limit");
      let bytes;
      if (end !== -1 && this.#size === 0) bytes = piece; // (a whole message in this chunk: no copy)
      else {
        this.#append(piece);
        if (end === -1) return;
        bytes = this.#buf.subarray(0, this.#size);
      }
      this.#size = 0;
      this.#message(bytes);
      if (this.#buf.length > INITIAL_BYTES) this.#buf = Buffer.alloc(0); // (a large message's buffer isn't kept)
      if (this.#reason !== null) return;
      start = end + 1;
    }
  }

  #append(piece) {
    const need = this.#size + piece.length;
    if (need > this.#buf.length) {
      let cap = Math.max(this.#buf.length, INITIAL_BYTES);
      while (cap < need) cap *= 2;
      const next = Buffer.allocUnsafe(Math.min(cap, LIMITS.messageBytes));
      this.#buf.copy(next, 0, 0, this.#size);
      this.#buf = next;
    }
    piece.copy(this.#buf, this.#size);
    this.#size = need;
  }

  #message(bytes) {
    let msg;
    try {
      msg = JSON.parse(utf8.decode(bytes));
    } catch {
      return this._close("malformed message");
    }
    if (!isObject(msg) || !okSession(msg.sessionId)) return this._close("malformed message");
    if ("id" in msg) {
      if (!Number.isSafeInteger(msg.id)) return this._close("malformed message");
      const p = this.#pending.get(msg.id);
      if (!p || p.sessionId !== msg.sessionId) return this._close("unmatched reply");
      if ("error" in msg) {
        const e = msg.error;
        if (!isObject(e) || !Number.isSafeInteger(e.code) || typeof e.message !== "string") return this._close("malformed message");
        this.#pending.delete(msg.id);
        return p.reject(new CdpError(e.code, e.message, e.data));
      }
      const result = msg.result === undefined ? {} : msg.result;
      if (!isObject(result)) return this._close("malformed message");
      this.#pending.delete(msg.id);
      return p.resolve(result);
    }
    if (typeof msg.method !== "string" || msg.method === "") return this._close("malformed message");
    const params = msg.params === undefined ? {} : msg.params;
    if (!isObject(params)) return this._close("malformed message");
    const ev = msg.sessionId === undefined ? { method: msg.method, params } : { method: msg.method, params, sessionId: msg.sessionId };
    for (const { listener } of [...this.#listeners]) {
      try {
        listener(ev);
      } catch {
        return this._close("listener threw");
      }
      if (this.#reason !== null) return;
    }
  }

  /** (internal) Closes the client once: rejects every pending send, settles `closed`, and releases both pipe ends. */
  _close(reason) {
    if (this.#reason !== null) return;
    this.#reason = reason;
    this.#buf = Buffer.alloc(0);
    this.#size = 0;
    const pending = [...this.#pending.values()];
    this.#pending.clear();
    for (const p of pending) p.reject(new CdpClosed(reason));
    this.#settle({ reason });
    this.#read.destroy?.();
    this.#write.destroy?.();
  }
}
