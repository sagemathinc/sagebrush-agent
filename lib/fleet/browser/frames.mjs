// Fleet protocol, the browser lane (the macOS app's runtime, browser-lane3-runtime.md, "The two sidecars and their
// IPC"): the frames between Rust and the two sidecars of one browser session, cdp and net. Each sidecar talks only to
// Rust, over its own stdin and stdout; Rust is the only router and checks every frame against the same tables (its
// mirror is in the app). Both sidecars use this codec.
//
// A frame is u32 BE total_len, u32 BE head_len, the head, then the body (the rest), with total_len = 4 + head_len +
// body_len. The head is canonical JSON (lib/canon.mjs: sorted keys, no whitespace, so no duplicate key and nothing
// after the value), at most 64 KiB: { to, kind, ...fields }. total_len is at most 64 MiB + 64 KiB.
//
// Every kind has one sender and one receiver (its prefix is the receiver) and a closed schema: exact fields, their
// types and caps. Only cdp.command, net.result, net.event and net.record may carry a body. Anything else (a short or
// oversize frame, a head that isn't canonical, an unknown or misrouted kind, a field missing, extra or out of bounds,
// a body where none is allowed, or the stream ending inside a frame) is a FrameError, and the decoder is dead after
// it: the sidecar ends (and Rust retires the session). Error messages are fixed strings: no head or body bytes.

import { parseCanonical, canonText } from "../canonical.mjs";
import { FleetError } from "../bytes.mjs";

export const LIMITS = Object.freeze({
  headBytes: 64 * 1024,
  totalBytes: 64 * 1024 * 1024 + 64 * 1024,
  idBytes: 64,
  reasonBytes: 256,
  urlBytes: 2048,
  credentialBytes: 128,
});

/** A frame that breaks the rules. `code`: short | oversize | head | kind | route | schema | body | truncated | dead. */
export class FrameError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "FrameError";
    this.code = code;
  }
}
const fail = (code, message) => { throw new FrameError(code, message); };

const bytes = (s) => Buffer.byteLength(s, "utf8");
const str = (max, { min = 1 } = {}) => (v) => typeof v === "string" && bytes(v) >= min && bytes(v) <= max;
const oneOf = (...xs) => (v) => xs.includes(v);
const u64 = (v) => Number.isSafeInteger(v) && v >= 0; // (JSON numbers: the safe integers; canon refuses the rest)
const id = str(LIMITS.idBytes);
const reason = str(LIMITS.reasonBytes);
const cred = str(LIMITS.credentialBytes);
const port = (v) => Number.isSafeInteger(v) && v >= 1024 && v <= 65535;
const wss = (v) => str(LIMITS.urlBytes)(v) && /^wss:\/\/[^\s]+$/.test(v);

// kind -> { from, fields: { name: check }, optional: { name: check }, body }
const K = (from, fields = {}, optional = {}, body = false) => Object.freeze({ from, fields, optional, body });
const control = (from) => K(from, {}, { reason });

export const KINDS = Object.freeze({
  // Rust -> net
  "net.start": K("rust", { session: id, browser_gen: u64, host_static_pub: id, relay_url: wss }),
  "net.record": K("rust", {}, {}, true),
  "net.policy": K("rust", { exceptions: (v) => Array.isArray(v) && v.length === 0 }),
  "net.takeover": control("rust"),
  "net.resume": control("rust"),
  "net.retire": control("rust"),
  // net -> Rust
  "rust.net_hello": K("net", {
    app_session_pub: id,
    proxy_port: port,
    proxy_username: cred,
    proxy_password: cred,
  }),
  "rust.net_state": K("net", { state: oneOf("connecting", "open", "resuming", "ended") }, { reason }),
  // Rust -> cdp
  "cdp.start": K("rust", { chrome_pid: (v) => Number.isSafeInteger(v) && v > 0 && v <= 0x7fffffff }),
  "cdp.proxy_auth": K("rust", { username: cred, password: cred, proxy_port: port }),
  "cdp.takeover": control("rust"),
  "cdp.resume": control("rust"),
  "cdp.retire": control("rust"),
  // cdp -> Rust
  "rust.cdp_state": K("cdp", { state: oneOf("starting", "ready", "paused", "ended") }, { reason }),
  "rust.takeover_done": control("cdp"),
  "rust.takeover_failed": control("cdp"),
  // net -> cdp, through Rust
  "cdp.command": K("net", { seq: u64 }, {}, true),
  // cdp -> net, through Rust
  "net.result": K("cdp", { seq: u64 }, {}, true),
  "net.event": K("cdp", {}, {}, true),
  "net.refused": K("cdp", { seq: u64, reason: oneOf("takeover", "bad") }),
});

const PARTIES = new Set(["rust", "cdp", "net"]);

/**
 * Whether a net.result body is the session's answer as the doc writes it: one JSON object, exactly
 * {"result": object} or {"error": {"code": integer, "message": string}}. The cdp sidecar's encoder checks it before
 * the frame is written (Rust routes on heads alone, and net never parses CDP).
 */
export function isAnswer(body) {
  let v;
  try { v = JSON.parse(utf8.decode(body)); } catch { return false; }
  if (v === null || typeof v !== "object" || Array.isArray(v)) return false;
  const keys = Object.keys(v);
  if (keys.length !== 1) return false;
  if (keys[0] === "result") return v.result !== null && typeof v.result === "object" && !Array.isArray(v.result);
  if (keys[0] !== "error") return false;
  const e = v.error;
  if (e === null || typeof e !== "object" || Array.isArray(e)) return false;
  const ek = Object.keys(e).sort();
  return ek.length === 2 && ek[0] === "code" && ek[1] === "message" && Number.isSafeInteger(e.code) && typeof e.message === "string" && bytes(e.message) <= LIMITS.reasonBytes * 4;
}
const utf8 = new TextDecoder("utf-8", { fatal: true });
const receiver = (kind) => kind.slice(0, kind.indexOf("."));

/** Check a head against its kind's schema; returns the kind's entry. `from`/`to` are the path's two ends. */
function check(head, bodyLength, from, to) {
  if (head === null || typeof head !== "object" || Array.isArray(head)) fail("head", "a frame head is an object");
  const kind = head.kind;
  if (typeof kind !== "string" || !Object.hasOwn(KINDS, kind)) fail("kind", "an unknown frame kind");
  const k = KINDS[kind];
  if (head.to !== receiver(kind) || receiver(kind) !== to || (from !== undefined && k.from !== from)) fail("route", "a frame kind not allowed on this path");
  for (const name of Object.keys(head)) {
    if (name === "to" || name === "kind") continue;
    const c = Object.hasOwn(k.fields, name) ? k.fields[name] : Object.hasOwn(k.optional, name) ? k.optional[name] : null;
    if (!c) fail("schema", "a field this frame kind doesn't have");
    if (!c(head[name])) fail("schema", "a field out of bounds");
  }
  for (const name of Object.keys(k.fields)) if (!Object.hasOwn(head, name)) fail("schema", "a field missing");
  if (bodyLength > 0 && !k.body) fail("body", "a body on a frame kind that has none");
  return k;
}

/**
 * The frame encoder for one party (`from`): encode(head, body?) -> Buffer. A head this party may not send, or that
 * breaks its kind's schema, throws FrameError (a bug in the caller: nothing is written).
 */
export function createEncoder({ from }) {
  if (!PARTIES.has(from)) throw new TypeError("createEncoder: from is rust, cdp or net");
  return (head, body = Buffer.alloc(0)) => {
    if (!(body instanceof Uint8Array)) throw new TypeError("encode: body must be bytes");
    const to = typeof head?.kind === "string" && head.kind.includes(".") ? receiver(head.kind) : undefined;
    check(head, body.length, from, to);
    if (head.kind === "net.result" && !isAnswer(body)) fail("body", "a result that isn't an answer");
    let text;
    try { text = canonText(head, LIMITS.headBytes); } catch (e) { if (e instanceof FleetError) fail("head", "a frame head that can't be encoded"); throw e; }
    const h = Buffer.from(text, "utf8");
    const total = 4 + h.length + body.length;
    if (total > LIMITS.totalBytes) fail("oversize", "a frame over the size limit");
    const out = Buffer.allocUnsafe(4 + total);
    out.writeUInt32BE(total, 0);
    out.writeUInt32BE(h.length, 4);
    h.copy(out, 8);
    Buffer.from(body.buffer, body.byteOffset, body.length).copy(out, 8 + h.length);
    return out;
  };
}

/**
 * The frame decoder for one party (`to`), reading what Rust sends it (or, for Rust, what one sidecar sends: give
 * `from`). push(chunk) -> [{ head, body }] in order; end() checks the stream didn't stop inside a frame. After any
 * FrameError the decoder is dead: every later call throws. A frame's length is checked as soon as its 4 bytes are in,
 * before any of its bytes are kept; a partial frame is held in one buffer that grows by doubling, never past one
 * frame's size, and each body is a copy (no frame keeps a reader's chunk alive).
 */
export function createDecoder({ to, from }) {
  if (!PARTIES.has(to) || (from !== undefined && (!PARTIES.has(from) || from === to))) throw new TypeError("createDecoder: to (and from) are rust, cdp or net");
  let buf = Buffer.alloc(0), size = 0, dead = false;
  const append = (piece) => {
    const need = size + piece.length;
    if (need > buf.length) {
      let cap = Math.max(buf.length, 64 * 1024);
      while (cap < need) cap *= 2;
      const next = Buffer.allocUnsafe(Math.min(cap, 4 + LIMITS.totalBytes));
      buf.copy(next, 0, 0, size);
      buf = next;
    }
    piece.copy(buf, size);
    size = need;
  };
  const lengthOf = (total) => {
    if (total < 4 + 2) fail("short", "a frame too short to hold a head");
    if (total > LIMITS.totalBytes) fail("oversize", "a frame over the size limit");
    return 4 + total;
  };
  const parse = (frame) => {
    const headLen = frame.readUInt32BE(4);
    if (headLen < 2 || headLen > frame.length - 8) fail("short", "a head length that doesn't fit the frame");
    if (headLen > LIMITS.headBytes) fail("oversize", "a head over the size limit");
    let head;
    try { head = parseCanonical(frame.subarray(8, 8 + headLen), LIMITS.headBytes); } catch (e) { if (e instanceof FleetError) fail("head", "a frame head that isn't canonical JSON"); throw e; }
    const body = Buffer.from(frame.subarray(8 + headLen)); // (a copy)
    check(head, body.length, from, to);
    return Object.freeze({ head, body });
  };
  const guard = (fn) => {
    if (dead) fail("dead", "the frame stream already failed");
    try { return fn(); } catch (e) {
      dead = true;
      buf = Buffer.alloc(0);
      size = 0;
      throw e;
    }
  };
  return Object.freeze({
    push(chunk) {
      if (!(chunk instanceof Uint8Array)) throw new TypeError("push: chunk must be bytes");
      return guard(() => {
        const frames = [];
        let rest = Buffer.from(chunk.buffer, chunk.byteOffset, chunk.length);
        while (rest.length > 0) {
          if (size === 0 && rest.length >= 4) {
            const want = lengthOf(rest.readUInt32BE(0));
            if (rest.length >= want) {
              frames.push(parse(rest.subarray(0, want))); // (a whole frame in this chunk: parsed in place)
              rest = rest.subarray(want);
              continue;
            }
          }
          if (size < 4) {
            const n = Math.min(4 - size, rest.length);
            append(rest.subarray(0, n));
            rest = rest.subarray(n);
            if (size < 4) break;
          }
          const want = lengthOf(buf.readUInt32BE(0));
          const n = Math.min(want - size, rest.length);
          append(rest.subarray(0, n));
          rest = rest.subarray(n);
          if (size < want) break;
          frames.push(parse(buf.subarray(0, want)));
          size = 0;
          if (buf.length > 64 * 1024) buf = Buffer.alloc(0); // (a large frame's buffer isn't kept)
        }
        return frames;
      });
    },
    end() {
      guard(() => { if (size > 0) fail("truncated", "the stream ended inside a frame"); });
    },
  });
}
