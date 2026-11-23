// The browser channel's frames (design agent-autonomous-browser-channel.md r4 §4; O11 §7.3): one frame per Noise
// transport message, a fixed 29-byte big-endian header and a raw body. A message larger than one frame is split into
// fragments under one seq and reassembled before it is acted on; its bytes are then canonical JSON with a closed
// schema per kind. The rules:
//   - who sends what: cmd only from the broker; res and evt only from the app; ctl from both. recv is the app's and
//     rack the broker's: the field a sender doesn't own is 0;
//   - per kind and direction, one message at a time (its fragments in order, no gap); kinds may interleave;
//   - seq is an exact counter per kind and direction, rising by one within a transport; ctl's starts at 1;
//   - acknowledgements take effect only on a message's first fragment (H5): there the owned field must be >= the
//     sender's high-water mark and no more than may be acknowledged, and the mark is committed only after every check
//     on that fragment has passed (for a one-fragment message, its body's too). A continuation must carry its first
//     fragment's exact tuple. Tuples die with the transport;
//   - any violation ends the session (a FleetError).

import { refuse } from "../bytes.mjs";
import { canonText, parseCanonical } from "../core/canonical.mjs";

export const HEADER = 29;
export const BODY_MAX = 60000;
export const KIND = Object.freeze({ cmd: 1, res: 2, evt: 3, ctl: 4 });
const NAME = Object.freeze({ 1: "cmd", 2: "res", 3: "evt", 4: "ctl" });
const MAX = Number.MAX_SAFE_INTEGER;

/** Per kind: the largest reassembled body, and so the most fragments. */
export const LIMITS = Object.freeze({
  cmd: Object.freeze({ bytes: 128 * 1024, nfrag: 3 }),
  res: Object.freeze({ bytes: 8 * 1024 * 1024, nfrag: 140 }),
  evt: Object.freeze({ bytes: 66560, nfrag: 2 }),
  ctl: Object.freeze({ bytes: 1024, nfrag: 1 }),
});
for (const l of Object.values(LIMITS)) if (Math.ceil(l.bytes / BODY_MAX) !== l.nfrag) throw new Error("frame limits disagree");

/** The kinds each end sends, and the acknowledgement field it owns. */
export const SENDER = Object.freeze({
  broker: Object.freeze({ kinds: Object.freeze(["cmd", "ctl"]), owns: "rack", zero: "recv" }),
  app: Object.freeze({ kinds: Object.freeze(["res", "evt", "ctl"]), owns: "recv", zero: "rack" }),
});

const exact = (v, what) => { if (!Number.isSafeInteger(v) || v < 0) refuse("bad_form", `${what} isn't an exact counter`); return v; };

/** One frame's bytes. */
export function encodeFrame({ kind, seq, frag, nfrag, recv, rack, body }) {
  const k = KIND[kind];
  if (!k) refuse("bad_form", "an unknown frame kind");
  if (!(body instanceof Uint8Array) || body.length > BODY_MAX) refuse("limit", "a frame body over 60,000 bytes");
  if (!Number.isInteger(frag) || !Number.isInteger(nfrag) || frag < 0 || frag >= nfrag || nfrag > LIMITS[kind].nfrag) refuse("bad_form", "a fragment index");
  const out = new Uint8Array(HEADER + body.length);
  const v = new DataView(out.buffer);
  v.setUint8(0, k);
  v.setBigUint64(1, BigInt(exact(seq, "seq")));
  v.setUint16(9, frag);
  v.setUint16(11, nfrag);
  v.setBigUint64(13, BigInt(exact(recv, "recv")));
  v.setBigUint64(21, BigInt(exact(rack, "rack")));
  out.set(body, HEADER);
  return out;
}

/** A frame's fields from its bytes: the 64-bit fields parsed as integers first, then held to 2^53 - 1. */
export function decodeFrame(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length < HEADER || bytes.length > HEADER + BODY_MAX) refuse("bad_form", "a frame's length");
  const v = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const kind = NAME[v.getUint8(0)];
  if (!kind) refuse("bad_form", "an unknown frame kind");
  const big = (at, what) => { const x = v.getBigUint64(at); if (x > BigInt(MAX)) refuse("bad_form", `${what} past 2^53 - 1`); return Number(x); };
  const seq = big(1, "seq"), recv = big(13, "recv"), rack = big(21, "rack");
  const frag = v.getUint16(9), nfrag = v.getUint16(11);
  if (nfrag < 1 || nfrag > LIMITS[kind].nfrag || frag >= nfrag) refuse("bad_form", "a fragment index");
  if (seq < 1) refuse("bad_form", "seq starts at 1");
  return { kind, seq, frag, nfrag, recv, rack, body: bytes.subarray(HEADER) };
}

/** A message's frames: its body split into fragments, every one carrying the same acknowledgements. */
export function fragment(kind, seq, body, { recv, rack }) {
  if (!LIMITS[kind]) refuse("bad_form", "an unknown frame kind");
  if (body.length > LIMITS[kind].bytes) refuse("limit", `a ${kind} over its bound`);
  const nfrag = Math.max(1, Math.ceil(body.length / BODY_MAX));
  const out = [];
  for (let frag = 0; frag < nfrag; frag++) out.push(encodeFrame({ kind, seq, frag, nfrag, recv, rack, body: body.subarray(frag * BODY_MAX, (frag + 1) * BODY_MAX) }));
  return out;
}

// ---- the closed body schemas (the reassembled bytes are canonical JSON)

const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const keysAre = (o, ...ks) => isObj(o) && Object.keys(o).length === ks.length && ks.every((k) => Object.hasOwn(o, k));
export const REFUSED_REASONS = Object.freeze(["takeover", "bad", "paused", "credits"]);

/** The one value each kind's body may hold. cmd and evt carry the CDP filter's objects; their contents are its. */
export function checkBody(kind, value) {
  const ok = {
    cmd: () => keysAre(value, "command") && isObj(value.command),
    evt: () => keysAre(value, "event") && isObj(value.event),
    res: () => (keysAre(value, "answer") && isObj(value.answer)) || (keysAre(value, "outcome", "reason") && value.outcome === "unknown" && value.reason === "abandoned"),
    ctl: () => {
      if (!isObj(value) || typeof value.ctl !== "string") return false;
      switch (value.ctl) {
        case "ping": case "pong": return keysAre(value, "ctl", "t") && Number.isSafeInteger(value.t) && value.t >= 0;
        case "refused": return keysAre(value, "ctl", "seq", "reason") && Number.isSafeInteger(value.seq) && value.seq >= 1 && REFUSED_REASONS.includes(value.reason);
        case "events_lost": return keysAre(value, "ctl", "n") && Number.isSafeInteger(value.n) && value.n >= 0;
        case "paused": return keysAre(value, "ctl");
        default: return false;
      }
    },
  }[kind];
  if (!ok || !ok()) refuse("bad_form", `a ${kind} body outside its schema`);
  return value;
}

/** A body's bytes: canonical JSON of a value its kind allows. */
export function encodeBody(kind, value) {
  checkBody(kind, value);
  return new TextEncoder().encode(canonText(value, LIMITS[kind].bytes));
}

// ---- the reader: one per direction per transport

/**
 * Reads one sender's frames on one transport. `from`: "broker" or "app" (who sent them). `ackLimit()`: the most the
 * sender may acknowledge now (for an app, the highest command seq sent to it; for a broker, the highest result seq).
 * `highWater`: the acknowledgement already applied for this session before this transport (a resume), or 0.
 * Returns an object whose `push(frameBytes)` gives { kind, seq, value, ack } when a message completes, else null.
 */
export function reader({ from, ackLimit, highWater = 0 }) {
  const side = SENDER[from];
  if (!side) throw new Error("a reader reads the broker's or the app's frames");
  let hw = exact(highWater, "the high-water mark");
  const open = new Map(); // kind -> { tuple, parts, size }
  const lastSeq = new Map(); // kind -> last completed seq on this transport
  let dead = false;
  return Object.freeze({
    get highWater() { return hw; },
    push(bytes) {
      if (dead) refuse("bad_form", "this session ended");
      try {
        const f = decodeFrame(bytes);
        if (!side.kinds.includes(f.kind)) refuse("bad_form", `a ${f.kind} from the ${from}`);
        if (f[side.zero] !== 0) refuse("bad_form", `${side.zero} isn't the ${from}'s to send`);
        let m = open.get(f.kind);
        let commit = null;
        if (f.frag === 0) {
          if (m) refuse("bad_form", "a new message before the last of this kind finished");
          const last = lastSeq.get(f.kind);
          if (last !== undefined ? f.seq !== last + 1 : f.kind === "ctl" && f.seq !== 1) refuse("bad_form", `${f.kind} seq out of order`);
          const ack = f[side.owns];
          // (the caller's limit, once per first fragment, as an exact count: a NaN or undefined would compare false)
          const limit = ackLimit();
          if (!Number.isSafeInteger(limit) || limit < 0) refuse("bad_form", "the acknowledgement limit isn't an exact count");
          if (ack < hw) refuse("bad_form", `${side.owns} went back`);
          if (ack > limit) refuse("bad_form", `${side.owns} acknowledges what wasn't sent`);
          m = { tuple: [f.kind, f.seq, f.nfrag, f.recv, f.rack], parts: [], size: 0 };
          commit = ack;
        } else {
          if (!m || m.tuple[1] !== f.seq || m.parts.length !== f.frag) refuse("bad_form", "a fragment out of order");
          const t = [f.kind, f.seq, f.nfrag, f.recv, f.rack];
          if (t.some((x, i) => x !== m.tuple[i])) refuse("bad_form", "a continuation's header isn't its message's");
        }
        m.size += f.body.length;
        if (m.size > LIMITS[f.kind].bytes) refuse("limit", `a ${f.kind} over its bound`);
        if (f.frag < f.nfrag - 1 && f.body.length !== BODY_MAX) refuse("bad_form", "a short fragment before the last");
        m.parts.push(f.body);
        if (f.frag < f.nfrag - 1) {
          if (commit !== null) hw = commit; // (a first fragment of several: every check on it has passed)
          open.set(f.kind, m);
          return null;
        }
        open.delete(f.kind);
        lastSeq.set(f.kind, f.seq);
        const all = new Uint8Array(m.size);
        let at = 0;
        for (const p of m.parts) { all.set(p, at); at += p.length; }
        const value = checkBody(f.kind, parseCanonical(all, LIMITS[f.kind].bytes));
        if (commit !== null) hw = commit; // (a one-fragment message: committed only after its body passed too)
        return { kind: f.kind, seq: f.seq, value, bytes: all, ack: m.tuple[side.owns === "recv" ? 3 : 4] };
      } catch (e) {
        dead = true;
        throw e;
      }
    },
  });
}
