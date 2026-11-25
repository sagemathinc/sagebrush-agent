// The writer's journal (the design note §3.1, §6.1): what a writer has to publish, kept durably by its caller (this
// module is the accounting and the order; the caller persists `state()` and restores it with `Journal.from`).
//
// The cap is on the DURABLE representation, exactly (LIMITS H3): `used` is the byte length of JSON.stringify(state())
// at every moment, counted incrementally: each line as its base64 text with its quotes and separator, each turn's own
// metadata (its id, time, counts, flags and intent), the context slot, and the envelope. So empty turns cost their
// metadata, and nothing persisted is uncounted. Every mutation that grows it checks it first; Journal.from refuses a
// state over its cap. Three sizes, distinguished:
//   - logical payload (`payload`): the raw bytes of the journaled lines and the context;
//   - durable bytes (`used`): what state() serializes to (base64 makes it about 4/3 of the payload, plus metadata);
//   - working memory: the lines and the context as held (the payload) plus each turn's small metadata; state() makes
//     a transient string of `used` bytes when the caller persists it.
// Room is held back, always: the open turn's completion (its gap line and metadata growth), each pending turn's intent,
// and the context slot's reserve (a context of up to `contextReserve` bytes).
//
// - A turn's lines that would pass the cap are kept up to it, and the rest become ONE gap line
//   { gap: true, omitted_lines, omitted_bytes }. Once a line is omitted, every later one is too.
// - When the journal is full, new turns aren't journaled: they're counted, and the next turn journaled starts with a gap
//   line { gap: true, turns, from_ms, to_ms }: visible, never silent, no backfill.
// - A turn's lines retire only by THAT turn's acknowledgement; the context slot holds the newest context and retires by
//   any acknowledgement at the same or a higher seq. Replacing the context never touches a turn's lines.

import { CONTEXT_MAX, JOURNAL_MAX } from "./limits.mjs";
import { encodeLine } from "./transcript.mjs";

/** A gap line's most bytes (a few ids and counts). */
const GAP_MAX = 256;
/** The most a turn's metadata grows after it begins (counts and flags), and an intent's serialized size. */
const META_SLACK = 128, INTENT_MAX = 256;

const b64len = (n) => 4 * Math.ceil(n / 3);
const lineCost = (n) => b64len(n) + 2; // its base64 text and quotes (the separating comma is counted per turn)
// (the UTF-8 bytes of a value's JSON: the durable form is bytes, whatever the characters)
const te = new TextEncoder();
const enc = (v) => te.encode(JSON.stringify(v)).length;
/** A turn's id: a non-empty string of at most this many UTF-8 bytes. */
const TURN_ID_MAX = 128;

export class Journal {
  constructor({ max = JOURNAL_MAX, contextReserve = CONTEXT_MAX } = {}) {
    if (!Number.isSafeInteger(max) || max < 1) throw new RangeError("max: a positive byte count");
    if (!Number.isSafeInteger(contextReserve) || contextReserve < 0) throw new RangeError("contextReserve: a byte count");
    this.max = max;
    this.contextReserve = contextReserve;
    // (the cap must hold its own envelope and the context slot's reserve, or nothing could ever be journaled)
    const floor = enc({ max, contextReserve, missed: null, turns: [], context: null }) - 4 + this.contextCost({ seq: Number.MAX_SAFE_INTEGER, bytes: { length: contextReserve } });
    if (floor > max) throw new RangeError("max: smaller than the envelope and the context reserve");
    this.turns = [];      // [{ turn, at_ms, lines: [Uint8Array], omitted: { lines, bytes }, done, intent }]
    this.context = null;  // { seq, bytes }
    this.missed = null;   // { turns, from_ms, to_ms }
    this.open = null;
    this.linesCost = new Map(); // turn -> the serialized cost of its lines (base64, quotes and commas)
  }

  // ---- the exact serialized size
  static meta(t) { return enc({ turn: t.turn, at_ms: t.at_ms, omitted: t.omitted, done: t.done, intent: t.intent, lines: [] }); }
  turnCost(t) { return Journal.meta(t) + (this.linesCost.get(t.turn) ?? 0); }
  contextCost(c) { return c ? enc({ seq: c.seq, bytes: "" }) + b64len(c.bytes.length) : 4; } // (4: "null")
  get used() {
    const envelope = enc({ max: this.max, contextReserve: this.contextReserve, missed: this.missed, turns: [], context: null }) - 4;
    const turns = this.turns.reduce((a, t) => a + this.turnCost(t), 0) + Math.max(0, this.turns.length - 1);
    return envelope + turns + this.contextCost(this.context);
  }
  /** The raw bytes held: lines and the context. */
  get payload() { return this.turns.reduce((a, t) => a + t.lines.reduce((x, l) => x + l.length, 0), 0) + (this.context ? this.context.bytes.length : 0); }

  /** What's held back: the open turn's completion, each pending turn's intent, the context slot's reserve. */
  reserved() {
    const open = this.open ? lineCost(GAP_MAX) + 1 + META_SLACK : 0;
    const intents = this.turns.filter((t) => t.intent === null).length * INTENT_MAX;
    const ctx = Math.max(0, this.contextCost({ seq: Number.MAX_SAFE_INTEGER, bytes: { length: this.contextReserve } }) - this.contextCost(this.context));
    return open + intents + ctx;
  }
  room() { return this.max - this.used - this.reserved(); }

  /**
   * Start journaling a turn: { ok, first }, `first` the index its own content lines start at (after a gap line for
   * missed turns). ok false when the turn's metadata and its completion don't fit: it is counted as missed.
   */
  begin(turn, at_ms) {
    if (this.open) throw new Error("a turn is already open");
    if (typeof turn !== "string" || turn.length === 0 || te.encode(turn).length > TURN_ID_MAX) throw new RangeError("turn: an id of at most TURN_ID_MAX bytes");
    if (!Number.isSafeInteger(at_ms)) throw new RangeError("at_ms: a safe integer");
    const t = { turn, at_ms, lines: [], omitted: { lines: 0, bytes: 0 }, done: false, intent: null };
    const need = Journal.meta(t) + 1 + INTENT_MAX + lineCost(GAP_MAX) + 1 + META_SLACK + (this.missed ? lineCost(GAP_MAX) + 1 : 0);
    if (need > this.room()) {
      this.missed = this.missed ? { turns: this.missed.turns + 1, from_ms: this.missed.from_ms, to_ms: at_ms } : { turns: 1, from_ms: at_ms, to_ms: at_ms };
      return { ok: false, first: 0 };
    }
    this.turns.push(t);
    this.linesCost.set(turn, 0);
    this.open = t;
    if (this.missed) {
      const m = this.missed;
      this.missed = null;
      this.push(t, encodeLine({ turn, i: 1, gap: true, turns: m.turns, from_ms: m.from_ms, to_ms: m.to_ms }));
    }
    return { ok: true, first: t.lines.length + 1 };
  }

  push(t, line) {
    t.lines.push(line);
    this.linesCost.set(t.turn, (this.linesCost.get(t.turn) ?? 0) + lineCost(line.length) + (t.lines.length > 1 ? 1 : 0));
  }

  /** Journal one content line (encoded, its `i` the next index). false when it didn't fit: counted as omitted. */
  add(line) {
    const t = this.open;
    if (!t) throw new Error("no open turn");
    if (t.omitted.lines === 0 && lineCost(line.length) + 1 <= this.room()) {
      this.push(t, line);
      return true;
    }
    t.omitted.lines++;
    t.omitted.bytes += line.length;
    return false;
  }

  /** Finish the open turn: a gap line for what was omitted (from its reserve), then it is publishable. */
  finish() {
    const t = this.open;
    if (!t) throw new Error("no open turn");
    if (t.omitted.lines) {
      const g = encodeLine({ turn: t.turn, i: t.lines.length + 1, gap: true, omitted_lines: t.omitted.lines, omitted_bytes: t.omitted.bytes });
      if (g.length > GAP_MAX) throw new Error("a gap line over GAP_MAX");
      this.push(t, g);
    }
    t.done = true;
    this.open = null;
    if (this.used > this.max) throw new Error("the journal over its cap");
    return t;
  }

  pending() { return this.turns.filter((t) => t.done); }

  /** The allocation intent, recorded before the start line's compare-and-set (from the turn's intent reserve). */
  intend(turn, intent) {
    const t = this.turns.find((x) => x.turn === turn);
    if (!t) return;
    if (enc(intent) > INTENT_MAX) throw new RangeError("an intent over INTENT_MAX");
    t.intent = intent;
    if (this.used > this.max) throw new Error("the journal over its cap");
  }

  retireTurn(turn) { this.turns = this.turns.filter((t) => t.turn !== turn); this.linesCost.delete(turn); if (this.open?.turn === turn) this.open = null; }

  /** The newest context replaces the slot: false (refused) when older than the slot's, or larger than the reserve. */
  setContext(seq, bytes) {
    if (this.context && this.context.seq > seq) return false;
    if (!(bytes instanceof Uint8Array) || bytes.length > this.contextReserve || !Number.isSafeInteger(seq)) return false;
    // (preflight: the total with this context, never over the cap)
    const prev = this.context;
    this.context = { seq, bytes };
    if (this.used > this.max) { this.context = prev; return false; }
    return true;
  }

  ackContext(seq) { if (this.context && this.context.seq <= seq) this.context = null; }

  /** The durable state: exactly `used` bytes once serialized. */
  state() {
    return { max: this.max, contextReserve: this.contextReserve, missed: this.missed,
      turns: this.turns.map((t) => ({ turn: t.turn, at_ms: t.at_ms, omitted: t.omitted, done: t.done, intent: t.intent, lines: t.lines.map(b64) })),
      context: this.context && { seq: this.context.seq, bytes: b64(this.context.bytes) } };
  }

  /** Back from a persisted state; refused when its serialized size passes its cap. */
  static from(s) {
    const j = new Journal({ max: s.max, contextReserve: s.contextReserve });
    j.missed = s.missed;
    for (const t of s.turns) {
      const u = { turn: t.turn, at_ms: t.at_ms, lines: [], omitted: t.omitted, done: t.done, intent: t.intent };
      j.turns.push(u);
      j.linesCost.set(u.turn, 0);
      for (const l of t.lines) j.push(u, unb64(l));
      if (!u.done) j.open = u;
    }
    if (s.context) {
      const bytes = unb64(s.context.bytes);
      if (bytes.length > j.contextReserve) throw new Error("a restored context over its reserve");
      j.context = { seq: s.context.seq, bytes };
    }
    if (j.used > j.max) throw new Error("a restored journal over its cap");
    return j;
  }
}

// (base64 without Node built-ins, so the module runs in a page as it does on a host)
function b64(u) {
  let s = "";
  for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode(...u.subarray(i, i + 0x8000));
  return btoa(s);
}
function unb64(x) {
  const s = atob(x), u = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) u[i] = s.charCodeAt(i);
  return u;
}
