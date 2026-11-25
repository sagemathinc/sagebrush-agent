// The writer's journal (the design note §3.1, §6.1): what a writer has to publish, kept durably by its caller (this
// module is the accounting and the order; the caller persists `state()` and restores it with `Journal.from`).
//
// - Its bytes are counted AS a turn is journaled, never after assembling it (LIMITS H3). Room is held back for the
//   turn's gap line, its end marker and a newest context of up to CONTEXT_MAX, before a payload line is accepted.
// - A turn's lines that would pass JOURNAL_MAX are kept up to the cap; the rest become ONE gap line
//   { gap: true, omitted_lines, omitted_bytes } before the marker. A turn is publishable only once finished, so no
//   unfinishable prefix is ever published.
// - When the journal is full of unpublished turns, new turns aren't journaled: they're counted, and the next turn that
//   is journaled starts with a gap line { gap: true, turns, from_ms, to_ms }: visible, never silent, no backfill.
// - Two kinds of entry, retired separately (TESTS H2): a turn's lines only by THAT turn's marker acknowledgement; the
//   context, ONE slot holding the newest pending context, by the acknowledgement of any context at the same or a
//   higher seq. Replacing the context never touches a turn's lines.

import { CONTEXT_MAX, JOURNAL_MAX, LINE_MAX } from "./limits.mjs";
import { encodeLine } from "./transcript.mjs";

/** Room held for a turn's closing lines: one gap line and the end marker, each at most a line. */
const TURN_RESERVE = 2 * LINE_MAX;

export class Journal {
  constructor({ max = JOURNAL_MAX, contextReserve = CONTEXT_MAX } = {}) {
    this.max = max;
    this.contextReserve = contextReserve;
    this.turns = [];          // [{ turn, at_ms, lines: [Uint8Array], bytes, omitted: { lines, bytes }, done, intent }]
    this.context = null;      // { seq, bytes }
    this.missed = null;       // { turns, from_ms, to_ms }: turns not journaled while full
    this.open = null;
  }

  /** Bytes held now: every turn's lines plus the context slot. */
  get used() { return this.turns.reduce((a, t) => a + t.bytes, 0) + (this.context ? this.context.bytes.length : 0); }

  /** Room for payload lines: the cap, less what's held, the open turn's closing reserve and a context's worst case. */
  room() { return this.max - this.used - TURN_RESERVE - Math.max(0, this.contextReserve - (this.context ? this.context.bytes.length : 0)); }

  /**
   * Start journaling a turn. false when the journal is too full to start one (the turn is counted as missed, for the
   * next turn's gap line). On true, a previous run of missed turns becomes this turn's first content line.
   */
  begin(turn, at_ms) {
    if (this.open) throw new Error("a turn is already open");
    // (returns { ok, first }: `first` is the index the turn's own content lines start at, after any gap line here)
    if (this.room() < LINE_MAX) {
      this.missed = this.missed ? { turns: this.missed.turns + 1, from_ms: this.missed.from_ms, to_ms: at_ms } : { turns: 1, from_ms: at_ms, to_ms: at_ms };
      return { ok: false, first: 0 };
    }
    this.open = { turn, at_ms, lines: [], bytes: 0, omitted: { lines: 0, bytes: 0 }, done: false, intent: null };
    this.turns.push(this.open);
    if (this.missed) {
      const g = encodeLine({ turn, i: 1, gap: true, turns: this.missed.turns, from_ms: this.missed.from_ms, to_ms: this.missed.to_ms });
      this.open.lines.push(g);
      this.open.bytes += g.length;
      this.missed = null;
    }
    return { ok: true, first: this.open.lines.length + 1 };
  }

  /** Journal one content line (encoded, its `i` the next index). false when it didn't fit: it is counted as omitted. */
  add(line) {
    const t = this.open;
    if (!t) throw new Error("no open turn");
    if (t.omitted.lines === 0 && line.length + 1 <= this.room()) {
      t.lines.push(line);
      t.bytes += line.length;
      return true;
    }
    // (once a line is omitted, every later one is too: the kept part is a prefix, the gap names the rest)
    t.omitted.lines++;
    t.omitted.bytes += line.length;
    return false;
  }

  /** Finish the open turn: a gap line for what was omitted, then it is publishable. Returns the turn's entry. */
  finish() {
    const t = this.open;
    if (!t) throw new Error("no open turn");
    if (t.omitted.lines) {
      const g = encodeLine({ turn: t.turn, i: t.lines.length + 1, gap: true, omitted_lines: t.omitted.lines, omitted_bytes: t.omitted.bytes });
      t.lines.push(g);
      t.bytes += g.length;
    }
    t.done = true;
    this.open = null;
    return t;
  }

  /** The turns to publish, in journal order (finished ones only). */
  pending() { return this.turns.filter((t) => t.done); }

  /** The allocation intent, recorded before the start line's compare-and-set. */
  intend(turn, intent) { const t = this.turns.find((x) => x.turn === turn); if (t) t.intent = intent; }

  /** A turn's end marker was acknowledged: its lines are retired. Nothing else retires them. */
  retireTurn(turn) { this.turns = this.turns.filter((t) => t.turn !== turn); }

  /** The newest context replaces the slot (an older pending one is dropped: "latest" is all it is). */
  setContext(seq, bytes) {
    if (this.context && this.context.seq > seq) return false;
    this.context = { seq, bytes };
    return true;
  }

  /** A context at `seq` was acknowledged: the slot is retired if it holds that seq or a lower one. */
  ackContext(seq) { if (this.context && this.context.seq <= seq) this.context = null; }

  /** The durable state (the caller persists it), and back. */
  state() {
    return { max: this.max, contextReserve: this.contextReserve, missed: this.missed,
      turns: this.turns.map((t) => ({ ...t, lines: t.lines.map(b64) })), context: this.context && { seq: this.context.seq, bytes: b64(this.context.bytes) } };
  }
  static from(s) {
    const u = unb64;
    const j = new Journal({ max: s.max, contextReserve: s.contextReserve });
    j.missed = s.missed;
    j.turns = s.turns.map((t) => ({ ...t, lines: t.lines.map(u) }));
    j.open = j.turns.find((t) => !t.done) ?? null;
    j.context = s.context && { seq: s.context.seq, bytes: u(s.context.bytes) };
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
