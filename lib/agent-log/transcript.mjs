// The transcript, `sb.agent-transcript.v1` (the design note §3): segments `transcript/<n>.jsonl` of canonical JSON
// lines, each ending in "\n", each at most LINE_MAX bytes. A turn is its start line (i = 0, carrying `seq`), its
// content lines (i = 1, 2, ...), and its end marker (normal or aborted). A segment is at most SEGMENT_MAX bytes, its
// footer included: a line goes in only if it plus FOOTER_MAX still fit, otherwise the segment is closed first. A closed
// segment's footer covers every byte before it, and a file with a footer is never written again.

import { lineText } from "./context.mjs";
import { ADAPTERS } from "./adapters.mjs";
import { FOOTER_MAX, LINE_MAX, SEGMENT_MAX, SUMMARY_CHARS } from "./limits.mjs";
import { Sha256 } from "./sha256.mjs";

const te = new TextEncoder(), td = new TextDecoder();
const NL = 10;

export const segmentPath = (n) => `transcript/${n}.jsonl`;
export const SEGMENT_RE = /^transcript\/([1-9][0-9]{0,15})\.jsonl$/;

/** The encoded bytes of one line's value, newline excluded; refuses one over LINE_MAX (its newline counted). */
export function encodeLine(value) {
  const b = te.encode(lineText(value));
  if (b.length + 1 > LINE_MAX) throw new Error("a line over LINE_MAX");
  return b;
}

async function sha256hex(bytes) {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return Array.from(d, (x) => x.toString(16).padStart(2, "0")).join("");
}

/** The bytes of lines, each with its newline. */
export function frame(lines) {
  const n = lines.reduce((a, l) => a + l.length + 1, 0);
  const out = new Uint8Array(n);
  let o = 0;
  for (const l of lines) { out.set(l, o); o += l.length; out[o++] = NL; }
  return out;
}

/** One line per word, split into `part` lines at UTF-8 boundaries when the line would pass LINE_MAX (one at a time). */
function* wordLines(turn, at_ms, role, text, next) {
  const whole = { turn, i: 0, at_ms, role, text };
  if (te.encode(lineText({ ...whole, i: Number.MAX_SAFE_INTEGER })).length + 1 <= LINE_MAX) {
    yield { ...whole, i: next() };
    return;
  }
  // (each part as long as fits; the worst-case i and part keep the bound for every index)
  const probe = (s) => te.encode(lineText({ turn, i: Number.MAX_SAFE_INTEGER, at_ms, role, part: Number.MAX_SAFE_INTEGER, text: s })).length + 1 <= LINE_MAX;
  let rest = text, part = 1;
  while (rest.length) {
    let lo = 1, hi = rest.length;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (probe(cutAt(rest, mid))) lo = mid; else hi = mid - 1;
    }
    const head = cutAt(rest, lo);
    yield { turn, i: next(), at_ms, role, part: part++, text: head };
    rest = rest.slice(head.length);
  }
}
// (a prefix of at most k UTF-16 units, never ending inside a surrogate pair, never empty)
function cutAt(s, k) {
  let n = Math.min(k, s.length);
  if (n < s.length && n > 1 && s.charCodeAt(n - 1) >= 0xd800 && s.charCodeAt(n - 1) <= 0xdbff) n--;
  return s.slice(0, Math.max(n, 1));
}

/** A tool call's one-line summary: its input as given (newlines as spaces), and the outcome in a word. */
export function toolSummary(input, outcome) {
  const flat = String(input ?? "").replace(/\s+/g, " ").trim();
  const tail = ` → ${outcome}`;
  const room = Math.max(0, SUMMARY_CHARS - tail.length);
  const head = flat.length > room ? flat.slice(0, Math.max(0, room - 1)) + "…" : flat;
  return head + tail;
}

/** The open tool calls a turn may hold waiting for their results; past it, the oldest is written as `no result`. */
export const OPEN_CALLS_MAX = 256;

/**
 * The CONTENT lines of one turn, one at a time, as normalized messages arrive (i from `first`, 1 unless the journal put
 * a gap line first): words as they are (in parts if long), and each tool call as ONE line with its outcome (`ok` or
 * `error`), written when its result arrives, or as `no result` when the turn ends without one (or when more than
 * OPEN_CALLS_MAX calls are waiting). A tool's output is never written: it stays on the machine that ran it. Nothing is
 * materialized beyond the waiting calls' one-line summaries, so a caller adds each line to its journal as it comes (LIMITS H3).
 */
class TurnLineBuilder {
  constructor(turn, at_ms, first) {
    this.turn = turn; this.at_ms = at_ms; this.i = first - 1;
    this.open = new Map(); // call id -> { name, input }: only the waiting calls' summaries are held
  }
  next() { return ++this.i; }
  toolLine(c, outcome) {
    return encodeLine({ turn: this.turn, i: this.next(), at_ms: this.at_ms, role: "tool", name: String(c.name ?? "").slice(0, 64), summary: toolSummary(c.input, outcome) });
  }
  /** The lines one message adds, one at a time. */
  *lines(m) {
    if (m.role === "user" || m.role === "assistant") {
      for (const l of wordLines(this.turn, this.at_ms, m.role, String(m.text ?? ""), () => this.next())) yield encodeLine(l);
    } else if (m.role === "tool_call") {
      this.open.set(m.call, { name: m.name, input: String(m.input ?? "").slice(0, SUMMARY_CHARS + 1) });
      if (this.open.size > OPEN_CALLS_MAX) {
        const [k, c] = this.open.entries().next().value;
        this.open.delete(k);
        yield this.toolLine(c, "no result");
      }
    } else if (m.role === "tool_result" && this.open.has(m.call)) {
      const c = this.open.get(m.call);
      this.open.delete(m.call);
      yield this.toolLine(c, m.error ? "error" : "ok");
    }
  }
  /** The calls still waiting when the turn ends. */
  *finish() { for (const c of this.open.values()) yield this.toolLine(c, "no result"); this.open.clear(); }
}

export function* turnLineStream(turn, at_ms, messages, first = 1) {
  const b = new TurnLineBuilder(turn, at_ms, first);
  for (const m of messages) yield* b.lines(m);
  yield* b.finish();
}

/** The same lines from a session's record stream (lines.mjs + an adapter), for one turn's records: never held whole. */
export async function* turnLinesFromRecords(turn, at_ms, provider, lineStream, first = 1) {
  const adapt = ADAPTERS[provider];
  if (!adapt) throw new RangeError(`unknown provider ${provider}`);
  const dec = new TextDecoder("utf-8", { fatal: false });
  const b = new TurnLineBuilder(turn, at_ms, first);
  for await (const item of lineStream) {
    if (item.skipped !== undefined) continue;
    let rec;
    try { rec = JSON.parse(dec.decode(item.line)); } catch { continue; }
    for (const m of adapt(rec).messages) yield* b.lines(m);
  }
  yield* b.finish();
}

/** The content lines of a turn as an array (small turns, and tests): exactly what turnLineStream yields. */
export const turnLines = (turn, at_ms, messages, first = 1) => [...turnLineStream(turn, at_ms, messages, first)];

export const startLine = (turn, seq, at_ms, extra = {}) => encodeLine({ turn, i: 0, start: true, seq, at_ms, ...extra });

/** The SHA-256 of content lines with their newlines, hashed line by line (never framed whole). */
export function linesDigest(contentLines) {
  const h = new Sha256(), nl = new Uint8Array([NL]);
  for (const l of contentLines) { h.update(l); h.update(nl); }
  return h.hex();
}

/** The end marker over the content lines (their bytes, newlines included), normal or aborted. */
export async function endLine(turn, i, seq, contentLines, { aborted = false } = {}) {
  const v = { turn, i, end: true, seq, lines: contentLines.length, sha256: linesDigest(contentLines) };
  if (aborted) v.aborted = true;
  return encodeLine(v);
}

export const gapLine = (turn, i, fields) => encodeLine({ turn, i, gap: true, ...fields });
export const pointerLine = (agent, seq) => encodeLine({ cloned_from: { agent, seq } });

/** The footer over a segment's bytes so far. */
export async function footerLine(segment) {
  const lines = countLines(segment);
  const b = encodeLine({ closed: true, lines, bytes: segment.length, sha256: await sha256hex(segment) });
  if (b.length + 1 > FOOTER_MAX) throw new Error("a footer over FOOTER_MAX");
  return b;
}

const countLines = (bytes) => { let n = 0; for (const b of bytes) if (b === NL) n++; return n; };

/** Whether `line` may go into a segment of `size` bytes, keeping the footer's room. */
export const fits = (size, line) => size + line.length + 1 + FOOTER_MAX <= SEGMENT_MAX;

/**
 * A segment's lines, parsed: { lines: [{ value, bytes }], closed, footerOk }. `closed` is true when the last line is a
 * footer; `footerOk` when its count, length and hash match the bytes before it (checked, never trusted).
 */
export async function parseSegment(bytes) {
  const lines = [];
  let start = 0;
  for (let k = 0; k < bytes.length; k++) {
    if (bytes[k] !== NL) continue;
    const b = bytes.subarray(start, k);
    let value = null;
    try { value = JSON.parse(td.decode(b)); } catch { /* (a malformed line: kept as bytes, value null) */ }
    lines.push({ value, bytes: b, offset: start });
    start = k + 1;
  }
  const last = lines.at(-1);
  if (!last || !last.value || last.value.closed !== true) return { lines, closed: false, footerOk: false };
  const before = bytes.subarray(0, last.offset);
  const ok = last.value.bytes === before.length && last.value.lines === lines.length - 1 && last.value.sha256 === (await sha256hex(before));
  return { lines: lines.slice(0, -1), closed: true, footerOk: ok, footer: last.value };
}

export { sha256hex };
