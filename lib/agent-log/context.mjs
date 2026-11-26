// The latest context file, `sb.agent-context.v1` (the design note §2): a header line, then the summary and every
// message after it, one canonical JSON object per line. At most CONTEXT_MAX bytes of the FINAL file, header, escaping
// and newlines included. Truncation, in order, until it fits:
//   1. whole messages, oldest first (a tool_call and its tool_result together, never one without the other);
//   2. if one message alone is still over, its text cut to fit at a UTF-8 boundary, head and tail kept;
//   3. if the header and the summary alone are over, the summary cut the same way.
// Tool results are kept whole otherwise (Q1). The header records what was cut, and `incomplete` when the reader
// skipped raw lines after the last compaction (a resume from it warns).

import { canon } from "../fleet/core/canon.mjs";
import { CONTEXT_MAX, HEADER_MAX, MODEL_MAX } from "./limits.mjs";

const te = new TextEncoder();
const bytesOf = (s) => te.encode(s).length;
const BIG = 64 * 1024 * 1024;

/** The canonical text of one line's value (refusing nothing canon refuses: plain data only). */
export function lineText(value) {
  const r = canon(value, BIG);
  if (!r.ok) throw new Error(`a line canon refuses: ${r.reason}`);
  return r.text;
}

/** `s` cut to at most `n` UTF-8 bytes, never inside a character. */
export function utf8Head(s, n) {
  if (bytesOf(s) <= n) return s;
  let lo = 0, hi = s.length;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (bytesOf(safeSlice(s, 0, mid)) <= n) lo = mid; else hi = mid - 1;
  }
  return safeSlice(s, 0, lo);
}
// (never split a surrogate pair)
function safeSlice(s, a, b) {
  if (b > a && b < s.length && s.charCodeAt(b - 1) >= 0xd800 && s.charCodeAt(b - 1) <= 0xdbff) b--;
  if (a > 0 && a < b && s.charCodeAt(a) >= 0xdc00 && s.charCodeAt(a) <= 0xdfff) a++;
  return s.slice(a, b);
}

/**
 * The longest head-and-tail cut of `text` whose line, `make(cutText)`, encodes to at most `room` bytes. The cut keeps
 * half the kept characters from each end, joined by a marker naming how many characters were cut. null if even the
 * marker alone doesn't fit.
 */
export function cutToFit(text, room, make) {
  const fits = (k) => bytesOf(lineText(make(cutText(text, k)))) <= room;
  if (fits(text.length)) return text;
  if (!fits(0)) return null;
  let lo = 0, hi = text.length;
  while (lo < hi) {
    const mid = Math.floor((lo + hi + 1) / 2);
    if (fits(mid)) lo = mid; else hi = mid - 1;
  }
  return cutText(text, lo);
}
function cutText(text, keep) {
  if (keep >= text.length) return text;
  const h = Math.ceil(keep / 2), t = keep - h;
  return safeSlice(text, 0, h) + `\n[… ${text.length - keep} characters cut …]\n` + safeSlice(text, text.length - t, text.length);
}

const fieldOf = (m) => (m.role === "tool_call" ? "input" : m.role === "tool_result" ? "output" : "text");

/**
 * The context file's bytes. `header` holds { agent, provider, model, at_ms, seq, marker } (and later fields, such as a
 * clone's `bootstrap`, carried as they are); `window` is adapters.contextWindow's result. Returns { bytes, truncated }.
 */
export function buildContext(header, window, { max = CONTEXT_MAX } = {}) {
  const truncated = { messages: window.dropped ?? 0, cut_message: false, cut_summary: false };
  const msgs = window.messages.map((m) => ({ ...m }));
  let summary = window.summary;
  const incomplete = window.skipped || window.summarySkipped ? { skipped: window.skipped ?? 0, summary_skipped: !!window.summarySkipped } : null;
  const head = (t) => {
    const h = { v: 1, type: "sb.agent-context.v1", ...header, model: utf8Head(String(header.model ?? ""), MODEL_MAX), truncated: t };
    if (incomplete) h.incomplete = incomplete;
    const s = lineText(h);
    if (bytesOf(s) > HEADER_MAX) throw new Error("the context's header over HEADER_MAX");
    return s;
  };
  // (the lines' budget holds back the header's whole reserve and its newline, so the final file never passes `max`)
  const room = max - HEADER_MAX - 1;
  const lineOf = (m) => lineText(m);
  const summaryLine = () => (summary === null ? null : lineText({ role: "summary", text: summary }));
  let lens = msgs.map((m) => bytesOf(lineOf(m)) + 1);
  let total = lens.reduce((a, b) => a + b, 0) + (summary === null ? 0 : bytesOf(summaryLine()) + 1);
  // 1. whole messages, oldest first; a tool_call takes every tool_result with its call id with it, wherever it is
  // (TESTS T2), and a result whose call is no longer here goes too: never a result without its call
  const dropAt = (k) => { total -= lens[k]; msgs.splice(k, 1); lens.splice(k, 1); truncated.messages++; };
  const orphan = (k) => msgs[k].role === "tool_result" && !msgs.some((m) => m.role === "tool_call" && m.call === msgs[k].call);
  for (let k = msgs.length - 1; k >= 0; k--) if (orphan(k)) dropAt(k);
  while (total > room && msgs.length > 1) {
    const first = msgs[0];
    const partners = first.role === "tool_call" ? msgs.filter((m, k) => k > 0 && m.role === "tool_result" && m.call === first.call).length : 0;
    if (partners && partners === msgs.length - 1) break;
    dropAt(0);
    if (first.role === "tool_call") for (let k = msgs.length - 1; k >= 0; k--) if (msgs[k].role === "tool_result" && msgs[k].call === first.call) dropAt(k);
  }
  // 2. the one message left (or the one pair), cut
  if (total > room && msgs.length) {
    const sumBytes = summary === null ? 0 : bytesOf(summaryLine()) + 1;
    const last = msgs.length - 1, others = lens.slice(0, last).reduce((a, b) => a + b, 0);
    const left = room - sumBytes - others - 1;
    const f = fieldOf(msgs[last]);
    const cut = left > 0 ? cutToFit(String(msgs[last][f] ?? ""), left, (t) => ({ ...msgs[last], [f]: t })) : null;
    if (cut !== null) {
      msgs[last][f] = cut;
      truncated.cut_message = true;
    } else {
      // (not even a cut message fits beside the summary: the messages go, and step 3 cuts the summary)
      truncated.messages += msgs.length;
      msgs.length = 0;
    }
    lens = msgs.map((m) => bytesOf(lineOf(m)) + 1);
    total = lens.reduce((a, b) => a + b, 0) + sumBytes;
  }
  // 3. the summary, cut
  if (total > room && summary !== null) {
    const others = lens.reduce((a, b) => a + b, 0);
    const cut = cutToFit(summary, room - others - 1, (t) => ({ role: "summary", text: t }));
    summary = cut ?? "";
    truncated.cut_summary = true;
  }
  const lines = [head(truncated)];
  if (summary !== null) lines.push(summaryLine());
  for (const m of msgs) lines.push(lineOf(m));
  const bytes = te.encode(lines.join("\n") + "\n");
  if (bytes.length > max) throw new Error("the context over its cap");
  return { bytes, truncated };
}

/** A context file's header, parsed (null if the first line isn't one). */
export function contextHeader(bytes) {
  const nl = bytes.indexOf(10);
  if (nl < 0) return null;
  try {
    const h = JSON.parse(new TextDecoder().decode(bytes.subarray(0, nl)));
    return h && h.type === "sb.agent-context.v1" && Number.isSafeInteger(h.seq) ? h : null;
  } catch { return null; }
}
