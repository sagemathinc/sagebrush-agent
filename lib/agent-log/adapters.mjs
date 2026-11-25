// Provider adapters (the design note §2): an agent tool's session records, normalized to one message form, with the
// context window kept as the LAST compaction summary plus every message after it.
//
// The normalized message is one of:
//   { role: "summary", text }                                  a compaction's summary (the window starts here)
//   { role: "user" | "assistant", text }                       words
//   { role: "tool_call", name, call, input }                   a tool call: its name, its call id, its input as text
//   { role: "tool_result", call, output, error }               its result, whole (Q1: kept whole), error a boolean
// Provider fields not needed to resume (ids, usage, signatures, thinking, metadata) are dropped.
//
// Everything here reads AGENT-WRITABLE input: a record can claim to be anything, so the result is the agent's
// self-reported account (§3, SEC H1), never authority. Unknown or malformed records are ignored, never fatal.
//
// Claude Code: each line is a record. Words and tool calls are `assistant` records whose message.content holds `text`
// and `tool_use` blocks; the user's words are `user` records with string content or `text` blocks; tool results are
// `user` records with `tool_result` blocks. A compaction is a `system` record with subtype `compact_boundary`, followed
// by a `user` record with `isCompactSummary: true` whose content is the summary.
//
// Codex: each line is { type, payload }. Words are `response_item` payloads of type `message` (role user or assistant,
// content `input_text` / `output_text` blocks); tool calls are `function_call` / `custom_tool_call`, and results
// `function_call_output` / `custom_tool_call_output`. A compaction is a `compacted` record whose payload.message is the
// summary.

const str = (v) => (typeof v === "string" ? v : null);

/** The text of a content field: a string, or the concatenation of its text blocks (`text`, `input_text`, ...). */
function textOf(content, kinds) {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return null;
  const out = [];
  for (const b of content) {
    if (b && typeof b === "object" && kinds.includes(b.type) && typeof b.text === "string") out.push(b.text);
    else if (typeof b === "string") out.push(b);
  }
  return out.length ? out.join("\n") : null;
}

const inputText = (v) => (typeof v === "string" ? v : v === undefined ? "" : safeJson(v));
function safeJson(v) { try { return JSON.stringify(v) ?? ""; } catch { return ""; } }

/** One Claude Code record: { reset?: true, messages: [...] }. */
export function claudeRecord(r) {
  if (!r || typeof r !== "object") return { messages: [] };
  if (r.type === "system" && r.subtype === "compact_boundary") return { reset: true, messages: [] };
  const m = r.message && typeof r.message === "object" ? r.message : null;
  if (r.type === "user" && m) {
    if (r.isCompactSummary === true) {
      const t = textOf(m.content, ["text"]);
      return t === null ? { messages: [] } : { reset: true, messages: [{ role: "summary", text: t }] };
    }
    if (typeof m.content === "string") return { messages: [{ role: "user", text: m.content }] };
    const out = [];
    if (Array.isArray(m.content)) {
      for (const b of m.content) {
        if (!b || typeof b !== "object") continue;
        if (b.type === "tool_result") {
          const out1 = typeof b.content === "string" ? b.content : textOf(b.content, ["text"]) ?? "";
          out.push({ role: "tool_result", call: str(b.tool_use_id) ?? "", output: out1, error: b.is_error === true });
        } else if (b.type === "text" && typeof b.text === "string") out.push({ role: "user", text: b.text });
      }
    }
    return { messages: out };
  }
  if (r.type === "assistant" && m && Array.isArray(m.content)) {
    const out = [];
    for (const b of m.content) {
      if (!b || typeof b !== "object") continue;
      if (b.type === "text" && typeof b.text === "string") out.push({ role: "assistant", text: b.text });
      else if (b.type === "tool_use") out.push({ role: "tool_call", name: str(b.name) ?? "", call: str(b.id) ?? "", input: inputText(b.input) });
    }
    return { messages: out };
  }
  return { messages: [] };
}

/** One Codex record: { reset?: true, messages: [...] }. */
export function codexRecord(r) {
  if (!r || typeof r !== "object") return { messages: [] };
  const p = r.payload && typeof r.payload === "object" ? r.payload : null;
  if (r.type === "compacted") {
    const t = p ? str(p.message) : null;
    return { reset: true, messages: t === null ? [] : [{ role: "summary", text: t }] };
  }
  if (r.type !== "response_item" || !p) return { messages: [] };
  switch (p.type) {
    case "message": {
      if (p.role !== "user" && p.role !== "assistant") return { messages: [] };
      const t = textOf(p.content, ["input_text", "output_text", "text"]);
      return { messages: t === null ? [] : [{ role: p.role, text: t }] };
    }
    case "function_call": return { messages: [{ role: "tool_call", name: str(p.name) ?? "", call: str(p.call_id) ?? "", input: inputText(p.arguments) }] };
    case "custom_tool_call": return { messages: [{ role: "tool_call", name: str(p.name) ?? "", call: str(p.call_id) ?? "", input: inputText(p.input) }] };
    case "function_call_output":
    case "custom_tool_call_output": {
      const o = typeof p.output === "string" ? p.output : textOf(p.output, ["input_text", "output_text", "text"]) ?? inputText(p.output);
      return { messages: [{ role: "tool_result", call: str(p.call_id) ?? "", output: o, error: false }] };
    }
    default: return { messages: [] };
  }
}

export const ADAPTERS = Object.freeze({ "claude-code": claudeRecord, codex: codexRecord });

/**
 * The context window of a session, read from a bounded line stream (lines.mjs): the last compaction's summary and every
 * message after it. Memory stays bounded by `budget` bytes of message text: once the kept messages pass it, the oldest
 * are dropped as the stream goes (counted in `dropped`), whole, and a tool result goes with its call. `skipped` counts
 * raw lines the reader discarded since the last compaction marker, and `summarySkipped` whether a skipped line could
 * have been the summary (a skip right after a compaction marker).
 */
export async function contextWindow(lineStream, provider, { budget } = {}) {
  const adapt = ADAPTERS[provider];
  if (!adapt) throw new RangeError(`unknown provider ${provider}`);
  const dec = new TextDecoder("utf-8", { fatal: false });
  let summary = null, messages = [], size = 0, dropped = 0, skipped = 0, summarySkipped = false, afterBoundary = false;
  const cost = (m) => (m.text?.length ?? 0) + (m.input?.length ?? 0) + (m.output?.length ?? 0) + (m.name?.length ?? 0) + 32;
  for await (const item of lineStream) {
    if (item.skipped !== undefined) {
      skipped++;
      if (afterBoundary) summarySkipped = true;
      continue;
    }
    let rec;
    try { rec = JSON.parse(dec.decode(item.line)); } catch { continue; }
    const { reset, messages: ms } = adapt(rec);
    if (reset) {
      // (a compaction: the window starts again here; a boundary marker with no summary yet waits for its summary)
      messages = []; size = 0; dropped = 0; skipped = 0; summarySkipped = false;
      const s = ms.find((m) => m.role === "summary");
      if (s) { summary = s.text; afterBoundary = false; } else { summary = null; afterBoundary = true; }
      continue;
    }
    afterBoundary = false;
    for (const m of ms) { messages.push(m); size += cost(m); }
    if (budget !== undefined) {
      while (size > budget && messages.length) {
        const first = messages.shift();
        size -= cost(first);
        dropped++;
        // (a call and its result leave together)
        if (first.role === "tool_call" && messages[0]?.role === "tool_result" && messages[0].call === first.call) { size -= cost(messages.shift()); dropped++; }
      }
    }
  }
  return { summary, messages, dropped, skipped, summarySkipped };
}
