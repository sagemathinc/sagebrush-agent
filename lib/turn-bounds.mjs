// A task's chat turn events made to fit the page's bounds before they are recorded (the one table: the page's
// web/workspace/tasks-schema.ts TURN, protocol §6.1), so an event the host records is never one the page refuses.
// Nothing is lost where it can be kept: long text is split into several deltas; free text is cut, ending in "…"; a
// code is cut; an id that isn't the page's kind of id is replaced by a stable one (the same original, the same id);
// an artifact of a kind the page doesn't show is not recorded, and the agent's log says so.

import { createHash } from "node:crypto";

export const PAGE_BOUNDS = Object.freeze({ short: 400, id: 128, text: 192 * 1024, code: 64, lang: 64, kinds: Object.freeze(["markdown", "code", "diff", "notebook", "board"]) });
// (where the host's own record check (tasks.mjs EVENT_SHAPES) is stricter than the page, its bound: both must pass)
const HOST = Object.freeze({ tool: 40, name: 200, lang: 40, errorMessage: 4096 });
const PAGE_ID = /^[\x21-\x7e]{1,128}$/;

/** An id as the page takes one (1 to 128 printable ASCII): kept if it is one, else "h" and 32 hex of its sha256. */
export const pageId = (s) => (typeof s === "string" && PAGE_ID.test(s) ? s : `h${createHash("sha256").update(String(s)).digest("hex").slice(0, 32)}`);

// (the longest start of `s` of at most `max` UTF-8 bytes, whole characters only)
function prefix(s, max) {
  if (Buffer.byteLength(s) <= max) return s;
  let n = 0, out = "";
  for (const ch of s) {
    const b = Buffer.byteLength(ch);
    if (n + b > max) break;
    n += b;
    out += ch;
  }
  return out;
}
/** `s` in at most `max` UTF-8 bytes: as it is, or cut and ending in "…". */
export const cut = (s, max) => (Buffer.byteLength(s) <= max ? s : `${prefix(s, max - 3)}…`);
/** `s` split into pieces of at most `max` UTF-8 bytes, at character boundaries; joined, they are `s`. */
export function split(s, max) {
  const out = [];
  let rest = s;
  while (Buffer.byteLength(rest) > max) {
    const p = prefix(rest, max);
    out.push(p);
    rest = rest.slice(p.length);
  }
  out.push(rest);
  return out;
}

/** One draft event, conformed: the events to record in its place (none, one, or a split delta's pieces). */
export function conformTurnEvent(e, log = () => {}) {
  const B = PAGE_BOUNDS;
  const x = { ...e };
  if (typeof x.turn_id === "string") x.turn_id = pageId(x.turn_id);
  switch (x.type) {
    case "message_revised":
      return [{ ...x, message: pageId(x.message) }];
    case "text_delta":
      return split(x.text, B.text).map((text) => ({ ...x, message: pageId(x.message), text }));
    case "thinking_delta":
      return split(x.text, B.text).map((text) => ({ ...x, text }));
    case "tool_call_started": {
      const o = { ...x, call: pageId(x.call), tool: prefix(x.tool, Math.min(B.short, HOST.tool)) };
      if (typeof o.name === "string") o.name = cut(o.name, Math.min(B.short, HOST.name));
      if (typeof o.summary === "string") o.summary = cut(o.summary, B.short);
      return [o];
    }
    case "tool_call_finished":
      return [{ ...x, call: pageId(x.call) }];
    case "turn_error":
      return [{ ...x, code: prefix(x.code, B.code), message: cut(x.message, HOST.errorMessage) }];
    case "turn_finished":
      return [typeof x.code === "string" ? { ...x, code: prefix(x.code, B.code) } : x];
    case "artifact": {
      if (!B.kinds.includes(x.kind)) {
        log(`an artifact of kind ${JSON.stringify(String(x.kind).slice(0, 40))} isn't one the page shows: not recorded`);
        return [];
      }
      const o = { ...x, id: pageId(x.id), title: cut(x.title, B.short) };
      if (typeof o.lang === "string") o.lang = prefix(o.lang, Math.min(B.lang, HOST.lang));
      return [o];
    }
    default:
      return [x];
  }
}
