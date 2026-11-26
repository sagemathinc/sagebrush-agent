// Cloning an agent (the transcript-and-context design note r0.8 §5): a NEW agent that knows what the source knows,
// with a new conversation of its own. The clone gets
//   - a bootstrap context: the source's latest context with ONLY its line 1 rewritten, in the clone's own sequence
//     (`seq: 0`, with `bootstrap.cloned_from` = { agent, context_seq, marker_seq }), so the clone's first context
//     (`seq` 1) replaces it by the ordinary rule;
//   - a new transcript: segment 1 holds one pointer line to the source's newest normal marker, and then the clone's own
//     turns from `seq` 1. Nothing of the source's transcript is copied;
//   - `agent.json` with `cloned_from: { agent, seq }`.
// The source's files are only read. Who may clone (the person, from a current device, after the disclosure; never a
// host) is decided outside this module, by the caller and the service.
//
// Pure, against the same abstract store as the writer (list, read, create): the source's store is only read, the
// clone's is only created into. Every file is written create-only; a write that finds the file holding the SAME bytes
// is its own earlier write whose acknowledgement was lost, and is done. So a caller resuming a clone must reuse the
// bytes it made (planClone's result), never make them again.

import { contextHeader, lineText } from "./context.mjs";
import { CONTEXT_MAX, HEADER_MAX } from "./limits.mjs";
import { SEGMENT_RE, frame, parseSegment, pointerLine, segmentPath } from "./transcript.mjs";

const te = new TextEncoder();
const CONTEXT = "context.jsonl", AGENT = "agent.json";
// (ids as the files' paths use them; the service checks them again, and `memory` and `hosts` are its own trees)
const ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const RESERVED = new Set(["memory", "hosts"]);

function checkId(name, v) {
  if (typeof v !== "string" || !ID_RE.test(v) || RESERVED.has(v)) throw new RangeError(`${name}: an agent id`);
}

/**
 * The bootstrap context: `source` (the source's context bytes) with line 1 rewritten for the clone. Refuses, never
 * cuts: a source that isn't a context, one whose header names another agent, a marker behind its context, and a
 * rewritten header over HEADER_MAX or a file over CONTEXT_MAX (both re-checked on the final bytes).
 */
export function bootstrapContext(source, { clone, from, marker_seq, at_ms }) {
  checkId("clone", clone);
  checkId("from", from);
  if (clone === from) throw new RangeError("a clone needs its own id");
  if (!Number.isSafeInteger(at_ms) || at_ms < 0) throw new RangeError("at_ms: a time");
  const h = contextHeader(source);
  if (!h) throw new RangeError("the source isn't a context");
  if (h.agent !== from) throw new RangeError("the source context is another agent's");
  if (!Number.isSafeInteger(h.seq) || h.seq < 0) throw new RangeError("the source context's seq");
  if (!Number.isSafeInteger(marker_seq) || marker_seq < h.seq) throw new RangeError("marker_seq: at or after the context's seq");
  const { bootstrap: _old, ...rest } = h; // (a clone of a clone points at its direct source only)
  const head = te.encode(lineText({ ...rest, agent: clone, at_ms, seq: 0, bootstrap: { cloned_from: { agent: from, context_seq: h.seq, marker_seq } } }));
  if (head.length > HEADER_MAX) throw new RangeError("the clone's header over HEADER_MAX");
  const body = source.subarray(source.indexOf(10)); // (from line 1's newline on, byte for byte)
  const out = new Uint8Array(head.length + body.length);
  out.set(head, 0);
  out.set(body, head.length);
  if (out.length > CONTEXT_MAX) throw new RangeError("the clone's context over CONTEXT_MAX");
  return out;
}

/**
 * The seq of the source's newest NORMAL end marker (an aborted one isn't a turn the context covers), reading back
 * from the newest segment; 0 when there is none (or only a pointer of its own).
 */
export async function newestNormalMarker(store) {
  const ns = [];
  for (const p of await store.list("transcript/")) { const m = SEGMENT_RE.exec(p); if (m) ns.push(Number(m[1])); }
  ns.sort((a, b) => b - a);
  for (const n of ns) {
    const r = await store.read(segmentPath(n));
    if (!r) continue;
    const { lines } = await parseSegment(r.bytes);
    for (let j = lines.length - 1; j >= 0; j--) {
      const v = lines[j].value;
      if (v && v.end === true && v.aborted !== true && Number.isSafeInteger(v.seq)) return v.seq;
    }
  }
  return 0;
}

/**
 * Plan a clone from the source's store: its context is read FIRST, then its newest normal marker (markers only move
 * forward, so the marker read is never behind the context read; a source context may lag its marker, and both
 * numbers are kept). Returns the clone's files as bytes: { context, segment, agent }.
 */
export async function planClone(source, { clone, from, name, provider, at_ms }) {
  const ctx = await source.read(CONTEXT);
  if (!ctx) throw new RangeError("the source has no context to clone");
  const marker_seq = await newestNormalMarker(source);
  const context = bootstrapContext(ctx.bytes, { clone, from, marker_seq, at_ms });
  if (typeof name !== "string" || typeof provider !== "string") throw new RangeError("name and provider: strings");
  const agent = te.encode(lineText({ v: 1, agent: clone, name, provider, created: at_ms, cloned_from: { agent: from, seq: marker_seq } }) + "\n");
  return { context, segment: frame([pointerLine(from, marker_seq)]), agent, marker_seq };
}

const same = (a, b) => a.length === b.length && a.every((x, k) => x === b[k]);

async function createOnce(store, path, bytes) {
  const c = await store.create(path, bytes);
  if (!c.exists) return true;
  const r = await store.read(path);
  return !!r && same(r.bytes, bytes);
}

/**
 * Write a planned clone into the clone's (empty) store, each file create-only: the context, then transcript segment
 * 1, then agent.json last (so a clone with an agent.json has the other two). Returns { state: "done" } (a re-run after
 * a lost acknowledgement included), or { state: "exists", path } when a file is there with other bytes: that id isn't
 * a fresh clone of this plan, and nothing more is written.
 */
export async function publishClone(store, plan) {
  for (const [path, bytes] of [[CONTEXT, plan.context], [segmentPath(1), plan.segment], [AGENT, plan.agent]]) {
    if (!(await createOnce(store, path, bytes))) return { state: "exists", path };
  }
  return { state: "done" };
}
