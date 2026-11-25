// Publishing a turn and the latest context (the design note §3.1, §3.2, §3.3), against an abstract store of one
// agent's files whose every write is checked:
//   store.list(prefix)            -> [path, ...]
//   store.read(path)              -> { bytes, rev } | null
//   store.cas(path, bytes, rev)   -> { ok: true, rev } | { conflict: true }     replace only if still at `rev`
//   store.create(path, bytes)     -> { ok: true, rev } | { exists: true }       never replaces
// (the workspace's E2E sync is that store; a fake in the tests). Every step re-reads after a refusal, so any number of
// writers and lost acknowledgements end in exactly one copy of each line.
//
// The rules:
// - a turn is its start line (the ALLOCATION: the compare-and-set that lands it takes seq = previous marker's + 1), its
//   content lines exactly as journaled, and its end marker. A turn starts only after a marker (or the transcript's
//   start or a clone's pointer), so turns never interleave;
// - a retry finds its turn by id, reading back no further than its anchor's segment. Every found content line must be
//   the journal's, byte for byte (else `mismatch`, never counted as saved); it continues from the next index;
// - a stalled turn (its segment's revision unchanged for STALL_MS on the OBSERVER's monotonic clock) may be closed by
//   an aborted marker, written by compare-and-set against that same revision, so any progress defeats it.

import { STALL_MS } from "./limits.mjs";
import { contextHeader } from "./context.mjs";
import { SEGMENT_RE, endLine, fits, footerLine, frame, linesDigest, parseSegment, segmentPath, startLine } from "./transcript.mjs";

const CONTEXT = "context.jsonl";
const MAX_ROUNDS = 64;

async function segmentNumbers(store) {
  const ns = [];
  for (const p of await store.list("transcript/")) { const m = SEGMENT_RE.exec(p); if (m) ns.push(Number(m[1])); }
  return ns.sort((a, b) => a - b);
}

async function readSegment(store, n) {
  const r = await store.read(segmentPath(n));
  if (!r) return null;
  return { n, rev: r.rev, bytes: r.bytes, ...(await parseSegment(r.bytes)) };
}

/**
 * The transcript's tail: the newest line that isn't a footer, with the newest marker's seq. `newest` is the newest
 * segment as already read: the decision is made on the SAME snapshot the following compare-and-set is checked
 * against (older segments are closed, so immutable).
 */
async function tailOf(store, ns, newest) {
  let tail = null, lastSeq = null;
  for (let k = ns.length - 1; k >= 0 && lastSeq === null; k--) {
    const seg = k === ns.length - 1 && newest ? newest : await readSegment(store, ns[k]);
    for (let j = seg.lines.length - 1; j >= 0; j--) {
      const v = seg.lines[j].value;
      if (!v) continue;
      if (tail === null) tail = v;
      if (v.end === true && Number.isSafeInteger(v.seq)) { lastSeq = v.seq; break; }
      if (v.cloned_from) { lastSeq = 0; break; }
    }
  }
  const open = tail !== null && tail.end !== true && !tail.cloned_from;
  return { tail, open, lastSeq: lastSeq ?? 0 };
}

/** The turn's lines as published, from the newest segment back to `fromN`: { start, contents (i -> bytes), end }. */
async function findTurn(store, ns, turn, fromN, newest) {
  const found = { start: null, contents: new Map(), end: null };
  for (let k = ns.length - 1; k >= 0 && ns[k] >= fromN; k--) {
    const seg = k === ns.length - 1 && newest ? newest : await readSegment(store, ns[k]);
    for (const l of seg.lines) {
      const v = l.value;
      if (!v || v.turn !== turn) continue;
      if (v.start === true) found.start = v;
      else if (v.end === true) found.end = v;
      else if (Number.isSafeInteger(v.i)) found.contents.set(v.i, l.bytes);
    }
    // (the start line is the turn's first: nothing of it lies before)
    if (found.start) break;
  }
  return found;
}

const sameBytes = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
const monthOf = (ms) => { const d = new Date(ms); return d.getUTCFullYear() * 12 + d.getUTCMonth(); };

/**
 * Publish one journaled turn: entry = { turn, at_ms, lines (its content lines, encoded, i = 1..n), anchor: { n, seq }
 * | null, retry_of? }. Returns { state: "done", seq } | { state: "blocked", tail } (another turn is unfinished at the
 * tail: the caller observes it for a stall) | { state: "aborted" } (this turn was aborted: re-send as a new turn) |
 * { state: "mismatch", i } (a published line isn't the journal's: refused, kept for the person).
 */
export async function publishTurn(store, entry) {
  const { turn, lines } = entry;
  for (let round = 0; round < MAX_ROUNDS; round++) {
    const ns = await segmentNumbers(store);
    if (!ns.length) { await store.create(segmentPath(1), new Uint8Array(0)); continue; }
    // (ONE read of the newest segment: every decision below is made on it, and the write is checked against its rev)
    const seg = await readSegment(store, ns.at(-1));
    if (!seg) continue;
    const fromN = entry.anchor?.n ?? 1;
    const f = await findTurn(store, ns, turn, fromN, seg);
    // (every published content line must be the journal's, byte for byte, finished turn or not: TESTS T1)
    for (const [i, b] of f.contents) if (!lines[i - 1] || !sameBytes(b, lines[i - 1])) return { state: "mismatch", i };
    if (f.end) {
      if (f.end.aborted) return { state: "aborted" };
      // (a finished turn is this journal's only if its marker covers exactly these lines)
      if (f.contents.size !== lines.length || f.end.lines !== lines.length || f.end.sha256 !== linesDigest(lines)) return { state: "mismatch", i: lines.length + 1 };
      return { state: "done", seq: f.end.seq };
    }
    let seq, pending;
    if (f.start) {
      seq = f.start.seq;
      const next = f.contents.size ? Math.max(...f.contents.keys()) + 1 : 1;
      pending = lines.slice(next - 1);
      pending.push(await endLine(turn, lines.length + 1, seq, lines));
    } else {
      const t = await tailOf(store, ns, seg);
      if (t.open) return { state: "blocked", tail: t.tail };
      seq = t.lastSeq + 1;
      // (the intent, durable in the caller's journal BEFORE the compare-and-set that allocates)
      if (entry.onIntent) await entry.onIntent({ seq, anchor: { n: seg.n, seq: t.lastSeq } });
      pending = [startLine(turn, seq, entry.at_ms, entry.retry_of ? { retry_of: entry.retry_of } : {}), ...lines];
      pending.push(await endLine(turn, lines.length + 1, seq, lines));
    }
    // (append to the newest segment: close it first when full, or when a new turn starts in a later UTC month)
    const startsHere = !f.start;
    const firstAt = seg.lines.find((l) => l.value && Number.isSafeInteger(l.value.at_ms))?.value.at_ms;
    const monthClose = startsHere && seg.lines.length > 0 && firstAt !== undefined && monthOf(entry.at_ms) > monthOf(firstAt);
    if (seg.closed || monthClose || !fits(seg.bytes.length, pending[0])) {
      if (!seg.closed) {
        const footer = await footerLine(seg.bytes);
        const r = await store.cas(segmentPath(seg.n), concat(seg.bytes, frame([footer])), seg.rev);
        if (r.conflict) continue;
      }
      await store.create(segmentPath(seg.n + 1), new Uint8Array(0));
      continue;
    }
    const batch = [];
    let size = seg.bytes.length;
    for (const l of pending) { if (!fits(size, l)) break; batch.push(l); size += l.length + 1; }
    const r = await store.cas(segmentPath(seg.n), concat(seg.bytes, frame(batch)), seg.rev);
    if (r.conflict) continue;
  }
  throw new Error("publishTurn: too many rounds");
}

function concat(a, b) { const o = new Uint8Array(a.length + b.length); o.set(a, 0); o.set(b, a.length); return o; }

/**
 * What is unfinished at the tail now: { n, rev, turn } of the newest segment when its last turn has no marker, else
 * null. A caller watching for a stall records it with its own monotonic clock.
 */
export async function observeTail(store) {
  const ns = await segmentNumbers(store);
  if (!ns.length) return null;
  const seg = await readSegment(store, ns.at(-1));
  if (!seg) return null;
  const t = await tailOf(store, ns, seg);
  if (!t.open) return null;
  return { n: seg.n, rev: seg.rev, turn: t.tail.turn };
}

/**
 * Abort a stalled turn: `seen` is an observeTail result and `seenAt` the observer's monotonic time when it first saw
 * that revision, `now` its monotonic time now. Only after STALL_MS with the revision unchanged, and only by a
 * compare-and-set against that revision. Returns { state: "wait" | "moved" | "aborted" }.
 */
export async function abortStalled(store, seen, seenAt, now) {
  if (!(now - seenAt >= STALL_MS)) return { state: "wait" };
  const seg = await readSegment(store, seen.n);
  if (!seg || seg.rev !== seen.rev || seg.closed) return { state: "moved" };
  const ns = await segmentNumbers(store);
  if (ns.at(-1) !== seen.n) return { state: "moved" };
  const f = await findTurn(store, ns, seen.turn, 1, seg);
  if (!f.start || f.end) return { state: "moved" };
  const present = [...f.contents.keys()].sort((a, b) => a - b).map((i) => f.contents.get(i));
  const marker = await endLine(seen.turn, present.length + 1, f.start.seq, present, { aborted: true });
  if (!fits(seg.bytes.length, marker)) {
    // (no room beside the footer: close it, then the marker starts the successor)
    const footer = await footerLine(seg.bytes);
    const r = await store.cas(segmentPath(seg.n), concat(seg.bytes, frame([footer])), seg.rev);
    if (r.conflict) return { state: "moved" };
    const c = await store.create(segmentPath(seg.n + 1), frame([marker]));
    return c.exists ? { state: "moved" } : { state: "aborted" };
  }
  const r = await store.cas(segmentPath(seg.n), concat(seg.bytes, frame([marker])), seg.rev);
  return r.conflict ? { state: "moved" } : { state: "aborted" };
}

/**
 * Publish the latest context for turn `seq` (the caller's own turn, after its NORMAL marker was acknowledged). Refused
 * as `stale` when the stored context's seq is at or above (an equal seq with the same bytes is this write's own,
 * acknowledged before: `done`). Returns { state: "done" | "stale" }.
 */
export async function publishContext(store, bytes, seq) {
  for (let round = 0; round < MAX_ROUNDS; round++) {
    const cur = await store.read(CONTEXT);
    if (!cur) {
      const c = await store.create(CONTEXT, bytes);
      if (c.exists) continue;
      return { state: "done" };
    }
    const h = contextHeader(cur.bytes);
    if (h && h.seq >= seq) return h.seq === seq && sameBytes(cur.bytes, bytes) ? { state: "done" } : { state: "stale" };
    const r = await store.cas(CONTEXT, bytes, cur.rev);
    if (r.conflict) continue;
    return { state: "done" };
  }
  throw new Error("publishContext: too many rounds");
}

/** The anchor a journal entry records before its first publication: the newest segment and marker seq now. */
export async function anchorNow(store) {
  const ns = await segmentNumbers(store);
  if (!ns.length) return { n: 1, seq: 0 };
  const seg = await readSegment(store, ns.at(-1));
  const t = await tailOf(store, ns, seg);
  return { n: ns.at(-1), seq: t.lastSeq };
}
