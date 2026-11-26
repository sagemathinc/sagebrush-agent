// Search over an agent's transcript, on the device only (the transcript-and-context design note §4): an index of the
// segments this device has decrypted, kept as a local cache (never synced; losing it costs only a rebuild).
//
// The index is the caller's (a SQLite FTS5 table on a host or in a page), behind an abstract transactional interface:
//   idx.transaction(fn)        runs fn(tx) atomically: every change commits, or (fn throws) none does
//   tx.checkpoint(path)        -> { revision, bytes, prefix, closed } | null
//   tx.setCheckpoint(path, cp) cp | null (null: forget the path)
//   tx.dropPath(path)          removes every indexed line of the path
//   tx.addLine(path, offset, { turn, role, text })
//
// Per path, the checkpoint is what was indexed: the sync revision, the byte length of the complete lines indexed, and
// the SHA-256 of exactly those bytes. A new revision whose first `bytes` bytes hash to `prefix` is a strict append, so
// only its new lines are indexed; anything else (shorter, an earlier byte changed) drops the path and indexes it whole.
// Only the bytes decide: a revision number is recorded, never trusted to order or to skip anything. A segment counts
// as closed only once its footer has been checked against the bytes before it. A path's rows and its checkpoint change in ONE transaction, so a crash leaves both old or both new, and
// the index always equals one rebuilt from the same bytes.

import { Sha256 } from "./sha256.mjs";
import { parseSegment } from "./transcript.mjs";

const NL = 10;
const td = new TextDecoder();
const shaOf = (bytes) => new Sha256().update(bytes).hex();

/** The searchable fields of one transcript line, or null for markers, footers, gaps and pointers. */
export function searchable(v) {
  if (!v || typeof v !== "object" || typeof v.turn !== "string") return null;
  if (v.role === "user" || v.role === "assistant") return typeof v.text === "string" ? { turn: v.turn, role: v.role, text: v.text } : null;
  if (v.role === "tool") return { turn: v.turn, role: "tool", text: `${v.name ?? ""} ${v.summary ?? ""}`.trim() };
  return null;
}

/**
 * Bring the index up to one revision of a segment (`bytes`, the whole decrypted segment). Returns { indexed (lines
 * added), rebuilt (whether the path was dropped first), closed, footerBad }.
 */
export async function indexSegment(idx, path, revision, bytes) {
  const end = bytes.lastIndexOf(NL) + 1; // (complete lines only)
  const seg = await parseSegment(bytes);
  const closed = seg.closed && seg.footerOk;
  const footerBad = seg.closed && !seg.footerOk;
  return idx.transaction(async (tx) => {
    const cp = await tx.checkpoint(path);
    const append = !!cp && end >= cp.bytes && shaOf(bytes.subarray(0, cp.bytes)) === cp.prefix;
    if (cp && !append) await tx.dropPath(path);
    let indexed = 0, start = append ? cp.bytes : 0;
    for (let k = start; k < end; k++) {
      if (bytes[k] !== NL) continue;
      let v = null;
      try { v = JSON.parse(td.decode(bytes.subarray(start, k))); } catch { /* (a malformed line: not searchable) */ }
      const f = searchable(v);
      if (f) { await tx.addLine(path, start, f); indexed++; }
      start = k + 1;
    }
    await tx.setCheckpoint(path, { revision, bytes: end, prefix: shaOf(bytes.subarray(0, end)), closed });
    return { indexed, rebuilt: !!cp && !append, closed, footerBad };
  });
}

/** Forget a segment that no longer exists (deleted, or its path reused later starts afresh). */
export async function removeSegment(idx, path) {
  return idx.transaction(async (tx) => { await tx.dropPath(path); await tx.setCheckpoint(path, null); });
}
