// Bounded line reading of an agent tool's session file (the design note §2, LIMITS H1). The file is the agent's own
// (agent-writable) and can be any size, so it is read forward in chunks, never whole, and never a whole line before
// its size is known: bytes are counted as they arrive, and a line that passes `max` is discarded from that point to its
// newline with nothing more buffered. The peak held is at most `max` plus one chunk.
//
// The source is any (async) iterable of Uint8Array chunks; the reader holds no file, so it stays pure.

import { RAW_LINE_MAX } from "./limits.mjs";

const NL = 10;

/**
 * Yields, in order, { line: Uint8Array } for each complete line (without its newline) and { skipped: n } for each line
 * that passed `max` (n: its full byte length, newline excluded). A final line without a newline is yielded too.
 * `stats.peak` records the most bytes ever held at once (what's buffered plus the chunk being read).
 */
export async function* boundedLines(chunks, { max = RAW_LINE_MAX, stats = {} } = {}) {
  if (!Number.isSafeInteger(max) || max < 1) throw new RangeError("max: a positive byte count");
  stats.peak = stats.peak ?? 0;
  let parts = [], held = 0, discarding = false, skippedLen = 0;
  const note = (n) => { if (n > stats.peak) stats.peak = n; };
  for await (const chunk of chunks) {
    if (!(chunk instanceof Uint8Array)) throw new TypeError("a chunk must be a Uint8Array");
    note(held + chunk.length);
    let start = 0;
    while (start < chunk.length) {
      const nl = chunk.indexOf(NL, start);
      const end = nl < 0 ? chunk.length : nl;
      const piece = end - start;
      if (discarding) {
        skippedLen += piece;
      } else if (held + piece > max) {
        // (the line passes the cap here: drop what was held, and count the rest without keeping it)
        discarding = true;
        skippedLen = held + piece;
        parts = [];
        held = 0;
      } else if (piece > 0) {
        parts.push(chunk.subarray(start, end));
        held += piece;
      }
      if (nl < 0) break;
      // (a newline ends the line)
      if (discarding) yield { skipped: skippedLen };
      else yield { line: join(parts, held) };
      parts = [];
      held = 0;
      discarding = false;
      skippedLen = 0;
      start = nl + 1;
    }
    // (copy what's held, so the caller may reuse its chunk buffer)
    if (parts.length) { const kept = join(parts, held); parts = [kept]; }
  }
  if (discarding) yield { skipped: skippedLen };
  else if (held > 0) yield { line: join(parts, held) };
}

function join(parts, n) {
  if (parts.length === 1 && parts[0].length === n) return parts[0].slice();
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}
