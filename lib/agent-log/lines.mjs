// Bounded line reading of an agent tool's session file (the design note §2, LIMITS H1). The file is the agent's own
// (agent-writable) and can be any size, so it is read forward in chunks, never whole, and never a whole line before
// its size is known: bytes are counted as they arrive, and a line that passes `max` is discarded from that point to its
// newline with nothing more buffered.
//
// Memory, exactly: the reader allocates ONE buffer of `max` bytes (on the first line that spans chunks) and nothing
// else per line. A yielded line is a VIEW, of that buffer or of the caller's chunk, valid only until the next value is
// requested: a consumer that keeps a line copies it. So what the reader holds at any moment is at most `max` plus the
// caller's current chunk, with no per-line copies and no prefix re-joined chunk after chunk.
//
// The source is any (async) iterable of Uint8Array chunks; the reader opens no file, so it stays pure.

import { RAW_LINE_MAX } from "./limits.mjs";

const NL = 10;

/**
 * Yields, in order, { line: Uint8Array } for each complete line (without its newline; a view, see above) and
 * { skipped: n } for each line that passed `max` (n: its full byte length, newline excluded). A final line without a
 * newline is yielded too. `stats.peak` is the reader's own buffer plus the largest chunk it was handed; `stats.buffer`
 * its buffer's size (0 or `max`).
 */
export async function* boundedLines(chunks, { max = RAW_LINE_MAX, stats = {} } = {}) {
  if (!Number.isSafeInteger(max) || max < 1) throw new RangeError("max: a positive byte count");
  stats.peak = stats.peak ?? 0;
  stats.buffer = 0;
  let buf = null, held = 0, discarding = false, skippedLen = 0;
  for await (const chunk of chunks) {
    if (!(chunk instanceof Uint8Array)) throw new TypeError("a chunk must be a Uint8Array");
    if (stats.buffer + chunk.length > stats.peak) stats.peak = stats.buffer + chunk.length;
    let start = 0;
    while (start < chunk.length) {
      const nl = chunk.indexOf(NL, start);
      const end = nl < 0 ? chunk.length : nl;
      const piece = end - start;
      if (discarding) {
        skippedLen += piece;
      } else if (held + piece > max) {
        // (the line passes the cap here: forget what was held, and count the rest without keeping it)
        discarding = true;
        skippedLen = held + piece;
        held = 0;
      } else if (nl >= 0 && held === 0) {
        // (a whole line inside this chunk: yielded as a view of the chunk, never copied)
        yield { line: chunk.subarray(start, end) };
        start = nl + 1;
        continue;
      } else if (piece > 0) {
        if (!buf) { buf = new Uint8Array(max); stats.buffer = max; if (max + chunk.length > stats.peak) stats.peak = max + chunk.length; }
        buf.set(chunk.subarray(start, end), held);
        held += piece;
      }
      if (nl < 0) break;
      // (a newline ends the line)
      if (discarding) yield { skipped: skippedLen };
      else yield { line: buf ? buf.subarray(0, held) : new Uint8Array(0) };
      held = 0;
      discarding = false;
      skippedLen = 0;
      start = nl + 1;
    }
  }
  if (discarding) yield { skipped: skippedLen };
  else if (held > 0) yield { line: buf.subarray(0, held) };
}
