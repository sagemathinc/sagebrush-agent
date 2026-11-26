// What a lost host never published (the transcript-and-context design note r0.8 §6): turns still pending in a lost
// host's export journal are gone (the journal isn't in host backup's sources). The first export after a restore
// compares the restored audit stream's turn ids with the newest published marker and writes, in its own turn, a gap
// line naming exactly the turns missing: { turn, i, gap: true, turns: [ids], from_ms, to_ms }. Their text is never
// re-derived from restored session files.
//
// Pure: the caller reads the audit stream and the newest marker.

import { LINE_MAX } from "./limits.mjs";
import { gapLine } from "./transcript.mjs";

const TURN_RE = /^[0-9a-f]{32}$/;

/**
 * The turns of `audit` ([{ turn, at_ms }], the restored audit stream in its order) that were never published:
 * those after the newest published marker's turn (`published`: { turn, at_ms } | null for nothing published). When
 * that turn isn't in the restored stream (it is older than the stream reaches), the entries after its time.
 */
export function missingTurns(audit, published) {
  const seen = new Set();
  for (const e of audit) {
    if (!e || !TURN_RE.test(e.turn) || !Number.isSafeInteger(e.at_ms)) throw new RangeError("audit: { turn, at_ms } entries");
    if (seen.has(e.turn)) throw new RangeError(`audit: turn ${e.turn} twice`);
    seen.add(e.turn);
  }
  if (published === null) return audit.slice();
  if (!published || !TURN_RE.test(published.turn) || !Number.isSafeInteger(published.at_ms)) throw new RangeError("published: { turn, at_ms } | null");
  const k = audit.findIndex((e) => e.turn === published.turn);
  return k >= 0 ? audit.slice(k + 1) : audit.filter((e) => e.at_ms > published.at_ms);
}

/**
 * The gap lines for the missing turns, as content lines of the export's current turn `turn` from index `i`: one line
 * naming every missing turn, or (past LINE_MAX, about 1,800 ids) as many lines as needed, each naming its own run of
 * turns, in order, so every missing id is named exactly once. [] when nothing is missing.
 */
export function restoreGapLines(turn, i, audit, published) {
  const missing = missingTurns(audit, published);
  const lines = [];
  for (let k = 0; k < missing.length; ) {
    // (the most ids that fit: each costs its quoted 32 hex digits and a comma, so a bound first, then checked)
    let n = Math.min(missing.length - k, Math.floor(LINE_MAX / 35));
    for (;;) {
      const run = missing.slice(k, k + n);
      const ms = run.map((e) => e.at_ms), fields = { turns: run.map((e) => e.turn), from_ms: Math.min(...ms), to_ms: Math.max(...ms) };
      try { lines.push(gapLine(turn, i + lines.length, fields)); k += n; break; } catch (e) { if (n === 1) throw e; n--; }
    }
  }
  return lines;
}
