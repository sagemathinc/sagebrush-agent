// The agent log's caps (the transcript-and-context design note r0.8). Every number here is a contract with LIMITS: a
// change is a reviewed change. Byte counts are of the FINAL encoded UTF-8, newlines and escaping included.

/** The latest context file, whole: header, every line, every newline (§2). */
export const CONTEXT_MAX = 8 * 1024 * 1024;
/** The context's header line (§2). */
export const HEADER_MAX = 4096;
/** One transcript line, encoded, its newline included (§3). A longer text continues on `part` lines. */
export const LINE_MAX = 64 * 1024;
/** One transcript segment, its footer included: a HARD cap (§3.3). */
export const SEGMENT_MAX = 1024 * 1024;
/** The footer line, reserved inside SEGMENT_MAX before any line is accepted (§3.3). */
export const FOOTER_MAX = 512;
/** One raw line of an agent tool's session file: past it, the rest of the line is discarded as it streams (§2). */
export const RAW_LINE_MAX = 16 * 1024 * 1024;
/** A writer's journal, per agent, counted as it is written (§6.1). */
export const JOURNAL_MAX = 64 * 1024 * 1024;
/** A tool call's one-line summary, in characters (§3). */
export const SUMMARY_CHARS = 200;
/** A stalled turn may be aborted after its segment's revision stays unchanged this long, on the observer's own
 *  monotonic clock (§3.1). */
export const STALL_MS = 10 * 60 * 1000;
/** The header's `model` field (§2). */
export const MODEL_MAX = 128;
