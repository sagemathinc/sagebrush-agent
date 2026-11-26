// The agent log: an agent's readable transcript and its latest context (the transcript-and-context design note r0.8).
// Pure, with no Node built-ins and no I/O of its own: a host imports it directly, and the page has a byte-for-byte
// mirror with pinned hashes, as for the fleet core. The store and the journal's persistence are the caller's.
export * from "./limits.mjs";
export { boundedLines } from "./lines.mjs";
export { ADAPTERS, WINDOW_BUDGET, claudeRecord, codexRecord, contextWindow, messageCost } from "./adapters.mjs";
export { buildContext, contextHeader, cutToFit, lineText, utf8Head } from "./context.mjs";
export {
  OPEN_CALLS_MAX, SEGMENT_RE, encodeLine, endLine, fits, footerLine, frame, gapLine, linesDigest, parseSegment, pointerLine, segmentPath, startLine,
  toolSummary, turnLineStream, turnLines, turnLinesFromRecords,
} from "./transcript.mjs";
export { abortStalled, anchorNow, observeTail, publishContext, publishTurn } from "./writer.mjs";
export { Journal } from "./journal.mjs";
export { Sha256 } from "./sha256.mjs";
export { KEEP_DAYS, KEEP_NEWEST, compact, isPrefix, planClosedSegment, planContext, planOpenSegment, retainedVersions } from "./retention.mjs";
export { indexSegment, removeSegment, searchable } from "./search.mjs";
