// The agent log: an agent's readable transcript and its latest context (the transcript-and-context design note r0.8).
// Pure, with no Node built-ins and no I/O of its own: a host imports it directly, and the page has a byte-for-byte
// mirror with pinned hashes, as for the fleet core. The store and the journal's persistence are the caller's.
export * from "./limits.mjs";
export { boundedLines } from "./lines.mjs";
export { ADAPTERS, claudeRecord, codexRecord, contextWindow } from "./adapters.mjs";
export { buildContext, contextHeader, cutToFit, lineText, utf8Head } from "./context.mjs";
export {
  SEGMENT_RE, encodeLine, endLine, fits, footerLine, frame, gapLine, parseSegment, pointerLine, segmentPath, startLine, toolSummary, turnLines,
} from "./transcript.mjs";
export { abortStalled, anchorNow, observeTail, publishContext, publishTurn } from "./writer.mjs";
export { Journal } from "./journal.mjs";
