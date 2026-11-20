// Each conversation's log: every message this agent sends a page about a conversation (its turns' events, a message
// it rejected) and every message the person sent in it, numbered in the order they happened. A page that
// (re)connects asks for what came after the last number it has (`chat.resume`) and gets just that (`chat.replay`),
// so a reload, a navigation or a second tab shows the conversation as it is, without the page keeping it itself.
//
// Who may read it: the paired page, whichever it is. Pairing (a code, or the session secret of a re-pair)
// authenticates the person's browser to this agent process, and it authorizes reading EVERY conversation's log kept
// here: a paired page, or a replacement for it, can ask for any conversation id. It is not scoped to a page or to a
// conversation; a workspace grant doesn't gate it. If per-page privacy is ever needed, this doesn't provide it.
//
// The numbers come from one counter for the whole process, so they only ever grow: a conversation's numbers have
// gaps, and a log that was dropped and starts again never reuses a number a page holds. The log is kept in memory
// only, like everything else this agent knows about a conversation: it goes when the agent stops (its transcripts
// are deleted then too). `instance` names this run of the agent, so a page holding numbers from an earlier run starts
// again from the beginning.
//
// It is bounded, keys and bookkeeping included:
// - a conversation id is at most ID_MAX bytes (a longer one is refused where it comes in, and never logged);
// - at most EVENTS_MAX entries and BYTES_MAX bytes a conversation (the oldest go first);
// - at most LOGS_MAX conversations and TOTAL_MAX bytes for the whole process: the oldest entries of the conversation
//   used least long ago go first, and a conversation left with no entries goes entirely;
// - an entry bigger than ENTRY_MAX is kept as a stub that says so, never cut. Its size is measured with a bounded
//   count that stops at the cap, so an oversized event is never serialized to find out (`omitted.at_least`).
// A page asking for numbers that are gone gets `reset` and what is kept.

import { randomBytes } from "node:crypto";
import { jsonBytes } from "./canon.mjs";

export const ID_MAX = 256;
export const EVENTS_MAX = 2000;
export const BYTES_MAX = 2 * 1024 * 1024;
export const LOGS_MAX = 256;
export const TOTAL_MAX = 32 * 1024 * 1024;
export const ENTRY_MAX = 256 * 1024;
const ENTRY_BYTES = 64; // (an entry's own object and its array slot, an allowance on top of its JSON)
const LOG_BYTES = 256; // (a log's own object, its array and its Map entry, an allowance on top of its key)

/** Whether `id` can name a conversation here: a string of 1 to ID_MAX bytes. */
export const conversationId = (id) => typeof id === "string" && id.length > 0 && id.length <= ID_MAX && Buffer.byteLength(id) <= ID_MAX;

export class ChatLogs {
  constructor({ eventsMax = EVENTS_MAX, bytesMax = BYTES_MAX, logsMax = LOGS_MAX, totalMax = TOTAL_MAX, entryMax = ENTRY_MAX } = {}) {
    this.instance = randomBytes(8).toString("hex");
    this.eventsMax = eventsMax;
    this.bytesMax = bytesMax;
    this.logsMax = logsMax;
    this.totalMax = totalMax;
    this.entryMax = entryMax;
    // conversation → { base, dropped, entries: [{ seq, method, params, bytes }], bytes }, used last at the end.
    // base: the counter when the log was made (numbers up to it aren't in this log); dropped: its highest number
    // that has gone (0: none).
    this.logs = new Map();
    this.seq = 0;
    this.total = 0;
  }

  // Record one message about `conversation`; returns its number (0: not logged, the id isn't one).
  append(conversation, method, params) {
    if (!conversationId(conversation)) return 0;
    let log = this.logs.get(conversation);
    if (log) this.logs.delete(conversation);
    else {
      log = { base: this.seq, dropped: 0, entries: [], bytes: LOG_BYTES + 2 * conversation.length };
      this.total += log.bytes;
    }
    this.logs.set(conversation, log);
    let n = jsonBytes(params, this.entryMax - ENTRY_BYTES);
    if (n < 0) {
      params = { conversation, omitted: { at_least: this.entryMax } };
      n = jsonBytes(params, this.entryMax);
    }
    const bytes = n + ENTRY_BYTES;
    const seq = ++this.seq;
    log.entries.push({ seq, method, params, bytes });
    log.bytes += bytes;
    this.total += bytes;
    while (log.entries.length > this.eventsMax || log.bytes - LOG_BYTES - 2 * conversation.length > this.bytesMax) this.shift(log);
    // (over the process's budget: the oldest entries of the conversation used least long ago go, and a log left
    //  empty goes too; this one keeps its newest entry)
    for (const [k, other] of this.logs) {
      if (this.total <= this.totalMax && this.logs.size <= this.logsMax) break;
      if (other === log) continue;
      while (this.total > this.totalMax && other.entries.length) this.shift(other);
      if (!other.entries.length || this.logs.size > this.logsMax) this.drop(k, other);
    }
    while (this.total > this.totalMax && log.entries.length > 1) this.shift(log);
    return seq;
  }

  shift(log) {
    const e = log.entries.shift();
    log.dropped = e.seq;
    log.bytes -= e.bytes;
    this.total -= e.bytes;
  }

  drop(k, log) {
    this.logs.delete(k);
    this.total -= log.bytes;
  }

  // What came after `after` in `conversation`: { events, last, reset? }. `reset` when entries after `after` are gone
  // (dropped, or the whole log went and started again), or when `instance` is another run's or `after` is a number
  // this run never gave; the page then keeps what it has and takes `events`.
  since(conversation, after, instance) {
    const log = conversationId(conversation) ? this.logs.get(conversation) : undefined;
    const last = log?.entries.length ? log.entries.at(-1).seq : 0;
    const stale = (instance !== undefined && instance !== this.instance) || after > this.seq;
    if (stale) after = 0;
    const gone = log ? after < log.dropped || (after > 0 && after < log.base) : after > 0;
    const events = [];
    for (const e of log?.entries ?? []) if (e.seq > after) events.push({ seq: e.seq, method: e.method, params: e.params });
    return { events, last, ...(stale || gone ? { reset: true } : {}) };
  }

  counters() {
    return { logs: this.logs.size, logBytes: this.total };
  }
}
