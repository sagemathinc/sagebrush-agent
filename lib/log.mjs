// Each conversation's log: every message this agent sends a page about a conversation (its turns' events, a message
// it rejected) and every message the person sent in it, numbered from 1 in the order they happened. A page that
// (re)connects asks for what came after the last number it has (`chat.resume`) and gets just that (`chat.replay`),
// so a reload, a navigation or a second tab shows the conversation as it is, without the page keeping it itself.
//
// The log is kept in memory only, like everything else this agent knows about a conversation: it goes when the
// agent stops (its transcripts are deleted then too). `instance` names this run of the agent, so a page holding
// numbers from an earlier run starts again from the beginning instead of asking for numbers that mean nothing now.
//
// It is bounded: at most EVENTS_MAX entries and BYTES_MAX bytes a conversation (the oldest go first), and TOTAL_MAX
// bytes for the whole process (the oldest entries of the conversation used least long ago go first). An entry
// bigger than ENTRY_MAX is kept as a stub that says so, never cut. A page asking for numbers that are gone gets
// `reset` (the first number still kept) and what is kept.

import { randomBytes } from "node:crypto";

export const EVENTS_MAX = 2000;
export const BYTES_MAX = 2 * 1024 * 1024;
export const TOTAL_MAX = 32 * 1024 * 1024;
export const ENTRY_MAX = 256 * 1024;
const ENTRY_BYTES = 64; // (an entry's own object and its Map slot, an allowance on top of its JSON)

export class ChatLogs {
  constructor({ eventsMax = EVENTS_MAX, bytesMax = BYTES_MAX, totalMax = TOTAL_MAX, entryMax = ENTRY_MAX } = {}) {
    this.instance = randomBytes(8).toString("hex");
    this.eventsMax = eventsMax;
    this.bytesMax = bytesMax;
    this.totalMax = totalMax;
    this.entryMax = entryMax;
    this.logs = new Map(); // conversation → { next, entries: [{ seq, method, params, bytes }], bytes }, used last at the end
    this.total = 0;
  }

  // Record one message about `conversation`; returns its number.
  append(conversation, method, params) {
    let log = this.logs.get(conversation);
    if (log) this.logs.delete(conversation);
    else log = { next: 1, entries: [], bytes: 0 };
    this.logs.set(conversation, log);
    let json = JSON.stringify(params);
    let bytes = Buffer.byteLength(json) + ENTRY_BYTES;
    if (bytes > this.entryMax) {
      params = { conversation, omitted: { bytes: bytes - ENTRY_BYTES } };
      bytes = Buffer.byteLength(JSON.stringify(params)) + ENTRY_BYTES;
    }
    const seq = log.next++;
    log.entries.push({ seq, method, params, bytes });
    log.bytes += bytes;
    this.total += bytes;
    while (log.entries.length > this.eventsMax || log.bytes > this.bytesMax) this.shift(log);
    // (over the whole budget: the oldest entries of the conversation used least long ago go, the newest one's last)
    for (const other of this.logs.values()) {
      while (this.total > this.totalMax && other.entries.length && (other !== log || other.entries.length > 1)) this.shift(other);
      if (this.total <= this.totalMax) break;
    }
    return seq;
  }

  shift(log) {
    const e = log.entries.shift();
    log.bytes -= e.bytes;
    this.total -= e.bytes;
  }

  // What came after `after` in `conversation`: { events, last, reset? }. `reset` (the first number kept) when numbers
  // after `after` are gone, or when `instance` is another run's; the page then starts again from `events`.
  since(conversation, after, instance) {
    const log = this.logs.get(conversation);
    const last = log ? log.next - 1 : 0;
    const first = log?.entries.length ? log.entries[0].seq : last + 1;
    // (numbers from another run, or beyond this run's last: they mean nothing here, so start again from the beginning)
    const stale = (instance !== undefined && instance !== this.instance) || after > last;
    if (stale) after = 0;
    const reset = stale || after + 1 < first ? first : undefined;
    const events = (log?.entries ?? []).filter((e) => e.seq > after).map(({ seq, method, params }) => ({ seq, method, params }));
    return { events, last, ...(reset !== undefined ? { reset } : {}) };
  }

  counters() {
    return { logs: this.logs.size, logBytes: this.total };
  }
}
