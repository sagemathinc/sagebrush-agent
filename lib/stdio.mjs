// `sagebrush-agent --stdio`: the runner's pipe, one JSON message per line on stdin and stdout.
//
// Bounds (every buffer finite; F is the runner's frame, from its start line):
//   - reading: stdin is the pipe socket (process.stdin), which Node reads in at most 64 KiB at a time; stdinChunks()
//     also cuts any larger chunk into 64 KiB pieces before the reader sees it. (Not fs.createReadStream on fd 0: its
//     blocking read in the thread pool keeps the process from exiting while the runner holds the pipe open.) Bytes are kept as a
//     list of chunks with a running length and joined once per line, so at most F + 1 + 64 KiB is kept between
//     lines; while a line is joined, its chunks, the input chunk and the joined line exist together, a peak of about
//     2F + 64 KiB. Before the
//     start line has given F, a line may be at most 4 KiB (BOOT_MAX). A line over the limit ends the process: the
//     runner broke the rule it set.
//   - writing: one queue of whole lines for the whole process, never preallocated. A line's buffer counts from when
//     it is queued until stdout is done with it: the callback of its last chunk (stdout keeps views into the line's
//     buffer until then, so the whole line counts, not only its unwritten tail). A data line is admitted only while
//     those buffers, with it, are at most 2F. Lines go to stdout in chunks of at most 64 KiB, waiting for "drain"
//     whenever a write returns false. A separate fixed 4 KiB reserve, counted the same way, carries the one notice
//     that a turn was stopped because the queue was full. So the line buffers this writer has made and that still
//     exist are at most 2F + 4 KiB; stdout's own bookkeeping per chunk is outside that count.
//   - a line over F is never queued: the caller refuses it first (see server.mjs, the clamp).
//   - chat input held by the server: at most 16 queued chat messages and 4 running turns' messages, each at most F,
//     for the whole process: up to 20F of serialized text (16F queued, about 64 MiB at F = 4 MiB; 20F in all, about
//     80 MiB at F = 4 MiB and 320 MiB at the largest frame a runner may set, 16 MiB), before JavaScript's and the
//     SDK's own overhead, plus one more frame being parsed when a message over the cap arrives and is refused.
//   - notebook reads kept for edits by cell (server.mjs): one process-wide budget of 8 MiB as counted (each cell id,
//     hash and ref at 2 bytes per UTF-16 unit, plus 96 bytes per cell and 256 per read, allowances for the runtime's
//     own objects, which may differ), the read used least long ago going first, in any conversation.
//   - sessions retired (server.mjs): at most 8 waiting for their transcript to be deleted, each deletion given 10 s.
// The counters() of both are what the tests bind; heap figures are only diagnostic.

import { EventEmitter } from "node:events";

export const BOOT_MAX = 4 * 1024; // the first line, before the start line gives F
export const CHUNK = 64 * 1024; // stdin's read size and stdout's write size
export const RESERVE = 4 * 1024; // the stopped-turn notice, outside the 2F budget
export const FRAME_MIN = 64 * 1024;
export const FRAME_MAX = 16 * 1024 * 1024;

export class LineReader {
  constructor({ onLine, onOver }) {
    this.onLine = onLine; // (Buffer) => void, without its newline
    this.onOver = onOver; // (limit) => void: a line longer than the limit; nothing more is read after it
    this.limit = BOOT_MAX;
    this.chunks = [];
    this.length = 0; // (bytes held in chunks: the current line so far)
    this.largest = 0; // (the largest chunk seen: a test reads it)
    this.over = false;
  }

  setLimit(n) { this.limit = n; }

  feed(chunk) {
    if (this.over) return;
    if (chunk.length > this.largest) this.largest = chunk.length;
    let at = 0;
    while (at < chunk.length) {
      const nl = chunk.indexOf(10, at);
      const end = nl === -1 ? chunk.length : nl;
      if (this.length + (end - at) > this.limit) {
        this.over = true;
        this.chunks = [];
        this.length = 0;
        return this.onOver(this.limit);
      }
      if (nl === -1) {
        this.chunks.push(at === 0 ? chunk : chunk.subarray(at));
        this.length += chunk.length - at;
        return;
      }
      const part = chunk.subarray(at, nl);
      const line = this.chunks.length ? Buffer.concat([...this.chunks, part], this.length + part.length) : part;
      this.chunks = [];
      this.length = 0;
      at = nl + 1;
      this.onLine(line);
      if (this.over) return;
    }
  }

  counters() { return { pending: this.length, chunks: this.chunks.length, largest: this.largest, limit: this.limit }; }
}

export class LineWriter {
  constructor(stream, { budget = 0 } = {}) {
    this.stream = stream;
    this.budget = budget; // 2F, once F is known (0: nothing may be queued yet)
    this.queue = []; // {buf, reserve}: lines not yet started
    this.live = new Set(); // lines started and not yet released by stdout (its callback for their last chunk)
    this.held = 0; // data bytes charged: lines queued, being written, or still held by stdout
    this.reserveHeld = 0; // the same, for reserve lines
    this.writing = false;
    this.inFlight = 0;
    this.closed = false;
    this.highWater = stream.writableHighWaterMark;
    this.wake = null; // (the pump's one pending wait for drain, close or error)
    const end = () => { this.closed = true; this.clear(); this.wake?.(); };
    stream.on?.("error", end);
    stream.on?.("close", end);
  }

  // Queue one line (a string, no newline). Returns "ok", or "full" when it would pass the budget (or the reserve,
  // for a reserve line). The caller has already refused anything over F.
  send(text, { reserve = false } = {}) {
    if (this.closed) return "closed";
    const buf = Buffer.from(text + "\n", "utf8");
    if (reserve) {
      if (this.reserveHeld + buf.length > RESERVE) return "full";
      this.reserveHeld += buf.length;
    } else {
      if (!this.room(buf.length)) return "full";
      this.held += buf.length;
    }
    this.queue.push({ buf, reserve, released: false });
    if (!this.writing) this.pump();
    return "ok";
  }

  // The data lines' backing buffers that exist: queued, being written, or handed to stdout and not yet released.
  // (stdout keeps views into a line's buffer until it has written them, so a line counts whole until the callback
  // of its last chunk.) This is what the 2F budget bounds.
  charged() { return this.held; }

  // Would a data line of n bytes (newline included) fit now?
  room(n) { return !this.closed && this.held + n <= this.budget; }

  release(item) {
    if (item.released) return;
    item.released = true;
    this.live.delete(item);
    if (item.reserve) this.reserveHeld -= item.buf.length; else this.held -= item.buf.length;
  }

  async pump() {
    this.writing = true;
    try {
      while (this.queue.length && !this.closed) {
        const item = this.queue.shift();
        this.live.add(item);
        const { buf } = item;
        this.inFlight = buf.length;
        for (let at = 0; at < buf.length && !this.closed; at += CHUNK) {
          const last = at + CHUNK >= buf.length;
          // (the last chunk's callback is when stdout is done with the whole line: released then, error or not)
          const ok = this.stream.write(buf.subarray(at, at + CHUNK), last ? () => this.release(item) : undefined);
          if (!ok && !this.closed) await this.drained();
        }
        this.inFlight = 0;
      }
    } finally {
      this.writing = false;
    }
  }

  // One wait for drain, close or error, with both listeners removed whichever comes first.
  drained() {
    return new Promise((resolve) => {
      const done = () => { this.stream.off("drain", done); this.wake = null; resolve(); };
      this.wake = done;
      this.stream.once("drain", done);
    });
  }

  // Drop the lines not yet started (detach, EOF, termination); a line already started finishes. Once the stream is
  // closed nothing more is written or released by it, so every line it holds is released here.
  clear() {
    for (const item of this.queue) this.release(item);
    this.queue = [];
    if (this.closed) { for (const item of [...this.live]) this.release(item); this.inFlight = 0; }
  }

  counters() {
    return { held: this.held, charged: this.charged(), reserveHeld: this.reserveHeld, queued: this.queue.length, live: this.live.size,
      liveBytes: [...this.live].reduce((n, i) => n + i.buf.length, 0), inFlight: this.inFlight,
      writableLength: this.stream.writableLength ?? 0, budget: this.budget, highWater: this.highWater };
  }
}

// stdin as a stream of chunks of at most CHUNK bytes: "data", then "end" or "close" or "error".
export function stdinChunks(stream = process.stdin) {
  const out = new EventEmitter();
  stream.on("data", (b) => { for (let at = 0; at < b.length; at += CHUNK) out.emit("data", at === 0 && b.length <= CHUNK ? b : b.subarray(at, at + CHUNK)); });
  for (const e of ["end", "close", "error"]) stream.on(e, (x) => out.emit(e, x));
  return out;
}

// The runner's start line: {"relay":{"start":{"frame":F,"protocol":1,"epoch":0}}}, or null if it isn't one.
export function parseStart(msg) {
  const s = msg?.relay?.start;
  if (!s || typeof s !== "object" || Object.keys(msg).length !== 1 || Object.keys(msg.relay).length !== 1) return null;
  if (s.protocol !== 1 || s.epoch !== 0) return null;
  if (!Number.isSafeInteger(s.frame) || s.frame < FRAME_MIN || s.frame > FRAME_MAX) return null;
  return { frame: s.frame };
}
