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
//   - writing: one queue of whole lines for the whole process, never preallocated. Resident output is counted once:
//     the lines queued and the one being written (each line's bytes and its newline, held until its last chunk is
//     written), plus what stdout still holds beyond that line's chunks already handed to it (writableLength less
//     those). A data line is admitted only if that total, the queued reserve line aside, stays at most 2F; the
//     total is the same before, during and after each write, since a chunk handed to stdout moves bytes from one
//     part of the count to the other. Lines go to stdout in chunks of at most 64 KiB, waiting for "drain" whenever a
//     write returns false. A separate fixed 4 KiB reserve carries the one notice that a turn was stopped because the
//     queue was full: queued, it counts against the reserve, not the 2F; once written, its bytes still in stdout
//     count in the total. So resident output is at most 2F + 4 KiB.
//   - a line over F is never queued: the caller refuses it first (see server.mjs, the clamp).
//   - chat input held by the server: at most 16 queued chat messages and 4 running turns' messages, each at most F,
//     for the whole process: up to 20F of serialized text (16F queued, about 64 MiB at F = 4 MiB; 20F in all, about
//     80 MiB at F = 4 MiB and 320 MiB at the largest frame a runner may set, 16 MiB), before JavaScript's and the
//     SDK's own overhead, plus one more frame being parsed when a message over the cap arrives and is refused.
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
    this.queue = []; // {buf, reserve}
    this.held = 0; // bytes charged against the budget: queued lines and the one being written
    this.reserveHeld = 0;
    this.writing = false;
    this.inFlight = 0;
    this.inFlightWritten = 0; // (bytes of the line being written already handed to stdout: in held and in writableLength)
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
    this.queue.push({ buf, reserve });
    if (!this.writing) this.pump();
    return "ok";
  }

  // Resident output against the 2F budget, each byte once: data lines queued or being written, plus what stdout
  // holds beyond the current line's chunks (earlier lines' bytes, a written reserve line's bytes).
  charged() { return this.held + Math.max(0, (this.stream.writableLength ?? 0) - this.inFlightWritten); }

  // Would a data line of n bytes (newline included) fit now?
  room(n) { return !this.closed && this.charged() + n <= this.budget; }

  async pump() {
    this.writing = true;
    try {
      while (this.queue.length && !this.closed) {
        const item = this.queue.shift();
        this.current = item;
        const { buf } = item;
        this.inFlight = buf.length;
        // (a reserve line is counted by reserveHeld until its last chunk is written; its chunks in stdout before
        // that count in charged() too, at most 4 KiB counted twice, which only makes admission stricter)
        for (let at = 0; at < buf.length && !this.closed; at += CHUNK) {
          const chunk = buf.subarray(at, at + CHUNK);
          const ok = this.stream.write(chunk);
          if (!item.reserve) this.inFlightWritten += chunk.length;
          if (!ok && !this.closed) await this.drained();
        }
        this.inFlight = 0;
        this.inFlightWritten = 0;
        if (this.closed) break; // (clear() has released the counts)
        if (item.reserve) this.reserveHeld -= buf.length; else this.held -= buf.length;
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

  // Drop the lines not yet started (detach, EOF, termination); the one being written finishes. Once the stream is
  // closed nothing more is written, so its counts are released too.
  clear() {
    if (this.closed && this.inFlight) {
      // (the line being written will never finish: release it with the queue)
      const item = this.current;
      if (item) { if (item.reserve) this.reserveHeld -= item.buf.length; else this.held -= item.buf.length; }
      this.inFlight = 0;
      this.inFlightWritten = 0;
    }
    for (const item of this.queue) { if (item.reserve) this.reserveHeld -= item.buf.length; else this.held -= item.buf.length; }
    this.queue = [];
  }

  counters() {
    return { held: this.held, charged: this.charged(), inFlightWritten: this.inFlightWritten, reserveHeld: this.reserveHeld, queued: this.queue.length, inFlight: this.inFlight,
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
