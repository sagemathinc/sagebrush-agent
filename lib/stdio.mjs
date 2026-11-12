// `sagebrush-agent --stdio`: the runner's pipe, one JSON message per line on stdin and stdout.
//
// Bounds (every buffer finite; F is the runner's frame, from its start line):
//   - reading: stdin is the pipe socket (process.stdin), which Node reads in at most 64 KiB at a time; stdinChunks()
//     also cuts any larger chunk into 64 KiB pieces before the reader sees it. (Not fs.createReadStream on fd 0: its
//     blocking read in the thread pool keeps the process from exiting while the runner holds the pipe open.) Bytes are kept as a
//     list of chunks with a running length and joined once per line, so at most F + 1 + 64 KiB is held. Before the
//     start line has given F, a line may be at most 4 KiB (BOOT_MAX). A line over the limit ends the process: the
//     runner broke the rule it set.
//   - writing: one queue of whole lines for the whole process, at most 2F bytes (each line's bytes and its newline),
//     never preallocated. A line is charged from when it is queued until its last chunk has been written, and what
//     stdout still holds of written lines (writableLength) is charged too. Lines go to stdout in chunks of at most
//     64 KiB, waiting for "drain" whenever a write returns false, so stdout holds at most its writableHighWaterMark
//     plus one chunk. A separate fixed 4 KiB
//     reserve carries the one notice that a turn was stopped because the queue was full; it isn't part of the 2F.
//   - a line over F is never queued: the caller refuses it first (see server.mjs, the clamp).
//   - input queued by the server: at most 16 chat messages of at most F each, for the whole process. That is up to
//     16F of serialized text (about 64 MiB at F = 4 MiB) before JavaScript's own overhead.
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
    this.closed = false;
    this.highWater = stream.writableHighWaterMark;
    stream.on?.("error", () => { this.closed = true; this.queue = []; });
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
      if (this.charged() + buf.length > this.budget) return "full";
      this.held += buf.length;
    }
    this.queue.push({ buf, reserve });
    if (!this.writing) this.pump();
    return "ok";
  }

  // What counts against the budget: lines queued or being written, and what stdout still holds of earlier ones
  // (writableLength: a line written whole leaves the queue, but its bytes may still be in stdout's buffer).
  charged() { return this.held + (this.stream.writableLength ?? 0); }

  // Would a line of n bytes (newline included) fit now?
  room(n) { return !this.closed && this.charged() + n <= this.budget; }

  async pump() {
    this.writing = true;
    try {
      while (this.queue.length && !this.closed) {
        const item = this.queue.shift();
        const { buf } = item;
        this.inFlight = buf.length;
        for (let at = 0; at < buf.length && !this.closed; at += CHUNK) {
          const ok = this.stream.write(buf.subarray(at, at + CHUNK));
          if (!ok && !this.closed) await new Promise((resolve) => { this.stream.once("drain", resolve); this.stream.once("close", resolve); });
        }
        this.inFlight = 0;
        if (item.reserve) this.reserveHeld -= buf.length; else this.held -= buf.length;
      }
    } finally {
      this.writing = false;
    }
  }

  // Drop the lines not yet started (detach, EOF, termination); the one being written finishes.
  clear() {
    for (const item of this.queue) { if (item.reserve) this.reserveHeld -= item.buf.length; else this.held -= item.buf.length; }
    this.queue = [];
  }

  counters() {
    return { held: this.held, charged: this.charged(), reserveHeld: this.reserveHeld, queued: this.queue.length, inFlight: this.inFlight,
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
