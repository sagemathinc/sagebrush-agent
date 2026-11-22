// `--stdio`'s stdout on Windows: the writes happen on a worker thread, so a runner that stops reading never blocks
// this process's main thread.
//
// Why: on Windows, Node writes to a stdout pipe synchronously. When the runner stops reading, process.stdout.write
// blocks the whole event loop until it reads again: every conversation, the pings and the control lines wait, and
// the queue in LineWriter (stdio.mjs) never fills, so its 2F bound can't stop the turn that is writing. Elsewhere the
// write returns at once and the pipe's own buffer grows.
//
// ThreadStdout is the small part of a Writable that LineWriter uses: write(chunk, callback) returning whether to keep
// writing, writableLength, writableHighWaterMark, and the events "drain", "error" and "close". Each chunk is copied
// and handed to one worker thread, which writes it to the file descriptor with blocking writes, in order, and says
// when it's done; the chunk's callback runs then. So LineWriter's queue, its 2F accounting and the moment a line is
// released (its last chunk's callback) stay on the main thread, unchanged.
//
// Bounds: the copies handed to the worker and not yet written are writableLength bytes. A write returns false once
// that reaches the high-water mark, and LineWriter then waits for "drain" before its next write, so the copies are at
// most HIGH_WATER + one chunk (64 KiB, stdio.mjs's CHUNK): 128 KiB, outside the 2F count as stdout's own buffer is.
//
// Errors: the first failed write (the runner closed the pipe) ends it: "error", then "close"; every chunk not yet
// written has its callback called with the error, and later writes do nothing and return false.
// flush(ms) resolves once everything handed over is written, or after ms (a runner that stopped reading).

import { EventEmitter } from "node:events";
import { Worker } from "node:worker_threads";

export const HIGH_WATER = 64 * 1024;

export class ThreadStdout extends EventEmitter {
  constructor({ fd = 1, highWaterMark = HIGH_WATER } = {}) {
    super();
    this.writableHighWaterMark = highWaterMark;
    this.writableLength = 0; // (bytes handed to the worker and not yet written)
    this.pending = new Map(); // id -> { n, cb }: in the order handed over
    this.next = 0;
    this.needDrain = false;
    this.ended = false;
    this.idle = []; // (flush's waiters)
    this.worker = new Worker(new URL("./stdout-thread-worker.mjs", import.meta.url), { workerData: { fd }, execArgv: [] });
    // (execArgv []: the thread takes none of the process's own flags, such as an -e script to run again)
    this.worker.on("message", (m) => this.done(m));
    this.worker.on("error", (e) => this.fail(e));
    this.worker.on("exit", () => this.fail(new Error("the stdout thread stopped")));
    this.worker.unref(); // (idle, it never keeps the process up; while it holds chunks it does: write() refs it)
  }

  write(chunk, cb) {
    if (this.ended) {
      if (cb) queueMicrotask(() => cb(this.error));
      return false;
    }
    const bytes = new Uint8Array(chunk.length); // (a copy of its own: a Buffer may be a view into a shared pool)
    bytes.set(chunk);
    const id = this.next++;
    if (this.pending.size === 0) this.worker.ref();
    this.pending.set(id, { n: bytes.length, cb });
    this.writableLength += bytes.length;
    this.worker.postMessage({ id, bytes }, [bytes.buffer]);
    if (this.writableLength < this.writableHighWaterMark) return true;
    this.needDrain = true;
    return false;
  }

  done({ id, error }) {
    if (error !== undefined) return this.fail(Object.assign(new Error(`stdout: ${error}`), { code: error }));
    const p = this.pending.get(id);
    if (!p) return;
    this.pending.delete(id);
    this.writableLength -= p.n;
    p.cb?.();
    if (this.needDrain && this.writableLength < this.writableHighWaterMark) {
      this.needDrain = false;
      this.emit("drain");
    }
    if (this.pending.size === 0) {
      this.worker.unref();
      for (const w of this.idle.splice(0)) w();
    }
  }

  fail(e) {
    if (this.ended) return;
    this.ended = true;
    this.error = e;
    const left = [...this.pending.values()];
    this.pending.clear();
    this.writableLength = 0;
    for (const p of left) p.cb?.(e);
    for (const w of this.idle.splice(0)) w();
    this.worker.terminate().catch(() => {});
    if (this.listenerCount("error")) this.emit("error", e);
    this.emit("close");
  }

  flush(ms) {
    if (this.ended || this.pending.size === 0) return Promise.resolve();
    return new Promise((resolve) => {
      const t = setTimeout(() => { this.idle.splice(this.idle.indexOf(done) >>> 0, 1); resolve(); }, ms);
      const done = () => { clearTimeout(t); resolve(); };
      this.idle.push(done);
    });
  }
}

// The stdout --stdio writes to: the thread on Windows, process.stdout elsewhere (its writes to a pipe don't block
// there). SAGEBRUSH_AGENT_STDOUT=thread or =stream picks one explicitly (the tests run the thread on every platform).
export function stdioOutput(env = process.env, platform = process.platform) {
  const pick = env.SAGEBRUSH_AGENT_STDOUT === "thread" || env.SAGEBRUSH_AGENT_STDOUT === "stream" ? env.SAGEBRUSH_AGENT_STDOUT : platform === "win32" ? "thread" : "stream";
  return pick === "thread" ? new ThreadStdout() : process.stdout;
}
