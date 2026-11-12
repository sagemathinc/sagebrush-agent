// The stdio reader and writer, byte-exact at every edge (lib/stdio.mjs).
import { test } from "node:test";
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { LineReader, LineWriter, parseStart, BOOT_MAX, CHUNK, RESERVE, FRAME_MIN, FRAME_MAX } from "../lib/stdio.mjs";

const reader = () => {
  const r = { lines: [], over: [] };
  r.r = new LineReader({ onLine: (b) => r.lines.push(b.toString("utf8")), onOver: (n) => r.over.push(n) });
  return r;
};

test("reader: before start, a first line of exactly 4 KiB passes and 4 KiB + 1 is over", () => {
  const a = reader();
  a.r.feed(Buffer.from("a".repeat(BOOT_MAX) + "\n"));
  assert.deepEqual([a.lines.length, a.over.length], [1, 0]);
  const b = reader();
  b.r.feed(Buffer.from("a".repeat(BOOT_MAX + 1) + "\n"));
  assert.deepEqual([b.lines.length, b.over], [0, [BOOT_MAX]]);
  const c = reader(); // (over before its newline has even arrived)
  c.r.feed(Buffer.from("a".repeat(BOOT_MAX + 1)));
  assert.deepEqual(c.over, [BOOT_MAX]);
});

test("reader: with F set, a line of exactly F passes and F + 1 is over, however it is split", () => {
  const F = FRAME_MIN;
  for (const split of [1, 7, CHUNK, F]) {
    const a = reader(); a.r.setLimit(F);
    const buf = Buffer.from("x".repeat(F) + "\n" + "y".repeat(F + 1) + "\n");
    for (let at = 0; at < buf.length; at += split) a.r.feed(buf.subarray(at, at + split));
    assert.equal(a.lines.length, 1, `split ${split}`);
    assert.equal(a.lines[0].length, F);
    assert.deepEqual(a.over, [F], `split ${split}`);
  }
});

test("reader: nothing is read after a line over the limit", () => {
  const a = reader();
  a.r.feed(Buffer.from("a".repeat(BOOT_MAX + 5) + "\nok\n"));
  a.r.feed(Buffer.from("more\n"));
  assert.deepEqual([a.lines, a.over.length], [[], 1]);
});

test("reader: a line split over many chunks is held as a list and joined once; pending is released", () => {
  const a = reader(); a.r.setLimit(FRAME_MIN);
  for (let i = 0; i < 100; i++) a.r.feed(Buffer.from("z".repeat(100)));
  assert.deepEqual([a.r.counters().pending, a.r.counters().chunks], [10000, 100]);
  a.r.feed(Buffer.from("\n"));
  assert.equal(a.lines[0].length, 10000);
  assert.deepEqual([a.r.counters().pending, a.r.counters().chunks], [0, 0]);
});

test("reader: several lines in one chunk, multibyte characters across chunk edges", () => {
  const a = reader();
  const buf = Buffer.from("€1\n€2\n€3");
  for (let i = 0; i < buf.length; i++) a.r.feed(buf.subarray(i, i + 1));
  a.r.feed(Buffer.from("\n"));
  assert.deepEqual(a.lines, ["€1", "€2", "€3"]);
});

test("parseStart: the one valid form, F at each edge and just outside, protocol, epoch, extra keys", () => {
  const s = (o) => parseStart({ relay: { start: o } });
  assert.deepEqual(s({ frame: FRAME_MIN, protocol: 1, epoch: 0 }), { frame: FRAME_MIN });
  assert.deepEqual(s({ frame: FRAME_MAX, protocol: 1, epoch: 0 }), { frame: FRAME_MAX });
  for (const bad of [{ frame: FRAME_MIN - 1, protocol: 1, epoch: 0 }, { frame: FRAME_MAX + 1, protocol: 1, epoch: 0 },
    { frame: 1.5, protocol: 1, epoch: 0 }, { frame: "1e6", protocol: 1, epoch: 0 }, { frame: -FRAME_MIN, protocol: 1, epoch: 0 },
    { frame: FRAME_MIN, protocol: 2, epoch: 0 }, { frame: FRAME_MIN, protocol: 1, epoch: 1 }, { frame: FRAME_MIN, protocol: 1 }]) {
    assert.equal(s(bad), null, JSON.stringify(bad));
  }
  assert.equal(parseStart({ relay: { start: { frame: FRAME_MIN, protocol: 1, epoch: 0 } }, x: 1 }), null);
  assert.equal(parseStart({ relay: { start: { frame: FRAME_MIN, protocol: 1, epoch: 0 }, page: "attached" } }), null);
  assert.equal(parseStart({ jsonrpc: "2.0" }), null);
});

// A stdout stand-in whose reads the test controls: write() returns false once its buffer passes the high-water mark;
// a write's callback is called when its bytes are taken (drainAll), as a real stream calls it once they are flushed.
class Pipe extends EventEmitter {
  constructor(highWater = 16 * 1024) { super(); this.writableHighWaterMark = highWater; this.writableLength = 0; this.out = []; this.cbs = []; this.paused = false; }
  write(b, cb) { this.out.push(Buffer.from(b)); this.writableLength += b.length; if (cb) this.cbs.push(cb); if (!this.paused) queueMicrotask(() => this.drainAll()); return this.writableLength < this.writableHighWaterMark; }
  drainAll() { if (this.writableLength === 0) return; this.writableLength = 0; for (const cb of this.cbs.splice(0)) cb(); this.emit("drain"); }
  text() { return Buffer.concat(this.out).toString("utf8"); }
}
const tick = () => new Promise((r) => setImmediate(r));

test("writer: the budget is exact: queued bytes reach exactly 2F, one more byte is full", async () => {
  const p = new Pipe(); p.paused = true;
  const w = new LineWriter(p, { budget: 2 * 100 });
  assert.equal(w.send("a".repeat(99)), "ok"); // (100 with its newline, now in flight)
  assert.equal(w.send("b".repeat(99)), "ok"); // (200: exactly the budget)
  assert.equal(w.send(""), "full"); // (one byte more)
  assert.deepEqual([w.counters().charged, w.counters().reserveHeld], [200, 0], "queued or still in stdout: all charged");
  assert.equal(w.send("stopped", { reserve: true }), "ok", "the reserve still takes the notice");
  assert.equal(w.send("x".repeat(RESERVE), { reserve: true }), "full");
  p.paused = false; p.drainAll();
  for (let i = 0; i < 10; i++) await tick();
  assert.equal(p.text(), "a".repeat(99) + "\n" + "b".repeat(99) + "\nstopped\n");
  assert.deepEqual([w.counters().charged, w.counters().reserveHeld, w.counters().queued], [0, 0, 0]);
});

test("writer: a line goes out in 64 KiB chunks, waiting for drain; it stays charged until its last chunk", async () => {
  const p = new Pipe(16 * 1024); p.paused = true;
  const w = new LineWriter(p, { budget: 1 << 20 });
  w.send("q".repeat(3 * CHUNK));
  await tick();
  assert.equal(p.out.length, 1, "one chunk, then a wait for drain");
  assert.equal(p.out[0].length, CHUNK);
  assert.equal(w.counters().held, 3 * CHUNK + 1);
  assert.equal(w.counters().highWater, 16 * 1024);
  for (let i = 0; i < 4; i++) { p.drainAll(); await tick(); }
  assert.deepEqual(p.out.map((b) => b.length), [CHUNK, CHUNK, CHUNK, 1]);
  assert.equal(w.counters().held, 0);
});

test("writer: clear() drops lines not started; the one in flight finishes whole", async () => {
  const p = new Pipe(16); p.paused = true;
  const w = new LineWriter(p, { budget: 1 << 20 });
  w.send("first-line-long-enough"); w.send("second"); w.send("third");
  await tick();
  w.clear();
  assert.equal(w.counters().queued, 0);
  p.drainAll(); await tick(); await tick();
  assert.equal(p.text(), "first-line-long-enough\n");
  assert.equal(w.counters().held, 0);
});

test("writer: nothing can be queued before the budget is set (before start)", () => {
  const w = new LineWriter(new Pipe());
  assert.equal(w.send("x"), "full");
});
