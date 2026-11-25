// The bounds the reviews asked to see hold at every step: the writer's count with a real stream.Writable, its
// listeners, a stream that closes mid-line, malformed permission answers, and the process-wide caps.
import { test } from "node:test";
import assert from "node:assert/strict";
import { Writable } from "node:stream";
import { EventEmitter } from "node:events";
import { LineWriter, RESERVE } from "../lib/stdio.mjs";
import { fakeCreateServer, fakeQuery } from "../lib/fake.mjs";
import { AgentServer, TEXT } from "../lib/server.mjs";

// A real Writable whose write callbacks the test releases: bytes stay in writableLength until then.
function heldWritable(highWaterMark) {
  const pending = [];
  const w = new Writable({ highWaterMark, write(chunk, _enc, cb) { pending.push({ n: chunk.length, cb }); } });
  w.release = (count = Infinity) => { let k = 0; while (pending.length && k++ < count) pending.shift().cb(); };
  w.pendingWrites = () => pending.length;
  return w;
}
const tick = () => new Promise((r) => setImmediate(r));

test("writer: with a real Writable, the count never passes 2F (data) or 2F + 4 KiB (all), at every step", async () => {
  const F = 65536, w = heldWritable(65536);
  const lw = new LineWriter(w, { budget: 2 * F });
  const check = (what) => {
    const c = lw.counters();
    assert.ok(c.charged <= 2 * F, `${what}: charged ${c.charged} > 2F`);
    assert.ok(c.charged + c.reserveHeld <= 2 * F + RESERVE, `${what}: total ${c.charged + c.reserveHeld} > 2F + 4 KiB`);
  };
  // (the limits review's case: 32,767 then 65,535 characters)
  assert.equal(lw.send("a".repeat(32767)), "ok"); check("first queued"); await tick(); check("first written");
  assert.equal(lw.send("b".repeat(65535)), "ok"); check("second queued"); await tick(); check("second's first chunk");
  // (more, of mixed sizes, while nothing drains: admitted only while they fit)
  const sizes = [1, 100, 4095, 20000, 65535, 3, 30000];
  const verdicts = [];
  for (const n of sizes) { verdicts.push(lw.send("c".repeat(n))); check(`after a line of ${n}`); }
  assert.ok(verdicts.includes("full"), "something was refused for room");
  assert.equal(lw.send("r".repeat(100), { reserve: true }), "ok"); check("reserve queued");
  // (partial drains, one write callback at a time, then everything)
  for (let i = 0; i < 40 && (w.pendingWrites() || lw.counters().queued); i++) { w.release(1); await tick(); check(`partial drain ${i}`); }
  w.release(); await tick(); await tick(); check("drained");
  for (let i = 0; i < 20 && lw.counters().queued + lw.counters().inFlight; i++) { w.release(); await tick(); }
  const c = lw.counters();
  assert.deepEqual([c.held, c.reserveHeld, c.inFlight, c.live, c.liveBytes], [0, 0, 0, 0, 0]);
});

test("writer: many backpressure cycles leave no listeners behind", async () => {
  const w = new Writable({ highWaterMark: 1, write(_c, _e, cb) { setImmediate(cb); } });
  const base = { drain: w.listenerCount("drain"), close: w.listenerCount("close"), error: w.listenerCount("error") };
  const lw = new LineWriter(w, { budget: 1 << 20 });
  const after = { close: w.listenerCount("close"), error: w.listenerCount("error") };
  for (let i = 0; i < 40; i++) lw.send("x");
  for (let i = 0; i < 200 && lw.counters().queued + lw.counters().inFlight; i++) await tick();
  assert.equal(lw.counters().queued, 0);
  assert.equal(w.listenerCount("drain"), base.drain, "no drain listener left");
  assert.equal(w.listenerCount("close"), after.close, "close listeners unchanged by the 40 cycles");
  assert.equal(w.listenerCount("error"), after.error);
  assert.ok(after.close - base.close <= 1 && after.error - base.error <= 1, "one each, the writer's own");
});

test("writer: a stream that closes mid-line settles the pump and releases every count", async () => {
  const w = heldWritable(16);
  const lw = new LineWriter(w, { budget: 1 << 20 });
  lw.send("q".repeat(200000)); lw.send("second"); lw.send("x", { reserve: true });
  await tick();
  assert.ok(lw.counters().inFlight > 0);
  w.destroy();
  for (let i = 0; i < 10; i++) await tick();
  const c = lw.counters();
  assert.deepEqual([c.held, c.reserveHeld, c.queued, c.inFlight], [0, 0, 0, 0]);
  assert.equal(lw.writing, false);
  assert.equal(lw.send("after"), "closed");
  assert.equal(w.listenerCount("drain"), 0);
});

// A server with a page bound, no transport: enough to call askPerson and the notifications directly.
function bound() {
  const logs = [];
  const server = new AgentServer({ query: fakeQuery, log: (m) => logs.push(m), stdio: true });
  server.createServer = fakeCreateServer;
  const ws = { readyState: 1, send() { return "ok"; } };
  server.sock = ws;
  server.binding = { ws, grant: { folders: ["/"], write: true }, gen: 1 };
  return { server, logs };
}

test("a malformed digest is a denial, never a throw: non-ASCII of the same length, astral, lone surrogate, wrong alphabet or length, not a string", async () => {
  for (const digest of ["é".repeat(43), "😀".repeat(21) + "a", "\ud800".repeat(43), "+".repeat(43), "a".repeat(42), "a".repeat(44), 42, null, { length: 43 }]) {
    const { server, logs } = bound();
    const verdict = server.askPerson(server.binding, () => {}, "WebSearch", { query: "q" }, {}, "c1");
    const id = [...server.permissions.keys()][0];
    assert.doesNotThrow(() => server.notification("chat.permission", { request_id: id, behavior: "allow", digest }), JSON.stringify(digest));
    assert.deepEqual(await verdict, { behavior: "deny", message: "The person said no." }, JSON.stringify(digest));
    assert.equal(server.permissions.size, 0, "settled once");
    assert.ok(logs.includes(TEXT.mismatch));
    // (and the agent goes on: the next question is asked and answered)
    const next = server.askPerson(server.binding, () => {}, "WebSearch", { query: "q2" }, {}, "c1");
    server.notification("chat.permission", { request_id: [...server.permissions.keys()][0], behavior: "deny" });
    assert.equal((await next).behavior, "deny");
    await server.close();
  }
});

test("at most 4 questions are open at once, in the whole process; the fifth is denied before any card; detach releases them", async () => {
  const { server } = bound();
  const cards = [];
  const asks = [];
  for (let i = 0; i < 6; i++) asks.push(server.askPerson(server.binding, (d) => cards.push(d), "WebSearch", { query: `q${i}` }, {}, `c${i % 2}`));
  assert.equal(server.permissions.size, 4);
  assert.equal(cards.length, 4, "no card for the fifth and sixth");
  assert.deepEqual(await asks[4], { behavior: "deny", message: TEXT.tooManyQuestions });
  assert.deepEqual(await asks[5], { behavior: "deny", message: TEXT.tooManyQuestions });
  server.rebind(null, TEXT.pageGone);
  for (const a of asks.slice(0, 4)) assert.equal((await a).behavior, "deny");
  assert.equal(server.permissions.size, 0);
  await server.close();
});

test("an aborted question leaves the count at once, so a new one can be asked", async () => {
  const { server } = bound();
  const ctl = [];
  for (let i = 0; i < 4; i++) { const a = new AbortController(); ctl.push(a); server.askPerson(server.binding, () => {}, "WebSearch", { query: `q${i}` }, { signal: a.signal }, "c1"); }
  assert.equal(server.permissions.size, 4);
  ctl[0].abort();
  assert.equal(server.permissions.size, 3);
  server.askPerson(server.binding, () => {}, "WebSearch", { query: "again" }, {}, "c1");
  assert.equal(server.permissions.size, 4);
  server.rebind(null, TEXT.pageGone);
  await server.close();
});

test("at most 32 workspace requests wait for the page at once; one more is refused with its text", async () => {
  const { server } = bound();
  server.frame = 65536;
  const reqs = [];
  for (let i = 0; i < 33; i++) reqs.push(server.request(server.binding, "workspace.stat", { path: `/f${i}` }).catch((e) => e.message));
  assert.equal(server.pending.size, 32);
  assert.equal(await reqs[32], TEXT.tooManyRequests);
  server.rebind(null, TEXT.pageGone);
  assert.equal((await Promise.all(reqs.slice(0, 32))).every((m) => m === TEXT.pageGone), true);
  assert.equal(server.pending.size, 0);
  await server.close();
});

test("conversations kept are at most 64: the idle one used least long ago goes; the counters match the conversations", async () => {
  const { server } = bound();
  for (let i = 0; i < 70; i++) server.conversation(`c${i}`);
  assert.equal(server.conversations.size, 64);
  assert.equal(server.conversations.has("c0"), false);
  assert.equal(server.conversations.has("c69"), true);
  server.conversation("c6"); // (used: moves to the end, so it outlives c7)
  server.conversation("new-1");
  assert.equal(server.conversations.has("c6"), true);
  assert.equal(server.conversations.has("c7"), false);
  assert.deepEqual([server.counters().running, server.counters().queued], [0, 0]);
  await server.close();
});

test("emit checks the writer's room from the count, before the line is built", () => {
  const { server } = bound();
  server.frame = 65536;
  let built = 0;
  const ws = { readyState: 1, room: () => false, send() { built++; return "ok"; } };
  const big = { jsonrpc: "2.0", method: "x", params: { s: "y".repeat(1000) } };
  const orig = JSON.stringify;
  let stringified = 0;
  JSON.stringify = (...a) => { stringified++; return orig(...a); };
  try {
    assert.equal(server.emit(ws, big), "full");
  } finally { JSON.stringify = orig; }
  assert.deepEqual([built, stringified], [0, 0], "nothing serialized or sent");
});

test("writer: a line counts whole until stdout's callback for its last chunk, even when only a small tail is outstanding", async () => {
  const F = 65536, w = heldWritable(1 << 20);
  const lw = new LineWriter(w, { budget: 2 * F });
  assert.equal(lw.send("a".repeat(F + 9)), "ok"); // (F + 10 bytes: a 64 KiB chunk and a 10-byte tail)
  await tick();
  assert.equal(w.pendingWrites(), 1, "the first chunk is being written; the stream buffers the tail");
  w.release(1); // (stdout is done with the first chunk; now the tail is written, and its callback is held)
  await tick();
  assert.equal(w.pendingWrites(), 1);
  const c = lw.counters();
  assert.equal(c.held, F + 10, "the whole line still counts: stdout's view of the tail keeps its buffer");
  assert.equal(c.liveBytes, c.held, "the count is the buffers that exist");
  // (so less room is left for the next lines: one that would pass 2F with the whole line counted is refused)
  assert.equal(lw.send("b".repeat(F - 20)), "ok");
  assert.equal(lw.send("c".repeat(30)), "full");
  w.release(); await tick(); w.release(); await tick();
  assert.deepEqual([lw.counters().held, lw.counters().live], [0, 0]);
});

test("writer: when every count is zero, no line buffer is left reachable from the writer", async () => {
  const w = heldWritable(1 << 20);
  const lw = new LineWriter(w, { budget: 1 << 20 });
  lw.send("x".repeat(32767)); lw.send("y".repeat(65535)); lw.send("z", { reserve: true });
  for (let i = 0; i < 10; i++) { w.release(); await tick(); }
  const c = lw.counters();
  assert.deepEqual([c.held, c.reserveHeld, c.queued, c.live], [0, 0, 0, 0]);
  const reachable = Object.values(lw).filter((v) => Buffer.isBuffer(v) || (v && typeof v === "object" && Buffer.isBuffer(v.buf)));
  assert.deepEqual(reachable, [], "no completed line kept");
  assert.equal(lw.live.size, 0);
  assert.equal(lw.queue.length, 0);
});
