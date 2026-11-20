// Each conversation's log and chat.resume: the log on its own (numbers, bounds, resets), then the daemon end to end
// with a fake page: a page that comes back gets what it missed, from the number it asks for.
import assert from "node:assert/strict";
import { test } from "node:test";
import WebSocket from "ws";
import { jsonBytes } from "../lib/canon.mjs";
import { fakeCreateServer, fakeQuery } from "../lib/fake.mjs";
import { ChatLogs, ENTRY_MAX, ID_MAX, LOGS_MAX, TOTAL_MAX } from "../lib/log.mjs";
import { AgentServer } from "../lib/server.mjs";

const ORIGIN = "https://agents.sagebrush.cloud";
const REPLAY_BYTES = 1024 * 1024;

test("log: numbers only grow, across conversations; since() gives what came after, and nothing twice", () => {
  const logs = new ChatLogs();
  assert.equal(logs.append("a", "turn.event", { conversation: "a", n: 1 }), 1);
  assert.equal(logs.append("a", "turn.event", { conversation: "a", n: 2 }), 2);
  assert.equal(logs.append("b", "chat.message", { conversation: "b", text: "hi" }), 3);
  assert.equal(logs.append("a", "chat.rejected", { conversation: "a", n: 3 }), 4);
  const all = logs.since("a", 0, logs.instance);
  assert.deepEqual(all.events.map((e) => [e.seq, e.method, e.params.n]), [[1, "turn.event", 1], [2, "turn.event", 2], [4, "chat.rejected", 3]]);
  assert.equal(all.last, 4);
  assert.equal(all.reset, undefined);
  assert.deepEqual(logs.since("a", 2, logs.instance).events.map((e) => e.seq), [4]);
  assert.deepEqual(logs.since("a", 3, logs.instance), { events: [{ seq: 4, method: "chat.rejected", params: { conversation: "a", n: 3 } }], last: 4 }); // (3 is b's: a gap, not a loss)
  assert.deepEqual(logs.since("a", 4, logs.instance).events, []);
  assert.deepEqual(logs.since("z", 0), { events: [], last: 0 });
});

test("log: another run's numbers, or numbers this run never gave, start again from the beginning with reset", () => {
  const logs = new ChatLogs();
  for (let i = 0; i < 3; i++) logs.append("a", "turn.event", { conversation: "a", i });
  const other = logs.since("a", 2, "an-earlier-run");
  assert.equal(other.reset, true);
  assert.deepEqual(other.events.map((e) => e.seq), [1, 2, 3]);
  const beyond = logs.since("a", 99, logs.instance);
  assert.equal(beyond.reset, true);
  assert.equal(beyond.events.length, 3);
  assert.deepEqual(logs.since("z", 5, "an-earlier-run"), { events: [], last: 0, reset: true });
  // (a conversation this run has no log for, asked from a number: its entries are gone)
  assert.deepEqual(logs.since("z", 2, logs.instance), { events: [], last: 0, reset: true });
});

test("log: bounded per conversation; a page behind what was dropped gets reset", () => {
  const logs = new ChatLogs({ eventsMax: 5 });
  for (let i = 1; i <= 8; i++) logs.append("a", "turn.event", { conversation: "a", i });
  const r = logs.since("a", 1, logs.instance);
  assert.equal(r.reset, true);
  assert.deepEqual(r.events.map((e) => e.seq), [4, 5, 6, 7, 8]);
  assert.equal(logs.since("a", 3, logs.instance).reset, undefined); // (3 was the last dropped: nothing after it is gone)
  const small = new ChatLogs({ bytesMax: 600 });
  for (let i = 0; i < 10; i++) small.append("a", "turn.event", { conversation: "a", text: "x".repeat(100) });
  assert.ok(small.logs.get("a").entries.reduce((n, e) => n + e.bytes, 0) <= 600);
  assert.equal(small.since("a", 0, small.instance).events.at(-1).seq, 10);
});

test("log: many conversations: at most LOGS_MAX logs and TOTAL_MAX bytes, keys counted, no empty log kept", () => {
  // (the reviewers' churn: 1000 distinct conversations of 100 kB each, default limits)
  const logs = new ChatLogs();
  for (let i = 0; i < 1000; i++) logs.append("conversation-" + i, "turn.event", { conversation: "conversation-" + i, text: "x".repeat(100_000) });
  const c = logs.counters();
  assert.ok(c.logs <= LOGS_MAX, `${c.logs} logs`);
  assert.ok(c.logBytes <= TOTAL_MAX, `${c.logBytes} bytes`);
  assert.equal([...logs.logs.values()].filter((x) => !x.entries.length).length, 0);
  // (the bookkeeping adds up: every log's bytes, keys and allowances included)
  assert.equal([...logs.logs.values()].reduce((n, x) => n + x.bytes, 0), c.logBytes);
  // tiny conversations, by the thousand, under a small budget: the count and the bytes hold
  const tiny = new ChatLogs({ logsMax: 50, totalMax: 64 * 1024 });
  for (let i = 0; i < 10_000; i++) tiny.append("c" + i, "chat.rejected", { conversation: "c" + i });
  assert.ok(tiny.counters().logs <= 50);
  assert.ok(tiny.counters().logBytes <= 64 * 1024);
  // a log dropped whole and started again: its numbers carry on from the counter, and an old page gets reset
  const again = tiny.since("c0", 1, tiny.instance);
  assert.deepEqual(again, { events: [], last: 0, reset: true });
  const seq = tiny.append("c0", "turn.event", { conversation: "c0" });
  assert.ok(seq > 10_000);
  const back = tiny.since("c0", 1, tiny.instance);
  assert.equal(back.reset, true);
  assert.deepEqual(back.events.map((e) => e.seq), [seq]);
});

test("log: a conversation id over ID_MAX bytes is never logged", () => {
  const logs = new ChatLogs();
  assert.equal(logs.append("x".repeat(ID_MAX + 1), "turn.event", { conversation: "x" }), 0);
  assert.equal(logs.append("é".repeat(ID_MAX / 2 + 1), "turn.event", {}), 0); // (bytes, not characters)
  assert.equal(logs.append("", "turn.event", {}), 0);
  assert.equal(logs.append(7, "turn.event", {}), 0);
  assert.equal(logs.counters().logs, 0);
  assert.ok(logs.append("x".repeat(ID_MAX), "turn.event", {}) > 0);
});

test("log: an entry over the cap is a stub saying at least how big, made without serializing the entry", () => {
  const logs = new ChatLogs({ entryMax: 1000 });
  const stringify = JSON.stringify;
  JSON.stringify = () => { throw new Error("serialized"); };
  try {
    logs.append("a", "turn.event", { conversation: "a", text: "z".repeat(50_000_000) });
  } finally {
    JSON.stringify = stringify;
  }
  const [e] = logs.since("a", 0, logs.instance).events;
  assert.equal(e.seq, 1);
  assert.deepEqual(e.params, { conversation: "a", omitted: { at_least: 1000 } });
  assert.ok(logs.counters().logBytes < 2000);
  // (the default cap: an entry just under it is kept whole, just over it is a stub)
  const d = new ChatLogs();
  d.append("a", "turn.event", { text: "y".repeat(ENTRY_MAX - 200) });
  d.append("a", "turn.event", { text: "y".repeat(ENTRY_MAX) });
  const [kept, stub] = d.since("a", 0, d.instance).events;
  assert.equal(kept.params.text.length, ENTRY_MAX - 200);
  assert.ok(stub.params.omitted);
});

test("jsonBytes counts a replay entry exactly as JSON.stringify writes it", () => {
  for (const e of [{ seq: 1, method: "turn.event", params: { conversation: "c", event: { type: "text_delta", text: "a\"b\n\u0001é😀" } } }, { seq: 22, method: "chat.message", params: { conversation: "c", id: "u1", text: "", author: "person" } }]) {
    assert.equal(jsonBytes(e, 1e9), Buffer.byteLength(JSON.stringify(e)));
  }
});

async function start(opts = {}) {
  const server = new AgentServer({ query: fakeQuery, log: () => {}, ...opts });
  server.createServer = fakeCreateServer;
  const port = await server.listen();
  return { server, port, code: server.newCode() };
}

// A fake page that keeps every message it gets, answers workspace verbs, and can ask for a replay.
function page(port) {
  const ws = new WebSocket(`ws://127.0.0.1:${port}/sagebrush`, { origin: ORIGIN });
  const msgs = [];
  let onHello;
  ws.on("message", (d) => {
    const m = JSON.parse(d.toString());
    if (m.id === "p1") return onHello?.(m);
    msgs.push(m);
    if (typeof m.id === "string" && m.method) {
      const result = m.method === "workspace.list" ? { entries: [] } : m.method === "workspace.stat" ? { entry: null } : { entry: { path: m.params?.path }, rev: 1 };
      ws.send(JSON.stringify({ jsonrpc: "2.0", id: m.id, result }));
    }
  });
  const hello = (params) => new Promise((resolve) => {
    onHello = resolve;
    ws.send(JSON.stringify({ jsonrpc: "2.0", id: "p1", method: "hello", params: { protocol: 1, page: { origin: ORIGIN, path: "/agents/" }, ...params } }));
  });
  const notify = (method, params) => ws.send(JSON.stringify({ jsonrpc: "2.0", method, params }));
  const open = new Promise((resolve, reject) => { ws.on("open", resolve); ws.on("error", reject); });
  const closed = new Promise((resolve) => ws.on("close", resolve));
  const replays = () => msgs.filter((m) => m.method === "chat.replay").map((m) => m.params);
  const events = () => msgs.filter((m) => m.method === "turn.event").map((m) => m.params);
  return { ws, msgs, hello, notify, open, closed, replays, events };
}

const until = async (f, ms = 5000) => {
  const t = Date.now();
  while (!f()) {
    if (Date.now() - t > ms) throw new Error("timed out");
    await new Promise((r) => setTimeout(r, 20));
  }
};

test("resume: live events carry their number; a page that comes back gets the message and the whole turn, then only what's new", async () => {
  const { server, port, code } = await start();
  const a = page(port);
  await a.open;
  const h = await a.hello({ code });
  a.notify("grant.changed", { folders: ["/"], write: true, expires: null });
  a.notify("chat.message", { conversation: "c1", id: "u1", author: "person", text: "hello there" });
  await until(() => a.events().some((e) => e.event.type === "turn_finished"));
  // (live: numbered in order after the person's message, which is 1)
  const live = a.events().map((e) => e.seq);
  assert.equal(live[0], 2);
  assert.deepEqual(live, live.map((_, i) => i + 2));
  a.ws.close();
  await a.closed;
  await new Promise((r) => setTimeout(r, 50));

  const b = page(port);
  await b.open;
  const hb = (await b.hello({ session: h.result.session })).result;
  assert.ok(hb.features.includes("chat.resume"));
  assert.equal(hb.log.instance, h.result.log.instance); // (the hello names the log's run: the same agent, the same run)
  b.notify("chat.resume", { conversation: "c1", after: 0 });
  await until(() => b.replays().some((r) => r.done));
  const all = b.replays().flatMap((r) => r.events);
  assert.deepEqual(all[0], { seq: 1, method: "chat.message", params: { conversation: "c1", id: "u1", text: "hello there", author: "person" } });
  assert.deepEqual(all.slice(1).map((e) => e.seq), live);
  assert.deepEqual(all.slice(1).map((e) => e.params.event), a.events().map((e) => e.event));
  const r0 = b.replays()[0];
  assert.equal(r0.last, live.at(-1));
  assert.equal(r0.reset, undefined);

  // (from the last number it has: nothing new)
  b.notify("chat.resume", { conversation: "c1", after: r0.last, instance: r0.instance });
  await until(() => b.replays().length === 2);
  assert.deepEqual(b.replays()[1].events, []);
  // (numbers from an earlier run of the agent: from the beginning, with reset)
  b.notify("chat.resume", { conversation: "c1", after: 3, instance: "an-earlier-run" });
  await until(() => b.replays().length === 3);
  assert.equal(b.replays()[2].reset, true);
  assert.equal(b.replays()[2].events.length, all.length);
  b.ws.close();
  server.close();
});

test("resume: a turn cut off by the page going away is in the log with its end, though no page got it then", async () => {
  const { server, port, code } = await start();
  const a = page(port);
  await a.open;
  const h = await a.hello({ code });
  a.notify("grant.changed", { folders: ["/"], write: true, expires: null });
  a.notify("chat.message", { conversation: "c1", id: "u1", author: "person", text: "x ".repeat(200) });
  await until(() => a.events().some((e) => e.event.type === "text_delta"));
  a.ws.close();
  await a.closed;
  await until(() => server.counters().running === 0);

  const b = page(port);
  await b.open;
  await b.hello({ session: h.result.session });
  b.notify("chat.resume", { conversation: "c1", after: 0 });
  await until(() => b.replays().some((r) => r.done));
  const ends = b.replays().flatMap((r) => r.events).filter((e) => e.method === "turn.event" && e.params.event.type === "turn_finished");
  assert.equal(ends.length, 1);
  assert.equal(ends[0].params.event.outcome, "interrupted");
  b.ws.close();
  server.close();
});

test("resume: a message turned away as busy isn't logged, its rejection is; nor do unique ids grow the logs past their bound", async () => {
  const { server, port, code } = await start();
  const a = page(port);
  await a.open;
  await a.hello({ code });
  a.notify("chat.message", { conversation: "c1", id: "u1", author: "agent", text: "not a person" }); // (malformed)
  await until(() => a.msgs.some((m) => m.method === "chat.rejected"));
  server.queuedCount = 16; // (QUEUED_MAX: every place taken, so the next message is turned away as busy)
  a.notify("chat.message", { conversation: "c2", id: "u2", author: "person", text: "hi" });
  await until(() => a.msgs.filter((m) => m.method === "chat.rejected").length === 2);
  const live = a.msgs.filter((m) => m.method === "chat.rejected")[1].params;
  assert.equal(live.reason.code, "busy");
  a.notify("chat.resume", { conversation: "c2", after: 0 });
  await until(() => a.replays().some((r) => r.done));
  assert.deepEqual(a.replays()[0].events.map((e) => [e.seq, e.method]), [[live.seq, "chat.rejected"]]);
  a.notify("chat.resume", { conversation: "c1", after: 0 });
  await until(() => a.replays().length === 2);
  assert.deepEqual(a.replays()[1].events.map((e) => [e.method, e.params.reason.code]), [["chat.rejected", "malformed"]]);
  // (a page sending unique conversation ids while the queue is full: the logs stay within LOGS_MAX)
  for (let i = 0; i < LOGS_MAX + 300; i++) a.notify("chat.message", { conversation: `u${i}`, id: `m${i}`, author: "person", text: "x" });
  await until(() => a.msgs.filter((m) => m.method === "chat.rejected").length === LOGS_MAX + 302, 15000);
  assert.ok(server.logs.counters().logs <= LOGS_MAX);
  server.queuedCount = 0;
  a.ws.close();
  server.close();
});

test("resume and chat.message: a conversation id over ID_MAX bytes is refused and never logged", async () => {
  const { server, port, code } = await start();
  const a = page(port);
  await a.open;
  await a.hello({ code });
  const long = "c".repeat(ID_MAX + 1);
  a.notify("chat.message", { conversation: long, id: "u1", author: "person", text: "hi" });
  await until(() => a.msgs.some((m) => m.method === "chat.rejected"));
  const r = a.msgs.find((m) => m.method === "chat.rejected").params;
  assert.equal(r.reason.code, "malformed");
  assert.equal(r.seq, undefined);
  assert.equal(server.logs.counters().logs, 0);
  a.notify("chat.resume", { conversation: long, after: 0 });
  a.notify("chat.resume", { conversation: "ok", after: 0 });
  await until(() => a.replays().length >= 1);
  await new Promise((res) => setTimeout(res, 50));
  assert.deepEqual(a.replays().map((x) => x.conversation), ["ok"]);
  a.ws.close();
  server.close();
});

test("resume: a malformed request is ignored; a well-formed one is answered", async () => {
  const { server, port, code } = await start();
  const a = page(port);
  await a.open;
  await a.hello({ code });
  for (const bad of [{}, { conversation: 1, after: 0 }, { conversation: "c1", after: -1 }, { conversation: "c1", after: 1.5 }, { conversation: "c1" }]) a.notify("chat.resume", bad);
  a.notify("chat.resume", { conversation: "c1", after: 0 });
  await until(() => a.replays().length >= 1);
  await new Promise((r) => setTimeout(r, 50));
  assert.equal(a.replays().length, 1);
  a.ws.close();
  server.close();
});

// The replays a fake socket got: each line's bytes and its events.
function capture(frame = null, { room = () => true, drains = true } = {}) {
  const server = new AgentServer({ query: fakeQuery, log: () => {} });
  const lines = [];
  const sock = { readyState: 1, bufferedAmount: 0, room, send: (text) => { lines.push(text); if (!drains) sock.bufferedAmount += Buffer.byteLength(text); return "ok"; } };
  server.frame = frame;
  server.sock = sock;
  server.binding = { ws: sock, grant: null, gen: 1 };
  const replays = () => lines.map((l) => ({ bytes: Buffer.byteLength(l), params: JSON.parse(l).params }));
  return { server, lines, sock, replays };
}

/** An entry whose replay form ({seq, method, params}) is exactly `size` bytes. */
function sized(logs, conversation, size) {
  const params = { conversation, text: "" };
  const seq = logs.seq + 1;
  const overhead = Buffer.byteLength(JSON.stringify({ seq, method: "turn.event", params }));
  params.text = "x".repeat(size - overhead);
  assert.equal(logs.append(conversation, "turn.event", params), seq);
}

test("resume: every replay holding more than one entry is at most REPLAY_BYTES, all of it (the reviewers' boundary)", () => {
  const { server, replays } = capture();
  for (let i = 1; i <= 5; i++) sized(server.logs, "c", i <= 4 ? 250_000 : 48_576);
  server.resume({ conversation: "c", after: 0 });
  const rs = replays();
  for (const r of rs) if (r.params.events.length > 1) assert.ok(r.bytes <= REPLAY_BYTES, `${r.bytes} bytes`);
  assert.deepEqual(rs.flatMap((r) => r.params.events).map((e) => e.seq), [1, 2, 3, 4, 5]);
  assert.equal(rs.at(-1).params.done, true);
  // (and filled to the byte: five entries, each under ENTRY_MAX, sized so a replay of them is exactly REPLAY_BYTES go in
  //  one; one byte more splits it)
  for (const extra of [0, 1]) {
    const c = capture();
    const env = jsonBytes({ jsonrpc: "2.0", method: "chat.replay", params: { conversation: "d", instance: c.server.logs.instance, last: 5, running: [], events: [], done: false } }, 1e9); // (done's longer value: the budget counts it)
    const room = REPLAY_BYTES - env - 4; // (four commas)
    const base = Math.floor(room / 5);
    for (let i = 0; i < 4; i++) sized(c.server.logs, "d", base);
    sized(c.server.logs, "d", room - 4 * base + extra);
    c.server.resume({ conversation: "d", after: 0 });
    const rs = c.replays();
    assert.deepEqual(rs.map((r) => r.params.events.length), extra ? [4, 1] : [5], `extra ${extra}`);
    if (!extra) assert.equal(rs[0].bytes, REPLAY_BYTES - 1); // (the last replay says done: true, a byte shorter)
    for (const r of rs) assert.ok(r.bytes <= REPLAY_BYTES);
    c.server.close();
  }
  server.close();
});

test("resume: on the WebSocket a page that isn't reading gets at most REPLAY_BYTES queued, however often it asks", () => {
  const { server, lines, sock } = capture(null, { drains: false });
  for (let i = 0; i < 13; i++) sized(server.logs, "c", 150_000); // (1.95 MB: within the conversation's 2 MiB)
  for (let k = 0; k < 100; k++) server.resume({ conversation: "c", after: 0 });
  const queued = lines.reduce((n, l) => n + Buffer.byteLength(l), 0);
  assert.equal(queued, sock.bufferedAmount);
  assert.ok(queued <= 2 * REPLAY_BYTES, `${queued} bytes queued`); // (it stops once REPLAY_BYTES are waiting: one more replay at most)
  // (once it drains, the page asks again from the last number it got and gets the rest)
  const got = Math.max(...lines.flatMap((l) => JSON.parse(l).params.events.map((e) => e.seq)));
  sock.bufferedAmount = 0;
  const before = lines.length;
  server.resume({ conversation: "c", after: got });
  assert.ok(got < 13, "the first replay stopped before the end");
  const rest = lines.slice(before).flatMap((l) => JSON.parse(l).params.events.map((e) => e.seq));
  assert.deepEqual(rest, Array.from({ length: 13 - got }, (_, i) => got + 1 + i));
  server.close();
});

test("resume: a long log comes in several replays, in order, each within its bound", async () => {
  const { server, port, code } = await start();
  const a = page(port);
  await a.open;
  await a.hello({ code });
  for (let i = 0; i < 30; i++) server.logs.append("c1", "turn.event", { conversation: "c1", turn_id: "t", event: { type: "text_delta", text: "w".repeat(60_000) } });
  a.notify("chat.resume", { conversation: "c1", after: 0 });
  await until(() => a.replays().some((r) => r.done));
  const rs = a.replays();
  assert.ok(rs.length > 1);
  assert.ok(rs.slice(0, -1).every((r) => r.done === false));
  for (const m of a.msgs.filter((m) => m.method === "chat.replay")) assert.ok(Buffer.byteLength(JSON.stringify(m)) <= REPLAY_BYTES);
  assert.deepEqual(rs.flatMap((r) => r.events).map((e) => e.seq), Array.from({ length: 30 }, (_, i) => i + 1));
  a.ws.close();
  server.close();
});

test("resume.tag: the hello says chat.resume.tag; a tag comes back on every replay of its request, within the bound; none without one; a malformed tag gets no replay", async () => {
  const { server, port, code } = await start();
  const a = page(port);
  await a.open;
  const h = (await a.hello({ code })).result;
  assert.ok(h.features.includes("chat.resume.tag"));
  for (let i = 0; i < 30; i++) server.logs.append("c1", "turn.event", { conversation: "c1", turn_id: "t", event: { type: "text_delta", text: "w".repeat(60_000) } });
  a.notify("chat.resume", { conversation: "c1", after: 0, tag: "mirror" });
  await until(() => a.replays().some((r) => r.done));
  const tagged = a.msgs.filter((m) => m.method === "chat.replay");
  assert.ok(tagged.length > 1, "several replays");
  assert.ok(tagged.every((m) => m.params.tag === "mirror"), "every replay of the request carries its tag");
  for (const m of tagged) assert.ok(Buffer.byteLength(JSON.stringify(m)) <= REPLAY_BYTES, "the tag is counted in the bound");
  assert.deepEqual(tagged.flatMap((m) => m.params.events).map((e) => e.seq), Array.from({ length: 30 }, (_, i) => i + 1));
  // (untagged: no tag field at all)
  const n = a.replays().length;
  a.notify("chat.resume", { conversation: "c1", after: 29 });
  await until(() => a.replays().length === n + 1);
  assert.equal("tag" in a.replays()[n], false);
  // (malformed: nothing comes back, not even an untagged replay; the next good request still does)
  for (const bad of ["", "Mirror", "mirror!", "a".repeat(17), 5, null, ["mirror"], { t: "mirror" }]) a.notify("chat.resume", { conversation: "c1", after: 29, tag: bad });
  a.notify("chat.resume", { conversation: "c1", after: 29, tag: "abcdefghijklmnop" });
  await until(() => a.replays().length === n + 2);
  await new Promise((r) => setTimeout(r, 100));
  assert.equal(a.replays().length, n + 2, "only the well-formed request was answered");
  assert.equal(a.replays()[n + 1].tag, "abcdefghijklmnop");
  a.ws.close();
  server.close();
});

test("resume with --stdio: every replay line fits the runner's frame; an entry too big to wrap is replayed as a stub", () => {
  const server = new AgentServer({ query: fakeQuery, log: () => {} });
  const frame = 64 * 1024; // (FRAME_MIN)
  const lines = [];
  const sock = { readyState: 1, send: (text) => { lines.push(text); return "ok"; }, room: () => true };
  server.frame = frame;
  server.sock = sock;
  server.binding = { ws: sock, grant: null, gen: 1 };
  for (let i = 0; i < 6; i++) server.logs.append("c1", "turn.event", { conversation: "c1", event: { type: "text_delta", text: "a".repeat(20_000) } });
  server.logs.append("c1", "turn.event", { conversation: "c1", event: { type: "text_delta", text: "b".repeat(frame - 200) } }); // (fitted live, not wrapped)
  server.resume({ conversation: "c1", after: 0 });
  assert.ok(lines.length > 1);
  for (const l of lines) {
    const n = Buffer.byteLength(l), k = JSON.parse(l).params.events.length;
    assert.ok(n + 1 <= frame, `a line of ${n} bytes`);
    if (k > 1) assert.ok(n <= frame / 2, `a line of ${k} entries, ${n} bytes, over half the frame`);
  }
  const events = lines.flatMap((l) => JSON.parse(l).params.events);
  assert.deepEqual(events.map((e) => e.seq), [1, 2, 3, 4, 5, 6, 7]);
  assert.ok(events[6].params.omitted.at_least > frame / 2);
  assert.equal(JSON.parse(lines.at(-1)).params.done, true);
  server.close();
});

test("resume with --stdio: a full output queue stops the replay; the page asks again from where it got to", () => {
  const server = new AgentServer({ query: fakeQuery, log: () => {} });
  const lines = [];
  let room = 1;
  const sock = { readyState: 1, send: (text) => { lines.push(text); return "ok"; }, room: () => room-- > 0 };
  server.frame = 64 * 1024;
  server.sock = sock;
  server.binding = { ws: sock, grant: null, gen: 1 };
  for (let i = 0; i < 6; i++) server.logs.append("c1", "turn.event", { conversation: "c1", event: { type: "text_delta", text: "a".repeat(20_000) } });
  server.resume({ conversation: "c1", after: 0 });
  assert.equal(lines.length, 1);
  const first = JSON.parse(lines[0]).params;
  assert.equal(first.done, false);
  const got = first.events.at(-1).seq;
  assert.ok(got < first.last);
  room = 100;
  server.resume({ conversation: "c1", after: got, instance: first.instance });
  const rest = lines.slice(1).flatMap((l) => JSON.parse(l).params.events).map((e) => e.seq);
  assert.deepEqual([...first.events.map((e) => e.seq), ...rest], [1, 2, 3, 4, 5, 6]);
  server.close();
});
