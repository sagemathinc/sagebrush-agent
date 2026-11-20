// Each conversation's log and chat.resume: the log on its own (numbers, bounds, resets), then the daemon end to end
// with a fake page: a page that comes back gets what it missed, from the number it asks for.
import assert from "node:assert/strict";
import { test } from "node:test";
import WebSocket from "ws";
import { fakeCreateServer, fakeQuery } from "../lib/fake.mjs";
import { ChatLogs } from "../lib/log.mjs";
import { AgentServer } from "../lib/server.mjs";

const ORIGIN = "https://agents.sagebrush.cloud";

test("log: numbers from 1 per conversation; since() gives what came after, and nothing twice", () => {
  const logs = new ChatLogs();
  assert.equal(logs.append("a", "turn.event", { conversation: "a", n: 1 }), 1);
  assert.equal(logs.append("a", "turn.event", { conversation: "a", n: 2 }), 2);
  assert.equal(logs.append("b", "chat.message", { conversation: "b", text: "hi" }), 1);
  assert.equal(logs.append("a", "chat.rejected", { conversation: "a", n: 3 }), 3);
  const all = logs.since("a", 0, logs.instance);
  assert.deepEqual(all.events.map((e) => [e.seq, e.method, e.params.n]), [[1, "turn.event", 1], [2, "turn.event", 2], [3, "chat.rejected", 3]]);
  assert.equal(all.last, 3);
  assert.equal(all.reset, undefined);
  const after = logs.since("a", 2, logs.instance);
  assert.deepEqual(after.events.map((e) => e.seq), [3]);
  assert.equal(after.reset, undefined);
  assert.deepEqual(logs.since("a", 3, logs.instance).events, []);
  // (a conversation this agent never saw: nothing, and nothing to reset for a page that has nothing either)
  assert.deepEqual(logs.since("z", 0), { events: [], last: 0 });
});

test("log: another run's numbers, or numbers beyond the last, start again from the beginning with reset", () => {
  const logs = new ChatLogs();
  for (let i = 0; i < 3; i++) logs.append("a", "turn.event", { conversation: "a", i });
  const other = logs.since("a", 2, "an-earlier-run");
  assert.equal(other.reset, 1);
  assert.deepEqual(other.events.map((e) => e.seq), [1, 2, 3]);
  const beyond = logs.since("a", 99, logs.instance);
  assert.equal(beyond.reset, 1);
  assert.equal(beyond.events.length, 3);
  // (an empty log, asked from an earlier run: reset, nothing to show)
  assert.deepEqual(logs.since("z", 5, "an-earlier-run"), { events: [], last: 0, reset: 1 });
});

test("log: bounded per conversation (count and bytes) and process-wide; a page behind the oldest gets reset", () => {
  const logs = new ChatLogs({ eventsMax: 5, bytesMax: 1e9, totalMax: 1e9 });
  for (let i = 1; i <= 8; i++) logs.append("a", "turn.event", { conversation: "a", i });
  const r = logs.since("a", 1, logs.instance);
  assert.equal(r.reset, 4);
  assert.deepEqual(r.events.map((e) => e.seq), [4, 5, 6, 7, 8]);
  assert.equal(logs.since("a", 5, logs.instance).reset, undefined);

  const small = new ChatLogs({ eventsMax: 1000, bytesMax: 600, totalMax: 1e9 });
  for (let i = 0; i < 10; i++) small.append("a", "turn.event", { conversation: "a", text: "x".repeat(100) });
  assert.ok(small.counters().logBytes <= 600);
  assert.equal(small.since("a", 0, small.instance).events.at(-1).seq, 10);

  // process-wide: the conversation used least long ago gives up its oldest entries first; the newest entry stays
  const total = new ChatLogs({ eventsMax: 1000, bytesMax: 1e9, totalMax: 1000 });
  for (let i = 0; i < 4; i++) total.append("old", "turn.event", { conversation: "old", text: "x".repeat(100) });
  for (let i = 0; i < 4; i++) total.append("new", "turn.event", { conversation: "new", text: "y".repeat(100) });
  assert.ok(total.counters().logBytes <= 1000);
  assert.equal(total.since("new", 0, total.instance).events.length, 4);
  assert.ok(total.since("old", 0, total.instance).events.length < 4);
});

test("log: an entry over the per-entry cap is kept as a stub that says so, never cut", () => {
  const logs = new ChatLogs({ entryMax: 1000 });
  logs.append("a", "turn.event", { conversation: "a", text: "z".repeat(5000) });
  const [e] = logs.since("a", 0, logs.instance).events;
  assert.equal(e.seq, 1);
  assert.equal(e.params.conversation, "a");
  assert.ok(e.params.omitted.bytes > 5000);
  assert.equal(e.params.text, undefined);
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
  assert.ok((await b.hello({ session: h.result.session })).result.features.includes("chat.resume"));
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
  assert.equal(b.replays()[2].reset, 1);
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

test("resume: a message the agent turned away is in the log with its rejection; a malformed one only by its rejection", async () => {
  const { server, port, code } = await start();
  const a = page(port);
  await a.open;
  await a.hello({ code });
  a.notify("chat.message", { conversation: "c1", id: "u1", author: "agent", text: "not a person" }); // (malformed: not logged)
  await until(() => a.msgs.some((m) => m.method === "chat.rejected"));
  server.queuedCount = 16; // (QUEUED_MAX: every place taken, so the next message is turned away as busy)
  a.notify("chat.message", { conversation: "c2", id: "u2", author: "person", text: "hi" });
  await until(() => a.msgs.filter((m) => m.method === "chat.rejected").length === 2);
  const live = a.msgs.filter((m) => m.method === "chat.rejected")[1].params;
  assert.equal(live.reason.code, "busy");
  assert.equal(live.seq, 2);
  a.notify("chat.resume", { conversation: "c2", after: 0 });
  await until(() => a.replays().some((r) => r.done));
  assert.deepEqual(a.replays()[0].events.map((e) => [e.seq, e.method]), [[1, "chat.message"], [2, "chat.rejected"]]);
  // (the malformed message isn't logged, but what the page was told about it is)
  a.notify("chat.resume", { conversation: "c1", after: 0 });
  await until(() => a.replays().length === 2);
  assert.deepEqual(a.replays()[1].events.map((e) => [e.seq, e.method, e.params.reason.code]), [[1, "chat.rejected", "malformed"]]);
  server.queuedCount = 0;
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

test("resume: a long log (under its 2 MiB bound) comes in several replays, each under the limit, in order", async () => {
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
  for (const m of a.msgs.filter((m) => m.method === "chat.replay")) assert.ok(Buffer.byteLength(JSON.stringify(m)) <= 1024 * 1024 + 70_000);
  assert.deepEqual(rs.flatMap((r) => r.events).map((e) => e.seq), Array.from({ length: 30 }, (_, i) => i + 1));
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
  for (const l of lines) assert.ok(Buffer.byteLength(l) + 1 <= frame, `a line of ${Buffer.byteLength(l)} bytes`);
  const events = lines.flatMap((l) => JSON.parse(l).params.events);
  assert.deepEqual(events.map((e) => e.seq), [1, 2, 3, 4, 5, 6, 7]);
  assert.ok(events[6].params.omitted.bytes > frame - 200);
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
