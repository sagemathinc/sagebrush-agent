// Rows the TESTS review of r2 asked for: exact counts for control characters and lone surrogates, the conversation
// cap never taking a running conversation, and the notebook reads cap.
import { test } from "node:test";
import assert from "node:assert/strict";
import { jsonBytes } from "../lib/canon.mjs";
import { fakeCreateServer, fakeQuery } from "../lib/fake.mjs";
import { AgentServer } from "../lib/server.mjs";

const exact = (v) => Buffer.byteLength(JSON.stringify(v));

test("jsonBytes: control characters count as JSON.stringify writes them (\\b\\t\\n\\f\\r as 2, the rest as 6), as keys and as values", () => {
  for (let c = 0; c < 0x20; c++) {
    const ch = String.fromCharCode(c);
    for (const v of [ch, "a" + ch + "b", { [ch]: 1 }, { k: ch.repeat(3) }, [ch]]) {
      assert.equal(jsonBytes(v, 1 << 20), exact(v), `U+${c.toString(16).padStart(4, "0")} in ${JSON.stringify(v)}`);
    }
  }
});

test("jsonBytes: lone surrogates count as 6 (\\udxxx), a pair as 4: lone high, lone low, and one at the end", () => {
  const cases = ["\ud800", "\udc00", "\udbff", "\udfff", "a\ud800b", "x\udc00", "ab\ud83d", "😀", "\ude00\ud83d", "\ud83d😀"];
  for (const s of cases) {
    for (const v of [s, { [s]: s }, [s, s]]) assert.equal(jsonBytes(v, 1 << 20), exact(v), JSON.stringify(v));
  }
});

test("the 64-conversation cap never takes a running conversation: with the least recently used one running, the 65th evicts an idle one", async () => {
  const server = new AgentServer({ query: fakeQuery, log: () => {}, stdio: true });
  server.createServer = fakeCreateServer;
  for (let i = 0; i < 64; i++) server.conversation(`c${i}`);
  server.conversations.get("c0").running = { binding: null, cancel() {} }; // (the oldest is running)
  server.conversations.get("c1").queue.push({ text: "waiting" }); // (and the next has a message waiting)
  server.conversation("c64");
  assert.equal(server.conversations.size, 64);
  assert.ok(server.conversations.has("c0"), "the running one stays");
  assert.ok(server.conversations.has("c1"), "the one with a queued message stays");
  assert.equal(server.conversations.has("c2"), false, "the oldest idle one goes");
  server.conversations.get("c0").running = null;
  server.conversations.get("c1").queue.length = 0;
  await server.close();
});

test("a conversation keeps reads of at most 32 notebooks: the 33rd drops the one read least long ago", async () => {
  const server = new AgentServer({ query: fakeQuery, log: () => {}, stdio: true });
  server.createServer = fakeCreateServer;
  const binding = { ws: { readyState: 1, send() { return "ok"; } }, grant: { folders: ["/"], write: true }, features: ["notebook.edit"] };
  server.binding = binding;
  server.sock = binding.ws;
  const c = server.conversation("c1");
  const tools = server.workspaceTools("c1", c, binding, undefined);
  const read = tools.handlers.workspace_read; // (the fake createServer keeps the handlers by name)
  // (the page's answer to a notebook read: a ref, a rev and cells)
  server.request = async (_b, method, params) => ({ ref: `r-${params.path}`, rev: 1, content: { json: { cells: [{ id: "a", cell_type: "code", source: "1" }], metadata: {}, nbformat: 4, nbformat_minor: 5 } } });
  for (let i = 0; i < 33; i++) await read({ path: `/n${i}.ipynb` });
  assert.equal(c.reads.size, 32);
  assert.equal(c.reads.has("/n0.ipynb"), false, "the least recent dropped");
  assert.ok(c.reads.has("/n32.ipynb"));
  await read({ path: "/n1.ipynb" }); // (read again: the most recent now)
  await read({ path: "/n33.ipynb" });
  assert.ok(c.reads.has("/n1.ipynb"), "a notebook read again moves to the end");
  assert.equal(c.reads.has("/n2.ipynb"), false);
  await server.close();
});
