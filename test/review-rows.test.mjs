// Rows the TESTS review asked for, one per surviving mutant: each makes its claim observable.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { EventEmitter } from "node:events";
import { fileURLToPath } from "node:url";
import { stdinChunks, CHUNK } from "../lib/stdio.mjs";
import { fakeCreateServer, fakeQuery } from "../lib/fake.mjs";
import { AgentServer, TEXT } from "../lib/server.mjs";
import { permissionDigest } from "../lib/canon.mjs";

const BIN = fileURLToPath(new URL("../bin/sagebrush-agent.mjs", import.meta.url));
const run = (args, { input } = {}) => new Promise((resolve) => {
  const p = spawn(process.execPath, [BIN, ...args], { env: { ...process.env, SAGEBRUSH_AGENT_FAKE: "1" }, stdio: ["pipe", "pipe", "pipe"] });
  let err = "";
  p.stderr.on("data", (d) => { err += d; });
  const t = setTimeout(() => p.kill("SIGKILL"), 10000);
  p.on("exit", (code, sig) => { clearTimeout(t); resolve({ code, sig, err }); });
  if (input) input(p);
});

test("stdinChunks: a chunk over 64 KiB reaches the reader in pieces of at most 64 KiB, in order, nothing lost; end, close and error pass through", () => {
  const src = new EventEmitter();
  const out = stdinChunks(src);
  const got = [], ends = [];
  out.on("data", (b) => got.push(b));
  for (const e of ["end", "close", "error"]) out.on(e, () => ends.push(e));
  const big = Buffer.alloc(3 * CHUNK + 123, 0x61);
  for (let i = 0; i < big.length; i++) big[i] = i % 251;
  src.emit("data", big);
  src.emit("data", Buffer.from("tail"));
  assert.ok(got.every((b) => b.length <= CHUNK), `largest ${Math.max(...got.map((b) => b.length))}`);
  assert.deepEqual(got.map((b) => b.length), [CHUNK, CHUNK, CHUNK, 123, 4]);
  assert.ok(Buffer.concat(got).equals(Buffer.concat([big, Buffer.from("tail")])));
  src.emit("end"); src.emit("close"); src.emit("error", new Error("x"));
  assert.deepEqual(ends, ["end", "close", "error"]);
});

test("--stdio with --port or --origin is refused (exit 2, with why)", async () => {
  for (const extra of [["--port", "8123"], ["--origin", "https://example.org"]]) {
    const r = await run(["--stdio", ...extra]);
    assert.equal(r.code, 2, extra.join(" "));
    assert.match(r.err, /--stdio can't be used with --port or --origin/);
  }
});

test("an stdout that fails (the runner went away) stops the agent", async () => {
  const r = await run(["--stdio"], {
    input: (p) => {
      p.stdout.destroy(); // (the read end goes: the agent's next write fails)
      p.stdin.write(JSON.stringify({ relay: { start: { frame: 65536, protocol: 1, epoch: 0 } } }) + "\n");
    },
  });
  assert.deepEqual([r.code, r.sig], [0, null], r.err);
});

// A server with a page bound, no transport.
function bound() {
  const server = new AgentServer({ query: fakeQuery, log: () => {}, stdio: true });
  server.createServer = fakeCreateServer;
  const ws = { readyState: 1, send() { return "ok"; } };
  server.sock = ws;
  server.binding = { ws, grant: { folders: ["/"], write: true }, gen: 1 };
  return server;
}

test("an answer without behavior \"allow\" exactly is a denial, even with the right digest", async () => {
  for (const behavior of [undefined, "Allow", "ALLOW", "yes", true, 1]) {
    const server = bound();
    let card;
    const verdict = server.askPerson(server.binding, (d) => { card = d[0]; }, "WebSearch", { query: "q" }, {}, "c1");
    const digest = permissionDigest({ child: card.child, conversation: card.conversation, request: card.request_id, tool: card.action.tool, input: card.action.input });
    server.notification("chat.permission", { request_id: card.id, ...(behavior === undefined ? {} : { behavior }), digest });
    assert.equal((await verdict).behavior, "deny", JSON.stringify(behavior));
    await server.close();
  }
  // (and the control: exactly "allow" with that digest is allowed)
  const server = bound();
  let card;
  const verdict = server.askPerson(server.binding, (d) => { card = d[0]; }, "WebSearch", { query: "q" }, {}, "c1");
  server.notification("chat.permission", { request_id: card.id, behavior: "allow", digest: permissionDigest({ child: card.child, conversation: card.conversation, request: card.request_id, tool: card.action.tool, input: card.action.input }) });
  assert.equal((await verdict).behavior, "allow");
  await server.close();
});

test("a control line whose epoch isn't an integer is ignored: the binding stays", async () => {
  const logs = [];
  const server = new AgentServer({ query: fakeQuery, log: (m) => logs.push(m), stdio: true });
  server.createServer = fakeCreateServer;
  const input = new EventEmitter();
  const out = Object.assign(new EventEmitter(), { writableHighWaterMark: 1 << 20, writableLength: 0, write() { return true; } });
  server.serveStdio({ input, output: out, fatal: (t) => logs.push("FATAL " + t) });
  const send = (o) => input.emit("data", Buffer.from(JSON.stringify(o) + "\n"));
  send({ relay: { start: { frame: 65536, protocol: 1, epoch: 0 } } });
  const sock = server.sock;
  for (const epoch of [1.5, "1", null, -1.5, 2 ** 53]) {
    send({ relay: { page: "detached", epoch } });
    send({ relay: { page: "attached", epoch } });
  }
  assert.equal(server.sock, sock, "the same page is attached");
  assert.equal(server.epoch, 0);
  assert.ok(!logs.some((l) => l.startsWith("FATAL")));
  await server.close();
});
