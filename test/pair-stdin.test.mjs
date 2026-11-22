// --pair-stdin, the desktop app's launch (lib/pair-stdin.mjs): the app's own origin only, the app's code over stdin
// (exact, single use, never printed), one stdout line with the port, and the end of stdin stops the agent. The parsing
// rows run in-process; the program's rows start the real bin with the fake model (no Anthropic calls).
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { EventEmitter } from "node:events";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import WebSocket from "ws";
import { PAIR_LINE_MAX, pairOrigin, parsePairLine, readPairLine } from "../lib/pair-stdin.mjs";
import { AgentServer } from "../lib/server.mjs";
import { fakeQuery } from "../lib/fake.mjs";

const BIN = fileURLToPath(new URL("../bin/sagebrush-agent.mjs", import.meta.url));
const APP = "http://127.0.0.1:41234"; // (the app page's origin; nothing listens there: the agent only compares it)
const newCode = () => randomBytes(32).toString("base64url");
const line = (o) => Buffer.from(JSON.stringify(o));

test("pairOrigin: only http://127.0.0.1:<1-65535>, written canonically", () => {
  for (const ok of ["http://127.0.0.1:1", "http://127.0.0.1:8080", "http://127.0.0.1:65535"]) assert.equal(pairOrigin(ok), ok, ok);
  for (const bad of ["http://127.0.0.1", "http://127.0.0.1:0", "http://127.0.0.1:65536", "http://127.0.0.1:080", "http://127.0.0.1:80/", "http://localhost:8080",
    "https://127.0.0.1:8080", "http://127.0.0.2:8080", "http://[::1]:8080", "https://sagebrush.space", "null", "", "http://127.0.0.1:8080/agents", "http://user@127.0.0.1:8080"])
    assert.equal(pairOrigin(bad), null, bad);
});

test("parsePairLine: exactly {v:1, pair: base64url of 32 bytes}, nothing else", () => {
  const c = newCode();
  assert.equal(parsePairLine(line({ v: 1, pair: c })), c);
  assert.equal(parsePairLine(line({ pair: c, v: 1 })), c);
  for (const [what, b] of [
    ["v 2", line({ v: 2, pair: c })],
    ["v a string", line({ v: "1", pair: c })],
    ["an extra key", line({ v: 1, pair: c, port: 1 })],
    ["no pair", line({ v: 1 })],
    ["16 bytes", line({ v: 1, pair: randomBytes(16).toString("base64url") })],
    ["padded base64", line({ v: 1, pair: randomBytes(32).toString("base64") })],
    ["non-canonical last character", line({ v: 1, pair: c.slice(0, 42) + (c[42] === "B" ? "C" : "B") })],
    ["an array", line([1, c])],
    ["not JSON", Buffer.from(`v=1 pair=${c}`)],
    ["too long", Buffer.from(JSON.stringify({ v: 1, pair: c }) + " ".repeat(PAIR_LINE_MAX))],
  ]) assert.equal(parsePairLine(b), null, what);
});

function stream() { return new EventEmitter(); }

test("readPairLine: a line in pieces; then the end of stdin, or more input, is reported once", async () => {
  const c = newCode();
  const s = stream();
  const after = [];
  const p = readPairLine(s, { onAfter: (w) => after.push(w) });
  const b = Buffer.from(JSON.stringify({ v: 1, pair: c }) + "\n");
  s.emit("data", b.subarray(0, 10));
  s.emit("data", b.subarray(10));
  assert.equal(await p, c);
  s.emit("data", Buffer.from("x"));
  s.emit("end");
  assert.deepEqual(after, ["data"]);
  const s2 = stream(), after2 = [];
  const p2 = readPairLine(s2, { onAfter: (w) => after2.push(w) });
  s2.emit("data", b);
  await p2;
  s2.emit("end");
  s2.emit("close");
  assert.deepEqual(after2, ["end"]);
});

test("readPairLine: refused with a fixed message, never the input: too long, a bad line, bytes after it, an early end, no line in time", async () => {
  const c = newCode();
  const cases = [
    ["too long", (s) => s.emit("data", Buffer.alloc(PAIR_LINE_MAX + 1, 0x41)), /too long/],
    ["too long in pieces", (s) => { s.emit("data", Buffer.alloc(200, 0x41)); s.emit("data", Buffer.alloc(100, 0x41)); }, /too long/],
    // (a character outside base64url: always invalid, whatever the random code)
    ["bad line", (s) => s.emit("data", Buffer.from(JSON.stringify({ v: 1, pair: c.slice(0, 42) + "!" }) + "\n")), /not a valid one/],
    ["bytes after the line", (s) => s.emit("data", Buffer.from(JSON.stringify({ v: 1, pair: c }) + "\nmore")), /after the pairing line/],
    ["early end", (s) => s.emit("end"), /ended before/],
  ];
  for (const [what, feed, why] of cases) {
    const s = stream();
    const p = readPairLine(s);
    feed(s);
    await assert.rejects(p, (e) => why.test(e.message) && !e.message.includes(c) && !e.message.includes("AAAA"), what);
  }
  await assert.rejects(readPairLine(stream(), { waitMs: 50 }), /in time/);
});

test("the server with the app's code: exact (case matters), single use, no TTL, no new codes, no localhost Host", async () => {
  const c = newCode();
  const server = new AgentServer({ origins: [APP], query: fakeQuery, log: () => {} });
  server.setAppCode(c);
  assert.throws(() => server.newCode(), /only with the code its app gave it/);
  assert.throws(() => server.setAppCode(newCode()), /set once/);
  const port = await server.listen();
  try {
    const hello = (code, { origin = APP, host } = {}) => new Promise((resolve) => {
      const ws = new WebSocket(`ws://127.0.0.1:${port}/sagebrush`, { origin, ...(host ? { headers: { host } } : {}) });
      ws.on("unexpected-response", (_req, res) => resolve({ status: res.statusCode }));
      ws.on("error", () => {});
      ws.on("open", () => ws.send(JSON.stringify({ jsonrpc: "2.0", id: "p1", method: "hello", params: { protocol: 1, page: { origin, path: "/agents/" }, code } })));
      ws.on("message", (d) => { const m = JSON.parse(d.toString()); if (m.id === "p1") resolve({ m, ws }); });
    });
    assert.equal((await hello(c, { host: `localhost:${port}` })).status, 403, "a localhost Host header");
    assert.equal((await hello(c, { origin: "https://sagebrush.space" })).status, 403, "a default origin");
    const lower = await hello(c.toLowerCase() === c ? c.toUpperCase() : c.toLowerCase());
    assert.equal(lower.m.error?.data?.code, "refused", "another case is another code");
    assert.match(lower.m.error.data.message, /connect again from the app/);
    const ok = await hello(c);
    assert.ok(ok.m.result?.session, "the app's code pairs");
    ok.ws.close();
    await new Promise((r) => setTimeout(r, 100));
    const replay = await hello(c);
    assert.equal(replay.m.error?.data?.code, "refused", "the code is spent");
    replay.ws.close();
  } finally {
    await server.close();
  }
});

// The program: started as the app starts it.
function launch(args, { env = {} } = {}) {
  const home = mkdtempSync(join(tmpdir(), "sb-pair-"));
  const p = spawn(process.execPath, [BIN, ...args], { env: { ...process.env, SAGEBRUSH_AGENT_FAKE: "1", SAGEBRUSH_TASKS_HOME: home, ...env }, stdio: ["pipe", "pipe", "pipe"] });
  let out = "", err = "";
  p.stdout.on("data", (d) => { out += d; });
  p.stderr.on("data", (d) => { err += d; });
  const exited = new Promise((resolve) => p.on("exit", (code) => resolve(code)));
  const cleanup = () => { try { p.kill("SIGKILL"); } catch {} rmSync(home, { recursive: true, force: true }); };
  return { p, exited, out: () => out, err: () => err, cleanup };
}
const firstLine = (l, ms = 15000) => new Promise((resolve, reject) => {
  const t0 = Date.now();
  const tick = () => {
    const o = l.out();
    if (o.includes("\n")) return resolve(o);
    if (Date.now() - t0 > ms) return reject(new Error(`no stdout line; stderr: ${l.err().slice(-400)}`));
    setTimeout(tick, 20);
  };
  tick();
});

test("the program refuses a launch that isn't the app's: wrong flags exit 2 before reading stdin", async () => {
  for (const args of [
    ["--pair-stdin", "--port", "0"],
    ["--pair-stdin", "--origin", APP],
    ["--pair-stdin", "--origin", APP, "--port", "5000"],
    ["--pair-stdin", "--origin", APP, "--origin", "http://127.0.0.1:41235", "--port", "0"],
    ["--pair-stdin", "--origin", "http://localhost:41234", "--port", "0"],
    ["--pair-stdin", "--origin", "https://sagebrush.space", "--port", "0"],
    ["--pair-stdin", "--origin", APP, "--port", "0", "--codex"],
    ["--pair-stdin", "--origin", APP, "--port", "0", "--stdio"],
  ]) {
    const l = launch(args);
    try {
      assert.equal(await l.exited, 2, args.join(" "));
      assert.equal(l.out(), "", "nothing on stdout");
    } finally { l.cleanup(); }
  }
});

test("the program refuses a bad pairing line: exit 2, nothing on stdout, the line never echoed", async () => {
  const c = newCode();
  for (const bad of [JSON.stringify({ v: 1, pair: c.slice(1) }) + "\n", JSON.stringify({ v: 1, pair: c }) + "\nextra", ""]) {
    const l = launch(["--pair-stdin", "--origin", APP, "--port", "0"]);
    try {
      l.p.stdin.end(bad);
      assert.equal(await l.exited, 2);
      assert.equal(l.out(), "");
      assert.ok(!l.err().includes(c) && !l.err().includes(c.slice(1)), "the code is not in stderr");
    } finally { l.cleanup(); }
  }
});

test("the program as the app runs it: one stdout line with the port, the app's code pairs once, nothing else on stdout, the end of stdin stops it", async () => {
  const c = newCode();
  const l = launch(["--pair-stdin", "--origin", APP, "--port", "0"]);
  try {
    l.p.stdin.write(JSON.stringify({ v: 1, pair: c }) + "\n");
    const o = await firstLine(l);
    const m = /^\{"v":1,"listening":(\d+)\}\n$/.exec(o);
    assert.ok(m, `exactly the port line: ${JSON.stringify(o.slice(0, 80))}`);
    const port = Number(m[1]);
    const hello = (code, origin = APP) => new Promise((resolve) => {
      const ws = new WebSocket(`ws://127.0.0.1:${port}/sagebrush`, { origin });
      ws.on("unexpected-response", (_req, res) => resolve({ status: res.statusCode }));
      ws.on("error", () => {});
      ws.on("open", () => ws.send(JSON.stringify({ jsonrpc: "2.0", id: "p1", method: "hello", params: { protocol: 1, page: { origin, path: "/agents/" }, code } })));
      ws.on("message", (d) => { const x = JSON.parse(d.toString()); if (x.id === "p1") resolve({ m: x, ws }); });
    });
    assert.equal((await hello(c, "https://sagebrush.space")).status, 403, "a default origin is refused");
    assert.equal((await hello(c, "http://127.0.0.1:41235")).status, 403, "another port's origin is refused");
    const ok = await hello(c);
    assert.ok(ok.m.result?.session, "paired");
    ok.ws.close();
    await new Promise((r) => setTimeout(r, 200));
    const replay = await hello(c);
    assert.equal(replay.m.error?.data?.code, "refused", "the code works once");
    replay.ws.close();
    await new Promise((r) => setTimeout(r, 200));
    assert.equal(l.out(), o, "nothing more on stdout: no link, no code");
    assert.ok(!l.err().includes(c), "the code is not in stderr");
    l.p.stdin.end();
    assert.equal(await Promise.race([l.exited, new Promise((r) => setTimeout(() => r("still running"), 10000))]), 0, "the end of stdin stops it");
  } finally { l.cleanup(); }
});

test("the program stops on input after the pairing line (a broken launch), exit 1", async () => {
  const l = launch(["--pair-stdin", "--origin", APP, "--port", "0"]);
  try {
    l.p.stdin.write(JSON.stringify({ v: 1, pair: newCode() }) + "\n");
    await firstLine(l);
    l.p.stdin.write("more\n");
    assert.equal(await Promise.race([l.exited, new Promise((r) => setTimeout(() => r("still running"), 10000))]), 1);
  } finally { l.cleanup(); }
});
