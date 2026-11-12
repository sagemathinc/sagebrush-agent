// The permission digest: an Allow counts only with the digest of the very action asked about, computed by the agent
// from its own pending action (never from the answer). The card carries the action and the identities, never a digest.
import assert from "node:assert/strict";
import { test } from "node:test";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import WebSocket from "ws";
import { fakeCreateServer, fakeQuery } from "../lib/fake.mjs";
import { AgentServer, TEXT } from "../lib/server.mjs";
import { permissionDigest } from "../lib/canon.mjs";

const ORIGIN = "https://agents.sagebrush.cloud";
const GRANT = { folders: ["/"], write: true, expires: null };

async function paired({ features = ["notebook.edit", "permission.digest"] } = {}) {
  const logs = [];
  const server = new AgentServer({ query: fakeQuery, log: (m) => logs.push(m) });
  server.createServer = fakeCreateServer;
  const port = await server.listen();
  const code = server.newCode();
  const ws = new WebSocket(`ws://127.0.0.1:${port}/sagebrush`, { origin: ORIGIN });
  const events = [];
  let hello;
  ws.on("message", (d) => {
    const m = JSON.parse(d.toString());
    if (m.id === "p1") hello = m;
    else if (m.method === "turn.event") events.push(m.params.event);
    else if (typeof m.id === "string" && m.method) {
      const result = m.method === "workspace.stat" ? { entry: null } : m.method === "workspace.list" ? { entries: [] } : { entry: { path: m.params.path }, rev: 1 };
      ws.send(JSON.stringify({ jsonrpc: "2.0", id: m.id, result }));
    }
  });
  await new Promise((r, j) => { ws.on("open", r); ws.on("error", j); });
  const notify = (method, params) => ws.send(JSON.stringify({ jsonrpc: "2.0", method, params }));
  ws.send(JSON.stringify({ jsonrpc: "2.0", id: "p1", method: "hello", params: { protocol: 1, code, page: { origin: ORIGIN, path: "/agents/" } } }));
  await until(() => hello);
  notify("grant.changed", GRANT);
  if (features) notify("page.features", { features });
  return { server, ws, events, notify, logs, hello, close: async () => { ws.close(); await server.close(); } };
}

const until = async (f, ms = 8000) => {
  const t = Date.now();
  while (!f()) {
    if (Date.now() - t > ms) throw new Error("timed out");
    await new Promise((r) => setTimeout(r, 10));
  }
};

// Ask one question (the fake model's search), answer it with `answer(card)`, and say what the model was told.
async function ask(p, answer) {
  p.notify("chat.message", { conversation: "c1", id: `u${Date.now()}`, author: "person", text: "please search for primes" });
  await until(() => p.events.some((e) => e.type === "attention" && e.state === "open"));
  const card = p.events.find((e) => e.type === "attention" && e.state === "open");
  p.notify("chat.permission", { request_id: card.id, ...answer(card) });
  await until(() => p.events.some((e) => e.type === "turn_finished"));
  const said = p.events.filter((e) => e.type === "text_delta").map((e) => e.text).join("");
  return { card, allowed: /You allowed the search/.test(said), denied: /You said no to the search/.test(said) };
}

// The page's side, as B will do it: the digest of the action it shows.
const pageDigest = (card, action = card.action) => permissionDigest({ child: card.child, conversation: card.conversation, request: card.request_id, tool: action.tool, input: action.input });

test("the card: the action, the child, the conversation and the request id; never a digest", async () => {
  const p = await paired();
  try {
    const { card, allowed } = await ask(p, (c) => ({ behavior: "allow", digest: pageDigest(c) }));
    assert.equal(allowed, true, "an Allow with the right digest is allowed");
    assert.deepEqual(card.action, { tool: "WebSearch", input: { query: "please search for primes" } });
    assert.equal(card.child, p.hello.result.child);
    assert.equal(card.conversation, "c1");
    assert.equal(card.request_id, card.id);
    assert.equal("digest" in card, false);
  } finally { await p.close(); }
});

test("R1: the shown action rewritten, the digest of what was shown: denied, and the runner's log says why", async () => {
  const p = await paired();
  try {
    const { allowed, denied } = await ask(p, (c) => ({ behavior: "allow", digest: pageDigest(c, { ...c.action, input: { query: "something harmless" } }) }));
    assert.deepEqual([allowed, denied], [false, true]);
    assert.ok(p.logs.includes(TEXT.mismatch));
  } finally { await p.close(); }
});

test("R2: action and digest both replaced (a digest that matches another action): denied, and the question is settled", async () => {
  const p = await paired();
  try {
    let card0;
    const { denied } = await ask(p, (c) => { card0 = c; return { behavior: "allow", digest: pageDigest(c, { tool: "WebFetch", input: { url: "https://evil.example" } }) }; });
    assert.equal(denied, true);
    // (the question is gone: a second answer, even the right one, changes nothing)
    p.notify("chat.permission", { request_id: card0.id, behavior: "allow", digest: pageDigest(card0) });
    await new Promise((r) => setTimeout(r, 200));
    assert.equal(p.events.filter((e) => e.type === "attention" && e.state === "approved").length, 0);
  } finally { await p.close(); }
});

test("R3: a digest computed for another child (a stale answer from before a restart): denied", async () => {
  const p = await paired();
  try {
    const { denied } = await ask(p, (c) => ({ behavior: "allow", digest: permissionDigest({ child: "an-earlier-child", conversation: c.conversation, request: c.request_id, tool: c.action.tool, input: c.action.input }) }));
    assert.equal(denied, true);
  } finally { await p.close(); }
});

test("an Allow with no digest, or a wrong-length one, is denied once the page sends digests; a Deny needs none", async () => {
  for (const answer of [{ behavior: "allow" }, { behavior: "allow", digest: "short" }, { behavior: "allow", digest: 42 }]) {
    const p = await paired();
    try { assert.equal((await ask(p, () => answer)).denied, true, JSON.stringify(answer)); } finally { await p.close(); }
  }
  const p = await paired();
  try { assert.equal((await ask(p, () => ({ behavior: "deny" }))).denied, true); } finally { await p.close(); }
});

test("the mode rule: over loopback, a page that doesn't send page.features with permission.digest keeps 0.3's answers", async () => {
  const p = await paired({ features: null });
  try { assert.equal((await ask(p, () => ({ behavior: "allow" }))).allowed, true); } finally { await p.close(); }
});

test("an action canon can't show exactly is denied before any card, with board's text to the model", async () => {
  const logs = [];
  const server = new AgentServer({ query: fakeQuery, log: (m) => logs.push(m) });
  const binding = { ws: { readyState: 1, send() {} }, grant: GRANT };
  server.binding = binding;
  const sent = [];
  for (const input of [{ n: 1.5 }, { deep: JSON.parse("[".repeat(40) + "]".repeat(40)) }, { s: "x".repeat(20000) }]) {
    const r = await server.askPerson(binding, (d) => sent.push(d), "WebFetch", input, {}, "c1");
    assert.deepEqual(r, { behavior: "deny", message: TEXT.notReviewable }, JSON.stringify(input).slice(0, 40));
  }
  assert.equal(sent.length, 0, "no card was shown");
  await server.close();
});

test("with --stdio the digest is required without any page.features: the real process, an Allow without one is denied", async () => {
  const BIN = fileURLToPath(new URL("../bin/sagebrush-agent.mjs", import.meta.url));
  const p = spawn(process.execPath, [BIN, "--stdio"], { env: { ...process.env, SAGEBRUSH_AGENT_FAKE: "1" }, stdio: ["pipe", "pipe", "pipe"] });
  const lines = [];
  let buf = "", err = "";
  p.stdout.on("data", (d) => { buf += d; let i; while ((i = buf.indexOf("\n")) >= 0) { lines.push(JSON.parse(buf.slice(0, i))); buf = buf.slice(i + 1); } });
  p.stderr.on("data", (d) => { err += d; });
  const send = (o) => p.stdin.write(JSON.stringify(o) + "\n");
  try {
    send({ relay: { start: { frame: 65536, protocol: 1, epoch: 0 } } });
    send({ jsonrpc: "2.0", method: "grant.changed", params: GRANT });
    const answered = new Set();
    const iv = setInterval(() => { for (const m of lines) if (typeof m.id === "string" && m.method && !answered.has(m.id)) { answered.add(m.id); send({ jsonrpc: "2.0", id: m.id, result: m.method === "workspace.stat" ? { entry: null } : { entries: [], rev: 1 } }); } }, 5);
    send({ jsonrpc: "2.0", method: "chat.message", params: { conversation: "c1", id: "u1", author: "person", text: "please search" } });
    const ev = () => lines.filter((m) => m.method === "turn.event").map((m) => m.params.event);
    await until(() => ev().some((e) => e.type === "attention" && e.state === "open"));
    const card = ev().find((e) => e.type === "attention");
    send({ jsonrpc: "2.0", method: "chat.permission", params: { request_id: card.id, behavior: "allow" } });
    await until(() => ev().some((e) => e.type === "turn_finished"));
    clearInterval(iv);
    assert.match(ev().filter((e) => e.type === "text_delta").map((e) => e.text).join(""), /said no to the search/);
    assert.ok(err.includes(TEXT.mismatch));
  } finally { p.kill("SIGKILL"); }
});
