// The daemon end to end with a fake page (a WebSocket client playing the
// page's side of the protocol) and the fake model. No Anthropic calls.
import assert from "node:assert/strict";
import { test } from "node:test";
import WebSocket from "ws";
import { fakeCreateServer, fakeQuery } from "../lib/fake.mjs";
import { AgentServer } from "../lib/server.mjs";
import { Turn } from "../lib/turns.mjs";

const ORIGIN = "https://agents.sagebrush.cloud";

async function start(opts = {}) {
  const server = new AgentServer({ query: fakeQuery, log: () => {}, ...opts });
  server.createServer = fakeCreateServer;
  const port = await server.listen();
  return { server, port, code: server.newCode() };
}

function page(port, origin = ORIGIN, { hold = false, big = 0 } = {}) {
  const ws = new WebSocket(`ws://127.0.0.1:${port}/sagebrush`, { origin });
  const files = new Map();
  const events = [];
  const answers = new Map();
  ws.on("message", (d) => {
    const m = JSON.parse(d.toString());
    if (m.id === "p1") return answers.get("p1")?.(m);
    if (m.method === "turn.event") return events.push(m.params);
    if (typeof m.id === "string" && m.method) {
      if (hold) return; // (a page that never answers)
      const p = m.params;
      let result;
      if (m.method === "workspace.stat") result = files.has(p.path) ? { entry: { path: p.path } } : { entry: null };
      else if (m.method === "workspace.create" || m.method === "workspace.write") { files.set(p.path, p.content.text); result = { entry: { path: p.path }, rev: 1 }; }
      else if (m.method === "workspace.list") result = { entries: [...files.keys()].map((path) => ({ path, kind: "file" })), ...(big ? { padding: "x".repeat(big) } : {}) };
      else result = {};
      ws.send(JSON.stringify({ jsonrpc: "2.0", id: m.id, result }));
    }
  });
  const requests = [];
  ws.on("message", (d) => { const m = JSON.parse(d.toString()); if (typeof m.id === "string" && m.method) requests.push(m.method); });
  const hello = (params) =>
    new Promise((resolve) => {
      answers.set("p1", resolve);
      ws.send(JSON.stringify({ jsonrpc: "2.0", id: "p1", method: "hello", params: { protocol: 1, page: { origin: ORIGIN, path: "/agents/" }, ...params } }));
    });
  const notify = (method, params) => ws.send(JSON.stringify({ jsonrpc: "2.0", method, params }));
  const open = new Promise((resolve, reject) => { ws.on("open", resolve); ws.on("error", reject); });
  const closed = new Promise((resolve) => ws.on("close", (code) => resolve(code)));
  return { ws, files, events, requests, hello, notify, open, closed };
}

const until = async (f, ms = 5000) => {
  const t = Date.now();
  while (!f()) {
    if (Date.now() - t > ms) throw new Error("timed out");
    await new Promise((r) => setTimeout(r, 20));
  }
};

test("a turn: pairing, grant, streamed text, a workspace write through the page, an artifact, the end", async () => {
  const { server, port, code } = await start();
  const p = page(port);
  await p.open;
  const h = await p.hello({ code: code.toLowerCase() });
  assert.equal(h.result.agent.client, "claude-agent-sdk");
  assert.ok(h.result.session);
  p.notify("grant.changed", { folders: ["/"], write: true, expires: null });
  p.notify("chat.message", { conversation: "c1", id: "u1", author: "person", text: "hello there" });
  await until(() => p.events.some((e) => e.event.type === "turn_finished"));
  const types = p.events.map((e) => e.event.type);
  assert.equal(types[0], "turn_started");
  assert.ok(types.includes("message_revised") && types.includes("text_delta"));
  const started = p.events.filter((e) => e.event.type === "tool_call_started").map((e) => e.event);
  assert.deepEqual(started.map((e) => e.name), ["workspace_write", "workspace_list"]);
  const finished = p.events.filter((e) => e.event.type === "tool_call_finished").map((e) => e.event);
  assert.deepEqual(finished.map((e) => e.status), ["ok", "ok"]);
  assert.match(p.files.get("/notes/fake-note.md"), /hello there/);
  const art = p.events.find((e) => e.event.type === "artifact").event;
  assert.equal(art.path, "/notes/fake-note.md");
  assert.equal(art.kind, "markdown");
  assert.equal(p.events.at(-1).event.outcome, "completed");
  assert.ok(new Set(p.events.map((e) => e.turn_id)).size === 1);
  p.ws.close();
  server.close();
});

test("an approval: asked in the chat, answered by the person", async () => {
  const { server, port, code } = await start();
  const p = page(port);
  await p.open;
  await p.hello({ code });
  p.notify("grant.changed", { folders: ["/"], write: true, expires: null });
  p.notify("chat.message", { conversation: "c1", id: "u1", author: "person", text: "please search for this" });
  await until(() => p.events.some((e) => e.event.type === "attention" && e.event.state === "open"));
  const ask = p.events.find((e) => e.event.type === "attention").event;
  // the card names the search's provider, never its terms (step 4, S6/P5), and carries the action it asks about
  assert.equal(ask.summary, "Anthropic");
  assert.deepEqual(JSON.parse(ask.detail), { provider: "Anthropic", reason: "" });
  assert.ok(!JSON.stringify(ask).includes("please search for this"), "the terms appear nowhere on the card");
  p.notify("chat.permission", { request_id: ask.id, behavior: "deny" });
  await until(() => p.events.some((e) => e.event.type === "turn_finished"));
  assert.ok(p.events.some((e) => e.event.type === "attention" && e.event.state === "denied"));
  const text = p.events.filter((e) => e.event.type === "text_delta").map((e) => e.event.text).join("");
  assert.match(text, /said no/);
  p.ws.close();
  server.close();
});

test("an interrupt ends the turn as interrupted", async () => {
  const { server, port, code } = await start();
  const p = page(port);
  await p.open;
  await p.hello({ code });
  p.notify("grant.changed", { folders: ["/"], write: true, expires: null });
  p.notify("chat.message", { conversation: "c1", id: "u1", author: "person", text: "x ".repeat(200) });
  await until(() => p.events.some((e) => e.event.type === "text_delta"));
  p.notify("chat.interrupt", { conversation: "c1" });
  await until(() => p.events.some((e) => e.event.type === "turn_finished"));
  assert.equal(p.events.at(-1).event.outcome, "interrupted");
  p.ws.close();
  server.close();
});

test("refusals: a wrong code, a reused code, a foreign origin, no grant", async () => {
  const { server, port, code } = await start();
  const bad = page(port);
  await bad.open;
  const r = await bad.hello({ code: "AAAA" });
  assert.equal(r.error.data.code, "refused");
  const ok = page(port);
  await ok.open;
  assert.ok((await ok.hello({ code })).result);
  ok.ws.close();
  await new Promise((r) => setTimeout(r, 50));
  const again = page(port);
  await again.open;
  assert.equal((await again.hello({ code })).error.data.code, "refused");
  const foreign = page(port, "https://evil.example");
  await assert.rejects(foreign.open);
  // no grant: a workspace call is refused, the turn still ends
  const s2 = await start();
  const p = page(s2.port);
  await p.open;
  await p.hello({ code: s2.code });
  p.notify("chat.message", { conversation: "c", id: "u", author: "person", text: "hi" });
  await until(() => p.events.some((e) => e.event.type === "turn_finished"));
  assert.ok(p.events.some((e) => e.event.type === "tool_call_finished" && e.event.status === "error"));
  p.ws.close();
  s2.server.close();
  server.close();
});

test("the real SDK accepts the workspace tools (built only, no Anthropic call)", async () => {
  const sdk = await import("@anthropic-ai/claude-agent-sdk");
  const server = new AgentServer({ query: () => null, log: () => {} });
  server.createServer = (spec) => sdk.createSdkMcpServer({ name: spec.name, version: spec.version, tools: spec.tools.map(([n, d, s, h]) => sdk.tool(n, d, s, h)) });
  const cfg = server.workspaceTools();
  assert.equal(cfg.type, "sdk");
  assert.equal(cfg.name, "sagebrush_page", "never \"sagebrush\", the person's own sagebrush-mcp's name (step 4, S8)");
  await server.close();
});

test("the mapper: a result with an error ends the turn as an error", () => {
  const t = new Turn("T", () => 0);
  const out = t.feed({ type: "result", subtype: "error_during_execution", is_error: true, usage: {} });
  assert.deepEqual(out.map((e) => e.type), ["turn_usage", "turn_error", "turn_finished"]);
  assert.equal(out.at(-1).outcome, "error");
  assert.deepEqual(t.interrupted(), []);
});

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const GRANT = { folders: ["/"], write: true, expires: null };

test("the SDK options: ask, never decide alone; only our MCP server; no settings from disk", async () => {
  let options;
  const { server, port, code } = await start({ query: (a) => { options = a.options; return fakeQuery(a); } });
  const p = page(port);
  await p.open;
  await p.hello({ code });
  p.notify("grant.changed", GRANT);
  p.notify("chat.message", { conversation: "c1", id: "u1", author: "person", text: "hi" });
  await until(() => p.events.some((e) => e.event.type === "turn_finished"));
  assert.equal(options.permissionMode, "default");
  assert.equal(options.strictMcpConfig, true);
  assert.deepEqual(options.settingSources, []);
  assert.deepEqual(options.tools, ["WebSearch"], "no built-in WebFetch: web_fetch is ours (step 4)");
  assert.deepEqual(options.settings.permissions.ask, ["WebSearch", "mcp__sagebrush_page__web_fetch", "mcp__sagebrush_page__workspace_rename", "mcp__sagebrush_page__workspace_remove"]);
  assert.equal(options.settings.permissions.disableAutoMode, "disable");
  assert.equal(options.settings.permissions.disableBypassPermissionsMode, "disable");
  // no bare allowedTools: every call reaches canUseTool (no SDK "shadowed" warning)
  assert.equal(options.allowedTools, undefined);
  for (const t of ["list", "read", "write", "mkdir"]) {
    const n = p.events.length;
    assert.deepEqual(await options.canUseTool(`mcp__sagebrush_page__workspace_${t}`, { path: "/a" }, {}), { behavior: "allow", updatedInput: { path: "/a" } });
    assert.equal(p.events.length, n); // (no question for these)
  }
  // under a later binding (the grant changed), the old turn's workspace calls are refused here too
  p.notify("grant.changed", { folders: ["/notes"], write: false, expires: null });
  await until(() => server.binding?.grant?.folders?.[0] === "/notes");
  assert.equal((await options.canUseTool("mcp__sagebrush_page__workspace_read", { path: "/a" }, {})).behavior, "deny");
  // a tool outside the ask list is refused without asking the person
  const before = p.events.length;
  const v = await options.canUseTool("Bash", { command: "ls" }, {});
  assert.equal(v.behavior, "deny");
  assert.equal(p.events.length, before);
  p.ws.close();
  await server.close();
});

test("removing a file asks the person; a no leaves the file", async () => {
  const { server, port, code } = await start();
  const p = page(port);
  await p.open;
  await p.hello({ code });
  p.notify("grant.changed", GRANT);
  p.notify("chat.message", { conversation: "c1", id: "u1", author: "person", text: "write it then remove it" });
  await until(() => p.events.some((e) => e.event.type === "attention" && e.event.state === "open"));
  const ask = p.events.find((e) => e.event.type === "attention").event;
  assert.equal(ask.title, "Allow workspace_remove?");
  p.notify("chat.permission", { request_id: ask.id, behavior: "deny" });
  await until(() => p.events.some((e) => e.event.type === "turn_finished"));
  assert.ok(!p.requests.includes("workspace.remove"));
  p.ws.close();
  await server.close();
});

test("a grant change cancels the running turn and its open question; nothing runs under the new grant", async () => {
  const { server, port, code } = await start();
  const p = page(port);
  await p.open;
  await p.hello({ code });
  p.notify("grant.changed", GRANT);
  p.notify("chat.message", { conversation: "c1", id: "u1", author: "person", text: "please search" });
  p.notify("chat.message", { conversation: "c1", id: "u2", author: "person", text: "queued after it" });
  await until(() => p.events.some((e) => e.event.type === "attention" && e.event.state === "open"));
  const ask = p.events.find((e) => e.event.type === "attention").event;
  const rejected = [];
  p.ws.on("message", (d) => { const m = JSON.parse(d.toString()); if (m.method === "chat.rejected") rejected.push(m.params); });
  const n = p.requests.length;
  p.notify("grant.changed", { folders: ["/notes"], write: false, expires: null });
  await until(() => p.events.some((e) => e.event.type === "turn_finished"));
  assert.equal(p.events.filter((e) => e.event.type === "turn_finished")[0].event.outcome, "interrupted");
  assert.ok(p.events.some((e) => e.event.type === "attention" && e.event.state === "denied"));
  // the old answer no longer counts, the queued message was dropped (and the page told), and no new work started
  p.notify("chat.permission", { request_id: ask.id, behavior: "allow" });
  await sleep(300);
  assert.deepEqual(rejected.map((r) => [r.id, r.reason.code]), [["u2", "cancelled"]]);
  assert.equal(new Set(p.events.map((e) => e.turn_id)).size, 1);
  assert.equal(p.requests.length, n);
  p.ws.close();
  await server.close();
});

test("a disconnect cancels the work; the page that comes back with the session doesn't get it", async () => {
  const { server, port, code } = await start();
  const p = page(port);
  await p.open;
  const h = await p.hello({ code });
  p.notify("grant.changed", GRANT);
  p.notify("chat.message", { conversation: "c1", id: "u1", author: "person", text: "please search" });
  p.notify("chat.message", { conversation: "c1", id: "u2", author: "person", text: "queued after it" });
  await until(() => p.events.some((e) => e.event.type === "attention" && e.event.state === "open"));
  p.ws.close();
  await p.closed;
  await until(() => server.sock === null); // (the agent has seen the page go: its close can come after the page's side)
  const q = page(port);
  await q.open;
  assert.ok((await q.hello({ session: h.result.session })).result);
  q.notify("grant.changed", GRANT);
  await sleep(400);
  assert.deepEqual(q.events, []);
  assert.deepEqual(q.requests, []);
  q.ws.close();
  await server.close();
});

test("two sockets let in before either hello: only the first to pair counts", async () => {
  const { server, port, code } = await start();
  const a = page(port);
  const b = page(port);
  await Promise.all([a.open, b.open]);
  const h = await a.hello({ code });
  assert.ok(h.result.session);
  const r = await b.hello({ session: h.result.session });
  assert.equal(r.error.data.code, "refused");
  // (said as another page, never as a wrong or spent code (A5): the page then waits for the other page, not a new code)
  assert.equal(r.error.data.message, "another page is paired with this agent");
  await b.closed;
  a.ws.close();
  await server.close();
});

test("before the hello: a big frame is cut off without buffering it, and a silent socket times out", async () => {
  const { server, port } = await start({ helloTimeoutMs: 300 });
  const big = page(port);
  await big.open;
  big.ws.send("x".repeat(64 * 1024));
  await big.closed;
  const silent = page(port);
  await silent.open;
  const t = Date.now();
  await silent.closed;
  assert.ok(Date.now() - t < 2000);
  await until(() => server.unpaired === 0);
  await server.close();
});

test("stopping deletes this run's transcripts and the working folder", async () => {
  const deleted = [];
  const { server, port, code } = await start({ deleteSession: async (id, o) => { deleted.push([id, o.dir]); } });
  const cwd = server.cwd;
  const p = page(port);
  await p.open;
  await p.hello({ code });
  p.notify("grant.changed", GRANT);
  p.notify("chat.message", { conversation: "c1", id: "u1", author: "person", text: "hi" });
  await until(() => p.events.some((e) => e.event.type === "turn_finished"));
  p.ws.close();
  await server.close();
  assert.equal(deleted.length, 1);
  assert.match(deleted[0][0], /^fake-/);
  assert.equal(deleted[0][1], cwd);
  const { existsSync } = await import("node:fs");
  assert.equal(existsSync(cwd), false);
});

test("approvals: a request too large to review is refused without asking; an answer covers exactly the shown arguments", async () => {
  let options;
  const { server, port, code } = await start({ query: (a) => { options = a.options; return fakeQuery(a); } });
  const p = page(port);
  await p.open;
  await p.hello({ code });
  p.notify("grant.changed", GRANT);
  p.notify("chat.message", { conversation: "c1", id: "u1", author: "person", text: "hi" });
  await until(() => p.events.some((e) => e.event.type === "turn_finished"));
  const before = p.events.length;
  // (step 4: the turn has ended, so no web request is released, and none is asked about (S5); the card, its sanitized
  //  action and the exact request it binds are rows of test/step4-server.test.mjs)
  for (const url of ["https://example.org/a?secret=hunter2", "https://example.org/" + "y".repeat(5000)])
    assert.equal((await options.canUseTool("mcp__sagebrush_page__web_fetch", { url, reason: "summarize" }, {})).behavior, "deny");
  assert.equal(p.events.length, before, "no card");
  p.ws.close();
  await server.close();
});

test("an interrupt settles a workspace call the page never answers", async () => {
  const { server, port, code } = await start();
  const p = page(port, ORIGIN, { hold: true });
  await p.open;
  await p.hello({ code });
  p.notify("grant.changed", GRANT);
  p.notify("chat.message", { conversation: "c1", id: "u1", author: "person", text: "hi" });
  await until(() => p.requests.length > 0);
  assert.equal(server.pending.size, 1);
  p.notify("chat.interrupt", { conversation: "c1" });
  await until(() => p.events.some((e) => e.event.type === "turn_finished"));
  await until(() => server.pending.size === 0);
  p.ws.close();
  await server.close();
});

test("after the hello a large answer from the page is fine", async () => {
  const { server, port, code } = await start();
  const p = page(port, ORIGIN, { big: 2 * 1024 * 1024 });
  await p.open;
  await p.hello({ code });
  p.notify("grant.changed", GRANT);
  p.notify("chat.message", { conversation: "c1", id: "u1", author: "person", text: "hi" });
  await until(() => p.events.some((e) => e.event.type === "turn_finished"));
  const fin = p.events.filter((e) => e.event.type === "tool_call_finished").map((e) => e.event.status);
  assert.deepEqual(fin, ["ok", "ok"]);
  p.ws.close();
  await server.close();
});

test("the hello must name protocol 1", async () => {
  const { server, port, code } = await start();
  const p = page(port);
  await p.open;
  const r = await p.hello({ code, protocol: 2 });
  assert.equal(r.error.data.code, "refused");
  await server.close();
});

test("the command line: --origin must be an exact http(s) origin", async () => {
  const { spawnSync } = await import("node:child_process");
  for (const bad of ["https://example.org/", "*", "null", "ftp://example.org", "https://example.org/path"]) {
    const r = spawnSync(process.execPath, ["bin/sagebrush-agent.mjs", "--origin", bad], { encoding: "utf8", env: { ...process.env, SAGEBRUSH_AGENT_FAKE: "1" } });
    assert.equal(r.status, 2, bad);
    assert.match(r.stderr, /exact origin/);
  }
});

test("the version the agent says (hello, status, its tool server) is the package's version", async () => {
  const { readFileSync } = await import("node:fs");
  const { VERSION } = await import("../lib/server.mjs");
  assert.equal(VERSION, JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")).version);
});

test("the command line: the printed link opens sagebrush.space/agents unless SAGEBRUSH_AGENT_PAGE says otherwise", async () => {
  const { spawn } = await import("node:child_process");
  const link = (env) => new Promise((resolve, reject) => {
    const e = { ...process.env, SAGEBRUSH_AGENT_FAKE: "1", ...env };
    if (env.SAGEBRUSH_AGENT_PAGE === undefined) delete e.SAGEBRUSH_AGENT_PAGE;
    const c = spawn(process.execPath, ["bin/sagebrush-agent.mjs"], { env: e, stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    const t = setTimeout(() => { c.kill("SIGKILL"); reject(new Error(`no link: ${out}`)); }, 10000);
    c.stdout.on("data", (d) => {
      out += d;
      const m = /Open: +(\S+)/.exec(out);
      if (m) { clearTimeout(t); c.kill("SIGKILL"); resolve(m[1]); }
    });
  });
  assert.match(await link({}), /^https:\/\/sagebrush\.space\/agents\/\?pair=[^&]+&port=\d+$/);
  assert.match(await link({ SAGEBRUSH_AGENT_PAGE: "https://dev.sagebrush.space/agents" }), /^https:\/\/dev\.sagebrush\.space\/agents\/\?pair=/);
});

test("the command line: when the page goes away, a fresh one-time link is printed; the page's session still reconnects", async () => {
  const { spawn } = await import("node:child_process");
  const c = spawn(process.execPath, ["bin/sagebrush-agent.mjs"], { env: { ...process.env, SAGEBRUSH_AGENT_FAKE: "1", SAGEBRUSH_AGENT_PAGE: "https://agents.sagebrush.cloud/agents/" }, stdio: ["ignore", "pipe", "pipe"] });
  let out = "";
  c.stdout.on("data", (d) => (out += d));
  try {
    const links = () => [...out.matchAll(/\?pair=([A-Z2-7]+)&port=(\d+)/g)].map((m) => ({ code: m[1], port: Number(m[2]) }));
    await until(() => links().length >= 1, 10000);
    const first = links()[0];
    const p1 = page(first.port);
    await p1.open;
    const r1 = await p1.hello({ code: first.code });
    assert.ok(r1.result, "the first link's code pairs");
    const session = r1.result.session;
    assert.equal(typeof session, "string");
    p1.ws.close();
    await until(() => links().length >= 2, 10000);
    assert.match(out, /The page disconnected; Claude's turns go on\. To connect a page, open:/);
    const second = links()[1];
    assert.notEqual(second.code, first.code, "a new code");
    assert.equal(second.port, first.port, "the same port");
    // the page's own session reconnects it, with no code
    const p2 = page(first.port);
    await p2.open;
    assert.ok((await p2.hello({ session })).result, "the session reconnects");
    p2.ws.close();
    await until(() => links().length >= 3, 10000);
    // the newest code pairs a page; an earlier printed code, replaced by a newer one, doesn't, and its refusal says where
    // a new code comes from, never a restart
    const p3 = page(first.port);
    await p3.open;
    const old = await p3.hello({ code: second.code });
    // (the page's dialog reads "wrong or expired code" to say a code is spent (web/workspace/agent-ui.ts): that part of the
    //  wording is a contract, pinned here exactly)
    assert.equal(old.error?.data?.message, "a wrong or expired code: use the newest link sagebrush-agent printed in its terminal");
    assert.ok(old.error && /use the newest link sagebrush-agent printed/.test(old.error.data.message) && !/start sagebrush-agent again/.test(old.error.data.message), "the second link's code, replaced by the third, is refused, with where a new one comes from");
    const p4 = page(first.port);
    await p4.open;
    assert.ok((await p4.hello({ code: links().at(-1).code })).result, "the newest code pairs");
    // another page while one is paired: refused at the upgrade (409), before any code is looked at
    const p5 = page(first.port);
    const r5 = await p5.open.then(() => "open", (e) => String(e?.message ?? e));
    assert.match(r5, /409/, "a second page while one is paired: refused (409)");
    p4.ws.close();
    assert.match(out, /^The code works once, for 5 minutes; a new one is printed here each time the page goes away\.$/m);
    assert.doesNotMatch(out, /press Enter/);
  } finally {
    c.kill("SIGKILL");
  }
});

test("the instructions: a notebook that runs by itself isn't run again; the Run button is named as the person sees it (A2, A4)", async () => {
  const { SYSTEM, SYSTEM_NATIVE } = await import("../lib/server.mjs");
  for (const [name, t] of [["scoped", SYSTEM], ["native", SYSTEM_NATIVE]]) {
    assert.match(t, /runs once by itself/, name);
    assert.match(t, /read it back for its outputs.{0,60}rather than running it again/, name);
    assert.match(t, /click ▶ \(Run\) beside the cell/, name);
  }
});

test("the page going away is said (onPageGone) when it disconnects, never while the agent stops", async () => {
  const { server, port, code } = await start();
  let gone = 0;
  server.onPageGone = () => gone++;
  const p = page(port);
  await p.open;
  const r = await p.hello({ code });
  p.ws.close();
  await until(() => gone === 1);
  const q = page(port);
  await q.open;
  assert.ok((await q.hello({ session: r.result.session })).result);
  await server.close(); // (with q paired: its socket closes on the way out)
  await new Promise((res) => setTimeout(res, 100));
  assert.equal(gone, 1, "stopping, with a page paired, says no page went away");
});

test("a malformed frame before the hello closes only that socket", async () => {
  const net = await import("node:net");
  const { server, port, code } = await start();
  const s = net.connect(port, "127.0.0.1");
  await new Promise((r) => s.on("connect", r));
  s.write(`GET /sagebrush HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nOrigin: ${ORIGIN}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n`);
  await new Promise((r) => s.once("data", r)); // (101 Switching Protocols)
  // a masked text frame declaring 13 MiB: 2 + 8 bytes of length + 4 of mask
  const h = Buffer.alloc(14);
  h[0] = 0x81; h[1] = 0x80 | 127; h.writeBigUInt64BE(13n * 1024n * 1024n, 2);
  s.write(h);
  await new Promise((r) => s.on("close", r));
  await until(() => server.unpaired === 0);
  // the daemon is still there for the real page
  const p = page(port);
  await p.open;
  assert.ok((await p.hello({ code })).result);
  p.ws.close();
  await server.close();
});

test("stopping waits for a running turn, then deletes; a failed deletion is reported", async () => {
  const deleted = [];
  const { server, port, code } = await start({
    deleteSession: async (id) => { deleted.push(id); throw new Error("disk says no"); },
  });
  const p = page(port);
  await p.open;
  await p.hello({ code });
  p.notify("grant.changed", GRANT);
  p.notify("chat.message", { conversation: "c1", id: "u1", author: "person", text: "x ".repeat(300) });
  await until(() => p.events.some((e) => e.event.type === "text_delta"));
  const c = server.conversations.get("c1");
  assert.ok(c.running?.done);
  const problems = await server.close();
  assert.equal(c.running, null); // (the turn had ended before the cleanup)
  assert.equal(deleted.length, 1);
  assert.equal(problems.length, 1);
  assert.match(problems[0], /disk says no.*~\/\.claude\/projects/);
});

test("changing an existing file without base is refused with how to do it; the page isn't asked", async () => {
  const { server, port, code } = await start();
  const p = page(port);
  await p.open;
  await p.hello({ code });
  p.notify("grant.changed", GRANT);
  p.notify("chat.message", { conversation: "c1", id: "u1", author: "person", text: "first" });
  await until(() => p.events.filter((e) => e.event.type === "turn_finished").length === 1);
  p.notify("chat.message", { conversation: "c1", id: "u2", author: "person", text: "second" });
  await until(() => p.events.filter((e) => e.event.type === "turn_finished").length === 2);
  const second = p.events.filter((e) => e.turn_id === p.events.at(-1).turn_id);
  const write = second.find((e) => e.event.type === "tool_call_finished").event;
  assert.equal(write.status, "error");
  assert.match(write.body, /already exists\. Read it with workspace_read, then call workspace_write again with base/);
  assert.ok(!p.requests.includes("workspace.write"));
  assert.match(p.files.get("/notes/fake-note.md"), /first/);
  assert.ok(!second.some((e) => e.event.type === "artifact"));

  p.ws.close();
  await server.close();
});
