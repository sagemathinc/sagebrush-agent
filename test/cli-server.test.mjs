// CLI mode through the agent server (design claude-cli-mode r3.2): an in-process --stdio AgentServer set up as the bin
// sets it up in CLI mode (client "claude-code", mcpSource "dynamic", no hooks, a closed native launch). Rows "cli server: …":
// the options a native turn passes (closed, the person's rules projected, every tool of ours asked, no hooks), and one
// Pair turn with the real pinned Claude Code against the fake Messages API, a workspace tool answered by the page.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough, Writable } from "node:stream";
import { AgentServer, SERVER } from "../lib/server.mjs";
import { fakeCreateServer, fakeQuery } from "../lib/fake.mjs";
import { claudeBinary, cliCreateServer, cliQuery } from "../lib/claude-cli.mjs";
import { fakeAnthropic, toolResults } from "./fake-anthropic.mjs";

const F = 64 * 1024;
const BIN = claudeBinary();
const skip = !BIN || process.platform === "win32" ? "no pinned Claude Code binary here" : false;

function inproc({ query, createServer = fakeCreateServer, resolver }) {
  const scratch = mkdtempSync(join(tmpdir(), "runner-cwd-"));
  const server = new AgentServer({ query, log: () => {}, stdio: true, resolver, runnerCwd: scratch, client: "claude-code" });
  server.createServer = createServer;
  server.mcpSource = "dynamic";
  server.hooks = false;
  server.closedLaunch = true;
  const input = new PassThrough();
  const lines = [];
  let buf = "";
  const send = (o) => input.write(Buffer.from(JSON.stringify(o) + "\n"));
  const output = new Writable({ write(chunk, _e, cb) {
    buf += chunk.toString("utf8");
    let nl;
    while ((nl = buf.indexOf("\n")) >= 0) {
      const m = JSON.parse(buf.slice(0, nl));
      buf = buf.slice(nl + 1);
      lines.push(m);
      // (the page: a workspace read is answered with a small file)
      if (m.method === "workspace.read" && m.id !== undefined) send({ jsonrpc: "2.0", id: m.id, result: { path: m.params.path, rev: "r1", content: { text: "the file's text" } } });
    }
    cb();
  } });
  server.serveStdio({ input, output, fatal: () => {} });
  send({ relay: { start: { frame: F, protocol: 1, epoch: 0 } } });
  let n = 0;
  return {
    server, scratch, lines,
    grant: (extra = {}) => send({ jsonrpc: "2.0", method: "grant.changed", params: { folders: ["/"], write: true, ...extra } }),
    say: (conversation, text) => send({ jsonrpc: "2.0", method: "chat.message", params: { conversation, id: `${conversation}-${n++}`, text, author: "person" } }),
    events: (conversation) => lines.filter((m) => m.method === "turn.event" && m.params.conversation === conversation).map((m) => m.params.event),
    until: async (f, what, ms = 8000) => { const t = Date.now(); while (!f()) { if (Date.now() - t > ms) throw new Error("timed out: " + what); await new Promise((r) => setTimeout(r, 10)); } },
    close: async () => { input.end(); await server.close(); rmSync(scratch, { recursive: true, force: true }); },
  };
}

test("cli server: a native turn in CLI mode is a closed launch: no setting sources, strict MCP, no hooks, the person's rules projected (no MCP allow), and every tool of ours asked", { timeout: 20000 }, async () => {
  const seen = [];
  const resolver = { resolveSettings: async () => ({ effective: { permissions: { defaultMode: "acceptEdits", allow: ["Bash(git *)", "mcp__sagebrush_page__workspace_read", "mcp__theirs__x"], ask: ["Edit"], deny: ["Bash(rm *)"] }, hooks: { SessionStart: [] } } }), filterEscalatingDefaultMode: (r) => r.effective };
  const h = inproc({ query: (o) => { seen.push(o.options); return fakeQuery(o); }, resolver });
  try {
    h.grant({ native: true });
    h.say("c1", "options?");
    await h.until(() => h.events("c1").some((e) => e.type === "turn_finished"), "the turn");
    const o = seen[0];
    assert.deepEqual(o.settingSources, []);
    assert.equal(o.strictMcpConfig, true);
    assert.ok(!("hooks" in o), "no hooks key at all");
    assert.equal(o.permissionMode, "acceptEdits");
    assert.deepEqual(o.settings.permissions.allow, ["Bash(git *)"], "the MCP allow rules are dropped");
    assert.deepEqual(o.settings.permissions.deny, ["Bash(rm *)"]);
    assert.ok(o.settings.permissions.ask.includes("Edit") && o.settings.permissions.ask.includes(`mcp__${SERVER}`));
    assert.equal(o.settings.permissions.disableBypassPermissionsMode, "disable");
    assert.ok(!("hooks" in o.settings) && !("env" in o.settings), "nothing else of the person's settings");
  } finally { await h.close(); }
});

test("cli server: a page-mode turn in CLI mode passes no hooks and a closed launch", { timeout: 20000 }, async () => {
  const seen = [];
  const h = inproc({ query: (o) => { seen.push(o.options); return fakeQuery(o); } });
  try {
    h.grant();
    h.say("c1", "options?");
    await h.until(() => h.events("c1").some((e) => e.type === "turn_finished"), "the turn");
    assert.ok(!("hooks" in seen[0]));
    assert.deepEqual(seen[0].settingSources, []);
  } finally { await h.close(); }
});

test("cli server: a Pair turn with the real pinned Claude Code: the hello says claude-code, the model is reported, a workspace read goes to the page and back", { skip, timeout: 120000 }, async () => {
  const api = await fakeAnthropic((body) => {
    if (toolResults(body).length) return [{ type: "text", text: `read: ${toolResults(body)[0].text.slice(0, 200)}` }];
    return (body.tools ?? []).some((t) => t.name === `mcp__${SERVER}__workspace_read`) ? [{ type: "tool_use", name: `mcp__${SERVER}__workspace_read`, input: { path: "/a.txt" } }] : [{ type: "text", text: "ok" }];
  });
  const home = mkdtempSync(join(tmpdir(), "sb-cli-home-"));
  const env = { PATH: process.env.PATH, HOME: home, CLAUDE_CONFIG_DIR: join(home, ".claude"), ANTHROPIC_API_KEY: "test-key-not-a-credential", ANTHROPIC_BASE_URL: api.url, DISABLE_AUTOUPDATER: "1", CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1" };
  const h = inproc({ query: (args) => cliQuery(args, { bin: BIN, env }), createServer: cliCreateServer });
  try {
    h.grant();
    h.say("c1", "read a.txt");
    await h.until(() => h.events("c1").some((e) => e.type === "turn_finished"), "the turn", 90000);
    const ev = h.events("c1");
    const fin = ev.find((e) => e.type === "turn_finished");
    assert.ok(!fin.error, JSON.stringify(fin));
    assert.ok(ev.some((e) => e.type === "turn_info" && typeof e.model === "string"), `the model is reported: ${JSON.stringify(ev).slice(0, 1500)}`);
    assert.ok(h.lines.some((m) => m.method === "workspace.read" && m.params.path === "/a.txt"), "the read went to the page");
    const last = api.requests.at(-1).body;
    assert.match(toolResults(last)[0].text, /the file's text/);
    const hello = h.lines.find((m) => m.method === "agent.ready");
    if (hello) assert.equal(hello.params.agent.client, "claude-code");
  } finally { await h.close(); await api.close(); }
});
