// CLI mode's implementation gates (design claude-cli-mode r3.2, SEC and TESTS): the real pinned Claude Code against
// the fake Messages API, as in claude-cli-real.test.mjs. Rows named "cli gate: …". Linux only (strace for the kernel's
// view of connects and execs; the pinned linux binary).
import assert from "node:assert/strict";
import { test } from "node:test";
import { spawn, spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import { accountProblem, claudeBinary, cliCreateServer, cliQuery, sdkGuard } from "../lib/claude-cli.mjs";
import { permissionRules } from "../lib/server.mjs";
import { briefOptions } from "../lib/brief.mjs";
import { fakeAnthropic, toolResults } from "./fake-anthropic.mjs";

const BIN = claudeBinary();
const STRACE = spawnSync("strace", ["-V"]).status === 0;
const skip = !BIN || process.platform !== "linux" ? "the pinned linux Claude Code isn't here" : false;
const skipStrace = skip || (!STRACE ? "no strace here" : false);
const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

const freshEnv = (api, home = mkdtempSync(join(tmpdir(), "sb-cli-home-"))) => ({
  home,
  env: { PATH: process.env.PATH, HOME: home, CLAUDE_CONFIG_DIR: join(home, ".claude"), ANTHROPIC_API_KEY: "test-key-not-a-credential", ANTHROPIC_BASE_URL: api.url, DISABLE_AUTOUPDATER: "1", CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1" },
});
function echoServer() {
  const ran = [];
  return { ran, server: cliCreateServer({ name: "sagebrush", version: "1", tools: [["echo", "Echo text back", { text: z.string() }, async (a) => { ran.push(a.text); return { content: [{ type: "text", text: `echo: ${a.text}` }] }; }]] }) };
}
// A model that calls echo with each of `inputs` (in one message), then answers.
const echoCalls = (...inputs) => (body) => {
  if (toolResults(body).length) return [{ type: "text", text: "done" }];
  return (body.tools ?? []).some((t) => t.name === "mcp__sagebrush__echo") ? inputs.map((input) => ({ type: "tool_use", name: "mcp__sagebrush__echo", input })) : [{ type: "text", text: "ok" }];
};
const drain = async (q) => { const m = []; for await (const x of q) m.push(x); return m; };
const base = (extra) => ({ settingSources: [], strictMcpConfig: true, tools: [], permissionMode: "default", ...extra });
async function mcpCall(l, server, method, params) {
  try {
    const r = await fetch(`http://127.0.0.1:${l.port}/${server}`, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${l.token}` }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) });
    if (r.status !== 200) return { status: r.status };
    const j = await r.json();
    return { status: 200, isError: !!j.result?.isError, text: j.result?.content?.map((c) => c.text).join("") ?? "" };
  } catch (e) { return { status: 0, error: e.message }; }
}
// The binary run under strace (the kernel's view of every connect and exec of its whole tree).
function traced(log) {
  const dir = mkdtempSync(join(tmpdir(), "sb-strace-"));
  const w = join(dir, "claude");
  writeFileSync(w, `#!/bin/sh\nexec strace -f -qq -e trace=connect,execve -o ${JSON.stringify(log)} ${JSON.stringify(BIN)} "$@"\n`);
  chmodSync(w, 0o700);
  return w;
}
// Every inet connect in a strace log: [{addr, port}].
const connects = (log) => [...readFileSync(log, "utf8").matchAll(/connect\(\d+, \{sa_family=AF_INET6?, sin6?_port=htons\((\d+)\),[^}]*?(?:inet_addr\("([^"]+)"\)|inet_pton\(AF_INET6, "([^"]+)")/g)].map((m) => ({ port: Number(m[1]), addr: m[2] ?? m[3] }));

test("cli gate: startup sources: planted user, project and local SessionStart hooks, a plugin and a project MCP server all run with the sources open (control), and none runs or connects in the closed launch", { skip, timeout: 120_000 }, async () => {
  const root = mkdtempSync(join(tmpdir(), "sb-plants-"));
  const canary = join(root, "canary");
  mkdirSync(canary);
  const home = join(root, "home"), cfg = join(home, ".claude"), proj = join(root, "proj"), mk = join(root, "mk");
  for (const d of [cfg, join(proj, ".claude"), join(mk, ".claude-plugin"), join(mk, "p", ".claude-plugin"), join(mk, "p", "hooks")]) mkdirSync(d, { recursive: true });
  const hook = (tag) => ({ SessionStart: [{ hooks: [{ type: "command", command: `touch ${join(canary, tag)}` }] }] });
  writeFileSync(join(mk, ".claude-plugin", "marketplace.json"), JSON.stringify({ name: "mk", owner: { name: "t" }, plugins: [{ name: "p", source: "./p" }] }));
  writeFileSync(join(mk, "p", ".claude-plugin", "plugin.json"), JSON.stringify({ name: "p", version: "1.0.0" }));
  writeFileSync(join(mk, "p", "hooks", "hooks.json"), JSON.stringify({ hooks: hook("plugin") }));
  writeFileSync(join(cfg, "settings.json"), JSON.stringify({ hooks: hook("user"), extraKnownMarketplaces: { mk: { source: { source: "directory", path: mk } } }, enabledPlugins: { "p@mk": true } }));
  writeFileSync(join(proj, ".claude", "settings.json"), JSON.stringify({ hooks: hook("project"), enableAllProjectMcpServers: true, permissions: { allow: ["mcp__sagebrush__*"] } }));
  writeFileSync(join(proj, ".claude", "settings.local.json"), JSON.stringify({ hooks: hook("local") }));
  writeFileSync(join(proj, ".mcp.json"), JSON.stringify({ mcpServers: { planted: { command: "sh", args: ["-c", `touch ${join(canary, "mcp")}; sleep 3`] } } }));
  const api = await fakeAnthropic(echoCalls({ text: "hi" }));
  const { env } = freshEnv(api, home);
  // (the control: the same plants, the binary run directly with the sources open)
  spawnSync(BIN, ["-p", "--output-format", "stream-json", "--verbose", "--setting-sources", "user,project,local", "hello"], { cwd: proj, env, timeout: 60_000 });
  await new Promise((r) => setTimeout(r, 1500));
  assert.deepEqual(readdirSync(canary).sort(), ["local", "mcp", "plugin", "project", "user"], "the control: every plant runs when its source loads");
  for (const f of readdirSync(canary)) spawnSync("rm", [join(canary, f)]);
  // (the closed launch, through cliQuery; and the project's allow rule for our tools doesn't apply: echo still asks)
  const { server, ran } = echoServer();
  const asked = [];
  const msgs = await drain(cliQuery({ prompt: "use echo", options: base({ cwd: proj, mcpServers: { sagebrush: server }, canUseTool: async (n, i) => { asked.push(n); return { behavior: "allow", updatedInput: i }; } }) }, { bin: BIN, env }));
  await new Promise((r) => setTimeout(r, 1500));
  assert.deepEqual(readdirSync(canary), [], "no plant ran");
  const init = msgs.find((m) => m.subtype === "init");
  assert.deepEqual(init.mcp_servers.map((s) => s.name).filter((n) => n === "planted"), [], "the planted MCP server isn't there");
  assert.ok(!init.plugins.some((p) => p.source === "p@mk"), "the planted plugin isn't loaded");
  assert.deepEqual(asked, ["mcp__sagebrush__echo"]);
  assert.deepEqual(ran, ["hi"]);
  await api.close();
});

test("cli gate: the permission rules N1 carries drop every MCP allow rule; and if one let our tool past the decision anyway, the call is refused (fail closed)", { skip, timeout: 90_000 }, async () => {
  assert.deepEqual(permissionRules({ allow: ["mcp__sagebrush__*", "Bash(git *)", "MCP__x", 3, "x".repeat(600)], ask: ["Edit"], deny: ["Bash(rm *)"], hooks: {}, defaultMode: "auto" }), { allow: ["Bash(git *)"], ask: ["Edit"], deny: ["Bash(rm *)"] });
  assert.deepEqual(permissionRules(undefined), { allow: [], ask: [], deny: [] });
  // (a launch whose settings allow our tool outright: Claude Code calls it without the permission tool, and it's refused)
  const api = await fakeAnthropic(echoCalls({ text: "hi" }));
  const { env, home } = freshEnv(api);
  const { server, ran } = echoServer();
  const asked = [];
  await drain(cliQuery({ prompt: "use echo", options: base({ cwd: home, settings: { permissions: { allow: ["mcp__sagebrush__echo"] } }, mcpServers: { sagebrush: server }, canUseTool: async (n, i) => { asked.push(n); return { behavior: "allow", updatedInput: i }; } }) }, { bin: BIN, env }));
  assert.deepEqual(asked, [], "no decision was asked");
  assert.deepEqual(ran, [], "so nothing ran");
  const r = api.requests.map((x) => toolResults(x.body)).flat();
  assert.match(r[0].text, /wasn't allowed/);
  await api.close();
});

test("cli gate: races: forged calls after a Deny, after the run's Allow was used, and with parallel calls of different inputs each run only as allowed, once", { skip, timeout: 120_000 }, async () => {
  const api = await fakeAnthropic(echoCalls({ text: "a" }, { text: "b" }, { text: "c" }));
  const { env, home } = freshEnv(api);
  const { server, ran } = echoServer();
  let L = null;
  const forged = [];
  const q = cliQuery({ prompt: "use echo", options: base({ cwd: home, mcpServers: { sagebrush: server }, canUseTool: async (n, input) => {
    if (input.text === "b") { setImmediate(async () => forged.push(["after deny", await mcpCall(L.tools, "sagebrush", "tools/call", { name: "echo", arguments: { text: "b" } })])); return { behavior: "deny", message: "not b" }; }
    // (an Allow, then a token holder races Claude Code's own call with the same input)
    setImmediate(async () => forged.push([`race ${input.text}`, await mcpCall(L.tools, "sagebrush", "tools/call", { name: "echo", arguments: input })]));
    return { behavior: "allow", updatedInput: input };
  } }) }, { bin: BIN, env, onListeners: (l) => { L = l; } });
  await drain(q);
  await new Promise((r) => setTimeout(r, 300));
  await api.close();
  assert.deepEqual([...ran].sort(), ["a", "c"], "a and c ran once each, b never");
  assert.equal(forged.find(([k]) => k === "after deny")[1].isError, true);
});

test("cli gate: no deadlock: a decision held 30 s, then allowed, runs the call once and ends the turn", { skip, timeout: 120_000 }, async () => {
  const api = await fakeAnthropic(echoCalls({ text: "late" }));
  const { env, home } = freshEnv(api);
  const { server, ran } = echoServer();
  const t0 = Date.now();
  const msgs = await drain(cliQuery({ prompt: "use echo", options: base({ cwd: home, mcpServers: { sagebrush: server }, canUseTool: async (n, i) => { await new Promise((r) => setTimeout(r, 30_000)); return { behavior: "allow", updatedInput: i }; } }) }, { bin: BIN, env }));
  assert.ok(Date.now() - t0 >= 30_000);
  assert.deepEqual(ran, ["late"]);
  assert.equal(msgs.find((m) => m.type === "result")?.subtype, "success");
  await api.close();
});

test("cli gate: after a Stop, a forged call reaches nothing and runs nothing", { skip, timeout: 90_000 }, async () => {
  const api = await fakeAnthropic(echoCalls({ text: "x" }));
  const { env, home } = freshEnv(api);
  const { server, ran } = echoServer();
  let L = null;
  const abort = new AbortController();
  await drain(cliQuery({ prompt: "use echo", options: base({ cwd: home, abortController: abort, mcpServers: { sagebrush: server }, canUseTool: () => { setTimeout(() => abort.abort(), 50); return new Promise(() => {}); } }) }, { bin: BIN, env, onListeners: (l) => { L = l; } }));
  const r = await mcpCall(L.tools, "sagebrush", "tools/call", { name: "echo", arguments: { text: "x" } });
  assert.ok(r.status === 0 || r.isError, JSON.stringify(r));
  assert.deepEqual(ran, []);
  await api.close();
});

test("cli gate: chat.brief's fork through the CLI: no tools, the Pair session read, not written", { skip, timeout: 90_000 }, async () => {
  const api = await fakeAnthropic(() => [{ type: "text", text: "a brief" }]);
  const { env, home } = freshEnv(api);
  const first = await drain(cliQuery({ prompt: "the pair chat", options: base({ cwd: home, canUseTool: async () => ({ behavior: "deny", message: "no" }) }) }, { bin: BIN, env }));
  const session = first.find((m) => m.subtype === "init").session_id;
  const forkId = "33333333-3333-4333-8333-333333333333";
  const o = briefOptions({ resume: session, forkId, cwd: home, abortController: new AbortController() });
  const msgs = await drain(cliQuery({ prompt: "write the brief", options: o }, { bin: BIN, env }));
  assert.equal(msgs.find((m) => m.type === "result")?.subtype, "success");
  const last = api.requests.at(-1).body;
  assert.ok(JSON.stringify(last.messages).includes("the pair chat"), "the fork read the Pair session");
  assert.deepEqual((last.tools ?? []).filter((t) => !t.name.startsWith("mcp__p_")), [], "no tools");
  const projects = join(home, ".claude", "projects");
  const files = readdirSync(projects, { recursive: true }).map(String);
  assert.ok(!files.some((f) => f.includes(forkId)), "the fork isn't written");
  await api.close();
});

test("cli gate: egress, the kernel's view: a turn connects only to the fake API and our two listeners; a direct socket that ignores proxies is seen (the canary)", { skip: skipStrace, timeout: 120_000 }, async () => {
  const log = join(mkdtempSync(join(tmpdir(), "sb-eg-")), "trace");
  const api = await fakeAnthropic((body) => {
    if (toolResults(body).length) return [{ type: "text", text: "done" }];
    return (body.tools ?? []).some((t) => t.name === "Bash") ? [{ type: "tool_use", name: "Bash", input: { command: "curl -s --noproxy '*' --max-time 2 http://127.0.0.2:9/ ; true", description: "canary" } }] : [{ type: "tool_use", name: "mcp__sagebrush__echo", input: { text: "e" } }];
  });
  const { env, home } = freshEnv(api);
  // (turn 1: our tool, no Bash: only the allowed peers)
  let L = null;
  const { server } = echoServer();
  await drain(cliQuery({ prompt: "use echo", options: base({ cwd: home, mcpServers: { sagebrush: server }, canUseTool: async (n, i) => ({ behavior: "allow", updatedInput: i }) }) }, { bin: traced(log), env, onListeners: (l) => { L = l; } }));
  const allowed = new Set([api.port, L.tools.port, L.perm.port]);
  const c1 = connects(log);
  const messages1 = api.requests.length;
  const other1 = c1.filter((c) => !(c.addr === "127.0.0.1" && allowed.has(c.port)));
  assert.ok(messages1 >= 1, "Messages requests are counted at the fake");
  assert.deepEqual(other1, [], `zero other network connects (saw ${c1.length} in all)`);
  // (turn 2, the canary: Bash allowed, a direct connect to 127.0.0.2:9 that no proxy setting would see)
  const log2 = log + "2";
  await drain(cliQuery({ prompt: "run it", options: base({ cwd: home, tools: ["Bash"], canUseTool: async (n, i) => ({ behavior: "allow", updatedInput: i }) }) }, { bin: traced(log2), env, onListeners: (l) => { L = l; } }));
  const allowed2 = new Set([api.port, L.perm.port]);
  const other2 = connects(log2).filter((c) => !(c.addr === "127.0.0.1" && allowed2.has(c.port)));
  assert.deepEqual(other2, [{ port: 9, addr: "127.0.0.2" }], "the canary's direct connect is the one other connect seen");
  await api.close();
});

test("cli gate: SDK mode sends zero Messages requests for any credential but the selected one, and releases the prompt for it", { skip, timeout: 180_000 }, async () => {
  const sdk = await import("@anthropic-ai/claude-agent-sdk");
  const cases = [
    ["a Claude login token, no key", "apiKey", { CLAUDE_CODE_OAUTH_TOKEN: "fake-oauth-not-a-credential" }, false],
    ["nothing at all", "apiKey", {}, false],
    ["a key and a login token", "apiKey", { ANTHROPIC_API_KEY: "k", CLAUDE_CODE_OAUTH_TOKEN: "fake-oauth-not-a-credential" }, false],
    ["bedrock selected, a login token", "bedrock", { CLAUDE_CODE_USE_BEDROCK: "1", AWS_REGION: "us-east-1", CLAUDE_CODE_OAUTH_TOKEN: "fake-oauth-not-a-credential" }, false],
    ["the key selected and given", "apiKey", { ANTHROPIC_API_KEY: "k" }, true],
  ];
  for (const [label, select, extra, released] of cases) {
    const api = await fakeAnthropic(() => [{ type: "text", text: "ok" }]);
    const { env, home } = freshEnv(api);
    delete env.ANTHROPIC_API_KEY;
    const q = sdkGuard(sdk.query, select)({ prompt: "hi", options: { cwd: home, env: { ...env, ...extra }, settingSources: [], tools: [], abortController: new AbortController() } });
    let err = null;
    try { await drain(q); } catch (e) { err = e; } finally { await q.return().catch(() => {}); }
    await new Promise((r) => setTimeout(r, 300));
    if (released) {
      assert.equal(err, null, `${label}: ${err?.message}`);
      assert.ok(api.requests.length >= 1, `${label}: the prompt went`);
    } else {
      // (refused by the guard, or by Claude Code itself before it could answer: an error either way, nothing sent)
      assert.ok(err, `${label}: the query failed`);
      assert.equal(api.requests.length, 0, `${label}: zero Messages requests`);
    }
    await api.close();
  }
  // (the guard's pair is exact: unknown fields, a helper's key, the wrong provider)
  assert.match(accountProblem({ apiProvider: "firstParty", apiKeySource: "apiKeyHelper" }, "apiKey"), /key source/);
  assert.match(accountProblem({ apiProvider: "firstParty", apiKeySource: "ANTHROPIC_API_KEY", surprise: 1 }, "apiKey"), /unknown field/);
  assert.match(accountProblem({ apiProvider: "vertex" }, "bedrock"), /provider/);
  assert.match(accountProblem({ apiProvider: "firstParty", tokenSource: "claude.ai" }, "apiKey"), /login/);
  assert.equal(accountProblem({ apiProvider: "bedrock" }, "bedrock"), null);
  assert.equal(accountProblem({ apiProvider: "firstParty", apiKeySource: "ANTHROPIC_API_KEY", tokenSource: "none" }, "apiKey"), null);
});

test("cli gate: the release entry refuses any *_BASE_URL before it starts anything, and the package holds no test endpoint", { skip: skipStrace, timeout: 120_000 }, () => {
  for (const v of ["ANTHROPIC_BASE_URL", "ANTHROPIC_BEDROCK_BASE_URL"]) {
    const log = join(mkdtempSync(join(tmpdir(), "sb-bu-")), "trace");
    const r = spawnSync("strace", ["-f", "-qq", "-e", "trace=execve", "-o", log, process.execPath, join(ROOT, "bin", "sagebrush-agent.mjs"), "--stdio"], { env: { PATH: process.env.PATH, HOME: mkdtempSync(join(tmpdir(), "sb-h-")), [v]: "http://127.0.0.1:9" }, encoding: "utf8", timeout: 60_000 });
    assert.equal(r.status, 2, r.stderr);
    assert.match(r.stderr, new RegExp(`${v} is set`));
    const execs = readFileSync(log, "utf8").split("\n").filter((l) => l.includes("execve("));
    assert.equal(execs.length, 1, `only node itself was executed: ${execs.join(" | ")}`);
  }
  const pack = JSON.parse(spawnSync("npm", ["pack", "--dry-run", "--json", "--ignore-scripts"], { cwd: ROOT, encoding: "utf8" }).stdout)[0];
  const files = pack.files.map((f) => f.path);
  assert.ok(!files.some((f) => f.startsWith("test/")), "no test/ file in the package");
  assert.ok(files.includes("lib/claude-cli.mjs") && files.includes("lib/claude-pin.json"));
  for (const f of files.filter((f) => /\.(mjs|js)$/.test(f))) {
    const t = readFileSync(join(ROOT, f), "utf8");
    assert.ok(!/fake-anthropic/.test(t), `${f} doesn't reach the test endpoint`);
    assert.ok(!/ANTHROPIC_(?:BEDROCK_|VERTEX_|FOUNDRY_)?BASE_URL\s*[:=]|\[["']ANTHROPIC_\w*BASE_URL["']\]\s*=/.test(t), `${f} never sets a base URL`);
  }
});

test("cli gate: the SDK's settings resolver never opens Claude Code's auth files", { skip: skipStrace, timeout: 60_000 }, () => {
  const home = mkdtempSync(join(tmpdir(), "sb-res-"));
  const cfg = join(home, ".claude");
  mkdirSync(cfg);
  writeFileSync(join(cfg, ".credentials.json"), "{}");
  writeFileSync(join(home, ".claude.json"), "{}");
  writeFileSync(join(cfg, "settings.json"), JSON.stringify({ permissions: { defaultMode: "acceptEdits", allow: ["Bash(git *)"] }, apiKeyHelper: "touch /nonexistent-should-not-run" }));
  const log = join(home, "trace");
  const script = `const s = await import(${JSON.stringify(join(ROOT, "node_modules", "@anthropic-ai", "claude-agent-sdk", "sdk.mjs"))}); const r = s.filterEscalatingDefaultMode(await s.resolveSettings({ cwd: ${JSON.stringify(home)}, settingSources: ["user", "project", "local"] })); process.stdout.write(JSON.stringify(r?.permissions?.allow ?? null));`;
  const r = spawnSync("strace", ["-f", "-qq", "-e", "trace=open,openat,execve", "-o", log, process.execPath, "--input-type=module", "-e", script], { env: { PATH: process.env.PATH, HOME: home, CLAUDE_CONFIG_DIR: cfg }, encoding: "utf8", timeout: 50_000 });
  assert.equal(r.status, 0, r.stderr);
  assert.equal(r.stdout, JSON.stringify(["Bash(git *)"]), "the resolver did read the settings");
  const t = readFileSync(log, "utf8");
  assert.ok(t.includes("settings.json"), "the trace sees settings reads");
  assert.ok(!/\.credentials\.json|\.claude\.json"/.test(t), "no auth file opened");
  assert.equal(t.split("\n").filter((l) => l.includes("execve(")).length, 1, "no helper was executed");
});
