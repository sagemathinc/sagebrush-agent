// CLI mode with the real pinned Claude Code (design claude-cli-mode r3.2): cliQuery runs the binary unmodified against a
// fake Messages API (test/fake-anthropic.mjs) that the test's own environment points it at, with a fresh HOME and
// config folder and a test key, never a login. Rows named "cli: …". Skipped where this platform has no pinned binary.
import assert from "node:assert/strict";
import { test } from "node:test";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { z } from "zod";
import { CLAUDE_PIN, claudeBinary, claudeVersionProblem, cliCreateServer, cliQuery } from "../lib/claude-cli.mjs";
import { fakeAnthropic, toolResults } from "./fake-anthropic.mjs";

const BIN = claudeBinary();
const skip = !BIN || process.platform === "win32" ? "no pinned Claude Code binary here" : false;

function freshEnv(api) {
  const home = mkdtempSync(join(tmpdir(), "sb-cli-home-"));
  return {
    home,
    env: {
      PATH: process.env.PATH, HOME: home, CLAUDE_CONFIG_DIR: join(home, ".claude"),
      ANTHROPIC_API_KEY: "test-key-not-a-credential", ANTHROPIC_BASE_URL: api.url,
      DISABLE_AUTOUPDATER: "1", CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1",
    },
  };
}

// The echo tool, counting what its handler ran with.
function echoServer() {
  const ran = [];
  const server = cliCreateServer({ name: "sagebrush", version: "1", tools: [["echo", "Echo text back", { text: z.string() }, async (a) => { ran.push(a.text); return { content: [{ type: "text", text: `echo: ${a.text}` }] }; }]] });
  return { server, ran };
}

// A model that calls echo once (with `input`), then answers with what came back.
const echoOnce = (input = { text: "hello" }) => (body) => {
  const offered = (body.tools ?? []).some((t) => t.name === "mcp__sagebrush__echo");
  const results = toolResults(body);
  if (results.length) return [{ type: "text", text: `got: ${results.map((r) => (r.error ? "ERROR " : "") + r.text).join(" | ")}` }];
  return offered ? [{ type: "tool_use", name: "mcp__sagebrush__echo", input }] : [{ type: "text", text: "ok" }];
};

async function drain(q) {
  const msgs = [];
  for await (const m of q) msgs.push(m);
  return msgs;
}

// A direct MCP request to one of the listeners (a stand-in for anything that got hold of a token).
async function mcpCall(l, server, method, params, token = l.token) {
  const r = await fetch(`http://127.0.0.1:${l.port}/${server}`, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${token}` }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) });
  if (r.status !== 200) return { status: r.status };
  const j = await r.json();
  return { status: 200, text: j.result?.content?.map((c) => c.text).join("") ?? "", isError: !!j.result?.isError, result: j.result };
}

const baseOptions = (extra = {}) => ({ includePartialMessages: true, settingSources: [], strictMcpConfig: true, tools: [], permissionMode: "default", persistSession: true, ...extra });

test("cli: the pinned binary is the SDK's own Claude Code release, and says so", { skip }, () => {
  const sdkPkg = JSON.parse(readFileSync(new URL("../node_modules/@anthropic-ai/claude-agent-sdk/package.json", import.meta.url), "utf8"));
  assert.equal(CLAUDE_PIN, sdkPkg.claudeCodeVersion);
  assert.equal(claudeVersionProblem(BIN, { env: { PATH: process.env.PATH, HOME: mkdtempSync(join(tmpdir(), "sb-v-")) } }), null);
});

test("cli: a turn calls our tool after an Allow; ours is the dynamic server; the permission tool is hidden; the launch is closed; the config is gone before the first request; no token in argv", { skip, timeout: 90_000 }, async () => {
  let configSeen = null, cmdline = null, child = null;
  const api = await fakeAnthropic(echoOnce(), {
    onRequest: (_b, n) => {
      if (n !== 0) return;
      cmdline = readFileSync(`/proc/${child.helperPid}/cmdline`, "utf8").split("\0");
      const i = cmdline.indexOf("--mcp-config");
      configSeen = existsSync(cmdline[i + 1]);
    },
  });
  const { env } = freshEnv(api);
  const { server, ran } = echoServer();
  let listeners = null;
  const asked = [];
  const q = cliQuery({ prompt: "use echo", options: baseOptions({ cwd: env.HOME, mcpServers: { sagebrush: server }, canUseTool: async (name, input) => { asked.push(name); return { behavior: "allow", updatedInput: input }; } }) }, { bin: BIN, env, onListeners: (l) => { listeners = l; } });
  const spawnWatch = setInterval(() => { if (q.child) { child = q.child; clearInterval(spawnWatch); } }, 1);
  const msgs = await drain(q);
  clearInterval(spawnWatch);
  await api.close();
  const init = msgs.find((m) => m.type === "system" && m.subtype === "init");
  assert.deepEqual(init.mcp_servers.filter((s) => s.name === "sagebrush"), [{ name: "sagebrush", status: "connected", source: "dynamic" }]);
  assert.ok(init.tools.includes("mcp__sagebrush__echo"));
  assert.ok(!init.tools.some((t) => t === listeners.perm.tool), "the permission tool isn't the model's");
  assert.deepEqual(asked, ["mcp__sagebrush__echo"]);
  assert.deepEqual(ran, ["hello"]);
  const result = msgs.find((m) => m.type === "result");
  assert.equal(result.subtype, "success");
  assert.match(msgs.filter((m) => m.type === "assistant").map((m) => JSON.stringify(m.message.content)).join(""), /got: echo: hello/);
  assert.equal(configSeen, false, "the MCP config file was removed before the first Messages request");
  const at = cmdline.indexOf("--setting-sources");
  assert.equal(cmdline[at + 1], "", "closed launch: no setting sources");
  for (const f of ["--strict-mcp-config", "--disable-slash-commands", "--replay-user-messages"]) assert.ok(cmdline.includes(f), f);
  const argv = cmdline.join(" ");
  assert.ok(!argv.includes(listeners.perm.token) && !argv.includes(listeners.tools.token), "no token in argv");
});

test("cli: a Deny runs nothing, and the model is told why", { skip, timeout: 90_000 }, async () => {
  const api = await fakeAnthropic(echoOnce());
  const { env } = freshEnv(api);
  const { server, ran } = echoServer();
  const msgs = await drain(cliQuery({ prompt: "use echo", options: baseOptions({ cwd: env.HOME, mcpServers: { sagebrush: server }, canUseTool: async () => ({ behavior: "deny", message: "no, says the person" }) }) }, { bin: BIN, env }));
  await api.close();
  assert.deepEqual(ran, []);
  const second = api.requests.find((r) => toolResults(r.body).length);
  assert.ok(second, "the model got a tool result");
  assert.deepEqual(toolResults(second.body).map((r) => [r.error, r.text.includes("no, says the person")]), [[true, true]]);
  assert.equal(msgs.at(-1).type === "result" || msgs.some((m) => m.type === "result"), true);
});

test("cli: a stolen token does nothing the person didn't allow: forged calls before the decision, mismatched decisions, a second run, crossed tokens", { skip, timeout: 120_000 }, async () => {
  const api = await fakeAnthropic(echoOnce());
  const { env } = freshEnv(api);
  const { server, ran } = echoServer();
  let L = null, release;
  const held = new Promise((r) => { release = r; });
  const seen = {};
  const q = cliQuery({ prompt: "use echo", options: baseOptions({ cwd: env.HOME, mcpServers: { sagebrush: server }, canUseTool: async (name, input, { toolUseID }) => {
    // (while the person hasn't decided: everything a token holder can try)
    seen.id = toolUseID;
    seen.forgedRun = await mcpCall(L.tools, "sagebrush", "tools/call", { name: "echo", arguments: { text: "hello" } });
    seen.changedInput = await mcpCall(L.perm, L.perm.name, "tools/call", { name: "decide", arguments: { tool_name: name, input: { text: "other" }, tool_use_id: toolUseID } });
    seen.changedName = await mcpCall(L.perm, L.perm.name, "tools/call", { name: "decide", arguments: { tool_name: "mcp__sagebrush__other", input, tool_use_id: toolUseID } });
    seen.unknownId = await mcpCall(L.perm, L.perm.name, "tools/call", { name: "decide", arguments: { tool_name: name, input, tool_use_id: "toolu_nope" } });
    seen.again = await mcpCall(L.perm, L.perm.name, "tools/call", { name: "decide", arguments: { tool_name: name, input, tool_use_id: toolUseID } });
    seen.crossed = await mcpCall({ port: L.perm.port, token: L.tools.token }, L.perm.name, "tools/list", {});
    seen.noToken = await mcpCall(L.tools, "sagebrush", "tools/list", {}, "x");
    seen.ranBefore = ran.length;
    await held;
    return { behavior: "allow", updatedInput: input };
  } }) }, { bin: BIN, env, onListeners: (l) => { L = l; } });
  const turn = drain(q);
  setTimeout(() => release(), 3000);
  await turn;
  // (after the genuine call ran: a replay of it is refused)
  assert.equal(seen.forgedRun.isError, true);
  assert.match(seen.forgedRun.text, /wasn't allowed/);
  assert.equal(seen.ranBefore, 0, "nothing ran before the decision");
  for (const k of ["changedInput", "changedName", "unknownId", "again"]) assert.equal(JSON.parse(seen[k].text).behavior, "deny", k);
  assert.equal(seen.crossed.status, 401);
  assert.equal(seen.noToken.status, 401);
  assert.deepEqual(ran, ["hello"], "the allowed call ran exactly once");
  await api.close();
});

test("cli: an Allow with a changed input authorizes that input only: the original is refused, the changed one runs once", { skip, timeout: 90_000 }, async () => {
  const api = await fakeAnthropic(echoOnce());
  const { env } = freshEnv(api);
  const { server, ran } = echoServer();
  let L = null;
  const forged = [];
  const q = cliQuery({ prompt: "use echo", options: baseOptions({ cwd: env.HOME, mcpServers: { sagebrush: server }, canUseTool: async () => {
    // (the decision is made; right after it, a token holder races the original input and the changed one)
    setImmediate(async () => {
      forged.push(await mcpCall(L.tools, "sagebrush", "tools/call", { name: "echo", arguments: { text: "hello" } }));
      forged.push(await mcpCall(L.tools, "sagebrush", "tools/call", { name: "echo", arguments: { text: "changed" } }));
    });
    return { behavior: "allow", updatedInput: { text: "changed" } };
  } }) }, { bin: BIN, env, onListeners: (l) => { L = l; } });
  await drain(q);
  await new Promise((r) => setTimeout(r, 200));
  await api.close();
  assert.deepEqual(ran, ["changed"], "only the changed input ran, once");
  assert.equal(forged[0].isError, true, "the original input is refused");
  // (the changed one raced Claude Code's own call: whichever came second was refused)
  assert.equal(ran.length, 1);
});

test("cli: a Stop while the person decides ends the run, its process group and its temp folder", { skip, timeout: 90_000 }, async () => {
  const api = await fakeAnthropic(echoOnce());
  const { env } = freshEnv(api);
  const { server, ran } = echoServer();
  const abort = new AbortController();
  let pid = null;
  const before = new Set(readdirSync(tmpdir()).filter((n) => n.startsWith("sb-claude-")));
  const q = cliQuery({ prompt: "use echo", options: baseOptions({ cwd: env.HOME, mcpServers: { sagebrush: server }, abortController: abort, canUseTool: () => { pid = q.child.pid; setTimeout(() => abort.abort(), 100); return new Promise(() => {}); } }) }, { bin: BIN, env });
  const t0 = Date.now();
  await drain(q);
  assert.ok(Date.now() - t0 < 30_000);
  await new Promise((r) => setTimeout(r, 2500));
  assert.throws(() => process.kill(-pid, 0), "the process group is gone");
  const after = readdirSync(tmpdir()).filter((n) => n.startsWith("sb-claude-") && !before.has(n));
  assert.deepEqual(after, [], "no temp folder left");
  assert.deepEqual(ran, []);
  await api.close();
});

test("cli: a steer mid-turn is replayed by its uuid, and a second turn resumes the first's session", { skip, timeout: 120_000 }, async () => {
  let release;
  const gate = new Promise((r) => { release = r; });
  const api = await fakeAnthropic(async (body, n) => { if (n === 0) await gate; return [{ type: "text", text: `reply ${n}` }]; });
  const { env } = freshEnv(api);
  const uuids = ["11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"];
  let push, end;
  const input = (async function* () {
    yield { type: "user", message: { role: "user", content: "first" }, parent_tool_use_id: null, session_id: "", uuid: uuids[0] };
    yield await new Promise((r) => { push = r; });
    await new Promise((r) => { end = r; });
  })();
  const msgs = [];
  const q = cliQuery({ prompt: input, options: baseOptions({ cwd: env.HOME, canUseTool: async () => ({ behavior: "deny", message: "no" }) }) }, { bin: BIN, env });
  let results = 0;
  for await (const m of q) {
    msgs.push(m);
    if (m.type === "system" && m.subtype === "init" && push) { push({ type: "user", message: { role: "user", content: "steer" }, parent_tool_use_id: null, session_id: "", uuid: uuids[1], priority: "next" }); push = null; setTimeout(() => release(), 300); }
    if (m.type === "result") results++;
    if (results >= 1 && msgs.some((x) => x.type === "user" && x.isReplay && x.uuid === uuids[1]) && msgs.filter((x) => x.type === "result").length >= 2) end?.();
    if (results >= 1 && m.type === "result" && msgs.filter((x) => x.type === "result").length >= 2) end?.();
  }
  const replays = msgs.filter((m) => m.type === "user" && m.isReplay).map((m) => m.uuid);
  for (const u of uuids) assert.equal(replays.filter((x) => x === u).length, 1, `one replay of ${u}`);
  const session = msgs.find((m) => m.type === "system" && m.subtype === "init").session_id;
  // (turn 2: resumes the session; the fake sees the earlier messages)
  const before = api.requests.length;
  const m2 = await drain(cliQuery({ prompt: "again", options: baseOptions({ cwd: env.HOME, resume: session, canUseTool: async () => ({ behavior: "deny", message: "no" }) }) }, { bin: BIN, env }));
  assert.ok(m2.some((m) => m.type === "result"));
  const r2 = api.requests.slice(before).find((r) => JSON.stringify(r.body.messages).includes("again"));
  assert.ok(JSON.stringify(r2.body.messages).includes("first"), "turn 2 carries turn 1");
  await api.close();
});

test("cli: options CLI mode can't honor are refused before anything starts: hooks (any, marked or not), setting sources, unknown options", () => {
  const effortShaped = async () => ({});
  effortShaped[Symbol.for("sagebrush.hook.reportOnly")] = true;
  assert.throws(() => cliQuery({ prompt: "x", options: { hooks: { PreToolUse: [{ hooks: [effortShaped] }] } } }), /hooks can't run/);
  assert.throws(() => cliQuery({ prompt: "x", options: { hooks: { Stop: [{ hooks: [async () => ({})] }] } } }), /hooks can't run/);
  assert.throws(() => cliQuery({ prompt: "x", options: { settingSources: ["user", "project", "local"] } }), /closed launch/);
  assert.throws(() => cliQuery({ prompt: "x", options: { canUseTool: () => {}, notAnOption: 1 } }), /isn't supported/);
  // (brief's empty hooks pass the check)
  const q = cliQuery({ prompt: "x", options: { hooks: {}, abortController: (() => { const a = new AbortController(); a.abort(); return a; })() } }, { bin: "/nonexistent" });
  return drain(q);
});

// (a stand-in executable whose descendant ignores TERM, in the child's process group: after a Stop, and after the
//  leader has already exited on its own, the whole group is gone once the run's iterator has returned)
test("cli: a Stop, or a leader that already exited, ends every process of the child's group, a TERM-ignoring descendant included", { skip: process.platform === "win32" ? "POSIX process groups" : false, timeout: 60_000 }, async () => {
  const { writeFileSync, chmodSync } = await import("node:fs");
  const dir = mkdtempSync(join(tmpdir(), "sb-grp-"));
  const pidFile = join(dir, "pids");
  const make = (name, tail) => {
    const p = join(dir, name);
    writeFileSync(p, `#!/bin/sh\n(trap "" TERM; echo $$ >> ${JSON.stringify(pidFile)}; exec sh -c 'trap "" TERM; while :; do sleep 1; done') &\n${tail}\n`);
    chmodSync(p, 0o700);
    return p;
  };
  for (const [label, bin, stop] of [["a Stop", make("held", "exec sleep 600"), true], ["the leader gone first", make("gone", "sleep 0.3; exit 1"), false]]) {
    const abort = new AbortController();
    const q = cliQuery({ prompt: "x", options: { abortController: abort, canUseTool: async () => ({ behavior: "deny", message: "no" }) } }, { bin, env: { PATH: process.env.PATH }, limits: { killGraceMs: 300, connectMs: 20_000 } });
    if (stop) setTimeout(() => abort.abort(), 500);
    try { for await (const _ of q) {} } catch {}
    await q.return();
    const pg = q.child.pid;
    let alive = true;
    try { process.kill(-pg, 0); } catch { alive = false; }
    assert.equal(alive, false, `${label}: the group is empty`);
  }
});

// (SEC H2 on the implementation: a tool_use id shown again while its decision is held answers neither call, whatever
//  the person then says; nothing runs)
test("cli: an id shown twice while the person decides is answered by neither, Allow or Deny; deterministic, on the run's own state", { timeout: 30_000 }, async () => {
  const { z: zz } = await import("zod");
  for (const answer of ["allow", "deny"]) {
    for (const second of [{ name: "mcp__s__t", input: { a: 1 } }, { name: "mcp__s__other", input: { a: 2 } }]) {
      let release;
      const held = new Promise((r) => { release = r; });
      const ran = [];
      const server = cliCreateServer({ name: "s", version: "1", tools: [["t", "t", { a: zz.number() }, async (x) => { ran.push(x); return { content: [] }; }]] });
      const abort = new AbortController();
      // (a stand-in that never connects: the run's own state is driven directly)
      const q = cliQuery({ prompt: "x", options: { abortController: abort, mcpServers: { s: server }, canUseTool: async () => { await held; return answer === "allow" ? { behavior: "allow", updatedInput: { a: 1 } } : { behavior: "deny", message: "no" }; } } }, { bin: "/bin/sleep", env: { PATH: process.env.PATH }, limits: { connectMs: 20_000 } });
      q.line(JSON.stringify({ type: "assistant", message: { content: [{ type: "tool_use", id: "toolu_dup", name: "mcp__s__t", input: { a: 1 } }] } }));
      const decided = q.permission({ tool_name: "mcp__s__t", input: { a: 1 }, tool_use_id: "toolu_dup" });
      await new Promise((r) => setImmediate(r));
      q.line(JSON.stringify({ type: "assistant", message: { content: [{ type: "tool_use", id: "toolu_dup", ...second }] } }));
      release();
      const out = JSON.parse((await decided).content[0].text);
      assert.equal(out.behavior, "deny", `${answer}, ${second.name}`);
      assert.equal(q.pending.get("toolu_dup").state, "denied");
      const t = server.tools[0];
      const call = await q.callTool("mcp__s__t", t, { a: 1 }, abort.signal);
      assert.equal(call.isError, true);
      assert.deepEqual(ran, []);
      abort.abort();
      await q.return();
    }
  }
});

test("cli: the real Claude Code shown a duplicated tool_use id (same or different input) while approval is held runs nothing, after Allow or Deny", { skip, timeout: 120_000 }, async () => {
  for (const answer of ["allow", "deny"]) {
    for (const second of [{ text: "a" }, { text: "b" }]) {
      const api = await fakeAnthropic((body) => toolResults(body).length ? [{ type: "text", text: "done" }]
        : (body.tools ?? []).some((t) => t.name === "mcp__sagebrush__echo") ? [{ type: "tool_use", id: "toolu_dupdupdup", name: "mcp__sagebrush__echo", input: { text: "a" } }, { type: "tool_use", id: "toolu_dupdupdup", name: "mcp__sagebrush__echo", input: second }] : [{ type: "text", text: "ok" }]);
      const { env } = freshEnv(api);
      const { server, ran } = echoServer();
      try {
        await drain(cliQuery({ prompt: "use echo", options: baseOptions({ cwd: env.HOME, mcpServers: { sagebrush: server }, canUseTool: async (n, i) => { await new Promise((r) => setTimeout(r, 1500)); return answer === "allow" ? { behavior: "allow", updatedInput: i } : { behavior: "deny", message: "no" }; } }) }, { bin: BIN, env }));
      } catch {}
      assert.deepEqual(ran, [], `${answer}, second input ${second.text}: nothing ran`);
      await api.close();
    }
  }
});

test("cli: a whole line over the bound ends the run, even when it ends with its newline (T2)", { skip: process.platform === "win32" ? "a shell stand-in" : false, timeout: 30_000 }, async () => {
  const { writeFileSync, chmodSync } = await import("node:fs");
  const dir = mkdtempSync(join(tmpdir(), "sb-line-"));
  const bin = join(dir, "big");
  writeFileSync(bin, `#!/bin/sh\nprintf '{"type":"result","subtype":"success","pad":"%s"}\\n' "$(head -c 2048 /dev/zero | tr '\\0' a)"\nexec sleep 30\n`);
  chmodSync(bin, 0o700);
  const q = cliQuery({ prompt: "x", options: { canUseTool: async () => ({ behavior: "deny", message: "no" }) } }, { bin, env: { PATH: process.env.PATH }, limits: { lineMax: 128, connectMs: 20_000, killGraceMs: 200 } });
  const got = [];
  let err = null;
  try { for await (const m of q) got.push(m); } catch (e) { err = e; }
  await q.return();
  assert.match(String(err?.message), /too large/);
  assert.equal(got.length, 0, "the oversized line was never yielded");
});

test("cli: the bound counts every unsettled tool call, waiting, being decided or allowed; settled ones keep no input (T3)", { timeout: 30_000 }, async () => {
  const held = [];
  const abort = new AbortController();
  const q = cliQuery({ prompt: "x", options: { abortController: abort, canUseTool: () => new Promise((r) => held.push(r)) } }, { bin: "/bin/sleep", env: { PATH: process.env.PATH }, limits: { pendingMax: 2, connectMs: 20_000 } });
  const use = (id) => q.line(JSON.stringify({ type: "assistant", message: { content: [{ type: "tool_use", id, name: "mcp__s__t", input: { id } }] } }));
  use("toolu_1"); use("toolu_2");
  const d1 = q.permission({ tool_name: "mcp__s__t", input: { id: "toolu_1" }, tool_use_id: "toolu_1" });
  const d2 = q.permission({ tool_name: "mcp__s__t", input: { id: "toolu_2" }, tool_use_id: "toolu_2" });
  await new Promise((r) => setImmediate(r));
  use("toolu_3");
  assert.equal(q.pending.has("toolu_3"), false, "a third, while two are being decided, isn't held");
  const d3 = await q.permission({ tool_name: "mcp__s__t", input: { id: "toolu_3" }, tool_use_id: "toolu_3" });
  assert.equal(JSON.parse(d3.content[0].text).behavior, "deny");
  held[0]({ behavior: "deny", message: "no" });
  held[1]({ behavior: "allow", updatedInput: { id: "toolu_2" } });
  await d1; await d2;
  assert.equal(q.pending.get("toolu_1").input, null, "a denied entry keeps no input");
  abort.abort();
  await q.return();
  assert.ok([...q.pending.values()].every((e) => e.input === null), "the end settles every entry and drops its input");
});

// (SEC H3 on the implementation: what a query retains per tool call is bounded in bytes, not only in count)
test("cli: retained state is bounded in bytes: id and name formats closed at 64 characters, settled entries keep neither name nor input, a measured ceiling for 65,536 ids, the held-input budget", { timeout: 60_000 }, async (t) => {
  const { CLI_LIMITS } = await import("../lib/claude-cli.mjs");
  // (the registered caps)
  assert.deepEqual({ pendingMax: CLI_LIMITS.pendingMax, seenMax: CLI_LIMITS.seenMax, heldInputBytes: CLI_LIMITS.heldInputBytes, lineMax: CLI_LIMITS.lineMax, bodyMax: CLI_LIMITS.bodyMax, queueMax: CLI_LIMITS.queueMax, queueBytesMax: CLI_LIMITS.queueBytesMax }, { pendingMax: 64, seenMax: 65536, heldInputBytes: 64 * 1024 * 1024, lineMax: 16 * 1024 * 1024, bodyMax: 32 * 1024 * 1024, queueMax: 256, queueBytesMax: 32 * 1024 * 1024 });
  // (a stand-in that only waits: the run's own state is driven directly)
  const { writeFileSync, chmodSync } = await import("node:fs");
  const sleeper = join(mkdtempSync(join(tmpdir(), "sb-sleep-")), "wait");
  writeFileSync(sleeper, "#!/bin/sh\nexec sleep 600\n");
  chmodSync(sleeper, 0o700);
  // (every run is ended in the end, also when a row fails: a failed row never leaves a child or a listener behind)
  const runs = [];
  t.after(async () => { for (const r of runs) { r.abort.abort(); await r.return().catch(() => {}); } });
  const run = (limits = {}) => { const r = cliQuery({ prompt: "x", options: { abortController: new AbortController(), canUseTool: () => new Promise(() => {}) } }, { bin: sleeper, env: { PATH: process.env.PATH }, limits: { connectMs: 600_000, killGraceMs: 200, ...limits } }); runs.push(r); return r; };
  const use = (q, id, name = "mcp__s__t", input = {}) => q.line(JSON.stringify({ type: "assistant", message: { content: [{ type: "tool_use", id, name, input }] } }));
  const ended = async (q) => { try { for await (const _ of q) {} return null; } catch (e) { return e.message; } };
  // (the boundaries: 64 characters pass, 65 end the query; so does anything outside [A-Za-z0-9_-])
  for (const [id, name, ok] of [["a".repeat(64), "n".repeat(64), true], ["a".repeat(65), "n", false], ["a", "n".repeat(65), false], ["tool é", "n", false], ["a", "mcp__x y", false]]) {
    const q = run();
    use(q, id, name);
    if (ok) { assert.equal(q.done, false); assert.equal(q.pending.get(id).name, name); q.abort.abort(); await q.return(); }
    else { assert.match(await ended(q), /can't follow/, JSON.stringify([id.length, name.length])); await q.return(); }
  }
  // (65,536 ids of 64 characters, each settled at once: a measured ceiling on what stays; then one more ends the query)
  const q = run({ pendingMax: 1 });
  global.gc?.();
  const before = process.memoryUsage().heapUsed;
  for (let i = 0; i < 65536; i++) {
    const id = i.toString(36).padStart(64, "_");
    use(q, id, "n".repeat(64), { v: "y".repeat(1000) });
    q.queue.length = 0; // (the consumer takes each message, as the agent's turn loop does)
    const e = q.pending.get(id);
    if (e) q.settle(e, "denied");
  }
  global.gc?.();
  const grew = process.memoryUsage().heapUsed - before;
  // (measured 11 MiB here and 28 MiB on another machine, with its heap's own overhead: the ceiling is a bound on
  //  growth that a retained input (1 KB each, 64 MiB in all) would break by far, not the measurement)
  assert.ok(grew < 48 * 1024 * 1024, `retained ${Math.round(grew / 1048576)} MiB for 65,536 ids`);
  assert.ok([...q.pending.values()].every((e) => e.name === null && e.input === null), "settled entries keep neither name nor input");
  use(q, "z".repeat(64));
  assert.match(await ended(q), /more tool calls/);
  await q.return();
  // (the held-input budget: a second input that would pass it isn't held)
  const h = run({ heldInputBytes: 1500 });
  use(h, "toolu_a", "mcp__s__t", { v: "y".repeat(1000) });
  use(h, "toolu_b", "mcp__s__t", { v: "y".repeat(1000) });
  assert.equal(h.pending.has("toolu_a"), true);
  assert.equal(h.pending.has("toolu_b"), false);
  h.abort.abort();
  await h.return();
});

// (TESTS T4 on the implementation: a Stop never waits on the prompt's producer)
test("cli: a Stop returns promptly whatever the prompt's producer does: blocked before or after its first message, then a late yield or a late failure; return() twice", { skip, timeout: 120_000 }, async () => {
  for (const [label, firstFirst, late] of [["blocked before the first", false, "yield"], ["blocked after the first", true, "yield"], ["blocked after the first, then fails", true, "reject"]]) {
    const api = await fakeAnthropic(() => [{ type: "text", text: "ok" }]);
    const { env } = freshEnv(api);
    let release;
    const gate = new Promise((r) => { release = r; });
    const input = (async function* () {
      if (firstFirst) yield { type: "user", message: { role: "user", content: "hi" }, parent_tool_use_id: null, session_id: "", uuid: "44444444-4444-4444-8444-444444444444" };
      const how = await gate;
      if (how === "reject") throw new Error("the producer failed late");
      yield { type: "user", message: { role: "user", content: "late" }, parent_tool_use_id: null, session_id: "", uuid: "55555555-5555-4555-8555-555555555555" };
    })();
    const abort = new AbortController();
    const q = cliQuery({ prompt: input, options: baseOptions({ cwd: env.HOME, abortController: abort, canUseTool: async () => ({ behavior: "deny", message: "no" }) }) }, { bin: BIN, env, limits: { killGraceMs: 200 } });
    const seen = [];
    const reader = (async () => { try { for await (const m of q) { seen.push(m.type); if (m.type === "result" || (!firstFirst && m.type === "system")) abort.abort(); } } catch {} })();
    if (!firstFirst) setTimeout(() => abort.abort(), 3000);
    await reader;
    const t0 = Date.now();
    await q.return();
    await q.return();
    assert.ok(Date.now() - t0 < 1500, `${label}: return() took ${Date.now() - t0} ms`);
    assert.equal(q.done, true);
    release(late);
    await new Promise((r) => setTimeout(r, 200));
    assert.equal(api.requests.filter((r) => JSON.stringify(r.body.messages).includes("late")).length, 0, `${label}: nothing late was sent`);
    await api.close();
  }
});

test("cli: a run that ends while it is still being set up starts no process and leaves no listener", { skip: process.platform === "win32" ? "a shell stand-in" : false, timeout: 30_000 }, async () => {
  const { writeFileSync, chmodSync } = await import("node:fs");
  const dir = mkdtempSync(join(tmpdir(), "sb-early-"));
  const mark = join(dir, "started");
  const bin = join(dir, "wait");
  writeFileSync(bin, `#!/bin/sh\ntouch ${JSON.stringify(mark)}\nexec sleep 600\n`);
  chmodSync(bin, 0o700);
  for (const how of ["a malformed line", "an abort"]) {
    const abort = new AbortController();
    const q = cliQuery({ prompt: "x", options: { abortController: abort, canUseTool: async () => ({ behavior: "deny", message: "no" }) } }, { bin, env: { PATH: process.env.PATH }, limits: { killGraceMs: 200 } });
    if (how === "an abort") abort.abort(); else q.line("{not json");
    try { for await (const _ of q) {} } catch {}
    await q.return().catch(() => {});
    await new Promise((r) => setTimeout(r, 300));
    assert.equal(q.child, null, `${how}: nothing was spawned`);
    assert.equal(existsSync(mark), false, `${how}: the stand-in never ran`);
  }
});

test("cli: the held-input budget counts canonical UTF-8 bytes, and an Allow's changed input is checked against it with every other held input", { timeout: 30_000 }, async () => {
  const { writeFileSync, chmodSync } = await import("node:fs");
  const sleeper = join(mkdtempSync(join(tmpdir(), "sb-sleep-")), "wait");
  writeFileSync(sleeper, "#!/bin/sh\nexec sleep 600\n");
  chmodSync(sleeper, 0o700);
  const use = (q, id, input) => q.line(JSON.stringify({ type: "assistant", message: { content: [{ type: "tool_use", id, name: "mcp__s__t", input }] } }));
  // (multibyte: 50 "é" are 58 characters of canonical text but 108 bytes, over a 60-byte budget: not held)
  const a = cliQuery({ prompt: "x", options: { canUseTool: async () => ({ behavior: "deny", message: "no" }) } }, { bin: sleeper, env: { PATH: process.env.PATH }, limits: { heldInputBytes: 60, connectMs: 600_000, killGraceMs: 200 } });
  use(a, "toolu_m", { v: "é".repeat(50) });
  assert.equal(a.pending.has("toolu_m"), false);
  use(a, "toolu_s", { v: "x".repeat(40) });
  assert.equal(a.pending.has("toolu_s"), true, "48 bytes fit");
  a.abort.abort(); await a.return();
  // (an Allow that grows the input past the budget is denied; with several held, the sum counts; a fitting one is allowed)
  let answers = {};
  const b = cliQuery({ prompt: "x", options: { canUseTool: async (n, input, { toolUseID }) => answers[toolUseID] } }, { bin: sleeper, env: { PATH: process.env.PATH }, limits: { heldInputBytes: 100, connectMs: 600_000, killGraceMs: 200 } });
  use(b, "toolu_1", { v: "x" });
  use(b, "toolu_2", { v: "x" });
  answers = { toolu_1: { behavior: "allow", updatedInput: { v: "x".repeat(1000) } }, toolu_2: { behavior: "allow", updatedInput: { v: "y".repeat(80) } } };
  const [r1, r2] = await Promise.all([b.permission({ tool_name: "mcp__s__t", input: { v: "x" }, tool_use_id: "toolu_1" }), b.permission({ tool_name: "mcp__s__t", input: { v: "x" }, tool_use_id: "toolu_2" })]);
  assert.equal(JSON.parse(r1.content[0].text).behavior, "deny", "1008 bytes don't fit");
  assert.equal(b.pending.get("toolu_1").state, "denied");
  assert.equal(JSON.parse(r2.content[0].text).behavior, "allow", "88 bytes fit beside nothing else held");
  assert.ok(b.heldBytes() <= 100, `held ${b.heldBytes()} bytes`);
  use(b, "toolu_3", { v: "z".repeat(20) });
  assert.equal(b.pending.has("toolu_3"), false, "88 + 28 bytes don't fit: the third isn't held");
  b.abort.abort(); await b.return();
});

// (TESTS T6: the queue's caps hold within one chunk of output: parsing stops, not only the stream)
test("cli: a burst of 1500 frames in one chunk, multibyte ones included, waits within the queue's count and byte caps; a slow consumer gets them all in order; a Stop while paused returns", { skip: process.platform === "win32" ? "a node stand-in" : false, timeout: 60_000 }, async () => {
  const { writeFileSync, chmodSync } = await import("node:fs");
  const dir = mkdtempSync(join(tmpdir(), "sb-burst-"));
  const bin = join(dir, "burst");
  writeFileSync(bin, `#!${process.execPath}\nconst lines = [];\nfor (let i = 0; i < 1500; i++) lines.push(JSON.stringify({ type: "stream_event", n: i, t: i % 3 ? "plain" : "é€😀".repeat(10) }));\nprocess.stdout.write(lines.join("\\n") + "\\n");\nsetTimeout(() => {}, 600000);\n`);
  chmodSync(bin, 0o700);
  for (const [label, limits] of [["count", { queueMax: 256 }], ["bytes", { queueMax: 100000, queueBytesMax: 4096 }]]) {
    const q = cliQuery({ prompt: "x", options: { canUseTool: async () => ({ behavior: "deny", message: "no" }) } }, { bin, env: { PATH: process.env.PATH }, limits: { connectMs: 600_000, killGraceMs: 200, ...limits } });
    await new Promise((r) => setTimeout(r, 1500));
    assert.equal(q.paused, true, `${label}: paused`);
    if (label === "count") assert.ok(q.queue.length <= 256, `${label}: ${q.queue.length} queued`);
    else assert.ok(q.queueBytes < 4096 + 200, `${label}: ${q.queueBytes} bytes queued`);
    // (a slow consumer: every frame, in order)
    const got = [];
    for (let i = 0; i < 1500; i++) {
      const s = await q.next();
      got.push(s.value.n);
      if (i % 200 === 0) await new Promise((r) => setTimeout(r, 20));
    }
    assert.deepEqual(got, Array.from({ length: 1500 }, (_, i) => i), `${label}: all, in order`);
    q.abort.abort();
    await q.return();
  }
  // (a Stop while paused)
  const q = cliQuery({ prompt: "x", options: { canUseTool: async () => ({ behavior: "deny", message: "no" }) } }, { bin, env: { PATH: process.env.PATH }, limits: { connectMs: 600_000, killGraceMs: 200 } });
  await new Promise((r) => setTimeout(r, 1500));
  assert.equal(q.paused, true);
  const t0 = Date.now();
  q.abort.abort();
  await q.return();
  assert.ok(Date.now() - t0 < 1500);
});

// (TESTS T7: a child that writes a burst and its result, then exits while parsing is paused: every frame and the
//  result are delivered, and the run ends as a success, not "stopped")
test("cli: a child that exits while its output waits unparsed: all 1500 frames and the result are delivered, then a clean end; a Stop in that state still returns promptly", { skip: process.platform === "win32" ? "a node stand-in" : false, timeout: 60_000 }, async () => {
  const { writeFileSync, chmodSync } = await import("node:fs");
  const dir = mkdtempSync(join(tmpdir(), "sb-exitp-"));
  const bin = join(dir, "burst-exit");
  writeFileSync(bin, `#!${process.execPath}\nconst lines = [];\nfor (let i = 0; i < 1500; i++) lines.push(JSON.stringify({ type: "stream_event", n: i, t: i % 3 ? "plain" : "é€😀".repeat(10) }));\nlines.push(JSON.stringify({ type: "result", subtype: "success", is_error: false }));\nprocess.stdout.write(lines.join("\\n") + "\\n", () => process.exit(0));\n`);
  chmodSync(bin, 0o700);
  const q = cliQuery({ prompt: "x", options: { canUseTool: async () => ({ behavior: "deny", message: "no" }) } }, { bin, env: { PATH: process.env.PATH }, limits: { connectMs: 600_000, killGraceMs: 200 } });
  await new Promise((r) => setTimeout(r, 1500));
  assert.equal(q.paused, true, "paused, with the child already gone");
  const got = [];
  let err = null;
  try { for await (const m of q) got.push(m); } catch (e) { err = e; }
  assert.equal(err, null, String(err?.message));
  assert.equal(got.length, 1501, "every frame and the result");
  assert.equal(got.at(-1).type, "result");
  assert.deepEqual(got.slice(0, 1500).map((m) => m.n), Array.from({ length: 1500 }, (_, i) => i));
  await q.return();
  // (a Stop while the exited child's output waits)
  const q2 = cliQuery({ prompt: "x", options: { canUseTool: async () => ({ behavior: "deny", message: "no" }) } }, { bin, env: { PATH: process.env.PATH }, limits: { connectMs: 600_000, killGraceMs: 200 } });
  await new Promise((r) => setTimeout(r, 1500));
  const t0 = Date.now();
  q2.abort.abort();
  await q2.return();
  assert.ok(Date.now() - t0 < 1500);
  assert.equal(q2.done, true);
});

// (SEC H5: an exited child whose output a descendant holds open past exitEofMs, and whose group outlives every KILL:
//  the run settles with the reaper's failure, never hangs and never calls the group empty)
test("cli: output held open after exit by a group that outlives its KILLs: the run settles, return() rejects with the reap failure, no timer is left", { skip: process.platform === "win32" ? "POSIX groups" : false, timeout: 60_000 }, async () => {
  const { writeFileSync, chmodSync } = await import("node:fs");
  const proc = await import("../lib/proc-start.mjs");
  const dir = mkdtempSync(join(tmpdir(), "sb-h5-"));
  const bin = join(dir, "held");
  writeFileSync(bin, "#!/bin/sh\n(trap '' TERM; while :; do sleep 1; done) &\nsleep 0.2\nexit 3\n");
  chmodSync(bin, 0o700);
  const q = cliQuery({ prompt: "x", options: { canUseTool: async () => ({ behavior: "deny", message: "no" }) } }, { bin, env: { PATH: process.env.PATH }, limits: { connectMs: 600_000, killGraceMs: 100, exitEofMs: 300 } });
  // (the group stays "alive" for the reaper: KILL is stubbed out for this group only, so the bound is reached)
  const realKill = process.kill;
  let pg = null;
  process.kill = (pid, sig) => { if (pg !== null && pid === -pg && sig === "SIGKILL") return true; return realKill.call(process, pid, sig); };
  // (the group's id from the spawn on: the KILL comes once, at the child's exit, before the loop below ends)
  const watch = setInterval(() => { if (q.child && pg === null) { pg = q.child.pid; clearInterval(watch); } }, 1);
  try {
    const t0 = Date.now();
    let err = null;
    try { for await (const _ of q) {} } catch (e) { err = e; }
    clearInterval(watch);
    assert.equal(pg, q.child.pid);
    assert.match(String(err?.message), /output stayed open/);
    let reap = null;
    try { await q.return(); } catch (e) { reap = e; }
    assert.ok(Date.now() - t0 < 30_000, "settled within the bound");
    // (the stub hid KILL only; TERM was ignored by the stand-in, so the group is really still there: the run says so)
    assert.equal(proc.groupAlive(pg), true, "the group really outlived the bound");
    assert.match(String(reap?.message), /still running after 10 s/);
    assert.equal(q.eofTimer ?? null, null);
  } finally {
    process.kill = realKill;
    if (pg !== null) { try { process.kill(-pg, "SIGKILL"); } catch {} }
  }
});
