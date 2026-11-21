#!/usr/bin/env node
// A fake `codex app-server`, for testing without OpenAI: it speaks the app-server's JSONL protocol on stdio
// (initialize, account/read, config/read, thread/start, turn/start, turn/interrupt), streams a scripted turn, calls
// the daemon's dynamic tools (item/tool/call) and asks its approvals, so the page round trip is real. Used only with
// SAGEBRUSH_AGENT_FAKE=1 --codex, and by the tests.
//
// What the person's message contains picks the script (see run()). The environment sets the rest:
//   FAKE_CODEX_RECORD=<file>     every message it gets, appended as JSON lines
//   FAKE_CODEX_VERSION=<v>       the version its userAgent names (default: the pinned one, codex-pin.json)
//   FAKE_CODEX_LOGGED_OUT=1      account/read says nobody is logged in
//   FAKE_CODEX_POLICY=<policy>   the approval_policy config/read reports (default on-request)
//   FAKE_CODEX_KEEP_NEVER=1      thread/start answers approvalPolicy never whatever it was asked
//   FAKE_CODEX_NOT_EPHEMERAL=1   thread/start answers a thread that isn't ephemeral
//   FAKE_CODEX_PLATFORM=<family> initialize's platformFamily (default unix)
//   FAKE_CODEX_SCHEMA=<file>     the schema `generate-json-schema` writes (a test/fixtures file); unset: it fails
//   FAKE_CODEX_SCHEMA_FAIL=1     `generate-json-schema` fails
//   FAKE_CODEX_EARLY_NOTES=1     notifications (configWarning) before initialize's answer, as Codex 0.163.0 sends
//   FAKE_CODEX_IGNORE_TERM=1     SIGTERM is ignored (only SIGKILL ends it)
//   FAKE_CODEX_SLOW_EXIT=1       on SIGTERM, exits 300 ms later (a Codex that takes a moment to end)
//   FAKE_CODEX_HOLD_INIT=1       initialize is never answered (a start that hangs)
//   FAKE_CODEX_NO_SANDBOX=1      the configWarning Codex sends when its Linux sandbox can't run (before initialize's answer)
//   FAKE_CODEX_MODEL=<m>         the model thread/start answers (default fake)
//   FAKE_CODEX_EFFORT=<e>        the reasoningEffort thread/start answers (default: none)
//   FAKE_CODEX_START_DELAY_MS=<n> thread/start answers n ms later
//   FAKE_CODEX_MODEL_PER_THREAD=1 each thread's model is fake-<thread id>

import { appendFileSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const env = process.env;
const PINNED = JSON.parse(readFileSync(new URL("./codex-pin.json", import.meta.url), "utf8")).version;

// `generate-json-schema --out <dir>` (the self-test's question): the schema in FAKE_CODEX_SCHEMA (a fixture of
// definitions, test/fixtures), written as the generated bundle; FAKE_CODEX_SCHEMA_FAIL=1 exits 1 instead.
if (process.argv.includes("generate-json-schema")) {
  const out = process.argv[process.argv.indexOf("--out") + 1];
  if (env.FAKE_CODEX_SCHEMA_FAIL === "1" || !env.FAKE_CODEX_SCHEMA || !out) {
    process.stderr.write("fake: no schema to generate; config line PRIVATE_CONFIG_MARKER token=sk-fake\n");
    process.exit(1);
  }
  if (env.FAKE_CODEX_RECORD) appendFileSync(env.FAKE_CODEX_RECORD, JSON.stringify({ argv: process.argv.slice(2) }) + "\n");
  const { definitions } = JSON.parse(readFileSync(env.FAKE_CODEX_SCHEMA, "utf8"));
  writeFileSync(join(out, "codex_app_server_protocol.schemas.json"), JSON.stringify({ definitions: {} }));
  writeFileSync(join(out, "codex_app_server_protocol.v2.schemas.json"), JSON.stringify({ definitions }));
  process.exit(0);
}
const record = env.FAKE_CODEX_RECORD;
let buf = "";
let next = 1;
const answers = new Map(); // our request id -> resolve
let current = null; // {threadId, turnId, stopped}
let earlyAnswer = null; // ("early": the answer to a request sent before turn/start's answer)

const write = (m) => process.stdout.write(JSON.stringify(m) + "\n");
const notify = (method, params) => write({ method, params });
const ask = (method, params) => new Promise((resolve) => { const id = `f${next++}`; answers.set(id, resolve); write({ id, method, params }); });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

if (record) appendFileSync(record, JSON.stringify({ pid: process.pid }) + "\n");
process.stdin.setEncoding("utf8");
process.stdin.on("data", (d) => {
  buf += d;
  let i;
  while ((i = buf.indexOf("\n")) >= 0) {
    const line = buf.slice(0, i);
    buf = buf.slice(i + 1);
    if (line.trim()) handle(JSON.parse(line));
  }
});
process.stdin.on("end", () => process.exit(0));
process.on("SIGTERM", () => { if (record) appendFileSync(record, JSON.stringify({ signal: "SIGTERM" }) + "\n"); if (env.FAKE_CODEX_IGNORE_TERM === "1") return; if (env.FAKE_CODEX_SLOW_EXIT === "1") setTimeout(() => process.exit(0), 300); else process.exit(0); });

function handle(m) {
  if (record) appendFileSync(record, JSON.stringify(m) + "\n");
  if (m.method === undefined) { answers.get(m.id)?.(m); answers.delete(m.id); return; }
  if (m.id === undefined) return; // (initialized)
  const p = m.params ?? {};
  const reply = (result) => write({ id: m.id, result });
  switch (m.method) {
    case "initialize":
      if (env.FAKE_CODEX_HOLD_INIT === "1") return;
      if (env.FAKE_CODEX_NO_SANDBOX === "1") notify("configWarning", { summary: "Codex's Linux sandbox uses bubblewrap and needs access to create user namespaces.", details: null });
      if (env.FAKE_CODEX_EARLY_NOTES === "1") {
        notify("configWarning", { summary: "fake warning", details: null });
        notify("remoteControl/status/changed", { status: "disabled", serverName: "fake" });
      }
      return reply({ userAgent: `${p.clientInfo?.name ?? "x"}/${env.FAKE_CODEX_VERSION ?? PINNED} (Fake 1.0; x86_64) dumb (${p.clientInfo?.name}; ${p.clientInfo?.version})`, codexHome: "/nonexistent/.codex", platformFamily: env.FAKE_CODEX_PLATFORM ?? "unix", platformOs: "linux" });
    case "account/read": return reply(env.FAKE_CODEX_LOGGED_OUT === "1" ? { account: null, requiresOpenaiAuth: true } : { account: { type: "chatgpt" }, requiresOpenaiAuth: true });
    case "config/read": return reply({ config: { approval_policy: env.FAKE_CODEX_POLICY ?? "on-request", sandbox_mode: "workspace-write" }, origins: {}, layers: null });
    case "thread/start": {
      const id = `thr-${next++}`;
      // (FAKE_CODEX_START_DELAY_MS: the answer comes that much later; FAKE_CODEX_MODEL_PER_THREAD: each thread its own model)
      const policy = env.FAKE_CODEX_KEEP_NEVER === "1" ? "never" : p.approvalPolicy ?? env.FAKE_CODEX_POLICY ?? "on-request";
      const answer = () => reply({ thread: { id, ephemeral: env.FAKE_CODEX_NOT_EPHEMERAL === "1" ? false : p.ephemeral === true }, model: env.FAKE_CODEX_MODEL_PER_THREAD === "1" ? `fake-${id}` : env.FAKE_CODEX_MODEL ?? "fake", cwd: p.cwd, approvalPolicy: policy,
        ...(env.FAKE_CODEX_EFFORT ? { reasoningEffort: env.FAKE_CODEX_EFFORT } : {}) });
      if (env.FAKE_CODEX_START_DELAY_MS) return void setTimeout(answer, Number(env.FAKE_CODEX_START_DELAY_MS));
      return answer();
    }
    case "turn/start": {
      const turnId = `fturn-${next++}`;
      const text = p.input?.find((x) => x.type === "text")?.text ?? "";
      if (text.includes("early")) {
        // (before the answer: a request and a delta for an earlier turn of this thread, then this turn's own message)
        earlyAnswer = ask("item/commandExecution/requestApproval", { threadId: p.threadId, turnId: "fturn-old", kind: "command", itemId: "cmd-old", startedAtMs: Date.now(), environmentId: null, command: "echo old" });
        notify("item/agentMessage/delta", { threadId: p.threadId, turnId: "fturn-old", itemId: "m-old", delta: "STALE " });
        notify("item/started", { threadId: p.threadId, turnId, item: { type: "agentMessage", id: "m-early", text: "" }, startedAtMs: Date.now() });
        notify("item/agentMessage/delta", { threadId: p.threadId, turnId, itemId: "m-early", delta: "EARLY-OK " });
      }
      reply({ turn: { id: turnId, status: "inProgress", items: [] } });
      run(p.threadId, turnId, text);
      return;
    }
    case "turn/interrupt": {
      if (current && current.turnId === p.turnId) current.stopped = true;
      return reply({});
    }
    default: return write({ id: m.id, error: { code: -32601, message: `fake: no ${m.method}` } });
  }
}

async function run(threadId, turnId, prompt) {
  const turn = (current = { threadId, turnId, stopped: false });
  const base = { threadId, turnId };
  const stop = () => turn.stopped;
  const has = (word) => prompt.includes(word);
  notify("turn/started", { threadId, turn: { id: turnId, status: "inProgress", items: [] } });
  const say = async (id, text) => {
    notify("item/started", { ...base, item: { type: "agentMessage", id, text: "" }, startedAtMs: Date.now() });
    for (const w of text.match(/\S+\s*/g) ?? []) {
      if (stop()) return false;
      await sleep(2);
      notify("item/agentMessage/delta", { ...base, itemId: id, delta: w });
    }
    notify("item/completed", { ...base, item: { type: "agentMessage", id, text }, completedAtMs: Date.now() });
    return true;
  };
  const tool = async (id, name, args) => {
    notify("item/started", { ...base, item: { type: "dynamicToolCall", id, namespace: null, tool: name, arguments: args, status: "inProgress", contentItems: null, success: null, durationMs: null }, startedAtMs: Date.now() });
    const r = await ask("item/tool/call", { ...base, callId: id, namespace: null, tool: name, arguments: args });
    const result = r.result ?? { contentItems: [{ type: "inputText", text: `error: ${r.error?.message}` }], success: false };
    notify("item/completed", { ...base, item: { type: "dynamicToolCall", id, namespace: null, tool: name, arguments: args, status: result.success ? "completed" : "failed", contentItems: result.contentItems, success: result.success, durationMs: 1 }, completedAtMs: Date.now() });
    return result;
  };
  const end = (status) => {
    notify("thread/tokenUsage/updated", { ...base, tokenUsage: { total: { totalTokens: 1300, inputTokens: 1200, cachedInputTokens: 0, outputTokens: 100 }, last: { totalTokens: 1300, inputTokens: 1200, cachedInputTokens: 0, outputTokens: 100 } } });
    notify("turn/completed", { threadId, turn: { id: turnId, status, items: [], error: status === "failed" ? { message: "fake failure", codexErrorInfo: "usageLimitExceeded" } : null } });
    if (current === turn) current = null;
  };
  // (each word below picks one step; the answer Codex got is said back, so a test reads it from the chat)
  if (has("crash")) { await sleep(20); process.exit(3); }
  if (has("fail")) return end("failed");
  if (has("deaf")) { while (true) await sleep(50); } // (never ends the turn, even when interrupted)
  if (!(await say("msg-1", `(fake Codex) You said: "${prompt.slice(0, 200)}".`))) return end("interrupted");
  if (has("early")) { const r = await earlyAnswer; await say("msg-early", `early decision: ${JSON.stringify(r.result?.decision)}`); }
  if (has("note")) await tool("call-1", "workspace_write", { path: "/notes/codex-note.md", text: "# A note from Codex\n\n$e^{i\\pi} + 1 = 0$\n" });
  if (has("list")) { const r = await tool("call-2", "workspace_list", { folder: "/", recursive: true }); await say("msg-l", `list ${r.success ? "ok" : "refused"}: ${r.contentItems?.[0]?.text ?? ""}`); }
  if (has("badargs")) { const r = await tool("call-b", "workspace_read", { path: 7 }); await say("msg-b", `badargs: ${r.contentItems?.[0]?.text ?? ""}`); }
  if (has("notool")) { const r = await tool("call-n", "workspace_launch", {}); await say("msg-n", `notool: ${r.contentItems?.[0]?.text ?? ""}`); }
  if (has("remove")) { const r = await tool("call-3", "workspace_remove", { path: "/notes/codex-note.md" }); await say("msg-r", `remove ${r.success ? "ok" : "refused"}: ${r.contentItems?.[0]?.text ?? ""}`); }
  if (has("command")) {
    notify("item/started", { ...base, item: { type: "commandExecution", id: "cmd-1", command: "ls -la", cwd: "/tmp", processId: null, source: "agent", status: "inProgress", commandActions: [], aggregatedOutput: null, exitCode: null, durationMs: null }, startedAtMs: Date.now() });
    const r = await ask("item/commandExecution/requestApproval", { ...base, kind: "command", itemId: "cmd-1", startedAtMs: Date.now(), environmentId: null, command: "ls -la", cwd: "/tmp", reason: "to see the files", ...(has("onlysession") ? { availableDecisions: ["acceptForSession", "decline"] } : {}) });
    const d = r.result?.decision;
    notify("item/completed", { ...base, item: { type: "commandExecution", id: "cmd-1", command: "ls -la", cwd: "/tmp", processId: null, source: "agent", status: d === "accept" ? "completed" : "declined", commandActions: [], aggregatedOutput: d === "accept" ? "total 0\n" : null, exitCode: d === "accept" ? 0 : null, durationMs: 3 }, completedAtMs: Date.now() });
    await say("msg-c", `command decision: ${JSON.stringify(d)}`);
  }
  if (has("stale")) {
    // (an approval for another turn of this thread, and one for another thread)
    const a = await ask("item/commandExecution/requestApproval", { threadId, turnId: "fturn-other", kind: "command", itemId: "cmd-s", startedAtMs: Date.now(), environmentId: null, command: "rm -rf /tmp/x" });
    const b = await ask("item/commandExecution/requestApproval", { threadId: "thr-other", turnId, kind: "command", itemId: "cmd-t", startedAtMs: Date.now(), environmentId: null, command: "rm -rf /tmp/y" });
    await say("msg-s", `stale decisions: ${JSON.stringify(a.result?.decision)} ${JSON.stringify(b.result?.decision)}`);
  }
  if (has("patch")) {
    const changes = [{ path: "/tmp/fake/a.txt", kind: { type: "add" }, diff: "+hello\n" }];
    if (!has("unseen")) notify("item/started", { ...base, item: { type: "fileChange", id: "fc-1", changes, status: "inProgress" }, startedAtMs: Date.now() });
    const r = await ask("item/fileChange/requestApproval", { ...base, itemId: "fc-1", startedAtMs: Date.now(), reason: "to add a.txt", grantRoot: null });
    const d = r.result?.decision;
    notify("item/completed", { ...base, item: { type: "fileChange", id: "fc-1", changes, status: d === "accept" ? "completed" : "declined" }, completedAtMs: Date.now() });
    await say("msg-p", `patch decision: ${JSON.stringify(d)}`);
  }
  if (has("access")) {
    const r = await ask("item/permissions/requestApproval", { ...base, itemId: "perm-1", environmentId: null, startedAtMs: Date.now(), cwd: "/tmp", reason: "needs the network", permissions: { network: { enabled: true }, fileSystem: null } });
    await say("msg-a", `access answer: ${JSON.stringify(r.result)}`);
  }
  if (has("question")) {
    const r = await ask("item/tool/requestUserInput", { ...base, itemId: "q-1", questions: [] });
    await say("msg-q", `question answer: ${r.error ? `error ${r.error.code} ${r.error.message}` : JSON.stringify(r.result)}`);
  }
  if (has("elicit")) {
    const r = await ask("mcpServer/elicitation/request", { ...base, serverName: "x", message: "?" });
    await say("msg-e", `elicit answer: ${JSON.stringify(r.result)}`);
  }
  if (has("refresh")) {
    const r = await ask("account/chatgptAuthTokens/refresh", { reason: "unauthorized" });
    await say("msg-f", `refresh answer: ${r.error ? `error ${r.error.code}` : "a result"}`);
  }
  if (has("wait")) { while (!stop()) await sleep(10); return end("interrupted"); }
  if (stop()) return end("interrupted");
  await say("msg-2", "Done.");
  end(stop() ? "interrupted" : "completed");
}
