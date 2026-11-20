// Codex (--codex --stdio): the person's own Codex over `codex app-server`, here the fake one (lib/fake-codex.mjs),
// driven through the agent's pipes as the runner drives them. Native only: refused before anything starts when the
// connection has no shell and files. The thread's settings are the person's (only approval_policy never is replaced);
// the workspace tools are dynamic tools under the turn's grant; Codex's asks are cards bound to their request, and
// only an Allow with that card's digest accepts; anything not for the running turn is declined; the rest is refused.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { mkdtempSync, existsSync, readFileSync, rmSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { permissionDigest } from "../lib/canon.mjs";
import { CODEX_TEXT, CODEX_VERSION, codexVersion } from "../lib/codex.mjs";
import { PIN } from "../lib/codex-fetch.mjs";
import { HINTS } from "../lib/codex-turns.mjs";

const BIN = fileURLToPath(new URL("../bin/sagebrush-agent.mjs", import.meta.url));
// (the schema the fake Codex gives the self-test: real Codex 0.163.0 output, test/fixtures)
const SCHEMA = fileURLToPath(new URL("./fixtures/codex-schema-0.163.0.json", import.meta.url));
const F = 64 * 1024;

function agent(fakeEnv = {}) {
  const runnerCwd = realpathSync(mkdtempSync(join(tmpdir(), "runner-cwd-")));
  const record = join(runnerCwd, ".record.jsonl");
  const env = { ...process.env, SAGEBRUSH_AGENT_FAKE: "1", FAKE_CODEX_RECORD: record, FAKE_CODEX_SCHEMA: SCHEMA, ...fakeEnv };
  const p = spawn(process.execPath, [BIN, "--codex", "--stdio"], { cwd: runnerCwd, env, stdio: ["pipe", "pipe", "pipe"] });
  const a = { p, runnerCwd, lines: [], err: "", waiters: [] };
  a.exited = new Promise((r) => p.on("exit", (code) => r(code)));
  let buf = "";
  p.stdout.on("data", (d) => {
    buf += d.toString("utf8");
    let nl;
    while ((nl = buf.indexOf("\n")) >= 0) { a.lines.push(JSON.parse(buf.slice(0, nl))); buf = buf.slice(nl + 1); a.check(); }
  });
  p.stderr.on("data", (d) => { a.err += d.toString("utf8"); a.check(); });
  a.check = () => { for (const w of [...a.waiters]) if (w.pred()) { a.waiters.splice(a.waiters.indexOf(w), 1); w.resolve(); } };
  a.until = (pred, what, ms = 15000) => new Promise((resolve, reject) => {
    if (pred()) return resolve();
    const poll = setInterval(() => a.check(), 50); // (the record file changes without a line from the agent)
    const t = setTimeout(() => { clearInterval(poll); reject(new Error(`timed out waiting for ${what}; stderr: ${a.err.slice(-400)}`)); }, ms);
    a.waiters.push({ pred, resolve: () => { clearTimeout(t); clearInterval(poll); resolve(); } });
  });
  a.send = (o) => p.stdin.write(JSON.stringify(o) + "\n");
  a.grant = (extra = {}) => a.send({ jsonrpc: "2.0", method: "grant.changed", params: { folders: ["/"], write: true, ...extra } });
  a.say = (conversation, text) => a.send({ jsonrpc: "2.0", method: "chat.message", params: { conversation, id: `${conversation}-${a.lines.length}`, text, author: "person" } });
  a.events = (conversation) => a.lines.filter((m) => m.method === "turn.event" && m.params.conversation === conversation).map((m) => m.params.event);
  a.text = (conversation) => a.events(conversation).filter((e) => e.type === "text_delta").map((e) => e.text).join("");
  a.finished = (conversation, n = 1) => a.events(conversation).filter((e) => e.type === "turn_finished").length >= n;
  a.cards = (conversation, state = "open") => a.events(conversation).filter((e) => e.type === "attention" && e.state === state);
  // (what the fake app-server got: its requests, and our answers to its requests)
  // (complete lines only: the fake may be appending one, and a read can land mid-line)
  a.rec = () => {
    if (!existsSync(record)) return [];
    const t = readFileSync(record, "utf8");
    return t.slice(0, t.lastIndexOf("\n") + 1).split("\n").filter(Boolean).map((l) => JSON.parse(l));
  };
  a.calls = (method) => a.rec().filter((m) => m.method === method);
  // (the page's side of a workspace verb: answered with `result`)
  a.answer = (method, result) => {
    const q = a.lines.find((m) => m.method === method && m.id !== undefined && !m.answered);
    q.answered = true;
    a.send({ jsonrpc: "2.0", id: q.id, result });
  };
  a.permit = async (c, allow = true, digestOf = c) => a.send({ jsonrpc: "2.0", method: "chat.permission", params: { request_id: c.request_id, behavior: allow ? "allow" : "deny", ...(allow ? { digest: await digest(digestOf) } : {}) } });
  a.kill = () => { try { p.kill("SIGKILL"); } catch {} rmSync(runnerCwd, { recursive: true, force: true }); };
  a.send({ relay: { start: { frame: F, protocol: 1, epoch: 0 } } });
  return a;
}
const digest = (c) => permissionDigest({ child: c.child, conversation: c.conversation, request: c.request_id, tool: c.action.tool, input: c.action.input });
const finishedEvent = (a, c) => a.events(c).find((e) => e.type === "turn_finished");
const errorEvent = (a, c) => a.events(c).find((e) => e.type === "turn_error");

test("codexVersion reads the userAgent's version; the version run is the pinned one", () => {
  assert.equal(codexVersion("sagebrush-agent/0.159.2 (Ubuntu 26.4.0; x86_64) xterm (sagebrush-agent; 0.7.0)"), "0.159.2");
  assert.equal(codexVersion("codex_cli_rs/0.166.0"), "0.166.0");
  for (const s of ["", "no-version", "x/ (y)", null, undefined]) assert.equal(codexVersion(s), null, JSON.stringify(s));
  assert.equal(CODEX_VERSION, PIN.version);
  assert.equal(CODEX_VERSION, "0.159.2");
});

test("--codex without --stdio is refused at the start (exit 2), naming the runner", () => {
  const r = spawnSync(process.execPath, [BIN, "--codex"], { env: { ...process.env, SAGEBRUSH_AGENT_FAKE: "1" }, encoding: "utf8", timeout: 15000 });
  assert.equal(r.status, 2);
  assert.match(r.stderr, /--codex works only with --stdio/);
});

test("the page is told it talks to Codex over codex-app-server", async () => {
  const a = agent();
  try {
    await a.until(() => a.lines.some((m) => m.method === "agent.ready"), "agent.ready");
    const ready = a.lines.find((m) => m.method === "agent.ready").params.agent;
    assert.equal(ready.name, "Codex");
    assert.equal(ready.client, "codex-app-server");
  } finally { a.kill(); }
});

test("native off: the turn is refused before Codex starts (no app-server at all), for absent and false", async () => {
  for (const extra of [{}, { native: false }]) {
    const a = agent();
    try {
      a.grant(extra);
      a.say("c1", "hello");
      await a.until(() => a.finished("c1"), "the refused turn");
      assert.deepEqual(errorEvent(a, "c1"), { type: "turn_error", code: "native_off", message: CODEX_TEXT.needsNative });
      assert.equal(finishedEvent(a, "c1").outcome, "error");
      assert.deepEqual(a.rec(), [], "the fake app-server was never started");
    } finally { a.kill(); }
  }
});

test("native on: Codex answers; the thread runs in the runner's folder, ephemeral, with the workspace tools and no settings of ours", async () => {
  const a = agent();
  try {
    a.grant({ native: true });
    a.say("c1", "hello there");
    await a.until(() => a.finished("c1"), "the turn");
    assert.equal(finishedEvent(a, "c1").outcome, "completed");
    assert.match(a.text("c1"), /You said: "hello there"\..*Done\./s);
    const init = a.calls("initialize")[0].params;
    assert.equal(init.capabilities.experimentalApi, true);
    const t = a.calls("thread/start")[0].params;
    assert.equal(t.cwd, a.runnerCwd);
    assert.equal(t.ephemeral, true);
    assert.deepEqual(Object.keys(t).sort(), ["cwd", "developerInstructions", "dynamicTools", "ephemeral"], "no approval, sandbox or config of ours");
    const names = t.dynamicTools.map((d) => d.name);
    for (const n of ["workspace_list", "workspace_read", "workspace_write", "workspace_write_notebook", "workspace_edit_notebook", "workspace_mkdir", "workspace_rename", "workspace_remove"]) assert.ok(names.includes(n), n);
    assert.ok(t.dynamicTools.every((d) => d.type === "function" && d.inputSchema?.type === "object"));
    assert.ok(a.events("c1").some((e) => e.type === "turn_usage" && e.usage.input_tokens === 1200 && e.usage.output_tokens === 100));
    // (the same conversation goes on in the same thread; another conversation gets its own)
    a.say("c1", "again");
    await a.until(() => a.finished("c1", 2), "the second turn");
    a.say("c2", "other");
    await a.until(() => a.finished("c2"), "the other conversation");
    const starts = a.calls("turn/start").map((m) => m.params.threadId);
    assert.equal(starts[0], starts[1]);
    assert.notEqual(starts[2], starts[0]);
    assert.equal(a.calls("thread/start").length, 2);
    assert.equal(a.calls("initialize").length, 1, "one app-server for the process");
  } finally { a.kill(); }
});

test("a workspace tool goes to the page under the grant; its answer goes back to Codex; a write is an artifact", async () => {
  const a = agent();
  try {
    a.grant({ native: true });
    a.say("c1", "list note");
    // (workspace_write: a stat first, then a create)
    await a.until(() => a.lines.some((m) => m.method === "workspace.stat" && m.id), "the write's stat");
    a.answer("workspace.stat", { entry: null });
    await a.until(() => a.lines.some((m) => m.method === "workspace.create" && m.id), "the create request");
    a.answer("workspace.create", { rev: 1 });
    await a.until(() => a.lines.some((m) => m.method === "workspace.list" && m.id), "the list request");
    a.answer("workspace.list", { entries: [{ path: "/notes" }] });
    await a.until(() => a.finished("c1"), "the turn");
    assert.match(a.text("c1"), /list ok: \{"entries":\[\{"path":"\/notes"\}\]\}/);
    const art = a.events("c1").find((e) => e.type === "artifact");
    assert.equal(art.path, "/notes/codex-note.md");
    assert.equal(art.kind, "markdown");
  } finally { a.kill(); }
});

test("tool calls the page can't take: bad arguments and an unknown tool are refused without reaching the page", async () => {
  const a = agent();
  try {
    a.grant({ native: true });
    a.say("c1", "badargs notool");
    await a.until(() => a.finished("c1"), "the turn");
    assert.match(a.text("c1"), /badargs: refused: path: /);
    assert.match(a.text("c1"), /notool: refused: workspace_launch isn't offered by this page/);
    assert.ok(!a.lines.some((m) => m.method === "workspace.read"));
  } finally { a.kill(); }
});

test("a command Codex asks about: a card with exactly what it sent; Allow with its digest accepts, Deny declines", async () => {
  for (const [allow, want] of [[true, "accept"], [false, "decline"]]) {
    const a = agent();
    try {
      a.grant({ native: true });
      a.say("c1", "command");
      await a.until(() => a.cards("c1").length, "the card");
      const c = a.cards("c1")[0];
      assert.equal(c.title, CODEX_TEXT.titleCommand);
      assert.equal(c.summary, "ls -la");
      assert.deepEqual(c.action, { tool: "codex.command", input: { kind: "command", command: "ls -la", cwd: "/tmp", reason: "to see the files" } });
      await a.permit(c, allow);
      await a.until(() => a.finished("c1"), "the turn");
      assert.match(a.text("c1"), new RegExp(`command decision: "${want}"`));
      assert.equal(a.cards("c1", allow ? "approved" : "denied").length, 1);
    } finally { a.kill(); }
  }
});

test("Codex's sandbox can't start here: the person is told once per conversation, just before its first command card", async () => {
  const a = agent({ FAKE_CODEX_NO_SANDBOX: "1" });
  try {
    a.grant({ native: true });
    for (const [n, conv] of [[1, "c1"], [2, "c1"], [1, "c2"]]) {
      a.say(conv, "command");
      await a.until(() => a.cards(conv).length >= n, "the card");
      const evs = a.events(conv);
      const said = evs.filter((e) => e.type === "thinking_delta" && e.text === CODEX_TEXT.noSandbox);
      assert.equal(said.length, 1, `${conv}: said once`);
      assert.ok(evs.indexOf(said[0]) < evs.indexOf(a.cards(conv)[0]), "before the first card");
      await a.permit(a.cards(conv).at(-1), false);
      await a.until(() => a.finished(conv, n), "the turn");
    }
  } finally { a.kill(); }
  const b = agent();
  try {
    b.grant({ native: true });
    b.say("c1", "command");
    await b.until(() => b.cards("c1").length, "the card");
    assert.ok(!b.events("c1").some((e) => e.text === CODEX_TEXT.noSandbox), "not said where the sandbox runs");
  } finally { b.kill(); }
});

test("an Allow whose digest is for another action declines (logged)", async () => {
  const a = agent();
  try {
    a.grant({ native: true });
    a.say("c1", "command");
    await a.until(() => a.cards("c1").length, "the card");
    const c = a.cards("c1")[0];
    await a.permit(c, true, { ...c, action: { tool: c.action.tool, input: { ...c.action.input, command: "rm -rf /" } } });
    await a.until(() => a.finished("c1"), "the turn");
    assert.match(a.text("c1"), /command decision: "decline"/);
    assert.match(a.err, /a permission answer that didn't match its question was refused/);
  } finally { a.kill(); }
});

test("a command whose available decisions lack a plain accept is declined without a card", async () => {
  const a = agent();
  try {
    a.grant({ native: true });
    a.say("c1", "command onlysession");
    await a.until(() => a.finished("c1"), "the turn");
    assert.match(a.text("c1"), /command decision: "decline"/);
    assert.equal(a.events("c1").filter((e) => e.type === "attention").length, 0);
  } finally { a.kill(); }
});

test("an approval for another turn or another thread is declined without a card", async () => {
  const a = agent();
  try {
    a.grant({ native: true });
    a.say("c1", "stale");
    await a.until(() => a.finished("c1"), "the turn");
    assert.match(a.text("c1"), /stale decisions: "decline" "decline"/);
    assert.equal(a.events("c1").filter((e) => e.type === "attention").length, 0);
  } finally { a.kill(); }
});

test("a file change: the card shows the changes Codex announced; Allow accepts; one never announced is declined with a denied card", async () => {
  const a = agent();
  try {
    a.grant({ native: true });
    a.say("c1", "patch");
    await a.until(() => a.cards("c1").length, "the card");
    const c = a.cards("c1")[0];
    assert.equal(c.title, CODEX_TEXT.titleFiles);
    assert.equal(c.summary, "/tmp/fake/a.txt");
    assert.deepEqual(c.action, { tool: "codex.fileChange", input: { changes: [{ path: "/tmp/fake/a.txt", kind: { type: "add" }, diff: "+hello\n" }], reason: "to add a.txt" } });
    await a.permit(c, true);
    await a.until(() => a.finished("c1"), "the turn");
    assert.match(a.text("c1"), /patch decision: "accept"/);
    a.say("c2", "patch unseen");
    await a.until(() => a.finished("c2"), "the unseen turn");
    assert.match(a.text("c2"), /patch decision: "decline"/);
    const d = a.cards("c2", "denied")[0];
    assert.equal(d.summary, CODEX_TEXT.notReviewable);
    assert.equal(a.cards("c2").length, 0, "no open card");
  } finally { a.kill(); }
});

test("more access: Allow grants exactly what was asked, for the turn; Deny grants nothing", async () => {
  for (const [allow, want] of [[true, { permissions: { network: { enabled: true } }, scope: "turn" }], [false, { permissions: {}, scope: "turn" }]]) {
    const a = agent();
    try {
      a.grant({ native: true });
      a.say("c1", "access");
      await a.until(() => a.cards("c1").length, "the card");
      const c = a.cards("c1")[0];
      assert.equal(c.title, CODEX_TEXT.titlePermissions);
      assert.deepEqual(c.action.input, { cwd: "/tmp", reason: "needs the network", permissions: { network: { enabled: true } } });
      await a.permit(c, allow);
      await a.until(() => a.finished("c1"), "the turn");
      assert.equal(JSON.parse(/access answer: (\{.*\})/.exec(a.text("c1"))[1]).scope, "turn");
      assert.deepEqual(JSON.parse(/access answer: (\{.*?\})(?=Done|$)/s.exec(a.text("c1"))[1].trim()), want);
    } finally { a.kill(); }
  }
});

test("removing a workspace file asks, in the handler; a No refuses it before the page is asked", async () => {
  const a = agent();
  try {
    a.grant({ native: true });
    a.say("c1", "remove");
    await a.until(() => a.cards("c1").length, "the card");
    const c = a.cards("c1")[0];
    assert.equal(c.action.tool, "mcp__sagebrush_page__workspace_remove");
    await a.permit(c, false);
    await a.until(() => a.finished("c1"), "the turn");
    assert.match(a.text("c1"), /remove refused: refused: The person said no\./);
    assert.ok(!a.lines.some((m) => m.method === "workspace.remove"));
  } finally { a.kill(); }
});

test("questions, MCP elicitations and other requests are refused, never answered for the person", async () => {
  const a = agent();
  try {
    a.grant({ native: true });
    a.say("c1", "question elicit refresh");
    await a.until(() => a.finished("c1"), "the turn");
    assert.match(a.text("c1"), new RegExp(`question answer: error -32000 ${CODEX_TEXT.askInChat}`));
    assert.match(a.text("c1"), /elicit answer: \{"action":"decline","content":null,"_meta":null\}/);
    assert.match(a.text("c1"), /refresh answer: error -32601/);
  } finally { a.kill(); }
});

test("Stop: Codex is asked to interrupt the turn, which ends interrupted; an open card is cancelled", async () => {
  const a = agent();
  try {
    a.grant({ native: true });
    a.say("c1", "wait");
    await a.until(() => a.calls("turn/start").length, "the turn's start");
    a.send({ jsonrpc: "2.0", method: "chat.interrupt", params: { conversation: "c1" } });
    await a.until(() => a.finished("c1"), "the interrupted turn");
    assert.equal(finishedEvent(a, "c1").outcome, "interrupted");
    assert.equal(a.calls("turn/interrupt").length, 1);
    a.say("c2", "command wait");
    await a.until(() => a.cards("c2").length, "the card");
    a.send({ jsonrpc: "2.0", method: "chat.interrupt", params: { conversation: "c2" } });
    await a.until(() => a.finished("c2"), "the second interrupted turn");
    const answer = a.rec().find((m) => m.result?.decision !== undefined);
    assert.equal(answer.result.decision, "cancel");
  } finally { a.kill(); }
});

test("a new grant while a card is open: the card is withdrawn and Codex's request is cancelled", async () => {
  const a = agent();
  try {
    a.grant({ native: true });
    a.say("c1", "command");
    await a.until(() => a.cards("c1").length, "the card");
    const c = a.cards("c1")[0];
    a.grant({ native: true });
    await a.until(() => a.finished("c1"), "the turn ends");
    await a.until(() => a.rec().some((m) => m.result?.decision !== undefined), "the answer");
    assert.equal(a.rec().find((m) => m.result?.decision !== undefined).result.decision, "cancel");
    // (a late Allow for the old card does nothing)
    await a.permit(c, true);
    await new Promise((r) => setTimeout(r, 200));
    assert.equal(a.rec().filter((m) => m.result?.decision !== undefined).length, 1);
  } finally { a.kill(); }
});

test("a turn Codex doesn't end after Stop: interrupted after the grace, and its thread is never used again", async () => {
  const a = agent();
  try {
    a.grant({ native: true });
    a.say("c1", "deaf");
    await a.until(() => a.calls("turn/start").length, "the turn's start");
    a.send({ jsonrpc: "2.0", method: "chat.interrupt", params: { conversation: "c1" } });
    await a.until(() => a.finished("c1"), "the turn, after the grace", 20000);
    assert.equal(finishedEvent(a, "c1").outcome, "interrupted");
    a.say("c1", "again");
    await a.until(() => a.finished("c1", 2), "the next turn");
    const starts = a.calls("turn/start").map((m) => m.params.threadId);
    assert.notEqual(starts[1], starts[0], "a new thread");
    assert.match(a.err, new RegExp(CODEX_TEXT.restarted.replace(/[()]/g, "\\$&")));
  } finally { a.kill(); }
});

test("Codex exiting mid-turn fails the turn with why; the next message starts a new app-server and thread", async () => {
  const a = agent();
  try {
    a.grant({ native: true });
    a.say("c1", "crash");
    await a.until(() => a.finished("c1"), "the failed turn");
    assert.match(errorEvent(a, "c1").message, /^Codex stopped: exit 3/);
    a.say("c1", "hello");
    await a.until(() => a.finished("c1", 2), "the next turn");
    assert.equal(a.events("c1").filter((e) => e.type === "turn_finished").at(-1).outcome, "completed");
    assert.equal(a.calls("initialize").length, 2);
  } finally { a.kill(); }
});

test("start-up refusals: not the pinned version, Windows, not logged in; each starts over at the next message", async () => {
  for (const [env, code, message] of [
    [{ FAKE_CODEX_VERSION: "0.160.0" }, "codex_version", CODEX_TEXT.version("0.160.0")],
    [{ FAKE_CODEX_PLATFORM: "windows" }, "codex_platform", CODEX_TEXT.windows],
    [{ FAKE_CODEX_LOGGED_OUT: "1" }, "unauthorized", HINTS.unauthorized],
  ]) {
    const a = agent(env);
    try {
      a.grant({ native: true });
      a.say("c1", "hello");
      await a.until(() => a.finished("c1"), "the refused turn");
      assert.deepEqual(errorEvent(a, "c1"), { type: "turn_error", code, message });
      assert.equal(a.calls("thread/start").length, 0);
      a.say("c1", "again");
      await a.until(() => a.finished("c1", 2), "the second refused turn");
      assert.equal(a.calls("initialize").length, 2);
    } finally { a.kill(); }
  }
});

test("approval_policy never: the thread asks for on-request (logged); a thread that still says never, or isn't ephemeral, doesn't run", async () => {
  const a = agent({ FAKE_CODEX_POLICY: "never" });
  try {
    a.grant({ native: true });
    a.say("c1", "hello");
    await a.until(() => a.finished("c1"), "the turn");
    assert.equal(a.calls("thread/start")[0].params.approvalPolicy, "on-request");
    assert.equal(finishedEvent(a, "c1").outcome, "completed");
    assert.ok(a.err.includes(CODEX_TEXT.noNever));
  } finally { a.kill(); }
  for (const [env, message] of [[{ FAKE_CODEX_KEEP_NEVER: "1" }, CODEX_TEXT.stillNever], [{ FAKE_CODEX_NOT_EPHEMERAL: "1" }, CODEX_TEXT.notEphemeral]]) {
    const b = agent(env);
    try {
      b.grant({ native: true });
      b.say("c1", "hello");
      await b.until(() => b.finished("c1"), "the refused turn");
      assert.equal(errorEvent(b, "c1").message, message);
      assert.equal(b.calls("turn/start").length, 0);
    } finally { b.kill(); }
  }
});

test("SIGTERM: the agent ends Codex's app-server and exits 0", async () => {
  const a = agent();
  try {
    a.grant({ native: true });
    a.say("c1", "hello");
    await a.until(() => a.finished("c1"), "the turn");
    a.p.kill("SIGTERM");
    assert.equal(await a.exited, 0);
    assert.ok(a.rec().some((m) => m.signal === "SIGTERM"), "the app-server got SIGTERM");
  } finally { a.kill(); }
});

test("a workspace tool call for a binding that isn't current is refused, even before its turn is stopped", async () => {
  // (in-process: rebind() stops the old binding's turns at once, so through the pipes the stop is seen first; this
  //  row holds the binding check on its own)
  const { CodexBackend } = await import("../lib/codex.mjs");
  const { CodexTurn } = await import("../lib/codex-turns.mjs");
  let listed = 0;
  const old = { grant: { folders: ["/"] } }, current = { grant: { folders: ["/"] } };
  const server = { binding: current, workspaceToolList: () => [["workspace_list", "", {}, async () => { listed++; return { content: [{ type: "text", text: "{}" }] }; }]] };
  const backend = new CodexBackend(server);
  const active = { binding: old, signal: new AbortController().signal, turn: new CodexTurn("t"), conversation: "c1", c: {}, send: () => {} };
  const r = await backend.toolCall(active, { tool: "workspace_list", arguments: {} });
  assert.equal(r.success, false);
  assert.match(r.contentItems[0].text, /^refused: /);
  assert.equal(listed, 0);
  active.binding = current; // (the same call under the current binding runs)
  assert.equal((await backend.toolCall(active, { tool: "workspace_list", arguments: {} })).success, true);
  assert.equal(listed, 1);
});

test("before Codex answers turn/start: a request for an earlier turn is declined without a card, its delta dropped; this turn's own early message is kept", async () => {
  const a = agent();
  try {
    a.grant({ native: true });
    a.say("c1", "early");
    await a.until(() => a.finished("c1"), "the turn");
    assert.match(a.text("c1"), /EARLY-OK /);
    assert.doesNotMatch(a.text("c1"), /STALE/);
    assert.match(a.text("c1"), /early decision: "decline"/);
    assert.equal(a.events("c1").filter((e) => e.type === "attention").length, 0);
    assert.equal(finishedEvent(a, "c1").outcome, "completed");
  } finally { a.kill(); }
});
