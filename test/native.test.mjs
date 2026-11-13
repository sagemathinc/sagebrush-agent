// Native mode (an agent on one of the person's computers, over the runner, with "shell and files" on): the grant's
// native field, strictly true or false (absent false, anything else refuses the grant); native only with --stdio, never
// over the loopback address; the SDK options each mode runs with, decided once per turn; and a native tool's ask as a
// card bound to its request: allowed, denied, refused without a card, too large, and an answer after a rebind.
// The real process on its fake model, driven through its pipes as the runner drives it (stdio.test.mjs's way).
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { mkdtempSync, existsSync, readFileSync, rmSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import WebSocket from "ws";
import { TEXT, AgentServer, parseGrant, settingsMode } from "../lib/server.mjs";
import { mkdirSync, writeFileSync } from "node:fs";
import { fakeCreateServer, fakeQuery } from "../lib/fake.mjs";
import { permissionDigest } from "../lib/canon.mjs";

const BIN = fileURLToPath(new URL("../bin/sagebrush-agent.mjs", import.meta.url));
const F = 64 * 1024;

function agent({ userMode, projectMode } = {}) {
  // (the runner's working folder: where it started the agent; native mode works there. And a home of its own, so the
  //  person's settings are the row's, never this machine's)
  const runnerCwd = realpathSync(mkdtempSync(join(tmpdir(), "runner-cwd-")));
  const home = join(runnerCwd, ".home");
  mkdirSync(join(home, ".claude"), { recursive: true });
  if (userMode) writeFileSync(join(home, ".claude", "settings.json"), JSON.stringify({ permissions: { defaultMode: userMode } }));
  if (projectMode) { mkdirSync(join(runnerCwd, ".claude")); writeFileSync(join(runnerCwd, ".claude", "settings.json"), JSON.stringify({ permissions: { defaultMode: projectMode } })); }
  const p = spawn(process.execPath, [BIN, "--stdio"], { cwd: runnerCwd, env: { ...process.env, HOME: home, SAGEBRUSH_AGENT_FAKE: "1" }, stdio: ["pipe", "pipe", "pipe"] });
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
    const t = setTimeout(() => reject(new Error(`timed out waiting for ${what}; stderr: ${a.err.slice(-400)}`)), ms);
    a.waiters.push({ pred, resolve: () => { clearTimeout(t); resolve(); } });
  });
  a.send = (o) => p.stdin.write(JSON.stringify(o) + "\n");
  a.grant = (extra = {}) => a.send({ jsonrpc: "2.0", method: "grant.changed", params: { folders: ["/"], write: true, ...extra } });
  a.say = (conversation, text) => a.send({ jsonrpc: "2.0", method: "chat.message", params: { conversation, id: `${conversation}-${a.lines.length}`, text, author: "person" } });
  a.events = (conversation) => a.lines.filter((m) => m.method === "turn.event" && m.params.conversation === conversation).map((m) => m.params.event);
  a.text = (conversation) => a.events(conversation).filter((e) => e.type === "text_delta").map((e) => e.text).join("");
  a.finished = (conversation, n = 1) => a.events(conversation).filter((e) => e.type === "turn_finished").length >= n;
  a.mode = () => a.lines.filter((m) => m.method === "agent.mode").map((m) => m.params.native);
  a.kill = () => { try { p.kill("SIGKILL"); } catch {} rmSync(runnerCwd, { recursive: true, force: true }); };
  a.send({ relay: { start: { frame: F, protocol: 1, epoch: 0 } } });
  return a;
}
const card = (a, conversation) => a.events(conversation).find((e) => e.type === "attention" && e.state === "open");
const digest = (c) => permissionDigest({ child: c.child, conversation: c.conversation, request: c.request_id, tool: c.action.tool, input: c.action.input });
const options = async (a, conversation) => {
  a.say(conversation, "options?");
  await a.until(() => a.finished(conversation), "the options turn");
  return strip(JSON.parse(/OPTIONS (\{.*\})/.exec(a.text(conversation))[1]));
};
// (the options without where and whether it resumed, which rows check on their own)
const strip = ({ cwd, resumed, ...o }) => o;
const optionsFull = async (a, conversation, n) => {
  a.say(conversation, "options?");
  await a.until(() => a.finished(conversation, n), "the options turn");
  return [...a.text(conversation).matchAll(/OPTIONS (\{.*?\})(?=OPTIONS|$)/g)].map((m) => JSON.parse(m[1])).at(-1);
};
const NATIVE = { tools: { type: "preset", preset: "claude_code" }, settingSources: ["user", "project", "local"], permissionMode: "default", strictMcpConfig: null, systemPrompt: "claude_code", settings: null };
const TOOLS_ONLY = { tools: ["WebSearch", "WebFetch"], settingSources: [], permissionMode: "default", strictMcpConfig: true, systemPrompt: "sagebrush", settings: "set" };

test("parseGrant: native exactly true or false; absent false; anything else refuses the grant", () => {
  assert.equal(parseGrant({ folders: ["/"] }).grant.native, false);
  assert.equal(parseGrant({ folders: ["/"], native: true }).grant.native, true);
  assert.equal(parseGrant({ folders: ["/"], native: false }).grant.native, false);
  for (const v of ["true", 1, null, {}, []]) assert.deepEqual(parseGrant({ folders: ["/"], native: v }), { grant: null, bad: true }, `native: ${JSON.stringify(v)}`);
  assert.deepEqual(parseGrant({ native: true }), { grant: null, bad: false });
  assert.deepEqual(parseGrant(null), { grant: null, bad: false });
});

test("over the runner, native true: Claude Code's tools and system prompt, the person's settings, the default mode; agent.mode says so", async () => {
  const a = agent();
  try {
    a.grant({ native: true });
    assert.deepEqual(await options(a, "c1"), NATIVE);
    assert.deepEqual(a.mode(), [true]);
  } finally { a.kill(); }
});

test("over the runner, native absent or false: today's tools-only options, unchanged; agent.mode false", async () => {
  for (const extra of [{}, { native: false }]) {
    const a = agent();
    try {
      a.grant(extra);
      assert.deepEqual(await options(a, "c1"), TOOLS_ONLY, JSON.stringify(extra));
      assert.deepEqual(a.mode(), [false]);
    } finally { a.kill(); }
  }
});

test("a malformed native refuses the grant (logged): no native options, no workspace; agent.mode says false", async () => {
  const a = agent();
  try {
    a.grant({ native: "yes" });
    await a.until(() => a.err.includes(TEXT.badGrant), "the refusal's log line");
    assert.deepEqual(await options(a, "c1"), TOOLS_ONLY);
    assert.deepEqual(a.mode(), [false]);
  } finally { a.kill(); }
});

test("the mode is decided per turn: native, then off, in the same conversation", async () => {
  const a = agent();
  try {
    a.grant({ native: true });
    assert.deepEqual(await options(a, "c1"), NATIVE);
    a.grant({ native: false });
    a.say("c1", "options?");
    await a.until(() => a.finished("c1", 2), "the second turn");
    const second = [...a.text("c1").matchAll(/OPTIONS (\{.*?\})(?=OPTIONS|$)/g)].map((m) => strip(JSON.parse(m[1])));
    assert.deepEqual(second.at(-1), TOOLS_ONLY);
    assert.deepEqual(a.mode(), [true, false]);
  } finally { a.kill(); }
});

test("native: Bash asks with a card (the command shown, the action exact); Allow with its digest runs it, Deny doesn't", async () => {
  for (const [answer, want] of [["allow", "VERDICT Bash allow"], ["deny", "VERDICT Bash deny: The person said no."]]) {
    const a = agent();
    try {
      a.grant({ native: true });
      a.say("c1", "tool Bash ls -la /home/user");
      await a.until(() => card(a, "c1"), "the card");
      const c = card(a, "c1");
      assert.equal(c.title, "Allow Bash?");
      assert.equal(c.summary, "ls -la /home/user");
      assert.deepEqual(c.action, { tool: "Bash", input: { command: "ls -la /home/user", description: "List files" } });
      a.send({ jsonrpc: "2.0", method: "chat.permission", params: { request_id: c.request_id, behavior: answer, ...(answer === "allow" ? { digest: digest(c) } : {}) } });
      await a.until(() => a.finished("c1"), "the turn");
      assert.ok(a.text("c1").includes(want), a.text("c1"));
    } finally { a.kill(); }
  }
});

test("native: an Allow whose digest is for another command counts as no", async () => {
  const a = agent();
  try {
    a.grant({ native: true });
    a.say("c1", "tool Bash echo hi");
    await a.until(() => card(a, "c1"), "the card");
    const c = card(a, "c1");
    a.send({ jsonrpc: "2.0", method: "chat.permission", params: { request_id: c.request_id, behavior: "allow", digest: digest({ ...c, action: { tool: "Bash", input: { command: "rm -rf ~", description: "List files" } } }) } });
    await a.until(() => a.finished("c1"), "the turn");
    assert.ok(a.text("c1").includes("VERDICT Bash deny"), a.text("c1"));
  } finally { a.kill(); }
});

test("native: Edit asks with the file's path as its summary", async () => {
  const a = agent();
  try {
    a.grant({ native: true });
    a.say("c1", "tool Edit");
    await a.until(() => card(a, "c1"), "the card");
    const c = card(a, "c1");
    assert.equal(c.summary, "/home/user/a.py");
    assert.deepEqual(c.action.input, { file_path: "/home/user/a.py", old_string: "x = 1", new_string: "x = 2" });
  } finally { a.kill(); }
});

test("native: AskUserQuestion is refused without a card (ask in the chat)", async () => {
  const a = agent();
  try {
    a.grant({ native: true });
    a.say("c1", "tool AskUserQuestion");
    await a.until(() => a.finished("c1"), "the turn");
    assert.ok(a.text("c1").includes(`VERDICT AskUserQuestion deny: ${TEXT.askInChat}`), a.text("c1"));
    assert.equal(card(a, "c1"), undefined);
  } finally { a.kill(); }
});

test("tools-only (native off): Bash is refused without a card, and nothing runs", async () => {
  const a = agent();
  try {
    a.grant({ native: false });
    a.say("c1", "tool Bash ls");
    await a.until(() => a.finished("c1"), "the turn");
    assert.ok(a.text("c1").includes("VERDICT Bash deny: Bash isn't available here."), a.text("c1"));
    assert.equal(card(a, "c1"), undefined);
  } finally { a.kill(); }
});

test("native: an ask over the review limit is refused, not cut, and shows no card", async () => {
  const a = agent();
  try {
    a.grant({ native: true });
    a.say("c1", "tool Bash echo " + "x".repeat(17 * 1024));
    await a.until(() => a.finished("c1"), "the turn");
    // (refused before any card, whichever bound it meets first: the exact form's or the review's size)
    assert.match(a.text("c1"), new RegExp(`VERDICT Bash deny: (${TEXT.notReviewable}|The request is too large for the person to review\\.)`), a.text("c1").slice(0, 200));
    assert.equal(card(a, "c1"), undefined);
  } finally { a.kill(); }
});

test("native: a card's answer after the grant changed (rebind) counts for nothing; the turn ends", async () => {
  const a = agent();
  try {
    a.grant({ native: true });
    a.say("c1", "tool Bash touch /tmp/should-not");
    await a.until(() => card(a, "c1"), "the card");
    const c = card(a, "c1");
    a.grant({ native: true }); // (a new binding: the open ask is answered no, and its turn stops)
    await a.until(() => a.finished("c1"), "the turn's end");
    a.send({ jsonrpc: "2.0", method: "chat.permission", params: { request_id: c.request_id, behavior: "allow", digest: digest(c) } });
    a.say("c2", "options?");
    await a.until(() => a.finished("c2"), "a later turn");
    assert.ok(!a.text("c1").includes("VERDICT Bash allow"), a.text("c1"));
    assert.ok(a.events("c1").some((e) => e.type === "attention" && e.state === "denied"), "the card ends denied");
  } finally { a.kill(); }
});

test("native: the Sagebrush workspace tools keep their own rules (removing a file still asks)", async () => {
  const a = agent();
  const answer = setInterval(() => {
    for (const m of a.lines) if (typeof m.id === "string" && m.method && !m.answered) { m.answered = true; a.send({ jsonrpc: "2.0", id: m.id, result: m.method === "workspace.stat" ? { entry: null } : m.method === "workspace.list" ? { entries: [] } : { ok: true, rev: 1 } }); }
  }, 5);
  try {
    a.grant({ native: true });
    a.say("c1", "please remove the note");
    await a.until(() => card(a, "c1"), "the card");
    assert.equal(card(a, "c1").title, "Allow workspace_remove?");
  } finally { clearInterval(answer); a.kill(); }
});

test("over the loopback address, native true is not taken: tools-only, logged, and Bash refused", async () => {
  const logs = [];
  const scratch = mkdtempSync(join(tmpdir(), "runner-cwd-"));
  const server = new AgentServer({ query: fakeQuery, log: (m) => logs.push(m), runnerCwd: scratch });
  server.createServer = fakeCreateServer;
  const port = await server.listen();
  const code = server.newCode();
  const ws = new WebSocket(`ws://127.0.0.1:${port}/sagebrush`, { origin: "https://agents.sagebrush.cloud" });
  const msgs = [];
  ws.on("message", (d) => msgs.push(JSON.parse(d.toString())));
  await new Promise((r, j) => { ws.on("open", r); ws.on("error", j); });
  const send = (o) => ws.send(JSON.stringify(o));
  const until = async (f, what) => { const t = Date.now(); while (!f()) { if (Date.now() - t > 8000) throw new Error("timed out: " + what); await new Promise((r) => setTimeout(r, 10)); } };
  const text = (conv) => msgs.filter((m) => m.method === "turn.event" && m.params.conversation === conv && m.params.event.type === "text_delta").map((m) => m.params.event.text).join("");
  const done = (conv) => msgs.some((m) => m.method === "turn.event" && m.params.conversation === conv && m.params.event.type === "turn_finished");
  try {
    send({ jsonrpc: "2.0", id: "p1", method: "hello", params: { protocol: 1, code, page: { origin: "https://agents.sagebrush.cloud", path: "/agents/" } } });
    await until(() => msgs.some((m) => m.id === "p1"), "hello");
    send({ jsonrpc: "2.0", method: "grant.changed", params: { folders: ["/"], write: true, native: true } });
    await until(() => logs.includes(TEXT.nativeLoopback), "the loopback log line");
    assert.deepEqual(msgs.filter((m) => m.method === "agent.mode").map((m) => m.params.native), [false]);
    send({ jsonrpc: "2.0", method: "chat.message", params: { conversation: "c1", id: "m1", text: "options?", author: "person" } });
    await until(() => done("c1"), "the options turn");
    assert.deepEqual(strip(JSON.parse(/OPTIONS (\{.*\})/.exec(text("c1"))[1])), TOOLS_ONLY);
    send({ jsonrpc: "2.0", method: "chat.message", params: { conversation: "c2", id: "m2", text: "tool Bash ls", author: "person" } });
    await until(() => done("c2"), "the Bash turn");
    assert.ok(text("c2").includes("VERDICT Bash deny: Bash isn't available here."), text("c2"));
  } finally { ws.close(); await server.close(); rmSync(scratch, { recursive: true, force: true }); }
});

test("native works in the runner's own folder; tools-only in the agent's own empty one", async () => {
  const a = agent();
  try {
    a.grant({ native: true });
    const n = await optionsFull(a, "c1", 1);
    assert.equal(n.cwd, a.runnerCwd);
    a.grant({ native: false });
    const t = await optionsFull(a, "c2", 1);
    assert.notEqual(t.cwd, a.runnerCwd);
    assert.match(t.cwd, /sagebrush-agent-/);
  } finally { a.kill(); rmSync(a.runnerCwd, { recursive: true, force: true }); }
});

test("a native file by a relative name stays in the runner's folder after the agent stops; the runner's folder stays too", async () => {
  const a = agent();
  try {
    a.grant({ native: true });
    a.say("c1", "touch made-natively.txt");
    await a.until(() => a.finished("c1"), "the touch turn");
    const file = join(a.runnerCwd, "made-natively.txt");
    assert.equal(readFileSync(file, "utf8"), "made by the fake model\n");
    a.p.stdin.end(); // (the runner closes the pipe: the agent stops, deleting what is its own)
    assert.equal(await a.exited, 0);
    assert.ok(existsSync(a.runnerCwd), "the runner's folder is still there");
    assert.equal(readFileSync(file, "utf8"), "made by the fake model\n");
  } finally { a.kill(); rmSync(a.runnerCwd, { recursive: true, force: true }); }
});

test("tools-only: a file in the agent's own folder goes with it when the agent stops", async () => {
  const a = agent();
  try {
    a.grant({ native: false });
    a.say("c1", "options?");
    await a.until(() => a.finished("c1"), "the options turn");
    const own = JSON.parse(/OPTIONS (\{.*\})/.exec(a.text("c1"))[1]).cwd;
    a.say("c2", "touch scratch.txt");
    await a.until(() => a.finished("c2"), "the touch turn");
    assert.ok(existsSync(join(own, "scratch.txt")));
    a.p.stdin.end();
    assert.equal(await a.exited, 0);
    assert.ok(!existsSync(own), "the agent's own folder is removed");
    assert.ok(!existsSync(join(a.runnerCwd, "scratch.txt")));
  } finally { a.kill(); rmSync(a.runnerCwd, { recursive: true, force: true }); }
});

test("a conversation goes on in its own folder only: after the mode changes, a new session starts", async () => {
  const a = agent();
  try {
    a.grant({ native: true });
    assert.equal((await optionsFull(a, "c1", 1)).resumed, false);
    assert.equal((await optionsFull(a, "c1", 2)).resumed, true, "native again: resumed");
    a.grant({ native: false });
    const t = await optionsFull(a, "c1", 3);
    assert.equal(t.resumed, false, "tools-only after native: a new session, not the other folder's");
    assert.equal((await optionsFull(a, "c1", 4)).resumed, true, "tools-only again: resumed");
  } finally { a.kill(); rmSync(a.runnerCwd, { recursive: true, force: true }); }
});

test("settingsMode: the person's configured mode (user, then project, then local; the last wins); none is default; bypass never", () => {
  const root = mkdtempSync(join(tmpdir(), "modes-"));
  try {
    const home = join(root, "home"), cwd = join(root, "cwd");
    mkdirSync(join(home, ".claude"), { recursive: true }); mkdirSync(join(cwd, ".claude"), { recursive: true });
    const put = (f, mode) => writeFileSync(f, typeof mode === "string" ? JSON.stringify({ permissions: { defaultMode: mode } }) : mode.raw);
    const U = join(home, ".claude", "settings.json"), P = join(cwd, ".claude", "settings.json"), L = join(cwd, ".claude", "settings.local.json");
    assert.deepEqual(settingsMode(cwd, home), { mode: "default", bypass: false }, "none set");
    put(U, "acceptEdits");
    assert.deepEqual(settingsMode(cwd, home), { mode: "acceptEdits", bypass: false }, "the user's");
    put(P, "plan");
    assert.deepEqual(settingsMode(cwd, home), { mode: "plan", bypass: false }, "the project's over the user's");
    put(L, "dontAsk");
    assert.deepEqual(settingsMode(cwd, home), { mode: "dontAsk", bypass: false }, "local over the project's");
    put(L, "bypassPermissions");
    assert.deepEqual(settingsMode(cwd, home), { mode: "default", bypass: true }, "bypass: default, said");
    put(L, "made-up");
    assert.deepEqual(settingsMode(cwd, home), { mode: "default", bypass: false }, "an unknown mode: default");
    put(L, { raw: "{not json" });
    assert.deepEqual(settingsMode(cwd, home), { mode: "plan", bypass: false }, "a file that can't be read is skipped");
    put(U, "auto"); rmSync(P); rmSync(L);
    assert.deepEqual(settingsMode(cwd, home), { mode: "auto", bypass: false }, "auto, when the person chose it");
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("native over the runner: the mode the person's settings choose there is the one the turn runs in", async () => {
  for (const [o, want] of [[{ userMode: "acceptEdits" }, "acceptEdits"], [{ userMode: "acceptEdits", projectMode: "plan" }, "plan"], [{ projectMode: "dontAsk" }, "dontAsk"]]) {
    const a = agent(o);
    try {
      a.grant({ native: true });
      assert.equal((await options(a, "c1")).permissionMode, want, JSON.stringify(o));
    } finally { a.kill(); }
  }
});

test("native over the runner: a bypassPermissions setting runs in the default mode, and says so once", async () => {
  const a = agent({ userMode: "bypassPermissions" });
  try {
    a.grant({ native: true });
    assert.equal((await options(a, "c1")).permissionMode, "default");
    assert.equal(a.err.split(TEXT.noBypass).length - 1, 1);
  } finally { a.kill(); }
});

test("tools-only ignores the person's settings: default mode, whatever they choose", async () => {
  const a = agent({ userMode: "acceptEdits", projectMode: "plan" });
  try {
    a.grant({ native: false });
    assert.deepEqual(await options(a, "c1"), TOOLS_ONLY);
  } finally { a.kill(); }
});

test("native: removing a workspace file asks even when the person's rules let the call through (no callback): nothing reaches the page before Allow", async () => {
  for (const answer of ["deny", "allow"]) {
    const a = agent();
    const removes = () => a.lines.filter((m) => m.method === "workspace.remove");
    const answering = setInterval(() => {
      for (const m of a.lines) if (typeof m.id === "string" && m.method && !m.answered) { m.answered = true; a.send({ jsonrpc: "2.0", id: m.id, result: { ok: true } }); }
    }, 5);
    try {
      a.grant({ native: true });
      a.say("c1", "direct remove /notes/a.md");
      await a.until(() => card(a, "c1"), "the card");
      const c = card(a, "c1");
      assert.equal(c.title, "Allow workspace_remove?");
      assert.deepEqual(c.action, { tool: "mcp__sagebrush__workspace_remove", input: { path: "/notes/a.md" } });
      assert.equal(removes().length, 0, "nothing sent to the page while the card is open");
      a.send({ jsonrpc: "2.0", method: "chat.permission", params: { request_id: c.request_id, behavior: answer, ...(answer === "allow" ? { digest: digest(c) } : {}) } });
      await a.until(() => a.finished("c1"), "the turn");
      if (answer === "deny") {
        assert.equal(removes().length, 0, "denied: never sent");
        assert.match(a.text("c1"), /DIRECT refused: refused: The person said no\./);
      } else {
        assert.deepEqual(removes().map((m) => m.params), [{ path: "/notes/a.md" }], "allowed: sent once, exactly as allowed");
        assert.match(a.text("c1"), /DIRECT done/);
      }
    } finally { clearInterval(answering); a.kill(); }
  }
});

test("each session's transcript is deleted where it ran: the runner's folder for a native one, the agent's own for the rest", async () => {
  const deleted = [];
  const scratch = mkdtempSync(join(tmpdir(), "runner-cwd-"));
  const server = new AgentServer({ query: fakeQuery, log: () => {}, runnerCwd: scratch, deleteSession: async (id, o) => { deleted.push([id, o.dir]); } });
  const own = server.cwd;
  try {
    server.sessions.add("native-1"); server.sessionDirs.set("native-1", scratch);
    server.sessions.add("tools-1"); server.sessionDirs.set("tools-1", own);
    server.sessions.add("older-1"); // (one with no folder recorded: the agent's own)
    await server.close();
    assert.deepEqual(deleted.sort(), [["native-1", scratch], ["older-1", own], ["tools-1", own]].sort());
    assert.ok(!existsSync(own), "the agent's own folder is removed");
    assert.ok(existsSync(scratch), "the runner's folder is not");
  } finally { rmSync(scratch, { recursive: true, force: true }); }
});

test("native: a workspace remove the permission callback lets through is asked once, not twice", async () => {
  const a = agent();
  const answering = setInterval(() => {
    for (const m of a.lines) if (typeof m.id === "string" && m.method && !m.answered) { m.answered = true; a.send({ jsonrpc: "2.0", id: m.id, result: m.method === "workspace.stat" ? { entry: null } : m.method === "workspace.list" ? { entries: [] } : { ok: true, rev: 1 } }); }
  }, 5);
  try {
    a.grant({ native: true });
    a.say("c1", "please remove the note");
    await a.until(() => card(a, "c1"), "the card");
    const c = card(a, "c1");
    a.send({ jsonrpc: "2.0", method: "chat.permission", params: { request_id: c.request_id, behavior: "allow", digest: digest(c) } });
    await a.until(() => a.finished("c1"), "the turn (a second card would leave it waiting)");
    assert.equal(a.events("c1").filter((e) => e.type === "attention" && e.state === "open").length, 1);
    assert.equal(a.lines.filter((m) => m.method === "workspace.remove").length, 1);
  } finally { clearInterval(answering); a.kill(); }
});
