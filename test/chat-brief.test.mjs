// Delegate briefs (chat.brief, lib/brief.mjs): a fake page over a real loopback WebSocket asks the agent, by id, for a
// brief drafted from a Pair conversation. The chat's turns and the draft are scripted models here (no Anthropic calls):
// the draft's options are checked exactly, and so are the answers, the errors, the caps, the cancels, the busy rules,
// the shared turn quota and the fork's deletion. The real pinned SDK's fork is in chat-brief-sdk.test.mjs.
import assert from "node:assert/strict";
import { test } from "node:test";
import WebSocket from "ws";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fakeBrief, fakeCreateServer, fakeQuery, promptText } from "../lib/fake.mjs";
import { AgentServer } from "../lib/server.mjs";
import { TaskStore } from "../lib/tasks.mjs";
import { TaskTurns } from "../lib/task-turns.mjs";
import { TaskRpc } from "../lib/task-rpc.mjs";
import { BRIEF_CUT, BRIEF_LIMITS, BRIEF_PROMPT, BRIEF_UNTITLED, cutBytes, shapeBrief } from "../lib/brief.mjs";

// (Delegate is refused on Windows in this version, and briefs come with it: declared skips there, never silent passes)
const WIN_DELEGATE = process.platform === "win32" ? { skip: "Delegate refused on win32 in this version" } : {};
const ORIGIN = "https://agents.sagebrush.cloud";
const GRANT = { folders: ["/"], write: true, delegate: true };
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const OUTLINED = "Title: Plot the partial sums\n\n## Goal\nA plot of the partial sums.\n\n## Decisions made\n- plot with matplotlib, not plotly\n\n## Files\n- /notes/sums.ipynb\n\n## Done when\nThe plot shows.";
const until = async (f, what = "", ms = 10000) => { const t = Date.now(); while (!f()) { if (Date.now() - t > ms) throw new Error(`timed out ${what}`); await new Promise((r) => setTimeout(r, 10)); } };
const code = (a) => a.error?.data?.code;

// The models. A chat turn: its init names the conversation's session ("pair-<n>", the same for every turn of a
// conversation, as a resumed session keeps its id); `hold` keeps it running until released. A draft: records its
// prompt and options, then answers `draft.text` (or hangs on `draft.hold`, or throws `draft.error`, or ends with
// `draft.result` as its result message).
function models() {
  const m = { chats: [], drafts: [], draft: { text: OUTLINED }, hold: null, deleted: [] };
  let n = 0;
  m.query = ({ prompt, options }) => {
    if (options.forkSession) {
      const rec = { options, prompt };
      m.drafts.push(rec);
      return (async function* () {
        rec.text = await promptText(prompt);
        const d = m.draft;
        if (d.beforeInit) await new Promise((r) => options.abortController.signal.addEventListener("abort", r, { once: true }));
        yield { type: "system", subtype: "init", session_id: options.sessionId, tools: [] };
        if (d.hold) await Promise.race([d.hold, new Promise((r) => options.abortController.signal.addEventListener("abort", r, { once: true }))]);
        if (options.abortController.signal.aborted) return;
        if (d.error) throw new Error(d.error);
        yield { type: "assistant", message: { role: "assistant", content: [{ type: "text", text: d.text }] } };
        yield d.result ?? { type: "result", subtype: "success", is_error: false, result: d.text, usage: {} };
      })();
    }
    const session = options.resume ?? `pair-${++n}`;
    m.chats.push({ options, session });
    return (async function* () {
      const text = await promptText(prompt);
      if (/^fail before init$/.test(text)) throw new Error("no session");
      yield { type: "system", subtype: "init", session_id: session, model: "fake", tools: [] };
      if (m.hold) await Promise.race([m.hold, new Promise((r) => options.abortController.signal.addEventListener("abort", r, { once: true }))]);
      yield { type: "result", subtype: "success", is_error: false, result: "ok", usage: { input_tokens: 1, output_tokens: 1 }, session_id: session };
    })();
  };
  m.deleteSession = async (id, opts) => { m.deleted.push({ id, dir: opts?.dir }); throw new Error(`session ${id} not found`); };
  return m;
}

async function setup({ tasks = true, backend = false, briefMs } = {}) {
  const dir = mkdtempSync(join(tmpdir(), "sb-brief-"));
  const m = models();
  const logs = [];
  const server = new AgentServer({ query: m.query, deleteSession: m.deleteSession, log: (s) => logs.push(String(s)), ...(briefMs ? { briefMs } : {}) });
  server.createServer = fakeCreateServer;
  if (tasks) {
    const store = new TaskStore({ root: join(dir, "tasks"), scope: "install-1" }).init();
    const turns = new TaskTurns({ store, query: fakeQuery, createServer: fakeCreateServer });
    server.setTasks({ store, turns, rpc: new TaskRpc({ store, turns }) });
  }
  if (backend) server.backend = { runTurn: async () => {}, close: async () => [] }; // (another agent runs the chats: Codex)
  const port = await server.listen();
  return { dir, server, m, logs, port, code: server.newCode(), done: async () => { await server.close(); rmSync(dir, { recursive: true, force: true }); } };
}
function page(port) {
  const ws = new WebSocket(`ws://127.0.0.1:${port}/sagebrush`, { origin: ORIGIN });
  const answers = new Map(), events = [], rejected = [], nullAnswers = [];
  let n = 1;
  ws.on("message", (d) => {
    const msg = JSON.parse(d.toString());
    if (msg.method === "turn.event") return events.push(msg.params);
    if (msg.method === "chat.rejected") return rejected.push(msg.params);
    if (typeof msg.id === "string" && ("result" in msg || "error" in msg)) answers.get(msg.id)?.(msg);
    if (msg.id === null && "error" in msg) nullAnswers.push(msg);
  });
  const call = (method, params, id = `p${++n}`) => new Promise((resolve) => { answers.set(id, resolve); ws.send(JSON.stringify({ jsonrpc: "2.0", id, method, params })); });
  const hello = (code) => call("hello", { protocol: 1, page: { origin: ORIGIN, path: "/agents/" }, code }, "p1");
  const notify = (method, params) => ws.send(JSON.stringify({ jsonrpc: "2.0", method, params }));
  const say = (conversation, text, id = `m${++n}`) => notify("chat.message", { conversation, id, author: "person", text });
  const finished = (conversation) => events.filter((e) => e.conversation === conversation && e.event.type === "turn_finished").length;
  const open = new Promise((resolve, reject) => { ws.on("open", resolve); ws.on("error", reject); });
  return { ws, call, hello, notify, say, finished, open, events, rejected, nullAnswers };
}
// (paired and granted, with one finished turn in conversation c1)
async function ready(h, { grant = GRANT } = {}) {
  const p = page(h.port);
  await p.open;
  const hello = await p.hello(h.code);
  if (grant) p.notify("grant.changed", grant);
  await until(() => !grant || h.server.binding?.grant, "the grant");
  p.say("c1", "Make a plot of the partial sums.\nDecision: plot with matplotlib, not plotly");
  await until(() => p.finished("c1") === 1, "the first turn");
  return { p, hello };
}

test("the hello offers chat.brief with Delegate and Claude; not without a task host, and not where Codex runs the chats", WIN_DELEGATE, async () => {
  for (const [opts, has] of [[{}, true], [{ tasks: false }, false], [{ backend: true }, false]]) {
    const h = await setup(opts);
    try {
      const p = page(h.port);
      await p.open;
      const hello = await p.hello(h.code);
      assert.equal(hello.result.features.includes("chat.brief"), has, JSON.stringify(opts));
      if (!has) {
        p.notify("grant.changed", GRANT);
        await until(() => h.server.binding?.grant, "the grant");
        const a = await p.call("chat.brief", { conversation: "c1" });
        assert.equal(code(a), "unavailable");
        assert.equal(a.error.message, opts.backend ? "drafting a brief needs a Claude chat in this version" : "this agent doesn't draft briefs over this connection");
      }
    } finally { await h.done(); }
  }
});

test("a brief: the draft forks the chat's session under a fresh id of ours, with no tools of any kind, one turn and the fixed prompt", WIN_DELEGATE, async () => {
  const h = await setup();
  try {
    const { p } = await ready(h);
    const pair = h.server.conversations.get("c1").sessionId;
    assert.equal(pair, "pair-1");
    const a = await p.call("chat.brief", { conversation: "c1" });
    assert.deepEqual(a.result, { title: "Plot the partial sums", brief: OUTLINED.slice(OUTLINED.indexOf("## Goal")), bytes: Buffer.byteLength(OUTLINED.slice(OUTLINED.indexOf("## Goal"))), cut: false });
    assert.equal(h.m.drafts.length, 1);
    const { options: o, text } = h.m.drafts[0];
    assert.equal(text, BRIEF_PROMPT);
    // (the option object exactly: nothing else, so nothing of a Pair turn's options came along)
    assert.deepEqual(Object.keys(o).sort(), ["abortController", "canUseTool", "cwd", "forkSession", "hooks", "maxTurns", "mcpServers", "permissionMode", "persistSession", "plugins", "resume", "sessionId", "settingSources", "settings", "strictMcpConfig", "tools"]);
    assert.equal(o.resume, pair);
    assert.equal(o.forkSession, true);
    assert.match(o.sessionId, UUID);
    assert.notEqual(o.sessionId, pair);
    assert.equal(o.persistSession, false);
    assert.deepEqual(o.tools, []);
    assert.deepEqual(o.mcpServers, {});
    assert.equal(o.strictMcpConfig, true);
    assert.deepEqual(o.settingSources, []);
    assert.deepEqual(o.plugins, []);
    assert.deepEqual(o.hooks, {});
    assert.equal(o.maxTurns, 1);
    assert.equal(o.permissionMode, "default");
    assert.deepEqual(o.settings, { disableAllHooks: true, autoMemoryEnabled: false, permissions: { defaultMode: "default", disableAutoMode: "disable", disableBypassPermissionsMode: "disable" } });
    assert.equal(o.cwd, h.server.dirOf(pair));
    // (canUseTool refuses anything at all: a built-in, a page tool, an MCP tool of anyone's)
    for (const t of ["Bash", "Read", "WebSearch", "mcp__sagebrush_page__workspace_read", "mcp__evil__x"]) {
      const v = await o.canUseTool(t, {}, { signal: new AbortController().signal });
      assert.equal(v.behavior, "deny", t);
    }
    // (the prompts are fixed: nothing of the page's in them)
    assert.doesNotMatch(BRIEF_PROMPT, /c1|partial sums|matplotlib/);
    // (the Pair session is unchanged: the conversation keeps its session, no turn event came from the draft, and
    //  the fork, and only the fork, was deleted, by our id, in the session's folder)
    assert.equal(h.server.conversations.get("c1").sessionId, pair);
    assert.equal(p.events.filter((e) => e.conversation === "c1" && e.event.type === "turn_started").length, 1);
    assert.deepEqual(h.m.deleted, [{ id: o.sessionId, dir: h.server.dirOf(pair) }]);
    assert.equal(h.server.counters().running, 0);
    // (the conversation goes on afterwards, from its own session)
    p.say("c1", "Thanks.");
    await until(() => p.finished("c1") === 2, "the next turn");
    assert.equal(h.m.chats.at(-1).options.resume, pair);
  } finally { await h.done(); }
});

test("bad requests: an id that isn't p<n>, params other than exactly {conversation}, a conversation id that isn't one", WIN_DELEGATE, async () => {
  const h = await setup();
  try {
    const { p } = await ready(h);
    p.ws.send(JSON.stringify({ jsonrpc: "2.0", id: "x1", method: "chat.brief", params: { conversation: "c1" } }));
    await until(() => p.nullAnswers.length === 1, "the id-null refusal");
    assert.equal(p.nullAnswers[0].error.data.code, "bad_request");
    for (const params of [{}, { conversation: "c1", extra: 1 }, { conversation: 7 }, { conversation: "" }, { conversation: "x".repeat(300) }, null, ["c1"]]) {
      assert.equal(code(await p.call("chat.brief", params)), "bad_request", JSON.stringify(params));
    }
    assert.equal(h.m.drafts.length, 0);
  } finally { await h.done(); }
});

test("not_found, unavailable (no grant; no session yet) and busy (a turn running; a draft running; the turn quota full)", WIN_DELEGATE, async () => {
  const h = await setup();
  try {
    // (no grant: nothing to draft for)
    const p0 = page(h.port);
    await p0.open;
    await p0.hello(h.code);
    const a0 = await p0.call("chat.brief", { conversation: "c1" });
    assert.equal(code(a0), "unavailable");
    assert.equal(a0.error.message, "the page has no grant: grant access, then ask again");
    p0.ws.close();
    await until(() => !h.server.sock, "the first page gone");
    h.code = h.server.newCode();
    const { p } = await ready(h);
    assert.equal(code(await p.call("chat.brief", { conversation: "nope" })), "not_found");
    // (a conversation whose only turn never got a session)
    p.say("c2", "fail before init");
    await until(() => p.finished("c2") === 1, "c2's failed turn");
    const a2 = await p.call("chat.brief", { conversation: "c2" });
    assert.equal(code(a2), "unavailable");
    assert.equal(a2.error.message, "this conversation has no session yet: send a message first");
    // (a turn running in the conversation)
    let release;
    h.m.hold = new Promise((r) => { release = r; });
    p.say("c1", "Another one.");
    await until(() => h.server.conversations.get("c1").running, "c1's turn running");
    const a3 = await p.call("chat.brief", { conversation: "c1" });
    assert.equal(code(a3), "busy");
    assert.equal(a3.error.message, "a turn is running in this conversation: wait for it, or Stop it");
    // (the turn quota: three more conversations running make four, RUNNING_MAX; a brief elsewhere waits its turn)
    for (const c of ["c3", "c4", "c5"]) p.say(c, "Hello.");
    await until(() => h.server.counters().running === 4, "four turns running");
    release();
    await until(() => h.server.counters().running === 0, "the turns ended");
    h.m.hold = null;
    // (a draft running: a second brief and a chat message to that conversation are both busy)
    let draftGo;
    h.m.draft = { text: OUTLINED, hold: new Promise((r) => { draftGo = r; }) };
    const first = p.call("chat.brief", { conversation: "c1" });
    await until(() => h.server.conversations.get("c1").drafting, "the draft running");
    assert.equal(code(await p.call("chat.brief", { conversation: "c1" })), "busy");
    p.say("c1", "While drafting.", "m-while");
    await until(() => p.rejected.some((r) => r.id === "m-while"), "the message refused");
    assert.deepEqual(p.rejected.find((r) => r.id === "m-while").reason, { code: "busy", message: "a brief is being drafted in this conversation: wait for it, or cancel it" });
    assert.equal(h.server.counters().running, 1, "the draft holds a running place");
    draftGo();
    assert.equal((await first).result.title, "Plot the partial sums");
    assert.equal(h.server.counters().running, 0);
  } finally { await h.done(); }
});

test("the turn quota is shared: with RUNNING_MAX turns running, a brief is busy, and a draft counts as a running turn", WIN_DELEGATE, async () => {
  const h = await setup();
  try {
    const { p } = await ready(h);
    let release;
    h.m.hold = new Promise((r) => { release = r; });
    for (const c of ["c2", "c3", "c4", "c5"]) p.say(c, "Hello.");
    await until(() => h.server.counters().running === 4, "four turns running");
    const a = await p.call("chat.brief", { conversation: "c1" });
    assert.equal(code(a), "busy");
    assert.equal(a.error.message, "the agent is running as many turns as it can: ask again in a moment");
    release();
    await until(() => h.server.counters().running === 0, "the turns ended");
    h.m.hold = null;
    // (and the other way: three turns and a draft running, a fifth conversation's message waits)
    let draftGo;
    h.m.draft = { text: OUTLINED, hold: new Promise((r) => { draftGo = r; }) };
    h.m.hold = new Promise((r) => { release = r; });
    for (const c of ["c2", "c3", "c4"]) p.say(c, "Again.");
    await until(() => h.server.counters().running === 3, "three turns running");
    const pending = p.call("chat.brief", { conversation: "c1" });
    await until(() => h.server.counters().running === 4, "the draft running too");
    p.say("c6", "Waiting.");
    await new Promise((r) => setTimeout(r, 100));
    assert.equal(h.server.counters().running, 4, "c6 waits: the draft holds a place");
    draftGo();
    assert.ok((await pending).result);
    release();
    await until(() => p.finished("c6") === 1, "c6 ran after the draft");
  } finally { await h.done(); }
});

test("Cancel (chat.brief_cancel) stops a draft: stopped; the fork is deleted; before the SDK's init too", WIN_DELEGATE, async () => {
  const h = await setup();
  try {
    const { p } = await ready(h);
    for (const beforeInit of [false, true]) {
      h.m.draft = beforeInit ? { text: OUTLINED, beforeInit: true } : { text: OUTLINED, hold: new Promise(() => {}) };
      const pending = p.call("chat.brief", { conversation: "c1" });
      await until(() => h.server.conversations.get("c1").drafting, "the draft running");
      const fork = h.server.conversations.get("c1").drafting.forkId;
      p.notify("chat.brief_cancel", { conversation: "c1" });
      const a = await pending;
      assert.equal(code(a), "stopped");
      assert.equal(a.error.message, "the draft was stopped");
      assert.deepEqual(h.m.deleted.at(-1), { id: fork, dir: h.server.dirOf("pair-1") });
      assert.equal(h.server.conversations.get("c1").drafting, null);
      assert.equal(h.server.counters().running, 0);
    }
    // (a cancel for a conversation with no draft, or of another page's: nothing)
    p.notify("chat.brief_cancel", { conversation: "c1" });
    p.notify("chat.brief_cancel", { conversation: "nope" });
    h.m.draft = { text: OUTLINED };
    assert.ok((await p.call("chat.brief", { conversation: "c1" })).result);
  } finally { await h.done(); }
});

test("the draft's own bound (60 s, shortened here): failed, with fixed words; the fork is deleted", WIN_DELEGATE, async () => {
  const h = await setup({ briefMs: 200 });
  try {
    const { p } = await ready(h);
    h.m.draft = { text: OUTLINED, hold: new Promise(() => {}) };
    const a = await p.call("chat.brief", { conversation: "c1" });
    assert.equal(code(a), "failed");
    assert.equal(a.error.message, "the draft took more than 60 seconds, so it was stopped");
    assert.equal(h.m.deleted.length, 1);
    assert.equal(h.m.deleted[0].id, h.m.drafts[0].options.sessionId);
  } finally { await h.done(); }
});

test("a rebind ends a draft and drops its result: a grant change, a revoke, the page going away; the fork is deleted each time", WIN_DELEGATE, async () => {
  const h = await setup();
  try {
    let { p } = await ready(h);
    for (const how of ["grant", "revoke", "close"]) {
      let go;
      h.m.draft = { text: OUTLINED, hold: new Promise((r) => { go = r; }) };
      let answered = false;
      p.call("chat.brief", { conversation: "c1" }).then(() => { answered = true; });
      await until(() => h.server.conversations.get("c1").drafting, "the draft running");
      const fork = h.server.conversations.get("c1").drafting.forkId;
      if (how === "grant") p.notify("grant.changed", { folders: ["/notes"], write: false, delegate: true });
      if (how === "revoke") p.notify("grant.changed", null);
      if (how === "close") p.ws.close();
      await until(() => !h.server.conversations.get("c1").drafting, `the draft ended (${how})`);
      go();
      await new Promise((r) => setTimeout(r, 100));
      assert.equal(answered, false, `no answer after ${how}`);
      assert.equal(h.m.deleted.at(-1).id, fork);
      assert.equal(h.server.counters().running, 0);
      if (how === "revoke") { p.notify("grant.changed", GRANT); await until(() => h.server.binding?.grant, "granted again"); }
      if (how === "close") {
        await until(() => !h.server.sock, "the page gone");
        h.code = h.server.newCode();
        p = page(h.port);
        await p.open;
        await p.hello(h.code);
        p.notify("grant.changed", GRANT);
        await until(() => h.server.binding?.grant, "granted on the new page");
      }
    }
    // (the conversation is still there, with its session: a new page's brief works)
    h.m.draft = { text: OUTLINED };
    assert.equal((await p.call("chat.brief", { conversation: "c1" })).result.title, "Plot the partial sums");
  } finally { await h.done(); }
});

test("failures say fixed words, never the model's text: an error, a non-success result, an empty answer", WIN_DELEGATE, async () => {
  const h = await setup();
  try {
    const { p } = await ready(h);
    for (const d of [{ error: "SECRET model text" }, { text: "x", result: { type: "result", subtype: "error_max_turns", is_error: true, result: "SECRET" } }, { text: "   " }]) {
      h.m.draft = d;
      const a = await p.call("chat.brief", { conversation: "c1" });
      assert.equal(code(a), "failed", JSON.stringify(d));
      assert.equal(a.error.message, "the brief couldn't be drafted");
      assert.doesNotMatch(JSON.stringify(a), /SECRET/);
    }
    assert.equal(h.m.deleted.length, 3, "the fork deleted after each");
    assert.equal(h.server.counters().running, 0);
  } finally { await h.done(); }
});

test("the caps: a title cut to 200 characters, a brief to 8 KiB with cut, an answer without the outline", WIN_DELEGATE, async () => {
  const h = await setup();
  try {
    const { p } = await ready(h);
    h.m.draft = { text: `Title: ${"é".repeat(250)}\n\n## Goal\n${"g".repeat(9000)}\n\n## Decisions made\nNone.\n\n## Files\nNone.\n\n## Done when\nok` };
    const a = (await p.call("chat.brief", { conversation: "c1" })).result;
    assert.equal([...a.title].length, 200);
    assert.equal(a.cut, true);
    assert.ok(a.brief.endsWith("[brief cut at 8 KiB]"));
    assert.equal(a.bytes, Buffer.byteLength(a.brief));
    assert.ok(a.bytes <= BRIEF_LIMITS.brief && a.bytes > BRIEF_LIMITS.brief - 64, String(a.bytes));
    h.m.draft = { text: "We should plot the sums.\nWith matplotlib." };
    assert.deepEqual((await p.call("chat.brief", { conversation: "c1" })).result, { title: "We should plot the sums.", brief: "We should plot the sums.\nWith matplotlib.", bytes: 41, cut: false });
  } finally { await h.done(); }
});

test("shapeBrief: the outline, its order, the fallbacks, well-formed text, and cuts at a character boundary", () => {
  assert.equal(shapeBrief(""), null);
  assert.equal(shapeBrief(" \n "), null);
  // (headings out of order, or one missing: not the outline; the whole answer is the brief)
  const swapped = OUTLINED.replace("## Files", "## X").replace("## Decisions made", "## Files").replace("## X", "## Decisions made");
  assert.equal(shapeBrief(swapped).brief, swapped);
  assert.equal(shapeBrief(swapped).title, "Plot the partial sums");
  assert.equal(shapeBrief(OUTLINED.replace("## Done when\n", "")).brief.startsWith("Title:"), true);
  // (an untitled outline, a heading as the first line, nothing usable)
  assert.equal(shapeBrief("Title:\n\n## Goal\ng\n## Decisions made\nd\n## Files\nf\n## Done when\nw").title, BRIEF_UNTITLED);
  assert.equal(shapeBrief("## Plan\nstuff").title, "Plan");
  assert.equal(shapeBrief("\u0007\u0001").title, BRIEF_UNTITLED);
  // (control characters out of a title; U+0000 and lone surrogates out of everything; CRLF as LF)
  assert.equal(shapeBrief("Title: a\tb\u0001c\r\n\r\n## Goal\r\ng\r\n## Decisions made\r\nd\r\n## Files\r\nf\r\n## Done when\r\nw").title, "a b c");
  const odd = shapeBrief("x\u0000y \ud800 z");
  assert.equal(odd.brief, "xy � z");
  // (a cut never splits a code point: 4-byte emoji)
  const emoji = "😀".repeat(3000);
  const r = shapeBrief(emoji);
  assert.equal(r.cut, true);
  assert.ok(r.brief.endsWith(BRIEF_CUT));
  assert.equal(r.brief.slice(0, -BRIEF_CUT.length).length % 2, 0);
  assert.doesNotMatch(r.brief, /[\ud800-\udbff](?![\udc00-\udfff])/);
  assert.equal(cutBytes("aé😀", 3), "aé");
  assert.equal(cutBytes("aé😀", 6), "aé");
  assert.equal(cutBytes("aé😀", 7), "aé😀");
});

test("the fake model's draft: the Goal is the person's first message, Decision: lines and named paths come along", async () => {
  // (a chat turn of the fake, read up to its init: what the person said is remembered for its session)
  const q = fakeQuery({ prompt: "Plot the partial sums in /notes/sums.ipynb.\nDecision: plot with matplotlib, not plotly", options: { resume: "S-brief", mcpServers: { sagebrush_page: { handlers: {} } } } });
  await q.next();
  const text = fakeBrief("S-brief");
  const shaped = shapeBrief(text);
  assert.equal(shaped.title, "Plot the partial sums in /notes/sums.ipynb.");
  assert.match(shaped.brief, /## Decisions made\n- plot with matplotlib, not plotly\n/);
  assert.match(shaped.brief, /## Files\n- \/notes\/sums\.ipynb\n/);
  // (and through fakeQuery as the agent calls it for a draft: no tools, forkSession)
  const draft = fakeQuery({ prompt: BRIEF_PROMPT, options: { resume: "S-brief", forkSession: true, sessionId: "f-1", tools: [], mcpServers: {} } });
  const msgs = [];
  for await (const m of draft) msgs.push(m);
  assert.equal(msgs[0].session_id, "f-1");
  assert.equal(msgs.at(-1).result, text);
});
