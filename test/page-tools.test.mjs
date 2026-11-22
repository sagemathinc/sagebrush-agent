// 0.5.0: the branch and run tools (git_branch, git_commit, git_status, git_wait, run_notebook, run_file, run_stop,
// latex_build), each calling the page's verb of the same name: their words and parameters as the page's, their
// timers, the agent's own run_stop, latex_build's pages, the page's errors, and the grant.
import { test, mock } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import * as sdk from "@anthropic-ai/claude-agent-sdk";
import { fakeCreateServer, fakeQuery } from "../lib/fake.mjs";
import { AgentServer, VERSION } from "../lib/server.mjs";
import { BUSY_LINE, PAGE_TEXT, PAGE_TOOL_VERBS, PAGE_VERBS, RUN_VERBS, isPng } from "../lib/page-tools.mjs";

// (the page's words for these verbs, as copied from its schema.json at the verbs' head: the page's repository checks
//  this same file against its schema.json; a change to either side is a change to review)
const PAGE_VERBS_SHA = "431a67a7c594944d2b024b3e1a734f360253f4f7c2e75925ed6c3e18826bf8ce";
const tick = () => new Promise((r) => setImmediate(r));
const until = async (f) => { for (let i = 0; i < 200 && !f(); i++) await tick(); assert.ok(f(), "waited for it"); };

/** A server bound to a fake page that records what it's sent and answers when told. */
function setup({ requestsTaken = 0, features = [], turnId = null } = {}) {
  const server = new AgentServer({ query: fakeQuery, log: () => {}, stdio: true });
  let spec;
  server.createServer = (s) => { spec = s; return fakeCreateServer(s); };
  const ws = { readyState: 1, sent: [], send(s) { this.sent.push(JSON.parse(s)); return "ok"; } };
  const binding = { ws, grant: { folders: ["/"], write: true }, features };
  server.binding = binding;
  server.sock = ws;
  for (let i = 0; i < requestsTaken; i++) server.pending.set(`x${i}`, { binding, resolve() {}, reject() {} });
  const ac = new AbortController();
  const tools = server.workspaceTools("c1", server.conversation("c1"), binding, ac.signal, null, turnId).handlers;
  const msg = (method) => ws.sent.filter((m) => m.method === method);
  const answer = (m, result) => server.dispatch(ws, { jsonrpc: "2.0", id: m.id, result });
  const fail = (m, message, code = "invalid") => server.dispatch(ws, { jsonrpc: "2.0", id: m.id, error: { code: -32000, message, data: { code, message } } });
  return { server, ws, binding, ac, tools, spec: () => spec, msg, answer, fail };
}
const done = async (s) => { for (const k of [...s.server.pending.keys()]) if (k.startsWith("x")) s.server.pending.delete(k); await s.server.close(); };
const text = (r) => r.content.map((c) => (c.type === "text" ? c.text : `[${c.type}]`)).join("\n");

// ---- row 1 (and 9): the tools as advertised: names, descriptions, JSON schemas, the busy line ------------------------

test("row 1: the vendored page-verbs.json is the reviewed copy (its sha256), with exactly the 8 verbs", () => {
  const bytes = readFileSync(new URL("../lib/page-verbs.json", import.meta.url));
  assert.equal(createHash("sha256").update(bytes).digest("hex"), PAGE_VERBS_SHA);
  assert.deepEqual(Object.keys(PAGE_VERBS).sort(), PAGE_TOOL_VERBS.map((v) => "workspace." + v).sort());
});

test("row 1 + 9: the 8 tools as the SDK advertises them: the page's description (the 3 run tools then the busy line, the others nothing more), and the page's JSON schema, closed", async () => {
  const s = setup();
  const spec = s.spec();
  const server = sdk.createSdkMcpServer({ name: spec.name, version: spec.version, tools: spec.tools.map(([n, d, sh, h]) => sdk.tool(n, d, sh, h)) });
  const listed = (await server.instance.server._requestHandlers.get("tools/list")({ method: "tools/list", params: {} }, {})).tools;
  const byName = Object.fromEntries(listed.map((t) => [t.name, t]));
  for (const verb of PAGE_TOOL_VERBS) {
    const t = byName["workspace_" + verb], page = PAGE_VERBS["workspace." + verb];
    assert.ok(t, verb);
    assert.equal(t.description, RUN_VERBS.includes(verb) ? `${page.description} ${BUSY_LINE}` : page.description, verb);
    assert.equal(t.description.includes(BUSY_LINE), RUN_VERBS.includes(verb), `${verb}: the busy line on the run tools only`);
    // (the page's schema, closed; zod writes its own $schema, and no "required" when it is empty (the page writes []):
    //  the only differences, said here. Integers have no upper bound, as on the page.)
    const { $schema: _a, ...want } = page.params;
    const { $schema: _b, ...got } = t.inputSchema;
    const req = (o) => (Array.isArray(o.required) && o.required.length === 0 ? (({ required, ...r }) => r)(o) : o);
    assert.deepEqual(req(got), req(want), verb);
    assert.equal(JSON.stringify(got).includes("maximum"), false, `${verb}: no upper bound the page doesn't have`);
    assert.equal(got.additionalProperties, false, verb);
  }
  await done(s);
});

// ---- row 2: what each tool sends ---------------------------------------------------------------------------------------

test("row 2: each tool sends exactly its page verb with the model's arguments, byte for byte", async () => {
  const s = setup();
  const args = {
    git_branch: { name: "fix-1" }, git_commit: { name: "fix-1", message: "Fix the sum\n\nand its test", review: true }, git_status: { name: "fix-1" },
    git_wait: { name: "fix-1", seconds: 7 }, run_notebook: { path: "/Branches/fix-1/Ännu nötbok.ipynb", timeout_s: 9 }, run_file: { path: "/a/ü.py" },
    run_stop: {}, latex_build: { path: "/p/main.tex", pages: [2, 1], timeout_s: 30 },
  };
  for (const verb of PAGE_TOOL_VERBS) {
    const n = s.ws.sent.length;
    const p = s.tools["workspace_" + verb](args[verb]);
    await tick();
    assert.equal(s.ws.sent.length, n + 1, verb);
    const m = s.ws.sent.at(-1);
    assert.equal(m.method, "workspace." + verb);
    assert.equal(JSON.stringify(m.params), JSON.stringify(args[verb]), `${verb}: the arguments as given`);
    s.answer(m, { ok: true });
    await p;
  }
  await done(s);
});

test("row 2b: run.context: where the page said it, each run says its chat and turn after the model's arguments; run_stop and the other tools never; without the page's feature or a turn, nothing added", async () => {
  const args = { run_notebook: { path: "/n.ipynb", timeout_s: 9 }, run_file: { path: "/a.py" }, latex_build: { path: "/p.tex" }, run_stop: {}, git_status: { name: "fix-1" } };
  const sent = async (s, verb) => {
    const n = s.ws.sent.length;
    const p = s.tools["workspace_" + verb](args[verb]);
    await tick();
    assert.equal(s.ws.sent.length, n + 1, verb);
    const m = s.ws.sent.at(-1);
    s.answer(m, { ok: true });
    await p;
    return JSON.stringify(m.params);
  };
  const on = setup({ features: ["run.context"], turnId: "turn-abc" });
  for (const verb of ["run_notebook", "run_file", "latex_build"]) assert.equal(await sent(on, verb), JSON.stringify({ ...args[verb], conversation: "c1", turn_id: "turn-abc" }), verb);
  for (const verb of ["run_stop", "git_status"]) assert.equal(await sent(on, verb), JSON.stringify(args[verb]), verb);
  await done(on);
  for (const o of [{ features: [], turnId: "turn-abc" }, { features: ["run.context"], turnId: null }]) {
    const s = setup(o);
    assert.equal(await sent(s, "run_notebook"), JSON.stringify(args.run_notebook), JSON.stringify(o));
    await done(s);
  }
});

test("row 2: an unknown key, or a required one missing, is refused by the schema and nothing is sent", async () => {
  const s = setup();
  const spec = s.spec();
  const server = sdk.createSdkMcpServer({ name: spec.name, version: spec.version, tools: spec.tools.map(([n, d, sh, h]) => sdk.tool(n, d, sh, h)) });
  const call = (name, a) => server.instance.server._requestHandlers.get("tools/call")({ method: "tools/call", params: { name, arguments: a } }, { signal: new AbortController().signal, requestId: 1, sendNotification: async () => {}, sendRequest: async () => {} });
  for (const [name, a] of [["workspace_git_branch", { name: "a", extra: 1 }], ["workspace_git_commit", { name: "a" }], ["workspace_run_file", {}], ["workspace_run_stop", { now: true }], ["workspace_latex_build", { path: "/a.tex", pages: [] }], ["workspace_git_branch", { name: "Bad Name" }]]) {
    const r = await call(name, a);
    assert.equal(r.isError, true, JSON.stringify(a));
    assert.match(r.content[0].text, /Input validation error/);
  }
  assert.equal(s.ws.sent.length, 0, "nothing sent");
  await done(s);
});

test("row 3: through the SDK's own call path, timeout_s 10^20 and seconds 10^9 reach the page as given and get its refusal; 1.5 and 0 are refused by the schema", async () => {
  const s = setup();
  const spec = s.spec();
  const server = sdk.createSdkMcpServer({ name: spec.name, version: spec.version, tools: spec.tools.map(([n, d, sh, h]) => sdk.tool(n, d, sh, h)) });
  const call = (name, a) => server.instance.server._requestHandlers.get("tools/call")({ method: "tools/call", params: { name, arguments: a } }, { signal: new AbortController().signal, requestId: 1, sendNotification: async () => {}, sendRequest: async () => {} });
  for (const [name, a, refusal] of [["workspace_run_file", { path: "/a.py", timeout_s: 1e20 }, "timeout_s is 1 to 600"], ["workspace_git_wait", { name: "b", seconds: 1e9 }, "git_wait's seconds are 1 to 50"]]) {
    const n = s.ws.sent.length;
    const p = call(name, a);
    await until(() => s.ws.sent.length === n + 1);
    const m = s.ws.sent.at(-1);
    assert.equal(JSON.stringify(m.params), JSON.stringify(a), `${name}: sent as given`);
    s.fail(m, refusal);
    assert.equal(text(await p), "refused: " + refusal);
  }
  const n = s.ws.sent.length;
  for (const t of [1.5, 0]) assert.equal((await call("workspace_run_file", { path: "/a.py", timeout_s: t })).isError, true, String(t));
  assert.equal(s.ws.sent.length, n, "nothing sent for 1.5 or 0");
  await done(s);
});

// ---- row 3: the timers --------------------------------------------------------------------------------------------------

/** Mock timers, with the live ones counted (so a row can say none are left). */
function clock() {
  mock.timers.enable({ apis: ["setTimeout"] });
  const live = new Set(), st = globalThis.setTimeout, ct = globalThis.clearTimeout;
  globalThis.setTimeout = (f, ms, ...a) => { const id = st(() => { live.delete(id); f(...a); }, ms); live.add(id); return id; };
  globalThis.clearTimeout = (id) => { live.delete(id); ct(id); };
  return { live, at: async (ms) => { mock.timers.tick(ms); await tick(); }, off: () => { globalThis.setTimeout = st; globalThis.clearTimeout = ct; mock.timers.reset(); } };
}

test("row 3: a call's own timer: a run's timeout_s + 30 s (120 s if left out), git_wait's seconds + 30 s (50 if left out), other calls 120 s", async () => {
  const cases = [
    ["run_notebook", { path: "/n.ipynb", timeout_s: 300 }, 330_000],
    ["run_file", { path: "/a.py" }, 150_000],
    ["latex_build", { path: "/m.tex", timeout_s: 600 }, 630_000],
    ["git_wait", { name: "b" }, 80_000],
    ["git_wait", { name: "b", seconds: 10 }, 40_000],
    ["git_status", { name: "b" }, 120_000],
  ];
  for (const [verb, a, ms] of cases) {
    const c = clock();
    const s = setup();
    try {
      let settled = null;
      s.tools["workspace_" + verb](a).then((r) => (settled = r));
      await c.at(ms - 100);
      assert.equal(settled, null, `${verb} ${JSON.stringify(a)}: still waiting at ${ms - 100} ms`);
      await c.at(100);
      await tick();
      assert.ok(settled, `${verb}: ended at ${ms} ms`);
      assert.equal(text(settled), "refused: the page didn't answer");
    } finally { c.off(); }
    await done(s);
  }
  // (and workspace_read, as before)
  const c = clock(), s = setup();
  try {
    let settled = null;
    s.tools.workspace_read({ path: "/a.md" }).then((r) => (settled = r));
    await c.at(119_900);
    assert.equal(settled, null);
    await c.at(100);
    await tick();
    assert.equal(text(settled), "refused: the page didn't answer");
  } finally { c.off(); }
  await done(s);
});

test("row 3: a timeout_s or seconds past the page's bound is sent as given (the page refuses it), its timer capped and finite", async () => {
  const c = clock(), s = setup();
  try {
    const p1 = s.tools.workspace_run_file({ path: "/a.py", timeout_s: 9007199254740991 });
    const p2 = s.tools.workspace_git_wait({ name: "b", seconds: 1_000_000_000 });
    await tick();
    const [m1, m2] = s.ws.sent;
    assert.equal(m1.params.timeout_s, 9007199254740991);
    assert.equal(m2.params.seconds, 1_000_000_000);
    assert.ok([...c.live].length >= 2, "both timers set");
    s.fail(m1, "timeout_s is 1 to 600");
    s.fail(m2, "git_wait's seconds are 1 to 50");
    assert.equal(text(await p1), "refused: timeout_s is 1 to 600");
    assert.equal(text(await p2), "refused: git_wait's seconds are 1 to 50");
    // (and the caps themselves: a run's timer at 630 s, a wait's at 80 s, whatever the argument)
    let r3 = null, r4 = null;
    s.tools.workspace_run_file({ path: "/a.py", timeout_s: 9007199254740991 }).then((r) => (r3 = r));
    s.tools.workspace_git_wait({ name: "b", seconds: 1_000_000_000 }).then((r) => (r4 = r));
    // (both sides: an uncapped timer would overflow setTimeout's 2^31 - 1 ms and end the call at once)
    await c.at(79_900);
    assert.ok(r4 === null && r3 === null, "both still waiting at 79.9 s");
    await c.at(100);
    await tick();
    assert.ok(r4 && r3 === null, "the wait ended at 80 s, the run not yet");
    await c.at(549_900);
    assert.equal(r3, null, "the run still waiting at 629.9 s");
    await c.at(100);
    await tick();
    assert.ok(r3, "the run ended at 630 s");
  } finally { c.off(); }
  await done(s);
});

// ---- row 4: the agent's own run_stop -------------------------------------------------------------------------------------

test("row 4: the turn stopped during a run: one run_stop on the run's binding, the call rejects \"the turn was stopped\"; a second stop sends nothing", async () => {
  const c = clock(), s = setup();
  try {
    const p = s.tools.workspace_run_notebook({ path: "/n.ipynb" });
    await tick();
    s.ac.abort();
    assert.equal(text(await p), "refused: the turn was stopped");
    await tick();
    assert.equal(s.msg("workspace.run_stop").length, 1);
    s.ac.abort();
    await tick();
    assert.equal(s.msg("workspace.run_stop").length, 1, "still one");
    s.answer(s.msg("workspace.run_stop")[0], { stopped: true });
    await tick();
    assert.equal(s.server.pending.size, 0);
    assert.equal(c.live.size, 0, "no timers left");
  } finally { c.off(); }
  await done(s);
});

test("row 4: a run call's own timer ends: one run_stop, and the call rejects with exactly \"the page didn't answer\"", async () => {
  const c = clock(), s = setup();
  try {
    let r = null;
    s.tools.workspace_latex_build({ path: "/m.tex", timeout_s: 10 }).then((x) => (r = x));
    await c.at(40_000);
    await tick();
    assert.equal(text(r), "refused: the page didn't answer");
    assert.equal(s.msg("workspace.run_stop").length, 1);
    // (a run_stop the page never answers is dropped within 5 s)
    await c.at(5_000);
    await tick();
    assert.equal(s.server.pending.size, 0, "the run_stop dropped");
    assert.equal(c.live.size, 0, "no timers left");
    assert.equal(s.msg("workspace.run_stop").length, 1, "never sent again");
  } finally { c.off(); }
  await done(s);
});

test("row 4: no run_stop when no run is in flight, after the run answered, or for a call that isn't a run", async () => {
  const c = clock(), s = setup();
  try {
    s.ac.abort(); // (nothing in flight)
    await tick();
    const s2 = setup();
    const p = s2.tools.workspace_run_file({ path: "/a.py" });
    await tick();
    s2.answer(s2.ws.sent[0], { ended: "done", exit: 0 });
    await p;
    s2.ac.abort();
    await c.at(200_000);
    const s3 = setup();
    s3.tools.workspace_git_wait({ name: "b" });
    await tick();
    s3.ac.abort();
    await tick();
    for (const x of [s, s2, s3]) assert.equal(x.msg("workspace.run_stop").length, 0);
    await done(s2);
    await done(s3);
  } finally { c.off(); }
  await done(s);
});

test("row 4: rebound before the stop: no run_stop on the old binding or the new one; the call rejects as any call does", async () => {
  const c = clock(), s = setup();
  try {
    const p = s.tools.workspace_run_notebook({ path: "/n.ipynb" });
    await tick();
    const ws2 = { readyState: 1, sent: [], send(x) { this.sent.push(JSON.parse(x)); return "ok"; } };
    s.server.rebind({ ws: ws2, grant: { folders: ["/"], write: true }, gen: 99 }, "the grant changed");
    assert.equal(text(await p), "refused: the grant changed");
    s.ac.abort();
    await c.at(200_000);
    assert.equal(s.msg("workspace.run_stop").length, 0);
    assert.equal(ws2.sent.length, 0);
  } finally { c.off(); }
  await done(s);
});

test("row 4: rebound with the run's turn running: the rebind cancels the turn before it rejects the call, so the stop comes while the new binding is current; no run_stop on the old binding or the new one", async () => {
  const c = clock(), s = setup();
  try {
    // (the conversation's running turn, as runTurn sets it: the rebind cancels it, which aborts the turn's signal)
    s.server.conversations.get("c1").running = { binding: s.binding, cancel: () => s.ac.abort() };
    const p = s.tools.workspace_run_notebook({ path: "/n.ipynb" });
    await tick();
    const ws2 = { readyState: 1, sent: [], send(x) { this.sent.push(JSON.parse(x)); return "ok"; } };
    s.server.rebind({ ws: ws2, grant: { folders: ["/"], write: true }, gen: 99 }, "the grant changed");
    assert.equal(text(await p), "refused: the turn was stopped");
    await c.at(200_000);
    assert.equal(s.msg("workspace.run_stop").length, 0, "none on the old binding");
    assert.equal(ws2.sent.filter((m) => m.method === "workspace.run_stop").length, 0, "none on the new one");
    s.server.conversations.get("c1").running = null;
  } finally { c.off(); }
  await done(s);
});

test("row 4: run_stop takes a request place like any call: sent when one is free, never queued when all are taken", async () => {
  const c = clock(), s = setup({ requestsTaken: 31 });
  try {
    // (the run holds the 32nd place; stopped, its own place is given back first, so its run_stop has one)
    const p = s.tools.workspace_run_file({ path: "/a.py" });
    await tick();
    assert.equal(s.server.pending.size, 32);
    s.ac.abort();
    await p;
    await tick();
    assert.equal(s.msg("workspace.run_stop").length, 1, "one place free: sent");
    // (all 32 taken by other calls when a run's timer ends: none sent, nothing waits to send it later)
    const s2 = setup({ requestsTaken: 31 });
    let r = null;
    s2.tools.workspace_run_file({ path: "/a.py", timeout_s: 1 }).then((x) => (r = x));
    await tick();
    s2.server.pending.set("x-late", { binding: s2.binding, resolve() {}, reject() {} });
    await c.at(31_000);
    await tick();
    assert.ok(r);
    assert.equal(s2.msg("workspace.run_stop").length, 0, "32 taken when it ended: no run_stop");
    s2.server.pending.delete("x-late");
    await c.at(10_000);
    assert.equal(s2.msg("workspace.run_stop").length, 0, "and none later, when a place frees");
    await done(s2);
  } finally { c.off(); }
  await done(s);
});

// ---- row 5: latex_build's pages ------------------------------------------------------------------------------------------

const PNG_B64 = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13, 73, 72, 68, 82]).toString("base64");
const latex = async (result) => {
  const s = setup();
  const p = s.tools.workspace_latex_build({ path: "/m.tex" });
  await tick();
  s.answer(s.ws.sent[0], result);
  const r = await p;
  await done(s);
  return r;
};

test("row 5: two good pages: two PNG image blocks, and the text with each page's n, w and h, no png and no base64", async () => {
  const r = await latex({ ended: "done", report: { problems: [] }, pages: [{ n: 1, w: 10, h: 20, png: PNG_B64 }, { n: 2, w: 11, h: 21, png: PNG_B64 }] });
  const images = r.content.filter((c) => c.type === "image");
  assert.equal(images.length, 2);
  for (const i of images) { assert.equal(i.mimeType, "image/png"); assert.equal(i.data, PNG_B64); }
  const t = JSON.parse(r.content[0].text);
  assert.deepEqual(t.pages, [{ n: 1, w: 10, h: 20 }, { n: 2, w: 11, h: 21 }]);
  assert.equal(r.content[0].text.includes(PNG_B64), false);
  assert.equal(r.content[0].text.includes('"png"'), false);
});

test("row 5: a JPEG, a 4-byte prefix of the signature, and invalid base64: each left out with its exact line", async () => {
  const jpeg = Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0, 16, 74, 70, 73, 70, 0, 1]).toString("base64");
  const prefix4 = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0, 0, 0, 0, 0, 0, 0, 0]).toString("base64");
  const bad = PNG_B64.slice(0, -2) + "!=";
  const r = await latex({ pages: [{ n: 1, w: 1, h: 1, png: jpeg }, { n: 2, w: 1, h: 1, png: prefix4 }, { n: 3, w: 1, h: 1, png: bad }, { n: 4, w: 1, h: 1, png: PNG_B64 }] });
  assert.deepEqual(r.content.slice(1).map((c) => c.type === "text" ? c.text : c.type), [PAGE_TEXT.notPng(1), PAGE_TEXT.notPng(2), PAGE_TEXT.notPng(3), "image"]);
  assert.equal(PAGE_TEXT.notPng(2), "Page 2: the page sent an image that isn't a PNG, so it was left out.");
  assert.equal(isPng(PNG_B64), true);
});

test("row 5: base64url ('-' or '_') in an otherwise valid PNG: left out with its line", async () => {
  const long = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Buffer.alloc(24, 0xff)]).toString("base64");
  for (const ch of ["-", "_"]) {
    const bad = long.slice(0, 16) + ch + long.slice(17);
    const r = await latex({ pages: [{ n: 1, w: 1, h: 1, png: bad }] });
    assert.deepEqual(r.content.slice(1), [{ type: "text", text: PAGE_TEXT.notPng(1) }], ch);
  }
});

test("row 5: the 256 KiB edge: an answer of exactly 262,144 bytes as JSON is used; 262,145 is refused whole", async () => {
  const sized = (bytes) => { const base = { report: "", pages: [{ n: 1, w: 1, h: 1, png: PNG_B64 }] }; base.report = "x".repeat(bytes - Buffer.byteLength(JSON.stringify(base))); assert.equal(Buffer.byteLength(JSON.stringify(base)), bytes); return base; };
  const at = await latex(sized(262_144));
  assert.equal(at.isError, undefined);
  assert.equal(at.content.filter((c) => c.type === "image").length, 1);
  const over = await latex(sized(262_145));
  assert.equal(over.isError, true);
  assert.deepEqual(over.content, [{ type: "text", text: PAGE_TEXT.tooLarge }]);
});

test("row 5: an answer over 256 KiB, or with 5 pages, is refused whole with its exact line, nothing converted", async () => {
  const line = "The page's answer was too large to pass on (over 256 KiB, or more than 4 pages), so none of it was used.";
  const big = await latex({ pages: [{ n: 1, w: 1, h: 1, png: PNG_B64 + "A".repeat(256 * 1024) }] });
  const five = await latex({ pages: [1, 2, 3, 4, 5].map((n) => ({ n, w: 1, h: 1, png: PNG_B64 })) });
  for (const r of [big, five]) { assert.equal(r.isError, true); assert.deepEqual(r.content, [{ type: "text", text: line }]); }
});

// ---- row 6: the page's errors reach the model as its text ----------------------------------------------------------------

test("row 6: the page's refusals reach the model as its own text", async () => {
  const s = setup();
  for (const [verb, a, message] of [
    ["git_branch", { name: "x" }, 'not a verb: "workspace.git_branch"'],
    ["run_file", { path: "/a.py" }, 'this grant doesn\'t allow running code: ask the person to check "May run code"'],
    ["run_file", { path: "/a.py", timeout_s: 601 }, "timeout_s is 1 to 600"],
    ["git_wait", { name: "b", seconds: 51 }, "git_wait's seconds are 1 to 50"],
    ["run_notebook", { path: "/n.ipynb" }, "busy: your run of /n.ipynb is still going; wait for it or call workspace.run_stop"],
  ]) {
    const p = s.tools["workspace_" + verb](a);
    await tick();
    s.fail(s.ws.sent.at(-1), message);
    assert.equal(text(await p), "refused: " + message);
  }
  assert.equal(s.msg("workspace.run_stop").length, 0, "a refusal is an answer: no run_stop");
  await done(s);
});

// ---- row 7: allowed while bound ------------------------------------------------------------------------------------------

test("row 7: all 8 allowed without a card while bound; after the grant changes, each denied and nothing sent", async () => {
  const s = setup();
  for (const verb of PAGE_TOOL_VERBS) {
    const r = await s.server.decide(s.binding, () => {}, "mcp__sagebrush_page__workspace_" + verb, {}, {}, "c1");
    assert.equal(r.behavior, "allow", verb);
  }
  s.server.rebind({ ws: s.ws, grant: { folders: ["/"], write: true }, gen: 2 }, "the grant changed");
  for (const verb of PAGE_TOOL_VERBS) {
    const r = await s.server.decide(s.binding, () => {}, "mcp__sagebrush_page__workspace_" + verb, {}, {}, "c1");
    assert.deepEqual(r, { behavior: "deny", message: "The page disconnected or the grant changed." }, verb);
  }
  const n = s.ws.sent.length;
  const r = await s.tools.workspace_run_file({ path: "/a.py" });
  assert.equal(text(r), "refused: the page disconnected or the grant changed");
  assert.equal(s.ws.sent.length, n, "nothing sent on the old binding");
  await done(s);
});

test("row 8: VERSION is 0.8.9", () => assert.equal(VERSION, "0.8.9"));
