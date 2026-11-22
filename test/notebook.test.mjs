// Notebooks for the agent: the tool's closed grammar and bounds, the base rule, the read summarized for the model, and
// the end-to-end path with a fake page and the fake model. No Anthropic calls.
import assert from "node:assert/strict";
import { test } from "node:test";
import WebSocket from "ws";
import { fakeCreateServer, fakeQuery } from "../lib/fake.mjs";
import { NOTEBOOK_LIMITS, notebookDoc } from "../lib/notebook.mjs";
import { AgentServer } from "../lib/server.mjs";

const ORIGIN = "https://agents.sagebrush.cloud";
const GRANT = { folders: ["/"], write: true, expires: null };

// A PNG's first bytes (signature + IHDR for 640×480), then filler: base64.
function png(width, height, bytes) {
  const b = Buffer.alloc(bytes);
  Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13, 0x49, 0x48, 0x44, 0x52]).copy(b, 0);
  b.writeUInt32BE(width, 16);
  b.writeUInt32BE(height, 20);
  return b.toString("base64");
}

test("notebookDoc: a closed grammar with bounds", () => {
  const ok = notebookDoc({ mode: "sage", cells: [{ type: "code", source: "1+1" }, { type: "markdown", source: "# t" }] });
  assert.equal(ok.mode, "sage");
  // (every language a Sagebrush notebook runs: MATLAB's and Magma's too)
  for (const mode of ["python", "matlab", "magma"]) {
    const d = notebookDoc({ mode, cells: [{ type: "code", source: mode === "matlab" ? "x = linspace(0, 3, 200); plot(x, sin(x.^2))" : "1+1" }] });
    assert.equal(d.mode, mode);
    assert.equal(d.cells.length, 1);
  }
  assert.deepEqual(ok.cells.map((c) => [c.type ?? "code", c.code]), [["code", "1+1"], ["markdown", "# t"]]);
  assert.equal(new Set(ok.cells.map((c) => c.id)).size, 2);
  for (const [bad, why] of [
    [{ mode: "julia", cells: [] }, /mode/],
    [{ mode: "python", cells: [{ type: "raw", source: "" }] }, /type/],
    [{ mode: "python", cells: [{ type: "code", source: "x", outputs: [] }] }, /unknown field "outputs"/],
    [{ mode: "python", cells: [{ type: "code" }] }, /source/],
    [{ mode: "python", cells: "x" }, /list/],
    [{ mode: "python", cells: Array.from({ length: NOTEBOOK_LIMITS.cells + 1 }, () => ({ type: "code", source: "" })) }, /at most 200 cells/],
    [{ mode: "python", cells: [{ type: "code", source: "x".repeat(NOTEBOOK_LIMITS.sourceBytes + 1) }] }, /bytes of source/],
    [{ mode: "python", cells: Array.from({ length: 17 }, () => ({ type: "code", source: "x".repeat(NOTEBOOK_LIMITS.sourceBytes) })) }, /over 4194304 bytes/],
  ]) {
    const r = notebookDoc(bad);
    assert.ok(r instanceof Error, JSON.stringify(bad).slice(0, 80));
    assert.match(r.message, why);
  }
});

// ART-C7: the cap is on what is returned (wrappers, labels, notes and metadata summaries included), not on text alone.
const bytes = (v) => Buffer.byteLength(JSON.stringify(v));
const readOf = (cells, extra = {}) => ({ entry: { path: "/n.ipynb" }, rev: 3, content: { json: { mode: "python", ...extra, cells } } });
const allSources = (r) => r.content.json.cells.map((c) => c.code).join("");

// A fake page that keeps documents ({json}) and texts, and records every request.
async function paired() {
  const server = new AgentServer({ query: fakeQuery, log: () => {} });
  server.createServer = fakeCreateServer;
  const port = await server.listen();
  const code = server.newCode();
  const ws = new WebSocket(`ws://127.0.0.1:${port}/sagebrush`, { origin: ORIGIN });
  const files = new Map(); // path -> {content, rev}
  const events = [];
  const asked = [];
  let hello;
  ws.on("message", (d) => {
    const m = JSON.parse(d.toString());
    if (m.id === "p1") return hello?.(m);
    if (m.method === "turn.event") return events.push(m.params);
    if (typeof m.id !== "string" || !m.method) return;
    asked.push({ method: m.method, params: m.params });
    const p = m.params;
    const reply = (result) => ws.send(JSON.stringify({ jsonrpc: "2.0", id: m.id, result }));
    const fail = (code, message) => ws.send(JSON.stringify({ jsonrpc: "2.0", id: m.id, error: { code: -32000, message, data: { code, message } } }));
    const f = files.get(p.path);
    if (m.method === "workspace.stat") return reply({ entry: f ? { path: p.path } : null });
    if (m.method === "workspace.create") { if (f) return fail("exists", "exists"); files.set(p.path, { content: p.content, rev: 1 }); return reply({ entry: { path: p.path } }); }
    if (m.method === "workspace.write") { if (!f) return fail("missing", "missing"); if (p.base !== f.rev) return fail("conflict", "conflict"); files.set(p.path, { content: p.content, rev: f.rev + 1 }); return reply({ entry: { path: p.path }, rev: f.rev + 1 }); }
    if (m.method === "workspace.read") return f ? reply({ entry: { path: p.path, kind: "notebook" }, rev: f.rev, content: f.content }) : fail("missing", "missing");
    reply({});
  });
  await new Promise((r, j) => { ws.on("open", r); ws.on("error", j); });
  await new Promise((resolve) => { hello = resolve; ws.send(JSON.stringify({ jsonrpc: "2.0", id: "p1", method: "hello", params: { protocol: 1, code, page: { origin: ORIGIN, path: "/agents/" } } })); });
  ws.send(JSON.stringify({ jsonrpc: "2.0", method: "grant.changed", params: GRANT }));
  const say = (id, text) => ws.send(JSON.stringify({ jsonrpc: "2.0", method: "chat.message", params: { conversation: "c1", id, author: "person", text } }));
  return { server, ws, files, events, asked, say };
}
const until = async (f, ms = 5000) => {
  const t = Date.now();
  while (!f()) {
    if (Date.now() - t > ms) throw new Error("timed out");
    await new Promise((r) => setTimeout(r, 20));
  }
};
const finished = (p, n) => until(() => p.events.filter((e) => e.event.type === "turn_finished").length >= n);

test("a notebook end to end: created as a {json} document, a notebook artifact, read back summarized; changing it needs a base; nothing runs", async () => {
  const p = await paired();
  p.say("u1", "make a notebook");
  await finished(p, 1);
  const create = p.asked.find((a) => a.method === "workspace.create");
  assert.equal(create.params.path, "/notes/plot.ipynb");
  assert.equal(create.params.mode, "python");
  assert.deepEqual(Object.keys(create.params.content), ["json"]);
  assert.equal(create.params.content.json.cells.length, 2);
  assert.equal(create.params.content.json.cells[0].type, "markdown");
  const art = p.events.find((e) => e.event.type === "artifact").event;
  assert.equal(art.kind, "notebook");
  assert.equal(art.path, "/notes/plot.ipynb");
  assert.equal(p.events.filter((e) => e.event.type === "tool_call_finished").map((e) => e.event.status).join(), "ok,ok");
  // the person ran it: outputs with a 2 MB picture; the agent's read is shortened, the file isn't
  const f = p.files.get("/notes/plot.ipynb");
  f.content.json.cells[1].outputs = [{ output_type: "display_data", data: { "image/png": png(640, 480, 2 * 1024 * 1024) } }];
  p.say("u2", "make a notebook again");
  await finished(p, 2);
  const turn2 = p.events.filter((e) => e.turn_id === p.events.at(-1).turn_id);
  const [write2, read2] = turn2.filter((e) => e.event.type === "tool_call_finished").map((e) => e.event);
  assert.equal(write2.status, "error");
  assert.match(write2.body, /already exists\. Read it with workspace_read, then call workspace_write_notebook again with base/);
  assert.equal(read2.status, "ok");
  // (the shared read format: the picture as its kind, type and decoded size, never its data; and the revision, for a base)
  assert.match(read2.body, /"outputs":\[\{"kind":"image","mime":"image\/png","bytes":2097152\}\]/);
  assert.match(read2.body, /revision 1/);
  assert.doesNotMatch(read2.body, /iVBORw0KGgo/);
  assert.ok(read2.body.length < 16 * 1024);
  assert.ok(p.files.get("/notes/plot.ipynb").content.json.cells[1].outputs[0].data["image/png"].length > 1024 * 1024); // (the file is as it was)
  assert.ok(!p.asked.some((a) => a.method === "workspace.write")); // (no write without base)
  // no request to run anything, ever: the daemon has no such verb
  assert.ok(!p.asked.some((a) => /run|execute/i.test(a.method)));
  p.ws.close();
  await p.server.close();
});

test("workspace_write_notebook: a stale base is refused by the page; a path that isn't .ipynb is refused here", async () => {
  const p = await paired();
  p.say("u1", "make a notebook");
  await finished(p, 1);
  const tools = p.server.workspaceTools("c1", {}, p.server.binding, undefined);
  const call = (name, a) => tools.handlers[name](a);
  const stale = await call("workspace_write_notebook", { path: "/notes/plot.ipynb", mode: "python", cells: [], base: 99 });
  assert.equal(stale.isError, true);
  assert.match(stale.content[0].text, /conflict/);
  const wrong = await call("workspace_write_notebook", { path: "/notes/plot.md", mode: "python", cells: [] });
  assert.equal(wrong.isError, true);
  assert.match(wrong.content[0].text, /ends in \.ipynb/);
  const good = await call("workspace_write_notebook", { path: "/notes/plot.ipynb", mode: "python", cells: [{ type: "code", source: "2+2" }], base: 1 });
  assert.equal(good.isError, undefined);
  assert.equal(p.files.get("/notes/plot.ipynb").rev, 2);
  p.ws.close();
  await p.server.close();
});
