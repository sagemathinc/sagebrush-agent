// Notebooks for the agent: the tool's closed grammar and bounds, the base rule, the read shortened for the model, and
// the end-to-end path with a fake page and the fake model. No Anthropic calls.
import assert from "node:assert/strict";
import { test } from "node:test";
import WebSocket from "ws";
import { fakeCreateServer, fakeQuery } from "../lib/fake.mjs";
import { NOTEBOOK_LIMITS, notebookDoc, shortNotebookRead, chargedBytes } from "../lib/notebook.mjs";
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

test("shortNotebookRead: pictures named, text cut at the cap on a character boundary, the file's entry and rev unchanged", () => {
  const cap = NOTEBOOK_LIMITS.outputBytes;
  const atCap = "a".repeat(cap);
  const overCap = "b".repeat(cap + 1);
  const multi = "c".repeat(cap - 1) + "é" + "dd"; // ("é" is 2 bytes: it straddles the cap)
  const read = {
    entry: { path: "/n.ipynb", kind: "notebook" },
    rev: 7,
    content: { json: { mode: "python", cells: [
      { id: "a", code: "plot()", outputs: [{ output_type: "display_data", data: { "image/png": png(640, 480, 2 * 1024 * 1024), "text/plain": "<Figure>" } }] },
      { id: "b", code: "print", outputs: [{ output_type: "stream", name: "stdout", text: atCap }, { output_type: "stream", name: "stdout", text: overCap }] },
      { id: "c", code: "m", outputs: [{ output_type: "execute_result", data: { "text/plain": multi } }] },
      { id: "d", code: "boom", outputs: [{ output_type: "error", ename: "ValueError", evalue: "bad", traceback: ["line 1"] }] },
      { id: "e", code: "no outputs" },
    ] } },
  };
  const before = JSON.stringify(read);
  const r = shortNotebookRead(read);
  assert.equal(JSON.stringify(read), before); // (the input isn't changed)
  assert.deepEqual(r.entry, read.entry);
  assert.equal(r.rev, 7);
  const cells = r.content.json.cells;
  assert.match(cells[0].outputs[0].data["image/png"], /^\[image\/png, 640×480, \d+ bytes omitted\]$/);
  assert.equal(cells[0].outputs[0].data["text/plain"], "<Figure>");
  assert.equal(cells[1].outputs[0].text, atCap); // (exactly at the cap: kept whole)
  assert.equal(cells[1].outputs[1].text, "b".repeat(cap) + "…[1 more bytes]");
  assert.equal(cells[2].outputs[0].data["text/plain"], "c".repeat(cap - 1) + "…[4 more bytes]"); // (cut before "é", not inside it)
  assert.match(cells[3].outputs[0].text, /^ValueError: bad\nline 1$/);
  assert.equal(cells[4].outputs, undefined);
  assert.ok(Buffer.byteLength(JSON.stringify(r)) < 64 * 1024);
});

test("shortNotebookRead: the whole read is bounded; later cells' outputs are omitted and say so", () => {
  const big = "x".repeat(NOTEBOOK_LIMITS.outputBytes);
  const n = Math.ceil(NOTEBOOK_LIMITS.readBytes / NOTEBOOK_LIMITS.outputBytes) + 5;
  const read = { entry: {}, rev: 1, content: { json: { cells: Array.from({ length: n }, (_, i) => ({ id: `c${i}`, code: "", outputs: [{ output_type: "stream", text: big }] })) } } };
  const r = shortNotebookRead(read);
  assert.match(r.content.json.note, /limit of 262144 bytes for outputs was reached at cell \d+/);
  assert.ok(chargedBytes(r) <= NOTEBOOK_LIMITS.readBytes, `charged ${chargedBytes(r)}`);
});

// ART-C7: the cap is on what is returned (wrappers, labels, notes and metadata summaries included), not on text alone.
const bytes = (v) => Buffer.byteLength(JSON.stringify(v));
const readOf = (cells, extra = {}) => ({ entry: { path: "/n.ipynb" }, rev: 3, content: { json: { mode: "python", ...extra, cells } } });
const allSources = (r) => r.content.json.cells.map((c) => c.code).join("");

test("shortNotebookRead: 8000 empty outputs are charged by their serialized bytes and stop at the cap", () => {
  const read = readOf(Array.from({ length: 40 }, (_, i) => ({ id: `c${i}`, code: "pass", outputs: Array.from({ length: 200 }, () => ({ output_type: "stream", name: "stdout", text: "" })) })));
  assert.ok(bytes(read.content.json.cells.map((c) => c.outputs)) > NOTEBOOK_LIMITS.readBytes); // (the counterexample: over the cap with no text at all)
  const r = shortNotebookRead(read);
  assert.ok(chargedBytes(r) <= NOTEBOOK_LIMITS.readBytes, `charged ${chargedBytes(r)}`);
  assert.match(r.content.json.note, /limit of 262144 bytes for outputs was reached at cell \d+/);
  assert.equal(r.content.json.cells.length, 40); // (every cell's source is still there)
  assert.equal(allSources(r), "pass".repeat(40));
  assert.equal(r.rev, 3);
});

test("shortNotebookRead: 200 cells of one 2000-byte output each: wrappers and commas charged, the cap held exactly", () => {
  const read = readOf(Array.from({ length: 200 }, (_, i) => ({ id: `c${i}`, code: "", outputs: [{ output_type: "stream", name: "stdout", text: "z".repeat(2000) }] })), { autorun: "always" });
  const r = shortNotebookRead(read);
  const charged = chargedBytes(r);
  assert.ok(charged <= NOTEBOOK_LIMITS.readBytes, `charged ${charged}`);
  // (and it fills the cap: one more cell's output would not have fit)
  assert.ok(charged > NOTEBOOK_LIMITS.readBytes - 2100, `charged only ${charged}`);
  assert.match(r.content.json.note, /reached at cell \d+/);
  assert.match(r.content.json.metadata, /^\[the notebook's metadata, \d+ bytes omitted\]$/);
});

test("shortNotebookRead: at the exact cap, over many cell and output shapes", () => {
  for (const n of [1, 7, 33, 150, 400]) for (const len of [0, 1, 500, 2000, 9000]) for (const per of [1, 3]) {
    const read = readOf(Array.from({ length: n }, (_, i) => ({ id: `c${i}`, code: "x", ...(i % 5 === 0 ? { metadata: { k: "v".repeat(50) } } : {}), outputs: Array.from({ length: per }, () => ({ output_type: "stream", name: "stdout", text: "é".repeat(len) })) })), { seed: "s" });
    const charged = chargedBytes(shortNotebookRead(read));
    assert.ok(charged <= NOTEBOOK_LIMITS.readBytes, `n=${n} len=${len} per=${per}: charged ${charged}`);
  }
});

test("shortNotebookRead: one output's text alternatives share one allowance", () => {
  const t = "y".repeat(NOTEBOOK_LIMITS.outputBytes);
  const r = shortNotebookRead(readOf([{ id: "a", code: "x", outputs: [{ output_type: "execute_result", data: { "text/plain": t, "text/markdown": t, "text/latex": t } }] }]));
  const d = r.content.json.cells[0].outputs[0].data;
  const kept = ["text/plain", "text/markdown", "text/latex"].map((m) => d[m].replace(/…\[\d+ more bytes\]$/, "")).join("");
  assert.equal(Buffer.byteLength(kept), NOTEBOOK_LIMITS.outputBytes, "8 KiB in all, not 8 KiB each");
  assert.equal(d["text/latex"], `…[${NOTEBOOK_LIMITS.outputBytes} more bytes]`);
});

test("shortNotebookRead: multibyte text and JSON escapes are charged as returned", () => {
  const nasty = "\u0001".repeat(40000) + "é".repeat(40000); // (each \u0001 is 6 bytes once serialized)
  const read = readOf(Array.from({ length: 60 }, (_, i) => ({ id: `c${i}`, code: "", outputs: [{ output_type: "stream", name: "stdout", text: nasty }] })));
  const r = shortNotebookRead(read);
  assert.ok(chargedBytes(r) <= NOTEBOOK_LIMITS.readBytes, `charged ${chargedBytes(r)}`);
  for (const c of r.content.json.cells) for (const o of c.outputs ?? []) assert.ok(!/\uFFFD/.test(o.text)); // (never cut inside a character)
});

test("shortNotebookRead: cell and notebook metadata are summarized, not returned", () => {
  const meta = { tags: ["t".repeat(300000)] };
  const r = shortNotebookRead(readOf([{ id: "a", code: "1", metadata: meta, attachments: { "x.png": { "image/png": "A".repeat(100000) } }, outputs: [{ output_type: "execute_result", metadata: meta, data: { "text/plain": "1" } }] }], { autorun: "always", seed: "s".repeat(500000) }));
  const json = r.content.json;
  assert.match(json.metadata, /^\[the notebook's metadata, \d+ bytes omitted\]$/);
  assert.match(json.cells[0].other, /^\[other fields of this cell, \d+ bytes omitted\]$/);
  assert.match(json.cells[0].outputs[0].metadata, /^\[metadata, \d+ bytes omitted\]$/);
  assert.equal(json.cells[0].outputs[0].data["text/plain"], "1");
  assert.ok(bytes(r) < 4096, `returned ${bytes(r)}`);
});

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

test("a notebook end to end: created as a {json} document, a notebook artifact, read back shortened; changing it needs a base; nothing runs", async () => {
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
  assert.match(read2.body, /\[image\/png, 640×480, \d+ bytes omitted\]/);
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
  const tools = p.server.workspaceTools({}, p.server.binding, undefined);
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
