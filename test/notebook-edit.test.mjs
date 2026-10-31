// A12 step 1, the helper's side of an edit by cell (cases E7a, E11h, E17, plus the hash rule shared with the page):
// workspace_edit_notebook only for a page that offers notebook.edit, from a read held here (its ref and each cell's
// hash), the read spent by the edit; workspace_write_notebook create-only with such a page. A fake page; no
// Anthropic calls.
import assert from "node:assert/strict";
import { test } from "node:test";
import WebSocket from "ws";
import { z } from "zod";
import { fakeCreateServer, fakeQuery } from "../lib/fake.mjs";
import { canonical, cellHash } from "../lib/notebook.mjs";
import { AgentServer } from "../lib/server.mjs";

const ORIGIN = "https://agents.sagebrush.cloud";
const GRANT = { folders: ["/"], write: true, expires: null };
const NB = { mode: "python", cells: [{ id: "a", code: "1+1", outputs: [{ output_type: "execute_result", data: { "text/plain": "2" }, execution_count: 1 }], n: 1 }, { id: "b", type: "markdown", code: "# t" }] };

// A fake page: one notebook at /n.ipynb (ref R1), and whether it offers notebook.edit.
async function paired({ features = true } = {}) {
  const server = new AgentServer({ query: fakeQuery, log: () => {} });
  server.createServer = fakeCreateServer;
  const port = await server.listen();
  const code = server.newCode();
  const ws = new WebSocket(`ws://127.0.0.1:${port}/sagebrush`, { origin: ORIGIN });
  const files = new Map([["/n.ipynb", { content: { json: structuredClone(NB) }, rev: 1, ref: "R1" }]]);
  const asked = [];
  let hello;
  ws.on("message", (d) => {
    const m = JSON.parse(d.toString());
    if (m.id === "p1") return hello?.(m);
    if (typeof m.id !== "string" || !m.method) return;
    asked.push({ method: m.method, params: m.params });
    const p = m.params, f = files.get(p.path);
    const reply = (result) => ws.send(JSON.stringify({ jsonrpc: "2.0", id: m.id, result }));
    const fail = (c, message) => ws.send(JSON.stringify({ jsonrpc: "2.0", id: m.id, error: { code: -32000, message, data: { code: c, message } } }));
    if (m.method === "workspace.read") return f ? reply({ entry: { path: p.path, kind: "notebook" }, rev: f.rev, content: f.content, ...(features ? { ref: f.ref } : {}) }) : fail("missing", "missing");
    if (m.method === "workspace.create") return f ? fail("exists", `${p.path} is there already`) : (files.set(p.path, { content: p.content, rev: 1, ref: "R2" }), reply({ entry: { path: p.path } }));
    if (m.method === "workspace.stat") return reply({ entry: f ? { path: p.path } : null });
    if (m.method === "notebook.edit") return reply({ ok: true, inserted: [] });
    reply({});
  });
  await new Promise((r, j) => { ws.on("open", r); ws.on("error", j); });
  const h = await new Promise((resolve) => { hello = resolve; ws.send(JSON.stringify({ jsonrpc: "2.0", id: "p1", method: "hello", params: { protocol: 1, code, page: { origin: ORIGIN, path: "/agents/" } } })); });
  ws.send(JSON.stringify({ jsonrpc: "2.0", method: "grant.changed", params: GRANT }));
  if (features) ws.send(JSON.stringify({ jsonrpc: "2.0", method: "page.features", params: { features: ["notebook.edit"] } }));
  await until(() => server.binding?.grant && (!features || server.binding.features));
  const c = {};
  const tools = () => server.workspaceTools("c1", c, server.binding, undefined);
  const close = async () => { ws.close(); await server.close(); };
  return { server, ws, files, asked, hello: h, tools, close };
}
const until = async (f, ms = 5000) => {
  const t = Date.now();
  while (!f()) {
    if (Date.now() - t > ms) throw new Error("timed out");
    await new Promise((r) => setTimeout(r, 20));
  }
};

test("the hash rule: canonical JSON (keys in order), sha256 of its UTF-8, the same for any key order", () => {
  assert.equal(canonical({ b: 1, a: [2, { d: null, c: "é" }], u: undefined }), '{"a":[2,{"c":"é","d":null}],"b":1}');
  assert.equal(cellHash({ id: "a", code: "x" }), cellHash({ code: "x", id: "a" }));
  assert.notEqual(cellHash({ id: "a", code: "x" }), cellHash({ id: "a", code: "y" }));
  assert.match(cellHash(NB.cells[0]), /^[0-9a-f]{64}$/);
  // (in the notebook's own form: a cell a save only re-formed hashes the same; a change of its content doesn't)
  assert.equal(cellHash({ id: "a", type: "code", code: "x", n: 1, outputs: [] }), cellHash({ id: "a", code: "x", n: "1", outputs: [], metadata: null }));
  assert.equal(cellHash({ id: "a", type: "code", code: "x" }), cellHash({ id: "a", code: "x", outputs: [], n: null }));
  assert.notEqual(cellHash({ id: "a", code: "x", n: "1", outputs: [] }), cellHash({ id: "a", code: "x", n: "2", outputs: [] }));
  assert.notEqual(cellHash({ id: "b", type: "markdown", code: "x" }), cellHash({ id: "b", code: "x" }));
});

test("E17 (helper): the hello says notebook.edit; the edit tool only for a page that offers it, and write_notebook as today without it", async () => {
  const off = await paired({ features: false });
  try {
  assert.deepEqual(off.hello.result.features, ["notebook.edit"]);
  assert.equal("workspace_edit_notebook" in off.tools().handlers, false);
  // (an old page: write_notebook on an existing path still asks for a base, as before)
  const w = await off.tools().handlers.workspace_write_notebook({ path: "/n.ipynb", mode: "python", cells: [] });
  assert.match(w.content[0].text, /already exists\. Read it with workspace_read, then call workspace_write_notebook again with base/);
  } finally { await off.close(); }
  const on = await paired();
  try { assert.equal("workspace_edit_notebook" in on.tools().handlers, true); } finally { await on.close(); }
});

test("E7a: an edit only from a read held here (its base), with the read's ref and each named cell's hash; the read is spent", async () => {
  const p = await paired();
  try {
  const t = p.tools();
  const edit = (a) => t.handlers.workspace_edit_notebook({ path: "/n.ipynb", ...a });
  // no read yet: refused here, nothing asked of the page
  const none = await edit({ base: 1, set: [{ id: "a", source: "2+2" }] });
  assert.equal(none.isError, true);
  assert.match(none.content[0].text, /no read of \/n\.ipynb at revision 1/);
  assert.ok(!p.asked.some((a) => a.method === "notebook.edit"));
  await t.handlers.workspace_read({ path: "/n.ipynb" });
  // a base that isn't the read's: refused
  const other = await edit({ base: 0, set: [{ id: "a", source: "2+2" }] });
  assert.equal(other.isError, true);
  const ok = await edit({ base: 1, set: [{ id: "a", source: "2+2" }], insert: [{ source: "3", after: "b" }] });
  assert.equal(ok.isError, undefined);
  const sent = p.asked.find((a) => a.method === "notebook.edit").params;
  assert.equal(sent.conversation, "c1");
  assert.equal(sent.ref, "R1");
  assert.equal(sent.base, 1);
  assert.deepEqual(sent.set, [{ id: "a", source: "2+2" }]);
  assert.deepEqual(sent.was, { a: cellHash(NB.cells[0]), b: cellHash(NB.cells[1]) });
  // spent: the same base again is refused (read again first)
  const again = await edit({ base: 1, set: [{ id: "a", source: "4" }] });
  assert.equal(again.isError, true);
  assert.equal(p.asked.filter((a) => a.method === "notebook.edit").length, 1);
  } finally { await p.close(); }
});

test("E11h: an extra field anywhere in an edit is refused by the tool's schema (strict), before the page", async () => {
  const p = await paired();
  try {
  const shape = z.object(p.tools().shapes.workspace_edit_notebook);
  assert.equal(shape.safeParse({ path: "/n.ipynb", base: 1, set: [{ id: "a", source: "x" }] }).success, true);
  for (const bad of [
    { path: "/n.ipynb", base: 1, set: [{ id: "a", source: "x", outputs: [] }] },
    { path: "/n.ipynb", base: 1, insert: [{ source: "x", after: null, id: "z" }] },
    { path: "/n.ipynb", base: 1, set: [{ id: "a", type: "raw" }] },
    { path: "/n.ipynb", base: 1, insert: [{ source: "x" }] },
  ]) assert.equal(shape.safeParse(bad).success, false, JSON.stringify(bad));
  } finally { await p.close(); }
});

test("E12 (helper): with such a page, write_notebook only creates: an existing path is refused by the page's create, and says how to edit", async () => {
  const p = await paired();
  try {
  const r = await p.tools().handlers.workspace_write_notebook({ path: "/n.ipynb", mode: "python", cells: [{ type: "code", source: "x" }], base: 1 });
  assert.equal(r.isError, true);
  assert.match(r.content[0].text, /use workspace_edit_notebook/);
  assert.ok(!p.asked.some((a) => a.method === "workspace.write"));
  assert.equal(p.files.get("/n.ipynb").content.json.cells[0].code, "1+1");
  const made = await p.tools().handlers.workspace_write_notebook({ path: "/m.ipynb", mode: "python", cells: [{ type: "code", source: "x" }] });
  assert.equal(made.isError, undefined);
  } finally { await p.close(); }
});
