// The notebook read (#1503): the format the page side keeps too, pinned by a shared fixture (test/fixtures/nb-read/,
// copied byte for byte: a change to the format changes it on both sides). The bytes must be exact.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { cutText, ipynbDoc, notebookRead, READ_LIMITS } from "../lib/notebook-read.mjs";

const FIX = new URL("./fixtures/nb-read/", import.meta.url);
const file = (name) => readFileSync(new URL(name, FIX), "utf8");
const sha = (name) => createHash("sha256").update(readFileSync(new URL(name, FIX))).digest("hex");
const doc = JSON.parse(file("notebook.json"));
const path = "notes/fixture.ipynb";
const OVERSIZE = [["read", {}], ["from-1", { from: 1 }], ["from-2", { from: 2 }], ["from-3", { from: 3 }], ["cell-0", { cell: 0 }], ["cell-1", { cell: 1 }], ["cell-2", { cell: 2 }], ["cell-3", { cell: 3 }], ["cell-4", { cell: 4 }]];

test("the fixture is the shared one, byte for byte", () => {
  assert.deepEqual(["notebook.json", "expected-read.json", "expected-from.json", "expected-cell-1.json", "expected-cell-3.json"].map(sha), [
    "e3389bdca56e634c3a6a2848f5f0768a0f4f03e4b938bab5e35115f1aeb6eb81", "d0a817d6cdd983dd0a79a7477aa1eb7a63cd6bd40f710bdfc76b8e7cd4679800",
    "d52ef4ccc37bdb269aa59e7183e0eaff17e46e1fc5f704a2830eff5ea21a284b", "76b585b6a19d708350e2274ddb83542d72d31a9e740b59ef00cda2e847bb8563",
    "00b0ec21acf19241da3455ad35f61f378553adcd2d6d4e945b02a36a874f0b16"]);
});

test("v2's oversize fixture is the shared one, byte for byte", () => {
  assert.deepEqual(["oversize.json", ...OVERSIZE.map(([n]) => `expected-oversize-${n}.json`)].map(sha).map((h) => h.slice(0, 16)), [
    "c8700055c5b410b8", "e1eba1ccdea47612", "443fef404fbefeeb", "79f6109cb80c3388", "265185a8dbf798d1",
    "3abac03647384f05", "9b09e6ce3f768ae7", "babd1e80796b37b9", "39d21a1370def99f", "6964f88bd266ed27"]);
});

test("v2: the oversize document's nine reads give the fixture's exact bytes, each within 48 KiB as serialized", () => {
  const big = JSON.parse(file("oversize.json"));
  for (const [name, o] of OVERSIZE) {
    const got = notebookRead(big, { path: "notes/oversize.ipynb", ...o });
    assert.equal(got, file(`expected-oversize-${name}.json`), name);
    assert.ok(Buffer.byteLength(got) <= READ_LIMITS.total, `${name}: ${Buffer.byteLength(got)} bytes`);
  }
});

test("the four reads give the fixture's exact bytes: the whole notebook, from cell 10, cell 1 and cell 3", () => {
  assert.equal(notebookRead(doc, { path }), file("expected-read.json"));
  assert.equal(notebookRead(doc, { path, from: 10 }), file("expected-from.json"));
  assert.equal(notebookRead(doc, { path, cell: 1 }), file("expected-cell-1.json"));
  assert.equal(notebookRead(doc, { path, cell: 3 }), file("expected-cell-3.json"));
});

test("the bounds: the answer within 48 KiB less the reserve; no image data inlined; the first cell asked for is always shown", () => {
  const whole = notebookRead(doc, { path });
  assert.ok(Buffer.byteLength(whole) <= READ_LIMITS.total - READ_LIMITS.reserve + 80, "with its last sentence");
  assert.doesNotMatch(whole, /iVBORw0KGgo/, "no PNG data");
  const big = { mode: "python", cells: [{ id: "a", type: "code", code: "x".repeat(60000), outputs: [] }, { id: "b", type: "code", code: "y", outputs: [] }] };
  const r = JSON.parse(notebookRead(big, { path: "b.ipynb" }));
  assert.equal(r.cells.length, 2, "a 16 KiB source fits; both shown");
  assert.equal(r.cells[0].source.length, 16384);
  assert.equal(r.cells[0].cut, true);
  const many = { mode: "python", cells: Array.from({ length: 10 }, (_, i) => ({ id: `c${i}`, type: "code", code: "z".repeat(16000), outputs: [] })) };
  const m = JSON.parse(notebookRead(many, { path: "m.ipynb" }));
  assert.equal(m.cells.length, 3);
  assert.match(m.note, /Cells 3-9 not shown: read them with \{path, from: 3\}\.$/);
  assert.equal(JSON.parse(notebookRead(many, { path: "m.ipynb", from: 9 })).cells.length, 1);
});

test("a cell that isn't there, and an empty notebook", () => {
  for (const [o, n] of [[{ cell: 99 }, 99], [{ cell: -1 }, -1], [{ from: 13 }, 13], [{ cell: 1.5 }, 1.5]]) {
    assert.equal(JSON.parse(notebookRead(doc, { path, ...o })).error, `no cell ${n}: the notebook has 13 cells (0 to 12)`);
  }
  assert.deepEqual(JSON.parse(notebookRead({ mode: "sage", cells: [] }, { path: "e.ipynb" })).cells, []);
});

test("cutText cuts at a code point's end; ipynbDoc reads an .ipynb into the read's form", () => {
  assert.deepEqual(cutText("aé€😀", 3), { text: "aé", cut: true });
  assert.deepEqual(cutText("aé€😀", 6), { text: "aé€", cut: true });
  assert.deepEqual(cutText("abc", 3), { text: "abc", cut: false });
  const nb = { cells: [{ cell_type: "markdown", id: "m", metadata: {}, source: ["# T", "itle"] }, { cell_type: "code", id: "c", metadata: {}, source: "x = 1", outputs: [{ output_type: "stream", name: "stdout", text: ["1\n"] }], execution_count: 1 }], metadata: { kernelspec: { name: "sagemath" } }, nbformat: 4, nbformat_minor: 5 };
  assert.deepEqual(ipynbDoc(JSON.stringify(nb)), { mode: "sage", cells: [{ id: "m", type: "markdown", code: "# Title" }, { id: "c", type: "code", code: "x = 1", outputs: [{ output_type: "stream", name: "stdout", text: ["1\n"] }] }] });
  for (const t of ["not json", "{}", "[1]", "null"]) assert.equal(ipynbDoc(t), null, t);
});
