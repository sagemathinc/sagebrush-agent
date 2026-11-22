// Notebooks for the agent: the document workspace_write_notebook builds (a closed grammar, bounded), and a cell's hash
// for an edit by cell. What a read of a notebook returns to the model is notebook-read.mjs.

import { createHash, randomBytes } from "node:crypto";

export const NOTEBOOK_LIMITS = Object.freeze({
  cells: 200, // cells in one write
  sourceBytes: 256 * 1024, // one cell's source
  totalBytes: 4 * 1024 * 1024, // all sources together
});

// (the languages a Sagebrush notebook runs, its mode)
const MODES = new Set(["python", "sage", "matlab", "magma"]);
const TYPES = new Set(["code", "markdown"]);
const utf8 = (s) => Buffer.byteLength(s, "utf8");

/** The notebook document for `{mode, cells: [{type, source}]}`, or an Error saying what isn't allowed. */
export function notebookDoc(args) {
  if (!args || typeof args !== "object" || Array.isArray(args)) return new Error("arguments must be an object");
  const { mode, cells } = args;
  if (!MODES.has(mode)) return new Error(`mode must be "python", "sage", "matlab" or "magma"`);
  if (!Array.isArray(cells)) return new Error("cells must be a list");
  if (cells.length > NOTEBOOK_LIMITS.cells) return new Error(`at most ${NOTEBOOK_LIMITS.cells} cells in one notebook (${cells.length} given)`);
  let total = 0;
  const out = [];
  const ids = new Set();
  for (const [i, c] of cells.entries()) {
    if (!c || typeof c !== "object" || Array.isArray(c)) return new Error(`cell ${i + 1} must be {type, source}`);
    const extra = Object.keys(c).filter((k) => k !== "type" && k !== "source");
    if (extra.length) return new Error(`cell ${i + 1}: unknown field ${JSON.stringify(extra[0])} (only type and source)`);
    if (!TYPES.has(c.type)) return new Error(`cell ${i + 1}: type must be "code" or "markdown"`);
    if (typeof c.source !== "string") return new Error(`cell ${i + 1}: source must be text`);
    const n = utf8(c.source);
    if (n > NOTEBOOK_LIMITS.sourceBytes) return new Error(`cell ${i + 1}: ${n} bytes of source, at most ${NOTEBOOK_LIMITS.sourceBytes}`);
    total += n;
    if (total > NOTEBOOK_LIMITS.totalBytes) return new Error(`the notebook's sources are over ${NOTEBOOK_LIMITS.totalBytes} bytes`);
    let id;
    do id = "c" + randomBytes(6).toString("hex"); while (ids.has(id));
    ids.add(id);
    out.push(c.type === "code" ? { id, code: c.source } : { id, type: "markdown", code: c.source });
  }
  return { mode, cells: out };
}

// A cell's hash for an edit by cell (A12 step 1): its whole JSON, every object's keys in order, so the page
// (web/workspace/notebook-edit.ts cellHash, the same rule) and this helper hash a cell alike.
export function canonical(v) {
  if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
  if (v && typeof v === "object") return `{${Object.keys(v).sort().filter((k) => v[k] !== undefined).map((k) => `${JSON.stringify(k)}:${canonical(v[k])}`).join(",")}}`;
  return JSON.stringify(v) ?? "null";
}
// A cell in the form the notebook keeps it (web/notebook/notebook.js snapshot; web/workspace/notebook-edit.ts cellForm,
// the same rule): a code cell's type implicit, its count as text, empty fields left out.
export function cellForm(c) {
  const type = c?.type ?? "code";
  const out = { id: c?.id, ...(type === "code" ? {} : { type }), code: c?.code ?? "" };
  if (type === "code") {
    out.outputs = Array.isArray(c?.outputs) ? c.outputs : [];
    out.n = c?.n === null || c?.n === undefined ? null : String(c.n);
    if (c?.ms !== null && c?.ms !== undefined) out.ms = c.ms;
  }
  if (type === "markdown" && c?.attachments) out.attachments = c.attachments;
  if (c?.metadata) out.metadata = c.metadata;
  return out;
}
export const cellHash = (cell) => createHash("sha256").update(canonical(cellForm(cell)), "utf8").digest("hex");
