// Notebooks for the agent: the document workspace_write_notebook builds (a closed grammar, bounded), and a read of a
// notebook shortened for the model (outputs cut, pictures named, never the file itself changed).

import { createHash, randomBytes } from "node:crypto";

export const NOTEBOOK_LIMITS = Object.freeze({
  cells: 200, // cells in one write
  sourceBytes: 256 * 1024, // one cell's source
  totalBytes: 4 * 1024 * 1024, // all sources together
  outputBytes: 8 * 1024, // one output's text in a read, for the model
  readBytes: 256 * 1024, // all outputs of a read together, for the model
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

// (cut text to at most `max` UTF-8 bytes, on a character boundary)
function cutBytes(s, max) {
  const b = Buffer.from(s, "utf8");
  if (b.length <= max) return { text: s, cut: 0 };
  let end = max;
  while (end > 0 && (b[end] & 0xc0) === 0x80) end--; // (not inside a multi-byte character)
  return { text: b.subarray(0, end).toString("utf8"), cut: b.length - end };
}

const joined = (v) => (Array.isArray(v) ? v.join("") : typeof v === "string" ? v : "");

function pictureSize(mime, data) {
  if (mime === "image/png" && typeof data === "string") {
    try {
      const b = Buffer.from(data.slice(0, 64), "base64"); // (the IHDR chunk is in the first 24 bytes)
      if (b.length >= 24 && b.toString("latin1", 12, 16) === "IHDR") return `${b.readUInt32BE(16)}×${b.readUInt32BE(20)}, `;
    } catch { /* (not base64: no size) */ }
  }
  return "";
}

// What a read of a notebook returns to the model (ART-C7):
// - every cell's source, whole, and its frame ({id, type}, the id cut to 64 characters): not charged to the cap below
//   (the model edits the notebook from them; the page's frame limit bounds the read);
// - everything else (outputs, with their wrappers, MIME labels and omission notes; cell fields other than id, type
//   and code; the document's fields other than mode) is charged by its serialized bytes against readBytes. Once
//   that is spent, no more outputs are returned: each cell says how many it left out, and the read says so too;
// - one output's text, over all its text alternatives together, is at most outputBytes.
const ID_MAX = 64;
const TEXT_MIMES = new Set(["text/plain", "text/markdown", "text/latex"]);
const size = (v) => utf8(JSON.stringify(v));

/** One output as the model reads it, its text (all its text alternatives together) at most `allow` bytes. */
function shortOutput(o, allow) {
  if (!o || typeof o !== "object" || Array.isArray(o)) return "[an output in an unknown form]";
  const take = (s) => {
    const { text, cut } = cutBytes(s, Math.max(0, allow));
    allow -= utf8(text);
    return cut ? `${text}…[${cut} more bytes]` : text;
  };
  if (o.output_type === "stream") return { output_type: "stream", name: String(o.name ?? "").slice(0, 16), text: take(joined(o.text)) };
  if (o.output_type === "error") return { output_type: "error", text: take(`${o.ename ?? "Error"}: ${o.evalue ?? ""}\n${joined(o.traceback)}`) };
  const data = o.data && typeof o.data === "object" && !Array.isArray(o.data) ? o.data : {};
  const shown = {};
  for (const [mime, v] of Object.entries(data)) {
    const label = mime.slice(0, 64);
    if (TEXT_MIMES.has(mime)) shown[label] = take(joined(v));
    else {
      const raw = typeof v === "string" ? v : JSON.stringify(v ?? "");
      shown[label] = `[${label}, ${pictureSize(mime, raw)}${utf8(raw)} bytes omitted]`;
    }
  }
  const out = { output_type: String(o.output_type ?? "").slice(0, 32), data: shown };
  if (o.metadata && typeof o.metadata === "object" && Object.keys(o.metadata).length) out.metadata = `[metadata, ${size(o.metadata)} bytes omitted]`;
  return out;
}

/** One output within `budget` serialized bytes (its text cut further if need be), or null if even the shortest
 * form of it doesn't fit. */
function fitOutput(o, budget) {
  let allow = Math.min(NOTEBOOK_LIMITS.outputBytes, budget);
  for (let i = 0; i < 8 && allow >= 0; i++) {
    const out = shortOutput(o, allow);
    const n = size(out);
    if (n <= budget) return { out, n };
    allow -= n - budget + 16; // (JSON escaping can make text longer than its bytes: cut again by the excess)
  }
  return null;
}

// (the bytes `,"key":value` adds to an object that has a key already: what adding a field to a cell or the read costs)
const field = (key, value) => utf8("," + JSON.stringify(key) + ":" + JSON.stringify(value));

/** A workspace.read result of a notebook, shortened for the model: entry and rev exactly as read. Everything but each
 * cell's frame ({id, type, code}) and the document's mode is charged exactly, field by field, against readBytes
 * (ART-C7 r3): the outputs lists and their commas, the outputs, the omission counts, the cells' other fields, and the
 * read's metadata summary and note. */
export function shortNotebookRead(r) {
  const doc = r?.content?.json;
  if (!doc || typeof doc !== "object" || !Array.isArray(doc.cells)) return r;
  const { cells: list, mode, ...meta } = doc;
  const metaNote = Object.keys(meta).length ? `[the notebook's metadata, ${size(meta)} bytes omitted]` : null;
  const noteFor = (i) => `[the read's limit of ${NOTEBOOK_LIMITS.readBytes} bytes for outputs was reached at cell ${i + 1}: from there on, outputs and other cell fields aren't shown]`;
  // (the read's own fields first: the metadata summary, and room for the note at the largest cell number it can name)
  let budget = NOTEBOOK_LIMITS.readBytes - (metaNote ? field("metadata", metaNote) : 0) - field("note", noteFor(list.length));
  let spentAt = -1; // (the first cell whose outputs or fields didn't all fit: from it on, none are returned)
  const cells = list.map((c, i) => {
    if (!c || typeof c !== "object" || Array.isArray(c)) return { code: "" };
    const { id, type, code, outputs, ...other } = c;
    const cell = { ...(typeof id === "string" ? { id: id.slice(0, ID_MAX) } : {}), ...(type === "markdown" || type === "raw" ? { type } : {}), code: typeof code === "string" ? code : "" };
    if (spentAt >= 0) return cell;
    if (Object.keys(other).length) {
      const note = `[other fields of this cell, ${size(other)} bytes omitted]`;
      const n = field("other", note);
      if (n > budget) { spentAt = i; return cell; }
      budget -= n;
      cell.other = note;
    }
    if (!Array.isArray(outputs) || !outputs.length) return cell;
    // (the list itself, and room kept for this cell's omission count, before any output)
    const listCost = field("outputs", []);
    const omitCost = field("outputs_omitted", outputs.length);
    if (listCost + omitCost > budget) { spentAt = i; return cell; }
    budget -= listCost;
    const outs = [];
    for (const o of outputs) {
      const comma = outs.length ? 1 : 0;
      const room = budget - omitCost - comma;
      const f = room > 0 ? fitOutput(o, room) : null;
      if (!f) break;
      budget -= f.n + comma;
      outs.push(f.out);
    }
    cell.outputs = outs;
    if (outs.length < outputs.length) {
      cell.outputs_omitted = outputs.length - outs.length;
      budget -= field("outputs_omitted", cell.outputs_omitted);
      spentAt = i;
    }
    return cell;
  });
  const json = { ...(typeof mode === "string" ? { mode: mode.slice(0, 16) } : {}), cells };
  if (metaNote) json.metadata = metaNote;
  if (spentAt >= 0) json.note = noteFor(spentAt);
  return { ...r, content: { json } };
}

/** The bytes of a shortened read charged to readBytes, measured independently of how they were charged: the read's
 * serialized size less that of the same read with only each cell's frame ({id, type, code}) and the mode (for tests). */
export function chargedBytes(shortRead) {
  const json = shortRead.content.json;
  const baseline = { ...(json.mode !== undefined ? { mode: json.mode } : {}), cells: json.cells.map((c) => ({ ...(c.id !== undefined ? { id: c.id } : {}), ...(c.type !== undefined ? { type: c.type } : {}), code: c.code })) };
  return size(json) - size(baseline);
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
