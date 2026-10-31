// Notebooks for the agent: the document workspace_write_notebook builds (a closed grammar, bounded), and a read of a
// notebook shortened for the model (outputs cut, pictures named, never the file itself changed).

import { randomBytes } from "node:crypto";

export const NOTEBOOK_LIMITS = Object.freeze({
  cells: 200, // cells in one write
  sourceBytes: 256 * 1024, // one cell's source
  totalBytes: 4 * 1024 * 1024, // all sources together
  outputBytes: 8 * 1024, // one output's text in a read, for the model
  readBytes: 256 * 1024, // all outputs of a read together, for the model
});

const MODES = new Set(["python", "sage"]);
const TYPES = new Set(["code", "markdown"]);
const utf8 = (s) => Buffer.byteLength(s, "utf8");

/** The notebook document for `{mode, cells: [{type, source}]}`, or an Error saying what isn't allowed. */
export function notebookDoc(args) {
  if (!args || typeof args !== "object" || Array.isArray(args)) return new Error("arguments must be an object");
  const { mode, cells } = args;
  if (!MODES.has(mode)) return new Error(`mode must be "python" or "sage"`);
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

/** One output as the model reads it: text kept up to the cap, everything else named with its size. */
function shortOutput(o, budget) {
  if (!o || typeof o !== "object") return { out: "[an output in an unknown form]", used: 0 };
  const take = (s) => {
    const { text, cut } = cutBytes(s, Math.min(NOTEBOOK_LIMITS.outputBytes, Math.max(0, budget)));
    return { text: cut ? `${text}…[${cut} more bytes]` : text, used: utf8(text) };
  };
  if (o.output_type === "stream") {
    const t = take(joined(o.text));
    return { out: { output_type: "stream", name: o.name, text: t.text }, used: t.used };
  }
  if (o.output_type === "error") {
    const t = take(`${o.ename ?? "Error"}: ${o.evalue ?? ""}\n${joined(o.traceback)}`);
    return { out: { output_type: "error", text: t.text }, used: t.used };
  }
  const data = o.data && typeof o.data === "object" ? o.data : {};
  const shown = {};
  let used = 0;
  for (const [mime, v] of Object.entries(data)) {
    if (mime === "text/plain" || mime === "text/markdown" || mime === "text/latex") {
      const t = take(joined(v));
      shown[mime] = t.text;
      used += t.used;
    } else {
      const raw = typeof v === "string" ? v : JSON.stringify(v ?? "");
      shown[mime] = `[${mime}, ${pictureSize(mime, raw)}${utf8(raw)} bytes omitted]`;
    }
  }
  return { out: { output_type: o.output_type, data: shown }, used };
}

/** A workspace.read result of a notebook, shortened for the model: entry and rev exactly as read. */
export function shortNotebookRead(r) {
  const doc = r?.content?.json;
  if (!doc || typeof doc !== "object" || !Array.isArray(doc.cells)) return r;
  let budget = NOTEBOOK_LIMITS.readBytes;
  let omitted = 0;
  const cells = doc.cells.map((c) => {
    const { outputs, ...rest } = c && typeof c === "object" ? c : {};
    if (!Array.isArray(outputs) || !outputs.length) return rest;
    if (budget <= 0) { omitted++; return { ...rest, outputs: "[outputs omitted: the read's limit was reached]" }; }
    const outs = [];
    for (const o of outputs) {
      const { out, used } = shortOutput(o, budget);
      budget -= used;
      outs.push(out);
    }
    return { ...rest, outputs: outs };
  });
  const { cells: _c, ...meta } = doc;
  const json = { ...meta, cells, ...(omitted ? { note: `[outputs of ${omitted} more cells omitted]` } : {}) };
  return { ...r, content: { json } };
}
