// What a read of a notebook returns to the model, in Pair (the page's document, as workspace.read gives it) and in
// Delegate (the task copy's .ipynb, first put in the same form by ipynbDoc): the format approved for #1503.
//
// - The answer is one line of JSON, {path, mode, bytes, cells, note}, keys in that order. bytes is the UTF-8 size of the
//   document given, as JSON.
// - Each cell is {i, id, type, source}: its source whole up to 16 KiB (cut: true past that). A code cell's outputs
//   are summarized: images and other data are never inlined (kind, MIME type and size only), and text is cut at
//   400 bytes, said so.
// - The whole answer is at most 48 KiB, less a 256-byte reserve for its last sentence. The first cell asked for is
//   always shown; the cells past the bound are named, with how to read them ({path, from: k}).
// - {cell: n}: one cell's source and text outputs (an error with its traceback), each up to 64 KiB and all within one
//   budget of 48 KiB less 4 KiB.
// Its bytes are pinned by a shared fixture (test/fixtures/nb-read/): the page side keeps the same format.

export const READ_LIMITS = Object.freeze({ source: 16384, text: 400, total: 49152, reserve: 256, cellText: 65536, cellReserve: 4096 });
export const READ_NOTE = "Outputs are summarized: images and other data are never inlined, and text is cut at 400 bytes. Read one cell in full with {path, cell: n}.";
export const CELL_NOTE = "One cell: its source and text outputs in full, up to 64 KB each and within the read's limit; images and other data are never inlined.";

// (images, in the order one is picked when an output has several; the first four are counted decoded)
const IMAGE_MIMES = ["image/png", "image/jpeg", "image/webp", "image/gif", "image/svg+xml"];
const DECODED = new Set(IMAGE_MIMES.slice(0, 4));
const bytesOf = (s) => Buffer.byteLength(s, "utf8");
const lines = (v) => (Array.isArray(v) ? v.map(String).join("") : typeof v === "string" ? v : "");
const textOf = (v) => (typeof v === "string" ? v : Array.isArray(v) ? v.map(String).join("") : JSON.stringify(v ?? ""));

/** `s` cut to at most `max` UTF-8 bytes, at the end of a code point: {text, cut}. */
export function cutText(s, max) {
  const b = Buffer.from(s, "utf8");
  if (b.length <= max) return { text: s, cut: false };
  let end = Math.max(0, max);
  while (end > 0 && (b[end] & 0xc0) === 0x80) end--; // (back to the first byte of the code point that doesn't fit)
  return { text: b.subarray(0, end).toString("utf8"), cut: true };
}

/** The size of base64 data once decoded (its whitespace ignored). */
function decodedSize(b64) {
  const s = String(b64).replace(/\s+/g, "");
  return Math.floor((s.length * 3) / 4) - (s.endsWith("==") ? 2 : s.endsWith("=") ? 1 : 0);
}

/** One output as the model reads it. `take` cuts each of its texts in turn; `whole`: an error's traceback too. */
function summaryOf(o, take, whole) {
  if (!o || typeof o !== "object" || Array.isArray(o)) return { kind: "other", type: "" };
  switch (o.output_type) {
    case "stream": {
      const all = lines(o.text), t = take(all);
      const out = { kind: "stream", name: String(o.name ?? ""), text: t.text };
      if (t.cut) Object.assign(out, { bytes: bytesOf(all), cut: true });
      return out;
    }
    case "error": {
      const value = take(String(o.evalue ?? ""));
      const out = { kind: "error", ename: String(o.ename ?? "Error"), evalue: value.text };
      let cut = value.cut;
      if (whole) {
        const tb = take(Array.isArray(o.traceback) ? o.traceback.map(String).join("\n") : "");
        out.traceback = tb.text;
        cut = cut || tb.cut;
      }
      if (cut) out.cut = true;
      return out;
    }
    case "display_data":
    case "execute_result": {
      const data = o.data && typeof o.data === "object" && !Array.isArray(o.data) ? o.data : {};
      const image = IMAGE_MIMES.find((m) => Object.hasOwn(data, m));
      if (image) return { kind: "image", mime: image, bytes: DECODED.has(image) ? decodedSize(textOf(data[image])) : bytesOf(textOf(data[image])) };
      const mimes = Object.keys(data);
      const out = { kind: "data", mimes, bytes: mimes.reduce((n, m) => n + bytesOf(textOf(data[m])), 0) };
      if (Object.hasOwn(data, "text/plain")) {
        const t = take(textOf(data["text/plain"]));
        out.text = t.text;
        if (t.cut) out.cut = true;
      }
      return out;
    }
    default:
      return { kind: "other", type: String(o.output_type ?? "").slice(0, 32) };
  }
}

/** A cell as read: its frame, its source (cut by `take`), and a code cell's outputs. */
function cellOf(c, i, takeSource, takeOutput, whole) {
  const type = c?.type === "markdown" || c?.type === "raw" ? c.type : "code";
  const cell = { i, id: String(c?.id ?? ""), type };
  const src = takeSource(String(c?.code ?? ""));
  cell.source = src.text;
  if (src.cut) cell.cut = true;
  const outs = Array.isArray(c?.outputs) ? c.outputs : [];
  if (type === "code" && outs.length) cell.outputs = outs.map((o) => summaryOf(o, takeOutput, whole));
  return cell;
}

/** The read of a notebook `doc` ({mode, cells: [{id, type, code, outputs}]}) at `path`, as its JSON text:
 *  `cell`: one cell in full; `from`: the cells from there on. A cell that isn't there is said so. */
export function notebookRead(doc, { path, cell, from } = {}) {
  const cells = Array.isArray(doc?.cells) ? doc.cells : [];
  const head = { path: String(path), mode: String(doc?.mode ?? "python"), bytes: bytesOf(JSON.stringify(doc)) };
  const missing = (n) => JSON.stringify({ ...head, error: `no cell ${n}: the notebook has ${cells.length} cells (0 to ${cells.length - 1})` });
  if (cell !== undefined) {
    if (!Number.isSafeInteger(cell) || cell < 0 || !cells[cell]) return missing(cell);
    // (one budget for the cell's texts, spent in order: its source, then each output's texts)
    let left = READ_LIMITS.total - READ_LIMITS.cellReserve;
    const take = (s) => { const t = cutText(s, Math.max(0, Math.min(READ_LIMITS.cellText, left))); left -= bytesOf(t.text); return t; };
    return JSON.stringify({ ...head, cell: cellOf(cells[cell], cell, take, take, true), note: CELL_NOTE });
  }
  const start = from ?? 0;
  if (!Number.isSafeInteger(start) || start < 0 || (cells.length > 0 && start >= cells.length)) return missing(start);
  // (the answer's size, kept as it grows: the frame with no cells and the note, then each cell and its comma)
  const limit = READ_LIMITS.total - READ_LIMITS.reserve;
  let size = bytesOf(JSON.stringify({ ...head, cells: [], note: READ_NOTE }));
  const shown = [];
  let k = start;
  for (; k < cells.length; k++) {
    const c = cellOf(cells[k], k, (s) => cutText(s, READ_LIMITS.source), (s) => cutText(s, READ_LIMITS.text), false);
    const grown = size + bytesOf(JSON.stringify(c)) + (shown.length ? 1 : 0);
    if (shown.length && grown > limit) break;
    shown.push(c);
    size = grown;
  }
  const note = k < cells.length ? `${READ_NOTE} Cells ${k}-${cells.length - 1} not shown: read them with {path, from: ${k}}.` : READ_NOTE;
  return JSON.stringify({ ...head, cells: shown, note });
}

// (a notebook's language, from its kernelspec as notebookIpynb writes it; python when it isn't one of these)
const MODES = { python3: "python", sagemath: "sage", magma: "magma", matlab: "matlab" };

/** An .ipynb file's JSON put in the form notebookRead reads ({mode, cells: [{id, type, code, outputs}]}), or null if
 *  it isn't a notebook's. */
export function ipynbDoc(text) {
  let j;
  try { j = JSON.parse(text); } catch { return null; }
  if (!j || typeof j !== "object" || !Array.isArray(j.cells)) return null;
  const mode = MODES[j.metadata?.kernelspec?.name] ?? "python";
  return {
    mode,
    cells: j.cells.map((c) => {
      const type = c?.cell_type === "markdown" || c?.cell_type === "raw" ? c.cell_type : "code";
      return { id: String(c?.id ?? ""), type, code: lines(c?.source), ...(type === "code" ? { outputs: Array.isArray(c?.outputs) ? c.outputs : [] } : {}) };
    }),
  };
}
