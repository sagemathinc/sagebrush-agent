// What a read of a notebook returns to the model, in Pair (the page's document, as workspace.read gives it) and in
// Delegate (the task copy's .ipynb, first put in the same form by ipynbDoc): the format approved for #1503, v2.
//
// - The answer is one line of JSON, {path, mode, bytes, cells, note}, keys in that order. bytes is the UTF-8 size of the
//   document given, as JSON.
// - Each cell is {i, id, type, source}: its source whole up to 16 KiB (cut: true past that). A code cell's outputs
//   are summarized: images and other data are never inlined (kind, MIME type and size only), and text is cut at
//   400 bytes, said so.
// - Every answer is at most 48 KiB as serialized, escaping, names and envelope included. A summary keeps 256 bytes of
//   that for its last sentence; the cells past the bound are named, with how to read them ({path, from: k}). The
//   first cell asked for is always shown: if it alone is over, outputs are left out from its end
//   (outputs_not_shown: m), and only if its source alone is over, the source is cut further.
// - {cell: n}: one cell's source and text outputs (an error with its traceback), each up to 64 KiB, all within one
//   budget of 48 KiB less 4 KiB, and the answer made to fit the same way.
// - Short fields are bounded: an id, a stream's name and the mode at 128 bytes, an error's name at 400 (cut: true), a
//   data output's MIME types at 16 (more_mimes: n).
// Its bytes are pinned by a shared fixture (test/fixtures/nb-read/): the page side keeps the same format.

export const READ_LIMITS = Object.freeze({ source: 16384, text: 400, total: 49152, reserve: 256, cellText: 65536, cellReserve: 4096, name: 128, mimes: 16 });
export const READ_NOTE = "Outputs are summarized: images and other data are never inlined, and text is cut at 400 bytes. Read one cell in full with {path, cell: n}.";
export const CELL_NOTE = "One cell: its source and text outputs in full, up to 64 KB each and within the read's limit; images and other data are never inlined.";

// (images, in the order one is picked when an output has several; the first four are counted decoded)
const IMAGE_MIMES = ["image/png", "image/jpeg", "image/webp", "image/gif", "image/svg+xml"];
const DECODED = new Set(IMAGE_MIMES.slice(0, 4));
const encoder = new TextEncoder();
// (UTF-8 bytes as the answer counts them: a lone surrogate as the 3 bytes of U+FFFD, the way TextEncoder writes it)
const bytesOf = (s) => encoder.encode(s).length;
const lines = (v) => (Array.isArray(v) ? v.map(String).join("") : typeof v === "string" ? v : "");
const textOf = (v) => (typeof v === "string" ? v : Array.isArray(v) ? v.map(String).join("") : JSON.stringify(v ?? ""));

/** `s` cut to at most `max` UTF-8 bytes, at the end of a code point (each code point kept as it is): {text, cut}. */
export function cutText(s, max) {
  if (bytesOf(s) <= max) return { text: s, cut: false };
  let used = 0, end = 0;
  for (const ch of s) {
    const n = bytesOf(ch);
    if (used + n > max) break;
    used += n;
    end += ch.length;
  }
  return { text: s.slice(0, end), cut: true };
}
const short = (v) => cutText(String(v), READ_LIMITS.name).text;

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
      const out = { kind: "stream", name: short(o.name ?? ""), text: t.text };
      if (t.cut) Object.assign(out, { bytes: bytesOf(all), cut: true });
      return out;
    }
    case "error": {
      const value = take(String(o.evalue ?? ""));
      const name = cutText(String(o.ename ?? "Error"), READ_LIMITS.text);
      const out = { kind: "error", ename: name.text, evalue: value.text };
      let cut = value.cut || name.cut;
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
      const all = Object.keys(data), mimes = all.slice(0, READ_LIMITS.mimes).map(short);
      const out = { kind: "data", mimes, bytes: all.reduce((n, m) => n + bytesOf(textOf(data[m])), 0) };
      if (all.length > mimes.length) out.more_mimes = all.length - mimes.length;
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

const outputsOf = (c) => (Array.isArray(c?.outputs) ? c.outputs : []);

/** A cell as read: its frame; its source, cut at `source` bytes when given, else by `take`; and a code cell's first
 *  `keep` outputs (each text cut by `take`), the number left out counted as outputs_not_shown. */
function cellOf(c, i, take, whole, keep, source) {
  const type = c?.type === "markdown" || c?.type === "raw" ? c.type : "code";
  const cell = { i, id: short(c?.id ?? ""), type };
  const src = source === undefined ? take(String(c?.code ?? "")) : cutText(String(c?.code ?? ""), source);
  cell.source = src.text;
  if (src.cut) cell.cut = true;
  const all = outputsOf(c), outs = all.slice(0, keep).map((o) => summaryOf(o, take, whole));
  if (type === "code" && outs.length) cell.outputs = outs;
  if (type === "code" && all.length > outs.length) cell.outputs_not_shown = all.length - outs.length;
  return cell;
}

/** The answer `build(budget, keep)` within `limit` bytes as serialized: as built, if it fits; else with as many of the
 *  cell's outputs as fit, kept from the start, its source whole; else with no outputs and the source's budget cut
 *  down until it fits. */
function fitted(build, budget, outputs, limit) {
  const fits = (t) => bytesOf(t) <= limit;
  let t = build(budget, outputs);
  if (fits(t)) return t;
  if (fits(build(budget, 0))) {
    let lo = 0, hi = outputs; // (lo fits, hi doesn't)
    while (hi - lo > 1) { const mid = (lo + hi) >> 1; if (fits(build(budget, mid))) lo = mid; else hi = mid; }
    return build(budget, lo);
  }
  let lo = 0, hi = budget;
  while (hi - lo > 1) { const mid = Math.floor((lo + hi) / 2); if (fits(build(mid, 0))) lo = mid; else hi = mid; }
  return build(lo, 0);
}

/** The read of a notebook `doc` ({mode, cells: [{id, type, code, outputs}]}) at `path`, as its JSON text:
 *  `cell`: one cell in full; `from`: the cells from there on. A cell that isn't there is said so. */
export function notebookRead(doc, { path, cell, from } = {}) {
  const cells = Array.isArray(doc?.cells) ? doc.cells : [];
  const head = { path: String(path), mode: short(doc?.mode ?? "python"), bytes: bytesOf(JSON.stringify(doc)) };
  const missing = (n) => JSON.stringify({ ...head, error: `no cell ${n}: the notebook has ${cells.length} cells (0 to ${cells.length - 1})` });
  if (cell !== undefined) {
    const c = cells[cell];
    if (!Number.isSafeInteger(cell) || cell < 0 || !c) return missing(cell);
    // (one budget for the cell's texts, spent in order: its source, then each output's texts)
    const build = (budget, keep) => {
      let left = budget;
      const take = (s) => { const t = cutText(s, Math.max(0, Math.min(READ_LIMITS.cellText, left))); left -= bytesOf(t.text); return t; };
      return JSON.stringify({ ...head, cell: cellOf(c, cell, take, true, keep), note: CELL_NOTE });
    };
    return fitted(build, READ_LIMITS.total - READ_LIMITS.cellReserve, outputsOf(c).length, READ_LIMITS.total);
  }
  const start = from ?? 0;
  if (!Number.isSafeInteger(start) || start < 0 || (cells.length > 0 && start >= cells.length)) return missing(start);
  // (the answer's size kept as it grows: the frame with no cells and the note, then each cell and its comma)
  const room = READ_LIMITS.total - READ_LIMITS.reserve;
  const textCut = (s) => cutText(s, READ_LIMITS.text);
  const shown = [];
  let size = 0, k = start;
  for (; k < cells.length; k++) {
    const c = cells[k];
    if (!shown.length) {
      // (the first cell asked for is always shown, made to fit)
      const one = fitted((budget, keep) => JSON.stringify({ ...head, cells: [cellOf(c, k, textCut, false, keep, Math.min(READ_LIMITS.source, budget))], note: READ_NOTE }), READ_LIMITS.source, outputsOf(c).length, room);
      shown.push(JSON.parse(one).cells[0]);
      size = bytesOf(one);
      continue;
    }
    const next = cellOf(c, k, textCut, false, Infinity, READ_LIMITS.source);
    const grown = size + bytesOf(JSON.stringify(next)) + 1;
    if (grown > room) break;
    shown.push(next);
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
