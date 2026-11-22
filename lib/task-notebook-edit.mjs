// A Delegate task's edit of a notebook in its copy, by cell (workspace_edit_notebook, the shape Pair's has): change a
// cell's source or type by its id, insert a cell after an id (null: first), remove a cell by id. Every other cell, its
// outputs and its id stay as they are; the file is written back in the layout it had (nbformat's 1-space indent, 2
// spaces or one line), so the cells this edit doesn't name keep their bytes.

import { randomBytes } from "node:crypto";

/** The JSON layout `text` is in, if it is one of these (a trailing newline kept as it was): its indent, or null. */
function layoutOf(text, j) {
  const body = text.endsWith("\n") ? text.slice(0, -1) : text;
  for (const indent of [1, 2, 0]) if (JSON.stringify(j, null, indent || undefined) === body) return indent;
  return null;
}

const codeCell = (id, source) => ({ cell_type: "code", execution_count: null, id, metadata: {}, outputs: [], source });
const markdownCell = (id, source) => ({ cell_type: "markdown", id, metadata: {}, source });

/** `text` (an .ipynb file's JSON) with the edit applied: {text, inserted: [new ids, in order]}, or an Error saying what
 *  isn't allowed (nothing is changed then). `newId` makes a fresh id (for tests). */
export function editIpynb(text, { set = [], insert = [], remove = [] } = {}, newId = () => "c" + randomBytes(6).toString("hex")) {
  let j;
  try { j = JSON.parse(text); } catch { return new Error("it isn't a notebook's JSON"); }
  if (!j || typeof j !== "object" || !Array.isArray(j.cells)) return new Error("it isn't a notebook's JSON");
  if (!set.length && !insert.length && !remove.length) return new Error("an edit sets, inserts or removes at least one cell");
  const ids = new Map();
  for (const [i, c] of j.cells.entries()) if (typeof c?.id === "string") ids.set(c.id, i);
  const missing = [...set.map((s) => s.id), ...remove, ...insert.map((x) => x.after).filter((a) => a !== null)].find((id) => !ids.has(id));
  if (missing !== undefined) return new Error(`no cell ${JSON.stringify(missing)} in the notebook`);
  const seen = new Set();
  for (const id of [...set.map((s) => s.id), ...remove]) {
    if (seen.has(id)) return new Error(`cell ${JSON.stringify(id)} is named twice in one edit`);
    seen.add(id);
  }
  if (insert.some((x) => x.after !== null && remove.includes(x.after))) return new Error("a cell can't be inserted after one this edit removes");
  const indent = layoutOf(text, j);
  // (set: a cell's source and/or type; a type change gives the cell what that type has: outputs for code, none for Markdown)
  const cells = j.cells.map((c) => ({ ...c }));
  for (const s of set) {
    const i = ids.get(s.id);
    let c = cells[i];
    const type = s.type ?? (c.cell_type === "markdown" ? "markdown" : "code");
    if (type !== c.cell_type) {
      const { outputs, execution_count, attachments, ...rest } = c;
      c = type === "code" ? { ...rest, cell_type: "code", execution_count: null, outputs: [] } : { ...rest, cell_type: "markdown" };
    }
    if (s.source !== undefined) c = { ...c, source: s.source };
    cells[i] = c;
  }
  // (insert: after the named cell, or first; several after one cell keep their order)
  const before = new Map(), first = [];
  const inserted = [];
  const taken = new Set(ids.keys());
  for (const x of insert) {
    let id;
    do id = newId(); while (taken.has(id));
    taken.add(id);
    inserted.push(id);
    const cell = (x.type ?? "code") === "markdown" ? markdownCell(id, x.source) : codeCell(id, x.source);
    if (x.after === null) first.push(cell);
    else { const at = ids.get(x.after); if (!before.has(at)) before.set(at, []); before.get(at).push(cell); }
  }
  const gone = new Set(remove.map((id) => ids.get(id)));
  const out = [...first];
  for (const [i, c] of cells.entries()) {
    if (!gone.has(i)) out.push(c);
    out.push(...(before.get(i) ?? []));
  }
  const next = { ...j, cells: out };
  const body = JSON.stringify(next, null, indent === null ? 1 : indent || undefined);
  return { text: indent !== null && text.endsWith("\n") ? body + "\n" : body, inserted };
}
