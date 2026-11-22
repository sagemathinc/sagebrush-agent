# Notebook read summary: golden fixture (#1503)

The format approved Nov 21 2026 for an agent's `workspace_read` of a notebook, in Pair and in Delegate. The reference implementation is `summarize.mjs`, and the expected files are its output. An implementation passes when, given `notebook.json` as its document, it returns these files' exact bytes (one line, no trailing newline).

| File | What |
|---|---|
| `notebook.json` | The input: the page's own `workspace.read` answer's `content.json`, for a notebook created through the page. It holds markdown; code with a 590-byte stdout (multibyte); a 40,562-byte PNG plus text/plain; an error; an HTML-plus-text table; a 17,270-byte source (cut at 16,384); and 7 more 6,710-byte sources. |
| `expected-read.json` | `summarize(doc, {path: "notes/fixture.ipynb"})`: cells 0-9, and the note "Cells 10-12 not shown: read them with {path, from: 10}." |
| `expected-from.json` | `summarize(doc, {path, from: 10})`. |
| `expected-cell-1.json` | `summarize(doc, {path, cell: 1})`: the full stdout. |
| `expected-cell-3.json` | `summarize(doc, {path, cell: 3})`: the error with its traceback. |
| `generate.mjs` | How `notebook.json` and the expected files were made: headless Chrome, the built Agents page, a stand-in agent, and a seeded PNG. |

Rules, as `summarize.mjs` has them:
- **The answer:** `JSON.stringify` of `{path, mode, bytes, cells, note}`, keys in that order. `bytes` is the UTF-8 size of `JSON.stringify` of the document given. `path` is as the caller names it.
- **A cell:** `{i, id, type, source}`, plus `cut: true` if the source was cut at 16,384 bytes (at a code point's end), plus `outputs` for a code cell that has any.
- **Outputs:**
  - stream: `{kind: "stream", name, text}`, with the text cut at 400 bytes; if cut, also `bytes` (the full text's) and `cut: true`.
  - error: `{kind: "error", ename, evalue}`, with evalue cut at 400 bytes (`cut: true` if cut).
  - display_data or execute_result with an image (image/png, jpeg, webp or gif, then svg+xml, in that order): `{kind: "image", mime, bytes}`. For a raster image, `bytes` is the decoded size; for SVG, its UTF-8 size.
  - any other display_data or execute_result: `{kind: "data", mimes, bytes}`, where `bytes` is the sum of all values' UTF-8 sizes. If it has text/plain, add `text` cut at 400 bytes (`cut: true` if cut).
  - anything else: `{kind: "other", type}`.
- **The total:** cells are added in order while the whole answer with the base note is at most 49,152 − 256 bytes. The first cell asked for is always shown. If any are left out, the note gains " Cells K-N not shown: read them with {path, from: K}."
- **`{cell: n}`:** `{path, mode, bytes, cell, note}`. The cell's source, then each output's texts, are cut in order against one budget of 49,152 − 4,096 bytes, each text also at most 65,536. An error adds `traceback` (its lines joined with "\n"). Images and other data are summarized as above.
- **A bad `cell` or `from`:** `{path, mode, bytes, error: "no cell N: the notebook has C cells (0 to C-1)"}`.
