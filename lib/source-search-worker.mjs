// One search of a cached source tree, in a worker thread (#1663, design r3 §5): the regex runs here, so a pattern
// that backtracks for ever is ended by the parent terminating this worker at its limit, never the agent's loop.
// In: workerData { tree, files: [[path, size], ...] (the admitted index, in order), pattern, flags, prefix, max,
// scanMax, lineMax, cut }. Out: one message { hits: [[path, line, text]], stopped, scanned }.
// Files are opened without following links and must be regular files of the indexed size; anything else is passed
// over. Each line is tested on its first lineMax characters only.
import { closeSync, constants as C, fstatSync, openSync, readSync } from "node:fs";
import { join } from "node:path";
import { parentPort, workerData } from "node:worker_threads";

const { tree, files, pattern, flags, prefix, max, scanMax, lineMax, cut } = workerData;
const NOFOLLOW = C.O_NOFOLLOW ?? 0;
const re = new RegExp(pattern, flags);
const hits = [];
let scanned = 0, stopped = false;

function readFile(rel, size) {
  let fd;
  try { fd = openSync(join(tree, rel), C.O_RDONLY | NOFOLLOW); } catch { return null; }
  try {
    const s = fstatSync(fd);
    if (!s.isFile() || s.size !== size) return null;
    const buf = Buffer.allocUnsafe(size);
    for (let at = 0; at < size; ) { const n = readSync(fd, buf, at, size - at, at); if (!n) return null; at += n; }
    return buf;
  } catch { return null; } finally { closeSync(fd); }
}

outer: for (const [rel, size] of files) {
  if (prefix && !(rel === prefix || rel.startsWith(prefix.endsWith("/") ? prefix : prefix + "/"))) continue;
  if (scanned + size > scanMax) { stopped = true; break; }
  const buf = readFile(rel, size);
  if (!buf) continue;
  scanned += size;
  const lines = buf.toString("utf8").split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].length > lineMax ? lines[i].slice(0, lineMax) : lines[i];
    re.lastIndex = 0;
    if (re.test(line)) {
      hits.push([rel, i + 1, line.length > cut ? line.slice(0, cut) + "…" : line]);
      if (hits.length >= max) { stopped = true; break outer; }
    }
  }
}
parentPort.postMessage({ hits, stopped, scanned });
