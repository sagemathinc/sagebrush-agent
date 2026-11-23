// The Sagebrush source archive (GitHub's tar.gz of one commit) read as data, for sagebrush_source (#1663, design r3
// §3): a gunzipped tar stream in, regular files written into a staging folder, an index out. Everything consumed is
// counted, written or not: every header, extension record, payload (a skipped file's too) and padding; the entries
// of every type; the folders; the files and bytes kept. Only regular files, folders, PAX path/size extensions, one
// leading global header (whose comment must be the expected commit) and GNU long names are read; any other entry
// type refuses the whole archive before anything acts on it. Names are checked after the extensions are applied: one
// root, sagebrush-<commit>/, stripped; portable parts only. Two names the same up to case (or Unicode composition),
// or a file and a folder at one path, refuse the archive; nothing is ever overwritten. A file over 1 MiB, or binary,
// or with a name outside the portable set is skipped and recorded; more than 1% of entries with such names refuses.
//
// The sink is synchronous and holds at most one chunk, one block, one extension record (64 KiB) and one file being
// kept (1 MiB): the caller (source-extract-worker.mjs) feeds it from a gunzip in a worker thread, under a deadline.

import { closeSync, constants as C, fchmodSync, mkdirSync, openSync, writeSync } from "node:fs";
import { join } from "node:path";

export const LIMITS = Object.freeze({
  inflated: 256 * 1024 * 1024, // every byte the gunzip gives, padding and skipped payloads included
  entries: 100_000,            // headers of every type
  dirs: 20_000,
  files: 60_000,               // files kept
  kept: 200 * 1024 * 1024,     // bytes kept
  fileMax: 1024 * 1024,        // a file over this is skipped (still counted)
  paxMax: 64 * 1024,           // one extension record's data
  longNameMax: 4096,
  depth: 24,
  pathBytes: 512,
  badNameShare: 0.01,          // more names than this share skipped refuses the archive
});

const BLOCK = 512;
const NOFOLLOW = C.O_NOFOLLOW ?? 0;
const PART = /^[A-Za-z0-9._@+=-][A-Za-z0-9._@+=,-]{0,127}$/;
const RESERVED = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\..*)?$/i;

export class SourceArchiveError extends Error {
  constructor(why) { super(`the source archive was refused: ${why}`); this.code = "source_archive"; }
}

/** Whether `rel` (the root already stripped) is a portable path: parts from a small set, no ".", "..", trailing dot,
 *  Windows device name, empty part; at most LIMITS.depth parts and LIMITS.pathBytes bytes. */
export function portable(rel) {
  if (!rel || Buffer.byteLength(rel) > LIMITS.pathBytes) return false;
  const parts = rel.split("/");
  if (parts.length > LIMITS.depth) return false;
  return parts.every((p) => PART.test(p) && p !== "." && p !== ".." && !p.endsWith(".") && !RESERVED.test(p));
}

const field = (h, off, len) => { const s = h.subarray(off, off + len); const z = s.indexOf(0); return (z >= 0 ? s.subarray(0, z) : s).toString("utf8"); };
const octal = (h, off, len) => { const s = field(h, off, len).trim(); return /^[0-7]{1,12}$/.test(s) ? parseInt(s, 8) : NaN; };
const padded = (n) => Math.ceil(n / BLOCK) * BLOCK;

/** PAX records: "<len> <key>=<value>\n", each length exact. Returns a Map, or throws. */
function paxRecords(buf) {
  const out = new Map();
  let at = 0;
  while (at < buf.length) {
    const sp = buf.indexOf(0x20, at);
    if (sp < 0 || sp - at > 8) throw new SourceArchiveError("a malformed extension record");
    const len = Number(buf.subarray(at, sp).toString("ascii"));
    if (!Number.isSafeInteger(len) || len <= sp - at + 1 || at + len > buf.length || buf[at + len - 1] !== 0x0a) throw new SourceArchiveError("a malformed extension record");
    const rec = buf.subarray(sp + 1, at + len - 1).toString("utf8");
    const eq = rec.indexOf("=");
    if (eq <= 0) throw new SourceArchiveError("a malformed extension record");
    out.set(rec.slice(0, eq), rec.slice(eq + 1));
    at += len;
  }
  return out;
}

/**
 * A sink for one gunzipped archive of commit `commit`, writing kept files under `dir` (which must exist, empty).
 * write(chunk) consumes; end() checks the archive ended properly and returns the index:
 * { files: [[path, size], ...], skipped: [[path, size, reason], ...], entries, bytes }.
 */
export function sourceTarSink(dir, commit, limits = LIMITS) {
  if (!/^[0-9a-f]{40}$/.test(commit)) throw new SourceArchiveError("not a commit");
  const root = `sagebrush-${commit}`;
  let buf = Buffer.alloc(0);
  let cur = null;      // { kind: "file", rel, size, left, keep, chunks, got } | { kind: "ext", type, size, left, chunks }
  let pad = 0, zeros = 0, done = false;
  let bytes = 0, entries = 0, dirs = 0, kept = 0, keptBytes = 0, badNames = 0;
  let first = true, sawGlobal = false;
  let nextPath = null, nextSize = null; // (from a PAX "x" or a GNU "L" for the next entry)
  const keys = new Map(); // (lowercase NFC path -> { kind: "f" | "d" | "i" (an implied folder), as: its spelling })
  const files = [], skipped = [];
  const made = new Set([""]);
  const fail = (why) => { throw new SourceArchiveError(why); };

  // (every folder counts once, whether its own header names it or a file's path implies it, before anything is made)
  const newDir = () => { if (++dirs > limits.dirs) fail("too many folders"); };
  // (a folder is made with the spelling it was first seen with; any other spelling of it, up to case or composition,
  // refuses the archive, so the folders made are exactly the ones counted, on every filesystem)
  const claim = (rel, kind) => {
    const k = rel.normalize("NFC").toLowerCase();
    const parts = k.split("/"), as = rel.split("/");
    if (parts.length !== as.length) fail("a name that changes under normalization");
    for (let i = 1; i < parts.length; i++) {
      const pk = parts.slice(0, i).join("/"), pas = as.slice(0, i).join("/");
      const have = keys.get(pk);
      if (have?.kind === "f") fail("a file and a folder at one path");
      if (have && have.as !== pas) fail("a name twice (or twice up to case)");
      if (!have) { newDir(); keys.set(pk, { kind: "i", as: pas }); }
    }
    const have = keys.get(k);
    if (have && !(have.kind === "i" && kind === "d" && have.as === rel)) fail(have.kind === kind || (have.kind === "i" && kind === "d") ? "a name twice (or twice up to case)" : "a file and a folder at one path");
    if (!have && kind === "d") newDir();
    keys.set(k, { kind, as: rel });
  };
  const ensureDirs = (rel) => {
    const parts = rel.split("/").slice(0, -1);
    let at = "";
    for (const p of parts) {
      at = at ? `${at}/${p}` : p;
      if (made.has(at)) continue;
      mkdirSync(join(dir, at), { mode: 0o700 });
      made.add(at);
    }
  };
  const nameOf = (h) => {
    const name = nextPath ?? ((field(h, 345, 155) ? field(h, 345, 155) + "/" : "") + field(h, 0, 100));
    nextPath = null;
    return name;
  };
  const relOf = (name) => {
    const n = name.endsWith("/") ? name.slice(0, -1) : name;
    if (n === root) return "";
    if (!n.startsWith(root + "/")) fail("an entry outside the one root folder");
    return n.slice(root.length + 1);
  };

  const header = (h) => {
    if (h.every((b) => b === 0)) { if (++zeros >= 2) done = true; return; }
    if (zeros) fail("an entry after an end block");
    if (++entries > limits.entries) fail("too many entries");
    const type = String.fromCharCode(h[156] || 48);
    let size = octal(h, 124, 12);
    if (!Number.isSafeInteger(size)) fail("a bad size");
    const wasFirst = first;
    first = false;
    if (type === "g") {
      if (!wasFirst || sawGlobal) fail("a global header that isn't first");
      if (size > limits.paxMax) fail("a long global header");
      sawGlobal = true;
      cur = { kind: "ext", type, size, left: size, chunks: [] };
      return;
    }
    if (!sawGlobal) fail("no global header naming the commit");
    if (type === "x" || type === "L") {
      if (nextPath !== null || nextSize !== null) fail("two extensions for one entry");
      if (size > (type === "L" ? limits.longNameMax : limits.paxMax)) fail("a long extension");
      cur = { kind: "ext", type, size, left: size, chunks: [] };
      return;
    }
    if (nextSize !== null) { size = nextSize; nextSize = null; }
    if (bytes + padded(size) > limits.inflated) fail("over the size it may inflate to");
    const rel = relOf(nameOf(h));
    if (type === "5") {
      if (size) fail("a folder with data");
      if (!rel) return; // (the root itself)
      if (!portable(rel)) { newDir(); badNames++; skipped.push([rel, 0, "name"]); return; }
      claim(rel, "d");
      return;
    }
    if (type !== "0") fail(`an entry of type ${JSON.stringify(type)}`); // (links, devices, FIFOs, sparse, anything else)
    if (!rel) fail("a file at the root's own name");
    const okName = portable(rel);
    if (okName) claim(rel, "f");
    let reason = okName ? null : "name";
    if (!reason && size > limits.fileMax) reason = "over 1 MiB";
    if (!reason && (kept + 1 > limits.files || keptBytes + size > limits.kept)) fail("more source than it may keep");
    if (reason === "name") badNames++;
    cur = { kind: "file", rel, size, left: size, keep: !reason, reason, chunks: [], got: 0 };
  };

  const finishExt = () => {
    const data = Buffer.concat(cur.chunks);
    if (cur.type === "L") {
      const z = data.indexOf(0);
      nextPath = (z >= 0 ? data.subarray(0, z) : data).toString("utf8");
    } else {
      const recs = paxRecords(data);
      for (const k of recs.keys()) if (k.startsWith("GNU.sparse") || k === "SCHILY.realsize") fail("a sparse entry");
      if (cur.type === "g") {
        if (recs.get("comment") !== commit) fail("the archive is of another commit");
      } else {
        if (recs.has("path")) nextPath = recs.get("path");
        if (recs.has("size")) {
          const n = Number(recs.get("size"));
          if (!/^\d{1,15}$/.test(recs.get("size")) || !Number.isSafeInteger(n)) fail("a bad extension size");
          nextSize = n;
        }
      }
    }
  };
  const finishFile = () => {
    const { rel, size } = cur;
    if (!cur.keep) { skipped.push([rel, size, cur.reason]); return; }
    const data = Buffer.concat(cur.chunks);
    if (data.subarray(0, 8192).includes(0)) { skipped.push([rel, size, "binary"]); return; }
    ensureDirs(rel);
    const fd = openSync(join(dir, rel), C.O_WRONLY | C.O_CREAT | C.O_EXCL | NOFOLLOW, 0o600);
    try {
      for (let at = 0; at < data.length; ) at += writeSync(fd, data, at, data.length - at);
      fchmodSync(fd, 0o400);
    } finally { closeSync(fd); }
    kept++;
    keptBytes += size;
    files.push([rel, size]);
  };

  return {
    write(chunk) {
      bytes += chunk.length;
      if (bytes > limits.inflated) fail("over the size it may inflate to");
      if (done) return; // (tar's own record padding after the end blocks: counted above, not read)
      buf = buf.length ? Buffer.concat([buf, chunk]) : chunk;
      for (;;) {
        if (pad) { const n = Math.min(pad, buf.length); pad -= n; buf = buf.subarray(n); if (pad) return; }
        if (cur) {
          const n = Math.min(cur.left, buf.length);
          if (cur.kind === "ext" || cur.keep) cur.chunks.push(Buffer.from(buf.subarray(0, n)));
          cur.left -= n;
          buf = buf.subarray(n);
          if (cur.left) return;
          if (cur.kind === "ext") finishExt(); else finishFile();
          pad = padded(cur.size) - cur.size;
          cur = null;
          continue;
        }
        if (buf.length < BLOCK) return;
        const h = buf.subarray(0, BLOCK);
        buf = buf.subarray(BLOCK);
        header(h);
        if (done) { buf = Buffer.alloc(0); return; }
      }
    },
    end() {
      if (cur || !done || nextPath !== null || nextSize !== null) fail("it ends early");
      if (badNames > Math.max(1, Math.floor(entries * limits.badNameShare))) fail("too many names outside the portable set");
      return { files, skipped, entries, bytes };
    },
  };
}
