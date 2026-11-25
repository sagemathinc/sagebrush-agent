// Host backup (design: agent-autonomous-host-backup.md r3.3 §5, "validation before resume"): a restored set is
// `validated` only if its filled tree is the snapshot's, less exactly the entries the manifest lists as unrestorable,
// and every SQLite file of an agent's sessions passes PRAGMA quick_check. Only a validated set's agent can be resumed.
//
// This module holds the parts that don't depend on how the filled tree is read:
// - parseListing: the one closed format (launcher contract A2 r3.6 §4b) of both the list the backup binary writes
//   beside a class's staged data (data/digests.json, from the MAC-verified plaintext) and the launcher's tree-digest
//   listing of the filled destination (fd-relative, beneath its verified handle);
// - compareTrees: that list, less the unrestorable paths, against the filled tree's own listing, both by path: every
//   path missing, extra, or changed in type, size, mode, target or content is reported, never only the first;
// - quickCheck: PRAGMA quick_check on the private copy of one sessions database that tree-digest made (the database
//   with its -wal and -journal siblings); the copy may be written by SQLite's recovery, the destination never is.
// - checkClass: one class's verdict from the digest list (its bytes bound by the hash recorded at staged), fill's
//   report and tree-digest's listing. The launches and the record's steps are restore-fill.mjs's.

import * as fs from "node:fs";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { refuse } from "../bytes.mjs";

/** A class's digest list is at most this many entries: the same bound as a backup walk and the restore's fill. */
export const MAX_ENTRIES = 2_000_000;
/** How many differing paths compareTrees lists (all are counted). */
export const DIFF_LIST_MAX = 20;

const TYPES = new Set(["dir", "file", "symlink"]);
const HEX64 = /^[0-9a-f]{64}$/;
const U53 = (n) => Number.isSafeInteger(n) && n >= 0;

/**
 * A listed path's raw bytes (A2 r3.7 S2's lossless codec): each maximal run of valid UTF-8 is written as itself, but
 * "%" as "%25"; every byte that isn't part of valid UTF-8 as "%XX" (upper-case hex). Returns the bytes, or null when
 * the text isn't exactly the codec's output for them (a stray "%", lower-case hex, a %XX that names a byte of valid
 * UTF-8, ...): decoding, then encoding again, must give the same text.
 */
export function rawPath(p) {
  if (typeof p !== "string") return null;
  const out = [];
  for (let i = 0; i < p.length;) {
    if (p[i] === "%") {
      const hx = p.slice(i + 1, i + 3);
      if (!/^[0-9A-F]{2}$/.test(hx)) return null;
      out.push(parseInt(hx, 16)); i += 3;
    } else {
      const cp = p.codePointAt(i), ch = String.fromCodePoint(cp);
      if (cp >= 0xd800 && cp <= 0xdfff) return null; // (a lone surrogate isn't text)
      out.push(...Buffer.from(ch, "utf8")); i += ch.length;
    }
  }
  const raw = Buffer.from(out);
  return encodePath(raw) === p ? raw : null;
}

/** The codec's text for raw path bytes (the inverse of rawPath). */
export function encodePath(raw) {
  let s = "";
  for (let i = 0; i < raw.length;) {
    const n = utf8Len(raw, i);
    if (n === 0) { s += "%" + raw[i].toString(16).toUpperCase().padStart(2, "0"); i += 1; continue; }
    const ch = raw.subarray(i, i + n).toString("utf8");
    s += ch === "%" ? "%25" : ch;
    i += n;
  }
  return s;
}

// (the length of the valid UTF-8 sequence at raw[i], or 0: no overlong forms, no surrogates, nothing past U+10FFFF)
function utf8Len(raw, i) {
  const b = raw[i], c = (k) => i + k < raw.length && (raw[i + k] & 0xc0) === 0x80;
  if (b < 0x80) return 1;
  if (b >= 0xc2 && b <= 0xdf) return c(1) ? 2 : 0;
  if (b >= 0xe0 && b <= 0xef) {
    if (!c(1) || !c(2)) return 0;
    const b1 = raw[i + 1];
    if ((b === 0xe0 && b1 < 0xa0) || (b === 0xed && b1 > 0x9f)) return 0;
    return 3;
  }
  if (b >= 0xf0 && b <= 0xf4) {
    if (!c(1) || !c(2) || !c(3)) return 0;
    const b1 = raw[i + 1];
    if ((b === 0xf0 && b1 < 0x90) || (b === 0xf4 && b1 > 0x8f)) return 0;
    return 4;
  }
  return 0;
}
// (a symlink's target: the codec's text for 1 to 4096 raw bytes without NUL, anything else allowed, ".." and "/" too)
const targetOk = (t) => { const raw = rawPath(t); return raw !== null && raw.length > 0 && raw.length <= 4096 && !raw.includes(0); };
// (a listed path: the codec's text for at most 4096 raw bytes, relative, segments without "", ".", ".." or NUL)
const relPath = (p) => {
  const raw = rawPath(p);
  if (raw === null || raw.length === 0 || raw.length > 4096 || raw.includes(0)) return false;
  const segs = raw.toString("latin1").split("/");
  return segs.every((s) => s !== "" && s !== "." && s !== "..");
};
const keysAre = (o, keys) => o !== null && typeof o === "object" && !Array.isArray(o)
  && Object.keys(o).length === keys.length && keys.every((k) => Object.hasOwn(o, k));

/** The longest listing either side may give (A2 r3.6 §4b MAX_LISTING): 512 MiB. */
export const MAX_LISTING = 512 * 2 ** 20;
const UNEXPECTED = new Set(["fifo", "socket", "char", "block", "mount"]);
// (a private SQLite copy's name: h, the first 32 hex digits of SHA-256 over the main's raw path, then its suffix)
const COPY = /^[0-9a-f]{32}\.db(?:-wal|-journal)?$/;
const SIDECARS = ["-wal", "-journal"];

/**
 * The format's one string quoting (both producers'): only `"` and `\` escaped, every character below U+0020 as
 * \u00xx (lower-case hex), every other character as itself.
 */
export function quote(s) {
  let o = '"';
  for (const ch of s) {
    const c = ch.codePointAt(0);
    o += ch === '"' ? '\\"' : ch === "\\" ? "\\\\" : c < 0x20 ? "\\u" + c.toString(16).padStart(4, "0") : ch;
  }
  return o + '"';
}

// (each line's one canonical spelling, keys in the format's order: a parsed line must re-serialize to itself exactly)
const canon = (e) => e.type === "file"
  ? `{"path":${quote(e.path)},"type":"file","size":${e.size},"mode":${e.mode},"sha256":"${e.sha256}"${Object.hasOwn(e, "copy") ? `,"copy":"${e.copy}"` : ""}}`
  : e.type === "dir" ? `{"path":${quote(e.path)},"type":"dir","size":0,"mode":${e.mode}}`
    : `{"path":${quote(e.path)},"type":"symlink","size":${e.size},"mode":511,"target":${quote(e.target)}}`;

/**
 * Parse one listing in A2 r3.6 §4b's format (the binary's data/digests.json, or tree-digest's output): JSON Lines, a
 * `{"v":1}` header, one canonical line per entry sorted by the bytes of its path with no path twice, then
 * `{"count":C,"total_bytes":B}`. Paths are the codec's text (rawPath). The EXPECTED list (digests.json) has modes with
 * the set-id bits cleared, and nothing else; the OBSERVED one ({ observed: true }, tree-digest) has the actual modes,
 * set-id included, may have `unexpected` lines (a special file or a mount), and a file entry may carry its private
 * SQLite copy's name, `copy`, after its sha256. Returns { entries: Map by path, unexpected: [{ path, type }] };
 * refuses bad_form for anything else, and limit past the bounds. The class root itself is never an entry.
 */
export function parseListing(text, { observed = false, maxEntries = MAX_ENTRIES, maxBytes = MAX_LISTING } = {}) {
  const allowUnexpected = observed;
  const bad = (what) => refuse("bad_form", `restore validation: the listing ${what}`);
  if (typeof text !== "string") bad("isn't text");
  if (Buffer.byteLength(text) > maxBytes) refuse("limit", "restore validation: a listing longer than a restore takes");
  if (!text.endsWith("\n")) bad("doesn't end with its trailer's newline");
  const lines = text.slice(0, -1).split("\n");
  if (lines.length < 2 || lines[0] !== '{"v":1}') bad("has no header");
  const trailer = (() => { try { return JSON.parse(lines[lines.length - 1]); } catch { return null; } })();
  if (!keysAre(trailer, ["count", "total_bytes"]) || !U53(trailer.count) || !U53(trailer.total_bytes)
    || lines[lines.length - 1] !== JSON.stringify({ count: trailer.count, total_bytes: trailer.total_bytes })) bad("has no closed trailer");
  const entries = new Map(), odd = [];
  let bytes = 0, prev = null;
  for (let i = 1; i < lines.length - 1; i++) {
    let e;
    try { e = JSON.parse(lines[i]); } catch { bad("has a line that isn't JSON"); }
    let path;
    if (e !== null && typeof e === "object" && Object.hasOwn(e, "unexpected")) {
      if (!allowUnexpected) bad("has an unexpected entry");
      if (!keysAre(e, ["unexpected", "type"]) || !UNEXPECTED.has(e.type) || !relPath(e.unexpected) || e.unexpected === ""
        || lines[i] !== `{"unexpected":${quote(e.unexpected)},"type":"${e.type}"}`) bad("has an unexpected entry that isn't closed");
      path = e.unexpected;
      odd.push({ path, type: e.type });
    } else {
      const kind = e?.type;
      const ok = TYPES.has(kind) && (kind === "dir" ? keysAre(e, ["path", "type", "size", "mode"]) && e.size === 0
        : kind === "file" ? (keysAre(e, ["path", "type", "size", "mode", "sha256"]) || (observed && keysAre(e, ["path", "type", "size", "mode", "sha256", "copy"]) && COPY.test(e.copy))) && HEX64.test(e.sha256)
          : keysAre(e, ["path", "type", "size", "mode", "target"]) && e.mode === 0o777 && targetOk(e.target));
      if (!ok || !relPath(e.path) || e.path === "" || !U53(e.size) || !Number.isInteger(e.mode) || e.mode < 0 || e.mode > 0o7777) bad("has an entry that isn't closed");
      if (lines[i] !== canon(e)) bad("has an entry that isn't canonical");
      if (!observed && (e.mode & 0o6000) !== 0) bad("keeps a set-id bit");
      if (kind === "symlink" && e.size !== rawPath(e.target).length) bad("has a symlink whose size isn't its target's");
      if (kind === "file") bytes += e.size;
      path = e.path;
      entries.set(path, e);
      if (entries.size > maxEntries) refuse("limit", "restore validation: more entries than a restore takes");
    }
    if (prev !== null && !(Buffer.compare(Buffer.from(prev), Buffer.from(path)) < 0)) bad("isn't sorted, each path once");
    prev = path;
  }
  if (trailer.count !== entries.size || trailer.total_bytes !== bytes) bad("trailer doesn't match its entries");
  return { entries, unexpected: odd };
}

/** The fields compared for each kind. */
const FIELDS = { dir: ["type", "size", "mode"], file: ["type", "size", "mode", "sha256"], symlink: ["type", "size", "mode", "target"] };

/**
 * Compare the snapshot's entries (a Map by path, parseListing's), less exactly the `unrestorable` paths (each must be
 * in the snapshot, or the manifest and the list disagree), with the filled tree's `actual` entries (a Map by path, the
 * same shape). Returns { ok, missing, extra, changed: { count, paths } } with every count and the first
 * DIFF_LIST_MAX paths of each, in path order.
 */
export function compareTrees(expected, actual, unrestorable = [], { listMax = DIFF_LIST_MAX } = {}) {
  if (!(expected instanceof Map) || !(actual instanceof Map) || !Array.isArray(unrestorable)) refuse("bad_form", "restore validation: not two listings");
  const skip = new Set(unrestorable);
  for (const p of skip) if (!expected.has(p)) refuse("bad_form", "restore validation: an unrestorable path the snapshot doesn't hold");
  const list = () => ({ count: 0, paths: [] });
  const missing = list(), extra = list(), changed = list();
  const note = (l, p) => { l.count += 1; if (l.paths.length < listMax) l.paths.push(p); };
  const paths = [...new Set([...expected.keys(), ...actual.keys()])].sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
  for (const p of paths) {
    const want = skip.has(p) ? undefined : expected.get(p), got = actual.get(p);
    if (want === undefined && got === undefined) continue;
    if (want === undefined) { note(extra, p); continue; } // (an unrestorable path that is present is extra too)
    if (got === undefined) { note(missing, p); continue; }
    if (want.type !== got.type || FIELDS[want.type].some((f) => want[f] !== got[f])) note(changed, p);
  }
  return { ok: missing.count === 0 && extra.count === 0 && changed.count === 0, missing, extra, changed };
}

/** The copy name's `h` for a main database at listed path `p`: the first 32 hex digits of SHA-256 over its raw bytes. */
export const copyKey = (p) => createHash("sha256").update(rawPath(p)).digest("hex").slice(0, 32);

/**
 * The private SQLite copies an observed listing names, checked for completeness (A2 r3.8): every `copy` is the name
 * its path gives (a main X as `<h>.db`, its X-wal or X-journal as `<h>.db-wal` or `<h>.db-journal`, h = copyKey(X)), no
 * sidecar copy is without its main's, and every X-wal or X-journal entry of a copied main X carries its copy, whatever
 * that sidecar's header says. Returns the mains, [{ path, copy, sidecars: [{ path, copy }] }], in path order; refuses
 * bad_form otherwise (an omitted sidecar is refused even if a main-only quick_check would pass).
 */
export function sqliteCopies(observed) {
  const bad = (what) => refuse("bad_form", `restore validation: the SQLite copies ${what}`);
  const mains = [];
  for (const [p, e] of observed) {
    if (!Object.hasOwn(e, "copy")) continue;
    const side = SIDECARS.find((x) => e.copy.endsWith(".db" + x));
    if (side === undefined) {
      if (e.copy !== `${copyKey(p)}.db`) bad("name a main by another path's key");
      continue;
    }
    if (!p.endsWith(side)) bad("name a sidecar that isn't named as one");
    const main = p.slice(0, -side.length);
    if (!observed.get(main)?.copy || observed.get(main).copy !== `${copyKey(main)}.db` || e.copy !== `${copyKey(main)}.db${side}`) bad("have a sidecar without its main's copy");
  }
  for (const [p, e] of observed) {
    if (!Object.hasOwn(e, "copy") || e.copy !== `${copyKey(p)}.db`) continue;
    const sidecars = [];
    for (const x of SIDECARS) {
      const s = observed.get(p + x);
      if (s === undefined) continue;
      if (s.type !== "file" || s.copy !== `${copyKey(p)}.db${x}`) bad("leave out a present sidecar of a copied main");
      sidecars.push({ path: p + x, copy: s.copy });
    }
    mains.push({ path: p, copy: e.copy, sidecars });
  }
  return mains;
}

/**
 * quick_check every copied database of a validated listing: each copy's SHA-256 (the main's and its sidecars') must be
 * its entry's before SQLite is pointed at it, in `dir` (the launcher's private <run>/<owner> directory). Returns
 * { ok, failed: [path] } (all mains checked; the first failures listed).
 */
export async function checkCopies(observed, dir, { sqlite, listMax = DIFF_LIST_MAX } = {}) {
  const failed = [];
  for (const m of sqliteCopies(observed)) {
    const files = [{ path: m.path, copy: m.copy }, ...m.sidecars];
    const same = files.every((f) => { try { return sha256File(join(dir, f.copy)) === observed.get(f.path).sha256; } catch { return false; } });
    const ok = same && (await quickCheck(join(dir, m.copy), { sqlite })).ok;
    if (!ok && failed.length < listMax) failed.push(m.path);
    if (!ok && failed.length >= listMax) break;
  }
  return { ok: failed.length === 0, failed };
}

/** The SHA-256 of a file's bytes, hex (validation's check of the digest list itself). */
export function sha256File(path, { fsx = fs } = {}) {
  const h = createHash("sha256");
  const fd = fsx.openSync(path, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const buf = Buffer.allocUnsafe(1 << 20);
    for (let n; (n = fsx.readSync(fd, buf, 0, buf.length, null)) > 0;) h.update(buf.subarray(0, n));
  } finally { fsx.closeSync(fd); }
  return h.digest("hex");
}

/**
 * PRAGMA quick_check on one private copy of a restored SQLite database (`path`, in the root-only directory the
 * launcher's tree-digest copied it into, with the database's -wal and -journal siblings when it had them). The copy
 * is opened for writing, so SQLite may recover a hot journal or replay a WAL there; nothing of the destination is
 * ever opened. Returns { ok, result }: ok only when SQLite answers exactly "ok". A file SQLite can't open (not a
 * database, or truncated) is { ok: false }; so is a copy that isn't there, or isn't a regular file of at least the
 * 100-byte header. node:sqlite is loaded only when a check runs.
 */
export async function quickCheck(path, { sqlite, fsx = fs } = {}) {
  const { DatabaseSync } = sqlite ?? (await import("node:sqlite"));
  // (opened for writing, SQLite would CREATE an empty database at a missing path, and an empty one passes: so the copy
  //  must already be there, a regular file of at least one page header)
  let st;
  try { st = fsx.lstatSync(path); } catch { return { ok: false, result: "no copy" }; }
  if (!st.isFile() || st.size < 100) return { ok: false, result: "not a database copy" };
  let db;
  try {
    db = new DatabaseSync(path);
    const rows = db.prepare("PRAGMA quick_check").all();
    const result = rows.map((r) => String(Object.values(r)[0])).join("\n");
    return { ok: result === "ok", result };
  } catch (e) {
    return { ok: false, result: String(e?.message ?? e).slice(0, 200) };
  } finally {
    try { db?.close(); } catch {}
  }
}

/**
 * The expected entries less what fill-home refused (its report, A2 §4 step 6): each refused path, and for a refused
 * directory its whole subtree, which fill neither walked nor placed. Matched on the ENCODED paths (A2 r3.9 §4b: the
 * codec commutes with "/"): the path itself, or it and "/" as a prefix. Each refused path must be in the list, and what
 * is removed (the path itself included) must be exactly the `entries` fill counted, else the report and the list
 * disagree (bad_form). A new Map.
 */
export function lessRefused(expected, refused) {
  const left = new Map(expected);
  for (const { path, entries } of refused) {
    const e = left.get(path);
    if (e === undefined) refuse("bad_form", "restore validation: a refused path the list doesn't hold");
    left.delete(path);
    let n = 1;
    if (e.type === "dir") for (const p of [...left.keys()]) if (p.startsWith(path + "/")) { left.delete(p); n++; }
    if (n !== entries) refuse("bad_form", "restore validation: a refused directory's count isn't the list's");
  }
  return left;
}

/**
 * One class's verdict (A2 r3.8.3 §4b): the digest list's bytes (`list`) must hash to the hash recorded at staged
 * (`sha256`) before a line of it is parsed; fill's report must be whole (not truncated) and list nothing unexpected;
 * tree-digest's listing (`observed`, its stdout) must parse and hold no unexpected line; and the list, less the
 * report's refused entries and the manifest's `unrestorable` paths, must equal it entry for entry. Returns
 * { ok: true, observed } (observed's entries, for the SQLite copies) or { ok: false, reason, why }; never throws for a
 * tree that doesn't match.
 */
export function checkClass({ list, sha256, report, observed, unrestorable = [] }) {
  const no = (reason, why) => ({ ok: false, reason, why });
  if (!Buffer.isBuffer(list)) return no("not_found", "no digest list");
  if (createHash("sha256").update(list).digest("hex") !== sha256) return no("bad_form", "the digest list isn't the one staged");
  if (report === null) return no("not_found", "no fill report for this attempt");
  if (report.truncated || report.unexpected.length > 0) return no("bad_form", "fill left unexpected or uncounted entries");
  try {
    const want = parseListing(list.toString("utf8"), {});
    if (!Buffer.from(list.toString("utf8")).equals(list)) return no("bad_form", "the digest list isn't UTF-8");
    const got = parseListing(observed, { observed: true });
    if (got.unexpected.length > 0) return no("bad_form", "the filled tree holds a special file or a mount");
    const diff = compareTrees(lessRefused(want.entries, report.refused), got.entries, unrestorable);
    if (!diff.ok) return no("bad_form", `the filled tree differs: ${diff.missing.count} missing, ${diff.extra.count} extra, ${diff.changed.count} changed`);
    return { ok: true, observed: got.entries };
  } catch (e) {
    // (a malformed or over-bound listing on either side, or a report that disagrees with the list)
    return no("bad_form", String(e?.message ?? e).slice(0, 200));
  }
}
