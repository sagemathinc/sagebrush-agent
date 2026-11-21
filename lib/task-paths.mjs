// A Delegate task's paths and the host's own file access (design/workspace-agent-protocol.md §6.1 "Paths"; plan r3.4
// §2.7).  The host touches a task's working copy only while nothing else of that task runs (its runner is a child it
// waits for), and then only through these: each path walked one component at a time from the task's root by lstat,
// every component a real directory and the last a regular file with one link; no link, FIFO, device or Windows
// reparse point is followed or opened.  Writes go to a temporary file beside the target, fsynced, then renamed.

import { closeSync, fstatSync, fsyncSync, lstatSync, mkdirSync, openSync, readSync, readdirSync, renameSync, unlinkSync, writeSync, constants } from "node:fs";
import { join } from "node:path";
import { syncDir, writeAll } from "./task-git.mjs";

export const PATH_LIMITS = Object.freeze({ files: 2000, component: 255, path: 1024 });
const RESERVED = /^(con|prn|aux|nul|com[0-9¹²³]|lpt[0-9¹²³])(\..*)?$/i;
const enc = new TextEncoder();
/** A UTF-16 surrogate with no partner: text that isn't well formed (the page refuses it too). */
export const LONE_SURROGATE = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/;
/** Text that isn't well formed for the protocol (§3 and §6: neither side accepts it): a lone surrogate, or U+0000 (a
 * binary document goes as {base64}). */
export const NOT_WELL_FORMED = /\u0000|[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/;

/** The name a volume that ignores case and Unicode form sees for `p` (macOS's APFS: é composed and é decomposed are
 * one name, as are "A" and "a"): NFC, lower case, then full case folding (upper then lower: "ß" and "ẞ" are "ss",
 * "ﬁ" is "fi", the final "ς" is "σ"), then NFC again.  Lower case first, so two names the old rule (equal lower case)
 * refused are always refused: without it "ẞ" would key to "ß", apart from "ß"'s "ss".  Two task paths with the same
 * key can't both be in one copy. */
export const nameKey = (p) => p.normalize("NFC").toLowerCase().toUpperCase().toLowerCase().normalize("NFC");

/** Why `p` isn't a task path, or null.  The rules: relative and normalized ("a/b.ipynb"), no "." or ".." component,
 * no empty component, no backslash, ":" (drive or ADS), control character or NUL, no Windows reserved name, no
 * component named .git (any case) or .sagebrush, each component at most 255 bytes, the path at most 1,024. */
export function pathProblem(p) {
  if (typeof p !== "string" || p === "") return "a path is a non-empty string";
  if (LONE_SURROGATE.test(p)) return "a path is well-formed text (no lone surrogate)";
  if (enc.encode(p).length > PATH_LIMITS.path) return `a path is at most ${PATH_LIMITS.path} bytes`;
  if (p.startsWith("/") || /[\\:\x00-\x1f\x7f]/.test(p)) return "a path is relative, with no backslash, colon or control character";
  for (const c of p.split("/")) {
    if (c === "" || c === "." || c === "..") return "a path has no empty, . or .. component";
    if (enc.encode(c).length > PATH_LIMITS.component) return `a path's component is at most ${PATH_LIMITS.component} bytes`;
    if (nameKey(c) === ".git" || c === ".sagebrush") return "no component may be .git or .sagebrush";
    if (RESERVED.test(c) || /[ .]$/.test(c)) return "a component may not be a Windows reserved name, or end in a space or dot";
  }
  return null;
}
/** Why a set of paths can't be one task's, or null: each valid, at most 2,000, no two the same name ignoring case
 * and Unicode form (nameKey), and no path also a folder of another (compared the same way). */
export function pathSetProblem(paths) {
  if (paths.length > PATH_LIMITS.files) return `at most ${PATH_LIMITS.files} files a task`;
  const seen = new Set();
  for (const p of paths) {
    const bad = pathProblem(p);
    if (bad) return `${JSON.stringify(p.slice(0, 80))}: ${bad}`;
    const k = nameKey(p);
    if (seen.has(k)) return `${JSON.stringify(p.slice(0, 80))}: two paths name the same file, ignoring case and Unicode form`;
    seen.add(k);
  }
  for (const p of paths) {
    const parts = nameKey(p).split("/");
    for (let i = 1; i < parts.length; i++) if (seen.has(parts.slice(0, i).join("/"))) return `${JSON.stringify(p.slice(0, 80))}: a path is also another's folder`;
  }
  return null;
}

export class UnsafePath extends Error {}
const isPlainDir = (st) => st.isDirectory() && !st.isSymbolicLink();

/** Walk `rel` under `root` component by component: every folder on the way a real directory (made, 0700, when
 * `make`), never a link.  The full path of the last component; it may not exist. */
function walk(root, rel, make) {
  // (the root itself first: a real directory, never a link, before anything under it is read or written)
  const rs = lstatSync(root);
  if (!isPlainDir(rs)) throw new UnsafePath("the working copy's folder is not a plain folder");
  const parts = rel.split("/");
  let cur = root;
  for (let i = 0; i < parts.length - 1; i++) {
    cur = join(cur, parts[i]);
    let st;
    try { st = lstatSync(cur); } catch (e) {
      if (e.code !== "ENOENT" || !make) throw e.code === "ENOENT" ? Object.assign(new Error("no such folder"), { code: "ENOENT" }) : e;
      mkdirSync(cur, { mode: 0o700 });
      st = lstatSync(cur);
    }
    if (!isPlainDir(st)) throw new UnsafePath(`${parts.slice(0, i + 1).join("/")} is not a plain folder`);
  }
  return join(cur, parts[parts.length - 1]);
}

/** A task file's bytes, read without following any link: a regular file with one link, at most `max` bytes. */
export function readTaskFile(root, rel, max) {
  const full = walk(root, rel, false);
  const st = lstatSync(full);
  if (!st.isFile() || st.nlink !== 1) throw new UnsafePath(`${rel} is not a plain file`);
  if (st.size > max) throw Object.assign(new Error(`${rel} is over ${max} bytes`), { code: "too_large" });
  const fd = openSync(full, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const f = fstatSync(fd);
    if (!f.isFile() || f.nlink !== 1 || f.ino !== st.ino || f.dev !== st.dev) throw new UnsafePath(`${rel} changed while it was opened`);
    if (f.size > max) throw Object.assign(new Error(`${rel} is over ${max} bytes`), { code: "too_large" });
    const buf = Buffer.alloc(f.size);
    let n = 0;
    while (n < f.size) { const k = readSync(fd, buf, n, f.size - n, n); if (k === 0) break; n += k; }
    return buf.subarray(0, n);
  } finally { closeSync(fd); }
}

/** Write a task file whole: folders made as needed (never through a link), the bytes to a temporary file beside it,
 * fsynced, renamed over it.  An existing target that isn't a plain file is refused, not replaced. */
export function writeTaskFile(root, rel, bytes) {
  const full = walk(root, rel, true);
  try {
    const st = lstatSync(full);
    if (!st.isFile() || st.nlink !== 1) throw new UnsafePath(`${rel} is not a plain file`);
  } catch (e) { if (e.code !== "ENOENT") throw e; }
  const tmp = `${full}.sb-${process.pid}-${Math.random().toString(36).slice(2, 10)}.tmp`;
  const fd = openSync(tmp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0), 0o600);
  try { writeAll(fd, bytes); fsyncSync(fd); } finally { closeSync(fd); }
  renameSync(tmp, full);
  syncDir(full.slice(0, full.lastIndexOf("/")));
}

/** Remove a task file (a plain file only). */
export function removeTaskFile(root, rel) {
  const full = walk(root, rel, false);
  const st = lstatSync(full);
  if (!st.isFile()) throw new UnsafePath(`${rel} is not a plain file`);
  unlinkSync(full);
}

/** Every file of the working copy, by a bounded no-follow walk: Map path -> {size}.  Anything but plain folders and
 * plain files with one link (a link, FIFO, device, a file with hard links) is a problem: `{files, problems}`.  At most
 * `maxEntries` entries are looked at; past them, a problem. */
export function scanTree(root, maxEntries = 20000) {
  const files = new Map(), problems = [];
  if (!isPlainDir(lstatSync(root))) return { files, problems: ["the working copy's folder is not a plain folder"] };
  let seen = 0;
  const visit = (dir, rel) => {
    for (const name of readdirSync(dir).sort()) {
      if (++seen > maxEntries) { problems.push(`more than ${maxEntries} entries`); return false; }
      const p = rel ? `${rel}/${name}` : name, full = join(dir, name), st = lstatSync(full);
      if (isPlainDir(st)) { if (visit(full, p) === false) return false; }
      else if (st.isFile() && st.nlink === 1) files.set(p, { size: st.size });
      else problems.push(`${p.slice(0, 200)}: ${st.isSymbolicLink() ? "a link" : st.isFile() ? "a file with more than one link" : "not a plain file or folder"}`);
    }
    return true;
  };
  visit(root, "");
  return { files, problems };
}

/** Why `dir` can't hold private task state, or null: it must be a real directory (not a link), owned by this user,
 * with no access for group or others.  POSIX only: on Windows there is no Delegate in M1 (plan r3.4 §0.5). */
export function privateDirProblem(dir) {
  if (process.platform === "win32") return "Delegate isn't available on Windows yet";
  let st;
  try { st = lstatSync(dir); } catch (e) { return `${dir}: ${e.code ?? e.message}`; }
  if (!isPlainDir(st)) return `${dir} is not a plain folder`;
  if (typeof process.getuid === "function" && st.uid !== process.getuid()) return `${dir} is not owned by this user`;
  if ((st.mode & 0o077) !== 0) return `${dir} is open to other users (mode ${(st.mode & 0o777).toString(8)})`;
  return null;
}
