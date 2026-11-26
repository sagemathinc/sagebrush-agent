// Host restore (launcher contract A2 r3.14 r2 §3): the staged host-store copy, read IN PLACE and only through file
// descriptors. Every directory, from the copy's root down, is opened O_DIRECTORY|O_NOFOLLOW, its handle fstat'd against
// the lstat of its name, and its children are named only through /proc/self/fd/<handle>, never by path again. Every
// entry must be owned by `uid` (root), a directory exactly 0700 and a regular file exactly 0600 (as the backup writes
// them); a link, a special file, another owner or mode, or an object swapped between its lstat and its open refuses.
// Bounds: at most MAX_FILES entries and MAX_BYTES of file bytes per copy.

import * as fs from "node:fs";
import { refuse } from "../bytes.mjs";

export const MAX_FILES = 200_000;
export const MAX_BYTES = 4 * 1024 * 1024 * 1024 + 64 * 1024 * 1024;
const { O_RDONLY, O_DIRECTORY, O_NOFOLLOW, O_NONBLOCK } = fs.constants;

const bad = (why) => refuse("not_granted", `host store copy: ${why}`);
const at = (fd, name) => `/proc/self/fd/${fd}/${name}`;
const okName = (n) => n !== "" && n !== "." && n !== ".." && !n.includes("/");

/** Open `path` (a directory) no-follow; its handle must be the lstat'd object, `uid`'s, exactly 0700. */
function openDir(fsx, path, uid) {
  let st;
  try { st = fsx.lstatSync(path); } catch (e) { if (e?.code === "ENOENT") refuse("not_found", "host store copy: a directory is missing"); throw e; }
  if (!st.isDirectory()) bad("not a directory (a link or another object)");
  let fd;
  try { fd = fsx.openSync(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW); } catch (e) {
    if (["ELOOP", "ENOTDIR", "ENOENT"].includes(e?.code)) bad("a directory was replaced while it was read");
    throw e;
  }
  const f = fsx.fstatSync(fd);
  if (!f.isDirectory() || f.dev !== st.dev || f.ino !== st.ino) { fsx.closeSync(fd); bad("a directory was replaced while it was read"); }
  if (f.uid !== uid || (f.mode & 0o7777) !== 0o700) { fsx.closeSync(fd); bad("a directory isn't root's, exactly 0700"); }
  return fd;
}

/** Read a regular file beneath the directory handle `dfd`: `uid`'s, exactly 0600, at most `max` bytes. */
function readAt(fsx, dfd, name, uid, max) {
  const p = at(dfd, name);
  let st;
  try { st = fsx.lstatSync(p); } catch (e) { if (e?.code === "ENOENT") refuse("not_found", `host store copy: ${name} is missing`); throw e; }
  if (!st.isFile()) bad(`${name} isn't a regular file`);
  let fd;
  try { fd = fsx.openSync(p, O_RDONLY | O_NOFOLLOW | O_NONBLOCK); } catch (e) {
    if (["ELOOP", "ENXIO", "ENOENT"].includes(e?.code)) bad(`${name} was replaced while it was read`);
    throw e;
  }
  try {
    const f = fsx.fstatSync(fd);
    if (!f.isFile() || f.dev !== st.dev || f.ino !== st.ino) bad(`${name} was replaced while it was read`);
    if (f.uid !== uid || (f.mode & 0o7777) !== 0o600) bad(`${name} isn't root's, exactly 0600`);
    if (f.size > max) bad(`${name} is too large`);
    const buf = Buffer.alloc(f.size);
    for (let off = 0; off < buf.length;) { const k = fsx.readSync(fd, buf, off, buf.length - off, off); if (k <= 0) bad(`${name} changed while it was read`); off += k; }
    return buf;
  } finally { fsx.closeSync(fd); }
}

/** A regular file's size beneath `dfd`, its handle checked as readAt checks it (owner, exact mode, the same object). */
function statAt(fsx, dfd, name, uid) {
  const p = at(dfd, name);
  const st = fsx.lstatSync(p);
  if (!st.isFile()) bad(`${name} isn't a regular file`);
  let fd;
  try { fd = fsx.openSync(p, O_RDONLY | O_NOFOLLOW | O_NONBLOCK); } catch (e) {
    if (["ELOOP", "ENXIO", "ENOENT"].includes(e?.code)) bad(`${name} was replaced while it was read`);
    throw e;
  }
  try {
    const f = fsx.fstatSync(fd);
    if (!f.isFile() || f.dev !== st.dev || f.ino !== st.ino) bad(`${name} was replaced while it was read`);
    if (f.uid !== uid || (f.mode & 0o7777) !== 0o600) bad(`${name} isn't root's, exactly 0600`);
    return f.size;
  } finally { fsx.closeSync(fd); }
}

const names = (fsx, fd) => fsx.readdirSync(`/proc/self/fd/${fd}`, { encoding: "buffer" }).map((b) => {
  const s = b.toString("utf8");
  if (!Buffer.from(s, "utf8").equals(b) || !okName(s)) bad("a name isn't UTF-8");
  return s;
}).sort();

/**
 * A reader of the staged copy at `root` (the attempt's data/<leaf>, whose ancestors the caller proved). Each call
 * re-opens from `root` down, component by component. `uid`: root's (a test seam).
 * - list(rel): the sorted names in the directory `rel` ("" for the copy's top);
 * - read(rel): a regular file's bytes;
 * - walk(rel): every directory and regular file beneath `rel` (relative to it), sorted, each checked (a file's owner,
 *   mode and size by its handle; its bytes are read later through read()); bounded by count and total size.
 */
export function copyReader(root, { uid = 0, fsx = fs, maxFiles = MAX_FILES, maxBytes = MAX_BYTES } = {}) {
  const parts = (rel) => {
    const p = rel === "" ? [] : rel.split("/");
    if (!p.every(okName)) refuse("bad_form", "host store copy: a bad relative path");
    return p;
  };
  // The root's identity, pinned at the first open: a root replaced between calls is refused.
  let pinned = null;
  const openRoot = () => {
    const fd = openDir(fsx, root, uid);
    const f = fsx.fstatSync(fd);
    if (pinned === null) pinned = { dev: f.dev, ino: f.ino };
    else if (f.dev !== pinned.dev || f.ino !== pinned.ino) { fsx.closeSync(fd); bad("the copy's root was replaced between reads"); }
    return fd;
  };
  /** Open the directory `rel`, one component at a time from the root's handle; run fn(fd); close every handle. */
  const withDir = (rel, fn) => {
    const opened = [openRoot()];
    try {
      for (const part of parts(rel)) opened.push(openDir(fsx, at(opened.at(-1), part), uid));
      return fn(opened.at(-1));
    } finally { for (const fd of opened.reverse()) fsx.closeSync(fd); }
  };
  return {
    list: (rel = "") => withDir(rel, (fd) => names(fsx, fd)),
    read: (rel) => {
      const p = parts(rel);
      if (p.length === 0) refuse("bad_form", "host store copy: not a file");
      return withDir(p.slice(0, -1).join("/"), (fd) => readAt(fsx, fd, p.at(-1), uid, maxBytes));
    },
    walk: (rel = "") => withDir(rel, (top) => {
      const out = [];
      let bytes = 0;
      const go = (dfd, prefix) => {
        for (const n of names(fsx, dfd)) {
          const r = prefix === "" ? n : `${prefix}/${n}`;
          const st = fsx.lstatSync(at(dfd, n));
          if (st.isDirectory()) {
            out.push({ rel: r, dir: true });
            if (out.length > maxFiles) refuse("limit", "host store copy: more entries than an import takes");
            const fd = openDir(fsx, at(dfd, n), uid);
            try { go(fd, r); } finally { fsx.closeSync(fd); }
          } else if (st.isFile()) {
            const size = statAt(fsx, dfd, n, uid);
            bytes += size;
            if (bytes > maxBytes) refuse("limit", "host store copy: larger than an import takes");
            out.push({ rel: r, dir: false, size });
            if (out.length > maxFiles) refuse("limit", "host store copy: more entries than an import takes");
          } else bad(`${r} is a link or a special file`);
        }
      };
      go(top, "");
      return out;
    }),
  };
}
