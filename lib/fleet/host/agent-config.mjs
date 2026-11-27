// An agent's config tree (amendment L1; the joint harness/config note §3; host restore e2e r1.7 delta R4-d2b §3–§4):
// its reader, its generation hash, and the import entry the restore's config import writes through. The person's own
// editing commands are a later change; they will write through the same rules.
//
//   /srv/sagebrush/agent-config/<id>/       root:root 0700
//     gen-<n>/                              immutable generations (n: canonical decimal, at most 8 digits)
//     current                               root 0600 regular, nlink 1, at most 64 bytes: "gen-<n>\n"
//     .gen-<n>.tmp/                         at most one, during a generation's write
//     .current.tmp                          at most one, during current's replacement
//
// - **Every entry, at every depth**, is root-owned; a directory exactly 0700, a regular file exactly 0600. No link, no
//   special file. Each level is opened O_DIRECTORY|O_NOFOLLOW, its handle fstat'd against the lstat of its name, and
//   read only through /proc/self/fd/<handle>, never by its path again. Anything else refuses.
// - **The invariant (R4-d2b, SEC's ruling):** `current` is absent exactly when the tree holds no generation. A tree with
//   generations but no `current` refuses for every reader, except the config import's own (`importing: true`), which
//   then checks that the generations are a prefix of what it is importing.
// - **The generation hash:** sha256 of `{"v":1,"entries":[...]}\n`, the entries in byte order of path, each
//   {path, type, mode, size, sha256} (a directory with size 0 and no sha256). EMPTY_CONFIG_HASH is that of no entry.

import * as fs from "node:fs";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { refuse } from "../bytes.mjs";
import { realIo } from "./store.mjs";

/** Bounds (the joint note §3): generations kept, and per generation, files and bytes. */
export const MAX_GENERATIONS = 16;
export const MAX_FILES = 4096;
export const MAX_BYTES = 256 * 2 ** 20;
export const MAX_DEPTH = 64;
export const MAX_PATH_BYTES = 4096;
export const CURRENT_TMP = ".current.tmp";
const GEN = /^gen-(0|[1-9][0-9]{0,7})$/;
export const GEN_TMP = /^\.gen-(0|[1-9][0-9]{0,7})\.tmp$/;
const { O_RDONLY, O_DIRECTORY, O_NOFOLLOW, O_NONBLOCK, O_CREAT, O_EXCL, O_WRONLY } = fs.constants;

const sha256 = (b) => createHash("sha256").update(b).digest("hex");
const bad = (why) => refuse("not_granted", `agent config: ${why}`);

/** The generation hash of a listing (its entries already in byte order of path). */
export function generationHash(entries) {
  return sha256(JSON.stringify({ v: 1, entries }) + "\n");
}
/** The hash of no configuration at all (a tree that was never configured). */
export const EMPTY_CONFIG_HASH = generationHash([]);

/**
 * The userspace dev_t of the launcher's [major, minor] (the kernel's new_encode_dev), so a handle's fstat can be
 * compared with a recorded identity.
 */
export const devOf = ([major, minor]) => (minor & 0xff) + ((major & 0xfff) * 2 ** 8) + ((minor & ~0xff) * 2 ** 12) + (Math.floor(major / 0x1000) * 2 ** 32);

/** Open `name` beneath the directory handle `dfd` (or the path `path` when dfd is null) as a directory, no-follow, the handle the lstat's object. */
function openDir(fsx, base, { uid }) {
  let st;
  try { st = fsx.lstatSync(base); } catch (e) { if (e?.code === "ENOENT") refuse("not_found", "agent config: a directory is missing"); throw e; }
  if (!st.isDirectory()) bad("not a directory (a link or another object)");
  let fd;
  try { fd = fsx.openSync(base, O_RDONLY | O_DIRECTORY | O_NOFOLLOW); } catch (e) {
    if (["ELOOP", "ENOTDIR", "ENOENT"].includes(e?.code)) bad("a directory was replaced while it was read");
    throw e;
  }
  const f = fsx.fstatSync(fd);
  if (!f.isDirectory() || f.dev !== st.dev || f.ino !== st.ino) { fsx.closeSync(fd); bad("a directory was replaced while it was read"); }
  if (f.uid !== uid || f.gid !== 0 && uid === 0 || (f.mode & 0o7777) !== 0o700) { fsx.closeSync(fd); bad("a directory isn't root's, exactly 0700"); }
  return { fd, st: f };
}
const at = (fd, name) => `/proc/self/fd/${fd}/${name}`;
const names = (fsx, fd) => fsx.readdirSync(`/proc/self/fd/${fd}`, { encoding: "buffer" }).map((b) => {
  const s = b.toString("utf8");
  if (!Buffer.from(s, "utf8").equals(b) || s.includes("/")) bad("a name isn't UTF-8");
  return s;
});

/** A regular file beneath `dfd`: root's, exactly 0600, nlink 1 (`single`), at most `max` bytes; its bytes. */
function readFileAt(fsx, dfd, name, { uid, max, single = false }) {
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
    if (f.uid !== uid || (f.mode & 0o7777) !== 0o600 || (single && f.nlink !== 1)) bad(`${name} isn't root's, exactly 0600`);
    if (f.size > max) bad(`${name} is too large`);
    const buf = Buffer.alloc(f.size);
    for (let off = 0; off < buf.length;) { const k = fsx.readSync(fd, buf, off, buf.length - off, off); if (k <= 0) bad(`${name} changed while it was read`); off += k; }
    return buf;
  } finally { fsx.closeSync(fd); }
}

/** One generation's listing, walked by handle: { entries, hash, files, bytes }. */
function listGeneration(fsx, dfd, name, { uid }) {
  const entries = [];
  let files = 0, bytes = 0;
  const walk = (base, rel, depth) => {
    if (depth > MAX_DEPTH) bad("a generation is too deep");
    const { fd } = openDir(fsx, base, { uid });
    try {
      for (const n of names(fsx, fd)) {
        const path = rel === "" ? n : `${rel}/${n}`;
        if (Buffer.byteLength(path, "utf8") > MAX_PATH_BYTES) bad("a path is too long");
        const st = fsx.lstatSync(at(fd, n));
        if (st.isDirectory()) {
          entries.push({ path, type: "dir", mode: 0o700, size: 0 });
          walk(at(fd, n), path, depth + 1);
        } else if (st.isFile()) {
          if (++files > MAX_FILES) bad("a generation has too many files");
          const b = readFileAt(fsx, fd, n, { uid, max: MAX_BYTES });
          bytes += b.length;
          if (bytes > MAX_BYTES) bad("a generation is too large");
          entries.push({ path, type: "file", mode: 0o600, size: b.length, sha256: sha256(b) });
        } else bad(`${path} is a link or a special file`);
      }
    } finally { fsx.closeSync(fd); }
  };
  walk(at(dfd, name), "", 0);
  entries.sort((x, y) => Buffer.compare(Buffer.from(x.path, "utf8"), Buffer.from(y.path, "utf8")));
  return { entries, hash: generationHash(entries), files, bytes };
}

/**
 * Read a config tree at `root` (a live tree, or a staged copy's `data/<id>`), whole. Options: `uid` (root's, a test
 * seam), `identity` (the provisioning's recorded { dev: [major, minor], ino } of the tree, checked on its handle),
 * `importing` (the config import's own read, which may find generations with no `current`). Returns
 * { current: n | null, generations: { n: { entries, hash } }, leftovers: { gen: n | null, current: bool } }.
 */
export function readConfigTree(root, { uid = 0, identity = null, importing = false, fsx = fs } = {}) {
  const h = openRoot(fsx, root, { uid, identity });
  try { return readTreeAt(fsx, h.fd, { uid, importing }); } finally { fsx.closeSync(h.fd); }
}

/**
 * The tree's root opened as a directory, no-follow, its handle checked against the recorded identity (when given):
 * every read and write of a writer goes through this ONE handle, so a root swapped for a substitute at any point
 * after it is opened is never written (R4-d2b §4: a substitute refuses before any effect).
 */
function openRoot(fsx, root, { uid, identity }) {
  const h = openDir(fsx, root, { uid });
  if (identity !== null && (h.st.dev !== devOf(identity.dev) || h.st.ino !== identity.ino)) { fsx.closeSync(h.fd); bad("not the recorded tree"); }
  return h;
}

/** Read the tree through its open root handle `fd` (readConfigTree's result). */
function readTreeAt(fsx, fd, { uid, importing }) {
  const generations = {};
  let currentText = null, genTmp = null, currentTmp = false;
  for (const n of names(fsx, fd)) {
    const g = GEN.exec(n), t = GEN_TMP.exec(n);
    const lst = fsx.lstatSync(at(fd, n));
    if (g) {
      if (!lst.isDirectory()) bad(`${n} isn't a directory`);
      generations[g[1]] = null;
    } else if (n === "current") {
      currentText = readFileAt(fsx, fd, n, { uid, max: 64, single: true }).toString("utf8");
    } else if (t) {
      if (!lst.isDirectory() || genTmp !== null) bad("more than one generation in progress, or not a directory");
      genTmp = t[1];
    } else if (n === CURRENT_TMP) {
      // A leftover: never read as current. A link is reported (setCurrent unlinks it itself, never following it); a
      // regular file must be root's 0600 like current; anything else (a directory, a special file) refuses.
      if (lst.isSymbolicLink()) currentTmp = true;
      else if (lst.isFile()) { readFileAt(fsx, fd, n, { uid, max: 64, single: true }); currentTmp = true; }
      else bad(".current.tmp isn't a regular file or a leftover link");
    } else bad(`a foreign entry: ${n}`);
  }
  if (Object.keys(generations).length > MAX_GENERATIONS) bad("more generations than kept");
  for (const n of Object.keys(generations)) {
    const { entries, hash } = listGeneration(fsx, fd, `gen-${n}`, { uid });
    generations[n] = { entries, hash };
  }
  let current = null;
  if (currentText !== null) {
    const m = /^gen-(0|[1-9][0-9]{0,7})\n$/.exec(currentText);
    if (!m) bad("current isn't exactly a generation's name");
    if (!Object.hasOwn(generations, m[1])) bad("current names a generation that isn't there");
    current = m[1];
  }
  // The invariant: no current exactly when no generation (the config import's own read excepted).
  if (current === null && Object.keys(generations).length > 0 && !importing) bad("generations with no current");
  return { current, generations, leftovers: { gen: genTmp, current: currentTmp } };
}

/**
 * Remove a leftover `.gen-<n>.tmp` beneath the root handle, by handle all the way down: each directory opened
 * no-follow and checked (root's, exactly 0700) before its entries are unlinked; a non-directory is unlinked itself,
 * never followed.
 */
function removeTmpAt(fsx, dfd, name, { uid }) {
  const { fd } = openDir(fsx, at(dfd, name), { uid });
  try {
    for (const n of names(fsx, fd)) {
      if (fsx.lstatSync(at(fd, n)).isDirectory()) removeTmpAt(fsx, fd, n, { uid });
      else fsx.unlinkSync(at(fd, n));
    }
  } finally { fsx.closeSync(fd); }
  fsx.rmdirSync(at(dfd, name));
}

/** The configuration's hash: the current generation's, or EMPTY_CONFIG_HASH for a tree never configured. */
export function configHash(tree) {
  return tree.current === null ? EMPTY_CONFIG_HASH : tree.generations[tree.current].hash;
}

/**
 * Import one generation: write the staged generation `source` (its directory, read by readConfigTree's rules) into the
 * live tree at `root` as `gen-<n>`. Exactly the source's listing, written to `.gen-<n>.tmp` (each file created
 * exclusively, written whole and fsynced, every directory fsynced), then renamed to `gen-<n>`; the tree fsynced.
 * An existing `gen-<n>` with the source's hash is kept; another one refuses. A leftover `.gen-*.tmp` is removed first.
 * Returns the hash written. Options as readConfigTree's, plus `io`.
 */
export function importGeneration(root, n, source, { uid = 0, identity = null, fsx = fs, io = realIo, onStep = () => {} } = {}) {
  if (typeof n !== "string" || !/^(0|[1-9][0-9]{0,7})$/.test(n)) refuse("bad_form", "agent config: a bad generation number");
  const want = readGenerationDir(source, { uid, fsx });
  // One root handle for the read, every write and the read-back.
  const { fd } = openRoot(fsx, root, { uid, identity });
  try {
    const tree = readTreeAt(fsx, fd, { uid, importing: true });
    if (Object.hasOwn(tree.generations, n)) {
      if (tree.generations[n].hash !== want.hash) bad(`gen-${n} exists with other content`);
      return want.hash;
    }
    if (tree.leftovers.gen !== null) removeTmpAt(fsx, fd, `.gen-${tree.leftovers.gen}.tmp`, { uid });
    const tmp = `.gen-${n}.tmp`;
    fsx.mkdirSync(at(fd, tmp), { mode: 0o700 });
    fsx.chmodSync(at(fd, tmp), 0o700);
    onStep("tmp-made");
    const { fd: tfd } = openDir(fsx, at(fd, tmp), { uid });
    try {
      const src = openDir(fsx, source, { uid });
      try { copyInto(fsx, src.fd, tfd, "", want, io); } finally { fsx.closeSync(src.fd); }
      io.fsync(tfd);
    } finally { fsx.closeSync(tfd); }
    onStep("tmp-written");
    fsx.renameSync(at(fd, tmp), at(fd, `gen-${n}`));
    io.fsync(fd);
    onStep("renamed");
    const back = readTreeAt(fsx, fd, { uid, importing: true });
    if (!Object.hasOwn(back.generations, n) || back.generations[n].hash !== want.hash) refuse("outcome_unknown", `agent config: gen-${n} didn't read back equal`);
    return want.hash;
  } finally { fsx.closeSync(fd); }
}

/** A standalone generation directory (a staged one), listed by the same rules. */
export function readGenerationDir(dir, { uid = 0, fsx = fs } = {}) {
  const parent = join(dir, "..");
  const { fd } = openDir(fsx, parent, { uid: fsx.lstatSync(parent).uid });
  try {
    const name = dir.slice(dir.lastIndexOf("/") + 1);
    return listGeneration(fsx, fd, name, { uid });
  } finally { fsx.closeSync(fd); }
}

/** Copy the listed entries under `rel` from the source handle into the destination handle, exactly. */
function copyInto(fsx, sfd, dfd, rel, want, io) {
  const here = want.entries.filter((e) => { const i = e.path.lastIndexOf("/"); return (i === -1 ? "" : e.path.slice(0, i)) === rel; });
  for (const e of here) {
    const name = e.path.slice(e.path.lastIndexOf("/") + 1);
    if (e.type === "dir") {
      fsx.mkdirSync(at(dfd, name), { mode: 0o700 });
      fsx.chmodSync(at(dfd, name), 0o700);
      const s = openDir(fsx, at(sfd, name), { uid: fsx.fstatSync(sfd).uid });
      const d = openDir(fsx, at(dfd, name), { uid: fsx.fstatSync(dfd).uid });
      try { copyInto(fsx, s.fd, d.fd, e.path, want, io); io.fsync(d.fd); } finally { fsx.closeSync(s.fd); fsx.closeSync(d.fd); }
    } else {
      const b = readFileAt(fsx, sfd, name, { uid: fsx.fstatSync(sfd).uid, max: MAX_BYTES });
      if (b.length !== e.size || sha256(b) !== e.sha256) refuse("outcome_unknown", "agent config: a staged file changed while it was imported");
      const out = fsx.openSync(at(dfd, name), O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW, 0o600);
      try {
        fsx.fchmodSync(out, 0o600);
        for (let off = 0; off < b.length;) { const k = io.write(out, b, off, b.length - off); if (!Number.isSafeInteger(k) || k <= 0) refuse("outcome_unknown", "agent config: a short write"); off += k; }
        io.fsync(out);
      } finally { fsx.closeSync(out); }
    }
  }
}

/**
 * Point `current` at `gen-<n>` (it must exist and read back): a leftover `.current.tmp` is unlinked first through the
 * tree's handle (never followed; a directory there refuses, nothing removed); then `.current.tmp` is created
 * exclusively (O_CREAT|O_EXCL|O_NOFOLLOW, 0600), written whole, fsynced, renamed over `current`, and the tree fsynced.
 */
export function setCurrent(root, n, { uid = 0, identity = null, fsx = fs, io = realIo, onStep = () => {} } = {}) {
  // One root handle for the read, every write and the read-back.
  const { fd } = openRoot(fsx, root, { uid, identity });
  try {
    const tree = readTreeAt(fsx, fd, { uid, importing: true });
    if (!Object.hasOwn(tree.generations, n)) refuse("not_found", `agent config: gen-${n} isn't there`);
    const tmp = at(fd, CURRENT_TMP);
    let st = null;
    try { st = fsx.lstatSync(tmp); } catch (e) { if (e?.code !== "ENOENT") throw e; }
    if (st !== null) {
      if (st.isDirectory()) bad(".current.tmp is a directory");
      fsx.unlinkSync(tmp); // unlinkat: a link is removed itself, never followed
      io.fsync(fd);
    }
    const text = Buffer.from(`gen-${n}\n`);
    const out = fsx.openSync(tmp, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW, 0o600);
    try {
      fsx.fchmodSync(out, 0o600);
      for (let off = 0; off < text.length;) { const k = io.write(out, text, off, text.length - off); if (!Number.isSafeInteger(k) || k <= 0) refuse("outcome_unknown", "agent config: a short write"); off += k; }
      onStep("tmp-written");
      io.fsync(out);
    } finally { fsx.closeSync(out); }
    onStep("tmp-synced");
    fsx.renameSync(tmp, at(fd, "current"));
    onStep("renamed");
    io.fsync(fd);
    const back = readTreeAt(fsx, fd, { uid, importing: false });
    if (back.current !== n) refuse("outcome_unknown", "agent config: current didn't read back");
  } finally { fsx.closeSync(fd); }
}
