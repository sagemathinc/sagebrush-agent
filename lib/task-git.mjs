// A Delegate task's history: an ordinary bare git repository, written by this module alone (pair-delegate plan r3.3
// §2.1; the protocol: design/workspace-agent-protocol.md §6).  Objects are git's own (blob, tree, commit: their SHA-1
// ids as `git hash-object` gives them), written as loose objects; a ref moves only by compare-and-swap under git's own
// lock file (`<ref>.lock`, created exclusively), so ordinary git reads the repository and agrees with it:
//   git --git-dir=<task>/git --work-tree=<task>/work log --all
// What this never does: read a config, a hook, an attribute or a pointer from anywhere; run anything; fetch or push.
// The repository's location is the caller's fixed path, never one found in a working copy.

import { createHash } from "node:crypto";
import { closeSync, fsyncSync, mkdirSync, openSync, readFileSync, readdirSync, renameSync, unlinkSync, writeSync, existsSync, lstatSync } from "node:fs";
import { join, dirname } from "node:path";
import { deflateSync, inflateSync } from "node:zlib";

/** The largest object read back (bytes, inflated): a task's document is at most 4 MB, a tree or commit far less. */
export const OBJECT_READ_MAX = 8 * 1024 * 1024;
const OID = /^[0-9a-f]{40}$/;
const REF = /^refs\/(heads|tags)\/[a-z0-9][a-z0-9-]{0,63}$/;
/** Who writes a task's commits (no person's name: the agent records what it and the page did). */
export const AUTHOR = "sagebrush-agent <tasks@sagebrush-agent.invalid>";

const enc = new TextEncoder();
const bytesOf = (b) => (typeof b === "string" ? enc.encode(b) : b);

/** The git id of an object of `type` holding `body`. */
export function objectId(type, body) {
  const b = bytesOf(body);
  return createHash("sha1").update(`${type} ${b.length}\0`).update(b).digest("hex");
}
/** The git blob id of `bytes` (what P0's `blob` is: the SHA-1 of "blob <n>\0" and the bytes). */
export const blobId = (bytes) => objectId("blob", bytes);

// (a file written whole and durably: a unique temporary name beside it, fsync, rename; the directory fsynced after)
function writeDurable(path, data, mode = 0o600) {
  const tmp = `${path}.${process.pid}.${Date.now().toString(36)}${Math.random().toString(36).slice(2, 8)}.tmp`;
  const fd = openSync(tmp, "wx", mode);
  try {
    writeSync(fd, data);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  renameSync(tmp, path);
  syncDir(dirname(path));
}
export function syncDir(dir) {
  let fd;
  try { fd = openSync(dir, "r"); fsyncSync(fd); } catch {} finally { if (fd !== undefined) closeSync(fd); }
}

/** A new bare repository at `gitdir` (which must not exist), private to this user. */
export function initRepo(gitdir) {
  mkdirSync(gitdir, { mode: 0o700 });
  for (const d of ["objects", "refs", "refs/heads", "refs/tags"]) mkdirSync(join(gitdir, d), { mode: 0o700 });
  writeDurable(join(gitdir, "HEAD"), "ref: refs/heads/base\n");
  writeDurable(join(gitdir, "config"), "[core]\n\trepositoryformatversion = 0\n\tbare = true\n");
}

/** Write an object (if it isn't there); its id. */
export function writeObject(gitdir, type, body) {
  const b = bytesOf(body);
  const oid = objectId(type, b);
  const dir = join(gitdir, "objects", oid.slice(0, 2)), path = join(dir, oid.slice(2));
  if (existsSync(path)) return oid;
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const head = enc.encode(`${type} ${b.length}\0`);
  const all = new Uint8Array(head.length + b.length);
  all.set(head, 0);
  all.set(b, head.length);
  writeDurable(path, deflateSync(all), 0o400);
  return oid;
}

/** An object's type and body; checked against its id.  Throws if missing, corrupt or too large. */
export function readObject(gitdir, oid) {
  if (!OID.test(oid)) throw new Error("not an object id");
  const raw = inflateSync(readFileSync(join(gitdir, "objects", oid.slice(0, 2), oid.slice(2))), { maxOutputLength: OBJECT_READ_MAX + 64 });
  const nul = raw.indexOf(0);
  const m = /^(blob|tree|commit) (\d+)$/.exec(raw.subarray(0, nul).toString("latin1"));
  if (!m || Number(m[2]) !== raw.length - nul - 1) throw new Error(`object ${oid} is malformed`);
  const body = raw.subarray(nul + 1);
  if (objectId(m[1], body) !== oid) throw new Error(`object ${oid} doesn't match its id`);
  return { type: m[1], body };
}

// ---- trees: a flat map of path -> blob id, written as git's nested trees
/** git's tree order: names as bytes, a directory's name compared as if it ended in "/". */
const treeKey = (e) => Buffer.from(e.dir ? e.name + "/" : e.name, "utf8");
function writeTreeLevel(gitdir, files) {
  const here = new Map(); // name -> {blob} | {sub: Map}
  for (const [path, oid] of files) {
    const [first, ...rest] = path.split("/");
    if (!rest.length) here.set(first, { blob: oid });
    else {
      const e = here.get(first) ?? { sub: new Map() };
      e.sub.set(rest.join("/"), oid);
      here.set(first, e);
    }
  }
  const entries = [...here].map(([name, e]) => (e.sub ? { name, dir: true, oid: writeTreeLevel(gitdir, e.sub) } : { name, dir: false, oid: e.blob }));
  entries.sort((a, b) => Buffer.compare(treeKey(a), treeKey(b)));
  const parts = entries.flatMap((e) => [enc.encode(`${e.dir ? "40000" : "100644"} ${e.name}\0`), Buffer.from(e.oid, "hex")]);
  return writeObject(gitdir, "tree", Buffer.concat(parts));
}
/** A tree for `files` (Map path -> blob id); its id. */
export const writeTree = (gitdir, files) => writeTreeLevel(gitdir, files);

/** A tree's files, recursively: Map path -> blob id.  Only regular files and directories are accepted. */
export function readTree(gitdir, oid, prefix = "", out = new Map()) {
  const { type, body } = readObject(gitdir, oid);
  if (type !== "tree") throw new Error(`${oid} is not a tree`);
  let i = 0;
  while (i < body.length) {
    const sp = body.indexOf(0x20, i), nul = body.indexOf(0, sp);
    const mode = body.subarray(i, sp).toString("latin1"), name = body.subarray(sp + 1, nul).toString("utf8");
    const child = body.subarray(nul + 1, nul + 21).toString("hex");
    i = nul + 21;
    if (mode === "40000") readTree(gitdir, child, prefix + name + "/", out);
    else if (mode === "100644") out.set(prefix + name, child);
    else throw new Error(`tree ${oid} has an entry of mode ${mode}`);
  }
  return out;
}

// ---- commits
/** A commit of `tree` with `parents` and `message`, at `time` (seconds); its id. */
export function writeCommit(gitdir, { tree, parents = [], message, time }) {
  const t = `${Math.floor(time)} +0000`;
  const text = `tree ${tree}\n${parents.map((p) => `parent ${p}\n`).join("")}author ${AUTHOR} ${t}\ncommitter ${AUTHOR} ${t}\n\n${message.endsWith("\n") ? message : message + "\n"}`;
  return writeObject(gitdir, "commit", text);
}
/** A commit's tree, parents and message. */
export function readCommit(gitdir, oid) {
  const { type, body } = readObject(gitdir, oid);
  if (type !== "commit") throw new Error(`${oid} is not a commit`);
  const text = body.toString("utf8"), blank = text.indexOf("\n\n");
  const head = text.slice(0, blank).split("\n");
  return { tree: head.find((l) => l.startsWith("tree ")).slice(5), parents: head.filter((l) => l.startsWith("parent ")).map((l) => l.slice(7)), message: text.slice(blank + 2) };
}

// ---- refs: read, and moved only by compare-and-swap
/** A ref's commit id, or null if it doesn't exist. */
export function readRef(gitdir, ref) {
  if (!REF.test(ref)) throw new Error("not a task ref");
  let t;
  try { t = readFileSync(join(gitdir, ref), "utf8"); } catch (e) { if (e.code === "ENOENT") return null; throw e; }
  const oid = t.trim();
  if (!OID.test(oid)) throw new Error(`ref ${ref} is malformed`);
  return oid;
}
export class RefConflict extends Error {}
/** Move `ref` from `expect` (null: absent) to `next`, or throw RefConflict.  git's protocol: `<ref>.lock` created
 * exclusively (another writer's lock is a conflict), the value checked under it, written, fsynced, renamed. */
export function casRef(gitdir, ref, expect, next) {
  if (!REF.test(ref) || !OID.test(next) || (expect !== null && !OID.test(expect))) throw new Error("bad ref update");
  const path = join(gitdir, ref), lock = path + ".lock";
  let fd;
  try { fd = openSync(lock, "wx", 0o600); } catch (e) { if (e.code === "EEXIST") throw new RefConflict(`${ref} is locked`); throw e; }
  let moved = false;
  try {
    const now = readRef(gitdir, ref);
    if (now !== expect) throw new RefConflict(`${ref} is ${now ?? "absent"}, not ${expect ?? "absent"}`);
    writeSync(fd, next + "\n");
    fsyncSync(fd);
    closeSync(fd);
    fd = undefined;
    renameSync(lock, path);
    moved = true;
    syncDir(dirname(path));
  } finally {
    if (fd !== undefined) closeSync(fd);
    if (!moved) try { unlinkSync(lock); } catch {}
  }
}
/** Locks left by a crash (only this process writes a task's refs, one operation at a time): removed at recovery. */
export function clearStaleLocks(gitdir) {
  for (const d of ["refs/heads", "refs/tags"]) {
    let names = [];
    try { names = readdirSync(join(gitdir, d)); } catch {}
    for (const n of names) if (n.endsWith(".lock")) { const p = join(gitdir, d, n); if (lstatSync(p).isFile()) unlinkSync(p); }
  }
}
