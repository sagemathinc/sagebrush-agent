// The local copy of Sagebrush's source for sagebrush_source (#1663, design r3 §4): a host-owned, read-only input,
// never task storage. Layout, under a private root (~/.cache/sagebrush-agent/source, every level a real directory of
// this account, mode 0700):
//
//   .lock.sqlite             the machine-wide lock: admission, leases and pruning happen only while holding it
//   .fetch.sqlite            held while one download and extraction runs (one at a time, machine-wide)
//   .staging-<random>/       an extraction in progress (removed on failure, or when its owner is gone)
//   .trash-<random>/         a commit being removed
//   <commit>/RESERVED        a slot reserved for a commit being fetched (its owner's pid and start time)
//   <commit>/tree/           the files (folders 0500, files 0400), renamed into place when complete
//   <commit>/index.json      the admitted files and the skipped ones
//   <commit>/COMPLETE        written last (temp, fsync, rename): only then is the commit a hit
//   <commit>/leases/<pid>-<start>-<random>   a reader's lease
//
// At most SLOTS commits (complete or reserved). A new commit is admitted only under the lock, and only if a slot is
// free or can be reclaimed (a complete commit with no live lease, a reservation whose owner is gone); otherwise the
// answer is busy, before any download or staging. A lease is live while its process is alive with the same start
// time (proc-start.mjs; a reused pid doesn't count) and was touched within LEASE_MS.
//
// The two locks are SQLite's own (node:sqlite, BEGIN EXCLUSIVE in the default rollback journal, no WAL): the
// operating system gives a lock back when its holder ends, however it ends, so there is no stale lock to judge or
// take over. The lock files and their -journal sidecars are never removed, renamed or replaced, and never opened
// except through SQLite (a plain open and close of one would drop another connection's locks); a damaged or foreign
// one is refused, not recreated. These guarantees need a local filesystem: on NFS and other network filesystems
// SQLite's locks can't be relied on. Out of scope (stated in the
// design): other code already running as this account, which could rewrite these files.

import { randomBytes } from "node:crypto";
import { chmodSync, closeSync, constants as C, fsyncSync, lstatSync, mkdirSync, openSync, readdirSync, readSync, renameSync, rmSync, unlinkSync, utimesSync, writeSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { Worker } from "node:worker_threads";
import { privateDirs } from "./codex-fetch.mjs";
import { procInfo as realProcInfo } from "./proc-start.mjs";

export const SLOTS = 2;
export const LEASE_MS = 15 * 60 * 1000;
export const EXTRACT_MS = 120 * 1000;
const NOFOLLOW = C.O_NOFOLLOW ?? 0;
const COMMIT = /^[0-9a-f]{40}$/;

// node:sqlite, loaded once and only when this tool first needs it (the agent and its other tools still run on Node
// 20): Node 22.13 or later (23.4 or later). Up to Node 24 it prints one ExperimentalWarning line to the agent's
// stderr when it loads; that line is left as it is (hiding it would mean changing process-wide warning handling).
let sqliteModule = null;
async function sqlite() {
  if (sqliteModule) return sqliteModule;
  let m = null;
  try { m = await import("node:sqlite"); } catch {}
  if (typeof m?.DatabaseSync !== "function") throw new SourceCacheError("source_node", "reading Sagebrush's source needs Node 22.13 or later");
  sqliteModule = m;
  return sqliteModule;
}

export class SourceCacheError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}
export const busy = () => new SourceCacheError("source_busy", "busy: two other Sagebrush versions are in use on this computer; try again later");

export const defaultRoot = (home = homedir()) => join(home, ".cache", "sagebrush-agent", "source");
const ours = (s) => !process.getuid || s.uid === process.getuid();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** A real directory of this account, exactly `mode`, never a link. */
function realDir(p, mode = 0o700) {
  const s = lstatSync(p);
  if (!s.isDirectory() || (process.platform !== "win32" && (!ours(s) || (s.mode & 0o7777) !== mode))) throw new SourceCacheError("source_cache", "the source cache isn't a private directory of this account");
}

function writeJsonExcl(path, value) {
  const fd = openSync(path, C.O_WRONLY | C.O_CREAT | C.O_EXCL | NOFOLLOW, 0o600);
  try { const b = Buffer.from(JSON.stringify(value)); writeSync(fd, b, 0, b.length); fsyncSync(fd); } finally { closeSync(fd); }
}
function readJson(path, max = 64 * 1024 * 1024) {
  const s = lstatSync(path);
  if (!s.isFile() || s.size > max) throw new Error("not a file");
  const fd = openSync(path, C.O_RDONLY | NOFOLLOW);
  try { const b = Buffer.alloc(s.size); let at = 0; while (at < b.length) { const n = readSync(fd, b, at, b.length - at, at); if (!n) break; at += n; } return JSON.parse(b.toString("utf8")); } finally { closeSync(fd); }
}

export class SourceCache {
  constructor({ root = defaultRoot(), procInfo = realProcInfo, now = Date.now, slots = SLOTS, leaseMs = LEASE_MS, extractMs = EXTRACT_MS, lockWaitMs = 10 * 60 * 1000, workerUrl = new URL("./source-extract-worker.mjs", import.meta.url) } = {}) {
    Object.assign(this, { root, procInfo, now, slots, leaseMs, extractMs, lockWaitMs, workerUrl });
    this.me = { pid: process.pid, start: procInfo(process.pid).start ?? null };
    this.indexes = new Map(); // (commit -> its index, read once a process)
  }

  // ---- identity and liveness
  /** Whether a recorded owner {pid, start} is this live process or another live one of the same start time. */
  alive(owner) {
    if (!owner || !Number.isSafeInteger(owner.pid)) return false;
    const info = this.procInfo(owner.pid);
    if (info.gone) return false;
    if (info.start) return info.start === owner.start;
    return true; // (can't tell: never taken as gone; LEASE_MS still ends a lease)
  }

  checkRoot() {
    mkdirSync(dirname(dirname(this.root)), { recursive: true }); // (~/.cache itself, if missing)
    privateDirs(this.root);
  }

  // ---- the machine-wide locks: OS file locks, released by the OS when their process dies
  // Each lock (.lock: admission, leases, pruning; .fetch: one download and extraction at a time) is a SQLite file in
  // the private root, held by BEGIN EXCLUSIVE on a connection of its own and given back by ROLLBACK and close. SQLite
  // takes the OS's own lock on the file (fcntl byte-range locks; LockFileEx on Windows), which the OS releases when the
  // holder dies: there is no staleness to judge, no takeover, and no lock path is ever removed. (A network file system
  // must honour these locks, as for any SQLite user.)
  async withLock(fn, file = ".lock", waitMs = this.lockWaitMs) {
    const { DatabaseSync } = await sqlite();
    const path = join(this.root, `${file}.sqlite`);
    // (an existing lock file must be a private regular file of ours; a damaged one is refused, never recreated)
    let existed = true;
    try {
      const st = lstatSync(path);
      if (!st.isFile() || !ours(st) || (process.platform !== "win32" && (st.mode & 0o077))) throw new SourceCacheError("source_cache", "the source cache's lock file isn't a private file of this account");
    } catch (e) { if (e instanceof SourceCacheError) throw e; if (e.code !== "ENOENT") throw new SourceCacheError("source_cache", "the source cache's lock file can't be checked"); existed = false; }
    let db;
    try { db = new DatabaseSync(path); } catch { throw new SourceCacheError("source_cache", "the source cache's lock couldn't be opened"); }
    let acquired = false;
    try {
      if (!existed) { try { chmodSync(path, 0o600); } catch {} }
      db.exec("PRAGMA busy_timeout = 0"); // (never a blocking wait inside SQLite: the retries below are async)
      const deadline = performance.now() + waitMs; // (monotonic)
      for (;;) {
        try { db.exec("BEGIN EXCLUSIVE"); acquired = true; break; } catch (e) {
          if (!/database is locked|SQLITE_BUSY|busy/i.test(String(e?.message))) throw new SourceCacheError("source_cache", "the source cache's lock file is damaged");
          if (performance.now() > deadline) throw busy();
          await sleep(50);
        }
      }
      return await fn();
    } finally {
      if (acquired) { try { db.exec("ROLLBACK"); } catch {} }
      try { db.close(); } catch {}
    }
  }

  // ---- what's there
  commitDir(commit) { return join(this.root, commit); }
  isComplete(commit) {
    try {
      realDir(this.commitDir(commit));
      const c = readJson(join(this.commitDir(commit), "COMPLETE"), 4096);
      if (c?.v !== 1 || c.commit !== commit || c.ok !== true) return false;
      realDir(join(this.commitDir(commit), "tree"), 0o500);
      return true;
    } catch { return false; }
  }
  liveLeases(commit) {
    const d = join(this.commitDir(commit), "leases");
    let names = [];
    try { realDir(d); names = readdirSync(d); } catch { return 0; }
    let n = 0;
    for (const name of names) {
      const p = join(d, name);
      try {
        const s = lstatSync(p);
        const l = readJson(p, 4096);
        if (s.isFile() && this.alive(l) && this.now() - s.mtimeMs < this.leaseMs) { n++; continue; }
      } catch {}
      try { unlinkSync(p); } catch {}
    }
    return n;
  }
  reservedAlive(commit) {
    try { return this.alive(readJson(join(this.commitDir(commit), "RESERVED"), 4096)); } catch { return false; }
  }
  commits() {
    return readdirSync(this.root).filter((n) => COMMIT.test(n));
  }
  /** Remove a commit (under the lock): renamed away first, then deleted without following links. */
  remove(commit) {
    const trash = join(this.root, `.trash-${randomBytes(6).toString("hex")}`);
    try { renameSync(this.commitDir(commit), trash); } catch { return; }
    try { chmodTree(trash); } catch {}
    rmSync(trash, { recursive: true, force: true });
  }
  /** Leftovers of processes that are gone: staging and trash folders, reservations, stray entries (under the lock). */
  tidy() {
    for (const n of readdirSync(this.root)) {
      const p = join(this.root, n);
      if (n.startsWith(".trash-")) { try { chmodTree(p); } catch {} rmSync(p, { recursive: true, force: true }); continue; }
      if (n.startsWith(".staging-")) {
        let owner = null;
        try { owner = readJson(join(p, "OWNER"), 4096); } catch {}
        if (!this.alive(owner)) { try { chmodTree(p); } catch {} rmSync(p, { recursive: true, force: true }); }
        continue;
      }
      if (COMMIT.test(n) && !this.isComplete(n) && !this.reservedAlive(n)) this.remove(n);
    }
  }

  // ---- leases
  addLease(commit) {
    const d = join(this.commitDir(commit), "leases");
    try { mkdirSync(d, { mode: 0o700 }); } catch (e) { if (e.code !== "EEXIST") throw e; }
    realDir(d);
    const p = join(d, `${this.me.pid}-${String(this.me.start ?? "x").replace(/[^A-Za-z0-9]/g, "")}-${randomBytes(6).toString("hex")}`);
    writeJsonExcl(p, this.me);
    { const t = new Date(this.now()); utimesSync(p, t, t); } // (its age by this cache's clock, as touch() keeps it)
    let released = false;
    return {
      commit,
      tree: join(this.commitDir(commit), "tree"),
      touch: () => { if (!released) { try { const t = new Date(this.now()); utimesSync(p, t, t); } catch {} } },
      release: () => { if (!released) { released = true; try { unlinkSync(p); } catch {} } },
    };
  }

  /**
   * A lease on `commit`'s complete tree: at once if it's here; else, if a slot can be had, after fetching it with
   * `fetchArchive()` (resolving to the .tar.gz as a Buffer) and extracting it; else busy, before any download.
   */
  async acquire(commit, fetchArchive) {
    if (!COMMIT.test(commit)) throw new SourceCacheError("source_commit", "not a commit");
    this.checkRoot();
    const admitted = await this.withLock(async () => {
      this.tidy();
      if (this.isComplete(commit)) return { lease: this.addLease(commit) };
      if (this.reservedAlive(commit)) return { wait: true }; // (another process is fetching it)
      const held = this.commits().filter((c) => c !== commit);
      if (held.length >= this.slots) {
        const free = held.find((c) => this.isComplete(c) ? this.liveLeases(c) === 0 : !this.reservedAlive(c));
        if (!free) throw busy();
        this.remove(free);
      }
      mkdirSync(this.commitDir(commit), { mode: 0o700 });
      writeJsonExcl(join(this.commitDir(commit), "RESERVED"), this.me);
      return { reserved: true };
    }, ".lock", 30_000);
    if (admitted.lease) return admitted.lease;
    if (admitted.wait) {
      // (another process holds the reservation: wait for it under the fetch lock, then look again)
      await this.withLock(async () => {}, ".fetch");
      return this.withLock(async () => {
        if (this.isComplete(commit)) return this.addLease(commit);
        throw new SourceCacheError("source_fetch", "the Sagebrush source couldn't be fetched");
      }, ".lock", 30_000);
    }
    // (reserved by us: fetch and extract one at a time, machine-wide; on any failure the slot and staging go)
    const staging = join(this.root, `.staging-${randomBytes(6).toString("hex")}`);
    try {
      const index = await this.withLock(async () => {
        mkdirSync(staging, { mode: 0o700 });
        writeJsonExcl(join(staging, "OWNER"), this.me);
        const tree = join(staging, "tree");
        mkdirSync(tree, { mode: 0o700 });
        const archive = await fetchArchive();
        return this.extract(archive, tree, commit);
      }, ".fetch");
      return await this.withLock(async () => {
        const cd = this.commitDir(commit);
        realDir(cd);
        // (moved while still writable: renaming a folder to another parent needs write on it, for its ".."; sealed after)
        renameSync(join(staging, "tree"), join(cd, "tree"));
        sealTree(join(cd, "tree"));
        writeJsonExcl(join(cd, "index.json"), index);
        const tmp = join(cd, `.COMPLETE-${randomBytes(4).toString("hex")}`);
        writeJsonExcl(tmp, { v: 1, commit, files: index.files.length, skipped: index.skipped.length, bytes: index.files.reduce((a, f) => a + f[1], 0), ok: true });
        renameSync(tmp, join(cd, "COMPLETE"));
        try { unlinkSync(join(cd, "RESERVED")); } catch {}
        rmSync(staging, { recursive: true, force: true });
        return this.addLease(commit);
      }, ".lock", 30_000);
    } catch (e) {
      await this.withLock(async () => { this.remove(commit); try { chmodTree(staging); } catch {} rmSync(staging, { recursive: true, force: true }); }, ".lock", 30_000).catch(() => {});
      throw e instanceof SourceCacheError ? e : new SourceCacheError("source_fetch", e?.code === "source_archive" ? e.message : "the Sagebrush source couldn't be fetched");
    }
  }

  /** Extract in a worker, ended at extractMs. Resolves to the index, or throws with fixed words. */
  extract(archive, tree, commit) {
    return new Promise((resolve, reject) => {
      const bytes = new Uint8Array(archive.buffer, archive.byteOffset, archive.byteLength);
      const w = new Worker(this.workerUrl, { workerData: { archive: bytes, dir: tree, commit } });
      let settled = false;
      const done = (f) => { if (!settled) { settled = true; clearTimeout(t); w.terminate().catch(() => {}); f(); } };
      const t = setTimeout(() => done(() => reject(new SourceCacheError("source_archive", "the source archive took too long to unpack"))), this.extractMs);
      w.once("message", (m) => done(() => (m?.ok ? resolve(m.index) : reject(new SourceCacheError("source_archive", String(m?.why ?? "the source archive was refused").slice(0, 200))))));
      w.once("error", () => done(() => reject(new SourceCacheError("source_archive", "the source archive couldn't be read"))));
      w.once("exit", () => done(() => reject(new SourceCacheError("source_archive", "the source archive couldn't be read"))));
    });
  }

  /** The admitted index of a complete commit (read once per process). */
  index(commit) {
    if (!this.indexes.has(commit)) {
      const j = readJson(join(this.commitDir(commit), "index.json"));
      if (!j || !Array.isArray(j.files) || !Array.isArray(j.skipped)) throw new SourceCacheError("source_cache", "the source cache's index is damaged");
      this.indexes.set(commit, { files: j.files, skipped: j.skipped, byPath: new Map(j.files.map(([p, s]) => [p, s])), skippedBy: new Map(j.skipped.map(([p, s, r]) => [p, r])) });
    }
    return this.indexes.get(commit);
  }
}

// (the finished tree read-only: folders 0500, files are already 0400; deepest first, links never followed)
function sealTree(dir) {
  for (const n of readdirSync(dir)) {
    const p = join(dir, n);
    const s = lstatSync(p);
    if (s.isDirectory()) sealTree(p);
    else if (!s.isFile()) throw new SourceCacheError("source_archive", "the source archive held something other than files and folders");
  }
  chmodSync(dir, 0o500);
}
// (writable again, so it can be removed: folders only, links never followed)
function chmodTree(dir) {
  const s = lstatSync(dir);
  if (!s.isDirectory()) return;
  chmodSync(dir, 0o700);
  for (const n of readdirSync(dir)) {
    const p = join(dir, n);
    if (lstatSync(p).isDirectory()) chmodTree(p);
  }
}
