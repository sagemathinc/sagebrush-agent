// Host supervisor (design: agent-autonomous-host-supervisor-freeze-r3.1.md §2.2, §3.3): durable root-only state with
// one writer per host.
//
// - **One writer.** The host store owner (host-store.mjs) takes ONE flock(2) on `<root>/.lock` for its lifetime, through
//   util-linux flock(1) holding the lock in a child that exits when our end of its stdin closes (so the lock dies with
//   this process, even on SIGKILL). A second open while the lock is held refuses with `in_progress`.
// - **Commit, then publish.** A change is built on a copy of the current state, checked against the full closed shape,
//   written to a temp file, fsynced, renamed into place, and the directory fsynced. Only then does the instance publish
//   it. Before each commit the file is re-read and must equal what the instance last committed.
// - **Poison on doubt.** If any write step fails, or the re-read differs, the instance is poisoned: every read and
//   write refuses with `outcome_unknown` until `reload()` re-reads a valid file from disk. So memory never answers
//   with authority the disk doesn't hold.

import { spawn } from "node:child_process";
import * as fs from "node:fs";
import { join } from "node:path";
import { refuse } from "../bytes.mjs";

/** The real filesystem steps of a durable write; tests replace single steps to inject failures. */
export const realIo = Object.freeze({
  open: (p, flags, mode) => fs.openSync(p, flags, mode),
  write: (fd, buf, off, len) => fs.writeSync(fd, buf, off, len),
  fsync: (fd) => fs.fsyncSync(fd),
  close: (fd) => fs.closeSync(fd),
  rename: (a, b) => fs.renameSync(a, b),
});

/** Write `data` to `dir/name` atomically and durably (temp, fsync, rename, fsync of the directory). Throws on any failure. */
export function writeDurable(dir, name, data, io = realIo) {
  const tmp = join(dir, `.${name}.${process.pid}.tmp`);
  const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
  const fd = io.open(tmp, "w", 0o600);
  try {
    // A write may be short; loop until every byte is written, and treat a zero or impossible count as an error.
    for (let off = 0; off < buf.length;) {
      const n = io.write(fd, buf, off, buf.length - off);
      if (!Number.isSafeInteger(n) || n <= 0 || n > buf.length - off) throw Object.assign(new Error("short write"), { code: "EIO" });
      off += n;
    }
    io.fsync(fd);
  } finally { io.close(fd); }
  // Read the temp file back before it replaces anything: a write that lied about its count never reaches the name.
  if (!fs.readFileSync(tmp).equals(buf)) { try { fs.unlinkSync(tmp); } catch {} throw Object.assign(new Error("temp read-back differs"), { code: "EIO" }); }
  io.rename(tmp, join(dir, name));
  const dfd = io.open(dir, "r");
  try { io.fsync(dfd); } finally { io.close(dfd); }
}

/**
 * Create `dir/name` holding exactly `data`, never replacing an existing file (exclusive create, whole write, fsync of
 * file and directory, read-back). If the file already exists with exactly these bytes, that is the same write done
 * before: fine. Any other existing content refuses. Throws on any failure.
 */
export function writeExclusive(dir, name, data, io = realIo) {
  const path = join(dir, name);
  const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
  let fd;
  try { fd = io.open(path, "wx", 0o600); } catch (e) {
    if (e?.code !== "EEXIST") throw e;
    if (!fs.readFileSync(path).equals(buf)) throw Object.assign(new Error("a different file already has this name"), { code: "EEXIST" });
    // The same bytes, possibly left by an earlier attempt that crashed before they were durable: make them durable now
    // (fsync the file and the directory, read back) before anyone relies on them.
    const efd = io.open(path, "r");
    try { io.fsync(efd); } finally { io.close(efd); }
    const dfd = io.open(dir, "r");
    try { io.fsync(dfd); } finally { io.close(dfd); }
    if (!fs.readFileSync(path).equals(buf)) throw Object.assign(new Error("read-back differs"), { code: "EIO" });
    return;
  }
  try {
    try {
      for (let off = 0; off < buf.length;) {
        const n = io.write(fd, buf, off, buf.length - off);
        if (!Number.isSafeInteger(n) || n <= 0 || n > buf.length - off) throw Object.assign(new Error("short write"), { code: "EIO" });
        off += n;
      }
      io.fsync(fd);
    } finally { io.close(fd); }
    const dfd = io.open(dir, "r");
    try { io.fsync(dfd); } finally { io.close(dfd); }
    if (!fs.readFileSync(path).equals(buf)) throw Object.assign(new Error("read-back differs"), { code: "EIO" });
  } catch (e) {
    // A file this call created but couldn't complete is removed, so a retry can create it whole.
    try { fs.unlinkSync(path); } catch {}
    throw e;
  }
}

/** Linux: is `pid` a live process (present in /proc and not a zombie)? */
function alive(pid) {
  try {
    const stat = fs.readFileSync(`/proc/${pid}/stat`, "utf8");
    const state = stat.slice(stat.lastIndexOf(")") + 2, stat.lastIndexOf(")") + 3);
    return state !== "Z" && state !== "X";
  } catch { return false; }
}

/** Take the host's single-writer lock on `dir` (the host store owner calls this once). Resolves to { release() } or refuses with `in_progress`. */
export function lockDir(dir, { waitMs = 0 } = {}) {
  return new Promise((resolve, reject) => {
    // -n: refuse at once; -w: wait at most waitMs (flock's conflict exit code covers the timeout too).
    const wait = waitMs > 0 ? ["-w", (waitMs / 1000).toFixed(3)] : ["-n"];
    const child = spawn("flock", [...wait, "-E", "75", join(dir, ".lock"), "sh", "-c", "echo locked; exec cat >/dev/null"], {
      stdio: ["pipe", "pipe", "ignore"],
    });
    let settled = false, out = "";
    const done = (fn) => { if (!settled) { settled = true; fn(); } };
    child.on("error", () => done(() => { try { refuse("preflight_missing", "flock is unavailable"); } catch (e) { reject(e); } }));
    child.on("exit", (code) => done(() => {
      try { refuse(code === 75 ? "in_progress" : "preflight_missing", code === 75 ? "another writer holds this state" : "the state lock failed"); } catch (e) { reject(e); }
    }));
    child.stdout.on("data", (b) => {
      out += b;
      if (out.startsWith("locked\n")) done(() => {
        child.unref(); child.stdout.unref?.(); child.stdin.unref?.();
        const lock = {
          closed: false,
          lost: false,
          // While releasing, the child is referenced again, so an otherwise idle process (a standalone stop-all) stays
          // alive until the lock is really gone and release resolves.
          release: () => new Promise((r) => {
            lock.closed = true;
            if (child.exitCode !== null || child.signalCode !== null) return r();
            child.ref();
            child.once("exit", () => r());
            child.stdin.end();
          }),
          // Asked of the OS, not only of Node's exit event (which can lag): the lock's holder must still be a live,
          // non-zombie process.
          held: () => !lock.closed && !lock.lost && child.exitCode === null && child.signalCode === null && alive(child.pid),
        };
        // If flock dies, an inherited copy of the lock may live on in its helper: close our end so that exits too.
        child.once("exit", () => { lock.lost = true; child.stdin.destroy(); });
        resolve(lock);
      });
    });
  });
}

const clone = (v) => structuredClone(v);

export class DurableState {
  #dir; #name; #check; #io; #cur = null; #text = null; #poisoned = false; #lock;

  /**
   * A durable state file `dir/name` under a lock the HOST STORE OWNER already holds (it never locks by itself).
   * Created from `initial()` if absent. `check(state)` validates the full closed shape and throws a FleetError on
   * anything else; it runs at load and on every candidate.
   */
  static attach(dir, name, { check, initial, io = realIo, lock }) {
    if (!lock || typeof lock.held !== "function" || !lock.held()) refuse("in_progress", `${name}: no writer lock`);
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    const s = new DurableState(dir, name, check, io, lock);
    if (!fs.existsSync(join(dir, name))) s.#commitFirst(initial());
    else s.#load();
    return s;
  }

  constructor(dir, name, check, io, lock) { this.#dir = dir; this.#name = name; this.#check = check; this.#io = io; this.#lock = lock; }

  // Losing the lock (its holder process died, or the owner closed) ends this view for good: a reload can't restore
  // exclusion, so every later call refuses and the caller must open a new host store.
  #guard() {
    this.#lockCheck();
    if (this.#poisoned) refuse("outcome_unknown", `${this.#name}: uncertain; reload`);
  }

  // A closed store refuses as closed (in_progress); a lost lock is uncertain authority (outcome_unknown). Neither is
  // ever undone by reload: the caller opens a new host store.
  #lockCheck() {
    if (this.#lock.closed) refuse("in_progress", `${this.#name}: the host store is closed`);
    if (!this.#lock.held()) { this.#poisoned = true; refuse("outcome_unknown", `${this.#name}: the writer lock was lost; reopen`); }
  }

  #readDisk() {
    let text, parsed;
    try { text = fs.readFileSync(join(this.#dir, this.#name), "utf8"); parsed = JSON.parse(text); } catch { refuse("bad_form", `${this.#name}: corrupt`); }
    this.#check(parsed);
    return { text, parsed };
  }

  #load() {
    this.#poisoned = true; // uncertain until a valid file has been read; cleared only on success
    const { text, parsed } = this.#readDisk();
    this.#cur = parsed; this.#text = text; this.#poisoned = false;
  }

  #commitFirst(state) {
    this.#check(state);
    const text = `${JSON.stringify(state)}\n`;
    writeDurable(this.#dir, this.#name, text, this.#io);
    if (fs.readFileSync(join(this.#dir, this.#name), "utf8") !== text) refuse("outcome_unknown", `${this.#name}: read-back differs`);
    this.#cur = state; this.#text = text;
  }

  get poisoned() { return this.#poisoned || !this.#lock.held(); }

  /** Refuses unless this view may write now (lock held, not poisoned): for writes next to the state file. */
  assertWritable() { this.#guard(); }

  /** A copy of the committed state. Refuses while poisoned or without the lock. */
  get() { this.#guard(); return clone(this.#cur); }

  /**
   * Commit `mutate(candidate)` (it edits the copy in place and may throw to refuse, leaving everything unchanged).
   * Returns the new committed state.
   */
  commit(mutate) {
    this.#guard();
    const candidate = clone(this.#cur);
    mutate(candidate);                                  // a refusal here changes nothing
    this.#check(candidate);
    const text = `${JSON.stringify(candidate)}\n`;
    try {
      let disk;
      try { disk = fs.readFileSync(join(this.#dir, this.#name), "utf8"); } catch { disk = null; }
      if (disk !== this.#text) refuse("outcome_unknown", `${this.#name}: changed on disk`);
      this.#lockCheck();
      writeDurable(this.#dir, this.#name, text, this.#io);
      // Read back what is now on disk; publish only if it is exactly what we meant to write, still under the lock.
      if (fs.readFileSync(join(this.#dir, this.#name), "utf8") !== text) refuse("outcome_unknown", `${this.#name}: read-back differs`);
      this.#lockCheck();
    } catch (e) { this.#poisoned = true; throw e; }
    this.#cur = candidate; this.#text = text;
    return clone(candidate);
  }

  /** Re-read the file; clears the poison only if it is valid. Never restores a lost lock. */
  reload() {
    this.#lockCheck();
    this.#load();
    return this.get();
  }
}

/** Exact-keys check for closed records. */
export const exactKeys = (o, keys) => o !== null && typeof o === "object" && !Array.isArray(o)
  && Object.keys(o).length === keys.length && keys.every((k) => Object.hasOwn(o, k));
