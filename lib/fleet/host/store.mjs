// Host supervisor (design: agent-autonomous-host-supervisor-freeze-r3.1.md §2.2, §3.3): durable root-only state with
// one writer per host.
//
// - **One writer.** `DurableState.open` takes an flock(2) on `<dir>/.lock` for the instance's lifetime, through
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
  write: (fd, data) => fs.writeSync(fd, data),
  fsync: (fd) => fs.fsyncSync(fd),
  close: (fd) => fs.closeSync(fd),
  rename: (a, b) => fs.renameSync(a, b),
});

/** Write `data` to `dir/name` atomically and durably (temp, fsync, rename, fsync of the directory). Throws on any failure. */
export function writeDurable(dir, name, data, io = realIo) {
  const tmp = join(dir, `.${name}.${process.pid}.tmp`);
  const fd = io.open(tmp, "w", 0o600);
  try { io.write(fd, data); io.fsync(fd); } finally { io.close(fd); }
  io.rename(tmp, join(dir, name));
  const dfd = io.open(dir, "r");
  try { io.fsync(dfd); } finally { io.close(dfd); }
}

/** Take the host's single-writer lock on `dir`. Resolves to { release() } or refuses with `in_progress`. */
export function lockDir(dir) {
  return new Promise((resolve, reject) => {
    const child = spawn("flock", ["-n", "-E", "75", join(dir, ".lock"), "sh", "-c", "echo locked; exec cat >/dev/null"], {
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
        resolve({ release: () => new Promise((r) => { if (child.exitCode !== null) return r(); child.once("exit", () => r()); child.stdin.end(); }) });
      });
    });
  });
}

const clone = (v) => structuredClone(v);

export class DurableState {
  #dir; #name; #check; #io; #cur = null; #text = null; #poisoned = false; #lock;

  /**
   * Open `dir/name` (creating it from `initial()` if absent) under the single-writer lock. `check(state)` validates the
   * full closed shape and throws a FleetError on anything else; it runs at load and on every candidate.
   */
  static async open(dir, name, { check, initial, io = realIo }) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    const lock = await lockDir(dir);
    try {
      const s = new DurableState(dir, name, check, io, lock);
      if (!fs.existsSync(join(dir, name))) s.#commitFirst(initial());
      else s.#load();
      return s;
    } catch (e) { await lock.release(); throw e; }
  }

  constructor(dir, name, check, io, lock) { this.#dir = dir; this.#name = name; this.#check = check; this.#io = io; this.#lock = lock; }

  #readDisk() {
    let text, parsed;
    try { text = fs.readFileSync(join(this.#dir, this.#name), "utf8"); parsed = JSON.parse(text); } catch { refuse("bad_form", `${this.#name}: corrupt`); }
    this.#check(parsed);
    return { text, parsed };
  }

  #load() { const { text, parsed } = this.#readDisk(); this.#cur = parsed; this.#text = text; this.#poisoned = false; }

  #commitFirst(state) {
    this.#check(state);
    const text = `${JSON.stringify(state)}\n`;
    writeDurable(this.#dir, this.#name, text, this.#io);
    this.#cur = state; this.#text = text;
  }

  get poisoned() { return this.#poisoned; }

  /** A copy of the committed state. Refuses while poisoned. */
  get() { if (this.#poisoned) refuse("outcome_unknown", `${this.#name}: uncertain; reload`); return clone(this.#cur); }

  /**
   * Commit `mutate(candidate)` (it edits the copy in place and may throw to refuse, leaving everything unchanged).
   * Returns the new committed state.
   */
  commit(mutate) {
    if (this.#poisoned) refuse("outcome_unknown", `${this.#name}: uncertain; reload`);
    const candidate = clone(this.#cur);
    mutate(candidate);                                  // a refusal here changes nothing
    this.#check(candidate);
    const text = `${JSON.stringify(candidate)}\n`;
    try {
      let disk;
      try { disk = fs.readFileSync(join(this.#dir, this.#name), "utf8"); } catch { disk = null; }
      if (disk !== this.#text) refuse("outcome_unknown", `${this.#name}: changed on disk`);
      writeDurable(this.#dir, this.#name, text, this.#io);
    } catch (e) { this.#poisoned = true; throw e; }
    this.#cur = candidate; this.#text = text;
    return clone(candidate);
  }

  /** Re-read the file; clears the poison only if it is valid. */
  reload() { this.#load(); return this.get(); }

  /** Release the lock (the process exiting releases it too). */
  close() { return this.#lock.release(); }
}

/** Exact-keys check for closed records. */
export const exactKeys = (o, keys) => o !== null && typeof o === "object" && !Array.isArray(o)
  && Object.keys(o).length === keys.length && keys.every((k) => Object.hasOwn(o, k));
