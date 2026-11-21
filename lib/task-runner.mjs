// The Delegate runner (pair-delegate plan r3.4 §2.6): one notebook of a task's copy run by the pinned engine under the
// pinned Deno, as a child of this agent, with no shell, no PATH and none of this agent's environment.
//
// Three layers, so no single one is the boundary: this host makes no links and walks work/ by lstat before and after
// every run (a link or special file there and the run doesn't start, or its result isn't kept); Deno's permissions
// (read and write only work/ and the run's own tmp, read the engine file, no network, subprocess, FFI or system
// calls); and the engine's own --confine, always given both roots.  There is no unconfined path and no fallback: where
// any of it can't be had, notebook_run refuses, saying why, and editing and proposing go on.
//
// RUNS_ENABLED is false in this version: runs are refused until the security review clears them on the full evidence.

import { createHash, randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
import { closeSync, constants as C, fstatSync, lstatSync, mkdirSync, openSync, readSync, realpathSync, rmSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import { platformKey } from "./codex-fetch.mjs";
import { ensureRunner, pinProblem, RUNNER_PIN } from "./runner-fetch.mjs";
import { procStart } from "./proc-start.mjs";
import { pathProblem, scanTree } from "./task-paths.mjs";
import { writeAll } from "./task-git.mjs";
import { TaskError } from "./tasks-schema.mjs";

/** Runs are off in this version: a separate, reviewed change turns them on. */
export const RUNS_ENABLED = false;
export const RUN_LIMITS = Object.freeze({
  timeoutS: 300, // a run's cells, all together, unless the call asks for less
  maxTimeoutS: 3600,
  marginMs: 30 * 1000, // on top of the cells' time: the wall bound, after which the run's process group is killed
  stdout: 4 * 1024 * 1024, // the engine's report; past it the run is killed and refused
  stderr: 64 * 1024, // kept for the reason; the rest dropped
});
export const TZ_SOURCE = new URL("./tzdata/zoneinfo/", import.meta.url).pathname;
const NOFOLLOW = C.O_NOFOLLOW ?? 0;
const unavailable = (why) => new TaskError("unavailable", `Running code isn't available for Delegate on this computer: ${why}`);

/** The fixed Deno argv for one run: every path absolute, each list one argv element, no shell (plan §2.6). */
export function runArgv({ engine, work, runTmp, notebook, timeoutS }) {
  return [
    "run", "--no-prompt", "--no-config", "--no-lock", "--no-remote", "--no-npm", "--cached-only", "--no-code-cache",
    `--allow-read=${work},${runTmp},${engine}`, `--allow-write=${work},${runTmp}`, "--allow-env",
    "--deny-net", "--deny-run", "--deny-ffi", "--deny-sys",
    engine, "notebook", "run", notebook, "--json", "--write", "--timeout", String(timeoutS), "--confine", work, "--confine", runTmp,
    // (the lifeline: this agent holds the run's standard input open; when the agent ends, however it ends, so does the run)
    "--until-stdin-ends",
  ];
}

/** The run's whole environment: nothing of this agent's (--allow-env exposes exactly these, and Deno's own PATH and
 * DENO_NODE_SHIM_ACTIVE). */
export function runEnv({ work, runTmp }) {
  const zones = join(runTmp, "zoneinfo");
  return { HOME: work, TMPDIR: runTmp, DENO_DIR: join(runTmp, "deno"), NO_COLOR: "1", TZ: "UTC", TZDIR: zones, PYTHONTZPATH: zones };
}

/** Copy the pinned zone data into `dest`, bytewise: each file read without following a link, a regular file with one
 * link, of its pinned size and sha256, written new (never over anything).  Throws on any difference. */
export function copyZones(dest, files, source = TZ_SOURCE) {
  mkdirSync(dest, { mode: 0o700 });
  for (const [rel, f] of Object.entries(files)) {
    if (pathProblem(rel)) throw new Error(`zone data: ${rel} isn't a plain path`);
    const parts = rel.split("/");
    for (let i = 1; i < parts.length; i++) { try { mkdirSync(join(dest, ...parts.slice(0, i)), { mode: 0o700 }); } catch (e) { if (e.code !== "EEXIST") throw e; } }
    const fd = openSync(join(source, rel), C.O_RDONLY | NOFOLLOW);
    let bytes;
    try {
      const st = fstatSync(fd);
      if (!st.isFile() || st.nlink !== 1 || st.size !== f.size) throw new Error(`zone data: ${rel} isn't as pinned`);
      bytes = Buffer.alloc(f.size);
      let n = 0;
      while (n < f.size) { const k = readSync(fd, bytes, n, f.size - n, n); if (!k) break; n += k; }
      if (n !== f.size || createHash("sha256").update(bytes).digest("hex") !== f.sha256) throw new Error(`zone data: ${rel} isn't as pinned`);
    } finally { closeSync(fd); }
    const out = openSync(join(dest, rel), C.O_WRONLY | C.O_CREAT | C.O_EXCL | NOFOLLOW, 0o600);
    try { writeAll(out, bytes); } finally { closeSync(out); }
  }
}
const zoneBytes = (files) => Object.values(files).reduce((n, f) => n + f.size, 0);

export class TaskRunner {
  /**
   * `store`: the TaskStore.  `enabled`: whether runs may happen at all (RUNS_ENABLED; tests say so explicitly).
   * `ensure`: gives the verified {deno, engine} paths (runner-fetch's ensureRunner; tests pass their own).
   */
  constructor({ store, enabled = RUNS_ENABLED, ensure = ensureRunner, pin = RUNNER_PIN, platform = platformKey(), zoneSource = TZ_SOURCE, limits = RUN_LIMITS, spawnFn = spawn }) {
    Object.assign(this, { store, enabled, ensure, pin, platform, zoneSource, spawnFn });
    this.limits = { ...RUN_LIMITS, ...limits };
  }

  /** Why runs are off on this computer or for this task, or null. */
  problem(task) {
    if (!this.enabled) return "runs are turned off in this version";
    if (process.platform === "win32") return "runs aren't available on Windows in this version";
    const why = pinProblem(this.pin, this.platform);
    if (why) return why;
    if (task && this.store.state(task).grant.run !== true) return "this task wasn't started with running code allowed";
    return null;
  }

  /**
   * Run one notebook of the task's copy (`rel`, a path in work/).  Resolves to the engine's JSON report, or rejects
   * with a TaskError saying why.  `signal`: the turn's abort; on it (a Stop, a breach, the time limit) the run's
   * process group is killed, the exit waited for, and work/ put back as it was before the run.  `admit`: why the run
   * can't have the disk it needs now (the turn's free-space admission), or null; asked after the fetch and the
   * snapshot (which may write the cache and git objects), before the run's tmp folder, zone data or process.
   */
  async run(task, rel, { timeoutS = this.limits.timeoutS, signal, admit } = {}) {
    const why = this.problem(task);
    if (why) throw unavailable(why);
    if (typeof rel !== "string" || pathProblem(rel) || !/\.ipynb$/i.test(rel)) throw new TaskError("bad_request", "a notebook's path in your copy, ending in .ipynb");
    if (!Number.isInteger(timeoutS) || timeoutS < 1 || timeoutS > this.limits.maxTimeoutS) throw new TaskError("bad_request", `a timeout of 1 to ${this.limits.maxTimeoutS} seconds`);
    let paths;
    try { paths = await this.ensure({ pin: this.pin, platform: this.platform, signal }); } catch (e) { throw unavailable(e?.message ?? String(e)); }
    const store = this.store, work = store.work(task);
    // (the notebook: a plain file in work/, reached through plain folders)
    let st;
    try { st = lstatSync(join(work, rel)); } catch { throw new TaskError("not_found", `${rel} isn't in your copy`); }
    if (!st.isFile() || st.nlink !== 1) throw new TaskError("bad_request", `${rel} isn't a plain file`);
    // (before: work/ by lstat, nothing but plain folders and files; and what a cut-off run goes back to)
    const before = await store.snapshotWork(task);
    // (the disk, asked again here, after the fetch and the snapshot: short, refused before the run's folder, the zone
    //  data or the run itself)
    const short = admit?.();
    if (short) throw new TaskError("busy", short);
    const runTmp = join(store.runTmpRoot(task), `run-${randomBytes(6).toString("hex")}`);
    mkdirSync(runTmp, { mode: 0o700 });
    // (the run record, before anything the run does: if this agent dies, its next start ends the run and undoes it)
    const record = { v: 1, tmp: basename(runTmp), snapshot: before, pid: null, start: null };
    let release = () => {}, settled = true;
    try {
      store.writeRunRecord(task, record);
      const engine = realpathSync(paths.engine), deno = realpathSync(paths.deno), realWork = realpathSync(work), realTmp = realpathSync(runTmp);
      // (Deno's permission lists are comma-separated: a path with a comma can't be granted exactly)
      for (const p of [engine, realWork, realTmp]) if (p.includes(",")) throw unavailable(`a folder it would need has a comma in its path (${p})`);
      // (the zone data, copied in for this run only, checked against its pin: its bytes reserved first, as any write is,
      //  against the task's budget and the total, and held until the run's tmp is removed)
      release = store.reserveRun(task, zoneBytes(this.pin.tzdata.files));
      try { copyZones(join(realTmp, "zoneinfo"), this.pin.tzdata.files, this.zoneSource); } catch (e) { throw unavailable(e?.message ?? String(e)); }
      const notebook = join(realWork, rel);
      settled = false;
      // (the run's identity recorded before anything else: if that can't be written, the run doesn't go on)
      const onStart = (pid) => { try { store.writeRunRecord(task, { ...record, pid, start: procStart(pid) }); return true; } catch { return false; } };
      const out = await this.#spawn(onStart, deno, runArgv({ engine, work: realWork, runTmp: realTmp, notebook, timeoutS }), runEnv({ work: realWork, runTmp: realTmp }), dirname(notebook), timeoutS, signal);
      // (after: the run's process group is gone; work/ walked again, and a link or special file there undoes the run)
      const { problems } = scanTree(work, store.budget.files * 10);
      if (!out.killed && !problems.length) settled = true;
      if (out.killed || problems.length) {
        await store.restoreWork(task, before);
        settled = true;
        if (problems.length) throw new TaskError("bad_request", `the run left what your copy can't hold (${problems.slice(0, 2).join("; ")}): its changes were undone`);
        if (out.killed === "couldn't record the run") throw new TaskError("unavailable", "the run failed: couldn't record the run; its changes were undone");
        throw new TaskError(out.killed === "output" ? "too_large" : "unavailable", out.killed === "output" ? "the run's report was too large: its changes were undone" : `the run was stopped (${out.killed}): its changes were undone`);
      }
      let report;
      try { report = JSON.parse(out.stdout); } catch { throw new TaskError("unavailable", `the run gave no report (exit ${out.code}${out.stderr ? `: ${out.stderr.slice(-300)}` : ""})`); }
      return { exit: out.code, report };
    } finally {
      rmSync(runTmp, { recursive: true, force: true });
      release();
      // (kept while the copy may still hold a cut-off run's changes: the next start undoes them)
      if (settled) store.clearRunRecord(task);
    }
  }

  // (the run as a process group of its own: killed whole on the turn's abort, the wall bound, or too much output; the
  //  exit always waited for before anything is read)
  #spawn(onStart, deno, argv, env, cwd, timeoutS, signal) {
    return new Promise((resolve, reject) => {
      let child;
      // (its standard input a pipe this agent holds open and never writes: the run's lifeline)
      try { child = this.spawnFn(deno, argv, { cwd, env, detached: true, stdio: ["pipe", "pipe", "pipe"] }); } catch (e) { return reject(unavailable(`Deno couldn't be started (${e?.code ?? e?.message ?? e})`)); }
      child.stdin.on("error", () => {});
      let recorded = false;
      if (child.pid) recorded = onStart(child.pid);
      let stdout = [], outBytes = 0, stderr = "", killed = null;
      const kill = (why) => {
        killed ??= why;
        try { process.kill(-child.pid, "SIGKILL"); } catch {}
      };
      const wall = setTimeout(() => kill("its time was up"), timeoutS * 1000 + this.limits.marginMs);
      if (child.pid && !recorded) kill("couldn't record the run");
      const onAbort = () => kill("the task's turn was stopped");
      if (signal?.aborted) onAbort();
      signal?.addEventListener("abort", onAbort, { once: true });
      child.stdout.on("data", (d) => { outBytes += d.length; if (outBytes > this.limits.stdout) kill("output"); else stdout.push(d); });
      child.stderr.on("data", (d) => { if (stderr.length < this.limits.stderr) stderr += d.toString("utf8").slice(0, this.limits.stderr - stderr.length); });
      child.on("error", (e) => { clearTimeout(wall); signal?.removeEventListener("abort", onAbort); reject(unavailable(`Deno couldn't be started (${e?.code ?? e?.message ?? e})`)); });
      child.on("close", (code, sig) => {
        clearTimeout(wall);
        signal?.removeEventListener("abort", onAbort);
        // (anything the run left in its group goes with it)
        try { process.kill(-child.pid, "SIGKILL"); } catch {}
        child.stdin.destroy();
        resolve({ code: code ?? sig, stdout: Buffer.concat(stdout).toString("utf8"), stderr, killed });
      });
    });
  }
}
