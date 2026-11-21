// The Delegate runner (lib/task-runner.mjs) with a stand-in for Deno: a small program that records how it was started
// (argv, environment, folder, its run tmp) and then does what the row asks (a report, a hang with a grandchild, a link
// planted in the copy, too much output).  The real Deno and engine are task-runner-real.test.mjs's.
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import fs from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import { fakeCreateServer } from "../lib/fake.mjs";
import { RUNNER_PIN } from "../lib/runner-fetch.mjs";
import { cfUserTextEncoding, copyZones, RUNS_ENABLED, runArgv, runEnv, TaskRunner, TZ_SOURCE } from "../lib/task-runner.mjs";
import { TaskRpc } from "../lib/task-rpc.mjs";
import { TaskTurns, TASK_SERVER } from "../lib/task-turns.mjs";
import { TaskStore } from "../lib/tasks.mjs";
import { checkRequest } from "../lib/tasks-schema.mjs";

const NB = JSON.stringify({ cells: [{ cell_type: "code", id: "a", metadata: {}, source: "x = 1", outputs: [], execution_count: null }], metadata: { kernelspec: { name: "python3", language: "python" } }, nbformat: 4, nbformat_minor: 5 });
const until = async (f, what, ms = 10000) => { const t = Date.now(); while (!f()) { if (Date.now() - t > ms) throw new Error(`timed out: ${what}`); await new Promise((r) => setTimeout(r, 5)); } };
const alive = (pid) => { try { process.kill(pid, 0); return true; } catch { return false; } };
// (a pin with an engine named, so only the switch and the grant decide; the engine is never fetched here)
const PIN = { ...RUNNER_PIN, engine: { version: "0.0.0-test", entry: "dist/sagebrush.cjs", files: {} } };

// The stand-in "deno": records, then acts as control.json says.
const FAKE = String.raw`
const fs = require("fs"), path = require("path"), cp = require("child_process");
const dir = __dirname, ctl = JSON.parse(fs.readFileSync(path.join(dir, "control.json"), "utf8"));
const [deno, ...argv] = process.argv.slice(2);
const runTmp = process.env.TMPDIR, zones = path.join(runTmp, "zoneinfo");
const count = (d) => fs.readdirSync(d, { withFileTypes: true }).reduce((n, e) => n + (e.isDirectory() ? count(path.join(d, e.name)) : 1), 0);
const nb = argv[argv.indexOf("run", 16) + 1];
fs.writeFileSync(path.join(dir, "seen.json"), JSON.stringify({ deno, argv, env: process.env, cwd: process.cwd(), tmpMode: fs.statSync(runTmp).mode & 0o777, zones: count(zones), paris: require("crypto").createHash("sha256").update(fs.readFileSync(path.join(zones, "Europe/Paris"))).digest("hex") }));
const work = process.env.HOME;
const report = { file: nb, mode: "python", ok: true, seed: "new", cells: [{ n: 1, id: "a", status: "ok", ms: 1, stdout: "hello\n", stderr: "", outputs: [] }], wrote: nb };
if (ctl.mode === "report") { fs.writeFileSync(path.join(work, "out.txt"), "made by the run"); process.stdout.write(JSON.stringify(report)); }
else if (ctl.mode === "hang") {
  fs.writeFileSync(path.join(work, "partial.txt"), "half done");
  const g = cp.spawn(process.execPath, [ctl.runtime === "deno" ? "eval" : "-e", "setInterval(() => {}, 1000)"], { stdio: "ignore" });
  fs.writeFileSync(path.join(dir, "grandchild"), String(g.pid));
  setInterval(() => {}, 1000);
}
else if (ctl.mode === "plant") { fs.symlinkSync("/etc/passwd", path.join(work, "evil")); process.stdout.write(JSON.stringify(report)); }
else if (ctl.mode === "big") { const s = "x".repeat(65536); for (let i = 0; i < 200; i++) process.stdout.write(s); setInterval(() => {}, 1000); }
else if (ctl.mode === "manyfiles") { for (let i = 0; i < ctl.files; i++) fs.writeFileSync(path.join(runTmp, "f" + i), ""); fs.writeFileSync(path.join(work, "partial.txt"), "half done"); setInterval(() => {}, 1000); }
else if (ctl.mode === "noreport") { process.stderr.write("sagebrush notebook run: refused\n"); process.exit(2); }
`;

// (what runs the stand-in: this node, unless it drops TMPDIR and TZDIR from a child's environment as glibc does for a
//  program with file capabilities (some hosts' node); then the real Deno, if there is one; else these rows are skipped)
const RUNTIME = (() => {
  const keeps = (cmd, args) => spawnSync(cmd, [...args, "process.stdout.write(String(process.env.TMPDIR) + String(process.env.TZDIR))"], { env: { TMPDIR: "/x", TZDIR: "/y" }, encoding: "utf8" }).stdout === "/x/y";
  if (keeps(process.execPath, ["-e"])) return { kind: "node", cmd: process.execPath, args: [] };
  const deno = spawnSync("sh", ["-c", "command -v deno"], { encoding: "utf8" }).stdout.trim();
  if (deno && keeps(deno, ["eval"])) return { kind: "deno", cmd: deno, args: ["run", "-A", "--quiet"] };
  return null;
})();
const T = RUNTIME ? {} : { skip: "needs a node that keeps TMPDIR and TZDIR in a child's environment, or deno on PATH" };

function setup({ mode = "report", enabled = true, run = true, root = null, limits = {}, zoneSource } = {}) {
  const dir = mkdtempSync(join(tmpdir(), "sb-runner-"));
  const fake = join(dir, "fake");
  mkdirSync(fake);
  writeFileSync(join(fake, "deno.cjs"), FAKE);
  writeFileSync(join(fake, "control.json"), JSON.stringify({ mode, runtime: RUNTIME?.kind, files: 2000 }));
  const engine = join(dir, "engine", "dist", "sagebrush.cjs");
  mkdirSync(join(dir, "engine", "dist"), { recursive: true });
  writeFileSync(engine, "// the engine stand-in: never run here\n");
  const store = new TaskStore({ root: root ?? join(dir, "tasks"), scope: "install-1", transcripts: join(dir, "projects") }).init();
  const spawned = [];
  const spawnFn = (cmd, argv, opts) => { spawned.push({ cmd, argv, opts }); return spawn(RUNTIME.cmd, [...RUNTIME.args, join(fake, "deno.cjs"), cmd, ...argv], opts); };
  const runner = new TaskRunner({ store, enabled, pin: PIN, platform: "linux-x64", ensure: async () => ({ deno: process.execPath, engine }), spawnFn, limits, ...(zoneSource ? { zoneSource } : {}) });
  const task = store.start(checkRequest("tasks.start", { title: "t", prompt: "p", target: "local", run, docs: [{ path: "nb dir/a.ipynb", kind: "notebook", content: NB }] })).task;
  const seen = () => JSON.parse(readFileSync(join(fake, "seen.json"), "utf8"));
  return { dir, fake, engine, store, runner, task, spawned, seen, done: () => rmSync(dir, { recursive: true, force: true }) };
}

test("off in this version: RUNS_ENABLED is false, and the default runner refuses, saying why; so does a task started without runs", async () => {
  assert.equal(RUNS_ENABLED, false);
  const h = setup({ enabled: undefined });
  const def = new TaskRunner({ store: h.store, pin: PIN, platform: "linux-x64" });
  assert.equal(def.problem(h.task), "runs are turned off in this version");
  await assert.rejects(def.run(h.task, "nb dir/a.ipynb"), (e) => e.code === "unavailable" && /Running code isn't available for Delegate on this computer: runs are turned off/.test(e.message));
  const noRun = setup({ run: false });
  assert.equal(noRun.runner.problem(noRun.task), "this task wasn't started with running code allowed");
  // (no engine pinned yet; a platform with no Deno pinned)
  assert.equal(new TaskRunner({ store: h.store, enabled: true, platform: "linux-x64" }).problem(h.task), "no engine with confinement is pinned yet");
  assert.match(new TaskRunner({ store: h.store, enabled: true, pin: PIN, platform: null }).problem(h.task), /runs aren't available on/);
  assert.equal(h.spawned.length + noRun.spawned.length, 0);
  h.done(); noRun.done();
});

test("the fixed launch: exactly the plan's argv, the environment replaced whole, the notebook's folder, a private run tmp with the pinned zone data, removed after", T, async () => {
  const h = setup();
  const { exit, report } = await h.runner.run(h.task, "nb dir/a.ipynb");
  assert.equal(exit, 0);
  assert.equal(report.cells[0].stdout, "hello\n");
  const s = h.seen(), work = h.store.work(h.task), runTmp = s.env.TMPDIR;
  assert.match(runTmp, new RegExp(`^${h.store.dir(h.task)}/tmp/run-[0-9a-f]{12}$`));
  assert.deepEqual(s.argv, runArgv({ engine: h.engine, work, runTmp, notebook: join(work, "nb dir/a.ipynb"), timeoutS: 300 }));
  assert.deepEqual(s.argv, ["run", "--no-prompt", "--no-config", "--no-lock", "--no-remote", "--no-npm", "--cached-only", "--no-code-cache",
    `--allow-read=${work},${runTmp},${h.engine}`, `--allow-write=${work},${runTmp}`, "--allow-env", "--deny-net", "--deny-run", "--deny-ffi", "--deny-sys",
    h.engine, "notebook", "run", join(work, "nb dir/a.ipynb"), "--json", "--write", "--timeout", "300", "--confine", work, "--confine", runTmp, "--until-stdin-ends"]);
  // (the environment: exactly these keys, nothing of this process's)
  assert.deepEqual(Object.keys(h.spawned[0].opts.env).sort(), ["DENO_DIR", "HOME", "NO_COLOR", "PYTHONTZPATH", "TMPDIR", "TZ", "TZDIR", ...(process.platform === "darwin" ? ["__CF_USER_TEXT_ENCODING"] : [])]);
  assert.deepEqual(h.spawned[0].opts.env, runEnv({ work, runTmp }));
  for (const [k, v] of Object.entries(runEnv({ work, runTmp }))) assert.equal(s.env[k], v, k);
  assert.equal(h.spawned[0].opts.detached, true, "a process group of its own");
  assert.equal(s.cwd, join(work, "nb dir"));
  assert.equal(s.tmpMode, 0o700);
  assert.equal(s.zones, Object.keys(PIN.tzdata.files).length);
  assert.equal(s.paris, PIN.tzdata.files["Europe/Paris"].sha256);
  assert.equal(existsSync(runTmp), false, "the run tmp removed after");
  assert.equal(readFileSync(join(work, "out.txt"), "utf8"), "made by the run");
  h.done();
});

test("a link or special file in the copy before a run: refused, nothing started; a link the run leaves undoes the run, the copy as it was before", T, async () => {
  const h = setup();
  symlinkSync("/etc/passwd", join(h.store.work(h.task), "planted"));
  await assert.rejects(h.runner.run(h.task, "nb dir/a.ipynb"), (e) => e.code === "bad_request" && /can't start from/.test(e.message));
  assert.equal(h.spawned.length, 0);
  h.done();
  const p = setup({ mode: "plant" });
  await p.store.writeWork(p.task, "mine.txt", Buffer.from("an edit not yet proposed"));
  await assert.rejects(p.runner.run(p.task, "nb dir/a.ipynb"), (e) => e.code === "bad_request" && /its changes were undone/.test(e.message));
  const work = p.store.work(p.task);
  assert.deepEqual(readdirSync(work).sort(), ["mine.txt", "nb dir"]);
  assert.equal(readFileSync(join(work, "mine.txt"), "utf8"), "an edit not yet proposed");
  assert.equal(readFileSync(join(work, "nb dir/a.ipynb"), "utf8"), NB);
  assert.deepEqual(readdirSync(p.store.dir(p.task)).filter((n) => n.startsWith(".")), [], "no half-built or dropped copy left");
  p.done();
});

test("Stop: the run's whole process group killed (a grandchild too), the exit waited for, and its changes undone", T, async () => {
  const h = setup({ mode: "hang" });
  const ac = new AbortController();
  const run = h.runner.run(h.task, "nb dir/a.ipynb", { signal: ac.signal });
  await until(() => existsSync(join(h.fake, "grandchild")), "the grandchild");
  const g = Number(readFileSync(join(h.fake, "grandchild"), "utf8"));
  assert.ok(alive(g));
  ac.abort();
  await assert.rejects(run, (e) => /stopped \(the task's turn was stopped\): its changes were undone/.test(e.message));
  await until(() => !alive(g), "the grandchild gone", 3000);
  assert.equal(existsSync(join(h.store.work(h.task), "partial.txt")), false);
  h.done();
});

test("the wall bound kills a run that outlives its cells' time; too much output kills it too; a run with no report says why", T, async () => {
  const w = setup({ mode: "hang", limits: { marginMs: 100 } });
  await assert.rejects(w.runner.run(w.task, "nb dir/a.ipynb", { timeoutS: 1 }), (e) => /its time was up/.test(e.message));
  assert.equal(existsSync(join(w.store.work(w.task), "partial.txt")), false);
  w.done();
  const b = setup({ mode: "big", limits: { stdout: 1024 * 1024 } });
  await assert.rejects(b.runner.run(b.task, "nb dir/a.ipynb"), (e) => e.code === "too_large");
  b.done();
  const n = setup({ mode: "noreport" });
  await assert.rejects(n.runner.run(n.task, "nb dir/a.ipynb"), (e) => e.code === "unavailable" && /no report \(exit 2: sagebrush notebook run: refused/.test(e.message));
  n.done();
});

test("paths: a space works; a comma anywhere Deno must be granted makes runs unavailable, nothing started; a path outside the copy is refused", T, async () => {
  const base = mkdtempSync(join(tmpdir(), "sb-runner-paths-"));
  const c = setup({ root: join(base, "with,comma", "tasks") });
  await assert.rejects(c.runner.run(c.task, "nb dir/a.ipynb"), (e) => e.code === "unavailable" && /comma/.test(e.message));
  assert.equal(c.spawned.length, 0);
  c.done();
  const s = setup({ root: join(base, "with space", "tasks") });
  assert.equal((await s.runner.run(s.task, "nb dir/a.ipynb")).exit, 0);
  for (const bad of ["../x.ipynb", "/etc/x.ipynb", "nb dir/a.txt"]) await assert.rejects(s.runner.run(s.task, bad), (e) => e.code === "bad_request", bad);
  s.done();
  rmSync(base, { recursive: true, force: true });
});

test("the zone data: copied only as pinned; a changed file or a link in the source makes runs unavailable, nothing started; its bytes count in the task's budget", T, async () => {
  const src = mkdtempSync(join(tmpdir(), "sb-zones-"));
  cpSync(TZ_SOURCE, src, { recursive: true });
  writeFileSync(join(src, "Europe/Paris"), "not the pinned bytes");
  const t = setup({ zoneSource: src + "/" });
  await assert.rejects(t.runner.run(t.task, "nb dir/a.ipynb"), (e) => e.code === "unavailable" && /Europe\/Paris isn't as pinned/.test(e.message));
  assert.equal(t.spawned.length, 0);
  t.done();
  rmSync(join(src, "Europe/Paris"));
  symlinkSync(join(TZ_SOURCE, "Europe/Paris"), join(src, "Europe/Paris"));
  assert.throws(() => copyZones(join(src, "..", `dest-${process.pid}`), PIN.tzdata.files, src + "/"), /ELOOP|isn't as pinned/);
  rmSync(join(src, "..", `dest-${process.pid}`), { recursive: true, force: true });
  rmSync(src, { recursive: true, force: true });
  const b = setup();
  b.store.budget = { ...b.store.budget, task: b.store.usage(b.task) + 100 * 1024 };
  await assert.rejects(b.runner.run(b.task, "nb dir/a.ipynb"), (e) => e.code === "busy");
  b.done();
});

test("in a turn: notebook_run gives the model the report; calls run one at a time (a write waits for the run); a Stop ends the turn only after the run's exit and undoing", T, async () => {
  // (a model that calls notebook_run and, at once, a write; then proposes)
  const h = setup({ mode: "hang" });
  let writeDone = null, runResult = null;
  const query = ({ options }) => (async function* () {
    const t = options.mcpServers[TASK_SERVER].handlers;
    const run = t.notebook_run({ path: "nb dir/a.ipynb" }).then((r) => { runResult = r; });
    const write = t.workspace_write({ path: "w.txt", text: "x" }).then(() => { writeDone = existsSync(join(h.fake, "grandchild")) ? "after the run started" : "before"; });
    yield { type: "system", subtype: "init", session_id: "s", tools: [], mcp_servers: [] };
    await Promise.all([run, write]);
    yield { type: "result", subtype: "success", is_error: false, result: "ok", usage: {} };
  })();
  const turns = new TaskTurns({ store: h.store, query, createServer: fakeCreateServer, free: () => 1e12, runner: h.runner, limits: { pollMs: 10, stopMs: 1 } }); // (a bound too short to cover the run: only the turn's own wait can)
  turns.begin(h.task, "start");
  await until(() => existsSync(join(h.fake, "grandchild")), "the run started");
  const g = Number(readFileSync(join(h.fake, "grandchild"), "utf8"));
  await new Promise((r) => setTimeout(r, 50));
  assert.equal(writeDone, null, "the write waits while the run is alive");
  // (the undoing made slow, so only the turn's own wait for its run can cover it)
  const restore = h.store.restoreWork.bind(h.store);
  h.store.restoreWork = async (...a) => { await new Promise((r) => setTimeout(r, 300)); return restore(...a); };
  // (what holds the moment the turn's place is freed)
  let atFree = null;
  turns.running.get(h.task).done.then(() => { atFree = { alive: alive(g), partial: existsSync(join(h.store.work(h.task), "partial.txt")) }; });
  await turns.stop(h.task);
  await until(() => atFree, "the turn over");
  assert.deepEqual(atFree, { alive: false, partial: false }, "the run's group gone, and its changes undone, before the turn's place is freed");
  assert.equal(h.store.state(h.task).status, "interrupted");
  h.done();
  // (a run that reports: its summary is the tool's result)
  const r = setup();
  let result;
  const q2 = ({ options }) => (async function* () {
    result = await options.mcpServers[TASK_SERVER].handlers.notebook_run({ path: "nb dir/a.ipynb", timeout: 30 });
    await options.mcpServers[TASK_SERVER].handlers.propose({ summary: "ran it" });
    yield { type: "result", subtype: "success", is_error: false, result: "ok", usage: {} };
  })();
  const t2 = new TaskTurns({ store: r.store, query: q2, createServer: fakeCreateServer, free: () => 1e12, runner: r.runner });
  t2.begin(r.task, "start");
  await until(() => r.store.state(r.task).status === "proposal", "proposed");
  assert.equal(result.isError, undefined);
  assert.deepEqual(JSON.parse(result.content[0].text), { ok: true, exit: 0, wrote: true, cells: [{ n: 1, id: "a", status: "ok", ms: 1, stdout: "hello\n" }] });
  assert.equal(r.seen().argv[r.seen().argv.indexOf("--timeout") + 1], "30");
  r.done();
});

test("leftovers of a crash during a run or an undo (run tmp folders, a half-built or dropped copy) are cleared when the store loads; other names are kept", () => {
  const dir = mkdtempSync(join(tmpdir(), "sb-runner-left-"));
  const store = new TaskStore({ root: join(dir, "tasks"), scope: "install-1" }).init();
  const task = store.start(checkRequest("tasks.start", { title: "t", prompt: "p", target: "local", run: true, docs: [{ path: "a.ipynb", kind: "notebook", content: NB }] })).task;
  const tdir = store.dir(task), tmp = store.runTmpRoot(task);
  for (const d of [join(tmp, "run-0123456789ab"), join(tdir, ".work-0123456789ab"), join(tdir, ".dropped-0123456789ab"), join(tmp, "keep-me"), join(tdir, ".work-not-ours")]) mkdirSync(join(d, "x"), { recursive: true });
  new TaskStore({ root: join(dir, "tasks"), scope: "install-1" }).init();
  assert.deepEqual(readdirSync(tmp).sort(), ["keep-me"]);
  assert.deepEqual(readdirSync(tdir).filter((n) => n.startsWith(".")).sort(), [".staging", ".work-not-ours"].filter((n) => existsSync(join(tdir, n))));
  assert.ok(existsSync(join(tdir, ".work-not-ours")));
  rmSync(dir, { recursive: true, force: true });
});

test("a crash between an undo's two renames: at load the undo is finished (the copy as before the run, the unproposed edit kept); with only the run's copy, that is put back; never both deleted", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sb-runner-undo-"));
  const open = () => new TaskStore({ root: join(dir, "tasks"), scope: "install-1" }).init();
  let s = open();
  const { task } = s.start(checkRequest("tasks.start", { title: "t", prompt: "p", target: "local", run: true, docs: [{ path: "a.txt", kind: "file", content: "base" }] }));
  await s.writeWork(task, "a.txt", Buffer.from("UNPROPOSED EDIT TO KEEP"));
  const tree = await s.snapshotWork(task);
  writeFileSync(join(s.work(task), "a.txt"), "PARTIAL RUN");
  // (the crash: the first rename done and durable, the second never made)
  const rename = fs.renameSync;
  fs.renameSync = (a, b) => { const r = rename(a, b); if (a === s.work(task) && b.includes("/.dropped-")) throw new Error("crash"); return r; };
  syncBuiltinESMExports();
  try { await assert.rejects(s.restoreWork(task, tree), /crash/); } finally { fs.renameSync = rename; syncBuiltinESMExports(); }
  assert.equal(existsSync(s.work(task)), false);
  s = open();
  assert.equal(readFileSync(join(s.work(task), "a.txt"), "utf8"), "UNPROPOSED EDIT TO KEEP");
  assert.deepEqual(readdirSync(s.dir(task)).filter((n) => /^\.(work|dropped)-/.test(n)), [], "the run's copy dropped once the undo is finished");
  // (only the run's copy left: put back, not deleted)
  fs.renameSync(s.work(task), join(s.dir(task), ".dropped-0123456789ab"));
  s = open();
  assert.equal(readFileSync(join(s.work(task), "a.txt"), "utf8"), "UNPROPOSED EDIT TO KEEP");
  assert.notEqual(s.state(task).status, "failed");
  // (work/ not a plain folder: nothing is renamed over it, and the copies beside it are kept, never deleted)
  fs.renameSync(s.work(task), join(s.dir(task), ".dropped-0123456789ab"));
  writeFileSync(s.work(task), "not a folder");
  s = open();
  assert.ok(existsSync(join(s.dir(task), ".dropped-0123456789ab", "a.txt")), "the only copy kept");
  rmSync(dir, { recursive: true, force: true });
});

test("the zone data is admitted as any write is: against the total as well as the task's budget, refused busy before any copy or start; a run's hold counts for every task until its tmp is gone", T, async () => {
  const h = setup();
  const zones = Object.values(PIN.tzdata.files).reduce((n, f) => n + f.size, 0);
  const all = () => h.store.list().tasks.reduce((n, t) => n + h.store.usage(t.task), 0);
  h.store.budget = { ...h.store.budget, total: all() + Math.floor(zones / 2) };
  await assert.rejects(h.runner.run(h.task, "nb dir/a.ipynb"), (e) => e.code === "busy" && /tasks' storage budget/.test(e.message));
  assert.equal(h.spawned.length, 0);
  assert.deepEqual(readdirSync(join(h.store.dir(h.task), "tmp")), [], "nothing copied, the tmp removed");
  assert.equal(h.store.held.size, 0);
  // (a hold, as a run has while its zone data is on disk: another task's write past the total is refused until it goes)
  h.store.budget = { ...h.store.budget, total: 4096 * 1024 * 1024 };
  const other = h.store.start(checkRequest("tasks.start", { title: "o", prompt: "p", target: "local", run: true, docs: [{ path: "x.txt", kind: "file", content: "x" }] })).task;
  h.store.budget = { ...h.store.budget, total: all() + zones + 1024 };
  const release = h.store.reserveRun(h.task, zones);
  await assert.rejects(h.store.writeWork(other, "big.txt", Buffer.alloc(4096)), (e) => e.code === "busy");
  release();
  await h.store.writeWork(other, "big.txt", Buffer.alloc(4096));
  // (a run that goes through holds nothing after)
  h.store.budget = { ...h.store.budget, total: 4096 * 1024 * 1024 };
  assert.equal((await h.runner.run(h.task, "nb dir/a.ipynb")).exit, 0);
  assert.equal(h.store.held.size, 0);
  h.done();
});

// ---- an agent that died with a run alive: recovery at the next load (the backstop; the lifeline is the real rows')
function deadAgentFixture(signal) {
  const dir = mkdtempSync(join(tmpdir(), "sb-runner-dead-"));
  const open = (more = {}) => new TaskStore({ root: join(dir, "tasks"), scope: "install-1", ...more }).init();
  const s = open();
  const { task } = s.start(checkRequest("tasks.start", { title: "t", prompt: "p", target: "local", run: true, docs: [{ path: "a.txt", kind: "file", content: "base" }] }));
  return { dir, open, s, task };
}
// (a stand-in for a run whose agent is gone: started by a parent that exits at once, so, as a real orphan, it is no
//  child of this test (a killed child of ours would linger unreaped); the leader of its own process group)
const sleeper = () => {
  const r = spawnSync(process.execPath, ["-e", "const c = require('child_process').spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { detached: true, stdio: 'ignore' }); c.unref(); process.stdout.write(String(c.pid))"], { encoding: "utf8" });
  return { pid: Number(r.stdout) };
};
const stopOwn = (pid) => { try { process.kill(-pid, "SIGKILL"); } catch {} };

test("at load, a run left alive by an agent that died: killed by group only when its start time matches, waited for, the copy undone, its tmp and record removed", async () => {
  const { procStart } = await import("../lib/proc-start.mjs");
  const f = deadAgentFixture();
  const snap = await f.s.snapshotWork(f.task);
  writeFileSync(join(f.s.work(f.task), "a.txt"), "CHANGED BY THE RUN");
  const tmp = join(f.s.runTmpRoot(f.task), "run-0123456789ab");
  mkdirSync(tmp);
  const p = sleeper();
  await until(() => procStart(p.pid), "the stand-in started");
  try {
    f.s.writeRunRecord(f.task, { v: 1, tmp: "run-0123456789ab", snapshot: snap, pid: p.pid, start: procStart(p.pid) });
    const s2 = f.open();
    assert.equal(alive(p.pid), false, "killed");
    assert.equal(readFileSync(join(s2.work(f.task), "a.txt"), "utf8"), "base");
    assert.equal(existsSync(tmp), false);
    assert.equal(existsSync(join(s2.dir(f.task), "run.json")), false);
    assert.equal(s2.state(f.task).status, "interrupted");
  } finally { stopOwn(p.pid); rmSync(f.dir, { recursive: true, force: true }); }
});

test("at load, a recorded pid whose start time differs is another process now: never signalled; the run is over, so the copy is undone", async () => {
  const f = deadAgentFixture();
  const snap = await f.s.snapshotWork(f.task);
  writeFileSync(join(f.s.work(f.task), "a.txt"), "CHANGED BY THE RUN");
  const p = sleeper();
  try {
    await until(() => alive(p.pid), "the stand-in started");
    f.s.writeRunRecord(f.task, { v: 1, tmp: "run-0123456789ab", snapshot: snap, pid: p.pid, start: "linux:1" });
    const s2 = f.open();
    assert.equal(alive(p.pid), true, "not signalled");
    assert.equal(readFileSync(join(s2.work(f.task), "a.txt"), "utf8"), "base");
  } finally { stopOwn(p.pid); rmSync(f.dir, { recursive: true, force: true }); }
});

test("at load, a run that can't be shown ended (still alive after the wait, or no start time recorded): the task is left as it is, served nothing, its record kept", async () => {
  const { procStart } = await import("../lib/proc-start.mjs");
  const f = deadAgentFixture();
  const snap = await f.s.snapshotWork(f.task);
  writeFileSync(join(f.s.work(f.task), "a.txt"), "CHANGED BY THE RUN");
  const p = sleeper();
  try {
    await until(() => procStart(p.pid), "the stand-in started");
    for (const [start, more] of [[procStart(p.pid), { signal: () => {}, runGoneMs: 200 }], [null, {}]]) {
      f.s.writeRunRecord(f.task, { v: 1, tmp: "run-0123456789ab", snapshot: snap, pid: p.pid, start });
      const s2 = f.open(more);
      assert.equal(s2.state(f.task).status, "failed");
      assert.match(s2.state(f.task).reason, /still running|may still be running/);
      assert.deepEqual(s2.get({ task: f.task, after: 0 }).events, [], "no events served");
      await assert.rejects(s2.resume({ task: f.task }), (e) => e.code === "final");
      assert.equal(readFileSync(join(s2.work(f.task), "a.txt"), "utf8"), "CHANGED BY THE RUN", "nothing touched");
      assert.ok(existsSync(join(s2.dir(f.task), "run.json")));
      assert.equal(alive(p.pid), true);
    }
  } finally { stopOwn(p.pid); rmSync(f.dir, { recursive: true, force: true }); }
});

test("each run asks for the disk again just before it writes anything: short of the task's remaining room plus 64 MB, refused busy, nothing started or copied", T, async () => {
  const h = setup();
  let free = 1e12, result;
  const query = ({ options }) => (async function* () {
    free = 100 * 1024 * 1024; // (above the watch's 64 MB floor, below the room the task may still use plus 64 MB)
    result = await options.mcpServers[TASK_SERVER].handlers.notebook_run({ path: "nb dir/a.ipynb" });
    yield { type: "result", subtype: "success", is_error: false, result: "ok", usage: {} };
  })();
  const turns = new TaskTurns({ store: h.store, query, createServer: fakeCreateServer, free: () => free, runner: h.runner, limits: { pollMs: 10 } });
  turns.begin(h.task, "start");
  await until(() => result, "the call answered");
  assert.equal(result.isError, true);
  assert.match(result.content[0].text, /not enough free disk space/);
  assert.equal(h.spawned.length, 0);
  const tmp = join(h.store.dir(h.task), "tmp");
  assert.ok(!existsSync(tmp) || readdirSync(tmp).length === 0, "nothing made for the run");
  h.done();
});

test("the watch covers the copy and the run's folder within the entry bound: a run past it is cut off, its group killed, and undone, with why", T, async () => {
  const h = setup({ mode: "manyfiles" });
  const query = ({ options }) => (async function* () {
    await options.mcpServers[TASK_SERVER].handlers.notebook_run({ path: "nb dir/a.ipynb" });
    yield { type: "result", subtype: "success", is_error: false, result: "ok", usage: {} };
  })();
  const turns = new TaskTurns({ store: h.store, query, createServer: fakeCreateServer, free: () => 1e12, runner: h.runner, limits: { pollMs: 10, transcriptEntries: 1000 } });
  turns.begin(h.task, "start");
  await until(() => h.store.state(h.task).status === "interrupted" && !turns.isRunning(h.task), "cut off");
  assert.match(h.store.state(h.task).reason, /more than 1000 files/);
  assert.equal(existsSync(join(h.store.work(h.task), "partial.txt")), false);
  assert.deepEqual(readdirSync(join(h.store.dir(h.task), "tmp")), []);
  h.done();
});

test("the measure and the watch skip an entry that goes between its listing and its lstat (a run's scratch file come and gone), and still fail on any other error", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sb-runner-gone-"));
  const store = new TaskStore({ root: join(dir, "tasks"), scope: "install-1" }).init();
  const task = store.start(checkRequest("tasks.start", { title: "t", prompt: "p", target: "local", run: true, docs: [{ path: "a.txt", kind: "file", content: "x" }] })).task;
  writeFileSync(join(store.work(task), "gone.txt"), "here when listed");
  const lstat = fs.lstatSync;
  const as = (code) => { fs.lstatSync = (p, ...a) => { if (String(p).endsWith("gone.txt")) throw Object.assign(new Error(code), { code }); return lstat(p, ...a); }; syncBuiltinESMExports(); };
  try {
    as("ENOENT");
    assert.notEqual(store.usage(task), null, "gone: not counted, still measured");
    assert.equal(store.runTreesProblem(task, 20000), null);
    as("EACCES");
    assert.equal(store.usage(task), null, "any other error: not measured");
    assert.match(store.runTreesProblem(task, 20000), /EACCES|can't/);
  } finally { fs.lstatSync = lstat; syncBuiltinESMExports(); rmSync(dir, { recursive: true, force: true }); }
});

// (rows that stand in an unreadable /proc entry: Linux only; macOS's answers come from ps, the rows after them)
const LINUX = process.platform === "linux" ? {} : { skip: "/proc is Linux's" };

test("at load, a run whose process can't be told apart (its /proc entry unreadable): never taken as ended; the task left as it is, its record kept", LINUX, async () => {
  const { procStart } = await import("../lib/proc-start.mjs");
  const f = deadAgentFixture();
  const snap = await f.s.snapshotWork(f.task);
  writeFileSync(join(f.s.work(f.task), "a.txt"), "RUN STILL ACTIVE");
  const p = sleeper();
  const read = fs.readFileSync;
  try {
    await until(() => procStart(p.pid), "the stand-in started");
    f.s.writeRunRecord(f.task, { v: 1, tmp: "run-0123456789ab", snapshot: snap, pid: p.pid, start: procStart(p.pid) });
    fs.readFileSync = function (path, ...a) { if (String(path) === `/proc/${p.pid}/stat`) throw Object.assign(new Error("EACCES"), { code: "EACCES" }); return read.call(this, path, ...a); };
    syncBuiltinESMExports();
    const s2 = f.open();
    fs.readFileSync = read;
    syncBuiltinESMExports();
    assert.equal(s2.state(f.task).status, "failed");
    assert.match(s2.state(f.task).reason, /may still be running \(its \/proc entry can't be read \(EACCES\)\)/);
    assert.equal(readFileSync(join(s2.work(f.task), "a.txt"), "utf8"), "RUN STILL ACTIVE", "nothing touched");
    assert.ok(existsSync(join(s2.dir(f.task), "run.json")));
    assert.equal(alive(p.pid), true, "not signalled");
  } finally { fs.readFileSync = read; syncBuiltinESMExports(); stopOwn(p.pid); rmSync(f.dir, { recursive: true, force: true }); }
});

test("procInfo (Linux): gone only on a definite no-such-process; an unreadable or unparsable entry is unknown, never gone", LINUX, async () => {
  const { procInfo } = await import("../lib/proc-start.mjs");
  const c = spawnSync(process.execPath, ["-e", "process.stdout.write(String(process.pid))"], { encoding: "utf8" });
  assert.deepEqual(procInfo(Number(c.stdout), "linux"), { gone: true }, "a process that has exited and been reaped");
  const me = procInfo(process.pid, "linux");
  assert.match(me.start, /^linux:\d+$/);
  assert.equal(me.pgid > 0, true);
  const read = fs.readFileSync;
  try {
    for (const [code, body] of [["EACCES", null], ["EIO", null], [null, "garbage without fields"]]) {
      fs.readFileSync = function (path, ...a) { if (String(path) === `/proc/${process.pid}/stat`) { if (code) throw Object.assign(new Error(code), { code }); return body; } return read.call(this, path, ...a); };
      syncBuiltinESMExports();
      const r = procInfo(process.pid, "linux");
      assert.ok(r.unknown && !r.gone, `${code ?? "unparsable"}: ${JSON.stringify(r)}`);
    }
  } finally { fs.readFileSync = read; syncBuiltinESMExports(); }
  assert.ok(procInfo(1, "linux").unknown, "pid 1 is never ours to judge");
});

test("the run's identity can't be recorded once it has started (an EIO): the run doesn't go on: its group killed, waited for, its changes undone, reported failed", T, async () => {
  const h = setup({ mode: "hang", limits: { marginMs: 2000 } });
  const write = h.store.writeRunRecord.bind(h.store);
  h.store.writeRunRecord = (task, rec) => { if (rec.pid !== null) throw Object.assign(new Error("EIO"), { code: "EIO" }); return write(task, rec); };
  // (a short wall bound: a run that went on regardless would end by it, with another reason)
  await assert.rejects(h.runner.run(h.task, "nb dir/a.ipynb", { timeoutS: 1 }), (e) => e.code === "unavailable" && /the run failed: couldn't record the run; its changes were undone/.test(e.message));
  const g = existsSync(join(h.fake, "grandchild")) ? Number(readFileSync(join(h.fake, "grandchild"), "utf8")) : null;
  if (g) await until(() => !alive(g), "the run's group gone", 3000);
  assert.equal(existsSync(join(h.store.work(h.task), "partial.txt")), false, "undone");
  assert.equal(existsSync(join(h.store.dir(h.task), "run.json")), false, "settled: no record left");
  h.done();
});

test("at load, a run recorded only before its start (the agent died between spawning it and recording it): unknown: failed, untouched, nothing signalled; deleting the task's folder discards it", async () => {
  const f = deadAgentFixture();
  const snap = await f.s.snapshotWork(f.task);
  writeFileSync(join(f.s.work(f.task), "a.txt"), "MAYBE A RUN'S");
  mkdirSync(join(f.s.runTmpRoot(f.task), "run-0123456789ab"));
  f.s.writeRunRecord(f.task, { v: 1, tmp: "run-0123456789ab", snapshot: snap, pid: null, start: null });
  const signals = [];
  const s2 = f.open({ signal: (...a) => signals.push(a) });
  assert.equal(s2.state(f.task).status, "failed");
  assert.match(s2.state(f.task).reason, /may have started.*delete the task's folder/);
  assert.equal(readFileSync(join(s2.work(f.task), "a.txt"), "utf8"), "MAYBE A RUN'S", "not put back");
  assert.ok(existsSync(join(s2.runTmpRoot(f.task), "run-0123456789ab")), "its tmp kept");
  assert.ok(existsSync(join(s2.dir(f.task), "run.json")));
  assert.deepEqual(signals, []);
  await assert.rejects(s2.resume({ task: f.task }), (e) => e.code === "final");
  // (the person's way out: the task's folder deleted; the next start doesn't know it, and signals nothing)
  rmSync(s2.dir(f.task), { recursive: true, force: true });
  const s3 = f.open({ signal: (...a) => signals.push(a) });
  assert.equal(s3.list().tasks.some((t) => t.task === f.task), false);
  assert.deepEqual(signals, []);
  rmSync(f.dir, { recursive: true, force: true });
});

test("procInfo on this computer: its own process is found (start time and group); a process that has exited and been reaped is gone", { skip: ["linux", "darwin"].includes(process.platform) ? false : "Linux and macOS only" }, async () => {
  const { procInfo } = await import("../lib/proc-start.mjs");
  const me = procInfo(process.pid);
  assert.match(me.start ?? "", new RegExp(`^${process.platform}:`));
  assert.ok(me.pgid > 0);
  const c = spawnSync(process.execPath, ["-e", "process.stdout.write(String(process.pid))"], { encoding: "utf8" });
  assert.deepEqual(procInfo(Number(c.stdout)), { gone: true });
});

test("procInfo (macOS's answers, from a stand-in ps): gone only on ESRCH; a start time and group read; a ps that fails or prints nothing, or another error, is unknown", async () => {
  const { procInfo } = await import("../lib/proc-start.mjs");
  const dir = mkdtempSync(join(tmpdir(), "sb-ps-"));
  // (a stand-in ps: prints what out.txt holds, and exits with code.txt's number)
  const ps = join(dir, "ps");
  writeFileSync(ps, `#!/bin/sh\ncat "${dir}/out.txt"\nexit "$(cat "${dir}/code.txt")"\n`);
  chmodSync(ps, 0o755);
  const say = (out, code = 0) => { writeFileSync(join(dir, "out.txt"), out); writeFileSync(join(dir, "code.txt"), String(code)); };
  const kill = (code) => () => { if (code) throw Object.assign(new Error(code), { code }); };
  try {
    say("  4242 Sat Nov 21 05:12:03 2026\n");
    assert.deepEqual(procInfo(4321, "darwin", { ps, kill: kill(null) }), { start: "darwin:Sat Nov 21 05:12:03 2026", pgid: 4242 });
    assert.deepEqual(procInfo(4321, "darwin", { ps, kill: kill("EPERM") }), { start: "darwin:Sat Nov 21 05:12:03 2026", pgid: 4242 }, "another account's process is there: still asked");
    assert.deepEqual(procInfo(4321, "darwin", { ps, kill: kill("ESRCH") }), { gone: true });
    for (const [out, code, why] of [["", 0, "nothing printed"], ["  4242 Sat Nov 21 05:12:03 2026\n", 1, "ps failed"], ["garbage\n", 0, "unparsable"]]) {
      say(out, code);
      const r = procInfo(4321, "darwin", { ps, kill: kill(null) });
      assert.ok(r.unknown && !r.gone, `${why}: ${JSON.stringify(r)}`);
    }
    assert.ok(procInfo(4321, "darwin", { ps, kill: kill("EINVAL") }).unknown, "an error other than ESRCH or EPERM: unknown");
    assert.ok(procInfo(4321, "darwin", { ps: join(dir, "no-such-ps"), kill: kill(null) }).unknown, "no ps at all: unknown");
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("on macOS the run's __CF_USER_TEXT_ENCODING is the runner's own, from the uid, never this process's; elsewhere there is none", () => {
  const before = process.env.__CF_USER_TEXT_ENCODING;
  process.env.__CF_USER_TEXT_ENCODING = "0x0:0x8000100:0x0";
  try {
    const at = { work: "/w", runTmp: "/t" };
    const base = ["DENO_DIR", "HOME", "NO_COLOR", "PYTHONTZPATH", "TMPDIR", "TZ", "TZDIR"];
    assert.deepEqual(Object.keys(runEnv(at, { platform: "linux", uid: 501 })).sort(), base);
    const mac = runEnv(at, { platform: "darwin", uid: 501 });
    assert.deepEqual(Object.keys(mac).sort(), [...base, "__CF_USER_TEXT_ENCODING"]);
    assert.equal(mac.__CF_USER_TEXT_ENCODING, "0x1F5:0:0");
    assert.equal(cfUserTextEncoding(0), "0x0:0:0");
    assert.equal(cfUserTextEncoding(4294967294), "0xFFFFFFFE:0:0");
    for (const uid of [null, -1, 1.5, "501"]) assert.throws(() => runEnv(at, { platform: "darwin", uid }), /uid/, String(uid));
  } finally {
    if (before === undefined) delete process.env.__CF_USER_TEXT_ENCODING; else process.env.__CF_USER_TEXT_ENCODING = before;
  }
});
