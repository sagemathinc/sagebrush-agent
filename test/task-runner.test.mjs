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
import { fakeCreateServer } from "../lib/fake.mjs";
import { RUNNER_PIN } from "../lib/runner-fetch.mjs";
import { copyZones, RUNS_ENABLED, runArgv, runEnv, TaskRunner, TZ_SOURCE } from "../lib/task-runner.mjs";
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
  writeFileSync(join(fake, "control.json"), JSON.stringify({ mode, runtime: RUNTIME?.kind }));
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
    h.engine, "notebook", "run", join(work, "nb dir/a.ipynb"), "--json", "--write", "--timeout", "300", "--confine", work, "--confine", runTmp]);
  // (the environment: exactly these keys, nothing of this process's)
  assert.deepEqual(Object.keys(h.spawned[0].opts.env).sort(), ["DENO_DIR", "HOME", "NO_COLOR", "PYTHONTZPATH", "TMPDIR", "TZ", "TZDIR"]);
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
