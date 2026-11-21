// The runner's acceptance rows (plan r3.4 §2.6, SEC's conditions) with the real pinned Deno and an engine with
// --confine: given as SAGEBRUSH_RUNNER_DENO (the deno executable) and SAGEBRUSH_RUNNER_ENGINE (the built engine
// bundle).  Without them these rows are skipped; SAGEBRUSH_REQUIRE_RUNNER=1 makes that a failure (a job that exists
// to produce this evidence).  Every row starts the run the way the agent does, through TaskRunner.run.
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { RUNNER_PIN } from "../lib/runner-fetch.mjs";
import { cfUserTextEncoding, TaskRunner } from "../lib/task-runner.mjs";
import { TaskStore } from "../lib/tasks.mjs";
import { checkRequest } from "../lib/tasks-schema.mjs";
import { platformKey } from "../lib/codex-fetch.mjs";

const DENO = process.env.SAGEBRUSH_RUNNER_DENO, ENGINE = process.env.SAGEBRUSH_RUNNER_ENGINE;
const missing = !DENO || !ENGINE || !existsSync(DENO) || !existsSync(ENGINE) ? "needs SAGEBRUSH_RUNNER_DENO and SAGEBRUSH_RUNNER_ENGINE (the pinned deno, a built engine with --confine)" : null;
if (missing && process.env.SAGEBRUSH_REQUIRE_RUNNER === "1" && process.platform !== "win32") test("the runner's acceptance rows are required here (SAGEBRUSH_REQUIRE_RUNNER=1)", () => assert.fail(missing));
// (Delegate is refused on Windows in this version: there these rows are declared skips, whatever is given)
const T = process.platform === "win32" ? { skip: "Delegate refused on win32 in this version" } : missing ? { skip: missing } : {};
const PIN = { ...RUNNER_PIN, engine: { version: "local", entry: "engine", files: {} } };

const nb = (cells) => JSON.stringify({ cells: cells.map((src, i) => ({ cell_type: "code", id: `c${i}`, metadata: {}, source: src, outputs: [], execution_count: null })), metadata: { kernelspec: { name: "python3", language: "python", display_name: "Python 3" } }, nbformat: 4, nbformat_minor: 5 });
function setup(cells, { root, extra = [] } = {}) {
  const dir = mkdtempSync(join(tmpdir(), "sb-runner-real-"));
  const store = new TaskStore({ root: root ?? join(dir, "tasks"), scope: "install-1", transcripts: join(dir, "projects") }).init();
  const runner = new TaskRunner({ store, enabled: true, pin: PIN, platform: platformKey(), ensure: async () => ({ deno: DENO, engine: ENGINE }) });
  const docs = [{ path: "nb/a.ipynb", kind: "notebook", content: nb(cells) }, ...extra];
  const task = store.start(checkRequest("tasks.start", { title: "t", prompt: "p", target: "local", run: true, docs })).task;
  const other = store.start(checkRequest("tasks.start", { title: "o", prompt: "p", target: "local", run: true, docs: [{ path: "secret.txt", kind: "file", content: "OTHER TASK" }] })).task;
  return { dir, store, runner, task, other, done: () => rmSync(dir, { recursive: true, force: true }) };
}
const stdout = (r) => r.report.cells.map((c) => c.stdout + (c.error ?? "")).join("\n");

test("a notebook runs: cells in order, a file beside it imports, zone data works, the outputs written into the copy's notebook", T, async () => {
  const h = setup(["import helper\nprint('sum', helper.add(2, 3))", "import zoneinfo, datetime\nprint('paris', datetime.datetime(2026, 7, 1, tzinfo=zoneinfo.ZoneInfo('Europe/Paris')).utcoffset())", "open('made.txt', 'w').write('by the run')\nprint('wrote')"],
    { extra: [{ path: "nb/helper.py", kind: "file", content: "def add(a, b):\n    return a + b\n" }] });
  const r = await h.runner.run(h.task, "nb/a.ipynb");
  assert.equal(r.report.ok, true, stdout(r));
  assert.deepEqual(r.report.cells.map((c) => c.stdout.trim()), ["sum 5", "paris 2:00:00", "wrote"]);
  const written = JSON.parse(readFileSync(join(h.store.work(h.task), "nb/a.ipynb"), "utf8"));
  assert.equal(written.cells[0].outputs[0].text.join?.("") ?? written.cells[0].outputs[0].text, "sum 5\n");
  assert.equal(readFileSync(join(h.store.work(h.task), "nb/made.txt"), "utf8"), "by the run");
  h.done();
});

test("sentinels outside the copy (under the real home, beside the engine, another task, this task's own control files and git): every read, write and listing refused, bytes unchanged", T, async () => {
  const tag = Math.random().toString(36).slice(2, 10);
  const homeSentinel = join(homedir(), `.sb-runner-sentinel-${tag}`);
  writeFileSync(homeSentinel, "HOME SENTINEL");
  const engineSentinel = join(realpathSync(join(ENGINE, "..")), `.sb-runner-sentinel-${tag}`);
  writeFileSync(engineSentinel, "CACHE SENTINEL");
  let h;
  try {
    h = setup([""]);
    const own = h.store.dir(h.task);
    const targets = [homeSentinel, engineSentinel, join(h.store.work(h.other), "secret.txt"), join(own, "task.json"), join(own, "git", "HEAD"), join(own, "log.jsonl")];
    const before = targets.map((p) => readFileSync(p));
    const probe = `import os, json\nres = []\nfor p in ${JSON.stringify(targets)}:\n    for what, f in (('read', lambda p: open(p).read()), ('write', lambda p: open(p, 'a').write('x')), ('list', lambda p: os.listdir(os.path.dirname(p)))):\n        try:\n            f(p); res.append(what + ' OK ' + p)\n        except Exception as e:\n            res.append(what + ' refused')\nprint(json.dumps(res))`;
    writeFileSync(join(h.store.work(h.task), "nb/a.ipynb"), nb([probe]));
    const r = await h.runner.run(h.task, "nb/a.ipynb");
    const res = JSON.parse(r.report.cells[0].stdout);
    assert.equal(res.length, targets.length * 3);
    assert.deepEqual(res.filter((x) => / OK /.test(x)), [], "nothing outside reached");
    targets.forEach((p, i) => assert.ok(readFileSync(p).equals(before[i]), p));
  } finally {
    rmSync(homeSentinel, { force: true });
    rmSync(engineSentinel, { force: true });
    h?.done();
  }
});

test("no network, no subprocess, no foreign code, no Deno namespace; the environment exactly the runner's (and Deno's own PATH and shim key), none of this process's", T, async () => {
  // (this process's environment poisoned: a planted secret, and a different, valid __CF_USER_TEXT_ENCODING; the run
  //  sees neither: on macOS exactly the runner's own value, at its first cell and at its last, elsewhere none)
  const cfBefore = process.env.__CF_USER_TEXT_ENCODING, darwin = process.platform === "darwin";
  process.env.SB_PARENT_SECRET = "must not be seen";
  process.env.__CF_USER_TEXT_ENCODING = `0x${((process.getuid?.() ?? 0) + 1).toString(16).toUpperCase()}:0x8000100:0x0`;
  const cf = "import json, os\nprint(json.dumps(os.environ.get('__CF_USER_TEXT_ENCODING')))";
  const h = setup([
    "import json, os\nprint(json.dumps(sorted(os.environ)))\nprint('secret' in str(os.environ.get('SB_PARENT_SECRET')))\nprint(json.dumps(os.environ.get('__CF_USER_TEXT_ENCODING')))",
    "res = []\nfor m in ('socket', 'subprocess', 'js', 'pyodide', 'ctypes'):\n    try:\n        mod = __import__(m)\n        res.append(m + ' imported')\n        if m == 'ctypes': mod.CDLL(None); res.append('ctypes CDLL OK')\n    except Exception as e:\n        res.append(m + ' refused')\nimport os\nfor name in ('system', 'symlink', 'link', 'mkfifo', 'readlink'):\n    res.append(name + (' present' if hasattr(os, name) else ' absent'))\nprint(res)",
    cf,
  ]);
  try {
    const r = await h.runner.run(h.task, "nb/a.ipynb");
    const [envLine, secret, cfFirst] = r.report.cells[0].stdout.trim().split("\n");
    assert.deepEqual(JSON.parse(envLine), ["DENO_DIR", "DENO_NODE_SHIM_ACTIVE", "HOME", "NO_COLOR", "PATH", "PYTHONTZPATH", "TMPDIR", "TZ", "TZDIR", ...(darwin ? ["__CF_USER_TEXT_ENCODING"] : [])]);
    assert.equal(secret, "False");
    const cfWant = darwin ? cfUserTextEncoding(process.getuid()) : null;
    assert.equal(JSON.parse(cfFirst), cfWant, "the first cell's __CF_USER_TEXT_ENCODING");
    assert.equal(JSON.parse(r.report.cells[2].stdout.trim()), cfWant, "the last cell's __CF_USER_TEXT_ENCODING");
    const res = r.report.cells[1].stdout;
    for (const bad of ["socket imported", "subprocess imported", "js imported", "pyodide imported", "CDLL OK", "system present", "symlink present", "link present", "mkfifo present", "readlink present"]) assert.ok(!res.includes(`'${bad}`), `${bad} in ${res}`);
  } finally {
    delete process.env.SB_PARENT_SECRET;
    if (cfBefore === undefined) delete process.env.__CF_USER_TEXT_ENCODING; else process.env.__CF_USER_TEXT_ENCODING = cfBefore;
    h.done();
  }
});

test("Stop kills the interpreter mid-cell, the exit is waited for, and the run's changes are undone; a cell over its time is stopped by the engine", T, async () => {
  const h = setup(["open('partial.txt', 'w').write('half')\nprint('started', flush=True)", "while True:\n    pass"]);
  const ac = new AbortController();
  const run = h.runner.run(h.task, "nb/a.ipynb", { signal: ac.signal });
  const t = Date.now();
  while (!existsSync(join(h.store.work(h.task), "nb/partial.txt")) && Date.now() - t < 60000) await new Promise((r) => setTimeout(r, 50));
  ac.abort();
  await assert.rejects(run, /stopped \(the task's turn was stopped\): its changes were undone/);
  assert.equal(existsSync(join(h.store.work(h.task), "nb/partial.txt")), false);
  const r = await h.runner.run(h.task, "nb/a.ipynb", { timeoutS: 3 });
  assert.equal(r.report.cells[1].status, "timeout");
  h.done();
});

test("planted config, import maps and lock files in the copy and above it change nothing; a folder with a space in its path works", T, async () => {
  const base = mkdtempSync(join(tmpdir(), "sb runner space-"));
  const h = setup(["print('ran')"], { root: join(base, "tasks dir"), extra: [
    { path: "deno.json", kind: "file", content: JSON.stringify({ imports: { "node:fs": "./evil.js" }, lock: "deno.lock", nodeModulesDir: "auto" }) },
    { path: "nb/deno.jsonc", kind: "file", content: "{\"importMap\": \"./map.json\"}" },
    { path: "nb/map.json", kind: "file", content: JSON.stringify({ imports: { "node:path": "./evil.js" } }) },
    { path: "nb/package.json", kind: "file", content: JSON.stringify({ type: "module", imports: { "#x": "./evil.js" } }) },
    { path: "deno.lock", kind: "file", content: "not a lock" },
    { path: "nb/evil.js", kind: "file", content: "throw new Error('evil loaded')" },
  ] });
  writeFileSync(join(h.store.dir(h.task), "deno.json"), JSON.stringify({ imports: { "node:fs": "./evil.js" } }));
  try {
    const r = await h.runner.run(h.task, "nb/a.ipynb");
    assert.equal(r.report.cells[0].stdout, "ran\n");
  } finally {
    h.done();
    rmSync(base, { recursive: true, force: true });
  }
});

test("the agent killed mid-run: the run ends with it (its input closed), and the next start undoes the copy, removes the run's folder and record, the task interrupted", T, async () => {
  const { spawn } = await import("node:child_process");
  const { readdirSync } = await import("node:fs");
  const h = setup(["open('partial.txt', 'w').write('half')\nprint('started', flush=True)", "while True:\n    pass"]);
  const lib = new URL("../lib/", import.meta.url).href;
  const agent = join(h.dir, "agent.mjs");
  writeFileSync(agent, `
import { TaskStore } from "${lib}tasks.mjs";
import { TaskRunner } from "${lib}task-runner.mjs";
import { RUNNER_PIN } from "${lib}runner-fetch.mjs";
import { platformKey } from "${lib}codex-fetch.mjs";
const store = new TaskStore({ root: ${JSON.stringify(h.store.root)}, scope: "install-1", transcripts: ${JSON.stringify(join(h.dir, "projects"))} }).init();
const runner = new TaskRunner({ store, enabled: true, pin: { ...RUNNER_PIN, engine: { version: "local", entry: "engine", files: {} } }, platform: platformKey(), ensure: async () => ({ deno: ${JSON.stringify(DENO)}, engine: ${JSON.stringify(ENGINE)} }) });
// (a store that loads a working task marks it interrupted, as after any restart: resumed, as the person would)
await store.resume({ task: ${JSON.stringify(h.task)} });
await runner.run(${JSON.stringify(h.task)}, "nb/a.ipynb");
`);
  const a = spawn(process.execPath, [agent], { stdio: ["ignore", "ignore", "pipe"] });
  let agentErr = "";
  a.stderr.on("data", (d) => { agentErr += d; });
  const record = join(h.store.dir(h.task), "run.json");
  const t = Date.now();
  let pid = null;
  while (Date.now() - t < 60000) {
    try { pid = JSON.parse(readFileSync(record, "utf8")).pid; } catch {}
    if (pid && existsSync(join(h.store.work(h.task), "nb/partial.txt"))) break;
    await new Promise((r) => setTimeout(r, 50));
  }
  const aliveP = (p) => { try { process.kill(p, 0); return true; } catch { return false; } };
  try {
    assert.ok(pid && aliveP(pid), `the run started, its pid recorded (agent: ${agentErr.slice(-800)})`);
    a.kill("SIGKILL");
    const k = Date.now();
    while (aliveP(pid) && Date.now() - k < 10000) await new Promise((r) => setTimeout(r, 50));
    assert.equal(aliveP(pid), false, "the run ended with its agent");
    const s2 = new TaskStore({ root: h.store.root, scope: "install-1", transcripts: join(h.dir, "projects") }).init();
    assert.equal(s2.state(h.task).status, "interrupted");
    assert.equal(existsSync(join(s2.work(h.task), "nb/partial.txt")), false, "the run's changes undone");
    assert.equal(existsSync(record), false);
    assert.deepEqual(readdirSync(join(s2.dir(h.task), "tmp")), []);
  } finally {
    if (pid) try { process.kill(-pid, "SIGKILL"); } catch {}
    h.done();
  }
});
