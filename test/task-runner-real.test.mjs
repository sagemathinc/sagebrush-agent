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
import { TaskRunner } from "../lib/task-runner.mjs";
import { TaskStore } from "../lib/tasks.mjs";
import { checkRequest } from "../lib/tasks-schema.mjs";
import { platformKey } from "../lib/codex-fetch.mjs";

const DENO = process.env.SAGEBRUSH_RUNNER_DENO, ENGINE = process.env.SAGEBRUSH_RUNNER_ENGINE;
const missing = !DENO || !ENGINE || !existsSync(DENO) || !existsSync(ENGINE) ? "needs SAGEBRUSH_RUNNER_DENO and SAGEBRUSH_RUNNER_ENGINE (the pinned deno, a built engine with --confine)" : null;
if (missing && process.env.SAGEBRUSH_REQUIRE_RUNNER === "1") test("the runner's acceptance rows are required here (SAGEBRUSH_REQUIRE_RUNNER=1)", () => assert.fail(missing));
const T = missing ? { skip: missing } : {};
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
  process.env.SB_PARENT_SECRET = "must not be seen";
  const h = setup([
    "import json, os\nprint(json.dumps(sorted(os.environ)))\nprint('secret' in str(os.environ.get('SB_PARENT_SECRET')))",
    "res = []\nfor m in ('socket', 'subprocess', 'js', 'pyodide', 'ctypes'):\n    try:\n        mod = __import__(m)\n        res.append(m + ' imported')\n        if m == 'ctypes': mod.CDLL(None); res.append('ctypes CDLL OK')\n    except Exception as e:\n        res.append(m + ' refused')\nimport os\nfor name in ('system', 'symlink', 'link', 'mkfifo', 'readlink'):\n    res.append(name + (' present' if hasattr(os, name) else ' absent'))\nprint(res)",
  ]);
  try {
    const r = await h.runner.run(h.task, "nb/a.ipynb");
    const [envLine, secret] = r.report.cells[0].stdout.trim().split("\n");
    assert.deepEqual(JSON.parse(envLine), ["DENO_DIR", "DENO_NODE_SHIM_ACTIVE", "HOME", "NO_COLOR", "PATH", "PYTHONTZPATH", "TMPDIR", "TZ", "TZDIR"]);
    assert.equal(secret, "False");
    const res = r.report.cells[1].stdout;
    for (const bad of ["socket imported", "subprocess imported", "js imported", "pyodide imported", "CDLL OK", "system present", "symlink present", "link present", "mkfifo present", "readlink present"]) assert.ok(!res.includes(`'${bad}`), `${bad} in ${res}`);
  } finally {
    delete process.env.SB_PARENT_SECRET;
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
