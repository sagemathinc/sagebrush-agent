// Windows: a tree started inside a job object (lib/win-job.mjs). The fixed helper source and how it is invoked, checked
// anywhere; the real job (kill the helper, the target exits, an orphan) on Windows only.
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { spawn } from "node:child_process";
import { test } from "node:test";
import { AppServer } from "../lib/codex.mjs";
import { JOB_REFUSED, jobRefusal, jobScript, jobSpawn, SOURCE, treeSpawn } from "../lib/win-job.mjs";

const decode = (args) => Buffer.from(args[args.indexOf("-EncodedCommand") + 1], "base64").toString("utf16le");
const specOf = (script) => JSON.parse(Buffer.from(/FromBase64String\('([A-Za-z0-9+/=]*)'\)/.exec(script)[1], "base64").toString("utf8"));

test("the helper's source is fixed: a job with KILL_ON_JOB_CLOSE, the helper in it before the target starts, the caller watched", () => {
  assert.match(SOURCE, /const uint KILL_ON_JOB_CLOSE = 0x2000/);
  assert.match(SOURCE, /info\.Basic\.LimitFlags = KILL_ON_JOB_CLOSE;/);
  assert.match(SOURCE, /SetInformationJobObject\(job, EXTENDED_LIMIT_INFORMATION, ref info/);
  const assign = SOURCE.indexOf("AssignProcessToJobObject(job, GetCurrentProcess())"), start = SOURCE.indexOf("Process.Start(psi)");
  assert.ok(assign > 0 && start > assign, "the helper joins the job before the target exists");
  assert.ok(SOURCE.indexOf("OpenProcess(SYNCHRONIZE | QUERY_LIMITED_INFORMATION, false, parentPid)") < start, "the caller's handle is opened before the target starts");
  assert.match(SOURCE, /pc > me\) throw/, "a caller created after the helper (a reused pid) isn't taken for it");
  assert.match(SOURCE, /psi\.UseShellExecute = false;/);
  assert.match(SOURCE, /psi\.Environment\.Clear\(\);/, "the target's environment is set whole");
  assert.doesNotMatch(SOURCE, /Redirect/, "the target's standard handles are the helper's, never redirected");
  // (the script around it: nothing evaluated from text, SOURCE in a single-quoted here-string, which PowerShell doesn't expand)
  const s = jobScript({ file: "C:\\x\\codex.exe", args: ["a"], cwd: "", keys: [], values: [], parent: 1 });
  assert.doesNotMatch(s, /Invoke-Expression|\biex\b|ScriptBlock::Create/i);
  assert.ok(s.includes("Add-Type -TypeDefinition @'\n" + SOURCE + "\n'@ -Language CSharp"));
  assert.doesNotMatch(SOURCE, /^'@/m, "the here-string can't end early");
  assert.match(s, new RegExp(`exit ${JOB_REFUSED}`));
});

test("the spec is the only variable part: base64 of the target's file, argv, folder, environment and the caller's pid", () => {
  const nasty = ["a b", 'q"uote', "back\\slash\\", "'@", "$(calc)", "`n", "\u00e9"];
  const s = jobScript({ file: "C:\\Program Files\\x\\codex.exe", args: nasty, cwd: "C:\\w d", keys: ["A", "B"], values: ["1", "'@$x"], parent: 4242 });
  const spec = specOf(s);
  assert.deepEqual(spec, { file: "C:\\Program Files\\x\\codex.exe", args: nasty, cwd: "C:\\w d", keys: ["A", "B"], values: ["1", "'@$x"], parent: 4242 });
  // (none of the target's text appears in the script itself)
  for (const t of ["'@$x", "$(calc)", "q\"uote"]) assert.ok(!s.includes(t), t);
});

test("jobSpawn: Windows PowerShell by its absolute path, the script encoded, the caller's stdio and folder, the target's environment in the spec", () => {
  const calls = [];
  const fake = (cmd, args, opts) => { calls.push({ cmd, args, opts }); return { pid: 1 }; };
  const helperEnv = { SystemRoot: "C:\\Windows", Path: "C:\\Windows\\System32", SECRET_OF_AGENT: "x" };
  jobSpawn("C:\\c\\codex.exe", ["app-server", "--x y"], { cwd: "C:\\run", env: { CODEX_HOME: "C:\\u\\.codex", Path: "C:\\c" }, stdio: ["pipe", "pipe", "pipe"] }, { spawnFn: fake, env: helperEnv });
  const [c] = calls;
  assert.equal(c.cmd, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
  assert.deepEqual(c.args.slice(0, 5), ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand"]);
  assert.deepEqual(c.opts.stdio, ["pipe", "pipe", "pipe"]);
  assert.equal(c.opts.cwd, "C:\\run");
  assert.equal(c.opts.windowsHide, true);
  assert.equal(c.opts.env, helperEnv, "the helper's own environment is this process's");
  const spec = specOf(decode(c.args));
  assert.deepEqual(spec, { file: "C:\\c\\codex.exe", args: ["app-server", "--x y"], cwd: "C:\\run", keys: ["CODEX_HOME", "Path"], values: ["C:\\u\\.codex", "C:\\c"], parent: process.pid });
  assert.ok(!spec.keys.includes("SECRET_OF_AGENT"), "the target gets exactly opts.env");
});

test("a helper that couldn't make the job: said as such, and Codex reports it as not started", async () => {
  assert.equal(jobRefusal(0, ""), null);
  assert.equal(jobRefusal(1, "sagebrush-job: x"), null);
  assert.match(jobRefusal(JOB_REFUSED, "noise\nsagebrush-job: CreateJobObject failed (5)\n"), /^Windows couldn't put it in a job object \(CreateJobObject failed \(5\)\), so it wasn't started/);
  // (through AppServer: a child that exits with JOB_REFUSED)
  const child = Object.assign(new EventEmitter(), { stdin: new PassThrough(), stdout: new PassThrough(), stderr: new PassThrough(), exitCode: null, signalCode: null, kill() {} });
  let said = null;
  const s = new AppServer(["codex", "app-server"], { onNotification: (_, m, p) => { if (m === "sagebrush/exited") said = p.message; }, onRequest: () => {}, spawnFn: () => child });
  child.stderr.write("sagebrush-job: AssignProcessToJobObject failed (5)\n");
  await new Promise((r) => setImmediate(r));
  child.emit("close", JOB_REFUSED, null);
  await s.exited;
  assert.match(said, /^Windows couldn't put it in a job object \(AssignProcessToJobObject failed \(5\)\), so it wasn't started/);
});

test("treeSpawn: plain spawn on POSIX (the process group rule as before), the job helper on Windows", { skip: process.platform === "win32" ? "POSIX half" : false }, async () => {
  const c = treeSpawn(process.execPath, ["-e", "process.stdout.write(String(process.pid))"], { stdio: ["ignore", "pipe", "ignore"] });
  let out = "";
  c.stdout.on("data", (d) => (out += d));
  await new Promise((r) => c.on("close", r));
  assert.equal(Number(out), c.pid, "the target itself, not a helper");
});

// (the real job, on Windows only)
const WIN = process.platform === "win32" ? {} : { skip: "a real job object: Windows only" };
const alive = (pid) => { try { process.kill(pid, 0); return true; } catch { return false; } };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const TREE = `const cp = require("child_process"); const g = cp.spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], { stdio: "ignore", detached: true }); g.unref(); process.stdout.write(JSON.stringify({ target: process.pid, grandchild: g.pid }) + "\\n"); if (process.argv[1] === "exit") setTimeout(() => process.exit(7), 300); else setInterval(() => {}, 1000);`;
async function started(mode) {
  const h = jobSpawn(process.execPath, ["-e", TREE, mode], { stdio: ["ignore", "pipe", "pipe"] });
  let out = "", err = "";
  h.stdout.on("data", (d) => (out += d));
  h.stderr.on("data", (d) => (err += d));
  for (let t = Date.now(); !out.includes("\n") && Date.now() - t < 30000; ) await sleep(50);
  assert.ok(out.includes("\n"), `the target's line, through the helper's stdout (stderr: ${err})`);
  return { h, ...JSON.parse(out.split("\n")[0]) };
}
test("on Windows: killing the helper ends the target and its detached grandchild", WIN, async () => {
  const t = await started("stay");
  assert.ok(alive(t.target) && alive(t.grandchild));
  t.h.kill();
  for (let i = 0; i < 40 && (alive(t.target) || alive(t.grandchild)); i++) await sleep(100);
  assert.ok(!alive(t.target) && !alive(t.grandchild), "both gone within 4 s");
});
test("on Windows: the target's exit code comes through, and its orphaned grandchild ends with the job", WIN, async () => {
  const t = await started("exit");
  const code = await new Promise((r) => t.h.on("close", r));
  assert.equal(code, 7);
  for (let i = 0; i < 40 && alive(t.grandchild); i++) await sleep(100);
  assert.ok(!alive(t.grandchild), "the orphan gone with the job");
});
