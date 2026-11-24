// Host backup r3.3 §1, §6: the client of the backup binary, against fake binaries (small executable scripts): closed
// requests only, an empty environment, exactly one JSON result agreeing with the exit status, bounded output, a
// deadline, and the whole process group killed when the call settles.
import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "./host-linux-only.mjs";
import { FleetError } from "../lib/fleet/index.mjs";
import { CODES, checkRequest, parseResult, runBackupOp } from "../lib/fleet/host/backup-binary.mjs";

const refused = (fn, code) => assert.throws(fn, (e) => e instanceof FleetError && e.code === code, code);
const SNAP = "a".repeat(64);

/** A fake binary: `body` is the JavaScript it runs; it sees the request on stdin. Returns { ctx, dir }. */
function fake(body) {
  const dir = mkdtempSync(join(tmpdir(), "sb-bbin-"));
  const bin = join(dir, "sagebrush-agent-backup");
  writeFileSync(bin, `#!${process.execPath}\nconst fs = require("node:fs");\nconst dir = ${JSON.stringify(dir)};\nconst input = fs.readFileSync(0, "utf8");\n${body}\n`);
  chmodSync(bin, 0o755);
  return { dir, ctx: { bin, state: join(dir, "state"), secrets: join(dir, "secrets"), cache: join(dir, "cache") } };
}

test("a success: the request arrives on stdin exactly, argv names the three directories, the environment is empty", async () => {
  const { dir, ctx } = fake(`fs.writeFileSync(dir + "/seen.json", JSON.stringify({ input, argv: process.argv.slice(2), env: process.env }));
process.stdout.write(JSON.stringify({ ok: true, snapshots: [] }) + "\\n");`);
  const r = await runBackupOp({ op: "snapshots" }, ctx, { ms: 10000 });
  assert.deepEqual(r, { ok: true, value: { snapshots: [] }, stderr: "" });
  const seen = JSON.parse(readFileSync(join(dir, "seen.json"), "utf8"));
  assert.equal(seen.input, JSON.stringify({ op: "snapshots" }));
  assert.deepEqual(seen.argv, ["--state", ctx.state, "--secrets", ctx.secrets, "--cache", ctx.cache]);
  assert.deepEqual(Object.keys(seen.env).filter((k) => !k.startsWith("NODE_") && k !== "PWD" && k !== "SHLVL" && k !== "_"), []);
});

test("the binary's own error, with a code it can give, is kept; quota and full-disk codes come through as themselves", async () => {
  for (const code of ["quota_exceeded", "no_space", "repository_missing"]) {
    const { ctx } = fake(`process.stdout.write(JSON.stringify({ ok: false, error: { code: ${JSON.stringify(code)}, message: "m" } }) + "\\n"); process.exitCode = 1;`);
    assert.deepEqual(await runBackupOp({ op: "prune" }, ctx, { ms: 10000 }), { ok: false, code, message: "m", stderr: "" });
  }
});

test("anything but one closed JSON result agreeing with the exit status is bad_result", async () => {
  const cases = {
    "two lines": `process.stdout.write('{"ok":true}\\n{"ok":true}\\n');`,
    "garbage": `process.stdout.write("hello\\n");`,
    "nothing": ``,
    "ok with exit 1": `process.stdout.write('{"ok":true}\\n'); process.exitCode = 1;`,
    "error with exit 0": `process.stdout.write('{"ok":false,"error":{"code":"usage","message":"m"}}\\n');`,
    "an unknown code": `process.stdout.write('{"ok":false,"error":{"code":"made_up","message":"m"}}\\n'); process.exitCode = 1;`,
    "an extra field in the error": `process.stdout.write('{"ok":false,"error":{"code":"usage","message":"m","x":1}}\\n'); process.exitCode = 1;`,
    "an array": `process.stdout.write('[1]\\n');`,
    "a crash by signal": `process.kill(process.pid, "SIGSEGV");`,
  };
  for (const [name, body] of Object.entries(cases)) {
    const { ctx } = fake(body);
    const r = await runBackupOp({ op: "snapshots" }, ctx, { ms: 10000 });
    assert.equal(r.ok, false, name); assert.equal(r.code, "bad_result", name);
  }
});

test("stdout past its limit is bad_result and the binary is killed; stderr keeps only its first 64 KiB", async () => {
  {
    const { ctx } = fake(`process.stdout.write("x".repeat(5000)); setTimeout(() => {}, 60000);`);
    const t0 = Date.now();
    const r = await runBackupOp({ op: "snapshots" }, ctx, { ms: 30000, outMax: 1000 });
    assert.equal(r.code, "bad_result"); assert.ok(Date.now() - t0 < 10000, "killed, not waited out");
  }
  {
    const { ctx } = fake(`process.stderr.write("e".repeat(200000)); process.stdout.write('{"ok":true}\\n');`);
    const r = await runBackupOp({ op: "snapshots" }, ctx, { ms: 10000 });
    assert.equal(r.ok, true); assert.equal(r.stderr.length, 64 * 1024);
  }
});

test("a deadline kills the whole process group, a grandchild included", async () => {
  const { dir, ctx } = fake(`const { spawn } = require("node:child_process");
const g = spawn(process.execPath, ["-e", "setInterval(() => require('fs').writeFileSync(" + JSON.stringify(dir + "/alive") + ", String(Date.now())), 50)"], { stdio: "ignore" });
fs.writeFileSync(dir + "/gpid", String(g.pid));
setTimeout(() => {}, 60000);`);
  const r = await runBackupOp({ op: "snapshots" }, ctx, { ms: 600 });
  assert.equal(r.code, "timed_out");
  await new Promise((res) => setTimeout(res, 300));
  const gpid = Number(readFileSync(join(dir, "gpid"), "utf8"));
  assert.throws(() => process.kill(gpid, 0), (e) => e.code === "ESRCH", "the grandchild is gone");
});

test("an abort kills it; an abort before the start never spawns", async () => {
  const { dir, ctx } = fake(`fs.writeFileSync(dir + "/ran", "1"); setTimeout(() => {}, 60000);`);
  const ac = new AbortController();
  const p = runBackupOp({ op: "snapshots" }, ctx, { ms: 30000, signal: ac.signal });
  setTimeout(() => ac.abort(), 300);
  assert.equal((await p).code, "aborted");
  const pre = fake(`fs.writeFileSync(dir + "/ran", "1");`);
  const ac2 = new AbortController(); ac2.abort();
  assert.equal((await runBackupOp({ op: "snapshots" }, pre.ctx, { ms: 30000, signal: ac2.signal })).code, "aborted");
  assert.equal(existsSync(join(pre.dir, "ran")), false);
});

test("a binary that can't be started is spawn_failed", async () => {
  const { ctx } = fake(``);
  const r = await runBackupOp({ op: "snapshots" }, { ...ctx, bin: "/nonexistent/sagebrush-agent-backup" }, { ms: 5000 });
  assert.equal(r.code, "spawn_failed");
});

test("closed requests: each op's exact fields; restore is never one; refused before any process starts", () => {
  const ok = [
    { op: "init" }, { op: "snapshots" }, { op: "prune" },
    { op: "backup", sources: ["/srv/sagebrush/agents/x/home"], host: "h1" },
    { op: "backup", sources: ["/a"], host: "h1", tags: ["sb-state=warm", "sb-run=r1"], parent: SNAP, excludes: ["*.tmp"] },
    { op: "backup", sources: ["/a"], host: "h1", parent: null },
    { op: "readback", snapshot: SNAP }, { op: "check-data", part: 3, of: 30 },
    { op: "dump", snapshot: SNAP, path: "manifest.json" }, { op: "forget", snapshots: [SNAP] },
    { op: "add-key", password_file: "/run/sagebrush/pw" },
  ];
  for (const r of ok) assert.equal(checkRequest(r), r, JSON.stringify(r));
  const bad = [
    null, [], {}, { op: "restore", snapshot: SNAP, dest: "/d" }, { op: "auto-init" }, { op: "init", force: true },
    { op: "backup", sources: [], host: "h" }, { op: "backup", sources: ["rel"], host: "h" }, { op: "backup", sources: ["/a/../b"], host: "h" },
    { op: "backup", sources: ["/a"], host: "" }, { op: "backup", sources: ["/a"], host: "h", tags: ["a,b=c"] },
    { op: "backup", sources: ["/a"], host: "h", parent: "abc" }, { op: "backup", sources: ["/a"], host: "h", ignore_ctime: true },
    { op: "readback", snapshot: "ABC" }, { op: "check-data", part: 0, of: 30 }, { op: "check-data", part: 31, of: 30 },
    { op: "dump", snapshot: SNAP, path: "/abs" }, { op: "dump", snapshot: SNAP, path: "a/../b" },
    { op: "forget", snapshots: [] }, { op: "forget", snapshots: [SNAP, SNAP] }, { op: "prune", instant: true },
    { op: "add-key", password_file: "rel" },
  ];
  for (const r of bad) refused(() => checkRequest(r), "bad_form");
  refused(() => runBackupOp({ op: "restore", snapshot: SNAP, dest: "/d" }, { bin: "/b", state: "/s", secrets: "/x", cache: "/c" }, { ms: 1 }), "bad_form");
  refused(() => runBackupOp({ op: "init" }, { bin: "rel", state: "/s", secrets: "/x", cache: "/c" }, { ms: 1 }), "bad_form");
  refused(() => runBackupOp({ op: "init" }, { bin: "/b", state: "/s", secrets: "/x", cache: "/c" }, {}), "bad_form");
});

test("parseResult on its own: closed errors only, and the codes list matches the binary's", () => {
  assert.deepEqual(parseResult('{"ok":true,"forgotten":2}\n', 0, null), { ok: true, value: { forgotten: 2 }, stderr: "" });
  assert.equal(parseResult('{"ok":false,"error":{"code":"usage","message":"m"},"extra":1}\n', 1, null).code, "bad_result");
  assert.ok(CODES.includes("quota_exceeded") && CODES.includes("no_space") && CODES.includes("capability_refused"));
});

/** With SB_TEST_BACKUP_BIN set to a built binary, the real one answers through this client with a closed error. */
test("the real binary (when SB_TEST_BACKUP_BIN is set): a closed error through the client", { skip: !process.env.SB_TEST_BACKUP_BIN && "SB_TEST_BACKUP_BIN is not set" }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "sb-bbin-real-"));
  const ctx = { bin: process.env.SB_TEST_BACKUP_BIN, state: join(dir, "state"), secrets: join(dir, "secrets"), cache: join(dir, "cache") };
  const r = await runBackupOp({ op: "snapshots" }, ctx, { ms: 30000 });
  assert.equal(r.ok, false); assert.ok(CODES.includes(r.code), r.code);
});
