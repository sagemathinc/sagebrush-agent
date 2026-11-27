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

/**
 * Whether a process is gone, waiting up to `ms`: no such process, or a zombie (state Z in /proc/<pid>/stat: killed,
 * only not yet reaped by init, which can take a while on a loaded host).
 */
async function gone(pid, ms = 5000) {
  const t0 = Date.now();
  for (;;) {
    try { process.kill(pid, 0); } catch (e) { if (e.code === "ESRCH") return true; }
    try { if (/^\d+ \(.*\) Z /.test(readFileSync(`/proc/${pid}/stat`, "utf8"))) return true; } catch { return true; }
    if (Date.now() - t0 > ms) return false;
    await new Promise((r) => setTimeout(r, 50));
  }
}

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
  assert.deepEqual(seen.argv, ["--state", ctx.state, "--secrets", ctx.secrets, "--cache", ctx.cache, "--parent-pid", String(process.pid)]);
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
    const { ctx } = fake(`process.stderr.write("e".repeat(200000)); process.stdout.write('{"ok":true,"snapshots":[]}\\n');`);
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
  const gpid = Number(readFileSync(join(dir, "gpid"), "utf8"));
  const dead = await gone(gpid);
  if (!dead) { try { process.kill(gpid, "SIGKILL"); } catch {} }
  assert.ok(dead, "the grandchild is gone (or a zombie awaiting its reaper)");
});

test("a normal settlement kills the group too: a descendant left behind by a binary that succeeded or failed cleanly is gone", async () => {
  for (const [name, result, exit] of [["success", '{"ok":true,"forgotten":1}', 0], ["closed error", '{"ok":false,"error":{"code":"forget_failed","message":"m"}}', 1]]) {
    const { dir, ctx } = fake(`const { spawn } = require("node:child_process");
const g = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], { stdio: "ignore" });
fs.writeFileSync(dir + "/gpid", String(g.pid));
process.stdout.write(${JSON.stringify(result + "\n")});
process.exitCode = ${exit};
setImmediate(() => process.exit(${exit}));`);
    const r = await runBackupOp({ op: "forget", snapshots: [SNAP] }, ctx, { ms: 10000 });
    assert.equal(r.ok, exit === 0, name);
    if (exit !== 0) assert.equal(r.code, "forget_failed", name);
    const gpid = Number(readFileSync(join(dir, "gpid"), "utf8"));
    const dead = await gone(gpid);
    if (!dead) { try { process.kill(gpid, "SIGKILL"); } catch {} }
    assert.ok(dead, `${name}: the descendant is killed when the call settles (gone, or a zombie awaiting its reaper)`);
  }
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
  assert.deepEqual(parseResult('{"ok":true,"forgotten":2}\n', 0, null, "", "forget"), { ok: true, value: { forgotten: 2 }, stderr: "" });
  assert.equal(parseResult('{"ok":false,"error":{"code":"usage","message":"m"},"extra":1}\n', 1, null, "", "forget").code, "bad_result");
  assert.ok(CODES.includes("quota_exceeded") && CODES.includes("no_space") && CODES.includes("capability_refused"));
});

test("success is each op's exact shape, bound to the op asked: extra fields, an error beside ok, another op's shape are bad_result", () => {
  const snap = { id: SNAP, time: "2026-11-24T03:00:00Z", tree: "b".repeat(64), host: "h1", paths: ["/a"], tags: ["sb-state=good"], summary: null };
  const ok = (op, v) => parseResult(JSON.stringify({ ok: true, ...v }) + "\n", 0, null, "", op);
  assert.equal(ok("backup", { snapshot: snap, cache_full: false }).ok, true);
  assert.equal(ok("readback", { snapshot: snap, findings: 0 }).ok, true);
  assert.equal(ok("snapshots", { snapshots: [snap, { ...snap, summary: { files_new: 1, files_changed: 0, files_unmodified: 2, total_files_processed: 3, total_bytes_processed: 10, data_added_packed: 5 } }] }).ok, true);
  for (const [op, v] of [
    ["forget", { forgotten: 1, error: { code: "usage", message: "m" } }],
    ["forget", { forgotten: 1, unexpected: true }],
    ["snapshots", { forgotten: 1 }],
    ["forget", { snapshots: [] }],
    ["backup", { snapshot: { ...snap, id: "short" }, cache_full: false }],
    ["backup", { snapshot: { ...snap, extra: 1 }, cache_full: false }],
    ["backup", { snapshot: snap }],
    ["readback", { snapshot: snap, findings: -1 }],
    ["snapshots", { snapshots: [{ ...snap, summary: { files_new: 1 } }] }],
    ["init", { initialized: false }],
    ["prune", { stats: 5 }],
    ["restore", { snapshot: SNAP, skipped_special: 0 }],
  ]) assert.equal(ok(op, v).code, "bad_result", `${op} ${JSON.stringify(v).slice(0, 60)}`);
});

test("requests match the binary's own rules: host 1-64 of [A-Za-z0-9-], tags 1-128 with '=', at most 64 KiB serialized", () => {
  const b = (x) => ({ op: "backup", sources: ["/a"], host: "h1", ...x });
  for (const host of [" ".repeat(200), "", "a".repeat(65), "h_1", "h.1", "h 1"]) refused(() => checkRequest(b({ host })), "bad_form");
  checkRequest(b({ host: "a".repeat(64) })); checkRequest(b({ host: "Host-1" }));
  for (const tag of ["noequals", "a=b,c", "a b=c", "=" + "x".repeat(128), "a=b/c"]) refused(() => checkRequest(b({ tags: [tag] })), "bad_form");
  checkRequest(b({ tags: ["a=b=c", "sb-run=20261124T030000Z-abcdefgh", "x".repeat(126) + "=y"] }));
  refused(() => checkRequest({ op: "check-data", part: 1, of: 2 ** 33 }), "bad_form");
  const big = b({ excludes: Array.from({ length: 300 }, (_, i) => "x".repeat(250) + i) });
  refused(() => checkRequest(big), "bad_form"); // 300 globs is over 256 anyway; and the serialized size:
  const near = { op: "forget", snapshots: Array.from({ length: 1100 }, (_, i) => i.toString(16).padStart(64, "0")) };
  assert.ok(JSON.stringify(near).length > 64 * 1024);
  refused(() => checkRequest(near), "bad_form");
});

/** With SB_TEST_BACKUP_BIN set to a built binary, the real one answers through this client with a closed error. */
test("the real binary (when SB_TEST_BACKUP_BIN is set): a closed error through the client", { skip: !process.env.SB_TEST_BACKUP_BIN && "SB_TEST_BACKUP_BIN is not set" }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "sb-bbin-real-"));
  const ctx = { bin: process.env.SB_TEST_BACKUP_BIN, state: join(dir, "state"), secrets: join(dir, "secrets"), cache: join(dir, "cache") };
  const r = await runBackupOp({ op: "snapshots" }, ctx, { ms: 30000 });
  assert.equal(r.ok, false); assert.ok(CODES.includes(r.code), r.code);
});

test("usage: the request's and the result's closed shapes", () => {
  const S = "a".repeat(64);
  checkRequest({ op: "usage", snapshot: S });
  checkRequest({ op: "usage", snapshot: S, path: "srv/sagebrush/agents/x/home" });
  for (const r of [{ op: "usage" }, { op: "usage", snapshot: "latest" }, { op: "usage", snapshot: S, path: "/abs" }, { op: "usage", snapshot: S, path: "a/../b" },
    { op: "usage", snapshot: S, path: "" }, { op: "usage", snapshot: S, exact: true }]) refused(() => checkRequest(r), "bad_form");
  const ok = (v) => parseResult(JSON.stringify({ ok: true, ...v }) + "\n", 0, null, "", "usage");
  const good = { snapshot: S, entries: 306, inodes: 305, blocks_upper: 262_903, peak_inodes: 308, peak_blocks_upper: 262_920, block_size: 4096 };
  assert.deepEqual(ok(good), { ok: true, value: good, stderr: "" });
  for (const bad of [{ ...good, inodes: 307 }, { ...good, peak_inodes: 304 }, { ...good, peak_blocks_upper: 262_902 }, { ...good, block_size: 1024 }, { ...good, entries: -1 }, { ...good, blocks_upper: 1.5 }, { ...good, extra: 1 }, { ...good, snapshot: "x" }]) {
    assert.equal(ok(bad).code, "bad_result", JSON.stringify(bad));
  }
  assert.ok(CODES.includes("usage_failed"));
});

test("the console command's signals (init/run d3 §5.2): the first aborts the call in flight and kills its group; a second is ignored; later calls answer aborted unstarted", async () => {
  const { EventEmitter } = await import("node:events");
  const { installCommandSignals } = await import("../lib/fleet/host/backup-binary.mjs");
  const { mkdtempSync, writeFileSync, chmodSync, readFileSync, existsSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const d = mkdtempSync(join(tmpdir(), "sb-sig-"));
  const bin = join(d, "bin");
  // A binary that records its pid, then a grandchild in its own group (as the real one may fork), and waits.
  writeFileSync(bin, `#!/bin/sh\necho $$ > ${d}/pid\nsleep 60 &\necho $! > ${d}/child\nwait\n`);
  chmodSync(bin, 0o755);
  const ctx = { bin, state: d, secrets: d, cache: d };
  const proc = new EventEmitter();
  const controller = new AbortController();
  const remove = installCommandSignals(controller, proc);
  try {
    assert.equal(proc.listenerCount("SIGTERM"), 1, "installed before any spawn");
    const p = runBackupOp({ op: "snapshots" }, ctx, { ms: 30_000 });
    const until = Date.now() + 5000;
    while (!existsSync(join(d, "child")) && Date.now() < until) await new Promise((r) => { setTimeout(r, 20); });
    const pids = ["pid", "child"].map((f) => Number(readFileSync(join(d, f), "utf8")));
    proc.emit("SIGINT");
    proc.emit("SIGTERM"); // (a second signal: ignored, no exit)
    const r = await p;
    assert.deepEqual([r.ok, r.code], [false, "aborted"]);
    // Gone or a zombie (a killed grandchild waits for init to reap it), within a short bound.
    const exited = (pid) => { try { return /\) [ZX] /.test(readFileSync(`/proc/${pid}/stat`, "utf8")); } catch { return true; } };
    for (const pid of pids) {
      const t0 = Date.now();
      while (!exited(pid) && Date.now() - t0 < 3000) await new Promise((r) => { setTimeout(r, 20); });
      assert.equal(exited(pid), true, `pid ${pid} gone with its group`);
    }
    // Every later call answers aborted without starting a process.
    const later = await runBackupOp({ op: "snapshots" }, { ...ctx, bin: join(d, "never-run") }, { ms: 30_000 });
    assert.deepEqual([later.ok, later.code], [false, "aborted"]);
  } finally { remove(); }
  assert.equal(proc.listenerCount("SIGTERM"), 0);
});
