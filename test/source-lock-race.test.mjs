// The source cache's lock with real processes (#1663, SEC/TESTS H4): an OS file lock (SQLite BEGIN EXCLUSIVE), so
// while one process holds it no other gets in, a holder that dies (SIGKILL, in the middle) gives it back by itself,
// and no lock path is ever removed by anyone: nothing to take over, nothing to remove by mistake.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const CHILD = fileURLToPath(new URL("./fixtures/source-lock-child.mjs", import.meta.url));

async function race(end) {
  const dir = mkdtempSync(join(tmpdir(), "sb-src-lock-"));
  mkdirSync(join(dir, "cache"), { mode: 0o700 });
  const kids = {};
  const at = (n) => existsSync(join(dir, n));
  const wait = async (n, ms = 15_000) => { const t0 = Date.now(); while (!at(n)) { assert.ok(Date.now() - t0 < ms, `deadline: ${n}`); await new Promise((r) => setTimeout(r, 10)); } };
  try {
    kids.A = spawn(process.execPath, ["--no-warnings", CHILD, dir, "A"], { stdio: "inherit" });
    await wait("A-held");
    kids.B = spawn(process.execPath, ["--no-warnings", CHILD, dir, "B"], { stdio: "inherit" });
    await wait("B-trying");
    await new Promise((r) => setTimeout(r, 800));
    assert.ok(!at("B-held"), "B got in while A held the lock");
    await end(kids.A, (n) => writeFileSync(join(dir, n), ""), wait);
    await wait("B-held");
    assert.ok(!at("A-leaving") || at("A-done"), "A had left before B got in");
    writeFileSync(join(dir, "B-end"), "");
    await wait("B-done");
    assert.deepEqual(readdirSync(join(dir, "cache")).filter((n) => !n.startsWith(".lock.sqlite")), [], "nothing but the lock file itself");
  } finally {
    for (const k of Object.values(kids)) k.kill("SIGKILL");
    rmSync(dir, { recursive: true, force: true });
  }
}

const NO_SQLITE = await import("node:sqlite").then((m) => typeof m.DatabaseSync !== "function", () => true) && "needs node:sqlite (Node 22.13 or later)";

test("source cache lock: one holder at a time across processes; a normal release lets the next in", { skip: NO_SQLITE }, async () => {
  await race(async (_a, touch, wait) => { touch("A-end"); await wait("A-done"); });
});

test("source cache lock: a holder killed in the middle gives the lock back by itself (no takeover, nothing removed)", { skip: NO_SQLITE }, async () => {
  await race(async (a) => { a.kill("SIGKILL"); await new Promise((r) => a.once("exit", r)); });
});
