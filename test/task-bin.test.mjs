// The agent program's Delegate wiring: with the fake model it keeps its tasks only in the folder
// SAGEBRUSH_TASKS_HOME names (else Delegate is off), and never makes ~/.sagebrush in the home it runs with.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import WebSocket from "ws";
import { DEFAULT_ORIGINS } from "../lib/server.mjs";

const BIN = fileURLToPath(new URL("../bin/sagebrush-agent.mjs", import.meta.url));
const ORIGIN = DEFAULT_ORIGINS[0];

// Start the program on the loopback, pair a page with the printed code, and answer the hello's features and stderr.
async function pairOnce(env) {
  const p = spawn(process.execPath, [BIN], { env: { ...process.env, SAGEBRUSH_AGENT_FAKE: "1", ...env }, stdio: ["ignore", "pipe", "pipe"] });
  let out = "", err = "";
  p.stderr.on("data", (d) => { err += d; });
  try {
    const { code, port } = await new Promise((resolve, reject) => {
      const t = setTimeout(() => reject(new Error(`no link printed; stderr: ${err.slice(-400)}`)), 10000);
      p.stdout.on("data", (d) => {
        out += d;
        const m = /\?pair=([^&\s]+)&port=(\d+)/.exec(out);
        if (m) { clearTimeout(t); resolve({ code: m[1], port: Number(m[2]) }); }
      });
      p.on("exit", () => reject(new Error(`exited; stderr: ${err.slice(-400)}`)));
    });
    const ws = new WebSocket(`ws://127.0.0.1:${port}/sagebrush`, { origin: ORIGIN });
    await new Promise((resolve, reject) => { ws.on("open", resolve); ws.on("error", reject); });
    const hello = await new Promise((resolve) => {
      ws.on("message", (d) => { const m = JSON.parse(d.toString()); if (m.id === "p1") resolve(m); });
      ws.send(JSON.stringify({ jsonrpc: "2.0", id: "p1", method: "hello", params: { protocol: 1, page: { origin: ORIGIN, path: "/agents/" }, code: code.toLowerCase() } }));
    });
    ws.close();
    return { features: hello.result?.features, err };
  } finally {
    p.kill("SIGTERM");
    await new Promise((r) => (p.exitCode !== null || p.signalCode !== null ? r() : p.on("exit", r)));
  }
}

test("fake model: Delegate on only in SAGEBRUSH_TASKS_HOME (private store made there), off without it; the home is never touched", async () => {
  const base = mkdtempSync(join(tmpdir(), "sb-taskbin-"));
  try {
    const home = join(base, "home"), tasks = join(base, "tasks");
    const on = await pairOnce({ HOME: home, SAGEBRUSH_TASKS_HOME: tasks });
    assert.ok(on.features.includes("delegate.1"), on.err);
    assert.match(statSync(join(tasks, ".sagebrush", "installation")).mode.toString(8), /600$/);
    assert.ok(statSync(join(tasks, ".sagebrush", "tasks")).isDirectory());
    const off = await pairOnce({ HOME: home, SAGEBRUSH_TASKS_HOME: "" });
    assert.ok(!off.features.includes("delegate.1"));
    assert.doesNotMatch(off.err, /Delegate tasks are off/);
    assert.equal(existsSync(join(home, ".sagebrush")), false);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});
