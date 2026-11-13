// Against a real Codex binary, when one is given (SAGEBRUSH_TEST_CODEX_BINS="<version>=<path>,..."; skipped
// otherwise): the start the agent makes (initialize, with whatever Codex sends before answering it, then the self-test
// on that Codex's own protocol) goes through, with no model call: an empty CODEX_HOME, so it stops at the login check,
// the step after them. Codex 0.163.0 sends configWarning and remoteControl notifications before initialize's answer.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough, Writable } from "node:stream";
import { AgentServer } from "../lib/server.mjs";
import { CodexBackend, CODEX_TEXT } from "../lib/codex.mjs";
import { fakeCreateServer } from "../lib/fake.mjs";

const bins = (process.env.SAGEBRUSH_TEST_CODEX_BINS ?? "").split(",").filter(Boolean).map((x) => x.split("="));

for (const [version, bin] of bins.length ? bins : [["(none given)", null]]) {
  test(`real Codex ${version}: initialize and the self-test pass; the start stops at the login, nothing else sent`, { skip: !bin, timeout: 60000 }, async () => {
    const scratch = mkdtempSync(join(tmpdir(), "real-codex-"));
    const home = mkdtempSync(join(tmpdir(), "codex-home-"));
    const server = new AgentServer({ log: () => {}, stdio: true, runnerCwd: scratch, name: "Codex", client: "codex-app-server" });
    server.createServer = fakeCreateServer;
    const sent = [];
    server.backend = new CodexBackend(server, { command: [bin, "app-server"], version, env: { ...process.env, CODEX_HOME: home } });
    const input = new PassThrough();
    const lines = [];
    let buf = "";
    server.serveStdio({ input, output: new Writable({ write(c, _e, cb) { buf += c.toString("utf8"); let nl; while ((nl = buf.indexOf("\n")) >= 0) { lines.push(JSON.parse(buf.slice(0, nl))); buf = buf.slice(nl + 1); } cb(); } }), fatal: () => {} });
    const send = (o) => input.write(Buffer.from(JSON.stringify(o) + "\n"));
    send({ relay: { start: { frame: 64 * 1024, protocol: 1, epoch: 0 } } });
    send({ jsonrpc: "2.0", method: "grant.changed", params: { folders: ["/"], write: true, native: true } });
    send({ jsonrpc: "2.0", method: "chat.message", params: { conversation: "c1", id: "m1", text: "hello", author: "person" } });
    const events = () => lines.filter((m) => m.method === "turn.event").map((m) => m.params.event);
    try {
      const t = Date.now();
      while (!events().some((e) => e.type === "turn_finished")) { if (Date.now() - t > 45000) throw new Error("no end"); await new Promise((r) => setTimeout(r, 20)); }
      const err = events().find((e) => e.type === "turn_error");
      assert.deepEqual(err, { type: "turn_error", code: "unauthorized", message: CODEX_TEXT.notLoggedIn }, "the step after initialize and the self-test");
    } finally {
      input.end();
      await server.close().catch(() => {});
      rmSync(scratch, { recursive: true, force: true });
      rmSync(home, { recursive: true, force: true });
    }
  });
}
