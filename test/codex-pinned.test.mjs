// The backend runs the pinned Codex `locate` hands it (lib/codex-fetch.mjs's ensureCodex in the agent), by its
// absolute path, for the app-server and for the self-test alike, never `codex` from PATH; the progress line goes to
// the turn that asked; a fetch refusal is one line and nothing is started. In-process, with the fake app-server
// behind a stand-in for the pinned executable.
import { test } from "node:test";
const T = { timeout: 20000 }; // (a row that hangs fails by name)
import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough, Writable } from "node:stream";
import { fileURLToPath } from "node:url";
import { AgentServer } from "../lib/server.mjs";
import { CodexBackend, CODEX_TEXT } from "../lib/codex.mjs";
import { CodexFetchError } from "../lib/codex-fetch.mjs";
import { fakeCreateServer } from "../lib/fake.mjs";

const F = 64 * 1024;
const FAKE = fileURLToPath(new URL("../lib/fake-codex.mjs", import.meta.url));
const SCHEMA = fileURLToPath(new URL("./fixtures/codex-schema-0.163.0.json", import.meta.url));

function harness(locate) {
  const scratch = mkdtempSync(join(tmpdir(), "pinned-"));
  // (the "pinned" Codex: an executable that runs the fake app-server; and a `codex` first on PATH that must never run)
  const pinned = join(scratch, "pinned-codex");
  writeFileSync(pinned, `#!/bin/sh\nexec "${process.execPath}" "${FAKE}" "$@"\n`);
  chmodSync(pinned, 0o755);
  const pathDir = join(scratch, "path");
  const marker = join(scratch, "PATH-CODEX-RAN");
  mkdirSync(pathDir);
  writeFileSync(join(pathDir, "codex"), `#!/bin/sh\necho ran > "${marker}"\nexit 1\n`);
  chmodSync(join(pathDir, "codex"), 0o755);
  const record = join(scratch, "record.jsonl");
  const env = { ...process.env, PATH: `${pathDir}:${process.env.PATH}`, FAKE_CODEX_SCHEMA: SCHEMA, FAKE_CODEX_RECORD: record };
  const server = new AgentServer({ log: () => {}, stdio: true, runnerCwd: scratch, name: "Codex", client: "codex-app-server" });
  server.createServer = fakeCreateServer;
  const located = [];
  server.backend = new CodexBackend(server, { env, locate: async (opts) => { located.push(opts); return locate(pinned, opts); } });
  const input = new PassThrough();
  const lines = [];
  let buf = "";
  const output = new Writable({ write(chunk, _e, cb) { buf += chunk.toString("utf8"); let nl; while ((nl = buf.indexOf("\n")) >= 0) { lines.push(JSON.parse(buf.slice(0, nl))); buf = buf.slice(nl + 1); } cb(); } });
  server.serveStdio({ input, output, fatal: () => {} });
  const send = (o) => input.write(Buffer.from(JSON.stringify(o) + "\n"));
  send({ relay: { start: { frame: F, protocol: 1, epoch: 0 } } });
  send({ jsonrpc: "2.0", method: "grant.changed", params: { folders: ["/"], write: true, native: true } });
  let n = 0;
  const events = () => lines.filter((m) => m.method === "turn.event").map((m) => m.params.event);
  const rec = () => { if (!existsSync(record)) return []; const t = readFileSync(record, "utf8"); return t.slice(0, t.lastIndexOf("\n") + 1).split("\n").filter(Boolean).map((l) => JSON.parse(l)); };
  return {
    pinned, marker, located, events, rec,
    say: (text) => send({ jsonrpc: "2.0", method: "chat.message", params: { conversation: "c1", id: `m${n++}`, text, author: "person" } }),
    finished: () => events().filter((e) => e.type === "turn_finished"),
    until: async (f, what) => { const t = Date.now(); while (!f()) { if (Date.now() - t > 15000) throw new Error("timed out: " + what); await new Promise((r) => setTimeout(r, 10)); } },
    close: async () => { input.end(); await server.close().catch(() => {}); rmSync(scratch, { recursive: true, force: true }); },
  };
}

test("the pinned Codex runs by its absolute path, for the self-test and the app-server; the `codex` on PATH never runs", T, async () => {
  const h = harness((bin) => ({ bin, dir: "/x", version: "0.159.2" }));
  try {
    h.say("hello");
    await h.until(() => h.finished().length, "the turn");
    assert.equal(h.finished()[0].outcome, "completed");
    assert.ok(!existsSync(h.marker), "PATH's codex never ran");
    assert.ok(h.rec().some((m) => m.argv?.includes("generate-json-schema")), "the self-test asked the pinned one");
    assert.equal(h.rec().filter((m) => m.method === "initialize").length, 1);
  } finally { await h.close(); }
});

test("the first download's progress: one line to the turn that asked, then the turn goes on", T, async () => {
  const h = harness((bin, { onProgress }) => { onProgress(16e6, 162475310); onProgress(32e6, 162475310); return { bin, dir: "/x", version: "0.159.2" }; });
  try {
    h.say("hello");
    await h.until(() => h.finished().length, "the turn");
    const lines = h.events().filter((e) => e.type === "thinking_delta" && e.text === CODEX_TEXT.getting(162));
    assert.equal(lines.length, 1, "said once");
    assert.equal(h.finished()[0].outcome, "completed");
  } finally { await h.close(); }
});

test("each fetch refusal is one line in the turn; nothing is started; the next message tries again", T, async () => {
  for (const [code, message] of [
    ["codex_download", CODEX_TEXT.download("HTTP 404")],
    ["codex_archive", CODEX_TEXT.mismatch],
    ["codex_cache", CODEX_TEXT.cache],
    ["codex_platform", CODEX_TEXT.platform],
  ]) {
    let calls = 0;
    const h = harness(() => { calls++; throw new CodexFetchError(code, code === "codex_download" ? "HTTP 404" : "secret /home/x path and details"); });
    try {
      h.say("hello");
      await h.until(() => h.finished().length, "the refused turn");
      const err = h.events().find((e) => e.type === "turn_error");
      assert.deepEqual(err, { type: "turn_error", code, message });
      assert.ok(!err.message.includes("secret"), "only the fixed words");
      assert.equal(h.rec().length, 0, "nothing started");
      h.say("again");
      await h.until(() => h.finished().length === 2, "the second turn");
      assert.equal(calls, 2);
    } finally { await h.close(); }
  }
});

test("the agent closing aborts a download under way (the signal locate gets)", T, async () => {
  let seen = null;
  const h = harness((bin, { signal }) => new Promise((_, reject) => { seen = signal; signal.addEventListener("abort", () => reject(new CodexFetchError("codex_download", "stopped"))); }));
  h.say("hello");
  await h.until(() => seen, "locate called");
  assert.equal(seen.aborted, false);
  await h.close();
  assert.equal(seen.aborted, true);
});
