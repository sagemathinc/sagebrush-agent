// The backend runs the pinned Codex `locate` hands it (lib/codex-fetch.mjs's ensureCodex in the agent), by its
// absolute path, for the app-server and for the self-test alike, never `codex` from PATH; the progress line goes to
// the turn that asked; a fetch refusal is one line and nothing is started. In-process, with the fake app-server
// behind a stand-in for the pinned executable.
import { test } from "node:test";
const T = { timeout: 20000 }; // (a row that hangs fails by name)
import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
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

function harness(locate, { generate = null, fakeEnv = {} } = {}) {
  const scratch = mkdtempSync(join(tmpdir(), "pinned-"));
  // (the "pinned" Codex: an executable that runs the fake app-server; and a `codex` first on PATH that must never run)
  const pinned = join(scratch, "pinned-codex");
  // (with `generate`: the schema probe runs that shell body instead, with $PIDFILE and $MARK)
  writeFileSync(pinned, generate
    ? `#!/bin/sh\ncase "$*" in *generate-json-schema*) PIDFILE="${join(scratch, "probe.pid")}"; MARK="${join(scratch, "probe-child-alive")}"; ${generate} ;; esac\nexec "${process.execPath}" "${FAKE}" "$@"\n`
    : `#!/bin/sh\nexec "${process.execPath}" "${FAKE}" "$@"\n`);
  chmodSync(pinned, 0o755);
  const pathDir = join(scratch, "path");
  const marker = join(scratch, "PATH-CODEX-RAN");
  mkdirSync(pathDir);
  writeFileSync(join(pathDir, "codex"), `#!/bin/sh\necho ran > "${marker}"\nexit 1\n`);
  chmodSync(join(pathDir, "codex"), 0o755);
  const record = join(scratch, "record.jsonl");
  const env = { ...process.env, PATH: `${pathDir}:${process.env.PATH}`, FAKE_CODEX_SCHEMA: SCHEMA, FAKE_CODEX_RECORD: record, TMPDIR: scratch, ...fakeEnv };
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
    say: (text, conversation = "c1") => send({ jsonrpc: "2.0", method: "chat.message", params: { conversation, id: `m${n++}`, text, author: "person" } }),
    stop: (conversation = "c1") => send({ jsonrpc: "2.0", method: "chat.interrupt", params: { conversation } }),
    finished: () => events().filter((e) => e.type === "turn_finished"),
    scratch, server,
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

// ---- cancelling a start: Stop and shutdown end the download, the app-server and the self-test's probe

const alive = (pid) => { try { process.kill(pid, 0); return true; } catch { return false; } };
const within = async (f, ms, what) => { const t = Date.now(); while (!f()) { if (Date.now() - t > ms) throw new Error(`not within ${ms} ms: ${what}`); await new Promise((r) => setTimeout(r, 10)); } };

test("closing the agent during the schema probe: its process group is gone (by pid) within 2 s, nothing after initialize is sent", T, async () => {
  const h = harness((bin) => ({ bin, dir: "/x", version: "0.159.2" }), { generate: `echo $$ > "$PIDFILE"; (sleep 3; echo alive > "$MARK") & sleep 30; exit 0` });
  h.say("hello");
  const pidFile = join(h.scratch, "probe.pid");
  await within(() => existsSync(pidFile) && readFileSync(pidFile, "utf8").trim(), 10000, "the probe started");
  const pid = Number(readFileSync(pidFile, "utf8"));
  assert.ok(alive(pid));
  const appPid = h.rec().find((m) => m.pid)?.pid;
  const t = Date.now();
  await h.server.close();
  await within(() => !alive(pid), 2000, "the probe ended");
  assert.ok(Date.now() - t < 5000);
  assert.ok(!appPid || !alive(appPid), "the app-server ended");
  await new Promise((r) => setTimeout(r, 3300));
  assert.ok(!existsSync(join(h.scratch, "probe-child-alive")), "nothing the probe started outlived it");
  for (const m of ["initialized", "account/read", "thread/start", "turn/start"]) assert.ok(!h.rec().some((x) => x.method === m), `${m} never sent`);
  assert.deepEqual(readdirSync(h.scratch).filter((n) => n.startsWith("sagebrush-codex-schema-")), [], "the probe's temp dir removed");
  rmSync(h.scratch, { recursive: true, force: true });
});

test("a Stop during the download cancels it (locate's signal, within 2 s of the Stop); the turn ends interrupted", T, async () => {
  let sig = null;
  const h = harness((bin, { signal }) => new Promise((_, rej) => { sig = signal; signal.addEventListener("abort", () => rej(new CodexFetchError("codex_download", "stopped"))); }));
  try {
    h.say("hello");
    await within(() => sig, 5000, "the download started");
    const t = Date.now();
    h.stop();
    await within(() => sig.aborted, 2000, "the download cancelled");
    await within(() => h.finished().length, 5000, "the turn ended");
    assert.equal(h.finished()[0].outcome, "interrupted");
    assert.ok(Date.now() - t < 5000);
    assert.equal(h.rec().length, 0, "nothing started");
  } finally { await h.close(); }
});

test("a Stop while initialize goes unanswered: the app-server is ended (by pid) and nothing more is sent", T, async () => {
  const h = harness((bin) => ({ bin, dir: "/x", version: "0.159.2" }), { fakeEnv: { FAKE_CODEX_HOLD_INIT: "1" } });
  try {
    h.say("hello");
    await within(() => h.rec().some((m) => m.method === "initialize"), 10000, "initialize sent");
    const pid = h.rec().find((m) => m.pid).pid;
    h.stop();
    await within(() => !alive(pid), 5000, "the app-server ended");
    await within(() => h.finished().length, 5000, "the turn ended");
    assert.equal(h.finished()[0].outcome, "interrupted");
    for (const m of ["initialized", "thread/start", "turn/start"]) assert.ok(!h.rec().some((x) => x.method === m), `${m} never sent`);
    assert.ok(!h.rec().some((x) => x.argv), "no probe after a cancelled start");
  } finally { await h.close(); }
});

test("two turns share a start: the first Stop doesn't cancel it, the last one does", T, async () => {
  let sig = null;
  const h = harness((bin, { signal }) => new Promise((_, rej) => { sig = signal; signal.addEventListener("abort", () => rej(new CodexFetchError("codex_download", "stopped"))); }));
  try {
    h.say("one", "c1");
    h.say("two", "c2");
    await within(() => sig, 5000, "the download started");
    h.stop("c1");
    await within(() => h.events().filter((e) => e.type === "turn_finished").length >= 1, 5000, "c1 ended");
    await new Promise((r) => setTimeout(r, 100));
    assert.equal(sig.aborted, false, "still wanted by c2");
    h.stop("c2");
    await within(() => sig.aborted, 2000, "cancelled with the last waiter");
  } finally { await h.close(); }
});
