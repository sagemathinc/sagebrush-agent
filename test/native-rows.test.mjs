// Native mode, in-process (an --stdio AgentServer on the fake model, its resolver and deleteSession held by the row):
// a retired native session's transcript is deleted where it ran, before the agent stops; the native system prompt is
// Claude Code's own with the Sagebrush part appended; an unknown permission mode runs as the default; and a native
// card's summary is the notebook's path or the search's pattern. (Their turns are "options?", which ends at once.)
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough, Writable } from "node:stream";
import { AgentServer, SYSTEM_NATIVE, nativeMode } from "../lib/server.mjs";
import { fakeCreateServer, fakeQuery } from "../lib/fake.mjs";

const F = 64 * 1024;
const RESOLVER = { resolveSettings: async () => ({ effective: {}, sources: [] }), filterEscalatingDefaultMode: (r) => r.effective };

function inproc({ deleteSession, query = fakeQuery } = {}) {
  const scratch = mkdtempSync(join(tmpdir(), "runner-cwd-"));
  const server = new AgentServer({ query, log: () => {}, stdio: true, resolver: RESOLVER, runnerCwd: scratch, deleteSession });
  server.createServer = fakeCreateServer;
  const input = new PassThrough();
  const lines = [];
  let buf = "";
  const output = new Writable({ write(chunk, _e, cb) { buf += chunk.toString("utf8"); let nl; while ((nl = buf.indexOf("\n")) >= 0) { lines.push(JSON.parse(buf.slice(0, nl))); buf = buf.slice(nl + 1); } cb(); } });
  server.serveStdio({ input, output, fatal: () => {} });
  const send = (o) => input.write(Buffer.from(JSON.stringify(o) + "\n"));
  send({ relay: { start: { frame: F, protocol: 1, epoch: 0 } } });
  let n = 0;
  return {
    server, scratch, lines,
    grant: (extra = {}) => send({ jsonrpc: "2.0", method: "grant.changed", params: { folders: ["/"], write: true, ...extra } }),
    say: (conversation, text) => send({ jsonrpc: "2.0", method: "chat.message", params: { conversation, id: `${conversation}-${n++}`, text, author: "person" } }),
    finished: (conversation) => lines.filter((m) => m.method === "turn.event" && m.params.conversation === conversation && m.params.event.type === "turn_finished").length,
    until: async (f, what) => { const t = Date.now(); while (!f()) { if (Date.now() - t > 8000) throw new Error("timed out: " + what); await new Promise((r) => setTimeout(r, 5)); } },
    close: async () => { input.end(); await server.close(); rmSync(scratch, { recursive: true, force: true }); },
  };
}

test("a native session replaced when the mode changes is deleted where it ran (the runner's folder), before the agent stops", { timeout: 20000 }, async () => {
  const deleted = [];
  const h = inproc({ deleteSession: async (id, o) => { deleted.push([id, o.dir]); } });
  try {
    h.grant({ native: true });
    h.say("c1", "options?");
    await h.until(() => h.finished("c1") === 1, "the native turn");
    const [native] = [...h.server.sessions];
    assert.ok(native, "a native session");
    assert.equal(h.server.dirOf(native), h.scratch);
    h.grant({ native: false });
    h.say("c1", "options?");
    await h.until(() => h.finished("c1") === 2, "the tools-only turn");
    await h.until(() => deleted.length >= 1, "the replaced session's deletion");
    assert.deepEqual(deleted[0], [native, h.scratch], "deleted in the runner's folder, not the agent's own");
  } finally { await h.close(); }
});

test("native: the system prompt is Claude Code's own, with the Sagebrush part appended", { timeout: 20000 }, async () => {
  const seen = [];
  const h = inproc({ query: (o) => { seen.push(o.options); return fakeQuery(o); } });
  try {
    h.grant({ native: true });
    h.say("c1", "options?");
    await h.until(() => h.finished("c1") === 1, "the turn");
    assert.deepEqual(seen[0].systemPrompt, { type: "preset", preset: "claude_code", append: SYSTEM_NATIVE });
  } finally { await h.close(); }
});

test("nativeMode: a defaultMode that isn't one of the modes runs as the default", async () => {
  for (const mode of ["weird", "Default", "", 7, null]) {
    const resolver = { resolveSettings: async () => ({ permissions: { defaultMode: mode } }), filterEscalatingDefaultMode: (r) => r };
    assert.deepEqual(await nativeMode("/tmp", resolver), { mode: "default", bypass: false }, JSON.stringify(mode));
  }
  const plan = { resolveSettings: async () => ({ permissions: { defaultMode: "plan" } }), filterEscalatingDefaultMode: (r) => r };
  assert.deepEqual(await nativeMode("/tmp", plan), { mode: "plan", bypass: false }, "a mode that is one is kept");
});

test("native: a card's summary is the notebook's path (NotebookEdit) or the pattern (Grep, Glob)", { timeout: 20000 }, async () => {
  const h = inproc();
  try {
    h.grant({ native: true });
    await h.until(() => h.server.binding?.grant, "the grant");
    for (const [tool, input, want] of [
      ["NotebookEdit", { notebook_path: "/home/user/n.ipynb", new_source: "x = 1" }, "/home/user/n.ipynb"],
      ["Grep", { pattern: "TODO" }, "TODO"],
      ["Glob", { pattern: "**/*.py" }, "**/*.py"],
    ]) {
      const cards = [];
      const answer = h.server.askPerson(h.server.binding, (d) => cards.push(...d), tool, input, {}, "c1", true);
      assert.equal(cards[0]?.summary, want, tool);
      h.server.permissions.get(cards[0].request_id).done(false);
      assert.equal((await answer).behavior, "deny");
    }
  } finally { await h.close(); }
});
