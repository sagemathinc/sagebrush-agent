// Codex's asks, in-process (lib/codex.mjs with a stand-in app-server): a card lives only while Codex waits for its
// request in the running turn. It is withdrawn when Codex says the request is resolved, when the turn completes, when
// Codex exits; an Allow after that accepts nothing. Before turn/start's answer, no request opens a card or picks the
// turn's id. A file change updated while its card is open is asked again with the new changes.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AgentServer } from "../lib/server.mjs";
import { CodexBackend } from "../lib/codex.mjs";
import { CodexTurn } from "../lib/codex-turns.mjs";

function setup({ turnId = "turn1" } = {}) {
  const dir = mkdtempSync(join(tmpdir(), "codex-lifetime-"));
  const server = new AgentServer({ stdio: true, runnerCwd: dir, log: () => {} });
  const binding = { grant: { native: true }, features: ["permission.digest"] };
  server.binding = binding;
  const backend = new CodexBackend(server);
  const app = { closed: false };
  const events = [];
  let ready;
  const started = new Promise((r) => { ready = r; });
  const finished = [];
  const active = { app, threadId: "th", codexTurnId: turnId, started: turnId ? Promise.resolve(turnId) : started, early: [], binding, signal: new AbortController().signal, turn: new CodexTurn("local"), conversation: "c1", c: {}, items: new Map(), asks: new Map(), send: (d) => events.push(...d), finish: (how) => finished.push(how), interrupted: false };
  backend.turns.set("th", active);
  const cards = (state) => events.filter((e) => e.type === "attention" && (!state || e.state === state));
  const open = () => [...server.permissions.values()];
  const tick = () => new Promise((r) => setImmediate(r));
  return { server, backend, app, active, events, cards, open, tick, ready, finished, done: async () => { await server.close().catch(() => {}); rmSync(dir, { recursive: true, force: true }); } };
}
const command = (turnId = "turn1") => ({ threadId: "th", turnId, kind: "command", itemId: "cmd1", command: "echo benign", cwd: "/tmp", availableDecisions: ["accept", "decline"] });

test("Codex resolves the request: the card is withdrawn, and an Allow after that accepts nothing", async () => {
  const t = setup();
  try {
    const answer = t.backend.request(t.app, "item/commandExecution/requestApproval", command(), 17);
    await t.tick();
    const [q] = t.open();
    assert.ok(q, "a card");
    t.backend.notification(t.app, "serverRequest/resolved", { threadId: "th", requestId: 17 });
    assert.equal(t.open().length, 0, "withdrawn");
    q.done(true); // (an Allow of the withdrawn card)
    assert.deepEqual(await answer, { decision: "cancel" });
    assert.deepEqual(t.cards().map((c) => c.state), ["open", "denied"]);
  } finally { await t.done(); }
});

test("a resolved notice for another request id, or another thread, leaves the card open", async () => {
  const t = setup();
  try {
    const answer = t.backend.request(t.app, "item/commandExecution/requestApproval", command(), "r-1");
    await t.tick();
    t.backend.notification(t.app, "serverRequest/resolved", { threadId: "th", requestId: "r-2" });
    t.backend.notification(t.app, "serverRequest/resolved", { threadId: "other", requestId: "r-1" });
    assert.equal(t.open().length, 1);
    t.open()[0].done(true);
    assert.deepEqual(await answer, { decision: "accept" });
  } finally { await t.done(); }
});

test("the turn completes while a card is open: withdrawn, and a later Allow accepts nothing", async () => {
  const t = setup();
  try {
    const answer = t.backend.request(t.app, "item/commandExecution/requestApproval", command(), 5);
    await t.tick();
    const [q] = t.open();
    t.backend.notification(t.app, "turn/completed", { threadId: "th", turn: { id: "turn1", status: "completed" } });
    assert.equal(t.open().length, 0);
    q.done(true);
    assert.deepEqual(await answer, { decision: "cancel" });
    assert.deepEqual(t.finished, ["completed"]);
  } finally { await t.done(); }
});

test("Codex exits while a card is open: withdrawn and cancelled", async () => {
  const t = setup();
  try {
    const answer = t.backend.request(t.app, "item/permissions/requestApproval", { threadId: "th", turnId: "turn1", cwd: "/tmp", reason: "net", permissions: { network: { enabled: true }, fileSystem: null } }, 9);
    await t.tick();
    assert.equal(t.open().length, 1);
    t.backend.notification(t.app, "sagebrush/exited", { message: "exit 3" });
    assert.equal(t.open().length, 0);
    assert.deepEqual(await answer, { permissions: {}, scope: "turn" });
  } finally { await t.done(); }
});

test("before turn/start's answer: a request opens no card and can't pick the turn's id; after it, only one naming that id counts", async () => {
  const t = setup({ turnId: null });
  try {
    const old = t.backend.request(t.app, "item/commandExecution/requestApproval", command("old-turn"), 1);
    const mine = t.backend.request(t.app, "item/commandExecution/requestApproval", command("new-turn"), 2);
    t.backend.notification(t.app, "item/agentMessage/delta", { threadId: "th", turnId: "new-turn", itemId: "m", delta: "x" });
    await t.tick();
    assert.equal(t.open().length, 0, "no card yet");
    assert.equal(t.active.codexTurnId, null, "no id taken from a request or a notification");
    assert.equal(t.active.early.length, 1, "the notification is held");
    t.active.codexTurnId = "new-turn"; // (what runTurn does with turn/start's answer)
    t.ready("new-turn");
    assert.deepEqual(await old, { decision: "decline" });
    await t.tick();
    assert.equal(t.open().length, 1, "this turn's request is asked");
    t.open()[0].done(false);
    assert.deepEqual(await mine, { decision: "decline" });
  } finally { await t.done(); }
});

test("a file change: the card shows the changes as last updated; an update while its card is open asks again, with the new diff", async () => {
  const t = setup();
  const base = { threadId: "th", turnId: "turn1" };
  const changes = (diff) => [{ path: "/tmp/benign.txt", kind: { type: "update", move_path: null }, diff }];
  try {
    t.backend.notification(t.app, "item/started", { ...base, item: { id: "p1", type: "fileChange", status: "inProgress", changes: changes("old diff") } });
    t.backend.notification(t.app, "item/fileChange/patchUpdated", { ...base, itemId: "p1", changes: changes("new diff") });
    const first = t.backend.request(t.app, "item/fileChange/requestApproval", { ...base, itemId: "p1" }, 3);
    await t.tick();
    assert.equal(t.cards("open")[0].action.input.changes[0].diff, "new diff");
    const [q1] = t.open();
    t.backend.notification(t.app, "item/fileChange/patchUpdated", { ...base, itemId: "p1", changes: changes("newer diff") });
    await t.tick();
    assert.equal(t.open().length, 1, "one card open: the new one");
    const [q2] = t.open();
    assert.notEqual(q2, q1);
    assert.equal(t.cards("open").at(-1).action.input.changes[0].diff, "newer diff");
    assert.notEqual(t.cards("open").at(-1).request_id, t.cards("open")[0].request_id, "a new request id, so a new digest");
    q1.done(true); // (an Allow of the old card: nothing)
    q2.done(true);
    assert.deepEqual(await first, { decision: "accept" });
  } finally { await t.done(); }
});

test("a change update for another turn doesn't touch the card", async () => {
  const t = setup();
  const changes = (diff) => [{ path: "/tmp/b.txt", kind: { type: "add" }, diff }];
  try {
    t.backend.notification(t.app, "item/started", { threadId: "th", turnId: "turn1", item: { id: "p1", type: "fileChange", status: "inProgress", changes: changes("mine") } });
    const answer = t.backend.request(t.app, "item/fileChange/requestApproval", { threadId: "th", turnId: "turn1", itemId: "p1" }, 4);
    await t.tick();
    t.backend.notification(t.app, "item/fileChange/patchUpdated", { threadId: "th", turnId: "other", itemId: "p1", changes: changes("theirs") });
    assert.equal(t.open().length, 1);
    assert.equal(t.cards("open").length, 1);
    t.open()[0].done(true);
    assert.deepEqual(await answer, { decision: "accept" });
  } finally { await t.done(); }
});

test("an Allow and the turn's end in the same tick: the Allow lands first but the request is cancelled, not accepted", async () => {
  for (const end of ["completed", "gone", "exited"]) {
    const t = setup();
    try {
      const answer = t.backend.request(t.app, "item/commandExecution/requestApproval", command(), 11);
      await t.tick();
      const [q] = t.open();
      q.done(true); // (the Allow settles the card first ...)
      // (... and before the request's answer is decided, the turn ends, in the same tick)
      if (end === "completed") t.backend.notification(t.app, "turn/completed", { threadId: "th", turn: { id: "turn1", status: "completed" } });
      if (end === "gone") { t.active.turn.finished = true; t.backend.turns.delete("th"); }
      if (end === "exited") t.backend.notification(t.app, "sagebrush/exited", { message: "exit 3" });
      assert.deepEqual(await answer, { decision: "cancel" }, end);
    } finally { await t.done(); }
  }
});
