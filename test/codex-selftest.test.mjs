// The Codex self-test (lib/codex-selftest.mjs): Codex's own generated protocol against what the agent uses
// (lib/codex-contract.json). Every check has a fixture that trips it: one thing broken in real Codex output
// (test/fixtures, from `codex app-server generate-json-schema --experimental`), and additions that must pass. Then
// the same through the agent with the fake Codex: a failing self-test sends nothing more, no thread and no turn.

import { test } from "node:test";
const T = { timeout: 20000 }; // (a row that hangs fails by name)
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { CONTRACT, checkContract, fieldOf } from "../lib/codex-selftest.mjs";
import { CODEX_TEXT } from "../lib/codex.mjs";

const fixture = (v) => JSON.parse(readFileSync(new URL(`./fixtures/codex-schema-${v}.json`, import.meta.url), "utf8")).definitions;
const fresh = () => structuredClone(fixture("0.163.0"));

// (the branch of a method union for one method: the place a method is removed or renamed)
const branchOf = (defs, union, method) => {
  const list = defs[union].oneOf ?? defs[union].anyOf;
  const i = list.findIndex((b) => (b.properties?.method?.enum ?? []).includes(method));
  assert.ok(i >= 0, `${union} has ${method} in the fixture`);
  return [list, i];
};
const itemOf = (defs, type) => (defs.ThreadItem.oneOf ?? defs.ThreadItem.anyOf).find((b) => (b.properties?.type?.enum ?? []).includes(type));

test("real Codex 0.159.2, 0.163.0 and 0.171.0 (the pinned one) output all pass", () => {
  assert.deepEqual(checkContract(fixture("0.159.2")), []);
  assert.deepEqual(checkContract(fixture("0.163.0")), []);
  assert.deepEqual(checkContract(fixture("0.171.0")), []);
});

// Each row breaks one thing the agent relies on; the self-test names it.
const BREAKS = [
  ["a removed method the agent calls", (d) => { const [l, i] = branchOf(d, "ClientRequest", "turn/start"); l.splice(i, 1); }, "no request turn/start"],
  ["a renamed parameter the agent sends", (d) => { const p = d.ThreadStartParams.properties; p.developer_instructions = p.developerInstructions; delete p.developerInstructions; }, "thread/start has no parameter developerInstructions"],
  ["a new required parameter", (d) => { d.TurnStartParams.required = [...(d.TurnStartParams.required ?? []), "workspaceId"]; d.TurnStartParams.properties.workspaceId = { type: "string" }; }, "turn/start needs a parameter workspaceId"],
  ["a renamed field read from an answer", (d) => { const p = d.ThreadStartResponse.properties; p.policy = p.approvalPolicy; delete p.approvalPolicy; }, "ThreadStartResponse has no approvalPolicy"],
  ["a renamed field read from an item", (d) => { const p = itemOf(d, "commandExecution").properties; p.output = p.aggregatedOutput; delete p.aggregatedOutput; }, "the commandExecution item has no aggregatedOutput"],
  ["a removed item kind", (d) => { const l = d.ThreadItem.oneOf ?? d.ThreadItem.anyOf; l.splice(l.indexOf(itemOf(d, "fileChange")), 1); }, "no fileChange item"],
  ["a removed notification the agent reads", (d) => { const [l, i] = branchOf(d, "ServerNotification", "turn/completed"); l.splice(i, 1); }, "no notification turn/completed"],
  ["a renamed field read from a notification", (d) => { const [l, i] = branchOf(d, "ServerNotification", "item/agentMessage/delta"); const ref = l[i].properties.params.$ref.split("/").pop(); const p = d[ref].properties; p.text = p.delta; delete p.delta; }, "item/agentMessage/delta has no delta"],
  ["a renamed server request the agent answers", (d) => { const [l, i] = branchOf(d, "ServerRequest", "item/tool/call"); l[i].properties.method.enum = ["item/tool/invoke"]; }, "no request item/tool/call"],
  ["a field read from a server request, renamed", (d) => { const [l, i] = branchOf(d, "ServerRequest", "item/fileChange/requestApproval"); const ref = l[i].properties.params.$ref.split("/").pop(); const p = d[ref].properties; p.item_id = p.itemId; delete p.itemId; }, "item/fileChange/requestApproval has no itemId"],
  ["an approval decision value Codex no longer takes", (d) => { for (const b of [d.CommandExecutionApprovalDecision, ...(d.CommandExecutionApprovalDecision.oneOf ?? [])]) if (b.enum) b.enum = b.enum.map((v) => (v === "accept" ? "approve" : v)); }, 'CommandExecutionApprovalDecision has no "accept"'],
  ["a renamed field of an answer the agent sends", (d) => { const p = d.DynamicToolCallResponse.properties; p.ok = p.success; delete p.success; }, "DynamicToolCallResponse has no success"],
];

for (const [what, breakIt, problem] of BREAKS) {
  test(`fails: ${what}`, () => {
    const d = fresh();
    breakIt(d);
    const problems = checkContract(d);
    assert.ok(problems.includes(problem), `${problem} in ${JSON.stringify(problems)}`);
  });
}

test("passes: additions only (an optional field, a new notification, a new method, a new decision value)", () => {
  const d = fresh();
  d.TurnStartParams.properties.parentTurnId2 = { type: ["string", "null"] };
  const [n] = branchOf(d, "ServerNotification", "turn/completed");
  n.push({ type: "object", properties: { method: { type: "string", enum: ["thread/somethingNew"] }, params: { type: "object", properties: {} } }, required: ["method"] });
  const [c] = branchOf(d, "ClientRequest", "turn/start");
  c.push({ type: "object", properties: { method: { type: "string", enum: ["thread/brandNew"] }, params: { type: "object", properties: {} } }, required: ["method"] });
  for (const b of [d.CommandExecutionApprovalDecision, ...(d.CommandExecutionApprovalDecision.oneOf ?? [])]) if (b.enum) b.enum = [...b.enum, "acceptWithNote"];
  assert.deepEqual(checkContract(d), []);
});

test("the contract names every method and field the agent's code uses (a sample read straight from lib/codex.mjs)", () => {
  const code = readFileSync(new URL("../lib/codex.mjs", import.meta.url), "utf8") + readFileSync(new URL("../lib/codex-turns.mjs", import.meta.url), "utf8");
  for (const m of code.matchAll(/app\.request\("([a-z/A-Z]+)"/g)) assert.ok(m[1] in CONTRACT.clientRequests, `${m[1]} is in the contract`);
  for (const m of code.matchAll(/method === "(item\/[a-zA-Z/]+|turn\/[a-z]+|thread\/[a-zA-Z/]+|error|serverRequest\/resolved)"/g)) {
    assert.ok(m[1] in CONTRACT.notifications || m[1] in CONTRACT.serverRequests, `${m[1]} is in the contract`);
  }
  for (const m of code.matchAll(/case "([a-zA-Z]+)": return \{ (?:name|ok)/g)) assert.ok(m[1] in CONTRACT.items, `the ${m[1]} item is in the contract`);
  assert.ok(fieldOf(fixture("0.163.0"), fixture("0.163.0").ThreadStartResponse, "thread.ephemeral"));
});

// ---- through the agent, with the fake Codex

const BIN = fileURLToPath(new URL("../bin/sagebrush-agent.mjs", import.meta.url));
const F = 64 * 1024;

function agent(fakeEnv) {
  const runnerCwd = realpathSync(mkdtempSync(join(tmpdir(), "runner-cwd-")));
  const record = join(runnerCwd, ".record.jsonl");
  const p = spawn(process.execPath, [BIN, "--codex", "--stdio"], { cwd: runnerCwd, env: { ...process.env, SAGEBRUSH_AGENT_FAKE: "1", FAKE_CODEX_RECORD: record, ...fakeEnv }, stdio: ["pipe", "pipe", "pipe"] });
  const lines = [];
  let buf = "";
  p.stdout.on("data", (d) => { buf += d.toString("utf8"); let nl; while ((nl = buf.indexOf("\n")) >= 0) { const l = buf.slice(0, nl); buf = buf.slice(nl + 1); try { lines.push(JSON.parse(l)); } catch {} } });
  p.stderr.on("data", () => {});
  const send = (o) => p.stdin.write(JSON.stringify(o) + "\n");
  send({ relay: { start: { frame: F, protocol: 1, epoch: 0 } } });
  send({ jsonrpc: "2.0", method: "grant.changed", params: { folders: ["/"], write: true, native: true } });
  const events = () => lines.filter((m) => m.method === "turn.event").map((m) => m.params.event);
  const rec = () => { if (!existsSync(record)) return []; const t = readFileSync(record, "utf8"); return t.slice(0, t.lastIndexOf("\n") + 1).split("\n").filter(Boolean).map((l) => JSON.parse(l)); };
  return {
    events, rec,
    say: (text) => send({ jsonrpc: "2.0", method: "chat.message", params: { conversation: "c1", id: `m-${Math.random()}`, text, author: "person" } }),
    finished: () => events().filter((e) => e.type === "turn_finished"),
    until: async (f, what) => { const t = Date.now(); while (!f()) { if (Date.now() - t > 15000) throw new Error("timed out: " + what); await new Promise((r) => setTimeout(r, 10)); } },
    // (the folder goes once the child has exited: Windows won't remove the folder a live process is in)
    kill: () => { try { p.kill("SIGKILL"); } catch {} const rm = () => rmSync(runnerCwd, { recursive: true, force: true, maxRetries: 20, retryDelay: 50 }); if (p.exitCode !== null || p.signalCode !== null) rm(); else p.once("exit", rm); },
  };
}

test("through the agent: a broken contract fails the turn in one line, and no thread or turn is ever started", T, async () => {
  const dir = mkdtempSync(join(tmpdir(), "schema-"));
  const d = fresh();
  BREAKS[0][1](d);
  const file = join(dir, "broken.json");
  writeFileSync(file, JSON.stringify({ definitions: d }));
  const a = agent({ FAKE_CODEX_SCHEMA: file });
  try {
    a.say("hello");
    await a.until(() => a.finished().length, "the refused turn");
    const err = a.events().find((e) => e.type === "turn_error");
    assert.equal(err.code, "codex_incompatible");
    assert.equal(err.message, CODEX_TEXT.incompatible("no request turn/start"));
    assert.equal(err.message.split("\n").length, 1);
    const methods = a.rec().map((m) => m.method).filter(Boolean);
    assert.ok(methods.includes("initialize"));
    for (const m of ["thread/start", "turn/start", "account/read", "config/read"]) assert.ok(!methods.includes(m), `${m} never sent`);
    assert.ok(a.rec().some((m) => m.argv?.includes("generate-json-schema")), "the schema was asked of this same Codex");
  } finally { a.kill(); rmSync(dir, { recursive: true, force: true }); }
});

test("through the agent: a Codex that can't describe its protocol fails the turn naming only its exit (never its stderr), nothing more sent", T, async () => {
  const a = agent({ FAKE_CODEX_SCHEMA_FAIL: "1", FAKE_CODEX_SCHEMA: "/nonexistent" });
  try {
    a.say("hello");
    await a.until(() => a.finished().length, "the refused turn");
    const err = a.events().find((e) => e.type === "turn_error");
    assert.equal(err.code, "codex_incompatible");
    assert.equal(err.message, CODEX_TEXT.noSchema("exit 1"));
    assert.ok(!err.message.includes("PRIVATE_CONFIG_MARKER") && !err.message.includes("sk-fake"), "never what Codex printed");
    assert.ok(!a.rec().some((m) => m.method === "thread/start" || m.method === "turn/start"));
  } finally { a.kill(); }
});

test("through the agent: notifications before initialize's answer (as Codex 0.163.0 sends) don't disturb the start; the turn completes", T, async () => {
  const a = agent({ FAKE_CODEX_SCHEMA: fileURLToPath(new URL("./fixtures/codex-schema-0.163.0.json", import.meta.url)), FAKE_CODEX_EARLY_NOTES: "1" });
  try {
    a.say("hello");
    await a.until(() => a.finished().length, "the turn");
    assert.equal(a.finished()[0].outcome, "completed");
    assert.equal(a.rec().filter((m) => m.method === "initialize").length, 1);
  } finally { a.kill(); }
});

// ---- the probe itself: fixed words only, bounded, ended by the agent stopping

import { generateSchemas } from "../lib/codex-selftest.mjs";
import { chmodSync as chmod2 } from "node:fs";
const script = (body) => { const d = mkdtempSync(join(tmpdir(), "probe-")); const f = join(d, "codex"); writeFileSync(f, `#!/bin/sh\n${body}\n`); chmod2(f, 0o755); return f; };

test("the probe's failures are fixed words: an exit, a schema it can't read, not found; never its output", T, async () => {
  // (on Windows, through the job helper: a program that can't be started is said as "it couldn't start"; the /bin/sh
  //  stand-ins below are POSIX only)
  if (process.platform === "win32") return void (await assert.rejects(generateSchemas(["C:\\nonexistent\\codex.exe"]), (e) => e.message === "it couldn't start"));
  await assert.rejects(generateSchemas([script("echo 'SECRET in stderr' >&2; exit 7")]), (e) => e.message === "exit 7");
  await assert.rejects(generateSchemas([script('for a; do [ "$p" = --out ] && o=$a; p=$a; done; echo "{SECRET not json" > "$o/codex_app_server_protocol.schemas.json"; exit 0')]), (e) => e.message === "its protocol couldn't be read");
  await assert.rejects(generateSchemas(["/nonexistent/codex"]), (e) => e.message === "it wasn't found");
});

test("the probe is bounded, and the agent stopping ends it (its whole process group)", T, async () => {
  const dir = mkdtempSync(join(tmpdir(), "probe-pg-"));
  const marker = join(dir, "child-alive");
  const slow = script(`(sleep 3; echo alive > "${marker}") & sleep 30`);
  const t = Date.now();
  await assert.rejects(generateSchemas([slow], { ms: 200 }), (e) => e.message === "it took too long");
  assert.ok(Date.now() - t < 5000);
  const ac = new AbortController();
  const p = generateSchemas([slow], { signal: ac.signal });
  setTimeout(() => ac.abort(), 100);
  await assert.rejects(p, (e) => /stopped by SIGKILL/.test(e.message));
  await new Promise((r) => setTimeout(r, 3500));
  assert.ok(!existsSync(marker), "nothing it started outlived it");
  rmSync(dir, { recursive: true, force: true });
});
