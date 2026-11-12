// `sagebrush-agent --stdio`, end to end: the real process on its fake model, driven through its pipes the way the
// runner drives it. Every order is forced by what the process writes (no sleeps decide a row).
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { TEXT } from "../lib/server.mjs";

const BIN = fileURLToPath(new URL("../bin/sagebrush-agent.mjs", import.meta.url));
const F = 64 * 1024; // (the smallest frame the agent accepts: the edges are cheap to reach)

function agent({ frame = F, start = true } = {}) {
  const p = spawn(process.execPath, [BIN, "--stdio"], { env: { ...process.env, SAGEBRUSH_AGENT_FAKE: "1" }, stdio: ["pipe", "pipe", "pipe"] });
  const a = { p, lines: [], raw: [], err: "", exit: null, waiters: [] };
  let buf = "";
  p.stdout.on("data", (d) => {
    a.raw.push(d);
    buf += d.toString("utf8");
    let nl;
    while ((nl = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, nl);
      buf = buf.slice(nl + 1);
      a.lines.push({ text: line, msg: JSON.parse(line) }); // (stdout carries protocol lines only: each must parse)
      a.check();
    }
  });
  p.stderr.on("data", (d) => { a.err += d.toString("utf8"); a.check(); });
  a.exited = new Promise((r) => p.on("exit", (code, sig) => { a.exit = { code, sig }; a.check(); r(a.exit); }));
  a.check = () => { for (const w of [...a.waiters]) if (w.pred()) { a.waiters.splice(a.waiters.indexOf(w), 1); w.resolve(); } };
  a.until = (pred, what, ms = 15000) => new Promise((resolve, reject) => {
    if (pred()) return resolve();
    const t = setTimeout(() => reject(new Error(`timed out waiting for ${what}; stderr: ${a.err.slice(-500)}`)), ms);
    a.waiters.push({ pred, resolve: () => { clearTimeout(t); resolve(); } });
  });
  a.write = (text) => p.stdin.write(text + "\n");
  a.send = (obj) => a.write(JSON.stringify(obj));
  a.find = (pred) => a.lines.find((l) => pred(l.msg));
  a.all = (pred) => a.lines.filter((l) => pred(l.msg));
  a.events = (turnPred = () => true) => a.lines.filter((l) => l.msg.method === "turn.event" && turnPred(l.msg.params)).map((l) => l.msg.params.event);
  a.start = () => a.send({ relay: { start: { frame, protocol: 1, epoch: 0 } } });
  a.grant = () => a.send({ jsonrpc: "2.0", method: "grant.changed", params: { folders: ["/"], write: true } });
  a.say = (conversation, text, id = `${conversation}-${a.lines.length}`) => a.send({ jsonrpc: "2.0", method: "chat.message", params: { conversation, id, text, author: "person" } });
  // (a page that answers the workspace verbs: nothing exists yet, and every create works)
  a.answering = () => {
    const seen = new Set();
    const tick = () => {
      for (const l of a.lines) {
        const m = l.msg;
        if (typeof m.id !== "string" || !m.method || seen.has(m.id)) continue;
        seen.add(m.id);
        const result = m.method === "workspace.stat" ? { entry: null } : m.method === "workspace.list" ? { entries: [] } : { ok: true, rev: 1 };
        a.send({ jsonrpc: "2.0", id: m.id, result });
      }
    };
    const iv = setInterval(tick, 5);
    a.stopAnswering = () => clearInterval(iv);
  };
  a.kill = () => { try { p.kill("SIGKILL"); } catch {} };
  if (start) a.start();
  return a;
}

const finished = (a, conversation) => a.lines.some((l) => l.msg.method === "turn.event" && l.msg.params.conversation === conversation && l.msg.params.event.type === "turn_finished");
const ready = (a, n = 1) => a.all((m) => m.method === "agent.ready").length >= n;

test("stdio: start, then agent.ready with this child's id and features; stdout is protocol lines only", async () => {
  const a = agent();
  try {
    await a.until(() => ready(a), "agent.ready");
    const r = a.find((m) => m.method === "agent.ready").msg.params;
    assert.deepEqual(r.features, ["notebook.edit", "permission.digest"]);
    assert.match(r.child, /^[A-Za-z0-9_-]{43}$/);
    a.p.stdin.end();
    assert.deepEqual(await a.exited, { code: 0, sig: null });
    assert.equal(Buffer.concat(a.raw).toString("utf8").split("\n").filter(Boolean).length, a.lines.length);
  } finally { a.kill(); }
});

test("stdio: a turn end to end: grant, message, workspace requests answered, turn completed", async () => {
  const a = agent();
  try {
    await a.until(() => ready(a), "agent.ready");
    a.answering(); a.grant(); a.say("c1", "hello");
    await a.until(() => finished(a, "c1"), "the turn's end");
    const ev = a.events((p) => p.conversation === "c1");
    assert.equal(ev.at(-1).outcome, "completed");
    assert.ok(a.find((m) => m.method === "workspace.create"));
  } finally { a.stopAnswering?.(); a.kill(); }
});

test("stdio: the clamp, byte-exact: a request line of exactly F is sent, F + 1 is an ordinary tool error and the agent stays up", async () => {
  const a = agent();
  try {
    await a.until(() => ready(a), "agent.ready");
    a.answering(); a.grant();
    // (measure the create line's overhead with a small write, then aim at F and F + 1; ids keep their digit count)
    a.say("probe", "big 10");
    await a.until(() => finished(a, "probe"), "the probe turn");
    const probe = a.find((m) => m.method === "workspace.create");
    const overhead = Buffer.byteLength(probe.text) - 10;
    const idLen = probe.msg.id.length;
    a.say("exact", `big ${F - overhead}`);
    await a.until(() => finished(a, "exact"), "the exact-F turn");
    const exact = a.all((m) => m.method === "workspace.create").at(-1);
    assert.equal(exact.msg.id.length, idLen);
    assert.equal(Buffer.byteLength(exact.text), F, "a line of exactly F bytes before its newline");
    a.say("over", `big ${F - overhead + 1}`);
    await a.until(() => finished(a, "over"), "the F + 1 turn");
    const creates = a.all((m) => m.method === "workspace.create").length;
    assert.equal(creates, 2, "the F + 1 request was never written");
    const done = a.events((p) => p.conversation === "over").find((e) => e.type === "tool_call_finished");
    assert.equal(done.status, "error");
    assert.equal(done.body, `refused: ${TEXT.requestOver}`);
    assert.equal(a.exit, null, "the agent is still running");
    // (and a 7 MiB write: refused the same way, without the agent building it as a line)
    a.say("huge", `big ${7 * 1024 * 1024}`);
    await a.until(() => finished(a, "huge"), "the 7 MiB turn");
    assert.equal(a.events((p) => p.conversation === "huge").find((e) => e.type === "tool_call_finished").body, `refused: ${TEXT.requestOver}`);
  } finally { a.stopAnswering?.(); a.kill(); }
});

test("stdio: detach ends the binding: the running turn stops, its open question is denied, and a late answer has no effect", async () => {
  const a = agent();
  try {
    await a.until(() => ready(a), "agent.ready");
    a.answering(); a.grant(); a.say("c1", "please search");
    await a.until(() => a.events().some((e) => e.type === "attention" && e.state === "open"), "the permission card");
    const card = a.events().find((e) => e.type === "attention" && e.state === "open");
    assert.equal(card.digest, undefined, "the card never carries a digest");
    assert.deepEqual(Object.keys(card.action).sort(), ["input", "tool"]);
    const before = a.lines.length;
    a.send({ relay: { page: "detached", epoch: 1 } });
    a.send({ relay: { page: "attached", epoch: 1 } });
    await a.until(() => ready(a, 2), "agent.ready after the re-attach");
    // (nothing of the old binding was written after the detach: the next line is the new agent.ready)
    assert.equal(a.lines[before].msg.method, "agent.ready");
    a.send({ jsonrpc: "2.0", method: "chat.permission", params: { request_id: card.id, behavior: "allow", digest: "x".repeat(43) } });
    a.grant(); a.say("c1", "hello again");
    await a.until(() => a.lines.slice(before).some((l) => l.msg.method === "turn.event" && l.msg.params.event.type === "turn_finished"), "the new turn's end");
    const after = a.lines.slice(before).filter((l) => l.msg.method === "turn.event").map((l) => l.msg.params.event);
    const said = after.filter((e) => e.type === "text_delta").map((e) => e.text).join("");
    assert.doesNotMatch(said, /allowed the search/, "the late Allow did nothing");
    assert.match(said, /said: "hello again"/, "the text is joined before matching (the fake sends a word per event)");
    assert.equal(after.at(-1).outcome, "completed");
  } finally { a.stopAnswering?.(); a.kill(); }
});

test("stdio: attached(n) with no detached(n) before it still ends the old binding; an earlier epoch is ignored", async () => {
  const a = agent();
  try {
    await a.until(() => ready(a), "agent.ready");
    a.answering(); a.grant(); a.say("c1", "slow");
    await a.until(() => a.events().some((e) => e.type === "text_delta"), "the slow turn streaming");
    a.send({ relay: { page: "attached", epoch: 1 } });
    await a.until(() => ready(a, 2), "agent.ready");
    const at = a.lines.findIndex((l, i) => i > 0 && l.msg.method === "agent.ready" && a.lines.slice(0, i).some((x) => x.msg.method === "turn.event"));
    const n = a.lines.length;
    await new Promise((r) => setTimeout(r, 200));
    assert.equal(a.lines.slice(at + 1).filter((l) => l.msg.method === "turn.event").length, 0, "the old turn writes nothing more");
    assert.equal(a.lines.length, n);
    a.send({ relay: { page: "detached", epoch: 0 } });
    await a.until(() => a.err.includes(TEXT.stale), "the stale line logged");
    a.send({ relay: { page: "something-new", epoch: 9 } }); // (an unknown relay line: ignored)
    a.send({ jsonrpc: "2.0", method: "page.features", params: { features: [] } });
    assert.equal(a.exit, null);
  } finally { a.stopAnswering?.(); a.kill(); }
});

test("stdio: SIGINT stops the running turn and the agent stays up; SIGTERM stops the agent within the runner's 2 s", async () => {
  const a = agent();
  try {
    await a.until(() => ready(a), "agent.ready");
    a.answering(); a.grant(); a.say("c1", "slow");
    await a.until(() => a.events().some((e) => e.type === "text_delta"), "the slow turn streaming");
    a.p.kill("SIGINT");
    await a.until(() => finished(a, "c1"), "the interrupted turn's end");
    assert.equal(a.events((p) => p.conversation === "c1").at(-1).outcome, "interrupted");
    a.say("c2", "hello");
    await a.until(() => finished(a, "c2"), "a turn after the SIGINT");
    const t = Date.now();
    a.p.kill("SIGTERM");
    assert.deepEqual(await a.exited, { code: 0, sig: null });
    assert.ok(Date.now() - t < 2000, `stopped in ${Date.now() - t} ms`);
  } finally { a.stopAnswering?.(); a.kill(); }
});

test("stdio: the start rules: payload first, a second start, an oversized first line, a bad frame, EOF before start", async () => {
  const cases = [
    ["a payload before start", (a) => a.send({ jsonrpc: "2.0", method: "grant.changed", params: {} }), TEXT.badStart],
    ["a second start", (a) => { a.start(); a.start(); }, TEXT.badStart],
    ["a first line of 4 KiB + 1", (a) => a.write("x".repeat(4 * 1024 + 1)), TEXT.lineOver],
    ["a frame just under the range", (a) => a.send({ relay: { start: { frame: F - 1, protocol: 1, epoch: 0 } } }), TEXT.badStart],
    ["EOF before start", (a) => a.p.stdin.end(), TEXT.badStart],
  ];
  for (const [what, act, text] of cases) {
    const a = agent({ start: false });
    try {
      act(a);
      assert.equal((await a.exited).code, 1, what);
      assert.ok(a.err.includes(text), `${what}: ${a.err}`);
    } finally { a.kill(); }
  }
});

test("stdio: an input line of exactly F is read; F + 1 exits 1", async () => {
  const pad = (n) => { const base = JSON.stringify({ jsonrpc: "2.0", method: "x.pad", params: { pad: "" } }); return JSON.stringify({ jsonrpc: "2.0", method: "x.pad", params: { pad: "p".repeat(n - base.length) } }); };
  const a = agent();
  try {
    await a.until(() => ready(a), "agent.ready");
    assert.equal(Buffer.byteLength(pad(F)), F);
    a.write(pad(F));
    a.send({ jsonrpc: "2.0", method: "page.features", params: { features: [] } });
    a.write(pad(F + 1));
    assert.equal((await a.exited).code, 1);
    assert.ok(a.err.includes(TEXT.lineOver));
  } finally { a.kill(); }
});

test("stdio: the caps: a fifth conversation waits for a running turn, and the 17th waiting message is refused", async () => {
  const a = agent();
  try {
    await a.until(() => ready(a), "agent.ready");
    a.answering(); a.grant();
    for (let i = 1; i <= 4; i++) a.say(`r${i}`, "slow");
    await a.until(() => [1, 2, 3, 4].every((i) => a.events((p) => p.conversation === `r${i}`).length > 0), "four turns started");
    for (let i = 1; i <= 16; i++) a.say("w", `hello ${i}`, `w-${i}`);
    a.say("w", "one too many", "w-17");
    await a.until(() => a.find((m) => m.method === "chat.rejected" && m.params.id === "w-17"), "the 17th refused");
    const rej = a.find((m) => m.method === "chat.rejected" && m.params.id === "w-17").msg.params;
    assert.deepEqual(rej.reason, { code: "busy", message: TEXT.tooMany });
    assert.equal(a.events((p) => p.conversation === "w").length, 0, "the fifth conversation hasn't started");
    a.p.kill("SIGINT"); // (the four stop; the waiting ones run, one at a time in their conversation)
    await a.until(() => a.events((p) => p.conversation === "w").length > 0, "the fifth conversation starting");
  } finally { a.stopAnswering?.(); a.kill(); }
});

test("stdio: a page that stops reading: the turn is stopped at the 2F bound and the page is told once, from the reserve", async () => {
  const a = agent();
  try {
    await a.until(() => ready(a), "agent.ready");
    a.answering(); a.grant();
    a.p.stdout.pause();
    a.say("c1", "flood 200");
    await new Promise((r) => setTimeout(r, 1500)); // (time for the agent to fill its queue; the row's verdict comes from the lines below)
    a.p.stdout.resume();
    await a.until(() => finished(a, "c1"), "the stopped turn's end");
    const ev = a.events((p) => p.conversation === "c1");
    const err = ev.find((e) => e.type === "turn_error");
    assert.equal(err?.message, TEXT.notReading);
    assert.ok(ev.filter((e) => e.type === "text_delta").length < 200, "the flood was cut short");
    a.say("c2", "hello");
    await a.until(() => finished(a, "c2"), "a turn afterwards");
  } finally { a.stopAnswering?.(); a.kill(); }
});

test("the fake model: imported only with SAGEBRUSH_AGENT_FAKE=1, and nothing on the wire can select it", () => {
  const read = (p) => readFileSync(fileURLToPath(new URL(p, import.meta.url)), "utf8");
  const bin = read("../bin/sagebrush-agent.mjs");
  // (one import of it, dynamic, inside the environment check)
  const imports = [...bin.matchAll(/import\(["']\.\.\/lib\/fake\.mjs["']\)/g)];
  assert.equal(imports.length, 1);
  const guard = bin.lastIndexOf('if (process.env.SAGEBRUSH_AGENT_FAKE === "1") {', imports[0].index);
  assert.ok(guard >= 0 && !bin.slice(guard, imports[0].index).includes("\n}"), "the import sits inside the environment check");
  assert.doesNotMatch(bin.replace(/import\(["']\.\.\/lib\/fake\.mjs["']\)/, ""), /fake\.mjs/);
  for (const f of ["../lib/server.mjs", "../lib/stdio.mjs", "../lib/canon.mjs", "../lib/turns.mjs", "../lib/notebook.mjs"]) {
    assert.doesNotMatch(read(f), /fake\.mjs|SAGEBRUSH_AGENT_FAKE|fakeQuery|fakeCreateServer/, `${f} never loads or selects the fake: no message can choose it`);
  }
});
