// First-run checks (#1788): what's missing is said before anything else starts, with the exact next step, and the
// agent never starts a Claude sign-in itself. Rows named "prereq: …".
import assert from "node:assert/strict";
import { test } from "node:test";
import { spawn, spawnSync } from "node:child_process";
import { chmodSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { SETUP_TEXT, claudeBinary, claudeSignedIn, cliQuery } from "../lib/claude-cli.mjs";
import { Turn } from "../lib/turns.mjs";

const BIN = fileURLToPath(new URL("../bin/sagebrush-agent.mjs", import.meta.url));
const NODE_CHECK = fileURLToPath(new URL("../lib/node-check.mjs", import.meta.url));
const CLAUDE = claudeBinary();
const posix = process.platform === "win32" ? "POSIX stand-ins" : false;
const stand = (body) => { const d = mkdtempSync(join(tmpdir(), "sb-pre-")); const p = join(d, "claude"); writeFileSync(p, `#!/bin/sh\n${body}\n`); chmodSync(p, 0o700); return p; };

test("prereq: a Node.js older than 20 is said first, with nodejs.org, and nothing else runs", () => {
  for (const v of ["18.20.0", "16.0.0"]) {
    const r = spawnSync(process.execPath, ["-e", `Object.defineProperty(process.versions, "node", { value: "${v}" }); import(${JSON.stringify(NODE_CHECK)}).then(() => console.log("went on"))`], { encoding: "utf8" });
    assert.equal(r.status, 2, v);
    assert.match(r.stderr, new RegExp(`Node.js 20 or later; this is Node.js ${v.replace(/\./g, "\\.")}`));
    assert.match(r.stderr, /https:\/\/nodejs\.org/);
    assert.equal(r.stdout, "");
  }
  const ok = spawnSync(process.execPath, ["-e", `import(${JSON.stringify(NODE_CHECK)}).then(() => console.log("went on"))`], { encoding: "utf8" });
  assert.equal(ok.stdout.trim(), "went on");
  // (and it is the bin's first import, before anything else loads)
  const src = spawnSync(process.execPath, ["-e", `process.stdout.write(require("fs").readFileSync(${JSON.stringify(BIN)}, "utf8"))`], { encoding: "utf8" }).stdout;
  assert.match(src.split("\n").find((l) => l.startsWith("import ")), /node-check\.mjs/);
});

test("prereq: the sign-in check reads only the pinned Claude Code's own loggedIn boolean; anything else is 'can't say'", { skip: posix }, () => {
  assert.equal(claudeSignedIn(stand(`echo '{"loggedIn":true,"authMethod":"claude.ai","email":"x"}'`)), true);
  assert.equal(claudeSignedIn(stand(`echo '{"loggedIn":false}'; exit 1`)), false);
  for (const out of [`echo '{"loggedIn":"yes"}'`, `echo 'not json'`, `echo '{}'`, `exit 1`]) assert.equal(claudeSignedIn(stand(out)), null, out);
  assert.equal(claudeSignedIn(null), null);
  assert.equal(claudeSignedIn("/nonexistent/claude"), null);
  // (it asks with exactly these arguments: `auth status --json`, never a login)
  const d = mkdtempSync(join(tmpdir(), "sb-args-"));
  const argsFile = join(d, "args");
  claudeSignedIn(stand(`echo "$@" > ${JSON.stringify(argsFile)}; echo '{"loggedIn":true}'`));
  assert.equal(spawnSync("cat", [argsFile], { encoding: "utf8" }).stdout.trim(), "auth status --json");
});

test("prereq: in a terminal, the pinned Claude Code not signed in is said at start with Anthropic's page and `claude auth login`, and nothing listens", { skip: !CLAUDE || posix ? "the pinned Claude Code and POSIX" : false, timeout: 60_000 }, () => {
  const home = mkdtempSync(join(tmpdir(), "sb-home-"));
  const r = spawnSync(process.execPath, [BIN], { env: { PATH: process.env.PATH, HOME: home, CLAUDE_CONFIG_DIR: join(home, ".claude") }, encoding: "utf8", timeout: 50_000 });
  assert.equal(r.status, 3);
  assert.equal(r.stderr.trim(), SETUP_TEXT.notSignedIn);
  assert.match(r.stderr, /https:\/\/code\.claude\.com\/docs\/en\/setup/);
  assert.match(r.stderr, /`claude auth login`/);
  assert.ok(!/Open:/.test(r.stdout), "no link printed: nothing listens");
});

test("prereq: with an API key (SDK mode) the sign-in check is skipped and the agent starts", { skip: posix, timeout: 60_000 }, async () => {
  const home = mkdtempSync(join(tmpdir(), "sb-home-"));
  const p = spawn(process.execPath, [BIN, "--port", "0"], { env: { PATH: process.env.PATH, HOME: home, ANTHROPIC_API_KEY: "test-key-not-a-credential" }, stdio: ["ignore", "pipe", "pipe"] });
  let out = "";
  p.stdout.on("data", (d) => { out += d; });
  const t0 = Date.now();
  while (!/Open:/.test(out) && Date.now() - t0 < 30_000 && p.exitCode === null) await new Promise((r) => setTimeout(r, 50));
  p.kill("SIGTERM");
  await new Promise((r) => p.once("exit", r));
  assert.match(out, /Open:/);
});

test("prereq: a turn that finds Claude Code not signed in says the same next step, once, and ends without a second error", { skip: posix, timeout: 30_000 }, async () => {
  // (the page's words: turns.mjs maps Claude Code's authentication_failed to the launcher's text)
  const turn = new Turn("t1");
  turn.start();
  const ev = turn.feed({ type: "assistant", error: "authentication_failed", message: { content: [{ type: "text", text: "Not logged in · Please run /login" }] } });
  assert.deepEqual(ev, [{ type: "turn_error", code: "claude_not_signed_in", message: SETUP_TEXT.turnNotSignedIn }]);
  // (a stand-in that ends as Claude Code does when it isn't signed in: that frame, an error result, exit 1)
  const bin = stand(`printf '%s\\n' '{"type":"assistant","error":"authentication_failed","message":{"content":[{"type":"text","text":"Not logged in"}]}}' '{"type":"result","subtype":"success","is_error":true,"result":"Not logged in"}'; exit 1`);
  const q = cliQuery({ prompt: "x", options: { canUseTool: async () => ({ behavior: "deny", message: "no" }) } }, { bin, env: { PATH: process.env.PATH }, limits: { connectMs: 20_000, killGraceMs: 200 } });
  const got = [];
  let err = null;
  try { for await (const m of q) got.push(m.type); } catch (e) { err = e; }
  await q.return().catch(() => {});
  assert.deepEqual(got, ["assistant", "result"]);
  assert.equal(err, null, "the error result said why; no extra 'stopped (exit 1)'");
});

// (#1804: an expired or invalid Claude login, as the pinned Claude Code says it, reaches the page as one fixed reason in
//  our words; Claude Code's own text, with its setup-token advice, never does)
test("prereq: an expired Claude login is one reason, claude_login_expired, in our words; Claude Code's text (setup-token advice) never reaches the page", () => {
  const raw = "Failed to authenticate: this login reached its time limit and cannot be renewed. Run `claude auth login` to sign in again, or use `claude setup-token` and set CLAUDE_CODE_OAUTH_TOKEN for unattended jobs";
  const flat = (evs) => JSON.stringify(evs);
  // (as a result only)
  const a = new Turn("t1"); a.start();
  const ra = a.feed({ type: "result", subtype: "success", is_error: true, result: raw });
  assert.deepEqual(ra.filter((e) => e.type !== "turn_usage"), [
    { type: "turn_error", code: "claude_login_expired", message: "Your Claude sign-in expired. In your terminal, run `claude auth login`, then send your message again." },
    { type: "turn_finished", outcome: "error", code: "claude_login_expired" },
  ]);
  assert.ok(!/setup-token|CLAUDE_CODE_OAUTH_TOKEN|time limit/.test(flat(ra)));
  // (as the assistant's error frame, then the result: said once)
  const b = new Turn("t2"); b.start();
  const rb = [...b.feed({ type: "assistant", error: "authentication_failed", message: { content: [{ type: "text", text: raw }] } }), ...b.feed({ type: "result", subtype: "success", is_error: true, result: raw })];
  assert.equal(rb.filter((e) => e.type === "turn_error").length, 1);
  assert.equal(rb.find((e) => e.type === "turn_finished").code, "claude_login_expired");
  assert.ok(!/setup-token|CLAUDE_CODE_OAUTH_TOKEN/.test(flat(rb)));
  // (not signed in, as the pinned release says it)
  const c = new Turn("t3"); c.start();
  const rc = [...c.feed({ type: "assistant", error: "authentication_failed", message: { content: [{ type: "text", text: "Not logged in · Please run /login" }] } }), ...c.feed({ type: "result", subtype: "success", is_error: true, result: "Not logged in · Please run /login" })];
  assert.deepEqual(rc.filter((e) => e.type === "turn_error").map((e) => e.code), ["claude_not_signed_in"]);
  assert.ok(!/Please run \/login/.test(flat(rc)));
  // (any other error result is as before: Claude's words as a message, the error fixed)
  const d = new Turn("t4"); d.start();
  const rd = d.feed({ type: "result", subtype: "success", is_error: true, result: "The tool failed." });
  assert.ok(rd.some((e) => e.type === "text_delta" && e.text === "The tool failed."));
  assert.ok(rd.some((e) => e.type === "turn_error" && e.code === "is_error"));
});

// (astra5's hold on the first cut: only the pinned Claude Code's own sign-in texts are sign-in failures; an error result
//  about any other time limit, authentication or token is said as before, with its text)
test("prereq: only the pinned Claude Code's sign-in texts are sign-in failures; other timeout, auth and token errors keep their text", async () => {
  const { signInFailure, keyFailure } = await import("../lib/claude-cli.mjs");
  for (const t of [
    "Login reached its time limit \u00b7 Please run /login",
    "Login expired \u00b7 Please run /login",
    "OAuth token revoked \u00b7 Please run /login",
    "Failed to authenticate: this login reached its time limit \u00b7 Sign in again to continue",
    "Failed to authenticate: OAuth session expired and could not be refreshed",
    "Failed to authenticate: OAuth token revoked. Please log in again or contact your administrator.",
  ]) assert.equal(signInFailure(t), "claude_login_expired", t);
  assert.equal(signInFailure("Not logged in \u00b7 run /login"), "claude_not_signed_in");
  const others = [
    "The tool reached its time limit.",
    "Failed to authenticate to the GitHub API.",
    "The upload access token expired.",
    "Your token has expired; run claude auth login on the server.",
    "Not logged in to the registry.",
    "Login expired for the database",
    "Invalid API key \u00b7 Fix external API key",
  ];
  for (const t of others) assert.equal(signInFailure(t), null, t);
  for (const [i, t] of others.entries()) {
    const turn = new Turn(`n${i}`); turn.start();
    const ev = turn.feed({ type: "result", subtype: "success", is_error: true, result: t });
    assert.ok(ev.some((e) => e.type === "text_delta" && e.text === t), t);
    assert.deepEqual(ev.filter((e) => e.type === "turn_error"), [{ type: "turn_error", code: "is_error", message: "Claude ended the turn with an error" }], t);
    assert.equal(ev.find((e) => e.type === "turn_finished").code, "is_error", t);
  }
  // (an authentication_failed about a key the person set isn't called an expired sign-in)
  assert.ok(keyFailure("Invalid API key \u00b7 Fix external API key") && keyFailure("Invalid auth token \u00b7 Fix external auth token"));
  const k = new Turn("k"); k.start();
  const rk = k.feed({ type: "assistant", error: "authentication_failed", message: { content: [{ type: "text", text: "Invalid API key \u00b7 Fix external API key" }] } });
  assert.deepEqual(rk.filter((e) => e.type === "turn_error").map((e) => e.code), ["authentication_failed"]);
});
