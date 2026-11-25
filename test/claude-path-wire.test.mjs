// --claude-path wired in (bin/sagebrush-agent.mjs and cliQuery's re-check): rows named "claude-path wire: …". POSIX only.
// The rows that bind a real path need a host whose "/" others can't write (a real computer; GitHub's runners); on one
// where they can (some containers), every path is refused parent_writable, so those rows say so and skip.
import assert from "node:assert/strict";
import { test } from "node:test";
import { spawn, spawnSync } from "node:child_process";
import { chmodSync, existsSync, lstatSync, mkdtempSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { cliQuery } from "../lib/claude-cli.mjs";
import { CLAUDE_PATH_REASONS, ClaudePathError, minimalEnv } from "../lib/claude-path.mjs";

const AGENT = fileURLToPath(new URL("../bin/sagebrush-agent.mjs", import.meta.url));
const skip = process.platform === "win32" ? "POSIX only" : false;
const rootWritable = (Number(lstatSync("/").mode) & 0o022) !== 0;
const skipBind = skip || (rootWritable ? "this host's \"/\" is writable by others, so every real path is refused parent_writable here" : false);
// (the agent's own environment for these rows: no API key or provider, so CLI mode; not the fake model)
const ENV = { PATH: process.env.PATH, HOME: process.env.HOME };
const ORIGIN = "http://127.0.0.1:5";
const PAIR = JSON.stringify({ v: 1, pair: "A".repeat(42) + "A" }) + "\n";

function base() { const b = mkdtempSync(join(tmpdir(), "sb-cpw-")); chmodSync(b, 0o700); return b; }
function exe(dir, name, body) { const p = join(dir, name); writeFileSync(p, body); chmodSync(p, 0o755); return p; }
const run = (args, opts = {}) => spawnSync(process.execPath, [AGENT, ...args], { env: ENV, encoding: "utf8", timeout: 20_000, input: opts.input ?? "", ...opts });

test("claude-path wire: --claude-path-reasons prints exactly the exported list, one JSON line", { skip }, () => {
  const r = run(["--claude-path-reasons"]);
  assert.equal(r.status, 0);
  assert.equal(r.stdout, JSON.stringify(CLAUDE_PATH_REASONS) + "\n");
  assert.equal(run(["--claude-path-reasons", "--port", "0"]).status, 2);
});

test("claude-path wire: --claude-path outside --pair-stdin is refused; the command line and --stdio are unchanged", { skip }, () => {
  for (const extra of [[], ["--stdio"], ["--port", "0"]]) {
    const r = run([...extra, "--claude-path", "/usr/bin/true"]);
    assert.equal(r.status, 2, String(extra));
    assert.match(r.stderr, /--claude-path works only with --pair-stdin/);
    assert.equal(r.stdout, "");
  }
});

test("claude-path wire: a refused path exits 3 with its reason word alone on stderr, before reading stdin or listening", { skip }, () => {
  const b = base();
  const pair = ["--pair-stdin", "--origin", ORIGIN, "--port", "0"];
  const cases = [["relative/claude", "not_absolute"], [join(b, "nope"), "missing"], [b, "not_regular"]];
  for (const [p, word] of cases) {
    const r = run([...pair, "--claude-path", p], { input: PAIR });
    assert.equal(r.status, 3, `${p}: ${r.stderr}`);
    assert.equal(r.stderr, word + "\n");
    assert.equal(r.stdout, "", "never listened");
  }
  rmSync(b, { recursive: true });
});

test("claude-path wire: no fallback: a refused --claude-path never runs the bundled Claude Code or a claude on PATH", { skip }, () => {
  const b = base();
  const marker = join(b, "path-claude-ran");
  exe(b, "claude", `#!/bin/sh\ntouch ${marker}\necho '2.1.330 (Claude Code)'\n`);
  const r = spawnSync(process.execPath, [AGENT, "--pair-stdin", "--origin", ORIGIN, "--port", "0", "--claude-path", join(b, "nope")],
    { env: { ...ENV, PATH: `${b}:${ENV.PATH}` }, encoding: "utf8", input: PAIR, timeout: 20_000 });
  assert.equal(r.status, 3);
  assert.equal(r.stderr, "missing\n");
  assert.equal(existsSync(marker), false, "the claude on PATH never ran");
  rmSync(b, { recursive: true });
});

test("claude-path wire: an API key or provider with --claude-path is refused (it would never run the chosen binary)", { skip }, () => {
  const r = spawnSync(process.execPath, [AGENT, "--pair-stdin", "--origin", ORIGIN, "--port", "0", "--claude-path", "/usr/bin/true"],
    { env: { ...ENV, ANTHROPIC_API_KEY: "sk-test-not-real" }, encoding: "utf8", input: PAIR, timeout: 20_000 });
  assert.equal(r.status, 2);
  assert.match(r.stderr, /--claude-path runs Claude Code with your own Claude login/);
});

test("claude-path wire: on a host with a sane root, a good chosen binary is bound and the agent listens; version variants refuse", { skip: skipBind, timeout: 60_000 }, async () => {
  const b = base();
  const good = exe(b, "claude", "#!/bin/sh\necho '2.1.330 (Claude Code)'\n");
  const listened = await new Promise((resolve) => {
    const c = spawn(process.execPath, [AGENT, "--pair-stdin", "--origin", ORIGIN, "--port", "0", "--claude-path", good], { env: ENV, stdio: ["pipe", "pipe", "pipe"] });
    let out = "";
    c.stdout.on("data", (d) => { out += d; if (out.includes("\n")) { c.stdin.end(); resolve(out); } });
    c.stdin.write(PAIR);
    setTimeout(() => { c.kill(); resolve(out); }, 30_000);
  });
  assert.match(listened, /^\{"v":1,"listening":\d+\}\n$/);
  for (const [body, word] of [["echo '2.1.331 (Claude Code)'", "version_mismatch"], ["echo '2.1.330 (Claude Code) '", "version_unknown"], ["exit 1", "no_answer"]]) {
    const f = exe(b, `c${word}`, `#!/bin/sh\n${body}\n`);
    const r = run(["--pair-stdin", "--origin", ORIGIN, "--port", "0", "--claude-path", f], { input: PAIR });
    assert.equal(r.status, 3, word);
    assert.equal(r.stderr, word + "\n");
  }
  rmSync(b, { recursive: true });
});

// cliQuery with the bin's wiring: the bound path, the built environment, the re-check before every spawn.
async function drain(q) { try { for await (const _ of q) { /* (until the run ends) */ } return null; } catch (e) { return e; } }

test("claude-path wire: identity_changed before a spawn: nothing is spawned and the run ends with that reason", { skip }, async () => {
  const b = base();
  const marker = join(b, "spawned");
  const f = exe(b, "claude", `#!/bin/sh\ntouch ${marker}\n`);
  let rechecks = 0;
  const q = cliQuery({ prompt: "hi", options: {} }, { bin: f, env: minimalEnv(), recheck: () => { rechecks++; throw new ClaudePathError("identity_changed"); } });
  const err = await drain(q);
  assert.equal(rechecks, 1);
  assert.ok(err instanceof ClaudePathError && err.reason === "identity_changed", String(err));
  assert.equal(existsSync(marker), false, "no spawn");
  rmSync(b, { recursive: true });
});

test("claude-path wire: a turn's spawn runs the re-checked path with the built environment only (DISABLE_AUTOUPDATER=1, nothing inherited)", { skip }, async () => {
  const b = base();
  const dump = join(b, "env.txt");
  const f = exe(b, "claude", `#!/bin/sh\n/usr/bin/env > ${dump}\n`);
  process.env.SB_PLANTED_SECRET = "must-not-be-seen";
  let rechecks = 0;
  await drain(cliQuery({ prompt: "hi", options: {} }, { bin: "/nonexistent/not-this", env: minimalEnv(), recheck: () => { rechecks++; return f; } }));
  delete process.env.SB_PLANTED_SECRET;
  assert.equal(rechecks, 1);
  const env = readFileSync(dump, "utf8");
  assert.match(env, /^DISABLE_AUTOUPDATER=1$/m);
  assert.doesNotMatch(env, /SB_PLANTED_SECRET/);
  assert.doesNotMatch(env, /^NODE_/m);
  rmSync(b, { recursive: true });
});

test("claude-path wire: the reason words the bin can print are exactly the list's", { skip }, () => {
  const src = readFileSync(AGENT, "utf8");
  assert.match(src, /console\.error\(e\.reason\); process\.exit\(3\)/);
  assert.ok(!/console\.error\("[a-z_]+"\); process\.exit\(3\)/.test(src), "no reason word outside the list's errors");
});
