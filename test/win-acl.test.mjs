// Windows privacy of the Codex and runner caches (lib/win-acl.mjs): the verdict on an access list by SID, the
// PowerShell reader (a stand-in run here; the real one on win32 only), and how codex-fetch and runner-fetch use it.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { aclVerdict, powershellPath, TRUSTED, windowsPrivateProblem } from "../lib/win-acl.mjs";
import { cacheRoot, CodexFetchError, platformKey, privateDirs as codexPrivateDirs, treeMatches } from "../lib/codex-fetch.mjs";
import { privateDirs as runnerPrivateDirs, runnerCacheRoot } from "../lib/runner-fetch.mjs";

const ME = "S-1-5-21-1111111111-2222222222-3333333333-1001";
const OTHER = "S-1-5-21-1111111111-2222222222-3333333333-1002";
const allow = (sid, extra = {}) => ({ sid, type: "Allow", rights: 2032127, inheritOnly: false, ...extra });
// (what a folder under %LOCALAPPDATA% has by default: this account, SYSTEM and Administrators, inherited)
const DEFAULT = { owner: ME, rules: [allow(ME), allow(TRUSTED.SYSTEM), allow(TRUSTED.ADMINISTRATORS)] };

test("the verdict: only this account, SYSTEM and Administrators may hold access; the owner is this account or Administrators", () => {
  assert.equal(aclVerdict(DEFAULT, ME), null);
  assert.equal(aclVerdict({ ...DEFAULT, owner: TRUSTED.ADMINISTRATORS }, ME), null, "what an elevated administrator makes");
  assert.match(aclVerdict({ ...DEFAULT, owner: OTHER }, ME), /owned by S-1-5-21-.*-1002, not this account/);
  for (const [who, sid] of [["Everyone", "S-1-1-0"], ["Users", "S-1-5-32-545"], ["Authenticated Users", "S-1-5-11"], ["another account", OTHER], ["Guests", "S-1-5-32-546"]]) {
    assert.match(aclVerdict({ ...DEFAULT, rules: [...DEFAULT.rules, allow(sid, { rights: 1179817 })] }, ME), new RegExp(`gives access to ${sid}`), who);
    // (inherit-only: the folder's new children get it, so it counts)
    assert.match(aclVerdict({ ...DEFAULT, rules: [...DEFAULT.rules, allow(sid, { inheritOnly: true })] }, ME), /gives access/, `${who}, inherit-only`);
  }
  // (CREATOR OWNER, inherit-only, becomes each child's creator; on the folder itself it would be a grant to a placeholder)
  assert.equal(aclVerdict({ ...DEFAULT, rules: [...DEFAULT.rules, allow("S-1-3-0", { inheritOnly: true })] }, ME), null);
  assert.match(aclVerdict({ ...DEFAULT, rules: [...DEFAULT.rules, allow("S-1-3-0")] }, ME), /gives access to S-1-3-0/);
  // (a Deny takes nothing away from privacy; an Allow of no rights grants nothing)
  assert.equal(aclVerdict({ ...DEFAULT, rules: [...DEFAULT.rules, { sid: "S-1-1-0", type: "Deny", rights: 2032127, inheritOnly: false }] }, ME), null);
  assert.equal(aclVerdict({ ...DEFAULT, rules: [...DEFAULT.rules, allow("S-1-1-0", { rights: 0 })] }, ME), null);
});

test("the verdict: anything that isn't read as expected is a problem, never a pass", () => {
  for (const [what, item, user] of [
    ["no item", null, ME], ["no rules", { owner: ME }, ME], ["no user", DEFAULT, undefined], ["a user that isn't a SID", DEFAULT, "BUILTIN\\Users"],
    ["a rule without a SID", { owner: ME, rules: [{ type: "Allow", rights: 1 }] }, ME], ["a name, not a SID", { owner: ME, rules: [allow("Everyone")] }, ME],
    ["an unknown type", { owner: ME, rules: [{ sid: ME, type: "Audit", rights: 1 }] }, ME], ["rights not a number", { owner: ME, rules: [{ sid: ME, type: "Allow", rights: "FullControl" }] }, ME],
  ]) assert.match(aclVerdict(item, user) ?? "", /couldn't be read|owned by/, what);
});

// (a stand-in for spawnSync: records the call, answers as Get-Acl's script would)
const fake = (answer) => { const calls = []; const run = (cmd, args, opts) => { calls.push({ cmd, args, opts }); return typeof answer === "function" ? answer(JSON.parse(opts.input)) : answer; }; return { run, calls }; };
const ok = (paths, items) => ({ status: 0, stdout: JSON.stringify({ user: ME, items: items ?? paths.map((path) => ({ path, ...DEFAULT })) }) });

test("the reader: Windows PowerShell by its absolute System32 path (never PATH), the script encoded, the paths on stdin; one call for all", () => {
  const f = fake((paths) => ok(paths));
  assert.equal(windowsPrivateProblem(["C:\\a\\sagebrush-agent", "C:\\a\\sagebrush-agent\\codex"], { run: f.run, env: { SystemRoot: "D:\\WINDOWS" } }), null);
  assert.equal(f.calls.length, 1);
  assert.equal(f.calls[0].cmd, "D:\\WINDOWS\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
  assert.deepEqual(f.calls[0].args.slice(0, 5), ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand"]);
  const script = Buffer.from(f.calls[0].args[5], "base64").toString("utf16le");
  assert.match(script, /Get-Acl -LiteralPath \$p/);
  assert.match(script, /GetAccessRules\(\$true, \$true, \$sid\)/);
  assert.match(script, /GetOwner\(\$sid\)/);
  assert.deepEqual(JSON.parse(f.calls[0].opts.input), ["C:\\a\\sagebrush-agent", "C:\\a\\sagebrush-agent\\codex"]);
  // (%SystemRoot% that isn't a drive's absolute path: C:\Windows, never a relative or odd one)
  for (const SystemRoot of [undefined, "Windows", "\\\\server\\share", "C:\\x\"&calc"]) assert.equal(powershellPath({ SystemRoot }), "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", String(SystemRoot));
});

test("the reader: a folder that isn't private is named; every failure to read is a problem", () => {
  const paths = ["C:\\a", "C:\\a\\b"];
  assert.match(windowsPrivateProblem(paths, { run: fake(ok(paths, [{ path: paths[0], ...DEFAULT }, { path: paths[1], owner: ME, rules: [...DEFAULT.rules, allow("S-1-1-0")] }])).run }), /^C:\\a\\b: it gives access to S-1-1-0$/);
  // (PowerShell's ConvertTo-Json writes a one-element list, and one rule, as a bare object: still read)
  assert.equal(windowsPrivateProblem(["C:\\a"], { run: fake({ status: 0, stdout: JSON.stringify({ user: ME, items: { path: "C:\\a", owner: ME, rules: allow(ME) } }) }).run }), null);
  for (const [what, answer] of [
    ["PowerShell missing", { error: Object.assign(new Error("spawn"), { code: "ENOENT" }) }], ["a timeout", { error: Object.assign(new Error("t"), { code: "ETIMEDOUT" }) }],
    ["an exit code", { status: 1, stdout: "" }], ["not JSON", { status: 0, stdout: "Get-Acl : Access is denied" }], ["an answer missing", ok(paths, [{ path: paths[0], ...DEFAULT }])],
    ["answers out of order", ok(paths, [{ path: paths[1], ...DEFAULT }, { path: paths[0], ...DEFAULT }])], ["no user", { status: 0, stdout: JSON.stringify({ items: paths.map((path) => ({ path, ...DEFAULT })) }) }],
  ]) assert.ok(windowsPrivateProblem(paths, { run: fake(answer).run }), what);
  assert.match(windowsPrivateProblem(paths, { run: () => { throw new Error("boom"); } }), /couldn't be read/);
});

test("codex-fetch on Windows: win32-x64 is a platform, the cache under %LOCALAPPDATA%, its folders checked by owner and access list (both, once), never by mode", () => {
  assert.equal(platformKey("win32", "x64"), "win32-x64");
  assert.equal(platformKey("win32", "arm64"), null);
  assert.equal(cacheRoot({ LOCALAPPDATA: "C:\\Users\\u\\AppData\\Local" }, "win32", "C:\\Users\\u"), "C:\\Users\\u\\AppData\\Local\\sagebrush-agent\\codex");
  assert.equal(cacheRoot({ LOCALAPPDATA: "relative\\x" }, "win32", "C:\\Users\\u"), "C:\\Users\\u\\AppData\\Local\\sagebrush-agent\\codex");
  assert.equal(runnerCacheRoot({ LOCALAPPDATA: "E:\\L" }, "win32", "C:\\Users\\u"), "E:\\L\\sagebrush-agent\\runner");
  const d = mkdtempSync(join(tmpdir(), "sb-winacl-"));
  try {
    for (const [name, check, Err] of [["codex", codexPrivateDirs, CodexFetchError], ["runner", runnerPrivateDirs, Error]]) {
      const root = join(d, name, "sagebrush-agent", "cache");
      mkdirSync(join(d, name), { recursive: true });
      const seen = [];
      check(root, { platform: "win32", acl: (dirs) => { seen.push(dirs); return null; } });
      assert.equal(seen.length, 1, `${name}: one ACL read`);
      assert.equal(seen[0].length, 2);
      // (on Windows mode bits mean nothing: a 0755 folder isn't refused for its mode, only by its access list)
      chmodSync(root, 0o755);
      check(root, { platform: "win32", acl: () => null });
      assert.throws(() => check(root, { platform: "win32", acl: () => "C:\\x: it gives access to S-1-1-0" }), (e) => e instanceof Err && /isn't a private (directory|folder) of this account: C:\\x: it gives access to S-1-1-0/.test(e.message), name);
      // (and POSIX as before: 0755 refused, without any ACL read)
      assert.throws(() => check(root, { platform: "linux", acl: () => { throw new Error("not on POSIX"); } }), /isn't a private/, `${name} on POSIX`);
    }
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test("treeMatches on Windows: sizes, sha256, kinds and nothing extra, without the POSIX modes", () => {
  const d = mkdtempSync(join(tmpdir(), "sb-wintree-"));
  try {
    mkdirSync(join(d, "bin"), { mode: 0o755 });
    writeFileSync(join(d, "bin", "codex.exe"), "MZ");
    chmodSync(join(d, "bin", "codex.exe"), 0o666);
    const files = { "bin/codex.exe": { size: 2, sha256: createHash("sha256").update("MZ").digest("hex"), exec: true } };
    chmodSync(d, 0o777);
    assert.equal(treeMatches(d, files, { platform: "win32" }), true);
    assert.equal(treeMatches(d, files, { platform: "linux" }), false, "on POSIX the modes still count");
    writeFileSync(join(d, "bin", "extra.dll"), "x");
    assert.equal(treeMatches(d, files, { platform: "win32" }), false, "nothing extra");
    rmSync(join(d, "bin", "extra.dll"));
    writeFileSync(join(d, "bin", "codex.exe"), "MX");
    assert.equal(treeMatches(d, files, { platform: "win32" }), false, "other bytes");
  } finally { rmSync(d, { recursive: true, force: true }); }
});

// (the real thing, on Windows only: a fresh folder under %LOCALAPPDATA% is private; granting Everyone makes it not)
const WIN = process.platform === "win32" ? {} : { skip: "a real access list: Windows only" };
test("on Windows: a new folder under %LOCALAPPDATA% is private by its real access list; granted to Everyone, it isn't", WIN, () => {
  const d = mkdtempSync(join(process.env.LOCALAPPDATA, "sb-winacl-"));
  try {
    assert.equal(windowsPrivateProblem([d]), null);
    const g = spawnSync(join(process.env.SystemRoot, "System32", "icacls.exe"), [d, "/grant", "*S-1-1-0:(OI)(CI)R"], { encoding: "utf8" });
    assert.equal(g.status, 0, g.stderr);
    assert.match(windowsPrivateProblem([d]) ?? "", /gives access to S-1-1-0/);
  } finally { rmSync(d, { recursive: true, force: true }); }
});
