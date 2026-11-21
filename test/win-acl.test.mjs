// Windows privacy of the Codex and runner caches (lib/win-acl.mjs): the verdict on an access list by SID, the
// PowerShell reader (a stand-in run here; the real one on win32 only), and how codex-fetch and runner-fetch use it.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { aclVerdict, daclState, powershellEnv, powershellPath, TRUSTED, windowsPrivateProblem } from "../lib/win-acl.mjs";
import { cacheRoot, CodexFetchError, platformKey, privateDirs as codexPrivateDirs, treeMatches } from "../lib/codex-fetch.mjs";
import { privateDirs as runnerPrivateDirs, runnerCacheRoot } from "../lib/runner-fetch.mjs";

const ME = "S-1-5-21-1111111111-2222222222-3333333333-1001";
const OTHER = "S-1-5-21-1111111111-2222222222-3333333333-1002";
const allow = (sid, extra = {}) => ({ sid, type: "Allow", rights: 2032127, inheritOnly: false, ...extra });
// (what a folder under %LOCALAPPDATA% has by default: this account, SYSTEM and Administrators, inherited)
const DEFAULT = { owner: ME, dacl: `D:AI(A;OICIID;FA;;;${ME})(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)`, rules: [allow(ME), allow(TRUSTED.SYSTEM), allow(TRUSTED.ADMINISTRATORS)] };

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

test("the verdict: a null or absent DACL (everyone may do anything) is never private, whatever the rules list says", () => {
  assert.equal(daclState(DEFAULT.dacl), "present");
  assert.equal(daclState("D:"), "present", "an empty DACL: no one but the owner's implicit rights");
  assert.equal(daclState("D:NO_ACCESS_CONTROL"), "null");
  assert.equal(daclState("D:PNO_ACCESS_CONTROL"), "null");
  assert.equal(daclState(""), "absent");
  for (const x of [undefined, null, 7, "O:BA", "S:(AU;SA;FA;;;WD)"]) assert.equal(daclState(x), "unreadable", String(x));
  // (as Get-Acl reads a null DACL: no rules at all; it must not pass as "nothing granted")
  for (const dacl of ["D:NO_ACCESS_CONTROL", "", undefined, "garbage"]) {
    for (const rules of [[], DEFAULT.rules]) assert.ok(aclVerdict({ owner: ME, dacl, rules }, ME), `${dacl} with ${rules.length} rules`);
  }
  assert.match(aclVerdict({ owner: ME, dacl: "D:NO_ACCESS_CONTROL", rules: [] }, ME), /a null access list, so anyone may use it/);
  assert.match(aclVerdict({ owner: ME, dacl: "", rules: [] }, ME), /no access list, so anyone may use it/);
  assert.equal(aclVerdict({ owner: ME, dacl: "D:P", rules: [] }, ME), null, "a present, empty DACL grants no one");
  // (through the reader: an answer without the dacl field, as before this check, is refused)
  assert.ok(windowsPrivateProblem(["C:\\cache"], { run: () => ({ status: 0, stdout: JSON.stringify({ user: ME, items: [{ path: "C:\\cache", owner: ME, rules: [] }] }) }) }));
  assert.match(windowsPrivateProblem(["C:\\cache"], { run: () => ({ status: 0, stdout: JSON.stringify({ user: ME, items: [{ path: "C:\\cache", owner: ME, dacl: "D:NO_ACCESS_CONTROL", rules: [] }] }) }) }), /^C:\\cache: it has a null access list/);
});

// (a stand-in for spawnSync: records the call, answers as Get-Acl's script would)
const fake = (answer) => { const calls = []; const run = (cmd, args, opts) => { calls.push({ cmd, args, opts }); return typeof answer === "function" ? answer(JSON.parse(opts.input)) : answer; }; return { run, calls }; };
const ok = (paths, items) => ({ status: 0, stdout: JSON.stringify({ user: ME, items: items ?? paths.map((path) => ({ path, ...DEFAULT })) }) });

test("the reader: Windows PowerShell by its absolute System32 path (never PATH), the script encoded, the paths on stdin; one call for all", () => {
  const f = fake((paths) => ok(paths));
  assert.equal(windowsPrivateProblem(["C:\\a\\sagebrush-agent", "C:\\a\\sagebrush-agent\\codex"], { run: f.run, env: { SystemRoot: "D:\\WINDOWS", PSModulePath: "C:\\Program Files\\PowerShell\\7\\Modules", X: "1" } }), null);
  assert.equal(f.calls.length, 1);
  assert.equal(f.calls[0].cmd, "D:\\WINDOWS\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
  assert.deepEqual(f.calls[0].args.slice(0, 5), ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand"]);
  const script = Buffer.from(f.calls[0].args[5], "base64").toString("utf16le");
  assert.match(script, /Get-Acl -LiteralPath \$p/);
  assert.match(script, /GetAccessRules\(\$true, \$true, \$sid\)/);
  assert.match(script, /GetOwner\(\$sid\)/);
  // (the paths unrolled: Windows PowerShell 5.1's ConvertFrom-Json gives a JSON list as one object; seen on Windows)
  assert.match(script, /\| ConvertFrom-Json \| ForEach-Object \{ \$_ \}\)/);
  // (without the caller's PSModulePath: started from PowerShell 7, Windows PowerShell couldn't load Get-Acl; seen on Windows)
  assert.deepEqual(f.calls[0].opts.env, { SystemRoot: "D:\\WINDOWS", X: "1" });
  assert.match(script, /GetSecurityDescriptorSddlForm\(\[System\.Security\.AccessControl\.AccessControlSections\]::Access\)/);
  assert.deepEqual(JSON.parse(f.calls[0].opts.input), ["C:\\a\\sagebrush-agent", "C:\\a\\sagebrush-agent\\codex"]);
  // (%SystemRoot% that isn't a drive's absolute path: C:\Windows, never a relative or odd one)
  for (const SystemRoot of [undefined, "Windows", "\\\\server\\share", "C:\\x\"&calc"]) assert.equal(powershellPath({ SystemRoot }), "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", String(SystemRoot));
});

test("powershellEnv: the environment without PSModulePath, in any letter case; the rest kept, the original unchanged", () => {
  const env = { Path: "C:\\x", PSModulePath: "a", psmodulepath: "b", SystemRoot: "C:\\Windows" };
  assert.deepEqual(powershellEnv(env), { Path: "C:\\x", SystemRoot: "C:\\Windows" });
  assert.equal(env.PSModulePath, "a");
});

test("the reader: a folder that isn't private is named; every failure to read is a problem", () => {
  const paths = ["C:\\a", "C:\\a\\b"];
  assert.match(windowsPrivateProblem(paths, { run: fake(ok(paths, [{ path: paths[0], ...DEFAULT }, { path: paths[1], ...DEFAULT, rules: [...DEFAULT.rules, allow("S-1-1-0")] }])).run }), /^C:\\a\\b: it gives access to S-1-1-0$/);
  // (PowerShell's ConvertTo-Json writes a one-element list, and one rule, as a bare object: still read)
  assert.equal(windowsPrivateProblem(["C:\\a"], { run: fake({ status: 0, stdout: JSON.stringify({ user: ME, items: { path: "C:\\a", owner: ME, dacl: DEFAULT.dacl, rules: allow(ME) } }) }).run }), null);
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

test("treeMatches on Windows: sizes, sha256, kinds and nothing extra, without the POSIX modes; every folder and file private by its own access list", () => {
  const d = mkdtempSync(join(tmpdir(), "sb-wintree-"));
  try {
    mkdirSync(join(d, "bin", "res"), { recursive: true, mode: 0o755 });
    writeFileSync(join(d, "bin", "codex.exe"), "MZ");
    writeFileSync(join(d, "bin", "res", "rg.exe"), "RG");
    chmodSync(join(d, "bin", "codex.exe"), 0o666);
    const sha = (t) => createHash("sha256").update(t).digest("hex");
    const files = { "bin/codex.exe": { size: 2, sha256: sha("MZ"), exec: true }, "bin/res/rg.exe": { size: 2, sha256: sha("RG"), exec: true } };
    chmodSync(d, 0o777);
    const seen = [];
    const acl = (paths) => { seen.push(paths); return null; };
    assert.equal(treeMatches(d, files, { platform: "win32", acl }), true);
    // (one read, for the tree's own folder, each folder in it and each file: a parent's list says nothing of a child's)
    assert.equal(seen.length, 1);
    assert.deepEqual(seen[0], [d, join(d, "bin"), join(d, "bin", "res"), join(d, "bin", "codex.exe"), join(d, "bin", "res", "rg.exe")]);
    // (a permissive descendant, the root and its parents private: not a match)
    for (const bad of seen[0]) {
      assert.equal(treeMatches(d, files, { platform: "win32", acl: (paths) => (paths.includes(bad) ? `${bad}: it gives access to S-1-1-0` : null) }), false, bad);
    }
    assert.equal(treeMatches(d, files, { platform: "win32", acl: () => "its access list couldn't be read" }), false, "unreadable: no match");
    assert.equal(treeMatches(d, files, { platform: "linux", acl: () => { throw new Error("not on POSIX"); } }), false, "on POSIX the modes still count, and no ACL is read");
    writeFileSync(join(d, "bin", "extra.dll"), "x");
    assert.equal(treeMatches(d, files, { platform: "win32", acl }), false, "nothing extra");
    rmSync(join(d, "bin", "extra.dll"));
    writeFileSync(join(d, "bin", "codex.exe"), "MX");
    assert.equal(treeMatches(d, files, { platform: "win32", acl }), false, "other bytes");
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
const ps = (script) => spawnSync(powershellPath(), ["-NoProfile", "-NonInteractive", "-Command", "-"], { input: script, env: powershellEnv(), encoding: "utf8" });
test("on Windows: a folder given a null DACL (everyone may do anything) isn't private", WIN, () => {
  const d = mkdtempSync(join(process.env.LOCALAPPDATA, "sb-winacl-null-"));
  try {
    assert.equal(windowsPrivateProblem([d]), null);
    const r = ps(`$a = Get-Acl -LiteralPath '${d}'; $a.SetSecurityDescriptorSddlForm('D:NO_ACCESS_CONTROL', [System.Security.AccessControl.AccessControlSections]::Access); Set-Acl -LiteralPath '${d}' -AclObject $a\n`);
    assert.equal(r.status, 0, r.stderr);
    assert.ok(windowsPrivateProblem([d]), "a null DACL is refused");
  } finally { rmSync(d, { recursive: true, force: true }); }
});
test("on Windows: a file in a private folder, given its own grant to Everyone, fails the tree check", WIN, () => {
  const d = mkdtempSync(join(process.env.LOCALAPPDATA, "sb-wintree-"));
  try {
    mkdirSync(join(d, "bin"));
    writeFileSync(join(d, "bin", "codex.exe"), "MZ");
    const files = { "bin/codex.exe": { size: 2, sha256: createHash("sha256").update("MZ").digest("hex"), exec: true } };
    assert.equal(treeMatches(d, files), true);
    const g = spawnSync(join(process.env.SystemRoot, "System32", "icacls.exe"), [join(d, "bin", "codex.exe"), "/grant", "*S-1-1-0:(M)"], { encoding: "utf8" });
    assert.equal(g.status, 0, g.stderr);
    assert.equal(windowsPrivateProblem([d, join(d, "bin")]), null, "its folders are still private");
    assert.equal(treeMatches(d, files), false, "the file's own grant fails the tree");
  } finally { rmSync(d, { recursive: true, force: true }); }
});
