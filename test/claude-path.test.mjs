// A bound executable (lib/claude-path.mjs): the checks on real files, the identity re-check, the bounded spawn and the
// version answer. Rows named "claude-path: …". POSIX only.
import assert from "node:assert/strict";
import { test } from "node:test";
import { chmodSync, linkSync, lstatSync, mkdirSync, mkdtempSync, renameSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { bindExecutable, boundedRun, CLAUDE_PATH_REASONS, claudeVersionOf, ClaudePathError, minimalEnv, recheck } from "../lib/claude-path.mjs";

const skip = process.platform === "win32" ? "POSIX only" : false;
const UID = process.getuid?.();
// (this test's computer may have a "/" others can write, as some containers do: "/" is reported as a real host's
//  root 0755; every other folder is the real one)
const realLstat = (p) => lstatSync(p, { bigint: true });
const hostLstat = (p) => {
  const s = realLstat(p);
  if (p !== "/") return s;
  return new Proxy(s, { get: (t, k) => (k === "uid" ? 0n : k === "mode" ? 0o40755n : typeof t[k] === "function" ? t[k].bind(t) : t[k]) });
};
const bind = (p, o = {}) => bindExecutable(p, { lstat: hostLstat, ...o });
const reason = (fn) => { try { fn(); } catch (e) { if (e instanceof ClaudePathError) return e.reason; throw e; } return "ok"; };
const areason = async (p) => { try { await p; } catch (e) { if (e instanceof ClaudePathError) return e.reason; throw e; } return "ok"; };

function base() {
  const b = mkdtempSync(join(tmpdir(), "sb-cp-")); // (/tmp-like: root-owned sticky above, this folder 0700 and ours)
  chmodSync(b, 0o700);
  return b;
}
function exe(dir, name, body = "#!/bin/sh\necho '2.1.330 (Claude Code)'\n", mode = 0o755) {
  const p = join(dir, name);
  writeFileSync(p, body);
  chmodSync(p, mode);
  return p;
}

test("claude-path: the reason list is closed, in the order the app mirrors", { skip }, () => {
  assert.deepEqual([...CLAUDE_PATH_REASONS], ["not_absolute", "missing", "not_regular", "not_executable", "wrong_owner", "writable_by_others",
    "parent_writable", "version_unknown", "version_mismatch", "no_answer", "identity_changed", "unsupported_platform"]);
  assert.ok(Object.isFrozen(CLAUDE_PATH_REASONS));
  assert.throws(() => new ClaudePathError("something_else"));
});

test("claude-path: a good file binds, with its identity", { skip }, () => {
  const b = base(), f = exe(b, "claude");
  const r = bind(f);
  assert.equal(r.path, f);
  assert.equal(r.identity.ino, String(lstatSync(f, { bigint: true }).ino));
  rmSync(b, { recursive: true });
});

test("claude-path: each refusal of the path and the file", { skip }, () => {
  const b = base();
  assert.equal(reason(() => bind("claude")), "not_absolute");
  assert.equal(reason(() => bind("./x/claude")), "not_absolute");
  assert.equal(reason(() => bind(join(b, "nope"))), "missing");
  mkdirSync(join(b, "d"), { mode: 0o700 });
  assert.equal(reason(() => bind(join(b, "d"))), "not_regular");
  assert.equal(reason(() => bind(exe(b, "noexec", "x", 0o644))), "not_executable");
  assert.equal(reason(() => bind(exe(b, "gw", "x", 0o775))), "writable_by_others");
  assert.equal(reason(() => bind(exe(b, "ow", "x", 0o757))), "writable_by_others");
  assert.equal(reason(() => bind(exe(b, "win"), { platform: "win32" })), "unsupported_platform");
  rmSync(b, { recursive: true });
});

test("claude-path: a link given binds its target, once; the link moving later doesn't move the binding", { skip }, () => {
  const b = base(), t1 = exe(b, "claude-a"), t2 = exe(b, "claude-b");
  symlinkSync(t1, join(b, "claude"));
  const r = bind(join(b, "claude"));
  assert.equal(r.path, t1);
  rmSync(join(b, "claude")); symlinkSync(t2, join(b, "claude"));
  assert.equal(recheck(r, { lstat: hostLstat }), t1); // (still the bound target, never re-resolved)
  rmSync(b, { recursive: true });
});

test("claude-path: the target swapped, rewritten, re-moded or removed after binding: identity_changed", { skip }, () => {
  const b = base();
  const f = exe(b, "claude"), r = bind(f);
  writeFileSync(join(b, "other"), "#!/bin/sh\necho x\n"); chmodSync(join(b, "other"), 0o755);
  renameSync(join(b, "other"), f); // (a different inode at the same name)
  assert.equal(reason(() => recheck(r, { lstat: hostLstat })), "identity_changed");
  const g = exe(b, "claude2"), r2 = bind(g);
  writeFileSync(g, "#!/bin/sh\necho changed-and-longer\n"); // (same inode, new size and mtime)
  assert.equal(reason(() => recheck(r2, { lstat: hostLstat })), "identity_changed");
  const h = exe(b, "claude3"), r3 = bind(h);
  chmodSync(h, 0o700);
  assert.equal(reason(() => recheck(r3, { lstat: hostLstat })), "identity_changed");
  const k = exe(b, "claude4"), r4 = bind(k);
  rmSync(k); symlinkSync(join(b, "claude"), k); // (now a link at the bound path)
  assert.equal(reason(() => recheck(r4, { lstat: hostLstat })), "identity_changed");
  const m = exe(b, "claude5"), r5 = bind(m);
  rmSync(m);
  assert.equal(reason(() => recheck(r5, { lstat: hostLstat })), "identity_changed");
  rmSync(b, { recursive: true });
});

test("claude-path: each ancestor case", { skip }, () => {
  const b = base();
  mkdirSync(join(b, "gw"), { mode: 0o700 }); chmodSync(join(b, "gw"), 0o775);
  assert.equal(reason(() => bind(exe(join(b, "gw"), "claude"))), "parent_writable");
  mkdirSync(join(b, "up", "in"), { recursive: true, mode: 0o700 }); chmodSync(join(b, "up"), 0o777);
  assert.equal(reason(() => bind(exe(join(b, "up", "in"), "claude"))), "parent_writable");
  // (a root-owned sticky folder: allowed ABOVE the file's own folder, never as it: /tmp/x/claude binds, /tmp/claude doesn't)
  const sticky = (p) => { const s = realLstat(p); return p === b ? new Proxy(s, { get: (t, k) => (k === "uid" ? 0n : k === "mode" ? 0o41777n : typeof t[k] === "function" ? t[k].bind(t) : t[k]) }) : hostLstat(p); };
  mkdirSync(join(b, "mine"), { mode: 0o700 });
  assert.equal(reason(() => bindExecutable(exe(join(b, "mine"), "claude"), { lstat: sticky })), "ok");
  assert.equal(reason(() => bindExecutable(exe(b, "claude-in-sticky"), { lstat: sticky })), "parent_writable");
  // (the same folder sticky but NOT root's: refused)
  const userSticky = (p) => { const s = realLstat(p); return p === b ? new Proxy(s, { get: (t, k) => (k === "mode" ? 0o41777n : typeof t[k] === "function" ? t[k].bind(t) : t[k]) }) : hostLstat(p); };
  assert.equal(reason(() => bindExecutable(join(b, "mine", "claude"), { lstat: userSticky })), "parent_writable");
  // (the real "/" of this computer, as it is: a host whose root others can write refuses everything below it)
  if ((Number(realLstat("/").mode) & 0o022) !== 0) assert.equal(reason(() => bindExecutable(join(b, "mine", "claude"))), "parent_writable");
  rmSync(b, { recursive: true });
});

test("claude-path: another owner, of the file or of a folder above: wrong_owner; root is fine", { skip }, () => {
  const b = base(); mkdirSync(join(b, "x"), { mode: 0o700 });
  const f = exe(join(b, "x"), "claude");
  const owner = (who, uid) => (p) => { const s = hostLstat(p); return p === who ? new Proxy(s, { get: (t, k) => (k === "uid" ? BigInt(uid) : typeof t[k] === "function" ? t[k].bind(t) : t[k]) }) : s; };
  assert.equal(reason(() => bindExecutable(f, { lstat: owner(f, 4242) })), "wrong_owner");
  assert.equal(reason(() => bindExecutable(f, { lstat: owner(join(b, "x"), 4242) })), "wrong_owner");
  assert.equal(reason(() => bindExecutable(f, { lstat: owner(f, 0) })), "ok");
  assert.equal(reason(() => bindExecutable(f, { lstat: owner(join(b, "x"), 0) })), "ok");
  rmSync(b, { recursive: true });
});

test("claude-path: the version answer: exact (with or without one newline); every variant refused", { skip }, async () => {
  const b = base(); const S = ["2.1.330"];
  const v = async (out) => areason(claudeVersionOf(bind(exe(b, `c${Math.random().toString(16).slice(2)}`, `#!/bin/sh\nprintf '${out}'\n`)), S, { lstat: hostLstat }));
  assert.equal(await v("2.1.330 (Claude Code)\\n"), "ok");
  assert.equal(await v("2.1.330 (Claude Code)"), "ok");
  assert.equal(await v("2.1.330 (Claude Code) \\n"), "version_unknown");
  assert.equal(await v("2.1.330 (Claude Code)\\n\\n"), "version_unknown");
  assert.equal(await v("2.1.330 (Claude Code)\\nextra\\n"), "version_unknown");
  assert.equal(await v(" 2.1.330 (Claude Code)\\n"), "version_unknown");
  assert.equal(await v("2.1.330 (claude code)\\n"), "version_unknown");
  assert.equal(await v(""), "version_unknown");
  assert.equal(await v("2.1.331 (Claude Code)\\n"), "version_mismatch");
  const fail = exe(b, "fails", "#!/bin/sh\necho '2.1.330 (Claude Code)'\nexit 1\n");
  assert.equal(await areason(claudeVersionOf(bind(fail), S, { lstat: hostLstat })), "no_answer");
  rmSync(b, { recursive: true });
});

test("claude-path: a hang past 5 s is no_answer, with its whole process group killed", { skip, timeout: 20_000 }, async () => {
  const b = base();
  const pidFile = join(b, "grandchild.pid");
  const f = exe(b, "hang", `#!/bin/sh\nsleep 60 & echo $! > ${pidFile}\nsleep 60\n`);
  const t0 = Date.now();
  assert.equal(await areason(claudeVersionOf(bind(f), ["2.1.330"], { lstat: hostLstat })), "no_answer");
  const took = Date.now() - t0;
  assert.ok(took >= 4900 && took < 9000, `took ${took} ms`);
  const gc = Number(String(await import("node:fs").then((m) => m.readFileSync(pidFile, "utf8"))).trim());
  let alive = true; try { process.kill(gc, 0); } catch { alive = false; }
  assert.equal(alive, false, "the grandchild in the group is gone");
  rmSync(b, { recursive: true });
});

test("claude-path: more than 4 KiB of answer is version_unknown, the group killed at once", { skip, timeout: 10_000 }, async () => {
  const b = base();
  const f = exe(b, "big", "#!/bin/sh\nhead -c 5000 /dev/zero | tr '\\\\0' x\nsleep 30\n");
  const t0 = Date.now();
  assert.equal(await areason(claudeVersionOf(bind(f), ["2.1.330"], { lstat: hostLstat })), "version_unknown");
  assert.ok(Date.now() - t0 < 4000, "ended on the overflow, not the deadline");
  rmSync(b, { recursive: true });
});

test("claude-path: the spawn's environment is built, nothing inherited; DISABLE_AUTOUPDATER=1; no shell; stdin closed", { skip }, async () => {
  const b = base();
  process.env.SB_PLANTED_SECRET = "must-not-be-seen";
  const f = exe(b, "envdump", "#!/bin/sh\nenv | sort\nread x && echo GOT-STDIN || echo STDIN-CLOSED\n");
  const r = await boundedRun(f, [], { env: minimalEnv() });
  delete process.env.SB_PLANTED_SECRET;
  const keys = r.stdout.split("\n").filter((l) => l.includes("=")).map((l) => l.split("=")[0]).filter((k) => k !== "PWD" && k !== "SHLVL" && k !== "_");
  assert.deepEqual(keys.sort(), ["DISABLE_AUTOUPDATER", "HOME", "LOGNAME", "PATH", "TMPDIR", "USER"]);
  assert.match(r.stdout, /^DISABLE_AUTOUPDATER=1$/m);
  assert.doesNotMatch(r.stdout, /SB_PLANTED_SECRET/);
  assert.match(r.stdout, /STDIN-CLOSED/);
  const shell = await boundedRun(f + " ; echo injected", [], { env: minimalEnv() });
  assert.equal(shell.failed || shell.code !== 0, true, "a path is never handed to a shell");
  rmSync(b, { recursive: true });
});

test("claude-path: the version check re-checks the identity first, and spawns nothing on a change", { skip }, async () => {
  const b = base();
  const marker = join(b, "ran");
  const f = exe(b, "claude", `#!/bin/sh\ntouch ${marker}\necho '2.1.330 (Claude Code)'\n`);
  const r = bind(f);
  writeFileSync(f, `#!/bin/sh\ntouch ${marker}\necho '2.1.330 (Claude Code)'  \n`);
  let spawned = 0;
  assert.equal(await areason(claudeVersionOf(r, ["2.1.330"], { lstat: hostLstat, run: async () => { spawned++; return { code: 0, stdout: "" }; } })), "identity_changed");
  assert.equal(spawned, 0);
  rmSync(b, { recursive: true });
});

test("claude-path: a hard link to the bound file from elsewhere doesn't change its identity (same inode)", { skip }, () => {
  const b = base(); const f = exe(b, "claude"); const r = bind(f);
  linkSync(f, join(b, "second-name"));
  // (the link count changes, but the identity is device, inode, size, mtime, mode and owner: unchanged)
  assert.equal(reason(() => recheck(r, { lstat: hostLstat })), "ok");
  rmSync(b, { recursive: true });
});
