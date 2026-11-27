// A bound executable (lib/claude-path.mjs): the checks on real files, the identity re-check, the bounded spawn and the
// version answer. Rows named "claude-path: …". POSIX only.
import assert from "node:assert/strict";
import { test } from "node:test";
import { spawn, spawnSync } from "node:child_process";
import { chmodSync, existsSync, linkSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, renameSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { bindExecutable, boundedRun, heldSpawn, CLAUDE_PATH_REASONS, claudeVersionOf, ClaudePathError, minimalEnv, recheck } from "../lib/claude-path.mjs";

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
// (the spawn environment as on a real host: PATH qualified against the same host view of "/")
const envT = () => minimalEnv({ lstat: hostLstat });
const reason = (fn) => { try { fn(); } catch (e) { if (e instanceof ClaudePathError) return e.reason; throw e; } return "ok"; };
const areason = async (p) => { try { await p; } catch (e) { if (e instanceof ClaudePathError) return e.reason; throw e; } return "ok"; };

// (a killed process is gone once it's absent or a zombie waiting for init to reap it: a zombie still answers kill(pid, 0),
//  and under load init can take a moment; up to 2 s)
async function gone(pid) {
  for (let i = 0; i < 100; i++) {
    let state = null;
    try { state = readFileSync(`/proc/${pid}/stat`, "utf8").replace(/^.*\) /, "")[0]; } catch {
      let alive = true; try { process.kill(pid, 0); } catch { alive = false; }
      if (!alive) return true;
    }
    if (state === "Z") return true;
    await new Promise((r) => setTimeout(r, 20));
  }
  return false;
}
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

test("claude-path: the version answer: exactly '<v> (Claude Code)\n', as the app checks it; every variant refused", { skip }, async () => {
  const b = base(); const S = ["2.1.330"];
  const v = async (body) => areason(claudeVersionOf(bind(exe(b, `c${Math.random().toString(16).slice(2)}`, `#!/bin/sh\n${body}\n`)), S, { lstat: hostLstat, env: envT() }));
  const pf = (out) => v(`printf '${out}'`);
  assert.equal(await pf("2.1.330 (Claude Code)\\n"), "ok");
  assert.equal(await pf("2.1.330 (Claude Code)"), "version_unknown", "the newline is required");
  assert.equal(await pf("2.1.330 (Claude Code) \\n"), "version_unknown");
  assert.equal(await pf("2.1.330 (Claude Code)\\r\\n"), "version_unknown");
  assert.equal(await pf("2.1.330 (Claude Code)\\n\\n"), "version_unknown");
  assert.equal(await pf("2.1.330 (Claude Code)\\nextra\\n"), "version_unknown");
  assert.equal(await pf(" 2.1.330 (Claude Code)\\n"), "version_unknown");
  assert.equal(await pf("2.1.330 (claude code)\\n"), "version_unknown");
  assert.equal(await pf("02.1.330 (Claude Code)\\n"), "version_unknown", "a leading zero");
  assert.equal(await pf("2.01.330 (Claude Code)\\n"), "version_unknown", "a leading zero");
  assert.equal(await pf("2.1.1234567 (Claude Code)\\n"), "version_unknown", "seven digits");
  assert.equal(await pf(""), "version_unknown");
  assert.equal(await pf("2.1.331 (Claude Code)\\n"), "version_mismatch");
  assert.equal(await pf("2.0.330 (Claude Code)\\n"), "version_mismatch");
  assert.equal(await v("echo '2.1.330 (Claude Code)'; exit 1"), "no_answer", "a non-zero exit, even with a good answer");
  assert.equal(await v("echo '2.1.330 (Claude Code)'; echo 'some warning' >&2"), "ok", "stderr within its cap is ignored");
  assert.equal(await v("echo '2.1.330 (Claude Code)'; head -c 5000 /dev/zero | tr '\\\\0' x >&2"), "version_unknown", "stderr over its cap");
  rmSync(b, { recursive: true });
});

test("claude-path: the caps: 4096 bytes accepted, 4097 refused, on stdout and on stderr", { skip, timeout: 20_000 }, async () => {
  const b = base();
  for (const [n, over] of [[4096, false], [4097, true]]) for (const fd of ["", " >&2"]) {
    const f = exe(b, `cap${n}${fd ? "e" : "o"}`, `#!/bin/sh\nhead -c ${n} /dev/zero | tr '\\\\0' x${fd}\n`);
    const r = await boundedRun(f, [], { env: envT() });
    assert.equal(r.overflow, over, `${n} bytes on ${fd ? "stderr" : "stdout"}`);
  }
  rmSync(b, { recursive: true });
});

test("claude-path: a hang past 5 s is no_answer, with its whole process group killed", { skip, timeout: 20_000 }, async () => {
  const b = base();
  const pidFile = join(b, "grandchild.pid");
  const f = exe(b, "hang", `#!/bin/sh\nsleep 60 & echo $! > ${pidFile}\nsleep 60\n`);
  const t0 = Date.now();
  assert.equal(await areason(claudeVersionOf(bind(f), ["2.1.330"], { lstat: hostLstat, env: envT() })), "no_answer");
  const took = Date.now() - t0;
  assert.ok(took >= 4900 && took < 9000, `took ${took} ms`);
  const gc = Number(readFileSync(pidFile, "utf8").trim());
  assert.equal(await gone(gc), true, "the grandchild in the group is gone");
  rmSync(b, { recursive: true });
});

test("claude-path: more than 4 KiB of answer is version_unknown, the group killed at once", { skip, timeout: 10_000 }, async () => {
  const b = base();
  const f = exe(b, "big", "#!/bin/sh\nhead -c 5000 /dev/zero | tr '\\\\0' x\nsleep 30\n");
  const t0 = Date.now();
  assert.equal(await areason(claudeVersionOf(bind(f), ["2.1.330"], { lstat: hostLstat, env: envT() })), "version_unknown");
  assert.ok(Date.now() - t0 < 4000, "ended on the overflow, not the deadline");
  rmSync(b, { recursive: true });
});

test("claude-path: the spawn's environment is exactly PATH, HOME and DISABLE_AUTOUPDATER=1; nothing planted gets in", { skip }, async () => {
  const b = base();
  const planted = { SB_PLANTED_SECRET: "must-not-be-seen", TMPDIR: "/attacker-tmpdir", TMP: "/attacker-tmp", TEMP: "/attacker-temp", HOME: "/attacker-home", USER: "attacker", PATH: "/attacker-path:" + process.env.PATH };
  const saved = {}; for (const [k, v] of Object.entries(planted)) { saved[k] = process.env[k]; process.env[k] = v; }
  let env, r;
  try {
    env = envT(); // (built while every planted variable is set)
    const f = exe(b, "envdump", "#!/bin/sh\nenv | sort\nread x && echo GOT-STDIN || echo STDIN-CLOSED\n");
    r = await boundedRun(f, [], { env });
  } finally { for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; } }
  // (the built environment itself, exactly: some Node builds drop TMPDIR from a child's environment on their own, so the
  //  child's view alone can't prove TMPDIR, TMP and TEMP were never put in)
  assert.deepEqual(Object.keys(env).sort(), ["DISABLE_AUTOUPDATER", "HOME", "PATH"]);
  assert.doesNotMatch(JSON.stringify(env), /attacker|SB_PLANTED_SECRET/);
  const keys = r.stdout.split("\n").filter((l) => l.includes("=")).map((l) => l.split("=")[0]).filter((k) => k !== "PWD" && k !== "SHLVL" && k !== "_");
  assert.deepEqual(keys.sort(), ["DISABLE_AUTOUPDATER", "HOME", "PATH"]);
  assert.match(r.stdout, /^DISABLE_AUTOUPDATER=1$/m);
  assert.match(r.stdout, /^PATH=\/usr\/bin:\/bin$/m);
  assert.match(r.stdout, new RegExp(`^HOME=${(await import("node:os")).userInfo().homedir}$`, "m"), "HOME from the account database");
  assert.doesNotMatch(r.stdout, /attacker|SB_PLANTED_SECRET/);
  assert.match(r.stdout, /STDIN-CLOSED/);
  const shell = await boundedRun(join(b, "envdump") + " ; echo injected", [], { env });
  assert.equal(shell.failed, true, "a path is never handed to a shell");
  rmSync(b, { recursive: true });
});

test("claude-path: PATH keeps a folder only if it and every folder above it, resolved, are root-owned and not g/o-writable", { skip }, () => {
  // (a fake filesystem: /usr/bin and /usr real; /bin a link resolved to /usr/bin or to /opt/bin; any entry can be made bad)
  const fs = (bad = {}, binTo = "/usr/bin") => ({
    realpath: (p) => (p === "/bin" ? binTo : p),
    lstat: (p) => ({ isDirectory: () => true, uid: BigInt(bad[p]?.uid ?? 0), mode: BigInt(bad[p]?.mode ?? 0o40755) }),
  });
  const P = (o) => minimalEnv(o).PATH;
  assert.equal(P(fs()), "/usr/bin:/bin");
  assert.equal(P(fs({ "/": { uid: 2001, mode: 0o40775 } })), "/dev/null", "a bad / excludes both (this host's case)");
  assert.equal(P(fs({ "/usr": { mode: 0o40775 } })), "/dev/null", "a group-writable /usr excludes /usr/bin, and /bin resolved into it");
  assert.equal(P(fs({ "/usr": { uid: 1000 } })), "/dev/null", "a /usr owned by someone else");
  assert.equal(P(fs({ "/usr/bin": { mode: 0o40757 } })), "/dev/null", "the leaf itself");
  assert.equal(P(fs({ "/opt": { mode: 0o40777 } }, "/opt/bin")), "/usr/bin", "/bin's resolved ancestry is what's checked");
  assert.equal(P(fs({}, "/opt/bin")), "/usr/bin:/bin");
  // (every step as written: a /usr that is itself a link into an open folder excludes /usr/bin, though /usr/bin's own
  //  resolution is fine)
  const viaUsr = { realpath: (p) => (p === "/usr" ? "/var/open/usr" : p === "/bin" ? "/usr/bin" : p), lstat: fs({ "/var/open": { mode: 0o41777 } }).lstat };
  assert.equal(P(viaUsr), "/bin", "/usr/bin's step /usr resolves under an open folder: out; /bin's steps (/bin, /) don't pass /usr: kept");
  // (a link anywhere on a resolved chain excludes the folder: a resolved chain holds no link)
  const linky = { realpath: (p) => p, lstat: (p) => ({ isDirectory: () => true, isSymbolicLink: () => p === "/usr", uid: 0n, mode: 0o40755n }) };
  assert.equal(P(linky), "/bin", "a link at /usr on /usr/bin's chain excludes it");
  assert.equal(P({ realpath: () => { throw new Error("ENOENT"); }, lstat: fs().lstat }), "/dev/null");
  assert.equal(P({ realpath: (p) => p, lstat: () => { throw new Error("EACCES"); } }), "/dev/null");
  // (the real "/" of this host, as it is: if others can write it, nothing qualifies here)
  if ((Number(lstatSync("/").mode) & 0o022) !== 0) assert.equal(minimalEnv().PATH, "/dev/null");
});

// (an empty PATH is one null entry, which a lookup takes as the current folder: with nothing qualified, a helper
//  sitting in the run's working folder must not be found by name)
test("claude-path: with no folder qualified, PATH is /dev/null and a helper in the working folder isn't found", { skip }, () => {
  const none = minimalEnv({ lstat: () => { throw new Error("EACCES"); }, realpath: (p) => p }).PATH;
  assert.equal(none, "/dev/null");
  const dir = mkdtempSync(join(tmpdir(), "sb-cwd-"));
  const mark = join(dir, "ran");
  writeFileSync(join(dir, "sbhelper"), `#!/bin/sh\necho x > ${JSON.stringify(mark)}\n`);
  chmodSync(join(dir, "sbhelper"), 0o755);
  const shells = ["/bin/sh", "/bin/bash", "/bin/dash", "/bin/zsh"].filter((s) => existsSync(s));
  for (const sh of shells) {
    // (the control: an empty PATH does find it, so the row can tell the two apart)
    const ctl = spawnSync(sh, ["-c", "sbhelper"], { cwd: dir, env: { PATH: "" } });
    assert.equal(ctl.status, 0, `${sh}: an empty PATH finds the helper in the working folder`);
    assert.ok(existsSync(mark)); rmSync(mark);
    const r = spawnSync(sh, ["-c", "sbhelper"], { cwd: dir, env: { PATH: none } });
    assert.equal(r.status, 127, `${sh}: not found through /dev/null`);
    assert.equal(existsSync(mark), false, `${sh}: the helper didn't run`);
  }
  assert.ok(shells.length >= 1);
});

test("claude-path: the group is killed while its holder is alive, never after (no signal to a possibly reused group id)", { skip, timeout: 30_000 }, async () => {
  const b = base();
  // (the helper exits at once and leaves one child keeping the group alive: that child is killed, by a kill sent
  //  while the holder still held the id; nothing is signalled after the holder is gone)
  const pidFile = join(b, "left.pid");
  const leaves = exe(b, "leaves", `#!/bin/sh\nsleep 60 & echo $! > ${pidFile}\necho done\n`);
  const t1 = [];
  const r1 = await boundedRun(leaves, [], { env: envT(), trace: t1 });
  assert.equal(r1.code, 0);
  const left = Number(readFileSync(pidFile, "utf8").trim());
  assert.equal(await gone(left), true, "the child it left in the group is gone");
  assert.ok(t1.includes("holder-exit"));
  assert.deepEqual(t1.slice(t1.indexOf("holder-exit") + 1), [], "no kill after the holder's exit");
  assert.ok(t1.indexOf("kill") >= 0 && t1.indexOf("kill") < t1.indexOf("holder-exit"));
  // (an empty group: the helper exits with no child; one kill while the holder is alive, then its exit, nothing after)
  const t2 = [];
  await boundedRun(exe(b, "alone", "#!/bin/sh\necho alone\n"), [], { env: envT(), trace: t2 });
  assert.deepEqual(t2, ["kill", "holder-exit"]);
  // (the deadline and the overflow: the same order)
  const t3 = [];
  const r3 = await boundedRun(exe(b, "slow", "#!/bin/sh\nsleep 30\n"), [], { env: envT(), timeoutMs: 300, trace: t3 });
  assert.equal(r3.timedOut, true);
  assert.deepEqual(t3.slice(t3.indexOf("holder-exit") + 1), []);
  const t4 = [];
  const r4 = await boundedRun(exe(b, "loud", "#!/bin/sh\nhead -c 9000 /dev/zero | tr '\\\\0' x\nsleep 30\n"), [], { env: envT(), trace: t4 });
  assert.equal(r4.overflow, true);
  assert.deepEqual(t4.slice(t4.indexOf("holder-exit") + 1), []);
  // (a holder already gone is never signalled: the kill function isn't even called)
  let calls = 0;
  const t5 = [];
  await boundedRun(exe(b, "quick", "#!/bin/sh\ntrue\n"), [], { env: envT(), trace: t5, kill: (...a) => { calls++; return process.kill(...a); } });
  assert.equal(calls, t5.filter((x) => x === "kill").length);
  rmSync(b, { recursive: true });
});

const hasSetsid = spawnSync("setsid", ["--version"]).status === 0;
// (a helper that answers well and exits at once, leaving a process in its own session holding stdout and stderr for
//  `hold` seconds; it waits until that escape has happened (the escaped process writes its pid), so no race with the
//  group kill at the helper's exit)
function escaping(b, name, hold) {
  const pidFile = join(b, `${name}.pid`);
  const f = exe(b, name, `#!/bin/sh\nsetsid sh -c 'echo $$ > ${pidFile}; sleep ${hold}' &\nwhile [ ! -s ${pidFile} ]; do sleep 0.02; done\necho '2.1.330 (Claude Code)'\n`);
  return { f, cleanup: () => { try { process.kill(-Number(readFileSync(pidFile, "utf8").trim()), "SIGKILL"); } catch { /* (gone) */ } } };
}

for (const [kind, hold] of [["finite (3 s)", 3], ["infinite (an hour)", 3600]]) {
  test(`claude-path: an escaped descendant holding the output, ${kind}: the run settles within the deadline plus the grace, marked escaped, no signal after the holder's exit`, { skip: skip || (hasSetsid ? false : "no setsid here"), timeout: 20_000 }, async () => {
    const b = base();
    const e1 = escaping(b, "run", hold);
    const trace = [];
    const fds = () => { try { return readdirSync("/proc/self/fd").length; } catch { return null; } };
    const before = fds();
    const t0 = Date.now();
    const r = await boundedRun(e1.f, [], { env: envT(), timeoutMs: 1000, trace });
    const took = Date.now() - t0;
    // (this side's ends of the output are closed at the settle, though the escaped process still holds the others:
    //  nothing of the run stays open in this process; Linux only, where /proc/self/fd counts them)
    if (before !== null) { await new Promise((res) => setImmediate(res)); assert.equal(fds(), before, "no descriptor of the run left open"); }
    assert.ok(took < 1000 + 500 + 400, `took ${took} ms`);
    assert.equal(r.escaped, true);
    assert.equal(r.code, 0);
    assert.ok(trace.includes("holder-exit"));
    assert.deepEqual(trace.slice(trace.indexOf("holder-exit") + 1), [], "no kill after the holder's exit");
    // (the version check refuses such an answer: it left a process holding its output)
    const e2 = escaping(b, "version", hold);
    const t1 = Date.now();
    assert.equal(await areason(claudeVersionOf(bind(e2.f), ["2.1.330"], { lstat: hostLstat, env: envT() })), "no_answer");
    assert.ok(Date.now() - t1 < 5000 + 500 + 400);
    e1.cleanup(); e2.cleanup(); // (the test's own cleanup of the processes it made)
    rmSync(b, { recursive: true });
  });
}

test("claude-path: a run whose output ends normally isn't marked escaped", { skip }, async () => {
  const b = base();
  const r = await boundedRun(exe(b, "plain", "#!/bin/sh\necho hi\n"), [], { env: envT() });
  assert.equal(r.escaped, false);
  assert.equal(r.stdout, "hi\n");
  rmSync(b, { recursive: true });
});

test("claude-path: the version check re-checks the identity first, and spawns nothing on a change", { skip }, async () => {
  const b = base();
  const marker = join(b, "ran");
  const f = exe(b, "claude", `#!/bin/sh\ntouch ${marker}\necho '2.1.330 (Claude Code)'\n`);
  const r = bind(f);
  writeFileSync(f, `#!/bin/sh\ntouch ${marker}\necho '2.1.330 (Claude Code)'  \n`);
  let spawned = 0;
  assert.equal(await areason(claudeVersionOf(r, ["2.1.330"], { lstat: hostLstat, env: envT(), run: async () => { spawned++; return { code: 0, stdout: "" }; } })), "identity_changed");
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

// (a long run's holder: CliRun's spawn. The rows record every signal sent to the group, and when)
const exitOf = (held) => new Promise((r) => { held.once("exit", (code, signal) => r({ code, signal })); held.once("error", (e) => r({ error: e })); });
const readPid = async (f) => { for (let i = 0; i < 200; i++) { try { const t = readFileSync(f, "utf8").trim(); if (t) return Number(t); } catch {} await new Promise((r) => setTimeout(r, 10)); } throw new Error("no pid"); };
function recordKills(pg) {
  const realKill = process.kill, log = [];
  process.kill = function (pid, sig) { if (pid === -pg()) log.push(sig); return realKill.call(process, pid, sig); };
  return { log, restore: () => { process.kill = realKill; } };
}

test("claude-path: a long run's group gets TERM, then KILL at the helper's exit; a grandchild that ignores TERM is ended; no signal after the holder is gone", { skip, timeout: 30_000 }, async () => {
  const b = base();
  const gp = join(b, "gp");
  const f = exe(b, "helper", `#!/bin/sh\n(trap '' TERM; exec sleep 600) &\necho $! > ${JSON.stringify(gp)}\nexec sleep 600\n`);
  const held = heldSpawn(f, [], { env: {}, cwd: b });
  const exited = exitOf(held);
  const grandchild = await readPid(gp);
  const k = recordKills(() => held.pid);
  try {
    const t0 = Date.now();
    const err = await held.end({ graceMs: 10_000, boundMs: 10_000 });
    assert.equal(err, null);
    assert.ok(Date.now() - t0 < 5_000, "the KILL came at the helper's exit, not after the grace");
    assert.deepEqual(k.log, ["SIGTERM", "SIGKILL"]);
    assert.equal((await exited).signal, "SIGTERM", "the helper ended on the TERM");
    assert.equal(held.alive(), false);
    assert.equal(held.signal("SIGKILL"), false, "nothing is sent once the holder is gone");
    assert.deepEqual(k.log, ["SIGTERM", "SIGKILL"]);
    assert.ok(await gone(grandchild), "the grandchild is gone");
  } finally { k.restore(); try { process.kill(grandchild, "SIGKILL"); } catch {} }
  rmSync(b, { recursive: true });
});

test("claude-path: a long run whose helper ignores TERM is KILLed after the grace", { skip, timeout: 30_000 }, async () => {
  const b = base();
  const pf = join(b, "pid");
  const f = exe(b, "helper", `#!/bin/sh\ntrap '' TERM\necho $$ > ${JSON.stringify(pf)}\nexec sleep 600\n`);
  const held = heldSpawn(f, [], { env: {}, cwd: b });
  const exited = exitOf(held);
  const pid = await readPid(pf);
  const k = recordKills(() => held.pid);
  try {
    const t0 = Date.now();
    assert.equal(await held.end({ graceMs: 400, boundMs: 10_000 }), null);
    assert.ok(Date.now() - t0 >= 400, "TERM was ignored: the KILL waited for the grace");
    assert.deepEqual(k.log, ["SIGTERM", "SIGKILL"]);
    await exited;
    assert.ok(await gone(pid));
  } finally { k.restore(); try { process.kill(pid, "SIGKILL"); } catch {} }
  rmSync(b, { recursive: true });
});

test("claude-path: a long run's output ends when the helper and its group let go of it, while the holder still lives", { skip, timeout: 30_000 }, async () => {
  const b = base();
  const f = exe(b, "helper", "#!/bin/sh\necho hi\necho err >&2\n");
  const held = heldSpawn(f, [], { env: {}, cwd: b });
  let out = "";
  held.stdout.setEncoding("utf8").on("data", (d) => { out += d; });
  held.stderr.resume();
  const ended = (st) => new Promise((r) => st.once("end", r));
  let t;
  try {
    const r = await Promise.race([Promise.all([ended(held.stdout), ended(held.stderr), exitOf(held)]).then(() => "ended"),
      new Promise((res) => { t = setTimeout(() => res("still open"), 5_000); })]);
    assert.equal(r, "ended", "nothing but the helper held its output");
    assert.equal(out, "hi\n");
    assert.equal(held.alive(), true, "the holder keeps the group's id until it is ended");
  } finally { clearTimeout(t); assert.equal(await held.end({ graceMs: 10_000, boundMs: 10_000 }), null); }
  assert.equal(held.alive(), false);
  rmSync(b, { recursive: true });
});

test("claude-path: a long run that can't start says so; its holder is ended", { skip, timeout: 30_000 }, async () => {
  const held = heldSpawn("/nonexistent/claude", [], { env: {}, cwd: "/" });
  const r = await exitOf(held);
  assert.match(String(r.error?.message), /ENOENT/);
  assert.equal(await held.end({ graceMs: 10_000, boundMs: 10_000 }), null);
  assert.equal(held.alive(), false);
});

test("claude-path: a holder that can't start (its cwd is gone) is terminal at once: an error, no group, end() resolves", { skip, timeout: 30_000 }, async () => {
  const b = base(); const gone = join(b, "gone"); // (never created)
  const held = heldSpawn(process.execPath, ["-e", ""], { env: {}, cwd: gone });
  const r = await exitOf(held);
  assert.match(String(r.error?.message), /ENOENT/);
  assert.equal(held.pid, undefined, "no holder, so no group id");
  assert.equal(held.alive(), false, "a holder that never started is gone");
  assert.equal(held.signal("SIGTERM"), false, "no signal to a group that never existed");
  const t0 = Date.now();
  assert.equal(await held.end({ graceMs: 10_000, boundMs: 10_000 }), null, "end() reports no survivor");
  assert.ok(Date.now() - t0 < 2_000, "end() doesn't wait out the grace or the bound");
  rmSync(b, { recursive: true });
});

test("claude-path: when this process dies, the holder ends its own group (nothing is left running)", { skip, timeout: 30_000 }, async () => {
  const b = base();
  const pf = join(b, "pid");
  const f = exe(b, "helper", `#!/bin/sh\ntrap '' TERM\necho $$ > ${JSON.stringify(pf)}\nexec sleep 600\n`);
  const lib = new URL("../lib/claude-path.mjs", import.meta.url).href;
  const parent = spawn(process.execPath, ["--input-type=module", "-e",
    `import { heldSpawn } from ${JSON.stringify(lib)}; const h = heldSpawn(${JSON.stringify(f)}, [], { env: {}, cwd: "/" }); console.log(h.pid); setInterval(() => {}, 1 << 30);`],
  { stdio: ["ignore", "pipe", "inherit"] });
  const holderPid = Number(await new Promise((r) => parent.stdout.once("data", (d) => r(String(d).trim()))));
  const helper = await readPid(pf);
  parent.kill("SIGKILL");
  try {
    assert.ok(await gone(holderPid), "the holder is gone");
    assert.ok(await gone(helper), "the helper, which ignores TERM, is gone");
  } finally { try { process.kill(helper, "SIGKILL"); } catch {} try { process.kill(-holderPid, "SIGKILL"); } catch {} }
  rmSync(b, { recursive: true });
});
