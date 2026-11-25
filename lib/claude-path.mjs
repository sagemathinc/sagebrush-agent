// An executable the desktop app hands over (`--claude-path`, later `--codex-path`): bound once, checked on its own
// here (the app checked it first: this is the second line), re-checked before every spawn, and run only through a
// bounded, isolated spawn. Never a fallback to the bundled binary or to PATH: a check that fails refuses with one
// reason word from a closed list, and the app mirrors that list.

import { spawn } from "node:child_process";
import { lstatSync, realpathSync } from "node:fs";
import { tmpdir, userInfo } from "node:os";
import { dirname, isAbsolute } from "node:path";

/** The closed list of reason words (exit 3, the word alone on stderr). The app reads it with --claude-path-reasons. */
export const CLAUDE_PATH_REASONS = Object.freeze([
  "not_absolute", "missing", "not_regular", "not_executable", "wrong_owner", "writable_by_others", "parent_writable",
  "version_unknown", "version_mismatch", "no_answer", "identity_changed", "unsupported_platform",
]);

export class ClaudePathError extends Error {
  constructor(reason) {
    if (!CLAUDE_PATH_REASONS.includes(reason)) throw new Error(`not a reason word: ${reason}`);
    super(reason);
    this.reason = reason;
  }
}
const refuse = (reason) => { throw new ClaudePathError(reason); };

export const PATH_LIMITS = Object.freeze({ versionMs: 5000, outputCap: 4096, reapMs: 2000 });

const S_ISVTX = 0o1000;
const GO_WRITE = 0o022;

/**
 * Bind an absolute path: resolve it ONCE (the final link included) and check the resolved target, which is what's
 * bound from then on. The file: a regular, executable file owned by this user or root, not writable by group or
 * others. Every folder above it: owned by this user or root and not writable by group or others; the one exception
 * is a root-owned sticky folder ABOVE the file's own folder (the file's own folder never gets the exception, so a file
 * directly in /tmp fails). Returns { path, identity } (identity: device, inode, size, mtime, mode, owner).
 */
export function bindExecutable(given, { platform = process.platform, uid = process.getuid?.(), lstat = (p) => lstatSync(p, { bigint: true }),
  realpath = realpathSync } = {}) {
  if (platform === "win32") refuse("unsupported_platform");
  if (typeof given !== "string" || !isAbsolute(given)) refuse("not_absolute");
  let path;
  try { path = realpath(given); } catch { refuse("missing"); }
  let st;
  try { st = lstat(path); } catch { refuse("missing"); }
  if (st.isSymbolicLink() || !st.isFile()) refuse("not_regular");
  const mode = Number(st.mode);
  if ((mode & 0o111) === 0) refuse("not_executable");
  if (!ownedOk(st, uid)) refuse("wrong_owner");
  if (mode & GO_WRITE) refuse("writable_by_others");
  const own = dirname(path);
  for (let d = own; ; d = dirname(d)) {
    let s;
    try { s = lstat(d); } catch { refuse("missing"); }
    if (!s.isDirectory()) refuse("not_regular");
    if (!ownedOk(s, uid)) refuse("wrong_owner");
    const m = Number(s.mode);
    if (m & GO_WRITE) {
      const rootSticky = Number(s.uid) === 0 && (m & S_ISVTX) !== 0;
      if (d === own || !rootSticky) refuse("parent_writable");
    }
    if (d === dirname(d)) break;
  }
  return Object.freeze({ path, identity: identityOf(st) });
}

function ownedOk(st, uid) {
  const o = Number(st.uid);
  return o === 0 || (uid !== undefined && o === uid);
}

function identityOf(st) {
  return Object.freeze({ dev: String(st.dev), ino: String(st.ino), size: String(st.size), mtimeNs: String(st.mtimeNs), mode: String(st.mode), uid: String(st.uid) });
}

/** Before every spawn: the bound target is still exactly what was bound (not a link, same identity), else identity_changed. */
export function recheck(bound, { lstat = (p) => lstatSync(p, { bigint: true }) } = {}) {
  let st;
  try { st = lstat(bound.path); } catch { refuse("identity_changed"); }
  if (st.isSymbolicLink() || !st.isFile()) refuse("identity_changed");
  const now = identityOf(st);
  for (const k of Object.keys(bound.identity)) if (now[k] !== bound.identity[k]) refuse("identity_changed");
  return bound.path;
}

/**
 * The environment of every spawn of a bound executable: built here, nothing inherited. The person's home (where their
 * Claude login lives: nothing here reads, copies or changes it) comes from the account database, not from the
 * environment; DISABLE_AUTOUPDATER=1 so the chosen binary never updates itself or writes elsewhere.
 */
export function minimalEnv({ configDir, user = userInfo() } = {}) {
  const env = {
    HOME: user.homedir, USER: user.username, LOGNAME: user.username,
    PATH: "/usr/bin:/bin:/usr/sbin:/sbin", TMPDIR: tmpdir(),
    DISABLE_AUTOUPDATER: "1",
  };
  if (configDir) env.CLAUDE_CONFIG_DIR = configDir;
  return env;
}

/**
 * Run a helper once, bounded: no shell, the given environment only, a fixed working folder, stdin closed, stdout and
 * stderr each capped (going over the cap ends it), a deadline, its own process group killed as a group at the deadline
 * or on overflow, and the group reaped. Resolves { code, signal, stdout, stderr, timedOut, overflow, reaped }.
 */
export function boundedRun(file, args, { env, cwd = "/", timeoutMs = PATH_LIMITS.versionMs, cap = PATH_LIMITS.outputCap, reapMs = PATH_LIMITS.reapMs } = {}) {
  return new Promise((resolve) => {
    let child;
    try {
      child = spawn(file, args, { shell: false, env: env ?? {}, cwd, stdio: ["ignore", "pipe", "pipe"], detached: true, windowsHide: true });
    } catch {
      resolve({ code: null, signal: null, stdout: "", stderr: "", timedOut: false, overflow: false, reaped: true, failed: true });
      return;
    }
    const out = { stdout: Buffer.alloc(0), stderr: Buffer.alloc(0) };
    let timedOut = false, overflow = false, failed = false;
    const killGroup = () => { try { process.kill(-child.pid, "SIGKILL"); } catch { /* (already gone) */ } };
    const take = (which) => (d) => {
      if (out[which].length + d.length > cap) { overflow = true; out[which] = Buffer.concat([out[which], d]).subarray(0, cap); killGroup(); return; }
      out[which] = Buffer.concat([out[which], d]);
    };
    child.stdout.on("data", take("stdout"));
    child.stderr.on("data", take("stderr"));
    const timer = setTimeout(() => { timedOut = true; killGroup(); }, timeoutMs);
    child.once("error", () => { failed = true; });
    child.once("close", (code, signal) => {
      clearTimeout(timer);
      // (the group outlives its leader when a member ignores the end: KILL it and wait until no member is left)
      killGroup();
      const until = Date.now() + reapMs;
      const wait = () => {
        let alive = true;
        try { process.kill(-child.pid, 0); } catch { alive = false; }
        if (alive && Date.now() < until) { killGroup(); setTimeout(wait, 20); return; }
        resolve({ code, signal, stdout: out.stdout.toString("utf8"), stderr: out.stderr.toString("utf8"), timedOut, overflow, reaped: !alive, failed });
      };
      wait();
    });
  });
}

/** The answer `claude --version` must give: exactly "<v> (Claude Code)" with one optional trailing newline. */
const VERSION_ANSWER = /^(\d{1,4}\.\d{1,4}\.\d{1,6}) \(Claude Code\)\n?$/;

/**
 * The bound Claude Code's version, which must be in `supported` (the set the agent tested). Re-checks the identity
 * first. Refuses: no_answer (it didn't answer in time, failed to start, or exited non-zero), version_unknown (any
 * other answer, an over-long one included), version_mismatch (a well-formed version outside the set).
 */
export async function claudeVersionOf(bound, supported, { run = boundedRun, env = minimalEnv(), lstat } = {}) {
  const file = recheck(bound, lstat ? { lstat } : {});
  const r = await run(file, ["--version"], { env, cwd: "/", timeoutMs: PATH_LIMITS.versionMs, cap: PATH_LIMITS.outputCap });
  if (r.overflow) refuse("version_unknown"); // (first: going over the cap is what killed it)
  if (r.failed || r.timedOut || r.code !== 0) refuse("no_answer");
  const m = VERSION_ANSWER.exec(r.stdout);
  if (!m) refuse("version_unknown");
  if (!supported.includes(m[1])) refuse("version_mismatch");
  return m[1];
}
