// An executable the desktop app hands over (`--claude-path`, later `--codex-path`): bound once, checked on its own
// here (the app checked it first: this is the second line), re-checked before every spawn, and run only through a
// bounded, isolated spawn. Never a fallback to the bundled binary or to PATH: a check that fails refuses with one
// reason word from a closed list, and the app mirrors that list.

import { spawn } from "node:child_process";
import { lstatSync, realpathSync } from "node:fs";
import { userInfo } from "node:os";
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

export const PATH_LIMITS = Object.freeze({ versionMs: 5000, outputCap: 4096, settleMs: 500 });

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

// The PATH of every spawn: fixed, never inherited. A folder is kept only if every step of its path as written (the
// folder, then each folder above it) resolves to a real folder that, with every folder above IT up to "/", is
// root-owned and not writable by group or others: so a link on the way, the folder a link sits in and the folders
// above a link's target are all covered. Anyone else able to write one of them could swap what PATH finds. The same
// rule as the app's. When no folder is left, PATH is /dev/null, never "": an empty PATH is one null entry, which a
// lookup takes as the current folder; /dev/null isn't a folder, so every lookup through it fails.
export const FIXED_PATH = Object.freeze(["/usr/bin", "/bin"]);
export const NO_PATH = "/dev/null";
export function qualifiedPath({ lstat = (p) => lstatSync(p, { bigint: true }), realpath = realpathSync } = {}) {
  const trusted = (r) => {
    for (let x = r; ; x = dirname(x)) {
      let s;
      try { s = lstat(x); } catch { return false; }
      if (s.isSymbolicLink?.() || !s.isDirectory() || Number(s.uid) !== 0 || (Number(s.mode) & GO_WRITE) !== 0) return false;
      if (x === dirname(x)) return true;
    }
  };
  return FIXED_PATH.filter((d) => {
    for (let w = d; ; w = dirname(w)) {
      let r;
      try { r = realpath(w); } catch { return false; }
      if (!trusted(r)) return false;
      if (w === dirname(w)) return true;
    }
  }).join(":") || NO_PATH;
}

/**
 * The environment of every spawn of a bound executable: built here, nothing read from this process's environment.
 * Exactly the app's: PATH (fixed, qualified), HOME (the person's home, from the account database: where their Claude
 * login lives, which nothing here reads, copies or changes) and DISABLE_AUTOUPDATER=1, so the chosen binary never
 * updates itself or writes elsewhere; CLAUDE_CONFIG_DIR only when the agent itself sets one. No TMPDIR, TMP or TEMP
 * (a child uses the system default), no USER, no locale.
 */
export function minimalEnv({ configDir, user = userInfo(), lstat, realpath } = {}) {
  const env = { PATH: qualifiedPath({ ...(lstat ? { lstat } : {}), ...(realpath ? { realpath } : {}) }), HOME: user.homedir, DISABLE_AUTOUPDATER: "1" };
  if (configDir) env.CLAUDE_CONFIG_DIR = configDir;
  return env;
}

// The holder (node, no shell): the group's leader, which starts the helper inside its own group and never exits by
// itself. While it is alive its group id can't be reused, so every group kill is sent only while it is alive (the
// holder's death is seen in the same libuv callback that reaps it, so no other JavaScript runs in between), and none
// after. The helper's exit status comes back on fd 3; its stdout and stderr are the holder's, shared by the whole
// group, so their end proves that no member is left holding them.
const HOLDER = `
const { spawn } = require("node:child_process"); const { writeSync } = require("node:fs");
const [file, args, cwd] = JSON.parse(process.argv[1]);
const say = (o) => { try { writeSync(3, JSON.stringify(o) + "\\n"); } catch {} };
let c;
try { c = spawn(file, args, { shell: false, cwd, env: process.env, stdio: ["ignore", "inherit", "inherit"] }); }
catch { say({ failed: true }); }
if (c) { c.once("error", () => say({ failed: true })); c.once("exit", (code, signal) => say({ code, signal })); }
setInterval(() => {}, 1 << 30);
`;

/**
 * Run a helper once, bounded: no shell, the given environment only, a fixed working folder, stdin closed, stdout and
 * stderr each capped (cap bytes accepted, one more ends it), a deadline; the whole group killed while its holder is
 * alive, at the helper's exit, the deadline or an overflow; resolved once every member has let go of the output, or
 * at most settleMs after the holder's exit (a descendant that left the group can hold the output open: then this side's
 * ends are closed, the run is marked `escaped`, and nothing is signalled). So a run takes at most the deadline plus
 * settleMs. Resolves { code, signal, stdout, stderr, timedOut, overflow, failed, escaped }. `trace`: for tests, the
 * order of kills and the holder's exit.
 */
export function boundedRun(file, args, { env, cwd = "/", timeoutMs = PATH_LIMITS.versionMs, cap = PATH_LIMITS.outputCap, settleMs = PATH_LIMITS.settleMs, kill = process.kill, trace = null } = {}) {
  return new Promise((resolve) => {
    let holder;
    try {
      holder = spawn(process.execPath, ["-e", HOLDER, JSON.stringify([file, args, cwd])],
        { shell: false, env: env ?? {}, cwd, stdio: ["ignore", "pipe", "pipe", "pipe"], detached: true, windowsHide: true });
    } catch {
      resolve({ code: null, signal: null, stdout: "", stderr: "", timedOut: false, overflow: false, failed: true, escaped: false });
      return;
    }
    const out = { stdout: Buffer.alloc(0), stderr: Buffer.alloc(0) };
    let timedOut = false, overflow = false, status = null, holderGone = false;
    let settled = false, settleTimer = null;
    // (the holder gone: wait at most settleMs for the output to end; a member that left the group may hold it open)
    holder.once("exit", () => { holderGone = true; trace?.push("holder-exit"); settleTimer = setTimeout(() => settle(true), settleMs); });
    const killGroup = () => {
      if (holderGone) return; // (never a signal to a group whose leader may be gone: its id could be anyone's now)
      trace?.push("kill");
      try { kill(-holder.pid, "SIGKILL"); } catch { /* (already gone) */ }
    };
    const take = (which) => (d) => {
      if (overflow) return;
      if (out[which].length + d.length > cap) { overflow = true; out[which] = Buffer.concat([out[which], d]).subarray(0, cap); killGroup(); return; }
      out[which] = Buffer.concat([out[which], d]);
    };
    holder.stdout.on("data", take("stdout"));
    holder.stderr.on("data", take("stderr"));
    let line = "";
    holder.stdio[3].on("data", (d) => {
      line += d;
      if (status === null && line.includes("\n")) {
        try { status = JSON.parse(line.slice(0, line.indexOf("\n"))); } catch { status = { failed: true }; }
        killGroup(); // (the helper is done: end whatever it left in the group, the holder with it)
      }
    });
    const timer = setTimeout(() => { timedOut = true; killGroup(); }, timeoutMs);
    holder.once("error", () => { status ??= { failed: true }; });
    const settle = (escaped) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer); clearTimeout(settleTimer);
      // (this side's ends closed: whatever still holds the other ends can't keep this run or this process waiting)
      for (const st of [holder.stdout, holder.stderr, holder.stdio[3]]) { st.removeAllListeners("data"); st.destroy(); }
      const s = status ?? { failed: true };
      resolve({ code: s.code ?? null, signal: s.signal ?? null, stdout: out.stdout.toString("utf8"), stderr: out.stderr.toString("utf8"),
        timedOut, overflow, failed: !!s.failed || status === null, escaped });
    };
    holder.once("close", () => settle(false));
  });
}

/**
 * The answer `claude --version` must give, exactly as the app checks it: "<MAJOR.MINOR.PATCH> (Claude Code)" and exactly
 * one "\n" (required); each part canonical decimal (no leading zero unless it is "0"), at most 6 digits.
 */
const PART = "(?:0|[1-9][0-9]{0,5})";
const VERSION_ANSWER = new RegExp(`^(${PART}\\.${PART}\\.${PART}) \\(Claude Code\\)\n$`);

/**
 * The bound Claude Code's version, which must be in `supported` (the set the agent tested). Re-checks the identity
 * first. Refuses: version_unknown (any other answer, or stdout or stderr over 4096 bytes), no_answer (it didn't answer in
 * time, failed to start, or exited non-zero, even with a good answer), version_mismatch (a well-formed version outside
 * the set). Stderr within its cap is ignored.
 */
export async function claudeVersionOf(bound, supported, { run = boundedRun, env = minimalEnv(), lstat } = {}) {
  const file = recheck(bound, lstat ? { lstat } : {});
  const r = await run(file, ["--version"], { env, cwd: "/", timeoutMs: PATH_LIMITS.versionMs, cap: PATH_LIMITS.outputCap });
  if (r.overflow) refuse("version_unknown"); // (first: going over the cap is what killed it)
  if (r.failed || r.timedOut || r.escaped || r.code !== 0) refuse("no_answer"); // (escaped: it left a process holding its output)
  const m = VERSION_ANSWER.exec(r.stdout);
  if (!m) refuse("version_unknown");
  if (!supported.includes(m[1])) refuse("version_mismatch");
  return m[1];
}
