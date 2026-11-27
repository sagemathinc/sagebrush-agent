// Host backup, design init-run d6 §1, §2: `host backup init [--discard]`. The person sets up backup on this host: the
// destination and its credential (stdin), a repository made with this host's own random password (the HOST slot), the
// person's backup code added as a second slot and shown ONCE on the console's terminal, then `backup/enabled` and the
// daily timer.
//
// - **A durable journal** (init.json) names each phase BEFORE its effects: begun, repo (with its attempt), code-slot
//   (with a probe swap's direction), shown, confirmed, initialized (terminal, kept).
// - **Recovery never repeats an effect that may already have happened without a probe first** (d6 §1's table):
//   - `repo`: a probe with the preserved host.key. It opens: init had committed. `repository_missing`: init runs
//     once. `open_failed`: a repository this host didn't make (refused, everything kept). Anything else: kept, refused.
//   - `code-slot`: a probe with the code (attach's rule): it opens, the slot exists; `open_failed`, add-key ONCE;
//     anything else, kept and refused.
//   - `shown`: the SAME code is shown again (it never left the host). `confirmed`: admitted past its own `enabled`
//     (T1) and finished idempotently.
// - **The code** is written to the controlling terminal only, never stdout, a log, the journal or a line; it is
//   removed from disk once the person has typed two of its groups back.
// - **The command's exclusion** is proven on entry, after each admission, around every binary call and before every
//   effect (attach's guard).

import * as fs from "node:fs";
import * as tty from "node:tty";
import { dirname, join } from "node:path";
import { randomBytes } from "node:crypto";
import { FleetError, refuse } from "../bytes.mjs";
import { exactKeys, realIo, writeDurable, writeExclusive } from "./store.mjs";
import { restoreOpen, withExclusion } from "./restore-begin.mjs";
import { BACKUP_STATE_DIR, HOST_SECRETS_DIR } from "./names.mjs";
import { commandSignal, readCommandInput, realBackupBinary } from "./backup-binary.mjs";
import { defaultRelease } from "./restore-cli.mjs";
import { ENABLED_FILE, backupEnabled, backupUnits } from "./backup-scheduler.mjs";
import { JOURNAL as ATTACH_JOURNAL } from "./backup-attach.mjs";
import { runArgv } from "./effects.mjs";

export const HANDLE = "backup";
export const JOURNAL = "init.json";
export const DEST = "dest.json";
export const HOST_KEY = "host.key";
export const CODE_KEY = "init-code.key";
export const SWAP_KEY = "init-swap.key";
export const UNIT_DIR = "/etc/systemd/system";
const PHASES = ["begun", "repo", "code-slot", "shown", "confirmed", "initialized"];
const MAX_INPUT = 64 * 1024;
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/** The input's closed shape: { v: 1, dest: {type: "s3", endpoint, bucket, prefix, region}, credential } (attach's without the code). */
export function checkInput(x) {
  const bad = () => refuse("bad_form", "backup init: not a valid input");
  const str = (v, max) => typeof v === "string" && v.length > 0 && v.length <= max && !/[\u0000-\u001f\u007f]/.test(v);
  if (!exactKeys(x, ["v", "dest", "credential"]) || x.v !== 1) bad();
  const d = x.dest;
  if (!exactKeys(d, ["type", "endpoint", "bucket", "prefix", "region"]) || d.type !== "s3") bad();
  if (!str(d.endpoint, 2048) || !d.endpoint.startsWith("https://") || !str(d.bucket, 63) || !str(d.prefix, 1024) || !str(d.region, 64)) bad();
  const c = x.credential;
  if (!exactKeys(c, ["access_key_id", "secret_access_key"]) || !str(c.access_key_id, 256) || !str(c.secret_access_key, 256)) bad();
  return x;
}

/** Parse stdin's bytes: one JSON object, bounded. */
export function parseInput(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length > MAX_INPUT) refuse("bad_form", "backup init: the input is too large");
  let x;
  try { x = JSON.parse(bytes.toString("utf8")); } catch { refuse("bad_form", "backup init: the input isn't JSON"); }
  return checkInput(x);
}

/** A backup code: 26 characters of [A-Z2-7] (130 random bits). */
export function newCode(rand = randomBytes) {
  const b = rand(17);
  let bits = 0, n = 0, out = "";
  for (const byte of b) {
    n = (n << 8) | byte; bits += 8;
    while (bits >= 5 && out.length < 26) { out += B32[(n >> (bits - 5)) & 31]; bits -= 5; }
  }
  return out;
}

/** The code's groups as shown: 5, 5, 5, 5 and 6 characters. */
export const groupsOf = (code) => [code.slice(0, 5), code.slice(5, 10), code.slice(10, 15), code.slice(15, 20), code.slice(20)];

/** A directory of `uid`, exactly 0700, created when missing (one level; each effect behind `guard`), else proven. */
function privateDir(fsx, p, uid, guard) {
  let st;
  try { st = fsx.lstatSync(p); } catch (e) {
    if (e?.code !== "ENOENT") throw e;
    guard();
    fsx.mkdirSync(p, { mode: 0o700 });
    guard();
    fsx.chmodSync(p, 0o700);
    st = fsx.lstatSync(p);
  }
  if (!st.isDirectory() || st.uid !== uid || (st.mode & 0o7777) !== 0o700) refuse("not_granted", "backup init: a directory isn't a private one");
  return p;
}

/** Admission's read-only look at a directory: "absent", or proven `uid`'s 0700 directory (else a refusal). */
function dirKind(fsx, p, uid) {
  let st;
  try { st = fsx.lstatSync(p); } catch (e) { if (e?.code === "ENOENT") return "absent"; throw e; }
  if (!st.isDirectory() || st.uid !== uid || (st.mode & 0o7777) !== 0o700) refuse("not_granted", "backup init: a directory isn't a private one");
  return "dir";
}

/** Is anything at `p` (no-follow)? */
function present(fsx, p) {
  try { fsx.lstatSync(p); return true; } catch (e) { if (e?.code === "ENOENT") return false; throw e; }
}

/** An init-owned path, no-follow: "absent", "file" (a regular file of `uid`, 0600), or a refusal. */
function kindOf(fsx, p, uid) {
  let st;
  try { st = fsx.lstatSync(p); } catch (e) { if (e?.code === "ENOENT") return "absent"; throw e; }
  if (!st.isFile() || st.uid !== uid || (st.mode & 0o7777) !== 0o600) refuse("not_granted", "backup init: an init path isn't a private regular file");
  return "file";
}

const journalText = (j) => JSON.stringify(j) + "\n";

/** The journal: null when absent; a present one exactly its closed shape { v: 1, phase, attempt?, swap? }. */
function readJournal(fsx, state, uid) {
  const p = join(state, JOURNAL);
  if (kindOf(fsx, p, uid) === "absent") return null;
  let j;
  try { j = JSON.parse(fsx.readFileSync(p, "utf8")); } catch { refuse("bad_form", "backup init: the journal isn't JSON"); }
  const keys = ["v", "phase", ...(j?.phase === "repo" ? ["attempt"] : []), ...(j?.phase === "code-slot" && j?.swap !== undefined ? ["swap"] : [])];
  const ok = j && j.v === 1 && PHASES.includes(j.phase) && exactKeys(j, keys)
    && (j.phase !== "repo" || j.attempt === 1) && (j.swap === undefined || ["forward", "back"].includes(j.swap));
  if (!ok) refuse("bad_form", "backup init: the journal is malformed");
  return j;
}

/**
 * `host backup init`. `input`: the checked input (null for --discard or a recovery that needs none). `deps`:
 * - binary(req, { ms }): the pinned backup binary over the state and secrets context;
 * - enabled(): backupEnabled's plain answer (false only when not set up); restoreOpen();
 * - tty: { write(text), ask(prompt) -> Promise<string|null> } (the controlling terminal; null means none);
 * - units({ service, timer, names }, { guard }): installs the unit files byte-equal (if missing or different), reloads
 *   systemd and enables the timer, checking `guard` before each effect and after each await; idempotent.
 * Options: `state`, `secrets`, `uid`, `fsx`, `io`, `rand`, `discard`, `ms`, `guard()`, `release` (for the units).
 * Resolves to { initialized: true } or { discarded: true }; refuses with a code otherwise.
 */
export async function init(input, deps, { state, secrets, uid = 0, fsx = fs, io = realIo, rand = randomBytes, discard = false, ms = 5 * 60 * 1000, guard = () => {}, release = defaultRelease() } = {}) {
  guard();
  if (!deps.tty) refuse("not_granted", "backup init: no controlling terminal to show the backup code on");
  const backupDir = dirname(state);
  const enabledNow = deps.enabled();
  guard();
  const open = deps.restoreOpen();
  guard();
  if (open !== false) refuse("in_progress", "backup init: a restore is open");
  // Admission only reads: nothing is created until every refusal has had its say.
  for (const d of [backupDir, state, secrets]) dirKind(fsx, d, uid);
  if (present(fsx, join(state, ATTACH_JOURNAL))) refuse("not_granted", "backup init: this host is attached to another host's store");
  const P = { journal: join(state, JOURNAL), dest: join(state, DEST), cred: join(secrets, HANDLE), host: join(state, HOST_KEY), code: join(state, CODE_KEY), swap: join(state, SWAP_KEY) };
  const kinds = Object.fromEntries(Object.entries(P).map(([k, p]) => [k, kindOf(fsx, p, uid)]));
  const j = readJournal(fsx, state, uid);
  // T1: backup is enabled only by init's own `confirmed` step; anything else that has it enabled (or an `enabled`
  // file at all) refuses.
  if ((enabledNow !== false || present(fsx, join(backupDir, ENABLED_FILE))) && j?.phase !== "confirmed") refuse("in_progress", "backup init: backup is enabled on this host");

  const setPhase = (phase, extra = {}) => { guard(); writeDurable(state, JOURNAL, journalText({ v: 1, phase, ...extra }), io); };
  const syncDir = (d) => { const fd = io.open(d, "r"); try { io.fsync(fd); } finally { io.close(fd); } };
  const rename = (a, b) => { guard(); io.rename(a, b); syncDir(state); };
  const unlink = (p) => { guard(); fsx.unlinkSync(p); };
  const exclusive = (dir, name, data) => { guard(); writeExclusive(dir, name, data, io); };
  const removeAll = () => {
    for (const k of ["swap", "code", "host", "dest"]) if (kindOf(fsx, P[k], uid) === "file") unlink(P[k]);
    if (kindOf(fsx, P.cred, uid) === "file") { unlink(P.cred); syncDir(secrets); }
    if (kindOf(fsx, P.journal, uid) === "file") unlink(P.journal);
    syncDir(state);
  };
  const run = async (req) => {
    guard();
    const r = await deps.binary(req, { ms });
    guard();
    // A call the console's signal stopped: not a registered refusal, and its effect may have committed (init, add-key),
    // so it is reported as unknown; the journal stays, and the next init probes.
    if (r?.code === "aborted") refuse("outcome_unknown", "backup init: stopped by a signal; init again to recover");
    return r;
  };
  const readCode = () => fsx.readFileSync(P.code, "utf8").split("\n")[0];

  /** `repo`'s probe: snapshots with the preserved host.key. */
  const probeRepo = async () => run({ op: "snapshots" });

  if (discard) {
    // Only while no repository holds this host's slot: `begun`, or `repo` whose probe proves none does.
    if (j === null) refuse("not_granted", "backup init: nothing to discard (no init journal)");
    if (j.phase === "repo") {
      const r = await probeRepo();
      if (r.ok || !["repository_missing", "open_failed"].includes(r.code)) refuse("not_granted", "backup init: a repository may hold this host's slot; complete init instead");
    } else if (j.phase !== "begun") refuse("not_granted", "backup init: a repository holds this host's slot; complete init instead");
    removeAll();
    return { discarded: true };
  }

  /** `code-slot`'s probe (attach's rule): the code swapped into host.key, snapshots, swapped back, by the journal. */
  const swapForward = () => {
    if (kindOf(fsx, P.swap, uid) === "absent") rename(P.host, P.swap);
    if (kindOf(fsx, P.host, uid) === "absent") exclusive(state, HOST_KEY, readCode() + "\n");
  };
  const swapBack = () => {
    if (kindOf(fsx, P.swap, uid) === "file") {
      if (kindOf(fsx, P.host, uid) === "file") unlink(P.host);
      rename(P.swap, P.host);
    }
  };
  const addCodeSlot = async () => {
    const a = await run({ op: "add-key", password_file: P.code });
    if (!a.ok) refuse(a.code ?? "outcome_unknown", "backup init: add-key didn't report success (init again to probe)");
  };
  const codeSlot = async () => {
    setPhase("code-slot", { swap: "forward" });
    swapForward();
    const r = await run({ op: "snapshots" });
    setPhase("code-slot", { swap: "back" });
    swapBack();
    setPhase("code-slot");
    if (r.ok) return; // the slot exists (a lost add-key response included)
    if (r.code !== "open_failed") refuse(r.code ?? "outcome_unknown", "backup init: the code's probe is inconclusive; init again later");
    await addCodeSlot(); // only open_failed: no slot, so add it ONCE
  };

  /** Show the code on the terminal and have two groups typed back; a wrong group asks again. */
  const show = async () => {
    const code = readCode();
    const g = groupsOf(code);
    deps.tty.write(`\nYour backup code (write it down; it is shown only now):\n\n    ${g.join("-")}\n\n`
      + "Without it, and without this host, nobody can open these backups, including Sagebrush.\n\n");
    const x = rand(1)[0] % 5, y = (x + 1 + (rand(1)[0] % 4)) % 5; // two different groups
    const [a, b] = [x + 1, y + 1].sort((m, n) => m - n);
    for (;;) {
      const answer = await deps.tty.ask(`Type group ${a} and group ${b} of the code, separated by a space: `);
      guard();
      if (answer === null) refuse("in_progress", "backup init: the code wasn't confirmed (init again to show it again)");
      const typed = answer.toUpperCase().trim().split(/[\s-]+/);
      if (typed.length === 2 && typed[0] === g[a - 1] && typed[1] === g[b - 1]) break;
      deps.tty.write("That doesn't match. Look at the code above and try again.\n");
    }
    deps.tty.write("\x1b[2J\x1b[H"); // (clear the screen: the code is no longer on it)
  };

  /** `confirmed`: each step proven before it is skipped; then the terminal phase. */
  const finish = async () => {
    if (kindOf(fsx, P.code, uid) === "file") { unlink(P.code); syncDir(state); }
    const en = join(backupDir, ENABLED_FILE);
    if (kindOf(fsx, en, uid) === "absent") exclusive(backupDir, ENABLED_FILE, "");
    else if (fsx.statSync(en).size !== 0) refuse("not_granted", "backup init: backup/enabled isn't init's");
    guard();
    await deps.units(backupUnits(release), { guard });
    guard();
    setPhase("initialized");
    return { initialized: true };
  };
  /** From `shown` on. */
  const fromShown = async () => { await show(); setPhase("confirmed"); return finish(); };
  /** From `code-slot` on (the slot made or proven, then shown). */
  const fromCodeSlot = async () => { await codeSlot(); setPhase("shown"); return fromShown(); };

  if (j !== null) {
    switch (j.phase) {
      case "initialized": refuse("in_progress", "backup init: already initialized");
      // eslint-disable-next-line no-fallthrough
      case "begun": // (no repository can exist yet: a fresh init follows, from this input)
        if (input === null) refuse("bad_form", "backup init: no input (an interrupted init restarts from its input)");
        removeAll();
        break;
      case "repo": {
        const r = await probeRepo();
        if (r.ok) { setPhase("code-slot"); return fromCodeSlot(); } // init had committed (a lost response included)
        if (r.code === "open_failed") refuse("not_granted", "backup init: the store holds a repository this host didn't make (use attach)");
        if (r.code !== "repository_missing") refuse(r.code ?? "outcome_unknown", "backup init: the repository's probe is inconclusive; init again later");
        const i = await run({ op: "init" }); // never committed: init ONCE
        if (!i.ok) refuse(i.code ?? "outcome_unknown", "backup init: the repository couldn't be made (init again to probe)");
        setPhase("code-slot");
        await addCodeSlot();
        setPhase("shown");
        return fromShown();
      }
      case "code-slot":
        if (j.swap === "forward" || j.swap === "back") { setPhase("code-slot", { swap: "back" }); swapBack(); setPhase("code-slot"); }
        return fromCodeSlot();
      case "shown": return fromShown();
      case "confirmed": return finish();
    }
  } else if (Object.values(kinds).some((k) => k !== "absent")) {
    refuse("not_granted", "backup init: init's files are present without its journal");
  }

  // A fresh init.
  if (input === null) refuse("bad_form", "backup init: no input");
  checkInput(input);
  for (const d of [backupDir, state, secrets]) privateDir(fsx, d, uid, guard);
  setPhase("begun");
  exclusive(state, DEST, JSON.stringify({ type: "s3", endpoint: input.dest.endpoint, bucket: input.dest.bucket, prefix: input.dest.prefix, region: input.dest.region, credential: { secret: HANDLE } }) + "\n");
  exclusive(secrets, HANDLE, JSON.stringify(input.credential) + "\n");
  exclusive(state, HOST_KEY, rand(32).toString("base64url") + "\n");
  exclusive(state, CODE_KEY, newCode(rand) + "\n");
  setPhase("repo", { attempt: 1 });
  const made = await run({ op: "init" });
  if (!made.ok) {
    // The FIRST init answering repository_exists: a repository this init didn't make is already there.
    if (made.code === "repository_exists") { removeAll(); refuse("not_granted", "backup init: the store already holds a repository (use attach)"); }
    refuse(made.code ?? "outcome_unknown", "backup init: the repository couldn't be made (init again to probe)");
  }
  setPhase("code-slot");
  await addCodeSlot();
  setPhase("shown");
  return fromShown();
}

/**
 * The controlling terminal, or null when the process has none. `ask` reads one line without blocking the event loop
 * (so the console's SIGINT, SIGTERM or SIGHUP still aborts the command while it waits); the command's signal, or the
 * terminal's end, answers null.
 */
export function realTty({ signal = commandSignal() } = {}) {
  let fd;
  try { fd = fs.openSync("/dev/tty", fs.constants.O_RDWR | fs.constants.O_NOCTTY); } catch { return null; }
  let input = null;
  const write = (s) => { fs.writeSync(fd, s); };
  const ask = (prompt) => new Promise((resolve) => {
    write(prompt);
    input ??= new tty.ReadStream(fd);
    let line = "";
    const done = (v) => {
      input.off("data", onData); input.off("end", onEnd); signal?.removeEventListener("abort", onEnd);
      input.pause();
      resolve(v);
    };
    const onData = (b) => {
      for (const c of b.toString("latin1")) {
        if (c === "\n" || c === "\r") { done(line); return; }
        if (line.length < 256) line += c;
      }
    };
    const onEnd = () => done(null);
    if (signal?.aborted) { done(null); return; }
    input.on("data", onData);
    input.once("end", onEnd);
    signal?.addEventListener("abort", onEnd, { once: true });
    input.resume();
  });
  const close = () => { if (input !== null) input.destroy(); else fs.closeSync(fd); };
  return { write, ask, close };
}

/**
 * The units, installed: written (root 0644, atomic) unless already a regular file (never a link) of `rootUid`, mode
 * 0644, byte-equal; anything else (missing, other bytes, mode or owner, a link) is replaced by the atomic write, whose
 * rename replaces the name itself, never what a link points to. Then reload and enable --now. `guard`
 * (init's held exclusion) is checked before each write and each systemctl call and after each await, so nothing is
 * written or enabled once the lock is known lost (the timer is never enabled after a lost reload).
 */
export function realUnits({ dir = UNIT_DIR, run = runArgv, fsx = fs, io = realIo, rootUid = 0 } = {}) {
  /** The unit at `p` is already exactly what it must be: a regular root 0644 file holding `text`. */
  const proven = (p, text) => {
    let st;
    try { st = fsx.lstatSync(p); } catch (e) { if (e?.code === "ENOENT") return false; throw e; }
    if (!st.isFile() || st.uid !== rootUid || (st.mode & 0o7777) !== 0o644) return false;
    return fsx.readFileSync(p, "utf8") === text;
  };
  return async ({ service, timer, names }, { guard = () => {} } = {}) => {
    for (const [name, text] of [[names.service, service], [names.timer, timer]]) {
      const ok = proven(join(dir, name), text);
      guard();
      if (!ok) writeDurable(dir, name, text, io, 0o644);
      if (!proven(join(dir, name), text)) refuse("outcome_unknown", "backup init: a unit file isn't root's 0644 file after its write");
    }
    for (const argv of [["systemctl", "daemon-reload"], ["systemctl", "enable", "--now", names.timer]]) {
      guard();
      let r;
      try { r = await run(argv, { ms: 30_000 }); } catch { r = null; } // (a spawn failure, a deadline or the command's signal)
      guard();
      if (r?.code !== 0) refuse("outcome_unknown", `backup init: ${argv.slice(1).join(" ")} failed`);
    }
  };
}

const USAGE = "usage: sagebrush-agent host backup init [--discard]  (the input: one JSON object on stdin)";

async function readStdin() {
  if (process.stdin.isTTY) return Buffer.alloc(0); // (a resume typed at the console: no input)
  return readCommandInput({ max: MAX_INPUT });
}

/**
 * `sagebrush-agent host backup init [--discard]`, root on the console only, under the backup/restore exclusion; the
 * input only from stdin, and only for a fresh init (a recovery reads none). Resolves to { code, line } (one JSON line
 * of codes) or { code: 2, usage }. `deps` (seams): uid(), rootUid, state, secrets, exclusion, stdin(), needsInput(),
 * binary, enabled(), restoreOpen(), tty, units, rand, release.
 */
export async function backupInitCommand(argv, deps = {}) {
  const { uid = () => process.getuid?.() ?? -1, rootUid = 0, state = BACKUP_STATE_DIR, secrets = HOST_SECRETS_DIR, exclusion = {}, stdin = readStdin, rand = randomBytes } = deps;
  const discard = argv.length === 2 && argv[1] === "--discard";
  if (argv[0] !== "init" || !(argv.length === 1 || discard)) return { code: 2, line: null, usage: USAGE };
  if (uid() !== rootUid) return { code: 1, line: { v: 1, refused: "not_granted" } };
  const tty = Object.hasOwn(deps, "tty") ? deps.tty : realTty();
  try {
    if (!tty) refuse("not_granted", "backup init: no controlling terminal");
    // A resume past `begun` needs no input: stdin may then be empty (or the terminal). Any input given is checked.
    const bytes = discard ? Buffer.alloc(0) : await stdin();
    const input = bytes.length === 0 ? null : parseInput(bytes);
    const ops = {
      binary: deps.binary ?? realBackupBinary(deps.release ?? defaultRelease()),
      enabled: deps.enabled ?? (() => backupEnabled().enabled !== false),
      restoreOpen: deps.restoreOpen ?? (() => restoreOpen()),
      tty,
      units: deps.units ?? realUnits(),
    };
    const out = await withExclusion((held) => init(input, ops, { state, secrets, uid: rootUid, rand, discard, release: deps.release,
      guard: () => {
        if (!held?.held?.()) refuse("outcome_unknown", "backup init: the exclusion was lost; init again to recover");
        if (commandSignal()?.aborted) refuse("outcome_unknown", "backup init: stopped by a signal; init again to recover");
      } }), exclusion);
    return { code: 0, line: { v: 1, ...out } };
  } catch (e) {
    // The code only (no path, value, secret or message reaches the line): a registered reason or a CONSOLE_CODES one.
    // Anything else thrown (a disk error midway) may have had effects: outcome_unknown, and the journal says what's next.
    return { code: 1, line: { v: 1, refused: e instanceof FleetError ? e.code : "outcome_unknown" } };
  } finally { tty?.close?.(); }
}
