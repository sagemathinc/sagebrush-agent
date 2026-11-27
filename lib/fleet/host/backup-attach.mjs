// Host backup, delta attach-d3: `host backup attach [--discard]`. A fresh host that will be restored reaches the
// EXISTING store without enabling backup: the binary's destination, its credential and a repository password of this
// host's own, where the binary reads them (the launcher's context paths), and never `backup/enabled`.
//
// - **The backup code is used once.** The repository is the old host's; only the person's backup code opens it. It is
//   written as host.key, the repository opened with it (snapshots), a fresh random password made (attach-new.key),
//   add-key run with it, and the new password renamed over host.key. The code is never kept.
// - **A durable journal** (attach.json) names each phase BEFORE its effects: begun, slot-pending, probing (with its
//   swap's direction), promoting, attached (terminal, kept). Recovery is driven by it alone.
// - **Recovery never adds a second key blindly.** From slot-pending, the new password is swapped into host.key and the
//   repository probed: it opens, so add-key had committed (a lost response included). Only `open_failed`, the
//   binary's answer that the key didn't open the repository (treated as "this key is invalid"), swaps back and runs
//   add-key ONCE. Any other result keeps `probing` with both secrets, runs nothing and refuses; a later run probes again.
// - **--discard** only from a present, well-formed `begun` journal (no slot can exist yet), with backup not enabled
//   and the destination's handle `restore-attach`. Everything else refuses with nothing removed.
// - **Every attach-owned path is lstat'd no-follow**: a link or another kind of object refuses.

import * as fs from "node:fs";
import { dirname, join } from "node:path";
import { randomBytes } from "node:crypto";
import { FleetError, refuse } from "../bytes.mjs";
import { exactKeys, realIo, writeDurable, writeExclusive } from "./store.mjs";
import { restoreOpen, withExclusion } from "./restore-begin.mjs";
import { BACKUP_STATE_DIR, HOST_SECRETS_DIR } from "./names.mjs";
import { commandSignal, readCommandInput, realBackupBinary } from "./backup-binary.mjs";
import { defaultRelease } from "./restore-cli.mjs";
import { backupEnabled } from "./backup-scheduler.mjs";

export const HANDLE = "restore-attach";
export const JOURNAL = "attach.json";
export const DEST = "dest.json";
export const HOST_KEY = "host.key";
export const NEW_KEY = "attach-new.key";
export const CODE_KEY = "attach-code.key";
const PHASES = ["begun", "slot-pending", "probing", "promoting", "attached"];
const CODE = /^[A-Z2-7]{26}$/;
const MAX_INPUT = 64 * 1024;

/**
 * The input's closed shape: { v: 1, dest: {type: "s3", endpoint, bucket, prefix, region}, credential, backup_code }.
 * Each string bounded and free of control characters, the endpoint https; the binary validates the destination itself
 * (its first open answers config_invalid or destination_refused, and every attach path is removed).
 */
export function checkInput(x) {
  const bad = () => refuse("bad_form", "backup attach: not a valid input");
  const str = (v, max) => typeof v === "string" && v.length > 0 && v.length <= max && !/[\u0000-\u001f\u007f]/.test(v);
  if (!exactKeys(x, ["v", "dest", "credential", "backup_code"]) || x.v !== 1) bad();
  const d = x.dest;
  if (!exactKeys(d, ["type", "endpoint", "bucket", "prefix", "region"]) || d.type !== "s3") bad();
  if (!str(d.endpoint, 2048) || !d.endpoint.startsWith("https://") || !str(d.bucket, 63) || !str(d.prefix, 1024) || !str(d.region, 64)) bad();
  const c = x.credential;
  if (!exactKeys(c, ["access_key_id", "secret_access_key"]) || !str(c.access_key_id, 256) || !str(c.secret_access_key, 256)) bad();
  if (typeof x.backup_code !== "string" || !CODE.test(x.backup_code)) bad();
  return x;
}

/** Parse stdin's bytes: one JSON object, bounded. */
export function parseInput(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length > MAX_INPUT) refuse("bad_form", "backup attach: the input is too large");
  let x;
  try { x = JSON.parse(bytes.toString("utf8")); } catch { refuse("bad_form", "backup attach: the input isn't JSON"); }
  return checkInput(x);
}

/** A directory of `uid`, exactly 0700, created when missing (one level; each effect behind `guard`), else proven (never a link). */
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
  if (!st.isDirectory() || st.uid !== uid || (st.mode & 0o7777) !== 0o700) refuse("not_granted", "backup attach: a directory isn't a private one");
  return p;
}

/** An attach-owned path, no-follow: "absent", "file" (a regular file of `uid`, 0600), or a refusal. */
function kindOf(fsx, p, uid) {
  let st;
  try { st = fsx.lstatSync(p); } catch (e) { if (e?.code === "ENOENT") return "absent"; throw e; }
  if (!st.isFile() || st.uid !== uid || (st.mode & 0o7777) !== 0o600) refuse("not_granted", "backup attach: an attach path isn't a private regular file");
  return "file";
}

const journalText = (j) => JSON.stringify(j) + "\n";

/** The journal: null when absent; a present one must be well-formed (exactly its keys and a known phase). */
function readJournal(fsx, state, uid) {
  const p = join(state, JOURNAL);
  if (kindOf(fsx, p, uid) === "absent") return null;
  let j;
  try { j = JSON.parse(fsx.readFileSync(p, "utf8")); } catch { refuse("bad_form", "backup attach: the journal isn't JSON"); }
  const swapOk = j?.phase === "probing" ? ["forward", "back"].includes(j.swap) : j?.swap === undefined;
  if (!j || j.v !== 1 || !PHASES.includes(j.phase) || !swapOk || !exactKeys(j, j.phase === "probing" ? ["v", "phase", "swap"] : ["v", "phase"])) {
    refuse("bad_form", "backup attach: the journal is malformed");
  }
  return j;
}

/**
 * `host backup attach`. `input`: the checked input (null for --discard). `deps`: { binary(req, { ms }) (the backup
 * binary's runner, with the state and secrets context), enabled() (backupEnabled), restoreOpen() }. Options: `state`,
 * `secrets` (the binary's context directories), `uid`, `fsx`, `io`, `rand`, `discard`, `ms`, `guard()` (refuses
 * outcome_unknown once the command's exclusion is lost: checked before and after each binary call and before each
 * durable effect, so a lost lock stops attach with its journal kept for a later run's recovery). Resolves to
 * { attached: true } or { discarded: true }; refuses with a code otherwise.
 */
export async function attach(input, deps, { state, secrets, uid = 0, fsx = fs, io = realIo, rand = randomBytes, discard = false, ms = 5 * 60 * 1000, guard = () => {} } = {}) {
  // The lock proven on entry and right after each admission, before anything is inspected or created.
  guard();
  const enabled = deps.enabled();
  guard();
  if (enabled !== false) refuse("in_progress", "backup attach: backup is enabled on this host");
  const open = deps.restoreOpen();
  guard();
  if (open !== false) refuse("in_progress", "backup attach: a restore is open");
  privateDir(fsx, dirname(state), uid, guard); // (backup's own directory, as backupEnabled proves it)
  privateDir(fsx, state, uid, guard);
  privateDir(fsx, secrets, uid, guard);
  const P = { journal: join(state, JOURNAL), dest: join(state, DEST), cred: join(secrets, HANDLE), host: join(state, HOST_KEY), fresh: join(state, NEW_KEY), code: join(state, CODE_KEY) };
  const kinds = Object.fromEntries(Object.entries(P).map(([k, p]) => [k, kindOf(fsx, p, uid)]));
  const j = readJournal(fsx, state, uid);
  const setPhase = (phase, extra = {}) => { guard(); writeDurable(state, JOURNAL, journalText({ v: 1, phase, ...extra }), io); };
  const syncState = () => { const fd = io.open(state, "r"); try { io.fsync(fd); } finally { io.close(fd); } };
  const rename = (a, b) => { guard(); io.rename(a, b); syncState(); };
  const unlink = (p) => { guard(); fsx.unlinkSync(p); };
  const exclusive = (dir, name, data) => { guard(); writeExclusive(dir, name, data, io); };
  const removeAll = () => {
    for (const k of ["fresh", "code", "host", "dest"]) if (kindOf(fsx, P[k], uid) === "file") unlink(P[k]);
    if (kindOf(fsx, P.cred, uid) === "file") { unlink(P.cred); const fd = io.open(secrets, "r"); try { io.fsync(fd); } finally { io.close(fd); } }
    if (kindOf(fsx, P.journal, uid) === "file") unlink(P.journal);
    syncState();
  };
  const run = async (req) => {
    guard();
    const r = await deps.binary(req, { ms });
    guard();
    // A call the console's signal stopped: not a registered refusal, and its effect may have committed (add-key), so it
    // is reported as unknown; the journal stays, and the next attach probes.
    if (r?.code === "aborted") refuse("outcome_unknown", "backup attach: stopped by a signal; attach again to recover");
    return r;
  };

  if (discard) {
    // Only before any slot can exist: a present, well-formed `begun` journal, the destination's handle ours.
    if (j === null || j.phase !== "begun") refuse("not_granted", "backup attach: nothing to discard safely (a key slot may exist)");
    let d = null;
    if (kinds.dest === "file") try { d = JSON.parse(fsx.readFileSync(P.dest, "utf8")); } catch { d = null; }
    if (d?.credential?.secret !== HANDLE) refuse("not_granted", "backup attach: the destination isn't attach's");
    removeAll();
    return { discarded: true };
  }

  /** Step 5: the new host.key opens the repository; then the terminal phase. */
  const finish = async () => {
    const r = await run({ op: "snapshots" });
    if (!r.ok) refuse(r.code ?? "outcome_unknown", "backup attach: the repository doesn't open with the new key (attach again)");
    if (kindOf(fsx, P.code, uid) === "file") unlink(P.code);
    if (kindOf(fsx, P.fresh, uid) === "file") unlink(P.fresh);
    setPhase("attached");
    return { attached: true };
  };
  /** add-key with the new password; on its reported success, promote it over host.key. */
  const addAndPromote = async () => {
    const a = await run({ op: "add-key", password_file: P.fresh });
    if (!a.ok) refuse(a.code ?? "outcome_unknown", "backup attach: add-key didn't report success (attach again to probe)");
    setPhase("promoting");
    rename(P.fresh, P.host);
    return finish();
  };
  /** The probe (d3 §4), host.key now the new password and the code in attach-code.key. */
  const probe = async () => {
    const r = await run({ op: "snapshots" });
    if (r.ok) {
      // The new key is host.key for good: `promoting` first, so a later run never swaps it away.
      setPhase("promoting");
      if (kindOf(fsx, P.code, uid) === "file") { unlink(P.code); syncState(); }
      return finish();
    }
    // Only open_failed means the key didn't open the repository: no slot was added. Swap back, then add-key ONCE.
    if (r.code !== "open_failed") refuse(r.code ?? "outcome_unknown", "backup attach: the probe is inconclusive; attach again later");
    setPhase("probing", { swap: "back" });
    rename(P.host, P.fresh);
    rename(P.code, P.host);
    setPhase("slot-pending");
    return addAndPromote();
  };
  /** Start (or finish) the forward swap: host.key (the code) to attach-code.key, attach-new.key to host.key. */
  const swapForward = () => {
    if (kindOf(fsx, P.code, uid) === "absent") rename(P.host, P.code);
    if (kindOf(fsx, P.fresh, uid) === "file") rename(P.fresh, P.host);
  };
  /** Finish a back swap a crash interrupted: host.key (new) to attach-new.key, attach-code.key to host.key. */
  const swapBack = () => {
    if (kindOf(fsx, P.fresh, uid) === "absent") rename(P.host, P.fresh);
    if (kindOf(fsx, P.code, uid) === "file") rename(P.code, P.host);
  };

  if (j !== null) {
    switch (j.phase) {
      case "attached": refuse("in_progress", "backup attach: already attached");
      // eslint-disable-next-line no-fallthrough
      case "begun": removeAll(); break; // (no slot can exist: a fresh attach follows, from this input)
      case "slot-pending":
        setPhase("probing", { swap: "forward" });
        swapForward();
        return probe();
      case "probing":
        if (j.swap === "forward") { swapForward(); return probe(); }
        swapBack();
        setPhase("slot-pending");
        return addAndPromote();
      case "promoting":
        if (kindOf(fsx, P.fresh, uid) === "file") rename(P.fresh, P.host);
        return finish();
    }
  } else if (Object.values(kinds).some((k) => k !== "absent")) {
    // No journal, but attach's files: never a fresh state (a successful attach keeps its journal): refused.
    refuse("not_granted", "backup attach: attach's files are present without its journal");
  }

  // A fresh attach.
  if (input === null) refuse("bad_form", "backup attach: no input");
  checkInput(input);
  setPhase("begun");
  exclusive(state, DEST, JSON.stringify({ type: "s3", endpoint: input.dest.endpoint, bucket: input.dest.bucket, prefix: input.dest.prefix, region: input.dest.region, credential: { secret: HANDLE } }) + "\n");
  exclusive(secrets, HANDLE, JSON.stringify(input.credential) + "\n");
  exclusive(state, HOST_KEY, input.backup_code + "\n");
  const opened = await run({ op: "snapshots" });
  if (!opened.ok) { removeAll(); refuse(opened.code ?? "outcome_unknown", "backup attach: the repository doesn't open with this code"); }
  exclusive(state, NEW_KEY, rand(32).toString("base64url") + "\n");
  setPhase("slot-pending");
  return addAndPromote();
}

const USAGE = "usage: sagebrush-agent host backup attach [--discard]  (the input: one JSON object on stdin)";

/** stdin's bytes, at most one byte past the input's bound (parseInput refuses more). */
async function readStdin() {
  return readCommandInput({ max: MAX_INPUT });
}

/**
 * `sagebrush-agent host backup attach [--discard]`, root only, under the backup/restore exclusion for the whole
 * command; the input only from stdin. Resolves to { code, line } (one JSON line of codes) or { code: 2, usage }.
 * `deps` (seams): uid(), rootUid, state, secrets, exclusion, stdin(), binary, enabled(), restoreOpen(), rand.
 */
export async function backupAttachCommand(argv, deps = {}) {
  const { uid = () => process.getuid?.() ?? -1, rootUid = 0, state = BACKUP_STATE_DIR, secrets = HOST_SECRETS_DIR, exclusion = {}, stdin = readStdin, rand = randomBytes } = deps;
  const discard = argv.length === 2 && argv[1] === "--discard";
  if (argv[0] !== "attach" || !(argv.length === 1 || discard)) return { code: 2, line: null, usage: USAGE };
  if (uid() !== rootUid) return { code: 1, line: { v: 1, refused: "not_granted" } };
  try {
    const input = discard ? null : parseInput(await stdin());
    const ops = {
      binary: deps.binary ?? realBackupBinary(defaultRelease()),
      enabled: deps.enabled ?? (() => backupEnabled().enabled !== false), // (anything but a plain no counts as enabled)
      restoreOpen: deps.restoreOpen ?? (() => restoreOpen()),
    };
    // The exclusion's handle is proven around every binary call and before every effect (attach's guard).
    const out = await withExclusion((held) => attach(input, ops, { state, secrets, uid: rootUid, rand, discard,
      guard: () => {
        if (!held?.held?.()) refuse("outcome_unknown", "backup attach: the exclusion was lost; attach again to recover");
        if (commandSignal()?.aborted) refuse("outcome_unknown", "backup attach: stopped by a signal; attach again to recover");
      } }), exclusion);
    return { code: 0, line: { v: 1, ...out } };
  } catch (e) {
    // The code only (no path, value, secret or message reaches the line): a registered reason or a CONSOLE_CODES one.
    // Anything else thrown (a disk error midway) may have had effects: outcome_unknown, and the journal says what's next.
    return { code: 1, line: { v: 1, refused: e instanceof FleetError ? e.code : "outcome_unknown" } };
  }
}
