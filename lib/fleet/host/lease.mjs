// Host supervisor (design: agent-autonomous-host-execution-lease.md r3.11 §2, §2.1): the execution lease's root
// primitives, which hold without the supervisor. An agent runs only while its `lease` fence (fence.mjs) is down, and
// that fence is lowered ONLY by the activation helper here, under the agent's activation lock, after the checks below.
//
// Files under LEASE_DIR (/run/sagebrush/lease, tmpfs: gone at reboot), all root:
//   <id>            the published record {lease_id, lg, expiry_tick, gen, sg}: the lease whose watchdog is
//                   authoritative (0644); gen is the lease's grant generation (execution lease r3.12): only the
//                   restore-resume helper compares it, every other reader just requires it in range; sg is the suspend
//                   gate's generation the lease was requested under (lease-on r1.5 §6.2): it is live only while the
//                   gate is open at exactly that generation
//   sleep, reopen   the suspend gate (lease-on r1.5 §6.1): `sleep` written only by the system-sleep hook, `reopen`
//                   only by the supervisor; gateOf below is the one rule that reads them
//   <id>.spent      the tombstone: the highest lg any watchdog has acted for; it only grows (0644)
//   <id>.lock       the activation lock, flock(2): the helper and the watchdog's tombstone step take it exclusive,
//                   the launcher's lease-check takes it shared (0600)
//   <id>.lock.pid   the helper's pid while it holds the lock (diagnostic only: nothing is ever killed by pid)
//   <id>.health     the watchdog's last result, for the supervisor to report
// expiry_tick is CLOCK_BOOTTIME in ms (bootNow below); lg is the supervisor's per-agent lease generation.
//
// - The watchdog (leaseExpire): a transient systemd timer per lease (armWatchdog) runs it at expiry_tick - 30 s, in
//   its own service outside the agent's slice. It is a no-op ONLY if the record holds a strictly newer lg; otherwise
//   it acts: tombstone (the atomic max, under the lock), the durable fence, the runtime mask, then the stop of the
//   whole slice and the recursive empty proof, retried every 10 s until proven. It takes no supervisor, host-store,
//   executor or fence lock, and waits on no lock holder: if the activation lock isn't free in 5 s it raises the
//   fence, masks, and kills the slice (every holder of the lock but itself runs inside it), then tries again.
// - The helper (leaseActivate): runs in a scope inside the agent's slice; under the lock it checks that the tombstone
//   is below its lg, that its own timer is still waiting, and that now < expiry_tick - 30 s; only then lowers the
//   fence, unmasks, and queues the start. The supervisor runs it (activationArgv) only after arming and publishing.
// - The thaw helper (leaseThaw): a person's resume of a PAUSED agent (frozen by systemd's freezer). In its own scope
//   inside the agent's slice, under the exclusive activation lock, it checks that the published record is its lease,
//   liveCheck passes and `lease` is down; only then does it thaw the unit. So an expiry at or before that point wins
//   (the watchdog's tombstone or the effective end refuses it), and one after it kills the thawed slice as always.
// - Neither the watchdog nor anything else here but the helper lowers a fence, unmasks or starts; nothing but the thaw
//   helper thaws.

import * as fs from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { isId, refuse } from "../bytes.mjs";
import { countProcs, refuseUnderFenceLock, selfCgroup } from "./fence.mjs";
import { runArgv } from "./effects.mjs";
import { FENCE_DIR, UNIT_DIR, agentSlice, agentSliceCgroup, agentUnit } from "./names.mjs";
import { exactKeys, lockFile, realIo, writeDurable } from "./store.mjs";

export const LEASE_DIR = "/run/sagebrush/lease";
export const LEASE_FENCE_DIR = `${FENCE_DIR}/lease`;
/** The watchdog fires this long before expiry_tick, and that point is the effective end of a lease (SEC H1). */
export const MARGIN_MS = 30000;
/** One try at the activation lock. */
export const LOCK_TRY_MS = 5000;
/** The watchdog's retry period while the slice can't be proven empty. */
export const PROOF_RETRY_MS = 10000;
/** /proc/uptime's resolution: a reading may be this much behind CLOCK_BOOTTIME. */
const UPTIME_RES_MS = 10;
/** Each systemctl or busctl call; systemd-run's arming (a slower one discards the renewal). */
const CTL_MS = 5000;
const ARM_MS = 5000;
/** The polite stop of the slice; then the kernel's cgroup.kill, and at most this long for the tree to empty. */
const STOP_MS = 10000;
const KILL_WAIT_MS = 5000;
const POLL_MS = 100;
const CGROUP2_SUPER_MAGIC = 0x63677270;

const LEASE_ID = /^[A-Za-z0-9_-]{1,64}$/;
const LG = /^[1-9][0-9]{0,14}$/;
/** A host-internal refusal of a lease (never on the wire): the caller publishes nothing and lowers nothing. */
const unverified = (what) => { throw Object.assign(new Error(`lease: ${what}`), { code: "lease_unverified" }); };
const need = (agent) => { if (!isId(agent)) refuse("bad_form", "lease: bad agent id"); return agent; };
const needLg = (lg) => { if (!Number.isSafeInteger(lg) || lg < 1) refuse("bad_form", "lease: bad lg"); return lg; };
const needLeaseId = (l) => { if (typeof l !== "string" || !LEASE_ID.test(l)) refuse("bad_form", "lease: bad lease id"); return l; };

/** Parse the argv form of (agent, lease_id, lg); refuses anything else. */
export function parseArgs(agent, leaseId, lg) {
  if (typeof lg !== "string" || !LG.test(lg)) refuse("bad_form", "lease: bad lg");
  return { agent: need(agent), leaseId: needLeaseId(leaseId), lg: needLg(Number(lg)) };
}

/** The transient watchdog of one lease: `<base>.timer` and the `<base>.service` it runs. */
export const watchdogBase = (agent, lg) => `sagebrush-lease-${need(agent)}-${needLg(lg)}`;
export const watchdogTimer = (agent, lg) => `${watchdogBase(agent, lg)}.timer`;
/** The activation helper's scope, inside the agent's slice. */
export const helperScope = (agent) => `sagebrush-lease-activate-${need(agent)}.scope`;
/** The thaw helper's scope, inside the agent's slice. */
export const thawScope = (agent) => `sagebrush-lease-thaw-${need(agent)}.scope`;

/**
 * The real clocks. mono: CLOCK_MONOTONIC in µs (Node's hrtime is CLOCK_MONOTONIC on Linux, the clock of systemd's
 * NextElapseUSecMonotonic). boot: CLOCK_BOOTTIME in ms from /proc/uptime (it counts suspend; Node's clocks don't).
 */
export const realClock = Object.freeze({
  mono: () => Number(process.hrtime.bigint() / 1000n),
  boot: () => {
    const m = /^([0-9]+)\.([0-9]{2}) /.exec(fs.readFileSync("/proc/uptime", "utf8"));
    if (!m) throw Object.assign(new Error("lease: /proc/uptime unreadable"), { code: "EIO" });
    return Number(m[1]) * 1000 + Number(m[2]) * 10;
  },
});

/** Now on CLOCK_BOOTTIME, rounded UP by /proc/uptime's resolution: every "now < deadline" check is conservative. */
export const bootNow = (clock = realClock) => clock.boot() + UPTIME_RES_MS;

/**
 * The deadline in the monotonic domain (T2e): three back-to-back (mono, boot, mono) samples, the one with the smallest
 * gap kept; m* = m_before + (expiry_tick - b_upper) - 30 s, in µs. Taking the monotonic reading from BEFORE the boot
 * read and the boot reading rounded up both move m* earlier, never later.
 */
export function monotonicDeadline(expiryTick, clock = realClock) {
  let best = null;
  for (let i = 0; i < 3; i++) {
    const m1 = clock.mono(), b = clock.boot(), m2 = clock.mono();
    if (best === null || m2 - m1 < best.gap) best = { gap: m2 - m1, m: m1, b: b + UPTIME_RES_MS };
  }
  return best.m + (expiryTick - best.b - MARGIN_MS) * 1000;
}

// ---- the runtime files ----------------------------------------------------------------------------------------------

const MAX_FILE = 4096;
/** Read a small regular root file; null if it doesn't exist; throws if it isn't one or can't be read. */
function readSmall(path, fsx) {
  let st;
  try { st = fsx.lstatSync(path); } catch (e) { if (e?.code === "ENOENT") return null; throw e; }
  if (!st.isFile() || st.size > MAX_FILE) throw Object.assign(new Error("lease: not a small regular file"), { code: "EIO" });
  return fsx.readFileSync(path, "utf8");
}

/**
 * The published record: { state: "ok", rec } | { state: "missing" } | { state: "bad" } (unreadable or malformed:
 * never treated as newer, so a watchdog acts on it, and never as current, so nothing activates on it).
 */
export function readRecord(agent, { dir = LEASE_DIR, fsx = fs } = {}) {
  let text;
  try { text = readSmall(join(dir, need(agent)), fsx); } catch { return { state: "bad" }; }
  if (text === null) return { state: "missing" };
  let rec;
  try { rec = JSON.parse(text); } catch { return { state: "bad" }; }
  if (!exactKeys(rec, ["lease_id", "lg", "expiry_tick", "gen", "sg"]) || typeof rec.lease_id !== "string" || !LEASE_ID.test(rec.lease_id)
    || !Number.isSafeInteger(rec.lg) || rec.lg < 1 || !Number.isSafeInteger(rec.expiry_tick) || rec.expiry_tick < 0
    || !Number.isSafeInteger(rec.gen) || rec.gen < 1 || !Number.isSafeInteger(rec.sg) || rec.sg < 0) return { state: "bad" };
  return { state: "ok", rec };
}

/** The tombstone's lg: 0 when there is none; null when it can't be read (callers fail closed). */
export function readTombstone(agent, { dir = LEASE_DIR, fsx = fs } = {}) {
  let text;
  try { text = readSmall(join(dir, `${need(agent)}.spent`), fsx); } catch { return null; }
  if (text === null) return 0;
  return /^(0|[1-9][0-9]{0,14})\n$/.test(text) ? Number(text) : null;
}

// ---- the suspend gate (lease-on r1.5 §6.1, §6.1.1) --------------------------------------------------------------------

export const SLEEP_FILE = "sleep";
export const REOPEN_FILE = "reopen";
/** The highest generation the gate ever opens at. 2^53 - 1 is terminal: reaching it is exhaustion, closed (T4). */
export const G_MAX = 2 ** 53 - 2;
const SLEEP_KEYS = ["gen", "phase", "pre_ok", "pre_at"];
const PHASES = ["pre", "post"];

/**
 * One gate file: { state: "missing" } | { state: "bad" } | { state: "ok", text }. Read as restore-record's readRegular
 * reads: lstat, then an open that never follows a link and never blocks, then fstat of THAT handle, which must be the
 * same object (dev and ino), a regular file owned by `uid` (root in production), without group or other write, at most
 * MAX_FILE bytes. Anything else, or a read error, is "bad": the gate then reads closed.
 */
export function readGateFile(dir, name, { fsx = fs, uid = process.getuid?.() ?? 0 } = {}) {
  const path = join(dir, name), bad = { state: "bad" };
  let before;
  try { before = fsx.lstatSync(path); } catch (e) { return e?.code === "ENOENT" ? { state: "missing" } : bad; }
  if (!before.isFile()) return bad;
  let fd;
  try { fd = fsx.openSync(path, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK); } catch (e) {
    return e?.code === "ENOENT" ? { state: "missing" } : bad;
  }
  try {
    const st = fsx.fstatSync(fd);
    if (!st.isFile() || st.dev !== before.dev || st.ino !== before.ino || st.uid !== uid || (st.mode & 0o022) !== 0 || st.size > MAX_FILE) return bad;
    const buf = Buffer.alloc(st.size);
    for (let off = 0; off < buf.length;) {
      const n = fsx.readSync(fd, buf, off, buf.length - off, off);
      if (n <= 0) return bad;
      off += n;
    }
    return { state: "ok", text: new TextDecoder("utf-8", { fatal: true }).decode(buf) }; // invalid UTF-8 throws: bad
  } catch { return bad; } finally { try { fsx.closeSync(fd); } catch { /* closed */ } }
}

/** The gate files' string bound, in UTF-8 bytes (the launcher's json::parse_with(src, 16)). */
const GATE_MAX_STR = 16;

/**
 * The gate files' JSON, parsed EXACTLY as the launcher's strict reader (launcher/src/json.rs) parses them, for the flat
 * objects the gate uses: one object of string keys whose values are strings, booleans or non-negative integers.
 * Whitespace is space, tab, CR and LF; strings take the standard escapes (no surrogates, no control characters
 * unescaped, no NUL) and at most GATE_MAX_STR bytes; integers have no leading zero and nothing of a fraction, exponent
 * or sign; duplicate keys and trailing data are refused. Anything else, nested values included, is null. An integer
 * above 2^53 - 1 is kept as Infinity, which every range check refuses. Returns a plain object or null.
 */
export function parseGateJson(text) {
  if (typeof text !== "string") return null;
  let i = 0;
  const ws = () => { while (i < text.length && (text[i] === " " || text[i] === "\n" || text[i] === "\r" || text[i] === "\t")) i++; };
  const str = () => {
    i++; // the opening quote
    let out = "";
    for (;;) {
      if (i >= text.length) return null;
      const ch = text[i++];
      if (ch === '"') break;
      if (ch === "\\") {
        const e = text[i++];
        const simple = { '"': '"', "\\": "\\", "/": "/", n: "\n", t: "\t", r: "\r", b: "\b", f: "\f" };
        if (e in simple) out += simple[e];
        else if (e === "u") {
          const h = text.slice(i, i + 4);
          if (!/^[0-9A-Fa-f]{4}$/.test(h)) return null;
          i += 4;
          const n = parseInt(h, 16);
          if (n >= 0xd800 && n <= 0xdfff) return null; // surrogates are refused (Rust: char::from_u32)
          out += String.fromCharCode(n);
        } else return null;
      } else if (ch.charCodeAt(0) <= 0x1f) return null; // control characters must be escaped
      else out += ch;
      if (Buffer.byteLength(out, "utf8") > GATE_MAX_STR) return null;
    }
    return out.includes("\0") ? null : out;
  };
  const value = () => {
    ws();
    const ch = text[i];
    if (ch === '"') { const s2 = str(); return s2 === null ? undefined : s2; }
    if (text.startsWith("true", i)) { i += 4; return true; }
    if (text.startsWith("false", i)) { i += 5; return false; }
    if (ch >= "0" && ch <= "9") {
      const start = i;
      while (i < text.length && text[i] >= "0" && text[i] <= "9") i++;
      const digits = text.slice(start, i);
      if ((digits.length > 1 && digits[0] === "0") || digits.length > 20) return undefined;
      if (i < text.length && ".eE-+".includes(text[i])) return undefined; // integers only
      const big = BigInt(digits);
      if (big > 18446744073709551615n) return undefined; // fits u64
      return big > BigInt(Number.MAX_SAFE_INTEGER) ? Infinity : Number(big);
    }
    return undefined; // null, nested objects and arrays: no gate field takes one
  };
  ws();
  if (text[i] !== "{") return null;
  i++;
  const out = Object.create(null);
  ws();
  if (text[i] === "}") { i++; ws(); return i === text.length ? out : null; }
  for (;;) {
    ws();
    if (text[i] !== '"') return null;
    const k = str();
    if (k === null || Object.prototype.hasOwnProperty.call(out, k)) return null; // a duplicate key
    ws();
    if (text[i] !== ":") return null;
    i++;
    const v = value();
    if (v === undefined) return null;
    out[k] = v;
    ws();
    if (text[i] === "}") { i++; break; }
    if (text[i] !== ",") return null;
    i++;
  }
  ws();
  return i === text.length ? out : null;
}

/** `sleep`'s closed shape, or null: {gen >= 1, phase pre|post, pre_ok boolean, pre_at >= 0}, all safe integers. */
export function parseSleep(text) {
  const v = parseGateJson(text);
  if (v === null || !exactKeys(v, SLEEP_KEYS) || !Number.isSafeInteger(v.gen) || v.gen < 1 || !PHASES.includes(v.phase)
    || typeof v.pre_ok !== "boolean" || !Number.isSafeInteger(v.pre_at) || v.pre_at < 0) return null;
  return { gen: v.gen, phase: v.phase, pre_ok: v.pre_ok, pre_at: v.pre_at };
}

/** `reopen`'s closed shape, or null: {gen >= 1}, a safe integer. */
export function parseReopen(text) {
  const v = parseGateJson(text);
  if (v === null || !exactKeys(v, ["gen"]) || !Number.isSafeInteger(v.gen) || v.gen < 1) return null;
  return { gen: v.gen };
}

/**
 * THE gate rule, pure (lease-on r1.5 §6.1): from the two files' reads (readGateFile's results) and now on
 * CLOCK_BOOTTIME (ms). { open: true, g } | { open: false, why }. Open only when both files are absent (g = 0), or both
 * are trusted and well formed, `sleep` is at `post` with pre_at <= now, `reopen.gen` equals `sleep.gen`, and that
 * generation is at most G_MAX. Every reader (liveCheck, accept, publish's re-read, the hook, the reopen, the restore
 * loop, and the launcher in Rust over the same vectors) decides with this rule.
 */
export function gateOf(sleep, reopen, now) {
  if (sleep?.state === "missing" && reopen?.state === "missing") return { open: true, g: 0 };
  if (sleep?.state === "missing" || reopen?.state === "missing") return { open: false, why: "one_sided" };
  if (sleep?.state !== "ok" || reopen?.state !== "ok") return { open: false, why: "untrusted" };
  const sl = parseSleep(sleep.text), ro = parseReopen(reopen.text);
  if (sl === null || ro === null || !Number.isSafeInteger(now) || sl.pre_at > now) return { open: false, why: "malformed" };
  if (ro.gen > sl.gen) return { open: false, why: "reopen_ahead" };
  if (sl.phase !== "post") return { open: false, why: "pre" };
  if (ro.gen !== sl.gen) return { open: false, why: "unacknowledged" };
  if (sl.gen > G_MAX) return { open: false, why: "exhausted" };
  return { open: true, g: sl.gen };
}

/** The gate as it is now. A lease directory that isn't ours and private to writes reads closed. */
export function readGate({ dir = LEASE_DIR, fsx = fs, clock = realClock, uid = process.getuid?.() ?? 0 } = {}) {
  let st = null;
  try { st = fsx.lstatSync(dir); } catch (e) { if (e?.code !== "ENOENT") return { open: false, why: "untrusted" }; }
  if (st !== null && (!st.isDirectory() || st.uid !== uid || (st.mode & 0o022) !== 0)) return { open: false, why: "untrusted" };
  let now;
  try { now = bootNow(clock); } catch { return { open: false, why: "no_clock" }; }
  return gateOf(readGateFile(dir, SLEEP_FILE, { fsx, uid }), readGateFile(dir, REOPEN_FILE, { fsx, uid }), now);
}

function ensureDir(dir, fsx) {
  fsx.mkdirSync(dir, { recursive: true, mode: 0o755 });
  const st = fsx.lstatSync(dir);
  if (!st.isDirectory() || (st.mode & 0o022) !== 0 || st.uid !== process.getuid()) {
    throw Object.assign(new Error("lease: the lease directory isn't ours and private to writes"), { code: "EIO" });
  }
}

/** Publish a record atomically (temp, fsync, rename, directory fsync), 0644. The re-arm's step 2 checks come first. */
export function writeRecord(agent, { lease_id, lg, expiry_tick, gen, sg }, { dir = LEASE_DIR, fsx = fs, io = realIo } = {}) {
  need(agent); needLeaseId(lease_id); needLg(lg);
  if (!Number.isSafeInteger(expiry_tick) || expiry_tick < 0) refuse("bad_form", "lease: bad expiry tick");
  if (!Number.isSafeInteger(gen) || gen < 1) refuse("bad_form", "lease: bad gen");
  if (!Number.isSafeInteger(sg) || sg < 0) refuse("bad_form", "lease: bad sg");
  ensureDir(dir, fsx);
  writeDurable(dir, agent, JSON.stringify({ lease_id, lg, expiry_tick, gen, sg }), io, 0o644);
}

/** Take the agent's activation lock. Refuses `in_progress` if it isn't free within waitMs. */
export function activationLock(agent, { dir = LEASE_DIR, fsx = fs, waitMs = LOCK_TRY_MS, shared = false, lock = lockFile } = {}) {
  refuseUnderFenceLock("taking an activation lock");
  ensureDir(dir, fsx);
  const path = join(dir, `${need(agent)}.lock`);
  fsx.closeSync(fsx.openSync(path, "a", 0o600));
  return lock(path, { waitMs, shared });
}

// ---- the fence, written directly ------------------------------------------------------------------------------------

/** Raise the agent's `lease` fence durably, with no lock (raising is always safe): temp, fsync, rename, dir fsync. */
export function raiseLeaseFence(agent, { fenceDir = LEASE_FENCE_DIR, fsx = fs, io = realIo } = {}) {
  fsx.mkdirSync(fenceDir, { recursive: true, mode: 0o700 });
  writeDurable(fenceDir, need(agent), "", io, 0o600);
}

/** Lower it: unlink, then fsync the directory. Only the helper calls this, under the exclusive activation lock. */
function lowerLeaseFence(agent, { fenceDir, fsx }) {
  try { fsx.unlinkSync(join(fenceDir, agent)); } catch (e) { if (e?.code !== "ENOENT") throw e; }
  const fd = fsx.openSync(fenceDir, "r");
  try { fsx.fsyncSync(fd); } finally { fsx.closeSync(fd); }
}

// ---- systemd and the cgroup -----------------------------------------------------------------------------------------

/** A D-Bus object path for a unit name (systemd's escaping: every byte outside [A-Za-z0-9] as _xx). */
export const unitObjectPath = (unit) => `/org/freedesktop/systemd1/unit/${[...unit].map((c) => /[A-Za-z0-9]/.test(c) ? c : `_${c.charCodeAt(0).toString(16).padStart(2, "0")}`).join("")}`;

/**
 * The real systemd and cgroup steps, every command by argv with a hard timeout. `run` as in effects.mjs.
 * timer(unit) → { active, sub, next } (next: NextElapseUSecMonotonic in µs, 0 when none), read through busctl, which
 * prints the raw number (systemctl show formats time spans).
 */
export function realSystem({ run = runArgv, fsx = fs } = {}) {
  const ok = async (argv, ms) => { const r = await run(argv, { ms }); if (r.code !== 0) throw Object.assign(new Error(`lease: ${argv[0]} ${argv[1]} exited ${r.code}`), { code: "effect_failed" }); return r.stdout; };
  const prop = (text, type) => {
    const vals = text.trim().split("\n").map((l) => { const m = new RegExp(`^${type} (.*)$`).exec(l.trim()); if (!m) throw Object.assign(new Error("lease: unexpected busctl output"), { code: "effect_failed" }); return m[1]; });
    return vals;
  };
  return {
    arm: (argv) => ok(argv, ARM_MS),
    timer: async (unit) => {
      const path = unitObjectPath(unit);
      const [active, sub] = prop(await ok(["busctl", "get-property", "org.freedesktop.systemd1", path, "org.freedesktop.systemd1.Unit", "ActiveState", "SubState"], CTL_MS), "s").map((v) => JSON.parse(v));
      const [next] = prop(await ok(["busctl", "get-property", "org.freedesktop.systemd1", path, "org.freedesktop.systemd1.Timer", "NextElapseUSecMonotonic"], CTL_MS), "t");
      if (!/^[0-9]{1,20}$/.test(next)) throw Object.assign(new Error("lease: unexpected elapse"), { code: "effect_failed" });
      return { active, sub, next: Number(next) };
    },
    /** A runtime mask, then is-enabled must say masked (a shadowed mask isn't one). */
    mask: async (unit) => {
      await ok(["systemctl", "mask", "--runtime", unit], CTL_MS);
      const r = await run(["systemctl", "is-enabled", unit], { ms: CTL_MS });
      const state = r.stdout.trim();
      if (state !== "masked-runtime" && state !== "masked") throw Object.assign(new Error(`lease: the mask isn't effective (${state})`), { code: "effect_failed" });
    },
    unmask: (unit) => ok(["systemctl", "unmask", "--runtime", unit], CTL_MS),
    thaw: (unit) => ok(["systemctl", "thaw", unit], CTL_MS),
    /** Stop a superseded watchdog's timer (the re-arm's step 3); a failure leaves a stale timer, which is a no-op. */
    disarm: (unit) => ok(["systemctl", "stop", unit], CTL_MS),
    start: (unit) => ok(["systemctl", "start", "--no-block", unit], CTL_MS),
    stop: (unit) => ok(["systemctl", "stop", unit], STOP_MS),
    /** null: the cgroup doesn't exist. Throws unless it is a real cgroup v2 directory (not a symlink). */
    cgroup: (dir) => {
      let st;
      try { st = fsx.lstatSync(dir); } catch (e) { if (e?.code === "ENOENT") return null; throw e; }
      if (!st.isDirectory() || fsx.statfsSync(dir).type !== CGROUP2_SUPER_MAGIC) throw Object.assign(new Error("lease: the slice isn't a cgroup"), { code: "EIO" });
      return dir;
    },
    kill: (dir) => fsx.writeFileSync(join(dir, "cgroup.kill"), "1"),
    /** The system-sleep hook's and the reopen's mask of many units: ONE runtime mask, then is-enabled must say masked
     * for every one (a shadowed mask isn't one). */
    maskAll: async (units) => {
      if (units.length === 0) return;
      await ok(["systemctl", "mask", "--runtime", ...units], CTL_MS);
      const r = await run(["systemctl", "is-enabled", ...units], { ms: CTL_MS });
      const states = r.stdout.trim().split("\n").map((l) => l.trim());
      if (states.length !== units.length || !states.every((x) => x === "masked-runtime" || x === "masked")) {
        throw Object.assign(new Error("lease: a mask isn't effective"), { code: "effect_failed" });
      }
    },
    /** A cgroup's own cgroup.freeze: "0" or "1" (throws on anything else). */
    freezeRead: (dir) => {
      const v = fsx.readFileSync(join(dir, "cgroup.freeze"), "utf8").trim();
      if (v !== "0" && v !== "1") throw Object.assign(new Error("lease: unexpected cgroup.freeze"), { code: "EIO" });
      return v;
    },
    freezeWrite: (dir, v) => fsx.writeFileSync(join(dir, "cgroup.freeze"), v),
    /** The recursive proof: every cgroup.procs in the tree empty, and the slice's cgroup.events says populated 0. */
    empty: (dir) => {
      if (countProcs(dir, fsx) !== 0) return false;
      let ev;
      try { ev = fsx.readFileSync(join(dir, "cgroup.events"), "utf8"); } catch (e) { if (e?.code === "ENOENT" && !fsx.existsSync(dir)) return true; throw e; }
      return /^populated 0$/m.test(ev);
    },
    selfCgroup: () => selfCgroup(fsx),
  };
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const lgString = (lg) => String(needLg(lg));

/** The command a watchdog's service runs: this release's node and lease-main.mjs. */
export const MAIN = fileURLToPath(new URL("./lease-main.mjs", import.meta.url));

/**
 * The systemd-run argv that arms one lease's watchdog for the monotonic deadline mStar (µs): an OnBootSec timer
 * (CLOCK_MONOTONIC, absolute, so a slow systemd-run can't push it later), accurate to 1 s, whose service runs
 * `lease-expire` in the default system slice (outside every agent slice).
 */
export function armArgv(agent, leaseId, lg, mStar, { node = process.execPath, main = MAIN } = {}) {
  if (!Number.isSafeInteger(mStar) || mStar < 1) refuse("bad_form", "lease: bad deadline");
  return ["systemd-run", "--quiet", `--unit=${watchdogBase(agent, lg)}`, `--on-boot=${mStar}us`, "--timer-property=AccuracySec=1s",
    "--property=Type=exec", "--", node, main, "lease-expire", agent, needLeaseId(leaseId), lgString(lg)];
}

/**
 * Run a helper (an activation helper, or the restore-resume helper) by its argv, synchronously with a timeout. Refused
 * (lock_order) while this process holds the fence lock: the helper takes the activation lock and then the fence lock.
 */
export async function runHelper(argv, { run = runArgv, ms = 30000 } = {}) {
  refuseUnderFenceLock("launching a helper");
  return run(argv, { ms });
}

/** The argv the supervisor runs the helper with: a transient scope inside the agent's slice (§2.1). */
export function activationArgv(agent, leaseId, lg, { node = process.execPath, main = MAIN } = {}) {
  return ["systemd-run", "--scope", "--quiet", "--collect", `--slice=${agentSlice(agent)}`, `--unit=${helperScope(agent)}`,
    "--", node, main, "lease-activate", agent, needLeaseId(leaseId), lgString(lg)];
}

/** The argv of the thaw helper for a paused agent: a transient scope inside the agent's slice. */
export function thawArgv(agent, leaseId, lg, { node = process.execPath, main = MAIN } = {}) {
  return ["systemd-run", "--scope", "--quiet", "--collect", `--slice=${agentSlice(agent)}`, `--unit=${thawScope(agent)}`,
    "--", node, main, "lease-thaw", agent, needLeaseId(leaseId), lgString(lg)];
}

/** A timer is still a live watchdog: active, waiting, with its next elapse after monoNow. */
const waiting = (t, monoNow) => t.active === "active" && t.sub === "waiting" && t.next > monoNow;

/**
 * Step 1 of the re-arm (and of a first lease): arm the watchdog for `rec`, then read it back. Resolves to
 * { timer, mStar } only when the timer is active, waiting, and elapses after now and at or before m*; otherwise
 * throws code `lease_unverified` (the caller then publishes nothing and lowers nothing; the old watchdog stays).
 */
export async function armWatchdog(agent, rec, { sys = realSystem(), clock = realClock, node, main } = {}) {
  need(agent); needLeaseId(rec?.lease_id); needLg(rec?.lg);
  const mStar = monotonicDeadline(rec.expiry_tick, clock);
  if (!(mStar > clock.mono())) unverified("the deadline has already passed");
  const timer = watchdogTimer(agent, rec.lg);
  try { await sys.arm(armArgv(agent, rec.lease_id, rec.lg, mStar, { node, main })); } catch { unverified("arming failed"); }
  let t;
  try { t = await sys.timer(timer); } catch { unverified("the timer can't be read back"); }
  if (!waiting(t, clock.mono()) || t.next > mStar) unverified("the armed timer doesn't match the deadline");
  return { timer, mStar };
}

/**
 * Step 2's checks, immediately before publishing (and the helper's, under the lock): the suspend gate is open at
 * exactly rec.sg; the timer for rec.lg is active and waiting with a future elapse; the tombstone is readable and below
 * rec.lg; now < expiry_tick - 30 s. Returns null when all hold, else the first failing reason.
 */
export async function liveCheck(agent, rec, { dir = LEASE_DIR, fsx = fs, sys = realSystem(), clock = realClock } = {}) {
  // The suspend gate FIRST (lease-on r1.5 §6.2): open at exactly the lease's generation.
  const gate = readGate({ dir, fsx, clock });
  if (!gate.open || gate.g !== rec.sg) return "suspended";
  const spent = readTombstone(agent, { dir, fsx });
  if (spent === null) return "tombstone_unreadable";
  if (spent >= rec.lg) return "spent";
  if (!(bootNow(clock) < rec.expiry_tick - MARGIN_MS)) return "expired";
  let t;
  try { t = await sys.timer(watchdogTimer(agent, rec.lg)); } catch { return "timer_unreadable"; }
  if (!waiting(t, clock.mono())) return "timer_not_waiting";
  return null;
}

/**
 * Re-arm step 2 (lease-on r1.5 §6.3): under the agent's activation lock, EXCLUSIVE (a busy lock: not published), it
 * publishes `rec` only if liveCheck passes right before; then it reads the gate AGAIN, and if the gate is no longer
 * open at rec.sg it spends the lease (the tombstone's atomic max) before releasing the lock. So a publication either
 * finishes before the system-sleep hook's close, and the hook spends it under the same lock, or it is spent here.
 * Resolves true only if published and still live.
 */
export async function publish(agent, rec, opts = {}) {
  const { dir = LEASE_DIR, fsx = fs, io = realIo, lock = lockFile, clock = realClock } = opts;
  let held;
  try { held = await activationLock(agent, { dir, fsx, lock, waitMs: LOCK_TRY_MS }); } catch { return false; }
  try {
    if ((await liveCheck(agent, rec, opts)) !== null) return false;
    writeRecord(agent, rec, opts);
    const gate = readGate({ dir, fsx, clock });
    if (!gate.open || gate.g !== rec.sg) {
      writeDurable(dir, `${agent}.spent`, `${Math.max(readTombstone(agent, { dir, fsx }) ?? 0, rec.lg)}\n`, io, 0o644);
      return false;
    }
    return true;
  } finally { await held.release(); }
}

// ---- the watchdog ---------------------------------------------------------------------------------------------------

/**
 * `lease-expire <agent> <lease_id> <lg>`: see the header. Options are test seams: { dir, fenceDir, fsx, io, sys,
 * clock, lock, cgroupOf, backup, barrier, wait, maxProofRetries, maxLockRetries }. `backup(agent)` is the backup
 * run's standalone recovery (lease part 3; none yet). Resolves to the result written to <id>.health.
 */
export async function leaseExpire(agent, leaseId, lg, opts = {}) {
  const { dir = LEASE_DIR, fenceDir = LEASE_FENCE_DIR, fsx = fs, io = realIo, sys = realSystem({ fsx }), lock = lockFile,
    cgroupOf = agentSliceCgroup, backup = null, barrier = async () => {}, wait = sleep,
    maxProofRetries = Infinity, maxLockRetries = Infinity } = opts;
  need(agent); needLeaseId(leaseId); needLg(lg);
  const r = readRecord(agent, { dir, fsx });
  if (r.state === "ok" && r.rec.lg > lg) return { acted: false, reason: "newer" };

  const unit = agentUnit(agent), slice = cgroupOf(agent);
  const result = { acted: true, lg, tombstone: false, fence: false, masked: false, proven: false };
  const raise = () => { try { raiseLeaseFence(agent, { fenceDir, fsx, io }); result.fence = true; } catch { /* reported */ } };
  const mask = async () => { try { await sys.mask(unit); result.masked = true; } catch { /* reported; the fence holds */ } };
  const kill = () => { try { const d = sys.cgroup(slice); if (d) sys.kill(d); } catch { /* the proof decides */ } };

  // (2) The tombstone, under the exclusive lock; never waiting on a holder: on a busy lock, raise, mask and kill the
  // slice (every other holder is inside it), then try again.
  let forced = false, renewed = false;
  for (let attempt = 0; ; attempt++) {
    let held = null;
    try { held = await activationLock(agent, { dir, fsx, lock, waitMs: LOCK_TRY_MS }); } catch (e) {
      if (e?.code !== "in_progress" || attempt >= maxLockRetries) break; // no tombstone: the fence, mask and stop still run
      forced = true;
      raise(); await mask(); kill();
      await barrier("after_busy_kill", { attempt });
      continue;
    }
    try {
      // The atomic max: read, compute, write, all under the exclusive lock. An unreadable tombstone is replaced by lg.
      writeDurable(dir, `${agent}.spent`, `${Math.max(readTombstone(agent, { dir, fsx }) ?? 0, lg)}\n`, io, 0o644);
      result.tombstone = readTombstone(agent, { dir, fsx }) >= lg;
      // A record published since the first read, for a strictly newer lg, has its own verified watchdog: this one is
      // stale after all and stops nothing (unless it already had to kill the slice for the lock).
      const again = readRecord(agent, { dir, fsx });
      renewed = again.state === "ok" && again.rec.lg > lg;
    } catch { /* reported */ } finally { await held.release(); }
    break;
  }
  await barrier("after_tombstone", {});
  if (renewed && !forced) return { acted: false, reason: "newer", tombstone: result.tombstone };

  // (3) The durable fence, (4) the runtime mask.
  raise();
  await barrier("after_fence", {});
  await mask();
  await barrier("after_mask", {});

  // (6) A backup run holding the slice first (part 3), then the stop of the whole slice and the recursive proof.
  if (backup) { try { result.backup = await backup(agent); } catch { result.backup = null; } }
  try { await sys.stop(agentSlice(agent)); } catch { /* the kernel's kill follows */ }
  for (let n = 0; ; n++) {
    if (await stopAndProve(sys, slice, wait)) { result.proven = true; break; }
    writeHealth(agent, { ...result, state: "proof_failed" }, { dir, fsx, io });
    if (n >= maxProofRetries) break;
    await wait(PROOF_RETRY_MS);
  }
  const final = { ...result, state: result.proven ? "stopped" : "proof_failed" };
  writeHealth(agent, final, { dir, fsx, io });
  return final;
}

/** Kill the slice through the kernel (after checking it is a cgroup), then wait a bounded time for the proof. */
async function stopAndProve(sys, slice, wait) {
  let d;
  try { d = sys.cgroup(slice); } catch { return false; }
  if (d === null) return true; // no slice: nothing of the agent exists
  try { if (sys.empty(d)) return true; } catch { /* unknown: kill and look again */ }
  try { sys.kill(d); } catch { return false; }
  for (let t = 0; t <= KILL_WAIT_MS; t += POLL_MS) {
    try { if (sys.cgroup(slice) === null || sys.empty(d)) return true; } catch { /* unknown is never empty */ }
    await wait(POLL_MS);
  }
  return false;
}

function writeHealth(agent, h, { dir, fsx, io }) {
  try { ensureDir(dir, fsx); writeDurable(dir, `${agent}.health`, JSON.stringify(h), io, 0o644); } catch { /* best effort */ }
}

// ---- the activation helper ------------------------------------------------------------------------------------------

/**
 * `lease-activate <agent> <lease_id> <lg>`: see the header. Resolves to { activated, reason, lowered }. It refuses
 * (activated: false, nothing changed) unless it runs inside the agent's slice, gets the lock within 5 s, and every
 * check holds under it: the published record is exactly (lease_id, lg), and liveCheck passes.
 */
export async function leaseActivate(agent, leaseId, lg, opts = {}) {
  const { dir = LEASE_DIR, fenceDir = LEASE_FENCE_DIR, fsx = fs, sys = realSystem({ fsx }), clock = realClock, lock = lockFile,
    barrier = async () => {}, pid = process.pid } = opts;
  need(agent); needLeaseId(leaseId); needLg(lg);
  const own = sys.selfCgroup();
  if (own !== `/sagebrush.slice/sagebrush-agents.slice/${agentSlice(agent)}/${helperScope(agent)}`) return { activated: false, reason: "outside_slice", lowered: false };
  let held;
  try { held = await activationLock(agent, { dir, fsx, lock, waitMs: LOCK_TRY_MS }); } catch { return { activated: false, reason: "busy", lowered: false }; }
  try {
    fsx.writeFileSync(join(dir, `${agent}.lock.pid`), `${pid}\n`, { mode: 0o644 });
    await barrier("after_pid", {});
    const r = readRecord(agent, { dir, fsx });
    if (r.state !== "ok" || r.rec.lg !== lg || r.rec.lease_id !== leaseId) return { activated: false, reason: "not_published", lowered: false };
    const why = await liveCheck(agent, r.rec, { dir, fsx, sys, clock });
    if (why !== null) return { activated: false, reason: why, lowered: false };
    await barrier("after_checks", {});
    lowerLeaseFence(agent, { fenceDir, fsx });
    await barrier("after_lower", {});
    const unit = agentUnit(agent);
    try { await sys.unmask(unit); } catch { return { activated: false, reason: "unmask_failed", lowered: true }; }
    await barrier("after_unmask", {});
    try { await sys.start(unit); } catch { return { activated: false, reason: "start_failed", lowered: true }; }
    await barrier("after_start", {});
    return { activated: true, reason: null, lowered: true };
  } finally {
    try { fsx.unlinkSync(join(dir, `${agent}.lock.pid`)); } catch { /* gone */ }
    await held.release();
  }
}

// ---- the thaw helper ------------------------------------------------------------------------------------------------

/**
 * `lease-thaw <agent> <lease_id> <lg>`: thaw a paused agent's unit, only under its live lease. Resolves to
 * { thawed, reason }. It refuses (nothing changed) unless it runs in its scope inside the agent's slice, gets the
 * activation lock (exclusive) within 5 s, and under it: the published record is exactly (lease_id, lg), liveCheck
 * passes, and `lease` is down. Then the thaw, still under the lock.
 */
export async function leaseThaw(agent, leaseId, lg, opts = {}) {
  const { dir = LEASE_DIR, fenceDir = LEASE_FENCE_DIR, fsx = fs, sys = realSystem({ fsx }), clock = realClock, lock = lockFile,
    barrier = async () => {}, pid = process.pid } = opts;
  need(agent); needLeaseId(leaseId); needLg(lg);
  if (sys.selfCgroup() !== `/sagebrush.slice/sagebrush-agents.slice/${agentSlice(agent)}/${thawScope(agent)}`) return { thawed: false, reason: "outside_slice" };
  let held;
  try { held = await activationLock(agent, { dir, fsx, lock, waitMs: LOCK_TRY_MS }); } catch { return { thawed: false, reason: "busy" }; }
  try {
    fsx.writeFileSync(join(dir, `${agent}.lock.pid`), `${pid}\n`, { mode: 0o644 });
    await barrier("after_pid", {});
    const r = readRecord(agent, { dir, fsx });
    if (r.state !== "ok" || r.rec.lg !== lg || r.rec.lease_id !== leaseId) return { thawed: false, reason: "not_published" };
    const why = await liveCheck(agent, r.rec, { dir, fsx, sys, clock });
    if (why !== null) return { thawed: false, reason: why };
    if (fsx.existsSync(join(fenceDir, agent))) return { thawed: false, reason: "lease_raised" };
    await barrier("after_checks", {});
    try { await sys.thaw(agentUnit(agent)); } catch { return { thawed: false, reason: "thaw_failed" }; }
    await barrier("after_thaw", {});
    return { thawed: true, reason: null };
  } finally {
    try { fsx.unlinkSync(join(dir, `${agent}.lock.pid`)); } catch { /* gone */ }
    await held.release();
  }
}

// ---- the system-sleep hook and the reopen (lease-on r1.5 §6.1.1, §6.4, §6.5) --------------------------------------------

/** The parent of every agent slice: freezing it freezes them all, and cgroup.kill on it kills them all. */
export const AGENTS_CGROUP = "/sys/fs/cgroup/sagebrush.slice/sagebrush-agents.slice";
/** The hook's evidence log: one JSON line per step, appended and fsynced. */
export const SLEEP_LOG = "/var/log/sagebrush/lease-sleep.log";
/** PRE's whole budget, inside systemd-sleep's own timeout for hooks. */
export const SLEEP_BUDGET_MS = 60000;
/** `sleep` at `pre` for longer than this (PRE's budget plus 5 minutes) is reported stuck (C8b). */
export const STUCK_MS = SLEEP_BUDGET_MS + 300000;
/** The fixed point's rounds at most. */
export const SLEEP_ROUNDS = 5;
const MAX_SAFE = Number.MAX_SAFE_INTEGER;
const AGENT_UNIT_NAME = /^sagebrush-agent-([a-z2-7]{25}[aeimquy4])\.service$/;
const AGENT_SLICE_NAME = /^sagebrush-agents-([a-z2-7]{25}[aeimquy4])\.slice$/;
const sleepJson = (r) => JSON.stringify({ gen: r.gen, phase: r.phase, pre_ok: r.pre_ok, pre_at: r.pre_at });

/**
 * The gate files as the hook and the reopen see them: whether the lease directory is trusted (or absent), and each
 * file's read plus its parse (`v`, null when the text isn't the closed shape).
 */
export function gateFiles({ dir = LEASE_DIR, fsx = fs, uid = process.getuid?.() ?? 0 } = {}) {
  let dirOk = true;
  try { const st = fsx.lstatSync(dir); dirOk = st.isDirectory() && st.uid === uid && (st.mode & 0o022) === 0; } catch (e) { dirOk = e?.code === "ENOENT"; }
  const sleep = readGateFile(dir, SLEEP_FILE, { fsx, uid }), reopen = readGateFile(dir, REOPEN_FILE, { fsx, uid });
  if (sleep.state === "ok") sleep.v = parseSleep(sleep.text);
  if (reopen.state === "ok") reopen.v = parseReopen(reopen.text);
  return { dirOk, sleep, reopen };
}

const bothAbsent = (g) => g.dirOk && g.sleep.state === "missing" && g.reopen.state === "missing";
const parsed = (x) => x.state === "ok" && x.v !== null;

/**
 * PRE's first write (C9, with SEC's r1.4 bounds), pure: the `sleep` record to write, or null to write NOTHING.
 * Generation 1 only from a trusted both-absent state. Otherwise sleep.gen + 1, only from a trusted, well-formed `sleep`
 * AND `reopen` with reopen.gen <= sleep.gen (a `post` record) or < (a `pre` record), and only within the safe range.
 * Anything else (untrusted, malformed, one-sided, a reopen ahead, an overflow) writes nothing: the gate already reads
 * closed then. So the next generation is always strictly above every published `reopen`.
 */
export function preRecord(g, now) {
  if (!Number.isSafeInteger(now) || now < 0) return null;
  if (bothAbsent(g)) return { gen: 1, phase: "pre", pre_ok: false, pre_at: now };
  if (!parsed(g.sleep) || !parsed(g.reopen)) return null;
  const sl = g.sleep.v, ro = g.reopen.v;
  if (sl.phase === "post" ? ro.gen > sl.gen : ro.gen >= sl.gen) return null;
  if (sl.gen + 1 > MAX_SAFE) return null;
  return { gen: sl.gen + 1, phase: "pre", pre_ok: false, pre_at: now };
}

/**
 * Post's write (C9, SEC's r1.4 ruling), pure: the record, or null to write nothing.
 * - the exact well-formed `pre` record, with `reopen` absent or below it: the same record at `post`;
 * - a trusted both-absent state (PRE never wrote): a failed first generation;
 * - a trusted `post` record while the gate is OPEN at it (PRE didn't run): the next generation, pre_ok false, which
 *   closes the gate and forces the supervisor's full containment.
 * Anything else writes nothing.
 */
export function postRecord(g, now) {
  if (!Number.isSafeInteger(now) || now < 0) return null;
  if (bothAbsent(g)) return { gen: 1, phase: "post", pre_ok: false, pre_at: now };
  if (!parsed(g.sleep) || g.reopen.state === "bad" || (g.reopen.state === "ok" && g.reopen.v === null)) return null;
  const sl = g.sleep.v, roGen = g.reopen.state === "missing" ? 0 : g.reopen.v.gen;
  if (sl.phase === "pre") return roGen < sl.gen ? { ...sl, phase: "post" } : null;
  const open = gateOf(g.sleep, g.reopen, now);
  if (open.open && open.g === sl.gen) return { gen: sl.gen + 1, phase: "post", pre_ok: false, pre_at: now };
  return null;
}

/** The health reasons the gate itself gives (C8b, T4): [] or a sorted list. */
export function sleepHealth({ dir = LEASE_DIR, fsx = fs, clock = realClock, uid } = {}) {
  const g = gateFiles({ dir, fsx, ...(uid === undefined ? {} : { uid }) });
  const out = new Set();
  if (parsed(g.sleep)) {
    const sl = g.sleep.v;
    let now = null;
    try { now = bootNow(clock); } catch { /* no clock: no age */ }
    if (sl.phase === "pre" && now !== null && now - sl.pre_at > STUCK_MS) out.add("suspend_gate_stuck");
    if (parsed(g.reopen) && g.reopen.v.gen > sl.gen) out.add("suspend_gate_stuck");
    if (sl.gen > G_MAX) out.add("suspend_gate_exhausted");
  }
  return [...out].sort();
}

/** The hook's file, rendered for a release at the absolute path `release` (installed in /usr/lib/systemd/system-sleep). */
export function sleepHook(release) {
  if (typeof release !== "string" || !release.startsWith("/") || /[\s"'\\%$`]/.test(release)) refuse("bad_form", "sleep hook: the release must be a plain absolute path");
  return fs.readFileSync(new URL("./units/sagebrush-lease-sleep", import.meta.url), "utf8").replaceAll("@RELEASE@", release);
}

/** Append one line to the hook's log, fsynced. Best effort: the log is evidence, never a gate on the stop. */
function realSleepLog(line, { path = SLEEP_LOG, fsx = fs } = {}) {
  try {
    fsx.mkdirSync(join(path, ".."), { recursive: true, mode: 0o700 });
    const fd = fsx.openSync(path, "a", 0o600);
    try { fsx.writeSync(fd, `${JSON.stringify(line)}\n`); fsx.fsyncSync(fd); } finally { fsx.closeSync(fd); }
  } catch { /* best effort */ }
}

/** The agents to contain: the union of the unit files, the agent slices and the records. complete: every source read. */
export function sleepAgents({ unitDir = UNIT_DIR, agentsCgroup = AGENTS_CGROUP, dir = LEASE_DIR, fsx = fs } = {}) {
  const ids = new Set();
  let complete = true;
  const scan = (d, pick) => {
    let names;
    try { names = fsx.readdirSync(d); } catch (e) { if (e?.code !== "ENOENT") complete = false; return; }
    for (const n of names) { const id = pick(n); if (id && isId(id)) ids.add(id); }
  };
  scan(unitDir, (n) => AGENT_UNIT_NAME.exec(n)?.[1]);
  scan(agentsCgroup, (n) => AGENT_SLICE_NAME.exec(n)?.[1]);
  scan(dir, (n) => (isId(n) ? n : null));
  return { agents: [...ids].sort(), complete };
}

/**
 * One containment round, shared by PRE and the reopen: discover, raise `lease`, mask, freeze the parent (read back)
 * and kill it, spend each record under its activation lock (busy: kill the parent and retry, never wait unbounded),
 * prove the parent empty recursively. It never lowers, unmasks, starts or thaws; it never touches restore, transfer,
 * grant or backup-journal state; the only fence it adds is `lease` (C2). Resolves to { agents, complete, raised,
 * masked, frozen, spent, proven }.
 */
async function containRound(c) {
  const { dir, fenceDir, unitDir, agentsCgroup, fsx, io, sys, lock, wait, left, note } = c;
  const found = sleepAgents({ unitDir, agentsCgroup, dir, fsx });
  const out = { agents: found.agents, complete: found.complete, raised: true, masked: true, frozen: true, spent: true, proven: false };
  note("discover", { agents: found.agents, complete: found.complete });
  for (const a of found.agents) { try { raiseLeaseFence(a, { fenceDir, fsx, io }); } catch { out.raised = false; } }
  note("raised", { ok: out.raised });
  try { await sys.maskAll(found.agents.map(agentUnit)); } catch { out.masked = false; }
  note("masked", { ok: out.masked });
  let parent = null;
  try { parent = sys.cgroup(agentsCgroup); } catch { out.frozen = false; }
  if (parent) {
    try { sys.freezeWrite(parent, "1"); out.frozen = sys.freezeRead(parent) === "1"; } catch { out.frozen = false; }
    try { sys.kill(parent); } catch { /* the proof decides */ }
  }
  note("frozen", { ok: out.frozen });
  for (const a of found.agents) {
    const r = readRecord(a, { dir, fsx });
    if (r.state === "missing") continue;
    let done = false;
    while (left() > 0) {
      let held;
      try { held = await activationLock(a, { dir, fsx, lock, waitMs: Math.max(1, Math.min(LOCK_TRY_MS, left())) }); } catch (e) {
        if (e?.code !== "in_progress") break;
        if (parent) { try { sys.kill(parent); } catch { /* the proof decides */ } }
        continue;
      }
      try {
        const again = readRecord(a, { dir, fsx });
        if (again.state !== "ok") done = true; // malformed or gone: no reader passes it (S1), nothing to spend by lg
        else {
          writeDurable(dir, `${a}.spent`, `${Math.max(readTombstone(a, { dir, fsx }) ?? 0, again.rec.lg)}\n`, io, 0o644);
          done = (readTombstone(a, { dir, fsx }) ?? -1) >= again.rec.lg;
        }
      } catch { /* not spent */ } finally { await held.release(); }
      break;
    }
    if (!done) out.spent = false;
  }
  note("spent", { ok: out.spent });
  while (left() > 0) {
    if (await stopAndProve(sys, agentsCgroup, wait)) { out.proven = true; break; }
    await wait(Math.min(1000, Math.max(1, left())));
  }
  note("proven", { ok: out.proven });
  return out;
}

const roundOk = (r) => r.complete && r.raised && r.masked && r.frozen && r.spent && r.proven;

/**
 * `lease-sleep pre|post`, the system-sleep hook (lease-on r1.5 §6.4). It takes no supervisor, host-store, executor,
 * backup-journal or fence lock (C3).
 * pre: (1) the close, §6.1.1's first write (or nothing, when C9 forbids it: the gate already reads closed); (2) the
 * fixed point, at most SLEEP_ROUNDS rounds within SLEEP_BUDGET_MS: a round passes only if it is complete and its next
 * discovery finds no agent it didn't cover; (3) only then is the record PRE wrote rewritten with pre_ok true. PRE NEVER
 * thaws: the parent stays frozen across the suspend, until the supervisor's reopen thaws it after its own proof.
 * post: §6.1.1's post write, or nothing. Options are test seams: { dir, fenceDir, unitDir, agentsCgroup, fsx, io, sys,
 * lock, clock, log, now, wait, uid }.
 */
export async function leaseSleep(phase, opts = {}) {
  const { dir = LEASE_DIR, fenceDir = LEASE_FENCE_DIR, unitDir = UNIT_DIR, agentsCgroup = AGENTS_CGROUP, fsx = fs, io = realIo,
    sys = realSystem({ fsx }), lock = lockFile, clock = realClock, log = realSleepLog, now = () => performance.now(),
    wait = sleep, uid } = opts;
  if (phase !== "pre" && phase !== "post") refuse("bad_form", "lease: the sleep phase is pre or post");
  const stamp = () => { try { return { boot_ms: clock.boot(), mono_us: clock.mono() }; } catch { return {}; } };
  const note = (step, more = {}) => log({ phase, step, ...more, ...stamp() });
  const u = uid === undefined ? {} : { uid };
  let t = null;
  try { t = bootNow(clock); } catch { /* no clock: nothing can be stamped, so nothing is written */ }
  const write = (rec) => {
    try { ensureDir(dir, fsx); writeDurable(dir, SLEEP_FILE, sleepJson(rec), io, 0o644); return true; } catch { return false; }
  };
  if (phase === "post") {
    const rec = t === null ? null : postRecord(gateFiles({ dir, fsx, ...u }), t);
    const wrote = rec !== null && write(rec);
    note("post", { wrote: wrote ? rec : null });
    return { ok: true, phase, wrote: wrote ? rec : null };
  }
  const t0 = now();
  const left = () => SLEEP_BUDGET_MS - (now() - t0);
  const rec = t === null ? null : preRecord(gateFiles({ dir, fsx, ...u }), t);
  const wrote = rec !== null && write(rec);
  note("close", { wrote: wrote ? rec : null });
  const c = { dir, fenceDir, unitDir, agentsCgroup, fsx, io, sys, lock, wait, left, note };
  let passed = false, rounds = 0;
  while (!passed && rounds < SLEEP_ROUNDS && left() > 0) {
    rounds++;
    const r = await containRound(c);
    if (!roundOk(r)) continue;
    const next = sleepAgents({ unitDir, agentsCgroup, dir, fsx });
    passed = next.complete && next.agents.every((a) => r.agents.includes(a))
      && next.agents.every((a) => { const x = readRecord(a, { dir, fsx }); return x.state !== "ok" || (readTombstone(a, { dir, fsx }) ?? -1) >= x.rec.lg; });
  }
  let preOk = false;
  if (passed && wrote) {
    // Rewrite exactly the record PRE wrote, with pre_ok true, only if it is still that record.
    const g = gateFiles({ dir, fsx, ...u });
    if (g.sleep.state === "ok" && g.sleep.text === sleepJson(rec)) preOk = write({ ...rec, pre_ok: true });
  }
  note("done", { rounds, passed, pre_ok: preOk });
  return { ok: passed, phase, rounds, wrote: wrote ? rec : null, pre_ok: preOk };
}

/**
 * The reopen (lease-on r1.5 §6.5), host-side, in both settings. C8a: it acts ONLY when a trusted `sleep` has phase
 * `post` with reopen.gen < sleep.gen (`reopen` absent counts as 0) and sleep.gen <= G_MAX; in every other state it is a
 * no-op (no void, no raise, no mask, no spend, no kill), and it never treats `pre` as `post`. When it acts: `onAct()`
 * (the lease machine's void, when there is one), then containment (one round, every part required), then the parent
 * thawed (read back), then `reopen` written. Any failure leaves the gate closed and the parent frozen, for the next try.
 * It never lowers a fence, so `lease` fences stay raised (C8, the off path), and never touches restore (C8c).
 * Resolves { acted, ok, gen }.
 */
export async function reopenAfterSleep(opts = {}) {
  const { dir = LEASE_DIR, fenceDir = LEASE_FENCE_DIR, unitDir = UNIT_DIR, agentsCgroup = AGENTS_CGROUP, fsx = fs, io = realIo,
    sys = realSystem({ fsx }), lock = lockFile, log = () => {}, now = () => performance.now(), wait = sleep, uid,
    onAct = () => {}, budgetMs = SLEEP_BUDGET_MS } = opts;
  const g = gateFiles({ dir, fsx, ...(uid === undefined ? {} : { uid }) });
  if (!g.dirOk || !parsed(g.sleep) || g.sleep.v.phase !== "post" || g.sleep.v.gen > G_MAX) return { acted: false, ok: true, gen: null };
  if (g.reopen.state === "bad" || (g.reopen.state === "ok" && g.reopen.v === null)) return { acted: false, ok: true, gen: null };
  const gen = g.sleep.v.gen, roGen = g.reopen.state === "missing" ? 0 : g.reopen.v.gen;
  if (!(roGen < gen)) return { acted: false, ok: true, gen: null };
  await onAct();
  const t0 = now();
  const left = () => budgetMs - (now() - t0);
  const note = (step, more = {}) => log({ phase: "reopen", gen, step, ...more });
  const r = await containRound({ dir, fenceDir, unitDir, agentsCgroup, fsx, io, sys, lock, wait, left, note });
  if (!roundOk(r)) return { acted: true, ok: false, gen };
  let parent = null;
  try { parent = sys.cgroup(agentsCgroup); } catch { return { acted: true, ok: false, gen }; }
  if (parent) {
    try { sys.freezeWrite(parent, "0"); if (sys.freezeRead(parent) !== "0") return { acted: true, ok: false, gen }; } catch { return { acted: true, ok: false, gen }; }
  }
  // Still the generation we contained for (a new PRE in between would have written a newer one: then we stop here).
  const again = gateFiles({ dir, fsx, ...(uid === undefined ? {} : { uid }) });
  if (!parsed(again.sleep) || again.sleep.v.gen !== gen || again.sleep.v.phase !== "post") return { acted: true, ok: false, gen };
  try { ensureDir(dir, fsx); writeDurable(dir, REOPEN_FILE, JSON.stringify({ gen }), io, 0o644); } catch { return { acted: true, ok: false, gen }; }
  note("reopened", {});
  return { acted: true, ok: true, gen };
}
