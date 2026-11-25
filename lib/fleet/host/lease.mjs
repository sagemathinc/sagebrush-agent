// Host supervisor (design: agent-autonomous-host-execution-lease.md r3.11 §2, §2.1): the execution lease's root
// primitives, which hold without the supervisor. An agent runs only while its `lease` fence (fence.mjs) is down, and
// that fence is lowered ONLY by the activation helper here, under the agent's activation lock, after the checks below.
//
// Files under LEASE_DIR (/run/sagebrush/lease, tmpfs: gone at reboot), all root:
//   <id>            the published record {lease_id, lg, expiry_tick, gen}: the lease whose watchdog is authoritative
//                   (0644); gen is the lease's grant generation (execution lease r3.12): only the restore-resume
//                   helper compares it, every other reader just requires it in range
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
// - Neither the watchdog nor anything else here but the helper lowers a fence, unmasks or starts.

import * as fs from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { isId, refuse } from "../bytes.mjs";
import { countProcs, selfCgroup } from "./fence.mjs";
import { runArgv } from "./effects.mjs";
import { FENCE_DIR, agentSlice, agentSliceCgroup, agentUnit } from "./names.mjs";
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
  if (!exactKeys(rec, ["lease_id", "lg", "expiry_tick", "gen"]) || typeof rec.lease_id !== "string" || !LEASE_ID.test(rec.lease_id)
    || !Number.isSafeInteger(rec.lg) || rec.lg < 1 || !Number.isSafeInteger(rec.expiry_tick) || rec.expiry_tick < 0
    || !Number.isSafeInteger(rec.gen) || rec.gen < 1) return { state: "bad" };
  return { state: "ok", rec };
}

/** The tombstone's lg: 0 when there is none; null when it can't be read (callers fail closed). */
export function readTombstone(agent, { dir = LEASE_DIR, fsx = fs } = {}) {
  let text;
  try { text = readSmall(join(dir, `${need(agent)}.spent`), fsx); } catch { return null; }
  if (text === null) return 0;
  return /^(0|[1-9][0-9]{0,14})\n$/.test(text) ? Number(text) : null;
}

function ensureDir(dir, fsx) {
  fsx.mkdirSync(dir, { recursive: true, mode: 0o755 });
  const st = fsx.lstatSync(dir);
  if (!st.isDirectory() || (st.mode & 0o022) !== 0 || st.uid !== process.getuid()) {
    throw Object.assign(new Error("lease: the lease directory isn't ours and private to writes"), { code: "EIO" });
  }
}

/** Publish a record atomically (temp, fsync, rename, directory fsync), 0644. The re-arm's step 2 checks come first. */
export function writeRecord(agent, { lease_id, lg, expiry_tick, gen }, { dir = LEASE_DIR, fsx = fs, io = realIo } = {}) {
  need(agent); needLeaseId(lease_id); needLg(lg);
  if (!Number.isSafeInteger(expiry_tick) || expiry_tick < 0) refuse("bad_form", "lease: bad expiry tick");
  if (!Number.isSafeInteger(gen) || gen < 1) refuse("bad_form", "lease: bad gen");
  ensureDir(dir, fsx);
  writeDurable(dir, agent, JSON.stringify({ lease_id, lg, expiry_tick, gen }), io, 0o644);
}

/** Take the agent's activation lock. Refuses `in_progress` if it isn't free within waitMs. */
export function activationLock(agent, { dir = LEASE_DIR, fsx = fs, waitMs = LOCK_TRY_MS, shared = false, lock = lockFile } = {}) {
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

/** The argv the supervisor runs the helper with: a transient scope inside the agent's slice (§2.1). */
export function activationArgv(agent, leaseId, lg, { node = process.execPath, main = MAIN } = {}) {
  return ["systemd-run", "--scope", "--quiet", "--collect", `--slice=${agentSlice(agent)}`, `--unit=${helperScope(agent)}`,
    "--", node, main, "lease-activate", agent, needLeaseId(leaseId), lgString(lg)];
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
 * Step 2's checks, immediately before publishing (and the helper's, under the lock): the timer for rec.lg is active
 * and waiting with a future elapse; the tombstone is readable and below rec.lg; now < expiry_tick - 30 s. Returns
 * null when all hold, else the first failing reason.
 */
export async function liveCheck(agent, rec, { dir = LEASE_DIR, fsx = fs, sys = realSystem(), clock = realClock } = {}) {
  const spent = readTombstone(agent, { dir, fsx });
  if (spent === null) return "tombstone_unreadable";
  if (spent >= rec.lg) return "spent";
  if (!(bootNow(clock) < rec.expiry_tick - MARGIN_MS)) return "expired";
  let t;
  try { t = await sys.timer(watchdogTimer(agent, rec.lg)); } catch { return "timer_unreadable"; }
  if (!waiting(t, clock.mono())) return "timer_not_waiting";
  return null;
}

/** Re-arm step 2: publish `rec` only if liveCheck passes right before. Resolves true if published. */
export async function publish(agent, rec, opts = {}) {
  const why = await liveCheck(agent, rec, opts);
  if (why !== null) return false;
  writeRecord(agent, rec, opts);
  return true;
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
