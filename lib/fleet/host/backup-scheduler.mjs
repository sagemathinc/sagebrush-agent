// Host backup (design: agent-autonomous-host-backup.md r3.3 §6): the scheduler. One run at a time per host, daily at
// 03:00 host-local (a systemd timer) and on demand, change-aware.
//
// **Off unless set up.** A run does anything only when the host has a destination (backup/state/dest.json) AND the
// host-local enabled flag (backup/enabled) that `host backup init` writes. Both must be regular root-owned 0600 files
// (never a link) in the root-only 0700 backup directory. Otherwise the run is a no-op that reports "not set up".
// Nothing here installs the timer: that is `host backup init`'s.
//
// One run (runOnce), under the backup/restore exclusion (no restore open, W1), then the run lock, proving both held
// for its whole life (init-run d6 §6.1, A1):
//   1. the root filesystem keeps its 5 GiB reserve, and the cache image is mounted (a fixed-size loop image, so the
//      cache's cap holds during the run by construction);
//   2. a journal left by an earlier run is recovered first (the recovery order, then its warm snapshot forgotten);
//   3. ONE snapshot of the host store, by its owner (wiring r0.4 §1.1, backup-snapshot.mjs): the registry copy and the
//      host store's copy from one locked view; the source sets built from that registry, forbidden roots refused, and
//      each set walked;
//   4. each set that changed since its last good snapshot gets the consistent pass (backup-run.mjs); an unchanged
//      one keeps its last good snapshot in the new manifest;
//   5. the snapshot's host-store copy is backed up;
//   6. only if every part is good: the manifest is committed and read back (backup-manifest.mjs);
//   7. then retention (backup-retention.mjs), the weekly prune, and the day's rotating data check.
// The turn-lease interface (an agent's active turns) is injected. Until the real one lands, the host passes none
// (lease: null, wiring r0.4 §4 Q1): a pass is consistency=crash at once, with no wait. failClosedLease stands for a
// configured provider whose every read fails (it waits its bound, and is never an idle proof).

import { randomBytes } from "node:crypto";
import * as fs from "node:fs";
import { join } from "node:path";
import { refuse } from "../bytes.mjs";
import { clearJournal, readJournal, recoverBackup, withJournalLock } from "./backup-journal.mjs";
import { BACKUP_DIR, FENCE_DIR } from "./names.mjs";
import { writeDurable, writeExclusive, lockDir } from "./store.mjs";
import { readRegular } from "./restore-record.mjs";

export const ROOT_RESERVE = 5 * 1024 ** 3;
export const CACHE_BYTES = 4 * 1024 ** 3;
export const CACHE_TRIM_TO = 3 * 1024 ** 3;
export const CACHE_DIR = "/var/cache/sagebrush-backup";
export const CACHE_IMAGE = "/var/lib/sagebrush/backup-cache.img";
export const STATE_FILE = "state.json";
export const ENABLED_FILE = "enabled";
export const DEST_FILE = "dest.json";
export const HOST_ID_FILE = "host-id";

/** The turn-lease interface for a host without the real one yet: every read fails, so no agent is ever idle. */
export const failClosedLease = Object.freeze({ activeTurns: async () => { throw Object.assign(new Error("no turn-lease provider"), { code: "ENOSYS" }); } });

/**
 * Is backup set up on this host? { enabled: true } or { enabled: false, why }. The backup directory and its state
 * directory (the binary's, where dest.json is: `state/`, names.mjs BACKUP_STATE_DIR) must be real directories owned by root (rootUid)
 * with mode 0700; the enabled flag (in the backup directory) and dest.json (in the state directory) regular files
 * (never links) owned by root with mode 0600.
 */
export function backupEnabled({ dir = BACKUP_DIR, stateDir = join(dir, "state"), fsx = fs, rootUid = 0 } = {}) {
  const st = (p) => { try { return fsx.lstatSync(p); } catch (e) { if (e?.code === "ENOENT") return null; throw e; } };
  for (const [p, what] of [[dir, "the backup directory"], [stateDir, "the backup state directory"]]) {
    const d = st(p);
    if (!d) return { enabled: false, why: "not set up" };
    if (!d.isDirectory() || d.uid !== rootUid || (d.mode & 0o777) !== 0o700) return { enabled: false, why: `${what} isn't root's 0700 directory` };
  }
  for (const [p, name] of [[join(stateDir, DEST_FILE), DEST_FILE], [join(dir, ENABLED_FILE), ENABLED_FILE]]) {
    const f = st(p);
    if (!f) return { enabled: false, why: "not set up" };
    if (!f.isFile() || f.uid !== rootUid || (f.mode & 0o777) !== 0o600) return { enabled: false, why: `${name} isn't a root-owned 0600 file` };
  }
  return { enabled: true };
}

const B32 = "abcdefghijklmnopqrstuvwxyz234567";
/** A run id: the UTC time to the second and 8 random base32 characters. */
export function newRunId(now, rand = randomBytes) {
  const t = new Date(now).toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z");
  const b = rand(8);
  return `${t}-${[...b].map((x) => B32[x & 31]).join("")}`;
}

/**
 * The install's backup host id (wiring r0.4 §4, amended): `local-` and 26 random base32 characters (130 bits), made
 * once on the first run and kept for the install's life, paired or not, so every manifest of this install is one
 * host's to retention. `<dir>/host-id`: root's 0600 regular file, written exclusively and durably, read no-follow.
 * Resolves to the id, or refuses (not_granted for a file that isn't root's 0600 one; bad_form for other content).
 */
export function backupHostId({ dir = BACKUP_DIR, uid = 0, fsx = fs, rand = randomBytes, guard = () => {} } = {}) {
  const p = join(dir, HOST_ID_FILE);
  const read = () => {
    let st;
    try { st = fsx.lstatSync(p); } catch (e) { if (e?.code === "ENOENT") return null; throw e; }
    if (!st.isFile() || st.uid !== uid || (st.mode & 0o7777) !== 0o600) refuse("not_granted", "backup: the host id isn't root's 0600 file");
    const text = readRegular(p, 128, "the host id", fsx).toString("utf8");
    if (!/^local-[a-z2-7]{26}\n$/.test(text)) refuse("bad_form", "backup: the host id is malformed");
    return text.trim();
  };
  const have = read();
  if (have !== null) return have;
  const b = rand(17);
  let bits = 0, n = 0, id = "";
  for (const byte of b) { n = (n << 8) | byte; bits += 8; while (bits >= 5 && id.length < 26) { id += B32[(n >> (bits - 5)) & 31]; bits -= 5; } }
  guard();
  writeExclusive(dir, HOST_ID_FILE, `local-${id}\n`);
  return read();
}

/** A source set's key in the state file. */
export const setKey = (set) => `${set.kind}:${set.id ?? "host"}`;

/**
 * The state file's closed shape: { v: 1, last_success, last_prune, last_check_day, sets: { key: { fingerprint,
 * snapshot, tree, since } } }. `since` is when a change was first seen that no good snapshot covers yet (the debt),
 * or null.
 */
export function checkState(s) {
  const ok = s !== null && typeof s === "object" && s.v === 1 && Object.keys(s).length === 5
    && (s.last_success === null || typeof s.last_success === "number")
    && (s.last_prune === null || typeof s.last_prune === "number")
    && (s.last_check_day === null || Number.isSafeInteger(s.last_check_day))
    && s.sets !== null && typeof s.sets === "object" && !Array.isArray(s.sets)
    && Object.values(s.sets).every((x) => x && typeof x === "object" && Object.keys(x).length === 4
      && (x.snapshot === null || /^[0-9a-f]{64}$/.test(x.snapshot)) && (x.tree === null || /^[0-9a-f]{64}$/.test(x.tree))
      && (x.since === null || typeof x.since === "number") && (x.fingerprint === null || typeof x.fingerprint === "object"));
  if (!ok) refuse("bad_form", "backup state: not a valid state file");
  return s;
}
export const emptyState = () => ({ v: 1, last_success: null, last_prune: null, last_check_day: null, sets: {} });

/**
 * The run's plan: for each set, whether it is backed up now or keeps its last good snapshot. A set is skipped only
 * when its fingerprint equals the one recorded with its last good snapshot (and that snapshot and tree are known).
 */
export function planRun(sets, fingerprints, state, unchanged) {
  return sets.map((set) => {
    const prev = state.sets[setKey(set)] ?? null;
    const fp = fingerprints.get(setKey(set));
    const keep = prev !== null && prev.snapshot !== null && prev.tree !== null && unchanged(fp, prev.fingerprint);
    return { set, fingerprint: fp, back_up: !keep, parent: prev?.snapshot ?? null, keep: keep ? { snapshot: prev.snapshot, tree: prev.tree } : null };
  });
}

/**
 * Which cache files to delete so the cache is at most `target` bytes: the least recently used first. `files`:
 * [{ path, size, atime }]. Returns the paths.
 */
export function trimPlan(files, target = CACHE_TRIM_TO) {
  let total = files.reduce((n, f) => n + f.size, 0);
  const out = [];
  for (const f of [...files].sort((a, b) => a.atime - b.atime || (a.path < b.path ? -1 : 1))) {
    if (total <= target) break;
    out.push(f.path); total -= f.size;
  }
  return out;
}

/**
 * The status shown to the person: { state: "not set up" | "ok" | "failing", last_success, debt_since, sets }. `debt_since`
 * is the oldest change not yet backed up (null when none). (The monthly cost and the offline state are the app's.)
 */
export function buildStatus({ enabled, state, lastRun = null }) {
  if (!enabled.enabled) return { state: "not set up", why: enabled.why, last_success: null, debt_since: null, sets: 0 };
  const debts = Object.values(state.sets).map((x) => x.since).filter((t) => t !== null);
  return {
    state: lastRun === null || lastRun.status === "ok" ? "ok" : "failing",
    last_success: state.last_success,
    debt_since: debts.length ? Math.min(...debts) : null,
    sets: Object.keys(state.sets).length,
  };
}

/** Read the state file (absent: the empty state). An unreadable or invalid one refuses. */
export function readState({ dir = BACKUP_DIR, fsx = fs } = {}) {
  let text;
  try { text = fsx.readFileSync(join(dir, STATE_FILE), "utf8"); } catch (e) { if (e?.code === "ENOENT") return emptyState(); throw e; }
  let s;
  try { s = JSON.parse(text); } catch { refuse("bad_form", "backup state: not JSON"); }
  return checkState(s);
}
export function writeState(s, { dir = BACKUP_DIR } = {}) { checkState(s); writeDurable(dir, STATE_FILE, JSON.stringify(s) + "\n"); }

/**
 * Run `fn(lock)` under the run lock (one backup run per host at a time); `lock.held()` proves it still held (A1).
 * Refuses in_progress when another holds it.
 */
export async function withRunLock(fn, { dir = join(BACKUP_DIR, "run") } = {}) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const lock = await lockDir(dir, { waitMs: 0 });
  try { return await fn(lock); } finally { await lock.release(); }
}

/** What the run's guard throws once a lock the run holds is gone (init-run d6 §6.1, A1). */
export const lockLost = () => Object.assign(new Error("backup run: a lock the run holds is gone"), { code: "lock_lost" });

/** The systemd units: the daily timer (03:00 host-local, catching up a missed run) and the oneshot service it starts. */
export function backupUnits(release) {
  if (typeof release !== "string" || !/^\/[A-Za-z0-9._/-]+$/.test(release) || release.split("/").includes("..")) refuse("bad_form", "backup units: bad release path");
  const service = [
    "[Unit]", "Description=Sagebrush host backup", "After=network-online.target", "Wants=network-online.target", "",
    "[Service]", "Type=oneshot", `ExecStartPre=/usr/lib/sagebrush/release-trust ${release}`, `ExecStart=/usr/bin/node ${release}/bin/sagebrush-agent.mjs host backup run`, "Nice=10", "IOSchedulingClass=idle",
    "Slice=sagebrush-backup.slice",
    // The whole run's budget (wiring r0.4 §1): for a oneshot, TimeoutStartSec bounds the run; at it systemd stops the
    // run's own processes (a worker's scope is outside the service's cgroup: the next run's recoverLeftover reaps it).
    "TimeoutStartSec=10h", "TimeoutStopSec=60s", "KillMode=control-group", "",
  ].join("\n");
  const timer = [
    "[Unit]", "Description=Sagebrush host backup, daily", "",
    "[Timer]", "OnCalendar=*-*-* 03:00:00", "Persistent=true", "RandomizedDelaySec=0", "", "[Install]", "WantedBy=timers.target", "",
  ].join("\n");
  return { service, timer, names: { service: "sagebrush-backup.service", timer: "sagebrush-backup.timer" } };
}

/**
 * One scheduled or on-demand run. Every effect is in `deps` (the host passes the real ones; tests pass fakes):
 * - withExclusion(fn): the backup/restore exclusion (wiring r0.4 §2), taken with no wait, calling fn(guard); refuses
 *   in_progress when another holds it. `guard()` throws (code lock_lost) once the exclusion is gone;
 * - restoreOpen(): W1, under the exclusion (false only when no restore is open); enabled(): backupEnabled's result;
 * - withRunLock(fn): fn(lock) under the run lock; freeBytes(path); ensureCache(); trimCache();
 * - recoverLeftover(guard): recover a journal left by an earlier run (the recovery order, its warm snapshot forgotten,
 *   the record cleared); resolves to { ok } or refuses when the journal can't be read;
 * - snapshot(run, guard): the ONE snapshot of the host store (r0.4 §1.1, backup-snapshot.mjs runSnapshot): resolves to
 *   { ok: true, registry, hoststore } (the registry copy and the host store's copy, from one locked view) or
 *   { ok: false, why };
 * - configHash(agent): the agent's config entry (until it is proven from the committed snapshot, r0.4 §1.2, it
 *   throws: the run fails `config_unbound` rather than bind config any other way); forbidden(): the roots no source
 *   may touch (FIXED_FORBIDDEN plus the harnesses' profile roots);
 * - sources(registry), checkForbidden(paths, roots), walk(set), unchanged(a, b): backup-sources.mjs's;
 * - backupSet(set, run, { parent, guard, host }): backup-run.mjs's, with its own deps bound;
 * - binary(req, { ms }): the backup binary; commitManifest(m, staging, guard), buildManifest(args): backup-manifest.mjs's;
 * - retention({ now, host, activeRun, guard }): backup-retention.mjs's pass; pruneDue(last, now), checkDataPart(now);
 * - hostId(guard): the install's backup host id (backupHostId); state: { read(), write(s) }; now(); stagingDir(name).
 * Resolves to { status: "not set up" | "skipped" | "failed" | "ok", ... }:
 * - skipped: busy (the exclusion is held), restore_open, root_reserve or snapshot_unavailable, each with nothing
 *   written;
 * - failed: lock_lost (A1: the exclusion or the run lock is gone; the run stopped at once, no later binary call or
 *   effect, its backup journal kept for the next run's recoverLeftover), or the failing parts.
 * The state never claims more than the store holds: before any backup work it records the debt of every set about to
 * be backed up, and only a committed manifest clears that debt and records the new snapshots and the last success.
 */
export async function runOnce(deps) {
  let entered = false;
  try {
    return await deps.withExclusion(async (guard) => {
      entered = true;
      guard();
      const open = deps.restoreOpen();
      guard();
      if (open !== false) return { status: "skipped", why: "restore_open" };
      const enabled = deps.enabled();
      guard();
      if (!enabled.enabled) return { status: "not set up", why: enabled.why };
      return deps.withRunLock((lock) => underLocks(deps, () => {
        guard();
        if (typeof lock?.held === "function" && !lock.held()) throw lockLost();
      }));
    });
  } catch (e) {
    if (!entered && e?.code === "in_progress") return { status: "skipped", why: "busy" };
    if (e?.code === "lock_lost") return { status: "failed", why: "lock_lost" };
    throw e;
  }
}

/** The run itself, under the exclusion and the run lock; `g()` proves both (before every effect, after every await). */
async function underLocks(deps, g) {
  const at = async (f) => { g(); const r = await f(); g(); return r; };
  const now = deps.now();
  if (deps.freeBytes("/") < ROOT_RESERVE) return { status: "skipped", why: "root_reserve" };
  await at(() => deps.ensureCache());
  await at(() => deps.recoverLeftover(g));
  const run = newRunId(now);
  g();
  const host = deps.hostId(g);
  const snap = await at(() => deps.snapshot(run, g));
  if (!snap.ok) return { status: "skipped", why: snap.why ?? "snapshot_unavailable" };
  const registry = snap.registry;
  const sets = deps.sources(registry);
  deps.checkForbidden(sets.flatMap((s) => s.sources), deps.forbidden());
  const state = deps.state.read();
  const fingerprints = new Map(), unrestorable = new Map();
  for (const set of sets) {
    const w = deps.walk(set);
    fingerprints.set(setKey(set), w.fingerprint);
    unrestorable.set(setKey(set), w.unrestorable);
  }
  const plan = planRun(sets, fingerprints, state, deps.unchanged);
  // The debt first, before any backup work: every set about to be backed up keeps its last good fingerprint,
  // snapshot and tree, and its change counts as not backed up (since: the earlier debt, or now) until a committed
  // manifest covers it. So every failure or throw from here on leaves the debt recorded; only the commit clears it.
  const next = { ...state, sets: { ...state.sets } };
  for (const p of plan) {
    if (!p.back_up) continue;
    const prev = state.sets[setKey(p.set)];
    next.sets[setKey(p.set)] = { fingerprint: prev?.fingerprint ?? null, snapshot: prev?.snapshot ?? null, tree: prev?.tree ?? null, since: prev?.since ?? now };
  }
  g();
  deps.state.write(next);
  const done = [], failures = [];
  for (const p of plan) {
    const key = setKey(p.set);
    if (!p.back_up) { done.push({ ...p.set, snapshot: p.keep.snapshot, tree: p.keep.tree, unrestorable: unrestorable.get(key) }); continue; }
    const r = await at(() => deps.backupSet(p.set, run, { parent: p.parent, guard: g, host }));
    if (r.outcome !== "good") { failures.push({ key, code: r.code }); continue; }
    done.push({ ...p.set, snapshot: r.snapshot, tree: null, unrestorable: unrestorable.get(key), fingerprint: p.fingerprint });
  }
  // The host store: the snapshot's copy (one locked view with the registry above), backed up like a set never live.
  let hoststore = null;
  if (failures.length === 0) {
    const r = await at(() => deps.backupSet({ kind: "hoststore", id: null, sources: [snap.hoststore], uids: [], members: [] }, run, { parent: null, guard: g, host }));
    if (r.outcome !== "good") failures.push({ key: "hoststore", code: r.code }); else hoststore = r.snapshot;
  }
  if (failures.length) return { status: "failed", run, failures }; // the debt is already written
  // Trees of the snapshots made in this run, from the store's own listing.
  const list = await at(() => deps.binary({ op: "snapshots" }, { ms: 30 * 60 * 1000 }));
  if (!list.ok) return { status: "failed", run, failures: [{ key: "listing", code: list.code }] };
  const treeOf = new Map(list.value.snapshots.map((s) => [s.id, s.tree]));
  for (const d of done) if (d.tree === null) d.tree = treeOf.get(d.snapshot) ?? null;
  if (done.some((d) => d.tree === null)) return { status: "failed", run, failures: [{ key: "listing", code: "snapshot_missing" }] };
  const config = {};
  for (const id of Object.keys(registry.agents).filter((a) => registry.agents[a].state !== "deleted")) {
    try { config[id] = await at(() => deps.configHash(id)); } catch (e) {
      if (e?.code === "lock_lost") throw e;
      failures.push({ key: `config:${id}`, code: "config_unbound" });
    }
  }
  if (failures.length) return { status: "failed", run, failures };
  const m = deps.buildManifest({ host, run, time: new Date(now).toISOString(), registry, sets: done, config, hoststore });
  g();
  const staging = deps.stagingDir(`manifest-${run}`);
  const c = await at(() => deps.commitManifest(m, staging, g));
  if (!c.ok) return { status: "failed", run, failures: [{ key: "manifest", code: c.code }] }; // the debt is already written
  for (const d of done) next.sets[setKey(d)] = { fingerprint: d.fingerprint ?? state.sets[setKey(d)]?.fingerprint ?? null, snapshot: d.snapshot, tree: d.tree, since: null };
  next.last_success = now;
  // Retention, then the weekly prune and the day's data check: each after the manifest, each reported on its own.
  const retention = await at(() => deps.retention({ now, host, activeRun: null, guard: g }));
  let prune = null, check = null;
  if (!retention.error && deps.pruneDue(state.last_prune, now)) {
    prune = await at(() => deps.binary({ op: "prune" }, { ms: 6 * 60 * 60 * 1000 }));
    if (prune.ok) next.last_prune = now;
  }
  const today = Math.floor(now / 86400000);
  if (state.last_check_day !== today) {
    const part = deps.checkDataPart(now);
    check = await at(() => deps.binary({ op: "check-data", part: part.part, of: part.of }, { ms: 6 * 60 * 60 * 1000 }));
    if (check.ok) next.last_check_day = today;
  }
  g();
  deps.state.write(next);
  await at(() => deps.trimCache());
  return { status: "ok", run, manifest: c.snapshot, retention, prune: prune && (prune.ok ? "ok" : prune.code), check: check && (check.ok ? check.value.findings : check.code) };
}

/**
 * Recover a journal an earlier run left behind, before a new run plans anything: the recovery order scoped to that
 * run (recoverBackup with expectedRun), then its warm snapshot forgotten, then its record cleared. A journal that
 * can't be read, a recovery that can't prove the thaw (the fence stays), or a forget that fails for any reason but
 * "already gone" refuses: no new run starts on top of an unknown one.
 * deps: { binary, dir, fenceDir, cg, now, sleep, lockWaitMs, guard } (`guard`: the run's held guard, before the forget and
 * the clear; the caller guards `binary` and `cg` too).
 */
export async function recoverLeftover({ binary, dir = BACKUP_DIR, fenceDir = FENCE_DIR, cg, now, sleep, lockWaitMs = 10000, ms = 30 * 60 * 1000, guard = () => {} } = {}) {
  let j;
  try { j = readJournal({ dir }); } catch { refuse("outcome_unknown", "backup: the run journal can't be read"); }
  if (j === null) return { ok: true, recovered: null };
  if (!(j.state === "released" && j.aborted)) {
    const opts = { expectedRun: j.run, dir, fenceDir, lockWaitMs, ...(cg ? { cg } : {}), ...(now ? { now } : {}), ...(sleep ? { sleep } : {}) };
    const r = await recoverBackup(j.agents[0], opts);
    if (r.state !== "released") refuse("outcome_unknown", "backup: a left-over run couldn't be recovered; its fence stays");
  }
  const cur = readJournal({ dir });
  if (cur?.run === j.run && cur.warm) {
    guard();
    const f = await binary({ op: "forget", snapshots: [cur.warm] }, { ms });
    guard();
    if (!f.ok && f.code !== "snapshot_missing") refuse("outcome_unknown", "backup: a left-over warm snapshot couldn't be forgotten");
  }
  await withJournalLock(() => { if (readJournal({ dir })?.run === j.run) { guard(); clearJournal({ dir }); } }, { dir, waitMs: lockWaitMs });
  return { ok: true, recovered: j.run };
}

/**
 * The cache's real effects, through an argv runner (`run(argv, { ms })` resolving to { code, stdout }):
 * - ensureCache(): the fixed-size image exists (created sparse, CACHE_BYTES, ext4) and is mounted at CACHE_DIR
 *   (nosuid, nodev, noexec); it refuses (preflight_missing) when it can't be;
 * - trimCache(): the least recently used cache files removed until the cache holds at most CACHE_TRIM_TO.
 */
export function cacheEffects({ run, fsx = fs, image = CACHE_IMAGE, mountpoint = CACHE_DIR, bytes = CACHE_BYTES, trimTo = CACHE_TRIM_TO }) {
  const must = async (argv, why) => { const r = await run(argv, { ms: 120000 }); if (r.code !== 0) refuse("preflight_missing", `backup cache: ${why}`); return r; };
  return {
    async ensureCache() {
      const mounted = await run(["/usr/bin/findmnt", "--noheadings", "--output", "SOURCE", "--mountpoint", mountpoint], { ms: 10000 });
      if (mounted.code === 0 && mounted.stdout.trim() !== "") return { mounted: true };
      if (!fsx.existsSync(image)) {
        await must(["/usr/bin/truncate", "--size", String(bytes), image], "can't create the image");
        fsx.chmodSync(image, 0o600);
        await must(["/usr/sbin/mkfs.ext4", "-q", "-F", "-m", "0", image], "can't format the image");
      }
      fsx.mkdirSync(mountpoint, { recursive: true, mode: 0o700 });
      await must(["/usr/bin/mount", "-o", "loop,nosuid,nodev,noexec", image, mountpoint], "can't mount the image");
      return { mounted: true };
    },
    async trimCache() {
      const files = [];
      const walk = (d) => {
        for (const e of fsx.readdirSync(d, { withFileTypes: true })) {
          const p = join(d, e.name);
          if (e.isDirectory()) { if (e.name !== "lost+found") walk(p); } else if (e.isFile()) { const st = fsx.statSync(p); files.push({ path: p, size: st.size, atime: st.atimeMs }); }
        }
      };
      walk(mountpoint);
      const gone = trimPlan(files, trimTo);
      for (const p of gone) fsx.unlinkSync(p);
      return { removed: gone.length };
    },
  };
}
