// Host backup (design: agent-autonomous-host-backup.md r3.3 §6): the scheduler. One run at a time per host, daily at
// 03:00 host-local (a systemd timer) and on demand, change-aware.
//
// **Off unless set up.** A run does anything only when the host has a destination (backup/dest.json) AND the
// host-local enabled flag (backup/enabled) that `host backup init` writes. Both must be regular root-owned 0600 files
// (never a link) in the root-only 0700 backup directory. Otherwise the run is a no-op that reports "not set up".
// Nothing here installs the timer: that is `host backup init`'s.
//
// One run (runOnce), under the run lock:
//   1. the root filesystem keeps its 5 GiB reserve, and the cache image is mounted (a fixed-size loop image, so the
//      cache's cap holds during the run by construction);
//   2. a journal left by an earlier run is recovered first (the recovery order, then its warm snapshot forgotten);
//   3. the registry copy is taken, its source sets built, forbidden roots refused, and each set walked;
//   4. each set that changed since its last good snapshot gets the consistent pass (backup-run.mjs); an unchanged
//      one keeps its last good snapshot in the new manifest;
//   5. the host store is copied under its lock and backed up;
//   6. only if every part is good: the manifest is committed and read back (backup-manifest.mjs);
//   7. then retention (backup-retention.mjs), the weekly prune, and the day's rotating data check.
// The turn-lease interface (an agent's active turns) is injected. Until the real one lands, the host passes
// failClosedLease: every read fails, so every pass treats its agents as busy and is consistency=crash.

import { randomBytes } from "node:crypto";
import * as fs from "node:fs";
import { join } from "node:path";
import { refuse } from "../bytes.mjs";
import { clearJournal, readJournal, recoverBackup, withJournalLock } from "./backup-journal.mjs";
import { BACKUP_DIR, FENCE_DIR } from "./names.mjs";
import { writeDurable, lockDir } from "./store.mjs";

export const ROOT_RESERVE = 5 * 1024 ** 3;
export const CACHE_BYTES = 4 * 1024 ** 3;
export const CACHE_TRIM_TO = 3 * 1024 ** 3;
export const CACHE_DIR = "/var/cache/sagebrush-backup";
export const CACHE_IMAGE = "/var/lib/sagebrush/backup-cache.img";
export const STATE_FILE = "state.json";
export const ENABLED_FILE = "enabled";
export const DEST_FILE = "dest.json";

/** The turn-lease interface for a host without the real one yet: every read fails, so no agent is ever idle. */
export const failClosedLease = Object.freeze({ activeTurns: async () => { throw Object.assign(new Error("no turn-lease provider"), { code: "ENOSYS" }); } });

/**
 * Is backup set up on this host? { enabled: true } or { enabled: false, why }. The backup directory must be a real
 * directory owned by root (rootUid) with mode 0700, and both dest.json and the enabled flag regular files (never
 * links) owned by root with mode 0600.
 */
export function backupEnabled({ dir = BACKUP_DIR, fsx = fs, rootUid = 0 } = {}) {
  const st = (p) => { try { return fsx.lstatSync(p); } catch (e) { if (e?.code === "ENOENT") return null; throw e; } };
  const d = st(dir);
  if (!d) return { enabled: false, why: "not set up" };
  if (!d.isDirectory() || d.uid !== rootUid || (d.mode & 0o777) !== 0o700) return { enabled: false, why: "the backup directory isn't root's 0700 directory" };
  for (const name of [DEST_FILE, ENABLED_FILE]) {
    const f = st(join(dir, name));
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

/** Run `fn` under the run lock (one backup run per host at a time). Refuses in_progress when another holds it. */
export async function withRunLock(fn, { dir = join(BACKUP_DIR, "run") } = {}) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const lock = await lockDir(dir, { waitMs: 0 });
  try { return await fn(); } finally { await lock.release(); }
}

/** The systemd units: the daily timer (03:00 host-local, catching up a missed run) and the oneshot service it starts. */
export function backupUnits(release) {
  if (typeof release !== "string" || !/^\/[A-Za-z0-9._/-]+$/.test(release) || release.split("/").includes("..")) refuse("bad_form", "backup units: bad release path");
  const service = [
    "[Unit]", "Description=Sagebrush host backup", "After=network-online.target", "Wants=network-online.target", "",
    "[Service]", "Type=oneshot", `ExecStart=${release}/bin/sagebrush-agent host backup run`, "Nice=10", "IOSchedulingClass=idle",
    "Slice=sagebrush-backup.slice", "",
  ].join("\n");
  const timer = [
    "[Unit]", "Description=Sagebrush host backup, daily", "",
    "[Timer]", "OnCalendar=*-*-* 03:00:00", "Persistent=true", "RandomizedDelaySec=0", "", "[Install]", "WantedBy=timers.target", "",
  ].join("\n");
  return { service, timer, names: { service: "sagebrush-backup.service", timer: "sagebrush-backup.timer" } };
}

/**
 * One scheduled or on-demand run. Every effect is in `deps` (the host passes the real ones; tests pass fakes):
 * - enabled(): backupEnabled's result; withRunLock(fn); freeBytes(path); ensureCache(); trimCache();
 * - recoverLeftover(): recover a journal left by an earlier run (the recovery order, its warm snapshot forgotten,
 *   the record cleared); resolves to { ok } or refuses when the journal can't be read;
 * - registry(): the registry copy (registry.mjs's closed shape); configHash(agent): the agent's config generation
 *   hash; forbidden(): the roots no source may touch (FIXED_FORBIDDEN plus the harnesses' profile roots);
 * - sources(registry), checkForbidden(paths, roots), walk(set), unchanged(a, b): backup-sources.mjs's;
 * - backupSet(set, run, { parent }): backup-run.mjs's, with its own deps bound;
 * - copyHostStore(staging): the host store copied under its lock into `staging`, resolving to the staging path;
 * - binary(req, { ms }): the backup binary; commitManifest(m, staging), buildManifest(args): backup-manifest.mjs's;
 * - retention({ now, activeRun }): backup-retention.mjs's pass; pruneDue(last, now), checkDataPart(now);
 * - state: { read(), write(s) }; host; now(); stagingDir(name).
 * Resolves to { status: "not set up" | "skipped" | "failed" | "ok", ... }; it never leaves the state file behind
 * the store: the state is written only after the manifest is committed (or, on a failure, only the debt).
 */
export async function runOnce(deps) {
  const enabled = deps.enabled();
  if (!enabled.enabled) return { status: "not set up", why: enabled.why };
  return deps.withRunLock(async () => {
    const now = deps.now();
    if (deps.freeBytes("/") < ROOT_RESERVE) return { status: "skipped", why: "root_reserve" };
    await deps.ensureCache();
    await deps.recoverLeftover();
    const run = newRunId(now);
    const registry = deps.registry();
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
    const next = { ...state, sets: { ...state.sets } };
    const done = [], failures = [];
    for (const p of plan) {
      const key = setKey(p.set);
      if (!p.back_up) { done.push({ ...p.set, snapshot: p.keep.snapshot, tree: p.keep.tree, unrestorable: unrestorable.get(key) }); continue; }
      const r = await deps.backupSet(p.set, run, { parent: p.parent });
      if (r.outcome !== "good") {
        failures.push({ key, code: r.code });
        next.sets[key] = { fingerprint: state.sets[key]?.fingerprint ?? null, snapshot: state.sets[key]?.snapshot ?? null, tree: state.sets[key]?.tree ?? null, since: state.sets[key]?.since ?? now };
        continue;
      }
      done.push({ ...p.set, snapshot: r.snapshot, tree: null, unrestorable: unrestorable.get(key), fingerprint: p.fingerprint });
    }
    // The host store, copied under its lock, then backed up like a set that is never live.
    let hoststore = null;
    if (failures.length === 0) {
      const staging = await deps.copyHostStore(deps.stagingDir(`hoststore-${run}`));
      const r = await deps.backupSet({ kind: "hoststore", id: null, sources: [staging], uids: [], members: [] }, run, { parent: null });
      if (r.outcome !== "good") failures.push({ key: "hoststore", code: r.code }); else hoststore = r.snapshot;
    }
    if (failures.length) { deps.state.write(next); return { status: "failed", run, failures }; }
    // Trees of the snapshots made in this run, from the store's own listing.
    const list = await deps.binary({ op: "snapshots" }, { ms: 30 * 60 * 1000 });
    if (!list.ok) return { status: "failed", run, failures: [{ key: "listing", code: list.code }] };
    const treeOf = new Map(list.value.snapshots.map((s) => [s.id, s.tree]));
    for (const d of done) if (d.tree === null) d.tree = treeOf.get(d.snapshot) ?? null;
    if (done.some((d) => d.tree === null)) return { status: "failed", run, failures: [{ key: "listing", code: "snapshot_missing" }] };
    const config = Object.fromEntries(Object.entries(registry.agents).filter(([, a]) => a.state !== "deleted").map(([id]) => [id, deps.configHash(id)]));
    const m = deps.buildManifest({ host: deps.host, run, time: new Date(now).toISOString(), registry, sets: done, config, hoststore });
    const c = await deps.commitManifest(m, deps.stagingDir(`manifest-${run}`));
    if (!c.ok) { deps.state.write(next); return { status: "failed", run, failures: [{ key: "manifest", code: c.code }] }; }
    for (const d of done) next.sets[setKey(d)] = { fingerprint: d.fingerprint ?? state.sets[setKey(d)]?.fingerprint ?? null, snapshot: d.snapshot, tree: d.tree, since: null };
    next.last_success = now;
    // Retention, then the weekly prune and the day's data check: each after the manifest, each reported on its own.
    const retention = await deps.retention({ now, activeRun: null });
    let prune = null, check = null;
    if (!retention.error && deps.pruneDue(state.last_prune, now)) {
      prune = await deps.binary({ op: "prune" }, { ms: 6 * 60 * 60 * 1000 });
      if (prune.ok) next.last_prune = now;
    }
    const today = Math.floor(now / 86400000);
    if (state.last_check_day !== today) {
      const part = deps.checkDataPart(now);
      check = await deps.binary({ op: "check-data", part: part.part, of: part.of }, { ms: 6 * 60 * 60 * 1000 });
      if (check.ok) next.last_check_day = today;
    }
    deps.state.write(next);
    await deps.trimCache();
    return { status: "ok", run, manifest: c.snapshot, retention, prune: prune && (prune.ok ? "ok" : prune.code), check: check && (check.ok ? check.value.findings : check.code) };
  });
}

/**
 * Recover a journal an earlier run left behind, before a new run plans anything: the recovery order scoped to that
 * run (recoverBackup with expectedRun), then its warm snapshot forgotten, then its record cleared. A journal that
 * can't be read, a recovery that can't prove the thaw (the fence stays), or a forget that fails for any reason but
 * "already gone" refuses: no new run starts on top of an unknown one.
 * deps: { binary, dir, fenceDir, cg, now, sleep, lockWaitMs }.
 */
export async function recoverLeftover({ binary, dir = BACKUP_DIR, fenceDir = FENCE_DIR, cg, now, sleep, lockWaitMs = 10000, ms = 30 * 60 * 1000 } = {}) {
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
    const f = await binary({ op: "forget", snapshots: [cur.warm] }, { ms });
    if (!f.ok && f.code !== "snapshot_missing") refuse("outcome_unknown", "backup: a left-over warm snapshot couldn't be forgotten");
  }
  await withJournalLock(() => { if (readJournal({ dir })?.run === j.run) clearJournal({ dir }); }, { dir, waitMs: lockWaitMs });
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
