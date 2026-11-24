// Host supervisor (designs: host Claude profiles r2.1 §3–§6, as amended by the advisor delta r3.2 §1, §8, §9; launcher
// contract amendment A4 r2.3): profiles piece 2, the lifecycle of a host harness profile directory,
// /srv/sagebrush/claude-profiles/<pid>. The records are profiles.mjs's; this does the effects, each state committed
// BEFORE the effects it allows, under the profile's own lifecycle lock (.locks/<pid>; lock order: fence, profile, store).
//
// - create (r2.1 §4.1): the fixed parents checked by the launcher; the directory made root:root 0700 (INIT: nobody else
//   can write), its project quota limits (mandatory: no quotas, no profiles, §5) and project label with inherit set and
//   VERIFIED, then published to the storage uid (still 0700); then the session mountpoints (advisor §8: the launcher's
//   `profile-mounts --op create`) recorded; then `bound`. A crash anywhere is finished by recovery.
// - retire (r2.1 §4.2, A4 §2): `retiring` committed (gen + 1) first. Then, in this order and only in this order:
//   1. drain the profile's leases (advisor §9; injected: the turn layer's), 2. stop its login unit and prove it empty
//   (injected), 3. a FRESH whole-host uid-empty proof of the storage uid. A live uid, or a proof that can't be read,
//   makes ZERO launcher calls. Only then the launcher: `profile-mounts --op clear` (if any were recorded), `identify`,
//   the identity checked against the record, the removal's expect recorded durably, `remove-tree`; then `retired`.
//   A retry whose profile is already gone completes only on positive evidence (A4 §2 r2.3): in the same epoch, the
//   recorded expect's own `remove-tree` 0; after a verified reboot (another boot id) on the SAME filesystem, a fresh
//   absence, with no launcher removal call. Anything else PARKS (stays `retiring`, reported): a remount in one boot,
//   another filesystem, a replacement object, any 73.
// - recover (r2.1 §4.3): every record, by state, before any other operation; orphans (a directory with no record) are
//   reported, never adopted.
// - removeOrphan (A4 §2): an operator's command only: a READ-ONLY identify, the storage-range owner, the login stop and
//   the uid proof, an EXACT re-identify, then remove-tree with owners [storage uid] only (a root-owned entry, such as an
//   immutable mountpoint, refuses with zero unlinks).
// - profileForbiddenRoots(): what a backup must never read (the profile directories live under one root).

import fs from "node:fs";
import { dirname, join } from "node:path";
import { isId, refuse } from "../bytes.mjs";
import { SRV } from "./names.mjs";
import { STORAGE_UID_RANGE } from "./profiles.mjs";
import { lockFile } from "./store.mjs";

/** The profiles root (A4 §1) and its lock directory (r2.1 §6). Both root:root 0700. */
export const PROFILES_ROOT = `${SRV}/claude-profiles`;
export const PROFILE_LOCKS = `${PROFILES_ROOT}/.locks`;
export const profileDir = (pid) => { if (!isId(pid)) refuse("bad_form", "profile: bad id"); return `${PROFILES_ROOT}/${pid}`; };
/** Where the launcher's expect files for profiles are written (root 0700; one per call, rewritten). */
export const PROFILE_EXPECT_DIR = "/run/sagebrush/profiles";
/** The mandatory per-profile quota (r2.1 §5): 1 GiB of blocks, 100,000 inodes. */
export const PROFILE_QUOTA_KB = 1024 * 1024;
export const PROFILE_QUOTA_INODES = 100000;
/** The lifecycle lock is waited for at most this long. */
const LOCK_WAIT_MS = 5000;

/** The roots a backup must never read (r2.1 §8): every profile directory lives under PROFILES_ROOT. */
export function profileForbiddenRoots() {
  return Object.freeze([PROFILES_ROOT]);
}

const hostFail = (what) => Object.assign(new Error(`profile: ${what}`), { code: "effect_failed" });

/** Same epoch: the boot and the anchor's unique mount id both equal. */
const sameEpoch = (a, b) => a.boot_id === b.boot_id && a.mnt_id === b.mnt_id;
/** The durable identity of an object: everything but the live dev and mnt_id. */
const durable = (o) => o && { type: o.type, mode: o.mode, uid: o.uid, gid: o.gid, ino: o.ino, gen: o.gen, projid: o.projid, inherit: o.inherit };
const sameDurable = (a, b) => JSON.stringify(durable(a)) === JSON.stringify(durable(b));

/**
 * The lifecycle. Options:
 * - `profiles`: the host store's profiles (profiles.mjs);
 * - `run(argv, { ms, signal })` → { code, stdout }: the argv runner; `launcher`: the release's sagebrush-agent-launch;
 * - `quota`: { mount } or null (null refuses every creation: no quotas, no profiles);
 * - `continuity(harness)` → the registry's declared top-level session subpaths for the pinned version ([] for none);
 * - `drain(pid, ms, signal)`: block new admissions on the profile and drain its leases (the turn layer's);
 * - `loginStop(pid, ms, signal)`: the profile's login unit stopped and its cgroup proven empty (or proven absent);
 * - `uidProof(uid, ms, signal)` → { empty, holders } (uid-proof.mjs storageUidEmpty);
 * - `fsx`, `root` (a prefix for tests), `rootUid`, `lock` (store.mjs lockFile).
 * Every operation returns { status, reason? }: "bound" | "retired" | "removed" | "pending" (retry later) | "parked"
 * (an operator decides) | "refused".
 */
export function profileLifecycle({ profiles, run, launcher, quota = null, continuity, drain, loginStop, uidProof, fsx = fs, root = "", rootUid = 0, lock = lockFile } = {}) {
  for (const [k, f] of Object.entries({ run, continuity, drain, loginStop, uidProof })) if (typeof f !== "function") throw hostFail(`${k} is required`);
  if (!profiles || typeof launcher !== "string") throw hostFail("profiles and launcher are required");
  const at = (p) => `${root}${p}`;

  const alive = (left, signal) => {
    if (signal?.aborted || left() <= 0) throw Object.assign(new Error("profile: aborted or out of time"), { code: "effect_failed", aborted: true });
  };
  const guarded = async (left, signal, f) => {
    alive(left, signal);
    let v;
    try { v = await f(); } catch (e) { alive(left, signal); throw e; }
    alive(left, signal);
    return v;
  };
  const exec = (argv, left, signal) => guarded(left, signal, () => run(argv, { ms: left(), signal }));
  const launch = (args, left, signal) => exec([launcher, ...args], left, signal);
  const json = (r, what) => { try { return JSON.parse(r.stdout); } catch { throw hostFail(`${what} printed no JSON`); } };
  const must = async (argv, left, signal) => {
    const r = await exec(argv, left, signal);
    if (r.code !== 0) throw hostFail(`${argv[0]} exited ${r.code}`);
    return r;
  };

  /** An expect file: root 0600 in a root 0700 directory, written whole, synced, renamed, the directory synced. */
  const writeExpect = (name, value) => {
    try { fsx.mkdirSync(at(PROFILE_EXPECT_DIR), { recursive: true, mode: 0o700 }); } catch { throw hostFail("the expect directory can't be made"); }
    const st = fsx.lstatSync(at(PROFILE_EXPECT_DIR));
    if (!st.isDirectory() || st.uid !== rootUid || (st.mode & 0o077) !== 0) throw hostFail("the expect directory isn't root-only");
    const p = join(PROFILE_EXPECT_DIR, `${name}.json`);
    const tmp = `${p}.tmp`;
    fsx.rmSync(at(tmp), { force: true });
    const fd = fsx.openSync(at(tmp), "wx", 0o600);
    try { fsx.writeSync(fd, JSON.stringify(value)); fsx.fsyncSync(fd); } finally { fsx.closeSync(fd); }
    fsx.renameSync(at(tmp), at(p));
    const dfd = fsx.openSync(at(PROFILE_EXPECT_DIR), "r");
    try { fsx.fsyncSync(dfd); } finally { fsx.closeSync(dfd); }
    return p;
  };

  /** fsync a directory (its entries, or its own inode's owner and mode), by path. */
  const fsyncDir = (p) => {
    const fd = fsx.openSync(at(p), "r");
    try { fsx.fsyncSync(fd); } finally { fsx.closeSync(fd); }
  };

  /** A root:root 0700 directory, made if missing; an existing one must be exactly that. */
  const rootDir = (p) => {
    try { fsx.mkdirSync(at(p), { mode: 0o700 }); fsx.chownSync(at(p), rootUid, rootUid); fsx.chmodSync(at(p), 0o700); return; } catch (e) {
      if (e?.code !== "EEXIST") throw hostFail(`can't make ${p}`);
    }
    const st = fsx.lstatSync(at(p));
    if (!st.isDirectory() || st.uid !== rootUid || st.gid !== rootUid || (st.mode & 0o7777) !== 0o700) throw hostFail(`${p} isn't root:root 0700`);
  };

  /** The root and the lock directory must already be root:root 0700 (creation makes them, after check-parents). */
  const rootOnly = (p) => {
    let st;
    try { st = fsx.lstatSync(at(p)); } catch { throw hostFail(`${p} is missing`); }
    if (!st.isDirectory() || st.uid !== rootUid || st.gid !== rootUid || (st.mode & 0o7777) !== 0o700) throw hostFail(`${p} isn't root:root 0700`);
  };
  /** The profile's lifecycle lock, around `f`. */
  const locked = async (pid, f) => {
    rootOnly(PROFILES_ROOT);
    rootOnly(PROFILE_LOCKS);
    const path = at(join(PROFILE_LOCKS, pid));
    fsx.closeSync(fsx.openSync(path, "a", 0o600));
    const held = await lock(path, { waitMs: LOCK_WAIT_MS });
    try { return await f(); } finally { await held.release(); }
  };

  const projectState = async (p, left, signal) => {
    const r = await exec(["lsattr", "-p", "-d", at(p)], left, signal);
    const m = r.code === 0 ? /^\s*(\d+)\s+(\S+)\s/.exec(r.stdout) : null;
    if (!m) throw hostFail(`lsattr can't read ${p}`);
    return { id: Number(m[1]), inherit: m[2].includes("P") };
  };
  /** The quota limits through the quota interface itself (TESTS: not only the label): `quota -P` must report them. */
  const quotaLimits = async (projectId, left, signal) => {
    const r = await exec(["quota", "-P", "-w", "-p", "--no-wrap", String(projectId)], left, signal);
    const line = r.code === 0 ? r.stdout.split("\n").find((l) => /^\s*\//.test(l)) : null;
    const f = line ? line.trim().split(/\s+/) : [];
    // With -p the grace columns are numeric: device, blocks, soft, hard, grace, files, soft, hard, grace.
    const nums = f.slice(1).map((x) => x.replace("*", ""));
    if (nums.length !== 8 || !nums.every((x) => /^\d+$/.test(x))) throw hostFail("quota -P can't be read");
    return { blocksHard: Number(nums[2]), inodesHard: Number(nums[6]) };
  };

  // ---- create (r2.1 §4.1, advisor §8, A4 §3)

  /** The entries of a directory other than the given names. */
  const others = (p, names) => fsx.readdirSync(at(p)).filter((n) => !names.includes(n));

  /** Continue a `creating` profile to `bound`. Every step reads before it writes; a crash is finished from where it stopped. */
  const finishCreate = async (pid, left, signal) => {
    const r = profiles.profile(pid);
    if (!r || r.state !== "creating") return { status: "refused", reason: "not creating" };
    if (quota === null) return { status: "refused", reason: "no quotas on this host: profiles are refused (r2.1 §5)" };
    const subs = continuity(r.harness);
    const p = profileDir(pid);
    await checkParents(false, left, signal); // strictly, before any effect beneath the root
    let st = null;
    try { st = fsx.lstatSync(at(p)); } catch (e) { if (e?.code !== "ENOENT") throw hostFail("the profile directory can't be read"); }
    if (st === null) {
      fsx.mkdirSync(at(p), { mode: 0o700 });
      fsx.chownSync(at(p), rootUid, rootUid);
      fsx.chmodSync(at(p), 0o700);
      st = fsx.lstatSync(at(p));
    }
    fsyncDir(PROFILES_ROOT); // the entry is durable before anything is set on it (also on a retry after a crash)
    const mode = st.mode & 0o7777;
    const init = st.isDirectory() && st.uid === rootUid && st.gid === rootUid && mode === 0o700;
    const owned = st.isDirectory() && st.uid === r.storage_uid && st.gid === r.storage_uid && mode === 0o700;
    // Only the declared mountpoints may be inside (a crash after profile-mounts and before they were recorded).
    if (!(init || owned) || others(p, subs).length) return { status: "parked", reason: "the directory differs from what creation makes (corrupt: retire it)" };
    if (owned) {
      const ps = await projectState(p, left, signal);
      if (!(ps.id === r.project_id && ps.inherit)) return { status: "parked", reason: "an owned directory without its label" };
    }
    // The limits are set every time (idempotent); the label only from INIT (an OWNED directory is already labelled).
    await must(["setquota", "-P", String(r.project_id), "0", String(PROFILE_QUOTA_KB), "0", String(PROFILE_QUOTA_INODES), quota.mount], left, signal);
    if (!owned) await must(["chattr", "+P", "-p", String(r.project_id), at(p)], left, signal);
    const ps = await projectState(p, left, signal);
    if (!(ps.id === r.project_id && ps.inherit)) throw hostFail("the project label didn't take");
    const q = await quotaLimits(r.project_id, left, signal);
    if (q.blocksHard !== PROFILE_QUOTA_KB || q.inodesHard !== PROFILE_QUOTA_INODES) throw hostFail("the quota limits didn't take");
    // Publish: the storage uid's, still 0700; then verify on disk.
    alive(left, signal);
    fsx.chownSync(at(p), r.storage_uid, r.storage_uid);
    fsx.chmodSync(at(p), 0o700);
    const pub = fsx.lstatSync(at(p));
    if (!pub.isDirectory() || pub.uid !== r.storage_uid || pub.gid !== r.storage_uid || (pub.mode & 0o7777) !== 0o700) throw hostFail("the profile directory didn't publish");
    fsyncDir(p); // its owner and mode durable before `bound`
    fsyncDir(PROFILES_ROOT);
    // The session mountpoints (advisor §8), made by the launcher and recorded before `bound`.
    let rows = [];
    if (subs.length) {
      const id = await launch(["identify", "--anchor", PROFILES_ROOT, "--name", pid], left, signal);
      if (id.code !== 0) throw hostFail(`identify exited ${id.code}`);
      const dirExpect = writeExpect(`${pid}-dir`, json(id, "identify"));
      const m = await launch(["profile-mounts", "--name", pid, "--op", "create", ...subs.flatMap((s) => ["--subpath", s]), "--expect-dir", dirExpect], left, signal);
      if (m.code !== 0) throw hostFail(`profile-mounts create exited ${m.code}`);
      rows = json(m, "profile-mounts");
      if (!Array.isArray(rows) || rows.length !== subs.length || rows.some((x, i) => x?.name !== subs[i])) throw hostFail("profile-mounts reported other mountpoints");
    }
    alive(left, signal);
    profiles.setMountpoints(pid, rows);
    profiles.markBound(pid);
    return { status: "bound" };
  };

  const checkParents = async (allowMissing, left, signal) => {
    if (quota === null) throw hostFail("no quota mount");
    const c = await launch(["check-parents", "--mount", quota.mount, ...(allowMissing ? ["--allow-missing"] : [])], left, signal);
    if (c.code !== 0) throw hostFail(`the fixed parents failed their check (${c.code})`);
  };
  /** The profiles root and its lock directory: checked by the launcher, made if missing, checked again strictly. */
  const ensureRoots = async (left, signal) => {
    await checkParents(true, left, signal);
    rootDir(PROFILES_ROOT);
    rootDir(PROFILE_LOCKS);
    // Every time, also on a retry after a crash before the sync: each directory's owner and mode, and its entry in
    // its parent (the profiles root's in /srv/sagebrush), durable before anything is made beneath them.
    for (const d of [PROFILES_ROOT, PROFILE_LOCKS]) { fsyncDir(d); fsyncDir(dirname(d)); }
    await checkParents(false, left, signal);
  };

  /** Create profile `pid` of `kind` for subscription `sub`: `creating` committed first, then finished. */
  const create = async (pid, kind, sub, ms, signal) => {
    const t0 = Date.now(), left = () => ms - (Date.now() - t0);
    if (quota === null) return { status: "refused", reason: "no quotas on this host: profiles are refused (r2.1 §5)" };
    await ensureRoots(left, signal);
    return locked(pid, async () => {
      profiles.beginCreate(pid, kind, sub);
      return finishCreate(pid, left, signal);
    });
  };

  // ---- removal (A4 §2)

  /** Steps 1-3 of A4 §2, in order. Null when they hold; else the reason (nothing of the launcher may run). */
  const preconditions = async (pid, uid, { leases }, left, signal) => {
    if (leases) {
      try { await guarded(left, signal, () => drain(pid, left(), signal)); } catch (e) { if (e?.aborted) throw e; return "the profile's leases couldn't be drained"; }
    }
    try { await guarded(left, signal, () => loginStop(pid, left(), signal)); } catch (e) { if (e?.aborted) throw e; return "the login unit couldn't be stopped and proven"; }
    let u;
    try { u = await guarded(left, signal, () => uidProof(uid, left(), signal)); } catch (e) { if (e?.aborted) throw e; return "the storage uid can't be proven empty"; }
    return u.empty ? null : `the storage uid is held: ${u.holders.join(", ")}`;
  };

  /**
   * Remove a recorded profile's directory (retiring, or a retired crash leftover): A4 §2 step 4 and the retry rules.
   * Returns { status: "removed" | "pending" | "parked", reason }.
   */
  const removeRecorded = async (pid, left, signal) => {
    const r = profiles.profile(pid);
    const id = await launch(["identify", "--anchor", PROFILES_ROOT, "--name", pid], left, signal);
    if (id.code !== 0) return { status: "parked", reason: `identify exited ${id.code}` };
    const now = json(id, "identify");
    const owners = [rootUid, r.storage_uid];
    const removeTree = async (expect) => {
      const file = writeExpect(`${pid}-rm`, expect);
      const rm = await launch(["remove-tree", "--anchor", PROFILES_ROOT, "--name", pid, "--expect", file], left, signal);
      if (rm.code === 0) return { status: "removed" };
      if (rm.code === 75) return { status: "pending", reason: "partly removed; the next attempt retries" };
      return { status: "parked", reason: `remove-tree refused (${rm.code})` }; // a 73 is never completion
    };
    if (r.removal !== null && now.object === null) {
      if (sameEpoch(now.epoch, r.removal.epoch) && now.fsid === r.removal.fsid) return removeTree(r.removal);
      if (now.epoch.boot_id !== r.removal.epoch.boot_id && now.fsid === r.removal.fsid) return { status: "removed" }; // a verified reboot: durably gone
      return { status: "parked", reason: "absent in another mount or filesystem than the recorded removal's (requalify)" };
    }
    if (now.object === null) return { status: "removed" }; // never made (an abandoned creation before its mkdir)
    if (r.removal !== null && !(now.fsid === r.removal.fsid && sameDurable(now.object, r.removal.root))) {
      return { status: "parked", reason: "another object than the recorded removal's" };
    }
    // The object must be what this profile's creation makes: a 0700 directory, root's (INIT) or the storage uid's,
    // unlabelled (INIT) or with this profile's project and inherit.
    const o = now.object;
    const okOwner = (o.uid === rootUid && o.gid === rootUid) || (o.uid === r.storage_uid && o.gid === r.storage_uid);
    const okLabel = (o.projid === r.project_id && o.inherit === true) || (o.projid === 0 && o.inherit === false);
    if (o.type !== "dir" || o.mode !== 0o700 || !okOwner || !okLabel) return { status: "parked", reason: "the directory isn't this profile's" };
    if (r.mountpoints?.length) {
      const file = writeExpect(`${pid}-clear`, { dir: now, mountpoints: r.mountpoints });
      const c = await launch(["profile-mounts", "--name", pid, "--op", "clear", "--expect", file], left, signal);
      if (c.code === 75) return { status: "pending", reason: "the mountpoints are partly cleared; the next attempt retries" };
      if (c.code !== 0) return { status: "parked", reason: `profile-mounts clear refused (${c.code})` };
    }
    const removal = { epoch: now.epoch, fsid: now.fsid, root: now.object, owners };
    alive(left, signal);
    profiles.setRemoval(pid, removal); // durably, BEFORE the first remove-tree
    return removeTree(removal);
  };

  /** Retire `pid` (logout is the caller's, through the login unit, before this; r2.1 §4.2 step 3). */
  const retire = (pid, ms, signal) => {
    const t0 = Date.now(), left = () => ms - (Date.now() - t0);
    return locked(pid, async () => {
      let r = profiles.profile(pid);
      if (!r) return { status: "refused", reason: "unknown profile" };
      if (r.state === "bound" || r.state === "creating") r = profiles.beginRetire(pid);
      if (r.state === "retired") return { status: "retired" };
      const why = await preconditions(pid, r.storage_uid, { leases: true }, left, signal);
      if (why) return { status: "pending", reason: why };
      const out = await removeRecorded(pid, left, signal);
      if (out.status !== "removed") return out;
      alive(left, signal);
      profiles.markRetired(pid);
      return { status: "retired" };
    });
  };

  /** A retired record whose directory remains (a crash after removal began): removed the same way; never recreated. */
  const removeLeftover = async (pid, left, signal) => {
    const r = profiles.profile(pid);
    const why = await preconditions(pid, r.storage_uid, { leases: false }, left, signal);
    if (why) return { status: "pending", reason: why };
    return removeRecorded(pid, left, signal);
  };

  // ---- recovery (r2.1 §4.3)

  /**
   * Null when a bound profile is in the exact final state creation leaves (r2.1 §4.3, advisor §8); else what differs.
   * The directory through the launcher's read-only identify: the storage uid's 0700 directory on the anchor's mount,
   * with this profile's project and inherit; its project's limits through `quota -P`. Each recorded mountpoint: a
   * root:root 0555 directory with its recorded inode, immutable. A piece-1 record (mountpoints null) is never startable (pool.mjs) and is reported here.
   */
  const boundDiffers = async (pid, left, signal) => {
    const r = profiles.profile(pid);
    if (r.mountpoints === null) return "from before recorded mountpoints (never selectable: retire and create it again)";
    let now;
    try {
      const id = await launch(["identify", "--anchor", PROFILES_ROOT, "--name", pid], left, signal);
      if (id.code !== 0) return `that can't be identified (${id.code})`;
      now = json(id, "identify");
    } catch (e) { if (e?.aborted) throw e; return "that can't be identified"; }
    const o = now.object;
    if (o === null) return "whose directory is missing";
    if (o.type !== "dir" || o.mode !== 0o700 || o.uid !== r.storage_uid || o.gid !== r.storage_uid) return "whose directory's owner or mode differs";
    if (o.projid !== r.project_id || o.inherit !== true) return "whose project label differs";
    if (o.mnt_id !== now.epoch.mnt_id) return "whose directory isn't on the anchor's mount";
    // Its limits, through the quota interface (r2.1 §5: missing or differing limits are never startable).
    if (quota === null) return "on a host without quotas";
    let q = null;
    try { q = await quotaLimits(r.project_id, left, signal); } catch (e) { if (e?.aborted) throw e; }
    if (q === null || q.blocksHard !== PROFILE_QUOTA_KB || q.inodesHard !== PROFILE_QUOTA_INODES) return "whose quota limits are missing or differ";
    for (const m of r.mountpoints) {
      const mp = join(profileDir(pid), m.name);
      let st;
      try { st = fsx.lstatSync(at(mp)); } catch { return `whose mountpoint ${m.name} is missing`; }
      if (!st.isDirectory() || st.uid !== 0 || st.gid !== 0 || (st.mode & 0o7777) !== 0o555 || st.ino !== m.ino) return `whose mountpoint ${m.name} differs`;
      let fl = null;
      try { fl = await exec(["lsattr", "-d", at(mp)], left, signal); } catch (e) { if (e?.aborted) throw e; }
      const f = fl?.code === 0 ? /^\s*(\S+)\s/.exec(fl.stdout) : null;
      if (!f || !f[1].includes("i")) return `whose mountpoint ${m.name} isn't immutable`;
    }
    return null;
  };

  /** Every record, by state; then the orphans, reported. Returns { profiles: { pid: result }, orphans: [pid] }. */
  const recover = async (ms, signal) => {
    const t0 = Date.now(), left = () => ms - (Date.now() - t0);
    const out = {};
    for (const { pid, state } of profiles.all()) {
      if (state === "creating") out[pid] = await locked(pid, () => finishCreate(pid, left, signal));
      else if (state === "retiring") out[pid] = await retire(pid, left(), signal);
      else if (state === "retired") {
        let present;
        try { fsx.lstatSync(at(profileDir(pid))); present = true; } catch (e) { if (e?.code !== "ENOENT") throw hostFail("a profile directory can't be read"); present = false; }
        if (present) out[pid] = await locked(pid, () => removeLeftover(pid, left, signal));
      } else if (state === "bound") {
        const why = await boundDiffers(pid, left, signal);
        if (why) out[pid] = { status: "parked", reason: `a bound profile ${why} (corrupt: retire it)` };
      }
    }
    let names = [];
    try { names = fsx.readdirSync(at(PROFILES_ROOT)); } catch (e) { if (e?.code !== "ENOENT") throw hostFail("the profiles root can't be listed"); }
    const orphans = names.filter((n) => n !== ".locks" && !(isId(n) && profiles.profile(n)));
    return { profiles: out, orphans };
  };

  // ---- the operator's orphan removal (A4 §2)

  const removeOrphan = (pid, ms, signal) => {
    const t0 = Date.now(), left = () => ms - (Date.now() - t0);
    if (!isId(pid)) refuse("bad_form", "profile: bad id");
    return locked(pid, async () => {
      if (profiles.profile(pid)) return { status: "refused", reason: "a recorded profile is never an orphan" };
      const ident = async () => {
        const r = await launch(["identify", "--anchor", PROFILES_ROOT, "--name", pid], left, signal);
        if (r.code !== 0) throw hostFail(`identify exited ${r.code}`);
        return json(r, "identify");
      };
      const first = await ident(); // read-only: it only opens and statx'es
      const o = first.object;
      if (o === null) {
        // Absent: perhaps an earlier call's remove-tree unlinked it and then failed its anchor fsync (75). The launcher
        // decides, with an expect that can match no object: in this epoch and on this filesystem, an absent target is
        // "already gone" only after the anchor is synced again (A1 r2.4 §5); anything at the name refuses (73).
        const never = { type: "dir", mode: 0o700, uid: STORAGE_UID_RANGE[0], gid: STORAGE_UID_RANGE[0], dev: [0, 0], ino: 0, gen: 0, mnt_id: first.epoch.mnt_id, projid: 0, inherit: false };
        const file = writeExpect(`${pid}-orphan`, { epoch: first.epoch, fsid: first.fsid, root: never, owners: [STORAGE_UID_RANGE[0]] });
        const rm = await launch(["remove-tree", "--anchor", PROFILES_ROOT, "--name", pid, "--expect", file], left, signal);
        if (rm.code === 0) return { status: "removed" };
        if (rm.code === 75) return { status: "pending", reason: "the anchor isn't synced yet; run it again" };
        return { status: "refused", reason: `remove-tree refused (${rm.code})` };
      }
      if (o.type !== "dir" || o.mode !== 0o700 || !(o.uid >= STORAGE_UID_RANGE[0] && o.uid <= STORAGE_UID_RANGE[1])) {
        return { status: "refused", reason: "not a storage uid's 0700 profile directory" };
      }
      const why = await preconditions(pid, o.uid, { leases: false }, left, signal);
      if (why) return { status: "refused", reason: why };
      const again = await ident();
      if (JSON.stringify(again) !== JSON.stringify(first)) return { status: "refused", reason: "the orphan changed across the proof" };
      const file = writeExpect(`${pid}-orphan`, { epoch: first.epoch, fsid: first.fsid, root: first.object, owners: [o.uid] });
      const rm = await launch(["remove-tree", "--anchor", PROFILES_ROOT, "--name", pid, "--expect", file], left, signal);
      if (rm.code === 0) return { status: "removed" };
      if (rm.code === 75) return { status: "pending", reason: "partly removed; run it again" };
      return { status: "refused", reason: `remove-tree refused (${rm.code}): a root-owned entry or a changed tree; operator recovery` };
    });
  };

  return { create, finishCreate, retire, recover, removeOrphan };
}
