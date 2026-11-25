// Host backup (design: agent-autonomous-host-backup.md r3.3 §5 steps 6-9; launcher amendments A1 r2.6, A2 r3.10): the
// real adapters restore-fill's driver is given, each a thin call into the launcher or the host's existing helpers.
// Dormant: nothing calls it yet.
//
// Where each set's destination comes from (a restore is a fresh provisioning, then a data fill):
// - a LIVE agent's home and sessions, and its tag folders, are provisioned by the executor's normal `provision` step
//   on this host's first grant that lists the agent (it keeps the restored uid; the `restore` fence keeps it from
//   starting). Until provisioned.json records the agent and both trees are empty, its set is not started: `ready`
//   says "waiting for this host's grant";
// - a DELETED agent's archive (and its config archive, L1) is provisioned here, by provision.mjs's own labelled()
//   step: a fresh root:root 0755 archive/<id> and root:root 0700 archive-config/<id>, both in the uid's project with
//   the inherit flag, under a hard limit of exactly the restore's need (restore-space.mjs's upper bounds, in the
//   quota's units: 4 KiB blocks and inodes, staging and the fill's peak included, plus the config archive's own
//   directory). An archive never grows, so nothing more.
// The destination's identity always comes from the launcher (inspect-home for an agent's trees, compared with the
// provisioned record; identify for an archive, and for a tag folder on the read-only tags anchor, A1 r2.7), never
// from a path here.
//
// A dirty destination (a fill that failed after its first move) is emptied by the launcher's `remove-tree --contents`
// (A1 r2.6 §5a), which keeps the destination and its identity, the one the restore record pinned. Before EVERY such
// call, the set's fences and a whole-host uid-empty proof for every non-root owner are taken afresh; without them
// there is no launcher call, and the set stays dirty and fenced.
//
// The SQLite copies of validation live under VALIDATE_DIR (A2 r3.7), which is made here: root 0700, checked by
// identity, never a link. tree-digest runs in a transient systemd scope, sagebrush-validate-<owner>.scope, with
// MemoryMax and RuntimeMaxSec (A2 r3.7 S3), so the kernel bounds it whatever the restored tree holds.

import * as fs from "node:fs";
import { join } from "node:path";
import { isId, refuse } from "../bytes.mjs";
import { checkIdentified, checkInspected, sameDurable } from "./deprovision-record.mjs";
import { agentHome, agentSessions, fenceFiles, RESTORE_DIR, RESTORE_STAGING, SRV, VALIDATE_DIR } from "./names.mjs";
import { fillExpect, ownersOf, writeExpectFile } from "./restore-fill.mjs";
import { CLASSES, ownerOf, RESTORE_RUN } from "./restore-record.mjs";
import { destOf } from "./restore-fill.mjs";
import { BLOCK, needOf } from "./restore-space.mjs";

/** Where restore's expect files go: root 0700, beside the records. */
export const EXPECT_DIR = `${RESTORE_DIR}/expect`;
/** The launcher's archive anchor (A1 §1) and the staging anchor (A2 §1). */
const ARCHIVE_ANCHOR = `${SRV}/archive`;
/** The tags anchor: read-only, for identify only (A1 r2.7). */
const TAGS_ANCHOR = `${SRV}/tags`;
/** The validation scope's unit: one per owner, so two sets never share one (A2 r3.7 S3). */
const SCOPE_UNIT = /^sagebrush-validate-[at]-[a-z2-7]{25}[aeimquy4]\.scope$/;

const hostFail = (what) => Object.assign(new Error(`restore: ${what}`), { code: "effect_failed" });

/**
 * The provisioned objects in a restored archive's project besides the restore's own need: the archive root itself
 * (the fill's destination: its inode, and a block of its own, though the peak's doubled directories already bound it)
 * and the config archive's root (an inode and a block). Both exist from provisioning on.
 */
export const ARCHIVE_ROOTS = Object.freeze({ inodes: 2, blocks: 2 });

/**
 * The hard limit of a restored archive, in the quota's units: the class's need (needOf's project bounds: blocks and
 * inodes at the larger of staging and the fill's peak, the launcher's objects and the digest list included) plus
 * ARCHIVE_ROOTS. Returns { kib, inodes } for setquota.
 */
export function archiveLimits(usage) {
  const n = needOf([usage]).project;
  return { kib: (n.blocks + ARCHIVE_ROOTS.blocks) * (BLOCK / 1024), inodes: n.inodesMax + ARCHIVE_ROOTS.inodes };
}

/**
 * The adapters. Options:
 * - `run(argv, { ms, signal })`: the argv runner; `launcher`: sagebrush-agent-launch's path; `mount`: the quota mount;
 * - `store`: the host store (its provisioned records); `registry()`: the restored registry (registry.mjs's shape);
 * - `provisioner`: provision.mjs's, for the archive (its `archive`);
 * - `usageOf(kind, id, cls)`: the class's measured usage (restore-space's input);
 * - `unrestorable(kind, id, cls)`: the manifest's unrestorable paths of the class (A2 §4b's codec);
 * - `procCount(agent, ms, signal)`: the agent's slice's process count; `uidProof(uid, agent, ms, signal)`: { empty };
 * - `report(event)`: what the person is told (a staging that can't be discarded, ...);
 * - `fsx`, `root` (a prefix for tests), `rootUid`, `rootGid`, `ms` (each call's deadline).
 */
export function restoreAdapters({
  run, launcher, mount, store, registry, provisioner, usageOf, unrestorable, procCount, uidProof, report = () => {},
  fsx = fs, root = "", rootUid = 0, rootGid = 0, ms = 60000,
} = {}) {
  for (const [k, f] of Object.entries({ run, registry, usageOf, unrestorable, procCount, uidProof, report })) {
    if (typeof f !== "function") refuse("bad_form", `restore adapters: ${k} is required`);
  }
  if (typeof launcher !== "string" || !launcher.startsWith("/") || typeof mount !== "string" || !mount.startsWith("/") || !store || !provisioner) {
    refuse("bad_form", "restore adapters: launcher, mount, store and provisioner are required");
  }
  const at = (p) => `${root}${p}`;
  const json = (r, what) => { try { return JSON.parse(r.stdout); } catch { throw hostFail(`${what} printed no JSON`); } };
  const call = (args, opts = {}) => run([launcher, ...args], { ms: opts.ms ?? ms, signal: opts.signal });

  /**
   * The launcher by argv. With `scope` (tree-digest's), it runs inside a transient scope that the kernel bounds:
   * systemd-run --scope execs it in place, so its exit status and output are the launcher's own; a scope killed at
   * its memory or time limit exits by signal, which the driver reads as no listing (a failed validation).
   */
  const launch = (args, { ms: t = ms, signal, scope } = {}) => {
    if (!Array.isArray(args) || !args.every((a) => typeof a === "string")) refuse("bad_form", "restore adapters: bad argv");
    if (scope === undefined) return call(args, { ms: t, signal });
    if (scope === null || typeof scope !== "object" || !SCOPE_UNIT.test(scope.unit) || scope.memoryMax !== "1G"
      || !Number.isSafeInteger(scope.runtimeMaxSec) || scope.runtimeMaxSec < 1 || scope.runtimeMaxSec > 86400) {
      refuse("bad_form", "restore adapters: not tree-digest's scope");
    }
    return run(["systemd-run", "--scope", "--quiet", "--collect", `--unit=${scope.unit}`, `--property=MemoryMax=${scope.memoryMax}`,
      `--property=RuntimeMaxSec=${scope.runtimeMaxSec}`, "--", launcher, ...args], { ms: t, signal });
  };

  /** A live agent's trees, as the launcher sees them now, checked against what provisioning recorded. */
  const inspected = async (id, opts) => {
    const rec = store.provisioned.record(id);
    if (rec === null) return null;
    const r = await call(["inspect-home", "--mount", mount, "--agent", id, "--tree", "home"], opts);
    if (r.code !== 0) throw hostFail(`inspect-home exited ${r.code}`);
    const now = json(r, "inspect-home");
    if (!checkInspected(now)) throw hostFail("inspect-home printed something else");
    // The same objects provisioning recorded (a reboot or remount rebinds only the live fields).
    if (!sameDurable(rec.home, now)) refuse("not_granted", "restore: the agent's trees aren't the provisioned ones");
    return now;
  };

  /**
   * Whether a set can start: { ready: true } or { ready: false, why }. A live agent needs this host's provisioning
   * (provisioned.json, from its first grant) and both trees empty; a tag folder needs to exist (a member's first grant
   * provisions it) and be empty; an archive is provisioned by provisionArchive first.
   */
  const ready = async (kind, id, opts = {}) => {
    if (kind === "tag") {
      if ((await identifiedAt(TAGS_ANCHOR, id, opts)) === null) return { ready: false, why: "waiting for this host's grant" };
      if (fsx.readdirSync(at(`${TAGS_ANCHOR}/${id}`)).length !== 0) return { ready: false, why: "its provisioned folder isn't empty" };
      return { ready: true };
    }
    if (kind === "archive") {
      return (await identifiedAt(ARCHIVE_ANCHOR, id, opts)) === null ? { ready: false, why: "the archive isn't provisioned" } : { ready: true };
    }
    if (kind !== "agent" || !isId(id)) refuse("bad_form", "restore adapters: not a set");
    if ((await inspected(id, opts)) === null) return { ready: false, why: "waiting for this host's grant" };
    // (a precheck only: fill-home itself refuses a destination that isn't empty)
    for (const p of [agentHome(id), agentSessions(id)]) if (fsx.readdirSync(at(p)).length !== 0) return { ready: false, why: "its provisioned trees aren't empty" };
    return { ready: true };
  };

  /** identify of anchor/name: the launcher's identity, or null when absent; anything else is host-side. */
  const identifiedAt = async (anchor, name, opts) => {
    if (!isId(name)) refuse("bad_form", "restore adapters: not an id");
    const r = await call(["identify", "--anchor", anchor, "--name", name], opts);
    if (r.code !== 0) throw hostFail(`identify exited ${r.code}`);
    const x = json(r, "identify");
    if (x?.object === null && Object.keys(x).length === 3) return null;
    if (!checkIdentified(x)) throw hostFail("identify printed something else");
    return x;
  };

  /** A deleted agent's archive and config archive, provisioned fresh (see the header). */
  const provisionArchive = async (id, opts = {}) => {
    const a = Object.hasOwn(registry().agents, id) ? registry().agents[id] : null;
    if (!a || a.state !== "deleted") refuse("not_found", "restore: not a deleted agent of the restored registry");
    const limits = archiveLimits(await usageOf("archive", id, "archive"));
    await provisioner.archive(id, a.uid, limits, opts.ms ?? ms, opts.signal);
  };

  /** The destination's identity in this epoch, from the launcher. */
  const identifyDest = async (kind, id, cls, opts = {}) => {
    if (kind === "agent" && CLASSES.agent.includes(cls)) {
      const now = await inspected(id, opts);
      if (now === null) refuse("not_found", "restore: waiting for this host's grant");
      return { epoch: now.epoch, fsid: now.fsid, object: now.entries[cls] };
    }
    if ((kind === "archive" && cls === "archive") || (kind === "tag" && cls === "tag")) {
      const x = await identifiedAt(kind === "tag" ? TAGS_ANCHOR : ARCHIVE_ANCHOR, id, opts);
      if (x === null) refuse("not_found", kind === "tag" ? "restore: waiting for this host's grant" : "restore: the archive isn't provisioned");
      return x;
    }
    refuse("bad_form", "restore adapters: not a class of this set");
  };

  const expectOf = async (kind, id, cls, identity) => writeExpectFile(at(EXPECT_DIR), `${kind}-${id}-${cls}.json`,
    fillExpect(identity, ownersOf(kind, id, registry())), { rootUid, rootGid });

  const projidOf = (kind, id) => ownersOf(kind, id, registry()).projid;

  /** Where each class's destination is for remove-tree --contents (A1 r2.6 §5a's closed table). */
  const contentsTarget = (kind, id, cls) => (kind === "agent" ? [`${SRV}/agents`, `${id}/${cls}`] : [kind === "tag" ? TAGS_ANCHOR : ARCHIVE_ANCHOR, id]);

  /**
   * Empty the record's dirty destinations, keeping them (A1 r2.6 §5a). Per class, in order: the destination the
   * launcher identifies now must be the one the record pinned (else refused: another object is never emptied); then,
   * afresh, the set's proofs (every agent of it fenced for restore, its slice empty, every non-root owner's uid empty
   * host-wide), else refused with no launcher call; then remove-tree --contents with exactly that identity, owners
   * root and the class's uids. A 75 (partly emptied) or any other exit throws: the record stays dirty, and the next
   * pass takes its proofs again and retries with the same identity.
   */
  const cleanDest = async (r, opts = {}) => {
    if (r === null || typeof r !== "object" || r.dest === null || typeof r.dest !== "object") refuse("bad_form", "restore adapters: no recorded destination");
    const { uids } = ownersOf(r.kind, r.id, registry());
    for (const cls of CLASSES[r.kind]) {
      const x = await identifyDest(r.kind, r.id, cls, opts);
      const d = destOf(x.object);
      if (d.dev !== r.dest[cls].dev || d.ino !== r.dest[cls].ino) refuse("not_granted", "restore: the destination isn't the recorded one; it is never emptied");
      if ((await proofs(r, opts)) !== true) refuse("not_granted", "restore: the set isn't proven stopped and fenced; nothing is emptied");
      const [anchor, name] = contentsTarget(r.kind, r.id, cls);
      const expect = writeExpectFile(at(EXPECT_DIR), `${r.kind}-${r.id}-contents${cls}.json`, { epoch: x.epoch, fsid: x.fsid, root: x.object, owners: [0, ...uids] }, { rootUid, rootGid });
      const rm = await call(["remove-tree", "--contents", "--anchor", anchor, "--name", name, "--expect", expect], opts);
      if (rm.code !== 0) throw hostFail(rm.code === 75 ? "the destination was partly emptied; the next pass retries" : `remove-tree --contents exited ${rm.code}`);
    }
  };

  /** The live agents a set's processes would run as: an agent's own, a tag's members; an archive's none. */
  const agentsOf = (kind, id) => {
    const reg = registry();
    if (kind === "agent") return [id];
    if (kind === "tag") return Object.entries(reg.agents).filter(([, a]) => a.state !== "deleted" && a.tags.includes(id)).map(([x]) => x).sort();
    return [];
  };

  /**
   * Whether the set is stopped and fenced, proven afresh (validation reads its destination): every agent of it has
   * its `restore` fence up, its slice holds no process, and its uid is proven empty host-wide; for an archive, the
   * deleted agent's uid is proven empty. true only then; any failure to prove is false (nothing is validated).
   */
  const stopped = async (r, opts = {}) => proofs(r, opts);

  /**
   * The set's owners as [agent, uid] pairs, each uid with ITS OWN agent (the uid-empty proof checks that agent's
   * user too): an agent's own; a tag's live members; a deleted agent's, for its archive.
   */
  const ownerPairs = (kind, id) => {
    const reg = registry();
    const ids = kind === "archive" ? [id] : agentsOf(kind, id);
    return ids.map((x) => [x, Object.hasOwn(reg.agents, x) ? reg.agents[x].uid : null]);
  };

  /**
   * The proofs, all taken afresh: every live agent of the set has its `restore` fence up and an empty slice, and every
   * owner's uid is proven empty host-wide, each with its own agent (ownerPairs). true only then; any failure to prove
   * is false.
   */
  const proofs = async (r, opts = {}) => {
    const pairs = ownerPairs(r.kind, r.id);
    try {
      for (const x of agentsOf(r.kind, r.id)) {
        if (!fsx.existsSync(at(fenceFiles(x).restore))) return false;
        if ((await procCount(x, opts.ms ?? ms, opts.signal)) !== 0) return false;
      }
      if (pairs.length === 0) return false;
      for (const [agent, uid] of pairs) {
        if (!Number.isSafeInteger(uid)) return false;
        if ((await uidProof(uid, agent, opts.ms ?? ms, opts.signal))?.empty !== true) return false;
      }
      return true;
    } catch { return false; }
  };

  const unrestorableOf = (kind, id, cls) => unrestorable(kind, id, cls);

  /**
   * remove-tree of one object beneath an anchor: identify it, then remove exactly that identity. Absent: nothing to
   * do. Returns the exit (0 removed or absent; else the launcher's code).
   */
  const removeAt = async (anchor, name, owners, key, opts = {}) => {
    const r = await call(["identify", "--anchor", anchor, "--name", name], opts);
    if (r.code !== 0) return r.code;
    const x = json(r, "identify");
    if (x.object === null) return 0;
    if (!checkIdentified(x)) throw hostFail("identify printed something else");
    const expect = writeExpectFile(at(EXPECT_DIR), key, { epoch: x.epoch, fsid: x.fsid, root: x.object, owners }, { rootUid, rootGid });
    return (await call(["remove-tree", "--anchor", anchor, "--name", name, "--expect", expect], opts)).code;
  };

  /**
   * Every staging of the set (any run, any attempt, every class) but, while the record is staging or published, its
   * current attempt. Listed under the staging root (root-only) and each removed by the launcher with owners exactly
   * [0] (A1 r2.8 §5b: below the root-only attempt and data/, no entry's owner is checked, so an attempt holding refused
   * entries of other owners is removed too). One that can't be removed (75: partly; anything else) is reported and
   * kept, never retried in a loop, and doesn't change the set's state.
   */
  const discardStaging = async (r, opts = {}) => {
    const owner = ownerOf(r.kind, r.id);
    const keep = ["staging", "published"].includes(r.state);
    const owners = [0];
    const list = (p) => { try { return fsx.readdirSync(at(p)); } catch (e) { if (e?.code === "ENOENT") return []; throw e; } };
    for (const run of list(RESTORE_STAGING).filter((x) => RESTORE_RUN.test(x))) {
      for (const cls of list(join(RESTORE_STAGING, run, owner)).filter((c) => CLASSES[r.kind].includes(c))) {
        for (const attempt of list(join(RESTORE_STAGING, run, owner, cls)).filter((n) => /^[1-9][0-9]{0,5}$/.test(n))) {
          if (keep && run === r.run && attempt === String(r.attempt)) continue;
          const code = await removeAt(RESTORE_STAGING, `${run}/${owner}/${cls}/${attempt}`, owners, `${r.kind}-${r.id}-staging${cls}.json`, opts);
          if (code !== 0) report({ kind: "restore.staging_kept", set: `${r.kind}-${r.id}`, attempt: `${run}/${owner}/${cls}/${attempt}`, code });
        }
      }
    }
  };

  /** The set's SQLite copy directory, <VALIDATE_DIR>/<run>/<owner>, removed (absent is fine); the anchor made first. */
  const removeCopies = async (r, opts = {}) => {
    validateAnchor();
    const code = await removeAt(VALIDATE_DIR, `${r.run}/${ownerOf(r.kind, r.id)}`, [0], `${r.kind}-${r.id}-copies.json`, opts);
    if (code !== 0) throw hostFail(`the SQLite copies can't be removed (${code})`);
  };

  /** The validate anchor: root:root 0700, a directory, never a link; made if absent, else refused unless exactly so. */
  const validateAnchor = () => {
    try { fsx.mkdirSync(at(VALIDATE_DIR), { mode: 0o700 }); } catch (e) { if (e?.code !== "EEXIST") throw hostFail("the validate anchor can't be made"); }
    const st = fsx.lstatSync(at(VALIDATE_DIR));
    if (!st.isDirectory() || st.uid !== rootUid || st.gid !== rootGid || (st.mode & 0o7777) !== 0o700) refuse("not_granted", "restore: the validate anchor isn't root's 0700 directory");
  };

  return { launch, ready, provisionArchive, identifyDest, expectOf, projidOf, cleanDest, stopped, unrestorableOf, discardStaging, removeCopies, validateAnchor };
}
