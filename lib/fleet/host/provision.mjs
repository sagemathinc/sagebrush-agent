// Host supervisor (design: agent-autonomous-host-supervisor-freeze-r3.1.md §2.1, §2.2, §5.2, §5.3, §5.4): provisioning
// a new agent's persistent host state, the executor's `provision` step. In order:
// - first, the host's subordinate ids must come only from the local files: an nsswitch.conf `subid:` line naming any
//   other source refuses before anything is changed (so the /etc/subuid and /etc/subgid checks below are complete);
// - its tag groups `sbt-<tag>` (gid from the registry), then its private group `sb-<id>` (gid = uid), then its user
//   `sb-<id>`: no login shell, no home created, and NO subordinate uid/gid range (useradd would otherwise allocate one
//   from login.defs, giving the agent user-namespace ids; both files are checked afterwards);
// - its directories under /srv/sagebrush: the agent's directory (root 0755) holding exactly its home, var-tmp and
//   sessions (the agent, 0700); its config tree beside it, agent-config/<id> (root 0700, amendment L1); the archive
//   parents archive and archive-config (root 0700, for deprovision); and each tag folder (root:sbt-<tag> 2770);
// - its quota-carrying directories (home, var-tmp, sessions and its config tree, each tag folder), made root-only first; with ext4 project quotas
//   available (the host says where /srv/sagebrush is mounted), their hard limits (the grant's disk_gb and 2 M inodes for
//   the agent, 50 GiB and 2 M inodes for a tag, §5.4) and project id with the inherit flag are set and verified BEFORE
//   the final owner and mode are published, so nothing can be written into them uncharged. Without quotas nothing is
//   set; the qualification report says "disk quotas: unavailable".
// Every step reads before it writes. A name or number that already exists must be exactly what this agent's would be
// (same uid, gid, home, shell; a group with no members; a directory with the same owner and mode, not a symlink): then
// it is left as it is, so a
// redone step changes nothing. Anything else is a host-side failure. Nothing is ever chowned recursively, and nothing
// that exists is modified.
//
// The runtime state under /run (the network namespace, the broker directory, the staging mounts) is rebuilt at every
// start instead (effects.mjs), because /run doesn't survive a reboot.

import fs from "node:fs";
import { isId, refuse } from "../bytes.mjs";
import { agentConfigDir, agentDir, agentHome, agentSessions, agentUser, agentVarTmp, SRV, tagDir, tagGroup } from "./names.mjs";
import { GID_RANGE, UID_RANGE } from "./registry.mjs";

export const NOLOGIN = "/usr/sbin/nologin";
/** §5.4: the inode limit for an agent and a tag; a tag's block limit. */
export const QUOTA_INODES = 2 * 1024 * 1024;
export const TAG_QUOTA_GB = 50;

const hostFail = (what) => Object.assign(new Error(`provision: ${what}`), { code: "effect_failed" });

/**
 * Subordinate ids may come only from the local files (the requirement this module checks /etc/subuid and /etc/subgid
 * under): an nsswitch.conf `subid:` line naming any source but `files` (an sss or other libsubid source) refuses. No
 * such line is glibc's default, the files.
 */
function subidFilesOnly(text) {
  for (const raw of text.split("\n")) {
    const line = raw.replace(/#.*/, "").trim();
    const m = /^subid\s*:(.*)$/.exec(line);
    if (!m) continue;
    const sources = m[1].replace(/\[[^\]]*\]/g, " ").split(/\s+/).filter(Boolean);
    if (sources.some((x) => x !== "files")) return false;
  }
  return true;
}

/** One getent entry, split on ':'; null when getent says there is none (exit 2). */
async function getent(run, db, key, ms, signal) {
  const r = await run(["getent", db, String(key)], { ms, signal });
  if (r.code === 2) return null;
  if (r.code !== 0) throw hostFail(`getent ${db} failed`);
  const lines = r.stdout.split("\n").filter(Boolean);
  if (lines.length !== 1) throw hostFail(`getent ${db} returned ${lines.length} entries`);
  return lines[0].split(":");
}

/**
 * The provisioning effect. Options: `run` (effects.mjs runArgv), `fsx` (node:fs), `root` (a filesystem prefix for
 * tests; "" on a host), `rootUid` (0), `tagGid(tag)` (the registry's gid for a tag), `quota`: null, or
 * { mount } (the mountpoint of the filesystem holding /srv/sagebrush, with ext4 project quotas on).
 */
export function provisioner({ run, fsx = fs, root = "", rootUid = 0, tagGid, quota = null } = {}) {
  if (typeof run !== "function" || typeof tagGid !== "function") refuse("bad_form", "provision: run and tagGid are required");
  const at = (p) => `${root}${p}`;
  const must = async (argv, left, signal) => {
    const r = await run(argv, { ms: left(), signal });
    if (r.code !== 0) throw hostFail(`${argv[0]} exited ${r.code}`);
  };

  /**
   * A group named `name` with exactly `gid` and NO members, created if neither exists. Any other holder of either is a
   * failure, and so is an existing group with a member list: adopting it would give those members the agent's or the
   * tag's access (a tag folder is root:<group> 2770).
   */
  const group = async (name, gid, left, signal) => {
    const byName = await getent(run, "group", name, left(), signal);
    const byGid = await getent(run, "group", gid, left(), signal);
    if (byName || byGid) {
      if (!byName || !byGid || byName[0] !== name || byName[2] !== String(gid) || byGid[0] !== name) throw hostFail("a group name or gid is taken");
      if (byName.length !== 4 || byName[3] !== "" || byGid.length !== 4 || byGid[3] !== "") throw hostFail("an existing group has members");
      return;
    }
    await must(["groupadd", "--gid", String(gid), name], left, signal);
  };

  /** The agent's user, exactly as this agent's would be; created if neither its name nor its uid exists. */
  const user = async (agent, uid, left, signal) => {
    const name = agentUser(agent);
    const want = [name, "x", String(uid), String(uid), "", agentHome(agent), NOLOGIN];
    const byName = await getent(run, "passwd", name, left(), signal);
    const byUid = await getent(run, "passwd", uid, left(), signal);
    if (byName || byUid) {
      if (!byName || !byUid || byUid[0] !== name || JSON.stringify(byName) !== JSON.stringify(want)) throw hostFail("a user name or uid is taken, or differs");
    } else {
      // -K SUB_*_COUNT=0: no subordinate ids for the agent (login.defs would otherwise allocate 65536 of each).
      await must(["useradd", "--uid", String(uid), "--gid", String(uid), "--no-create-home", "--home-dir", agentHome(agent),
        "--shell", NOLOGIN, "--comment", "", "-K", "SUB_UID_COUNT=0", "-K", "SUB_GID_COUNT=0", name], left, signal);
    }
    for (const f of ["/etc/subuid", "/etc/subgid"]) {
      let text = "";
      try { text = fsx.readFileSync(at(f), "utf8"); } catch (e) { if (e?.code !== "ENOENT") throw hostFail(`${f} is unreadable`); }
      if (text.split("\n").some((l) => l.split(":")[0] === name || l.split(":")[0] === String(uid))) throw hostFail(`the agent has a ${f} range`);
    }
  };

  const empty = (p) => fsx.readdirSync(at(p)).length === 0;

  /**
   * A directory with exactly this owner, group and mode. Made if missing. An existing one that matches is left as it
   * is (returns false). An existing one that is empty, root-owned and not group- or world-writable is what a crash
   * between mkdir and chown leaves (nobody else could have written into it): it is finished (returns true, as new).
   * Anything else, a symlink or file included, is refused.
   */
  const dir = (p, uid, gid, mode) => {
    try { fsx.mkdirSync(at(p), { mode }); } catch (e) {
      if (e?.code !== "EEXIST") throw hostFail(`can't make ${p}`);
      const st = fsx.lstatSync(at(p));
      if (!st.isDirectory()) throw hostFail(`${p} exists and isn't a directory`);
      if (st.uid === uid && st.gid === gid && (st.mode & 0o7777) === mode) return false;
      if (!(st.uid === rootUid && (st.mode & 0o022) === 0 && empty(p))) throw hostFail(`${p} exists and differs`);
    }
    fsx.chownSync(at(p), uid, gid);
    fsx.chmodSync(at(p), mode); // mkdir's mode is filtered by the umask, and drops the setgid bit
    return true;
  };

  /** A directory's ext4 project id and whether it has the inherit flag (P), from `lsattr -p -d`. */
  const projectState = async (p, left, signal) => {
    const r = await run(["lsattr", "-p", "-d", at(p)], { ms: left(), signal });
    const m = r.code === 0 ? /^\s*(\d+)\s+(\S+)\s/.exec(r.stdout) : null;
    if (!m) throw hostFail(`lsattr can't read ${p}`);
    return { id: Number(m[1]), inherit: m[2].includes("P") };
  };

  /**
   * A directory that carries a project quota (an agent's home and var-tmp, a tag folder), created so that nobody but
   * root can write into it before its quota exists:
   * 1. made root:root 0700 (the INIT state: not writable by the agent or the tag group);
   * 2. with quotas: its hard limits, then its project id with the inherit flag, then both VERIFIED with lsattr;
   * 3. published: the final owner first (still 0700, the OWNED state: no group access yet), then the final mode.
   * An existing directory is adopted only in its exact final state: owner, group, mode and, with quotas, project id and
   * inherit flag (then nothing is run). An EMPTY directory in the INIT or OWNED state is what a crash between these steps
   * leaves: the steps are finished from 2. Anything else (another project state, a populated incomplete directory, a
   * symlink or file) is refused and never rewritten: no migration in v1, and relabelling a populated directory wouldn't
   * charge what is already in it.
   */
  const labelled = async (p, uid, gid, mode, projId, gb, left, signal) => {
    let st = null;
    try { st = fsx.lstatSync(at(p)); } catch (e) { if (e?.code !== "ENOENT") throw hostFail(`can't read ${p}`); }
    if (st === null) {
      try { fsx.mkdirSync(at(p), { mode: 0o700 }); } catch { throw hostFail(`can't make ${p}`); }
      fsx.chownSync(at(p), rootUid, rootUid);
      fsx.chmodSync(at(p), 0o700);
    } else {
      if (!st.isDirectory()) throw hostFail(`${p} exists and isn't a directory`);
      const m = st.mode & 0o7777;
      if (st.uid === uid && st.gid === gid && m === mode) {
        if (quota === null) return;
        const ps = await projectState(p, left, signal);
        if (ps.id === projId && ps.inherit) return; // the exact final state
        // A root:root 0700 directory's final state IS the INIT state (the config tree): an empty one that isn't
        // labelled yet is a crash before step 2, finished from there.
        const initIsFinal = uid === rootUid && gid === rootUid && mode === 0o700;
        if (!(initIsFinal && empty(p))) throw hostFail(`${p} has another project state`);
      } else {
        const init = st.uid === rootUid && st.gid === rootUid && m === 0o700;
        const owned = st.uid === uid && st.gid === gid && m === 0o700;
        if (!(init || owned) || !empty(p)) throw hostFail(`${p} exists and differs`);
      }
    }
    if (quota !== null) {
      await must(["setquota", "-P", String(projId), "0", String(gb * 1024 * 1024), "0", String(QUOTA_INODES), quota.mount], left, signal);
      await must(["chattr", "+P", "-p", String(projId), at(p)], left, signal);
      const ps = await projectState(p, left, signal);
      if (!(ps.id === projId && ps.inherit)) throw hostFail(`${p}'s project label didn't take`);
    }
    fsx.chownSync(at(p), uid, gid);
    fsx.chmodSync(at(p), mode);
  };

  const provision = async (agent, uid, grantAgent, ms, signal) => {
    const t0 = Date.now();
    const left = () => ms - (Date.now() - t0);
    if (!isId(agent) || (grantAgent.id ?? grantAgent.agent) !== agent) throw hostFail("the grant entry is for another agent");
    if (!Number.isSafeInteger(uid) || uid < UID_RANGE[0] || uid > UID_RANGE[1]) throw hostFail("a uid outside the agent range");
    let nss = "";
    try { nss = fsx.readFileSync(at("/etc/nsswitch.conf"), "utf8"); } catch (e) { if (e?.code !== "ENOENT") throw hostFail("nsswitch.conf is unreadable"); }
    if (!subidFilesOnly(nss)) throw hostFail("subordinate ids may come from a source other than the local files");
    const tags = grantAgent.tags.map((t) => {
      const gid = tagGid(t);
      if (!Number.isSafeInteger(gid) || gid < GID_RANGE[0] || gid > GID_RANGE[1]) throw hostFail("a tag gid outside the tag range");
      return { t, gid };
    });
    for (const { t, gid } of tags) await group(tagGroup(t), gid, left, signal);
    await group(agentUser(agent), uid, left, signal);
    await user(agent, uid, left, signal);
    for (const p of [SRV, `${SRV}/agents`, `${SRV}/tags`, `${SRV}/agent-config`]) dir(p, rootUid, rootUid, 0o755);
    for (const p of [`${SRV}/archive`, `${SRV}/archive-config`]) dir(p, rootUid, rootUid, 0o700);
    dir(agentDir(agent), rootUid, rootUid, 0o755);
    const gb = grantAgent.config.resources.disk_gb;
    for (const p of [agentHome(agent), agentVarTmp(agent), agentSessions(agent)]) await labelled(p, uid, uid, 0o700, uid, gb, left, signal);
    await labelled(agentConfigDir(agent), rootUid, rootUid, 0o700, uid, gb, left, signal);
    for (const { t, gid } of tags) await labelled(tagDir(t), rootUid, gid, 0o2770, gid, TAG_QUOTA_GB, left, signal);
  };

  /** The agent's quota limits again (writeUnit: the grant's disk_gb may have changed). Nothing without quotas. */
  const requota = async (agent, uid, grantAgent, left, signal) => {
    if (quota === null) return;
    await must(["setquota", "-P", String(uid), "0", String(grantAgent.config.resources.disk_gb * 1024 * 1024), "0", String(QUOTA_INODES), quota.mount], left, signal);
  };

  return { provision, requota };
}
