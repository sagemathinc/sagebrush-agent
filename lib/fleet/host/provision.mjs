// Host supervisor (design: agent-autonomous-host-supervisor-freeze-r3.1.md §2.1, §2.2, §5.2, §5.3, §5.4): provisioning
// a new agent's persistent host state, the executor's `provision` step. In order:
// - its tag groups `sbt-<tag>` (gid from the registry), then its private group `sb-<id>` (gid = uid), then its user
//   `sb-<id>`: no login shell, no home created, and NO subordinate uid/gid range (useradd would otherwise allocate one
//   from login.defs, giving the agent user-namespace ids; both files are checked afterwards);
// - its directories under /srv/sagebrush: the agent's directory (root 0755), its home and var-tmp (the agent, 0700),
//   and each tag folder (root:sbt-<tag> 2770);
// - with project quotas available (the host says where /srv/sagebrush is mounted): the agent's project id (= uid) on
//   home and var-tmp, each tag's (= its gid) on the tag folder, with the inherit flag, and the hard limits: the grant's
//   disk_gb and 2 M inodes for the agent, 50 GiB and 2 M inodes for a tag (§5.4). Without them nothing is set; the
//   qualification report says "disk quotas: unavailable".
// Every step reads before it writes. A name or number that already exists must be exactly what this agent's would be
// (same uid, gid, home, shell; a directory with the same owner and mode, not a symlink): then it is left as it is, so a
// redone step changes nothing. Anything else is a host-side failure. Nothing is ever chowned recursively, and nothing
// that exists is modified.
//
// The runtime state under /run (the network namespace, the broker directory, the staging mounts) is rebuilt at every
// start instead (effects.mjs), because /run doesn't survive a reboot.

import fs from "node:fs";
import { isId, refuse } from "../bytes.mjs";
import { agentDir, agentHome, agentUser, agentVarTmp, SRV, tagDir, tagGroup } from "./names.mjs";
import { GID_RANGE, UID_RANGE } from "./registry.mjs";

export const NOLOGIN = "/usr/sbin/nologin";
/** §5.4: the inode limit for an agent and a tag; a tag's block limit. */
export const QUOTA_INODES = 2 * 1024 * 1024;
export const TAG_QUOTA_GB = 50;

const hostFail = (what) => Object.assign(new Error(`provision: ${what}`), { code: "effect_failed" });

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

  /** A group named `name` with exactly `gid`, created if neither exists; any other holder of either is a failure. */
  const group = async (name, gid, left, signal) => {
    const byName = await getent(run, "group", name, left(), signal);
    const byGid = await getent(run, "group", gid, left(), signal);
    if (byName || byGid) {
      if (!byName || !byGid || byName[0] !== name || byName[2] !== String(gid) || byGid[0] !== name) throw hostFail("a group name or gid is taken");
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

  /** A directory with exactly this owner, group and mode: made if missing, refused if it differs or is a symlink. */
  const dir = (p, uid, gid, mode) => {
    try { fsx.mkdirSync(at(p), { mode }); } catch (e) {
      if (e?.code !== "EEXIST") throw hostFail(`can't make ${p}`);
      const st = fsx.lstatSync(at(p));
      if (!st.isDirectory() || st.uid !== uid || st.gid !== gid || (st.mode & 0o7777) !== mode) throw hostFail(`${p} exists and differs`);
      return false;
    }
    fsx.chownSync(at(p), uid, gid);
    fsx.chmodSync(at(p), mode); // mkdir's mode is filtered by the umask, and drops the setgid bit
    return true;
  };

  /** Project quota: the id on the directory with the inherit flag, then its hard limits. */
  const project = async (p, id, gb, left, signal) => {
    if (quota === null) return;
    await must(["chattr", "+P", "-p", String(id), at(p)], left, signal);
    await must(["setquota", "-P", String(id), "0", String(gb * 1024 * 1024), "0", String(QUOTA_INODES), quota.mount], left, signal);
  };

  const provision = async (agent, uid, grantAgent, ms, signal) => {
    const t0 = Date.now();
    const left = () => ms - (Date.now() - t0);
    if (!isId(agent) || (grantAgent.id ?? grantAgent.agent) !== agent) throw hostFail("the grant entry is for another agent");
    if (!Number.isSafeInteger(uid) || uid < UID_RANGE[0] || uid > UID_RANGE[1]) throw hostFail("a uid outside the agent range");
    const tags = grantAgent.tags.map((t) => {
      const gid = tagGid(t);
      if (!Number.isSafeInteger(gid) || gid < GID_RANGE[0] || gid > GID_RANGE[1]) throw hostFail("a tag gid outside the tag range");
      return { t, gid };
    });
    for (const { t, gid } of tags) await group(tagGroup(t), gid, left, signal);
    await group(agentUser(agent), uid, left, signal);
    await user(agent, uid, left, signal);
    for (const p of [SRV, `${SRV}/agents`, `${SRV}/tags`]) dir(p, rootUid, rootUid, 0o755);
    dir(agentDir(agent), rootUid, rootUid, 0o755);
    for (const p of [agentHome(agent), agentVarTmp(agent)]) {
      dir(p, uid, uid, 0o700);
      await project(p, uid, grantAgent.config.resources.disk_gb, left, signal);
    }
    for (const { t, gid } of tags) {
      dir(tagDir(t), rootUid, gid, 0o2770);
      await project(tagDir(t), gid, TAG_QUOTA_GB, left, signal);
    }
  };

  /** The agent's quota limits again (writeUnit: the grant's disk_gb may have changed). Nothing without quotas. */
  const requota = async (agent, uid, grantAgent, left, signal) => {
    if (quota === null) return;
    await must(["setquota", "-P", String(uid), "0", String(grantAgent.config.resources.disk_gb * 1024 * 1024), "0", String(QUOTA_INODES), quota.mount], left, signal);
  };

  return { provision, requota };
}
