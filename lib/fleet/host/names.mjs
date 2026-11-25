// Host supervisor (design: agent-autonomous-host-supervisor-freeze-r3.1.md §2.1): every name on a host is derived from an
// immutable id, never from a display name. An id is checked against the one id grammar before any name is made from
// it, so nothing but 26 characters of [a-z2-7] can ever reach a user name, a unit name, a path or a shell.

import { isId, refuse } from "../bytes.mjs";

const need = (id) => { if (!isId(id)) refuse("bad_form", "not an id"); return id; };

/** An agent's Unix user and private group: `sb-<id>` (29 characters; Linux allows 32). */
export const agentUser = (agent) => `sb-${need(agent)}`;
/** A tag's Unix group: `sbt-<id>` (30 characters). */
export const tagGroup = (tag) => `sbt-${need(tag)}`;
/** An agent's systemd unit. */
export const agentUnit = (agent) => `sagebrush-agent-${need(agent)}.service`;
/** The slice every agent unit runs in, so a local stop can stop them all without the supervisor (§3.3). */
export const AGENT_SLICE = "sagebrush-agents.slice";
/**
 * An agent's own slice inside it (execution lease §2.1): its unit, every turn scope and the lease activation helper's
 * scope run here, so killing this one cgroup ends everything of the agent, and nothing else.
 */
export const agentSlice = (agent) => `sagebrush-agents-${need(agent)}.slice`;
/**
 * The restore resume helper's scope, inside the agent's slice (the first-lease rule r2.1, S2): the only place the
 * agent's `restore` fence is lowered from.
 */
export const restoreResumeScope = (agent) => `sagebrush-restore-resume-${need(agent)}.scope`;
/** A scope's cgroup inside the agent's slice, as /proc/self/cgroup names it. */
export const agentScopeCgroup = (agent, scope) => `/sagebrush.slice/${AGENT_SLICE}/${agentSlice(agent)}/${scope}`;
/** An agent's network namespace (§5.1). */
export const agentNetns = (agent) => `sb-${need(agent)}`;

export const SRV = "/srv/sagebrush";
/** An agent's directory, holding exactly `home`, `var-tmp` and `sessions` (§4.6; deprovision r3.2 §3.6). */
export const agentDir = (agent) => `${SRV}/agents/${need(agent)}`;
export const agentHome = (agent) => `${agentDir(agent)}/home`;
export const agentVarTmp = (agent) => `${agentDir(agent)}/var-tmp`;
/** The agent's harness session store (advisor delta r3.2 §8), bound privately into each turn. */
export const agentSessions = (agent) => `${agentDir(agent)}/sessions`;
/** The agent's config generations (amendment L1): root-owned, beside the agent directory, never inside it. */
export const agentConfigDir = (agent) => `${SRV}/agent-config/${need(agent)}`;
/** Where deprovision archives an agent's directory and its config tree (deprovision r3.2 §3.6, L1 step 6b). */
export const agentArchive = (agent) => `${SRV}/archive/${need(agent)}`;
export const agentConfigArchive = (agent) => `${SRV}/archive-config/${need(agent)}`;
/** A tag's shared folder. */
export const tagDir = (tag) => `${SRV}/tags/${need(tag)}`;

/** The broker's per-agent socket directory, bound read-only at /run/sagebrush/self inside the unit (§5.2). */
export const brokerDir = (agent) => `/run/sagebrush/broker/${need(agent)}`;

/**
 * Where the generated agent units are installed: a persistent load path that systemd ranks BELOW /run/systemd/system,
 * so a runtime mask (`systemctl mask --runtime`, a link to /dev/null in /run/systemd/system) always wins over the unit.
 * /etc/systemd/system ranks above /run/systemd/system: a runtime mask there is shadowed by the unit and doesn't stop a
 * start (freeze §3.3, §3.4: masked units can't be started by Restart=, a dependency or daemon-reload).
 */
export const UNIT_DIR = "/usr/local/lib/systemd/system";
/** The load paths systemd ranks above /run/systemd/system: an agent unit file in any of them would shadow the mask. */
export const UNIT_DIRS_ABOVE_MASK = Object.freeze([
  "/etc/systemd/system.control", "/run/systemd/system.control", "/run/systemd/transient", "/run/systemd/generator.early",
  "/etc/systemd/system", "/etc/systemd/system.attached",
]);

export const FENCE_DIR = "/var/lib/sagebrush/fence";
/** The host store's root (supervisor freeze r3.1 §2.2: the durable state, root-only). */
export const HOST_STORE = "/var/lib/sagebrush/state";
/** The host's own settings (host daemon r2.5 §2: `execution_lease`), root 0644. */
export const HOST_CONFIG = "/etc/sagebrush/host.json";
/** The broker's service, the one broker unit the release installs (r3.1 §9.1), and the user every broker process runs as. */
export const BROKER_UNIT = "sagebrush-broker.service";
export const BROKER_USER = "sb-broker";
/** The daemon's own unit (host daemon main r1.1 §1). */
export const SUPERVISOR_UNIT = "sagebrush-supervisor.service";
/**
 * The fence files of an agent, one per cause (§3.3): each is lowered only by its own cause. `backup` (host backup
 * §4), `lease` (execution lease §2), `restore` (§5) and `transferred` (execution lease §4: never lowered) are per agent,
 * each in its own directory.
 */
export const fenceFiles = (agent) => ({
  all: `${FENCE_DIR}/all`,
  agent: `${FENCE_DIR}/${need(agent)}`,
  expiry: `${FENCE_DIR}/expiry`,
  backup: `${FENCE_DIR}/backup/${need(agent)}`,
  lease: `${FENCE_DIR}/lease/${need(agent)}`,
  restore: `${FENCE_DIR}/restore/${need(agent)}`,
  transferred: `${FENCE_DIR}/transferred/${need(agent)}`,
});

/** The host backup's state (host backup §4): the run journal `run.json` and its lock. Root 0700. */
export const BACKUP_DIR = "/var/lib/sagebrush/backup";
/** A restore's per-set records (restore-record.mjs), root 0700; and its staging root on the quota filesystem. */
export const RESTORE_DIR = "/var/lib/sagebrush/restore";
export const RESTORE_STAGING = `${SRV}/.restore`;
/**
 * Validation's private SQLite copies (launcher amendment A2 r3.7 §4a): tree-digest copies a sessions class's databases
 * into <VALIDATE_DIR>/<run>/<owner>. Root 0700, on the root filesystem, never the quota mount.
 */
export const VALIDATE_DIR = "/var/lib/sagebrush/validate";
/**
 * The slice the backup worker's scope runs in, outside every agent's slice: `cgroup.freeze` is hierarchical, so a
 * worker inside the agent's slice would freeze with it.
 */
export const BACKUP_SLICE = "sagebrush-backup.slice";
/**
 * The cgroup of an agent's own slice, sagebrush-agents-<id>.slice (agentSlice): what the backup freezes and thaws, and
 * what the lease watchdog kills and proves empty.
 */
export const agentSliceCgroup = (agent) => `/sys/fs/cgroup/sagebrush.slice/sagebrush-agents.slice/sagebrush-agents-${need(agent)}.slice`;
/** The cgroup of BACKUP_SLICE, and of a backup worker's scope in it, by its scope name (sagebrush-backup-<run>.scope). */
export const BACKUP_SLICE_CGROUP = `/sys/fs/cgroup/sagebrush.slice/${BACKUP_SLICE}`;
export const backupScopeCgroup = (scope) => `${BACKUP_SLICE_CGROUP}/${scope}`;
