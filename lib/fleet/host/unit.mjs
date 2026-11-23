// Host supervisor (design: agent-autonomous-host-supervisor-freeze-r3.1.md §4.2, §4.3, §4.5, §4.6, §5.3, §5.4, §3.3): the
// generator. From one grant agent and what the host decided for it (uid, tag groups, staged bind handles, the release),
// it renders, deterministically:
// - the agent's systemd unit (every §4.2 directive; the three stop fences as start conditions; LoadCredential for the
//   broker placeholder and workspace capability, never Environment=);
// - the §4.6 path contract, as one list of rows from which both the unit's mount view and the Landlock ruleset come,
//   so the two can't disagree;
// - the Landlock ruleset for the launcher (ABI 4 only).
// It refuses anything it can't render safely: a value that could break out of a unit line (whitespace, control
// characters, ':' in a bind path), staged binds that don't match the grant exactly, a `root` that isn't a boolean, or a
// GPU grant without device nodes.
//
// A root agent (`root: true`, §4.5) gets the same unit with User=root and Group=root, and without the §4.2 Privilege
// row (NoNewPrivileges, CapabilityBoundingSet, AmbientCapabilities, RestrictSUIDSGID, SecureBits) and Namespaces row
// (RestrictNamespaces). Everything else stays: the fences, the mount view and Landlock, the syscall filter, the kernel
// and proc protections, the netns, the resources. That narrows what it does by accident; it is NOT isolation: root is
// the host's trust boundary (it can reach every agent and the broker), and its stop is best effort (fence.mjs).

import { createHash } from "node:crypto";
import { isId, refuse } from "../bytes.mjs";
import { validateConfig } from "./config.mjs";
import { AGENT_SLICE, agentHome, agentUnit, agentUser, agentVarTmp, brokerDir, fenceFiles, tagDir, tagGroup, agentNetns } from "./names.mjs";

export const LANDLOCK_ABI = 4;

/** Path characters a unit line can carry without quoting or escaping: no whitespace, no control characters, no ':'. */
const SAFE_PATH = /^\/[A-Za-z0-9._+@\/-]*$/;
const safePath = (p, what) => {
  if (typeof p !== "string" || !SAFE_PATH.test(p) || p.includes("//") || p.length > 1024) refuse("bad_form", `unit: ${what} can't be rendered safely`);
  return p;
};

const CREDS = (agent) => `/var/lib/sagebrush/creds/${agent}`;
const MANAGED = (agent) => `/var/lib/sagebrush/managed/${agent}`;
const RESOLV = (agent) => `/var/lib/sagebrush/resolv/${agent}.conf`;
const STAGING = (agent) => `/run/sagebrush/binds/${agent}`;
/** The launcher's contract file (host side), bound read-only at CONTRACT_IN_VIEW inside the unit. */
export const CONTRACT = (agent) => `/var/lib/sagebrush/contract/${agent}.json`;
export const CONTRACT_IN_VIEW = "/run/sagebrush/contract.json";

/** The managed CLI settings file each client reads, bound read-only over the client's system path (§6). */
const MANAGED_TARGET = Object.freeze({
  claude: "/etc/claude-code/managed-settings.json",
  codex: "/etc/codex/managed_config.toml",
});

const SYSCALL_DENY = ["@mount", "@swap", "@reboot", "@raw-io", "@module", "@obsolete", "@cpu-emulation", "@privileged"];

/**
 * Build the §4.6 path contract for one agent. Each row: { path (as the agent sees it), source (host path or null),
 * mount ("ro" | "rw" | "tmpfs" | "system" | "proc" | "sys" | "dev" | "hidden"), landlock: "" | "r" | "rx" | "rwx" | "rw" }.
 */
export function pathContract(agent, ctx) {
  const { id, client, tags, config } = agent;
  const rows = [
    { path: "/usr", source: null, mount: "system", landlock: "rx" },
    // No /bin, /sbin, /lib or /lib64 rows: on a merged-usr system (Ubuntu 24.04) they are symlinks into /usr, which
    // the launcher refuses to follow (RESOLVE_NO_SYMLINKS, exit 66), and /usr already covers what they point to.
    { path: "/etc", source: null, mount: "system", landlock: "r" },
    { path: safePath(ctx.release, "the release path"), source: null, mount: "system", landlock: "rx" },
    { path: safePath(ctx.cliPath, "the CLI path"), source: null, mount: "system", landlock: "rx" },
    { path: MANAGED_TARGET[client], source: `${MANAGED(id)}/${client === "claude" ? "managed-settings.json" : "managed_config.toml"}`, mount: "ro", landlock: "r" },
    { path: agentHome(id), source: agentHome(id), mount: "rw", landlock: "rwx" },
    { path: "/var/tmp", source: agentVarTmp(id), mount: "rw", landlock: "rwx" },
    ...tags.map((t) => ({ path: tagDir(t), source: tagDir(t), mount: "rw", landlock: "rwx" })),
    ...config.files.rw.map((p) => ({ path: safePath(p, "a granted path"), source: stagedFor(ctx, p, "rw"), mount: "rw", landlock: "rwx" })),
    ...config.files.ro.map((p) => ({ path: safePath(p, "a granted path"), source: stagedFor(ctx, p, "ro"), mount: "ro", landlock: "rx" })),
    { path: "/tmp", source: null, mount: "tmpfs", landlock: "rwx" },
    { path: "/dev/shm", source: null, mount: "tmpfs", landlock: "rwx" },
    { path: "/proc", source: null, mount: "proc", landlock: "r" },
    { path: "/sys", source: null, mount: "sys", landlock: "r" },
    { path: "/dev", source: null, mount: "dev", landlock: "rw" },
    { path: `/run/credentials/${agentUnit(id)}`, source: null, mount: "system", landlock: "r" },
    { path: "/run/sagebrush/self", source: brokerDir(id), mount: "ro", landlock: "rw" },
    { path: "/etc/resolv.conf", source: RESOLV(id), mount: "ro", landlock: "r" },
    // The launcher's contract: bound read-only for the launcher to read BEFORE it restricts itself; no Landlock right,
    // so the agent's CLI can't read it afterwards.
    { path: CONTRACT_IN_VIEW, source: CONTRACT(id), mount: "ro", landlock: "" },
  ];
  return rows;
}

function stagedFor(ctx, path, mode) {
  const s = (ctx.staged ?? []).filter((x) => x.path === path && x.mode === mode);
  if (s.length !== 1) refuse("preflight_missing", "unit: a granted path has no staged bind handle");
  return s[0].staging;
}

/** The Landlock ruleset (§4.3): exactly the contract's Landlock column, ABI 4. */
export function landlockRules(contract) {
  return { abi: LANDLOCK_ABI, rules: contract.filter((r) => r.landlock).map((r) => ({ path: r.path, access: r.landlock })) };
}

function checkInput(agent, ctx) {
  if (!agent || !isId(agent.id)) refuse("bad_form", "unit: bad agent id");
  if (typeof agent.root !== "boolean") refuse("bad_form", "unit: root is a boolean");
  if (!Object.hasOwn(MANAGED_TARGET, agent.client)) refuse("bad_form", "unit: unknown client");
  if (!Array.isArray(agent.tags) || !agent.tags.every(isId) || new Set(agent.tags).size !== agent.tags.length) refuse("bad_form", "unit: bad tags");
  validateConfig(agent.config, ctx.hostInfo ?? {});
  if (!Number.isSafeInteger(ctx.uid)) refuse("bad_form", "unit: no uid");
  // Staged binds must match the grant's files exactly (one per path and mode, nothing extra), each under this agent's
  // root-only staging directory.
  const want = [...agent.config.files.rw.map((p) => `rw ${p}`), ...agent.config.files.ro.map((p) => `ro ${p}`)].sort();
  const staged = ctx.staged ?? [];
  const have = staged.map((s) => `${s.mode} ${s.path}`).sort();
  if (JSON.stringify(want) !== JSON.stringify(have)) refuse("preflight_missing", "unit: staged binds don't match the grant");
  const prefix = `${STAGING(agent.id)}/`;
  for (const s of staged) {
    safePath(s.staging, "a staging path");
    if (!s.staging.startsWith(prefix) || !/^[0-9]+$/.test(s.staging.slice(prefix.length))) refuse("bad_form", "unit: a staging path outside this agent's staging directory");
  }
  if (agent.config.gpu) {
    if (!Array.isArray(ctx.gpuNodes) || ctx.gpuNodes.length === 0) refuse("preflight_missing", "unit: a GPU grant with no device nodes");
    for (const n of ctx.gpuNodes) if (!/^\/dev\/(nvidia[0-9a-z-]*|dri\/[a-zA-Z0-9]+)$/.test(n)) refuse("bad_form", "unit: a GPU node outside /dev/nvidia* or /dev/dri");
  }
}

/**
 * Render one agent's unit. `agent` is the grant agent (id = `agent.agent`, or `agent.id`); `ctx`:
 * { uid, release, cliPath, staged: [{ path, mode: "rw"|"ro", staging }], gpuNodes?, hostInfo? }.
 * Returns { name, text, contract, landlock, digest, root } (digest: sha256 hex of text and landlock, for the audit record).
 */
export function renderUnit(grantAgent, ctx) {
  const agent = { ...grantAgent, id: grantAgent.id ?? grantAgent.agent };
  checkInput(agent, ctx);
  const { id, config, root } = agent;
  const r = config.resources;
  const contract = pathContract(agent, ctx);
  const fences = fenceFiles(id);
  const tmpfsMb = Math.max(64, Math.min(2048, Math.floor(r.memory_max_mb / 4)));
  const inodes = 1048576;
  const lines = [];
  const L = (k, v) => lines.push(`${k}=${v}`);

  lines.push("# Generated by the Sagebrush host supervisor from a signed grant. Do not edit.");
  if (root) lines.push("# ROOT AGENT (person-signed root: true): runs as uid 0; not isolated from the host; stop is best effort.");
  lines.push("[Unit]");
  L("Description", `Sagebrush agent ${id}`);
  // The stop fences (§3.3): systemd itself skips a start while any of these exists.
  L("ConditionPathExists", `!${fences.all}`);
  L("ConditionPathExists", `!${fences.agent}`);
  L("ConditionPathExists", `!${fences.expiry}`);
  L("StartLimitIntervalSec", "300");
  L("StartLimitBurst", "5");
  lines.push("");
  lines.push("[Service]");
  L("Type", "simple");
  L("Slice", AGENT_SLICE);
  // The launcher contract's `exec` (sha256 147ec4e3…): it reads its contract at CONTRACT_IN_VIEW, then execs the pinned CLI.
  L("ExecStart", `${safePath(ctx.release, "the release path")}/bin/sagebrush-agent-launch exec --agent ${id} --contract ${CONTRACT_IN_VIEW} --cli ${safePath(ctx.cliPath, "the CLI path")}`);
  L("Restart", "on-failure");
  L("RestartSec", "5");
  L("KillMode", "control-group");
  L("TimeoutStopSec", "10");
  L("Delegate", "no");
  // Identity (a root agent: uid 0; tag groups would add nothing to root)
  L("User", root ? "root" : agentUser(id));
  L("Group", root ? "root" : agentUser(id));
  if (!root && agent.tags.length) L("SupplementaryGroups", agent.tags.map(tagGroup).join(" "));
  L("KeyringMode", "private");
  L("UMask", "0077");
  // Privilege (not for a root agent, §4.5)
  if (!root) {
    L("NoNewPrivileges", "yes");
    L("CapabilityBoundingSet", "");
    L("AmbientCapabilities", "");
    L("RestrictSUIDSGID", "yes");
    L("SecureBits", "noroot-locked");
  }
  // Filesystem view (§4.6): system paths read-only; /srv, /run hidden except the contract's binds.
  L("ProtectSystem", "strict");
  L("ProtectHome", "yes");
  L("TemporaryFileSystem", "/srv/sagebrush:ro");
  L("TemporaryFileSystem", "/run:ro");
  // /var/lib hidden too (freeze §4.6: everything under /run, /srv, /home, /root and /var/lib that isn't bound is
  // absent). Bind sources below are resolved in the host's mount namespace, so /var/lib/sagebrush/... still binds.
  L("TemporaryFileSystem", "/var/lib:ro");
  L("TemporaryFileSystem", `/tmp:size=${tmpfsMb}M,nr_inodes=${inodes},mode=1777`);
  L("TemporaryFileSystem", `/dev/shm:size=${tmpfsMb}M,nr_inodes=${inodes},mode=1777`);
  for (const row of contract) {
    if (row.mount === "rw") L("BindPaths", row.source === row.path ? row.path : `${row.source}:${row.path}`);
    else if (row.mount === "ro" && row.source) L("BindReadOnlyPaths", `${row.source}:${row.path}`);
  }
  // Temp and IPC
  L("PrivateIPC", "yes");
  // Proc and kernel
  L("ProtectProc", "invisible");
  L("ProcSubset", "all");
  for (const k of ["ProtectKernelTunables", "ProtectKernelModules", "ProtectKernelLogs", "ProtectControlGroups", "ProtectClock", "ProtectHostname", "LockPersonality", "RestrictRealtime"]) L(k, "yes");
  // Namespaces (not for a root agent, §4.5) and syscalls
  if (!root) L("RestrictNamespaces", "yes");
  L("SystemCallArchitectures", "native");
  L("SystemCallFilter", "@system-service");
  L("SystemCallFilter", `~${SYSCALL_DENY.join(" ")}`);
  // Devices
  if (config.gpu) {
    L("DevicePolicy", "closed");
    for (const n of ctx.gpuNodes) L("DeviceAllow", `${n} rw`);
  } else {
    L("PrivateDevices", "yes");
  }
  // Network (§5.1)
  L("NetworkNamespacePath", `/run/netns/${agentNetns(id)}`);
  L("RestrictAddressFamilies", "AF_UNIX AF_INET AF_INET6 AF_NETLINK");
  // Core dumps
  L("LimitCORE", "0");
  // Resources (§5.4)
  L("MemoryHigh", `${Math.floor((r.memory_max_mb * 5) / 6)}M`);
  L("MemoryMax", `${r.memory_max_mb}M`);
  L("MemorySwapMax", "0");
  L("TasksMax", String(r.tasks_max));
  L("CPUWeight", String(r.cpu_weight));
  if (r.cpu_quota_pct !== null) L("CPUQuota", `${r.cpu_quota_pct}%`);
  L("IOWeight", String(r.io_weight));
  L("LimitNOFILE", String(r.nofile));
  // Secrets: by credential, never Environment= (§4.2)
  L("LoadCredential", `broker-placeholder:${CREDS(id)}/broker-placeholder`);
  L("LoadCredential", `workspace-capability:${CREDS(id)}/workspace-capability`);
  const text = `${lines.join("\n")}\n`;
  if (/^Environment(File)?=/m.test(text)) refuse("bad_form", "unit: Environment= is never rendered"); // (defence: no code path writes it)
  if (/^User=root$/m.test(text) !== root) refuse("bad_form", "unit: User=root exactly when the grant says root"); // (defence)
  const landlock = landlockRules(contract);
  const digest = createHash("sha256").update(text).update("\0").update(JSON.stringify(landlock)).digest("hex");
  return { name: agentUnit(id), text, contract, landlock, digest, root };
}

/** The fixed environment the launcher passes to the CLI (contract file "env"; names from launcher/src/contract.rs). */
function launcherEnv(agent, net) {
  const env = [["HOME", agentHome(agent.id)], ["PATH", "/usr/local/bin:/usr/bin:/bin"], ["LANG", "C.UTF-8"], ["SAGEBRUSH_AGENT", agent.id]];
  if (net?.launcherEnv) for (const k of ["HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY"]) env.push([k, net.launcherEnv[k]]);
  return env;
}

/**
 * The launcher's contract file (launcher/src/contract.rs): { v: 1, agent, rules, staged, env }. `rules` are the path
 * contract's Landlock column; `staged` comes from stage-bind's records ({ index, path, mode, dev: [maj, min], ino }),
 * one per granted path, each also a rule; `net` is planNetwork's result (its launcherEnv for an allowlist agent).
 * Returns the exact bytes to write at CONTRACT(agent).
 */
export function launcherContract(grantAgent, ctx, records, net) {
  const agent = { ...grantAgent, id: grantAgent.id ?? grantAgent.agent };
  const rules = landlockRules(pathContract(agent, ctx)).rules.map((r) => ({ path: r.path, access: r.access }));
  const staged = records.map((r, i) => {
    if (!Number.isSafeInteger(r.index) || r.index < 0 || r.index > 63 || !rules.some((x) => x.path === r.path)) refuse("bad_form", "unit: a staged record outside the contract");
    if (!["rw", "ro"].includes(r.mode) || !Array.isArray(r.dev) || r.dev.length !== 2 || !Number.isSafeInteger(r.ino)) refuse("bad_form", "unit: a malformed staged record");
    return { index: r.index, path: r.path, mode: r.mode, dev: [r.dev[0], r.dev[1]], ino: r.ino, _i: i };
  }).map(({ _i, ...r }) => r);
  return `${JSON.stringify({ v: 1, agent: agent.id, rules, staged, env: launcherEnv(agent, net) })}\n`;
}
