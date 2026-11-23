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
/** An agent's network namespace (§5.1). */
export const agentNetns = (agent) => `sb-${need(agent)}`;

export const SRV = "/srv/sagebrush";
/** An agent's directory, holding `home` and `var-tmp` (§4.6). */
export const agentDir = (agent) => `${SRV}/agents/${need(agent)}`;
export const agentHome = (agent) => `${agentDir(agent)}/home`;
export const agentVarTmp = (agent) => `${agentDir(agent)}/var-tmp`;
/** A tag's shared folder. */
export const tagDir = (tag) => `${SRV}/tags/${need(tag)}`;

/** The broker's per-agent socket directory, bound read-only at /run/sagebrush/self inside the unit (§5.2). */
export const brokerDir = (agent) => `/run/sagebrush/broker/${need(agent)}`;

export const FENCE_DIR = "/var/lib/sagebrush/fence";
/** The three fence files of an agent, one per cause (§3.3): each is lowered only by its own cause. */
export const fenceFiles = (agent) => ({
  all: `${FENCE_DIR}/all`,
  agent: `${FENCE_DIR}/${need(agent)}`,
  expiry: `${FENCE_DIR}/expiry`,
});
