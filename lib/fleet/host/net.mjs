// Host supervisor (design: agent-autonomous-host-supervisor-freeze-r3.1.md §5.1): the per-agent network plan. From one
// grant agent and its uid it derives, deterministically and as data (never shell text):
// - the steps that build its network namespace (`sb-<id>`) and, unless the mode is `none`, one veth pair whose agent
//   end is renamed `eth0` inside the namespace;
// - its addresses: a /30 from 10.250.0.0/16 chosen by uid (host side .1, agent side .2), so every agent's address is
//   distinct and derivable;
// - its nftables rules, in the host's `inet sagebrush` table, enforced at the host side of its veth;
// - its resolv.conf, and (allowlist) the proxy's allow list.
//
// Policy, per mode:
// - none: lo only. No veth, no egress, no DNS. The broker stays reachable by its Unix socket.
// - allowlist: only TCP to the gateway's proxy port. No DNS from the agent (the proxy resolves the listed names
//   itself), so DNS can't carry data out either. Everything else from the veth is dropped.
// - full: NATed egress, except the always-blocked set: link-local (incl. the metadata service), loopback, this host's
//   own addresses, every agent subnet, CGNAT, multicast, reserved, and the private ranges unless a grant's lan_allow
//   lists an exception. DNS only to the gateway resolver. Nothing else reaches the host.
// IPv6 egress is not provided in v1: the namespace's eth0 gets no IPv6 address and the host drops IPv6 from the veth.

import { isIPv4 } from "node:net";
import { isId, refuse } from "../bytes.mjs";
import { checkLanCidr } from "./config.mjs";
import { UID_RANGE } from "./registry.mjs";
import { agentNetns } from "./names.mjs";

export const AGENT_NET = "10.250.0.0/16";
export const PROXY_PORT = 3128;
const BASE = 10 * 2 ** 24 + 250 * 2 ** 16;

const ip = (n) => [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");

/** The always-blocked IPv4 destinations for `full` (and, by construction, for everything else). */
export const BLOCKED_V4 = Object.freeze([
  "0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10", "224.0.0.0/4", "240.0.0.0/4", AGENT_NET,
]);
export const PRIVATE_V4 = Object.freeze(["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]);

/**
 * The host's `inet sagebrush` table, created once before any agent's rules. Forwarding defaults to DROP, so a packet
 * from an agent veth that no agent chain accepts is never routed. Input keeps the host's own default (agent veths are
 * judged by their own chains, which end in drop); postrouting holds the agents' masquerade rules.
 */
export function baseTable() {
  return [
    "add table inet sagebrush",
    "add chain inet sagebrush input { type filter hook input priority 0 ; policy accept ; }",
    "add chain inet sagebrush forward { type filter hook forward priority 0 ; policy drop ; }",
    "add chain inet sagebrush postrouting { type nat hook postrouting priority 100 ; policy accept ; }",
    "",
  ].join("\n");
}

/** Interface names: Linux allows 15 characters. The index is uid - 70000 (0–9999), so names are at most 8. */
export function vethNames(uid) {
  if (!Number.isSafeInteger(uid) || uid < UID_RANGE[0] || uid > UID_RANGE[1]) refuse("bad_form", "net: uid outside the agent range");
  const n = uid - UID_RANGE[0];
  return { host: `sbv${n}`, peer: `sbp${n}`, index: n };
}

/** The agent's /30: { net, host (gateway), agent }. */
export function addresses(uid) {
  const { index } = vethNames(uid);
  const base = BASE + 4 * index;
  return { net: `${ip(base)}/30`, host: ip(base + 1), agent: ip(base + 2), prefix: 30 };
}

/**
 * Plan one agent's network. `agent`: the grant agent ({ agent | id, config }); `ctx`: { uid, hostAddrs: [ipv4…] }.
 * Returns { netns, mode, veth?, addr?, steps, nft, resolv, proxy? }.
 */
export function planNetwork(grantAgent, ctx) {
  const id = grantAgent.id ?? grantAgent.agent;
  if (!isId(id)) refuse("bad_form", "net: bad agent id");
  const { mode, allow, lan_allow } = grantAgent.config.network;
  if (!["none", "allowlist", "full"].includes(mode)) refuse("bad_form", "net: unknown mode");
  const hostAddrs = ctx.hostAddrs ?? [];
  if (!Array.isArray(hostAddrs) || !hostAddrs.every((a) => isIPv4(a))) refuse("bad_form", "net: host addresses must be IPv4");
  if (mode !== "full" && lan_allow.length) refuse("bad_form", "net: lan_allow is only for full");
  if (mode !== "allowlist" && allow.length) refuse("bad_form", "net: allow is only for allowlist");
  lan_allow.forEach(checkLanCidr);
  const netns = agentNetns(id);
  const steps = [
    { op: "netns-add", netns },
    { op: "link-up", netns, dev: "lo" },
    { op: "sysctl", netns, key: "net.ipv6.conf.all.disable_ipv6", value: "1" },
  ];
  if (mode === "none") {
    return { netns, mode, steps, nft: "", resolv: "# no network for this agent\n" };
  }
  const veth = vethNames(ctx.uid);
  const addr = addresses(ctx.uid);
  steps.push(
    { op: "veth-add", host: veth.host, peer: veth.peer },
    { op: "link-netns", dev: veth.peer, netns },
    { op: "link-rename", netns, dev: veth.peer, to: "eth0" },
    { op: "addr-add", dev: veth.host, addr: `${addr.host}/${addr.prefix}` },
    { op: "addr-add", netns, dev: "eth0", addr: `${addr.agent}/${addr.prefix}` },
    { op: "link-up", dev: veth.host },
    { op: "link-up", netns, dev: "eth0" },
    { op: "route-default", netns, via: addr.host },
  );
  const v = veth.host;
  const lines = [];
  // Every packet from this veth is judged by this agent's chains; nothing falls through to a permissive default.
  lines.push(`add chain inet sagebrush in_${veth.index}`);
  lines.push(`add chain inet sagebrush fwd_${veth.index}`);
  lines.push(`add rule inet sagebrush input iifname "${v}" jump in_${veth.index}`);
  lines.push(`add rule inet sagebrush forward iifname "${v}" jump fwd_${veth.index}`);
  lines.push(`add rule inet sagebrush forward oifname "${v}" ct state established,related accept`);
  lines.push(`add rule inet sagebrush forward oifname "${v}" drop`);
  lines.push(`add rule inet sagebrush in_${veth.index} meta nfproto ipv6 drop`);
  lines.push(`add rule inet sagebrush fwd_${veth.index} meta nfproto ipv6 drop`);
  lines.push(`add rule inet sagebrush in_${veth.index} ip saddr != ${addr.agent} drop`); // no spoofing another source
  lines.push(`add rule inet sagebrush fwd_${veth.index} ip saddr != ${addr.agent} drop`);
  if (mode === "allowlist") {
    lines.push(`add rule inet sagebrush in_${veth.index} ip daddr ${addr.host} tcp dport ${PROXY_PORT} accept`);
    lines.push(`add rule inet sagebrush in_${veth.index} drop`);
    lines.push(`add rule inet sagebrush fwd_${veth.index} drop`);
  } else {
    lines.push(`add rule inet sagebrush in_${veth.index} ip daddr ${addr.host} udp dport 53 accept`);
    lines.push(`add rule inet sagebrush in_${veth.index} ip daddr ${addr.host} tcp dport 53 accept`);
    lines.push(`add rule inet sagebrush in_${veth.index} drop`);
    for (const d of [...BLOCKED_V4, ...hostAddrs.map((a) => `${a}/32`)]) lines.push(`add rule inet sagebrush fwd_${veth.index} ip daddr ${d} drop`);
    for (const c of lan_allow) lines.push(`add rule inet sagebrush fwd_${veth.index} ip daddr ${c} accept`);
    for (const d of PRIVATE_V4) lines.push(`add rule inet sagebrush fwd_${veth.index} ip daddr ${d} drop`);
    lines.push(`add rule inet sagebrush fwd_${veth.index} accept`);
    lines.push(`add rule inet sagebrush postrouting ip saddr ${addr.agent} oifname != "${v}" masquerade`);
  }
  const nft = `${lines.join("\n")}\n`;
  const resolv = mode === "full" ? `nameserver ${addr.host}\noptions edns0\n` : "# no DNS: names are resolved by the proxy\n";
  const out = { netns, mode, veth, addr, steps, nft, resolv };
  if (mode === "allowlist") {
    out.proxy = { listen: `${addr.host}:${PROXY_PORT}`, agent: id, allow: [...allow].sort() };
    // Not secrets, but the unit never carries Environment= (§4.2): the launcher exports these into the CLI.
    out.launcherEnv = { HTTPS_PROXY: `http://${addr.host}:${PROXY_PORT}`, HTTP_PROXY: `http://${addr.host}:${PROXY_PORT}`, NO_PROXY: "" };
  }
  return out;
}
