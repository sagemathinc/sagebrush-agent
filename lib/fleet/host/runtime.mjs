// Host supervisor (design: agent-autonomous-host-supervisor-freeze-r3.1.md §5.1, §5.2): an agent's runtime host state,
// rebuilt at every start because /run, network namespaces and nftables rules don't survive a reboot:
// - its broker directory /run/sagebrush/broker/<id>: root:sb-<id> 0710 (§5.2; the broker lane owns the socket in it);
// - its network namespace, torn down first if it exists (with a host-side veth a crashed earlier build left behind: only
//   if `ip` reports it as a veth; any other object with that name refuses), then built from net.mjs's steps, each one
//   an `ip` argv. The plan is derived here from ONE validated source (the agent id, its uid and its grant entry), and
//   every argv is built before the first command, so a bad uid, an entry for another agent or an unbuildable plan
//   runs nothing, and the names torn down are always those of the plan that is built;
// - its nftables rules, replaced in ONE `nft -f` transaction, so there is never a moment with the old and new rules
//   mixed or with neither: the transaction deletes, by handle, the rules this agent added to the shared chains (they
//   carry its comment, net.mjs), flushes and deletes its own chains, then adds the new plan. The base table (net.mjs's
//   baseTable) is created first if it is missing. Forwarding defaults to drop, so a failed apply leaves the agent cut
//   off, never open.
// An agent is started only after it was stopped and masked, so tearing its namespace down never disturbs a running
// agent. Every command goes through effects.mjs's runArgv (argv only, bounded, owning its process group).

import fs from "node:fs";
import { join } from "node:path";
import { isId, refuse } from "../bytes.mjs";
import { agentUser, brokerDir } from "./names.mjs";
import { addresses, agentNftComment, baseTable, planNetwork, vethNames } from "./net.mjs";
import { UID_RANGE } from "./registry.mjs";
import { writeDurable } from "./store.mjs";

/** Where the generated nft transaction files are written (root-only) before `nft -f`. */
export const NFT_DIR = "/run/sagebrush/nft";
const BROKER_ROOT = "/run/sagebrush/broker";

const hostFail = (what) => Object.assign(new Error(`runtime: ${what}`), { code: "effect_failed" });

/** One net.mjs step as an `ip` argv; anything else refuses. */
export function ipArgv(step) {
  const ns = step.netns;
  const inNs = (args) => (ns ? ["ip", "-n", ns, ...args] : ["ip", ...args]);
  switch (step.op) {
    case "netns-add": return ["ip", "netns", "add", ns];
    case "link-up": return inNs(["link", "set", "dev", step.dev, "up"]);
    case "sysctl": return ["ip", "netns", "exec", ns, "sysctl", "-q", "-w", `${step.key}=${step.value}`];
    case "veth-add": return ["ip", "link", "add", step.host, "type", "veth", "peer", "name", step.peer];
    case "link-netns": return ["ip", "link", "set", "dev", step.dev, "netns", ns];
    case "link-rename": return inNs(["link", "set", "dev", step.dev, "name", step.to]);
    case "addr-add": return inNs(["addr", "add", step.addr, "dev", step.dev]);
    case "route-default": return inNs(["route", "add", "default", "via", step.via]);
    default: return refuse("bad_form", "runtime: unknown network step");
  }
}

/** The base table's fixed chains (net.mjs baseTable): hooked ones with their exact type, hook, priority and policy. */
const BASE_CHAINS = Object.freeze({
  input: { type: "filter", hook: "input", prio: 0, policy: "accept" },
  forward: { type: "filter", hook: "forward", prio: 0, policy: "drop" },
  postrouting: { type: "nat", hook: "postrouting", prio: 100, policy: "accept" },
  agent_ingress: null,
  agent_return: null,
});
/** The base chains agents add their (commented) rules to. */
const SHARED = new Set(["input", "agent_ingress", "agent_return", "postrouting"]);
const AGENT_CHAIN = /^(in|fwd)_([0-9]+)$/;
const AGENT_COMMENT = /^sb-agent-([0-9]+)$/;

/** The interface names a rule's expression matches on (meta iifname / oifname), in any position. */
function vethsIn(expr) {
  const names = [];
  const walk = (v) => {
    if (Array.isArray(v)) { v.forEach(walk); return; }
    if (!v || typeof v !== "object") return;
    const m = v.match;
    if (m && m.left?.meta && ["iifname", "oifname"].includes(m.left.meta.key)) names.push(m.right);
    for (const x of Object.values(v)) walk(x);
  };
  walk(expr);
  return names;
}

/**
 * Validate the whole `inet sagebrush` table in a parsed `nft -a -j list table inet sagebrush` listing, and return its
 * chains and rules. Exactly net.mjs's base:
 * - the five fixed chains, the hooked ones with exactly their type, hook, priority and policy (forward: drop);
 * - in `forward`, exactly the two jumps, agent_ingress then agent_return, and nothing else;
 * - in the shared chains, only agent rules: each with an agent's comment, matching only that agent's veth;
 * - every other chain an agent's own (in_<n> or fwd_<n>) carrying that agent's comment.
 * Anything else (a foreign rule or chain, a missing or differing base chain) refuses: the table is never adopted or
 * repaired here; changing it is a separate step with the host stopped.
 */
export function validateTable(listing) {
  const items = listing?.nftables;
  if (!Array.isArray(items)) throw hostFail("the nft listing isn't the JSON schema");
  const tables = items.filter((i) => i.table);
  if (tables.length !== 1 || tables[0].table.family !== "inet" || tables[0].table.name !== "sagebrush") throw hostFail("the listing isn't exactly the sagebrush table");
  const chains = new Map();
  for (const { chain: c } of items.filter((i) => i.chain)) {
    if (c.family !== "inet" || c.table !== "sagebrush" || chains.has(c.name)) throw hostFail("an unexpected chain");
    chains.set(c.name, c);
  }
  for (const [name, want] of Object.entries(BASE_CHAINS)) {
    const c = chains.get(name);
    if (!c) throw hostFail(`the base chain ${name} is missing`);
    if (want === null ? c.hook !== undefined : !(c.type === want.type && c.hook === want.hook && c.prio === want.prio && c.policy === want.policy)) {
      throw hostFail(`the base chain ${name} differs`);
    }
  }
  for (const [name, c] of chains) {
    if (name in BASE_CHAINS) continue;
    const m = AGENT_CHAIN.exec(name);
    if (!m || c.hook !== undefined || c.comment !== agentNftComment(Number(m[2]))) throw hostFail(`a foreign chain ${name}`);
  }
  const rules = items.filter((i) => i.rule).map((i) => i.rule);
  const fwd = rules.filter((r) => r.chain === "forward");
  const jumps = fwd.map((r) => (Array.isArray(r.expr) && r.expr.length === 1 && r.comment === undefined ? r.expr[0]?.jump?.target : null));
  if (JSON.stringify(jumps) !== JSON.stringify(["agent_ingress", "agent_return"])) throw hostFail("the forward chain isn't exactly the two jumps");
  for (const r of rules) {
    if (r.family !== "inet" || r.table !== "sagebrush" || !chains.has(r.chain)) throw hostFail("a rule outside the table's chains");
    if (!Number.isSafeInteger(r.handle)) throw hostFail("an nft rule without a usable handle");
    if (!SHARED.has(r.chain)) continue; // forward is checked above; an agent's own chain is that agent's
    const m = AGENT_COMMENT.exec(r.comment ?? "");
    const veths = m ? vethsIn(r.expr) : [];
    if (!m || veths.length === 0 || !veths.every((v) => v === `sbv${m[1]}`)) throw hostFail(`a foreign rule in ${r.chain}`);
  }
  return { chains, rules };
}

/**
 * The nft transaction that replaces agent `index`'s rules, from a parsed listing that validateTable accepts: delete
 * its rules in the shared chains by handle (they carry its comment and match only its veth), flush and delete its own
 * chains (they carry its comment), then add `planNft`. Returns "" when there is nothing to delete and nothing to add.
 */
export function replaceTransaction(listing, index, planNft) {
  if (!Number.isSafeInteger(index) || index < 0) refuse("bad_form", "runtime: bad agent index");
  const { chains, rules } = validateTable(listing);
  const comment = agentNftComment(index);
  const own = [`in_${index}`, `fwd_${index}`].filter((c) => chains.has(c));
  const lines = [];
  for (const c of own) lines.push(`flush chain inet sagebrush ${c}`);
  for (const r of rules) if (SHARED.has(r.chain) && r.comment === comment) lines.push(`delete rule inet sagebrush ${r.chain} handle ${r.handle}`);
  for (const c of own) lines.push(`delete chain inet sagebrush ${c}`);
  if (lines.length === 0 && planNft === "") return "";
  return `${lines.join("\n")}${lines.length ? "\n" : ""}${planNft}`;
}

/**
 * The runtime effects. Options: `run` (effects.mjs runArgv), `fsx` (node:fs), `root` (a filesystem prefix for tests),
 * `rootUid` (0), `hostAddrs` (this host's own IPv4 addresses, for net.mjs), `uidOf(agent)` (the agent's uid in the
 * registry, or null). Returns { brokerDirFor, applyNetwork }.
 */
export function runtime({ run, fsx = fs, root = "", rootUid = 0, hostAddrs = [], uidOf } = {}) {
  if (typeof run !== "function" || typeof uidOf !== "function") refuse("bad_form", "runtime: run and uidOf are required");
  const at = (p) => `${root}${p}`;
  const must = async (argv, left, signal) => {
    const r = await run(argv, { ms: left(), signal });
    if (r.code !== 0) throw hostFail(`${argv.slice(0, 3).join(" ")} exited ${r.code}`);
    return r;
  };

  /** A directory with exactly this owner, group and mode: made if missing, refused if it differs. */
  const dir = (p, uid, gid, mode) => {
    try { fsx.mkdirSync(at(p), { mode }); } catch (e) {
      if (e?.code !== "EEXIST") throw hostFail(`can't make ${p}`);
      const st = fsx.lstatSync(at(p));
      if (!st.isDirectory() || st.uid !== uid || st.gid !== gid || (st.mode & 0o7777) !== mode) throw hostFail(`${p} exists and differs`);
      return;
    }
    fsx.chownSync(at(p), uid, gid);
    fsx.chmodSync(at(p), mode);
  };

  /** §5.2: /run/sagebrush/broker/<id>, root:sb-<id> 0710 (its group is the agent's private group, gid = uid). */
  const brokerDirFor = (agent, gid) => {
    if (!isId(agent)) throw hostFail("bad agent id");
    // The group is the agent's own private group: in the agent range, and exactly its registry uid (never -1, which
    // chown would take as "leave unchanged", nor another agent's).
    if (!Number.isSafeInteger(gid) || gid < UID_RANGE[0] || gid > UID_RANGE[1] || uidOf(agent) !== gid) throw hostFail("a gid that isn't this agent's");
    dir("/run/sagebrush", rootUid, rootUid, 0o755);
    dir(BROKER_ROOT, rootUid, rootUid, 0o755);
    dir(brokerDir(agent), rootUid, gid, 0o710);
    return agentUser(agent);
  };

  /**
   * Rebuild the agent's namespace and replace its nft rules, from its uid and its grant entry. Everything (the plan, the
   * names torn down, every `ip` argv) is derived and checked before the first command.
   */
  const applyNetwork = async (agent, uid, grantAgent, left, signal) => {
    if (!isId(agent) || (grantAgent?.id ?? grantAgent?.agent) !== agent) throw hostFail("a grant entry for another agent");
    if (!Number.isSafeInteger(uid) || uid < UID_RANGE[0] || uid > UID_RANGE[1]) throw hostFail("a uid outside the agent range");
    let plan, build;
    try {
      plan = planNetwork(grantAgent, { uid, hostAddrs });
      build = plan.steps.map(ipArgv);
    } catch { throw hostFail("no network plan for this agent"); }
    const { host, index } = vethNames(uid);
    // 1. Tear down: the namespace (its veth end goes with it, and the pair with that), and a host-side veth that a
    //    build interrupted between veth-add and link-netns left in the host namespace: only a veth, never another object.
    const list = await must(["ip", "netns", "list"], left, signal);
    if (list.stdout.split("\n").some((l) => l.split(/\s+/)[0] === plan.netns)) {
      // Ours only if it holds nothing but what a build makes: lo, and an eth0 that is a veth. Anything else is
      // someone else's namespace with this name: refused, and left alone.
      const inside = await must(["ip", "-n", plan.netns, "-d", "-j", "addr", "show"], left, signal);
      let links;
      try { links = JSON.parse(inside.stdout); } catch { throw hostFail("ip's namespace listing isn't JSON"); }
      const addrsOf = (l) => (l?.addr_info ?? []).map((a) => a?.local);
      const ours = Array.isArray(links) && links.every((l) => (l?.ifname === "lo" && addrsOf(l).every((a) => a === "127.0.0.1" || a === "::1"))
        || (l?.ifname === "eth0" && l?.linkinfo?.info_kind === "veth" && addrsOf(l).every((a) => a === addresses(uid).agent)));
      if (!ours) throw hostFail(`${plan.netns} exists and isn't this agent's namespace`);
      await must(["ip", "netns", "del", plan.netns], left, signal);
    }
    const link = await run(["ip", "-d", "-j", "addr", "show", "dev", host], { ms: left(), signal });
    if (link.code === 0) {
      // Ours only as a build interrupted it: a veth whose peer is this agent's sbp<n> in the host namespace, with no
      // address or only this agent's gateway address.
      let info;
      try { info = JSON.parse(link.stdout); } catch { throw hostFail("ip's link listing isn't JSON"); }
      const l = Array.isArray(info) && info.length === 1 ? info[0] : null;
      const addrs = (l?.addr_info ?? []).map((a) => a?.local);
      if (!l || l.ifname !== host || l.linkinfo?.info_kind !== "veth" || l.link !== vethNames(uid).peer || !addrs.every((a) => a === addresses(uid).host)) {
        throw hostFail(`${host} exists and isn't this agent's veth`);
      }
      await must(["ip", "link", "del", "dev", host], left, signal);
    } else if (!/does not exist/i.test(link.stderr)) throw hostFail("ip can't list the agent's veth");
    // 2. Build.
    for (const argv of build) await must(argv, left, signal);
    // 3. nftables: the base table if missing, then one transaction replacing this agent's rules.
    dir("/run/sagebrush", rootUid, rootUid, 0o755);
    dir(NFT_DIR, rootUid, rootUid, 0o700);
    const base = await run(["nft", "list", "table", "inet", "sagebrush"], { ms: left(), signal });
    if (base.code !== 0) {
      writeDurable(at(NFT_DIR), "base.nft", baseTable());
      await must(["nft", "-f", at(join(NFT_DIR, "base.nft"))], left, signal);
    }
    let listing;
    try { listing = JSON.parse((await must(["nft", "-a", "-j", "list", "table", "inet", "sagebrush"], left, signal)).stdout); } catch (e) {
      if (e?.code === "effect_failed") throw e;
      throw hostFail("the nft listing isn't JSON");
    }
    const tx = replaceTransaction(listing, index, plan.nft);
    if (tx === "") return;
    const name = `agent-${index}.nft`;
    writeDurable(at(NFT_DIR), name, tx);
    await must(["nft", "-f", at(join(NFT_DIR, name))], left, signal);
  };

  return { brokerDirFor, applyNetwork };
}
