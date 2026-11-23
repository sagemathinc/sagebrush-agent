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
import { agentNetns, agentUser, brokerDir } from "./names.mjs";
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
/** Agent indices are uid - 70000: canonical decimal 0..9999 only (no leading zeros, nothing larger). */
const INDEX = "(0|[1-9][0-9]{0,3})";
const AGENT_CHAIN = new RegExp(`^(in|fwd)_${INDEX}$`);
const AGENT_COMMENT = new RegExp(`^sb-agent-${INDEX}$`);
/** The only kinds of object the table may hold (`nft -j` lists one per item). */
const ITEM_KINDS = new Set(["metainfo", "table", "chain", "rule"]);

/** A rule expression's match statements (meta keys and payload fields) and its verdicts, in order, from `nft -j`. */
function shape(expr) {
  const matches = [], verdicts = [];
  if (!Array.isArray(expr)) return { matches, verdicts, ok: false };
  for (const st of expr) {
    if (st?.match) {
      const { op, left, right } = st.match;
      const key = left?.meta ? `meta ${left.meta.key}` : left?.payload ? `${left.payload.protocol} ${left.payload.field}` : left?.ct ? `ct ${left.ct.key}` : null;
      matches.push({ key, op, right });
    } else {
      // Only verdicts besides matches: any other statement (counter, log, limit, set, …) isn't a generated rule.
      const keys = st && typeof st === "object" ? Object.keys(st) : [];
      if (keys.length !== 1 || !["jump", "goto", "accept", "drop", "masquerade", "reject", "return"].includes(keys[0])) return { matches, verdicts, ok: false };
      verdicts.push({ v: keys[0], target: st[keys[0]]?.target });
    }
  }
  return { matches, verdicts, ok: true };
}

/**
 * Is `rule` exactly a rule net.mjs generates for agent `n` in shared chain `chain`? Operator-aware and chain-specific:
 * - input / agent_ingress: `iifname == sbv<n>` (the only interface match) and a jump to its own in_<n> / fwd_<n>;
 * - agent_return: exactly `oifname == sbv<n>`, `ct state established,related`, accept; or `oifname == sbv<n>`, drop;
 * - postrouting: `ip saddr == <the agent's address>`, `oifname != sbv<n>`, and masquerade.
 */
function agentRule(chain, rule, n) {
  const { matches, verdicts, ok } = shape(rule.expr);
  if (!ok) return false;
  const veth = `sbv${n}`;
  const iface = matches.filter((m) => m.key === "meta iifname" || m.key === "meta oifname");
  // Each chain's exact match count (below) already rules out a second interface match.
  const only = (key, op) => iface[0]?.key === key && iface[0].op === op && iface[0].right === veth;
  const one = (v, target) => verdicts.length === 1 && verdicts[0].v === v && (target === undefined || verdicts[0].target === target);
  switch (chain) {
    case "input": return matches.length === 1 && only("meta iifname", "==") && one("jump", `in_${n}`);
    case "agent_ingress": return matches.length === 1 && only("meta iifname", "==") && one("jump", `fwd_${n}`);
    case "agent_return": {
      const ct = matches.filter((m) => m.key === "ct state");
      const established = ct.length === 1 && ct[0].op === "in" && JSON.stringify(ct[0].right) === JSON.stringify(["established", "related"]);
      return only("meta oifname", "==") && ((matches.length === 2 && established && one("accept")) || (matches.length === 1 && one("drop")));
    }
    case "postrouting": {
      const src = matches.filter((m) => m.key === "ip saddr");
      return matches.length === 2 && src.length === 1 && src[0].op === "==" && src[0].right === addresses(UID_RANGE[0] + n).agent
        && only("meta oifname", "!=") && one("masquerade");
    }
    default: return false;
  }
}

/**
 * Validate the whole `inet sagebrush` table in a parsed `nft -a -j list table inet sagebrush` listing, and return its
 * chains and rules. Exactly net.mjs's base:
 * - the five fixed chains, the hooked ones with exactly their type, hook, priority and policy (forward: drop);
 * - in `forward`, exactly the two jumps, agent_ingress then agent_return, and nothing else;
 * - in the shared chains, only agent rules: each with an agent's comment and exactly the shape net.mjs generates for
 *   that agent in that chain (agentRule: operators, its own veth, jump target, NAT source);
 * - every other chain an agent's own (in_<n> or fwd_<n>) carrying that agent's comment.
 * Anything else (a foreign rule or chain, a missing or differing base chain) refuses: the table is never adopted or
 * repaired here; changing it is a separate step with the host stopped.
 */
export function validateTable(listing) {
  const items = listing?.nftables;
  if (!Array.isArray(items)) throw hostFail("the nft listing isn't the JSON schema");
  // A set, map, flowtable, named counter, quota, limit, ct helper or any other object: not ours to keep.
  for (const i of items) {
    const kinds = i && typeof i === "object" ? Object.keys(i) : [];
    if (kinds.length !== 1 || !ITEM_KINDS.has(kinds[0])) throw hostFail(`an unexpected nft object (${kinds.join(",") || "none"})`);
  }
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
    if (!m || !agentRule(r.chain, r, Number(m[1]))) throw hostFail(`a foreign rule in ${r.chain}`);
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
 * registry, or null). Returns { brokerDirFor, applyNetwork, removeNetwork }.
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
   * Tear down the agent's namespace `netns` and its veth, but only what is provably ours (step 1 of applyNetwork, and
   * deprovision's network step).
   */
  const teardown = async (netns, uid, left, signal) => {
    const { host } = vethNames(uid);
    // 1. Tear down, but only what is provably ours: BOTH objects are inspected before either is deleted, so a mixed
    //    state (an owned-looking namespace next to a foreign link with the agent's veth name) is left wholly untouched.
    //    - the namespace sb-<id>: exactly one real loopback `lo` (loopback addresses only), and at most an `eth0` that
    //      is a veth with no address or this agent's (a build makes nothing else);
    //    - a host link sbv<n>: a veth with no address or this agent's gateway address, whose peer is EITHER this agent's
    //      sbp<n> in the host namespace (a build interrupted between veth-add and link-netns) OR exactly that
    //      namespace's eth0 (a finished build: the peer's namespace id and ifindex match). Deleting the namespace removes
    //      a pair of the second kind; only the first is deleted on its own.
    let nsList;
    try { nsList = JSON.parse((await must(["ip", "-j", "netns", "list"], left, signal)).stdout || "[]"); } catch (e) {
      if (e?.code === "effect_failed") throw e;
      throw hostFail("ip's namespace list isn't JSON");
    }
    const nsEntry = Array.isArray(nsList) ? nsList.find((n) => n?.name === netns) : null;
    const hasNs = Boolean(nsEntry);
    let eth0 = null;
    if (hasNs) {
      const inside = await must(["ip", "-n", netns, "-d", "-j", "addr", "show"], left, signal);
      let links;
      try { links = JSON.parse(inside.stdout); } catch { throw hostFail("ip's namespace listing isn't JSON"); }
      const addrsOf = (l) => (Array.isArray(l?.addr_info) ? l.addr_info : []).map((x) => x?.local);
      const isLo = (l) => l?.ifname === "lo" && l?.link_type === "loopback" && addrsOf(l).every((x) => x === "127.0.0.1" || x === "::1");
      const isEth0 = (l) => l?.ifname === "eth0" && l?.linkinfo?.info_kind === "veth" && addrsOf(l).every((x) => x === addresses(uid).agent);
      const ours = Array.isArray(links) && links.filter(isLo).length === 1 && links.filter(isEth0).length <= 1
        && links.every((l) => isLo(l) || isEth0(l));
      if (!ours) throw hostFail(`${netns} exists and isn't this agent's namespace`);
      eth0 = links.find(isEth0) ?? null;
    }
    const link = await run(["ip", "-d", "-j", "addr", "show", "dev", host], { ms: left(), signal });
    let hasLink = false;
    if (link.code === 0) {
      let info;
      try { info = JSON.parse(link.stdout); } catch { throw hostFail("ip's link listing isn't JSON"); }
      const l = Array.isArray(info) && info.length === 1 ? info[0] : null;
      const addrs = (Array.isArray(l?.addr_info) ? l.addr_info : []).map((x) => x?.local);
      const peerHere = l?.link === vethNames(uid).peer && l?.link_netnsid === undefined;
      const peerInOurNs = hasNs && eth0 !== null && Number.isSafeInteger(nsEntry.id) && l?.link_netnsid === nsEntry.id && l?.link_index === eth0.ifindex;
      if (!l || l.ifname !== host || l.linkinfo?.info_kind !== "veth" || !(peerHere || peerInOurNs) || !addrs.every((x) => x === addresses(uid).host)) {
        throw hostFail(`${host} exists and isn't this agent's veth`);
      }
      hasLink = peerHere; // a pair peered into our namespace goes with it
    } else if (!/does not exist/i.test(link.stderr)) throw hostFail("ip can't list the agent's veth");
    if (hasNs) await must(["ip", "netns", "del", netns], left, signal);
    if (hasLink) await must(["ip", "link", "del", "dev", host], left, signal);
  };

  /** The agent's nft rules replaced by `planNft` ("" removes them): one transaction, the whole table validated first. */
  const replaceRules = async (index, planNft, left, signal, { create = true } = {}) => {
    dir("/run/sagebrush", rootUid, rootUid, 0o755);
    dir(NFT_DIR, rootUid, rootUid, 0o700);
    const base = await run(["nft", "list", "table", "inet", "sagebrush"], { ms: left(), signal });
    if (base.code !== 0) {
      if (!create) return; // no table: no rules of this agent to remove
      writeDurable(at(NFT_DIR), "base.nft", baseTable());
      await must(["nft", "-f", at(join(NFT_DIR, "base.nft"))], left, signal);
    }
    let listing;
    try { listing = JSON.parse((await must(["nft", "-a", "-j", "list", "table", "inet", "sagebrush"], left, signal)).stdout); } catch (e) {
      if (e?.code === "effect_failed") throw e;
      throw hostFail("the nft listing isn't JSON");
    }
    const tx = replaceTransaction(listing, index, planNft);
    if (tx === "") return;
    const name = `agent-${index}.nft`;
    writeDurable(at(NFT_DIR), name, tx);
    await must(["nft", "-f", at(join(NFT_DIR, name))], left, signal);
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
    await teardown(plan.netns, uid, left, signal);
    // 2. Build.
    for (const argv of build) await must(argv, left, signal);
    // 3. nftables: the base table if missing, then one transaction replacing this agent's rules.
    await replaceRules(vethNames(uid).index, plan.nft, left, signal);
  };

  /**
   * Deprovision's network step (deprovision r3.2 §3.3): the namespace and veth torn down through the same identity
   * checks, then the agent's nft rules removed by one transaction (an empty plan) after the whole table is validated.
   */
  const removeNetwork = async (agent, uid, left, signal) => {
    if (!isId(agent)) throw hostFail("bad agent id");
    if (!Number.isSafeInteger(uid) || uid < UID_RANGE[0] || uid > UID_RANGE[1]) throw hostFail("a uid outside the agent range");
    await teardown(agentNetns(agent), uid, left, signal);
    await replaceRules(vethNames(uid).index, "", left, signal, { create: false });
  };

  return { brokerDirFor, applyNetwork, removeNetwork };
}
