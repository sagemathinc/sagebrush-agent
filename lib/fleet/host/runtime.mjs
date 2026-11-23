// Host supervisor (design: agent-autonomous-host-supervisor-freeze-r3.1.md §5.1, §5.2): an agent's runtime host state,
// rebuilt at every start because /run, network namespaces and nftables rules don't survive a reboot:
// - its broker directory /run/sagebrush/broker/<id>: root:sb-<id> 0710 (§5.2; the broker lane owns the socket in it);
// - its network namespace, torn down first if it exists (with a host-side veth a crashed earlier build left behind),
//   then built from net.mjs's steps, each one an `ip` argv;
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
import { agentNftComment, baseTable, vethNames } from "./net.mjs";
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

/**
 * The nft transaction that replaces agent `index`'s rules: from `listing` (the parsed `nft -a -j list table inet
 * sagebrush`), delete its shared-chain rules by handle and its own chains, then add `planNft`. Returns "" when there
 * is nothing to delete and nothing to add.
 */
export function replaceTransaction(listing, index, planNft) {
  if (!Number.isSafeInteger(index) || index < 0) refuse("bad_form", "runtime: bad agent index");
  const items = listing?.nftables;
  if (!Array.isArray(items)) throw hostFail("the nft listing isn't the JSON schema");
  const comment = agentNftComment(index);
  const own = new Set([`in_${index}`, `fwd_${index}`]);
  const lines = [];
  const chains = items.filter((i) => i.chain && i.chain.family === "inet" && i.chain.table === "sagebrush").map((i) => i.chain.name);
  for (const c of chains) if (own.has(c)) lines.push(`flush chain inet sagebrush ${c}`);
  for (const i of items) {
    const r = i.rule;
    if (!r || r.family !== "inet" || r.table !== "sagebrush" || r.comment !== comment) continue;
    if (!Number.isSafeInteger(r.handle) || typeof r.chain !== "string" || !/^[a-z_0-9]+$/.test(r.chain)) throw hostFail("an nft rule without a usable handle");
    lines.push(`delete rule inet sagebrush ${r.chain} handle ${r.handle}`);
  }
  for (const c of chains) if (own.has(c)) lines.push(`delete chain inet sagebrush ${c}`);
  if (lines.length === 0 && planNft === "") return "";
  return `${lines.join("\n")}${lines.length ? "\n" : ""}${planNft}`;
}

/**
 * The runtime effects. Options: `run` (effects.mjs runArgv), `fsx` (node:fs), `root` (a filesystem prefix for tests),
 * `rootUid` (0). Returns { brokerDirFor, applyNetwork }.
 */
export function runtime({ run, fsx = fs, root = "", rootUid = 0 } = {}) {
  if (typeof run !== "function") refuse("bad_form", "runtime: run is required");
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
    dir("/run/sagebrush", rootUid, rootUid, 0o755);
    dir(BROKER_ROOT, rootUid, rootUid, 0o755);
    dir(brokerDir(agent), rootUid, gid, 0o710);
    return agentUser(agent);
  };

  /** Rebuild the agent's namespace from `plan` (net.mjs planNetwork) and replace its nft rules. */
  const applyNetwork = async (agent, uid, plan, left, signal) => {
    if (!isId(agent) || plan?.netns !== `sb-${agent}`) throw hostFail("a network plan for another agent");
    // 1. Tear down: the namespace (its veth end goes with it, and the pair with that), and a host-side veth that a
    //    build interrupted between veth-add and link-netns left in the host namespace.
    const list = await must(["ip", "netns", "list"], left, signal);
    if (list.stdout.split("\n").some((l) => l.split(/\s+/)[0] === plan.netns)) await must(["ip", "netns", "del", plan.netns], left, signal);
    const { host } = vethNames(uid);
    const link = await run(["ip", "link", "show", "dev", host], { ms: left(), signal });
    if (link.code === 0) await must(["ip", "link", "del", "dev", host], left, signal);
    // 2. Build.
    for (const step of plan.steps) await must(ipArgv(step), left, signal);
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
    const index = vethNames(uid).index;
    const tx = replaceTransaction(listing, index, plan.nft);
    if (tx === "") return;
    const name = `agent-${index}.nft`;
    writeDurable(at(NFT_DIR), name, tx);
    await must(["nft", "-f", at(join(NFT_DIR, name))], left, signal);
  };

  return { brokerDirFor, applyNetwork };
}
