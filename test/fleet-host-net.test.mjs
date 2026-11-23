// Host supervisor freeze r3.1 §5.1: the per-agent network plan. Golden nftables rules per mode; addresses distinct per
// uid; names within IFNAMSIZ; the always-blocked set before any lan_allow exception and the private ranges after it;
// no DNS and no forwarding in allowlist mode; none has no veth at all; bad inputs refused.
import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { test } from "./host-linux-only.mjs";
import { FleetError } from "../lib/fleet/index.mjs";
import { planNetwork, addresses, vethNames, baseTable, PROXY_PORT, BLOCKED_V4 } from "../lib/fleet/host/net.mjs";

const refused = (fn, code) => assert.throws(fn, (e) => e instanceof FleetError && e.code === code, code);
const A = "abcdefghijklmnopqrstuvwxya";
const agent = (network) => ({ agent: A, config: { network } });
const golden = (name, text) => {
  const url = new URL(`./fixtures/host/${name}`, import.meta.url);
  if (process.env.UPDATE_GOLDEN === "1") writeFileSync(url, text);
  assert.equal(text, readFileSync(url, "utf8"), name);
};

test("full: golden nft rules; blocked set, then lan_allow, then private ranges; DNS only to the gateway; masquerade", () => {
  const p = planNetwork(agent({ mode: "full", allow: [], lan_allow: ["192.168.1.0/24"] }), { uid: 70007, hostAddrs: ["10.128.0.5"] });
  golden("net-full.nft", p.nft);
  assert.equal(p.resolv, "nameserver 10.250.0.29\noptions edns0\n");
  const fwd = p.nft.split("\n").filter((l) => l.startsWith("add rule inet sagebrush fwd_7 "));
  const idx = (s) => fwd.findIndex((l) => l.includes(s));
  // Every always-blocked range, and the host's own address, come before the lan_allow accept; the private ranges after.
  for (const d of [...BLOCKED_V4, "10.128.0.5/32"]) assert.ok(idx(`ip daddr ${d} drop`) >= 0 && idx(`ip daddr ${d} drop`) < idx("ip daddr 192.168.1.0/24 accept"), d);
  for (const d of ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]) assert.ok(idx(`ip daddr ${d} drop`) > idx("ip daddr 192.168.1.0/24 accept"), d);
  assert.ok(idx("ip daddr 169.254.0.0/16 drop") >= 0, "the metadata service is in the blocked set");
  assert.equal(fwd.at(-1), "add rule inet sagebrush fwd_7 accept");
  assert.equal(p.proxy, undefined);
});

test("allowlist: golden nft rules; only the proxy port on the gateway; no DNS; nothing forwarded; proxy allow list", () => {
  const p = planNetwork(agent({ mode: "allowlist", allow: ["registry.npmjs.org", "github.com:443"], lan_allow: [] }), { uid: 70000, hostAddrs: [] });
  golden("net-allowlist.nft", p.nft);
  assert.doesNotMatch(p.nft, /dport 53/);
  assert.doesNotMatch(p.nft, /masquerade/);
  assert.match(p.nft, new RegExp(`in_0 ip daddr 10\\.250\\.0\\.1 tcp dport ${PROXY_PORT} accept`));
  assert.match(p.nft, /^add rule inet sagebrush fwd_0 drop$/m);
  assert.deepEqual(p.proxy, { listen: `10.250.0.1:${PROXY_PORT}`, agent: A, allow: ["github.com:443", "registry.npmjs.org"] });
  assert.equal(p.launcherEnv.HTTPS_PROXY, `http://10.250.0.1:${PROXY_PORT}`);
  assert.equal(p.resolv, "# no DNS: names are resolved by the proxy\n");
});

test("none: lo only, no veth, no rules, no DNS", () => {
  const p = planNetwork(agent({ mode: "none", allow: [], lan_allow: [] }), { uid: 70001 });
  assert.equal(p.nft, "");
  assert.equal(p.veth, undefined);
  assert.deepEqual(p.steps.map((s) => s.op), ["netns-add", "link-up", "sysctl"]);
  assert.equal(p.steps[0].netns, `sb-${A}`);
});

test("every mode drops IPv6 and spoofed sources, and judges every packet from its veth", () => {
  for (const mode of ["allowlist", "full"]) {
    const p = planNetwork(agent({ mode, allow: [], lan_allow: [] }), { uid: 70002 });
    for (const line of [
      'add rule inet sagebrush input iifname "sbv2" jump in_2', 'add rule inet sagebrush agent_ingress iifname "sbv2" jump fwd_2',
      "add rule inet sagebrush in_2 meta nfproto ipv6 drop", "add rule inet sagebrush fwd_2 meta nfproto ipv6 drop",
      "add rule inet sagebrush in_2 ip saddr != 10.250.0.10 drop", "add rule inet sagebrush fwd_2 ip saddr != 10.250.0.10 drop",
      'add rule inet sagebrush agent_return oifname "sbv2" drop', "add rule inet sagebrush in_2 drop",
    ]) assert.ok(p.nft.split("\n").includes(line), `${mode}: ${line}`);
  }
});

test("addresses and names: distinct per uid, inside 10.250.0.0/16, names within 15 characters", () => {
  const seen = new Set();
  for (const uid of [70000, 70001, 72047, 79999]) {
    const a = addresses(uid), v = vethNames(uid);
    assert.ok(!seen.has(a.agent)); seen.add(a.agent);
    assert.match(a.agent, /^10\.250\.\d+\.\d+$/);
    assert.ok(v.host.length <= 15 && v.peer.length <= 15);
  }
  assert.deepEqual(addresses(79999), { net: "10.250.156.60/30", host: "10.250.156.61", agent: "10.250.156.62", prefix: 30 });
  refused(() => vethNames(69999), "bad_form");
  refused(() => vethNames(80000), "bad_form");
});

test("refused: bad id, unknown mode, cross-mode lists, non-private lan_allow, non-IPv4 host addresses", () => {
  refused(() => planNetwork({ agent: "worker-1", config: { network: { mode: "none", allow: [], lan_allow: [] } } }, { uid: 70000 }), "bad_form");
  refused(() => planNetwork(agent({ mode: "open", allow: [], lan_allow: [] }), { uid: 70000 }), "bad_form");
  refused(() => planNetwork(agent({ mode: "allowlist", allow: [], lan_allow: ["10.0.0.0/8"] }), { uid: 70000 }), "bad_form");
  refused(() => planNetwork(agent({ mode: "full", allow: ["github.com"], lan_allow: [] }), { uid: 70000 }), "bad_form");
  refused(() => planNetwork(agent({ mode: "full", allow: [], lan_allow: ["8.8.8.0/24"] }), { uid: 70000 }), "bad_form");
  // fc00::/7 (the reviewer's row): refused, no plan returned.
  let plan = null;
  assert.throws(() => { plan = planNetwork(agent({ mode: "full", allow: [], lan_allow: ["fc00::/7"] }), { uid: 70000 }); }, (e) => e instanceof FleetError && e.code === "bad_form");
  assert.equal(plan, null);
  refused(() => planNetwork(agent({ mode: "full", allow: [], lan_allow: ["10.1.0.0/16", "fd12:3456::/32"] }), { uid: 70000 }), "bad_form");
  refused(() => planNetwork(agent({ mode: "full", allow: [], lan_allow: [] }), { uid: 70000, hostAddrs: ["fe80::1"] }), "bad_form");
  refused(() => planNetwork(agent({ mode: "full", allow: [], lan_allow: [] }), { uid: 70000, hostAddrs: ['1.2.3.4" accept'] }), "bad_form");
  refused(() => planNetwork(agent({ mode: "full", allow: [], lan_allow: [] }), { uid: 1000 }), "bad_form");
});

test("the base table: forwarding defaults to drop; input and postrouting exist for the agent chains", () => {
  golden("net-base.nft", baseTable());
  assert.match(baseTable(), /forward \{ type filter hook forward priority 0 ; policy drop ; \}/);
});

test("two agents, added in either order: no rule is added to the forward base chain; every agent's ingress dispatch is judged before any return accept", () => {
  const a = planNetwork({ agent: "aaaaaaaaaaaaaaaaaaaaaaaaaa", config: { network: { mode: "full", allow: [], lan_allow: [] } } }, { uid: 70001 });
  const b = planNetwork({ agent: "bbbbbbbbbbbbbbbbbbbbbbbbbe", config: { network: { mode: "allowlist", allow: [], lan_allow: [] } } }, { uid: 70002 });
  for (const order of [[a, b], [b, a]]) {
  const all = (baseTable() + order[0].nft + order[1].nft).split("\n").filter(Boolean);
  const forwardRules = all.filter((l) => l.startsWith("add rule inet sagebrush forward "));
  assert.deepEqual(forwardRules, ["add rule inet sagebrush forward jump agent_ingress", "add rule inet sagebrush forward jump agent_return"]);
  // Every ingress dispatch lives in agent_ingress, every return accept in agent_return, regardless of add order.
  assert.ok(all.filter((l) => / iifname "sbv\d+" jump fwd_/.test(l)).every((l) => l.includes(" agent_ingress ")));
  assert.ok(all.filter((l) => / ct state established,related accept/.test(l)).every((l) => l.includes(" agent_return ")));
  // Each agent chain ends in a verdict, so a packet from an agent veth never falls through to agent_return.
  for (const [p, n] of [[a, 1], [b, 2]]) assert.match(p.nft.split("\n").filter((l) => l.startsWith(`add rule inet sagebrush fwd_${n} `)).at(-1), / (accept|drop)$/);
  }
});
