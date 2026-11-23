// Host supervisor freeze r3.1 §5.1, §5.2: an agent's runtime state, rebuilt at each start. A scripted runner stands in
// for `ip` and `nft`; the nft transaction is checked as text against a realistic `nft -a -j` listing.
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import { join } from "node:path";
import { test } from "./host-linux-only.mjs";
import { FleetError } from "../lib/fleet/index.mjs";
import { planNetwork } from "../lib/fleet/host/net.mjs";
import { NFT_DIR, ipArgv, replaceTransaction, runtime } from "../lib/fleet/host/runtime.mjs";

const A = "abcdefghijklmnopqrstuvwxya", UID = 70007, NS = `sb-${A}`;
const host = (e) => !(e instanceof FleetError) && e.code === "effect_failed";
const badForm = (e) => e instanceof FleetError && e.code === "bad_form";
const ga = (mode) => ({ agent: A, config: { network: { mode, allow: mode === "allowlist" ? ["github.com"] : [], lan_allow: [] } } });

/** A realistic, valid `nft -a -j list table inet sagebrush`: the exact base (its hooked chains, the two forward jumps),
 * agent 7's and agent 70's owned chains and their shared-chain rules (each matching only its own veth), and a rule
 * inside in_7. */
const meta = (key, right, op = "==") => ({ match: { op, left: { meta: { key } }, right } });
const listing = () => ({ nftables: [
  { metainfo: { version: "1.0.9", json_schema_version: 1 } },
  { table: { family: "inet", name: "sagebrush", handle: 1 } },
  { chain: { family: "inet", table: "sagebrush", name: "input", handle: 2, type: "filter", hook: "input", prio: 0, policy: "accept" } },
  { chain: { family: "inet", table: "sagebrush", name: "forward", handle: 3, type: "filter", hook: "forward", prio: 0, policy: "drop" } },
  { chain: { family: "inet", table: "sagebrush", name: "postrouting", handle: 4, type: "nat", hook: "postrouting", prio: 100, policy: "accept" } },
  { chain: { family: "inet", table: "sagebrush", name: "agent_ingress", handle: 5 } },
  { chain: { family: "inet", table: "sagebrush", name: "agent_return", handle: 6 } },
  ...[["in_7", 7], ["fwd_7", 7], ["in_70", 70], ["fwd_70", 70]].map(([name, n], i) => ({ chain: { family: "inet", table: "sagebrush", name, handle: 7 + i, comment: `sb-agent-${n}` } })),
  { rule: { family: "inet", table: "sagebrush", chain: "forward", handle: 18, expr: [{ jump: { target: "agent_ingress" } }] } },
  { rule: { family: "inet", table: "sagebrush", chain: "forward", handle: 19, expr: [{ jump: { target: "agent_return" } }] } },
  { rule: { family: "inet", table: "sagebrush", chain: "input", handle: 21, comment: "sb-agent-7", expr: [meta("iifname", "sbv7"), { jump: { target: "in_7" } }] } },
  { rule: { family: "inet", table: "sagebrush", chain: "agent_ingress", handle: 22, comment: "sb-agent-7", expr: [meta("iifname", "sbv7"), { jump: { target: "fwd_7" } }] } },
  { rule: { family: "inet", table: "sagebrush", chain: "agent_return", handle: 23, comment: "sb-agent-7", expr: [meta("oifname", "sbv7"), { accept: null }] } },
  { rule: { family: "inet", table: "sagebrush", chain: "agent_return", handle: 24, comment: "sb-agent-7", expr: [meta("oifname", "sbv7"), { drop: null }] } },
  { rule: { family: "inet", table: "sagebrush", chain: "postrouting", handle: 25, comment: "sb-agent-7", expr: [meta("oifname", "sbv7", "!="), { masquerade: null }] } },
  { rule: { family: "inet", table: "sagebrush", chain: "input", handle: 30, comment: "sb-agent-70", expr: [meta("iifname", "sbv70"), { jump: { target: "in_70" } }] } },
  { rule: { family: "inet", table: "sagebrush", chain: "in_7", handle: 40, expr: [{ drop: null }] } },
] });
const withItems = (f) => { const l = listing(); f(l.nftables); return l; };
/** What `ip -n sb-<id> -d -j addr show` lists for a namespace a build made (eth0's ifindex 2). */
const OUR_NS = [{ ifindex: 1, ifname: "lo", link_type: "loopback", addr_info: [{ local: "127.0.0.1" }] },
  { ifindex: 2, ifname: "eth0", link_type: "ether", linkinfo: { info_kind: "veth" }, addr_info: [{ local: "10.250.0.30" }] }];

test("each network step is one exact ip argv; an unknown step refuses", () => {
  const p = planNetwork(ga("full"), { uid: UID, hostAddrs: [] });
  assert.deepEqual(p.steps.map(ipArgv), [
    ["ip", "netns", "add", NS],
    ["ip", "-n", NS, "link", "set", "dev", "lo", "up"],
    ["ip", "netns", "exec", NS, "sysctl", "-q", "-w", "net.ipv6.conf.all.disable_ipv6=1"],
    ["ip", "link", "add", "sbv7", "type", "veth", "peer", "name", "sbp7"],
    ["ip", "link", "set", "dev", "sbp7", "netns", NS],
    ["ip", "-n", NS, "link", "set", "dev", "sbp7", "name", "eth0"],
    ["ip", "addr", "add", "10.250.0.29/30", "dev", "sbv7"],
    ["ip", "-n", NS, "addr", "add", "10.250.0.30/30", "dev", "eth0"],
    ["ip", "link", "set", "dev", "sbv7", "up"],
    ["ip", "-n", NS, "link", "set", "dev", "eth0", "up"],
    ["ip", "-n", NS, "route", "add", "default", "via", "10.250.0.29"],
  ]);
  assert.throws(() => ipArgv({ op: "exec", netns: NS }), badForm);
});

test("the nft transaction deletes exactly this agent's rules by handle and its own chains, then adds the plan", () => {
  const tx = replaceTransaction(listing(), 7, "add chain inet sagebrush in_7\n");
  assert.equal(tx, [
    "flush chain inet sagebrush in_7", "flush chain inet sagebrush fwd_7",
    "delete rule inet sagebrush input handle 21", "delete rule inet sagebrush agent_ingress handle 22",
    "delete rule inet sagebrush agent_return handle 23", "delete rule inet sagebrush agent_return handle 24",
    "delete rule inet sagebrush postrouting handle 25",
    "delete chain inet sagebrush in_7", "delete chain inet sagebrush fwd_7",
    "add chain inet sagebrush in_7", "",
  ].join("\n"));
  // Agent 70's rules and the base rule are untouched (the comment is matched exactly, never as a prefix).
  assert.doesNotMatch(tx, /handle (18|19|30|40)\b/);
  assert.doesNotMatch(tx, /in_70|fwd_70/);
  // A move to `none` (an empty plan) still removes the old rules; nothing at all is "".
  assert.match(replaceTransaction(listing(), 7, ""), /^flush chain inet sagebrush in_7\n[\s\S]*delete chain inet sagebrush fwd_7\n$/);
  const base = withItems((it) => { for (let i = it.length - 1; i >= 0; i--) if (it[i].rule?.comment || it[i].chain?.comment || it[i].rule?.chain === "in_7") it.splice(i, 1); });
  assert.equal(replaceTransaction(base, 7, ""), "");
  assert.equal(replaceTransaction(base, 7, "add x\n"), "add x\n");
  // Unusable listings are host-side; a bad index refuses.
  assert.throws(() => replaceTransaction({}, 7, ""), host);
  const noHandle = withItems((it) => { it.find((i) => i.rule?.handle === 21).rule.handle = "21"; });
  assert.throws(() => replaceTransaction(noHandle, 7, ""), host);
  assert.throws(() => replaceTransaction(listing(), -1, ""), badForm);
});

let seq = 0;
function setup(over = {}) {
  const root = join(os.tmpdir(), `sb-rt-${process.pid}-${seq++}`);
  fs.rmSync(root, { recursive: true, force: true });
  fs.mkdirSync(join(root, "run"), { recursive: true });
  const calls = [];
  const run = async (argv, { ms }) => {
    assert.ok(ms > 0);
    calls.push(argv);
    for (const [m, fn] of Object.entries(over)) if (argv.join(" ").includes(m)) { const r = fn(argv); if (r) return { stdout: "", stderr: "", ...r }; }
    if (argv.join(" ") === "ip -j netns list") return { code: 0, stdout: JSON.stringify([{ name: NS, id: 3 }, { name: "sb-other", id: 4 }]), stderr: "" };
    if (argv.join(" ").startsWith("ip -d -j addr show dev")) return { code: 1, stdout: "", stderr: `Device "${argv.at(-1)}" does not exist.\n` };
    if (argv.join(" ") === `ip -n ${NS} -d -j addr show`) return { code: 0, stdout: JSON.stringify(OUR_NS), stderr: "" };
    if (argv.join(" ") === "nft -a -j list table inet sagebrush") return { code: 0, stdout: JSON.stringify(listing()), stderr: "" };
    return { code: 0, stdout: "", stderr: "" };
  };
  const owner = new Map();
  const fsx = { ...fs, chownSync: (p, u, g) => owner.set(p, [u, g]), lstatSync: (p) => { const st = fs.lstatSync(p); const o = owner.get(p); return o ? Object.assign(Object.create(Object.getPrototypeOf(st)), st, { uid: o[0], gid: o[1] }) : st; } };
  for (const p of ["run"]) owner.set(join(root, p), [0, 0]);
  return { root, calls, owner, rt: runtime({ run, fsx, root, rootUid: 0, hostAddrs: [], uidOf: (a) => (a === A ? UID : null) }), fsx };
}
const left = () => 5000;
const line = (c) => c.join(" ");

test("applyNetwork: tear down first, build from the plan, then one nft transaction replacing this agent's rules", async () => {
  // A host veth left by a crashed build: ip reports it as a veth.
  const s = setup({ "ip -d -j addr show dev": () => ({ code: 0, stdout: JSON.stringify([{ ifname: "sbv7", link: "sbp7", linkinfo: { info_kind: "veth" }, addr_info: [] }]) }) });
  const plan = planNetwork(ga("full"), { uid: UID, hostAddrs: [] });
  await s.rt.applyNetwork(A, UID, ga("full"), left);
  const seqs = s.calls.map(line);
  const del = seqs.indexOf(`ip netns del ${NS}`), vdel = seqs.indexOf("ip link del dev sbv7"), add = seqs.indexOf(`ip netns add ${NS}`);
  assert.ok(del >= 0 && vdel > del && add > vdel, "the namespace and the stray veth are removed before the build");
  assert.deepEqual(s.calls.slice(add, add + plan.steps.length), plan.steps.map(ipArgv));
  const nftF = s.calls.filter((c) => c[0] === "nft" && c[1] === "-f");
  assert.equal(nftF.length, 1, "the base table exists: only the agent's transaction");
  const file = join(s.root, NFT_DIR, "agent-7.nft");
  assert.deepEqual(nftF[0], ["nft", "-f", file]);
  assert.equal(fs.readFileSync(file, "utf8"), replaceTransaction(listing(), 7, plan.nft));
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  assert.equal(fs.statSync(join(s.root, NFT_DIR)).mode & 0o777, 0o700);
});

test("applyNetwork: a missing base table is created first; no namespace to remove is fine; a failing command stops it", async () => {
  const s = setup({ "nft list table inet sagebrush": () => ({ code: 1 }), "ip -j netns list": () => ({ code: 0, stdout: JSON.stringify([{ name: "sb-other", id: 4 }]) }) });
  await s.rt.applyNetwork(A, UID, ga("none"), left);
  const seqs = s.calls.map(line);
  assert.ok(!seqs.includes(`ip netns del ${NS}`));
  const nftF = s.calls.filter((c) => c[0] === "nft" && c[1] === "-f").map((c) => c[2]);
  assert.deepEqual(nftF, [join(s.root, NFT_DIR, "base.nft"), join(s.root, NFT_DIR, "agent-7.nft")], "base first; then the agent's old rules removed (mode none)");
  for (const m of ["ip netns add", "ip link add", "nft -f", "nft -a -j"]) {
    const f = setup({ [m]: () => ({ code: 2 }) });
    await assert.rejects(f.rt.applyNetwork(A, UID, ga("full"), left), host, m);
  }
  const j = setup({ "nft -a -j": () => ({ code: 0, stdout: "not json" }) });
  await assert.rejects(j.rt.applyNetwork(A, UID, ga("full"), left), host);
});

test("the broker directory: root:<agent group> 0710 under root-owned parents; one that differs is refused", () => {
  const s = setup();
  s.rt.brokerDirFor(A, UID);
  const st = s.fsx.lstatSync(join(s.root, `/run/sagebrush/broker/${A}`));
  assert.deepEqual([st.uid, st.gid, st.mode & 0o7777], [0, UID, 0o710]);
  const b = s.fsx.lstatSync(join(s.root, "/run/sagebrush/broker"));
  assert.deepEqual([b.uid, b.gid, b.mode & 0o7777], [0, 0, 0o755]);
  s.rt.brokerDirFor(A, UID); // again: unchanged, fine
  fs.chmodSync(join(s.root, `/run/sagebrush/broker/${A}`), 0o777);
  assert.throws(() => s.rt.brokerDirFor(A, UID), host);
  assert.throws(() => setup().rt.brokerDirFor("nope", UID), host);
  // The group must be this agent's own: in the range and its registry uid. -1, another range, another agent's: refused,
  // before anything is made.
  for (const gid of [-1, 0, 69999, 80000, 70008, "70007", 70007.5]) {
    const b = setup();
    assert.throws(() => b.rt.brokerDirFor(A, gid), host, String(gid));
    assert.equal(fs.existsSync(join(b.root, "/run/sagebrush/broker")), false, `${gid}: nothing made`);
  }
  assert.throws(() => runtime({ run: async () => ({}) }), badForm, "uidOf is required");
});

test("applyNetwork derives its plan from one validated source: a bad uid or another agent's entry runs ZERO commands", async () => {
  for (const [name, uid, entry] of [["uid below the range", 69999, ga("full")], ["uid above the range", 80000, ga("full")], ["a bad uid in mode none", 69999, ga("none")], ["not an integer", "70007", ga("full")],
    ["another agent's entry", UID, { ...ga("full"), agent: "bbbbbbbbbbbbbbbbbbbbbbbbbe" }], ["an unplannable entry", UID, { agent: A, config: { network: { mode: "open", allow: [], lan_allow: [] } } }]]) {
    const s = setup();
    await assert.rejects(s.rt.applyNetwork(A, uid, entry, left), host, name);
    assert.deepEqual(s.calls, [], `${name}: nothing ran`);
  }
  // The names torn down and the plan built always belong together: uid 70008 removes and builds sbv8, writes agent-8.
  const s = setup({ "ip -j netns list": () => ({ code: 0, stdout: "" }) });
  await s.rt.applyNetwork(A, 70008, ga("full"), left);
  const lines = s.calls.map((c) => c.join(" "));
  assert.ok(lines.includes("ip -d -j addr show dev sbv8"));
  assert.ok(lines.includes("ip link add sbv8 type veth peer name sbp8"));
  assert.ok(!lines.some((l) => /sbv7|sbp7/.test(l)));
  assert.match(fs.readFileSync(join(s.root, NFT_DIR, "agent-8.nft"), "utf8"), /^add chain inet sagebrush in_8 \{ comment "sb-agent-8" ; \}$/m);
});

test("a foreign link or namespace with the agent's name is refused and left alone", async () => {
  // A host link named like the agent's veth that isn't a veth (a bridge, say): refused, not deleted.
  for (const out of [[{ ifname: "sbv7", linkinfo: { info_kind: "bridge" } }], [{ ifname: "sbv7" }], [], "not json",
    [{ ifname: "sbv7", link: "sbp7", linkinfo: { info_kind: "bridge" }, addr_info: [] }], // right peer and address, not a veth
    [{ ifname: "sbv7", link: "eth9", linkinfo: { info_kind: "veth" }, addr_info: [] }], // another peer
    [{ ifname: "sbv7", link_netnsid: 4, linkinfo: { info_kind: "veth" }, addr_info: [] }], // its peer in some other namespace
    [{ ifname: "sbv7", link: "sbp7", linkinfo: { info_kind: "veth" }, addr_info: [{ local: "192.168.1.5" }] }]]) { // a foreign address
    const s = setup({ "ip -d -j addr show dev": () => ({ code: 0, stdout: typeof out === "string" ? out : JSON.stringify(out) }) });
    await assert.rejects(s.rt.applyNetwork(A, UID, ga("full"), left), host, JSON.stringify(out));
    assert.ok(!s.calls.some((c) => c.join(" ").startsWith("ip link del")), "nothing deleted");
    assert.ok(!s.calls.some((c) => c.join(" ").startsWith("ip link add")), "nothing built");
  }
  // ip failing for another reason than "does not exist": host-side, nothing deleted or built.
  const e = setup({ "ip -d -j addr show dev": () => ({ code: 1, stderr: "RTNETLINK answers: Operation not permitted\n" }) });
  await assert.rejects(e.rt.applyNetwork(A, UID, ga("full"), left), host);
  assert.ok(!e.calls.some((c) => /^ip (link (del|add)|netns add)/.test(c.join(" "))));
  // A namespace with this agent's name that holds anything but lo and a veth eth0: refused, not deleted.
  const LO = OUR_NS[0], ETH0 = OUR_NS[1];
  for (const links of [[LO, { ...ETH0, linkinfo: { info_kind: "macvlan" } }], [LO, { ifname: "wg0", linkinfo: { info_kind: "wireguard" } }],
    [LO, { ...ETH0, addr_info: [{ local: "10.250.0.34" }] }], // another agent's address
    [{ ...LO, addr_info: [{ local: "10.0.0.9" }] }],
    [], // empty: no loopback at all
    [ETH0], // eth0 without lo
    [LO, LO, ETH0], // a duplicate lo
    [{ ifname: "lo", link_type: "ether", addr_info: [] }, ETH0], // something named lo that isn't a loopback
    [LO, ETH0, ETH0]]) { // two eth0
    const s = setup({ [`ip -n ${NS} -d -j addr show`]: () => ({ code: 0, stdout: JSON.stringify(links) }) });
    await assert.rejects(s.rt.applyNetwork(A, UID, ga("full"), left), host, JSON.stringify(links));
    assert.ok(!s.calls.some((c) => c.join(" ") === `ip netns del ${NS}`), "the namespace is left alone");
  }
  // Ours (lo and a veth eth0, or only lo in mode none): torn down.
  const ok = setup();
  await ok.rt.applyNetwork(A, UID, ga("full"), left);
  assert.ok(ok.calls.some((c) => c.join(" ") === `ip netns del ${NS}`));
});

test("the base table is validated whole: any difference refuses, and nothing is applied", async () => {
  const cases = {
    "forward policy accept": (it) => { it.find((i) => i.chain?.name === "forward").chain.policy = "accept"; },
    "a wrong hook": (it) => { it.find((i) => i.chain?.name === "input").chain.hook = "output"; },
    "a wrong priority": (it) => { it.find((i) => i.chain?.name === "postrouting").chain.prio = 0; },
    "a missing base chain": (it) => { it.splice(it.findIndex((i) => i.chain?.name === "agent_return"), 1); },
    "a missing jump": (it) => { it.splice(it.findIndex((i) => i.rule?.handle === 19), 1); },
    "reordered jumps": (it) => { const a = it.findIndex((i) => i.rule?.handle === 18); [it[a], it[a + 1]] = [it[a + 1], it[a]]; },
    "an extra rule in forward": (it) => { it.push({ rule: { family: "inet", table: "sagebrush", chain: "forward", handle: 50, expr: [{ accept: null }] } }); },
    "a hooked agent_ingress": (it) => { Object.assign(it.find((i) => i.chain?.name === "agent_ingress").chain, { type: "filter", hook: "forward", prio: -1, policy: "accept" }); },
    "a foreign chain": (it) => { it.push({ chain: { family: "inet", table: "sagebrush", name: "admin", handle: 60 } }); },
    "an agent chain without its comment": (it) => { delete it.find((i) => i.chain?.name === "fwd_70").chain.comment; },
    "an agent chain with another agent's comment": (it) => { it.find((i) => i.chain?.name === "fwd_70").chain.comment = "sb-agent-7"; },
    "a foreign rule in input": (it) => { it.push({ rule: { family: "inet", table: "sagebrush", chain: "input", handle: 61, expr: [{ accept: null }] } }); },
    "our comment on a rule for another veth": (it) => { it.push({ rule: { family: "inet", table: "sagebrush", chain: "input", handle: 62, comment: "sb-agent-7", expr: [meta("iifname", "eth0"), { accept: null }] } }); },
    "our comment on a rule matching no veth": (it) => { it.push({ rule: { family: "inet", table: "sagebrush", chain: "postrouting", handle: 63, comment: "sb-agent-7", expr: [{ masquerade: null }] } }); },
    "another table": (it) => { it.find((i) => i.table).table.name = "other"; },
  };
  for (const [name, f] of Object.entries(cases)) {
    assert.throws(() => replaceTransaction(withItems(f), 7, "add x\n"), host, name);
    const s = setup({ "nft -a -j": () => ({ code: 0, stdout: JSON.stringify(withItems(f)) }) });
    await assert.rejects(s.rt.applyNetwork(A, UID, ga("full"), left), host, name);
    assert.ok(!s.calls.some((c) => c[0] === "nft" && c[1] === "-f"), `${name}: nothing applied`);
  }
  // The valid listing itself passes, and its own agent-70 objects are never touched by agent 7's transaction.
  assert.doesNotMatch(replaceTransaction(listing(), 7, ""), /_70|handle 30/);
});

test("a host veth peered into our own namespace (a finished build) is accepted; a mixed foreign state deletes nothing", async () => {
  // The steady state after a build: sbv7's peer is eth0 (ifindex 2) in namespace id 3. The namespace goes, taking it.
  const steady = [{ ifname: "sbv7", link_netnsid: 3, link_index: 2, linkinfo: { info_kind: "veth" }, addr_info: [{ local: "10.250.0.29" }] }];
  const s = setup({ "ip -d -j addr show dev": () => ({ code: 0, stdout: JSON.stringify(steady) }) });
  await s.rt.applyNetwork(A, UID, ga("full"), left);
  const lines = s.calls.map((c) => c.join(" "));
  assert.ok(lines.includes(`ip netns del ${NS}`));
  assert.ok(!lines.includes("ip link del dev sbv7"), "the pair goes with the namespace");
  // Peered into another namespace id, or another ifindex: refused, and NOTHING deleted (not even our namespace).
  for (const bad of [{ ...steady[0], link_netnsid: 4 }, { ...steady[0], link_index: 5 }]) {
    const t = setup({ "ip -d -j addr show dev": () => ({ code: 0, stdout: JSON.stringify([bad]) }) });
    await assert.rejects(t.rt.applyNetwork(A, UID, ga("full"), left), host);
    assert.ok(!t.calls.some((c) => /^ip (netns|link) del/.test(c.join(" "))), "zero deletes");
  }
  // The mixed case: an owned-looking namespace next to a foreign sbv7 (a bridge): both left untouched.
  const m = setup({ "ip -d -j addr show dev": () => ({ code: 0, stdout: JSON.stringify([{ ifname: "sbv7", link: "sbp7", linkinfo: { info_kind: "bridge" }, addr_info: [] }]) }) });
  await assert.rejects(m.rt.applyNetwork(A, UID, ga("full"), left), host);
  assert.ok(!m.calls.some((c) => /^ip (netns|link) del/.test(c.join(" "))), "zero deletes");
  // A namespace list that isn't JSON: host-side, nothing deleted.
  const j = setup({ "ip -j netns list": () => ({ code: 0, stdout: "sb-x (id: 1)" }) });
  await assert.rejects(j.rt.applyNetwork(A, UID, ga("full"), left), host);
});

test("only canonical agent indices 0..9999, and only chains and rules: anything else in the table refuses", async () => {
  const cases = {
    "a non-canonical chain in_07": (it) => { it.push({ chain: { family: "inet", table: "sagebrush", name: "in_07", handle: 70, comment: "sb-agent-7" } }); },
    "an out-of-range chain in_10000": (it) => { it.push({ chain: { family: "inet", table: "sagebrush", name: "in_10000", handle: 71, comment: "sb-agent-10000" } }); },
    "a non-canonical rule comment": (it) => { it.push({ rule: { family: "inet", table: "sagebrush", chain: "input", handle: 72, comment: "sb-agent-07", expr: [meta("iifname", "sbv07"), { accept: null }] } }); },
    "an out-of-range rule comment": (it) => { it.push({ rule: { family: "inet", table: "sagebrush", chain: "input", handle: 73, comment: "sb-agent-10000", expr: [meta("iifname", "sbv10000"), { accept: null }] } }); },
    "a named set": (it) => { it.push({ set: { family: "inet", table: "sagebrush", name: "allow", type: "ipv4_addr", handle: 74 } }); },
    "a map": (it) => { it.push({ map: { family: "inet", table: "sagebrush", name: "m", type: "ipv4_addr", map: "verdict", handle: 75 } }); },
    "a flowtable": (it) => { it.push({ flowtable: { family: "inet", table: "sagebrush", name: "ft", handle: 76 } }); },
    "a named counter": (it) => { it.push({ counter: { family: "inet", table: "sagebrush", name: "c", handle: 77 } }); },
    "an item of two kinds": (it) => { it.push({ chain: { family: "inet", table: "sagebrush", name: "x" }, set: {} }); },
    "an empty item": (it) => { it.push({}); },
  };
  for (const [name, f] of Object.entries(cases)) {
    assert.throws(() => replaceTransaction(withItems(f), 7, "add x\n"), host, name);
    const s = setup({ "nft -a -j": () => ({ code: 0, stdout: JSON.stringify(withItems(f)) }) });
    await assert.rejects(s.rt.applyNetwork(A, UID, ga("full"), left), host, name);
    assert.ok(!s.calls.some((c) => c[0] === "nft" && c[1] === "-f"), `${name}: nothing applied`);
  }
  // The highest canonical index is fine.
  const hi = withItems((it) => it.push({ chain: { family: "inet", table: "sagebrush", name: "in_9999", handle: 80, comment: "sb-agent-9999" } }));
  assert.match(replaceTransaction(hi, 9999, ""), /^flush chain inet sagebrush in_9999$/m);
});
