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

/** A realistic `nft -a -j list table inet sagebrush`: the base chains, agent 7's chains and rules, agent 70's, and a
 * base rule. */
const listing = () => ({ nftables: [
  { metainfo: { version: "1.0.9", json_schema_version: 1 } },
  { table: { family: "inet", name: "sagebrush", handle: 1 } },
  ...["input", "forward", "postrouting", "agent_ingress", "agent_return", "in_7", "fwd_7", "in_70", "fwd_70"].map((name, i) => ({ chain: { family: "inet", table: "sagebrush", name, handle: 2 + i } })),
  { rule: { family: "inet", table: "sagebrush", chain: "forward", handle: 20, expr: [] } },
  { rule: { family: "inet", table: "sagebrush", chain: "input", handle: 21, comment: "sb-agent-7", expr: [] } },
  { rule: { family: "inet", table: "sagebrush", chain: "agent_ingress", handle: 22, comment: "sb-agent-7", expr: [] } },
  { rule: { family: "inet", table: "sagebrush", chain: "agent_return", handle: 23, comment: "sb-agent-7", expr: [] } },
  { rule: { family: "inet", table: "sagebrush", chain: "agent_return", handle: 24, comment: "sb-agent-7", expr: [] } },
  { rule: { family: "inet", table: "sagebrush", chain: "postrouting", handle: 25, comment: "sb-agent-7", expr: [] } },
  { rule: { family: "inet", table: "sagebrush", chain: "input", handle: 30, comment: "sb-agent-70", expr: [] } },
  { rule: { family: "inet", table: "sagebrush", chain: "in_7", handle: 40, expr: [] } },
] });

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
  assert.doesNotMatch(tx, /handle (20|30)\b/);
  assert.doesNotMatch(tx, /in_70|fwd_70/);
  // A move to `none` (an empty plan) still removes the old rules; nothing at all is "".
  assert.match(replaceTransaction(listing(), 7, ""), /^flush chain inet sagebrush in_7\n[\s\S]*delete chain inet sagebrush fwd_7\n$/);
  assert.equal(replaceTransaction({ nftables: [{ table: { family: "inet", name: "sagebrush" } }] }, 7, ""), "");
  assert.equal(replaceTransaction({ nftables: [] }, 7, "add x\n"), "add x\n");
  // Unusable listings are host-side; a bad index refuses.
  assert.throws(() => replaceTransaction({}, 7, ""), host);
  const noHandle = listing(); noHandle.nftables.find((i) => i.rule?.handle === 21).rule.handle = "21";
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
    if (argv.join(" ") === "ip netns list") return { code: 0, stdout: `${NS} (id: 3)\nsb-other (id: 4)\n`, stderr: "" };
    if (argv.join(" ").startsWith("ip link show")) return { code: 1, stdout: "", stderr: "" };
    if (argv.join(" ") === "nft -a -j list table inet sagebrush") return { code: 0, stdout: JSON.stringify(listing()), stderr: "" };
    return { code: 0, stdout: "", stderr: "" };
  };
  const owner = new Map();
  const fsx = { ...fs, chownSync: (p, u, g) => owner.set(p, [u, g]), lstatSync: (p) => { const st = fs.lstatSync(p); const o = owner.get(p); return o ? Object.assign(Object.create(Object.getPrototypeOf(st)), st, { uid: o[0], gid: o[1] }) : st; } };
  for (const p of ["run"]) owner.set(join(root, p), [0, 0]);
  return { root, calls, owner, rt: runtime({ run, fsx, root, rootUid: 0 }), fsx };
}
const left = () => 5000;
const line = (c) => c.join(" ");

test("applyNetwork: tear down first, build from the plan, then one nft transaction replacing this agent's rules", async () => {
  const s = setup({ "ip link show": () => ({ code: 0 }) }); // a host veth left by a crashed build
  const plan = planNetwork(ga("full"), { uid: UID, hostAddrs: [] });
  await s.rt.applyNetwork(A, UID, plan, left);
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
  const s = setup({ "nft list table inet sagebrush": () => ({ code: 1 }), "ip netns list": () => ({ code: 0, stdout: "sb-other\n" }) });
  await s.rt.applyNetwork(A, UID, planNetwork(ga("none"), { uid: UID }), left);
  const seqs = s.calls.map(line);
  assert.ok(!seqs.includes(`ip netns del ${NS}`));
  const nftF = s.calls.filter((c) => c[0] === "nft" && c[1] === "-f").map((c) => c[2]);
  assert.deepEqual(nftF, [join(s.root, NFT_DIR, "base.nft"), join(s.root, NFT_DIR, "agent-7.nft")], "base first; then the agent's old rules removed (mode none)");
  for (const m of ["ip netns add", "ip link add", "nft -f", "nft -a -j"]) {
    const f = setup({ [m]: () => ({ code: 2 }) });
    await assert.rejects(f.rt.applyNetwork(A, UID, planNetwork(ga("full"), { uid: UID, hostAddrs: [] }), left), host, m);
  }
  const j = setup({ "nft -a -j": () => ({ code: 0, stdout: "not json" }) });
  await assert.rejects(j.rt.applyNetwork(A, UID, planNetwork(ga("full"), { uid: UID, hostAddrs: [] }), left), host);
  await assert.rejects(setup().rt.applyNetwork(A, UID, { ...planNetwork(ga("full"), { uid: UID, hostAddrs: [] }), netns: "sb-other" }, left), host);
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
});
