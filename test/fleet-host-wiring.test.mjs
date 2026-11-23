// Host supervisor freeze r3.1 §3.3: the production effects assembled from the host store. The lookup reads the current
// grant and the registry; the assembled fx has every effect the executor calls (read from executor.mjs itself, so the
// two can't drift apart); provisioning takes each tag's gid from the registry.
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import { join } from "node:path";
import { test } from "./host-linux-only.mjs";
import { FleetError } from "../lib/fleet/index.mjs";
import { planNetwork } from "../lib/fleet/host/net.mjs";
import { hostEffects, storeLookup } from "../lib/fleet/host/wiring.mjs";

const A = "abcdefghijklmnopqrstuvwxya", B = "bbbbbbbbbbbbbbbbbbbbbbbbbe", T1 = "tagtagtagtagtagtagtagtagaa";
const host = (e) => !(e instanceof FleetError) && e.code === "effect_failed";
const config = (mode = "full") => ({
  files: { rw: [], ro: [] }, network: { mode, allow: [], lan_allow: [] }, programs: "run", mcp_allow: null, gpu: false,
  resources: { memory_max_mb: 6144, tasks_max: 4096, cpu_weight: 100, cpu_quota_pct: 200, io_weight: 100, disk_gb: 50, nofile: 65536 },
  wakes: [], turns: { per_day: 100, wall_s: 7200 },
});
const body = { gen: 3, agents: [{ agent: A, client: "claude", root: false, tags: [T1], config: config() }] };
const store = (over = {}) => ({
  grants: { currentBytes: () => Buffer.from(JSON.stringify(body)) },
  registry: { agent: (id) => (id === A ? { uid: 70007, state: "running" } : null), tag: (id) => (id === T1 ? { gid: 80003 } : null) },
  ...over,
});
const bodyOf = (bytes) => JSON.parse(Buffer.from(bytes).toString("utf8"));
const HOST = { release: "/opt/sagebrush/1.2.3", cliPath: { claude: "/opt/sagebrush/cli/claude-2.1.0" }, hostAddrs: ["10.128.0.5"], quota: null, hostInfo: { ramMb: 16384, cpus: 4 } };

test("the lookup: the agent's entry in the current grant, its registry uid (gid the same), and its network plan for this host", () => {
  const r = storeLookup({ store: store(), bodyOf, hostAddrs: HOST.hostAddrs })(A);
  assert.deepEqual(r.grantAgent, body.agents[0]);
  assert.deepEqual([r.uid, r.gid], [70007, 70007]);
  assert.deepEqual(r.net, planNetwork(body.agents[0], { uid: 70007, hostAddrs: HOST.hostAddrs }));
  assert.match(r.net.nft, /ip daddr 10\.128\.0\.5\/32 drop/, "the host's own address is in the plan");
  assert.throws(() => storeLookup({ store: store(), bodyOf })(B), host, "not in the grant");
  assert.throws(() => storeLookup({ store: store({ grants: { currentBytes: () => null } }), bodyOf })(A), host, "no current grant");
  assert.throws(() => storeLookup({ store: store({ registry: { agent: () => null, tag: () => null } }), bodyOf })(A), host, "no registry record");
  assert.throws(() => storeLookup({ store: {}, bodyOf }), (e) => e instanceof FleetError && e.code === "bad_form");
});

test("the assembled fx has every effect the executor calls", () => {
  const src = fs.readFileSync(new URL("../lib/fleet/host/executor.mjs", import.meta.url), "utf8");
  const used = [...new Set([...src.matchAll(/this\.fx\.([a-zA-Z]+)/g)].map((m) => m[1]))].sort();
  assert.ok(used.length >= 15, `found ${used.length}`);
  const adapters = Object.fromEntries(["appendIntent", "openIntents", "audit", "brokerGen", "brokerRevoke", "publishMap", "sendAck"].map((k) => [k, async () => {}]));
  const fx = hostEffects({ store: store(), bodyOf, host: HOST, adapters });
  for (const k of used) assert.ok(k in fx, `fx.${k}`);
  // Without the adapters, exactly the adapters are missing (they belong to other lanes).
  const bare = hostEffects({ store: store(), bodyOf, host: HOST });
  assert.deepEqual(used.filter((k) => !(k in bare)).sort(), Object.keys(adapters).filter((k) => used.includes(k)).sort());
});

test("provisioning through the wiring takes each tag's gid from the registry; a tag without one is host-side", async () => {
  const root = join(os.tmpdir(), `sb-wire-${process.pid}`);
  fs.rmSync(root, { recursive: true, force: true });
  fs.mkdirSync(join(root, "srv"), { recursive: true });
  const calls = [];
  const tree = (t) => JSON.stringify({ tree: t }); // the launcher's output is passed through to the record, parsed
  const run = async (argv) => {
    calls.push(argv);
    if (argv[1] === "inspect-home") return { code: 0, stdout: tree(argv.at(-1)), stderr: "" };
    return argv[0] === "getent" ? { code: 2, stdout: "", stderr: "" } : { code: 0, stdout: "", stderr: "" };
  };
  const fsx = { ...fs, chownSync: () => {} };
  const adopted = [];
  const st = store({ provisioned: { adopt: (...a) => { adopted.push(a); return "recorded"; } } });
  const fx = hostEffects({ store: st, bodyOf, host: HOST, run, fsx, root, rootUid: process.getuid?.() ?? 0 });
  await fx.provision(A, 70007, body.agents[0], 5000);
  assert.deepEqual(calls.find((c) => c[0] === "groupadd"), ["groupadd", "--gid", "80003", `sbt-${T1}`]);
  // The fixed parents are checked by the release's launcher, tolerant first, then strict (A1 r2.2).
  const launch = `${HOST.release}/bin/sagebrush-agent-launch`;
  const checks = calls.filter((c) => c[1] === "check-parents");
  assert.deepEqual(checks, [[launch, "check-parents", "--mount", "/", "--allow-missing"], [launch, "check-parents", "--mount", "/"]]);
  assert.equal(calls.indexOf(checks[0]), 0);
  // Then the trees' identity from the launcher, recorded (deprovision r3.2 §3.6): home, then config, after everything.
  const ins = calls.filter((c) => c[1] === "inspect-home");
  assert.deepEqual(ins, [[launch, "inspect-home", "--mount", "/", "--agent", A, "--tree", "home"], [launch, "inspect-home", "--mount", "/", "--agent", A, "--tree", "config"]]);
  assert.equal(calls.indexOf(ins[0]), calls.length - 2);
  assert.deepEqual(adopted, [[A, 70007, false, { tree: "home" }, { tree: "config" }]]);
  // A failing inspect, a non-JSON one, or a refused record: host-side.
  for (const [what, r2, adopt] of [
    ["inspect fails", async (argv) => (argv[1] === "inspect-home" ? { code: 73, stdout: "", stderr: "" } : run(argv)), () => "recorded"],
    ["inspect prints no JSON", async (argv) => (argv[1] === "inspect-home" ? { code: 0, stdout: "nope", stderr: "" } : run(argv)), () => "recorded"],
    ["the record refuses (a substitute)", run, () => { throw Object.assign(new Error("provisioned: another object in the same epoch"), { code: "bad_form" }); }],
  ]) {
    const f2 = hostEffects({ store: store({ provisioned: { adopt } }), bodyOf, host: HOST, run: r2, fsx, root, rootUid: process.getuid?.() ?? 0 });
    await assert.rejects(f2.provision(A, 70007, body.agents[0], 5000), host, what);
  }
  const none = hostEffects({ store: store({ registry: { agent: () => ({ uid: 70007 }), tag: () => null } }), bodyOf, host: HOST, run: async (argv) => ({ code: argv[1] === "check-parents" ? 0 : 2, stdout: "", stderr: "" }), root });
  await assert.rejects(none.provision(A, 70007, body.agents[0], 5000), host);
  fs.rmSync(root, { recursive: true, force: true });
});

test("the deprovision pass through the wiring: the executor's cgroup count, the whole-host uid proof under the same root; no broker adapter is host-side", async () => {
  const root = join(os.tmpdir(), `sb-wire-dp-${process.pid}`);
  fs.rmSync(root, { recursive: true, force: true });
  fs.mkdirSync(root, { recursive: true });
  const reg = { uid: 70007, gid: 70007, life: 1, gen: 3, state: "deleted" };
  const rec = { life: 1, gen: 3, uid: 70007, gid: 70007, policy: "archive", steps_done: [], identities: {}, done: false };
  const st = store({
    registry: { agent: (id) => (id === A ? reg : null), tag: () => null },
    deprovision: { ensure: () => structuredClone(rec) },
    pool: { names: () => false },
  });
  const calls = [];
  const run = async (argv) => { calls.push(argv); return { code: 0, stdout: "", stderr: "" }; };
  const adapters = { brokerRevoke: async () => { calls.push(["broker-revoke"]); } };
  const fx = hostEffects({ store: st, bodyOf, host: HOST, adapters, run, root });
  // No /proc under this root: the uid proof fails closed, so the pass parks before any step.
  assert.deepEqual(await fx.deprovision(A, 5000), { status: "pending", step: "channels", reason: "the uid can't be proven empty" });
  assert.ok(calls.some((c) => c[0] === "systemctl" && c[1] === "show" && c.at(-1).includes(A)), "the cgroup proof is the executor's procCount");
  assert.ok(!calls.some((c) => c[0] === "broker-revoke"));
  const bare = hostEffects({ store: st, bodyOf, host: HOST, run, root });
  await assert.rejects(bare.deprovision(A, 5000), host);
  fs.rmSync(root, { recursive: true, force: true });
});
