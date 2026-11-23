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
  const run = async (argv) => { calls.push(argv); return argv[0] === "getent" ? { code: 2, stdout: "", stderr: "" } : { code: 0, stdout: "", stderr: "" }; };
  const fsx = { ...fs, chownSync: () => {} };
  const fx = hostEffects({ store: store(), bodyOf, host: HOST, run, fsx, root, rootUid: process.getuid?.() ?? 0 });
  await fx.provision(A, 70007, body.agents[0], 5000);
  assert.deepEqual(calls.find((c) => c[0] === "groupadd"), ["groupadd", "--gid", "80003", `sbt-${T1}`]);
  const none = hostEffects({ store: store({ registry: { agent: () => ({ uid: 70007 }), tag: () => null } }), bodyOf, host: HOST, run: async () => ({ code: 2, stdout: "", stderr: "" }), root });
  await assert.rejects(none.provision(A, 70007, body.agents[0], 5000), host);
  fs.rmSync(root, { recursive: true, force: true });
});
