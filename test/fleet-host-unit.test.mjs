// Host supervisor freeze r3.1 §4.2, §4.3, §4.5, §4.6: the unit generator. A fixed agent renders byte-for-byte to the golden
// unit; every §4.2 directive is present; the stop fences are start conditions; secrets arrive only by LoadCredential;
// the mount view and the Landlock ruleset come from one contract; anything unsafe to render is refused.
import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { test } from "./host-linux-only.mjs";
import { FleetError } from "../lib/fleet/index.mjs";
import { renderUnit, pathContract, landlockRules, LANDLOCK_ABI, launcherContract, CONTRACT, CONTRACT_IN_VIEW } from "../lib/fleet/host/unit.mjs";

const refused = (fn, code) => assert.throws(fn, (e) => e instanceof FleetError && e.code === code, code);

// Fixed ids so the golden file is stable.
const A = "abcdefghijklmnopqrstuvwxya", T1 = "tagtagtagtagtagtagtagtagaa", T2 = "bbbbbbbbbbbbbbbbbbbbbbbbbe";
const config = () => ({
  files: { rw: ["/data/project"], ro: ["/data/reference"] },
  network: { mode: "allowlist", allow: ["github.com"], lan_allow: [] },
  programs: "run", mcp_allow: null, gpu: false,
  resources: { memory_max_mb: 6144, tasks_max: 4096, cpu_weight: 100, cpu_quota_pct: 200, io_weight: 100, disk_gb: 50, nofile: 65536 },
  wakes: [], turns: { per_day: 100, wall_s: 7200 },
});
const agent = (over = {}) => ({ agent: A, name: "worker-1", client: "claude", root: false, tags: [T1, T2], config: config(), ...over });
const ctx = (over = {}) => ({
  uid: 70000, release: "/opt/sagebrush/1.2.3", cliPath: "/opt/sagebrush/cli/claude-2.1.0",
  staged: [{ path: "/data/project", mode: "rw", staging: `/run/sagebrush/binds/${A}/0` }, { path: "/data/reference", mode: "ro", staging: `/run/sagebrush/binds/${A}/1` }],
  hostInfo: { ramMb: 16384, cpus: 4 }, ...over,
});

const GOLDEN = new URL("./fixtures/host/agent-unit.service", import.meta.url);

test("a fixed agent renders byte-for-byte to the golden unit (regenerate with UPDATE_GOLDEN=1, then review the diff)", () => {
  const { text, name } = renderUnit(agent(), ctx());
  assert.equal(name, `sagebrush-agent-${A}.service`);
  if (process.env.UPDATE_GOLDEN === "1") writeFileSync(GOLDEN, text);
  assert.equal(text, readFileSync(GOLDEN, "utf8"));
});

test("every required §4.2 directive is present, and the dangerous ones are absent", () => {
  const { text } = renderUnit(agent(), ctx());
  const has = (line) => assert.ok(text.split("\n").includes(line), line);
  for (const line of [
    `User=sb-${A}`, `Group=sb-${A}`, `SupplementaryGroups=sbt-${T1} sbt-${T2}`, "KeyringMode=private", "UMask=0077",
    "NoNewPrivileges=yes", "CapabilityBoundingSet=", "AmbientCapabilities=", "RestrictSUIDSGID=yes", "SecureBits=noroot-locked",
    "ProtectSystem=strict", "ProtectHome=yes", "TemporaryFileSystem=/srv/sagebrush:ro", "TemporaryFileSystem=/run:ro",
    "PrivateIPC=yes", "ProtectProc=invisible", "ProcSubset=all", "ProtectKernelTunables=yes", "ProtectKernelModules=yes",
    "ProtectKernelLogs=yes", "ProtectControlGroups=yes", "ProtectClock=yes", "ProtectHostname=yes", "LockPersonality=yes",
    "RestrictRealtime=yes", "RestrictNamespaces=yes", "SystemCallArchitectures=native", "SystemCallFilter=@system-service",
    "SystemCallFilter=~@mount @swap @reboot @raw-io @module @obsolete @cpu-emulation @privileged", "PrivateDevices=yes",
    `NetworkNamespacePath=/run/netns/sb-${A}`, "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK", "LimitCORE=0",
    "Slice=sagebrush-agents.slice", "Delegate=no", "KillMode=control-group", "Restart=on-failure", "MemorySwapMax=0",
    "MemoryMax=6144M", "TasksMax=4096", "CPUQuota=200%", "LimitNOFILE=65536",
  ]) has(line);
  for (const bad of [/^Environment/m, /^MemoryDenyWriteExecute/m, /^PAMName/m, /^PrivateTmp/m, /^User=root/m, /^AmbientCapabilities=.+/m, /^CapabilityBoundingSet=.+/m]) {
    assert.doesNotMatch(text, bad);
  }
});

test("the three stop fences are start conditions (§3.3), one per cause", () => {
  const { text } = renderUnit(agent(), ctx());
  const conds = text.split("\n").filter((l) => l.startsWith("ConditionPathExists="));
  assert.deepEqual(conds, [
    "ConditionPathExists=!/var/lib/sagebrush/fence/all",
    `ConditionPathExists=!/var/lib/sagebrush/fence/${A}`,
    "ConditionPathExists=!/var/lib/sagebrush/fence/expiry",
  ]);
});

test("secrets arrive only by LoadCredential", () => {
  const { text } = renderUnit(agent(), ctx());
  assert.deepEqual(text.split("\n").filter((l) => l.startsWith("LoadCredential=")), [
    `LoadCredential=broker-placeholder:/var/lib/sagebrush/creds/${A}/broker-placeholder`,
    `LoadCredential=workspace-capability:/var/lib/sagebrush/creds/${A}/workspace-capability`,
  ]);
});

test("one contract: every bind comes from a contract row and every Landlock rule matches its row", () => {
  const out = renderUnit(agent(), ctx());
  const binds = out.text.split("\n").filter((l) => /^Bind(ReadOnly)?Paths=/.test(l));
  const fromContract = out.contract.flatMap((r) => r.mount === "rw" ? [`BindPaths=${r.source === r.path ? r.path : `${r.source}:${r.path}`}`]
    : r.mount === "ro" && r.source ? [`BindReadOnlyPaths=${r.source}:${r.path}`] : []);
  assert.deepEqual(binds, fromContract);
  assert.equal(out.landlock.abi, LANDLOCK_ABI);
  assert.deepEqual(out.landlock, landlockRules(out.contract));
  const ll = Object.fromEntries(out.landlock.rules.map((r) => [r.path, r.access]));
  // Granted paths: rw is rwx, ro is rx; staged handles are the bind sources, never the original names.
  assert.equal(ll["/data/project"], "rwx");
  assert.equal(ll["/data/reference"], "rx");
  assert.ok(binds.includes(`BindPaths=/run/sagebrush/binds/${A}/0:/data/project`));
  assert.ok(binds.includes(`BindReadOnlyPaths=/run/sagebrush/binds/${A}/1:/data/reference`));
  // Landlock reads cover what the tools need (§4.6): /proc, /sys, /dev, the credentials dir, the broker dir, resolv.conf.
  for (const p of ["/proc", "/sys", "/dev", `/run/credentials/sagebrush-agent-${A}.service`, "/run/sagebrush/self", "/etc/resolv.conf"]) assert.ok(ll[p], p);
  assert.equal(ll["/etc"], "r"); // /etc read only, never execute
  // The agent's own home and its tags are rwx; nothing of another agent appears.
  assert.equal(ll[`/srv/sagebrush/agents/${A}/home`], "rwx");
  assert.equal(ll[`/srv/sagebrush/tags/${T1}`], "rwx");
  assert.equal(Object.keys(ll).filter((p) => p.startsWith("/srv/sagebrush/agents/") && !p.includes(A)).length, 0);
});

test("the managed settings file follows the client", () => {
  const claude = renderUnit(agent(), ctx()).text;
  assert.match(claude, new RegExp(`^BindReadOnlyPaths=/var/lib/sagebrush/managed/${A}/managed-settings.json:/etc/claude-code/managed-settings.json$`, "m"));
  const codex = renderUnit(agent({ client: "codex" }), ctx()).text;
  assert.match(codex, new RegExp(`^BindReadOnlyPaths=/var/lib/sagebrush/managed/${A}/managed_config.toml:/etc/codex/managed_config.toml$`, "m"));
});

test("GPU: closed device policy with exactly the listed nodes; refused without nodes or with nodes outside /dev/nvidia* or /dev/dri", () => {
  const c = config(); c.gpu = true;
  const text = renderUnit(agent({ config: c }), ctx({ gpuNodes: ["/dev/nvidia0", "/dev/nvidiactl", "/dev/dri/renderD128"] })).text;
  assert.match(text, /^DevicePolicy=closed$/m);
  assert.deepEqual(text.split("\n").filter((l) => l.startsWith("DeviceAllow=")), ["DeviceAllow=/dev/nvidia0 rw", "DeviceAllow=/dev/nvidiactl rw", "DeviceAllow=/dev/dri/renderD128 rw"]);
  assert.doesNotMatch(text, /^PrivateDevices=/m);
  refused(() => renderUnit(agent({ config: c }), ctx()), "preflight_missing");
  refused(() => renderUnit(agent({ config: c }), ctx({ gpuNodes: ["/dev/sda"] })), "bad_form");
  refused(() => renderUnit(agent({ config: c }), ctx({ gpuNodes: ["/dev/nvidia0 rw\nUser=root"] })), "bad_form");
});

test("refused: anything that could break out of a unit line", () => {
  const withPaths = (rw, staged) => { const c = config(); c.files = { rw, ro: [] }; return [agent({ config: c }), ctx({ staged })]; };
  for (const bad of ["/data/a b", "/data/a\nUser=root", "/data/a:b", "/data/a\tb", "/data/é"]) {
    const [a, x] = withPaths([bad], [{ path: bad, mode: "rw", staging: `/run/sagebrush/binds/${A}/0` }]);
    assert.throws(() => renderUnit(a, x), (e) => e instanceof FleetError && e.code === "bad_form", JSON.stringify(bad));
  }
  refused(() => renderUnit(agent(), ctx({ release: "/opt/sagebrush/1 2" })), "bad_form");
  refused(() => renderUnit(agent(), ctx({ release: "/opt//sagebrush/1.2.3" })), "bad_form");
  refused(() => renderUnit(agent(), ctx({ cliPath: "/opt/cli\nExecStartPre=/bin/sh" })), "bad_form");
});

test("refused: staged binds that don't match the grant exactly, or that sit outside this agent's staging directory", () => {
  refused(() => renderUnit(agent(), ctx({ staged: [] })), "preflight_missing");
  refused(() => renderUnit(agent(), ctx({ staged: [...ctx().staged, { path: "/data/extra", mode: "rw", staging: `/run/sagebrush/binds/${A}/2` }] })), "preflight_missing");
  refused(() => renderUnit(agent(), ctx({ staged: [{ ...ctx().staged[0], mode: "ro" }, ctx().staged[1]] })), "preflight_missing");
  refused(() => renderUnit(agent(), ctx({ staged: [{ ...ctx().staged[0], staging: "/data/project" }, ctx().staged[1]] })), "bad_form");
  refused(() => renderUnit(agent(), ctx({ staged: [{ ...ctx().staged[0], staging: `/run/sagebrush/binds/${T1}/0` }, ctx().staged[1]] })), "bad_form");
});

test("refused: a root that isn't a boolean, an unknown client, bad ids, bad tags, a bad config", () => {
  for (const root of [undefined, null, "yes", 1, 0, "true"]) refused(() => renderUnit(agent({ root }), ctx()), "bad_form");
  refused(() => renderUnit(agent({ client: "gpt" }), ctx()), "bad_form");
  refused(() => renderUnit(agent({ agent: "worker-1" }), ctx()), "bad_form");
  refused(() => renderUnit(agent({ tags: [T1, T1] }), ctx()), "bad_form");
  refused(() => renderUnit(agent({ tags: ["x"] }), ctx()), "bad_form");
  const c = config(); c.files.rw = ["/etc/passwd"];
  refused(() => renderUnit(agent({ config: c }), ctx({ staged: [{ path: "/etc/passwd", mode: "rw", staging: `/run/sagebrush/binds/${A}/0` }, ctx().staged[1]] })), "bad_form");
  refused(() => renderUnit(agent(), ctx({ uid: undefined })), "bad_form");
});

test("the digest covers the unit text and the Landlock ruleset", async () => {
  const a = renderUnit(agent(), ctx()).digest;
  assert.equal(a, renderUnit(agent(), ctx()).digest); // deterministic
  const c = config(); c.resources.tasks_max = 4095;
  assert.notEqual(a, renderUnit(agent({ config: c }), ctx()).digest);
  assert.match(a, /^[0-9a-f]{64}$/);
  const out = renderUnit(agent(), ctx());
  const { createHash } = await import("node:crypto");
  assert.equal(out.digest, createHash("sha256").update(out.text).update("\0").update(JSON.stringify(out.landlock)).digest("hex"));
});

test("no CPUQuota line when the quota is null", () => {
  const c = config(); c.resources.cpu_quota_pct = null;
  assert.doesNotMatch(renderUnit(agent({ config: c }), ctx()).text, /^CPUQuota=/m);
});

test("pathContract hides other agents and lists the tags only of this agent", () => {
  const rows = pathContract({ ...agent(), id: A }, ctx());
  assert.equal(rows.filter((r) => r.path.startsWith("/srv/sagebrush/tags/")).length, 2);
});

// §4.5: a root agent's unit is the same unit with User=root and Group=root, and without the Privilege and Namespaces
// rows. Compared line by line with the non-root unit of the same grant, so a shared row can neither bring a dropped
// restriction back nor lose a retained one.
const GOLDEN_ROOT = new URL("./fixtures/host/agent-unit-root.service", import.meta.url);
const DROPPED = ["NoNewPrivileges=yes", "CapabilityBoundingSet=", "AmbientCapabilities=", "RestrictSUIDSGID=yes", "SecureBits=noroot-locked", "RestrictNamespaces=yes"];

test("a fixed root agent renders byte-for-byte to the golden root unit", () => {
  const out = renderUnit(agent({ root: true }), ctx());
  assert.equal(out.root, true);
  assert.equal(renderUnit(agent(), ctx()).root, false);
  if (process.env.UPDATE_GOLDEN === "1") writeFileSync(GOLDEN_ROOT, out.text);
  assert.equal(out.text, readFileSync(GOLDEN_ROOT, "utf8"));
});

test("root unit = the non-root unit minus exactly the Privilege and Namespaces rows, with uid 0 and no tag groups", () => {
  const plain = renderUnit(agent(), ctx()).text.split("\n");
  const root = renderUnit(agent({ root: true }), ctx()).text.split("\n");
  const swapped = plain
    .filter((l) => !DROPPED.includes(l) && !l.startsWith("SupplementaryGroups="))
    .map((l) => (l === `User=sb-${A}` ? "User=root" : l === `Group=sb-${A}` ? "Group=root" : l));
  const banner = "# ROOT AGENT (person-signed root: true): runs as uid 0; not isolated from the host; stop is best effort.";
  assert.deepEqual(root, [swapped[0], banner, ...swapped.slice(1)]);
  for (const l of DROPPED) assert.ok(plain.includes(l), l);
  // Retained, named explicitly: the fences, the mount view, the syscall filter, the netns, the resources, the secrets.
  for (const l of [`ConditionPathExists=!/var/lib/sagebrush/fence/all`, "ProtectSystem=strict", "TemporaryFileSystem=/srv/sagebrush:ro",
    "SystemCallFilter=~@mount @swap @reboot @raw-io @module @obsolete @cpu-emulation @privileged", "PrivateIPC=yes", "ProtectKernelModules=yes",
    `NetworkNamespacePath=/run/netns/sb-${A}`, "MemoryMax=6144M", "Delegate=no", "KillMode=control-group",
    `LoadCredential=broker-placeholder:/var/lib/sagebrush/creds/${A}/broker-placeholder`]) assert.ok(root.includes(l), l);
  assert.ok(!root.some((l) => /^Environment/.test(l)));
});

test("a root agent keeps the same path contract and Landlock ruleset; its digest differs from the non-root one", () => {
  const plain = renderUnit(agent(), ctx()), root = renderUnit(agent({ root: true }), ctx());
  assert.deepEqual(root.contract, plain.contract);
  assert.deepEqual(root.landlock, plain.landlock);
  assert.notEqual(root.digest, plain.digest);
});

test("a root agent with no tags and a GPU still renders, with no tag groups and the GPU device policy", () => {
  const c = config(); c.gpu = true;
  const { text } = renderUnit(agent({ root: true, tags: [], config: c }), ctx({ gpuNodes: ["/dev/nvidia0"] }));
  assert.match(text, /^User=root$/m);
  assert.match(text, /^DevicePolicy=closed$/m);
  assert.doesNotMatch(text, /^SupplementaryGroups=/m);
  assert.doesNotMatch(text, /^PrivateDevices=/m);
});

test("merged-usr: the path contract names no /bin, /sbin, /lib or /lib64 row (symlinks into /usr, refused by the launcher)", () => {
  const rows = pathContract({ ...agent(), id: A }, ctx());
  for (const p of ["/bin", "/sbin", "/lib", "/lib64"]) assert.ok(!rows.some((r) => r.path === p), p);
  assert.ok(rows.some((r) => r.path === "/usr" && r.landlock === "rx"), "/usr covers them");
});

test("freeze §4.6: /var/lib is hidden in the unit's view (closing part 3's gap), and the contract is bound at /run/sagebrush/contract.json", () => {
  const { text, contract } = renderUnit(agent(), ctx());
  const lines = text.split("\n");
  assert.ok(lines.includes("TemporaryFileSystem=/var/lib:ro"));
  assert.ok(lines.includes(`BindReadOnlyPaths=${CONTRACT(A)}:${CONTRACT_IN_VIEW}`));
  // Nothing under /var/lib is bound INTO the view: only used as a bind source.
  for (const l of lines.filter((x) => /^Bind(ReadOnly)?Paths=/.test(x))) {
    const target = l.split("=")[1].split(":").pop();
    assert.ok(!target.startsWith("/var/lib"), l);
  }
  const row = contract.find((r) => r.path === CONTRACT_IN_VIEW);
  assert.deepEqual([row.mount, row.landlock], ["ro", ""], "readable by the launcher before it restricts itself; no Landlock right");
  assert.ok(!landlockRules(contract).rules.some((r) => r.path === CONTRACT_IN_VIEW));
});

test("ExecStart is the launcher contract's exec, with the in-view contract and the pinned CLI", () => {
  const { text } = renderUnit(agent(), ctx());
  assert.ok(text.split("\n").includes(`ExecStart=/opt/sagebrush/1.2.3/bin/sagebrush-agent-launch exec --agent ${A} --contract ${CONTRACT_IN_VIEW} --cli /opt/sagebrush/cli/claude-2.1.0`));
});

test("launcherContract: the launcher's closed JSON (rules = the Landlock column, staged records, fixed env)", () => {
  const recs = [{ index: 0, path: "/data/project", mode: "rw", dev: [8, 1], ino: 42 }, { index: 1, path: "/data/reference", mode: "ro", dev: [8, 1], ino: 43 }];
  const doc = JSON.parse(launcherContract(agent(), ctx(), recs, null));
  assert.deepEqual(Object.keys(doc), ["v", "agent", "rules", "staged", "env"]);
  assert.equal(doc.v, 1);
  assert.deepEqual(doc.rules, landlockRules(pathContract({ ...agent(), id: A }, ctx())).rules.map((r) => ({ path: r.path, access: r.access })));
  assert.ok(!doc.rules.some((r) => ["/bin", "/sbin", "/lib", "/lib64", CONTRACT_IN_VIEW].includes(r.path)));
  assert.deepEqual(doc.staged, recs);
  assert.deepEqual(doc.env.map((e) => e[0]), ["HOME", "PATH", "LANG", "SAGEBRUSH_AGENT"]);
  const withProxy = JSON.parse(launcherContract(agent(), ctx(), recs, { launcherEnv: { HTTPS_PROXY: "http://10.250.0.1:3128", HTTP_PROXY: "http://10.250.0.1:3128", NO_PROXY: "" } }));
  assert.deepEqual(withProxy.env.slice(-3).map((e) => e[0]), ["HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY"]);
  refused(() => launcherContract(agent(), ctx(), [{ index: 0, path: "/elsewhere", mode: "rw", dev: [8, 1], ino: 1 }], null), "bad_form");
  refused(() => launcherContract(agent(), ctx(), [{ index: 64, path: "/data/project", mode: "rw", dev: [8, 1], ino: 1 }], null), "bad_form");
});
