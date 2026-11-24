// Host supervisor freeze r3.1 §2.1 and §6.1: names derived only from ids, and the config_schema 1 validator: a valid
// config passes; each shape mistake and each cross-field or path rule is refused with bad_form.
import assert from "node:assert/strict";
import { test } from "./host-linux-only.mjs";
import { FleetError, newId } from "../lib/fleet/index.mjs";
import { HOST_FREEZE, validateConfig, checkGrantPath, checkLanCidr } from "../lib/fleet/host/config.mjs";
import { agentUser, tagGroup, agentUnit, agentNetns, agentHome, agentVarTmp, agentSessions, agentConfigDir, agentArchive, agentConfigArchive, tagDir, brokerDir, fenceFiles } from "../lib/fleet/host/names.mjs";

const refused = (fn, code = "bad_form") => assert.throws(fn, (e) => e instanceof FleetError && e.code === code);

const base = () => ({
  files: { rw: ["/data/project"], ro: ["/data/reference"] },
  network: { mode: "allowlist", allow: ["github.com", "registry.npmjs.org:443"], lan_allow: [] },
  programs: "run",
  mcp_allow: null,
  gpu: false,
  resources: { memory_max_mb: 4096, tasks_max: 4096, cpu_weight: 100, cpu_quota_pct: null, io_weight: 100, disk_gb: 50, nofile: 65536 },
  wakes: [{ kind: "every", every_s: 600 }, { kind: "message" }, { kind: "path", path: "/Course/status.md", poll_s: 60 }, { kind: "at", at_ms: 1 }],
  turns: { per_day: 100, wall_s: 7200 },
});
const with_ = (f) => { const c = base(); f(c); return c; };

test("the freeze pin is r3.1 7f51ec73…", () => {
  assert.equal(HOST_FREEZE.revision, "r3.1");
  assert.equal(HOST_FREEZE.sha256, "7f51ec735ca27968ebbb50dd3f21f765c9f203e04827fe3d50e8e3cb8fef1a12");
});

test("names: derived from the id, within Linux's 32-character user and group limit; a non-id is refused", () => {
  const a = newId(), t = newId();
  assert.equal(agentUser(a), `sb-${a}`);
  assert.equal(agentUser(a).length, 29);
  assert.equal(tagGroup(t), `sbt-${t}`);
  assert.equal(tagGroup(t).length, 30);
  assert.equal(agentUnit(a), `sagebrush-agent-${a}.service`);
  assert.equal(agentNetns(a), `sb-${a}`);
  assert.equal(agentHome(a), `/srv/sagebrush/agents/${a}/home`);
  assert.equal(agentVarTmp(a), `/srv/sagebrush/agents/${a}/var-tmp`);
  assert.equal(agentSessions(a), `/srv/sagebrush/agents/${a}/sessions`);
  assert.equal(agentConfigDir(a), `/srv/sagebrush/agent-config/${a}`);
  assert.equal(agentArchive(a), `/srv/sagebrush/archive/${a}`);
  assert.equal(agentConfigArchive(a), `/srv/sagebrush/archive-config/${a}`);
  assert.equal(tagDir(t), `/srv/sagebrush/tags/${t}`);
  assert.equal(brokerDir(a), `/run/sagebrush/broker/${a}`);
  assert.deepEqual(fenceFiles(a), { all: "/var/lib/sagebrush/fence/all", agent: `/var/lib/sagebrush/fence/${a}`, expiry: "/var/lib/sagebrush/fence/expiry", lease: `/var/lib/sagebrush/fence/lease/${a}` });
  for (const bad of ["worker-1", a.toUpperCase(), `${a}x`, "../etc", `${a.slice(0, 25)}b`, "", null, 5]) {
    for (const f of [agentUser, tagGroup, agentUnit, agentNetns, agentHome, agentSessions, agentConfigDir, agentArchive, agentConfigArchive, tagDir, brokerDir, fenceFiles]) refused(() => f(bad));
  }
});

test("config: a full valid config passes, with and without host bounds", () => {
  assert.equal(validateConfig(base()), true);
  assert.equal(validateConfig(base(), { ramMb: 8192, cpus: 4 }), true);
  assert.equal(validateConfig(with_((c) => { c.programs = "no-shell"; c.mcp_allow = [{ name: "math", argv: ["/usr/bin/node", "/data/mcp/math.mjs"] }]; })), true);
  assert.equal(validateConfig(with_((c) => { c.network = { mode: "full", allow: [], lan_allow: ["10.1.0.0/16", "192.168.1.0/24"] }; })), true);
  // v1 has no IPv6 egress (ruled): an IPv6 lan_allow refuses the grant at activation.
  assert.throws(() => validateConfig(with_((c) => { c.network = { mode: "full", allow: [], lan_allow: ["fc00::/7"] }; })), (e) => e instanceof FleetError && e.code === "bad_form");
  assert.equal(validateConfig(with_((c) => { c.network = { mode: "none", allow: [], lan_allow: [] }; c.files = { rw: [], ro: [] }; c.wakes = []; })), true);
  assert.equal(validateConfig(with_((c) => { c.resources.cpu_quota_pct = 400; })), true);
});

test("config: the shape is closed", () => {
  refused(() => validateConfig(with_((c) => { c.extra = 1; })));
  refused(() => validateConfig(with_((c) => { delete c.turns; })));
  refused(() => validateConfig(with_((c) => { c.files.rw.push("relative/path"); })));
  refused(() => validateConfig(with_((c) => { c.files.rw.push("/data/project"); }))); // duplicate
  refused(() => validateConfig(with_((c) => { c.network.mode = "open"; })));
  refused(() => validateConfig(with_((c) => { c.network.allow = ["*.github.com"]; })));
  refused(() => validateConfig(with_((c) => { c.network.allow = ["GitHub.com"]; })));
  refused(() => validateConfig(with_((c) => { c.network.allow = ["localhost"]; })));
  refused(() => validateConfig(with_((c) => { c.programs = "confined"; })));
  refused(() => validateConfig(with_((c) => { c.resources.memory_max_mb = 128; })));
  refused(() => validateConfig(with_((c) => { c.resources.tasks_max = 70000; })));
  refused(() => validateConfig(with_((c) => { c.resources.disk_gb = 1.5; })));
  refused(() => validateConfig(with_((c) => { delete c.resources.nofile; })));
  refused(() => validateConfig(with_((c) => { c.wakes = [{ kind: "every", every_s: 59 }]; })));
  refused(() => validateConfig(with_((c) => { c.wakes = [{ kind: "path", path: "/x", poll_s: 10 }]; })));
  refused(() => validateConfig(with_((c) => { c.wakes = [{ kind: "cron", spec: "* * * * *" }]; })));
  refused(() => validateConfig(with_((c) => { c.turns.wall_s = 59; })));
  refused(() => validateConfig(with_((c) => { c.mcp_allow = [{ name: "x", argv: ["node"] }]; })));
  refused(() => validateConfig(with_((c) => { c.files.rw = Array.from({ length: 33 }, (_, i) => `/data/p${i}`); })));
});

test("config: the rules one field imposes on another", () => {
  refused(() => validateConfig(with_((c) => { c.network.mode = "none"; })));           // allow without allowlist
  refused(() => validateConfig(with_((c) => { c.network.lan_allow = ["10.0.0.0/8"]; }))); // lan_allow without full
  refused(() => validateConfig(with_((c) => { c.programs = "no-shell"; })));            // no-shell needs a list
  refused(() => validateConfig(with_((c) => { c.files.ro = ["/data/project"]; })));      // both rw and ro
  refused(() => validateConfig(with_((c) => { c.mcp_allow = [{ name: "a", argv: ["/usr/bin/a"] }, { name: "a", argv: ["/usr/bin/b"] }]; })));
  refused(() => validateConfig(with_((c) => { c.mcp_allow = [{ name: "a", argv: ["/etc/evil"] }]; })));
  refused(() => validateConfig(with_((c) => { c.network.allow = ["github.com:0"]; })));
  refused(() => validateConfig(with_((c) => { c.network.allow = ["github.com:70000"]; })));
  refused(() => validateConfig(base(), { ramMb: 2048 }));
  refused(() => validateConfig(with_((c) => { c.resources.cpu_quota_pct = 500; }), { cpus: 4 }));
});

test("paths: / is refused exactly; protected subtrees match whole segments; unnormalized paths are refused", () => {
  for (const ok of ["/etcetera", "/etc-data/x", "/devices", "/runs", "/srv/sagebrushx", "/srv/other", "/opt/sagebrush-cli-cache", "/var/lib/postgres", "/var/libsagebrush", "/home/person/project", "/proc2"]) {
    assert.equal(checkGrantPath(ok), ok, ok);
  }
  for (const bad of ["/", "/etc", "/etc/ssh", "/proc/1", "/sys", "/dev/shm", "/run/user", "/boot", "/root", "/opt/sagebrush", "/opt/sagebrush/1.0",
    "/srv/sagebrush", "/srv/sagebrush/agents/x", "/var/lib/sagebrush", "/var/lib/sagebrush-broker/keys", "/var/lib/sagebrushx",
    "/data/../etc", "/data/./x", "/data//x", "/data/", "data", ""]) {
    refused(() => checkGrantPath(bad), "bad_form");
  }
});

test("lan_allow: canonical CIDRs inside private ranges only; never loopback, link-local or metadata", () => {
  for (const ok of ["10.0.0.0/8", "10.20.30.0/24", "172.16.0.0/12", "172.31.255.0/24", "192.168.0.0/16", "192.168.4.128/25"]) {
    assert.equal(checkLanCidr(ok), ok, ok);
  }
  for (const bad of ["127.0.0.0/8", "169.254.169.254/32", "169.254.0.0/16", "8.8.8.0/24", "172.32.0.0/16", "10.0.0.0/7", "0.0.0.0/0",
    "10.0.0.1/24", "fe80::/10", "::1/128", "::/0", "fc00::/6", "10.0.0.0/33", "10.0.0.0", "10.0.0.0/08", "::ffff:10.0.0.0/104", "x/8",
    "fc00::/7", "fd00::/8", "fd12:3456:789a::/48"]) { // (v1: no IPv6 exceptions at all)
    refused(() => checkLanCidr(bad), "bad_form");
  }
});
