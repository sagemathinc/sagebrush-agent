// Host supervisor freeze r3.1 §3.3, §4.6 and the host launcher contract §3-§5: the real effects. The argv runner is
// tested against real processes; the systemd and launcher steps against a scripted runner and a temporary filesystem
// root, so the staging, record and contract handling runs for real without root or systemd.
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import { join } from "node:path";
import { test } from "./host-linux-only.mjs";
import { FleetError } from "../lib/fleet/index.mjs";
import { BINDS, UNIT_DIR, launcherExit, realEffects, runArgv, stagingPlan } from "../lib/fleet/host/effects.mjs";
import { CONTRACT, launcherContract, renderUnit } from "../lib/fleet/host/unit.mjs";

const A = "abcdefghijklmnopqrstuvwxya", T1 = "tagtagtagtagtagtagtagtagaa";
const UID = 70000, GID = 70000, ME = process.getuid();
const UNIT = `sagebrush-agent-${A}.service`;
const config = () => ({
  files: { rw: ["/data/project"], ro: ["/data/reference"] },
  network: { mode: "none", allow: [], lan_allow: [] },
  programs: "run", mcp_allow: null, gpu: false,
  resources: { memory_max_mb: 6144, tasks_max: 4096, cpu_weight: 100, cpu_quota_pct: 200, io_weight: 100, disk_gb: 50, nofile: 65536 },
  wakes: [], turns: { per_day: 100, wall_s: 7200 },
});
const grantAgent = (over = {}) => ({ agent: A, name: "worker-1", client: "claude", root: false, tags: [T1], config: config(), ...over });
const HOST = { release: "/opt/sagebrush/1.2.3", cliPath: { claude: "/opt/sagebrush/cli/claude-2.1.0" }, hostInfo: { ramMb: 16384, cpus: 4 } };

const typed = (code) => (e) => e instanceof FleetError && e.code === code;
const host = (e) => !(e instanceof FleetError) && e.code === "effect_failed";

let seq = 0;
/** A temporary root with the host directories the effects write under. */
function tmpRoot() {
  const root = join(os.tmpdir(), `sb-effects-${process.pid}-${seq++}`);
  fs.rmSync(root, { recursive: true, force: true });
  for (const d of ["/run/sagebrush", UNIT_DIR, "/var/lib/sagebrush/contract"]) fs.mkdirSync(join(root, d), { recursive: true, mode: 0o755 });
  for (const d of ["/run", "/run/sagebrush"]) fs.chmodSync(join(root, d), 0o755);
  return root;
}

/**
 * A scripted runner: `script(argv)` returns { code, stdout } or undefined (code 0). Records every argv. The default
 * script is a healthy host: nothing is mounted, stage-bind writes its record, the unit starts and keeps running.
 */
function scripted(root, over = {}) {
  const calls = [];
  const dflt = (argv) => {
    if (argv[0] === "mountpoint") return { code: 1 };
    if (argv[1] === "stage-bind") {
      const get = (k) => argv[argv.indexOf(k) + 1];
      const staging = `${BINDS}/${get("--agent")}/${get("--index")}`;
      const rec = { path: get("--path"), mode: get("--mode"), dev: [8, 1], ino: 1000 + Number(get("--index")), uid: 0, staging };
      fs.writeFileSync(join(root, get("--record")), `${JSON.stringify(rec)}\n`);
      return { code: 0 };
    }
    if (argv[0] === "systemctl" && argv[1] === "show") return { code: 0, stdout: "ActiveState=active\nSubState=running\nResult=success\nExecMainCode=0\nExecMainStatus=0\nConditionResult=yes\n" };
    return { code: 0 };
  };
  const run = async (argv, { ms }) => {
    assert.ok(ms > 0, `no time left for ${argv.join(" ")}`);
    calls.push(argv);
    for (const [match, fn] of Object.entries(over)) if (argv.join(" ").includes(match)) { const r = fn(argv, calls); if (r) return { stdout: "", stderr: "", ...r }; }
    return { stdout: "", stderr: "", ...dflt(argv) };
  };
  return { run, calls };
}

/** chown is recorded, not done (the tests don't run as root). */
function setup({ over, settleMs = 30, ga = grantAgent() } = {}) {
  const root = tmpRoot();
  const { run, calls } = scripted(root, over);
  const chowns = [];
  const fsx = { ...fs, chownSync: (p, u, g) => chowns.push([p, u, g]) };
  const fx = realEffects({
    lookup: (agent) => ({ grantAgent: ga, uid: UID, gid: GID, net: { mode: "none" } }),
    host: HOST, provision: async () => {}, run, fsx, root, rootUid: ME, settleMs,
  });
  return { root, fx, calls, chowns, ga };
}
const ctl = (calls) => calls.filter((c) => c[0] === "systemctl").map((c) => c.slice(1).join(" "));
const show = (s) => () => ({ code: 0, stdout: Object.entries(s).map(([k, v]) => `${k}=${v}\n`).join("") });

test("runArgv runs argv without a shell, with a fixed environment, and caps the output", async () => {
  const echo = await runArgv(["/bin/echo", "$HOME; ls *"], { ms: 5000 });
  assert.deepEqual([echo.code, echo.stdout], [0, "$HOME; ls *\n"]);
  const env = await runArgv(["/usr/bin/env"], { ms: 5000 });
  assert.deepEqual(env.stdout.trim().split("\n").sort(), ["LANG=C.UTF-8", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"]);
  const big = await runArgv(["/usr/bin/head", "-c", "200000", "/dev/zero"], { ms: 5000 });
  assert.equal(big.stdout.length, 64 * 1024);
  assert.equal((await runArgv(["/bin/sh", "-c", "exit 7"], { ms: 5000 })).code, 7);
});

test("runArgv kills a command past its time or on abort, and refuses a bad argv", async () => {
  let t = Date.now();
  await assert.rejects(runArgv(["/bin/sleep", "5"], { ms: 100 }), host);
  assert.ok(Date.now() - t < 2000);
  const ac = new AbortController();
  t = Date.now();
  setTimeout(() => ac.abort(), 100);
  await assert.rejects(runArgv(["/bin/sleep", "5"], { ms: 5000, signal: ac.signal }), host);
  assert.ok(Date.now() - t < 2000);
  for (const argv of [[], ["/bin/echo", "a\0b"], ["/bin/echo", ""], "/bin/echo"]) await assert.rejects(runArgv(argv, { ms: 1000 }), host);
  await assert.rejects(runArgv(["/bin/true"], { ms: 0 }), host);
  await assert.rejects(runArgv(["/nonexistent/bin"], { ms: 1000 }), host);
});

test("the launcher's exit codes map exactly as the contract's table", () => {
  const want = { 64: null, 65: "preflight_missing", 66: "preflight_missing", 67: "landlock_abi", 68: "preflight_missing", 69: "preflight_missing", 70: "unit_failed", 71: "unit_failed", 72: null, 1: "unit_failed", 203: "unit_failed" };
  for (const [code, reason] of Object.entries(want)) assert.equal(launcherExit(Number(code)), reason, code);
});

test("the staging plan numbers the rw paths, then the ro paths, under the agent's binds directory", () => {
  assert.deepEqual(stagingPlan(grantAgent()), [
    { path: "/data/project", mode: "rw", index: 0, staging: `${BINDS}/${A}/0`, record: `${BINDS}/${A}/0.record` },
    { path: "/data/reference", mode: "ro", index: 1, staging: `${BINDS}/${A}/1`, record: `${BINDS}/${A}/1.record` },
  ]);
  const many = config();
  many.files.rw = Array.from({ length: 65 }, (_, i) => `/data/p${i}`);
  assert.throws(() => stagingPlan(grantAgent({ config: many })), typed("bad_form"));
  assert.throws(() => stagingPlan(grantAgent({ agent: "nope" })), typed("bad_form"));
});

test("the systemd effects are the exact systemctl argv, and a non-zero exit is host-side", async () => {
  const { fx, calls } = setup();
  for (const [f, args] of [["mask", ["mask", "--runtime", UNIT]], ["unmask", ["unmask", "--runtime", UNIT]], ["stopUnit", ["stop", UNIT]], ["freeze", ["freeze", UNIT]], ["thaw", ["thaw", UNIT]]]) {
    await fx[f](A, 1000);
    assert.deepEqual(calls.at(-1), ["systemctl", ...args]);
  }
  await fx.daemonReload(1000);
  assert.deepEqual(calls.at(-1), ["systemctl", "daemon-reload"]);
  const bad = setup({ over: { "systemctl mask": () => ({ code: 1 }) } });
  await assert.rejects(bad.fx.mask(A, 1000), host);
  assert.throws(() => setup().fx.mask("not-an-id", 1000), typed("bad_form"));
});

test("isActive is true only for active; inactive is false; anything else is unknown", async () => {
  const one = (r) => setup({ over: { "is-active": () => r } }).fx.isActive(A, 1000);
  assert.equal(await one({ code: 0, stdout: "active\n" }), true);
  assert.equal(await one({ code: 3, stdout: "inactive\n" }), false);
  assert.equal(await one({ code: 3, stdout: "failed\n" }), false);
  await assert.rejects(one({ code: 1, stdout: "" }), host);
  await assert.rejects(one({ code: 0, stdout: "activating\n" }), host);
});

test("procCount reads the unit's own cgroup; no cgroup is 0, and an unreadable one throws", async () => {
  const cg = "/sagebrush.slice/sagebrush-agents.slice/x.service";
  const { root, fx } = setup({ over: { ControlGroup: () => ({ code: 0, stdout: `${cg}\n` }) } });
  fs.mkdirSync(join(root, "/sys/fs/cgroup", cg, "child"), { recursive: true });
  fs.writeFileSync(join(root, "/sys/fs/cgroup", cg, "cgroup.procs"), "101\n102\n");
  fs.writeFileSync(join(root, "/sys/fs/cgroup", cg, "child/cgroup.procs"), "103\n");
  assert.equal(await fx.procCount(A, 1000), 3);
  fs.rmSync(join(root, "/sys/fs/cgroup", cg, "child/cgroup.procs"));
  await assert.rejects(fx.procCount(A, 1000));
  assert.equal(await setup({ over: { ControlGroup: () => ({ code: 0, stdout: "\n" }) } }).fx.procCount(A, 1000), 0);
});

test("writeUnit writes the rendered unit root 0644, and first removes the launcher's old contract", async () => {
  const { root, fx, ga } = setup();
  const contract = join(root, CONTRACT(A));
  fs.writeFileSync(contract, "an older grant's contract\n");
  const r = await fx.writeUnit(A, UID, ga, 1000);
  const want = renderUnit(ga, { uid: UID, release: HOST.release, cliPath: HOST.cliPath.claude, hostInfo: HOST.hostInfo,
    staged: [{ path: "/data/project", mode: "rw", staging: `${BINDS}/${A}/0` }, { path: "/data/reference", mode: "ro", staging: `${BINDS}/${A}/1` }] });
  const p = join(root, UNIT_DIR, UNIT);
  assert.equal(fs.readFileSync(p, "utf8"), want.text);
  assert.equal(fs.statSync(p).mode & 0o777, 0o644);
  assert.equal(r.digest, want.digest);
  assert.equal(fs.existsSync(contract), false);
  // Unrenderable input writes nothing.
  fs.rmSync(p);
  await assert.rejects(fx.writeUnit(A, UID, { ...ga, root: "yes" }, 1000), typed("bad_form"));
  assert.equal(fs.existsSync(p), false);
});

test("start: fresh mountpoints, one stage-bind per path in order, the checked records in the contract, then start and settle", async () => {
  // Leftovers of an earlier, wider start: a still-mounted index 5, its record, and a stale record and temp record of 0.
  let mounted = true;
  const { root, fx, calls, chowns, ga } = setup({ over: {
    mountpoint: (argv) => (argv.at(-1).endsWith("/5") && mounted ? { code: 0 } : { code: 1 }),
    umount: () => { mounted = false; return { code: 0 }; },
  } });
  const dir = join(root, BINDS, A);
  fs.mkdirSync(join(dir, "5"), { recursive: true });
  for (const f of ["5.record", "0.record", "0.record.tmp"]) fs.writeFileSync(join(dir, f), "old");
  await fx.start(A, 5000);
  const sc = { calls };
  const seq = sc.calls.map((c) => c[0] === "systemctl" ? `systemctl ${c[1]}` : c[1] === "stage-bind" ? `stage-bind ${c[c.indexOf("--index") + 1]}` : c[0]);
  const firstStage = seq.indexOf("stage-bind 0");
  assert.ok(seq.slice(0, firstStage).includes("umount"), "the old mount is detached before any stage-bind");
  assert.deepEqual(seq.slice(firstStage, firstStage + 3), ["stage-bind 0", "stage-bind 1", "systemctl start"]);
  assert.ok(seq.slice(firstStage + 3).every((x) => x === "systemctl show"));
  assert.deepEqual(sc.calls[sc.calls.findIndex((c) => c[1] === "stage-bind")], [`${HOST.release}/bin/sagebrush-agent-launch`, "stage-bind", "--agent", A, "--index", "0", "--mode", "rw", "--path", "/data/project", "--record", `${BINDS}/${A}/0.record`]);
  // The staging directory holds exactly the fresh mountpoints and the new records; the stale ones are gone.
  assert.deepEqual(fs.readdirSync(dir).sort(), ["0", "0.record", "1", "1.record"]);
  for (const n of ["0", "1"]) assert.equal(fs.statSync(join(dir, n)).mode & 0o777, 0o700);
  // The contract carries the records' identities, root:<agent group> 0640.
  const contract = join(root, CONTRACT(A));
  const ctx = { uid: UID, release: HOST.release, cliPath: HOST.cliPath.claude, hostInfo: HOST.hostInfo,
    staged: [{ path: "/data/project", mode: "rw", staging: `${BINDS}/${A}/0` }, { path: "/data/reference", mode: "ro", staging: `${BINDS}/${A}/1` }] };
  assert.equal(fs.readFileSync(contract, "utf8"), launcherContract(ga, ctx, [
    { index: 0, path: "/data/project", mode: "rw", dev: [8, 1], ino: 1000 }, { index: 1, path: "/data/reference", mode: "ro", dev: [8, 1], ino: 1001 },
  ], { mode: "none" }));
  assert.equal(fs.statSync(contract).mode & 0o777, 0o640);
  assert.deepEqual(chowns, [[contract, ME, GID]]);
});

test("start waits until the unit has been running for the settle time", async () => {
  const { fx, calls } = setup({ settleMs: 300 });
  const t = Date.now();
  await fx.start(A, 5000);
  assert.ok(Date.now() - t >= 300);
  assert.ok(ctl(calls).filter((c) => c.startsWith("show")).length >= 3);
});

test("start: stage-bind's 66 is preflight_missing and nothing starts; any other stage-bind failure is host-side", async () => {
  for (const [code, check] of [[66, typed("preflight_missing")], [70, host], [64, host], [72, host], [1, host]]) {
    const { fx, calls } = setup({ over: { "stage-bind": (argv) => (argv.includes("1") ? { code } : undefined) } });
    await assert.rejects(fx.start(A, 5000), check, String(code));
    assert.ok(!ctl(calls).some((c) => c.startsWith("start")), `${code}: nothing started`);
  }
});

test("start: a record that is missing, malformed or for another bind is host-side, and nothing starts", async () => {
  const cases = {
    missing: () => ({ code: 0 }),
    "not JSON": (root, rec) => fs.writeFileSync(rec, "{nope"),
    "another path": (root, rec, r) => fs.writeFileSync(rec, JSON.stringify({ ...r, path: "/data/other" })),
    "another staging": (root, rec, r) => fs.writeFileSync(rec, JSON.stringify({ ...r, staging: `${BINDS}/${A}/7` })),
    "an extra key": (root, rec, r) => fs.writeFileSync(rec, JSON.stringify({ ...r, extra: 1 })),
    "a bad dev": (root, rec, r) => fs.writeFileSync(rec, JSON.stringify({ ...r, dev: [8] })),
    "a symlink": (root, rec) => fs.symlinkSync("/etc/hostname", rec),
  };
  for (const [name, write] of Object.entries(cases)) {
    let root;
    const s = setup({ over: { "stage-bind": (argv) => {
      const rec = join(root, argv[argv.indexOf("--record") + 1]);
      const r = { path: argv[argv.indexOf("--path") + 1], mode: argv[argv.indexOf("--mode") + 1], dev: [8, 1], ino: 1, uid: 0, staging: `${BINDS}/${A}/${argv[argv.indexOf("--index") + 1]}` };
      write(root, rec, r);
      return { code: 0 };
    } } });
    root = s.root;
    await assert.rejects(s.fx.start(A, 5000), host, name);
    assert.ok(!ctl(s.calls).some((c) => c.startsWith("start")), `${name}: nothing started`);
  }
});

test("start: a staging ancestor that isn't root-only, or an unexpected staging entry, refuses before any stage-bind", async () => {
  const a = setup();
  fs.chmodSync(join(a.root, "/run/sagebrush"), 0o777);
  await assert.rejects(a.fx.start(A, 5000), host);
  assert.ok(!a.calls.some((c) => c[1] === "stage-bind"));
  const b = setup();
  fs.mkdirSync(join(b.root, BINDS, A), { recursive: true });
  fs.writeFileSync(join(b.root, BINDS, A, "evil"), "");
  await assert.rejects(b.fx.start(A, 5000), host);
  assert.ok(!b.calls.some((c) => c[1] === "stage-bind"));
  const c = setup({ over: { mountpoint: () => ({ code: 0 }), umount: () => ({ code: 0 }) } });
  fs.mkdirSync(join(c.root, BINDS, A, "3"), { recursive: true });
  await assert.rejects(c.fx.start(A, 5000), host, "a mount that never detaches");
  assert.ok(!c.calls.some((x) => x[1] === "stage-bind"));
});

test("start: the launcher's exit, read after the unit fails, is the typed start failure; 64, 72 and anything else are as tabled", async () => {
  const failedWith = (code, status) => show({ ActiveState: "failed", SubState: "failed", Result: "exit-code", ExecMainCode: code, ExecMainStatus: status, ConditionResult: "yes" });
  const cases = [
    [failedWith("1", "65"), typed("preflight_missing")], [failedWith("1", "66"), typed("preflight_missing")],
    [failedWith("1", "67"), typed("landlock_abi")], [failedWith("1", "68"), typed("preflight_missing")],
    [failedWith("1", "69"), typed("preflight_missing")], [failedWith("1", "71"), typed("unit_failed")],
    [failedWith("1", "64"), host], [failedWith("1", "72"), host], [failedWith("2", "9"), typed("unit_failed")],
    [show({ ActiveState: "activating", SubState: "auto-restart", Result: "exit-code", ExecMainCode: "1", ExecMainStatus: "67", ConditionResult: "yes" }), typed("landlock_abi")],
    [show({ ActiveState: "inactive", SubState: "dead", Result: "success", ExecMainCode: "0", ExecMainStatus: "0", ConditionResult: "no" }), host],
  ];
  for (const [fn, check] of cases) await assert.rejects(setup({ over: { "systemctl show": fn } }).fx.start(A, 5000), check);
});

test("start: a failed systemctl start is never taken as started", async () => {
  // Masked (or anything else that fails the job before the launcher ran): the unit is inactive with Result=success.
  const masked = setup({ over: { "systemctl start": () => ({ code: 1 }), "systemctl show": show({ ActiveState: "inactive", SubState: "dead", Result: "success", ExecMainCode: "0", ExecMainStatus: "0", ConditionResult: "yes" }) } });
  await assert.rejects(masked.fx.start(A, 5000), host);
  // The job failed because the unit did: mapped.
  const abi = setup({ over: { "systemctl start": () => ({ code: 1 }), "systemctl show": show({ ActiveState: "failed", SubState: "failed", Result: "exit-code", ExecMainCode: "1", ExecMainStatus: "67", ConditionResult: "yes" }) } });
  await assert.rejects(abi.fx.start(A, 5000), typed("landlock_abi"));
});

test("start: a unit that never settles is host-side within the start's time; an abort stops the wait", async () => {
  const slow = setup({ over: { "systemctl show": show({ ActiveState: "activating", SubState: "start", Result: "success", ExecMainCode: "0", ExecMainStatus: "0", ConditionResult: "yes" }) } });
  let t = Date.now();
  await assert.rejects(slow.fx.start(A, 600), host);
  assert.ok(Date.now() - t < 1500);
  const ac = new AbortController();
  const s = setup({ settleMs: 5000 });
  t = Date.now();
  setTimeout(() => ac.abort(), 200);
  await assert.rejects(s.fx.start(A, 10000, ac.signal), host);
  assert.ok(Date.now() - t < 2000);
});

test("start uses the lookup's agent only: another agent's entry is host-side", async () => {
  const root = tmpRoot();
  const { run } = scripted(root);
  const fx = realEffects({ lookup: () => ({ grantAgent: grantAgent({ agent: T1 }), uid: UID, gid: GID, net: null }), host: HOST, provision: async () => {}, run, root, rootUid: ME });
  await assert.rejects(fx.start(A, 5000), host);
  assert.throws(() => realEffects({ host: HOST, provision: async () => {} }), typed("bad_form"));
});
