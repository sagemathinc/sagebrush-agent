// Host supervisor (design: agent-autonomous-host-supervisor-freeze-r3.1.md §3.3, §4.1, §4.6; the host launcher contract
// §3-§5): the real effects behind the executor's `fx`, for its systemd and launcher steps. Every command runs by argv,
// never through a shell, with a fixed environment, within the time the executor gives it (`ms`), and is killed when
// the executor aborts it (`signal`).
//
// - mask and unmask (--runtime), stop, freeze and thaw, daemon-reload, is-active, and the cgroup's process count;
// - writeUnit: render the unit from the grant agent (unit.mjs) and write it atomically, root 0644. The launcher's old
//   contract is removed first, so nothing can start with a contract from an earlier grant;
// - start, by the launcher contract §3-§5:
//   1. the staging directory's ancestors are checked (root-owned, not group- or world-writable);
//   2. every old staging mountpoint and record of the agent is removed (each mount detached first), and a fresh, empty,
//      root 0700 mountpoint made for each granted path;
//   3. one `stage-bind` per granted path, serialized: exit 66 is preflight_missing; anything else non-zero is host-side;
//   4. each record is read back and checked against the call that made it;
//   5. the launcher's contract (unit.mjs) is written atomically, root:<agent's group> 0640;
//   6. `systemctl start`, then the unit is watched until it settles (the unit is Type=simple: start returns at fork).
//      The launcher's exit (ExecMainStatus) maps 65, 66, 68 and 69 to preflight_missing, 67 to landlock_abi, and 71 or
//      any other failure of the unit to unit_failed; 64 and 72 are host-side.
//   Agent-side reasons are FleetErrors with the executor's typed codes; everything else is host-side, `effect_failed`.
//
// Provisioning (users, groups, directories, quotas, the network) and the broker, audit, intent and acknowledgement
// adapters are passed in; this module doesn't implement them.

import { spawn } from "node:child_process";
import fs from "node:fs";
import { basename, dirname, join } from "node:path";
import { FleetError, isId, refuse } from "../bytes.mjs";
import { countProcs, realSystemd } from "./fence.mjs";
import { agentUnit } from "./names.mjs";
import { exactKeys, writeDurable } from "./store.mjs";
import { CONTRACT, launcherContract, renderUnit } from "./unit.mjs";

export const UNIT_DIR = "/etc/systemd/system";
/** The root-only staging directories (launcher contract §3): /run/sagebrush/binds/<id>/<n> and <n>.record. */
export const BINDS = "/run/sagebrush/binds";
/** The staging directory's ancestors, each checked before a stage-bind (launcher contract §3.1); /run is a tmpfs, so the
 * last two are made (root 0755 and 0700) when missing, as after a reboot. */
const STAGING_ANCESTORS = [["/run", null], ["/run/sagebrush", 0o755], [BINDS, 0o700]];
const ENV = Object.freeze({ PATH: "/usr/sbin:/usr/bin:/sbin:/bin", LANG: "C.UTF-8" });
const OUT_MAX = 64 * 1024;
const POLL_MS = 100;

const hostFail = (what) => Object.assign(new Error(`effects: ${what}`), { code: "effect_failed" });

/**
 * Run `argv` (never a shell) with a fixed environment, within `ms`. Resolves { code, stdout, stderr } (each output
 * capped at 64 KiB) when the process exits. Rejects (host-side) if it can't be spawned, is killed by a signal, takes
 * longer than `ms`, or is aborted; in the last two cases the process is killed first and waited for.
 */
export function runArgv(argv, { ms, signal } = {}) {
  return new Promise((resolve, reject) => {
    if (!Array.isArray(argv) || argv.length === 0 || !argv.every((a) => typeof a === "string" && a.length > 0 && !a.includes("\0"))) {
      reject(hostFail("bad argv")); return;
    }
    if (!(ms > 0)) { reject(hostFail("no time left")); return; }
    if (signal?.aborted) { reject(hostFail("aborted")); return; }
    let child;
    try { child = spawn(argv[0], argv.slice(1), { env: ENV, stdio: ["ignore", "pipe", "pipe"] }); } catch { reject(hostFail("spawn failed")); return; }
    const out = { stdout: [], stderr: [] }, size = { stdout: 0, stderr: 0 };
    for (const k of ["stdout", "stderr"]) child[k].on("data", (b) => { if (size[k] < OUT_MAX) { out[k].push(b.subarray(0, OUT_MAX - size[k])); size[k] += b.length; } });
    let why = null;
    const kill = (w) => { if (why === null) { why = w; child.kill("SIGKILL"); } };
    const timer = setTimeout(() => kill("timed out"), ms);
    const onAbort = () => kill("aborted");
    signal?.addEventListener("abort", onAbort, { once: true });
    child.on("error", () => kill("spawn failed"));
    child.on("close", (code, sig) => {
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
      if (why !== null) reject(hostFail(why));
      else if (code === null) reject(hostFail(`killed by ${sig}`));
      else resolve({ code, stdout: Buffer.concat(out.stdout).toString("utf8"), stderr: Buffer.concat(out.stderr).toString("utf8") });
    });
  });
}

/** Sleep `ms`, or less if `signal` aborts (then it rejects). */
const sleep = (ms, signal) => new Promise((resolve, reject) => {
  if (signal?.aborted) { reject(hostFail("aborted")); return; }
  const t = setTimeout(() => { signal?.removeEventListener("abort", onAbort); resolve(); }, ms);
  const onAbort = () => { clearTimeout(t); reject(hostFail("aborted")); };
  signal?.addEventListener("abort", onAbort, { once: true });
});

/** The launcher's `exec` exit codes (launcher contract §5) as the executor's start failures; null is host-side. */
export function launcherExit(status) {
  if ([65, 66, 68, 69].includes(status)) return "preflight_missing";
  if (status === 67) return "landlock_abi";
  if (status === 64 || status === 72) return null;
  return "unit_failed";
}

/** The staged binds for a grant agent: its rw paths, then its ro paths, numbered from 0 (unit.mjs and the launcher). */
export function stagingPlan(grantAgent) {
  const id = grantAgent.id ?? grantAgent.agent;
  if (!isId(id)) refuse("bad_form", "effects: bad agent id");
  const files = grantAgent.config.files;
  const rows = [...files.rw.map((path) => ({ path, mode: "rw" })), ...files.ro.map((path) => ({ path, mode: "ro" }))];
  if (rows.length > 64) refuse("bad_form", "effects: more than 64 granted paths");
  return rows.map((r, index) => ({ ...r, index, staging: `${BINDS}/${id}/${index}`, record: `${BINDS}/${id}/${index}.record` }));
}

/** Parse `systemctl show` Key=Value lines. */
const parseShow = (text) => Object.fromEntries(text.split("\n").filter((l) => l.includes("=")).map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1)]));

/**
 * The real effects. Options:
 * - `lookup(agent)` → { grantAgent, uid, gid, net }: the agent's current grant entry, its uid and private gid, and its
 *   network plan (net.mjs). Called by writeUnit and start.
 * - `host`: { release, cliPath: { claude, codex }, gpuNodes?, hostInfo? } for unit.mjs.
 * - `provision(agent, uid, grantAgent, ms, signal)` and `adapters` { appendIntent, openIntents, audit, brokerGen,
 *   brokerRevoke, publishMap, sendAck }: passed through.
 * - Test seams: `run` (runArgv), `fsx` (node:fs), `root` (a prefix for every filesystem path; "" on a host), `rootUid`
 *   (0), `settleMs` (how long a started unit must stay running), `sys` (fence.mjs's realSystemd).
 */
export function realEffects({ lookup, host, provision, adapters = {}, run = runArgv, fsx = fs, root = "", rootUid = 0, settleMs = 2000, sys = realSystemd } = {}) {
  if (typeof lookup !== "function" || !host || typeof provision !== "function") refuse("bad_form", "effects: lookup, host and provision are required");
  const at = (p) => `${root}${p}`;
  const unitOf = (agent) => agentUnit(agent);
  const ctl = async (args, ms, signal) => {
    const r = await run(["systemctl", ...args], { ms, signal });
    if (r.code !== 0) throw hostFail(`systemctl ${args[0]} exited ${r.code}`);
    return r;
  };
  const ctxFor = (grantAgent, uid) => ({
    uid, release: host.release, cliPath: host.cliPath?.[grantAgent.client], gpuNodes: host.gpuNodes, hostInfo: host.hostInfo,
    staged: stagingPlan(grantAgent).map(({ path, mode, staging }) => ({ path, mode, staging })),
  });
  const removeIfThere = (p) => {
    try { fsx.unlinkSync(p); } catch (e) { if (e?.code !== "ENOENT") throw hostFail("can't remove an old file"); return false; }
    return true;
  };
  const fsyncDir = (d) => { const fd = fsx.openSync(d, "r"); try { fsx.fsyncSync(fd); } finally { fsx.closeSync(fd); } };

  /** A root-owned directory that isn't group- or world-writable and isn't a symlink; host-side otherwise. */
  const trustedDir = (p) => {
    let st;
    try { st = fsx.lstatSync(at(p)); } catch { throw hostFail("a staging ancestor is missing"); }
    if (!st.isDirectory() || st.uid !== rootUid || (st.mode & 0o022) !== 0) throw hostFail("a staging ancestor isn't root-only");
  };

  /** Detach every mount stacked on a staging mountpoint (at most 8), then remove the empty directory. */
  const clearMountpoint = async (p, left, signal) => {
    for (let i = 0; ; i++) {
      const m = await run(["mountpoint", "-q", "--nofollow", at(p)], { ms: left(), signal });
      if (m.code !== 0) break; // not (or no longer) a mountpoint
      if (i === 8) throw hostFail("a staging mountpoint won't detach");
      const u = await run(["umount", "--lazy", "--no-canonicalize", at(p)], { ms: left(), signal });
      if (u.code !== 0) throw hostFail("a staging mountpoint won't detach");
    }
    try { fsx.rmdirSync(at(p)); } catch (e) { if (e?.code !== "ENOENT") throw hostFail("an old staging mountpoint can't be removed"); }
  };

  /** Steps 1-2: a clean staging directory with a fresh, empty, root 0700 mountpoint per planned bind. */
  const freshStaging = async (agent, plan, left, signal) => {
    for (const [a, mode] of STAGING_ANCESTORS) {
      if (mode !== null) try { fsx.mkdirSync(at(a), { mode }); } catch (e) { if (e?.code !== "EEXIST") throw hostFail("can't make a staging ancestor"); }
      trustedDir(a);
    }
    const dir = `${BINDS}/${agent}`;
    try { fsx.mkdirSync(at(dir), { mode: 0o700 }); } catch (e) { if (e?.code !== "EEXIST") throw hostFail("can't make the staging directory"); }
    fsx.chmodSync(at(dir), 0o700);
    trustedDir(dir);
    for (const name of fsx.readdirSync(at(dir))) {
      if (/^[0-9]+$/.test(name)) await clearMountpoint(`${dir}/${name}`, left, signal);
      else if (/^[0-9]+\.record(\.tmp)?$/.test(name)) removeIfThere(at(`${dir}/${name}`));
      else throw hostFail("an unexpected entry in the staging directory");
    }
    for (const b of plan) { fsx.mkdirSync(at(b.staging), { mode: 0o700 }); fsx.chmodSync(at(b.staging), 0o700); }
    fsyncDir(at(dir));
  };

  /** Step 4: a record exactly as stage-bind writes it, for exactly this bind. */
  const readRecord = (b) => {
    let st, rec;
    try { st = fsx.lstatSync(at(b.record)); } catch { throw hostFail("stage-bind left no record"); }
    if (!st.isFile() || st.uid !== rootUid || st.size > 4096) throw hostFail("a stage-bind record isn't a small root file");
    try { rec = JSON.parse(fsx.readFileSync(at(b.record), "utf8")); } catch { throw hostFail("a stage-bind record isn't JSON"); }
    const int = (n) => Number.isSafeInteger(n) && n >= 0;
    if (!exactKeys(rec, ["path", "mode", "dev", "ino", "uid", "staging"]) || rec.path !== b.path || rec.mode !== b.mode || rec.staging !== b.staging
      || !Array.isArray(rec.dev) || rec.dev.length !== 2 || !rec.dev.every(int) || !int(rec.ino) || !int(rec.uid)) {
      throw hostFail("a stage-bind record doesn't match its call");
    }
    return { index: b.index, path: b.path, mode: b.mode, dev: rec.dev, ino: rec.ino };
  };

  const status = async (agent, left, signal) => {
    const props = ["ActiveState", "SubState", "Result", "ExecMainCode", "ExecMainStatus", "ConditionResult"];
    return parseShow((await ctl(["show", ...props.flatMap((p) => ["-p", p]), unitOf(agent)], left(), signal)).stdout);
  };
  const isFailed = (s) => s.ActiveState === "failed" || s.SubState === "auto-restart" || (s.ActiveState === "inactive" && s.Result !== "success");
  /** A failed unit's reason: ExecMainCode 1 is CLD_EXITED, so ExecMainStatus is the launcher's exit; a signal or anything
   * else is unit_failed. Throws: a typed FleetError, or host-side for 64 and 72. */
  const failure = (s) => {
    const reason = s.ExecMainCode === "1" ? launcherExit(Number(s.ExecMainStatus)) : "unit_failed";
    if (reason === null) throw hostFail("the launcher reported a host-side failure");
    throw new FleetError(reason, "the agent's unit didn't start");
  };

  /** Step 6: watch the started unit until it has run for settleMs, or failed; map a failure to its reason. */
  const settle = async (agent, left, signal) => {
    const runningSince = { t: null };
    for (;;) {
      const s = await status(agent, left, signal);
      if (isFailed(s)) failure(s);
      if (s.ActiveState === "inactive" && s.ConditionResult === "no") throw hostFail("systemd skipped the start (a condition)");
      if (s.ActiveState === "inactive") return; // it ran and exited cleanly: the start happened
      if (s.ActiveState === "active" && s.SubState === "running") {
        runningSince.t ??= Date.now();
        if (Date.now() - runningSince.t >= settleMs) return;
      } else runningSince.t = null;
      if (left() <= POLL_MS) throw hostFail("the unit didn't settle in time");
      await sleep(POLL_MS, signal);
    }
  };

  return {
    ...adapters,
    sys,
    provision,
    mask: (agent, ms, signal) => ctl(["mask", "--runtime", unitOf(agent)], ms, signal).then(() => {}),
    unmask: (agent, ms, signal) => ctl(["unmask", "--runtime", unitOf(agent)], ms, signal).then(() => {}),
    stopUnit: (agent, ms, signal) => ctl(["stop", unitOf(agent)], ms, signal).then(() => {}),
    freeze: (agent, ms, signal) => ctl(["freeze", unitOf(agent)], ms, signal).then(() => {}),
    thaw: (agent, ms, signal) => ctl(["thaw", unitOf(agent)], ms, signal).then(() => {}),
    daemonReload: (ms, signal) => ctl(["daemon-reload"], ms, signal).then(() => {}),
    /** true only for "active"; is-active's exit 3 (inactive, failed, …) is false; anything else is unknown (throws). */
    isActive: async (agent, ms, signal) => {
      const r = await run(["systemctl", "is-active", unitOf(agent)], { ms, signal });
      if (r.code === 0 && r.stdout.trim() === "active") return true;
      if (r.code === 3) return false;
      throw hostFail("is-active is unknown");
    },
    /** The unit's cgroup process count; a cgroup systemd doesn't report is 0, an unreadable one throws. */
    procCount: async (agent, ms, signal) => {
      const r = await ctl(["show", "-p", "ControlGroup", "--value", unitOf(agent)], ms, signal);
      const cg = r.stdout.trim();
      if (!cg) return 0;
      return countProcs(at(join("/sys/fs/cgroup", cg)), fsx);
    },
    writeUnit: async (agent, uid, grantAgent, ms, signal) => {
      signal?.throwIfAborted();
      const { name, text, digest } = renderUnit(grantAgent, ctxFor(grantAgent, uid));
      const contract = at(CONTRACT(agent));
      if (removeIfThere(contract)) fsyncDir(dirname(contract));
      writeDurable(at(UNIT_DIR), name, text, undefined, 0o644);
      return { digest };
    },
    start: async (agent, ms, signal) => {
      const t0 = Date.now();
      const left = () => ms - (Date.now() - t0);
      const { grantAgent, uid, gid, net } = lookup(agent);
      if ((grantAgent.id ?? grantAgent.agent) !== agent) throw hostFail("lookup returned another agent");
      const plan = stagingPlan(grantAgent);
      await freshStaging(agent, plan, left, signal);
      const records = [];
      for (const b of plan) {
        const r = await run([`${host.release}/bin/sagebrush-agent-launch`, "stage-bind", "--agent", agent, "--index", String(b.index),
          "--mode", b.mode, "--path", b.path, "--record", b.record], { ms: left(), signal });
        if (r.code === 66) throw new FleetError("preflight_missing", "a granted path can't be staged");
        if (r.code !== 0) throw hostFail(`stage-bind exited ${r.code}`);
        records.push(readRecord(b));
      }
      const bytes = launcherContract(grantAgent, ctxFor(grantAgent, uid), records, net);
      const contract = at(CONTRACT(agent));
      writeDurable(dirname(contract), basename(contract), bytes, undefined, 0o640);
      fsx.chownSync(contract, rootUid, gid);
      signal?.throwIfAborted();
      const r = await run(["systemctl", "start", unitOf(agent)], { ms: left(), signal });
      if (r.code !== 0) {
        // A start that systemctl reports failed is never taken as started: either the unit failed (mapped), or it is
        // host-side (masked, missing, a job that failed before the launcher ran).
        const s = await status(agent, left, signal);
        if (isFailed(s)) failure(s);
        throw hostFail(`systemctl start exited ${r.code}`);
      }
      await settle(agent, left, signal);
    },
  };
}
