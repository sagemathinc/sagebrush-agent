// Host supervisor (design: agent-autonomous-host-daemon-main r1.1, implementing host daemon r2.5 §1, §3.0, §3.1, §4, §7,
// §8): the daemon's main. Two short root commands, run by systemd or by the person, never by a shell:
//   sagebrush-agent host run              the daemon (sagebrush-supervisor.service)
//   sagebrush-agent host reset-identity   the reset (§3.3), with the daemon's unit stopped
// Each refusal is ONE line on stderr, {"v":1,"refused":"<reason>"} with a registered host reason, and exit status 3;
// the unit's RestartPreventExitStatus=3 keeps systemd from starting it again until the person does.
//
// `hostRun(d)` and `hostResetIdentity(d)` take every outside effect in `d` (the rows inject fakes; `realDeps()` wires
// the host). The order (r1.1 §2): preflight; the ownership lock; the pinned systemd, KEPT; classify once; contain when
// the state isn't PAIRED or the pin is bad (§2.1: the whole operation, retried every 10 s while unproven, never
// advancing and never exiting on its own); a bad pin refuses before any state action; then the state. PAIRED: orphans,
// the lease setting, the adapters (each refusal contained first), the broker's unmask, the store, the executor
// (lease off: `lease: null`, `restoreResume: null`), recovery, one chain sync, serving.
//
// The signing key is used in memory only: nothing here prints, records or throws a key or anything derived from one.

import fs from "node:fs";
import { availableParallelism, totalmem } from "node:os";
import { dirname, isAbsolute, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { FleetError, refuse } from "../bytes.mjs";
import { deviceKey } from "../index.mjs";
import { ChainSync, SYNC_EVERY_MS, SYNC_MS, chainAdopter } from "./chain-sync.mjs";
import { runArgv } from "./effects.mjs";
import { Supervisor } from "./executor.mjs";
import { realSystemd, stop as fencedStop } from "./fence.mjs";
import { verifyGrant } from "./grant.mjs";
import { hostSystemdPreflight } from "./host-preflight.mjs";
import { HostStore } from "./host-store.mjs";
import { classify, completeReset, dropOrphans, firstBoot, hostPaths, resetIdentity, takeOwnership } from "./identity.mjs";
import { BROKER_UNIT, BROKER_USER, HOST_CONFIG, HOST_STORE, SUPERVISOR_UNIT } from "./names.mjs";
import { brokerUidEmpty } from "./uid-proof.mjs";
import { hostEffects } from "./wiring.mjs";

/** The execution lease is refused until this release is qualified for it (r2.5 §8). No runtime override. */
export const LEASE_QUALIFIED = false;
/** The unproven containment's retry interval (r1.1 §2.1). */
export const CONTAIN_RETRY_MS = 10_000;
/** The initial chain sync's deadline: SYNC_MS for each of at most 4 pages (r1.1 §2 step 12). */
export const INITIAL_SYNC_MS = 4 * SYNC_MS;
/** The settings file's size bound (r1.1 §2 step 8). */
export const CONFIG_MAX = 4096;
/** The time `systemctl --version` may take (the start preflight's). */
export const SYSTEMD_MS = 10_000;
/** The effects' adapters, each owned by its own lane (G2): any missing refuses `preflight_missing`. */
export const ADAPTERS = Object.freeze(["appendIntent", "openIntents", "audit", "brokerGen", "brokerRevoke", "publishMap", "sendAck"]);

const TERM = Symbol("term");
const { O_RDONLY, O_NOFOLLOW, O_NONBLOCK } = fs.constants;

/**
 * The host's settings, `/etc/sagebrush/host.json` (r2.5 §8; r1.1 §2 step 8): `{ lease: "off" | "on" }`. Absent, or no
 * `execution_lease`, is off. Read once by descriptor: no link, a regular file owned by `rootUid` with no group or other
 * write, at most CONFIG_MAX bytes, a JSON object whose only key may be `execution_lease`, "off" or "on". Anything else
 * throws (bad_form, `config: true`): the caller refuses `bad_config`.
 */
export function readHostConfig(path = HOST_CONFIG, { fsx = fs, rootUid = 0 } = {}) {
  const bad = (why) => { throw Object.assign(new FleetError("bad_form", `host config: ${why}`), { config: true }); };
  let before;
  try { before = fsx.lstatSync(path); } catch (e) { if (e?.code === "ENOENT") return { lease: "off" }; bad("unreadable"); }
  if (!before.isFile()) bad("not a plain file");
  let fd;
  try { fd = fsx.openSync(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK); } catch { bad("unreadable"); }
  let text;
  try {
    const st = fsx.fstatSync(fd);
    if (!st.isFile() || st.dev !== before.dev || st.ino !== before.ino) bad("not the file looked at");
    if (st.uid !== rootUid || (st.mode & 0o022) !== 0) bad("not root's alone");
    if (st.size > CONFIG_MAX) bad("too large");
    const buf = Buffer.alloc(st.size);
    for (let off = 0; off < buf.length;) {
      const k = fsx.readSync(fd, buf, off, buf.length - off, off);
      if (k <= 0) bad("changed while read");
      off += k;
    }
    text = buf.toString("utf8");
  } finally { fsx.closeSync(fd); }
  let o;
  try { o = JSON.parse(text); } catch { bad("not JSON"); }
  if (o === null || typeof o !== "object" || Array.isArray(o)) bad("not an object");
  if (Object.keys(o).some((k) => k !== "execution_lease")) bad("an unknown key");
  const v = Object.hasOwn(o, "execution_lease") ? o.execution_lease : "off";
  if (v !== "off" && v !== "on") bad("an unknown execution_lease");
  return { lease: v };
}

/** The daemon's unit file (r1.1 §1) for a release at the absolute path `release`. */
export function supervisorUnit(release) {
  if (typeof release !== "string" || !isAbsolute(release) || /[\s"'\\%$]/.test(release)) refuse("bad_form", "supervisor unit: the release must be a plain absolute path");
  const text = fs.readFileSync(new URL(`./units/${SUPERVISOR_UNIT}`, import.meta.url), "utf8");
  return text.replaceAll("@RELEASE@", release);
}

/** A grant's body from bytes accepted earlier (no checks: the executor's bodyOf). */
export const bodyOf = (bytes) => JSON.parse(Buffer.from(bytes).toString("utf8")).body;

/** The shared start: preflight (step 1), then the lock (step 2). Resolves { refused } or { broker, lock }. */
async function own(d) {
  if (!d.isRoot() || !d.isLinux()) return { refused: "preflight_missing" };
  const broker = d.brokerAccount();
  if (!broker || !Number.isSafeInteger(broker.uid) || broker.uid <= 0) return { refused: "preflight_missing" };
  try { return { broker, lock: await d.takeOwnership(d.paths, { rootUid: d.rootUid }) }; } catch (e) {
    if (e?.code === "in_progress") return { refused: "busy" };
    if (e?.code === "bad_form") return { refused: "identity_broken" };
    throw e;
  }
}

/**
 * `host run` (r1.1 §2). Resolves { code } once the daemon is done: 0 after a SIGTERM drain (or an idle FRESH/PAIRING
 * stop), 3 after a refusal or a SIGTERM during an unproven containment.
 */
export async function hostRun(d) {
  const say = (o) => d.out(JSON.stringify({ v: 1, ...o }));
  const refused = (reason) => { say({ refused: reason }); return { code: 3, refused: reason }; };
  let termed = false;
  const term = d.terminated.then(() => { termed = true; return TERM; });

  /** One containment attempt (§2.1 steps 1–4), the whole operation; true only if every part is proven. */
  const attempt = async () => {
    let agents = false, broker = false;
    try { agents = (await d.sys.stopAll())?.proven === true; } catch { agents = false; }
    try { broker = (await d.sys.stopBroker())?.proven === true; } catch { broker = false; }
    return agents && broker;
  };
  /** Wait out the retry interval; false if SIGTERM came first (the unproven line is said once more). */
  const retryWait = async () => {
    say({ containment: "unproven" });
    const r = termed ? TERM : await Promise.race([d.sleep(CONTAIN_RETRY_MS), term]);
    if (r !== TERM) return true;
    say({ containment: "unproven" });
    return false;
  };
  /** Contain until proven; false only on SIGTERM while unproven. */
  const contain = async () => {
    for (;;) {
      if (await attempt()) return true;
      if (!(await retryWait())) return false;
    }
  };
  const containThenRefuse = async (reason) => ((await contain()) ? refused(reason) : { code: 3, refused: null });
  const idle = async (state) => { say({ state }); await term; return { code: 0 }; };

  const o = await own(d);
  if (o.refused) return refused(o.refused);
  const { broker, lock } = o;
  try {
    const pinBad = (await hostSystemdPreflight(d.systemdVersion, SYSTEMD_MS)) !== null; // kept, not acted on yet
    const id = await d.classify(d.paths, { machineId: d.machineId, brokerUid: broker.uid, rootUid: d.rootUid });
    if ((id.state !== "PAIRED" || pinBad) && !(await contain())) return { code: 3, refused: null };
    if (pinBad) return refused("qualify_required");
    switch (id.state) {
      case "RESETTING": {
        for (;;) {
          try { await d.completeReset(d.paths, d.sys, { rootUid: d.rootUid }); break; } catch (e) {
            if (e?.code === "bad_form") return refused("identity_broken");
            if (e?.code !== "not_empty") throw e;
            if (!(await retryWait())) return { code: 3, refused: null };
          }
        }
        d.firstBoot(d.paths, { machineId: d.machineId, brokerUid: broker.uid, chown: d.chownBroker(broker) });
        return await idle("FRESH");
      }
      case "NO_KEYS":
        d.firstBoot(d.paths, { machineId: d.machineId, brokerUid: broker.uid, chown: d.chownBroker(broker) });
        return await idle("FRESH");
      case "FRESH": case "PAIRING": return await idle(id.state);
      case "REVOKED": return refused("host_ended");
      case "CLONE": return refused("clone_detected");
      case "PAIRED": return await paired(id);
      default: return refused("identity_broken");
    }
  } finally { await lock.release(); }

  async function paired(id) {
    d.dropOrphans(d.paths, id.orphans);
    let config;
    try { config = d.readConfig(); } catch { return await containThenRefuse("bad_config"); }
    if (config.lease === "on") return await containThenRefuse("lease_unqualified"); // (LEASE_QUALIFIED is false: the lease-on path is a later change)
    if (!ADAPTERS.every((k) => typeof d.adapters?.[k] === "function")) return await containThenRefuse("preflight_missing");
    await d.unmaskBroker();
    const store = await d.openStore();
    try { return await serve(id, store); } finally { await store.close(); }
  }

  async function serve(id, store) {
    const { pin, cert } = id;
    let sup = null, endedNow;
    const ended = new Promise((r) => { endedNow = r; });
    const submit = async (op) => { const r = await sup.submit(op); if (sup.revoked) endedNow(); return r; };
    const sync = d.makeSync({ snapshot: id.chain, aud: pin.aud, fleet: pin.fleet, host: cert.body.host, signer: id.keys.sign,
      gen: () => store.grants.highwater.gen, submit, origin: pin.aud });
    // r2.5 §5: the snapshot read ONCE per call; the wall clock sampled at the call; a signer above the pin asks for a sync.
    const ctxAt = (state, now) => ({ aud: pin.aud, fleet: pin.fleet, host: cert.body.host, cert: cert.hash, now,
      resolveKey: (signer, _type, body) => deviceKey(state, signer, body?.chain_seq).raw, hostInfo: d.hostInfo });
    const verify = (bytes) => {
      const snap = sync.snapshot();
      try { return verifyGrant(bytes, ctxAt(snap, d.wall())); } catch (e) {
        if (e?.code === "device_unknown") sync.sync().catch(() => {});
        throw e;
      }
    };
    const chain = chainAdopter({ paths: d.paths, certBytes: id.certBytes, keys: id.keys, pin, sync, rootUid: d.rootUid, now: d.wall,
      grantValidAt: async (state, bytes, now) => verifyGrant(bytes, ctxAt(state, now)) });
    const fx = d.effects({ store, bodyOf, host: d.host, adapters: d.adapters });
    sup = d.makeSupervisor({ store, fx, verify, bodyOf, lease: null, restoreResume: null, chain });
    await sup.recover();
    await Promise.race([sync.sync().catch(() => null), d.sleep(INITIAL_SYNC_MS)]);
    if (sup.revoked) { sync.stop(); return refused("host_ended"); }
    sync.start({ first: SYNC_EVERY_MS });
    const stopInputs = d.inputs ? d.inputs({ submit: (op) => sup.submit(op) }) : null;
    say({ state: "PAIRED", serving: true });
    const why = await Promise.race([term.then(() => "term"), ended.then(() => "ended")]);
    sync.stop();
    if (typeof stopInputs === "function") stopInputs();
    if (why === "ended") return refused("host_ended");
    await sup.close();
    return { code: 0 };
  }
}

/** `host reset-identity` (r1.1 §3). Resolves { code }: 0 done (NO_KEYS), 3 refused or unproven. */
export async function hostResetIdentity(d) {
  const say = (o) => d.out(JSON.stringify({ v: 1, ...o }));
  const o = await own(d);
  if (o.refused === "busy") { say({ refused: "busy", unit: SUPERVISOR_UNIT, next: "stop the unit first" }); return { code: 3, refused: "busy" }; }
  if (o.refused) { say({ refused: o.refused }); return { code: 3, refused: o.refused }; }
  try {
    try { await d.resetIdentity(d.paths, d.sys, { rootUid: d.rootUid }); } catch (e) {
      if (e?.code === "not_empty") { say({ containment: "unproven" }); return { code: 3, refused: null }; }
      if (e?.code === "bad_form") { say({ refused: "identity_broken" }); return { code: 3, refused: "identity_broken" }; }
      throw e;
    }
    say({ state: "NO_KEYS" });
    return { code: 0 };
  } finally { await o.lock.release(); }
}

/**
 * The containment's real effects (§2.1), for the broker uid `brokerUid`:
 * - stopAll: `all` raised and every agent slice stopped with the fenced stop, proven ("stopped and fenced");
 * - stopBroker: the broker unit runtime-masked, then stopped; proven only if it is inactive, masked-runtime, its cgroup
 *   is empty, and no process, user manager, linger file or session holds the broker's uid anywhere on the host.
 */
export function realContainSys(brokerUid, { run = runArgv, sys = realSystemd, stopAll = (o) => fencedStop({ all: true }, "all", o), uidEmpty = brokerUidEmpty, ms = 15_000 } = {}) {
  return Object.freeze({
    stopAll: async () => ({ proven: (await stopAll({ sys })).status === "stopped and fenced" }),
    stopBroker: async () => {
      const mask = await run(["systemctl", "mask", "--runtime", BROKER_UNIT], { ms });
      await run(["systemctl", "stop", BROKER_UNIT], { ms });
      const active = String((await run(["systemctl", "is-active", BROKER_UNIT], { ms })).stdout ?? "").trim();
      const enabled = String((await run(["systemctl", "is-enabled", BROKER_UNIT], { ms })).stdout ?? "").trim();
      const procs = sys.procCount(BROKER_UNIT, ms);
      const uid = await uidEmpty(brokerUid, { run, ms });
      return { proven: mask.code === 0 && ["inactive", "failed"].includes(active) && enabled === "masked-runtime" && procs === 0 && uid.empty === true };
    },
  });
}

/** The broker's account from /etc/passwd: { uid, gid }, or null if there is none. */
export function brokerAccount({ fsx = fs, root = "" } = {}) {
  let text;
  try { text = fsx.readFileSync(`${root}/etc/passwd`, "utf8"); } catch { return null; }
  for (const line of text.split("\n")) {
    const f = line.split(":");
    if (f[0] === BROKER_USER && /^[0-9]+$/.test(f[2] ?? "") && /^[0-9]+$/.test(f[3] ?? "")) return { uid: Number(f[2]), gid: Number(f[3]) };
  }
  return null;
}

/** The host's own wiring. */
export function realDeps() {
  const release = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
  const run = runArgv;
  const brokerUid = () => brokerAccount()?.uid ?? -1;
  return {
    paths: hostPaths(""),
    rootUid: 0,
    isRoot: () => process.getuid?.() === 0,
    isLinux: () => process.platform === "linux",
    brokerAccount: () => brokerAccount(),
    takeOwnership,
    systemdVersion: async (ms, signal) => {
      const r = await run(["systemctl", "--version"], { ms, signal });
      if (r.code !== 0) throw new Error("systemctl --version failed");
      return r.stdout;
    },
    machineId: () => fs.readFileSync("/etc/machine-id", "utf8"),
    classify,
    get sys() { return realContainSys(brokerUid()); },
    completeReset,
    resetIdentity,
    firstBoot,
    dropOrphans,
    chownBroker: ({ uid, gid }) => (p) => fs.chownSync(p, uid, gid),
    readConfig: () => readHostConfig(HOST_CONFIG),
    adapters: {}, // (G2: the intent, audit, broker and ack adapters land with their lanes; until then PAIRED refuses)
    unmaskBroker: async () => {
      const r = await run(["systemctl", "unmask", "--runtime", BROKER_UNIT], { ms: 15_000 });
      if (r.code !== 0) throw new Error("the broker unit couldn't be unmasked");
    },
    openStore: () => HostStore.open(HOST_STORE),
    effects: (o) => hostEffects(o),
    makeSupervisor: (o) => new Supervisor(o),
    makeSync: (o) => new ChainSync(o),
    host: { release, cliPath: {}, hostAddrs: [], quota: null },
    hostInfo: { ramMb: Math.floor(totalmem() / 2 ** 20), cpus: availableParallelism() },
    inputs: null, // (G3: the grant transport and person ops attach here when they land)
    wall: Date.now,
    sleep: (ms) => new Promise((r) => { setTimeout(r, ms); }),
    terminated: new Promise((r) => { process.once("SIGTERM", r); }),
    out: (s) => { process.stderr.write(`${s}\n`); },
  };
}

/** `sagebrush-agent host <command>`: resolves the exit status. */
export async function main(argv) {
  const [cmd, ...rest] = argv;
  if (!["run", "reset-identity"].includes(cmd) || rest.length !== 0) {
    process.stderr.write("usage: sagebrush-agent host run | reset-identity\n");
    return 2;
  }
  const d = realDeps();
  try {
    return (cmd === "run" ? await hostRun(d) : await hostResetIdentity(d)).code;
  } catch (e) {
    // (only the code, never the message: no path, value or key reaches the line)
    d.out(JSON.stringify({ v: 1, failed: e instanceof FleetError ? e.code : "error" }));
    return 1;
  }
}
