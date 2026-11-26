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
// (lease off: `lease: null`, `restoreResume: null`; on, only when leaseQualified() holds: the lease machine and the
// restore resume, lease-on r1.6 §1), recovery, one chain sync, serving.
//
// The signing key is used in memory only: nothing here prints, records or throws a key or anything derived from one.

import fs from "node:fs";
import { availableParallelism, totalmem } from "node:os";
import { dirname, isAbsolute, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { FleetError, refuse } from "../bytes.mjs";
import { checkTransferForHost, deviceKey, verifyTransferReceipt } from "../index.mjs";
import { ChainSync, SYNC_EVERY_MS, SYNC_MS, chainAdopter } from "./chain-sync.mjs";
import { runArgv } from "./effects.mjs";
import { launcherRunner } from "./restore-adapters.mjs";
import { anyRestoreScope, restoreTicker, restoreWorkerSeam } from "./restore-wiring.mjs";
import { Supervisor } from "./executor.mjs";
import { realSystemd, stop as fencedStop } from "./fence.mjs";
import { verifyGrant } from "./grant.mjs";
import { hostSystemdPreflight } from "./host-preflight.mjs";
import { hostRecordsFromCert } from "./host-records.mjs";
import { HostStore } from "./host-store.mjs";
import { classify, completeReset, dropOrphans, firstBoot, hostPaths, resetIdentity, takeOwnership } from "./identity.mjs";
import { runHelper } from "./lease.mjs";
import { leaseDeps } from "./lease-client.mjs";
import { LeaseMachine } from "./lease-machine.mjs";
import { leaseQualified } from "./lease-qualified.mjs";
import { BROKER_UNIT, BROKER_USER, HOST_CONFIG, HOST_STORE, SUPERVISOR_UNIT } from "./names.mjs";
import { expectedOf, readPlan } from "./restore-plan.mjs";
import { restoreReady } from "./restore-record.mjs";
import { RESUME_HELPER_MS, requestResume } from "./restore-resume.mjs";
import { brokerUidEmpty } from "./uid-proof.mjs";
import { hostEffects } from "./wiring.mjs";

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
  const containThenRefuse = async (reason, item) => {
    if (!(await contain())) return { code: 3, refused: null };
    if (item === undefined) return refused(reason);
    say({ refused: reason, item }); // (the qualification's failing item: a fixed token, never a path or value)
    return { code: 3, refused: reason };
  };
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
    // The qualification, computed once here, before the setting is acted on (lease-on r1.6 §1, §2): no record, or any
    // binding that doesn't hold, refuses after containment, naming the failing item.
    let leaseOn = false;
    if (config.lease === "on") {
      let q;
      try { q = await d.leaseQualified(); } catch { q = { ok: false, why: "unreadable" }; }
      if (q?.ok !== true) return await containThenRefuse("lease_unqualified", typeof q?.why === "string" ? q.why : "unreadable");
      leaseOn = true;
    }
    if (!ADAPTERS.every((k) => typeof d.adapters?.[k] === "function")) return await containThenRefuse("preflight_missing");
    await d.unmaskBroker();
    const store = await d.openStore();
    try { return await serve(id, store, leaseOn); } finally { await store.close(); }
  }

  async function serve(id, store, leaseOn) {
    const { pin, cert } = id;
    let sup = null, endedNow, provenEnd = false;
    const ended = new Promise((r) => { endedNow = r; });
    const adoptions = [];
    // Only an adoption that PROVED its stop and committed ends the daemon as host_ended; one still proving it keeps
    // the daemon (and its lock) where it is until it proves or SIGTERM closes it.
    const submit = async (op) => {
      const p = sup.submit(op);
      if (op?.kind === "chain-adopt") adoptions.push(p);
      const r = await p;
      if (sup.revoked && r?.proven === true) { provenEnd = true; endedNow(); }
      return r;
    };
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
    // Lease on (qualified): the lease machine, its requests signed with the certified key and sent to the pinned
    // origin, its chain read at each use; and the restore resume, its base frozen, its chain read per call (r1.6 §1).
    let lease = null, restoreResume = null;
    if (leaseOn) {
      const deps = leaseDeps({ aud: pin.aud, fleet: pin.fleet, signer: id.keys.sign, cert, chain: () => sync.snapshot(), origin: pin.aud,
        onChainBehind: () => { sync.sync().catch(() => {}); }, ...(d.leaseFetch ? { fetch: d.leaseFetch } : {}) });
      lease = d.makeLease({ verify: deps.verify, context: deps.context, sign: deps.sign, send: deps.send, submit: (op) => sup.submit(op) });
      const tagsOf = (a) => [...(store.registry.agent(a)?.tags ?? [])];
      const base = resumeBase({
        restoreState: (a) => { const plan = d.readPlan(); return plan === null ? "none" : d.restoreReady(a, tagsOf(a), expectedOf(plan)); },
        tagsOf, pairOf: d.pairOf, verifyTransferReceipt, checkTransferForHost, aud: pin.aud, fleet: pin.fleet,
        host: hostRecordsFromCert(store, cert), run: d.runHelper, node: process.execPath, main: d.resumeMain, ms: RESUME_HELPER_MS,
      });
      restoreResume = resumeRequester(base, () => sync.snapshot(), d.requestResume);
    }
    // The host restore's worker seam (restore e2e §3): hold for the lifecycle ops, dispatch for the timer below.
    const restoreWorker = d.restoreWorker ? d.restoreWorker({ store }) : null;
    sup = d.makeSupervisor({ store, fx, verify, bodyOf, lease, restoreResume, chain, ...(restoreWorker ? { restoreWorker } : {}) });
    // Recovery, then one chain sync (completed, failed, or past its deadline), each cut short by SIGTERM: a stop is
    // never held back by the sync's deadline, so the drain fits the unit's stop timeout.
    const stopping = term.then(() => TERM);
    const recovery = sup.recover().then(() => null);
    recovery.catch(() => {}); // (after SIGTERM the close ends it with Closing; before, a failure still throws below)
    if ((await Promise.race([recovery, stopping])) !== TERM) {
      await Promise.race([sync.sync().catch(() => null), d.sleep(INITIAL_SYNC_MS), stopping]);
    }
    let stopInputs = null, why, reopenTimer = null, dispatchTimer = null;
    if (termed) why = "term";
    else if (provenEnd) why = "ended";
    else {
      // Revoked with its stop still unproven: nothing is served (no timer, no inputs); wait for the proof or SIGTERM.
      if (!sup.revoked) {
        sync.start({ first: SYNC_EVERY_MS });
        stopInputs = d.inputs ? d.inputs({ submit: (op) => sup.submit(op) }) : null;
        // The suspend gate's reopen (lease-on r1.5 §6.5, C8): once now, before serving, then every 2 minutes, in both
        // settings, as executor ops (a no-op unless the hook finished a suspend that isn't reopened yet).
        // The first reopen is raced with SIGTERM and the end: neither waits on it, and the drain's close cuts it short.
        let first = null;
        if (d.sleepReopenMs) {
          first = await Promise.race([sup.submit({ kind: "sleep-reopen", authority: "host" }).then(() => null, () => null),
            term.then(() => "term"), ended.then(() => "ended")]);
          if (first === null) reopenTimer = d.every(() => { sup.submit({ kind: "sleep-reopen", authority: "host" }).catch(() => {}); }, d.sleepReopenMs);
        }
        // The restore's dispatch, every restoreDispatchMs as an executor op: idle unless a begun, open restore has a set
        // to fill (at most one worker per host, started detached; restore-worker.mjs dispatchOnce).
        if (first === null && restoreWorker && d.restoreDispatchMs) {
          // (and, by the same timer, the agent sets' imports: files_validated to validated, R4-d2b §2). Coalesced: at most
          // one of each queued or running, whatever the number of ticks meanwhile.
          dispatchTimer = d.every(restoreTicker((x) => sup.submit(x)), d.restoreDispatchMs);
        }
        if (first === null) say({ state: "PAIRED", serving: true });
        why = first;
      }
      why ??= await Promise.race([term.then(() => "term"), ended.then(() => "ended")]);
    }
    sync.stop();
    if (reopenTimer !== null) d.clearEvery(reopenTimer);
    if (dispatchTimer !== null) d.clearEvery(dispatchTimer);
    if (typeof stopInputs === "function") stopInputs();
    await sup.close();
    if (why === "ended") return refused("host_ended");
    // SIGTERM: an adoption that ended the certificate and was still proving its stop ends uncommitted at the close,
    // a SIGTERM during an unproven containment (§2.1): exit 3. One that proved it is host_ended.
    if (sup.revoked) {
      const done = await Promise.allSettled(adoptions);
      if (done.some((x) => x.value?.status === "revoked" && x.value.proven === true)) return refused("host_ended");
      say({ containment: "unproven" });
      return { code: 3, refused: null };
    }
    return { code: 0 };
  }
}

/** The restore resume's base keys (lease-on r1.6 §1): each the supervisor's, none a lease or a chain. */
export const RESUME_BASE_KEYS = Object.freeze(["restoreState", "tagsOf", "pairOf", "verifyTransferReceipt", "checkTransferForHost", "aud", "fleet",
  "host", "run", "node", "main", "ms"]);

/**
 * The restore resume's frozen base: exactly RESUME_BASE_KEYS. A `liveLease` or `verifyCtx` key (or any other) refuses
 * (bad_form): a lease reaches the resume only per call, from the executor, and the chain only per call, here.
 */
export function resumeBase(o) {
  const keys = o !== null && typeof o === "object" ? Reflect.ownKeys(o) : null;
  if (keys === null || keys.includes("liveLease") || keys.includes("verifyCtx")) refuse("bad_form", "restore resume: no lease or chain in the base");
  if (keys.length !== RESUME_BASE_KEYS.length || !RESUME_BASE_KEYS.every((k) => keys.includes(k))) refuse("bad_form", "restore resume: the base's keys");
  return Object.freeze({ ...o });
}

/**
 * The executor's restoreResume: `request(agent, extra)` takes EXACTLY `liveLease` (a function) from `extra` (C1): any
 * other key refuses (bad_form) before any effect, and `extra` is never spread over the base. The verification context
 * is built per call, with the chain read at that moment (H2(a)).
 */
export function resumeRequester(base, chainNow, request = requestResume) {
  if (!Object.isFrozen(base) || typeof chainNow !== "function" || typeof request !== "function") refuse("bad_form", "restore resume: bad wiring");
  return Object.freeze({
    request: async (agent, extra) => {
      const keys = extra !== null && typeof extra === "object" ? Reflect.ownKeys(extra) : null;
      if (keys === null || keys.length !== 1 || keys[0] !== "liveLease" || typeof extra.liveLease !== "function") {
        refuse("bad_form", "restore resume: only the live lease comes per call");
      }
      const liveLease = extra.liveLease;
      return request(agent, { ...base, liveLease, verifyCtx: { aud: base.aud, fleet: base.fleet, chain: chainNow() } });
    },
  });
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

/**
 * Resolves at SIGTERM. It holds the process open until then: a signal listener alone keeps no event loop alive, and an
 * idle daemon (FRESH, PAIRING) has nothing else pending, so without this Node would end it at once.
 */
export function untilSigterm(proc = process) {
  return new Promise((r) => {
    const hold = setInterval(() => {}, 2 ** 30);
    proc.once("SIGTERM", () => { clearInterval(hold); r(); });
  });
}

/** The host's own wiring. */
export function realDeps() {
  const release = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
  const run = runArgv;
  const brokerUid = () => brokerAccount()?.uid ?? -1;
  const host = { release, cliPath: {}, hostAddrs: [], quota: null };
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
    leaseQualified: () => leaseQualified(release),
    makeLease: (o) => new LeaseMachine(o),
    leaseFetch: null,
    readPlan: () => readPlan(),
    restoreReady,
    pairOf: () => null, // (the grant intake writes the pairs and brings their reader; until then no resume has a pair)
    runHelper: (argv, o) => runHelper(argv, o),
    resumeMain: fileURLToPath(new URL("./restore-resume-main.mjs", import.meta.url)),
    requestResume,
    sleepReopenMs: 120000,
    // The host restore's worker seam over the trusted launcher; its dispatch every 30 seconds.
    restoreWorker: ({ store }) => restoreWorkerSeam({
      store, launch: launcherRunner({ run: runArgv, launcher: `${release}/bin/sagebrush-agent-launch` }), mount: host.quota?.mount ?? "/", // (the same mount the host's effects use: wiring.mjs)
      main: fileURLToPath(new URL("./restore-worker-main.mjs", import.meta.url)),
      isActive: async (unit) => (await runArgv(["systemctl", "is-active", "--quiet", unit], { ms: 2000 }).catch(() => ({ code: 1 }))).code === 0,
      // Gone: systemd reports it inactive or unknown (a collected scope); unsure is never gone.
      isGone: async (unit) => {
        const r = await runArgv(["systemctl", "show", "-p", "ActiveState", "--value", unit], { ms: 2000 }).catch(() => null);
        return r?.code === 0 && ["inactive", ""].includes(String(r.stdout).trim());
      },
      killUnit: async (unit) => { await runArgv(["systemctl", "kill", "--signal=SIGKILL", unit], { ms: 2000 }).catch(() => {}); },
      anyWorker: anyRestoreScope({ run: runArgv }),
    }),
    restoreDispatchMs: 30000,
    every: (fn, ms) => { const t = setInterval(fn, ms); t.unref?.(); return t; },
    clearEvery: (t) => clearInterval(t),
    makeSync: (o) => new ChainSync(o),
    host,
    hostInfo: { ramMb: Math.floor(totalmem() / 2 ** 20), cpus: availableParallelism() },
    inputs: null, // (G3: the grant transport and person ops attach here when they land)
    wall: Date.now,
    sleep: (ms) => new Promise((r) => { setTimeout(r, ms); }),
    terminated: untilSigterm(),
    out: (s) => { process.stderr.write(`${s}\n`); },
  };
}

/** `sagebrush-agent host <command>`: resolves the exit status. */
export async function main(argv) {
  const [cmd, ...rest] = argv;
  // The person's restore commands (root console; R6-d1): one JSON line on stdout, no supervisor needed.
  if (cmd === "restore") {
    const { restoreCommand } = await import("./restore-cli.mjs");
    const out = await restoreCommand(rest);
    if (out.code === 2) { process.stderr.write(`${out.usage}\n`); return 2; }
    process.stdout.write(`${JSON.stringify(out.line)}\n`);
    return out.code;
  }
  // Attach to an existing backup store without enabling backup (attach-d3): the input on stdin, one JSON line out.
  if (cmd === "backup") {
    const { backupAttachCommand } = await import("./backup-attach.mjs");
    const out = await backupAttachCommand(rest);
    if (out.code === 2) { process.stderr.write(`${out.usage}\n`); return 2; }
    process.stdout.write(`${JSON.stringify(out.line)}\n`);
    return out.code;
  }
  if (!["run", "reset-identity"].includes(cmd) || rest.length !== 0) {
    process.stderr.write("usage: sagebrush-agent host run | reset-identity | restore list | restore begin <snapshot> | restore status | restore retry <kind>-<id> | restore close | backup attach [--discard]\n");
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
