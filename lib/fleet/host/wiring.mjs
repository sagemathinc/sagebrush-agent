// Host supervisor (design: agent-autonomous-host-supervisor-freeze-r3.1.md §3.3): the production effects, assembled
// from the host store. The executor (executor.mjs) takes `fx`; this builds it from its parts:
// - lookup(agent): the agent's entry in the CURRENT grant (the bytes GrantState holds since step 3 of applying it, read
//   with the executor's own bodyOf), its uid from the registry (its private gid is the same number), and its network
//   plan (net.mjs) for this host's addresses. An agent with no entry or no registry record is a host-side failure;
// - provisioning (provision.mjs), with each tag's gid from the registry and the host's quota setting;
// - the runtime state rebuilt at each start (runtime.mjs);
// - the systemd and launcher effects (effects.mjs), every command through runArgv;
// - a deleted agent's deprovision pass (deprovision.mjs), from those same effects, the runtime's network removal, the
//   whole-host uid proof (uid-proof.mjs) and the pool policy's membership.
// The broker, audit, intent and acknowledgement adapters are passed in: they belong to their own lanes.

import fs from "node:fs";
import { refuse } from "../bytes.mjs";
import { realEffects, runArgv } from "./effects.mjs";
import { planNetwork } from "./net.mjs";
import { deprovisioner } from "./deprovision.mjs";
import { provisioner } from "./provision.mjs";
import { runtime as runtimeOf } from "./runtime.mjs";
import { uidEmpty } from "./uid-proof.mjs";

const hostFail = (what) => Object.assign(new Error(`wiring: ${what}`), { code: "effect_failed" });

/**
 * The lookup the start effect uses: { grantAgent, uid, gid, net } for `agent`, from the current grant and the
 * registry. `store` is the host store ({ grants, registry }); `bodyOf(bytes)` is the executor's.
 */
export function storeLookup({ store, bodyOf, hostAddrs = [] }) {
  if (!store?.grants || !store?.registry || typeof bodyOf !== "function") refuse("bad_form", "wiring: store and bodyOf are required");
  return (agent) => {
    const bytes = store.grants.currentBytes();
    if (!bytes) throw hostFail("no current grant");
    const grantAgent = bodyOf(bytes).agents.find((a) => a.agent === agent);
    const rec = store.registry.agent(agent);
    if (!grantAgent || !rec || !Number.isSafeInteger(rec.uid)) throw hostFail("the agent has no grant entry or registry record");
    return { grantAgent, uid: rec.uid, gid: rec.uid, net: planNetwork(grantAgent, { uid: rec.uid, hostAddrs }) };
  };
}

/**
 * The executor's `fx` for a real host. `host`: { release, cliPath: { claude, codex }, hostAddrs, quota: null |
 * { mount }, gpuNodes?, hostInfo? }. `adapters`: { appendIntent, openIntents, audit, brokerGen, brokerRevoke,
 * publishMap, sendAck }. Test seams as in effects.mjs.
 */
export function hostEffects({ store, bodyOf, host, adapters = {}, run = runArgv, fsx = fs, root = "", rootUid = 0, settleMs } = {}) {
  if (!host) refuse("bad_form", "wiring: host is required");
  const prov = provisioner({
    run, fsx, root, rootUid, quota: host.quota ?? null,
    tagGid: (tag) => store.registry.tag(tag)?.gid, // provision.mjs refuses one missing or outside the tag range
    // The trusted launcher checks the fixed parents through opened handles (launcher amendment A1 r2.2).
    checkParents: async (allowMissing, left, signal) => {
      const argv = [`${host.release}/bin/sagebrush-agent-launch`, "check-parents", "--mount", host.quota?.mount ?? "/", ...(allowMissing ? ["--allow-missing"] : [])];
      const r = await run(argv, { ms: left(), signal });
      if (r.code !== 0) throw Object.assign(new Error(`provision: the fixed parents failed their check (${r.code})`), { code: "effect_failed" });
    },
  });
  const launcher = `${host.release}/bin/sagebrush-agent-launch`;
  const mount = host.quota?.mount ?? "/";
  /** The launcher's inspect-home output for one tree, parsed; anything else is host-side. */
  const inspect = async (agent, tree, left, signal) => {
    const r = await run([launcher, "inspect-home", "--mount", mount, "--agent", agent, "--tree", tree], { ms: left(), signal });
    if (r.code !== 0) throw Object.assign(new Error(`provision: inspect-home ${tree} exited ${r.code}`), { code: "effect_failed" });
    try { return JSON.parse(r.stdout); } catch { throw Object.assign(new Error(`provision: inspect-home ${tree} printed no JSON`), { code: "effect_failed" }); }
  };
  /**
   * Provision, then record the trees' authoritative identity (provisioned.mjs; deprovision r3.2 §3.6) from the trusted
   * launcher: recorded once, verified unchanged in the same epoch, requalified only to the same durable objects in
   * another. A refusal is host-side: the agent isn't started on trees that aren't exactly its own.
   */
  const provision = async (agent, uid, grantAgent, ms, signal) => {
    const t0 = Date.now();
    const left = () => ms - (Date.now() - t0);
    await prov.provision(agent, uid, grantAgent, ms, signal);
    const home = await inspect(agent, "home", left, signal);
    const config = await inspect(agent, "config", left, signal);
    try { store.provisioned.adopt(agent, uid, host.quota != null, home, config); } catch (e) {
      throw Object.assign(new Error(`provision: the trees' identity: ${e.message}`), { code: "effect_failed" });
    }
  };
  const runtime = runtimeOf({ run, fsx, root, rootUid, hostAddrs: host.hostAddrs ?? [], uidOf: (agent) => store.registry.agent(agent)?.uid ?? null });
  const fx = realEffects({
    lookup: storeLookup({ store, bodyOf, hostAddrs: host.hostAddrs ?? [] }),
    host, adapters, run, fsx, root, rootUid, settleMs,
    provision,
    requota: prov.requota,
    runtime,
  });
  // Assembled on first use: the broker adapter belongs to its own lane, and a host without one fails here, host-side.
  let dp = null;
  fx.deprovision = async (agent, ms, signal) => {
    dp ??= deprovisioner({
      store, run, launcher, mount, fsx, root, rootUid,
      procCount: fx.procCount,
      uidProof: (uid, a, ms2, signal2) => uidEmpty(uid, a, { fsx, root, run, ms: ms2, signal: signal2 }),
      daemonReload: fx.daemonReload,
      removeNetwork: runtime.removeNetwork,
      brokerRevoke: adapters.brokerRevoke,
      inPool: (a) => store.pool.names(a),
    });
    return dp.pass(agent, ms, signal);
  };
  return fx;
}
