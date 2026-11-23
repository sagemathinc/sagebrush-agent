// Host supervisor (design: agent-autonomous-host-supervisor-freeze-r3.1.md §3.3): the production effects, assembled
// from the host store. The executor (executor.mjs) takes `fx`; this builds it from its parts:
// - lookup(agent): the agent's entry in the CURRENT grant (the bytes GrantState holds since step 3 of applying it, read
//   with the executor's own bodyOf), its uid from the registry (its private gid is the same number), and its network
//   plan (net.mjs) for this host's addresses. An agent with no entry or no registry record is a host-side failure;
// - provisioning (provision.mjs), with each tag's gid from the registry and the host's quota setting;
// - the runtime state rebuilt at each start (runtime.mjs);
// - the systemd and launcher effects (effects.mjs), every command through runArgv.
// The broker, audit, intent and acknowledgement adapters are passed in: they belong to their own lanes.

import fs from "node:fs";
import { refuse } from "../bytes.mjs";
import { realEffects, runArgv } from "./effects.mjs";
import { planNetwork } from "./net.mjs";
import { provisioner } from "./provision.mjs";
import { runtime as runtimeOf } from "./runtime.mjs";

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
  });
  return realEffects({
    lookup: storeLookup({ store, bodyOf, hostAddrs: host.hostAddrs ?? [] }),
    host, adapters, run, fsx, root, rootUid, settleMs,
    provision: prov.provision,
    requota: prov.requota,
    runtime: runtimeOf({ run, fsx, root, rootUid, hostAddrs: host.hostAddrs ?? [], uidOf: (agent) => store.registry.agent(agent)?.uid ?? null }),
  });
}
