// Host supervisor (design: agent-autonomous-host-supervisor-freeze-r3.1.md §3.2–§3.4, §7): the executor. One work queue
// runs every input to completion or to a durable failure state, one at a time; stops, capability revocations, expiry
// and the local stop-all go to the front, and preempt an application at its next step boundary (or when the step's
// deadline passes).
//
// The effects are injected (`fx`): this module decides order, durability and failure handling only; the real systemd,
// users, directories, network and broker calls live in a separate module. Inputs arrive already authenticated by the
// caller (grant envelopes are checked here by `verify`; ops by their signature or channel, upstream); this module
// enforces which authority may do what: the service channel and the local CLI only narrow, a person also resumes and
// deletes.
//
// Effects are OWNED. Each one gets an AbortSignal and its deadline. Past the deadline the signal is aborted and the
// executor waits a short grace for the effect to settle. An effect that settles (done, failed or cancelled) is over:
// nothing of it can happen later. An effect that doesn't settle is "unsettled": it may still complete at any time, so
//   - if it concerns an agent, that agent is CONTAINED WITH A FENCE (below): its late completion can't start it (the
//     fence makes systemd skip any start, and a mask refuses one), and only a person's resume brings it back, which
//     regenerates its unit before starting it;
//   - and until every unsettled effect has settled, every normal input is refused (`in_progress`). Emergencies (stops,
//     revoke-caps, expiry, stop-all) still run: they only take authority away, behind fences.
// So no two effects ever overlap except a narrowing emergency with an abandoned, contained effect.
//
// Containing an agent (after a failed or unknown start, pause, revocation or step), under the fence lock:
//   optionally raise its own fence (with its run state set to `stopped` first, so a resume can lower it), mask it, then
//   part 5's drain (stop, cancel and drain start jobs, re-stop anything active) and the empty-cgroup proof. If the mask
//   or the proof fails, the fence is raised and the drain repeated. The result says whether it was fenced and proven.
//
// Applying generation N (§3.3): verify → durable intent → grant bytes, highwater and applying(N, plan) (GrantState) →
// the plan's steps (plan.mjs), each durably marked done → applied(N) with its acknowledgement → the acknowledgement.
// Design choices, as ruled for this part:
// - Narrowing (plan.mjs): any change to an agent's entry or its tags' membership stops, masks, regenerates, restarts.
// - An agent missing from grant N is retired: run state `stopped` (no lifecycle op counted), stopped and masked. It
//   runs again only when a later grant lists it and a person resumes it.
// - A failed step, by cause:
//   - agent-side (a start refused for preflight_missing or landlock_abi; a unit that failed; a start past its
//     deadline that then settled): start_failed is set, the run state becomes `stopped` (no lifecycle op counted),
//     and the agent is contained (no fence: the stopped state, the mask and the drain proof hold it), the other steps
//     go on, and N still reaches applied(N). The acknowledgement (sb.grant-ack.v1, unchanged) lists in `restarted`
//     only the agents that really started. Recovery never starts it. A person's resume clears start_failed and
//     retries it; the next grant clears start_failed and regenerates its unit, but doesn't start a stopped agent.
//   - host-side (any other failure, any other step past its deadline, or ANY unsettled effect, a start's included):
//     the step's agent, if any, is contained (with a fence when the effect is unsettled), the phase stays applying(N),
//     there is no acknowledgement, and the next input redoes the remaining steps.
// - Expiry is an emergency like a stop: fence, stop, mask. An interrupted application is HELD at applying(N): it isn't
//   continued, finished or acknowledged while the expiry fence is up. Only a newer valid grant lowers the fence, and it
//   supersedes the held application (so does a newer grant when the held one's grant no longer verifies), planning
//   every listed agent anew. Recovery from applying(N) re-verifies grant N first and fails closed.
// - `revoke-caps` (§7): the op is counted, the old unit is stopped and proven empty, THEN the broker revokes at a new
//   generation, then the unit is regenerated and started. A failure or unknown outcome anywhere contains the agent with
//   a fence. A late broker completion can only revoke; it can't start anything. v1 has no op to the permanent
//   `revoked` state.
// - A failed or unknown pause (freeze) contains the agent with a fence.
// - Every start holds the fence lock while it checks all of the agent's fences and starts, so no start slips past a fence.
// - Run states are written durably before the effect that changes them.
//
// The execution lease (execution lease r3.12 §2, §3, §3.1; lease-machine.mjs), when a LeaseMachine is given (`lease`):
// - Supervisor start: recovery raises EVERY agent's durable `lease` fence before anything else, so nothing starts
//   until a fresh lease is accepted; a grant raises it, in its own op, for every agent it adds or whose entry
//   generation it changes, and voids that agent's lease and request (the plan's stop then proves it down).
// - lease-request: one outstanding request per agent the accepted grant lists and no person has stopped.
// - lease-response: through the widening gate first (a pending proof is proven, or nothing is accepted), then the full
//   check, the re-arm and the publication (lease-machine.mjs accept); then, if the `lease` fence is up, a start.
// - lease-timer (an emergency): a timer bound to (lease_id, lg); when it still names the current lease, `lease` is
//   raised and the agent's slice stopped, masked and proven, like every other stop.
// - A start of an agent whose `lease` fence is up (and no other) needs its live lease, and runs the activation helper
//   for it, which alone lowers `lease`, BEFORE taking the fence lock (lock order: activation lock, then fence lock).
//   One other fence may be up with it: `restore`, when the agent's restore record is `validated` (a restored agent
//   waiting for the person's resume, whose helper requires `lease` down). The unit's own condition on the restore fence
//   makes systemd skip the helper's start; the fenced check below then refuses this start, and the run state is left
//   as it is: only the resume starts the agent.
// - A person's resume of a PAUSED agent needs its live lease with `lease` down, checked before anything changes (else
//   refused, and a renewal asked for), and thaws only through the thaw helper, whose own checks run under the
//   activation lock: an expiry at or before the thaw wins, and the agent is then contained with its own fence.
// Without a LeaseMachine, none of this runs and no `lease` fence is ever raised here.

import { existsSync } from "node:fs";
import { join } from "node:path";
import { FleetError, refuse } from "../bytes.mjs";
import { drainAgent, fenceCauses, fenced, lowerFence, raiseFence, stop as fencedStop, withFenceLock } from "./fence.mjs";
import { raiseLeaseFence } from "./lease.mjs";
import { FENCE_DIR, RESTORE_DIR } from "./names.mjs";
import { readRecord as readRestoreRecord } from "./restore-record.mjs";
import { parseStep, planGrant } from "./plan.mjs";
import { hostSystemdPreflight } from "./host-preflight.mjs";
import { entryDigest } from "./grant.mjs";

/** Step deadlines in ms (§3.3; mask, provision and freeze are this module's choice), and the settle grace. */
export const DEADLINES = Object.freeze({
  "broker-gen": 5000, "systemd-version": 5000, stop: 15000, mask: 5000, provision: 30000, unit: 5000, "daemon-reload": 30000, start: 30000,
  map: 5000, freeze: 15000, apply: 300000, grace: 2000, deprovision: 120000,
});

/** Agent-side start failures: refused before any effect (audited `refused` with the reason) … */
const START_REFUSED = Object.freeze(["preflight_missing", "landlock_abi"]);
/** … or after it may have run (audited `unknown_effect`, no reason). */
const START_UNKNOWN = Object.freeze(["unit_failed", "start_timeout"]);

const EMERGENCY = Object.freeze(["stop", "stop-all", "revoke-caps", "expiry", "lease-timer", "chain-adopt"]);
/** Which authority may submit which op (§3.2). */
const MAY = Object.freeze({
  service: ["stop", "pause", "revoke-caps"],
  // The host owner's local CLI only narrows, plus the two deprovision host commands (deprovision r3.2 §3.6), which no
  // remote authority can submit.
  local: ["stop", "stop-all", "purge", "requalify"],
  person: ["stop", "stop-all", "pause", "revoke-caps", "resume", "resume-all", "delete"],
  host: ["expiry", "lease-request", "lease-response", "lease-timer", "chain-adopt"],
});

/** A throw from a barrier: a simulated crash in a test build. It is never handled as a step failure. */
class Crash extends Error {}
const crashThrough = (e) => { if (e instanceof Crash) throw e; };

class StepFailed extends Error {
  constructor(reason, side, { unknown = false, settled = true } = {}) { super(reason); Object.assign(this, { reason, side, unknown, settled }); }
}

const TIMEOUT = Symbol("timeout");
/** An error's outcome: settled unless it is an abandoned effect that didn't settle. */
const settledOf = (e) => e?.settled !== false;

export class Supervisor {
  #normal = []; #urgent = []; #running = false; #revoked = false;
  /** Effects that passed their deadline and grace without settling. */
  #unsettled = new Set();

  /**
   * `store`: an open HostStore (registry, grants). `fx`: the effects (the tests' fake lists every one); each is called
   * with its own arguments, then (ms, signal), and must stop when the signal aborts.
   * `verify(bytes)` → { body, digest, hash }: the full §3.2 check of a grant for this host now (throws to refuse);
   *   `digest` hashes the envelope bytes, `hash` its signed bytes (grant.mjs verifyGrant);
   * `bodyOf(bytes)` → the body of bytes accepted earlier (no time check).
   * Options: { fenceDir, deadlines, barrier: async (name, detail) => {} (a test hook; production passes none),
   * lease: a LeaseMachine (lease-machine.mjs), or null for none; restoreState(agent): its restore record's state or null
   * (restore-record.mjs; a test seam); chain: the chain adoption's seam (chain-sync.mjs chainAdopter: { certValid(state),
   * grantValid(state, bytes), markRevoked(), commit(candidate) }), or null for none }.
   */
  constructor({ store, fx, verify, bodyOf, fenceDir = FENCE_DIR, deadlines = {}, barrier = async () => {}, lease = null,
    restoreState = (agent) => readRestoreRecord("agent", agent, { dir: RESTORE_DIR })?.state ?? null, chain = null }) {
    const hook = async (name, detail) => { try { await barrier(name, detail); } catch (e) { throw Object.assign(new Crash(e?.message ?? "crash"), { cause: e }); } };
    Object.assign(this, { store, fx, verify, bodyOf, fenceDir, deadlines: { ...DEADLINES, ...deadlines }, barrier: hook, lease, restoreState, chain });
  }

  get registry() { return this.store.registry; }
  get grants() { return this.store.grants; }
  /** How many abandoned effects haven't settled yet (normal inputs are refused while any hasn't). */
  get unsettled() { return this.#unsettled.size; }

  /**
   * Run one effect, owned: `fn(ms, signal)` with the deadline `ms`. Past it, abort the signal and wait the grace for
   * it to settle. Throws the effect's own error, or a deadline error with `settled` saying whether it settled. `agent`:
   * the agent the effect acts on, re-contained when an unsettled effect finally settles. `widen`: the effect can give
   * authority, so it is refused (host-side, in_progress) while any effect is unsettled; only narrowing effects (mask,
   * stop, the drain, freeze, revoke) and reads still run then.
   */
  async #owned(fn, ms, agent = null, { widen = false } = {}) {
    // An effect that can give authority (write or start a unit, publish, thaw, ...) never runs while an abandoned
    // effect may still complete, not even later within the same input.
    if (widen && this.#unsettled.size > 0) throw new StepFailed("in_progress", "host");
    if (widen) this.#widen(agent); // every widening effect; an agentless one is host-wide (#widen(null))
    const ac = new AbortController();
    const p = Promise.resolve().then(() => fn(ms, ac.signal));
    let timer;
    const first = await Promise.race([
      p.then((v) => ({ v }), (e) => ({ e })),
      new Promise((r) => { timer = setTimeout(() => r(TIMEOUT), ms); }),
    ]);
    clearTimeout(timer);
    if (first !== TIMEOUT) { if ("e" in first) throw first.e; return first.v; }
    ac.abort();
    let g;
    const settled = await Promise.race([p.then(() => true, () => true), new Promise((r) => { g = setTimeout(() => r(false), this.deadlines.grace); })]);
    clearTimeout(g);
    if (!settled) {
      // When it finally settles, whatever it did to its agent is undone first: contained again (mask, drain, proof),
      // ahead of every normal input (which are all refused until then).
      this.#unsettled.add(p);
      const done = () => {
        if (agent) this.#enqueue({ kind: "recontain", agent }, "urgent").catch(() => {});
        this.#unsettled.delete(p);
      };
      p.then(done, done);
    }
    throw Object.assign(new Error("step_deadline"), { deadline: true, settled });
  }

  /**
   * Queue an input; resolves with its result. `{ kind: "grant", bytes }`, or an op `{ kind, authority, agent? }`.
   * Emergencies go to the front, still one at a time.
   */
  submit(input) {
    const kind = input?.kind;
    if (kind !== "grant" && !(Object.hasOwn(MAY, input?.authority ?? "") && MAY[input.authority].includes(kind))) {
      return Promise.reject(new FleetError("not_granted", "executor: that authority can't do that"));
    }
    if (kind.startsWith("lease-") && this.lease === null) return Promise.reject(new FleetError("bad_form", "executor: no execution lease here"));
    if (kind === "chain-adopt" && this.chain === null) return Promise.reject(new FleetError("bad_form", "executor: no chain adoption here"));
    return this.#enqueue(input, EMERGENCY.includes(kind) ? "urgent" : "normal");
  }

  /** Recovery at supervisor start (§3.3), before any agent runs; ahead of every queued input but emergencies. */
  recover() { return this.#enqueue({ kind: "recover" }, "first"); }

  #enqueue(input, where) {
    return new Promise((resolve, reject) => {
      const job = { input, resolve, reject };
      if (where === "urgent") this.#urgent.push(job);
      else if (where === "first") this.#normal.unshift(job);
      else this.#normal.push(job);
      this.#pump();
    });
  }

  async #pump() {
    if (this.#running) return;
    this.#running = true;
    try {
      for (;;) {
        const job = this.#urgent.shift() ?? this.#normal.shift();
        if (!job) break;
        try { job.resolve(await this.#run(job.input)); } catch (e) { job.reject(e); }
      }
    } finally { this.#running = false; }
  }

  async #run(input) {
    // Revoked (a chain adoption ended the host's authority): nothing is served any more; the daemon exits.
    if (this.#revoked) return { status: "refused", reason: "revoked" };
    // While an abandoned effect may still complete, only narrowing emergencies run.
    if (!EMERGENCY.includes(input.kind) && input.kind !== "recontain" && this.#unsettled.size > 0) return { status: "refused", reason: "in_progress", unsettled: this.#unsettled.size };
    switch (input.kind) {
      case "grant": return this.#grant(input.bytes);
      case "continue": return this.grants.pending().phase !== "applying" ? { status: "applied" } : this.#heldByExpiry() ? { status: "held", reason: "expired" } : this.#continue();
      case "recover": return this.#recover();
      case "recontain": return this.#containLocked(input.agent, { fence: false });
      case "stop": return input.agent ? this.#stopAgent(input.agent) : this.#stopAll("all");
      case "stop-all": return this.#stopAll("all");
      case "expiry": return this.#stopAll("expiry");
      case "revoke-caps": return this.#revokeCaps(input.agent);
      case "pause": return this.#pause(input.agent);
      case "resume": return this.#resume(input.agent);
      case "resume-all": return this.#resumeAll();
      case "delete": return this.#delete(input.agent);
      case "purge":
      case "requalify": return this.#hostCommand(input.kind, input.agent);
      case "lease-request": return this.#leaseRequest(input.agent);
      case "lease-response": return this.#leaseResponse(input.agent, input.bytes);
      case "lease-timer": return this.#leaseTimer(input.agent, input.lease_id, input.lg);
      case "chain-adopt": return this.#chainAdopt(input.candidate);
      default: return refuse("bad_form", "executor: unknown input");
    }
  }

  // ---- grants (§3.3)

  async #grant(bytes) {
    this.verify(bytes); // an invalid grant is refused before anything runs
    await this.barrier("after_verify", { gen: this.bodyOf(bytes).gen });
    // An unfinished application is redone first (the next input redoes the remaining steps) when its grant still
    // verifies and the host isn't expired. Otherwise it is held (Q4), and this newer valid grant supersedes it: every
    // agent it lists is planned anew, so nothing depends on the steps the held one didn't do.
    let supersede = false;
    if (this.grants.pending().phase === "applying") {
      const expired = this.#heldByExpiry();
      if (expired || !this.#stillValid()) {
        const { body, digest } = this.verify(bytes);
        // Lower, or equal but different, is refused; the held grant itself again changes nothing.
        if (this.grants.admit(body.gen, digest).reapply) return { status: "held", reason: expired ? "expired" : "grant_not_valid", gen: body.gen };
        supersede = true;
      } else {
        const r = await this.#continue();
        if (r.status !== "applied") return { status: "refused", reason: "in_progress", previous: r };
      }
    }
    // A verification is never carried across an await: verify again now, then admit and plan with no await between,
    // and GrantState.begin checks it once more after the intent's append, before anything is accepted.
    const { body, digest, hash } = this.verify(bytes);
    const gen = body.gen;
    if (!supersede && this.grants.admit(gen, digest).reapply) {
      // A byte-identical re-apply has no effect; it re-sends the acknowledgement, but never while a proof is pending.
      if (this.grants.pendingProofs().length > 0) return { status: "refused", reason: "in_progress", pending_proof: this.grants.pendingProofs() };
      return { status: "reapplied", gen, ack: await this.#sendAck(gen, this.grants.ack) };
    }
    const prevBytes = this.grants.currentBytes();
    // After expiry every listed agent is restarted by the newer grant (§3.4); the plan holds that durably.
    const planned = planGrant(prevBytes ? this.bodyOf(prevBytes) : null, body, this.registry, { all: this.#expired() || supersede }).steps;
    // A superseded application's unfinished work never just disappears: every agent with an unfinished step in it
    // must first be proven down, durably, as the new plan's first steps, whatever the new grant says about it.
    // Every plan starts with a prove step for each agent whose proof is pending, listed in the grant or not.
    const carried = [...new Set([...this.grants.pendingProofs(), ...(supersede ? this.#unfinishedAgents() : [])])].sort().map((id) => `prove:${id}`);
    // A newer valid grant lowers the expiry fence, and nothing else (§3.3). It widens every agent, so it is a step of
    // its own, durable and redone like any other, right after the proofs, and gated on no pending proof at all.
    const steps = [...carried, ...(this.#expired() ? ["unexpire"] : []), ...planned];
    const genBefore = Object.fromEntries(body.agents.map((a) => [a.agent, this.grants.record(a.agent)?.entry_gen ?? null]));
    await this.grants.begin(gen, bytes, digest, steps, async (rec) => { await this.fx.appendIntent(rec); await this.barrier("after_intent", { gen }); },
      { supersede, recheck: () => { if (this.verify(bytes).digest !== digest) refuse("bad_form", "executor: the grant changed"); },
        entries: Object.fromEntries(body.agents.map((a) => [a.agent, entryDigest(a)])), hash });
    await this.barrier("after_highwater_persist", { gen });
    // The lease (§3.1): an agent this grant adds, or whose entry generation it changes, has its lease and request voided
    // and its `lease` fence raised, in this op and before any of the plan's steps (its stop step proves it down).
    if (this.lease) {
      for (const a of body.agents) {
        if (this.grants.record(a.agent)?.entry_gen === genBefore[a.agent]) continue;
        this.lease.invalidate(a.agent);
        this.#raiseLease(a.agent);
      }
      await this.barrier("after_lease_raise", { gen });
    }
    return this.#continue();
  }

  #expired() { return existsSync(join(this.fenceDir, "expiry")); }

  /**
   * Is the unfinished application held by expiry (Q4)? Only when the expiry fence is up AND its plan doesn't still
   * hold its own unexpire step: a newer grant's application that lowers expiry is continued, not held.
   */
  #heldByExpiry() {
    if (!this.#expired()) return false;
    const steps = this.grants.steps();
    return !this.grants.pending().remaining.some((i) => steps[i] === "unexpire");
  }

  /** The agents with an unfinished step in the plan being applied (sorted, once each). */
  #unfinishedAgents() {
    const steps = this.grants.steps();
    const ids = this.grants.pending().remaining.map((i) => parseStep(steps[i]).agent).filter((id) => id !== null);
    return [...new Set(ids)].sort();
  }

  /** Does the accepted grant still pass the full §3.2 check now? (Recovery and a redo never run on an invalid one.) */
  #stillValid() {
    try { this.verify(this.grants.currentBytes()); return true; } catch { return false; }
  }

  /** Run the remaining steps of applying(N), then applied(N) and the acknowledgement. */
  async #continue() {
    const { gen, remaining } = this.grants.pending();
    const body = this.bodyOf(this.grants.currentBytes());
    const steps = this.grants.steps();
    const t0 = Date.now();
    for (const i of remaining) {
      if (this.#urgent.length > 0) {
        // Preempted at a step boundary: the emergency runs next; this application is continued right after it.
        await this.barrier("emergency_preempt", { gen, step: steps[i] });
        this.#enqueue({ kind: "continue" }, "first");
        return { status: "preempted", gen, step: steps[i] };
      }
      if (Date.now() - t0 > this.deadlines.apply) return this.#hostFailure(gen, steps[i], new StepFailed("apply_deadline", "host"));
      try {
        await this.#step(steps[i], gen, body);
      } catch (e) {
        crashThrough(e);
        if (!(e instanceof StepFailed && e.side === "agent")) return this.#hostFailure(gen, steps[i], e);
      }
      this.grants.done(i);
    }
    // No application reaches applied(N) while any proof is pending, whatever its plan held: prove each one now.
    for (const id of this.grants.pendingProofs()) {
      try { await this.#proveDown(id); } catch (e) { crashThrough(e); return this.#hostFailure(gen, `prove:${id}`, e); }
    }
    const ack = await this.#ackOf(steps);
    this.grants.finish(ack);
    await this.barrier("after_applied_persist", { gen });
    await this.#sendAck(gen, ack);
    await this.barrier("after_ack_send", { gen });
    return { status: "applied", gen, ack };
  }

  /**
   * narrowed: the plan stopped anything. restarted: the agents of its start steps that are running now, by the
   * independent evidence of systemd (so it holds across a crash in the middle), with no start failure on record.
   */
  async #ackOf(steps) {
    const parsed = steps.map(parseStep);
    const restarted = [];
    for (const { kind, agent } of parsed) {
      if (kind !== "start" || restarted.includes(agent)) continue;
      const a = this.registry.agent(agent);
      if (!a || a.state !== "running" || a.start_failed !== null) continue;
      let active = false;
      try { active = (await this.#owned((ms, signal) => this.fx.isActive(agent, ms, signal), this.deadlines.mask)) === true; } catch { /* not proven */ }
      if (active) restarted.push(agent);
    }
    return { narrowed: parsed.some((s) => s.kind === "stop"), restarted: restarted.sort() };
  }

  async #sendAck(gen, ack) {
    try { await this.#owned((ms, signal) => this.fx.sendAck(gen, ack, ms, signal), this.deadlines.map); } catch { /* re-sent on a byte-identical re-apply */ }
    return ack;
  }

  async #hostFailure(gen, step, e) {
    const unknown = e?.deadline === true || e?.unknown === true;
    if (e?.deadline === true) await this.barrier("step_deadline", { step });
    const { agent } = parseStep(step);
    if (agent && !(e instanceof StepFailed && e.contained)) await this.#containLocked(agent, { fence: !settledOf(e) });
    this.#audit({ kind: "grant.apply", gen, step, phase: unknown ? "unknown_effect" : "failed_no_effect" });
    return { status: "failed", gen, step, reason: e?.reason ?? e?.code ?? (unknown ? "step_deadline" : "effect_failed"), settled: settledOf(e) };
  }

  /** One plan step, idempotent. Throws StepFailed (agent- or host-side) or an effect's error (host-side). */
  async #step(step, gen, body) {
    const { kind, agent } = parseStep(step);
    // FIRST, ahead of every early return:
    // - a plan step that widens an agent goes through the widening gate: a pending agent is proven first (so a redo
    //   makes progress once the count is really 0), or the step is refused, host-side;
    // - a start step completes only through an actual start or a passed proof, and a prove step only through a
    //   passed proof.
    if (["provision", "unit", "start"].includes(kind)) await this.#proveOrRefuse(agent);
    if (["broker-gen", "daemon-reload", "map"].includes(kind)) await this.#proveOrRefuse(null); // host-wide widening
    if (kind === "start") return this.#startStep(agent, gen);
    if (kind === "prove") { await this.#proveDown(agent); return undefined; }
    if (kind === "unexpire") {
      await this.#proveOrRefuse(null);
      await lowerFence("expiry", null, "newer-grant", { dir: this.fenceDir });
      return undefined;
    }
    const ga = agent ? body.agents.find((a) => a.agent === agent) ?? null : null;
    const d = this.deadlines;
    // An agent deleted since the plan was made (an op between two inputs) only ever gets stopped and masked.
    if (agent && this.registry.agent(agent)?.state === "deleted" && !["stop", "mask"].includes(kind)) return undefined;
    switch (kind) {
      case "broker-gen":
        await this.#owned((ms, signal) => this.fx.brokerGen(gen, ms, signal), d["broker-gen"], null, { widen: true });
        return this.barrier("after_broker_gen", { gen });
      case "retire": {
        const a = this.registry.agent(agent);
        if (a && !["stopped", "revoked", "deleted"].includes(a.state)) await this.#setState(agent, "stopped");
        return undefined;
      }
      case "stop":
        await this.#stopUnit(agent);
        return this.barrier("after_stop", { agent });
      case "mask":
        await this.#owned((ms, signal) => this.fx.mask(agent, ms, signal), d.mask, agent);
        return this.barrier("after_mask", { agent });
      case "provision": {
        for (const t of ga.tags) this.registry.addTag(t);
        const uid = this.registry.agent(agent)?.uid ?? this.registry.addAgent(agent, gen, ga.tags);
        return this.#owned((ms, signal) => this.fx.provision(agent, uid, ga, ms, signal), d.provision, agent, { widen: true });
      }
      case "unit": {
        for (const t of ga.tags) this.registry.addTag(t);
        const { uid } = this.registry.setGrant(agent, gen, ga.tags); // also clears start_failed: a new grant
        await this.#owned((ms, signal) => this.fx.writeUnit(agent, uid, ga, ms, signal), d.unit, agent, { widen: true });
        return this.barrier("after_unit_write", { agent });
      }
      case "daemon-reload":
        await this.#owned((ms, signal) => this.fx.daemonReload(ms, signal), d["daemon-reload"], null, { widen: true });
        return this.barrier("after_daemon_reload", {});
      case "map": {
        const map = body.agents.flatMap((a) => { const r = this.registry.agent(a.agent); return r ? [{ agent: a.agent, uid: r.uid }] : []; });
        await this.#owned((ms, signal) => this.fx.publishMap(gen, map, ms, signal), d.map, null, { widen: true });
        return this.barrier("after_map_publish", { gen });
      }
      default: return refuse("bad_form", "executor: unknown step");
    }
  }

  /** Stop one unit and prove its cgroup empty, within the stop deadline; not empty is a host-side failure. */
  async #stopUnit(agent) {
    // (A failure here is host-side: the containment that follows runs #stopProved, which marks the proof if needed.)
    await this.#owned(async (ms, signal) => {
      const t0 = Date.now();
      await this.fx.stopUnit(agent, ms, signal);
      const n = await this.fx.procCount(agent, Math.max(1, ms - (Date.now() - t0)), signal);
      if (n !== 0) throw new StepFailed("not_empty", "host");
    }, this.deadlines.stop, agent);
  }

  /**
   * Start one agent if its run state allows it and none of its fences is up, holding the fence lock across the check,
   * the start and, on any failure, the containment. A skip is not a failure. Agent-side failures are recorded and
   * thrown as StepFailed("agent"); an unsettled start or an unknown error is host-side.
   */
  async #start(agent, gen) {
    // (A pending agent never starts: its unmask and start are widening effects, refused by #widen inside #owned, and so
    // is its registry move toward running in #setState.)
    const a = this.registry.agent(agent);
    if (!a || !["provisioned", "running"].includes(a.state) || a.start_failed !== null) return { started: false, why: "state" };
    // (gen 0: never granted on this host, a restored agent before this host's first grant. It never starts, whatever
    //  its fences say: a start needs a grant here)
    if (!(a.gen >= 1)) return { started: false, why: "ungranted" };
    // The host's systemd must be the one its syscall policy was qualified with, asked afresh before EVERY start and
    // before any start effect; a refusal latches the qualification invalidated (host-preflight.mjs, qualification.mjs).
    if (await this.#unqualified()) {
      this.#audit({ kind: "agent.start", agent, gen, phase: "refused", reason: "qualify_required" });
      return { started: false, why: "qualify_required" };
    }
    // The lease: with `lease` up (and no other fence), only its live lease's activation helper lowers it. Outside the
    // fence lock, which the helper takes after the activation lock.
    if (this.lease && this.#leaseUp(agent)) {
      const others = fenceCauses(agent, { dir: this.fenceDir }).filter((c) => c !== "lease");
      const restoring = others.length === 1 && others[0] === "restore" && this.#restoreValidated(agent);
      if (others.length > 0 && !restoring) return { started: false, why: "fenced" };
      const live = await this.lease.live(agent);
      if (live === null) { this.lease.due(agent); return { started: false, why: "no_lease" }; }
      // Durable before the helper's start; not for a restored agent, whose start comes only with its resume.
      if (a.state === "provisioned" && !restoring) await this.#setState(agent, "running");
      await this.barrier("before_activate", { agent });
      let ok = false;
      try { ok = await this.lease.activate(agent, live); } catch (e) { crashThrough(e); }
      await this.barrier("after_activate", { agent });
      // (A helper that exits 0 but left `lease` up is refused by the fence check below, under the fence lock.)
      if (!ok) return { started: false, why: "lease" };
    }
    return withFenceLock(async () => {
      if (fenced(agent, { dir: this.fenceDir })) return { started: false, why: "fenced" };
      if (a.state === "provisioned") await this.#setState(agent, "running"); // durable before the effect
      await this.fx.appendIntent({ kind: "agent.start", agent, gen });
      await this.barrier("before_start", { agent });
      try {
        await this.#owned(async (ms, signal) => {
          await this.fx.unmask(agent, ms, signal);
          signal.throwIfAborted(); // an abandoned closure never goes on to its next effect
          await this.fx.start(agent, ms, signal);
        }, this.deadlines.start, agent, { widen: true });
      } catch (e) {
        if (e?.deadline) await this.barrier("step_deadline", { step: `start:${agent}` });
        const settled = settledOf(e);
        const typed = e?.deadline ? "start_timeout" : e instanceof FleetError && [...START_REFUSED, ...START_UNKNOWN].includes(e.code) ? e.code : null;
        if (typed) this.registry.setStartFailed(agent, typed);
        // A failed start leaves the agent stopped (no lifecycle op counted), contained before the lock is released:
        // a fence too when the start may still complete. A person's resume clears start_failed and retries.
        await this.#setState(agent, "stopped");
        const c = await this.#contain(agent, { fence: !settled });
        // Only a start that settled AND whose containment proved the cgroup empty is agent-side.
        if (typed === null || !settled || !c.proven) {
          this.#audit({ kind: "agent.start", agent, gen, phase: "unknown_effect" });
          throw Object.assign(new StepFailed(c.proven ? e?.code ?? "effect_failed" : "not_empty", "host", { unknown: true, settled }), { contained: c });
        }
        this.#audit(START_REFUSED.includes(typed)
          ? { kind: "agent.start", agent, gen, phase: "refused", reason: typed }
          : { kind: "agent.start", agent, gen, phase: "unknown_effect" });
        throw new StepFailed(typed, "agent");
      }
      await this.barrier("after_start", { agent });
      this.#audit({ kind: "agent.start", agent, gen, phase: "succeeded" });
      return { started: true };
    }, { dir: this.fenceDir });
  }

  /**
   * Whether the host isn't qualified to start agents: its qualification already invalidated (latched: not asked again),
   * or its systemd, asked now, isn't exactly the qualified major, which invalidates it durably.
   */
  async #unqualified() {
    const q = this.store.qualification;
    if (q.latched) return true;
    if ((await hostSystemdPreflight(this.fx.systemdVersion, this.deadlines["systemd-version"])) === null) return false;
    q.invalidate(Date.now());
    return true;
  }

  /**
   * Contain an agent; the caller holds the fence lock. With `fence`: its run state becomes `stopped` (a paused or
   * ended one keeps its state), then its own fence is raised. Then mask, drain and prove the cgroup empty; a failed mask
   * or proof raises the fence (if it isn't up) and drains again. Returns { fenced, proven }.
   */
  async #contain(agent, { fence }) {
    let up = false;
    const raise = async () => {
      if (up) return;
      const a = this.registry.agent(agent);
      if (a && ["provisioned", "running"].includes(a.state)) { try { await this.#setState(agent, "stopped"); } catch (e) { crashThrough(e); } }
      try { raiseFence("agent", agent, { dir: this.fenceDir }); up = true; } catch { /* reported: fenced false */ }
    };
    if (fence) await raise();
    try { await this.#owned((ms, signal) => this.fx.mask(agent, ms, signal), this.deadlines.mask, agent); } catch { await raise(); }
    const drain = () => this.#stopProved({ agent }, null);
    let r = await drain();
    if (!(r.drained && r.empty) && !up) { await raise(); r = await drain(); }
    const proven = r.drained && r.empty; // (an unproven drain was already marked pending by #stopProved)
    await this.barrier("after_contain", { agent, fenced: up });
    return { fenced: up, proven };
  }

  /**
   * A plan's start step. It completes ONLY through an actual start, or through #proveDown passing (masked, drained,
   * cgroup count 0), whatever the agent's registry state is: provisioned, running, paused, stopped, revoked, deleted,
   * fenced, failed, or any state added later. Anything else throws (host-side, or agent-side only after its own
   * containment proved the cgroup empty), so the step stays to be redone and N never reaches applied(N) while
   * something of the agent may run.
   */
  async #startStep(agent, gen) {
    // (A pending agent isn't started: #start refuses it, and the proof below then decides the step.)
    const r = await this.#start(agent, gen);
    if (r.started !== true) await this.#proveDown(agent);
  }

  /**
   * THE widening gate, the mirror of #stopProved: every effect that gives an agent authority back passes here first.
   * That covers lowering one of its fences, a registry move toward running, thaw, a unit write or regeneration, unmask
   * and start (#owned's widening effects), and its entry in a map publish. While the agent's proof is pending it
   * refuses before anything happens. The only way past is a passing #proveDown (#proveOrRefuse).
   */
  #widen(agent) {
    const pending = this.grants.pendingProofs();
    // agent null: a host-wide widening effect (broker generation, daemon-reload, map publish): refused while ANY
    // agent's proof is pending.
    if (agent === null ? pending.length > 0 : pending.includes(agent)) throw new StepFailed("pending_proof", "host");
  }

  /**
   * The way past the gate: prove a pending agent down first (agent null: every pending agent), or refuse with nothing
   * changed.
   */
  async #proveOrRefuse(agent) {
    for (const id of agent === null ? this.grants.pendingProofs() : this.grants.pendingProofs().filter((x) => x === agent)) await this.#proveDown(id);
    this.#widen(agent);
  }

  /** Contain (no new fence) and require the proof; host-side not_empty if it can't be had. */
  async #proveDown(agent) {
    const c = await this.#containLocked(agent, { fence: false });
    if (!c.proven) throw Object.assign(new StepFailed("not_empty", "host", { unknown: true }), { contained: c });
    this.grants.clearProof(agent); // the only place a pending proof is cleared
    return c;
  }

  /** Contain, taking the fence lock first (for callers outside #start). */
  #containLocked(agent, opts) { return withFenceLock(() => this.#contain(agent, opts), { dir: this.fenceDir }); }

  async #mask(agent) { try { await this.#owned((ms, signal) => this.fx.mask(agent, ms, signal), this.deadlines.mask, agent); } catch { /* the fence or state still holds */ } }

  /** Every run-state record goes through here: durable before the effect it precedes. */
  async #setState(agent, state, op = null) {
    // A registry MOVE toward running widens (recording an op on an agent already running doesn't).
    if (state === "running" && this.registry.agent(agent)?.state !== "running") this.#widen(agent);
    await this.barrier("before_runstate_record", { agent, state });
    return this.registry.setState(agent, state, op);
  }

  #audit(rec) { try { this.fx.audit(rec); } catch { /* terminal records are best effort; the health signal shows it */ } }

  /** The agents of the accepted grant that have registry records, with their records. */
  #agents() {
    const bytes = this.grants.currentBytes();
    const ids = bytes ? this.bodyOf(bytes).agents.map((a) => a.agent) : [];
    return ids.flatMap((id) => { const a = this.registry.agent(id); return a ? [[id, a]] : []; });
  }

  #grantAgent(agent) {
    const bytes = this.grants.currentBytes();
    return bytes ? this.bodyOf(bytes).agents.find((x) => x.agent === agent) ?? null : null;
  }

  // ---- the chain adoption (host daemon r2.5 §6.2): an emergency, serialized with every effect

  /** True once a chain adoption found the host's certificate no longer valid: the daemon then exits. */
  get revoked() { return this.#revoked; }

  /**
   * Adopt a candidate chain state (built and verified outside the queue). Against the CANDIDATE, with fresh time:
   * (1) the certificate no longer verifies → the revoked marker durably FIRST, then `all` raised and every agent stopped,
   *     masked and proven, then the entries and the pin; nothing is served after it;
   * (2) the accepted grant no longer verifies → the `expiry` stop (fence first, stop, mask), then the entries and the pin;
   *     only a NEWER valid grant lowers `expiry` (its unexpire step);
   * (3) otherwise the entries and the pin.
   * The commit writes the entries, then the pin, durably, and only then swaps the snapshot every verifier reads.
   */
  async #chainAdopt(candidate) {
    if (!candidate?.state || !Array.isArray(candidate.entries) || candidate.entries.length === 0) refuse("bad_form", "executor: not a chain candidate");
    if (!(await this.chain.certValid(candidate.state))) {
      this.chain.markRevoked();
      this.#revoked = true;
      await this.barrier("after_revoked_marker", {});
      const stop = await this.#stopAll("all");
      await this.barrier("after_revoked_stop", {});
      this.chain.commit(candidate);
      this.#audit({ kind: "host.revoked", phase: "revoked" });
      return { status: "revoked", stop };
    }
    const bytes = this.grants.currentBytes();
    if (bytes && !(await this.chain.grantValid(candidate.state, bytes))) {
      const stop = await this.#stopAll("expiry");
      await this.barrier("after_grant_stop", {});
      this.chain.commit(candidate);
      return { status: "expired", stop };
    }
    this.chain.commit(candidate);
    return { status: "adopted", seq: candidate.state.seq };
  }

  // ---- the execution lease (execution lease r3.12 §3, §3.1)

  #leaseUp(agent) { return existsSync(join(this.fenceDir, "lease", agent)); }

  /** Is the agent's restore record validated (a restored agent waiting for its resume)? Unreadable: no. */
  #restoreValidated(agent) {
    try { return this.restoreState(agent) === "validated"; } catch { return false; }
  }

  /** Raise the agent's `lease` fence durably (raising needs no lock and is always safe); a failure throws. */
  #raiseLease(agent) { raiseLeaseFence(agent, { fenceDir: join(this.fenceDir, "lease") }); }

  /**
   * A renewal request for an agent the accepted grant lists, at its entry generation there, unless it ended (deleted,
   * revoked) or a person stopped it (its own fence or `all`): then skipped, and nothing is outstanding.
   */
  async #leaseRequest(agent) {
    const a = this.registry.agent(agent), rec = this.grants.record(agent);
    if (!a || ["deleted", "revoked"].includes(a.state) || rec === null) return { status: "skipped", reason: "not_listed" };
    if (fenceCauses(agent, { dir: this.fenceDir }).some((c) => c === "all" || c === "agent")) return { status: "skipped", reason: "stopped" };
    return { status: "requested", bytes: await this.lease.request(agent, rec.entry_gen) };
  }

  /**
   * A response, checked in full when this op runs: never while a stop or proof of the agent is unfinished (the widening
   * gate proves it first, or refuses with nothing accepted), then accept (verify, the generation, the effective
   * expiry, arm, publish). A published lease starts the agent if its `lease` fence is up and it should run.
   */
  async #leaseResponse(agent, bytes) {
    try { await this.#proveOrRefuse(agent); } catch (e) { crashThrough(e); return { status: "refused", reason: "pending_proof" }; }
    const r = await this.lease.accept(agent, bytes, this.grants.record(agent)?.entry_gen ?? null);
    if (!r.accepted) return { status: "ignored", reason: r.reason };
    await this.barrier("after_lease_publish", { agent });
    if (!this.#leaseUp(agent)) return { status: "renewed", lg: r.rec.lg };
    let started = false;
    try { started = (await this.#start(agent, this.grants.pending().gen)).started === true; } catch (e) { crashThrough(e); /* recorded and contained */ }
    return { status: "accepted", lg: r.rec.lg, started };
  }

  /** A lease timer: stale (another lease or lg since) does nothing; otherwise raise `lease`, stop, mask, prove. */
  async #leaseTimer(agent, leaseId, lg) {
    if (!this.lease.expire(agent, leaseId, lg)) return { status: "stale" };
    const r = await this.#stopProved({ agent }, "lease");
    await this.#mask(agent);
    this.#audit({ kind: "agent.lease", agent, phase: "expired" });
    this.lease.due(agent);
    return r;
  }

  // ---- recovery (§3.3)

  async #recover() {
    this.registry.reload(); this.grants.reload();
    // The lease (§2): EVERY agent's `lease` fence is raised before anything else, whatever its state; no lease survives
    // a supervisor start (they're never read from disk). Each is asked for at start (§3); the request op, queued
    // behind this recovery, skips an agent the grant doesn't list, one that ended, and one a person stopped.
    if (this.lease) {
      for (const id of this.registry.ids()) { this.lease.init(id); this.#raiseLease(id); }
      await this.barrier("after_lease_raise", {});
      for (const id of this.registry.ids()) this.lease.due(id);
    }
    for (const g of (await this.fx.openIntents?.()) ?? []) {
      const r = this.grants.reconcileIntent(g); // AU07: highwater below g proves no effect
      this.#audit({ kind: "grant.apply", gen: g, phase: r === "failed_no_effect" ? "reconciled_no_effect" : "reconciled_succeeded" });
    }
    // Deleted agents first: narrowing, so before (and whatever) the grant decides below.
    const swept = await this.#sweepDeleted();
    const report = (r) => {
      const unproven = [...new Set([...swept.unproven, ...(r.unproven ?? [])])];
      const out = { ...r };
      delete out.unproven;
      if (unproven.length) out.unproven = unproven;
      if (swept.deprovisioning.length) out.deprovisioning = swept.deprovisioning;
      return out;
    };
    const { phase, gen } = this.grants.pending();
    if (gen === 0) return report({ status: "empty" });
    if (phase === "applying") {
      // Fail closed exactly as from applied(N): an invalid grant runs nothing; an expired host holds it (Q4).
      if (!this.#stillValid()) return report({ status: "not_started", reason: "grant_not_valid" });
      if (this.#heldByExpiry()) return report({ status: "held", reason: "expired" });
      return report(await this.#continue());
    }
    let body;
    try { body = this.verify(this.grants.currentBytes()).body; } catch { return report({ status: "not_started", reason: "grant_not_valid" }); }
    const allowed = new Set(body.agents.map((x) => x.agent));
    const started = [], unproven = [];
    // Every pending proof first, before any start: one that still fails is reported, and #start refuses that agent.
    // (The deleted agents the sweep took are settled either way.)
    for (const id of this.grants.pendingProofs()) {
      if (swept.taken.has(id)) continue;
      try { await this.#proveDown(id); } catch (e) { crashThrough(e); unproven.push(id); }
    }
    for (const [id, a] of this.#agents()) {
      if (swept.taken.has(id)) continue;
      if (a.state === "paused") await this.#setState(id, "stopped"); // a pause never becomes a run
      else if (a.state === "running" && a.start_failed === null && allowed.has(id)) {
        try { if ((await this.#start(id, gen)).started) { started.push(id); continue; } } catch (e) { crashThrough(e); /* recorded and contained */ }
      }
      // Every agent recovery doesn't start is proven down (masked, drained, empty; that clears a pending proof), or
      // reported and left pending.
      if (unproven.includes(id)) continue;
      try { await this.#proveDown(id); } catch (e) { crashThrough(e); unproven.push(id); }
    }
    return report({ status: "recovered", gen, started, unproven });
  }

  /**
   * Recovery's deprovision lane (deprovision r3.2 §2: no hole between `deleted` and the record). Every agent the
   * REGISTRY records as deleted whose deprovision isn't done, in the current grant or not, with a pending proof or
   * not (a crash between `deleted` and its stop leaves none), is proven down afresh: masked, drained, its cgroup
   * proven empty. Only then does it get a pass; one that can't be proven gets none and is reported unproven. It needs
   * no grant: it only narrows. Returns { taken, unproven, deprovisioning }.
   */
  async #sweepDeleted() {
    const taken = new Set(), unproven = [], deprovisioning = [];
    for (const id of this.registry.ids()) {
      if (this.registry.agent(id).state !== "deleted" || this.store.deprovision.record(id)?.done) continue;
      taken.add(id);
      try { await this.#proveDown(id); } catch (e) { crashThrough(e); unproven.push(id); continue; }
      if ((await this.#deprovision(id)).status !== "done") deprovisioning.push(id);
    }
    return { taken, unproven, deprovisioning };
  }

  // ---- narrowing and lifecycle ops (§7)

  /**
   * THE stop primitive: every path that stops an agent's cgroup comes through here (containment, a person's stop,
   * delete, stop-all, expiry, revoke-caps through containment). `cause` null: part 5's drain alone, for a caller that
   * holds the fence lock; otherwise part 5's whole fenced stop for that cause. Unless the result PROVES the drain and
   * an empty cgroup, every agent it covers becomes a pending proof, durably, before it returns. Only #proveDown clears
   * one.
   */
  async #stopProved(target, cause) {
    const agents = target.all === true ? this.registry.ids() : [target.agent];
    const r = cause === null
      ? await drainAgent(target.agent, { sys: this.fx.sys, deadlineMs: this.deadlines.stop, barrier: this.barrier })
      : await fencedStop(target, cause, { sys: this.fx.sys, dir: this.fenceDir, barrier: this.barrier });
    if (!(r.drained === true && r.empty === true)) for (const id of agents) this.grants.markProof(id);
    return r;
  }

  async #stopAgent(agent) {
    const a = this.registry.agent(agent);
    if (!a) return refuse("not_granted", "executor: unknown agent");
    if (["provisioned", "running", "paused"].includes(a.state)) await this.#setState(agent, "stopped", "stop");
    const r = await this.#stopProved({ agent }, "agent");
    await this.#mask(agent);
    this.#audit({ kind: "agent.stop", agent, phase: r.status === "stopped and fenced" ? "succeeded" : "unknown_effect" });
    return r;
  }

  async #stopAll(cause) {
    // A stop of all covers every recorded agent, whether or not the current grant lists it.
    const r = await this.#stopProved({ all: true }, cause);
    for (const [id] of this.#agents()) await this.#mask(id);
    this.#audit(cause === "expiry" ? { kind: "grant.expire", phase: "expired", reason: "grant_expired" } : { kind: "agent.stop", phase: r.status === "stopped and fenced" ? "succeeded" : "unknown_effect" });
    return r;
  }

  /**
   * §7 revoke capabilities: count the op; stop the old unit and prove it empty (contained, no fence); then the broker
   * revokes at a new generation; then regenerate and start. A failure or unknown outcome anywhere leaves the agent
   * contained with a fence: it runs again only after a person's resume, which regenerates its unit first.
   */
  async #revokeCaps(agent) {
    const a = this.registry.agent(agent);
    if (!a || ["revoked", "deleted"].includes(a.state)) return refuse("not_granted", "executor: unknown or ended agent");
    const wasRunning = a.state === "running";
    await this.#setState(agent, a.state, "revoke-caps");
    const fail = async (e) => {
      const c = await this.#containLocked(agent, { fence: true });
      this.#audit({ kind: "agent.revoke", agent, phase: "unknown_effect" });
      return { status: "failed", reason: e?.reason ?? e?.code ?? (e?.deadline ? "step_deadline" : "effect_failed"), settled: settledOf(e), ...c };
    };
    const held = await this.#containLocked(agent, { fence: false }); // the old unit, with its old capabilities, is gone first
    if (!held.proven) return fail(new StepFailed("not_empty", "host"));
    try { await this.#owned((ms, signal) => this.fx.brokerRevoke(agent, ms, signal), this.deadlines["broker-gen"], agent); } catch (e) { crashThrough(e); return fail(e); }
    const ga = this.#grantAgent(agent);
    if (!ga || !wasRunning) { this.#audit({ kind: "agent.revoke", agent, phase: "succeeded" }); return { status: "revoked-caps", started: false }; }
    try { await this.#proveOrRefuse(null); } catch (e) { crashThrough(e); return fail(e); } // its daemon-reload is host-wide
    try {
      await this.#owned((ms, signal) => this.fx.writeUnit(agent, a.uid, ga, ms, signal), this.deadlines.unit, agent, { widen: true });
      await this.#owned((ms, signal) => this.fx.daemonReload(ms, signal), this.deadlines["daemon-reload"], null, { widen: true });
    } catch (e) { crashThrough(e); return fail(e); }
    let started = false;
    try { started = (await this.#start(agent, this.grants.pending().gen)).started; } catch (e) { crashThrough(e); /* recorded and contained */ }
    this.#audit({ kind: "agent.revoke", agent, phase: "succeeded" });
    return { status: "revoked-caps", started };
  }

  /** Pause (freeze). A failed or unknown freeze leaves the agent contained with a fence, state `paused`. */
  async #pause(agent) {
    const a = this.registry.agent(agent);
    if (!a || a.state !== "running") return refuse("not_granted", "executor: only a running agent pauses");
    await this.#setState(agent, "paused", "pause");
    try {
      await this.#owned((ms, signal) => this.fx.freeze(agent, ms, signal), this.deadlines.freeze, agent);
    } catch (e) {
      crashThrough(e);
      const c = await this.#containLocked(agent, { fence: true });
      this.#audit({ kind: "agent.pause", agent, phase: "unknown_effect" });
      return { status: "failed", reason: e?.code ?? (e?.deadline ? "step_deadline" : "effect_failed"), settled: settledOf(e), ...c };
    }
    this.#audit({ kind: "agent.pause", agent, phase: "succeeded" });
    return { status: "paused" };
  }

  /**
   * §7: lower the agent's fence; thaw a frozen unit, or regenerate its unit from the current grant and start it (so
   * nothing an abandoned effect left behind is ever started).
   */
  async #resume(agent) {
    const a = this.registry.agent(agent);
    if (!a || !["paused", "stopped"].includes(a.state)) return refuse("not_granted", "executor: only a paused or stopped agent resumes");
    const ga = this.#grantAgent(agent);
    if (!ga) return refuse("not_granted", "executor: the current grant doesn't list this agent");
    // A thaw resumes a frozen agent's processes, a start in effect: the systemd preflight first, before its fence, its
    // state or anything else changes (#start asks again before the start itself).
    if (await this.#unqualified()) {
      this.#audit({ kind: "agent.resume", agent, phase: "refused", reason: "qualify_required" });
      return { status: "refused", reason: "qualify_required", started: false };
    }
    // Through the widening gate before ANY widening effect: its fence, its state, a thaw, a unit write, a start.
    // (Every pending agent, not only this one: a resume also reloads systemd, a host-wide widening effect.)
    try { await this.#proveOrRefuse(null); } catch (e) { crashThrough(e); return { status: "refused", reason: "pending_proof", started: false }; }
    this.#widen(agent);
    // A paused agent's thaw resumes its processes: under a lease, only with its live lease and `lease` down, checked
    // before anything changes (the thaw helper checks it all again under the activation lock).
    let live = null;
    if (this.lease && a.state === "paused") {
      if (this.#leaseUp(agent)) { this.lease.due(agent); return { status: "refused", reason: "lease_raised", started: false }; }
      live = await this.lease.live(agent);
      if (live === null) { this.lease.due(agent); return { status: "refused", reason: "no_lease", started: false }; }
    }
    await lowerFence("agent", agent, "resume-agent", { dir: this.fenceDir, agentState: a.state });
    const wasPaused = a.state === "paused";
    await this.#setState(agent, "running", "resume"); // also clears start_failed
    if (wasPaused && this.lease) {
      await this.barrier("before_thaw", { agent });
      let ok = false;
      try { ok = await this.lease.thaw(agent, live); } catch (e) { crashThrough(e); }
      if (ok) { this.#audit({ kind: "agent.resume", agent, phase: "succeeded" }); return { status: "resumed", started: true, thawed: true }; }
      // Refused under the lock (an expiry at or before the thaw, or a failed thaw): contained, with its own fence.
      const c = await this.#containLocked(agent, { fence: true });
      this.#audit({ kind: "agent.resume", agent, phase: "failed_no_effect" });
      return { status: "failed", reason: "lease", started: false, ...c };
    }
    if (wasPaused) {
      try {
        await this.#owned((ms, signal) => this.fx.thaw(agent, ms, signal), this.deadlines.freeze, agent, { widen: true });
        this.#audit({ kind: "agent.resume", agent, phase: "succeeded" });
        return { status: "resumed", started: true, thawed: true };
      } catch (e) {
        crashThrough(e);
        // A thaw that may still complete: contain with a fence and stop here. Otherwise it wasn't frozen (contained, or
        // it crossed a recovery): start it below.
        if (!settledOf(e)) {
          const c = await this.#containLocked(agent, { fence: true });
          this.#audit({ kind: "agent.resume", agent, phase: "unknown_effect" });
          return { status: "failed", reason: "step_deadline", settled: false, ...c };
        }
      }
    }
    try {
      await this.#owned((ms, signal) => this.fx.writeUnit(agent, a.uid, ga, ms, signal), this.deadlines.unit, agent, { widen: true });
      await this.#owned((ms, signal) => this.fx.daemonReload(ms, signal), this.deadlines["daemon-reload"], null, { widen: true });
      const r = await this.#start(agent, this.grants.pending().gen);
      this.#audit({ kind: "agent.resume", agent, phase: r.started ? "succeeded" : "failed_no_effect" });
      return { status: "resumed", ...r };
    } catch (e) {
      crashThrough(e);
      if (!(e instanceof StepFailed)) await this.#containLocked(agent, { fence: !settledOf(e) });
      return { status: "resumed", started: false, why: e?.reason ?? e?.code ?? "effect_failed" };
    }
  }

  async #resumeAll() {
    // Lowering fence/all widens every agent: every pending one is proven first, or nothing is lowered.
    try { await this.#proveOrRefuse(null); } catch (e) { crashThrough(e); return { status: "refused", reason: "pending_proof", started: [] }; }
    await lowerFence("all", null, "resume-all", { dir: this.fenceDir });
    const gen = this.grants.pending().gen;
    const started = [];
    for (const [id, a] of this.#agents()) {
      if (a.state === "running" && a.start_failed === null) { try { if ((await this.#start(id, gen)).started) started.push(id); } catch (e) { crashThrough(e); /* recorded and contained */ } }
    }
    return { status: "resumed", started };
  }

  async #delete(agent) {
    const a = this.registry.agent(agent);
    if (!a) return refuse("not_granted", "executor: unknown agent");
    if (a.state !== "deleted") await this.#setState(agent, "deleted", "delete");
    const r = await this.#stopProved({ agent }, "agent");
    await this.#mask(agent);
    this.#audit({ kind: "agent.delete", agent, phase: r.status === "stopped and fenced" ? "succeeded" : "unknown_effect" });
    // Deprovision (deprovision r3.2): only on a PROVEN stop; otherwise the agent stays pending and recovery retries.
    if (r.status === "stopped and fenced" && !this.grants.pendingProofs().includes(agent)) await this.#deprovision(agent);
    return r;
  }

  /**
   * One deprovision pass for a deleted agent (deprovision.mjs takes its own two proofs before any step). Its result is
   * audited; a parked or failed pass leaves the agent pending for the next recovery, never an error for the caller.
   */
  async #deprovision(agent) {
    // While an abandoned effect may still complete, no new pass starts (it stays pending for the next recovery).
    if (this.#unsettled.size > 0) return { status: "pending", step: null, reason: "in_progress" };
    let d;
    // Owned: the deadline aborts its signal (every seam of the pass takes it); one that doesn't settle within the
    // grace is abandoned, the queue goes on, and the agent is contained again when it finally settles.
    try { d = await this.#owned((ms, signal) => this.fx.deprovision(agent, ms, signal), this.deadlines.deprovision, agent); } catch (e) {
      crashThrough(e);
      this.#audit({ kind: "agent.deprovision", agent, phase: "unknown_effect" });
      return { status: "pending", step: null, reason: e?.deadline ? "step_deadline" : "host-side failure", settled: settledOf(e) };
    }
    this.#audit(d.status === "done"
      ? { kind: "agent.deprovision", agent, phase: "succeeded" }
      : { kind: "agent.deprovision", agent, phase: "pending", step: d.step, reason: d.reason });
    return d;
  }

  /**
   * The local root host commands (deprovision r3.2 §3.6): `requalify` rebinds a deleted agent's stale-epoch identities
   * after an exact durable match; `purge` removes a done agent's archives. Each takes its own two fresh proofs
   * (deprovision.mjs), runs owned under the deprovision deadline in this one queue (so after the fence and store locks
   * every input takes), and is audited. Only a deleted agent; never a remote op (MAY).
   */
  async #hostCommand(cmd, agent) {
    if (this.registry.agent(agent)?.state !== "deleted") return { status: "refused", reason: "not_deleted" };
    let d;
    try { d = await this.#owned((ms, signal) => this.fx[cmd](agent, ms, signal), this.deadlines.deprovision, agent); } catch (e) {
      crashThrough(e);
      this.#audit({ kind: `agent.${cmd}`, agent, phase: "unknown_effect" });
      return { status: "pending", step: null, reason: e?.deadline ? "step_deadline" : "host-side failure", settled: settledOf(e) };
    }
    this.#audit(d.status === "pending"
      ? { kind: `agent.${cmd}`, agent, phase: "pending", reason: d.reason }
      : { kind: `agent.${cmd}`, agent, phase: "succeeded", ...(d.rebound ? { rebound: d.rebound } : {}) });
    return d;
  }
}
