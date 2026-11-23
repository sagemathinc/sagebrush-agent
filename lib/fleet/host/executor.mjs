// Host supervisor (design: agent-autonomous-host-supervisor-freeze-r3.1.md §3.2–§3.4, §7): the executor. One work queue
// runs every input to completion or to a durable failure state, one at a time; stops, capability revocations, expiry
// and the local stop-all go to the front, and preempt an application at its next step boundary (or when the step's
// deadline passes). Nothing is ever run concurrently with anything else.
//
// The effects are injected (`fx`): this module decides order, durability and failure handling only; the real systemd,
// users, directories, network and broker calls live in a separate module. Inputs arrive already authenticated by the
// caller (grant envelopes are checked here by `verify`; ops by their signature or channel, upstream); this module
// enforces which authority may do what: the service channel and the local CLI only narrow, a person also resumes and
// deletes.
//
// Applying generation N (§3.3): verify → durable intent → grant bytes, highwater and applying(N, plan) (GrantState) →
// the plan's steps (plan.mjs), each durably marked done → applied(N) with its acknowledgement → the acknowledgement.
// Design choices, as ruled for this part:
// - Narrowing (plan.mjs): any change to an agent's entry or its tags' membership stops, masks, regenerates, restarts.
// - An agent missing from grant N is retired: run state `stopped` (no lifecycle op counted), stopped and masked. It
//   runs again only when a later grant lists it and a person resumes it.
// - A failed step, by cause:
//   - agent-side (a start refused for preflight_missing or landlock_abi; a unit that failed; a start past its
//     deadline): the agent's start_failed is set, it is left stopped and masked, the other steps go on, and N still
//     reaches applied(N). The acknowledgement (sb.grant-ack.v1, unchanged) lists in `restarted` only the agents that
//     really started, so a failed one shows by its absence. Recovery never retries it; the next grant or a resume
//     clears start_failed.
//   - host-side (any other failure, or any other step past its deadline): the agent the step was for, if any, is left
//     stopped and masked (best effort), the phase stays applying(N), there is no acknowledgement, and the next input
//     redoes the remaining steps.
// - Expiry is an emergency like a stop: fence, stop, mask. An interrupted application stays applying(N); starts are
//   skipped while the expiry fence is up. Only a newer valid grant lowers it.
// - `revoke-caps` (§7): the op is counted, the broker revokes at a new generation, then the narrowing restart. The run
//   state is unchanged and no fence is raised. v1 has no op that moves an agent to the permanent `revoked` state.
// - Every start holds the fence lock while it checks all three fences and starts, so no start slips past a fence.
// - Run states are written durably before the effect that changes them.

import { existsSync } from "node:fs";
import { join } from "node:path";
import { FleetError, refuse } from "../bytes.mjs";
import { fenced, lowerFence, stop as fencedStop, withFenceLock } from "./fence.mjs";
import { FENCE_DIR } from "./names.mjs";
import { parseStep, planGrant } from "./plan.mjs";

/** Step deadlines in ms (§3.3; retire, mask and provision are this module's choice). */
export const DEADLINES = Object.freeze({
  "broker-gen": 5000, stop: 15000, mask: 5000, provision: 30000, unit: 5000, "daemon-reload": 30000, start: 30000,
  map: 5000, apply: 300000,
});

/** Agent-side start failures: refused before any effect (audited `refused` with the reason) … */
const START_REFUSED = Object.freeze(["preflight_missing", "landlock_abi"]);
/** … or after it may have run (audited `unknown_effect`, no reason). */
const START_UNKNOWN = Object.freeze(["unit_failed", "start_timeout"]);

const EMERGENCY = Object.freeze(["stop", "stop-all", "revoke-caps", "expiry"]);
/** Which authority may submit which op (§3.2). */
const MAY = Object.freeze({
  service: ["stop", "pause", "revoke-caps"],
  local: ["stop", "stop-all"],
  person: ["stop", "stop-all", "pause", "revoke-caps", "resume", "resume-all", "delete"],
  host: ["expiry"],
});

/** A throw from a barrier: a simulated crash in a test build. It is never handled as a step failure. */
class Crash extends Error {}
const crashThrough = (e) => { if (e instanceof Crash) throw e; };

class StepFailed extends Error {
  constructor(reason, side, unknown = false) { super(reason); this.reason = reason; this.side = side; this.unknown = unknown; }
}

/** Run `fn(ms)` with a deadline; past it, reject with a deadline error (the effect may still be running: unknown). */
function withDeadline(fn, ms) {
  let timer;
  return Promise.race([
    Promise.resolve().then(() => fn(ms)),
    new Promise((_, rej) => { timer = setTimeout(() => rej(Object.assign(new Error("step_deadline"), { deadline: true })), ms); }),
  ]).finally(() => clearTimeout(timer));
}

export class Supervisor {
  #normal = []; #urgent = []; #running = false;

  /**
   * `store`: an open HostStore (registry, grants). `fx`: the effects (the tests' fake lists every one).
   * `verify(bytes)` → { body, digest }: the full §3.2 check of a grant for this host now (throws to refuse);
   * `bodyOf(bytes)` → the body of bytes accepted earlier (no time check).
   * Options: { fenceDir, deadlines, barrier: async (name, detail) => {} (a test hook; production passes none) }.
   */
  constructor({ store, fx, verify, bodyOf, fenceDir = FENCE_DIR, deadlines = {}, barrier = async () => {} }) {
    const hook = async (name, detail) => { try { await barrier(name, detail); } catch (e) { throw Object.assign(new Crash(e?.message ?? "crash"), { cause: e }); } };
    Object.assign(this, { store, fx, verify, bodyOf, fenceDir, deadlines: { ...DEADLINES, ...deadlines }, barrier: hook });
  }

  get registry() { return this.store.registry; }
  get grants() { return this.store.grants; }

  /**
   * Queue an input; resolves with its result. `{ kind: "grant", bytes }`, or an op `{ kind, authority, agent? }`.
   * Emergencies go to the front, still one at a time.
   */
  submit(input) {
    const kind = input?.kind;
    if (kind !== "grant" && !(Object.hasOwn(MAY, input?.authority ?? "") && MAY[input.authority].includes(kind))) {
      return Promise.reject(new FleetError("not_granted", "executor: that authority can't do that"));
    }
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
    switch (input.kind) {
      case "grant": return this.#grant(input.bytes);
      case "continue": return this.grants.pending().phase === "applying" ? this.#continue() : { status: "applied" };
      case "recover": return this.#recover();
      case "stop": return input.agent ? this.#stopAgent(input.agent) : this.#stopAll("all");
      case "stop-all": return this.#stopAll("all");
      case "expiry": return this.#stopAll("expiry");
      case "revoke-caps": return this.#revokeCaps(input.agent);
      case "pause": return this.#pause(input.agent);
      case "resume": return this.#resume(input.agent);
      case "resume-all": return this.#resumeAll();
      case "delete": return this.#delete(input.agent);
      default: return refuse("bad_form", "executor: unknown input");
    }
  }

  // ---- grants (§3.3)

  async #grant(bytes) {
    // An unfinished application is redone first: the next input redoes the remaining steps.
    if (this.grants.pending().phase === "applying") {
      const r = await this.#continue();
      if (r.status !== "applied") return { status: "refused", reason: "in_progress", previous: r };
    }
    const { body, digest } = this.verify(bytes);
    const gen = body.gen;
    if (this.grants.admit(gen, digest).reapply) {
      // A byte-identical re-apply has no effect; it re-sends the acknowledgement.
      return { status: "reapplied", gen, ack: await this.#sendAck(gen, this.grants.ack) };
    }
    const prevBytes = this.grants.currentBytes();
    // After expiry every listed agent is restarted by the newer grant (§3.4); the plan holds that durably.
    const expired = existsSync(join(this.fenceDir, "expiry"));
    const { steps } = planGrant(prevBytes ? this.bodyOf(prevBytes) : null, body, this.registry, { all: expired });
    await this.barrier("after_verify", { gen });
    await this.grants.begin(gen, bytes, digest, steps, async (rec) => { await this.fx.appendIntent(rec); await this.barrier("after_intent", { gen }); });
    await this.barrier("after_highwater_persist", { gen });
    // A newer valid grant lowers the expiry fence, and nothing else (§3.3): accepted, so it is the newer one.
    await lowerFence("expiry", null, "newer-grant", { dir: this.fenceDir });
    return this.#continue();
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
      try { active = (await withDeadline((ms) => this.fx.isActive(agent, ms), this.deadlines.mask)) === true; } catch { /* not proven */ }
      if (active) restarted.push(agent);
    }
    return { narrowed: parsed.some((s) => s.kind === "stop"), restarted: restarted.sort() };
  }

  async #sendAck(gen, ack) {
    try { await this.fx.sendAck(gen, ack); } catch { /* re-sent on a byte-identical re-apply */ }
    return ack;
  }

  async #hostFailure(gen, step, e) {
    const unknown = e?.deadline === true || e?.unknown === true;
    if (e?.deadline === true) await this.barrier("step_deadline", { step });
    const { agent } = parseStep(step);
    if (agent) await this.#quiesce(agent);
    this.#audit({ kind: "grant.apply", gen, step, phase: unknown ? "unknown_effect" : "failed_no_effect" });
    return { status: "failed", gen, step, reason: e?.reason ?? e?.code ?? (unknown ? "step_deadline" : "effect_failed") };
  }

  /** One plan step, idempotent. Throws StepFailed (agent- or host-side) or an effect's error (host-side). */
  async #step(step, gen, body) {
    const { kind, agent } = parseStep(step);
    const ga = agent ? body.agents.find((a) => a.agent === agent) ?? null : null;
    const d = this.deadlines;
    // An agent deleted since the plan was made (an op between two inputs) only ever gets stopped and masked.
    if (agent && this.registry.agent(agent)?.state === "deleted" && !["stop", "mask"].includes(kind)) return undefined;
    switch (kind) {
      case "broker-gen":
        await withDeadline((ms) => this.fx.brokerGen(gen, ms), d["broker-gen"]);
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
        await withDeadline((ms) => this.fx.mask(agent, ms), d.mask);
        return this.barrier("after_mask", { agent });
      case "provision": {
        for (const t of ga.tags) this.registry.addTag(t);
        const uid = this.registry.agent(agent)?.uid ?? this.registry.addAgent(agent, gen, ga.tags);
        return withDeadline((ms) => this.fx.provision(agent, uid, ga, ms), d.provision);
      }
      case "unit": {
        for (const t of ga.tags) this.registry.addTag(t);
        const { uid } = this.registry.setGrant(agent, gen, ga.tags); // also clears start_failed: a new grant
        await withDeadline((ms) => this.fx.writeUnit(agent, uid, ga, ms), d.unit);
        return this.barrier("after_unit_write", { agent });
      }
      case "daemon-reload":
        await withDeadline((ms) => this.fx.daemonReload(ms), d["daemon-reload"]);
        return this.barrier("after_daemon_reload", {});
      case "start":
        return this.#start(agent, gen);
      case "map": {
        const map = body.agents.flatMap((a) => { const r = this.registry.agent(a.agent); return r ? [{ agent: a.agent, uid: r.uid }] : []; });
        await withDeadline((ms) => this.fx.publishMap(gen, map, ms), d.map);
        return this.barrier("after_map_publish", { gen });
      }
      default: return refuse("bad_form", "executor: unknown step");
    }
  }

  /** Stop one unit and prove its cgroup empty, within the stop deadline; not empty is a host-side failure. */
  async #stopUnit(agent) {
    await withDeadline(async (ms) => {
      const t0 = Date.now();
      await this.fx.stopUnit(agent, ms);
      const n = await this.fx.procCount(agent, Math.max(1, ms - (Date.now() - t0)));
      if (n !== 0) throw new StepFailed("not_empty", "host");
    }, this.deadlines.stop);
  }

  /**
   * Start one agent if its run state allows it and none of its fences is up, holding the fence lock across the check
   * and the start. A skip is not a failure. Agent-side failures are recorded and thrown as StepFailed("agent").
   */
  async #start(agent, gen) {
    const a = this.registry.agent(agent);
    if (!a || !["provisioned", "running"].includes(a.state) || a.start_failed !== null) return { started: false, why: "state" };
    return withFenceLock(async () => {
      if (fenced(agent, { dir: this.fenceDir })) return { started: false, why: "fenced" };
      if (a.state === "provisioned") await this.#setState(agent, "running"); // durable before the effect
      await this.fx.appendIntent({ kind: "agent.start", agent, gen });
      await this.barrier("before_start", { agent });
      try {
        await withDeadline(async (ms) => { await this.fx.unmask(agent, ms); await this.fx.start(agent, ms); }, this.deadlines.start);
      } catch (e) {
        if (e?.deadline) await this.barrier("step_deadline", { step: `start:${agent}` });
        const reason = e?.deadline ? "start_timeout" : e instanceof FleetError && [...START_REFUSED, ...START_UNKNOWN].includes(e.code) ? e.code : null;
        await this.#quiesce(agent);
        if (reason === null) throw new StepFailed(e?.code ?? "effect_failed", "host", true);
        this.registry.setStartFailed(agent, reason);
        this.#audit(START_REFUSED.includes(reason)
          ? { kind: "agent.start", agent, gen, phase: "refused", reason }
          : { kind: "agent.start", agent, gen, phase: "unknown_effect" });
        throw new StepFailed(reason, "agent");
      }
      await this.barrier("after_start", { agent });
      this.#audit({ kind: "agent.start", agent, gen, phase: "succeeded" });
      return { started: true };
    }, { dir: this.fenceDir });
  }

  /** Leave an agent stopped and masked, best effort: a failed step never leaves older, wider authority running. */
  async #quiesce(agent) {
    try { await withDeadline((ms) => this.fx.stopUnit(agent, ms), this.deadlines.stop); } catch { /* best effort */ }
    await this.#mask(agent);
  }

  async #mask(agent) { try { await withDeadline((ms) => this.fx.mask(agent, ms), this.deadlines.mask); } catch { /* the fence or state still holds */ } }

  /** Every run-state record goes through here: durable before the effect it precedes. */
  async #setState(agent, state, op = null) {
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

  // ---- recovery (§3.3)

  async #recover() {
    this.registry.reload(); this.grants.reload();
    for (const g of (await this.fx.openIntents?.()) ?? []) {
      const r = this.grants.reconcileIntent(g); // AU07: highwater below g proves no effect
      this.#audit({ kind: "grant.apply", gen: g, phase: r === "failed_no_effect" ? "reconciled_no_effect" : "reconciled_succeeded" });
    }
    const { phase, gen } = this.grants.pending();
    if (gen === 0) return { status: "empty" };
    if (phase === "applying") return this.#continue();
    let body;
    try { body = this.verify(this.grants.currentBytes()).body; } catch { return { status: "not_started", reason: "grant_not_valid" }; }
    const allowed = new Set(body.agents.map((x) => x.agent));
    const started = [];
    for (const [id, a] of this.#agents()) {
      if (a.state === "paused") { await this.#setState(id, "stopped"); await this.#quiesce(id); continue; } // a pause never becomes a run
      if (a.state === "running" && a.start_failed === null && allowed.has(id)) {
        try { if ((await this.#start(id, gen)).started) started.push(id); } catch (e) { crashThrough(e); /* recorded; it stays stopped and masked */ }
      }
    }
    return { status: "recovered", gen, started };
  }

  // ---- narrowing and lifecycle ops (§7)

  async #stopAgent(agent) {
    const a = this.registry.agent(agent);
    if (!a) return refuse("not_granted", "executor: unknown agent");
    if (["provisioned", "running", "paused"].includes(a.state)) await this.#setState(agent, "stopped", "stop");
    const r = await fencedStop({ agent }, "agent", { sys: this.fx.sys, dir: this.fenceDir, barrier: this.barrier });
    await this.#mask(agent);
    this.#audit({ kind: "agent.stop", agent, phase: r.status === "stopped and fenced" ? "succeeded" : "unknown_effect" });
    return r;
  }

  async #stopAll(cause) {
    const r = await fencedStop({ all: true }, cause, { sys: this.fx.sys, dir: this.fenceDir, barrier: this.barrier });
    for (const [id] of this.#agents()) await this.#mask(id);
    this.#audit(cause === "expiry" ? { kind: "grant.expire", phase: "expired", reason: "grant_expired" } : { kind: "agent.stop", phase: r.status === "stopped and fenced" ? "succeeded" : "unknown_effect" });
    return r;
  }

  /** §7 revoke capabilities: count the op, the broker revokes at a new generation, then the narrowing restart. */
  async #revokeCaps(agent) {
    const a = this.registry.agent(agent);
    if (!a || ["revoked", "deleted"].includes(a.state)) return refuse("not_granted", "executor: unknown or ended agent");
    await this.#setState(agent, a.state, "revoke-caps");
    await withDeadline((ms) => this.fx.brokerRevoke(agent, ms), this.deadlines["broker-gen"]);
    const ga = this.#grantAgent(agent);
    try {
      await this.#stopUnit(agent);
      await withDeadline((ms) => this.fx.mask(agent, ms), this.deadlines.mask);
      if (ga) {
        await withDeadline((ms) => this.fx.writeUnit(agent, a.uid, ga, ms), this.deadlines.unit);
        await withDeadline((ms) => this.fx.daemonReload(ms), this.deadlines["daemon-reload"]);
      }
    } catch (e) {
      await this.#quiesce(agent);
      this.#audit({ kind: "agent.revoke", agent, phase: "unknown_effect" });
      return { status: "failed", reason: e?.reason ?? e?.code ?? "effect_failed" };
    }
    let started = false;
    if (ga) { try { started = (await this.#start(agent, this.grants.pending().gen)).started; } catch (e) { crashThrough(e); /* recorded */ } }
    this.#audit({ kind: "agent.revoke", agent, phase: "succeeded" });
    return { status: "revoked-caps", started };
  }

  #grantAgent(agent) {
    const bytes = this.grants.currentBytes();
    return bytes ? this.bodyOf(bytes).agents.find((x) => x.agent === agent) ?? null : null;
  }

  async #pause(agent) {
    const a = this.registry.agent(agent);
    if (!a || a.state !== "running") return refuse("not_granted", "executor: only a running agent pauses");
    await this.#setState(agent, "paused", "pause");
    await withDeadline((ms) => this.fx.freeze(agent, ms), this.deadlines.stop);
    this.#audit({ kind: "agent.pause", agent, phase: "succeeded" });
    return { status: "paused" };
  }

  /** §7: lower the agent's fence; thaw a frozen unit, or unmask and start a stopped one with the current grant. */
  async #resume(agent) {
    const a = this.registry.agent(agent);
    if (!a || !["paused", "stopped"].includes(a.state)) return refuse("not_granted", "executor: only a paused or stopped agent resumes");
    if (!this.#grantAgent(agent)) return refuse("not_granted", "executor: the current grant doesn't list this agent");
    await lowerFence("agent", agent, "resume-agent", { dir: this.fenceDir, agentState: a.state });
    const wasPaused = a.state === "paused";
    await this.#setState(agent, "running", "resume"); // also clears start_failed
    if (wasPaused) {
      try {
        await withDeadline((ms) => this.fx.thaw(agent, ms), this.deadlines.stop);
        this.#audit({ kind: "agent.resume", agent, phase: "succeeded" });
        return { status: "resumed", started: true, thawed: true };
      } catch { /* not frozen any more (it crossed a recovery): start it below */ }
    }
    try {
      const r = await this.#start(agent, this.grants.pending().gen);
      this.#audit({ kind: "agent.resume", agent, phase: r.started ? "succeeded" : "failed_no_effect" });
      return { status: "resumed", ...r };
    } catch (e) { crashThrough(e); return { status: "resumed", started: false, why: e?.reason ?? "effect_failed" }; }
  }

  async #resumeAll() {
    await lowerFence("all", null, "resume-all", { dir: this.fenceDir });
    const gen = this.grants.pending().gen;
    const started = [];
    for (const [id, a] of this.#agents()) {
      if (a.state === "running" && a.start_failed === null) { try { if ((await this.#start(id, gen)).started) started.push(id); } catch (e) { crashThrough(e); /* recorded */ } }
    }
    return { status: "resumed", started };
  }

  async #delete(agent) {
    const a = this.registry.agent(agent);
    if (!a) return refuse("not_granted", "executor: unknown agent");
    if (a.state !== "deleted") await this.#setState(agent, "deleted", "delete");
    const r = await fencedStop({ agent }, "agent", { sys: this.fx.sys, dir: this.fenceDir, barrier: this.barrier });
    await this.#mask(agent);
    this.#audit({ kind: "agent.delete", agent, phase: r.status === "stopped and fenced" ? "succeeded" : "unknown_effect" });
    return r;
  }
}
