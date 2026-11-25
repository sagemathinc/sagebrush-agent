// Host supervisor (design: agent-autonomous-host-execution-lease.md r3.12 §3, §3.1; lease wire type r3 §2.4): the
// execution lease's renewal state machine. Its decisions run as ops in the supervisor's ONE executor queue
// (executor.mjs: lease-request, lease-response, lease-timer), so none runs concurrently with another for the same agent,
// nor with a grant's application, a stop or its proof.
//
// Per agent, in memory only (a lease is volatile: never accepted from disk):
//   lg           the local lease generation: every lg this process gives a lease or an expiry is new. It starts above
//                every lg the runtime files have seen (the tombstone, the published record), so a restarted supervisor
//                never reuses a spent one
//   current      the lease this process published, { lease_id, lg, expiry_tick, gen }, or null
//   outstanding  the ONE request in flight, { request (the SHA-256 of its signed bytes), gen, nonce, boot_id,
//                sent_tick }, or null; a new request replaces it, and acceptance clears it (a response counts once)
// Times are CLOCK_BOOTTIME in ms (lease.mjs realClock.boot; never Node's clocks, which stop during suspend). sent_tick is
// read before the request is signed and sent, so the expiry, sent_tick + ttl_ms, is never later than the service's.
//
// - request(agent, gen): a fresh outstanding request for the agent's CURRENT entry generation, and its signed bytes.
// - accept(agent, bytes, currentGen): the full check of a response, run when its op runs (after any stop or proof ahead
//   of it in the queue): the injected verifier (verifyExecutionLease: signature under the lease key in force, this
//   host, the outstanding request echoed exactly, 0 < ttl_ms <= 10 min), then here, the agent's entry generation is
//   still the request's, and the response isn't expired on arrival at its EFFECTIVE end: now < sent_tick + ttl_ms - 30 s
//   (SEC H1). Then the re-arm (§2.1): arm the new watchdog and verify it, publish (with its own re-checks), stop the old
//   watchdog. Anything short of a publish leaves the lease unused; whatever was armed for it only ever stops.
// - expire(agent, lease_id, lg): a bound timer. It acts only if both still name the current lease.
// - invalidate(agent): a grant changed the agent's generation (or added it): the lease and the request are void now.
// - live(agent): the published record AND liveCheck (lease-live.mjs liveLease) AND the lease this process accepted.
// - activate(agent, rec): the activation helper (lease.mjs), which alone lowers `lease`. Never under the fence lock.
// - thaw(agent, rec): the thaw helper (lease.mjs), the only way a paused agent is thawed under a lease.
// - due(agent) / renew(agent): the cadence, outside the queue: a lease-request op, the send (injected), then a
//   lease-response op; every RENEW_MS while the supervisor asks for the agent, until an op says it no longer does.
// Nothing here lowers a fence, unmasks or starts anything itself.

import { randomBytes } from "node:crypto";
import * as fs from "node:fs";
import { isId, refuse } from "../bytes.mjs";
import { LEASE_DIR, MARGIN_MS, activationArgv, armWatchdog, bootNow, publish, readGate, readRecord, readTombstone, realClock, realSystem, runHelper, thawArgv, watchdogTimer } from "./lease.mjs";
import { liveLease } from "./lease-live.mjs";
import { realIo } from "./store.mjs";

/** The renewal period (§3: at start, then every 2 minutes, and right away when a grant changes the generation). */
export const RENEW_MS = 120000;
/** The longest lease (§3: 0 < ttl <= 10 minutes). */
export const MAX_TTL_MS = 600000;
/** Why a response was ignored, counted for health (§3: each is counted). */
export const IGNORED = Object.freeze(["no_request", "refused", "mismatch", "stale_gen", "ttl", "expired", "suspended"]);
/** Why an accepted response's lease wasn't used: its watchdog not armed and verified, or a re-check before publication. */
export const UNUSED = Object.freeze(["unverified", "not_published"]);

const need = (agent) => { if (!isId(agent)) refuse("bad_form", "lease: bad agent id"); return agent; };
const realTimers = Object.freeze({
  set: (ms, fn) => { const t = setTimeout(fn, Math.max(0, ms)); t.unref?.(); return t; },
  clear: (t) => clearTimeout(t),
});
const realBootId = () => fs.readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim();

export class LeaseMachine {
  #agents = new Map();
  #counts = Object.fromEntries([...IGNORED, ...UNUSED].map((k) => [k, 0]));

  /**
   * `verify(bytes, ctx)` → { body, hash }: core's verifyExecutionLease (throws to refuse). `context()` → { aud, fleet,
   * chain, host, hostKey }: this host's certified id and certificate fingerprint and the chain it holds now. `sign(body)`
   * → { bytes, hash }: an sb.lease-request.v1 signed with the host's certified key, `hash` the SHA-256 of its signed
   * bytes. `submit(op)`: queue an op on the supervisor (the timers' only way in). `send(bytes)` → the response's bytes,
   * or null: the host's service channel (none: no response ever, so every lease fence stays raised). Test seams: { dir,
   * fsx, io, sys, clock, run, helperMs, timers, bootId, nonce, wall }.
   */
  constructor({ verify, context, sign, submit, send = async () => null, dir = LEASE_DIR, fsx = fs, io = realIo, sys = realSystem(), clock = realClock,
    run, helperMs = 30000, timers = realTimers, bootId = realBootId, nonce = () => randomBytes(16).toString("base64url"), wall = Date.now }) {
    if (typeof verify !== "function" || typeof context !== "function" || typeof sign !== "function" || typeof submit !== "function") {
      refuse("bad_form", "lease: verify, context, sign and submit are required");
    }
    Object.assign(this, { verify, context, sign, submit, send, dir, fsx, io, sys, clock, run, helperMs, timers, bootId, nonce, wall });
  }

  /** Ignored and unused responses so far, by reason (health). */
  get counts() { return { ...this.#counts }; }

  #state(agent) {
    need(agent);
    let s = this.#agents.get(agent);
    if (!s) {
      s = { lg: this.#seen(agent), current: null, outstanding: null, timer: null, next: null };
      this.#agents.set(agent, s);
    }
    return s;
  }

  /** The highest lg the runtime files have seen (a watchdog acts on its lg and below, so a reused lg is spent). */
  #seen(agent) {
    const spent = readTombstone(agent, { dir: this.dir, fsx: this.fsx }) ?? 0;
    const r = readRecord(agent, { dir: this.dir, fsx: this.fsx });
    return Math.max(spent, r.state === "ok" ? r.rec.lg : 0);
  }

  /** The lease this process accepted and published for the agent, or null. */
  current(agent) { const c = this.#state(agent).current; return c ? { ...c } : null; }
  /** The outstanding request, or null. */
  outstanding(agent) { const o = this.#state(agent).outstanding; return o ? { ...o } : null; }
  /** The agent's current lg. */
  lg(agent) { return this.#state(agent).lg; }

  /** Supervisor start: every agent starts with no lease and no request (the caller raises every `lease` fence). */
  init(agent) {
    const s = this.#state(agent);
    this.#void(s, { request: true });
    s.lg = Math.max(s.lg, this.#seen(agent));
  }

  /**
   * Every agent's lease and outstanding request void (lg + 1 each, timers cleared): the reopen after a suspend
   * (lease-on r1.5 §6.5 step 1), so nothing from before the suspend is used again.
   */
  voidAll() {
    for (const s of this.#agents.values()) { this.#void(s, { request: true }); s.lg += 1; }
  }

  /** The lease is void (its timer cleared); with `request`, the outstanding request too. */
  #void(s, { request }) {
    if (s.timer !== null) { this.timers.clear(s.timer); s.timer = null; }
    s.current = null;
    if (request) s.outstanding = null;
  }

  /** A grant changed (or added) the agent's entry generation: its lease and its request are void now (lg + 1). */
  invalidate(agent) {
    const s = this.#state(agent);
    this.#void(s, { request: true });
    s.lg += 1;
  }

  /**
   * A new outstanding request for `gen` (it replaces any other); resolves to its signed bytes, or null while the
   * suspend gate is closed (lease-on r1.5 §6.2: no request then). The request records the gate's generation `sg`.
   */
  async request(agent, gen) {
    const s = this.#state(agent);
    if (!Number.isSafeInteger(gen) || gen < 1) refuse("bad_form", "lease: bad gen");
    const gate = readGate({ dir: this.dir, fsx: this.fsx, clock: this.clock });
    if (!gate.open) return null;
    const { aud, fleet, host } = this.context();
    const nonce = this.nonce(), boot_id = this.bootId();
    // Read BEFORE the request exists: the expiry it starts can only come early.
    const sent_tick = this.clock.boot();
    const { bytes, hash } = await this.sign({ fleet, aud, agent, host, gen, nonce, boot_id, at_ms: this.wall() });
    s.outstanding = { request: hash, gen, nonce, boot_id, sent_tick, sg: gate.g };
    return bytes;
  }

  #ignore(reason) { this.#counts[reason]++; return { accepted: false, reason }; }

  /**
   * One response, checked in full now. `currentGen`: the agent's entry generation in the accepted grant now (null if
   * it lists the agent no more). Resolves { accepted: true, rec } after the publish, else { accepted: false, reason }.
   */
  async accept(agent, bytes, currentGen) {
    const s = this.#state(agent);
    const out = s.outstanding;
    if (out === null) return this.#ignore("no_request");
    let v;
    try {
      v = await this.verify(bytes, { ...this.context(), outstanding: { request: out.request, agent, gen: out.gen, nonce: out.nonce, boot_id: out.boot_id } });
    } catch { return this.#ignore("refused"); } // a forged or foreign copy never voids the real request in flight
    if (s.outstanding !== out) return this.#ignore("no_request"); // replaced while verifying
    const b = v?.body;
    if (!b || b.agent !== agent || b.gen !== out.gen || b.nonce !== out.nonce || b.boot_id !== out.boot_id || b.request !== out.request) return this.#ignore("mismatch");
    if (currentGen !== out.gen) { s.outstanding = null; return this.#ignore("stale_gen"); }
    if (!Number.isSafeInteger(b.ttl_ms) || b.ttl_ms <= 0 || b.ttl_ms > MAX_TTL_MS) { s.outstanding = null; return this.#ignore("ttl"); }
    const expiry_tick = out.sent_tick + b.ttl_ms;
    // Expired on arrival at the EFFECTIVE end, the watchdog's fire point (SEC H1); publish checks it again.
    if (!(bootNow(this.clock) < expiry_tick - MARGIN_MS)) { s.outstanding = null; return this.#ignore("expired"); }
    // The suspend gate must still be open at the generation the request was made under (§6.2): a response to a
    // request from before a suspend is never used after it.
    const gate = readGate({ dir: this.dir, fsx: this.fsx, clock: this.clock });
    if (!gate.open || gate.g !== out.sg) { s.outstanding = null; return this.#ignore("suspended"); }
    s.outstanding = null; // a response counts at most once
    s.lg += 1;
    const rec = { lease_id: b.lease_id, lg: s.lg, expiry_tick, gen: b.gen, sg: out.sg };
    const opts = { dir: this.dir, fsx: this.fsx, io: this.io, sys: this.sys, clock: this.clock };
    // (1) arm and verify the new watchdog; (2) publish, re-checked right before; (3) stop the old watchdog.
    try { await armWatchdog(agent, rec, { sys: this.sys, clock: this.clock }); } catch { this.#counts.unverified++; return { accepted: false, reason: "unverified" }; }
    if (!(await publish(agent, rec, opts))) { this.#counts.not_published++; return { accepted: false, reason: "not_published" }; }
    const old = s.current;
    if (s.timer !== null) this.timers.clear(s.timer);
    s.current = rec;
    s.timer = this.timers.set(rec.expiry_tick - MARGIN_MS - bootNow(this.clock),
      () => this.submit({ kind: "lease-timer", authority: "host", agent, lease_id: rec.lease_id, lg: rec.lg }).catch(() => {}));
    if (old) { try { await this.sys.disarm(watchdogTimer(agent, old.lg)); } catch { /* stale: it sees a newer lg and does nothing */ } }
    return { accepted: true, rec: { ...rec } };
  }

  /**
   * A timer bound to (lease_id, lg): true when it still names the current lease, which is then void (lg + 1). The
   * outstanding request stays: a response to it, queued behind this expiry's stop, is checked in full when it runs.
   */
  expire(agent, leaseId, lg) {
    const s = this.#state(agent);
    if (s.current === null || s.current.lease_id !== leaseId || s.current.lg !== lg) return false;
    this.#void(s, { request: false });
    s.lg += 1;
    return true;
  }

  /** The agent's live lease: the published record passes liveCheck AND is exactly the lease this process accepted. */
  async live(agent) {
    const c = this.#state(agent).current;
    if (c === null) return null;
    const l = await liveLease(agent, { dir: this.dir, fsx: this.fsx, sys: this.sys, clock: this.clock });
    if (l === null || l.lease_id !== c.lease_id || l.lg !== c.lg || l.gen !== c.gen || l.expiry_tick !== c.expiry_tick || l.sg !== c.sg) return null;
    return l;
  }

  /**
   * Run the activation helper for `rec` (lowers `lease`, unmasks, queues the start, all under the activation lock and
   * its own re-checks). Refused (lock_order) under the fence lock. Resolves true only on the helper's exit 0.
   */
  async activate(agent, rec) {
    need(agent);
    const r = await runHelper(activationArgv(agent, rec.lease_id, rec.lg), { ...(this.run ? { run: this.run } : {}), ms: this.helperMs });
    return r?.code === 0;
  }

  /** Run the thaw helper for `rec` (its own checks under the activation lock). Resolves true only on its exit 0. */
  async thaw(agent, rec) {
    need(agent);
    const r = await runHelper(thawArgv(agent, rec.lease_id, rec.lg), { ...(this.run ? { run: this.run } : {}), ms: this.helperMs });
    return r?.code === 0;
  }

  /** Renew the agent after `ms` (default now); one schedule per agent, a later call replacing it. */
  due(agent, ms = 0) {
    const s = this.#state(agent);
    if (s.next !== null) this.timers.clear(s.next);
    s.next = this.timers.set(ms, () => { s.next = null; return this.renew(agent).catch(() => {}); });
  }

  /**
   * One renewal: the request op, the send, the response op. The next one is scheduled unless the supervisor no longer
   * asks for this agent (skipped: not listed, ended, or stopped by a person; a resume calls due() again).
   */
  async renew(agent) {
    let r;
    try { r = await this.submit({ kind: "lease-request", authority: "host", agent }); } catch { r = { status: "failed" }; }
    if (r?.status === "skipped") return r;
    this.due(agent, RENEW_MS);
    if (r?.status !== "requested") return r;
    let resp;
    try { resp = await this.send(r.bytes); } catch { return { status: "send_failed" }; }
    if (resp === null || resp === undefined) return { status: "no_response" };
    return this.submit({ kind: "lease-response", authority: "host", agent, bytes: resp });
  }
}
