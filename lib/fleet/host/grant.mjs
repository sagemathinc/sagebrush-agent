// Host supervisor (design: agent-autonomous-host-supervisor-freeze-r3.1.md §3.2–§3.4): verifying a person-signed host
// grant, and the durable grant state that makes applying it crash-safe.
//
// Order of applying generation N (§3.3, as ruled): verify and prepare → durable audit intent → durable grant bytes,
// highwater = N and phase applying(N, plan) → effects → phase applied(N) → acknowledgement. This module owns the first
// three and the state; the effects (broker, units, map) are the supervisor's, which marks each plan step done here.
//
// The caller supplies what this module must not decide by itself:
// - `resolveKey(signer, type, body)`: which device keys count, from the pinned device chain (O6/O7 §2);
// - `appendIntent(record)`: the audit stream's durable append (§8.1); it returns only after the intent is durable, and
//   throws (audit_unavailable / audit_timeout) otherwise.

import { readFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { isId, refuse, sha256b64 } from "../bytes.mjs";
import { open } from "../envelope.mjs";
import { compile } from "../schema.mjs";
import { validateConfig, CONFIG_SCHEMA } from "./config.mjs";
import { DurableState, exactKeys, realIo, writeExclusive } from "./store.mjs";

// ---- the host-grant schema, with config_schema 1 in place of the shared schema's reserved `config`

const readJson = (rel) => JSON.parse(readFileSync(new URL(rel, import.meta.url), "utf8"));
const fleetDefs = readJson("../../../schema/fleet/fleet.schema.json").$defs;
const configDefs = readJson("../../../schema/fleet/host-config.schema.json").$defs;
for (const name of Object.keys(configDefs)) {
  if (name !== "config" && Object.hasOwn(fleetDefs, name)) throw new Error(`host-config.schema.json $defs/${name} collides with fleet.schema.json`);
}
const validateGrantBody = compile({ $defs: { ...fleetDefs, ...configDefs }, $ref: "#/$defs/host-grant" });

/**
 * Verify a grant envelope's bytes for this host. `ctx`: { aud, fleet, host, cert (the base64url sha256 of this host's
 * certificate), now (ms), resolveKey, hostInfo: { ramMb, cpus } }. Returns { body, digest } or throws a FleetError.
 * Doesn't look at stored state: the generation rule is `admit`'s.
 */
export function verifyGrant(bytes, ctx) {
  const { type, body } = open(bytes, { aud: ctx.aud, fleet: ctx.fleet, resolveKey: ctx.resolveKey });
  if (type !== "sb.host-grant.v1") refuse("bad_form", "not a host grant");
  validateGrantBody(body);
  if (body.host !== ctx.host) refuse("not_granted", "a grant for another host");
  if (body.cert !== ctx.cert) refuse("not_granted", "a grant for another host key");
  if ((body.not_after_ms === null) !== (body.no_expiry_ack === true)) refuse("bad_form", "no_expiry_ack exactly when there is no expiry");
  if (!Number.isSafeInteger(ctx.now)) refuse("bad_form", "no clock");
  if (ctx.now < body.not_before_ms) refuse("grant_expired", "the grant is not valid yet");
  if (body.not_after_ms !== null && ctx.now >= body.not_after_ms) refuse("grant_expired"); // in force: not_before ≤ now < not_after (O6/O7 r2.3 §1.6)
  const tagIds = new Set(body.tags.map((t) => t.tag));
  if (tagIds.size !== body.tags.length) refuse("bad_form", "tags must be unique");
  const agentIds = new Set(body.agents.map((a) => a.agent));
  if (agentIds.size !== body.agents.length) refuse("bad_form", "agents must be unique");
  for (const a of body.agents) {
    if (a.config_schema !== CONFIG_SCHEMA) refuse("bad_form", "unknown config_schema");
    if (!a.tags.every((t) => tagIds.has(t))) refuse("bad_form", "an agent's tag is not in the grant");
    validateConfig(a.config, ctx.hostInfo ?? {});
  }
  for (const s of body.subscriptions) if (!s.use.every((x) => agentIds.has(x))) refuse("bad_form", "a subscription names an agent not in the grant");
  return { body, digest: sha256b64(bytes) };
}

// ---- durable grant state: one atomic file, under the host store's single writer lock (store.mjs, host-store.mjs)

const FILE = "state.json";
/** A grant's bytes file: generation and digest (base64url, filename-safe). */
const grantFile = (gen, digest) => `${gen}-${digest}`;
const MAX_STEPS = 4096;
const initial = () => ({ v: 1, gen: 0, digest: null, phase: "applied", plan: [], ack: null });

/** The full closed shape of the grant state (refuses anything else, with bad_form). */
export function checkGrantState(st) {
  const bad = () => refuse("bad_form", "grant state: corrupt");
  if (!exactKeys(st, ["v", "gen", "digest", "phase", "plan", "ack"]) || st.v !== 1) bad();
  if (!Number.isSafeInteger(st.gen) || st.gen < 0) bad();
  if (st.gen === 0 ? st.digest !== null : (typeof st.digest !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(st.digest))) bad();
  if (!["applied", "applying"].includes(st.phase) || !Array.isArray(st.plan) || st.plan.length > MAX_STEPS) bad();
  if (st.phase === "applied" && st.plan.length !== 0) bad();
  if (st.phase === "applying" && st.gen === 0) bad();
  // The acknowledgement of applied(N), kept so a byte-identical re-apply re-sends the same one (§3.3).
  if (st.phase === "applying" || st.gen === 0 ? st.ack !== null : !isAck(st.ack)) bad();
  for (const s of st.plan) {
    if (!exactKeys(s, ["step", "done"]) || typeof s.step !== "string" || s.step.length < 1 || s.step.length > 200 || typeof s.done !== "boolean") bad();
  }
  return true;
}

const isAck = (a) => exactKeys(a, ["narrowed", "restarted"]) && typeof a.narrowed === "boolean" && Array.isArray(a.restarted)
  && a.restarted.length <= 64 && a.restarted.every(isId) && new Set(a.restarted).size === a.restarted.length;

export class GrantState {
  #s; #dir; #busy = false;

  /** A view of the grant state in `dir`, under the host store's lock (host-store.mjs); it never locks by itself. */
  static attach(dir, lock, { io = realIo } = {}) {
    const g = new GrantState();
    g.#dir = dir;
    g.#s = DurableState.attach(dir, FILE, { check: checkGrantState, initial, io, lock });
    mkdirSync(join(dir, "grants"), { recursive: true, mode: 0o700 });
    g.io = io;
    return g;
  }

  get poisoned() { return this.#s.poisoned; }
  reload() { this.#s.reload(); }

  /** The accepted generation and its digest. */
  get highwater() { const st = this.#s.get(); return { gen: st.gen, digest: st.digest }; }

  /** The generation rule (§3.2): lower, or equal but not byte-identical, is refused; byte-identical is a re-apply. */
  admit(gen, digest) {
    const st = this.#s.get();
    if (gen < st.gen) refuse("stale_generation");
    if (gen === st.gen) {
      if (digest === st.digest) return { reapply: true };
      refuse("stale_generation");
    }
    return { reapply: false };
  }

  /**
   * Accept generation `gen` (§3.3 steps 2–3): first the durable audit intent, then the grant bytes, then ONE atomic
   * commit of highwater and applying(N, plan). If the intent can't be made durable, nothing changes. If the commit
   * fails, the instance is poisoned and the disk still holds the old state, so N is not accepted (AU07 reconciles it).
   */
  async begin(gen, bytes, digest, plan, appendIntent) {
    if (this.#busy) refuse("in_progress", "another begin is in progress");
    this.#busy = true;
    try { await this.#begin(gen, bytes, digest, plan, appendIntent); } finally { this.#busy = false; }
  }

  async #begin(gen, bytes, digest, plan, appendIntent) {
    const { reapply } = this.admit(gen, digest);
    if (reapply) refuse("bad_form", "a re-apply has no effects to begin");
    if (!Array.isArray(plan) || plan.length > MAX_STEPS || !plan.every((s) => typeof s === "string" && s.length > 0 && s.length <= 200)) refuse("bad_form", "a plan is a list of step names");
    if (sha256b64(bytes) !== digest) refuse("bad_form", "the digest is not of these bytes");
    if (this.#s.get().phase === "applying") refuse("in_progress", "another generation is still applying");
    await appendIntent({ op: "grant.apply", gen, digest, plan_digest: sha256b64(Buffer.from(JSON.stringify(plan))) });
    // The bytes go to grants/<gen>-<digest>, created exclusively (never replacing a file), and only while this view
    // holds the host lock, checked right before and right after the write. A stale writer can never replace accepted
    // bytes: at worst it leaves an orphan file.
    this.#s.assertWritable();
    writeExclusive(join(this.#dir, "grants"), grantFile(gen, digest), Buffer.from(bytes), this.io);
    this.#s.assertWritable();
    this.#s.commit((st) => {
      // Re-checked against the committed state after the await: nothing may have moved past or onto `gen`.
      if (gen <= st.gen) refuse("stale_generation");
      if (st.phase === "applying") refuse("in_progress", "another generation is still applying");
      st.gen = gen; st.digest = digest; st.phase = "applying"; st.ack = null;
      st.plan = plan.map((step) => ({ step, done: false }));
    });
  }

  /** Mark plan step `i` done, durably (recovery redoes only the steps not done). */
  done(i) {
    this.#s.commit((st) => {
      if (st.phase !== "applying" || !Number.isSafeInteger(i) || !st.plan[i]) refuse("bad_form", "no such step");
      st.plan[i].done = true;
    });
  }

  /** Every step done: applied(N), with its acknowledgement `ack` ({ narrowed, restarted }). Only then is it sent. */
  finish(ack) {
    if (!isAck(ack)) refuse("bad_form", "grant state: bad acknowledgement");
    this.#s.commit((st) => {
      if (st.phase !== "applying" || !st.plan.every((s) => s.done === true)) refuse("bad_form", "steps remain");
      st.phase = "applied"; st.plan = []; st.ack = { narrowed: ack.narrowed, restarted: [...ack.restarted] };
    });
  }

  /** The step names of the plan being applied (empty when applied). */
  steps() { return this.#s.get().plan.map((s) => s.step); }

  /** The acknowledgement of the accepted generation, once applied (null before). */
  get ack() { const a = this.#s.get().ack; return a && { narrowed: a.narrowed, restarted: [...a.restarted] }; }

  /** What recovery must redo: { phase, gen, remaining: [indices] }. */
  pending() {
    const st = this.#s.get();
    return { phase: st.phase, gen: st.gen, remaining: st.plan.flatMap((s, i) => (s.done === true ? [] : [i])) };
  }

  /**
   * AU07 (§3.3 recovery): an intent for `gen` with no durable outcome. If the persisted highwater is below `gen`, the
   * intent had no effect (that is the proof); otherwise the grant was accepted and recovery continues its plan.
   */
  reconcileIntent(gen) { return this.#s.get().gen < gen ? "failed_no_effect" : "accepted"; }

  /** The stored bytes of the accepted generation, for re-verification at recovery; checked against its digest. */
  currentBytes() {
    const st = this.#s.get();
    if (st.gen === 0) return null;
    let bytes;
    try { bytes = readFileSync(join(this.#dir, "grants", grantFile(st.gen, st.digest))); } catch { refuse("outcome_unknown", "grant state: the accepted bytes are missing"); }
    if (sha256b64(bytes) !== st.digest) refuse("outcome_unknown", "grant state: the accepted bytes don't match their digest");
    return bytes;
  }
}
