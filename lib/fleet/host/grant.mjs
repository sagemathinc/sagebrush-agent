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

import { readFileSync, existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { refuse, sha256b64 } from "../bytes.mjs";
import { open } from "../envelope.mjs";
import { compile } from "../schema.mjs";
import { validateConfig, CONFIG_SCHEMA } from "./config.mjs";
import { writeDurable } from "./registry.mjs";

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
  if (body.not_after_ms !== null && ctx.now > body.not_after_ms) refuse("grant_expired");
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

// ---- durable grant state

const HW = "highwater.json", PHASE = "phase.json";

export class GrantState {
  /** `dir` is root-only (0700); it holds highwater.json, phase.json and grants/<gen>. */
  constructor(dir) {
    this.dir = dir;
    mkdirSync(join(dir, "grants"), { recursive: true, mode: 0o700 });
    this.hw = this.#read(HW) ?? { gen: 0, digest: null };
    this.phase = this.#read(PHASE) ?? { phase: "applied", gen: 0, plan: [] };
    const ok = Number.isSafeInteger(this.hw.gen) && this.hw.gen >= 0 && ["applied", "applying"].includes(this.phase.phase)
      && this.phase.gen === this.hw.gen && Array.isArray(this.phase.plan);
    if (!ok) refuse("bad_form", "grant state: corrupt");
  }

  #read(name) {
    const p = join(this.dir, name);
    if (!existsSync(p)) return null;
    try { return JSON.parse(readFileSync(p, "utf8")); } catch { refuse("bad_form", "grant state: corrupt"); }
  }

  /** The generation rule (§3.2): lower, or equal but not byte-identical, is refused; byte-identical is a re-apply. */
  admit(gen, digest) {
    if (gen < this.hw.gen) refuse("stale_generation");
    if (gen === this.hw.gen) {
      if (digest === this.hw.digest) return { reapply: true };
      refuse("stale_generation");
    }
    return { reapply: false };
  }

  /**
   * Accept generation `gen` (§3.3 steps 2–3): first the durable audit intent, then the grant bytes, highwater and
   * applying(N, plan). If the intent can't be made durable, nothing here changes. `plan` is the ordered step names.
   */
  async begin(gen, bytes, digest, plan, appendIntent) {
    const { reapply } = this.admit(gen, digest);
    if (reapply) refuse("bad_form", "a re-apply has no effects to begin");
    if (!Array.isArray(plan) || !plan.every((s) => typeof s === "string" && s.length > 0 && s.length <= 200)) refuse("bad_form", "a plan is a list of step names");
    await appendIntent({ op: "grant.apply", gen, digest, plan_digest: sha256b64(Buffer.from(JSON.stringify(plan))) });
    writeDurable(join(this.dir, "grants"), String(gen), Buffer.from(bytes));
    writeDurable(this.dir, HW, JSON.stringify({ gen, digest }));
    this.hw = { gen, digest };
    this.phase = { phase: "applying", gen, plan: plan.map((step) => ({ step, done: false })) };
    writeDurable(this.dir, PHASE, JSON.stringify(this.phase));
  }

  /** Mark plan step `i` done, durably (recovery redoes only the steps not done). */
  done(i) {
    if (this.phase.phase !== "applying" || !this.phase.plan[i]) refuse("bad_form", "no such step");
    this.phase.plan[i].done = true;
    writeDurable(this.dir, PHASE, JSON.stringify(this.phase));
  }

  /** Every step done: applied(N). Only then may the acknowledgement be sent. */
  finish() {
    if (this.phase.phase !== "applying" || !this.phase.plan.every((s) => s.done)) refuse("bad_form", "steps remain");
    this.phase = { phase: "applied", gen: this.hw.gen, plan: [] };
    writeDurable(this.dir, PHASE, JSON.stringify(this.phase));
  }

  /** What recovery must redo: { phase, gen, remaining: [indices] }. */
  pending() {
    const remaining = this.phase.plan.flatMap((s, i) => (s.done ? [] : [i]));
    return { phase: this.phase.phase, gen: this.phase.gen, remaining };
  }

  /**
   * AU07 (§3.3 recovery): an intent for `gen` with no durable outcome. If highwater is below `gen`, the intent had no
   * effect (the persisted highwater is the proof); otherwise the grant was accepted and recovery continues its plan.
   */
  reconcileIntent(gen) {
    return this.hw.gen < gen ? "failed_no_effect" : "accepted";
  }

  /** The stored bytes of the current generation, for re-verification at recovery. */
  currentBytes() {
    if (this.hw.gen === 0) return null;
    return readFileSync(join(this.dir, "grants", String(this.hw.gen)));
  }
}
