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
import { canonText } from "../core/canonical.mjs";
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
  // Which agents draw from which Claude subscription is the person's host-local pool policy (pool.mjs), which never
  // reaches a server; a service-visible grant naming a Claude subscription is refused whole (advisor delta r3.2 §3).
  if (body.subscriptions.some((s) => s.provider === "claude")) refuse("bad_form", "a Claude subscription belongs in the host's pool policy, not the grant");
  // Likewise no per-agent Claude-subscription right: eligibility is the pool policy alone, and the bit would tell the
  // service which agents use a Claude subscription.
  if (body.agents.some((a) => a.broker.includes("claude-subscription"))) refuse("bad_form", "a Claude subscription right belongs to the host's pool policy, not the grant");
  return { body, digest: sha256b64(bytes) };
}

// ---- durable grant state: one atomic file, under the host store's single writer lock (store.mjs, host-store.mjs)
//
// It also holds the per-agent records the transfer checks read (schemas r2.4 §3.7.1, §3.7.3 check 5): for each agent
// in the accepted grant, `entry` (the SHA-256 of its grant_agent entry's canonical bytes), `entry_gen` (the gen in which
// that entry last changed: added, or any field different) and `listed_since` (the gen from which it has been in every
// accepted grant). They move in the SAME atomic commit as the highwater (nextRecords), compared against the previously
// accepted grant's entries, so they can never disagree with it. An agent a grant drops loses its record (an id is
// never re-added: the registry refuses it). Every accepted grant's digest stays readable by gen: the current one in
// this file, each earlier one in accepted/<gen>, written before the next generation is accepted. All of it is
// host-local: a restored host starts with no grant state, and its first grant adds every agent.
//
// v:1, from before these records, is refused once it has accepted a grant (its history can't be rebuilt: which grant
// was accepted at each gen isn't recorded); an empty v:1 state becomes v:2.

const FILE = "state.json";
const ACCEPTED = "accepted";
/** A grant's bytes file: generation and digest (base64url, filename-safe). */
const grantFile = (gen, digest) => `${gen}-${digest}`;
const MAX_STEPS = 4096;
/** Why an agent's containment is still unproven (a failed proof); the set is cleared only by a passing proof. */
export const PROOF_REASONS = Object.freeze(["not_empty"]);
const MAX_AGENTS = 4096;
const DIGEST = /^[A-Za-z0-9_-]{43}$/;
const initial = () => ({ v: 2, gen: 0, digest: null, phase: "applied", plan: [], ack: null, proof: {}, records: {} });

/** The SHA-256 (base64url) of a grant_agent entry's canonical bytes: two entries are the same entry iff these match. */
export const entryDigest = (entry) => sha256b64(Buffer.from(canonText(entry)));

/**
 * The per-agent records after accepting generation `gen`, from the records of the previously accepted one and `entries`
 * (agent id -> entryDigest, every agent the new grant lists). Pure. Added: entry_gen = listed_since = gen. Changed:
 * entry_gen = gen. Identical: kept. Not listed: dropped.
 */
export function nextRecords(records, entries, gen) {
  const out = {};
  for (const [id, entry] of Object.entries(entries)) {
    const r = Object.hasOwn(records, id) ? records[id] : null;
    if (r === null) out[id] = { entry, entry_gen: gen, listed_since: gen };
    else out[id] = r.entry === entry ? { ...r } : { entry, entry_gen: gen, listed_since: r.listed_since };
  }
  return out;
}

const isEntries = (e) => e !== null && typeof e === "object" && !Array.isArray(e) && Object.keys(e).length <= MAX_AGENTS
  && Object.entries(e).every(([id, d]) => isId(id) && typeof d === "string" && DIGEST.test(d));

/** The full closed shape of the grant state (refuses anything else, with bad_form). */
export function checkGrantState(st) {
  const bad = () => refuse("bad_form", "grant state: corrupt");
  if (!exactKeys(st, ["v", "gen", "digest", "phase", "plan", "ack", "proof", "records"]) || st.v !== 2) bad();
  if (st.records === null || typeof st.records !== "object" || Array.isArray(st.records) || Object.keys(st.records).length > MAX_AGENTS) bad();
  for (const [id, r] of Object.entries(st.records)) {
    if (!isId(id) || !exactKeys(r, ["entry", "entry_gen", "listed_since"]) || typeof r.entry !== "string" || !DIGEST.test(r.entry)) bad();
    if (!Number.isSafeInteger(r.listed_since) || r.listed_since < 1 || !Number.isSafeInteger(r.entry_gen) || r.entry_gen < r.listed_since || r.entry_gen > st.gen) bad();
  }
  // The pending proofs: agent id -> reason. Host-level, outside any plan: they survive supersession, registry changes,
  // expiry and restarts.
  if (st.proof === null || typeof st.proof !== "object" || Array.isArray(st.proof) || Object.keys(st.proof).length > 4096) bad();
  for (const [id, why] of Object.entries(st.proof)) if (!isId(id) || !PROOF_REASONS.includes(why)) bad();
  if (!Number.isSafeInteger(st.gen) || st.gen < 0) bad();
  if (st.gen === 0 ? st.digest !== null : (typeof st.digest !== "string" || !DIGEST.test(st.digest))) bad();
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

/**
 * What a state file may hold when it is loaded: v:2 (checkGrantState), or an EMPTY v:1 (never accepted a grant), which
 * attach makes v:2. A v:1 state that has accepted a grant is refused before anything is written.
 */
function checkLoaded(st) {
  if (st?.v !== 1) return checkGrantState(st);
  if (!exactKeys(st, ["v", "gen", "digest", "phase", "plan", "ack", "proof"])) refuse("bad_form", "grant state: corrupt");
  if (st.gen !== 0) refuse("bad_form", "grant state: v1 from before the transfer records, with an accepted grant; re-provision this host");
  const { v, ...rest } = st;
  return checkGrantState({ ...rest, v: 2, records: {} });
}

const isAck = (a) => exactKeys(a, ["narrowed", "restarted"]) && typeof a.narrowed === "boolean" && Array.isArray(a.restarted)
  && a.restarted.length <= 64 && a.restarted.every(isId) && new Set(a.restarted).size === a.restarted.length;

export class GrantState {
  #s; #dir; #busy = false;

  /** A view of the grant state in `dir`, under the host store's lock (host-store.mjs); it never locks by itself. */
  static attach(dir, lock, { io = realIo } = {}) {
    const g = new GrantState();
    g.#dir = dir;
    g.#s = DurableState.attach(dir, FILE, { check: checkLoaded, initial, io, lock });
    if (g.#s.get().v === 1) g.#s.commit((st) => { st.v = 2; st.records = {}; });
    mkdirSync(join(dir, "grants"), { recursive: true, mode: 0o700 });
    mkdirSync(join(dir, ACCEPTED), { recursive: true, mode: 0o700 });
    g.io = io;
    return g;
  }

  get poisoned() { return this.#s.poisoned; }
  reload() { this.#s.reload(); }

  /** The accepted generation and its digest. */
  get highwater() { const st = this.#s.get(); return { gen: st.gen, digest: st.digest }; }

  /** An agent's records in the accepted grant ({ entry, entry_gen, listed_since }), or null if it doesn't list it. */
  record(agent) { const r = this.#s.get().records; return Object.hasOwn(r, agent) ? r[agent] : null; }

  /**
   * The digest of the grant this host accepted at generation `gen`, or null (never accepted, or no record of it: the
   * caller refuses). The current one is in the state; an earlier one in accepted/<gen>.
   */
  digestAt(gen) {
    const st = this.#s.get();
    if (!Number.isSafeInteger(gen) || gen < 1 || gen > st.gen) return null;
    if (gen === st.gen) return st.digest;
    let text;
    try { text = readFileSync(join(this.#dir, ACCEPTED, String(gen)), "utf8"); } catch (e) { if (e?.code === "ENOENT") return null; throw e; }
    if (!DIGEST.test(text)) refuse("bad_form", "grant state: a corrupt accepted digest");
    return text;
  }

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
  async begin(gen, bytes, digest, plan, appendIntent, { supersede = false, recheck = () => {}, entries } = {}) {
    if (this.#busy) refuse("in_progress", "another begin is in progress");
    this.#busy = true;
    try { await this.#begin(gen, bytes, digest, plan, appendIntent, supersede, recheck, entries); } finally { this.#busy = false; }
  }

  /**
   * `supersede`: begin N+1 although applying(N) is unfinished. Only for an N that is held (its grant no longer
   * verifies, or the host expired); the caller plans every listed agent anew. The generation rule still applies.
   * `recheck()`: called after the intent's append and before anything is accepted; a throw leaves N unaccepted (the
   * intent then reconciles as failed_no_effect, AU07). The caller re-verifies the grant there.
   * `entries`: agent id -> entryDigest of its grant_agent entry, for every agent the grant lists (nextRecords).
   */
  async #begin(gen, bytes, digest, plan, appendIntent, supersede, recheck, entries) {
    if (!isEntries(entries)) refuse("bad_form", "grant state: no entries for the records");
    const { reapply } = this.admit(gen, digest);
    if (reapply) refuse("bad_form", "a re-apply has no effects to begin");
    if (!Array.isArray(plan) || plan.length > MAX_STEPS || !plan.every((s) => typeof s === "string" && s.length > 0 && s.length <= 200)) refuse("bad_form", "a plan is a list of step names");
    if (sha256b64(bytes) !== digest) refuse("bad_form", "the digest is not of these bytes");
    if (this.#s.get().phase === "applying" && !supersede) refuse("in_progress", "another generation is still applying");
    await appendIntent({ op: "grant.apply", gen, digest, plan_digest: sha256b64(Buffer.from(JSON.stringify(plan))) });
    recheck();
    // The bytes go to grants/<gen>-<digest>, created exclusively (never replacing a file), and only while this view
    // holds the host lock, checked right before and right after the write. A stale writer can never replace accepted
    // bytes: at worst it leaves an orphan file.
    this.#s.assertWritable();
    writeExclusive(join(this.#dir, "grants"), grantFile(gen, digest), Buffer.from(bytes), this.io);
    // The generation accepted now stops being the current one: its digest goes to accepted/<gen> first, durably, so
    // every earlier accepted generation stays readable (digestAt). Created exclusively, never replaced.
    const prev = this.#s.get();
    if (prev.gen > 0) writeExclusive(join(this.#dir, ACCEPTED), String(prev.gen), Buffer.from(prev.digest), this.io);
    this.#s.assertWritable();
    this.#s.commit((st) => {
      // Re-checked against the committed state after the await: nothing may have moved past or onto `gen`.
      if (gen <= st.gen) refuse("stale_generation");
      if (st.phase === "applying" && !supersede) refuse("in_progress", "another generation is still applying");
      if (st.gen !== prev.gen) refuse("in_progress", "grant state: the accepted generation moved");
      st.records = nextRecords(st.records, entries, gen);
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
      // No generation reaches applied(N) (or an acknowledgement) while any agent's containment is unproven.
      if (Object.keys(st.proof).length > 0) refuse("in_progress", "grant state: a containment proof is pending");
      st.phase = "applied"; st.plan = []; st.ack = { narrowed: ack.narrowed, restarted: [...ack.restarted] };
    });
  }

  /** The agents whose containment proof is pending (sorted). */
  pendingProofs() { return Object.keys(this.#s.get().proof).sort(); }

  /** Record that an agent's containment couldn't be proven (durable before anything relies on it). */
  markProof(agent, reason = "not_empty") {
    if (!isId(agent) || !PROOF_REASONS.includes(reason)) refuse("bad_form", "grant state: bad proof record");
    if (this.#s.get().proof[agent] === reason) return;
    this.#s.commit((st) => { st.proof[agent] = reason; });
  }

  /** Clear an agent's pending proof: ONLY after a proof for that agent passed (the executor's #proveDown). */
  clearProof(agent) {
    if (!Object.hasOwn(this.#s.get().proof, agent)) return;
    this.#s.commit((st) => { delete st.proof[agent]; });
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
