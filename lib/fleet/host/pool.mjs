// Host supervisor (design: agent-autonomous-host-claude-advisor.md r3.2 §3, §0.1): the host-local harness pool policy.
// It says which of the person's subscriptions each agent may draw from, per harness, plus the advisor's thresholds and
// optional capacity hints. It lives only on this host (root 0600, durable), written only by the person (the local root
// command, or the app over the end-to-end host channel, which verifies the person's device signature first), and it
// never reaches a server: the service-visible grant carries no Claude subscription (grant.mjs).
//
// - A generation strictly above the current one replaces the whole document; anything invalid refuses the whole
//   document and the current generation stays in force.
// - Pools compare as canonical SETS (poolOf sorts): reordering changes nothing.
// - Validity: a closed shape; unique `sub`; members unique within an entry and each a current agent on this host; at
//   most POOL_CAP entries name any one agent (the per-agent pool cap); capacity hints only for listed subscriptions.
// - A subscription's { harness, provider } is bound the first time any generation lists it, and never changes: the
//   bindings are kept, append-only, beside the policy (a sub dropped and listed again must have its old binding). A
//   different harness or provider is a different subscription id. Selection (eligible) also requires each profile's
//   own recorded kind to match its entry exactly.

import { isId, refuse } from "../bytes.mjs";
import { DurableState, exactKeys, realIo } from "./store.mjs";
import { HARNESSES, MULTI_PROVIDER, PROVIDER } from "./profiles.mjs";

export const MAX_SUBSCRIPTIONS = 16; // entries in one pool policy
export const POOL_CAP = 8; // entries naming any one agent (advisor r3.2 §3)
export const MAX_LABEL = 64; // a subscription's label, in UTF-16 code units
export const MAX_CAPACITY = 1e12; // a capacity hint, in weighted tokens (advisor r3.2 §4)
const WINDOWS = Object.freeze(["five_hour", "seven_day"]);

const FILE = "pool.json";
const BINDINGS = "bindings.json";
const MAX_BINDINGS = 4096; // subscriptions ever listed on this host
const empty = () => ({ v: 1, gen: 0, subscriptions: [], thresholds: { five_hour: 0.8, seven_day: 0.9 }, capacity: {} });
const emptyBindings = () => ({ v: 1, subs: {} });
const isMap = (o) => o !== null && typeof o === "object" && !Array.isArray(o);
// A label is the person's own text: any characters but control characters, 1..MAX_LABEL long.
const isLabel = (s) => typeof s === "string" && s.length >= 1 && s.length <= MAX_LABEL && !/[\u0000-\u001f\u007f-\u009f]/.test(s);
const isThreshold = (x) => typeof x === "number" && Number.isFinite(x) && x > 0 && x <= 1;
const isCapacity = (x) => Number.isSafeInteger(x) && x >= 1 && x <= MAX_CAPACITY;

/** The full closed shape (refuses anything else, with bad_form). Membership in the host's agents is checked by set(). */
export function checkPool(p) {
  const bad = (why) => refuse("bad_form", `pool: ${why}`);
  if (!exactKeys(p, ["v", "gen", "subscriptions", "thresholds", "capacity"]) || p.v !== 1) bad("not the closed shape");
  if (!Number.isSafeInteger(p.gen) || p.gen < 0) bad("bad generation");
  if (!Array.isArray(p.subscriptions) || p.subscriptions.length > MAX_SUBSCRIPTIONS) bad("too many subscriptions");
  const subs = new Set(), perAgent = new Map();
  for (const s of p.subscriptions) {
    if (!exactKeys(s, ["sub", "label", "harness", "provider", "use"])) bad("a subscription isn't the closed shape");
    if (!isId(s.sub) || !isLabel(s.label) || !HARNESSES.includes(s.harness)) bad("a bad subscription");
    if (MULTI_PROVIDER.includes(s.harness) ? !(typeof s.provider === "string" && PROVIDER.test(s.provider)) : s.provider !== null) bad("a bad provider");
    if (subs.has(s.sub)) bad("a subscription id appears twice");
    subs.add(s.sub);
    if (!Array.isArray(s.use) || !s.use.every(isId) || new Set(s.use).size !== s.use.length) bad("a bad member list");
    for (const a of s.use) {
      perAgent.set(a, (perAgent.get(a) ?? 0) + 1);
      if (perAgent.get(a) > POOL_CAP) bad(`an agent is in more than ${POOL_CAP} subscriptions`);
    }
  }
  if (!exactKeys(p.thresholds, WINDOWS) || !WINDOWS.every((w) => isThreshold(p.thresholds[w]))) bad("bad thresholds");
  if (!isMap(p.capacity)) bad("bad capacity");
  for (const [sub, c] of Object.entries(p.capacity)) {
    if (!subs.has(sub)) bad("a capacity hint for an unlisted subscription");
    // A hint may give either window or both; an absent window is "unknown" (advisor r3.2 §4).
    if (!isMap(c) || Object.keys(c).length === 0 || !Object.keys(c).every((w) => WINDOWS.includes(w) && isCapacity(c[w]))) bad("a bad capacity hint");
  }
  return true;
}

/** The append-only { sub: { harness, provider } } bindings (closed shape, bad_form otherwise). */
export function checkBindings(b) {
  if (!exactKeys(b, ["v", "subs"]) || b.v !== 1 || !isMap(b.subs) || Object.keys(b.subs).length > MAX_BINDINGS) refuse("bad_form", "pool: bindings corrupt");
  for (const [sub, k] of Object.entries(b.subs)) {
    if (!isId(sub) || !exactKeys(k, ["harness", "provider"]) || !HARNESSES.includes(k.harness)) refuse("bad_form", "pool: bindings corrupt");
    if (MULTI_PROVIDER.includes(k.harness) ? !(typeof k.provider === "string" && PROVIDER.test(k.provider)) : k.provider !== null) refuse("bad_form", "pool: bindings corrupt");
  }
  return true;
}

export class PoolPolicy {
  #s; #b;

  /** A view of the pool policy in `dir`, under the host store's lock (host-store.mjs); it never locks by itself. */
  static attach(dir, lock, { io = realIo } = {}) {
    const p = new PoolPolicy();
    p.#s = DurableState.attach(dir, FILE, { check: checkPool, initial: empty, io, lock });
    p.#b = DurableState.attach(dir, BINDINGS, { check: checkBindings, initial: emptyBindings, io, lock });
    return p;
  }

  get poisoned() { return this.#s.poisoned || this.#b.poisoned; }
  reload() { this.#b.reload(); this.#s.reload(); }

  /** A copy of the policy in force (generation 0: none set yet, so every pool is empty). */
  get() { return this.#s.get(); }

  /**
   * Replace the policy with `doc`, a whole new generation, after the caller authenticated the person (local root, or a
   * verified device signature). `isAgent(id)`: whether `id` is a current agent on this host. Refuses (changing nothing)
   * a generation not above the current one, any invalid document, a member that isn't a current agent, or a
   * subscription whose harness or provider differs from its binding.
   *
   * Order: new bindings are committed first (append-only), then the policy. A crash between leaves bindings for subs
   * no policy lists yet, which only constrains later documents to what this one already asked for.
   */
  set(doc, isAgent) {
    if (typeof isAgent !== "function") refuse("bad_form", "pool: no agent check");
    checkPool(doc);
    for (const s of doc.subscriptions) for (const a of s.use) if (!isAgent(a)) refuse("bad_form", "pool: a member isn't an agent on this host");
    if (doc.gen <= this.#s.get().gen) refuse("bad_form", "pool: the generation must increase");
    const bound = this.#b.get().subs, fresh = {};
    for (const s of doc.subscriptions) {
      const k = bound[s.sub];
      if (k && (k.harness !== s.harness || k.provider !== s.provider)) refuse("bad_form", "pool: a subscription's harness and provider never change");
      if (!k) fresh[s.sub] = { harness: s.harness, provider: s.provider };
    }
    if (Object.keys(fresh).length > 0) this.#b.commit((b) => { Object.assign(b.subs, fresh); });
    return this.#s.commit((p) => {
      for (const k of Object.keys(p)) delete p[k];
      Object.assign(p, structuredClone(doc));
    });
  }

  /** The agent's pool for `harness` (and `provider`, for a multi-provider harness): its subscription ids, sorted. */
  poolOf(agent, harness, provider = null) {
    return this.#s.get().subscriptions
      .filter((s) => s.harness === harness && s.provider === provider && s.use.includes(agent))
      .map((s) => s.sub)
      .sort();
  }

  /**
   * The profiles a turn of `agent` on `harness` (and `provider`) may use: from `profiles` (Profiles.all()), the `bound`
   * ones whose subscription is in the agent's pool AND whose own recorded kind is exactly that entry's harness and
   * provider. Sorted by `sub`. A profile of another kind under a pool sub is never selectable.
   */
  eligible(agent, harness, provider, profiles) {
    const entries = new Map(this.#s.get().subscriptions
      .filter((s) => s.harness === harness && s.provider === provider && s.use.includes(agent)).map((s) => [s.sub, s]));
    return profiles
      .filter((r) => r.state === "bound" && entries.has(r.sub) && r.harness === harness && r.provider === provider)
      .sort((x, y) => (x.sub < y.sub ? -1 : x.sub > y.sub ? 1 : 0));
  }

  /** A subscription's permanent { harness, provider } binding, or null if no generation has listed it. */
  bindingOf(sub) { const k = this.#b.get().subs[sub]; return k ? { ...k } : null; }

  /** Whether any subscription still names `agent` (deprovision parks its accounts step until none does). */
  names(agent) { return this.#s.get().subscriptions.some((s) => s.use.includes(agent)); }
}
