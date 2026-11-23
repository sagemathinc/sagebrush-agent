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

import { isId, refuse } from "../bytes.mjs";
import { DurableState, exactKeys, realIo } from "./store.mjs";
import { HARNESSES } from "./profiles.mjs";

export const MAX_SUBSCRIPTIONS = 16; // entries in one pool policy
export const POOL_CAP = 8; // entries naming any one agent (advisor r3.2 §3)
export const MAX_LABEL = 64; // a subscription's label, in UTF-16 code units
export const MAX_CAPACITY = 1e12; // a capacity hint, in weighted tokens (advisor r3.2 §4)
/** Harnesses whose profile is one provider's credential set: their entries name the provider. */
const MULTI_PROVIDER = Object.freeze(["opencode", "pi"]);
const PROVIDER = /^[a-z0-9][a-z0-9-]{0,31}$/;
const WINDOWS = Object.freeze(["five_hour", "seven_day"]);

const FILE = "pool.json";
const empty = () => ({ v: 1, gen: 0, subscriptions: [], thresholds: { five_hour: 0.8, seven_day: 0.9 }, capacity: {} });
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

export class PoolPolicy {
  #s;

  /** A view of the pool policy in `dir`, under the host store's lock (host-store.mjs); it never locks by itself. */
  static attach(dir, lock, { io = realIo } = {}) {
    const p = new PoolPolicy();
    p.#s = DurableState.attach(dir, FILE, { check: checkPool, initial: empty, io, lock });
    return p;
  }

  get poisoned() { return this.#s.poisoned; }
  reload() { this.#s.reload(); }

  /** A copy of the policy in force (generation 0: none set yet, so every pool is empty). */
  get() { return this.#s.get(); }

  /**
   * Replace the policy with `doc`, a whole new generation, after the caller authenticated the person (local root, or a
   * verified device signature). `isAgent(id)`: whether `id` is a current agent on this host. Refuses (changing nothing)
   * a generation not above the current one, any invalid document, or a member that isn't a current agent.
   */
  set(doc, isAgent) {
    if (typeof isAgent !== "function") refuse("bad_form", "pool: no agent check");
    checkPool(doc);
    for (const s of doc.subscriptions) for (const a of s.use) if (!isAgent(a)) refuse("bad_form", "pool: a member isn't an agent on this host");
    return this.#s.commit((p) => {
      if (doc.gen <= p.gen) refuse("bad_form", "pool: the generation must increase");
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

  /** Whether any subscription still names `agent` (deprovision parks its accounts step until none does). */
  names(agent) { return this.#s.get().subscriptions.some((s) => s.use.includes(agent)); }
}
