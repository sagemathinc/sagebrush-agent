// Host supervisor (design: agent-autonomous-host-supervisor-freeze-r3.1.md §2.2, §3.3, §7): the root-only UID registry.
// It maps each immutable agent id to a numeric uid and each tag id to a gid, and keeps every agent's run state and
// lifecycle counter `life`.
//
// The rules it enforces:
// - uids come from 70000–79999 and tag gids from 80000–89999, allocated monotonically and NEVER reused, so no stale uid
//   or descriptor can become a new agent;
// - an id is recorded once, forever: deleting an agent tombstones it, and the same id can't be added again;
// - run states only move along the transitions below; `revoked` and `deleted` never run again;
// - one writer per host (the host store's lock), and every change committed durably before it is visible (store.mjs): a failed write poisons
//   the instance until a reload, and a registry that isn't exactly the closed shape is refused, never replaced.

import { isId, refuse } from "../bytes.mjs";
import { DurableState, exactKeys, realIo } from "./store.mjs";

export const UID_RANGE = Object.freeze([70000, 79999]);
export const GID_RANGE = Object.freeze([80000, 89999]);
export const STATES = Object.freeze(["provisioned", "running", "paused", "stopped", "revoked", "deleted"]);
export const MAX_TAGS = 16; // an agent's tags (O6/O7 r2.3 §1.8)

/** Allowed run-state moves. A resume is stopped/paused → running; it needs a person-signed op, which the caller checks. */
const MOVES = Object.freeze({
  provisioned: ["running", "stopped", "revoked", "deleted"],
  running: ["paused", "stopped", "revoked", "deleted"],
  paused: ["running", "stopped", "revoked", "deleted"],
  stopped: ["running", "revoked", "deleted"],
  revoked: ["deleted"],
  deleted: [],
});

/**
 * Why an agent's last start failed on its own side (§3.3 partial failure, as ruled). While set, the agent stays stopped
 * and masked and recovery never starts it; the next grant or a resume clears it.
 */
export const START_FAILURES = Object.freeze(["preflight_missing", "landlock_abi", "unit_failed", "start_timeout"]);

/** The lifecycle ops that increment `life` (O6/O7 r2.3 §3.4). */
export const LIFE_OPS = Object.freeze(["pause", "stop", "revoke-caps", "resume", "delete"]);

const FILE = "registry.json";
const empty = () => ({ v: 1, next_uid: UID_RANGE[0], next_gid: GID_RANGE[0], agents: {}, tags: {} });

const isTagList = (t) => Array.isArray(t) && t.length <= MAX_TAGS && t.every(isId) && new Set(t).size === t.length;
const isMap = (o) => o !== null && typeof o === "object" && !Array.isArray(o);
/** The registry a restore of `copy` produces: every field kept, each start failure cleared. */
// (a restored agent that can still be granted keeps no grant generation: the old host's counted the old host's grants
//  and means nothing here, so it is 0, "no grant on this host yet", until this host's first grant sets it. A revoked or
//  deleted agent is fixed, no grant ever changes it, and keeps its generation as recorded: its deprovision record
//  matches on it. gen 0 is therefore valid in every state: a restored agent may be revoked or deleted before this host
//  ever grants it, and keeps 0)
const FIXED = new Set(["revoked", "deleted"]);
const restoredFrom = (copy) => {
  const want = { v: 1, next_uid: copy.next_uid, next_gid: copy.next_gid, agents: {}, tags: {} };
  for (const [id, a] of Object.entries(copy.agents)) {
    want.agents[id] = { ...a, gen: FIXED.has(a.state) ? a.gen : 0, tags: [...a.tags], start_failed: null };
  }
  for (const [id, t] of Object.entries(copy.tags)) want.tags[id] = { gid: t.gid };
  return want;
};
/** JSON with sorted keys, to compare two registries by content. */
const stable = (v) => (Array.isArray(v) ? `[${v.map(stable).join(",")}]` : isMap(v)
  ? `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${stable(v[k])}`).join(",")}}` : JSON.stringify(v));

/** The full closed shape (refuses anything else, with bad_form). */
export function checkRegistry(r) {
  const bad = () => refuse("bad_form", "registry: corrupt");
  if (!exactKeys(r, ["v", "next_uid", "next_gid", "agents", "tags"]) || r.v !== 1) bad();
  if (!Number.isSafeInteger(r.next_uid) || r.next_uid < UID_RANGE[0] || r.next_uid > UID_RANGE[1] + 1) bad();
  if (!Number.isSafeInteger(r.next_gid) || r.next_gid < GID_RANGE[0] || r.next_gid > GID_RANGE[1] + 1) bad();
  if (!isMap(r.agents) || !isMap(r.tags)) bad();
  const uids = new Set(), gids = new Set();
  for (const [id, a] of Object.entries(r.agents)) {
    if (!isId(id) || !exactKeys(a, ["uid", "state", "life", "gen", "tags", "start_failed"])) bad();
    if (a.start_failed !== null && !START_FAILURES.includes(a.start_failed)) bad();
    if (!STATES.includes(a.state) || !Number.isSafeInteger(a.uid) || a.uid < UID_RANGE[0] || a.uid >= r.next_uid || uids.has(a.uid)) bad();
    // (gen 0: no grant applied on this host yet, a restored agent's until its first grant here, in any state)
    if (!Number.isSafeInteger(a.life) || a.life < 0 || !Number.isSafeInteger(a.gen) || a.gen < 0 || !isTagList(a.tags)) bad();
    uids.add(a.uid);
  }
  for (const [id, t] of Object.entries(r.tags)) {
    if (!isId(id) || !exactKeys(t, ["gid"]) || !Number.isSafeInteger(t.gid) || t.gid < GID_RANGE[0] || t.gid >= r.next_gid || gids.has(t.gid)) bad();
    gids.add(t.gid);
  }
  return true;
}

export class Registry {
  #s;

  /** A view of the registry in `dir`, under the host store's lock (host-store.mjs); it never locks by itself. */
  static attach(dir, lock, { io = realIo } = {}) {
    const r = new Registry();
    r.#s = DurableState.attach(dir, FILE, { check: checkRegistry, initial: empty, io, lock });
    return r;
  }

  get poisoned() { return this.#s.poisoned; }
  reload() { this.#s.reload(); }

  /** A copy of an agent's record, or null. */
  agent(id) { return this.#s.get().agents[id] ?? null; }
  tag(id) { return this.#s.get().tags[id] ?? null; }

  /** Record a new agent under grant generation `gen`; returns its uid. An id is accepted once, ever. */
  addAgent(id, gen, tags = []) {
    if (!isId(id) || !Number.isSafeInteger(gen) || gen < 1 || !isTagList(tags)) refuse("bad_form", "registry: bad agent");
    let uid;
    this.#s.commit((r) => {
      if (Object.hasOwn(r.agents, id)) refuse("bad_form", "registry: an agent id is never reused");
      if (r.next_uid > UID_RANGE[1]) refuse("uid_exhausted", "registry: the agent uid range is used up");
      uid = r.next_uid;
      r.agents[id] = { uid, state: "provisioned", life: 0, gen, tags: [...tags], start_failed: null };
      r.next_uid = uid + 1;
    });
    return uid;
  }

  /** Record a tag; returns its gid (the existing one if already recorded: tag ids are fleet-scoped and stable). */
  addTag(id) {
    if (!isId(id)) refuse("bad_form", "registry: bad tag");
    const known = this.#s.get().tags[id];
    if (known) return known.gid;
    let gid;
    this.#s.commit((r) => {
      if (r.next_gid > GID_RANGE[1]) refuse("uid_exhausted", "registry: the tag gid range is used up");
      gid = r.next_gid;
      r.tags[id] = { gid };
      r.next_gid = gid + 1;
    });
    return gid;
  }

  /**
   * Move an agent to `state`. `op`, when it is a lifecycle op, increments `life` in the same durable write (§7).
   * Refuses a move the table doesn't allow. Returns the new record.
   */
  setState(id, state, op = null) {
    if (!STATES.includes(state)) refuse("bad_form", "registry: unknown state");
    if (op !== null && !LIFE_OPS.includes(op)) refuse("bad_form", "registry: unknown op");
    return this.#s.commit((r) => {
      const a = r.agents[id];
      if (!a) refuse("not_granted", "registry: unknown agent");
      if (a.state !== state && !MOVES[a.state].includes(state)) refuse("not_granted", "registry: that state change is not allowed");
      a.state = state;
      if (op !== null) a.life += 1;
      if (op === "resume") a.start_failed = null;
    }).agents[id];
  }

  /** Update an agent's tags and grant generation (applying a newer grant, §3.3). Deleted and revoked agents are fixed. */
  setGrant(id, gen, tags) {
    if (!Number.isSafeInteger(gen) || gen < 1 || !isTagList(tags)) refuse("bad_form", "registry: bad grant update");
    return this.#s.commit((r) => {
      const a = r.agents[id];
      if (!a) refuse("not_granted", "registry: unknown agent");
      if (a.state === "deleted" || a.state === "revoked") refuse("not_granted", "registry: a revoked or deleted agent is fixed");
      if (gen < a.gen) refuse("bad_form", "registry: bad grant update");
      a.gen = gen;
      a.tags = [...tags];
      a.start_failed = null;
    }).agents[id];
  }

  /** Record (or clear, with null) why the agent's last start failed on its own side. */
  setStartFailed(id, reason) {
    if (reason !== null && !START_FAILURES.includes(reason)) refuse("bad_form", "registry: unknown start failure");
    return this.#s.commit((r) => {
      const a = r.agents[id];
      if (!a) refuse("not_granted", "registry: unknown agent");
      a.start_failed = reason;
    }).agents[id];
  }

  /**
   * A restore (host backup §5 step 5), read only: may `copy` be imported here? "fresh" when this registry has never
   * recorded anything (no agent, no tag, both counters at the start of their ranges), "same" when it already is
   * exactly this import; anything else refuses (not_granted). The restore calls this before ANY effect of its own
   * (fences, deprovision records), so an import that can't happen leaves nothing behind.
   */
  importPreflight(copy) {
    checkRegistry(copy);
    const r = this.#s.get();
    if (stable(r) === stable(restoredFrom(copy))) return "same";
    if (Object.keys(r.agents).length !== 0 || Object.keys(r.tags).length !== 0 || r.next_uid !== UID_RANGE[0] || r.next_gid !== GID_RANGE[0]) {
      refuse("not_granted", "registry: a restore needs a registry that has never recorded anything");
    }
    return "fresh";
  }

  /**
   * A restore (host backup §5 step 5): replace an EMPTY registry (nothing ever recorded: no agent, no tag, both
   * counters at the start of their ranges) with a restored one, in one durable write. Every uid, gid, tombstone,
   * state and life is kept exactly, so no uid or gid is ever reallocated; each agent's start failure is cleared (it was
   * the old host's). A live agent's grant generation is reset to 0, "no grant on this host yet" (schemas r2.4 §3.7.1:
   * the old host's value counts the old host's grants); this host's first grant sets it. A revoked or deleted agent
   * keeps its own. The caller checks the copy against its manifest first, and calls
   * importPreflight before its own effects; this checks again, at the write. The same import again is a no-op (a
   * retry); any other registry that has ever recorded anything refuses (not_granted).
   */
  importRestored(copy) {
    // The same import again (a retry): its earlier write may not be durable yet, so make it so before it counts.
    if (this.importPreflight(copy) === "same") { this.#s.sync(); return this.#s.get(); }
    const want = restoredFrom(copy);
    return this.#s.commit((r) => {
      if (Object.keys(r.agents).length !== 0 || Object.keys(r.tags).length !== 0 || r.next_uid !== UID_RANGE[0] || r.next_gid !== GID_RANGE[0]) {
        refuse("not_granted", "registry: a restore needs a registry that has never recorded anything");
      }
      Object.assign(r, structuredClone(want));
    });
  }

  /** Every recorded agent id, whatever its state (sorted). */
  ids() { return Object.keys(this.#s.get().agents).sort(); }

  /** Agents recovery may start: recorded `running`, and no start failure on record (§3.3 recovery, as ruled). */
  runnable() {
    const r = this.#s.get();
    return Object.keys(r.agents).filter((id) => r.agents[id].state === "running" && r.agents[id].start_failed === null).sort();
  }
}
