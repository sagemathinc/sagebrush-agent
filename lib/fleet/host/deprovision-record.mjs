// Host supervisor (design: agent-autonomous-host-deprovision.md r3.2 §2, §3; amendment L1): the durable progress record
// of a deleted agent's deprovisioning, one closed-shape record per agent in the host store.
//
// - It is BOUND to the agent: its id, its registry `life` and grant `gen` at delete, its uid and gid, the record
//   version and the policy (always `archive`). A record whose binding doesn't match the registry is refused by the
//   caller (bindingMatches), never repaired.
// - It lists the steps done, in the fixed order below; only a valid PREFIX of that order is a valid record, and a step
//   is marked only after its effect was verified (verify, act, mark).
// - It holds the identities recorded BEFORE a step acts: the launcher's `identify` / `inspect-home` output (closed
//   shapes, checked here), so recovery and purge compare the exact object, never whatever is at the path.
// - `done` is set only when every step is done. It is eligibility for purge, not a lasting proof.
// - One writer per host (the host store's lock); every change is durable before it is visible (store.mjs).

import { isId, refuse } from "../bytes.mjs";
import { DurableState, exactKeys, realIo } from "./store.mjs";
import { UID_RANGE } from "./registry.mjs";

/** The steps, in order (deprovision r3.2 §3; L1 adds `config`, the config tree's archive, step 6b). */
export const STEPS = Object.freeze(["channels", "unit", "network", "runtime", "files", "home", "config", "accounts"]);
/** The identities a record may hold: the trees (inspect-home) and the single objects (identify). */
export const TREE_KEYS = Object.freeze(["home", "config"]);
export const OBJECT_KEYS = Object.freeze(["binds", "broker", "creds", "contract", "resolv", "managed", "secrets"]);

const FILE = "deprovision.json";
const empty = () => ({ v: 1, agents: {} });
const isMap = (o) => o !== null && typeof o === "object" && !Array.isArray(o);
const nat = (n) => Number.isSafeInteger(n) && n >= 0;
const u32 = (n) => nat(n) && n <= 0xffffffff;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const FSID = /^[0-9a-f]{16}$/;

/** One object's identity, exactly as the launcher prints it (A1 §1). */
export function checkObject(x) {
  if (!exactKeys(x, ["type", "mode", "uid", "gid", "dev", "ino", "gen", "mnt_id", "projid", "inherit"])) return false;
  if (!["dir", "file", "symlink"].includes(x.type) || !nat(x.mode) || x.mode > 0o7777 || !u32(x.uid) || !u32(x.gid)) return false;
  if (!Array.isArray(x.dev) || x.dev.length !== 2 || !x.dev.every(u32) || !nat(x.ino) || !nat(x.mnt_id)) return false;
  const none = x.gen === null && x.projid === null && x.inherit === null;
  const all = u32(x.gen) && u32(x.projid) && typeof x.inherit === "boolean";
  return x.type === "symlink" ? none : all;
}

const checkHead = (x) => isMap(x.epoch) && exactKeys(x.epoch, ["boot_id", "mnt_id"]) && typeof x.epoch.boot_id === "string" && UUID.test(x.epoch.boot_id) && nat(x.epoch.mnt_id) && typeof x.fsid === "string" && FSID.test(x.fsid);

/** `identify`'s output, with the object present (a record holds only objects that existed). */
export function checkIdentified(x) {
  return exactKeys(x, ["epoch", "fsid", "object"]) && checkHead(x) && checkObject(x.object);
}

/** `inspect-home`'s output: the tree's directory and its entries (at most 18: a config tree's 16 + current + tmp). */
export function checkInspected(x) {
  if (!exactKeys(x, ["epoch", "fsid", "dir", "entries"]) || !checkHead(x) || !checkObject(x.dir) || x.dir.type !== "dir") return false;
  if (!isMap(x.entries) || Object.keys(x.entries).length > 18) return false;
  return Object.entries(x.entries).every(([n, o]) => typeof n === "string" && n.length > 0 && n.length <= 32 && !n.includes("/") && checkObject(o));
}

/** The full closed shape (refuses anything else, with bad_form). */
export function checkRecords(r) {
  const bad = () => refuse("bad_form", "deprovision: corrupt");
  if (!exactKeys(r, ["v", "agents"]) || r.v !== 1 || !isMap(r.agents)) bad();
  for (const [id, a] of Object.entries(r.agents)) {
    if (!isId(id) || !exactKeys(a, ["life", "gen", "uid", "gid", "policy", "steps_done", "identities", "done"])) bad();
    if (!nat(a.life) || !Number.isSafeInteger(a.gen) || a.gen < 1 || a.policy !== "archive" || typeof a.done !== "boolean") bad();
    if (!Number.isSafeInteger(a.uid) || a.uid < UID_RANGE[0] || a.uid > UID_RANGE[1] || a.gid !== a.uid) bad();
    // Only a valid prefix of the fixed order; `done` exactly when every step is done.
    if (!Array.isArray(a.steps_done) || a.steps_done.length > STEPS.length || !a.steps_done.every((s, i) => s === STEPS[i])) bad();
    if (a.done !== (a.steps_done.length === STEPS.length)) bad();
    if (!isMap(a.identities)) bad();
    for (const [k, v] of Object.entries(a.identities)) {
      if (TREE_KEYS.includes(k) ? !checkInspected(v) : OBJECT_KEYS.includes(k) ? !checkIdentified(v) : true) bad();
    }
  }
  return true;
}

export class DeprovisionRecords {
  #s;

  /** A view of the records in `dir`, under the host store's lock (host-store.mjs); it never locks by itself. */
  static attach(dir, lock, { io = realIo } = {}) {
    const d = new DeprovisionRecords();
    d.#s = DurableState.attach(dir, FILE, { check: checkRecords, initial: empty, io, lock });
    return d;
  }

  get poisoned() { return this.#s.poisoned; }
  reload() { this.#s.reload(); }

  /** A copy of the agent's record, or null. */
  record(agent) { const a = this.#s.get().agents[agent]; return a ? structuredClone(a) : null; }

  /** The agents whose record isn't done (recovery's pending set, with every deleted agent that has no record yet). */
  pending() { return Object.entries(this.#s.get().agents).filter(([, a]) => !a.done).map(([id]) => id).sort(); }

  /**
   * The record for a deleted agent, created bound to its registry record if missing (deprovision r3.2 §2: no hole
   * between `deleted` and the record; recovery reconstructs it with no step done). Returns the record.
   */
  ensure(agent, reg) {
    if (!isId(agent) || reg?.state !== "deleted") refuse("not_granted", "deprovision: only a deleted agent");
    const have = this.#s.get().agents[agent];
    if (have) {
      if (!bindingMatches(have, reg)) refuse("bad_form", "deprovision: the record is bound to another life, generation or uid");
      return structuredClone(have);
    }
    return structuredClone(this.#s.commit((r) => {
      r.agents[agent] = { life: reg.life, gen: reg.gen, uid: reg.uid, gid: reg.uid, policy: "archive", steps_done: [], identities: {}, done: false };
    }).agents[agent]);
  }

  /** Record an identity before its step acts. A key is recorded once; recording another value for it refuses. */
  recordIdentity(agent, key, value) {
    if (!TREE_KEYS.includes(key) && !OBJECT_KEYS.includes(key)) refuse("bad_form", "deprovision: an unknown identity");
    return this.#s.commit((r) => {
      const a = r.agents[agent];
      if (!a || a.done) refuse("not_granted", "deprovision: no pending record");
      if (Object.hasOwn(a.identities, key)) {
        if (JSON.stringify(a.identities[key]) !== JSON.stringify(value)) refuse("bad_form", "deprovision: an identity is recorded once");
        return;
      }
      a.identities[key] = structuredClone(value);
    }).agents[agent];
  }

  /** Requalification (deprovision r3.2 §3.6): the same durable identity, rebound to the current epoch's live fields. */
  rebindIdentity(agent, key, value) {
    return this.#s.commit((r) => {
      const a = r.agents[agent];
      if (!a || !Object.hasOwn(a.identities, key)) refuse("not_granted", "deprovision: nothing to rebind");
      if (!sameDurable(a.identities[key], value)) refuse("bad_form", "deprovision: another durable identity");
      a.identities[key] = structuredClone(value);
    }).agents[agent];
  }

  /** Mark `step` done: only the NEXT step in the order. The last one also sets `done`. */
  markStep(agent, step) {
    return this.#s.commit((r) => {
      const a = r.agents[agent];
      if (!a || a.done) refuse("not_granted", "deprovision: no pending record");
      if (STEPS[a.steps_done.length] !== step) refuse("bad_form", "deprovision: steps are marked in order");
      a.steps_done.push(step);
      a.done = a.steps_done.length === STEPS.length;
    }).agents[agent];
  }
}

/** Whether a record is bound to this registry record: the same life, generation and uid (the gid is the uid). */
export function bindingMatches(rec, reg) {
  return !!reg && rec.life === reg.life && rec.gen === reg.gen && rec.uid === reg.uid && rec.gid === reg.uid;
}

/** The durable fields of an object (deprovision r3.2 §3.6): everything but the live dev and mnt_id. */
const durable = (o) => ({ type: o.type, mode: o.mode, uid: o.uid, gid: o.gid, ino: o.ino, gen: o.gen, projid: o.projid, inherit: o.inherit });

/** Whether two recorded identities (identify or inspect-home outputs) are the same durable object(s) and filesystem. */
export function sameDurable(a, b) {
  if (a.fsid !== b.fsid) return false;
  const objs = (x) => ("object" in x ? { object: x.object } : { dir: x.dir, ...x.entries });
  const [oa, ob] = [objs(a), objs(b)];
  const ka = Object.keys(oa).sort(), kb = Object.keys(ob).sort();
  if (JSON.stringify(ka) !== JSON.stringify(kb)) return false;
  return ka.every((k) => JSON.stringify(durable(oa[k])) === JSON.stringify(durable(ob[k])));
}
