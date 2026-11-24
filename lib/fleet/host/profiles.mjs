// Host supervisor (designs: agent-autonomous-host-claude-profiles.md r2.1 §4, §5, as amended by the advisor delta
// agent-autonomous-host-claude-advisor.md r3.2 §1, §3): the root-only record of the host's harness profiles. A profile is
// one directory holding ONE harness's sign-in and that harness's own account state, signed in on this host for one of
// the person's subscriptions (`sub`, the pool policy's id). It belongs to the person, not to an agent: which agents may
// draw from it is the pool policy (pool.mjs), and which profile a turn uses is the advisor's choice. Its record holds
// its credential's immutable kind { harness, provider, auth }, the subscription, its own storage uid and ext4 project
// id, a generation, and its state:
//
//   creating → bound → retiring → retired          (and creating → retiring, for a creation that is abandoned)
//
// - Every state change is committed durably BEFORE the effects it allows (the caller runs the effects). `bound` is the
//   only selectable state: it means "signed in on this host", the person's "Use on this host" choice.
// - The kind { harness, provider, auth } is fixed at creation and checked against the auth table (AUTH_TABLE): a Claude
//   subscription sign-in exists only for the `claude` harness (the unmodified CLI), whose cloud backend is part of its
//   auth kind; opencode and pi have no Anthropic route at all in v1. A profile is selectable only for a pool entry of
//   exactly its harness and provider (pool.mjs, eligible).
// - A profile id is recorded once, forever: a retired id can never be created again. A subscription has at most one
//   profile on this host that isn't retired.
// - Storage uids and project ids come from their own reserved ranges, allocated monotonically and never reused; when a
//   range is used up, creation refuses (it never wraps). No agent ever runs as a storage uid.
// - One writer per host (the host store's lock); a record that isn't exactly the closed shape is refused, never replaced
//   (store.mjs).

import { isId, refuse } from "../bytes.mjs";
import { DurableState, exactKeys, realIo } from "./store.mjs";

/** The profiles' storage uids: disjoint from the agent uid (70000–79999) and tag gid (80000–89999) ranges. */
export const STORAGE_UID_RANGE = Object.freeze([90000, 99999]);
/** The profiles' ext4 project ids: disjoint from the agent uids (an agent's project id is its uid) and the tag gids. */
export const PROJECT_RANGE = Object.freeze([100000, 109999]);
/** Harnesses whose profile is one provider's credential set: their profiles and pool entries name the provider. */
export const MULTI_PROVIDER = Object.freeze(["opencode", "pi"]);
/**
 * THE closed table of allowed profile kinds: harness → provider ("" for a single-provider harness) → auth kinds. It is
 * the only auth authority on the host, exactly the harness registry's v1 kinds (joint harness/config note r3.3 §2.1),
 * and the registry is to generate it (a test then proves the two byte-for-byte). Anything not listed refuses: an
 * unknown provider, an alias, an unlisted auth kind. A provider is never a vendor name but `openai`; claude's cloud
 * backend is its auth kind (bedrock, vertex, foundry). opencode and pi have no Anthropic route in v1: their pinned
 * versions ship a Claude subscription sign-in that no setting removes on its own, and Anthropic's terms permit a
 * Claude subscription only in the unmodified `claude` CLI.
 */
export const AUTH_TABLE = Object.freeze({
  claude: Object.freeze({ "": Object.freeze(["subscription", "api_key", "bedrock", "vertex", "foundry"]) }),
  codex: Object.freeze({ "": Object.freeze(["subscription", "api_key"]) }),
  opencode: Object.freeze({ openai: Object.freeze(["api_key"]) }),
  pi: Object.freeze({ openai: Object.freeze(["api_key"]) }),
});
/** The harnesses a profile may be for (advisor r3.2 §0.1): exactly the table's. */
export const HARNESSES = Object.freeze(Object.keys(AUTH_TABLE));
/** The auth kinds the table allows for `harness` and `provider` (null for a single-provider harness); [] if none. */
export function authKinds(harness, provider) {
  // Primitive strings only: a property lookup would coerce ["claude"] to "claude".
  if (typeof harness !== "string" || !Object.hasOwn(AUTH_TABLE, harness)) return [];
  // A multi-provider harness looks its provider (a string) up; a single-provider one has exactly the "" row, for null.
  const key = MULTI_PROVIDER.includes(harness) ? (typeof provider === "string" ? provider : null) : provider === null ? "" : null;
  return Object.hasOwn(AUTH_TABLE[harness], key) ? [...AUTH_TABLE[harness][key]] : [];
}
/** Whether `provider` is a provider the table lists for `harness` (null exactly for a single-provider harness). */
export const providerOk = (harness, provider) => authKinds(harness, provider).length > 0;
const kindOk = (harness, provider, auth) => authKinds(harness, provider).includes(auth);
export const PROFILE_STATES = Object.freeze(["creating", "bound", "retiring", "retired"]);
const MOVES = Object.freeze({ creating: ["bound", "retiring"], bound: ["retiring"], retiring: ["retired"], retired: [] });

const FILE = "profiles.json";
const empty = () => ({ v: 3, next_storage_uid: STORAGE_UID_RANGE[0], next_project: PROJECT_RANGE[0], profiles: {} });
/** A record's keys: v2 (piece 1), and v3 (piece 2), which adds the recorded mountpoints and the removal's expect. */
const KEYS_V2 = ["harness", "provider", "auth", "sub", "storage_uid", "project_id", "gen", "state"];
const KEYS_V3 = [...KEYS_V2, "mountpoints", "removal"];
/** At most this many session mountpoints per profile (launcher amendment A4 §3). */
export const MAX_MOUNTPOINTS = 16;
const SUBPATH = /^[A-Za-z0-9._-]{1,64}$/;
/** One recorded mountpoint, as `profile-mounts --op create` reports it. */
const isMountpoint = (m) => exactKeys(m, ["name", "ino", "gen"]) && SUBPATH.test(m.name) && m.name !== "." && m.name !== ".."
  && Number.isSafeInteger(m.ino) && m.ino >= 0 && Number.isSafeInteger(m.gen) && m.gen >= 0 && m.gen <= 0xffffffff;
/** A removal's expect: the launcher's remove-tree input, from identify (epoch, fsid, root object, owners). */
const isRemoval = (x) => exactKeys(x, ["epoch", "fsid", "root", "owners"]) && isMap(x.epoch) && typeof x.fsid === "string" && isMap(x.root)
  && Array.isArray(x.owners) && x.owners.length >= 1 && x.owners.length <= 2 && x.owners.every((u) => Number.isSafeInteger(u) && u >= 0);
const isMap = (o) => o !== null && typeof o === "object" && !Array.isArray(o);
const inNext = (n, [lo, hi]) => Number.isSafeInteger(n) && n >= lo && n <= hi + 1;

/** The full closed shape (refuses anything else, with bad_form). */
export function checkProfiles(p) {
  const bad = () => refuse("bad_form", "profiles: corrupt");
  if (!exactKeys(p, ["v", "next_storage_uid", "next_project", "profiles"]) || (p.v !== 2 && p.v !== 3) || !isMap(p.profiles)) bad();
  if (!inNext(p.next_storage_uid, STORAGE_UID_RANGE) || !inNext(p.next_project, PROJECT_RANGE)) bad();
  const uids = new Set(), projects = new Set(), live = new Set();
  for (const [pid, r] of Object.entries(p.profiles)) {
    if (!isId(pid) || !exactKeys(r, p.v === 2 ? KEYS_V2 : KEYS_V3)) bad();
    if (p.v === 3) {
      if (r.mountpoints !== null && !(Array.isArray(r.mountpoints) && r.mountpoints.length <= MAX_MOUNTPOINTS && r.mountpoints.every(isMountpoint)
        && new Set(r.mountpoints.map((m) => m.name)).size === r.mountpoints.length)) bad();
      if (r.removal !== null && !isRemoval(r.removal)) bad();
      // The removal's expect exists only once retirement has begun; the mountpoints are fixed before `bound`.
      if (r.removal !== null && r.state !== "retiring" && r.state !== "retired") bad();
      if (r.state === "bound" && r.mountpoints === null) bad();
    }
    if (!kindOk(r.harness, r.provider, r.auth) || !isId(r.sub) || !PROFILE_STATES.includes(r.state)) bad();
    if (!Number.isSafeInteger(r.storage_uid) || r.storage_uid < STORAGE_UID_RANGE[0] || r.storage_uid >= p.next_storage_uid || uids.has(r.storage_uid)) bad();
    if (!Number.isSafeInteger(r.project_id) || r.project_id < PROJECT_RANGE[0] || r.project_id >= p.next_project || projects.has(r.project_id)) bad();
    if (!Number.isSafeInteger(r.gen) || r.gen < 1) bad();
    // A subscription has at most one profile on this host that isn't retired.
    if (r.state !== "retired") { if (live.has(r.sub)) bad(); live.add(r.sub); }
    uids.add(r.storage_uid);
    projects.add(r.project_id);
  }
  return true;
}

/** A v2 document as v3: every record gains `mountpoints` and `removal` (null). Done inside each commit. */
function upgrade(p) {
  if (p.v === 3) return;
  p.v = 3;
  for (const r of Object.values(p.profiles)) { r.mountpoints = null; r.removal = null; }
}

export class Profiles {
  #s;

  /** A view of the profile records in `dir`, under the host store's lock (host-store.mjs); it never locks by itself. */
  static attach(dir, lock, { io = realIo } = {}) {
    const p = new Profiles();
    p.#s = DurableState.attach(dir, FILE, { check: checkProfiles, initial: empty, io, lock });
    return p;
  }

  get poisoned() { return this.#s.poisoned; }
  reload() { this.#s.reload(); }

  /** A copy of a profile's record, or null. */
  profile(pid) { const r = this.#s.get().profiles[pid]; return r ? { ...r } : null; }

  /** The subscription's profile on this host that isn't retired, as { pid, ...record }, or null. */
  profileFor(sub) {
    for (const [pid, r] of Object.entries(this.#s.get().profiles)) if (r.sub === sub && r.state !== "retired") return { pid, ...r };
    return null;
  }

  /** Every profile id with its record (for recovery's scan, and the advisor's candidates: the `bound` ones). */
  all() { return Object.entries(this.#s.get().profiles).map(([pid, r]) => ({ pid, ...r })); }

  /**
   * Begin creating profile `pid`, of kind { harness, provider, auth }, for subscription `sub` (the person turned on
   * "Use on this host"): commits `creating` with gen 1, a new storage uid and a new project id, before any directory
   * exists. Refuses a kind the harness table doesn't allow (a Claude subscription outside `claude` included), an id
   * ever recorded (any state: never reused), a subscription that already has a profile here that isn't retired, and an
   * exhausted range (never wraps). The kind never changes afterwards. Returns the new record.
   */
  beginCreate(pid, { harness, provider = null, auth }, sub) {
    if (!isId(pid) || !kindOk(harness, provider, auth) || !isId(sub)) refuse("bad_form", "profiles: bad profile");
    return this.#s.commit((p) => {
      upgrade(p);
      if (Object.hasOwn(p.profiles, pid)) refuse("bad_form", "profiles: a profile id is never reused");
      for (const r of Object.values(p.profiles)) if (r.sub === sub && r.state !== "retired") refuse("bad_form", "profiles: the subscription already has a profile on this host");
      if (p.next_storage_uid > STORAGE_UID_RANGE[1]) refuse("uid_exhausted", "profiles: the storage uid range is used up");
      if (p.next_project > PROJECT_RANGE[1]) refuse("uid_exhausted", "profiles: the profile project-id range is used up");
      p.profiles[pid] = { harness, provider, auth, sub, storage_uid: p.next_storage_uid, project_id: p.next_project, gen: 1, state: "creating", mountpoints: null, removal: null };
      p.next_storage_uid += 1;
      p.next_project += 1;
    }).profiles[pid];
  }

  /** Move a profile to `state` along the table, advancing its gen when it leaves `bound` or `creating` for retirement. */
  #move(pid, state) {
    return this.#s.commit((p) => {
      upgrade(p);
      const r = p.profiles[pid];
      if (!r) refuse("not_granted", "profiles: unknown profile");
      if (!MOVES[r.state].includes(state)) refuse("not_granted", "profiles: that state change is not allowed");
      if (state === "bound" && r.mountpoints === null) refuse("not_granted", "profiles: the mountpoints aren't recorded");
      if (state === "retiring") r.gen += 1;
      r.state = state;
    }).profiles[pid];
  }

  /** creating → bound: signed in on this host, so selectable from now on. */
  markBound(pid) { return this.#move(pid, "bound"); }
  /** bound or creating → retiring (gen + 1): never selectable again; committed before the drain, logout and removal. */
  beginRetire(pid) { return this.#move(pid, "retiring"); }
  /** retiring → retired: the id, storage uid and project id stay recorded, never reused. */
  markRetired(pid) { return this.#move(pid, "retired"); }

  /**
   * Record the session mountpoints `profile-mounts --op create` made (A4 §3), while `creating` only; [] for a harness
   * without continuity. Required before `bound`.
   */
  setMountpoints(pid, rows) {
    if (!Array.isArray(rows) || rows.length > MAX_MOUNTPOINTS || !rows.every(isMountpoint)) refuse("bad_form", "profiles: bad mountpoints");
    return this.#s.commit((p) => {
      upgrade(p);
      const r = p.profiles[pid];
      if (!r || r.state !== "creating") refuse("not_granted", "profiles: mountpoints are recorded only while creating");
      r.mountpoints = rows.map((m) => ({ name: m.name, ino: m.ino, gen: m.gen }));
    }).profiles[pid];
  }

  /**
   * Record the removal's expect (A4 §2: durably, before the first remove-tree), while `retiring` or `retired` (a
   * crash leftover). Replacing it is allowed only by the caller's durable-identity match after a reboot.
   */
  setRemoval(pid, removal) {
    if (!isRemoval(removal)) refuse("bad_form", "profiles: bad removal");
    return this.#s.commit((p) => {
      upgrade(p);
      const r = p.profiles[pid];
      if (!r || (r.state !== "retiring" && r.state !== "retired")) refuse("not_granted", "profiles: a removal is recorded only while retiring");
      r.removal = structuredClone(removal);
    }).profiles[pid];
  }
}
