// Host supervisor (design: agent-autonomous-host-supervisor-freeze-r3.1.md §2.2, §3.3, §7): the root-only UID registry.
// It maps each immutable agent id to a numeric uid and each tag id to a gid, and keeps every agent's run state and
// lifecycle counter `life`.
//
// The rules it enforces:
// - uids come from 70000–79999 and tag gids from 80000–89999, allocated monotonically and NEVER reused, so no stale uid
//   or descriptor can become a new agent;
// - an id is recorded once, forever: deleting an agent tombstones it, and the same id can't be added again;
// - run states only move along the transitions below; `revoked` and `deleted` never run again;
// - every change is written atomically (temp file, fsync, rename, fsync of the directory) before it is reported, so a
//   crash leaves either the old registry or the new one, never a mix. A registry that doesn't parse is refused: the
//   supervisor fails closed until it is repaired, rather than inventing one.

import { closeSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, writeSync, existsSync } from "node:fs";
import { join } from "node:path";
import { isId, refuse } from "../bytes.mjs";

export const UID_RANGE = Object.freeze([70000, 79999]);
export const GID_RANGE = Object.freeze([80000, 89999]);
export const STATES = Object.freeze(["provisioned", "running", "paused", "stopped", "revoked", "deleted"]);

/** Allowed run-state moves. A resume is stopped/paused → running; it needs a person-signed op, which the caller checks. */
const MOVES = Object.freeze({
  provisioned: ["running", "stopped", "revoked", "deleted"],
  running: ["paused", "stopped", "revoked", "deleted"],
  paused: ["running", "stopped", "revoked", "deleted"],
  stopped: ["running", "revoked", "deleted"],
  revoked: ["deleted"],
  deleted: [],
});

/** The lifecycle ops that increment `life` (O6/O7 r2.3 §3.4). */
export const LIFE_OPS = Object.freeze(["pause", "stop", "revoke-caps", "resume", "delete"]);

const FILE = "registry.json";

const empty = () => ({ v: 1, next_uid: UID_RANGE[0], next_gid: GID_RANGE[0], agents: {}, tags: {} });

function checkShape(r) {
  const bad = () => refuse("bad_form", "registry: corrupt");
  if (!r || typeof r !== "object" || r.v !== 1) bad();
  if (!Number.isSafeInteger(r.next_uid) || r.next_uid < UID_RANGE[0] || r.next_uid > UID_RANGE[1] + 1) bad();
  if (!Number.isSafeInteger(r.next_gid) || r.next_gid < GID_RANGE[0] || r.next_gid > GID_RANGE[1] + 1) bad();
  const uids = new Set(), gids = new Set();
  for (const [id, a] of Object.entries(r.agents ?? bad())) {
    if (!isId(id) || !a || !STATES.includes(a.state) || !Number.isSafeInteger(a.uid) || a.uid < UID_RANGE[0] || a.uid >= r.next_uid) bad();
    if (!Number.isSafeInteger(a.life) || a.life < 0 || !Number.isSafeInteger(a.gen) || a.gen < 1) bad();
    if (uids.has(a.uid)) bad();
    uids.add(a.uid);
  }
  for (const [id, t] of Object.entries(r.tags ?? bad())) {
    if (!isId(id) || !t || !Number.isSafeInteger(t.gid) || t.gid < GID_RANGE[0] || t.gid >= r.next_gid || gids.has(t.gid)) bad();
    gids.add(t.gid);
  }
  return r;
}

/** Write `text` to `dir/name` atomically and durably. */
export function writeDurable(dir, name, text) {
  const tmp = join(dir, `.${name}.tmp`);
  const fd = openSync(tmp, "w", 0o600);
  try { writeSync(fd, text); fsyncSync(fd); } finally { closeSync(fd); }
  renameSync(tmp, join(dir, name));
  const dfd = openSync(dir, "r");
  try { fsyncSync(dfd); } finally { closeSync(dfd); }
}

export class Registry {
  /** Open (or create, if absent) the registry in `dir`, which the caller has made root-only (0700). */
  constructor(dir) {
    this.dir = dir;
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    const path = join(dir, FILE);
    if (!existsSync(path)) { this.r = empty(); this.#save(); return; }
    let parsed;
    try { parsed = JSON.parse(readFileSync(path, "utf8")); } catch { refuse("bad_form", "registry: corrupt"); }
    this.r = checkShape(parsed);
  }

  #save() { writeDurable(this.dir, FILE, `${JSON.stringify(this.r)}\n`); }

  /** A copy of an agent's record, or null. */
  agent(id) { const a = this.r.agents[id]; return a ? { ...a, tags: [...a.tags] } : null; }
  tag(id) { const t = this.r.tags[id]; return t ? { ...t } : null; }

  /** Record a new agent under grant generation `gen`; returns its uid. An id is accepted once, ever. */
  addAgent(id, gen, tags = []) {
    if (!isId(id) || !Number.isSafeInteger(gen) || gen < 1 || !tags.every(isId)) refuse("bad_form", "registry: bad agent");
    if (Object.hasOwn(this.r.agents, id)) refuse("bad_form", "registry: an agent id is never reused");
    if (this.r.next_uid > UID_RANGE[1]) refuse("uid_exhausted", "registry: the agent uid range is used up");
    const uid = this.r.next_uid;
    this.r.agents[id] = { uid, state: "provisioned", life: 0, gen, tags: [...tags] };
    this.r.next_uid = uid + 1;
    this.#save();
    return uid;
  }

  /** Record a tag; returns its gid (the existing one if already recorded: tag ids are fleet-scoped and stable). */
  addTag(id) {
    if (!isId(id)) refuse("bad_form", "registry: bad tag");
    if (Object.hasOwn(this.r.tags, id)) return this.r.tags[id].gid;
    if (this.r.next_gid > GID_RANGE[1]) refuse("uid_exhausted", "registry: the tag gid range is used up");
    const gid = this.r.next_gid;
    this.r.tags[id] = { gid };
    this.r.next_gid = gid + 1;
    this.#save();
    return gid;
  }

  /**
   * Move an agent to `state`. `op`, when it is a lifecycle op, increments `life` in the same durable write (§7).
   * Refuses a move the table doesn't allow. Returns the new record.
   */
  setState(id, state, op = null) {
    const a = this.r.agents[id];
    if (!a) refuse("not_granted", "registry: unknown agent");
    if (!STATES.includes(state)) refuse("bad_form", "registry: unknown state");
    if (op !== null && !LIFE_OPS.includes(op)) refuse("bad_form", "registry: unknown op");
    if (a.state !== state && !MOVES[a.state].includes(state)) refuse("not_granted", "registry: that state change is not allowed");
    a.state = state;
    if (op !== null) a.life += 1;
    this.#save();
    return this.agent(id);
  }

  /** Update an agent's tags and grant generation (applying a newer grant, §3.3). Deleted and revoked agents are fixed. */
  setGrant(id, gen, tags) {
    const a = this.r.agents[id];
    if (!a) refuse("not_granted", "registry: unknown agent");
    if (a.state === "deleted" || a.state === "revoked") refuse("not_granted", "registry: a revoked or deleted agent is fixed");
    if (!Number.isSafeInteger(gen) || gen < a.gen || !tags.every(isId)) refuse("bad_form", "registry: bad grant update");
    a.gen = gen;
    a.tags = [...tags];
    this.#save();
    return this.agent(id);
  }

  /** Agents recovery may start: those whose recorded state is `running` (§3.3 recovery). */
  runnable() { return Object.keys(this.r.agents).filter((id) => this.r.agents[id].state === "running").sort(); }
}
