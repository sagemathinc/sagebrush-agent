// Host backup (design: agent-autonomous-host-backup.md r3.3 §4 "The host manifest", §6): the run's manifest.
//
// A run ends by committing ONE manifest snapshot (sb-kind=manifest), only after every part is good and read back. A
// host backup is successful only when its manifest is committed and read back. Restore takes a manifest, never
// loose snapshots; listing shows only snapshots a read-back manifest references.
//
// The manifest binds:
// - the registry copy taken at the run's start: its hash and every agent's uid, state, life, gen and tags, and the
//   tags' gids (a deleted agent is its tombstone);
// - for each agent, tag and archive, the snapshot and tree it is restored from (an earlier run's good snapshot for a
//   set that didn't change);
// - each LIVE agent's config generation hash: the keys are exactly the live agents (none missing, none extra, no
//   deleted agent's);
// - the host store's snapshot;
// - the unrestorable entries, per set.
// Built here only if it is consistent: every live agent of the registry copy has an agent entry, every deleted one
// an archive entry, every tag a tag entry, and nothing else; otherwise the run isn't a success (refused).

import { createHash } from "node:crypto";
import * as fs from "node:fs";
import { join } from "node:path";
import { isId, refuse } from "../bytes.mjs";

export const MANIFEST_FILE = "manifest.json";
const HEX64 = /^[0-9a-f]{64}$/;
const RUN = /^[0-9]{8}T[0-9]{6}Z-[a-z2-7]{8}$/;
const HOST = /^[A-Za-z0-9-]{1,64}$/;
const KINDS = ["agent", "archive", "tag"];
const isMap = (o) => o !== null && typeof o === "object" && !Array.isArray(o);
const exact = (o, keys) => isMap(o) && Object.keys(o).length === keys.length && keys.every((k) => Object.hasOwn(o, k));

/** JSON with every object's keys sorted, so the same manifest always has the same bytes (and hash). */
export function canonical(v) {
  if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
  if (isMap(v)) return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonical(v[k])}`).join(",")}}`;
  return JSON.stringify(v);
}
export const sha256 = (s) => createHash("sha256").update(s).digest("hex");

/** The manifest's closed shape. Returns it, or refuses (bad_form). */
export function checkManifest(m) {
  const bad = (why) => refuse("bad_form", `backup manifest: ${why}`);
  if (!exact(m, ["v", "host", "run", "time", "registry", "sets", "config", "hoststore", "unrestorable"]) || m.v !== 1) bad("shape");
  if (!HOST.test(m.host) || !RUN.test(m.run) || typeof m.time !== "string" || Number.isNaN(Date.parse(m.time))) bad("host, run or time");
  const r = m.registry;
  if (!exact(r, ["hash", "agents", "tags"]) || !HEX64.test(r.hash) || !isMap(r.agents) || !isMap(r.tags)) bad("registry");
  for (const [id, a] of Object.entries(r.agents)) {
    if (!isId(id) || !exact(a, ["uid", "state", "life", "gen", "tags"]) || !Number.isSafeInteger(a.uid) || typeof a.state !== "string"
      || !Number.isSafeInteger(a.life) || !Number.isSafeInteger(a.gen) || !Array.isArray(a.tags) || !a.tags.every(isId)) bad("registry agent");
  }
  for (const [id, t] of Object.entries(r.tags)) if (!isId(id) || !exact(t, ["gid"]) || !Number.isSafeInteger(t.gid)) bad("registry tag");
  if (!Array.isArray(m.sets)) bad("sets");
  for (const s of m.sets) {
    if (!exact(s, ["kind", "id", "snapshot", "tree"]) || !KINDS.includes(s.kind) || !isId(s.id) || !HEX64.test(s.snapshot) || !HEX64.test(s.tree)) bad("set");
  }
  if (!isMap(m.config) || !Object.entries(m.config).every(([id, h]) => isId(id) && HEX64.test(h))) bad("config");
  // Consistency with its own registry copy, the same rules buildManifest applies, so a parsed manifest is held to them.
  const live = Object.entries(r.agents).filter(([, a]) => a.state !== "deleted").map(([id]) => id).sort();
  if (Object.keys(m.config).sort().join() !== live.join()) bad("the config hashes aren't exactly the live agents'");
  const want = [...Object.entries(r.agents).map(([id, a]) => `${a.state === "deleted" ? "archive" : "agent"}:${id}`), ...Object.keys(r.tags).map((id) => `tag:${id}`)].sort();
  const have = m.sets.map((s) => `${s.kind}:${s.id}`).sort();
  if (have.join() !== want.join()) bad("the sets aren't exactly the registry copy's");
  if (!HEX64.test(m.hoststore)) bad("hoststore");
  if (!Array.isArray(m.unrestorable) || !m.unrestorable.every((u) => exact(u, ["kind", "id", "count", "paths"]) && KINDS.includes(u.kind)
    && isId(u.id) && Number.isSafeInteger(u.count) && u.count > 0 && Array.isArray(u.paths) && u.paths.length <= 20 && u.paths.every((p) => typeof p === "string"))) bad("unrestorable");
  return m;
}

/**
 * Build the run's manifest, refusing (not_granted) if it isn't consistent with the registry copy:
 * - `registry`: the registry copy taken at the run's start (registry.mjs's closed shape);
 * - `sets`: [{ kind, id, snapshot, tree, unrestorable: { count, paths } }], one per source set, each good and read
 *   back (this run's, or an earlier run's for an unchanged set);
 * - `config`: { agent id: config generation hash }; `hoststore`: the host store's good snapshot id.
 */
export function buildManifest({ host, run, time, registry, sets, config, hoststore }) {
  const agents = {}, tags = {};
  for (const [id, a] of Object.entries(registry.agents)) agents[id] = { uid: a.uid, state: a.state, life: a.life, gen: a.gen, tags: [...a.tags] };
  for (const [id, t] of Object.entries(registry.tags)) tags[id] = { gid: t.gid };
  const want = new Set([
    ...Object.entries(registry.agents).map(([id, a]) => `${a.state === "deleted" ? "archive" : "agent"}:${id}`),
    ...Object.keys(registry.tags).map((id) => `tag:${id}`),
  ]);
  const have = new Set(sets.map((s) => `${s.kind}:${s.id}`));
  if (have.size !== sets.length) refuse("not_granted", "backup manifest: a set appears twice");
  for (const k of want) if (!have.has(k)) refuse("not_granted", `backup manifest: no snapshot for ${k.split(":")[0]} in the registry copy`);
  for (const k of have) if (!want.has(k)) refuse("not_granted", "backup manifest: a set the registry copy doesn't name (or names in another state)");
  const live = Object.entries(registry.agents).filter(([, a]) => a.state !== "deleted").map(([id]) => id);
  const keys = Object.keys(config ?? {});
  // Exactly the live agents: a missing hash (the counts differ), an extra or a deleted agent's are all refused.
  if (keys.length !== live.length || !keys.every((k) => live.includes(k))) refuse("not_granted", "backup manifest: the config hashes aren't exactly the live agents'");
  const order = (a, b) => (a.kind < b.kind ? -1 : a.kind > b.kind ? 1 : a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
  const m = {
    v: 1, host, run, time,
    registry: { hash: sha256(canonical(registry)), agents, tags },
    sets: sets.map((s) => ({ kind: s.kind, id: s.id, snapshot: s.snapshot, tree: s.tree })).sort(order),
    config: { ...config },
    hoststore,
    unrestorable: sets.filter((s) => s.unrestorable?.count > 0)
      .map((s) => ({ kind: s.kind, id: s.id, count: s.unrestorable.count, paths: s.unrestorable.paths.slice(0, 20) })).sort(order),
  };
  return checkManifest(m);
}

/** Every snapshot a manifest references (its sets and the host store). */
export const referenced = (m) => [...m.sets.map((s) => s.snapshot), m.hoststore];

/**
 * Commit the manifest: write it into a fresh staging directory, back that up as its own snapshot (sb-kind=manifest,
 * sb-state=good, sb-run), read the snapshot back, and dump the file and compare it byte for byte. Only then is the
 * run a success. If any check after the backup fails, the manifest snapshot is forgotten (best effort), so every
 * manifest left in the store is a committed one. `deps.binary(req, { ms })` as in backup-run; `staging` must not
 * exist. Resolves to { ok: true, snapshot, sha256 } or { ok: false, code }.
 */
export async function commitManifest(m, staging, deps, { ms = 30 * 60 * 1000 } = {}) {
  checkManifest(m);
  const text = canonical(m) + "\n";
  fs.mkdirSync(staging, { mode: 0o700 });
  const fd = fs.openSync(join(staging, MANIFEST_FILE), "wx", 0o600);
  try { fs.writeSync(fd, text); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  const tags = [`sb-run=${m.run}`, "sb-state=good", "sb-kind=manifest"];
  const b = await deps.binary({ op: "backup", sources: [staging], host: m.host, tags }, { ms });
  if (!b.ok) return { ok: false, code: b.code };
  const id = b.value.snapshot.id;
  const fail = async (code) => { await deps.binary({ op: "forget", snapshots: [id] }, { ms }); return { ok: false, code }; };
  const rb = await deps.binary({ op: "readback", snapshot: id }, { ms });
  if (!rb.ok || rb.value.findings !== 0) return fail(rb.ok ? "check_failed" : rb.code);
  const d = await deps.binary({ op: "dump", snapshot: id, path: `${staging.slice(1)}/${MANIFEST_FILE}` }, { ms });
  if (!d.ok) return fail(d.code);
  if (d.value.text !== text) return fail("readback_failed");
  return { ok: true, snapshot: id, sha256: sha256(text) };
}

/** Parse a manifest's text as dumped from the store (exactly canonical, closed shape). Refuses anything else. */
export function parseManifest(text) {
  let m;
  try { m = JSON.parse(text); } catch { refuse("bad_form", "backup manifest: not JSON"); }
  checkManifest(m);
  if (canonical(m) + "\n" !== text) refuse("bad_form", "backup manifest: not in canonical form");
  return m;
}
