// Host backup (design: agent-autonomous-host-backup.md r3.3 §6): retention over manifests, the roots, and what
// forget may remove; the weekly prune and the rotating data check.
//
// - The policy picks which MANIFESTS to keep: always the last committed one, plus the newest of each of the 7 most
//   recent days, 4 most recent weeks and 6 most recent months that have one (UTC days, ISO weeks, calendar months).
// - The ROOTS are every snapshot a kept manifest references, the kept manifests themselves, and every good snapshot
//   newer than the last committed manifest (the next manifest may reference it). They are recomputed on every pass
//   from the manifests as read back from the store, never from a local list.
// - forget may remove only snapshots outside the roots, and only of kinds it knows: a manifest not kept; a good
//   snapshot no kept manifest references and not newer than the last manifest; a warm snapshot older than a day (or
//   named by a run that ended), never the current run's. A snapshot without our tags is never touched.
// - prune runs weekly (rustic's delayed deletion keeps every pack a remaining snapshot needs); the data check reads
//   a rotating 1/30 of the packs each day.

import { refuse } from "../bytes.mjs";

export const KEEP = Object.freeze({ daily: 7, weekly: 4, monthly: 6 });
export const WARM_MAX_AGE_MS = 24 * 60 * 60 * 1000;
export const PRUNE_EVERY_MS = 7 * 24 * 60 * 60 * 1000;
export const CHECK_PARTS = 30;

const tag = (snap, name) => snap.tags.find((t) => t.startsWith(`${name}=`))?.slice(name.length + 1) ?? null;
/** What a snapshot is, from its tags: { kind, state, run }, or null when it isn't one of ours. */
export function classify(snap) {
  const kind = tag(snap, "sb-kind"), state = tag(snap, "sb-state"), run = tag(snap, "sb-run");
  if (!kind || !state || !run || !["warm", "good"].includes(state)) return null;
  if (!["agent", "archive", "tag", "hoststore", "manifest"].includes(kind)) return null;
  if (kind === "manifest" && state !== "good") return null;
  return { kind, state, run };
}

const day = (t) => new Date(t).toISOString().slice(0, 10);
const month = (t) => new Date(t).toISOString().slice(0, 7);
/** ISO 8601 week, as "YYYY-Www". */
export function isoWeek(t) {
  const d = new Date(t);
  const date = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
  const dow = date.getUTCDay() || 7;
  date.setUTCDate(date.getUTCDate() + 4 - dow);
  const year = date.getUTCFullYear();
  const week = Math.ceil(((date - Date.UTC(year, 0, 1)) / 86400000 + 1) / 7);
  return `${year}-W${String(week).padStart(2, "0")}`;
}

/**
 * Which manifests to keep. `manifests`: [{ snapshot, time (ms) }] of committed (read-back) manifests. Returns the
 * set of kept snapshot ids.
 */
export function keepManifests(manifests, keep = KEEP) {
  const sorted = [...manifests].sort((a, b) => b.time - a.time || (a.snapshot < b.snapshot ? -1 : 1));
  const kept = new Set();
  if (sorted.length) kept.add(sorted[0].snapshot);
  for (const [n, key] of [[keep.daily, day], [keep.weekly, isoWeek], [keep.monthly, month]]) {
    const seen = new Set();
    for (const m of sorted) {
      const k = key(m.time);
      if (seen.has(k)) continue;
      if (seen.size >= n) break;
      seen.add(k); kept.add(m.snapshot);
    }
  }
  return kept;
}

/**
 * The roots. `kept`: kept manifest ids; `contents`: id -> the manifest's referenced snapshot ids (from manifests read
 * back from the store); `snapshots`: every snapshot ({ id, time (ms), tags }); `lastManifestTime`: the newest
 * committed manifest's time (or -Infinity). A kept manifest whose content is missing refuses: unknown is never "no
 * roots".
 */
export function rootsOf(kept, contents, snapshots, lastManifestTime) {
  const roots = new Set();
  for (const id of kept) {
    if (!contents.has(id)) refuse("not_found", "backup retention: a kept manifest couldn't be read back");
    roots.add(id);
    for (const r of contents.get(id)) roots.add(r);
  }
  for (const s of snapshots) {
    const c = classify(s);
    if (c && c.state === "good" && c.kind !== "manifest" && s.time > lastManifestTime) roots.add(s.id);
  }
  return roots;
}

/**
 * What forget may remove: snapshot ids outside the roots, of a kind it knows. `activeRun`: the run of a journal that
 * is in progress (its warm snapshot is never forgotten here), or null; `endedRuns`: runs whose journals ended
 * aborted (their warm snapshots go now, whatever their age).
 */
export function forgetPlan(snapshots, roots, { now, activeRun = null, endedRuns = new Set() }) {
  if (!Number.isFinite(now)) refuse("bad_form", "backup retention: a time is required");
  const out = [];
  for (const s of snapshots) {
    if (roots.has(s.id)) continue;
    const c = classify(s);
    if (c === null) continue; // not ours: never touched
    if (c.state === "warm") {
      if (c.run === activeRun) continue;
      if (endedRuns.has(c.run) || now - s.time > WARM_MAX_AGE_MS) out.push(s.id);
      continue;
    }
    out.push(s.id); // a good snapshot or a manifest outside the roots
  }
  return out.sort();
}

/** Today's rotating data check: part (day number mod 30) + 1 of 30. */
export function checkDataPart(now, of = CHECK_PARTS) {
  const dayNumber = Math.floor(now / 86400000);
  return { part: (dayNumber % of) + 1, of };
}

/** A prune is due a week after the last one (or when there has been none). */
export const pruneDue = (lastPrune, now) => lastPrune === null || now - lastPrune >= PRUNE_EVERY_MS;

/**
 * One retention pass against the store (deps.binary as in backup-run). It lists every snapshot, then reads back,
 * dumps and parses EVERY manifest (commitManifest forgets a manifest whose own commit failed, so every manifest in
 * the store is a committed one), keeps the manifests the policy picks, computes the roots from what those manifests
 * say, and forgets only what forgetPlan allows. Any doubt stops the pass before anything is forgotten: a listing, a
 * read-back, a dump that fails, or a manifest that doesn't parse (it is reported, for a person to look at). Resolves
 * to { kept, roots, forgotten } (ids), or { error, snapshot? }.
 * `parse(text)` is backup-manifest's parseManifest; `referenced(m)` its referenced().
 */
export async function retentionPass(deps, { now, activeRun = null, endedRuns = new Set(), parse, referenced, ms = 30 * 60 * 1000, batch = 200 }) {
  const list = await deps.binary({ op: "snapshots" }, { ms });
  if (!list.ok) return { error: list.code };
  const snapshots = list.value.snapshots.map((s) => ({ id: s.id, time: Date.parse(s.time), tags: s.tags, paths: s.paths }));
  if (snapshots.some((s) => !Number.isFinite(s.time))) return { error: "bad_result" };
  const committed = [], contents = new Map();
  for (const s of snapshots) {
    const c = classify(s);
    if (!c || c.kind !== "manifest") continue;
    if (s.paths.length !== 1) return { error: "bad_manifest", snapshot: s.id };
    const rb = await deps.binary({ op: "readback", snapshot: s.id }, { ms });
    if (!rb.ok || rb.value.findings !== 0) return { error: rb.ok ? "check_failed" : rb.code, snapshot: s.id };
    const d = await deps.binary({ op: "dump", snapshot: s.id, path: `${s.paths[0].slice(1)}/manifest.json` }, { ms });
    if (!d.ok) return { error: d.code, snapshot: s.id };
    let m;
    try { m = parse(d.value.text); } catch { return { error: "bad_manifest", snapshot: s.id }; }
    committed.push({ snapshot: s.id, time: s.time });
    contents.set(s.id, referenced(m));
  }
  const kept = keepManifests(committed);
  const last = committed.reduce((t, m) => Math.max(t, m.time), -Infinity);
  const roots = rootsOf(kept, contents, snapshots, last);
  const plan = forgetPlan(snapshots, roots, { now, activeRun, endedRuns });
  for (let i = 0; i < plan.length; i += batch) {
    const f = await deps.binary({ op: "forget", snapshots: plan.slice(i, i + batch) }, { ms });
    if (!f.ok) return { error: f.code, kept: [...kept], roots: [...roots], forgotten: plan.slice(0, i) };
  }
  return { kept: [...kept].sort(), roots: [...roots].sort(), forgotten: plan };
}
