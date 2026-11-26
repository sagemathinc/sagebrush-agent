// Compaction of an agent's context file and transcript segments (the transcript-and-context design note r0.8 §8 Q2,
// and the sync delta's §3): which versions are kept, which are released, and the release done so that a crash or a
// lost acknowledgement never loses a line or releases the wrong version.
//
// - **The retained set** of a context file or an OPEN segment: the union of its newest 10 versions and each of the last
//   7 UTC days' newest, by the versions' `cseq` order (the sync log's order). The current version (the highest
//   `cseq`) is always kept. The writer's clock only picks which versions to keep; it never decides whether a release
//   is allowed (that is the release's authorization, outside this module).
// - **A context file** releases the rest: contexts are replaced whole, so no prefix rule applies.
// - **An open segment** releases a version only if its bytes are a byte prefix of a RETAINED newer version of the same
//   segment, checked by streaming both, so every line of it survives. A version that isn't is kept and counted as an
//   anomaly, never released.
// - **A closed segment**, once its footer is acknowledged, keeps its final version alone, forever: every earlier
//   version that is a verified prefix of the final one is released; an anomaly is kept and counted.
// - **The release is witnessed first** (TESTS' pin): the plan is recorded, create-only and immutable, before anything
//   is released. A run that finds a witness resumes exactly it (never a new plan), and releases are idempotent, so a
//   crash or a lost acknowledgement at any point ends with the same versions released, once. The current version is
//   checked again just before releasing and is never in a release.
//
// Pure: the store and the witness are the caller's.
//   store.versions(path)         -> [{ cseq, t }]   (t: the version's time, ms)
//   store.read(path, cseq)       -> async iterable of Uint8Array chunks
//   store.release(path, cseqs)   -> resolves when acknowledged (idempotent: releasing a released version is a no-op)
//   witness.get(key)             -> record | null       (one slot per file, durable)
//   witness.create(key, record)  -> { ok } | { exists }  (never replaces a record that is there)
//   witness.remove(key)          -> idempotent; called only once the record's release is acknowledged

import { Sha256 } from "./sha256.mjs";

export const KEEP_NEWEST = 10;
export const KEEP_DAYS = 7;
const DAY = 86_400_000;

/** The cseqs kept: the newest `newest` by cseq, each of the last `days` UTC days' newest (relative to now_ms), and the current. */
export function retainedVersions(versions, now_ms, { newest = KEEP_NEWEST, days = KEEP_DAYS } = {}) {
  if (!Number.isSafeInteger(now_ms)) throw new RangeError("now_ms: a safe integer");
  const byCseq = [...versions].sort((a, b) => b.cseq - a.cseq);
  const keep = new Set(byCseq.slice(0, newest).map((v) => v.cseq));
  if (byCseq.length) keep.add(byCseq[0].cseq);
  const today = Math.floor(now_ms / DAY) * DAY;
  for (let d = 0; d < days; d++) {
    const from = today - d * DAY, to = from + DAY;
    const first = byCseq.find((v) => v.t >= from && v.t < to);
    if (first) keep.add(first.cseq);
  }
  return keep;
}

/**
 * Whether the bytes of `a` are a byte prefix of the bytes of `b`, read as two streams of chunks, holding at most one
 * chunk of each at a time. Also returns each stream's SHA-256 as far as it was read (`a` in full when true).
 */
export async function isPrefix(a, b) {
  const ia = a[Symbol.asyncIterator](), ib = b[Symbol.asyncIterator]();
  const ha = new Sha256();
  let ca = new Uint8Array(0), cb = new Uint8Array(0), pa = 0, pb = 0;
  for (;;) {
    if (pa === ca.length) {
      const r = await ia.next();
      if (r.done) { await ib.return?.(); return { prefix: true, sha256: ha.hex() }; }
      ca = r.value; pa = 0;
      ha.update(ca);
      continue;
    }
    if (pb === cb.length) {
      const r = await ib.next();
      if (r.done) { await ia.return?.(); return { prefix: false }; }
      cb = r.value; pb = 0;
      continue;
    }
    const n = Math.min(ca.length - pa, cb.length - pb);
    for (let k = 0; k < n; k++) if (ca[pa + k] !== cb[pb + k]) { await ia.return?.(); await ib.return?.(); return { prefix: false }; }
    pa += n; pb += n;
  }
}

/** A context file's plan: release every version outside the retained set. */
export function planContext(versions, now_ms) {
  const keep = retainedVersions(versions, now_ms);
  return { release: versions.filter((v) => !keep.has(v.cseq)).map((v) => v.cseq).sort((x, y) => x - y), anomalies: [] };
}

/**
 * An open segment's plan: a version outside the retained set is released only if it is a verified prefix of the
 * nearest retained newer version; otherwise it is kept as an anomaly. `read(cseq)` streams a version.
 */
export async function planOpenSegment(versions, now_ms, read) {
  const keep = retainedVersions(versions, now_ms);
  const retained = [...keep].sort((x, y) => x - y);
  const release = [], anomalies = [];
  for (const v of [...versions].sort((x, y) => x.cseq - y.cseq)) {
    if (keep.has(v.cseq)) continue;
    const newer = retained.find((c) => c > v.cseq);
    const ok = newer !== undefined && (await isPrefix(read(v.cseq), read(newer))).prefix;
    (ok ? release : anomalies).push(v.cseq);
  }
  return { release, anomalies };
}

/**
 * A closed segment's plan, once its footer is acknowledged: every earlier version that is a verified prefix of the
 * final one (`finalCseq`, never released) is released; any other is kept as an anomaly.
 */
export async function planClosedSegment(versions, finalCseq, read) {
  const release = [], anomalies = [];
  // (no final version among them: nothing is a verified prefix of it, so nothing is released)
  if (!versions.some((v) => v.cseq === finalCseq)) return { release, anomalies: versions.map((v) => v.cseq).sort((x, y) => x - y) };
  for (const v of [...versions].sort((x, y) => x.cseq - y.cseq)) {
    if (v.cseq === finalCseq) continue;
    if (v.cseq > finalCseq) { anomalies.push(v.cseq); continue; }
    ((await isPrefix(read(v.cseq), read(finalCseq))).prefix ? release : anomalies).push(v.cseq);
  }
  return { release, anomalies };
}

/**
 * Compact one file: `kind` is "context", "open" or "closed" (with `finalCseq`). One witness slot per file: a record
 * there is a compaction in progress and is resumed EXACTLY (never replaced by a new plan); otherwise a plan is made and
 * recorded, create-only, BEFORE any release. The record is removed only after its release is acknowledged. The current
 * version is read again just before releasing and is never released, nor a closed segment's final one. Returns
 * { released, anomalies, resumed }.
 */
export async function compact(store, witness, path, kind, { now_ms, finalCseq } = {}) {
  const key = `compact:${path}`;
  let record = await witness.get(key);
  const resumed = !!record;
  if (!record) {
    const versions = await store.versions(path);
    const read = (c) => store.read(path, c);
    const plan = kind === "context" ? planContext(versions, now_ms)
      : kind === "open" ? await planOpenSegment(versions, now_ms, read)
      : kind === "closed" ? await planClosedSegment(versions, finalCseq, read)
      : null;
    if (!plan) throw new RangeError(`unknown kind ${kind}`);
    if (!plan.release.length) return { released: [], anomalies: plan.anomalies, resumed: false };
    const made = { path, kind, finalCseq: kind === "closed" ? finalCseq : null, release: plan.release, anomalies: plan.anomalies };
    const c = await witness.create(key, made);
    record = c.exists ? await witness.get(key) : made;
  }
  // (the current version, read again now: never released, whatever the record says)
  const now = await store.versions(path);
  const current = now.reduce((m, v) => Math.max(m, v.cseq), -Infinity);
  const release = record.release.filter((c) => c !== current && c !== record.finalCseq);
  if (release.length) await store.release(path, release);
  await witness.remove(key);
  return { released: release, anomalies: record.anomalies, resumed };
}
