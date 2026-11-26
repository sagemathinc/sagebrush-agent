// The agent log's retention and device search (lib/agent-log; the transcript-and-context design note r0.8), rows 7
// and 13: the retained set, the prefix-verified release with its witness, and the search index against a fresh
// rebuild. The version store and the witness are fakes with crash and lost-acknowledgement seams; the index is SQLite
// FTS5 (node:sqlite) behind the indexer's transactional interface, here only.
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { test } from "node:test";
import {
  KEEP_DAYS, KEEP_NEWEST, compact, encodeLine, footerLine, frame, indexSegment, isPrefix, planClosedSegment, planContext, planOpenSegment,
  removeSegment, retainedVersions, searchable,
} from "../lib/agent-log/index.mjs";

const te = new TextEncoder();
const DAY = 86_400_000;
const T0 = Date.UTC(2026, 10, 17); // (a UTC midnight)
const cat = (...parts) => { const out = new Uint8Array(parts.reduce((a, p) => a + p.length, 0)); let o = 0; for (const p of parts) { out.set(p, o); o += p.length; } return out; };
const startsWith = (b, a) => a.length <= b.length && a.every((x, k) => x === b[k]);

/** Chunks of `bytes`, `size` at a time, counting how many were pulled. */
function chunks(bytes, size, pulled = { n: 0 }) {
  return (async function* () { for (let o = 0; o < bytes.length; o += size) { pulled.n++; yield bytes.subarray(o, o + size); } })();
}

/** A store of file versions. `seam(op, path, cseqs)` runs before a release applies ("before") and after ("after"). */
function versionStore({ seam = async () => {} } = {}) {
  const files = new Map();
  const st = { files, releases: [] };
  st.put = (path, cseq, t, bytes) => { if (!files.has(path)) files.set(path, new Map()); files.get(path).set(cseq, { t, bytes }); };
  st.cseqs = (path) => [...(files.get(path)?.keys() ?? [])].sort((a, b) => a - b);
  st.bytes = (path, c) => files.get(path).get(c).bytes;
  st.versions = async (path) => [...(files.get(path) ?? new Map())].map(([cseq, v]) => ({ cseq, t: v.t }));
  st.read = (path, c) => chunks(files.get(path).get(c).bytes, 5);
  st.release = async (path, cseqs) => {
    await seam("before", path, cseqs);
    for (const c of cseqs) files.get(path)?.delete(c);
    st.releases.push([path, [...cseqs]]);
    await seam("after", path, cseqs);
  };
  return st;
}

/** A durable, create-only witness. `seam(op)` runs before each operation. */
function witnessStore({ seam = async () => {} } = {}) {
  const slots = new Map();
  return {
    slots,
    get: async (k) => { await seam("get", k); return slots.has(k) ? structuredClone(slots.get(k)) : null; },
    create: async (k, r) => { await seam("create", k); if (slots.has(k)) return { exists: true }; slots.set(k, structuredClone(r)); return { ok: true }; },
    remove: async (k) => { await seam("remove", k); slots.delete(k); },
  };
}

const line = (turn, i, text, role = "assistant") => encodeLine({ turn, i, at_ms: T0, role, text });

/** An open segment rewritten once per turn: version k holds lines 1..k, each the bytes of the one before plus a line. */
function rewrites(st, path, times) {
  let bytes = new Uint8Array(0);
  times.forEach((t, k) => { bytes = cat(bytes, frame([line(`t${k + 1}`, 1, `turn ${k + 1}`)])); st.put(path, k + 1, t, bytes); });
  return bytes;
}

// ---- the retained set ----

test("the retained set: the newest 10 by cseq, each of the last 7 UTC days' newest by cseq, and the current", () => {
  const vs = [];
  for (let c = 1; c <= 30; c++) vs.push({ cseq: c, t: T0 + Math.floor((c - 1) / 4) * DAY + (c % 4) * 3_600_000 }); // (30 over 8 days)
  const now = T0 + 8 * DAY + 5;
  const keep = retainedVersions(vs, now);
  // (independently: the days today-6 .. today, each's highest cseq)
  const want = new Set(Array.from({ length: 10 }, (_, k) => 30 - k));
  for (let d = 0; d < 7; d++) {
    const from = T0 + (8 - d) * DAY;
    const inDay = vs.filter((v) => v.t >= from && v.t < from + DAY).map((v) => v.cseq);
    if (inDay.length) want.add(Math.max(...inDay));
  }
  assert.deepEqual([...keep].sort((a, b) => a - b), [...want].sort((a, b) => a - b));
  assert.ok(!keep.has(4), "a version from 8 days ago is not kept by its day");
  assert.equal(KEEP_NEWEST, 10);
  assert.equal(KEEP_DAYS, 7);

  // (by cseq, not by time: a clock that ran backwards picks the higher cseq of a day)
  const skew = [{ cseq: 1, t: T0 + 10 }, { cseq: 2, t: T0 + 5 }, { cseq: 3, t: T0 + 2 * DAY }];
  assert.deepEqual([...retainedVersions(skew, T0 + 2 * DAY, { newest: 1 })].sort(), [2, 3]);
  // (the day boundary is UTC midnight: the last millisecond of a day and the first of the next are different days)
  const edge = [{ cseq: 1, t: T0 + DAY - 1 }, { cseq: 2, t: T0 + DAY }, { cseq: 3, t: T0 + DAY + 1 }];
  assert.deepEqual([...retainedVersions(edge, T0 + DAY, { newest: 0 })].sort(), [1, 3]);
  // (the current is kept even with nothing else)
  assert.deepEqual([...retainedVersions([{ cseq: 7, t: 0 }, { cseq: 9, t: 0 }], T0 + 30 * DAY, { newest: 0 })], [9]);
  assert.deepEqual([...retainedVersions([], T0)], []);
  assert.throws(() => retainedVersions(vs, 1.5), RangeError);
  assert.throws(() => retainedVersions(vs, undefined), RangeError);
});

test("a context file releases exactly the versions outside the retained set", () => {
  const vs = Array.from({ length: 14 }, (_, k) => ({ cseq: k + 1, t: T0 }));
  assert.deepEqual(planContext(vs, T0), { release: [1, 2, 3, 4], anomalies: [] });
  assert.deepEqual(planContext(vs.slice(0, 10), T0).release, []);
});

// ---- the streaming prefix check ----

test("isPrefix streams both sides, across any chunk boundaries, and stops at the first difference", async () => {
  const b = te.encode("the quick brown fox jumps over the lazy dog\n");
  for (let n = 0; n <= b.length; n++) {
    for (const [sa, sb] of [[1, 1], [3, 7], [7, 3], [64, 2]]) {
      const r = await isPrefix(chunks(b.subarray(0, n), sa), chunks(b, sb));
      assert.equal(r.prefix, true, `${n} ${sa} ${sb}`);
    }
  }
  assert.equal((await isPrefix(chunks(b, 4), chunks(b, 9))).prefix, true, "equal bytes are a prefix");
  assert.equal((await isPrefix(chunks(b, 4), chunks(b.subarray(0, b.length - 1), 9))).prefix, false, "longer is not");
  const last = b.slice(); last[b.length - 1] = 0x21;
  assert.equal((await isPrefix(chunks(last, 4), chunks(b, 3))).prefix, false, "the last byte differs");
  const first = b.slice(); first[0] = 0x54;
  assert.equal((await isPrefix(chunks(first, 4), chunks(b, 3))).prefix, false, "the first byte differs");
  assert.equal((await isPrefix(chunks(new Uint8Array(0), 4), chunks(new Uint8Array(0), 4))).prefix, true);
  assert.equal((await isPrefix(chunks(b.subarray(0, 10), 4), chunks(new Uint8Array(0), 4))).prefix, false);

  // (the hash is of `a`, whole)
  const { sha256 } = await isPrefix(chunks(b.subarray(0, 20), 3), chunks(b, 5));
  const want = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", b.subarray(0, 20))), (x) => x.toString(16).padStart(2, "0")).join("");
  assert.equal(sha256, want);

  // (a difference at the start reads one chunk of each, not the 1 MiB behind it)
  const big = new Uint8Array(1 << 20), other = big.slice(); other[0] = 1;
  const pa = { n: 0 }, pb = { n: 0 };
  assert.equal((await isPrefix(chunks(other, 1024, pa), chunks(big, 1024, pb))).prefix, false);
  assert.ok(pa.n === 1 && pb.n === 1, `pulled ${pa.n} and ${pb.n}`);
});

// ---- row 13 ----

test("row 13: an open segment rewritten over 30 turns across 9 UTC days keeps exactly the retained union", async () => {
  const st = versionStore(), w = witnessStore(), path = "transcript/1.jsonl";
  const times = Array.from({ length: 30 }, (_, k) => T0 + Math.floor((k * 9) / 30) * DAY + k * 1000);
  const current = rewrites(st, path, times);
  const now = T0 + 8 * DAY + 12 * 3_600_000;
  const want = retainedVersions(await st.versions(path), now);
  assert.ok(want.size > 10 && want.size < 30, `${want.size}`);
  const before = st.cseqs(path).map((c) => [c, st.bytes(path, c)]);

  const r = await compact(st, w, path, "open", { now_ms: now });
  assert.deepEqual(st.cseqs(path), [...want].sort((a, b) => a - b));
  assert.deepEqual(r.anomalies, []);
  assert.equal(r.resumed, false);
  for (const [c, bytes] of before) {
    if (want.has(c)) continue;
    assert.ok(r.released.includes(c));
    assert.ok(startsWith(current, bytes), `the current version starts with released ${c}`);
  }
  assert.equal(w.slots.size, 0, "the witness is removed once the release is acknowledged");
  // (again: nothing more to release, and no witness is written)
  const again = await compact(st, w, path, "open", { now_ms: now });
  assert.deepEqual(again.released, []);
  assert.equal(st.releases.length, 1);
});

test("row 13: closing releases every verified earlier prefix, then the final version alone is kept forever", async () => {
  const st = versionStore(), w = witnessStore(), path = "transcript/2.jsonl";
  const open = rewrites(st, path, Array.from({ length: 10 }, (_, k) => T0 + k * 60_000));
  const final = cat(open, frame([await footerLine(open)]));
  st.put(path, 11, T0 + 3_600_000, final);
  const r = await compact(st, w, path, "closed", { finalCseq: 11 });
  assert.deepEqual(r.released, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
  assert.deepEqual(st.cseqs(path), [11]);
  for (const later of [T0 + DAY, T0 + 7 * DAY, T0 + 400 * DAY]) {
    assert.deepEqual((await compact(st, w, path, "closed", { finalCseq: 11, now_ms: later })).released, []);
    assert.deepEqual(st.cseqs(path), [11]);
    assert.deepEqual(st.bytes(path, 11), final);
  }
  assert.equal(st.releases.length, 1);
});

test("row 13: the final closed version is never released, even alone, and nothing is without it", async () => {
  const st = versionStore(), w = witnessStore(), path = "transcript/3.jsonl";
  st.put(path, 4, T0, frame([line("a", 1, "only")]));
  assert.deepEqual((await compact(st, w, path, "closed", { finalCseq: 4 })).released, []);
  assert.deepEqual(st.cseqs(path), [4]);
  // (a final that isn't in the store: no version is a verified prefix of it, so all are kept, as anomalies)
  st.put(path, 2, T0, frame([line("a", 1, "earlier")]));
  const p = await planClosedSegment(await st.versions(path), 9, (c) => st.read(path, c));
  assert.deepEqual(p, { release: [], anomalies: [2, 4] });
  // (a version newer than the final is an anomaly, kept)
  st.put(path, 6, T0, cat(st.bytes(path, 4), frame([line("b", 1, "after")])));
  const q = await compact(st, w, path, "closed", { finalCseq: 4 });
  assert.deepEqual(q.anomalies, [2, 6]);
  assert.deepEqual(st.cseqs(path), [2, 4, 6]);
});

test("row 13 control: a version that isn't a prefix of a retained newer one is never released, at closing or by age", async () => {
  const st = versionStore(), w = witnessStore(), path = "transcript/4.jsonl";
  const open = rewrites(st, path, Array.from({ length: 14 }, () => T0));
  st.put(path, 3, T0, frame([line("x", 1, "written directly into the history")])); // (replaces version 3)
  // (by age: 1, 2 and 4 are older than the newest 10 and prefixes, 3 isn't)
  const aged = await compact(st, w, path, "open", { now_ms: T0 + 30 * DAY });
  assert.deepEqual(aged.released, [1, 2, 4]);
  assert.deepEqual(aged.anomalies, [3]);
  assert.ok(st.cseqs(path).includes(3));
  // (at closing)
  st.put(path, 15, T0, cat(open, frame([await footerLine(open)])));
  const closed = await compact(st, w, path, "closed", { finalCseq: 15 });
  assert.deepEqual(closed.anomalies, [3]);
  assert.deepEqual(st.cseqs(path), [3, 15]);
  // (and the plan of an open segment counts it the same way, released never)
  assert.deepEqual((await planOpenSegment(await st.versions(path), T0 + 30 * DAY, (c) => st.read(path, c))).release, []);
});

// ---- the witness: crashes, lost acknowledgements, resuming ----

/** Ten open versions plus a closed final at 11. */
async function closing(seams = {}) {
  const st = versionStore(seams), w = witnessStore(seams), path = "transcript/5.jsonl";
  const open = rewrites(st, path, Array.from({ length: 10 }, () => T0));
  st.put(path, 11, T0, cat(open, frame([await footerLine(open)])));
  return { st, w, path };
}

test("the plan is witnessed before anything is released, and the final version is there at every step", async () => {
  let seen = 0, st, w, path;
  ({ st, w, path } = await closing({
    seam: async (op) => {
      if (op !== "before") return;
      seen++;
      assert.ok(w.slots.has(`compact:${path}`), "a witness before the release");
      assert.ok(st.cseqs(path).includes(11));
    },
  }));
  await compact(st, w, path, "closed", { finalCseq: 11 });
  assert.equal(seen, 1);
  assert.deepEqual(st.cseqs(path), [11]);
});

for (const [name, crashAt] of [
  ["a crash after the witness, before the release", "release-before"],
  ["a lost acknowledgement of the release", "release-after"],
  ["a crash before the witness is removed", "remove"],
]) {
  test(`resuming after ${name} ends as an uninterrupted run, released once in effect`, async () => {
    let armed = true;
    const crash = (where) => { if (armed && where === crashAt) { armed = false; throw new Error(`crash: ${where}`); } };
    const { st, w, path } = await closing({ seam: async (op) => crash(op === "before" ? "release-before" : op === "after" ? "release-after" : op) });
    await assert.rejects(compact(st, w, path, "closed", { finalCseq: 11 }), /crash/);
    assert.ok(w.slots.has(`compact:${path}`), "the witness survives the crash");
    assert.ok(st.cseqs(path).includes(11));
    const r = await compact(st, w, path, "closed", { finalCseq: 11 });
    assert.equal(r.resumed, true);
    assert.deepEqual(r.released, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    assert.deepEqual(st.cseqs(path), [11]);
    assert.equal(w.slots.size, 0);
    assert.deepEqual((await compact(st, w, path, "closed", { finalCseq: 11 })).released, [], "and then it is done");
  });
}

test("a resume follows the witnessed plan exactly, never a new one, and never releases the current version", async () => {
  const st = versionStore(), w = witnessStore(), path = "transcript/6.jsonl";
  rewrites(st, path, Array.from({ length: 12 }, () => T0));
  // (an interrupted compaction's record: 1 and 2 planned)
  await w.create(`compact:${path}`, { path, kind: "open", finalCseq: null, release: [1, 2], anomalies: [] });
  // (meanwhile more turns: a fresh plan would release 1..5)
  for (let c = 13; c <= 15; c++) st.put(path, c, T0, cat(st.bytes(path, 12), frame([line(`t${c}`, 1, `turn ${c}`)])));
  const r = await compact(st, w, path, "open", { now_ms: T0 });
  assert.equal(r.resumed, true);
  assert.deepEqual(r.released, [1, 2]);
  assert.deepEqual(st.cseqs(path).slice(0, 3), [3, 4, 5]);
  // (the next run plans afresh)
  assert.deepEqual((await compact(st, w, path, "open", { now_ms: T0 })).released, [3, 4, 5]);

  // (a record naming the current version, or a closed final, never releases it)
  await w.create(`compact:${path}`, { path, kind: "closed", finalCseq: 14, release: [6, 14, 15], anomalies: [] });
  assert.deepEqual((await compact(st, w, path, "open", { now_ms: T0 })).released, [6]);
  assert.ok(st.cseqs(path).includes(14) && st.cseqs(path).includes(15));
});

test("a compactor that loses the witness race follows the record already there", async () => {
  const st = versionStore(), path = "transcript/7.jsonl";
  rewrites(st, path, Array.from({ length: 13 }, () => T0));
  const w = witnessStore();
  const theirs = { path, kind: "open", finalCseq: null, release: [1], anomalies: [] };
  const realGet = w.get;
  let first = true;
  w.get = async (k) => { if (first) { first = false; await w.create(k, theirs); return null; } return realGet(k); };
  const r = await compact(st, w, path, "open", { now_ms: T0 });
  assert.deepEqual(r.released, [1]);
  assert.deepEqual(st.cseqs(path)[0], 2);
});

test("compact refuses an unknown kind, and writes no witness when there is nothing to release", async () => {
  const st = versionStore(), w = witnessStore(), path = "context.md";
  for (let c = 1; c <= 3; c++) st.put(path, c, T0, te.encode(`context ${c}`));
  await assert.rejects(compact(st, w, path, "other", { now_ms: T0 }), RangeError);
  const created = [];
  const w2 = { ...w, create: async (k, r) => { created.push(k); return w.create(k, r); } };
  assert.deepEqual((await compact(st, w2, path, "context", { now_ms: T0 })).released, []);
  assert.deepEqual(created, []);
  for (let c = 4; c <= 12; c++) st.put(path, c, T0, te.encode(`context ${c}`));
  assert.deepEqual((await compact(st, w2, path, "context", { now_ms: T0 })).released, [1, 2]);
  assert.deepEqual(created, [`compact:${path}`]);
});

// ---- row 7: the device search index ----

/** An FTS5 index behind the indexer's interface. `atomic: false` commits each change on its own (a control). */
function sqliteIndex(db, { atomic = true, crash = () => {} } = {}) {
  db.exec(`CREATE VIRTUAL TABLE IF NOT EXISTS lines USING fts5(path UNINDEXED, off UNINDEXED, turn UNINDEXED, role UNINDEXED, text);
           CREATE TABLE IF NOT EXISTS checkpoints (path TEXT PRIMARY KEY, cp TEXT NOT NULL);`);
  const tx = {
    checkpoint: async (p) => { const r = db.prepare("SELECT cp FROM checkpoints WHERE path = ?").get(p); return r ? JSON.parse(r.cp) : null; },
    setCheckpoint: async (p, cp) => {
      crash("checkpoint");
      if (cp === null) db.prepare("DELETE FROM checkpoints WHERE path = ?").run(p);
      else db.prepare("INSERT OR REPLACE INTO checkpoints (path, cp) VALUES (?, ?)").run(p, JSON.stringify(cp));
    },
    dropPath: async (p) => { db.prepare("DELETE FROM lines WHERE path = ?").run(p); },
    addLine: async (p, off, f) => { db.prepare("INSERT INTO lines (path, off, turn, role, text) VALUES (?, ?, ?, ?, ?)").run(p, off, f.turn, f.role, f.text); },
  };
  return {
    transaction: async (fn) => {
      if (atomic) db.exec("BEGIN");
      try { const r = await fn(tx); if (atomic) db.exec("COMMIT"); return r; } catch (e) { if (atomic) db.exec("ROLLBACK"); throw e; }
    },
  };
}

const QUERIES = ["alpha", "bravo", "charlie", "delta", "echo", "grep", "turn", "foxtrot OR golf"];
function snapshot(db) {
  const rows = db.prepare("SELECT path, off, turn, role, text FROM lines ORDER BY path, off").all().map((r) => ({ ...r }));
  const cps = db.prepare("SELECT path, cp FROM checkpoints ORDER BY path").all().map((r) => ({ path: r.path, cp: JSON.parse(r.cp) }));
  const answers = Object.fromEntries(QUERIES.map((q) => [q, db.prepare("SELECT path, off FROM lines WHERE lines MATCH ? ORDER BY path, off").all(q).map((r) => `${r.path}@${r.off}`)]));
  return { rows, cps, answers };
}

/** A fresh index of exactly the live segments. */
async function rebuilt(live) {
  const db = new DatabaseSync(":memory:"), idx = sqliteIndex(db);
  for (const [path, { revision, bytes }] of live) await indexSegment(idx, path, revision, bytes);
  return snapshot(db);
}

const seg = (...ls) => frame(ls.map(([turn, i, text, role]) => line(turn, i, text, role)));

test("row 7: the incremental index equals a fresh rebuild through every kind of change", async (t) => {
  const realFetch = globalThis.fetch;
  globalThis.fetch = () => { throw new Error("the network sentinel: nothing of the index leaves the device"); };
  t.after(() => { globalThis.fetch = realFetch; });

  let db = new DatabaseSync(":memory:"), idx = sqliteIndex(db);
  const live = new Map();
  const step = async (path, revision, bytes, want = {}) => {
    const r = await indexSegment(idx, path, revision, bytes);
    live.set(path, { revision, bytes });
    for (const [k, v] of Object.entries(want)) assert.equal(r[k], v, `${path}@${revision} ${k}`);
    assert.deepEqual(snapshot(db), await rebuilt(live), `${path}@${revision} equals a rebuild`);
    return r;
  };
  const A = "transcript/1.jsonl", B = "transcript/2.jsonl";
  const a1 = seg(["t1", 1, "alpha bravo", "user"], ["t1", 2, "charlie"]);
  await step(A, 1, a1, { indexed: 2, rebuilt: false });
  // (a strict append: only the new lines)
  const a2 = cat(a1, seg(["t2", 1, "delta"], ["t2", 2, "echo"]));
  await step(A, 2, a2, { indexed: 2, rebuilt: false });
  // (a tool line is searchable by its name and summary; a start or end marker isn't)
  const a3 = cat(a2, frame([encodeLine({ turn: "t3", i: 0, start: true, seq: 3, at_ms: T0 }), encodeLine({ turn: "t3", i: 1, at_ms: T0, role: "tool", name: "grep", summary: "foxtrot" })]));
  await step(A, 3, a3, { indexed: 1 });
  // (the same line count, an earlier line changed, the length kept)
  const a4 = cat(seg(["t1", 1, "alphx bravo", "user"]), a3.subarray(seg(["t1", 1, "alpha bravo", "user"]).length));
  assert.equal(a4.length, a3.length);
  await step(A, 4, a4, { rebuilt: true });
  // (shorter)
  await step(A, 5, a4.subarray(0, seg(["t1", 1, "alphx bravo", "user"]).length), { rebuilt: true, indexed: 1 });
  // (an older, out-of-order revision number with longer bytes: the bytes decide)
  await step(A, 2, a2, { rebuilt: true, indexed: 4 });
  // (an incomplete last line is not indexed until it is whole)
  const half = cat(a2, te.encode('{"turn":"t4","i":1,"role":"assistant","text":"golf'));
  await step(A, 6, half, { indexed: 0, rebuilt: false });
  const whole = cat(a2, seg(["t4", 1, "golf"]));
  await step(A, 7, whole, { indexed: 1, rebuilt: false });
  // (open to closed: the footer checked, not indexed)
  const closedA = cat(whole, frame([await footerLine(whole)]));
  await step(A, 8, closedA, { closed: true, footerBad: false, indexed: 0, rebuilt: false });
  // (a footer whose hash doesn't match: not closed)
  const b1 = seg(["u1", 1, "alpha"]);
  const forged = cat(b1, frame([encodeLine({ closed: true, lines: 1, bytes: b1.length, sha256: "0".repeat(64) })]));
  await step(B, 1, forged, { closed: false, footerBad: true });
  // (deletion, then reappearance with other bytes)
  await removeSegment(idx, B);
  live.delete(B);
  assert.deepEqual(snapshot(db), await rebuilt(live));
  await step(B, 2, seg(["u2", 1, "bravo charlie"]), { rebuilt: false, indexed: 1 });

  // (a crash between the rows and the checkpoint: neither is committed, and the retry equals a rebuild)
  const before = snapshot(db);
  let crashNext = true;
  idx = sqliteIndex(db, { crash: (w) => { if (crashNext && w === "checkpoint") { crashNext = false; throw new Error("crash"); } } });
  const b3 = cat(seg(["u2", 1, "bravo charlie"]), seg(["u3", 1, "delta delta"]));
  await assert.rejects(indexSegment(idx, B, 3, b3), /crash/);
  assert.deepEqual(snapshot(db), before, "the crash left the index as it was");
  await step(B, 3, b3, { rebuilt: false, indexed: 1 });

  // (an index schema reset: the tables dropped and made again)
  db.exec("DROP TABLE lines; DROP TABLE checkpoints;");
  idx = sqliteIndex(db);
  for (const [p, { revision, bytes }] of live) assert.equal((await indexSegment(idx, p, revision, bytes)).rebuilt, false);
  assert.deepEqual(snapshot(db), await rebuilt(live));
  // (the whole cache deleted)
  db.close();
  db = new DatabaseSync(":memory:");
  idx = sqliteIndex(db);
  for (const [p, { revision, bytes }] of live) assert.equal((await indexSegment(idx, p, revision, bytes)).rebuilt, false);
  assert.deepEqual(snapshot(db), await rebuilt(live));
  assert.deepEqual(snapshot(db).answers["foxtrot OR golf"], [`${A}@${whole.length - seg(["t4", 1, "golf"]).length}`]);
});

test("row 7 control: a checkpoint committed apart from the rows leaves an index that differs from a rebuild", async () => {
  const db = new DatabaseSync(":memory:");
  let crashNext = false;
  const idx = sqliteIndex(db, { atomic: false, crash: (w) => { if (crashNext && w === "checkpoint") { crashNext = false; throw new Error("crash"); } } });
  const p = "transcript/1.jsonl", b1 = seg(["t1", 1, "alpha"]), b2 = cat(b1, seg(["t2", 1, "bravo"]));
  await indexSegment(idx, p, 1, b1);
  crashNext = true;
  await assert.rejects(indexSegment(idx, p, 2, b2), /crash/);
  await indexSegment(idx, p, 2, b2);
  assert.notDeepEqual(snapshot(db), await rebuilt(new Map([[p, { revision: 2, bytes: b2 }]])));
});

test("searchable: the words of user, assistant and tool lines; nothing of markers, gaps, pointers or footers", () => {
  assert.deepEqual(searchable({ turn: "t", i: 1, role: "user", text: "hi" }), { turn: "t", role: "user", text: "hi" });
  assert.deepEqual(searchable({ turn: "t", i: 2, role: "tool", name: "grep", summary: "x" }), { turn: "t", role: "tool", text: "grep x" });
  assert.deepEqual(searchable({ turn: "t", i: 2, role: "tool" }), { turn: "t", role: "tool", text: "" });
  for (const v of [null, 3, "s", {}, { turn: "t", i: 0, start: true }, { turn: "t", i: 4, end: true }, { turn: "t", i: 1, gap: true }, { cloned_from: { agent: "a", seq: 1 } },
    { closed: true }, { turn: "t", role: "user" }, { turn: 5, role: "user", text: "x" }]) assert.equal(searchable(v), null, JSON.stringify(v));
});
