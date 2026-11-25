// The agent log (lib/agent-log; the transcript-and-context design note r0.8), rows 1-6, 11 and 12 (the journal's), on
// a fake store that follows the writer's contract: compare-and-set on a revision, create-only, and acknowledgements
// that can be lost after the write applied. The sync service that will be the real store is a later PR's.
import assert from "node:assert/strict";
import { test } from "node:test";
import {
  CONTEXT_MAX, FOOTER_MAX, HEADER_MAX, LINE_MAX, SEGMENT_MAX, STALL_MS, Journal, abortStalled, anchorNow, boundedLines, buildContext, claudeRecord,
  codexRecord, contextHeader, contextWindow, encodeLine, observeTail, parseSegment, publishContext, publishTurn, segmentPath, turnLines,
} from "../lib/agent-log/index.mjs";

const te = new TextEncoder(), td = new TextDecoder();
const AT = Date.UTC(2026, 10, 25, 12);

/** A store with checked writes. `lose(path)` true: the write applies, then its acknowledgement is lost (it throws). */
function fakeStore({ lose = () => false, before = async () => {} } = {}) {
  const files = new Map();
  let rev = 0;
  const st = { files, writes: 0 };
  st.list = async (prefix) => [...files.keys()].filter((p) => p.startsWith(prefix));
  st.read = async (p) => (files.has(p) ? { bytes: files.get(p).bytes, rev: files.get(p).rev } : null);
  st.cas = async (p, bytes, r) => {
    await before(p, "cas");
    const f = files.get(p);
    if (!f || f.rev !== r) return { conflict: true };
    files.set(p, { bytes, rev: ++rev });
    st.writes++;
    if (lose(p)) throw new Error("the acknowledgement was lost");
    return { ok: true, rev };
  };
  st.create = async (p, bytes) => {
    await before(p, "create");
    if (files.has(p)) return { exists: true };
    files.set(p, { bytes, rev: ++rev });
    st.writes++;
    if (lose(p)) throw new Error("the acknowledgement was lost");
    return { ok: true, rev };
  };
  return st;
}

/** Retry until done, swallowing lost acknowledgements (as a writer's loop does). */
async function until(f) {
  for (let k = 0; k < 200; k++) { try { return await f(); } catch (e) { if (!/acknowledgement was lost/.test(e.message)) throw e; } }
  throw new Error("never done");
}

/** Every line of every segment, in order, with the segment it is in. */
async function allLines(store) {
  const ns = (await store.list("transcript/")).map((p) => Number(/(\d+)\.jsonl$/.exec(p)[1])).sort((a, b) => a - b);
  const out = [];
  for (const n of ns) {
    const seg = await parseSegment((await store.read(segmentPath(n))).bytes);
    for (const l of seg.lines) out.push({ n, value: l.value, bytes: l.bytes });
  }
  return out;
}
const entryOf = (turn, texts, at_ms = AT, anchor = null) => ({ turn, at_ms, anchor, lines: turnLines(turn, at_ms, texts.map((t) => ({ role: "assistant", text: t }))) });
async function* chunksOf(text, size = 7) { const b = te.encode(text); for (let i = 0; i < b.length; i += size) yield b.subarray(i, i + size); }
const jsonl = (records) => records.map((r) => JSON.stringify(r)).join("\n") + "\n";

// ---- row 1: the adapters
test("row 1: Claude Code: the window is the last compaction's summary plus everything after it, provider fields dropped", async () => {
  const user = (text) => ({ type: "user", uuid: "u", message: { role: "user", content: text } });
  const said = (text) => ({ type: "assistant", uuid: "a", message: { role: "assistant", id: "m", usage: { input_tokens: 9 }, content: [{ type: "thinking", thinking: "hm", signature: "s" }, { type: "text", text }] } });
  const call = (id, input) => ({ type: "assistant", message: { role: "assistant", content: [{ type: "tool_use", id, name: "Bash", input }] } });
  const result = (id, content, is_error = false) => ({ type: "user", message: { role: "user", content: [{ type: "tool_result", tool_use_id: id, content, is_error }] } });
  const boundary = { type: "system", subtype: "compact_boundary" }, summary = (t) => ({ type: "user", isCompactSummary: true, message: { role: "user", content: t } });
  const recs0 = [user("hi"), said("hello"), call("t1", { command: "ls" }), result("t1", "a b")];
  const w0 = await contextWindow(boundedLines(chunksOf(jsonl(recs0))), "claude-code");
  assert.equal(w0.summary, null);
  assert.deepEqual(w0.messages, [{ role: "user", text: "hi" }, { role: "assistant", text: "hello" }, { role: "tool_call", name: "Bash", call: "t1", input: '{"command":"ls"}' }, { role: "tool_result", call: "t1", output: "a b", error: false }]);
  const recs2 = [user("one"), boundary, summary("S1"), user("two"), boundary, summary("S2"), user("three"), said("ok")];
  const w2 = await contextWindow(boundedLines(chunksOf(jsonl(recs2))), "claude-code");
  assert.equal(w2.summary, "S2");
  assert.deepEqual(w2.messages, [{ role: "user", text: "three" }, { role: "assistant", text: "ok" }]);
  const w1 = await contextWindow(boundedLines(chunksOf(jsonl(recs2.slice(0, 4)))), "claude-code");
  assert.equal(w1.summary, "S1");
  assert.deepEqual(w1.messages, [{ role: "user", text: "two" }]);
  // (nothing of the provider's own fields survives)
  assert.ok(!JSON.stringify(w0).includes("usage") && !JSON.stringify(w0).includes("signature"));
});

test("row 1: Codex: compacted resets the window to its summary; messages, calls and outputs normalized", async () => {
  const item = (payload) => ({ type: "response_item", payload });
  const recs = [
    item({ type: "message", role: "user", content: [{ type: "input_text", text: "before" }] }),
    { type: "compacted", payload: { message: "SUM", replacement_history: [] } },
    item({ type: "message", role: "developer", content: [{ type: "input_text", text: "system stuff" }] }),
    item({ type: "message", role: "user", content: [{ type: "input_text", text: "q" }] }),
    item({ type: "reasoning", encrypted_content: "x", summary: [] }),
    item({ type: "function_call", name: "shell", call_id: "c1", arguments: '{"cmd":"pwd"}' }),
    item({ type: "function_call_output", call_id: "c1", output: "/tmp" }),
    item({ type: "custom_tool_call", name: "apply_patch", call_id: "c2", input: "*** patch" }),
    item({ type: "custom_tool_call_output", call_id: "c2", output: [{ type: "input_text", text: "done" }] }),
    item({ type: "message", role: "assistant", content: [{ type: "output_text", text: "a" }] }),
    { type: "event_msg", payload: { type: "token_count" } },
  ];
  const w = await contextWindow(boundedLines(chunksOf(jsonl(recs))), "codex");
  assert.equal(w.summary, "SUM");
  assert.deepEqual(w.messages, [
    { role: "user", text: "q" }, { role: "tool_call", name: "shell", call: "c1", input: '{"cmd":"pwd"}' }, { role: "tool_result", call: "c1", output: "/tmp", error: false },
    { role: "tool_call", name: "apply_patch", call: "c2", input: "*** patch" }, { role: "tool_result", call: "c2", output: "done", error: false }, { role: "assistant", text: "a" },
  ]);
  // (two compactions: the last wins)
  const w2 = await contextWindow(boundedLines(chunksOf(jsonl([...recs, { type: "compacted", payload: { message: "SUM2" } }, recs[3]]))), "codex");
  assert.equal(w2.summary, "SUM2");
  assert.deepEqual(w2.messages, [{ role: "user", text: "q" }]);
  // (garbage records are ignored, never fatal)
  assert.deepEqual(codexRecord(null).messages, []);
  assert.deepEqual(claudeRecord({ type: "user", message: { content: [{ type: "x" }] } }).messages, []);
});

// ---- row 2: the context's bound
const header = { agent: "a".repeat(26), provider: "codex", model: "m", at_ms: AT, seq: 1, marker: null };
const sizes = (r) => ({ total: r.bytes.length, lines: td.decode(r.bytes).split("\n").filter(Boolean) });

test("row 2: the final encoded bytes never pass the cap; around the threshold, truncation starts exactly when the lines pass the room", () => {
  const max = 64 * 1024;
  const room = max - HEADER_MAX - 1;
  // (one message whose line, with its newline, is exactly `room` bytes: kept whole; one byte less too; one more: cut)
  const base = lineLen({ role: "user", text: "" });
  for (const delta of [-1, 0, 1]) {
    const text = "x".repeat(room - base + delta);
    const r = buildContext(header, { summary: null, messages: [{ role: "user", text }], dropped: 0 }, { max });
    assert.ok(r.bytes.length <= max, `delta ${delta}: ${r.bytes.length}`);
    assert.equal(r.truncated.cut_message, delta > 0, `delta ${delta}`);
  }
  // (escape-heavy and multibyte text counted as encoded)
  const r = buildContext(header, { summary: "é\"\\\n".repeat(20000), messages: [{ role: "assistant", text: "𝄞\u0001".repeat(20000) }], dropped: 0 }, { max });
  assert.ok(r.bytes.length <= max);
  assert.ok(td.decode(r.bytes).split("\n").filter(Boolean).every((l) => { JSON.parse(l); return true; }), "every line is valid JSON");
});
function lineLen(v) { return te.encode(JSON.stringify(Object.fromEntries(Object.entries(v).sort()))).length + 1; }

test("row 2: truncation order: whole messages oldest first (a call with its result), then one message, then the summary", () => {
  const max = 32 * 1024;
  // (a call and its result are dropped together, never split)
  const big = "y".repeat(12000);
  const w = { summary: "s", dropped: 0, messages: [
    { role: "tool_call", name: "t", call: "c", input: big }, { role: "tool_result", call: "c", output: big, error: false },
    { role: "user", text: big }, { role: "assistant", text: "last" },
  ] };
  const r = buildContext(header, w, { max });
  const lines = sizes(r).lines.map((l) => JSON.parse(l));
  assert.ok(!lines.some((l) => l.role === "tool_call") || lines.some((l) => l.role === "tool_result"), "never a call without its result");
  assert.ok(lines.at(-1).text === "last");
  assert.ok(lines[0].truncated.messages >= 2);
  // (no summary, one oversized message: cut, head and tail kept)
  const one = buildContext(header, { summary: null, dropped: 0, messages: [{ role: "tool_result", call: "c", output: "H" + "z".repeat(200000) + "T", error: false }] }, { max });
  const ol = sizes(one).lines.map((l) => JSON.parse(l));
  assert.equal(ol[0].truncated.cut_message, true);
  assert.ok(ol[1].output.startsWith("H") && ol[1].output.endsWith("T") && ol[1].output.includes("characters cut"));
  // (the header and the summary alone over the cap: the summary is cut)
  const s = buildContext(header, { summary: "S" + "q".repeat(100000), dropped: 0, messages: [{ role: "user", text: "u" }] }, { max });
  const sl = sizes(s).lines.map((l) => JSON.parse(l));
  assert.equal(sl[0].truncated.cut_summary, true);
  assert.ok(s.bytes.length <= max);
  // (a skipped record after the marker: the header says incomplete)
  const inc = buildContext(header, { summary: "s", dropped: 0, messages: [], skipped: 1, summarySkipped: true });
  assert.deepEqual(contextHeader(inc.bytes).incomplete, { skipped: 1, summary_skipped: true });
});

test("row 2: at the real CONTEXT_MAX: an 8 MiB tool result plus a summary stays within the cap", () => {
  const r = buildContext(header, { summary: "s", dropped: 0, messages: [{ role: "tool_result", call: "c", output: "w".repeat(CONTEXT_MAX), error: false }] });
  assert.ok(r.bytes.length <= CONTEXT_MAX);
  assert.equal(r.truncated.cut_message, true);
});

// ---- row 3: turns
test("row 3: one turn published, then a lost acknowledgement at every write: the exact bytes, each line once", async () => {
  // (the reference: published with no faults)
  const ref = fakeStore();
  const e = entryOf("t1", ["one", "two", "three"]);
  assert.deepEqual(await publishTurn(ref, e), { state: "done", seq: 1 });
  const want = (await allLines(ref)).map((l) => td.decode(l.bytes));
  // (each write's acknowledgement lost, one at a time, then retried with the same entry)
  for (let k = 1; k <= 4; k++) {
    let w = 0;
    const s = fakeStore({ lose: () => ++w === k });
    const r = await until(() => publishTurn(s, e));
    assert.equal(r.state, "done");
    assert.deepEqual((await allLines(s)).map((l) => td.decode(l.bytes)), want, `lost ack at write ${k}`);
  }
});

test("row 3: the same turn id with different content is a mismatch, never counted as saved", async () => {
  const e = entryOf("t1", ["a", "b"]);
  const changed = entryOf("t1", ["A", "b"]);
  // (a FINISHED turn is done, whatever is asked again under its id)
  const done = fakeStore();
  assert.equal((await publishTurn(done, e)).state, "done");
  assert.deepEqual(await publishTurn(done, changed), { state: "done", seq: 1 });
  // (an UNFINISHED turn whose published line differs from the journal's: mismatch, nothing written)
  const half = fakeStore();
  await publishTurnPartial(half, e, 2);
  const before = half.writes;
  assert.deepEqual(await publishTurn(half, changed), { state: "mismatch", i: 1 });
  assert.equal(half.writes, before);
  // (and the right journal finishes it)
  assert.deepEqual(await publishTurn(half, e), { state: "done", seq: 1 });
});
/** Publish only the first `k` lines of a turn (start + k-1 content), as a writer that died mid-turn would leave it. */
async function publishTurnPartial(store, entry, k) {
  const { startLine, frame } = await import("../lib/agent-log/index.mjs");
  await store.create(segmentPath(1), new Uint8Array(0));
  const cur = await store.read(segmentPath(1));
  const lines = [startLine(entry.turn, 1, entry.at_ms), ...entry.lines.slice(0, k - 1)];
  await store.cas(segmentPath(1), frame(lines), cur.rev);
}

test("row 3: two writers offline for the same slot reconnect together: distinct seqs, each turn contiguous", async () => {
  const eA = entryOf("tA", ["a1", "a2"]), eB = entryOf("tB", ["b1", "b2"]);
  let fired = false;
  const s = fakeStore({ before: async (p, op) => { if (!fired && op === "cas") { fired = true; await publishTurn(s, eB); } } });
  const rA = await publishTurn(s, eA);
  const rB = await publishTurn(s, eB);
  assert.deepEqual(rB, { state: "done", seq: 1 });
  assert.deepEqual(rA, { state: "done", seq: 2 });
  const turns = (await allLines(s)).map((l) => l.value.turn);
  assert.deepEqual(turns, ["tB", "tB", "tB", "tB", "tA", "tA", "tA", "tA"], "B's turn whole, then A's");
});

test("row 3: a stalled turn: no abort before STALL_MS, progress defeats it, then an exact aborted marker and a re-send", async () => {
  const s = fakeStore();
  const eA = entryOf("tA", ["a1", "a2", "a3"]);
  await publishTurnPartial(s, eA, 2);
  const eB = entryOf("tB", ["b1"]);
  assert.equal((await publishTurn(s, eB)).state, "blocked");
  const seen = await observeTail(s);
  assert.equal(seen.turn, "tA");
  // (9:59.999 on the observer's monotonic clock: wait)
  assert.equal((await abortStalled(s, seen, 1000, 1000 + STALL_MS - 1)).state, "wait");
  // (the stalled writer makes progress: the revision moved, so the abort is refused)
  const cur = await s.read(segmentPath(1));
  const { frame } = await import("../lib/agent-log/index.mjs");
  await s.cas(segmentPath(1), concat(cur.bytes, frame([eA.lines[1]])), cur.rev);
  assert.equal((await abortStalled(s, seen, 1000, 1000 + STALL_MS)).state, "moved");
  // (then a new observation, unchanged for STALL_MS: aborted, with the turn's seq and its content lines' count)
  const seen2 = await observeTail(s);
  assert.equal((await abortStalled(s, seen2, 5000, 5000 + STALL_MS)).state, "aborted");
  const last = (await allLines(s)).at(-1).value;
  assert.equal(last.aborted, true);
  assert.equal(last.seq, 1);
  assert.equal(last.lines, 2);
  // (the next turn takes seq + 1; the stalled writer's retry learns it was aborted)
  assert.deepEqual(await publishTurn(s, eB), { state: "done", seq: 2 });
  assert.deepEqual(await publishTurn(s, eA), { state: "aborted" });
  // (it re-sends as a new turn, linked)
  const again = { ...entryOf("tA2", ["a1", "a2", "a3"]), retry_of: "tA" };
  assert.deepEqual(await publishTurn(s, again), { state: "done", seq: 3 });
  assert.equal((await allLines(s)).find((l) => l.value.turn === "tA2" && l.value.start).value.retry_of, "tA");
});
function concat(a, b) { const o = new Uint8Array(a.length + b.length); o.set(a); o.set(b, a.length); return o; }

test("row 3: the intent is recorded before the allocating write; the scan is bounded by the anchor, never by time", async () => {
  const s = fakeStore();
  const intents = [];
  const e = { ...entryOf("t1", ["x"]), onIntent: async (i) => { intents.push({ ...i, writesBefore: s.writes }); } };
  await publishTurn(s, e);
  assert.equal(intents.length, 1);
  assert.equal(intents[0].seq, 1);
  // (a week-late upload whose at_ms is far in the past still finds its place after the anchor)
  for (let k = 2; k <= 4; k++) await publishTurn(s, entryOf(`t${k}`, ["y"]));
  const anchor = await anchorNow(s);
  const late = entryOf("tLate", ["z"], AT - 7 * 86400000, anchor);
  assert.deepEqual(await publishTurn(s, late), { state: "done", seq: 5 });
  assert.deepEqual(await publishTurn(s, late), { state: "done", seq: 5 }, "found again by id, after its anchor");
});

// ---- row 4: the context's sequence
test("row 4: contexts move only forward; an older one is stale; the same one again (a lost ack) is done", async () => {
  const s = fakeStore();
  const ctx = (seq, extra = "") => buildContext({ ...header, seq }, { summary: "s" + extra, messages: [], dropped: 0 }).bytes;
  assert.deepEqual(await publishContext(s, ctx(2), 2), { state: "done" });
  assert.deepEqual(await publishContext(s, ctx(1), 1), { state: "stale" });
  assert.deepEqual(await publishContext(s, ctx(2), 2), { state: "done" });
  assert.deepEqual(await publishContext(s, ctx(2, "other"), 2), { state: "stale" });
  assert.deepEqual(await publishContext(s, ctx(3), 3), { state: "done" });
  assert.equal(contextHeader((await s.read("context.jsonl")).bytes).seq, 3);
});

// ---- row 5: segments
test("row 5: no segment ever passes SEGMENT_MAX; a full segment is closed with a verified footer, and a turn continues in the next", async () => {
  const s = fakeStore();
  // (turns of escape-heavy and multibyte lines, about 2.5 MiB in all)
  for (let k = 0; k < 40; k++) await publishTurn(s, entryOf(`t${k}`, Array.from({ length: 4 }, (_, j) => `"é𝄞\\${k}-${j}`.repeat(1500))));
  const ns = (await s.list("transcript/")).length;
  assert.ok(ns >= 3, `${ns} segments`);
  for (const p of await s.list("transcript/")) {
    const b = (await s.read(p)).bytes;
    assert.ok(b.length <= SEGMENT_MAX, `${p}: ${b.length}`);
    const seg = await parseSegment(b);
    if (seg.closed) assert.equal(seg.footerOk, true, p);
  }
  // (every turn's lines are contiguous and once)
  const lines = await allLines(s);
  const seqs = lines.filter((l) => l.value.end).map((l) => l.value.seq);
  assert.deepEqual(seqs, Array.from({ length: 40 }, (_, k) => k + 1));
});

test("row 5: a text over LINE_MAX is split into parts at UTF-8 boundaries, each line within LINE_MAX, nothing lost", () => {
  const text = "𝄞é".repeat(40000) + "end";
  const lines = turnLines("t", AT, [{ role: "assistant", text }]);
  assert.ok(lines.length > 1);
  for (const l of lines) assert.ok(l.length + 1 <= LINE_MAX);
  const parts = lines.map((l) => JSON.parse(td.decode(l)));
  assert.deepEqual(parts.map((p) => p.part), parts.map((_, k) => k + 1));
  assert.equal(parts.map((p) => p.text).join(""), text);
});

test("row 5: a lost footer acknowledgement gives one footer; a new month's first turn starts a new segment", async () => {
  let losing = true;
  const s = fakeStore({ lose: (p) => losing && p === segmentPath(1) && s.files.get(p).bytes.length > SEGMENT_MAX - 2 * FOOTER_MAX - LINE_MAX });
  for (let k = 0; k < 80 && (await s.list("transcript/")).length < 2; k++) await until(() => publishTurn(s, entryOf(`t${k}`, ["x".repeat(30000)])));
  losing = false;
  const raw = td.decode((await s.read(segmentPath(1))).bytes);
  assert.equal(raw.split("\n").filter((l) => l.includes('"closed":true')).length, 1, "exactly one footer");
  const seg1 = await parseSegment((await s.read(segmentPath(1))).bytes);
  assert.equal(seg1.closed, true);
  assert.equal(seg1.footerOk, true);
  assert.ok((await s.list("transcript/")).length === 2, "one successor");
  // (the month)
  const m = fakeStore();
  await publishTurn(m, entryOf("nov", ["a"], Date.UTC(2026, 10, 30)));
  await publishTurn(m, entryOf("dec", ["b"], Date.UTC(2026, 11, 1)));
  assert.equal((await m.list("transcript/")).length, 2);
  const first = await parseSegment((await m.read(segmentPath(1))).bytes);
  assert.equal(first.closed, true);
});

// ---- row 6: no tool output in the transcript
test("row 6: a tool's output never enters the transcript: its call is one line with its outcome", () => {
  const SENTINEL = "SECRET-OUTPUT-SENTINEL";
  const lines = turnLines("t", AT, [
    { role: "tool_call", name: "Bash", call: "c", input: "cat /etc/passwd" },
    { role: "tool_result", call: "c", output: `${SENTINEL} ${"x".repeat(1000)}`, error: false },
    { role: "tool_call", name: "Bash", call: "d", input: "false" },
    { role: "tool_result", call: "d", output: SENTINEL, error: true },
  ]);
  const all = lines.map((l) => td.decode(l)).join("\n");
  assert.ok(!all.includes(SENTINEL));
  const v = lines.map((l) => JSON.parse(td.decode(l)));
  assert.deepEqual(v.map((x) => x.summary), ["cat /etc/passwd → ok", "false → error"]);
});

// ---- row 11: the input's bound
test("row 11: a huge raw line is discarded as it streams, with the peak held at most the cap plus one chunk", async () => {
  const max = 1024 * 1024, chunk = 64 * 1024;
  async function* gen() {
    yield te.encode('{"type":"user","message":{"role":"user","content":"a"}}\n');
    // (a 64 MiB line, streamed)
    for (let k = 0; k < 1024; k++) yield new Uint8Array(chunk).fill(120);
    yield te.encode("\n");
    yield te.encode('{"type":"user","message":{"role":"user","content":"b"}}\n');
  }
  const stats = {};
  const seen = [];
  for await (const x of boundedLines(gen(), { max, stats })) seen.push(x.skipped !== undefined ? `skip ${x.skipped}` : td.decode(x.line).slice(0, 10));
  assert.deepEqual(seen, ['{"type":"u', `skip ${64 * 1024 * 1024}`, '{"type":"u']);
  assert.ok(stats.peak <= max + chunk, `peak ${stats.peak}`);
  // (skipped after a compaction marker: the window says the summary may be missing, and the context is incomplete)
  async function* afterBoundary() {
    yield te.encode(JSON.stringify({ type: "system", subtype: "compact_boundary" }) + "\n");
    for (let k = 0; k < 20; k++) yield new Uint8Array(chunk).fill(121);
    yield te.encode("\n" + JSON.stringify({ type: "user", message: { role: "user", content: "after" } }) + "\n");
  }
  const w = await contextWindow(boundedLines(afterBoundary(), { max }), "claude-code");
  assert.equal(w.skipped, 1);
  assert.equal(w.summarySkipped, true);
  assert.deepEqual(contextHeader(buildContext(header, w).bytes).incomplete, { skipped: 1, summary_skipped: true });
});

// ---- row 12: the journal
test("row 12: the journal counts as it goes: a turn over the cap keeps a prefix and a gap line; when full, turns are missed visibly", () => {
  const j = new Journal({ max: 1024 * 1024, contextReserve: 128 * 1024 });
  const big = encodeLine({ turn: "t", i: 1, at_ms: AT, role: "assistant", text: "x".repeat(60000) });
  assert.equal(j.begin("t", AT).ok, true);
  let kept = 0, omitted = 0;
  for (let k = 0; k < 40; k++) (j.add(big) ? kept++ : omitted++);
  const t = j.finish();
  assert.ok(kept > 0 && omitted > 0);
  const gap = JSON.parse(td.decode(t.lines.at(-1)));
  assert.deepEqual([gap.gap, gap.omitted_lines], [true, omitted]);
  assert.ok(j.used + 2 * LINE_MAX + 128 * 1024 <= 1024 * 1024 + LINE_MAX, `within the cap with its reserves: ${j.used}`);
  // (full: the next turns are missed, then the first one journaled after carries the gap)
  assert.equal(j.begin("m1", AT + 1).ok, false);
  assert.equal(j.begin("m2", AT + 2).ok, false);
  j.retireTurn("t");
  const b = j.begin("next", AT + 3);
  assert.deepEqual(b, { ok: true, first: 2 });
  const g = JSON.parse(td.decode(j.open.lines[0]));
  assert.deepEqual([g.gap, g.turns, g.from_ms, g.to_ms], [true, 2, AT + 1, AT + 2]);
});

test("row 12: retirement: a turn only by its own marker; the context slot by any newer acknowledgement; the state survives a restart", () => {
  const j = new Journal({ max: 4 * 1024 * 1024, contextReserve: 64 * 1024 });
  j.begin("a", AT); j.add(encodeLine({ turn: "a", i: 1, role: "user", text: "x" })); j.finish();
  j.begin("b", AT); j.add(encodeLine({ turn: "b", i: 1, role: "user", text: "y" })); j.finish();
  j.setContext(1, te.encode("c1"));
  assert.equal(j.setContext(2, te.encode("c2")), true);
  assert.equal(j.setContext(1, te.encode("old")), false, "an older context never replaces a newer one");
  j.ackContext(1);
  assert.equal(j.context.seq, 2, "an older ack doesn't retire the newer slot");
  j.ackContext(3);
  assert.equal(j.context, null);
  assert.deepEqual(j.pending().map((t) => t.turn), ["a", "b"], "no context ever retires a turn's lines");
  j.retireTurn("a");
  const k = Journal.from(JSON.parse(JSON.stringify(j.state())));
  assert.deepEqual(k.pending().map((t) => t.turn), ["b"]);
  assert.deepEqual(k.pending()[0].lines, j.pending()[0].lines);
});

test("row 12: repeated offline drain, crash and restart: every turn once and in order, only the newest context", async () => {
  const j = new Journal({ max: 4 * 1024 * 1024, contextReserve: 64 * 1024 });
  for (let k = 1; k <= 20; k++) {
    const r = j.begin(`t${k}`, AT + k);
    for (const l of turnLines(`t${k}`, AT + k, [{ role: "user", text: `turn ${k}` }], r.first)) j.add(l);
    j.finish();
    j.setContext(k, te.encode(`ctx ${k}`));
  }
  const s = fakeStore();
  // (a crash after each of the first 5 publications: the journal state reloaded each time)
  let state = j.state();
  for (let crash = 0; crash < 6; crash++) {
    const jj = Journal.from(JSON.parse(JSON.stringify(state)));
    for (const t of jj.pending()) {
      const r = await publishTurn(s, { turn: t.turn, at_ms: t.at_ms, lines: t.lines, anchor: null });
      assert.equal(r.state, "done");
      jj.retireTurn(t.turn);
      if (crash < 5) break;
    }
    state = jj.state();
  }
  const ends = (await allLines(s)).filter((l) => l.value.end);
  assert.deepEqual(ends.map((l) => l.value.turn), Array.from({ length: 20 }, (_, k) => `t${k + 1}`));
  assert.deepEqual(ends.map((l) => l.value.seq), Array.from({ length: 20 }, (_, k) => k + 1));
  assert.equal(Journal.from(state).context.seq, 20, "only the newest context is pending");
});

// ---- exact boundaries and the contracts a mutant run showed unpinned
test("row 11: the reader's cap is exact: a line of exactly max bytes is kept, max + 1 is skipped", async () => {
  const max = 1000;
  const items = [];
  for await (const x of boundedLines(chunksOf("a".repeat(max) + "\n" + "b".repeat(max + 1) + "\n", 300), { max })) items.push(x.line ? x.line.length : `skip ${x.skipped}`);
  assert.deepEqual(items, [max, `skip ${max + 1}`]);
});

test("row 2: the window's budget drops a tool call with its result, never the call alone", async () => {
  const recs = [
    { type: "assistant", message: { role: "assistant", content: [{ type: "tool_use", id: "c", name: "Bash", input: { command: "x".repeat(500) } }] } },
    { type: "user", message: { role: "user", content: [{ type: "tool_result", tool_use_id: "c", content: "y".repeat(500) }] } },
    { type: "user", message: { role: "user", content: "keep" } },
  ];
  const w = await contextWindow(boundedLines(chunksOf(jsonl(recs))), "claude-code", { budget: 600 });
  assert.deepEqual(w.messages, [{ role: "user", text: "keep" }]);
  assert.equal(w.dropped, 2);
});

test("row 2: the header's model is held to MODEL_MAX bytes", () => {
  const r = buildContext({ ...header, model: "é".repeat(200) }, { summary: null, messages: [], dropped: 0 });
  assert.ok(te.encode(contextHeader(r.bytes).model).length <= 128);
});

test("row 5: a line fits only with the footer's room kept: exactly at the edge, and one byte over", async () => {
  const { fits } = await import("../lib/agent-log/index.mjs");
  const line = new Uint8Array(100);
  assert.equal(fits(SEGMENT_MAX - FOOTER_MAX - 101, line), true);
  assert.equal(fits(SEGMENT_MAX - FOOTER_MAX - 100, line), false);
});

test("row 5: a footer is checked against the bytes before it, never trusted", async () => {
  const s = fakeStore();
  for (let k = 0; k < 80 && (await s.list("transcript/")).length < 2; k++) await publishTurn(s, entryOf(`t${k}`, ["x".repeat(30000)]));
  const b = (await s.read(segmentPath(1))).bytes.slice();
  assert.equal((await parseSegment(b)).footerOk, true);
  b[10] ^= 1;
  assert.equal((await parseSegment(b)).footerOk, false, "a changed byte before the footer");
});

test("row 3: a turn left half-published is finished with each line exactly once", async () => {
  const s = fakeStore();
  const e = entryOf("t1", ["a", "b", "c"]);
  await publishTurnPartial(s, e, 2);
  assert.deepEqual(await publishTurn(s, e), { state: "done", seq: 1 });
  const is = (await allLines(s)).filter((l) => l.value.turn === "t1").map((l) => l.value.i);
  assert.deepEqual(is, [0, 1, 2, 3, 4]);
});

test("row 12: once a line of a turn is omitted, every later one is too (the kept part is a prefix)", () => {
  const j = new Journal({ max: 1024 * 1024, contextReserve: 128 * 1024 });
  j.begin("t", AT);
  const big = encodeLine({ turn: "t", i: 1, role: "user", text: "x".repeat(60000) });
  while (j.add(big)) { /* fill */ }
  assert.equal(j.add(encodeLine({ turn: "t", i: 99, role: "user", text: "tiny" })), false);
});
