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
/** The journal's durable bytes: the UTF-8 length of its serialized state. */
const durable = (j) => te.encode(JSON.stringify(j.state())).length;
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
  const one = buildContext(header, { summary: null, dropped: 0, messages: [{ role: "tool_call", name: "t", call: "c", input: "i" }, { role: "tool_result", call: "c", output: "H" + "z".repeat(200000) + "T", error: false }] }, { max });
  const ol = sizes(one).lines.map((l) => JSON.parse(l));
  assert.equal(ol[0].truncated.cut_message, true);
  assert.ok(ol[2].output.startsWith("H") && ol[2].output.endsWith("T") && ol[2].output.includes("characters cut"));
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
  const r = buildContext(header, { summary: "s", dropped: 0, messages: [{ role: "tool_call", name: "t", call: "c", input: "i" }, { role: "tool_result", call: "c", output: "w".repeat(CONTEXT_MAX), error: false }] });
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
  // (a FINISHED turn is done only for its own journal: the same id with other content is a mismatch (TESTS T1))
  const done = fakeStore();
  assert.equal((await publishTurn(done, e)).state, "done");
  assert.deepEqual(await publishTurn(done, e), { state: "done", seq: 1 });
  assert.equal((await publishTurn(done, changed)).state, "mismatch");
  assert.equal((await publishTurn(done, { ...e, lines: e.lines.slice(0, 1) })).state, "mismatch", "a journal with fewer lines");
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
  assert.ok(j.used <= 1024 * 1024, `within the cap: ${j.used}`);
  assert.equal(j.used, durable(j), "used is the durable bytes, exactly");
  // (full: the next turns are missed, then the first one journaled after carries the gap)
  let fill = 0;
  while (j.begin(`e${fill}`, AT).ok) { j.finish(); fill++; }
  assert.equal(j.begin("m2", AT + 2).ok, false);
  for (let k = 0; k < fill; k++) j.retireTurn(`e${k}`);
  j.retireTurn("t");
  const b = j.begin("next", AT + 3);
  assert.deepEqual(b, { ok: true, first: 2 });
  const g = JSON.parse(td.decode(j.open.lines[0]));
  assert.deepEqual([g.gap, g.turns, g.from_ms, g.to_ms], [true, 2, AT, AT + 2]);
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

// ---- LIMITS H1-H3 and TESTS T1-T3 on the first head: independent measurements and the controls they asked for
import v8 from "node:v8";
import vm from "node:vm";
v8.setFlagsFromString("--expose-gc");
const gc = vm.runInNewContext("gc");
const arrayBuffers = () => { gc(); gc(); return process.memoryUsage().arrayBuffers; };

test("LIMITS H1: a 16 MiB line in reused 1 MiB chunks: the ArrayBuffers actually live stay within the cap plus one chunk", async () => {
  const { RAW_LINE_MAX } = await import("../lib/agent-log/index.mjs");
  const chunk = new Uint8Array(1024 * 1024).fill(120);
  const base = arrayBuffers();
  let peak = 0;
  async function* gen() {
    for (let k = 0; k < 16; k++) { peak = Math.max(peak, arrayBuffers() - base); yield chunk; }
    yield te.encode("\n");
  }
  let len = 0;
  for await (const x of boundedLines(gen(), { max: RAW_LINE_MAX })) { peak = Math.max(peak, arrayBuffers() - base); len = x.line?.length ?? -1; }
  assert.equal(len, RAW_LINE_MAX, "the line of exactly the cap is kept");
  assert.ok(peak <= RAW_LINE_MAX + chunk.length, `live ArrayBuffers ${peak} > ${RAW_LINE_MAX + chunk.length}`);
});

test("LIMITS H2: every field is charged (call ids included), the budget is validated, and the newest message is never evicted", async () => {
  const { WINDOW_BUDGET, messageCost } = await import("../lib/agent-log/index.mjs");
  const item = (payload) => ({ type: "response_item", payload });
  const recs = [];
  for (let k = 0; k < 30; k++) recs.push(item({ type: "function_call", name: "f", call_id: `${k}`.padEnd(100000, "x"), arguments: "" }), item({ type: "function_call_output", call_id: `${k}`.padEnd(100000, "x"), output: "" }));
  const w = await contextWindow(boundedLines(chunksOf(jsonl(recs), 65536)), "codex", { budget: 1024 });
  assert.ok(w.messages.length <= 2, `${w.messages.length} kept`);
  assert.ok(w.held <= 1024 + w.messages.reduce((a, m) => a + messageCost(m), 0), `held ${w.held}`);
  assert.ok(w.messages.length === 0 || w.messages.every((m) => m.role !== "tool_result" || w.messages.some((c) => c.role === "tool_call" && c.call === m.call)), "never a result without its call");
  for (const b of [0, -1, 1.5, 8 * CONTEXT_MAX + 1]) await assert.rejects(contextWindow(boundedLines(chunksOf("")), "codex", { budget: b }), RangeError);
  // (the default bounds a long stream with no compaction: 40 messages of 1 MiB)
  async function* long() { for (let k = 0; k < 40; k++) yield te.encode(JSON.stringify({ type: "user", message: { role: "user", content: "é".repeat(512 * 1024) } }) + "\n"); }
  const d = await contextWindow(boundedLines(long()), "claude-code");
  assert.ok(d.held <= WINDOW_BUDGET + messageCost(d.messages.at(-1)), `held ${d.held}`);
  assert.ok(d.dropped > 0);
  // (one oversized result is kept whole by the window; the context's truncation cuts it)
  const big = await contextWindow(boundedLines(chunksOf(jsonl([
    { type: "assistant", message: { role: "assistant", content: [{ type: "tool_use", id: "c", name: "Bash", input: {} }] } },
    { type: "user", message: { role: "user", content: [{ type: "tool_result", tool_use_id: "c", content: "z".repeat(9 * 1024 * 1024) }] } },
  ]), 1 << 20)), "claude-code", { budget: 1024 });
  assert.equal(big.messages.at(-1).output.length, 9 * 1024 * 1024, "the newest result whole in the window");
  const ctx = buildContext(header, big);
  assert.ok(ctx.bytes.length <= CONTEXT_MAX && ctx.truncated.cut_message);
});

test("LIMITS H3: the journal's used is its durable bytes exactly; empty turns, intents and contexts are all counted and capped", () => {
  const j = new Journal({ max: 262144, contextReserve: 0 });
  let ok = 0, missed = 0;
  for (let k = 0; k < 5000; k++) { const r = j.begin(`t${k}`, AT + k); if (r.ok) { j.finish(); ok++; } else missed++; }
  assert.ok(missed > 0, "empty turns fill it: their metadata counts");
  assert.equal(j.used, durable(j));
  assert.ok(j.used <= 262144);
  // (an intent comes from its reserve, and stays within the cap)
  j.intend("t0", { seq: 1, anchor: { n: 1, seq: 0 } });
  assert.equal(j.used, durable(j));
  assert.ok(j.used <= 262144);
  // (a context over its reserve is refused)
  const c = new Journal({ max: 262144, contextReserve: 1000 });
  assert.equal(c.setContext(1, new Uint8Array(1001)), false);
  assert.equal(c.setContext(1, new Uint8Array(1000)), true);
  assert.equal(c.used, durable(c));
  // (a restored state over its cap is refused)
  const s = c.state();
  assert.throws(() => Journal.from({ ...s, max: 100 }));
  // (the room is exact: a line whose cost is the room fits; the next base64 step doesn't)
  const r = new Journal({ max: 65536, contextReserve: 0 });
  r.begin("t", AT);
  const room = r.room();
  const n = Math.floor((room - 1 - 2) / 4) * 3;
  const fitsLine = new Uint8Array(n), over = new Uint8Array(n + 3);
  assert.equal(r.add(over), false, "one base64 step over the room");
  const r2 = new Journal({ max: 65536, contextReserve: 0 });
  r2.begin("t", AT);
  assert.equal(r2.add(fitsLine), true, "exactly within the room");
  assert.equal(r2.used, durable(r2));
});

test("LIMITS H3: a turn over 64 MiB, streamed from its records into the journal: a prefix, a gap line, the cap held", async () => {
  const { turnLinesFromRecords } = await import("../lib/agent-log/index.mjs");
  const text = "w".repeat(60000);
  async function* records() { for (let k = 0; k < 1200; k++) yield te.encode(JSON.stringify({ type: "assistant", message: { role: "assistant", content: [{ type: "text", text }] } }) + "\n"); }
  const j = new Journal();
  const b = j.begin("big", AT);
  let kept = 0, omitted = 0;
  for await (const l of turnLinesFromRecords("big", AT, "claude-code", boundedLines(records()), b.first)) (j.add(l) ? kept++ : omitted++);
  const t = j.finish();
  assert.equal(kept + omitted, 1200);
  assert.ok(omitted > 0 && kept > 0);
  assert.equal(JSON.parse(td.decode(t.lines.at(-1))).omitted_lines, omitted);
  assert.ok(j.used <= j.max);
});

test("TESTS T2: a call and its result pair by id, not by position: crossed calls, in the window and in the context's truncation", async () => {
  const A = { role: "tool_call", name: "a", call: "A", input: "x".repeat(CONTEXT_MAX) }, Bc = { role: "tool_call", name: "b", call: "B", input: "b" };
  const Ar = { role: "tool_result", call: "A", output: "ar", error: false }, Br = { role: "tool_result", call: "B", output: "br", error: false };
  const ctx = buildContext(header, { summary: "s", dropped: 0, messages: [A, Bc, Ar, Br] });
  const kept = td.decode(ctx.bytes).split("\n").filter(Boolean).slice(1).map((l) => JSON.parse(l));
  assert.ok(!kept.some((m) => m.role === "tool_result" && m.call === "A"), "A's result went with A's call");
  assert.ok(kept.some((m) => m.call === "B" && m.role === "tool_call") && kept.some((m) => m.call === "B" && m.role === "tool_result"));
  // (the window: A's result arriving after its call was evicted is dropped on arrival)
  const recs = [
    { type: "assistant", message: { role: "assistant", content: [{ type: "tool_use", id: "A", name: "a", input: { big: "x".repeat(3000) } }] } },
    { type: "assistant", message: { role: "assistant", content: [{ type: "tool_use", id: "B", name: "b", input: {} }] } },
    { type: "user", message: { role: "user", content: [{ type: "tool_result", tool_use_id: "A", content: "ar" }] } },
    { type: "user", message: { role: "user", content: [{ type: "tool_result", tool_use_id: "B", content: "br" }] } },
  ];
  const w = await contextWindow(boundedLines(chunksOf(jsonl(recs), 4096)), "claude-code", { budget: 1000 });
  assert.ok(!w.messages.some((m) => m.call === "A"), "nothing of A remains");
  assert.deepEqual(w.messages.map((m) => `${m.role}:${m.call}`), ["tool_call:B", "tool_result:B"]);
});

test("TESTS T3: the intent completes before the allocating write; the scan reads nothing before the anchor; the aborted marker's digest is the lines'", async () => {
  // (the intent: awaited, and only then the compare-and-set)
  const events = [];
  const s = fakeStore({ before: async (p, op) => { events.push(op); } });
  await publishTurn(s, { ...entryOf("t1", ["x"]), onIntent: async () => { await new Promise((r) => setTimeout(r, 20)); events.push("intent"); } });
  assert.ok(events.indexOf("intent") >= 0 && events.indexOf("intent") < events.indexOf("cas"), events.join());
  // (the anchor: many segments, and a late turn's publication reads none before its anchor's)
  const m = fakeStore();
  for (let k = 0; k < 60; k++) await publishTurn(m, entryOf(`f${k}`, ["y".repeat(60000)]));
  const segs = (await m.list("transcript/")).length;
  assert.ok(segs >= 3, `${segs} segments`);
  const anchor = await anchorNow(m);
  const reads = [];
  const realRead = m.read;
  m.read = async (p) => { reads.push(p); return realRead(p); };
  // (the FIRST publication scans back for the turn, finding nothing: no further than the anchor's segment)
  await publishTurn(m, entryOf("late", ["z"], AT, anchor));
  const nums = reads.filter((p) => p.startsWith("transcript/")).map((p) => Number(/(\d+)\.jsonl/.exec(p)[1]));
  assert.ok(nums.every((n) => n >= anchor.n), `read ${nums} before anchor ${anchor.n}`);
  // (the aborted marker: its sha256 and count, checked against an independent hash of exactly the lines present)
  const a = fakeStore();
  const eA = entryOf("tA", ["a1", "a2", "a3"]);
  await publishTurnPartial(a, eA, 3);
  const seen = await observeTail(a);
  assert.equal((await abortStalled(a, seen, 0, STALL_MS)).state, "aborted");
  const marker = (await allLines(a)).at(-1).value;
  const present = eA.lines.slice(0, 2);
  const framed = new Uint8Array(present.reduce((x, l) => x + l.length + 1, 0));
  let o = 0; for (const l of present) { framed.set(l, o); o += l.length; framed[o++] = 10; }
  const want = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", framed)), (x) => x.toString(16).padStart(2, "0")).join("");
  assert.deepEqual({ lines: marker.lines, sha256: marker.sha256, seq: marker.seq, i: marker.i }, { lines: 2, sha256: want, seq: 1, i: 3 });
});

// ---- the rows a mutant run at the fix head showed missing
test("H1: a whole line inside a chunk is yielded as a view of that chunk, never a copy", async () => {
  const chunk = te.encode("one\ntwo\nthree\n");
  async function* gen() { yield chunk; }
  for await (const x of boundedLines(gen())) assert.equal(x.line.buffer, chunk.buffer);
});

test("T2: evicting a call takes its result with it even when the result isn't the newest message", async () => {
  // (the call is the big one: evicting it alone brings the window within budget, so its small result would stay
  // behind as an orphan unless it goes with its call)
  const recs = [
    { type: "assistant", message: { role: "assistant", content: [{ type: "tool_use", id: "A", name: "a", input: { big: "x".repeat(2000) } }] } },
    { type: "user", message: { role: "user", content: [{ type: "tool_result", tool_use_id: "A", content: "r" }] } },
    { type: "user", message: { role: "user", content: "u".repeat(100) } },
    { type: "user", message: { role: "user", content: "last" } },
  ];
  const w = await contextWindow(boundedLines(chunksOf(jsonl(recs), 4096)), "claude-code", { budget: 1000 });
  assert.ok(!w.messages.some((m) => m.role === "tool_result" && !w.messages.some((c) => c.role === "tool_call" && c.call === m.call)), JSON.stringify(w.messages.map((m) => m.role)));
  assert.equal(w.messages.at(-1).text, "last");
});

test("T2: a result whose call isn't in the context is dropped even when everything fits", () => {
  const r = buildContext(header, { summary: "s", dropped: 0, messages: [{ role: "tool_result", call: "gone", output: "o", error: false }, { role: "user", text: "u" }] });
  const kept = td.decode(r.bytes).split("\n").filter(Boolean).slice(1).map((l) => JSON.parse(l));
  assert.deepEqual(kept.map((m) => m.role), ["summary", "user"]);
});

test("row 6: a tool line holds exactly its fields: never any output", () => {
  const [l] = turnLines("t", AT, [{ role: "tool_call", name: "Bash", call: "c", input: "ls" }, { role: "tool_result", call: "c", output: "o", error: false }]);
  assert.deepEqual(Object.keys(JSON.parse(td.decode(l))).sort(), ["at_ms", "i", "name", "role", "summary", "turn"]);
});

test("T1: a published finished turn with FEWER lines than the journal under its id is a mismatch", async () => {
  const s = fakeStore();
  assert.equal((await publishTurn(s, entryOf("t", ["a"]))).state, "done");
  const more = entryOf("t", ["a", "b"]);
  assert.equal((await publishTurn(s, more)).state, "mismatch");
});

test("H3: filled to the brim, the open turn still finishes with its gap line, and every pending intent fits, within the cap", () => {
  const j = new Journal({ max: 65536, contextReserve: 0 });
  const small = (k) => encodeLine({ turn: `t${k}`, i: 1, role: "user", text: "x".repeat(40) });
  let k = 0;
  for (;;) {
    const r = j.begin(`t${k}`, AT);
    if (!r.ok) break;
    // (at most 40 lines a turn, so several turns are pending when the brim is reached; the last one omits)
    for (let n = 0; n < 40 && j.add(small(k)); n++) { /* fill */ }
    j.finish();
    k++;
  }
  assert.ok(k > 1);
  assert.ok(j.used <= j.max, `${j.used}`);
  // (each pending turn's intent at its maximum size: exactly what its reserve holds)
  const intent = { seq: 9007199254740991, anchor: { n: 9007199254740991, seq: 9007199254740991 }, pad: "" };
  intent.pad = "p".repeat(256 - JSON.stringify(intent).length);
  assert.equal(JSON.stringify(intent).length, 256);
  for (const t of j.pending()) j.intend(t.turn, intent);
  assert.ok(j.used <= j.max, `with every intent: ${j.used}`);
  // (and, on top, a refused begin at the widest times: the missed record at its largest; every reserve used at once)
  assert.equal(j.begin("late", -Number.MAX_SAFE_INTEGER).ok, false);
  assert.equal(j.begin("late2", Number.MAX_SAFE_INTEGER).ok, false);
  assert.ok(j.used <= j.max, `with every intent and the widest missed record: ${j.used}`);
  assert.equal(j.used, durable(j));
});

// ---- LIMITS H3 at the second head: waiting calls bounded by bytes; the journal counts UTF-8 and checks its own floor
test("H3: waiting tool calls hold a fixed size each, whatever their ids: 257 calls with 256 KiB ids", async () => {
  const { turnLineStream, OPEN_CALLS_MAX } = await import("../lib/agent-log/index.mjs");
  // (the calls are made lazily, so the test itself holds none of them: what stays live is what the builder keeps)
  function* calls() { for (let k = 0; k < OPEN_CALLS_MAX + 1; k++) yield { role: "tool_call", name: "n".repeat(1000), call: `${k}`.padEnd(256 * 1024, "x"), input: "i" }; }
  gc(); gc();
  const before = process.memoryUsage().heapUsed;
  const it = turnLineStream("t", AT, calls());
  const first = it.next();
  gc(); gc();
  const delta = process.memoryUsage().heapUsed - before;
  assert.equal(JSON.parse(td.decode(first.value)).summary.endsWith("no result"), true, "the 257th call writes out the oldest");
  assert.ok(delta < 8 * 1024 * 1024, `heap held by 256 waiting calls: ${delta}`);
  const rest = [...it];
  assert.equal(rest.length, OPEN_CALLS_MAX);
  assert.ok(rest.every((l) => JSON.parse(td.decode(l)).name.length <= 64));
});

test("H3: the journal counts UTF-8 bytes, validates turn ids, and refuses a cap below its own floor", () => {
  const j = new Journal({ max: 65536, contextReserve: 0 });
  assert.equal(j.begin("é".repeat(50), AT).ok, true);
  j.add(encodeLine({ turn: "é", i: 1, role: "user", text: "é".repeat(100) }));
  j.finish();
  assert.equal(j.used, durable(j), "used is UTF-8 bytes, multibyte ids and lines included");
  assert.throws(() => new Journal({ max: 65536 }).begin("é".repeat(100), AT), RangeError, "an id over 128 bytes");
  assert.throws(() => new Journal({ max: 65536 }).begin("t", 1.5), RangeError);
  assert.throws(() => new Journal({ max: 100, contextReserve: 100 }), RangeError, "a cap smaller than its envelope and context reserve");
  // (at exactly its floor: a context of exactly the reserve fits, within the cap)
  let max = 1;
  for (;; max++) { try { new Journal({ max, contextReserve: 100 }); break; } catch { /* below the floor */ } }
  const f = new Journal({ max, contextReserve: 100 });
  assert.equal(f.setContext(1, new Uint8Array(100)), true);
  assert.ok(f.used <= f.max, `${f.used} <= ${f.max}`);
  assert.equal(f.used, durable(f));
  assert.equal(f.setContext(2, new Uint8Array(101)), false, "over the reserve");
});

test("H3: a restored state is checked against its cap, and setContext preflights against a state with no reserve room left", () => {
  const j = new Journal({ max: 65536, contextReserve: 100 });
  j.begin("t", AT);
  for (let k = 0; k < 20; k++) j.add(encodeLine({ turn: "t", i: k + 1, role: "user", text: "x".repeat(500) }));
  j.finish();
  const s = j.state();
  // (a cap above the floor but below this state's size: refused on restore)
  assert.throws(() => Journal.from({ ...s, max: j.used - 1 }), /over its cap/);
  // (within the cap but with no room left for a context: the context is refused, the state unchanged)
  const r = Journal.from({ ...s, max: j.used + 10 });
  assert.equal(r.setContext(1, new Uint8Array(100)), false);
  assert.equal(r.context, null);
  assert.ok(r.used <= r.max);
});

test("H3: at its exact floor with a full context, refused begins still fit: the missed-turn record is reserved", () => {
  let max = 1;
  for (;; max++) { try { new Journal({ max, contextReserve: 100 }); break; } catch { /* below the floor */ } }
  const j = new Journal({ max, contextReserve: 100 });
  assert.equal(j.setContext(Number.MAX_SAFE_INTEGER, new Uint8Array(100)), true);
  // (each refused begin, at the widest times, records itself as missed: never past the cap)
  for (const at of [Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0, Number.MAX_SAFE_INTEGER]) {
    assert.equal(j.begin("t", at).ok, false);
    assert.ok(j.used <= j.max, `${j.used} <= ${j.max}`);
    assert.equal(j.used, durable(j));
  }
  // (and a restore of that state is accepted, the same size)
  const r = Journal.from(JSON.parse(JSON.stringify(j.state())));
  assert.equal(r.used, j.used);
  // (control: a cap one byte below the floor is refused at construction)
  assert.throws(() => new Journal({ max: max - 1, contextReserve: 100 }), RangeError);
});

test("H3: the reserves are real: the widest missed record always, and the widest gap line while a turn is open", () => {
  const b64cost = (n) => 4 * Math.ceil(n / 3) + 3; // base64, quotes, separator
  const W = Number.MAX_SAFE_INTEGER, id = "t".repeat(128);
  // (the widest missed record, as JSON bytes beyond the "null" it replaces)
  const widestMissed = te.encode(JSON.stringify({ turns: W, from_ms: -W, to_ms: -W })).length - 4;
  // (the widest gap line a turn can end with: a 128-byte id, every number at its largest)
  const widestGap = Math.max(
    encodeLine({ turn: id, i: W, gap: true, omitted_lines: W, omitted_bytes: W }).length,
    encodeLine({ turn: id, i: 1, gap: true, turns: W, from_ms: -W, to_ms: -W }).length);
  assert.ok(widestGap <= 256, `the widest gap line, ${widestGap} bytes, fits GAP_MAX`);
  const j = new Journal({ max: 1 << 20, contextReserve: 0 });
  const r0 = j.reserved();
  assert.ok(r0 >= widestMissed, `held back at rest: ${r0} >= the widest missed record ${widestMissed}`);
  j.begin(id, AT);
  assert.ok(j.reserved() - r0 >= b64cost(widestGap), `an open turn holds back ${j.reserved() - r0} >= its widest gap line ${b64cost(widestGap)}`);
});

