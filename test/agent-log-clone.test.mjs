// Cloning an agent and the restore gap line (lib/agent-log; the transcript-and-context design note r0.8 §5, §6): row
// 8 and row 12's restore bullet, on the writer's fake store (checked creates, acknowledgements that can be lost after
// the write applied). Who may clone is the caller's and the service's, not this module's.
import assert from "node:assert/strict";
import { test } from "node:test";
import {
  CONTEXT_MAX, HEADER_MAX, LINE_MAX, bootstrapContext, buildContext, contextHeader, encodeLine, endLine, frame, missingTurns, newestNormalMarker,
  parseSegment, planClone, publishClone, publishContext, publishTurn, restoreGapLines, segmentPath, turnLines,
} from "../lib/agent-log/index.mjs";

const te = new TextEncoder(), td = new TextDecoder();
const AT = Date.UTC(2026, 10, 25, 12);
const SRC = "src-agent", CLONE = "clone-agent";
const hex = (k) => k.toString(16).padStart(32, "0");

/** The writer's store: checked creates and compare-and-sets; `lose(path, op)` loses an acknowledgement after applying. */
function fakeStore({ lose = () => false, readOnly = false } = {}) {
  const files = new Map();
  let rev = 0;
  const st = { files };
  const write = (p, bytes, op) => {
    if (readOnly) throw new Error(`a write to a read-only store: ${op} ${p}`);
    files.set(p, { bytes, rev: ++rev });
    if (lose(p, op)) throw new Error("the acknowledgement was lost");
    return { ok: true, rev };
  };
  st.list = async (prefix) => [...files.keys()].filter((p) => p.startsWith(prefix));
  st.read = async (p) => (files.has(p) ? { bytes: files.get(p).bytes, rev: files.get(p).rev } : null);
  st.cas = async (p, bytes, r) => { const f = files.get(p); if (!f || f.rev !== r) return { conflict: true }; return write(p, bytes, "cas"); };
  st.create = async (p, bytes) => (files.has(p) ? { exists: true } : write(p, bytes, "create"));
  st.snapshot = () => new Map([...files].map(([p, f]) => [p, f.bytes.slice()]));
  return st;
}
async function until(f) {
  for (let k = 0; k < 50; k++) { try { return await f(); } catch (e) { if (!/acknowledgement was lost/.test(e.message)) throw e; } }
  throw new Error("never done");
}

const contextOf = (agent, seq, text = "what the agent knows") =>
  buildContext({ agent, provider: "claude-code", model: "m", at_ms: AT, seq, marker: seq }, { summary: "the summary", dropped: 0, messages: [{ role: "user", text }, { role: "assistant", text: "ok" }] }).bytes;

/** A source with `turns` published turns and its context at `ctxSeq`. */
async function source(turns, ctxSeq) {
  const st = fakeStore();
  for (let k = 1; k <= turns; k++) {
    const r = await publishTurn(st, { turn: hex(k), at_ms: AT + k, anchor: null, lines: turnLines(hex(k), AT + k, [{ role: "assistant", text: `turn ${k}` }]) });
    assert.deepEqual(r, { state: "done", seq: k });
  }
  assert.equal((await publishContext(st, contextOf(SRC, ctxSeq), ctxSeq)).state, "done");
  return st;
}

/** A read-only view of a store: any write throws. */
const readOnly = (st) => ({ list: st.list, read: st.read, create: () => { throw new Error("the source was written"); }, cas: () => { throw new Error("the source was written"); } });

const lines = (bytes) => td.decode(bytes).split("\n").slice(0, -1);

// ---- row 8 ----

test("row 8: the bootstrap differs from the source's context only in line 1, in the clone's own sequence", async () => {
  const src = await source(100, 100);
  const before = src.snapshot();
  const plan = await planClone(readOnly(src), { clone: CLONE, from: SRC, name: "the clone", provider: "claude-code", at_ms: AT + 5000 });
  const srcCtx = (await src.read("context.jsonl")).bytes;
  const a = lines(srcCtx), b = lines(plan.context);
  assert.equal(a.length, b.length);
  assert.deepEqual(b.slice(1), a.slice(1), "every line but the first is the source's, byte for byte");
  const h = contextHeader(plan.context), s = contextHeader(srcCtx);
  assert.equal(h.agent, CLONE);
  assert.equal(h.seq, 0);
  assert.equal(h.at_ms, AT + 5000);
  assert.deepEqual(h.bootstrap, { cloned_from: { agent: SRC, context_seq: 100, marker_seq: 100 } });
  // (and nothing else of the header changed)
  const { agent: _a, seq: _s, at_ms: _t, bootstrap: _b, ...hRest } = h;
  const { agent: _a2, seq: _s2, at_ms: _t2, ...sRest } = s;
  assert.deepEqual(hRest, sRest);
  assert.deepEqual(src.snapshot(), before, "the source's files are byte-unchanged");
  assert.equal(plan.marker_seq, 100);
});

test("row 8: the clone's transcript is its pointer line, then its own turns from seq 1; nothing of the source is copied", async () => {
  const src = await source(100, 100);
  const before = src.snapshot();
  const cl = fakeStore();
  const plan = await planClone(readOnly(src), { clone: CLONE, from: SRC, name: "c", provider: "claude-code", at_ms: AT + 1 });
  assert.deepEqual(await publishClone(cl, plan), { state: "done" });
  assert.deepEqual([...cl.files.keys()].sort(), ["agent.json", "context.jsonl", "transcript/1.jsonl"]);
  const seg = await parseSegment((await cl.read(segmentPath(1))).bytes);
  assert.deepEqual(seg.lines.map((l) => l.value), [{ cloned_from: { agent: SRC, seq: 100 } }]);
  assert.deepEqual(JSON.parse(td.decode((await cl.read("agent.json")).bytes)), { v: 1, agent: CLONE, name: "c", provider: "claude-code", created: AT + 1, cloned_from: { agent: SRC, seq: 100 } });

  // (its first turn is seq 1, and its context at seq 1 replaces the bootstrap)
  const t = hex(9001);
  assert.deepEqual(await publishTurn(cl, { turn: t, at_ms: AT + 2, anchor: null, lines: turnLines(t, AT + 2, [{ role: "user", text: "hello, clone" }]) }), { state: "done", seq: 1 });
  assert.deepEqual(await publishContext(cl, contextOf(CLONE, 1, "the clone's own"), 1), { state: "done" });
  assert.equal(contextHeader((await cl.read("context.jsonl")).bytes).seq, 1);
  const all = await parseSegment((await cl.read(segmentPath(1))).bytes);
  assert.deepEqual(all.lines.map((l) => l.value.turn ?? "pointer"), ["pointer", t, t, t]);
  for (const l of all.lines) assert.ok(!/turn [0-9]/.test(td.decode(l.bytes)), "no source line in the clone's transcript");
  assert.deepEqual(src.snapshot(), before);
});

test("row 8: a lost acknowledgement of each write: the re-run finds the same bytes and is done, once", async () => {
  const src = await source(3, 3);
  for (const lost of ["context.jsonl", "transcript/1.jsonl", "agent.json"]) {
    let armed = true;
    const cl = fakeStore({ lose: (p) => { if (armed && p === lost) { armed = false; return true; } return false; } });
    const plan = await planClone(readOnly(src), { clone: CLONE, from: SRC, name: "c", provider: "codex", at_ms: AT });
    await assert.rejects(publishClone(cl, plan), /acknowledgement was lost/);
    assert.deepEqual(await publishClone(cl, plan), { state: "done" }, lost);
    assert.equal(cl.files.size, 3);
    for (const [p, b] of [["context.jsonl", plan.context], ["transcript/1.jsonl", plan.segment], ["agent.json", plan.agent]]) assert.deepEqual(cl.files.get(p).bytes, b);
  }
  // (the first context's lost acknowledgement, after the bootstrap: done on the re-read too)
  const cl = fakeStore({ lose: (p, op) => p === "context.jsonl" && op === "cas" });
  await publishClone(cl, await planClone(readOnly(src), { clone: CLONE, from: SRC, name: "c", provider: "codex", at_ms: AT }));
  const t = hex(77);
  await until(() => publishTurn(cl, { turn: t, at_ms: AT, anchor: null, lines: turnLines(t, AT, [{ role: "user", text: "x" }]) }));
  await assert.rejects(publishContext(cl, contextOf(CLONE, 1), 1), /acknowledgement was lost/);
  assert.deepEqual(await publishContext(cl, contextOf(CLONE, 1), 1), { state: "done" });
});

test("row 8: a lagging source (context 99, newest marker 100) keeps both, and the pointer names 100", async () => {
  const src = await source(100, 99);
  const plan = await planClone(readOnly(src), { clone: CLONE, from: SRC, name: "c", provider: "codex", at_ms: AT });
  assert.deepEqual(contextHeader(plan.context).bootstrap, { cloned_from: { agent: SRC, context_seq: 99, marker_seq: 100 } });
  assert.deepEqual(JSON.parse(td.decode(plan.segment)), { cloned_from: { agent: SRC, seq: 100 } });
});

test("row 8: the newest NORMAL marker: an aborted one after it doesn't count", async () => {
  const st = fakeStore();
  const t1 = hex(1), t2 = hex(2);
  await st.create(segmentPath(1), frame([encodeLine({ turn: t1, i: 0, start: true, seq: 7, at_ms: AT }), await endLine(t1, 1, 7, [])]));
  await st.create(segmentPath(2), frame([encodeLine({ turn: t2, i: 0, start: true, seq: 8, at_ms: AT }), await endLine(t2, 1, 8, [], { aborted: true })]));
  assert.equal(await newestNormalMarker(st), 7);
  assert.equal(await newestNormalMarker(fakeStore()), 0);
  // (the newest segment is read first: a normal marker there beats an older segment's)
  const t3 = hex(3);
  await st.create(segmentPath(3), frame([encodeLine({ turn: t3, i: 0, start: true, seq: 9, at_ms: AT }), await endLine(t3, 1, 9, [])]));
  assert.equal(await newestNormalMarker(st), 9);
});

test("row 8: a clone of a clone points at its direct source only", async () => {
  const src = await source(2, 2);
  const c1 = fakeStore();
  await publishClone(c1, await planClone(readOnly(src), { clone: CLONE, from: SRC, name: "c", provider: "codex", at_ms: AT }));
  const plan2 = await planClone(readOnly(c1), { clone: "grandchild", from: CLONE, name: "g", provider: "codex", at_ms: AT });
  // (the first clone has no turn of its own yet: its marker is its pointer's, 0 in its own sequence)
  assert.deepEqual(contextHeader(plan2.context).bootstrap, { cloned_from: { agent: CLONE, context_seq: 0, marker_seq: 0 } });
});

test("row 8 control: a clone that keeps the source's seq has its first context refused", async () => {
  const src = await source(100, 100);
  const srcCtx = (await src.read("context.jsonl")).bytes;
  // (the control: the source's context with only the agent changed, its seq 100 kept as the high-water)
  const h = contextHeader(srcCtx);
  const kept = te.encode(JSON.stringify({ ...h, agent: CLONE }) + td.decode(srcCtx.subarray(srcCtx.indexOf(10))));
  const bad = fakeStore();
  await bad.create("context.jsonl", kept);
  assert.deepEqual(await publishContext(bad, contextOf(CLONE, 1), 1), { state: "stale" });
  // (the bootstrap, in the clone's own sequence, is replaced)
  const good = fakeStore();
  await publishClone(good, await planClone(readOnly(src), { clone: CLONE, from: SRC, name: "c", provider: "codex", at_ms: AT }));
  assert.deepEqual(await publishContext(good, contextOf(CLONE, 1), 1), { state: "done" });
});

test("a clone into an id that already has other files writes nothing more", async () => {
  const src = await source(1, 1);
  const plan = await planClone(readOnly(src), { clone: CLONE, from: SRC, name: "c", provider: "codex", at_ms: AT });
  const cl = fakeStore();
  await cl.create("context.jsonl", contextOf(CLONE, 5));
  assert.deepEqual(await publishClone(cl, plan), { state: "exists", path: "context.jsonl" });
  assert.equal(cl.files.size, 1);
  const cl2 = fakeStore();
  await cl2.create(segmentPath(1), frame([encodeLine({ cloned_from: { agent: "other", seq: 1 } })]));
  assert.deepEqual(await publishClone(cl2, plan), { state: "exists", path: segmentPath(1) });
  assert.equal(cl2.files.has("agent.json"), false, "agent.json, written last, isn't written");
});

test("the bootstrap refuses rather than cuts: the header and the file re-checked at their caps (LIMITS)", () => {
  const base = contextOf(SRC, 4);
  const args = { clone: CLONE, from: SRC, marker_seq: 4, at_ms: AT };
  // (the header: a source whose header is just under HEADER_MAX passes over it once the bootstrap is added)
  const h = contextHeader(base);
  const pad = (n) => { const head = te.encode(JSON.stringify({ ...h, pad: "p".repeat(n) })); return { head, bytes: new Uint8Array([...head, ...base.subarray(base.indexOf(10))]) }; };
  let n = HEADER_MAX - te.encode(JSON.stringify({ ...h, pad: "" })).length;
  const atCap = pad(n).bytes;
  assert.equal(pad(n).head.length, HEADER_MAX);
  assert.throws(() => bootstrapContext(atCap, args), /header over HEADER_MAX/);
  // (one that fits with its bootstrap passes, at exactly HEADER_MAX)
  const withBoot = te.encode(JSON.stringify({ ...h, agent: CLONE, at_ms: AT, seq: 0, bootstrap: { cloned_from: { agent: SRC, context_seq: 4, marker_seq: 4 } }, pad: "" })).length;
  const fit = pad(HEADER_MAX - withBoot).bytes;
  const out = bootstrapContext(fit, args);
  assert.equal(out.indexOf(10), HEADER_MAX);
  assert.throws(() => bootstrapContext(pad(HEADER_MAX - withBoot + 1).bytes, args), /HEADER_MAX/);
  // (the file: a source at exactly CONTEXT_MAX, its header short and its lines long, which no built context is; the
  // bootstrap's header is longer, so the file would pass the cap, and is refused)
  const head = te.encode(JSON.stringify(h) + "\n");
  const shell = te.encode(JSON.stringify({ role: "user", text: "" }) + "\n").length;
  const filler = te.encode(JSON.stringify({ role: "user", text: "z".repeat(CONTEXT_MAX - head.length - shell) }) + "\n");
  const full = new Uint8Array([...head, ...filler]);
  assert.equal(full.length, CONTEXT_MAX);
  assert.ok(contextHeader(full));
  assert.throws(() => bootstrapContext(full, args), /over CONTEXT_MAX/);
});

test("the bootstrap's inputs: ids, the source's own agent, the marker not behind the context", () => {
  const ctx = contextOf(SRC, 4);
  const ok = { clone: CLONE, from: SRC, marker_seq: 4, at_ms: AT };
  assert.ok(bootstrapContext(ctx, ok));
  for (const bad of [{ clone: SRC }, { clone: "" }, { clone: "a/b" }, { clone: "memory" }, { clone: "hosts" }, { clone: "x".repeat(129) }, { from: "other" },
    { marker_seq: 3 }, { marker_seq: 4.5 }, { at_ms: -1 }, { at_ms: 1.5 }]) {
    assert.throws(() => bootstrapContext(ctx, { ...ok, ...bad }), RangeError, JSON.stringify(bad).slice(0, 60));
  }
  assert.throws(() => bootstrapContext(te.encode('{"no":"header"}\n'), ok), /isn't a context/);
  assert.ok(bootstrapContext(ctx, { ...ok, clone: "x".repeat(128) }));
});

test("planClone refuses a source with no context", async () => {
  await assert.rejects(planClone(fakeStore(), { clone: CLONE, from: SRC, name: "c", provider: "codex", at_ms: AT }), /no context/);
});

// ---- row 12: a host restore after losing pending turns ----

const audit = (from, to) => Array.from({ length: to - from + 1 }, (_, k) => ({ turn: hex(from + k), at_ms: AT + (from + k) * 1000 }));

test("row 12: a restore names exactly the turns after the newest published marker, in one gap line", () => {
  const a = audit(1, 10);
  assert.deepEqual(missingTurns(a, { turn: hex(7), at_ms: AT + 7000 }).map((e) => e.turn), [hex(8), hex(9), hex(10)]);
  const ls = restoreGapLines(hex(99), 1, a, { turn: hex(7), at_ms: AT + 7000 });
  assert.equal(ls.length, 1);
  assert.deepEqual(JSON.parse(td.decode(ls[0])), { turn: hex(99), i: 1, gap: true, turns: [hex(8), hex(9), hex(10)], from_ms: AT + 8000, to_ms: AT + 10000 });
  // (nothing missing; nothing published; the published turn older than the restored stream reaches)
  assert.deepEqual(restoreGapLines(hex(99), 1, a, { turn: hex(10), at_ms: AT + 10000 }), []);
  assert.equal(missingTurns(a, null).length, 10);
  assert.deepEqual(missingTurns(audit(5, 8), { turn: hex(3), at_ms: AT + 3000 }).map((e) => e.turn), [hex(5), hex(6), hex(7), hex(8)]);
  assert.deepEqual(missingTurns(audit(5, 8), { turn: hex(1), at_ms: AT + 6000 }).map((e) => e.turn), [hex(7), hex(8)]);
});

test("row 12: past LINE_MAX the missing turns run over several gap lines, each id named exactly once, in order", () => {
  const a = audit(1, 5000);
  const ls = restoreGapLines(hex(99999), 3, a, { turn: hex(1), at_ms: AT + 1000 });
  assert.ok(ls.length >= 3);
  const named = [];
  ls.forEach((l, k) => {
    assert.ok(l.length + 1 <= LINE_MAX);
    const v = JSON.parse(td.decode(l));
    assert.equal(v.i, 3 + k);
    assert.equal(v.from_ms, Math.min(...v.turns.map((t) => AT + parseInt(t, 16) * 1000)));
    named.push(...v.turns);
  });
  assert.deepEqual(named, a.slice(1).map((e) => e.turn));
  // (every line but the last is full: one more id would pass LINE_MAX)
  assert.ok(ls[0].length + 1 + 35 > LINE_MAX);
});

test("row 12: the audit stream's entries are checked", () => {
  for (const bad of [[{ turn: "x", at_ms: 1 }], [{ turn: hex(1), at_ms: 1.5 }], [{ turn: hex(1), at_ms: 1 }, { turn: hex(1), at_ms: 2 }], [null]]) {
    assert.throws(() => missingTurns(bad, null), RangeError);
  }
  assert.throws(() => missingTurns(audit(1, 2), { turn: "x", at_ms: 1 }), RangeError);
  assert.throws(() => missingTurns(audit(1, 2), undefined), RangeError);
});
