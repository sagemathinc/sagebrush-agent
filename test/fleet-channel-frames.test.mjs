// The browser channel's frames (lib/fleet/channel/frames.mjs; design agent-autonomous-browser-channel.md r4 §4): the
// 29-byte header with exact counters, per-kind bounds, fragments in order with kinds interleaving, the first-fragment
// acknowledgement rule (H5), field ownership, ctl's own counter, and closed canonical bodies. Both directions.
import assert from "node:assert/strict";
import { test } from "node:test";
import { FleetError } from "../lib/fleet/index.mjs";
import { BODY_MAX, HEADER, LIMITS, decodeFrame, encodeBody, encodeFrame, fragment, reader } from "../lib/fleet/channel/frames.mjs";

const code = (fn) => { try { fn(); } catch (e) { if (e instanceof FleetError) return e.code; throw e; } return "ok"; };
const big = (n) => ({ answer: { data: "x".repeat(n) } });
const ack = (from, v) => (from === "app" ? { recv: v, rack: 0 } : { recv: 0, rack: v });
// (each direction's kinds: the app sends res, evt, ctl; the broker sends cmd, ctl)
const LONG = { app: "res", broker: "cmd" };
const longBody = (from) => (from === "app" ? encodeBody("res", big(70000)) : encodeBody("cmd", { command: { data: "y".repeat(70000) } }));
const ping = (t = 1) => encodeBody("ctl", { ctl: "ping", t });

test("the header: 29 bytes, exact 64-bit fields held to 2^53 - 1, known kinds, fragment indexes in bounds", () => {
  const f = encodeFrame({ kind: "res", seq: 7, frag: 0, nfrag: 1, recv: 11, rack: 0, body: new Uint8Array(3) });
  assert.equal(f.length, HEADER + 3);
  assert.deepEqual({ ...decodeFrame(f), body: undefined }, { kind: "res", seq: 7, frag: 0, nfrag: 1, recv: 11, rack: 0, body: undefined });
  const set64 = (bytes, at, v) => { const c = Uint8Array.from(bytes); new DataView(c.buffer).setBigUint64(at, v); return c; };
  for (const at of [1, 13, 21]) {
    assert.equal(code(() => decodeFrame(set64(f, at, 2n ** 53n))), "bad_form", `field at ${at}: 2^53`);
    assert.equal(decodeFrame(set64(f, at, 2n ** 53n - 1n)).kind, "res", `field at ${at}: 2^53 - 1`);
  }
  assert.equal(code(() => decodeFrame(set64(f, 1, 0n))), "bad_form", "seq 0");
  const k = Uint8Array.from(f); k[0] = 9;
  assert.equal(code(() => decodeFrame(k)), "bad_form", "kind 9");
  assert.equal(code(() => encodeFrame({ kind: "ctl", seq: 1, frag: 0, nfrag: 2, recv: 0, rack: 0, body: new Uint8Array(1) })), "bad_form", "ctl is one fragment");
  assert.equal(code(() => encodeFrame({ kind: "cmd", seq: 1, frag: 3, nfrag: 3, recv: 0, rack: 0, body: new Uint8Array(1) })), "bad_form", "frag < nfrag");
  assert.equal(code(() => encodeFrame({ kind: "res", seq: 1, frag: 0, nfrag: 1, recv: 0, rack: 0, body: new Uint8Array(BODY_MAX + 1) })), "limit");
  assert.equal(code(() => decodeFrame(new Uint8Array(HEADER + BODY_MAX + 1))), "bad_form", "a frame over 29 + 60,000 bytes");
});

test("each kind's bound: at the limit, and one past it", () => {
  for (const [kind, l] of Object.entries(LIMITS)) {
    assert.equal(fragment(kind, 1, new Uint8Array(l.bytes), { recv: 0, rack: 0 }).length, l.nfrag, `${kind} at its bound`);
    assert.equal(code(() => fragment(kind, 1, new Uint8Array(l.bytes + 1), { recv: 0, rack: 0 })), "limit", `${kind} past it`);
  }
});

for (const from of ["app", "broker"]) {
  const L = LONG[from];
  const open = (limit = 100) => reader({ from, ackLimit: () => limit });

  test(`acknowledgements (H5), from the ${from}: the interleave is accepted, and a continuation keeps its message's value`, () => {
    const r = open();
    const long = fragment(L, 7, longBody(from), ack(from, 11));
    assert.equal(long.length, 2);
    assert.equal(r.push(long[0]), null);
    assert.equal(r.highWater, 11, "an accepted first fragment of several commits at once, before any interleave");
    assert.equal(r.push(fragment("ctl", 1, ping(), ack(from, 12))[0]).kind, "ctl");
    const done = r.push(long[1]);
    assert.deepEqual([done.kind, done.seq, done.ack], [L, 7, 11]);
    assert.equal(r.highWater, 12, "the continuation neither re-applied nor lowered the mark");
  });

  test(`acknowledgements, from the ${from}: a changed continuation, a lower first fragment and an over-acknowledgement are refused`, () => {
    const long = fragment(L, 7, longBody(from), ack(from, 11));
    const changed = fragment(L, 7, longBody(from), ack(from, 12))[1];
    const r1 = open();
    r1.push(long[0]);
    assert.equal(code(() => r1.push(changed)), "bad_form", "a continuation whose acknowledgement differs");
    const r2 = open();
    r2.push(fragment("ctl", 1, ping(), ack(from, 12))[0]);
    assert.equal(code(() => r2.push(fragment(L, 1, encodeBody(L, from === "app" ? { answer: {} } : { command: {} }), ack(from, 11))[0])), "bad_form", "a new message lower than the mark");
    assert.equal(r2.highWater, 12, "a refused first fragment leaves the mark");
    // a first fragment with a higher acknowledgement, refused by a later check on that same fragment: the mark stays
    const r4 = open();
    r4.push(fragment("ctl", 1, ping(), ack(from, 12))[0]);
    const shortHigh = encodeFrame({ kind: L, seq: 1, frag: 0, nfrag: 2, ...ack(from, 20), body: new Uint8Array(10) });
    assert.equal(code(() => r4.push(shortHigh)), "bad_form");
    assert.equal(r4.highWater, 12, "committed only after the first fragment is accepted in full");
    // a one-fragment message whose body fails (not canonical; an extra field): the mark stays where it was
    for (const text of ['{"ctl":"ping", "t":1}', '{"ctl":"ping","t":1,"x":1}']) {
      const r5 = open();
      assert.equal(code(() => r5.push(fragment("ctl", 1, new TextEncoder().encode(text), ack(from, 20))[0])), "bad_form", text);
      assert.equal(r5.highWater, 0, `${text}: committed only after the body passed`);
    }
    const r3 = open();
    r3.push(fragment("ctl", 1, ping(), ack(from, 12))[0]);
    assert.equal(r3.push(fragment(L, 1, encodeBody(L, from === "app" ? { answer: {} } : { command: {} }), ack(from, 12))[0]).kind, L, "an equal acknowledgement on a new message of another kind");
    assert.equal(code(() => open(5).push(fragment("ctl", 1, ping(), ack(from, 6))[0])), "bad_form", "acknowledging what wasn't sent");
    assert.equal(open(6).push(fragment("ctl", 1, ping(), ack(from, 6))[0]).ack, 6, "exactly what was sent");
    // (H3) the caller's limit must be an exact count: anything else ends the reader, the mark unchanged
    for (const bad of [NaN, undefined, Infinity, -1, 1.5, "6", null]) {
      const r6 = reader({ from, ackLimit: () => bad });
      assert.equal(code(() => r6.push(fragment("ctl", 1, ping(), ack(from, 0))[0])), "bad_form", String(bad));
      assert.equal(r6.highWater, 0, String(bad));
      assert.equal(code(() => r6.push(fragment("ctl", 1, ping(), ack(from, 0))[0])), "bad_form", `${bad}: dead`);
    }
    assert.equal(code(() => reader({ from, ackLimit: () => NaN }).push(fragment("ctl", 1, ping(), ack(from, Number.MAX_SAFE_INTEGER))[0])), "bad_form", "a peer acknowledging 2^53 - 1 against a NaN limit");
  });

  test(`ownership and order, from the ${from}: the unowned field is 0, only its own kinds, seq and fragments in order`, () => {
    const unowned = from === "app" ? { recv: 0, rack: 1 } : { recv: 1, rack: 0 };
    assert.equal(code(() => open().push(fragment("ctl", 1, ping(), unowned)[0])), "bad_form", "a non-zero unowned field");
    const foreign = from === "app" ? fragment("cmd", 1, encodeBody("cmd", { command: {} }), ack(from, 0))[0] : fragment("res", 1, encodeBody("res", { answer: {} }), ack(from, 0))[0];
    assert.equal(code(() => open().push(foreign)), "bad_form", "a kind this end doesn't send");
    assert.equal(code(() => open().push(fragment("ctl", 2, ping(), ack(from, 0))[0])), "bad_form", "ctl starts at 1");
    const r = open();
    r.push(fragment("ctl", 1, ping(), ack(from, 0))[0]);
    assert.equal(code(() => r.push(fragment("ctl", 3, ping(), ack(from, 0))[0])), "bad_form", "a skipped ctl seq");
    const long = fragment(L, 4, longBody(from), ack(from, 0));
    const r2 = open();
    r2.push(long[0]);
    assert.equal(code(() => r2.push(fragment(L, 5, encodeBody(L, from === "app" ? { answer: {} } : { command: {} }), ack(from, 0))[0])), "bad_form", "a new message of a kind before its open one finished");
    assert.equal(code(() => open().push(long[1])), "bad_form", "a continuation with no first fragment");
    const short = encodeFrame({ kind: L, seq: 1, frag: 0, nfrag: 2, recv: 0, rack: 0, body: new Uint8Array(10) });
    assert.equal(code(() => open().push(short)), "bad_form", "a short fragment before the last");
    const r3 = open();
    assert.equal(code(() => r3.push(foreign)), "bad_form");
    assert.equal(code(() => r3.push(fragment("ctl", 1, ping(), ack(from, 0))[0])), "bad_form", "a reader is dead after any refusal");
  });
}

test("bodies: canonical JSON, one closed shape per kind and per ctl variant", () => {
  const r = () => reader({ from: "app", ackLimit: () => 100 });
  const raw = (kind, text) => fragment(kind, 1, new TextEncoder().encode(text), { recv: 0, rack: 0 })[0];
  assert.equal(r().push(raw("res", '{"answer":{"a":1}}')).value.answer.a, 1);
  assert.equal(r().push(raw("res", '{"outcome":"unknown","reason":"abandoned"}')).value.outcome, "unknown");
  for (const bad of ['{"answer":{"a":1}, "x":1}', '{"answer": {"a":1}}', '{"answer":[1]}', '{"outcome":"unknown","reason":"takeover"}', '{"outcome":"unknown"}', "[]", "not json"])
    assert.equal(code(() => r().push(raw("res", bad))), "bad_form", bad);
  for (const ok of ['{"ctl":"ping","t":5}', '{"ctl":"pong","t":5}', '{"ctl":"refused","reason":"takeover","seq":3}', '{"ctl":"events_lost","n":0}', '{"ctl":"paused"}'])
    assert.equal(r().push(raw("ctl", ok)).kind, "ctl", ok);
  for (const bad of ['{"ctl":"refused","reason":"abandoned","seq":3}', '{"ctl":"ping"}', '{"ctl":"ping","t":-1}', '{"ctl":"paused","x":1}', '{"ctl":"other"}'])
    assert.equal(code(() => r().push(raw("ctl", bad))), "bad_form", bad);
  assert.equal(code(() => encodeBody("cmd", { command: [] })), "bad_form");
  assert.equal(code(() => encodeBody("ctl", { ctl: "ping", t: 1, extra: true })), "bad_form");
});
