// The browser channel's sessions (lib/fleet/channel/{broker,app,link}.mjs; design agent-autonomous-browser-channel.md
// r4.2 §6 and §7): the result sequence rows 1-8 (r4.2), takeover outcomes, the bounds, the blocked transport, health
// and the resume window. Every transport is a real Noise_IK handshake; the wire, the clock and the app's executor are
// the test's (fleet-channel-harness.mjs).
import assert from "node:assert/strict";
import { test } from "node:test";
import { appVsRaw, brokerVsRaw, connect, manualClock, sessions, settle, sink, handshake } from "./fleet-channel-harness.mjs";
import { encodeFrame, encodeBody, fragment, reader } from "../lib/fleet/channel/frames.mjs";
import { FleetError } from "../lib/fleet/index.mjs";

const EMPTY = new Uint8Array(0);
const kinds = (sent) => sent.map((m) => (m.kind === "ctl" ? `ctl:${m.value.ctl}` : `${m.kind}:${m.seq}`));
const codeOf = (fn) => { try { fn(); return "ok"; } catch (e) { if (e instanceof FleetError) return e.code; throw e; } };

// ---- r4.2 §7, the result sequence

test("row 1: cmd 1 -> res 1, cmd 2 refused, cmd 3 -> res 3: one outcome each, 2 not run and never resent; also across a resume", async () => {
  const s = sessions();
  const t = connect(s.broker, s.app);
  const out = [1, 2, 3].map((n) => s.broker.submit({ n, bad: n === 2 }));
  await t.pump();
  assert.deepEqual((await Promise.all(out)).map((o) => o.outcome), ["result", "not_run", "result"]);
  assert.equal((await out[1]).reason, "bad");
  assert.equal(s.exec.calls, 2, "the refused command never ran");
  assert.deepEqual(kinds(s.appSent).filter((k) => !k.startsWith("ctl:p")), ["res:1", "ctl:refused", "res:3"], "a gap in res seqs after the refusal");
  assert.equal(s.broker.rack, 3);

  // across a resume: res 1 arrives, the refusal and res 3 are lost with the transport
  const r = sessions();
  const t1 = connect(r.broker, r.app);
  const o = [1, 2, 3].map((n) => r.broker.submit({ n, bad: n === 2 }));
  t1.deliverToApp();
  await settle();
  t1.deliverToBroker(1); // (the app's first frame on this transport... its outcomes follow)
  while (r.broker.rack < 1 && t1.toBroker.length) t1.deliverToBroker(1);
  assert.equal(r.broker.rack, 1);
  t1.cut();
  const t2 = connect(r.broker, r.app);
  await t2.pump();
  assert.deepEqual((await Promise.all(o)).map((x) => x.outcome), ["result", "not_run", "result"]);
  assert.equal(r.exec.calls, 2);
  assert.equal(r.brokerSent.filter((m) => m.kind === "cmd").length, 3, "no command resent: the app's recv covered all three");
});

test("row 2: res 1 delivered, its rack lost, a resume: one delivery and one execution, retention released; a mid-fragment cut restarts from frag 0", async () => {
  const s = sessions();
  const t1 = connect(s.broker, s.app);
  const p = s.broker.submit({ n: 1, click: true });
  t1.deliverToApp();
  await settle();
  t1.deliverToBroker(); // (res 1 delivered; the broker's ack, carrying rack 1, waits in toApp)
  await settle();
  assert.equal((await p).outcome, "result");
  assert.equal(s.app.retained.count, 1, "retained until the rack arrives");
  t1.cut(); // (the rack is lost)
  const before = s.appSent.length;
  const t2 = connect(s.broker, s.app);
  await t2.pump();
  assert.equal(s.exec.calls, 1);
  assert.equal(s.app.retained.count, 0, "released by the new transport's first frame");
  assert.ok(!s.appSent.slice(before).some((m) => m.kind === "res"), "never replayed: the rack came first");
  assert.equal(s.broker.ended, null);

  // an 8 MiB result cut after 70 of its 140 fragments, then a resume: sent again from frag 0, delivered once, intact
  const b = sessions({ appOpts: {} });
  const big = "x".repeat(8 * 1024 * 1024 - 64);
  b.exec.execute = async (command) => { b.exec.calls++; return { data: big }; };
  const app2 = (await import("../lib/fleet/channel/app.mjs")).appSession({ execute: b.exec.execute, clock: b.clock });
  const u1 = connect(b.broker, app2);
  const q = b.broker.submit({ n: 1 });
  u1.deliverToApp();
  await settle();
  // (the first message toBroker is the result's frag 0 onward; deliver half of them)
  const frames = u1.toBroker.length;
  assert.ok(frames >= 140, `the result went out in ${frames} messages`);
  u1.deliverToBroker(70);
  u1.cut();
  const u2 = connect(b.broker, app2);
  await u2.pump(400);
  const got = await q;
  assert.equal(got.outcome, "result");
  assert.equal(got.answer.data.length, big.length, "intact");
  assert.equal(b.exec.calls, 1);
});

test("row 3: cmd 1 admitted and unresolved, then res 3: the session ends; 1 is unknown, never success, never racked away, never retried", async () => {
  const s = sessions();
  const w = brokerVsRaw(s.broker);
  const out = [1, 2, 3].map((n) => s.broker.submit({ n }));
  w.flush();
  assert.equal(w.raw.got.filter((m) => m.kind === "cmd").length, 3);
  w.raw.l.send("res", 3, { answer: { n: 3 } }, { recv: 3, rack: 0 });
  w.flush();
  assert.ok(s.broker.ended, "the session ended");
  const o = await Promise.all(out);
  assert.deepEqual(o.map((x) => x.outcome), ["unknown", "unknown", "unknown"]);
  assert.equal(s.broker.rack, 0, "nothing racked");
  // (an outcome for a command submitted but never sent: held back by the credits)
  const u = sessions({ brokerOpts: { credits: 1 } });
  const wu = brokerVsRaw(u.broker);
  const held = [u.broker.submit({ n: 1 }), u.broker.submit({ n: 2 })];
  wu.flush();
  assert.equal(wu.raw.got.filter((m) => m.kind === "cmd").length, 1, "1 sent, 2 held");
  wu.raw.l.send("ctl", 1, { ctl: "refused", seq: 1, reason: "bad" }, { recv: 1, rack: 0 });
  wu.flush();
  // (the refusal freed the credit, so 2 went out: now an outcome for 3, submitted and held)
  const third = u.broker.submit({ n: 3 });
  u.broker.submit({ n: 4 });
  wu.flush();
  assert.equal(wu.raw.got.filter((m) => m.kind === "cmd").length, 2);
  wu.raw.l.send("res", 3, { answer: {} }, { recv: 2, rack: 0 });
  wu.flush();
  assert.ok(u.broker.ended, "an outcome for a command never sent");
  assert.deepEqual((await third).outcome, "not_run");
  assert.deepEqual((await held[1]).outcome, "unknown");
});

test("row 4: refused then res, res then refused, a duplicate refusal: exact on a fresh transport is ignored, a conflict ends the session", async () => {
  // (a) refused then res, one transport
  const a = sessions();
  const wa = brokerVsRaw(a.broker);
  const pa = a.broker.submit({ n: 1 });
  wa.flush();
  wa.raw.l.send("ctl", 1, { ctl: "refused", seq: 1, reason: "bad" }, { recv: 1, rack: 0 });
  wa.flush();
  assert.equal((await pa).outcome, "not_run");
  wa.raw.l.send("res", 1, { answer: {} }, { recv: 1, rack: 0 });
  wa.flush();
  assert.ok(a.broker.ended, "res after refused");
  // (b) res then refused, one transport
  const b = sessions();
  const wb = brokerVsRaw(b.broker);
  b.broker.submit({ n: 1 });
  wb.flush();
  wb.raw.l.send("res", 1, { answer: {} }, { recv: 1, rack: 0 });
  wb.raw.l.send("ctl", 1, { ctl: "refused", seq: 1, reason: "bad" }, { recv: 1, rack: 0 });
  wb.flush();
  assert.ok(b.broker.ended, "refused after res");
  // (b2) an exact duplicate refusal on the same transport ends the session
  const b2 = sessions();
  const wb2 = brokerVsRaw(b2.broker);
  b2.broker.submit({ n: 1 });
  wb2.flush();
  wb2.raw.l.send("ctl", 1, { ctl: "refused", seq: 1, reason: "bad" }, { recv: 1, rack: 0 });
  wb2.raw.l.send("ctl", 2, { ctl: "refused", seq: 1, reason: "bad" }, { recv: 1, rack: 0 });
  wb2.flush();
  assert.ok(b2.broker.ended, "an exact duplicate on the same transport");
  // (c) a duplicate refusal on a fresh transport: exact, ignored; a changed reason ends the session
  for (const [reason, alive] of [["bad", true], ["paused", false]]) {
    const c = sessions();
    const w1 = brokerVsRaw(c.broker);
    const pc = c.broker.submit({ n: 1 });
    w1.flush();
    w1.raw.l.send("ctl", 1, { ctl: "refused", seq: 1, reason: "bad" }, { recv: 1, rack: 0 });
    w1.flush();
    w1.bl.lost("cut");
    const w2 = brokerVsRaw(c.broker, { highWater: 0 });
    w2.flush();
    w2.raw.l.send("ctl", 1, { ctl: "refused", seq: 1, reason }, { recv: 1, rack: 0 });
    w2.flush();
    assert.equal(c.broker.ended === null, alive, `a duplicate refusal, reason ${reason}`);
    assert.deepEqual(await pc, { outcome: "not_run", reason: "bad" }, "the first outcome stands");
  }
});

test("row 5: a sparse rack; a rack past what was sent is refused; recv alone frees nothing; the first res 3 on a resumed link after rack 1 and refused 2", async () => {
  // a rack past the app's last outcome ends the app's session
  const a = sessions();
  const w = appVsRaw(a.app);
  w.raw.l.send("ctl", 1, { ctl: "ping", t: 1 }, { recv: 0, rack: 5 });
  await w.flush();
  assert.ok(a.app.ended, "rack 5 with nothing sent");
  // recv alone frees nothing, and settles nothing
  const b = sessions();
  const t = connect(b.broker, b.app);
  const release = b.exec.barrier(1);
  const p = b.broker.submit({ n: 1, hold: "before" });
  await t.pump();
  assert.equal(b.app.recv, 1, "admitted");
  assert.equal(b.broker.rack, 0, "but no outcome: recv settles nothing");
  assert.equal(b.app.retained.count, 0, "and frees nothing");
  release();
  await t.pump();
  assert.equal((await p).outcome, "result");
  // rack 1 reached the app, refused 2 was lost; then res 3 is the first res on the resumed link
  const c = sessions();
  const t1 = connect(c.broker, c.app);
  const r3 = c.exec.barrier(3);
  const o = [1, 2, 3].map((n) => c.broker.submit({ n, bad: n === 2, ...(n === 3 ? { hold: "before" } : {}) }));
  t1.deliverToApp();
  await settle();
  // (res 1, then the refusal: deliver only res 1, let the broker's ack reach the app, then cut)
  t1.deliverToBroker(1);
  await settle();
  while (c.broker.rack < 1 && t1.toBroker.length) t1.deliverToBroker(1);
  await settle();
  t1.toBroker.length = 0;
  t1.deliverToApp();
  assert.equal(c.app.rack, 1);
  t1.cut();
  const t2 = connect(c.broker, c.app);
  r3();
  await t2.pump();
  assert.deepEqual((await Promise.all(o)).map((x) => x.outcome), ["result", "not_run", "result"]);
  assert.equal(c.broker.ended, null);
});

test("row 6: a fragmented sparse res 3 interleaved with ctl and evt is accepted; dense cmd, evt and ctl gaps are still refused", async () => {
  const s = sessions();
  const hs = handshake();
  const toApp = [];
  const bl = s.broker.attach({ cipher: hs.broker, sink: sink(toApp) });
  const out = [1, 2, 3].map((n) => s.broker.submit({ n }));
  const enc = (f) => hs.app.send.encrypt(EMPTY, f);
  const ack = { recv: 3, rack: 0 };
  // (two refusals, then res 3 in two fragments with a ctl and an evt between them)
  bl.deliver(enc(fragment("ctl", 1, encodeBody("ctl", { ctl: "refused", seq: 1, reason: "bad" }), ack)[0]));
  bl.deliver(enc(fragment("ctl", 2, encodeBody("ctl", { ctl: "refused", seq: 2, reason: "bad" }), ack)[0]));
  const res = fragment("res", 3, encodeBody("res", { answer: { data: "y".repeat(70000) } }), ack);
  assert.equal(res.length, 2);
  bl.deliver(enc(res[0]));
  bl.deliver(enc(fragment("ctl", 3, encodeBody("ctl", { ctl: "ping", t: 1 }), ack)[0]));
  bl.deliver(enc(fragment("evt", 1, encodeBody("evt", { event: { e: 1 } }), ack)[0]));
  assert.equal(s.broker.rack, 2, "no outcome before the last fragment");
  bl.deliver(enc(res[1]));
  assert.equal(s.broker.ended, null);
  assert.deepEqual((await Promise.all(out)).map((x) => x.outcome), ["not_run", "not_run", "result"]);
  assert.deepEqual(s.events, [{ event: { e: 1 } }]);
  // dense kinds: a gap in cmd, evt or ctl seq ends the reader
  const body = (kind) => encodeBody(kind, kind === "cmd" ? { command: {} } : kind === "evt" ? { event: {} } : { ctl: "ping", t: 1 });
  for (const [from, kind] of [["broker", "cmd"], ["app", "evt"], ["app", "ctl"], ["broker", "ctl"]]) {
    const r = reader({ from, ackLimit: () => 100 });
    const a = from === "app" ? { recv: 0, rack: 0 } : { recv: 0, rack: 0 };
    r.push(fragment(kind, 1, body(kind), a)[0]);
    assert.equal(codeOf(() => r.push(fragment(kind, 3, body(kind), a)[0])), "bad_form", `a ${kind} gap from the ${from}`);
  }
  // and res: strictly increasing, gaps allowed, equal or lower refused
  const r = reader({ from: "app", ackLimit: () => 100 });
  const resF = (seq) => fragment("res", seq, encodeBody("res", { answer: {} }), { recv: 0, rack: 0 })[0];
  r.push(resF(2));
  r.push(resF(5));
  assert.equal(codeOf(() => r.push(resF(5))), "bad_form", "an equal res seq");
  const r2 = reader({ from: "app", ackLimit: () => 100 });
  r2.push(resF(5));
  assert.equal(codeOf(() => r2.push(resF(4))), "bad_form", "a lower res seq");
});

test("row 7: an exact duplicate on a fresh transport only re-acknowledges; a changed body ends the session; after eviction it fails closed; within one transport an equal res seq ends it even when exact", async () => {
  // exact res on a fresh transport: ignored, no second delivery
  const a = sessions();
  const w1 = brokerVsRaw(a.broker);
  const pa = a.broker.submit({ n: 1 });
  w1.flush();
  w1.raw.l.send("res", 1, { answer: { v: 1 } }, { recv: 1, rack: 0 });
  w1.flush();
  assert.deepEqual(await pa, { outcome: "result", answer: { v: 1 } });
  w1.bl.lost("cut");
  const w2 = brokerVsRaw(a.broker, { highWater: 0 });
  w2.flush();
  w2.raw.l.send("res", 1, { answer: { v: 1 } }, { recv: 1, rack: 0 });
  w2.flush();
  await settle();
  assert.equal(a.broker.ended, null, "exact: harmless");
  assert.ok(w2.raw.got.some((m) => m.kind === "ctl" && m.value.ctl === "ping"), "re-acknowledged");
  // changed body on a fresh transport
  const w3 = brokerVsRaw(a.broker);
  w3.flush();
  w3.raw.l.send("res", 1, { answer: { v: 2 } }, { recv: 1, rack: 0 });
  w3.flush();
  assert.ok(a.broker.ended, "a changed body");
  // after its fingerprint's eviction: fails closed
  const b = sessions({ brokerOpts: { fingerprints: 1 } });
  const v1 = brokerVsRaw(b.broker);
  b.broker.submit({ n: 1 });
  b.broker.submit({ n: 2 });
  v1.flush();
  v1.raw.l.send("res", 1, { answer: {} }, { recv: 2, rack: 0 });
  v1.raw.l.send("res", 2, { answer: {} }, { recv: 2, rack: 0 });
  v1.flush();
  v1.bl.lost("cut");
  const v2 = brokerVsRaw(b.broker);
  v2.flush();
  v2.raw.l.send("res", 1, { answer: {} }, { recv: 2, rack: 0 });
  v2.flush();
  assert.ok(b.broker.ended, "evicted: fails closed");
  // within one transport, an exact duplicate res seq ends the session
  const c = sessions();
  const x = brokerVsRaw(c.broker);
  c.broker.submit({ n: 1 });
  x.flush();
  x.raw.l.send("res", 1, { answer: {} }, { recv: 1, rack: 0 });
  x.raw.l.send("res", 1, { answer: {} }, { recv: 1, rack: 0 });
  x.flush();
  assert.ok(c.broker.ended, "the same transport");
});

test("row 8: no result or refusal is replayed before the first authenticated rack on a new transport", async () => {
  const s = sessions();
  const t1 = connect(s.broker, s.app);
  const out = [1, 2].map((n) => s.broker.submit({ n, bad: n === 2 }));
  t1.deliverToApp();
  await settle();
  t1.cut(); // (res 1 and the refusal never reached the broker)
  const before = s.appSent.length;
  const t2 = connect(s.broker, s.app);
  s.app.event({ early: true }); // (an event before the broker's first frame: not sent, counted lost)
  await settle();
  t2.deliverToBroker(); // (whatever the app sent before hearing from the broker)
  assert.deepEqual(kinds(s.appSent.slice(before)), ["ctl:events_lost"], "only ctl before the first frame");
  t2.deliverToApp(); // (the broker's ping with rack 0)
  await t2.pump();
  assert.deepEqual(kinds(s.appSent.slice(before)).filter((k) => !k.startsWith("ctl:p")), ["ctl:events_lost", "res:1", "ctl:refused"], "the replay, after it, in seq order");
  assert.deepEqual((await Promise.all(out)).map((o) => o.outcome), ["result", "not_run"]);
});

// ---- takeover (r4.2 §7: astra2's rows 1-4; row 5 is a mutant)

test("takeover 1: a command after pause reaches no execution, and is not run", async () => {
  const s = sessions();
  const t = connect(s.broker, s.app);
  await t.pump();
  s.app.pause();
  const p = s.broker.submit({ n: 1, click: true });
  await t.pump();
  assert.deepEqual(await p, { outcome: "not_run", reason: "paused" });
  assert.equal(s.exec.calls, 0);
  assert.equal(s.exec.clicks, 0);
  assert.ok(s.events.some((e) => e.paused), "the broker heard the pause");
});

test("takeover 2: a started command whose effect happened is abandoned: unknown, never not run, never run again", async () => {
  const s = sessions();
  const t = connect(s.broker, s.app);
  const release = s.exec.barrier(1);
  const p = s.broker.submit({ n: 1, click: true, hold: "after" });
  await t.pump();
  assert.equal(s.exec.clicks, 1);
  s.app.pause();
  assert.equal(s.app.abandon(1), true);
  await t.pump();
  assert.deepEqual(await p, { outcome: "unknown", reason: "abandoned" });
  release(); // (the late answer)
  s.app.unpause();
  await t.pump();
  assert.equal(s.exec.calls, 1, "never executed again");
  assert.equal(s.broker.ended, null);
});

test("takeover 3: the command path's own unknown, and admitted work that never started swept as takeover (not run)", async () => {
  const s = sessions();
  const t = connect(s.broker, s.app);
  const release = s.exec.barrier(2);
  const out = [s.broker.submit({ n: 1, fail: true }), s.broker.submit({ n: 2, hold: "before" }), s.broker.submit({ n: 3, click: true }), s.broker.submit({ n: 4, click: true })];
  await t.pump();
  s.app.pause(); // (2 is started and held; 3 and 4 never started)
  assert.equal(s.app.abandon(2), true);
  release();
  await t.pump();
  const o = await Promise.all(out);
  assert.deepEqual(o.map((x) => `${x.outcome}:${x.reason ?? ""}`), ["unknown:abandoned", "unknown:abandoned", "not_run:takeover", "not_run:takeover"]);
  assert.equal(s.exec.clicks, 0);
  assert.deepEqual(s.exec.started, [1, 2]);
});

test("takeover 4: a late result after an abandon and a resume is discarded; every seq gets one outcome", async () => {
  const s = sessions();
  const t1 = connect(s.broker, s.app);
  const release = s.exec.barrier(1);
  const p = s.broker.submit({ n: 1, click: true, hold: "after" });
  await t1.pump();
  s.app.abandon(1);
  t1.cut();
  const t2 = connect(s.broker, s.app);
  release();
  await t2.pump();
  assert.deepEqual(await p, { outcome: "unknown", reason: "abandoned" });
  assert.equal(s.appSent.filter((m) => m.kind === "res").length <= 2, true);
  assert.ok(s.appSent.filter((m) => m.kind === "res").every((m) => m.value.outcome === "unknown"), "the late answer never went out");
  assert.equal(s.broker.ended, null);
});

// ---- the bounds, each at the limit and one past it

test("bounds: 32 credits, 64 retained outcomes, 8 MiB retained, 1 MiB of unadmitted command bytes", async () => {
  // credits: the broker never has more than 32 outstanding; the 33rd waits and then runs
  const a = sessions();
  const t = connect(a.broker, a.app);
  const release = a.exec.barrier(1);
  const out = Array.from({ length: 33 }, (_, i) => a.broker.submit({ n: i + 1, ...(i === 0 ? { hold: "before" } : {}) }));
  await t.pump();
  assert.equal(a.broker.outstanding, 32, "32 sent, the 33rd held");
  assert.equal(a.brokerSent.filter((m) => m.kind === "cmd").length, 32);
  release();
  await t.pump(200);
  assert.ok((await Promise.all(out)).every((o) => o.outcome === "result"));
  // the app refuses past 32 unresolved from a broker that ignores its credits
  const b = sessions();
  const w = appVsRaw(b.app);
  const rel = b.exec.barrier(1);
  w.raw.l.send("ctl", 1, { ctl: "ping", t: 1 }, { recv: 0, rack: 0 });
  for (let n = 1; n <= 33; n++) w.raw.l.send("cmd", n, { command: { n, hold: "before" } }, { recv: 0, rack: 0 });
  await w.flush();
  const refusals = w.raw.got.filter((m) => m.kind === "ctl" && m.value.ctl === "refused");
  assert.deepEqual(refusals.map((m) => [m.value.seq, m.value.reason]), [], "none refused yet: they wait behind 1");
  rel();
  await w.flush();
  // (32 unresolved at once was the limit: command 33 came while 1..32 were unresolved, so it is refused)
  const after = w.raw.got.filter((m) => m.kind === "ctl" && m.value.ctl === "refused");
  assert.deepEqual(after.map((m) => [m.value.seq, m.value.reason]), [[33, "credits"]]);
  // retention: with no rack, 64 outcomes are retained and the 65th command is refused
  const c = sessions();
  const v = appVsRaw(c.app);
  v.raw.l.send("ctl", 1, { ctl: "ping", t: 1 }, { recv: 0, rack: 0 });
  for (let n = 1; n <= 65; n++) { v.raw.l.send("cmd", n, { command: { n } }, { recv: 0, rack: 0 }); await v.flush(); }
  assert.equal(c.app.retained.count, 65, "64 results and the 65th command's refusal");
  const last = v.raw.got.filter((m) => m.kind === "ctl" && m.value.ctl === "refused").map((m) => [m.value.seq, m.value.reason]);
  assert.deepEqual(last, [[65, "credits"]]);
  // (a broker that keeps sending without a rack: 32 more refusals at most, then the session ends)
  for (let n = 66; n <= 96; n++) { v.raw.l.send("cmd", n, { command: { n } }, { recv: 0, rack: 0 }); await v.flush(); }
  assert.equal(c.app.ended, null, "64 + 32 retained: at the bound");
  v.raw.l.send("cmd", 97, { command: { n: 97 } }, { recv: 0, rack: 0 });
  await v.flush();
  assert.equal(c.app.ended, "limit", "one past it");
  // 8 MiB: outcomes of ~1.2 MiB each; the command after the bytes pass 8 MiB is refused
  const d = sessions();
  d.exec.execute = async (command) => ({ data: "z".repeat(1_250_000) });
  const app = (await import("../lib/fleet/channel/app.mjs")).appSession({ execute: d.exec.execute, clock: d.clock });
  const u = appVsRaw(app);
  u.raw.l.send("ctl", 1, { ctl: "ping", t: 1 }, { recv: 0, rack: 0 });
  for (let n = 1; n <= 8; n++) { u.raw.l.send("cmd", n, { command: { n } }, { recv: 0, rack: 0 }); await u.flush(); }
  assert.ok(app.retained.bytes >= 8 * 1024 * 1024 && app.retained.count === 8, `7 results past 8 MiB, and the refusal (${app.retained.bytes}, ${app.retained.count})`);
  assert.deepEqual(u.raw.got.filter((m) => m.kind === "ctl" && m.value.ctl === "refused").map((m) => [m.value.seq, m.value.reason]), [[8, "credits"]]);
  // 1 MiB of unadmitted command bytes: the broker holds what would pass it
  const e = sessions();
  const x = brokerVsRaw(e.broker);
  for (let n = 1; n <= 12; n++) e.broker.submit({ n, pad: "p".repeat(100_000) });
  x.flush();
  const sent = x.raw.got.filter((m) => m.kind === "cmd").length;
  assert.equal(sent, 10, `10 commands of ~100 kB within 1 MiB, the 11th held (${sent})`);
});

// ---- the blocked transport (r4.2 §7 (c)), health and the resume window

test("a real blocked transport: the writer's callbacks withheld, a flood reaches the cap and ends the session at once; reading pauses; the close is bounded", async () => {
  const clock = manualClock();
  const s = sessions({ clock, appOpts: { linkOptions: { cap: 64 * 1024, reserve: 2048, closeMs: 1000 } } });
  const hs = handshake();
  const toApp = [];
  const held = [];
  const blocked = { write(ct, cb) { held.push(cb); return held.length < 4; }, once(ev, fn) { this.drain = fn; }, end() { this.ended = true; }, destroy() { this.destroyed = true; } };
  s.broker.attach({ cipher: hs.broker, sink: sink(toApp) });
  const pauses = [];
  const al = s.app.attach({ cipher: hs.app, sink: blocked });
  // (the broker's first frame, so the app may send)
  while (toApp.length) al.deliver(toApp.shift());
  let n = 0;
  while (!s.app.ended && n < 10_000) { s.app.event({ e: n++, pad: "q".repeat(500) }); }
  assert.ok(s.app.ended, "the cap ended the session");
  assert.equal(s.app.ended, "limit");
  assert.ok(n < 200, `synchronously, within the cap's worth of events (${n})`);
  assert.ok(blocked.ended && !blocked.destroyed);
  clock.advance(1000);
  assert.ok(blocked.destroyed, "destroyed at the bounded close");
  // reading pauses while the writer must drain, and resumes at its drain
  const t = sessions();
  const hs2 = handshake();
  const q = [];
  let more = false;
  const slow = { cbs: [], write(ct, cb) { this.cbs.push(cb); return more; }, once(ev, fn) { this.drain = fn; }, end() {}, destroy() {} };
  t.broker.attach({ cipher: hs2.broker, sink: sink(q) });
  const changes = [];
  const app = (await import("../lib/fleet/channel/app.mjs")).appSession({ execute: async () => ({}), clock: t.clock, linkOptions: { onReadPause: (p) => changes.push(p) } });
  const l = app.attach({ cipher: hs2.app, sink: slow });
  while (q.length) l.deliver(q.shift());
  app.event({ e: 1 });
  assert.equal(l.readPaused, true);
  more = true;
  for (const cb of slow.cbs.splice(0)) cb();
  slow.drain();
  assert.equal(l.readPaused, false);
  assert.deepEqual(changes, [true, false]);
});

test("the terminal frame may use the reserve; nothing is sent after it", () => {
  const hs = handshake();
  const q = [];
  const held = { write(ct) { q.push(ct); return true; }, once() {}, end() {}, destroy() {} };
  // (callbacks never called: the queue only grows)
  let ended = null;
  const l = (awaitLink()).link({ role: "app", cipher: hs.app, sink: held, ackLimit: () => 0, onMessage() {}, onEnd: (r) => { ended = r; }, cap: 4096, reserve: 1024, clock: manualClock() });
  let sent = 0;
  while (l.send("evt", sent + 1, { event: { pad: "r".repeat(400) } }, { recv: 0, rack: 0 })) sent++;
  assert.equal(ended, "limit");
  assert.ok(sent >= 5 && sent <= 7, `ordinary frames up to cap - reserve (${sent})`);
  // a fresh link, filled to just under cap - reserve, then the terminal frame fits in the reserve
  let ended2 = null;
  const hs3 = handshake();
  const q2 = [];
  const l2 = (awaitLink()).link({ role: "app", cipher: hs3.app, sink: { write(ct) { q2.push(ct); return true; }, once() {}, end() {}, destroy() {} }, ackLimit: () => 0, onMessage() {}, onEnd: (r) => { ended2 = r; }, cap: 4096, reserve: 1024, clock: manualClock() });
  let k = 0;
  while (l2.queued + 520 <= 4096 - 1024 && l2.send("evt", k + 1, { event: { pad: "r".repeat(400) } }, { recv: 0, rack: 0 })) k++;
  const before = q2.length;
  assert.equal(l2.sendTerminal(1, { ctl: "paused" }, { recv: 0, rack: 0 }), true);
  assert.equal(q2.length, before + 1, "the terminal frame was written");
  assert.equal(ended2, "closed");
  assert.equal(l2.send("evt", k + 1, { event: {} }, { recv: 0, rack: 0 }), false, "nothing after it");
  const n2 = q2.length;
  assert.equal(l2.sendTerminal(2, { ctl: "paused" }, { recv: 0, rack: 0 }), false, "nor a second terminal frame");
  assert.equal(q2.length, n2);
});

test("health: a ping every 10 s; stalled after 3 misses; a pong is ok again", async () => {
  const clock = manualClock();
  const s = sessions({ clock });
  const health = [];
  const { brokerSession } = await import("../lib/fleet/channel/broker.mjs");
  const broker = brokerSession({ clock, onHealth: (h) => health.push(h.state) });
  const t = connect(broker, s.app);
  await t.pump();
  for (let i = 0; i < 3; i++) clock.advance(10_000); // (pings go out; their pongs wait in toBroker, undelivered)
  assert.equal(health[health.length - 1], "stalled", "stalled after 3 unanswered pings");
  assert.equal(health.filter((h) => h === "stalled").length, 1, "at the third miss, not before");
  t.deliverToApp();
  await settle();
  t.deliverToBroker();
  assert.equal(health[health.length - 1], "ok");
});

test("the resume window: 60 s after a transport is lost, unanswered sent commands are unknown and unsent ones not run", async () => {
  const clock = manualClock();
  const s = sessions({ clock });
  const t = connect(s.broker, s.app);
  const sent = s.broker.submit({ n: 1, hold: "before" });
  s.exec.barrier(1);
  await t.pump();
  t.cut();
  const unsent = s.broker.submit({ n: 2 });
  clock.advance(59_999);
  assert.equal(s.broker.ended, null, "still resumable at 59.999 s");
  clock.advance(1);
  assert.equal(s.broker.ended, "not resumed");
  assert.deepEqual(await sent, { outcome: "unknown", reason: "not resumed" });
  assert.deepEqual(await unsent, { outcome: "not_run", reason: "not resumed" });
});

function awaitLink() { return linkModule; }
const linkModule = await import("../lib/fleet/channel/link.mjs");
