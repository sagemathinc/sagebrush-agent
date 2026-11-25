// The browser channel's §9.10 matrix (O11 §9.10; design agent-autonomous-browser-channel.md r4.2 §7): a broker
// session and a JS fake app over real Noise transports, cut at each point with causal barriers, each with and without a
// resume. The fake app's click counter is the effect oracle: at most one click; exactly one where the effect ran; the
// outcome is the definitive result after a resume, `not run` only for a command never sent or explicitly refused,
// `unknown` for every other sent command after the session is lost, and never `not run` when a click happened.
// (This oracle is the fake app's; the app's net sidecar is qualified separately.)
import assert from "node:assert/strict";
import { test } from "node:test";
import { connect, manualClock, sessions, settle } from "./fleet-channel-harness.mjs";

const RESUME_MS = 60_000;

/**
 * One run: `setup(s, t1)` drives the first transport up to the cut point and returns the command's outcome promise;
 * then the transport is cut, and either a resume follows (a new transport, everything released) or the session is
 * left to lapse (the resume window passes; the app, too, gives up).
 */
async function run(setup, { resume }) {
  const clock = manualClock();
  const s = sessions({ clock });
  const t1 = connect(s.broker, s.app);
  const { outcome, release = () => {} } = await setup(s, t1);
  t1.cut();
  if (resume) {
    const t2 = connect(s.broker, s.app);
    release();
    await t2.pump(100);
  } else {
    clock.advance(RESUME_MS);
    release();
    await settle(10);
  }
  return { o: await outcome, clicks: s.exec.clicks, calls: s.exec.calls, s };
}

// the cut points (O11 §9.10)
const CUTS = {
  "before the first fragment is sent": async (s) => {
    // (the transport is lost before the command is submitted: it is never sent on it)
    s.broker.end; // (no-op: the command comes after the cut, see below)
    return { outcome: null };
  },
  "sent but not admitted": async (s, t) => {
    const outcome = s.broker.submit({ n: 1, click: true });
    await settle();
    t.toApp.length = 0; // (the command's frames never reach the app)
    return { outcome };
  },
  "admitted, the recv lost, with the effect": async (s, t) => {
    const release = s.exec.barrier(1);
    const outcome = s.broker.submit({ n: 1, click: true, hold: "after" });
    await settle();
    t.deliverToApp();
    await settle();
    t.toBroker.length = 0;
    return { outcome, release };
  },
  "admitted, the recv lost, without the effect (held before it)": async (s, t) => {
    const release = s.exec.barrier(1);
    const outcome = s.broker.submit({ n: 1, click: true, hold: "before" });
    await settle();
    t.deliverToApp();
    await settle();
    t.toBroker.length = 0;
    return { outcome, release };
  },
  "after the effect, before the result": async (s, t) => {
    const release = s.exec.barrier(1);
    const outcome = s.broker.submit({ n: 1, click: true, hold: "after" });
    await settle();
    t.deliverToApp();
    await t.pump(); // (admitted, its recv delivered; the click happened, the result held)
    return { outcome, release };
  },
  "after the result, before the rack": async (s, t) => {
    const outcome = s.broker.submit({ n: 1, click: true });
    await settle();
    t.deliverToApp();
    await settle();
    t.deliverToBroker(); // (the result is delivered; the broker's ack waits, and is lost)
    await settle();
    t.toApp.length = 0;
    return { outcome };
  },
};

for (const [cut, setup] of Object.entries(CUTS)) {
  for (const resume of [true, false]) {
    test(`§9.10: ${cut}, ${resume ? "with a resume" : "without one"}`, async () => {
      let r;
      if (cut === "before the first fragment is sent") {
        // (the transport is lost first; the command is submitted while there is none)
        const clock = manualClock();
        const s = sessions({ clock });
        const t1 = connect(s.broker, s.app);
        await t1.pump();
        t1.cut();
        const outcome = s.broker.submit({ n: 1, click: true });
        if (resume) { const t2 = connect(s.broker, s.app); await t2.pump(); } else clock.advance(RESUME_MS);
        r = { o: await outcome, clicks: s.exec.clicks, calls: s.exec.calls };
        if (resume) assert.deepEqual([r.o.outcome, r.clicks], ["result", 1]);
        else assert.deepEqual([r.o.outcome, r.clicks, r.calls], ["not_run", 0, 0], "never sent: not run, and no effect");
        return;
      }
      r = await run(setup, { resume });
      assert.ok(r.clicks <= 1, `at most one click (${r.clicks})`);
      assert.ok(r.calls <= 1, `at most one execution (${r.calls})`);
      if (r.clicks > 0) assert.notEqual(r.o.outcome, "not_run", "never not run when the oracle shows a click");
      if (resume) {
        assert.equal(r.o.outcome, "result", "the definitive result after a resume");
        assert.equal(r.clicks, 1, "exactly one click");
      } else if (cut === "after the result, before the rack") {
        assert.equal(r.o.outcome, "result", "the result was delivered before the cut");
        assert.equal(r.clicks, 1);
      } else {
        assert.equal(r.o.outcome, "unknown", "sent, then the session was lost");
      }
      if (cut.includes("with the effect") || cut.startsWith("after the effect")) assert.equal(r.clicks, 1, "the effect ran, once");
    });
  }
}

test("§9.10: two concurrent resumes: the later transport wins; the earlier one's frames have no effect; one outcome, one click", async () => {
  const s = sessions();
  const t1 = connect(s.broker, s.app);
  const release = s.exec.barrier(1);
  const outcome = s.broker.submit({ n: 1, click: true, hold: "after" });
  await settle();
  t1.deliverToApp();
  await settle();
  t1.cut();
  // (two transports come up; the second replaces the first on both ends before the first delivers anything)
  const a = connect(s.broker, s.app);
  const b = connect(s.broker, s.app);
  assert.ok(a.bl.ended && a.al.ended, "the earlier transport is closed for good");
  a.deliverToApp();
  a.deliverToBroker(); // (nothing: an ended link ignores what arrives)
  release();
  await b.pump();
  assert.deepEqual([(await outcome).outcome, s.exec.clicks, s.exec.calls], ["result", 1, 1]);
});

test("§9.10: the same seq with a different body ends the session; a duplicate after rack ends it", async () => {
  const { appVsRaw } = await import("./fleet-channel-harness.mjs");
  const a = sessions();
  const w = appVsRaw(a.app);
  w.raw.l.send("ctl", 1, { ctl: "ping", t: 1 }, { recv: 0, rack: 0 });
  w.raw.l.send("cmd", 1, { command: { n: 1, hold: "before" } }, { recv: 0, rack: 0 });
  a.exec.barrier(1);
  await w.flush();
  // (a resent seq 1 with another body: on a new transport, since one transport can't repeat a cmd seq)
  w.al.lost("cut");
  const w2 = appVsRaw(a.app, { highWater: 0 });
  w2.raw.l.send("ctl", 1, { ctl: "ping", t: 1 }, { recv: 0, rack: 0 });
  w2.raw.l.send("cmd", 1, { command: { n: 1, other: true } }, { recv: 0, rack: 0 });
  await w2.flush();
  assert.ok(a.app.ended, "a different body at an admitted seq");

  const b = sessions();
  const v = appVsRaw(b.app);
  v.raw.l.send("ctl", 1, { ctl: "ping", t: 1 }, { recv: 0, rack: 0 });
  v.raw.l.send("cmd", 1, { command: { n: 1 } }, { recv: 0, rack: 0 });
  await v.flush();
  v.raw.l.send("ctl", 2, { ctl: "ping", t: 2 }, { recv: 0, rack: 1 });
  await v.flush();
  assert.equal(b.app.rack, 1);
  v.al.lost("cut");
  const v2 = appVsRaw(b.app, { highWater: 1 });
  v2.raw.l.send("ctl", 1, { ctl: "ping", t: 1 }, { recv: 0, rack: 1 });
  v2.raw.l.send("cmd", 1, { command: { n: 1 } }, { recv: 0, rack: 1 });
  await v2.flush();
  assert.ok(b.app.ended, "a duplicate after rack");

  // a command seq that skips ahead, on a fresh transport (where its first cmd may carry any seq)
  const c = sessions();
  const x = appVsRaw(c.app);
  x.raw.l.send("ctl", 1, { ctl: "ping", t: 1 }, { recv: 0, rack: 0 });
  x.raw.l.send("cmd", 1, { command: { n: 1 } }, { recv: 0, rack: 0 });
  await x.flush();
  x.al.lost("cut");
  const x2 = appVsRaw(c.app, { highWater: 1 });
  x2.raw.l.send("ctl", 1, { ctl: "ping", t: 1 }, { recv: 0, rack: 0 });
  x2.raw.l.send("cmd", 3, { command: { n: 3 } }, { recv: 0, rack: 0 });
  await x2.flush();
  assert.ok(c.app.ended, "a skipped command seq");
});
