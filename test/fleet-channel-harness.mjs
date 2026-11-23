// A harness for the browser channel's session tests (fleet-channel-session.test.mjs, fleet-channel-matrix.test.mjs):
// a real Noise_IK handshake per transport, an in-memory wire whose two directions the test drives (deliver, hold,
// drop, cut), a manual clock, and a fake app executor with an effect counter and causal barriers.
import { initiator, responder, x25519Generate } from "../lib/fleet/channel/noise.mjs";
import { decodeFrame } from "../lib/fleet/channel/frames.mjs";
import { brokerSession } from "../lib/fleet/channel/broker.mjs";
import { appSession } from "../lib/fleet/channel/app.mjs";
import { FleetError } from "../lib/fleet/index.mjs";
import { link } from "../lib/fleet/channel/link.mjs";

const PROLOGUE = new TextEncoder().encode("sagebrush-browser/1 test");
const EMPTY = new Uint8Array(0);

/** One handshake: each end's transport halves. */
export function handshake() {
  const hs = x25519Generate(), as = x25519Generate();
  const I = initiator({ s: as, rs: hs.raw, prologue: PROLOGUE });
  const R = responder({ s: hs, prologue: PROLOGUE });
  R.readMessage1(I.writeMessage1(EMPTY));
  const r2 = R.writeMessage2(EMPTY);
  const i2 = I.readMessage2(r2.message);
  return { app: { send: i2.send, receive: i2.receive }, broker: { send: r2.send, receive: r2.receive } };
}

/** A manual clock: timers run only when the test advances it. */
export function manualClock(start = 1_800_000_000_000) {
  let t = start, id = 0;
  const timers = new Map();
  return {
    now: () => t,
    setTimeout(fn, ms) { const k = ++id; timers.set(k, { at: t + ms, fn }); return k; },
    clearTimeout(k) { timers.delete(k); },
    advance(ms) {
      const until = t + ms;
      for (;;) {
        const next = [...timers.entries()].filter(([, x]) => x.at <= until).sort((a, b) => a[1].at - b[1].at)[0];
        if (!next) break;
        timers.delete(next[0]);
        t = next[1].at;
        next[1].fn();
      }
      t = until;
    },
    get pending() { return timers.size; },
  };
}

/** A sink that hands each written message to a queue, calling back at once. `log` collects what was written. */
export function sink(queue) {
  return { written: 0, write(ct, cb) { queue.push(ct); this.written += ct.length; cb(); return true; }, once() {}, end() { this.ended = true; }, destroy() { this.destroyed = true; } };
}

/** Let promises and microtasks run. */
export const settle = async (n = 5) => { for (let i = 0; i < n; i++) await new Promise((r) => setImmediate(r)); };

/**
 * One transport between a broker session and an app session: a fresh handshake, both attached. toApp and toBroker
 * hold the Noise messages in flight; pump() delivers both directions until quiet. What each side sent is in the
 * sessions' traces (sessions()'s brokerSent and appSent).
 */
export function connect(broker, app, { order = "broker-first" } = {}) {
  const hs = handshake();
  const toApp = [], toBroker = [];
  const bl = broker.attach({ cipher: hs.broker, sink: sink(toApp) });
  const al = app.attach({ cipher: hs.app, sink: sink(toBroker) });
  const t = {
    bl, al, toApp, toBroker, hs,
    deliverToApp(n = Infinity) { for (let i = 0; i < n && toApp.length; i++) al.deliver(toApp.shift()); },
    deliverToBroker(n = Infinity) { for (let i = 0; i < n && toBroker.length; i++) bl.deliver(toBroker.shift()); },
    async pump(rounds = 50) {
      for (let i = 0; i < rounds; i++) {
        await settle();
        if (!toApp.length && !toBroker.length) { await settle(); if (!toApp.length && !toBroker.length) return; }
        if (order === "broker-first") { t.deliverToApp(); t.deliverToBroker(); } else { t.deliverToBroker(); t.deliverToApp(); }
      }
    },
    /** The transport closes under both ends (the relay or the network): in-flight messages are lost. */
    cut() { toApp.length = 0; toBroker.length = 0; bl.lost("cut"); al.lost("cut"); },
  };
  return t;
}

/** A fake app executor: commands { n, click?, hold?, fail? }; clicks count effects; holds wait at a barrier. */
export function fakeExecutor() {
  const x = { clicks: 0, calls: 0, started: [], barriers: new Map(), answers: [] };
  x.barrier = (n) => { let release; const p = new Promise((r) => { release = r; }); x.barriers.set(n, { p, release }); return release; };
  x.execute = async (command, { seq }) => {
    x.calls++;
    x.started.push(seq);
    const b = x.barriers.get(command.n);
    if (command.hold === "before") await b.p;
    if (command.click) x.clicks++;
    if (command.hold === "after") await b.p;
    if (command.fail) throw new Error("the command path failed");
    return { n: command.n, ok: true };
  };
  return x;
}

export function sessions({ clock = manualClock(), brokerOpts = {}, appOpts = {} } = {}) {
  const exec = fakeExecutor();
  const events = [], states = [], brokerSent = [], appSent = [];
  const broker = brokerSession({ clock, onEvent: (e) => events.push(e), ...brokerOpts, linkOptions: { onSend: (kind, seq, value) => brokerSent.push({ kind, seq, value }), ...brokerOpts.linkOptions } });
  const app = appSession({ execute: exec.execute, validate: (c) => !c.bad, clock, onState: (s) => states.push(s), ...appOpts, linkOptions: { onSend: (kind, seq, value) => appSent.push({ kind, seq, value }), ...appOpts.linkOptions } });
  return { clock, exec, broker, app, events, states, brokerSent, appSent };
}

/**
 * A hand-driven peer for a session under test: a bare link of `role` on `cipher`, writing to `out`. It records what it
 * receives, and sends whatever the test asks (even what a correct peer never would).
 */
export function rawPeer(role, cipher, out, { ackLimit = () => Number.MAX_SAFE_INTEGER, highWater = 0, clock = manualClock() } = {}) {
  const got = [];
  const peer = { got, ended: null, ctl: 0 };
  peer.l = link({ role, cipher, sink: sink(out), clock, ackLimit, highWater, onMessage: (m) => got.push(m), onEnd: (reason, fatal) => { peer.ended = { reason, fatal }; } });
  return peer;
}

/** A broker session against a raw app on a fresh transport. */
export function brokerVsRaw(broker, opts) {
  const hs = handshake();
  const toApp = [], toBroker = [];
  const bl = broker.attach({ cipher: hs.broker, sink: sink(toApp) });
  const raw = rawPeer("app", hs.app, toBroker, opts);
  return {
    bl, raw, toApp, toBroker,
    flush() { while (toApp.length) raw.l.deliver(toApp.shift()); while (toBroker.length) bl.deliver(toBroker.shift()); },
  };
}

/** An app session against a raw broker on a fresh transport. */
export function appVsRaw(app, opts) {
  const hs = handshake();
  const toApp = [], toBroker = [];
  const al = app.attach({ cipher: hs.app, sink: sink(toBroker) });
  const raw = rawPeer("broker", hs.broker, toApp, opts);
  return {
    al, raw, toApp, toBroker,
    async flush() { for (let i = 0; i < 20; i++) { await settle(); if (!toApp.length && !toBroker.length) return; while (toApp.length) al.deliver(toApp.shift()); while (toBroker.length) raw.l.deliver(toBroker.shift()); } },
  };
}

export const code = async (fn) => { try { await fn(); return "ok"; } catch (e) { if (e instanceof FleetError) return e.code; throw e; } };
export { decodeFrame };
