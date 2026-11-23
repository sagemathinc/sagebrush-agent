// The browser relay's slots (lib/fleet/relay/slots.mjs): identity by the full tuple, candidates and the handshake
// gate, the commit switch, forwarding, the 1 MiB cap, the no-progress stall, expiry, revocation and the limits from
// verified facts. Fake sockets and a manual clock; the same semantics as the channel's FakeRelay.

import assert from "node:assert/strict";
import { test } from "node:test";
import { newId } from "../lib/fleet/index.mjs";
import { Slots, SLOTS, CODES, RelayRefusal } from "../lib/fleet/relay/slots.mjs";
import { manualClock, FakeWs, ids, facts } from "./fleet-relay-harness.mjs";

function setup(limits = SLOTS) {
  const clock = manualClock(), log = [];
  return { clock, log, slots: new Slots({ clock, log: (o) => log.push(o), limits }) };
}
/** Open both sides of a tuple; returns { host, app, hf, af } with attached fake sockets. */
function pair(slots, t, over = {}) {
  const hf = facts("host", t, over), af = facts("app", t, over);
  const host = new FakeWs(), app = new FakeWs();
  slots.reserve(hf).attach(host);
  slots.reserve(af).attach(app);
  return { host, app, hf, af };
}
const commitOf = (hf, af, over = {}) => ({ fleet: hf.fleet, host: hf.host, agent: hf.agent, browser_gen: hf.browser_gen, session: hf.session, resume_n: hf.resume_n,
  host_gen: hf.host_gen, host_nonce: hf.nonce, app_request: af.request, ...over });
const refused = (f, code) => assert.throws(f, (e) => e instanceof RelayRefusal && e.code === code);
const handshake = (p) => { p.app.in("m1"); p.host.in("m2"); p.host.take(); p.app.take(); }; // (both ends read)

test("a candidate pair passes exactly the handshake's two messages, app then host; a third, a text message or a wrong order closes only it", () => {
  const { slots } = setup(), t = ids();
  const p = pair(slots, t);
  p.app.in("m1");
  assert.deepEqual(p.host.sent.map(String), ["m1"]);
  p.host.in("m2");
  assert.deepEqual(p.app.sent.map(String), ["m2"]);
  p.app.in("m3");
  assert.equal(p.app.closed.code, CODES.handshake);
  assert.equal(p.host.closed.code, CODES.handshake);
  for (const [what, act, code] of [["host first", (q) => q.host.in("x"), CODES.handshake], ["text", (q) => q.app.in("x", false), CODES.binaryOnly]]) {
    const s = setup().slots, q = pair(s, ids());
    act(q);
    assert.equal(q.app.closed?.code, code, what);
  }
  const s = setup().slots, u = ids(), hf = facts("host", u), host = new FakeWs();
  s.reserve(hf).attach(host);
  host.in("x"); // (no peer yet)
  assert.equal(host.closed.code, CODES.handshake);
});

test("the commit switches the named candidate once, by full tuple, resume_n, the signer's host_gen and its two opens; a mismatch or a replay changes nothing", () => {
  const { slots } = setup(), t = ids();
  const p = pair(slots, t);
  handshake(p);
  for (const [what, over] of [["another host", { host: newId() }], ["another agent", { agent: newId() }], ["another gen", { browser_gen: 2 }], ["another session", { session: newId() }],
    ["another resume_n", { resume_n: 1 }], ["another host_gen", { host_gen: 2 }], ["another host nonce", { host_nonce: newId() }], ["another app request", { app_request: newId() }]]) {
    refused(() => slots.commit(commitOf(p.hf, p.af, over)), "not_found");
    assert.equal(p.host.closed, null, what);
  }
  slots.commit(commitOf(p.hf, p.af));
  refused(() => slots.commit(commitOf(p.hf, p.af)), "not_found"); // (no longer a candidate)
  p.app.in("data");
  p.host.in("more");
  assert.deepEqual(p.host.sent.map(String), ["m1", "data"]);
  assert.deepEqual(p.app.sent.map(String), ["m2", "more"]);
});

test("a commit closes that agent's active pair, the same tuple's other slots and older sessions, and nothing of another agent", () => {
  const { slots } = setup(), t = ids();
  const old = pair(slots, t);
  handshake(old);
  slots.commit(commitOf(old.hf, old.af));
  const other = { ...ids(), fleet: t.fleet, host: t.host }; // (another agent on the same host)
  const keep = pair(slots, other);
  handshake(keep);
  slots.commit(commitOf(keep.hf, keep.af));
  const resume = pair(slots, t, { resume_n: 1 });
  handshake(resume);
  slots.commit(commitOf(resume.hf, resume.af));
  assert.equal(old.app.closed.code, CODES.replaced);
  assert.equal(keep.app.closed, null);
  assert.equal(resume.app.closed, null);
  const newer = pair(slots, { ...t, session: newId() }, { browser_gen: 2 });
  handshake(newer);
  slots.commit(commitOf(newer.hf, newer.af));
  assert.equal(resume.app.closed.code, CODES.replaced);
  assert.equal(keep.app.closed, null);
});

test("candidates: another resume_n or a taken side is in_progress; two per agent; a failed candidate never touches the active pair; 30 s expiry", () => {
  const { slots, clock } = setup(), t = ids();
  const active = pair(slots, t);
  handshake(active);
  slots.commit(commitOf(active.hf, active.af));
  slots.reserve(facts("host", t, { resume_n: 1 }));
  refused(() => slots.reserve(facts("host", t, { resume_n: 1 })), "in_progress");
  refused(() => slots.reserve(facts("app", t, { resume_n: 2 })), "in_progress");
  slots.reserve(facts("host", { ...t, session: newId() }, { browser_gen: 2 }));
  refused(() => slots.reserve(facts("host", { ...t, session: newId() }, { browser_gen: 3 })), "limit");
  clock.advance(SLOTS.pendingMs - 1);
  assert.equal(slots.sockets, 4);
  clock.advance(1);
  assert.equal(slots.sockets, 2, "both candidates expired; the active pair stays");
  assert.equal(active.app.closed, null);
  const bad = pair(slots, t, { resume_n: 1 });
  bad.host.in("x"); // (outside the handshake)
  assert.equal(bad.host.closed.code, CODES.handshake);
  assert.equal(active.app.closed, null);
});

test("forwarding: a send past the 1 MiB queue closes the slot", () => {
  const { slots } = setup(), p = pair(slots, ids());
  handshake(p);
  slots.commit(commitOf(p.hf, p.af));
  p.host.bufferedAmount = SLOTS.queueMax - 10;
  p.app.in(Buffer.alloc(10));
  assert.equal(p.host.closed, null);
  p.app.in(Buffer.alloc(1));
  assert.equal(p.host.closed.code, CODES.tooLarge);
});

test("the stall: below the cap, a queue that never moves closes at exactly 30 s; progress restarts it; an empty queue clears it; one timer per socket; a late drain changes nothing", () => {
  const live = () => { const s = setup(), p = pair(s.slots, ids()); handshake(p); s.slots.commit(commitOf(p.hf, p.af)); p.host.take(); p.app.take(); return { ...s, p }; };
  { const { clock, p } = live();
    p.app.in(Buffer.alloc(1000));
    clock.advance(SLOTS.stallMs - 1);
    assert.equal(p.host.closed, null);
    clock.advance(1);
    assert.equal(p.host.closed.code, CODES.stalled);
    p.host.take(); // (late)
    clock.advance(SLOTS.stallMs);
    assert.equal(p.app.closed.code, CODES.stalled); }
  { const { clock, p } = live();
    p.app.in(Buffer.alloc(1000));
    clock.advance(20_000);
    p.host.take(400); // (progress, not a full drain)
    clock.advance(SLOTS.pollMs);
    clock.advance(SLOTS.stallMs - SLOTS.pollMs - 1);
    assert.equal(p.host.closed, null, "restarted at the progress");
    clock.advance(SLOTS.pollMs + 1);
    assert.equal(p.host.closed.code, CODES.stalled); }
  { const { clock, p, slots } = live();
    for (let i = 0; i < 5; i++) { p.app.in(Buffer.alloc(100)); clock.advance(29_000); p.host.take(); clock.advance(SLOTS.pollMs); }
    assert.equal(p.host.closed, null);
    const slot = [...slots.slots.values()][0];
    assert.ok(slot.timers.size <= 1, `timers ${slot.timers.size}`); }
});

test("the stall restarts on any decrease from the last observed size: growth, then a partial drain above the old low, is progress", () => {
  const { slots, clock } = setup(), p = pair(slots, ids());
  handshake(p); slots.commit(commitOf(p.hf, p.af));
  p.app.in(Buffer.alloc(10)); // (t = 0: 10 queued)
  clock.advance(10_000);
  p.app.in(Buffer.alloc(90)); // (t = 10 s: 100 queued)
  clock.advance(1000);
  p.host.take(20); // (t = 11 s: 80 queued, above the old low of 10)
  clock.advance(SLOTS.pollMs);
  clock.advance(SLOTS.stallMs - 2 * SLOTS.pollMs - 1);
  assert.equal(p.host.closed, null, "not at 30 s: the drain at 11 s was progress");
  clock.advance(SLOTS.pollMs + 11_000 + 1);
  assert.equal(p.host.closed?.code, CODES.stalled, "30 s after the last progress");
});

test("revocation and expiry: an agent, account or host change closes its slots; each side's end closes the pair, and a null host grant end never removes the app's", () => {
  const { slots } = setup(), t = ids(), u = ids(), w = ids();
  const a = pair(slots, t), b = pair(slots, u), c = pair(slots, w);
  slots.revoke("account", t.account);
  assert.equal(a.app.closed.code, CODES.revoked);
  assert.equal(b.app.closed, null);
  slots.revoke("agent", u.agent);
  assert.equal(b.host.closed.code, CODES.revoked);
  slots.revoke("host", w.host);
  assert.equal(c.app.closed.code, CODES.revoked);
  for (const [what, hostOver, appOver, at] of [
    ["the app's record end", {}, { not_after_ms: Date.now() + 5000 }, 5000],
    ["the account session's expiry", {}, { account_session_expires_ms: Date.now() + 5000 }, 5000],
    ["the host's grant end", { not_after_ms: Date.now() + 5000 }, {}, 5000],
  ]) {
    const s2 = setup(), x = ids();
    const hf = facts("host", x, hostOver), af = facts("app", x, appOver), host = new FakeWs(), app = new FakeWs();
    s2.slots.reserve(hf).attach(host); s2.slots.reserve(af).attach(app);
    s2.clock.advance(at - 1000);
    assert.equal(app.closed, null, what);
    s2.clock.advance(2000);
    assert.equal(app.closed?.code, CODES.revoked, what);
  }
  refused(() => setup().slots.reserve(facts("app", ids(), { not_after_ms: Date.now() - 1 })), "grant_expired");
});

test("limits from verified facts: per agent, per host, per account, sockets in all, and opens a minute", () => {
  const lim = { ...SLOTS, perAgent: 2, perHost: 3, perAccount: 2, sockets: 6, opensPerMinute: 3 };
  { const { slots } = setup(lim), t = ids();
    pair(slots, t);
    refused(() => slots.reserve(facts("host", { ...t, session: newId() }, { browser_gen: 2 })), "limit"); }
  { const { slots } = setup(lim), t = ids();
    slots.reserve(facts("app", t)); slots.reserve(facts("app", { ...ids(), account: t.account }));
    refused(() => slots.reserve(facts("app", { ...ids(), account: t.account })), "limit"); }
  { const { slots, clock } = setup({ ...lim, perAccount: 99 }), t = ids();
    for (let i = 0; i < 3; i++) slots.reserve(facts("host", { ...ids(), host: t.host }));
    refused(() => slots.reserve(facts("host", { ...ids(), host: t.host })), "limit");
    clock.advance(60_000);
    void clock; }
});

test("memory: the verified rate history holds only the last minute's opens, however many hosts and accounts come and go", () => {
  const { slots, clock } = setup();
  for (let minute = 0; minute < 20; minute++) {
    for (let i = 0; i < 10; i++) slots.reserve(facts("host", ids()));
    assert.ok(slots.opens.keys <= 20 && slots.opens.size <= 10, `minute ${minute}: ${slots.opens.keys} keys`);
    clock.advance(60_000);
  }
  clock.advance(60_000);
  assert.equal(slots.opens.keys, 0);
  assert.equal(slots.opens.size, 0);
});
