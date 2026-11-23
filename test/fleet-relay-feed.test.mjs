// The browser relay's durable store (lib/fleet/relay/store.mjs) and revocation feed (feed.mjs), against a fake Worker
// that speaks the core's control contract. The clock is stepped (async answers run between steps), so each bound is
// observed as the relay would meet it: a change closes its slots at the next poll (within 8 s); each call is aborted
// at 3 s; the independent fail-close fires at exactly 30 s and nothing but a committed success resets it; a quiet
// healthy feed keeps pairs open; cursor_expired closes everything and restarts from since=0 without counting.

import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { openStore, CONSUMED_MS } from "../lib/fleet/relay/store.mjs";
import { controlClient, CONTROL } from "../lib/fleet/relay/control.mjs";
import { controlKey } from "../lib/fleet/core/control.mjs";
import { Slots, CODES } from "../lib/fleet/relay/slots.mjs";
import { Feed, FEED } from "../lib/fleet/relay/feed.mjs";
import { manualClock, run, FakeWs, FakeWorker, ids, facts, settle, KEY_TEXT } from "./fleet-relay-harness.mjs";

const KEY = controlKey(KEY_TEXT());

test("the store: an id is consumed once, by kind, and stays consumed across a reopen until its window passes; the cursor only moves forward, survives a reopen, and resets only on purpose", () => {
  const dir = mkdtempSync(join(tmpdir(), "relay-store-")), path = join(dir, "relay.sqlite");
  try {
    let s = openStore(path);
    assert.equal(s.consume("host", "n1", 1000), true);
    assert.equal(s.consume("host", "n1", 1000), false);
    assert.equal(s.consume("app", "n1", 1000), true, "kinds are separate");
    assert.equal(s.cursor(), -1);
    assert.equal(s.advance(5), true);
    assert.equal(s.advance(5), false);
    assert.equal(s.advance(4), false);
    s.close();
    s = openStore(path);
    assert.equal(s.consume("host", "n1", 2000), false, "after a restart");
    assert.equal(s.consumed("host", "n1"), true);
    assert.equal(s.cursor(), 5, "never rolled back");
    s.reset();
    assert.equal(s.cursor(), -1);
    s.prune(1000 + CONSUMED_MS);
    assert.equal(s.consume("host", "n1", 1000 + CONSUMED_MS), true, "after its window");
    assert.throws(() => s.consume("other", "x", 1));
    assert.throws(() => s.advance(-1));
    s.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

function setup({ store = openStore(":memory:") } = {}) {
  const clock = manualClock(), worker = new FakeWorker(KEY), log = [];
  const control = controlClient({ transport: worker.transport, key: KEY });
  const slots = new Slots({ clock, log: () => {} });
  const feed = new Feed({ control, store, slots, clock, log: (o) => log.push(o) });
  return { clock, worker, slots, feed, store, log, control };
}
/** An active pair (committed), whose ends read everything. */
const livePair = (slots, t) => {
  const host = new FakeWs(), app = new FakeWs(), hf = facts("host", t), af = facts("app", t);
  slots.reserve(hf).attach(host);
  slots.reserve(af).attach(app);
  app.in("m1"); host.in("m2"); host.take(); app.take();
  slots.commit({ ...t, browser_gen: 1, resume_n: 0, host_gen: 1, host_nonce: hf.nonce, app_request: af.request });
  return { host, app };
};
const fail = () => { throw new Error("down"); };

test("opens wait for the first success (from since=0); a quiet healthy feed keeps pairs open well past 30 s", async () => {
  const { clock, feed, slots, worker } = setup();
  const sinces = [];
  worker.feedQueue.push((since) => { sinces.push(since); return worker.empty(since); });
  assert.equal(feed.available, false);
  feed.start(); await settle();
  assert.deepEqual(sinces, [0], "the first poll asks from now");
  assert.equal(feed.available, true);
  const p = livePair(slots, ids());
  await run(clock, 100_000);
  assert.equal(p.app.closed, null, "100 s of empty answers");
  feed.stop();
});

test("a change recorded just after a poll closes the affected pairs at the next poll, within 8 s, by agent, account or host; other pairs stay", async () => {
  for (const kind of ["agents", "accounts", "hosts"]) {
    const { clock, feed, slots, worker } = setup();
    feed.start(); await settle();
    const t = ids(), u = ids();
    const a = livePair(slots, t), b = livePair(slots, u);
    const id = { agents: t.agent, accounts: t.account, hosts: t.host }[kind];
    worker.feedQueue.push(undefined, (since) => worker.empty(since, { [kind]: [{ id, epoch: 1 }] }));
    await run(clock, FEED.pollMs, 100);
    assert.equal(a.app.closed, null, kind);
    await run(clock, FEED.pollMs, 100);
    assert.equal(a.app.closed?.code, CODES.revoked, kind);
    assert.equal(b.app.closed, null, kind);
    const k = kind.slice(0, -1);
    assert.equal(feed.current({ account: 0, agent: 0, host: 0 }, { agent: t.agent, account: t.account, host: t.host }), false, `an older admit answer is no longer current (${k})`);
    feed.stop();
  }
});

test("the fail-close: at exactly 30 s without a success everything closes and opens are refused; errors, a since that isn't ours, lower epochs and failed cursor writes never reset it", async () => {
  const cases = [
    ["an error", () => fail],
    ["another since", (w) => (since) => w.empty(since + 1)],
    ["a lower epoch than one known", (w, feed, t) => { feed.current({ agent: 5, account: 0, host: 0 }, { agent: t.agent, account: "x", host: "y" }); return (since) => w.empty(since, { agents: [{ id: t.agent, epoch: 4 }] }); }],
    ["a failed cursor write", (w, feed, t, store) => { store.advance = () => { throw new Error("disk full"); }; return undefined; }],
  ];
  for (const [what, make] of cases) {
    const store = openStore(":memory:"), { clock, feed, slots, worker } = setup({ store });
    feed.start(); await settle();
    const p = livePair(slots, ids()), t = ids();
    const next = make(worker, feed, t, store);
    for (let i = 0; i < 12; i++) worker.feedQueue.push(next);
    await run(clock, FEED.failMs - 500, 500);
    clock.advance(499); await settle();
    assert.equal(p.app.closed, null, what);
    clock.advance(1); await settle();
    assert.equal(p.app.closed?.code, CODES.unavailable, what);
    assert.equal(feed.available, false, what);
    feed.stop();
  }
});

test("cursor_expired closes everything at once, resets the cursor, and restarts from since=0; it isn't a success, so the fail-close still fires at 30 s", async () => {
  const { clock, feed, slots, worker, store } = setup();
  feed.start(); await settle();
  const before = store.cursor();
  const p = livePair(slots, ids());
  const sinces = [];
  worker.feedQueue.push((since) => ({ result: "refused", since, code: "cursor_expired" }));
  for (let i = 0; i < 12; i++) worker.feedQueue.push((since) => { sinces.push(since); return fail(); });
  await run(clock, FEED.pollMs, 100);
  assert.equal(p.app.closed?.code, CODES.unavailable, "closed at once");
  assert.equal(store.cursor(), -1);
  assert.ok(before > 0);
  await run(clock, FEED.pollMs, 100);
  assert.equal(sinces[0], 0, "the next poll starts from since=0");
  assert.equal(feed.available, true, "not yet failed closed: 30 s haven't passed since the last success");
  await run(clock, FEED.failMs - 2 * FEED.pollMs - 100, 100);
  assert.equal(feed.available, true, "at 29.9 s");
  await run(clock, 100, 100);
  assert.equal(feed.available, false, "the fail-close fired at 30 s after the last success");
  feed.stop();
});

test("more: true polls again at once, at most 8 times in a row, each answer checked; then the normal interval", async () => {
  const { clock, feed, worker } = setup();
  let polls = 0;
  for (let i = 0; i < 20; i++) worker.feedQueue.push((since) => { polls++; return worker.empty(since, { more: true }); });
  feed.start(); await settle(40);
  assert.equal(polls, 9, "the first poll and 8 more at once");
  await run(clock, FEED.pollMs - 100, 100);
  assert.equal(polls, 9);
  await run(clock, 100, 100); await settle(40);
  assert.equal(polls, 18);
  feed.stop();
});

test("a call held across the 30 s mark: aborted at its own 3 s deadline, everything closes at exactly 30 s, and its late answer changes nothing", async () => {
  const { clock, feed, slots, worker } = setup();
  feed.start(); await settle();
  const p = livePair(slots, ids());
  let release, heldSignal;
  const held = new Promise((r) => { release = r; });
  worker.feedQueue.push(fail, fail, fail, fail, async (since, signal) => { heldSignal = signal; await held; return worker.empty(since); }, fail);
  await run(clock, 25_000, 100);
  await run(clock, CONTROL.feedMs - 100, 100);
  assert.equal(heldSignal.aborted, false);
  await run(clock, 100, 100);
  assert.equal(heldSignal.aborted, true, "aborted at its own 3 s deadline");
  await run(clock, FEED.failMs - 25_000 - CONTROL.feedMs - 100, 100);
  assert.equal(p.app.closed, null);
  await run(clock, 100, 100);
  assert.equal(p.app.closed?.code, CODES.unavailable, "at 30 s");
  release(); await settle(20);
  assert.equal(feed.available, false, "the late answer doesn't count");
  await run(clock, 2 * FEED.pollMs, 100);
  assert.equal(feed.available, true, "a fresh poll's success does");
  feed.stop();
});

test("a restart never rolls the cursor back: an answer behind the committed cursor isn't a success", async () => {
  const dir = mkdtempSync(join(tmpdir(), "relay-cursor-")), path = join(dir, "r.sqlite");
  try {
    let s = openStore(path);
    s.advance(100); s.close();
    s = openStore(path);
    const { clock, feed, worker } = setup({ store: s });
    const sinces = [];
    worker.feedQueue.push((since) => { sinces.push(since); return { result: "ok", since, cursor: since + 1, at_ms: 1, more: false, agents: [], accounts: [], hosts: [] }; });
    worker.feedQueue.push((since) => ({ result: "ok", since: 50, cursor: 60, at_ms: 1, more: false, agents: [], accounts: [], hosts: [] }));
    feed.start(); await settle();
    assert.deepEqual(sinces, [100], "it asks from the committed cursor");
    assert.equal(feed.available, true);
    assert.equal(s.cursor(), 101);
    await run(clock, FEED.pollMs, 100);
    assert.equal(s.cursor(), 101, "an answer for another since changes nothing");
    feed.stop(); s.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
