// The per-turn advisor (advisor r3.3 to r3.5). Part 1 is cocalc-ai's own tests, PORTED row for row from commit 2f21405
// (src/packages/util/ai/claude-pool.test.ts: turn cost, windows, pick, usage history, reservations; and
// src/packages/util/ai/claude-usage.test.ts's snapshot rows), with profile ids for credential ids. Part 2 is the
// host's rows pinning every constant and edge as LITERALS (r3.4, r3.5). Part 3 is the locked pick
// (server/agents/claude-pool.ts's limit marking, turn costs and reservation recording) and SEC's clearLimited.
import assert from "node:assert/strict";
import { test } from "node:test";
import {
  appendTurnCostSamples, appendUsageHistory, availableAt, clearLimited, memberOf, parseRateLimitSnapshot, parseReservations,
  parseTurnCostSamples, parseUsageHistory, pick, pickForTurn, rateLimitSnapshot, reservedAmount, scoreOf, turnCostEstimate, windowsOf,
} from "../lib/fleet/host/advisor.mjs";

const now = Date.parse("2026-10-02T12:00:00Z");
const HOUR = 3_600_000;
const sec = (ms) => Math.round(ms / 1000);
const close = (a, b, d = 1e-2) => assert.ok(Math.abs(a - b) < d / 2, `${a} ≈ ${b}`);

function member(id, { five = 0, fiveResetsIn = 2 * HOUR, week = 0, weekResetsIn = 72 * HOUR, observedAgo = 0, ...rest } = {}) {
  return {
    profile: id,
    usage: { observed_at: new Date(now - observedAgo).toISOString(), windows: {
      five_hour: { utilization: five, resets_at: sec(now + fiveResetsIn) },
      seven_day: { utilization: week, resets_at: sec(now + weekResetsIn) },
    } },
    ...rest,
  };
}
const cost = { typical: 0.02, heavy: 0.1, samples: 0 };

// ---- part 1: ported from cocalc-ai 2f21405, util/ai/claude-pool.test.ts

test("ported, turn cost: defaults until there are enough turns, raised to the largest seen", () => {
  assert.deepEqual(turnCostEstimate([]), { typical: 0.02, heavy: 0.1, samples: 0 });
  assert.equal(turnCostEstimate([0.01, 0.3]).heavy, 0.3);
});

test("ported, turn cost: the mean and the 95th percentile of observed turns", () => {
  const e = turnCostEstimate(Array.from({ length: 20 }, (_, i) => (i + 1) / 100));
  close(e.typical, 0.105);
  assert.equal(e.heavy, 0.19);
  assert.equal(e.samples, 20);
});

test("ported, turn cost: only valid, recent samples are kept", () => {
  assert.deepEqual(parseTurnCostSamples({ samples: [0.1, -1, 2, "x", 0.2] }), [0.1, 0.2]);
  const many = appendTurnCostSamples({ samples: Array(50).fill(0.01) }, [0.5, NaN]);
  assert.equal(many.samples.length, 50);
  assert.equal(many.samples.at(-1), 0.5);
});

test("ported, windows: a window whose reset has passed is unused; limits and the limited mark read from stored state", () => {
  const stale = member("a", { five: 0.99, fiveResetsIn: -HOUR, week: 0.5, observedAgo: 3 * HOUR });
  const w = windowsOf(stale, now);
  assert.deepEqual([w.five, w.week], [0, 0.5]);
  const m = memberOf("a", { usage: member("a", { five: 0.4 }).usage, limited: { until: new Date(now + HOUR).toISOString() } }, now);
  assert.equal(m.limited_until, now + HOUR);
  assert.equal(m.usage?.windows.five_hour?.utilization, 0.4);
  assert.equal(memberOf("a", { limited: { until: new Date(now - 1).toISOString() } }, now).limited_until, undefined);
});

test("ported, pick: the weekly capacity that expires soonest", () => {
  assert.deepEqual(pick({ members: [member("late", { week: 0.2, weekResetsIn: 120 * HOUR }), member("soon", { week: 0.2, weekResetsIn: 10 * HOUR })], cost, now }), { profile: "soon" });
});

test("ported, pick: skips a profile where a heavy turn wouldn't fit in 5 hours", () => {
  assert.deepEqual(pick({ members: [member("full", { five: 0.91, weekResetsIn: 10 * HOUR }), member("ok", { five: 0.5, weekResetsIn: 100 * HOUR })], cost, now }), { profile: "ok" });
});

test("ported, pick: counts turns already running on a profile", () => {
  assert.deepEqual(pick({ members: [member("busy", { five: 0.8, weekResetsIn: 10 * HOUR, reserved: 0.15 }), member("idle", { five: 0.5, weekResetsIn: 100 * HOUR })], cost, now }), { profile: "idle" });
});

test("ported, pick: skips a profile whose week is used up, and one marked limited", () => {
  assert.deepEqual(pick({ members: [member("week", { week: 0.99, weekResetsIn: 2 * HOUR }), member("limited", { limited_until: now + HOUR }), member("ok", { week: 0.9, weekResetsIn: 100 * HOUR })], cost, now }), { profile: "ok" });
});

test("ported, pick: keeps the current profile unless another is much better", () => {
  const a = member("a", { week: 0.5, weekResetsIn: 50 * HOUR });
  assert.deepEqual(pick({ members: [a, member("b", { week: 0.5, weekResetsIn: 40 * HOUR })], cost, current: "a", now }), { profile: "a" });
  assert.deepEqual(pick({ members: [a, member("b", { week: 0.5, weekResetsIn: 20 * HOUR })], cost, current: "a", now }), { profile: "a" }, "2.5 times better: not enough");
  assert.deepEqual(pick({ members: [a, member("b", { week: 0.5, weekResetsIn: 15 * HOUR })], cost, current: "a", now }), { profile: "b" });
});

test("ported, pick: holds until the earliest time one can take a turn; an empty pool", () => {
  assert.deepEqual(pick({ members: [member("a", { five: 1, fiveResetsIn: 3 * HOUR }), member("b", { five: 0.95, fiveResetsIn: 2 * HOUR }), member("c", { limited_until: now + 4 * HOUR })], cost, now }),
    { hold_until: now + 2 * HOUR, next: "b" });
  assert.deepEqual(pick({ members: [member("a", { five: 0.85, reserved: 0.1 })], cost, now }), { hold_until: now + 600_000, next: "a" });
  assert.deepEqual(pick({ members: [], cost, now }), {});
});

test("ported, pick: a profile never reported is unused", () => {
  assert.deepEqual(pick({ members: [member("used", { five: 0.95 }), { profile: "new" }], cost, now }), { profile: "new" });
});

const reading = (agoHours, week, resetsIn = 72 * HOUR) => ({ at: now - agoHours * HOUR, week, resets_at: sec(now + resetsIn) });
const usageOf = (week, observedAgo = 0, resetsIn = 72 * HOUR) => member("x", { week, observedAgo, weekResetsIn: resetsIn }).usage;

test("ported, usage history: a newer reading at most every half hour, or when the week resets", () => {
  assert.equal(appendUsageHistory(undefined, undefined, now), undefined);
  const first = appendUsageHistory(undefined, usageOf(0.1), now);
  assert.deepEqual(first, [reading(0, 0.1)]);
  assert.equal(appendUsageHistory(first, usageOf(0.1), now), undefined);
  const later = now + HOUR / 6;
  assert.equal(appendUsageHistory(first, usageOf(0.12, -HOUR / 6), later), undefined);
  assert.equal(appendUsageHistory(first, usageOf(0.15, -HOUR / 2), now + HOUR / 2).length, 2);
  assert.equal(appendUsageHistory(first, usageOf(0.01, -HOUR / 6, 7 * 24 * HOUR), later).length, 2, "a reset is added at once");
});

test("ported, usage history: readings older than two days and bad entries are dropped; read from stored state", () => {
  const stored = [reading(50, 0.1), reading(10, 0.2), { at: "x", week: 0.3, resets_at: 1 }];
  assert.equal(parseUsageHistory(stored).length, 2);
  assert.deepEqual(appendUsageHistory(stored, usageOf(0.2, 10 * HOUR), now), [reading(10, 0.2)]);
  assert.deepEqual(memberOf("a", { history: [reading(3, 0.1)] }, now).history, [reading(3, 0.1)]);
});

test("ported, reservations: only valid ones still in effect", () => {
  const r = parseReservations({ aa: { amount: 0.02, expires: now + 60_000 }, bb: { amount: 0.02, expires: now - 1 }, cc: { amount: 7, expires: now + 60_000 },
    "not-hex": { amount: 0.02, expires: now + 60_000 }, dd: { amount: 0.03, expires: now + 48 * HOUR } }, now);
  assert.deepEqual(Object.keys(r), ["aa"]);
  close(reservedAmount(r), 0.02);
  assert.deepEqual(parseReservations([1, 2], now), {});
});

// ---- ported from cocalc-ai 2f21405, util/ai/claude-usage.test.ts (the snapshot)

test("ported, snapshot: per-window readings preferred, else the single limiter named; utilization capped at 1; a reset over 366 days away refused; a stored reading over 5 min in the future refused", () => {
  const s = rateLimitSnapshot({ unifiedWindows: { five_hour: { utilization: 0.4, resetsAt: sec(now + HOUR) }, seven_day: { utilization: 1.7, resetsAt: sec(now + 50 * HOUR) } } }, now);
  assert.deepEqual(s.windows, { five_hour: { utilization: 0.4, resets_at: sec(now + HOUR) }, seven_day: { utilization: 1, resets_at: sec(now + 50 * HOUR) } });
  assert.deepEqual(rateLimitSnapshot({ rateLimitType: "seven_day", utilization: 0.3, resetsAt: sec(now + HOUR) }, now).windows, { seven_day: { utilization: 0.3, resets_at: sec(now + HOUR) } });
  assert.equal(rateLimitSnapshot({ rateLimitType: "five_hour", utilization: 0.3, resetsAt: sec(now + 367 * 24 * HOUR) }, now), undefined);
  assert.equal(rateLimitSnapshot({}, now), undefined);
  const future = { ...s, observed_at: new Date(now + 5 * 60_000 + 1000).toISOString() };
  assert.equal(parseRateLimitSnapshot(future, now), undefined);
  assert.ok(parseRateLimitSnapshot({ ...s, observed_at: new Date(now + 5 * 60_000).toISOString() }, now));
});

// ---- part 2: the host's rows, every constant and edge as a LITERAL (r3.4, r3.5)

test("ties go to the earlier profile, for the pick and for hold_until's next", () => {
  assert.deepEqual(pick({ members: [member("x"), member("y")], cost, now }), { profile: "x" });
  assert.deepEqual(pick({ members: [member("x", { five: 1, fiveResetsIn: HOUR }), member("y", { five: 1, fiveResetsIn: HOUR })], cost, now }).next, "x");
});

test("stickiness: exactly 3x keeps, 3x + e switches, 2.5x keeps; an ineligible current is never kept", () => {
  // scores are (1 - week) / hoursToReset: a at 60 h, b at 20 h is exactly 3x
  const a = member("a", { week: 0.5, weekResetsIn: 60 * HOUR });
  assert.deepEqual(pick({ members: [a, member("b", { week: 0.5, weekResetsIn: 20 * HOUR })], cost, current: "a", now }), { profile: "a" }, "exactly 3x");
  assert.deepEqual(pick({ members: [a, member("b", { week: 0.5, weekResetsIn: 20 * HOUR - 60_000 })], cost, current: "a", now }), { profile: "b" }, "3x + e");
  assert.deepEqual(pick({ members: [a, member("b", { week: 0.5, weekResetsIn: 24 * HOUR })], cost, current: "a", now }), { profile: "a" }, "2.5x");
  assert.deepEqual(pick({ members: [member("a", { week: 0.99, weekResetsIn: 90 * HOUR }), member("b", { week: 0.5, weekResetsIn: 90 * HOUR })], cost, current: "a", now }), { profile: "b" }, "ineligible current");
  // an ineligible current that would otherwise be kept (limited, scoring within 3x of the best): never kept
  assert.deepEqual(pick({ members: [member("a", { week: 0.5, weekResetsIn: 60 * HOUR, limited_until: now + HOUR }), member("b", { week: 0.5, weekResetsIn: 50 * HOUR })], cost, current: "a", now }), { profile: "b" }, "limited current, close score");
});

test("the score: the five-hour factor, the 1-hour floor, an unknown weekly reset as 7 days", () => {
  assert.ok(scoreOf(member("lo", { five: 0.1 }), now) > scoreOf(member("hi", { five: 0.6 }), now), "less five-hour used scores higher");
  close(scoreOf(member("a", { week: 0.5, weekResetsIn: HOUR / 2 }), now), 0.5 * 1, 1e-9); // (30 min counts as 1 h)
  const unknown = { profile: "u", usage: { observed_at: new Date(now).toISOString(), windows: { five_hour: { utilization: 0, resets_at: sec(now + HOUR) } } } };
  close(scoreOf(unknown, now), 1 / 168, 1e-12);
});

test("reservations: exactly 600000 ms; at most 100, the newest kept; one expiring at now is gone", () => {
  const { updates } = pickForTurn({ p: {} }, { turn: "ab" }, now);
  assert.deepEqual(updates.find((u) => u.key === "reservations").value, { ab: { amount: 0.02, expires: now + 600_000 } });
  const r = parseReservations({ aa: { amount: 0.02, expires: now + 600_000 } }, now + 599_999);
  assert.deepEqual(Object.keys(r), ["aa"]);
  assert.deepEqual(parseReservations({ aa: { amount: 0.02, expires: now + 600_000 } }, now + 600_000), {});
  const many = Object.fromEntries(Array.from({ length: 101 }, (_, i) => [i.toString(16).padStart(2, "0"), { amount: 0.001, expires: now + 1000 + i }]));
  const kept = parseReservations(many, now);
  assert.equal(Object.keys(kept).length, 100);
  assert.ok(!Object.hasOwn(kept, "00") && Object.hasOwn(kept, (100).toString(16)), "the newest 100 kept");
});

test("turn cost: exactly 0.02 and 0.1 at 4 samples, the mean at 5; the clamps 0.005 and 0.5; heavy never below typical", () => {
  assert.deepEqual(turnCostEstimate([0.03, 0.03, 0.03, 0.03]), { typical: 0.02, heavy: 0.1, samples: 4 });
  close(turnCostEstimate([0.03, 0.03, 0.03, 0.03, 0.03]).typical, 0.03, 1e-9);
  assert.equal(turnCostEstimate([0.001, 0.001, 0.001, 0.001, 0.001]).typical, 0.005);
  assert.equal(turnCostEstimate([0.9, 0.9, 0.9, 0.9, 0.9]).typical, 0.5);
  assert.equal(turnCostEstimate([0.9, 0.9, 0.9, 0.9, 0.9]).heavy, 0.5);
  const e = turnCostEstimate([0.2, 0.2, 0.2, 0.2, 0.2]);
  assert.ok(e.heavy >= e.typical);
  // one big outlier above the 95th percentile: the mean exceeds p95, and heavy is raised to typical
  const o = turnCostEstimate([...Array(19).fill(0.01), 0.9]);
  close(o.typical, 0.0545, 1e-9);
  assert.equal(o.heavy, o.typical);
});

test("eligibility edges: week + typical = 1 is out (>=); five + heavy = 1 is in (> 1 is the bar); likewise with reservations", () => {
  const c = { typical: 0.02, heavy: 0.1 };
  assert.ok(availableAt(member("w", { week: 0.98 }), c, now) > now, "week + typical = 1");
  assert.equal(availableAt(member("w", { week: 0.98 - 1e-9 }), c, now), now);
  assert.equal(availableAt(member("f", { five: 0.9 }), c, now), now, "five + heavy = 1");
  assert.ok(availableAt(member("f", { five: 0.9 + 1e-9 }), c, now) > now);
  assert.equal(availableAt(member("r", { five: 0.8, reserved: 0.1 }), c, now), now, "five + reserved + heavy = 1");
  assert.equal(availableAt(member("r", { five: 0.8, reserved: 0.1 + 1e-9 }), c, now), now + 600_000);
});

test("WK2, FV2: an unknown reset holds for exactly 604800000 ms (week) and 18000000 ms (five hours)", () => {
  // (a member with no readings has both windows at 0 and no reset: a turn cost that fills a window reaches the defaults)
  assert.equal(availableAt({ profile: "a" }, { typical: 1, heavy: 0 }, now), now + 604_800_000, "WK2");
  assert.equal(availableAt({ profile: "a" }, { typical: 0, heavy: 1.01 }, now), now + 18_000_000, "FV2");
});

test("WN1: a reset exactly at now counts as 0 (eligible), and at now - 1 s; at now + 1 s it doesn't", () => {
  const k = sec(now); // (resets_at is in whole seconds: now is k * 1000)
  const at = (resetsAt) => ({ profile: "a", usage: { observed_at: new Date(now - HOUR).toISOString(), windows: { seven_day: { utilization: 1, resets_at: resetsAt } } } });
  assert.equal(availableAt(at(k), cost, k * 1000), k * 1000);
  assert.equal(windowsOf(at(k), k * 1000).week, 0, "the window itself reads 0 at its reset");
  assert.equal(windowsOf(at(k + 1), k * 1000).week, 1);
  assert.equal(availableAt(at(k - 1), cost, k * 1000), k * 1000);
  assert.ok(availableAt(at(k + 1), cost, k * 1000) > k * 1000);
});

test("UH1, UH2: the history holds at most 120 (a 121st drops the oldest); a reading 1799000 ms after the last isn't added, one at 1800000 ms is", () => {
  // (120 readings within the 48 h keep are only possible across a weekly reset, so the new one names another reset)
  const full = Array.from({ length: 120 }, (_, i) => ({ at: now - (120 - i) * 60_000 * 23, week: 0.1, resets_at: sec(now + 71 * HOUR) }));
  const next = appendUsageHistory(full, usageOf(0.2), now);
  assert.equal(next.length, 120);
  assert.equal(next.at(-1).at, now);
  assert.equal(next[0].at, full[1].at, "the oldest dropped");
  const last = [{ at: now, week: 0.1, resets_at: sec(now + 72 * HOUR) }];
  assert.equal(appendUsageHistory(last, usageOf(0.2, -1_799_000), now + 1_799_000), undefined);
  assert.equal(appendUsageHistory(last, usageOf(0.2, -1_800_000), now + 1_800_000).length, 2);
});

// ---- part 3: the locked pick (ported from server/agents/claude-pool.ts) and clearLimited

test("pickForTurn: a limit just hit marks its profile until the reported reset, else 5 h, always within [1 min, 7 d]; the pick then skips it", () => {
  const st = { a: { usage: member("a", { week: 0.2, weekResetsIn: 10 * HOUR }).usage }, b: { usage: member("b", { week: 0.2, weekResetsIn: 100 * HOUR }).usage } };
  const lim = (resets_at) => pickForTurn(st, { turn: "aa", limited: { profile: "a", resets_at } }, now);
  const until = (r) => Date.parse(r.updates.find((u) => u.key === "limited").value.until);
  const r = lim(sec(now + 2 * HOUR));
  assert.equal(until(r), now + 2 * HOUR);
  assert.deepEqual(r.result, { profile: "b" });
  assert.equal(until(lim(undefined)), now + 18_000_000, "5 h default");
  assert.equal(until(lim(sec(now + 10_000))), now + 60_000, "at least 1 min");
  assert.equal(until(lim(sec(now + 30 * 24 * HOUR))), now + 604_800_000, "at most 7 d");
});

test("pickForTurn: turn costs (at most 20 a pick) refine the estimate; this turn's own earlier reservation is replaced; an empty pool is empty", () => {
  const st = { a: { reservations: { aa: { amount: 0.3, expires: now + 60_000 } } } };
  const r = pickForTurn(st, { turn: "aa", turn_costs: Array.from({ length: 25 }, () => ({ profile: "a", cost: 0.04 })) }, now);
  assert.equal(r.updates.find((u) => u.key === "turn_costs").value.samples.length, 20);
  const res = r.updates.filter((u) => u.key === "reservations").at(-1).value;
  assert.deepEqual(Object.keys(res), ["aa"]);
  close(res.aa.amount, 0.04, 1e-9);
  assert.equal(res.aa.expires, now + 600_000);
  assert.deepEqual(pickForTurn({}, { turn: "aa" }, now), { result: { empty: true }, updates: [] });
});

test("clearLimited (SEC's hardening): a later success without a limit clears another turn's limited mark; nothing to clear gives null", () => {
  assert.deepEqual(clearLimited({ limited: { until: new Date(now + HOUR).toISOString() } }, "a", now), { profile: "a", key: "limited", value: null });
  assert.equal(clearLimited({ limited: { until: new Date(now - 1).toISOString() } }, "a", now), null);
  assert.equal(clearLimited({}, "a", now), null);
});
