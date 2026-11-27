// Host supervisor (design: agent-autonomous-host-claude-advisor r3.2 §4, ported in r3.3, rows in r3.4 and r3.5): the
// per-turn advisor, which of an agent's pooled Claude subscription profiles a turn uses, from the limits Claude
// last reported for each. Pure: no I/O, no clock of its own (every function takes `now`), deterministic.
//
// PORTED from cocalc-ai (SageMath, Inc.), commit 2f21405, with the behaviour and every constant unchanged:
// - src/packages/util/ai/claude-pool.ts: the turn-cost estimate, the windows, eligibility, the score, the pick, the
//   reservations and the usage history (the forecast, a display feature, isn't ported);
// - src/packages/util/ai/claude-usage.ts: the rate-limit snapshot from a turn's rate_limit_info, and its revalidation;
// - src/packages/server/agents/claude-pool.ts: one locked pick over the pool's state (limit marking, turn costs,
//   reservations, history), as a pure function returning the updates the caller writes under the host store's lock.
// What differs is only where it runs (here, on the person's host, never a server) and the profile ids for
// cocalc-ai's credential ids. SEC's hardening (advisor r3.3 note) is added: clearLimited.
//
// The inputs (own-login d3r1 §7): the rate-limit readings the CLI reports in turns, the host's own turn records,
// and the pool policy. Nothing here reads a profile's files or holds a token.

const HOUR_MS = 3_600_000;
const FIVE_HOURS_MS = 5 * HOUR_MS;
const WEEK_MS = 7 * 24 * HOUR_MS;

export const MAX_TURN_COST_SAMPLES = 50;
/** Before there is enough data: a typical turn, and a heavy one (fractions of a five-hour limit). */
export const DEFAULT_TURN_COST = 0.02;
export const DEFAULT_HEAVY_TURN_COST = 0.1;
export const MIN_TURN_COST_SAMPLES = 5;
export const MIN_TURN_COST = 0.005;
export const MAX_TURN_COST = 0.5;
/** Keep the thread's profile unless another scores more than this many times better (the prompt cache is per account). */
export const STICKY_FACTOR = 3;
/** Running turns count against a profile for at most this long. */
export const RESERVATION_MS = 10 * 60_000;
export const MAX_RESERVATIONS = 100;
/** The usage history: at most one reading per 30 min, kept 48 h, at most 120. */
export const USAGE_HISTORY_SPACING_MS = 30 * 60_000;
export const USAGE_HISTORY_KEEP_MS = 48 * HOUR_MS;
export const MAX_USAGE_HISTORY = 120;
/** A limit reached with no reset reported: this long; always within [1 min, 7 d]. */
export const DEFAULT_LIMITED_MS = 5 * HOUR_MS;
export const MIN_LIMITED_MS = 60_000;
export const MAX_LIMITED_MS = 7 * 24 * HOUR_MS;
/** Turn costs taken per pick. */
export const MAX_TURN_COSTS_PER_PICK = 20;

const WINDOWS = ["five_hour", "seven_day"];

const isSample = (v) => typeof v === "number" && Number.isFinite(v) && v >= 0 && v <= 1;

// ---- the rate-limit snapshot (claude-usage.ts) -----------------------------------------------------------------------

function windowOf(value, now) {
  if (!value || typeof value !== "object") return undefined;
  const { utilization, resets_at } = value;
  if (typeof utilization !== "number" || !Number.isFinite(utilization) || utilization < 0 || utilization > 10
    || typeof resets_at !== "number" || !Number.isInteger(resets_at)
    // seconds since the epoch, within a year of now
    || Math.abs(resets_at * 1000 - now) > 366 * 24 * 3600 * 1000) return undefined;
  return { utilization: Math.min(1, utilization), resets_at };
}

/** A snapshot from a turn's rate_limit_info: its per-window readings, else the single limiter it names. */
export function rateLimitSnapshot(info, now) {
  if (!info || typeof info !== "object") return undefined;
  const windows = {};
  for (const key of WINDOWS) {
    const u = info.unifiedWindows?.[key];
    const reading = windowOf(u && { utilization: u.utilization, resets_at: u.resetsAt }, now);
    if (reading) windows[key] = reading;
  }
  if (Object.keys(windows).length === 0) {
    const key = WINDOWS.find((k) => k === info.rateLimitType);
    const reading = key && windowOf({ utilization: info.utilization, resets_at: info.resetsAt }, now);
    if (key && reading) windows[key] = reading;
  }
  if (Object.keys(windows).length === 0) return undefined;
  return { observed_at: new Date(now).toISOString(), windows };
}

/** Revalidate a stored snapshot: refused when observed more than 5 minutes in the future. */
export function parseRateLimitSnapshot(value, now) {
  if (!value || typeof value !== "object") return undefined;
  const { observed_at, windows } = value;
  const observed = typeof observed_at === "string" && observed_at.length < 40 ? Date.parse(observed_at) : NaN;
  if (!Number.isFinite(observed) || observed > now + 5 * 60_000) return undefined;
  const result = { observed_at: new Date(observed).toISOString(), windows: {} };
  for (const key of WINDOWS) {
    const reading = windowOf(windows?.[key], now);
    if (reading) result.windows[key] = reading;
  }
  return Object.keys(result.windows).length ? result : undefined;
}

// ---- turn costs, reservations, history (claude-pool.ts) --------------------------------------------------------------

export function parseTurnCostSamples(value) {
  const samples = value?.samples;
  if (!Array.isArray(samples)) return [];
  return samples.filter(isSample).slice(-MAX_TURN_COST_SAMPLES);
}

export function appendTurnCostSamples(value, add) {
  return { samples: [...parseTurnCostSamples(value), ...add.filter(isSample)].slice(-MAX_TURN_COST_SAMPLES) };
}

/** The stored reservations still in effect (expired and invalid dropped), the newest MAX_RESERVATIONS. */
export function parseReservations(value, now) {
  const result = {};
  if (!value || typeof value !== "object" || Array.isArray(value)) return result;
  const entries = Object.entries(value)
    .filter(([key, r]) => /^[a-f0-9]{1,64}$/.test(key) && isSample(r?.amount) && typeof r?.expires === "number"
      && r.expires > now && r.expires <= now + 24 * HOUR_MS)
    .sort(([, a], [, b]) => b.expires - a.expires)
    .slice(0, MAX_RESERVATIONS);
  for (const [key, r] of entries) result[key] = { amount: r.amount, expires: r.expires };
  return result;
}

export const reservedAmount = (reservations) => Object.values(reservations).reduce((sum, r) => sum + r.amount, 0);

export function parseUsageHistory(value) {
  if (!Array.isArray(value)) return [];
  const ok = (x) => typeof x === "number" && Number.isFinite(x);
  return value
    .filter((r) => r && ok(r.at) && r.at > 0 && ok(r.week) && r.week >= 0 && r.week <= 2 && ok(r.resets_at) && r.resets_at > 0)
    .map(({ at, week, resets_at }) => ({ at, week, resets_at }))
    .sort((a, b) => a.at - b.at)
    .slice(-MAX_USAGE_HISTORY);
}

/** The history with the latest weekly reading added (newer than the last, and 30 min on or the week reset); undefined when unchanged. */
export function appendUsageHistory(stored, usage, now) {
  const history = parseUsageHistory(stored).filter((r) => r.at > now - USAGE_HISTORY_KEEP_MS);
  const week = usage?.windows.seven_day;
  const at = usage ? Date.parse(usage.observed_at) : NaN;
  const last = history[history.length - 1];
  if (week && Number.isFinite(at) && at <= now + 60_000 && at > now - USAGE_HISTORY_KEEP_MS
    && (!last || (at > last.at && (at - last.at >= USAGE_HISTORY_SPACING_MS || week.resets_at !== last.resets_at)))) {
    history.push({ at, week: week.utilization, resets_at: week.resets_at });
  }
  const next = history.slice(-MAX_USAGE_HISTORY);
  if (next.length === 0 && stored == null) return undefined;
  return JSON.stringify(next) === JSON.stringify(stored ?? null) ? undefined : next;
}

/** The five-hour share of a typical and a heavy turn, from observed turns; defaults (raised to the largest seen) before enough. */
export function turnCostEstimate(samples) {
  const valid = samples.filter(isSample);
  const clamp = (x) => Math.min(MAX_TURN_COST, Math.max(MIN_TURN_COST, x));
  if (valid.length < MIN_TURN_COST_SAMPLES) {
    return { typical: DEFAULT_TURN_COST, heavy: clamp(Math.max(DEFAULT_HEAVY_TURN_COST, ...valid)), samples: valid.length };
  }
  const sorted = [...valid].sort((a, b) => a - b);
  const mean = sorted.reduce((sum, x) => sum + x, 0) / sorted.length;
  const p95 = sorted[Math.ceil(0.95 * sorted.length) - 1]; // (nearest rank)
  const typical = clamp(mean);
  return { typical, heavy: Math.max(typical, clamp(p95)), samples: valid.length };
}

// ---- members, windows, eligibility, score, pick (claude-pool.ts) -----------------------------------------------------

/** A member from its stored state { usage, limited: { until (ISO) }, history }. */
export function memberOf(profile, state, now) {
  const usage = parseRateLimitSnapshot(state?.usage, now);
  const until = typeof state?.limited?.until === "string" ? Date.parse(state.limited.until) : NaN;
  const history = parseUsageHistory(state?.history);
  return { profile, ...(usage ? { usage } : {}), ...(Number.isFinite(until) && until > now ? { limited_until: until } : {}), ...(history.length ? { history } : {}) };
}

/** Current utilization: a window whose reset has passed (at or before now) is at 0; never reported is unused. */
export function windowsOf(member, now) {
  const reading = (key) => {
    const w = member.usage?.windows[key];
    if (!w) return { utilization: 0 };
    const resetsAt = w.resets_at * 1000;
    return resetsAt <= now ? { utilization: 0 } : { utilization: w.utilization, resetsAt };
  };
  const five = reading("five_hour"), week = reading("seven_day");
  return { five: five.utilization, ...(five.resetsAt ? { fiveResetsAt: five.resetsAt } : {}), week: week.utilization, ...(week.resetsAt ? { weekResetsAt: week.resetsAt } : {}) };
}

/** When the member could take a heavy turn (now if it can). */
export function availableAt(member, cost, now) {
  const w = windowsOf(member, now);
  let at = now;
  if (member.limited_until && member.limited_until > now) at = Math.max(at, member.limited_until);
  if (w.week + cost.typical >= 1) at = Math.max(at, w.weekResetsAt ?? now + WEEK_MS);
  if (w.five + cost.heavy > 1) at = Math.max(at, w.fiveResetsAt ?? now + FIVE_HOURS_MS);
  else if (w.five + (member.reserved ?? 0) + cost.heavy > 1) at = Math.max(at, now + RESERVATION_MS); // (only running turns are in the way)
  return at;
}

/** The weekly capacity that would otherwise expire unused, per hour until the week resets, weighted by five-hour headroom. */
export function scoreOf(member, now) {
  const w = windowsOf(member, now);
  const untilReset = Math.max(HOUR_MS, (w.weekResetsAt ?? now + WEEK_MS) - now);
  return ((1 - w.week) / (untilReset / HOUR_MS)) * (1 - w.five);
}

/**
 * The profile for the next turn, over `members` in the pool's canonical order: { profile }, or, when none can take
 * a turn now, { hold_until, next } (the one free first), or {} for an empty pool. The best score wins (ties to the
 * earlier member); the thread's `current` is kept while eligible and the best isn't more than STICKY_FACTOR better.
 */
export function pick({ members, cost, current, now }) {
  if (members.length === 0) return {};
  const eligible = members.filter((m) => availableAt(m, cost, now) <= now).map((member) => ({ member, score: scoreOf(member, now) }));
  if (eligible.length === 0) {
    const next = members.map((member) => ({ member, at: availableAt(member, cost, now) })).reduce((a, b) => (b.at < a.at ? b : a));
    return { hold_until: next.at, next: next.member.profile };
  }
  const best = eligible.reduce((a, b) => (b.score > a.score ? b : a));
  const kept = eligible.find((x) => x.member.profile === current);
  if (kept && !(best.score > STICKY_FACTOR * kept.score)) return { profile: kept.member.profile };
  return { profile: best.member.profile };
}

// ---- one locked pick over the pool's state (server/agents/claude-pool.ts) --------------------------------------------

/**
 * One pick, as the host does it under its store lock. `state`: profile id -> { usage, limited, turn_costs,
 * reservations, history } (the pool's members, in canonical order, already filtered to the agent's pool and to
 * selectable profiles). `opts`: { turn (a hex key for this turn), current (the thread's last profile), limited:
 * { profile, resets_at (s) } (a limit the last turn just hit), turn_costs: [{ profile, cost }] }. Returns
 * { result, updates }: result { profile } | { hold_until, next } | { empty: true }; updates: [{ profile, key, value }]
 * for the caller to write.
 */
export function pickForTurn(state, opts, now) {
  const ids = Object.keys(state);
  const rows = new Map(ids.map((id) => [id, { ...state[id] }]));
  const updates = [];
  const set = (id, key, value) => { rows.get(id)[key] = value; updates.push({ profile: id, key, value }); };
  // a limit just reached: skip that profile until it resets
  const lim = opts.limited;
  if (lim && rows.has(lim.profile)) {
    const resets = typeof lim.resets_at === "number" && Number.isFinite(lim.resets_at) ? lim.resets_at * 1000 : now + DEFAULT_LIMITED_MS;
    set(lim.profile, "limited", { until: new Date(Math.min(now + MAX_LIMITED_MS, Math.max(now + MIN_LIMITED_MS, resets))).toISOString() });
  }
  // observed turns refine the cost estimate
  const costs = new Map();
  for (const e of (opts.turn_costs ?? []).slice(0, MAX_TURN_COSTS_PER_PICK)) {
    if (!rows.has(e?.profile)) continue;
    costs.set(e.profile, [...(costs.get(e.profile) ?? []), e.cost]);
  }
  for (const [id, add] of costs) {
    const next = appendTurnCostSamples(rows.get(id).turn_costs, add);
    if (next.samples.length > 0) set(id, "turn_costs", next);
  }
  // running turns, without this turn's own earlier reservation and without expired ones
  const reservations = new Map();
  for (const id of ids) {
    const stored = rows.get(id).reservations;
    const cur = parseReservations(stored, now);
    delete cur[opts.turn];
    reservations.set(id, cur);
    if (stored != null && JSON.stringify(stored) !== JSON.stringify(cur)) set(id, "reservations", cur);
  }
  for (const id of ids) {
    const history = appendUsageHistory(rows.get(id).history, parseRateLimitSnapshot(rows.get(id).usage, now), now);
    if (history) set(id, "history", history);
  }
  const cost = turnCostEstimate(ids.flatMap((id) => parseTurnCostSamples(rows.get(id).turn_costs)));
  const members = ids.map((id) => ({ ...memberOf(id, rows.get(id), now), reserved: reservedAmount(reservations.get(id) ?? {}) }));
  const p = ids.length === 0 ? undefined : pick({ members, cost, current: opts.current, now });
  let result;
  if (!p) result = { empty: true };
  else if (!("profile" in p)) result = { ...(p.hold_until != null ? { hold_until: p.hold_until } : {}), ...(p.next ? { next: p.next } : {}) };
  else {
    set(p.profile, "reservations", { ...reservations.get(p.profile), [opts.turn]: { amount: cost.typical, expires: now + RESERVATION_MS } });
    result = { profile: p.profile };
  }
  return { result, updates };
}

/**
 * SEC's hardening (advisor r3.3 note): a turn that SUCCEEDED on `profile` without hitting a limit clears a
 * limited mark another turn set, so one misbehaving agent can't hold a pooled profile for days. The update, or null.
 */
export function clearLimited(state, profile, now) {
  const until = typeof state?.limited?.until === "string" ? Date.parse(state.limited.until) : NaN;
  return Number.isFinite(until) && until > now ? { profile, key: "limited", value: null } : null;
}
