// Host supervisor (design: agent-autonomous-host-supervisor-freeze-r3.1.md §3.3 steps 4–9): the plan for applying a
// grant. Pure: from the previous accepted grant body (or null), the new one, and the registry's view of the agents, it
// returns the ordered list of step names that GrantState.begin records and the executor runs, each step idempotent.
//
// Step names, in this order:
//   broker-gen                 tell the broker "current generation N" (step 4)
//   retire:<id>                an agent the new grant no longer lists: its run state becomes `stopped`, durably, before
//                              the effects below (no lifecycle op is counted)
//   stop:<id>, mask:<id>       narrowing (step 5): every agent that is removed or whose authority may change
//   provision:<id>             a new agent: registry record, uid, user, directories, network namespace
//   unit:<id>                  regenerate its unit file and group membership from grant N (step 6)
//   daemon-reload              once, if any unit was written
//   start:<id>                 unmask and start (step 7): the narrowed agents first, then the new ones; at run time the
//                              executor starts only an agent whose run state allows it and whose fences are all down
//   map                        publish the uid-to-agent map at N (step 8)
//
// What counts as narrowing: ANY change to an agent's grant entry, or to the membership of any tag it holds, is treated
// as one, so the agent is stopped and masked before its unit is regenerated. A pure widening restarts it too: there is
// never a moment where an older, wider unit runs under the new grant. An unchanged agent is not touched, except:
// - an agent whose last start failed on its own side (start_failed): the next grant clears it and retries it;
// - every listed agent, when the host was expired (`{ all: true }`): a later valid grant starts them again (§3.4).

import { isId, refuse } from "../bytes.mjs";

const canon = (v) => JSON.stringify(v, (k, x) => (x && typeof x === "object" && !Array.isArray(x) ? Object.fromEntries(Object.keys(x).sort().map((key) => [key, x[key]])) : x));

function members(body) {
  const m = new Map();
  for (const a of body?.agents ?? []) for (const t of a.tags) { if (!m.has(t)) m.set(t, []); m.get(t).push(a.agent); }
  for (const v of m.values()) v.sort();
  return m;
}

function byId(body) {
  const m = new Map();
  for (const a of body?.agents ?? []) {
    if (!isId(a?.agent)) refuse("bad_form", "plan: bad agent id");
    if (m.has(a.agent)) refuse("bad_form", "plan: an agent is listed twice");
    m.set(a.agent, a);
  }
  return m;
}

/**
 * The steps for applying `next` after `prev` (null for the first grant). `registry.agent(id)` returns the agent's
 * registry record or null. `all`: treat every listed agent as changed. Returns { steps, changed, added, removed }.
 */
export function planGrant(prev, next, registry, { all = false } = {}) {
  if (!next || !Array.isArray(next.agents)) refuse("bad_form", "plan: no grant");
  const before = byId(prev), after = byId(next);
  const mBefore = members(prev), mAfter = members(next);
  const tagMoved = (t) => canon(mBefore.get(t) ?? []) !== canon(mAfter.get(t) ?? []);

  const known = (id) => registry.agent(id) !== null;
  const fixed = (id) => ["revoked", "deleted"].includes(registry.agent(id)?.state);
  const added = [], changed = [], removed = [];
  for (const [id, a] of after) {
    if (!known(id)) { added.push(id); continue; }
    if (fixed(id)) continue; // a revoked or deleted agent never runs again, whatever a grant says
    if (all || !before.has(id) || canon(before.get(id)) !== canon(a) || a.tags.some(tagMoved) || registry.agent(id).start_failed !== null) changed.push(id);
  }
  for (const id of before.keys()) if (!after.has(id) && known(id) && !fixed(id)) removed.push(id);
  for (const l of [added, changed, removed]) l.sort();

  const steps = ["broker-gen"];
  for (const id of removed) steps.push(`retire:${id}`);
  for (const id of [...removed, ...changed]) steps.push(`stop:${id}`, `mask:${id}`);
  for (const id of added) steps.push(`provision:${id}`);
  for (const id of [...changed, ...added]) steps.push(`unit:${id}`);
  if (changed.length + added.length > 0) steps.push("daemon-reload");
  for (const id of [...changed, ...added]) steps.push(`start:${id}`);
  steps.push("map");
  return { steps, changed, added, removed };
}

/** Split a step name into { kind, agent } (agent null for host-wide steps). Refuses a name the planner never makes. */
export function parseStep(step) {
  const host = ["broker-gen", "daemon-reload", "map"];
  if (host.includes(step)) return { kind: step, agent: null };
  const m = /^(retire|stop|mask|provision|unit|start):([a-z2-7]{26})$/.exec(step);
  if (!m || !isId(m[2])) refuse("bad_form", "plan: unknown step");
  return { kind: m[1], agent: m[2] };
}
