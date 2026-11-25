// Host supervisor (execution lease r3.12, lease part 2): what the supervisor reads, in-process, of an agent's lease and
// of its running turns. Read-only: nothing here raises, lowers, masks or starts anything.
//
// - liveLease(agent): the agent's live lease, { lease_id, lg, gen, expiry_tick, sg }, or null. Live means the published
//   record is well formed AND liveCheck passes now: the tombstone is below its lg, now is before its effective end
//   (expiry_tick - 30 s, CLOCK_BOOTTIME) and its watchdog timer is still waiting. Anything else, an unreadable record
//   included, is null, which callers read as "no lease" (fail closed). The restore-resume gate compares its gen with the
//   agent's entry generation; admission requires it non-null.
// - activeTurns(agent): how many of the agent's turns are running: the turn scopes (sagebrush-turn-<id>-<turn>.scope,
//   launcher contract A5) under the agent's slice whose cgroup is populated. A missing slice is 0 (nothing of the agent
//   runs). Anything it can't read, or doesn't recognize, REJECTS: it never reports 0 for a tree it couldn't see, so the
//   backup's idle check (backup-run.mjs) treats it as not idle.

import * as fs from "node:fs";
import { join } from "node:path";
import { isId, refuse } from "../bytes.mjs";
import { LEASE_DIR, liveCheck, readRecord, realClock, realSystem } from "./lease.mjs";
import { agentSliceCgroup } from "./names.mjs";

const need = (agent) => { if (!isId(agent)) refuse("bad_form", "lease: bad agent id"); return agent; };

/** The agent's live lease { lease_id, lg, gen, expiry_tick, sg }, or null (no record, malformed, spent, expired, or no live watchdog). */
export async function liveLease(agent, { dir = LEASE_DIR, fsx = fs, sys = realSystem(), clock = realClock } = {}) {
  const r = readRecord(need(agent), { dir, fsx });
  if (r.state !== "ok") return null;
  if ((await liveCheck(agent, r.rec, { dir, fsx, sys, clock })) !== null) return null;
  const { lease_id, lg, gen, expiry_tick, sg } = r.rec;
  return { lease_id, lg, gen, expiry_tick, sg };
}

/** A turn scope's name under the agent's slice: sagebrush-turn-<agent>-<32 hex turn id>.scope (launcher contract A5 §1). */
export const turnScopePattern = (agent) => new RegExp(`^sagebrush-turn-${need(agent)}-[0-9a-f]{32}\\.scope$`);

const fail = (what) => Object.assign(new Error(`lease: ${what}`), { code: "EIO" });

/** How many of the agent's turn scopes are populated. Rejects when the slice's tree can't be read or isn't as expected. */
export async function activeTurns(agent, { sys = realSystem(), fsx = fs } = {}) {
  const slice = sys.cgroup(agentSliceCgroup(need(agent))); // null: no slice; throws unless a real cgroup v2 directory
  if (slice === null) return 0;
  const turn = turnScopePattern(agent);
  let n = 0;
  for (const e of fsx.readdirSync(slice, { withFileTypes: true })) {
    if (!turn.test(e.name)) continue;
    if (!e.isDirectory()) throw fail("a turn scope that isn't a cgroup directory");
    const events = fsx.readFileSync(join(slice, e.name, "cgroup.events"), "utf8");
    if (/^populated 1$/m.test(events)) n++;
    else if (!/^populated 0$/m.test(events)) throw fail("a turn scope's cgroup.events has no populated line");
  }
  return n;
}
