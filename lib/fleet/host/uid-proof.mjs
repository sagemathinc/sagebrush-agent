// Host supervisor (design: agent-autonomous-host-deprovision.md r3.2 §2): the WHOLE-HOST uid-empty proof, taken before
// any destructive deprovision step (and again on recovery, before the accounts step and before done). It covers what
// the cgroup proof can't: anything that escaped the agent's cgroup, and every login path.
//
// The uid is empty only if ALL of these hold:
// - no process anywhere has it in any slot (real, effective, saved or filesystem) of the `Uid:` line of
//   /proc/<pid>/status;
// - no user manager `user@<uid>.service` is active, activating, deactivating or reloading;
// - no linger file /var/lib/systemd/linger/sb-<id> exists;
// - no logind session belongs to it (`loginctl list-sessions`).
//
// It fails closed: anything it can't read or parse throws (unknown is never "empty"). A process that exits while being
// read (its status file vanishes) is simply gone.

import fs from "node:fs";
import { join } from "node:path";
import { isId } from "../bytes.mjs";
import { BROKER_USER, agentUser } from "./names.mjs";
import { STORAGE_UID_RANGE } from "./profiles.mjs";
import { UID_RANGE } from "./registry.mjs";

const unknown = (what) => Object.assign(new Error(`uid proof: ${what}`), { code: "effect_failed" });
const LIVE = new Set(["active", "activating", "deactivating", "reloading"]);

/** The four uids of a /proc/<pid>/status `Uid:` line, or null if the text has none (refused by the caller). */
export function statusUids(text) {
  const m = /^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$/m.exec(text);
  return m ? m.slice(1, 5).map(Number) : null;
}

/**
 * Prove `uid` (agent `agent`) empty on the whole host. Returns { empty, holders }: `holders` lists what holds it
 * (`pid <n>`, `user-manager`, `linger`, `session <id>`). Throws when anything can't be read: never "empty" by default.
 * `fsx`, `root` (a prefix for tests) and `run` (argv runner: { code, stdout }) are injectable.
 */
export async function uidEmpty(uid, agent, opts = {}) {
  if (!Number.isSafeInteger(uid) || uid < UID_RANGE[0] || uid > UID_RANGE[1] || !isId(agent)) throw unknown("a uid outside the agent range");
  return prove(uid, agentUser(agent), opts);
}

/**
 * The same proof for a harness profile's STORAGE uid (launcher amendment A4 §2): it has no account, so there is no
 * linger file to check (`loginctl enable-linger` needs a user name), and every other check is the same.
 */
export async function storageUidEmpty(uid, opts = {}) {
  if (!Number.isSafeInteger(uid) || uid < STORAGE_UID_RANGE[0] || uid > STORAGE_UID_RANGE[1]) throw unknown("a uid outside the storage range");
  return prove(uid, null, opts);
}

/**
 * The same proof for the broker's user, `sb-broker` (host daemon main r1.1 §2.1): every process that can hold the host's
 * private keys, other than root, has this uid in a slot, whatever unit, scope or session started it.
 */
export async function brokerUidEmpty(uid, opts = {}) {
  if (!Number.isSafeInteger(uid) || uid <= 0) throw unknown("not the broker's uid");
  return prove(uid, BROKER_USER, opts);
}

async function prove(uid, lingerName, { fsx = fs, root = "", run, ms, signal } = {}) {
  const at = (p) => `${root}${p}`;
  const holders = [];
  // 1. Every process's four uid slots.
  let pids;
  try { pids = fsx.readdirSync(at("/proc")).filter((n) => /^[1-9][0-9]*$/.test(n)); } catch { throw unknown("/proc can't be listed"); }
  for (const pid of pids) {
    let text;
    try { text = fsx.readFileSync(join(at("/proc"), pid, "status"), "utf8"); } catch (e) {
      if (e?.code === "ENOENT" || e?.code === "ESRCH") continue; // it exited while we looked
      throw unknown(`a process's status can't be read`);
    }
    const uids = statusUids(text);
    if (uids === null) throw unknown("a process's status has no Uid line");
    if (uids.includes(uid)) holders.push(`pid ${pid}`);
  }
  // 2. The user manager.
  const mgr = await run(["systemctl", "is-active", `user@${uid}.service`], { ms, signal });
  const state = String(mgr.stdout ?? "").trim();
  if (!/^[a-z-]+$/.test(state)) throw unknown("the user manager's state can't be read");
  if (LIVE.has(state)) holders.push("user-manager");
  // 3. Linger.
  if (lingerName !== null) {
    try { fsx.lstatSync(at(`/var/lib/systemd/linger/${lingerName}`)); holders.push("linger"); } catch (e) {
      if (e?.code !== "ENOENT") throw unknown("the linger file can't be checked");
    }
  }
  // 4. logind sessions: "SESSION UID USER SEAT TTY ..." per line.
  const ls = await run(["loginctl", "list-sessions", "--no-legend", "--no-pager"], { ms, signal });
  if (ls.code !== 0) throw unknown("logind's sessions can't be listed");
  for (const line of String(ls.stdout).split("\n").map((l) => l.trim()).filter(Boolean)) {
    const [id, u] = line.split(/\s+/);
    if (!/^\d+$/.test(u ?? "")) throw unknown("a logind session line can't be parsed");
    if (Number(u) === uid) holders.push(`session ${id}`);
  }
  return { empty: holders.length === 0, holders };
}
