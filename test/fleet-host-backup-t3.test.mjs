// Host backup, wiring r0.4 §3 and §5 (T3): the execution lease's watchdog STOPS FIRST and leaves the journal to the
// backup. The REAL leaseExpire on a frozen target in a FULL journal (64 members) while another member can't prove its
// thaw, the worker's reap is slow and the journal lock is held: the target's slice is killed and proven empty first,
// within the stop's own bound, nothing is thawed and `backup` stays raised. The backup's own recovery reconciles after.
// The control: r0.1's wiring (recoverBackup before the stop) is killed by the deadline assertion.
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "./host-linux-only.mjs";
import { newId } from "../lib/fleet/index.mjs";
import { leaseExpire } from "../lib/fleet/host/lease.mjs";
import { advance, newJournal, readJournal, recoverBackup, withJournalLock, writeJournal } from "../lib/fleet/host/backup-journal.mjs";
import { recoverLeftover } from "../lib/fleet/host/backup-scheduler.mjs";
import { raiseFence } from "../lib/fleet/host/fence.mjs";
import { agentSliceCgroup, backupScopeCgroup } from "../lib/fleet/host/names.mjs";

const RUN = "20261126T030000Z-abcdefgh";
const STOP_BOUND_MS = 5000 + 1000; // (lease.mjs: the kill's wait, KILL_WAIT_MS, and its first polls)

/**
 * A full backup run and the lease's world over ONE virtual clock and ONE cgroup tree. 64 members, all frozen; the
 * target (members[0]) has processes; `stuck` can't be thawed; the worker's scope reaps only after `reapAfterMs`.
 */
function world({ reapAfterMs = 20_000 } = {}) {
  const root = mkdtempSync(join(tmpdir(), "sb-t3-"));
  const dir = join(root, "backup"), fenceDir = join(root, "fence"), leaseDir = join(root, "lease"), leaseFence = join(root, "lease-fence");
  for (const d of [dir, fenceDir, leaseDir, leaseFence]) mkdirSync(d, { recursive: true, mode: 0o700 });
  const members = Array.from({ length: 64 }, () => newId());
  const [target, stuck] = members;
  const j = advance(advance(advance(newJournal(RUN, members), "fenced"), "idle"), "frozen");
  writeJournal(j, { dir });
  for (const a of members) raiseFence("backup", a, { dir: fenceDir });
  let t = 0;
  const clock = { now: () => t, sleep: async (ms) => { t += ms; } };
  const events = [];
  const groups = {};
  for (const a of members) groups[agentSliceCgroup(a)] = { procs: a === target ? 3 : 1, frozen: true };
  const scope = backupScopeCgroup(j.scope);
  groups[scope] = { procs: 2, frozen: false };
  const g = (p) => (groups[p] ??= { procs: 0, frozen: false });
  // The backup's cgroup view (backup-journal's realCgroup shape).
  const cg = {
    kill: (p) => { events.push({ t, what: "kill", p }); if (p !== scope || t >= reapAfterMs) g(p).procs = 0; },
    procs: (p) => g(p).procs,
    freeze: (p, on) => {
      events.push({ t, what: on ? "freeze" : "thaw", p, procs: g(p).procs });
      if (!on && p === agentSliceCgroup(stuck)) return; // (this member's thaw never takes)
      g(p).frozen = on;
    },
    frozen: (p) => g(p).frozen,
  };
  // The lease's system view of the same tree: cgroup.kill works on frozen tasks.
  const sys = {
    mask: async (unit) => { events.push({ t, what: "mask", unit }); },
    // A systemctl stop of a FROZEN slice: its SIGTERM can't land, so it runs its whole bound (lease.mjs STOP_MS) and
    // stops nothing.
    stop: async (unit) => { events.push({ t, what: "stop", unit }); t += 10_000; },
    cgroup: (d) => d,
    kill: (d) => { events.push({ t, what: "lease-kill", p: d }); g(d).procs = 0; },
    empty: (d) => { const e = g(d).procs === 0; if (e) events.push({ t, what: "proven-empty", p: d }); return e; },
  };
  const freeLock = async () => ({ release: async () => {}, held: () => true });
  const expire = (backup) => leaseExpire(target, "L-1", 1, { dir: leaseDir, fenceDir: leaseFence, sys, lock: freeLock, cgroupOf: agentSliceCgroup, backup, wait: clock.sleep });
  return { root, dir, fenceDir, members, target, stuck, clock, events, groups, cg, expire, scope };
}

/** The target's kill and its proof: when they happened, and whether the target was ever thawed with processes in it. */
function targetStop(w) {
  const slice = agentSliceCgroup(w.target);
  const killed = w.events.find((e) => e.what === "lease-kill" && e.p === slice);
  const proven = w.events.find((e) => e.what === "proven-empty" && e.p === slice);
  const thawedLive = w.events.some((e) => e.what === "thaw" && e.p === slice && e.procs > 0);
  return { killed, proven, thawedLive };
}

test("T3: the REAL leaseExpire (production wiring: no backup seam) on a frozen target in a full 64-member journal, the journal lock held, another member stuck and the reap slow: the target is killed and proven empty first, within the stop's bound; nothing is thawed; backup stays raised", async () => {
  const w = world();
  const before = JSON.stringify(readJournal({ dir: w.dir }));
  let release;
  const held = new Promise((r) => { release = r; });
  let lockedNow;
  const locked = new Promise((r) => { lockedNow = r; });
  const holder = withJournalLock(async () => { lockedNow(); await held; }, { dir: w.dir, waitMs: 1000 });
  await locked;
  try {
    const r = await w.expire(null);
    assert.equal(r.proven, true, JSON.stringify(r));
    const s = targetStop(w);
    assert.ok(s.killed && s.proven, "the target's slice killed and proven empty");
    assert.ok(s.proven.t <= STOP_BOUND_MS, `within the stop's own bound (proven at ${s.proven.t} ms)`);
    const stopAt = w.events.find((e) => e.what === "stop");
    assert.ok(stopAt && s.proven.t <= stopAt.t, "killed and proven BEFORE the unit's stop (which a frozen slice holds for its whole bound)");
    assert.equal(s.thawedLive, false, "never thawed while it had processes");
    assert.deepEqual(w.events.filter((e) => e.what === "thaw" || e.what === "freeze" || e.what === "kill"), [], "nothing of the backup touched: no thaw, no reap");
    assert.equal(existsSync(join(w.fenceDir, "backup", w.target)), true, "backup stays raised");
    assert.equal(JSON.stringify(readJournal({ dir: w.dir })), before, "the journal untouched (its lock never taken)");
    assert.equal(w.groups[agentSliceCgroup(w.target)].procs, 0, "nothing of the target runs after its expiry");
  } finally { release(); await holder; }
});

test("T3, then the backup reconciles itself: once the stuck member and the reap come good, the next run's recoverLeftover reaps, thaws every member and lowers backup", async () => {
  const w = world({ reapAfterMs: 0 });
  await w.expire(null);
  // The stuck member comes good (its thaw now takes).
  w.cg.freeze = ((orig) => (p, on) => { w.groups[p].frozen = on; })(w.cg.freeze);
  const r = await recoverLeftover({ binary: async () => ({ ok: true, value: { forgotten: 1 } }), dir: w.dir, fenceDir: w.fenceDir, cg: w.cg, ...w.clock });
  assert.deepEqual(r, { ok: true, recovered: RUN });
  for (const a of w.members) {
    assert.equal(w.groups[agentSliceCgroup(a)].frozen, false, "thawed");
    assert.equal(existsSync(join(w.fenceDir, "backup", a)), false, "backup lowered");
  }
  assert.equal(readJournal({ dir: w.dir }), null);
});

test("T3's control: r0.1's wiring (recoverBackup as the watchdog's backup seam, before the stop) is killed by the deadline assertion, and thaws the target while it still has processes", async () => {
  const w = world();
  const r01 = (agent) => recoverBackup(agent, { dir: w.dir, fenceDir: w.fenceDir, cg: w.cg, ...w.clock, reapMs: 5000, thawMs: 5000, lockWaitMs: 2000 });
  await w.expire(r01);
  const s = targetStop(w);
  assert.ok(s.proven, "the stop still happens, eventually");
  assert.ok(s.proven.t > STOP_BOUND_MS, `the deadline assertion catches it (proven only at ${s.proven.t} ms)`);
  assert.equal(s.thawedLive, true, "and the target was thawed with processes in it, past its expiry");
});

test("T3 in production: every call of leaseExpire outside lease.mjs passes no backup seam (it stays null, r0.4 §3)", async () => {
  const { readdirSync, readFileSync } = await import("node:fs");
  const { fileURLToPath } = await import("node:url");
  const repo = fileURLToPath(new URL("..", import.meta.url));
  const calls = [];
  const walk = (d) => {
    for (const n of readdirSync(join(repo, d), { withFileTypes: true })) {
      const p = join(d, n.name);
      if (n.isDirectory()) walk(p);
      else if (n.name.endsWith(".mjs") && p !== join("lib", "fleet", "host", "lease.mjs")) {
        const text = readFileSync(join(repo, p), "utf8");
        for (const m of text.matchAll(/leaseExpire\(([^)]*)\)/g)) calls.push({ file: p, args: m[1] });
      }
    }
  };
  walk("lib");
  walk("bin");
  assert.ok(calls.length >= 1, "the watchdog's entry calls it");
  const withBackup = (c) => /\bbackup\b/.test(c.args) || c.args.split(",").length > 3;
  assert.deepEqual(calls.filter(withBackup), [], "no production call wires a backup seam");
  // The control: r0.1's wiring would be caught.
  assert.equal(withBackup({ args: "agent, id, lg, { backup: (a) => recoverBackup(a) }" }), true);
  // Those calls rely on leaseExpire's default: it must stay null (no seam unless a caller wires one).
  const lease = readFileSync(join(repo, "lib", "fleet", "host", "lease.mjs"), "utf8");
  const sig = lease.slice(lease.indexOf("export async function leaseExpire("), lease.indexOf("need(agent); needLeaseId(leaseId); needLg(lg);", lease.indexOf("export async function leaseExpire(")));
  assert.match(sig, /\bbackup = null,/, "the default is null");
  assert.equal((sig.match(/\bbackup\b/g) ?? []).length, 1, "and nothing else in the signature names it");
});
