// Host supervisor (design: agent-autonomous-host-deprovision.md r3.2 §2, §3; amendment L1; launcher amendment A1): the
// deprovision of a deleted agent, one pass at a time. The executor's delete runs a pass right after its stop proof;
// recovery runs one for every deleted agent whose record isn't done.
//
// - BEFORE any step of a pass: the cgroup proof (the agent's unit has no process) and the whole-host uid-empty proof
//   (uid-proof.mjs). If either fails, NOTHING runs: the pass ends `pending`.
// - The steps run in the fixed order of deprovision-record.mjs, each as VERIFY, ACT, MARK: a step first checks for its
//   own completed state by the same identity checks, acts only if needed, and is marked only on proof.
// - Everything destructive goes through the trusted launcher (identify, inspect-home, archive-home, remove-tree): an
//   object's identity is recorded before it is removed, and only that exact object can be.
// - Anything the launcher refuses (another object, a foreign owner, a mount, a stale epoch, an existing destination)
//   PARKS the agent: the pass ends `pending` with the reason, nothing is guessed, and a person (or the local root
//   requalify command, for a stale epoch) resolves it. A partial removal (75) is retried by the next pass.
// - The accounts step waits until the agent is in no pool (`inPool`), re-takes both proofs, and removes only the user
//   and group that still have exactly the recorded uid and gid. The proofs are taken again before `done`.

import fs from "node:fs";
import { join } from "node:path";
import { isId } from "../bytes.mjs";
import { STEPS, bindingMatches } from "./deprovision-record.mjs";
import { agentUnit, agentUser, UNIT_DIR } from "./names.mjs";

const hostFail = (what) => Object.assign(new Error(`deprovision: ${what}`), { code: "effect_failed" });
/** Where the expect files for the launcher are written: root 0700, one per object, rewritten for every call. */
export const EXPECT_DIR = "/run/sagebrush/deprovision";

/** The host files removed in the `files` step (deprovision r3.2 §3.5, L1 for secrets): key, anchor, name. */
const FILES = (id) => [
  ["creds", "/var/lib/sagebrush/creds", id],
  ["contract", "/var/lib/sagebrush/contract", `${id}.json`],
  ["resolv", "/var/lib/sagebrush/resolv", `${id}.conf`],
  ["managed", "/var/lib/sagebrush/managed", id],
  ["secrets", "/var/lib/sagebrush/secrets", id],
];

/**
 * The deprovisioner. Options:
 * - `store`: the host store (registry, deprovision, provisioned);
 * - `run(argv, { ms, signal })`: the argv runner; `launcher`: the release's sagebrush-agent-launch path;
 *   `mount`: the quota mount (or "/");
 * - `procCount(agent, ms, signal)`: the agent's cgroup process count (the cgroup proof);
 * - `uidProof(uid, agent, ms, signal)`: { empty, holders } (uid-proof.mjs);
 * - `daemonReload(ms, signal)`, `removeNetwork(agent, uid, left, signal)`, `brokerRevoke(agent, ms, signal)`;
 * - `inPool(agent)`: whether any harness pool entry still names the agent;
 * - `fsx`, `root` (a prefix for tests), `rootUid`.
 * Returns { pass(agent, ms, signal) } → { status: "done" | "pending", step, reason }.
 */
export function deprovisioner({ store, run, launcher, mount = "/", procCount, uidProof, daemonReload, removeNetwork, brokerRevoke, inPool, fsx = fs, root = "", rootUid = 0 } = {}) {
  for (const [k, f] of Object.entries({ run, procCount, uidProof, daemonReload, removeNetwork, brokerRevoke, inPool })) {
    if (typeof f !== "function") throw hostFail(`${k} is required`);
  }
  if (!store || typeof launcher !== "string") throw hostFail("store and launcher are required");
  const at = (p) => `${root}${p}`;

  /** The launcher, by argv: { code, stdout, stderr } (never a shell). */
  const launch = (args, left, signal) => run([launcher, ...args], { ms: left(), signal });
  const json = (r, what) => { try { return JSON.parse(r.stdout); } catch { throw hostFail(`${what} printed no JSON`); } };

  /** An expect file for the launcher: root 0600 in a root 0700 directory, written whole, synced, renamed, the directory synced. */
  const writeExpect = (agent, key, value) => {
    try { fsx.mkdirSync(at(EXPECT_DIR), { recursive: true, mode: 0o700 }); } catch { throw hostFail("the expect directory can't be made"); }
    const st = fsx.lstatSync(at(EXPECT_DIR));
    if (!st.isDirectory() || st.uid !== rootUid || (st.mode & 0o077) !== 0) throw hostFail("the expect directory isn't root-only");
    const p = join(EXPECT_DIR, `${agent}-${key}.json`);
    const tmp = `${p}.tmp`;
    fsx.rmSync(at(tmp), { force: true });
    const fd = fsx.openSync(at(tmp), "wx", 0o600);
    try { fsx.writeSync(fd, JSON.stringify(value)); fsx.fsyncSync(fd); } finally { fsx.closeSync(fd); }
    fsx.renameSync(at(tmp), at(p));
    const dfd = fsx.openSync(at(EXPECT_DIR), "r");
    try { fsx.fsyncSync(dfd); } finally { fsx.closeSync(dfd); }
    return p;
  };

  /** Both proofs (deprovision r3.2 §2). Returns null when both hold, else the reason (nothing may run). */
  const proofs = async (agent, uid, left, signal) => {
    let n;
    try { n = await procCount(agent, left(), signal); } catch { return "the cgroup can't be read"; }
    if (n !== 0) return `the cgroup has ${n} process(es)`;
    let u;
    try { u = await uidProof(uid, agent, left(), signal); } catch { return "the uid can't be proven empty"; }
    return u.empty ? null : `the uid is held: ${u.holders.join(", ")}`;
  };

  /**
   * Remove one object beneath a compiled anchor: identify it; record its identity once (or require the recorded one);
   * then remove-tree with exactly that identity. Returns null when the object is gone, or the reason to park.
   */
  const removeObject = async (agent, key, anchor, name, owners, left, signal) => {
    const r = await launch(["identify", "--anchor", anchor, "--name", name], left, signal);
    if (r.code !== 0) return `identify ${key} exited ${r.code}`;
    const now = json(r, "identify");
    const rec = store.deprovision.record(agent);
    const have = rec.identities[key];
    // Absent and never recorded: never made, nothing to do. Absent but recorded (an earlier pass's remove-tree, perhaps
    // with a 75 at its final sync): the launcher still decides, with the recorded expect: the epoch first (a stale one
    // parks), then the anchor synced again (A1 r2.4 §5).
    if (now.object === null && !have) return null;
    if (now.object !== null && have) {
      if (have.epoch.boot_id !== now.epoch.boot_id || have.epoch.mnt_id !== now.epoch.mnt_id) return `${key}: a stale epoch (requalify)`;
      if (JSON.stringify(have.object) !== JSON.stringify(now.object) || have.fsid !== now.fsid) return `${key}: another object than the recorded one`;
    } else if (!have) {
      store.deprovision.recordIdentity(agent, key, now);
    }
    const ident = store.deprovision.record(agent).identities[key];
    const expect = writeExpect(agent, key, { epoch: ident.epoch, fsid: ident.fsid, root: ident.object, owners });
    const rm = await launch(["remove-tree", "--anchor", anchor, "--name", name, "--expect", expect], left, signal);
    if (rm.code === 0) return null;
    if (rm.code === 75) return `${key}: partly removed; the next pass retries`;
    return `${key}: remove-tree refused (${rm.code})`;
  };

  /** inspect-home for `tree`, live or archived: the output, or "absent", or the refusal code. */
  const inspect = async (agent, tree, archive, left, signal) => {
    const r = await launch(["inspect-home", "--mount", mount, "--agent", agent, "--tree", tree, ...(archive ? ["--archive"] : [])], left, signal);
    if (r.code === 0) return json(r, "inspect-home");
    if (r.code === 73 && /the tree is absent/.test(r.stderr)) return "absent";
    return { refused: r.code };
  };
  const sameEpoch = (a, b) => a.epoch.boot_id === b.epoch.boot_id && a.epoch.mnt_id === b.epoch.mnt_id;
  const exact = (a, b) => JSON.stringify(a) === JSON.stringify(b);

  /**
   * Archive one tree (deprovision r3.2 §3.6, L1 step 6b) by the retry table. Returns null when it is archived as
   * recorded, or the reason to park (or retry).
   */
  const archiveTree = async (agent, tree, left, signal) => {
    const src = await inspect(agent, tree, false, left, signal);
    const dst = await inspect(agent, tree, true, left, signal);
    if (src?.refused || dst?.refused) return `${tree}: inspect refused (${src?.refused ?? dst?.refused})`;
    let rec = store.deprovision.record(agent);
    if (!rec.identities[tree]) {
      // Before the move: the source must be exactly the provisioned identity, in the current epoch.
      if (src === "absent") return `${tree}: the source is missing and nothing was recorded`;
      const prov = store.provisioned.record(agent);
      if (!prov) return `${tree}: no provisioned identity`;
      const want = tree === "home" ? prov.home : prov.config;
      const got = tree === "home" ? src : { epoch: src.epoch, fsid: src.fsid, dir: src.dir };
      if (!sameEpoch(want, got)) return `${tree}: a stale epoch (requalify)`;
      if (!exact(want, got)) return `${tree}: not the provisioned tree`;
      store.deprovision.recordIdentity(agent, tree, src);
      rec = store.deprovision.record(agent);
    }
    const ident = rec.identities[tree];
    const live = src !== "absent" ? src : dst !== "absent" ? dst : null;
    if (live && !sameEpoch(ident, live)) return `${tree}: a stale epoch (requalify)`;
    if (src !== "absent" && dst === "absent") {
      if (!exact(src, ident)) return `${tree}: the source differs from the recorded identity`;
      const expect = writeExpect(agent, tree, ident);
      const r = await launch(["archive-home", "--mount", mount, "--agent", agent, "--tree", tree, "--expect", expect], left, signal);
      if (r.code === 0) return null;
      if (r.code === 75) return `${tree}: moved, not yet confirmed; the next pass verifies`;
      return `${tree}: archive-home refused (${r.code})`;
    }
    if (src === "absent" && dst !== "absent") {
      // Already moved (a crash, or a 75 at either sync, after the rename): only the exact recorded object, and done
      // only once the launcher has synced both parents again (archive-home --finish; A1 r2.4 §4a).
      if (!exact(dst, ident)) return `${tree}: the archive differs from the recorded identity`;
      const expect = writeExpect(agent, tree, ident);
      const r = await launch(["archive-home", "--mount", mount, "--agent", agent, "--tree", tree, "--expect", expect, "--finish"], left, signal);
      if (r.code === 0) return null;
      if (r.code === 75) return `${tree}: archived, not yet confirmed durable; the next pass syncs again`;
      return `${tree}: archive-home --finish refused (${r.code})`;
    }
    return src === "absent" ? `${tree}: neither the source nor the archive exists` : `${tree}: both the source and the archive exist`;
  };

  /** The unit file: exactly the generated name, a regular root file (never a symlink); removed, then daemon-reload. */
  const removeUnit = async (agent, left, signal) => {
    const p = join(UNIT_DIR, agentUnit(agent));
    let st = null;
    try { st = fsx.lstatSync(at(p)); } catch (e) { if (e?.code !== "ENOENT") throw hostFail("the unit file can't be read"); }
    if (st) {
      if (!st.isFile() || st.uid !== rootUid) return "the unit file isn't a regular root file";
      fsx.unlinkSync(at(p));
      const dfd = fsx.openSync(at(UNIT_DIR), "r");
      try { fsx.fsyncSync(dfd); } finally { fsx.closeSync(dfd); }
    }
    await daemonReload(left(), signal);
    return null;
  };

  /** The staged mounts under the agent's staging directory detached (the staging tree is then removed by remove-tree). */
  const detachStaging = async (agent, left, signal) => {
    const dir = `/run/sagebrush/binds/${agent}`;
    let names = [];
    try { names = fsx.readdirSync(at(dir)); } catch (e) { if (e?.code === "ENOENT") return null; throw hostFail("the staging directory can't be listed"); }
    for (const n of names.filter((x) => /^[0-9]+$/.test(x))) {
      for (let i = 0; ; i++) {
        const m = await run(["mountpoint", "-q", "--nofollow", at(`${dir}/${n}`)], { ms: left(), signal });
        if (m.code !== 0) break;
        if (i === 8) return "a staged mount won't detach";
        const u = await run(["umount", "--lazy", "--no-canonicalize", at(`${dir}/${n}`)], { ms: left(), signal });
        if (u.code !== 0) return "a staged mount won't detach";
      }
    }
    return null;
  };

  /** The user and its private group, only with exactly the recorded uid and gid; userdel without -r. */
  const removeAccounts = async (agent, uid, left, signal) => {
    const name = agentUser(agent);
    const getent = async (db, key) => {
      const r = await run(["getent", db, String(key)], { ms: left(), signal });
      if (r.code === 2) return null;
      if (r.code !== 0) throw hostFail(`getent ${db} failed`);
      const lines = r.stdout.split("\n").filter(Boolean);
      if (lines.length !== 1) throw hostFail(`getent ${db} returned ${lines.length} entries`);
      return lines[0].split(":");
    };
    const pw = await getent("passwd", name);
    if (pw) {
      if (pw[2] !== String(uid) || pw[3] !== String(uid)) return "the user has another uid or gid";
      const r = await run(["userdel", name], { ms: left(), signal });
      if (r.code !== 0) throw hostFail(`userdel exited ${r.code}`);
    } else if (await getent("passwd", uid)) return "another user holds the uid";
    const gr = await getent("group", name);
    if (gr) {
      if (gr[2] !== String(uid)) return "the group has another gid";
      if ((gr[3] ?? "") !== "") return "the group has members";
      const r = await run(["groupdel", name], { ms: left(), signal });
      if (r.code !== 0) throw hostFail(`groupdel exited ${r.code}`);
    } else if (await getent("group", uid)) return "another group holds the gid";
    return null;
  };

  /** One pass. */
  const pass = async (agent, ms, signal) => {
    const t0 = Date.now();
    const left = () => ms - (Date.now() - t0);
    if (!isId(agent)) throw hostFail("bad agent id");
    const reg = store.registry.agent(agent);
    if (reg?.state !== "deleted") throw hostFail("only a deleted agent is deprovisioned");
    let rec = store.deprovision.ensure(agent, reg);
    if (!bindingMatches(rec, reg)) return { status: "pending", step: null, reason: "the record is bound to another life" };
    if (rec.done) return { status: "done", step: null, reason: null };
    const uid = reg.uid;
    const pending = (step, reason) => ({ status: "pending", step, reason });
    const gate = await proofs(agent, uid, left, signal);
    if (gate) return pending(STEPS[rec.steps_done.length], gate);
    for (const step of STEPS.slice(rec.steps_done.length)) {
      let why = null;
      switch (step) {
        case "channels": await brokerRevoke(agent, left(), signal); break;
        case "unit": why = await removeUnit(agent, left, signal); break;
        case "network": await removeNetwork(agent, uid, left, signal); break;
        case "runtime":
          why = await detachStaging(agent, left, signal)
            ?? await removeObject(agent, "binds", "/run/sagebrush/binds", agent, [rootUid], left, signal)
            ?? await removeObject(agent, "broker", "/run/sagebrush/broker", agent, [rootUid, uid], left, signal);
          break;
        case "files":
          for (const [key, anchor, name] of FILES(agent)) {
            why = await removeObject(agent, key, anchor, name, [rootUid], left, signal);
            if (why) break;
          }
          break;
        case "home":
        case "config":
          why = await archiveTree(agent, step, left, signal);
          break;
        case "accounts": {
          if (inPool(agent)) { why = "the agent is still in a harness pool"; break; }
          why = await proofs(agent, uid, left, signal);
          if (why) break;
          why = await removeAccounts(agent, uid, left, signal);
          if (why) break;
          why = await proofs(agent, uid, left, signal); // again, immediately before done
          break;
        }
        default: throw hostFail(`an unknown step ${step}`);
      }
      if (why) return pending(step, why);
      rec = store.deprovision.markStep(agent, step);
    }
    return { status: "done", step: null, reason: null };
  };

  return { pass };
}
