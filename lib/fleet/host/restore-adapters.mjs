// Host restore e2e r1.7 (§3, §7) and delta d2: the restore worker's REAL adapters, over the trusted launcher. Every
// destination effect goes through the launcher by argv (never a shell), with an expect file naming the exact object
// it may touch; this module reads nothing of an agent's tree itself. What the store knows comes from the set's input
// (restore-inputs.mjs), copied by the dispatch: the recorded identities, the owners, the members and the manifest's
// unrestorable paths.
//
// - identifyDest: an agent's home and sessions through `inspect-home --tree home` (identify can't reach the agents'
//   parent); an archive through `identify` under /srv/sagebrush/archive; a tag folder under /srv/sagebrush/tags.
// - isEmpty: `tree-digest` of the identified object, whose whole listing must be exactly the empty one.
// - cleanDest: per class, identify now, require the record's BOUND identity, then `remove-tree --contents` with an
//   expect of that object (A1 r2.6 §5a): the destination is emptied and kept, and the launcher re-checks the object and
//   the epoch at its open, so a swap in between is refused there.
// - discardStaging: every attempt of the set under /srv/sagebrush/.restore, any run, by `identify` then `remove-tree`
//   with owners [0] (A2 r3.11), but, while the record is staging or published, its current attempt.
// - removeCopies: the set's SQLite copy directory under the validation anchor, the same way.
// - stopped: every member restore-fenced and its slice proven empty, live (the caller's seams).
// - launch: the launcher by argv; tree-digest in its transient scope (MemoryMax, RuntimeMaxSec).

import * as fs from "node:fs";
import { join } from "node:path";
import { refuse } from "../bytes.mjs";
import { RESTORE_STAGING, VALIDATE_DIR } from "./names.mjs";
import { CLASSES, RESTORE_RUN, STAGED, ownerOf, sameIdentity } from "./restore-record.mjs";
import { destOf, fillExpect, writeExpectFile } from "./restore-fill.mjs";
import { checkDest } from "./restore-inputs.mjs";
import { realIo } from "./store.mjs";

/** Where the restore's expect files are written (root 0700, as the deprovision's). */
export const RESTORE_EXPECT_DIR = "/run/sagebrush/restore-expect";
const AGENTS = "/srv/sagebrush/agents", ARCHIVE = "/srv/sagebrush/archive", TAGS = "/srv/sagebrush/tags";
const ARCHIVE_CONFIG = "/srv/sagebrush/archive-config";
/** A non-agent class's anchor (A2 r3.13 adds an archive's config archive). */
const anchorOf = (kind, cls) => (cls === "archive-config" ? ARCHIVE_CONFIG : kind === "archive" ? ARCHIVE : TAGS);
/** tree-digest's whole output for an empty directory: the header and a zero total, nothing between. */
export const EMPTY_LISTING = '{"v":1}\n{"count":0,"total_bytes":0}\n';
const ATTEMPT = /^[1-9][0-9]{0,5}$/;

const fail = (what) => refuse("outcome_unknown", `restore adapter: ${what}`);
/** One JSON object on one line, exactly, from an exit-0 launcher run; anything else is unknown. */
function oneJson(r, what) {
  if (r?.code !== 0) fail(`${what} exited ${r?.code}`);
  const s = String(r.stdout ?? "");
  if (!s.endsWith("\n") || s.indexOf("\n") !== s.length - 1) fail(`${what} printed no single line`);
  try { return JSON.parse(s); } catch { fail(`${what} printed no JSON`); }
}

/**
 * The launcher by argv: `launch(args, { ms, signal, scope })`. With `scope` ({ unit, memoryMax, runtimeMaxSec }, as
 * restore-fill gives tree-digest), it runs in that transient scope. `run` is effects.mjs's runArgv.
 */
export function launcherRunner({ run, launcher }) {
  if (typeof run !== "function" || typeof launcher !== "string" || !launcher.startsWith("/")) refuse("bad_form", "restore adapter: the launcher is required");
  return (args, { ms, signal, scope } = {}) => {
    if (!scope) return run([launcher, ...args], { ms, signal });
    const { unit, memoryMax, runtimeMaxSec } = scope;
    if (!/^sagebrush-validate-[a-t]-[a-z2-7]{25}[aeimquy4]\.scope$/.test(unit ?? "") || !/^[0-9]+[KMG]$/.test(memoryMax ?? "") || !Number.isSafeInteger(runtimeMaxSec) || runtimeMaxSec <= 0) {
      refuse("bad_form", "restore adapter: a bad scope");
    }
    return run(["systemd-run", "--scope", "--quiet", "--collect", `--unit=${unit}`, "-p", `MemoryMax=${memoryMax}`, "-p", `RuntimeMaxSec=${runtimeMaxSec}`,
      "--", launcher, ...args], { ms, signal });
  };
}

/**
 * A destination's identity now, by the launcher: an agent's home and sessions through `inspect-home --tree home`
 * (identify can't reach the agents' parent), an archive or a tag folder through `identify` under its own anchor.
 * Resolves to { epoch, fsid, object }; a missing one refuses not_found, anything malformed outcome_unknown.
 */
export function destIdentifier({ launch, mount, ms = 60_000 }) {
  return async (kind, id, cls) => {
    if (!Object.hasOwn(CLASSES, kind) || !CLASSES[kind].includes(cls)) refuse("bad_form", "restore adapter: not a class of the kind");
    if (kind === "agent") {
      const x = oneJson(await launch(["inspect-home", "--mount", mount, "--agent", id, "--tree", "home"], { ms }), "inspect-home");
      const d = { epoch: x?.epoch, fsid: x?.fsid, object: x?.entries?.[cls] ?? null };
      if (d.object === null) refuse("not_found", `restore adapter: the agent's ${cls} is missing`);
      if (!checkDest(d)) fail("inspect-home's entry isn't a directory's identity");
      return d;
    }
    const x = oneJson(await launch(["identify", "--anchor", anchorOf(kind, cls), "--name", id], { ms }), "identify");
    if (x?.object === null) refuse("not_found", `restore adapter: the ${kind} destination is missing`);
    const d = { epoch: x?.epoch, fsid: x?.fsid, object: x?.object };
    if (!checkDest(d)) fail("identify's object isn't a directory's identity");
    return d;
  };
}

/**
 * A set's removals beneath an anchor, by the launcher: `removeUnder(anchor, name, tag)` identifies the object, then
 * remove-tree with an expect of exactly that, owners [0]; `discardStaging(record)` removes every staging of the set
 * under the staging anchor (any run, any attempt) but, while the record is staging or published, its current
 * attempt, and an agent's config attempt while it is files_validated (the config import reads it). `expect(name,
 * value)` writes an expect file and returns its path. Used by the worker's adapters and by the config import step.
 */
export function stagingRemover(kind, id, { launch, staging = RESTORE_STAGING, expect, fsx = fs, ms = 60_000 }) {
  const owner = ownerOf(kind, id);
  const removeUnder = anchorRemover({ launch, expect, ms });
  const names = (dir) => { try { return fsx.readdirSync(dir); } catch (e) { if (e?.code === "ENOENT") return []; throw e; } };
  /** `all`: every attempt, the live one included (an abandon gives the set up: nothing of its staging is kept). */
  async function discardStaging(r, { all = false } = {}) {
    const live = (cls) => !all && (["staging", "published"].includes(r.state)
      // An agent's config attempt outlives the fill: the config import reads it after files_validated (R4).
      || (cls === "config" && r.state === "files_validated"));
    for (const run of names(staging).filter((n) => RESTORE_RUN.test(n)).sort()) {
      for (const cls of STAGED[kind]) {
        for (const attempt of names(join(staging, run, owner, cls)).filter((n) => ATTEMPT.test(n)).sort()) {
          if (live(cls) && run === r.run && attempt === String(r.attempt)) continue;
          await removeUnder(staging, `${run}/${owner}/${cls}/${attempt}`, `s${cls}`);
        }
      }
    }
  }
  /** No attempt of the set left under the staging anchor, any run, any class. */
  const stagingGone = () => names(staging).filter((n) => RESTORE_RUN.test(n))
    .every((run) => STAGED[kind].every((cls) => names(join(staging, run, owner, cls)).filter((n) => ATTEMPT.test(n)).length === 0));
  return { removeUnder, discardStaging, stagingGone };
}

/**
 * A set's destinations, by the launcher: `identifyDest(cls)` (destIdentifier's), `isEmpty(cls, identified)` (tree-digest
 * under an expect of that identity and the class's owners equals EMPTY_LISTING), and `cleanDest(r)` (every class's
 * RECORDED object emptied, remove-tree --contents; another object there refuses, nothing removed). `ownersOf(cls)`: the
 * class's owners ({ uids, gid, projid }). Used by the worker's adapters and by the abandon finish.
 */
export function destTools(kind, id, { launch, mount, expect, ownersOf, ms = 60_000 }) {
  if (!Object.hasOwn(CLASSES, kind)) refuse("bad_form", "restore adapter: not a set kind");
  const owner = ownerOf(kind, id);
  const where = (cls) => (kind === "agent" ? { anchor: AGENTS, name: `${id}/${cls}` } : { anchor: anchorOf(kind, cls), name: id });
  const identifyNow = destIdentifier({ launch, mount, ms });
  const identifyDest = (cls) => identifyNow(kind, id, cls);
  const expectOf = (cls, identity) => expect(cls, fillExpect(identity, ownersOf(cls)));
  async function isEmpty(cls, identified) {
    const path = await expectOf(cls, identified);
    const r = await launch(["tree-digest", "--mount", mount, "--owner", owner, "--class", cls, "--expect", path], { ms });
    return r?.code === 0 && r.stdout === EMPTY_LISTING;
  }
  async function cleanDest(r) {
    for (const cls of CLASSES[kind]) {
      const now = await identifyDest(cls);
      // Only the record's bound object is ever emptied: another one here refuses, nothing removed.
      if (!sameIdentity(destOf(now.object), r.dest[cls])) refuse("not_granted", `restore adapter: the ${cls} isn't the bound destination`);
      const owners = [...new Set([0, ...ownersOf(cls).uids])]; // (root, then the class's own: root alone for a root class)
      const path = expect(`c${cls}`, { epoch: now.epoch, fsid: now.fsid, root: now.object, owners });
      const { anchor, name } = where(cls);
      const out = await launch(["remove-tree", "--contents", "--anchor", anchor, "--name", name, "--expect", path], { ms });
      if (out?.code !== 0) fail(`remove-tree --contents of the ${cls} exited ${out?.code}`);
    }
  }
  return { identifyDest, expectOf, isEmpty, cleanDest };
}

/**
 * Remove one object beneath an anchor, by the launcher: identify it, then remove-tree with an expect of exactly that
 * object, owners [0]; nothing there is fine. Shared by the sets' staging removals and the host-store stage's.
 */
export function anchorRemover({ launch, expect, ms = 60_000 }) {
  return async function removeUnder(anchor, name, tag) {
    const x = oneJson(await launch(["identify", "--anchor", anchor, "--name", name], { ms }), "identify");
    if (x?.object === null) return;
    const path = expect(tag, { epoch: x.epoch, fsid: x.fsid, root: x.object, owners: [0] });
    const out = await launch(["remove-tree", "--anchor", anchor, "--name", name, "--expect", path], { ms });
    if (out?.code !== 0) fail(`remove-tree of ${anchor}/${name} exited ${out?.code}`);
  };
}

/** An expect-file writer for a set's owner (an expect file's name is the owner and letters, a class's hyphen dropped). */
export const expectWriter = (owner, { expectDir = RESTORE_EXPECT_DIR, rootUid = 0, rootGid = 0, io = realIo } = {}) =>
  (name, value) => writeExpectFile(expectDir, `${owner}-${name.replace(/-/g, "")}.json`, value, { rootUid, rootGid, io });

/**
 * The fill driver's adapters for one set, over its checked `input`. Options: `launch` (launcherRunner's), `mount`,
 * `fenceRaised(agent)` (the agent's `restore` fence is up), `sliceEmpty(agent)` (its slice holds no process, proven),
 * and seams: `expectDir`, `staging` (the staging anchor), `copies` (the validation anchor), `rootUid`, `rootGid`, `io`,
 * `fsx`, `ms` (each launcher call's deadline).
 */
export function restoreAdapters(input, { launch, mount, fenceRaised, sliceEmpty, expectDir = RESTORE_EXPECT_DIR, staging = RESTORE_STAGING,
  copies = VALIDATE_DIR, rootUid = 0, rootGid = 0, io = realIo, fsx = fs, ms = 60_000 } = {}) {
  if (typeof launch !== "function" || typeof mount !== "string" || typeof fenceRaised !== "function" || typeof sliceEmpty !== "function") {
    refuse("bad_form", "restore adapter: launch, mount and the stop seams are required");
  }
  const { kind, id } = input;
  const owner = ownerOf(kind, id);
  const classOf = (k, i, cls) => {
    if (k !== kind || i !== id || !CLASSES[kind].includes(cls)) refuse("bad_form", "restore adapter: not this set's class");
    return input.classes[cls];
  };
  // (an expect file's name is the owner and letters: a class's hyphen dropped, so "archive-config" is "archiveconfig")
  const expect = expectWriter(owner, { expectDir, rootUid, rootGid, io });
  const tools = destTools(kind, id, { launch, mount, expect, ownersOf: (cls) => input.classes[cls].owners, ms });
  const identifyDest = async (k, i, cls) => { classOf(k, i, cls); return tools.identifyDest(cls); };
  const expectOf = async (k, i, cls, identity) => { classOf(k, i, cls); return tools.expectOf(cls, identity); };
  const isEmpty = async (k, i, cls, identified) => { classOf(k, i, cls); return tools.isEmpty(cls, identified); };
  const cleanDest = (r) => tools.cleanDest(r);

  const { removeUnder, discardStaging } = stagingRemover(kind, id, { launch, staging, expect, fsx, ms });
  const removeCopies = async (r) => removeUnder(copies, `${r.run}/${owner}`, "copies");

  /** Every member restore-fenced and its slice proven empty, asked live; an archive has none to stop. */
  async function stopped() {
    for (const m of input.members) {
      if ((await fenceRaised(m.agent)) !== true || (await sliceEmpty(m.agent)) !== true) return false;
    }
    return true;
  }

  return {
    launch, mount, identifyDest, isEmpty, expectOf, cleanDest, discardStaging, removeCopies, stopped,
    projidOf: (k, i) => classOf(k, i, CLASSES[kind][0]).owners.projid,
    unrestorableOf: (k, i, cls) => [...classOf(k, i, cls).unrestorable],
  };
}
