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
import { CLASSES, RESTORE_RUN, ownerOf, sameIdentity } from "./restore-record.mjs";
import { destOf, fillExpect, writeExpectFile } from "./restore-fill.mjs";
import { checkDest } from "./restore-inputs.mjs";
import { realIo } from "./store.mjs";

/** Where the restore's expect files are written (root 0700, as the deprovision's). */
export const RESTORE_EXPECT_DIR = "/run/sagebrush/restore-expect";
const AGENTS = "/srv/sagebrush/agents", ARCHIVE = "/srv/sagebrush/archive", TAGS = "/srv/sagebrush/tags";
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
  const expect = (name, value) => writeExpectFile(expectDir, `${owner}-${name}.json`, value, { rootUid, rootGid, io });
  const where = (cls) => (kind === "agent" ? { anchor: AGENTS, name: `${id}/${cls}` } : { anchor: kind === "archive" ? ARCHIVE : TAGS, name: id });

  async function identifyDest(k, i, cls) {
    classOf(k, i, cls);
    if (kind === "agent") {
      const x = oneJson(await launch(["inspect-home", "--mount", mount, "--agent", id, "--tree", "home"], { ms }), "inspect-home");
      const d = { epoch: x?.epoch, fsid: x?.fsid, object: x?.entries?.[cls] ?? null };
      if (d.object === null) refuse("not_found", `restore adapter: the agent's ${cls} is missing`);
      if (!checkDest(d)) fail("inspect-home's entry isn't a directory's identity");
      return d;
    }
    const x = oneJson(await launch(["identify", "--anchor", where(cls).anchor, "--name", id], { ms }), "identify");
    if (x?.object === null) refuse("not_found", `restore adapter: the ${kind} destination is missing`);
    const d = { epoch: x?.epoch, fsid: x?.fsid, object: x?.object };
    if (!checkDest(d)) fail("identify's object isn't a directory's identity");
    return d;
  }

  const expectOf = async (k, i, cls, identity) => expect(cls, fillExpect(identity, classOf(k, i, cls).owners));

  async function isEmpty(k, i, cls, identified) {
    const path = await expectOf(k, i, cls, identified);
    const r = await launch(["tree-digest", "--mount", mount, "--owner", owner, "--class", cls, "--expect", path], { ms });
    return r?.code === 0 && r.stdout === EMPTY_LISTING;
  }

  async function cleanDest(r) {
    for (const cls of CLASSES[kind]) {
      const now = await identifyDest(kind, id, cls);
      // Only the record's bound object is ever emptied: another one here refuses, nothing removed.
      if (!sameIdentity(destOf(now.object), r.dest[cls])) refuse("not_granted", `restore adapter: the ${cls} isn't the bound destination`);
      const path = expect(`c${cls}`, { epoch: now.epoch, fsid: now.fsid, root: now.object, owners: [0, ...input.classes[cls].owners.uids] });
      const { anchor, name } = where(cls);
      const out = await launch(["remove-tree", "--contents", "--anchor", anchor, "--name", name, "--expect", path], { ms });
      if (out?.code !== 0) fail(`remove-tree --contents of the ${cls} exited ${out?.code}`);
    }
  }

  /** Remove one object beneath an anchor: identify it, then remove-tree with an expect of exactly that, owners [0]. */
  async function removeUnder(anchor, name, tag) {
    const x = oneJson(await launch(["identify", "--anchor", anchor, "--name", name], { ms }), "identify");
    if (x?.object === null) return;
    const path = expect(tag, { epoch: x.epoch, fsid: x.fsid, root: x.object, owners: [0] });
    const out = await launch(["remove-tree", "--anchor", anchor, "--name", name, "--expect", path], { ms });
    if (out?.code !== 0) fail(`remove-tree of ${anchor}/${name} exited ${out?.code}`);
  }
  const names = (dir) => { try { return fsx.readdirSync(dir); } catch (e) { if (e?.code === "ENOENT") return []; throw e; } };

  async function discardStaging(r) {
    const keep = ["staging", "published"].includes(r.state) ? { run: r.run, attempt: String(r.attempt) } : null;
    for (const run of names(staging).filter((n) => RESTORE_RUN.test(n)).sort()) {
      for (const cls of CLASSES[kind]) {
        for (const attempt of names(join(staging, run, owner, cls)).filter((n) => ATTEMPT.test(n)).sort()) {
          if (keep && run === keep.run && attempt === keep.attempt) continue;
          await removeUnder(staging, `${run}/${owner}/${cls}/${attempt}`, `s${cls}`);
        }
      }
    }
  }

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
