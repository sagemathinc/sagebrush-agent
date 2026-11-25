// Host backup (design: agent-autonomous-host-backup.md r3.3 §5 steps 7-8, T3, T5, H2; launcher amendment A2): the
// per-set fill driver. Dormant: nothing calls it yet.
//
// One set (an agent, a deleted agent's archive, a tag folder) is restored by moving its record (restore-record.mjs)
// one step at a time, each step written BEFORE it acts, and every effect is the launcher's:
// - stage: per class, `restore-stage` restores the class from the set's snapshot into
//   <run>/<owner>/<class>/<attempt>/data/<leaf> (launcher amendment A2 r3.5: only that class), charged
//   to the class's project, and writes the class's completion marker once the data is durable. When every class's
//   marker is exactly its name, the record steps to staged. Each class's success line is exactly
//   {ok, snapshot, skipped_special, digests_sha256} (A2 r3.8.3), the snapshot the record's; its hash is written into
//   the record (the "digest" step) before the next class is staged.
// - fill: the record steps to filling, with the destinations' identities, BEFORE the first `fill-home`; per class,
//   `fill-home` unlinks the marker (the attempt is consumed from then on) and moves the staged class into its empty,
//   provisioned destination, checked against the expect file (the destination's identity in this epoch, the owners,
//   the project). Each class's report ({placed, refused, unexpected, truncated}) is saved, bound to the attempt, and
//   when every class is placed, the record steps to published.
// - validate (A2 r3.8.3 §4a, §4b): with the set stopped and fenced, per class, the staged digest list is read and must
//   hash to the recorded value, `tree-digest` lists the filled destination (a sessions class with its SQLite copies),
//   and the list less fill's refused entries and the manifest's unrestorable ones must be that listing exactly; every
//   copied database must pass quick_check. Then validated, and only then is the attempt discarded. A mismatch, a
//   missing list or report, or a tree-digest refusal is failed (still fenced, never re-staged automatically); a
//   transient tree-digest exit (75, or 74's stale copy directory, removed first) is tried again, a bounded number of
//   times, from the start.
// - What the launcher's exit means (A2 §3.1): 0 done; 76 a quota hit, permanent: not_fitting, never retried
//   automatically (H2); 77 the filesystem out of space and 75 a partial or interrupted step: a new automatic attempt
//   (T5), bounded by the record's MAX_ATTEMPTS; 74 an attempt that already exists: begun, so a new attempt; anything
//   else (a refusal, a changed identity, a contract or internal error): failed (outcome_unknown), stopped.
// - Recovery and the loop are recoveryStep's: a dirty record's destinations are emptied first, under their recorded
//   identities; a filling record is never filled again. Staging is discarded before each new attempt is staged, and a
//   settled set's (published, validated or stopped) before it is reported (on every call, so a crash in between is
//   repaired); a stop is never restaged or refilled automatically.
// Everything runs under the restore lock, which the caller holds. The launcher, the destinations' identities and the
// cleanups are injected (the real adapters come with provisioning), so every branch is tested against fakes.

import { randomBytes } from "node:crypto";
import * as fs from "node:fs";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { FleetError, refuse } from "../bytes.mjs";
import { checkIdentified } from "./deprovision-record.mjs";
import { RESTORE_DIR, SRV, VALIDATE_DIR } from "./names.mjs";
import { checkRegistry } from "./registry.mjs";
import { realIo } from "./store.mjs";
import {
  CLASSES, MAX_ATTEMPTS, checkFillReport, newRecord, ownerOf, readFillReport, readMarker, readRecord, readRegular, recoveryStep, stagingDir,
  step, writeFillReport, writeRecord,
} from "./restore-record.mjs";
import { MAX_LISTING, checkClass, checkCopies } from "./restore-validate.mjs";
import { checkPlan } from "./restore-plan.mjs";

/** The launcher's exit codes the driver tells apart (A2 §3.1; err.rs). */
export const EXIT = Object.freeze({ ok: 0, exists: 74, partial: 75, quota: 76, no_space: 77 });
/** fill-home's bound on a class's owners (A2: a tag's members). */
const MAX_UIDS = 64;
/** At most this many steps per call: a fill settles in far fewer; more is a bug, never a loop. */
const MAX_STEPS = 64;
/** tree-digest runs per class per validation for its transient exits (75, 74) before the set fails. */
const DIGEST_TRIES = 3;
/** tree-digest's scope (A2 r3.7 S3): its memory bound and, by default, validation's deadline per class. */
export const VALIDATE_MEMORY_MAX = "1G";
const VALIDATE_SECONDS = 3600;

/**
 * Where a class lives in the backup, as restore-stage's `--path` (beneath the snapshot's root: the class directory
 * itself), and where it lands in staging, as fill-home's `--source`. Launcher amendment A2 r3.5: restore-stage restores
 * the CONTENTS of `--path` into data/<leaf>, <leaf> being the path's last segment, so only this class is staged (and
 * charged to its project), never its sibling.
 */
export function classPaths(kind, id, cls) {
  ownerOf(kind, id);
  const rel = SRV.slice(1);
  const path = { "agent/home": `${rel}/agents/${id}/home`, "agent/sessions": `${rel}/agents/${id}/sessions`,
    "archive/archive": `${rel}/archive/${id}`, "tag/tag": `${rel}/tags/${id}` }[`${kind}/${cls}`];
  if (path === undefined) refuse("bad_form", "restore fill: not a class of this set");
  return { path, source: `data/${path.slice(path.lastIndexOf("/") + 1)}` };
}

/**
 * The owners and project of a set's classes, from the RESTORED registry (registry.mjs's shape): an agent's and an
 * archive's are its uid (gid = uid, project = uid); a tag folder's uids are its live members' (sorted), its gid and
 * project the tag's gid. Refuses when the registry doesn't say: an unknown or wrongly-stated agent, an unknown tag, or
 * a tag with no live member (nobody could own its entries).
 */
export function ownersOf(kind, id, registry) {
  ownerOf(kind, id);
  checkRegistry(registry);
  if (kind === "tag") {
    const t = Object.hasOwn(registry.tags, id) ? registry.tags[id] : null;
    if (!t) refuse("not_found", "restore fill: not a tag of the restored registry");
    const uids = Object.values(registry.agents).filter((a) => a.state !== "deleted" && a.tags.includes(id)).map((a) => a.uid).sort((x, y) => x - y);
    if (uids.length === 0 || uids.length > MAX_UIDS) refuse("not_found", "restore fill: a tag folder with no live member (or too many) isn't filled");
    return { uids, gid: t.gid, projid: t.gid };
  }
  const a = Object.hasOwn(registry.agents, id) ? registry.agents[id] : null;
  if (!a || (kind === "archive") !== (a.state === "deleted")) refuse("not_found", "restore fill: not this set's agent in the restored registry");
  return { uids: [a.uid], gid: a.uid, projid: a.uid };
}

/**
 * fill-home's expect (A2 §4 step 1): the destination's identity as `identify` printed it in this epoch, and the class's
 * owners and project (ownersOf). A closed shape; refuses an identity that isn't the launcher's exact form.
 */
export function fillExpect(identity, owners) {
  if (!checkIdentified(identity)) refuse("bad_form", "restore fill: not an identified destination");
  if (identity.object.type !== "dir" || identity.object.projid !== owners.projid || identity.object.inherit !== true) {
    refuse("not_granted", "restore fill: the destination isn't a directory in the class's project, with the inherit flag");
  }
  return { epoch: identity.epoch, fsid: identity.fsid, dest: identity.object, uids: [...owners.uids], gid: owners.gid, projid: owners.projid };
}

/**
 * Write an expect file: root 0600 in a root 0700 directory (owned by `rootUid`:`rootGid`, nobody else may read or
 * write it, never a link), written whole into a fresh temp name created exclusively (O_EXCL: never an existing entry,
 * never through a link), fsynced, renamed over the name (a link planted there is replaced, never followed), the
 * directory fsynced. `rootUid`/`rootGid`/`io` are the test seam (the real caller passes root's, 0 and 0). Its path.
 */
export function writeExpectFile(dir, name, value, { rootUid = 0, rootGid = 0, io = realIo } = {}) {
  if (!/^[a-z]+-[a-z2-7]{25}[aeimquy4]-[a-z]+\.json$/.test(name)) refuse("bad_form", "restore fill: bad expect name");
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const st = fs.lstatSync(dir);
  if (!st.isDirectory() || st.uid !== rootUid || st.gid !== rootGid || (st.mode & 0o077) !== 0) {
    refuse("not_granted", "restore fill: the expect directory isn't root-only");
  }
  const tmp = join(dir, `.${name}.${randomBytes(8).toString("hex")}.tmp`);
  const buf = Buffer.from(JSON.stringify(value) + "\n");
  const fd = io.open(tmp, "wx", 0o600);
  try {
    try {
      for (let off = 0; off < buf.length;) {
        const n = io.write(fd, buf, off, buf.length - off);
        if (!Number.isSafeInteger(n) || n <= 0 || n > buf.length - off) throw Object.assign(new Error("short write"), { code: "EIO" });
        off += n;
      }
      io.fsync(fd);
    } finally { io.close(fd); }
    io.rename(tmp, join(dir, name));
  } catch (e) { try { fs.unlinkSync(tmp); } catch {} throw e; }
  const dfd = io.open(dir, "r");
  try { io.fsync(dfd); } finally { io.close(dfd); }
  if (!fs.readFileSync(join(dir, name)).equals(buf)) refuse("outcome_unknown", "restore fill: the expect file read back differs");
  return join(dir, name);
}

/** What a launcher exit means for the record (see the header). */
export function outcomeOf(code) {
  if (code === EXIT.ok) return "ok";
  if (code === EXIT.quota) return "not_fitting";
  if (code === EXIT.no_space || code === EXIT.partial || code === EXIT.exists) return "retry";
  return "failed";
}

/**
 * The record's destination identity of one class: from the launcher's [major, minor] device (A1 §1) as one decimal,
 * major * 2^20 + minor, and its inode. Compare only against launcher objects through destOf, never against a device
 * number from anywhere else (whose encoding may differ).
 */
export const destOf = (object) => ({ dev: String(object.dev[0] * 2 ** 20 + object.dev[1]), ino: String(object.ino) });

const HEX64 = /^[0-9a-f]{64}$/;
/** One JSON line exactly: the text, one "\n" at its end and none before it, as an object; null otherwise. */
const oneLine = (stdout) => {
  if (typeof stdout !== "string" || !stdout.endsWith("\n") || stdout.indexOf("\n") !== stdout.length - 1) return null;
  try { const v = JSON.parse(stdout); return v !== null && typeof v === "object" && !Array.isArray(v) ? v : null; } catch { return null; }
};
const keysAre = (o, keys) => Object.keys(o).length === keys.length && keys.every((k) => Object.hasOwn(o, k));

/**
 * restore-stage's success line (A2 r3.8.3): exactly {ok: true, snapshot, skipped_special, digests_sha256}, the
 * snapshot the record's. Returns the digest list's hash, or null for anything else (never trusted, never recorded).
 */
export function stagedDigest(stdout, snapshot) {
  const v = oneLine(stdout);
  if (v === null || !keysAre(v, ["ok", "snapshot", "skipped_special", "digests_sha256"]) || v.ok !== true || v.snapshot !== snapshot
    || !Number.isSafeInteger(v.skipped_special) || v.skipped_special < 0 || typeof v.digests_sha256 !== "string" || !HEX64.test(v.digests_sha256)) return null;
  return v.digests_sha256;
}

/**
 * fill-home's success line (A2 §4 step 6): exactly {placed: {dirs, files, symlinks}, refused, unexpected, truncated},
 * its paths in §4b's codec. Returns { refused, unexpected, truncated } (checked as a fill report), or null.
 */
export function fillReport(stdout) {
  const v = oneLine(stdout);
  const n = (x) => Number.isSafeInteger(x) && x >= 0;
  if (v === null || !keysAre(v, ["placed", "refused", "unexpected", "truncated"]) || v.placed === null || typeof v.placed !== "object"
    || !keysAre(v.placed, ["dirs", "files", "symlinks"]) || !n(v.placed.dirs) || !n(v.placed.files) || !n(v.placed.symlinks)) return null;
  const x = { refused: v.refused, unexpected: v.unexpected, truncated: v.truncated };
  try { checkFillReport({ v: 1, run: "aaaaaaaaaaaaaaaa", attempt: 1, cls: "home", ...x }); } catch { return null; }
  return x;
}

/**
 * A class's staged digest list, data/digests.json beside data/<leaf>: its bytes, or null when there is none. Read by
 * readRegular (lstat, a no-follow non-blocking open, fstat of the same object): one regular file of at most MAX_LISTING
 * bytes. Anything else there (a link, a directory, FIFO, socket or device, a swapped object, an oversized file) refuses
 * bad_form: permanent, never a list. An I/O error throws as it is (an interruption).
 */
export function readDigestList(r, cls, root) {
  return readRegular(join(stagingDir(r, cls, root), "data", "digests.json"), MAX_LISTING, "the digest list");
}

/**
 * The driver for one restore. Options:
 * - `launch(args, { ms, signal })`: the launcher by argv, resolving to { code, stdout, stderr };
 * - `mount`: the quota mount (restore-stage's and fill-home's --mount);
 * - `identifyDest(kind, id, cls)`: the provisioned destination's identity in this epoch, { epoch, fsid, object };
 * - `expectOf(kind, id, cls, identity)`: fill-home's expect file for it ({ epoch, fsid, dest, uids, gid, projid },
 *   written root-only and durably), resolving to its path;
 * - `projidOf(kind, id)`: the class's project id from the restored registry (an agent's uid; a tag's gid);
 * - `cleanDest(record)`: empty the record's destinations under their recorded identities;
 * - `discardStaging(record)`: remove every staging of the set (any run, any attempt) but, while the record is
 *   staging or published, its current attempt (validation reads its digest lists): a validated or stopped record
 *   keeps none (its attempt is consumed or abandoned);
 * - `stopped(record)`: resolves true only when every agent of the set is stopped and restore-fenced, its slice proven
 *   empty (validation reads the destination and runs SQLite on copies of it); otherwise nothing is validated;
 * - `unrestorableOf(kind, id, cls)`: the manifest's unrestorable paths of the class (A2 §4b's codec);
 * - `removeCopies(record)`: remove-tree of the set's SQLite copy directory, <copies>/<run>/<owner> (none is fine);
 * - `copies`: the copy anchor (VALIDATE_DIR); `sqlite`: node:sqlite's stand-in (tests); `validateSeconds`: the
 *   tree-digest scope's deadline;
 * - `dir`, `root`: the records' directory and the staging root (tests).
 * `launch` gets tree-digest's scope as opts.scope, { unit, memoryMax, runtimeMaxSec }: the real launcher adapter runs
 * it in that transient scope. Returns fillSet(kind, id, plan, { ms, signal }) → the record it settled on: validated,
 * not_fitting or failed, its staging discarded.
 */
export function restoreFiller({
  launch, mount, identifyDest, expectOf, projidOf, cleanDest, discardStaging, stopped, unrestorableOf, removeCopies,
  copies = VALIDATE_DIR, sqlite, validateSeconds = VALIDATE_SECONDS, dir = RESTORE_DIR, root,
} = {}) {
  for (const [k, f] of Object.entries({ launch, identifyDest, expectOf, projidOf, cleanDest, discardStaging, stopped, unrestorableOf, removeCopies })) {
    if (typeof f !== "function") refuse("bad_form", `restore fill: ${k} is required`);
  }
  if (typeof mount !== "string" || !mount.startsWith("/")) refuse("bad_form", "restore fill: the mount is required");
  const save = (r) => { writeRecord(r, { dir }); return r; };
  const names = (r, cls) => ["--mount", mount, "--owner", ownerOf(r.kind, r.id), "--class", cls, "--run", r.run, "--attempt", String(r.attempt)];

  /** Move to the next attempt, or stop as failed once the run has none left. */
  const retry = (r) => (r.attempt >= MAX_ATTEMPTS ? save(step(r, "failed", { reason: "outcome_unknown" })) : save(step(r, "retry")));
  /**
   * A launcher outcome that isn't "ok", as the record's next step. A stop (not_fitting, failed) is written; the loop
   * then settles it before reporting it: a dirty one's destinations are emptied, and every stopped set's staging is
   * discarded (fillSet's last step), so nothing stays charged to the set's project once it is reported stopped.
   */
  const stop = (r, outcome) => {
    if (outcome === "retry") return retry(r);
    return save(outcome === "not_fitting" ? step(r, "not_fitting") : step(r, "failed", { reason: "outcome_unknown" }));
  };

  const ops = {
    async stage(r, opts) {
      await discardStaging(r);
      for (const cls of CLASSES[r.kind]) {
        const { path } = classPaths(r.kind, r.id, cls);
        const out = await launch(["restore-stage", ...names(r, cls), "--projid", String(projidOf(r.kind, r.id)), "--snapshot", r.snapshot, "--path", path], opts);
        const o = outcomeOf(out.code);
        if (o !== "ok") return stop(r, o);
        // An exit 0 whose line isn't the closed success shape: the list's hash is unknown, so the attempt is unusable.
        const sha256 = stagedDigest(out.stdout, r.snapshot);
        if (sha256 === null) return stop(r, "retry");
        r = save(step(r, "digest", { cls, sha256 }));
      }
      // Every class staged. The markers aren't trusted here: the next recoveryStep fills only when every class's
      // marker is exactly its name, and retries otherwise.
      return save(step(r, "staged"));
    },
    async fill(r, opts) {
      const ids = {};
      for (const cls of CLASSES[r.kind]) ids[cls] = await identifyDest(r.kind, r.id, cls);
      const dest = Object.fromEntries(CLASSES[r.kind].map((c) => [c, destOf(ids[c].object)]));
      // filling is written BEFORE the first fill-home: from here on this attempt is never filled again.
      r = save(step(r, "filling", { dest }));
      for (const cls of CLASSES[r.kind]) {
        const expect = await expectOf(r.kind, r.id, cls, ids[cls]);
        const { source } = classPaths(r.kind, r.id, cls);
        const out = await launch(["fill-home", ...names(r, cls), "--source", source, "--expect", expect], opts);
        const o = outcomeOf(out.code);
        if (o !== "ok") return stop(r, o);
        // Placed and durable, but without its report validation couldn't subtract what fill refused: a new attempt.
        const report = fillReport(out.stdout);
        if (report === null) return stop(r, "retry");
        writeFillReport(r, cls, report, { dir });
      }
      return save(step(r, "published"));
    },
    async validate(r, opts) {
      if ((await stopped(r)) !== true) refuse("not_granted", "restore fill: the set isn't stopped and fenced; nothing is validated");
      const fail = (reason) => save(step(r, "failed", { reason }));
      // A list or report that can't be one (a link, another type, malformed: bad_form) is PERMANENT: the set fails,
      // durably, and is never validated or staged again. Anything else thrown (an I/O error, a crash) leaves it
      // published, and the next call validates again from the start.
      const permanent = (f) => {
        try { return { v: f() }; } catch (e) { if (e instanceof FleetError && e.code === "bad_form") return null; throw e; }
      };
      // Every class's list and report first, so a permanent fault in any class stops the set before anything is listed.
      const inputs = {};
      for (const cls of CLASSES[r.kind]) {
        const got = permanent(() => [readDigestList(r, cls, root), readFillReport(r, cls, { dir })]);
        if (got === null) return fail("bad_form");
        // (none there, or only another attempt's: equally permanent, the attempt's own was never kept)
        if (got.v[0] === null || got.v[1] === null) return fail("not_found");
        inputs[cls] = got.v;
      }
      for (const cls of CLASSES[r.kind]) {
        const [list, report] = inputs[cls];
        const id = await identifyDest(r.kind, r.id, cls);
        const d = destOf(id.object);
        if (d.dev !== r.dest[cls].dev || d.ino !== r.dest[cls].ino) return fail("outcome_unknown");
        const expect = await expectOf(r.kind, r.id, cls, id);
        const sessions = cls === "sessions";
        const args = ["tree-digest", "--mount", mount, "--owner", ownerOf(r.kind, r.id), "--class", cls, "--expect", expect,
          ...(sessions ? ["--copy-sqlite", "--run", r.run] : [])];
        const scope = { unit: `sagebrush-validate-${ownerOf(r.kind, r.id)}.scope`, memoryMax: VALIDATE_MEMORY_MAX, runtimeMaxSec: validateSeconds };
        let out;
        for (let t = 1; ; t++) {
          // A sessions listing copies into a fresh directory: any earlier one (a crash, a 74) is removed first.
          if (sessions) await removeCopies(r);
          out = await launch(args, { ...opts, scope });
          if (out.code === EXIT.ok || ![EXIT.partial, EXIT.exists].includes(out.code) || t >= DIGEST_TRIES) break;
        }
        if (out.code !== EXIT.ok) {
          if (sessions) await removeCopies(r);
          return fail(out.code === 64 ? "bad_form" : "outcome_unknown");
        }
        const v = checkClass({ list, sha256: r.digests[cls], report, observed: out.stdout, unrestorable: unrestorableOf(r.kind, r.id, cls) });
        let ok = v.ok;
        if (ok && sessions) {
          try { ok = (await checkCopies(v.observed, join(copies, r.run, ownerOf(r.kind, r.id)), { sqlite })).ok; } catch { ok = false; }
        }
        if (sessions) await removeCopies(r);
        if (!ok) return fail(v.ok ? "bad_form" : v.reason);
      }
      return save(step(r, "validated"));
    },
    async clean(r) {
      // The destinations only: the stale staging goes with the next stage, or with the stop's settling.
      await cleanDest(r);
      return save(step(r, "clean"));
    },
  };

  /** Settle one set: start it or resume it from its record, until it is validated or stopped. */
  return async function fillSet(kind, id, plan, opts = {}) {
    checkPlan(plan);
    const key = `${kind}-${id}`;
    if (!Object.hasOwn(plan.sets, key)) refuse("not_found", "restore fill: not a set of this restore");
    const want = plan.sets[key];
    for (let i = 0; i < MAX_STEPS; i++) {
      if (opts.signal?.aborted) refuse("outcome_unknown", "restore fill: aborted");
      let r = readRecord(kind, id, { dir });
      if (r !== null && (r.run !== want.run || r.snapshot !== want.snapshot)) refuse("not_granted", "restore fill: the record is another restore's");
      const disk = r === null ? { markers: {}, begun: false } : {
        markers: Object.fromEntries(CLASSES[kind].map((c) => [c, readMarker(r, c, { root })])),
        begun: CLASSES[kind].some((c) => existsSync(stagingDir(r, c, root))),
      };
      switch (recoveryStep(r, disk)) {
        case "start": r = save(newRecord({ kind, id, run: want.run, snapshot: want.snapshot })); await ops.stage(r, opts); break;
        case "stage": await ops.stage(r, opts); break;
        case "promote": save(step(r, "staged")); break;
        case "fill": await ops.fill(r, opts); break;
        case "clean": await ops.clean(r); break;
        case "retry": retry(r); break;
        // Published: its attempt is kept (the digest lists are read from it) until validated is durable. A crash
        // during validation validates again, against the same recorded hashes and the same attempt.
        case "validate": await ops.validate(r, opts); break;
        default:
          // Settled: validated, or a clean stop (only the person restarts it). Its staging is discarded here, before
          // it is reported, every time: a validated set's consumed attempt still holds its digest lists and the staged
          // copies of its directories and symlinks (fill-home makes them anew), a stopped set's whatever it staged.
          // Idempotent, so a crash before or during it is repaired by the next call; nothing is staged or filled.
          await discardStaging(r);
          return r;
      }
    }
    refuse("outcome_unknown", "restore fill: the set doesn't settle");
  };
}
