// Host restore e2e r1.7, delta R4-d2b §2: an agent's two imports (its config tree and its harness context), as the
// executor's `restore-import` step. The worker's fill stops an agent's set at files_validated; this step takes it to
// validated, in the supervisor (the worker can't open the host store, and both imports need it).
//
// - **Under the set's restore hold** (holdSets of the agent's own set) for the whole step: a worker started meanwhile
//   finds its lock held and exits busy. A held set is skipped (busy), touching nothing.
// - **Before each effect, under the hold** (`still`): the restore open (begun, its plan not closed), no abandon
//   intent for the set (one ends the step, writing nothing more), and the record still files_validated at exactly the
//   plan's run and snapshot (one that moved refuses).
// - **Each import is an intent:** its `expected` is computed from its source; `pending` with expected's hash is written
//   durably BEFORE the first write; the writes are idempotent; `done`, with the SAME hash, only after a typed read-back
//   equal to `expected`. A pending import at the step's start re-runs against the same expected, whose hash must be
//   the record's, or the set fails.
// - **Config (D1):** expected is the staged config attempt's tree (its marker exactly its name, read by
//   agent-config.mjs's rules; a staged tree with generations but no `current` refuses); its configuration hash must be
//   the manifest's config[id] (the plan's). The live tree, reached from the provisioning's recorded identity, must hold
//   a PREFIX of expected (its first generations, equal; `current` only once all are there); each missing generation is
//   imported in ascending order, `current` last; the read-back must be expected exactly, with no leftover, and its
//   configuration hash the manifest's. An unconfigured agent's empty tree imports as nothing: EMPTY_CONFIG_HASH.
// - **Context (D2), until the host lane's typed reader exists:** the host store copy's harness-sessions and
//   harness-turns are only LISTED, never read as a format: no entry of this agent (the directories absent, empty, or
//   holding only other agents' entries) is the import of nothing, pending then done with the empty set's hash; any
//   entry of this agent leaves the set files_validated with no import state changed, reported importer_missing:
//   context. That is checked first, so such a set writes nothing at all.
// - **Then validated**, and the set's staging (its config attempt) is discarded once validated is durable.

import { createHash } from "node:crypto";
import * as fs from "node:fs";
import { join } from "node:path";
import { FleetError, isId, refuse } from "../bytes.mjs";
import { RESTORE_DIR, RESTORE_STAGING } from "./names.mjs";
import { readMarker, readRecord, stagingDir, stagingName, step, writeRecord } from "./restore-record.mjs";
import { readPlan } from "./restore-plan.mjs";
import { HOSTSTORE_COPY, parseKey, provenDir, readBegin } from "./restore-begin.mjs";
import { readIntent } from "./restore-worker.mjs";
import { classPaths } from "./restore-fill.mjs";
import { configHash, importGeneration, readConfigTree, setCurrent } from "./agent-config.mjs";

/** The host store copy's harness directories (backup-hoststore.mjs's HOSTSTORE_INCLUDE), the host lane's format. */
export const HARNESS = Object.freeze(["harness-sessions", "harness-turns"]);
/** What a set with harness records of its agent waits for. */
export const IMPORTER_MISSING = "importer_missing: context";

const sha256 = (s) => createHash("sha256").update(s).digest("hex");
/** An import's expected result's hash: sha256 of its canonical JSON plus a newline. */
export const expectedHash = (x) => sha256(JSON.stringify(x) + "\n");

/** A config tree's canonical expected form: its current and each generation's hash, in ascending generation order. */
export function configExpected(tree) {
  const ns = Object.keys(tree.generations).sort((a, b) => Number(a) - Number(b));
  return { v: 1, current: tree.current, generations: ns.map((n) => [n, tree.generations[n].hash]) };
}
/** The context import's expected form with no record: the empty set. */
export const EMPTY_CONTEXT = Object.freeze({ v: 1, records: [] });

/** A step's stop: the set fails (its reason), or the step ends with nothing more written (abandoning). */
class Stop extends Error {
  constructor(kind, reason) { super(kind); this.kind = kind; this.reason = reason; }
}
const failSet = (reason) => { throw new Stop("failed", reason); };

/**
 * Run an agent-config read or write: its refusals of what is on disk (a foreign entry, other content, a missing
 * object) fail the set; anything else (an I/O error, a read-back that didn't settle) is retried by the next step.
 */
function onDisk(fn) {
  try { return fn(); } catch (e) {
    if (e instanceof FleetError && (e.code === "not_granted" || e.code === "bad_form")) throw new Stop("failed", "outcome_unknown");
    if (e instanceof FleetError && e.code === "not_found") throw new Stop("failed", "not_found");
    throw e;
  }
}

/**
 * Does the host store copy hold any harness record of `agent`? Lists the copy's harness directories only (each proven
 * a private directory beneath the copy, never followed): an entry whose name begins with the agent's id is its
 * record. Absent directories hold none.
 */
export function harnessRecordsOf(agent, { dir = RESTORE_DIR, uid = 0, run, fsx = fs }) {
  if (!isId(agent)) refuse("bad_form", "restore import: bad agent");
  const copy = provenDir(dir, `${HOSTSTORE_COPY}/${run}`, { uid, fsx });
  for (const h of HARNESS) {
    let d;
    try { d = provenDir(copy, h, { uid, fsx }); } catch (e) { if (e?.code === "ENOENT") continue; throw e; }
    if (fsx.readdirSync(d).some((n) => n.startsWith(agent))) return true;
  }
  return false;
}

/**
 * One agent set's imports, under its hold (§2). `deps`:
 * - hold(): holdSets of the agent's own set → { release } or null (held: busy);
 * - liveConfig(): { root, identity } of the agent's live config tree (the provisioning's record), or null;
 * - hasContext(): harnessRecordsOf's answer;
 * - discard(record): the set's staging removal (restore-adapters.mjs stagingRemover's discardStaging).
 * Options: `dir`, `uid`, `staging` (the staging anchor), `io`, `signal` (aborted: nothing more is done).
 * Resolves to { status: "busy" | "abandoning" | "files_validated" (with `reason`) | "validated" | "failed" (with
 * `reason`) }; a record that moved, or a closed restore, refuses not_granted.
 */
export async function importAgentSet(id, deps, { dir = RESTORE_DIR, uid = 0, staging = RESTORE_STAGING, io, signal } = {}) {
  if (!isId(id)) refuse("bad_form", "restore import: bad agent");
  const key = `agent-${id}`;
  const held = await deps.hold();
  if (held === null) return { status: "busy" };
  const ioOpt = io ? { io } : {};
  try {
    /** Before each effect: open, no intent, the record exactly files_validated at the plan's run and snapshot. */
    const still = async () => {
      await null; // (an effect boundary: the op's deadline and a close can cut in here)
      if (signal?.aborted) refuse("outcome_unknown", "restore import: cut short; nothing more is done");
      const b = readBegin({ dir }), p = readPlan({ dir });
      if (b === null || b.state !== "done" || p === null || Object.hasOwn(p, "closed")) refuse("not_granted", "restore import: the restore isn't open");
      if (!Object.hasOwn(p.sets, key)) refuse("not_found", "restore import: not a set of this restore");
      if (readIntent("agent", id, { dir, uid }) !== null) throw new Stop("abandoning");
      const r = readRecord("agent", id, { dir });
      if (r === null || r.state !== "files_validated" || r.run !== p.sets[key].run || r.snapshot !== p.sets[key].snapshot) {
        refuse("not_granted", "restore import: the set's record moved");
      }
      return { r, p, b };
    };
    const write = async (to, opts) => { const { r } = await still(); const n = step(r, to, opts); writeRecord(n, { dir, ...ioOpt }); return n; };
    let r, p, b;
    try {
      ({ r, p, b } = await still());
      // The context first, read only: records of this agent wait for their importer, and nothing is written.
      const ctx = r.imports.context;
      if (ctx.state !== "done" && (await deps.hasContext({ run: b.run })) === true) {
        if (ctx.state === "none") return { status: "files_validated", reason: IMPORTER_MISSING };
        failSet("outcome_unknown"); // (a pending import of nothing now finds records: not its expected)
      }
      // The config (D1). Only agent-config's own refusals (and the staging's proofs) become the set's failure.
      if (r.imports.config.state !== "done") {
        if (readMarker(r, "config", { root: staging }) !== stagingName(r, "config")) failSet("outcome_unknown");
        const src = join(stagingDir(r, "config", staging), classPaths("agent", id, "config").source);
        const staged = onDisk(() => { provenDir(staging, `${stagingName(r, "config")}/data`, { uid }); return readConfigTree(src, { uid }); });
        const want = configExpected(staged), h = expectedHash(want);
        if (configHash(staged) !== p.config[id]) failSet("bad_form"); // not the configuration the manifest binds
        const c = r.imports.config;
        if (c.state === "pending" && c.sha256 !== h) failSet("outcome_unknown");
        if (c.state === "none") r = await write("import", { which: "config", phase: "pending", sha256: h });
        const live = await deps.liveConfig();
        if (live === null) failSet("not_found");
        const opts = { uid, identity: live.identity, ...ioOpt };
        const tree = onDisk(() => readConfigTree(live.root, { ...opts, importing: true }));
        const have = configExpected(tree).generations;
        // A prefix of expected: its first generations, each equal; current only once every one is there.
        if (have.length > want.generations.length || !have.every(([n, x], i) => want.generations[i][0] === n && want.generations[i][1] === x)) failSet("outcome_unknown");
        if (tree.current !== null && (tree.current !== want.current || have.length !== want.generations.length)) failSet("outcome_unknown");
        for (const [n] of want.generations.slice(have.length)) {
          await still();
          onDisk(() => importGeneration(live.root, n, join(src, `gen-${n}`), opts));
        }
        if (want.current !== null && tree.current === null) {
          await still();
          onDisk(() => setCurrent(live.root, want.current, opts));
        }
        const back = onDisk(() => readConfigTree(live.root, opts)); // the invariant holds again: no reader exception
        if (expectedHash(configExpected(back)) !== h || back.leftovers.gen !== null || back.leftovers.current) failSet("outcome_unknown");
        if (configHash(back) !== p.config[id]) failSet("outcome_unknown");
        r = await write("import", { which: "config", phase: "done", sha256: h });
      }
      // The context (D2): the import of nothing, read back as nothing.
      if (r.imports.context.state !== "done") {
        const h = expectedHash(EMPTY_CONTEXT);
        if (r.imports.context.state === "pending" && r.imports.context.sha256 !== h) failSet("outcome_unknown");
        if (r.imports.context.state === "none") r = await write("import", { which: "context", phase: "pending", sha256: h });
        if ((await deps.hasContext({ run: b.run })) !== false) failSet("outcome_unknown");
        r = await write("import", { which: "context", phase: "done", sha256: h });
      }
      r = await write("validated");
    } catch (e) {
      if (!(e instanceof Stop)) throw e;
      if (e.kind === "abandoning") return { status: "abandoning" };
      // The set fails, durably: written only if the record is still exactly this set's (an intent writes nothing).
      try { await write("failed", { reason: e.reason }); } catch (x) { if (x instanceof Stop && x.kind === "abandoning") return { status: "abandoning" }; throw x; }
      return { status: "failed", reason: e.reason };
    }
    // Validated is durable: the set's staging (its config attempt) is no longer needed.
    try { await deps.discard(r); } catch { /* the next step's discard of a validated set tries again */ }
    return { status: "validated" };
  } finally {
    await held.release();
  }
}

/**
 * The executor's `restore-import` op: every agent set of the open restore whose record is files_validated, in key
 * order, each under its own hold (importAgentSet); and, for a validated agent set, its leftover staging discarded.
 * `depsOf(id)` → importAgentSet's deps. Resolves to { sets: { key: result } } for the sets it looked at (an idle step
 * looks at none).
 */
export async function importOnce(depsOf, { dir = RESTORE_DIR, uid = 0, staging = RESTORE_STAGING, io, signal } = {}) {
  let b, p;
  try { b = readBegin({ dir }); p = readPlan({ dir }); } catch { return { sets: {}, why: "unreadable" }; }
  if (b === null || p === null || b.state !== "done" || Object.hasOwn(p, "closed")) return { sets: {} };
  const out = {};
  for (const k of Object.keys(p.sets).sort()) {
    const { kind, id } = parseKey(k);
    if (kind !== "agent") continue;
    if (signal?.aborted) break;
    const r = readRecord(kind, id, { dir });
    if (r === null || r.run !== p.sets[k].run || r.snapshot !== p.sets[k].snapshot) continue;
    if (readIntent(kind, id, { dir, uid }) !== null) continue;
    const deps = depsOf(id);
    if (r.state === "validated") {
      // (a discard after validated that failed, or a crash before it: tried again, under the hold)
      const held = await deps.hold();
      if (held === null) continue;
      try { await deps.discard(r); } catch { /* again next time */ } finally { await held.release(); }
      continue;
    }
    if (r.state !== "files_validated") continue;
    try { out[k] = await importAgentSet(id, deps, { dir, uid, staging, io, signal }); } catch (e) {
      out[k] = { status: "refused", reason: e?.code ?? "host-side failure" };
    }
  }
  return { sets: out };
}
