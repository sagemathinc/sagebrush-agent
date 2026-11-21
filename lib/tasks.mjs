// Delegate tasks on this computer: where each one lives, its history, its log and its state (the protocol:
// design/workspace-agent-protocol.md §6, `delegate.1`; the design: pair-delegate plan r3.4 §2.1, §2.8, §2.9).
//
//   <root>/                       private (0700, ours, a real folder: checked at every start and load)
//     <task>/                     private; <task> = 32 lowercase hex
//       task.json                 control state, host-only: status, frozen grant, rounds, the merge ledger, an intent
//       log.jsonl                 the task's events, one per line {seq, at, event}; seq only grows, across restarts
//       git/                      a bare repository (task-git.mjs): refs/heads/base, proposal, mine-<n>, merged;
//                                 refs/tags/round-<n>
//       work/                     the agent's copy: the only folder its tools and its runner may change
//       reserve                   1 MiB kept free for recording a "disk full" interruption
//
// Nothing here writes the person's workspace: Merge is the page's, and tasks.merged only records what it reports.
// The working copy is touched only through task-paths.mjs (no link followed, plain files only).  Every operation on a
// task runs alone (one queue a task); an operation that moves a ref writes an intent first, so a crash at any point is
// either finished or undone at the next start (recover), never half-applied; a ref that is neither what the intent
// expected nor what it meant to write is a conflict, and the task is failed, kept for inspection.

import { randomBytes, createHash } from "node:crypto";
import { closeSync, constants, existsSync, fsyncSync, lstatSync, mkdirSync, openSync, readdirSync, realpathSync, renameSync, rmdirSync, rmSync, unlinkSync, ftruncateSync, fstatSync } from "node:fs";
import { dirname, join } from "node:path";
import { homedir } from "node:os";
import * as git from "./task-git.mjs";
import { pathProblem, pathSetProblem, privateDirProblem, readTaskFile, scanTree, writeTaskFile, UnsafePath } from "./task-paths.mjs";
import { LIMITS, STATUSES, TaskError } from "./tasks-schema.mjs";

const MiB = 1024 * 1024;
/** One task's budget and the store's (plan r3.4 §2.9.1). */
export const BUDGET = Object.freeze({
  task: 512 * MiB, // everything a task keeps: work, git, log (and, with A2/A3, its transcript and run tmp)
  work: 256 * MiB,
  files: 2000,
  log: 16 * MiB,
  event: 256 * 1024,
  tasks: 64,
  total: 4096 * MiB,
  reserve: 1 * MiB,
});
const FINAL = new Set(["merged", "closed", "failed"]);
const HEX32 = /^[0-9a-f]{32}$/;
const enc = new TextEncoder();

export const defaultRoot = () => join(homedir(), ".sagebrush", "tasks");

// ---- small durable-file helpers
const NOFOLLOW = constants.O_NOFOLLOW ?? 0;
// (a control file written whole: a fresh temporary file beside it (exclusive, never through a link), every byte written,
//  fsynced, renamed over the old one, the folder fsynced; any failure is thrown, so nothing is acknowledged)
function writeJson(path, v) {
  const tmp = `${path}.${process.pid}.${randomBytes(4).toString("hex")}.tmp`;
  const fd = openSync(tmp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | NOFOLLOW, 0o600);
  try { git.writeAll(fd, canonical(v)); fsyncSync(fd); } finally { closeSync(fd); }
  renameSync(tmp, path);
  git.syncDir(path.slice(0, path.lastIndexOf("/")));
}
/** A persisted record's text parsed, only if it is exactly the canonical form this store writes (keys sorted, no
 * whitespace, no repeated key): anything else (a duplicate key, reordering, spacing) is not one of ours. */
function parseCanonical(text) {
  const v = JSON.parse(text);
  if (canonical(v) !== text) throw new SyntaxError("not in its canonical form");
  return v;
}
/** Why `p` isn't a plain directory (a real one, not a link), or null. */
const plainDirProblem = (p) => { try { const st = lstatSync(p); return st.isDirectory() && !st.isSymbolicLink() ? null : "not a plain folder"; } catch (e) { return String(e?.code ?? e); } };
/** The bytes of everything under `dir` (no link followed), or null when they can't be measured safely: the folder
 * itself not a plain one, an error during the walk, or more than `max` entries. */
function dirBytes(dir, max = 200000) {
  let n = 0, seen = 0;
  const walk = (d) => {
    for (const name of readdirSync(d)) {
      if (++seen > max) throw new Error("too many entries");
      const p = join(d, name), st = lstatSync(p);
      if (st.isDirectory() && !st.isSymbolicLink()) walk(p);
      else n += st.size;
    }
  };
  try { const st = lstatSync(dir); if (!st.isDirectory() || st.isSymbolicLink()) return null; walk(dir); } catch { return null; }
  return n;
}
/** The bytes of the plain files under `dir`, walked by lstat; null when anything there is a link or a special file, or
 * there are more than `max` entries: such a tree is never measured through. */
function plainTreeBytes(dir, max = 200000) {
  let n = 0, seen = 0;
  const walk = (d) => {
    for (const name of readdirSync(d)) {
      if (++seen > max) throw new Error("too many entries");
      const p = join(d, name), st = lstatSync(p);
      if (st.isDirectory()) walk(p);
      else if (st.isFile()) n += st.size;
      else throw new Error("a link or special file");
    }
  };
  try { walk(dir); } catch { return null; }
  return n;
}
/** Remove the plain files and folders under `dir`, and `dir` itself once empty, walking by lstat: a link or special
 * file is left where it is (with the folders holding it), never followed or removed. */
function removePlainTree(dir) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name), st = lstatSync(p);
    if (st.isDirectory()) removePlainTree(p);
    else if (st.isFile()) unlinkSync(p);
  }
  try { rmdirSync(dir); } catch {}
}
const sha256 = (s) => createHash("sha256").update(s).digest("hex");
/** A value's canonical JSON (keys sorted), for the merge ledger's exact-request binding. */
export function canonical(v) {
  if (Array.isArray(v)) return "[" + v.map(canonical).join(",") + "]";
  if (v && typeof v === "object" && !(v instanceof Uint8Array)) return "{" + Object.keys(v).filter((k) => v[k] !== undefined).sort().map((k) => JSON.stringify(k) + ":" + canonical(v[k])).join(",") + "}";
  if (v instanceof Uint8Array) return JSON.stringify(Buffer.from(v).toString("base64"));
  return JSON.stringify(v);
}
/** A document's bytes as P0's `content`: text if it is well-formed UTF-8 text with no NUL, else {base64}. */
function asContent(bytes) {
  const b = Buffer.from(bytes), s = b.toString("utf8");
  return !b.includes(0) && Buffer.from(s, "utf8").equals(b) ? s : { base64: b.toString("base64") };
}
/** A reason as the page may receive it: well-formed text with no NUL or other control character, bounded. */
const reasonText = (r) => String(r).replace(/[\u0000-\u0008\u000b-\u001f\u007f]|[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/g, "\ufffd").slice(0, 500);

// ---- task.json: one strict loader (closed keys, types, ranges, well-formed bounded text); nothing in it is trusted
// because it is on disk.  The cross-record checks (refs, history, log, ledger, receipt) are #reconcile's.
const STATE_REQUIRED = ["v", "task", "title", "prompt", "target", "status", "grant", "base", "proposals", "mines", "merged", "seq", "ledger", "intent", "created", "updated", "bytes"];
const STATE_OPTIONAL = ["reason", "receipt"];
const NOT_WELL = /\u0000|[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/;
const OIDS = /^[0-9a-f]{40}$/;
const isPlainObj = (v) => !!v && typeof v === "object" && !Array.isArray(v) && Object.getPrototypeOf(v) === Object.prototype;
const exactKeys = (o, req, opt = []) => isPlainObj(o) && req.every((k) => Object.hasOwn(o, k)) && Object.keys(o).every((k) => req.includes(k) || opt.includes(k));
const wellText = (v, maxBytes, nonEmpty = false) => typeof v === "string" && !NOT_WELL.test(v) && Buffer.byteLength(v) <= maxBytes && (!nonEmpty || v.trim() !== "");
const safeInt = (v, min = 0) => Number.isSafeInteger(v) && v >= min;
const oidList = (v) => Array.isArray(v) && v.length <= 10000 && v.every((c) => typeof c === "string" && OIDS.test(c));
function receiptProblem(r) {
  if (!exactKeys(r, ["proposal", "merge_id", "files"]) || !OIDS.test(r.proposal) || !HEX32.test(r.merge_id) || !Array.isArray(r.files) || r.files.length > 2000) return "its receipt";
  const side = (v) => v === "absent" || v === "not sent" || (typeof v === "string" && OIDS.test(v));
  if (!r.files.every((f) => exactKeys(f, ["path", "proposal_blob", "mine", "merged"]) && typeof f.path === "string" && !pathProblemQuick(f.path) && (f.proposal_blob === null || OIDS.test(f.proposal_blob)) && side(f.mine) && side(f.merged))) return "its receipt's files";
  return null;
}
const pathProblemQuick = (p) => pathProblem(p);
function ledgerProblem(l) {
  if (!isPlainObj(l) || Object.keys(l).length > 1) return "its ledger";
  for (const [k, v] of Object.entries(l)) {
    if (!HEX32.test(k) || !exactKeys(v, ["hash", "answer"]) || !/^[0-9a-f]{64}$/.test(v.hash)) return "its ledger";
    const a = v.answer;
    if (!(exactKeys(a, ["recorded", "commit"]) && ((a.recorded === "merge" && typeof a.commit === "string" && OIDS.test(a.commit)) || (a.recorded === "receipt" && a.commit === null)))) return "its ledger's answer";
  }
  return null;
}
/** Why `t` isn't a well-formed task.json for task `id` of installation `scope`, or null. */
function stateProblem(t, id, scope) {
  if (!exactKeys(t, STATE_REQUIRED, STATE_OPTIONAL)) return "its fields";
  if (t.v !== 1 || t.task !== id || t.target !== "local") return "its header";
  if (!wellText(t.title, 800, true) || [...t.title].length > LIMITS.title) return "its title";
  if (!wellText(t.prompt, LIMITS.prompt)) return "its prompt";
  if (!STATUSES.includes(t.status)) return "its status";
  if (Object.hasOwn(t, "reason") && !wellText(t.reason, 2000, true)) return "its reason";
  const g = t.grant;
  if (!exactKeys(g, ["docs", "run", "scope", "created", "revoked"]) || !Array.isArray(g.docs) || g.docs.length > 2000 || !g.docs.every((d) => typeof d === "string" && !pathProblem(d)) || typeof g.run !== "boolean" || typeof g.revoked !== "boolean" || !safeInt(g.created)) return "its grant";
  if (g.scope !== scope) return "its installation (another installation's task)";
  if (typeof t.base !== "string" || !OIDS.test(t.base) || !oidList(t.proposals) || !oidList(t.mines) || !(t.merged === null || (typeof t.merged === "string" && OIDS.test(t.merged)))) return "its commits";
  if (!safeInt(t.seq) || !safeInt(t.created) || !safeInt(t.updated) || !safeInt(t.bytes)) return "its numbers";
  const lp = ledgerProblem(t.ledger);
  if (lp) return lp;
  if (Object.hasOwn(t, "receipt")) { const rp = receiptProblem(t.receipt); if (rp) return rp; }
  if (!(t.intent === null || isPlainObj(t.intent))) return "its intent";
  return null;
}

// ---- the log: each complete line one closed record, seqs 1, 2, 3... with no gap or repeat, each event one of the
// protocol's (§6.1: the task's status and proposal, and the chat turn events a task's turn records)
const STATUS_EVENT = ["type", "status"];
const EVENT_SHAPES = {
  task_status: (e) => exactKeys(e, STATUS_EVENT, ["reason"]) && STATUSES.includes(e.status) && (e.reason === undefined || wellText(e.reason, 2000, true)),
  proposal: (e) => exactKeys(e, ["type", "round", "base", "commit", "files"]) && safeInt(e.round, 1) && OIDS.test(e.base ?? "") && OIDS.test(e.commit ?? "") && Array.isArray(e.files) && e.files.every((f) => exactKeys(f, ["path", "kind", "change", "base_blob", "blob"]) && typeof f.path === "string" && !pathProblem(f.path) && (f.kind === "notebook" || f.kind === "file") && ["added", "modified", "deleted"].includes(f.change) && (f.base_blob === null || OIDS.test(f.base_blob)) && (f.blob === null || OIDS.test(f.blob))),
  turn_started: (e) => exactKeys(e, ["type"]),
  message_revised: (e) => exactKeys(e, ["type", "message", "revision"]) && wellText(e.message, 200) && safeInt(e.revision, 1),
  text_delta: (e) => exactKeys(e, ["type", "message", "revision", "text"]) && wellText(e.message, 200) && safeInt(e.revision, 1) && wellText(e.text, 256 * 1024),
  thinking_delta: (e) => exactKeys(e, ["type", "text"]) && wellText(e.text, 256 * 1024),
  tool_call_started: (e) => exactKeys(e, ["type", "call", "tool", "name"], ["summary"]) && wellText(e.call, 200) && wellText(e.tool, 40) && wellText(e.name, 200) && (e.summary === undefined || wellText(e.summary, 4096)),
  tool_call_finished: (e) => exactKeys(e, ["type", "call", "status", "duration_ms"], ["body", "body_cut"]) && wellText(e.call, 200) && (e.status === "ok" || e.status === "error") && safeInt(e.duration_ms) && (e.body === undefined || wellText(e.body, 256 * 1024)) && (e.body_cut === undefined || e.body_cut === true),
  turn_error: (e) => exactKeys(e, ["type", "code", "message"]) && wellText(e.code, 200) && wellText(e.message, 4096),
  turn_usage: (e) => exactKeys(e, ["type", "usage"]) && exactKeys(e.usage, ["input_tokens", "output_tokens"]) && safeInt(e.usage.input_tokens) && safeInt(e.usage.output_tokens),
  turn_finished: (e) => exactKeys(e, ["type", "outcome"], ["code"]) && ["completed", "interrupted", "error"].includes(e.outcome) && (e.code === undefined || wellText(e.code, 200)),
  artifact: (e) => exactKeys(e, ["type", "id", "kind", "title", "path", "body"], ["lang"]) && wellText(e.id, 1024) && wellText(e.kind, 40) && wellText(e.title, 1024) && wellText(e.path, 1024) && wellText(e.body, 256 * 1024) && (e.lang === undefined || wellText(e.lang, 40)),
};
/** Why `e` isn't one of the protocol's events, or null. */
export function eventProblem(e) {
  return isPlainObj(e) && Object.hasOwn(EVENT_SHAPES, e.type) && EVENT_SHAPES[e.type](e) ? null : `an event that isn't the protocol's (${String(e?.type).slice(0, 40)})`;
}
class LogProblem extends Error {}

// ---- every operation's intent, from one builder per operation: the writer uses it, and recovery rebuilds the intent
// from the task's state (and git) with the same builder and requires it to be exactly what was recorded.  So a
// recorded intent can only ever be one this module would have written for that state; nothing else is applied.
const OID = /^[0-9a-f]{40}$/, HEX32I = /^[0-9a-f]{32}$/, HEX64 = /^[0-9a-f]{64}$/;
const WELL = /\u0000|[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/;
class BadIntent extends Error {}
const need = (ok, what) => { if (!ok) throw new BadIntent(what); };
/** The files a commit changes from the task's base: the proposal event's and tasks.diff's list. */
export function changesBetween(gd, base, commit) {
  const a = git.readTree(gd, git.readCommit(gd, base).tree), b = git.readTree(gd, git.readCommit(gd, commit).tree), files = [];
  for (const p of [...new Set([...a.keys(), ...b.keys()])].sort()) {
    const x = a.get(p) ?? null, y = b.get(p) ?? null;
    if (x !== y) files.push({ path: p, kind: /\.ipynb$/.test(p) ? "notebook" : "file", change: x === null ? "added" : y === null ? "deleted" : "modified", base_blob: x, blob: y });
  }
  return files;
}
const parentsOf = (gd, c) => { need(typeof c === "string" && OID.test(c), "a commit id"); return git.readCommit(gd, c).parents; };
/** The status changes that move no ref: from which statuses, to which, with which reason. */
const STATUS_OPS = {
  stop: { from: ["working"], to: "interrupted", reason: "stopped by the person" },
  recover: { from: ["working"], to: "interrupted", reason: "the agent stopped while the task was working" },
  interrupt: { from: ["working"], to: "interrupted", reason: undefined }, // (the host's own reason: args.reason)
  resume: { from: ["interrupted"], to: "working", reason: null },
  close: { from: ["working", "proposal", "interrupted"], to: "closed", reason: "closed by the person" },
  revoke: { from: ["working", "proposal", "interrupted"], to: "closed", reason: "revoked by the person", revoked: true },
};
const BUILD = {
  status(gd, t, id, args) {
    const o = STATUS_OPS[args?.op];
    need(o && keysOnlyB(args, o.reason === undefined ? ["op", "reason"] : ["op"]), "a status change's arguments");
    need(o.from.includes(t.status), `${t.status} can't be ${args.op}ped`);
    let reason = o.reason;
    if (reason === undefined) { reason = args.reason; need(typeof reason === "string" && reason.length > 0 && reason.length <= 500 && !WELL.test(reason), "a reason"); }
    return { id, op: "status", args: o.reason === undefined ? { op: args.op, reason } : { op: args.op }, events: [{ type: "task_status", status: o.to, ...(reason ? { reason } : {}) }], set: { status: o.to, reason, ...(o.revoked ? { revoked: true } : {}) } };
  },
  propose(gd, t, id, args) {
    need(keysOnlyB(args, ["commit"]) && t.status === "working", "a proposal from a working task");
    const prev = t.proposals.at(-1) ?? null, round = t.proposals.length + 1, commit = args.commit;
    need(sameListB(parentsOf(gd, commit), [prev ?? t.base]), "a proposal's parent is the last round, or the base");
    return { id, op: "propose", args: { commit }, ref: "refs/heads/proposal", expect: prev, next: commit, tags: [{ ref: `refs/tags/round-${round}`, next: commit }], events: [{ type: "proposal", round, base: t.base, commit, files: changesBetween(gd, t.base, commit) }, { type: "task_status", status: "proposal" }], set: { status: "proposal", proposals: [...t.proposals, commit] } };
  },
  merge(gd, t, id, args) {
    need(keysOnlyB(args, ["merge", "mine", "merge_id", "hash"]) && t.status === "proposal" && HEX32I.test(args.merge_id ?? "") && HEX64.test(args.hash ?? ""), "a merge's arguments");
    const proposal = t.proposals.at(-1), n = t.mines.length + 1;
    need(sameListB(parentsOf(gd, args.mine), [t.base]) && sameListB(parentsOf(gd, args.merge), [args.mine, proposal]), "a merge's commits");
    need(!t.ledger[args.merge_id], "a merge id already recorded");
    return { id, op: "merge", args: { merge: args.merge, mine: args.mine, merge_id: args.merge_id, hash: args.hash }, ref: "refs/heads/merged", expect: null, next: args.merge, tags: [{ ref: `refs/heads/mine-${n}`, next: args.mine }], events: [{ type: "task_status", status: "merged" }], set: { status: "merged", merged: args.merge, mines: [...t.mines, args.mine] }, ledger: { merge_id: args.merge_id, hash: args.hash, answer: { recorded: "merge", commit: args.merge } } };
  },
  receipt(gd, t, id, args) {
    need(keysOnlyB(args, ["merge_id", "hash", "files"]) && t.status === "proposal" && HEX32I.test(args.merge_id ?? "") && HEX64.test(args.hash ?? "") && Array.isArray(args.files), "a receipt's arguments");
    need(!t.ledger[args.merge_id], "a merge id already recorded");
    const proposal = t.proposals.at(-1), changes = changesBetween(gd, t.base, proposal);
    const side = (v) => v === "absent" || v === "not sent" || (typeof v === "string" && OID.test(v));
    need(args.files.length === changes.length && args.files.every((f, k) => keysOnlyB(f, ["path", "proposal_blob", "mine", "merged"]) && f.path === changes[k].path && f.proposal_blob === changes[k].blob && side(f.mine) && side(f.merged)), "a receipt's files are the proposal's changed paths");
    need(args.files.some((f) => f.mine === "not sent" || f.merged === "not sent"), "a receipt is for content not sent");
    const files = args.files.map((f) => ({ path: f.path, proposal_blob: f.proposal_blob, mine: f.mine, merged: f.merged }));
    return { id, op: "receipt", args: { merge_id: args.merge_id, hash: args.hash, files }, events: [{ type: "task_status", status: "merged" }], set: { status: "merged", receipt: { proposal, merge_id: args.merge_id, files } }, ledger: { merge_id: args.merge_id, hash: args.hash, answer: { recorded: "receipt", commit: null } } };
  },
  ask(gd, t, id, args) {
    need(keysOnlyB(args, ["mine"]) && t.status === "proposal", "an Ask's arguments");
    need(sameListB(parentsOf(gd, args.mine), [t.base]), "an Ask's commit");
    const n = t.mines.length + 1;
    return { id, op: "ask", args: { mine: args.mine }, ref: `refs/heads/mine-${n}`, expect: null, next: args.mine, events: [{ type: "task_status", status: "working" }], set: { status: "working", mines: [...t.mines, args.mine] } };
  },
};
function keysOnlyB(o, keys) { return !!o && typeof o === "object" && !Array.isArray(o) && Object.keys(o).length === keys.length && keys.every((k) => Object.hasOwn(o, k)); }
const sameListB = (a, b) => Array.isArray(a) && a.length === b.length && a.every((x, k) => x === b[k]);
/** The intent operation `op` writes for task `t` with `args` (the builder's), or a BadIntent. */
export function buildIntent(gd, t, op, id, args) {
  need(Object.hasOwn(BUILD, op) && HEX32I.test(id ?? ""), "not an operation");
  return BUILD[op](gd, t, id, args);
}
/** Why recorded intent `i` isn't exactly what its operation would write for `t` as it stands, or null. */
function intentProblem(gd, t, i) {
  try {
    if (!i || typeof i !== "object" || Array.isArray(i)) return "not an intent";
    const want = buildIntent(gd, t, i.op, i.id, i.args);
    return canonical(want) === canonical(i) ? null : "it isn't what its operation writes";
  } catch (e) {
    return e instanceof BadIntent ? e.message : `it can't be checked (${String(e?.message ?? e).slice(0, 100)})`;
  }
}

/** The grant as recorded in the base commit's message (immutable): what task.json's grant must equal. */
const GRANT_LINE = "Sagebrush-Task-Grant: ";
const grantText = (g) => canonical({ docs: g.docs, run: g.run, scope: g.scope, created: g.created });
/** The grant a base commit's message records: its last line, exactly "Sagebrush-Task-Grant: <canonical JSON>", parsed as
 * the closed record {created, docs, run, scope} and given back canonical; null if the message doesn't end so. */
function grantOf(message) {
  const lines = message.replace(/\n$/, "").split("\n"), last = lines[lines.length - 1];
  if (!last.startsWith(GRANT_LINE)) return null;
  let g;
  try { g = JSON.parse(last.slice(GRANT_LINE.length)); } catch { return null; }
  if (!g || typeof g !== "object" || Array.isArray(g) || Object.keys(g).sort().join(",") !== "created,docs,run,scope") return null;
  if (!Array.isArray(g.docs) || !g.docs.every((d) => typeof d === "string") || typeof g.run !== "boolean" || typeof g.scope !== "string" || !Number.isSafeInteger(g.created)) return null;
  const text = grantText(g);
  return text === last.slice(GRANT_LINE.length) ? text : null;
}

export class TaskStore {
  /** `root`: the tasks folder; `scope`: this installation's id (the grant's scope); `now`: ms clock (tests);
   * `transcripts`: the folder where Claude Code keeps its transcripts (`~/.claude/projects`), so each task's is counted
   * in its budget and deleted at Merge and Close (null: no turns, nothing to count). */
  constructor({ root = defaultRoot(), scope, now = () => Date.now(), budget = BUDGET, transcripts = null } = {}) {
    if (typeof scope !== "string" || !scope) throw new Error("TaskStore needs this installation's scope id");
    this.root = root;
    this.transcripts = transcripts;
    this.scope = scope;
    this.now = now;
    this.budget = budget;
    this.tasks = new Map(); // task -> state (task.json)
    this.queues = new Map(); // task -> the tail of its operations
    this.listeners = new Set();
  }

  /** Make the root (private), check it, and load and recover every task in it.  Throws TaskError("unavailable")
   * where Delegate can't run (Windows; a root that isn't private and ours). */
  init() {
    mkdirSync(this.root, { recursive: true, mode: 0o700 });
    const why = privateDirProblem(this.root);
    if (why) throw new TaskError("unavailable", `the tasks folder can't be used: ${why}`);
    // (its real path: Claude Code names a turn's transcript folder after the real working folder, sdk/)
    this.root = realpathSync(this.root);
    if (this.transcripts && this.#transcriptName("0".repeat(32)).length > 200) throw new TaskError("unavailable", "the tasks folder's path is too long for Claude Code's transcript folders");
    // (starts are built in .staging/ and renamed into place only when whole: what is still there was never
    //  acknowledged, and only that is ever removed)
    const staging = join(this.root, ".staging");
    mkdirSync(staging, { mode: 0o700, recursive: true });
    const sw = privateDirProblem(staging);
    if (sw) throw new TaskError("unavailable", `the tasks folder's staging folder can't be used: ${sw}`);
    for (const name of readdirSync(staging)) if (HEX32.test(name) && !plainDirProblem(join(staging, name))) rmSync(join(staging, name), { recursive: true, force: true });
    for (const name of readdirSync(this.root).sort()) {
      if (!HEX32.test(name)) continue;
      const dir = join(this.root, name);
      // (a task folder that is a link, or open to others: kept as it is, failed, never followed or read)
      const pd = privateDirProblem(dir);
      if (pd) { this.tasks.set(name, this.#broken(name, `its folder can't be used (${pd})`)); continue; }
      // (unreadable or invalid control state never deletes anything: the task is failed in place, its data kept)
      let t;
      try { t = parseCanonical(git.readPlain(join(dir, "task.json"), 64 * MiB).toString("utf8")); } catch (e) {
        this.tasks.set(name, this.#broken(name, `its control state can't be read (${String(e?.code ?? e?.message ?? e).slice(0, 80)})`));
        continue;
      }
      const bad = stateProblem(t, name, this.scope);
      if (bad) { this.tasks.set(name, this.#broken(name, `its control state is invalid (${bad})`)); continue; }
      this.tasks.set(name, t);
      this.#recover(name);
      // (a task merged or closed before a transcript could be deleted: deleted now)
      if (t.status === "merged" || t.status === "closed") this.#dropTranscript(name);
      this.#dropRunLeftovers(name);
    }
    return this;
  }
  onEvent(f) { this.listeners.add(f); return () => this.listeners.delete(f); }

  // ---- paths
  dir(id) { return join(this.root, id); }
  sdk(id) { return join(this.root, id, "sdk"); }
  /** Where the SDK keeps this task's transcript, or null when this store has no transcripts folder. */
  transcriptDir(id) { return this.transcripts ? join(this.transcripts, this.#transcriptName(id)) : null; }
  // (Claude Code's name for a working folder's transcripts: each character but a letter or digit as "-")
  #transcriptName(id) { return this.sdk(id).replace(/[^A-Za-z0-9]/g, "-"); }
  // (each component the host walks to a transcript, checked by lstat: Claude Code's folder and its projects folder,
  //  then the task's own transcript folder; one that is missing is fine (nothing written yet), one that is a link or
  //  not a folder is a problem: nothing is measured or deleted through it)
  #transcriptProblem(id) {
    for (const p of [dirname(this.transcripts), this.transcripts, this.transcriptDir(id)]) {
      let st;
      try { st = lstatSync(p); } catch (e) { if (e?.code === "ENOENT") return "absent"; return String(e?.code ?? e); }
      if (!st.isDirectory()) return "not a plain folder";
    }
    return null;
  }
  /** The bytes of this task's transcript: 0 when there is none yet, null when it can't be measured safely (a link on
   * the way to it or inside it, a special file, or more than `max` entries). */
  transcriptBytes(id, max) {
    if (!this.transcripts) return 0;
    const why = this.#transcriptProblem(id);
    if (why === "absent") return 0;
    if (why) return null;
    return plainTreeBytes(this.transcriptDir(id), max);
  }
  /** Why this task's sdk/ folder (the SDK's working folder) can't be used, or null: absent, or a plain private folder. */
  sdkProblem(id) {
    try { lstatSync(this.sdk(id)); } catch (e) { return e?.code === "ENOENT" ? null : String(e?.code ?? e); }
    return privateDirProblem(this.sdk(id));
  }
  // (best effort: only plain files and folders reached by lstat are removed; a link anywhere on the way or inside is
  //  left alone, never followed, and what is left still counts in the task's use)
  #dropTranscript(id) {
    if (!this.transcripts || this.#transcriptProblem(id)) return;
    try { removePlainTree(this.transcriptDir(id)); } catch {}
  }
  work(id) { return join(this.root, id, "work"); }
  gitdir(id) { return join(this.root, id, "git"); }

  // ---- one operation at a time per task
  #serial(id, f) {
    const prev = this.queues.get(id) ?? Promise.resolve();
    const next = prev.then(f, f);
    this.queues.set(id, next.catch(() => {}));
    return next;
  }
  #get(id) {
    const t = this.tasks.get(id);
    if (!t) throw new TaskError("not_found", "no such task");
    return t;
  }

  // ---- the log
  #logPath(id) { return join(this.dir(id), "log.jsonl"); }
  /** The log's events, every complete line checked: one closed record {seq, at, event, intent?}, seqs 1, 2, 3...
   * with no gap or repeat, each event the protocol's.  A torn final fragment (no newline yet) is cut off first; a bad
   * complete line is a LogProblem (the task fails; nothing is dropped silently).  Never through a link. */
  #readLog(id) {
    const p = this.#logPath(id);
    let buf;
    try { buf = git.readPlain(p, this.budget.log + this.budget.event); } catch (e) { if (e.code === "ENOENT") return []; throw new LogProblem(`its log can't be read (${String(e?.code ?? e?.message ?? e).slice(0, 80)})`); }
    const end = buf.lastIndexOf(0x0a) + 1;
    if (end !== buf.length) {
      const fd = openSync(p, constants.O_RDWR | NOFOLLOW);
      try { const st = fstatSync(fd); if (!st.isFile() || st.nlink !== 1) throw new LogProblem("its log isn't a plain file"); ftruncateSync(fd, end); fsyncSync(fd); } finally { closeSync(fd); }
      buf = buf.subarray(0, end);
    }
    const out = [];
    let prev = 0;
    for (const line of buf.toString("utf8").split("\n")) {
      if (!line) continue;
      let e;
      try { e = parseCanonical(line); } catch { throw new LogProblem(`its log has a line that isn't one of its records (after seq ${prev})`); }
      if (!exactKeys(e, ["seq", "at", "event"], ["intent"]) || e.seq !== prev + 1 || !safeInt(e.seq, 1) || typeof e.at !== "string" || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(e.at) || (e.intent !== undefined && !HEX32.test(e.intent))) throw new LogProblem(`its log's record after seq ${prev} isn't one`);
      const ep = eventProblem(e.event);
      if (ep) throw new LogProblem(`its log at seq ${e.seq} has ${ep}`);
      out.push(e);
      prev = e.seq;
    }
    return out;
  }
  /** Append events (fsynced) with the next seqs; returns them.  Over the log's budget: refused `busy`. */
  #append(id, events, intentId) {
    const t = this.#get(id), p = this.#logPath(id);
    if (t.broken) throw new TaskError("final", "the task is failed");
    if (!Number.isSafeInteger(t.seq + events.length)) throw new TaskError("busy", "the task's log is full");
    for (const ev of events) { const ep = eventProblem(ev); if (ep) throw new TaskError("bad_request", ep); }
    // (an event is never cut or replaced by a stub, which the protocol has no form for: one over the bound is refused,
    //  and the operations that make big events (propose) check that before anything is written)
    const lines = events.map((event, i) => {
      const s = canonical({ seq: t.seq + 1 + i, at: new Date(this.now()).toISOString(), event, ...(intentId ? { intent: intentId } : {}) });
      if (enc.encode(s).length > this.budget.event) throw new TaskError("too_large", "an event would be over its bound");
      return s;
    });
    const data = lines.join("\n") + "\n";
    // (opened without following a link, a plain file with one link; the bound in bytes as written: UTF-8)
    const fd = openSync(p, constants.O_WRONLY | constants.O_APPEND | constants.O_CREAT | NOFOLLOW, 0o600);
    try {
      const st = fstatSync(fd);
      if (!st.isFile() || st.nlink !== 1) throw new TaskError("conflict", "the task's log isn't a plain file");
      if (st.size + Buffer.byteLength(data, "utf8") > this.budget.log) throw new TaskError("busy", "the task's log is full");
      git.writeAll(fd, data);
      fsyncSync(fd);
    } finally { closeSync(fd); }
    const out = lines.map((l) => JSON.parse(l));
    t.seq = out[out.length - 1].seq;
    return out;
  }
  #emit(id, entries) { for (const e of entries) for (const f of this.listeners) try { f({ task: id, seq: e.seq, event: e.event }); } catch {} }
  #save(id) {
    const t = this.#get(id);
    if (t.broken) throw new TaskError("final", "the task is failed");
    t.updated = this.now();
    // (the in-memory marks (broken, unserved) are never written: task.json holds only its schema's fields)
    const { broken: _b, unserved: _u, ...record } = t;
    writeJson(join(this.dir(id), "task.json"), record);
  }

  // ---- budget
  // (every kept task's use, broken ones included, measured afresh from its folder on disk at each admission (a start, a
  //  reservation), never read from its state or a cache; a task whose use can't be measured safely counts as unknown,
  //  and then nothing new is admitted: `busy`.  The walk's entry bound caps the cost)
  #bytes(id) { return this.usage(id) ?? 0; }
  /** A task's use: its folder and its transcript, measured now; null when either can't be measured safely. */
  usage(id) {
    const own = dirBytes(this.dir(id)), tr = this.transcriptBytes(id);
    return own === null || tr === null || this.sdkProblem(id) ? null : own + tr;
  }
  #totalUse() {
    let total = 0;
    for (const id of this.tasks.keys()) {
      const n = this.usage(id);
      if (n === null) throw new TaskError("busy", "a kept task's storage can't be measured: new work isn't admitted until it is discarded");
      total += n;
    }
    return total;
  }
  #reserve(id, incoming) {
    const t = this.#get(id);
    const own = this.usage(id);
    if (own === null) throw new TaskError("busy", "the task's storage can't be measured");
    t.bytes = own;
    if (t.bytes + incoming > this.budget.task) throw new TaskError("busy", "the task's storage budget is used up");
    if (this.#totalUse() + incoming > this.budget.total) throw new TaskError("busy", "the tasks' storage budget is used up");
  }

  // ---- intents: a ref move, then its log events and status, finished or undone after a crash
  #commitIntent(id, intent) {
    const t = this.#get(id);
    t.intent = intent;
    this.#save(id);
    if (intent.ref) git.casRef(this.gitdir(id), intent.ref, intent.expect, intent.next);
    return this.#finish(id);
  }
  #finish(id) {
    const t = this.#get(id), i = t.intent;
    // (the intent's further refs (a round's tag, a merge's mine-<n>): made if absent; one already there must be exactly
    //  what this operation writes)
    for (const tag of i.tags ?? []) {
      const now = git.readRef(this.gitdir(id), tag.ref);
      if (now === null) git.casRef(this.gitdir(id), tag.ref, null, tag.next);
      else if (now !== tag.next) throw new TaskError("conflict", `${tag.ref} is not what this operation wrote`);
    }
    // (the intent's events: those already in the log must be exactly its first ones, in order, at the log's end; the
    //  rest are appended; the intent is cleared only once every one of them is durable)
    const log = this.#readLog(id), logged = log.filter((e) => e.intent === i.id);
    if (logged.length > i.events.length || logged.some((e, k) => canonical(e.event) !== canonical(i.events[k])) || (logged.length && log.at(-1) !== logged.at(-1)) || (logged.length > 1 && logged.at(-1).seq - logged[0].seq !== logged.length - 1)) throw new LogProblem("its log's record of an interrupted operation isn't that operation's");
    const entries = [...logged, ...(logged.length < i.events.length ? this.#append(id, i.events.slice(logged.length), i.id) : [])];
    // (only the closed list of fields an operation may change: never the grant, which only narrows, by `revoked`)
    const set = i.set ?? {};
    for (const k of ["status", "proposals", "mines", "merged", "receipt"]) if (Object.hasOwn(set, k)) t[k] = set[k];
    if (Object.hasOwn(set, "reason")) { if (set.reason === null) delete t.reason; else t.reason = set.reason; }
    if (set.revoked === true) t.grant = { ...t.grant, revoked: true };
    if (i.ledger) t.ledger[i.ledger.merge_id] = { hash: i.ledger.hash, answer: i.ledger.answer };
    t.intent = null;
    this.#save(id);
    this.#emit(id, entries);
    return entries;
  }
  #recover(id) {
    this.recovering = id;
    try { this.#recoverTask(id); } finally { this.recovering = null; }
  }
  #recoverTask(id) {
    const t = this.#get(id), gd = this.gitdir(id);
    try {
      // (the task's own folders and files first: plain, never links)
      for (const d of ["work"]) { const pd = plainDirProblem(join(this.dir(id), d)); if (pd) return this.#fail(id, `its ${d} folder can't be used (${pd})`, { log: false }); }
      const rp = git.repoProblem(gd);
      if (rp) return this.#fail(id, `its history can't be used (${rp})`, { log: false });
      git.clearStaleLocks(gd);
      // (the log, checked whole; its last seq is the task's: a state ahead of its log, or behind it, is a mismatch)
      let log;
      try { log = this.#readLog(id); } catch (e) { if (e instanceof LogProblem) return this.#fail(id, e.message, { log: false }); throw e; }
      const lastSeq = log.length ? log.at(-1).seq : 0;
      if (t.seq !== lastSeq && !(t.intent && t.seq <= lastSeq)) return this.#fail(id, "its state and its log disagree (seq)");
      t.seq = lastSeq;
      t.bytes = this.#bytes(id); // (never trusted from disk: measured)
      // (the grant must be the one recorded at the task's start, anchored to git, not to the control state: the base is
      //  the fixed refs/heads/base, a root commit (no parents), and its grant is its message's own final trailer record,
      //  parsed whole and compared exactly; a "Sagebrush-Task-Grant:" line anywhere else, in a proposal's summary or
      //  in the prompt, is never read)
      if (git.readRef(gd, "refs/heads/base") !== t.base) return this.#fail(id, "its base isn't the commit recorded at its start");
      const baseCommit = git.readCommit(gd, t.base);
      if (baseCommit.parents.length !== 0) return this.#fail(id, "its base isn't the task's first commit");
      if (grantOf(baseCommit.message) !== grantText(t.grant)) return this.#fail(id, "its grant doesn't match the one recorded at its start");
      const i = t.intent;
      // (an interrupted operation's intent is checked closed against what that operation may do, before any of it is
      //  applied: control state on disk is not trusted)
      const bad = i ? intentProblem(gd, t, i) : null;
      if (bad) return this.#fail(id, `its interrupted operation's record is invalid (${bad})`);
      if (i) {
        const now = i.ref ? git.readRef(gd, i.ref) : null;
        if (!i.ref || now === i.next) this.#finish(id);
        else if (now === i.expect) { t.intent = null; this.#save(id); }
        else return this.#fail(id, `${i.ref} is neither what the interrupted operation expected nor what it wrote`);
      }
      // (the completed records against each other: refs, history, log, ledger, receipt, finality)
      const cp = this.#reconcile(id);
      if (cp) return this.#fail(id, `its records disagree (${cp})`);
      // (a task that was working when the agent stopped: interrupted, and only a person's Resume goes on)
      if (t.status === "working") this.#transition(id, "recover");
      // (and the grant checked again against the base commit after recovery, before the task is offered or resumed)
      if (grantOf(baseCommit.message) !== grantText(t.grant)) return this.#fail(id, "its grant doesn't match the one recorded at its start");
    } catch (e) {
      this.#fail(id, `it couldn't be recovered (${String(e?.message ?? e).slice(0, 200)})`, { log: !(e instanceof LogProblem) });
    }
  }
  /** The completed records checked against each other (SEC sweep H2): why they disagree, or null. */
  #reconcile(id) {
    const t = this.#get(id), gd = this.gitdir(id), log = this.#readLog(id);
    const ref = (r) => git.readRef(gd, r);
    // (the refs: exactly the ones the records name, no more)
    const want = new Map([["refs/heads/base", t.base]]);
    if (t.proposals.length) want.set("refs/heads/proposal", t.proposals.at(-1));
    t.proposals.forEach((c, k) => want.set(`refs/tags/round-${k + 1}`, c));
    t.mines.forEach((c, k) => want.set(`refs/heads/mine-${k + 1}`, c));
    if (t.merged) want.set("refs/heads/merged", t.merged);
    const have = new Map();
    for (const d of ["refs/heads", "refs/tags"]) for (const n of readdirSync(join(gd, d))) if (!n.endsWith(".lock")) have.set(`${d}/${n}`, ref(`${d}/${n}`));
    for (const [r, c] of want) if (have.get(r) !== c) return `${r} isn't ${c.slice(0, 8)}`;
    for (const r of have.keys()) if (!want.has(r)) return `${r} isn't one the task records`;
    // (the history: each round's parent the one before (the first, the base); each mine's parent the base)
    let prev = t.base;
    for (const c of t.proposals) { if (!sameListB(git.readCommit(gd, c).parents, [prev])) return "a round's parent"; prev = c; }
    for (const c of t.mines) if (!sameListB(git.readCommit(gd, c).parents, [t.base])) return "a mine's parent";
    // (the status's own requirements)
    const entries = Object.entries(t.ledger);
    if (t.status === "proposal" && !t.proposals.length) return "a proposal status with no round";
    if (t.merged) {
      if (t.status !== "merged" || !t.mines.length || !t.proposals.length || !sameListB(git.readCommit(gd, t.merged).parents, [t.mines.at(-1), t.proposals.at(-1)])) return "the merge commit";
      if (entries.length !== 1 || canonical(entries[0][1].answer) !== canonical({ recorded: "merge", commit: t.merged }) || Object.hasOwn(t, "receipt")) return "the merge's ledger";
    } else if (Object.hasOwn(t, "receipt")) {
      if (t.status !== "merged" || t.receipt.proposal !== t.proposals.at(-1) || entries.length !== 1 || entries[0][0] !== t.receipt.merge_id || canonical(entries[0][1].answer) !== canonical({ recorded: "receipt", commit: null })) return "the receipt's ledger";
      const changes = changesBetween(gd, t.base, t.receipt.proposal);
      if (t.receipt.files.length !== changes.length || t.receipt.files.some((f, k) => f.path !== changes[k].path || f.proposal_blob !== changes[k].blob)) return "the receipt's files";
    } else {
      if (entries.length) return "a ledger with no merge";
      if (t.status === "merged") return "merged with neither a merge nor a receipt";
    }
    // (the log: its last status is the task's; finality and revocation are monotone and agree with it)
    const statuses = log.filter((e) => e.event.type === "task_status").map((e) => e.event);
    if (!t.intent) {
      const last = statuses.at(-1);
      if (!last || last.status !== t.status) return "the task's status isn't its log's last";
      const finalAt = statuses.findIndex((e) => ["merged", "closed", "failed"].includes(e.status));
      if (finalAt >= 0 && finalAt !== statuses.length - 1) return "a final status was left";
      const revoked = statuses.some((e) => e.status === "closed" && e.reason === "revoked by the person");
      if (revoked !== t.grant.revoked) return "its revocation and its log disagree";
      const rounds = log.filter((e) => e.event.type === "proposal").map((e) => e.event);
      if (rounds.length !== t.proposals.length) return "its rounds and its log disagree";
      // (each round's event exactly as its builder makes it from git: round number, base, commit and changed files)
      for (const [k, ev] of rounds.entries()) if (canonical(ev) !== canonical({ type: "proposal", round: k + 1, base: t.base, commit: t.proposals[k], files: changesBetween(gd, t.base, t.proposals[k]) })) return `round ${k + 1}'s event isn't its commit's`;
    }
    return null;
  }
  /** The task failed in place: its data kept; the reason in its state and (unless its log is the problem) its log. */
  #fail(id, reason, { log = true } = {}) {
    reason = reasonText(reason);
    const t = this.#get(id);
    // (failed while its records were being checked: nothing is served from them (no events, diff or file), only that it failed)
    if (this.recovering === id) t.unserved = true;
    t.status = "failed";
    t.reason = reason;
    t.intent = null;
    if (t.broken) return;
    try { this.#save(id); if (log) this.#emit(id, this.#append(id, [{ type: "task_status", status: "failed", reason }])); } catch {}
  }
  #broken(id, reason) {
    return { v: 1, task: id, title: "(unreadable task)", prompt: "", target: "local", status: "failed", reason, grant: { docs: [], run: false, scope: "", created: 0, revoked: true }, base: "0".repeat(40), proposals: [], mines: [], merged: null, seq: 0, ledger: {}, intent: null, created: 0, updated: 0, broken: true };
  }
  /** A status change with no ref: its intent names the event, so a crash between the log and task.json is finished. */
  #transition(id, op, reason) {
    const t = this.#get(id);
    return this.#commitIntent(id, buildIntent(this.gitdir(id), t, "status", randomBytes(16).toString("hex"), { op, ...(reason !== undefined ? { reason } : {}) }));
  }

  // ======================================================================== the protocol's requests (§6.1)
  /** tasks.start: the documents copied into a new task's work/, its base commit (with the frozen grant), its state. */
  start(p) {
    if (this.tasks.size >= this.budget.tasks) throw new TaskError("busy", `at most ${this.budget.tasks} tasks are kept`);
    const total = p.docs.reduce((n, d) => n + d.bytes.length, 0);
    if (this.#totalUse() + total + this.budget.reserve > this.budget.total) throw new TaskError("busy", "the tasks' storage budget is used up");
    const id = randomBytes(16).toString("hex"), final = this.dir(id), dir = join(this.root, ".staging", id);
    const gd = join(dir, "git"), work = join(dir, "work");
    mkdirSync(dir, { mode: 0o700 });
    try {
      git.initRepo(gd);
      mkdirSync(work, { mode: 0o700 });
      const files = new Map();
      for (const d of p.docs) {
        writeTaskFile(work, d.path, d.bytes);
        files.set(d.path, git.writeObject(gd, "blob", d.bytes));
      }
      const created = this.now();
      const grant = { docs: p.docs.map((d) => d.path).sort(), run: p.run, scope: this.scope, created, revoked: false };
      const tree = git.writeTree(gd, files);
      const base = git.writeCommit(gd, { tree, message: `Task: ${p.title}\n\n${p.prompt}\n\n${GRANT_LINE}${grantText(grant)}\n`, time: created / 1000 });
      git.casRef(gd, "refs/heads/base", null, base);
      writeTaskFile(dir, "reserve", Buffer.alloc(this.budget.reserve));
      const at = new Date(this.now()).toISOString();
      const first = { seq: 1, at, event: { type: "task_status", status: "working" } };
      const lfd = openSync(join(dir, "log.jsonl"), constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | NOFOLLOW, 0o600);
      try { git.writeAll(lfd, canonical(first) + "\n"); fsyncSync(lfd); } finally { closeSync(lfd); }
      const t = { v: 1, task: id, title: p.title, prompt: p.prompt, target: "local", status: "working", grant, base, proposals: [], mines: [], merged: null, seq: 1, ledger: {}, intent: null, created, updated: created, bytes: dirBytes(dir) ?? 0 };
      writeJson(join(dir, "task.json"), t);
      // (whole: renamed into place, so a task folder is only ever an acknowledged start)
      renameSync(dir, final);
      git.syncDir(join(this.root, ".staging"));
      git.syncDir(this.root);
      this.tasks.set(id, t);
      this.#emit(id, [first]);
      return { task: id, base, seq: t.seq };
    } catch (e) {
      this.tasks.delete(id);
      // (only the staging folder, never an acknowledged task's)
      if (existsSync(dir)) rmSync(dir, { recursive: true, force: true });
      throw e;
    }
  }

  #entry(t) {
    return { task: t.task, title: t.title, status: t.status, target: t.target, run: t.grant.run, round: t.proposals.length, seq: t.seq, proposal: t.proposals.at(-1) ?? null, question: false, updated: t.updated };
  }
  list() { return { tasks: [...this.tasks.values()].sort((a, b) => b.updated - a.updated).slice(0, this.budget.tasks).map((t) => this.#entry(t)) }; }

  /** tasks.get: the events after `after`, at most 4 MiB of them; `reset` when `after` is past what this task issued. */
  get({ task, after }) {
    const t = this.#get(task);
    // (a task whose log can't be read whole is failed; its events aren't served, never in part)
    if (t.unserved) throw new TaskError("conflict", "the task's records disagree: nothing is served from them");
    const readLog = () => { try { return t.broken ? [] : this.#readLog(task); } catch (e) { if (e instanceof LogProblem) throw new TaskError("conflict", "the task's log can't be read"); throw e; } };
    const reset = after > t.seq;
    const all = readLog().filter((e) => reset || e.seq > after);
    const events = [];
    let bytes = 0, last = reset ? 0 : after;
    for (const e of all) {
      const n = enc.encode(JSON.stringify(e.event)).length + 64;
      if (events.length && bytes + n > LIMITS.frame - 64 * 1024) break;
      bytes += n;
      events.push({ seq: e.seq, event: e.event });
      last = e.seq;
    }
    return { task: this.#entry(t), events, last, reset };
  }

  /** A commit the request may name: this task's base or one of its proposal rounds, exactly. */
  #named(t, commit) {
    if (t.unserved || t.broken) throw new TaskError("conflict", "the task's records disagree: nothing is served from them");
    if (commit !== t.base && !t.proposals.includes(commit)) throw new TaskError("not_found", "not a commit of this task's base or proposals");
    return git.readTree(this.gitdir(t.task), git.readCommit(this.gitdir(t.task), commit).tree);
  }
  #changes(t, commit) {
    const base = git.readTree(this.gitdir(t.task), git.readCommit(this.gitdir(t.task), t.base).tree), now = this.#named(t, commit);
    const files = [];
    for (const p of [...new Set([...base.keys(), ...now.keys()])].sort()) {
      const a = base.get(p) ?? null, b = now.get(p) ?? null;
      if (a === b) continue;
      files.push({ path: p, kind: /\.ipynb$/.test(p) ? "notebook" : "file", change: a === null ? "added" : b === null ? "deleted" : "modified", base_blob: a, blob: b });
    }
    return files;
  }
  diff({ task, commit }) {
    const t = this.#get(task);
    return { task, base: t.base, commit, round: commit === t.base ? 0 : t.proposals.indexOf(commit) + 1, seq: t.seq, files: this.#changes(t, commit) };
  }
  file({ task, commit, path }) {
    const t = this.#get(task), tree = this.#named(t, commit), blob = tree.get(path);
    if (!blob) throw new TaskError("not_found", "no such file in that commit");
    const { body } = git.readObject(this.gitdir(task), blob);
    return { blob, content: asContent(body) };
  }

  /** The working copy committed as the next proposal round (the agent's `propose`, A2). */
  propose(task, { summary = "" } = {}) {
    return this.#serial(task, () => {
      const t = this.#get(task);
      if (t.status !== "working") throw new TaskError(FINAL.has(t.status) ? "final" : "stale", `the task is ${t.status}`);
      const { files, problems } = scanTree(this.work(task), this.budget.files * 10);
      if (problems.length) throw new TaskError("bad_request", `the working copy has what can't be proposed: ${problems.slice(0, 3).join("; ")}`);
      if (files.size > this.budget.files) throw new TaskError("too_large", `at most ${this.budget.files} files`);
      // (the whole set against the protocol's path rules, before any object, ref or event: a name the page would refuse,
      //  a reserved name, .git anywhere, or two that differ only in case, refuses the proposal with nothing written)
      const badPaths = pathSetProblem([...files.keys()]);
      if (badPaths) throw new TaskError("bad_request", `the working copy has a path that can't be proposed: ${badPaths}`);
      const size = [...files.values()].reduce((n, f) => n + f.size, 0);
      if (size > this.budget.work) throw new TaskError("too_large", "the working copy is over its budget");
      this.#reserve(task, size);
      const gd = this.gitdir(task), map = new Map();
      for (const p of files.keys()) map.set(p, git.writeObject(gd, "blob", readTaskFile(this.work(task), p, LIMITS.doc)));
      const prev = t.proposals.at(-1) ?? null, round = t.proposals.length + 1;
      const commit = git.writeCommit(gd, { tree: git.writeTree(gd, map), parents: [prev ?? t.base], message: `Proposal, round ${round}\n\n${summary}\n`, time: this.now() / 1000 });
      const intent = buildIntent(gd, t, "propose", randomBytes(16).toString("hex"), { commit });
      // (the proposal's event must fit the log's per-event bound as it will be written: else refused here, before any
      //  intent, ref or event, like the other budget refusals; the objects written so far are unreferenced)
      const event = intent.events[0];
      const sized = canonical({ seq: Number.MAX_SAFE_INTEGER, at: new Date(this.now()).toISOString(), event, intent: "0".repeat(32) });
      if (enc.encode(sized).length > this.budget.event) throw new TaskError("too_large", `the proposal changes too many files to describe in one event (at most ${this.budget.event} bytes): propose fewer changes at a time`);
      return this.#commitIntent(task, intent);
    });
  }
  /** tasks.merged: what the page merged, recorded (never written to the workspace). */
  merged(p) {
    return this.#serial(p.task, () => {
      const t = this.#get(p.task);
      // (an identical retry after a lost answer gets the same answer; the same merge_id with another payload is a conflict)
      const hash = sha256(canonical({ ...p, files: p.files.map((f) => ({ ...f })) }));
      // (a retry is answered from the ledger only by a merged task, whose records were reconciled at load; a failed or
      //  closed task answers nothing from its records)
      if (t.status !== "merged" && FINAL.has(t.status)) throw new TaskError("final", `the task is ${t.status}`);
      const prior = t.status === "merged" ? t.ledger[p.merge_id] : undefined;
      if (prior) { if (prior.hash === hash) return prior.answer; throw new TaskError("conflict", "this merge_id was used with another request"); }
      if (t.status === "merged") throw new TaskError("final", "the task is already merged");
      if (FINAL.has(t.status)) throw new TaskError("final", `the task is ${t.status}`);
      if (t.status !== "proposal" || p.proposal !== t.proposals.at(-1) || p.seq !== t.seq) throw new TaskError("stale", "the task has moved on from that proposal");
      const changes = this.#changes(t, p.proposal);
      const want = new Map(changes.map((c) => [c.path, c.blob]));
      if (p.files.length !== want.size || !p.files.every((f) => want.has(f.path) && want.get(f.path) === f.proposal_blob)) throw new TaskError("bad_request", "files must be exactly the proposal's changed paths, each with its proposal_blob");
      // (fresh bytes: their hash recomputed and compared; no stored object is named by them)
      for (const f of p.files) for (const s of [f.mine, f.merged]) if (s?.bytes && git.blobId(s.bytes) !== s.blob) throw new TaskError("bad_request", `${f.path}: a blob doesn't match its content`);
      const complete = p.files.every((f) => f.mine !== null && f.merged !== null);
      const gd = this.gitdir(p.task), id = randomBytes(16).toString("hex");
      if (!complete) {
        // (a receipt: the hashes, and that the content was not sent; no commit claims to be the merge)
        const answer = { recorded: "receipt", commit: null };
        // (in the proposal's own path order, whatever the request's order: §6.1 asks for the set; the ledger's hash above
        //  is of the request exactly as sent, so an identical retry still gets the same answer)
        const files = p.files.map((f) => ({ path: f.path, proposal_blob: f.proposal_blob, mine: f.mine?.absent ? "absent" : f.mine?.blob ?? "not sent", merged: f.merged?.absent ? "absent" : f.merged?.blob ?? "not sent" })).sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
        // (the receipt is kept in the control state, not sent as an event: §6.1's events are task_status and proposal)
        this.#commitIntent(p.task, buildIntent(gd, t, "receipt", id, { merge_id: p.merge_id, hash, files }));
        this.#dropTranscript(p.task);
        return answer;
      }
      this.#reserve(p.task, p.files.reduce((n, f) => n + (f.mine?.bytes?.length ?? 0) + (f.merged?.bytes?.length ?? 0), 0));
      const base = git.readTree(gd, git.readCommit(gd, t.base).tree);
      const tree = (side) => {
        const m = new Map(base);
        for (const f of p.files) { const s = f[side]; if (s.absent) m.delete(f.path); else m.set(f.path, git.writeObject(gd, "blob", s.bytes)); }
        return git.writeTree(gd, m);
      };
      const n = t.mines.length + 1, time = this.now() / 1000;
      const trailers = `Sagebrush-Task: ${p.task}\nSagebrush-Proposal: ${p.proposal}\nSagebrush-Seq: ${p.seq}\nSagebrush-Merge-Id: ${p.merge_id}\nSagebrush-Reported-By: the page (its merge, as it reported it; paths the proposal didn't change are as in the base)\n`;
      const mine = git.writeCommit(gd, { tree: tree("mine"), parents: [t.base], message: `The person's version at Merge\n\n${trailers}`, time });
      const merge = git.writeCommit(gd, { tree: tree("merged"), parents: [mine, p.proposal], message: `Merged, as the page reported it\n\n${trailers}`, time });
      const answer = { recorded: "merge", commit: merge };
      // (both refs under the one intent, written first: the merge ref by CAS, then mine-<n> as the intent's second ref,
      //  made when the operation finishes, so a crash anywhere leaves neither or, after recovery, both)
      this.#commitIntent(p.task, buildIntent(gd, t, "merge", id, { merge, mine, merge_id: p.merge_id, hash }));
      this.#dropTranscript(p.task);
      return answer;
    });
  }

  /** tasks.close: nothing changes; final. */
  close(p) {
    return this.#serial(p.task, () => {
      const t = this.#get(p.task);
      if (FINAL.has(t.status)) throw new TaskError("final", `the task is ${t.status}`);
      if (p.seq !== t.seq || (p.proposal ?? null) !== (t.proposals.at(-1) ?? null)) throw new TaskError("stale", "the task has moved on");
      this.#transition(p.task, "close");
      this.#dropTranscript(p.task);
      return { status: "closed" };
    });
  }
  /** tasks.ask: the person's note and current versions recorded (mine-<n>); back to working, for the next round. */
  ask(p) {
    return this.#serial(p.task, () => {
      const t = this.#get(p.task);
      if (FINAL.has(t.status)) throw new TaskError("final", `the task is ${t.status}`);
      if (t.status !== "proposal" || p.proposal !== t.proposals.at(-1) || p.seq !== t.seq) throw new TaskError("stale", "the task has moved on from that proposal");
      const own = new Set(t.grant.docs);
      if (!p.current.every((d) => own.has(d.path))) throw new TaskError("bad_request", "current may name only the task's own documents");
      this.#reserve(p.task, p.current.reduce((n, d) => n + d.bytes.length, 0));
      const gd = this.gitdir(p.task), m = git.readTree(gd, git.readCommit(gd, t.base).tree);
      for (const d of p.current) m.set(d.path, git.writeObject(gd, "blob", d.bytes));
      const n = t.mines.length + 1;
      const mine = git.writeCommit(gd, { tree: git.writeTree(gd, m), parents: [t.base], message: `The person's version at Ask for changes (round ${t.proposals.length})\n\n${p.note}\n`, time: this.now() / 1000 });
      this.#commitIntent(p.task, buildIntent(gd, t, "ask", randomBytes(16).toString("hex"), { mine }));
      return { status: "working", round: t.proposals.length };
    });
  }
  /** The person's latest Ask for changes, for the turn that answers it: their note exactly as sent, and the paths whose
   * versions in the request (mine-<n>) differ from the base; null when the task has none. */
  lastAsk(task) {
    const t = this.#get(task);
    if (!t.mines.length) return null;
    const gd = this.gitdir(task), mine = t.mines.at(-1), { message } = git.readCommit(gd, mine);
    if (!message.startsWith("The person's version at Ask for changes")) return null;
    return { note: message.slice(message.indexOf("\n\n") + 2).replace(/\n$/, ""), paths: changesBetween(gd, t.base, mine).map((c) => c.path) };
  }
  /** tasks.stop: a working task interrupted (its turn and run are the caller's to stop). */
  stop({ task }) {
    return this.#serial(task, () => {
      const t = this.#get(task);
      if (FINAL.has(t.status)) throw new TaskError("final", `the task is ${t.status}`);
      if (t.status === "working") this.#transition(task, "stop");
      return { status: this.#get(task).status };
    });
  }
  /** tasks.revoke: closed for good, its grant void. */
  revoke({ task }) {
    return this.#serial(task, () => {
      const t = this.#get(task);
      if (FINAL.has(t.status)) throw new TaskError("final", `the task is ${t.status}`);
      this.#transition(task, "revoke");
      this.#dropTranscript(task);
      return { status: "closed" };
    });
  }
  /** tasks.resume: an interrupted task working again, under its frozen grant. */
  resume({ task }) {
    return this.#serial(task, () => {
      const t = this.#get(task);
      if (FINAL.has(t.status)) throw new TaskError("final", `the task is ${t.status}`);
      if (t.status !== "interrupted") throw new TaskError("stale", "only an interrupted task resumes");
      if (t.grant.revoked) throw new TaskError("forbidden", "the task's grant was revoked");
      this.#transition(task, "resume");
      return { status: "working" };
    });
  }
  // ---- for the task's turns (task-turns.mjs)
  /** A turn's own events (the chat turn events of §6.1), logged and sent as they are; one over its bound is refused,
   * never cut.  Only while the task is working. */
  record(task, events) {
    return this.#serial(task, () => {
      const t = this.#get(task);
      if (t.status !== "working") throw new TaskError("stale", `the task is ${t.status}`);
      const entries = this.#append(task, events);
      this.#save(task);
      this.#emit(task, entries);
      return entries;
    });
  }
  /** A working task stopped by the host, with its reason (a turn that ended without a proposal, a limit). */
  interrupt(task, reason) {
    return this.#serial(task, () => {
      const t = this.#get(task);
      if (t.status === "working") this.#transition(task, "interrupt", reason);
      return { status: this.#get(task).status };
    });
  }
  /** Write one file of a working task's copy (the turn's tools): the protocol's path rules, the copy's file count
   * and size and the task's budget checked first; a plain file only (task-paths.mjs). */
  // ---- for runs (task-runner.mjs)
  /** A run's own tmp folder root, tmp/ in the task's folder: made private if missing, else it must be a private
   * plain folder. */
  runTmpRoot(task) {
    const d = join(this.dir(task), "tmp");
    try { mkdirSync(d, { mode: 0o700 }); } catch (e) { if (e.code !== "EEXIST") throw e; }
    const why = privateDirProblem(d);
    if (why) throw new TaskError("unavailable", `the task's tmp folder can't be used (${why})`);
    return d;
  }
  /** work/'s files now, as a tree in git/ (objects only, no ref): what a run the host cuts off goes back to.  Refused,
   * with nothing written, when work/ holds a link, a special file or a file with more than one link. */
  snapshotWork(task) {
    return this.#serial(task, () => {
      const t = this.#get(task);
      if (t.status !== "working") throw new TaskError(FINAL.has(t.status) ? "final" : "stale", `the task is ${t.status}`);
      const { files, problems } = scanTree(this.work(task), this.budget.files * 10);
      if (problems.length) throw new TaskError("bad_request", `your copy has what a run can't start from: ${problems.slice(0, 3).join("; ")}`);
      if (files.size > this.budget.files) throw new TaskError("too_large", `at most ${this.budget.files} files`);
      this.#reserve(task, [...files.values()].reduce((n, f) => n + f.size, 0));
      const gd = this.gitdir(task), map = new Map();
      for (const p of files.keys()) map.set(p, git.writeObject(gd, "blob", readTaskFile(this.work(task), p, this.budget.work)));
      return git.writeTree(gd, map);
    });
  }
  /** work/ replaced whole by `tree`'s files: built beside it in a fresh folder, swapped in by rename, and what was
   * there removed (rm never follows a link it finds). */
  restoreWork(task, tree) {
    return this.#serial(task, () => {
      const gd = this.gitdir(task), dir = this.dir(task), files = git.readTree(gd, tree), tag = randomBytes(6).toString("hex");
      const fresh = join(dir, `.work-${tag}`), old = join(dir, `.dropped-${tag}`);
      mkdirSync(fresh, { mode: 0o700 });
      try { for (const [p, oid] of files) writeTaskFile(fresh, p, git.readObject(gd, oid).body); } catch (e) { rmSync(fresh, { recursive: true, force: true }); throw e; }
      renameSync(this.work(task), old);
      renameSync(fresh, this.work(task));
      git.syncDir(dir);
      rmSync(old, { recursive: true, force: true });
    });
  }
  // (what a crash during a run or a restore can leave: the run tmp folders and a half-built or dropped copy; only plain
  //  folders of those names are removed)
  #dropRunLeftovers(id) {
    const dir = this.dir(id), tmp = join(dir, "tmp");
    try {
      for (const name of readdirSync(dir)) if (/^\.(work|dropped)-[0-9a-f]{12}$/.test(name) && !plainDirProblem(join(dir, name))) rmSync(join(dir, name), { recursive: true, force: true });
      if (!plainDirProblem(tmp)) for (const name of readdirSync(tmp)) if (/^run-[0-9a-f]{12}$/.test(name) && !plainDirProblem(join(tmp, name))) rmSync(join(tmp, name), { recursive: true, force: true });
    } catch {}
  }
  writeWork(task, path, bytes) {
    return this.#serial(task, () => {
      const t = this.#get(task);
      if (t.status !== "working") throw new TaskError("stale", `the task is ${t.status}`);
      const why = pathProblem(path);
      if (why) throw new TaskError("bad_request", why);
      if (bytes.length > LIMITS.doc) throw new TaskError("too_large", `a file is at most ${LIMITS.doc} bytes`);
      const { files } = scanTree(this.work(task), this.budget.files * 10);
      const names = [...files.keys()];
      if (!files.has(path)) {
        if (files.size + 1 > this.budget.files) throw new TaskError("too_large", `at most ${this.budget.files} files`);
        const clash = pathSetProblem([...names, path]);
        if (clash) throw new TaskError("bad_request", clash);
      }
      const size = [...files.values()].reduce((n, f) => n + f.size, 0) - (files.get(path)?.size ?? 0) + bytes.length;
      if (size > this.budget.work) throw new TaskError("too_large", "the working copy would be over its budget");
      this.#reserve(task, bytes.length);
      writeTaskFile(this.work(task), path, bytes);
      return { path, bytes: bytes.length };
    });
  }

  /** tasks.answer: questions come in M2. */
  answer() { throw new TaskError("unavailable", "questions come in a later version"); }

  /** For tests and the turns (A2): a task's state, read only. */
  state(id) { return structuredClone(this.#get(id)); }
}
