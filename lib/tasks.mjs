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
import { closeSync, existsSync, fsyncSync, lstatSync, mkdirSync, openSync, readFileSync, readdirSync, renameSync, rmSync, statSync, writeSync, ftruncateSync, fstatSync, readSync, unlinkSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import * as git from "./task-git.mjs";
import { privateDirProblem, readTaskFile, scanTree, writeTaskFile, UnsafePath } from "./task-paths.mjs";
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
function writeJson(path, v) {
  const tmp = `${path}.${process.pid}.tmp`;
  const fd = openSync(tmp, "w", 0o600);
  try { writeSync(fd, JSON.stringify(v)); fsyncSync(fd); } finally { closeSync(fd); }
  renameSync(tmp, path);
  git.syncDir(path.slice(0, path.lastIndexOf("/")));
}
/** The bytes of everything under `dir` (no link followed), bounded by `max` entries. */
function dirBytes(dir, max = 200000) {
  let n = 0, seen = 0;
  const walk = (d) => {
    for (const name of readdirSync(d)) {
      if (++seen > max) return;
      const p = join(d, name), st = lstatSync(p);
      if (st.isDirectory() && !st.isSymbolicLink()) walk(p);
      else n += st.size;
    }
  };
  try { walk(dir); } catch {}
  return n;
}
const sha256 = (s) => createHash("sha256").update(s).digest("hex");
/** A value's canonical JSON (keys sorted), for the merge ledger's exact-request binding. */
function canonical(v) {
  if (Array.isArray(v)) return "[" + v.map(canonical).join(",") + "]";
  if (v && typeof v === "object" && !(v instanceof Uint8Array)) return "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canonical(v[k])).join(",") + "}";
  if (v instanceof Uint8Array) return JSON.stringify(Buffer.from(v).toString("base64"));
  return JSON.stringify(v);
}
/** A document's bytes as P0's `content`: text if it is valid UTF-8, else {base64}. */
function asContent(bytes) {
  const s = Buffer.from(bytes).toString("utf8");
  return Buffer.from(s, "utf8").equals(Buffer.from(bytes)) ? s : { base64: Buffer.from(bytes).toString("base64") };
}

// ---- task.json: checked closed on every load (nothing in it is trusted because it is on disk)
const STATE_KEYS = ["v", "task", "title", "prompt", "target", "status", "reason", "grant", "base", "proposals", "mines", "merged", "receipt", "seq", "ledger", "intent", "created", "updated", "bytes"];
function stateProblem(t, id) {
  if (!t || typeof t !== "object" || Array.isArray(t)) return "not an object";
  for (const k of Object.keys(t)) if (!STATE_KEYS.includes(k)) return `unknown field ${k}`;
  if (t.v !== 1 || t.task !== id || typeof t.title !== "string" || typeof t.prompt !== "string" || t.target !== "local") return "bad header";
  if (!STATUSES.includes(t.status)) return "bad status";
  const g = t.grant;
  if (!g || typeof g !== "object" || !Array.isArray(g.docs) || typeof g.run !== "boolean" || typeof g.scope !== "string" || typeof g.revoked !== "boolean") return "bad grant";
  if (!/^[0-9a-f]{40}$/.test(t.base ?? "") || !Array.isArray(t.proposals) || !t.proposals.every((c) => /^[0-9a-f]{40}$/.test(c))) return "bad commits";
  if (!Array.isArray(t.mines) || !(t.merged === null || /^[0-9a-f]{40}$/.test(t.merged))) return "bad mines";
  if (!Number.isSafeInteger(t.seq) || t.seq < 0 || !t.ledger || typeof t.ledger !== "object") return "bad seq or ledger";
  return null;
}
/** The grant as recorded in the base commit's message (immutable): what task.json's grant must equal. */
const GRANT_LINE = "Sagebrush-Task-Grant: ";
const grantText = (g) => canonical({ docs: g.docs, run: g.run, scope: g.scope, created: g.created });

export class TaskStore {
  /** `root`: the tasks folder; `scope`: this installation's id (the grant's scope); `now`: ms clock (tests). */
  constructor({ root = defaultRoot(), scope, now = () => Date.now(), budget = BUDGET } = {}) {
    if (typeof scope !== "string" || !scope) throw new Error("TaskStore needs this installation's scope id");
    this.root = root;
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
    for (const name of readdirSync(this.root).sort()) {
      if (!HEX32.test(name)) continue;
      const dir = join(this.root, name);
      if (privateDirProblem(dir)) continue;
      let t;
      try { t = JSON.parse(readFileSync(join(dir, "task.json"), "utf8")); } catch {
        // (a task whose start never finished: never acknowledged, so it is removed)
        rmSync(dir, { recursive: true, force: true });
        continue;
      }
      const bad = stateProblem(t, name);
      if (bad) { this.tasks.set(name, this.#broken(name, `its control state is invalid (${bad})`)); continue; }
      this.tasks.set(name, t);
      this.#recover(name);
    }
    return this;
  }
  onEvent(f) { this.listeners.add(f); return () => this.listeners.delete(f); }

  // ---- paths
  dir(id) { return join(this.root, id); }
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
  /** The log's valid events; a torn last line is cut off (truncated) first. */
  #readLog(id) {
    const p = this.#logPath(id);
    let buf;
    try { buf = readFileSync(p); } catch (e) { if (e.code === "ENOENT") return []; throw e; }
    const end = buf.lastIndexOf(0x0a) + 1;
    if (end !== buf.length) {
      const fd = openSync(p, "r+");
      try { ftruncateSync(fd, end); fsyncSync(fd); } finally { closeSync(fd); }
      buf = buf.subarray(0, end);
    }
    const out = [];
    for (const line of buf.toString("utf8").split("\n")) {
      if (!line) continue;
      try { const e = JSON.parse(line); if (Number.isSafeInteger(e.seq) && e.event && typeof e.event.type === "string") out.push(e); } catch {}
    }
    return out;
  }
  /** Append events (fsynced) with the next seqs; returns them.  Over the log's budget: refused `busy`. */
  #append(id, events, intentId) {
    const t = this.#get(id), p = this.#logPath(id);
    const lines = events.map((event, i) => {
      const e = { seq: t.seq + 1 + i, at: new Date(this.now()).toISOString(), event, ...(intentId ? { intent: intentId } : {}) };
      let s = JSON.stringify(e);
      if (enc.encode(s).length > this.budget.event) s = JSON.stringify({ ...e, event: { type: e.event.type, omitted: true } });
      return s;
    });
    const data = lines.join("\n") + "\n";
    let size = 0;
    try { size = statSync(p).size; } catch {}
    // (the bound is in bytes as written: UTF-8, not the string's UTF-16 length)
    if (size + Buffer.byteLength(data, "utf8") > this.budget.log) throw new TaskError("busy", "the task's log is full");
    const fd = openSync(p, "a", 0o600);
    try { writeSync(fd, data); fsyncSync(fd); } finally { closeSync(fd); }
    const out = lines.map((l) => JSON.parse(l));
    t.seq = out[out.length - 1].seq;
    return out;
  }
  #emit(id, entries) { for (const e of entries) for (const f of this.listeners) try { f({ task: id, seq: e.seq, event: e.event }); } catch {} }
  #save(id) {
    const t = this.#get(id);
    t.updated = this.now();
    writeJson(join(this.dir(id), "task.json"), t);
  }

  // ---- budget
  #bytes(id) { return dirBytes(this.dir(id)); }
  #reserve(id, incoming) {
    const t = this.#get(id);
    t.bytes = this.#bytes(id);
    if (t.bytes + incoming > this.budget.task) throw new TaskError("busy", "the task's storage budget is used up");
    const total = [...this.tasks.values()].reduce((n, x) => n + (x.bytes ?? 0), 0);
    if (total + incoming > this.budget.total) throw new TaskError("busy", "the tasks' storage budget is used up");
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
    const logged = this.#readLog(id).filter((e) => e.intent === i.id);
    const entries = logged.length ? logged : this.#append(id, i.events, i.id);
    Object.assign(t, i.set ?? {});
    if (i.ledger) t.ledger[i.ledger.merge_id] = { hash: i.ledger.hash, answer: i.ledger.answer };
    t.intent = null;
    this.#save(id);
    this.#emit(id, entries);
    return entries;
  }
  #recover(id) {
    const t = this.#get(id), gd = this.gitdir(id);
    try {
      git.clearStaleLocks(gd);
      // (the seq never goes back: the larger of the log's last and the state's)
      const log = this.#readLog(id);
      if (log.length) t.seq = Math.max(t.seq, log[log.length - 1].seq);
      // (the grant must be the base commit's, which can't be edited)
      const msg = git.readCommit(gd, t.base).message;
      if (!msg.includes(GRANT_LINE + grantText(t.grant) + "\n")) return this.#fail(id, "its grant doesn't match the one recorded at its start");
      const i = t.intent;
      if (i) {
        const now = i.ref ? git.readRef(gd, i.ref) : null;
        if (!i.ref || now === i.next) this.#finish(id);
        else if (now === i.expect) { t.intent = null; this.#save(id); }
        else return this.#fail(id, `${i.ref} is neither what the interrupted operation expected nor what it wrote`);
      }
      // (a task that was working when the agent stopped: interrupted, and only a person's Resume goes on)
      if (t.status === "working") this.#transition(id, "interrupted", "the agent stopped while the task was working");
    } catch (e) {
      this.#fail(id, `it couldn't be recovered (${String(e?.message ?? e).slice(0, 200)})`);
    }
  }
  #fail(id, reason) {
    const t = this.#get(id);
    t.status = "failed";
    t.reason = reason;
    t.intent = null;
    try { this.#save(id); this.#emit(id, this.#append(id, [{ type: "task_status", status: "failed", reason }])); } catch {}
  }
  #broken(id, reason) {
    return { v: 1, task: id, title: "(unreadable task)", prompt: "", target: "local", status: "failed", reason, grant: { docs: [], run: false, scope: "", created: 0, revoked: true }, base: "0".repeat(40), proposals: [], mines: [], merged: null, seq: 0, ledger: {}, intent: null, created: 0, updated: 0, broken: true };
  }
  /** A status change with no ref: its intent names the event, so a crash between the log and task.json is finished. */
  #transition(id, status, reason, extra = {}) {
    const t = this.#get(id);
    const ev = { type: "task_status", status, ...(reason ? { reason } : {}) };
    return this.#commitIntent(id, { id: randomBytes(16).toString("hex"), events: [ev], set: { status, ...(reason ? { reason } : { reason: undefined }), ...extra } });
  }

  // ======================================================================== the protocol's requests (§6.1)
  /** tasks.start: the documents copied into a new task's work/, its base commit (with the frozen grant), its state. */
  start(p) {
    if (this.tasks.size >= this.budget.tasks) throw new TaskError("busy", `at most ${this.budget.tasks} tasks are kept`);
    const total = p.docs.reduce((n, d) => n + d.bytes.length, 0);
    const used = [...this.tasks.values()].reduce((n, x) => n + (x.bytes ?? 0), 0);
    if (used + total + this.budget.reserve > this.budget.total) throw new TaskError("busy", "the tasks' storage budget is used up");
    const id = randomBytes(16).toString("hex"), dir = this.dir(id);
    mkdirSync(dir, { mode: 0o700 });
    try {
      git.initRepo(this.gitdir(id));
      mkdirSync(this.work(id), { mode: 0o700 });
      const files = new Map();
      for (const d of p.docs) {
        writeTaskFile(this.work(id), d.path, d.bytes);
        files.set(d.path, git.writeObject(this.gitdir(id), "blob", d.bytes));
      }
      const created = this.now();
      const grant = { docs: p.docs.map((d) => d.path).sort(), run: p.run, scope: this.scope, created, revoked: false };
      const tree = git.writeTree(this.gitdir(id), files);
      const base = git.writeCommit(this.gitdir(id), { tree, message: `Task: ${p.title}\n\n${p.prompt}\n\n${GRANT_LINE}${grantText(grant)}\n`, time: created / 1000 });
      git.casRef(this.gitdir(id), "refs/heads/base", null, base);
      writeTaskFile(dir, "reserve", Buffer.alloc(this.budget.reserve));
      const t = { v: 1, task: id, title: p.title, prompt: p.prompt, target: "local", status: "working", grant, base, proposals: [], mines: [], merged: null, seq: 0, ledger: {}, intent: null, created, updated: created, bytes: 0 };
      this.tasks.set(id, t);
      // (task.json last: until it exists the task was never started, and a restart removes the folder)
      this.#save(id);
      const entries = this.#append(id, [{ type: "task_status", status: "working" }]);
      t.bytes = this.#bytes(id);
      this.#save(id);
      this.#emit(id, entries);
      return { task: id, base, seq: t.seq };
    } catch (e) {
      this.tasks.delete(id);
      rmSync(dir, { recursive: true, force: true });
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
    const reset = after > t.seq;
    const all = this.#readLog(task).filter((e) => reset || e.seq > after);
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
      const size = [...files.values()].reduce((n, f) => n + f.size, 0);
      if (size > this.budget.work) throw new TaskError("too_large", "the working copy is over its budget");
      this.#reserve(task, size);
      const gd = this.gitdir(task), map = new Map();
      for (const p of files.keys()) map.set(p, git.writeObject(gd, "blob", readTaskFile(this.work(task), p, LIMITS.doc)));
      const prev = t.proposals.at(-1) ?? null, round = t.proposals.length + 1;
      const commit = git.writeCommit(gd, { tree: git.writeTree(gd, map), parents: [prev ?? t.base], message: `Proposal, round ${round}\n\n${summary}\n`, time: this.now() / 1000 });
      const changes = this.#changesWith(t, map);
      return this.#commitIntent(task, {
        id: randomBytes(16).toString("hex"), ref: "refs/heads/proposal", expect: prev, next: commit,
        tags: [{ ref: `refs/tags/round-${round}`, next: commit }],
        events: [{ type: "proposal", round, base: t.base, commit, files: changes }, { type: "task_status", status: "proposal" }],
        set: { status: "proposal", proposals: [...t.proposals, commit] },
      });
    });
  }
  #changesWith(t, now) {
    const base = git.readTree(this.gitdir(t.task), git.readCommit(this.gitdir(t.task), t.base).tree), files = [];
    for (const p of [...new Set([...base.keys(), ...now.keys()])].sort()) {
      const a = base.get(p) ?? null, b = now.get(p) ?? null;
      if (a !== b) files.push({ path: p, kind: /\.ipynb$/.test(p) ? "notebook" : "file", change: a === null ? "added" : b === null ? "deleted" : "modified", base_blob: a, blob: b });
    }
    return files;
  }

  /** tasks.merged: what the page merged, recorded (never written to the workspace). */
  merged(p) {
    return this.#serial(p.task, () => {
      const t = this.#get(p.task);
      // (an identical retry after a lost answer gets the same answer; the same merge_id with another payload is a conflict)
      const hash = sha256(canonical({ ...p, files: p.files.map((f) => ({ ...f })) }));
      const prior = t.ledger[p.merge_id];
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
        const files = p.files.map((f) => ({ path: f.path, proposal_blob: f.proposal_blob, mine: f.mine?.absent ? "absent" : f.mine?.blob ?? "not sent", merged: f.merged?.absent ? "absent" : f.merged?.blob ?? "not sent" }));
        // (the receipt is kept in the control state, not sent as an event: §6.1's events are task_status and proposal)
        return this.#commitIntent(p.task, { id, events: [{ type: "task_status", status: "merged" }], set: { status: "merged", receipt: { proposal: p.proposal, merge_id: p.merge_id, files } }, ledger: { merge_id: p.merge_id, hash, answer } }) && answer;
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
      this.#commitIntent(p.task, { id, ref: "refs/heads/merged", expect: null, next: merge, tags: [{ ref: `refs/heads/mine-${n}`, next: mine }], events: [{ type: "task_status", status: "merged" }], set: { status: "merged", merged: merge, mines: [...t.mines, mine] }, ledger: { merge_id: p.merge_id, hash, answer } });
      return answer;
    });
  }

  /** tasks.close: nothing changes; final. */
  close(p) {
    return this.#serial(p.task, () => {
      const t = this.#get(p.task);
      if (FINAL.has(t.status)) throw new TaskError("final", `the task is ${t.status}`);
      if (p.seq !== t.seq || (p.proposal ?? null) !== (t.proposals.at(-1) ?? null)) throw new TaskError("stale", "the task has moved on");
      this.#transition(p.task, "closed", "closed by the person", { grant: { ...t.grant } });
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
      this.#commitIntent(p.task, { id: randomBytes(16).toString("hex"), ref: `refs/heads/mine-${n}`, expect: null, next: mine, events: [{ type: "task_status", status: "working" }], set: { status: "working", mines: [...t.mines, mine] } });
      return { status: "working", round: t.proposals.length };
    });
  }
  /** tasks.stop: a working task interrupted (its turn and run are the caller's to stop). */
  stop({ task }) {
    return this.#serial(task, () => {
      const t = this.#get(task);
      if (FINAL.has(t.status)) throw new TaskError("final", `the task is ${t.status}`);
      if (t.status === "working") this.#transition(task, "interrupted", "stopped by the person");
      return { status: this.#get(task).status };
    });
  }
  /** tasks.revoke: closed for good, its grant void. */
  revoke({ task }) {
    return this.#serial(task, () => {
      const t = this.#get(task);
      if (FINAL.has(t.status)) throw new TaskError("final", `the task is ${t.status}`);
      this.#transition(task, "closed", "revoked by the person", { grant: { ...t.grant, revoked: true } });
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
      this.#transition(task, "working");
      return { status: "working" };
    });
  }
  /** tasks.answer: questions come in M2. */
  answer() { throw new TaskError("unavailable", "questions come in a later version"); }

  /** For tests and the turns (A2): a task's state, read only. */
  state(id) { return structuredClone(this.#get(id)); }
}
