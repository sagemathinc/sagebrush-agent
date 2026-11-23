// A Delegate task's turns (pair-delegate plan r3.4 §2.2; the protocol: design/workspace-agent-protocol.md §6): Claude
// working on the task's own copy, with no page at all.  A turn belongs to its task, not to a page or a pairing: its
// tools act on the task's work/ folder only, through the task store (tasks.mjs), and it makes no page call, so the
// page can come and go while it runs.  The turn ends when Claude proposes (the store's propose, which commits the copy
// as the next round), or it is interrupted, with its reason, when it ends without one.
//
// The SDK runs with no setting sources, no native tools (no Bash, Read, Edit, Write, WebFetch or WebSearch), no MCP
// server but the task's own, no hooks, in the task's own sdk/ folder, every tool call through one callback that admits
// only the task's tools.  notebook_run goes to the task runner (task-runner.mjs), which refuses, saying why, wherever
// runs can't be had (in this version, everywhere: they stay off until their review clears them).  A turn's tool calls
// run one at a time, so nothing touches the copy while a run's process group is alive, and a turn ends only once its
// run has exited and, if the host cut it off, been undone.
//
// Limits: at most 4 turns running at once (more wait, at most 16), each at most 24 hours.  The SDK's transcript (under
// ~/.claude/projects, in the folder named after the task's sdk/) is the one thing a turn writes that the store doesn't:
// while a turn runs, it, the task's whole use and the disk's free space are checked every 500 ms, and a turn past a
// bound is interrupted then, with why (best effort: what is written between two checks can pass the bound).

import { mkdirSync, statfsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { z } from "zod";
import { Turn } from "./turns.mjs";
import { conformTurnEvent } from "./turn-bounds.mjs";
import { turnInfo } from "./turn-info.mjs";
import { notebookDoc } from "./notebook.mjs";
import { ipynbDoc, notebookRead } from "./notebook-read.mjs";
import { editIpynb } from "./task-notebook-edit.mjs";
import { readTaskFile, scanTree } from "./task-paths.mjs";
import { LIMITS, TaskError } from "./tasks-schema.mjs";

export const TASK_SERVER = "sagebrush_task";
// (the summary of a round proposed for a turn that completed with changes but didn't call propose, #1621)
export const AUTO_SUMMARY = "Proposed automatically: Claude's turn ended with changes in the copy but without calling propose.";
const PREFIX = `mcp__${TASK_SERVER}__`;
const MiB = 1024 * 1024;
const HALT = Symbol("halt");
export const TURN_LIMITS = Object.freeze({ running: 4, queued: 16, turnMs: 24 * 60 * 60 * 1000, readBytes: 256 * 1024, stopMs: 10000, transcript: 64 * MiB, transcriptEntries: 20000, headroom: 64 * MiB, pollMs: 500 });
/** Where Claude Code keeps its transcripts: `projects` in its config folder (CLAUDE_CONFIG_DIR, else ~/.claude). */
export const claudeProjects = (env = process.env) => join(env.CLAUDE_CONFIG_DIR || join(homedir(), ".claude"), "projects");
// (the free bytes of the filesystem holding `dir`, as an unprivileged writer sees them)
const freeBytes = (dir) => { const f = statfsSync(dir); return f.bavail * f.bsize; };
const KERNEL = {
  python: { name: "python3", display_name: "Python 3", language: "python" },
  sage: { name: "sagemath", display_name: "SageMath", language: "sage" },
  magma: { name: "magma", display_name: "Magma", language: "magma" },
  matlab: { name: "matlab", display_name: "MATLAB", language: "matlab" },
};

// (the task's system prompt; `runs`: whether notebook_run can run code for this task, on this computer)
export const taskSystem = (runs) => `You are Claude, working on a task the person delegated to you in Sagebrush, a workspace for mathematics. You work on your own copy of the task's documents: nothing you do changes the person's own files. Use the workspace tools to read and change your copy (paths are relative to it, like "notes/a.md" or "analysis.ipynb"). ${runs ? "You can run a notebook of your copy with notebook_run to check your work: its code reads and writes only your copy, with no network. " : "Running code isn't available for this task: check your work by reading it. "}When you are done, call propose with a short summary of what you changed and why; the person then reviews the difference and merges it, closes it, or asks for changes. Don't call propose until the copy is the way you want it.`;

const text = (t) => ({ content: [{ type: "text", text: t }] });
const refusal = (t) => ({ content: [{ type: "text", text: `refused: ${t}` }], isError: true });
const rel = (p) => (typeof p === "string" ? p.replace(/^\/+/, "") : p);

/** A notebook written by the tool, as an .ipynb file (nbformat 4.5, Sagebrush's own cell ids). */
export function notebookIpynb(doc) {
  return JSON.stringify({
    cells: doc.cells.map((c) => (c.type === "markdown" ? { cell_type: "markdown", id: c.id, metadata: {}, source: c.code } : { cell_type: "code", id: c.id, metadata: {}, source: c.code, outputs: [], execution_count: null })),
    metadata: { kernelspec: KERNEL[doc.mode] ?? KERNEL.python, language_info: { name: (KERNEL[doc.mode] ?? KERNEL.python).language } },
    nbformat: 4,
    nbformat_minor: 5,
  }, null, 1);
}

/** A run's report as the model reads it: each code cell's status, time, output text and error, cut to `max` bytes in
 * all (said so). */
export function runSummary({ exit, report }, max) {
  const cells = (report?.cells ?? []).map((c) => ({ n: c.n, id: c.id, status: c.status, ...(c.ms !== undefined ? { ms: c.ms } : {}), ...(c.stdout ? { stdout: c.stdout } : {}), ...(c.stderr ? { stderr: c.stderr } : {}), ...(c.error ? { error: c.error } : {}), ...(c.outputs?.length ? { outputs: c.outputs } : {}) }));
  const whole = JSON.stringify({ ok: report?.ok === true, exit, ...(report?.wrote ? { wrote: true } : {}), cells }, null, 1);
  return Buffer.byteLength(whole) <= max ? whole : `${Buffer.from(whole).subarray(0, max).toString("utf8")}\n[cut: the report is ${Buffer.byteLength(whole)} bytes; ${max} shown. The outputs are in the notebook: read it.]`;
}

export class TaskTurns {
  /** `store`: the TaskStore; `query` and `createServer`: the SDK's (or the tests' fakes, as the agent server takes them). */
  constructor({ store, query, createServer, log = () => {}, limits = TURN_LIMITS, free = freeBytes, runner = null }) {
    this.store = store;
    this.runner = runner; // (a TaskRunner, or null: then notebook_run refuses)
    this.free = free;
    this.query = query;
    this.createServer = createServer;
    this.log = log;
    this.limits = { ...TURN_LIMITS, ...limits };
    this.running = new Map(); // task -> {abort, done, then}
    this.waiting = []; // [{task, kind}]
    this.reserved = 0; // (places held for requests between their check and their begin)
  }

  /** Why a turn for this task can't start for lack of disk, or null: the filesystem must have the task's remaining
   * budget plus the headroom free. */
  diskProblem(task) {
    const used = this.store.usage(task);
    if (used === null) return "the task's storage can't be measured";
    let free;
    try { free = this.free(this.store.root); } catch (e) { return `the free disk space can't be read (${e?.code ?? e?.message ?? e})`; }
    const need = Math.max(0, this.store.budget.task - used) + this.limits.headroom;
    return free < need ? `not enough free disk space for this task (${Math.ceil(need / MiB)} MB needed, ${Math.floor(free / MiB)} MB free)` : null;
  }
  /** Refused `busy` when a turn for this task couldn't start now for lack of disk (before a start, Ask or Resume is
   * recorded). */
  admit(task) {
    const why = task ? this.diskProblem(task) : this.#freeProblem();
    if (why) throw new TaskError("busy", why);
  }
  #freeProblem() {
    let free;
    try { free = this.free(this.store.root); } catch (e) { return `the free disk space can't be read (${e?.code ?? e?.message ?? e})`; }
    const need = this.store.budget.task + this.limits.headroom;
    return free < need ? `not enough free disk space for a task (${Math.ceil(need / MiB)} MB needed, ${Math.floor(free / MiB)} MB free)` : null;
  }
  /** What is over a bound while this task's turn runs, or null: its transcript, its whole use, the disk's headroom. */
  #breach(task) {
    // (the copy and the run's folder too, within the same entry bound: past it, or unreadable, a breach)
    const trees = this.store.runTreesProblem(task, this.limits.transcriptEntries);
    if (trees) return trees;
    const tr = this.store.transcriptBytes(task, this.limits.transcriptEntries);
    if (tr === null) return "its transcript can't be measured (a link there, or too many files)";
    if (tr > this.limits.transcript) return `its transcript passed ${Math.round(this.limits.transcript / MiB)} MB`;
    const used = this.store.usage(task);
    if (used === null) return "the task's storage can't be measured";
    if (used > this.store.budget.task) return "the task's storage budget is used up";
    let free;
    try { free = this.free(this.store.root); } catch { free = 0; }
    if (free < this.limits.headroom) return "the disk is almost full";
    return null;
  }

  /** A place for one more turn, held from before a request records anything until its begin (or its release):
   * refused `busy`, with nothing changed, when the running and waiting places are all taken.  A task whose turn is
   * still running holds its own place already. */
  reserve(task = null) {
    if (task && this.running.has(task)) return { release() {} };
    if (this.running.size + this.waiting.length + this.reserved >= this.limits.running + this.limits.queued) throw new TaskError("busy", `at most ${this.limits.running} tasks run at once, and ${this.limits.queued} wait`);
    this.reserved++;
    let held = true;
    return { release: () => { if (held) { held = false; this.reserved--; } } };
  }

  /** Start a turn for a working task (`kind`: "start", "ask" or "resume"), now or when a place frees; refused `busy` past
   * the queue.  `slot`: a place reserve() held for it, given back here.  `note`: a Resume's message from the person,
   * for that turn's prompt only (it waits with the turn, in memory). */
  begin(task, kind, slot = null, { note = null } = {}) {
    slot?.release();
    // (a turn still ending (it proposed, and is finishing its records): the new one follows it, in its place)
    const r = this.running.get(task);
    if (r) { if (!r.then) { r.then = kind; r.thenNote = note; } return { queued: true }; }
    if (this.waiting.some((w) => w.task === task)) return { queued: false, already: true };
    if (this.running.size >= this.limits.running) {
      if (this.waiting.length >= this.limits.queued) throw new TaskError("busy", `at most ${this.limits.running} tasks run at once, and ${this.limits.queued} wait`);
      this.waiting.push({ task, kind, note });
      return { queued: true };
    }
    this.#run(task, kind, note);
    return { queued: false };
  }
  /** Stop a task's turn (running or waiting); resolves when it has stopped. */
  async stop(task, cause = null) {
    this.waiting = this.waiting.filter((w) => w.task !== task);
    const r = this.running.get(task);
    if (!r) return;
    r.then = null;
    // (why it stops, for the task's record: { reason, code } (REASON_CODES); else "the turn was stopped", stopped)
    r.cause ??= cause;
    r.abort.abort();
    // (bounded: a model that doesn't heed the abort can't hold a Stop or the switch's turning off; the caller then
    //  records the task's stop, and the turn's own end, if it ever comes, finds the task no longer working)
    let t;
    await Promise.race([r.done, new Promise((res) => { t = setTimeout(res, this.limits.stopMs ?? 10000); })]);
    clearTimeout(t);
  }
  /** Stop every turn (the agent stopping, or the Delegate switch turned off). */
  async stopAll(cause = null) {
    this.waiting = [];
    await Promise.all([...this.running.keys()].map((t) => this.stop(t, cause)));
  }
  isRunning(task) { return this.running.has(task); }

  #next() {
    while (this.running.size < this.limits.running && this.waiting.length) {
      const w = this.waiting.shift();
      if (this.store.state(w.task).status === "working") this.#run(w.task, w.kind, w.note);
    }
  }

  #run(task, kind, note = null) {
    const abort = new AbortController();
    // (each turn its own entry, and only the entry still current for its task records or changes the task's state: a
    //  turn that was stopped can't touch the task's next turn)
    const entry = { abort, done: null, then: null, thenNote: null, note, runs: new Set() };
    this.running.set(task, entry);
    entry.done = this.#turn(task, kind, entry).catch((e) => this.log(`a task's turn failed: ${e?.message ?? e}`)).finally(() => {
      this.running.delete(task);
      if (entry.then && this.store.state(task).status === "working") return this.#run(task, entry.then, entry.thenNote);
      queueMicrotask(() => this.#next());
    });
  }

  #prompt(task, kind, note = null) {
    const t = this.store.state(task);
    const files = [...scanTree(this.store.work(task)).files.keys()].sort();
    const head = `Task: ${t.title}\n\n${t.prompt}\n\nYour copy holds: ${files.join(", ") || "(nothing)"}.`;
    // (the person's request, exactly as they wrote it, between two marker lines it can't forge: a fresh random tag)
    const ask = kind === "ask" || (kind === "resume" && t.mines.length > 0 && t.mines.length === t.proposals.length) ? this.store.lastAsk(task) : null;
    const request = () => {
      const tag = randomBytes(8).toString("hex");
      const theirs = ask.paths.length ? `\n\nWith their request they sent their own current versions of: ${ask.paths.join(", ")}. Those are recorded with the request, not in your copy; when they merge, the page combines your proposal with their versions.` : "";
      return `The person reviewed your proposal (round ${t.proposals.length}) and asked for changes. Their request, exactly as they wrote it, is between the two marker lines:\n----- the person's request ${tag} -----\n${ask.note}\n----- end of the person's request ${tag} -----${theirs}\n\nYour copy still holds what you proposed.`;
    };
    if (kind === "ask") return `${head}\n\n${ask ? request() : `The person reviewed your proposal (round ${t.proposals.length}) and asked for changes. Your copy still holds what you proposed.`} Make the changes they ask for, then propose again.`;
    // (a Resume with the person's message: exactly as they wrote it, between marker lines of its own fresh tag)
    const told = () => {
      const tag = randomBytes(8).toString("hex");
      return `The person stopped you to tell you something. Their message, exactly as they wrote it, is between the two marker lines:\n----- the person's message ${tag} -----\n${note}\n----- end of the person's message ${tag} -----\n\nTake it into account as you carry on. Your copy is as you left it.`;
    };
    if (kind === "resume" && note !== null) return `${head}\n\n${ask ? `${request()}\n\n` : ""}${told()}`;
    if (kind === "resume") return `${head}\n\n${ask ? `${request()}\n\n` : ""}You were interrupted while working on this task; your copy is as you left it. Look at it, then carry on.`;
    return head;
  }

  // The task's tools: its copy only, through the store.
  #tools(task, proposed, entry) {
    const store = this.store, work = store.work(task), abort = entry.abort;
    // (one call at a time: the SDK may ask for several at once, and nothing may touch the copy while a run is alive;
    //  before each call: the turn not stopped, and the task still working, not stopped, revoked, closed or merged)
    let tail = Promise.resolve();
    const call = (f) => {
      const next = tail.then(async () => {
        if (abort.signal.aborted || store.state(task).status !== "working") return refusal("this task's turn is over");
        try { return await f(); } catch (e) { return refusal(e instanceof TaskError ? e.message : String(e?.message ?? e)); }
      });
      tail = next.catch(() => {});
      return next;
    };
    const path = z.string().max(1024).describe("A path in your copy, like notes/a.md or analysis.ipynb");
    return [
      ["workspace_list", "List the files of your copy of the task's documents.", { folder: z.string().max(1024).optional() }, (a) => call(async () => {
        const f = rel(a.folder ?? "");
        const all = [...scanTree(work).files].filter(([p]) => !f || p === f || p.startsWith(f.replace(/\/$/, "") + "/"));
        return text(JSON.stringify(all.map(([p, x]) => ({ path: p, size: x.size }))));
      })],
      ["workspace_read", "Read one file of your copy. A notebook is read as its cells with their outputs summarized (pictures never shown, text cut), up to about 48 KB; with cell: n, one cell's source and text outputs in full; with from: k, the cells from k on. Other files as text; a long one is cut, said so.", {
        path,
        cell: z.number().int().min(0).optional().describe("A notebook only: read this cell (0-based) in full"),
        from: z.number().int().min(0).optional().describe("A notebook only: read its cells from this one (0-based) on"),
      }, (a) => call(async () => {
        const p = rel(a.path);
        const nb = /\.ipynb$/i.test(p);
        if (!nb && (a.cell !== undefined || a.from !== undefined)) return refusal("cell and from are for notebooks (.ipynb) only");
        const bytes = readTaskFile(work, p, LIMITS.doc);
        const t = bytes.toString("utf8");
        // (a notebook: the shared read format, as Pair's; one that isn't a notebook's JSON is read as text)
        const doc = nb ? ipynbDoc(t) : null;
        if (doc) return text(notebookRead(doc, { path: a.path, cell: a.cell, from: a.from }));
        if (nb && (a.cell !== undefined || a.from !== undefined)) return refusal(`${p} isn't a notebook's JSON, so it has no cells to read`);
        const cut = Buffer.byteLength(t) > this.limits.readBytes;
        return text(cut ? `${Buffer.from(t).subarray(0, this.limits.readBytes).toString("utf8")}\n[cut: ${p} is ${bytes.length} bytes; a read returns at most ${this.limits.readBytes}, so only its start is shown]` : t);
      })],
      ["workspace_write", "Write one text file of your copy, whole (it is created if it isn't there).", { path, text: z.string().max(LIMITS.doc) }, (a) => call(async () => {
        if (/\.ipynb$/i.test(rel(a.path))) {
          try { const j = JSON.parse(a.text); if (!j || !Array.isArray(j.cells)) throw 0; } catch { return refusal("a notebook is written as its .ipynb JSON, or with workspace_write_notebook"); }
        }
        await store.writeWork(task, rel(a.path), Buffer.from(a.text, "utf8"));
        return text(`wrote ${rel(a.path)}`);
      })],
      ["workspace_edit_notebook", "Change a notebook of your copy by cell, keeping every other cell, its outputs and its id: set changes a cell's source or type (by its id), insert adds a cell after a cell id (null: first), remove deletes a cell. Read the notebook first with workspace_read for its cells' ids.", {
        path,
        set: z.array(z.object({ id: z.string(), source: z.string().optional(), type: z.enum(["code", "markdown"]).optional() }).strict()).max(200).optional(),
        insert: z.array(z.object({ source: z.string(), type: z.enum(["code", "markdown"]).optional(), after: z.string().nullable() }).strict()).max(200).optional(),
        remove: z.array(z.string()).max(200).optional(),
      }, (a) => call(async () => {
        const p = rel(a.path);
        if (!/\.ipynb$/i.test(p)) return refusal("a notebook's path ends in .ipynb");
        const r = editIpynb(readTaskFile(work, p, LIMITS.doc).toString("utf8"), { set: a.set, insert: a.insert, remove: a.remove });
        if (r instanceof Error) return refusal(`${p}: ${r.message}`);
        await store.writeWork(task, p, Buffer.from(r.text, "utf8"));
        const n = (x) => x?.length ?? 0;
        return text(`edited ${p}: ${n(a.set)} set, ${n(a.insert)} inserted${r.inserted.length ? ` (new ids: ${r.inserted.join(", ")})` : ""}, ${n(a.remove)} removed`);
      })],
      ["workspace_delete", "Delete a file of your copy, or a folder with everything in it: any, the documents the task started with included. The deletion is part of your proposal, which the person reviews.", { path }, (a) => call(async () => {
        const r = await store.deleteWork(task, rel(a.path));
        const k = (c, w) => `${c} ${w}${c === 1 ? "" : "s"}`;
        return text(r.folders ? `deleted ${rel(a.path)}: ${k(r.files, "file")}, ${k(r.folders, "folder")}` : `deleted ${rel(a.path)}`);
      })],
      ["workspace_write_notebook", "Write a Sagebrush notebook (an .ipynb file) of your copy, whole: its language and its cells, code and Markdown.", {
        path,
        mode: z.enum(["python", "sage", "matlab", "magma"]),
        cells: z.array(z.object({ type: z.enum(["code", "markdown"]), source: z.string() }).strict()),
      }, (a) => call(async () => {
        if (!/\.ipynb$/i.test(rel(a.path))) return refusal("a notebook's path ends in .ipynb");
        const doc = notebookDoc({ mode: a.mode, cells: a.cells });
        if (doc instanceof Error) return refusal(doc.message);
        await store.writeWork(task, rel(a.path), Buffer.from(notebookIpynb(doc), "utf8"));
        return text(`wrote ${rel(a.path)} (${doc.cells.length} cells)`);
      })],
      ["notebook_run", "Run every code cell of a notebook of your copy, with its outputs written into it. Code can read and write only your copy (and a scratch folder of its own); it has no network.", {
        path,
        timeout: z.number().int().min(1).max(3600).optional().describe("Seconds for all its cells together (default 300)"),
      }, (a) => call(async () => {
        const why = this.runner ? this.runner.problem(task) : "runs are turned off in this version";
        if (why) return refusal(`Running code isn't available for Delegate on this computer: ${why}. Check your work by reading it.`);
        // (the run's own admission: the same free space a turn needs, asked again before the run's tmp folder, zone
        //  data or process is made)
        const run = this.runner.run(task, rel(a.path), { ...(a.timeout ? { timeoutS: a.timeout } : {}), signal: abort.signal, admit: () => this.diskProblem(task) });
        entry.runs.add(run);
        try { return text(runSummary(await run, this.limits.readBytes)); } finally { entry.runs.delete(run); }
      })],
      ["propose", "Propose your copy to the person: they see the difference from what you started with, and merge it, close it, or ask for changes. Call it once, when you are done.", { summary: z.string().max(LIMITS.prompt) }, (a, extra) => call(async () => {
        if (proposed.done) return refusal("you already proposed in this turn");
        // (the proposal ends the turn: once the task isn't working nothing more of it is recorded, so this call's answer
        //  and the turn's end go into the log with the proposal, in the same step, before its events (#1610). The call
        //  is named by the id Claude Code passes the handler; the turn is marked ended only once the store took it)
        const answer = "proposed: the person will review it";
        const closing = proposed.turn.closing(extra?._meta?.["claudecode/toolUseId"], answer).flatMap((d) => conformTurnEvent(d, this.log));
        await store.propose(task, { summary: a.summary, events: closing });
        proposed.turn.end();
        proposed.done = true;
        return text(answer);
      })],
    ];
  }

  async #turn(task, kind, entry) {
    const store = this.store, abort = entry.abort;
    const current = () => this.running.get(task) === entry;
    const turn = new Turn(`task-${randomBytes(6).toString("hex")}`);
    // (each event made to fit the page's bounds first: what the host records, the page can show)
    const send = async (drafts) => { const events = drafts.flatMap((d) => conformTurnEvent(d, this.log)); if (events.length && current()) await store.record(task, events); };
    const proposed = { done: false, turn };
    // (whyCode: why's code (REASON_CODES); the turn's time bound is a limit of its own)
    let whyCode = null;
    const deadline = setTimeout(() => { if (!why) { why = "the turn reached its 24 hour limit"; whyCode = "limit"; } abort.abort(); }, this.limits.turnMs);
    const sdkDir = store.sdk(task);
    // (the watch: a bound passed mid-turn interrupts it, with why)
    let why = null, it = null, completed = false; // (completed: Claude's result said the turn succeeded)
    const halted = new Promise((r) => abort.signal.addEventListener("abort", () => r(HALT), { once: true }));
    const watch = setInterval(() => {
      if (why || abort.signal.aborted) return;
      try { why = this.#breach(task); if (why) whyCode = "limit"; } catch (e) { why = `the task's storage can't be checked (${e?.code ?? e?.message ?? e})`; whyCode = "failed"; }
      if (why) abort.abort();
    }, this.limits.pollMs);
    try {
      // (a turn that waited: the disk checked again as it starts; short, it doesn't start, and the task says why)
      why = this.diskProblem(task);
      if (why) { whyCode = "limit"; return; }
      // (sdk/ made here, not through a link: a link or anything but a private folder there, and the turn doesn't start)
      try { mkdirSync(sdkDir, { mode: 0o700 }); } catch (e) { if (e?.code !== "EEXIST") throw e; }
      why = store.sdkProblem(task) && `its sdk folder can't be used (${store.sdkProblem(task)})`;
      if (why) { whyCode = "failed"; return; }
      await send(turn.start());
      const server = this.createServer({ name: TASK_SERVER, version: "1", tools: this.#tools(task, proposed, entry) });
      const q = this.query({
        prompt: this.#prompt(task, kind, entry.note),
        options: {
          includePartialMessages: true,
          cwd: sdkDir,
          mcpServers: { [TASK_SERVER]: server },
          systemPrompt: taskSystem(!!this.runner && this.runner.problem(task) === null),
          settingSources: [],
          strictMcpConfig: true,
          tools: [],
          permissionMode: "default",
          settings: { permissions: { defaultMode: "default", disableAutoMode: "disable", disableBypassPermissionsMode: "disable" } },
          // (every call through here: the task's own tools pass, anything else is refused)
          canUseTool: async (name, input) => (typeof name === "string" && name.startsWith(PREFIX) ? { behavior: "allow", updatedInput: input } : { behavior: "deny", message: "only the task's own tools are available" }),
          persistSession: true,
          abortController: abort,
        },
      });
      // (each message raced against the turn's abort: a Stop, a breach or the time limit ends the turn here at once,
      //  whether or not the SDK heeds the abort; nothing it yields after that is taken or recorded)
      it = q[Symbol.asyncIterator]();
      // (W3, #1551: the model this turn runs, as Claude's init says it, once a turn, as a Pair turn says it; the thinking
      //  level Pair takes from a hook isn't said here: a task's turn runs no hooks)
      let inited = false;
      for (;;) {
        const next = it.next();
        next.catch(() => {});
        const m = await Promise.race([next, halted]);
        if (m === HALT || m.done || abort.signal.aborted) break;
        if (store.state(task).status !== "working") break; // (proposed, or stopped: the turn's work is over)
        if (!inited && m.value?.type === "system" && m.value?.subtype === "init") {
          inited = true;
          const info = turnInfo({ model: m.value.model });
          if (info) await send([info]);
        }
        const drafts = turn.feed(m.value);
        if (drafts.some((d) => d.type === "turn_finished" && d.outcome === "completed")) completed = true;
        await send(drafts);
      }
      if (store.state(task).status === "working") await send(abort.signal.aborted ? turn.interrupted() : turn.finished ? [] : turn.failed("the agent stopped without a result"));
    } catch (e) {
      if (store.state(task).status === "working") await send(abort.signal.aborted ? turn.interrupted() : turn.failed(e?.message ?? e)).catch(() => {});
    } finally {
      clearTimeout(deadline);
      // (a run still alive was killed by the same abort: its exit, and the undoing of its changes, waited for here, so
      //  nothing else touches the copy before that; the watch keeps measuring meanwhile)
      if (entry.runs.size) await Promise.allSettled([...entry.runs]);
      clearInterval(watch);
      // (a turn that completed with changes in the copy but no propose call: its copy proposed for it, saying so
      //  (#1621); one the store refuses, or any other end without a proposal, leaves the task interrupted, with why;
      //  only the person's Resume goes on)
      let unproposed = null;
      if (current() && store.state(task).status === "working" && completed && !why && !abort.signal.aborted) {
        try {
          if (store.workChanged(task)) await store.propose(task, { summary: AUTO_SUMMARY });
        } catch (e) { unproposed = `the agent's turn ended without a proposal, and its changes can't be proposed (${e?.message ?? e})`; }
      }
      if (current() && store.state(task).status === "working") {
        // (why, with its code: a bound or a failure found by the turn; a stop with its cause (the person's Stop,
        //  the Delegate switch, the agent stopping); changes the store refused; a completed turn with nothing to propose;
        //  else the turn ended in an error)
        const end = why ? [why, whyCode ?? "failed"]
          : abort.signal.aborted ? [entry.cause?.reason ?? "the turn was stopped", entry.cause?.code ?? "stopped"]
          : unproposed ? [unproposed, "unproposable"]
          : completed ? ["the agent's turn ended without a proposal", "no_proposal"]
          : ["the agent's turn ended with an error, without a proposal", "failed"];
        await store.interrupt(task, end[0], end[1]).catch(() => {});
      }
      // (then the SDK's query closed, on every way out: a proposal, an end, an error, a Stop or a breach; after an
      //  abort, that ends Claude Code's process (stdin closed, then killed after a grace period); waited for at most
      //  the stop bound, and only then is the turn's place freed)
      if (it) {
        let t;
        await Promise.race([Promise.resolve().then(() => it.return?.()).catch(() => {}), new Promise((r) => { t = setTimeout(r, this.limits.stopMs); })]);
        clearTimeout(t);
      }
    }
  }
}
