// A Delegate task's turns (pair-delegate plan r3.4 §2.2; the protocol: design/workspace-agent-protocol.md §6): Claude
// working on the task's own copy, with no page at all.  A turn belongs to its task, not to a page or a pairing: its
// tools act on the task's work/ folder only, through the task store (tasks.mjs), and it makes no page call, so the
// page can come and go while it runs.  The turn ends when Claude proposes (the store's propose, which commits the copy
// as the next round), or it is interrupted, with its reason, when it ends without one.
//
// The SDK runs with no setting sources, no native tools (no Bash, Read, Edit, Write, WebFetch or WebSearch), no MCP
// server but the task's own, no hooks, in the task's own sdk/ folder, every tool call through one callback that admits
// only the task's tools.  Running code is not offered yet: notebook_run refuses, saying so (the runner, A3, stays off
// until its review clears it).
//
// Limits: at most 4 turns running at once (more wait, at most 16), each at most 24 hours.

import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { z } from "zod";
import { Turn } from "./turns.mjs";
import { notebookDoc } from "./notebook.mjs";
import { readTaskFile, scanTree } from "./task-paths.mjs";
import { LIMITS, TaskError } from "./tasks-schema.mjs";

export const TASK_SERVER = "sagebrush_task";
const PREFIX = `mcp__${TASK_SERVER}__`;
export const TURN_LIMITS = Object.freeze({ running: 4, queued: 16, turnMs: 24 * 60 * 60 * 1000, readBytes: 256 * 1024, stopMs: 10000 });
const KERNEL = {
  python: { name: "python3", display_name: "Python 3", language: "python" },
  sage: { name: "sagemath", display_name: "SageMath", language: "sage" },
  magma: { name: "magma", display_name: "Magma", language: "magma" },
  matlab: { name: "matlab", display_name: "MATLAB", language: "matlab" },
};

export const TASK_SYSTEM = `You are Claude, working on a task the person delegated to you in Sagebrush, a workspace for mathematics. You work on your own copy of the task's documents: nothing you do changes the person's own files. Use the workspace tools to read and change your copy (paths are relative to it, like "notes/a.md" or "analysis.ipynb"). Running code isn't available for delegated tasks yet: check your work by reading it. When you are done, call propose with a short summary of what you changed and why; the person then reviews the difference and merges it, closes it, or asks for changes. Don't call propose until the copy is the way you want it.`;

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

export class TaskTurns {
  /** `store`: the TaskStore; `query` and `createServer`: the SDK's (or the tests' fakes, as the agent server takes them). */
  constructor({ store, query, createServer, log = () => {}, limits = TURN_LIMITS }) {
    this.store = store;
    this.query = query;
    this.createServer = createServer;
    this.log = log;
    this.limits = limits;
    this.running = new Map(); // task -> {abort, done}
    this.waiting = []; // [{task, kind}]
  }

  /** Start a turn for a working task (`kind`: "start", "ask" or "resume"), now or when a place frees; refused `busy` past the queue. */
  begin(task, kind) {
    if (this.running.has(task) || this.waiting.some((w) => w.task === task)) return { queued: false, already: true };
    if (this.running.size >= this.limits.running) {
      if (this.waiting.length >= this.limits.queued) throw new TaskError("busy", `at most ${this.limits.running} tasks run at once, and ${this.limits.queued} wait`);
      this.waiting.push({ task, kind });
      return { queued: true };
    }
    this.#run(task, kind);
    return { queued: false };
  }
  /** Stop a task's turn (running or waiting); resolves when it has stopped. */
  async stop(task) {
    this.waiting = this.waiting.filter((w) => w.task !== task);
    const r = this.running.get(task);
    if (!r) return;
    r.abort.abort();
    // (bounded: a model that doesn't heed the abort can't hold a Stop or the switch's turning off; the caller then
    //  records the task's stop, and the turn's own end, if it ever comes, finds the task no longer working)
    let t;
    await Promise.race([r.done, new Promise((res) => { t = setTimeout(res, this.limits.stopMs ?? 10000); })]);
    clearTimeout(t);
  }
  /** Stop every turn (the agent stopping, or the Delegate switch turned off). */
  async stopAll() {
    this.waiting = [];
    await Promise.all([...this.running.keys()].map((t) => this.stop(t)));
  }
  isRunning(task) { return this.running.has(task); }

  #next() {
    while (this.running.size < this.limits.running && this.waiting.length) {
      const w = this.waiting.shift();
      if (this.store.state(w.task).status === "working") this.#run(w.task, w.kind);
    }
  }

  #run(task, kind) {
    const abort = new AbortController();
    const entry = { abort, done: null };
    this.running.set(task, entry);
    entry.done = this.#turn(task, kind, abort).catch((e) => this.log(`a task's turn failed: ${e?.message ?? e}`)).finally(() => {
      this.running.delete(task);
      queueMicrotask(() => this.#next());
    });
  }

  #prompt(task, kind) {
    const t = this.store.state(task);
    const files = [...scanTree(this.store.work(task)).files.keys()].sort();
    const head = `Task: ${t.title}\n\n${t.prompt}\n\nYour copy holds: ${files.join(", ") || "(nothing)"}.`;
    if (kind === "resume") return `${head}\n\nYou were interrupted while working on this task; your copy is as you left it. Look at it, then carry on.`;
    if (kind === "ask") return `${head}\n\nThe person reviewed your proposal (round ${t.proposals.length}) and asked for changes. Your copy still holds what you proposed. Make the changes they ask for, then propose again.`;
    return head;
  }

  // The task's tools: its copy only, through the store.
  #tools(task, proposed) {
    const store = this.store, work = store.work(task);
    const call = async (f) => { try { return await f(); } catch (e) { return refusal(e instanceof TaskError ? e.message : String(e?.message ?? e)); } };
    const path = z.string().max(1024).describe("A path in your copy, like notes/a.md or analysis.ipynb");
    return [
      ["workspace_list", "List the files of your copy of the task's documents.", { folder: z.string().max(1024).optional() }, (a) => call(async () => {
        const f = rel(a.folder ?? "");
        const all = [...scanTree(work).files].filter(([p]) => !f || p === f || p.startsWith(f.replace(/\/$/, "") + "/"));
        return text(JSON.stringify(all.map(([p, x]) => ({ path: p, size: x.size }))));
      })],
      ["workspace_read", "Read one file of your copy (text; a notebook as its .ipynb JSON). Long files are cut, said so.", { path }, (a) => call(async () => {
        const bytes = readTaskFile(work, rel(a.path), LIMITS.doc);
        const t = bytes.toString("utf8");
        const cut = Buffer.byteLength(t) > this.limits.readBytes;
        return text(cut ? `${Buffer.from(t).subarray(0, this.limits.readBytes).toString("utf8")}\n[cut: the file is ${bytes.length} bytes; ${this.limits.readBytes} shown]` : t);
      })],
      ["workspace_write", "Write one text file of your copy, whole (it is created if it isn't there).", { path, text: z.string().max(LIMITS.doc) }, (a) => call(async () => {
        if (/\.ipynb$/i.test(rel(a.path))) {
          try { const j = JSON.parse(a.text); if (!j || !Array.isArray(j.cells)) throw 0; } catch { return refusal("a notebook is written as its .ipynb JSON, or with workspace_write_notebook"); }
        }
        await store.writeWork(task, rel(a.path), Buffer.from(a.text, "utf8"));
        return text(`wrote ${rel(a.path)}`);
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
      ["notebook_run", "Run a notebook of your copy.", { path }, async () => refusal("running code isn't available for delegated tasks yet; check your work by reading it")],
      ["propose", "Propose your copy to the person: they see the difference from what you started with, and merge it, close it, or ask for changes. Call it once, when you are done.", { summary: z.string().max(LIMITS.prompt) }, (a) => call(async () => {
        if (proposed.done) return refusal("you already proposed in this turn");
        await store.propose(task, { summary: a.summary });
        proposed.done = true;
        return text("proposed: the person will review it");
      })],
    ];
  }

  async #turn(task, kind, abort) {
    const store = this.store;
    const turn = new Turn(`task-${randomBytes(6).toString("hex")}`);
    const send = async (drafts) => { if (drafts.length) await store.record(task, drafts); };
    const proposed = { done: false };
    const deadline = setTimeout(() => abort.abort(), this.limits.turnMs);
    const sdkDir = join(store.dir(task), "sdk");
    mkdirSync(sdkDir, { recursive: true, mode: 0o700 });
    try {
      await send(turn.start());
      const server = this.createServer({ name: TASK_SERVER, version: "1", tools: this.#tools(task, proposed) });
      const q = this.query({
        prompt: this.#prompt(task, kind),
        options: {
          includePartialMessages: true,
          cwd: sdkDir,
          mcpServers: { [TASK_SERVER]: server },
          systemPrompt: TASK_SYSTEM,
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
      for await (const m of q) {
        if (abort.signal.aborted) break;
        if (store.state(task).status !== "working") break; // (proposed, or stopped: the turn's work is over)
        await send(turn.feed(m));
      }
      if (store.state(task).status === "working") await send(abort.signal.aborted ? turn.interrupted() : turn.finished ? [] : turn.failed("the agent stopped without a result"));
    } catch (e) {
      if (store.state(task).status === "working") await send(abort.signal.aborted ? turn.interrupted() : turn.failed(e?.message ?? e)).catch(() => {});
    } finally {
      clearTimeout(deadline);
      // (a turn that ended without a proposal leaves the task interrupted, with why; only the person's Resume goes on)
      if (store.state(task).status === "working") {
        const why = abort.signal.aborted ? "the turn was stopped" : "the agent's turn ended without a proposal";
        await store.interrupt(task, why).catch(() => {});
      }
    }
  }
}
