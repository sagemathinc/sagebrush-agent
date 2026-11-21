// A stand-in Delegate host for the page's tests (the Agents page's task rows): the protocol's JSON-RPC requests
// (design/workspace-agent-protocol.md §6.1) answered by a REAL task store in a folder of the test's, and a scripted
// agent in place of Claude: after a start, or an Ask for changes, it edits the task's copy (by default: one Markdown
// cell appended to each notebook, one line to each text file) and proposes it.  Requests and answers are exactly the
// agent's own; only the turns are scripted.
//
//   const host = await fakeTasks({ root });            // root: an empty folder the test owns
//   host.onNotify((msg) => ...)                        // {jsonrpc, method: "task.event", params: {task, seq, event}}
//   const answer = await host.handle(frame)            // a request frame (string or object) -> its answer frame
//   await host.settled()                               // every scripted turn so far finished
//
// Options: `script(task, files) -> files | Promise` (files: Map path -> Buffer, the copy before; return the copy
// after, or null to propose nothing), `delayMs` before each scripted turn (0), `scope` ("fake-installation").

import { TaskStore } from "./tasks.mjs";
import { checkRequest, LIMITS, METHODS, TaskError } from "./tasks-schema.mjs";
import { readTaskFile, scanTree, writeTaskFile, removeTaskFile } from "./task-paths.mjs";

/** The default script: a Markdown cell appended to each notebook, a line to each text file. */
export function defaultScript(_task, files) {
  const out = new Map(files);
  for (const [path, bytes] of files) {
    if (path.endsWith(".ipynb")) {
      const nb = JSON.parse(bytes.toString("utf8"));
      nb.cells.push({ cell_type: "markdown", id: `fake${nb.cells.length}`, metadata: {}, source: "Proposed by the stand-in agent." });
      out.set(path, Buffer.from(JSON.stringify(nb, null, 1), "utf8"));
    } else out.set(path, Buffer.concat([bytes, Buffer.from("# proposed by the stand-in agent\n")]));
  }
  return out;
}

export async function fakeTasks({ root, script = defaultScript, delayMs = 0, scope = "fake-installation" } = {}) {
  const store = new TaskStore({ root, scope }).init();
  const listeners = new Set();
  store.onEvent((e) => { for (const f of listeners) f({ jsonrpc: "2.0", method: "task.event", params: e }); });
  const turns = new Set();
  const enc = new TextEncoder();

  // (a scripted turn: the copy read, the script's edit written, then proposed)
  function turn(task) {
    const p = (async () => {
      if (delayMs) await new Promise((r) => setTimeout(r, delayMs));
      if (store.state(task).status !== "working") return;
      const work = store.work(task), before = new Map();
      for (const path of scanTree(work).files.keys()) before.set(path, readTaskFile(work, path, LIMITS.doc));
      const after = await script(task, before);
      if (!after) return;
      for (const [path, bytes] of after) if (!before.get(path)?.equals(bytes)) writeTaskFile(work, path, bytes);
      for (const path of before.keys()) if (!after.has(path)) removeTaskFile(work, path);
      if (store.state(task).status === "working") await store.propose(task, { summary: "the stand-in agent's change" });
    })().catch(() => {}).finally(() => turns.delete(p));
    turns.add(p);
  }

  const CALL = {
    "tasks.start": (p) => { const r = store.start(p); turn(r.task); return r; },
    "tasks.list": () => store.list(),
    "tasks.get": (p) => store.get(p),
    "tasks.diff": (p) => store.diff(p),
    "tasks.file": (p) => store.file(p),
    "tasks.merged": (p) => store.merged(p),
    "tasks.close": (p) => store.close(p),
    "tasks.ask": async (p) => { const r = await store.ask(p); turn(p.task); return r; },
    "tasks.stop": (p) => store.stop(p),
    "tasks.revoke": (p) => store.revoke(p),
    "tasks.resume": async (p) => { const r = await store.resume(p); turn(p.task); return r; },
    "tasks.answer": (p) => store.answer(p),
  };
  const refusal = (id, code, message) => ({ jsonrpc: "2.0", id, error: { code: -32000, message, data: { code } } });

  /** One request frame (its raw text, or the parsed object) -> its answer frame. */
  async function handle(frame) {
    let msg = frame;
    if (typeof frame === "string") {
      if (enc.encode(frame).length > LIMITS.frame) return refusal(null, "too_large", `a tasks request is at most ${LIMITS.frame} bytes`);
      try { msg = JSON.parse(frame); } catch { return refusal(null, "bad_request", "not JSON"); }
    }
    const id = msg && typeof msg.id === "string" && /^p[0-9]{1,16}$/.test(msg.id) ? msg.id : null;
    if (!msg || msg.jsonrpc !== "2.0" || id === null || typeof msg.method !== "string") return refusal(id, "bad_request", "not a tasks request");
    if (!METHODS.includes(msg.method)) return refusal(id, "bad_request", "not a tasks method");
    try {
      const result = await CALL[msg.method](checkRequest(msg.method, msg.params));
      const answer = { jsonrpc: "2.0", id, result };
      if (enc.encode(JSON.stringify(answer)).length > LIMITS.frame) return refusal(id, "too_large", "the answer would be over the frame bound");
      return answer;
    } catch (e) {
      if (e instanceof TaskError) return refusal(id, e.code, e.message);
      return refusal(id, "bad_request", String(e?.message ?? e).slice(0, 300));
    }
  }
  return {
    store,
    handle,
    onNotify: (f) => (listeners.add(f), () => listeners.delete(f)),
    settled: async () => { while (turns.size) await Promise.all([...turns]); },
  };
}
