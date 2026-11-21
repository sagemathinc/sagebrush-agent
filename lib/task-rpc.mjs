// The Delegate requests on the pairing (design/workspace-agent-protocol.md §6.1, `delegate.1`): each checked closed
// (tasks-schema.mjs), then answered by the task store and the task's turns.  The agent server (server.mjs) admits a
// request only from the paired page whose grant holds `delegate: true`, over the loopback only, at most 8 at once,
// each frame at most 4 MiB; this module is what a request does once admitted.

import { checkRequest, LIMITS, TaskError } from "./tasks-schema.mjs";

/** The id a page's request carries: "p" and a decimal counter. */
export const REQUEST_ID = /^p[0-9]{1,16}$/;

export class TaskRpc {
  /** `store`: the TaskStore; `turns`: its TaskTurns. */
  constructor({ store, turns }) {
    this.store = store;
    this.turns = turns;
    this.offs = 0; // (the switch's turnings off: a request recorded across one starts no turn)
  }

  /** One request's result (the method's checked params, then the store and turns), or a TaskError. */
  async call(method, params) {
    const p = checkRequest(method, params);
    const { store, turns } = this;
    switch (method) {
      // (start, Ask and Resume begin a turn: refused `busy`, with nothing recorded, when the disk is short)
      case "tasks.start": return this.#withPlace(null, () => store.start(p), (r) => r.task, "start");
      case "tasks.list": return store.list();
      case "tasks.get": return store.get(p);
      case "tasks.diff": return store.diff(p);
      case "tasks.file": return store.file(p);
      case "tasks.merged": return store.merged(p);
      case "tasks.close": await turns.stop(p.task); return store.close(p);
      case "tasks.ask": return this.#withPlace(p.task, () => store.ask(p), () => p.task, "ask");
      case "tasks.stop": await turns.stop(p.task); return store.stop(p);
      case "tasks.revoke": await turns.stop(p.task); return store.revoke(p);
      case "tasks.resume": return this.#withPlace(p.task, () => store.resume(p), () => p.task, "resume");
      case "tasks.answer": return store.answer(p);
    }
    throw new TaskError("bad_request", "not a tasks method");
  }

  // Start, Ask and Resume: the disk and a turn's place checked, and the place held, before anything is recorded; refused
  // `busy` with nothing changed.  The place goes to the new turn, or back if the store refuses.
  async #withPlace(task, record, taskOf, kind) {
    this.turns.admit(task);
    const slot = this.turns.reserve(task), offs = this.offs;
    try {
      const r = await record();
      // (the switch turned off while this was being recorded: no turn; its task interrupted like the others)
      if (this.offs !== offs) { await this.store.interrupt(taskOf(r), "the Delegate switch was turned off").catch(() => {}); return r; }
      this.turns.begin(taskOf(r), kind, slot);
      return r;
    } finally {
      slot.release();
    }
  }

  /** The Delegate switch turned off (the pairing's grant lost `delegate`, or the pairing was revoked): every running
   * or waiting turn stopped, and their tasks interrupted, not closed. */
  async switchedOff() {
    this.offs++;
    await this.turns.stopAll();
    for (const t of this.store.list().tasks) if (t.status === "working") await this.store.interrupt(t.task, "the Delegate switch was turned off").catch(() => {});
  }
}

/** A request frame's answer frame: `{jsonrpc, id, result}` or a refusal `{jsonrpc, id, error: {code: -32000, message, data: {code}}}`. */
export const answer = (id, result) => ({ jsonrpc: "2.0", id, result });
export const refusal = (id, code, message) => ({ jsonrpc: "2.0", id, error: { code: -32000, message, data: { code } } });
export { LIMITS };
