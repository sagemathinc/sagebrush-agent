// Fleet protocol, the browser lane (O11 draft 5 §2, §4.1, §4.4, §8.1): the driver of one browser session. It runs in
// the app's browser sidecar, between the CDP pipe (macapp's `cdp`: send, on, closed, close, pid) and the agent (a sink
// the sidecar connects to its channel), with the Filter (./filter.mjs) in the middle:
//
// - start(): the agent's own browser context, hardened by macapp's hook, then auto-attach to every target, each held
//   until it's hardened (waitForDebuggerOnStart). A target whose hardening fails is closed (a worker's page is
//   closed; a worker with no page retires the session). Only the agent context's pages are shown to the agent;
//   out-of-process iframes and workers are hardened but never exposed (v1). A page the agent didn't open is shown only
//   if its URL is http(s) or about:blank, and only up to the page limit; otherwise it's closed.
// - command(): the Filter's answer, or the command sent on the page's real session. Commands with the spec's
//   deadline get 30 s: then "timed out", Runtime.terminateExecution on that page, its object group released, and its
//   late answer never used.
// - takeover() (§8.1): pause, revoke; wait 2 s for commands in flight; terminate script on the pages that still have
//   one and wait up to 3 s more; what's still pending is abandoned (outcome unknown); release every agent object
//   group with its own session. If terminate fails or doesn't answer within those 3 s, the session retires.
// - Every second, the Filter's timed ends (console objects released).
// - The session retires (the sink is told why, and Chrome is closed) when the Filter retires, the browser context
//   can't be hardened, or the pipe closes.
//
// Every CDP event goes first to macapp's privileged hook (proxy authentication, Fetch), then, for an exposed page,
// through the Filter. Timers come from `clock`, so the tests drive them.

import { LIMITS } from "./filter.mjs";

export const DRAIN = Object.freeze({ waitMs: 2000, terminateMs: 3000, tickMs: 1000, attachMs: 30000, closeMs: 5000 });
const AUTO_ATTACH = Object.freeze({ autoAttach: true, waitForDebuggerOnStart: true, flatten: true });
const REAL_CLOCK = Object.freeze({ setTimeout: (f, ms) => setTimeout(f, ms), clearTimeout: (h) => clearTimeout(h) });

const timedOut = () => ({ error: { code: -32000, message: "timed out" } });
const ABANDONED = Symbol("abandoned"); // (a command the takeover's drain gave up on: its outcome is unknown)
const openable = (url) => url === "" || url === "about:blank" || /^https?:\/\//i.test(url);

export class BrowserSession {
  #cdp; #filter; #harden; #privileged; #sink; #clock;
  #context = undefined; // the agent's browser context id
  #targets = new Map(); // real sessionId -> { targetId, type, page (its page's real sessionId, or null), exposed }
  #exposed = 0;
  #inflight = new Map(); // a marker that settles with the command -> { sessionId (its real session), abandon() }
  #waiting = new Map(); // targetId -> [resolve] for createTarget calls waiting for their page
  #state = "new"; // new, running, paused, retired
  #tick = null;
  #unsubscribe = null;

  /**
   * `cdp`: macapp's pipe client. `filter`: a Filter for this session. `hooks.harden({ cdp, kind, sessionId?,
   * targetInfo?, browserContextId? })`: O11 §2's table, rejects on any failed step. `hooks.privileged(ev)`: sees every
   * event first. `sink.event(ev)` gets what the agent may see; `sink.retired(reason)` once, when the session ends.
   */
  constructor({ cdp, filter, hooks, sink, clock = REAL_CLOCK }) {
    this.#cdp = cdp; this.#filter = filter; this.#harden = hooks.harden; this.#privileged = hooks.privileged;
    this.#sink = sink; this.#clock = clock;
  }

  get state() { return this.#state; }
  /** For tests: how many commands are in flight. */
  get inflight() { return this.#inflight.size; }
  /** For tests: how many createTarget calls are waiting for their page. */
  get waitingTargets() { let n = 0; for (const l of this.#waiting.values()) n += l.length; return n; }

  /** Create and harden the agent's context and start attaching. Resolves true, or false if the session retired. */
  async start() {
    this.#unsubscribe = this.#cdp.on((ev) => this.#onEvent(ev));
    this.#cdp.closed.then((c) => this.#retire(`the browser closed (${c?.reason ?? "unknown"})`), () => this.#retire("the browser closed"));
    try {
      const { browserContextId } = await this.#cdp.send("Target.createBrowserContext", { disposeOnDetach: true });
      this.#context = browserContextId;
      await this.#harden({ cdp: this.#cdp, kind: "browser_context", browserContextId });
      await this.#cdp.send("Target.setDiscoverTargets", { discover: true });
      await this.#cdp.send("Target.setAutoAttach", AUTO_ATTACH);
    } catch {
      this.#retire("the browser context couldn't be set up and hardened");
      return false;
    }
    if (this.#state === "retired") return false;
    this.#state = "running";
    this.#scheduleTick();
    return true;
  }

  // ---- the agent ----

  /** An agent command. Resolves { result }, { error } or { unknown: true } (the outcome can't be known). */
  async command(cmd) {
    if (this.#state === "new") return { error: { code: -32000, message: "session not started" } };
    if (this.#state === "retired") return { error: { code: -32000, message: "session retired" } }; // (whatever retired it)
    const r = this.#filter.command(cmd);
    this.#checkFilter();
    if (r.error || r.result) return r;
    return r.app ? this.#app(r) : this.#send(r);
  }

  async #send({ send, token, deadlineMs }) {
    const sent = this.#track(this.#cdp.send(send.method, send.params, send.sessionId), send.sessionId);
    const out = await this.#race(sent.wait, deadlineMs);
    if (!out.ok && out.error === ABANDONED) return { unknown: true };
    if (out.timeout) {
      sent.forget();
      this.#cdp.send("Runtime.terminateExecution", {}, send.sessionId).catch(() => {});
      const group = this.#filter.abandoned(token);
      if (group) this.#cdp.send("Runtime.releaseObjectGroup", { objectGroup: group.objectGroup }, group.sessionId).catch(() => {});
      return this.#state === "running" ? timedOut() : { unknown: true };
    }
    return this.#answer(token, out);
  }

  #answer(token, out) {
    if (!out.ok && !isCdpError(out.error)) { this.#retire("the browser closed"); return { unknown: true }; }
    const r = out.ok ? this.#filter.result(token, out.value) : this.#filter.failed(token);
    this.#checkFilter();
    return r.discard ? { unknown: true } : r;
  }

  async #app({ app, token }) {
    if (app.op === "createTarget") {
      // (one 30 s bound over both the answer and the page's attach, hardening and showing)
      let targetId, live = true; // (live: the command hasn't been answered yet; a late CDP answer registers nothing)
      const created = (async () => {
        const v = await this.#cdp.send("Target.createTarget", { url: app.url, browserContextId: this.#context, background: app.background });
        targetId = v?.targetId;
        if (live && this.#state !== "retired" && !this.#isExposed(targetId)) await new Promise((resolve) => this.#waiting.set(targetId, [...(this.#waiting.get(targetId) ?? []), resolve]));
        return { targetId };
      })();
      const op = this.#track(created, undefined);
      const out = await this.#race(op.wait, DRAIN.attachMs);
      live = false;
      if (out.timeout) { op.forget(); if (targetId !== undefined) this.#waiting.delete(targetId); this.#filter.failed(token); return timedOut(); }
      if (!out.ok && out.error === ABANDONED) return { unknown: true };
      return this.#answer(token, out);
    }
    const method = app.op === "activateTarget" ? "Target.activateTarget" : "Target.closeTarget";
    const op = this.#track(this.#cdp.send(method, { targetId: app.targetId }), undefined);
    const out = await this.#race(op.wait, DRAIN.attachMs);
    if (out.timeout) { op.forget(); this.#filter.failed(token); return timedOut(); }
    if (!out.ok && out.error === ABANDONED) return { unknown: true };
    return this.#answer(token, out);
  }

  #isExposed(targetId) {
    for (const t of this.#targets.values()) if (t.exposed && t.targetId === targetId) return true;
    return false;
  }

  // Track a command until it settles or is given up. Returns { wait, forget }: `wait` is the promise to wait on (the
  // command's, or one that rejects with ABANDONED when the takeover's drain or retirement gives up on it); `forget()`
  // gives it up now, as every timeout does: it leaves the in-flight set at once, and its late answer is never used.
  #track(promise, sessionId) {
    let abandon;
    const cut = new Promise((_, reject) => { abandon = () => reject(ABANDONED); });
    cut.catch(() => {});
    const marker = promise.then(() => {}, () => {});
    this.#inflight.set(marker, { sessionId, abandon });
    marker.then(() => this.#inflight.delete(marker));
    const forget = () => { if (this.#inflight.delete(marker)) abandon(); };
    return { wait: Promise.race([promise, cut]), forget };
  }

  #abandonAll() {
    for (const [marker, e] of this.#inflight) { this.#inflight.delete(marker); e.abandon(); }
  }

  // ---- takeover and handback (§8.1, §8.3) ----

  /** Pause the agent. Resolves { paused: true }, or { retired: true } if the browser didn't stop in time. */
  async takeover() {
    if (this.#state !== "running") return this.#state === "paused" ? { paused: true } : { retired: true };
    this.#state = "paused";
    const t = this.#filter.takeover();
    let pending = [...this.#inflight];
    if (pending.length) {
      await this.#race(Promise.all(pending.map(([m]) => m)), DRAIN.waitMs);
      pending = [...this.#inflight];
    }
    if (pending.length) {
      const busy = [...new Set(pending.map(([, e]) => e.sessionId).filter((s) => typeof s === "string"))];
      const terminated = Promise.all(busy.map((s) => this.#cdp.send("Runtime.terminateExecution", {}, s)));
      const drained = this.#race(Promise.all(pending.map(([m]) => m)), DRAIN.terminateMs); // (the same 3 s window for both)
      const stopped = await this.#race(terminated, DRAIN.terminateMs);
      if (stopped.timeout || !stopped.ok) { this.#retire("takeover: the browser didn't stop the agent's script in time"); return { retired: true }; }
      await drained;
    }
    this.#abandonAll(); // (what's still pending is abandoned: its outcome is unknown, and a later takeover won't wait for it)
    if (this.#state === "retired") return { retired: true };
    for (const g of t.releaseGroups) this.#cdp.send("Runtime.releaseObjectGroup", { objectGroup: g.objectGroup }, g.sessionId).catch(() => {});
    return { paused: true };
  }

  /** Give the browser back to the agent: its pages come back with new handles. */
  handback() {
    if (this.#state !== "paused") return false;
    this.#state = "running";
    for (const ev of this.#filter.handback()) this.#sink.event(ev);
    this.#checkFilter();
    return this.#state === "running";
  }

  // ---- CDP events ----

  #onEvent(ev) {
    if (this.#state === "retired") return;
    try { this.#privileged?.(ev); } catch { /* (macapp's hook handles its own failures) */ }
    const m = ev.method, p = ev.params ?? {};
    if (m === "Target.attachedToTarget") { this.#attached(ev.sessionId, p).catch(() => this.#retire("attaching a target failed")); return; }
    if (m === "Target.detachedFromTarget") { this.#detached(p.sessionId); return; }
    if (m === "Target.targetInfoChanged") {
      for (const [s, t] of this.#targets) if (t.exposed && t.targetId === p.targetInfo?.targetId) this.#filter.pageInfo(s, p.targetInfo);
      return;
    }
    if (typeof ev.sessionId !== "string" || !this.#targets.get(ev.sessionId)?.exposed) return; // (the browser's own, a worker's, an iframe's: never the agent's)
    const out = this.#filter.event(ev.sessionId, m, p);
    if (out) this.#sink.event(out);
    this.#checkFilter();
  }

  async #attached(parent, p) {
    const { sessionId, targetInfo: info } = p;
    if (typeof sessionId !== "string" || !info) return;
    const page = info.type === "page" ? sessionId : this.#targets.get(parent)?.page ?? null;
    const t = { targetId: info.targetId, type: info.type, page, exposed: false };
    this.#targets.set(sessionId, t);
    try {
      await this.#harden({ cdp: this.#cdp, kind: info.type, sessionId, targetInfo: info });
      if (info.type === "page" || info.type === "iframe") await this.#cdp.send("Target.setAutoAttach", AUTO_ATTACH, sessionId);
    } catch {
      await this.#closeFailed(t);
      return;
    }
    if (this.#state === "retired" || !this.#targets.has(sessionId)) return;
    if (info.type === "page" && info.browserContextId === this.#context) {
      const url = info.url ?? "";
      if (!openable(url) || this.#exposed >= LIMITS.pages) { await this.#closeOrRetire(info.targetId, "a page the agent may not see couldn't be closed"); return; }
      t.exposed = true;
      this.#exposed++;
      const ev = this.#filter.pageAttached({ targetId: info.targetId, sessionId, url: url || "about:blank", title: info.title ?? "" });
      if (ev) this.#sink.event(ev);
      this.#checkFilter();
      for (const resolve of this.#waiting.get(info.targetId) ?? []) resolve();
      this.#waiting.delete(info.targetId);
    }
    await this.#cdp.send("Runtime.runIfWaitingForDebugger", {}, sessionId).catch(() => {});
  }

  // A target whose hardening failed: closed, or its page closed; a worker with no page ends the session.
  async #closeFailed(t) {
    const pageTarget = t.type === "page" || t.type === "iframe" ? t.targetId : this.#targets.get(t.page)?.targetId;
    if (pageTarget === undefined) { this.#retire("a target without a page couldn't be hardened"); return; }
    await this.#closeOrRetire(pageTarget, "a target that couldn't be hardened couldn't be closed");
  }

  // Close a target for safety. Only CDP's { success: true } within DRAIN.closeMs counts; anything else (a refusal,
  // success false, silence) retires the session: a target that must not run is never left to run.
  async #closeOrRetire(targetId, why) {
    const out = await this.#race(this.#cdp.send("Target.closeTarget", { targetId }), DRAIN.closeMs);
    if (!(out.ok && out.value?.success === true)) this.#retire(why);
  }

  #detached(sessionId) {
    const t = this.#targets.get(sessionId);
    if (!t) return;
    this.#targets.delete(sessionId);
    if (t.exposed) {
      this.#exposed--;
      const ev = this.#filter.pageDetached(sessionId);
      if (ev) this.#sink.event(ev);
    }
  }

  // ---- time, retirement ----

  #scheduleTick() {
    this.#tick = this.#clock.setTimeout(() => {
      if (this.#state === "retired") return;
      for (const r of this.#filter.expire()) this.#cdp.send("Runtime.releaseObject", { objectId: r.objectId }, r.sessionId).catch(() => {});
      this.#scheduleTick();
    }, DRAIN.tickMs);
  }

  #checkFilter() { if (this.#filter.retired) this.#retire("the session's handle or object-group budget is spent"); }

  #retire(reason) {
    if (this.#state === "retired") return;
    this.#state = "retired";
    if (this.#tick !== null) this.#clock.clearTimeout(this.#tick);
    this.#unsubscribe?.();
    this.#waiting.clear();
    this.#abandonAll();
    this.#sink.retired(reason);
    this.#cdp.close().catch(() => {});
  }

  // A promise's outcome within `ms` (no bound if ms is undefined): { ok, value }, { ok: false, error } or { timeout }.
  #race(promise, ms) {
    return new Promise((resolve) => {
      let done = false;
      const h = ms === undefined ? null : this.#clock.setTimeout(() => { if (!done) { done = true; resolve({ timeout: true }); } }, ms);
      const end = (r) => { if (!done) { done = true; if (h !== null) this.#clock.clearTimeout(h); resolve(r); } };
      promise.then((value) => end({ ok: true, value }), (error) => end({ ok: false, error }));
    });
  }
}

// macapp's CdpError carries a numeric CDP code; anything else (CdpClosed) means the pipe is gone.
function isCdpError(e) { return e !== null && typeof e === "object" && typeof e.code === "number"; }
