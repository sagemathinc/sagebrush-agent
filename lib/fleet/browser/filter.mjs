// Fleet protocol, the browser lane (O11 draft 5 §4, §6 layer 3, §8.1 steps 1-4): the CDP filter for one agent session.
// It holds no sockets and no timers: the app gives it what the agent sent and what CDP said, and does what it returns.
//
// - command(): an agent command is refused (a CDP error), sent to CDP on the page's real session with real ids, or
//   handed to the app (the virtual Target methods). Paused (takeover) and retired sessions refuse everything.
// - result() / failed(): CDP's answer, rewritten in the page's scope (its real CDP session id) and capped; a value that
//   can't be rewritten, or is over its cap, is never forwarded, and is answered with an error instead.
// - event(): every raw event from an agent page. It ends handles by CDP's own rules (navigation, document updates,
//   destroyed contexts, finished requests), and forwards only the allowed events, redacted, rewritten and capped.
// - pageAttached() / pageDetached(): the agent's pages, as the app attaches and loses them.
// - takeover() / handback() / expire(): §8.1's pause and revoke, the re-exposure with new handles, and the timed ends
//   (request handles 120 s after their load ends, console objects after 60 s).
//
// When the session's handle budget is spent the filter retires: it answers everything with "session retired", and the
// app ends the session. Nothing partly rewritten is ever returned.

import { FleetError } from "../index.mjs";
import { Vids } from "./vids.mjs";
import { rewrite } from "./rewrite.mjs";
import { realParams } from "./params.mjs";
import { checkUrl } from "./urls.mjs";

export const LIMITS = Object.freeze({ pages: 16, deadlineMs: 30000, requestMs: 120000, consoleMs: 60000, titleBytes: 1024, groups: 256 });
export const GROUP_PREFIX = "agent-"; // (the agent's object groups, prefixed so they never collide with the app's)

const err = (code, message) => ({ error: { code, message } });
const E = {
  unknown: () => err(-32601, "method not allowed"),
  params: () => err(-32602, "invalid parameters"),
  scheme: () => err(-32602, "only http, https and about:blank can be opened"),
  stale: () => err(-32000, "stale handle"),
  paused: () => err(-32000, "paused: takeover"),
  retired: () => err(-32000, "session retired"),
  tooLarge: () => err(-32000, "result too large"),
  unmappable: () => err(-32000, "result can't be shown to the agent"),
  pages: () => err(-32000, "too many pages"),
  account: (origin) => err(-32000, `blocked: account site (${origin})`),
  browser: () => err(-32000, "the browser refused the command"),
};
const REDACT = (spec) => new Set(spec.redaction.headers.map((h) => h.toLowerCase()));
const bytes = (v) => Buffer.byteLength(JSON.stringify(v), "utf8");

export class Filter {
  #spec; #program; #commands; #origins; #vids; #now; #redact;
  #pages = new Map(); // real CDP sessionId -> { targetId, url, title, vid }
  #pending = 0; // createTarget calls the app hasn't finished
  #groups = new Map(); // real CDP sessionId -> Set of real object groups there (at most LIMITS.groups in all; past it the session retires)
  #objects = new Map(); // `${scope}\0${real objectId}` -> { group, cx }: cx the real context, or null if unknown
  #frames = new Map(); // scope -> { main: real frameId, defaults: Map(real frameId -> real default context id) }
  #timed = []; // { kind, real, scope, at, release }
  #paused = false;
  #retired = false;
  #gen = 0; // takeovers so far: a token from an earlier one is never answered

  /** `commands` from compileCommands(spec); `program` from loadProgram(); `origins` from accountOrigins(). */
  constructor({ spec, program, commands, origins, vids = new Vids(), now = () => Date.now() }) {
    this.#spec = spec; this.#program = program; this.#commands = commands; this.#origins = origins;
    this.#vids = vids; this.#now = now; this.#redact = REDACT(spec);
  }

  get paused() { return this.#paused; }
  get retired() { return this.#retired; }

  // Anything the handles refuse: a stale or foreign one is the agent's error; a spent budget retires the session.
  #handleError(e) {
    if (!(e instanceof FleetError)) throw e;
    if (e.code === "handle_budget") { this.#retired = true; return E.retired(); }
    if (e.code === "stale_handle" || e.code === "bad_scope") return E.stale();
    if (e.code === "bad_params") return E.params();
    if (e.code === "unmappable" || e.code === "unknown_owner") return E.unmappable();
    throw e;
  }

  // A group a command will create objects in. Returns undefined (and retires the session) past LIMITS.groups.
  // Groups belong to a page's runtime: the same name in two pages is two groups, each released on its own.
  #useGroup(scope, name) {
    const g = GROUP_PREFIX + (name ?? "default");
    let here = this.#groups.get(scope);
    if (!here?.has(g)) {
      let n = 0;
      for (const set of this.#groups.values()) n += set.size;
      if (n >= LIMITS.groups) { this.#retired = true; return undefined; }
      if (!here) this.#groups.set(scope, (here = new Set()));
      here.add(g);
    }
    return g;
  }

  #frame(scope) {
    let f = this.#frames.get(scope);
    if (!f) this.#frames.set(scope, (f = { main: undefined, defaults: new Map() }));
    return f;
  }

  // The context an object will live in: the one named, the object's own, the main frame's default world, or null.
  #mainContext(scope) {
    const f = this.#frames.get(scope);
    return f?.main !== undefined ? f.defaults.get(f.main) ?? null : null;
  }

  // End the object handles in `scope` that `pred(entry)` selects.
  #endObjects(scope, pred) {
    const ended = new Set();
    for (const [key, o] of this.#objects) {
      const at = key.indexOf("\0");
      if (key.slice(0, at) === scope && pred(o)) { ended.add(key.slice(at + 1)); this.#objects.delete(key); }
    }
    if (ended.size) this.#vids.revoke((k, r, s) => k === "ob" && s === scope && ended.has(r));
  }

  // The vids a rewrite mints, recorded: the same Vids, seen through out() (rewrite also reads `spent`).
  #recorder(minted) {
    const vids = this.#vids;
    return { out: (k, r, s) => { const v = vids.out(k, r, s); if (k === "ob") minted.push(r); return v; }, get spent() { return vids.spent; } };
  }

  #track(scope, reals, group, cx) {
    for (const r of reals) this.#objects.set(`${scope}\0${r}`, { group, cx });
  }

  // ---- the agent's pages ----

  /** The app attached to one of the agent's pages. Returns the Target.targetCreated event to forward, or null. */
  pageAttached({ targetId, sessionId, url = "", title = "" }) {
    if (this.#retired) return null;
    let vid;
    try { vid = this.#vids.out("pg", targetId); } catch (e) { this.#handleError(e); return null; }
    const page = { targetId, url, title, vid };
    this.#pages.set(sessionId, page);
    if (this.#pending > 0) this.#pending--;
    return this.#paused ? null : { method: "Target.targetCreated", params: { targetInfo: this.#info(page) } };
  }

  /** The page's URL or title changed (from the app's own target events). Nothing is forwarded. */
  pageInfo(sessionId, { url, title }) {
    const p = this.#pages.get(sessionId);
    if (p) { if (typeof url === "string") p.url = url; if (typeof title === "string") p.title = title; }
  }

  /** The page closed or detached. Its handles end; returns the Target.targetDestroyed event to forward, or null. */
  pageDetached(sessionId) {
    const p = this.#pages.get(sessionId);
    if (!p) return null;
    this.#pages.delete(sessionId);
    this.#vids.revoke((kind, real, scope) => scope === sessionId || (kind === "pg" && real === p.targetId));
    this.#timed = this.#timed.filter((t) => t.scope !== sessionId);
    for (const key of this.#objects.keys()) if (key.startsWith(`${sessionId}\0`)) this.#objects.delete(key);
    this.#frames.delete(sessionId);
    this.#groups.delete(sessionId); // (its runtime is gone with it)
    return this.#paused || this.#retired ? null : { method: "Target.targetDestroyed", params: { targetId: p.vid } };
  }

  #info(p) {
    let title = p.title;
    while (Buffer.byteLength(title, "utf8") > LIMITS.titleBytes) title = title.slice(0, -1);
    return { targetId: p.vid, type: "page", url: p.url, title };
  }

  #pageByVid(vid) {
    let targetId;
    try { targetId = this.#vids.in("pg", vid); } catch (e) { return { error: this.#handleError(e) }; }
    for (const [sessionId, p] of this.#pages) if (p.targetId === targetId) return { sessionId, page: p };
    return { error: E.stale() };
  }

  // ---- commands ----

  /**
   * The agent's command: { method, params, sessionId } (sessionId: the page's vid, absent for Target methods).
   * Returns { error }, { send: { sessionId, method, params }, token, deadlineMs? }, { app: { op, ... }, token } or
   * { result } (answered here).
   */
  command({ method, params = {}, sessionId }) {
    if (this.#retired) return E.retired();
    if (this.#paused) return E.paused();
    const cmd = Object.hasOwn(this.#commands, method) ? this.#commands[method] : undefined;
    if (!cmd) return E.unknown();
    if (cmd.virtual) return this.#virtual(method, cmd, params, sessionId);
    if (typeof sessionId !== "string") return E.params();
    const at = this.#pageByVid(sessionId);
    if (at.error) return at.error;
    let real, urls;
    try { ({ params: real, urls } = realParams(cmd, params, this.#vids, at.sessionId)); } catch (e) { return this.#handleError(e); }
    for (const [holder, key] of urls) {
      const u = checkUrl(holder[key], this.#origins);
      if (!u.ok) return u.why === "account" ? E.account(u.origin) : E.scheme();
      holder[key] = u.url;
    }
    const scope = at.sessionId, token = { method, scope, gen: this.#gen };
    if (method === "Runtime.evaluate" || method === "Runtime.callFunctionOn" || method === "DOM.resolveNode") {
      const g = this.#useGroup(scope, real.objectGroup);
      if (g === undefined) return E.retired();
      real.objectGroup = token.group = g;
      const parent = typeof real.objectId === "string" ? this.#objects.get(`${scope}\0${real.objectId}`) : undefined;
      token.cx = real.contextId ?? real.executionContextId ?? (parent ? parent.cx : method === "Runtime.evaluate" ? this.#mainContext(scope) : null);
    } else if (method === "Runtime.getProperties") {
      const parent = this.#objects.get(`${scope}\0${real.objectId}`);
      token.group = parent?.group ?? null; token.cx = parent ? parent.cx : null; // (its objects join the parent's group)
    } else if (method === "Runtime.releaseObjectGroup") token.releasedGroup = real.objectGroup = GROUP_PREFIX + real.objectGroup;
    else if (method === "Runtime.releaseObject") token.released = real.objectId;
    if (method === "Runtime.evaluate") real.timeout = real.timeout ?? LIMITS.deadlineMs;
    return { send: { sessionId: at.sessionId, method, params: real }, token, ...(cmd.deadline ? { deadlineMs: LIMITS.deadlineMs } : {}) };
  }

  #virtual(method, cmd, params, sessionId) {
    if (sessionId !== undefined) return E.params();
    try { cmd.validate(params); } catch (e) { if (e instanceof FleetError && e.code === "bad_form") return E.params(); throw e; }
    if (method === "Target.getTargets") return this.#cap(method, { targetInfos: [...this.#pages.values()].map((p) => this.#info(p)) });
    if (method === "Target.createTarget") {
      if (this.#pages.size + this.#pending >= LIMITS.pages) return E.pages();
      const u = checkUrl(params.url, this.#origins);
      if (!u.ok) return u.why === "account" ? E.account(u.origin) : E.scheme();
      this.#pending++;
      return { app: { op: "createTarget", url: u.url, background: params.background === true }, token: { method, gen: this.#gen } };
    }
    const at = this.#pageByVid(params.targetId);
    if (at.error) return at.error;
    return { app: { op: method === "Target.activateTarget" ? "activateTarget" : "closeTarget", targetId: at.page.targetId }, token: { method, gen: this.#gen } };
  }

  #cap(method, value) {
    return bytes(value) > this.#commands[method].maxBytes ? E.tooLarge() : { result: value };
  }

  /**
   * CDP's (or, for the virtual methods, the app's) result for `token`. Returns { result } or { error }, or
   * { discard: true } for a command a takeover abandoned (its late answer is never forwarded; its outcome is unknown).
   */
  result(token, raw) {
    if (token.gen !== this.#gen || this.#paused) return { discard: true };
    if (this.#retired) return E.retired();
    const { method } = token;
    if (method === "Target.createTarget") {
      for (const p of this.#pages.values()) if (p.targetId === raw?.targetId) return this.#cap(method, { targetId: p.vid });
      if (this.#pending > 0) this.#pending--;
      return E.browser();
    }
    if (method === "Target.activateTarget") return { result: {} };
    if (method === "Target.closeTarget") return { result: { success: raw?.success === true } };
    const scope = token.scope;
    if (method === "Accessibility.getFullAXTree" || method === "Accessibility.getPartialAXTree") this.#vids.revoke((k, r, s) => k === "ax" && s === scope); // (a new tree replaces the old one)
    if (method === "DOM.getDocument") this.#vids.revoke((k, r, s) => k === "nd" && s === scope); // (CDP's rule: a new document, new node ids)
    if (method === "Page.getFrameTree" && typeof raw?.frameTree?.frame?.id === "string") this.#frame(scope).main = raw.frameTree.frame.id;
    const minted = [];
    let value;
    try { value = rewrite(this.#program, `${method} result`, structuredClone(raw ?? {}), this.#recorder(minted), scope); } catch (e) { return this.#handleError(e); }
    this.#track(scope, minted, token.group ?? null, token.cx ?? null);
    if (Object.hasOwn(token, "released")) this.#releaseOne(scope, token.released);
    if (Object.hasOwn(token, "releasedGroup")) { this.#endObjects(scope, (o) => o.group === token.releasedGroup); this.#groups.get(scope)?.delete(token.releasedGroup); }
    return this.#cap(method, value);
  }

  #releaseOne(scope, real) {
    this.#objects.delete(`${scope}\0${real}`);
    this.#vids.revoke((k, r, s) => k === "ob" && s === scope && r === real);
  }

  /** CDP refused the command for `token`. Its message isn't forwarded (it might carry a real id). */
  failed(token) {
    if (token.gen !== this.#gen || this.#paused) return { discard: true };
    if (this.#retired) return E.retired();
    if (token.method === "Target.createTarget" && this.#pending > 0) this.#pending--;
    return E.browser();
  }

  // ---- events ----

  /** A raw event from the agent page whose real CDP session is `sessionId`. Returns { method, params, sessionId } to forward, or null. */
  event(sessionId, method, params) {
    const page = this.#pages.get(sessionId);
    if (!page || this.#retired) return null;
    this.#lifetimes(sessionId, method, params);
    if (this.#paused) return null;
    const ev = Object.hasOwn(this.#spec.events, method) ? this.#spec.events[method] : undefined;
    if (!ev || ev.virtual) return null; // (not allowed; Target events are the filter's own)
    let value = structuredClone(params ?? {});
    if (ev.redactHeaders) this.#redactNetwork(value);
    const minted = [];
    try { value = rewrite(this.#program, `${method} event`, value, this.#recorder(minted), sessionId); } catch (e) { this.#handleError(e); return null; }
    if (method === "Runtime.executionContextDestroyed") this.#vids.revoke((k, r, s) => k === "cx" && s === sessionId && r === params.executionContextId);
    const cx = method === "Runtime.consoleAPICalled" ? params.executionContextId : method === "Runtime.exceptionThrown" ? params.exceptionDetails?.executionContextId : undefined;
    this.#track(sessionId, minted, null, Number.isSafeInteger(cx) ? cx : null);
    if (method === "Runtime.consoleAPICalled") for (const real of minted) this.#timed.push({ kind: "ob", real, scope: sessionId, at: this.#now() + LIMITS.consoleMs, release: true });
    if (bytes(value) > ev.maxBytes) return null;
    return { method, params: value, sessionId: page.vid };
  }

  // CDP's own ends for handles (O11 §4.3; the spec's "handles"), applied to every raw event, forwarded or not.
  #lifetimes(scope, method, p) {
    const here = (pred) => this.#vids.revoke((k, r, s) => s === scope && pred(k, r));
    if (method === "DOM.documentUpdated") here((k) => k === "nd");
    else if (method === "Runtime.executionContextsCleared") { here((k) => k === "cx" || k === "ob"); this.#endObjects(scope, () => true); this.#frame(scope).defaults.clear(); }
    else if (method === "Runtime.executionContextCreated" && p?.context?.auxData?.isDefault === true && typeof p.context.auxData.frameId === "string" && Number.isSafeInteger(p.context.id))
      this.#frame(scope).defaults.set(p.context.auxData.frameId, p.context.id);
    else if (method === "Runtime.executionContextDestroyed") { // (its objects end; so do objects whose context isn't known: fail closed)
      this.#endObjects(scope, (o) => o.cx === null || o.cx === p?.executionContextId);
      const d = this.#frame(scope).defaults;
      for (const [fid, id] of d) if (id === p?.executionContextId) d.delete(fid);
    }
    else if (method === "Page.frameDetached") here((k, r) => k === "fr" && r === p?.frameId);
    else if (method === "Page.frameNavigated" && p?.frame && !p.frame.parentId) {
      const main = p.frame.id; // (the main frame keeps its id; everything under the old document ends)
      this.#frame(scope).main = main;
      here((k, r) => k === "nd" || k === "bn" || k === "ax" || k === "ld" || k === "rq" || (k === "fr" && r !== main));
      this.#timed = this.#timed.filter((t) => !(t.scope === scope && t.kind === "rq"));
    } else if ((method === "Network.loadingFinished" || method === "Network.loadingFailed") && typeof p?.requestId === "string")
      this.#timed.push({ kind: "rq", real: p.requestId, scope, at: this.#now() + LIMITS.requestMs, release: false });
  }

  // Header redaction (O11 §4.2; the spec's "redaction"): every headers object and headers text, at any depth, by name,
  // case-insensitively; associated cookies and request bodies are dropped.
  #redactNetwork(v) {
    const walk = (o) => {
      if (Array.isArray(o)) { o.forEach(walk); return; }
      if (o === null || typeof o !== "object") return;
      for (const k of Object.keys(o)) {
        if (k === "associatedCookies" || k === "postData" || k === "postDataEntries") { delete o[k]; continue; }
        if ((k === "headers" || k === "requestHeaders") && o[k] && typeof o[k] === "object" && !Array.isArray(o[k])) {
          for (const h of Object.keys(o[k])) if (this.#redact.has(h.toLowerCase())) o[k][h] = this.#spec.redaction.value;
          continue;
        }
        if ((k === "headersText" || k === "requestHeadersText") && typeof o[k] === "string") { o[k] = this.#redactText(o[k]); continue; }
        walk(o[k]);
      }
    };
    walk(v);
  }

  #redactText(text) {
    const out = [];
    let hiding = false;
    for (const [i, line] of text.split(/\r?\n/).entries()) {
      if (i > 0 && /^[ \t]/.test(line)) { if (!hiding) out.push(line); continue; } // (a folded continuation line)
      const m = i > 0 ? /^([^:]+):/.exec(line) : null;
      hiding = Boolean(m && this.#redact.has(m[1].trim().toLowerCase()));
      out.push(hiding ? `${m[1]}: ${this.#spec.redaction.value}` : line);
    }
    return out.join("\r\n");
  }

  // ---- takeover, handback, timed ends ----

  /**
   * §8.1 steps 1, 2 and 4: stop admitting commands and forwarding events, and revoke every handle. Returns what the
   * app must do with its privileged session: release these object groups ({ sessionId, objectGroup }) and terminate
   * script on these sessions
   * (the drain, step 3, is the app's).
   */
  takeover() {
    this.#paused = true;
    this.#gen++;
    this.#vids.revoke();
    this.#timed = [];
    this.#objects.clear();
    const release = [];
    for (const [sessionId, set] of this.#groups) for (const objectGroup of set) release.push({ sessionId, objectGroup });
    this.#groups.clear();
    return { releaseGroups: release, sessions: [...this.#pages.keys()] };
  }

  /** §8.3: re-expose the pages with new handles. Returns the Target.targetCreated events to forward. */
  handback() {
    if (this.#retired) return [];
    this.#paused = false;
    const out = [];
    for (const p of this.#pages.values()) {
      try { p.vid = this.#vids.out("pg", p.targetId); } catch (e) { this.#handleError(e); return []; }
      out.push({ method: "Target.targetCreated", params: { targetInfo: this.#info(p) } });
    }
    return out;
  }

  /** The timed ends that are due. Returns the console objects the app releases: [{ sessionId, objectId }]. */
  expire() {
    const now = this.#now(), due = this.#timed.filter((t) => t.at <= now);
    this.#timed = this.#timed.filter((t) => t.at > now);
    for (const t of due) { this.#vids.revoke((k, r, s) => k === t.kind && r === t.real && s === t.scope); if (t.kind === "ob") this.#objects.delete(`${t.scope}\0${t.real}`); }
    return due.filter((t) => t.release).map((t) => ({ sessionId: t.scope, objectId: t.real }));
  }
}
