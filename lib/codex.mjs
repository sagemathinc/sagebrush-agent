// Codex as the agent: one pinned Codex release on the computer the runner is on (codex-fetch.mjs), run as `codex app-server`
// (JSON-RPC over stdio, one JSON message per line), with that computer's Codex login and settings, as when they type
// `codex` there. Only over the runner (--stdio) and only with "shell and files" on for the connection: Codex works on
// that computer's files and shell, so a connection without them gets a refusal, never a narrower Codex.
//
// What Codex gets besides its own tools: the Sagebrush workspace tools, as app-server "dynamic tools" answered
// through the page under the turn's grant (the same handlers as Claude's). What Codex asks before it acts (a command,
// a file change, more access), as its settings there decide, comes to the person as a card bound to this process,
// the conversation and that one request; anything but an Allow of that card declines it.

import { jobRefusal, treeSpawn } from "./win-job.mjs";
import { randomBytes } from "node:crypto";
import { z } from "zod";
import { CodexTurn, HINTS } from "./codex-turns.mjs";
import { CodexFetchError, PIN, ensureCodex } from "./codex-fetch.mjs";
import { checkContract, generateSchemas } from "./codex-selftest.mjs";
import { SYSTEM_NATIVE, VERSION } from "./server.mjs";
import { turnInfo } from "./turn-info.mjs";

// The Codex this runs is the pinned one (lib/codex-pin.json, fetched and checked by codex-fetch.mjs), never the one
// on PATH; before its first conversation it's asked for its own protocol and checked (codex-selftest.mjs).
export const CODEX_VERSION = PIN.version;
const KILL_REAP_MS = 2000; // after SIGKILL, how long to wait for the exit to be reaped
const PROBLEMS_SHOWN = 5; // self-test problems named to the person (each cut to 120 characters)
// (the self-test probe's own failure words, the only ones shown besides "exit N": lib/codex-selftest.mjs)
const SCHEMA_WHY = new Set(["it took too long", "it wasn't found", "it couldn't start", "its protocol couldn't be read"]);

const REQUEST_TIMEOUT_MS = 60 * 1000; // a request to Codex that never answers (not a turn: turns end by notification)
const INTERRUPT_GRACE_MS = 10 * 1000; // after turn/interrupt, how long to wait for Codex to say the turn ended
const LINE_MAX = 16 * 1024 * 1024; // one line from Codex
const STDERR_KEEP = 4000; // the end of Codex's stderr, kept for the message when it stops
const ITEMS_MAX = 256; // file changes a turn keeps, to show one exactly when Codex asks about it
const EARLY_MAX = 256; // notifications held for a turn until Codex answers turn/start (more are dropped)
const OPEN_REQUESTS_MAX = 64; // requests from Codex a turn has open at once (more are declined)
const PATCH_ROUNDS = 8; // times one file change is asked again because Codex updated it while its card was open

// What the person and the runner's log are told (set by board; quoted word for word in the review).
export const CODEX_TEXT = {
  needsNative: "Codex needs shell and files on this computer: turn them on for this connection, then send your message again.",
  // (getting the pinned Codex, and why it can't be used)
  getting: (mb) => `Getting Codex ${CODEX_VERSION} for this computer (${mb} MB, once)…`,
  download: (why) => `Codex ${CODEX_VERSION} couldn't be downloaded from registry.npmjs.org (${why}): check that this computer can reach that site, then send your message again.`,
  mismatch: `The downloaded Codex ${CODEX_VERSION} isn't the one this sagebrush-agent was made for, so it wasn't run.`,
  cache: "The folder sagebrush-agent keeps Codex in isn't private to this account, so Codex wasn't run: make it readable and writable only by you, then send your message again.",
  platform: "This sagebrush-agent has no Codex for this kind of computer, so Codex can't run here.",
  incompatible: (list) => `Codex ${CODEX_VERSION} can't be used by this sagebrush-agent here: ${list}.`,
  version: (v) => `The Codex that started says it's ${v}, not the pinned ${CODEX_VERSION}, so it wasn't used.`,
  noSchema: (why) => `Codex ${CODEX_VERSION} couldn't describe its protocol (${why}), so it wasn't run.`,
  notFound: `Codex ${CODEX_VERSION} couldn't be started on this computer.`,
  windows: "Codex on Windows isn't supported here.",
  notLoggedIn: HINTS.unauthorized,
  noNever: "the Codex settings here choose approval_policy never, which isn't taken up here: on-request is used, and Codex's asks come to the page",
  stillNever: "Codex started this conversation with approval_policy never, which isn't taken up here, so this reply didn't start.",
  notEphemeral: "Codex didn't start a conversation that is kept only while it runs, so this reply didn't start.",
  restarted: "Codex had stopped, so a conversation goes on in a new Codex conversation that doesn't remember the earlier replies",
  stopped: (why) => `Codex stopped: ${why}`,
  notReviewable: "Codex asked to change files without saying exactly which changes: declined.",
  askInChat: "ask the person in the chat instead",
  noSandbox: "Codex's sandbox can't start on this computer, so each command asks you first and then runs outside it.",
  titleCommand: "Run this command?",
  titleStdin: "Send input to a running command?",
  titleFiles: "Make these file changes?",
  titlePermissions: "Give Codex more access?",
};

/** The version in an app-server's userAgent ("<client>/<version> (<os>; <arch>) ..."), or null. */
export function codexVersion(userAgent) {
  const m = /^[^/\s]+\/([0-9][^\s]*)(\s|$)/.exec(String(userAgent ?? ""));
  return m ? m[1] : null;
}

// One `codex app-server` process: requests to it, its notifications, and its requests to us.
export class AppServer {
  constructor(command, { cwd, env, onNotification, onRequest, spawnFn = treeSpawn }) {
    this.onNotification = onNotification;
    this.onRequest = onRequest;
    this.next = 1;
    this.waiting = new Map(); // id -> {resolve, reject, timer}
    this.closed = false;
    const [bin, ...args] = command;
    this.child = spawnFn(bin, args, { cwd, env, stdio: ["pipe", "pipe", "pipe"] });
    let buf = "";
    this.child.stdout.setEncoding("utf8");
    this.child.stdout.on("data", (d) => {
      if (this.closed) return;
      buf += d;
      let i;
      while ((i = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, i);
        buf = buf.slice(i + 1);
        if (line.trim()) this.line(line);
        if (this.closed) return;
      }
      if (buf.length > LINE_MAX) { this.fail(new Error("Codex sent a message that is too large")); this.kill(); }
    });
    this.stderr = "";
    this.child.stderr.setEncoding("utf8");
    this.child.stderr.on("data", (d) => { this.stderr = (this.stderr + d).slice(-STDERR_KEEP); });
    this.exited = new Promise((resolve) => this.child.on("close", (code, signal) => {
      const last = this.stderr.trim().split("\n").pop();
      // (on Windows, the job-object helper that couldn't make the job: Codex never started, said as such)
      const refused = jobRefusal(code, this.stderr);
      this.fail(Object.assign(new Error(refused ?? `${signal ?? `exit ${code}`}${last ? `: ${last}` : ""}`), { exited: true }));
      resolve();
    }));
    this.child.on("error", (e) => {
      this.fail(e?.code === "ENOENT" ? Object.assign(new Error(CODEX_TEXT.notFound), { code: "codex_missing" }) : e);
    });
    this.child.stdin.on("error", () => {}); // (a write after Codex exited: reported by close)
  }

  line(line) {
    let m;
    try { m = JSON.parse(line); } catch { return; }
    if (!m || typeof m !== "object" || Array.isArray(m)) return;
    if (typeof m.method === "string" && m.id !== undefined && m.id !== null) {
      // A request from Codex: answered always, once (an unanswered one would hold Codex up). It is taken now, in the
      // order the lines came, so a notification after it in the same read (its serverRequest/resolved) finds it;
      // only the answer is awaited.
      let answer;
      try { answer = this.onRequest(this, m.method, m.params ?? {}, m.id); } catch (e) { answer = Promise.reject(e); }
      Promise.resolve(answer)
        .then((result) => this.write({ id: m.id, result }), (e) => this.write({ id: m.id, error: { code: e?.rpcCode ?? -32603, message: String(e?.message ?? e) } }));
      return;
    }
    if (typeof m.method === "string") return void this.onNotification(this, m.method, m.params ?? {});
    const w = this.waiting.get(m.id);
    if (!w) return;
    this.waiting.delete(m.id);
    clearTimeout(w.timer);
    if (m.error) w.reject(Object.assign(new Error(String(m.error.message ?? "Codex refused")), { rpc: m.error }));
    else w.resolve(m.result);
  }

  write(m) {
    if (!this.closed) this.child.stdin.write(JSON.stringify(m) + "\n");
  }

  request(method, params, timeoutMs = REQUEST_TIMEOUT_MS) {
    if (this.closed) return Promise.reject(this.error ?? new Error("Codex stopped"));
    const id = this.next++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { this.waiting.delete(id); reject(new Error(`Codex didn't answer ${method}`)); }, timeoutMs);
      this.waiting.set(id, { resolve, reject, timer });
      this.write({ id, method, params });
    });
  }

  notify(method, params) {
    this.write(params === undefined ? { method } : { method, params });
  }

  fail(e) {
    if (this.closed) return;
    this.closed = true;
    this.error = e;
    for (const w of this.waiting.values()) { clearTimeout(w.timer); w.reject(e); }
    this.waiting.clear();
    this.onNotification(this, "sagebrush/exited", { message: e.message });
  }

  kill() {
    if (this.child.exitCode === null && this.child.signalCode === null) this.child.kill("SIGTERM");
  }

  // Ends the process: SIGTERM, then SIGKILL if it hasn't exited within `ms`. True when it exited in time.
  async close(ms) {
    this.fail(new Error("the agent stopped"));
    this.kill();
    let t;
    const inTime = await Promise.race([this.exited.then(() => true), new Promise((r) => { t = setTimeout(() => r(false), ms); })]);
    clearTimeout(t);
    if (!inTime) {
      // (killed, and reaped: waited for its exit, bounded, so no process is left behind when this returns)
      this.child.kill("SIGKILL");
      await Promise.race([this.exited, new Promise((r) => { t = setTimeout(r, KILL_REAP_MS); })]);
      clearTimeout(t);
    }
    return inTime;
  }
}

export class CodexBackend {
  // server: the AgentServer (native mode, the runner's folder, the cards, the workspace tools).
  // command: how to start the app-server, for tests and the fake (default: the pinned Codex, fetched by `locate`);
  // spawnFn: a test's stand-in for child_process.spawn; selfTest: a test's stand-in for the protocol check; version:
  // what the Codex must say it is (the pin's).
  constructor(server, { command = null, env = process.env, spawnFn = treeSpawn, locate = ensureCodex, selfTest = null, version = CODEX_VERSION } = {}) {
    this.server = server;
    this.command = command;
    this.env = env;
    this.spawnFn = spawnFn;
    this.locate = locate;
    this.version = version; // (the version the pinned Codex reports; a real-binary row names another)
    this.selfTest = selfTest ?? ((cmd, signal) => generateSchemas([...cmd, "generate-json-schema", "--experimental"], { env: this.env, cwd: this.server.runnerCwd, spawnFn: this.spawnFn, signal }).then((defs) => checkContract(defs)));
    this.app = null; // the running app-server, started at the first turn
    this.starting = null;
    this.opening = null; // (getting the pinned Codex and starting it: shared by turns that come meanwhile)
    this.startApps = new Set(); // (app-servers whose start, or its cleanup, isn't over yet)
    this.fetchAbort = new AbortController(); // (the agent stopping: a download under way ends)
    this.turns = new Map(); // Codex thread id -> the running turn there
    this.dead = new Set(); // (threads whose last turn didn't end when stopped: nothing from them is acted on again)
  }

  // The app-server's command: the pinned Codex, fetched the first time and checked file by file at every start, as
  // an absolute path (never `codex` from PATH). `say`: the progress line, to the turn that asked; `signal`: this start
  // cancelled (its last waiting turn stopped, or the agent stopping).
  async codexCommand(say, signal) {
    if (this.command) return this.command;
    let told = false;
    try {
      const { bin } = await this.locate({ env: this.env, signal, onProgress: (got, size) => { if (!told) { told = true; say?.(CODEX_TEXT.getting(Math.round(size / 1e6))); } } });
      return [bin, "app-server"];
    } catch (e) {
      if (!(e instanceof CodexFetchError)) throw e;
      const text = e.code === "codex_download" ? CODEX_TEXT.download(e.message) : e.code === "codex_platform" ? CODEX_TEXT.platform : e.code === "codex_cache" ? CODEX_TEXT.cache : CODEX_TEXT.mismatch;
      this.server.log?.(`Codex: ${e.code}`);
      throw Object.assign(new Error(text), { code: e.code });
    }
  }

  // Get and start the app-server and say hello (once; again after it stopped). Checks its version, its platform,
  // its protocol (the self-test, before any thread) and its login, and reads the approval policy the person's
  // settings choose in the runner's folder. Turns that come while it starts share the start; it is cancelled (the
  // download, the app-server and the self-test's probe all ended) when every turn waiting on it has stopped, or the
  // agent stops. `signal`: the asking turn's Stop.
  ensure(say, signal) {
    if (!this.opening && this.app && !this.app.closed) return this.starting.then(() => this.app);
    if (!this.opening) {
      const op = { ac: new AbortController(), waiters: 0, promise: null };
      op.promise = this.open(say, AbortSignal.any([op.ac.signal, this.fetchAbort.signal])).finally(() => { if (this.opening === op) this.opening = null; });
      op.promise.catch(() => {});
      this.opening = op;
    }
    const op = this.opening;
    op.waiters++;
    const release = () => { if (--op.waiters === 0 && this.opening === op) op.ac.abort(); };
    if (signal?.aborted) release();
    else signal?.addEventListener("abort", release, { once: true });
    return op.promise.finally(() => signal?.removeEventListener("abort", release));
  }

  async open(say, signal) {
    const stopped = () => Object.assign(new Error("stopped"), { stopped: true });
    const command = await this.codexCommand(say, signal);
    if (signal.aborted) throw stopped();
    const app = new AppServer(command, {
      cwd: this.server.runnerCwd,
      env: this.env,
      spawnFn: this.spawnFn,
      onNotification: (from, method, p) => this.notification(from, method, p),
      onRequest: (from, method, p, id) => this.request(from, method, p, id),
    });
    this.app = app;
    this.startApps.add(app); // (held until this start, and its cleanup, is over: close() ends it if need be)
    // (cancelled while it starts: the app-server is ended, which fails whatever it was asked, so nothing after is
    //  sent; the start then fails "stopped")
    const onCancel = () => { app.close(3000).catch(() => {}); };
    signal.addEventListener("abort", onCancel, { once: true });
    this.starting = (async () => {
      const hello = await app.request("initialize", { clientInfo: { name: "sagebrush-agent", title: "Sagebrush agent", version: VERSION }, capabilities: { experimentalApi: true } });
      const version = codexVersion(hello?.userAgent);
      if (version !== this.version) throw Object.assign(new Error(CODEX_TEXT.version(version ?? "of an unknown version")), { code: "codex_version" });
      if (hello?.platformFamily === "windows") throw Object.assign(new Error(CODEX_TEXT.windows), { code: "codex_platform" });
      // (the self-test: this same Codex's own protocol against what this agent uses; nothing else is sent until it
      //  passes. What's shown is fixed words or names from the contract, never Codex's output)
      let problems;
      try { problems = await this.selfTest(command, signal); }
      catch (e) {
        const why = SCHEMA_WHY.has(e?.message) || /^(exit \d+|stopped by [A-Z0-9]+)$/.test(e?.message ?? "") ? e.message : "it failed";
        throw Object.assign(new Error(CODEX_TEXT.noSchema(why)), { code: "codex_incompatible" });
      }
      if (problems.length) throw Object.assign(new Error(CODEX_TEXT.incompatible(problems.slice(0, PROBLEMS_SHOWN).map((p) => p.slice(0, 120)).join("; "))), { code: "codex_incompatible" });
      app.notify("initialized");
      const account = await app.request("account/read", {});
      if (account?.requiresOpenaiAuth && !account?.account) throw Object.assign(new Error(CODEX_TEXT.notLoggedIn), { code: "unauthorized" });
      const read = await app.request("config/read", { includeLayers: false, cwd: this.server.runnerCwd });
      app.never = read?.config?.approval_policy === "never";
    })().catch(async (e) => {
      // (the next turn starts over: after `codex login`, say)
      if (this.app === app) this.app = null;
      await app.close(3000);
      throw signal.aborted ? stopped() : e;
    }).finally(() => { signal.removeEventListener("abort", onCancel); this.startApps.delete(app); });
    return this.starting.then(() => app);
  }

  // The workspace tools, as Codex is told them: every one a page may offer (a call to one the page doesn't is refused).
  toolSpecs(conversation, c) {
    return this.server.workspaceToolList(conversation, c, { features: ["notebook.edit"] }, undefined, null)
      .map(([name, description, shape]) => ({ type: "function", name, description, inputSchema: z.toJSONSchema(schemaOf(shape)) }));
  }

  // A thread per conversation in this app-server, kept only while it runs (ephemeral: no session files). A new
  // app-server (after Codex stopped) means a new thread, and the person is told. One start at a time per conversation
  // and app-server: a turn that comes while one is under way (its own turn stopped while it waited) waits for that
  // same start, so a late answer can never replace a newer thread.
  thread(conversation, c, app) {
    if (c.codex && c.codex.app === app && !this.dead.has(c.codex.id)) return Promise.resolve(c.codex.id);
    if (c.threadStart && c.threadStart.app === app && !app.closed) return c.threadStart.promise;
    const start = { app, promise: null };
    start.promise = this.startThread(conversation, c, app).finally(() => { if (c.threadStart === start) c.threadStart = null; });
    c.threadStart = start;
    return start.promise;
  }

  async startThread(conversation, c, app) {
    const restarted = !!c.codex;
    if (app.never) this.server.log(CODEX_TEXT.noNever);
    const r = await app.request("thread/start", {
      cwd: this.server.runnerCwd,
      ephemeral: true,
      developerInstructions: SYSTEM_NATIVE,
      dynamicTools: this.toolSpecs(conversation, c),
      ...(app.never ? { approvalPolicy: "on-request" } : {}),
    });
    const id = r?.thread?.id;
    if (typeof id !== "string") throw new Error("Codex didn't start a conversation");
    // (checked on Codex's own answer, whatever was asked: never a thread that keeps files, never one that doesn't ask)
    if (r.thread.ephemeral !== true) { this.dead.add(id); throw new Error(CODEX_TEXT.notEphemeral); }
    if (r.approvalPolicy === "never") { this.dead.add(id); throw new Error(CODEX_TEXT.stillNever); }
    // (a start is replaced only by one in a newer app-server, after this one's closed, which rejects its request
    //  before it gets here: so this is the conversation's current start)
    c.codex = { app, id };
    // (W3: the model and effort Codex says this thread runs with: a property of the thread, kept with its id, and said by
    //  the first live turn on this thread that gets it; a turn that has ended never says it)
    const info = turnInfo({ model: r.model, effort: r.reasoningEffort });
    c.codexInfo = info ? { threadId: id, info } : null;
    // (the page has no notice event yet: said in the runner's log)
    if (restarted) this.server.log(CODEX_TEXT.restarted);
    return id;
  }

  async runTurn(conversation, c, m, binding) {
    const server = this.server;
    const turnId = `turn-${randomBytes(6).toString("hex")}`;
    const turn = new CodexTurn(turnId);
    const send = (drafts) => { for (const event of drafts) server.sendTo(binding, "turn.event", { conversation, turn_id: turnId, in_reply_to: m.id, event }); };
    const abort = new AbortController();
    c.running = { binding, turnId, cancel: () => abort.abort() };
    server.runningCount++;
    if (server.closing) abort.abort();
    send(turn.start());
    // (a Stop, a new grant, a disconnect or the agent stopping, while something was awaited: this turn ends there)
    const stale = () => abort.signal.aborted || binding !== server.binding || server.closing;
    let active = null, graceTimer = null;
    try {
      // (native only: refused before anything starts, never run as a narrower Codex)
      if (!server.nativeFor(binding)) return void send(turn.failed(CODEX_TEXT.needsNative, "native_off"));
      // (Codex's start-up and the thread's start end with the turn: a Stop doesn't wait for Codex to answer them)
      const untilStop = (p) => new Promise((resolve, reject) => {
        const onAbort = () => reject(Object.assign(new Error("stopped"), { stopped: true }));
        if (abort.signal.aborted) return onAbort();
        abort.signal.addEventListener("abort", onAbort, { once: true });
        p.then((v) => { abort.signal.removeEventListener("abort", onAbort); resolve(v); }, (e) => { abort.signal.removeEventListener("abort", onAbort); reject(e); });
      });
      const app = await untilStop(this.ensure((text) => send([{ type: "thinking_delta", text }]), abort.signal));
      if (stale()) return void send(turn.interrupted());
      const threadId = await untilStop(this.thread(conversation, c, app));
      if (stale()) return void send(turn.interrupted());
      // (only this live turn's own thread's start info: never another thread's)
      if (c.codexInfo?.threadId === threadId) {
        const { info } = c.codexInfo;
        c.codexInfo = null;
        send([info]);
      }
      let finish, ready, notReady;
      const ended = new Promise((resolve) => { finish = resolve; });
      // (the turn's id is Codex's answer to turn/start, and only that: until it comes, what Codex sends for this thread
      //  waits (requests) or is held (notifications), then counts only if it names that id)
      const started = new Promise((resolve, reject) => { ready = resolve; notReady = reject; });
      started.catch(() => {});
      active = { turn, send, binding, signal: abort.signal, app, threadId, codexTurnId: null, started, early: [], finish, items: new Map(), requests: new Map(), conversation, c, interrupted: false };
      this.turns.set(threadId, active);
      const interrupt = () => {
        if (active.interrupted || !active.codexTurnId) return;
        active.interrupted = true;
        app.request("turn/interrupt", { threadId, turnId: active.codexTurnId }).catch(() => {});
      };
      const onAbort = () => {
        interrupt();
        graceTimer ??= setTimeout(() => finish("timeout"), INTERRUPT_GRACE_MS);
      };
      abort.signal.addEventListener("abort", onAbort, { once: true });
      let r;
      try { r = await app.request("turn/start", { threadId, input: [{ type: "text", text: m.text, text_elements: [] }] }); }
      catch (e) { notReady(e); throw e; }
      if (typeof r?.turn?.id !== "string") { const e = new Error("Codex didn't start the reply"); notReady(e); throw e; }
      active.codexTurnId = r.turn.id;
      ready(r.turn.id);
      // (what came before the answer, in order: only what names this turn)
      for (const [method, p] of active.early.splice(0)) this.deliver(active, method, p);
      if (abort.signal.aborted) onAbort();
      const how = await ended;
      abort.signal.removeEventListener("abort", onAbort);
      if (how === "timeout") {
        // (Codex didn't say the turn ended: its thread isn't used again, and nothing it asks later is allowed)
        this.dead.add(threadId);
        send(turn.interrupted());
      } else if (how !== "completed") send(turn.failed(CODEX_TEXT.stopped(how)));
    } catch (err) {
      // (Codex having exited reads as it does mid-turn: "Codex stopped: <why>")
      send(abort.signal.aborted ? turn.interrupted() : turn.failed(err?.exited ? CODEX_TEXT.stopped(err.message) : err?.message ?? err, typeof err?.code === "string" ? err.code : "agent_error"));
    } finally {
      clearTimeout(graceTimer);
      if (active) {
        this.withdrawAll(active); // (no card of this turn stays open after it)
        if (this.turns.get(active.threadId) === active) this.turns.delete(active.threadId);
      }
      c.running = null;
      server.runningCount--;
      queueMicrotask(() => server.schedule());
    }
  }

  // The running turn of a message's thread, in the app-server that sent it (its turn id is checked by the caller).
  activeFor(app, p) {
    const active = typeof p?.threadId === "string" ? this.turns.get(p.threadId) : undefined;
    if (!active || active.app !== app || this.dead.has(active.threadId)) return null;
    return active;
  }

  // Whether a turn is still the one running in its thread, unfinished, in a live app-server, under the current binding.
  live(active) {
    return this.turns.get(active.threadId) === active && !active.turn.finished && !active.app.closed && active.binding === this.server.binding && !active.signal.aborted;
  }

  // Ends every request of a turn still open: none of them is answered "accept" after this, and their cards go.
  withdrawAll(active) {
    for (const req of active.requests.values()) endRequest(req);
  }

  // A notification from Codex: to the turn running in its thread.
  notification(app, method, p) {
    if (method === "sagebrush/exited") {
      if (this.app === app) this.app = null;
      for (const [id, active] of [...this.turns]) if (active.app === app) { this.turns.delete(id); this.withdrawAll(active); active.finish(p.message); }
      return;
    }
    // (Codex saying at start that its sandbox can't run here: then a command it asks about runs outside it, which the
    //  person is told once per conversation, with the first such card)
    if (method === "configWarning" && /sandbox/i.test(String(p?.summary ?? ""))) { app.sandboxDown = true; return; }
    const active = this.activeFor(app, p);
    if (!active) return;
    // (Codex no longer waits for an answer to that request: its card goes)
    if (method === "serverRequest/resolved") {
      const req = active.requests.get(rpcKey(p.requestId));
      if (req) endRequest(req);
      return;
    }
    if (active.codexTurnId === null) {
      if (active.early.length < EARLY_MAX) active.early.push([method, p]);
      return;
    }
    this.deliver(active, method, p);
  }

  // A notification for a turn whose id is known: only one naming that id counts.
  deliver(active, method, p) {
    const named = typeof p.turnId === "string" ? p.turnId : typeof p.turn?.id === "string" ? p.turn.id : null;
    if (named !== active.codexTurnId) return;
    // (a file change, kept for when Codex asks about it: what the card shows is what Codex last said it will change)
    const item = p.item;
    if ((method === "item/started" || method === "item/completed") && item?.type === "fileChange" && typeof item.id === "string") this.keepItem(active, item.id, item.changes);
    if (method === "item/fileChange/patchUpdated" && typeof p.itemId === "string") {
      this.keepItem(active, p.itemId, p.changes);
      // (a card open for the old changes is withdrawn; the person is asked again about the new ones)
      for (const req of active.requests.values()) if (req.ask?.itemId === p.itemId) { req.ask.changed = true; req.ask.ac.abort(); }
    }
    active.send(active.turn.feed(method, p));
    if (method === "turn/completed") { this.withdrawAll(active); active.finish("completed"); }
  }

  keepItem(active, id, changes) {
    active.items.delete(id);
    active.items.set(id, { changes });
    if (active.items.size > ITEMS_MAX) active.items.delete(active.items.keys().next().value);
  }

  // A request from Codex. The workspace tools run under the turn's grant; what Codex asks before it acts is asked of
  // the person; the rest is refused. Anything not for the running turn of its thread is declined.
  async request(app, method, p, rpcId) {
    // (the request's own record, made before anything is awaited: Codex resolving it, the turn ending or Codex stopping
    //  marks it over, whether a card is open yet or not, and from then on no card opens for it and nothing accepts it)
    const owner = this.activeFor(app, p);
    const key = rpcKey(rpcId);
    const req = { over: false, ask: null, ac: new AbortController() }; // (ac: aborted when the request is over)
    if (owner) {
      if (owner.requests.size >= OPEN_REQUESTS_MAX) endRequest(req);
      else {
        const was = owner.requests.get(key); // (an id Codex uses again: the earlier request is over)
        if (was) endRequest(was);
        owner.requests.set(key, req);
      }
    }
    try {
      return await this.answer(owner, req, method, p);
    } finally {
      if (owner?.requests.get(key) === req) owner.requests.delete(key);
    }
  }

  async answer(owner, req, method, p) {
    let active = owner;
    // (before the turn's id is known: wait for it, then check this request names it)
    if (active && active.codexTurnId === null) await active.started.catch(() => {});
    if (active && (p.turnId !== active.codexTurnId || !this.live(active))) active = null;
    if (method === "item/tool/call") return this.toolCall(active, p, req);
    if (method === "item/commandExecution/requestApproval") {
      const dec = (d) => ({ decision: d });
      if (!active) return dec("decline");
      // (only a plain accept is ever sent: never for the session, never a policy change)
      if (Array.isArray(p.availableDecisions) && !p.availableDecisions.includes("accept")) return dec("decline");
      const input = pick(p, ["kind", "command", "cwd", "reason", "additionalPermissions", "networkApprovalContext"]);
      if (active.app.sandboxDown && !active.c.sandboxSaid) { active.c.sandboxSaid = true; active.send([{ type: "thinking_delta", text: CODEX_TEXT.noSandbox }]); }
      const v = await this.ask(active, req, p.kind === "writeStdin" ? "codex.stdin" : "codex.command", input, p.kind === "writeStdin" ? CODEX_TEXT.titleStdin : CODEX_TEXT.titleCommand, typeof p.command === "string" ? p.command : undefined);
      return dec(v);
    }
    if (method === "item/fileChange/requestApproval") {
      const dec = (d) => ({ decision: d });
      if (!active) return dec("decline");
      // (asked about the changes as Codex last announced them; if they change while the card is open, asked again:
      //  each round's ask() checks first that the request isn't over)
      for (let round = 0; round < PATCH_ROUNDS; round++) {
        const item = active.items.get(p.itemId);
        if (!item || !Array.isArray(item.changes) || !item.changes.length) {
          active.send([{ type: "attention", id: `codex-${randomBytes(6).toString("hex")}`, kind: "approval", state: "denied", title: CODEX_TEXT.titleFiles, summary: CODEX_TEXT.notReviewable }]);
          return dec("decline");
        }
        const changes = item.changes.map((x) => ({ path: x?.path, kind: x?.kind, diff: x?.diff }));
        const input = { changes, ...pick(p, ["reason", "grantRoot"]) };
        const v = await this.ask(active, req, "codex.fileChange", input, CODEX_TEXT.titleFiles, changes.map((x) => String(x.path)).join(", "), p.itemId);
        if (v !== "changed") return dec(v);
      }
      return dec("decline");
    }
    if (method === "item/permissions/requestApproval") {
      const none = { permissions: {}, scope: "turn" };
      if (!active) return none;
      const asked = pick(p.permissions ?? {}, ["network", "fileSystem"]);
      const input = { ...pick(p, ["cwd", "reason"]), permissions: asked };
      const v = await this.ask(active, req, "codex.permissions", input, CODEX_TEXT.titlePermissions, typeof p.reason === "string" ? p.reason : undefined);
      // (an Allow grants exactly what was asked, for this turn only)
      return v === "accept" ? { permissions: asked, scope: "turn" } : none;
    }
    if (method === "mcpServer/elicitation/request") return { action: "decline", content: null, _meta: null };
    if (method === "item/tool/requestUserInput") throw Object.assign(new Error(CODEX_TEXT.askInChat), { rpcCode: -32000 });
    throw Object.assign(new Error(`${method} isn't supported by sagebrush-agent`), { rpcCode: -32601 });
  }

  // One card for the person about request `req` of this turn. No card opens for a request that is over (resolved by
  // Codex, its turn ended or stopped, Codex stopped), and one open is withdrawn when it becomes over (or, for a file
  // change, when its changes are updated: "changed"). "accept" only for an Allow of exactly this card while the
  // request isn't over and the turn is live; "cancel" when the request is over, the turn isn't live or the card was
  // withdrawn; "decline" otherwise (No, a disconnect, too many questions, a request too large to show).
  async ask(active, req, tool, input, title, summary, itemId = null) {
    if (req.over || !this.live(active)) return "cancel";
    const ac = new AbortController();
    const onTurn = () => ac.abort();
    active.signal.addEventListener("abort", onTurn, { once: true });
    const ask = { ac, itemId, changed: false };
    req.ask = ask;
    let v;
    try {
      v = await this.server.askPerson(active.binding, active.send, tool, input, { signal: ac.signal, title, summary }, active.conversation, true);
    } finally {
      active.signal.removeEventListener("abort", onTurn);
      if (req.ask === ask) req.ask = null;
    }
    if (req.over || !this.live(active)) return "cancel";
    if (ask.changed) return "changed";
    if (v.behavior === "allow" && !ac.signal.aborted) return "accept";
    return ac.signal.aborted ? "cancel" : "decline";
  }

  // A workspace tool Codex called: the same handler Claude's call runs, under the turn's binding and for as long as
  // Codex's request lasts: the handler's signal is aborted when the turn stops or the request is over (resolved,
  // its id used again, its turn ended), so a card it opens (renaming, removing) is withdrawn and a page call it
  // waits on is dropped; an over request runs nothing.
  async toolCall(active, p, req = null) {
    const reply = (ok, text) => ({ contentItems: [{ type: "inputText", text }], success: ok });
    const server = this.server;
    if (!active || active.signal.aborted || active.binding !== server.binding || active.turn.finished) return reply(false, "refused: the turn was stopped, the page disconnected or the grant changed");
    if (req?.over) return reply(false, "refused: Codex no longer waits for this call");
    const name = String(p.tool ?? "");
    const signal = req ? AbortSignal.any([active.signal, req.ac.signal]) : active.signal;
    const tools = server.workspaceToolList(active.conversation, active.c, active.binding, signal, active.send, active.turn.turnId);
    const tool = tools.find(([n]) => n === name);
    if (!tool) return reply(false, `refused: ${name} isn't offered by this page`);
    const parsed = schemaOf(tool[2]).safeParse(p.arguments ?? {});
    if (!parsed.success) return reply(false, `refused: ${parsed.error.issues.map((i) => `${i.path.join(".") || "arguments"}: ${i.message}`).join("; ")}`);
    const r = await tool[3](parsed.data);
    const text = (r?.content ?? []).map((x) => (x?.type === "text" ? x.text : "")).join("");
    return reply(!r?.isError, text);
  }

  // Ends the app-server, within `ms`. Returns what couldn't be done, for the person to see.
  async close(ms) {
    this.fetchAbort.abort(); // (a start under way is cancelled: its download, probe and app-server end)
    // (every app-server this backend has, the one a start is still cleaning up included, ended within one budget:
    //  past it, killed and reaped, and said so)
    const deadline = Date.now() + ms;
    const apps = new Set([this.app, ...this.startApps].filter(Boolean));
    this.app = null;
    const problems = [];
    for (const app of apps) if (!(await app.close(Math.max(0, deadline - Date.now())))) problems.push("Codex didn't stop in time and was killed");
    return [...new Set(problems)];
  }
}

// (a request from Codex is over: nothing more is done for it, its card goes and what its handler waits on is dropped)
function endRequest(req) {
  req.over = true;
  req.ac.abort();
  req.ask?.ac.abort();
}

// (a request's id from Codex, a string or a number, as one key)
const rpcKey = (id) => JSON.stringify(id ?? null);

// (a tool's arguments: a zod object, or the shape of one, as the SDK's tool() takes either)
const schemaOf = (shape) => (shape instanceof z.ZodType ? shape : z.object(shape));

// (the fields of `o` named, those present and not null: what a card shows is what Codex sent, nothing added)
function pick(o, keys) {
  return Object.fromEntries(keys.filter((k) => o?.[k] !== undefined && o?.[k] !== null).map((k) => [k, o[k]]));
}
