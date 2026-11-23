// Claude through the unmodified `claude` CLI (design claude-cli-mode r2). A Claude subscription is only ever used by
// Claude Code itself: here each Claude turn (a Pair turn, a Delegate task's turn, chat.brief's draft) runs the pinned
// Claude Code binary, exactly as shipped, as `claude -p` with stream-json in and out, signed in through its own flow and
// its own stored login. This process never reads, copies or passes a credential. The Agent SDK is used only where the
// environment selects an API key or a cloud provider (SDK mode, sdkGuard below), and is then checked, before the
// prompt exists for it, not to be on a subscription.
//
// The rest of the agent doesn't change: cliQuery and cliCreateServer have the SDK's query and createSdkMcpServer
// contract as the agent uses it (the fakes have it too). cliQuery yields the CLI's own stream-json messages, which are
// the messages the SDK yields.
//
// What Claude gets besides its own tools, and how the person decides, goes over two loopback MCP listeners of this
// process, one for the agent's tools and one for permission decisions (--permission-prompt-tool), each with its own
// random port and 256-bit token. Their config is a file only until Claude Code has connected to both: it is removed
// before the first user message is written, so nothing Claude later runs as this user can read it (H1). A permission
// decision is answered only for a tool call the stream has shown, bound one-shot to its id, exact name and canonical
// input (H2).

import { spawn, spawnSync } from "node:child_process";
import { createServer as httpServer } from "node:http";
import { randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { closeSync, constants as FS, lstatSync, mkdtempSync, openSync, readdirSync, readFileSync, rmSync, writeSync } from "node:fs";
import { createRequire } from "node:module";
import { homedir, tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { z } from "zod";
import { canon } from "./canon.mjs";
import { jobSpawn } from "./win-job.mjs";
import { groupAlive } from "./proc-start.mjs";

/** The Claude Code release this sagebrush-agent runs: the one the pinned SDK release ships (lib/claude-pin.json). */
export const CLAUDE_PIN = JSON.parse(readFileSync(new URL("./claude-pin.json", import.meta.url), "utf8")).claudeCodeVersion;

export const CLI_LIMITS = Object.freeze({
  connectMs: 30_000, // Claude Code connecting to both listeners after it starts (then the turn fails)
  permissionWaitMs: 10_000, // a permission call waiting for its tool call to show in the stream (then denied)
  pendingMax: 64, // tool calls a query holds not yet settled at once: waiting, being decided or allowed (more: denied)
  queueMax: 256, // messages read and not yet taken: at it, reading and parsing stop until they're taken
  queueBytesMax: 32 * 1024 * 1024, // the same, in the UTF-8 bytes of their lines
  seenMax: 65_536, // tool call ids one query remembers (to refuse an id shown twice); more ends the query
  heldInputBytes: 64 * 1024 * 1024, // canonical inputs of unsettled tool calls held at once, in all (more: not held, denied)
  lineMax: 16 * 1024 * 1024, // one line of Claude Code's output
  bodyMax: 32 * 1024 * 1024, // one MCP request body
  killGraceMs: 2_000, // TERM, then KILL of the process group
  exitEofMs: 2_000, // after the child exits, reading unpaused: how long its output may stay open (a descendant holding it)
  versionMs: 30_000, // `claude --version`
  guardMs: 15_000, // SDK mode: the initialize answer before the prompt is released
  stderrKeep: 4_000, // the end of Claude Code's stderr, kept for the message when it stops
});

// The environment variables that point Claude Code at another API endpoint. The release entry refuses to start with
// any of them set (r2 §6): only tests, calling this module directly, use a fake endpoint.
export const BASE_URL_VARS = ["ANTHROPIC_BASE_URL", "ANTHROPIC_BEDROCK_BASE_URL", "ANTHROPIC_VERTEX_BASE_URL", "ANTHROPIC_FOUNDRY_BASE_URL"];
export const baseUrlSet = (env = process.env) => BASE_URL_VARS.filter((v) => typeof env[v] === "string" && env[v] !== "");

const PROVIDERS = { CLAUDE_CODE_USE_BEDROCK: "bedrock", CLAUDE_CODE_USE_VERTEX: "vertex", CLAUDE_CODE_USE_FOUNDRY: "foundry" };

/**
 * Which way Claude runs, chosen once for the process (r3 H1). The explicit selectors are ANTHROPIC_API_KEY (non-empty)
 * and each CLAUDE_CODE_USE_<provider>=1. None: CLI mode. Exactly one: SDK mode with it. Two or more: refused, as is
 * SAGEBRUSH_AGENT_CLAUDE=cli with any selector; an explicit credential request never quietly becomes a subscription.
 * Returns {mode: "cli"}, {mode: "sdk", select: "apiKey"|<provider>} or {mode: "refuse", why}.
 */
export function claudeMode(env = process.env) {
  const selectors = [
    ...(typeof env.ANTHROPIC_API_KEY === "string" && env.ANTHROPIC_API_KEY !== "" ? [["ANTHROPIC_API_KEY", "apiKey"]] : []),
    ...Object.entries(PROVIDERS).filter(([v]) => env[v] === "1"),
  ];
  const names = selectors.map(([v]) => v).join(" and ");
  if (env.SAGEBRUSH_AGENT_CLAUDE === "cli") return selectors.length ? { mode: "refuse", why: `SAGEBRUSH_AGENT_CLAUDE=cli can't be used with ${names}: unset one of them` } : { mode: "cli" };
  if (selectors.length > 1) return { mode: "refuse", why: `${names} are all set: choose one way to reach Claude, then start sagebrush-agent again` };
  if (selectors.length === 1) return { mode: "sdk", select: selectors[0][1] };
  return { mode: "cli" };
}

// ---------------------------------------------------------------------------------------------------------------
// The first-run checks (#1788): what's missing, said with the exact next step, before anything else starts. The
// agent never starts a Claude sign-in itself: the person installs Claude Code from Anthropic's own page and signs in
// with it. The same words are the page's (turns.mjs's authentication_failed hint).

export const SETUP_TEXT = Object.freeze({
  claudeInstallUrl: "https://code.claude.com/docs/en/setup",
  nodeUrl: "https://nodejs.org",
  notSignedIn: "Claude Code isn't signed in on this computer. Install Claude Code (https://code.claude.com/docs/en/setup), run `claude auth login` once in a terminal, then start sagebrush-agent again.",
  // (a turn's words, #1788 and #1804: the agent is running, so the next step ends with sending the message again)
  turnNotSignedIn: "Claude Code isn't signed in on this computer. Install Claude Code (https://code.claude.com/docs/en/setup), run `claude auth login` once in a terminal, then send your message again.",
  turnLoginExpired: "Your Claude sign-in expired. In your terminal, run `claude auth login`, then send your message again.",
});

/**
 * A Claude sign-in failure, from Claude Code's own words (the pinned release's; a fixture per pin): "claude_not_signed_in",
 * "claude_login_expired", or null when the text isn't one. Its words are never shown (they may advise setup tokens,
 * which aren't part of this agent's flow): the turn says ours.
 */
export function signInFailure(text) {
  const t = String(text ?? "");
  if (/^\s*Not logged in\b/i.test(t)) return "claude_not_signed_in";
  if (/reached its time limit|Failed to authenticate|(OAuth|access) token (has )?expired|token has expired|re-?authenticate|claude auth login|claude setup-token|CLAUDE_CODE_OAUTH_TOKEN/i.test(t)) return "claude_login_expired";
  return null;
}
export const SIGN_IN_TEXT = Object.freeze({ claude_not_signed_in: SETUP_TEXT.turnNotSignedIn, claude_login_expired: SETUP_TEXT.turnLoginExpired });

/**
 * Whether the pinned Claude Code is signed in, by its own `claude auth status` (it reads its own login; this reads
 * only the `loggedIn` boolean of its answer): true, false, or null when it can't say (then nothing is refused here;
 * a turn says it). For CLI mode only: SDK mode has its own check before each prompt.
 */
export function claudeSignedIn(bin, { env = process.env, run = spawnSync } = {}) {
  if (!bin) return null;
  const r = run(bin, ["auth", "status", "--json"], { env, encoding: "utf8", timeout: CLI_LIMITS.versionMs, windowsHide: true, maxBuffer: 64 * 1024 });
  if (r.error) return null;
  let j;
  try { j = JSON.parse(String(r.stdout ?? "")); } catch { return null; }
  return j && typeof j === "object" && typeof j.loggedIn === "boolean" ? j.loggedIn : null;
}

// ---------------------------------------------------------------------------------------------------------------
// The pinned binary (r2 §2): the platform package of the pinned SDK release, never a `claude` on PATH.

export function claudeBinary({ platform = process.platform, arch = process.arch, resolve = createRequire(import.meta.url).resolve } = {}) {
  const names = platform === "linux" ? [`linux-${arch}`, `linux-${arch}-musl`] : [`${platform}-${arch}`];
  for (const n of names) {
    let pkg;
    try { pkg = resolve(`@anthropic-ai/claude-agent-sdk-${n}/package.json`); } catch { continue; }
    return join(dirname(pkg), platform === "win32" ? "claude.exe" : "claude");
  }
  return null;
}

const versionChecked = new Map(); // (binary path -> null when it is the pinned version, else why not)
/** Why the binary can't be used (it isn't there, doesn't start, or isn't the pinned version), or null. */
export function claudeVersionProblem(bin, { env = process.env, run = spawnSync } = {}) {
  if (!bin) return "this sagebrush-agent has no Claude Code for this kind of computer";
  if (versionChecked.has(bin)) return versionChecked.get(bin);
  const r = run(bin, ["--version"], { env, encoding: "utf8", timeout: CLI_LIMITS.versionMs, windowsHide: true });
  const said = String(r.stdout ?? "").trim();
  const why = r.error || r.status !== 0 ? "Claude Code couldn't be started on this computer"
    : said !== `${CLAUDE_PIN} (Claude Code)` ? `the Claude Code here says it's ${JSON.stringify(said.slice(0, 60))}, not the pinned ${CLAUDE_PIN}, so it wasn't used` : null;
  versionChecked.set(bin, why);
  return why;
}

// ---------------------------------------------------------------------------------------------------------------
// Tools: what createServer is given, served over MCP by this process.

/** createSdkMcpServer's contract, as the agent uses it: [name, description, zod shape or schema, handler(args, extra)]. */
export function cliCreateServer(spec) {
  const tools = spec.tools.map(([name, description, shape, handler]) => {
    // (a raw shape, or a zod schema whole, as the SDK's tool() takes either; the page tools pass both kinds)
    const schema = shape?._zod ? shape : z.object(shape);
    const inputSchema = z.toJSONSchema(schema, { unrepresentable: "any" });
    delete inputSchema.$schema;
    return { name, description, schema, inputSchema, handler };
  });
  return { type: "sagebrush-cli", name: spec.name, version: spec.version, tools };
}

const SERVER_NAME = /^[A-Za-z0-9_-]{1,64}$/;

// One loopback listener: POST only, JSON only, its own bearer token, the minimal MCP subset (initialize,
// notifications/initialized, tools/list, tools/call, ping). `servers`: name -> {tools: [{name, description, inputSchema,
// call(args, signal)}]}. `onListed(name)`: called when Claude Code has listed a server's tools (connected).
async function listener(servers, onListed, signal) {
  const token = randomBytes(32);
  const tokenText = token.toString("hex");
  const want = Buffer.from(`Bearer ${tokenText}`);
  const srv = httpServer((req, res) => {
    const auth = Buffer.from(String(req.headers.authorization ?? ""));
    if (auth.length !== want.length || !timingSafeEqual(auth, want)) { res.writeHead(401); return res.end(); }
    const name = decodeURIComponent((req.url ?? "").split("?")[0].replace(/^\//, ""));
    const server = Object.hasOwn(servers, name) ? servers[name] : null;
    if (req.method !== "POST" || !server) { res.writeHead(405); return res.end(); }
    const chunks = [];
    let size = 0, over = false;
    req.on("data", (d) => { size += d.length; if (size > CLI_LIMITS.bodyMax) { over = true; req.destroy(); } else chunks.push(d); });
    req.on("error", () => {});
    req.on("end", async () => {
      if (over) return;
      let m;
      try { m = JSON.parse(Buffer.concat(chunks).toString("utf8")); } catch { res.writeHead(400); return res.end(); }
      if (!m || typeof m !== "object" || Array.isArray(m) || typeof m.method !== "string") { res.writeHead(400); return res.end(); }
      if (m.id === undefined || m.id === null) { res.writeHead(202); return res.end(); } // (a notification)
      const reply = (body) => { res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify({ jsonrpc: "2.0", id: m.id, ...body })); };
      const p = m.params && typeof m.params === "object" ? m.params : {};
      try {
        if (m.method === "initialize") return reply({ result: { protocolVersion: typeof p.protocolVersion === "string" ? p.protocolVersion : "2025-06-18", capabilities: { tools: {} }, serverInfo: { name, version: "1" } } });
        if (m.method === "ping") return reply({ result: {} });
        if (m.method === "tools/list") {
          const result = { tools: server.tools.map((t) => ({ name: t.name, description: t.description, inputSchema: t.inputSchema })) };
          reply({ result });
          onListed(name);
          return;
        }
        if (m.method === "tools/call") {
          const t = server.tools.find((x) => x.name === p.name);
          if (!t) return reply({ result: { content: [{ type: "text", text: `no such tool: ${String(p.name).slice(0, 80)}` }], isError: true } });
          const out = await t.call(p.arguments ?? {}, signal);
          return reply({ result: out });
        }
        return reply({ error: { code: -32601, message: "method not found" } });
      } catch (e) {
        return reply({ result: { content: [{ type: "text", text: String(e?.message ?? e).slice(0, 2000) }], isError: true } });
      }
    });
  });
  srv.headersTimeout = 30_000;
  await new Promise((ok, fail) => { srv.once("error", fail); srv.listen(0, "127.0.0.1", ok); });
  return { srv, port: srv.address().port, token: tokenText, close: () => new Promise((r) => { srv.close(() => r()); srv.closeAllConnections?.(); }) };
}

// A file only this user can read, made new (never an existing file or a link to one).
function privateFile(path, text) {
  const fd = openSync(path, FS.O_WRONLY | FS.O_CREAT | FS.O_EXCL | (FS.O_NOFOLLOW ?? 0), 0o600);
  try { writeSync(fd, text); } finally { closeSync(fd); }
  return path;
}

// ---------------------------------------------------------------------------------------------------------------
// The query.

// The options cliQuery maps to Claude Code's flags; any other is an error, never silently dropped. `hooks` must be
// empty (r3 H2): the agent passes no hooks in CLI mode, so W3's effort report is the SDK's only, the accepted gap.
const KNOWN = new Set(["resume", "forkSession", "sessionId", "persistSession", "includePartialMessages", "cwd", "mcpServers", "systemPrompt", "settingSources", "tools", "disallowedTools", "settings", "permissionMode", "strictMcpConfig", "plugins", "canUseTool", "hooks", "abortController", "maxTurns", "configDir"]);

// (a tool call's id and its full name, as a turn may hold them: closed, short formats; anything else ends the query, so
//  what a query retains per call is bounded: at most 64 + 64 ASCII characters, and the input only while unsettled)
const TOOL_USE_ID = /^[A-Za-z0-9_-]{1,64}$/;
const TOOL_NAME = /^[A-Za-z0-9_-]{1,64}$/;

const userMessage = (text, uuid) => ({ type: "user", message: { role: "user", content: text }, parent_tool_use_id: null, session_id: "", uuid });

/**
 * The SDK's query({prompt, options}), run by the pinned Claude Code (r2 §3). `prompt`: a string (one message, then
 * the input ends when the result comes) or an async iterable of user messages (Pair steering: each is written as it
 * comes, and the input ends when the iterable does). `deps`: for tests only (the binary, its environment, limits);
 * the release entry passes none.
 */
export function cliQuery({ prompt, options = {} }, deps = {}) {
  for (const k of Object.keys(options)) if (!KNOWN.has(k)) throw new Error(`cliQuery: the option ${k} isn't supported in CLI mode`);
  // (hooks: none can run in CLI mode, so a non-empty hooks option is an error (r3 H2); the agent passes none here)
  for (const list of Object.values(options.hooks ?? {})) if (!Array.isArray(list) || list.length) throw new Error("cliQuery: hooks can't run in CLI mode");
  if (options.settingSources !== undefined && !(Array.isArray(options.settingSources) && options.settingSources.length === 0)) throw new Error("cliQuery: only a closed launch (no setting sources) is supported in CLI mode");
  return new CliRun(prompt, options, deps);
}

class CliRun {
  constructor(prompt, options, deps) {
    this.prompt = prompt;
    this.o = options;
    this.limits = { ...CLI_LIMITS, ...(deps.limits ?? {}) };
    this.bin = deps.bin ?? null;
    this.env = deps.env ?? null;
    this.onListeners = deps.onListeners ?? null; // (tests: the listeners' ports, tokens and the permission tool's name)
    this.queue = []; // (messages read, not yet taken)
    this.queueSizes = []; // (their lines' UTF-8 bytes)
    this.queueBytes = 0;
    this.waiting = null; // (a next() waiting: its resolve)
    this.done = false;
    this.error = null;
    this.pending = new Map(); // (tool_use_id -> {name, input: canonical text, state: "pending" | "deciding" | "allowed" | "denied" | "ran"})
    this.seen = new Set(); // (every tool_use_id this query has shown: a second one with the same id is refused)
    this.unsettled = new Set(); // (the entries not yet settled, at most pendingMax: what the bounds count)
    this.idWaiters = new Set();
    this.abort = new AbortController(); // (ours: the caller's abort, an error, or return())
    this.cleanups = [];
    this.child = null;
    this.resultSeen = false;
    this.abort.signal.addEventListener("abort", () => this.finish(null), { once: true });
    const outer = options.abortController?.signal;
    if (outer) {
      if (outer.aborted) this.abort.abort();
      else outer.addEventListener("abort", () => this.abort.abort(), { once: true });
    }
    this.started = this.done ? Promise.resolve() : this.start().catch((e) => this.finish(e));
  }

  [Symbol.asyncIterator]() { return this; }

  next() {
    if (this.queue.length) {
      const value = this.queue.shift();
      this.queueBytes -= this.queueSizes.shift() ?? 0;
      if (this.paused && this.queue.length < this.limits.queueMax / 2 && this.queueBytes < this.limits.queueBytesMax / 2) {
        this.paused = false;
        this.drain(); // (the lines already read first, then the stream again)
        if (!this.paused) this.stream?.resume();
      }
      return Promise.resolve({ value, done: false });
    }
    if (this.done) return this.error ? Promise.reject(this.error) : Promise.resolve({ value: undefined, done: true });
    return new Promise((resolve, reject) => { this.waiting = { resolve, reject }; });
  }

  async return() {
    this.queue.length = 0;
    this.abort.abort();
    await this.started;
    await this.reaped;
    if (this.reapError) throw this.reapError;
    return { value: undefined, done: true };
  }

  push(msg, bytes = 0) {
    if (this.done) return;
    if (this.waiting) { const w = this.waiting; this.waiting = null; w.resolve({ value: msg, done: false }); }
    else {
      this.queue.push(msg);
      this.queueSizes.push(bytes);
      this.queueBytes += bytes;
      // (backpressure: a consumer that doesn't take messages stops the parsing and the reading, so what waits here is
      //  bounded in count and in bytes)
      if (this.queue.length >= this.limits.queueMax || this.queueBytes >= this.limits.queueBytesMax) this.paused = true;
    }
  }

  // The end, once: an error (or null for a plain end); the child's process group killed, the listeners closed, the
  // temp folder removed, every pending decision denied.
  finish(err) {
    if (this.done) return;
    this.done = true;
    if (this.eofTimer) { clearTimeout(this.eofTimer); this.eofTimer = null; }
    this.error = err && !this.abort.signal.aborted ? err : null;
    if (!this.abort.signal.aborted) this.abort.abort();
    for (const e of this.pending.values()) this.settle(e, "denied");
    for (const w of this.idWaiters) w();
    this.idWaiters.clear();
    this.kill();
    for (const c of this.cleanups.splice(0)) { try { c(); } catch {} }
    if (this.waiting) {
      const w = this.waiting; this.waiting = null;
      if (this.error && !this.queue.length) w.reject(this.error); else w.resolve(this.queue.length ? { value: this.queue.shift(), done: false } : { value: undefined, done: true });
    }
  }

  // The child's whole process group ended (POSIX): TERM to the group, then KILL to the group after the grace, again
  // until the group is empty, whether or not its leader has already exited (a descendant may outlive it, or ignore
  // TERM, and still hold the streams). `this.reaped` settles when the group is gone (or after a last KILL past the
  // bound). Windows: the job object ends the whole tree with the helper.
  // (the group id can't name another group while this one has a member: Linux doesn't hand out a pid that is still
  //  some process's group id. Each signal follows a check that the group still has a member, and the loop stops at
  //  the first check that finds it empty; what remains is the instant between the two calls, in which the last member
  //  would have to exit and the pid space wrap around to that number)
  kill() {
    const c = this.child;
    if (!c || this.killing) return;
    this.killing = true;
    try { c.stdin?.destroy(); c.stdout?.destroy(); c.stderr?.destroy(); } catch {}
    if (process.platform === "win32") {
      try { c.kill("SIGKILL"); } catch {}
      this.reaped = Promise.resolve();
      return;
    }
    const pg = c.pid;
    const sig = (s) => { try { process.kill(-pg, s); } catch {} };
    sig("SIGTERM");
    const t0 = Date.now();
    this.reaped = new Promise((done) => {
      const tick = () => {
        if (!groupAlive(pg)) return done();
        const waited = Date.now() - t0;
        if (waited >= this.limits.killGraceMs) sig("SIGKILL");
        // (a group that outlives 10 s of KILLs: said, never taken for empty; return() rejects with it)
        if (waited >= this.limits.killGraceMs + 10_000) { this.reapError = new Error(`processes of Claude Code's group ${pg} were still running after 10 s of KILL`); return done(); }
        setTimeout(tick, 50); // (referenced: this process doesn't exit while the group still has a member)
      };
      setTimeout(tick, 50);
    });
  }

  async start() {
    const o = this.o;
    const env = { ...(this.env ?? process.env) };
    if (o.configDir) env.CLAUDE_CONFIG_DIR = o.configDir;
    let bin = this.bin;
    if (!bin) {
      bin = claudeBinary();
      const why = claudeVersionProblem(bin, { env });
      if (why) throw new Error(why);
    }
    if (this.abort.signal.aborted) return;

    // (the tools and the permission tool, each on its own listener and token)
    const toolServers = {};
    for (const [name, s] of Object.entries(o.mcpServers ?? {})) {
      if (!s || s.type !== "sagebrush-cli" || !SERVER_NAME.test(name)) throw new Error(`cliQuery: the MCP server ${name} isn't one cliCreateServer made`);
      toolServers[name] = { tools: s.tools.map((t) => ({ name: t.name, description: t.description, inputSchema: t.inputSchema, call: (args, signal) => this.callTool(`mcp__${name}__${t.name}`, t, args, signal) })) };
    }
    const permName = `p_${randomBytes(8).toString("hex")}`;
    const permTool = `mcp__${permName}__decide`;
    const permServers = { [permName]: { tools: [{ name: "decide", description: "internal", inputSchema: { type: "object", properties: { tool_name: { type: "string" }, input: { type: "object" }, tool_use_id: { type: "string" } }, required: ["tool_name", "input"] }, call: (args) => this.permission(args) }] } };
    const expected = new Set([...Object.keys(toolServers), permName]);
    let connected;
    const allListed = new Promise((r) => { connected = r; });
    const onListed = (name) => { expected.delete(name); if (!expected.size) connected(); };
    const L = [];
    // (each listener is closed with the run, also one made after the run already ended while this awaited)
    const keep = (l) => { L.push(l); if (this.done) l.close(); else this.cleanups.push(() => { l.close(); }); return l; };
    if (Object.keys(toolServers).length) keep(await listener(toolServers, onListed, this.abort.signal));
    const perm = keep(await listener(permServers, onListed, this.abort.signal));
    if (this.done) return; // (the run ended while the listeners started: nothing is spawned)
    const tools = L.length === 2 ? L[0] : null;
    this.onListeners?.({ tools: tools && { port: tools.port, token: tools.token }, perm: { port: perm.port, token: perm.token, name: permName, tool: permTool } });

    // (the files Claude Code reads at start, in a private folder removed before the first user message: H1)
    const dir = mkdtempSync(join(tmpdir(), "sb-claude-"));
    let dirGone = false;
    const removeDir = () => { if (!dirGone) { dirGone = true; rmSync(dir, { recursive: true, force: true }); } };
    this.cleanups.push(removeDir);
    const mcpServers = {};
    for (const n of Object.keys(toolServers)) mcpServers[n] = { type: "http", url: `http://127.0.0.1:${tools.port}/${encodeURIComponent(n)}`, headers: { Authorization: `Bearer ${tools.token}` } };
    mcpServers[permName] = { type: "http", url: `http://127.0.0.1:${perm.port}/${permName}`, headers: { Authorization: `Bearer ${perm.token}` } };
    const args = ["-p", "--input-format", "stream-json", "--output-format", "stream-json", "--verbose", "--replay-user-messages"];
    if (o.includePartialMessages) args.push("--include-partial-messages");
    args.push("--mcp-config", privateFile(join(dir, "mcp.json"), JSON.stringify({ mcpServers })));
    args.push("--permission-prompt-tool", permTool);
    const disallowed = [permTool, ...(o.disallowedTools ?? [])];
    args.push("--disallowedTools", disallowed.join(","));
    if (o.resume) args.push("--resume", String(o.resume));
    if (o.forkSession) args.push("--fork-session");
    if (o.sessionId) args.push("--session-id", String(o.sessionId));
    if (o.persistSession === false) args.push("--no-session-persistence");
    // (r3 H2 (a): a closed launch, whatever the caller passes: no user, project or local settings, so none of their
    //  hooks, plugins, MCP servers or commands; only our two MCP servers; no slash commands)
    args.push("--setting-sources", "", "--disable-slash-commands");
    args.push("--strict-mcp-config");
    if (o.settings) args.push("--settings", privateFile(join(dir, "settings.json"), JSON.stringify(o.settings)));
    if (Array.isArray(o.tools)) args.push("--tools", o.tools.join(","));
    else if (o.tools?.type === "preset" && o.tools.preset === "claude_code") args.push("--tools", "default");
    else if (o.tools !== undefined) throw new Error("cliQuery: tools must be a list or the claude_code preset");
    if (typeof o.systemPrompt === "string") args.push("--system-prompt-file", privateFile(join(dir, "system.txt"), o.systemPrompt));
    else if (o.systemPrompt?.type === "preset" && o.systemPrompt.preset === "claude_code") {
      if (o.systemPrompt.append) args.push("--append-system-prompt-file", privateFile(join(dir, "append.txt"), o.systemPrompt.append));
    } else if (o.systemPrompt !== undefined) throw new Error("cliQuery: systemPrompt must be a string or the claude_code preset");
    if (o.permissionMode) args.push("--permission-mode", String(o.permissionMode));
    if (o.maxTurns) args.push("--max-turns", String(o.maxTurns));
    if (Array.isArray(o.plugins) && o.plugins.length) throw new Error("cliQuery: plugins aren't supported in CLI mode");

    // (the child: its own process group on POSIX, so a Stop ends everything it started; a job object on Windows)
    const spawnOpts = { cwd: o.cwd, env, stdio: ["pipe", "pipe", "pipe"], windowsHide: true };
    if (this.done) { removeDir(); return; } // (the run ended while this was set up: nothing is spawned)
    const child = this.child = process.platform === "win32" ? jobSpawn(bin, args, spawnOpts) : spawn(bin, args, { ...spawnOpts, detached: true });
    child.stdin.on("error", () => {});
    let stderr = "";
    child.stderr.on("data", (d) => { stderr = (stderr + d).slice(-this.limits.stderrKeep); });
    const exited = new Promise((r) => child.once("exit", (code, sig) => r({ code, sig })));
    child.once("error", (e) => this.finish(new Error(`Claude Code couldn't be started: ${e.message}`)));
    this.readLines(child.stdout);
    // (the exit is judged only once its output has all been read: stdout at its end and every buffered line parsed,
    //  which waits for the consumer while parsing is paused; a Stop still ends the run at once)
    exited.then(({ code, sig }) => {
      this.exitInfo = { code, sig, stderr };
      this.settleExit();
      this.armExitEof();
    });

    // (connected to both listeners, then the files removed, then the prompt: H1; fail closed on anything else)
    let timer;
    const outcome = await Promise.race([
      allListed.then(() => "connected"),
      exited.then(() => "exited"),
      new Promise((r) => { timer = setTimeout(() => r("timeout"), this.limits.connectMs); }),
      new Promise((r) => (this.abort.signal.aborted ? r("aborted") : this.abort.signal.addEventListener("abort", () => r("aborted"), { once: true }))),
    ]);
    clearTimeout(timer);
    if (outcome !== "connected") {
      removeDir();
      if (outcome === "timeout") this.finish(new Error("Claude Code didn't connect to this agent's tools in time"));
      return;
    }
    removeDir();
    if (this.done) return;
    // (the input pump runs on its own: a Stop never waits for the prompt's producer, which may be blocked; a late
    //  failure of the producer ends the run, and the producer is told to stop when the run ends)
    this.pump = this.writePrompt(child).catch((e) => this.finish(e));
  }

  async writePrompt(child) {
    const write = (m) => { if (!this.done) child.stdin.write(JSON.stringify(m) + "\n"); };
    // (when the run ends, the producer is asked to stop, without waiting for it)
    if (typeof this.prompt !== "string") this.cleanups.push(() => { Promise.resolve().then(() => this.prompt.return?.()).catch(() => {}); });
    if (typeof this.prompt === "string") {
      write(userMessage(this.prompt, randomUUID()));
      return; // (the input ends when the result comes: readLines)
    }
    try {
      for await (const m of this.prompt) {
        if (this.done) return;
        write(m);
      }
    } catch (e) {
      return this.finish(e);
    }
    if (!this.done) child.stdin.end();
  }

  // Claude Code's stdout, one JSON message a line. Parsing stops while the queue is full (`paused`), both the stream
  // and the lines already read: what waits is at most queueMax messages, queueBytesMax bytes, and one chunk of unsplit
  // text; it goes on when messages are taken (next()).
  readLines(stream) {
    this.buf = "";
    this.stream = stream;
    stream.setEncoding("utf8");
    stream.on("data", (d) => {
      this.buf += d;
      this.drain();
    });
    stream.on("error", () => {});
    stream.on("end", () => { this.stdoutEnded = true; this.drain(); });
    stream.on("close", () => { if (!this.stdoutEnded) { this.stdoutEnded = true; this.drain(); } });
  }

  // (the child has exited, but its output stays open while this reads it unpaused: a descendant holds it. After
  //  exitEofMs the run ends with what was read: a success only after a result and exit 0, else an error; finish()'s
  //  kill() then ends the group, with its bound and its reapError. Paused time doesn't count)
  armExitEof() {
    if (this.done || !this.exitInfo || this.stdoutEnded || this.paused || this.eofTimer) return;
    this.eofTimer = setTimeout(() => {
      this.eofTimer = null;
      if (this.done || this.stdoutEnded || this.paused) return; // (re-armed when reading resumes)
      if (this.buf.indexOf("\n") >= 0) return this.drain(); // (lines still to parse first; drain() re-arms)
      const { code, sig, stderr } = this.exitInfo;
      if (this.resultSeen && code === 0) return this.finish(null);
      this.finish(new Error(`Claude Code stopped (${sig ?? `exit ${code}`}) and its output stayed open${stderr.trim() ? `: ${stderr.trim().slice(-500)}` : ""}`));
    }, this.limits.exitEofMs);
  }

  // (the child has exited and its output is all parsed: the run ends, as a success only after a result and exit 0)
  settleExit() {
    if (this.done || !this.exitInfo || !this.stdoutEnded || this.paused) return;
    if (this.buf.indexOf("\n") >= 0) return; // (lines still to parse: drain() comes back here)
    if (this.buf.trim()) { const rest = this.buf; this.buf = ""; const bytes = Buffer.byteLength(rest, "utf8"); if (bytes > this.limits.lineMax) return this.finish(new Error("Claude Code sent a message that is too large")); this.line(rest, bytes); if (this.done || this.paused) return; }
    const { code, sig, stderr } = this.exitInfo;
    // (a result says how the run ended: exit 0 after it, or a non-zero exit after an error result, which is how Claude
    //  Code ends a run it refused, as when it isn't signed in; the result has said why)
    if (this.resultSeen && (code === 0 || (this.resultError && sig === null))) return this.finish(null);
    this.finish(new Error(`Claude Code stopped (${sig ?? `exit ${code}`})${stderr.trim() ? `: ${stderr.trim().slice(-500)}` : ""}`));
  }

  drain() {
    let i;
    while (!this.done && !this.paused && (i = this.buf.indexOf("\n")) >= 0) {
      const line = this.buf.slice(0, i);
      this.buf = this.buf.slice(i + 1);
      // (each whole line within the bound, measured in bytes before it's parsed; then the unfinished rest, below)
      const bytes = Buffer.byteLength(line, "utf8");
      if (bytes > this.limits.lineMax) return this.finish(new Error("Claude Code sent a message that is too large"));
      if (line.trim()) this.line(line, bytes);
    }
    if (this.paused) { this.stream?.pause(); if (this.eofTimer) { clearTimeout(this.eofTimer); this.eofTimer = null; } }
    if (!this.done && Buffer.byteLength(this.buf, "utf8") > this.limits.lineMax + 65536) return this.finish(new Error("Claude Code sent a message that is too large"));
    this.settleExit();
    this.armExitEof();
  }

  line(text, bytes = Buffer.byteLength(text, "utf8")) {
    if (this.done) return;
    let m;
    try { m = JSON.parse(text); } catch { return this.finish(new Error("Claude Code sent something that isn't JSON")); }
    if (!m || typeof m !== "object") return;
    if (m.type === "assistant" && Array.isArray(m.message?.content)) {
      for (const b of m.message.content) {
        if (b?.type !== "tool_use") continue;
        if (typeof b.id !== "string" || !TOOL_USE_ID.test(b.id) || typeof b.name !== "string" || !TOOL_NAME.test(b.name)) return this.finish(new Error("Claude Code named a tool call this agent can't follow"));
        this.expect(b.id, b.name, b.input);
      }
    }
    if (m.type === "result") {
      this.resultSeen = true;
      this.resultError = m.is_error === true;
      if (typeof this.prompt === "string") this.child?.stdin.end();
    }
    this.push(m, bytes);
  }

  // A tool call the stream shows: pending a decision, bound to its id, exact name and canonical input (H2).
  expect(id, name, input) {
    if (this.seen.has(id)) { const e = this.pending.get(id); if (e) this.settle(e, "denied"); return; } // (an id shown twice: neither is answered)
    if (this.seen.size >= this.limits.seenMax) return this.finish(new Error("Claude Code made more tool calls in one turn than this agent follows"));
    this.seen.add(id);
    // (the bound counts every entry not yet settled: waiting for its decision, being decided, or allowed and not run)
    if (this.unsettled.size >= this.limits.pendingMax) return;
    const c = canon(input ?? {}, this.limits.bodyMax);
    // (the held-input budget, in canonical UTF-8 bytes, over every unsettled entry: past it, not held, so denied)
    if (c.ok && this.heldBytes() + c.bytes > this.limits.heldInputBytes) return;
    const e = { name, input: c.ok ? c.text : null, bytes: c.ok ? c.bytes : 0, state: "pending" };
    this.pending.set(id, e);
    this.unsettled.add(e);
    for (const w of this.idWaiters) w();
  }

  // (an entry settled, ran or denied: neither its name nor its input is kept; the entry stays, so its id is never
  //  answered again)
  settle(e, state) {
    e.state = state;
    e.input = null;
    e.name = null;
    e.bytes = 0;
    this.unsettled.delete(e);
  }

  // (the canonical UTF-8 bytes of the inputs held by unsettled entries, `but` one)
  heldBytes(but = null) {
    let n = 0;
    for (const e of this.unsettled) if (e !== but) n += e.bytes;
    return n;
  }

  // (wait until a tool call shows in the stream, the run ends, or `until`)
  idChanged(until) {
    return new Promise((r) => { const w = () => { this.idWaiters.delete(w); clearTimeout(t); r(); }; const t = setTimeout(w, Math.max(0, until - Date.now())); this.idWaiters.add(w); });
  }

  // A tool call over the tools listener runs only after the person's decision has allowed exactly it (r3.1, T3/H1):
  // the same full name and the canonical input that was allowed (updatedInput, if the decision changed it), in state
  // "allowed", moved to "ran" before the handler starts. Anything else, now, is refused with no effect: pending or
  // deciding (a decision not yet made), denied, unknown, already run, or the run ended. The permission tool sets
  // "allowed" before its answer goes back, so Claude Code's own call always finds it; nothing waits here. (Every call
  // of ours comes through the permission tool: the launch is closed, so no allow rule lets one past it; one that did
  // would be refused here, failing closed.)
  async callTool(full, t, args, signal) {
    const c = canon(args ?? {}, this.limits.bodyMax);
    const e = !this.done && c.ok ? [...this.unsettled].find((x) => x.name === full && x.input === c.text && x.state === "allowed") : null;
    if (!e) return { content: [{ type: "text", text: "refused: this tool call wasn't allowed" }], isError: true };
    this.settle(e, "ran");
    const parsed = t.schema.safeParse(args);
    if (!parsed.success) return { content: [{ type: "text", text: `invalid arguments: ${parsed.error.message.slice(0, 1000)}` }], isError: true };
    return await t.handler(parsed.data, { signal });
  }

  // --permission-prompt-tool: answered only for a pending tool call whose id, name and canonical input all match,
  // consumed at once; everything else is denied (H2). The decision itself is the caller's canUseTool.
  async permission(a) {
    const deny = (message) => ({ content: [{ type: "text", text: JSON.stringify({ behavior: "deny", message }) }] });
    const id = typeof a?.tool_use_id === "string" ? a.tool_use_id : null;
    const name = typeof a?.tool_name === "string" ? a.tool_name : null;
    if (!id || !name || !a.input || typeof a.input !== "object" || Array.isArray(a.input)) return deny("refused: not a permission request this agent can answer");
    if (!this.pending.has(id) && !this.done) {
      const until = Date.now() + this.limits.permissionWaitMs;
      while (!this.pending.has(id) && !this.done && Date.now() < until) await this.idChanged(until);
    }
    const e = this.pending.get(id);
    if (this.done || !e || e.state !== "pending") return deny("refused: no such tool call is waiting for a decision");
    const c = canon(a.input, this.limits.bodyMax);
    if (e.name !== name || !c.ok || e.input !== c.text) return deny("refused: the request doesn't match the tool call");
    e.state = "deciding";
    let r;
    try { r = await this.o.canUseTool(name, a.input, { signal: this.abort.signal, toolUseID: id, suggestions: [] }); } catch (err) { if (e.state === "deciding") this.settle(e, "denied"); return deny(String(err?.message ?? err)); }
    // (while the person decided, the entry may have changed: the same id shown again, so neither call is answered, or
    //  the run ended. Only an entry still "deciding", the same object, takes the answer; anything else is a deny that
    //  changes nothing: denied never becomes allowed)
    if (this.pending.get(id) !== e || e.state !== "deciding") return deny("refused: the tool call changed while it was decided");
    if (this.done) { this.settle(e, "denied"); return deny("The turn ended."); }
    if (r?.behavior === "allow") {
      const updated = r.updatedInput ?? a.input;
      const u = canon(updated, this.limits.bodyMax);
      if (!u.ok) { this.settle(e, "denied"); return deny("refused: the allowed input can't be checked"); }
      // (the allowed input replaces the held one only within the budget, checked with every other held input)
      if (this.heldBytes(e) + u.bytes > this.limits.heldInputBytes) { this.settle(e, "denied"); return deny("refused: the allowed input is larger than this agent holds"); }
      e.input = u.text; // (the call that may now run is the allowed one)
      e.bytes = u.bytes;
      e.state = "allowed";
      return { content: [{ type: "text", text: JSON.stringify({ behavior: "allow", updatedInput: updated }) }] };
    }
    this.settle(e, "denied");
    return deny(typeof r?.message === "string" ? r.message : "Denied.");
  }
}

// ---------------------------------------------------------------------------------------------------------------
// Transcripts (r2 §7): this run's sessions removed when the daemon stops, by exact name, links never followed.

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
export async function cliDeleteSession(sessionId, { configDir = process.env.CLAUDE_CONFIG_DIR || join(homedir(), ".claude") } = {}) {
  if (!UUID.test(String(sessionId))) throw new Error("not a session id");
  const projects = join(configDir, "projects");
  let dirs;
  try { dirs = readdirSync(projects, { withFileTypes: true }); } catch (e) { if (e?.code === "ENOENT") return; throw e; }
  for (const d of dirs) {
    if (!d.isDirectory()) continue;
    for (const name of [`${sessionId}.jsonl`, sessionId]) {
      const p = join(projects, d.name, name);
      let st;
      try { st = lstatSync(p); } catch { continue; }
      if (st.isSymbolicLink()) continue;
      rmSync(p, { recursive: st.isDirectory(), force: true });
    }
  }
}

// ---------------------------------------------------------------------------------------------------------------
// SDK mode's guard (r2 §1, H3): the SDK's query, its prompt held back until the initialize answer shows the selected
// non-subscription credential and nothing else; any other answer (or none in time) ends the query before the prompt
// exists for it. `select`: "apiKey" or a provider, as claudeMode chose.

// (r3 H1: the API key selector's one source; an apiKeyHelper would be its own selector, with its own exact pair)
const ALLOWED_KEY_SOURCES = new Set(["ANTHROPIC_API_KEY"]);
const NONE = (v) => v === undefined || v === "none";

/** Why the initialize answer doesn't match the selection, or null. */
export function accountProblem(info, select) {
  if (!info || typeof info !== "object") return "no answer";
  const known = new Set(["tokenSource", "apiKeySource", "apiProvider", "email", "organization", "subscriptionType"]);
  for (const k of Object.keys(info)) if (!known.has(k)) return `an unknown field ${k}`;
  if (!NONE(info.tokenSource)) return `a Claude login (${String(info.tokenSource).slice(0, 40)})`;
  if (info.subscriptionType !== undefined && info.subscriptionType !== null) return "a Claude subscription";
  if (select === "apiKey") {
    if (info.apiProvider !== "firstParty") return `the provider ${String(info.apiProvider).slice(0, 20)}`;
    if (!ALLOWED_KEY_SOURCES.has(info.apiKeySource)) return `the key source ${String(info.apiKeySource ?? "none").slice(0, 40)}`;
    return null;
  }
  if (info.apiProvider !== select) return `the provider ${String(info.apiProvider).slice(0, 20)}, not ${select}`;
  if (!NONE(info.apiKeySource)) return `the key source ${String(info.apiKeySource).slice(0, 40)}`;
  return null;
}

export function sdkGuard(query, select, { limits = CLI_LIMITS } = {}) {
  return ({ prompt, options = {} }) => {
    const abort = new AbortController();
    const outer = options.abortController?.signal;
    if (outer) { if (outer.aborted) abort.abort(); else outer.addEventListener("abort", () => abort.abort(), { once: true }); }
    let open, resultSeen;
    const gate = new Promise((r) => { open = r; });
    const ended = new Promise((r) => { resultSeen = r; });
    abort.signal.addEventListener("abort", () => { open(false); resultSeen(); }, { once: true });
    const held = (async function* () {
      if (!(await gate)) return;
      if (typeof prompt === "string") {
        yield userMessage(prompt, randomUUID());
        await ended; // (one message: the input ends when its result comes, as a string prompt's does)
      } else {
        for await (const m of prompt) yield m;
      }
    })();
    const q = query({ prompt: held, options: { ...options, abortController: abort } });
    const it = q[Symbol.asyncIterator]();
    let checked = null;
    const check = () => (checked ??= (async () => {
      let t;
      const info = await Promise.race([
        q.accountInfo(),
        new Promise((_, fail) => { t = setTimeout(() => fail(new Error("no answer in time")), limits.guardMs); }),
        new Promise((_, fail) => (abort.signal.aborted ? fail(new Error("stopped")) : abort.signal.addEventListener("abort", () => fail(new Error("stopped")), { once: true }))),
      ]).finally(() => clearTimeout(t));
      const why = accountProblem(info, select);
      if (why) throw new Error(`SDK mode found ${why}, not the ${select === "apiKey" ? "API key" : select} this agent was started with, so nothing was sent`);
      open(true);
    })().catch((e) => { abort.abort(); throw e; }));
    return {
      [Symbol.asyncIterator]() { return this; },
      async next() {
        await check();
        const step = await it.next();
        if (!step.done && step.value?.type === "result") resultSeen();
        return step;
      },
      async return() { abort.abort(); return it.return ? it.return() : { done: true }; },
      accountInfo: () => q.accountInfo(),
    };
  };
}
