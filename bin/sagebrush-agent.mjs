#!/usr/bin/env node
// sagebrush-agent: chat with Claude in Sagebrush. Runs Claude on this computer
// (the Claude Agent SDK, with your own Claude login) and waits for a
// Sagebrush page to pair with it over the loopback address.
//
//   npx sagebrush-agent [--port N] [--origin https://...]
//
// Then open the link it prints (or enter the code and port in the page): on <origin>/agents/ with one --origin,
// else on sagebrush.space; SAGEBRUSH_AGENT_PAGE sets the link's page instead.
//
//   sagebrush-agent --stdio
//
// is how `sagebrush remote --serve-agents --agent-cmd ...` runs it: the page is
// reached through the runner, one JSON message per line on stdin and stdout
// (stdout carries nothing else). SIGINT stops the running turns; SIGTERM, or
// the end of stdin, stops the agent.
//
//   sagebrush-agent --codex --stdio
//
// runs Codex there instead: one pinned release, fetched and checked (never the
// `codex` on PATH), as `codex app-server` with that computer's Codex login and
// settings: only over the runner, and only for a connection with shell and files on.
//
//   sagebrush-agent --pair-stdin --origin http://127.0.0.1:<port> --port 0
//
// is how the desktop app starts it (lib/pair-stdin.mjs): the app's own page is the only origin, the app hands the one-time
// code over stdin, and the agent prints only {"v":1,"listening":<port>} on stdout. The end of stdin stops it.

import { fileURLToPath } from "node:url";
import { AgentServer, DEFAULT_ORIGINS, TEXT } from "../lib/server.mjs";
import { stdinChunks } from "../lib/stdio.mjs";
import { pairOrigin, readPairLine } from "../lib/pair-stdin.mjs";
import { stdioOutput } from "../lib/stdout-thread.mjs";

// An exact http(s) origin, like https://example.org or http://127.0.0.1:8000: no path, no wildcard.
function exactOrigin(s) {
  let u;
  try { u = new URL(s); } catch { u = null; }
  if (!u || (u.protocol !== "https:" && u.protocol !== "http:") || u.origin !== s) {
    console.error(`--origin needs an exact origin like https://example.org (not ${JSON.stringify(s)})`);
    process.exit(2);
  }
  return s;
}

const args = process.argv.slice(2);
let port = 0;
let stdio = false;
let codex = false;
let loopbackFlags = false;
let pairStdin = false;
let portGiven = null;
const given = [];
for (let i = 0; i < args.length; i++) {
  if (args[i] === "--port") { portGiven = String(args[++i]); port = Number(portGiven); loopbackFlags = true; }
  else if (args[i] === "--origin") { given.push(String(args[++i])); loopbackFlags = true; }
  else if (args[i] === "--pair-stdin") pairStdin = true;
  else if (args[i] === "--stdio") stdio = true;
  else if (args[i] === "--codex") codex = true;
  else if (args[i] === "--help" || args[i] === "-h") {
    console.log("usage: sagebrush-agent [--port N] [--origin https://...]\n       (prints a link to <origin>/agents/ with one --origin, else to https://sagebrush.space/agents/;\n        SAGEBRUSH_AGENT_PAGE=<url> sets the link's page instead)\n       sagebrush-agent [--codex] --stdio   (run by sagebrush remote --serve-agents)\n       sagebrush-agent --pair-stdin --origin http://127.0.0.1:<port> --port 0   (run by the desktop app)");
    process.exit(0);
  } else {
    console.error(`unknown argument: ${args[i]}`);
    process.exit(2);
  }
}
// (--pair-stdin: exactly the app page's origin, http://127.0.0.1:<port>, never the default ones; the port the app
//  passes is 0, so the agent picks a free one and reports it; nothing else on the command line)
let origins;
if (pairStdin) {
  if (stdio || codex) {
    console.error("--pair-stdin can't be used with --stdio or --codex");
    process.exit(2);
  }
  if (given.length !== 1 || !pairOrigin(given[0])) {
    console.error("--pair-stdin needs exactly one --origin http://127.0.0.1:<port>");
    process.exit(2);
  }
  if (portGiven !== "0") {
    console.error("--pair-stdin needs --port 0");
    process.exit(2);
  }
  origins = [given[0]];
} else {
  origins = [...DEFAULT_ORIGINS, ...given.map(exactOrigin)];
}
if (codex && !stdio) {
  console.error("--codex works only with --stdio: Codex is run by sagebrush remote --serve-agents, with shell and files on");
  process.exit(2);
}
if (stdio && loopbackFlags) {
  console.error("--stdio can't be used with --port or --origin: the runner is the only peer");
  process.exit(2);
}

let query, createServer, deleteSession;
// (native mode's permission mode: the SDK's own settings resolver and the CLI's trust filter, with the fake model too)
const { resolveSettings, filterEscalatingDefaultMode } = await import("@anthropic-ai/claude-agent-sdk");
const resolver = { resolveSettings, filterEscalatingDefaultMode };
if (process.env.SAGEBRUSH_AGENT_FAKE === "1") {
  // The fake model, for tests: chosen only by this variable, set where the agent is started; nothing the page or
  // the runner sends can choose it.
  const fake = await import("../lib/fake.mjs");
  ({ fakeQuery: query, fakeCreateServer: createServer } = fake);
  console.error("FAKE model: no Claude, for testing");
} else {
  const sdk = await import("@anthropic-ai/claude-agent-sdk");
  query = sdk.query;
  deleteSession = sdk.deleteSession;
  createServer = (spec) => sdk.createSdkMcpServer({ name: spec.name, version: spec.version, tools: spec.tools.map(([name, description, shape, handler]) => sdk.tool(name, description, shape, handler)) });
}

if (stdio) {
  const server = new AgentServer({ query, deleteSession, stdio: true, resolver, ...(codex ? { name: "Codex", client: "codex-app-server" } : {}) });
  server.createServer = createServer;
  if (codex) {
    const { CodexBackend } = await import("../lib/codex.mjs");
    // (the fake app-server, for tests: chosen only by SAGEBRUSH_AGENT_FAKE=1, like the fake model)
    // (the real one: the pinned Codex, fetched and checked by the backend, never `codex` from PATH)
    const command = process.env.SAGEBRUSH_AGENT_FAKE === "1" ? [process.execPath, fileURLToPath(new URL("../lib/fake-codex.mjs", import.meta.url))] : null;
    server.backend = new CodexBackend(server, { command });
  }
  // (stdout: on Windows, a thread does the writes, so a runner that stops reading never blocks this process:
  //  lib/stdout-thread.mjs; elsewhere process.stdout itself)
  const output = stdioOutput();
  let stopping = false;
  const stop = async (code = 0) => {
    if (stopping) return;
    stopping = true;
    let problems;
    try { problems = await server.close(); } catch (e) { problems = [String(e?.message ?? e)]; }
    for (const p of problems) console.error(p);
    // (what the thread still holds is written first, waiting at most 500 ms for a runner that stopped reading)
    await output.flush?.(500);
    process.exit(problems.length ? 1 : code);
  };
  const fatal = (text) => { console.error(text); stop(1); };
  // (a runner that went away: nothing more can be written)
  output.on("error", () => stop(0));
  process.on("SIGINT", () => server.stopTurns());
  process.once("SIGTERM", () => stop(0));
  await server.serveStdio({ input: stdinChunks(), output, fatal });
  if (!server.stdioStarted) fatal(TEXT.badStart);
  else stop(0);
} else if (pairStdin) {
  // (the code first: a launch without a valid line never listens)
  let stopAfter = null;
  let code;
  try {
    code = await readPairLine(process.stdin, { onAfter: (why) => stopAfter ? stopAfter(why) : process.exit(1) });
  } catch (e) {
    console.error(`--pair-stdin: ${e.message}`);
    process.exit(2);
  }
  await listenLoopback({ appCode: code, onStop: (f) => { stopAfter = f; } });
} else {
await listenLoopback();
}

async function listenLoopback({ appCode = null, onStop = null } = {}) {
const server = new AgentServer({ port, origins, query, deleteSession });
server.createServer = createServer;
// Delegate tasks (design/workspace-agent-protocol.md §6), over this loopback pairing only: on where the tasks folder
// (~/.sagebrush/tasks) can be used, else off, saying why.  The page shows Delegate only under the person's own switch.
// (with the fake model, for tests: only in the folder SAGEBRUSH_TASKS_HOME names, else off; never the real home)
const fakeHome = process.env.SAGEBRUSH_AGENT_FAKE === "1" ? process.env.SAGEBRUSH_TASKS_HOME || null : undefined;
if (fakeHome !== null) try {
  const { TaskStore } = await import("../lib/tasks.mjs");
  const { TaskTurns, claudeProjects } = await import("../lib/task-turns.mjs");
  const { TaskRpc } = await import("../lib/task-rpc.mjs");
  const { installationId } = await import("../lib/installation.mjs");
  const { join } = await import("node:path");
  const store = fakeHome
    ? new TaskStore({ root: join(fakeHome, ".sagebrush", "tasks"), scope: installationId(fakeHome), transcripts: claudeProjects({ CLAUDE_CONFIG_DIR: join(fakeHome, ".claude") }) }).init()
    : new TaskStore({ scope: installationId(), transcripts: claudeProjects() }).init();
  // (the runner: refuses every run in this version, saying why; RUNS_ENABLED is turned on only by a reviewed change)
  const { TaskRunner } = await import("../lib/task-runner.mjs");
  const turns = new TaskTurns({ store, query, createServer, log: (m) => console.error(m), runner: new TaskRunner({ store }) });
  server.setTasks({ store, turns, rpc: new TaskRpc({ store, turns }) });
} catch (e) {
  console.error(`Delegate tasks are off on this computer: ${e?.message ?? e}`);
}
if (appCode) server.setAppCode(appCode);
const p = await server.listen();
if (appCode) {
  // (the one stdout line, before anything else; then stdout carries nothing: the app reads only that line, and
  //  everything else this process says goes to stderr, which the app keeps out of its general log)
  process.stdout.write(JSON.stringify({ v: 1, listening: p }) + "\n");
  console.log = console.error;
  const stop = async (why) => {
    console.error(why === "data" ? "stopping: unexpected input on stdin" : "stopping: the app is gone");
    let problems;
    try { problems = await server.close(); } catch (e) { problems = [String(e?.message ?? e)]; }
    for (const q of problems) console.error(`  ${q}`);
    process.exit(problems.length || why === "data" ? 1 : 0);
  };
  onStop(stop);
  process.once("SIGINT", () => stop("end"));
  process.once("SIGTERM", () => stop("end"));
  return;
}
// (#1620: a code that expires while no page is paired is replaced, and its link printed on one line: the newest link
//  printed always works. Set before the first code, whose expiry starts it)
server.onCodeRenewed = (c) => console.log(`The last code expired unused. To connect a page, open:  ${page}?pair=${c}&port=${p}`);
const code = server.newCode();
// The printed link: SAGEBRUSH_AGENT_PAGE if it is set; else, with exactly one --origin, that origin's /agents/; else
// sagebrush.space's. Either changes only the printed link, never the allowed origins.
const pageEnv = process.env.SAGEBRUSH_AGENT_PAGE;
const page = (pageEnv ?? (given.length === 1 ? `${given[0]}/agents/` : "https://sagebrush.space/agents/")).replace(/\/?$/, "/");
if (!/^https?:$/.test(new URL(page, "x:/").protocol)) {
  console.error("SAGEBRUSH_AGENT_PAGE must be an http(s) URL");
  process.exit(2);
}
console.log(`
Sagebrush agent: Claude on this computer, waiting for your Sagebrush page.

  Open:  ${page}?pair=${code}&port=${p}
  (or enter code ${code} and port ${p} in the page)
${pageEnv === undefined && given.length > 1 ? "  (with more than one --origin this link opens sagebrush.space: set SAGEBRUSH_AGENT_PAGE to choose the page)\n" : ""}
The code works once, for 5 minutes; a new one is printed here each time the page goes away, or the last one expires unused.
Claude uses your own Claude login, and only the workspace files you allow in the page.
Press Ctrl+C to stop (this run's conversation transcripts are deleted then).
`);
// (a fresh one-time link each time the page goes away. A new code ends only the old code; it never ends the page's
//  session or a running turn. (No terminal input is read: a background job reading its terminal would be stopped.))
const fresh = (why) => {
  const c = server.newCode();
  console.log(`
${why} To connect a page, open:

  ${page}?pair=${c}&port=${p}
  (or enter code ${c} and port ${p} in the page)

The code works once, for 5 minutes. A page that reconnects by itself doesn't need it.
`);
};
server.onPageGone = () => fresh("The page disconnected; Claude's turns go on.");

const stop = async () => {
  console.error("stopping: deleting this run's transcripts ...");
  let problems;
  try { problems = await server.close(); } catch (e) { problems = [String(e?.message ?? e)]; }
  for (const p of problems) console.error(`  ${p}`);
  console.error(problems.length ? "stopped, but see above." : "stopped; this run's transcripts are deleted.");
  process.exit(problems.length ? 1 : 0);
};
process.once("SIGINT", stop);
process.once("SIGTERM", stop);
}
