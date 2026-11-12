#!/usr/bin/env node
// sagebrush-agent: chat with Claude in Sagebrush. Runs Claude on this computer
// (the Claude Agent SDK, with your own Claude login) and waits for a
// Sagebrush page to pair with it over the loopback address.
//
//   npx sagebrush-agent [--port N] [--origin https://...]
//
// Then open the link it prints (or enter the code and port in the page).
//
//   sagebrush-agent --stdio
//
// is how `sagebrush remote --serve-agents --agent-cmd ...` runs it: the page is
// reached through the runner, one JSON message per line on stdin and stdout
// (stdout carries nothing else). SIGINT stops the running turns; SIGTERM, or
// the end of stdin, stops the agent.

import { AgentServer, DEFAULT_ORIGINS, TEXT } from "../lib/server.mjs";
import { stdinChunks } from "../lib/stdio.mjs";

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
let loopbackFlags = false;
const origins = [...DEFAULT_ORIGINS];
for (let i = 0; i < args.length; i++) {
  if (args[i] === "--port") { port = Number(args[++i]); loopbackFlags = true; }
  else if (args[i] === "--origin") { origins.push(exactOrigin(String(args[++i]))); loopbackFlags = true; }
  else if (args[i] === "--stdio") stdio = true;
  else if (args[i] === "--help" || args[i] === "-h") {
    console.log("usage: sagebrush-agent [--port N] [--origin https://...]\n       sagebrush-agent --stdio   (run by sagebrush remote --serve-agents)");
    process.exit(0);
  } else {
    console.error(`unknown argument: ${args[i]}`);
    process.exit(2);
  }
}
if (stdio && loopbackFlags) {
  console.error("--stdio can't be used with --port or --origin: the runner is the only peer");
  process.exit(2);
}

let query, createServer, deleteSession;
if (process.env.SAGEBRUSH_AGENT_FAKE === "1") {
  // The fake model is only in the source checkout, not in the published package.
  const fake = await import("../lib/fake.mjs").catch(() => {
    console.error("SAGEBRUSH_AGENT_FAKE needs the source checkout (lib/fake.mjs isn't published)");
    process.exit(2);
  });
  ({ fakeQuery: query, fakeCreateServer: createServer } = fake);
  console.error("FAKE model: no Claude, for testing");
} else {
  const sdk = await import("@anthropic-ai/claude-agent-sdk");
  query = sdk.query;
  deleteSession = sdk.deleteSession;
  createServer = (spec) => sdk.createSdkMcpServer({ name: spec.name, version: spec.version, tools: spec.tools.map(([name, description, shape, handler]) => sdk.tool(name, description, shape, handler)) });
}

if (stdio) {
  const server = new AgentServer({ query, deleteSession, stdio: true });
  server.createServer = createServer;
  let stopping = false;
  const stop = async (code = 0) => {
    if (stopping) return;
    stopping = true;
    let problems;
    try { problems = await server.close(); } catch (e) { problems = [String(e?.message ?? e)]; }
    for (const p of problems) console.error(p);
    process.exit(problems.length ? 1 : code);
  };
  const fatal = (text) => { console.error(text); stop(1); };
  // (a runner that went away: nothing more can be written)
  process.stdout.on("error", () => stop(0));
  process.on("SIGINT", () => server.stopTurns());
  process.once("SIGTERM", () => stop(0));
  await server.serveStdio({ input: stdinChunks(), output: process.stdout, fatal });
  if (!server.stdioStarted) fatal(TEXT.badStart);
  else stop(0);
} else {
await listenLoopback();
}

async function listenLoopback() {
const server = new AgentServer({ port, origins, query, deleteSession });
server.createServer = createServer;
const p = await server.listen();
const code = server.newCode();
// SAGEBRUSH_AGENT_PAGE changes only the printed link, never the allowed origins.
const page = (process.env.SAGEBRUSH_AGENT_PAGE ?? "https://sagebrush.space/agents/").replace(/\/?$/, "/");
if (!/^https?:$/.test(new URL(page, "x:/").protocol)) {
  console.error("SAGEBRUSH_AGENT_PAGE must be an http(s) URL");
  process.exit(2);
}
console.log(`
Sagebrush agent: Claude on this computer, waiting for your Sagebrush page.

  Open:  ${page}?pair=${code}&port=${p}
  (or enter code ${code} and port ${p} in the page)

The code works once, for 5 minutes. Claude uses your own Claude login, and only the
workspace files you allow in the page. Press Ctrl+C to stop (this run's conversation
transcripts are deleted then).
`);
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
