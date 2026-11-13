#!/usr/bin/env node
// The nightly check: is upstream's newest Codex still one this agent could drive, before we move the pin to it? It
// downloads that release's linux-x64 tarball (checked against the registry's integrity), asks it for its own
// protocol (no model call, an empty CODEX_HOME) and runs the self-test's contract against it. Also notes the newest
// Claude Agent SDK beside ours. Writes a report; on a red (a contract problem, or a check that couldn't run) it
// calls the alert command with a short message file. A green alerts nobody. It changes nothing users get: not the
// pin, not the contract, nothing in lib/.
//
//   node scripts/codex-nightly.mjs <report dir> [--alert "<command reading the message file as $1>"]

import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gunzipSync } from "node:zlib";
import { PIN, tarSink } from "../lib/codex-fetch.mjs";
import { checkContract, generateSchemas } from "../lib/codex-selftest.mjs";

const SDK = "@anthropic-ai/claude-agent-sdk";

export async function latest(pkg, fetchFn = fetch) {
  const r = await fetchFn(`https://registry.npmjs.org/${pkg.replace("/", "%2f")}`, { headers: { accept: "application/vnd.npm.install-v1+json" } });
  if (!r.ok) throw new Error(`${pkg}: HTTP ${r.status}`);
  return (await r.json())["dist-tags"].latest;
}

// (the release's linux-x64 codex, unpacked by the agent's own reader into `work`; its path)
export async function codexBinary(version, work, fetchFn = fetch) {
  const meta = await (await fetchFn(`https://registry.npmjs.org/@openai/codex/${version}-linux-x64`)).json();
  const bytes = Buffer.from(await (await fetchFn(meta.dist.tarball)).arrayBuffer());
  const integrity = "sha512-" + createHash("sha512").update(bytes).digest("base64");
  if (integrity !== meta.dist.integrity) throw new Error(`@openai/codex@${version}-linux-x64: integrity mismatch`);
  const dir = mkdtempSync(join(work, "codex-"));
  const sink = tarSink(dir, null);
  sink.write(gunzipSync(bytes));
  sink.end();
  return join(dir, "vendor/x86_64-unknown-linux-musl/bin/codex");
}

/** One night's check. `deps` are stand-ins for tests: latest, codexBinary, schemaOf (bin -> definitions). */
export async function nightly({ work, pinned = PIN.version, ours = sdkOurs(), deps = {} } = {}) {
  const { latest: newest = latest, codexBinary: binOf = codexBinary, schemaOf = (bin) => generateSchemas([bin, "app-server", "generate-json-schema", "--experimental"], { env: { ...process.env, CODEX_HOME: mkdtempSync(join(work, "home-")) } }) } = deps;
  const report = { at: new Date().toISOString(), codex: { pinned }, claudeSdk: { ours } };
  try {
    const v = await newest("@openai/codex");
    report.codex.newest = v;
    if (v === pinned) report.codex.result = "same";
    else {
      const problems = checkContract(await schemaOf(await binOf(v, work)));
      report.codex.result = problems.length ? "red" : "green";
      if (problems.length) report.codex.problems = problems.slice(0, 20);
    }
  } catch (e) {
    report.codex.result = "red";
    report.codex.problems = [`the check couldn't run: ${String(e?.message ?? e).slice(0, 200)}`];
  }
  try { report.claudeSdk.newest = await newest(SDK); } catch (e) { report.claudeSdk.newest = null; }
  report.red = report.codex.result === "red";
  return report;
}

function sdkOurs() {
  try { return JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")).dependencies[SDK]; } catch { return null; }
}

/** The alert's words for a red report (short; names only versions and contract problems). */
export function alertText(r) {
  return [`sagebrush-agent nightly: Codex ${r.codex.newest ?? "?"} (pinned ${r.codex.pinned}) is RED.`, ...(r.codex.problems ?? []).map((p) => `- ${p}`), `Claude Agent SDK: ours ${r.claudeSdk.ours}, newest ${r.claudeSdk.newest ?? "?"}.`].join("\n");
}

/** A night: the report written to `out`; on a red, the alert command run with the message file as $1. */
export async function runNightly({ out, alert = null, deps, pinned, ours } = {}) {
  mkdirSync(out, { recursive: true });
  const work = mkdtempSync(join(process.env.TMPDIR || tmpdir(), "codex-nightly-"));
  try {
    const r = await nightly({ work, deps, ...(pinned ? { pinned } : {}), ...(ours ? { ours } : {}) });
    writeFileSync(join(out, `codex-nightly-${r.at.slice(0, 10)}.json`), JSON.stringify(r, null, 2) + "\n");
    if (r.red && alert) {
      const msg = join(out, "alert.md");
      writeFileSync(msg, alertText(r) + "\n");
      execFileSync("/bin/sh", ["-c", alert, "alert", msg], { stdio: "inherit" });
    }
    return r;
  } finally { rmSync(work, { recursive: true, force: true }); }
}

async function main(args) {
  const ai = args.indexOf("--alert");
  if (!args[0]) { console.error("usage: node scripts/codex-nightly.mjs <report dir> [--alert <command>]"); process.exit(2); }
  const r = await runNightly({ out: args[0], alert: ai >= 0 ? args[ai + 1] : null });
  console.log(`codex ${r.codex.newest}: ${r.codex.result}`);
  process.exitCode = r.red ? 1 : 0;
}

if (import.meta.url === `file://${process.argv[1]}`) await main(process.argv.slice(2));
