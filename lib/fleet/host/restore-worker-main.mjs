// The host restore's worker (restore e2e r1.7 §3, delta d2), run by the dispatch in its own transient scope under the
// host's slice, never by a shell:
//   restore-worker <kind> <id> <run> <nonce> <mount>
// It takes the set's lock, reads its dispatch's input under it, and fills the set through the trusted launcher
// (restore-worker.mjs runWorker, restore-wiring.mjs workerDeps). It prints one JSON line. Exit: 0 settled or stopped
// as recorded, 3 refused (nothing done past the refusal), 2 bad arguments, 1 anything else.

import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { FleetError, isId } from "../bytes.mjs";
import { runArgv } from "./effects.mjs";
import { realSystemd } from "./fence.mjs";
import { KINDS, RESTORE_RUN } from "./restore-record.mjs";
import { launcherRunner } from "./restore-adapters.mjs";
import { liveStop, workerDeps } from "./restore-wiring.mjs";
import { runWorker } from "./restore-worker.mjs";

/** Parse the worker's argv: { kind, id, run, nonce, mount }, or null. */
export function parseWorkerArgv(args) {
  const [cmd, kind, id, run, nonce, mount, ...rest] = args;
  if (cmd !== "restore-worker" || rest.length !== 0 || !KINDS.includes(kind) || !isId(id ?? "") || !RESTORE_RUN.test(run ?? "") || !isId(nonce ?? "")
    || typeof mount !== "string" || !mount.startsWith("/") || !/^[A-Za-z0-9._/-]+$/.test(mount)) return null;
  return { kind, id, run, nonce, mount };
}

/** One worker run, its deps injectable (tests): resolves to { code, line }. */
export async function workerMain(args, { depsOf = defaultDeps, run = runWorker } = {}) {
  const a = parseWorkerArgv(args);
  if (a === null) return { code: 2, line: { v: 1, error: "usage: restore-worker <kind> <id> <run> <nonce> <mount>" } };
  try {
    const out = await run(a.kind, a.id, a.run, a.nonce, depsOf(a));
    return { code: 0, line: { v: 1, set: `${a.kind}-${a.id}`, status: out.status } };
  } catch (e) {
    if (e instanceof FleetError) return { code: 3, line: { v: 1, set: `${a.kind}-${a.id}`, refused: e.code } };
    return { code: 1, line: { v: 1, set: `${a.kind}-${a.id}`, failed: true } };
  }
}

function defaultDeps({ mount }) {
  const release = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
  const launch = launcherRunner({ run: runArgv, launcher: `${release}/bin/sagebrush-agent-launch` });
  return workerDeps({ launch, mount, ...liveStop({ sys: realSystemd }) });
}

async function main() {
  const { code, line } = await workerMain(process.argv.slice(2));
  process.stdout.write(`${JSON.stringify(line)}\n`);
  process.exitCode = code;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) await main();
