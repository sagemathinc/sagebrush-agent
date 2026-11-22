// CI's evidence for the Delegate runner: the pinned Deno and engine fetched exactly as the agent fetches them
// (lib/runner-fetch.mjs ensureRunner: npm tarballs, every file checked against lib/runner-pin.json), into a private
// folder, then the runner's acceptance rows run against them with SAGEBRUSH_REQUIRE_RUNNER=1, so a missing runner
// is a failure, never a skip.  Usage: node scripts/runner-ci.mjs <a new or private folder for the runner>
import { spawnSync } from "node:child_process";
import { mkdirSync } from "node:fs";
import { join, resolve } from "node:path";
import { ensureRunner } from "../lib/runner-fetch.mjs";

const parent = resolve(process.argv[2] ?? "");
if (!process.argv[2]) { console.error("usage: node scripts/runner-ci.mjs <folder>"); process.exit(2); }
mkdirSync(parent, { recursive: true, mode: 0o700 });
// (the platform pinned for this computer, ignoring RUN_PLATFORMS: the rows are the evidence that decides it)
const r = await ensureRunner({ root: join(parent, "runner") });
console.log(`runner: ${r.deno}\nengine: ${r.engine}`);
const t = spawnSync(process.execPath, ["--test", "--test-force-exit", "test/task-runner-real.test.mjs", "test/task-runner.test.mjs"], {
  stdio: "inherit",
  env: { ...process.env, SAGEBRUSH_REQUIRE_RUNNER: "1", SAGEBRUSH_RUNNER_DENO: r.deno, SAGEBRUSH_RUNNER_ENGINE: r.engine },
});
process.exit(t.status ?? 1);
