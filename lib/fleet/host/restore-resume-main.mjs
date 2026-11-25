// The restore resume's short root command (backup r3.3 §5 step 11; the first-lease rule r2.1), run by systemd in a
// transient scope inside the agent's slice, never by a shell:
//   resume-restored <agent> <gen> <lease_id> <lg> [<tag>...]
// It prints one JSON line. Exit: 0 resumed, 3 refused (nothing lowered), 2 bad arguments.

import { fileURLToPath } from "node:url";
import { isId, refuse } from "../bytes.mjs";
import { resumeRestored } from "./restore-resume.mjs";
import { expectedOf, readPlan } from "./restore-plan.mjs";
import { restoreReady } from "./restore-record.mjs";

const NUM = /^[1-9][0-9]{0,15}$/;

async function main() {
  const [cmd, agent, gen, leaseId, lg, ...tags] = process.argv.slice(2);
  if (cmd !== "resume-restored" || !isId(agent ?? "") || !NUM.test(gen ?? "") || !NUM.test(lg ?? "") || !tags.every(isId)) {
    process.stderr.write("usage: restore-resume-main.mjs resume-restored <agent> <gen> <lease_id> <lg> [<tag>...]\n");
    process.exitCode = 2;
    return;
  }
  // The current restore's binding (its plan) and the agent's and its tags' records, read afresh under the lock.
  const restoreState = (a) => {
    const plan = readPlan();
    if (plan === null) refuse("not_found", "restore resume: no restore plan");
    return restoreReady(a, tags, expectedOf(plan));
  };
  let out;
  try {
    out = await resumeRestored(agent, Number(gen), leaseId, Number(lg), { restoreState });
  } catch (e) {
    out = { resumed: false, reason: "helper_failed", error: e?.code ?? "failed" };
  }
  process.stdout.write(`${JSON.stringify(out)}\n`);
  process.exitCode = out.resumed ? 0 : 3;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) await main();
