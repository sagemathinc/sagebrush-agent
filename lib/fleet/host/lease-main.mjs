// The execution lease's two short root commands (design: agent-autonomous-host-execution-lease.md r3.11 §2.1), run
// by systemd, never by a shell:
//   lease-expire <agent> <lease_id> <lg>     the watchdog's service (armed by lease.mjs armWatchdog)
//   lease-activate <agent> <lease_id> <lg>   the activation helper, in its scope inside the agent's slice
//   lease-thaw <agent> <lease_id> <lg>       the thaw helper (a paused agent's resume), in its scope in the slice
//   lease-sleep pre|post                     the system-sleep hook (lease-on r1.5 §6.4), run by systemd-sleep
// Each prints one JSON line. Exit: 0 done (or a stale watchdog's no-op), 3 refused or not proven, 2 bad arguments.
//
//   node lib/fleet/host/lease-main.mjs lease-expire <agent> <lease_id> <lg>

import { fileURLToPath } from "node:url";
import { leaseActivate, leaseExpire, leaseSleep, leaseThaw, parseArgs } from "./lease.mjs";

async function main() {
  const [cmd, ...rest] = process.argv.slice(2);
  if (cmd === "lease-sleep") {
    if (rest.length !== 1 || !["pre", "post"].includes(rest[0])) { process.stderr.write("usage: lease-main.mjs lease-sleep pre|post\n"); process.exitCode = 2; return; }
    let out;
    try { out = await leaseSleep(rest[0]); } catch (e) { out = { error: e?.code ?? "failed", ok: false }; }
    process.stdout.write(`${JSON.stringify(out)}\n`);
    process.exitCode = out.ok ? 0 : 3;
    return;
  }
  let args;
  try {
    if (!["lease-expire", "lease-activate", "lease-thaw"].includes(cmd) || rest.length !== 3) throw new Error("usage");
    args = parseArgs(...rest);
  } catch {
    process.stderr.write("usage: lease-main.mjs lease-expire|lease-activate|lease-thaw <agent> <lease_id> <lg>\n");
    process.exitCode = 2;
    return;
  }
  let out, code;
  try {
    if (cmd === "lease-expire") { out = await leaseExpire(args.agent, args.leaseId, args.lg); code = !out.acted || out.proven ? 0 : 3; }
    else if (cmd === "lease-activate") { out = await leaseActivate(args.agent, args.leaseId, args.lg); code = out.activated ? 0 : 3; }
    else { out = await leaseThaw(args.agent, args.leaseId, args.lg); code = out.thawed ? 0 : 3; }
  } catch (e) {
    out = { error: e?.code ?? "failed" }; code = 3;
  }
  process.stdout.write(`${JSON.stringify(out)}\n`);
  process.exitCode = code;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) await main();
