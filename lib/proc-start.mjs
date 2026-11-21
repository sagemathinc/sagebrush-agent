// A process's start time, as the system reports it: what ties a recorded run to the process that is running now, so a
// process id that has since been reused is never taken for the run (pair-delegate plan r3.4 §2.6: a run's recovery
// after the agent died).  Linux: /proc/<pid>/stat's field 22 (clock ticks since boot); macOS: `ps -o lstart=`.

import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";

/** Process `pid`'s start time (a string) and process group, or null when there is no such process or they can't be
 * read. */
export function procInfo(pid, platform = process.platform) {
  if (!Number.isSafeInteger(pid) || pid <= 1) return null;
  if (platform === "linux") {
    let s;
    try { s = readFileSync(`/proc/${pid}/stat`, "utf8"); } catch { return null; }
    // (the fields after the command's name, which is in parentheses and may hold anything: field 3 onward)
    const rest = s.slice(s.lastIndexOf(")") + 2).split(" ");
    const start = rest[22 - 3], pgid = rest[5 - 3];
    return /^\d+$/.test(start ?? "") && /^\d+$/.test(pgid ?? "") ? { start: `linux:${start}`, pgid: Number(pgid) } : null;
  }
  if (platform === "darwin") {
    const r = spawnSync("/bin/ps", ["-o", "pgid=,lstart=", "-p", String(pid)], { encoding: "utf8", timeout: 5000, env: { LC_ALL: "C", PATH: "/usr/bin:/bin" } });
    const m = r.status === 0 ? /^\s*(\d+)\s+(\S.*\S)\s*$/.exec(r.stdout) : null;
    return m ? { start: `darwin:${m[2]}`, pgid: Number(m[1]) } : null;
  }
  return null;
}
/** Process `pid`'s start time, or null. */
export const procStart = (pid, platform) => procInfo(pid, platform)?.start ?? null;

/** Whether process `pid` exists (one of another account counts too: it can't be signalled, but it is there). */
export function alive(pid) {
  try { process.kill(pid, 0); return true; } catch (e) { return e?.code === "EPERM"; }
}

/** Whether any process of group `pgid` exists. */
export function groupAlive(pgid) {
  try { process.kill(-pgid, 0); return true; } catch (e) { return e?.code === "EPERM"; }
}
