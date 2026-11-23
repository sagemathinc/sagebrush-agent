// A standalone Node process (no test runner keeping the event loop alive) that awaits stop, lowerFence and
// withFenceLock at top level must print its result and exit 0: releasing the lock keeps the process alive until the
// lock is really gone.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

const url = (p) => new URL(p, import.meta.url).href;

for (const [name, body] of [
  ["stop", `const { stop } = await import(${JSON.stringify(url("../lib/fleet/host/fence.mjs"))});
     const sys = { stop() {}, jobs() { return []; }, cancel() {}, activeAgentUnits() { return []; }, rootUnits() { return []; }, procCount() { return 0; } };
     const r = await stop({ all: true }, "all", { dir: process.argv[1], sys });
     console.log("result", r.status);`],
  ["lowerFence", `const { raiseFence, lowerFence, fenced } = await import(${JSON.stringify(url("../lib/fleet/host/fence.mjs"))});
     raiseFence("all", null, { dir: process.argv[1] });
     await lowerFence("all", null, "resume-all", { dir: process.argv[1] });
     console.log("result", "lowered");`],
  ["withFenceLock", `const { withFenceLock } = await import(${JSON.stringify(url("../lib/fleet/host/fence.mjs"))});
     const v = await withFenceLock(() => 42, { dir: process.argv[1] });
     console.log("result", v);`],
  ["HostStore", `const { HostStore } = await import(${JSON.stringify(url("../lib/fleet/host/host-store.mjs"))});
     const h = await HostStore.open(process.argv[1]);
     await h.close();
     console.log("result", "closed");`],
]) {
  test(`standalone: top-level await ${name} prints its result and exits 0`, () => {
    const dir = join(mkdtempSync(join(tmpdir(), "sb-standalone-")), "d");
    const r = spawnSync(process.execPath, ["--input-type=module", "-e", body, dir], { encoding: "utf8", timeout: 30000 });
    assert.equal(r.status, 0, `exit ${r.status}; stderr: ${r.stderr}`);
    assert.match(r.stdout, /^result /m);
  });
}
