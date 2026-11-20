// The published package holds every file the program loads: from the bin, each relative import (static or dynamic) and
// each JSON a module reads by its own URL, followed through lib/, must be in package.json's "files" (a release once
// left lib/turn-info.mjs out, so the installed agent couldn't start). Checked against `npm pack --dry-run`'s own list.
import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync, existsSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { dirname, join, relative, normalize } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));

/** Every file reachable from `start` by relative imports and `new URL("./x", import.meta.url)` reads. */
function reachable(start) {
  const seen = new Set(), todo = [start];
  while (todo.length) {
    const f = todo.pop();
    if (seen.has(f)) continue;
    seen.add(f);
    if (!f.endsWith(".mjs") && !f.endsWith(".js")) continue;
    const src = readFileSync(join(root, f), "utf8");
    const refs = [
      ...src.matchAll(/\bfrom\s+["'](\.{1,2}\/[^"']+)["']/g),
      ...src.matchAll(/\bimport\s*\(\s*["'](\.{1,2}\/[^"']+)["']\s*\)/g),
      ...src.matchAll(/\bimport\s+["'](\.{1,2}\/[^"']+)["']/g),
      ...src.matchAll(/new URL\(\s*["'](\.{1,2}\/[^"']+)["']\s*,\s*import\.meta\.url\s*\)/g),
    ].map((m) => m[1]);
    for (const r of refs) {
      const t = normalize(join(dirname(f), r));
      if (t.startsWith("test/") || t.startsWith("..")) continue;
      if (existsSync(join(root, t))) todo.push(t);
    }
  }
  return seen;
}

test("package: every file the bin reaches is in the published package (npm pack --dry-run)", () => {
  const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
  const out = JSON.parse(execFileSync("npm", ["pack", "--dry-run", "--json", "--ignore-scripts"], { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }));
  const packed = new Set(out[0].files.map((f) => f.path));
  const need = [...reachable(relative(root, join(root, pkg.bin["sagebrush-agent"])))];
  const missing = need.filter((f) => !packed.has(f));
  assert.deepEqual(missing, [], `not in the package: ${missing.join(", ")}`);
  assert.ok(need.includes("lib/turn-info.mjs") && need.includes("lib/server.mjs"), `the walk reaches the modules (${need.length} files)`);
});
