// The published package holds every file the program loads: from the bin, each relative import (static or dynamic) and
// each JSON a module reads by its own URL, followed through lib/, must be in package.json's "files" (a release once
// left lib/turn-info.mjs out, so the installed agent couldn't start). Checked against `npm pack --dry-run`'s own list.
import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync, existsSync, readdirSync } from "node:fs";
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
      const t = normalize(join(dirname(f), r)).replaceAll("\\", "/");
      if (t.startsWith("test/") || t.startsWith("..")) continue;
      if (existsSync(join(root, t))) todo.push(t);
    }
  }
  return seen;
}

let packedList = null;
/** The files `npm pack --dry-run` would publish (computed once). */
function packedFilesOnce() {
  if (packedList) return packedList;
  // (npm on Windows is npm.cmd, which Node starts only through the shell; the arguments here are fixed)
  const win = process.platform === "win32";
  const out = JSON.parse(execFileSync(win ? "npm.cmd" : "npm", ["pack", "--dry-run", "--json", "--ignore-scripts"], { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"], shell: win }));
  return (packedList = new Set(out[0].files.map((f) => f.path)));
}

test("package: every file the bin reaches is in the published package (npm pack --dry-run)", () => {
  const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
  const packed = packedFilesOnce();
  const need = [...reachable(relative(root, join(root, pkg.bin["sagebrush-agent"])).replaceAll("\\", "/"))];
  // (a folder a module reads by its URL ("./tzdata/zoneinfo/"): every file under it on disk must be packed)
  const under = (d) => readdirSync(join(root, d), { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? under(`${d}${e.name}/`) : [`${d}${e.name}`]));
  const missing = need.flatMap((f) => (f.endsWith("/") ? under(f) : [f])).filter((f) => !packed.has(f));
  assert.deepEqual(missing, [], `not in the package: ${missing.join(", ")}`);
  assert.ok(need.includes("lib/turn-info.mjs") && need.includes("lib/server.mjs"), `the walk reaches the modules (${need.length} files)`);
  assert.ok(need.includes("lib/tzdata/zoneinfo/") && under("lib/tzdata/zoneinfo/").length === 598, "the runner's zone data, every file");
});

test("package: server-only code stays out: no lib/fleet/relay/ file is published, and the bin never reaches one", () => {
  const relay = readdirSync(join(root, "lib/fleet/relay")).filter((f) => f.endsWith(".mjs"));
  assert.ok(relay.length >= 6, "the relay's files are on disk (so this check isn't vacuous)");
  const inPackage = [...packedFilesOnce()].filter((f) => f.startsWith("lib/fleet/relay/"));
  assert.deepEqual(inPackage, [], `server-only files in the package: ${inPackage.join(", ")}`);
  const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
  const reached = [...reachable(relative(root, join(root, pkg.bin["sagebrush-agent"])).replaceAll("\\", "/"))].filter((f) => f.startsWith("lib/fleet/relay/"));
  assert.deepEqual(reached, [], "the bin imports nothing from the relay");
});
