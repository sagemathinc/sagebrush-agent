// lib/fleet/core/ is what a page, a Worker or the app's web view loads as it is (the page mirrors it byte for byte):
// its source alone is checked here, without loading it, so a mistake in it is reported as itself.
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { test } from "node:test";

test("the core is pure: no Node built-ins, no Buffer or process, and no import from outside lib/fleet/core/", () => {
  const dir = new URL("../lib/fleet/core/", import.meta.url);
  const files = readdirSync(dir).filter((f) => f.endsWith(".mjs"));
  assert.ok(files.length >= 13, files.join(" "));
  for (const f of files) {
    const src = readFileSync(new URL(f, dir), "utf8");
    // (code only: comments may name what the core avoids)
    const code = src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:"'`\\])\/\/.*$/gm, "$1");
    assert.doesNotMatch(code, /\bnode:|\bBuffer\b|\bprocess\b|\brequire\s*\(|\bimport\.meta\b|\bimport\s*\(/, f);
    // (every static import and re-export, bare side-effect imports included)
    const specs = [...code.matchAll(/(?:\bfrom|^\s*import)\s*["']([^"']+)["']/gm)].map((m) => m[1]);
    for (const spec of specs) assert.match(spec, /^\.\/[a-z0-9-]+\.mjs$/, `${f} imports ${spec}`);
  }
});
