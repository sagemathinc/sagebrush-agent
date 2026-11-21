#!/usr/bin/env node
// The review packet's pin step for the Delegate runner (lib/task-runner.mjs): Deno and the engine are npm's
// tarballs, checked against the registry's integrity, then read by the agent's own tar reader (lib/codex-fetch.mjs)
// into a manifest of every file; the zone data is a folder of compiled zone files (the sagebrush repo's pinned
// tzdata), copied into lib/tzdata/ with a manifest of every file.  Writes a PROPOSAL; it never writes
// lib/runner-pin.json, which changes only by a reviewed edit.
//
//   node scripts/runner-pin.mjs deno <version> <out.json>
//   node scripts/runner-pin.mjs engine <version> <out.json>
//   node scripts/runner-pin.mjs tzdata <zoneinfo dir> <source.json> <out.json>   (also copies the files into lib/tzdata/)

import { createHash } from "node:crypto";
import { copyFileSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { gunzipSync } from "node:zlib";
import { tarSink } from "../lib/codex-fetch.mjs";

// (this computer's platform as the pin names it -> Deno's npm package for it)
export const DENO_PACKAGES = { "linux-x64": "@deno/linux-x64-glibc", "linux-arm64": "@deno/linux-arm64-glibc", "darwin-x64": "@deno/darwin-x64", "darwin-arm64": "@deno/darwin-arm64" };
const PIN_FILE = resolve(new URL("../lib/runner-pin.json", import.meta.url).pathname);
const TZ_DIR = resolve(new URL("../lib/tzdata", import.meta.url).pathname);

export function checkOut(out) {
  const target = resolve(out);
  let same = target === PIN_FILE;
  try { same ||= realpathSync(target) === realpathSync(PIN_FILE); } catch {}
  if (same) throw new Error("the proposal can't be written over lib/runner-pin.json: that file changes only by a reviewed edit");
  return target;
}

// (one npm tarball: its url, size, sha256 and integrity, and every file in it, as the agent's reader reads it)
async function tarball(name, version, work) {
  const meta = await (await fetch(`https://registry.npmjs.org/${name.replace("/", "%2f")}/${version}`)).json();
  const url = meta.dist.tarball;
  const bytes = Buffer.from(await (await fetch(url)).arrayBuffer());
  const dir = mkdtempSync(join(work, "pkg-"));
  const sink = tarSink(dir, null);
  sink.write(gunzipSync(bytes));
  const files = sink.end();
  const sha256 = createHash("sha256").update(bytes).digest("hex");
  const integrity = "sha512-" + createHash("sha512").update(bytes).digest("base64");
  if (integrity !== meta.dist.integrity) throw new Error(`${name}@${version}: npm integrity mismatch`);
  return { url, size: bytes.length, sha256, integrity, files };
}

// (every regular file under `dir`, by lstat: a link or anything else there is refused)
function zoneFiles(dir) {
  const files = {};
  const walk = (rel) => {
    for (const name of readdirSync(join(dir, rel)).sort()) {
      const r = rel ? `${rel}/${name}` : name, s = lstatSync(join(dir, r));
      if (s.isDirectory()) walk(r);
      else if (s.isFile()) files[r] = { size: s.size, sha256: createHash("sha256").update(readFileSync(join(dir, r))).digest("hex") };
      else throw new Error(`${r}: not a regular file`);
    }
  };
  walk("");
  return files;
}

async function main([kind, a, b, c]) {
  const work = mkdtempSync(join(process.env.TMPDIR || tmpdir(), "runner-pin-"));
  try {
    if (kind === "deno" && /^\d+\.\d+\.\d+$/.test(a ?? "") && b) {
      const target = checkOut(b), platforms = {};
      for (const [p, pkg] of Object.entries(DENO_PACKAGES)) {
        const t = await tarball(pkg, a, work);
        if (!t.files.deno?.exec) throw new Error(`${p}: no executable deno`);
        platforms[p] = { package: pkg, ...t, bin: "deno" };
        console.log(`${p}: ${t.size} B, ${Object.keys(t.files).length} files, deno ${t.files.deno.sha256}`);
      }
      writeFileSync(target, JSON.stringify({ proposal: true, deno: { version: a, platforms } }, null, 1) + "\n");
    } else if (kind === "engine" && /^\d+\.\d+\.\d+$/.test(a ?? "") && b) {
      const target = checkOut(b), t = await tarball("sagebrush", a, work);
      if (!t.files["dist/sagebrush.cjs"]) throw new Error("no dist/sagebrush.cjs");
      console.log(`sagebrush ${a}: ${t.size} B, ${Object.keys(t.files).length} files, engine ${t.files["dist/sagebrush.cjs"].sha256}`);
      writeFileSync(target, JSON.stringify({ proposal: true, engine: { version: a, package: "sagebrush", ...t, entry: "dist/sagebrush.cjs" } }, null, 1) + "\n");
    } else if (kind === "tzdata" && a && b && c) {
      const target = checkOut(c), source = JSON.parse(readFileSync(b, "utf8")), files = zoneFiles(a);
      rmSync(join(TZ_DIR, "zoneinfo"), { recursive: true, force: true });
      for (const rel of Object.keys(files)) { mkdirSync(dirname(join(TZ_DIR, "zoneinfo", rel)), { recursive: true }); copyFileSync(join(a, rel), join(TZ_DIR, "zoneinfo", rel)); }
      console.log(`tzdata ${source.version}: ${Object.keys(files).length} files`);
      writeFileSync(target, JSON.stringify({ proposal: true, tzdata: { version: source.version, wheel: { url: source.url, sha256: source.sha256 }, files } }, null, 1) + "\n");
    } else {
      console.error("usage: node scripts/runner-pin.mjs deno|engine <version> <out.json>\n       node scripts/runner-pin.mjs tzdata <zoneinfo dir> <source.json> <out.json>");
      process.exit(2);
    }
  } finally { rmSync(work, { recursive: true, force: true }); }
}

if (import.meta.url === `file://${process.argv[1]}`) await main(process.argv.slice(2));
