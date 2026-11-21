#!/usr/bin/env node
// The review packet's pin step for one Codex release: for each platform, npm's platform tarball
// (@openai/codex@<v>-<platform>), checked against the registry's integrity, then read by the agent's own tar reader
// (lib/codex-fetch.mjs) into a manifest of every file. Writes a PROPOSAL; it never writes lib/codex-pin.json, which
// changes only by a reviewed edit after the rest of the packet (protocol diff, behavioral rows).
//
//   node scripts/codex-pin.mjs <version> <out.json> [platform]   (one platform only, to add it to an existing pin)

import { createHash } from "node:crypto";
import { mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { gunzipSync } from "node:zlib";
import { tarSink } from "../lib/codex-fetch.mjs";

const PLATFORMS = { "linux-x64": "x86_64-unknown-linux-musl", "linux-arm64": "aarch64-unknown-linux-musl", "darwin-x64": "x86_64-apple-darwin", "darwin-arm64": "aarch64-apple-darwin", "win32-x64": "x86_64-pc-windows-msvc" };
const PIN_FILE = fileURLToPath(new URL("../lib/codex-pin.json", import.meta.url));

export function checkOut(out) {
  const target = resolve(out);
  let same = target === PIN_FILE;
  try { same ||= realpathSync(target) === realpathSync(PIN_FILE); } catch {}
  if (same) throw new Error("the proposal can't be written over lib/codex-pin.json: that file changes only by a reviewed edit");
  return target;
}

async function entry(version, platform, triple, work) {
  const meta = await (await fetch(`https://registry.npmjs.org/@openai/codex/${version}-${platform}`)).json();
  const url = meta.dist.tarball;
  // (the registry doesn't say the size up front: the whole archive, then read as the agent will)
  const bytes = Buffer.from(await (await fetch(url)).arrayBuffer());
  const size = bytes.length;
  const dir = mkdtempSync(join(work, `${platform}-`));
  const sink = tarSink(dir, null);
  sink.write(gunzipSync(bytes));
  const files = sink.end();
  const sha256 = createHash("sha256").update(bytes).digest("hex");
  const integrity = "sha512-" + createHash("sha512").update(bytes).digest("base64");
  if (integrity !== meta.dist.integrity) throw new Error(`${platform}: npm integrity mismatch`);
  // (Windows runs a program by its .exe name; its archive mode bits don't matter there, but the file must be in it)
  const win = platform.startsWith("win32-");
  const bin = `vendor/${triple}/bin/codex${win ? ".exe" : ""}`;
  if (!files[bin] || (!win && !files[bin].exec)) throw new Error(`${platform}: no executable ${bin}`);
  return { url, size, sha256, integrity, bin, binSha256: files[bin].sha256, files };
}

async function main([version, out, only]) {
  if (!/^\d+\.\d+\.\d+$/.test(version ?? "") || !out) { console.error("usage: node scripts/codex-pin.mjs <version> <out.json> [platform]"); process.exit(2); }
  const target = checkOut(out);
  const work = mkdtempSync(join(process.env.TMPDIR || tmpdir(), "codex-pin-"));
  try {
    const platforms = {};
    for (const [p, triple] of Object.entries(PLATFORMS)) {
      if (only && p !== only) continue;
      platforms[p] = await entry(version, p, triple, work);
      console.log(`${p}: ${platforms[p].size} B, ${Object.keys(platforms[p].files).length} files, codex ${platforms[p].binSha256}`);
    }
    writeFileSync(target, JSON.stringify({ proposal: true, version, platforms }, null, 2) + "\n");
  } finally { rmSync(work, { recursive: true, force: true }); }
}

if (import.meta.url === `file://${process.argv[1]}`) await main(process.argv.slice(2));
