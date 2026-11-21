// The runner's pinned Deno and engine (lib/runner-fetch.mjs): the reviewed Codex fetcher's path with the runner's own
// cache and words.  A stand-in for fetch serves made-up archives; no network.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { gzipSync } from "node:zlib";
import { ensureEntry, ensureRunner, pinProblem, RUNNER_PIN, RunnerFetchError, runnerCacheRoot } from "../lib/runner-fetch.mjs";

const sha = (b) => createHash("sha256").update(b).digest("hex");
function header(name, size, { type = "0", mode = 0o644 } = {}) {
  const h = Buffer.alloc(512);
  h.write(name, 0, 100);
  h.write(mode.toString(8).padStart(7, "0") + "\0", 100);
  h.write("0000000\0", 108);
  h.write("0000000\0", 116);
  h.write(size.toString(8).padStart(11, "0") + "\0", 124);
  h.write("00000000000\0", 136);
  h.write(type, 156);
  h.write("ustar\0", 257);
  h.write("00", 263);
  h.write("        ", 148);
  let sum = 0;
  for (const b of h) sum += b;
  h.write(sum.toString(8).padStart(6, "0") + "\0 ", 148);
  return h;
}
const pad = (n) => Buffer.alloc((512 - (n % 512)) % 512);
const member = (name, data, opts) => Buffer.concat([header(name, data.length, opts), data, pad(data.length)]);
const DENO = Buffer.from("#!/bin/sh\necho deno 9.9.9\n"), PKG = Buffer.from('{"name":"@deno/linux-x64-glibc"}');
const ARCHIVE = gzipSync(Buffer.concat([member("package/deno", DENO, { mode: 0o755 }), member("package/package.json", PKG), Buffer.alloc(1024)]));
const URL0 = "https://registry.npmjs.org/@deno/linux-x64-glibc/-/linux-x64-glibc-9.9.9.tgz";
const ENTRY = { url: URL0, size: ARCHIVE.length, sha256: sha(ARCHIVE), bin: "deno", files: { deno: { size: DENO.length, sha256: sha(DENO), exec: true }, "package.json": { size: PKG.length, sha256: sha(PKG) } } };
function server(routes) {
  const f = async (url) => { f.calls.push(url); const r = routes[url]; return r === undefined ? new Response("no", { status: 404 }) : typeof r === "string" ? new Response(null, { status: 302, headers: { location: r } }) : new Response(r, { status: 200 }); };
  f.calls = [];
  return f;
}
const scratch = () => mkdtempSync(join(tmpdir(), "sb-runner-cache-"));

test("the pins: Deno 2.9.0 for the four M1 platforms from npm only; the engine slot empty, so runs say why; the zone data pinned file by file", () => {
  assert.equal(RUNNER_PIN.deno.version, "2.9.0");
  assert.deepEqual(Object.keys(RUNNER_PIN.deno.platforms).sort(), ["darwin-arm64", "darwin-x64", "linux-arm64", "linux-x64"]);
  for (const e of Object.values(RUNNER_PIN.deno.platforms)) {
    assert.match(e.url, /^https:\/\/registry\.npmjs\.org\/@deno\/[a-z0-9-]+\/-\/[a-z0-9-]+-2\.9\.0\.tgz$/);
    assert.equal(e.files.deno.exec, true);
    assert.match(e.sha256, /^[0-9a-f]{64}$/);
  }
  assert.equal(RUNNER_PIN.engine, null);
  assert.equal(pinProblem(RUNNER_PIN, "linux-x64"), "no engine with confinement is pinned yet");
  assert.match(pinProblem(RUNNER_PIN, null), /aren't available on/);
  assert.equal(RUNNER_PIN.tzdata.version, "2026.5");
  assert.equal(Object.keys(RUNNER_PIN.tzdata.files).length, 598);
  if (process.platform === "win32") return; // (the POSIX places below are joined with the host's own separator)
  assert.match(runnerCacheRoot({}, "linux", "/h"), /^\/h\/\.cache\/sagebrush-agent\/runner$/);
  assert.match(runnerCacheRoot({}, "darwin", "/h"), /^\/h\/Library\/Caches\/sagebrush-agent\/runner$/);
});

test("ensureRunner refuses where the pins can't serve, fetching nothing", async () => {
  const f = server({}), dir = scratch();
  await assert.rejects(ensureRunner({ root: join(dir, "r"), platform: "linux-x64", fetchFn: f }), (e) => e instanceof RunnerFetchError && e.code === "runner_platform" && /no engine/.test(e.message));
  assert.equal(f.calls.length, 0);
  assert.equal(existsSync(join(dir, "r")), false, "no cache folder made");
  rmSync(dir, { recursive: true, force: true });
});

test("one entry: fetched once from the pinned URL, unpacked, checked; reused while it matches; a changed copy moved aside (never deleted) and fetched again", async () => {
  const dir = scratch(), root = join(dir, "sagebrush-agent", "runner"), f = server({ [URL0]: ARCHIVE });
  const got = await ensureEntry(root, "deno-9.9.9-linux-x64", ENTRY, "Deno", { fetchFn: f });
  assert.equal(got, join(root, "deno-9.9.9-linux-x64"));
  assert.equal(f.calls.length, 1);
  await ensureEntry(root, "deno-9.9.9-linux-x64", ENTRY, "Deno", { fetchFn: f });
  assert.equal(f.calls.length, 1, "the cache reused");
  writeFileSync(join(got, "package.json"), "changed");
  await ensureEntry(root, "deno-9.9.9-linux-x64", ENTRY, "Deno", { fetchFn: f });
  assert.equal(f.calls.length, 2);
  assert.equal(readdirSync(root).filter((n) => n.includes(".bad-")).length, 1);
  rmSync(dir, { recursive: true, force: true });
});

test("refusals in the runner's words: other bytes, another host, a linked cache folder", async () => {
  const dir = scratch(), root = join(dir, "sagebrush-agent", "runner");
  const other = gzipSync(Buffer.concat([member("package/deno", Buffer.from("#!/bin/sh\necho other\n"), { mode: 0o755 }), member("package/package.json", PKG), Buffer.alloc(1024)]));
  await assert.rejects(ensureEntry(root, "d", { ...ENTRY, size: other.length }, "Deno", { fetchFn: server({ [URL0]: other }) }), (e) => e instanceof RunnerFetchError && e.code.startsWith("runner_") && !/Codex/.test(e.message) && /Deno|pinned/.test(e.message));
  await assert.rejects(ensureEntry(root, "d", { ...ENTRY, url: "https://example.org/deno.tgz" }, "Deno", { fetchFn: server({}) }), (e) => e instanceof RunnerFetchError && /registry\.npmjs\.org/.test(e.message));
  const d2 = scratch(), outside = join(d2, "outside");
  mkdirSync(outside);
  mkdirSync(join(d2, "sagebrush-agent"), { mode: 0o700 });
  symlinkSync(outside, join(d2, "sagebrush-agent", "runner"));
  await assert.rejects(ensureEntry(join(d2, "sagebrush-agent", "runner"), "d", ENTRY, "Deno", { fetchFn: server({ [URL0]: ARCHIVE }) }), (e) => e.code === "runner_cache");
  assert.deepEqual(readdirSync(outside), []);
  assert.equal(existsSync(join(root, "d")), false);
  rmSync(dir, { recursive: true, force: true });
  rmSync(d2, { recursive: true, force: true });
});
