// The pinned Codex (lib/codex-fetch.mjs): fetched once from the pinned URL, checked against the pin (archive and
// every file), unpacked by its own reader, kept in a private cache and checked again at every start. Archives here
// are made in the test; nothing goes to the network (fetchFn is a stand-in).

import { test } from "node:test";
const T = { timeout: 20000 }; // (a row that hangs fails by name)
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, renameSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import { CodexFetchError, FETCH, archiveBounds, cacheRoot, download, ensureCodex, memberPath, platformKey, tarSink, treeMatches } from "../lib/codex-fetch.mjs";

const sha = (b) => createHash("sha256").update(b).digest("hex");

// ---- making archives

function header(name, size, { type = "0", mode = 0o644, linkname = "" } = {}) {
  const h = Buffer.alloc(512);
  h.write(name, 0, 100);
  h.write(mode.toString(8).padStart(7, "0") + "\0", 100);
  h.write("0000000\0", 108);
  h.write("0000000\0", 116);
  h.write(size.toString(8).padStart(11, "0") + "\0", 124);
  h.write("00000000000\0", 136);
  h.write(type, 156);
  h.write(linkname, 157, 100);
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
const pax = (path) => { const rec = (k, v) => { let s = ` ${k}=${v}\n`; let n = s.length; n += String(n + String(n).length).length; return `${n}${s}`; }; const d = Buffer.from(rec("path", path)); return Buffer.concat([header("PaxHeader", d.length, { type: "x" }), d, pad(d.length)]); };
const END = Buffer.alloc(1024);
// (one extended-header record, its length counted as tar does: the digits include themselves)
const paxRecord = (k, v) => { const body = ` ${k}=${v}\n`; let n = body.length + 1; while (String(n).length + body.length !== n) n = String(n).length + body.length; const d = Buffer.from(`${n}${body}`); return Buffer.concat([header("PaxHeader", d.length, { type: "x" }), d, pad(d.length)]); };

const CODEX = Buffer.from("#!/bin/sh\necho codex-cli 9.9.9\n");
const RG = Buffer.from("rg".repeat(700));
const LICENSE = Buffer.from("license text\n");
const goodMembers = () => [
  member("package/", Buffer.alloc(0), { type: "5", mode: 0o755 }),
  member("package/package.json", Buffer.from('{"name":"x"}')),
  member("package/vendor/bin/codex", CODEX, { mode: 0o755 }),
  member("package/vendor/path/rg", RG, { mode: 0o755 }),
  member("package/LICENSE", LICENSE),
];
const FILES = {
  "package.json": { size: 12, sha256: sha(Buffer.from('{"name":"x"}')) },
  "vendor/bin/codex": { size: CODEX.length, sha256: sha(CODEX), exec: true },
  "vendor/path/rg": { size: RG.length, sha256: sha(RG), exec: true },
  LICENSE: { size: LICENSE.length, sha256: sha(LICENSE) },
};
const URL0 = "https://registry.npmjs.org/@openai/codex/-/codex-9.9.9-linux-x64.tgz";
function pinFor(archive, extra = {}) {
  return { version: "9.9.9", platforms: { "linux-x64": { url: URL0, size: archive.length, sha256: sha(archive), bin: "vendor/bin/codex", files: FILES, ...extra } } };
}
const GOOD = gzipSync(Buffer.concat([...goodMembers(), END]));

// (a stand-in for fetch: a map of URL -> archive or a redirect; counts calls)
function server(routes) {
  const f = async (url, opts) => {
    f.calls.push(url);
    const r = routes[url];
    if (r === undefined) return new Response("no", { status: 404 });
    if (typeof r === "string") return new Response(null, { status: 302, headers: { location: r } });
    if (typeof r === "function") return r(opts);
    return new Response(r, { status: 200 });
  };
  f.calls = [];
  return f;
}
const scratch = () => mkdtempSync(join(tmpdir(), "codex-cache-"));
const rootIn = (dir) => join(dir, "sagebrush-agent", "codex");
const run = (dir, pin, fetchFn, more = {}) => ensureCodex({ root: rootIn(dir), pin, platform: "linux-x64", fetchFn, ...more });
const refused = async (p, code, re) => {
  await assert.rejects(p, (e) => e instanceof CodexFetchError && e.code === code && (!re || re.test(e.message)));
};
const leftovers = (dir) => readdirSync(rootIn(dir)).filter((n) => n.startsWith(".fetch-"));

// ---- rows

test("first use: fetched from the pinned URL, unpacked, checked; a second start uses the cache without fetching", T, async () => {
  const dir = scratch();
  try {
    const f = server({ [URL0]: GOOD });
    const r = await run(dir, pinFor(GOOD), f);
    assert.equal(r.bin, join(rootIn(dir), "9.9.9-linux-x64", "vendor/bin/codex"));
    assert.equal(lstatSync(r.bin).mode & 0o777, 0o755);
    assert.equal(lstatSync(join(r.dir, "LICENSE")).mode & 0o777, 0o644);
    assert.equal(lstatSync(rootIn(dir)).mode & 0o777, 0o700);
    assert.deepEqual(f.calls, [URL0]);
    await run(dir, pinFor(GOOD), f);
    assert.equal(f.calls.length, 1, "no second download");
    assert.deepEqual(leftovers(dir), []);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("the archive's sha256 isn't the pin's: refused, nothing put in place, no temp left", T, async () => {
  const dir = scratch();
  try {
    const other = gzipSync(Buffer.concat([...goodMembers(), END, Buffer.alloc(512)]));
    await refused(run(dir, { ...pinFor(GOOD), platforms: { "linux-x64": { ...pinFor(GOOD).platforms["linux-x64"], size: other.length } } }, server({ [URL0]: other })), "codex_archive", /other bytes/);
    assert.ok(!existsSync(join(rootIn(dir), "9.9.9-linux-x64")));
    assert.deepEqual(leftovers(dir), []);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// One archive per way it can differ from the manifest; each refused before anything is put in place.
const BAD_ARCHIVES = [
  ["a file with other bytes", () => [...goodMembers().slice(0, 2), member("package/vendor/bin/codex", Buffer.from("#!/bin/sh\necho codex-cli 6.6.6\n"), { mode: 0o755 }), ...goodMembers().slice(3)], /other bytes/],
  ["a member not in the manifest", () => [...goodMembers(), member("package/extra.sh", Buffer.from("x"))], /unexpected member extra\.sh/],
  ["a path climbing out", () => [...goodMembers(), member("package/../evil", Buffer.from("x"))], /member path/],
  ["an absolute path", () => [...goodMembers(), member("/etc/evil", Buffer.from("x"))], /member path/],
  ["a symlink", () => [...goodMembers(), member("package/link", Buffer.alloc(0), { type: "2", linkname: "/etc/passwd" })], /member type "2"/],
  ["a hard link", () => [...goodMembers(), member("package/hard", Buffer.alloc(0), { type: "1", linkname: "package/LICENSE" })], /member type "1"/],
  ["a device", () => [...goodMembers(), member("package/dev", Buffer.alloc(0), { type: "3" })], /member type "3"/],
  ["a member twice", () => [...goodMembers(), member("package/LICENSE", LICENSE)], /twice/],
  ["a missing file", () => goodMembers().slice(0, 4), /LICENSE is missing/],
  ["another size", () => [...goodMembers().slice(0, 4), member("package/LICENSE", Buffer.from("license text!!\n"))], /another size/],
  ["a global extension header", () => [member("pax_global_header", Buffer.from("20 comment=hello\n"), { type: "g" }), ...goodMembers()], /member type "g"/],
  ["an unknown extension key", () => [paxRecord("linkpath", "/etc/passwd"), ...goodMembers()], /extension linkpath/],
];
for (const [what, members, re] of BAD_ARCHIVES) {
  test(`refused: ${what}`, T, async () => {
    const dir = scratch();
    try {
      const archive = gzipSync(Buffer.concat([...members(), END]));
      await refused(run(dir, pinFor(archive), server({ [URL0]: archive })), "codex_archive", re);
      assert.ok(!existsSync(join(rootIn(dir), "9.9.9-linux-x64")));
      assert.deepEqual(leftovers(dir), []);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
}

test("refused: an archive that ends early (truncated tar), and one that isn't gzip", T, async () => {
  for (const [archive, re] of [[gzipSync(Buffer.concat(goodMembers()).subarray(0, 1700)), /ends early/], [Buffer.from("not gzip at all"), /gzip/]]) {
    const dir = scratch();
    try {
      await refused(run(dir, pinFor(archive), server({ [URL0]: archive })), "codex_archive", re);
      assert.deepEqual(leftovers(dir), []);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  }
});

test("a long path through an extended header is read; the bounds count headers and every byte", () => {
  const dir = scratch();
  try {
    const sink = tarSink(dir, FILES);
    sink.write(Buffer.concat([...goodMembers().slice(0, 2), pax("package/vendor/bin/codex"), member("package/placeholder", CODEX, { mode: 0o755 }), ...goodMembers().slice(3), END]));
    assert.deepEqual(Object.keys(sink.end()).sort(), Object.keys(FILES).sort());
    const b = archiveBounds(FILES);
    assert.equal(b.headers, 2 * 4 + 3 + 1); // (4 files: own + extension each; package/, vendor/, vendor/bin, vendor/path... 3 directories; +1)
    const tight = tarSink(mkdtempSync(join(dir, "t-")), FILES, { headers: 3, bytes: b.bytes });
    assert.throws(() => tight.write(Buffer.concat([...goodMembers(), END])), /too many members/);
    const small = tarSink(mkdtempSync(join(dir, "s-")), FILES, { headers: b.headers, bytes: 2048 });
    assert.throws(() => small.write(Buffer.concat([...goodMembers(), END])), /too large/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("member paths: only under the package root, no empty, '.', '..' or backslash parts", () => {
  assert.equal(memberPath("package/a/b"), "a/b");
  for (const n of ["a/b", "package/", "package//a", "package/./a", "package/a/../b", "package/a\\b", "/package/a", "packagex/a"]) assert.equal(memberPath(n), null, n);
});

test("the download: larger or shorter than pinned, another host, plain http, too many redirects; each refused", T, async () => {
  const big = Buffer.concat([GOOD, Buffer.alloc(10)]);
  const cases = [
    [server({ [URL0]: big }), "codex_archive", /larger than pinned|another size/],
    [server({ [URL0]: GOOD.subarray(0, GOOD.length - 5) }), "codex_archive", /shorter than pinned|another size|ends early|gzip/],
    [server({ [URL0]: "https://evil.example/x.tgz" }), "codex_download", /evil\.example/],
    [server({ [URL0]: "http://registry.npmjs.org/x.tgz" }), "codex_download", /only registry\.npmjs\.org over https/],
    [server({ [URL0]: URL0 + "?1", [URL0 + "?1"]: URL0 + "?2", [URL0 + "?2"]: URL0 + "?3", [URL0 + "?3"]: URL0 + "?4" }), "codex_download", /too many redirects/],
    [server({}), "codex_download", /HTTP 404/],
  ];
  for (const [f, code, re] of cases) {
    const dir = scratch();
    try {
      await refused(run(dir, pinFor(GOOD), f), code, re);
      assert.deepEqual(leftovers(dir), []);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  }
});

test("a redirect within the registry is followed (at most 3)", T, async () => {
  const dir = scratch();
  try {
    const f = server({ [URL0]: URL0 + "?cdn", [URL0 + "?cdn"]: GOOD });
    await run(dir, pinFor(GOOD), f);
    assert.deepEqual(f.calls, [URL0, URL0 + "?cdn"]);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("a Stop (the agent closing) ends a download under way: refused 'stopped', its temp dir removed", T, async () => {
  const dir = scratch();
  try {
    const ac = new AbortController();
    const f = server({ [URL0]: (opts) => new Response(new ReadableStream({ start(c) { c.enqueue(GOOD.subarray(0, 100)); opts.signal.addEventListener("abort", () => c.error(new Error("aborted"))); setTimeout(() => ac.abort(), 20); } }), { status: 200 }) });
    await refused(run(dir, pinFor(GOOD), f, { signal: ac.signal }), "codex_download", /stopped/);
    assert.deepEqual(leftovers(dir), []);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("progress: reported while the download goes on", T, async () => {
  const dir = scratch();
  try {
    const seen = [];
    const was = FETCH.progressEvery;
    FETCH.progressEvery = 64;
    try { await run(dir, pinFor(GOOD), server({ [URL0]: GOOD }), { onProgress: (g, s) => seen.push([g, s]) }); } finally { FETCH.progressEvery = was; }
    assert.ok(seen.length >= 1 && seen.every(([g, s]) => s === GOOD.length && g <= s));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// ---- the cache, at every start

async function cached(mutate) {
  const dir = scratch();
  const f = server({ [URL0]: GOOD });
  const r = await run(dir, pinFor(GOOD), f);
  mutate(r.dir, dir);
  return { dir, f, r };
}

for (const [what, mutate] of [
  ["a file's bytes changed", (d) => writeFileSync(join(d, "vendor/bin/codex"), "#!/bin/sh\necho evil-ish codex\n")],
  ["an extra file", (d) => writeFileSync(join(d, "vendor/bin/extra"), "x")],
  ["a file replaced by a symlink", (d) => { rmSync(join(d, "LICENSE")); symlinkSync("/etc/hostname", join(d, "LICENSE")); }],
  ["a directory replaced by a link to an identical copy (the walk mustn't follow it)", (d) => { const alt = `${d}-alt`; renameSync(join(d, "vendor"), alt); symlinkSync(alt, join(d, "vendor")); }],
  ["the executable's mode", (d) => chmodSync(join(d, "vendor/bin/codex"), 0o644)],
  ["a group-writable file", (d) => chmodSync(join(d, "LICENSE"), 0o664)],
]) {
  test(`at start, the cached copy no longer matches (${what}): moved aside (never deleted), fetched once more`, T, async () => {
    const { dir, f, r } = await cached(mutate);
    try {
      const again = await run(dir, pinFor(GOOD), f);
      assert.equal(again.dir, r.dir);
      assert.equal(f.calls.length, 2);
      const aside = readdirSync(rootIn(dir)).filter((n) => n.includes(".bad-"));
      assert.equal(aside.length, 1, "the old tree kept aside");
      assert.ok(treeMatches(again.dir, FILES));
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
}

test("a cached copy that doesn't match, and a fetch that still doesn't: one re-fetch, then refused", T, async () => {
  const { dir } = await cached((d) => writeFileSync(join(d, "LICENSE"), "changed!!!!!!"));
  try {
    const other = gzipSync(Buffer.concat([...goodMembers().slice(0, 4), member("package/LICENSE", Buffer.from("license tex!\n")), END]));
    const f = server({ [URL0]: other });
    await refused(run(dir, { ...pinFor(GOOD), platforms: { "linux-x64": { ...pinFor(GOOD).platforms["linux-x64"], size: other.length } } }, f), "codex_archive");
    assert.equal(f.calls.length, 1, "exactly one more fetch");
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("the cached version dir is a symlink: not followed, moved aside, fetched again", T, async () => {
  const dir = scratch();
  try {
    const elsewhere = mkdtempSync(join(dir, "elsewhere-"));
    mkdirSync(rootIn(dir), { recursive: true, mode: 0o700 });
    symlinkSync(elsewhere, join(rootIn(dir), "9.9.9-linux-x64"));
    const f = server({ [URL0]: GOOD });
    const r = await run(dir, pinFor(GOOD), f);
    assert.ok(!lstatSync(r.dir).isSymbolicLink());
    assert.ok(existsSync(elsewhere), "the link's target is untouched");
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("the cache directory is a symlink, or not a directory: refused, nothing fetched", T, async () => {
  const dir = scratch();
  try {
    mkdirSync(join(dir, "real"));
    symlinkSync(join(dir, "real"), join(dir, "sagebrush-agent"));
    const f = server({ [URL0]: GOOD });
    await refused(run(dir, pinFor(GOOD), f), "codex_cache");
    assert.equal(f.calls.length, 0);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("a fetch that loses the race to put its copy in place keeps the winner's (same inode), and removes its own", T, async () => {
  const dir = scratch();
  try {
    let firstDone, n = 0;
    const done = new Promise((r) => { firstDone = r; });
    // (the start that asked first is answered only after the other's copy is in place, so it finds one there)
    const f = server({ [URL0]: async () => (++n === 1 ? (await done, new Response(GOOD)) : new Response(GOOD)) });
    const second = run(dir, pinFor(GOOD), f);
    while (!f.calls.length) await new Promise((r) => setTimeout(r, 1));
    const first = await run(dir, pinFor(GOOD), f);
    const ino = lstatSync(join(rootIn(dir), "9.9.9-linux-x64")).ino;
    firstDone();
    const r2 = await second;
    assert.ok(first);
    assert.equal(lstatSync(r2.dir).ino, ino, "the copy in place wasn't replaced");
    assert.equal(f.calls.length, 2);
    assert.deepEqual(leftovers(dir), []);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("two starts at once: one copy put in place, both use it, no temp dir left, nothing set aside", T, async () => {
  const dir = scratch();
  try {
    const f = server({ [URL0]: GOOD });
    const [a, b] = await Promise.all([run(dir, pinFor(GOOD), f), run(dir, pinFor(GOOD), f)]);
    assert.equal(a.dir, b.dir);
    assert.ok(treeMatches(a.dir, FILES));
    assert.deepEqual(leftovers(dir), []);
    assert.deepEqual(readdirSync(rootIn(dir)).filter((n) => n.includes(".bad-")), []);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("no pin for this platform: refused before anything; the platforms and the cache's place", T, async () => {
  await refused(ensureCodex({ root: "/nonexistent", platform: null, pin: pinFor(GOOD) }), "codex_platform");
  await refused(ensureCodex({ root: "/nonexistent", platform: "darwin-arm64", pin: pinFor(GOOD) }), "codex_platform");
  assert.equal(platformKey("linux", "x64"), "linux-x64");
  assert.equal(platformKey("win32", "x64"), null);
  assert.equal(cacheRoot({ XDG_CACHE_HOME: "/x/c" }, "linux", "/h"), "/x/c/sagebrush-agent/codex");
  assert.equal(cacheRoot({ XDG_CACHE_HOME: "relative" }, "linux", "/h"), "/h/.cache/sagebrush-agent/codex");
  assert.equal(cacheRoot({}, "darwin", "/h"), "/h/Library/Caches/sagebrush-agent/codex");
});

test("the shipped pin: four platforms, each an https registry.npmjs.org tarball with an executable bin in its manifest", T, async () => {
  const { PIN } = await import("../lib/codex-fetch.mjs");
  assert.deepEqual(Object.keys(PIN.platforms).sort(), ["darwin-arm64", "darwin-x64", "linux-arm64", "linux-x64"]);
  for (const [k, e] of Object.entries(PIN.platforms)) {
    const u = new URL(e.url);
    assert.equal(u.protocol, "https:", k);
    assert.equal(u.hostname, "registry.npmjs.org", k);
    assert.match(e.sha256, /^[0-9a-f]{64}$/, k);
    assert.ok(e.files[e.bin]?.exec, `${k}: ${e.bin} executable in the manifest`);
    assert.ok(Number.isInteger(e.size) && e.size > 0, k);
  }
});

// ---- private modes and owners, whatever the umask; no write waits forever

test("a cache directory others can read or write: refused, nothing fetched", T, async () => {
  for (const level of ["sagebrush-agent", "sagebrush-agent/codex"]) {
    const dir = scratch();
    try {
      mkdirSync(join(dir, "sagebrush-agent", "codex"), { recursive: true, mode: 0o700 });
      chmodSync(join(dir, "sagebrush-agent"), 0o700);
      chmodSync(join(dir, level), 0o777);
      const f = server({ [URL0]: GOOD });
      await refused(run(dir, pinFor(GOOD), f), "codex_cache");
      assert.equal(f.calls.length, 0, level);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  }
});

for (const [what, mutate] of [
  ["the copy's own directory opened to others", (d) => chmodSync(d, 0o777)],
  ["a directory inside it opened to others", (d) => chmodSync(join(d, "vendor/bin"), 0o755)],
  ["a special bit on the executable", (d) => chmodSync(join(d, "vendor/bin/codex"), 0o4755)],
  ["a file executable that shouldn't be", (d) => chmodSync(join(d, "LICENSE"), 0o755)],
]) {
  test(`at start, ${what}: not used, moved aside, fetched once more`, T, async () => {
    const { dir, f } = await cached(mutate);
    try {
      const r = await run(dir, pinFor(GOOD), f);
      assert.equal(f.calls.length, 2);
      assert.ok(treeMatches(r.dir, FILES));
      assert.equal(lstatSync(r.dir).mode & 0o7777, 0o700);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
}

test("written under a strict umask, the copy still has its exact modes (and is used at the next start)", T, async () => {
  const dir = scratch();
  const was = process.umask(0o077);
  try {
    const f = server({ [URL0]: GOOD });
    const r = await run(dir, pinFor(GOOD), f);
    assert.equal(lstatSync(r.bin).mode & 0o7777, 0o755);
    assert.equal(lstatSync(join(r.dir, "LICENSE")).mode & 0o7777, 0o644);
    assert.equal(lstatSync(join(r.dir, "vendor")).mode & 0o7777, 0o700);
    await run(dir, pinFor(GOOD), f);
    assert.equal(f.calls.length, 1, "the cached copy matched");
  } finally { process.umask(was); rmSync(dir, { recursive: true, force: true }); }
});

test("an archive that isn't gzip, larger than the gunzip takes at once: refused at once, not left waiting", T, async () => {
  const dir = scratch();
  try {
    const junk = Buffer.alloc(4 << 20, 0x41);
    const t = Date.now();
    await refused(run(dir, pinFor(GOOD, { size: junk.length, sha256: sha(junk) }), server({ [URL0]: junk })), "codex_archive", /gzip|couldn't be read/);
    assert.ok(Date.now() - t < 5000);
    assert.deepEqual(leftovers(dir), []);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("a Stop while a write waits: the download ends 'stopped' within 2 s of the abort, the write never settling", T, async () => {
  const ac = new AbortController();
  const f = server({ [URL0]: GOOD });
  let aborted = 0;
  ac.signal.addEventListener("abort", () => { aborted = Date.now(); });
  setTimeout(() => ac.abort(), 30);
  // (short download limits: a write left waiting fails this row by name within its own time, not the run's)
  await refused(download(URL0, { size: GOOD.length, fetchFn: f, signal: ac.signal, onData: () => new Promise(() => {}), limits: { ...FETCH, totalMs: 3000, idleMs: 3000 } }), "codex_download", /stopped/);
  assert.ok(aborted && Date.now() - aborted < 2000, `settled ${Date.now() - aborted} ms after the abort`);
});

test("refused while the gunzip is busy (a bad first member, then megabytes in small chunks): settles at once, temp removed", T, async () => {
  const dir = scratch();
  try {
    const archive = gzipSync(Buffer.concat([member("package/evil", Buffer.alloc(4 << 20, 1)), ...goodMembers(), END]), { level: 0 });
    const f = server({ [URL0]: () => new Response(new ReadableStream({ start(c) { for (let i = 0; i < archive.length; i += 16384) c.enqueue(archive.subarray(i, i + 16384)); c.close(); } }), { status: 200 }) });
    const t = Date.now();
    await refused(run(dir, pinFor(archive), f), "codex_archive", /unexpected member evil/);
    assert.ok(Date.now() - t < 5000);
    assert.deepEqual(leftovers(dir), []);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("a network failure is said in fixed words, never the error's own text", T, async () => {
  const dir = scratch();
  try {
    const f = async () => { throw new Error("getaddrinfo ENOTFOUND secret-host.internal /home/x/.npmrc"); };
    await refused(run(dir, pinFor(GOOD), f), "codex_download", /^the connection failed$/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
