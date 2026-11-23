// sagebrush_source (#1663, design r3 §8): the archive sink's bounds and refusals on crafted tarballs, the cache's
// admission, leases, locks and pruning, and the tool's commit resolution, operations and local bounds. No network:
// a fake transport stands in for safeGet, and records every request it is given.
import assert from "node:assert/strict";
import { test } from "node:test";
import { gzipSync } from "node:zlib";
import { chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { LIMITS as TAR, portable, sourceTarSink } from "../lib/source-tar.mjs";
import { SourceCache } from "../lib/source-cache.mjs";
import { LIMITS, searchPool, sourcePath, sourceVerbs } from "../lib/source.mjs";
import { CardlessBudget } from "../lib/netverbs.mjs";

const SHA = "1111111111111111111111111111111111111111";
const SHA2 = "2222222222222222222222222222222222222222";
const SHA3 = "3333333333333333333333333333333333333333";
const ROOT = (sha = SHA) => `sagebrush-${sha}`;

// ---- a small tar writer
function header(name, { type = "0", size = 0 } = {}) {
  const h = Buffer.alloc(512);
  h.write(name.slice(0, 100), 0, "utf8");
  h.write("0000644\0", 100); h.write("0000000\0", 108); h.write("0000000\0", 116);
  h.write(size.toString(8).padStart(11, "0") + "\0", 124);
  h.write("00000000000\0", 136);
  h.write("        ", 148);
  h.write(type, 156);
  h.write("ustar\0", 257); h.write("00", 263);
  let sum = 0;
  for (const b of h) sum += b;
  h.write(sum.toString(8).padStart(6, "0") + "\0 ", 148);
  return h;
}
const pad = (b) => Buffer.concat([b, Buffer.alloc((512 - (b.length % 512)) % 512)]);
function paxData(recs) {
  return Buffer.concat(Object.entries(recs).map(([k, v]) => {
    const body = ` ${k}=${v}\n`;
    let n = Buffer.byteLength(body) + 1;
    while (String(n).length + Buffer.byteLength(body) !== n) n = String(n).length + Buffer.byteLength(body);
    return Buffer.from(`${n}${body}`);
  }));
}
const ent = (name, data = "", type = "0") => { const d = Buffer.from(data); return [header(name, { type, size: d.length }), pad(d)]; };
const ext = (recs, type = "x", name = "PaxHeader") => { const d = paxData(recs); return [header(name, { type, size: d.length }), pad(d)]; };
const longName = (name) => { const d = Buffer.from(name + "\0"); return [header("././@LongLink", { type: "L", size: d.length }), pad(d)]; };
function tarOf(parts, { sha = SHA, global = true } = {}) {
  return Buffer.concat([...(global ? ext({ comment: sha }, "g", "pax_global_header") : []), ...parts.flat(), Buffer.alloc(1024)]);
}
const small = (sha = SHA) => tarOf([ent(`${ROOT(sha)}/`, "", "5"), ent(`${ROOT(sha)}/README.md`, "# hi\nline two\n"), ent(`${ROOT(sha)}/engine/`, "", "5"), ent(`${ROOT(sha)}/engine/lib.rs`, "fn gcd(a: u64) {}\nfn lcm() {}\n")], { sha });

const tmp = () => mkdtempSync(join(tmpdir(), "sb-src-test-"));
const unseal = (d) => { try { chmodSync(d, 0o700); } catch {} let names = []; try { names = readdirSync(d); } catch {} for (const n of names) { const p = join(d, n); try { if (lstatSync(p).isDirectory()) unseal(p); } catch {} } };
const cleanup = (d) => { unseal(d); rmSync(d, { recursive: true, force: true }); };
function sink(buf, sha = SHA, limits) {
  const dir = tmp();
  try {
    const s = sourceTarSink(dir, sha, limits);
    for (let at = 0; at < buf.length; at += 700) s.write(buf.subarray(at, at + 700));
    return s.end();
  } finally { cleanup(dir); }
}

// ---- the archive sink (§3)
test("source tar: a good archive: files kept, the root stripped, folders made", () => {
  const r = sink(small());
  assert.deepEqual(r.files.map((f) => f[0]).sort(), ["README.md", "engine/lib.rs"]);
  assert.equal(r.skipped.length, 0);
});

test("source tar: the global header must name the expected commit, first", () => {
  assert.throws(() => sink(small(), SHA2), /another commit/);
  assert.throws(() => sink(tarOf([ent(`${ROOT()}/a`, "x")], { global: false })), /no global header/);
  assert.throws(() => sink(tarOf([ent(`${ROOT()}/a`, "x"), ext({ comment: SHA }, "g", "g2")])), /global header that isn't first/);
});

test("source tar: every refused entry type refuses the whole archive", () => {
  for (const t of ["1", "2", "3", "4", "6", "7", "S", "M", "K", "V", "Z"]) assert.throws(() => sink(tarOf([ent(`${ROOT()}/x`, "", t)])), /type/, `type ${t}`);
  assert.throws(() => sink(tarOf([ext({ "GNU.sparse.size": "10" }), ent(`${ROOT()}/x`, "a")])), /sparse/);
});

test("source tar: names: one root, portable parts; a bad name is skipped and counted, more than 1% refuses", () => {
  assert.throws(() => sink(tarOf([ent(`other/x`, "a")])), /outside the one root/);
  assert.throws(() => sink(tarOf([ent(`${ROOT()}x/y`, "a")])), /outside the one root/);
  for (const bad of ["../x", "a/../b", "/abs", "C:", "a\\b", "x.", "con", "aux.txt", "a b", "a//b", "."]) assert.equal(portable(bad), false, bad);
  for (const ok of [".github/workflows/ci.yml", "engine/src/lib.rs", "a-b_c+d@e=f,g"]) assert.equal(portable(ok), true, ok);
  const one = tarOf([ent(`${ROOT()}/Homework 1.ipynb`, "x"), ...Array.from({ length: 150 }, (_, i) => ent(`${ROOT()}/f${i}`, "x"))]);
  const r = sink(one);
  assert.deepEqual(r.skipped, [["Homework 1.ipynb", 1, "name"]]);
  const many = tarOf([ent(`${ROOT()}/a b`, "x"), ent(`${ROOT()}/c d`, "x"), ent(`${ROOT()}/ok`, "x")]);
  assert.throws(() => sink(many), /too many names/);
  // (an effective name from a PAX path or a GNU long name is checked like any other)
  assert.throws(() => sink(tarOf([ext({ path: "../../etc/x" }), ent(`${ROOT()}/fine`, "a")])), /outside the one root/);
  assert.throws(() => sink(tarOf([longName("/etc/passwd"), ent(`${ROOT()}/fine`, "a")])), /outside the one root/);
  assert.deepEqual(sink(tarOf([longName(`${ROOT()}/long/name.txt`), ent(`${ROOT()}/x`, "abc")])).files, [["long/name.txt", 3]]);
});

test("source tar: collisions refuse: a name twice, twice up to case or composition, a file and a folder", () => {
  assert.throws(() => sink(tarOf([ent(`${ROOT()}/a`, "1"), ent(`${ROOT()}/a`, "2")])), /twice/);
  assert.throws(() => sink(tarOf([ent(`${ROOT()}/Readme`, "1"), ent(`${ROOT()}/README`, "2")])), /twice/);
  assert.throws(() => sink(tarOf([ent(`${ROOT()}/a`, "1"), ent(`${ROOT()}/a/b`, "2")])), /file and a folder/);
  assert.throws(() => sink(tarOf([ent(`${ROOT()}/a/b`, "1"), ent(`${ROOT()}/a`, "2")])), /file and a folder|twice/);
});

test("source tar: skipped work counts: binary and over-1-MiB files skipped but their bytes count toward the inflated cap", () => {
  const big = "x".repeat(TAR.fileMax + 1);
  const r = sink(tarOf([ent(`${ROOT()}/big.txt`, big), ent(`${ROOT()}/bin.dat`, "a\0b"), ent(`${ROOT()}/ok.txt`, "fine")]));
  assert.deepEqual(r.files, [["ok.txt", 4]]);
  assert.deepEqual(r.skipped.map((s) => s[2]).sort(), ["binary", "over 1 MiB"]);
  // (the same archive under a small inflated cap: refused, though only 4 bytes would be kept)
  assert.throws(() => sink(tarOf([ent(`${ROOT()}/big.txt`, big), ent(`${ROOT()}/ok.txt`, "fine")]), SHA, { ...TAR, inflated: TAR.fileMax }), /inflate/);
});

test("source tar: floods refused: entries, folders, an extension record, a long name, kept files", () => {
  assert.throws(() => sink(tarOf(Array.from({ length: 30 }, (_, i) => ent(`${ROOT()}/f${i}`, "x"))), SHA, { ...TAR, entries: 20 }), /too many entries/);
  assert.throws(() => sink(tarOf(Array.from({ length: 30 }, (_, i) => ent(`${ROOT()}/d${i}/`, "", "5"))), SHA, { ...TAR, dirs: 20 }), /too many folders/);
  assert.throws(() => sink(tarOf([ext({ path: `${ROOT()}/` + "a".repeat(70_000) }), ent(`${ROOT()}/x`, "a")])), /long extension/);
  assert.throws(() => sink(tarOf([longName(`${ROOT()}/` + "a".repeat(5000)), ent(`${ROOT()}/x`, "a")])), /long extension/);
  assert.throws(() => sink(tarOf(Array.from({ length: 10 }, (_, i) => ent(`${ROOT()}/f${i}`, "x"))), SHA, { ...TAR, files: 5 }), /more source than it may keep/);
});

test("source tar: an archive that ends early is refused", () => {
  const t = small();
  assert.throws(() => sink(t.subarray(0, t.length - 1024 - 512)), /ends early/);
});

// ---- the cache (§4)
const pid0 = { pid: process.pid };
function cacheAt(home, opts = {}) { return new SourceCache({ root: join(home, ".cache", "sagebrush-agent", "source"), ...opts }); }
const gz = (t) => gzipSync(t);

test("source cache: one fetch, then a hit; the tree read-only; leases counted and released", async () => {
  const home = tmp();
  try {
    const c = cacheAt(home);
    let n = 0;
    const l = await c.acquire(SHA, async () => { n++; return gz(small()); });
    assert.equal(n, 1);
    assert.ok(c.isComplete(SHA));
    assert.equal(lstatSync(l.tree).mode & 0o777, 0o500);
    assert.equal(lstatSync(join(l.tree, "README.md")).mode & 0o777, 0o400);
    const l2 = await c.acquire(SHA, async () => { n++; throw new Error("not again"); });
    assert.equal(n, 1);
    assert.equal(c.liveLeases(SHA), 2);
    l.release(); l2.release();
    assert.equal(c.liveLeases(SHA), 0);
  } finally { cleanup(home); }
});

test("source cache: a refused archive leaves no slot, no staging, no tree", async () => {
  const home = tmp();
  try {
    const c = cacheAt(home);
    await assert.rejects(c.acquire(SHA, async () => gz(small(SHA2))), /another commit/);
    assert.deepEqual(readdirSync(c.root).filter((n) => n !== ".lock"), []);
    await assert.rejects(c.acquire(SHA, async () => { throw new Error("network"); }), /couldn't be fetched/);
    assert.deepEqual(readdirSync(c.root), []);
  } finally { cleanup(home); }
});

test("source cache: the extraction deadline ends the worker and removes staging", async () => {
  const home = tmp();
  try {
    const c = cacheAt(home, { extractMs: 1 });
    const t = tarOf(Array.from({ length: 3000 }, (_, i) => ent(`${ROOT()}/f${i}`, "x".repeat(200))));
    await assert.rejects(c.acquire(SHA, async () => gz(t)), /too long/);
    assert.deepEqual(readdirSync(c.root).filter((n) => n !== ".lock"), []);
  } finally { cleanup(home); }
});

test("source cache: two slots held by live leases, then a third commit: busy, with no download and no staging", async () => {
  const home = tmp();
  try {
    const c = cacheAt(home);
    const a = await c.acquire(SHA, async () => gz(small(SHA)));
    const b = await c.acquire(SHA2, async () => gz(small(SHA2)));
    let fetched = false;
    await assert.rejects(c.acquire(SHA3, async () => { fetched = true; return gz(small(SHA3)); }), /busy/);
    assert.equal(fetched, false, "no download");
    assert.deepEqual(readdirSync(c.root).filter((n) => n.startsWith(".staging-") || n === SHA3), [], "no staging, no slot");
    // (a slot whose leases are all gone is reclaimed: the unleased commit goes, the leased one stays)
    b.release();
    const d = await c.acquire(SHA3, async () => gz(small(SHA3)));
    assert.ok(c.isComplete(SHA) && c.isComplete(SHA3) && !existsSync(join(c.root, SHA2)), "the leased commit stays; the unleased one was pruned");
    a.release(); d.release();
  } finally { cleanup(home); }
});

test("source cache: leases: a reused pid (another start time) or an old lease doesn't pin", async () => {
  const home = tmp();
  try {
    let start = "linux:100";
    let t = 1_000_000;
    const c = cacheAt(home, { procInfo: (pid) => (pid === process.pid ? { start } : { gone: true }), now: () => t });
    await c.acquire(SHA, async () => gz(small(SHA)));
    assert.equal(c.liveLeases(SHA), 1);
    start = "linux:200"; // (this pid now belongs to another process)
    assert.equal(c.liveLeases(SHA), 0, "a reused pid doesn't pin");
    start = "linux:100";
    const c2 = cacheAt(home, { procInfo: () => ({ start: "linux:100" }), now: () => t, leaseMs: 1000 });
    c2.addLease(SHA);
    t += 5000;
    assert.equal(c2.liveLeases(SHA), 0, "an old lease doesn't pin");
  } finally { cleanup(home); }
});

test("source cache: leftovers of a process that's gone are cleaned; an incomplete commit is never a hit", async () => {
  const home = tmp();
  try {
    const c = cacheAt(home, { procInfo: (pid) => (pid === process.pid ? { start: "me" } : { gone: true }) });
    c.checkRoot();
    mkdirSync(join(c.root, SHA), { mode: 0o700 });
    writeFileSync(join(c.root, SHA, "RESERVED"), JSON.stringify({ pid: 999999, start: "x" }), { mode: 0o600 });
    mkdirSync(join(c.root, ".staging-dead"), { mode: 0o700 });
    writeFileSync(join(c.root, ".staging-dead", "OWNER"), JSON.stringify({ pid: 999999, start: "x" }), { mode: 0o600 });
    writeFileSync(join(c.root, ".lock"), JSON.stringify({ pid: 999999, start: "x", t: Date.now() }), { mode: 0o600 });
    assert.equal(c.isComplete(SHA), false);
    let n = 0;
    await c.acquire(SHA, async () => { n++; return gz(small()); });
    assert.equal(n, 1, "fetched afresh: the dead reservation wasn't a hit");
    assert.ok(!existsSync(join(c.root, ".staging-dead")), "the dead staging was removed");
  } finally { cleanup(home); }
});

test("source cache: two caches (two processes) asking at once: one download, both served", async () => {
  const home = tmp();
  try {
    const c1 = cacheAt(home), c2 = cacheAt(home);
    let n = 0;
    const slow = async () => { n++; await new Promise((r) => setTimeout(r, 200)); return gz(small()); };
    const [a, b] = await Promise.all([c1.acquire(SHA, slow), c2.acquire(SHA, slow)]);
    assert.equal(n, 1);
    assert.ok(a.tree && b.tree);
  } finally { cleanup(home); }
});

test("source cache: a planted link or a loose mode at the root is refused", async () => {
  const home = tmp();
  try {
    mkdirSync(join(home, ".cache", "sagebrush-agent"), { recursive: true, mode: 0o700 });
    const elsewhere = tmp();
    symlinkSync(elsewhere, join(home, ".cache", "sagebrush-agent", "source"));
    await assert.rejects(cacheAt(home).acquire(SHA, async () => gz(small())), /private directory/);
    rmSync(join(home, ".cache", "sagebrush-agent", "source"));
    mkdirSync(join(home, ".cache", "sagebrush-agent", "source"), { mode: 0o755 });
    chmodSync(join(home, ".cache", "sagebrush-agent", "source"), 0o755);
    await assert.rejects(cacheAt(home).acquire(SHA, async () => gz(small())), /private directory/);
    cleanup(elsewhere);
  } finally { cleanup(home); }
});

// ---- the tool (§1, §5, §6)
function fakeGet({ version = { core: SHA }, archive = () => gz(small()), status = 200 } = {}) {
  const calls = [];
  const get = async (u, o) => {
    calls.push({ url: u.origin + u.target, o });
    if (u.pathname === "/version.json") return typeof version === "function" ? version() : { status, type: "application/json", body: Buffer.from(typeof version === "string" ? version : JSON.stringify(version)) };
    return typeof archive === "function" && archive.length === 0 ? { status: 200, type: "application/x-gzip", body: archive() } : archive;
  };
  return { get, calls };
}
async function withTool(opts, fn) {
  const home = tmp();
  try {
    const cache = cacheAt(home);
    const f = fakeGet(opts.net);
    const v = sourceVerbs({ budget: opts.budget ?? new CardlessBudget(), pairedOrigin: opts.origin ?? null, get: f.get, cache, ...(opts.limits ? { limits: { ...LIMITS, ...opts.limits } } : {}) });
    return await fn(v.sagebrush_source, f.calls);
  } finally { cleanup(home); }
}
const text = (r) => r.content.map((c) => c.text).join("\n");

test("source tool: the commit: a paired Sagebrush site's own, else production's, labeled; never a model's origin", async () => {
  await withTool({ origin: "https://dev.sagebrush.space" }, async (src, calls) => {
    const r = await src({ op: "index", origin: "https://evil.example" });
    assert.match(r.content[0].text, /^source: paired_site, https:\/\/dev\.sagebrush\.space, commit 1{40}\./);
    assert.deepEqual(calls.map((c) => c.url), ["https://dev.sagebrush.space/version.json", `https://codeload.github.com/sagemathinc/sagebrush/tar.gz/${SHA}`]);
    assert.equal(calls[0].o.maxBytes, 4096);
    assert.deepEqual(calls[1].o.hosts, ["codeload.github.com"]);
    assert.equal(calls[1].o.maxBytes, 64 * 1024 * 1024);
  });
  for (const origin of [null, "http://127.0.0.1:41234", "https://agents.sagebrush.cloud"]) {
    await withTool({ origin }, async (src, calls) => {
      const r = await src({ op: "index" });
      assert.match(r.content[0].text, /^source: production_default, https:\/\/sagebrush\.space, commit 1{40} \(Sagebrush's production site; the code running on this page may differ\)/, String(origin));
      assert.equal(calls[0].url, "https://sagebrush.space/version.json");
    });
  }
});

test("source tool: a site that can't say its commit fails, with no fallback, and the failure holds for the turn", async () => {
  for (const version of ["<html>", { core: "abc" }, { core: "ABCDEF0123".repeat(4) }, { nope: SHA }, () => ({ redirect: "https://evil.example" }), () => { throw new Error("down"); }]) {
    await withTool({ origin: "https://sagebrush.space", net: { version } }, async (src, calls) => {
      const r = await src({ op: "index" });
      assert.ok(r.isError && /which version/.test(text(r)), JSON.stringify(String(version)));
      await src({ op: "list" });
      assert.equal(calls.length, 1, "asked once a turn, never another site, never the archive");
    });
  }
});

test("source tool: index, list and read: bounded, inside the index, with the reasons for a skipped file", async () => {
  await withTool({}, async (src) => {
    assert.match(text(await src({ op: "index" })), /no INDEX\.md[\s\S]*README\.md[\s\S]*engine\//);
    assert.match(text(await src({ op: "list", path: "engine" })), /lib\.rs {2}\d+/);
    assert.match(text(await src({ op: "read", path: "engine/lib.rs" })), /1\tfn gcd/);
    assert.match(text(await src({ op: "read", path: "engine/lib.rs", from: 2, to: 2 })), /2\tfn lcm[^\n]*$/);
    for (const p of ["../x", "/etc/passwd", "engine/../README.md", "engine//lib.rs", "a\\b", "x".repeat(600)]) assert.ok((await src({ op: "read", path: p })).isError, p);
    assert.match(text(await src({ op: "read", path: "nope.rs" })), /isn't a file of this source/);
    assert.match(text(await src({ op: "read", path: "engine" })), /isn't a file/);
    assert.ok((await src({ op: "read", path: "README.md", from: 3, to: 1 })).isError);
    assert.ok((await src({ op: "nope" })).isError);
  });
});

test("source tool: search: hits as path:line, max and the 'at least' wording, line cuts, a giant line, a folder prefix", async () => {
  const many = tarOf([...Array.from({ length: 30 }, (_, i) => ent(`${ROOT()}/src/f${i}.rs`, "fn x() {}\n")), ent(`${ROOT()}/giant.txt`, "y".repeat(100_000) + "NEEDLE")]);
  await withTool({ net: { archive: () => gz(many) } }, async (src, calls) => {
    const r = text(await src({ op: "search", pattern: "fn x", max: 5 }));
    assert.match(r, /at least 5 matches \(stopped\)/);
    assert.equal((r.match(/^src\/f\d+\.rs:1: fn x/gm) ?? []).length, 5);
    assert.match(text(await src({ op: "search", pattern: "y{10}", max: 1 })), /giant\.txt:1: y{300}…/);
    assert.match(text(await src({ op: "search", pattern: "NEEDLE" })), /^0 matches/m, "a line is tested on its first 4,096 characters only");
    assert.match(text(await src({ op: "search", pattern: "fn x", path: "nowhere" })), /^0 matches/m);
    assert.ok((await src({ op: "search", pattern: "(" })).isError);
    assert.ok((await src({ op: "search", pattern: "a".repeat(201) })).isError);
    assert.ok((await src({ op: "search", pattern: "x", max: 201 })).isError);
    // (no request ever carries a pattern or a path)
    assert.ok(calls.every((c) => !/fn|NEEDLE|nowhere|giant/.test(c.url)));
    assert.equal(calls.length, 2);
  });
});

test("source tool: a catastrophic regex ends at the time limit; a fourth concurrent search is busy", async () => {
  const evil = tarOf([ent(`${ROOT()}/a.txt`, "a".repeat(40) + "!\n")]);
  await withTool({ net: { archive: () => gz(evil) }, limits: { searchMs: 400 } }, async (src) => {
    await src({ op: "index" });
    const t0 = Date.now();
    const r = await src({ op: "search", pattern: "^(a+)+$" });
    assert.ok(r.isError && /time limit/.test(text(r)) && Date.now() - t0 < 5000, `${text(r).slice(0, 200)} after ${Date.now() - t0} ms`);
    const runs = [1, 2, 3].map(() => src({ op: "search", pattern: "^(a+)+$" }));
    await new Promise((r) => setTimeout(r, 50));
    const fourth = await src({ op: "search", pattern: "x" });
    assert.ok(fourth.isError && /busy/.test(text(fourth)), "one running, two waiting, the fourth busy");
    await Promise.all(runs);
    assert.equal(searchPool.running, 0);
    assert.equal(searchPool.waiting.length, 0);
  });
});

test("source tool: the per-turn call limit, and the fixed requests charged to the turn's budget", async () => {
  await withTool({ limits: { callsPerTurn: 3 } }, async (src) => {
    for (let i = 0; i < 3; i++) assert.ok(!(await src({ op: "index" })).isError);
    assert.match(text(await src({ op: "index" })), /used its 3 source calls/);
  });
  const budget = new CardlessBudget();
  await withTool({ budget }, async (src) => {
    await src({ op: "index" });
    assert.equal(budget.calls, 2, "version.json and the archive: one call each");
    assert.equal(budget.bytes, 0, "with no chosen bytes");
  });
});

test("source tool: a redirect off codeload or another commit's archive: refused, and no slot kept", async () => {
  await withTool({ net: { archive: { redirect: "https://evil.example" } } }, async (src) => {
    assert.match(text(await src({ op: "index" })), /didn't give the Sagebrush source/);
  });
  await withTool({ net: { archive: () => gz(small(SHA2)) } }, async (src) => {
    assert.match(text(await src({ op: "index" })), /another commit/);
  });
});

test("sourcePath: relative, no '..', bounded", () => {
  assert.equal(sourcePath("engine/lib.rs"), "engine/lib.rs");
  assert.equal(sourcePath("engine/", { folder: true }), "engine");
  assert.equal(sourcePath(undefined, { folder: true }), "");
  for (const bad of ["", "/x", "a/../b", "a//b", ".", "a\\b", "x".repeat(513)]) assert.equal(sourcePath(bad), null, bad);
});
