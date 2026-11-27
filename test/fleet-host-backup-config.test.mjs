// Host backup, wiring r0.4 §1.2 with amendment A3 (r1) and the config tree design: each live agent's config entry
// proven from its committed snapshot's `tree` listing. Over real config trees (agent-config.mjs's own layout and
// reader), a fake store whose `tree` and `dump` answer from what was saved exactly as backup/src/ops.rs does (the
// source root's synthesized node, stored name order, a direct `.gen-<n>.tmp` never descended, bounded pages, the
// cursor), every request and result through the binary's own closed shapes, and the REAL restore comparison (configHash
// over the restored tree, as the restore's config import compares it with the manifest's entry).
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmodSync, linkSync, lstatSync, rmSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, readlinkSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "./host-linux-only.mjs";
import { EMPTY_CONFIG_HASH, GEN_TMP, MAX_BYTES, MAX_DEPTH, MAX_FILES, MAX_PATH_BYTES, configHash, readConfigTree } from "../lib/fleet/host/agent-config.mjs";
import { TREE_PAGE_MS, configFold, proveConfig } from "../lib/fleet/host/backup-config.mjs";
import { STRICT_MARK, checkRequest, parseResult } from "../lib/fleet/host/backup-binary.mjs";

const rm = (p) => rmSync(p, { recursive: true });
const sub = (p, name) => Buffer.concat([Buffer.from(p), Buffer.from("/"), name]);
const UID = typeof process.getuid === "function" ? process.getuid() : -1; // (Linux-only rows; off Linux the file only loads)
const GID = typeof process.getgid === "function" ? process.getgid() : -1;
const ID = "a".repeat(26);
const SNAP = "5".repeat(64);
const sha = (b) => createHash("sha256").update(b).digest("hex");
const GEN1 = { "manifest.json": '{"v":1}\n', "instructions.md": "be kind\n", skills: null, "skills/a": null, "skills/a/SKILL.md": "x" };
const GEN2 = { ...GEN1, "instructions.md": "be kinder\n" };

/** A live config tree: <base>/agent-config/<id>, 0700; its generations from { path: content | null (a directory) }. */
function live(gens = {}, current = null) {
  const base = mkdtempSync(join(tmpdir(), "sb-bcfg-"));
  chmodSync(base, 0o700);
  const root = join(base, "agent-config", ID);
  mkdirSync(root, { recursive: true, mode: 0o700 });
  chmodSync(join(base, "agent-config"), 0o700);
  chmodSync(root, 0o700);
  for (const [n, files] of Object.entries(gens)) writeGen(join(root, `gen-${n}`), files);
  if (current !== null) { writeFileSync(join(root, "current"), `gen-${current}\n`, { mode: 0o600 }); chmodSync(join(root, "current"), 0o600); }
  return { base, root };
}
function writeGen(dir, files) {
  mkdirSync(dir, { mode: 0o700 }); chmodSync(dir, 0o700);
  for (const [p, c] of Object.entries(files).sort()) {
    const full = join(dir, p);
    if (c === null) { mkdirSync(full, { mode: 0o700 }); chmodSync(full, 0o700); } else { writeFileSync(full, c, { mode: 0o600 }); chmodSync(full, 0o600); }
  }
}

/**
 * What a backup saved of `root`: its nodes as the archiver stores them, { name (Buffer), type, mode, uid, gid, nlink,
 * size, content (Buffer, a file's) | target (a link's) | children (a directory's, in stored name order) }. The root is
 * the backup source's own node: synthesized metadata (a directory, 0755, no owner), as the archiver stores it.
 */
function save(root) {
  const node = (p, name) => {
    const st = lstatSync(p);
    const meta = { name, mode: st.mode & 0o7777, uid: st.uid, gid: st.gid, nlink: st.isDirectory() ? null : st.nlink, size: 0 };
    if (st.isDirectory()) {
      const kids = readdirSync(p, { encoding: "buffer" }).sort(Buffer.compare);
      return { ...meta, type: "dir", children: kids.map((k) => node(sub(p, k), k)) };
    }
    if (st.isFile()) { const content = readFileSync(p); return { ...meta, type: "file", size: content.length, content }; }
    if (st.isSymbolicLink()) return { ...meta, type: "symlink", target: readlinkSync(p) };
    return { ...meta, type: "other" };
  };
  return { ...node(root, Buffer.from("")), mode: 0o755, uid: null, gid: null };
}
/** The saved node at `rel` (a "/"-separated path beneath the root), or undefined. */
const find = (saved, rel) => rel.split("/").reduce((n, c) => n?.children?.find((k) => k.name.toString() === c), saved);
const dir = (name, children = [], o = {}) => ({ name: Buffer.from(name), type: "dir", mode: 0o700, uid: UID, gid: GID, nlink: null, size: 0, children, ...o });
const file = (name, text, o = {}) => ({ name: Buffer.from(name), type: "file", mode: 0o600, uid: UID, gid: GID, nlink: 1, size: Buffer.byteLength(text), content: Buffer.from(text), ...o });

/**
 * The store's read ops over one saved snapshot, as backup/src/ops.rs answers them: `tree` (paged, at most `pageEntries`
 * entries and 4 MiB of lines a page) and `dump`. `spoil(req, value)` may alter a page; `fail(req)` returns a code.
 */
function store(saved, root, { pageEntries = 2048, spoil = (_req, v) => v, fail = () => null, laxCursor = false } = {}) {
  const calls = [];
  const rel = root.replace(/^\/+/, ""), digest = sha(rel);
  const flat = [];
  const walk = (n, path, depth) => {
    flat.push({ n, path, depth });
    const leftover = depth === 1 && GEN_TMP.test(n.name.toString("latin1"));
    if (n.type !== "dir" || leftover) return;
    for (const k of n.children) {
      const s = k.name.toString("utf8");
      if (!Buffer.from(s, "utf8").equals(k.name)) { flat.push({ refused: true }); return; }
      walk(k, path === "" ? s : `${path}/${s}`, depth + 1);
    }
  };
  walk(saved, "", 0);
  const answer = (op, value) => parseResult(JSON.stringify({ ok: true, ...value }) + "\n", 0, null, "", op);
  const binary = async (req, o) => {
    checkRequest(req);
    assert.equal(o.ms, TREE_PAGE_MS);
    calls.push(req.op === "tree" ? `tree:${req.cursor ?? 0}` : `${req.op}:${req.path}`);
    const code = fail(req);
    if (code) return { ok: false, code };
    if (req.snapshot !== SNAP) return { ok: false, code: "snapshot_missing" };
    if (req.op === "dump") {
      const n = find(saved, req.path.slice(rel.length + 1));
      return n?.type === "file" ? answer("dump", { text: n.content.toString("utf8") }) : { ok: false, code: "dump_failed" };
    }
    // A path not in the snapshot (another one, or an EMPTY source, which the archiver never stores: d2r7).
    if (req.path !== rel || saved.children?.length === 0) return { ok: false, code: "tree_absent" };
    let start = 0;
    if (req.cursor !== null && req.cursor !== undefined) {
      const [s, d, i] = req.cursor.split(":");
      if (!laxCursor && (s !== SNAP || d !== digest)) return { ok: false, code: "tree_refused" };
      start = Number(i);
    }
    const entries = [];
    let bytes = 0, next = null;
    for (let i = 0; i < flat.length; i++) {
      if (flat[i].refused) return { ok: false, code: "tree_refused" };
      if (i < start) continue;
      const { n, path } = flat[i];
      if (entries.length >= pageEntries) { next = `${SNAP}:${digest}:${i}`; break; }
      const e = { index: i, path, type: n.type, mode: n.mode, uid: n.uid, gid: n.gid, nlink: n.nlink, size: n.size, sha256: n.type === "file" ? (n.sha256 ?? sha(n.content)) : null };
      const len = JSON.stringify(e).length + 1;
      if (entries.length > 0 && bytes + len > 4 * 2 ** 20) { next = `${SNAP}:${digest}:${i}`; break; }
      bytes += len;
      entries.push(e);
    }
    if (start > 0 && entries.length === 0) return { ok: false, code: "tree_refused" };
    return answer("tree", spoil(req, { entries, next }));
  };
  binary.calls = calls;
  return binary;
}

/** The restore: the saved tree made again (exact modes) in a fresh place, and read as the restore's import reads it. */
function restored(saved) {
  const base = mkdtempSync(join(tmpdir(), "sb-bcfg-restore-"));
  chmodSync(base, 0o700);
  const at = join(base, ID);
  mkdirSync(at, { mode: 0o700 }); chmodSync(at, 0o700); // (the staged directory: the root's stored metadata is never used)
  const make = (n, p) => {
    if (n.type === "dir") { mkdirSync(p); for (const k of n.children) make(k, sub(p, k.name)); chmodSync(p, n.mode); }
    else if (n.type === "file") { writeFileSync(p, n.content); chmodSync(p, n.mode); }
    else if (n.type === "symlink") symlinkSync(n.target, p);
  };
  for (const k of saved.children) make(k, sub(at, k.name));
  return configHash(readConfigTree(at, { uid: UID }));
}
/** The committed snapshot's record as the store lists it: strict, naming the source (d2r8). */
const strictRecord = (root, o = {}) => ({ id: SNAP, paths: [root], tags: [STRICT_MARK], ...o });
/** The proof's answer: the hash, or the error's code. */
const prove = async (saved, root, o = {}) => { try { return await proveConfig(ID, SNAP, { binary: store(saved, root, o), record: "record" in o ? o.record : strictRecord(root), root, uid: UID }); } catch (e) { return e.code; } };
/** The restore's answer: the hash, or "refused". */
const restore = (saved) => { try { return restored(saved); } catch { return "refused"; } };

test("a configured tree: the saved current's generation binds the live generation's hash; the real restore comparison agrees", async () => {
  const t = live({ 1: GEN1 }, 1);
  const saved = save(t.root);
  const b = store(saved, t.root);
  const h = await proveConfig(ID, SNAP, { binary: b, root: t.root, uid: UID });
  assert.equal(h, readConfigTree(t.root, { uid: UID }).generations["1"].hash);
  assert.notEqual(h, EMPTY_CONFIG_HASH);
  assert.equal(restored(saved), h, "the restore's configHash over the restored tree equals the manifest's entry");
  assert.deepEqual(b.calls, ["tree:0", `dump:${t.root.slice(1)}/current`], "one page, then current's text");
});

test("A3, d2r8: an empty source (never saved: tree_absent) binds EMPTY_CONFIG_HASH only from a strict snapshot naming it exactly; the real restore comparison agrees", async () => {
  const t = live();
  const saved = save(t.root);
  const b = store(saved, t.root);
  assert.equal(await proveConfig(ID, SNAP, { binary: b, record: strictRecord(t.root), root: t.root, uid: UID }), EMPTY_CONFIG_HASH);
  assert.deepEqual(b.calls, ["tree:0"], "nothing more is read");
  assert.equal(restored(saved), EMPTY_CONFIG_HASH, "the stage's own empty directory, read by agent-config");
  // T5: the mark twice (the closed shape accepts it; only the binary writes it, once) is read as marked.
  assert.equal(await prove(saved, t.root, { record: strictRecord(t.root, { tags: [STRICT_MARK, STRICT_MARK] }) }), EMPTY_CONFIG_HASH);
  // Every other absence is unbound: the corrupt-as-empty control.
  for (const [what, record] of [["no record", null], ["not strict (no mark)", strictRecord(t.root, { tags: [] })],
    ["a caller-like tag, not the mark", strictRecord(t.root, { tags: ["sagebrush.walk=lax"] })],
    ["the mark with a suffix", strictRecord(t.root, { tags: ["sagebrush.walk=strictX"] })], ["the mark with a trailing space", strictRecord(t.root, { tags: ["sagebrush.walk=strict "] })],
    ["the mark's key, no value", strictRecord(t.root, { tags: ["sagebrush.walk="] })], ["the mark in another case", strictRecord(t.root, { tags: ["SAGEBRUSH.WALK=strict"] })],
    ["the mark inside a longer tag", strictRecord(t.root, { tags: ["x.sagebrush.walk=strict"] })], ["the mark as a prefix", strictRecord(t.root, { tags: ["sagebrush.walk=stric"] })], ["another snapshot's record", strictRecord(t.root, { id: "6".repeat(64) })],
    ["the source not in paths", strictRecord(t.root, { paths: ["/srv/sagebrush/agents/x/home"] })], ["a parent in paths (a prefix)", strictRecord(t.root, { paths: [join(t.root, "..")] })],
    ["the parent's path as text", strictRecord(t.root, { paths: [t.root.slice(0, t.root.lastIndexOf("/"))] })], ["a trailing slash", strictRecord(t.root, { paths: [`${t.root}/`] })],
    ["a longer path", strictRecord(t.root, { paths: [`${t.root}x`] })], ["paths not a list", strictRecord(t.root, { paths: t.root })]]) {
    assert.equal(await prove(saved, t.root, { record }), "config_unbound", what);
  }
  const c = live({ 1: GEN1 }, 1);
  // tree_absent past the first page is never an empty source.
  assert.equal(await prove(save(c.root), c.root, { pageEntries: 3, fail: (req) => (req.cursor ? "tree_absent" : null) }), "config_unbound");
});

test("d2r6: the root is the source's synthesized node, checked for its type only (0755, no owner, proven); a root that isn't a directory is unbound", async () => {
  const t = live({ 1: GEN1 }, 1);
  const saved = save(t.root);
  assert.deepEqual([saved.mode, saved.uid, saved.gid], [0o755, null, null]);
  assert.equal(await prove(saved, t.root), restored(saved));
  const odd = { ...saved, mode: 0o4777, uid: 12345, gid: null };
  assert.equal(await prove(odd, t.root), restored(saved), "any metadata on the root: never restored, never judged");
  assert.equal(await prove({ ...file("", "x"), mode: 0o755 }, t.root), "config_unbound");
});

test("a change from 1 to 2 during the run: the save holds current = 2 and all of gen-2, so the entry is gen-2's hash, not gen-1's", async () => {
  const t = live({ 1: GEN1, 2: GEN2 }, 2);
  const saved = save(t.root);
  const tree = readConfigTree(t.root, { uid: UID });
  const h = await prove(saved, t.root);
  assert.equal(h, tree.generations["2"].hash);
  assert.notEqual(h, tree.generations["1"].hash);
  assert.equal(restored(saved), h);
});

test("leftovers: a .gen-<n>.tmp is a node only (its contents never listed: a non-UTF-8 name, an over-long path, a large sparse file inside); a .current.tmp file or link", async () => {
  const t = live({ 1: GEN1 }, 1);
  const tmp = join(t.root, ".gen-2.tmp");
  mkdirSync(tmp, { mode: 0o700 }); chmodSync(tmp, 0o700);
  writeFileSync(Buffer.concat([Buffer.from(`${tmp}/bad-`), Buffer.from([0xff])]), "y");
  let deep = tmp;
  for (let i = 0; i < MAX_DEPTH + 16; i++) { deep = join(deep, "d"); mkdirSync(deep); } // (deeper than MAX_DEPTH)
  writeFileSync(join(tmp, "big"), Buffer.alloc(0));
  symlinkSync("gen-1\n", join(t.root, ".current.tmp"));
  const saved = save(t.root);
  find(saved, ".gen-2.tmp/big").size = MAX_BYTES + 1; // (a large file inside: never hashed, never counted)
  find(saved, ".gen-2.tmp/big").sha256 = "0".repeat(64);
  const b = store(saved, t.root);
  const h = await proveConfig(ID, SNAP, { binary: b, root: t.root, uid: UID });
  assert.equal(h, readConfigTree(t.root, { uid: UID }).generations["1"].hash);
  assert.equal(restored(saved), h, "the restore's reader never reads inside the leftover either");
  // A path longer than MAX_PATH_BYTES inside it (in the save only: no live path can be that long).
  let d = find(saved, ".gen-2.tmp");
  for (let i = 0; i < 20; i++) { const k = dir("e".repeat(250)); d.children.push(k); d = k; }
  assert.equal(await prove(saved, t.root), h);
  // A .current.tmp that's a regular file like current is a leftover too.
  const u = live({ 1: GEN1 }, 1);
  writeFileSync(join(u.root, ".current.tmp"), "gen-1\n", { mode: 0o600 }); chmodSync(join(u.root, ".current.tmp"), 0o600);
  const s2 = save(u.root);
  assert.equal(await prove(s2, u.root), restored(s2));
});

test("a maximal tree across pages: MAX_FILES files in a generation, listed in pages, proven; one file more is unbound, and the reader refuses it too", async () => {
  const files = { manifest: "m" };
  for (let i = 1; i < MAX_FILES; i++) files[`f${i}`] = `${i}`;
  const t = live({ 1: files }, 1);
  const saved = save(t.root);
  const b = store(saved, t.root);
  const h = await proveConfig(ID, SNAP, { binary: b, root: t.root, uid: UID });
  assert.equal(h, readConfigTree(t.root, { uid: UID }).generations["1"].hash);
  assert.deepEqual(b.calls.slice(0, 3), ["tree:0", `tree:${SNAP}:${sha(t.root.slice(1))}:2048`, `tree:${SNAP}:${sha(t.root.slice(1))}:4096`]);
  assert.equal(restored(saved), h);
  // Small pages: the same hash, whatever the page size.
  assert.equal(await prove(saved, t.root, { pageEntries: 7 }), h);
  writeFileSync(join(t.root, "gen-1", "one-more"), "x", { mode: 0o600 }); chmodSync(join(t.root, "gen-1", "one-more"), 0o600);
  const over = save(t.root);
  assert.equal(await prove(over, t.root), "config_unbound");
  assert.equal(restore(over), "refused");
});

test("the bounds, as the reader's: depth MAX_DEPTH proven and one deeper unbound; a path of MAX_PATH_BYTES and one byte more; MAX_BYTES and one byte more; MAX_GENERATIONS and one more", async () => {
  // Depth: live trees, so the reader itself agrees.
  const chain = (k) => { const f = { }; let p = ""; for (let i = 0; i < k; i++) { p = p === "" ? "d" : `${p}/d`; f[p] = null; } return f; };
  for (const [k, want] of [[MAX_DEPTH, "proven"], [MAX_DEPTH + 1, "config_unbound"]]) {
    const t = live({ 1: chain(k) }, 1);
    const saved = save(t.root);
    const got = await prove(saved, t.root);
    assert.equal(got === "config_unbound" ? got : "proven", want, `depth ${k}`);
    assert.equal(restore(saved), got === "config_unbound" ? "refused" : got, `depth ${k}: the reader agrees`);
  }
  // A path's bytes (gen-1/<rel>): beneath one directory named to fill the bound exactly.
  const at = (len) => { const s = live({ 1: GEN1 }, 1); const saved = save(s.root); const n = "x".repeat(255); const segs = []; let left = len; while (left > 256) { segs.push(n); left -= 256; } const g = find(saved, "gen-1"); let d = g; for (const sg of segs) { const k = dir(sg); d.children.push(k); d = k; } d.children.push(file("y".repeat(left), "z")); return { s, saved }; };
  for (const [len, want] of [[MAX_PATH_BYTES, "proven"], [MAX_PATH_BYTES + 1, "config_unbound"]]) {
    const { s, saved } = at(len);
    const got = await prove(saved, s.root);
    assert.equal(got === "config_unbound" ? got : "proven", want, `path ${len}`);
  }
  // A generation's bytes: sizes as stored (their digests as listed).
  const big = (total) => { const s = live({ 1: { m: "" } }, 1); const saved = save(s.root); const g = find(saved, "gen-1"); g.children = [file("a", "", { size: total - 1, sha256: "a".repeat(64) }), file("b", "", { size: 1, sha256: "b".repeat(64) })]; return { s, saved }; };
  assert.notEqual(await prove(big(MAX_BYTES).saved, big(MAX_BYTES).s.root), "config_unbound");
  const over = big(MAX_BYTES + 1);
  assert.equal(await prove(over.saved, over.s.root), "config_unbound");
  // Generations: live, so the reader agrees.
  for (const [k, want] of [[16, "proven"], [17, "config_unbound"]]) {
    const gens = {};
    for (let i = 1; i <= k; i++) gens[i] = { m: `${i}` };
    const t = live(gens, 1);
    const saved = save(t.root);
    const got = await prove(saved, t.root);
    assert.equal(got === "config_unbound" ? got : "proven", want, `${k} generations`);
    assert.equal(restore(saved), got === "config_unbound" ? "refused" : got);
  }
});

test("SEC: substitutions and foreign entries are unbound, and the real restore refuses them too (or they are never restored as proven)", async () => {
  const cases = {
    "a generation substituted by a link to a directory": (t) => { const g = join(t.root, "gen-1"); const o = join(t.base, "elsewhere"); writeGen(o, GEN1); rm(g); symlinkSync(o, g); },
    "a directory beneath a generation substituted by a link": (t) => { const p = join(t.root, "gen-1", "skills"); rm(p); symlinkSync("/etc", p); },
    "current a directory": (t) => { rm(join(t.root, "current")); mkdirSync(join(t.root, "current"), { mode: 0o700 }); chmodSync(join(t.root, "current"), 0o700); },
    "current a link": (t) => { rm(join(t.root, "current")); symlinkSync("/etc/hostname", join(t.root, "current")); },
    "current hard-linked": (t) => { linkSync(join(t.root, "current"), join(t.base, "other-name")); },
    "a .current.tmp hard-linked": (t) => { writeFileSync(join(t.root, ".current.tmp"), "gen-1\n", { mode: 0o600 }); chmodSync(join(t.root, ".current.tmp"), 0o600); linkSync(join(t.root, ".current.tmp"), join(t.base, "x")); },
    "a .current.tmp directory": (t) => { mkdirSync(join(t.root, ".current.tmp"), { mode: 0o700 }); chmodSync(join(t.root, ".current.tmp"), 0o700); },
    "a foreign entry at the root": (t) => { writeFileSync(join(t.root, "notes"), "x", { mode: 0o600 }); chmodSync(join(t.root, "notes"), 0o600); },
    "a non-canonical generation name": (t) => { writeGen(join(t.root, "gen-01"), GEN1); },
    "two leftovers in progress": (t) => { for (const n of [2, 3]) { mkdirSync(join(t.root, `.gen-${n}.tmp`), { mode: 0o700 }); chmodSync(join(t.root, `.gen-${n}.tmp`), 0o700); } },
    "a leftover that isn't a directory": (t) => { writeFileSync(join(t.root, ".gen-2.tmp"), "x", { mode: 0o600 }); chmodSync(join(t.root, ".gen-2.tmp"), 0o600); },
    "a file's mode 0640": (t) => { chmodSync(join(t.root, "gen-1", "manifest.json"), 0o640); },
    "a file setuid 04600": (t) => { chmodSync(join(t.root, "gen-1", "manifest.json"), 0o4600); },
    "a directory's mode 0750": (t) => { chmodSync(join(t.root, "gen-1", "skills"), 0o750); },
    "a directory sticky 01700": (t) => { chmodSync(join(t.root, "gen-1", "skills"), 0o1700); },
    "a generation's mode 0755": (t) => { chmodSync(join(t.root, "gen-1"), 0o755); },
    "current's mode 0644": (t) => { chmodSync(join(t.root, "current"), 0o644); },
    "a link in a generation": (t) => { symlinkSync("manifest.json", join(t.root, "gen-1", "ln")); },
  };
  // A type substitution that leaves a well-formed generation (a file for an empty 0700 directory, or the reverse) is
  // another listing: proven as what was saved, never as the original, and the reader agrees.
  for (const [rel, make] of [["instructions.md", (p) => { mkdirSync(p, { mode: 0o700 }); chmodSync(p, 0o700); }], ["skills", (p) => { writeFileSync(p, "x", { mode: 0o600 }); chmodSync(p, 0o600); }]]) {
    const f = live({ 1: GEN1 }, 1);
    const p = join(f.root, "gen-1", rel);
    const before = readConfigTree(f.root, { uid: UID }).generations["1"].hash;
    rm(p); make(p);
    const fs2 = save(f.root);
    assert.equal(await prove(fs2, f.root), restored(fs2), rel);
    assert.notEqual(restored(fs2), before, rel);
  }
  for (const [what, spoil] of Object.entries(cases)) {
    const t = live({ 1: GEN1 }, 1);
    spoil(t);
    const saved = save(t.root);
    assert.equal(await prove(saved, t.root), "config_unbound", what);
    const r = restore(saved);
    // (a hard link is restored as one link, so the reader would take it: the proof is stricter, never laxer)
    if (!/hard-linked/.test(what)) assert.equal(r, "refused", `${what}: the reader refuses it too`);
  }
});

test("owners: another owner on a file, a directory, current or a generation, or a directory's group other than 0 under root, is unbound", async () => {
  const t = live({ 1: GEN1 }, 1);
  for (const [what, p, o] of [["a file's uid", "gen-1/manifest.json", { uid: UID + 1 }], ["a directory's uid", "gen-1/skills", { uid: UID + 1 }],
    ["current's uid", "current", { uid: UID + 1 }], ["a generation's uid", "gen-1", { uid: UID + 1 }], ["a missing uid", "gen-1/manifest.json", { uid: null }],
    ["a missing mode", "gen-1/skills", { mode: null }]]) {
    const saved = save(t.root);
    Object.assign(find(saved, p), o);
    assert.equal(await prove(saved, t.root), "config_unbound", what);
  }
  // Under root (uid 0), a directory's gid must be 0, as the reader's.
  const root = (gid) => { const fold = configFold({ uid: 0 }); fold.add({ index: 0, path: "", type: "dir", mode: 0o755, uid: null, gid: null, nlink: null, size: 0, sha256: null }); fold.add({ index: 1, path: "gen-1", type: "dir", mode: 0o700, uid: 0, gid, nlink: null, size: 0, sha256: null }); return fold.finish(); };
  assert.equal(root(0).generations.size, 1);
  assert.throws(() => root(5), (e) => e.code === "config_unbound");
});

test("every corrupt or unprovable tree is config_unbound, never EMPTY_CONFIG_HASH (the corrupt-as-empty control)", async () => {
  const cases = {
    "generations saved, no current": (t) => { rm(join(t.root, "current")); },
    "current not a generation's name (a bare number)": (t) => { writeFileSync(join(t.root, "current"), "1\n"); },
    "current not canonical": (t) => { writeFileSync(join(t.root, "current"), "gen-01\n"); },
    "current without its newline": (t) => { writeFileSync(join(t.root, "current"), "gen-1"); },
    "current naming a generation not saved": (t) => { writeFileSync(join(t.root, "current"), "gen-3\n"); },
    "current naming the leftover": (t) => { mkdirSync(join(t.root, ".gen-3.tmp"), { mode: 0o700 }); chmodSync(join(t.root, ".gen-3.tmp"), 0o700); writeFileSync(join(t.root, "current"), "gen-3\n"); },
  };
  for (const [what, spoil] of Object.entries(cases)) {
    const t = live({ 1: GEN1 }, 1);
    spoil(t);
    const saved = save(t.root);
    assert.equal(await prove(saved, t.root), "config_unbound", what);
    assert.equal(restore(saved), "refused", `${what}: the reader refuses it too`);
  }
  // The save without the path at all, from a snapshot that doesn't name it: unbound.
  const t = live({ 1: GEN1 }, 1);
  await assert.rejects(proveConfig(ID, SNAP, { binary: store(save(t.root), t.root), record: strictRecord(t.root), root: `${t.root}-gone`, uid: UID }), (e) => e.code === "config_unbound");
  // current's dumped text not the listed one (another file read than the one listed), naming a saved generation.
  const t2 = live({ 1: GEN1, 2: GEN2 }, 1);
  const s = save(t2.root);
  find(s, "current").sha256 = sha("gen-1\n");
  find(s, "current").content = Buffer.from("gen-2\n");
  assert.equal(await prove(s, t2.root), "config_unbound");
});

test("d2r2 §A: pages that break continuity are unbound (a gap, a repeat, a reorder, an empty page, a cursor not naming the next entry)", async () => {
  const t = live({ 1: GEN1 }, 1);
  const saved = save(t.root);
  const h = await prove(saved, t.root, { pageEntries: 3 });
  assert.equal(h, restored(saved));
  const first = (req) => req.cursor === null;
  const second = (req) => req.cursor !== null;
  const spoils = {
    "a gap within a page": (req, v) => (first(req) ? { ...v, entries: [v.entries[0], v.entries[2]] } : v),
    "a gap between pages": (req, v) => (second(req) ? { ...v, entries: v.entries.slice(1) } : v),
    "a repeat": (req, v) => (first(req) ? { ...v, entries: [v.entries[0], v.entries[1], v.entries[1]] } : v),
    "a reorder": (req, v) => (first(req) ? { ...v, entries: [v.entries[0], v.entries[2], v.entries[1]] } : v),
    "a cursor past the next entry": (req, v) => (first(req) ? { ...v, next: v.next.replace(/:3$/, ":4") } : v),
    "a cursor before it": (req, v) => (first(req) ? { ...v, next: v.next.replace(/:3$/, ":2") } : v),
    "a cursor of another path": (req, v) => (first(req) ? { ...v, next: v.next.replace(/:[0-9a-f]{64}:/, `:${"0".repeat(64)}:`) } : v),
    "a cursor of another snapshot": (req, v) => (first(req) ? { ...v, next: v.next.replace(/^[0-9a-f]{64}/, "6".repeat(64)) } : v),
  };
  for (const [what, spoil] of Object.entries(spoils)) assert.equal(await prove(saved, t.root, { pageEntries: 3, spoil }), "config_unbound", what);
  // A page whose count and cursor are right but an entry is another one repeated, its own index kept (a generation's
  // file listed twice, one not at all): only the indices show it.
  const dup = (req, v) => (second(req) ? { ...v, entries: [v.entries[0], v.entries[0], ...v.entries.slice(2)] } : v);
  assert.equal(await prove(saved, t.root, { pageEntries: 3, spoil: dup }), "config_unbound", "a repeat replacing an entry");
  // A binary that would serve a foreign cursor: the proof never sends one (its own check, not the binary's).
  for (const [what, spoil] of Object.entries({ "another snapshot's": spoils["a cursor of another snapshot"], "another path's": spoils["a cursor of another path"] })) {
    assert.equal(await prove(saved, t.root, { pageEntries: 3, spoil, laxCursor: true }), "config_unbound", `${what} cursor, served`);
  }
  // An empty page isn't even a closed tree result: bad_result, a transport failure.
  assert.equal(await prove(saved, t.root, { pageEntries: 3, spoil: (req, v) => (second(req) ? { ...v, entries: [] } : v) }), "bad_result");
});

test("N2: a transport failure keeps its own code (transient, never config_unbound); tree_refused is structural; a lost lock stays lock_lost", async () => {
  const t = live({ 1: GEN1 }, 1);
  const saved = save(t.root);
  for (const code of ["tree_failed", "timed_out", "spawn_failed", "bad_result", "open_failed", "index_failed", "dump_failed"]) {
    assert.equal(await prove(saved, t.root, { pageEntries: 3, fail: (req) => (req.cursor ? code : null) }), code, `${code} on a later page`);
  }
  assert.equal(await prove(saved, t.root, { fail: (req) => (req.op === "dump" ? "dump_failed" : null) }), "dump_failed", "current's dump failing");
  assert.equal(await prove(saved, t.root, { pageEntries: 3, fail: (req) => (req.cursor ? "tree_refused" : null) }), "config_unbound");
  // On the first page too, with a strict record naming the source: refused is structural, never an empty source.
  assert.equal(await prove(saved, t.root, { fail: (req) => (req.op === "tree" ? "tree_refused" : null) }), "config_unbound");
  const b = store(saved, t.root, { pageEntries: 3 });
  let n = 0;
  const lossy = async (req, o) => { if (++n === 2) throw Object.assign(new Error("lost"), { code: "lock_lost" }); return b(req, o); };
  await assert.rejects(proveConfig(ID, SNAP, { binary: lossy, root: t.root, uid: UID }), (e) => e.code === "lock_lost");
  const thrower = async () => { throw new Error("a bug"); };
  await assert.rejects(proveConfig(ID, SNAP, { binary: thrower, root: t.root, uid: UID }), (e) => e.code === "outcome_unknown");
});


test("the census: agent-config's GEN_TMP and the binary's is_gen_tmp agree on one shared case table", () => {
  const t = JSON.parse(readFileSync(new URL("../backup/tests/gen-tmp-cases.json", import.meta.url), "utf8"));
  assert.ok(t.cases.length >= 30);
  for (const c of t.cases) assert.equal(GEN_TMP.test(c.name), c.leftover, JSON.stringify(c.name));
});

test("the listing is rebuilt in byte order of path, as listGeneration's (the walk's order differs: \"a/x\" is walked before \"a-b\"; UTF-16 order differs past the BMP)", async () => {
  const t = live({ 1: { a: null, "a/x": "1", "a-b": "2", "a.c": "3", b: "4", "\u{ff61}": "5", "\u{1f600}": "6" } }, 1);
  const saved = save(t.root);
  const h = await prove(saved, t.root);
  assert.equal(h, readConfigTree(t.root, { uid: UID }).generations["1"].hash);
  assert.equal(restored(saved), h);
});

test("an entry beneath anything but the generation being read is unbound (a page that isn't depth first)", () => {
  const node = (index, path, type, o = {}) => ({ index, path, type, mode: type === "dir" ? 0o700 : 0o600, uid: UID, gid: GID, nlink: type === "dir" ? null : 1, size: 1, sha256: type === "file" ? "a".repeat(64) : null, ...o });
  const run = (entries) => { const f = configFold({ uid: UID }); for (const e of entries) f.add(e); return f.finish(); };
  const root = node(0, "", "dir", { mode: 0o755, uid: null, gid: null });
  assert.equal(run([root, node(1, "gen-1", "dir"), node(2, "gen-1/a", "file"), node(3, "gen-2", "dir"), node(4, "gen-2/b", "file")]).generations.size, 2);
  for (const [what, entries] of [["beneath an earlier generation", [root, node(1, "gen-1", "dir"), node(2, "gen-2", "dir"), node(3, "gen-1/a", "file")]],
    ["beneath a generation not yet listed", [root, node(1, "gen-1", "dir"), node(2, "gen-2/a", "file")]],
    ["beneath current", [root, node(1, "current", "file", { size: 6 }), node(2, "current/x", "file")]],
    ["beneath a leftover", [root, node(1, ".gen-2.tmp", "dir"), node(2, ".gen-2.tmp/x", "file")]],
    ["before any direct entry", [root, node(1, "gen-1/a", "file")]]]) {
    assert.throws(() => run(entries), (e) => e.code === "config_unbound", what);
  }
});

test("the binary's closed tree result: exactly its keys and types; anything else is bad_result", () => {
  const e = { index: 0, path: "", type: "dir", mode: 0o755, uid: null, gid: null, nlink: null, size: 0, sha256: null };
  const f = { index: 1, path: "current", type: "file", mode: 0o600, uid: 0, gid: 0, nlink: 1, size: 6, sha256: "a".repeat(64) };
  const parse = (v) => parseResult(JSON.stringify({ ok: true, ...v }) + "\n", 0, null, "", "tree");
  assert.equal(parse({ entries: [e, f], next: null }).ok, true);
  assert.equal(parse({ entries: [e], next: `${SNAP}:${"b".repeat(64)}:1` }).ok, true);
  for (const [what, v] of [["no entries", { entries: [], next: null }], ["an extra key", { entries: [e], next: null, more: 1 }],
    ["an entry's extra key", { entries: [{ ...e, x: 1 }], next: null }], ["a file without its digest", { entries: [{ ...f, sha256: null }], next: null }],
    ["a directory with a digest", { entries: [{ ...e, sha256: "a".repeat(64) }], next: null }], ["a mode past 07777", { entries: [{ ...f, mode: 0o10000 }], next: null }],
    ["an unknown type", { entries: [{ ...e, type: "socket" }], next: null }], ["nlink 0", { entries: [{ ...f, nlink: 0 }], next: null }],
    ["an absolute path", { entries: [{ ...f, path: "/current" }], next: null }], ["a negative size", { entries: [{ ...f, size: -1 }], next: null }],
    ["a malformed cursor", { entries: [e], next: `${SNAP}:1` }], ["a cursor's index not canonical", { entries: [e], next: `${SNAP}:${"b".repeat(64)}:01` }],
    ["more than a page", { entries: Array.from({ length: 2049 }, (_, i) => ({ ...e, index: i })), next: null }]]) {
    assert.equal(parse(v).code, "bad_result", what);
  }
  // The strict mark is the binary's own: a backup request can't carry it (d2r8).
  assert.doesNotThrow(() => checkRequest({ op: "backup", sources: ["/srv/x"], host: "h", tags: ["sagebrush.run=1"] }));
  for (const tag of [STRICT_MARK, "sagebrush.walk=lax", "sagebrush.walk="]) {
    assert.throws(() => checkRequest({ op: "backup", sources: ["/srv/x"], host: "h", tags: [tag] }), (x) => x.code === "bad_form", tag);
  }
  // T5: tags are case-sensitive: another case is a caller's ordinary tag (and never the mark, above).
  assert.doesNotThrow(() => checkRequest({ op: "backup", sources: ["/srv/x"], host: "h", tags: ["SAGEBRUSH.WALK=strict"] }));
  // T4: at most 63 caller tags (the mark makes 64, the closed shape's most).
  const tags = (n) => Array.from({ length: n }, (_, i) => `t${i}=x`);
  assert.doesNotThrow(() => checkRequest({ op: "backup", sources: ["/srv/x"], host: "h", tags: tags(63) }));
  assert.throws(() => checkRequest({ op: "backup", sources: ["/srv/x"], host: "h", tags: tags(64) }), (x) => x.code === "bad_form");
  const snap = (n) => parseResult(JSON.stringify({ ok: true, snapshot: { id: SNAP, time: "t", tree: SNAP, host: "h", paths: ["/srv/x"], tags: [...tags(n), STRICT_MARK], summary: null }, cache_full: false }) + "\n", 0, null, "", "backup");
  assert.equal(snap(63).ok, true, "a 63-tag request's snapshot, 64 with the mark, passes the closed shape");
  assert.equal(snap(64).code, "bad_result", "65 never does");
  // T6: no request carries a strictness of its own, for any class's backup (an unknown field is refused).
  for (const extra of [{ strict: false }, { strict: true }, { nonstrict: 1 }]) {
    assert.throws(() => checkRequest({ op: "backup", sources: ["/srv/x"], host: "h", ...extra }), (x) => x.code === "bad_form", JSON.stringify(extra));
  }
  assert.doesNotThrow(() => checkRequest({ op: "tree", snapshot: SNAP, path: "srv/x", cursor: null }));
  assert.doesNotThrow(() => checkRequest({ op: "tree", snapshot: SNAP, path: "srv/x" }));
  for (const r of [{ op: "tree", snapshot: SNAP, path: "/srv/x" }, { op: "tree", snapshot: SNAP, path: "srv/../x" }, { op: "tree", snapshot: SNAP, path: "srv/x", cursor: "x" }, { op: "tree", snapshot: SNAP, path: "srv/x", depth: 1 }]) {
    assert.throws(() => checkRequest(r), (x) => x.code === "bad_form", JSON.stringify(r));
  }
});
