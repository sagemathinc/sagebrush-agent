// Host backup, wiring r0.4 §1.2 with amendment A3 (r1): each live agent's config entry proven from its committed
// snapshot. Over real config trees (agent-config.mjs's own layout and reader), a fake store whose `usage` and `dump`
// answer from what was saved, and the REAL restore comparison (configHash over the restored tree, as the restore's
// config import compares it with the manifest's entry).
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "./host-linux-only.mjs";
import { EMPTY_CONFIG_HASH, configHash, readConfigTree } from "../lib/fleet/host/agent-config.mjs";
import { proveConfig } from "../lib/fleet/host/backup-config.mjs";

const UID = typeof process.getuid === "function" ? process.getuid() : -1; // (Linux-only rows; off Linux the file only loads)
const ID = "a".repeat(26);
const SNAP = "5".repeat(64);
const unbound = (p) => assert.rejects(p, (e) => e?.code === "config_unbound");
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

/** What a backup saved of `root`: { relative path (no leading "/"): content | null (a directory) }, the root included. */
function save(root) {
  const out = {};
  const rel = (p) => p.replace(/^\/+/, "");
  const walk = (p) => {
    const st = lstatSync(p);
    if (st.isDirectory()) { out[rel(p)] = null; for (const n of readdirSync(p)) walk(join(p, n)); } else out[rel(p)] = readFileSync(p, "utf8");
  };
  walk(root);
  return out;
}

/** The store's read ops over one saved snapshot: usage counts the entries strictly beneath a saved directory; dump a saved file. */
function store(saved, { fail = () => false } = {}) {
  const calls = [];
  const binary = async (req) => {
    calls.push(`${req.op}:${req.path}`);
    if (req.snapshot !== SNAP || fail(req)) return { ok: false, code: `${req.op}_failed` };
    if (req.op === "usage") {
      if (saved[req.path] !== null || !Object.hasOwn(saved, req.path)) return { ok: false, code: "usage_failed" };
      const entries = Object.keys(saved).filter((p) => p.startsWith(`${req.path}/`)).length;
      return { ok: true, value: { snapshot: SNAP, entries, inodes: entries, blocks_upper: 0, peak_inodes: entries, peak_blocks_upper: 0, block_size: 4096 } };
    }
    if (req.op === "dump") return typeof saved[req.path] === "string" ? { ok: true, value: { text: saved[req.path] } } : { ok: false, code: "dump_failed" };
    return { ok: false, code: "request_invalid" };
  };
  binary.calls = calls;
  return binary;
}

/** The restore: the saved tree made again (exact modes) in a fresh place, and read as the restore's import reads it. */
function restored(saved, root) {
  const base = mkdtempSync(join(tmpdir(), "sb-bcfg-restore-"));
  chmodSync(base, 0o700);
  const at = join(base, ID), prefix = root.replace(/^\/+/, "");
  for (const p of Object.keys(saved).filter((x) => x === prefix || x.startsWith(`${prefix}/`)).sort()) {
    const full = join(at, p.slice(prefix.length));
    if (saved[p] === null) { mkdirSync(full, { mode: 0o700 }); chmodSync(full, 0o700); } else { writeFileSync(full, saved[p], { mode: 0o600 }); chmodSync(full, 0o600); }
  }
  return configHash(readConfigTree(at, { uid: UID }));
}

test("a configured tree: the saved current's generation, complete and byte-identical, binds the live generation's hash; the real restore comparison agrees", async () => {
  const t = live({ 1: GEN1 }, 1);
  const saved = save(t.root);
  const h = await proveConfig(ID, SNAP, { binary: store(saved), root: t.root, uid: UID });
  assert.equal(h, readConfigTree(t.root, { uid: UID }).generations["1"].hash);
  assert.notEqual(h, EMPTY_CONFIG_HASH);
  assert.equal(restored(saved, t.root), h, "the restore's configHash over the restored tree equals the manifest's entry");
});

test("A3: a saved tree that is provably empty (its directory saved, nothing beneath) binds EMPTY_CONFIG_HASH; the real restore comparison agrees", async () => {
  const t = live();
  const saved = save(t.root);
  const b = store(saved);
  assert.equal(await proveConfig(ID, SNAP, { binary: b, root: t.root, uid: UID }), EMPTY_CONFIG_HASH);
  assert.deepEqual(b.calls, [`usage:${t.root.slice(1)}`], "nothing more is read");
  assert.equal(restored(saved, t.root), EMPTY_CONFIG_HASH);
});

test("a change from 1 to 2 during the run: the save holds current = 2 and all of gen-2, so the entry is gen-2's hash, not gen-1's", async () => {
  const t = live({ 1: GEN1, 2: GEN2 }, 2);
  const saved = save(t.root);
  const tree = readConfigTree(t.root, { uid: UID });
  const h = await proveConfig(ID, SNAP, { binary: store(saved), root: t.root, uid: UID });
  assert.equal(h, tree.generations["2"].hash);
  assert.notEqual(h, tree.generations["1"].hash);
  assert.equal(restored(saved, t.root), h);
});

test("the traversal race: the saved current names gen-2 but the walk predates it (no gen-2 in the save): config_unbound; a live-only check would wrongly pass (the control)", async () => {
  const t = live({ 1: GEN1 }, 1);
  const saved = save(t.root); // the listing, taken before the writer installs gen-2
  writeGen(join(t.root, "gen-2"), GEN2);
  writeFileSync(join(t.root, "current"), "gen-2\n", { mode: 0o600 });
  saved[`${t.root.slice(1)}/current`] = "gen-2\n"; // (current read after the install: the race)
  await unbound(proveConfig(ID, SNAP, { binary: store(saved), root: t.root, uid: UID }));
  // The control: the live tree alone hashes fine, so a live-only (or saved-pointer plus live generation) check passes.
  assert.equal(configHash(readConfigTree(t.root, { uid: UID })), readConfigTree(t.root, { uid: UID }).generations["2"].hash);
  assert.throws(() => restored(saved, t.root), "and the save itself isn't even a readable tree");
});

test("every corrupt or unprovable tree is config_unbound, never EMPTY_CONFIG_HASH (the corrupt-as-empty control)", async () => {
  const cases = {
    "the path missing from the save": (t, s) => { for (const k of Object.keys(s)) delete s[k]; },
    "the save's usage fails": (t, s, o) => { o.fail = (r) => r.op === "usage"; },
    "generations saved, no current": (t, s) => { delete s[`${t.root.slice(1)}/current`]; },
    "current not a generation's name (a bare number)": (t, s) => { s[`${t.root.slice(1)}/current`] = "1\n"; },
    "current not canonical": (t, s) => { s[`${t.root.slice(1)}/current`] = "gen-01\n"; },
    "current without its newline": (t, s) => { s[`${t.root.slice(1)}/current`] = "gen-1"; },
    "current naming a generation the live tree no longer holds": (t) => { rmSync(join(t.root, "gen-1"), { recursive: true }); writeGen(join(t.root, "gen-3"), GEN1); writeFileSync(join(t.root, "current"), "gen-3\n"); },
    "a saved file missing (a count mismatch)": (t, s) => { delete s[`${t.root.slice(1)}/gen-1/instructions.md`]; },
    "an extra saved file (a count mismatch)": (t, s) => { s[`${t.root.slice(1)}/gen-1/extra`] = "x"; },
    "a saved file that differs": (t, s) => { s[`${t.root.slice(1)}/gen-1/instructions.md`] = "be unkind\n"; },
    "a file's dump fails": (t, s, o) => { o.fail = (r) => r.op === "dump" && r.path.endsWith("SKILL.md"); },
    "the live tree unreadable (a link in it)": (t) => { symlinkSync("/etc/hostname", join(t.root, "gen-1", "link")); },
    "the live tree unreadable (another mode)": (t) => { chmodSync(join(t.root, "gen-1", "manifest.json"), 0o644); },
  };
  for (const [what, spoil] of Object.entries(cases)) {
    const t = live({ 1: GEN1 }, 1);
    const saved = save(t.root);
    const o = {};
    spoil(t, saved, o);
    let got;
    try { got = await proveConfig(ID, SNAP, { binary: store(saved, o), root: t.root, uid: UID }); } catch (e) { got = e.code; }
    assert.equal(got, "config_unbound", what);
  }
});

test("A1: a lost lock inside the proof's binary calls is the run's loss (lock_lost), never mapped to config_unbound", async () => {
  const t = live({ 1: GEN1 }, 1);
  const saved = save(t.root);
  const b = store(saved);
  let n = 0;
  const lossy = async (req, o) => { if (++n === 2) throw Object.assign(new Error("lost"), { code: "lock_lost" }); return b(req, o); };
  await assert.rejects(proveConfig(ID, SNAP, { binary: lossy, root: t.root, uid: UID }), (e) => e.code === "lock_lost");
  assert.equal(existsSync(t.root), true);
});
