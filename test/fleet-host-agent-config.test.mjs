// An agent's config tree (amendment L1; restore e2e delta R4-d2b §3–§4): the reader's closed layout and exact modes at
// every depth, the generation hash, EMPTY_CONFIG_HASH and the invariant (no current exactly when no generation, the
// import's own read excepted), and the import entry's writes (importGeneration, setCurrent with .current.tmp), with
// their crash points and substitutes. Real temporary trees, owned by the test's uid in place of root.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import * as fs from "node:fs";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, renameSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "./host-linux-only.mjs";
import { FleetError } from "../lib/fleet/index.mjs";
import {
  CURRENT_TMP, EMPTY_CONFIG_HASH, MAX_FILES, MAX_GENERATIONS, configHash, devOf, generationHash, importGeneration, readConfigTree, readGenerationDir, setCurrent,
} from "../lib/fleet/host/agent-config.mjs";

const UID = typeof process.getuid === "function" ? process.getuid() : -1;
const refused = (fn, code) => assert.throws(fn, (e) => e instanceof FleetError && e.code === code, code);
const O = { uid: UID };

/** A fresh tree root, 0700. */
function tree() {
  const base = mkdtempSync(join(tmpdir(), "sb-cfg-"));
  chmodSync(base, 0o700);
  const root = join(base, "agent-config");
  mkdirSync(root, { mode: 0o700 });
  chmodSync(root, 0o700);
  return { base, root };
}
/** Write a generation directory `dir` from { path: content | null (a directory) }, every mode exact. */
function writeGen(dir, files) {
  mkdirSync(dir, { mode: 0o700 }); chmodSync(dir, 0o700);
  for (const [p, c] of Object.entries(files).sort()) {
    const full = join(dir, p);
    if (c === null) { mkdirSync(full, { mode: 0o700 }); chmodSync(full, 0o700); } else { writeFileSync(full, c, { mode: 0o600 }); chmodSync(full, 0o600); }
  }
}
const GEN = { "manifest.json": '{"v":1}\n', "instructions.md": "be kind\n", skills: null, "skills/a": null, "skills/a/SKILL.md": "x" };
const sha = (s) => createHash("sha256").update(s).digest("hex");

test("an empty tree: no current, no generation, EMPTY_CONFIG_HASH (the hash of no entry)", () => {
  const t = tree();
  const r = readConfigTree(t.root, O);
  assert.deepEqual(r, { current: null, generations: {}, leftovers: { gen: null, current: false } });
  assert.equal(configHash(r), EMPTY_CONFIG_HASH);
  assert.equal(EMPTY_CONFIG_HASH, sha('{"v":1,"entries":[]}\n'));
});

test("a configured tree: the listing in byte order of path, the hash stable and changed by any byte or path", () => {
  const t = tree();
  writeGen(join(t.root, "gen-1"), GEN);
  writeFileSync(join(t.root, "current"), "gen-1\n", { mode: 0o600 }); chmodSync(join(t.root, "current"), 0o600);
  const r = readConfigTree(t.root, O);
  assert.equal(r.current, "1");
  assert.deepEqual(r.generations["1"].entries.map((e) => e.path), ["instructions.md", "manifest.json", "skills", "skills/a", "skills/a/SKILL.md"]);
  assert.deepEqual(r.generations["1"].entries[2], { path: "skills", type: "dir", mode: 0o700, size: 0 });
  assert.deepEqual(r.generations["1"].entries[0], { path: "instructions.md", type: "file", mode: 0o600, size: 8, sha256: sha("be kind\n") });
  assert.equal(configHash(r), generationHash(r.generations["1"].entries));
  // The same content elsewhere hashes the same; one byte or one name changes it.
  const u = tree();
  writeGen(join(u.root, "gen-7"), GEN);
  writeFileSync(join(u.root, "current"), "gen-7\n", { mode: 0o600 }); chmodSync(join(u.root, "current"), 0o600);
  assert.equal(configHash(readConfigTree(u.root, O)), configHash(r));
  for (const change of [{ ...GEN, "instructions.md": "be kind!\n" }, { ...GEN, "instructions.md": undefined, "Instructions.md": "be kind\n" }]) {
    const v = tree();
    writeGen(join(v.root, "gen-1"), Object.fromEntries(Object.entries(change).filter(([, c]) => c !== undefined)));
    writeFileSync(join(v.root, "current"), "gen-1\n", { mode: 0o600 }); chmodSync(join(v.root, "current"), 0o600);
    assert.notEqual(configHash(readConfigTree(v.root, O)), configHash(r));
  }
});

test("the invariant: generations with no current refuse for every reader but the import's own; a current naming a missing generation refuses everywhere", () => {
  const t = tree();
  writeGen(join(t.root, "gen-1"), GEN);
  refused(() => readConfigTree(t.root, O), "not_granted");
  const r = readConfigTree(t.root, { ...O, importing: true });
  assert.deepEqual([r.current, Object.keys(r.generations)], [null, ["1"]]);
  writeFileSync(join(t.root, "current"), "gen-2\n", { mode: 0o600 }); chmodSync(join(t.root, "current"), 0o600);
  refused(() => readConfigTree(t.root, O), "not_granted");
  refused(() => readConfigTree(t.root, { ...O, importing: true }), "not_granted");
});

test("the closed layout and exact modes, at every depth: foreign entries, links, special files, other modes and owners, bad current, two temps refuse", () => {
  const cases = {
    "a foreign entry": (r) => writeFileSync(join(r, "notes.txt"), "x", { mode: 0o600 }),
    "a link at the top": (r) => symlinkSync("/etc", join(r, "gen-2")),
    "a link nested": (r) => { writeGen(join(r, "gen-2"), GEN); symlinkSync("/etc/passwd", join(r, "gen-2", "skills", "evil")); },
    "a fifo nested": (r) => { writeGen(join(r, "gen-2"), GEN); execFileSync("mkfifo", [join(r, "gen-2", "skills", "pipe")]); },
    "a 0755 directory nested": (r) => { writeGen(join(r, "gen-2"), GEN); chmodSync(join(r, "gen-2", "skills", "a"), 0o755); },
    "a 0777 directory nested": (r) => { writeGen(join(r, "gen-2"), GEN); chmodSync(join(r, "gen-2", "skills"), 0o777); },
    "a 0644 file nested": (r) => { writeGen(join(r, "gen-2"), GEN); chmodSync(join(r, "gen-2", "skills", "a", "SKILL.md"), 0o644); },
    "a 0666 file": (r) => { writeGen(join(r, "gen-2"), GEN); chmodSync(join(r, "gen-2", "manifest.json"), 0o666); },
    "a 0700 file": (r) => { writeGen(join(r, "gen-2"), GEN); chmodSync(join(r, "gen-2", "manifest.json"), 0o700); },
    "a setuid file": (r) => { writeGen(join(r, "gen-2"), GEN); chmodSync(join(r, "gen-2", "manifest.json"), 0o4600); },
    "the tree 0755": (r) => chmodSync(r, 0o755),
    "a generation as a file": (r) => writeFileSync(join(r, "gen-2"), "x", { mode: 0o600 }),
    "a non-canonical generation": (r) => writeGen(join(r, "gen-01"), GEN),
    "current with other text": (r) => { writeFileSync(join(r, "current"), "gen-1", { mode: 0o600 }); },
    "current 0644": (r) => { writeFileSync(join(r, "current"), "gen-1\n", { mode: 0o644 }); chmodSync(join(r, "current"), 0o644); },
    "current hard-linked": (r) => { writeFileSync(join(r, "current"), "gen-1\n", { mode: 0o600 }); execFileSync("ln", [join(r, "current"), join(r, "..", "other")]); },
    "two generation temps": (r) => { mkdirSync(join(r, ".gen-2.tmp"), { mode: 0o700 }); mkdirSync(join(r, ".gen-3.tmp"), { mode: 0o700 }); },
    ".current.tmp a directory": (r) => mkdirSync(join(r, CURRENT_TMP), { mode: 0o700 }),
    ".current.tmp a 0644 file": (r) => { writeFileSync(join(r, CURRENT_TMP), "gen-1\n", { mode: 0o644 }); chmodSync(join(r, CURRENT_TMP), 0o644); },
    "another dotted temp": (r) => writeFileSync(join(r, ".current.tmp2"), "x", { mode: 0o600 }),
  };
  for (const [what, make] of Object.entries(cases)) {
    const t = tree();
    writeGen(join(t.root, "gen-1"), GEN);
    writeFileSync(join(t.root, "current"), "gen-1\n", { mode: 0o600 }); chmodSync(join(t.root, "current"), 0o600);
    make(t.root);
    assert.throws(() => readConfigTree(t.root, O), (e) => e instanceof FleetError && e.code === "not_granted", what);
  }
  // Another owner than the one required: refused (the test stands in uid+1 for "not root").
  const t = tree();
  assert.throws(() => readConfigTree(t.root, { uid: UID + 1 }), (e) => e.code === "not_granted");
  // The tree is a link: refused; missing: not_found.
  const l = tree();
  symlinkSync(l.root, join(l.base, "link"));
  refused(() => readConfigTree(join(l.base, "link"), O), "not_granted");
  refused(() => readConfigTree(join(l.base, "missing"), O), "not_found");
});

test("bounds: at most 16 generations and 4096 files a generation, each at the bound and one over", () => {
  const t = tree();
  for (let i = 1; i <= MAX_GENERATIONS; i++) writeGen(join(t.root, `gen-${i}`), { "manifest.json": `${i}` });
  writeFileSync(join(t.root, "current"), "gen-1\n", { mode: 0o600 }); chmodSync(join(t.root, "current"), 0o600);
  assert.equal(Object.keys(readConfigTree(t.root, O).generations).length, MAX_GENERATIONS);
  writeGen(join(t.root, `gen-${MAX_GENERATIONS + 1}`), { "manifest.json": "x" });
  refused(() => readConfigTree(t.root, O), "not_granted");
  const u = tree();
  const files = {};
  for (let i = 0; i < MAX_FILES; i++) files[`f${i}`] = "";
  writeGen(join(u.root, "gen-1"), files);
  writeFileSync(join(u.root, "current"), "gen-1\n", { mode: 0o600 }); chmodSync(join(u.root, "current"), 0o600);
  assert.equal(readConfigTree(u.root, O).generations["1"].entries.length, MAX_FILES);
  writeFileSync(join(u.root, "gen-1", "one-more"), "", { mode: 0o600 }); chmodSync(join(u.root, "gen-1", "one-more"), 0o600);
  refused(() => readConfigTree(u.root, O), "not_granted");
});

test("the recorded identity: the tree's handle must be that object (device and inode)", () => {
  const t = tree();
  const st = statSync(t.root);
  // (the launcher's [major, minor] for this device: inverted from the userspace dev_t)
  const major = Number((BigInt(st.dev) >> 8n) & 0xfffn) | Number((BigInt(st.dev) >> 32n) & ~0xfffn);
  const minor = Number(BigInt(st.dev) & 0xffn) | Number((BigInt(st.dev) >> 12n) & ~0xffn);
  assert.equal(devOf([major, minor]), st.dev);
  readConfigTree(t.root, { ...O, identity: { dev: [major, minor], ino: st.ino } });
  refused(() => readConfigTree(t.root, { ...O, identity: { dev: [major, minor], ino: st.ino + 1 } }), "not_granted");
  refused(() => readConfigTree(t.root, { ...O, identity: { dev: [major + 1, minor], ino: st.ino } }), "not_granted");
});

/** A staged config tree (the snapshot's), with generation `n` from GEN. */
function staged(n = "1", files = GEN) {
  const s = tree();
  writeGen(join(s.root, `gen-${n}`), files);
  return s;
}

test("importGeneration: exactly the staged generation, through a temp, then renamed; kept if equal, refused if other; read back", () => {
  const s = staged("3");
  const want = readGenerationDir(join(s.root, "gen-3"), O);
  const t = tree();
  assert.equal(importGeneration(t.root, "3", join(s.root, "gen-3"), O), want.hash);
  const r = readConfigTree(t.root, { ...O, importing: true });
  assert.equal(r.generations["3"].hash, want.hash);
  assert.deepEqual(readdirSync(t.root), ["gen-3"]);
  assert.equal(statSync(join(t.root, "gen-3", "skills", "a", "SKILL.md")).mode & 0o7777, 0o600);
  // Again: kept.
  assert.equal(importGeneration(t.root, "3", join(s.root, "gen-3"), O), want.hash);
  // Another content under the same number: refused, nothing changed.
  const o = staged("3", { ...GEN, "instructions.md": "other\n" });
  refused(() => importGeneration(t.root, "3", join(o.root, "gen-3"), O), "not_granted");
  assert.equal(readConfigTree(t.root, { ...O, importing: true }).generations["3"].hash, want.hash);
  // A bad number, or a staged generation that breaks the rules: refused before any write.
  refused(() => importGeneration(t.root, "03", join(s.root, "gen-3"), O), "bad_form");
  const bad = staged("4");
  chmodSync(join(bad.root, "gen-4", "manifest.json"), 0o644);
  refused(() => importGeneration(t.root, "4", join(bad.root, "gen-4"), O), "not_granted");
  assert.ok(!existsSync(join(t.root, ".gen-4.tmp")) && !existsSync(join(t.root, "gen-4")));
});

test("importGeneration's crash points (the temp made, written, renamed): a re-run reaches the same tree; a leftover temp is removed first", () => {
  const s = staged("2");
  const want = readGenerationDir(join(s.root, "gen-2"), O).hash;
  for (const point of ["tmp-made", "tmp-written", "renamed"]) {
    const t = tree();
    assert.throws(() => importGeneration(t.root, "2", join(s.root, "gen-2"), { ...O, onStep: (x) => { if (x === point) throw new Error("crash"); } }), /crash/);
    assert.equal(importGeneration(t.root, "2", join(s.root, "gen-2"), O), want, point);
    const r = readConfigTree(t.root, { ...O, importing: true });
    assert.deepEqual([Object.keys(r.generations), r.generations["2"].hash, r.leftovers.gen], [["2"], want, null], point);
  }
});

test("setCurrent: .current.tmp created exclusively, fsynced, renamed over current; a leftover file or link removed first (never followed); a directory there refuses", () => {
  const t = tree();
  writeGen(join(t.root, "gen-1"), GEN);
  refused(() => setCurrent(t.root, "2", O), "not_found");
  setCurrent(t.root, "1", O);
  assert.equal(readFileSync(join(t.root, "current"), "utf8"), "gen-1\n");
  assert.equal(statSync(join(t.root, "current")).mode & 0o7777, 0o600);
  assert.equal(readConfigTree(t.root, O).current, "1");
  // A leftover temp file: reported by the reader, never read as current; removed by the next setCurrent.
  writeFileSync(join(t.root, CURRENT_TMP), "gen-9\n", { mode: 0o600 }); chmodSync(join(t.root, CURRENT_TMP), 0o600);
  const r = readConfigTree(t.root, O);
  assert.deepEqual([r.current, r.leftovers.current], ["1", true]);
  setCurrent(t.root, "1", O);
  assert.ok(!existsSync(join(t.root, CURRENT_TMP)));
  // A link there: reported as a leftover (never followed), then the link itself unlinked, its target untouched.
  const target = join(t.base, "target");
  writeFileSync(target, "keep");
  symlinkSync(target, join(t.root, CURRENT_TMP));
  assert.deepEqual([readConfigTree(t.root, O).current, readConfigTree(t.root, O).leftovers.current], ["1", true]);
  setCurrent(t.root, "1", O);
  assert.ok(!existsSync(join(t.root, CURRENT_TMP)));
  assert.equal(readFileSync(target, "utf8"), "keep");
  // A directory there: refused, nothing removed.
  mkdirSync(join(t.root, CURRENT_TMP), { mode: 0o700 });
  writeFileSync(join(t.root, CURRENT_TMP, "x"), "x");
  refused(() => setCurrent(t.root, "1", { ...O, importing: true }), "not_granted");
  assert.ok(existsSync(join(t.root, CURRENT_TMP, "x")));
});

test("setCurrent's crash points (after the write, after its fsync, after the rename): a re-run reaches the same current", () => {
  for (const point of ["tmp-written", "tmp-synced", "renamed"]) {
    const t = tree();
    writeGen(join(t.root, "gen-1"), GEN);
    writeGen(join(t.root, "gen-2"), { ...GEN, "instructions.md": "two\n" });
    writeFileSync(join(t.root, "current"), "gen-1\n", { mode: 0o600 }); chmodSync(join(t.root, "current"), 0o600);
    assert.throws(() => setCurrent(t.root, "2", { ...O, onStep: (x) => { if (x === point) throw new Error("crash"); } }), /crash/);
    // Before the re-run, the tree is valid: current names an existing generation (the old or the new one).
    assert.ok(["1", "2"].includes(readConfigTree(t.root, O).current), point);
    setCurrent(t.root, "2", O);
    const r = readConfigTree(t.root, O);
    assert.deepEqual([r.current, r.leftovers.current], ["2", false], point);
  }
});

test("a substitute root never takes a write: swapped before the open, the recorded identity refuses with nothing written; swapped after it, every write goes through the one handle to the recorded tree", () => {
  const idOf = (p) => {
    const st = statSync(p);
    const major = Number((BigInt(st.dev) >> 8n) & 0xfffn) | Number((BigInt(st.dev) >> 32n) & ~0xfffn);
    const minor = Number(BigInt(st.dev) & 0xffn) | Number((BigInt(st.dev) >> 12n) & ~0xffn);
    return { dev: [major, minor], ino: st.ino };
  };
  for (const writer of ["generation", "current"]) {
    for (const when of ["before-open", "after-open"]) {
      const t = tree();
      const src = join(t.base, "src");
      mkdirSync(src, { mode: 0o700 }); chmodSync(src, 0o700);
      writeGen(join(src, "gen-1"), GEN);
      const other = join(t.base, "other");
      mkdirSync(other, { mode: 0o700 }); chmodSync(other, 0o700);
      if (writer === "current") { writeGen(join(t.root, "gen-1"), GEN); writeGen(join(other, "gen-1"), GEN); }
      const identity = idOf(t.root);
      const moved = join(t.base, "original");
      let swapped = false;
      const swap = () => { if (!swapped) { swapped = true; renameSync(t.root, moved); renameSync(other, t.root); } };
      const fsx = when === "before-open"
        // (between the root's lstat and its open: the handle is the substitute's)
        ? { ...fs, openSync: (p, ...a) => { if (p === t.root) swap(); return fs.openSync(p, ...a); } }
        // (just after the root is opened: the handle is the recorded tree's, the path now the substitute's)
        : { ...fs, openSync: (p, ...a) => { const fd = fs.openSync(p, ...a); if (p === t.root) swap(); return fd; } };
      let err = null;
      try {
        if (writer === "generation") importGeneration(t.root, "1", join(src, "gen-1"), { ...O, identity, fsx });
        else setCurrent(t.root, "1", { ...O, identity, fsx });
      } catch (e) { err = e; }
      const label = `${writer} ${when}`;
      assert.ok(swapped, `${label}: the swap happened`);
      const sub = readdirSync(t.root).sort(), orig = readdirSync(moved).sort();
      if (when === "before-open") {
        assert.ok(err instanceof FleetError && err.code === "not_granted", `${label}: refused`);
        assert.deepEqual([sub, orig], writer === "generation" ? [[], []] : [["gen-1"], ["gen-1"]], `${label}: nothing written anywhere`);
      } else {
        assert.equal(err, null, `${label}: the recorded tree written`);
        assert.deepEqual(sub, writer === "generation" ? [] : ["gen-1"], `${label}: the substitute untouched`);
        assert.deepEqual(orig, writer === "generation" ? ["gen-1"] : ["current", "gen-1"], `${label}: written through the handle`);
      }
    }
  }
});
