// Host backup r3.3 §5, validation before resume: the one listing format both sides give (launcher contract A2 r3.6
// §4b), the tree compare (less exactly the unrestorable entries; every difference counted), and PRAGMA quick_check on
// the private copy of a sessions database.
import assert from "node:assert/strict";
import { test } from "node:test";
import { copyFileSync, existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { FleetError } from "../lib/fleet/index.mjs";
import * as mod from "../lib/fleet/host/restore-validate.mjs";
const { checkCopies, compareTrees, copyKey, encodePath, parseListing, quickCheck, rawPath, sha256File, sqliteCopies } = mod;

const refused = (fn, code) => assert.throws(fn, (e) => e instanceof FleetError && e.code === code, code);
const H = (s) => createHash("sha256").update(s).digest("hex");
const file = (path, body, mode = 0o640) => ({ path, type: "file", size: Buffer.byteLength(body), mode, sha256: H(body) });
const dir = (path, mode = 0o750) => ({ path, type: "dir", size: 0, mode });
const link = (path, target) => ({ path, type: "symlink", size: Buffer.byteLength(target), mode: 0o777, target });
/** A listing's exact text: the header, the entry lines as given, the trailer (count and total from the entries). */
const text = (lines, { count, total } = {}) => {
  const entries = lines.filter((l) => typeof l === "object" && !Object.hasOwn(l, "unexpected"));
  const c = count ?? entries.length, b = total ?? entries.filter((e) => e.type === "file").reduce((n, e) => n + e.size, 0);
  return ['{"v":1}', ...lines.map((l) => (typeof l === "string" ? l : JSON.stringify(l))), JSON.stringify({ count: c, total_bytes: b })].join("\n") + "\n";
};
const tree = () => [dir("a"), file("a/x", "hello"), link("a/y", "x"), file("b", "world")];

test("the listing: the header, canonical sorted entries each once, the exact trailer; the class root is no entry", () => {
  const { entries, unexpected } = parseListing(text(tree()));
  assert.deepEqual([...entries.keys()], ["a", "a/x", "a/y", "b"]);
  assert.deepEqual(unexpected, []);
  assert.equal(parseListing(text([])).entries.size, 0, "an empty class");
  const bad = (t, o) => refused(() => parseListing(t, o), "bad_form");
  bad(null); bad(""); bad('{"v":1}\n'); bad(text(tree()).slice(0, -1)); // no final newline
  bad(text(tree()).replace('{"v":1}', '{"v":2}')); bad(text(tree()).replace('{"v":1}\n', ""));
  bad(text(tree()) + "\n"); // a blank line
  bad(text([file("b", "1"), file("a", "2")])); // unsorted
  bad(text([file("a", "1"), file("a", "2")])); // a path twice
  bad(text([dir(""), file("a", "1")])); // the root as an entry
  bad(text(tree(), { count: 3 })); bad(text(tree(), { total: 11 })); // the trailer's count, its total
  bad(text(tree()).replace(/\{"count":4,"total_bytes":10\}\n$/, '{"total_bytes":10,"count":4}\n')); // trailer key order
  bad(text(tree()).replace(/\{"count":4,"total_bytes":10\}\n$/, '{"count":4,"total_bytes":10,"x":1}\n'));
  // entries: key order, extra or missing keys, kinds, set-id bits, sizes, paths
  bad(text([`{"type":"file","path":"a","size":1,"mode":416,"sha256":"${H("1")}"}`]));
  bad(text([{ ...file("a", "1"), extra: 1 }]));
  bad(text([{ path: "a", type: "file", size: 1, mode: 0o640 }]));
  bad(text([{ ...file("a", "1"), sha256: "AB".repeat(32) }]));
  bad(text([{ ...dir("a"), size: 4096 }])); // a directory's size is 0
  bad(text([{ path: "a", type: "fifo", size: 0, mode: 0o640 }]));
  bad(text([file("a", "1", 0o4755)])); bad(text([file("a", "1", 0o2755)])); // the EXPECTED list never keeps set-id bits
  // the OBSERVED listing reports the actual mode, set-id included, so a fill that didn't strip it is a changed entry
  for (const m of [0o4755, 0o2755]) assert.equal(parseListing(text([file("a", "1", m)]), { observed: true }).entries.get("a").mode, m);
  assert.equal(parseListing(text([dir("d", 0o2775)]), { observed: true }).entries.get("d").mode, 0o2775);
  bad(text([{ ...link("a", "x"), size: 2 }])); bad(text([{ ...link("a", "x"), mode: 0o755 }]));
  bad(text(["not json"]));
  for (const p of ["/a", "a/", "a//b", "./a", "a/../b", "a\u0000b"]) bad(text([file(p, "1")]));
  // unexpected lines: tree-digest's only, closed, sorted with the entries, not counted
  const t = text([dir("a"), { unexpected: "a/p", type: "fifo" }, file("b", "1")]);
  bad(t);
  assert.deepEqual(parseListing(t, { observed: true }).unexpected, [{ path: "a/p", type: "fifo" }]);
  bad(text([{ unexpected: "a", type: "door" }]), { observed: true });
  bad(text([{ type: "fifo", unexpected: "a" }]), { observed: true });
  bad(text([file("b", "1"), { unexpected: "a", type: "fifo" }]), { observed: true }); // unsorted with the entries
  // bounds
  refused(() => parseListing(text(tree()), { maxEntries: 3 }), "limit");
  refused(() => parseListing(text(tree()), { maxBytes: 100 }), "limit");
  assert.equal(parseListing(text(tree()), { maxEntries: 4 }).entries.size, 4);
});

test("the compare: equal trees are ok; every missing, extra and changed path is counted and listed in path order", () => {
  const want = parseListing(text(tree())).entries;
  assert.deepEqual(compareTrees(want, new Map(want)), { ok: true, missing: { count: 0, paths: [] }, extra: { count: 0, paths: [] }, changed: { count: 0, paths: [] } });
  const got = new Map(want);
  got.delete("b"); got.delete("a/x");
  got.set("c", file("c", "new"));
  got.set("a", { ...dir("a"), mode: 0o700 });
  const r = compareTrees(want, got);
  assert.equal(r.ok, false);
  assert.deepEqual(r.missing, { count: 2, paths: ["a/x", "b"] });
  assert.deepEqual(r.extra, { count: 1, paths: ["c"] });
  assert.deepEqual(r.changed, { count: 1, paths: ["a"] });
  // each field of each kind, a same-size byte change included
  for (const [p, e] of [
    ["a/x", file("a/x", "hellp")], ["a/x", { ...file("a/x", "hello"), size: 6 }], ["a/x", file("a/x", "hello", 0o600)],
    ["a/y", link("a/y", "z")], ["a/y", file("a/y", "x")], ["a", file("a", "")], ["b", dir("b")],
  ]) {
    const g = new Map(want); g.set(p, e);
    assert.deepEqual(compareTrees(want, g).changed, { count: 1, paths: [p] }, `${p}: ${JSON.stringify(e)}`);
  }
  const many = new Map(want); for (let i = 0; i < 30; i++) many.set(`z${String(i).padStart(2, "0")}`, file(`z${i}`, "q"));
  const rm = compareTrees(want, many, [], { listMax: 20 });
  assert.equal(rm.extra.count, 30); assert.equal(rm.extra.paths.length, 20);
  refused(() => compareTrees([], want), "bad_form");
});

test("unrestorable entries: exactly those are left out, one that is present anyway is extra, one the snapshot doesn't hold is refused", () => {
  const want = parseListing(text(tree())).entries;
  const got = new Map(want); got.delete("b");
  assert.equal(compareTrees(want, got, ["b"]).ok, true);
  assert.deepEqual(compareTrees(want, new Map(want), ["b"]).extra, { count: 1, paths: ["b"] });
  assert.deepEqual(compareTrees(want, got, []).missing, { count: 1, paths: ["b"] });
  const got2 = new Map(got); got2.delete("a/x");
  assert.deepEqual(compareTrees(want, got2, ["b"]).missing, { count: 1, paths: ["a/x"] }, "an omission beyond the declared ones fails");
  refused(() => compareTrees(want, got, ["nope"]), "bad_form");
});

test("quick_check on a private copy: a sound database is ok, a WAL is replayed and a hot journal recovered in the copy; corrupt ones fail", async (t) => {
  let sqlite;
  try { sqlite = await import("node:sqlite"); } catch { return t.skip("node:sqlite is unavailable"); }
  const dir = mkdtempSync(join(tmpdir(), "sb-qc-"));
  const make = (path, journal) => {
    const db = new sqlite.DatabaseSync(path);
    db.exec(`PRAGMA journal_mode=${journal}; CREATE TABLE t (k INTEGER PRIMARY KEY, v TEXT); CREATE INDEX tv ON t (v);`);
    const ins = db.prepare("INSERT INTO t (v) VALUES (?)");
    for (let i = 0; i < 2000; i++) ins.run(`row ${i} ${"x".repeat(50)}`);
    return db;
  };
  const good = join(dir, "good.db");
  make(good, "DELETE").close();
  assert.deepEqual(await quickCheck(good), { ok: true, result: "ok" });
  // a WAL database copied mid-life: the main file alone is stale, the WAL beside it holds the rows
  const wal = join(dir, "wal.db"), db = make(wal, "WAL");
  db.exec("PRAGMA wal_autocheckpoint=0;");
  const ins = db.prepare("INSERT INTO t (v) VALUES (?)");
  for (let i = 0; i < 500; i++) ins.run(`late ${i}`);
  const copyDir = mkdtempSync(join(tmpdir(), "sb-qc-copy-"));
  copyFileSync(wal, join(copyDir, "db")); copyFileSync(wal + "-wal", join(copyDir, "db-wal"));
  db.close();
  assert.deepEqual(await quickCheck(join(copyDir, "db")), { ok: true, result: "ok" });
  const check = new sqlite.DatabaseSync(join(copyDir, "db"));
  assert.equal(check.prepare("SELECT count(*) AS n FROM t").get().n, 2500, "the copy's WAL was replayed, not ignored");
  check.close();
  // corrupt: a page of the index overwritten; truncated; not a database
  const before = readFileSync(good), bytes = Buffer.from(before);
  for (let i = bytes.length - 8192; i < bytes.length - 4096; i++) bytes[i] = 0x5a;
  const corrupt = join(dir, "corrupt.db"); writeFileSync(corrupt, bytes);
  const trunc = join(dir, "trunc.db"); writeFileSync(trunc, before.subarray(0, 4096 * 3 + 100));
  const textDb = join(dir, "text.db"); writeFileSync(textDb, "not a database at all, just text\n".repeat(200));
  for (const p of [corrupt, trunc, textDb]) assert.equal((await quickCheck(p)).ok, false, p);
  assert.ok(!existsSync(join(dir, "missing.db")));
  assert.equal((await quickCheck(join(dir, "missing.db"))).ok, false, "a copy that isn't there fails, it isn't created ok");
  assert.ok(!existsSync(join(dir, "missing.db")), "and nothing is created there");
  writeFileSync(join(dir, "empty.db"), "");
  assert.equal((await quickCheck(join(dir, "empty.db"))).ok, false, "an empty file isn't a database that passes");
  assert.equal((await quickCheck(dir)).ok, false, "a directory isn't a copy");
});

test("sha256File: the file's bytes", () => {
  const d = mkdtempSync(join(tmpdir(), "sb-sha-"));
  writeFileSync(join(d, "f"), "hello");
  assert.equal(sha256File(join(d, "f")), H("hello"));
});

test("the path codec: valid UTF-8 as itself but % as %25, every other byte %XX upper-case; only the codec's own text is a path", () => {
  const cases = [["a", "61"], ["a%25b", "612562"], ["a%FFb", "61ff62"], ["\u00e9", "c3a9"], ["x%C3", "78c3"], ["%E2%82", "e282"], ["\u{1F600}", "f09f9880"]];
  for (const [t, hex] of cases) {
    assert.equal(rawPath(t)?.toString("hex"), hex, t);
    assert.equal(encodePath(Buffer.from(hex, "hex")), t, hex);
  }
  for (const t of ["a%", "a%2", "a%ff", "%41", "%2F", "a%C3%A9", "%25%", "\ud800"]) assert.equal(rawPath(t), null, t);
  for (const hex of ["c080", "eda080", "f4908080", "ff", "25", "2f", "e282ac", "c3"]) assert.equal(rawPath(encodePath(Buffer.from(hex, "hex"))).toString("hex"), hex);
  const bad = (p) => refused(() => parseListing(text([file(p, "1")])), "bad_form");
  bad("%41"); bad("a%ff"); bad("%2F"); bad("a" + "%FF".repeat(4096)); bad("%00");
  assert.equal(parseListing(text([file("a%FFb", "1")])).entries.size, 1);
  assert.equal(parseListing(text([file("x".repeat(4096), "1")])).entries.size, 1);
});

test("SQLite copies: the name follows the main's raw path; every present sidecar of a copied main carries its copy", () => {
  const h = copyKey("s/db");
  assert.equal(h, createHash("sha256").update("s/db").digest("hex").slice(0, 32));
  const main = { ...file("s/db", "M"), copy: `${h}.db` }, wal = { ...file("s/db-wal", "W"), copy: `${h}.db-wal` }, jour = { ...file("s/db-journal", "J"), copy: `${h}.db-journal` };
  const obs = (...es) => parseListing(text([dir("s"), ...es]), { observed: true }).entries;
  assert.deepEqual(sqliteCopies(obs(main, wal)), [{ path: "s/db", copy: `${h}.db`, sidecars: [{ path: "s/db-wal", copy: `${h}.db-wal` }] }]);
  assert.equal(sqliteCopies(obs(main)).length, 1, "an absent sidecar is fine");
  assert.equal(sqliteCopies(obs(main, jour, wal)).length, 1);
  const bad = (...es) => refused(() => sqliteCopies(obs(...es)), "bad_form");
  bad(main, file("s/db-wal", "W"));
  bad(main, file("s/db-journal", "J"));
  bad({ ...main, copy: `${copyKey("s/x")}.db` });
  bad(wal);
  bad(main, { ...file("s/db-wal", "W"), copy: `${copyKey("s/x")}.db-wal` });
  bad(main, { ...file("s/other", "W"), copy: `${h}.db-wal` });
  assert.deepEqual(sqliteCopies(obs(file("s/y-wal", "W"))), []);
  refused(() => parseListing(text([main])), "bad_form");
  refused(() => parseListing(text([{ ...main, copy: "x.db" }]), { observed: true }), "bad_form");
  refused(() => parseListing(text([`{"path":"s/db","type":"file","size":1,"mode":416,"copy":"${h}.db","sha256":"${H("M")}"}`]), { observed: true }), "bad_form");
});

test("checking the copies: each copy's hash is its entry's first; then quick_check on the main, with its WAL beside it", async (t) => {
  let sqlite;
  try { sqlite = await import("node:sqlite"); } catch { return t.skip("node:sqlite is unavailable"); }
  const src = mkdtempSync(join(tmpdir(), "sb-cc-src-")), priv = mkdtempSync(join(tmpdir(), "sb-cc-priv-"));
  const db = new sqlite.DatabaseSync(join(src, "db"));
  db.exec("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; CREATE TABLE t (v TEXT);");
  for (let i = 0; i < 300; i++) db.prepare("INSERT INTO t VALUES (?)").run(`r${i}`);
  const h = copyKey("db");
  // (the restored files, as the walk read them: one set of private copies per check, since SQLite may change a copy)
  const mainBytes = readFileSync(join(src, "db")), walBytes = readFileSync(join(src, "db-wal"));
  db.close();
  const copies = (wal = walBytes) => {
    const d = mkdtempSync(join(tmpdir(), "sb-cc-priv-"));
    writeFileSync(join(d, `${h}.db`), mainBytes); writeFileSync(join(d, `${h}.db-wal`), wal);
    return d;
  };
  const entry = (name, b, copy) => ({ path: name, type: "file", size: b.length, mode: 0o600, sha256: H(b), copy });
  const obs = parseListing(text([entry("db", mainBytes, `${h}.db`), entry("db-wal", walBytes, `${h}.db-wal`)]), { observed: true }).entries;
  assert.deepEqual(await checkCopies(obs, copies()), { ok: true, failed: [] });
  const w = Buffer.from(walBytes); w[100] ^= 1;
  assert.deepEqual(await checkCopies(obs, copies(w)), { ok: false, failed: ["db"] }, "a copy whose bytes aren't its entry's fails before SQLite reads it");
  const priv2 = mkdtempSync(join(tmpdir(), "sb-cc-priv2-"));
  assert.deepEqual(await checkCopies(obs, priv2), { ok: false, failed: ["db"] });
});


test("the one quoting: only \" and \\ escaped, every control character as \\u00xx; a symlink's target in the codec, its size the raw length", () => {
  const { quote } = mod;
  assert.equal(quote('a\nb"\\\u001f\u007fé'), '"a\\u000ab\\"\\\\\\u001f\u007fé"');
  // a name with a newline: the \u000a spelling is the canonical one, the \n short form is refused
  const nl = `{"path":"a\\u000ab","type":"file","size":1,"mode":416,"sha256":"${H("1")}"}`;
  const one = { count: 1, total: 1 };
  assert.equal(parseListing(text([nl], one)).entries.has("a\nb"), true);
  refused(() => parseListing(text([nl.replace("\\u000a", "\\n")], one)), "bad_form");
  refused(() => parseListing(text([nl.replace("\\u000a", "\\u000A")], one)), "bad_form");
  // a symlink whose target isn't UTF-8: the codec's text, its size the raw bytes'
  const t = `{"path":"l","type":"symlink","size":3,"mode":511,"target":"x%FFy"}`;
  const ln = { count: 1, total: 0 };
  assert.equal(parseListing(text([t], ln)).entries.get("l").target, "x%FFy");
  refused(() => parseListing(text([t.replace('"size":3', '"size":5')], ln)), "bad_form"); // the encoded length isn't the size
  refused(() => parseListing(text([t.replace("x%FFy", "x%ffy")], ln)), "bad_form"); // not the codec's text
  assert.equal(parseListing(text([link("l2", "../a/b")])).entries.size, 1, "a target may hold .. and /");
});

test("the shared listing corpus (test/fixtures/listing-corpus.json): each valid line parses to exactly its row; the others are refused", () => {
  const { rows } = JSON.parse(readFileSync(new URL("./fixtures/listing-corpus.json", import.meta.url), "utf8"));
  assert.ok(rows.length >= 16);
  let valid = 0;
  for (const r of rows) {
    const t = `{"v":1}\n${r.line}\n{"count":1,"total_bytes":${r.type === "file" ? r.size : 0}}\n`;
    if (!r.valid) { refused(() => parseListing(t), "bad_form"); continue; }
    const { entries } = parseListing(t);
    assert.equal(entries.size, 1, r.name);
    const [[path, e]] = [...entries];
    assert.equal(rawPath(path).toString("hex"), r.raw_path_hex, `${r.name}: the path's raw bytes`);
    assert.deepEqual([e.type, e.size, e.mode], [r.type, r.size, r.mode], r.name);
    if (r.type === "file") assert.equal(e.sha256, r.sha256, r.name);
    if (r.type === "symlink") assert.equal(rawPath(e.target).toString("hex"), r.raw_target_hex, `${r.name}: the target's raw bytes`);
    // JSON.stringify's spelling of the same entry is canonical only where it agrees byte for byte with the pinned quoting
    const js = JSON.stringify(JSON.parse(r.line));
    if (js !== r.line) refused(() => parseListing(`{"v":1}\n${js}\n{"count":1,"total_bytes":${r.type === "file" ? r.size : 0}}\n`), "bad_form");
    valid++;
  }
  assert.equal(valid, rows.filter((r) => r.valid).length);
});
