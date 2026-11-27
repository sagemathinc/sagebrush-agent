// Host restore e2e r1.7 delta d2: the restore worker's input file. Built from a registry and the recorded identities;
// the closed shape checked whole (each cap at the cap and one over, every missing, extra or repeated key, members equal
// to the owners' uids); written durably and 0600 in a proven private directory; read back by a no-follow read; removed
// name by name, a link removed itself.
import assert from "node:assert/strict";
import { chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "./host-linux-only.mjs";
import { FleetError, newId } from "../lib/fleet/index.mjs";
import { newRestoreRun } from "../lib/fleet/host/restore-record.mjs";
import { realIo } from "../lib/fleet/host/store.mjs";
import {
  INPUTS, MAX_INPUT_BYTES, MAX_MEMBERS, MAX_PATH_BYTES, MAX_UNRESTORABLE, buildInput, checkInput, readInput, removeInputs, writeInput,
} from "../lib/fleet/host/restore-inputs.mjs";

const UID = typeof process.getuid === "function" ? process.getuid() : -1; // (Linux-only rows; off Linux the file only loads)
const refused = (fn, code) => assert.throws(fn, (e) => e instanceof FleetError && e.code === code, code);
const RUN = newRestoreRun(1795500000000, () => Buffer.alloc(6));
const obj = (over = {}) => ({ type: "dir", mode: 0o700, uid: 70000, gid: 70000, dev: [8, 1], ino: 4242, gen: 1, mnt_id: 7, projid: 70000, inherit: true, ...over });
const dest = (over = {}) => ({ epoch: { boot_id: "00000000-0000-4000-8000-000000000000", mnt_id: 7 }, fsid: "0123456789abcdef", object: obj(over) });
const dirOf = () => { const d = join(mkdtempSync(join(tmpdir(), "sb-inputs-")), "restore"); mkdirSync(d, { mode: 0o700 }); return d; };

/** A registry: agent a (tag t), agent b (tag t), c deleted (tag t, not a live member), tag t. */
function world() {
  const [a, b, c, t] = [newId(), newId(), newId(), newId()];
  const registry = {
    v: 1, next_uid: 70010, next_gid: 80010,
    agents: {
      [a]: { uid: 70003, state: "running", life: 1, gen: 1, tags: [t], start_failed: null },
      [b]: { uid: 70001, state: "stopped", life: 1, gen: 1, tags: [t], start_failed: null },
      [c]: { uid: 70002, state: "deleted", life: 1, gen: 1, tags: [t], start_failed: null },
    },
    tags: { [t]: { gid: 80001 } },
  };
  return { a, b, c, t, registry };
}
const build = (w, kind, id, over = {}) => buildInput({ kind, id, run: RUN, nonce: newId(), registry: w.registry, destOf: () => dest(), unrestorableOf: () => [], ...over });

test("built from the registry: owners per class, members the set's live agents with their uids; no trusted identity, no input", () => {
  const w = world();
  const ag = build(w, "agent", w.a);
  assert.deepEqual(Object.keys(ag.classes), ["home", "sessions"]);
  assert.deepEqual(ag.classes.home.owners, { uids: [70003], gid: 70003, projid: 70003 });
  assert.deepEqual(ag.members, [{ agent: w.a, uid: 70003 }]);
  const tg = build(w, "tag", w.t);
  assert.deepEqual(tg.classes.tag.owners, { uids: [70001, 70003], gid: 80001, projid: 80001 }, "live members only: the deleted one isn't");
  assert.deepEqual(tg.members, [{ agent: w.b, uid: 70001 }, { agent: w.a, uid: 70003 }], "sorted by uid");
  const ar = build(w, "archive", w.c);
  assert.deepEqual([ar.classes.archive.owners, ar.members], [{ uids: [70002], gid: 70002, projid: 70002 }, []]);
  // An archive's config archive is root's alone, in the set's project (A2 r3.13): never the deleted agent's uid.
  assert.deepEqual(Object.keys(ar.classes), ["archive", "archive-config"]);
  assert.deepEqual(ar.classes["archive-config"].owners, { uids: [0], gid: 0, projid: 70002 });
  // The recorded identity is what goes in, never anything else.
  const seen = [];
  build(w, "agent", w.a, { destOf: (k, i, cls) => { seen.push([k, i, cls]); return dest({ ino: cls === "home" ? 1 : 2 }); } });
  assert.deepEqual(seen, [["agent", w.a, "home"], ["agent", w.a, "sessions"]]);
  // One class without a trusted identity: no input at all.
  assert.equal(build(w, "agent", w.a, { destOf: (k, i, cls) => (cls === "sessions" ? null : dest()) }), null);
  assert.equal(build(w, "tag", w.t, { destOf: () => undefined }), null);
  // A set the registry doesn't support refuses (an archive of a live agent; an agent that is deleted).
  refused(() => build(w, "archive", w.a), "not_found");
  refused(() => build(w, "agent", w.c), "not_found");
});

test("the closed shape: every missing, extra or wrong key, at every level, refuses", () => {
  const w = world();
  const good = () => structuredClone(build(w, "tag", w.t));
  checkInput(good());
  const muts = [
    (x) => { delete x.v; }, (x) => { x.extra = 1; }, (x) => { x.v = 2; }, (x) => { x.kind = "home"; }, (x) => { x.id = "nope"; },
    (x) => { x.run = "x"; }, (x) => { x.nonce = "short"; }, (x) => { x.nonce = RUN; },
    (x) => { x.classes = {}; }, (x) => { x.classes.home = x.classes.tag; }, (x) => { x.classes.tag.extra = 1; }, (x) => { delete x.classes.tag.unrestorable; },
    (x) => { x.classes.tag.dest.object.type = "file"; }, (x) => { x.classes.tag.dest.object.dev = [8]; }, (x) => { delete x.classes.tag.dest.object.ino; },
    (x) => { x.classes.tag.dest.epoch.boot_id = "x"; }, (x) => { x.classes.tag.dest.fsid = "XYZ"; }, (x) => { x.classes.tag.dest.extra = 1; },
    (x) => { x.classes.tag.owners.uids = []; }, (x) => { x.classes.tag.owners.uids.reverse(); }, (x) => { x.classes.tag.owners.gid = -1; },
    (x) => { x.classes.tag.owners.extra = 0; }, (x) => { x.classes.tag.unrestorable = ["a", "a"]; }, (x) => { x.classes.tag.unrestorable = [""]; },
    (x) => { x.members.reverse(); }, (x) => { x.members.push(x.members[0]); }, (x) => { x.members.pop(); }, (x) => { x.members[0].uid = 1; },
    (x) => { x.members[0].extra = 1; }, (x) => { x.members[0].agent = "nope"; }, (x) => { x.members = {}; },
  ];
  for (const [i, m] of muts.entries()) { const x = good(); m(x); refused(() => checkInput(x), "bad_form"); assert.ok(true, String(i)); }
  // An agent set's one member is the agent itself; an archive has none.
  const ag = structuredClone(build(w, "agent", w.a));
  ag.members = [{ agent: w.b, uid: 70003 }];
  refused(() => checkInput(ag), "bad_form");
  const ar = structuredClone(build(w, "archive", w.c));
  ar.members = [{ agent: w.c, uid: 70002 }];
  refused(() => checkInput(ar), "bad_form");
});

test("caps at the cap and one over: members, unrestorable paths and their bytes, the file", () => {
  const w = world();
  // members (and the tag's owner uids with them)
  const tagOf = (n) => {
    const x = structuredClone(build(w, "tag", w.t));
    const ms = Array.from({ length: n }, (_, i) => ({ agent: newId(), uid: 71000 + i }));
    x.members = ms;
    x.classes.tag.owners.uids = ms.map((m) => m.uid);
    return x;
  };
  checkInput(tagOf(MAX_MEMBERS));
  refused(() => checkInput(tagOf(MAX_MEMBERS + 1)), "bad_form");
  // unrestorable paths: the count, and each path's bytes (a multi-byte character counts its bytes)
  const withPaths = (ps) => build(w, "agent", w.a, { unrestorableOf: () => ps });
  assert.equal(withPaths(Array.from({ length: MAX_UNRESTORABLE }, (_, i) => `p${i}`)).classes.home.unrestorable.length, MAX_UNRESTORABLE);
  refused(() => withPaths(Array.from({ length: MAX_UNRESTORABLE + 1 }, (_, i) => `p${i}`)), "bad_form");
  withPaths(["x".repeat(MAX_PATH_BYTES)]);
  refused(() => withPaths(["x".repeat(MAX_PATH_BYTES + 1)]), "bad_form");
  refused(() => withPaths(["é".repeat(MAX_PATH_BYTES / 2) + "x"]), "bad_form");
  // the file: over 1 MiB refuses at write; a file over it on disk refuses at read
  const dir = dirOf();
  const big = withPaths(Array.from({ length: MAX_UNRESTORABLE }, (_, i) => `${i}`.padStart(1100, "z")));
  assert.ok(JSON.stringify(big).length > MAX_INPUT_BYTES);
  refused(() => writeInput(big, { dir, uid: UID }), "bad_form");
  assert.equal(existsSync(join(dir, INPUTS, `agent-${w.a}.json`)), false);
  mkdirSync(join(dir, INPUTS), { mode: 0o700, recursive: true });
  writeFileSync(join(dir, INPUTS, `agent-${w.a}.json`), "x".repeat(MAX_INPUT_BYTES + 1));
  refused(() => readInput("agent", w.a, { dir, uid: UID }), "bad_form");
});

test("written durably and private, read back whole; replaced by the next write; missing is null", () => {
  const w = world();
  const dir = dirOf();
  assert.equal(readInput("agent", w.a, { dir, uid: UID }), null, "no inputs directory");
  const x = build(w, "agent", w.a);
  writeInput(x, { dir, uid: UID });
  const p = join(dir, INPUTS, `agent-${w.a}.json`);
  assert.equal(statSync(p).mode & 0o777, 0o600);
  assert.equal(statSync(join(dir, INPUTS)).mode & 0o777, 0o700);
  assert.deepEqual(readInput("agent", w.a, { dir, uid: UID }), x);
  const y = build(w, "agent", w.a);
  writeInput(y, { dir, uid: UID });
  assert.equal(readInput("agent", w.a, { dir, uid: UID }).nonce, y.nonce, "the newer nonce");
  assert.equal(readInput("tag", w.t, { dir, uid: UID }), null);
  // Malformed on disk: refused.
  writeFileSync(p, "{");
  refused(() => readInput("agent", w.a, { dir, uid: UID }), "bad_form");
  writeFileSync(p, JSON.stringify({ ...y, extra: 1 }));
  refused(() => readInput("agent", w.a, { dir, uid: UID }), "bad_form");
});

test("never through a link, never a directory that isn't private", () => {
  const w = world();
  const dir = dirOf();
  const x = build(w, "agent", w.a);
  // The input a link to a well-formed file elsewhere: refused, never followed.
  const elsewhere = join(dir, "..", "elsewhere.json");
  writeFileSync(elsewhere, JSON.stringify(x) + "\n");
  mkdirSync(join(dir, INPUTS), { mode: 0o700 });
  symlinkSync(elsewhere, join(dir, INPUTS, `agent-${w.a}.json`));
  refused(() => readInput("agent", w.a, { dir, uid: UID }), "bad_form");
  // Removal removes the link itself, not its target.
  removeInputs([`agent-${w.a}`], { dir, uid: UID });
  assert.equal(existsSync(join(dir, INPUTS, `agent-${w.a}.json`)), false);
  assert.ok(existsSync(elsewhere));
  // The inputs directory a link, or writable by others: refused for read, write and removal.
  const d2 = dirOf();
  const other = join(d2, "..", "other");
  mkdirSync(other, { mode: 0o700 });
  symlinkSync(other, join(d2, INPUTS));
  refused(() => readInput("agent", w.a, { dir: d2, uid: UID }), "not_granted");
  refused(() => writeInput(x, { dir: d2, uid: UID }), "not_granted");
  refused(() => removeInputs([`agent-${w.a}`], { dir: d2, uid: UID }), "not_granted");
  const d3 = dirOf();
  mkdirSync(join(d3, INPUTS), { mode: 0o700 });
  chmodSync(join(d3, INPUTS), 0o777);
  refused(() => writeInput(x, { dir: d3, uid: UID }), "not_granted");
  assert.equal(lstatSync(other).isDirectory(), true);
});

test("removeInputs: by set key, missing fine, durable; a bad key refuses before anything", () => {
  const w = world();
  const dir = dirOf();
  removeInputs([`agent-${w.a}`], { dir, uid: UID }); // no directory: nothing to do
  writeInput(build(w, "agent", w.a), { dir, uid: UID });
  writeInput(build(w, "tag", w.t), { dir, uid: UID });
  assert.throws(() => removeInputs(["nope"], { dir, uid: UID }), (e) => e.code === "bad_form");
  assert.ok(existsSync(join(dir, INPUTS, `agent-${w.a}.json`)), "a bad key removes nothing");
  const ops = [];
  const io = { ...realIo, open: (p, f, m) => { ops.push(["open", p]); return realIo.open(p, f, m); }, fsync: (fd) => { ops.push(["fsync"]); return realIo.fsync(fd); } };
  removeInputs([`agent-${w.a}`, `archive-${w.a}`], { dir, uid: UID, io });
  assert.deepEqual(ops, [["open", join(dir, INPUTS)], ["fsync"]], "the directory synced once after the removal");
  ops.length = 0;
  removeInputs([`archive-${w.a}`], { dir, uid: UID, io });
  assert.deepEqual(ops, [], "nothing removed, nothing to sync");
  assert.equal(existsSync(join(dir, INPUTS, `agent-${w.a}.json`)), false);
  assert.ok(existsSync(join(dir, INPUTS, `tag-${w.t}.json`)), "only the named ones");
  assert.ok(readFileSync(join(dir, INPUTS, `tag-${w.t}.json`)).length > 0);
});

test("an archive's owner uids are capped too (no member equality bounds them)", () => {
  const w = world();
  const x = structuredClone(build(w, "archive", w.c));
  x.classes.archive.owners.uids = Array.from({ length: MAX_MEMBERS }, (_, i) => 71000 + i);
  checkInput(x);
  x.classes.archive.owners.uids = Array.from({ length: MAX_MEMBERS + 1 }, (_, i) => 71000 + i);
  refused(() => checkInput(x), "bad_form");
});

test("raw bytes: a repeated key (at the root, nested, or escaped) refuses; only the writer's exact bytes are an input", () => {
  const w = world();
  const dir = dirOf();
  const x = build(w, "agent", w.a);
  writeInput(x, { dir, uid: UID });
  const p = join(dir, INPUTS, `agent-${w.a}.json`);
  const good = readFileSync(p, "utf8");
  assert.deepEqual(readInput("agent", w.a, { dir, uid: UID }), x, "the writer's bytes read back");
  const put = (text) => writeFileSync(p, text);
  const cases = {
    "a root key repeated": good.replace('{"v":1,', '{"v":1,"v":1,'),
    "a root key repeated, escaped": good.replace('{"v":1,', '{"\\u0076":1,"v":1,'),
    "an escaped key alone": good.replace('{"v":1,', '{"\\u0076":1,'),
    "a nested key repeated (owners.gid)": good.replace('"gid":70003,', '"gid":1,"gid":70003,'),
    "a nested key repeated, last wins differently": good.replace('"gid":70003,', '"gid":70003,"gid":70003,'),
    "other spacing": good.replace('{"v":1,', '{ "v": 1,'),
    "no final newline": good.slice(0, -1),
    "a second line": good + good,
  };
  for (const [what, text] of Object.entries(cases)) {
    assert.notEqual(text, good, `${what}: (the case differs)`);
    put(text);
    refused(() => readInput("agent", w.a, { dir, uid: UID }), "bad_form");
  }
  // Bytes that aren't UTF-8 inside a string: refused.
  writeFileSync(p, Buffer.concat([Buffer.from(good.slice(0, 10)), Buffer.from([0xff]), Buffer.from(good.slice(10))]));
  refused(() => readInput("agent", w.a, { dir, uid: UID }), "bad_form");
  put(good);
  assert.deepEqual(readInput("agent", w.a, { dir, uid: UID }), x);
});

test("raw bytes: an invalid UTF-8 byte INSIDE a string (an unrestorable path) refuses; it isn't decoded into a replacement character that round-trips", () => {
  const w = world();
  const dir = dirOf();
  const x = build(w, "agent", w.a, { unrestorableOf: () => ["a/b"] });
  writeInput(x, { dir, uid: UID });
  const p = join(dir, INPUTS, `agent-${w.a}.json`);
  const good = readFileSync(p);
  const at = good.indexOf(Buffer.from('"a/b"'));
  assert.ok(at > 0);
  for (const bytes of [[0xff], [0xc3], [0xed, 0xa0, 0x80]]) { // a stray byte, a truncated sequence, an encoded surrogate
    writeFileSync(p, Buffer.concat([good.subarray(0, at + 2), Buffer.from(bytes), good.subarray(at + 2)]));
    refused(() => readInput("agent", w.a, { dir, uid: UID }), "bad_form");
  }
  // The same path written with a real U+FFFD by the writer is an input: only the writer's bytes count.
  const y = build(w, "agent", w.a, { unrestorableOf: () => ["a\ufffdb"] });
  writeInput(y, { dir, uid: UID });
  assert.deepEqual(readInput("agent", w.a, { dir, uid: UID }), y);
});
