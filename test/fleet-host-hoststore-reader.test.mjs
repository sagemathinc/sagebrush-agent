// Launcher contract A2 r3.14 r2 §3: the staged host-store copy read in place, only through file descriptors, every
// entry root's with exact modes; links, specials, other owners or modes, swapped objects and over-bound trees refused.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import * as fs from "node:fs";
import { chmodSync, mkdirSync, mkdtempSync, renameSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "./host-linux-only.mjs";
import { FleetError } from "../lib/fleet/index.mjs";
import { copyReader } from "../lib/fleet/host/hoststore-reader.mjs";

const UID = typeof process.getuid === "function" ? process.getuid() : -1; // (Linux-only rows; off Linux the file only loads)
const refused = (fn, code) => assert.throws(fn, (e) => e instanceof FleetError && e.code === code, code);

/** A copy as the backup writes it: { registry/registry.json, audit/{1.log, old/0.log} }, dirs 0700, files 0600. */
function copy() {
  const c = join(mkdtempSync(join(tmpdir(), "sb-hsr-")), "copy");
  for (const d of [c, join(c, "registry"), join(c, "audit"), join(c, "audit", "old")]) { mkdirSync(d, { recursive: true }); chmodSync(d, 0o700); }
  for (const [f, t] of [["registry/registry.json", "{}\n"], ["audit/1.log", "one\n"], ["audit/old/0.log", "zero\n"]]) { writeFileSync(join(c, f), t); chmodSync(join(c, f), 0o600); }
  return c;
}

test("list, read and walk through handles: names sorted, bytes exact, entries bounded and typed", () => {
  const c = copy();
  const r = copyReader(c, { uid: UID });
  assert.deepEqual(r.list(""), ["audit", "registry"]);
  assert.deepEqual(r.list("audit"), ["1.log", "old"]);
  assert.equal(r.read("registry/registry.json").toString(), "{}\n");
  assert.deepEqual(r.walk("audit"), [{ rel: "1.log", dir: false, size: 4 }, { rel: "old", dir: true }, { rel: "old/0.log", dir: false, size: 5 }]);
  for (const bad of ["..", "a/../b", "a//b", "/abs", "registry/"]) refused(() => r.read(bad), "bad_form");
  refused(() => r.read(""), "bad_form");
  refused(() => r.read("registry/none.json"), "not_found"); // (lstat's ENOENT, surfaced)
});

test("every refusal: a link, a special file, another owner or mode, at any depth; nothing is followed", () => {
  const cases = [
    ["a link in place of a file", (c) => { fs.rmSync(join(c, "registry/registry.json")); symlinkSync("/etc/passwd", join(c, "registry/registry.json")); }, (r) => r.read("registry/registry.json")],
    ["a link in place of a directory", (c) => { fs.rmSync(join(c, "audit"), { recursive: true }); symlinkSync("/etc", join(c, "audit")); }, (r) => r.list("audit")],
    ["a link inside a walked tree", (c) => symlinkSync("/etc/passwd", join(c, "audit/old/l")), (r) => r.walk("audit")],
    ["a file 0644", (c) => chmodSync(join(c, "audit/old/0.log"), 0o644), (r) => r.walk("audit")],
    ["a file 0400", (c) => chmodSync(join(c, "registry/registry.json"), 0o400), (r) => r.read("registry/registry.json")],
    ["a directory 0755", (c) => chmodSync(join(c, "audit/old"), 0o755), (r) => r.walk("audit")],
    ["the top 0750", (c) => chmodSync(c, 0o750), (r) => r.list("")],
    ["a fifo", (c) => execFileSync("mkfifo", [join(c, "audit/fifo")]), (r) => r.walk("audit")],
  ];
  for (const [what, plant, call] of cases) {
    const c = copy();
    plant(c);
    assert.throws(() => call(copyReader(c, { uid: UID })), (e) => e instanceof FleetError && ["not_granted", "not_found"].includes(e.code) && (what.startsWith("a link in place of a file") ? e.code === "not_granted" : true), what);
  }
  // Another owner: the reader is root's; a tree owned by anyone else (here: the test's uid, read as another's) refuses.
  refused(() => copyReader(copy(), { uid: UID + 1 }).list(""), "not_granted");
});

test("an object swapped between its lstat and its open is refused (the handle must be the lstat'd object)", () => {
  for (const kind of ["file", "dir"]) {
    const c = copy();
    const target = kind === "file" ? join(c, "registry/registry.json") : join(c, "audit");
    let swapped = false;
    const fsx = {
      ...fs,
      openSync: (p, ...a) => {
        // (just before the open of the target, by its handle-relative name: another object of the same type takes its place)
        if (!swapped && (p.endsWith("/registry.json") && kind === "file" || p.endsWith("/audit") && kind === "dir")) {
          swapped = true;
          const other = `${target}.other`;
          if (kind === "file") { writeFileSync(other, "x"); chmodSync(other, 0o600); } else { mkdirSync(other); chmodSync(other, 0o700); }
          renameSync(target, `${target}.orig`);
          renameSync(other, target);
        }
        return fs.openSync(p, ...a);
      },
    };
    const r = copyReader(c, { uid: UID, fsx });
    refused(() => (kind === "file" ? r.read("registry/registry.json") : r.list("audit")), "not_granted");
    assert.ok(swapped, kind);
  }
});

test("bounds: more entries or more bytes than an import takes refuse (limit)", () => {
  const c = copy();
  refused(() => copyReader(c, { uid: UID, maxFiles: 2 }).walk("audit"), "limit");
  refused(() => copyReader(c, { uid: UID, maxBytes: 8 }).walk("audit"), "limit");
  assert.equal(copyReader(c, { uid: UID, maxFiles: 3, maxBytes: 9 }).walk("audit").length, 3, "at the bounds");
  refused(() => copyReader(c, { uid: UID, maxBytes: 2 }).read("registry/registry.json"), "not_granted"); // (a file over the bound)
});

test("the root is pinned at the first open: a copy root replaced between calls (same owner and mode) refuses every later call", () => {
  const c = copy();
  const r = copyReader(c, { uid: UID });
  assert.deepEqual(r.list(""), ["audit", "registry"]);
  const other = copy();
  renameSync(c, `${c}.old`);
  renameSync(other, c);
  refused(() => r.list(""), "not_granted");
  refused(() => r.read("registry/registry.json"), "not_granted");
  refused(() => r.walk(""), "not_granted");
  // Put back, the pinned root reads again.
  renameSync(c, other);
  renameSync(`${c}.old`, c);
  assert.equal(r.read("registry/registry.json").toString(), "{}\n");
});
