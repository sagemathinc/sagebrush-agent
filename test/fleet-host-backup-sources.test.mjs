// Host backup r3.3 §3, §6: the run's source allowlist from the registry, the forbidden roots (logins and secrets,
// as given and as resolved), and the one bounded walk giving the unrestorable list and the change fingerprint.
import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, symlinkSync, utimesSync, writeFileSync, lstatSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "./host-linux-only.mjs";
import { FleetError, newId } from "../lib/fleet/index.mjs";
import { FIXED_FORBIDDEN, backupSources, checkExcludes, checkForbidden, realOrSelf, unchanged, walkSources, within } from "../lib/fleet/host/backup-sources.mjs";

const refused = (fn, code) => assert.throws(fn, (e) => e instanceof FleetError && e.code === code, code);
const SRV = "/srv/sagebrush";

function registry() {
  const [a, b, c] = [newId(), newId(), newId()].sort();
  const t = newId();
  return {
    a, b, c, t,
    reg: {
      v: 1, next_uid: 70003, next_gid: 80001,
      agents: {
        [a]: { uid: 70000, state: "running", life: 0, gen: 1, tags: [t], start_failed: null },
        [b]: { uid: 70001, state: "stopped", life: 1, gen: 1, tags: [t], start_failed: null },
        [c]: { uid: 70002, state: "deleted", life: 2, gen: 1, tags: [t], start_failed: null },
      },
      tags: { [t]: { gid: 80000 } },
    },
  };
}

test("the allowlist: home, sessions and config for a live agent; the archives for a deleted one; a tag with its live members", () => {
  const { a, b, c, t, reg } = registry();
  assert.deepEqual(backupSources(reg), [
    { kind: "agent", id: a, sources: [`${SRV}/agents/${a}/home`, `${SRV}/agents/${a}/sessions`, `${SRV}/agent-config/${a}`], uids: [70000], members: [a] },
    { kind: "agent", id: b, sources: [`${SRV}/agents/${b}/home`, `${SRV}/agents/${b}/sessions`, `${SRV}/agent-config/${b}`], uids: [70001], members: [b] },
    { kind: "archive", id: c, sources: [`${SRV}/archive/${c}`, `${SRV}/archive-config/${c}`], uids: [70002], members: [] },
    { kind: "tag", id: t, sources: [`${SRV}/tags/${t}`], uids: [70000, 70001], members: [a, b] },
  ]);
  const all = backupSources(reg).flatMap((s) => s.sources);
  for (const p of all) for (const never of ["var-tmp", "claude-profiles", "harness-pool", "claude-pool", "provisioned", "deprovision", "host-secrets", "/fence"]) {
    assert.ok(!p.includes(never), `${p} is never a source`);
  }
  refused(() => backupSources(null), "bad_form");
});

test("forbidden roots: refused when one is at or beneath a source, or a source is at or beneath one", () => {
  const src = [`${SRV}/agents/x/home`];
  checkForbidden(src, FIXED_FORBIDDEN, { real: (p) => p });
  refused(() => checkForbidden(src, [`${SRV}/agents/x/home/.claude`], { real: (p) => p }), "not_granted"); // a profile root inside a home
  refused(() => checkForbidden(src, [`${SRV}/agents/x/home`], { real: (p) => p }), "not_granted");
  refused(() => checkForbidden([`${SRV}/claude-profiles/p1`], FIXED_FORBIDDEN, { real: (p) => p }), "not_granted"); // a source inside one
  checkForbidden([`${SRV}/agents/x/homeX`], [`${SRV}/agents/x/home`], { real: (p) => p }); // a sibling with a shared prefix is fine
  for (const bad of ["rel", "/a/../b", "/a/", "/a//b", "/"]) refused(() => checkForbidden([bad], [], { real: (p) => p }), "bad_form");
  assert.ok(within("/a/b", "/a") && within("/a", "/a") && !within("/ab", "/a"));
});

test("forbidden roots are checked as resolved too: a symlink can't bring one into a source", () => {
  const root = mkdtempSync(join(tmpdir(), "sb-bsrc-"));
  mkdirSync(join(root, "profiles", "p1"), { recursive: true });
  mkdirSync(join(root, "home"));
  symlinkSync(join(root, "profiles"), join(root, "home", "linked"));
  // The forbidden root is reached only through the link: as given it isn't inside the source, as resolved it isn't
  // either; but a source that IS the link resolves into the forbidden root.
  refused(() => checkForbidden([join(root, "home", "linked")], [join(root, "profiles")]), "not_granted");
  checkForbidden([join(root, "home")], [join(root, "profiles")]);
});

test("a missing tail behind a symlink is resolved through the link, in both directions and for several missing parts", () => {
  const root = mkdtempSync(join(tmpdir(), "sb-btail-"));
  const forbidden = join(root, "forbidden"), safe = join(root, "safe"), home = join(root, "home");
  for (const d of [forbidden, safe, home]) mkdirSync(d);
  symlinkSync(forbidden, join(safe, "link"));
  symlinkSync(home, join(safe, "tohome"));
  // a source through the link, with one and with several parts that don't exist yet
  refused(() => checkForbidden([join(safe, "link", "missing")], [forbidden]), "not_granted");
  refused(() => checkForbidden([join(safe, "link", "a", "b", "c")], [forbidden]), "not_granted");
  // a forbidden root through a link into the source, with missing parts
  refused(() => checkForbidden([home], [join(safe, "tohome", "profiles", "p1")]), "not_granted");
  // and nothing is refused when the link leads elsewhere
  checkForbidden([join(safe, "tohome", "x")], [forbidden]);
  assert.equal(realOrSelf(join(safe, "link", "a", "b")), join(forbidden, "a", "b"));
  assert.equal(realOrSelf("/nonexistent-root-xyz/a"), "/nonexistent-root-xyz/a");
  assert.throws(() => realOrSelf("/x/y", { realpath: () => { throw Object.assign(new Error("EACCES"), { code: "EACCES" }); } }), (e) => e.code === "EACCES");
});

test("the walk: owners not allowed are counted and listed, links aren't followed, a missing source is reported", () => {
  const root = mkdtempSync(join(tmpdir(), "sb-bwalk-"));
  const home = join(root, "home");
  mkdirSync(join(home, "d"), { recursive: true });
  writeFileSync(join(home, "a.txt"), "hello");
  writeFileSync(join(home, "d", "b.bin"), Buffer.alloc(1000));
  symlinkSync("/etc/passwd", join(home, "link"));
  const me = lstatSync(home).uid;
  const set = { sources: [home, join(root, "sessions")], uids: [me] };
  const r = walkSources(set);
  assert.equal(r.fingerprint.entries, 5); // home, a.txt, d, d/b.bin, link (not followed)
  assert.equal(r.fingerprint.bytes, "1005");
  assert.deepEqual(r.unrestorable, { count: 0, paths: [] });
  assert.deepEqual(r.missing, [join(root, "sessions")]);
  const other = walkSources({ sources: [home], uids: [me + 1] });
  assert.equal(other.unrestorable.count, 5);
  assert.deepEqual(other.unrestorable.paths.slice(0, 2), [home, join(home, "a.txt")]);
  assert.equal(walkSources({ sources: [home], uids: [me + 1] }, { listMax: 2 }).unrestorable.paths.length, 2);
  refused(() => walkSources(set, { maxEntries: 4 }), "limit");
});

test("the fingerprint changes on a write even when size and mtime are put back (ctime), and on a delete", async () => {
  const root = mkdtempSync(join(tmpdir(), "sb-bfp-"));
  const home = join(root, "home");
  mkdirSync(home);
  writeFileSync(join(home, "f"), "aaaa");
  // Whole-second times, so they can be put back exactly (a Date would lose the nanoseconds).
  utimesSync(join(home, "f"), 1_000_000, 1_000_000); utimesSync(home, 1_000_000, 1_000_000);
  const set = { sources: [home], uids: [lstatSync(home).uid] };
  const before = walkSources(set).fingerprint;
  assert.equal(unchanged(walkSources(set).fingerprint, before), true);
  await new Promise((r) => setTimeout(r, 20));
  writeFileSync(join(home, "f"), "bbbb");
  utimesSync(join(home, "f"), 1_000_000, 1_000_000); // same size, mtime put back exactly: only ctime moved
  const after = walkSources(set).fingerprint;
  assert.equal(after.bytes, before.bytes); assert.equal(after.mtime_ns, before.mtime_ns, "the mtime is exactly as before");
  assert.equal(after.entries, before.entries);
  assert.notEqual(after.ctime_ns, before.ctime_ns);
  assert.equal(unchanged(after, before), false, "ctime moved");
  assert.equal(unchanged(after, null), false, "no last snapshot: never skipped");
});

test("a mount below a source isn't entered, and is reported", () => {
  const home = "/h";
  const mk = (dev, dir, uid = 1) => ({ dev, uid: BigInt(uid), size: 0n, mtimeNs: 1n, ctimeNs: 1n, isFile: () => !dir, isDirectory: () => dir });
  const tree = { "/h": mk(1n, true), "/h/m": mk(2n, true), "/h/m/x": mk(2n, false), "/h/f": mk(1n, false) };
  const fsx = { lstatSync: (p) => { if (!tree[p]) throw Object.assign(new Error(), { code: "ENOENT" }); return tree[p]; }, readdirSync: (p) => Object.keys(tree).filter((k) => k !== p && k.startsWith(p + "/") && !k.slice(p.length + 1).includes("/")).map((k) => k.slice(p.length + 1)) };
  const r = walkSources({ sources: [home], uids: [1] }, { fsx });
  assert.deepEqual(r.other_fs, ["/h/m"]);
  assert.equal(r.fingerprint.entries, 2);
});

test("excludes: at most 256 one-line globs without commas", () => {
  assert.deepEqual(checkExcludes(["*.tmp", "node_modules"]), ["*.tmp", "node_modules"]);
  for (const bad of [null, ["a,b"], ["a\nb"], [""], Array(257).fill("x"), ["x".repeat(257)]]) refused(() => checkExcludes(bad), "bad_form");
});
