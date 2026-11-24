// Host backup r3.3 §5 step 7: the space check before any staging says exactly one of three things: "fits" (proven by
// upper bounds on blocks and inodes within every limit), "doesnt_fit" (proven by a lower bound on inodes only), or
// "cant_tell" (it refuses, with the person's options). The need is each class's peak (usage's peak_inodes and
// peak_blocks_upper) plus the launcher's own staging objects: 4 inodes and 3 blocks charged to the class's project and
// the filesystem, and up to 3 parent directories charged to the filesystem only (none when shared).
import assert from "node:assert/strict";
import { test } from "./host-linux-only.mjs";
import { BLOCK, CANT_TELL_OPTIONS, STAGING, needOf, spaceVerdict } from "../lib/fleet/host/restore-space.mjs";

const usage = (peak_blocks_upper, peak_inodes, { blocks_upper = 0, inodes = 0 } = {}) =>
  ({ snapshot: "a".repeat(64), entries: inodes, inodes, blocks_upper, peak_inodes, peak_blocks_upper, block_size: 4096 });
const project = (blocks, inodes) => ({ what: "the agent's quota", kind: "project", blocks, inodes, blockSize: 4096 });
const fsys = (blocks, inodes) => ({ what: "the filesystem", kind: "filesystem", blocks, inodes, blockSize: 4096 });

test("the staging objects: an empty class still needs the attempt, data, its leaf, the marker and maybe the parents", () => {
  assert.deepEqual(STAGING, { project: { inodes: 4, blocks: 3 }, parents: { inodesMin: 0, inodesMax: 3, blocks: 3 } });
  const need = needOf([usage(0, 0)]);
  assert.deepEqual(need, { project: { blocks: 3, inodesMin: 4, inodesMax: 4 }, filesystem: { blocks: 6, inodesMin: 4, inodesMax: 7 } });
  // With nothing free it never fits: the inodes the launcher makes itself prove it doesn't.
  assert.equal(spaceVerdict(need, [project(0, 0), fsys(0, 0)]).verdict, "doesnt_fit");
  assert.equal(spaceVerdict(need, [project(1000, 1000), fsys(0, 0)]).verdict, "doesnt_fit", "the filesystem's lower bound too");
});

test("exact: at every limit it fits; one short is doesnt_fit by inodes, can't tell by blocks or the parents", () => {
  const need = needOf([usage(100, 10)]); // project 103 blocks, 14 inodes; filesystem 106 blocks, 14..17 inodes
  assert.deepEqual(spaceVerdict(need, [project(103, 14), fsys(106, 17)]), { verdict: "fits" }, "exactly at the limits");
  // One inode short of the project's exact need: proven.
  assert.deepEqual(spaceVerdict(need, [project(103, 13), fsys(106, 17)]), { verdict: "doesnt_fit", why: "at least 14 inodes needed, 13 free in the agent's quota" });
  // One inode short of the filesystem's upper bound but not its lower: the parents may already exist: can't tell.
  const p = spaceVerdict(need, [project(103, 14), fsys(106, 16)]);
  assert.deepEqual([p.verdict, p.why], ["cant_tell", "up to 17 inodes may be needed, 16 free in the filesystem"]);
  assert.deepEqual(p.options, [...CANT_TELL_OPTIONS]);
  // One block short anywhere: never proof of doesn't fit.
  assert.equal(spaceVerdict(need, [project(102, 14), fsys(106, 17)]).verdict, "cant_tell");
  assert.equal(spaceVerdict(need, [project(103, 14), fsys(105, 17)]).verdict, "cant_tell");
  // The project's need excludes the parents; the filesystem's includes them.
  assert.equal(spaceVerdict(need, [project(103, 14)]).verdict, "fits", "a project quota of exactly its need");
});

test("coexisting classes: an agent's two classes count together, and their parents are never counted short", () => {
  // home and sessions of one agent: the run and owner directories are shared, only the class directories differ.
  const need = needOf([usage(50, 5), usage(20, 2)]);
  assert.deepEqual(need.project, { blocks: 50 + 3 + 20 + 3, inodesMin: 5 + 4 + 2 + 4, inodesMax: 15 });
  assert.deepEqual(need.filesystem, { blocks: 76 + 6, inodesMin: 15, inodesMax: 15 + 6 });
  // Really made: run + owner + 2 class directories = 4 parent inodes, within the bound 6, above the lower bound 0.
  const really = 15 + 4;
  assert.ok(need.filesystem.inodesMin <= really && really <= need.filesystem.inodesMax);
  // So a filesystem with exactly the real count free is "can't tell", never a false "doesn't fit".
  assert.equal(spaceVerdict(need, [fsys(1000, really)]).verdict, "cant_tell");
  assert.equal(spaceVerdict(need, [fsys(1000, 21)]).verdict, "fits");
});

test("the peak, not the final size: directories and symlinks counted twice by usage, used as given", () => {
  const u = usage(30, 7, { blocks_upper: 20, inodes: 5 });
  assert.deepEqual(needOf([u]).project, { blocks: 33, inodesMin: 11, inodesMax: 11 });
  for (const bad of [{ ...u, peak_inodes: 4 }, { ...u, peak_blocks_upper: 19 }, { ...u, block_size: 512 }, { ...u, peak_inodes: -1 }]) {
    assert.throws(() => needOf([bad]), (e) => e.code === "bad_form", JSON.stringify(bad));
  }
});

test("another block size makes the bound no proof: can't tell, never fits", () => {
  const v = spaceVerdict(needOf([usage(1, 1)]), [project(1_000_000, 100), { ...fsys(1_000_000, 100), blockSize: 1024 }]);
  assert.equal(v.verdict, "cant_tell");
  assert.match(v.why, /1024-byte blocks/);
  assert.equal(BLOCK, 4096);
});

test("refusals: no usage, a bad need or limit", () => {
  for (const u of [[], null, [{}]]) assert.throws(() => needOf(u), (e) => e.code === "bad_form");
  const need = needOf([usage(1, 1)]);
  for (const [n, limits] of [
    [null, [project(1, 1)]], [{ project: need.project }, [project(1, 1)]],
    [{ ...need, project: { ...need.project, inodesMin: 9, inodesMax: 8 } }, [project(1, 1)]],
    [need, []], [need, [{ ...project(1, 1), kind: "tag" }]], [need, [{ ...project(1, 1), what: 1 }]], [need, [project(-1, 1)]],
  ]) assert.throws(() => spaceVerdict(n, limits), (e) => e.code === "bad_form");
});
