// Host backup r3.3 §5 step 7: the space check before any staging says exactly one of three things: "fits" (proven by
// upper bounds on blocks and inodes within every limit), "doesnt_fit" (proven only when the staged tree's inodes,
// a lower bound, are over a limit), or "cant_tell" (it refuses, with the person's options). Each class's upper bound
// is the larger of its two phases: staged (the staged tree, the attempt, data, its leaf and the marker) and filled at
// its peak (every directory twice, the attempt, data and its leaf: the marker is gone before the first
// destination write); the filesystem also gets up to 3 parent directories per class.
import assert from "node:assert/strict";
import { test } from "./host-linux-only.mjs";
import { BLOCK, CANT_TELL_OPTIONS, STAGING, needOf, spaceVerdict } from "../lib/fleet/host/restore-space.mjs";

const usage = ({ blocks_upper = 0, inodes = 0, peak_blocks_upper = blocks_upper, peak_inodes = inodes } = {}) =>
  ({ snapshot: "a".repeat(64), entries: inodes, inodes, blocks_upper, peak_inodes, peak_blocks_upper, block_size: 4096 });
const project = (blocks, inodes) => ({ what: "the agent's quota", kind: "project", blocks, inodes, blockSize: 4096 });
const fsys = (blocks, inodes) => ({ what: "the filesystem", kind: "filesystem", blocks, inodes, blockSize: 4096 });

test("the staging objects per phase: the marker only while staged", () => {
  assert.deepEqual(STAGING, { staged: { inodes: 4, blocks: 3 }, filled: { inodes: 3, blocks: 2 }, parents: { inodes: 3, blocks: 3 } });
});

test("an empty class: nothing restored, so nothing proves it doesn't fit; its staging objects make it can't tell", () => {
  const need = needOf([usage({ blocks_upper: 4, peak_blocks_upper: 8 })]);
  assert.deepEqual(need.project, { blocks: Math.max(4 + 3, 8 + 2), inodesMin: 0, inodesMax: 4 });
  assert.deepEqual(need.filesystem, { blocks: 10 + 3, inodesMin: 0, inodesMax: 4 + 3 });
  assert.equal(spaceVerdict(need, [project(0, 0), fsys(0, 0)]).verdict, "cant_tell", "never a false doesnt_fit");
  assert.equal(spaceVerdict(need, [project(10, 4), fsys(13, 7)]).verdict, "fits");
});

test("one empty directory: staged 3 + marker + the directory = 5, filled 3 + the directory twice = 5; never doesnt_fit at 5", () => {
  // usage: final 1 inode (the directory), peak 2 (it exists twice while the fill runs).
  const need = needOf([usage({ inodes: 1, peak_inodes: 2, blocks_upper: 8, peak_blocks_upper: 16 })]);
  assert.deepEqual([need.project.inodesMin, need.project.inodesMax], [1, 5], "max(1 + 4, 2 + 3)");
  // The real peak is 5 in both phases: room for 5 fits (with the blocks), and 4 is only can't tell.
  assert.equal(spaceVerdict(need, [project(1000, 5)]).verdict, "fits");
  assert.equal(spaceVerdict(need, [project(1000, 4)]).verdict, "cant_tell");
  // Only room for less than the restored inode itself proves it.
  assert.equal(spaceVerdict(need, [project(1000, 0)]).verdict, "doesnt_fit");
});

test("exact: at every limit it fits; under the restored inodes is doesnt_fit; anything between is can't tell", () => {
  const need = needOf([usage({ inodes: 10, peak_inodes: 12, blocks_upper: 100, peak_blocks_upper: 120 })]);
  // project: blocks max(103, 122) = 122, inodes 10..max(14, 15) = 15; filesystem: 125 blocks, 10..18 inodes
  assert.deepEqual(need, { project: { blocks: 122, inodesMin: 10, inodesMax: 15 }, filesystem: { blocks: 125, inodesMin: 10, inodesMax: 18 } });
  assert.deepEqual(spaceVerdict(need, [project(122, 15), fsys(125, 18)]), { verdict: "fits" }, "exactly at the limits");
  assert.deepEqual(spaceVerdict(need, [project(122, 9), fsys(125, 18)]), { verdict: "doesnt_fit", why: "at least 10 inodes needed, 9 free in the agent's quota" });
  const c = spaceVerdict(need, [project(122, 14), fsys(125, 18)]);
  assert.deepEqual([c.verdict, c.why], ["cant_tell", "up to 15 inodes may be needed, 14 free in the agent's quota"]);
  assert.deepEqual(c.options, [...CANT_TELL_OPTIONS]);
  assert.equal(spaceVerdict(need, [project(122, 15), fsys(125, 17)]).verdict, "cant_tell", "the parents may already exist");
  assert.equal(spaceVerdict(need, [project(121, 15), fsys(125, 18)]).verdict, "cant_tell", "one block short");
  assert.equal(spaceVerdict(need, [project(122, 15), fsys(124, 18)]).verdict, "cant_tell");
  assert.equal(spaceVerdict(need, [project(122, 15)]).verdict, "fits", "the project's need excludes the parents");
});

test("coexisting classes: an agent's two classes count together at their larger phases, parents never short", () => {
  const need = needOf([usage({ inodes: 5, peak_inodes: 6, blocks_upper: 50, peak_blocks_upper: 60 }), usage({ inodes: 2, peak_inodes: 2, blocks_upper: 20, peak_blocks_upper: 20 })]);
  assert.deepEqual(need.project, { blocks: 62 + 23, inodesMin: 7, inodesMax: 9 + 6 });
  assert.deepEqual(need.filesystem, { blocks: 85 + 6, inodesMin: 7, inodesMax: 15 + 6 });
  // Really made at most: 15 + run + owner + two class directories = 19, between the bounds.
  assert.ok(need.filesystem.inodesMin <= 19 && 19 <= need.filesystem.inodesMax);
  assert.equal(spaceVerdict(need, [fsys(1000, 19)]).verdict, "cant_tell");
  assert.equal(spaceVerdict(need, [fsys(1000, 21)]).verdict, "fits");
});

test("another block size makes the bound no proof: can't tell, never fits", () => {
  const v = spaceVerdict(needOf([usage({ inodes: 1, peak_inodes: 1, blocks_upper: 1, peak_blocks_upper: 1 })]), [project(1_000_000, 100), { ...fsys(1_000_000, 100), blockSize: 1024 }]);
  assert.equal(v.verdict, "cant_tell");
  assert.match(v.why, /1024-byte blocks/);
  assert.equal(BLOCK, 4096);
});

test("refusals: no usage, a usage that isn't one, a bad need or limit", () => {
  const u = usage({ inodes: 5, peak_inodes: 7, blocks_upper: 20, peak_blocks_upper: 30 });
  for (const bad of [[], null, [{}], [{ ...u, peak_inodes: 4 }], [{ ...u, peak_blocks_upper: 19 }], [{ ...u, block_size: 512 }], [{ ...u, peak_inodes: -1 }]]) {
    assert.throws(() => needOf(bad), (e) => e.code === "bad_form", JSON.stringify(bad));
  }
  const need = needOf([u]);
  for (const [n, limits] of [
    [null, [project(1, 1)]], [{ project: need.project }, [project(1, 1)]],
    [{ ...need, project: { ...need.project, inodesMin: 9, inodesMax: 8 } }, [project(1, 1)]],
    [need, []], [need, [{ ...project(1, 1), kind: "tag" }]], [need, [{ ...project(1, 1), what: 1 }]], [need, [project(-1, 1)]],
  ]) assert.throws(() => spaceVerdict(n, limits), (e) => e.code === "bad_form");
});

test("one long symlink: moved, not made anew, so its peak is its final count; the boundary at 5 inodes", () => {
  // usage of a class holding one 200-byte symlink: 1 inode at the end and at the peak; its block once.
  const need = needOf([usage({ inodes: 1, peak_inodes: 1, blocks_upper: 5, peak_blocks_upper: 9 })]);
  assert.deepEqual([need.project.inodesMin, need.project.inodesMax], [1, 5], "max(1 + 4 staged, 1 + 3 filled)");
  assert.equal(spaceVerdict(need, [project(1000, 5)]).verdict, "fits");
  assert.equal(spaceVerdict(need, [project(1000, 4)]).verdict, "cant_tell");
  assert.equal(spaceVerdict(need, [project(1000, 0)]).verdict, "doesnt_fit");
});
