// Host backup r3.3 §5 step 7: the space check before any staging says exactly one of three things: "fits" (proven by
// the usage op's upper bound on blocks and its exact inode count, within every limit), "doesnt_fit" (proven by inodes
// only), or "cant_tell" (it refuses, with the person's options). Blocks never prove "doesn't fit": the bound is upper.
import assert from "node:assert/strict";
import { test } from "./host-linux-only.mjs";
import { BLOCK, CANT_TELL_OPTIONS, spaceVerdict, sumUsage } from "../lib/fleet/host/restore-space.mjs";

const usage = (blocks_upper, inodes) => ({ snapshot: "a".repeat(64), entries: inodes, inodes, blocks_upper, block_size: 4096 });
const quota = (blocks, inodes) => ({ what: "the agent's quota", blocks, inodes, blockSize: 4096 });
const fsys = (blocks, inodes) => ({ what: "the filesystem", blocks, inodes, blockSize: 4096 });

test("fits only when the upper bound and the inodes are within every limit", () => {
  const need = sumUsage([usage(1000, 10), usage(500, 5)]);
  assert.deepEqual(need, { blocks: 1500, inodes: 15 });
  assert.deepEqual(spaceVerdict(need, [quota(1500, 15), fsys(10_000, 1000)]), { verdict: "fits" }, "exactly at the limits fits");
  assert.equal(BLOCK, 4096);
});

test("doesnt_fit is proven by the exact inode count, never by blocks", () => {
  const need = { blocks: 1500, inodes: 16 };
  const v = spaceVerdict(need, [quota(1_000_000, 15), fsys(10_000_000, 1000)]);
  assert.deepEqual(v, { verdict: "doesnt_fit", why: "16 inodes needed, 15 free in the agent's quota" });
  assert.equal(spaceVerdict(need, [quota(1_000_000, 100), fsys(10_000, 15)]).verdict, "doesnt_fit", "the filesystem's inodes too");
  // Blocks over a limit: only "can't tell" (a sparse file may need far less than the bound).
  const c = spaceVerdict({ blocks: 1501, inodes: 1 }, [quota(1500, 15), fsys(10_000, 1000)]);
  assert.equal(c.verdict, "cant_tell");
  assert.equal(c.why, "up to 1501 blocks may be needed, 1500 free in the agent's quota");
  assert.deepEqual(c.options, [...CANT_TELL_OPTIONS]);
  assert.equal(spaceVerdict({ blocks: 1501, inodes: 1 }, [quota(100_000, 15), fsys(1500, 1000)]).verdict, "cant_tell", "the filesystem's blocks too");
  // Inodes first: over on inodes is doesnt_fit even when blocks are also over.
  assert.equal(spaceVerdict({ blocks: 9e9, inodes: 99 }, [quota(1, 1)]).verdict, "doesnt_fit");
});

test("another block size makes the bound no proof: can't tell, never fits", () => {
  const v = spaceVerdict({ blocks: 1, inodes: 1 }, [quota(1_000_000, 100), { what: "the filesystem", blocks: 1_000_000, inodes: 100, blockSize: 1024 }]);
  assert.equal(v.verdict, "cant_tell");
  assert.match(v.why, /1024-byte blocks/);
});

test("refusals: no usage, a result that isn't usage's, a bad need or limit", () => {
  for (const u of [[], null, [usage(1, 1), { ...usage(1, 1), block_size: 512 }], [{ ...usage(1, 1), inodes: -1 }], [{ ...usage(1, 1), blocks_upper: 0.5 }]]) {
    assert.throws(() => sumUsage(u), (e) => e.code === "bad_form", JSON.stringify(u));
  }
  for (const [need, limits] of [[null, [quota(1, 1)]], [{ blocks: 1, inodes: -1 }, [quota(1, 1)]], [{ blocks: 1, inodes: 1 }, []], [{ blocks: 1, inodes: 1 }, [{ blocks: 1, inodes: 1, blockSize: 4096 }]], [{ blocks: 1, inodes: 1 }, [quota(-1, 1)]]]) {
    assert.throws(() => spaceVerdict(need, limits), (e) => e.code === "bad_form");
  }
});
