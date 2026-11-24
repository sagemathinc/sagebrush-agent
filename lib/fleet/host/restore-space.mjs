// Host backup (design: agent-autonomous-host-backup.md r3.3 §5 step 7): does a restore fit, before any staging? Fill's
// own quota (the kernel's, through fill-home's 76) stays the real guard; this check says, before anything is written,
// one of exactly three things:
// - "fits": PROVEN. The backup binary's `usage` (backup/src/ops.rs, from the tree's metadata only) gives an upper bound
//   on the blocks a restore can charge and the exact number of inodes; both fit within every limit that applies (the
//   set's project quota and the filesystem's free space).
// - "doesnt_fit": PROVEN, by the inode count only (exact). Without reading the data there is no lower bound on blocks: a
//   sparse file can need far less than its size, so blocks never prove "doesn't fit".
// - "cant_tell": neither. The check refuses, and says what the person can do.
// Dormant: nothing calls it yet.

import { refuse } from "../bytes.mjs";

/** The block size the bound is for, and the filesystem's must be the same. */
export const BLOCK = 4096;
/** What the person can do when the check can't tell. */
export const CANT_TELL_OPTIONS = Object.freeze([
  "free space on the host, or raise the agent's disk quota in its grant, then check again",
  "restore fewer agents at once",
]);

const nat = (n) => Number.isSafeInteger(n) && n >= 0;

/** The need of several usage results together (an agent's classes, or a whole restore on one filesystem). */
export function sumUsage(usages) {
  if (!Array.isArray(usages) || usages.length === 0) refuse("bad_form", "restore space: no usage");
  let blocks = 0, inodes = 0;
  for (const u of usages) {
    if (!u || !nat(u.blocks_upper) || !nat(u.inodes) || u.block_size !== BLOCK) refuse("bad_form", "restore space: not a usage result");
    blocks += u.blocks_upper;
    inodes += u.inodes;
  }
  if (!nat(blocks) || !nat(inodes)) refuse("bad_form", "restore space: too large");
  return { blocks, inodes };
}

/**
 * The verdict for `need` ({ blocks, inodes }, sumUsage's) against `limits`: [{ what, blocks, inodes, blockSize }], the
 * free blocks and inodes of each limit that applies (a project quota's room left, the filesystem's available space),
 * in blocks of `blockSize`. Returns { verdict: "fits" } | { verdict: "doesnt_fit", why } | { verdict: "cant_tell",
 * why, options }.
 */
export function spaceVerdict(need, limits) {
  if (!need || !nat(need.blocks) || !nat(need.inodes)) refuse("bad_form", "restore space: bad need");
  if (!Array.isArray(limits) || limits.length === 0) refuse("bad_form", "restore space: no limits");
  for (const l of limits) {
    if (!l || typeof l.what !== "string" || !nat(l.blocks) || !nat(l.inodes) || !nat(l.blockSize)) refuse("bad_form", "restore space: bad limit");
  }
  // The inode count is exact: over any limit is proven.
  const over = limits.find((l) => need.inodes > l.inodes);
  if (over) return { verdict: "doesnt_fit", why: `${need.inodes} inodes needed, ${over.inodes} free in ${over.what}` };
  // The block bound is in 4 KiB blocks; another block size makes it no proof.
  const other = limits.find((l) => l.blockSize !== BLOCK);
  if (other) return { verdict: "cant_tell", why: `${other.what} has ${other.blockSize}-byte blocks; the bound is for ${BLOCK}`, options: [...CANT_TELL_OPTIONS] };
  const short = limits.find((l) => need.blocks > l.blocks);
  if (short) return { verdict: "cant_tell", why: `up to ${need.blocks} blocks may be needed, ${short.blocks} free in ${short.what}`, options: [...CANT_TELL_OPTIONS] };
  return { verdict: "fits" };
}
