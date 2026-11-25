// Host backup (design: agent-autonomous-host-backup.md r3.3 §5 step 7): does a restore fit, before any staging? Fill's
// own quota (the kernel's, through fill-home's 76) stays the real guard; this check says, before anything is written,
// one of exactly three things:
// - "fits": PROVEN. The need's upper bounds on blocks and inodes fit within every limit that applies.
// - "doesnt_fit": PROVEN, by inodes only: the need's LOWER bound on inodes is over a limit. Without reading the data
//   there is no lower bound on blocks (a sparse file can need far less than its size), so blocks never prove it. The
//   lower bound is the STAGED tree's inodes (usage's `inodes`): every entry the restore makes, whatever its owner, is
//   staged and charged to the class's project before any class is filled (the fill later skips wrong owners, but
//   staging has already charged them), so they all exist at once at the end of staging. Nothing of the staging
//   objects is in it, so no conservative padding ever proves "doesn't fit".
// - "cant_tell": neither. The check refuses, and says what the person can do.
//
// The UPPER bound of each class is the larger of its two phases, with the launcher's own staging objects (launcher
// amendment A2 §3-§4, r3.5), which the tree doesn't know:
// - staged: the staged tree (usage's `inodes`, `blocks_upper`) plus the attempt directory, data, data/<leaf> and the
//   completion marker: 4 inodes, 3 blocks at most (the attempt, data and the marker; data/<leaf>'s blocks are the
//   destination directory's, already in the usage);
// - filled, at its peak: usage's `peak_inodes` and `peak_blocks_upper` (every directory twice; files and symlinks
//   are moved, once) plus the attempt, data and data/<leaf>: 3 inodes, 2 blocks. fill-home unlinks the marker before
//   its first destination write, so the marker never coexists with this peak.
// Both are charged to the class's PROJECT (they carry its project id, set with the inherit flag) and to the
// filesystem. The FILESYSTEM alone is charged the run, owner and class directories (made under .restore, without the
// class's project id): up to 3 inodes and 3 blocks per class, none when an earlier class or set already made them, so
// in the upper bound only (shared parents are never counted short).
// Every class of every set restored together is counted as coexisting: their staging is discarded only once they are
// validated or stopped.
// Dormant: nothing calls it yet.

import { refuse } from "../bytes.mjs";

/** The block size the bound is for, and the filesystem's must be the same. */
export const BLOCK = 4096;
/** The launcher's staging objects per class (see the header): exact inodes and at most these blocks. */
export const STAGING = Object.freeze({
  staged: Object.freeze({ inodes: 4, blocks: 3 }),
  filled: Object.freeze({ inodes: 3, blocks: 2 }),
  parents: Object.freeze({ inodes: 3, blocks: 3 }),
});
/** What the person can do when the check can't tell. */
export const CANT_TELL_OPTIONS = Object.freeze([
  "free space on the host, or raise the agent's disk quota in its grant, then check again",
  "restore fewer agents at once",
]);

const nat = (n) => Number.isSafeInteger(n) && n >= 0;
const isUsage = (u) => u && nat(u.peak_blocks_upper) && nat(u.peak_inodes) && u.block_size === BLOCK
  && nat(u.blocks_upper) && nat(u.inodes) && u.peak_inodes >= u.inodes && u.peak_blocks_upper >= u.blocks_upper;

/**
 * The need of some classes restored together, one usage result per class (an agent's home and sessions for its
 * project; every class of the restore for the filesystem), every class counted as coexisting at its larger phase.
 * Returns { project: { blocks, inodesMin, inodesMax }, filesystem: { blocks, inodesMin, inodesMax } }: upper bounds on
 * blocks and inodes, and the staged trees' inodes as the lower bound.
 */
export function needOf(usages) {
  if (!Array.isArray(usages) || usages.length === 0) refuse("bad_form", "restore space: no usage");
  const project = { blocks: 0, inodesMin: 0, inodesMax: 0 }, filesystem = { blocks: 0, inodesMin: 0, inodesMax: 0 };
  for (const u of usages) {
    if (!isUsage(u)) refuse("bad_form", "restore space: not a usage result");
    const blocks = Math.max(u.blocks_upper + STAGING.staged.blocks, u.peak_blocks_upper + STAGING.filled.blocks);
    const inodes = Math.max(u.inodes + STAGING.staged.inodes, u.peak_inodes + STAGING.filled.inodes);
    project.blocks += blocks; project.inodesMin += u.inodes; project.inodesMax += inodes;
    filesystem.blocks += blocks + STAGING.parents.blocks;
    filesystem.inodesMin += u.inodes;
    filesystem.inodesMax += inodes + STAGING.parents.inodes;
  }
  for (const n of [project, filesystem]) if (!Object.values(n).every(nat)) refuse("bad_form", "restore space: too large");
  return { project, filesystem };
}

/**
 * The verdict for `need` (needOf's) against `limits`: [{ what, kind: "project" | "filesystem", blocks, inodes,
 * blockSize }], the free blocks and inodes of each limit that applies (a project quota's room left, the
 * filesystem's available space), in blocks of `blockSize`. Each limit is held to its own kind's need.
 * Returns { verdict: "fits" } | { verdict: "doesnt_fit", why } | { verdict: "cant_tell", why, options }.
 */
export function spaceVerdict(need, limits) {
  const okNeed = (n) => n && nat(n.blocks) && nat(n.inodesMin) && nat(n.inodesMax) && n.inodesMin <= n.inodesMax;
  if (!need || !okNeed(need.project) || !okNeed(need.filesystem)) refuse("bad_form", "restore space: bad need");
  if (!Array.isArray(limits) || limits.length === 0) refuse("bad_form", "restore space: no limits");
  for (const l of limits) {
    if (!l || typeof l.what !== "string" || !["project", "filesystem"].includes(l.kind) || !nat(l.blocks) || !nat(l.inodes) || !nat(l.blockSize)) {
      refuse("bad_form", "restore space: bad limit");
    }
  }
  // Inodes: the lower bound over a limit is proven.
  const over = limits.find((l) => need[l.kind].inodesMin > l.inodes);
  if (over) return { verdict: "doesnt_fit", why: `at least ${need[over.kind].inodesMin} inodes needed, ${over.inodes} free in ${over.what}` };
  const cant = (why) => ({ verdict: "cant_tell", why, options: [...CANT_TELL_OPTIONS] });
  // The block bound is in 4 KiB blocks; another block size makes it no proof.
  const other = limits.find((l) => l.blockSize !== BLOCK);
  if (other) return cant(`${other.what} has ${other.blockSize}-byte blocks; the bound is for ${BLOCK}`);
  const many = limits.find((l) => need[l.kind].inodesMax > l.inodes);
  if (many) return cant(`up to ${need[many.kind].inodesMax} inodes may be needed, ${many.inodes} free in ${many.what}`);
  const short = limits.find((l) => need[l.kind].blocks > l.blocks);
  if (short) return cant(`up to ${need[short.kind].blocks} blocks may be needed, ${short.blocks} free in ${short.what}`);
  return { verdict: "fits" };
}
