// Host backup, wiring r0.4 §1.2 with amendment A3 (r1), and the config tree design d2r1, d2r2, d2r5 and d2r6: each
// live agent's config entry in the manifest is PROVEN from the agent's COMMITTED snapshot alone. The live tree is never
// read, so there is no race between the save and the live tree.
//
// The binary's `tree` op lists the saved `agent-config/<id>` page by page (each page bounded, the cursor bound to the
// snapshot and path), and the listing is judged by agent-config's own reader rules (readTreeAt, listGeneration), so a
// save is either exactly what the restore's reader accepts and hashes, or `config_unbound`:
// - the root (the backup source's own node, stored with synthesized metadata and never restored, d2r6): a directory;
// - its direct entries only `current` (a regular file, root's, 0600, nlink 1, at most 64 bytes), `gen-<n>` directories
//   (at most MAX_GENERATIONS), at most one `.gen-<n>.tmp` (a directory, never descended) and `.current.tmp` (a regular
//   file like `current`, or a link);
// - beneath a generation: directories root's (gid 0 when root) 0700, regular files root's 0600, nothing else; each
//   directory walked at depth at most MAX_DEPTH, each path at most MAX_PATH_BYTES, per generation at most MAX_FILES
//   files and MAX_BYTES bytes; the generation's listing rebuilt and hashed exactly as listGeneration does;
// - `current`'s text (by `dump`, its digest checked against the listing) exactly "gen-<n>\n" naming a saved generation;
//   no `current` exactly when no generation; the entry is that generation's hash, or EMPTY_CONFIG_HASH (A3r1).
// An EMPTY source isn't saved at all (d2r7, d2r8): the binary answers `tree_absent`. That proves the empty tree only
// when the committed snapshot's own record carries the binary's strict mark (every walk error failed the backup, so
// nothing was silently left out) AND names this source exactly in its `paths` (it existed when the backup ran);
// any other absence is `config_unbound`.
// Memory: the walk is depth first, so a generation's entries arrive contiguously; only the generation being read is
// held, then hashed and dropped (no more than the reader itself holds for the same tree).
// Failures: a structural one (a rule above, a page breaking continuity, the binary's `tree_refused`) is
// `config_unbound`; a transport one (`tree_failed`, `timed_out`, ...) keeps its own code, transient, retried by the
// next run; a lost lock stays `lock_lost`.

import { createHash } from "node:crypto";
import { EMPTY_CONFIG_HASH, MAX_BYTES, MAX_DEPTH, MAX_FILES, MAX_GENERATIONS, MAX_PATH_BYTES, CURRENT_TMP, GEN_TMP, generationHash } from "./agent-config.mjs";
import { agentConfigDir } from "./names.mjs";
import { STRICT_MARK } from "./backup-binary.mjs";

/** Each `tree` page's deadline (d2r1 §0.5): enough for the page's bounded hashing. */
export const TREE_PAGE_MS = 10 * 60 * 1000;
const GEN = /^gen-(0|[1-9][0-9]{0,7})$/;
const CURRENT = /^gen-(0|[1-9][0-9]{0,7})\n$/;
const sha256 = (b) => createHash("sha256").update(b).digest("hex");
const MODE_DIR = 0o700, MODE_FILE = 0o600;
const ABSENT = Symbol("absent");

/** A structural failure: the save isn't provably what the restore accepts. */
const unbound = (why) => { throw Object.assign(new Error(`backup config: ${why}`), { code: "config_unbound" }); };
/** A transport failure, with its own code (the next run retries). */
const transient = (code) => { throw Object.assign(new Error(`backup config: the listing failed (${code})`), { code }); };

/**
 * The fold of a listing, entry by entry (configFromListing). `uid`: root's. `add(entry)` judges one entry; `finish()`
 * resolves the tree's shape: { current: { sha256 } | null, generations: Map n -> hash }.
 */
export function configFold({ uid = 0 } = {}) {
  let root = false, open = null, genTmp = false, currentEntry = null;
  const generations = new Map();
  const dirOk = (e) => e.type === "dir" && e.uid === uid && (uid !== 0 || e.gid === 0) && e.mode === MODE_DIR;
  const fileOk = (e) => e.type === "file" && e.uid === uid && e.mode === MODE_FILE;
  const close = () => {
    if (open === null) return;
    open.entries.sort((x, y) => Buffer.compare(Buffer.from(x.path, "utf8"), Buffer.from(y.path, "utf8")));
    generations.set(open.n, generationHash(open.entries));
    open = null;
  };
  return {
    add(e) {
      if (!root) {
        if (e.path !== "" || e.type !== "dir") unbound("the saved tree's root isn't a directory");
        root = true;
        return;
      }
      const slash = e.path.indexOf("/");
      const top = slash < 0 ? e.path : e.path.slice(0, slash);
      if (slash < 0) {
        close(); // (a new direct entry: the generation before it is complete)
        const g = GEN.exec(top);
        if (g) {
          if (!dirOk(e)) unbound(`${top} isn't root's 0700 directory`);
          if (generations.has(g[1]) || generations.size >= MAX_GENERATIONS) unbound("more generations than kept");
          open = { n: g[1], entries: [], files: 0, bytes: 0 };
        } else if (top === "current") {
          if (!fileOk(e) || e.nlink !== 1 || !(e.size <= 64)) unbound("current isn't root's 0600 single-link file");
          currentEntry = e;
        } else if (GEN_TMP.test(top)) {
          if (e.type !== "dir" || genTmp) unbound("more than one generation in progress, or not a directory");
          genTmp = true;
        } else if (top === CURRENT_TMP) {
          if (e.type !== "symlink" && !(fileOk(e) && e.nlink === 1 && e.size <= 64)) unbound(".current.tmp isn't a regular file or a leftover link");
        } else unbound(`a foreign entry: ${top}`);
        return;
      }
      // Beneath a direct entry: only inside the generation being read (the walk is depth first).
      if (open === null || top !== `gen-${open.n}`) unbound("an entry outside any generation");
      const rel = e.path.slice(slash + 1);
      if (Buffer.byteLength(rel, "utf8") > MAX_PATH_BYTES) unbound("a path is too long");
      if (e.type === "dir") {
        if (rel.split("/").length > MAX_DEPTH) unbound("a generation is too deep");
        if (!dirOk(e)) unbound("a directory isn't root's, exactly 0700");
        open.entries.push({ path: rel, type: "dir", mode: MODE_DIR, size: 0 });
      } else if (e.type === "file") {
        if (!fileOk(e) || typeof e.sha256 !== "string") unbound("a file isn't root's, exactly 0600");
        if (++open.files > MAX_FILES) unbound("a generation has too many files");
        open.bytes += e.size;
        if (open.bytes > MAX_BYTES) unbound("a generation is too large");
        open.entries.push({ path: rel, type: "file", mode: MODE_FILE, size: e.size, sha256: e.sha256 });
      } else unbound(`${rel} is a link or a special file`);
    },
    finish() {
      if (!root) unbound("an empty listing");
      close();
      return { current: currentEntry, generations };
    },
  };
}

/**
 * The config entry of agent `id` from its committed snapshot `snapshot`: EMPTY_CONFIG_HASH or a generation's hash;
 * throws config_unbound (structural), a transport code (transient) or lock_lost. `binary(req, { ms })`: the backup
 * binary (the caller guards it); `record`: the snapshot as the store lists it ({ paths, tags, ... }, or null); `root`:
 * the tree's absolute path (a test seam); `uid`: root's.
 */
export async function proveConfig(id, snapshot, { binary, record = null, root = agentConfigDir(id), uid = 0, ms = TREE_PAGE_MS }) {
  const rel = root.replace(/^\/+/, "");
  const call = async (req) => {
    let r;
    try { r = await binary(req, { ms }); } catch (e) {
      if (e?.code === "lock_lost") throw e;
      transient(typeof e?.code === "string" ? e.code : "outcome_unknown");
    }
    if (r?.ok) return r.value;
    if (r?.code === "tree_absent") return ABSENT;
    if (r?.code === "tree_refused") unbound("the binary refused the listing (structural)");
    return transient(r?.code ?? "outcome_unknown");
  };
  const fold = configFold({ uid });
  const digest = sha256(rel);
  let cursor = null, expect = 0;
  for (;;) {
    const page = await call({ op: "tree", snapshot, path: rel, cursor });
    if (page === ABSENT) {
      // An empty source (never saved), proven only from a strict snapshot that names it exactly.
      const strict = record !== null && record.id === snapshot && Array.isArray(record.tags) && record.tags.includes(STRICT_MARK);
      if (cursor !== null || !strict || !Array.isArray(record.paths) || !record.paths.includes(root)) unbound("the tree isn't in the snapshot, and the snapshot doesn't prove it empty");
      return EMPTY_CONFIG_HASH;
    }
    const { entries, next } = page;
    // d2r2 §A: whole-page continuity; a page that breaks it is structural (d2r5 E1).
    if (entries.length === 0) unbound("an empty page");
    for (const e of entries) {
      if (e.index !== expect) unbound("a page out of order (a gap, a repeat or a reorder)");
      expect += 1;
      fold.add(e);
    }
    if (next === null) break;
    if (next !== `${snapshot}:${digest}:${expect}`) unbound("a cursor that doesn't name the next entry");
    cursor = next;
  }
  const { current, generations } = fold.finish();
  if (current === null) {
    if (generations.size !== 0) unbound("generations with no current");
    return EMPTY_CONFIG_HASH;
  }
  const d = await call({ op: "dump", snapshot, path: `${rel}/current` });
  if (sha256(Buffer.from(d.text, "utf8")) !== current.sha256) unbound("current's text isn't the listed one");
  const m = CURRENT.exec(d.text);
  if (m === null) unbound("current isn't exactly a generation's name");
  if (!generations.has(m[1])) unbound("current names a generation that isn't saved");
  return generations.get(m[1]);
}
