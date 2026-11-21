// The Delegate runner's Deno and engine (lib/runner-pin.json): each one pinned npm tarball, fetched by the same
// reviewed path as the pinned Codex (lib/codex-fetch.mjs: https to registry.npmjs.org only, bounded download and
// unpack, only the manifest's regular files, an atomic install into a private cache), and checked again, every file,
// at every use.  Never a `deno` or `sagebrush` on PATH or in node_modules/.bin.  Nothing here runs either of them.

import { randomBytes } from "node:crypto";
import { lstatSync, mkdirSync, readFileSync, renameSync, rmSync } from "node:fs";
import { homedir } from "node:os";
import { join, sep } from "node:path";
import { CodexFetchError, fetchInto, platformKey, treeMatches } from "./codex-fetch.mjs";

export const RUNNER_PIN = JSON.parse(readFileSync(new URL("./runner-pin.json", import.meta.url), "utf8"));

/** Where the runner's pinned files are kept: as the Codex cache, with runner/ in place of codex/. */
export function runnerCacheRoot(env = process.env, platform = process.platform, home = homedir()) {
  const xdg = env.XDG_CACHE_HOME;
  const base = platform === "darwin" ? join(home, "Library", "Caches") : xdg && xdg.startsWith(sep) ? xdg : join(home, ".cache");
  return join(base, "sagebrush-agent", "runner");
}

export class RunnerFetchError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}

// (sagebrush-agent/ and sagebrush-agent/runner/: made 0700 if missing; lstat'ed, so a link is refused, as is a folder
//  of another account or open to others)
function privateDirs(root) {
  for (const d of [join(root, ".."), root]) {
    try { mkdirSync(d, { mode: 0o700 }); } catch (e) { if (e.code !== "EEXIST") throw e; }
    const s = lstatSync(d);
    if (!s.isDirectory() || (process.getuid && s.uid !== process.getuid()) || (s.mode & 0o077)) throw new RunnerFetchError("runner_cache", "the runner's cache folder isn't a private folder of this account");
  }
}

// (the shared fetcher's errors, in the runner's words: its codes kept, "Codex" named as what was fetched)
const reword = (e, what) => (e instanceof CodexFetchError ? new RunnerFetchError(e.code.replace(/^codex_/, "runner_"), e.message.replace(/the (unpacked |cached )?Codex/g, `the $1${what}`).replace(/Codex/g, what)) : e);

/** One pinned entry, ready: its verified folder under `root`, as `name`.  Fetched the first time; a cached copy that
 * no longer matches is moved aside (never deleted: it may not be ours) and fetched once more. */
export async function ensureEntry(root, name, entry, what, { signal, fetchFn } = {}) {
  privateDirs(root);
  const final = join(root, name);
  const present = () => { try { lstatSync(final); return true; } catch { return false; } };
  if (present()) {
    if (treeMatches(final, entry.files)) return final;
    try { renameSync(final, `${final}.bad-${randomBytes(4).toString("hex")}`); } catch { throw new RunnerFetchError("runner_cache", `the cached ${what} doesn't match its pin and can't be moved aside`); }
  }
  let temp;
  try { temp = await fetchInto(root, entry, { signal, fetchFn }); } catch (e) { throw reword(e, what); }
  try { renameSync(temp, final); } catch {
    // (another agent put one in place first: kept if it matches, never replaced; ours goes)
    try { if (lstatSync(temp).isDirectory()) rmSync(temp, { recursive: true, force: true }); } catch {}
    if (!present()) throw new RunnerFetchError("runner_cache", `the fetched ${what} couldn't be put in place`);
  }
  if (!treeMatches(final, entry.files)) throw new RunnerFetchError("runner_archive", `the cached ${what} doesn't match its pin`);
  return final;
}

/** Why runs can't use this computer's pins at all, or null: the platform, and an engine pinned. */
export function pinProblem(pin = RUNNER_PIN, platform = platformKey()) {
  if (!platform || !pin.deno?.platforms?.[platform]) return `runs aren't available on ${process.platform}-${process.arch} in this version`;
  if (!pin.engine) return "no engine with confinement is pinned yet";
  return null;
}

/** The pinned Deno and engine, verified: absolute paths of the `deno` executable and the engine's entry file. */
export async function ensureRunner({ pin = RUNNER_PIN, root = runnerCacheRoot(), platform = platformKey(), signal, fetchFn } = {}) {
  const why = pinProblem(pin, platform);
  if (why) throw new RunnerFetchError("runner_platform", why);
  const d = pin.deno.platforms[platform], e = pin.engine;
  const denoDir = await ensureEntry(root, `deno-${pin.deno.version}-${platform}`, d, "Deno", { signal, fetchFn });
  const engineDir = await ensureEntry(root, `engine-${e.version}`, e, "engine", { signal, fetchFn });
  return { deno: join(denoDir, d.bin), engine: join(engineDir, e.entry), denoDir, engineDir };
}
