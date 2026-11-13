// The Codex this agent runs: one pinned upstream release (lib/codex-pin.json, from the review packet), never the
// `codex` on PATH. On first use it's downloaded from the npm registry (the platform tarball: the same bytes as
// OpenAI's GitHub release and the Homebrew cask), checked against the pin, unpacked here (not by tar(1)) into a
// private cache, and checked again, every file, at every start. It runs with the person's own Codex login and
// settings (CODEX_HOME): nothing here reads, copies or changes them.
//
// Out of scope: someone who can already write the person's files or this process; the cache is not an OS boundary.

import { createHash, randomBytes } from "node:crypto";
import { chmodSync, closeSync, constants as C, fchmodSync, fsyncSync, lstatSync, mkdirSync, mkdtempSync, openSync, readdirSync, readFileSync, readSync, renameSync, rmSync, writeSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, sep } from "node:path";
import { createGunzip } from "node:zlib";

export const PIN = JSON.parse(readFileSync(new URL("./codex-pin.json", import.meta.url), "utf8"));
export const FETCH = {
  totalMs: 10 * 60 * 1000, // the whole download
  idleMs: 60 * 1000, // no bytes for this long: given up
  redirects: 3,
  hosts: ["registry.npmjs.org"], // where the archive and its redirects may be
  progressEvery: 16 * 1024 * 1024, // bytes between progress reports
};
const BLOCK = 512;
const PAX_MAX = 8 * 1024; // one extended header's data
const TAIL_MAX = 20 * BLOCK; // what may follow the end-of-archive blocks (tar's own record padding)
const NOFOLLOW = C.O_NOFOLLOW ?? 0;

/** This computer's platform as the pin names it ("linux-x64"), or null where there's no Codex for it here. */
export function platformKey(platform = process.platform, arch = process.arch) {
  const k = `${platform}-${arch}`;
  return ["linux-x64", "linux-arm64", "darwin-x64", "darwin-arm64"].includes(k) ? k : null;
}

/** Where pinned Codex releases are kept: ~/Library/Caches/sagebrush-agent/codex on macOS, else $XDG_CACHE_HOME (absolute)
 *  or ~/.cache, then sagebrush-agent/codex. */
export function cacheRoot(env = process.env, platform = process.platform, home = homedir()) {
  const xdg = env.XDG_CACHE_HOME;
  const base = platform === "darwin" ? join(home, "Library", "Caches") : xdg && xdg.startsWith(sep) ? xdg : join(home, ".cache");
  return join(base, "sagebrush-agent", "codex");
}

export class CodexFetchError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}
const cut = (s, n = 120) => (s.length > n ? s.slice(0, n) + "…" : s);

// ---- the cache's own directories: real, private, ours

// (sagebrush-agent/ and sagebrush-agent/codex/: made 0700 if missing; lstat'ed, so a symlink is "not a directory":
//  refused, as is another owner)
function privateDirs(root) {
  for (const d of [dirname(root), root]) {
    try { mkdirSync(d, { mode: 0o700 }); } catch (e) { if (e.code !== "EEXIST") throw e; }
    const s = lstatSync(d);
    if (!s.isDirectory() || !ours(s) || (s.mode & 0o077)) throw new CodexFetchError("codex_cache", "the Codex cache directory isn't a private directory of this account");
  }
}

// (owned by this account; on systems without uids, by whoever runs this)
const ours = (s) => !process.getuid || s.uid === process.getuid();
// (the exact mode a manifest file has, whatever the umask was when it was written)
const FILE_MODE = (f) => (f.exec ? 0o755 : 0o644);

// (a directory this fetch made with mkdtemp: removed only while it's still a real directory)
function removeOwnTemp(dir) {
  try { if (lstatSync(dir).isDirectory()) rmSync(dir, { recursive: true, force: true }); } catch {}
}

// ---- checking a tree against the pin's manifest

function sha256File(file) {
  const h = createHash("sha256");
  const fd = openSync(file, C.O_RDONLY | NOFOLLOW);
  try {
    const buf = Buffer.allocUnsafe(1 << 20);
    for (let n; (n = readSync(fd, buf, 0, buf.length, null)); ) h.update(buf.subarray(0, n));
  } finally { closeSync(fd); }
  return h.digest("hex");
}

/** Whether `dir` is exactly the manifest: every directory and file lstat'ed (no link followed), each file regular,
 *  of its size, mode (executable or not, never group/other-writable) and sha256, and nothing else in the tree. */
export function treeMatches(dir, files) {
  const dirs = new Set([""]);
  for (const rel of Object.keys(files)) { const parts = rel.split("/"); for (let i = 1; i < parts.length; i++) dirs.add(parts.slice(0, i).join("/")); }
  try {
    const walk = (rel) => {
      const s = lstatSync(rel ? join(dir, rel) : dir);
      // (lstat: a link is never a directory here; every directory private and ours)
      if (!s.isDirectory() || !ours(s) || (s.mode & 0o7777) !== 0o700) return false;
      for (const name of readdirSync(rel ? join(dir, rel) : dir)) {
        const r = rel ? `${rel}/${name}` : name;
        if (dirs.has(r)) { if (!walk(r)) return false; continue; }
        const f = files[r];
        if (!f) return false; // (anything not in the manifest)
        const fs = lstatSync(join(dir, r));
        if (!fs.isFile() || fs.size !== f.size) return false;
        if (!ours(fs) || (fs.mode & 0o7777) !== FILE_MODE(f)) return false; // (exactly, special bits included)
      }
      return true;
    };
    if (!walk("")) return false;
    for (const [rel, f] of Object.entries(files)) if (sha256File(join(dir, rel)) !== f.sha256) return false;
    return true;
  } catch { return false; }
}

// ---- reading a tar stream: only the manifest's members, as data

/** A member's path relative to the package root, or null if it can't be one of ours. */
export function memberPath(name, root = "package/") {
  if (!name.startsWith(root)) return null;
  const rel = name.slice(root.length);
  if (!rel || rel.includes("\\") || rel.split("/").some((x) => x === "" || x === "." || x === "..")) return null;
  return rel;
}

const field = (h, off, len) => { const s = h.subarray(off, off + len); const z = s.indexOf(0); return (z >= 0 ? s.subarray(0, z) : s).toString("utf8"); };
const octal = (h, off, len) => { const s = field(h, off, len).trim(); return /^[0-7]{1,12}$/.test(s) ? parseInt(s, 8) : NaN; };
const padded = (n) => Math.ceil(n / BLOCK) * BLOCK;

// (a member's directories under `root`, each made 0700 exactly, whatever the umask)
function makeDirs(root, rel) {
  if (rel === "." || rel === "") return;
  let at = root;
  for (const part of rel.split("/")) {
    at = join(at, part);
    try { mkdirSync(at, { mode: 0o700 }); chmodSync(at, 0o700); } catch (e) { if (e.code !== "EEXIST") throw e; }
  }
}

/** The bounds for one manifest's archive: headers (a file's own, maybe a path extension, its directories), and every
 *  byte the gunzip may give (payloads padded, headers, extension data, the end blocks and their padding). */
export function archiveBounds(files) {
  const n = Object.keys(files).length;
  const dirs = new Set();
  for (const rel of Object.keys(files)) { const parts = rel.split("/"); for (let i = 1; i < parts.length; i++) dirs.add(parts.slice(0, i).join("/")); }
  const headers = 2 * n + dirs.size + 1;
  const bytes = Object.values(files).reduce((a, f) => a + padded(f.size), 0) + headers * BLOCK + n * padded(PAX_MAX) + 2 * BLOCK + TAIL_MAX;
  return { headers, bytes };
}

/**
 * A sink for a gunzipped tar stream that writes the manifest's members into `dir` (or, with `files` null, every
 * regular file, to make a manifest). Anything else fails it: an unexpected, duplicate or missing member, another
 * size or other bytes, a link, device, global or unknown header, a path outside the package root, too many headers
 * or bytes, or an archive that ends early. Holds at most one chunk plus a block; extension data at most PAX_MAX.
 */
export function tarSink(dir, files, bounds = files ? archiveBounds(files) : { headers: 100000, bytes: 4 * 2 ** 30 }) {
  let buf = Buffer.alloc(0);
  let cur = null; // a member being read: {rel, left, fd, hash, size, exec} or {pax, left, data}
  let pad = 0, pax = null, zeros = 0, done = false, headers = 0, bytes = 0;
  const seen = {};
  const fail = (why) => { throw new CodexFetchError("codex_archive", `the Codex archive isn't as pinned: ${cut(why)}`); };
  const open = (rel, size, mode) => {
    const want = files ? files[rel] : null;
    if (files && !want) fail(`unexpected member ${rel}`);
    if (want && want.size !== size) fail(`${rel} has another size`);
    if (seen[rel] || cur?.rel === rel) fail(`${rel} appears twice`);
    const p = join(dir, rel);
    makeDirs(dir, dirname(rel));
    const exec = want ? !!want.exec : (mode & 0o111) !== 0;
    const fd = openSync(p, C.O_WRONLY | C.O_CREAT | C.O_EXCL | NOFOLLOW, exec ? 0o755 : 0o644);
    fchmodSync(fd, exec ? 0o755 : 0o644); // (exactly, whatever the umask)
    cur = { rel, left: size, fd, hash: createHash("sha256"), size, exec };
  };
  const closeMember = () => {
    fsyncSync(cur.fd);
    closeSync(cur.fd);
    const sha = cur.hash.digest("hex");
    if (files && files[cur.rel].sha256 !== sha) fail(`${cur.rel} has other bytes`);
    seen[cur.rel] = { size: cur.size, sha256: sha, ...(cur.exec ? { exec: true } : {}) };
    pad = padded(cur.size) - cur.size;
    cur = null;
  };
  const header = (h) => {
    if (h.every((b) => b === 0)) { if (++zeros >= 2) done = true; return; }
    if (zeros) fail("a header after an empty block");
    if (++headers > bounds.headers) fail("too many members");
    const type = String.fromCharCode(h[156] || 48);
    const size = octal(h, 124, 12);
    if (!Number.isFinite(size)) fail("a bad header");
    const name = pax ?? ((field(h, 345, 155) ? field(h, 345, 155) + "/" : "") + field(h, 0, 100));
    pax = null;
    if (type === "x") { if (size > PAX_MAX) fail("a long extension"); cur = { pax: true, left: size, size, data: [] }; return; }
    if (type === "5") { if (size) fail("a directory with data"); if (name !== "package/" && !memberPath(name.replace(/\/$/, ""))) fail(`directory ${JSON.stringify(cut(name))}`); return; }
    if (type !== "0") fail(`member type ${JSON.stringify(type)}`);
    const rel = memberPath(name);
    if (!rel) fail(`member path ${JSON.stringify(cut(name))}`);
    open(rel, size, octal(h, 100, 8));
  };
  return {
    write(chunk) {
      bytes += chunk.length;
      if (bytes > bounds.bytes) fail("too large");
      if (done) { return; } // (the record padding after the end blocks: counted, not read)
      buf = buf.length ? Buffer.concat([buf, chunk]) : chunk;
      for (;;) {
        if (pad) { const n = Math.min(pad, buf.length); pad -= n; buf = buf.subarray(n); if (pad) return; }
        if (cur) {
          const n = Math.min(cur.left, buf.length);
          if (cur.pax) cur.data.push(Buffer.from(buf.subarray(0, n)));
          else { writeSync(cur.fd, buf, 0, n); cur.hash.update(buf.subarray(0, n)); }
          cur.left -= n;
          buf = buf.subarray(n);
          if (cur.left) return;
          if (cur.pax) {
            const text = Buffer.concat(cur.data).toString("utf8");
            for (const rec of text.split("\n").filter(Boolean)) {
              const m = /^\d+ ([a-zA-Z.]+)=/.exec(rec);
              if (!m) fail("a bad extension");
              if (m[1] === "path") pax = rec.slice(m[0].length);
              else if (!["mtime", "atime", "ctime"].includes(m[1])) fail(`extension ${m[1]}`);
            }
            pad = padded(cur.size) - cur.size;
            cur = null;
          } else closeMember();
          continue;
        }
        if (buf.length < BLOCK) return;
        const h = buf.subarray(0, BLOCK);
        buf = buf.subarray(BLOCK);
        header(h);
        if (done) { buf = Buffer.alloc(0); return; }
      }
    },
    end() {
      if (cur || !done || pax) fail("it ends early");
      if (files) for (const rel of Object.keys(files)) if (!seen[rel]) fail(`${rel} is missing`);
      return seen;
    },
    abort() { if (cur && !cur.pax) { try { closeSync(cur.fd); } catch {} } cur = null; },
  };
}

// ---- downloading

/** The archive at `url`, streamed through `onData`, within the pin's size and FETCH's bounds; returns its sha256. */
export async function download(url, { size, onData, onProgress, signal, fetchFn = fetch, limits = FETCH } = {}) {
  const ac = new AbortController();
  let why = null;
  const stop = (w) => () => { why ??= w; ac.abort(); };
  const onStop = stop("stopped");
  signal?.addEventListener("abort", onStop, { once: true });
  if (signal?.aborted) onStop();
  // (a write that waits while the download is stopped or times out ends with it)
  const stopped = new Promise((_, rej) => ac.signal.addEventListener("abort", () => rej(new CodexFetchError("codex_download", why ?? "stopped")), { once: true }));
  stopped.catch(() => {});
  const total = setTimeout(stop("it took too long"), limits.totalMs);
  let idle = setTimeout(stop("it took too long"), limits.idleMs);
  try {
    let r, at = url;
    for (let hop = 0; ; hop++) {
      const u = new URL(at);
      if (u.protocol !== "https:" || !limits.hosts.includes(u.hostname)) throw new CodexFetchError("codex_download", `not downloaded from ${u.host}: only ${limits.hosts.join(", ")} over https`);
      r = await fetchFn(u.href, { redirect: "manual", signal: ac.signal, headers: { accept: "application/octet-stream" } });
      const to = r.status >= 300 && r.status < 400 ? r.headers.get("location") : null;
      if (!to) break;
      if (hop >= limits.redirects) throw new CodexFetchError("codex_download", "too many redirects");
      at = new URL(to, u).href;
    }
    if (!r.ok) throw new CodexFetchError("codex_download", `HTTP ${r.status}`);
    const len = Number(r.headers.get("content-length") ?? NaN);
    if (Number.isFinite(len) && len !== size) throw new CodexFetchError("codex_archive", "the archive has another size than pinned");
    const h = createHash("sha256");
    let got = 0, told = 0;
    for await (const chunk of r.body) {
      clearTimeout(idle);
      idle = setTimeout(stop("it took too long"), limits.idleMs);
      got += chunk.length;
      if (got > size) throw new CodexFetchError("codex_archive", "the archive is larger than pinned");
      const b = Buffer.from(chunk);
      h.update(b);
      await Promise.race([onData(b), stopped]);
      if (onProgress && got - told >= limits.progressEvery) { told = got; onProgress(got, size); }
    }
    if (got !== size) throw new CodexFetchError("codex_archive", "the archive is shorter than pinned");
    return h.digest("hex");
  } catch (e) {
    if (e instanceof CodexFetchError) throw e;
    throw new CodexFetchError("codex_download", why ?? "the connection failed"); // (fixed words: never the error's own text)
  } finally {
    clearTimeout(total);
    clearTimeout(idle);
    signal?.removeEventListener("abort", onStop);
  }
}

// (gunzip, then the tar sink, chunk by chunk with backpressure; end() resolves once the gunzip has drained)
function unpacker(sink) {
  const gz = createGunzip();
  let error = null;
  const fail = (e) => { error ??= e; };
  const done = new Promise((resolve, reject) => {
    gz.on("data", (d) => { if (error) return; try { sink.write(d); } catch (e) { fail(e); gz.destroy(); } });
    gz.on("end", resolve);
    gz.on("error", () => { fail(new CodexFetchError("codex_archive", "the archive isn't gzip")); });
    gz.on("close", () => { if (error) reject(error); });
  });
  done.catch(() => {});
  // (a write waits for the gunzip to take more, or for it to end in an error, a close or an abort: never forever)
  const write = (chunk) => new Promise((res, rej) => {
    if (error || gz.destroyed) return rej(error ?? new CodexFetchError("codex_archive", "the archive couldn't be read"));
    if (gz.write(chunk)) return res();
    const off = () => { gz.off("drain", ok); gz.off("close", bad); };
    const ok = () => { off(); res(); };
    const bad = () => { off(); rej(error ?? new CodexFetchError("codex_archive", "the archive couldn't be read")); };
    gz.on("drain", ok);
    gz.on("close", bad);
  });
  return {
    write,
    end: async () => { gz.end(); await done; if (error) throw error; return sink.end(); },
    abort: () => { fail(new CodexFetchError("codex_download", "stopped")); gz.destroy(); sink.abort(); },
  };
}

/** Download and unpack one pinned platform entry into a fresh temp dir under `root`; returns it, checked. */
export async function fetchInto(root, entry, opts = {}) {
  const temp = mkdtempSync(join(root, ".fetch-"));
  const u = unpacker(tarSink(temp, entry.files));
  try {
    const sha = await download(entry.url, { size: entry.size, onData: (c) => u.write(c), ...opts });
    if (sha !== entry.sha256) throw new CodexFetchError("codex_archive", "the archive has other bytes than pinned");
    await u.end();
    if (!treeMatches(temp, entry.files)) throw new CodexFetchError("codex_archive", "the unpacked Codex isn't as pinned");
    return temp;
  } catch (e) {
    u.abort();
    removeOwnTemp(temp);
    throw e;
  }
}

/**
 * The pinned Codex, ready to run: its verified directory and the absolute path of its `codex`. Fetched the first
 * time; a cached copy that no longer matches is moved aside and fetched once more; otherwise a CodexFetchError.
 */
export async function ensureCodex({ env = process.env, pin = PIN, root = cacheRoot(env), platform = platformKey(), signal, onProgress, fetchFn } = {}) {
  const entry = platform && pin.platforms?.[platform];
  if (!entry) throw new CodexFetchError("codex_platform", "no pinned Codex for this platform");
  privateDirs(root);
  const final = join(root, `${pin.version}-${platform}`);
  const ready = () => ({ dir: final, bin: join(final, entry.bin), version: pin.version });
  const present = () => { try { lstatSync(final); return true; } catch { return false; } };
  if (present()) {
    if (treeMatches(final, entry.files)) return ready();
    // (not what was pinned: moved aside, never deleted, since it may not be what we made)
    try { renameSync(final, `${final}.bad-${randomBytes(4).toString("hex")}`); } catch { throw new CodexFetchError("codex_cache", "the cached Codex doesn't match its pin and can't be moved aside"); }
  }
  const temp = await fetchInto(root, entry, { signal, onProgress, fetchFn });
  try { renameSync(temp, final); } catch (e) {
    // (another agent promoted one first: kept if it matches, never replaced; ours goes)
    removeOwnTemp(temp);
    if (!present()) throw new CodexFetchError("codex_cache", "the fetched Codex couldn't be put in place");
  }
  if (!treeMatches(final, entry.files)) throw new CodexFetchError("codex_archive", "the cached Codex doesn't match its pin");
  return ready();
}
