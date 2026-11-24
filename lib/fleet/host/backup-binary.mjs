// Host backup (design: agent-autonomous-host-backup.md r3.3 §1, §6): the client of the `sagebrush-agent-backup` binary.
//
// The binary takes ONE JSON request on stdin and writes ONE JSON object on stdout: `{ ok: true, ... }` or
// `{ ok: false, error: { code, message } }`, with exit status 0 exactly when ok. Secrets never pass through here: the
// binary reads the destination and the host key itself, by path, from the state and secrets directories named in argv.
//
// This module:
// - builds only the closed requests the binary accepts (the same shapes as its own parser), refusing anything else
//   before any process starts;
// - runs it with an empty environment, as the leader of its own process group, and kills the whole group when the
//   call settles (exit, deadline or abort), so nothing it started outlives the call;
// - bounds what it reads: stdout past OUT_MAX, or anything but exactly one JSON object agreeing with the exit status,
//   is `bad_result`; stderr keeps its first ERR_MAX bytes for the audit and the rest is read and dropped;
// - returns `{ ok: true, value }` or `{ ok: false, code, message }`, where a binary's own code is kept only if it is
//   one the binary can give (CODES); a local failure (spawn, deadline, abort, a bad result) has its own code.

import { spawn } from "node:child_process";
import { refuse } from "../bytes.mjs";

/** The binary's error codes (backup/src). Anything else from it is reported as bad_result. */
export const CODES = Object.freeze([
  "add_key_failed", "backup_failed", "capability_refused", "check_failed", "config_invalid", "config_missing",
  "destination_refused", "destination_unavailable", "dump_failed", "forget_failed", "index_failed", "init_failed",
  "list_failed", "no_space", "open_failed", "prune_failed", "quota_exceeded", "readback_failed", "repository_exists",
  "repository_missing", "request_invalid", "restore_failed", "snapshot_missing", "usage",
]);
/** Local failures of a call, never from the binary. */
export const LOCAL_CODES = Object.freeze(["spawn_failed", "timed_out", "aborted", "bad_result"]);
export const OUT_MAX = 32 * 1024 * 1024;
export const ERR_MAX = 64 * 1024;
/** After a kill, how long the call waits for the process to be reaped before it settles anyway. */
const GRACE_MS = 2000;

const SNAPSHOT_ID = /^[0-9a-f]{64}$/;
const TAG = /^[A-Za-z0-9._:-]+=[A-Za-z0-9._:-]+$/;
const absPath = (p) => typeof p === "string" && p.startsWith("/") && !p.includes("\0") && !p.split("/").includes("..");
const relPath = (p) => typeof p === "string" && p.length > 0 && !p.startsWith("/") && !p.includes("\0") && !p.split("/").some((s) => s === ".." || s === "");
const nonEmpty = (s) => typeof s === "string" && s.length > 0 && s.length <= 256 && !/[\0\n,]/.test(s);
const keysOf = (o) => Object.keys(o).sort().join(",");

/**
 * The closed requests, by op: required fields, optional fields, and a check of the whole request. These match the
 * binary's own parser (deny_unknown_fields), so a request this refuses is one the binary would refuse too.
 */
const OPS = Object.freeze({
  init: { req: [], opt: [], ok: () => true },
  "add-key": { req: ["password_file"], opt: [], ok: (r) => absPath(r.password_file) },
  backup: {
    req: ["sources", "host"], opt: ["tags", "parent", "excludes"],
    ok: (r) => Array.isArray(r.sources) && r.sources.length > 0 && r.sources.length <= 1024 && r.sources.every(absPath)
      && nonEmpty(r.host)
      && (r.tags === undefined || (Array.isArray(r.tags) && r.tags.length <= 64 && r.tags.every((t) => typeof t === "string" && TAG.test(t))))
      && (r.parent === undefined || r.parent === null || SNAPSHOT_ID.test(r.parent))
      && (r.excludes === undefined || (Array.isArray(r.excludes) && r.excludes.length <= 1024 && r.excludes.every(nonEmpty))),
  },
  readback: { req: ["snapshot"], opt: [], ok: (r) => SNAPSHOT_ID.test(r.snapshot) },
  "check-data": { req: ["part", "of"], opt: [], ok: (r) => Number.isInteger(r.of) && r.of >= 1 && r.of <= 1000 && Number.isInteger(r.part) && r.part >= 1 && r.part <= r.of },
  snapshots: { req: [], opt: [], ok: () => true },
  dump: { req: ["snapshot", "path"], opt: [], ok: (r) => SNAPSHOT_ID.test(r.snapshot) && relPath(r.path) },
  forget: { req: ["snapshots"], opt: [], ok: (r) => Array.isArray(r.snapshots) && r.snapshots.length > 0 && r.snapshots.length <= 10000 && r.snapshots.every((s) => SNAPSHOT_ID.test(s)) && new Set(r.snapshots).size === r.snapshots.length },
  prune: { req: [], opt: [], ok: () => true },
});
// `restore` is not here: a restore runs only through the launcher's restore runner (it must drop CAP_SYS_RESOURCE
// first), never from the supervisor.

/** Check a request against its op's closed shape. Returns the request, or refuses (bad_form). */
export function checkRequest(r) {
  if (r === null || typeof r !== "object" || Array.isArray(r) || typeof r.op !== "string" || !Object.hasOwn(OPS, r.op)) {
    refuse("bad_form", "backup request: unknown op");
  }
  const spec = OPS[r.op];
  const keys = Object.keys(r).filter((k) => k !== "op");
  if (!spec.req.every((k) => Object.hasOwn(r, k)) || !keys.every((k) => spec.req.includes(k) || spec.opt.includes(k)) || !spec.ok(r)) {
    refuse("bad_form", `backup request: not a valid ${r.op} request`);
  }
  return r;
}

/**
 * Run one request. `ctx`: { bin (the release's binary, absolute), state, secrets, cache (absolute directories) }.
 * Options: { ms (the deadline, required), signal, outMax = OUT_MAX, spawnFn (tests) }.
 * Resolves to { ok: true, value, stderr } or { ok: false, code, message, stderr }; never rejects for anything the
 * binary or the process does. It refuses (before any process starts) only a bad request or a bad ctx.
 */
export function runBackupOp(req, ctx, { ms, signal, outMax = OUT_MAX, spawnFn = spawn } = {}) {
  checkRequest(req);
  for (const k of ["bin", "state", "secrets", "cache"]) if (!absPath(ctx?.[k])) refuse("bad_form", `backup binary: ${k} must be an absolute path`);
  if (!(ms > 0)) refuse("bad_form", "backup binary: a deadline is required");
  const argv = ["--state", ctx.state, "--secrets", ctx.secrets, "--cache", ctx.cache];
  return new Promise((resolve) => {
    const local = (code, message, stderr = "") => ({ ok: false, code, message, stderr });
    if (signal?.aborted) { resolve(local("aborted", "aborted before it started")); return; }
    let child;
    try { child = spawnFn(ctx.bin, argv, { env: {}, stdio: ["pipe", "pipe", "pipe"], detached: true }); } catch (e) {
      resolve(local("spawn_failed", String(e?.code ?? e))); return;
    }
    const out = [], err = [];
    let outLen = 0, errLen = 0, overflow = false, why = null, settled = false, exited = null, hard = null;
    const group = () => { try { process.kill(-child.pid, "SIGKILL"); } catch { /* gone */ } };
    const stderrText = () => Buffer.concat(err).toString("utf8");
    const finish = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer); clearTimeout(hard);
      signal?.removeEventListener("abort", onAbort);
      group();
      child.stdout.destroy(); child.stderr.destroy();
      resolve(result);
    };
    const kill = (w) => {
      if (settled || why !== null) return;
      why = w;
      group();
      if (exited !== null) finish(local(w, w, stderrText()));
      else hard = setTimeout(() => finish(local(w, w, stderrText())), GRACE_MS);
    };
    const onAbort = () => kill("aborted");
    const timer = setTimeout(() => kill("timed_out"), ms);
    signal?.addEventListener("abort", onAbort, { once: true });
    child.on("error", (e) => { if (exited === null && why === null) finish(local("spawn_failed", String(e?.code ?? e))); });
    child.stdout.on("data", (b) => {
      if (outLen + b.length > outMax) { overflow = true; kill("bad_result"); return; }
      out.push(b); outLen += b.length;
    });
    child.stderr.on("data", (b) => { if (errLen < ERR_MAX) { err.push(b.subarray(0, ERR_MAX - errLen)); } errLen += b.length; });
    child.stdin.on("error", () => { /* the binary may exit before reading all of it; its result says why */ });
    child.on("close", (code, sig) => {
      exited = { code, sig };
      if (why !== null) { finish(local(why, overflow ? "stdout over its limit" : why, stderrText())); return; }
      finish(parseResult(Buffer.concat(out).toString("utf8"), code, sig, stderrText()));
    });
    child.stdin.end(JSON.stringify(req));
  });
}

/** Read the binary's stdout: exactly one JSON object, agreeing with the exit status, with a known error code. */
export function parseResult(text, code, sig, stderr = "") {
  const bad = (message) => ({ ok: false, code: "bad_result", message, stderr });
  if (sig) return bad(`killed by ${sig}`);
  const lines = text.split("\n");
  if (lines.length > 2 || (lines.length === 2 && lines[1] !== "")) return bad("not exactly one line");
  let v;
  try { v = JSON.parse(lines[0]); } catch { return bad("not JSON"); }
  if (v === null || typeof v !== "object" || Array.isArray(v) || typeof v.ok !== "boolean") return bad("not a result object");
  if (v.ok !== (code === 0)) return bad("ok disagrees with the exit status");
  if (v.ok) { const { ok, ...value } = v; return { ok: true, value, stderr }; }
  const e = v.error;
  if (e === null || typeof e !== "object" || keysOf(e) !== "code,message" || typeof e.message !== "string" || !CODES.includes(e.code) || keysOf(v) !== "error,ok") {
    return bad("not a closed error");
  }
  return { ok: false, code: e.code, message: e.message.slice(0, 4096), stderr };
}
