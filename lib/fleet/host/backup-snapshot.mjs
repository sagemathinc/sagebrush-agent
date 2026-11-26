// Host backup, wiring r0.4 §1.1: the run never reads the live host store. It plans, copies and binds from ONE
// immutable snapshot, made by whoever owns the store, identified by the run and a fresh nonce:
//   1. the request: every older `snapshot/` entry removed, then `snapshot/request.json` = { v: 1, run, nonce }
//      (root 0600, atomic, durable);
//   2. the owner: if no daemon owns the store (HostStore.open succeeds at once), the run takes the snapshot itself
//      under that lock (takeSnapshot) and releases the lock before any backup work. If the store is owned (a PAIRED
//      daemon), its executor serves the request with the same function;
//   3. the wait: at most 60 s for `snapshot/<run>/done.json` with THIS run's run and nonce; otherwise the run ends
//      `skipped: snapshot_unavailable`, having written no debt;
//   4. the result: the binding's registry (checked, its hash recomputed) and the host store's copy
//      (`snapshot/<run>/hoststore/`), which is the host-store set's source.
// takeSnapshot re-reads the request right before `done`: if a later run replaced it, the late owner removes its own
// `snapshot/<run>/` and writes no `done`. The request, the binding and `done` are root's 0600 regular files, bounded,
// read through a no-follow handle with a same-object check, closed-shape and durable.

import * as fs from "node:fs";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { refuse } from "../bytes.mjs";
import { exactKeys, writeDurable } from "./store.mjs";
import { copyHostStore } from "./backup-hoststore.mjs";
import { canonical, sha256 } from "./backup-manifest.mjs";
import { checkRegistry } from "./registry.mjs";
import { readRegular } from "./restore-record.mjs";

export const REQUEST = "request.json";
export const BINDING = "binding.json";
export const DONE = "done.json";
export const WAIT_MS = 60 * 1000;
const RUN = /^[0-9]{8}T[0-9]{6}Z-[a-z2-7]{8}$/;
const NONCE = /^[A-Za-z0-9_-]{22}$/;
const MAX_REQUEST = 1024;
const MAX_BINDING = 16 * 1024 * 1024;

/** A file of the snapshot protocol: absent (null), or root's (`uid`) 0600 regular file's bytes; anything else refuses. */
function readOwn(path, max, what, uid, fsx) {
  let st;
  try { st = fsx.lstatSync(path); } catch (e) { if (e?.code === "ENOENT") return null; throw e; }
  if (!st.isFile() || st.uid !== uid || (st.mode & 0o7777) !== 0o600) refuse("not_granted", `backup snapshot: ${what} isn't root's 0600 file`);
  return readRegular(path, max, what, fsx);
}
const parse = (bytes, what) => { try { return JSON.parse(bytes.toString("utf8")); } catch { refuse("bad_form", `backup snapshot: ${what} isn't JSON`); } };
const ident = (x) => exactKeys(x, ["v", "run", "nonce"]) && x.v === 1 && RUN.test(x.run) && NONCE.test(x.nonce);

/** The snapshot directory, root's 0700 (created when missing, one level), or a refusal. */
function ownDir(dir, uid, fsx) {
  let st;
  try { st = fsx.lstatSync(dir); } catch (e) {
    if (e?.code !== "ENOENT") throw e;
    fsx.mkdirSync(dir, { mode: 0o700 });
    fsx.chmodSync(dir, 0o700);
    st = fsx.lstatSync(dir);
  }
  if (!st.isDirectory() || st.uid !== uid || (st.mode & 0o7777) !== 0o700) refuse("not_granted", "backup snapshot: the snapshot directory isn't root's 0700");
}

/** The request now in `dir`, or null (none, or one not of the closed shape: then no owner serves it). */
export function readRequest(dir, { uid = 0, fsx = fs } = {}) {
  const b = readOwn(join(dir, REQUEST), MAX_REQUEST, "the request", uid, fsx);
  if (b === null) return null;
  let x;
  try { x = parse(b, "the request"); } catch { return null; }
  return ident(x) ? x : null;
}

/**
 * Take the snapshot for the request { run, nonce } (the owner's side; the caller holds the host store `store`, whose
 * `held` must stay true). Copies the host store's allowlist into `<dir>/<run>/hoststore/`, writes the binding from the
 * SAME locked view, re-reads the request, and only if it still names this run and nonce writes `done`. Otherwise it
 * removes its own `<dir>/<run>/` and writes nothing more. Resolves to { done: true } or { done: false }.
 */
export function takeSnapshot(store, { run, nonce }, { dir, root, uid = 0, fsx = fs, guard = () => {} }) {
  if (!RUN.test(run) || !NONCE.test(nonce)) refuse("bad_form", "backup snapshot: a bad request");
  const held = () => store.held === true;
  const mine = join(dir, run);
  guard();
  fsx.mkdirSync(mine, { mode: 0o700 });
  fsx.chmodSync(mine, 0o700);
  guard();
  copyHostStore(root, join(mine, "hoststore"), { held, fsx });
  const registry = store.registry.snapshot();
  checkRegistry(registry);
  guard();
  writeDurable(mine, BINDING, JSON.stringify({ v: 1, run, nonce, registry_hash: sha256(canonical(registry)), registry }) + "\n");
  if (!held()) refuse("not_granted", "backup snapshot: the host-store lock was lost");
  const now = readRequest(dir, { uid, fsx });
  if (now === null || now.run !== run || now.nonce !== nonce) {
    guard();
    fsx.rmSync(mine, { recursive: true, force: true }); // (a late owner: its own result only; rm never follows a link)
    return { done: false };
  }
  guard();
  writeDurable(mine, DONE, JSON.stringify({ v: 1, run, nonce }) + "\n");
  return { done: true };
}

/** This run's result, or null when it isn't (yet) there: `done` and the binding for exactly { run, nonce }. */
export function readResult(dir, { run, nonce }, { uid = 0, fsx = fs } = {}) {
  const mine = join(dir, run);
  const d = readOwn(join(mine, DONE), MAX_REQUEST, "done", uid, fsx);
  if (d === null) return null;
  const done = parse(d, "done");
  if (!ident(done) || done.run !== run || done.nonce !== nonce) return null; // (not this run's: never accepted)
  const b = readOwn(join(mine, BINDING), MAX_BINDING, "the binding", uid, fsx);
  if (b === null) refuse("bad_form", "backup snapshot: done without its binding");
  const x = parse(b, "the binding");
  if (!exactKeys(x, ["v", "run", "nonce", "registry_hash", "registry"]) || x.v !== 1 || x.run !== run || x.nonce !== nonce) refuse("bad_form", "backup snapshot: the binding isn't this run's");
  checkRegistry(x.registry);
  if (x.registry_hash !== sha256(canonical(x.registry))) refuse("bad_form", "backup snapshot: the binding's registry hash doesn't match");
  const hs = join(mine, "hoststore");
  const st = fsx.lstatSync(hs);
  if (!st.isDirectory() || st.uid !== uid || (st.mode & 0o7777) !== 0o700) refuse("not_granted", "backup snapshot: the host store's copy isn't root's 0700");
  return { registry: x.registry, registryHash: x.registry_hash, hoststore: hs };
}

/**
 * The run's side (steps 1-4). `openStore()`: HostStore.open of the live store (refuses in_progress when a daemon owns
 * it); `root`: the store's directory; `guard()`: the run's held guard, before every effect and after every await.
 * Resolves to { ok: true, registry, registryHash, hoststore } or { ok: false, why: "snapshot_unavailable" }.
 */
export async function runSnapshot(run, { dir, root, openStore, uid = 0, fsx = fs, rand = randomBytes, guard = () => {},
  waitMs = WAIT_MS, pollMs = 1000, now = Date.now, sleep = (ms) => new Promise((r) => { setTimeout(r, ms); }) }) {
  guard();
  ownDir(dir, uid, fsx);
  // Every older entry goes first (a late owner's leftovers are never read), then this run's request.
  for (const name of fsx.readdirSync(dir)) { guard(); fsx.rmSync(join(dir, name), { recursive: true, force: true }); }
  const nonce = rand(16).toString("base64url");
  guard();
  writeDurable(dir, REQUEST, JSON.stringify({ v: 1, run, nonce }) + "\n");
  let store = null;
  try { store = await openStore(); } catch (e) { if (e?.code !== "in_progress") throw e; }
  if (store !== null) {
    // No daemon owns the store: this run is the owner, for the copy only. The store is released whatever happens
    // after its open, the run's guard included (a lost run never keeps the store's lock).
    try { guard(); takeSnapshot(store, { run, nonce }, { dir, root, uid, fsx, guard }); } finally { await store.close(); }
  }
  guard();
  const t0 = now();
  for (;;) {
    const r = readResult(dir, { run, nonce }, { uid, fsx });
    if (r !== null) return { ok: true, ...r };
    if (store !== null || now() - t0 >= waitMs) return { ok: false, why: "snapshot_unavailable" };
    await sleep(Math.min(pollMs, waitMs - (now() - t0)));
    guard();
  }
}
