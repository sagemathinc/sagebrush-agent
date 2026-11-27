// `sagebrush-agent host pair` (host pairing d2, d2r1, d3, d3r1, d3r2; the service side is auth's d3 and d3r1): a FRESH
// host asks the service for a pairing, shows the short code and its fingerprint on the console, waits for the person's
// approval in the app, then fetches the fleet's chain and writes its identity (pairWrite) — only after the fleet's
// genesis matches the fleet fingerprint the person gave BEFORE anything was sent (option B, mandatory).
//
// The attempt is a durable intent, `<identity>/pairing.json` (root 0600, written exclusively and fsynced with its
// directory before the first request, read no-follow): { v: 1, host, host_fp, origin, fleet_fp, created_ms, pairing? }.
// - host: this attempt's host id (a new one per attempt); host_fp: the fingerprint of (host, the host's own identity
//   keys), so a key reset can't resume it; origin: the service (its audience); fleet_fp: the anchor, normalized;
//   created_ms: the intent's first write.
// - Everything but `pairing` is immutable for the record's life: the rewrite that adds `pairing` refuses to change it.
// - On resume the record's values ARE the attempt: a different --fleet or --service is not_granted, nothing done.
// - The create is idempotent at the service per (host, sign_key): a resume with no `pairing` re-POSTs and gets the
//   same live pairing (a new code), its approved state, or expired.
// - A resume past created_ms + RESUME_HORIZON (or with the clock before created_ms) sends nothing: pairing_expired.
// - expired or not_found: the record is removed and the command reports it and exits; a new attempt is a new run (a
//   new host id, the anchor asked again), so a code never changes silently under the person.
// Output: one JSON line of codes; the code and the fingerprints go only to the terminal.

import * as fs from "node:fs";
import { randomBytes } from "node:crypto";
import { hostname } from "node:os";
import { dirname, join } from "node:path";
import { FleetError, refuse, isId, newId, b64, unb64, enc } from "../bytes.mjs";
import { AUDIENCES } from "../envelope.mjs";
import { hostFingerprint, fleetFingerprint, showFingerprint } from "../core/verify.mjs";
import { replay as replayChain } from "../core/chain.mjs";
import { CHAIN_PAGE_BYTES, chainTarget, parseChainPage } from "../core/chain-service.mjs";
import { signRequest } from "../request.mjs";
import { boundedGet } from "./chain-sync.mjs";
import { classify, hostPaths, pairWrite, takeOwnership, verifyCertFor } from "./identity.mjs";
import { exactKeys, realIo, writeDurable } from "./store.mjs";
import { readRegular } from "./restore-record.mjs";
import { commandSignal } from "./backup-binary.mjs";
import { brokerAccount, readMachineId } from "./host-main.mjs";

export const PAIRING = "pairing.json";
/** The local resume horizon (d3r2): at most half the service's 30-day tombstone retention, so a resume allowed to reach
 *  the service always lands while it still remembers the pairing (the same pairing, or expired, never a new one). */
export const RESUME_HORIZON_MS = 7 * 24 * 60 * 60 * 1000;
export const POLL_MS = 5000;
export const PAIR_ROUTE = "/api/fleet/v1/host/pair";
export const RESULT_ROUTE = "/api/fleet/v1/host/pair/result";
const REQUEST_MS = 15000;
const REPLY_MAX = 64 * 1024;
const CHAIN_PAGES_MAX = 4096; // (256 entries a page: a chain of a million entries; more is a broken service)
const MAX_INTENT = 2048;
const FP = /^[a-z2-7]{20}$/;
const NAME = /^[a-z0-9-]{1,32}$/;
const USAGE = "usage: sagebrush-agent host pair [--fleet <fleet fingerprint>] [--service <origin>] [--name <label>]";

/** The expected fleet fingerprint as typed (any case; dashes and spaces dropped), or null if it isn't one. */
export function normalizeFleetFp(s) {
  if (typeof s !== "string") return null;
  const t = s.toLowerCase().replace(/[-\s]/g, "");
  return FP.test(t) ? t : null;
}
/** A fleet's fingerprint as the person compares it, normalized: showFingerprint of the genesis's exact bytes. */
export async function fleetFp(fleet, genesisBytes) {
  return normalizeFleetFp(showFingerprint(await fleetFingerprint(fleet, genesisBytes)));
}

const INTENT_KEYS = ["v", "host", "host_fp", "origin", "fleet_fp", "created_ms"];
const isIntent = (x) => (exactKeys(x, INTENT_KEYS) || (exactKeys(x, [...INTENT_KEYS, "pairing"]) && isId(x.pairing)))
  && x.v === 1 && isId(x.host) && typeof x.host_fp === "string" && x.host_fp.length > 0 && AUDIENCES.includes(x.origin)
  && FP.test(x.fleet_fp) && Number.isSafeInteger(x.created_ms) && x.created_ms >= 0;

/** The intent now on disk, or null. Root's (`uid`) 0600 regular file, closed shape; anything else refuses. */
export function readIntent(dir, { uid = 0, fsx = fs } = {}) {
  const p = join(dir, PAIRING);
  let st;
  try { st = fsx.lstatSync(p); } catch (e) { if (e?.code === "ENOENT") return null; throw e; }
  if (!st.isFile() || st.uid !== uid || (st.mode & 0o7777) !== 0o600) refuse("not_granted", "host pair: pairing.json isn't root's 0600 file");
  let x;
  try { x = JSON.parse(readRegular(p, MAX_INTENT, "pairing.json", fsx).toString("utf8")); } catch (e) {
    if (e instanceof FleetError) throw e;
    refuse("bad_form", "host pair: pairing.json isn't JSON");
  }
  if (!isIntent(x)) refuse("bad_form", "host pair: pairing.json isn't an intent");
  return x;
}

/** The identity directory: root's 0700, made (one level, its parent 0755) when missing. */
function identityDir(dir, uid, fsx) {
  try { fsx.lstatSync(dir); } catch (e) {
    if (e?.code !== "ENOENT") throw e;
    fsx.mkdirSync(dirname(dir), { recursive: true, mode: 0o755 });
    fsx.mkdirSync(dir, { mode: 0o700 });
  }
  const st = fsx.lstatSync(dir);
  if (!st.isDirectory() || st.uid !== uid || (st.mode & 0o7777) !== 0o700) refuse("not_granted", "host pair: the identity directory isn't root's 0700");
}

const syncDir = (dir, io, fsx) => { const fd = fsx.openSync(dir, "r"); try { io.fsync(fd); } finally { io.close(fd); } };

/** The first intent's temporary name (never read as an intent; a stale one is removed before the next write). */
export const INTENT_TMP = `.${PAIRING}.tmp`;

/**
 * The intent's first write, published whole: written and fsynced at a temporary name, then hard-linked to its final
 * name, which never replaces an existing attempt (EEXIST refuses), then the temporary removed and the directory
 * fsynced. A crash at any point leaves either no pairing.json or a complete one, never an empty or partial one.
 */
export function writeIntent(dir, x, { io = realIo, fsx = fs } = {}) {
  if (!isIntent(x) || Object.hasOwn(x, "pairing")) refuse("bad_form", "host pair: not a first intent");
  const { O_WRONLY, O_CREAT, O_EXCL, O_NOFOLLOW } = fs.constants;
  const buf = enc(JSON.stringify(x) + "\n");
  const tmp = join(dir, INTENT_TMP);
  try { fsx.unlinkSync(tmp); } catch (e) { if (e?.code !== "ENOENT") throw e; }
  const fd = io.open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600);
  try {
    fsx.fchmodSync(fd, 0o600);
    for (let off = 0; off < buf.length;) { const k = io.write(fd, buf, off, buf.length - off); if (!(k > 0)) refuse("bad_form", "host pair: a short write"); off += k; }
    io.fsync(fd);
  } finally { io.close(fd); }
  try { fsx.linkSync(tmp, join(dir, PAIRING)); } catch (e) {
    if (e?.code === "EEXIST") refuse("in_progress", "host pair: another attempt's intent appeared; run it again");
    throw e;
  } finally { try { fsx.unlinkSync(tmp); } catch { /* removed next time */ } }
  syncDir(dir, io, fsx);
}

/** Add the service's pairing id (atomic, durable). Every earlier field stays exactly as it was. */
export function addPairing(dir, prev, pairing, { uid = 0, io = realIo, fsx = fs } = {}) {
  const now = readIntent(dir, { uid, fsx });
  if (now === null || INTENT_KEYS.some((k) => now[k] !== prev[k]) || Object.hasOwn(now, "pairing") || !isId(pairing)) {
    refuse("not_granted", "host pair: the intent changed under the attempt");
  }
  const next = { ...now, pairing };
  writeDurable(dir, PAIRING, JSON.stringify(next) + "\n", io, 0o600);
  syncDir(dir, io, fsx);
  return next;
}

export function removeIntent(dir, { io = realIo, fsx = fs } = {}) {
  try { fsx.unlinkSync(join(dir, PAIRING)); } catch (e) { if (e?.code !== "ENOENT") throw e; }
  syncDir(dir, io, fsx);
}

/** Read a response body, at most `max` bytes. */
async function readCapped(res, max) {
  const reader = res.body.getReader();
  const parts = [];
  let n = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      n += value.length;
      if (n > max) throw Object.assign(new Error("oversize"), { cls: "oversize" });
      parts.push(value);
    }
  } finally { reader.cancel().catch(() => {}); }
  const out = new Uint8Array(n);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

/**
 * One POST to the service, bounded: { status, json } (a refusal's `{error}` included), or { cls } for a transport
 * failure (timeout, redirect, network, oversize, bad_reply). No redirect is followed.
 */
export async function boundedPost(fetch, url, body, headers, { ms = REQUEST_MS, max = REPLY_MAX } = {}) {
  const ac = new AbortController();
  let timer;
  const deadline = new Promise((resolve) => { timer = setTimeout(() => { ac.abort(); resolve({ cls: "timeout" }); }, ms); });
  const exchange = (async () => {
    const res = await fetch(url, { method: "POST", body, redirect: "error", signal: ac.signal, headers: { "content-type": "application/json", ...headers } });
    if (res.redirected || (res.status >= 300 && res.status < 400)) return { cls: "redirect" };
    const bytes = await readCapped(res, max);
    let json;
    try { json = JSON.parse(Buffer.from(bytes).toString("utf8")); } catch { return { cls: "bad_reply" }; }
    return { status: res.status, json };
  })().catch((e) => ({ cls: e?.cls === "oversize" ? "oversize" : ac.signal.aborted ? "timeout" : "network" }));
  try { return await Promise.race([exchange, deadline]); } finally { clearTimeout(timer); }
}

/** The service as `host pair` uses it, over fetch: pair, result, and the paged chain read. */
export function realService({ fetch = globalThis.fetch } = {}) {
  return {
    pair: (origin, body, header) => boundedPost(fetch, `${origin}${PAIR_ROUTE}`, body, { "sagebrush-sig": header }),
    result: (origin, body, header) => boundedPost(fetch, `${origin}${RESULT_ROUTE}`, body, { "sagebrush-sig": header }),
    chainPage: async (origin, target, header) => {
      const r = await boundedGet(fetch, `${origin}${target}`, { "sagebrush-sig": header }, { max: CHAIN_PAGE_BYTES, ms: REQUEST_MS });
      return r.bytes ? { bytes: r.bytes } : { cls: r.cls };
    },
  };
}

/** A service refusal's registered code, or a transport class, as the command's own refusal. */
const failed = (r) => {
  if (r?.cls) refuse("outcome_unknown", `host pair: the service couldn't be reached (${r.cls})`);
  const code = r?.json?.error;
  refuse(typeof code === "string" && /^[a-z_]{1,40}$/.test(code) ? code : "outcome_unknown", "host pair: the service refused");
};
const isCode = (s) => typeof s === "string" && /^[a-z2-7]{8}$/.test(s);

function parseArgs(argv) {
  const o = {};
  for (let i = 0; i < argv.length; i += 2) {
    const k = argv[i], v = argv[i + 1];
    if (!["--fleet", "--service", "--name"].includes(k) || typeof v !== "string" || Object.hasOwn(o, k)) return null;
    o[k] = v;
  }
  return o;
}

/**
 * The command. `argv`: after "pair". `deps` (all seams for tests): uid(), rootUid, paths, tty ({write, ask, close} or
 * null), lock (takeOwnership's), classify(paths), machineId, brokerUid, service (realService's shape), now() (wall
 * ms), newHostId(), nonce(), sleep(ms), signal, pairWrite, io, fsx. Resolves { code, line } (code 2: usage).
 */
export async function pairCommand(argv, deps = {}) {
  const args = parseArgs(argv);
  if (args === null) return { code: 2, line: null, usage: USAGE };
  const { uid = () => process.getuid?.() ?? -1, rootUid = 0, paths = hostPaths(), service = realService(), now = Date.now,
    newHostId = newId, nonce = () => randomBytes(16).toString("base64url"), signal = commandSignal(), io = realIo, fsx = fs,
    sleep = (ms) => new Promise((r) => { const t = setTimeout(r, ms); signal?.addEventListener("abort", () => { clearTimeout(t); r(); }, { once: true }); }),
    write = pairWrite } = deps;
  if (uid() !== rootUid) return { code: 1, line: { v: 1, refused: "not_granted" } };
  const tty = Object.hasOwn(deps, "tty") ? deps.tty : (await import("./backup-init.mjs")).realTty();
  let lock = null;
  try {
    if (!tty) refuse("not_granted", "host pair: no controlling terminal to show the code on");
    const stopped = () => { if (signal?.aborted) refuse("outcome_unknown", "host pair: stopped by a signal; run it again to resume"); };
    if (args["--service"] !== undefined && !AUDIENCES.includes(args["--service"])) refuse("bad_form", "host pair: not a known service");
    // The service's rule: 1 to 32 of [a-z0-9-]. The default is the machine's hostname, folded into it.
    const name = args["--name"] ?? (hostname().toLowerCase().replace(/[^a-z0-9-]/g, "-").slice(0, 32) || "host");
    if (!NAME.test(name)) refuse("bad_form", "host pair: a name is 1 to 32 of a-z, 0-9 and -");
    // The ownership lock, no wait: the daemon holds it while it runs.
    try { lock = await (deps.lock ?? takeOwnership)(paths, { rootUid }); } catch (e) { if (e?.busy || e?.code === "in_progress") refuse("in_progress", "host pair: the daemon owns this host; stop it first"); throw e; }
    // The supervisor's own classify inputs (host-main realDeps): the machine-id file's exact text and the broker
    // account's uid, which firstBoot made the keys' owner. Any other value misreads a normal host as BROKEN or CLONE.
    const classifyReal = (p) => {
      const broker = (deps.brokerAccount ?? brokerAccount)();
      if (!broker || !Number.isSafeInteger(broker.uid) || broker.uid <= 0) refuse("not_granted", "host pair: no broker account on this host");
      return classify(p, { machineId: deps.machineId ?? readMachineId, brokerUid: broker.uid, rootUid });
    };
    const st = await (deps.classify ?? classifyReal)(paths);
    if (st.state === "PAIRED") refuse("in_progress", "host pair: this host is already paired");
    if (st.state !== "FRESH" && st.state !== "PAIRING") refuse("not_granted", `host pair: the identity is ${st.state}`);
    const keys = st.keys;
    identityDir(paths.identity, rootUid, fsx);
    const dir = paths.identity;

    // The intent: resumed (its values are the attempt), or a new one, durable before any request.
    let x = readIntent(dir, { uid: rootUid, fsx });
    const given = args["--fleet"] === undefined ? undefined : normalizeFleetFp(args["--fleet"]);
    if (args["--fleet"] !== undefined && given === null) refuse("bad_form", "host pair: not a fleet fingerprint");
    if (x !== null) {
      const t = now();
      if (t > x.created_ms + RESUME_HORIZON_MS || t < x.created_ms) { removeIntent(dir, { io, fsx }); refuse("pairing_expired", "host pair: the attempt is past its resume horizon; run it again"); }
      if (b64(await hostFingerprint(x.host, keys.sign.raw, keys.enc.raw)) !== x.host_fp) { removeIntent(dir, { io, fsx }); refuse("pairing_expired", "host pair: the host's keys changed since the attempt began; run it again"); }
      if ((given !== undefined && given !== x.fleet_fp) || (args["--service"] !== undefined && args["--service"] !== x.origin)) {
        refuse("not_granted", "host pair: a different fleet fingerprint or service than the attempt's");
      }
    } else {
      let fp = given;
      if (fp === undefined) fp = normalizeFleetFp(await tty.ask("The fleet fingerprint shown in the Sagebrush app (xxxx-xxxx-xxxx-xxxx-xxxx): "));
      stopped();
      if (!fp) refuse("bad_form", "host pair: no fleet fingerprint given");
      const host = newHostId();
      x = { v: 1, host, host_fp: b64(await hostFingerprint(host, keys.sign.raw, keys.enc.raw)), origin: args["--service"] ?? AUDIENCES[0], fleet_fp: fp, created_ms: now() };
      writeIntent(dir, x, { io, fsx });
    }
    const sig = (method, target, body) => signRequest({ aud: x.origin, method, target, body, host: x.host, key: keys.sign, fields: { gen: 1, ts: now(), nonce: nonce() } });
    const showHost = async () => tty.write(`This host's fingerprint: ${showFingerprint(await hostFingerprint(x.host, keys.sign.raw, keys.enc.raw))}\n`);

    // The request, on a first attempt AND on every resume: the service's re-POST is idempotent per host id and keys
    // (the same pairing, a fresh code, the old code dead). So a resume shows a code the person can use even when the
    // earlier attempt was interrupted after the pairing id was saved but before its code was shown.
    {
      stopped();
      if (Object.hasOwn(x, "pairing")) tty.write("\nResuming the pairing started earlier.\n");
      const body = enc(JSON.stringify({ host: x.host, sign_key: b64(keys.sign.raw), enc_key: b64(keys.enc.raw), fingerprint: x.host_fp, name }));
      const r = await service.pair(x.origin, body, sig("POST", PAIR_ROUTE, body));
      if (r?.status !== 200) failed(r);
      const j = r.json;
      if (!isId(j?.pairing)) refuse("outcome_unknown", "host pair: the service's reply isn't a pairing");
      if (Object.hasOwn(x, "pairing") && j.pairing !== x.pairing) refuse("outcome_unknown", "host pair: the service answered with another pairing than the attempt's");
      if (j.state === "expired" && exactKeys(j, ["pairing", "state"])) { removeIntent(dir, { io, fsx }); refuse("pairing_expired", "host pair: the pairing expired; run it again"); }
      if (!Object.hasOwn(x, "pairing")) x = addPairing(dir, x, j.pairing, { uid: rootUid, io, fsx });
      if (exactKeys(j, ["pairing", "code", "expires_at_ms"]) && isCode(j.code) && Number.isSafeInteger(j.expires_at_ms)) {
        tty.write(`\nPairing code: ${j.code.slice(0, 4)}-${j.code.slice(4)}  (enter it in the Sagebrush app within 10 minutes)\n`);
        await showHost();
      } else if (!(j.state === "approved" && exactKeys(j, ["pairing", "state"]))) refuse("outcome_unknown", "host pair: the service's reply isn't a pairing");
    }

    // The poll, every POLL_MS, until approved, expired, not_found, a signal, or a refusal.
    let approved = null;
    for (;;) {
      stopped();
      const body = enc(JSON.stringify({ pairing: x.pairing }));
      const r = await service.result(x.origin, body, sig("POST", RESULT_ROUTE, body));
      if (r?.status === 200) {
        const j = r.json;
        if (j?.state === "approved" && exactKeys(j, ["state", "fleet", "cert"]) && isId(j.fleet) && typeof j.cert === "string") { approved = j; break; }
        if (j?.state === "expired" && exactKeys(j, ["state"])) { removeIntent(dir, { io, fsx }); refuse("pairing_expired", "host pair: the pairing expired; run it again"); }
        if (!(j?.state === "pending" && exactKeys(j, ["state"]))) refuse("outcome_unknown", "host pair: the service's poll reply isn't a state");
      } else if (r?.json?.error === "not_found") {
        removeIntent(dir, { io, fsx });
        refuse("not_found", "host pair: the service doesn't know this pairing; run it again");
      } else if (!r?.cls && r?.json?.error !== "rate") failed(r); // (a transport failure or a rate limit: poll again)
      await sleep(POLL_MS);
    }

    // The chain, from genesis to the head the service has now, the anchor checked BEFORE anything is written.
    stopped();
    const entries = [];
    let after = -1, head = null;
    for (let pages = 0; ; pages++) {
      if (pages >= CHAIN_PAGES_MAX) refuse("limit", "host pair: the chain has too many pages");
      stopped();
      const target = chainTarget(after < 0 ? null : after);
      const r = await service.chainPage(x.origin, target, sig("GET", target, new Uint8Array(0)));
      if (!r?.bytes) refuse("outcome_unknown", "host pair: the chain couldn't be read");
      const p = parseChainPage(r.bytes, after);
      entries.push(...p.entries);
      after = p.next;
      head = p.head;
      if (p.entries.length === 0 || after >= head) break;
    }
    if (entries.length === 0) refuse("bad_form", "host pair: an empty chain");
    if (await fleetFp(approved.fleet, entries[0]) !== x.fleet_fp) refuse("not_granted", "host pair: the fleet's fingerprint isn't the one given; nothing was written");
    const state = await replayChain(entries, { aud: x.origin, fleet: approved.fleet });
    const pin = { fleet: approved.fleet, aud: x.origin, seq: state.seq, hash: state.head };
    let certBytes;
    try { certBytes = unb64(approved.cert); } catch { refuse("bad_form", "host pair: the certificate isn't base64url"); }
    const cert = await verifyCertFor(certBytes, keys, pin, state).catch(() => refuse("not_granted", "host pair: the certificate isn't this host's in this fleet"));
    if (cert?.body?.host !== x.host) refuse("not_granted", "host pair: the certificate names another host id");
    stopped();
    await write(paths, { keys, entries, pin, certBytes }, { rootUid, io, fsx });
    removeIntent(dir, { io, fsx });
    tty.write("Paired. Start the host: systemctl start sagebrush-supervisor.service\n");
    return { code: 0, line: { v: 1, paired: true } };
  } catch (e) {
    // The code only (no path, key, code or message reaches the line).
    return { code: 1, line: { v: 1, refused: e instanceof FleetError ? e.code : "outcome_unknown" } };
  } finally {
    try { await lock?.release?.(); } catch { /* (released with the process) */ }
    tty?.close?.();
  }
}
