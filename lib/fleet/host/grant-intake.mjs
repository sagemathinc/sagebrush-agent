// Host supervisor (design: slice B, the grant reader and the pairs intake, grant-intake d1 to d1r8): the daemon's grant
// input. It reads the host's grant from the service, stores each transferred agent's pair durably, and submits the
// grant to the executor, one generation at a time.
//
// - The reader (d1 §1, d1r2 T1, d1r5 T7): GET /api/fleet/v1/host/grant, signed with the certified host key, every 60 s
//   and once more after a chain adoption (a nudge). The newest answer is read first and HELD; when the host is behind,
//   the generations between are read by ?gen=k in order, and the held newest is intaken when k reaches it.
// - The authority (d1r4 T5): the executor's applied {gen, hash}. The accepted file is only a hint: rewritten when below
//   it, a fault when above it.
// - One generation k, in order (d1r3, d1r4 B-H1, d1r5 B-H8):
//   1. verify the grant (the executor's own verify), its gen = applied + 1;
//   2. verify every pair and bind it to THIS grant (S1): the receipt and transfer under the pinned chain, the grant's
//      hash, gen k, this host, an agent the grant lists, one pair per agent, before anything is written;
//   3. the durable `grant.intake` intent {grant_hash, pairs_digest};
//   4. every new pair written (temp, fsync, rename), then ONE fsync of the pairs directory;
//   5. a `pair.store` record for every pair of the set (written or kept), then ONE fsync of the stream;
//   6. the intent's terminal (succeeded, and `reconciles` an earlier open intent for k), durable;
//   7. submit; accepted when the executor reports it applied (or reapplied).
//   Any refusal at k ends the cycle at k: nothing of k is kept that isn't verified, and nothing after k is read.
// - pairOf (d1 §3, d1r4 B-H6, d1r5 P1): the stored pair, only when its digests equal the LATEST pair.store record for
//   the agent in the verified stream. requestResume re-verifies it against the chain at use.
// - Recovery (d1r6, d1r7): a stored pair the index doesn't match is recorded `kept` only if it re-verifies and binds to
//   the grant the agent has been listed in since (its arrival), as the stream shows it applied.
// - Refusals with a verified context are signed `refused` records, at most one per (gen, reason) per 10 s, with their
//   count (d1r4 B-H3, d1r5 N8). Transport failures are health only.

import fs from "node:fs";
import { randomBytes } from "node:crypto";
import { join } from "node:path";
import { canonText, enc, isId, parseCanonical, sha256b64, SIGNED_MAX } from "../index.mjs";
import { signRequest } from "../request.mjs";
import { GRANT_PAIRS_MAX, GRANT_READ_BYTES, GRANT_READ_MS, grantTarget, parseGrantRead } from "../core/grant-service.mjs";
import { boundedGet } from "./chain-sync.mjs";
import { realIo } from "./store.mjs";

/** The poll (B2). */
export const POLL_MS = 60_000;
/** The backoff after a rate limit, a 503 or a transport failure: doubling from POLL_MS, capped here (d1r2 N2). */
export const BACKOFF_MAX_MS = 600_000;
/** At most one signed refusal record per (gen, reason) in this window, with its count (d1r5 N8). */
export const REFUSAL_EVERY_MS = 10_000;
/** A stored pair file: the two envelopes embedded as canonical objects, plus the framing (d1r2 N5). */
export const PAIR_FILE_MAX = 2 * SIGNED_MAX + 32;
/** A refusal answer's body, read for its code. */
export const ERROR_BODY_MAX = 4096;
/** The reasons a signed refusal may carry (d1r4 B-H3). */
export const REFUSAL_REASONS = Object.freeze(["bad_signature", "bad_audience", "stale_generation", "not_granted", "bad_form", "no_grant", "chain_fork"]);

const newOpId = () => randomBytes(16).toString("base64url");
const digest = (bytes) => sha256b64(bytes);
const fail = (reason, why, extra = {}) => ({ ok: false, reason, why, ...extra });

// ---- the transport ---------------------------------------------------------------------------------------------------

/**
 * The grant read, as one function `read(gen | null)`: { read: {gen, grant, pairs} } (parsed, UNVERIFIED), or
 * { refused: code, retryAfterMs } (the service's answer), or { transport: cls }. Signed like the chain read (§5.1:
 * gen = the host's applied gen, at least 1).
 */
export function grantReader({ aud, origin, host, signer, gen, fetch = globalThis.fetch, wall = Date.now, mono, ms = GRANT_READ_MS,
  nonce = () => randomBytes(16).toString("base64url") }) {
  const u = new URL(origin);
  if (u.protocol !== "https:" || (u.pathname !== "/" && u.pathname !== "") || u.search || u.hash) throw new Error("grant reader: the origin must be https://host[:port]");
  return async (k = null) => {
    const target = grantTarget(k);
    const header = signRequest({ aud, method: "GET", target, host, key: signer, fields: { gen: Math.max(1, gen()), ts: wall(), nonce: nonce() } });
    const r = await boundedGet(fetch, `${u.origin}${target}`, { "sagebrush-sig": header }, { max: GRANT_READ_BYTES, ms, errorMax: ERROR_BODY_MAX, ...(mono ? { mono } : {}) });
    if (r.bytes && !r.cls) {
      try { return { read: parseGrantRead(r.bytes, k) }; } catch { return { refused: "bad_form" }; }
    }
    if (r.cls === "status") {
      let code = null, retryAfterMs = null;
      try {
        const v = JSON.parse(new TextDecoder().decode(r.bytes ?? new Uint8Array(0)));
        if (typeof v?.error === "string" && /^[a-z][a-z0-9_]{0,39}$/.test(v.error)) code = v.error;
        if (Number.isSafeInteger(v?.retry_after_s) && v.retry_after_s >= 0) retryAfterMs = v.retry_after_s * 1000;
      } catch { /* a bare status */ }
      if (r.status === 429) return { refused: "rate", retryAfterMs };
      if (code === null) return { transport: `status_${r.status}` };
      return { refused: code, retryAfterMs };
    }
    return { transport: r.cls };
  };
}

// ---- the pair files --------------------------------------------------------------------------------------------------

/**
 * transfers/pairs/<agent> under the host store: root 0600, the directory root 0700. Each file is
 * canonText({receipt, transfer}) with both envelopes as canonical objects (so their bytes are reproduced exactly).
 */
export class PairFiles {
  constructor(dir, { io = realIo, fsx = fs, uid = 0 } = {}) { Object.assign(this, { dir, io, fsx, uid }); }

  ensure() {
    try { this.fsx.mkdirSync(this.dir, { mode: 0o700, recursive: true }); } catch (e) { if (e?.code !== "EEXIST") throw e; }
    const st = this.fsx.lstatSync(this.dir);
    if (!st.isDirectory() || (st.mode & 0o077) !== 0 || st.uid !== this.uid) throw Object.assign(new Error("the pairs directory isn't private"), { code: "bad_form" });
  }

  /** The file's text for a pair { receipt, transfer } (each the envelope's bytes). */
  static textOf(pair) {
    const obj = (b) => parseCanonical(b, SIGNED_MAX);
    return canonText({ receipt: obj(pair.receipt), transfer: obj(pair.transfer) });
  }

  /**
   * The stored pair for `agent`: { pair: { receipt, transfer } (bytes), text }, null when absent, or { bad: why } (a
   * link, not root's, not 0600, over the bound, or not the shape). Never follows a link.
   */
  read(agent) {
    if (!isId(agent)) return { bad: "agent" };
    const p = join(this.dir, agent);
    let fd;
    try { fd = this.fsx.openSync(p, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK); } catch (e) {
      if (e?.code === "ENOENT") return null;
      return { bad: e?.code === "ELOOP" ? "link" : "open" };
    }
    try {
      const st = this.fsx.fstatSync(fd);
      if (!st.isFile() || st.nlink !== 1 || st.uid !== this.uid || (st.mode & 0o777) !== 0o600) return { bad: "not root's 0600 file" };
      if (st.size > PAIR_FILE_MAX) return { bad: "over the bound" };
      const buf = Buffer.alloc(st.size + 1);
      const n = this.fsx.readSync(fd, buf, 0, buf.length, 0);
      if (n > PAIR_FILE_MAX) return { bad: "over the bound" };
      const text = buf.subarray(0, n).toString("utf8");
      const v = parseCanonical(enc(text), PAIR_FILE_MAX);
      if (!v || typeof v !== "object" || Array.isArray(v) || Object.keys(v).sort().join() !== "receipt,transfer") return { bad: "shape" };
      return { pair: { receipt: enc(canonText(v.receipt)), transfer: enc(canonText(v.transfer)) }, text };
    } catch { return { bad: "unreadable" }; } finally { this.fsx.closeSync(fd); }
  }

  /** The transfer's gen of a stored pair (its body, as stored). */
  static genOf(pair) {
    try { return parseCanonical(pair.transfer, SIGNED_MAX)?.body?.gen ?? null; } catch { return null; }
  }

  /** One file staged: temp, whole write, fsync, rename (no directory fsync: syncDir does that once for the set). */
  stage(agent, text) {
    const tmp = join(this.dir, `.${agent}.${process.pid}.tmp`);
    const buf = Buffer.from(text);
    const fd = this.io.open(tmp, "w", 0o600);
    try {
      this.fsx.fchmodSync(fd, 0o600);
      for (let off = 0; off < buf.length;) {
        const n = this.io.write(fd, buf, off, buf.length - off);
        if (!Number.isSafeInteger(n) || n <= 0 || n > buf.length - off) throw Object.assign(new Error("short write"), { code: "EIO" });
        off += n;
      }
      this.io.fsync(fd);
    } finally { this.io.close(fd); }
    this.io.rename(tmp, join(this.dir, agent));
  }

  syncDir() {
    const dfd = this.io.open(this.dir, "r");
    try { this.io.fsync(dfd); } finally { this.io.close(dfd); }
  }

  list() {
    try { return this.fsx.readdirSync(this.dir).filter((n) => isId(n)); } catch (e) { if (e?.code === "ENOENT") return []; throw e; }
  }
}

/** The ordered digest of a generation's pair set: agents ascending, each { agent, receipt_digest, transfer_digest }. */
export function pairsDigest(items) {
  const rows = items.map((x) => ({ agent: x.agent, receipt_digest: x.receipt_digest, transfer_digest: x.transfer_digest }))
    .sort((a, b) => (a.agent < b.agent ? -1 : a.agent > b.agent ? 1 : 0));
  return sha256b64(enc(canonText(rows)));
}

// ---- the accepted hint -----------------------------------------------------------------------------------------------

/** /var/lib/sagebrush/grants/accepted: { gen, hash }, a hint (d1r4 T5), root 0600, written durably. */
export class AcceptedHint {
  constructor(dir, { io = realIo, fsx = fs } = {}) { Object.assign(this, { dir, io, fsx }); }
  read() {
    try {
      const v = JSON.parse(this.fsx.readFileSync(join(this.dir, "accepted"), "utf8"));
      return Number.isSafeInteger(v?.gen) && v.gen >= 0 && (v.hash === null || typeof v.hash === "string") ? { gen: v.gen, hash: v.hash } : null;
    } catch { return null; }
  }
  write(v) {
    try { this.fsx.mkdirSync(this.dir, { mode: 0o700, recursive: true }); } catch (e) { if (e?.code !== "EEXIST") throw e; }
    const tmp = join(this.dir, `.accepted.${process.pid}.tmp`), buf = Buffer.from(JSON.stringify({ gen: v.gen, hash: v.hash }) + "\n");
    const fd = this.io.open(tmp, "w", 0o600);
    try { this.fsx.fchmodSync(fd, 0o600); this.io.write(fd, buf, 0, buf.length); this.io.fsync(fd); } finally { this.io.close(fd); }
    this.io.rename(tmp, join(this.dir, "accepted"));
    const dfd = this.io.open(this.dir, "r");
    try { this.io.fsync(dfd); } finally { this.io.close(dfd); }
  }
}

// ---- the intake ------------------------------------------------------------------------------------------------------

/**
 * One host's grant intake. `deps`:
 * - read(gen | null): grantReader's; verify(bytes): the executor's own grant verify ({ body, hash, digest }, throws a
 *   FleetError); verifyPair(pair): core verifyTransferReceipt under the pinned chain ({ transfer, receipt, transferHash });
 * - host: { id, fingerprint } (the certificate's); applied(): the executor's accepted { gen, hash };
 *   listedSince(agent): the gen the agent has been listed since in the accepted grant, or null;
 * - submit(op): the executor's; stream: the audit stream; files: PairFiles; hint: AcceptedHint;
 * - now, timers { set, clear }, barrier(name, info) (a test seam: an async hook at each durability point).
 */
export class GrantIntake {
  #faults = new Map(); // kind -> { gen, reason, why, at_ms }
  #summaries = new Map(); // `${gen}|${reason}` -> { count, first_at_ms, last_at_ms, timer }
  #unresolved = new Map(); // gen -> { epoch, seq } of a grant.intake intent left without a success
  #pairHealth = new Map(); // agent -> why pairOf answered null
  #stopped = false;

  constructor(deps) {
    const need = ["read", "verify", "verifyPair", "applied", "listedSince", "submit", "stream", "files", "hint"];
    for (const k of need) if (deps?.[k] === undefined) throw new Error(`grant intake: ${k} is required`);
    this.d = { now: Date.now, barrier: async () => {}, timers: { set: (ms, fn) => { const t = setTimeout(fn, ms); t.unref?.(); return t; }, clear: (t) => clearTimeout(t) }, ...deps };
  }

  /** An open grant.intake intent from an earlier epoch (recovery reports it): the next intake of `gen` reconciles it. */
  noteUnresolved(gen, ref) { if (Number.isSafeInteger(gen)) this.#unresolved.set(gen, ref); }

  stop() {
    this.#stopped = true;
    for (const [key, s] of this.#summaries) { this.d.timers.clear(s.timer); this.#flush(key); }
  }

  health() {
    return { faults: Object.fromEntries(this.#faults), pairs: Object.fromEntries(this.#pairHealth) };
  }

  // ---- faults and refusals

  #fault(kind, gen, reason, why, signed = true) {
    this.#faults.set(kind, { gen, reason, why, at_ms: this.d.now() });
    if (signed && REFUSAL_REASONS.includes(reason) && Number.isSafeInteger(gen) && gen >= 1) this.#refusal(gen, reason);
    return fail(reason, why, { kind, gen });
  }

  /** One signed refusal per (gen, reason) per window, written at the window's end with its count. */
  #refusal(gen, reason) {
    const key = `${gen}|${reason}`, t = this.d.now();
    const s = this.#summaries.get(key);
    if (s) { s.count += 1; s.last_at_ms = t; return; }
    const entry = { gen, reason, count: 1, first_at_ms: t, last_at_ms: t, timer: null };
    entry.timer = this.d.timers.set(REFUSAL_EVERY_MS, () => this.#flush(key));
    this.#summaries.set(key, entry);
  }

  #flush(key) {
    const s = this.#summaries.get(key);
    if (!s) return;
    this.#summaries.delete(key);
    this.d.stream.record({ op: "grant.intake", op_id: newOpId(), phase: "refused", gen: s.gen, reason: s.reason,
      detail: { refusal: { count: s.count, first_at_ms: s.first_at_ms, last_at_ms: s.last_at_ms } } });
  }

  // ---- the cycle

  /**
   * One cycle (d1r2 T1, d1r4 T5, d1r5 T7). Resolves { status: "current" | "applied" | "fault" | "transport" | "refused"
   * | "stopped", ..., retryAfterMs }.
   */
  async cycle() {
    if (this.#stopped) return { status: "stopped" };
    const applied = this.d.applied();
    const a = applied.gen;
    const hint = this.d.hint.read();
    if (hint !== null && hint.gen > a) {
      return { status: "fault", ...this.#fault("grant_rollback", hint.gen, "chain_fork", `the accepted file names gen ${hint.gen} above the executor's ${a}`) };
    }
    if (hint === null || hint.gen < a || hint.hash !== applied.hash) this.d.hint.write(applied);
    const first = await this.d.read(null);
    const bad = this.#answerFault(first, null);
    if (bad) return bad;
    const newest = first.read;
    const N = newest.gen;
    if (N < a) return { status: "fault", ...this.#fault("grant_rollback", N, "chain_fork", `the newest grant is gen ${N}, below the applied ${a}`) };
    if (N === a) {
      let g;
      try { g = this.d.verify(newest.grant); } catch (e) { return { status: "fault", ...this.#fault("grant_fork", a, "chain_fork", `gen ${a}: ${e?.code ?? "invalid"}`) }; }
      if (g.hash !== applied.hash) return { status: "fault", ...this.#fault("grant_fork", a, "chain_fork", `gen ${a}: another grant than the applied one`) };
      this.#faults.delete("grant_fork"); this.#faults.delete("grant_rollback");
      return { status: "current", gen: a };
    }
    for (let k = a + 1; k <= N; k++) {
      if (this.#stopped) return { status: "stopped" };
      let rk;
      if (k === N) rk = newest;
      else {
        const r = await this.d.read(k);
        const f = this.#answerFault(r, k);
        if (f) return f;
        rk = r.read;
      }
      if (rk.gen !== k) return { status: "fault", ...this.#fault("grant_fork", k, "chain_fork", `asked for gen ${k}, got ${rk.gen}`) };
      const res = await this.intake(k, rk);
      if (!res.ok) return { status: "fault", ...res };
      this.d.hint.write({ gen: k, hash: res.hash });
    }
    this.#faults.delete("grant_fork"); this.#faults.delete("grant_rollback"); this.#faults.delete("no_grant"); this.#faults.delete("pair_conflict");
    return { status: "applied", gen: N };
  }

  /** A read's failure as a cycle result, or null when it's a read. */
  #answerFault(r, k) {
    if (r?.read) return null;
    if (r?.transport) { this.#faults.set("transport", { gen: k, reason: r.transport, why: "transport", at_ms: this.d.now() }); return { status: "transport", cls: r.transport }; }
    if (r?.refused === "rate" || r?.refused === "unavailable") return { status: "transport", cls: r.refused, retryAfterMs: r.retryAfterMs ?? null };
    if (r?.refused === "no_grant" || r?.refused === "not_found") return { status: "refused", ...this.#fault("no_grant", k, "no_grant", k === null ? "no grant yet" : `gen ${k} has no grant (a gap)`, k !== null) };
    const code = r?.refused ?? "bad_form";
    return { status: "refused", ...this.#fault("service", k, code, `the service refused: ${code}`, k !== null && REFUSAL_REASONS.includes(code)) };
  }

  /** One generation k (the order in the header). Resolves { ok: true, hash } or a fault. */
  async intake(k, read) {
    const { verify, verifyPair, stream, files, submit, barrier } = this.d;
    // 1. the grant
    const applied = this.d.applied();
    if (k !== applied.gen + 1) return this.#fault("grant_fork", k, "chain_fork", `gen ${k} isn't the applied gen ${applied.gen} + 1`);
    let g;
    try { g = verify(read.grant); } catch (e) { return this.#fault("grant_fork", k, REFUSAL_REASONS.includes(e?.code) ? e.code : "chain_fork", `gen ${k}: the grant doesn't verify (${e?.code ?? "invalid"})`); }
    if (g.body.gen !== k) return this.#fault("grant_fork", k, "chain_fork", `gen ${k}: the grant names gen ${g.body.gen}`);
    const listed = new Set(g.body.agents.map((x) => x.agent));
    // 2. every pair, verified and bound to this grant, before any write
    if (!Array.isArray(read.pairs) || read.pairs.length > GRANT_PAIRS_MAX) return this.#fault("pair", k, "bad_form", "the pairs");
    const items = [], seen = new Set();
    for (const pair of read.pairs) {
      let v;
      try { v = await verifyPair(pair); } catch (e) { return this.#fault("pair", k, REFUSAL_REASONS.includes(e?.code) ? e.code : "not_granted", `a pair doesn't verify (${e?.code ?? "invalid"})`); }
      const t = v.transfer;
      if (t.grant !== g.hash) return this.#fault("pair", k, "not_granted", "a pair names another grant");
      if (t.gen !== k) return this.#fault("pair", k, "not_granted", "a pair names another gen");
      if (t.to_host !== this.d.host.id || t.to_host_key !== this.d.host.fingerprint) return this.#fault("pair", k, "not_granted", "a pair moves its agent to another host");
      if (!listed.has(t.agent)) return this.#fault("pair", k, "not_granted", "a pair's agent isn't in this grant");
      if (v.receipt?.agent !== t.agent) return this.#fault("pair", k, "not_granted", "a receipt for another agent");
      if (seen.has(t.agent)) return this.#fault("pair", k, "bad_form", "two pairs for one agent");
      seen.add(t.agent);
      const text = PairFiles.textOf(pair);
      const stored = files.read(t.agent);
      let action = "written", replaces = null;
      if (stored?.bad) return this.#fault("pair_conflict", k, "bad_form", `the stored pair for ${t.agent} is unreadable (${stored.bad})`);
      if (stored) {
        if (stored.text === text) action = "kept";
        else {
          const sg = PairFiles.genOf(stored.pair);
          if (!(Number.isSafeInteger(sg) && sg < k)) return this.#fault("pair_conflict", k, "bad_form", `the stored pair for ${t.agent} is at gen ${sg}, not below ${k}`);
          replaces = { gen: sg, transfer_digest: digest(stored.pair.transfer) };
        }
      }
      items.push({ agent: t.agent, text, action, replaces, receipt_digest: digest(pair.receipt), transfer_digest: digest(pair.transfer) });
    }
    // 3. the intent
    const opId = newOpId();
    let at;
    try {
      at = await stream.intent({ op: "grant.intake", op_id: opId, phase: "authorized", gen: k, detail: { grant_hash: g.hash, pairs_digest: pairsDigest(items) } });
    } catch (e) { return this.#fault("audit", k, e?.code ?? "audit_unavailable", "the intake's intent isn't durable", false); }
    const intent = { epoch: at.epoch, seq: at.seq };
    const terminal = async (phase, extra = {}) => stream.append("sb.audit-event.v1", { op: "grant.intake", op_id: opId, phase, gen: k, intent, ...extra }, { durable: true });
    // 4. the writes, then one directory fsync
    const writes = items.filter((x) => x.action === "written");
    let wrote = false;
    try {
      if (writes.length > 0) files.ensure();
      for (const x of writes) {
        await barrier("before_pair_write", { agent: x.agent });
        wrote = true;
        files.stage(x.agent, x.text);
        await barrier("after_pair_rename", { agent: x.agent });
      }
      if (writes.length > 0) files.syncDir();
      await barrier("after_dir_fsync", { gen: k });
    } catch (e) {
      this.#unresolved.set(k, intent);
      await terminal(wrote ? "unknown_effect" : "failed_no_effect", { reason: "bad_form" }).catch(() => {});
      return this.#fault("pair_write", k, "audit_unavailable", `a pair write failed (${e?.code ?? e?.message})`, false);
    }
    // 5. the pair.store records, one fsync
    const reconciles = this.#unresolved.get(k) ?? null;
    try {
      await stream.appendAll(items.map((x) => ({ op: "pair.store", op_id: newOpId(), phase: "succeeded", gen: k, agent: x.agent, intent,
        detail: { pair: { action: x.action, receipt_digest: x.receipt_digest, transfer_digest: x.transfer_digest, replaces: x.replaces }, ...(reconciles ? { reconciles } : {}) } })));
      await barrier("after_pair_store", { gen: k });
      // 6. the terminal
      await terminal("succeeded", reconciles ? { detail: { reconciles } } : {});
      await barrier("after_terminal", { gen: k });
    } catch (e) {
      this.#unresolved.set(k, intent);
      return this.#fault("audit", k, e?.code ?? "audit_unavailable", "the pair.store records or the terminal aren't durable", false);
    }
    this.#unresolved.delete(k);
    // 7. submit
    let r;
    try { r = await submit({ kind: "grant", bytes: read.grant }); } catch (e) { return this.#fault("submit", k, e?.code ?? "in_progress", "the executor's submit failed", false); }
    if (r?.status !== "applied" && r?.status !== "reapplied") return this.#fault("submit", k, r?.reason ?? r?.status ?? "in_progress", `the executor answered ${r?.status}`, false);
    const now = this.d.applied();
    if (now.gen !== k || now.hash !== g.hash) return this.#fault("submit", k, "chain_fork", "the executor's applied grant isn't this one", false);
    return { ok: true, hash: g.hash };
  }

  // ---- recovery and pairOf

  /**
   * At start, after the stream verified (d1r6, d1r7): each stored pair the index doesn't match for its current
   * (agent, gen, digests), with no NEWER record and no same-gen conflict, is recorded `kept` only if it re-verifies and
   * binds to L, the grant the agent has been listed in since, which the stream shows applied. Resolves the agents
   * reconciled.
   */
  async recover() {
    const { files, stream, verifyPair, listedSince } = this.d;
    const out = [];
    const keep = [];
    for (const agent of files.list()) {
      const s = files.read(agent);
      if (!s || s.bad) { this.#pairHealth.set(agent, s?.bad ?? "absent"); continue; }
      const gen = PairFiles.genOf(s.pair), rd = digest(s.pair.receipt), td = digest(s.pair.transfer);
      const rec = stream.latestPairStore(agent);
      if (rec && rec.gen === gen && rec.receipt_digest === rd && rec.transfer_digest === td) continue;
      if (rec && (rec.gen > gen || rec.gen === gen)) { this.#pairHealth.set(agent, "pair_conflict"); continue; }
      let v;
      try { v = await verifyPair(s.pair); } catch { this.#pairHealth.set(agent, "pair_conflict"); continue; }
      const t = v.transfer, L = listedSince(agent), Lhash = Number.isSafeInteger(L) ? stream.appliedGrantHash(L) : null;
      const binds = t.agent === agent && v.receipt?.agent === agent && Lhash !== null && t.grant === Lhash && t.gen === L
        && t.to_host === this.d.host.id && t.to_host_key === this.d.host.fingerprint;
      if (!binds) { this.#pairHealth.set(agent, "pair_conflict"); continue; }
      const reconciles = this.#unresolved.get(gen) ?? null;
      keep.push({ op: "pair.store", op_id: newOpId(), phase: "succeeded", gen, agent,
        detail: { pair: { action: "kept", receipt_digest: rd, transfer_digest: td, replaces: null }, ...(reconciles ? { reconciles } : {}) } });
      out.push(agent);
    }
    if (keep.length > 0) await stream.appendAll(keep);
    return out;
  }

  /** The stored pair for `agent`, only when it matches the latest pair.store; null otherwise (health says why). */
  pairOf(agent) {
    const s = this.d.files.read(agent);
    if (s === null) return null;
    if (s.bad) { this.#pairHealth.set(agent, s.bad); return null; }
    const rec = this.d.stream.latestPairStore(agent);
    if (rec === null) { this.#pairHealth.set(agent, "no pair.store record"); return null; }
    const gen = PairFiles.genOf(s.pair);
    if (rec.gen !== gen || rec.receipt_digest !== digest(s.pair.receipt) || rec.transfer_digest !== digest(s.pair.transfer)) {
      this.#pairHealth.set(agent, `the stored pair differs from the latest record (gen ${rec.gen})`);
      return null;
    }
    this.#pairHealth.delete(agent);
    return s.pair;
  }
}

// ---- the poller ------------------------------------------------------------------------------------------------------

/**
 * The timer around the intake (d1 §1, d1r2 N1/N2): one cycle at a time; every POLL_MS, or after a backoff that doubles
 * from POLL_MS to BACKOFF_MAX_MS (a 429's retry_after honoured); nudge() during a cycle gives exactly one more cycle
 * right after it. stop() ends it: no read starts afterwards.
 */
export class GrantPoller {
  #running = null; #again = false; #timer = null; #life = 0; #backoff = POLL_MS;

  constructor(intake, { timers = { set: (ms, fn) => { const t = setTimeout(fn, ms); t.unref?.(); return t; }, clear: (t) => clearTimeout(t) }, pollMs = POLL_MS } = {}) {
    Object.assign(this, { intake, timers, pollMs });
    this.#backoff = pollMs;
  }

  start({ first = 0 } = {}) { this.#arm(++this.#life, first); }

  stop() {
    this.#life += 1;
    if (this.#timer !== null) this.timers.clear(this.#timer);
    this.#timer = null;
    this.intake.stop();
    return this.#running ?? Promise.resolve();
  }

  nudge() {
    if (this.#running) { this.#again = true; return; }
    this.#arm(this.#life, 0);
  }

  #arm(life, ms) {
    if (this.#timer !== null) this.timers.clear(this.#timer);
    this.#timer = this.timers.set(ms, () => { this.#timer = null; this.#run(life); });
  }

  async #run(life) {
    if (life !== this.#life || this.#running) return;
    this.#running = this.intake.cycle().catch(() => ({ status: "transport", cls: "error" }));
    const r = await this.#running;
    this.#running = null;
    if (life !== this.#life) return;
    let next = this.pollMs;
    if (r.status === "transport") {
      next = Math.min(BACKOFF_MAX_MS, this.#backoff);
      this.#backoff = Math.min(BACKOFF_MAX_MS, this.#backoff * 2);
      if (Number.isSafeInteger(r.retryAfterMs) && r.retryAfterMs > next) next = r.retryAfterMs;
    } else this.#backoff = this.pollMs;
    if (this.#again) { this.#again = false; next = 0; }
    this.#arm(life, next);
  }
}
