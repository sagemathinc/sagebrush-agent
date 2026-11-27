// The host audit stream (host audit stream design d1 to d1r5; supervisor-freeze r3.1 §8.1; the audit freeze r2 §3,
// §3.1, §3.2, §4, §6.2): the durable, signed, chained record of the daemon's authoritative effects, and the three
// executor adapters over it (appendIntent, openIntents, audit).
//
// On disk, in `dir` (/var/lib/sagebrush/audit, root 0700):
// - `stream`: the stream id (written once, exclusively);
// - `epoch-<n>.log`: one append-only file per epoch, each record ONE line: its envelope's canonical bytes and `\n`;
// - `checkpoints/<epoch>-<seq>.json`: each checkpoint record's bytes, written durably;
// - `reserve`: the bytes kept for narrowing (§8.1's emergency reserve), shrunk as narrowing uses them.
// Every record (sb.audit-event.v1, sb.audit-checkpoint.v1, sb.audit-continuity.v1) is signed by the host
// certificate's sign_key and carries one binding prefix { v, fleet, aud, host, cert, chain_seq, stream, epoch, seq,
// prev, at_ms }. Within an epoch seq is contiguous from 0 and every record's `prev` is the SHA-256 of its predecessor's
// signed bytes. An epoch's seq 0 is its continuity record:
// - genesis (only when neither the stream file nor any log exists): prev, prior_checkpoint and prior_last null;
// - restart_unanchored (every later start until an externally trusted checkpoint exists): prior_checkpoint null,
//   prior_last = the prior epoch's last verified record, prev = its digest;
// - restart (only with an externally trusted checkpoint, supplied by the upload-and-ack slice): all three set.
// LOCAL CHECKPOINTS ARE NOT ROLLBACK AUTHORITY (d1r1): they live in this same replaceable directory, so a stream rolled
// back together with them is locally invisible. Until an external checkpoint exists the stream is UNANCHORED, at
// genesis too: completeness is unknown, health is degraded_audit with the reason UNANCHORED, and every WIDENING intent
// is refused audit_unavailable. Narrowing (pause, stop, revoke, expiry, the local stop) is never blocked and never
// awaited: normal append, else the reserve, else held in memory and appended later with `late`. Held records are
// volatile: a crash before they are appended loses them, and no later record ever claims a durable authorization for
// them (d1r4).
// Open (torn vs corrupt, d1r1/d1r2): only the LAST epoch's final unterminated line is a torn append (truncated, the
// truncation fsynced before anything new); any terminated record that fails its encoding, signature, schema, stream,
// epoch, seq, prev or continuity rules, an empty or over-size line, an unterminated line in an earlier epoch, an epoch
// gap, or a stream file without logs (or logs without it) is fail_closed: the bytes are kept, widening is refused.

import * as fs from "node:fs";
import { randomBytes } from "node:crypto";
import { join } from "node:path";
import { FleetError, refuse, newId, b64, sha256b64, enc } from "../bytes.mjs";
import { seal, open as openEnvelope, signedBytes } from "../envelope.mjs";
import { bodyValidator } from "../schemas.mjs";
import { AUDIT_DIR } from "./names.mjs";

export const AUDIT_LIMITS = Object.freeze({
  cap: 2 * 2 ** 30, reserve: 64 * 2 ** 20, record: 8192, text: 256,
  intentMs: 2000, commitMs: 1000, checkpointEvery: 1000, checkpointMs: 60_000, heldMax: 4096,
});
/** The one health reason while no externally trusted checkpoint anchors the stream (genesis and restarts alike). */
export const UNANCHORED = "unanchored: awaiting external checkpoint";
const TYPES = Object.freeze({ "sb.audit-event.v1": "audit-event", "sb.audit-checkpoint.v1": "audit-checkpoint", "sb.audit-continuity.v1": "audit-continuity" });
const EPOCH_FILE = /^epoch-(0|[1-9][0-9]{0,8})\.log$/;
const PHASES = new Set(["requested", "refused", "authorized", "started", "succeeded", "failed_no_effect", "unknown_effect", "reconciled_succeeded", "reconciled_no_effect", "revoked", "expired"]);
const TERMINAL = new Set(["refused", "succeeded", "failed_no_effect", "unknown_effect", "reconciled_succeeded", "reconciled_no_effect"]);
/** Narrowing kinds (d1r2 T3e): never blocked by the stream. Everything else is widening. */
export const NARROWING_OPS = Object.freeze(new Set(["agent.pause", "agent.stop", "agent.revoke", "grant.expire", "local.stop"]));
export const isNarrowing = (op, phase) => NARROWING_OPS.has(op) || phase === "revoked" || phase === "expired";

const failure = (code, why) => Object.assign(new FleetError(code, `audit: ${why}`), { audit: true });
const keyOf = (op, gen, agent) => `${op}|${gen ?? ""}|${agent ?? ""}`;

/**
 * Open (or create) the stream and verify it whole. `id`: { fleet, aud, host, cert (the host certificate's hash),
 * chainSeq() (the pinned head now), signer (the certified sign key: keyFromSeed's), keyFor(certHash, chainSeq) (the
 * raw public key of the certificate a record names, valid at that chain_seq; throws to refuse) }. Options: dir, limits,
 * now, fsx, io ({ open, write, fsync, close } over fds: test seams for the hung fsync and failures), barrier(name),
 * external (an externally trusted checkpoint { epoch, seq, digest }, or null: none exists before the upload slice),
 * trustGenesis (TEST ONLY: treat a genesis epoch as anchored so widening paths can be exercised; no production caller).
 */
export async function openAuditStream(id, opts = {}) {
  const s = new AuditStream(id, opts);
  await s.open();
  return s;
}

const realIo = Object.freeze({
  open: (p, flags, mode) => fs.promises.open(p, flags, mode),
  write: (fh, buf) => fh.write(buf, 0, buf.length, null),
  fsync: (fh) => fh.datasync(),
  close: (fh) => fh.close(),
});

export class AuditStream {
  #id; #o; #dir; #L; #fh = null; #tail = Promise.resolve();
  #stream = null; #epoch = -1; #seq = -1; #prev = null; #logBytes = 0; #reserveLeft = 0; #atCap = false;
  #failed = null; #anchored = false; #sinceCheckpoint = 0; #lastCheckpointAt = 0; #lastCheckpoint = null;
  #openIntents = new Map(); // key -> { epoch, seq, op_id, op, gen, agent }
  #recovered = []; // intents left open by earlier epochs (recovery reports them once)
  #held = []; #heldIds = new Set();
  #queue = []; #pump = null; // the records handed over without waiting, and their one writer (the held replay's owner)
  #broken = null; // a write or fsync failed in this epoch: nothing more is appended to it (a partial line may be there)
  #cause = null; // the code of the last failure to take a record: audit_full (capacity) or audit_unavailable
  #syncSince = null; // when the fsync in progress started (a hung fsync is audit_timeout in health)
  #pending = []; #timer = null; #closed = false; #inflight = new Set();
  #pairStore = new Map(); // agent -> the latest pair.store's { gen, receipt_digest, transfer_digest } (slice B's index)
  counters = { refusals: 0, unrecorded: 0, dropped: 0, fsync_failures: 0, write_failures: 0, uncertain: 0, lost_terminals: 0, bad_records: 0, checkpoints_skipped: 0 };

  constructor(id, { dir = AUDIT_DIR, limits = {}, now = Date.now, fsx = fs, io = realIo, barrier = async () => {}, external = null, trustGenesis = false } = {}) {
    this.#id = id; this.#dir = dir; this.#L = { ...AUDIT_LIMITS, ...limits };
    this.#o = { now, fsx, io, barrier, external, trustGenesis };
  }

  // ---- open and verify -----------------------------------------------------------------------------------------------

  async open() {
    const { fsx } = this.#o;
    privateDir(fsx, this.#dir);
    const names = fsx.readdirSync(this.#dir);
    const logs = names.filter((n) => n.startsWith("epoch-"));
    const hasStream = names.includes("stream");
    if (!hasStream && logs.length === 0) return this.#genesis();
    if (!hasStream || logs.length === 0) return this.#failClosed(hasStream ? "the stream file has no epoch logs" : "epoch logs without the stream file");
    if (logs.some((n) => !EPOCH_FILE.test(n))) return this.#failClosed("an epoch file of another name");
    const epochs = logs.map((n) => Number(EPOCH_FILE.exec(n)[1])).sort((a, b) => a - b);
    if (epochs.some((e, i) => e !== i)) return this.#failClosed("the epochs aren't contiguous from 0");
    this.#stream = fsx.readFileSync(join(this.#dir, "stream"), "utf8").trim();
    if (!/^[a-z2-7]{25}[aeimquy4]$/.test(this.#stream)) return this.#failClosed("the stream id isn't an id");
    let last = null;
    for (const e of epochs) {
      const r = await this.#verifyEpoch(e, e === epochs.at(-1), last);
      if (r === null) return; // (fail_closed already)
      last = r;
    }
    this.#logBytes = epochs.reduce((n, e) => n + fsx.statSync(join(this.#dir, `epoch-${e}.log`)).size, 0);
    this.#reserveLeft = this.#readReserve();
    this.#recovered = [...this.#openIntents.values()];
    this.#openIntents.clear();
    return this.#startEpoch(epochs.at(-1) + 1, last);
  }

  /** Verify one epoch's file. Returns its last record { seq, digest } or null after failing closed. */
  async #verifyEpoch(e, isLast, priorLast) {
    const { fsx, io } = this.#o;
    const p = join(this.#dir, `epoch-${e}.log`);
    let bytes = fsx.readFileSync(p);
    const end = bytes.lastIndexOf(0x0a);
    if (end !== bytes.length - 1) {
      // An unterminated final line: torn only in the LAST epoch, truncated durably before anything new is written.
      if (!isLast) return this.#failClosed(`an unterminated line in epoch ${e}, which isn't the last`), null;
      const fh = await io.open(p, "r+");
      try { await fh.truncate(end + 1); await io.fsync(fh); } finally { await io.close(fh); }
      await this.#o.barrier("after_torn_truncate");
      this.counters.bad_records += 1;
      bytes = bytes.subarray(0, end + 1);
    }
    let seq = -1, prev = null, lastRec = null;
    let start = 0;
    while (start < bytes.length) {
      const nl = bytes.indexOf(0x0a, start);
      const line = bytes.subarray(start, nl);
      start = nl + 1;
      if (line.length === 0) return this.#failClosed(`an empty line in epoch ${e}`), null;
      if (line.length + 1 > this.#L.record) return this.#failClosed(`an over-size line in epoch ${e}`), null;
      let r;
      try { r = await this.#verifyRecord(line); } catch (err) { return this.#failClosed(`epoch ${e} seq ${seq + 1}: ${err.message}`), null; }
      const b = r.body;
      if (b.stream !== this.#stream || b.epoch !== e || b.seq !== seq + 1) return this.#failClosed(`epoch ${e}: a stream, epoch or seq break`), null;
      if (b.seq === 0) {
        if (r.type !== "sb.audit-continuity.v1") return this.#failClosed(`epoch ${e} doesn't open with continuity`), null;
        const why = this.#checkContinuity(b, e, priorLast);
        if (why) return this.#failClosed(`epoch ${e}: ${why}`), null;
      } else {
        if (r.type === "sb.audit-continuity.v1") return this.#failClosed(`epoch ${e}: continuity past seq 0`), null;
        if (b.prev !== prev) return this.#failClosed(`epoch ${e} seq ${b.seq}: prev isn't its predecessor`), null;
        if (r.type === "sb.audit-checkpoint.v1" && (b.covers.seq !== b.seq - 1 || b.covers.digest !== prev)) return this.#failClosed(`epoch ${e} seq ${b.seq}: a checkpoint covering another record`), null;
      }
      if (r.type === "sb.audit-event.v1") this.#index(b, e);
      if (r.type === "sb.audit-checkpoint.v1") this.#lastCheckpoint = { epoch: e, seq: b.seq, digest: r.digest };
      seq = b.seq; prev = r.digest; lastRec = { epoch: e, seq, digest: r.digest };
    }
    if (lastRec === null) return this.#failClosed(`epoch ${e} is empty`), null;
    this.#seq = seq; this.#prev = prev;
    return lastRec;
  }

  /** The continuity rules at seq 0 (d1r3): exact nullness, prior_last = the prior epoch's actual last record. */
  #checkContinuity(b, e, priorLast) {
    if (b.reason === "genesis") {
      if (e !== 0 || b.prev !== null || b.prior_checkpoint !== null || b.prior_last !== null) return "a genesis that isn't the first epoch's or isn't all null";
      return null;
    }
    if (e === 0 || priorLast === null) return "a restart with no prior epoch";
    const pl = b.prior_last;
    if (pl === null || pl.epoch !== priorLast.epoch || pl.seq !== priorLast.seq || pl.digest !== priorLast.digest) return "prior_last isn't the prior epoch's last record";
    if (b.reason === "restart_unanchored") {
      if (b.prior_checkpoint !== null || b.prev !== pl.digest) return "an unanchored restart with a checkpoint, or prev not its prior_last";
      return null;
    }
    // restart: only with an externally trusted checkpoint, which the verifier must hold itself.
    const x = this.#o.external, pc = b.prior_checkpoint;
    if (x === null || pc === null || pc.epoch !== x.epoch || pc.seq !== x.seq || pc.digest !== x.digest || b.prev !== pc.digest) return "a restart not bound to the externally trusted checkpoint";
    return null;
  }

  /** Verify one record's bytes: the envelope (host signer, the named certificate's key at its chain_seq), its schema. */
  async #verifyRecord(line) {
    const id = this.#id;
    const r = await openEnvelope(line, {
      aud: id.aud, fleet: id.fleet,
      resolveKey: (signer, type, body) => {
        if (!Object.hasOwn(TYPES, type) || signer?.kind !== "host" || signer.id !== id.host) refuse("bad_signature", "not this host's audit record");
        return id.keyFor(body?.cert, body?.chain_seq);
      },
    });
    bodyValidator(TYPES[r.type])(r.body);
    if (r.body.host !== id.host) refuse("bad_form", "another host");
    return { type: r.type, body: r.body, digest: sha256b64(r.signed) };
  }

  /** Index an event read back: intents and their terminals; the latest pair.store per agent. */
  #index(b, e) {
    if (b.phase === "authorized") this.#openIntents.set(`${e}:${b.seq}`, { epoch: e, seq: b.seq, op_id: b.op_id, op: b.op, gen: b.gen, agent: b.agent });
    if (b.intent) this.#openIntents.delete(`${b.intent.epoch}:${b.intent.seq}`);
    if (b.op === "pair.store" && b.detail?.pair && b.agent) this.#pairStore.set(b.agent, { gen: b.gen, receipt_digest: b.detail.pair.receipt_digest, transfer_digest: b.detail.pair.transfer_digest });
  }

  #failClosed(why) {
    this.#failed = why;
    this.#anchored = false;
  }

  /** A write or fsync failed: fail closed, and append nothing more to this epoch. */
  #breakEpoch(why) {
    this.#broken ??= why;
    this.#cause = "audit_unavailable";
    this.#failClosed(why);
  }

  // ---- epochs --------------------------------------------------------------------------------------------------------

  async #genesis() {
    const { fsx } = this.#o;
    this.#stream = newId();
    const fd = fsx.openSync(join(this.#dir, "stream"), fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL, 0o600);
    try { fsx.writeSync(fd, `${this.#stream}\n`); fsx.fsyncSync(fd); } finally { fsx.closeSync(fd); }
    this.#writeReserve(this.#L.reserve);
    syncDir(fsx, this.#dir);
    return this.#startEpoch(0, null);
  }

  async #startEpoch(e, priorLast) {
    const x = this.#o.external;
    let reason, prev, priorCheckpoint = null;
    if (e === 0) { reason = "genesis"; prev = null; }
    else if (x !== null) { reason = "restart"; priorCheckpoint = { epoch: x.epoch, seq: x.seq, digest: x.digest }; prev = x.digest; }
    else { reason = "restart_unanchored"; prev = priorLast.digest; }
    this.#epoch = e; this.#seq = -1; this.#prev = prev;
    this.#fh = await this.#o.io.open(join(this.#dir, `epoch-${e}.log`), "a", 0o600);
    syncDir(this.#o.fsx, this.#dir);
    // (the continuity record may use the reserve: one bounded record, so narrowing always has a stream, d1r2 T4b)
    await this.append("sb.audit-continuity.v1", { reason, prior_checkpoint: priorCheckpoint, prior_last: priorLast }, { narrowing: true, durable: true });
    this.#anchored = this.#failed === null && (reason === "restart" || (reason === "genesis" && this.#o.trustGenesis === true));
    this.#lastCheckpointAt = this.#o.now();
  }

  // ---- the writer ----------------------------------------------------------------------------------------------------

  /** Serialized: each append in order, after every earlier one. */
  #serial(fn) {
    const p = this.#tail.then(fn);
    this.#tail = p.catch(() => {});
    return p;
  }

  /**
   * Append one record, serialized. `durable`: wait for its own fsync (intents) instead of the group commit.
   * `narrowing`: it may use the reserve, and it is refused only by a failure of the disk itself.
   */
  async append(type, own, { durable = false, narrowing = false } = {}) {
    // The write is serialized; waiting for durability is NOT (a commit queued behind a waiting write would deadlock).
    const w = await this.#serial(() => this.#writeOne(type, own, { narrowing }));
    if (durable) await this.#serial(() => this.#sync());
    else await w.committed;
    if (type === "sb.audit-event.v1") await this.#maybeCheckpoint();
    return w.at;
  }

  /** Write one record (no fsync). `committed`: settles when a later fsync covers it. */
  async #writeOne(type, own, { narrowing }) {
    if (this.#closed) throw failure("audit_unavailable", "the stream is closed");
    if (this.#broken !== null || this.#fh === null) throw failure("audit_unavailable", `the stream can't be written: ${this.#broken ?? this.#failed ?? "not open"}`);
    if (this.#failed !== null && !narrowing) throw failure("audit_unavailable", `the stream failed closed: ${this.#failed}`);
    const id = this.#id;
    const body = { v: 1, fleet: id.fleet, aud: id.aud, host: id.host, cert: id.cert, chain_seq: id.chainSeq(), stream: this.#stream, epoch: this.#epoch, seq: this.#seq + 1, prev: this.#prev, at_ms: this.#o.now(), ...own };
    if (type === "sb.audit-checkpoint.v1") body.covers = { seq: this.#seq, digest: this.#prev };
    try { bodyValidator(TYPES[type])(body); } catch { this.counters.bad_records += 1; throw failure("bad_form", "a record outside its closed body"); }
    const rf = body.detail?.refusal;
    if (rf && rf.first_at_ms > rf.last_at_ms) { this.counters.bad_records += 1; throw failure("bad_form", "a refusal summary's times out of order"); }
    const signer = { kind: "host", id: id.host, alg: "ed25519", key: id.signer.key };
    const bytes = await seal(type, signer, body, id.signer);
    const line = Buffer.concat([Buffer.from(bytes), Buffer.from("\n")]);
    if (line.length > this.#L.record) { this.counters.bad_records += 1; throw failure("bad_form", "a record over its size"); }
    // The cap: ordinary records stop at cap - reserve; narrowing may go on to the cap, out of the reserve.
    const room = this.#L.cap - this.#L.reserve - this.#logBytes;
    if (line.length > room) {
      this.#atCap = true; // (from here widening is refused: the host reports reserve_only)
      if (!narrowing) throw failure("audit_full", "the stream is at its cap");
      if (line.length > this.#reserveLeft) throw failure("audit_full", "the reserve is exhausted");
      this.#writeReserve(this.#reserveLeft - line.length);
    }
    await this.#o.barrier("before_append", { type, seq: body.seq });
    // The whole line (H1): a short write loops. A failure before any byte is written leaves nothing on disk, so the record
    // is simply not taken (a narrowing one is held and retried; ENOSPC is capacity). A failure or zero progress AFTER
    // some bytes breaks the epoch: a partial line may be on disk (the next open truncates it as the last epoch's torn
    // tail), so nothing more is appended to it.
    let off = 0;
    try {
      while (off < line.length) {
        const r = await this.#o.io.write(this.#fh, line.subarray(off));
        const n = typeof r === "number" ? r : r?.bytesWritten;
        if (!Number.isSafeInteger(n) || n <= 0 || n > line.length - off) throw Object.assign(new Error(n === 0 ? "no progress" : "a bad write count"), { code: "EIO" });
        off += n;
      }
    } catch (e) {
      this.counters.write_failures += 1;
      if (off === 0) throw failure(e?.code === "ENOSPC" ? "audit_full" : "audit_unavailable", `write: ${e?.code ?? e?.message}`);
      this.#breakEpoch(`write: ${e?.code ?? e?.message} after ${off} of ${line.length} bytes`);
      throw failure("audit_unavailable", this.#broken);
    }
    this.#logBytes += line.length;
    this.#seq = body.seq;
    const digest = sha256b64(signedBytes(type, signer, body));
    this.#prev = digest;
    if (type === "sb.audit-event.v1") this.#index(body, this.#epoch);
    const at = { epoch: this.#epoch, seq: body.seq, digest };
    // (registered right after the write: the next fsync to START covers it)
    const committed = new Promise((resolve, reject) => { this.#pending.push({ resolve, reject }); });
    committed.catch(() => {});
    this.#armCommit();
    return { at, committed };
  }

  /** One fsync; it settles exactly the records written before it started. */
  async #sync() {
    const batch = this.#pending.splice(0);
    if (this.#broken !== null) { const err = failure("audit_unavailable", this.#broken); for (const w of batch) w.reject(err); throw err; }
    this.#syncSince = this.#o.now();
    try { await this.#o.io.fsync(this.#fh); } catch (e) {
      this.counters.fsync_failures += 1;
      // (after a failed fsync nothing written since the last good one can be trusted: its records are uncertain, never
      // re-appended, and the epoch takes no more writes)
      this.counters.uncertain += batch.length;
      this.#breakEpoch(`fsync: ${e?.code ?? e?.message}`);
      const err = failure("audit_unavailable", this.#broken);
      for (const w of batch) w.reject(err);
      throw err;
    } finally { this.#syncSince = null; }
    for (const w of batch) w.resolve();
  }

  /** The group commit: one fsync at most commitMs after the first record waiting for it. */
  #armCommit() {
    if (this.#timer !== null) return;
    this.#timer = setTimeout(() => {
      this.#timer = null;
      if (this.#pending.length > 0) this.#serial(() => this.#sync()).catch(() => {});
    }, this.#L.commitMs);
    this.#timer.unref?.();
  }

  async #maybeCheckpoint() {
    this.#sinceCheckpoint += 1;
    if (this.#sinceCheckpoint < this.#L.checkpointEvery && this.#o.now() - this.#lastCheckpointAt < this.#L.checkpointMs) return;
    // At the cap minus the reserve, checkpoints stop (counted): they never eat the reserve (d1r2 T4c).
    if (this.#L.cap - this.#L.reserve - this.#logBytes < this.#L.record) { this.counters.checkpoints_skipped += 1; return; }
    this.#sinceCheckpoint = 0;
    this.#lastCheckpointAt = this.#o.now();
    let at;
    try { at = await this.append("sb.audit-checkpoint.v1", {}, { durable: true }); } catch { this.counters.checkpoints_skipped += 1; return; }
    this.#lastCheckpoint = at;
    const dir = join(this.#dir, "checkpoints");
    privateDir(this.#o.fsx, dir);
    writeFileDurable(this.#o.fsx, dir, `${at.epoch}-${at.seq}.json`, JSON.stringify(at) + "\n");
  }

  // ---- the reserve ---------------------------------------------------------------------------------------------------

  #readReserve() {
    try { return this.#o.fsx.statSync(join(this.#dir, "reserve")).size; } catch { return 0; }
  }

  #writeReserve(size) {
    const { fsx } = this.#o;
    const p = join(this.#dir, "reserve");
    const fd = fsx.openSync(p, fs.constants.O_WRONLY | fs.constants.O_CREAT, 0o600);
    try {
      const cur = fsx.fstatSync(fd).size;
      if (size < cur) fsx.ftruncateSync(fd, size);
      else {
        // (written, not sparse: the reserve must hold real blocks)
        const chunk = Buffer.alloc(Math.min(1 << 20, Math.max(size - cur, 1)));
        for (let off = cur; off < size; off += chunk.length) fsx.writeSync(fd, chunk, 0, Math.min(chunk.length, size - off), off);
      }
      fsx.fsyncSync(fd);
    } finally { fsx.closeSync(fd); }
    this.#reserveLeft = size;
  }

  // ---- the adapters' entry points ------------------------------------------------------------------------------------

  /**
   * A widening intent: durable within min(ms, intentMs), or a refusal (audit_unavailable, audit_timeout, audit_full),
   * and the effect never starts. Unanchored, it is refused (the health reason says why).
   */
  async intent(own, ms = this.#L.intentMs) {
    if (!this.#anchored) { this.counters.refusals += 1; throw failure("audit_unavailable", this.#failed !== null ? `failed closed: ${this.#failed}` : UNANCHORED); }
    const bound = Math.min(ms, this.#L.intentMs);
    let timer;
    const p = this.append("sb.audit-event.v1", own, { durable: true });
    const timeout = new Promise((_, reject) => { timer = setTimeout(() => reject(failure("audit_timeout", "the intent wasn't durable in time")), bound); });
    try { return await Promise.race([p, timeout]); } catch (e) {
      this.counters.refusals += 1;
      if (e?.code === "audit_timeout") {
        // (if the intent lands later, its effect provably never started: it is closed as failed_no_effect)
        p.then((at) => this.append("sb.audit-event.v1", { op: own.op, op_id: own.op_id, phase: "failed_no_effect", ...(own.gen ? { gen: own.gen } : {}), ...(own.agent ? { agent: own.agent } : {}), intent: { epoch: at.epoch, seq: at.seq } })).catch(() => {});
      }
      throw e instanceof FleetError ? e : failure("audit_unavailable", String(e?.message ?? e));
    } finally { clearTimeout(timer); }
  }

  /**
   * A record handed over without waiting (audit(), narrowing, recovery's closures). It is queued and written by ONE pump
   * (H2), in order, after every held record: a narrowing record the stream can't take is held (bounded) and written
   * later with `late`, counted once; a widening terminal it can't take is counted lost (lost_terminals). The pump writes
   * without waiting for the fsync (the group commit settles it; a failed fsync breaks the epoch), so a hung disk never
   * holds back the caller.
   */
  record(own, { narrowing = false } = {}) {
    this.#queue.push({ own, narrowing });
    this.#runPump();
  }

  #runPump() {
    if (this.#pump !== null) return;
    const p = (async () => {
      while (this.#queue.length > 0) {
        const { own, narrowing } = this.#queue.shift();
        const clear = await this.#flushHeld();
        const r = clear ? await this.#tryWrite(own, narrowing, false) : "fail";
        if (r !== "fail") continue; // ("bad": refused at the writer, counted there)
        if (!narrowing) { this.counters.lost_terminals += 1; continue; }
        this.#hold(own);
      }
    })().finally(() => { this.#pump = null; if (this.#queue.length > 0) this.#runPump(); });
    this.#pump = p;
    this.#inflight.add(p);
    p.finally(() => this.#inflight.delete(p));
  }

  /** The held records, oldest first; false when the first can't be written yet (it stays first). */
  async #flushHeld() {
    while (this.#held.length > 0) {
      const h = this.#held[0];
      const r = await this.#tryWrite(h, true, true);
      if (r === "fail") return false;
      this.#held.shift(); this.#heldIds.delete(h.op_id);
    }
    return true;
  }

  /** One write through the serial queue: "ok", "bad" (refused at the writer: never retried), or "fail" (the cause kept). */
  async #tryWrite(own, narrowing, late) {
    const rec = late ? { ...own, detail: { ...(own.detail ?? {}), late: true } } : own;
    try {
      await this.#serial(() => this.#writeOne("sb.audit-event.v1", rec, { narrowing }));
      this.#maybeCheckpoint().catch(() => {});
      return "ok";
    } catch (e) {
      if (e?.code === "bad_form") return "bad";
      this.#cause = e?.code === "audit_full" ? "audit_full" : "audit_unavailable";
      return "fail";
    }
  }

  #hold(own) {
    if (this.#heldIds.has(own.op_id)) return;
    this.counters.unrecorded += 1;
    if (this.#held.length >= this.#L.heldMax) { this.counters.dropped += 1; return; }
    this.#held.push(own); this.#heldIds.add(own.op_id);
  }

  /** Every record handed over so far has been appended (or held): the writer is idle. */
  async drain() {
    // (a record waiting for the group commit is committed now, rather than after its window)
    while (this.#inflight.size > 0 || this.#pending.length > 0) {
      if (this.#pending.length > 0) {
        if (this.#timer !== null) { clearTimeout(this.#timer); this.#timer = null; }
        await this.#serial(() => this.#sync()).catch(() => {});
      }
      await new Promise((r) => setImmediate(r));
    }
    await this.#tail;
  }

  /** Intents left open by earlier epochs (each closed now as unknown_effect, once). */
  recoveredIntents() { const r = this.#recovered; this.#recovered = []; return r; }
  /** The latest pair.store for an agent from the verified stream (slice B's index), or null. */
  latestPairStore(agent) { return this.#pairStore.get(agent) ?? null; }

  health() {
    // The state and its code (H5): failed closed or unanchored is audit_unavailable; an fsync in progress past the intent
    // deadline is audit_timeout; only a capacity failure is reserve_only with audit_full. Any record not taken (held,
    // lost or uncertain) keeps the host out of ok.
    const hung = this.#syncSince !== null && this.#o.now() - this.#syncSince >= this.#L.intentMs;
    const capacity = this.#cause === "audit_full" || this.#atCap;
    const state = this.#failed !== null ? "fail_closed" : !this.#anchored ? "degraded_audit" : hung ? "degraded_audit"
      : this.#held.length || capacity || this.counters.lost_terminals ? (capacity ? "reserve_only" : "degraded_audit") : "ok";
    const code = state === "ok" ? null : state === "reserve_only" ? "audit_full" : hung && this.#failed === null && this.#anchored ? "audit_timeout" : "audit_unavailable";
    return {
      state, code, reason: this.#failed !== null ? `failed closed: ${this.#failed}` : !this.#anchored ? UNANCHORED : hung ? "an fsync is past its deadline" : null,
      completeness: this.#anchored ? "anchored" : "unknown", epoch: this.#epoch, last_seq: this.#seq,
      last_checkpoint: this.#lastCheckpoint, reserve_free_pct: this.#L.reserve ? Math.floor((100 * this.#reserveLeft) / this.#L.reserve) : 0,
      held: this.#held.length, counters: { ...this.counters },
    };
  }

  async close() {
    await this.drain();
    if (this.#timer !== null) { clearTimeout(this.#timer); this.#timer = null; }
    if (this.#fh !== null) { try { await this.#o.io.fsync(this.#fh); } catch { /* reported by the next open */ } await this.#o.io.close(this.#fh); this.#fh = null; }
    this.#closed = true;
  }
}

/**
 * The stream's health as host-state.mjs's reader takes it, { state, reasons }: §8.1's state, with the host-owned code
 * that says why (unanchored and failed closed refuse widening as audit_unavailable; at the cap, as audit_full).
 */
export function auditHealth(stream) {
  const { state, code } = stream.health();
  return { state, reasons: code === null ? [] : [code] };
}

// ---- the executor's three adapters (d1 §3, d1r1 H4, d1r5) ---------------------------------------------------------

/** A record's own fields from an executor record { op | kind, gen?, agent?, step?, set?, reason?, digest?, plan_digest? }. */
function ownOf(rec, phase, opId) {
  const op = rec.op ?? rec.kind;
  const detail = {};
  for (const k of ["digest", "plan_digest", "step", "set", "grant_hash", "pairs_digest"]) if (rec[k] !== undefined) detail[k] = rec[k];
  return {
    op, op_id: opId, phase,
    ...(rec.gen !== undefined ? { gen: rec.gen } : {}), ...(rec.agent !== undefined ? { agent: rec.agent } : {}),
    ...(rec.reason !== undefined ? { reason: rec.reason } : {}), ...(Object.keys(detail).length ? { detail } : {}),
  };
}
const newOpId = () => b64(randomBytes(16));

/** appendIntent, openIntents and audit over an open stream (the executor's contracts, executor.mjs:145-146). */
export function auditAdapters(stream) {
  const open = new Map(); // key -> { epoch, seq, op_id }
  return {
    async appendIntent(rec, ms) {
      const op = rec.op ?? rec.kind;
      const opId = newOpId();
      const own = ownOf(rec, "authorized", opId);
      if (isNarrowing(op, own.phase)) { stream.record(own, { narrowing: true }); return; } // (never thrown, never awaited)
      const at = await stream.intent(own, ms);
      open.set(keyOf(op, rec.gen, rec.agent), { epoch: at.epoch, seq: at.seq, op_id: opId });
    },
    audit(rec) {
      const op = rec.op ?? rec.kind;
      // The executor's `failed` (restore.import) is unknown_effect: no "no effect" claim without proof (d1r5).
      const phase = rec.phase === "failed" ? "unknown_effect" : rec.phase;
      if (!PHASES.has(phase)) { stream.counters.bad_records += 1; return; } // (refused at the writer, counted)
      const k = keyOf(op, rec.gen, rec.agent);
      const i = TERMINAL.has(phase) ? open.get(k) : undefined;
      if (i) open.delete(k);
      const own = ownOf(rec, phase, i ? i.op_id : newOpId());
      if (i) own.intent = { epoch: i.epoch, seq: i.seq };
      stream.record(own, { narrowing: isNarrowing(op, phase) });
    },
    async openIntents() {
      const gens = [];
      // (each closure is narrowing reconciliation: queued, never awaited and never thrown, H4; it claims no effect)
      for (const x of stream.recoveredIntents()) {
        stream.record({ op: x.op, op_id: x.op_id, phase: "unknown_effect", ...(x.gen ? { gen: x.gen } : {}), ...(x.agent ? { agent: x.agent } : {}), intent: { epoch: x.epoch, seq: x.seq } }, { narrowing: true });
        if (x.op === "grant.apply" && x.gen) gens.push(x.gen);
      }
      return gens;
    },
  };
}

// ---- small helpers -------------------------------------------------------------------------------------------------

/** Make `d` (root 0700) if missing, and refuse it unless it's a private directory owned by this process's uid. */
export function ensurePrivateDir(fsx, d) { privateDir(fsx, d); }

function privateDir(fsx, d) {
  try { fsx.mkdirSync(d, { mode: 0o700 }); } catch (e) { if (e?.code !== "EEXIST") throw e; }
  const st = fsx.lstatSync(d);
  if (!st.isDirectory() || (st.mode & 0o077) !== 0) throw failure("audit_unavailable", `${d} isn't a private directory`);
}
function syncDir(fsx, d) { const fd = fsx.openSync(d, "r"); try { fsx.fsyncSync(fd); } finally { fsx.closeSync(fd); } }
function writeFileDurable(fsx, dir, name, text) {
  const tmp = join(dir, `.${name}.tmp`);
  const fd = fsx.openSync(tmp, "w", 0o600);
  try { fsx.writeSync(fd, enc(text)); fsx.fsyncSync(fd); } finally { fsx.closeSync(fd); }
  fsx.renameSync(tmp, join(dir, name));
  syncDir(fsx, dir);
}
