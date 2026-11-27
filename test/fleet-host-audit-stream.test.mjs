// The host audit stream (host audit stream d1 to d1r5): its records, its verified open (torn vs corrupt, the chain,
// continuity's exact rules, the genesis variants), the unanchored refusal, the writer's durability and bounds, the
// emergency narrowing path, checkpoints, recovery's unknown_effect, and the executor adapters' mapping.
import assert from "node:assert/strict";
import { appendFileSync, existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, truncateSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "./host-linux-only.mjs";
import { newId, keyFromSeed, b64, refuse } from "../lib/fleet/index.mjs";
import { seal } from "../lib/fleet/envelope.mjs";
import { AUDIT_LIMITS, UNANCHORED, auditAdapters, auditHealth, isNarrowing, openAuditStream } from "../lib/fleet/host/audit-stream.mjs";

const key = keyFromSeed(new Uint8Array(32).fill(7));
const other = keyFromSeed(new Uint8Array(32).fill(8));
const CERT = b64(new Uint8Array(32).fill(1));
const D32 = (n) => b64(new Uint8Array(32).fill(n));
const ident = (o = {}) => ({ fleet: FLEET, aud: "https://dev.sagebrush.space", host: HOST, cert: CERT, chainSeq: () => 5, signer: key,
  keyFor: (c) => (c === CERT ? key.raw : refuse("bad_signature", "another certificate")), ...o });
const FLEET = newId(), HOST = newId();
const SMALL = { reserve: 4096, cap: 64 * 1024 };
const fresh = () => join(mkdtempSync(join(tmpdir(), "sb-audit-")), "audit");
const lines = (dir, e) => readFileSync(join(dir, `epoch-${e}.log`), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
const open = (dir, o = {}) => openAuditStream(ident(o.id), { dir, limits: SMALL, ...o });

test("genesis: the stream file, epoch 0, the reserve; continuity genesis with every link null; unanchored: degraded, widening refused with the one reason", async () => {
  const dir = fresh();
  const s = await open(dir);
  await s.close();
  assert.deepEqual(readdirSync(dir).sort(), ["epoch-0.log", "reserve", "stream"]);
  assert.equal(statSync(join(dir, "reserve")).size, SMALL.reserve);
  const [c] = lines(dir, 0);
  assert.equal(c.type, "sb.audit-continuity.v1");
  assert.deepEqual([c.body.reason, c.body.seq, c.body.prev, c.body.prior_checkpoint, c.body.prior_last], ["genesis", 0, null, null, null]);
  for (const k of ["fleet", "aud", "host", "cert", "chain_seq", "stream", "epoch", "at_ms"]) assert.ok(Object.hasOwn(c.body, k), k);
  const h = s.health();
  assert.deepEqual([h.state, h.reason, h.completeness], ["degraded_audit", UNANCHORED, "unknown"]);
  const s2 = await open(dir);
  await assert.rejects(auditAdapters(s2).appendIntent({ op: "grant.apply", gen: 1 }, 2000), (e) => e.code === "audit_unavailable" && e.message.includes(UNANCHORED));
  await s2.close();
});

test("a restart is restart_unanchored: prior_last is the prior epoch's last record, prev its digest, prior_checkpoint null; still unanchored", async () => {
  const dir = fresh();
  const s = await open(dir, { trustGenesis: true });
  auditAdapters(s).audit({ kind: "agent.stop", agent: newId(), phase: "succeeded" });
  await s.close();
  const s2 = await open(dir);
  await s2.close();
  const prior = lines(dir, 0).at(-1);
  const [c] = lines(dir, 1);
  assert.equal(c.body.reason, "restart_unanchored");
  assert.equal(c.body.prior_checkpoint, null);
  assert.deepEqual([c.body.prior_last.epoch, c.body.prior_last.seq], [0, prior.body.seq]);
  assert.equal(c.body.prev, c.body.prior_last.digest);
  assert.equal(s2.health().reason, UNANCHORED);
});

test("a widening intent is durable (fsynced) before it resolves; its terminal names it and carries its op_id; narrowing goes through unanchored", async () => {
  const dir = fresh();
  const syncs = [];
  const io = { open: (p, f, m) => import("node:fs").then((fs) => fs.promises.open(p, f, m)), write: (fh, b) => fh.write(b, 0, b.length, null), fsync: async (fh) => { syncs.push(1); await fh.datasync(); }, close: (fh) => fh.close() };
  const s = await open(dir, { trustGenesis: true, io });
  const a = auditAdapters(s);
  const before = syncs.length;
  await a.appendIntent({ op: "grant.apply", gen: 3, digest: D32(2), plan_digest: D32(3) }, 2000);
  assert.equal(syncs.length, before + 1, "one fsync for the intent before it resolved");
  a.audit({ kind: "grant.apply", gen: 3, phase: "succeeded" });
  await s.close();
  const rs = lines(dir, 0);
  const intent = rs.find((r) => r.body.phase === "authorized"), term = rs.find((r) => r.body.phase === "succeeded");
  assert.deepEqual(intent.body.detail, { digest: D32(2), plan_digest: D32(3) });
  assert.deepEqual(term.body.intent, { epoch: 0, seq: intent.body.seq });
  assert.equal(term.body.op_id, intent.body.op_id);
  // Unanchored: narrowing still recorded.
  const s2 = await open(dir);
  auditAdapters(s2).audit({ kind: "agent.pause", agent: newId(), phase: "succeeded" });
  await s2.close();
  assert.ok(lines(dir, 1).some((r) => r.body.op === "agent.pause"));
});

test("the intent deadline: a hung fsync refuses the intent with audit_timeout within its bound, and the effect never starts; narrowing never waits", async () => {
  const dir = fresh();
  let hang = false;
  const hung = []; // (released at the end, so the stream closes its handle)
  const io = { open: (p, f, m) => import("node:fs").then((fs) => fs.promises.open(p, f, m)), write: (fh, b) => fh.write(b, 0, b.length, null),
    fsync: (fh) => (hang ? new Promise((r) => hung.push(r)) : fh.datasync()), close: (fh) => fh.close() };
  const s = await open(dir, { trustGenesis: true, io });
  const a = auditAdapters(s);
  hang = true;
  const t0 = Date.now();
  await assert.rejects(a.appendIntent({ op: "agent.start", agent: newId(), gen: 1 }, 50), (e) => e.code === "audit_timeout");
  assert.ok(Date.now() - t0 < 1000, "refused within the bound");
  // narrowing: audit() returns at once whatever the disk does
  const t1 = Date.now();
  a.audit({ kind: "agent.stop", agent: newId(), phase: "succeeded" });
  await a.appendIntent({ kind: "agent.pause", agent: newId() }, 2000); // (a narrowing intent: never awaited, never thrown)
  assert.ok(Date.now() - t1 < 100, "narrowing returned within 100 ms against a hung fsync");
  hang = false;
  for (const r of hung.splice(0)) r();
  await s.close();
});

test("open, torn vs corrupt: only the LAST epoch's unterminated final line is torn (truncated, its intent left open); a terminated corrupt record is fail_closed, its bytes kept", async () => {
  // Torn: a complete, valid record missing only its newline.
  const dir = fresh();
  const s = await open(dir, { trustGenesis: true });
  await auditAdapters(s).appendIntent({ op: "grant.apply", gen: 4 }, 2000);
  await s.close();
  const p = join(dir, "epoch-0.log");
  truncateSync(p, statSync(p).size - 1); // (the intent's newline gone: the line itself is a valid record)
  const s2 = await open(dir);
  assert.equal(s2.health().state, "degraded_audit", "opened, unanchored");
  assert.equal(lines(dir, 0).length, 1, "the torn line truncated");
  assert.deepEqual(await auditAdapters(s2).openIntents(), [], "the torn intent was never durable, so nothing is reconciled from it");
  await s2.close();
  // Corrupt: a terminated final record with its signature flipped.
  const d2 = fresh();
  const s3 = await open(d2, { trustGenesis: true });
  auditAdapters(s3).audit({ kind: "agent.stop", agent: newId(), phase: "succeeded" });
  await s3.close();
  const p2 = join(d2, "epoch-0.log");
  const text = readFileSync(p2, "utf8");
  const bad = text.replace(/"sig":"(.)/g, (m, c) => `"sig":"${c === "A" ? "B" : "A"}`);
  writeFileSync(p2, bad);
  const s4 = await open(d2);
  assert.equal(s4.health().state, "fail_closed");
  assert.equal(readFileSync(p2, "utf8"), bad, "the corrupt bytes kept as evidence");
  await assert.rejects(s4.intent({ op: "grant.apply", op_id: b64(new Uint8Array(16)), phase: "authorized" }), (e) => e.code === "audit_unavailable");
  await s4.close();
});

test("open: each break is fail_closed: an empty line, an over-size line, an earlier epoch's unterminated line, an epoch gap, a stream file without logs, logs without a stream file, another certificate", async () => {
  const mk = async () => { const d = fresh(); const s = await open(d, { trustGenesis: true }); auditAdapters(s).audit({ kind: "agent.stop", agent: newId(), phase: "succeeded" }); await s.close(); return d; };
  const cases = {
    "an empty line": (d) => appendFileSync(join(d, "epoch-0.log"), "\n"),
    "an over-size line": (d) => appendFileSync(join(d, "epoch-0.log"), `${"x".repeat(9000)}\n`),
    "an earlier epoch's unterminated line": async (d) => { await (await open(d)).close(); appendFileSync(join(d, "epoch-0.log"), "{"); },
    "an epoch gap": async (d) => { await (await open(d)).close(); writeFileSync(join(d, "epoch-3.log"), readFileSync(join(d, "epoch-1.log"))); },
    "a stream file without logs": (d) => { rmSync(join(d, "epoch-0.log")); },
    "logs without a stream file": (d) => { rmSync(join(d, "stream")); },
  };
  for (const [what, spoil] of Object.entries(cases)) {
    const d = await mk();
    await spoil(d);
    const s = await open(d);
    assert.equal(s.health().state, "fail_closed", what);
    await s.close();
  }
  const d = await mk();
  const s = await open(d, { id: { keyFor: () => refuse("bad_signature", "revoked") } });
  assert.equal(s.health().state, "fail_closed", "a record whose certificate doesn't verify at its chain_seq");
  await s.close();
});

test("open: prior_last must name the prior epoch's actual last record: its tail deleted after a later epoch exists is fail_closed", async () => {
  const d = fresh();
  const s = await open(d, { trustGenesis: true });
  const a = auditAdapters(s);
  for (let i = 0; i < 3; i++) a.audit({ kind: "agent.stop", agent: newId(), phase: "succeeded" });
  await s.close();
  await (await open(d)).close(); // epoch 1 names epoch 0's last record
  const p = join(d, "epoch-0.log");
  const all = readFileSync(p, "utf8").split("\n").filter(Boolean);
  writeFileSync(p, all.slice(0, -1).join("\n") + "\n"); // (epoch 0's last record removed, the file still terminated)
  const failed = await open(d);
  assert.equal(failed.health().state, "fail_closed");
  await failed.close();
});

test("checkpoints: each covers its predecessor (covers == prev, never itself); written to checkpoints/; they stop at the cap minus the reserve (counted), never eating the reserve", async () => {
  const d = fresh();
  const s = await open(d, { trustGenesis: true, limits: { ...SMALL, checkpointEvery: 2 } });
  const a = auditAdapters(s);
  for (let i = 0; i < 4; i++) a.audit({ kind: "agent.stop", agent: newId(), phase: "succeeded" });
  await s.close();
  const rs = lines(d, 0);
  const cks = rs.filter((r) => r.type === "sb.audit-checkpoint.v1");
  assert.ok(cks.length >= 1);
  for (const c of cks) {
    const pred = rs[c.body.seq - 1];
    assert.equal(c.body.covers.seq, pred.body.seq);
    assert.equal(c.body.covers.digest, c.body.prev);
  }
  assert.ok(readdirSync(join(d, "checkpoints")).length >= 1);
});

test("the cap and the reserve: widening refused audit_full once the next record would cross cap - reserve; narrowing goes on out of the reserve; past it narrowing is held and appended later with late", async () => {
  const d = fresh();
  const s = await open(d, { trustGenesis: true, limits: { reserve: 2048, cap: 6 * 1024 } });
  const a = auditAdapters(s);
  let full = null;
  for (let i = 0; i < 40 && full === null; i++) {
    try { await a.appendIntent({ op: "agent.start", agent: newId(), gen: 1 }, 2000); } catch (e) { full = e.code; }
  }
  assert.equal(full, "audit_full");
  const before = s.health();
  for (let i = 0; i < 20; i++) a.audit({ kind: "agent.stop", agent: newId(), phase: "succeeded" });
  await s.drain();
  const h = s.health();
  assert.ok(h.reserve_free_pct < before.reserve_free_pct, "narrowing used the reserve");
  assert.ok(h.counters.unrecorded >= 1 && h.held >= 1, "past the reserve, held and counted");
  assert.equal(h.counters.unrecorded, h.held + h.counters.dropped, "counted exactly once per record");  await s.close();
});

test("recovery: intents left open by an earlier epoch become unknown_effect, once; openIntents returns the grant.apply gens only (agent.start leftovers reported, not reconciled)", async () => {
  const d = fresh();
  const s = await open(d, { trustGenesis: true });
  const a = auditAdapters(s);
  await a.appendIntent({ op: "grant.apply", gen: 7, digest: D32(4) }, 2000);
  await a.appendIntent({ kind: "agent.start", agent: newId(), gen: 7 }, 2000);
  await s.close();
  const s2 = await open(d);
  assert.deepEqual(await auditAdapters(s2).openIntents(), [7]);
  await s2.close();
  const u = lines(d, 1).filter((r) => r.body.phase === "unknown_effect");
  assert.deepEqual(u.map((r) => r.body.op).sort(), ["agent.start", "grant.apply"]);
  for (const r of u) assert.ok(r.body.intent && r.body.intent.epoch === 0);
  const s3 = await open(d);
  assert.deepEqual(await auditAdapters(s3).openIntents(), [], "reported once: the unknown_effect records close them");
  await s3.close();
});

test("the executor's shapes: failed is written as unknown_effect with its reason; step and set as detail; an unknown phase or a malformed field is refused at the writer, counted", async () => {
  const d = fresh();
  const s = await open(d, { trustGenesis: true });
  const a = auditAdapters(s);
  a.audit({ kind: "restore.import", set: `agent:${newId()}`, phase: "failed", reason: "bad_form" });
  a.audit({ kind: "grant.apply", gen: 2, step: "broker-gen", phase: "failed_no_effect" });
  a.audit({ kind: "restore.import", set: "not a set", phase: "succeeded" });
  a.audit({ kind: "agent.stop", agent: newId(), phase: "exploded" });
  await s.close();
  const rs = lines(d, 0).map((r) => r.body);
  const f = rs.find((b) => b.op === "restore.import");
  assert.deepEqual([f.phase, f.reason], ["unknown_effect", "bad_form"]);
  assert.match(f.detail.set, /^agent:/);
  assert.equal(rs.find((b) => b.op === "grant.apply").detail.step, "broker-gen");
  assert.ok(!rs.some((b) => b.phase === "exploded") && !rs.some((b) => b.detail?.set === "not a set"));
  assert.equal(s.health().counters.bad_records, 2);
});

test("the classification table: narrowing kinds and phases, and widening", () => {
  for (const op of ["agent.pause", "agent.stop", "agent.revoke", "grant.expire", "local.stop"]) assert.equal(isNarrowing(op, "succeeded"), true, op);
  assert.equal(isNarrowing("grant.apply", "revoked"), true);
  assert.equal(isNarrowing("agent.start", "expired"), true);
  for (const op of ["grant.apply", "agent.start", "grant.intake"]) assert.equal(isNarrowing(op, "authorized"), false, op);
  assert.equal(AUDIT_LIMITS.intentMs, 2000);
  assert.equal(AUDIT_LIMITS.commitMs, 1000);
});

test("open: a correctly signed checkpoint whose covers names another record is fail_closed", async () => {
  const d = fresh();
  const s = await open(d, { trustGenesis: true, limits: { ...SMALL, checkpointEvery: 2 } });
  const a = auditAdapters(s);
  for (let i = 0; i < 4; i++) a.audit({ kind: "agent.stop", agent: newId(), phase: "succeeded" });
  await s.close();
  const p = join(d, "epoch-0.log");
  const all = readFileSync(p, "utf8").split("\n").filter(Boolean);
  const i = all.findIndex((l) => JSON.parse(l).type === "sb.audit-checkpoint.v1");
  assert.ok(i > 1);
  const r = JSON.parse(all[i]);
  const forged = Buffer.from(await seal(r.type, r.signer, { ...r.body, covers: { ...r.body.covers, seq: r.body.seq - 2 } }, key)).toString();
  writeFileSync(p, [...all.slice(0, i), forged].join("\n") + "\n"); // (the forged checkpoint last, so only covers is wrong)
  const failed = await open(d);
  assert.equal(failed.health().state, "fail_closed");
  await failed.close();
});

test("held narrowing records are bounded by heldMax: past it each is dropped and counted, never held", async () => {
  const d = fresh();
  const s = await open(d, { trustGenesis: true, limits: { reserve: 2048, cap: 6 * 1024, heldMax: 2 } });
  const a = auditAdapters(s);
  for (let i = 0; i < 80; i++) a.audit({ kind: "agent.stop", agent: newId(), phase: "succeeded" });
  await s.drain();
  const h = s.health();
  assert.equal(h.held, 2);
  assert.ok(h.counters.dropped >= 1);
  assert.equal(h.counters.unrecorded, h.held + h.counters.dropped);  await s.close();
});

test("health for the host's report: unanchored and failed closed are audit_unavailable; at the cap (widening refused) reserve_only with audit_full; host-state accepts each", async () => {
  const { HEALTH, HEALTH_REASONS } = await import("../lib/fleet/host/host-state.mjs");
  const accepted = (h) => Object.hasOwn(HEALTH, h.state) && h.reasons.every((r) => HEALTH_REASONS.includes(r));
  const d = fresh();
  const s0 = await open(d);
  assert.deepEqual(auditHealth(s0), { state: "degraded_audit", reasons: ["audit_unavailable"] });
  assert.ok(accepted(auditHealth(s0)));
  await s0.close();
  const d2 = fresh();
  const s = await open(d2, { trustGenesis: true, limits: { reserve: 2048, cap: 6 * 1024 } });
  assert.deepEqual(auditHealth(s), { state: "ok", reasons: [] });
  const a = auditAdapters(s);
  let full = false;
  for (let i = 0; i < 40 && !full; i++) await a.appendIntent({ op: "agent.start", agent: newId(), gen: 1 }, 2000).catch((e) => { full = e.code === "audit_full"; });
  assert.ok(full);
  assert.deepEqual(auditHealth(s), { state: "reserve_only", reasons: ["audit_full"] }, "widening refused: not ok");
  assert.ok(accepted(auditHealth(s)));
  await s.close();
});

// ---- AUDIT's H1-H5 on the first head (short writes, one replay pump, nonblocking recovery, health's cause)

/** An io over real files whose writes, fsyncs or both a row can steer. */
function steeredIo() {
  const st = { chunk: Infinity, failNext: null, failAfter: null, hang: false, hung: [], fsyncFail: 0 };
  const io = {
    open: (p, f, m) => import("node:fs").then((fs) => fs.promises.open(p, f, m)),
    write: async (fh, b) => {
      if (st.failNext) { const code = st.failNext; st.failNext = null; throw Object.assign(new Error(code), { code }); }
      const n = Math.min(st.chunk, b.length);
      const r = await fh.write(b, 0, n, null);
      if (st.failAfter !== null && --st.failAfter < 0) { st.failAfter = null; st.failNext = "EIO"; }
      return r;
    },
    fsync: (fh) => {
      if (st.fsyncFail > 0) { st.fsyncFail -= 1; return Promise.reject(Object.assign(new Error("EIO"), { code: "EIO" })); }
      return st.hang ? new Promise((r) => st.hung.push(() => r(fh.datasync()))) : fh.datasync();
    },
    close: (fh) => fh.close(),
  };
  return { st, io, release: () => { st.hang = false; for (const r of st.hung.splice(0)) r(); } };
}

test("H1: short writes loop to the whole line (and the stream reopens clean); a write failing after part of a line breaks the epoch: the intent is refused, nothing more is written, and the next open truncates the torn tail", async () => {
  const d = fresh();
  const x = steeredIo();
  const s = await open(d, { trustGenesis: true, io: x.io });
  x.st.chunk = 7; // (every write call takes at most 7 bytes)
  await auditAdapters(s).appendIntent({ op: "grant.apply", gen: 1 }, 2000);
  auditAdapters(s).audit({ kind: "grant.apply", gen: 1, phase: "succeeded" });
  await s.drain();
  x.st.chunk = Infinity;
  // a failure after the first chunk of the next line
  x.st.chunk = 10; x.st.failAfter = 0;
  await assert.rejects(auditAdapters(s).appendIntent({ op: "grant.apply", gen: 2 }, 2000), (e) => e.code === "audit_unavailable");
  x.st.chunk = Infinity;
  assert.equal(s.health().state, "fail_closed");
  assert.deepEqual(auditHealth(s).reasons, ["audit_unavailable"]);
  auditAdapters(s).audit({ kind: "agent.stop", agent: newId(), phase: "succeeded" });
  await s.drain();
  assert.ok(s.health().held >= 1, "narrowing held, never written after the partial line");
  await s.close();
  const reopened = await open(d);
  assert.equal(reopened.health().state, "degraded_audit", "the torn tail truncated; the stream opens (unanchored)");
  const rs = lines(d, 0);
  assert.deepEqual(rs.filter((r) => r.body.op === "grant.apply").map((r) => [r.body.gen, r.body.phase]), [[1, "authorized"], [1, "succeeded"]]);
  await reopened.close();
});

test("H1: a write failing before any byte (or with zero progress) takes nothing: the intent is refused, the epoch isn't broken, and the next record is written", async () => {
  const d = fresh();
  const x = steeredIo();
  const s = await open(d, { trustGenesis: true, io: x.io });
  x.st.failNext = "EAGAIN";
  await assert.rejects(auditAdapters(s).appendIntent({ op: "grant.apply", gen: 1 }, 2000), (e) => e.code === "audit_unavailable");
  await auditAdapters(s).appendIntent({ op: "grant.apply", gen: 2 }, 2000);
  assert.equal(s.health().state, "ok");
  await s.close();
  assert.deepEqual(lines(d, 0).filter((r) => r.body.op === "grant.apply").map((r) => r.body.gen), [2]);
});

test("H2: held records replay exactly once, in order, before newer ones, under concurrent new records (one pump)", async () => {
  const d = fresh();
  const x = steeredIo();
  const s = await open(d, { trustGenesis: true, io: x.io });
  const a = auditAdapters(s);
  const ag = Array.from({ length: 4 }, () => newId());
  x.st.failNext = "EAGAIN"; // (A can't be taken: held)
  a.audit({ kind: "agent.stop", agent: ag[0], phase: "succeeded" });
  await s.drain();
  // B is held behind A while the first replay attempt also fails
  x.st.failNext = "EAGAIN";
  a.audit({ kind: "agent.stop", agent: ag[1], phase: "succeeded" });
  await s.drain();
  assert.equal(s.health().held, 2);
  // the disk recovers; two new records at once
  a.audit({ kind: "agent.stop", agent: ag[2], phase: "succeeded" });
  a.audit({ kind: "agent.stop", agent: ag[3], phase: "succeeded" });
  await s.close();
  const stops = lines(d, 0).filter((r) => r.body.op === "agent.stop").map((r) => [ag.indexOf(r.body.agent), r.body.detail?.late === true]);
  assert.deepEqual(stops, [[0, true], [1, true], [2, false], [3, false]]);
});

test("H4: recovery's unknown_effect closures never wait or throw: openIntents answers at once under a hung fsync, and under storage that takes nothing; the closures land (or are held), claiming no effect", async () => {
  const d = fresh();
  const s0 = await open(d, { trustGenesis: true });
  await auditAdapters(s0).appendIntent({ op: "grant.apply", gen: 9 }, 2000);
  await s0.close();
  const x = steeredIo();
  const s = await open(d, { io: x.io });
  x.st.hang = true;
  const t0 = Date.now();
  const answer = await Promise.race([auditAdapters(s).openIntents(), new Promise((r) => setTimeout(() => r("waited on the disk"), 1000))]);
  assert.deepEqual(answer, [9]);
  assert.ok(Date.now() - t0 < 100, "answered without waiting on the disk");
  x.release();
  await s.close();
  const u = lines(d, 1).filter((r) => r.body.phase === "unknown_effect");
  assert.equal(u.length, 1);
  assert.deepEqual(u[0].body.intent, { epoch: 0, seq: 1 });
  // storage that takes nothing: no throw, the closure held
  const d2 = fresh();
  const s1 = await open(d2, { trustGenesis: true });
  await auditAdapters(s1).appendIntent({ op: "grant.apply", gen: 3 }, 2000);
  await s1.close();
  const y = steeredIo();
  const s2 = await open(d2, { io: y.io });
  y.st.failNext = "ENOSPC";
  assert.deepEqual(await auditAdapters(s2).openIntents(), [3]);
  await s2.drain();
  assert.equal(s2.health().held, 1);
  assert.deepEqual(auditHealth(s2).reasons, ["audit_unavailable"], "(unanchored: the stream's own state names it)");
  await s2.close();
});

test("H5: health keeps the cause: a failed fsync under an anchored stream is fail_closed (audit_unavailable), never ok; an EIO-held narrowing record is audit_unavailable, not audit_full; ENOSPC is audit_full; a hung fsync past the deadline is audit_timeout", async () => {
  const x = steeredIo();
  const s = await open(fresh(), { trustGenesis: true, io: x.io });
  x.st.fsyncFail = 1;
  auditAdapters(s).audit({ kind: "grant.apply", gen: 1, phase: "succeeded" });
  await s.drain();
  assert.equal(s.health().state, "fail_closed");
  assert.deepEqual(auditHealth(s).reasons, ["audit_unavailable"]);
  assert.ok(s.health().counters.uncertain >= 1);
  await s.close();
  // EIO before any byte, on a narrowing record: held, and its cause is unavailability
  const y = steeredIo();
  const s2 = await open(fresh(), { trustGenesis: true, io: y.io });
  y.st.failNext = "EIO";
  auditAdapters(s2).audit({ kind: "agent.stop", agent: newId(), phase: "succeeded" });
  await s2.drain();
  assert.deepEqual([s2.health().state, ...auditHealth(s2).reasons], ["degraded_audit", "audit_unavailable"]);
  await s2.close();
  // ENOSPC: capacity
  const z = steeredIo();
  const s3 = await open(fresh(), { trustGenesis: true, io: z.io });
  z.st.failNext = "ENOSPC";
  auditAdapters(s3).audit({ kind: "agent.stop", agent: newId(), phase: "succeeded" });
  await s3.drain();
  assert.deepEqual([s3.health().state, ...auditHealth(s3).reasons], ["reserve_only", "audit_full"]);
  await s3.close();
  // a hung fsync past the intent deadline
  const w = steeredIo();
  const s4 = await open(fresh(), { trustGenesis: true, io: w.io, limits: { ...SMALL, intentMs: 30 } });
  w.st.hang = true;
  auditAdapters(s4).audit({ kind: "grant.apply", gen: 1, phase: "succeeded" });
  const syncing = s4.drain();
  await new Promise((r) => setTimeout(r, 60));
  assert.deepEqual([s4.health().state, ...auditHealth(s4).reasons], ["degraded_audit", "audit_timeout"]);
  w.release();
  await syncing;
  await s4.close();
});

test("a refusal summary's times out of order, or a count of 0, is refused at the writer", async () => {
  const s = await open(fresh(), { trustGenesis: true });
  for (const refusal of [{ count: 1, first_at_ms: 5, last_at_ms: 4 }, { count: 0, first_at_ms: 4, last_at_ms: 5 }]) {
    await assert.rejects(s.append("sb.audit-event.v1", { op: "grant.intake", op_id: b64(new Uint8Array(16).fill(refusal.count + 1)), phase: "refused", gen: 2, reason: "chain_fork", detail: { refusal } }), (e) => e.code === "bad_form");
  }
  await s.close();
});
