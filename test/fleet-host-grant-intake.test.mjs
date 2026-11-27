// The grant intake (slice B, grant-intake d1 to d1r8): the catch-up order, the pairs bound to their grant and stored
// before the submit, the audit records around them, the accepted hint, rollbacks and forks, recovery's `kept`, pairOf,
// signed refusals, and the poller. The verifiers are fakes over canonical envelopes (the core's are tested on their
// own); the audit stream, the pair files and the hint are the real ones.
import assert from "node:assert/strict";
import fs, { mkdtempSync, readFileSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach } from "node:test";
import { test } from "./host-linux-only.mjs";
import { FleetError, b64, canonText, enc, newId, sha256b64 } from "../lib/fleet/index.mjs";
import { auditAdapters, openAuditStream } from "../lib/fleet/host/audit-stream.mjs";
import { AcceptedHint, BACKOFF_MAX_MS, GrantIntake, GrantPoller, PAIR_FILE_MAX, PairFiles, POLL_MS, REFUSAL_EVERY_MS, pairsDigest } from "../lib/fleet/host/grant-intake.mjs";
import { keyFromSeed } from "../lib/fleet/index.mjs";
import { realIo } from "../lib/fleet/host/store.mjs";

const UID = process.getuid();
const HOST = newId(), FP = b64(new Uint8Array(32).fill(3));
const key = keyFromSeed(new Uint8Array(32).fill(9));
const CERT = b64(new Uint8Array(32).fill(1));
const env = (body) => enc(canonText({ type: "t", body }));
const hashOf = (bytes) => sha256b64(bytes);

/** The fake service's world: grants by gen, each with its agents and pairs. */
function world() {
  const w = { grants: new Map(), reads: [], fail: new Map() };
  w.add = (gen, agents, moved = []) => {
    const grant = env({ gen, agents: agents.map((agent) => ({ agent })) });
    const h = hashOf(grant);
    const pairs = moved.map((m) => {
      const agent = typeof m === "string" ? m : m.agent;
      const t = { agent, gen, grant: h, to_host: HOST, to_host_key: FP, nonce: newId(), ...(m.transfer ?? {}) };
      const r = { agent: m.receiptAgent ?? agent, gen, ...(m.receipt ?? {}) };
      return { transfer: env(t), receipt: env(r) };
    });
    w.grants.set(gen, { gen, grant, pairs, hash: h });
    return w.grants.get(gen);
  };
  w.read = async (k) => {
    w.reads.push(k);
    if (w.fail.has(k ?? "newest")) return w.fail.get(k ?? "newest");
    const gen = k ?? Math.max(...w.grants.keys());
    const g = w.grants.get(gen);
    if (!g) return { refused: "no_grant" };
    return { read: { gen: g.gen, grant: g.grant, pairs: g.pairs } };
  };
  return w;
}

const OPEN = [];
afterEach(async () => { for (const st of OPEN.splice(0)) await st.close().catch(() => {}); });

/** An intake over a real anchored stream, real pair files and a fake executor at `applied`. */
async function setup(o = {}) {
  const root = mkdtempSync(join(tmpdir(), "sb-intake-"));
  const stream = await openAuditStream({ fleet: newId(), aud: "https://dev.sagebrush.space", host: HOST, cert: CERT, chainSeq: () => 3, signer: key, keyFor: () => key.raw },
    { dir: join(root, "audit"), trustGenesis: o.anchored ?? true });
  OPEN.push(stream);
  const w = o.world ?? world();
  const ex = { gen: o.applied ?? 0, hash: o.appliedHash ?? null, submits: [], listed: new Map() };
  const adapters = auditAdapters(stream, { grantHashAt: (g) => (g === ex.gen ? ex.hash : null) });
  const log = [];
  const io = o.io ?? realIo;
  const files = new PairFiles(join(root, "transfers", "pairs"), { io, uid: UID });
  const hint = new AcceptedHint(join(root, "grants"));
  const timers = o.timers ?? { set: (ms, fn) => { const t = setTimeout(fn, ms); t.unref?.(); return t; }, clear: (t) => clearTimeout(t) };
  const intake = new GrantIntake({
    read: w.read, host: { id: HOST, fingerprint: FP },
    verify: (bytes) => {
      const b = JSON.parse(new TextDecoder().decode(bytes)).body;
      if (b.bad) throw new FleetError("bad_signature", "fake");
      return { body: b, hash: hashOf(bytes), digest: hashOf(bytes) };
    },
    verifyPair: async (pair) => {
      const t = JSON.parse(new TextDecoder().decode(pair.transfer)).body, r = JSON.parse(new TextDecoder().decode(pair.receipt)).body;
      if (t.bad || r.bad) throw new FleetError("bad_signature", "fake pair");
      return { transfer: t, receipt: r, transferHash: hashOf(pair.transfer) };
    },
    applied: () => ({ gen: ex.gen, hash: ex.hash }),
    listedSince: (agent) => ex.listed.get(agent) ?? null,
    submit: async (op) => {
      log.push("submit");
      const b = JSON.parse(new TextDecoder().decode(op.bytes)).body;
      ex.submits.push(b.gen);
      if (o.submitAnswer) return o.submitAnswer(b.gen);
      ex.gen = b.gen; ex.hash = hashOf(op.bytes);
      for (const a of b.agents) if (!ex.listed.has(a.agent)) ex.listed.set(a.agent, b.gen);
      adapters.audit({ kind: "grant.apply", gen: b.gen, phase: "succeeded" });
      return { status: "applied", gen: b.gen };
    },
    stream, files, hint, timers,
    barrier: async (name, info) => { log.push(name); if (o.barrier) await o.barrier(name, info); },
  });
  return { root, stream, w, ex, intake, files, hint, log, adapters };
}
const events = async (s) => {
  await s.stream.drain();
  const dir = join(s.root, "audit");
  return fs.readdirSync(dir).filter((n) => n.startsWith("epoch-")).sort().flatMap((n) => readFileSync(join(dir, n), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l).body));
};
const A = () => newId();

// ---- catch-up order (d1r2 T1, d1r5 T7)

test("catch-up: a = 3, N = 7 reads exactly [newest, 4, 5, 6] and submits exactly [4, 5, 6, 7]; a = N-1 one read one submit; a = N one read, none", async () => {
  const w = world();
  const ag = A();
  for (let g = 1; g <= 7; g++) w.add(g, [ag]);
  const s = await setup({ world: w, applied: 3, appliedHash: w.grants.get(3).hash });
  assert.equal((await s.intake.cycle()).status, "applied");
  assert.deepEqual(w.reads, [null, 4, 5, 6]);
  assert.deepEqual(s.ex.submits, [4, 5, 6, 7]);
  assert.deepEqual(s.hint.read(), { gen: 7, hash: w.grants.get(7).hash });
  w.reads.length = 0; s.ex.submits.length = 0;
  w.add(8, [ag]);
  await s.intake.cycle();
  assert.deepEqual([w.reads, s.ex.submits], [[null], [8]]);
  w.reads.length = 0; s.ex.submits.length = 0;
  assert.equal((await s.intake.cycle()).status, "current");
  assert.deepEqual([w.reads, s.ex.submits], [[null], []]);
});

test("a cold host (applied 0) at N = 5 reads [newest, 1, 2, 3, 4] and submits [1, 2, 3, 4, 5]", async () => {
  const w = world();
  for (let g = 1; g <= 5; g++) w.add(g, [A()]);
  const s = await setup({ world: w });
  await s.intake.cycle();
  assert.deepEqual(w.reads, [null, 1, 2, 3, 4]);
  assert.deepEqual(s.ex.submits, [1, 2, 3, 4, 5]);
});

test("a gap's no_grant ends the cycle there, nothing after it read; the next cycle resumes it", async () => {
  const w = world();
  for (let g = 1; g <= 4; g++) w.add(g, [A()]);
  w.fail.set(2, { refused: "no_grant" });
  const s = await setup({ world: w });
  const r = await s.intake.cycle();
  assert.deepEqual([r.status, w.reads, s.ex.submits], ["refused", [null, 1, 2], [1]]);
  w.fail.delete(2); w.reads.length = 0;
  await s.intake.cycle();
  assert.deepEqual([w.reads, s.ex.submits], [[null, 2, 3], [1, 2, 3, 4]]);
});

// ---- one generation: the order and the records (d1r3, d1r4 B-H1, d1r5 B-H8)

test("one generation's order: intent, then each pair temp+fsync+rename, ONE directory fsync, the pair.store records, the terminal, then the submit", async () => {
  const w = world();
  const [x, y] = [A(), A()];
  w.add(1, [x, y], [x, y]);
  const ops = [];
  const io = {
    open: (p, f, m) => { ops.push(p.endsWith("pairs") ? "open dir" : "open temp"); return realIo.open(p, f, m); },
    write: (fd, b, o, l) => { ops.push("write"); return realIo.write(fd, b, o, l); },
    fsync: (fd) => { ops.push("fsync"); return realIo.fsync(fd); },
    close: (fd) => realIo.close(fd),
    rename: (a, b) => { ops.push("rename"); return realIo.rename(a, b); },
  };
  let storedBeforeDirFsync = null;
  const s = await setup({ world: w, io, barrier: async (name) => { if (name === "after_dir_fsync") storedBeforeDirFsync = s.stream.latestPairStore(x); } });
  await s.intake.cycle();
  assert.equal(storedBeforeDirFsync, null, "no pair.store before the directory fsync");
  assert.deepEqual(ops, ["open temp", "write", "fsync", "rename", "open temp", "write", "fsync", "rename", "open dir", "fsync"]);
  const ev = (await events(s)).filter((b) => b.op === "grant.intake" || b.op === "pair.store");
  assert.deepEqual(ev.map((b) => `${b.op}:${b.phase}`), ["grant.intake:authorized", "pair.store:succeeded", "pair.store:succeeded", "grant.intake:succeeded"]);
  assert.equal(ev[0].detail.grant_hash, w.grants.get(1).hash);
  for (const p of ev.slice(1, 3)) assert.deepEqual([p.detail.pair.action, p.intent], ["written", { epoch: 0, seq: ev[0].seq }]);
  assert.deepEqual(s.log.slice(-3), ["after_pair_store", "after_terminal", "submit"]);
  // the stored files: root's 0600, the directory 0700
  assert.equal(statSync(join(s.root, "transfers", "pairs", x)).mode & 0o777, 0o600);
  assert.equal(statSync(join(s.root, "transfers", "pairs")).mode & 0o777, 0o700);
});

test("pairs_digest is the ordered digest: the same for pairs in any arrival order", () => {
  const rows = [{ agent: "b", receipt_digest: "1", transfer_digest: "2" }, { agent: "a", receipt_digest: "3", transfer_digest: "4" }];
  assert.equal(pairsDigest(rows), pairsDigest([...rows].reverse()));
});

test("S1: a pair naming another grant, another gen, another host, an agent outside the grant, a receipt for another agent, or a second pair for one agent refuses the whole generation; the bad pair LAST of three; nothing written, nothing submitted", async () => {
  const cases = {
    "another grant": { transfer: { grant: b64(new Uint8Array(32).fill(7)) } },
    "another gen": { transfer: { gen: 9 } },
    "another host": { transfer: { to_host: newId() } },
    "another host key": { transfer: { to_host_key: b64(new Uint8Array(32).fill(8)) } },
    "a receipt for another agent": { receiptAgent: newId() },
    "a pair that doesn't verify": { transfer: { bad: true } },
  };
  for (const [what, spoil] of Object.entries(cases)) {
    const w = world();
    const ag = [A(), A(), A()];
    w.add(1, ag, [ag[0], ag[1], { agent: ag[2], ...spoil }]);
    const s = await setup({ world: w });
    const r = await s.intake.cycle();
    assert.equal(r.status, "fault", what);
    assert.deepEqual(s.ex.submits, [], what);
    assert.deepEqual(s.files.list(), [], `${what}: nothing written`);
    assert.ok(!(await events(s)).some((b) => b.op === "grant.intake" && b.phase === "authorized"), `${what}: no intent`);
  }
  // an agent the grant doesn't list
  const w = world();
  const [x, y] = [A(), A()];
  w.add(1, [x], [x, y]);
  const s = await setup({ world: w });
  assert.equal((await s.intake.cycle()).status, "fault");
  assert.deepEqual([s.ex.submits, s.files.list()], [[], []]);
  // two pairs for one agent
  const w2 = world();
  const z = A();
  w2.add(1, [z], [z, z]);
  const s2 = await setup({ world: w2 });
  assert.equal((await s2.intake.cycle()).reason, "bad_form");
  assert.deepEqual(s2.files.list(), []);
});

test("S2: a grant that doesn't verify, or names another gen, writes no pair (even one that verifies) and submits nothing", async () => {
  const w = world();
  const x = A();
  const g = w.add(1, [x], [x]);
  g.grant = env({ gen: 1, agents: [{ agent: x }], bad: true });
  const s = await setup({ world: w });
  assert.equal((await s.intake.cycle()).status, "fault");
  assert.deepEqual([s.ex.submits, s.files.list()], [[], []]);
  const w2 = world();
  const g2 = w2.add(1, [x], [x]);
  g2.grant = env({ gen: 2, agents: [{ agent: x }] });
  const s2 = await setup({ world: w2 });
  assert.equal((await s2.intake.cycle()).status, "fault");
  assert.deepEqual([s2.ex.submits, s2.files.list()], [[], []]);
});

test("S4: a = 3, N = 7 with gen 5 forked: submits exactly [4], nothing of 5 stored, 6 and 7 never read; the next cycle stops at 5 again", async () => {
  const w = world();
  const ag = A();
  for (let g = 1; g <= 7; g++) w.add(g, [ag]);
  const moved = A();
  const g5 = w.add(5, [ag, moved], [{ agent: moved, transfer: { grant: b64(new Uint8Array(32).fill(5)) } }]);
  void g5;
  const s = await setup({ world: w, applied: 3, appliedHash: w.grants.get(3).hash });
  const r = await s.intake.cycle();
  assert.equal(r.status, "fault");
  assert.deepEqual([w.reads, s.ex.submits, s.files.list()], [[null, 4, 5], [4], []]);
  w.reads.length = 0;
  await s.intake.cycle();
  assert.deepEqual(w.reads, [null, 5]);
});

test("T2/S3: the newest below the applied gen is a rollback (nothing read further, nothing submitted); a ?gen=k answer for another gen is a fork", async () => {
  const w = world();
  w.add(1, [A()]); w.add(2, [A()]);
  const s = await setup({ world: w, applied: 5, appliedHash: b64(new Uint8Array(32).fill(4)) });
  const r = await s.intake.cycle();
  assert.deepEqual([r.status, r.kind, s.ex.submits], ["fault", "grant_rollback", []]);
  const w2 = world();
  w2.add(1, [A()]); w2.add(2, [A()]); w2.add(3, [A()]);
  w2.fail.set(2, { read: { gen: 3, grant: w2.grants.get(3).grant, pairs: [] } });
  const s2 = await setup({ world: w2, applied: 1, appliedHash: w2.grants.get(1).hash });
  const r2 = await s2.intake.cycle();
  assert.deepEqual([r2.status, r2.kind, s2.ex.submits], ["fault", "grant_fork", []]);
});

test("k == applied with another hash is a fork, every cycle; with the same hash, current", async () => {
  const w = world();
  w.add(1, [A()]);
  const s = await setup({ world: w, applied: 1, appliedHash: b64(new Uint8Array(32).fill(2)) });
  assert.equal((await s.intake.cycle()).kind, "grant_fork");
  assert.equal((await s.intake.cycle()).kind, "grant_fork");
  const s2 = await setup({ world: w, applied: 1, appliedHash: w.grants.get(1).hash });
  assert.equal((await s2.intake.cycle()).status, "current");
});

test("T5: the accepted file is a hint: one above the executor's gen is a fault with no read; one below (an old reinstalled file, or a crash before its write) is rewritten, with no re-read of old generations", async () => {
  const w = world();
  for (let g = 1; g <= 4; g++) w.add(g, [A()]);
  const s = await setup({ world: w, applied: 2, appliedHash: w.grants.get(2).hash });
  s.hint.write({ gen: 4, hash: "x" });
  const r = await s.intake.cycle();
  assert.deepEqual([r.kind, w.reads], ["grant_rollback", []]);
  s.hint.write({ gen: 0, hash: null });
  await s.intake.cycle();
  assert.deepEqual([w.reads, s.ex.submits], [[null, 3], [3, 4]]);
});

// ---- the stored pairs: kept, replaced, conflicts (d1 §2.2, d1r2 T4, d1r5 T6)

test("a newer transfer of an agent replaces its older stored pair (written, replaces naming the old gen and digest); the older never overwrites the newer", async () => {
  const w = world();
  const x = A();
  w.add(1, [x], [x]);
  w.add(2, [x], [x]);
  const s = await setup({ world: w });
  await s.intake.cycle();
  const ps = (await events(s)).filter((b) => b.op === "pair.store");
  assert.deepEqual(ps.map((b) => [b.gen, b.detail.pair.action]), [[1, "written"], [2, "written"]]);
  assert.deepEqual(ps[1].detail.pair.replaces, { gen: 1, transfer_digest: hashOf(w.grants.get(1).pairs[0].transfer) });
  assert.equal(PairFiles.genOf(s.intake.pairOf(x)), 2);
});

test("pair_conflict: a stored pair at the SAME gen with other bytes refuses the generation; the stored pair is untouched", async () => {
  const w = world();
  const x = A();
  w.add(1, [x], [x]);
  const s = await setup({ world: w });
  // another valid-looking pair for x at gen 1 already on disk (other nonce)
  const other = { transfer: env({ agent: x, gen: 1, grant: w.grants.get(1).hash, to_host: HOST, to_host_key: FP, nonce: newId() }), receipt: env({ agent: x, gen: 1 }) };
  s.files.ensure();
  s.files.stage(x, PairFiles.textOf(other)); s.files.syncDir();
  const before = readFileSync(join(s.root, "transfers", "pairs", x), "utf8");
  const r = await s.intake.cycle();
  assert.deepEqual([r.kind, s.ex.submits], ["pair_conflict", []]);
  assert.equal(readFileSync(join(s.root, "transfers", "pairs", x), "utf8"), before);
});

// ---- crashes and recovery (d1r5 T6, B-H8; d1r6; d1r7; d1r8 N11)

test("a failure after the pair writes and before the terminal: no submit; the NEXT intake of k records the pair kept under a new op with reconciles, then submits", async () => {
  const w = world();
  const x = A();
  w.add(1, [x], [x]);
  let crash = true;
  const s = await setup({ world: w, barrier: async (name) => { if (name === "after_dir_fsync" && crash) { crash = false; throw new Error("crash"); } } });
  const r = await s.intake.cycle();
  assert.equal(r.status, "fault");
  assert.deepEqual(s.ex.submits, []);
  await s.intake.cycle();
  assert.deepEqual(s.ex.submits, [1]);
  const ev = await events(s);
  const intents = ev.filter((b) => b.op === "grant.intake" && b.phase === "authorized");
  const ps = ev.filter((b) => b.op === "pair.store");
  assert.equal(intents.length, 2);
  assert.deepEqual(ev.filter((b) => b.op === "grant.intake" && b.intent?.seq === intents[0].seq).map((b) => b.phase), ["unknown_effect"]);
  assert.deepEqual(ps.map((b) => [b.detail.pair.action, b.detail.reconciles]), [["kept", { epoch: 0, seq: intents[0].seq }]]);
  assert.ok(s.intake.pairOf(x));
});

test("recovery (d1r6/d1r7): a stored pair with no record that binds to the grant its agent was listed in since, as the stream shows it applied, is recorded kept and pairOf returns it; an older genuine pair (moved at 5 and again at 8, the file holds 5) is not", async () => {
  const w = world();
  const x = A();
  w.add(1, [x], [x]);
  const s = await setup({ world: w });
  await s.intake.cycle(); // applied 1, pair written, records present
  // lose the stream's records: a fresh stream over a fresh dir (the pair file stays)
  const s2 = await setup({ world: w, applied: 1, appliedHash: w.grants.get(1).hash });
  s2.ex.listed.set(x, 1);
  s2.adapters.audit({ kind: "grant.apply", gen: 1, phase: "succeeded" }); // the stream shows gen 1 applied
  await s2.stream.drain();
  fs.mkdirSync(join(s2.root, "transfers", "pairs"), { recursive: true, mode: 0o700 });
  fs.copyFileSync(join(s.root, "transfers", "pairs", x), join(s2.root, "transfers", "pairs", x));
  fs.chmodSync(join(s2.root, "transfers", "pairs", x), 0o600);
  assert.equal(s2.intake.pairOf(x), null, "no record yet: null (P1)");
  assert.deepEqual(await s2.intake.recover(), [x]);
  assert.ok(s2.intake.pairOf(x), "kept, then returned");
  // the gen 5 / gen 8 case: listed since 8, the file holds 5
  const w5 = world();
  const y = A();
  for (let g = 1; g <= 8; g++) w5.add(g, [y], g === 5 || g === 8 ? [y] : []);
  const s5 = await setup({ world: w5 });
  await s5.intake.cycle();
  const s6 = await setup({ world: w5, applied: 8, appliedHash: w5.grants.get(8).hash });
  s6.ex.listed.set(y, 8);
  s6.adapters.audit({ kind: "grant.apply", gen: 8, phase: "succeeded" });
  await s6.stream.drain();
  s6.files.ensure();
  const p5 = w5.grants.get(5).pairs[0];
  s6.files.stage(y, PairFiles.textOf(p5)); s6.files.syncDir();
  assert.deepEqual(await s6.intake.recover(), [], "pair 5 doesn't bind to gen 8: not reconciled");
  assert.equal(s6.intake.pairOf(y), null);
  s6.files.stage(y, PairFiles.textOf(w5.grants.get(8).pairs[0])); s6.files.syncDir();
  assert.deepEqual(await s6.intake.recover(), [y], "pair 8 does");
});

test("recovery never blesses a rollback: a file rolled back to an older valid pair under a newer record, or the same gen with other bytes, is not reconciled; pairOf null", async () => {
  const w = world();
  const x = A();
  w.add(1, [x], [x]); w.add(2, [x], [x]);
  const s = await setup({ world: w });
  await s.intake.cycle(); // pair 2 recorded last
  s.files.stage(x, PairFiles.textOf(w.grants.get(1).pairs[0])); s.files.syncDir(); // rolled back to pair 1
  assert.deepEqual(await s.intake.recover(), []);
  assert.equal(s.intake.pairOf(x), null);
});

// ---- pairOf (d1 §3, d1r2 N4/N5, d1r4 B-H6)

test("pairOf: the intaken pair byte-identical; null for a tampered file, a symlink, a file over the bound, a foreign mode, or no record", async () => {
  const w = world();
  const x = A();
  w.add(1, [x], [x]);
  const s = await setup({ world: w });
  await s.intake.cycle();
  const p = s.intake.pairOf(x);
  assert.deepEqual([Buffer.from(p.transfer), Buffer.from(p.receipt)], [Buffer.from(w.grants.get(1).pairs[0].transfer), Buffer.from(w.grants.get(1).pairs[0].receipt)]);
  assert.equal(s.intake.pairOf(A()), null, "no file");
  const f = join(s.root, "transfers", "pairs", x);
  const good = readFileSync(f);
  writeFileSync(f, good.toString().replace(/"nonce":"[a-z2-7]+"/, `"nonce":"${newId()}"`)); fs.chmodSync(f, 0o600);
  assert.equal(s.intake.pairOf(x), null, "tampered");
  fs.rmSync(f); symlinkSync(join(s.root, "elsewhere"), f);
  assert.equal(s.intake.pairOf(x), null, "a symlink");
  fs.rmSync(f); writeFileSync(f, "x".repeat(PAIR_FILE_MAX + 1), { mode: 0o600 });
  assert.equal(s.intake.pairOf(x), null, "over the bound");
  fs.rmSync(f); writeFileSync(f, good, { mode: 0o644 }); fs.chmodSync(f, 0o644);
  assert.equal(s.intake.pairOf(x), null, "not 0600");
  fs.chmodSync(f, 0o600);
  assert.ok(s.intake.pairOf(x), "restored");
});

// ---- audit: unanchored, refusals (d1r4 B-H3, d1r5 N8, d1r8 N13)

test("an unanchored stream refuses the intake's intent: nothing written, nothing submitted", async () => {
  const w = world();
  const x = A();
  w.add(1, [x], [x]);
  const s = await setup({ world: w, anchored: false });
  const r = await s.intake.cycle();
  assert.deepEqual([r.status, r.reason, s.ex.submits, s.files.list()], ["fault", "audit_unavailable", [], []]);
});

test("refusals: two for one (gen, reason) within 10 s give ONE signed record with count 2; a third after the window gives a new record with its own count", async () => {
  const pending = [];
  const timers = { set: (ms, fn) => { pending.push({ ms, fn }); return pending.length; }, clear: () => {} };
  const w = world();
  w.add(1, [A()]); w.add(2, [A()]);
  w.fail.set(1, { refused: "stale_generation" });
  const s = await setup({ world: w, timers });
  await s.intake.cycle(); await s.intake.cycle();
  assert.equal(pending.length, 1);
  assert.equal(pending[0].ms, REFUSAL_EVERY_MS);
  pending.shift().fn();
  await s.intake.cycle();
  pending.shift().fn();
  const rs = (await events(s)).filter((b) => b.phase === "refused");
  assert.deepEqual(rs.map((b) => [b.gen, b.reason, b.detail.refusal.count]), [[1, "stale_generation", 2], [1, "stale_generation", 1]]);
});

test("transport failures are health only: no signed record", async () => {
  const w = world();
  w.add(1, [A()]);
  w.fail.set("newest", { transport: "timeout" });
  const pending = [];
  const s = await setup({ world: w, timers: { set: (ms, fn) => { pending.push(fn); return 1; }, clear: () => {} } });
  assert.equal((await s.intake.cycle()).status, "transport");
  assert.equal(pending.length, 0);
});

// ---- the poller (d1 §1, d1r2 N1/N2)

test("the poller: one cycle at a time; three nudges during a cycle give exactly one more; backoff doubles from the poll to its cap, a retry_after longer than it is honoured; stop starts no read afterwards", async () => {
  const sets = [];
  const timers = { set: (ms, fn) => { sets.push({ ms, fn }); return sets.length; }, clear: () => {} };
  let release, cycles = 0, answer = { status: "applied" };
  const intake = { cycle: () => { cycles += 1; return new Promise((r) => { release = () => r(answer); }); }, stop: () => {} };
  const p = new GrantPoller(intake, { timers });
  p.start();
  sets.shift().fn();
  assert.equal(cycles, 1);
  p.nudge(); p.nudge(); p.nudge();
  release(); await new Promise((r) => setImmediate(r));
  assert.equal(sets.at(-1).ms, 0, "one more right after");
  sets.shift().fn();
  assert.equal(cycles, 2);
  answer = { status: "transport", cls: "timeout" };
  const delays = [];
  for (let i = 0; i < 6; i++) { release(); await new Promise((r) => setImmediate(r)); delays.push(sets.at(-1).ms); sets.shift().fn(); }
  assert.deepEqual(delays.slice(0, 5), [POLL_MS, 2 * POLL_MS, 4 * POLL_MS, 8 * POLL_MS, BACKOFF_MAX_MS]);
  answer = { status: "transport", cls: "rate", retryAfterMs: 2 * BACKOFF_MAX_MS };
  release(); await new Promise((r) => setImmediate(r));
  assert.equal(sets.at(-1).ms, 2 * BACKOFF_MAX_MS, "retry_after honoured");
  const n = cycles;
  await Promise.race([p.stop(), Promise.resolve()]);
  for (const s of sets.splice(0)) s.fn();
  assert.equal(cycles, n, "no cycle after stop");
});
