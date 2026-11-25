// The browser channel's handshake, host side (lib/fleet/channel/accept.mjs; design agent-autonomous-browser-channel.md
// r4 §3): the pre-Noise checks, the record's checks, fresh vs resume (H1), and one durable compare-and-set per agent
// before message 2 (H2), on a real chain, host certificate and signed record, and a real DurableState under the
// host's lock. Linux only, as the host store is.
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "./host-linux-only.mjs";
import { FleetError, b64, newId, keyFromSeed, seal, applyChainEntry as apply, hostFingerprint, verifyHostCert, sha256b64 } from "../lib/fleet/index.mjs";
import { lockDir, realIo } from "../lib/fleet/host/store.mjs";
import { acceptMessage1, openChannelStore, prologueBytes, STORE_NAME } from "../lib/fleet/channel/accept.mjs";
import { message2Outcome } from "../lib/fleet/channel/message2.mjs";
import { initiator, x25519Generate } from "../lib/fleet/channel/noise.mjs";

const AUD = "https://dev.sagebrush.space";
const NOW = 1_800_000_000_000;
const code = async (fn) => { try { await fn(); } catch (e) { if (e instanceof FleetError) return e.code; throw e; } return "ok"; };
let n = 90;
const key = () => keyFromSeed(new Uint8Array(32).fill(n++));

/** A fleet (native device N), a host with its certificate and X25519 key, an agent, and the host's channel store. */
async function setup(t) {
  const fleet = newId(), host = newId(), agent = newId(), ctx = { aud: AUD, fleet };
  const N = key(), nId = newId(), rec = key();
  const sN = { kind: "device", id: nId, alg: "ed25519", key: N.key };
  const chain = (await apply(null, seal("sb.device-chain.v1", sN, { fleet, aud: AUD, seq: 0, prev: "", op: "genesis", at_ms: 1, auth_time_ms: 1,
    device: { id: nId, alg: "ed25519", key: b64(N.raw), name: "mac", tier: "native" }, recovery_key: { alg: "ed25519", key: b64(rec.raw) } }, N), ctx)).state;
  const H = key(), encKey = x25519Generate();
  const fp = await hostFingerprint(host, H.raw, encKey.raw);
  const cert = await verifyHostCert(seal("sb.host-cert.v1", sN, { fleet, aud: AUD, chain_seq: 0, host, sign_key: b64(H.raw), enc_key: b64(encKey.raw), fingerprint: b64(fp), name: "box", at_ms: 1 }, N), { ...ctx, chain });
  const dir = mkdtempSync(join(tmpdir(), "fleet-channel-"));
  const lock = await lockDir(dir);
  t.after(async () => { await lock.release(); rmSync(dir, { recursive: true, force: true }); });
  const store = openChannelStore(dir, lock);
  let gen = 1;
  const s = {
    fleet, host, agent, chain, cert, encKey, store, dir, lock, N, sN,
    // a session as the app makes it: its X25519 key, and the record the person's device signs
    session(extra = {}) {
      const app = x25519Generate();
      const body = { fleet, aud: AUD, at_ms: NOW - 1000, not_before_ms: NOW - 1000, not_after_ms: NOW + 3_600_000, session: newId(), host, agent,
        browser_gen: gen++, host_gen: 3, chain_seq: 0, app_session_pub: b64(app.raw), account_origins_manifest_sha256: b64(new Uint8Array(32).fill(1)),
        exceptions_sha256: b64(new Uint8Array(32).fill(2)), ...extra };
      return { app, body, record: seal("sb.browser-session.v1", sN, body, N) };
    },
    prologue: (sess, resume_n = 0, extra = {}) => ({ fleet, aud: AUD, session: sess.body.session, host, agent, browser_gen: sess.body.browser_gen, host_gen: sess.body.host_gen, resume_n, ...extra }),
    // message 1 from the app, for prologue p (the app's own view of it)
    message1: (sess, p, appKey = sess.app) => initiator({ s: appKey, rs: encKey.raw, prologue: prologueBytes(p) }),
    ctx: (p, extra = {}) => ({ self: { host, aud: AUD, fleet }, prologue: p, encKey, cert, chain, store, now: NOW, live: () => {}, ...extra }),
  };
  return s;
}

async function handshake(s, sess, resume_n = 0, extra = {}) {
  const p = s.prologue(sess, resume_n);
  const I = s.message1(sess, p);
  const a = await acceptMessage1(I.writeMessage1(sess.record), s.ctx(p, extra));
  const r2 = a.reply();
  const i2 = I.readMessage2(r2.message);
  return { a, r2, i2 };
}

test("a fresh session: accepted, committed before message 2, message 2 carries the committed values, and the transport works", async (t) => {
  const s = await setup(t);
  const sess = s.session({ browser_gen: 5 });
  const { a, r2, i2 } = await handshake(s, sess);
  assert.deepEqual(JSON.parse(new TextDecoder().decode(i2.payload)), { browser_gen: 5, host_gen: 3, resume_n: 0 });
  assert.deepEqual(a.accepted, { host_gen: 3, browser_gen: 5, resume_n: 0 });
  const live = s.store.get().agents[s.agent];
  assert.deepEqual([live.high, live.live.session, live.live.resume_n, live.live.app_static], [5, sess.body.session, 0, sess.body.app_session_pub]);
  assert.equal(live.live.record_sha256, await sha256b64(sess.record));
  assert.deepEqual(r2.receive.decrypt(new Uint8Array(0), i2.send.encrypt(new Uint8Array(0), Uint8Array.of(7))), Uint8Array.of(7));
  assert.equal(await code(() => a.reply()), "bad_form", "message 2 is written once");
});

test("fresh vs resume (r4.1): a fresh session needs a strictly higher browser_gen; an id may recur only above it; a resume needs the exact live session", async (t) => {
  const s = await setup(t);
  const one = s.session({ browser_gen: 5 });
  await handshake(s, one);
  // fresh: an equal or lower browser_gen is refused, whatever the session id
  assert.equal(await code(() => handshake(s, s.session({ browser_gen: 5 }))), "browser_gen_stale", "equal");
  assert.equal(await code(() => handshake(s, s.session({ browser_gen: 4 }))), "browser_gen_stale", "lower");
  assert.equal(await code(() => handshake(s, s.session({ browser_gen: 5, session: one.body.session }))), "browser_gen_stale", "the live session's id at its own gen");
  assert.equal(await code(() => handshake(s, s.session({ browser_gen: 3, session: one.body.session }))), "browser_gen_stale", "an old id at an old gen");
  // resume: exactly resume_n + 1, the same record and key; the exact live record at another counter gets A2's
  // authenticated refusal naming the stored value, and nothing is written
  assert.deepEqual((await handshake(s, one, 2)).a.refused, { host_gen: 3, browser_gen: 5, resume_n: 0 }, "a skipped resume_n");
  assert.equal((await handshake(s, one, 1)).a.accepted.resume_n, 1);
  assert.deepEqual((await handshake(s, one, 1)).a.refused, { host_gen: 3, browser_gen: 5, resume_n: 1 }, "the same resume_n again");
  const otherKey = s.session({ browser_gen: 5, session: one.body.session });
  assert.equal(await code(() => handshake(s, otherKey, 2)), "bad_form", "the live session, re-signed with another app key");
  // a new session replaces the old one: the old one never resumes again
  const two = s.session({ browser_gen: 6 });
  await handshake(s, two);
  assert.equal(await code(() => handshake(s, one, 2)), "browser_gen_stale", "a replaced session resuming");
  assert.equal(await code(() => handshake(s, s.session({ browser_gen: 7 }), 1)), "browser_gen_stale", "a resume of a session never accepted");
  assert.equal(await code(() => handshake(s, s.session({ browser_gen: 6 }), 1)), "browser_gen_stale", "a resume of another session at the live session's browser_gen");
  // the same id again, at a higher browser_gen: a new tuple, accepted (identity is (host, agent, browser_gen, session))
  assert.equal((await handshake(s, s.session({ browser_gen: 7, session: one.body.session }))).a.accepted.browser_gen, 7, "an id reused above the high-water mark");
  assert.deepEqual(Object.keys(s.store.get().agents[s.agent]).sort(), ["high", "live"], "no history of retired ids");
});

test("r4.1: far past any history size, an id never returns at an old or equal browser_gen", async (t) => {
  const s = await setup(t);
  const first = s.session({ browser_gen: 1 });
  await handshake(s, first);
  for (let g = 2; g <= 260; g++) await handshake(s, s.session({ browser_gen: g }));
  assert.equal(s.store.get().agents[s.agent].high, 260);
  assert.equal(await code(() => handshake(s, s.session({ browser_gen: 1, session: first.body.session }))), "browser_gen_stale", "its own old gen");
  assert.equal(await code(() => handshake(s, s.session({ browser_gen: 259, session: first.body.session }))), "browser_gen_stale", "a gen below the mark");
  assert.equal(await code(() => handshake(s, s.session({ browser_gen: 260, session: first.body.session }))), "browser_gen_stale", "the mark itself");
});

test("before Noise: a stream for another host, fleet or audience, and a held key that isn't the certified one, are refused", async (t) => {
  const s = await setup(t);
  const sess = s.session();
  const garbage = new Uint8Array(200); // (never read: the refusal comes first)
  const p = s.prologue(sess);
  assert.equal(await code(() => acceptMessage1(garbage, s.ctx({ ...p, host: newId() }))), "not_granted");
  assert.equal(await code(() => acceptMessage1(garbage, s.ctx({ ...p, fleet: newId() }))), "not_granted");
  assert.equal(await code(() => acceptMessage1(garbage, s.ctx({ ...p, aud: "https://sagebrush.space" }))), "bad_audience");
  assert.equal(await code(() => acceptMessage1(garbage, s.ctx(p, { encKey: x25519Generate() }))), "not_granted", "the held key, checked here and not left to Noise");
  assert.equal(await code(() => acceptMessage1(garbage, s.ctx(p))), "bad_signature", "the positive control: garbage reaches Noise (an all-zero e)");
});

test("the record: its fields are the stream's, its key is the initiator's, its time window holds", async (t) => {
  const s = await setup(t);
  const run = async (sess, p = s.prologue(sess), extra = {}, appKey) => acceptMessage1(s.message1(sess, p, appKey).writeMessage1(sess.record), s.ctx(p, extra));
  const ok = s.session();
  assert.equal(await code(() => run(ok)), "ok");
  for (const [k, v] of [["session", newId()], ["agent", newId()], ["browser_gen", 2], ["host_gen", 4]]) {
    const sess = s.session();
    assert.equal(await code(() => run(sess, { ...s.prologue(sess), [k]: v })), "bad_form", k);
  }
  const sess = s.session();
  assert.equal(await code(() => run(sess, s.prologue(sess), {}, x25519Generate())), "bad_signature", "an initiator key that isn't app_session_pub");
  assert.equal(await code(() => run(s.session({ not_after_ms: NOW - 1000 + 12 * 3600_000 + 1 }))), "bad_form", "past 12 hours");
  assert.equal(await code(() => run(s.session({ not_before_ms: NOW + 1 }))), "grant_expired", "not yet");
  assert.equal(await code(() => run(s.session({ not_after_ms: NOW }))), "grant_expired", "now = not_after_ms");
  assert.equal(await code(() => run(s.session({ not_after_ms: NOW + 1 }))), "ok", "the last millisecond");
  assert.equal(Object.keys(s.store.get().agents).length, 1, "only the accepted ones committed");
});

test("the live checks: a refusal before the commit, and one only at commit time, both commit nothing", async (t) => {
  const s = await setup(t);
  const sess = s.session({ browser_gen: 3 });
  const p = s.prologue(sess);
  const revoked = () => { const e = new FleetError("host_revoked"); throw e; };
  assert.equal(await code(() => acceptMessage1(s.message1(sess, p).writeMessage1(sess.record), s.ctx(p, { live: revoked }))), "host_revoked");
  let calls = 0;
  const lateRevoke = () => { if (++calls === 2) throw new FleetError("agent_revoked"); };
  assert.equal(await code(() => acceptMessage1(s.message1(sess, p).writeMessage1(sess.record), s.ctx(p, { live: lateRevoke }))), "agent_revoked");
  assert.equal(calls, 2, "checked again inside the commit");
  assert.deepEqual(s.store.get().agents, {}, "nothing committed");
  assert.equal((await handshake(s, sess)).a.accepted.browser_gen, 3, "and the same session is then accepted");
});

test("(a) durable before message 2: a failed commit gives no message 2; a lost reply (or a failed relay authorization) never rolls back", async (t) => {
  const s = await setup(t);
  // a store whose write fails at the fsync: the commit refuses, there is no reply to send, and the store is in doubt
  const dir = mkdtempSync(join(tmpdir(), "fleet-channel-io-"));
  const lock = await lockDir(dir);
  t.after(async () => { await lock.release(); rmSync(dir, { recursive: true, force: true }); });
  let failing = false;
  const io = { ...realIo, fsync: (fd) => { if (failing) throw Object.assign(new Error("fsync failed"), { code: "EIO" }); return realIo.fsync(fd); } };
  const broken = openChannelStore(dir, lock, io);
  failing = true;
  const sess = s.session({ browser_gen: 2 });
  const p = s.prologue(sess);
  await assert.rejects(acceptMessage1(s.message1(sess, p).writeMessage1(sess.record), s.ctx(p, { store: broken })), (e) => e.code === "EIO");
  assert.equal(await code(() => broken.get()), "outcome_unknown", "in doubt until reloaded");
  failing = false;
  assert.deepEqual(broken.reload().agents, {}, "and nothing was committed");
  // the lost reply: accepted and committed, message 2 never sent (or the relay's authorization failed after the commit)
  const lost = s.session({ browser_gen: 4 });
  const lp = s.prologue(lost);
  await acceptMessage1(s.message1(lost, lp).writeMessage1(lost.record), s.ctx(lp)); // (reply() never called)
  assert.equal(s.store.get().agents[s.agent].live.session, lost.body.session, "committed");
  assert.deepEqual((await handshake(s, lost, 0)).a.refused, { host_gen: 3, browser_gen: 4, resume_n: 0 }, "the same fresh attempt again: never rolled back, and told so (A2)");
  assert.equal((await handshake(s, lost, 1)).a.accepted.resume_n, 1, "then the next resume_n");
});

test("(b) two responders sharing one store: concurrent fresh sessions at one browser_gen, and concurrent resumes, have exactly one winner", async (t) => {
  const s = await setup(t);
  const a = s.session({ browser_gen: 8 }), b = s.session({ browser_gen: 8 });
  const both = await Promise.allSettled([handshake(s, a), handshake(s, b)]);
  assert.deepEqual(both.map((r) => r.status).sort(), ["fulfilled", "rejected"]);
  assert.equal(both.find((r) => r.status === "rejected").reason.code, "browser_gen_stale");
  const winner = both[0].status === "fulfilled" ? a : b;
  assert.equal(s.store.get().agents[s.agent].live.session, winner.body.session);
  const resumes = await Promise.all([handshake(s, winner, 1), handshake(s, winner, 1)]);
  assert.deepEqual(resumes.map((r) => (r.a.accepted ? "accepted" : "refused")).sort(), ["accepted", "refused"], "one winner; the loser is told the stored value (A2)");
  assert.equal(resumes.find((r) => r.a.refused).a.refused.resume_n, 1);
  assert.equal(s.store.get().agents[s.agent].live.resume_n, 1);
  // a second store on the same directory can't open while the first holds the lock
  await assert.rejects(lockDir(s.dir), (e) => e.code === "in_progress");
});

test("the store refuses a file that isn't its closed shape", async (t) => {
  const s = await setup(t);
  await handshake(s, s.session({ browser_gen: 2 }));
  for (const bad of [{ v: 2, agents: {} }, { v: 1, agents: { x: { high: 0, live: null } } }, { v: 1, agents: {}, extra: 1 }]) {
    assert.throws(() => s.store.commit((st) => { Object.assign(st, bad); if (bad.extra === undefined) delete st.extra; if (bad.v === 2) st.v = 2; if (bad.agents.x) st.agents = bad.agents; }), (e) => e.code === "bad_form", JSON.stringify(bad));
  }
  assert.equal(s.store.get().agents[s.agent].high, 2, "unchanged");
});

// ---- addendum A2: the one authenticated answer to a refusal, and the app's reading of message 2

const storeText = (s) => readFileSync(join(s.dir, STORE_NAME), "utf8");
const attemptOf = (sess, resume_n) => ({ host_gen: sess.body.host_gen, browser_gen: sess.body.browser_gen, resume_n });
/** One attempt through the real acceptMessage1 and compare-and-set; `lose` drops message 2 (reply never sent). */
async function attempt(s, sess, resume_n, { lose = false } = {}) {
  const p = s.prologue(sess, resume_n);
  const I = s.message1(sess, p);
  const a = await acceptMessage1(I.writeMessage1(sess.record), s.ctx(p));
  if (lose) return { a };
  const r2 = a.reply();
  const i2 = I.readMessage2(r2.message);
  return { a, r2, outcome: message2Outcome(i2.payload, attemptOf(sess, resume_n)) };
}

test("A2: a fresh session whose message 2 was lost: the retry at 0 is told 0, with no effect, and resume 1 then succeeds", async (t) => {
  const s = await setup(t);
  const sess = s.session({ browser_gen: 4 });
  await attempt(s, sess, 0, { lose: true }); // (committed; message 2 never reaches the app)
  const before = storeText(s);
  const retry = await attempt(s, sess, 0);
  assert.deepEqual(retry.a.refused, { host_gen: 3, browser_gen: 4, resume_n: 0 });
  assert.equal(retry.a.accepted, undefined, "nothing admitted");
  assert.deepEqual(Object.keys(retry.r2), ["message"], "a refusal hands out no transport");
  assert.deepEqual(retry.outcome, { refused: true, next: 1 }, "the app reads the authenticated refusal");
  assert.equal(storeText(s), before, "the store is byte-identical: nothing written");
  const next = await attempt(s, sess, 1);
  assert.deepEqual([next.a.accepted.resume_n, next.outcome.accepted], [1, true]);
});

test("A2: a resume whose message 2 was lost: the retry at n is told n, then n + 1 resumes; a lost refusal is answered the same again", async (t) => {
  const s = await setup(t);
  const sess = s.session({ browser_gen: 2 });
  await attempt(s, sess, 0);
  await attempt(s, sess, 1, { lose: true });
  const before = storeText(s);
  // (the refusal's own message 2 lost too: the same retry gets the same answer, still with no effect)
  const first = await attempt(s, sess, 1, { lose: true });
  assert.deepEqual(first.a.refused, { host_gen: 3, browser_gen: 2, resume_n: 1 });
  const again = await attempt(s, sess, 1);
  assert.deepEqual([again.a.refused.resume_n, again.outcome], [1, { refused: true, next: 2 }]);
  assert.equal(storeText(s), before);
  assert.equal((await attempt(s, sess, 2)).a.accepted.resume_n, 2);
});

test("A2: an attempt that never committed (its message 1 lost): the retry at the same n is simply accepted", async (t) => {
  const s = await setup(t);
  const sess = s.session({ browser_gen: 2 });
  await attempt(s, sess, 0);
  // (message 1 at 1 never reached the host: nothing happened there, so the retry at 1 is the next)
  const r = await attempt(s, sess, 1);
  assert.deepEqual([r.a.accepted.resume_n, r.outcome.accepted], [1, true]);
});

test("A2: silence stays silent: another key, record or session, and a replaced or stale one, get no message 2 at all", async (t) => {
  const s = await setup(t);
  const one = s.session({ browser_gen: 5 });
  await attempt(s, one, 0);
  const before = storeText(s);
  // (the live session re-signed with another app key; the same fields re-signed into another record; another session)
  assert.equal(await code(() => attempt(s, s.session({ browser_gen: 5, session: one.body.session }), 0)), "browser_gen_stale");
  assert.equal(await code(() => attempt(s, s.session({ browser_gen: 5, session: one.body.session }), 2)), "bad_form");
  // (the same session, generation and app key in another valid record, signed by the same device: its hash differs)
  const otherBody = { ...one.body, at_ms: one.body.at_ms + 1 };
  const resigned = { ...one, body: otherBody, record: seal("sb.browser-session.v1", s.sN, otherBody, s.N) };
  assert.equal(await code(() => attempt(s, resigned, 2)), "bad_form", "another record of the live session: silent");
  assert.equal(await code(() => attempt(s, resigned, 0)), "browser_gen_stale", "and fresh: silent");
  assert.equal(await code(() => attempt(s, s.session({ browser_gen: 6 }), 1)), "browser_gen_stale", "a session never accepted");
  assert.equal(storeText(s), before);
  await attempt(s, s.session({ browser_gen: 6 }), 0);
  assert.equal(await code(() => attempt(s, one, 1)), "browser_gen_stale", "a replaced session: silent, even with its exact old record");
  assert.equal(await code(() => attempt(s, one, 0)), "browser_gen_stale");
});

test("A2: a replayed old message 1 of the live session gets the refusal, writes nothing, and doesn't disturb the session", async (t) => {
  const s = await setup(t);
  const sess = s.session({ browser_gen: 3 });
  const p1 = s.prologue(sess, 0);
  const old = s.message1(sess, p1).writeMessage1(sess.record);
  await acceptMessage1(old, s.ctx(p1)).then((a) => a.reply());
  await attempt(s, sess, 1);
  const before = storeText(s);
  const replayed = await acceptMessage1(old, s.ctx(p1));
  assert.deepEqual(replayed.refused, { host_gen: 3, browser_gen: 3, resume_n: 1 });
  replayed.reply();
  assert.equal(storeText(s), before);
  assert.equal((await attempt(s, sess, 2)).a.accepted.resume_n, 2, "the live session goes on");
});

test("A2: the app's reading of message 2: two closed shapes, exactly this attempt's values, and nothing else", () => {
  const at = { host_gen: 3, browser_gen: 5, resume_n: 2 };
  const p = (v) => new TextEncoder().encode(JSON.stringify(v));
  const bad = (v, why) => assert.throws(() => message2Outcome(typeof v === "string" ? new TextEncoder().encode(v) : p(v), at), (e) => e instanceof FleetError && e.code === "bad_form", why);
  assert.deepEqual(message2Outcome(p({ browser_gen: 5, host_gen: 3, resume_n: 2 }), at), { accepted: true });
  assert.deepEqual(message2Outcome(p({ browser_gen: 5, host_gen: 3, refused: "resume_n", resume_n: 2 }), at), { refused: true, next: 3 });
  bad({ browser_gen: 5, host_gen: 3, resume_n: 1 }, "accepted at another counter");
  bad({ browser_gen: 5, host_gen: 4, resume_n: 2 }, "accepted at another host_gen");
  bad({ browser_gen: 5, host_gen: 3, refused: "resume_n", resume_n: 1 }, "a refusal naming n - 1");
  bad({ browser_gen: 5, host_gen: 3, refused: "resume_n", resume_n: 3 }, "a refusal naming n + 1");
  bad({ browser_gen: 6, host_gen: 3, refused: "resume_n", resume_n: 2 }, "another browser_gen");
  bad({ browser_gen: 5, host_gen: 2, refused: "resume_n", resume_n: 2 }, "another host_gen");
  bad({ browser_gen: 5, host_gen: 3, refused: "other", resume_n: 2 }, "another refused value");
  bad({ browser_gen: 5, host_gen: 3, refused: "resume_n", resume_n: 2, x: 1 }, "an extra key");
  bad({ browser_gen: 5, refused: "resume_n", resume_n: 2 }, "a missing key");
  bad('{"host_gen":3,"browser_gen":5,"resume_n":2}', "not canonical");
  const top = { host_gen: 3, browser_gen: 5, resume_n: Number.MAX_SAFE_INTEGER };
  assert.throws(() => message2Outcome(p({ browser_gen: 5, host_gen: 3, refused: "resume_n", resume_n: Number.MAX_SAFE_INTEGER }), top), (e) => e.code === "bad_form", "no next past the safe integers");
});
