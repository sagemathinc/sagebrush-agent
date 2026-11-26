// `sagebrush-agent host pair` (host pairing d2, d2r1, d3, d3r1, d3r2) against an in-process fake of the service's
// contract (auth's service d3 and d3r1): POST /host/pair, idempotent per (host, sign_key), verified by the core's own
// verifyRequest with gen 1 and the BODY's sign_key; POST /host/pair/result, verified with the pairing's STORED key
// (another key or host: not_found); the approved, expired and pending states; and the existing paged chain read. On a
// temporary root with the shared fixtures' honest chain; certificates sealed by the fixtures' native device.
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "./host-linux-only.mjs";
import { b64, canonBytes, hostFingerprint, keyFromSeed, newId, refuse, replayChain, seal, unb64 } from "../lib/fleet/index.mjs";
import { verifyRequest } from "../lib/fleet/request.mjs";
import { parseChainTarget } from "../lib/fleet/core/chain-service.mjs";
import { classify, firstBoot, hostPaths } from "../lib/fleet/host/identity.mjs";
import { PAIRING, PAIR_ROUTE, POLL_MS, RESULT_ROUTE, RESUME_HORIZON_MS, addPairing, fleetFp, normalizeFleetFp, pairCommand, readIntent } from "../lib/fleet/host/pair.mjs";

const F = JSON.parse(readFileSync(new URL("./fixtures/fleet-fixtures.json", import.meta.url), "utf8"));
const enc = (s) => new TextEncoder().encode(s);
const AUD = F.aud, FLEET = F.ids.fleet;
const N = keyFromSeed(Buffer.from(F.keys["device-native"].seed, "hex"));
const ENTRIES = F.objects.chain.map(enc);
const UID = process.getuid?.() ?? -1;
const machine = () => "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n";
const T0 = 1_800_000_000_000;
let FP; // the fixtures' fleet fingerprint, shown form

/** A fake of the service's pairing contract. `clock.now()`: its wall clock (shared with the host's). */
function fakeService(clock, { pageSize = 256, fleet = FLEET, entries = ENTRIES } = {}) {
  const byHost = new Map(), nonces = new Set(), log = [];
  const s = { log, byHost, dropReply: 0, failPair: 0, rateNext: 0 };
  const verify = (header, method, target, body, keyOf) => verifyRequest({ header, method, target, body }, {
    aud: AUD, now: clock.now(), hostKey: keyOf, currentGen: () => 1,
    consumeNonce: (h, n) => (nonces.has(`${h}/${n}`) ? false : (nonces.add(`${h}/${n}`), true)),
  });
  const ok = (json) => ({ status: 200, json });
  const no = (status, error) => ({ status, json: { error } });
  const code = () => Array.from({ length: 8 }, () => "abcdefghijklmnopqrstuvwxyz234567"[Math.floor(Math.random() * 32)]).join("");
  s.pair = async (origin, body, header) => {
    log.push("pair");
    if (s.failPair > 0) { s.failPair--; return { cls: "network" }; }
    assert.equal(origin, AUD);
    if (body.length > 4096) return no(400, "bad_form");
    const b = JSON.parse(Buffer.from(body).toString("utf8"));
    if (!/^[a-z0-9-]{1,32}$/.test(b.name)) return no(400, "bad_form");
    try { verify(header, "POST", PAIR_ROUTE, body, (h) => { if (h !== b.host) refuse("bad_signature"); return unb64(b.sign_key, 32); }); } catch (e) { return no(401, e.code); }
    if (b64(await hostFingerprint(b.host, unb64(b.sign_key, 32), unb64(b.enc_key, 32))) !== b.fingerprint) return no(400, "bad_form");
    let r = byHost.get(b.host);
    if (r && (r.sign_key !== b.sign_key || r.enc_key !== b.enc_key)) return no(400, "bad_form");
    if (!r) { r = { pairing: newId(), ...b, expires: clock.now() + 600_000, cert: null, expired: false }; byHost.set(b.host, r); }
    let out;
    if (r.cert) out = ok({ pairing: r.pairing, state: "approved" });
    else if (r.expired || clock.now() > r.expires) out = ok({ pairing: r.pairing, state: "expired" });
    else { r.code = code(); out = ok({ pairing: r.pairing, code: r.code, expires_at_ms: r.expires }); }
    if (s.dropReply > 0) { s.dropReply--; return { cls: "network" }; } // (created, then the reply lost)
    return out;
  };
  const byPairing = (id) => [...byHost.values()].find((r) => r.pairing === id);
  s.result = async (origin, body, header) => {
    log.push("result");
    const b = JSON.parse(Buffer.from(body).toString("utf8"));
    const r = byPairing(b.pairing);
    if (!r) return no(404, "not_found");
    try { verify(header, "POST", RESULT_ROUTE, body, (h) => { if (h !== r.host) refuse("not_found"); return unb64(r.sign_key, 32); }); } catch (e) { return no(e.code === "not_found" ? 404 : 401, e.code); }
    if (s.rateNext > 0) { s.rateNext--; return no(429, "rate"); }
    if (r.cert) return ok({ state: "approved", fleet, cert: b64(r.cert) });
    if (r.expired || clock.now() > r.expires) return ok({ state: "expired" });
    return ok({ state: "pending" });
  };
  s.chainPage = async (origin, target, header) => {
    log.push("chain");
    const known = [...byHost.values()].find((r) => r.cert);
    try { verify(header, "GET", target, new Uint8Array(0), (h) => { if (!known || h !== known.host) refuse("unknown_host"); return unb64(known.sign_key, 32); }); } catch { return { cls: "status" }; }
    const after = parseChainTarget(target);
    const page = entries.slice(after + 1, after + 1 + pageSize).map((e) => Buffer.from(e).toString("utf8"));
    return { bytes: canonBytes({ entries: page, head: entries.length - 1 }) };
  };
  /** The app's approval: a certificate for the pairing's host and keys (or `o`'s), sealed by the native device. */
  s.approve = async (host, o = {}) => {
    const r = byHost.get(host);
    const chain = await replayChain(ENTRIES, { aud: AUD, fleet: FLEET });
    const signRaw = unb64(o.sign_key ?? r.sign_key, 32), encRaw = unb64(o.enc_key ?? r.enc_key, 32), id = o.host ?? r.host;
    const body = { fleet: FLEET, aud: AUD, chain_seq: chain.seq, host: id, sign_key: b64(signRaw), enc_key: b64(encRaw),
      fingerprint: b64(await hostFingerprint(id, signRaw, encRaw)), name: r.name, at_ms: clock.now() };
    r.cert = seal("sb.host-cert.v1", { kind: "device", id: F.ids.device_native, alg: "ed25519", key: N.key }, body, N);
  };
  s.only = () => { assert.equal(byHost.size, 1, "one pairing at the service"); return [...byHost.values()][0]; };
  return s;
}

/** A FRESH host on a temporary root, and a run of `host pair` against `svc`. */
function setup(o = {}) {
  const root = mkdtempSync(join(tmpdir(), "sb-pair-"));
  mkdirSync(join(root, "var/lib/sagebrush"), { recursive: true, mode: 0o755 });
  const p = hostPaths(root);
  firstBoot(p, { machineId: machine, brokerUid: UID });
  const clock = { t: T0, now() { return this.t; } };
  const svc = fakeService(clock, o);
  const out = [];
  const tty = { write: (s) => out.push(s), ask: async () => o.answer ?? null, close: () => {} };
  const writes = [];
  const run = (argv = ["--fleet", FP, "--service", AUD], extra = {}) => pairCommand(argv, {
    uid: () => UID, rootUid: UID, paths: p, tty, service: svc, now: () => clock.now(),
    lock: async () => ({ release() {} }),
    classify: (pp) => classify(pp, { machineId: machine, brokerUid: UID, rootUid: UID }),
    sleep: async (ms) => { clock.t += ms; await (extra.onSleep ?? (() => {}))(); },
    ...extra,
    pairWrite: extra.pairWrite ?? (async (...a) => { writes.push(1); return (await import("../lib/fleet/host/identity.mjs")).pairWrite(...a); }),
  });
  const intent = () => readIntent(p.identity, { uid: UID });
  const intentBytes = () => (existsSync(join(p.identity, PAIRING)) ? readFileSync(join(p.identity, PAIRING)) : null);
  const state = async () => (await classify(p, { machineId: machine, brokerUid: UID, rootUid: UID })).state;
  const identityFiles = () => (existsSync(p.identity) ? readdirSync(p.identity).sort() : []);
  return { root, p, clock, svc, out, run, intent, intentBytes, state, identityFiles, writes };
}
/** Approve at the poll after the request: the newest pairing (the attempt under way). */
const approveSoon = (h) => async () => { const r = [...h.svc.byHost.values()].at(-1); if (r && !r.cert) await h.svc.approve(r.host); };

test("the fixtures' fleet fingerprint, normalized: any case, dashes and spaces; anything else is no fingerprint", async () => {
  FP = (await import("../lib/fleet/index.mjs")).showFingerprint(await (await import("../lib/fleet/index.mjs")).fleetFingerprint(FLEET, ENTRIES[0]));
  assert.equal(await fleetFp(FLEET, ENTRIES[0]), FP.replace(/-/g, ""));
  assert.equal(normalizeFleetFp(FP.toUpperCase().replace(/-/g, " ")), FP.replace(/-/g, ""));
  for (const bad of ["", "abc", `${FP}a`, FP.replace(/^./, "1"), null, undefined, 7]) assert.equal(normalizeFleetFp(bad), null, String(bad));
});

test("the happy path, FRESH to PAIRED: the intent before the request, the code and fingerprint only on the terminal, the chain fetched and checked, the identity written, the intent removed", async () => {
  const h = setup({ pageSize: 2 });
  let sawIntentBeforePair = false;
  const pair = h.svc.pair;
  h.svc.pair = async (...a) => { sawIntentBeforePair = h.intent() !== null; return pair(...a); };
  const r = await h.run(undefined, { onSleep: approveSoon(h) });
  assert.deepEqual(r, { code: 0, line: { v: 1, paired: true } });
  assert.ok(sawIntentBeforePair, "the intent is durable before the first request");
  assert.equal(await h.state(), "PAIRED");
  assert.equal(h.intentBytes(), null, "the intent removed after pairWrite");
  const shown = h.out.join("");
  const rec = h.svc.only();
  assert.ok(shown.includes(`${rec.code.slice(0, 4)}-${rec.code.slice(4)}`), "the code on the terminal");
  assert.match(shown, /This host's fingerprint: [a-z2-7]{4}(-[a-z2-7]{4}){4}/);
  assert.ok(!JSON.stringify(r.line).includes(rec.code), "never in the line");
  assert.deepEqual(h.svc.log.filter((x) => x === "chain").length, 3, "6 entries in pages of 2");
});

test("option B: the anchor comes before any request; none, or a malformed one, is bad_form with nothing sent or written", async () => {
  for (const [argv, answer] of [[["--service", AUD], null], [["--service", AUD], "not-a-fingerprint"], [["--fleet", "abc", "--service", AUD], null]]) {
    const h = setup({ answer });
    const r = await h.run(argv);
    assert.deepEqual(r.line, { v: 1, refused: "bad_form" }, JSON.stringify(argv));
    assert.deepEqual(h.svc.log, [], "nothing sent");
    assert.equal(h.intentBytes(), null, "nothing written");
  }
  // Asked on the terminal when --fleet is absent.
  const h = setup({ answer: FP.toUpperCase() });
  const r = await h.run(["--service", AUD], { onSleep: approveSoon(h) });
  assert.equal(r.code, 0);
});

test("a fetched genesis whose fingerprint isn't the one given: not_granted, pairWrite never called, the identity untouched", async () => {
  const other = FP.replace(/^a/, "b") === FP ? FP.replace(/^./, "a") : FP.replace(/^./, (c) => (c === "a" ? "b" : "a"));
  const h = setup();
  const r = await h.run(["--fleet", other, "--service", AUD], { onSleep: approveSoon(h) });
  assert.deepEqual(r.line, { v: 1, refused: "not_granted" });
  assert.equal(h.writes.length, 0, "pairWrite never reached");
  assert.equal(await h.state(), "FRESH");
  assert.deepEqual(h.identityFiles(), [PAIRING], "only the intent (kept: its pairing lives)");
});

test("d3: a crash before the create, or after it with the reply lost, or during the POST: the resume re-POSTs and gets the SAME pairing (one at the service), same host and anchor", async () => {
  for (const how of ["before", "lost", "signal"]) {
    const h = setup();
    const ac = new AbortController();
    if (how === "before") h.svc.failPair = 1;
    if (how === "lost") h.svc.dropReply = 1;
    const first = await h.run(undefined, how === "signal" ? { signal: ac.signal, onSleep: () => ac.abort() } : {});
    assert.equal(first.code, 1, how);
    const x1 = h.intent();
    assert.ok(x1 !== null, `${how}: the intent kept`);
    const firstCode = h.svc.byHost.size ? h.svc.only().code : null;
    const r = await h.run(undefined, { onSleep: approveSoon(h) });
    assert.equal(r.code, 0, `${how}: ${JSON.stringify(r)}`);
    const rec = h.svc.only();
    assert.equal(rec.host, x1.host, `${how}: the same host id`);
    if (how === "lost") assert.notEqual(rec.code, firstCode, "a new code for the same pairing");
  }
});

test("d3: a resume with the pairing recorded polls it (no new request); approval while stopped, resumed after more than 10 minutes (within the horizon), completes", async () => {
  const h = setup();
  const ac = new AbortController();
  const first = await h.run(undefined, { signal: ac.signal, onSleep: () => ac.abort() });
  assert.deepEqual(first.line, { v: 1, refused: "outcome_unknown" });
  const x = h.intent();
  assert.ok(x.pairing);
  await h.svc.approve(x.host);
  h.clock.t += 3 * 60 * 60 * 1000; // (3 hours later: past the 10-minute approval window, inside the horizon)
  h.svc.log.length = 0;
  const r = await h.run();
  assert.equal(r.code, 0);
  assert.equal(h.svc.log[0], "result", "polled, not re-requested");
  assert.ok(!h.svc.log.includes("pair"));
  assert.equal(await h.state(), "PAIRED");
});

test("d2r1 §B: on resume the record is THE anchor: without --fleet it's used; a different --fleet or --service is not_granted with nothing done", async () => {
  const h = setup();
  h.svc.failPair = 1;
  await h.run();
  const before = h.intentBytes();
  const other = `${FP.slice(0, -1)}${FP.endsWith("a") ? "b" : "a"}`;
  for (const argv of [["--fleet", other], ["--fleet", FP, "--service", "https://sagebrush.space"]]) {
    h.svc.log.length = 0;
    const r = await h.run(argv);
    assert.deepEqual(r.line, { v: 1, refused: "not_granted" }, JSON.stringify(argv));
    assert.deepEqual(h.svc.log, [], "no request");
    assert.deepEqual(h.intentBytes(), before, "the record byte-identical");
  }
  const r = await h.run([], { onSleep: approveSoon(h) });
  assert.equal(r.code, 0, "the persisted anchor and service used");
});

test("expired: by the poll, or by a re-POST: reported pairing_expired, the record removed, no second request in that invocation; a rerun is a new attempt with a new host id", async () => {
  // The poll answers expired.
  const h = setup();
  const r = await h.run(undefined, { onSleep: () => { h.clock.t += 600_000; } });
  assert.deepEqual(r.line, { v: 1, refused: "pairing_expired" });
  assert.equal(h.intentBytes(), null);
  assert.equal(h.svc.log.filter((x) => x === "pair").length, 1, "no new attempt in the same invocation");
  // A re-POST answered expired (the reply of the first create lost, then the approval window passed).
  const g = setup();
  g.svc.dropReply = 1;
  await g.run();
  const old = g.intent().host;
  g.clock.t += 600_001;
  g.svc.log.length = 0;
  const r2 = await g.run();
  assert.deepEqual(r2.line, { v: 1, refused: "pairing_expired" });
  assert.deepEqual(g.svc.log, ["pair"], "one re-POST, nothing more");
  assert.equal(g.intentBytes(), null);
  const r3 = await g.run(undefined, { onSleep: approveSoon(g) });
  assert.equal(r3.code, 0);
  assert.equal(g.svc.byHost.size, 2, "the rerun is a new pairing");
  assert.ok(![...g.svc.byHost.values()].find((x) => x.cert && x.host === old), "under a NEW host id");
});

test("d3r2: the resume horizon, exactly 7 days and 7 days + 1 ms, with and without a saved pairing; a backwards clock is past it; nothing is sent past it", async () => {
  for (const saved of [false, true]) {
    for (const [dt, past] of [[RESUME_HORIZON_MS, false], [RESUME_HORIZON_MS + 1, true], [-1, true]]) {
      const h = setup();
      const ac = new AbortController();
      if (saved) await h.run(undefined, { signal: ac.signal, onSleep: () => ac.abort() }); else { h.svc.failPair = 1; await h.run(); }
      const x = h.intent();
      assert.equal(Object.hasOwn(x, "pairing"), saved);
      if (saved) await h.svc.approve(x.host);
      h.clock.t = x.created_ms + dt;
      h.svc.log.length = 0;
      // (within the horizon the approval window is long past: a saved pairing is approved; an unsaved one re-POSTs and is expired)
      const r = await h.run();
      const what = `saved=${saved} dt=${dt}`;
      if (past) {
        assert.deepEqual(r.line, { v: 1, refused: "pairing_expired" }, what);
        assert.deepEqual(h.svc.log, [], `${what}: no request of any kind`);
        assert.equal(h.intentBytes(), null, what);
      } else {
        assert.ok(h.svc.log.length > 0, `${what}: resumed`);
        assert.equal(h.svc.log[0], saved ? "result" : "pair", what);
      }
    }
  }
});

test("the intent's fields are immutable: the rewrite that adds the pairing refuses a changed record, and a second intent never replaces the first", async () => {
  const h = setup();
  h.svc.failPair = 1;
  await h.run();
  const x = h.intent();
  for (const k of ["host", "host_fp", "origin", "fleet_fp", "created_ms"]) {
    const changed = { ...x, [k]: k === "created_ms" ? x.created_ms + 1 : k === "origin" ? "https://sagebrush.space" : k === "fleet_fp" ? "a".repeat(20) : k === "host" ? newId() : "x" };
    assert.throws(() => addPairing(h.p.identity, changed, newId(), { uid: UID }), (e) => e.code === "not_granted", k);
  }
  const { writeIntent } = await import("../lib/fleet/host/pair.mjs");
  assert.throws(() => writeIntent(h.p.identity, { ...x, host: newId() }), (e) => e.code === "EEXIST");
  assert.deepEqual(h.intent(), x);
});

test("not_found from the poll (the service forgot the pairing): reported, the record removed", async () => {
  const h = setup();
  const r = await h.run(undefined, { onSleep: () => { h.svc.byHost.clear(); } });
  assert.deepEqual(r.line, { v: 1, refused: "not_found" });
  assert.equal(h.intentBytes(), null);
});

test("a rate refusal or a transport failure while polling is waited out; the pairing completes", async () => {
  const h = setup();
  h.svc.rateNext = 2;
  let n = 0;
  const result = h.svc.result;
  h.svc.result = async (...a) => (++n === 2 ? { cls: "timeout" } : result(...a));
  const r = await h.run(undefined, { onSleep: async () => { if (n >= 4) await approveSoon(h)(); } });
  assert.equal(r.code, 0);
});

test("a certificate for another host id, or for other keys: not_granted, nothing written", async () => {
  for (const o of [{ host: newId() }, { sign_key: b64(keyFromSeed(new Uint8Array(32).fill(9)).raw) }]) {
    const h = setup();
    const r = await h.run(undefined, { onSleep: async () => { const rec = [...h.svc.byHost.values()][0]; if (!rec.cert) await h.svc.approve(rec.host, o); } });
    assert.deepEqual(r.line, { v: 1, refused: "not_granted" }, JSON.stringify(Object.keys(o)));
    assert.equal(await h.state(), "FRESH");
  }
});

test("the host's keys changed since the attempt began (a reset): the intent can't resume; pairing_expired, removed, nothing sent", async () => {
  const h = setup();
  h.svc.failPair = 1;
  await h.run();
  const x = h.intent();
  const { writeFileSync } = await import("node:fs");
  writeFileSync(join(h.p.identity, PAIRING), JSON.stringify({ ...x, host_fp: b64(new Uint8Array(32)) }) + "\n", { mode: 0o600 });
  h.svc.log.length = 0;
  const r = await h.run();
  assert.deepEqual(r.line, { v: 1, refused: "pairing_expired" });
  assert.deepEqual(h.svc.log, []);
  assert.equal(h.intentBytes(), null);
});

test("refusals with nothing sent or written: not root, no terminal, the lock held, PAIRED, CLONE", async () => {
  const cases = {
    "not root": { uid: () => UID + 1, want: "not_granted" },
    "no terminal": { tty: null, want: "not_granted" },
    "the lock held": { lock: async () => { throw Object.assign(new Error("busy"), { code: "in_progress", busy: true }); }, want: "in_progress" },
    PAIRED: { classify: async () => ({ state: "PAIRED" }), want: "in_progress" },
    CLONE: { classify: async () => ({ state: "CLONE" }), want: "not_granted" },
    REVOKED: { classify: async () => ({ state: "REVOKED" }), want: "not_granted" },
  };
  for (const [what, { want, ...extra }] of Object.entries(cases)) {
    const h = setup();
    const r = await h.run(undefined, extra);
    assert.deepEqual(r.line, { v: 1, refused: want }, what);
    assert.deepEqual(h.svc.log, [], `${what}: nothing sent`);
    assert.equal(h.intentBytes(), null, `${what}: nothing written`);
  }
});

test("usage: unknown or repeated flags", async () => {
  for (const argv of [["--bogus", "x"], ["--fleet"], ["--fleet", "a", "--fleet", "b"]]) {
    const r = await pairCommand(argv, {});
    assert.equal(r.code, 2, JSON.stringify(argv));
  }
  assert.equal(POLL_MS, 5000);
});
