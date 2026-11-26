// Host supervisor (host daemon main r1.1, frozen): `host run` and `host reset-identity` against fake effects, each run's
// effects recorded in one event log. The order of preflight, the lock, the kept systemd pin, the classification, the
// containment (the whole operation, retried while unproven), each state's step, PAIRED's gates and serving; SIGTERM in
// each phase; the settings file; the real containment's effects against fakes; the registry's names and meanings for
// every emitter; the bin's hand-over; and no key on any surface. (The real systemd and cgroup rows run on a VM.)
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "./host-linux-only.mjs";
import { b64, hostFingerprint, keyFromSeed, newId, replayChain, seal, sha256b64 } from "../lib/fleet/index.mjs";
import { classify, firstBoot, hostPaths } from "../lib/fleet/host/identity.mjs";
import { ADAPTERS, CONFIG_MAX, CONTAIN_RETRY_MS, INITIAL_SYNC_MS, RESUME_BASE_KEYS, brokerAccount, hostResetIdentity, hostRun, readHostConfig, realContainSys, resumeBase, resumeRequester, supervisorUnit } from "../lib/fleet/host/host-main.mjs";
import { RESUME_HELPER_MS, requestResume } from "../lib/fleet/host/restore-resume.mjs";
import { expectedOf } from "../lib/fleet/host/restore-plan.mjs";
import { QUALIFIED_MAJOR } from "../lib/fleet/host/host-preflight.mjs";
import { HEALTH_REASONS, hostState } from "../lib/fleet/host/host-state.mjs";
import { Supervisor } from "../lib/fleet/host/executor.mjs";
import { HostStore } from "../lib/fleet/host/host-store.mjs";
import { brokerUidEmpty } from "../lib/fleet/host/uid-proof.mjs";
import { BROKER_UNIT, BROKER_USER } from "../lib/fleet/host/names.mjs";

const F = JSON.parse(readFileSync(new URL("./fixtures/fleet-fixtures.json", import.meta.url), "utf8"));
const REG = JSON.parse(readFileSync(new URL("../schema/fleet/reasons.json", import.meta.url), "utf8")).reasons;
const enc = (s) => new TextEncoder().encode(s);
// process.getuid doesn't exist off POSIX; there every test here is skipped (host-linux-only), so UID is never used.
const UID = process.getuid?.() ?? -1;
const AUD = F.aud, FLEET = F.ids.fleet, HOST = F.ids.host, NOW = 1_800_000_000_000;
const N = keyFromSeed(Buffer.from(F.keys["device-native"].seed, "hex"));
const tmp = () => mkdtempSync(join(tmpdir(), "sb-main-"));
const machine = () => "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n";
const GOOD = `systemd ${QUALIFIED_MAJOR} (${QUALIFIED_MAJOR}.4-1ubuntu8.19)\n`, BAD = `systemd ${QUALIFIED_MAJOR + 1} (${QUALIFIED_MAJOR + 1}.1-1)\n`;

/** A real PAIRED identity on a temporary root (its keys from first boot), and its private key bytes for the scan. */
async function pairedIdentity() {
  const root = tmp(), p = hostPaths(root);
  mkdirSync(join(root, "var/lib/sagebrush"), { recursive: true, mode: 0o755 });
  firstBoot(p, { machineId: machine, brokerUid: UID });
  const fresh = await classify(p, { machineId: machine, brokerUid: UID, rootUid: UID });
  const entries = F.objects.chain.map(enc);
  const chain = await replayChain(entries, { aud: AUD, fleet: FLEET });
  const pin = { fleet: FLEET, aud: AUD, seq: chain.seq, hash: chain.head };
  const body = { fleet: FLEET, aud: AUD, chain_seq: chain.seq, host: HOST, sign_key: b64(fresh.keys.sign.raw), enc_key: b64(fresh.keys.enc.raw),
    fingerprint: b64(await hostFingerprint(HOST, fresh.keys.sign.raw, fresh.keys.enc.raw)), name: "t", at_ms: NOW };
  const certBytes = seal("sb.host-cert.v1", { kind: "device", id: F.ids.device_native, alg: "ed25519", key: N.key }, body, N);
  mkdirSync(join(p.identity, "chain"), { recursive: true, mode: 0o700 });
  chmodSync(p.identity, 0o700);
  entries.forEach((e, s) => writeFileSync(join(p.identity, "chain", String(s)), e, { mode: 0o600 }));
  writeFileSync(join(p.identity, "pin"), JSON.stringify(pin), { mode: 0o600 });
  writeFileSync(join(p.identity, "host-cert"), certBytes, { mode: 0o600 });
  const id = await classify(p, { machineId: machine, brokerUid: UID, rootUid: UID });
  assert.equal(id.state, "PAIRED", id.why);
  const secrets = { signSeed: readFileSync(join(p.keys, "sign")), encPriv: readFileSync(join(p.keys, "enc")) };
  secrets.signPriv = Buffer.concat([secrets.signSeed, Buffer.from(id.keys.sign.raw)]); // (the 64-byte private key form)
  return { id, paths: p, secrets };
}
let PAIRED_ID = null;
const paired = async () => (PAIRED_ID ??= await pairedIdentity());

/** Every surface every row wrote to (SEC H3): scanned for the keys after the whole suite. */
const SURFACES = [];
const capture = (surface, v) => { SURFACES.push({ surface, text: typeof v === "string" ? v : safeJson(v) }); };
function safeJson(v) {
  try { return JSON.stringify(v, (_k, x) => (x instanceof Uint8Array ? Array.from(x) : typeof x === "bigint" ? String(x) : x)); } catch { return String(v); }
}

/**
 * Fake effects for `hostRun` / `hostResetIdentity`. `o`: { state | id, version, contain: [bool...] (each attempt's
 * proof; the last repeats), config (throws if an Error), adapters, root, linux, broker, lock: "ok" | "busy" | "bad",
 * sleep(ms) → promise, sync (the initial sync's promise), reset: [errors...], supervisor: over }.
 */
function harness(o = {}) {
  const log = [], lines = [], made = {};
  let termNow;
  const terminated = new Promise((r) => { termNow = r; });
  const contain = o.contain ?? [true];
  let attempts = 0;
  const ev = (name, detail) => { log.push(detail === undefined ? name : `${name}:${detail}`); capture("event", { name, detail }); };
  const adapters = o.adapters ?? Object.fromEntries(ADAPTERS.map((k) => [k, (...a) => { capture("audit", { adapter: k, args: a }); }]));
  const d = {
    paths: o.paths ?? hostPaths(tmp()),
    rootUid: UID,
    isRoot: () => o.root ?? true,
    isLinux: () => o.linux ?? true,
    brokerAccount: () => (o.broker === undefined ? { uid: 990, gid: 990 } : o.broker),
    takeOwnership: async () => {
      ev("lock");
      if (o.lock === "busy") throw Object.assign(new Error("held"), { code: "in_progress", busy: true });
      if (o.lock === "bad") throw Object.assign(new Error("bad"), { code: "bad_form" });
      return { release: async () => ev("release") };
    },
    systemdVersion: async () => { ev("systemd"); return o.version ?? GOOD; },
    machineId: machine,
    classify: async () => { ev("classify"); return o.id ?? { state: o.state ?? "FRESH" }; },
    sys: {
      stopAll: async () => { ev("stopAll"); return { proven: contain[Math.min(attempts, contain.length - 1)] }; },
      stopBroker: async () => { ev("stopBroker"); const p = contain[Math.min(attempts, contain.length - 1)]; attempts += 1; return { proven: p }; },
    },
    completeReset: async () => {
      ev("completeReset");
      const e = (o.reset ?? []).shift();
      if (e) throw e;
    },
    resetIdentity: async () => { ev("resetIdentity"); const e = (o.reset ?? []).shift(); if (e) throw e; },
    firstBoot: () => ev("firstBoot"),
    dropOrphans: () => ev("dropOrphans"),
    chownBroker: () => () => {},
    readConfig: () => { ev("config"); if (o.config instanceof Error) throw o.config; return o.config ?? { lease: "off" }; },
    // the lease's qualification (lease-on r1.7 §2): unqualified (no record) unless a row says otherwise
    leaseQualified: async () => { ev("leaseQualified"); if (o.qualified instanceof Error) throw o.qualified; return o.qualified ?? { ok: false, why: "record" }; },
    makeLease: (x) => { ev("lease"); made.leaseOpts = x; made.lease = { live: () => null, due: () => {}, voidAll: () => {} }; return made.lease; },
    readPlan: () => null,
    restoreReady: () => "validated",
    pairOf: () => null,
    runHelper: async (argv) => { ev("runHelper"); made.helperArgv = argv; return { code: 0, stdout: "" }; },
    resumeMain: "/opt/sagebrush/release/lib/fleet/host/restore-resume-main.mjs",
    requestResume: async (agent, opts) => { ev("requestResume"); (made.resumeCalls ??= []).push({ agent, opts }); return { resumed: false, reason: "no_receipt" }; },
    adapters,
    unmaskBroker: async () => ev("unmask"),
    openStore: async () => { ev("store"); return { grants: { highwater: { gen: 0 } }, close: async () => ev("storeClose") }; },
    effects: (x) => { ev("effects"); made.effects = x; return {}; },
    makeSupervisor: (x) => {
      ev("supervisor");
      made.supervisor = x;
      const sup = { revoked: false, recover: async () => ev("recover"), submit: async (op) => { ev("submit", op.kind); return { status: "ok" }; },
        close: async () => ev("close"), ...(o.supervisor?.(x, ev) ?? {}) };
      made.sup = sup;
      return sup;
    },
    makeSync: (x) => {
      ev("syncMade");
      made.sync = x;
      return { sync: () => { ev("sync"); return o.sync ?? Promise.resolve({ status: "current" }); }, snapshot: () => made.snapshot ?? x.snapshot,
        start: (s) => ev("syncStart", s.first), stop: () => ev("syncStop") };
    },
    host: { release: "/opt/sagebrush/release" },
    hostInfo: { ramMb: 8192, cpus: 4 },
    inputs: ({ submit }) => { ev("inputs"); made.submit = submit; return () => ev("inputsStop"); },
    wall: () => NOW,
    sleep: o.sleep ?? ((ms) => { ev("sleep", ms); return Promise.resolve(); }),
    terminated,
    out: (s) => { capture("stderr", s); lines.push(JSON.parse(s)); },
  };
  return { d, log, lines, made, term: () => termNow(), attempts: () => attempts };
}
/** Settle until `fn()` holds (the daemon's awaits run in between), at most 2000 turns. */
async function until(fn) { for (let i = 0; i < 2000 && !fn(); i++) await new Promise((r) => setImmediate(r)); assert.ok(fn(), "never reached"); }
const CONTAIN = ["stopAll", "stopBroker"];
const refusal = (lines) => lines.filter((l) => l.refused !== undefined).map((l) => l.refused);

// ---- preflight and the lock (r1.1 §2 steps 1–2)

test("preflight: not root, not Linux, or no sb-broker user refuses preflight_missing with the log empty: no lock, nothing classified, read or stopped", async () => {
  for (const over of [{ root: false }, { linux: false }, { broker: null }, { broker: { uid: 0, gid: 0 } }]) {
    const h = harness(over);
    const r = await hostRun(h.d);
    assert.deepEqual([r.code, refusal(h.lines)], [3, ["preflight_missing"]], JSON.stringify(over));
    assert.deepEqual(h.log, [], JSON.stringify(over));
    const g = harness(over);
    assert.equal((await hostResetIdentity(g.d)).code, 3);
    assert.deepEqual(g.log, []);
  }
});

test("the lock first: held refuses busy and a bad lock or parent refuses identity_broken, each with nothing classified or stopped", async () => {
  for (const [lock, reason] of [["busy", "busy"], ["bad", "identity_broken"]]) {
    const h = harness({ lock });
    assert.equal((await hostRun(h.d)).code, 3);
    assert.deepEqual(refusal(h.lines), [reason]);
    assert.deepEqual(h.log, ["lock"]);
  }
});

// ---- the containment (§2.1) and each state (§2 steps 5–7)

test("each non-PAIRED state: the proven containment before anything else, then exactly its step", async () => {
  const want = {
    FRESH: [[], "FRESH"], PAIRING: [[], "PAIRING"], NO_KEYS: [["firstBoot"], "FRESH"], RESETTING: [["completeReset", "firstBoot"], "FRESH"],
    REVOKED: [[], "host_ended"], CLONE: [[], "clone_detected"], BROKEN: [[], "identity_broken"],
  };
  for (const [state, [steps, end]] of Object.entries(want)) {
    const h = harness({ state });
    const run = hostRun(h.d);
    if (["FRESH", "PAIRING", "NO_KEYS", "RESETTING"].includes(state)) {
      await until(() => h.lines.some((l) => l.state));
      assert.deepEqual(h.lines, [{ v: 1, state: end }], state);
      assert.ok(!h.log.includes("release"), "the lock is held while idle");
      h.term();
      assert.equal((await run).code, 0, state);
    } else {
      assert.equal((await run).code, 3, state);
      assert.deepEqual(refusal(h.lines), [end], state);
    }
    assert.deepEqual(h.log, ["lock", "systemd", "classify", ...CONTAIN, ...steps, "release"], state);
  }
});

test("the containment is the whole operation: unproven, it says so, waits 10 s and repeats raise, stop, mask and prove; nothing else meanwhile; no exit, the lock held", async () => {
  const sleeps = [];
  let wake;
  const h = harness({ state: "NO_KEYS", contain: [false, false, true], sleep: (ms) => { sleeps.push(ms); return new Promise((r) => { wake = r; }); } });
  const run = hostRun(h.d);
  await until(() => sleeps.length === 1);
  assert.deepEqual(h.log, ["lock", "systemd", "classify", ...CONTAIN]);
  assert.deepEqual(h.lines, [{ v: 1, containment: "unproven" }]);
  wake();
  await until(() => sleeps.length === 2);
  assert.deepEqual(h.log, ["lock", "systemd", "classify", ...CONTAIN, ...CONTAIN], "the whole attempt again, nothing else");
  assert.deepEqual(sleeps, [CONTAIN_RETRY_MS, CONTAIN_RETRY_MS]);
  wake();
  await until(() => h.lines.some((l) => l.state));
  assert.deepEqual(h.log, ["lock", "systemd", "classify", ...CONTAIN, ...CONTAIN, ...CONTAIN, "firstBoot"], "proven: then the state's step");
  h.term();
  assert.equal((await run).code, 0);
});

test("either part alone unproven is unproven: the agents proven and the broker not, or the reverse; the frozen intervals", async () => {
  assert.equal(CONTAIN_RETRY_MS, 10_000, "r1.1 §2.1: every 10 s");
  assert.equal(INITIAL_SYNC_MS, 60_000, "r1.1 §2 step 12: SYNC_MS for each of at most 4 pages");
  for (const [agents, broker] of [[[true], [false, true]], [[false, true], [true]]]) {
    const h = harness({ state: "CLONE" });
    let a = 0, b = 0;
    h.d.sys = { stopAll: async () => ({ proven: agents[Math.min(a++, agents.length - 1)] }), stopBroker: async () => ({ proven: broker[Math.min(b++, broker.length - 1)] }) };
    assert.equal((await hostRun(h.d)).code, 3);
    assert.deepEqual(h.lines, [{ v: 1, containment: "unproven" }, { v: 1, refused: "clone_detected" }], JSON.stringify({ agents, broker }));
    assert.deepEqual([a, b], [2, 2], "the whole attempt twice");
  }
});

test("a containment part that throws is unproven, and the other part still runs in that attempt", async () => {
  const h = harness({ state: "CLONE" });
  let n = 0;
  h.d.sys = { stopAll: async () => { n += 1; if (n === 1) throw new Error("x"); return { proven: true }; }, stopBroker: async () => { h.log.push("stopBroker"); return { proven: true }; } };
  assert.equal((await hostRun(h.d)).code, 3);
  assert.deepEqual(h.lines, [{ v: 1, containment: "unproven" }, { v: 1, refused: "clone_detected" }]);
  assert.equal(h.log.filter((l) => l === "stopBroker").length, 2);
});

test("the wrong systemd major, for PAIRED and each other state: contained, then qualify_required, before any state action; unproven, it retries with no refusal and no exit", async () => {
  const { id } = await paired();
  for (const state of ["PAIRED", "FRESH", "PAIRING", "NO_KEYS", "RESETTING", "REVOKED", "CLONE", "BROKEN"]) {
    const h = harness({ version: BAD, ...(state === "PAIRED" ? { id } : { state }) });
    assert.equal((await hostRun(h.d)).code, 3, state);
    assert.deepEqual(refusal(h.lines), ["qualify_required"], state);
    assert.deepEqual(h.log, ["lock", "systemd", "classify", ...CONTAIN, "release"], state);
  }
  for (const version of ["", "garbage\n"]) {
    const h = harness({ version, id });
    await hostRun(h.d);
    assert.deepEqual(refusal(h.lines), ["qualify_required"], "an unreadable version is a bad pin");
  }
  let wake;
  const sleeps = [];
  const h = harness({ version: BAD, id, contain: [false, true], sleep: (ms) => { sleeps.push(ms); return new Promise((r) => { wake = r; }); } });
  const run = hostRun(h.d);
  await until(() => sleeps.length === 1);
  assert.deepEqual(refusal(h.lines), [], "no refusal while unproven");
  assert.ok(!h.log.includes("release"), "the lock held");
  wake();
  assert.equal((await run).code, 3);
  assert.deepEqual(h.lines, [{ v: 1, containment: "unproven" }, { v: 1, refused: "qualify_required" }]);
  assert.deepEqual(h.log, ["lock", "systemd", "classify", ...CONTAIN, ...CONTAIN, "release"]);
});

test("SIGTERM during an unproven containment: the unproven line once more, exit 3, nothing after the containment", async () => {
  for (const state of ["NO_KEYS", "CLONE"]) {
    const sleeps = [];
    const h = harness({ state, contain: [false], sleep: (ms) => { sleeps.push(ms); return new Promise(() => {}); } });
    const run = hostRun(h.d);
    await until(() => sleeps.length === 1);
    h.term();
    const r = await run;
    assert.deepEqual([r.code, r.refused], [3, null], state);
    assert.deepEqual(h.lines, [{ v: 1, containment: "unproven" }, { v: 1, containment: "unproven" }]);
    assert.deepEqual(h.log, ["lock", "systemd", "classify", ...CONTAIN, "release"]);
  }
  // A SIGTERM that arrives during the attempt itself: no wait, the same exit.
  const h = harness({ state: "FRESH", contain: [false] });
  h.d.sys.stopBroker = async () => { h.term(); await new Promise((r) => setImmediate(r)); return { proven: false }; };
  const r = await hostRun(h.d);
  assert.equal(r.code, 3);
  assert.ok(!h.log.some((l) => l.startsWith("sleep")));
});

test("RESETTING: an unproven completion retries the same way; a layout refusal is identity_broken", async () => {
  const h = harness({ state: "RESETTING", reset: [Object.assign(new Error("x"), { code: "not_empty" })] });
  const run = hostRun(h.d);
  await until(() => h.lines.some((l) => l.state));
  h.term();
  assert.equal((await run).code, 0);
  assert.deepEqual(h.log, ["lock", "systemd", "classify", ...CONTAIN, "completeReset", `sleep:${CONTAIN_RETRY_MS}`, "completeReset", "firstBoot", "release"]);
  const g = harness({ state: "RESETTING", reset: [Object.assign(new Error("x"), { code: "bad_form" })] });
  assert.equal((await hostRun(g.d)).code, 3);
  assert.deepEqual(refusal(g.lines), ["identity_broken"]);
});

// ---- PAIRED (§2 steps 7–14)

test("PAIRED: orphans, config, adapters, unmask, store, the executor (lease off), recovery, the initial sync, then serving; SIGTERM drains", async () => {
  const { id } = await paired();
  const h = harness({ id });
  const run = hostRun(h.d);
  await until(() => h.lines.some((l) => l.serving));
  assert.deepEqual(h.log, ["lock", "systemd", "classify", "dropOrphans", "config", "unmask", "store", "syncMade", "effects", "supervisor", "recover", "sync",
    `sleep:${INITIAL_SYNC_MS}`, `syncStart:${3_600_000}`, "inputs"]);
  assert.equal(h.made.supervisor.lease, null);
  assert.equal(h.made.supervisor.restoreResume, null);
  assert.ok(h.made.supervisor.chain && typeof h.made.supervisor.chain.commit === "function");
  assert.equal(h.made.sync.origin, AUD);
  // The origin is the pin's audience, whichever it is.
  const prod = harness({ id: { ...id, pin: { ...id.pin, aud: "https://sagebrush.space" } } });
  const run2 = hostRun(prod.d);
  await until(() => prod.lines.some((l) => l.serving));
  assert.equal(prod.made.sync.origin, "https://sagebrush.space");
  assert.equal(prod.made.sync.aud, "https://sagebrush.space");
  prod.term();
  await run2;
  assert.equal(h.made.sync.gen(), 0);
  assert.equal(h.made.effects.adapters, h.d.adapters);
  h.term();
  assert.equal((await run).code, 0);
  assert.deepEqual(h.log.slice(-5), ["syncStop", "inputsStop", "close", "storeClose", "release"]);
});

test("PAIRED gates: bad_config, lease_unqualified and each missing adapter refuse after the proven containment, with no unmask, store or start", async () => {
  const { id } = await paired();
  const cases = [
    [{ config: Object.assign(new Error("bad"), { config: true }) }, "bad_config", ["config"]],
    [{ config: { lease: "on" } }, "lease_unqualified", ["config", "leaseQualified"]],
    ...ADAPTERS.map((k) => [{ adapters: Object.fromEntries(ADAPTERS.filter((x) => x !== k).map((x) => [x, () => {}])) }, "preflight_missing", ["config"]]),
    [{ adapters: { ...Object.fromEntries(ADAPTERS.map((x) => [x, () => {}])), audit: "not a function" } }, "preflight_missing", ["config"]],
  ];
  for (const [over, reason, steps] of cases) {
    const h = harness({ id, ...over });
    assert.equal((await hostRun(h.d)).code, 3, reason);
    assert.deepEqual(refusal(h.lines), [reason]);
    assert.deepEqual(h.log, ["lock", "systemd", "classify", "dropOrphans", ...steps, ...CONTAIN, "release"], reason);
  }
  // Unproven before the refusal: the retry, then the refusal once proven.
  const h = harness({ id, config: { lease: "on" }, contain: [false, true] });
  assert.equal((await hostRun(h.d)).code, 3);
  assert.deepEqual(h.lines, [{ v: 1, containment: "unproven" }, { v: 1, refused: "lease_unqualified", item: "record" }]);
});

test("the initial sync gates serving: nothing is served until it completes, fails, or reaches its deadline", async () => {
  const { id } = await paired();
  for (const how of ["completes", "fails", "deadline"]) {
    let settle, deadline;
    const sync = new Promise((res, rej) => { settle = how === "fails" ? () => rej(new Error("x")) : res; });
    const h = harness({ id, sync, sleep: (ms) => (ms === INITIAL_SYNC_MS ? new Promise((r) => { deadline = r; }) : Promise.resolve()) });
    const run = hostRun(h.d);
    await until(() => h.log.includes("sync"));
    for (let i = 0; i < 50; i++) await new Promise((r) => setImmediate(r));
    assert.ok(!h.log.includes("inputs"), `${how}: not served yet`);
    if (how === "deadline") deadline(); else settle();
    await until(() => h.log.includes("inputs"));
    h.term();
    assert.equal((await run).code, 0, how);
  }
});

test("a chain-adopt that ends the certificate: host_ended only once it returns proven, then drained; during the initial sync, before serving", async () => {
  const { id } = await paired();
  const h = harness({ id, supervisor: () => ({}) });
  const run = hostRun(h.d);
  await until(() => h.log.includes("inputs"));
  h.made.sup.submit = async () => { h.made.sup.revoked = true; return { status: "revoked", proven: true }; };
  await h.made.sync.submit({ kind: "chain-adopt", authority: "host" });
  const r = await run;
  assert.deepEqual([r.code, refusal(h.lines)], [3, ["host_ended"]]);
  assert.ok(h.log.includes("close"), "drained before the exit");
  // During the initial sync: the adoption proves within it; nothing is served, and the ending is host_ended.
  let finishSync;
  const g = harness({ id, sync: new Promise((res) => { finishSync = res; }), sleep: (ms) => (ms === INITIAL_SYNC_MS ? new Promise(() => {}) : Promise.resolve()) });
  const run2 = hostRun(g.d);
  await until(() => g.log.includes("sync"));
  g.made.sup.submit = async () => { g.made.sup.revoked = true; return { status: "revoked", proven: true }; };
  await g.made.sync.submit({ kind: "chain-adopt", authority: "host" });
  finishSync({ status: "current" });
  assert.equal((await run2).code, 3);
  assert.deepEqual(refusal(g.lines), ["host_ended"]);
  assert.ok(!g.log.includes("inputs") && !g.lines.some((l) => l.serving));
});

test("crossed: the initial sync's deadline while an adoption has revoked the host and is still proving its stop: no ending, nothing served, the lock held; then the proof (host_ended) or SIGTERM (unproven, 3)", async () => {
  const { id } = await paired();
  for (const how of ["proves", "sigterm"]) {
    let deadline, finish;
    const h = harness({ id, sync: new Promise(() => {}), sleep: (ms) => (ms === INITIAL_SYNC_MS ? new Promise((r) => { deadline = r; }) : Promise.resolve()) });
    const run = hostRun(h.d);
    await until(() => h.log.includes("sync"));
    h.made.sup.submit = (op) => (op.kind === "chain-adopt" ? new Promise((r) => { h.made.sup.revoked = true; finish = r; }) : Promise.resolve({}));
    h.made.sup.close = async () => { h.log.push("close"); finish?.({ status: "revoked", proven: false }); };
    const adoption = h.made.sync.submit({ kind: "chain-adopt", authority: "host" });
    for (let i = 0; i < 20; i++) await new Promise((r) => setImmediate(r));
    deadline();
    for (let i = 0; i < 50; i++) await new Promise((r) => setImmediate(r));
    assert.deepEqual(refusal(h.lines), [], `${how}: no ending at the deadline`);
    assert.ok(!h.log.includes("release") && !h.log.includes("inputs") && !h.lines.some((l) => l.serving), `${how}: the lock held, nothing served`);
    assert.ok(!h.log.includes(`syncStart:${3_600_000}`), "no timer for a revoked host");
    if (how === "proves") {
      finish({ status: "revoked", proven: true });
      const r = await run;
      assert.deepEqual([r.code, refusal(h.lines)], [3, ["host_ended"]]);
    } else {
      h.term();
      const r = await run;
      assert.deepEqual([r.code, r.refused], [3, null]);
      assert.deepEqual(h.lines.slice(-1), [{ v: 1, containment: "unproven" }]);
    }
    assert.ok(h.log.includes("close"), `${how}: drained`);
    await adoption;
  }
});

test("crossed: SIGTERM during a held initial sync, or a held recovery, reaches the drain at once (not after the sync's deadline)", async () => {
  const { id } = await paired();
  for (const where of ["sync", "recover"]) {
    const h = harness({ id, sync: new Promise(() => {}), sleep: (ms) => (ms === INITIAL_SYNC_MS ? new Promise(() => {}) : Promise.resolve()),
      supervisor: (_x, ev) => (where === "recover" ? { recover: () => { ev("recover"); return new Promise(() => {}); } } : {}) });
    const run = hostRun(h.d);
    await until(() => h.log.includes(where));
    h.term();
    const r = await Promise.race([run, new Promise((res) => setTimeout(() => res("held"), 2000))]);
    assert.notEqual(r, "held", `${where}: SIGTERM must not wait for the sync's deadline`);
    assert.equal(r.code, 0, where);
    assert.ok(h.log.includes("close") && h.log.includes("syncStop") && !h.log.includes("inputs"), where);
  }
});

test("SIGTERM while an adoption that ended the certificate is still proving its stop: the close ends it uncommitted; the unproven line, exit 3", async () => {
  const { id } = await paired();
  let finish;
  const h = harness({ id });
  const run = hostRun(h.d);
  await until(() => h.log.includes("inputs"));
  h.made.sup.submit = (op) => (op.kind === "chain-adopt" ? new Promise((r) => { h.made.sup.revoked = true; finish = () => r({ status: "revoked", proven: false }); }) : Promise.resolve({}));
  h.made.sup.close = async () => { h.log.push("close"); finish(); };
  const adoption = h.made.sync.submit({ kind: "chain-adopt", authority: "host" });
  for (let i = 0; i < 20; i++) await new Promise((r) => setImmediate(r));
  assert.ok(!h.lines.some((l) => l.refused), "no ending while the stop is unproven");
  h.term();
  const r = await run;
  assert.deepEqual([r.code, r.refused], [3, null]);
  assert.deepEqual(h.lines.slice(-1), [{ v: 1, containment: "unproven" }]);
  assert.ok(h.log.includes("close"));
  assert.deepEqual(await adoption, { status: "revoked", proven: false });
  // An adoption result that isn't proven never ends serving as host_ended by itself.
  const g = harness({ id });
  const run2 = hostRun(g.d);
  await until(() => g.log.includes("inputs"));
  g.made.sup.submit = async () => { g.made.sup.revoked = true; return { status: "revoked", proven: false }; };
  await g.made.sync.submit({ kind: "chain-adopt", authority: "host" });
  for (let i = 0; i < 20; i++) await new Promise((r) => setImmediate(r));
  assert.ok(!g.lines.some((l) => l.refused), "still serving: no host_ended without the proof");
  g.term();
  assert.equal((await run2).code, 3);
});

test("verify: device keys from the snapshot at the call; a signer above the pin refuses device_unknown and asks for one sync", async () => {
  const { id } = await paired();
  const h = harness({ id });
  const run = hostRun(h.d);
  await until(() => h.log.includes("inputs"));
  const syncs = () => h.log.filter((l) => l === "sync").length;
  const signer = { kind: "device", id: F.ids.device_native, alg: "ed25519", key: N.key };
  const grant = (chainSeq) => seal("sb.host-grant.v1", signer, { fleet: FLEET, aud: AUD, host: HOST, cert: id.cert.hash, chain_seq: chainSeq }, N);
  // Above the pin: device_unknown, and a sync is asked for (one more).
  const before = syncs();
  assert.throws(() => h.made.supervisor.verify(grant(id.chain.seq + 1)), (e) => e.code === "device_unknown");
  assert.equal(syncs(), before + 1);
  // At the pin: the device resolves (the signature verifies), so the refusal is the body's form, and no sync is asked.
  assert.throws(() => h.made.supervisor.verify(grant(id.chain.seq)), (e) => e.code === "bad_form");
  assert.equal(syncs(), before + 1);
  h.term();
  await run;
});

test("the executor's drain: the running op reaches its end, a queued one never starts, later ones are refused", async () => {
  const log = [];
  const store = await HostStore.open(join(tmp(), "state"));
  const fenceDir = join(tmp(), "fence");
  const fx = {
    appendIntent: async () => {}, audit: () => {}, brokerGen: async () => {}, brokerRevoke: async () => {},
    stopUnit: async () => {}, procCount: async () => 0, mask: async () => {}, unmask: async () => {}, provision: async () => {}, writeUnit: async () => {},
    daemonReload: async () => {}, systemdVersion: async () => GOOD, start: async () => {}, isActive: async () => false, publishMap: async () => {}, sendAck: async () => {},
    sys: { stop: () => {}, jobs: () => [], cancel: () => {}, rootUnits: () => [], activeAgentUnits: () => [], procCount: () => 0 },
  };
  let release, reached;
  const gate = new Promise((r) => { release = r; }), at = new Promise((r) => { reached = r; });
  const sup = new Supervisor({ store, fx, verify: () => { throw new Error("no"); }, bodyOf: () => ({}), fenceDir,
    barrier: async (n) => { if (n === "after_fence_write" && !log.includes("held")) { log.push("held"); reached(); await gate; } } });
  await sup.recover();
  const running = sup.submit({ kind: "stop-all", authority: "person" }).then(() => log.push("running done"));
  await at;
  const queued = sup.submit({ kind: "stop-all", authority: "local" }).then(() => log.push("queued ran"), (e) => log.push(`queued ${e.code}`));
  const closing = sup.close().then(() => log.push("closed"));
  release();
  await Promise.all([running, queued, closing]);
  assert.deepEqual(log, ["held", "queued in_progress", "running done", "closed"]);
  await assert.rejects(sup.submit({ kind: "stop-all", authority: "person" }), (e) => e.code === "in_progress");
  await assert.rejects(sup.recover(), (e) => e.code === "in_progress");
  await store.close();
});

// ---- the REAL executor under hostRun (SEC/TESTS H3): only the store's contents, the effects and grant verification
//      are fakes; the close must end recovery's direct awaits and owned effects within the unit's 30 s stop

const AGENT = F.ids.agent;
const grantOf = (gen, agents) => Buffer.from(JSON.stringify({ gen, agents: agents.map((agent) => ({ agent, tags: [], config: { x: 1 } })) }));
const fakeVerify = (bytes) => { const body = JSON.parse(String(bytes)); return { body, digest: sha256b64(bytes), hash: sha256b64(Buffer.concat([Buffer.from("s"), bytes])) }; };
const fakeBodyOf = (bytes) => JSON.parse(String(bytes));
/** Fake effects over fake units; `hold(name)` makes that effect never settle (and ignore its abort); `calls` logs each. */
function unitFx({ hold = () => false, fenceDir } = {}) {
  const units = {}, calls = [];
  const u = (id) => (units[id] ??= { active: false, masked: false });
  const never = new Promise(() => {});
  const step = (name, f) => (...a) => { calls.push(name); return hold(name) ? never : f(...a); };
  const fx = {
    appendIntent: step("appendIntent", async () => {}), openIntents: step("openIntents", async () => []), audit: () => {},
    brokerGen: step("brokerGen", async () => {}), brokerRevoke: async () => {}, publishMap: step("publishMap", async () => {}), sendAck: step("sendAck", async () => {}),
    stopUnit: step("stopUnit", async (id) => { u(id).active = false; }), procCount: async (id) => (u(id).active ? 1 : 0),
    mask: step("mask", async (id) => { u(id).masked = true; }), unmask: step("unmask", async (id) => { u(id).masked = false; }),
    provision: step("provision", async () => {}), writeUnit: step("writeUnit", async () => {}), daemonReload: step("daemonReload", async () => {}),
    systemdVersion: async () => GOOD, isActive: step("isActive", async (id) => u(id).active),
    freeze: step("freeze", async () => { throw new Error("the freeze failed"); }), thaw: step("thaw", async () => {}),
    start: step("start", async (id) => { if (!u(id).masked) u(id).active = true; }),
    sys: { stop: (unit) => { for (const s of Object.values(units)) s.active = false; void unit; }, jobs: () => [], cancel: () => {}, rootUnits: () => [],
      activeAgentUnits: () => Object.entries(units).filter(([, x]) => x.active).map(([id]) => `sagebrush-agent-${id}.service`), procCount: () => Object.values(units).filter((x) => x.active).length },
  };
  void fenceDir;
  return { fx, calls, u };
}
/** A host store where AGENT is running under grant 1 (applied by a real executor, then closed as at a stop). */
async function seededStore() {
  const root = join(tmp(), "state"), fenceDir = join(tmp(), "fence");
  const store = await HostStore.open(root);
  const { fx } = unitFx();
  const sup = new Supervisor({ store, fx, verify: fakeVerify, bodyOf: fakeBodyOf, fenceDir });
  await sup.recover();
  assert.equal((await sup.submit({ kind: "grant", bytes: grantOf(1, [AGENT]) })).status, "applied");
  await sup.close();
  await store.close();
  return { root, fenceDir };
}
/** hostRun over the REAL Supervisor and a real store at `root`. */
function realHarness(id, { root, fenceDir, fx, sync } = {}) {
  const h = harness({ id, ...(sync ? { sync, sleep: (ms) => (ms === INITIAL_SYNC_MS ? new Promise(() => {}) : Promise.resolve()) } : {}) });
  let store = null;
  h.d.openStore = async () => { store = await HostStore.open(root ?? join(tmp(), "state")); const close = store.close.bind(store); store.close = async () => { h.log.push("storeClose"); return close(); }; return store; };
  h.d.effects = () => fx;
  h.d.makeSupervisor = (o) => { const sup = new Supervisor({ ...o, verify: fakeVerify, bodyOf: fakeBodyOf, fenceDir: fenceDir ?? join(tmp(), "fence"), deadlines: { grace: 200 } }); h.made.sup = sup; return sup; };
  return h;
}
const within = (p, ms) => Promise.race([p, new Promise((r) => setTimeout(() => r("HELD"), ms))]);
/** Wait (on the clock: real store I/O) until `fn()` holds, at most `ms`. */
async function waitFor(fn, ms = 5000) { const t0 = Date.now(); while (!fn() && Date.now() - t0 < ms) await new Promise((r) => setTimeout(r, 10)); assert.ok(fn(), "never reached"); }

test("REAL executor: SIGTERM while recovery's direct await (openIntents) never settles: the close ends it, the store and the lock are released within the bound", async () => {
  const { id } = await paired();
  const { fx, calls } = unitFx({ hold: (n) => n === "openIntents" });
  const h = realHarness(id, { fx });
  const run = hostRun(h.d);
  await waitFor(() => calls.includes("openIntents"));
  const t0 = Date.now();
  h.term();
  const r = await within(run, 5000);
  assert.notEqual(r, "HELD", "hostRun held by the running recovery");
  assert.equal(r.code, 0);
  assert.ok(Date.now() - t0 < 5000);
  assert.ok(h.log.includes("storeClose") && h.log.includes("release"), "store closed, lock released");
  assert.deepEqual(calls, ["openIntents"], "no effect after the close");
});

test("REAL executor: SIGTERM while recovery's owned start effect never settles (and ignores its abort): aborted within the grace; no later effect; the agent keeps its state with a pending proof; the next start proves it down before starting it", async () => {
  const { id } = await paired();
  const seed = await seededStore();
  const { fx, calls } = unitFx({ hold: (n) => n === "start" });
  const h = realHarness(id, { ...seed, fx });
  const run = hostRun(h.d);
  await waitFor(() => calls.includes("start"));
  const before = calls.length;
  h.term();
  const r = await within(run, 5000);
  assert.notEqual(r, "HELD", "hostRun held by the owned effect");
  assert.equal(r.code, 0);
  assert.ok(h.log.includes("storeClose") && h.log.includes("release"));
  for (let i = 0; i < 20; i++) await new Promise((res) => setImmediate(res));
  assert.equal(calls.length, before, "no effect after the close (narrowing or widening)");
  // Fail closed: the cut-off start's agent is durably pending a proof, and still `running` (never turned `stopped`).
  const store = await HostStore.open(seed.root);
  assert.ok(store.grants.pendingProofs().includes(AGENT), "pending proof");
  assert.equal(store.registry.agent(AGENT).state, "running");
  await store.close();
  // The next start: recovery proves it down (mask, stop) before it starts it again.
  const next = unitFx();
  const g = realHarness(id, { ...seed, fx: next.fx });
  const run2 = hostRun(g.d);
  await waitFor(() => g.log.includes("inputs"));
  const firstStart = next.calls.indexOf("start"), firstMask = next.calls.indexOf("mask");
  assert.ok(firstMask >= 0 && (firstStart === -1 || firstMask < firstStart), `proven down first: ${next.calls.join(",")}`);
  g.term();
  assert.equal((await run2).code, 0);
});

test("REAL executor: once closed, no effect starts, even where an op swallows a failed effect and goes on (a stop-all closed inside its fenced stop masks nothing after)", async () => {
  const seed = await seededStore();
  const store = await HostStore.open(seed.root);
  const { fx, calls } = unitFx();
  let closing = null;
  const sup = new Supervisor({ store, fx, verify: fakeVerify, bodyOf: fakeBodyOf, fenceDir: seed.fenceDir, deadlines: { grace: 200 },
    barrier: async (n) => { if (n === "after_fence_write" && !closing) closing = sup.close(); } });
  const before = calls.length;
  await sup.submit({ kind: "stop-all", authority: "person" }).catch(() => {});
  await closing;
  assert.deepEqual(calls.slice(before), [], `no effect after the close: ${calls.slice(before).join(",")}`);
  await store.close();
});

test("REAL executor: a close while a grant's final ack read (isActive) is held ends the apply there, before applied; the next recovery finishes it and sends the ack", async () => {
  const root = join(tmp(), "state"), fenceDir = join(tmp(), "fence");
  const store = await HostStore.open(root);
  let held = true;
  const { fx, calls } = unitFx({ hold: (n) => n === "isActive" && held });
  const sup = new Supervisor({ store, fx, verify: fakeVerify, bodyOf: fakeBodyOf, fenceDir, deadlines: { grace: 200 } });
  await sup.recover();
  const applying = sup.submit({ kind: "grant", bytes: grantOf(1, [AGENT]) });
  await waitFor(() => calls.includes("isActive"));
  await within(sup.close(), 5000);
  await assert.rejects(applying, /closing/, "the op ends at the crash point, never resolving applied");
  assert.ok(!calls.includes("sendAck"), "no ack");
  assert.equal(store.grants.pending().phase, "applying", "not applied");
  await store.close();
  held = false;
  const store2 = await HostStore.open(root);
  const next = unitFx();
  const sup2 = new Supervisor({ store: store2, fx: next.fx, verify: fakeVerify, bodyOf: fakeBodyOf, fenceDir });
  await sup2.recover();
  assert.equal(store2.grants.pending().phase, "applied", "recovery finished the apply");
  assert.ok(next.calls.includes("sendAck"), "and sent the ack");
  await sup2.close();
  await store2.close();
});

test("REAL executor: a close while the grant's ack send is held ends the op after applied (as a crash there); a byte-identical re-apply sends the ack", async () => {
  const root = join(tmp(), "state"), fenceDir = join(tmp(), "fence");
  const store = await HostStore.open(root);
  const { fx, calls } = unitFx({ hold: (n) => n === "sendAck" });
  const sup = new Supervisor({ store, fx, verify: fakeVerify, bodyOf: fakeBodyOf, fenceDir, deadlines: { grace: 200 } });
  await sup.recover();
  const applying = sup.submit({ kind: "grant", bytes: grantOf(1, [AGENT]) });
  await waitFor(() => calls.includes("sendAck"));
  await within(sup.close(), 5000);
  await assert.rejects(applying, /closing/, "the op ends with Closing, not a resolved 'applied'");
  assert.equal(store.grants.pending().phase, "applied");
  await store.close();
  const store2 = await HostStore.open(root);
  const next = unitFx();
  const sup2 = new Supervisor({ store: store2, fx: next.fx, verify: fakeVerify, bodyOf: fakeBodyOf, fenceDir });
  await sup2.recover();
  const again = await sup2.submit({ kind: "grant", bytes: grantOf(1, [AGENT]) });
  assert.equal(again.status, "reapplied", JSON.stringify(again));
  assert.ok(next.calls.includes("sendAck"), "the re-apply sends the ack");
  await sup2.close();
  await store2.close();
});

test("REAL executor: a close during a contain's or a stop's mask ends the op (mask's fallback never swallows it)", async () => {
  // A person's stop of the seeded agent, its mask held: the close ends the op with Closing, not a resolved stop.
  const seed = await seededStore();
  const store = await HostStore.open(seed.root);
  const { fx, calls } = unitFx({ hold: (n) => n === "mask" });
  const sup = new Supervisor({ store, fx, verify: fakeVerify, bodyOf: fakeBodyOf, fenceDir: seed.fenceDir, deadlines: { grace: 200 } });
  const stopping = sup.submit({ kind: "stop", authority: "person", agent: AGENT });
  await waitFor(() => calls.includes("mask"));
  await within(sup.close(), 5000);
  await assert.rejects(stopping, /closing/);
  await store.close();
  // A pause whose freeze fails is contained (the contain's mask): that mask held, the close ends the op too.
  const seed2 = await seededStore();
  const store2 = await HostStore.open(seed2.root);
  const p = unitFx({ hold: (n) => n === "mask" });
  const sup2 = new Supervisor({ store: store2, fx: p.fx, verify: fakeVerify, bodyOf: fakeBodyOf, fenceDir: seed2.fenceDir, deadlines: { grace: 200 } });
  const pausing = sup2.submit({ kind: "pause", authority: "person", agent: AGENT });
  await waitFor(() => p.calls.includes("freeze") && p.calls.includes("mask"));
  await within(sup2.close(), 5000);
  await assert.rejects(pausing, /closing/);
  await store2.close();
});

test("REAL executor: SIGTERM during a held initial sync: nothing runs, the close is immediate, exit 0", async () => {
  const { id } = await paired();
  const { fx } = unitFx();
  const h = realHarness(id, { fx, sync: new Promise(() => {}) });
  const run = hostRun(h.d);
  await waitFor(() => h.log.includes("sync"));
  h.term();
  const r = await within(run, 2000);
  assert.notEqual(r, "HELD");
  assert.equal(r.code, 0);
  assert.ok(h.log.includes("storeClose") && h.log.includes("release"));
});

// ---- the reset command (§3)

test("host reset-identity: busy with the daemon holding the lock; an unproven broker or slice stop exits 3; otherwise NO_KEYS", async () => {
  const b = harness({ lock: "busy" });
  assert.equal((await hostResetIdentity(b.d)).code, 3);
  assert.deepEqual(b.lines, [{ v: 1, refused: "busy", unit: "sagebrush-supervisor.service", next: "stop the unit first" }]);
  assert.deepEqual(b.log, ["lock"]);
  const u = harness({ reset: [Object.assign(new Error("x"), { code: "not_empty" })] });
  assert.equal((await hostResetIdentity(u.d)).code, 3);
  assert.deepEqual(u.lines, [{ v: 1, containment: "unproven" }]);
  const l = harness({ reset: [Object.assign(new Error("x"), { code: "bad_form" })] });
  assert.equal((await hostResetIdentity(l.d)).code, 3);
  assert.deepEqual(refusal(l.lines), ["identity_broken"]);
  const ok = harness();
  assert.equal((await hostResetIdentity(ok.d)).code, 0);
  assert.deepEqual(ok.lines, [{ v: 1, state: "NO_KEYS" }]);
  assert.deepEqual(ok.log, ["lock", "resetIdentity", "release"]);
});

// ---- the settings file (§2 step 8)

test("the settings file: absent, empty object, and off are off; on is on; every other form is bad_config", () => {
  const dir = tmp();
  const at = (name, text, mode = 0o644) => { const p = join(dir, name); writeFileSync(p, text, { mode }); chmodSync(p, mode); return p; };
  const read = (p, uid = UID) => readHostConfig(p, { rootUid: uid });
  assert.deepEqual(read(join(dir, "absent")), { lease: "off" });
  assert.deepEqual(read(at("a", "{}")), { lease: "off" });
  assert.deepEqual(read(at("b", '{"execution_lease":"off"}')), { lease: "off" });
  assert.deepEqual(read(at("c", '{"execution_lease":"on"}')), { lease: "on" });
  const bad = (p, uid) => assert.throws(() => read(p, uid), (e) => e.code === "bad_form" && e.config === true, p);
  mkdirSync(join(dir, "adir"));
  bad(join(dir, "adir"));
  symlinkSync(at("target", "{}"), join(dir, "link"));
  bad(join(dir, "link"));
  bad(at("owner", "{}"), UID + 1);
  bad(at("gw", "{}", 0o664));
  bad(at("ow", "{}", 0o646));
  bad(at("big", `{"execution_lease":"off"${" ".repeat(CONFIG_MAX)}}`));
  bad(at("notjson", "{"));
  bad(at("array", "[]"));
  bad(at("null", "null"));
  bad(at("key", '{"execution_lease":"off","x":1}'));
  bad(at("value", '{"execution_lease":"maybe"}'));
  bad(at("valuetype", '{"execution_lease":true}'));
  assert.deepEqual(read(at("max", `{"execution_lease":"on"}${" ".repeat(CONFIG_MAX - 24)}`)), { lease: "on" });
});

// ---- the real containment's effects (§2.1), against fakes

test("the broker's containment: masked first, then stopped; proven only when inactive, masked-runtime, cgroup-empty and the broker uid empty host-wide", async () => {
  const mk = (over = {}) => {
    const calls = [];
    const st = { mask: 0, active: "inactive", enabled: "masked-runtime", procs: 0, uid: { empty: true, holders: [] }, ...over };
    const run = async (argv) => {
      calls.push(argv.join(" "));
      if (argv[1] === "mask") return { code: st.mask, stdout: "" };
      if (argv[1] === "is-active") return { code: 3, stdout: `${st.active}\n` };
      if (argv[1] === "is-enabled") return { code: 1, stdout: `${st.enabled}\n` };
      return { code: 0, stdout: "" };
    };
    const sys = { procCount: (u) => { calls.push(`procCount ${u}`); if (st.procs === "throw") throw new Error("x"); return st.procs; } };
    const uidEmpty = async (uid) => { calls.push(`uid ${uid}`); if (st.uid === "throw") throw new Error("x"); return st.uid; };
    return { s: realContainSys(990, { run, sys, uidEmpty, stopAll: async () => ({ status: over.all ?? "stopped and fenced" }) }), calls };
  };
  const ok = mk();
  assert.deepEqual(await ok.s.stopBroker(), { proven: true });
  assert.deepEqual(ok.calls, [`systemctl mask --runtime ${BROKER_UNIT}`, `systemctl stop ${BROKER_UNIT}`, `systemctl is-active ${BROKER_UNIT}`,
    `systemctl is-enabled ${BROKER_UNIT}`, `procCount ${BROKER_UNIT}`, "uid 990"]);
  assert.deepEqual(await ok.s.stopAll(), { proven: true });
  for (const over of [{ mask: 1 }, { active: "active" }, { active: "deactivating" }, { enabled: "enabled" }, { enabled: "masked" }, { procs: 1 },
    { uid: { empty: false, holders: ["pid 4242"] } }, { uid: { empty: false, holders: ["session 3"] } }]) {
    assert.deepEqual(await mk(over).s.stopBroker(), { proven: false }, JSON.stringify(over));
  }
  for (const over of [{ procs: "throw" }, { uid: "throw" }]) await assert.rejects(mk(over).s.stopBroker(), undefined, JSON.stringify(over));
  for (const all of ["not empty", "not durable", "killed, not durable"]) assert.deepEqual(await mk({ all }).s.stopAll(), { proven: false }, all);
});

test("the broker uid proof: a stray sb-broker process outside any unit, its user manager, linger or session is a holder; unreadable fails closed", async () => {
  const status = (u) => `Name:\tx\nUid:\t${u}\t${u}\t${u}\t${u}\nGid:\t0\t0\t0\t0\n`;
  const fake = ({ procs = {}, linger = false, mgr = "inactive", sessions = "" } = {}) => {
    const root = tmp();
    for (const [pid, u] of Object.entries({ 1: 0, ...procs })) { mkdirSync(join(root, "proc", pid), { recursive: true }); writeFileSync(join(root, "proc", pid, "status"), status(u)); }
    mkdirSync(join(root, "var/lib/systemd/linger"), { recursive: true });
    if (linger) writeFileSync(join(root, `var/lib/systemd/linger/${BROKER_USER}`), "");
    return { root, run: async (argv) => (argv[0] === "systemctl" ? { code: 3, stdout: `${mgr}\n` } : { code: 0, stdout: sessions }), ms: 1000 };
  };
  assert.deepEqual(await brokerUidEmpty(990, fake()), { empty: true, holders: [] });
  assert.deepEqual((await brokerUidEmpty(990, fake({ procs: { 4242: 990 } }))).holders, ["pid 4242"]);
  assert.deepEqual((await brokerUidEmpty(990, fake({ linger: true }))).holders, ["linger"]);
  assert.deepEqual((await brokerUidEmpty(990, fake({ mgr: "active" }))).holders, ["user-manager"]);
  assert.deepEqual((await brokerUidEmpty(990, fake({ sessions: "7 990 sb-broker\n" }))).holders, ["session 7"]);
  for (const bad of [0, -1, 1.5, "990"]) await assert.rejects(brokerUidEmpty(bad, fake()), /broker's uid/);
  await assert.rejects(brokerUidEmpty(990, { root: "/nonexistent-root", run: async () => ({ code: 0, stdout: "" }) }), /can't be listed/);
});

test("the broker's account: from /etc/passwd by name; absent or malformed is none", () => {
  const root = tmp();
  mkdirSync(join(root, "etc"));
  writeFileSync(join(root, "etc/passwd"), "root:x:0:0::/root:/bin/bash\nsb-brokerx:x:5:5::/:/x\nsb-broker:x:991:992::/nonexistent:/usr/sbin/nologin\n");
  assert.deepEqual(brokerAccount({ root }), { uid: 991, gid: 992 });
  writeFileSync(join(root, "etc/passwd"), "root:x:0:0::/root:/bin/bash\nsb-broker:x:abc:1::/:/x\n");
  assert.equal(brokerAccount({ root }), null);
  assert.equal(brokerAccount({ root: join(root, "none") }), null);
});

test("the unit as shipped: the release's host run as root, refusals (status 3) not restarted, a crash restarted, no ExecStop", () => {
  const u = supervisorUnit("/opt/sagebrush/r1");
  for (const l of ["ExecStartPre=/usr/lib/sagebrush/release-trust /opt/sagebrush/r1", "ExecStart=/usr/bin/node /opt/sagebrush/r1/bin/sagebrush-agent.mjs host run", "User=root", "Type=simple", "Restart=on-failure", "RestartSec=10s",
    "RestartPreventExitStatus=3", "TimeoutStopSec=30s", "WantedBy=multi-user.target"]) assert.ok(u.split("\n").includes(l), l);
  assert.ok(!/ExecStop/.test(u) && !u.includes("@RELEASE@"));
  for (const bad of ["rel", "/a b", "/a$x", "/a%n", "/a\"b", null]) assert.throws(() => supervisorUnit(bad), (e) => e.code === "bad_form", String(bad));
});

// ---- the registry (AUDIT H1): every emitter's name, host-owned, and the phrase its meaning must contain

test("registry: every emitter's refusal is a host-owned registered name whose meaning covers its class", async () => {
  const { id } = await paired();
  const meaning = (name) => REG.find((r) => r.name === name);
  const table = [
    [{ root: false }, "preflight_missing", "privilege"],
    [{ linux: false }, "preflight_missing", "platform"],
    [{ broker: null }, "preflight_missing", "account"],
    ...ADAPTERS.map((k) => [{ id, adapters: Object.fromEntries(ADAPTERS.filter((x) => x !== k).map((x) => [x, () => {}])) }, "preflight_missing", "adapter"]),
    [{ lock: "bad" }, "identity_broken", "trusted parents"],
    [{ lock: "bad" }, "identity_broken", "ownership lock"],
    [{ state: "BROKEN" }, "identity_broken", "restore-root separation"],
    [{ state: "BROKEN" }, "identity_broken", "no closed state"],
    [{ lock: "busy" }, "busy", "ownership lock"],
    [{ state: "REVOKED" }, "host_ended", "no longer verifies"],
    [{ id, config: { lease: "on" } }, "lease_unqualified", "execution lease"],
    [{ id, config: Object.assign(new Error("x"), { config: true }) }, "bad_config", "settings file"],
    [{ state: "CLONE" }, "clone_detected", "machine id"],
    [{ version: BAD, state: "FRESH" }, "qualify_required", "qualification"],
  ];
  for (const [over, name, phrase] of table) {
    const h = harness(over);
    await hostRun(h.d);
    assert.deepEqual(refusal(h.lines), [name], JSON.stringify(Object.keys(over)));
    const r = meaning(name);
    assert.ok(r && r.owner === "host" && !Object.hasOwn(r, "status"), name);
    assert.ok(r.meaning.includes(phrase), `${name}: "${phrase}"`);
  }
  for (const n of ["identity_broken", "host_ended", "lease_unqualified", "bad_config", "preflight_missing"]) assert.ok(HEALTH_REASONS.includes(n), n);
  // Every name the module can print is in the table above or "busy".
  const src = readFileSync(new URL("../lib/fleet/host/host-main.mjs", import.meta.url), "utf8");
  const printed = new Set([...src.matchAll(/refused\("([a-z_]+)"\)|refused: "([a-z_]+)"/g)].map((m) => m[1] ?? m[2]));
  for (const n of printed) assert.ok(meaning(n)?.owner === "host", n);
});

test("an idle daemon stays up until SIGTERM: the real wait holds the process open, and SIGTERM ends it with 0", async () => {
  const mod = new URL("../lib/fleet/host/host-main.mjs", import.meta.url).href;
  const { spawn } = await import("node:child_process");
  const child = spawn(process.execPath, ["--input-type=module", "-e",
    `const { untilSigterm } = await import(${JSON.stringify(mod)}); process.stdout.write("waiting\\n"); await untilSigterm(); process.stdout.write("ended\\n"); process.exit(0);`],
  { stdio: ["ignore", "pipe", "pipe"] });
  let out = "", err = "";
  child.stdout.on("data", (b) => { out += b; });
  child.stderr.on("data", (b) => { err += b; });
  const exited = new Promise((r) => child.on("exit", (code, signal) => r({ code, signal })));
  try {
    for (let i = 0; i < 200 && !out.includes("waiting"); i++) await new Promise((r) => setTimeout(r, 50));
    assert.match(out, /waiting/, err);
    await new Promise((r) => setTimeout(r, 1500));
    assert.equal(child.exitCode, null, `still running after 1.5 s (${err})`);
    child.kill("SIGTERM");
    assert.deepEqual(await exited, { code: 0, signal: null });
    assert.match(out, /ended/);
    assert.doesNotMatch(err, /unsettled top-level await/);
  } finally { if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL"); }
});

// ---- the bin's hand-over (§1)

test("the bin hands `host` over before ANY chat-agent module is loaded: with ANTHROPIC_BASE_URL set, a chat-agent argument, and a hook that fails on the chat graph", () => {
  const bin = new URL("../bin/sagebrush-agent.mjs", import.meta.url).pathname;
  const env = { ...process.env, ANTHROPIC_BASE_URL: "http://127.0.0.1:9" };
  const a = spawnSync(process.execPath, [bin, "host", "--port", "1"], { env, encoding: "utf8", timeout: 30_000 });
  assert.equal(a.status, 2);
  assert.match(a.stderr, /^usage: sagebrush-agent host run \| reset-identity$/m);
  assert.doesNotMatch(a.stderr, /ANTHROPIC_BASE_URL|unknown argument/);
  // The control: a resolve hook that fails the moment any chat-agent module (or its ws or zod) is even resolved. Host
  // mode never trips it; the chat agent does at once.
  const hook = `data:text/javascript,${encodeURIComponent('export async function resolve(s, c, n) { if (/sagebrush-agent-chat|(^|\\/)(server|stdio|pair-stdin|stdout-thread|claude-cli)\\.mjs$|^(ws|zod)$/.test(s)) throw new Error("CHAT GRAPH: " + s); return n(s, c); }')}`;
  const reg = `data:text/javascript,${encodeURIComponent(`import { register } from "node:module"; register(${JSON.stringify(hook)});`)}`;
  const h1 = spawnSync(process.execPath, ["--import", reg, bin, "host", "--port", "1"], { env, encoding: "utf8", timeout: 30_000 });
  assert.equal(h1.status, 2, h1.stderr);
  assert.match(h1.stderr, /^usage: sagebrush-agent host run \| reset-identity$/m);
  assert.doesNotMatch(h1.stderr, /CHAT GRAPH/);
  const c1 = spawnSync(process.execPath, ["--import", reg, bin, "--help"], { env, encoding: "utf8", timeout: 30_000 });
  assert.notEqual(c1.status, 0);
  assert.match(c1.stderr, /CHAT GRAPH: \.\/sagebrush-agent-chat\.mjs/, "the control trips for the chat agent");
  if (UID !== 0) {
    const b = spawnSync(process.execPath, [bin, "host", "run"], { env, encoding: "utf8", timeout: 30_000 });
    assert.equal(b.status, 3);
    assert.equal(b.stderr.trim(), '{"v":1,"refused":"preflight_missing"}');
    capture("stderr", b.stderr);
  }
});

// ---- no key anywhere (SEC H3): run last, over everything captured above

test("no key on any surface: stderr, events, audit calls, health records, the executor's options and errors, raw and encoded", async () => {
  const { id, secrets } = await paired();
  // A health record from a store, as the running daemon reports it; and an error from main's own catch.
  const store = await HostStore.open(join(tmp(), "state"));
  capture("health", await hostState({ agentIds: () => [], run: () => "running", fences: () => [], liveLease: async () => null, restore: () => null,
    qualification: () => store.qualification.state, nowMs: () => NOW, bootNowMs: () => 1000 }));
  await store.close();
  const h = harness({ id });
  const run = hostRun(h.d);
  await until(() => h.log.includes("inputs"));
  capture("supervisor options", { lease: h.made.supervisor.lease, restoreResume: h.made.supervisor.restoreResume });
  try { h.made.supervisor.verify(new Uint8Array(3)); } catch (e) { capture("error", { message: e.message, code: e.code, cause: String(e.cause ?? ""), json: safeJson(e) }); }
  h.term();
  await run;
  const enc = (b) => [Buffer.from(b).toString("latin1"), Buffer.from(b).toString("hex"), Buffer.from(b).toString("base64").replace(/=+$/, ""),
    Buffer.from(b).toString("base64url"), JSON.stringify(Array.from(b)).slice(1, -1)];
  assert.ok(SURFACES.length > 50, "the suite captured its surfaces");
  for (const [name, bytes] of Object.entries(secrets)) {
    for (const form of enc(bytes)) {
      for (const s of SURFACES) assert.ok(!s.text.includes(form), `${name} on ${s.surface}`);
    }
  }
});

test("PAIRED with the reopen wired (lease-on r1.5 §6.5): one sleep-reopen before serving, then every sleepReopenMs, cleared at the drain", async () => {
  const { id } = await paired();
  const h = harness({ id });
  const timers = [];
  h.d.sleepReopenMs = 120000;
  h.d.every = (fn, ms) => { const t = { fn, ms, cleared: false }; timers.push(t); h.log.push(`every:${ms}`); return t; };
  h.d.clearEvery = (t) => { t.cleared = true; h.log.push("clearEvery"); };
  const run = hostRun(h.d);
  await until(() => h.lines.some((l) => l.serving));
  const i = h.log.indexOf("submit:sleep-reopen");
  assert.ok(i > h.log.indexOf("recover") && i < h.log.indexOf("every:120000"), JSON.stringify(h.log));
  timers[0].fn();
  await until(() => h.log.filter((x) => x === "submit:sleep-reopen").length === 2);
  h.term();
  assert.equal((await run).code, 0);
  assert.equal(timers[0].cleared, true);
  assert.ok(h.log.indexOf("clearEvery") < h.log.indexOf("close"), "cleared before the executor closes");
});

test("TESTS H2: SIGTERM while the FIRST reopen is held: the drain isn't held by it (sync stopped, inputs stopped, close), no serving line, exit 0", async () => {
  const { id } = await paired();
  let releaseFirst, closed = false;
  const h = harness({ id, supervisor: (_x, ev) => ({
    submit: async (op) => { ev("submit", op.kind); if (op.kind === "sleep-reopen") await new Promise((r) => { releaseFirst = r; }); return { status: "noop" }; },
    // the real executor's close cuts the running reopen short (the executor rows); here it releases the held submit
    close: async () => { ev("close"); closed = true; releaseFirst?.(); },
  }) });
  h.d.sleepReopenMs = 120000;
  h.d.every = () => { h.log.push("every"); return {}; };
  h.d.clearEvery = () => h.log.push("clearEvery");
  const run = hostRun(h.d);
  await until(() => h.log.includes("submit:sleep-reopen"));
  h.term();
  const out = await Promise.race([run, new Promise((r) => setTimeout(() => r("HELD"), 2000))]);
  assert.notEqual(out, "HELD", "the drain isn't held by the first reopen");
  if (out === "HELD") { releaseFirst?.(); await run; } // (a held run released, so the file still ends)
  assert.equal(out.code, 0);
  assert.ok(closed);
  assert.ok(!h.lines.some((l) => l.serving), "no serving line after SIGTERM");
  assert.ok(!h.log.includes("every"), "no reopen timer started");
  for (const e of ["syncStop", "inputsStop", "close"]) assert.ok(h.log.includes(e), e);
  assert.ok(h.log.indexOf("syncStop") < h.log.indexOf("close"));
});

test("the restore worker seam: built over the open store and given to the executor; its dispatch every restoreDispatchMs, cleared at the drain", async () => {
  const { id } = await paired();
  const h = harness({ id });
  const timers = [];
  const seen = [];
  h.d.restoreWorker = ({ store }) => { seen.push(store); return { hold: async () => null, dispatch: async () => ({ dispatched: null }), imports: async () => ({ sets: {} }) }; };
  h.d.restoreDispatchMs = 30000;
  h.d.every = (fn, ms) => { const t = { fn, ms, cleared: false }; timers.push(t); h.log.push(`every:${ms}`); return t; };
  h.d.clearEvery = (t) => { t.cleared = true; h.log.push("clearEvery"); };
  const run = hostRun(h.d);
  await until(() => h.lines.some((l) => l.serving));
  assert.equal(seen.length, 1, "built once, over the store the executor gets");
  assert.ok(h.made.supervisor.restoreWorker && typeof h.made.supervisor.restoreWorker.dispatch === "function");
  assert.equal(seen[0], h.made.supervisor.store);
  const t = timers.find((x) => x.ms === 30000);
  assert.ok(t, "the dispatch timer");
  t.fn();
  await until(() => h.log.includes("submit:restore-dispatch") && h.log.includes("submit:restore-import"));
  assert.ok(h.log.indexOf("submit:restore-dispatch") < h.log.indexOf("submit:restore-import"), "the dispatch, then the imports, by the same timer");
  h.term();
  assert.equal((await run).code, 0);
  assert.equal(t.cleared, true);
  assert.ok(h.log.lastIndexOf("clearEvery") < h.log.indexOf("close"), "cleared before the executor closes");
  // Without the seam: no restoreWorker for the executor and no timer.
  const g = harness({ id });
  const gt = [];
  g.d.restoreDispatchMs = 30000;
  g.d.every = (fn, ms) => { gt.push(ms); return {}; };
  g.d.clearEvery = () => {};
  const run2 = hostRun(g.d);
  await until(() => g.lines.some((l) => l.serving));
  assert.equal(g.made.supervisor.restoreWorker, undefined);
  assert.ok(!gt.includes(30000));
  g.term();
  await run2;
});

// ---- lease on (lease-on r1.7 §1): the qualification, the lease machine, the restore resume's base and its C1 wrapper

test("lease on and UNQUALIFIED: each failing item is named in the refusal, after the proven containment, with no unmask, store or start; a throwing check is unreadable", async () => {
  const { id } = await paired();
  for (const why of ["record", "manifest", "launcher", "layout", "sleep_hook", "systemd_major", "node_major", "kernel_series", "cgroup", "uptime"]) {
    const h = harness({ id, config: { lease: "on" }, qualified: { ok: false, why } });
    const out = await Promise.race([hostRun(h.d), new Promise((r) => setTimeout(() => r("SERVING"), 2000))]);
    if (out === "SERVING") { h.term(); assert.fail(`${why}: served instead of refusing`); }
    assert.equal(out.code, 3, why);
    assert.deepEqual(h.lines, [{ v: 1, refused: "lease_unqualified", item: why }], why);
    assert.deepEqual(h.log, ["lock", "systemd", "classify", "dropOrphans", "config", "leaseQualified", ...CONTAIN, "release"], why);
  }
  for (const qualified of [new Error("boom"), { ok: "yes" }, null, { ok: true, why: 1 }.why]) {
    const h = harness({ id, config: { lease: "on" }, qualified: qualified ?? { ok: 0 } });
    assert.equal((await hostRun(h.d)).code, 3);
    assert.deepEqual(refusal(h.lines), ["lease_unqualified"]);
    assert.ok(!h.log.includes("unmask") && !h.log.includes("store"));
  }
  // lease off never asks
  const off = harness({ id });
  const run = hostRun(off.d);
  await until(() => off.lines.some((l) => l.serving));
  assert.ok(!off.log.includes("leaseQualified"));
  off.term();
  await run;
});

test("lease on and QUALIFIED: asked once, before the unmask; a LeaseMachine from the certified key, the pin's audience and fleet and the live chain, and the restore resume, reach the Supervisor", async () => {
  const { id } = await paired();
  const h = harness({ id, config: { lease: "on" }, qualified: { ok: true } });
  const run = hostRun(h.d);
  await until(() => h.lines.some((l) => l.serving));
  assert.equal(h.log.filter((x) => x === "leaseQualified").length, 1);
  assert.ok(h.log.indexOf("leaseQualified") < h.log.indexOf("unmask"));
  assert.ok(h.log.indexOf("lease") > h.log.indexOf("syncMade") && h.log.indexOf("lease") < h.log.indexOf("supervisor"));
  assert.equal(h.made.supervisor.lease, h.made.lease);
  assert.deepEqual(Object.keys(h.made.leaseOpts).sort(), ["context", "send", "sign", "submit", "verify"]);
  const c = h.made.leaseOpts.context();
  assert.deepEqual([c.aud, c.fleet, c.host], [id.pin.aud, id.pin.fleet, id.cert.body.host]);
  assert.equal(c.chain, h.made.sync.snapshot, "the chain the sync holds, read at the use");
  assert.equal(typeof h.made.supervisor.restoreResume.request, "function");
  assert.ok(Object.isFrozen(h.made.supervisor.restoreResume));
  h.term();
  assert.equal((await run).code, 0);
});

test("the restore resume through hostRun's wiring: exactly the base keys plus the per-call liveLease and verifyCtx; pairOf is null, so a real request refuses no_receipt and launches nothing", async () => {
  const { id } = await paired();
  const h = harness({ id, config: { lease: "on" }, qualified: { ok: true } });
  const run = hostRun(h.d);
  await until(() => h.lines.some((l) => l.serving));
  const A = newId();
  const live = async () => ({ lease_id: "L", lg: 3, gen: 1, expiry_tick: 1 });
  await h.made.supervisor.restoreResume.request(A, { liveLease: live });
  const { opts } = h.made.resumeCalls[0];
  assert.deepEqual(Object.keys(opts).sort(), [...RESUME_BASE_KEYS, "liveLease", "verifyCtx"].sort());
  assert.equal(opts.liveLease, live, "the executor's, untouched");
  assert.deepEqual(Object.keys(opts.verifyCtx).sort(), ["aud", "chain", "fleet"]);
  assert.deepEqual([opts.verifyCtx.aud, opts.verifyCtx.fleet, opts.verifyCtx.chain], [id.pin.aud, id.pin.fleet, h.made.sync.snapshot]);
  assert.deepEqual([opts.aud, opts.fleet, opts.ms, opts.node, opts.main], [id.pin.aud, id.pin.fleet, RESUME_HELPER_MS, process.execPath, h.d.resumeMain]);
  assert.equal(typeof opts.host.entryGen, "function");
  assert.equal(opts.pairOf(A), null);
  // H2(a): the chain is read per call: a rotation between two requests reaches the second, the first's untouched
  const rotated = { rotated: true };
  h.made.snapshot = rotated;
  await h.made.supervisor.restoreResume.request(A, { liveLease: live });
  assert.equal(h.made.resumeCalls[1].opts.verifyCtx.chain, rotated);
  assert.equal(opts.verifyCtx.chain, h.made.sync.snapshot);
  // the real requestResume over that wiring: no pair, no launch
  const r = await requestResume(A, { ...opts, restoreState: () => "validated", verifyTransferReceipt: async () => { throw new Error("never"); } });
  assert.deepEqual(r, { resumed: false, reason: "no_receipt" });
  assert.ok(!h.log.includes("runHelper"));
  h.term();
  await run;
});

const BASE = () => ({ restoreState: () => "validated", tagsOf: () => [], pairOf: () => null, verifyTransferReceipt: async () => ({}), checkTransferForHost: () => ({}),
  aud: "https://a", fleet: "F", host: { entryGen: () => 1, recordTransfer: () => {} }, run: async () => ({}), node: "/n", main: "/m", ms: RESUME_HELPER_MS });

test("resumeBase: exactly its keys, frozen; a liveLease, a verifyCtx, an unknown or a missing key refuses (bad_form)", () => {
  const b = resumeBase(BASE());
  assert.ok(Object.isFrozen(b));
  assert.deepEqual(Object.keys(b).sort(), [...RESUME_BASE_KEYS].sort());
  for (const [why, o] of [
    ["liveLease", { ...BASE(), liveLease: () => null }], ["verifyCtx", { ...BASE(), verifyCtx: {} }], ["unknown", { ...BASE(), chain: {} }],
    ["a symbol", { ...BASE(), [Symbol("x")]: 1 }], ["null", null], ["a string", "x"],
    ...RESUME_BASE_KEYS.map((k) => [`missing ${k}`, (() => { const o = BASE(); delete o[k]; return o; })()]),
    ...RESUME_BASE_KEYS.map((k) => [`liveLease instead of ${k}`, (() => { const o = BASE(); delete o[k]; o.liveLease = () => null; return o; })()]),
  ]) assert.throws(() => resumeBase(o), (e) => e.code === "bad_form", why);
});

test("C1: the wrapper takes EXACTLY liveLease per call: every base key, verifyCtx, anything else, or a non-function refuses before any effect; extra is never spread over the base", async () => {
  const calls = [];
  let chain = { v: 1 };
  const rr = resumeRequester(resumeBase(BASE()), () => chain, async (agent, opts) => { calls.push(opts); return { resumed: false, reason: "x" }; });
  const live = () => null;
  const bad = [
    ...RESUME_BASE_KEYS.map((k) => [`with ${k}`, { liveLease: live, [k]: BASE()[k] }]),
    ...RESUME_BASE_KEYS.map((k) => [`${k} alone`, { [k]: BASE()[k] }]),
    ["verifyCtx", { liveLease: live, verifyCtx: { chain: { forged: true } } }], ["verifyCtx alone", { verifyCtx: {} }],
    ["unknown", { liveLease: live, extra: 1 }], ["empty", {}], ["null", null], ["undefined", undefined], ["a string", "liveLease"],
    ["not a function", { liveLease: { live: 1 } }], ["a symbol beside", { liveLease: live, [Symbol("s")]: 1 }],
  ];
  for (const [why, extra] of bad) await assert.rejects(rr.request("A", extra), (e) => e.code === "bad_form", why);
  assert.equal(calls.length, 0, "nothing reached the resume");
  // H2(a): the chain is read per call; an earlier call's context isn't mutated by a rotation
  await rr.request("A", { liveLease: live });
  chain = { v: 2 };
  await rr.request("A", { liveLease: live });
  assert.deepEqual([calls[0].verifyCtx.chain, calls[1].verifyCtx.chain], [{ v: 1 }, { v: 2 }]);
  assert.equal(calls[0].liveLease, live);
  assert.ok(calls.every((c) => Object.keys(c).length === RESUME_BASE_KEYS.length + 2));
  assert.throws(() => resumeRequester({ ...BASE() }, () => chain), (e) => e.code === "bad_form", "an unfrozen base");
});

test("the host's own wiring asks leaseQualified with the release root alone: no test seam (rootUid, fsx, hook path) reaches production", () => {
  const src = readFileSync(new URL("../lib/fleet/host/host-main.mjs", import.meta.url), "utf8");
  const args = [...src.matchAll(/leaseQualified\(([^)]*)\)/g)].map((m) => m[1]);
  assert.ok(args.includes("release") && args.every((a) => a === "" || a === "release"), JSON.stringify(args));
  assert.match(src, /\n    leaseQualified: \(\) => leaseQualified\(release\),\n/);
});

// ---- the restore resume's validation gate through hostRun (restore owner, #172 H1): requestResume records a NEW
// transfer receipt durably before its helper runs, so a restore that isn't validated must refuse BEFORE the pair is read

/** A plan's config hashes for its agent sets (the manifest's, R4-d2b). */
const withConfig = (p) => ({ ...p, config: Object.fromEntries(Object.keys(p.sets).filter((k) => k.startsWith("agent-")).map((k) => [k.slice(6), "5".repeat(64)])) });
/** A valid restore plan naming `agent` and its `tags`. */
const RPLAN = (agent, tags) => {
  const hex = (c) => c.repeat(64), set = (c) => ({ run: "aaaaaaaaaaaaaaaa", snapshot: hex(c), tree: hex(c) });
  return withConfig({ v: 1, host: "h1", manifest: hex("1"), sha256: hex("2"), hoststore: hex("3"),
    sets: Object.fromEntries([[`agent-${agent}`, set("4")], ...tags.map((t, i) => [`tag-${t}`, set(String(5 + i))])]) });
};

/**
 * One resume request through hostRun (lease on, qualified) with the REAL requestResume and the base hostRun builds,
 * over a store whose registry lists the agent with two tags. `plan`: false for none, true for one naming the agent
 * and its tags. Spies: restoreReady (answering `verdict`), pairOf (a pair, counted), the transfer record, the helper.
 */
async function resumeGate({ plan, verdict = "validated" }) {
  const { id } = await paired();
  const agent = newId(), tags = [newId(), newId()];
  const p = plan ? RPLAN(agent, tags) : null;
  const s = { readyCalls: [], pairCalls: 0, recorded: [], helper: 0 };
  const h = harness({ id, config: { lease: "on" }, qualified: { ok: true } });
  h.d.openStore = async () => ({
    grants: { highwater: { gen: 0 }, record: () => null },
    registry: { agent: (x) => (x === agent ? { tags: [...tags] } : null) },
    transfers: { record: (...a) => { s.recorded.push(a); } },
    close: async () => {},
  });
  h.d.readPlan = () => p;
  h.d.restoreReady = (...a) => { s.readyCalls.push(a); return verdict; };
  h.d.pairOf = () => { s.pairCalls++; return { transfer: "T", receipt: "R" }; };
  h.d.runHelper = async () => { s.helper++; return { code: 0, stdout: "" }; };
  h.d.requestResume = requestResume;
  const run = hostRun(h.d);
  await until(() => h.lines.some((l) => l.serving));
  const r = await h.made.supervisor.restoreResume.request(agent, { liveLease: async () => ({ lease_id: "L", lg: 3, gen: 1, expiry_tick: 1 }) });
  h.term();
  await run;
  return { r, s, agent, tags, plan: p };
}

test("the resume gate (a): no restore plan: not_validated; restoreReady never asked; no pair read, nothing recorded, no helper", async () => {
  const { r, s } = await resumeGate({ plan: false });
  assert.deepEqual(r, { resumed: false, reason: "not_validated" });
  assert.deepEqual([s.readyCalls.length, s.pairCalls, s.recorded.length, s.helper], [0, 0, 0, 0]);
});

test("the resume gate (b): a plan: restoreReady gets exactly (the agent, its registry tags, expectedOf(plan)); every non-validated verdict refuses before the pair is read", async () => {
  for (const verdict of ["none", "importing", "files_validated", "abandoned", "failed"]) {
    const { r, s, agent, tags, plan } = await resumeGate({ plan: true, verdict });
    assert.deepEqual(r, { resumed: false, reason: "not_validated" }, verdict);
    assert.equal(s.readyCalls.length, 1, verdict);
    assert.deepEqual(s.readyCalls[0], [agent, tags, expectedOf(plan)], `${verdict}: the agent, its registry tags (not []), expectedOf(plan)`);
    assert.deepEqual([s.pairCalls, s.recorded.length, s.helper], [0, 0, 0], `${verdict}: nothing read, recorded or launched`);
  }
});

test("the resume gate (c): validated: the request passes the gate and reaches the receipt checks (the pair read and verified)", async () => {
  const { r, s, agent, tags, plan } = await resumeGate({ plan: true, verdict: "validated" });
  assert.deepEqual(s.readyCalls, [[agent, tags, expectedOf(plan)]]);
  assert.equal(s.pairCalls, 1, "the pair is read only after the gate");
  assert.equal(r.resumed, false);
  assert.equal(r.reason, "receipt", "the real verifier refused the fake pair: the receipt checks ran");
  assert.deepEqual([s.recorded.length, s.helper], [0, 0]);
});
