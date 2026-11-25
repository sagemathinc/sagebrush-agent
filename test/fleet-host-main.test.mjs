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
import { b64, hostFingerprint, keyFromSeed, replayChain, seal } from "../lib/fleet/index.mjs";
import { classify, firstBoot, hostPaths } from "../lib/fleet/host/identity.mjs";
import { ADAPTERS, CONFIG_MAX, CONTAIN_RETRY_MS, INITIAL_SYNC_MS, LEASE_QUALIFIED, brokerAccount, hostResetIdentity, hostRun, readHostConfig, realContainSys, supervisorUnit } from "../lib/fleet/host/host-main.mjs";
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
      return { sync: () => { ev("sync"); return o.sync ?? Promise.resolve({ status: "current" }); }, snapshot: () => x.snapshot,
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
  assert.equal(LEASE_QUALIFIED, false);
  const cases = [
    [{ config: Object.assign(new Error("bad"), { config: true }) }, "bad_config", ["config"]],
    [{ config: { lease: "on" } }, "lease_unqualified", ["config"]],
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
  assert.deepEqual(h.lines, [{ v: 1, containment: "unproven" }, { v: 1, refused: "lease_unqualified" }]);
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
  for (const l of ["ExecStart=/opt/sagebrush/r1/bin/sagebrush-agent host run", "User=root", "Type=simple", "Restart=on-failure", "RestartSec=10s",
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
