// Host supervisor (host daemon r2.5 §2, §3): the identity store. Its owner (the lock), the states, first boot, pairing's
// writes and their crash recovery, orphan entries, the containment and the reset with its intent record. On a temporary
// root, with the shared fixtures' honest chain and native device (which certifies this test's own fresh keys), and an
// injected stop (the real systemd/cgroup rows are the daemon's, L2c-2c).
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { chmodSync, lstatSync as lstatReal, statSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, symlinkSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "./host-linux-only.mjs";
import { b64, hostFingerprint, keyFromSeed, replayChain, seal } from "../lib/fleet/index.mjs";
import { classify, completeReset, contain, dropOrphans, firstBoot, hostPaths, pairWrite, resetIdentity, takeOwnership } from "../lib/fleet/host/identity.mjs";

const F = JSON.parse(readFileSync(new URL("./fixtures/fleet-fixtures.json", import.meta.url), "utf8"));
const enc = (s) => new TextEncoder().encode(s);
const AUD = F.aud, FLEET = F.ids.fleet, HOST = F.ids.host;
const N = keyFromSeed(Buffer.from(F.keys["device-native"].seed, "hex"));
const ENTRIES = F.objects.chain.map(enc);
const UID = process.getuid();
const tmp = () => mkdtempSync(join(tmpdir(), "sb-ident-"));
const machineA = () => "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n", machineB = () => "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n";
const opts = (root, machine = machineA) => ({ machineId: machine, brokerUid: UID, rootUid: UID });

/** A host root with keys (first boot) and, by `upTo`, pairing's writes: "entries", "pin", "cert". */
async function host(upTo = "none", { machine = machineA } = {}) {
  const root = tmp(), p = hostPaths(root);
  firstBoot(p, { machineId: machine });
  const fresh = await classify(p, opts(root, machine));
  assert.equal(fresh.state, "FRESH");
  const chain = await replayChain(ENTRIES, { aud: AUD, fleet: FLEET });
  const pin = { fleet: FLEET, aud: AUD, seq: chain.seq, hash: chain.head };
  const signer = { kind: "device", id: F.ids.device_native, alg: "ed25519", key: N.key };
  const body = { fleet: FLEET, aud: AUD, chain_seq: chain.seq, host: HOST, sign_key: b64(fresh.keys.sign.raw), enc_key: b64(fresh.keys.enc.raw),
    fingerprint: b64(await hostFingerprint(HOST, fresh.keys.sign.raw, fresh.keys.enc.raw)), name: "test-box", at_ms: 1_800_000_000_000 };
  const certBytes = seal("sb.host-cert.v1", signer, body, N);
  const id = join(p.identity), dir = join(id, "chain");
  if (upTo !== "none") { mkdirSync(dir, { recursive: true, mode: 0o700 }); chmodSync(id, 0o700); ENTRIES.forEach((e, s) => { writeFileSync(join(dir, String(s)), e, { mode: 0o600 }); }); }
  if (upTo === "pin" || upTo === "cert") writeFileSync(join(id, "pin"), JSON.stringify(pin), { mode: 0o600 });
  if (upTo === "cert") writeFileSync(join(id, "host-cert"), certBytes, { mode: 0o600 });
  return { root, p, keys: fresh.keys, pin, certBytes, chain };
}

/** A fake stop: { stopAll, stopBroker } with their proofs and a log. */
function sysFake({ agents = true, broker = true } = {}) {
  const log = [];
  return { log, stopAll: async () => { log.push("stopAll"); return { proven: agents }; }, stopBroker: async () => { log.push("stopBroker"); return { proven: broker }; } };
}

// ---- §3.0 the owner

test("one owner: a second takeOwnership (a second daemon, a reset) is refused in_progress at once, touching nothing; a dead owner's lock is gone", async () => {
  const { p } = await host("cert");
  const before = readdirSync(p.keys).map((f) => readFileSync(join(p.keys, f)).toString("hex")).join();
  const one = await takeOwnership(p);
  const t0 = Date.now();
  await assert.rejects(takeOwnership(p), (e) => e.code === "in_progress" && e.busy === true);
  assert.ok(Date.now() - t0 < 1000, "refused at once, never waiting");
  assert.equal(readdirSync(p.keys).map((f) => readFileSync(join(p.keys, f)).toString("hex")).join(), before, "nothing read-dependent written");
  await one.release();
  const two = await takeOwnership(p);
  await two.release();
  // A SIGKILLed owner: the kernel releases its flock with it.
  const child = spawn(process.execPath, ["--input-type=module", "-e",
    `import { takeOwnership, hostPaths } from ${JSON.stringify(new URL("../lib/fleet/host/identity.mjs", import.meta.url).href)}; await takeOwnership(hostPaths(${JSON.stringify(p.lock.replace("/var/lib/sagebrush/host.lock", ""))})); console.log("held"); setInterval(() => {}, 1000);`], { stdio: ["ignore", "pipe", "inherit"] });
  await new Promise((r) => child.stdout.on("data", (b) => { if (String(b).includes("held")) r(); }));
  await assert.rejects(takeOwnership(p), (e) => e.code === "in_progress");
  child.kill("SIGKILL");
  await new Promise((r) => child.on("exit", r));
  let got = null;
  for (let i = 0; i < 50 && !got; i++) { try { got = await takeOwnership(p); } catch { await new Promise((r) => setTimeout(r, 50)); } }
  assert.ok(got, "the next owner takes the lock once the dead owner's is gone");
  await got.release();
  assert.ok(existsSync(p.lock), "the lock file stays");
});

// ---- §3.1 the states

test("states: NO_KEYS, then first boot gives FRESH with broker-owned 0600 keys and a marker; a second start keeps the same keys", async () => {
  const root = tmp(), p = hostPaths(root);
  assert.equal((await classify(p, opts(root))).state, "NO_KEYS");
  firstBoot(p, { machineId: machineA });
  for (const f of ["sign", "enc", "first-boot"]) assert.equal(statSync(join(p.keys, f)).mode & 0o777, 0o600, f);
  assert.equal(statSync(p.keys).mode & 0o777, 0o700);
  assert.notDeepEqual(readFileSync(join(p.keys, "sign")), readFileSync(join(p.keys, "enc")), "two independent keys");
  // Owned by the broker's user: another uid than the files' is BROKEN.
  assert.equal((await classify(p, { ...opts(root), brokerUid: UID + 1 })).state, "BROKEN");
  // One key file owned by someone else (its directory right): BROKEN.
  const fsx = { ...(await import("node:fs")), lstatSync: (q, ...r) => {
    const st = lstatReal(q, ...r);
    return q.endsWith("/sign") ? Object.assign(Object.create(Object.getPrototypeOf(st)), st, { uid: UID + 1 }) : st;
  } };
  assert.equal((await classify(p, { ...opts(root), fsx })).state, "BROKEN");
  const a = await classify(p, opts(root)), b = await classify(p, opts(root));
  assert.equal(a.state, "FRESH");
  assert.deepEqual(b.keys.sign.raw, a.keys.sign.raw, "the same pair at the next start");
  // Two first boots on two roots: independent keys.
  const root2 = tmp(), p2 = hostPaths(root2);
  firstBoot(p2, { machineId: machineA });
  assert.notDeepEqual((await classify(p2, opts(root2))).keys.sign.raw, a.keys.sign.raw);
});

test("states: the pairing writes give FRESH (entries only), PAIRING (entries + pin) and PAIRED (+ cert); a cert without a pin is BROKEN", async () => {
  assert.equal((await classify((await host("entries")).p, opts())).state, "FRESH", "entries without a pin are ignored");
  const pairing = await classify((await host("pin")).p, opts());
  assert.equal(pairing.state, "PAIRING");
  assert.equal(pairing.chain.seq, 5);
  const h = await host("cert");
  const paired = await classify(h.p, opts());
  assert.equal(paired.state, "PAIRED", paired.why);
  assert.equal(paired.cert.body.host, HOST);
  const c = await host("cert");
  unlinkSync(join(c.p.identity, "pin"));
  assert.equal((await classify(c.p, opts())).state, "BROKEN");
});

test("states: CLONE (another machine id), REVOKED, RESETTING (whatever else is there)", async () => {
  const h = await host("cert");
  assert.equal((await classify(h.p, opts(h.root, machineB))).state, "CLONE");
  writeFileSync(join(h.p.identity, "revoked"), "1\n", { mode: 0o600 });
  assert.equal((await classify(h.p, opts())).state, "REVOKED");
  writeFileSync(h.p.resetPending, "1\n", { mode: 0o600 });
  assert.equal((await classify(h.p, opts(h.root, machineB))).state, "RESETTING", "the record first, even over a clone");
});

test("states: every broken combination and file is BROKEN, never another state", async () => {
  const cases = [
    ["one key missing", (h) => unlinkSync(join(h.p.keys, "enc"))],
    ["the marker missing", (h) => unlinkSync(join(h.p.keys, "first-boot"))],
    ["a key of the wrong mode", (h) => chmodSync(join(h.p.keys, "sign"), 0o644)],
    ["the keys directory of the wrong mode", (h) => chmodSync(h.p.keys, 0o755)],
    ["a key that is a link", (h) => { const t = join(h.root, "k"); writeFileSync(t, readFileSync(join(h.p.keys, "sign")), { mode: 0o600 }); unlinkSync(join(h.p.keys, "sign")); symlinkSync(t, join(h.p.keys, "sign")); }],
    ["a key that is a FIFO", (h) => { unlinkSync(join(h.p.keys, "enc")); spawnSyncMkfifo(join(h.p.keys, "enc")); }],
    ["a marker naming other keys", (h) => { const m = JSON.parse(readFileSync(join(h.p.keys, "first-boot"))); m.sign = "A".repeat(43); writeFileSync(join(h.p.keys, "first-boot"), JSON.stringify(m), { mode: 0o600 }); }],
    ["a chain entry missing", (h) => unlinkSync(join(h.p.identity, "chain", "2"))],
    ["a chain entry altered", (h) => { const f = join(h.p.identity, "chain", "3"); writeFileSync(f, Buffer.concat([readFileSync(f), Buffer.from(" ")]), { mode: 0o600 }); }],
    ["a pin off the chain", (h) => writeFileSync(join(h.p.identity, "pin"), JSON.stringify({ ...h.pin, hash: "A".repeat(43) }), { mode: 0o600 })],
    ["a pin above the chain", (h) => writeFileSync(join(h.p.identity, "pin"), JSON.stringify({ ...h.pin, seq: 6 }), { mode: 0o600 })],
    ["a certificate altered", (h) => writeFileSync(join(h.p.identity, "host-cert"), Buffer.concat([h.certBytes.slice(0, -2), Buffer.from("A}")]), { mode: 0o600 })],
    ["a certificate for other keys", async (h) => { const o = await host("cert"); writeFileSync(join(h.p.identity, "host-cert"), o.certBytes, { mode: 0o600 }); }],
    ["a stray chain file", (h) => writeFileSync(join(h.p.identity, "chain", "x"), "", { mode: 0o600 })],
  ];
  for (const [what, spoil] of cases) {
    const h = await host("cert");
    await spoil(h);
    const r = await classify(h.p, opts());
    assert.equal(r.state, "BROKEN", `${what}: ${r.state}`);
  }
  // The identity directory inside a restore root, or a link to one.
  const h = await host("cert");
  const inside = { ...h.p, identity: join(h.root, "var/lib/sagebrush/restore/identity") };
  assert.equal((await classify(inside, opts())).state, "BROKEN");
  const link = join(h.root, "var/lib/sagebrush/identity-link");
  symlinkSync(h.p.identity, link);
  assert.equal((await classify({ ...h.p, identity: link }, opts())).state, "BROKEN");
  // ... also on a FRESH host, whose identity directory holds no file yet.
  const f = await host("none");
  mkdirSync(join(f.root, "elsewhere"), { mode: 0o700 });
  const flink = join(f.root, "var/lib/sagebrush/identity-link");
  mkdirSync(join(f.root, "var/lib/sagebrush"), { recursive: true });
  symlinkSync(join(f.root, "elsewhere"), flink);
  assert.equal((await classify({ ...f.p, identity: flink }, opts())).state, "BROKEN");
});
function spawnSyncMkfifo(path) { assert.equal(spawnSync("mkfifo", ["-m", "600", path]).status, 0); }

test("first boot discards identity files left behind (keys gone, a pin and a certificate still there)", async () => {
  const h = await host("cert");
  for (const f of ["sign", "enc", "first-boot"]) unlinkSync(join(h.p.keys, f));
  assert.equal((await classify(h.p, opts())).state, "NO_KEYS");
  firstBoot(h.p, { machineId: machineA });
  assert.equal(existsSync(join(h.p.identity, "pin")), false);
  assert.equal(existsSync(join(h.p.identity, "host-cert")), false);
  assert.equal((await classify(h.p, opts())).state, "FRESH");
});

test("orphan entries above the pin: never read as authority (PAIRED at the old pin), and dropped at the PAIRED start", async () => {
  const h = await host("cert");
  // An adoption's entries written, its pin not: seqs 6 and 7 with junk bytes.
  writeFileSync(join(h.p.identity, "chain", "6"), "junk", { mode: 0o600 });
  writeFileSync(join(h.p.identity, "chain", "7"), "junk", { mode: 0o600 });
  const r = await classify(h.p, opts());
  assert.equal(r.state, "PAIRED");
  assert.equal(r.chain.seq, 5, "the old pin's authority");
  assert.deepEqual(r.orphans, [6, 7]);
  dropOrphans(h.p, r.orphans);
  assert.deepEqual(readdirSync(join(h.p.identity, "chain")).map(Number).sort((a, b) => a - b), [0, 1, 2, 3, 4, 5]);
});

// ---- §3.2 pairing

test("pairing writes entries, then the pin, then the certificate; a certificate for other keys or off the chain writes nothing", async () => {
  const h = await host("none");
  const other = await host("none");
  // Another host's certificate: refused before any write.
  await assert.rejects(pairWrite(h.p, { keys: h.keys, entries: ENTRIES, pin: h.pin, certBytes: other.certBytes }));
  assert.equal(existsSync(join(h.p.identity, "pin")), false);
  assert.equal((await classify(h.p, opts())).state, "FRESH");
  // A pin that isn't the head: refused, above it and below it.
  await assert.rejects(pairWrite(h.p, { keys: h.keys, entries: ENTRIES.slice(0, 4), pin: h.pin, certBytes: h.certBytes }));
  const below = await replayChain(ENTRIES.slice(0, 4), { aud: AUD, fleet: FLEET });
  await assert.rejects(pairWrite(h.p, { keys: h.keys, entries: ENTRIES, pin: { ...h.pin, seq: below.seq, hash: below.head }, certBytes: h.certBytes }));
  assert.equal(existsSync(join(h.p.identity, "pin")), false);
  // The real one.
  const cert = await pairWrite(h.p, { keys: h.keys, entries: ENTRIES, pin: h.pin, certBytes: h.certBytes });
  assert.equal(cert.body.host, HOST);
  assert.equal((await classify(h.p, opts())).state, "PAIRED");
  // A restarted pairing from PAIRING rewrites its entries and completes.
  const g = await host("pin");
  await pairWrite(g.p, { keys: g.keys, entries: ENTRIES, pin: g.pin, certBytes: g.certBytes });
  assert.equal((await classify(g.p, opts())).state, "PAIRED");
});

// ---- §3.1 containment and §3.3 the reset

test("the containment needs BOTH the agents and the broker proven", async () => {
  await contain(sysFake());
  await assert.rejects(contain(sysFake({ agents: false })), (e) => e.code === "not_empty");
  await assert.rejects(contain(sysFake({ broker: false })), (e) => e.code === "not_empty");
  const s = sysFake();
  await contain(s);
  assert.deepEqual(s.log, ["stopAll", "stopBroker"]);
});

test("the reset: broker proven gone BEFORE the record; then the record; then the containment; keys first; the record last", async () => {
  const h = await host("cert");
  const s = sysFake(), seen = [];
  const barrier = async (name) => {
    seen.push([name, existsSync(h.p.resetPending), existsSync(join(h.p.keys, "sign")), existsSync(join(h.p.keys, "enc")), existsSync(join(h.p.keys, "first-boot")), existsSync(join(h.p.identity, "pin"))]);
  };
  const r = await resetIdentity(h.p, s, { barrier });
  assert.deepEqual(r, { state: "NO_KEYS" });
  assert.deepEqual(s.log, ["stopBroker", "stopAll", "stopBroker"]);
  assert.deepEqual(seen, [
    ["after_broker", false, true, true, true, true],
    ["after_record", true, true, true, true, true],
    ["after_contain", true, true, true, true, true],
    ["after_key_sign", true, false, true, true, true],
    ["after_key_enc", true, false, false, true, true],
    ["after_marker", true, false, false, false, true],
    ["after_identity", true, false, false, false, false],
  ]);
  assert.equal(existsSync(h.p.resetPending), false);
  assert.equal((await classify(h.p, opts())).state, "NO_KEYS");
});

test("the reset's failures: a key holder surviving records nothing; a slice surviving keeps the record and deletes nothing", async () => {
  const h = await host("cert");
  await assert.rejects(resetIdentity(h.p, sysFake({ broker: false })), (e) => e.code === "not_empty");
  assert.equal(existsSync(h.p.resetPending), false);
  assert.equal((await classify(h.p, opts())).state, "PAIRED", "before the record: the old identity, unchanged");
  await assert.rejects(resetIdentity(h.p, sysFake({ agents: false })), (e) => e.code === "not_empty");
  assert.equal(existsSync(h.p.resetPending), true);
  assert.equal(existsSync(join(h.p.keys, "sign")), true, "nothing deleted");
  assert.equal((await classify(h.p, opts())).state, "RESETTING", "and the next start completes it, never PAIRED again");
  await completeReset(h.p, sysFake());
  assert.equal((await classify(h.p, opts())).state, "NO_KEYS");
});

test("a crash at each step after the record: the next start is RESETTING and completes; before it: unchanged and PAIRED", async () => {
  for (const at of ["after_broker", "after_record", "after_contain", "after_key_sign", "after_key_enc", "after_marker", "after_identity"]) {
    const h = await host("cert");
    await assert.rejects(resetIdentity(h.p, sysFake(), { barrier: async (n) => { if (n === at) throw new Error("crash"); } }), /crash/);
    const r = await classify(h.p, opts());
    if (at === "after_broker") {
      assert.equal(r.state, "PAIRED", "before the record: nothing changed");
      continue;
    }
    assert.equal(r.state, "RESETTING", at);
    await completeReset(h.p, sysFake());
    assert.equal((await classify(h.p, opts())).state, "NO_KEYS", at);
    // NO KEYS's first boot gives NEW keys.
    firstBoot(h.p, { machineId: machineA });
    assert.notDeepEqual((await classify(h.p, opts())).keys.sign.raw, h.keys.sign.raw, at);
  }
});
