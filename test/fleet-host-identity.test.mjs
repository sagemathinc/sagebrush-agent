// Host supervisor (host daemon r2.5 §2, §3): the identity store. Its owner (the lock), the states, first boot, pairing's
// writes and their crash recovery, orphan entries, the containment and the reset with its intent record. On a temporary
// root, with the shared fixtures' honest chain and native device (which certifies this test's own fresh keys), and an
// injected stop (the real systemd/cgroup rows are the daemon's, L2c-2c).
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { chmodSync, lstatSync as lstatReal, renameSync as renameReal, rmdirSync as rmdirReal, statSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, symlinkSync, unlinkSync, writeFileSync } from "node:fs";
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
// A host root with the package's /var/lib/sagebrush (0755, the test's own uid standing for root): nothing creates it.
const tmp = () => { const r = mkdtempSync(join(tmpdir(), "sb-ident-")); mkdirSync(join(r, "var/lib/sagebrush"), { recursive: true, mode: 0o755 }); return r; };
const R = { rootUid: UID };
const machineA = () => "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n", machineB = () => "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n";
const opts = (root, machine = machineA) => ({ machineId: machine, brokerUid: UID, rootUid: UID });

/** A host root with keys (first boot) and, by `upTo`, pairing's writes: "entries", "pin", "cert". */
async function host(upTo = "none", { machine = machineA } = {}) {
  const root = tmp(), p = hostPaths(root);
  firstBoot(p, { machineId: machine, brokerUid: UID });
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
  const one = await takeOwnership(p, { rootUid: UID });
  const t0 = Date.now();
  await assert.rejects(takeOwnership(p, { rootUid: UID }), (e) => e.code === "in_progress" && e.busy === true);
  assert.ok(Date.now() - t0 < 1000, "refused at once, never waiting");
  assert.equal(readdirSync(p.keys).map((f) => readFileSync(join(p.keys, f)).toString("hex")).join(), before, "nothing read-dependent written");
  await one.release();
  const two = await takeOwnership(p, { rootUid: UID });
  await two.release();
  // A SIGKILLed owner: the kernel releases its flock with it.
  const child = spawn(process.execPath, ["--input-type=module", "-e",
    `import { takeOwnership, hostPaths } from ${JSON.stringify(new URL("../lib/fleet/host/identity.mjs", import.meta.url).href)}; await takeOwnership(hostPaths(${JSON.stringify(p.lock.replace("/var/lib/sagebrush/host.lock", ""))}), { rootUid: ${UID} }); console.log("held"); setInterval(() => {}, 1000);`], { stdio: ["ignore", "pipe", "inherit"] });
  await new Promise((r) => child.stdout.on("data", (b) => { if (String(b).includes("held")) r(); }));
  await assert.rejects(takeOwnership(p, { rootUid: UID }), (e) => e.code === "in_progress");
  child.kill("SIGKILL");
  await new Promise((r) => child.on("exit", r));
  let got = null;
  for (let i = 0; i < 50 && !got; i++) { try { got = await takeOwnership(p, { rootUid: UID }); } catch { await new Promise((r) => setTimeout(r, 50)); } }
  assert.ok(got, "the next owner takes the lock once the dead owner's is gone");
  await got.release();
  assert.ok(existsSync(p.lock), "the lock file stays");
});

// ---- §3.1 the states

test("states: NO_KEYS, then first boot gives FRESH with broker-owned 0600 keys and a marker; a second start keeps the same keys", async () => {
  const root = tmp(), p = hostPaths(root);
  assert.equal((await classify(p, opts(root))).state, "NO_KEYS");
  firstBoot(p, { machineId: machineA, brokerUid: UID });
  for (const f of ["sign", "enc", "first-boot"]) assert.equal(statSync(join(p.keys, f)).mode & 0o777, 0o600, f);
  assert.equal(statSync(p.keys).mode & 0o777, 0o700);
  assert.notDeepEqual(readFileSync(join(p.keys, "sign")), readFileSync(join(p.keys, "enc")), "two independent keys");
  // Owned by the broker's user: another uid than the files' is BROKEN.
  assert.equal((await classify(p, { ...opts(root), brokerUid: UID + 1 })).state, "BROKEN");
  // One key file owned by someone else (its directory right): BROKEN.
  const realFs = await import("node:fs"), signFds = new Set();
  const fsx = { ...realFs,
    openSync: (q, ...r) => { const fd = realFs.openSync(q, ...r); if (String(q).endsWith("/sign")) signFds.add(fd); return fd; },
    closeSync: (fd) => { signFds.delete(fd); return realFs.closeSync(fd); },
    fstatSync: (fd, ...r) => { const st = realFs.fstatSync(fd, ...r); return signFds.has(fd) ? Object.assign(Object.create(Object.getPrototypeOf(st)), st, { uid: UID + 1 }) : st; } };
  assert.equal((await classify(p, { ...opts(root), fsx })).state, "BROKEN");
  // The keys DIRECTORY owned by someone else (by its descriptor): BROKEN.
  const dirFds = new Set();
  const fsxd = { ...realFs,
    openSync: (q, ...r) => { const fd = realFs.openSync(q, ...r); if (String(q) === p.keys) dirFds.add(fd); return fd; },
    closeSync: (fd) => { dirFds.delete(fd); return realFs.closeSync(fd); },
    fstatSync: (fd, ...r) => { const st = realFs.fstatSync(fd, ...r); return dirFds.has(fd) ? Object.assign(Object.create(Object.getPrototypeOf(st)), st, { uid: UID + 1 }) : st; } };
  assert.equal((await classify(p, { ...opts(root), fsx: fsxd })).state, "BROKEN");
  const a = await classify(p, opts(root)), b = await classify(p, opts(root));
  assert.equal(a.state, "FRESH");
  assert.deepEqual(b.keys.sign.raw, a.keys.sign.raw, "the same pair at the next start");
  // Two first boots on two roots: independent keys.
  const root2 = tmp(), p2 = hostPaths(root2);
  firstBoot(p2, { machineId: machineA, brokerUid: UID });
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
    ["a marker with an extra field", (h) => { const m = JSON.parse(readFileSync(join(h.p.keys, "first-boot"))); m.extra = 1; writeFileSync(join(h.p.keys, "first-boot"), JSON.stringify(m), { mode: 0o600 }); }],
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

test("separation (§2) first: the identity under the validation or staging root, or behind a linked ancestor even before it exists, is BROKEN", async () => {
  const h = await host("cert");
  assert.equal((await classify({ ...h.p, identity: join(h.root, "var/lib/sagebrush/validate/identity") }, opts())).state, "BROKEN");
  assert.equal((await classify({ ...h.p, identity: join(h.root, "srv/sagebrush/.restore/identity") }, opts())).state, "BROKEN");
  // A directory literally named "..x" inside a root is inside it (the exact relative-path test).
  assert.equal((await classify({ ...h.p, identity: join(h.root, "srv/sagebrush/..x") }, opts())).state, "BROKEN");
  // A linked ancestor pointing elsewhere (not into a root), the identity directory not created yet: BROKEN.
  const root2 = tmp(), p2 = hostPaths(root2);
  firstBoot(p2, { machineId: machineA, brokerUid: UID });
  mkdirSync(join(root2, "elsewhere"), { recursive: true });
  rmdirReal(join(root2, "var/lib/sagebrush"));
  symlinkSync(join(root2, "elsewhere"), join(root2, "var/lib/sagebrush"));
  assert.equal((await classify(p2, opts(root2))).state, "BROKEN");
});

test("separation before every state: no keys or a pending reset with the identity linked into a restore tree is BROKEN; nothing generated, discarded or deleted", async () => {
  // No keys, /var/lib/sagebrush a link into the homes' root (the identity directory isn't there yet).
  const root = tmp(), p = hostPaths(root);
  mkdirSync(join(root, "srv/sagebrush"), { recursive: true });
  rmdirReal(join(root, "var/lib/sagebrush"));
  symlinkSync(join(root, "srv/sagebrush"), join(root, "var/lib/sagebrush"));
  assert.equal((await classify(p, opts(root))).state, "BROKEN", "not NO_KEYS: no first boot follows");
  assert.equal(existsSync(p.keys), false, "no keys generated");
  // A pending reset with the identity directory a link into the restore records: BROKEN, the target untouched.
  const h = await host("cert");
  const target = join(h.root, "var/lib/sagebrush/restore");
  mkdirSync(target, { recursive: true });
  writeFileSync(join(target, "agent-x.json"), "record");
  for (const n of readdirSync(join(h.p.identity, "chain"))) unlinkSync(join(h.p.identity, "chain", n));
  rmdirReal(join(h.p.identity, "chain"));
  for (const f of readdirSync(h.p.identity)) unlinkSync(join(h.p.identity, f));
  rmdirReal(h.p.identity);
  symlinkSync(target, h.p.identity);
  writeFileSync(h.p.resetPending, "1\n", { mode: 0o600 });
  assert.equal((await classify(h.p, opts())).state, "BROKEN", "not RESETTING: its deletion never runs");
  assert.equal(readFileSync(join(target, "agent-x.json"), "utf8"), "record");
});

test("the reset never follows a link: a linked chain directory is removed itself; a linked identity or keys directory refuses the reset; the target is untouched either way", async () => {
  for (const which of ["chain", "identity"]) {
    const h = await host("cert");
    const target = join(h.root, "target");
    mkdirSync(target, { mode: 0o700 });
    writeFileSync(join(target, "keepme"), "x");
    for (const n of readdirSync(join(h.p.identity, "chain"))) unlinkSync(join(h.p.identity, "chain", n));
    rmdirReal(join(h.p.identity, "chain"));
    if (which === "chain") {
      symlinkSync(target, join(h.p.identity, "chain"));
      await resetIdentity(h.p, sysFake(), R);
      assert.equal(existsSync(join(h.p.identity, "chain")), false, "the link itself removed");
    } else {
      for (const f of readdirSync(h.p.identity)) unlinkSync(join(h.p.identity, f));
      rmdirReal(h.p.identity);
      symlinkSync(target, h.p.identity);
      await assert.rejects(resetIdentity(h.p, sysFake(), R), (e) => e.code === "bad_form");
    }
    assert.equal(readFileSync(join(target, "keepme"), "utf8"), "x", which);
  }
  // A linked keys directory: the reset (and a RESETTING completion) refuses; the target's files stay.
  const h = await host("cert");
  const kt = join(h.root, "ktarget");
  mkdirSync(kt, { mode: 0o700 });
  writeFileSync(join(kt, "sign"), "x");
  for (const f of readdirSync(h.p.keys)) unlinkSync(join(h.p.keys, f));
  rmdirReal(h.p.keys);
  symlinkSync(kt, h.p.keys);
  writeFileSync(h.p.resetPending, "1\n");
  await assert.rejects(completeReset(h.p, sysFake(), R), (e) => e.code === "bad_form");
  assert.equal(readFileSync(join(kt, "sign"), "utf8"), "x");
});

test("the reset runs the layout check first: a linked ancestor of the keys or the identity refuses before the broker stop or any record, nothing deleted", async () => {
  for (const which of ["var/lib/sagebrush-broker", "var/lib/sagebrush"]) {
    const h = await host("cert");
    const moved = join(h.root, "moved");
    renameReal(join(h.root, which), moved);
    symlinkSync(moved, join(h.root, which));
    const watched = which.endsWith("broker") ? join(moved, "keys") : join(moved, "identity");
    const before = readdirSync(watched).sort();
    const s = sysFake();
    await assert.rejects(resetIdentity(h.p, s, R), (e) => e.code === "bad_form", which);
    assert.deepEqual(s.log, [], `${which}: no stop ran`);
    assert.equal(existsSync(join(moved, "reset-pending")) || existsSync(h.p.resetPending), false, `${which}: nothing recorded`);
    assert.deepEqual(readdirSync(watched).sort(), before, `${which}: nothing deleted`);
    await assert.rejects(completeReset(h.p, sysFake(), R), (e) => e.code === "bad_form", which);
    assert.deepEqual(readdirSync(watched).sort(), before);
  }
});

test("the lock: created exactly 0600; a pre-existing lock that is a link, or of another mode, is refused before anything is read", async () => {
  const root = tmp(), p = hostPaths(root);
  mkdirSync(join(root, "var/lib/sagebrush"), { recursive: true, mode: 0o755 });
  const old = process.umask(0o277); // a umask that would leave 0400: the lock is still made exactly 0600
  let l;
  try { l = await takeOwnership(p, { rootUid: UID }); } finally { process.umask(old); }
  assert.equal(statSync(p.lock).mode & 0o777, 0o600);
  await l.release();
  const r2 = tmp(), p2 = hostPaths(r2);
  mkdirSync(join(r2, "var/lib/sagebrush"), { recursive: true });
  writeFileSync(join(r2, "elsewhere"), "", { mode: 0o600 }); // a target that would itself pass: only the link refuses
  symlinkSync(join(r2, "elsewhere"), p2.lock);
  await assert.rejects(takeOwnership(p2, { rootUid: UID }), (e) => e.code === "bad_form");
  const r3 = tmp(), p3 = hostPaths(r3);
  mkdirSync(join(r3, "var/lib/sagebrush"), { recursive: true });
  writeFileSync(p3.lock, "", { mode: 0o644 });
  chmodSync(p3.lock, 0o644);
  await assert.rejects(takeOwnership(p3, { rootUid: UID }), (e) => e.code === "bad_form");
});

/** An fs whose fstat reports another owner for any descriptor opened on `path`. */
async function ownerFs(path) {
  const realFs = await import("node:fs");
  const fds = new Set();
  return { ...realFs,
    openSync: (q, ...r) => { const fd = realFs.openSync(q, ...r); if (String(q) === path) fds.add(fd); return fd; },
    closeSync: (fd) => { fds.delete(fd); realFs.closeSync(fd); },
    fstatSync: (fd, ...r) => { const st = realFs.fstatSync(fd, ...r); return fds.has(fd) ? Object.assign(Object.create(Object.getPrototypeOf(st)), st, { uid: UID + 1 }) : st; } };
}

test("the parents: the lock's and the record's directory, or any ancestor, writable by group or other, of another owner, linked or missing refuses before any lock, stop or record; nothing created", async () => {
  for (const which of ["0777", "0775", "ancestor 0777", "owner", "linked", "missing"]) {
    const h = await host("cert");
    const parent = join(h.root, "var/lib/sagebrush");
    writeFileSync(h.p.resetPending, "1\n", { mode: 0o600 }); // a pending reset: RESETTING, were the parent fine
    let fsx;
    if (which === "0777") chmodSync(parent, 0o777);
    if (which === "0775") chmodSync(parent, 0o775);
    if (which === "ancestor 0777") chmodSync(join(h.root, "var"), 0o777);
    if (which === "owner") fsx = await ownerFs(parent);
    if (which === "linked") { renameReal(parent, join(h.root, "moved")); symlinkSync(join(h.root, "moved"), parent); }
    if (which === "missing") { unlinkSync(h.p.resetPending); for (const n of readdirSync(join(h.p.identity, "chain"))) unlinkSync(join(h.p.identity, "chain", n)); rmdirReal(join(h.p.identity, "chain")); for (const f of readdirSync(h.p.identity)) unlinkSync(join(h.p.identity, f)); rmdirReal(h.p.identity); rmdirReal(parent); }
    const keys = readdirSync(h.p.keys).sort();
    const o = fsx ? { fsx } : {};
    await assert.rejects(takeOwnership(h.p, { rootUid: UID, ...o }), (e) => e.code === "bad_form", which);
    assert.equal(existsSync(h.p.lock), false, `${which}: no lock file made`);
    const c = await classify(h.p, { ...opts(), ...o });
    assert.equal(c.state, "BROKEN", `${which}: not RESETTING or NO_KEYS`);
    const s = sysFake();
    await assert.rejects(resetIdentity(h.p, s, { ...R, ...o }), (e) => e.code === "bad_form", which);
    await assert.rejects(completeReset(h.p, s, { ...R, ...o }), (e) => e.code === "bad_form", which);
    assert.deepEqual(s.log, [], `${which}: no stop ran`);
    assert.deepEqual(readdirSync(h.p.keys).sort(), keys, `${which}: nothing deleted`);
    if (which === "missing") assert.equal(existsSync(parent), false, "a missing parent is never created");
    else assert.equal(existsSync(h.p.resetPending), true, which);
  }
});

test("the lock can't be split: replacing its pathname needs a parent someone besides root can write, and then the next owner refuses rather than locking a second file", async () => {
  const h = await host("cert");
  const parent = join(h.root, "var/lib/sagebrush");
  const one = await takeOwnership(h.p, R);
  // The parent as it must be: root's (here the test's uid), no group or other write, so only root can unlink the lock.
  const st = statSync(parent);
  assert.equal(st.uid, UID);
  assert.equal(st.mode & 0o022, 0);
  // A parent opened to others is the only way the held lock's name could be unlinked and a fresh file put there: the
  // second owner refuses before creating or locking anything.
  chmodSync(parent, 0o777);
  unlinkSync(h.p.lock);
  await assert.rejects(takeOwnership(h.p, R), (e) => e.code === "bad_form");
  assert.equal(existsSync(h.p.lock), false, "no second lock file");
  chmodSync(parent, 0o755);
  await one.release();
});

test("owner and mode come from the descriptor read: a key swapped for a same-bytes 0644 copy between the look and the open is BROKEN; a linked keys ancestor is BROKEN", async () => {
  const h = await host("cert");
  const realFs = await import("node:fs");
  let swapped = false;
  const fsx = { ...realFs, openSync: (q, ...r) => {
    if (!swapped && String(q).endsWith("/keys/sign")) {
      swapped = true;
      const bytes = realFs.readFileSync(q);
      realFs.unlinkSync(q);
      realFs.writeFileSync(q, bytes, { mode: 0o644 });
      realFs.chmodSync(q, 0o644);
    }
    return realFs.openSync(q, ...r);
  } };
  assert.equal((await classify(h.p, { ...opts(), fsx })).state, "BROKEN");
  // The same swap with a 0600 copy of the same bytes: owner, mode and content all right, but another file than the one
  // looked at: BROKEN.
  const k = await host("cert");
  let swapped2 = false;
  const fsx2 = { ...realFs, openSync: (q, ...r) => {
    if (!swapped2 && String(q).endsWith("/keys/sign")) {
      swapped2 = true;
      const bytes = realFs.readFileSync(q);
      realFs.unlinkSync(q);
      realFs.writeFileSync(q, bytes, { mode: 0o600 });
    }
    return realFs.openSync(q, ...r);
  } };
  assert.equal((await classify(k.p, { ...opts(), fsx: fsx2 })).state, "BROKEN");
  // /var/lib/sagebrush-broker itself a link (the keys reached through it).
  const g = await host("cert");
  const real = join(g.root, "broker-real");
  realFs.renameSync(join(g.root, "var/lib/sagebrush-broker"), real);
  symlinkSync(real, join(g.root, "var/lib/sagebrush-broker"));
  assert.equal((await classify(g.p, opts())).state, "BROKEN");
});

test("reset-pending and revoked are hardened records: a link, a FIFO, the wrong mode, other content or an oversize file is BROKEN, never RESETTING or REVOKED", async () => {
  for (const [which, path] of [["reset-pending", (h) => h.p.resetPending], ["revoked", (h) => join(h.p.identity, "revoked")]]) {
    for (const [what, make] of [
      ["a link", (f, h) => { writeFileSync(join(h.root, "t"), "1\n", { mode: 0o600 }); symlinkSync(join(h.root, "t"), f); }],
      ["a FIFO", (f) => spawnSyncMkfifo(f)],
      ["mode 0644", (f) => { writeFileSync(f, "1\n", { mode: 0o644 }); chmodSync(f, 0o644); }],
      ["other content", (f) => writeFileSync(f, "yes", { mode: 0o600 })],
      ["oversize", (f) => writeFileSync(f, "1\n".repeat(100), { mode: 0o600 })],
    ]) {
      const h = await host("cert");
      make(path(h), h);
      assert.equal((await classify(h.p, opts())).state, "BROKEN", `${which}: ${what}`);
    }
    const ok = await host("cert");
    writeFileSync(path(ok), "1\n", { mode: 0o600 });
    assert.equal((await classify(ok.p, opts())).state, which === "revoked" ? "REVOKED" : "RESETTING");
  }
});

test("creation never inherits an unsafe directory: an existing keys or identity directory of the wrong mode, or a link, refuses; new ones are exactly 0700", async () => {
  // A pre-existing keys directory 0755: first boot refuses, writes no key.
  const root = tmp(), p = hostPaths(root);
  mkdirSync(p.keys, { recursive: true, mode: 0o755 });
  chmodSync(p.keys, 0o755);
  assert.throws(() => firstBoot(p, { machineId: machineA, brokerUid: UID }), (e) => e.code === "bad_form");
  assert.deepEqual(readdirSync(p.keys), []);
  // A keys directory that is a link: refused.
  const r2 = tmp(), p2 = hostPaths(r2);
  mkdirSync(join(r2, "kreal"), { mode: 0o700 });
  mkdirSync(join(r2, "var/lib/sagebrush-broker"), { recursive: true });
  symlinkSync(join(r2, "kreal"), p2.keys);
  assert.throws(() => firstBoot(p2, { machineId: machineA, brokerUid: UID }), (e) => e.code === "bad_form");
  assert.deepEqual(readdirSync(join(r2, "kreal")), []);
  // A linked ancestor of the keys directory (/var/lib/sagebrush-broker a link): refused, nothing written there.
  const r4 = tmp(), p4 = hostPaths(r4);
  mkdirSync(join(r4, "breal"), { mode: 0o755 });
  mkdirSync(join(r4, "var/lib"), { recursive: true });
  symlinkSync(join(r4, "breal"), join(r4, "var/lib/sagebrush-broker"));
  assert.throws(() => firstBoot(p4, { machineId: machineA, brokerUid: UID }), (e) => e.code === "bad_form");
  assert.deepEqual(readdirSync(join(r4, "breal")), []);
  // New directories under a narrowing umask are still exactly 0700.
  const r3 = tmp(), p3 = hostPaths(r3);
  mkdirSync(join(r3, "var/lib/sagebrush-broker"), { recursive: true, mode: 0o755 });
  const old = process.umask(0o277);
  try { firstBoot(p3, { machineId: machineA, brokerUid: UID }); } finally { process.umask(old); }
  assert.equal(statSync(p3.keys).mode & 0o777, 0o700);
  // Pairing into an identity directory of the wrong mode: refused, nothing written.
  const h = await host("none");
  mkdirSync(h.p.identity, { recursive: true, mode: 0o755 });
  chmodSync(h.p.identity, 0o755);
  await assert.rejects(pairWrite(h.p, { keys: h.keys, entries: ENTRIES, pin: h.pin, certBytes: h.certBytes }, { rootUid: UID }), (e) => e.code === "bad_form");
  assert.equal(existsSync(join(h.p.identity, "pin")), false);
});

test("chain file names are canonical safe integers only", async () => {
  for (const bad of ["9007199254740993", "00", "01", "-1", "1e3"]) {
    const h = await host("cert");
    writeFileSync(join(h.p.identity, "chain", bad), "x", { mode: 0o600 });
    assert.equal((await classify(h.p, opts())).state, "BROKEN", bad);
  }
});

test("first boot discards identity files left behind (keys gone, a pin and a certificate still there)", async () => {
  const h = await host("cert");
  for (const f of ["sign", "enc", "first-boot"]) unlinkSync(join(h.p.keys, f));
  assert.equal((await classify(h.p, opts())).state, "NO_KEYS");
  firstBoot(h.p, { machineId: machineA, brokerUid: UID });
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
  await assert.rejects(pairWrite(h.p, { keys: h.keys, entries: ENTRIES, pin: h.pin, certBytes: other.certBytes }, { rootUid: UID }));
  assert.equal(existsSync(join(h.p.identity, "pin")), false);
  assert.equal((await classify(h.p, opts())).state, "FRESH");
  // A pin that isn't the head: refused, above it and below it.
  await assert.rejects(pairWrite(h.p, { keys: h.keys, entries: ENTRIES.slice(0, 4), pin: h.pin, certBytes: h.certBytes }, { rootUid: UID }));
  const below = await replayChain(ENTRIES.slice(0, 4), { aud: AUD, fleet: FLEET });
  await assert.rejects(pairWrite(h.p, { keys: h.keys, entries: ENTRIES, pin: { ...h.pin, seq: below.seq, hash: below.head }, certBytes: h.certBytes }, { rootUid: UID }));
  assert.equal(existsSync(join(h.p.identity, "pin")), false);
  // The real one.
  const cert = await pairWrite(h.p, { keys: h.keys, entries: ENTRIES, pin: h.pin, certBytes: h.certBytes }, { rootUid: UID });
  assert.equal(cert.body.host, HOST);
  assert.equal((await classify(h.p, opts())).state, "PAIRED");
  // A restarted pairing from PAIRING rewrites its entries and completes.
  const g = await host("pin");
  await pairWrite(g.p, { keys: g.keys, entries: ENTRIES, pin: g.pin, certBytes: g.certBytes }, { rootUid: UID });
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
  const r = await resetIdentity(h.p, s, { barrier, ...R });
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
  await assert.rejects(resetIdentity(h.p, sysFake({ broker: false }), R), (e) => e.code === "not_empty");
  assert.equal(existsSync(h.p.resetPending), false);
  assert.equal((await classify(h.p, opts())).state, "PAIRED", "before the record: the old identity, unchanged");
  await assert.rejects(resetIdentity(h.p, sysFake({ agents: false }), R), (e) => e.code === "not_empty");
  assert.equal(existsSync(h.p.resetPending), true);
  assert.equal(existsSync(join(h.p.keys, "sign")), true, "nothing deleted");
  assert.equal((await classify(h.p, opts())).state, "RESETTING", "and the next start completes it, never PAIRED again");
  await completeReset(h.p, sysFake(), R);
  assert.equal((await classify(h.p, opts())).state, "NO_KEYS");
});

test("a crash at each step after the record: the next start is RESETTING and completes; before it: unchanged and PAIRED", async () => {
  for (const at of ["after_broker", "after_record", "after_contain", "after_key_sign", "after_key_enc", "after_marker", "after_identity"]) {
    const h = await host("cert");
    await assert.rejects(resetIdentity(h.p, sysFake(), { ...R, barrier: async (n) => { if (n === at) throw new Error("crash"); } }), /crash/);
    const r = await classify(h.p, opts());
    if (at === "after_broker") {
      assert.equal(r.state, "PAIRED", "before the record: nothing changed");
      continue;
    }
    assert.equal(r.state, "RESETTING", at);
    await completeReset(h.p, sysFake(), R);
    assert.equal((await classify(h.p, opts())).state, "NO_KEYS", at);
    // NO KEYS's first boot gives NEW keys.
    firstBoot(h.p, { machineId: machineA, brokerUid: UID });
    assert.notDeepEqual((await classify(h.p, opts())).keys.sign.raw, h.keys.sign.raw, at);
  }
});
