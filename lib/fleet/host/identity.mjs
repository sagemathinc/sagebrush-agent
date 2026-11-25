// Host supervisor (design: agent-autonomous-host-daemon r2.5, §2, §3): the host's identity on disk. Its owner, its
// state, first boot, pairing's writes and the reset. No daemon here: `host run` (and `reset-identity`) call these.
//
// Files (§2), root-relative so a test can use a temporary root:
//   /var/lib/sagebrush/host.lock                the ownership lock (§3.0): a kernel flock held for the owner's life
//   /var/lib/sagebrush/reset-pending            a reset's durable intent (§3.3)
//   /var/lib/sagebrush-broker/keys/{sign,enc}   the private keys (sb-broker, 0600; dir 0700), raw 32 bytes each
//   /var/lib/sagebrush-broker/keys/first-boot   the marker: the machine id's sha256 and both public keys
//   /var/lib/sagebrush/identity/chain/<seq>     the pinned chain's entries (root 0600; dir 0700)
//   /var/lib/sagebrush/identity/pin             { fleet, aud, seq, hash } (core's pin shape: replay needs the audience)
//   /var/lib/sagebrush/identity/host-cert       the sb.host-cert.v1 envelope bytes
//   /var/lib/sagebrush/identity/revoked         the revoked marker (§6.2)
// Every write: temp, fsync, rename, directory fsync. Every read: the hardened regular-file read (no link, no FIFO, the
// same object as looked at, a size bound).
//
// The states (§3.1), read under the lock in this order: first the identity directory's separation from every restore
// root and from any link (§2; failing it is BROKEN, whatever else is there, so nothing is ever deleted inside a restore
// tree), then reset-pending (present: RESETTING), the keys and marker, then the identity files. Exactly one results; anything else is BROKEN. Only PAIRED has authority.

import { createHash, randomBytes } from "node:crypto";
import * as fs from "node:fs";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { FleetError, b64, isId, refuse } from "../bytes.mjs";
import { keyFromSeed, replayChain, verifyHostCert } from "../index.mjs";
import { nodeSync } from "../node-crypto.mjs";
import { BACKUP_DIR, RESTORE_DIR, RESTORE_STAGING, SRV, VALIDATE_DIR } from "./names.mjs";
import { exactKeys, lockFile, realIo, writeDurable } from "./store.mjs";

export const STATES = Object.freeze(["RESETTING", "CLONE", "NO_KEYS", "FRESH", "PAIRING", "PAIRED", "REVOKED", "BROKEN"]);
const MAX_KEY = 32, MAX_MARKER = 512, MAX_PIN = 512, MAX_CERT = 16384, MAX_ENTRY = 65536;

/**
 * The paths under `root` ("" on a host). `restoreRoots`: every root a backup or a restore writes, from names.mjs (the
 * backup and restore records, the validation copies, the staging root, and the agent homes' parent), so a move of any
 * of them moves the check with it. `top`: where the parent check (checkParents) stops: "/" on a host.
 */
export function hostPaths(root = "") {
  const at = (p) => `${root}${p}`;
  return Object.freeze({
    lock: at("/var/lib/sagebrush/host.lock"),
    resetPending: at("/var/lib/sagebrush/reset-pending"),
    keys: at("/var/lib/sagebrush-broker/keys"),
    identity: at("/var/lib/sagebrush/identity"),
    top: root ? resolve(root) : "/",
    restoreRoots: Object.freeze([BACKUP_DIR, RESTORE_DIR, VALIDATE_DIR, RESTORE_STAGING, SRV].map(at)),
  });
}

const broken = (why) => { throw Object.assign(new FleetError("bad_form", `identity: ${why}`), { identity: "BROKEN" }); };

// ---- §3.0 the owner

/**
 * Take the ownership lock, non-blocking, before ANYTHING of the identity or the config is read. Resolves to the lock
 * ({ release, held }); refuses `in_progress` (the daemon reports it as the registered reason `busy`) while another
 * process (a daemon, a reset, an image-prepare) holds it, having read, written and stopped nothing.
 */
export async function takeOwnership(paths, { lock = lockFile, fsx = fs, rootUid = 0 } = {}) {
  checkParents(paths, { fsx, rootUid }); // a parent only root can write: nobody else can unlink or replace the lock
  // The lock file itself: created 0600 (whatever the umask), or an existing one that is a root-owned 0600 plain file;
  // a link, another type or another owner or mode refuses (bad_form), having read nothing of the identity.
  const { O_RDWR, O_CREAT, O_EXCL } = fs.constants;
  let fd, created = false;
  try { fd = fsx.openSync(paths.lock, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600); created = true; } catch (e) {
    if (e?.code !== "EEXIST") throw e;
    try { fd = fsx.openSync(paths.lock, O_RDWR | O_NOFOLLOW | O_NONBLOCK); } catch { refuse("bad_form", "identity: the lock path isn't a plain file"); }
  }
  try {
    if (created) fsx.fchmodSync(fd, 0o600); // exactly 0600, whatever the umask
    const st = fsx.fstatSync(fd);
    if (!st.isFile() || st.uid !== rootUid || (st.mode & 0o777) !== 0o600) refuse("bad_form", "identity: the lock isn't a root-owned 0600 file");
  } finally { fsx.closeSync(fd); }
  try { return await lock(paths.lock, { waitMs: 0 }); } catch (e) {
    if (e?.code === "in_progress") throw Object.assign(new FleetError("in_progress", "identity: another owner holds the host"), { busy: true });
    throw e;
  }
}

// ---- reading

const exists = (path, fsx) => { try { fsx.lstatSync(path); return true; } catch (e) { if (e?.code === "ENOENT") return false; throw e; } };
const { O_RDONLY, O_NOFOLLOW, O_NONBLOCK, O_DIRECTORY } = fs.constants;

/**
 * A file of the right owner and mode in a directory of the right owner and mode, read by ONE descriptor: lstat (absent:
 * null), then an open that never follows a link or blocks, then fstat of that descriptor, which must be the same object
 * (dev, ino), a regular file, owned by `uid`, mode exactly 0600, at most `max` bytes; the bytes are read from it. The
 * directory is checked the same way, by its own descriptor: `dir` "private" (0700, owned by `uid`) or "root" (owned by
 * `uid`, no group or other write). Anything else is BROKEN.
 */
function readOwned(path, max, { uid, fsx, dir = "private" }) {
  const name = path.split("/").pop();
  let before;
  try { before = fsx.lstatSync(path); } catch (e) { if (e?.code === "ENOENT") return null; throw e; }
  if (!before.isFile()) broken(`${name} isn't a plain file`);
  checkDir(dirname(path), uid, dir, fsx);
  let fd;
  try { fd = fsx.openSync(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK); } catch (e) {
    if (["ENOENT", "ELOOP", "ENXIO", "EISDIR", "ENODEV"].includes(e?.code)) broken(`${name} changed while opened`);
    throw e;
  }
  try {
    const st = fsx.fstatSync(fd);
    if (!st.isFile() || st.dev !== before.dev || st.ino !== before.ino) broken(`${name} isn't the file that was looked at`);
    if (st.uid !== uid || (st.mode & 0o777) !== 0o600) broken(`${name}: not a ${uid}-owned 0600 file`);
    if (st.size > max) broken(`${name} is longer than it can be`);
    const buf = Buffer.alloc(st.size);
    for (let off = 0; off < buf.length;) {
      const k = fsx.readSync(fd, buf, off, buf.length - off, off);
      if (k <= 0) broken(`${name} changed while read`);
      off += k;
    }
    return buf;
  } finally { fsx.closeSync(fd); }
}

/** A directory checked by its own descriptor (never through a link): owner `uid`, and "private" 0700 or "root" no g/o write. */
function checkDir(dir, uid, kind, fsx) {
  let fd;
  try { fd = fsx.openSync(dir, O_RDONLY | O_NOFOLLOW | O_DIRECTORY); } catch { broken(`${dir} isn't a plain directory`); }
  try {
    const d = fsx.fstatSync(fd);
    const ok = d.isDirectory() && d.uid === uid && (kind === "private" ? (d.mode & 0o777) === 0o700 : (d.mode & 0o022) === 0);
    if (!ok) broken(`${dir}: not a ${uid}-owned ${kind === "private" ? "0700" : "non-writable"} directory`);
  } finally { fsx.closeSync(fd); }
}

/**
 * A directory the identity writes into: every existing component on its path checked against links; if it exists, it
 * must already be a `uid`-owned 0700 directory (an unsafe one is never inherited); if not, it is made 0700 exactly (a
 * umask can't widen or narrow it) and given to `uid` (`chown`), then checked the same way.
 */
function ensureDir(dir, uid, { fsx, chown }) {
  canonical(dir, fsx, true);
  if (!exists(dir, fsx)) {
    fsx.mkdirSync(dirname(dir), { recursive: true, mode: 0o755 });
    fsx.mkdirSync(dir, { mode: 0o700 });
    fsx.chmodSync(dir, 0o700);
    chown(dir);
  }
  checkDir(dir, uid, "private", fsx);
}

/** A one-line record ("1\n"), owned and read by descriptor; null if absent; anything else is BROKEN. */
function readRecordFile(path, opts) {
  const b = readOwned(path, 16, opts);
  if (b === null) return null;
  if (String(b) !== "1\n") broken(`${path.split("/").pop()} isn't a record`);
  return true;
}

/**
 * The canonical path of `p`, which may not exist yet: the nearest EXISTING ancestor resolved through realpath, then the
 * missing tail appended. `strict`: refuse (BROKEN) if any existing component on the way is a link.
 */
function canonical(p, fsx, strict) {
  let base = resolve(p), tail = "";
  for (;;) {
    try { fsx.lstatSync(base); break; } catch (e) { if (e?.code !== "ENOENT") throw e; }
    tail = tail ? join(base.split(sep).pop(), tail) : base.split(sep).pop();
    base = dirname(base);
  }
  const real = fsx.realpathSync(base);
  if (strict && real !== base) broken(`${p} is reached through a link`);
  return tail ? join(real, tail) : real;
}

/** Is `x` inside `y` (or the same path)? Exactly: the relative path is not "..", doesn't start with "../" and isn't absolute. */
const inside = (x, y) => { const r = relative(y, x); return !(r === ".." || r.startsWith(`..${sep}`) || isAbsolute(r)); };

/** Is the identity directory `a` inside the root `b`, or `b` inside `a`? `a` must be reached through no link at all. */
function overlaps(a, b, fsx) {
  const ra = canonical(a, fsx, true), rb = canonical(b, fsx, false);
  return inside(ra, rb) || inside(rb, ra);
}

const markerOf = (machineId, signPub, encPub) => JSON.stringify({ v: 1, machine: createHash("sha256").update(machineId).digest("base64url"), sign: b64(signPub), enc: b64(encPub) });

/**
 * The identity state (§3.1), read once, under the lock. `machineId()`: /etc/machine-id's text; `brokerUid`, `rootUid`:
 * the owners the files must have; `aud`: the audience a certificate is verified under. Resolves to
 * { state, ... } with, for PAIRED: { keys: { sign, enc } (keyFromSeed's sign, the x25519 pair), pin, chain (the replayed
 * state), cert (verifyHostCert's result), orphans: [seq, ...] }; for PAIRING: { pin, chain, orphans }. BROKEN carries
 * `why`. Never writes.
 */
export async function classify(paths, { machineId, brokerUid = 0, rootUid = 0, fsx = fs } = {}) {
  try {
    // FIRST, before even the reset record: a parent of the lock or the record that isn't root's alone, or an identity
    // directory that overlaps a restore tree or is reached through a link, is BROKEN, so neither a reset's deletion nor a
    // first boot's discard ever runs inside such a tree.
    checkLayout(paths, { fsx, rootUid });
    if (readRecordFile(paths.resetPending, { uid: rootUid, fsx, dir: "root" })) return { state: "RESETTING" };
    const kSign = readOwned(join(paths.keys, "sign"), MAX_KEY, { uid: brokerUid, fsx });
    const kEnc = readOwned(join(paths.keys, "enc"), MAX_KEY, { uid: brokerUid, fsx });
    const marker = readOwned(join(paths.keys, "first-boot"), MAX_MARKER, { uid: brokerUid, fsx });
    if (kSign === null && kEnc === null && marker === null) return { state: "NO_KEYS" };
    if (kSign === null || kEnc === null || marker === null) broken("a key or the marker alone is missing");
    if (kSign.length !== 32 || kEnc.length !== 32) broken("a key isn't 32 bytes");
    const sign = keyFromSeed(new Uint8Array(kSign));
    const enc = nodeSync.x25519FromPrivate(new Uint8Array(kEnc));
    let m;
    try { m = JSON.parse(String(marker)); } catch { broken("the marker isn't JSON"); }
    if (!exactKeys(m, ["v", "machine", "sign", "enc"])) broken("the marker isn't { v, machine, sign, enc }");
    const want = JSON.parse(markerOf(machineId(), sign.raw, enc.raw));
    if (m?.machine !== want.machine) return { state: "CLONE" };
    if (m.v !== 1 || m.sign !== want.sign || m.enc !== want.enc) broken("the marker doesn't name these keys");
    const keys = { sign, enc };

    if (exists(paths.identity, fsx) && readRecordFile(join(paths.identity, "revoked"), { uid: rootUid, fsx })) return { state: "REVOKED", keys };
    const pinBytes = exists(paths.identity, fsx) ? readOwned(join(paths.identity, "pin"), MAX_PIN, { uid: rootUid, fsx }) : null;
    const certBytes = exists(paths.identity, fsx) ? readOwned(join(paths.identity, "host-cert"), MAX_CERT, { uid: rootUid, fsx }) : null;
    if (pinBytes === null) {
      if (certBytes !== null) broken("a certificate without a pin");
      return { state: "FRESH", keys };
    }
    let pin;
    try { pin = JSON.parse(String(pinBytes)); } catch { broken("the pin isn't JSON"); }
    if (!pin || !isId(pin.fleet) || typeof pin.aud !== "string" || !Number.isSafeInteger(pin.seq) || pin.seq < 0 || typeof pin.hash !== "string") broken("the pin isn't { fleet, aud, seq, hash }");
    // The chain: exactly seqs 0..pin.seq, each a plain file; anything above the pin is an orphan, never read as authority.
    const dir = join(paths.identity, "chain");
    const names = exists(dir, fsx) ? fsx.readdirSync(dir) : [];
    const orphans = [];
    for (const n of names) {
      if (!/^(0|[1-9][0-9]{0,15})$/.test(n) || !Number.isSafeInteger(Number(n))) broken(`a stray chain file ${n}`);
      if (Number(n) > pin.seq) orphans.push(Number(n));
    }
    const entries = [];
    for (let s = 0; s <= pin.seq; s++) {
      const e = readOwned(join(dir, String(s)), MAX_ENTRY, { uid: rootUid, fsx });
      if (e === null) broken(`chain entry ${s} is missing`);
      entries.push(new Uint8Array(e));
    }
    let chain;
    try { chain = await replayChain(entries, { aud: pin.aud, fleet: pin.fleet }, pin); } catch { broken("the chain doesn't replay to the pin"); }
    if (chain.seq !== pin.seq) broken("the chain doesn't end at the pin");
    orphans.sort((a, b) => a - b);
    if (certBytes === null) return { state: "PAIRING", keys, pin, chain, orphans };
    const cert = await certFor(certBytes, keys, pin, chain).catch(() => null);
    if (cert === null) broken("the certificate doesn't verify against the pin, or isn't these keys'");
    return { state: "PAIRED", keys, pin, chain, cert, orphans };
  } catch (e) {
    if (e?.identity === "BROKEN") return { state: "BROKEN", why: e.message };
    throw e;
  }
}

/**
 * The layout every identity path depends on (§2, §3.1's precondition): the parents of the lock and the reset record
 * root's alone (checkParents), the identity directory apart from every backup/restore root and reached through no link,
 * and no linked ancestor of the keys or the reset record's directory. classify, resetIdentity and completeReset each run
 * it FIRST. Throws (BROKEN, bad_form) otherwise.
 */
export function checkLayout(paths, { fsx = fs, rootUid = 0 } = {}) {
  checkParents(paths, { fsx, rootUid });
  for (const r of paths.restoreRoots) if (overlaps(paths.identity, r, fsx)) broken(`the identity directory overlaps ${r}`);
  for (const p of [paths.keys, dirname(paths.resetPending)]) canonical(p, fsx, true);
}

/**
 * The lock's and the reset record's directory, and every ancestor up to `paths.top`, each opened by its own descriptor
 * (never through a link) and fstat'd: a directory owned by `rootUid` with no group or other write, so only root can
 * unlink or rename the lock or the record (root is trusted already). A missing one refuses and is never created.
 * Throws (BROKEN, bad_form) otherwise. takeOwnership runs it before the lock; checkLayout before anything else.
 */
export function checkParents(paths, { fsx = fs, rootUid = 0 } = {}) {
  const top = resolve(paths.top ?? "/");
  for (const parent of new Set([dirname(paths.lock), dirname(paths.resetPending)])) {
    for (let d = resolve(parent); ; d = dirname(d)) {
      checkDir(d, rootUid, "root", fsx);
      if (d === top || d === dirname(d)) break;
    }
  }
}

/** A certificate valid against `chain` that names exactly these two public keys (throws otherwise). */
export async function verifyCertFor(certBytes, keys, pin, chain) { return certFor(certBytes, keys, pin, chain); }

/** A certificate valid against `chain` that names exactly these two public keys. */
async function certFor(certBytes, keys, pin, chain) {
  const cert = await verifyHostCert(new Uint8Array(certBytes), { aud: pin.aud, fleet: pin.fleet, chain });
  const same = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
  if (!same(cert.signRaw, keys.sign.raw) || !same(cert.encRaw, keys.enc.raw)) throw new Error("not these keys");
  return cert;
}

// ---- first boot (§3.1 NO KEYS)

/**
 * Generate both pairs independently from the OS (getrandom), write them and the marker (broker-owned 0600, dir 0700),
 * then discard any identity files left behind. Only under the lock, in NO_KEYS, after the containment (§3.1).
 * `chown(path)` gives a file to the broker's user (a test seam).
 */
export function firstBoot(paths, { machineId, brokerUid = 0, random = randomBytes, chown = () => {}, io = realIo, fsx = fs } = {}) {
  ensureDir(paths.keys, brokerUid, { fsx, chown });
  const seed = new Uint8Array(random(32)), sk = new Uint8Array(random(32));
  const sign = keyFromSeed(seed), enc = nodeSync.x25519FromPrivate(sk);
  writeDurable(paths.keys, "sign", Buffer.from(seed), io, 0o600); chown(join(paths.keys, "sign"));
  writeDurable(paths.keys, "enc", Buffer.from(sk), io, 0o600); chown(join(paths.keys, "enc"));
  writeDurable(paths.keys, "first-boot", markerOf(machineId(), sign.raw, enc.raw), io, 0o600); chown(join(paths.keys, "first-boot"));
  removeIdentity(paths, { fsx, io });
}

/**
 * Delete every identity file (chain, pin, cert, revoked), the directory fsync'd; the directory itself stays. Never
 * follows a link: a link in place of the identity or chain directory is itself removed, its target never walked.
 */
function removeIdentity(paths, { fsx, io }) {
  if (!dropIfLink(paths.identity, fsx)) return;
  const dir = join(paths.identity, "chain");
  if (dropIfLink(dir, fsx)) { for (const n of fsx.readdirSync(dir)) fsx.unlinkSync(join(dir, n)); syncDir(dir, io); fsx.rmdirSync(dir); }
  for (const f of ["host-cert", "pin", "revoked"]) { try { fsx.unlinkSync(join(paths.identity, f)); } catch (e) { if (e?.code !== "ENOENT") throw e; } }
  syncDir(paths.identity, io);
}

/**
 * For a directory the reset empties: true if `dir` is a real directory to walk; false if it doesn't exist, or was a link
 * or another file, which is removed itself (its target untouched).
 */
function dropIfLink(dir, fsx) {
  let st;
  try { st = fsx.lstatSync(dir); } catch (e) { if (e?.code === "ENOENT") return false; throw e; }
  if (st.isDirectory()) return true;
  fsx.unlinkSync(dir);
  return false;
}

function syncDir(dir, io) { const fd = io.open(dir, "r"); try { io.fsync(fd); } finally { io.close(fd); } }

/** Delete the chain entries above the pin (orphans of an adoption that crashed before its pin, §3.1). PAIRED start only. */
export function dropOrphans(paths, orphans, { fsx = fs, io = realIo } = {}) {
  if (orphans.length === 0) return;
  const dir = join(paths.identity, "chain");
  for (const s of orphans) { try { fsx.unlinkSync(join(dir, String(s))); } catch (e) { if (e?.code !== "ENOENT") throw e; } }
  syncDir(dir, io);
}

// ---- pairing's writes (§3.2)

/**
 * Pairing, in order: (1) the chain entries, verified from the first; (2) the pin; (3) the certificate, verified
 * against that pin and naming this host's two public keys. FRESH or PAIRING only, under the lock. `entries`: the chain's
 * entry bytes from genesis; `pin`: { fleet, aud, seq, hash } (the head they replay to). Resolves to the cert.
 */
export async function pairWrite(paths, { keys, entries, pin, certBytes }, { rootUid = 0, chown = () => {}, io = realIo, fsx = fs } = {}) {
  const chain = await replayChain(entries, { aud: pin.aud, fleet: pin.fleet }, pin);
  if (chain.seq !== pin.seq) refuse("bad_form", "identity: the pin isn't the chain's head");
  const cert = await certFor(certBytes, keys, pin, chain); // before anything is written: a wrong certificate writes nothing
  ensureDir(paths.identity, rootUid, { fsx, chown });
  removeIdentity(paths, { fsx, io }); // a restarted pairing rewrites its entries
  const dir = join(paths.identity, "chain");
  ensureDir(dir, rootUid, { fsx, chown });
  entries.forEach((e, s) => writeDurable(dir, String(s), Buffer.from(e), io, 0o600));
  writeDurable(paths.identity, "pin", JSON.stringify({ fleet: pin.fleet, aud: pin.aud, seq: pin.seq, hash: pin.hash }), io, 0o600);
  writeDurable(paths.identity, "host-cert", Buffer.from(certBytes), io, 0o600);
  return cert;
}

// ---- a chain adoption's writes (§6.2)

/**
 * Write the adopted entries (seqs fromSeq, fromSeq+1, ...), each before the pin that names them, then the pin, all
 * durable. Entries above the old pin left by a crash before the pin are orphans (§3.1): replay never reads them.
 */
export function adoptWrite(paths, entries, fromSeq, pin, { io = realIo, fsx = fs, rootUid = 0, chown = () => {} } = {}) {
  if (!Number.isSafeInteger(fromSeq) || fromSeq < 1 || entries.length === 0 || fromSeq + entries.length - 1 !== pin.seq) refuse("bad_form", "identity: an adoption's entries and pin disagree");
  const dir = join(paths.identity, "chain");
  ensureDir(dir, rootUid, { fsx, chown });
  entries.forEach((e, i) => writeDurable(dir, String(fromSeq + i), Buffer.from(e), io, 0o600));
  writeDurable(paths.identity, "pin", JSON.stringify({ fleet: pin.fleet, aud: pin.aud, seq: pin.seq, hash: pin.hash }), io, 0o600);
}

/** The revoked marker (§6.2 step 1), durable: from here the host is REVOKED at every start until a reset. */
export function markRevoked(paths, { io = realIo } = {}) {
  writeDurable(paths.identity, "revoked", "1\n", io, 0o600);
}

// ---- the containment every non-PAIRED state runs first (§3.1), and the reset (§3.3)

/**
 * §3.1's stop: raise `all` durably and stop and prove every agent slice; stop and runtime-mask the broker's units and
 * prove every key holder gone. `sys`: { stopAll() → { proven }, stopBroker() → { proven } } (the executor's stop-all
 * primitive and the broker units' stop; injected). Throws `not_empty` unless BOTH are proven.
 */
export async function contain(sys) {
  const agents = await sys.stopAll();
  const broker = await sys.stopBroker();
  if (!agents?.proven || !broker?.proven) throw unproven("the containment couldn't be proven");
}

/** A stop that couldn't be proven (not a protocol refusal: the same code as the executor's own unproven stops). */
const unproven = (what) => Object.assign(new Error(`identity: ${what}`), { code: "not_empty" });

/**
 * `reset-identity` (§3.3), under the lock the caller took: (2) the broker stopped, masked and every key holder proven
 * gone, else nothing recorded; (3) reset-pending, durable: from here irrevocable; (4) `all` and every slice stopped and
 * proven, else nothing deleted; (5) the private keys FIRST; (6) the marker, then the identity files; (7) reset-pending
 * last. `completeReset` runs (4)–(7) for a RESETTING start (and the reset itself after (3)). `barrier(name)`: a test hook.
 */
export async function resetIdentity(paths, sys, { io = realIo, fsx = fs, rootUid = 0, barrier = async () => {} } = {}) {
  checkLayout(paths, { fsx, rootUid }); // before the broker's stop or any record: a linked or misplaced layout changes nothing
  const broker = await sys.stopBroker();
  if (!broker?.proven) throw unproven("a key holder survived; nothing recorded");
  await barrier("after_broker");
  writeDurable(dirname(paths.resetPending), "reset-pending", "1\n", io, 0o600);
  await barrier("after_record");
  return completeReset(paths, sys, { io, fsx, rootUid, barrier });
}

/** Steps (4)–(7): the containment, the keys first, the rest, then the record. A failed proof deletes nothing. */
export async function completeReset(paths, sys, { io = realIo, fsx = fs, rootUid = 0, barrier = async () => {} } = {}) {
  checkLayout(paths, { fsx, rootUid }); // callable on its own: never deletes through a linked or misplaced layout
  await contain(sys); // (4), with the broker again: a RESETTING start must prove it too
  await barrier("after_contain");
  const keysDir = dropIfLink(paths.keys, fsx); // a link in place of the keys directory: removed itself, never walked
  for (const k of keysDir ? ["sign", "enc"] : []) {
    try { fsx.unlinkSync(join(paths.keys, k)); } catch (e) { if (e?.code !== "ENOENT") throw e; }
    if (exists(paths.keys, fsx)) syncDir(paths.keys, io);
    await barrier(`after_key_${k}`);
  }
  if (keysDir) {
    try { fsx.unlinkSync(join(paths.keys, "first-boot")); } catch (e) { if (e?.code !== "ENOENT") throw e; }
    syncDir(paths.keys, io);
  }
  await barrier("after_marker");
  removeIdentity(paths, { fsx, io });
  await barrier("after_identity");
  fsx.unlinkSync(paths.resetPending);
  syncDir(dirname(paths.resetPending), io);
  return { state: "NO_KEYS" };
}
