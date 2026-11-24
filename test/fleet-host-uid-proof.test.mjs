// Deprovision design r3.2 §2: the whole-host uid-empty proof. Every uid slot of every process, the user manager,
// linger and logind sessions; it fails closed on anything unreadable; a process exiting mid-scan is simply gone.
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, writeFileSync, rmSync } from "node:fs";
import fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "./host-linux-only.mjs";
import { newId } from "../lib/fleet/index.mjs";
import { statusUids, uidEmpty , storageUidEmpty } from "../lib/fleet/host/uid-proof.mjs";
import { STORAGE_UID_RANGE } from "../lib/fleet/host/profiles.mjs";

const UID = 70001;
const A = newId();
const status = (r, e, s, f) => `Name:\tx\nUid:\t${r}\t${e}\t${s}\t${f}\nGid:\t0\t0\t0\t0\n`;

function host({ procs = { 1: [0, 0, 0, 0] }, mgr = "inactive", linger = false, sessions = "" } = {}) {
  const root = mkdtempSync(join(tmpdir(), "sb-uidproof-"));
  for (const [pid, u] of Object.entries(procs)) {
    mkdirSync(join(root, "proc", pid), { recursive: true });
    if (u !== null) writeFileSync(join(root, "proc", pid, "status"), status(...u));
  }
  mkdirSync(join(root, "proc", "self"), { recursive: true }); // non-numeric entries are ignored
  mkdirSync(join(root, "var/lib/systemd/linger"), { recursive: true });
  if (linger) writeFileSync(join(root, `var/lib/systemd/linger/sb-${A}`), "");
  const calls = [];
  const run = async (argv) => {
    calls.push(argv);
    if (argv[0] === "systemctl") return { code: mgr === "active" ? 0 : 3, stdout: `${mgr}\n` };
    return { code: 0, stdout: sessions };
  };
  return { root, run, calls };
}
const prove = (h, o = {}) => uidEmpty(UID, A, { root: h.root, run: h.run, ms: 1000, ...o });

test("empty: no process, manager, linger or session holds the uid", async () => {
  const h = host({ procs: { 1: [0, 0, 0, 0], 42: [1000, 1000, 1000, 1000] }, sessions: "3 1000 alice seat0 tty2\n" });
  assert.deepEqual(await prove(h), { empty: true, holders: [] });
  assert.deepEqual(h.calls, [["systemctl", "is-active", `user@${UID}.service`], ["loginctl", "list-sessions", "--no-legend", "--no-pager"]]);
});

test("the uid in ANY slot of any process holds it (real, effective, saved, filesystem)", async () => {
  for (const slot of [0, 1, 2, 3]) {
    const u = [0, 0, 0, 0];
    u[slot] = UID;
    const r = await prove(host({ procs: { 1: [0, 0, 0, 0], 77: u } }));
    assert.deepEqual(r, { empty: false, holders: ["pid 77"] }, `slot ${slot}`);
  }
});

test("a user manager in any live state, a linger file, or a logind session holds it", async () => {
  for (const mgr of ["active", "activating", "deactivating", "reloading"]) {
    assert.deepEqual((await prove(host({ mgr }))).holders, ["user-manager"], mgr);
  }
  for (const mgr of ["inactive", "failed", "unknown"]) assert.equal((await prove(host({ mgr }))).empty, true, mgr);
  assert.deepEqual((await prove(host({ linger: true }))).holders, ["linger"]);
  assert.deepEqual((await prove(host({ sessions: `5 ${UID} sb-x  pts/0\n7 1000 alice seat0 tty2\n` }))).holders, ["session 5"]);
});

test("fails closed: an unreadable status, a status without a Uid line, an unparsable session or manager state", async () => {
  // A status file that is a directory (unreadable as a file): never "empty".
  const h = host({ procs: { 1: [0, 0, 0, 0], 9: null } });
  mkdirSync(join(h.root, "proc/9/status"));
  await assert.rejects(prove(h), /status can't be read/);
  const g = host({ procs: { 1: [0, 0, 0, 0], 9: null } });
  writeFileSync(join(g.root, "proc/9/status"), "Name:\tx\n");
  await assert.rejects(prove(g), /no Uid line/);
  await assert.rejects(prove(host({ sessions: "garbage-line\n" })), /can't be parsed/);
  await assert.rejects(prove(host({ mgr: "" })), /user manager/);
  const bad = host();
  await assert.rejects(uidEmpty(UID, A, { root: bad.root, ms: 1000, run: async (argv) => (argv[0] === "loginctl" ? { code: 1, stdout: "" } : { code: 3, stdout: "inactive\n" }) }), /sessions can't be listed/);
  await assert.rejects(prove(host(), { root: "/nonexistent-root" }), /can't be listed/);
  await assert.rejects(uidEmpty(1000, A, { root: bad.root, run: bad.run, ms: 1000 }), /outside the agent range/);
});

test("a process that exits mid-scan (its status vanishes) is simply gone", async () => {
  const h = host({ procs: { 1: [0, 0, 0, 0], 9: null } }); // pid dir without a status file: ENOENT
  assert.equal((await prove(h)).empty, true);
  // And an fs whose read races to ESRCH.
  const fsx = { ...fs, readFileSync: (p, e) => { if (String(p).includes("/proc/1/")) throw Object.assign(new Error("gone"), { code: "ESRCH" }); return fs.readFileSync(p, e); } };
  assert.equal((await prove(host(), { fsx })).empty, true);
});

test("statusUids parses exactly the four uid fields", () => {
  assert.deepEqual(statusUids(status(1, 2, 3, 4)), [1, 2, 3, 4]);
  assert.equal(statusUids("Uid:\t1\t2\t3\n"), null);
  assert.equal(statusUids("Gid:\t1\t2\t3\t4\n"), null);
});

test("a storage uid (A4 §2): its processes, user manager and sessions hold it; there is no linger file to check; the range is the storage range", async () => {
  const SU = STORAGE_UID_RANGE[0] + 5;
  const sp = (h) => storageUidEmpty(SU, { root: h.root, run: h.run, ms: 1000 });
  assert.deepEqual(await sp(host()), { empty: true, holders: [] });
  assert.deepEqual((await sp(host({ procs: { 1: [0, 0, 0, 0], 77: [0, SU, 0, 0] } }))).holders, ["pid 77"]);
  assert.deepEqual((await sp(host({ mgr: "active" }))).holders, ["user-manager"]);
  assert.deepEqual((await sp(host({ sessions: `9 ${SU} x seat0 tty3\n` }))).holders, ["session 9"]);
  for (const bad of [UID, STORAGE_UID_RANGE[0] - 1, STORAGE_UID_RANGE[1] + 1, 0, "90001"]) {
    await assert.rejects(storageUidEmpty(bad, { root: host().root, run: host().run, ms: 1000 }), /storage range/);
  }
  await assert.rejects(uidEmpty(SU, A, { root: host().root, run: host().run, ms: 1000 }), /agent range/, "the agent proof refuses a storage uid");
});
