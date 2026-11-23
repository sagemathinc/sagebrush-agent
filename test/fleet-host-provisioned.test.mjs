// Deprovision design r3.2 §3.6 and amendment L1: the authoritative identity of an agent's provisioned trees. Recorded
// from the launcher's inspect-home output only when it is exactly the agent's layout; the same epoch must find it
// unchanged (a substitute refuses); another epoch requalifies only the same durable objects.
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "./host-linux-only.mjs";
import { FleetError, newId } from "../lib/fleet/index.mjs";
import { HostStore } from "../lib/fleet/host/host-store.mjs";
import { checkProvisioned } from "../lib/fleet/host/provisioned.mjs";

const refused = (fn) => assert.throws(fn, (e) => e instanceof FleetError && e.code === "bad_form");
const fresh = () => join(mkdtempSync(join(tmpdir(), "sb-provd-")), "state");
const open = async (root) => { const h = await HostStore.open(root); const p = h.provisioned; p.close = () => h.close(); return p; };
const UID = 70001, BOOT = "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0", BOOT2 = "11111111-2222-3333-4444-555555555555";
const o = (x = {}) => ({ type: "dir", mode: 0o700, uid: UID, gid: UID, dev: [8, 1], ino: 12, gen: 7, mnt_id: 30, projid: UID, inherit: true, ...x });
const head = (boot = BOOT, mnt = 30) => ({ epoch: { boot_id: boot, mnt_id: mnt }, fsid: "0000abcd00001234" });
const home = (x = {}, boot, mnt = 30) => ({ ...head(boot, mnt), dir: o({ uid: 0, gid: 0, mode: 0o755, ino: 11, projid: 0, inherit: false, mnt_id: mnt }), entries: { home: o({ mnt_id: mnt }), "var-tmp": o({ ino: 13, mnt_id: mnt }), sessions: o({ ino: 14, mnt_id: mnt }) }, ...x });
const config = (x = {}, boot, mnt = 30) => ({ ...head(boot, mnt), dir: o({ uid: 0, gid: 0, ino: 20, mnt_id: mnt }), entries: { "gen-1": o({ uid: 0, gid: 0, mode: 0o755, ino: 21, mnt_id: mnt }) }, ...x });
const unlabelled = (t) => ({ ...t, dir: t.dir, entries: Object.fromEntries(Object.entries(t.entries).map(([k, v]) => [k, { ...v, projid: 0, inherit: false }])) });

test("recorded once from exactly the agent's layout; the config tree's entries aren't part of its identity", async () => {
  const root = fresh();
  const p = await open(root);
  const A = newId();
  assert.equal(p.adopt(A, UID, true, home(), config()), "recorded");
  const r = p.record(A);
  assert.deepEqual(Object.keys(r.config).sort(), ["dir", "epoch", "fsid"]);
  // The same epoch, the same objects: unchanged, even after the config tree gained a generation.
  assert.equal(p.adopt(A, UID, true, home(), config({ entries: { "gen-1": o({ uid: 0, gid: 0, mode: 0o755, ino: 21 }), "gen-2": o({ uid: 0, gid: 0, mode: 0o755, ino: 22 }), current: o({ type: "file", uid: 0, gid: 0, mode: 0o600, ino: 23 }) } })), "unchanged");
  await p.close();
  const again = await open(root);
  assert.equal(again.record(A).uid, UID);
  await again.close();
});

test("the same epoch: any other object is a substitute and refused; nothing re-recorded", async () => {
  const p = await open(fresh());
  const A = newId();
  p.adopt(A, UID, true, home(), config());
  const before = JSON.stringify(p.record(A));
  for (const [name, h, c] of [
    ["another ino for home", home({ entries: { ...home().entries, home: o({ ino: 99 }) } }), config()],
    ["another generation (a reused inode)", home({ entries: { ...home().entries, sessions: o({ ino: 14, gen: 8 }) } }), config()],
    ["another config directory", home(), config({ dir: o({ uid: 0, gid: 0, ino: 77 }) })],
  ]) {
    refused(() => p.adopt(A, UID, true, h, c), name);
  }
  assert.equal(JSON.stringify(p.record(A)), before);
});

test("another epoch: the same durable objects requalify (live fields rebound); anything else refuses", async () => {
  const p = await open(fresh());
  const A = newId();
  p.adopt(A, UID, true, home(), config());
  // After a reboot the mount id and dev changed; fsid, ino, gen, owners, modes and projects are the same.
  const h2 = home({}, BOOT2, 41), c2 = config({}, BOOT2, 41);
  h2.dir.dev = [8, 2];
  assert.equal(p.adopt(A, UID, true, h2, c2), "requalified");
  assert.equal(p.record(A).home.epoch.boot_id, BOOT2);
  // A same-shaped substitute after another reboot (another ino, or the same ino with another generation): refused.
  for (const h of [home({ entries: { ...home({}, BOOT, 50).entries, home: o({ ino: 99, mnt_id: 50 }) } }, BOOT, 50), home({ entries: { ...home({}, BOOT, 50).entries, home: o({ gen: 9, mnt_id: 50 }) } }, BOOT, 50)]) {
    refused(() => p.adopt(A, UID, true, h, config({}, BOOT, 50)));
  }
  // Another filesystem (fsid) after a remount: refused.
  refused(() => p.adopt(A, UID, true, { ...home({}, BOOT, 60), fsid: "0000000000000009" }, { ...config({}, BOOT, 60), fsid: "0000000000000009" }));
});

test("not the agent's layout: refused before anything is recorded", async () => {
  const p = await open(fresh());
  const A = newId();
  const cases = {
    "a fourth entry": [home({ entries: { ...home().entries, extra: o({ ino: 15 }) } }), config()],
    "a missing sessions": [home({ entries: { home: o(), "var-tmp": o({ ino: 13 }) } }), config()],
    "another owner": [home({ entries: { ...home().entries, home: o({ uid: UID + 1 }) } }), config()],
    "unlabelled on a quota host": [unlabelled(home()), config()],
    "a non-root config dir": [home(), config({ dir: o({ ino: 20 }) })],
    "an entry on another mount": [home({ entries: { ...home().entries, home: o({ mnt_id: 31 }) } }), config()],
    "the trees from different epochs": [home(), config({}, BOOT2)],
    "an agent dir that isn't 0755": [home({ dir: o({ uid: 0, gid: 0, mode: 0o750, ino: 11, projid: 0, inherit: false }) }), config()],
  };
  for (const [name, [h, c]] of Object.entries(cases)) refused(() => p.adopt(A, UID, true, h, c), name);
  assert.equal(p.record(A), null);
  // A host without quotas: nothing labelled, consistently.
  const c0 = config(); c0.dir.projid = 0; c0.dir.inherit = false;
  assert.equal(p.adopt(A, UID, false, unlabelled(home()), c0), "recorded");
  refused(() => p.adopt(A, UID, true, home(), config())); // the quota setting can't change under a record
});

test("anything but the exact closed shape is refused at load", () => {
  const A = newId();
  const ok = () => ({ v: 1, agents: { [A]: { uid: UID, quota: true, home: home(), config: { ...head(), dir: o({ uid: 0, gid: 0, ino: 20 }) } } } });
  assert.equal(checkProvisioned(ok()), true);
  for (const [name, f] of Object.entries({
    "an extra key": (s) => { s.agents[A].x = 1; },
    "config with entries": (s) => { s.agents[A].config.entries = {}; },
    "a uid outside the range": (s) => { s.agents[A].uid = 1000; },
    "a layout that doesn't match": (s) => { s.agents[A].home.entries.home.projid = 0; },
    "quota not a boolean": (s) => { s.agents[A].quota = 1; },
  })) { const s = ok(); f(s); assert.throws(() => checkProvisioned(s), (e) => e instanceof FleetError, name); }
});
