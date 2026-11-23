// Deprovision design r3.2 §2, §3 (and amendment L1): the durable progress record. It is bound to the agent's life,
// generation and uid; only a valid prefix of the fixed step order is valid; steps are marked in order; identities are
// the launcher's closed outputs, recorded once and rebound only to the same durable object; `done` exactly when every
// step is done; and a deleted agent with no record gets one (no hole between `deleted` and the record).
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "./host-linux-only.mjs";
import { FleetError, newId } from "../lib/fleet/index.mjs";
import { HostStore } from "../lib/fleet/host/host-store.mjs";
import { STEPS, bindingMatches, checkRecords, sameDurable } from "../lib/fleet/host/deprovision-record.mjs";

const refused = (fn, code = "bad_form") => assert.throws(fn, (e) => e instanceof FleetError && e.code === code, code);
const fresh = () => join(mkdtempSync(join(tmpdir(), "sb-deprov-")), "state");
const disk = (root) => JSON.parse(readFileSync(join(root, "deprovision", "deprovision.json"), "utf8"));
const open = async (root) => { const h = await HostStore.open(root); const d = h.deprovision; d.close = () => h.close(); return d; };
const UID = 70001;
const reg = (o = {}) => ({ uid: UID, state: "deleted", life: 3, gen: 2, tags: [], start_failed: null, ...o });
const BOOT = "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0";
const obj = (o = {}) => ({ type: "dir", mode: 0o700, uid: UID, gid: UID, dev: [8, 1], ino: 12, gen: 7, mnt_id: 30, projid: UID, inherit: true, ...o });
const tree = (o = {}) => ({ epoch: { boot_id: BOOT, mnt_id: 30 }, fsid: "0000abcd00001234", dir: obj({ uid: 0, gid: 0, mode: 0o755, projid: 0, inherit: false }), entries: { home: obj(), "var-tmp": obj({ ino: 13 }), sessions: obj({ ino: 14 }) }, ...o });
const ident = (o = {}) => ({ epoch: { boot_id: BOOT, mnt_id: 22 }, fsid: "0000000000000001", object: obj({ type: "file", mode: 0o644, uid: 0, gid: 0, projid: 0, inherit: false }), ...o });

test("a deleted agent gets a record bound to its life, generation and uid; it is durable and reloads", async () => {
  const root = fresh();
  const d = await open(root);
  const A = newId();
  assert.deepEqual(d.ensure(A, reg()), { life: 3, gen: 2, uid: UID, gid: UID, policy: "archive", steps_done: [], identities: {}, done: false });
  assert.equal(disk(root).agents[A].life, 3);
  assert.deepEqual(d.pending(), [A]);
  // Ensure again is the same record; a registry record of another life, generation or uid is refused, not repaired.
  assert.equal(d.ensure(A, reg()).life, 3);
  for (const other of [reg({ life: 4 }), reg({ gen: 3 }), reg({ uid: UID + 1 })]) refused(() => d.ensure(A, other));
  refused(() => d.ensure(newId(), reg({ state: "stopped" })), "not_granted"); // only a deleted agent
  await d.close();
  const again = await open(root);
  assert.equal(again.record(A).uid, UID);
  await again.close();
});

test("steps are marked only in order; done exactly when all are; nothing after done", async () => {
  const d = await open(fresh());
  const A = newId();
  d.ensure(A, reg());
  refused(() => d.markStep(A, "unit")); // not the next step
  for (const [i, s] of STEPS.entries()) {
    refused(() => d.markStep(A, STEPS[i + 1] ?? "channels")); // never out of order
    const r = d.markStep(A, s);
    assert.equal(r.done, i === STEPS.length - 1);
  }
  refused(() => d.markStep(A, "channels"), "not_granted");
  assert.deepEqual(d.pending(), []);
  refused(() => d.markStep(newId(), "channels"), "not_granted");
  await d.close();
});

test("identities: the launcher's closed shapes, recorded once, rebound only to the same durable object", async () => {
  const d = await open(fresh());
  const A = newId();
  d.ensure(A, reg());
  d.recordIdentity(A, "home", tree());
  d.recordIdentity(A, "home", tree()); // the same value again is fine (a redone verify)
  refused(() => d.recordIdentity(A, "home", tree({ fsid: "0000abcd00009999" })));
  d.recordIdentity(A, "contract", ident());
  refused(() => d.recordIdentity(A, "passwd", ident())); // an unknown key
  refused(() => d.recordIdentity(A, "config", { ...tree(), extra: 1 })); // not the closed shape
  // Requalification after a reboot: the live fields change (another mnt_id and dev), the durable ones don't.
  const rebooted = tree({ epoch: { boot_id: "11111111-2222-3333-4444-555555555555", mnt_id: 31 }, dir: { ...tree().dir, mnt_id: 31, dev: [8, 2] } });
  d.rebindIdentity(A, "home", rebooted);
  assert.equal(d.record(A).identities.home.epoch.mnt_id, 31);
  // A same-shaped substitute (another ino, or the same ino with another generation) is never rebound.
  for (const sub of [tree({ entries: { ...tree().entries, home: obj({ ino: 99 }) } }), tree({ entries: { ...tree().entries, home: obj({ gen: 8 }) } }), tree({ fsid: "0000abcd00009999" })]) {
    refused(() => d.rebindIdentity(A, "home", sub));
  }
  refused(() => d.rebindIdentity(A, "config", tree()), "not_granted"); // nothing recorded under that key
  await d.close();
});

test("sameDurable compares fsid, ino, generation, owners, modes and project ids, not the live dev and mnt_id", () => {
  assert.ok(sameDurable(tree(), tree({ epoch: { boot_id: BOOT, mnt_id: 99 }, dir: { ...tree().dir, mnt_id: 99, dev: [9, 9] } })));
  for (const f of ["ino", "gen", "uid", "gid", "mode", "projid", "inherit", "type"]) {
    const v = { ino: 5, gen: 1, uid: 1, gid: 1, mode: 0o755, projid: 1, inherit: false, type: "file" }[f];
    assert.ok(!sameDurable(tree(), tree({ entries: { ...tree().entries, sessions: obj({ ino: 14, [f]: v }) } })), f);
  }
  assert.ok(!sameDurable(tree(), tree({ entries: { home: obj(), "var-tmp": obj({ ino: 13 }) } })), "an entry missing");
  assert.ok(sameDurable(ident(), ident({ object: { ...ident().object, mnt_id: 1 } })));
});

test("bindingMatches: the same life, generation and uid", () => {
  const rec = { life: 3, gen: 2, uid: UID, gid: UID };
  assert.ok(bindingMatches(rec, reg()));
  for (const r of [reg({ life: 2 }), reg({ gen: 1 }), reg({ uid: 70002 }), null]) assert.ok(!bindingMatches(rec, r));
});

test("anything but the exact closed shape is refused at load", () => {
  const A = newId();
  const ok = () => ({ v: 1, agents: { [A]: { life: 3, gen: 2, uid: UID, gid: UID, policy: "archive", steps_done: ["channels", "unit"], identities: { home: tree(), contract: ident() }, done: false } } });
  assert.equal(checkRecords(ok()), true);
  const cases = {
    "another version": (s) => { s.v = 2; },
    "an extra key": (s) => { s.agents[A].x = 1; },
    "a non-prefix step list": (s) => { s.agents[A].steps_done = ["unit"]; },
    "a repeated step": (s) => { s.agents[A].steps_done = ["channels", "channels"]; },
    "done before all steps": (s) => { s.agents[A].done = true; },
    "all steps but not done": (s) => { s.agents[A].steps_done = [...STEPS]; },
    "another policy": (s) => { s.agents[A].policy = "remove"; },
    "a gid that isn't the uid": (s) => { s.agents[A].gid = UID + 1; },
    "a uid outside the range": (s) => { s.agents[A].uid = 1000; s.agents[A].gid = 1000; },
    "an unknown identity key": (s) => { s.agents[A].identities.passwd = ident(); },
    "a malformed tree": (s) => { s.agents[A].identities.home.entries.home.mode = 0o10000; },
    "a symlink with a generation": (s) => { s.agents[A].identities.contract.object = obj({ type: "symlink" }); },
    "a bad boot id": (s) => { s.agents[A].identities.home.epoch.boot_id = "x"; },
    "a bad fsid": (s) => { s.agents[A].identities.contract.fsid = "XYZ"; },
    "a bad agent id": (s) => { s.agents.nope = s.agents[A]; delete s.agents[A]; },
  };
  for (const [name, f] of Object.entries(cases)) { const s = ok(); f(s); assert.throws(() => checkRecords(s), (e) => e instanceof FleetError && e.code === "bad_form", name); }
});
