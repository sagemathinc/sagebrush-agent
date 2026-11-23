// Host harness profiles (profiles design r2.1 §4, §5, as amended by the advisor delta r3.2 §1, §3): the root-only
// profile records. States move only along the table; every change is durable before it is visible; a profile id is
// never reused; a subscription has at most one live profile on the host; storage uids and project ids are monotonic,
// never reused and never wrap; a profile belongs to the person (no owner agent).
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, statSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "./host-linux-only.mjs";
import { FleetError, newId } from "../lib/fleet/index.mjs";
import { HostStore } from "../lib/fleet/host/host-store.mjs";
import { HARNESSES, PROJECT_RANGE, STORAGE_UID_RANGE, checkProfiles } from "../lib/fleet/host/profiles.mjs";
import { GID_RANGE, UID_RANGE } from "../lib/fleet/host/registry.mjs";

const refused = (fn, code) => assert.throws(fn, (e) => e instanceof FleetError && e.code === code, code);
const fresh = () => join(mkdtempSync(join(tmpdir(), "sb-profiles-")), "state");
const disk = (root) => JSON.parse(readFileSync(join(root, "profiles", "profiles.json"), "utf8"));
const open = async (root) => { const h = await HostStore.open(root); const p = h.profiles; p.close = () => h.close(); return p; };

test("create, bind, retire: each state durable on disk before it is visible", async () => {
  const root = fresh();
  const p = await open(root);
  const pid = newId(), sub = newId();
  const first = { harness: "claude", sub, storage_uid: STORAGE_UID_RANGE[0], project_id: PROJECT_RANGE[0], gen: 1, state: "creating" };
  assert.deepEqual(p.beginCreate(pid, "claude", sub), first);
  assert.equal(disk(root).profiles[pid].state, "creating");
  assert.equal(statSync(join(root, "profiles", "profiles.json")).mode & 0o777, 0o600);
  p.markBound(pid);
  assert.deepEqual(p.profileFor(sub), { pid, ...first, state: "bound" });
  assert.equal(disk(root).profiles[pid].state, "bound");
  // Retiring advances the gen (a stale selection can't match) and is never selectable again.
  assert.equal(p.beginRetire(pid).gen, 2);
  assert.equal(disk(root).profiles[pid].state, "retiring");
  p.markRetired(pid);
  assert.equal(p.profileFor(sub), null, "a retired profile is no subscription's live profile");
  assert.equal(disk(root).profiles[pid].state, "retired");
  await p.close();
  const again = await open(root);
  assert.equal(again.profile(pid).state, "retired");
  await again.close();
});

test("only the table's moves; a creation can be abandoned to retiring", async () => {
  const p = await open(fresh());
  const pid = newId();
  p.beginCreate(pid, "claude", newId());
  refused(() => p.markRetired(pid), "not_granted"); // creating → retired skips the non-selectable intent
  assert.equal(p.beginRetire(pid).state, "retiring"); // an abandoned creation
  refused(() => p.markBound(pid), "not_granted"); // never back to selectable
  p.markRetired(pid);
  for (const f of ["markBound", "beginRetire", "markRetired"]) refused(() => p[f](pid), "not_granted");
  refused(() => p.markBound(newId()), "not_granted"); // unknown
  await p.close();
});

test("a profile id is never reused; a subscription has at most one live profile; uids and project ids never repeat", async () => {
  const p = await open(fresh());
  const pid = newId(), sub = newId();
  p.beginCreate(pid, "claude", sub);
  refused(() => p.beginCreate(pid, "claude", newId()), "bad_form"); // same id, another subscription
  refused(() => p.beginCreate(newId(), "claude", sub), "bad_form"); // a second live profile for the subscription
  p.beginRetire(pid); p.markRetired(pid);
  refused(() => p.beginCreate(pid, "claude", sub), "bad_form"); // a retired id never comes back
  const next = p.beginCreate(newId(), "claude", sub); // a NEW profile for the same subscription is fine once retired
  assert.equal(next.storage_uid, STORAGE_UID_RANGE[0] + 1, "storage uids are never reused");
  assert.equal(next.project_id, PROJECT_RANGE[0] + 1, "project ids are never reused");
  // Profiles of different subscriptions and harnesses coexist.
  for (const h of HARNESSES) assert.equal(p.beginCreate(newId(), h, newId()).harness, h);
  await p.close();
});

test("bad input refuses: an unknown harness, bad ids", async () => {
  const p = await open(fresh());
  for (const h of ["Claude", "gemini", "", null, 1]) refused(() => p.beginCreate(newId(), h, newId()), "bad_form");
  refused(() => p.beginCreate("nope", "claude", newId()), "bad_form");
  refused(() => p.beginCreate(newId(), "claude", "nope"), "bad_form");
  assert.deepEqual(p.all(), [], "nothing recorded");
  await p.close();
});

test("the storage uid range sits beside the agent uid and tag gid ranges, never inside them", () => {
  for (const [lo, hi] of [UID_RANGE, GID_RANGE]) assert.ok(STORAGE_UID_RANGE[0] > hi || STORAGE_UID_RANGE[1] < lo);
  assert.ok(PROJECT_RANGE[0] > STORAGE_UID_RANGE[1]);
});

for (const [name, full, first] of [
  ["storage uid", { next_storage_uid: STORAGE_UID_RANGE[1] + 1, next_project: PROJECT_RANGE[0] + 1 }, { storage_uid: STORAGE_UID_RANGE[1], project_id: PROJECT_RANGE[0] }],
  ["project id", { next_storage_uid: STORAGE_UID_RANGE[0] + 1, next_project: PROJECT_RANGE[1] + 1 }, { storage_uid: STORAGE_UID_RANGE[0], project_id: PROJECT_RANGE[1] }],
]) {
  test(`the ${name} range refuses when used up, and never wraps`, async () => {
    const root = fresh();
    mkdirSync(join(root, "profiles"), { recursive: true, mode: 0o700 });
    const pid = newId();
    writeFileSync(join(root, "profiles", "profiles.json"), JSON.stringify({ v: 2, ...full,
      profiles: { [pid]: { harness: "claude", sub: newId(), ...first, gen: 1, state: "bound" } } }), { mode: 0o600 });
    const p = await open(root);
    const before = readFileSync(join(root, "profiles", "profiles.json"), "utf8");
    refused(() => p.beginCreate(newId(), "claude", newId()), "uid_exhausted");
    assert.equal(readFileSync(join(root, "profiles", "profiles.json"), "utf8"), before, "nothing allocated");
    await p.close();
  });
}

test("anything but the exact closed shape is refused at load", () => {
  const P = newId(), Q = newId(), S = newId();
  const ok = () => ({ v: 2, next_storage_uid: STORAGE_UID_RANGE[0] + 2, next_project: PROJECT_RANGE[0] + 2, profiles: {
    [P]: { harness: "claude", sub: S, storage_uid: STORAGE_UID_RANGE[0], project_id: PROJECT_RANGE[0], gen: 1, state: "bound" },
    [Q]: { harness: "claude", sub: S, storage_uid: STORAGE_UID_RANGE[0] + 1, project_id: PROJECT_RANGE[0] + 1, gen: 3, state: "retired" } } });
  assert.equal(checkProfiles(ok()), true);
  const cases = {
    "another version": (s) => { s.v = 1; },
    "an extra key": (s) => { s.extra = 1; },
    "a record with an extra key": (s) => { s.profiles[P].x = 1; },
    "the old owner fields": (s) => { s.profiles[P].owner_agent = newId(); },
    "an unknown state": (s) => { s.profiles[P].state = "active"; },
    "an unknown harness": (s) => { s.profiles[P].harness = "gemini"; },
    "a bad sub": (s) => { s.profiles[P].sub = "nope"; },
    "a storage uid at or past next": (s) => { s.profiles[P].storage_uid = s.next_storage_uid; },
    "a duplicate storage uid": (s) => { s.profiles[Q].storage_uid = STORAGE_UID_RANGE[0]; },
    "a storage uid below the range": (s) => { s.profiles[P].storage_uid = UID_RANGE[0]; },
    "a project id at or past next": (s) => { s.profiles[P].project_id = s.next_project; },
    "a duplicate project id": (s) => { s.profiles[Q].project_id = PROJECT_RANGE[0]; },
    "a project id below the range": (s) => { s.profiles[P].project_id = 99999; },
    "two live profiles for one subscription": (s) => { s.profiles[Q].state = "creating"; },
    "a gen of 0": (s) => { s.profiles[P].gen = 0; },
    "a bad profile id": (s) => { s.profiles.nope = s.profiles[P]; delete s.profiles[P]; },
    "next storage uid past the range end + 1": (s) => { s.next_storage_uid = STORAGE_UID_RANGE[1] + 2; },
    "next project past the range end + 1": (s) => { s.next_project = PROJECT_RANGE[1] + 2; },
  };
  for (const [name, f] of Object.entries(cases)) { const s = ok(); f(s); assert.throws(() => checkProfiles(s), (e) => e instanceof FleetError && e.code === "bad_form", name); }
});
