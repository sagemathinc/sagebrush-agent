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
import { AUTH_TABLE, HARNESSES, PROJECT_RANGE, STORAGE_UID_RANGE, authKinds, checkProfiles } from "../lib/fleet/host/profiles.mjs";
import { GID_RANGE, UID_RANGE } from "../lib/fleet/host/registry.mjs";

const refused = (fn, code) => assert.throws(fn, (e) => e instanceof FleetError && e.code === code, code);
const fresh = () => join(mkdtempSync(join(tmpdir(), "sb-profiles-")), "state");
const disk = (root) => JSON.parse(readFileSync(join(root, "profiles", "profiles.json"), "utf8"));
const CL = { harness: "claude", auth: "subscription" };
const open = async (root) => { const h = await HostStore.open(root); const p = h.profiles; p.close = () => h.close(); return p; };

test("create, bind, retire: each state durable on disk before it is visible", async () => {
  const root = fresh();
  const p = await open(root);
  const pid = newId(), sub = newId();
  const first = { harness: "claude", provider: null, auth: "subscription", sub, storage_uid: STORAGE_UID_RANGE[0], project_id: PROJECT_RANGE[0], gen: 1, state: "creating", mountpoints: null, removal: null };
  assert.deepEqual(p.beginCreate(pid, CL, sub), first);
  assert.equal(disk(root).profiles[pid].state, "creating");
  assert.equal(statSync(join(root, "profiles", "profiles.json")).mode & 0o777, 0o600);
  refused(() => p.markBound(pid), "not_granted"); // the mountpoints aren't recorded yet
  p.setMountpoints(pid, [{ name: "projects", ino: 12, gen: 7 }]);
  p.markBound(pid);
  assert.deepEqual(p.profileFor(sub), { pid, ...first, state: "bound", mountpoints: [{ name: "projects", ino: 12, gen: 7 }] });
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
  p.beginCreate(pid, CL, newId());
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
  p.beginCreate(pid, CL, sub);
  refused(() => p.beginCreate(pid, CL, newId()), "bad_form"); // same id, another subscription
  refused(() => p.beginCreate(newId(), CL, sub), "bad_form"); // a second live profile for the subscription
  p.beginRetire(pid); p.markRetired(pid);
  refused(() => p.beginCreate(pid, CL, sub), "bad_form"); // a retired id never comes back
  const next = p.beginCreate(newId(), CL, sub); // a NEW profile for the same subscription is fine once retired
  assert.equal(next.storage_uid, STORAGE_UID_RANGE[0] + 1, "storage uids are never reused");
  assert.equal(next.project_id, PROJECT_RANGE[0] + 1, "project ids are never reused");
  // Profiles of different subscriptions and kinds coexist.
  for (const k of [{ harness: "codex", auth: "api_key" }, { harness: "opencode", provider: "openai", auth: "api_key" }, { harness: "pi", provider: "openai", auth: "api_key" }]) {
    assert.deepEqual((({ harness, provider, auth }) => ({ harness, provider, auth }))(p.beginCreate(newId(), k, newId())), { provider: null, ...k });
  }
  await p.close();
});

test("the kind is checked against the auth table: a Claude subscription only in claude; no Anthropic route in opencode or pi", async () => {
  const p = await open(fresh());
  // Anthropic's terms, and v1's registry: opencode and pi have no Anthropic route at all, whatever the auth kind.
  for (const h of ["opencode", "pi"]) {
    for (const auth of ["subscription", "oauth", "api_key", "cloud", "bedrock"]) refused(() => p.beginCreate(newId(), { harness: h, provider: "anthropic", auth }, newId()), "bad_form");
    for (const auth of ["oauth", "subscription", "cloud"]) refused(() => p.beginCreate(newId(), { harness: h, provider: "openai", auth }, newId()), "bad_form");
    assert.equal(p.beginCreate(newId(), { harness: h, provider: "openai", auth: "api_key" }, newId()).auth, "api_key");
    refused(() => p.beginCreate(newId(), { harness: h, auth: "api_key" }, newId()), "bad_form"); // a provider is required
    refused(() => p.beginCreate(newId(), { harness: h, provider: "Open AI", auth: "api_key" }, newId()), "bad_form");
  }
  // claude: its cloud backend is the auth kind; there is no generic "cloud", and never a provider.
  for (const auth of ["subscription", "api_key", "bedrock", "vertex", "foundry"]) assert.equal(p.beginCreate(newId(), { harness: "claude", auth }, newId()).auth, auth);
  for (const auth of ["cloud", "oauth", "Bedrock"]) refused(() => p.beginCreate(newId(), { harness: "claude", auth }, newId()), "bad_form");
  for (const provider of ["anthropic", "bedrock", "openai"]) refused(() => p.beginCreate(newId(), { harness: "claude", provider, auth: "api_key" }, newId()), "bad_form");
  for (const auth of ["subscription", "api_key"]) assert.equal(p.beginCreate(newId(), { harness: "codex", auth }, newId()).auth, auth);
  for (const auth of ["cloud", "bedrock", "oauth"]) refused(() => p.beginCreate(newId(), { harness: "codex", auth }, newId()), "bad_form");
  assert.deepEqual(authKinds("gemini", null), []);
  // A provider the table doesn't list refuses, whatever it is called: an alias of Anthropic, an unknown provider.
  for (const h of ["opencode", "pi"]) {
    for (const provider of ["claude", "claude-ai", "Anthropic", "OpenAI", "mistral", "", null]) {
      for (const auth of ["subscription", "oauth", "api_key", "cloud"]) refused(() => p.beginCreate(newId(), { harness: h, provider, auth }, newId()), "bad_form");
    }
  }
  await p.close();
});

test("only primitive strings: arrays, objects and other wrong types never match a table key (no property-key coercion)", async () => {
  const wrong = [["claude"], { toString: () => "claude" }, 1, true, undefined];
  for (const h of wrong) assert.deepEqual(authKinds(h, null), [], String(h));
  for (const pr of [["anthropic"], ["openai"], { toString: () => "openai" }, 1, true, undefined]) {
    for (const h of ["opencode", "pi"]) assert.deepEqual(authKinds(h, pr), [], `${h} ${String(pr)}`);
  }
  for (const pr of [[""], "", 0, false, undefined]) assert.deepEqual(authKinds("claude", pr), [], String(pr)); // exactly null
  const p = await open(fresh());
  refused(() => p.beginCreate(newId(), { harness: ["claude"], auth: "subscription" }, newId()), "bad_form");
  refused(() => p.beginCreate(newId(), { harness: "pi", provider: ["anthropic"], auth: "api_key" }, newId()), "bad_form");
  refused(() => p.beginCreate(newId(), { harness: "claude", auth: ["subscription"] }, newId()), "bad_form");
  assert.deepEqual(p.all(), []);
  await p.close();
});

test("the auth table is closed and exactly this (a change is a reviewed change to this row)", () => {
  assert.deepEqual(JSON.parse(JSON.stringify(AUTH_TABLE)), {
    claude: { "": ["subscription", "api_key", "bedrock", "vertex", "foundry"] },
    codex: { "": ["subscription", "api_key"] },
    opencode: { openai: ["api_key"] },
    pi: { openai: ["api_key"] },
  });
  assert.deepEqual(HARNESSES, ["claude", "codex", "opencode", "pi"]);
  // Only claude and codex list a subscription, each its own vendor's through its own CLI; no harness has an
  // anthropic provider; the only provider is openai.
  for (const [h, byProvider] of Object.entries(AUTH_TABLE)) {
    for (const [prov, kinds] of Object.entries(byProvider)) {
      assert.ok(prov === "" || prov === "openai", `${h} ${prov}`);
      if (kinds.includes("subscription")) assert.ok(["claude", "codex"].includes(h) && prov === "");
    }
  }
  assert.ok(Object.isFrozen(AUTH_TABLE) && Object.isFrozen(AUTH_TABLE.pi) && Object.isFrozen(AUTH_TABLE.pi.openai));
  // A copy is returned: mutating it changes nothing.
  const k = authKinds("pi", "openai"); k.push("subscription");
  assert.deepEqual(authKinds("pi", "openai"), ["api_key"]);
});

test("bad input refuses: an unknown harness, bad ids", async () => {
  const p = await open(fresh());
  for (const h of ["Claude", "gemini", "", null, 1]) refused(() => p.beginCreate(newId(), { harness: h, auth: "api_key" }, newId()), "bad_form");
  refused(() => p.beginCreate("nope", CL, newId()), "bad_form");
  refused(() => p.beginCreate(newId(), CL, "nope"), "bad_form");
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
      profiles: { [pid]: { harness: "claude", provider: null, auth: "subscription", sub: newId(), ...first, gen: 1, state: "bound" } } }), { mode: 0o600 });
    const p = await open(root);
    const before = readFileSync(join(root, "profiles", "profiles.json"), "utf8");
    refused(() => p.beginCreate(newId(), CL, newId()), "uid_exhausted");
    assert.equal(readFileSync(join(root, "profiles", "profiles.json"), "utf8"), before, "nothing allocated");
    await p.close();
  });
}

test("anything but the exact closed shape is refused at load", () => {
  const P = newId(), Q = newId(), S = newId();
  const ok = () => ({ v: 2, next_storage_uid: STORAGE_UID_RANGE[0] + 2, next_project: PROJECT_RANGE[0] + 2, profiles: {
    [P]: { harness: "claude", provider: null, auth: "subscription", sub: S, storage_uid: STORAGE_UID_RANGE[0], project_id: PROJECT_RANGE[0], gen: 1, state: "bound" },
    [Q]: { harness: "claude", provider: null, auth: "subscription", sub: S, storage_uid: STORAGE_UID_RANGE[0] + 1, project_id: PROJECT_RANGE[0] + 1, gen: 3, state: "retired" } } });
  assert.equal(checkProfiles(ok()), true);
  const cases = {
    "another version": (s) => { s.v = 1; },
    "an extra key": (s) => { s.extra = 1; },
    "a record with an extra key": (s) => { s.profiles[P].x = 1; },
    "the old owner fields": (s) => { s.profiles[P].owner_agent = newId(); },
    "an unknown state": (s) => { s.profiles[P].state = "active"; },
    "an unknown harness": (s) => { s.profiles[P].harness = "gemini"; },
    "a provider on claude": (s) => { s.profiles[P].provider = "anthropic"; },
    "an auth kind the harness lacks": (s) => { s.profiles[P].auth = "oauth"; },
    "a Claude subscription in opencode": (s) => { Object.assign(s.profiles[P], { harness: "opencode", provider: "anthropic", auth: "subscription" }); },
    "an unlisted provider": (s) => { Object.assign(s.profiles[P], { harness: "pi", provider: "claude", auth: "oauth" }); },
    "an array harness": (s) => { s.profiles[P].harness = ["claude"]; },
    "an array provider": (s) => { Object.assign(s.profiles[P], { harness: "pi", provider: ["anthropic"], auth: "api_key" }); },
    "an array auth": (s) => { s.profiles[P].auth = ["subscription"]; },
    "an omitted provider": (s) => { delete s.profiles[P].provider; },
    "no auth": (s) => { delete s.profiles[P].auth; },
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

test("piece 2's record fields: mountpoints only while creating and required for bound; a removal only while retiring", async () => {
  const p = await open(fresh());
  const pid = newId();
  p.beginCreate(pid, CL, newId());
  for (const bad of [null, "x", [{ name: "..", ino: 1, gen: 1 }], [{ name: "a/b", ino: 1, gen: 1 }], [{ name: "p", ino: -1, gen: 1 }],
    [{ name: "p", ino: 1, gen: 2 ** 32 }], [{ name: "p", ino: 1, gen: 1, x: 1 }], Array.from({ length: 17 }, (_, i) => ({ name: `s${i}`, ino: i, gen: 1 }))]) {
    refused(() => p.setMountpoints(pid, bad), "bad_form");
  }
  refused(() => p.setMountpoints(pid, [{ name: "p", ino: 1, gen: 1 }, { name: "p", ino: 2, gen: 1 }]), "bad_form"); // a duplicate name (the shape check)
  p.setMountpoints(pid, []);
  const removal = { epoch: { boot_id: "b", mnt_id: 3 }, fsid: "00000000000000ab", root: { type: "dir" }, owners: [0, STORAGE_UID_RANGE[0]] };
  refused(() => p.setRemoval(pid, removal), "not_granted"); // not while creating
  p.markBound(pid);
  refused(() => p.setMountpoints(pid, []), "not_granted"); // fixed once bound
  refused(() => p.setRemoval(pid, removal), "not_granted");
  p.beginRetire(pid);
  refused(() => p.setRemoval(pid, { ...removal, owners: [] }), "bad_form");
  refused(() => p.setRemoval(pid, { ...removal, owners: [0, 1, 2] }), "bad_form");
  assert.deepEqual(p.setRemoval(pid, removal).removal, removal);
  p.markRetired(pid);
  assert.deepEqual(p.setRemoval(pid, removal).removal, removal, "a crash leftover's removal may be recorded on a retired record");
  await p.close();
});

test("a v2 bound record (piece 1) upgrades to bound with mountpoints null: commits go on, it's never selectable, it retires", async () => {
  const root = fresh();
  const pid = newId(), sub = newId();
  mkdirSync(join(root, "profiles"), { recursive: true, mode: 0o700 });
  const v2 = { v: 2, next_storage_uid: STORAGE_UID_RANGE[0] + 1, next_project: PROJECT_RANGE[0] + 1, profiles: {
    [pid]: { harness: "claude", provider: null, auth: "subscription", sub, storage_uid: STORAGE_UID_RANGE[0], project_id: PROJECT_RANGE[0], gen: 1, state: "bound" } } };
  writeFileSync(join(root, "profiles", "profiles.json"), JSON.stringify(v2), { mode: 0o600 });
  const p = await open(root);
  const other = newId();
  p.beginCreate(other, CL, newId()); // the first commit upgrades the file; the bound record must not fail it
  const d = disk(root);
  assert.equal(d.v, 3);
  assert.deepEqual([d.profiles[pid].state, d.profiles[pid].mountpoints, d.profiles[pid].removal], ["bound", null, null], "no [] invented");
  assert.equal(checkProfiles(d), true);
  refused(() => p.setMountpoints(pid, []), "not_granted"); // never made startable in place
  assert.equal(p.beginRetire(pid).state, "retiring");
  await p.close();
  const again = await open(root); // and it loads again
  assert.equal(again.profile(pid).state, "retiring");
  await again.close();
});

test("a v2 file (piece 1) loads, and its first commit upgrades every record to v3 with null fields", async () => {
  const root = fresh();
  const pid = newId(), sub = newId();
  mkdirSync(join(root, "profiles"), { recursive: true, mode: 0o700 });
  const v2 = { v: 2, next_storage_uid: STORAGE_UID_RANGE[0] + 1, next_project: PROJECT_RANGE[0] + 1, profiles: {
    [pid]: { harness: "claude", provider: null, auth: "subscription", sub, storage_uid: STORAGE_UID_RANGE[0], project_id: PROJECT_RANGE[0], gen: 1, state: "creating" } } };
  writeFileSync(join(root, "profiles", "profiles.json"), JSON.stringify(v2), { mode: 0o600 });
  const p = await open(root);
  assert.equal(p.profile(pid).state, "creating");
  p.setMountpoints(pid, []);
  const d = disk(root);
  assert.equal(d.v, 3);
  assert.deepEqual([d.profiles[pid].mountpoints, d.profiles[pid].removal], [[], null]);
  await p.close();
});
