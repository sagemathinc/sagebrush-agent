// Host backup r3.3 §5 step 5: a restored host store's copy brought into a fresh host, registry first. Only the
// registry is imported (its typed importer, onto a registry that never recorded anything, exactly the manifest's); the
// grant is kept read-only as provenance and never attached; the audit is archived read-only; the other entries are
// listed as kept in the backup, not restored. Against a real HostStore in a temporary root.
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "./host-linux-only.mjs";
import { FleetError, newId } from "../lib/fleet/index.mjs";
import { HostStore } from "../lib/fleet/host/host-store.mjs";
import { buildManifest, canonical, sha256 } from "../lib/fleet/host/backup-manifest.mjs";
import { newPlan } from "../lib/fleet/host/restore-plan.mjs";
import { BY_RULE, DISPOSITION, NOT_RESTORED, PER_HOST, copyReadOnly, importHostStore } from "../lib/fleet/host/restore-import.mjs";

const refused = (fn, code) => assert.throws(fn, (e) => e instanceof FleetError && e.code === code, code);
let n = 0;
const hex = () => (++n).toString(16).padStart(64, "0");
const RUN = "20261124T030000Z-abcdefgh", RRUN = "20261126T010000Z-cdefghij";
const tmp = () => mkdtempSync(join(tmpdir(), "sb-import-"));

/** An old host's registry: two live agents (one with a start failure), a tombstone, a tag; and its manifest and plan. */
function fixture() {
  const [a, b, dead, t] = [newId(), newId(), newId(), newId()];
  const registry = {
    v: 1, next_uid: 70007, next_gid: 80002, // the counters are kept exactly, whatever the highest uid
    agents: {
      [a]: { uid: 70000, state: "running", life: 3, gen: 7, tags: [t], start_failed: "unit_failed" },
      [b]: { uid: 70003, state: "stopped", life: 1, gen: 7, tags: [], start_failed: null },
      [dead]: { uid: 70004, state: "deleted", life: 2, gen: 5, tags: [], start_failed: null },
    },
    tags: { [t]: { gid: 80001 } },
  };
  const sets = [{ kind: "agent", id: a }, { kind: "agent", id: b }, { kind: "archive", id: dead }, { kind: "tag", id: t }]
    .map((s) => ({ ...s, snapshot: hex(), tree: hex(), unrestorable: { count: 0, paths: [] } }));
  const manifest = buildManifest({ host: "old-host", run: RUN, time: "2026-11-24T03:10:00.000Z", registry, sets, config: { [a]: hex(), [b]: hex() }, hoststore: hex() });
  const plan = newPlan({ manifest, snapshot: hex(), sha256: sha256(canonical(manifest) + "\n") }, RRUN);
  return { a, b, dead, t, registry, manifest, plan };
}

/** The host store's restored copy: the given entries, as the backup copied them. */
function copyOf(registry, { entries = ["registry", "grant", "audit", "state", "harness-sessions", "harness-turns", "config"], registryText = null } = {}) {
  const c = join(tmp(), "copy");
  mkdirSync(c, { mode: 0o700 });
  for (const e of entries) mkdirSync(join(c, e), { mode: 0o700 });
  if (entries.includes("registry")) writeFileSync(join(c, "registry", "registry.json"), registryText ?? JSON.stringify(registry) + "\n");
  if (entries.includes("grant")) {
    writeFileSync(join(c, "grant", "state.json"), JSON.stringify({ v: 1, gen: 7, digest: "x".repeat(43), phase: "applied", plan: [], ack: { narrowed: false, restarted: [] }, proof: {} }));
    mkdirSync(join(c, "grant", "grants"));
    writeFileSync(join(c, "grant", "grants", `7-${"x".repeat(43)}`), "signed grant bytes");
  }
  if (entries.includes("audit")) { writeFileSync(join(c, "audit", "000001.log"), "line 1\n"); mkdirSync(join(c, "audit", "old")); writeFileSync(join(c, "audit", "old", "000000.log"), "line 0\n"); }
  for (const e of ["state", "harness-sessions", "harness-turns", "config"]) if (entries.includes(e)) writeFileSync(join(c, e, "x.json"), "{}");
  return c;
}

async function host() {
  const root = join(tmp(), "store");
  const store = await HostStore.open(root);
  return { root, store, restoreDir: join(tmp(), "restore") };
}

test("the import: the registry restored exactly, the grant kept read-only as provenance, the audit archived, the rest listed", async () => {
  const { a, b, dead, t, registry, manifest, plan } = fixture();
  const { root, store, restoreDir } = await host();
  try {
    const copy = copyOf(registry);
    const r = importHostStore({ copy, store, root, plan, manifest, restoreDir });
    assert.deepEqual(r.entries, {
      registry: "restored", grant: "provenance", audit: "archived",
      config: PER_HOST, "harness-sessions": NOT_RESTORED, "harness-turns": NOT_RESTORED, state: BY_RULE,
    });
    // Every uid, state, life, gen and tag kept, the tombstone too; the start failure cleared.
    assert.deepEqual(store.registry.agent(a), { ...registry.agents[a], start_failed: null });
    assert.deepEqual(store.registry.agent(b), registry.agents[b]);
    assert.deepEqual(store.registry.agent(dead), registry.agents[dead]);
    assert.deepEqual(store.registry.tag(t), { gid: 80001 });
    assert.deepEqual(store.registry.ids(), [a, b, dead].sort());
    // A retry of the same import (a crash after it was durable) is a no-op with the same report.
    assert.deepEqual(importHostStore({ copy: copyOf(registry), store, root, plan, manifest, restoreDir }), r);
    // No uid or gid is ever reallocated: the next ones continue after the restored counters.
    assert.equal(store.registry.addAgent(newId(), 8), 70007);
    assert.equal(store.registry.addTag(newId()), 80002);
    refused(() => store.registry.addAgent(dead, 8), "bad_form"); // a tombstoned id is never reused
    // The grant: bytes kept read-only, never attached: the live grant state is still the fresh host's (none).
    const prov = join(restoreDir, "provenance", "grant");
    assert.equal(readFileSync(join(prov, "grants", `7-${"x".repeat(43)}`), "utf8"), "signed grant bytes");
    for (const [p, mode] of [[prov, 0o500], [join(prov, "grants"), 0o500], [join(prov, "state.json"), 0o400]]) assert.equal(statSync(p).mode & 0o777, mode, p);
    const live = JSON.parse(readFileSync(join(root, "grant", "state.json"), "utf8"));
    assert.deepEqual([live.gen, live.digest], [0, null], "the restored grant is never the live grant");
    assert.deepEqual(readdirSync(join(root, "grant", "grants")), []);
    // The audit: read-only under the manifest's host and day; nothing else of the copy reaches the host root.
    const arch = join(root, "audit", "restored-old-host-2026-11-24");
    assert.equal(readFileSync(join(arch, "old", "000000.log"), "utf8"), "line 0\n");
    assert.equal(statSync(arch).mode & 0o777, 0o500);
    for (const e of ["state", "harness-sessions", "harness-turns", "config", "profiles", "pool"]) assert.equal(existsSync(join(root, e, "x.json")), false, e);
    // After the host has moved on (a new agent recorded), the same import is refused: it was once, onto an empty one.
    refused(() => importHostStore({ copy: copyOf(registry), store, root, plan, manifest, restoreDir }), "not_granted");
  } finally { await store.close(); }
});

test("the report's words for what isn't restored: exactly these three lines", async () => {
  assert.equal(BY_RULE, "not restored (by rule: a restored host waits for a fresh grant)");
  assert.equal(PER_HOST, "not restored (per host)");
  assert.equal(NOT_RESTORED, "kept in the backup, not restored (no importer)");
  const { registry, manifest, plan } = fixture();
  for (const [entry, line] of [["state", BY_RULE], ["config", PER_HOST], ["harness-sessions", NOT_RESTORED], ["harness-turns", NOT_RESTORED]]) {
    const { root, store, restoreDir } = await host();
    try {
      const r = importHostStore({ copy: copyOf(registry, { entries: ["registry", entry] }), store, root, plan, manifest, restoreDir });
      assert.deepEqual(r.entries, { registry: "restored", [entry]: line }, entry);
      assert.equal(existsSync(join(root, entry, "x.json")), false, `${entry}: nothing of it reaches the host`);
    } finally { await store.close(); }
  }
  // An absent entry isn't reported.
  const { root, store, restoreDir } = await host();
  try {
    assert.deepEqual(importHostStore({ copy: copyOf(registry, { entries: ["registry"] }), store, root, plan, manifest, restoreDir }).entries, { registry: "restored" });
  } finally { await store.close(); }
});

test("only the manifest's registry is imported, registry first: a refusal leaves nothing of the copy on the host", async () => {
  const { a, registry, manifest, plan } = fixture();
  const cases = [
    ["a valid registry the manifest doesn't bind", () => copyOf({ ...registry, agents: { ...registry.agents, [a]: { ...registry.agents[a], uid: 70001 } } }), "not_granted", {}],
    ["not JSON", () => copyOf(registry, { registryText: "{" }), "bad_form", {}],
    ["not the closed shape", () => copyOf(registry, { registryText: JSON.stringify({ ...registry, extra: 1 }) }), "bad_form", {}],
    ["no registry entry", () => copyOf(registry, { entries: ["grant", "audit"] }), "not_found", {}],
    ["no registry file", () => { const c = copyOf(registry); writeFileSync(join(c, "registry", "other.json"), "{}"); rmSync(join(c, "registry", "registry.json")); return c; }, "not_found", {}],
    ["an entry the backup never copies", () => { const c = copyOf(registry); mkdirSync(join(c, "profiles")); return c; }, "bad_form", {}],
    ["not the plan's manifest", () => copyOf(registry), "not_granted", { manifest: { ...manifest, time: "2026-11-24T03:11:00.000Z" } }],
  ];
  for (const [why, make, code, over] of cases) {
    const { root, store, restoreDir } = await host();
    try {
      refused(() => importHostStore({ copy: make(), store, root, plan, manifest, restoreDir, ...over }), code);
      assert.deepEqual(store.registry.ids(), [], why);
      assert.equal(existsSync(join(restoreDir, "provenance")), false, why);
      assert.equal(existsSync(join(root, "audit")), false, why);
    } finally { await store.close(); }
  }
});

test("the registry importer: only onto a registry that never recorded anything; the same import again is a no-op", async () => {
  const { registry, manifest, plan } = fixture();
  for (const [why, prep] of [
    ["an agent recorded", (s) => s.registry.addAgent(newId(), 1)],
    ["a tag recorded", (s) => s.registry.addTag(newId())],
  ]) {
    const { root, store, restoreDir } = await host();
    try {
      prep(store);
      const before = store.registry.ids();
      refused(() => importHostStore({ copy: copyOf(registry), store, root, plan, manifest, restoreDir }), "not_granted");
      assert.deepEqual(store.registry.ids(), before, why);
    } finally { await store.close(); }
  }
  // Another restore's registry onto a restored one refuses; the same one is fine.
  const { root, store, restoreDir } = await host();
  try {
    importHostStore({ copy: copyOf(registry), store, root, plan, manifest, restoreDir });
    const other = fixture();
    refused(() => store.registry.importRestored(other.registry), "not_granted");
    store.registry.importRestored(registry);
    refused(() => store.registry.importRestored({ ...registry, next_uid: 1 }), "bad_form");
  } finally { await store.close(); }
});

test("read-only copies: whole or nothing, links and special files refused, a retry identical, a different copy refused", () => {
  const src = join(tmp(), "src");
  mkdirSync(join(src, "d"), { recursive: true });
  writeFileSync(join(src, "a"), "A");
  writeFileSync(join(src, "d", "b"), "B");
  const dst = join(tmp(), "out", "dst");
  // A leftover of an interrupted copy is removed and redone.
  mkdirSync(`${dst}.partial`, { recursive: true });
  writeFileSync(`${dst}.partial/stale`, "x");
  assert.equal(copyReadOnly(src, dst), "copied");
  assert.equal(existsSync(`${dst}.partial`), false);
  assert.deepEqual(readdirSync(dst).sort(), ["a", "d"]);
  assert.equal(readFileSync(join(dst, "d", "b"), "utf8"), "B");
  assert.deepEqual([statSync(dst).mode & 0o777, statSync(join(dst, "d")).mode & 0o777, statSync(join(dst, "a")).mode & 0o777], [0o500, 0o500, 0o400]);
  assert.equal(copyReadOnly(src, dst), "present", "a retry");
  writeFileSync(join(src, "a"), "changed");
  refused(() => copyReadOnly(src, dst), "not_granted");
  writeFileSync(join(src, "a"), "A");
  writeFileSync(join(src, "extra"), "E");
  refused(() => copyReadOnly(src, dst), "not_granted");
  // Links are refused before anything is written.
  const linked = join(tmp(), "linked");
  mkdirSync(linked);
  symlinkSync("/etc/passwd", join(linked, "l"));
  const dst2 = join(tmp(), "dst2");
  refused(() => copyReadOnly(linked, dst2), "bad_form");
  assert.equal(existsSync(dst2), false);
  assert.equal(existsSync(`${dst2}.partial`), false);
  assert.ok(DISPOSITION.registry === "restored");
});
