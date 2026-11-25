// Host supervisor: the host's `…/state` report for the fleet pages (agent-autonomous-pages-fleet §2.1), from its readers,
// and the readers over a real HostStore.
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "./host-linux-only.mjs";
import { FleetError, newId } from "../lib/fleet/index.mjs";
import { CAUSES, fenceCauses, raiseFence } from "../lib/fleet/host/fence.mjs";
import { HEALTH, HEALTH_REASONS, hostState, hostStateReaders } from "../lib/fleet/host/host-state.mjs";
import { HostStore } from "../lib/fleet/host/host-store.mjs";
import { MARGIN_MS } from "../lib/fleet/host/lease.mjs";
import { newRecord, newRestoreRun, writeRecord } from "../lib/fleet/host/restore-record.mjs";

const refused = (p, code) => assert.rejects(p, (e) => e instanceof FleetError && e.code === code, code);
const tmp = (n) => mkdtempSync(join(tmpdir(), `sb-state-${n}-`));
const A = newId(), B = newId();
const NOW = 1_800_000_000_000, BOOT = 5_000_000;

/** Readers over plain data: agents { id: { run, fences, lease, restore } }. */
function readers({ agents = {}, qual = "qualified", health, now = NOW, boot = BOOT } = {}) {
  return {
    agentIds: () => Object.keys(agents).sort(),
    run: (id) => agents[id].run,
    fences: (id) => agents[id].fences ?? [],
    liveLease: async (id) => agents[id].lease ?? null,
    restore: (id) => agents[id].restore ?? null,
    qualification: () => qual,
    health,
    nowMs: () => now,
    bootNowMs: () => boot,
  };
}

test("the report: exactly the agreed fields, closed enums, the lease's effective end on the wall clock", async () => {
  const r = await hostState(readers({ agents: {
    [A]: { run: "running", fences: [], lease: { lease_id: "L", lg: 3, gen: 2, expiry_tick: BOOT + 600_000 } },
    [B]: { run: "stopped", fences: ["lease", "agent", "lease"], restore: "validated" },
  } }));
  assert.deepEqual(r, {
    host: { reported_at_ms: NOW, health: "ok", health_reasons: [] },
    agents: {
      [A]: { run: "running", fences: [], lease: "live", lease_expires_at_ms: NOW + 600_000 - MARGIN_MS, restore: null },
      [B]: { run: "stopped", fences: ["agent", "lease"], lease: "none", lease_expires_at_ms: null, restore: "validated" },
    },
  });
  // Nothing beyond the agreed keys: no lease id, lg or gen, no profile, path or conversation.
  assert.deepEqual(Object.keys(r.agents[A]), ["run", "fences", "lease", "lease_expires_at_ms", "restore"]);
  assert.ok(!JSON.stringify(r).includes("\"L\""), "the lease id isn't reported");
});

test("health: §8.1's states coarsened to ok, degraded and failing; the qualification latch is always reported", async () => {
  assert.deepEqual(HEALTH, { ok: "ok", degraded_audit: "degraded", reserve_only: "degraded", fail_closed: "failing", qualify_required: "failing" });
  const host = async (o) => (await hostState(readers(o))).host;
  assert.deepEqual(await host({ health: () => ({ state: "degraded_audit", reasons: ["audit_timeout"] }) }), { reported_at_ms: NOW, health: "degraded", health_reasons: ["audit_timeout"] });
  assert.deepEqual(await host({ health: () => ({ state: "reserve_only", reasons: ["audit_full"] }) }), { reported_at_ms: NOW, health: "degraded", health_reasons: ["audit_full"] });
  assert.deepEqual(await host({ health: () => ({ state: "fail_closed", reasons: ["audit_unavailable", "audit_unavailable"] }) }), { reported_at_ms: NOW, health: "failing", health_reasons: ["audit_unavailable"] });
  // The latch: ok becomes failing with qualify_required; a worse state keeps failing and gains the reason; sorted, unique.
  assert.deepEqual(await host({ qual: "qualify_required" }), { reported_at_ms: NOW, health: "failing", health_reasons: ["qualify_required"] });
  assert.deepEqual(await host({ qual: "qualify_required", health: () => ({ state: "degraded_audit", reasons: ["audit_timeout"] }) }),
    { reported_at_ms: NOW, health: "failing", health_reasons: ["audit_timeout", "qualify_required"] });
  assert.deepEqual(await host({ qual: "qualify_required", health: () => ({ state: "fail_closed", reasons: ["qualify_required"] }) }),
    { reported_at_ms: NOW, health: "failing", health_reasons: ["qualify_required"] });
});

test("a report never carries anything outside its enums: unknown states, causes, reasons or clocks are refused", async () => {
  const one = (a) => readers({ agents: { [A]: { run: "running", ...a } } });
  await refused(hostState(one({ run: "frozen" })), "bad_form");
  await refused(hostState(one({ fences: ["lease", "maintenance"] })), "bad_form");
  await refused(hostState(one({ restore: "almost" })), "bad_form");
  await refused(hostState(readers({ health: () => ({ state: "fine", reasons: [] }) })), "bad_form");
  await refused(hostState(readers({ health: () => ({ state: "fail_closed", reasons: ["not_a_reason"] }) })), "bad_form");
  await refused(hostState(readers({ health: () => ({ state: "fail_closed", reasons: ["bad_form"] }) })), "bad_form"); // a shared code, not host health
  await refused(hostState(readers({ health: () => ({ state: "ok", reasons: ["audit_full"] }) })), "bad_form"); // reasons on an ok host
  await refused(hostState(readers({ health: () => ({ state: "constructor", reasons: [] }) })), "bad_form");
  await refused(hostState(readers({ now: 1.5 })), "bad_form");
  await refused(hostState(readers({ boot: NaN })), "bad_form");
});

test("every health reason is a host-owned code in schema/fleet/reasons.json", () => {
  const reg = JSON.parse(readFileSync(new URL("../schema/fleet/reasons.json", import.meta.url), "utf8")).reasons;
  for (const x of HEALTH_REASONS) assert.equal(reg.find((r) => r.name === x)?.owner, "host", x);
});

test("the readers over a real HostStore: the registry's agents and states, their raised causes, restore records, the latch", async () => {
  const root = tmp("store"), fenceDir = tmp("fence"), restoreDir = tmp("restore");
  const store = await HostStore.open(root);
  store.registry.addAgent(A, 1);
  store.registry.addAgent(B, 1);
  raiseFence("lease", A, { dir: fenceDir });
  raiseFence("expiry", A, { dir: fenceDir });
  writeRecord(newRecord({ kind: "agent", id: B, run: newRestoreRun(NOW), snapshot: "a".repeat(64) }), { dir: restoreDir });
  const lease = { lease_id: "L", lg: 1, gen: 1, expiry_tick: 9e12 };
  const r = hostStateReaders(store, { fenceDir, restoreDir, liveLease: async (id) => (id === B ? lease : null), wall: () => NOW, clock: { boot: () => BOOT, mono: () => 0 } });
  assert.deepEqual(r.agentIds(), [A, B].sort());
  assert.deepEqual(fenceCauses(A, { dir: fenceDir }), ["expiry", "lease"]);
  assert.deepEqual(fenceCauses(B, { dir: fenceDir }), ["expiry"], "expiry fences every agent");
  const s = await hostState(r);
  assert.deepEqual(s.agents[A], { run: "provisioned", fences: ["expiry", "lease"], lease: "none", lease_expires_at_ms: null, restore: null });
  assert.deepEqual(s.agents[B], { run: "provisioned", fences: ["expiry"], lease: "live", lease_expires_at_ms: NOW + 9e12 - MARGIN_MS - (BOOT + 10), restore: "staging" });
  assert.equal(s.host.health, "ok");
  store.qualification.invalidate(NOW);
  assert.deepEqual((await hostState(r)).host, { reported_at_ms: NOW, health: "failing", health_reasons: ["qualify_required"] });
  // Without a lease reader, no lease is ever live.
  assert.equal((await hostState(hostStateReaders(store, { fenceDir, restoreDir }))).agents[B].lease, "none");
  // Every cause name fenceCauses can return is a CAUSES name, in CAUSES order.
  for (const c of ["all", "backup", "restore", "transferred"]) raiseFence(c, A, { dir: fenceDir });
  assert.deepEqual(fenceCauses(A, { dir: fenceDir }), CAUSES.filter((c) => c !== "agent"));
  await store.close();
});
