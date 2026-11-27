// A turn's reasons (launcher contract amendment A5 §8.3): the seven new host entries in schema/fleet/reasons.json, the
// closed phase-and-reason table, and the unit start's preflight_missing left exactly as it was.

import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { TURN_REASONS, TURN_PHASES_WITHOUT_REASON, SUMMARY_ONLY, launcherTurnReason, turnPairOk } from "../lib/fleet/host/turn-reasons.mjs";
import { launcherExit } from "../lib/fleet/host/effects.mjs";

const registry = JSON.parse(readFileSync(new URL("../schema/fleet/reasons.json", import.meta.url), "utf8"));
const byName = new Map(registry.reasons.map((r) => [r.name, r]));
const NEW = ["profile_identity", "turn_preflight", "no_profile", "all_blocked", "busy", "agent_fenced", "source_unavailable"];

test("the seven turn reasons are host entries, each with exactly one meaning", () => {
  for (const n of NEW) {
    const r = byName.get(n);
    assert.ok(r, n);
    assert.deepEqual(Object.keys(r), ["name", "owner", "meaning"], `${n}: a host code is local (no HTTP status)`);
    assert.equal(r.owner, "host", n);
    assert.ok(r.meaning.length > 0 && !r.meaning.includes(";;"), n);
  }
  // Each name once in the whole registry.
  const names = registry.reasons.map((r) => r.name);
  assert.equal(new Set(names).size, names.length);
});

// The host daemon main's entries (host daemon main r1.1 §4, AUDIT-cleared), added after this registry's turn reasons,
// and its one widening of an entry that existed before: preflight_missing's meaning.
const DAEMON = ["identity_broken", "host_ended", "lease_unqualified", "bad_config"];
// The execution lease's suspend gate (lease-on r1.5 §6.5, C8b, T4), host health reasons added after those.
const GATE = ["suspend_gate_stuck", "suspend_gate_exhausted"];
const PREFLIGHT_BEFORE = "a required unit, Landlock or path-contract control is missing at start";
const PREFLIGHT_NOW = "a required host platform, privilege, account, unit, adapter, Landlock or path-contract control is missing at start";

test("every entry that existed before is byte-for-byte unchanged, but for preflight_missing's ruled widening", () => {
  // sha256 of JSON.stringify of the registry's 50 entries before this change, in order (preflight_missing with the
  // meaning it had then: the only later change to any of them).
  const before = registry.reasons.filter((r) => !NEW.includes(r.name) && !DAEMON.includes(r.name) && !GATE.includes(r.name))
    .map((r) => (r.name === "preflight_missing" ? { ...r, meaning: PREFLIGHT_BEFORE } : r));
  assert.equal(before.length, 50);
  assert.equal(createHash("sha256").update(JSON.stringify(before)).digest("hex"), "49d4933821966df89ba7ee9fbf2fa006fe5bbf5f356160f47e340fd2e73e854c");
  assert.equal(byName.get("preflight_missing").meaning, PREFLIGHT_NOW);
  // The unit start's own mapping is untouched: its codes are still preflight_missing, never a turn's reason.
  for (const c of [65, 66, 68, 69]) assert.equal(launcherExit(c), "preflight_missing", String(c));
  assert.equal(launcherExit(67), "landlock_abi");
});

test("the launcher's failure record maps to exactly one reason, and an unknown code to none", () => {
  assert.equal(launcherTurnReason(73), "profile_identity");
  assert.equal(launcherTurnReason(67), "landlock_abi");
  for (const c of [64, 65, 66, 68, 69, 71, 72]) assert.equal(launcherTurnReason(c), "turn_preflight", String(c));
  for (const c of [0, 1, 63, 70, 74, 75, 76, 77, 78, 255, -1, 66.5, "66", null, undefined]) assert.equal(launcherTurnReason(c), null, String(c));
  // A turn never uses preflight_missing.
  for (let c = 0; c < 256; c++) assert.notEqual(launcherTurnReason(c), "preflight_missing");
});

// The contract's table (A5 §8.3), written out here independently of the module under test.
const CONTRACT = {
  failed_no_effect: ["profile_identity", "turn_preflight", "landlock_abi"],
  refused: ["no_profile", "all_blocked", "agent_fenced", "source_unavailable"],
};
const REASONLESS = ["authorized", "succeeded", "unknown_effect", "reconciled_no_effect", "reconciled_succeeded"];

test("the module's table is exactly the contract's", () => {
  assert.deepEqual(Object.keys(TURN_REASONS).sort(), Object.keys(CONTRACT).sort());
  for (const [p, rs] of Object.entries(CONTRACT)) assert.deepEqual([...TURN_REASONS[p]].sort(), [...rs].sort(), p);
  assert.deepEqual([...TURN_PHASES_WITHOUT_REASON].sort(), [...REASONLESS].sort());
});

test("the phase-and-reason table is closed: every pair outside it is refused", () => {
  const phases = [...Object.keys(CONTRACT), ...REASONLESS];
  const reasons = registry.reasons.map((r) => r.name);
  let allowed = 0;
  for (const p of [...phases, "aborted", "failed", ""]) {
    for (const r of [...reasons, null, "made_up_reason"]) {
      const want = REASONLESS.includes(p) ? r === null : (CONTRACT[p] ?? []).includes(r);
      assert.equal(turnPairOk(p, r), want, `${p} ${r}`);
      if (want) allowed++;
    }
  }
  // Exactly the contract: 3 failed_no_effect reasons, 4 refused reasons, and 5 reasonless phases with none.
  assert.equal(allowed, 12);
  // busy is never an event's reason, and a refused event can't carry a launcher reason.
  for (const p of phases) assert.equal(turnPairOk(p, "busy"), false, p);
  assert.deepEqual(SUMMARY_ONLY, ["busy"]);
  assert.equal(turnPairOk("refused", "turn_preflight"), false);
  assert.equal(turnPairOk("failed_no_effect", "no_profile"), false);
  // A prototype name is no phase.
  for (const p of ["constructor", "__proto__", "toString", "hasOwnProperty"]) assert.equal(turnPairOk(p, "turn_preflight"), false, p);
});

test("nothing is coerced: a phase or reason that isn't a primitive string is refused, never thrown on", () => {
  const nullProto = Object.assign(Object.create(null), { x: 1 });
  const stringy = { toString: () => "refused" };
  for (const p of [["refused"], ["failed_no_effect"], new String("refused"), stringy, nullProto, 1, true, undefined, null, Symbol("refused")]) {
    assert.equal(turnPairOk(p, "no_profile"), false, String(typeof p));
    assert.equal(turnPairOk(p, "profile_identity"), false, String(typeof p));
    assert.equal(turnPairOk(p, null), false, String(typeof p));
  }
  for (const r of [["no_profile"], new String("no_profile"), { toString: () => "no_profile" }, nullProto, 0, false, undefined]) {
    assert.equal(turnPairOk("refused", r), false, String(typeof r));
    assert.equal(turnPairOk("succeeded", r), false, `reasonless with ${typeof r}`);
  }
});

test("every reason the table names is registered, and an unregistered name is refused", () => {
  for (const r of [...Object.values(CONTRACT).flat(), ...SUMMARY_ONLY]) assert.ok(byName.has(r), r);
  for (const r of NEW) assert.ok([...Object.values(CONTRACT).flat(), ...SUMMARY_ONLY].includes(r), `${r} is used by the table`);
  assert.equal(turnPairOk("failed_no_effect", "profile_identity_x"), false);
  assert.equal(byName.has("profile_identity_x"), false);
});

test("the suspend gate's two health reasons are host codes, local, registered once, and reportable", async () => {
  const { HEALTH_REASONS } = await import("../lib/fleet/host/host-state.mjs");
  for (const n of GATE) {
    const r = byName.get(n);
    assert.ok(r, n);
    assert.deepEqual(Object.keys(r), ["name", "owner", "meaning"], `${n}: a host code is local`);
    assert.equal(r.owner, "host", n);
    assert.ok(HEALTH_REASONS.includes(n), `${n} is a health reason`);
  }
  assert.equal(registry.reasons.filter((r) => GATE.includes(r.name)).length, 2);
});
