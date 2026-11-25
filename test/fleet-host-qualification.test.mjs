// Host supervisor: the systemd preflight (host-preflight.mjs) and the qualification latch it sets (qualification.mjs).
// Exactly the pinned major passes; anything else, a failure or no answer in time refuses. An invalidation is durable,
// keeps its first time, and has no way back here.
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "./host-linux-only.mjs";
import { FleetError } from "../lib/fleet/index.mjs";
import { HostStore } from "../lib/fleet/host/host-store.mjs";
import { QUALIFIED_MAJOR, hostSystemdPreflight } from "../lib/fleet/host/host-preflight.mjs";
import { Qualification, checkQualification } from "../lib/fleet/host/qualification.mjs";

const badForm = (e) => e instanceof FleetError && e.code === "bad_form";
const V255 = "systemd 255 (255.4-1ubuntu8.19)\n+PAM +AUDIT +SELINUX\ndefault-hierarchy=unified\n";

test("the qualified major is the policy artifact's pin: 255", () => {
  const pin = JSON.parse(readFileSync(new URL("../schema/fleet/agent-seccomp-policy.json", import.meta.url), "utf8")).pin;
  assert.equal(QUALIFIED_MAJOR, 255);
  assert.equal(QUALIFIED_MAJOR, pin.groups_from.systemd_major);
});

test("preflight: exactly the pinned major passes; any other answer, a throw or a non-string refuses", async () => {
  const answer = (v) => async () => v;
  assert.equal(await hostSystemdPreflight(answer(V255), 1000), null);
  assert.equal(await hostSystemdPreflight(answer("systemd 255 (255)\n"), 1000), null);
  for (const v of ["systemd 256 (256.5-2ubuntu3)\n", "systemd 25 (25)\n", "systemd 2550 (2550)\n", "systemd 254 (254.1-1)\n",
    "systemd 255\n", "systemd 255 (255.4 extra)\n", " systemd 255 (255.4)\n", "systemd 0255 (255.4)\n", "", "\n", "garbage",
    undefined, null, 255, Buffer.from(V255)]) {
    assert.equal(await hostSystemdPreflight(answer(v), 1000), "qualify_required", JSON.stringify(String(v)));
  }
  assert.equal(await hostSystemdPreflight(async () => { throw new Error("exit 1"); }, 1000), "qualify_required");
  assert.equal(await hostSystemdPreflight(() => { throw new Error("sync"); }, 1000), "qualify_required");
  // Another pin: the same answer is checked against it.
  assert.equal(await hostSystemdPreflight(answer(V255), 1000, 256), "qualify_required");
  assert.equal(await hostSystemdPreflight(answer("systemd 256 (256.5)\n"), 1000, 256), null);
});

test("preflight: bounded; past its time the signal aborts and the answer is a refusal, even if 255 comes later", async () => {
  let seen;
  const slow = (ms, signal) => { seen = { ms, signal }; return new Promise((r) => setTimeout(() => r(V255), 200)); };
  const t0 = Date.now();
  assert.equal(await hostSystemdPreflight(slow, 30), "qualify_required");
  assert.ok(Date.now() - t0 < 150, "didn't wait for the late answer");
  assert.equal(seen.ms, 30);
  assert.equal(seen.signal.aborted, true);
  // An answer that settles after the deadline while a busy event loop keeps the timer from firing: still refused, and
  // the signal aborted (the deadline is checked when the answer arrives, not only by the timer).
  let late;
  const busy = async (ms, signal) => { late = signal; await null; const until = performance.now() + 30; while (performance.now() < until); return V255; };
  assert.equal(await hostSystemdPreflight(busy, 1), "qualify_required");
  assert.equal(late.aborted, true);
  // The same at a wider deadline: answered in 30 ms of a blocked loop against 20 ms.
  assert.equal(await hostSystemdPreflight(busy, 20), "qualify_required");
  assert.equal(late.aborted, true);
  // In time: not aborted.
  let sig;
  assert.equal(await hostSystemdPreflight(async (ms, signal) => { sig = signal; return V255; }, 1000), null);
  assert.equal(sig.aborted, false);
});

test("qualification: starts qualified; an invalidation latches, durably, keeping its first time", async () => {
  const root = join(mkdtempSync(join(tmpdir(), "sb-qual-")), "state");
  let store = await HostStore.open(root);
  const q = store.qualification;
  assert.deepEqual([q.state, q.latched], ["qualified", false]);
  q.invalidate(1000);
  assert.deepEqual([q.state, q.latched], ["qualify_required", true]);
  q.invalidate(2000);
  const file = join(root, "qualification", "qualification.json");
  assert.deepEqual(JSON.parse(readFileSync(file, "utf8")), { v: 1, invalidated: { reason: "qualify_required", at_ms: 1000 } });
  for (const bad of [-1, 1.5, "1", NaN, null]) assert.throws(() => q.invalidate(bad), badForm, String(bad));
  // No way back here: nothing on the object clears it.
  assert.deepEqual(Object.getOwnPropertyNames(Qualification.prototype).sort(), ["constructor", "invalidate", "latched", "state"]);
  await store.close();
  store = await HostStore.open(root);
  assert.equal(store.qualification.state, "qualify_required");
  await store.close();
  // A hand-edited record that isn't the closed shape is refused, never read as qualified.
  writeFileSync(file, JSON.stringify({ v: 1, invalidated: null, extra: 1 }));
  store = await HostStore.open(root);
  assert.throws(() => store.qualification.state, badForm);
  await store.close();
});

test("qualification: the closed record shape", () => {
  assert.equal(checkQualification({ v: 1, invalidated: null }), true);
  assert.equal(checkQualification({ v: 1, invalidated: { reason: "qualify_required", at_ms: 0 } }), true);
  for (const r of [{}, { v: 2, invalidated: null }, { v: 1 }, { v: 1, invalidated: null, x: 1 }, { v: 1, invalidated: {} },
    { v: 1, invalidated: { reason: "other", at_ms: 1 } }, { v: 1, invalidated: { reason: "qualify_required", at_ms: -1 } },
    { v: 1, invalidated: { reason: "qualify_required", at_ms: 1.5 } }, { v: 1, invalidated: { reason: "qualify_required" } },
    { v: 1, invalidated: { reason: "qualify_required", at_ms: 1, version: "systemd 256" } }, { v: 1, invalidated: false }]) {
    assert.throws(() => checkQualification(r), badForm, JSON.stringify(r));
  }
});
