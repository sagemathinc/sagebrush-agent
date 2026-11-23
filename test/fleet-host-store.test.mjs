// Host supervisor freeze r3.1 §2.2, §3.3: the durable single-writer store under the registry and grant state. A commit
// whose candidate fails the closed-shape check is refused before any write: not poisoned, disk unchanged.
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { FleetError, refuse } from "../lib/fleet/index.mjs";
import { DurableState, exactKeys, lockDir } from "../lib/fleet/host/store.mjs";

const check = (s) => { if (!exactKeys(s, ["n"]) || !Number.isSafeInteger(s.n)) refuse("bad_form", "shape"); return true; };

test("a candidate that fails the shape check is refused before writing; not poisoned; disk unchanged", async () => {
  const root = mkdtempSync(join(tmpdir(), "sb-store-"));
  const lock = await lockDir(root);
  const dir = join(root, "s");
  const s = DurableState.attach(dir, "x.json", { check, initial: () => ({ n: 0 }), lock });
  assert.deepEqual(s.commit((c) => { c.n = 1; }), { n: 1 });
  const before = readFileSync(join(dir, "x.json"), "utf8");
  assert.throws(() => s.commit((c) => { c.extra = true; }), (e) => e instanceof FleetError && e.code === "bad_form");
  assert.throws(() => s.commit((c) => { c.n = "2"; }), (e) => e instanceof FleetError && e.code === "bad_form");
  assert.equal(s.poisoned, false);
  assert.equal(readFileSync(join(dir, "x.json"), "utf8"), before);
  assert.deepEqual(s.get(), { n: 1 });
  const copy = s.get(); copy.n = 99;
  assert.deepEqual(s.get(), { n: 1 }); // reads are copies
  await lock.release();
  assert.throws(() => s.get(), (e) => e instanceof FleetError && e.code === "in_progress");
});

test("attach refuses without a held lock: components never lock by themselves", async () => {
  const root = mkdtempSync(join(tmpdir(), "sb-store-"));
  assert.throws(() => DurableState.attach(join(root, "s"), "x.json", { check, initial: () => ({ n: 0 }) }), (e) => e instanceof FleetError && e.code === "in_progress");
  const lock = await lockDir(root);
  await lock.release();
  assert.throws(() => DurableState.attach(join(root, "s"), "x.json", { check, initial: () => ({ n: 0 }), lock }), (e) => e instanceof FleetError && e.code === "in_progress");
});
