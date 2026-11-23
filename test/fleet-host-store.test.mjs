// Host supervisor freeze r3.1 §2.2, §3.3: the durable single-writer store under the registry and grant state. A commit
// whose candidate fails the closed-shape check is refused before any write: not poisoned, disk unchanged.
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { FleetError, refuse } from "../lib/fleet/index.mjs";
import { DurableState, exactKeys } from "../lib/fleet/host/store.mjs";

const check = (s) => { if (!exactKeys(s, ["n"]) || !Number.isSafeInteger(s.n)) refuse("bad_form", "shape"); return true; };

test("a candidate that fails the shape check is refused before writing; not poisoned; disk unchanged", async () => {
  const dir = join(mkdtempSync(join(tmpdir(), "sb-store-")), "s");
  const s = await DurableState.open(dir, "x.json", { check, initial: () => ({ n: 0 }) });
  assert.deepEqual(s.commit((c) => { c.n = 1; }), { n: 1 });
  const before = readFileSync(join(dir, "x.json"), "utf8");
  assert.throws(() => s.commit((c) => { c.extra = true; }), (e) => e instanceof FleetError && e.code === "bad_form");
  assert.throws(() => s.commit((c) => { c.n = "2"; }), (e) => e instanceof FleetError && e.code === "bad_form");
  assert.equal(s.poisoned, false);
  assert.equal(readFileSync(join(dir, "x.json"), "utf8"), before);
  assert.deepEqual(s.get(), { n: 1 });
  const copy = s.get(); copy.n = 99;
  assert.deepEqual(s.get(), { n: 1 }); // reads are copies
  await s.close();
});
