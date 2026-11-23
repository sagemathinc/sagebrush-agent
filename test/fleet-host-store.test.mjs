// Host supervisor freeze r3.1 §2.2, §3.3: the durable single-writer store under the registry and grant state. A commit
// whose candidate fails the closed-shape check is refused before any write: not poisoned, disk unchanged.
import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "./host-linux-only.mjs";
import { FleetError, refuse } from "../lib/fleet/index.mjs";
import { DurableState, exactKeys, lockDir, writeDurable } from "../lib/fleet/host/store.mjs";

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

test("writeDurable sets the requested mode exactly, whatever the umask, even over a crashed write's leftover temp", () => {
  const dir = mkdtempSync(join(tmpdir(), "sb-store-mode-"));
  const old = process.umask(0o077);
  try {
    writeDurable(dir, "unit.service", "a\n", undefined, 0o644);
    assert.equal(statSync(join(dir, "unit.service")).mode & 0o777, 0o644);
    writeDurable(dir, "state.json", "b\n");
    assert.equal(statSync(join(dir, "state.json")).mode & 0o777, 0o600);
    // A temp file left by a crashed write, with a wider mode: open keeps that mode, so the fchmod must set it.
    const tmp = join(dir, `.secret.json.${process.pid}.tmp`);
    writeFileSync(tmp, "stale");
    chmodSync(tmp, 0o666);
    writeDurable(dir, "secret.json", "c\n");
    assert.equal(statSync(join(dir, "secret.json")).mode & 0o777, 0o600);
    assert.equal(readFileSync(join(dir, "secret.json"), "utf8"), "c\n");
  } finally { process.umask(old); }
});
