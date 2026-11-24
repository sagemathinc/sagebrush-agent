// Host backup r3.3 §3, §4: the host store's copy, under the host-store lock, of an allowlist of its entries only.
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "./host-linux-only.mjs";
import { FleetError } from "../lib/fleet/index.mjs";
import { HOSTSTORE_INCLUDE, copyHostStore } from "../lib/fleet/host/backup-hoststore.mjs";

const refused = (fn, code) => assert.throws(fn, (e) => e instanceof FleetError && e.code === code, code);

function store() {
  const root = mkdtempSync(join(tmpdir(), "sb-bhs-"));
  const s = join(root, "store");
  for (const d of ["registry", "grant", "pool", "profiles", "deprovision", "provisioned", "audit/2026"]) mkdirSync(join(s, d), { recursive: true });
  writeFileSync(join(s, "registry", "registry.json"), '{"v":1}');
  writeFileSync(join(s, "registry", ".registry.json.123.tmp"), "half");
  writeFileSync(join(s, "grant", "grant.json"), '{"g":1}');
  writeFileSync(join(s, "pool", "pool.json"), "{}");
  writeFileSync(join(s, "profiles", "profiles.json"), "{}");
  writeFileSync(join(s, "audit", "2026", "a.log"), "x".repeat(10));
  writeFileSync(join(s, ".lock"), "");
  return { root, s, staging: join(root, "staging") };
}

test("only the allowlisted entries are copied, whole, 0700/0600; temp files and the lock are not", () => {
  const { s, staging } = store();
  const r = copyHostStore(s, staging, { held: () => true });
  assert.deepEqual(r, { files: 3, bytes: 7 + 7 + 10, entries: ["registry", "grant", "audit"] });
  assert.equal(readFileSync(join(staging, "registry", "registry.json"), "utf8"), '{"v":1}');
  for (const never of ["pool", "profiles", "deprovision", "provisioned", ".lock", "registry/.registry.json.123.tmp"]) assert.equal(existsSync(join(staging, never)), false, never);
  assert.equal(statSync(staging).mode & 0o777, 0o700);
  assert.equal(statSync(join(staging, "registry", "registry.json")).mode & 0o777, 0o600);
  assert.ok(!HOSTSTORE_INCLUDE.some((n) => ["pool", "profiles", "deprovision", "provisioned"].includes(n)));
});

test("refused without the host-store lock, before anything is written, and if the lock is lost during the copy", () => {
  const { s, staging } = store();
  refused(() => copyHostStore(s, staging, { held: () => false }), "not_granted");
  assert.equal(existsSync(staging), false);
  refused(() => copyHostStore(s, staging, {}), "not_granted");
  let n = 0;
  refused(() => copyHostStore(s, staging, { held: () => n++ === 0 }), "not_granted");
});

test("an existing staging directory, a link in the store, or a store too large: refused", () => {
  {
    const { s, staging } = store();
    mkdirSync(staging);
    assert.throws(() => copyHostStore(s, staging, { held: () => true }), (e) => e.code === "EEXIST");
  }
  {
    const { s, staging } = store();
    symlinkSync("/etc/shadow", join(s, "registry", "evil.json"));
    refused(() => copyHostStore(s, staging, { held: () => true }), "bad_form");
  }
  {
    const { s, staging } = store();
    refused(() => copyHostStore(s, staging, { held: () => true, maxFiles: 2 }), "limit");
  }
});
