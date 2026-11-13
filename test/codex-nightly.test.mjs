// The nightly check (scripts/codex-nightly.mjs): upstream's newest Codex against the contract; a red alerts us, a
// green or the same version alerts nobody, and nothing users get is ever changed. The registry and Codex are stand-ins.
import { test } from "node:test";
const T = { timeout: 20000 }; // (a row that hangs fails by name)
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { alertText, nightly, runNightly } from "../scripts/codex-nightly.mjs";

const defs = () => JSON.parse(readFileSync(new URL("./fixtures/codex-schema-0.163.0.json", import.meta.url), "utf8")).definitions;
const broken = () => { const d = defs(); delete d.ThreadStartResponse; return d; };
const deps = (newestCodex, schema) => ({ latest: async (pkg) => (pkg === "@openai/codex" ? newestCodex : "9.9.9"), codexBinary: async () => "/x/codex", schemaOf: async () => schema() });
const shipped = () => ["lib/codex-pin.json", "lib/codex-contract.json", "lib/codex-selftest.mjs", "lib/codex-fetch.mjs", "lib/codex.mjs"].map((f) => createHash("sha256").update(readFileSync(new URL(`../${f}`, import.meta.url))).digest("hex"));

test("the same version as pinned: nothing to check, not red", T, async () => {
  const r = await nightly({ work: tmpdir(), pinned: "0.159.2", deps: deps("0.159.2", defs) });
  assert.equal(r.codex.result, "same");
  assert.equal(r.red, false);
});

test("a newer Codex whose protocol still fits: green", T, async () => {
  const r = await nightly({ work: tmpdir(), pinned: "0.159.2", deps: deps("0.163.0", defs) });
  assert.deepEqual([r.codex.newest, r.codex.result, r.red], ["0.163.0", "green", false]);
  assert.equal(r.claudeSdk.newest, "9.9.9");
});

test("a newer Codex that breaks the contract: red, with what broke", T, async () => {
  const r = await nightly({ work: tmpdir(), pinned: "0.159.2", deps: deps("0.170.0", broken) });
  assert.equal(r.red, true);
  assert.ok(r.codex.problems.includes("no ThreadStartResponse"));
  assert.match(alertText(r), /Codex 0\.170\.0 \(pinned 0\.159\.2\) is RED\.\n- no ThreadStartResponse/);
});

test("a check that can't run (the registry fails) is red, never silent", T, async () => {
  const r = await nightly({ work: tmpdir(), deps: { latest: async () => { throw new Error("HTTP 503"); }, codexBinary: async () => "/x", schemaOf: async () => defs() } });
  assert.equal(r.red, true);
  assert.match(r.codex.problems[0], /couldn't run: HTTP 503/);
});

test("a red alerts (the command gets the message file); a green writes its report and alerts nobody; nothing shipped changes", T, async () => {
  const before = shipped();
  for (const [schema, red] of [[broken, true], [defs, false]]) {
    const out = mkdtempSync(join(tmpdir(), "nightly-"));
    try {
      const marker = join(out, "ALERTED");
      const r = await runNightly({ out, pinned: "0.159.2", alert: `cp "$1" "${marker}"`, deps: deps("0.170.0", schema) });
      assert.equal(r.red, red);
      assert.equal(existsSync(marker), red, red ? "alerted" : "no alert");
      if (red) assert.equal(readFileSync(marker, "utf8"), alertText(r) + "\n");
      assert.ok(existsSync(join(out, `codex-nightly-${r.at.slice(0, 10)}.json`)));
    } finally { rmSync(out, { recursive: true, force: true }); }
  }
  assert.deepEqual(shipped(), before, "the pin, the contract and the code are untouched");
});
