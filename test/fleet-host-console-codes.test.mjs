// The host console's codes, mechanically: every line `host backup init` and `host backup attach` print refuses with a
// code from schema/fleet/reasons.json or from CONSOLE_CODES (the backup binary's own codes and its local failures,
// never `aborted`). Each binary call of each command, in a first run and in the recoveries after it, answers every
// code the binary can give (and a raw throw), over real temporary directories and the real exclusion.
import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "./host-linux-only.mjs";
import { CODES, CONSOLE_CODES, LOCAL_CODES } from "../lib/fleet/host/backup-binary.mjs";
import { backupInitCommand, groupsOf } from "../lib/fleet/host/backup-init.mjs";
import { backupAttachCommand } from "../lib/fleet/host/backup-attach.mjs";

const UID = typeof process.getuid === "function" ? process.getuid() : -1; // (Linux-only rows; off Linux the file only loads)
const REASONS = new Set(JSON.parse(readFileSync(fileURLToPath(new URL("../schema/fleet/reasons.json", import.meta.url)), "utf8")).reasons.map((r) => r.name));
const CODE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DEST = { type: "s3", endpoint: "https://s3.example.com", bucket: "b-1", prefix: "host/x", region: "us-east-1" };
const CRED = { access_key_id: "AKIDEXAMPLE", secret_access_key: "s3cr3t-value" };
const ANSWERS = [...CODES, ...LOCAL_CODES, "throw"];

/**
 * A world for `which`: a fake repository opened by host.key's first line (attach: one with the code's slot; init:
 * none yet). `fault` = { at, answer }: the at-th binary call of the run in which it is armed answers `answer` (a code,
 * or a raw throw), as a failed call would; every other call answers as the repository would.
 */
function world(which) {
  const base = mkdtempSync(join(tmpdir(), `sb-codes-${which}-`));
  const state = join(base, "backup", "state"), secrets = join(base, "host-secrets");
  if (which === "attach") { mkdirSync(join(base, "backup"), { mode: 0o700 }); chmodSync(join(base, "backup"), 0o700); }
  const repo = { exists: which === "attach", slots: which === "attach" ? [CODE] : [], n: 0, fault: null };
  const pw = (f) => { try { return readFileSync(f, "utf8").split("\n")[0]; } catch { return null; } };
  const binary = async (req) => {
    const i = repo.n++;
    if (repo.fault && i === repo.fault.at) {
      if (repo.fault.answer === "throw") throw Object.assign(new Error("EIO"), { code: "EIO" });
      return { ok: false, code: repo.fault.answer };
    }
    const key = pw(join(state, "host.key"));
    if (req.op === "init") {
      if (repo.exists) return { ok: false, code: "repository_exists" };
      Object.assign(repo, { exists: true, slots: [key] });
      return { ok: true, value: { initialized: true } };
    }
    if (!repo.exists) return { ok: false, code: "repository_missing" };
    if (!repo.slots.includes(key)) return { ok: false, code: "open_failed" };
    if (req.op === "add-key") repo.slots.push(pw(req.password_file));
    return { ok: true, value: req.op === "snapshots" ? { snapshots: [] } : { key: "k" } };
  };
  const tty = { write() {}, ask: async (p) => { const [a, b] = p.match(/group (\d) and group (\d)/).slice(1).map(Number); const g = groupsOf(readFileSync(join(state, "init-code.key"), "utf8").trim()); return `${g[a - 1]} ${g[b - 1]}`; } };
  const input = which === "attach" ? { v: 1, dest: DEST, credential: CRED, backup_code: CODE } : { v: 1, dest: DEST, credential: CRED };
  const deps = { uid: () => UID, rootUid: UID, state, secrets, rand: (n) => Buffer.alloc(n, 7), release: "/opt/sagebrush-agent",
    stdin: async () => Buffer.from(JSON.stringify(input)), exclusion: { path: join(base, "x.lock"), uid: UID, waitMs: 0 },
    binary, enabled: () => false, restoreOpen: () => false, tty, units: async () => {} };
  const run = () => (which === "attach" ? backupAttachCommand(["attach"], deps) : backupInitCommand(["init"], deps));
  return { repo, run };
}

for (const which of ["init", "attach"]) {
  test(`${which}: every line's code is a registered reason or a console code, whatever any binary call answers, in a first run and in recovery`, { timeout: 600_000 }, async () => {
    const seen = new Set();
    let lines = 0;
    for (const recovery of [false, true]) {
      for (let at = 0; at < 4; at += 1) {
        for (const answer of ANSWERS) {
          const w = world(which);
          // In recovery: a first run fails at its add-key (a transient code), so the fault lands on the recovery's calls.
          if (recovery) {
            w.repo.fault = { at: 1, answer: "destination_unavailable" };
            await w.run();
            w.repo.n = 0;
          }
          w.repo.fault = { at, answer };
          const outs = [await w.run()];
          w.repo.fault = null;
          for (let k = 0; k < 3 && outs.at(-1).code !== 0; k += 1) outs.push(await w.run()); // (recover, as a person would rerun)
          for (const out of outs) {
            lines += 1;
            assert.ok(out.code === 0 || out.code === 1, JSON.stringify(out));
            if (out.code === 0) continue;
            const c = out.line.refused;
            seen.add(c);
            assert.ok(REASONS.has(c) || CONSOLE_CODES.includes(c), `${which}: call ${at} answering ${answer}${recovery ? " (recovery)" : ""}: ${c} is neither registered nor a console code`);
            assert.notEqual(c, "aborted");
            assert.notEqual(c, "error");
          }
        }
      }
    }
    assert.ok(lines > ANSWERS.length * 8, `${lines} lines checked`);
    // The diagnostics are kept: a transient code reaches the line as itself, and a raw throw is outcome_unknown.
    for (const c of ["destination_unavailable", "outcome_unknown"]) assert.ok(seen.has(c), `${c} seen`);
  });
}

test("the console set: exactly the binary's codes and its local failures, without aborted; none is a registered reason", () => {
  assert.deepEqual([...CONSOLE_CODES].sort(), [...CODES, ...LOCAL_CODES].filter((c) => c !== "aborted").sort());
  assert.equal(new Set(CONSOLE_CODES).size, CONSOLE_CODES.length);
  for (const c of CONSOLE_CODES) assert.equal(REASONS.has(c), false, `${c} would be ambiguous with a registered reason`);
});

test("restore's lines: list answering every binary code, and a raw throw from list, begin or close, each refuse with a registered reason or a console code", async () => {
  const { restoreCommand } = await import("../lib/fleet/host/restore-cli.mjs");
  const base = mkdtempSync(join(tmpdir(), "sb-codes-restore-"));
  const deps = { uid: () => UID, rootUid: UID, dir: join(base, "restore"), fenceDir: join(base, "fence"), exclusion: { path: join(base, "x.lock"), uid: UID, waitMs: 0 } };
  const check = (out, what) => {
    assert.equal(out.code, 1, what);
    const c = out.line.refused;
    assert.ok(REASONS.has(c) || CONSOLE_CODES.includes(c), `${what}: ${c} is neither registered nor a console code`);
    assert.notEqual(c, "aborted");
    assert.notEqual(c, "error");
    return c;
  };
  for (const answer of [...CODES, ...LOCAL_CODES]) {
    const c = check(await restoreCommand(["list"], { ...deps, ops: { list: async () => ({ error: answer }) } }), `list: ${answer}`);
    if (answer !== "aborted") assert.equal(c, answer, "a binary code is kept as the diagnostic it is");
  }
  const raw = async () => { throw Object.assign(new Error("EIO"), { code: "EIO" }); };
  assert.equal(check(await restoreCommand(["list"], { ...deps, ops: { list: raw } }), "list throws"), "outcome_unknown");
  assert.equal(check(await restoreCommand(["begin", "a".repeat(64)], { ...deps, ops: { begin: raw } }), "begin throws"), "outcome_unknown");
  mkdirSync(deps.dir, { mode: 0o700 });
  chmodSync(deps.dir, 0o700);
  writeFileSync(join(deps.dir, "begin.json"), "{", { mode: 0o600 });
  check(await restoreCommand(["close"], { ...deps, removeHostStage: raw }), "close over a malformed begin");
});
