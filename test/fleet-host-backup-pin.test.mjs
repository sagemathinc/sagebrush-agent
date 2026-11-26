// The backup binary runs as root only once its bytes match the release's pin (lib/fleet/host/backup.sha256): the
// pinned runner realBackupBinary, over a real temporary release; and a source census that it is the ONE production
// path to the binary (a closed allowlist names the launcher's own restore-stage exec, outside Node).
import assert from "node:assert/strict";
import * as fs from "node:fs";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "./host-linux-only.mjs";
import { FleetError } from "../lib/fleet/index.mjs";
import { BACKUP_BIN, BACKUP_PIN, realBackupBinary } from "../lib/fleet/host/backup-binary.mjs";

const UID = typeof process.getuid === "function" ? process.getuid() : -1; // (Linux-only rows; off Linux the file only loads)
const REPO = fileURLToPath(new URL("..", import.meta.url));
const hex = (b) => createHash("sha256").update(b).digest("hex");
const notGranted = (e) => e instanceof FleetError && e.code === "not_granted";

/** A release whose bin/sagebrush-agent-backup is a script that marks each run and answers `snapshots`. */
function release({ pinOf = (b) => hex(b), mode = 0o755 } = {}) {
  const r = mkdtempSync(join(tmpdir(), "sb-bpin-"));
  chmodSync(r, 0o755);
  for (const d of ["bin", "lib", "lib/fleet", "lib/fleet/host"]) { mkdirSync(join(r, d), { mode: 0o755 }); chmodSync(join(r, d), 0o755); }
  const marker = join(r, "ran");
  const bytes = Buffer.from(`#!/bin/sh\ncat >/dev/null\necho x >> ${marker}\necho '{"ok":true,"snapshots":[]}'\n`);
  writeFileSync(join(r, BACKUP_BIN), bytes);
  chmodSync(join(r, BACKUP_BIN), mode);
  writeFileSync(join(r, BACKUP_PIN), `${pinOf(bytes)}  sagebrush-agent-backup\n`);
  chmodSync(join(r, BACKUP_PIN), 0o644);
  return { r, marker, runs: () => (existsSync(marker) ? readFileSync(marker, "utf8").split("\n").filter(Boolean).length : 0) };
}

test("the pinned runner: a matching binary runs (its files checked once for every call); every refusal runs nothing, then or later", async () => {
  const ok = release();
  const bin = realBackupBinary(ok.r, { rootUid: UID });
  const a = await bin({ op: "snapshots" }, { ms: 10_000 });
  const b = await bin({ op: "snapshots" }, { ms: 10_000 });
  assert.equal(a.ok, true, JSON.stringify(a));
  assert.equal(b.ok, true);
  assert.equal(ok.runs(), 2);
  const cases = {
    "other bytes": release({ pinOf: () => "0".repeat(64) }),
    "the binary 0775": release({ mode: 0o775 }),
    "the binary setuid": release({ mode: 0o4755 }),
  };
  for (const [what, x] of Object.entries(cases)) {
    const run = realBackupBinary(x.r, { rootUid: UID });
    for (let i = 0; i < 2; i += 1) assert.throws(() => run({ op: "snapshots" }, { ms: 10_000 }), notGranted, what);
    assert.equal(x.runs(), 0, `${what}: nothing ran`);
  }
  // Another owner: refused.
  const other = release();
  assert.throws(() => realBackupBinary(other.r, { rootUid: UID + 1 })({ op: "snapshots" }, { ms: 10_000 }), notGranted);
  assert.equal(other.runs(), 0);
  // A refusal holds once the release is put right.
  const later = release({ mode: 0o775 });
  const run = realBackupBinary(later.r, { rootUid: UID });
  assert.throws(() => run({ op: "snapshots" }, { ms: 10_000 }), notGranted);
  chmodSync(join(later.r, BACKUP_BIN), 0o755);
  assert.throws(() => run({ op: "snapshots" }, { ms: 10_000 }), notGranted);
  assert.equal(later.runs(), 0);
  assert.throws(() => realBackupBinary("relative"), (e) => e instanceof FleetError && e.code === "bad_form");
});

test("this tree's backup pin is well-formed", () => {
  assert.match(readFileSync(join(REPO, BACKUP_PIN), "utf8"), /^[0-9a-f]{64} {2}sagebrush-agent-backup\n?$/);
});

// ---- the census: the ONE production path to the binary ----

/** Every production source file under lib/ and bin/ (.mjs) and launcher/src (.rs), with its non-comment lines. */
function sources() {
  const out = [];
  const walk = (d, ext) => {
    for (const n of readdirSync(d, { withFileTypes: true })) {
      const p = join(d, n.name);
      if (n.isDirectory()) walk(p, ext);
      else if (n.name.endsWith(ext)) out.push({ file: relative(REPO, p), lines: readFileSync(p, "utf8").split("\n").filter((l) => !/^\s*(\/\/|\*|\/\*)/.test(l)) });
    }
  };
  walk(join(REPO, "lib"), ".mjs");
  walk(join(REPO, "bin"), ".mjs");
  walk(join(REPO, "launcher/src"), ".rs");
  return out;
}
/** The closed allowlist: the files outside backup-binary.mjs that may name the binary, each with why. */
const ALLOWED = Object.freeze({
  "launcher/src/child.rs": "the launcher's own restore-stage exec (bound by the launcher's pin and its bin/ binding)",
  "launcher/src/restore.rs": "a launcher test's release layout (in its #[cfg(test)] module)",
});
function census(files, allowed = ALLOWED) {
  const bad = [];
  for (const { file, lines } of files) {
    if (file === "lib/fleet/host/backup-binary.mjs") continue;
    const calls = lines.some((l) => /\brunBackupOp\s*\(/.test(l) || /import\s*\{[^}]*\brunBackupOp\b/.test(l));
    const names = lines.some((l) => l.includes("sagebrush-agent-backup") || /\bBACKUP_BIN\b/.test(l));
    if (calls) bad.push(`${file}: calls runBackupOp`);
    else if (names && !Object.hasOwn(allowed, file)) bad.push(`${file}: names the binary`);
  }
  return bad;
}

test("the census: only realBackupBinary reaches runBackupOp in production; the binary is named only by the closed allowlist", () => {
  const files = sources();
  assert.deepEqual(census(files), []);
  // Every allowlisted file still names it (a stale entry is caught too).
  for (const f of Object.keys(ALLOWED)) assert.ok(files.find((x) => x.file === f)?.lines.some((l) => l.includes("sagebrush-agent-backup")), `${f} still names the binary`);
  // Controls: another Node caller that bypasses realBackupBinary; a raw spawn by name; an unlisted Rust exception.
  const extra = (file, line) => [...files, { file, lines: [line] }];
  assert.deepEqual(census(extra("lib/fleet/host/x.mjs", "  const r = await runBackupOp(req, ctx, { ms });")), ["lib/fleet/host/x.mjs: calls runBackupOp"]);
  assert.deepEqual(census(extra("lib/fleet/host/y.mjs", 'import { runBackupOp } from "./backup-binary.mjs";')), ["lib/fleet/host/y.mjs: calls runBackupOp"]);
  assert.deepEqual(census(extra("lib/fleet/host/z.mjs", 'spawn(`${release}/bin/sagebrush-agent-backup`, argv);')), ["lib/fleet/host/z.mjs: names the binary"]);
  assert.deepEqual(census(extra("launcher/src/other.rs", 'Command::new("sagebrush-agent-backup")')), ["launcher/src/other.rs: names the binary"]);
});
