// The console's restore commands run the launcher only after its bytes match the release's pin
// (lib/fleet/host/launcher.sha256): over a real temporary release, every refusal launches nothing.
import assert from "node:assert/strict";
import * as fs from "node:fs";
import { chmodSync, mkdirSync, mkdtempSync, renameSync, symlinkSync, unlinkSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "./host-linux-only.mjs";
import { FleetError } from "../lib/fleet/index.mjs";
import { LAUNCHER, LAUNCHER_PIN, checkLauncherPin, pinnedLauncherRunner } from "../lib/fleet/host/restore-adapters.mjs";

const UID = typeof process.getuid === "function" ? process.getuid() : -1; // (Linux-only rows; off Linux the file only loads)
const refused = (fn, code) => assert.throws(fn, (e) => e instanceof FleetError && e.code === code, code);
const BYTES = Buffer.from("#!/bin/sh\necho launcher\n");
const hex = (b) => createHash("sha256").update(b).digest("hex");

/** A release: bin/sagebrush-agent-launch (0755) and its pin (0644), every directory 0755. */
function release({ bytes = BYTES, pin = `${hex(BYTES)}  sagebrush-agent-launch\n` } = {}) {
  const r = mkdtempSync(join(tmpdir(), "sb-pin-"));
  chmodSync(r, 0o755);
  for (const d of ["bin", "lib", "lib/fleet", "lib/fleet/host"]) { mkdirSync(join(r, d), { mode: 0o755 }); chmodSync(join(r, d), 0o755); }
  writeFileSync(join(r, LAUNCHER), bytes);
  chmodSync(join(r, LAUNCHER), 0o755);
  writeFileSync(join(r, LAUNCHER_PIN), pin);
  chmodSync(join(r, LAUNCHER_PIN), 0o644);
  return r;
}

/** The runner over `r`, recording what it would run. */
function runner(r, more = {}) {
  const ran = [];
  const launch = pinnedLauncherRunner({ run: async (argv) => { ran.push(argv); return { code: 0, stdout: "" }; }, release: r, rootUid: UID, ...more });
  return { launch, ran };
}

test("the pinned launcher runs: its bytes match the pin (with or without the trailing newline); the check is made once per runner", async () => {
  for (const pin of [`${hex(BYTES)}  sagebrush-agent-launch\n`, `${hex(BYTES)}  sagebrush-agent-launch`]) {
    const r = release({ pin });
    let opens = 0;
    const fsx = { ...fs, openSync: (...a) => { opens += 1; return fs.openSync(...a); } };
    const { launch, ran } = runner(r, { fsx });
    await launch(["identify", "--anchor", "x"]);
    await launch(["remove-tree"]);
    assert.deepEqual(ran, [[join(r, LAUNCHER), "identify", "--anchor", "x"], [join(r, LAUNCHER), "remove-tree"]]);
    assert.equal(opens, 2, "the pin and the launcher, read once");
  }
});

test("every refusal (not_granted) launches nothing, on the first call and every later one", async () => {
  const cases = {
    "other bytes": () => release({ bytes: Buffer.from("#!/bin/sh\necho other\n") }),
    "the launcher missing": () => { const r = release(); unlinkSync(join(r, LAUNCHER)); return r; },
    "the launcher a link": () => { const r = release(); const real = join(r, "bin", "real"); renameSync(join(r, LAUNCHER), real); symlinkSync(real, join(r, LAUNCHER)); return r; },
    "the launcher 0775": () => { const r = release(); chmodSync(join(r, LAUNCHER), 0o775); return r; },
    "the launcher 0700": () => { const r = release(); chmodSync(join(r, LAUNCHER), 0o700); return r; },
    "the launcher setuid": () => { const r = release(); chmodSync(join(r, LAUNCHER), 0o4755); return r; },
    "bin/ group-writable": () => { const r = release(); chmodSync(join(r, "bin"), 0o775); return r; },
    "the pin missing": () => { const r = release(); unlinkSync(join(r, LAUNCHER_PIN)); return r; },
    "the pin a link": () => { const r = release(); const real = join(r, "lib", "pin"); renameSync(join(r, LAUNCHER_PIN), real); symlinkSync(real, join(r, LAUNCHER_PIN)); return r; },
    "the pin world-writable": () => { const r = release(); chmodSync(join(r, LAUNCHER_PIN), 0o646); return r; },
    "the pin's directory group-writable": () => { const r = release(); chmodSync(join(r, "lib/fleet/host"), 0o775); return r; },
    "the pin uppercase": () => release({ pin: `${hex(BYTES).toUpperCase()}  sagebrush-agent-launch\n` }),
    "the pin another name": () => release({ pin: `${hex(BYTES)}  sagebrush-agent\n` }),
    "the pin one space": () => release({ pin: `${hex(BYTES)} sagebrush-agent-launch\n` }),
    "the pin two lines": () => release({ pin: `${hex(BYTES)}  sagebrush-agent-launch\n${hex(BYTES)}  sagebrush-agent-launch\n` }),
    "the pin empty": () => release({ pin: "" }),
    "the pin too large": () => release({ pin: `${hex(BYTES)}  sagebrush-agent-launch\n${" ".repeat(5000)}` }),
  };
  for (const [what, make] of Object.entries(cases)) {
    const { launch, ran } = runner(make());
    for (let i = 0; i < 2; i += 1) assert.throws(() => launch(["identify"]), (e) => e instanceof FleetError && e.code === "not_granted", what);
    assert.deepEqual(ran, [], `${what}: nothing launched`);
  }
  // Another owner (the files are this test's, the expected owner another uid): refused.
  const { launch, ran } = runner(release(), { rootUid: UID + 1 });
  assert.throws(() => launch(["identify"]), (e) => e instanceof FleetError && e.code === "not_granted");
  assert.deepEqual(ran, []);
});

test("a launcher replaced between its lstat and its open (another object at the name) refuses", () => {
  const r = release();
  const other = join(r, "bin", "other");
  writeFileSync(other, BYTES);
  chmodSync(other, 0o755);
  const fsx = { ...fs, openSync: (p, ...a) => (p === join(r, LAUNCHER) ? fs.openSync(other, ...a) : fs.openSync(p, ...a)) };
  refused(() => checkLauncherPin(r, { rootUid: UID, fsx }), "not_granted");
  // A launcher cut short while it is read.
  const short = { ...fs, readSync: (fd, buf, off, len, pos) => (len > 4 ? fs.readSync(fd, buf, off, 4, pos) && 0 : fs.readSync(fd, buf, off, len, pos)) };
  refused(() => checkLauncherPin(r, { rootUid: UID, fsx: short }), "not_granted");
  // The release root must be absolute.
  assert.throws(() => pinnedLauncherRunner({ run: async () => ({}), release: "relative" }), (e) => e instanceof FleetError && e.code === "bad_form");
});

test("this tree's own pin is well-formed (the shape the check reads)", () => {
  const pin = fs.readFileSync(new URL(`../${LAUNCHER_PIN}`, import.meta.url), "utf8");
  assert.match(pin, /^[0-9a-f]{64} {2}sagebrush-agent-launch\n?$/);
});

test("the console's restore ops run the launcher only through the pinned runner: close's stage removal over an unpinned release launches nothing", async () => {
  const { realRestoreOps } = await import("../lib/fleet/host/restore-cli.mjs");
  const { newRestoreRun } = await import("../lib/fleet/host/restore-record.mjs");
  const run = newRestoreRun(1795500000000, () => Buffer.alloc(6));
  // A staged host-store attempt, so the removal needs the launcher (identify, then remove-tree).
  const staging = mkdtempSync(join(tmpdir(), "sb-pin-stage-"));
  mkdirSync(join(staging, run, "host", "hoststore", "1"), { recursive: true });
  const ran = [];
  const ops = realRestoreOps({ release: release({ bytes: Buffer.from("tampered") }), staging, enabled: () => ({ enabled: false }),
    run: async (argv) => { ran.push(argv); return { code: 0, stdout: `${JSON.stringify({ object: null })}\n` }; } });
  await assert.rejects(ops.removeHostStage(run), (e) => e instanceof FleetError && e.code === "not_granted");
  assert.deepEqual(ran, [], "nothing launched");
});

test("each check alone (the others passing): the file's owner, its kind, the no-follow open, the size bound before any open, a refusal kept", async () => {
  const L = (r) => join(r, LAUNCHER);
  const lie = (r, name, over) => ({ ...fs, lstatSync: (p, ...a) => { const st = fs.lstatSync(p, ...a); return p === join(r, name) ? Object.assign(Object.create(Object.getPrototypeOf(st)), st, over(st)) : st; } });
  // The launcher's owner alone another uid (its directory and the pin root's).
  { const r = release(); refused(() => checkLauncherPin(r, { rootUid: UID, fsx: lie(r, LAUNCHER, () => ({ uid: UID + 1 })) }), "not_granted"); }
  // The launcher's lstat a link (owner and mode as a file's): the kind alone refuses.
  { const r = release(); refused(() => checkLauncherPin(r, { rootUid: UID, fsx: lie(r, LAUNCHER, () => ({ isFile: () => false, isSymbolicLink: () => true })) }), "not_granted"); }
  // Both opens are no-follow.
  {
    const r = release();
    const flags = [];
    checkLauncherPin(r, { rootUid: UID, fsx: { ...fs, openSync: (p, f, ...a) => { flags.push(f); return fs.openSync(p, f, ...a); } } });
    assert.equal(flags.length, 2);
    for (const f of flags) assert.equal(f & fs.constants.O_NOFOLLOW, fs.constants.O_NOFOLLOW);
  }
  // A pin larger than its bound is refused before anything is opened.
  {
    const r = release();
    let opens = 0;
    const fsx = { ...lie(r, LAUNCHER_PIN, () => ({ size: 5000 })), openSync: (...a) => { opens += 1; return fs.openSync(...a); } };
    refused(() => checkLauncherPin(r, { rootUid: UID, fsx }), "not_granted");
    assert.equal(opens, 0);
  }
  // A refusal holds for the runner's later calls, even once the release is put right.
  {
    const r = release();
    chmodSync(L(r), 0o775);
    const { launch, ran } = runner(r);
    assert.throws(() => launch(["identify"]), (e) => e instanceof FleetError && e.code === "not_granted");
    chmodSync(L(r), 0o755);
    assert.throws(() => launch(["identify"]), (e) => e instanceof FleetError && e.code === "not_granted");
    assert.deepEqual(ran, []);
  }
});
