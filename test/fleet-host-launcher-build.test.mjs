// scripts/launcher-build.sh's toolchain closure, exactly scripts/backup-build.sh's (host backup init/run d6 §4.1) for the
// linker (the launcher is pure Rust, linked through gcc-13 and binutils): the pinned packages and versions refuse any other, every tool is named by path, cargo runs under
// `env -i` with a closed list of variables, and a cargo config file anywhere cargo would read one refuses. Over a copy
// of the real script whose tool directory is a mock one; the mock cargo logs the environment it was given and exits
// 97, before any build.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "./host-linux-only.mjs";

const SCRIPT = readFileSync(fileURLToPath(new URL("../scripts/launcher-build.sh", import.meta.url)), "utf8");
const exe = (p, body) => { writeFileSync(p, `#!/bin/sh\n${body}\n`); chmodSync(p, 0o755); };
const PINNED = { "gcc-13": "13.3.0-6ubuntu2~24.04.1", binutils: "2.42-4ubuntu2.10" };

/** A world: root/scripts/launcher-build.sh (its TOOLS the mock directory), the mock tools, a cargo home with mock cargo and rustc. */
function world({ versions = PINNED, rustc = "1.99.0", gcc13 = "13.3.0" } = {}) {
  const w = mkdtempSync(join(tmpdir(), "sb-lbuild-"));
  const root = join(w, "root"), tools = join(w, "tools"), home = join(w, "home"), cargoHome = join(w, "cargo");
  for (const d of [join(root, "scripts"), join(root, "launcher"), tools, home, join(cargoHome, "bin")]) mkdirSync(d, { recursive: true });
  assert.equal(SCRIPT.split("\nTOOLS=/usr/bin\n").length, 2, "the script names its tool directory once");
  writeFileSync(join(root, "scripts/launcher-build.sh"), SCRIPT.replace("\nTOOLS=/usr/bin\n", `\nTOOLS=${tools}\n`));
  exe(join(root, "scripts/backup-static-check.sh"), "exit 0");
  writeFileSync(join(root, "launcher/Cargo.toml"), "");
  const cases = Object.entries(versions).map(([p, v]) => `  ${p}) printf %s '${v}' ;;`).join("\n");
  exe(join(tools, "dpkg-query"), `for a; do last=$a; done\ncase "$last" in\n${cases}\n  *) exit 1 ;;\nesac`);
  exe(join(tools, "gcc-13"), `echo ${gcc13}`);
  const log = join(w, "cargo-env");
  exe(join(cargoHome, "bin/rustc"), `echo "rustc ${rustc} (mock)"`);
  exe(join(cargoHome, "bin/cargo"), `env > '${log}'\nexit 97`);
  return { w, root, tools, home, cargoHome, log };
}

/** Run the copy with the caller's environment `extra` (plus HOME and CARGO_HOME). */
function build(x, extra = {}) {
  const env = { PATH: process.env.PATH, HOME: x.home, CARGO_HOME: x.cargoHome, RUSTUP_HOME: join(x.home, ".rustup"), ...extra };
  return spawnSync("sh", [join(x.root, "scripts/launcher-build.sh"), join(x.w, "out")], { env, encoding: "utf8" });
}
const envOf = (x) => Object.fromEntries(readFileSync(x.log, "utf8").split("\n").filter(Boolean).map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1)]));

const HOSTILE = {
  CC: "/usr/bin/clang", TARGET_CC: "/usr/bin/clang", REALGCC: "/usr/bin/clang",
  RUSTFLAGS: "-C opt-level=0", CARGO_ENCODED_RUSTFLAGS: "-Copt-level=0", RUSTC_WRAPPER: "/usr/bin/sccache", RUSTC: "/usr/bin/rustc",
  CARGO_BUILD_RUSTFLAGS: "-Copt-level=0", CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER: "/usr/bin/clang", CARGO_BUILD_TARGET_DIR: "/tmp/x",
  CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS: "-Copt-level=0", RUSTUP_TOOLCHAIN: "nightly", SOURCE_DATE_EPOCH: "1", LD_PRELOAD: "/tmp/evil.so",
};

test("the launcher's build reaches cargo with exactly the recipe's variables; no inherited override survives", () => {
  const x = world();
  const r = build(x, HOSTILE);
  assert.equal(r.status, 97, `cargo reached (${r.stderr})`);
  const e = envOf(x);
  assert.deepEqual(Object.keys(e).filter((k) => k !== "PWD" && k !== "SHLVL" && k !== "_").sort(), [
    "CARGO_HOME", "CARGO_INCREMENTAL", "CARGO_TARGET_DIR", "CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER", "HOME", "PATH", "RUSTC",
    "RUSTFLAGS", "RUSTUP_HOME", "RUSTUP_TOOLCHAIN", "SOURCE_DATE_EPOCH",
  ]);
  assert.equal(e.CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER, join(x.tools, "gcc-13"), "the pinned linker, never the caller's");
  assert.equal(e.RUSTC, join(x.cargoHome, "bin/rustc"));
  assert.equal(e.RUSTUP_TOOLCHAIN, "1.99.0");
  assert.equal(e.SOURCE_DATE_EPOCH, "0");
  assert.equal(e.PATH, `${x.tools}:/bin`);
  assert.equal(e.PWD, x.root, "cargo runs from the source root");
  assert.ok(!e.RUSTFLAGS.includes("opt-level"), "the recipe's RUSTFLAGS only");
  // The control: the same world with no hostile variables reaches cargo with the same keys.
  const y = world();
  assert.equal(build(y).status, 97);
  assert.deepEqual(Object.keys(envOf(y)).sort(), Object.keys(e).sort());
});

test("any other toolchain version, or a missing package, refuses before cargo", () => {
  const cases = {
    "gcc-13": { versions: { ...PINNED, "gcc-13": "13.3.0-6ubuntu2~24.04.2" } },
    binutils: { versions: { ...PINNED, binutils: "2.42-4ubuntu2.11" } },
    "binutils missing": { versions: { "gcc-13": PINNED["gcc-13"] } },
    "gcc-13 missing": { versions: { binutils: PINNED.binutils } },
    "gcc-13 runs another gcc": { gcc13: "15.2.0" },
    rustc: { rustc: "1.98.0" },
  };
  for (const [what, opts] of Object.entries(cases)) {
    const x = world(opts);
    const r = build(x);
    assert.equal(r.status, 1, `${what}: refused (${r.stderr})`);
    assert.match(r.stderr, /^launcher-build: /m);
    assert.equal(existsSync(x.log), false, `${what}: cargo never ran`);
  }
});

test("a cargo config file anywhere cargo would read one refuses before cargo", () => {
  for (const where of ["home config.toml", "home config", "root .cargo/config.toml", "a parent's .cargo/config"]) {
    const x = world();
    if (where === "home config.toml") writeFileSync(join(x.cargoHome, "config.toml"), '[target.x86_64-unknown-linux-musl]\nlinker = "clang"\n');
    else if (where === "home config") writeFileSync(join(x.cargoHome, "config"), "");
    else if (where === "root .cargo/config.toml") { mkdirSync(join(x.root, ".cargo")); writeFileSync(join(x.root, ".cargo/config.toml"), "[build]\nrustflags = []\n"); }
    else { mkdirSync(join(x.w, ".cargo")); writeFileSync(join(x.w, ".cargo/config"), ""); }
    const r = build(x);
    assert.equal(r.status, 1, `${where}: refused (${r.stderr})`);
    assert.match(r.stderr, /a cargo config file would steer the build/);
    assert.equal(existsSync(x.log), false, `${where}: cargo never ran`);
  }
});
