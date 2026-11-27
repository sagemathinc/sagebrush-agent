#!/bin/sh
# The backup binary's ONE reproducible build: the bytes a release ships as bin/sagebrush-agent-backup, pinned by
# lib/fleet/host/backup.sha256, which the root installer and the pinned runner (realBackupBinary) check.
#
#   scripts/backup-build.sh <out>
#
# The launcher's recipe (scripts/launcher-build.sh): rust 1.99.0, target x86_64-unknown-linux-musl (static), --locked
# --offline --release; the source, the target directory and cargo's home remapped to fixed names; SOURCE_DATE_EPOCH=0;
# no build id. The binary also compiles C (zstd and aws-lc, through cc), so the same remapping is given to the C
# compiler (-ffile-prefix-map), so no build path reaches an object. The dependencies must already be in cargo's cache
# (`cargo fetch --locked` first): the build itself never touches the network. Two builds from two directories must be
# byte-identical (the CI job checks it, and that the result equals the pin). No feature is enabled: in particular not
# the test-only ones (test-loopback-http, test-pause-before-start, test-tree-counters,
# test-walk-hooks).
#
# Unlike the launcher (pure Rust), the C parts are compiled, and the whole binary linked, by the machine's C toolchain,
# so the toolchain is pinned too, and nothing the caller's environment or a cargo config file says can choose another:
# - the packages, exactly, by their installed versions: Ubuntu 24.04's gcc-13 13.3.0-6ubuntu2~24.04.1, musl-dev 1.2.4-2
#   and binutils 2.42-4ubuntu2.10 (as, ld, ar); musl-gcc must run gcc 13.3.0;
# - every tool by absolute path: cargo and rustc from cargo's home (rustc 1.99.0), the C compiler $TOOLS/musl-gcc, the
#   archiver $TOOLS/ar and the linker $TOOLS/gcc-13, set explicitly for the target;
# - cargo runs under `env -i` with a closed list of variables, all set here (nothing inherited: no CC, TARGET_CC, CFLAGS,
#   RUSTFLAGS, CARGO_ENCODED_RUSTFLAGS, RUSTC_WRAPPER, REALGCC or CARGO_* override reaches it);
# - a cargo config file anywhere cargo would read one ($CARGO_HOME, or a .cargo/ in the source root, the work directory
#   or any of their parents) refuses the build.
# CI builds on the pinned runner image ubuntu-24.04. A change of any pinned package moves the pin, deliberately.
set -eu

[ "$#" -eq 1 ] || { echo "usage: scripts/backup-build.sh <out>" >&2; exit 2; }
out=$1
case "$out" in /*) ;; *) out=$(pwd -P)/$out ;; esac # (absolute before the cd into the source root below)
root=$(cd "$(dirname "$0")/.." && pwd -P)
target=x86_64-unknown-linux-musl
TOOLS=/usr/bin
no() { echo "backup-build: $1" >&2; exit 1; }

cargo_home=${CARGO_HOME:-$HOME/.cargo}
cargo_home=$(cd "$cargo_home" && pwd -P)
rustup_home=${RUSTUP_HOME:-$HOME/.rustup}
CARGO=$cargo_home/bin/cargo
RUSTC=$cargo_home/bin/rustc
# clean <cmd...>: the command with ONLY these variables (the toolchain chosen here, never by the caller)
clean() {
  env -i PATH="$TOOLS:/bin" HOME="$HOME" CARGO_HOME="$cargo_home" RUSTUP_HOME="$rustup_home" RUSTUP_TOOLCHAIN=1.99.0 "$@"
}

version=$(clean "$RUSTC" --version 2>/dev/null | cut -d' ' -f2)
[ "$version" = 1.99.0 ] || no "rust 1.99.0 is required (found ${version:-none})"
pkg() { clean "$TOOLS/dpkg-query" -W -f '${Version}' "$1" 2>/dev/null || echo none; }
[ "$(pkg gcc-13)" = 13.3.0-6ubuntu2~24.04.1 ] || no "gcc-13 13.3.0-6ubuntu2~24.04.1 is required (found $(pkg gcc-13))"
[ "$(pkg musl-dev)" = 1.2.4-2 ] || no "musl-dev 1.2.4-2 is required (found $(pkg musl-dev))"
[ "$(pkg binutils)" = 2.42-4ubuntu2.10 ] || no "binutils 2.42-4ubuntu2.10 is required (found $(pkg binutils))"
[ "$(clean "$TOOLS/musl-gcc" -dumpfullversion 2>/dev/null)" = 13.3.0 ] || no "musl-gcc must run gcc 13.3.0"
[ "$(clean "$TOOLS/gcc-13" -dumpfullversion 2>/dev/null)" = 13.3.0 ] || no "gcc-13 must be gcc 13.3.0"
[ -x "$TOOLS/ar" ] || no "$TOOLS/ar is missing"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# No cargo configuration may steer the build: none in cargo's home, none in a .cargo/ of the source root, the work
# directory, or any parent of either (cargo reads them from the directory it runs in, $root, upward).
for f in "$cargo_home/config" "$cargo_home/config.toml"; do
  [ ! -e "$f" ] && [ ! -L "$f" ] || no "a cargo config file would steer the build: $f"
done
for start in "$root" "$work"; do
  d=$start
  while :; do
    for f in "$d/.cargo/config" "$d/.cargo/config.toml"; do
      [ ! -e "$f" ] && [ ! -L "$f" ] || no "a cargo config file would steer the build: $f"
    done
    [ "$d" = / ] && break
    d=$(dirname "$d")
  done
done

maps="-ffile-prefix-map=$root=/sagebrush -ffile-prefix-map=$cargo_home=/cargo -ffile-prefix-map=$work=/build"
cd "$root"
clean \
  RUSTC="$RUSTC" \
  SOURCE_DATE_EPOCH=0 \
  CARGO_TARGET_DIR="$work/target" \
  CARGO_INCREMENTAL=0 \
  RUSTFLAGS="--remap-path-prefix=$root=/sagebrush --remap-path-prefix=$cargo_home=/cargo --remap-path-prefix=$work=/build -C link-arg=-Wl,--build-id=none" \
  CFLAGS_x86_64_unknown_linux_musl="$maps" \
  CC_x86_64_unknown_linux_musl="$TOOLS/musl-gcc" \
  AR_x86_64_unknown_linux_musl="$TOOLS/ar" \
  CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER="$TOOLS/gcc-13" \
  "$CARGO" build --locked --offline --release --manifest-path "$root/backup/Cargo.toml" --target "$target"

# static: no dynamic loader (the launcher refuses a binary that names one)
bash "$root/scripts/backup-static-check.sh" "$work/target/$target/release/sagebrush-agent-backup"
cp "$work/target/$target/release/sagebrush-agent-backup" "$out"
chmod 0755 "$out"
