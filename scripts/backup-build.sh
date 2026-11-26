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
# the test-only ones (test-loopback-http, test-pause-before-start).
#
# Unlike the launcher (pure Rust), the C parts are compiled by the machine's C toolchain, so the toolchain is pinned too:
# Ubuntu 24.04's gcc-13 13.3.0-6ubuntu2~24.04.1 (through musl-gcc) and musl-dev 1.2.4-2, exactly, checked by their
# installed package versions (another compiler or musl gives other bytes: refused, as another rustc is). CI builds on the
# pinned runner image ubuntu-24.04; a change of either package moves the pin, deliberately.
set -eu

[ "$#" -eq 1 ] || { echo "usage: scripts/backup-build.sh <out>" >&2; exit 2; }
out=$1
root=$(cd "$(dirname "$0")/.." && pwd -P)
target=x86_64-unknown-linux-musl

version=$(rustc --version | cut -d' ' -f2)
[ "$version" = 1.99.0 ] || { echo "backup-build: rust 1.99.0 is required (found $version)" >&2; exit 1; }
pkg() { dpkg-query -W -f '${Version}' "$1" 2>/dev/null || echo none; }
[ "$(pkg gcc-13)" = 13.3.0-6ubuntu2~24.04.1 ] || { echo "backup-build: gcc-13 13.3.0-6ubuntu2~24.04.1 is required (found $(pkg gcc-13))" >&2; exit 1; }
[ "$(pkg musl-dev)" = 1.2.4-2 ] || { echo "backup-build: musl-dev 1.2.4-2 is required (found $(pkg musl-dev))" >&2; exit 1; }
[ "$(musl-gcc -dumpfullversion 2>/dev/null)" = 13.3.0 ] || { echo "backup-build: musl-gcc must run gcc 13.3.0" >&2; exit 1; }

cargo_home=${CARGO_HOME:-$HOME/.cargo}
cargo_home=$(cd "$cargo_home" && pwd -P)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

maps="-ffile-prefix-map=$root=/sagebrush -ffile-prefix-map=$cargo_home=/cargo -ffile-prefix-map=$work=/build"
SOURCE_DATE_EPOCH=0 \
CARGO_TARGET_DIR="$work/target" \
CARGO_INCREMENTAL=0 \
RUSTFLAGS="--remap-path-prefix=$root=/sagebrush --remap-path-prefix=$cargo_home=/cargo --remap-path-prefix=$work=/build -C link-arg=-Wl,--build-id=none" \
CFLAGS_x86_64_unknown_linux_musl="$maps" \
  cargo build --locked --offline --release --manifest-path "$root/backup/Cargo.toml" --target "$target"

# static: no dynamic loader (the launcher refuses a binary that names one)
bash "$root/scripts/backup-static-check.sh" "$work/target/$target/release/sagebrush-agent-backup"
cp "$work/target/$target/release/sagebrush-agent-backup" "$out"
chmod 0755 "$out"
