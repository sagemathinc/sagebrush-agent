#!/bin/sh
# The launcher's ONE reproducible build (lease-on design r1.7 §2.2): the bytes a qualified release ships as
# bin/sagebrush-agent-launch, and a bound member of the lease qualification (a change here un-qualifies every record).
#
#   scripts/launcher-build.sh <out>
#
# rust 1.99.0 (the CI pin), target x86_64-unknown-linux-musl (static, as the backup binary ships), --locked --offline
# --release; the source, the target directory and cargo's home remapped to fixed names; SOURCE_DATE_EPOCH=0; no build
# id. The crate's one dependency must already be in cargo's cache (`cargo fetch --locked` first): the build itself never
# touches the network. Two builds from two directories must be byte-identical (the CI job checks it).
set -eu

[ "$#" -eq 1 ] || { echo "usage: scripts/launcher-build.sh <out>" >&2; exit 2; }
out=$1
root=$(cd "$(dirname "$0")/.." && pwd -P)
target=x86_64-unknown-linux-musl

version=$(rustc --version | cut -d' ' -f2)
[ "$version" = 1.99.0 ] || { echo "launcher-build: rust 1.99.0 is required (found $version)" >&2; exit 1; }

cargo_home=${CARGO_HOME:-$HOME/.cargo}
cargo_home=$(cd "$cargo_home" && pwd -P)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

SOURCE_DATE_EPOCH=0 \
CARGO_TARGET_DIR="$work/target" \
CARGO_INCREMENTAL=0 \
RUSTFLAGS="--remap-path-prefix=$root=/sagebrush --remap-path-prefix=$cargo_home=/cargo --remap-path-prefix=$work=/build -C link-arg=-Wl,--build-id=none" \
  cargo build --locked --offline --release --manifest-path "$root/launcher/Cargo.toml" --target "$target"

# static: no dynamic loader (the launcher refuses one that names one, as the backup binary's check does)
bash "$root/scripts/backup-static-check.sh" "$work/target/$target/release/sagebrush-agent-launch"
cp "$work/target/$target/release/sagebrush-agent-launch" "$out"
chmod 0755 "$out"
