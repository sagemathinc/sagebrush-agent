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
#
# The toolchain is closed as scripts/backup-build.sh closes its own (host backup init/run d6 §4.1), except that the
# launcher is pure Rust, so no C toolchain is pinned (its bytes reproduce across hosts' gcc and binutils versions):
# - every tool by absolute path: cargo and rustc from cargo's home (rustc 1.99.0), the linker $TOOLS/cc, set
#   explicitly for the target (the one rustc picks by default);
# - cargo runs under `env -i` with a closed list of variables, all set here (nothing inherited: no RUSTFLAGS,
#   CARGO_ENCODED_RUSTFLAGS, RUSTC_WRAPPER, RUSTC or CARGO_* override reaches it);
# - a cargo config file anywhere cargo would read one ($CARGO_HOME, or a .cargo/ in the source root, the work directory
#   or any of their parents) refuses the build.
set -eu

[ "$#" -eq 1 ] || { echo "usage: scripts/launcher-build.sh <out>" >&2; exit 2; }
out=$(cd "$(dirname "$1")" && pwd -P)/$(basename "$1") # (absolute: the build runs from the source root)
root=$(cd "$(dirname "$0")/.." && pwd -P)
target=x86_64-unknown-linux-musl

TOOLS=/usr/bin
no() { echo "launcher-build: $1" >&2; exit 1; }

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
[ -x "$TOOLS/cc" ] || no "$TOOLS/cc is missing"
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

cd "$root"
clean \
  RUSTC="$RUSTC" \
  SOURCE_DATE_EPOCH=0 \
  CARGO_TARGET_DIR="$work/target" \
  CARGO_INCREMENTAL=0 \
  RUSTFLAGS="--remap-path-prefix=$root=/sagebrush --remap-path-prefix=$cargo_home=/cargo --remap-path-prefix=$work=/build -C link-arg=-Wl,--build-id=none" \
  CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER="$TOOLS/cc" \
  "$CARGO" build --locked --offline --release --manifest-path "$root/launcher/Cargo.toml" --target "$target"

# static: no dynamic loader (the launcher refuses one that names one, as the backup binary's check does)
bash "$root/scripts/backup-static-check.sh" "$work/target/$target/release/sagebrush-agent-launch"
cp "$work/target/$target/release/sagebrush-agent-launch" "$out"
chmod 0755 "$out"
