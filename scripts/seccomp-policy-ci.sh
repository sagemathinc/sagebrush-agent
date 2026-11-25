#!/bin/sh
# The turn's syscall policy, regenerated from its PIN (launcher contract amendment A5 §3, part 3b-ii a), offline:
#   1. fetch the pin's five .debs from the dated Ubuntu snapshot, and require each one's sha256 BEFORE anything reads
#      it, then its Package, Version and Architecture;
#   2. pull the Ubuntu 24.04 image by its linux/amd64 manifest digest;
#   3. in it, with NO network, unpack the .debs and run the pinned systemd-analyze through the image's own loader and
#      libraries, with an empty environment: its version, its syscall-filter tables;
#   4. require those outputs, and the pinned header's x86_64 numbers, to be the committed fixtures byte for byte, and
#      the committed artifact to be what they generate (scripts/seccomp-policy.mjs check).
# Then the controls: a corrupted hash and a wrong version must each be refused by the same check.
set -eu
cd "$(dirname "$0")/.."
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir "$work/debs" "$work/out"

# verify <file> <sha256> <package> <version> <architecture>: the hash first; only then the control fields.
verify() {
  echo "$2  $1" | sha256sum -c --quiet - >/dev/null 2>&1 || { echo "seccomp policy: $1: sha256 isn't the pin's" >&2; return 1; }
  [ "$(dpkg-deb -f "$1" Package)" = "$3" ] || { echo "seccomp policy: $1: Package isn't $3" >&2; return 1; }
  [ "$(dpkg-deb -f "$1" Version)" = "$4" ] || { echo "seccomp policy: $1: Version isn't $4" >&2; return 1; }
  [ "$(dpkg-deb -f "$1" Architecture)" = "$5" ] || { echo "seccomp policy: $1: Architecture isn't $5" >&2; return 1; }
}

node scripts/seccomp-policy.mjs debs > "$work/debs.txt"
[ "$(wc -l < "$work/debs.txt")" -eq 5 ] || { echo "seccomp policy: the pin doesn't name five .debs" >&2; exit 1; }
while read -r url sha pkg ver arch file; do
  curl -fsSL --proto '=https' --tlsv1.2 -o "$work/debs/$file" "$url"
  verify "$work/debs/$file" "$sha" "$pkg" "$ver" "$arch"
done < "$work/debs.txt"

# The controls: the same check refuses a corrupted hash and a wrong version.
read -r _ sha pkg ver arch file < "$work/debs.txt"
if verify "$work/debs/$file" "$(echo "$sha" | tr '0-9a-f' '1-9a-f0')" "$pkg" "$ver" "$arch" 2>/dev/null; then echo "seccomp policy: control: a corrupted hash was accepted" >&2; exit 1; fi
if verify "$work/debs/$file" "$sha" "$pkg" "$ver.0" "$arch" 2>/dev/null; then echo "seccomp policy: control: a wrong version was accepted" >&2; exit 1; fi

image="ubuntu@$(node -p 'require("./schema/fleet/agent-seccomp-policy.json").pin.image.linux_amd64')"
docker pull --quiet --platform linux/amd64 "$image"
docker run --rm --network none --platform linux/amd64 -v "$work/debs:/debs:ro" -v "$work/out:/out" "$image" sh -euc '
  mkdir /x
  for d in /debs/*.deb; do dpkg-deb -x "$d" /x; done
  L=/x/usr/lib/x86_64-linux-gnu/systemd:/x/usr/lib/x86_64-linux-gnu:/usr/lib/x86_64-linux-gnu
  env -i /usr/lib64/ld-linux-x86-64.so.2 --library-path "$L" /x/usr/bin/systemd-analyze --version > /out/version
  env -i /usr/lib64/ld-linux-x86-64.so.2 --library-path "$L" /x/usr/bin/systemd-analyze syscall-filter --no-pager > /out/syscall-filter
  cp /x/usr/include/x86_64-linux-gnu/asm/unistd_64.h /out/unistd_64.h
'
node scripts/seccomp-policy.mjs check "$work/out/syscall-filter" "$work/out/unistd_64.h" "$work/out/version"
echo "seccomp policy: the artifact is the pinned systemd's, byte for byte"
