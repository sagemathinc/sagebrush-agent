#!/bin/sh
# The turn's syscall policy, regenerated from its PIN (launcher contract amendment A5 §3, part 3b-ii a), offline:
#   1. fetch the pin's five .debs, and require each one's sha256 BEFORE anything reads it, then its Package, Version and
#      Architecture. Each is tried from an ordered list of sources (the dated Ubuntu snapshot, then the archive, the
#      security pocket and Launchpad's file link): the pin's hash, not the source, is what makes a .deb the pin's, so
#      a source that serves other bytes is refused and the next one tried;
#   2. pull the Ubuntu 24.04 image by its linux/amd64 manifest digest;
#   3. in it, with NO network, unpack the .debs and run the pinned systemd-analyze through the image's own loader and
#      libraries, with an empty environment: its version, its syscall-filter tables;
#   4. require those outputs, and the pinned header's x86_64 numbers, to be the committed fixtures byte for byte, and
#      the committed artifact to be what they generate (scripts/seccomp-policy.mjs check).
# Then the controls: a corrupted hash and a wrong version must each be refused by the same check, and a source that
# serves another file's bytes must be refused (the next source's right bytes taken, or none at all).
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

# sources <snapshot url> <file>: the sources to try, in order. A .deb's pool path is the same in each Ubuntu mirror.
sources() {
  case "$1" in
    https://snapshot.ubuntu.com/ubuntu/*/pool/*) pool=${1#https://snapshot.ubuntu.com/ubuntu/*/} ;;
    *) echo "$1"; return ;;
  esac
  printf '%s\n' "$1" "https://archive.ubuntu.com/ubuntu/$pool" "https://security.ubuntu.com/ubuntu/$pool" \
    "https://launchpad.net/ubuntu/+archive/primary/+files/$2"
}

# fetch <dest> <sha256> <package> <version> <architecture> <source>...: each source in turn; the first whose bytes pass
# verify (the hash first) is kept. Anything else is deleted before the next source, and no source at all is a failure.
fetch() {
  dest=$1 sha=$2 pkg=$3 ver=$4 arch=$5
  shift 5
  for u in "$@"; do
    rm -f "$dest"
    if curl -fsSL --proto '=https' --tlsv1.2 --max-time 300 -o "$dest" "$u" 2>/dev/null; then
      verify "$dest" "$sha" "$pkg" "$ver" "$arch" && return 0
      echo "seccomp policy: $u: refused; trying the next source" >&2
    else
      echo "seccomp policy: $u: no answer; trying the next source" >&2
    fi
  done
  rm -f "$dest"
  echo "seccomp policy: $(basename "$dest"): no source gave the pinned bytes" >&2
  return 1
}

node scripts/seccomp-policy.mjs debs > "$work/debs.txt"
[ "$(wc -l < "$work/debs.txt")" -eq 5 ] || { echo "seccomp policy: the pin doesn't name five .debs" >&2; exit 1; }
while read -r url sha pkg ver arch file; do
  # shellcheck disable=SC2046 # the sources are URLs without spaces, one per line
  fetch "$work/debs/$file" "$sha" "$pkg" "$ver" "$arch" $(sources "$url" "$file") || exit 1
done < "$work/debs.txt"

# The controls: the same check refuses a corrupted hash and a wrong version.
read -r _ sha pkg ver arch file < "$work/debs.txt"
if verify "$work/debs/$file" "$(echo "$sha" | tr '0-9a-f' '1-9a-f0')" "$pkg" "$ver" "$arch" 2>/dev/null; then echo "seccomp policy: control: a corrupted hash was accepted" >&2; exit 1; fi
if verify "$work/debs/$file" "$sha" "$pkg" "$ver.0" "$arch" 2>/dev/null; then echo "seccomp policy: control: a wrong version was accepted" >&2; exit 1; fi
# A source serving another .deb's bytes (a valid package, the wrong hash) is refused and a later source's right bytes
# are kept; with only such sources, the fetch fails. Each control lists every source of its .debs (the snapshot alone
# may not answer) and requires that a wrong source was answered and REFUSED, so neither passes vacuously. (The two
# smallest .debs: the 3rd and 4th lines.)
read -r o_url _ _ _ _ o_file <<EOF
$(sed -n 3p "$work/debs.txt")
EOF
read -r k_url k_sha k_pkg k_ver k_arch k_file <<EOF
$(sed -n 4p "$work/debs.txt")
EOF
# shellcheck disable=SC2046
fetch "$work/c1.deb" "$k_sha" "$k_pkg" "$k_ver" "$k_arch" $(sources "$o_url" "$o_file") $(sources "$k_url" "$k_file") 2>"$work/c1.err" \
  || { echo "seccomp policy: control: a later right source wasn't taken" >&2; exit 1; }
grep -q ": refused; trying the next source" "$work/c1.err" || { echo "seccomp policy: control: no wrong source was refused" >&2; exit 1; }
echo "$k_sha  $work/c1.deb" | sha256sum -c --quiet - || { echo "seccomp policy: control: the kept bytes aren't the pin's" >&2; exit 1; }
# shellcheck disable=SC2046
if fetch "$work/c2.deb" "$k_sha" "$k_pkg" "$k_ver" "$k_arch" $(sources "$o_url" "$o_file") 2>"$work/c2.err"; then
  echo "seccomp policy: control: a source with the wrong hash was accepted" >&2; exit 1
fi
grep -q ": refused; trying the next source" "$work/c2.err" || { echo "seccomp policy: control: no wrong source answered to be refused" >&2; exit 1; }
[ ! -e "$work/c2.deb" ] || { echo "seccomp policy: control: refused bytes were left behind" >&2; exit 1; }

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
