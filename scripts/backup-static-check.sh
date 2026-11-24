#!/bin/bash
# The backup binary ships as a static musl build: the launcher's restore runner execs it in a filesystem view with no
# loader and no libraries, and refuses any binary that names a dynamic loader. This checks a built binary the same way:
# an ELF executable with no PT_INTERP segment. A static-pie build keeps a PT_DYNAMIC segment for its own relocations,
# which is fine; it must not need any library (no DT_NEEDED).
#   scripts/backup-static-check.sh BINARY
# Each readelf output is captured whole before it is matched, and a readelf that fails or reports anything on stderr
# fails the check: a match never reads from a pipe that a failure could cut short.
set -euo pipefail
bin=${1:?usage: scripts/backup-static-check.sh BINARY}
fail() { echo "backup-static-check: $bin $1" >&2; exit 1; }
errs=$(mktemp)
trap 'rm -f "$errs"' EXIT
inspect() {
  local out
  out=$(readelf "$@" -- "$bin" 2>"$errs") || fail "can't be inspected (readelf $*: $(head -c 300 "$errs"))"
  [ ! -s "$errs" ] || fail "can't be inspected cleanly (readelf $*: $(head -c 300 "$errs"))"
  printf '%s' "$out"
}
headers=$(inspect -hlW)
[[ $headers =~ (^|$'\n')\ *Type:\ +(EXEC|DYN)\  ]] || fail "is not an ELF executable"
[[ $headers =~ (^|$'\n')\ *INTERP\  ]] && fail "names a dynamic loader (PT_INTERP); build it with --target x86_64-unknown-linux-musl"
dynamic=$(inspect -dW)
[[ $dynamic == *"(NEEDED)"* ]] && fail "needs shared libraries (DT_NEEDED)"
echo "backup-static-check: $bin is static (no PT_INTERP, no DT_NEEDED)"
