#!/bin/bash
# The backup binary ships as a static musl build: the launcher's restore runner execs it in a filesystem view with no
# loader and no libraries, and refuses any binary that names a dynamic loader. This checks a built binary the same way:
# an ELF executable with no PT_INTERP segment. A static-pie build keeps a PT_DYNAMIC segment for its own relocations,
# which is fine; it must not need any library (no DT_NEEDED).
#   scripts/backup-static-check.sh BINARY
set -euo pipefail
bin=${1:?usage: scripts/backup-static-check.sh BINARY}
headers=$(readelf -hlW -- "$bin")
grep -Eq '^ *Type: +(EXEC|DYN) ' <<<"$headers" || { echo "backup-static-check: $bin is not an ELF executable" >&2; exit 1; }
if grep -Eq '^ *INTERP ' <<<"$headers"; then
  echo "backup-static-check: $bin names a dynamic loader (PT_INTERP); build it with --target x86_64-unknown-linux-musl" >&2
  exit 1
fi
if readelf -dW -- "$bin" | grep -q '(NEEDED)'; then
  echo "backup-static-check: $bin needs shared libraries (DT_NEEDED)" >&2
  exit 1
fi
echo "backup-static-check: $bin is static (no PT_INTERP, no DT_NEEDED)"
