#!/bin/bash
# The test-only hooks of the backup binary (backup/Cargo.toml's test-pause-before-start and test-walk-hooks) are named
# here once, by their environment variables. `absent`: the binary holds no trace of any of them (the pinned release
# build). `present`: the binary holds EVERY one (a build with those features: the check's positive control, so a
# mistyped name or a wrong path can't pass silently).
set -euo pipefail
HOOKS=(SB_TEST_PAUSE_MS SB_TEST_SANITIZED_GATE SB_TEST_NONSTRICT)
[ $# -eq 2 ] && [ -f "$1" ] && { [ "$2" = absent ] || [ "$2" = present ]; } || { echo "usage: $0 <binary> absent|present" >&2; exit 2; }
bad=0
for h in "${HOOKS[@]}"; do
  if grep -aqF "$h" "$1"; then found=1; else found=0; fi
  if [ "$2" = absent ] && [ $found = 1 ]; then echo "backup-hook-trace: $h is in $1" >&2; bad=1; fi
  if [ "$2" = present ] && [ $found = 0 ]; then echo "backup-hook-trace: $h is missing from $1" >&2; bad=1; fi
done
exit $bad
