#!/bin/bash
# Tests for scripts/backup-static-check.sh on generated ELF files:
# - passes: a static-pie shape (PT_DYNAMIC, no DT_NEEDED), with a small dynamic table and with a 10,000-entry one;
# - refused: one DT_NEEDED; 10,000 of them (a table large enough that a short-reading match would cut readelf off);
#   a PT_INTERP; a non-ELF file; and a static-pie file when `readelf -d` fails, or succeeds but reports on stderr.
#   scripts/backup-static-check-test.sh [BINARY_THAT_MUST_PASS]
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
check=$here/backup-static-check.sh
dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
# A minimal ELF64 x86-64 ET_DYN: one PT_LOAD over the whole file (vaddr = offset), a PT_DYNAMIC with NEEDED entries
# naming libc.so.6, DT_DEBUG filler entries, then DT_STRTAB, DT_STRSZ and DT_NULL, and optionally a PT_INTERP.
#   make_elf PATH NEEDED_COUNT INTERP(0|1) [FILLER_COUNT]
make_elf() {
  python3 -I - "$1" "$2" "$3" "${4:-0}" <<'PY'
import struct, sys
path, needed, interp, filler = sys.argv[1], int(sys.argv[2]), sys.argv[3] == "1", int(sys.argv[4])
phnum = 3 if interp else 2
off = 64 + 56 * phnum
interp_s = b"/lib64/ld-linux-x86-64.so.2\0"
interp_off = off
if interp:
    off += len(interp_s)
dynstr = b"\0libc.so.6\0"
dynstr_off = off
off += len(dynstr)
off = (off + 7) & ~7
dyn_off = off
dyn = b"".join(struct.pack("<qQ", 1, 1) for _ in range(needed))
dyn += b"".join(struct.pack("<qQ", 21, 0) for _ in range(filler))
dyn += struct.pack("<qQ", 5, dynstr_off) + struct.pack("<qQ", 10, len(dynstr)) + struct.pack("<qQ", 0, 0)
size = dyn_off + len(dyn)
ehdr = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
ehdr += struct.pack("<HHIQQQIHHHHHH", 3, 62, 1, 0, 64, 0, 0, 64, 56, phnum, 64, 0, 0)
def ph(t, flags, o, sz, align):
    return struct.pack("<IIQQQQQQ", t, flags, o, o, o, sz, sz, align)
phs = b""
if interp:
    phs += ph(3, 4, interp_off, len(interp_s), 1)
phs += ph(1, 6, 0, size, 0x1000) + ph(2, 6, dyn_off, len(dyn), 8)
body = ehdr + phs + (interp_s if interp else b"") + dynstr
body += bytes(dyn_off - len(body)) + dyn
open(path, "wb").write(body)
PY
}
# expect pass|refuse NAME [PATH_PREFIX]: runs the check on $dir/NAME, with PATH_PREFIX first on PATH when given.
expect() {
  local want=$1 name=$2 path=${3:+$3:}$PATH got=0
  PATH=$path "$check" "$dir/$name" >/dev/null 2>&1 || got=$?
  if { [ "$want" = pass ] && [ "$got" -ne 0 ]; } || { [ "$want" = refuse ] && [ "$got" -eq 0 ]; }; then
    echo "backup-static-check-test: $name should $want, the check exited $got" >&2
    PATH=$path "$check" "$dir/$name" >&2 || true
    exit 1
  fi
  echo "ok: $name ($want${3:+, readelf from $3})"
}
make_elf "$dir/static-pie" 0 0
make_elf "$dir/needed-one" 1 0
make_elf "$dir/needed-10000" 10000 0
make_elf "$dir/large-table" 0 0 10000
make_elf "$dir/interp" 0 1
printf '#!/bin/sh\n' > "$dir/not-elf"
expect pass static-pie
expect pass large-table
expect refuse needed-one
expect refuse needed-10000
expect refuse interp
expect refuse not-elf
# readelf shims: the header read goes to the real readelf; the dynamic-table read fails, or succeeds with a warning.
real=$(command -v readelf)
mkdir "$dir/fails" "$dir/warns"
printf '#!/bin/bash\n[ "$1" = -dW ] && { echo "readelf: Error: simulated" >&2; exit 1; }\nexec %q "$@"\n' "$real" > "$dir/fails/readelf"
printf '#!/bin/bash\n[ "$1" = -dW ] && echo "readelf: Warning: simulated" >&2\nexec %q "$@"\n' "$real" > "$dir/warns/readelf"
chmod 0755 "$dir/fails/readelf" "$dir/warns/readelf"
expect refuse static-pie "$dir/fails"
expect refuse static-pie "$dir/warns"
if [ $# -ge 1 ]; then
  "$check" "$1"
  echo "ok: $1 (pass)"
fi
