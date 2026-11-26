#!/bin/sh
# The release trust boundary (lease-on design r1.12 §2.6): installed OUTSIDE the release as
# /usr/lib/sagebrush/release-trust, run as the supervisor unit's ExecStartPre (and the backup unit's, and first in the
# system-sleep shim), so it decides BEFORE any release code runs as root. A bound member of the lease qualification.
#
#   release-trust <release>
#
# Exits 0 only if no principal but root can change what will run:
#   - every component from / to <release> is a real directory (never a link), owned by uid 0, no group or other write;
#   - under <release> (links never followed): everything owned by uid 0; nothing but a link has group or other write;
#     the only link is bin/sagebrush-agent, whose target is exactly sagebrush-agent.mjs; nothing but directories,
#     regular files and that link;
#   - /bin/sh, its tools and /usr/bin/node: every component of each path, and of its resolution, owned by uid 0, the
#     directories with no group or other write, the resolved file a regular file with no group or other write.
# Otherwise one line on stderr naming the failing path and why (never file contents), and exit 1. It uses only
# /usr/bin/stat, /usr/bin/find and /usr/bin/readlink, by absolute path; nothing is looked up in a search path.
# The OS's own base (systemd, the dynamic loader and shared libraries) is trusted as root's, as every root service's is:
# the chains above catch a misconfigured tool or node path, not a host whose system directories are already writable.
set -u
PATH=/usr/bin:/bin
export PATH
STAT=/usr/bin/stat
FIND=/usr/bin/find
READLINK=/usr/bin/readlink

no() { printf 'release-trust: %s\n' "$1" >&2; exit 1; }

[ "$#" -eq 1 ] || no "usage: release-trust <release>"
R=$1
case "$R" in /*) ;; *) no "the release must be an absolute path" ;; esac
case "$R" in *[!A-Za-z0-9/._-]*) no "the release path has characters outside [A-Za-z0-9/._-]" ;; esac
case "$R" in / | */ | *//* | */./* | */../* | */. | */..) no "the release path isn't normal" ;; esac

# meta <path>: "<uid> <mode>" (mode decimal), or nothing when it can't be read; never follows a final link.
meta() {
  out=$("$STAT" -c '%u %f' -- "$1" 2>/dev/null) || return 0
  set -- $out
  printf '%s %s\n' "$1" "$((0x$2))"
}
word() { case "$1" in d) echo "a directory" ;; f) echo "a regular file" ;; *) echo "a link" ;; esac; }
# owned <path> <want: d|f|l|any>: root's, of that type; directories and files with no group or other write.
owned() {
  m=$(meta "$1")
  [ -n "$m" ] || no "missing or unreadable: $1"
  set -- "$1" "$2" $m
  [ "$3" = 0 ] || no "not owned by root: $1"
  t=$(($4 & 61440))
  case "$t" in 16384) k=d ;; 32768) k=f ;; 40960) k=l ;; *) no "not a directory, regular file or link: $1" ;; esac
  case "$2" in any) ;; *) [ "$k" = "$2" ] || no "$(word "$k") where $(word "$2") is required: $1" ;; esac
  if [ "$k" != l ] && [ $(($4 & 18)) -ne 0 ]; then no "group- or other-writable: $1"; fi
  return 0
}
# chain <abs path> <final: d|f>: every proper ancestor a real root directory, then the path itself of type <final>.
chain() {
  p=""
  rest=${1#/}
  owned / d
  while [ -n "$rest" ]; do
    seg=${rest%%/*}
    case "$rest" in */*) rest=${rest#*/} ;; *) rest="" ;; esac
    p="$p/$seg"
    if [ -n "$rest" ]; then owned "$p" d; else owned "$p" "$2"; fi
  done
}
# tool <abs path>: each lexical component root's (links allowed: only root can change a link in a root directory),
# then the resolution's chain strictly, ending in a regular file.
tool() {
  p=""
  rest=${1#/}
  owned / d
  while [ -n "$rest" ]; do
    seg=${rest%%/*}
    case "$rest" in */*) rest=${rest#*/} ;; *) rest="" ;; esac
    p="$p/$seg"
    owned "$p" any
  done
  r=$("$READLINK" -f -- "$1" 2>/dev/null) || no "can't resolve: $1"
  [ -n "$r" ] || no "can't resolve: $1"
  chain "$r" f
}

for t in /bin/sh "$STAT" "$FIND" "$READLINK" /usr/bin/node; do tool "$t"; done

chain "$R" d

first() { "$FIND" "$R" "$@" -print -quit 2>/dev/null || no "the release can't be walked: $R"; }
x=$(first ! -uid 0); [ -z "$x" ] || no "not owned by root: $x"
x=$(first ! -type l -perm /022); [ -z "$x" ] || no "group- or other-writable: $x"
x=$(first -type l ! -path "$R/bin/sagebrush-agent"); [ -z "$x" ] || no "a link other than bin/sagebrush-agent: $x"
x=$(first ! -type d ! -type f ! -type l); [ -z "$x" ] || no "not a directory, regular file or link: $x"
[ -L "$R/bin/sagebrush-agent" ] || no "missing link: $R/bin/sagebrush-agent"
[ "$("$READLINK" -- "$R/bin/sagebrush-agent")" = sagebrush-agent.mjs ] || no "bin/sagebrush-agent doesn't link to sagebrush-agent.mjs"
exit 0
