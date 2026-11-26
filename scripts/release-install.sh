#!/bin/sh
# A qualified release's FRESH install (lease-on design r1.12 §2.5, §2.6), and a bound member of the lease
# qualification:
#
#   scripts/release-install.sh <commit> <dest> <launcher>   (as root, in a clone holding <commit>, systemd running)
#   scripts/release-install.sh --verify <dest>         (read-only: the effective unit is exactly the installed one)
#
# SB_RELEASE_INSTALL_CUT=<step> (tests): stop with status 9 right after that step, as a crash there would.
#
# <launcher> is a launcher built beforehand, WITHOUT root (scripts/launcher-build.sh); its bytes must have exactly the
# SHA-256 pinned in the reviewed tree at <commit> (lib/fleet/host/launcher.sha256). The root installer runs no
# toolchain, build script or tool the caller chose: the commit is read through an isolated bare copy of the clone (no
# config, hooks or local attributes, so no filter runs), and the launcher's bytes are verified against the pin before
# anything on the host changes.
#
# It installs a release and the trust boundary that keeps release code from running as root unless the tree is
# root's: the checker /usr/lib/sagebrush/release-trust (outside the release), the supervisor unit (ExecStartPre: the
# checker) and the system-sleep shim (the checker first). It enables and starts nothing; the person does.
#
# FRESH hosts only: any earlier sagebrush entrypoint, on disk or known to systemd, refuses with nothing touched.
# Upgrade-in-place is a launch prerequisite (a later design), not done here. Steps (refusing at the first failure):
#   0/1 (i)  read-only: <dest> absent; the absence probe; every destination and tool chain proven; what to create;
#            the commit archived (isolated) and the launcher's bytes verified against its pin, staged under /run.
#       (ii) create the missing directories, then prove every chain again.
#   2  close: the closing drop-in (an unmet condition), daemon-reload, its loading verified.
#   3  the release: the staged archive, the staged launcher, the dispatcher link, root's; the checker passes on it.
#   4  the checker, the unit and the shim, each atomically (exclusive temp, owner, mode, fsync, rename, dir fsync).
#   5  daemon-reload.  6  the EFFECTIVE unit verified, still closed.  7  open: the drop-in removed, reload, verified.
# A cut at any point leaves nothing startable: before step 4 there is no unit; from step 2 to 7 the unit is closed.
set -eu
# Nothing of the caller's environment reaches any tool (TAR_OPTIONS, GIT_*, locale, pagers, ...): unless the
# environment is already exactly PATH=/usr/bin:/bin (plus what sh itself sets, and the tests' cut step), start again
# in an empty one.
clean_env=1
while IFS= read -r line; do
  case "$line" in PATH=/usr/bin:/bin | PWD=* | OLDPWD=* | SHLVL=* | _=* | SB_RELEASE_INSTALL_CUT=*) ;; *) clean_env=0 ;; esac
done <<EOF_ENV
$(env)
EOF_ENV
if [ "$clean_env" != 1 ]; then
  exec /usr/bin/env -i PATH=/usr/bin:/bin ${SB_RELEASE_INSTALL_CUT:+SB_RELEASE_INSTALL_CUT="$SB_RELEASE_INSTALL_CUT"} /bin/sh "$0" "$@"
fi
PATH=/usr/bin:/bin
export PATH
STAT=/usr/bin/stat
FIND=/usr/bin/find
READLINK=/usr/bin/readlink
SHA256SUM=/usr/bin/sha256sum
GIT=/usr/bin/git
TAR=/usr/bin/tar
SYSTEMCTL=/usr/bin/systemctl
BUSCTL=/usr/bin/busctl
ANALYZE=/usr/bin/systemd-analyze
UNIT=sagebrush-supervisor.service
ETC=/etc/systemd/system
DROPDIR=$ETC/$UNIT.d
CLOSED=$DROPDIR/00-closed.conf
CLOSED_PATH=/nonexistent/sagebrush-closed
LIBDIR=/usr/lib/sagebrush
CHECKER=$LIBDIR/release-trust
SLEEPDIR=/usr/lib/systemd/system-sleep
SHIM=$SLEEPDIR/sagebrush-lease

no() { printf 'release-install: %s\n' "$1" >&2; exit 1; }

case "$#:${1:-}" in 2:--verify) ;; 3:*) ;; *) no "usage: scripts/release-install.sh <commit> <dest> <launcher> | --verify <dest>" ;; esac
COMMIT=$1
DEST=$2
LAUNCHER=${3:-}
cut() { if [ "${SB_RELEASE_INSTALL_CUT:-}" = "$1" ]; then printf 'release-install: cut after step %s\n' "$1" >&2; exit 9; fi; }
case "$DEST" in /*) ;; *) no "<dest> must be an absolute path" ;; esac
case "$DEST" in *[!A-Za-z0-9/._-]*) no "<dest> has characters outside [A-Za-z0-9/._-]" ;; esac
case "$DEST" in / | */ | *//* | */./* | */../* | */. | */..) no "<dest> isn't a normal path" ;; esac
[ "$(id -u)" -eq 0 ] || no "run as root"
VERIFY_ONLY=0
[ "$COMMIT" = --verify ] && VERIFY_ONLY=1
REPO=$(pwd -P)
# git with nothing of the caller's: no system or global config, no HOME, an empty environment
igit() { env -i PATH=/usr/bin:/bin HOME=/nonexistent GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null "$GIT" "$@"; }

# ---- the proofs (the same rules as scripts/release-trust.sh) ----------------------------------------------------------
word() { case "$1" in d) echo "a directory" ;; f) echo "a regular file" ;; *) echo "a link" ;; esac; }
meta() {
  out=$("$STAT" -c '%u %f' -- "$1" 2>/dev/null) || return 0
  set -- $out
  printf '%s %s\n' "$1" "$((0x$2))"
}
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
# an existing install directory may only be the empty, root-owned 0755 trace of a cut install
empty_trace() {
  chain "$1" d
  [ "$("$STAT" -c '%a' -- "$1")" = 755 ] || no "not mode 0755: $1"
  [ -z "$("$FIND" "$1" -mindepth 1 -print -quit)" ] || no "not empty (an earlier install?): $1"
}
prove_all() {
  for t in /bin/sh "$STAT" "$FIND" "$READLINK" /usr/bin/node "$SYSTEMCTL" "$BUSCTL" "$ANALYZE" "$SHA256SUM" "$GIT" "$TAR"; do tool "$t"; done
  chain "$(dirname "$DEST")" d
  chain /usr/lib d
  chain "$ETC" d
  chain "$SLEEPDIR" d
  if [ -e "$LIBDIR" ] || [ -L "$LIBDIR" ]; then empty_trace "$LIBDIR"; fi
  if [ -e "$DROPDIR" ] || [ -L "$DROPDIR" ]; then empty_trace "$DROPDIR"; fi
  return 0
}

# ---- phase (i): wholly read-only -------------------------------------------------------------------------------------
if [ "$VERIFY_ONLY" = 1 ]; then :; else
if [ -e "$DEST" ] || [ -L "$DEST" ]; then no "<dest> exists: $DEST"; fi
# The absence probe, on disk: every systemd unit lookup directory, any sagebrush-* entry (a unit, a link, a .d
# directory, a .wants/.requires/.upholds link) or any link whose target names one. The drop-in directory is allowed
# only as an empty trace (proven below), so it is skipped here but its contents are not.
for d in $("$ANALYZE" unit-paths); do
  [ -d "$d" ] || continue
  x=$("$FIND" "$d" -maxdepth 2 \( -name 'sagebrush-*' -o -lname '*sagebrush-*' \) ! -path "$DROPDIR" -print -quit 2>/dev/null) \
    || no "a unit directory can't be read: $d"
  [ -z "$x" ] || no "a sagebrush systemd entry is present (not a fresh host): $x"
done
if [ -e "$SHIM" ] || [ -L "$SHIM" ]; then no "the sleep shim is present (not a fresh host): $SHIM"; fi
# ... and in systemd: nothing by the name, loaded or as a unit file, in any state
[ -d /run/systemd/system ] || no "systemd isn't running"
# (unfiltered, then matched here: with a pattern that matches nothing, list-unit-files exits non-zero)
x=$("$SYSTEMCTL" list-units --all --plain --no-legend --no-pager 2>&1) || no "systemctl list-units failed"
x=$(printf '%s\n' "$x" | awk '{ u = ($1 == "●" || $1 == "*") ? $2 : $1; if (u ~ /^sagebrush-/) { print u; exit } }')
[ -z "$x" ] || no "systemd knows a sagebrush unit (not a fresh host): $x"
x=$("$SYSTEMCTL" list-unit-files --no-legend --no-pager 2>&1) || no "systemctl list-unit-files failed"
x=$(printf '%s\n' "$x" | awk '$1 ~ /^sagebrush-/ { print $1; exit }')
[ -z "$x" ] || no "systemd has a sagebrush unit file (not a fresh host): $x"
for u in "$UNIT" sagebrush-backup.service sagebrush-backup.timer; do
  s=$("$SYSTEMCTL" show "$u" -p LoadState -p ActiveState -p SubState -p UnitFileState -p FragmentPath -p DropInPaths -p Names -p NeedDaemonReload 2>&1) \
    || no "systemctl show $u failed"
  want="LoadState=not-found
ActiveState=inactive
SubState=dead
UnitFileState=
FragmentPath=
DropInPaths=
Names=$u
NeedDaemonReload=no"
  [ "$(printf '%s\n' "$s" | sort)" = "$(printf '%s\n' "$want" | sort)" ] || no "systemd's state for $u isn't absent (not a fresh host)"
done
prove_all
# The commit, through an isolated bare repository holding a COPY of the clone's object store only (no config, hooks,
# attributes or refs of the clone come along, and no git command runs in the clone itself, so no filter or hook can
# run), archived into a root-only staging directory; then the launcher's bytes, copied in once and verified against
# the reviewed tree's pin. /run is outside every install area.
STAGE=$(mktemp -d /run/sb-release-install.XXXXXX) || no "can't create a staging directory"
trap 'rm -rf -- "$STAGE"' EXIT
# the clone's common git directory, read from disk: .git, or a linked worktree's .git file naming its gitdir, whose
# commondir file names the common one
gd=$REPO/.git
if [ -f "$gd" ]; then
  gd=$(sed -n 's/^gitdir: //p' "$gd"); case "$gd" in /*) ;; *) gd=$REPO/$gd ;; esac
  if [ -f "$gd/commondir" ]; then c=$(cat "$gd/commondir"); case "$c" in /*) gd=$c ;; *) gd=$gd/$c ;; esac; fi
fi
[ -d "$gd/objects" ] || no "can't find the clone's objects"
igit init -q --bare --template= "$STAGE/repo.git" || no "can't create the staging repository"
rm -rf -- "$STAGE/repo.git/objects"
cp -R -- "$gd/objects" "$STAGE/repo.git/objects" || no "can't copy the clone's objects"
if [ -f "$gd/shallow" ]; then cp -- "$gd/shallow" "$STAGE/repo.git/shallow"; fi
igit --git-dir="$STAGE/repo.git" rev-parse --verify --quiet "$COMMIT^{commit}" >/dev/null || no "no such commit"
mkdir -m 0700 "$STAGE/tree"
igit --git-dir="$STAGE/repo.git" -c core.attributesFile=/dev/null archive --format=tar "$COMMIT" \
  | "$TAR" -x --no-same-owner --no-same-permissions -C "$STAGE/tree" || no "can't archive the commit"
PIN=$(sed -n 's/^\([0-9a-f]\{64\}\)  sagebrush-agent-launch$/\1/p' "$STAGE/tree/lib/fleet/host/launcher.sha256" 2>/dev/null)
[ -n "$PIN" ] || no "the commit has no launcher pin"
case "$LAUNCHER" in /*) ;; *) no "<launcher> must be an absolute path" ;; esac
[ -f "$LAUNCHER" ] && [ ! -L "$LAUNCHER" ] || no "<launcher> isn't a regular file"
cp -- "$LAUNCHER" "$STAGE/launch"
# digest <file>: its SHA-256 (no pipe, no redirection: the sum of the named file, its exit status checked)
digest() {
  sum=$("$SHA256SUM" -- "$1" 2>&1) || no "sha256sum failed on $1: $sum"
  d=${sum%% *}
  case "$d" in *[!0-9a-f]* | "") no "sha256sum gave no digest for $1: [$sum] ($(ls -la -- "$1" 2>&1))" ;; esac
  [ "${#d}" -eq 64 ] || no "sha256sum gave no digest for $1: [$sum]"
  printf '%s\n' "$d"
}
GOT=$(digest "$STAGE/launch")
[ "$GOT" = "$PIN" ] || no "the launcher's digest isn't the pinned one (got $GOT, pinned $PIN)"
fi
CREATE=""
if [ "$VERIFY_ONLY" = 0 ]; then
  [ -e "$LIBDIR" ] || CREATE="$CREATE $LIBDIR"
  [ -e "$DROPDIR" ] || CREATE="$CREATE $DROPDIR"
fi

# ---- phase (ii): create, then prove again ----------------------------------------------------------------------------
[ "$VERIFY_ONLY" = 1 ] || cut 1
for d in $CREATE; do
  mkdir -m 0755 -- "$d" || no "can't create $d"
  chown 0:0 -- "$d"
  chmod 0755 -- "$d"
  sync -- "$(dirname "$d")"
done
[ "$VERIFY_ONLY" = 1 ] || { cut 1m; prove_all; }

# atomic <target> <mode> <source file>: a fresh temp in the target's proven directory, owner 0:0, exact mode, fsync,
# rename over the target, fsync of the directory.
atomic() {
  dir=$(dirname "$1")
  tmp=$(mktemp "$dir/.sb-install.XXXXXX") || no "can't create a temp file in $dir"
  cat -- "$3" > "$tmp"
  chown 0:0 -- "$tmp"
  chmod "$2" -- "$tmp"
  sync -- "$tmp"
  mv -T -- "$tmp" "$1"
  sync -- "$dir"
}
show() { "$SYSTEMCTL" show "$UNIT" -p "$1" --value; }
argv_of() { # the single command line of an Exec property, or nothing when there isn't exactly one
  v=$(show "$1")
  n=$(printf '%s' "$v" | grep -o '{ path=' | wc -l)
  [ "$n" -eq 1 ] || return 0
  printf '%s' "$v" | sed -n 's/.*argv\[\]=\([^;]*\) ;.*/\1/p'
}
conditions() {
  path=$("$BUSCTL" call org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager GetUnit s "$UNIT" 2>/dev/null \
    | sed -n 's/^o "\(.*\)"$/\1/p')
  [ -n "$path" ] || return 0
  "$BUSCTL" get-property org.freedesktop.systemd1 "$path" org.freedesktop.systemd1.Unit Conditions 2>/dev/null
}
# verify closed|open: the unit systemd will run is exactly this one
verify() {
  [ "$(show LoadState)" = loaded ] || return 1
  [ "$(show FragmentPath)" = "$ETC/$UNIT" ] || return 1
  [ "$(show Names)" = "$UNIT" ] || return 1
  [ "$(show NeedDaemonReload)" = no ] || return 1
  [ "$(show ActiveState)" = inactive ] || return 1
  [ "$(argv_of ExecStartPre)" = "$CHECKER $DEST" ] || return 1
  [ "$(argv_of ExecStart)" = "/usr/bin/node $DEST/bin/sagebrush-agent.mjs host run" ] || return 1
  c=$(conditions)
  if [ "$1" = closed ]; then
    [ "$(show DropInPaths)" = "$CLOSED" ] || return 1
    case "$c" in "a(sbbsi) 1 \"ConditionPathExists\" false false \"$CLOSED_PATH\" "*) ;; *) return 1 ;; esac
  else
    [ -z "$(show DropInPaths)" ] || return 1
    [ "$c" = "a(sbbsi) 0" ] || return 1
  fi
  return 0
}
render() { sed "s#@RELEASE@#$DEST#g" "$1" > "$2"; }
if [ "$VERIFY_ONLY" = 1 ]; then
  [ -d /run/systemd/system ] || no "systemd isn't running"
  verify open || no "the effective unit isn't exactly the installed one"
  printf 'release-install: the effective %s is the installed one for %s\n' "$UNIT" "$DEST"
  exit 0
fi

# ---- step 2: close -------------------------------------------------------------------------------------------------
[ -e "$CLOSED_PATH" ] && no "$CLOSED_PATH exists"
work=$(mktemp -d "$(dirname "$DEST")/.sb-release.XXXXXX") || no "can't create a work directory next to <dest>"
trap 'rm -rf -- "$work" "$STAGE"' EXIT
printf '[Unit]\nConditionPathExists=%s\n' "$CLOSED_PATH" > "$work/closed.conf"
atomic "$CLOSED" 0644 "$work/closed.conf"
"$SYSTEMCTL" daemon-reload
# On a fresh host the unit has no fragment yet: systemd reports it not-found, and shows no drop-ins for a unit it
# can't load (DropInPaths is empty). A not-found unit can't start; and systemd reads a unit's fragment together with
# its drop-ins from disk, on a reload or on demand, so from the moment the fragment exists the closing condition
# applies. Here: not-found, no reload pending, inactive, and on disk the closing drop-in is the unit's ONLY drop-in in
# every lookup directory. The effective closed condition itself is proven at step 6, once the fragment is loaded.
[ "$(show LoadState)" = not-found ] || no "the unit isn't not-found after the close"
[ "$(show NeedDaemonReload)" = no ] || no "systemd needs a reload after the close"
[ "$(show ActiveState)" = inactive ] || no "the unit isn't inactive"
for d in $("$ANALYZE" unit-paths); do
  [ -e "$d/$UNIT.d" ] || [ -L "$d/$UNIT.d" ] || continue
  [ "$d/$UNIT.d" = "$DROPDIR" ] || no "another drop-in directory for the unit: $d/$UNIT.d"
  [ "$(cd "$DROPDIR" && "$FIND" . -mindepth 1 -print)" = "./00-closed.conf" ] || no "the closing drop-in isn't the unit's only drop-in"
done
cut 2

# ---- step 3: the release ---------------------------------------------------------------------------------------------
mkdir -m 0700 -- "$work/tree"
igit --git-dir="$STAGE/repo.git" -c core.attributesFile=/dev/null archive --format=tar "$COMMIT" \
  | "$TAR" -x --no-same-owner --no-same-permissions -C "$work/tree"
cp -- "$STAGE/launch" "$work/tree/bin/sagebrush-agent-launch"
[ "$(digest "$work/tree/bin/sagebrush-agent-launch")" = "$PIN" ] || no "the staged launcher changed"
ln -s sagebrush-agent.mjs "$work/tree/bin/sagebrush-agent"
chown -R -h 0:0 -- "$work/tree"
chmod -R go-w -- "$work/tree"
chmod 0755 -- "$work/tree" "$work/tree/bin/sagebrush-agent-launch"
mv -T -- "$work/tree" "$DEST"
sync -- "$(dirname "$DEST")"
/bin/sh "$DEST/scripts/release-trust.sh" "$DEST" || no "the installed release doesn't pass its own checker"
cut 3

# ---- step 4: the boundary files --------------------------------------------------------------------------------------
render "$DEST/lib/fleet/host/units/sagebrush-supervisor.service" "$work/unit"
render "$DEST/lib/fleet/host/units/sagebrush-lease-sleep" "$work/shim"
atomic "$CHECKER" 0755 "$DEST/scripts/release-trust.sh"
atomic "$ETC/$UNIT" 0644 "$work/unit"
atomic "$SHIM" 0755 "$work/shim"
cut 4

# ---- steps 5, 6: reload, and the effective unit, still closed --------------------------------------------------------
"$SYSTEMCTL" daemon-reload
cut 5
verify closed || no "the loaded unit isn't exactly the installed one (still closed)"
cut 6

# ---- step 7: open ----------------------------------------------------------------------------------------------------
rm -f -- "$CLOSED"
sync -- "$DROPDIR"
rmdir -- "$DROPDIR"
sync -- "$ETC"
"$SYSTEMCTL" daemon-reload
if ! verify open; then
  mkdir -m 0755 -- "$DROPDIR" 2>/dev/null || true
  atomic "$CLOSED" 0644 "$work/closed.conf"
  "$SYSTEMCTL" daemon-reload
  no "the opened unit isn't exactly the installed one (closed again)"
fi
printf 'release-install: %s installed at %s; enable and start %s when ready\n' "$COMMIT" "$DEST" "$UNIT"
