#!/bin/bash
# The trust boundary's rows (lease-on design r1.12 §2.6, §7): the checker, the preload regression, and the FRESH
# installer against real systemd. Destructive to sagebrush state: run only on a disposable host (a CI runner, a VM).
#
#   sudo SB_TEST_LAUNCHER=<path> scripts/release-trust-test.sh
#       (root; systemd running; /usr/bin/node a root-owned node binary; <path> the launcher scripts/launcher-build.sh
#        built WITHOUT root, whose digest is the pinned one)
#
# Every row prints "ok" or "FAIL"; the script exits 1 if any row failed. It removes every sagebrush unit, drop-in,
# shim, checker and test release before and after the installer rows.
set -uo pipefail
REPO=$(cd "$(dirname "$0")/.." && pwd -P)
CHECK="$REPO/scripts/release-trust.sh"
INSTALL="$REPO/scripts/release-install.sh"
SBIN=/usr/local/sbin/sagebrush-release-install      # the supported entrypoint: a root-owned copy (lease-on r1.13)
UNIT=sagebrush-supervisor.service
FAILS=0
ok() { echo "ok   $1"; }
bad() { echo "FAIL $1"; FAILS=$((FAILS + 1)); }
# rc <label> <want> <cmd...>: the command's exit status is <want>
rc() { local label=$1 want=$2; shift 2; local out r; out=$("$@" 2>&1); r=$?; if [ "$r" = "$want" ]; then ok "$label"; else bad "$label (exit $r, want $want: ${out:0:300})"; fi; }

[ "$(id -u)" = 0 ] || { echo "release-trust-test: run as root" >&2; exit 2; }
[ -d /run/systemd/system ] || { echo "release-trust-test: systemd isn't running" >&2; exit 2; }
[ "$(stat -c %u "$(readlink -f /usr/bin/node)")" = 0 ] || { echo "release-trust-test: /usr/bin/node must be root's" >&2; exit 2; }
LAUNCH=${SB_TEST_LAUNCHER:?release-trust-test: SB_TEST_LAUNCHER (the non-root build of the launcher) is required}
COMMIT=$(git -c safe.directory='*' -C "$REPO" rev-parse HEAD) || { echo "release-trust-test: no commit" >&2; exit 2; }

# ---- A. the checker ------------------------------------------------------------------------------------------------
T=/var/lib/sb-trust-test   # (not /opt: a CI runner's /opt is writable, which the checker rightly refuses)
mk_tree() {
  rm -rf "$T"; mkdir -p "$T/rel/bin" "$T/rel/lib"
  echo 'process.exit(0)' > "$T/rel/bin/sagebrush-agent.mjs"; echo y > "$T/rel/lib/a.mjs"
  ln -s sagebrush-agent.mjs "$T/rel/bin/sagebrush-agent"
  chown -R -h 0:0 "$T"; chmod -R go-w "$T"; chmod 0755 "$T"
}
R=$T/rel
chk() { /bin/sh "$CHECK" "$@"; }
mk_tree
rc "checker: a root tree passes" 0 chk "$R"
for m in 664 646; do chmod $m "$R/lib/a.mjs"; rc "checker: a member $m" 1 chk "$R"; chmod 644 "$R/lib/a.mjs"; done
for m in 775 757 1777; do chmod $m "$R/lib"; rc "checker: a member directory $m" 1 chk "$R"; chmod 755 "$R/lib"; done
chown 65534 "$R/lib/a.mjs"; rc "checker: a foreign member" 1 chk "$R"; chown 0 "$R/lib/a.mjs"
chown 65534 "$R/lib"; rc "checker: a foreign directory" 1 chk "$R"; chown 0 "$R/lib"
ln -s a.mjs "$R/lib/b.mjs"; rc "checker: an extra link" 1 chk "$R"; rm "$R/lib/b.mjs"
mv "$R/lib" "$R/lib.real"; ln -s lib.real "$R/lib"; rc "checker: a linked directory" 1 chk "$R"; rm "$R/lib"; mv "$R/lib.real" "$R/lib"
ln -sfn sagebrush-agent-chat.mjs "$R/bin/sagebrush-agent"; rc "checker: the link elsewhere" 1 chk "$R"; ln -sfn sagebrush-agent.mjs "$R/bin/sagebrush-agent"
mkfifo "$R/lib/f"; rc "checker: a FIFO" 1 chk "$R"; rm "$R/lib/f"
chmod g+w "$T"; rc "checker: a writable ancestor" 1 chk "$R"; chmod g-w "$T"
chown 65534 "$T"; rc "checker: a foreign ancestor" 1 chk "$R"; chown 0 "$T"
ln -s rel "$T/rl"; rc "checker: a linked release" 1 chk "$T/rl"; rm "$T/rl"
mkdir -p /tmp/sb-node; cp "$(readlink -f /usr/bin/node)" /tmp/sb-node/node; mv /usr/bin/node /usr/bin/node.sb-aside; ln -s /tmp/sb-node/node /usr/bin/node
rc "checker: node resolving through a writable directory" 1 chk "$R"; rm /usr/bin/node; mv /usr/bin/node.sb-aside /usr/bin/node; rm -rf /tmp/sb-node
rc "checker: a root tree passes again" 0 chk "$R"

# ---- B. the preload regression (SEC): a replace-then-restore payload never runs -----------------------------------
rm -f /run/sb-payload-ran /run/sb-benign-ran
cat > "$R/bin/sagebrush-agent.mjs" <<'EOF'
import fs from "node:fs";
fs.writeFileSync("/run/sb-payload-ran", "1");                          // as root, then put the tree back
fs.chmodSync(new URL("../lib", import.meta.url), 0o755);
EOF
chown 0:0 "$R/bin/sagebrush-agent.mjs"; chmod 644 "$R/bin/sagebrush-agent.mjs"
chmod 775 "$R/lib"                                                       # the writable path the payload came through
/bin/sh "$CHECK" "$R" 2>/dev/null && /usr/bin/node "$R/bin/sagebrush-agent.mjs"
if [ -e /run/sb-payload-ran ]; then bad "preload: the payload ran"; else ok "preload: behind a writable directory, the payload never runs"; fi
chmod 755 "$R/lib"
echo 'import fs from "node:fs"; fs.writeFileSync("/run/sb-benign-ran", "1");' > "$R/bin/sagebrush-agent.mjs"
/bin/sh "$CHECK" "$R" && /usr/bin/node "$R/bin/sagebrush-agent.mjs"
if [ -e /run/sb-benign-ran ]; then ok "preload control: with the tree root's, the dispatcher runs"; else bad "preload control: the benign dispatcher didn't run"; fi
rm -f /run/sb-payload-ran /run/sb-benign-ran
rm -rf "$T"

# ---- C. the installer, fresh-only, against real systemd -----------------------------------------------------------
P=/var/lib/sb-release-parent
D=$P/release
clean() {
  for u in $(systemctl list-units --all --plain --no-legend 'sagebrush-*' 2>/dev/null | awk '{print $1}') $UNIT sagebrush-backup.service sagebrush-backup.timer sagebrush-x.service sagebrush-y.service other.service; do
    systemctl stop "$u" 2>/dev/null; systemctl disable "$u" 2>/dev/null
  done
  for d in $(systemd-analyze unit-paths); do
    [ -d "$d" ] || continue
    find "$d" -maxdepth 2 \( -name 'sagebrush-*' -o -lname '*sagebrush-*' -o -name 'other.service' \) -exec rm -rf {} + 2>/dev/null
  done
  rm -rf /usr/lib/sagebrush /usr/lib/systemd/system-sleep/sagebrush-lease "$P" /run/sb-*-ran
  mkdir -m 0755 "$P"; chown 0:0 "$P"
  systemctl daemon-reload; systemctl reset-failed 2>/dev/null; true
}
snap() { snaptext | md5sum; }
# The whole tree of every install area, recursively: each entry's type, owner, group, mode, size, mtime and link
# target, and the sha256 of every regular file's contents (so a changed byte, mode, owner or link anywhere shows).
snaptree() {
  [ -e "$1" ] || [ -L "$1" ] || return 0
  find "$1" -printf '%y %p %u %g %m %s %T@ ->%l\n' 2>/dev/null | sort
  find "$1" -type f -print0 2>/dev/null | sort -z | xargs -0 -r sha256sum 2>/dev/null
}
snaptext() {
  { for d in /etc/systemd/system /run/systemd/system /run/systemd/system.control /run/systemd/generator \
       /usr/lib/systemd/system /usr/lib/systemd/system-sleep /usr/lib/sagebrush "$P"; do
      snaptree "$d"
    done
    # (/run/systemd/transient holds units the host makes on its own at any time, a CI runner's log collection among
    #  them: only its sagebrush entries, each recursively)
    for e in /run/systemd/transient/sagebrush-*; do snaptree "$e"; done
    # (of /usr/lib, only the sagebrush entry: package updates may change the rest at any time)
    find /usr/lib -maxdepth 1 -name 'sagebrush*' -printf '%y %p %u %g %m %s %T@ ->%l\n' 2>/dev/null
    # (spaces squeezed: systemctl pads its columns to the longest name of ANY unit, so a runner's own unit coming or
    #  going between two snapshots changes the padding of a sagebrush line whose fields are all the same)
    systemctl list-units --all --plain --no-legend 2>/dev/null | grep sagebrush- | tr -s ' '
    systemctl list-unit-files --no-legend 2>/dev/null | grep sagebrush- | tr -s ' '
    for u in $UNIT sagebrush-backup.service; do systemctl show "$u" -p LoadState -p ActiveState -p DropInPaths -p FragmentPath -p NeedDaemonReload 2>/dev/null; done
  }
}
# ri <args>: the ONLY supported invocation: an absolute env -i on the root-owned copy (the cut, in tests, explicitly)
ri() { (cd "$REPO" && /usr/bin/env -i PATH=/usr/bin:/bin ${CUT:+SB_RELEASE_INSTALL_CUT=$CUT} /bin/sh "$SBIN" "$@"); }
inst() { ri "$COMMIT" "$D" "$LAUNCH"; }
markers() { ls /run/sb-*-ran 2>/dev/null | wc -l; }
# refuse_check <label> <setup cmd> <expected message part> [<change after the install, for the controls>]: 0 when the
# install refuses FOR THAT REASON with the snapshots identical and no new marker; prints why otherwise
refuse_check() {
  local label=$1 want=$3 before after m0 out r
  clean; eval "$2"
  snaptext > /tmp/sb-snap-before; before=$(md5sum < /tmp/sb-snap-before); m0=$(markers)
  out=$(inst 2>&1); r=$?
  [ -z "${4:-}" ] || eval "$4"
  snaptext > /tmp/sb-snap-after; after=$(md5sum < /tmp/sb-snap-after)
  [ "$before" = "$after" ] || diff /tmp/sb-snap-before /tmp/sb-snap-after | head -20 | sed 's/^/     changed: /'
  REFUSE_OUT="exit $r, want \"$want\", unchanged=$([ "$before" = "$after" ] && echo yes || echo no), markers $m0->$(markers): ${out:0:300}"
  [ "$r" = 1 ] && [[ "$out" == *"$want"* ]] && [ "$before" = "$after" ] && [ "$(markers)" = "$m0" ] && REFUSE_OUT=${out##*release-install: }
}
# refuses <label> <setup cmd> <expected message part>: the refusal row
refuses() { if refuse_check "$@"; then ok "install refuses: $1 ($REFUSE_OUT)"; else bad "install refuses: $1 ($REFUSE_OUT)"; fi; }
unitfile() { printf '[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/bin/sh -c "touch /run/sb-%s-ran"\n' "$1"; }

install -o root -g root -m 0755 "$INSTALL" "$SBIN"
clean
# C1: the clean positive, and the start goes through release-trust before node
out=$(inst 2>&1); r=$?
if [ "$r" = 0 ]; then ok "install: a clean host installs"; else bad "install: a clean host (exit $r: ${out:0:400})"; fi
rc "install: --verify passes" 0 ri --verify "$D"
rc "install: the installed release's manifest equals the checkout's" 0 /usr/bin/node --input-type=module -e "
  const { leaseManifest } = await import('$REPO/lib/fleet/host/lease-manifest.mjs');
  process.exit(JSON.stringify(leaseManifest('$REPO')) === JSON.stringify(leaseManifest('$D')) ? 0 : 1);"
[ "$(readlink "$D/bin/sagebrush-agent")" = sagebrush-agent.mjs ] && ok "install: the dispatcher link" || bad "install: the dispatcher link"
[ "$(systemctl show $UNIT -p DropInPaths --value)" = "" ] && ok "install: opened (no drop-in)" || bad "install: a drop-in remains"
systemctl start $UNIT 2>/dev/null; sleep 2
pre=$(systemctl show $UNIT -p ExecStartPre --value); main=$(systemctl show $UNIT -p ExecMainStartTimestampMonotonic --value)
# (systemd prints an exited command's status as "code=exited ; status=0", or "status=0/0" in older versions)
case "$pre" in *"code=exited ; status=0 "* | *"code=exited ; status=0/0"*) ok "start: release-trust ran and passed";; *) bad "start: release-trust didn't pass ($pre)";; esac
[ "${main:-0}" != 0 ] && ok "start: node ran after the check" || bad "start: node didn't run"
systemctl stop $UNIT 2>/dev/null; systemctl reset-failed $UNIT 2>/dev/null
# C9: a writable member stops the start in ExecStartPre; a payload dispatcher never runs
chmod 775 "$D/lib"
cp "$D/bin/sagebrush-agent.mjs" /tmp/sb-dispatcher.bak
echo 'import fs from "node:fs"; fs.writeFileSync("/run/sb-payload-ran", "1");' > "$D/bin/sagebrush-agent.mjs"
systemctl start $UNIT 2>/dev/null; sleep 2
main=$(systemctl show $UNIT -p ExecMainStartTimestampMonotonic --value)
if [ "${main:-0}" = 0 ] && [ ! -e /run/sb-payload-ran ]; then ok "start: a writable member stops it in ExecStartPre; the payload never runs"; else bad "start: ran despite a writable member (main=$main)"; fi
cp /tmp/sb-dispatcher.bak "$D/bin/sagebrush-agent.mjs"; chmod 755 "$D/lib"; rm -f /tmp/sb-dispatcher.bak
systemctl reset-failed $UNIT 2>/dev/null
# C8: --verify against a changed effective unit (each refuses; removed, it passes)
mkdir -p /run/systemd/system/$UNIT.d; printf '[Service]\nExecStartPre=\nExecStart=\nExecStart=/bin/true\n' > /run/systemd/system/$UNIT.d/override.conf; systemctl daemon-reload
rc "verify: an overriding drop-in refuses" 1 ri --verify "$D"
rm -rf /run/systemd/system/$UNIT.d; systemctl daemon-reload
echo "# changed" >> /etc/systemd/system/$UNIT
rc "verify: a changed file not reloaded refuses" 1 ri --verify "$D"
sed -i '$d' /etc/systemd/system/$UNIT; systemctl daemon-reload
mkdir -p /run/systemd/system.control; printf '[Service]\nExecStart=/bin/true\n' > /run/systemd/system.control/$UNIT; systemctl daemon-reload
rc "verify: an outranking fragment refuses" 1 ri --verify "$D"
rm -f /run/systemd/system.control/$UNIT; systemctl daemon-reload
rc "verify: restored, it passes" 0 ri --verify "$D"
# reinstalling over it is refused (fresh only)
refuses "an existing install (fresh only)" "inst >/dev/null 2>&1" "<dest> exists"
# Controls for the helper itself (TESTS on #172): with a change slipped in after the refused install, the same row must
# FAIL, for a deep file's contents and for a link's target inside the existing release
if refuse_check "control: a deep content change" "inst >/dev/null 2>&1" "<dest> exists" "printf x >> '$D/lib/fleet/host/lease.mjs'" >/dev/null; then bad "control: a deep content change went unseen by the refusal helper"; else ok "control: a deep content change (lib/fleet/host/lease.mjs) makes the refusal helper fail"; fi
if refuse_check "control: a link retarget" "inst >/dev/null 2>&1" "<dest> exists" "ln -sfn sagebrush-agent-chat.mjs '$D/bin/sagebrush-agent'" >/dev/null; then bad "control: a link retarget went unseen by the refusal helper"; else ok "control: a link retarget (bin/sagebrush-agent) makes the refusal helper fail"; fi

# C2: <dest> exists
refuses "<dest> a file" "touch $D" "<dest> exists"
refuses "<dest> a directory" "mkdir $D" "<dest> exists"
refuses "<dest> a link to a directory" "ln -s /usr $D" "<dest> exists"
refuses "<dest> a dangling link" "ln -s /nonexistent $D" "<dest> exists"
# C3: each legacy entrypoint, separately
refuses "a supervisor fragment on disk" "unitfile sup > /etc/systemd/system/$UNIT" "a sagebrush systemd entry is present"
refuses "a supervisor drop-in directory with a file" "mkdir /etc/systemd/system/$UNIT.d && echo '[Unit]' > /etc/systemd/system/$UNIT.d/x.conf" "not empty"
refuses "a backup service on disk" "unitfile bk > /etc/systemd/system/sagebrush-backup.service" "a sagebrush systemd entry is present"
refuses "a backup timer on disk" "printf '[Timer]\nOnCalendar=daily\n' > /usr/lib/systemd/system/sagebrush-backup.timer" "a sagebrush systemd entry is present"
refuses "a backup template on disk" "unitfile tpl > /usr/lib/systemd/system/sagebrush-backup@.service" "a sagebrush systemd entry is present"
refuses "the sleep shim" "printf '#!/bin/sh\ntouch /run/sb-shim-ran\n' > /usr/lib/systemd/system-sleep/sagebrush-lease" "the sleep shim is present"
refuses "a file under /usr/lib/sagebrush" "mkdir -m 0755 /usr/lib/sagebrush && touch /usr/lib/sagebrush/release-trust" "not empty"
refuses "a unit in /run/systemd/system" "unitfile run > /run/systemd/system/sagebrush-x.service" "a sagebrush systemd entry is present"
refuses "a unit in system.control" "mkdir -p /run/systemd/system.control && unitfile ctl > /run/systemd/system.control/$UNIT" "a sagebrush systemd entry is present"
refuses "a generated unit" "mkdir -p /run/systemd/generator && unitfile gen > /run/systemd/generator/sagebrush-y.service" "a sagebrush systemd entry is present"
refuses "loaded only (file gone, no reload; kept loaded by being active)" "unitfile ld > /etc/systemd/system/sagebrush-x.service && systemctl daemon-reload && systemctl start sagebrush-x.service && rm /etc/systemd/system/sagebrush-x.service" "systemd knows a sagebrush unit"
refuses "a loaded transient unit" "systemd-run --unit=sagebrush-x --remain-after-exit /bin/true >/dev/null 2>&1" "a sagebrush systemd entry is present"
refuses "an alias under another name" "unitfile al > /etc/systemd/system/sagebrush-x.service && ln -s /etc/systemd/system/sagebrush-x.service /etc/systemd/system/other.service && systemctl daemon-reload" "a sagebrush systemd entry is present"
refuses "a drop-in for the supervisor in /run" "mkdir -p /run/systemd/system/$UNIT.d && printf '[Unit]\nConditionPathExists=\n' > /run/systemd/system/$UNIT.d/99-reset.conf" "a sagebrush systemd entry is present"
refuses "enabled (a wants link only)" "mkdir -p /etc/systemd/system/multi-user.target.wants && ln -s /usr/lib/systemd/system/sagebrush-backup.service /etc/systemd/system/multi-user.target.wants/sagebrush-backup.service" "a sagebrush systemd entry is present"
refuses "active" "unitfile act > /run/systemd/system/sagebrush-x.service && systemctl daemon-reload && systemctl start sagebrush-x.service" "a sagebrush systemd entry is present"
refuses "failed (remembered)" "printf '[Service]\nExecStart=/bin/false\n' > /run/systemd/system/sagebrush-x.service && systemctl daemon-reload && systemctl start sagebrush-x.service; rm /run/systemd/system/sagebrush-x.service; systemctl daemon-reload" "systemd knows a sagebrush unit"
refuses "all of them together" "unitfile a > /etc/systemd/system/$UNIT; unitfile b > /etc/systemd/system/sagebrush-backup.service; printf '#!/bin/sh\n' > /usr/lib/systemd/system-sleep/sagebrush-lease; mkdir -p /run/systemd/system/$UNIT.d; echo '[Unit]' > /run/systemd/system/$UNIT.d/x.conf; systemd-run --unit=sagebrush-x --remain-after-exit /bin/true >/dev/null 2>&1; systemctl daemon-reload" "not a fresh host"
# C4: each later chain failing while /usr/lib/sagebrush starts absent (it stays absent: the snapshot covers /usr/lib)
refuses "/etc/systemd/system group-writable" "chmod g+w /etc/systemd/system" "group- or other-writable: /etc/systemd/system"; chmod g-w /etc/systemd/system
refuses "system-sleep foreign-owned" "chown 65534 /usr/lib/systemd/system-sleep" "not owned by root: /usr/lib/systemd/system-sleep"; chown 0 /usr/lib/systemd/system-sleep
refuses "<dest>'s parent writable" "chmod o+w $P" "group- or other-writable: $P"; chmod o-w "$P" 2>/dev/null
refuses "node through a writable directory" "mkdir -p /tmp/sb-node && cp \"\$(readlink -f /usr/bin/node)\" /tmp/sb-node/node && mv /usr/bin/node /usr/bin/node.sb-aside && ln -s /tmp/sb-node/node /usr/bin/node" "group- or other-writable: /tmp"
[ -e /usr/bin/node.sb-aside ] && { rm -f /usr/bin/node; mv /usr/bin/node.sb-aside /usr/bin/node; rm -rf /tmp/sb-node; }
# C5: the PATH control: fakes first on PATH, never executed, refusals unchanged
clean; mkdir -p /tmp/sb-fake
for f in find stat readlink sh node systemctl busctl systemd-analyze; do printf '#!/bin/sh\ntouch /run/sb-fake-%s-ran\nexit 0\n' "$f" > /tmp/sb-fake/$f; chmod 755 /tmp/sb-fake/$f; done
unitfile sup > /etc/systemd/system/$UNIT
out=$(cd "$REPO" && /usr/bin/env -i PATH=/tmp/sb-fake:/usr/bin:/bin /bin/sh "$SBIN" "$COMMIT" "$D" "$LAUNCH" 2>&1); r=$?
mkdir -p "$T/rel/lib" && chmod 775 "$T/rel/lib"
PATH=/tmp/sb-fake:$PATH /bin/sh "$CHECK" "$T/rel" >/dev/null 2>&1; r2=$?
if [ "$r" != 0 ] && [ "$r2" != 0 ] && ! ls /run/sb-fake-*-ran >/dev/null 2>&1; then ok "PATH: fakes first on PATH never run; the installer and the checker still refuse"; else bad "PATH: a fake ran or a refusal changed ($r $r2; $(ls /run/sb-fake-*-ran 2>/dev/null))"; fi
rm -rf /tmp/sb-fake /run/sb-fake-*-ran "$T"
# C10: the launcher pin (SEC on #172): a wrong digest refuses with nothing changed; the root installer runs no
# toolchain, wrapper, Cargo config or git filter of the caller's, and the pinned launcher installs
cp "$LAUNCH" /tmp/sb-bad-launch; printf '\0' >> /tmp/sb-bad-launch
refuses "a launcher whose digest isn't the pinned one" "LAUNCH_SAVE=\$LAUNCH; LAUNCH=/tmp/sb-bad-launch" "the launcher's digest isn't the pinned one"; LAUNCH=$LAUNCH_SAVE; rm -f /tmp/sb-bad-launch
clean; mkdir -p /tmp/sb-tool/bin /tmp/sb-tool/cargo
for f in cargo rustc bash rustup cc; do printf '#!/bin/sh\ntouch /run/sb-tool-%s-ran\nexit 0\n' "$f" > /tmp/sb-tool/bin/$f; chmod 755 /tmp/sb-tool/bin/$f; done
printf '#!/bin/sh\ntouch /run/sb-tool-wrapper-ran\nexec "$@"\n' > /tmp/sb-tool/wrap; chmod 755 /tmp/sb-tool/wrap
printf '[build]\nrustc-wrapper = "/tmp/sb-tool/wrap"\n' > /tmp/sb-tool/cargo/config.toml
printf '#!/bin/sh\ntouch /run/sb-tool-filter-ran\ncat\n' > /tmp/sb-tool/smudge; chmod 755 /tmp/sb-tool/smudge
printf '#!/bin/sh\ntouch /run/sb-tool-tar-ran\n' > /tmp/sb-tool/tarmark; chmod 755 /tmp/sb-tool/tarmark
mkdir -p "$REPO/.git/info" 2>/dev/null; gitdir=$(git -c safe.directory='*' -C "$REPO" rev-parse --git-common-dir)
cp "$gitdir/config" /tmp/sb-tool/config.bak; printf '* filter=evil\n' >> "$gitdir/info/attributes"
git -c safe.directory='*' -C "$REPO" config filter.evil.smudge /tmp/sb-tool/smudge
# The caller's environment can't reach the installer: a dirty one (fakes first on PATH, a Cargo home and wrapper,
# TAR_OPTIONS) refuses at entry, before any tool runs; the clean supported invocation, with a git filter configured
# in the clone, installs the pinned launcher and runs no filter
out=$(cd "$REPO" && /usr/bin/env -i PATH=/tmp/sb-tool/bin:/usr/bin:/bin CARGO_HOME=/tmp/sb-tool/cargo RUSTC_WRAPPER=/tmp/sb-tool/wrap \
  "TAR_OPTIONS=--checkpoint=1 --checkpoint-action=exec=/tmp/sb-tool/tarmark" /bin/sh "$SBIN" "$COMMIT" "$D" "$LAUNCH" 2>&1); r=$?
if [ "$r" = 1 ] && [[ "$out" == *"isn't the supported one"* ]] && ! ls /run/sb-tool-*-ran >/dev/null 2>&1 && [ ! -e "$D" ]; then ok "toolchain: a dirty environment (PATH fakes, Cargo home and wrapper, TAR_OPTIONS) refuses at entry; nothing of it ran"
else bad "toolchain (dirty environment): exit $r, ran: $(ls /run/sb-tool-*-ran 2>/dev/null | tr '\n' ' ') ${out:0:300}"; fi
clean
out=$(inst 2>&1); r=$?
if [ "$r" = 0 ] && ! ls /run/sb-tool-*-ran >/dev/null 2>&1; then ok "toolchain: the clean invocation installs with a git filter configured in the clone; the filter never runs"
else bad "toolchain: exit $r, ran: $(ls /run/sb-tool-*-ran 2>/dev/null | tr '\n' ' ') ${out:0:300}"; fi
[ "$(sha256sum < "$D/bin/sagebrush-agent-launch" | cut -d' ' -f1)" = "$(cut -d' ' -f1 "$REPO/lib/fleet/host/launcher.sha256")" ] && ok "toolchain: the installed launcher is the pinned bytes" || bad "toolchain: the installed launcher isn't the pinned bytes"
cp /tmp/sb-tool/config.bak "$gitdir/config"; sed -i '/^\* filter=evil$/d' "$gitdir/info/attributes"; rm -rf /tmp/sb-tool /run/sb-tool-*-ran
# One hostile environment inside env -i (SEC on #172): the installer refuses at entry, and nothing it would run acts
clean; mkdir -p /tmp/sb-env
printf '#!/bin/sh\ntouch /run/sb-env-%s-ran\n' tar > /tmp/sb-env/tar; printf '#!/bin/sh\ntouch /run/sb-env-bashenv-ran\n' > /tmp/sb-env/bashenv
printf '#!/bin/sh\ntouch /run/sb-env-fsmonitor-ran\n' > /tmp/sb-env/fsmon; chmod 755 /tmp/sb-env/tar /tmp/sb-env/bashenv /tmp/sb-env/fsmon
# the preload library records every process that loads it, by name: only the ones that start the installer (env,
# and the script itself before its re-exec) may appear, never a tool the installer runs
cat > /tmp/sb-env/p.c <<'EOF_C'
#include <stdio.h>
#include <string.h>
__attribute__((constructor)) static void m(void) {
  char c[64] = "", p[128]; FILE *f = fopen("/proc/self/comm", "r");
  if (f) { if (fgets(c, sizeof c, f)) c[strcspn(c, "\n")] = 0; fclose(f); }
  snprintf(p, sizeof p, "/run/sb-env-preload-%s", c); f = fopen(p, "w"); if (f) fclose(f);
}
EOF_C
cc -shared -fPIC -o /tmp/sb-env/p.so /tmp/sb-env/p.c 2>/dev/null || echo "     (no cc: the LD_PRELOAD library is absent; the variable is still set)"
snaptext > /tmp/sb-snap-before
out=$(cd "$REPO" && /usr/bin/env -i PATH=/usr/bin:/bin "TAR_OPTIONS=--checkpoint=1 --checkpoint-action=exec=/tmp/sb-env/tar" \
  "GIT_CONFIG_PARAMETERS='core.fsmonitor=/tmp/sb-env/fsmon'" LD_PRELOAD=/tmp/sb-env/p.so BASH_ENV=/tmp/sb-env/bashenv ENV=/tmp/sb-env/bashenv \
  /bin/sh "$SBIN" "$COMMIT" "$D" "$LAUNCH" 2>&1); r=$?
snaptext > /tmp/sb-snap-after
m=$(ls /run/sb-env-* 2>/dev/null | grep -v -e '^/run/sb-env-preload-env$' -e '^/run/sb-env-preload-sh$' -e '^/run/sb-env-preload-dash$' -e '^/run/sb-env-preload-release-install$' | tr '\n' ' ')
# (an LD_PRELOAD given to the interpreter itself acts before any script line: that is the launcher's to prevent, and
#  sudo's env_reset does; what the installer does is refuse, and run nothing)
if [ "$r" = 1 ] && [[ "$out" == *"isn't the supported one"* ]] && [ -z "$m" ] && cmp -s /tmp/sb-snap-before /tmp/sb-snap-after; then ok "hostile environment (TAR_OPTIONS, GIT_CONFIG_PARAMETERS, LD_PRELOAD, BASH_ENV, ENV) inside env -i: refused at entry; no tool ran; nothing changed"
else bad "hostile environment: exit $r, ran: $m ${out:0:300}"; fi
rm -rf /tmp/sb-env /run/sb-env-*
# C11: the entrypoint contract (lease-on r1.13): only a root-owned script path, only the exact environment, only a
# self-contained object store
clean
r=0; out=$(cd "$REPO" && /usr/bin/env -i PATH=/usr/bin:/bin /bin/sh "$INSTALL" "$COMMIT" "$D" "$LAUNCH" 2>&1) || r=$?
if [ "$(stat -c %u "$INSTALL")" != 0 ]; then
  [ "$r" = 1 ] && [[ "$out" == *"not owned by root"* ]] && [ ! -e "$D" ] && ok "entrypoint: the caller's own (non-root) copy refuses" || bad "entrypoint: the caller's copy ran ($r: ${out:0:200})"
fi
mkdir -p /var/lib/sb-inst-w && chmod 0777 /var/lib/sb-inst-w && install -o root -g root -m 0755 "$INSTALL" /var/lib/sb-inst-w/ri
r=0; out=$(cd "$REPO" && /usr/bin/env -i PATH=/usr/bin:/bin /bin/sh /var/lib/sb-inst-w/ri "$COMMIT" "$D" "$LAUNCH" 2>&1) || r=$?
[ "$r" = 1 ] && [[ "$out" == *"group- or other-writable: /var/lib/sb-inst-w"* ]] && [ ! -e "$D" ] && ok "entrypoint: a root-owned copy in a writable directory refuses" || bad "entrypoint: a writable parent ran ($r: ${out:0:200})"
rm -rf /var/lib/sb-inst-w
r=0; out=$(cd /usr/local/sbin && /usr/bin/env -i PATH=/usr/bin:/bin /bin/sh sagebrush-release-install "$COMMIT" "$D" "$LAUNCH" 2>&1) || r=$?
[ "$r" = 1 ] && [[ "$out" == *"absolute, root-owned path"* ]] && ok "entrypoint: a relative script path refuses" || bad "entrypoint: a relative path ran ($r: ${out:0:200})"
r=0; out=$(cd "$REPO" && /usr/bin/env -i PATH=/usr/bin:/bin SB_EXTRA=1 /bin/sh "$SBIN" "$COMMIT" "$D" "$LAUNCH" 2>&1) || r=$?
[ "$r" = 1 ] && [[ "$out" == *"isn't the supported one"* ]] && [ ! -e "$D" ] && ok "entrypoint: one extra variable refuses" || bad "entrypoint: an extra variable ran ($r: ${out:0:200})"
for kind in alternates http-alternates; do
  clean; rm -rf /var/lib/sb-alt
  # (the file written explicitly: `clone --shared` from a shallow checkout, as CI's is, silently makes no alternates)
  git -c safe.directory='*' clone -q --no-hardlinks "$REPO" /var/lib/sb-alt && mkdir -p /var/lib/sb-alt/.git/objects/info
  if [ "$kind" = alternates ]; then echo "$(git -c safe.directory='*' -C "$REPO" rev-parse --path-format=absolute --git-common-dir)/objects" > /var/lib/sb-alt/.git/objects/info/alternates
  else echo "https://example.invalid/objects" > /var/lib/sb-alt/.git/objects/info/http-alternates; fi
  r=0; out=$(cd /var/lib/sb-alt && /usr/bin/env -i PATH=/usr/bin:/bin /bin/sh "$SBIN" "$COMMIT" "$D" "$LAUNCH" 2>&1) || r=$?
  [ "$r" = 1 ] && [[ "$out" == *"uses alternates"* ]] && [ ! -e "$D" ] && ok "entrypoint: a clone with $kind refuses" || bad "entrypoint: $kind didn't refuse ($r: ${out:0:200})"
done
rm -rf /var/lib/sb-alt
# C6: cuts. After each, nothing starts; after the mkdirs only, a retry completes
for step in 1m 2 3 4 5 6; do
  clean
  out=$(CUT=$step inst 2>&1); r=$?
  [ "$r" = 9 ] && ok "cut after step $step: the install reached it" || bad "cut after step $step: didn't reach the cut (exit $r: ${out:0:300})"
  systemctl start $UNIT >/dev/null 2>&1; sleep 1
  main=$(systemctl show $UNIT -p ExecMainStartTimestampMonotonic --value 2>/dev/null)
  if [ "${main:-0}" = 0 ]; then ok "cut after step $step: nothing starts"; else bad "cut after step $step: the unit started"; fi
  if [ "$step" = 6 ]; then
    c=$(busctl get-property org.freedesktop.systemd1 "$(busctl call org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager LoadUnit s $UNIT | sed -n 's/^o "\(.*\)"$/\1/p')" org.freedesktop.systemd1.Unit Conditions)
    case "$c" in 'a(sbbsi) 1 "ConditionPathExists" false false "/nonexistent/sagebrush-closed" '*) ok "cut after step 6: the effective closed condition is in force";; *) bad "cut after step 6: conditions $c";; esac
  fi
  if [ "$step" = 1m ]; then
    out=$(inst 2>&1); r=$?
    [ "$r" = 0 ] && ok "cut after the mkdirs: a retry completes" || bad "cut after the mkdirs: the retry failed ($r: ${out:0:300})"
    clean; mkdir -m 0755 /usr/lib/sagebrush; touch /usr/lib/sagebrush/planted
    out=$(inst 2>&1); r=$?
    [ "$r" != 0 ] && ok "cut after the mkdirs, then a planted file: the retry refuses" || bad "a planted file after a cut: the retry succeeded"
  fi
done
clean
rm -f "$SBIN"
echo "release-trust-test: $FAILS failure(s)"
[ "$FAILS" = 0 ]
