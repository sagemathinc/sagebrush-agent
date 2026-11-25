#!/bin/bash
# The trust boundary's rows (lease-on design r1.12 §2.6, §7): the checker, the preload regression, and the FRESH
# installer against real systemd. Destructive to sagebrush state: run only on a disposable host (a CI runner, a VM).
#
#   sudo scripts/release-trust-test.sh          (root; systemd running; /usr/bin/node a root-owned node binary)
#
# Every row prints "ok" or "FAIL"; the script exits 1 if any row failed. It removes every sagebrush unit, drop-in,
# shim, checker and test release before and after the installer rows.
set -uo pipefail
REPO=$(cd "$(dirname "$0")/.." && pwd -P)
CHECK="$REPO/scripts/release-trust.sh"
INSTALL="$REPO/scripts/release-install.sh"
UNIT=sagebrush-supervisor.service
FAILS=0
ok() { echo "ok   $1"; }
bad() { echo "FAIL $1"; FAILS=$((FAILS + 1)); }
# rc <label> <want> <cmd...>: the command's exit status is <want>
rc() { local label=$1 want=$2; shift 2; local out r; out=$("$@" 2>&1); r=$?; if [ "$r" = "$want" ]; then ok "$label"; else bad "$label (exit $r, want $want: ${out:0:300})"; fi; }

[ "$(id -u)" = 0 ] || { echo "release-trust-test: run as root" >&2; exit 2; }
[ -d /run/systemd/system ] || { echo "release-trust-test: systemd isn't running" >&2; exit 2; }
[ "$(stat -c %u "$(readlink -f /usr/bin/node)")" = 0 ] || { echo "release-trust-test: /usr/bin/node must be root's" >&2; exit 2; }

# ---- A. the checker ------------------------------------------------------------------------------------------------
T=/opt/sb-trust-test
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
D=/opt/sb-release-test
clean() {
  for u in $(systemctl list-units --all --plain --no-legend 'sagebrush-*' 2>/dev/null | awk '{print $1}') $UNIT sagebrush-backup.service sagebrush-backup.timer sagebrush-x.service sagebrush-y.service other.service; do
    systemctl stop "$u" 2>/dev/null; systemctl disable "$u" 2>/dev/null
  done
  for d in $(systemd-analyze unit-paths); do
    [ -d "$d" ] || continue
    find "$d" -maxdepth 2 \( -name 'sagebrush-*' -o -lname '*sagebrush-*' -o -name 'other.service' \) -exec rm -rf {} + 2>/dev/null
  done
  rm -rf /usr/lib/sagebrush /usr/lib/systemd/system-sleep/sagebrush-lease "$D" /opt/.sb-release.* /run/sb-*-ran
  systemctl daemon-reload; systemctl reset-failed 2>/dev/null; true
}
snap() {
  { for d in /etc/systemd/system /run/systemd/system /run/systemd/system.control /run/systemd/transient /run/systemd/generator \
       /usr/lib/systemd/system /usr/lib/systemd/system-sleep /usr/lib /opt; do
      [ -d "$d" ] && find "$d" -maxdepth 2 -printf '%p %u %m %s %T@\n' 2>/dev/null | grep -v -e '^/opt/sb-release-test' | sort
    done
    systemctl list-units --all --plain --no-legend 'sagebrush-*' 2>/dev/null
    systemctl list-unit-files --no-legend 'sagebrush-*' 2>/dev/null
    for u in $UNIT sagebrush-backup.service; do systemctl show "$u" -p LoadState -p ActiveState -p DropInPaths -p FragmentPath -p NeedDaemonReload 2>/dev/null; done
  } | md5sum
}
inst() { (cd "$REPO" && "$INSTALL" HEAD "$D"); }
markers() { ls /run/sb-*-ran 2>/dev/null | wc -l; }
# refuses <label> <setup cmd> : the install refuses, snapshots identical, no new marker
refuses() {
  local label=$1 before after m0 out r
  clean; eval "$2"
  before=$(snap); m0=$(markers)
  out=$(inst 2>&1); r=$?
  after=$(snap)
  if [ "$r" != 0 ] && [ "$before" = "$after" ] && [ "$(markers)" = "$m0" ]; then ok "install refuses: $label (${out##*release-install: })"
  else bad "install refuses: $label (exit $r, unchanged=$([ "$before" = "$after" ] && echo yes || echo no), markers $m0->$(markers): ${out:0:300})"; fi
}
unitfile() { printf '[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/bin/sh -c "touch /run/sb-%s-ran"\n' "$1"; }

clean
# C1: the clean positive, and the start goes through release-trust before node
out=$(inst 2>&1); r=$?
if [ "$r" = 0 ]; then ok "install: a clean host installs"; else bad "install: a clean host (exit $r: ${out:0:400})"; fi
rc "install: --verify passes" 0 bash -c "cd '$REPO' && '$INSTALL' --verify '$D'"
rc "install: the installed release's manifest equals the checkout's" 0 /usr/bin/node --input-type=module -e "
  const { leaseManifest } = await import('$REPO/lib/fleet/host/lease-manifest.mjs');
  process.exit(JSON.stringify(leaseManifest('$REPO')) === JSON.stringify(leaseManifest('$D')) ? 0 : 1);"
[ "$(readlink "$D/bin/sagebrush-agent")" = sagebrush-agent.mjs ] && ok "install: the dispatcher link" || bad "install: the dispatcher link"
[ "$(systemctl show $UNIT -p DropInPaths --value)" = "" ] && ok "install: opened (no drop-in)" || bad "install: a drop-in remains"
systemctl start $UNIT 2>/dev/null; sleep 2
pre=$(systemctl show $UNIT -p ExecStartPre --value); main=$(systemctl show $UNIT -p ExecMainStartTimestampMonotonic --value)
case "$pre" in *"status=0/0"*) ok "start: release-trust ran and passed";; *) bad "start: release-trust didn't pass ($pre)";; esac
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
rc "verify: an overriding drop-in refuses" 1 bash -c "cd '$REPO' && '$INSTALL' --verify '$D'"
rm -rf /run/systemd/system/$UNIT.d; systemctl daemon-reload
echo "# changed" >> /etc/systemd/system/$UNIT
rc "verify: a changed file not reloaded refuses" 1 bash -c "cd '$REPO' && '$INSTALL' --verify '$D'"
sed -i '$d' /etc/systemd/system/$UNIT; systemctl daemon-reload
mkdir -p /run/systemd/system.control; printf '[Service]\nExecStart=/bin/true\n' > /run/systemd/system.control/$UNIT; systemctl daemon-reload
rc "verify: an outranking fragment refuses" 1 bash -c "cd '$REPO' && '$INSTALL' --verify '$D'"
rm -f /run/systemd/system.control/$UNIT; systemctl daemon-reload
rc "verify: restored, it passes" 0 bash -c "cd '$REPO' && '$INSTALL' --verify '$D'"
# reinstalling over it is refused (fresh only)
refuses "an existing install (fresh only)" "inst >/dev/null 2>&1"

# C2: <dest> exists
refuses "<dest> a file" "touch $D"
refuses "<dest> a directory" "mkdir $D"
refuses "<dest> a link to a directory" "ln -s /usr $D"
refuses "<dest> a dangling link" "ln -s /nonexistent $D"
# C3: each legacy entrypoint, separately
refuses "a supervisor fragment on disk" "unitfile sup > /etc/systemd/system/$UNIT"
refuses "a supervisor drop-in directory with a file" "mkdir /etc/systemd/system/$UNIT.d && echo '[Unit]' > /etc/systemd/system/$UNIT.d/x.conf"
refuses "a backup service on disk" "unitfile bk > /etc/systemd/system/sagebrush-backup.service"
refuses "a backup timer on disk" "printf '[Timer]\nOnCalendar=daily\n' > /usr/lib/systemd/system/sagebrush-backup.timer"
refuses "a backup template on disk" "unitfile tpl > /usr/lib/systemd/system/sagebrush-backup@.service"
refuses "the sleep shim" "printf '#!/bin/sh\ntouch /run/sb-shim-ran\n' > /usr/lib/systemd/system-sleep/sagebrush-lease"
refuses "a file under /usr/lib/sagebrush" "mkdir -m 0755 /usr/lib/sagebrush && touch /usr/lib/sagebrush/release-trust"
refuses "a unit in /run/systemd/system" "unitfile run > /run/systemd/system/sagebrush-x.service"
refuses "a unit in system.control" "mkdir -p /run/systemd/system.control && unitfile ctl > /run/systemd/system.control/$UNIT"
refuses "a generated unit" "mkdir -p /run/systemd/generator && unitfile gen > /run/systemd/generator/sagebrush-y.service"
refuses "loaded only (file gone, no reload)" "unitfile ld > /etc/systemd/system/sagebrush-x.service && systemctl daemon-reload && rm /etc/systemd/system/sagebrush-x.service"
refuses "a loaded transient unit" "systemd-run --unit=sagebrush-x --remain-after-exit /bin/true >/dev/null 2>&1"
refuses "an alias under another name" "unitfile al > /etc/systemd/system/sagebrush-x.service && ln -s /etc/systemd/system/sagebrush-x.service /etc/systemd/system/other.service && systemctl daemon-reload"
refuses "a drop-in for the supervisor in /run" "mkdir -p /run/systemd/system/$UNIT.d && printf '[Unit]\nConditionPathExists=\n' > /run/systemd/system/$UNIT.d/99-reset.conf"
refuses "enabled (a wants link only)" "mkdir -p /etc/systemd/system/multi-user.target.wants && ln -s /usr/lib/systemd/system/sagebrush-backup.service /etc/systemd/system/multi-user.target.wants/sagebrush-backup.service"
refuses "active" "unitfile act > /run/systemd/system/sagebrush-x.service && systemctl daemon-reload && systemctl start sagebrush-x.service"
refuses "failed (remembered)" "printf '[Service]\nExecStart=/bin/false\n' > /run/systemd/system/sagebrush-x.service && systemctl daemon-reload && systemctl start sagebrush-x.service; rm /run/systemd/system/sagebrush-x.service; systemctl daemon-reload"
refuses "all of them together" "unitfile a > /etc/systemd/system/$UNIT; unitfile b > /etc/systemd/system/sagebrush-backup.service; printf '#!/bin/sh\n' > /usr/lib/systemd/system-sleep/sagebrush-lease; mkdir -p /run/systemd/system/$UNIT.d; echo '[Unit]' > /run/systemd/system/$UNIT.d/x.conf; systemd-run --unit=sagebrush-x --remain-after-exit /bin/true >/dev/null 2>&1; systemctl daemon-reload"
# C4: each later chain failing while /usr/lib/sagebrush starts absent (it stays absent: the snapshot covers /usr/lib)
refuses "/etc/systemd/system group-writable" "chmod g+w /etc/systemd/system"; chmod g-w /etc/systemd/system
refuses "system-sleep foreign-owned" "chown 65534 /usr/lib/systemd/system-sleep"; chown 0 /usr/lib/systemd/system-sleep
refuses "<dest>'s parent writable" "mkdir -p /opt && chmod o+w /opt"; chmod o-w /opt
refuses "node through a writable directory" "mkdir -p /tmp/sb-node && cp \"\$(readlink -f /usr/bin/node)\" /tmp/sb-node/node && mv /usr/bin/node /usr/bin/node.sb-aside && ln -s /tmp/sb-node/node /usr/bin/node"
[ -e /usr/bin/node.sb-aside ] && { rm -f /usr/bin/node; mv /usr/bin/node.sb-aside /usr/bin/node; rm -rf /tmp/sb-node; }
# C5: the PATH control: fakes first on PATH, never executed, refusals unchanged
clean; mkdir -p /tmp/sb-fake
for f in find stat readlink sh node systemctl busctl systemd-analyze; do printf '#!/bin/sh\ntouch /run/sb-fake-%s-ran\nexit 0\n' "$f" > /tmp/sb-fake/$f; chmod 755 /tmp/sb-fake/$f; done
unitfile sup > /etc/systemd/system/$UNIT
out=$(cd "$REPO" && PATH=/tmp/sb-fake:$PATH "$INSTALL" HEAD "$D" 2>&1); r=$?
mkdir -p /opt/sb-trust-test/rel/lib && chmod 775 /opt/sb-trust-test/rel/lib
PATH=/tmp/sb-fake:$PATH /bin/sh "$CHECK" /opt/sb-trust-test/rel >/dev/null 2>&1; r2=$?
if [ "$r" != 0 ] && [ "$r2" != 0 ] && ! ls /run/sb-fake-*-ran >/dev/null 2>&1; then ok "PATH: fakes first on PATH never run; the installer and the checker still refuse"; else bad "PATH: a fake ran or a refusal changed ($r $r2; $(ls /run/sb-fake-*-ran 2>/dev/null))"; fi
rm -rf /tmp/sb-fake /run/sb-fake-*-ran /opt/sb-trust-test
# C6: cuts. After each, nothing starts; after the mkdirs only, a retry completes
for step in 1m 2 3 4 5 6; do
  clean
  (cd "$REPO" && SB_RELEASE_INSTALL_CUT=$step "$INSTALL" HEAD "$D" >/dev/null 2>&1)
  systemctl start $UNIT >/dev/null 2>&1; sleep 1
  main=$(systemctl show $UNIT -p ExecMainStartTimestampMonotonic --value 2>/dev/null)
  if [ "${main:-0}" = 0 ]; then ok "cut after step $step: nothing starts"; else bad "cut after step $step: the unit started"; fi
  if [ "$step" = 6 ]; then
    c=$(busctl get-property org.freedesktop.systemd1 "$(busctl call org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager GetUnit s $UNIT | sed -n 's/^o "\(.*\)"$/\1/p')" org.freedesktop.systemd1.Unit Conditions)
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
echo "release-trust-test: $FAILS failure(s)"
[ "$FAILS" = 0 ]
