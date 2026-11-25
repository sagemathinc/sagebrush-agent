#!/bin/sh
# A qualified release's layout (lease-on design r1.7 §2.5, C6), and a bound member of the lease qualification:
#
#   scripts/release-install.sh <commit> <dest>        (run as root, from a clone holding <commit>)
#
# <dest> (which must not exist) becomes: every file `git archive <commit>` holds; bin/sagebrush-agent-launch, the
# output of scripts/launcher-build.sh built from that same tree, 0755; bin/sagebrush-agent, a relative link to
# sagebrush-agent.mjs (what the units run). Root's throughout, with no group or other write: leaseQualified() proves
# exactly that, from / down to every member. No node_modules: the lease path imports none. Delivering a release to a
# host is not this script's business; any other layout is simply unqualified.
set -eu

[ "$#" -eq 2 ] || { echo "usage: scripts/release-install.sh <commit> <dest>" >&2; exit 2; }
commit=$1
dest=$2
case "$dest" in /*) ;; *) echo "release-install: <dest> must be absolute" >&2; exit 2 ;; esac
[ ! -e "$dest" ] && [ ! -L "$dest" ] || { echo "release-install: $dest exists" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || { echo "release-install: run as root" >&2; exit 1; }
git rev-parse --verify --quiet "$commit^{commit}" >/dev/null || { echo "release-install: no such commit" >&2; exit 1; }

umask 022
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir "$work/tree"
git archive --format=tar "$commit" | tar -x --no-same-owner --no-same-permissions -C "$work/tree"
(cd "$work/tree" && scripts/launcher-build.sh "$work/tree/bin/sagebrush-agent-launch")
ln -s sagebrush-agent.mjs "$work/tree/bin/sagebrush-agent"
chown -R -h 0:0 "$work/tree"
chmod -R go-w "$work/tree"
chmod 0755 "$work/tree/bin/sagebrush-agent-launch"
mv "$work/tree" "$dest"
