#!/bin/bash
# Tests only: the S3-compatible server the backup binary's integration tests start (backup/tests/s3.rs), SeaweedFS
# 4.53's linux_amd64 release, fetched from its GitHub release and checked against pinned SHA-256s (the archive's and
# the binary's). Never shipped or linked.
#   scripts/fetch-test-s3.sh DEST_DIR      (then SB_TEST_WEED=DEST_DIR/bin/weed)
set -euo pipefail
dest=${1:?usage: scripts/fetch-test-s3.sh DEST_DIR}
url=https://github.com/seaweedfs/seaweedfs/releases/download/4.53/linux_amd64.tar.gz
archive_sha=d1a7dec9f48d8b33895a0ea8951971defc2dc5312906dcc76fa5a5f74a6ee90d
weed_sha=fa936e61bfb11f33c1f823045c4007e7da4b8b38bb6adc3b970f132d832e805b
[ "$(uname -s)/$(uname -m)" = Linux/x86_64 ] || { echo "fetch-test-s3: only linux x86_64 is pinned" >&2; exit 1; }
if [ -x "$dest/bin/weed" ] && echo "$weed_sha  $dest/bin/weed" | sha256sum -c --quiet 2>/dev/null; then
  echo "fetch-test-s3: $dest/bin/weed already there"
  exit 0
fi
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl -fsSL --retry 3 --max-time 300 -o "$tmp/weed.tgz" "$url"
echo "$archive_sha  $tmp/weed.tgz" | sha256sum -c --quiet
tar -xzf "$tmp/weed.tgz" -C "$tmp" weed
echo "$weed_sha  $tmp/weed" | sha256sum -c --quiet
mkdir -p "$dest/bin"
install -m 0755 "$tmp/weed" "$dest/bin/weed"
echo "fetch-test-s3: SeaweedFS 4.53 at $dest/bin/weed"
