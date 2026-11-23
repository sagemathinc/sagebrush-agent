# sagebrush-agent-backup

The encrypted backup engine of an Autonomous agent host. It follows the host backup design, r3.3. The host side decides when each operation runs (scheduling, freezing agents, manifests, retention, restore order). This binary does one operation exactly, per run.

```
sagebrush-agent-backup --state DIR --secrets DIR [--cache DIR] < request.json > result.json
```

**Input and output:**
- One JSON request on stdin (at most 64 KiB), with `op` one of `init`, `add-key`, `backup`, `readback`, `check-data`, `snapshots`, `dump`, `restore`, `forget` or `prune`.
- One JSON result on stdout: `{"ok": true, ...}` with exit 0, or `{"ok": false, "error": {"code", "message"}}` with exit 1.
- The library's warnings go to stderr, bounded.

**What it refuses, by construction:**
- **Secrets only by handle.** `DIR/dest.json` names an `s3` destination and a credential handle. The credential is in `SECRETS/<handle>`, and the repository password is in `DIR/host.key`. Each must be a regular file, owned by this user, mode 0600. Nothing secret comes from argv or the environment. AWS config files and instance metadata are never read.
- **One destination type, `s3`, over https,** with system roots and no redirect followed. Plain http is allowed only for a loopback endpoint, and only in a build with the test-only `test-loopback-http` feature.
- **No automatic init.** Only `init` creates a repository; every other operation on an empty destination fails with `repository_missing`.
- **Change detection is never weakened:** a backup always compares ctime and inode against its parent.
- **Restore requires `CAP_SYS_RESOURCE` to be gone** from all five capability sets, and sets `no_new_privs`, so the kernel enforces the agent's project quota. Removing the capability is the caller's job (the launcher's runner). A quota hit is reported as `quota_exceeded`, and a full filesystem as `no_space`.
- **Prune never deletes at once:** it uses rustic's delayed deletion.
- **A full or unwritable cache** is a warning (`cache_full` in the result), not a failure. Success is decided by `readback`, which reads without the cache.

**The library:** `rustic_core` from `sagemathinc/rustic_core` at the qualified rev `51115c47` (Apache-2.0 OR MIT), with our own S3 backend over OpenDAL's S3 service only.
- `THIRD-PARTY.txt` lists every linked crate (`node scripts/backup-third-party.mjs` regenerates it).
- `deny.toml` holds the license allowlist and the one named exception.

**The release build is static:** `cargo build --locked --release --target x86_64-unknown-linux-musl` (it needs `musl-tools`, for the C parts of zstd and aws-lc). The launcher runs a restore in a filesystem view with no loader or libraries, and refuses a binary that names one. `scripts/backup-static-check.sh BINARY` checks a build the same way: no `PT_INTERP`, no `DT_NEEDED`.

**Tests:**
- `cargo test --locked` runs the unit tests.
- With `--features test-loopback-http` and `SB_TEST_WEED` set to a SeaweedFS 4.53 binary (`scripts/fetch-test-s3.sh`), it also runs the integration tests against a local S3 server: the qualification rows plus the review gates. Restore rows need `CAP_SYS_RESOURCE` absent; where the bounding set still has it, they run through `sudo -n setpriv`.
