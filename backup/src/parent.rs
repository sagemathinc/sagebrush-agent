//! The binary's parent binding (host backup init/run d3 §5.3): a root process whose parent dies must not run on. The
//! binary accepts exactly two bound states, checked first, before it reads its request:
//! - `--parent-pid <n>` (Node's spawns): `getppid()` equals `n`, then `PR_SET_PDEATHSIG(SIGKILL)` succeeds, then
//!   `getppid()` equals `n` again. A parent that died before the first check (every later `getppid()` sees the reaper)
//!   or between the checks is caught, and a death after the second is delivered as SIGKILL.
//! - no flag: only when the death signal is ALREADY exactly SIGKILL. That is the launcher's restore stage: its child arms
//!   `PR_SET_PDEATHSIG(SIGKILL)` and re-checks its parent before `execve`, which keeps the setting.
//!
//! Anything else exits before any work (`usage` without a bound state, `parent_gone` on a mismatch). The death signal
//! follows the parent THREAD that forked; for Node that is libuv's main-loop thread, which lives as long as the process.

use crate::error::{Fail, Result};

/// Binds this process to its parent, or refuses. `expected`: the `--parent-pid` value, if given.
pub fn bind(expected: Option<i32>) -> Result<()> {
    // Tests only: a pause before the first check, so a test can kill the parent before it (never in a release build:
    // backup-build.sh enables no feature).
    #[cfg(feature = "test-pause-before-start")]
    if let Some(ms) = std::env::var("SB_TEST_PAUSE_MS").ok().and_then(|v| v.parse::<u64>().ok()) {
        std::thread::sleep(std::time::Duration::from_millis(ms));
    }
    match expected {
        Some(pid) => {
            // SAFETY: getppid has no preconditions.
            if unsafe { libc::getppid() } != pid {
                return Err(Fail::new("parent_gone", "the parent named by --parent-pid isn't this process's parent"));
            }
            // SAFETY: PR_SET_PDEATHSIG takes one signal number; the rest are unused.
            if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL as libc::c_ulong, 0 as libc::c_ulong, 0 as libc::c_ulong, 0 as libc::c_ulong) } != 0 {
                return Err(Fail::new("parent_gone", "the death signal couldn't be set"));
            }
            // SAFETY: as above.
            if unsafe { libc::getppid() } != pid {
                return Err(Fail::new("parent_gone", "the parent died before the death signal was set"));
            }
            Ok(())
        }
        None => {
            let mut sig: libc::c_int = 0;
            // SAFETY: PR_GET_PDEATHSIG writes one int through the pointer given, which points at `sig`.
            let r = unsafe { libc::prctl(libc::PR_GET_PDEATHSIG, &mut sig as *mut libc::c_int as libc::c_ulong, 0 as libc::c_ulong, 0 as libc::c_ulong, 0 as libc::c_ulong) };
            if r != 0 || sig != libc::SIGKILL {
                return Err(Fail::new("usage", "--parent-pid is required unless the parent already set a SIGKILL death signal"));
            }
            Ok(())
        }
    }
}
