//! The restore runs without `CAP_SYS_RESOURCE` (host backup design r3.3 §5.7): absent from all five capability sets before
//! the first write, under `no_new_privs`, so the kernel enforces each agent's project quota and nothing can bring
//! the capability back. The parent (the launcher's restore runner) drops it; this binary refuses to restore unless it is
//! already gone, and sets `no_new_privs` itself as well.
//!
//! Every check asks the kernel directly (`capget`, `prctl`), never `/proc`: the restore's filesystem view has no
//! procfs, and a check that can't run fails closed.

use crate::error::{Fail, Result};

/// `CAP_SYS_RESOURCE` (linux/capability.h).
const CAP_SYS_RESOURCE: u32 = 24;

/// `_LINUX_CAPABILITY_VERSION_3` (linux/capability.h): two 32-bit words per set.
const CAPABILITY_VERSION_3: u32 = 0x2008_0522;

/// The five capability sets, by the names `/proc/<pid>/status` gives them.
pub const SETS: [&str; 5] = ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"];

/// Whether each of the five sets (in `SETS` order) holds `CAP_SYS_RESOURCE`. `None` means the kernel couldn't say.
pub type Holding = [Option<bool>; 5];

/// Which of the five sets hold `CAP_SYS_RESOURCE`. A set the kernel couldn't answer for counts as holding it (fail
/// closed).
pub fn sets_holding_sys_resource(holding: &Holding) -> Vec<&'static str> {
    SETS.iter().zip(holding).filter(|(_, h)| h.unwrap_or(true)).map(|(set, _)| *set).collect()
}

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: libc::c_int,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

/// This process's `CAP_SYS_RESOURCE`, set by set, from `capget` (inheritable, permitted, effective), `PR_CAPBSET_READ`
/// (bounding) and `PR_CAP_AMBIENT_IS_SET` (ambient).
fn read_holding() -> Holding {
    let mut header = CapHeader { version: CAPABILITY_VERSION_3, pid: 0 };
    let mut data = [CapData::default(); 2];
    // SAFETY: capget writes two `CapData` words for version 3 into `data`, which has room for exactly two.
    let r = unsafe { libc::syscall(libc::SYS_capget, &mut header as *mut CapHeader, data.as_mut_ptr()) };
    let word = data[(CAP_SYS_RESOURCE / 32) as usize];
    let bit = 1u32 << (CAP_SYS_RESOURCE % 32);
    let from_capget = |mask: u32| (r == 0 && header.version == CAPABILITY_VERSION_3).then_some(mask & bit != 0);
    let from_prctl = |r: libc::c_int| match r {
        0 => Some(false),
        1 => Some(true),
        _ => None,
    };
    // SAFETY: these prctl reads have no memory effects.
    let bounding = unsafe { libc::prctl(libc::PR_CAPBSET_READ, CAP_SYS_RESOURCE as libc::c_ulong, 0, 0, 0) };
    // SAFETY: as above.
    let ambient = unsafe {
        libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_IS_SET as libc::c_ulong, CAP_SYS_RESOURCE as libc::c_ulong, 0, 0)
    };
    [
        from_capget(word.inheritable),
        from_capget(word.permitted),
        from_capget(word.effective),
        from_prctl(bounding),
        from_prctl(ambient),
    ]
}

/// Set `no_new_privs`, then require `CAP_SYS_RESOURCE` to be absent from all five sets of this process.
pub fn require_no_sys_resource() -> Result<()> {
    // SAFETY: prctl with these arguments has no memory effects.
    let r = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if r != 0 {
        return Err(Fail::new("capability_refused", "couldn't set no_new_privs"));
    }
    // SAFETY: as above.
    if unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) } != 1 {
        return Err(Fail::new("capability_refused", "no_new_privs isn't set"));
    }
    let held = sets_holding_sys_resource(&read_holding());
    if !held.is_empty() {
        return Err(Fail::new(
            "capability_refused",
            format!("CAP_SYS_RESOURCE is still in {}: a restore must run without it, so quotas hold", held.join(", ")),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_set_is_checked() {
        assert_eq!(sets_holding_sys_resource(&[Some(false); 5]), Vec::<&str>::new());
        for (i, set) in SETS.iter().enumerate() {
            let mut h = [Some(false); 5];
            h[i] = Some(true);
            assert_eq!(sets_holding_sys_resource(&h), vec![*set]);
        }
        assert_eq!(sets_holding_sys_resource(&[Some(true); 5]).len(), 5);
    }

    #[test]
    fn an_unanswered_set_fails_closed() {
        assert_eq!(sets_holding_sys_resource(&[None; 5]).len(), 5);
        assert_eq!(sets_holding_sys_resource(&[None, Some(false), Some(false), Some(false), Some(false)]), vec!["CapInh"]);
    }

    /// The syscall reading agrees with the kernel's own `/proc/self/status` for this test process, set by set.
    #[test]
    fn the_syscalls_agree_with_proc_status() {
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        let from_proc: Vec<bool> = SETS
            .iter()
            .map(|set| {
                let mask = status.lines().find_map(|l| l.strip_prefix(set)?.strip_prefix(':').map(str::trim)).unwrap();
                u64::from_str_radix(mask, 16).unwrap() & (1 << CAP_SYS_RESOURCE) != 0
            })
            .collect();
        let from_syscalls: Vec<bool> = read_holding().iter().map(|h| h.expect("the kernel answered")).collect();
        assert_eq!(from_syscalls, from_proc);
    }
}
