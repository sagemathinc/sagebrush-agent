//! The restore runs without `CAP_SYS_RESOURCE` (host backup design r3.3 §5.7): absent from all five capability sets before
//! the first write, under `no_new_privs`, so the kernel enforces each agent's project quota and nothing can bring
//! the capability back. The parent (the launcher's restore runner) drops it; this binary refuses to restore unless it is
//! already gone, and sets `no_new_privs` itself as well.

use std::fs;

use crate::error::{Fail, Result};

/// `CAP_SYS_RESOURCE` (linux/capability.h).
const CAP_SYS_RESOURCE: u32 = 24;

/// The five capability sets, as `/proc/self/status` names them.
pub const SETS: [&str; 5] = ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"];

/// Which of the five sets hold `CAP_SYS_RESOURCE`, from the text of `/proc/<pid>/status`. A set that is missing or
/// unparsable counts as holding it (fail closed).
pub fn sets_holding_sys_resource(status: &str) -> Vec<&'static str> {
    SETS.iter()
        .copied()
        .filter(|set| {
            let mask = status.lines().find_map(|l| l.strip_prefix(set)?.strip_prefix(':').map(str::trim));
            match mask.and_then(|m| u64::from_str_radix(m, 16).ok()) {
                Some(bits) => bits & (1u64 << CAP_SYS_RESOURCE) != 0,
                None => true,
            }
        })
        .collect()
}

/// Set `no_new_privs`, then require `CAP_SYS_RESOURCE` to be absent from all five sets of this process.
pub fn require_no_sys_resource() -> Result<()> {
    // SAFETY: prctl with these arguments has no memory effects.
    let r = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if r != 0 {
        return Err(Fail::new("capability_refused", "couldn't set no_new_privs"));
    }
    let status = fs::read_to_string("/proc/self/status").map_err(|e| Fail::new("capability_refused", format!("/proc/self/status: {e}")))?;
    if !status.lines().any(|l| l.split_whitespace().eq(["NoNewPrivs:", "1"])) {
        return Err(Fail::new("capability_refused", "no_new_privs isn't set"));
    }
    let held = sets_holding_sys_resource(&status);
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

    const BIT: u64 = 1 << 24;

    fn status(inh: u64, prm: u64, eff: u64, bnd: u64, amb: u64) -> String {
        format!("Name:\tx\nCapInh:\t{inh:016x}\nCapPrm:\t{prm:016x}\nCapEff:\t{eff:016x}\nCapBnd:\t{bnd:016x}\nCapAmb:\t{amb:016x}\nNoNewPrivs:\t1\n")
    }

    #[test]
    fn every_set_is_checked() {
        let all = 0x1ff_ffff_ffffu64;
        assert_eq!(sets_holding_sys_resource(&status(0, 0, 0, 0, 0)), Vec::<&str>::new());
        assert_eq!(sets_holding_sys_resource(&status(0, all & !BIT, all & !BIT, all & !BIT, 0)), Vec::<&str>::new());
        assert_eq!(sets_holding_sys_resource(&status(BIT, 0, 0, 0, 0)), vec!["CapInh"]);
        assert_eq!(sets_holding_sys_resource(&status(0, BIT, 0, 0, 0)), vec!["CapPrm"]);
        assert_eq!(sets_holding_sys_resource(&status(0, 0, BIT, 0, 0)), vec!["CapEff"]);
        assert_eq!(sets_holding_sys_resource(&status(0, 0, 0, BIT, 0)), vec!["CapBnd"]);
        assert_eq!(sets_holding_sys_resource(&status(0, 0, 0, 0, BIT)), vec!["CapAmb"]);
        assert_eq!(sets_holding_sys_resource(&status(all, all, all, all, all)).len(), 5);
    }

    #[test]
    fn missing_or_garbled_sets_fail_closed() {
        assert_eq!(sets_holding_sys_resource("Name:\tx\n").len(), 5);
        assert_eq!(sets_holding_sys_resource("CapInh:\tzz\nCapPrm:\t0\nCapEff:\t0\nCapBnd:\t0\nCapAmb:\t0\n"), vec!["CapInh"]);
    }
}
