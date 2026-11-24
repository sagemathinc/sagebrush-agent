//! Exit codes (contract §5). Every failure is one of these, with one fixed stderr line that never echoes a value.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fail {
    Usage,
    Contract,
    Preflight,
    LandlockAbi,
    Landlock,
    Credentials,
    Record,
    Exec,
    Internal,
    /// A1: an identity, mount, type, owner, mode, project id or generation differs, a stale epoch, or a foreign,
    /// too deep or too large tree. No unlink and no rename happened.
    Identity,
    /// A1: archive-home's destination exists. Nothing happened.
    Exists,
    /// A1: effects happened (an unlink or the rename), then something failed; the caller's retry table decides.
    Partial,
    /// A2: the class's project is at its own block or inode limit, or that can't be attributed (`quota_unknown`).
    /// Permanent: no automatic retry.
    Quota,
    /// A2: the filesystem itself is out of blocks or inodes. Transient for the agent.
    NoSpace,
    /// A3: no current execution lease (no record, a spent lg, past the effective end, or the lock busy). Nothing
    /// changed and nothing of the unit or turn executed.
    Lease,
}

impl Fail {
    pub fn code(self) -> i32 {
        match self {
            Fail::Usage => 64,
            Fail::Contract => 65,
            Fail::Preflight => 66,
            Fail::LandlockAbi => 67,
            Fail::Landlock => 68,
            Fail::Credentials => 69,
            Fail::Record => 70,
            Fail::Exec => 71,
            Fail::Internal => 72,
            Fail::Identity => 73,
            Fail::Exists => 74,
            Fail::Partial => 75,
            Fail::Quota => 76,
            Fail::NoSpace => 77,
            Fail::Lease => 78,
        }
    }

    pub fn reason(self) -> &'static str {
        match self {
            Fail::Usage => "usage",
            Fail::Contract => "contract",
            Fail::Preflight => "preflight_missing",
            Fail::LandlockAbi => "landlock_abi",
            Fail::Landlock => "landlock",
            Fail::Credentials => "credentials",
            Fail::Record => "record",
            Fail::Exec => "exec",
            Fail::Internal => "internal",
            Fail::Identity => "identity",
            Fail::Exists => "exists",
            Fail::Partial => "partial",
            Fail::Quota => "quota",
            Fail::NoSpace => "no_space",
            Fail::Lease => "lease",
        }
    }
}

/// A failure with a fixed message (a static string: it can't carry a path, a value or a secret).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error {
    pub fail: Fail,
    pub msg: &'static str,
}

pub type Result<T> = core::result::Result<T, Error>;

pub const fn err(fail: Fail, msg: &'static str) -> Error {
    Error { fail, msg }
}

impl Error {
    pub fn line(&self) -> String {
        format!("sagebrush-agent-launch: {}: {}", self.fail.reason(), self.msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_the_contract_table() {
        let all = [
            (Fail::Usage, 64, "usage"),
            (Fail::Contract, 65, "contract"),
            (Fail::Preflight, 66, "preflight_missing"),
            (Fail::LandlockAbi, 67, "landlock_abi"),
            (Fail::Landlock, 68, "landlock"),
            (Fail::Credentials, 69, "credentials"),
            (Fail::Record, 70, "record"),
            (Fail::Exec, 71, "exec"),
            (Fail::Internal, 72, "internal"),
            (Fail::Identity, 73, "identity"),
            (Fail::Exists, 74, "exists"),
            (Fail::Partial, 75, "partial"),
            (Fail::Quota, 76, "quota"),
            (Fail::NoSpace, 77, "no_space"),
            (Fail::Lease, 78, "lease"),
        ];
        for (f, c, r) in all {
            assert_eq!(f.code(), c);
            assert_eq!(f.reason(), r);
        }
        assert_eq!(err(Fail::Record, "rollback failed").line(), "sagebrush-agent-launch: record: rollback failed");
    }
}
