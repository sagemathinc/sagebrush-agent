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
        ];
        for (f, c, r) in all {
            assert_eq!(f.code(), c);
            assert_eq!(f.reason(), r);
        }
        assert_eq!(err(Fail::Record, "rollback failed").line(), "sagebrush-agent-launch: record: rollback failed");
    }
}
