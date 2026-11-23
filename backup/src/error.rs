//! One error shape for every operation: a stable `code` the host side branches on, and a message for people.
//! Messages never carry a credential or a password (nothing here formats one).

use std::{error::Error as StdError, fmt};

pub type Result<T> = std::result::Result<T, Fail>;

#[derive(Debug)]
pub struct Fail {
    pub code: &'static str,
    pub message: String,
}

impl Fail {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self { code, message: message.into() }
    }

    /// A library error, classified. A quota (`EDQUOT`) or a full filesystem (`ENOSPC`) anywhere in its source chain
    /// gets its own code, so the caller can tell a permanent quota refusal from a transient failure (host backup design r3.3 §5.7).
    pub fn from_lib(code: &'static str, err: &(dyn StdError + 'static)) -> Self {
        let mut cur: Option<&(dyn StdError + 'static)> = Some(err);
        while let Some(e) = cur {
            if let Some(io) = e.downcast_ref::<std::io::Error>() {
                match io.raw_os_error() {
                    Some(libc::EDQUOT) => return Self::new("quota_exceeded", err.to_string()),
                    Some(libc::ENOSPC) => return Self::new("no_space", err.to_string()),
                    _ => {}
                }
            }
            cur = e.source();
        }
        Self::new(code, err.to_string())
    }
}

impl fmt::Display for Fail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

/// `Fail::from_lib` for rustic_core's boxed errors.
pub fn lib(code: &'static str) -> impl Fn(Box<rustic_core::RusticError>) -> Fail {
    move |e| Fail::from_lib(code, &*e)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct Wrap(std::io::Error);
    impl fmt::Display for Wrap {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "wrapped")
        }
    }
    impl StdError for Wrap {
        fn source(&self) -> Option<&(dyn StdError + 'static)> {
            Some(&self.0)
        }
    }

    #[test]
    fn classifies_errno_in_the_chain() {
        let q = Wrap(std::io::Error::from_raw_os_error(libc::EDQUOT));
        assert_eq!(Fail::from_lib("restore_failed", &q).code, "quota_exceeded");
        let s = Wrap(std::io::Error::from_raw_os_error(libc::ENOSPC));
        assert_eq!(Fail::from_lib("restore_failed", &s).code, "no_space");
        let o = Wrap(std::io::Error::from_raw_os_error(libc::EIO));
        assert_eq!(Fail::from_lib("restore_failed", &o).code, "restore_failed");
    }
}
