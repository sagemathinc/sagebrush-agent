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
        match chain_errno(err) {
            Some(libc::EDQUOT) => Self::new("quota_exceeded", err.to_string()),
            Some(libc::ENOSPC) => Self::new("no_space", err.to_string()),
            _ => Self::new(code, err.to_string()),
        }
    }
}

/// The first `EDQUOT` or `ENOSPC` in an error's source chain.
///
/// Each link is checked two ways. An `io::Error` link gives its errno directly. Otherwise the link's `Debug` text is
/// searched for an `io::Error`'s own `Debug` form, `Os { code: N, kind: K, .. }`: rustic_core's restore wraps the
/// write's `io::Error` in its local-destination error kind as a plain field, not as a source, and that type isn't
/// public, so the chain ends one link above the errno and only that link's `Debug` text still carries it.
fn chain_errno(err: &(dyn StdError + 'static)) -> Option<i32> {
    let mut cur: Option<&(dyn StdError + 'static)> = Some(err);
    while let Some(e) = cur {
        let found = match e.downcast_ref::<std::io::Error>() {
            Some(io) => io.raw_os_error().into_iter().find(|c| is_space_errno(*c)),
            None => debug_errnos(&format!("{e:?}")).find(|c| is_space_errno(*c)),
        };
        if found.is_some() {
            return found;
        }
        cur = e.source();
    }
    None
}

fn is_space_errno(code: i32) -> bool {
    code == libc::EDQUOT || code == libc::ENOSPC
}

/// The errnos in `io::Error` `Debug` text: each `Os { code: N, kind: ` (the `kind` field confirms the shape), found
/// only outside string literals. Paths, messages and context values are all `Debug`-quoted (with `"` and `\`
/// escaped), so a file named like the pattern can't be mistaken for an errno.
fn debug_errnos(text: &str) -> std::vec::IntoIter<i32> {
    let bare = outside_strings(text);
    let mut found = Vec::new();
    for (i, m) in bare.match_indices("Os { code: ") {
        let rest = &bare[i + m.len()..];
        let Some(digits) = rest.find(|c: char| !c.is_ascii_digit()).filter(|&n| n > 0) else { continue };
        if rest[digits..].starts_with(", kind: ") {
            if let Ok(code) = rest[..digits].parse() {
                found.push(code);
            }
        }
    }
    found.into_iter()
}

/// `Debug` text with the contents of every string literal removed (the quotes stay). Inside a literal, `\` escapes
/// the next character. An unterminated literal removes the rest.
fn outside_strings(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let (mut in_string, mut escaped) = (false, false);
    for c in text.chars() {
        if in_string {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
                out.push(c);
            }
        } else {
            if c == '"' {
                in_string = true;
            }
            out.push(c);
        }
    }
    out
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

    /// The shape rustic_core's restore gives a failed write: its error kind holds the `io::Error` as a plain field (no
    /// `source()`), inside a `RusticError` whose source is that kind.
    #[derive(Debug)]
    enum OpaqueKind {
        CouldNotWriteToBuffer(#[allow(dead_code)] std::io::Error),
    }
    impl fmt::Display for OpaqueKind {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "could not write to buffer")
        }
    }
    impl StdError for OpaqueKind {}

    fn rustic_write_error(errno: i32) -> Box<rustic_core::RusticError> {
        rustic_core::RusticError::with_source(
            rustic_core::ErrorKind::InputOutput,
            "Failed to write restore contents for `{path}` at `{offset}`.",
            OpaqueKind::CouldNotWriteToBuffer(std::io::Error::from_raw_os_error(errno)),
        )
        .attach_context("path", "home/a.txt")
        .attach_context("offset", "0")
    }

    #[test]
    fn classifies_errno_held_as_a_plain_field() {
        assert_eq!(lib("restore_failed")(rustic_write_error(libc::EDQUOT)).code, "quota_exceeded");
        assert_eq!(lib("restore_failed")(rustic_write_error(libc::ENOSPC)).code, "no_space");
        assert_eq!(lib("restore_failed")(rustic_write_error(libc::EIO)).code, "restore_failed");
    }

    /// A restored file named like the pattern, in the error's context, can't turn another failure into a quota.
    #[test]
    fn a_path_shaped_like_an_errno_is_not_one() {
        let named = |errno: i32| {
            rustic_write_error(errno).attach_context("path", "home/Os { code: 122, kind: QuotaExceeded, message: \"x\" }")
        };
        assert_eq!(lib("restore_failed")(named(libc::EIO)).code, "restore_failed");
        assert_eq!(lib("restore_failed")(named(libc::ENOSPC)).code, "no_space");
        // paths that try to close the quoting first: an embedded quote, a trailing backslash, both; each full-shape
        let tricky = [
            "a\" Os { code: 28, kind: StorageFull }",
            "a\\\" Os { code: 122, kind: QuotaExceeded }",
            "a\\",
            "\\\"Os { code: 28, kind: StorageFull }\\",
        ];
        for path in tricky {
            for (errno, want) in [(libc::EIO, "restore_failed"), (libc::EDQUOT, "quota_exceeded"), (libc::ENOSPC, "no_space")] {
                let e = rustic_write_error(errno).attach_context("path", path).attach_context("next", "Os { code: 28, kind: StorageFull }");
                assert_eq!(lib("restore_failed")(e).code, want, "path {path:?}, errno {errno}");
            }
        }
    }

    #[test]
    fn debug_text_needs_the_whole_io_error_shape() {
        assert_eq!(debug_errnos("X(Os { code: 122, kind: QuotaExceeded, message: \"q\" })").collect::<Vec<_>>(), vec![122]);
        assert_eq!(debug_errnos("Os { code: 28, kind: StorageFull } Os { code: 5, kind: Other }").collect::<Vec<_>>(), vec![28, 5]);
        // a path or message that merely mentions the words, a missing kind, or no digits: nothing
        assert_eq!(debug_errnos("path \"Os { code: 122 }\"").count(), 0);
        // the whole pattern inside a string literal, also after an escaped quote: nothing
        assert_eq!(debug_errnos("CouldNotWriteToBuffer(\"Os { code: 28, kind: StorageFull\")").count(), 0);
        assert_eq!(debug_errnos("\"a\\\" Os { code: 122, kind: QuotaExceeded \\\\\" Os { code: 5, kind: Other }").collect::<Vec<_>>(), vec![5]);
        assert_eq!(debug_errnos("Os { code: , kind: X }").count(), 0);
        assert_eq!(debug_errnos("code: 122, kind: QuotaExceeded").count(), 0);
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
