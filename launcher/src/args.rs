//! Argument, id and path validation (contract §2). Everything here is safe code.

use crate::err::{err, Fail, Result};
use std::ffi::OsString;

pub const MAX_ARGS_BEFORE: usize = 32;
pub const MAX_ARG_LEN: usize = 4096;
pub const MAX_CLI_ARGS: usize = 256;
pub const MAX_CLI_BYTES: usize = 64 * 1024;
pub const MAX_PATH: usize = 1024;
pub const MAX_ENV_ENTRIES: usize = 64;
pub const MAX_ENV_BYTES: usize = 64 * 1024;

/// The 26-character lowercase base32 fleet id (a-z, 2-7), whose last character carries no partial bits.
pub fn is_id(s: &str) -> bool {
    s.len() == 26
        && s.bytes().all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
        && matches!(s.as_bytes()[25], b'a' | b'e' | b'i' | b'm' | b'q' | b'u' | b'y' | b'4')
}

/// An absolute, normalized path: starts with '/', no empty, "." or ".." segment, no trailing '/', not "/" itself,
/// at most MAX_PATH bytes, valid UTF-8 without NUL.
pub fn is_path(s: &str) -> bool {
    if s.len() < 2 || s.len() > MAX_PATH || !s.starts_with('/') || s.contains('\0') {
        return false;
    }
    s[1..].split('/').all(|seg| !seg.is_empty() && seg != "." && seg != "..")
}

/// The path relative to the trusted root (the leading '/' checked and stripped).
pub fn rel(s: &str) -> Option<&str> {
    if is_path(s) { Some(&s[1..]) } else { None }
}

/// Every argument as UTF-8 without NUL, within the bounds; split at the first "--".
pub fn split(raw: Vec<OsString>) -> Result<(Vec<String>, Vec<String>)> {
    let bad = || err(Fail::Usage, "bad arguments");
    let mut all = Vec::with_capacity(raw.len());
    for a in raw {
        let s = a.into_string().map_err(|_| bad())?;
        if s.contains('\0') {
            return Err(bad());
        }
        all.push(s);
    }
    let (before, after) = match all.iter().position(|a| a == "--") {
        Some(i) => {
            let after = all.split_off(i + 1);
            all.pop();
            (all, after)
        }
        None => (all, Vec::new()),
    };
    if before.len() > MAX_ARGS_BEFORE || before.iter().any(|a| a.len() > MAX_ARG_LEN) {
        return Err(bad());
    }
    if after.len() > MAX_CLI_ARGS || after.iter().map(|a| a.len() + 1).sum::<usize>() > MAX_CLI_BYTES {
        return Err(bad());
    }
    Ok((before, after))
}

/// `--name value` pairs: exactly the given names, each once, in any order. Returns the values in `names` order.
pub fn flags<'a>(args: &'a [String], names: &[&str]) -> Result<Vec<&'a str>> {
    let bad = || err(Fail::Usage, "bad arguments");
    if args.len() != names.len() * 2 {
        return Err(bad());
    }
    let mut out: Vec<Option<&str>> = vec![None; names.len()];
    for pair in args.chunks(2) {
        let name = pair[0].strip_prefix("--").ok_or_else(bad)?;
        let i = names.iter().position(|n| *n == name).ok_or_else(bad)?;
        if out[i].is_some() {
            return Err(bad());
        }
        out[i] = Some(pair[1].as_str());
    }
    out.into_iter().map(|v| v.ok_or_else(bad)).collect()
}

/// The inherited environment's bounds (contract §2): at most 64 entries and 64 KiB.
pub fn env_within_bounds() -> bool {
    let mut n = 0usize;
    let mut bytes = 0usize;
    for (k, v) in std::env::vars_os() {
        n += 1;
        bytes += k.len() + v.len() + 2;
        if n > MAX_ENV_ENTRIES || bytes > MAX_ENV_BYTES {
            return false;
        }
    }
    true
}

/// A canonical decimal descriptor number: no sign, no leading zero except "0", at most 10 digits, within i32.
pub fn canonical_fd(name: &[u8]) -> Option<i32> {
    if name.is_empty() || name.len() > 10 || !name.iter().all(u8::is_ascii_digit) || (name.len() > 1 && name[0] == b'0') {
        return None;
    }
    core::str::from_utf8(name).ok()?.parse::<i32>().ok()
}

/// The names in a getdents64 buffer (`len` bytes), parsed with safe slice code: (d_reclen at 16..18, name from 19 to
/// its NUL). None if a record is malformed.
pub fn dirent_names(buf: &[u8], len: usize) -> Option<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off < len {
        let reclen = u16::from_ne_bytes(buf.get(off + 16..off + 18)?.try_into().ok()?) as usize;
        if reclen < 20 || off + reclen > len {
            return None;
        }
        let name = buf.get(off + 19..off + reclen)?;
        let end = name.iter().position(|&b| b == 0)?;
        out.push(name[..end].to_vec());
        off += reclen;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(v: &[&str]) -> Vec<OsString> {
        v.iter().map(OsString::from).collect()
    }

    #[test]
    fn ids_and_paths() {
        assert!(is_id("abcdefghijklmnopqrstuvwxya"));
        for bad in ["", "ABCDEFGHIJKLMNOPQRSTUVWXYA", "abcdefghijklmnopqrstuvwxyb", "abcdefghijklmnopqrstuvwxy", "abcdefghijklmnopqrstuvwx1a"] {
            assert!(!is_id(bad), "{bad}");
        }
        for good in ["/data", "/data/x y", "/a/b/c"] {
            assert!(is_path(good), "{good}");
        }
        for bad in ["", "/", "data", "/data/", "//data", "/data//x", "/data/./x", "/data/../x", "/x\0y"] {
            assert!(!is_path(bad), "{bad:?}");
        }
        assert!(!is_path(&format!("/{}", "a".repeat(MAX_PATH))));
        assert_eq!(rel("/run/sagebrush"), Some("run/sagebrush"));
    }

    #[test]
    fn argv_bounds_and_flags() {
        let (b, a) = split(os(&["--agent", "x", "--", "-p", "--"])).unwrap();
        assert_eq!((b.len(), a), (2, vec!["-p".to_string(), "--".to_string()]));
        assert!(split(os(&["x"; MAX_ARGS_BEFORE + 1])).is_err());
        assert!(split(vec![OsString::from("a".repeat(MAX_ARG_LEN + 1))]).is_err());
        let mut many = os(&["--"]);
        many.extend(os(&["y"; MAX_CLI_ARGS + 1]));
        assert!(split(many).is_err());
        let args: Vec<String> = ["--b", "2", "--a", "1"].iter().map(|s| s.to_string()).collect();
        assert_eq!(flags(&args, &["a", "b"]).unwrap(), vec!["1", "2"]);
        let dup: Vec<String> = ["--a", "1", "--a", "2"].iter().map(|s| s.to_string()).collect();
        assert!(flags(&dup, &["a", "b"]).is_err());
        let unknown: Vec<String> = ["--a", "1", "--c", "2"].iter().map(|s| s.to_string()).collect();
        assert!(flags(&unknown, &["a", "b"]).is_err());
        assert!(flags(&args[..3], &["a", "b"]).is_err());
    }

    #[test]
    fn canonical_descriptor_names() {
        assert_eq!(canonical_fd(b"0"), Some(0));
        assert_eq!(canonical_fd(b"2147483647"), Some(i32::MAX));
        for bad in [&b""[..], b"01", b"+1", b"-1", b"2147483648", b"12345678901", b"1a", b".", b".."] {
            assert_eq!(canonical_fd(bad), None, "{:?}", bad);
        }
    }

    #[test]
    fn dirent_parsing() {
        // Two records: "." (reclen 24) and "ab" (reclen 24).
        let mut buf = vec![0u8; 48];
        for (i, name) in [(0usize, &b"."[..]), (24, b"ab")] {
            buf[i + 16..i + 18].copy_from_slice(&24u16.to_ne_bytes());
            buf[i + 19..i + 19 + name.len()].copy_from_slice(name);
        }
        assert_eq!(dirent_names(&buf, 48).unwrap(), vec![b".".to_vec(), b"ab".to_vec()]);
        assert!(dirent_names(&buf, 40).is_none(), "a record past the end");
        let mut bad = buf.clone();
        bad[16..18].copy_from_slice(&4u16.to_ne_bytes());
        assert!(dirent_names(&bad, 48).is_none(), "an impossible reclen");
    }
}
