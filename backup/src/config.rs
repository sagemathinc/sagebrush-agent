//! The destination and the repository password, read only from root-owned files in the backup state directory
//! (design §2): `dest.json` holds a handle, never a credential, and the credential and the password are each in their
//! own file. Nothing secret ever comes from argv or the environment.

use std::{
    fs,
    io::Read,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};

use serde::Deserialize;

use crate::error::{Fail, Result};

/// The largest file read here (a destination, a credential or a password).
const MAX_FILE: u64 = 64 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DestFile {
    #[serde(rename = "type")]
    kind: String,
    endpoint: String,
    bucket: String,
    prefix: String,
    region: String,
    credential: CredentialRef,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialRef {
    secret: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretFile {
    access_key_id: String,
    secret_access_key: String,
}

/// A destination, checked. The secret fields are never printed (no `Debug`).
pub struct Destination {
    pub endpoint: String,
    pub bucket: String,
    pub prefix: String,
    pub region: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    /// true only for an `http` loopback endpoint under the test-only feature
    pub plain_http: bool,
}

/// The backup state directory (`dest.json`, `host.key`) and the host secret store beside it.
pub struct State {
    pub dir: PathBuf,
    pub secrets: PathBuf,
}

impl State {
    pub fn new(dir: &Path, secrets: &Path) -> Self {
        Self { dir: dir.to_path_buf(), secrets: secrets.to_path_buf() }
    }

    pub fn destination(&self) -> Result<Destination> {
        let raw = read_private(&self.dir.join("dest.json"), "destination")?;
        let d: DestFile = serde_json::from_slice(&raw).map_err(|e| Fail::new("config_invalid", format!("dest.json: {e}")))?;
        if d.kind != "s3" {
            return Err(Fail::new("destination_refused", "only the `s3` destination type is supported"));
        }
        let plain_http = check_endpoint(&d.endpoint)?;
        check_name("bucket", &d.bucket, 3, 63)?;
        check_prefix(&d.prefix)?;
        check_name("region", &d.region, 1, 64)?;
        let r = &d.credential.secret;
        if r.is_empty() || r.len() > 64 || !r.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') {
            return Err(Fail::new("config_invalid", "the credential handle must be 1-64 of [a-z0-9-]"));
        }
        let raw = read_private(&self.secrets.join(r), "credential")?;
        let s: SecretFile = serde_json::from_slice(&raw).map_err(|_| Fail::new("config_invalid", "the credential file is not the expected JSON shape"))?;
        if s.access_key_id.is_empty() || s.secret_access_key.is_empty() {
            return Err(Fail::new("config_invalid", "the credential file has an empty field"));
        }
        Ok(Destination {
            endpoint: d.endpoint,
            bucket: d.bucket,
            prefix: d.prefix,
            region: d.region,
            access_key_id: s.access_key_id,
            secret_access_key: s.secret_access_key,
            plain_http,
        })
    }

    /// The host key slot's password (design §2: `host.key`, root 0600).
    pub fn host_password(&self) -> Result<String> {
        password_file(&self.dir.join("host.key"))
    }
}

/// A password from a private file: its first line, which must be non-empty.
pub fn password_file(path: &Path) -> Result<String> {
    let raw = read_private(path, "password")?;
    let text = String::from_utf8(raw).map_err(|_| Fail::new("config_invalid", "a password file is not UTF-8"))?;
    let line = text.lines().next().unwrap_or("").to_string();
    if line.is_empty() {
        return Err(Fail::new("config_invalid", "a password file is empty"));
    }
    Ok(line)
}

/// Read a small file that must be a regular file owned by this process's user, with no group or other access.
fn read_private(path: &Path, what: &str) -> Result<Vec<u8>> {
    let meta = fs::symlink_metadata(path).map_err(|e| Fail::new("config_missing", format!("{what} file {}: {e}", path.display())))?;
    if !meta.file_type().is_file() {
        return Err(Fail::new("config_invalid", format!("{what} file {} is not a regular file", path.display())));
    }
    if meta.permissions().mode() & 0o077 != 0 {
        return Err(Fail::new("config_invalid", format!("{what} file {} is readable by others (it must be 0600)", path.display())));
    }
    // SAFETY: geteuid has no preconditions.
    let euid = unsafe { libc::geteuid() };
    if meta.uid() != euid {
        return Err(Fail::new("config_invalid", format!("{what} file {} has another owner", path.display())));
    }
    if meta.len() > MAX_FILE {
        return Err(Fail::new("config_invalid", format!("{what} file {} is too large", path.display())));
    }
    let mut buf = Vec::new();
    fs::File::open(path)
        .and_then(|f| f.take(MAX_FILE + 1).read_to_end(&mut buf))
        .map_err(|e| Fail::new("config_missing", format!("{what} file {}: {e}", path.display())))?;
    Ok(buf)
}

/// `https://host[:port]` with no path, query, fragment or userinfo; `http://` only for a loopback host under the
/// test-only feature. Returns whether it is plain http.
pub fn check_endpoint(endpoint: &str) -> Result<bool> {
    let refused = |why: &str| Fail::new("destination_refused", format!("endpoint: {why}"));
    let (plain, rest) = if let Some(r) = endpoint.strip_prefix("https://") {
        (false, r)
    } else if let Some(r) = endpoint.strip_prefix("http://") {
        (true, r)
    } else {
        return Err(refused("must start with https://"));
    };
    if rest.is_empty() || rest.contains(['/', '?', '#', '@', ' ']) || rest.chars().any(char::is_control) {
        return Err(refused("must be scheme://host[:port], with nothing else"));
    }
    // (an IPv6 literal is bracketed: a port follows its `]`)
    let (host, port) = match rest.rfind(':') {
        Some(i) if !rest[i..].contains(']') => (&rest[..i], Some(&rest[i + 1..])),
        _ => (rest, None),
    };
    if let Some(port) = port {
        if port.is_empty() || port.len() > 5 || !port.bytes().all(|b| b.is_ascii_digit()) || port.starts_with('0') {
            return Err(refused("bad port"));
        }
    }
    if host.is_empty() || host.len() > 253 {
        return Err(refused("bad host"));
    }
    if plain {
        let loopback = host == "127.0.0.1" || host == "[::1]" || host == "localhost";
        if !(cfg!(feature = "test-loopback-http") && loopback) {
            return Err(refused("must be https"));
        }
    }
    Ok(plain)
}

fn check_name(what: &str, v: &str, min: usize, max: usize) -> Result<()> {
    if v.len() < min || v.len() > max || !v.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.') {
        return Err(Fail::new("config_invalid", format!("{what} must be {min}-{max} of [a-z0-9.-]")));
    }
    Ok(())
}

/// A key prefix inside the bucket: path segments of [A-Za-z0-9._-], no empty, `.` or `..` segment.
fn check_prefix(v: &str) -> Result<()> {
    let bad = || Fail::new("config_invalid", "prefix must be segments of [A-Za-z0-9._-] separated by '/'");
    if v.is_empty() || v.len() > 512 {
        return Err(bad());
    }
    for seg in v.split('/') {
        if seg.is_empty() || seg == "." || seg == ".." || !seg.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-') {
            return Err(bad());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints() {
        assert!(!check_endpoint("https://s3.example.com").unwrap());
        assert!(!check_endpoint("https://s3.example.com:8443").unwrap());
        assert!(!check_endpoint("https://[2001:db8::1]:8443").unwrap());
        for bad in [
            "s3.example.com",
            "ftp://s3.example.com",
            "https://s3.example.com/",
            "https://s3.example.com/path",
            "https://user@s3.example.com",
            "https://s3.example.com?x=1",
            "https://s3.example.com#f",
            "https://s3.example.com:0443",
            "https://s3.example.com:",
            "https://s3.example.com:99999x",
            "https://",
            "http://s3.example.com",
            "http://10.0.0.1:9000",
        ] {
            assert!(check_endpoint(bad).is_err(), "{bad} must be refused");
        }
        if cfg!(feature = "test-loopback-http") {
            assert!(check_endpoint("http://127.0.0.1:9000").unwrap());
        } else {
            assert!(check_endpoint("http://127.0.0.1:9000").is_err());
        }
    }

    #[test]
    fn prefixes() {
        assert!(check_prefix("hosts/abc").is_ok());
        for bad in ["", "/abs", "a//b", "a/../b", "a/./b", "a b", "trailing/"] {
            assert!(check_prefix(bad).is_err(), "{bad:?} must be refused");
        }
    }
}
