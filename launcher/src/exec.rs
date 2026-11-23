//! `exec` (contract §4): the agent unit's ExecStart. Check the staged identities, restrict itself with Landlock (ABI
//! 4, rules from the contract only), set no_new_privs, load the two credentials into a fresh environment, close every
//! descriptor above 2, and exec the pinned CLI. Every failure exits before exec; nothing runs unconfined.

use crate::args::{canonical_fd, dirent_names, is_id, is_path, rel};
use crate::contract::{self, Contract};
use crate::err::{err, Error, Fail, Result};
use crate::landlock::{self, PathBeneathAttr, RulesetAttr};
use crate::secret::Secret;
use crate::sys;
use std::ffi::CString;
use std::os::fd::{AsRawFd, OwnedFd};

/// The credential files systemd's LoadCredential= provides, and the environment names the CLI receives them under.
pub const CREDENTIALS: [(&str, &str); 2] =
    [("broker-placeholder", "SAGEBRUSH_BROKER_PLACEHOLDER"), ("workspace-capability", "SAGEBRUSH_WORKSPACE_CAPABILITY")];
/// A credential is at most 16 KiB; the buffer is one byte larger so a full one is detected as too large.
pub const CREDENTIAL_MAX: usize = 16 * 1024;

pub struct Args<'a> {
    pub agent: &'a str,
    pub contract: &'a str,
    pub cli: &'a str,
}

pub fn parse<'a>(v: &[&'a str]) -> Result<Args<'a>> {
    let [agent, contract, cli] = v else { return Err(err(Fail::Usage, "bad arguments")) };
    if !is_id(agent) || !is_path(contract) || !is_path(cli) {
        return Err(err(Fail::Usage, "bad arguments"));
    }
    Ok(Args { agent, contract, cli })
}

fn cstr(s: &str, fail: Fail) -> Result<CString> {
    CString::new(s).map_err(|_| err(fail, "bad string"))
}

/// Read a whole file through the trusted root into a bounded buffer (non-secret: the contract).
fn read_bounded(root: &OwnedFd, rel_path: &str, max: usize, fail: Fail, msg: &'static str) -> Result<Vec<u8>> {
    let f = sys::openat2(root, &cstr(rel_path, fail)?, libc::O_RDONLY, 0).map_err(|_| err(fail, msg))?;
    let mut buf = vec![0u8; max + 1];
    let mut len = 0;
    loop {
        let n = match sys::read(&f, &mut buf[len..]) {
            Ok(n) => n,
            Err(e) if e.raw_os_error() == Some(libc::EINTR) => continue,
            Err(_) => return Err(err(fail, msg)),
        };
        if n == 0 {
            break;
        }
        len += n;
        if len > max {
            return Err(err(fail, msg));
        }
    }
    buf.truncate(len);
    Ok(buf)
}

/// Read one credential into a Secret zero-initialized to CREDENTIAL_MAX + 1 bytes (contract §7).
fn read_credential(root: &OwnedFd, rel_path: &str) -> Result<Secret> {
    let bad = || err(Fail::Credentials, "a credential can't be read");
    let f = sys::openat2(root, &cstr(rel_path, Fail::Credentials)?, libc::O_RDONLY, 0).map_err(|_| bad())?;
    let mut s = Secret::zeroed(CREDENTIAL_MAX + 1);
    loop {
        if s.spare().is_empty() {
            return Err(err(Fail::Credentials, "a credential is too large")); // the Secret is zeroed as it drops
        }
        let n = match sys::read(&f, s.spare()) {
            Ok(n) => n,
            Err(e) if e.raw_os_error() == Some(libc::EINTR) => continue,
            Err(_) => return Err(bad()),
        };
        if n == 0 {
            break;
        }
        s.advance(n);
    }
    if s.is_empty() || s.as_bytes().contains(&0) {
        return Err(err(Fail::Credentials, "a credential is empty or holds a NUL"));
    }
    Ok(s)
}

/// "NAME=value\0" built in a Secret reserved at exactly its final length.
fn env_entry(name: &str, value: &Secret) -> Result<Secret> {
    let mut e = Secret::zeroed(name.len() + 1 + value.len() + 1);
    let ok = e.push(name.as_bytes()) && e.push(b"=") && e.push(value.as_bytes()) && e.push(b"\0");
    if !ok {
        return Err(err(Fail::Internal, "an environment entry doesn't fit"));
    }
    Ok(e)
}

const S_IFMT: u16 = 0o170000;
const S_IFDIR: u16 = 0o040000;

pub fn run(a: &Args, cli_args: &[String]) -> Result<Error> {
    // The inherited CREDENTIALS_DIRECTORY, validated (contract §2).
    let cred_dir = match std::env::var("CREDENTIALS_DIRECTORY") {
        Ok(d) if is_path(&d) => d,
        _ => return Err(err(Fail::Credentials, "no valid credentials directory")),
    };
    let root = sys::open_root().map_err(|_| err(Fail::Preflight, "the root can't be opened"))?;

    // 1. The contract: closed and bounded.
    let bytes = read_bounded(&root, rel(a.contract).unwrap(), contract::MAX_BYTES, Fail::Contract, "the contract can't be read")?;
    let c: Contract = contract::read(&bytes, a.agent).ok_or(err(Fail::Contract, "the contract is not the closed shape"))?;

    // 2. Every staged row's identity, from its in-view path.
    for s in &c.staged {
        let h = sys::openat2(&root, &cstr(rel(&s.path).unwrap(), Fail::Preflight)?, libc::O_PATH, 0)
            .map_err(|_| err(Fail::Preflight, "a staged path can't be opened"))?;
        let st = sys::statx(&h).map_err(|_| err(Fail::Preflight, "a staged path can't be read"))?;
        if st.dev != s.dev || st.ino != s.ino {
            return Err(err(Fail::Preflight, "a staged identity differs"));
        }
    }

    // 3. Landlock ABI 4 or refuse.
    match sys::landlock_abi() {
        Ok(v) if v >= landlock::MIN_ABI => {}
        _ => return Err(err(Fail::LandlockAbi, "landlock ABI 4 is not available")),
    }

    // 4. The ruleset: the contract's rules only, each added from its own O_PATH handle; network not handled.
    let attr = RulesetAttr { handled_access_fs: landlock::FS_HANDLED, handled_access_net: landlock::NET_HANDLED };
    let ruleset = sys::landlock_create_ruleset(&attr).map_err(|_| err(Fail::Landlock, "the ruleset can't be created"))?;
    for r in &c.rules {
        let h = sys::openat2(&root, &cstr(rel(&r.path).unwrap(), Fail::Preflight)?, libc::O_PATH, 0)
            .map_err(|_| err(Fail::Preflight, "a contract path can't be opened"))?;
        let st = sys::statx(&h).map_err(|_| err(Fail::Preflight, "a contract path can't be read"))?;
        let access = landlock::rights(&r.access, st.mode & S_IFMT == S_IFDIR).ok_or(err(Fail::Contract, "a bad access"))?;
        let rule = PathBeneathAttr { allowed_access: access, parent_fd: h.as_raw_fd() };
        sys::landlock_add_path_rule(&ruleset, rule).map_err(|_| err(Fail::Landlock, "a rule can't be added"))?;
    }

    // 5-6. no_new_privs, always; then restrict.
    sys::no_new_privs().map_err(|_| err(Fail::Landlock, "no_new_privs can't be set"))?;
    sys::landlock_restrict_self(&ruleset).map_err(|_| err(Fail::Landlock, "the ruleset can't be applied"))?;
    drop(ruleset);

    // 7. The credentials, into Secrets; a fresh environment without CREDENTIALS_DIRECTORY.
    let mut secret_entries: Vec<Secret> = Vec::with_capacity(CREDENTIALS.len());
    for (file, name) in CREDENTIALS {
        let value = read_credential(&root, &format!("{}/{file}", rel(&cred_dir).unwrap()))?;
        secret_entries.push(env_entry(name, &value)?);
        drop(value); // zeroed now
    }
    let mut plain_env: Vec<CString> = Vec::with_capacity(c.env.len());
    for (k, v) in &c.env {
        plain_env.push(cstr(&format!("{k}={v}"), Fail::Contract)?);
    }
    let cli = cstr(a.cli, Fail::Usage)?;
    let mut argv_store: Vec<CString> = vec![cli.clone()];
    for s in cli_args {
        argv_store.push(cstr(s, Fail::Usage)?);
    }

    // 8. Close every descriptor above 2: drop every OwnedFd first, then close_range (or the checked fallback).
    close_all_above_2(root)?;
    let mut argv: Vec<*const libc::c_char> = argv_store.iter().map(|s| s.as_ptr()).collect();
    argv.push(core::ptr::null());
    let mut envp: Vec<*const libc::c_char> = plain_env.iter().map(|s| s.as_ptr()).collect();
    envp.extend(secret_entries.iter().map(|s| s.as_ptr() as *const libc::c_char));
    envp.push(core::ptr::null());
    let _e = sys::execve(&cli, &argv, &envp);
    // execve returned: it failed. Zero every secret copy before reporting (contract §7).
    drop(envp);
    drop(secret_entries);
    Ok(err(Fail::Exec, "the CLI can't be executed"))
}

/// close_range(3, ~0U, 0) with no OwnedFd left (the root is dropped first). On ENOSYS only: re-open the root, list
/// proc/<pid>/fd through it (getdents64 to EOF, bounded), DROP both handles, then close each listed number above 2;
/// EBADF (a gap: the listing's own, now closed handles) is tolerated, any other error is 72.
fn close_all_above_2(root: OwnedFd) -> Result<()> {
    let internal = |m| err(Fail::Internal, m);
    drop(root);
    match sys::close_range_from_3() {
        Ok(()) => return Ok(()),
        Err(e) if e.raw_os_error() == Some(libc::ENOSYS) => {}
        Err(_) => return Err(internal("descriptors can't be closed")),
    }
    let mut fds: Vec<i32> = Vec::new();
    {
        let root = sys::open_root().map_err(|_| internal("the root can't be opened"))?;
        let rel_dir = format!("proc/{}/fd", std::process::id()); // not proc/self: a symlink RESOLVE_NO_SYMLINKS refuses
        let d = sys::openat2(&root, &cstr(&rel_dir, Fail::Internal)?, libc::O_RDONLY | libc::O_DIRECTORY, 0)
            .map_err(|_| internal("the descriptors can't be listed"))?;
        let mut buf = [0u8; 4096];
        let mut calls = 0;
        loop {
            calls += 1;
            if calls > 4096 {
                return Err(internal("too many descriptors"));
            }
            let n = sys::getdents64(&d, &mut buf).map_err(|_| internal("the descriptors can't be listed"))?;
            if n == 0 {
                break;
            }
            for name in dirent_names(&buf, n).ok_or(internal("the descriptors can't be listed"))? {
                if name == b"." || name == b".." {
                    continue;
                }
                fds.push(canonical_fd(&name).ok_or(internal("an odd descriptor name"))?);
                if fds.len() > 65536 {
                    return Err(internal("too many descriptors"));
                }
            }
        }
        drop(d);
        drop(root); // both dropped BEFORE any raw close: no Drop can close a number the loop closes
    }
    for fd in fds.into_iter().filter(|&f| f > 2) {
        match sys::close_raw(fd) {
            Ok(()) => {}
            Err(e) if e.raw_os_error() == Some(libc::EBADF) => {}
            Err(_) => return Err(internal("a descriptor can't be closed")),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arguments_are_closed() {
        let a = "abcdefghijklmnopqrstuvwxya";
        assert!(parse(&[a, "/var/lib/sagebrush/contract/x.json", "/opt/sagebrush/cli/claude"]).is_ok());
        for bad in [["x", "/c", "/cli"], [a, "c", "/cli"], [a, "/c", "cli"], [a, "/c/", "/cli"]] {
            assert_eq!(parse(&bad).err().map(|e| e.fail), Some(Fail::Usage));
        }
    }

    #[test]
    fn env_entries_are_exact_and_nul_terminated() {
        let mut v = Secret::zeroed(CREDENTIAL_MAX + 1);
        assert!(v.push(b"tok"));
        let e = env_entry("SAGEBRUSH_BROKER_PLACEHOLDER", &v).unwrap();
        assert_eq!(e.as_bytes(), b"SAGEBRUSH_BROKER_PLACEHOLDER=tok\0");
    }
}
