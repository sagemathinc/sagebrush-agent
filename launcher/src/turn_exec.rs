//! `turn`'s process (launcher contract amendment A5 r4.7): the status and go handshake (§1), the failure record, step
//! 1, steps 2–7 (`turn::stage`), and steps 8–12 WITHOUT §3's syscall filter, which part 3b-ii adds. Until then the
//! `turn` entry point refuses (64) before anything else: `TURN_ENABLED` is false.
//!
//! - §1: the first actions are `FD_CLOEXEC` on fds 3 and 4 (an invalid one is 65 with no record: nothing can be
//!   proved), closing every descriptor from 5 up, the `start` record on fd 3, and ONE go byte read from fd 4, which is
//!   then closed. Nothing else happens before the go byte.
//! - From then on every failure writes ONE failure record `{"k":"fail","code":<exit>,"step":<n>}` (at most 64 bytes, one
//!   write) and exits with that code. A failed or short record write exits at once, with no further write.
//! - Step 8: the agent unit's contract through the turn's root, plus the one `rwx` row for the staged profile; a
//!   contract that names that path itself is 65. Step 9: no credentials. Step 10 (r4.7): the bounding set and ambient
//!   dropped while root, then the groups and the ids (read back), then the remaining three sets cleared and the whole
//!   mask verified empty, then no_new_privs and Landlock. Step 11: the contract's environment plus exactly
//!   `CLAUDE_CONFIG_DIR`. Step 12: fds 1 and 2 must be AF_UNIX stream sockets, every descriptor from 4 up closed, exec.

use crate::contract::{self, Contract, Rule};
use crate::{landlock, sys, tree};
use std::ffi::CString;
use std::os::fd::{AsRawFd, OwnedFd};
use crate::err::{err, Error, Fail, Result};
use crate::turn::{read_turn_file, stage, TurnFile, TurnOps, STAGED};
use std::io;

/// The `turn` entry point stays off until part 3b-ii adds §3's syscall filter (A5 r4.7 §7).
pub const TURN_ENABLED: bool = false;
/// The status pipe's write end and the go pipe's read end (A5 §1).
pub const STATUS: i32 = 3;
pub const GO: i32 = 4;
/// The agent unit's contract, at its fixed path for the agent (A1's anchor; the same file `exec` reads).
pub const CONTRACTS: &str = "var/lib/sagebrush/contract";
/// The highest capability number probed; the kernel's last one ends the probe (EINVAL), as A2 O3 does.
const CAP_PROBE_MAX: u32 = 63;

/// The process-level operations steps 1 and 8–12 add (the real ones are syscall wrappers in `sys`).
pub trait ProcOps {
    fn cloexec(&mut self, fd: i32) -> io::Result<()>;
    /// A pipe opened write-only.
    fn status_fd_ok(&mut self, fd: i32) -> io::Result<bool>;
    fn close_from(&mut self, fd: u32) -> io::Result<()>;
    fn write(&mut self, fd: i32, b: &[u8]) -> io::Result<usize>;
    fn read(&mut self, fd: i32, b: &mut [u8]) -> io::Result<usize>;
    fn close(&mut self, fd: i32) -> io::Result<()>;
    /// An AF_UNIX SOCK_STREAM socket.
    fn unix_stream(&mut self, fd: i32) -> io::Result<bool>;
    fn is_root(&mut self) -> bool;
    /// A file through the turn's root (after step 3, `/` is the turn's), at most `max` bytes.
    fn read_root(&mut self, rel: &str, max: usize) -> io::Result<Vec<u8>>;
    /// The (dev, ino) of a path through the turn's root (O_PATH, not followed).
    fn path_ident(&mut self, rel: &str) -> io::Result<((u32, u32), u64)>;
    fn bound_has(&mut self, cap: u32) -> io::Result<bool>;
    fn bound_drop(&mut self, cap: u32) -> io::Result<()>;
    fn ambient_clear(&mut self) -> io::Result<()>;
    fn ambient_has(&mut self, cap: u32) -> io::Result<bool>;
    fn setgroups(&mut self, gids: &[u32]) -> io::Result<()>;
    fn setresgid(&mut self, g: u32) -> io::Result<()>;
    fn setresuid(&mut self, u: u32) -> io::Result<()>;
    /// (getresuid, getresgid, getgroups).
    fn ids(&mut self) -> io::Result<((u32, u32, u32), (u32, u32, u32), Vec<u32>)>;
    fn capget(&mut self) -> io::Result<(u64, u64, u64)>;
    fn capset(&mut self, e: u64, p: u64, i: u64) -> io::Result<()>;
    fn no_new_privs(&mut self) -> io::Result<()>;
    /// Landlock ABI 4 or refuse (67), then a ruleset of exactly these rules restricting this process (68).
    fn landlock(&mut self, rules: &[Rule]) -> Result<()>;
    /// execve; returns only on failure (the fake returns Ok to mean "exec'd").
    fn exec(&mut self, cli: &str, argv: &[String], env: &[String]) -> io::Result<()>;
}

/// The one failure record (§1): `{"k":"fail","code":<exit>,"step":<n>}`, at most 64 bytes.
pub fn record_bytes(code: i32, step: u8) -> Vec<u8> {
    format!("{{\"k\":\"fail\",\"code\":{code},\"step\":{step}}}").into_bytes()
}
pub const START: &[u8] = b"{\"k\":\"start\"}";

/// The outcome of `run`: Ok(()) only after a successful exec (in the fake); otherwise the error to report and exit
/// with. Its record, when one is possible, has already been written.
pub fn run<O: TurnOps, P: ProcOps>(o: &mut O, p: &mut P, argv: &[String]) -> Result<()> {
    // §1, first: both inherited descriptors close on exec; an invalid status pipe (or go pipe) can prove nothing.
    if p.cloexec(STATUS).is_err() || !p.status_fd_ok(STATUS).unwrap_or(false) || p.cloexec(GO).is_err() {
        return Err(err(Fail::Contract, "the status or go descriptor isn't valid"));
    }
    if p.close_from(5).is_err() {
        return Err(err(Fail::Internal, "descriptors can't be closed"));
    }
    if p.write(STATUS, START).map_or(true, |n| n != START.len()) {
        return Err(err(Fail::Internal, "the start record can't be written"));
    }
    // ONE go byte, then fd 4 closed; anything else is a failure record.
    let mut step = 1u8;
    let mut b = [0u8; 1];
    let go = match p.read(GO, &mut b) {
        Ok(1) => p.close(GO).map_err(|_| err(Fail::Internal, "the go descriptor can't be closed")),
        _ => Err(err(Fail::Internal, "no go byte")),
    };
    let r = go.and_then(|()| steps(o, p, argv, &mut step));
    if let Err(e) = r {
        let rec = record_bytes(e.fail.code(), step);
        let _ = p.write(STATUS, &rec); // one write; a failed or short one ends here too, with nothing more written
    }
    r
}

fn bad() -> Error {
    err(Fail::Usage, "bad arguments")
}

/// Steps 1–12, each refusal carrying the step it happened at.
fn steps<O: TurnOps, P: ProcOps>(o: &mut O, p: &mut P, argv: &[String], step: &mut u8) -> Result<()> {
    // 1. The arguments (only `--turn <32 hex>`), the root guard, the trusted root, the turn file.
    *step = 1;
    let [flag, turn] = argv else { return Err(bad()) };
    if flag != "--turn" {
        return Err(bad());
    }
    if !p.is_root() {
        return Err(err(Fail::Preflight, "root only"));
    }
    let host = o.root().map_err(|_| err(Fail::Preflight, "the root can't be opened"))?;
    let tf = read_turn_file(o, &host, turn)?;
    // 2–7.
    let staged = stage(o, host, &tf, step)?;
    // 8. The contract: the unit's own, read and checked as exec's steps 1–2, plus the staged profile's row.
    *step = 8;
    let (rules, env) = contract_rules(p, &tf)?;
    // 9. No credentials: a turn carries none.
    // 10. The confinement, equal to the unit's (r4.7's order).
    *step = 10;
    confine(p, &tf, &rules)?;
    // 11. The environment: the contract's, plus exactly CLAUDE_CONFIG_DIR.
    *step = 11;
    let env = environment(&env);
    // 12. The stdio, every other descriptor closed, exec.
    *step = 12;
    for fd in [1, 2] {
        if !p.unix_stream(fd).unwrap_or(false) {
            return Err(err(Fail::Contract, "stdout or stderr isn't a stream socket"));
        }
    }
    drop(staged);
    p.close_from(4).map_err(|_| err(Fail::Internal, "descriptors can't be closed"))?;
    p.exec(&tf.cli, &tf.args, &env).map_err(|_| err(Fail::Exec, "the CLI can't be executed"))
}

fn contract_of<P: ProcOps>(p: &mut P, tf: &TurnFile) -> Result<Contract> {
    let bytes = p.read_root(&format!("{CONTRACTS}/{}.json", tf.agent), contract::MAX_BYTES).map_err(|_| err(Fail::Contract, "the contract can't be read"))?;
    contract::read(&bytes, &tf.agent).ok_or(err(Fail::Contract, "the contract is not the closed shape"))
}

/// Step 8: the contract's rules, each staged row's identity checked from its in-view path (exec §4 steps 1–2), and the
/// one added row; and its environment, read here once (after Landlock it may not be readable). A contract that names the
/// staged profile's path, or a path beneath it, is 65.
fn contract_rules<P: ProcOps>(p: &mut P, tf: &TurnFile) -> Result<(Vec<Rule>, Vec<(String, String)>)> {
    let c = contract_of(p, tf)?;
    let names_staged = |path: &str| path == STAGED || path.starts_with(&format!("{STAGED}/"));
    if c.rules.iter().any(|r| names_staged(&r.path)) || c.staged.iter().any(|s| names_staged(&s.path)) {
        return Err(err(Fail::Contract, "the contract names the staged profile"));
    }
    for s in &c.staged {
        let (dev, ino) = p.path_ident(&s.path[1..]).map_err(|_| err(Fail::Preflight, "a staged path can't be opened"))?;
        if (dev, ino) != (s.dev, s.ino) {
            return Err(err(Fail::Preflight, "a staged identity differs"));
        }
    }
    let mut rules = c.rules;
    rules.push(Rule { path: STAGED.to_string(), access: "rwx".to_string() });
    Ok((rules, c.env))
}

/// Step 10 (A5 r4.7): every failure is 68 except Landlock's own (67 for the ABI).
fn confine<P: ProcOps>(p: &mut P, tf: &TurnFile, rules: &[Rule]) -> Result<()> {
    let caps = |_| err(Fail::Landlock, "the capabilities can't be dropped");
    // 10.0: while root, the bounding set (each capability the kernel has) and ambient.
    let mut last = None;
    for cap in 0..=CAP_PROBE_MAX {
        match p.bound_has(cap) {
            Ok(has) => {
                last = Some(cap);
                if has {
                    p.bound_drop(cap).map_err(caps)?;
                }
            }
            Err(e) if e.raw_os_error() == Some(libc::EINVAL) => break,
            Err(_) => return Err(err(Fail::Landlock, "the bounding set can't be read")),
        }
    }
    let last = last.ok_or(err(Fail::Landlock, "the bounding set can't be read"))?;
    p.ambient_clear().map_err(caps)?;
    // 10.1–10.2: the groups, then the gid and uid, read back.
    let setid = |_| err(Fail::Landlock, "the ids can't be set");
    p.setgroups(&tf.gids).map_err(setid)?;
    p.setresgid(tf.agent_uid).map_err(setid)?;
    p.setresuid(tf.agent_uid).map_err(setid)?;
    let (u, g, mut groups) = p.ids().map_err(setid)?;
    groups.sort_unstable();
    groups.dedup();
    let a = tf.agent_uid;
    if u != (a, a, a) || g != (a, a, a) || groups != tf.gids {
        return Err(err(Fail::Landlock, "the ids aren't the agent's"));
    }
    // 10.3: the three remaining sets cleared, then the WHOLE mask verified empty.
    p.capset(0, 0, 0).map_err(caps)?;
    let verify = |_| err(Fail::Landlock, "the capabilities can't be verified");
    if p.capget().map_err(verify)? != (0, 0, 0) {
        return Err(err(Fail::Landlock, "a capability is left"));
    }
    for cap in 0..=last {
        if p.bound_has(cap).map_err(verify)? || p.ambient_has(cap).map_err(verify)? {
            return Err(err(Fail::Landlock, "a capability is left"));
        }
    }
    // 10.4–10.5 (10.6, the filter, is part 3b-ii's).
    p.no_new_privs().map_err(|_| err(Fail::Landlock, "no_new_privs can't be set"))?;
    p.landlock(rules)
}

/// Step 11: the contract's environment, then exactly CLAUDE_CONFIG_DIR (r2.1 §7.1). Nothing else can pass: the
/// contract's names are its closed set, which has no ANTHROPIC_* name.
fn environment(contract_env: &[(String, String)]) -> Vec<String> {
    let mut env: Vec<String> = contract_env.iter().map(|(k, v)| format!("{k}={v}")).collect();
    env.push(format!("CLAUDE_CONFIG_DIR={STAGED}"));
    env
}

// ---- the real operations

/// The real process: each operation one wrapper in `sys`. The turn's root is opened lazily (after step 3 `/` is the
/// turn's) and dropped before the descriptors are closed.
#[derive(Default)]
pub struct RealProc {
    root: Option<OwnedFd>,
}

impl RealProc {
    fn root(&mut self) -> io::Result<&OwnedFd> {
        if self.root.is_none() {
            self.root = Some(sys::open_root()?);
        }
        Ok(self.root.as_ref().unwrap())
    }
}

impl ProcOps for RealProc {
    fn cloexec(&mut self, fd: i32) -> io::Result<()> {
        sys::fd_cloexec(fd)
    }
    fn status_fd_ok(&mut self, fd: i32) -> io::Result<bool> {
        sys::fd_is_pipe_writer(fd)
    }
    fn close_from(&mut self, fd: u32) -> io::Result<()> {
        self.root = None; // no OwnedFd of ours above the range
        sys::close_range_from(fd)
    }
    fn write(&mut self, fd: i32, b: &[u8]) -> io::Result<usize> {
        sys::write_raw(fd, b)
    }
    fn read(&mut self, fd: i32, b: &mut [u8]) -> io::Result<usize> {
        sys::read_raw(fd, b)
    }
    fn close(&mut self, fd: i32) -> io::Result<()> {
        sys::close_raw(fd)
    }
    fn unix_stream(&mut self, fd: i32) -> io::Result<bool> {
        sys::fd_is_unix_stream(fd)
    }
    fn is_root(&mut self) -> bool {
        sys::is_root()
    }
    fn read_root(&mut self, rel: &str, max: usize) -> io::Result<Vec<u8>> {
        let f = sys::openat2(self.root()?, &tree::c(rel)?, libc::O_RDONLY | libc::O_NONBLOCK, 0)?;
        let mut out = vec![0u8; max + 1];
        let mut n = 0;
        loop {
            let k = sys::pread(&f, &mut out[n..], n as u64)?;
            if k == 0 {
                break;
            }
            n += k;
            if n > max {
                return Err(io::Error::from_raw_os_error(libc::EFBIG));
            }
        }
        out.truncate(n);
        Ok(out)
    }
    fn path_ident(&mut self, rel: &str) -> io::Result<((u32, u32), u64)> {
        let h = sys::openat2(self.root()?, &tree::c(rel)?, libc::O_PATH, 0)?;
        let st = sys::statx(&h)?;
        Ok((st.dev, st.ino))
    }
    fn bound_has(&mut self, cap: u32) -> io::Result<bool> {
        sys::capbset_read(cap)
    }
    fn bound_drop(&mut self, cap: u32) -> io::Result<()> {
        sys::capbset_drop(cap)
    }
    fn ambient_clear(&mut self) -> io::Result<()> {
        sys::ambient_clear()
    }
    fn ambient_has(&mut self, cap: u32) -> io::Result<bool> {
        sys::ambient_is_set(cap)
    }
    fn setgroups(&mut self, gids: &[u32]) -> io::Result<()> {
        sys::setgroups(gids)
    }
    fn setresgid(&mut self, g: u32) -> io::Result<()> {
        sys::setresgid(g)
    }
    fn setresuid(&mut self, u: u32) -> io::Result<()> {
        sys::setresuid(u)
    }
    fn ids(&mut self) -> io::Result<((u32, u32, u32), (u32, u32, u32), Vec<u32>)> {
        Ok((sys::getresuid()?, sys::getresgid()?, sys::getgroups()?))
    }
    fn capget(&mut self) -> io::Result<(u64, u64, u64)> {
        sys::capget()
    }
    fn capset(&mut self, e: u64, p: u64, i: u64) -> io::Result<()> {
        sys::capset(e, p, i)
    }
    fn no_new_privs(&mut self) -> io::Result<()> {
        sys::no_new_privs()
    }
    /// As `exec`'s steps 3, 4 and 6: the ABI, a ruleset of exactly these rules (each added from its own O_PATH handle
    /// through the turn's root), then restrict. no_new_privs is already set (10.4).
    fn landlock(&mut self, rules: &[Rule]) -> Result<()> {
        match sys::landlock_abi() {
            Ok(v) if v >= landlock::MIN_ABI => {}
            _ => return Err(err(Fail::LandlockAbi, "landlock ABI 4 is not available")),
        }
        let attr = landlock::RulesetAttr { handled_access_fs: landlock::FS_HANDLED, handled_access_net: landlock::NET_HANDLED };
        let ruleset = sys::landlock_create_ruleset(&attr).map_err(|_| err(Fail::Landlock, "the ruleset can't be created"))?;
        for r in rules {
            let root = self.root().map_err(|_| err(Fail::Preflight, "the root can't be opened"))?;
            let h = sys::openat2(root, &tree::c(&r.path[1..]).map_err(|_| err(Fail::Contract, "a bad path"))?, libc::O_PATH, 0)
                .map_err(|_| err(Fail::Preflight, "a contract path can't be opened"))?;
            let st = sys::statx(&h).map_err(|_| err(Fail::Preflight, "a contract path can't be read"))?;
            let access = landlock::rights(&r.access, st.mode & 0o170000 == 0o040000).ok_or(err(Fail::Contract, "a bad access"))?;
            let rule = landlock::PathBeneathAttr { allowed_access: access, parent_fd: h.as_raw_fd() };
            sys::landlock_add_path_rule(&ruleset, rule).map_err(|_| err(Fail::Landlock, "a rule can't be added"))?;
        }
        sys::landlock_restrict_self(&ruleset).map_err(|_| err(Fail::Landlock, "the ruleset can't be applied"))
    }
    fn exec(&mut self, cli: &str, argv: &[String], env: &[String]) -> io::Result<()> {
        let bad = || io::Error::from_raw_os_error(libc::EINVAL);
        let cli_c = CString::new(cli).map_err(|_| bad())?;
        let mut store = vec![cli_c.clone()];
        for a in argv {
            store.push(CString::new(a.as_str()).map_err(|_| bad())?);
        }
        let envs: Vec<CString> = env.iter().map(|e| CString::new(e.as_str())).collect::<core::result::Result<_, _>>().map_err(|_| bad())?;
        let mut av: Vec<*const libc::c_char> = store.iter().map(|s| s.as_ptr()).collect();
        av.push(core::ptr::null());
        let mut ev: Vec<*const libc::c_char> = envs.iter().map(|s| s.as_ptr()).collect();
        ev.push(core::ptr::null());
        Err(sys::execve(&cli_c, &av, &ev))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::tests::{Fake, A};
    use crate::turn::tests::{host, with_turn_file, AUID, TURN, UNIT};
    use std::collections::{BTreeMap, BTreeSet};

    /// The highest capability this fake kernel has (a probe past it is EINVAL).
    const LAST: u32 = 40;
    const ALL: u64 = (1u64 << (LAST + 1)) - 1;
    const CAP_SETGID: u32 = 6;
    const CAP_SETUID: u32 = 7;
    const CAP_SETPCAP: u32 = 8;

    /// The process, as the kernel would treat it: descriptors 0–4, the five capability sets, the ids, no_new_privs,
    /// Landlock; every call logged. `fail` makes the named call fail once it is reached; `leak` leaves one bit in a set.
    struct Proc {
        log: Vec<String>,
        fail: Option<&'static str>,
        short_write: Option<usize>,
        status_ok: bool,
        go: Vec<u8>,
        status: Vec<Vec<u8>>,
        sockets: BTreeSet<i32>,
        closed_from: Option<u32>,
        root: bool,
        files: BTreeMap<String, Vec<u8>>,
        idents: BTreeMap<String, ((u32, u32), u64)>,
        bound: u64,
        ambient: u64,
        eff: u64,
        perm: u64,
        inh: u64,
        uid: (u32, u32, u32),
        gid: (u32, u32, u32),
        groups: Vec<u32>,
        nnp: bool,
        leak: Option<&'static str>,
        /// The ids read-back lies about one of uid, gid or groups.
        lie: Option<&'static str>,
        /// The status write numbered this (1 = start) fails.
        fail_write_at: Option<usize>,
        writes: usize,
        landlock_rules: Vec<Rule>,
        abi_ok: bool,
        exec: Option<(String, Vec<String>, Vec<String>)>,
    }

    fn contract_json(rules: &str, env: &str) -> Vec<u8> {
        format!("{{\"v\":1,\"agent\":\"{A}\",\"rules\":[{rules}],\"staged\":[{{\"index\":0,\"path\":\"/srv/x\",\"mode\":\"rw\",\"dev\":[8,1],\"ino\":77}}],\"env\":[{env}]}}").into_bytes()
    }

    impl Proc {
        fn new() -> Proc {
            let mut files = BTreeMap::new();
            files.insert(format!("{CONTRACTS}/{A}.json"), contract_json("{\"path\":\"/usr\",\"access\":\"rx\"},{\"path\":\"/srv/x\",\"access\":\"rw\"}", "[\"PATH\",\"/usr/bin\"],[\"HOME\",\"/home/agent\"]"));
            let mut idents = BTreeMap::new();
            idents.insert("srv/x".to_string(), ((8, 1), 77));
            Proc {
                log: vec![],
                fail: None,
                short_write: None,
                status_ok: true,
                go: vec![b'g'],
                status: vec![],
                sockets: [1, 2].into_iter().collect(),
                closed_from: None,
                root: true,
                files,
                idents,
                bound: ALL,
                ambient: 1 << 3,
                eff: ALL,
                perm: ALL,
                inh: 1 << 2, // inheritable survives the setid: only 10.3's capset clears it
                uid: (0, 0, 0),
                gid: (0, 0, 0),
                groups: vec![0],
                nnp: false,
                leak: None,
                lie: None,
                fail_write_at: None,
                writes: 0,
                landlock_rules: vec![],
                abi_ok: true,
                exec: None,
            }
        }
        fn op(&mut self, name: &'static str) -> io::Result<()> {
            self.log.push(name.to_string());
            if self.fail == Some(name) {
                self.fail = None;
                return Err(io::Error::from_raw_os_error(libc::EPERM));
            }
            Ok(())
        }
        fn has(&self, cap: u32) -> bool {
            self.eff & (1 << cap) != 0
        }
        fn seen(&self, name: &str) -> bool {
            self.log.iter().any(|l| l == name)
        }
    }

    impl ProcOps for Proc {
        fn cloexec(&mut self, fd: i32) -> io::Result<()> {
            self.op(if fd == STATUS { "cloexec3" } else { "cloexec4" })
        }
        fn status_fd_ok(&mut self, _fd: i32) -> io::Result<bool> {
            self.op("status_fd_ok")?;
            Ok(self.status_ok)
        }
        fn close_from(&mut self, fd: u32) -> io::Result<()> {
            self.op(if fd == 5 { "close_from5" } else { "close_from4" })?;
            self.closed_from = Some(fd);
            Ok(())
        }
        fn write(&mut self, _fd: i32, b: &[u8]) -> io::Result<usize> {
            self.op("write")?;
            self.writes += 1;
            if self.fail_write_at == Some(self.writes) {
                return Err(io::Error::from_raw_os_error(libc::EPIPE));
            }
            let n = self.short_write.take().unwrap_or(b.len()).min(b.len());
            self.status.push(b[..n].to_vec());
            Ok(n)
        }
        fn read(&mut self, _fd: i32, b: &mut [u8]) -> io::Result<usize> {
            self.op("read_go")?;
            let n = self.go.len().min(b.len());
            b[..n].copy_from_slice(&self.go[..n]);
            Ok(n)
        }
        fn close(&mut self, _fd: i32) -> io::Result<()> {
            self.op("close4")
        }
        fn unix_stream(&mut self, fd: i32) -> io::Result<bool> {
            self.op(if fd == 1 { "stdout" } else { "stderr" })?;
            Ok(self.sockets.contains(&fd))
        }
        fn is_root(&mut self) -> bool {
            self.root
        }
        fn read_root(&mut self, rel: &str, max: usize) -> io::Result<Vec<u8>> {
            self.op("contract")?;
            let b = self.files.get(rel).cloned().ok_or(io::Error::from_raw_os_error(libc::ENOENT))?;
            if b.len() > max { Err(io::Error::from_raw_os_error(libc::EFBIG)) } else { Ok(b) }
        }
        fn path_ident(&mut self, rel: &str) -> io::Result<((u32, u32), u64)> {
            self.op("path_ident")?;
            self.idents.get(rel).copied().ok_or(io::Error::from_raw_os_error(libc::ENOENT))
        }
        fn bound_has(&mut self, cap: u32) -> io::Result<bool> {
            if cap > LAST {
                return Err(io::Error::from_raw_os_error(libc::EINVAL));
            }
            Ok(self.bound & (1 << cap) != 0)
        }
        fn bound_drop(&mut self, cap: u32) -> io::Result<()> {
            self.op("bound_drop")?;
            // The kernel: PR_CAPBSET_DROP needs CAP_SETPCAP in the effective set.
            if !self.has(CAP_SETPCAP) {
                self.log.push("EPERM bound_drop".into());
                return Err(io::Error::from_raw_os_error(libc::EPERM));
            }
            if !(self.leak == Some("bound") && cap == 12) {
                self.bound &= !(1 << cap);
            }
            Ok(())
        }
        fn ambient_clear(&mut self) -> io::Result<()> {
            self.op("ambient_clear")?;
            if self.leak != Some("ambient") {
                self.ambient = 0;
            }
            Ok(())
        }
        fn ambient_has(&mut self, cap: u32) -> io::Result<bool> {
            Ok(self.ambient & (1 << cap) != 0)
        }
        fn setgroups(&mut self, gids: &[u32]) -> io::Result<()> {
            self.op("setgroups")?;
            if !self.has(CAP_SETGID) {
                return Err(io::Error::from_raw_os_error(libc::EPERM));
            }
            self.groups = gids.to_vec();
            Ok(())
        }
        fn setresgid(&mut self, g: u32) -> io::Result<()> {
            self.op("setresgid")?;
            if !self.has(CAP_SETGID) {
                return Err(io::Error::from_raw_os_error(libc::EPERM));
            }
            self.gid = (g, g, g);
            Ok(())
        }
        fn setresuid(&mut self, u: u32) -> io::Result<()> {
            self.op("setresuid")?;
            if !self.has(CAP_SETUID) {
                return Err(io::Error::from_raw_os_error(libc::EPERM));
            }
            let was_root = self.uid.0 == 0 || self.uid.1 == 0 || self.uid.2 == 0;
            self.uid = (u, u, u);
            // The kernel: all of root's uids non-zero clears permitted, effective and ambient (capabilities(7)).
            if was_root && u != 0 && self.leak != Some("setid") {
                self.perm = 0;
                self.eff = 0;
                if self.leak != Some("ambient") {
                    self.ambient = 0; // (a leaked ambient bit is modelled as surviving, to isolate its check)
                }
            }
            Ok(())
        }
        fn ids(&mut self) -> io::Result<((u32, u32, u32), (u32, u32, u32), Vec<u32>)> {
            self.op("ids")?;
            let (mut u, mut g, mut gr) = (self.uid, self.gid, self.groups.clone());
            match self.lie {
                Some("uid") => u.2 = 0,
                Some("gid") => g.1 = 0,
                Some("groups") => gr.push(80009),
                Some("groups-missing") => gr.clear(),
                Some("groups-repeated") => gr.extend(gr.clone()),
                _ => {}
            }
            Ok((u, g, gr))
        }
        fn capget(&mut self) -> io::Result<(u64, u64, u64)> {
            self.op("capget")?;
            Ok((self.eff, self.perm, self.inh))
        }
        fn capset(&mut self, e: u64, p: u64, i: u64) -> io::Result<()> {
            self.op("capset")?;
            let keep = |set: &str| if self.leak == Some(set) { 1u64 << 21 } else { 0 };
            let (ke, kp, ki) = (keep("eff"), keep("perm"), keep("inh"));
            self.eff = e | ke;
            self.perm = p | kp;
            self.inh = i | ki;
            Ok(())
        }
        fn no_new_privs(&mut self) -> io::Result<()> {
            self.op("nnp")?;
            self.nnp = true;
            Ok(())
        }
        fn landlock(&mut self, rules: &[Rule]) -> Result<()> {
            self.log.push("landlock".into());
            if !self.abi_ok {
                return Err(err(Fail::LandlockAbi, "landlock ABI 4 is not available"));
            }
            if self.fail == Some("landlock") || !self.nnp {
                return Err(err(Fail::Landlock, "the ruleset can't be applied"));
            }
            self.landlock_rules = rules.to_vec();
            Ok(())
        }
        fn exec(&mut self, cli: &str, argv: &[String], env: &[String]) -> io::Result<()> {
            self.op("exec")?;
            self.exec = Some((cli.to_string(), argv.to_vec(), env.to_vec()));
            Ok(())
        }
    }

    fn argv() -> Vec<String> {
        vec!["--turn".into(), TURN.into()]
    }

    /// A host where the whole turn can run: the unit, the profile, one mountpoint and its store, the turn file.
    fn world() -> (Fake, TurnFile, Proc) {
        let (mut f, tf) = host(&["projects"]);
        with_turn_file(&mut f, &tf);
        (f, tf, Proc::new())
    }

    fn code(r: &Result<()>) -> i32 {
        r.as_ref().err().map_or(0, |e| e.fail.code())
    }

    /// The status pipe's records after `start`: exactly one, or none.
    fn record(p: &Proc) -> Option<String> {
        assert_eq!(p.status.first().map(Vec::as_slice), Some(START), "start comes first");
        assert!(p.status.len() <= 2, "at most one record after start: {:?}", p.status);
        p.status.get(1).map(|b| String::from_utf8(b.clone()).unwrap())
    }

    #[test]
    fn the_whole_turn_in_order_exec_with_the_staged_profile() {
        let (mut f, tf, mut p) = world();
        let r = run(&mut f, &mut p, &argv());
        assert_eq!(code(&r), 0, "{r:?} {:?}", p.log);
        assert_eq!(record(&p), None, "no failure record");
        // §1 first, then the go byte, then the steps.
        assert_eq!(p.log[..7], ["cloexec3", "status_fd_ok", "cloexec4", "close_from5", "write", "read_go", "close4"]);
        assert!(f.log.iter().any(|l| l == &format!("setns {UNIT}")), "steps 2-7 ran");
        // 10, r4.7's order: bounding and ambient while root, then the ids, then the clear and the verification.
        let pos = |n: &str| p.log.iter().position(|l| l == n).unwrap_or_else(|| panic!("{n}: {:?}", p.log));
        assert!(pos("contract") < pos("bound_drop") && pos("bound_drop") < pos("ambient_clear"));
        assert!(pos("ambient_clear") < pos("setgroups") && pos("setgroups") < pos("setresgid") && pos("setresgid") < pos("setresuid"));
        assert!(pos("setresuid") < pos("ids") && pos("ids") < pos("capset") && pos("capset") < pos("capget") && pos("capget") < pos("nnp"));
        assert!(pos("nnp") < pos("landlock") && pos("landlock") < pos("stdout") && pos("stderr") < pos("close_from4") && pos("close_from4") < pos("exec"));
        // The end state: the agent's ids and groups, every set empty, no_new_privs.
        assert_eq!((p.uid, p.gid, p.groups.clone()), ((AUID, AUID, AUID), (AUID, AUID, AUID), tf.gids.clone()));
        assert_eq!((p.bound, p.ambient, p.eff, p.perm, p.inh), (0, 0, 0, 0, 0));
        assert!(p.nnp);
        // Landlock: the contract's rules plus exactly the staged profile's rwx row.
        assert_eq!(p.landlock_rules.last().unwrap(), &Rule { path: STAGED.into(), access: "rwx".into() });
        assert_eq!(p.landlock_rules.len(), 3);
        // The exec: the turn file's CLI and args; the contract's environment plus exactly CLAUDE_CONFIG_DIR.
        let (cli, args, env) = p.exec.clone().unwrap();
        assert_eq!((cli, args), (tf.cli.clone(), tf.args.clone()));
        assert_eq!(env, ["PATH=/usr/bin", "HOME=/home/agent", "CLAUDE_CONFIG_DIR=/run/sagebrush/claude-profile"]);
        assert_eq!(p.closed_from, Some(4));
    }

    #[test]
    fn an_invalid_status_or_go_descriptor_is_65_with_no_record_and_nothing_else() {
        for (what, spoil) in [("fd 3 can't be set", (|p: &mut Proc| p.fail = Some("cloexec3")) as fn(&mut Proc)), ("fd 3 isn't a pipe writer", |p| p.status_ok = false), ("fd 4 can't be set", |p| p.fail = Some("cloexec4"))] {
            let (mut f, _, mut p) = world();
            spoil(&mut p);
            let r = run(&mut f, &mut p, &argv());
            assert_eq!(code(&r), 65, "{what}");
            assert!(p.status.is_empty(), "{what}: nothing written, not even start");
            assert!(!p.seen("read_go") && !p.seen("close_from5"), "{what}");
            assert!(f.log.is_empty(), "{what}: nothing of the turn");
        }
    }

    #[test]
    fn before_the_go_byte_nothing_happens_and_after_start_every_failure_is_one_record() {
        // close_range or the start write failing: 72, no record (nothing proved), nothing after.
        for what in ["close_from5", "write"] {
            let (mut f, _, mut p) = world();
            p.fail = Some(what);
            assert_eq!(code(&run(&mut f, &mut p, &argv())), 72, "{what}");
            assert!(p.status.is_empty() && !p.seen("read_go") && f.log.is_empty(), "{what}");
        }
        // A short start write: 72, nothing more written or read.
        let (mut f, _, mut p) = world();
        p.short_write = Some(3);
        assert_eq!(code(&run(&mut f, &mut p, &argv())), 72);
        assert_eq!(p.status.len(), 1);
        assert!(!p.seen("read_go"));
        // No go byte (EOF), a read error, or fd 4 not closing: one record 72 at step 1, and nothing of the turn ran.
        for (what, spoil) in [("EOF", (|p: &mut Proc| p.go.clear()) as fn(&mut Proc)), ("a read error", |p| p.fail = Some("read_go")), ("fd 4 can't be closed", |p| p.fail = Some("close4"))] {
            let (mut f, _, mut p) = world();
            spoil(&mut p);
            assert_eq!(code(&run(&mut f, &mut p, &argv())), 72, "{what}");
            assert_eq!(record(&p).as_deref(), Some("{\"k\":\"fail\",\"code\":72,\"step\":1}"), "{what}");
            assert!(f.log.is_empty() && !p.seen("contract"), "{what}: nothing after");
        }
    }

    #[test]
    fn step_1_refusals_are_records() {
        let rows: Vec<(&str, Vec<String>, i32)> = vec![
            ("no arguments", vec![], 64),
            ("another flag", vec!["--agent".into(), TURN.into()], 64),
            ("an extra argument", vec!["--turn".into(), TURN.into(), "x".into()], 64),
            ("a turn id that isn't hex", vec!["--turn".into(), "zz".into()], 64),
        ];
        for (what, a, want) in rows {
            let (mut f, _, mut p) = world();
            assert_eq!(code(&run(&mut f, &mut p, &a)), want, "{what}");
            assert_eq!(record(&p), Some(format!("{{\"k\":\"fail\",\"code\":{want},\"step\":1}}")), "{what}");
            assert!(!f.log.iter().any(|l| l.starts_with("setns")), "{what}");
        }
        let (mut f, _, mut p) = world();
        p.root = false;
        assert_eq!(code(&run(&mut f, &mut p, &argv())), 66);
        assert_eq!(record(&p).as_deref(), Some("{\"k\":\"fail\",\"code\":66,\"step\":1}"));
        // A turn file that isn't there: 65.
        let (mut f, _, mut p) = world();
        f.files.remove(&format!("run/sagebrush/turns/{TURN}/turn.json"));
        assert_eq!(code(&run(&mut f, &mut p, &argv())), 65);
        assert_eq!(record(&p).as_deref(), Some("{\"k\":\"fail\",\"code\":65,\"step\":1}"));
    }

    #[test]
    fn a_staging_refusal_carries_its_own_step_and_stops_the_turn() {
        // A mountpoint that isn't the recorded one: 73 at step 5.
        let (mut f, _, mut p) = world();
        let mp = format!("srv/sagebrush/claude-profiles/{}/projects", crate::turn::tests::PID);
        f.node(&mp).gen = 12;
        assert_eq!(code(&run(&mut f, &mut p, &argv())), 73);
        assert_eq!(record(&p).as_deref(), Some("{\"k\":\"fail\",\"code\":73,\"step\":5}"));
        assert!(!p.seen("contract") && !p.seen("exec"));
    }

    #[test]
    fn step_8_refusals() {
        let rows: Vec<(&str, fn(&mut Proc), i32)> = vec![
            ("no contract", |p| { p.files.clear(); }, 65),
            ("a contract naming the staged profile", |p| { p.files.insert(format!("{CONTRACTS}/{A}.json"), contract_json("{\"path\":\"/srv/x\",\"access\":\"rw\"},{\"path\":\"/run/sagebrush/claude-profile\",\"access\":\"r\"}", "")); }, 65),
            ("a contract naming a path beneath it", |p| { p.files.insert(format!("{CONTRACTS}/{A}.json"), contract_json("{\"path\":\"/srv/x\",\"access\":\"rw\"},{\"path\":\"/run/sagebrush/claude-profile/x\",\"access\":\"r\"}", "")); }, 65),
            ("an ANTHROPIC_ variable", |p| { p.files.insert(format!("{CONTRACTS}/{A}.json"), contract_json("{\"path\":\"/srv/x\",\"access\":\"rw\"}", "[\"ANTHROPIC_API_KEY\",\"x\"]")); }, 65),
            ("a staged identity that differs", |p| { p.idents.insert("srv/x".into(), ((8, 1), 78)); }, 66),
            ("a staged path missing", |p| { p.idents.clear(); }, 66),
        ];
        for (what, spoil, want) in rows {
            let (mut f, _, mut p) = world();
            spoil(&mut p);
            assert_eq!(code(&run(&mut f, &mut p, &argv())), want, "{what}");
            assert_eq!(record(&p), Some(format!("{{\"k\":\"fail\",\"code\":{want},\"step\":8}}")), "{what}");
            assert!(!p.seen("bound_drop") && !p.seen("exec"), "{what}: no confinement started");
        }
    }

    #[test]
    fn step_10_each_failure_is_68_and_stops_there() {
        let later = ["setgroups", "setresgid", "setresuid", "ids", "capset", "capget", "nnp", "landlock", "exec"];
        for (i, op) in ["bound_drop", "ambient_clear", "setgroups", "setresgid", "setresuid", "ids", "capset", "capget", "nnp"].iter().enumerate() {
            let (mut f, _, mut p) = world();
            p.fail = Some(op);
            assert_eq!(code(&run(&mut f, &mut p, &argv())), 68, "{op}");
            assert_eq!(record(&p), Some("{\"k\":\"fail\",\"code\":68,\"step\":10}".into()), "{op}");
            let after = p.log.iter().position(|l| l == op).unwrap();
            for l in &p.log[after + 1..] {
                assert!(!later[i.saturating_sub(1)..].contains(&l.as_str()) || l == op, "{op}: {l} after the failure");
            }
            assert!(p.exec.is_none(), "{op}");
        }
        // Landlock: its ABI is 67, its own failure 68.
        let (mut f, _, mut p) = world();
        p.abi_ok = false;
        assert_eq!(code(&run(&mut f, &mut p, &argv())), 67);
        assert_eq!(record(&p).as_deref(), Some("{\"k\":\"fail\",\"code\":67,\"step\":10}"));
        let (mut f, _, mut p) = world();
        p.fail = Some("landlock");
        assert_eq!(code(&run(&mut f, &mut p, &argv())), 68);
        assert!(p.exec.is_none());
    }

    #[test]
    fn step_10_ids_and_every_capability_set_are_verified() {
        // Any single capability left in any of the five sets: 68, no exec.
        for set in ["bound", "ambient", "eff", "perm", "inh"] {
            let (mut f, _, mut p) = world();
            p.leak = Some(set);
            assert_eq!(code(&run(&mut f, &mut p, &argv())), 68, "{set}");
            assert!(p.exec.is_none() && !p.seen("nnp"), "{set}: refused before no_new_privs");
        }
        // A read-back that isn't the agent's: a saved uid, an effective gid, an extra or a missing group.
        for lie in ["uid", "gid", "groups", "groups-missing"] {
            let (mut f, _, mut p) = world();
            p.lie = Some(lie);
            assert_eq!(code(&run(&mut f, &mut p, &argv())), 68, "{lie}");
            assert!(!p.seen("capset") && p.exec.is_none(), "{lie}: stops at the read-back");
        }
        // The groups are compared as a set: a read-back that repeats one is still the agent's.
        let (mut f, _, mut p) = world();
        p.lie = Some("groups-repeated");
        assert_eq!(code(&run(&mut f, &mut p, &argv())), 0);
        // Capabilities kept across the setid are still cleared by 10.3's capset: not a leftover.
        let (mut f, _, mut p) = world();
        p.leak = Some("setid");
        assert_eq!(code(&run(&mut f, &mut p, &argv())), 0);
        assert_eq!((p.eff, p.perm, p.inh), (0, 0, 0));
    }

    #[test]
    fn the_late_bounding_drop_the_kernel_refuses_is_why_10_0_comes_first() {
        // The fake kernel refuses PR_CAPBSET_DROP without CAP_SETPCAP, which the setid clears: dropping after it fails.
        let mut p = Proc::new();
        p.setresuid(AUID).unwrap();
        assert!(p.bound_drop(5).is_err());
        assert!(p.seen("EPERM bound_drop"));
    }

    #[test]
    fn step_12_stdio_and_exec() {
        for (what, fd) in [("stdout", 1), ("stderr", 2)] {
            let (mut f, _, mut p) = world();
            p.sockets.remove(&fd);
            assert_eq!(code(&run(&mut f, &mut p, &argv())), 65, "{what}");
            assert_eq!(record(&p).as_deref(), Some("{\"k\":\"fail\",\"code\":65,\"step\":12}"), "{what}");
            assert!(p.exec.is_none() && p.closed_from != Some(4), "{what}");
        }
        let (mut f, _, mut p) = world();
        p.fail = Some("close_from4");
        assert_eq!(code(&run(&mut f, &mut p, &argv())), 72);
        assert!(p.exec.is_none());
        let (mut f, _, mut p) = world();
        p.fail = Some("exec");
        assert_eq!(code(&run(&mut f, &mut p, &argv())), 71);
        assert_eq!(record(&p).as_deref(), Some("{\"k\":\"fail\",\"code\":71,\"step\":12}"));
    }

    #[test]
    fn the_record_is_one_short_write_and_a_failed_one_ends_the_turn() {
        assert_eq!(record_bytes(73, 12), b"{\"k\":\"fail\",\"code\":73,\"step\":12}");
        for code in [64, 65, 66, 67, 68, 71, 72, 73] {
            for step in 1..=12 {
                assert!(record_bytes(code, step).len() <= 64);
            }
        }
        // The record's write failing: the code still returns, and nothing more is written or attempted.
        let (mut f, _, mut p) = world();
        p.go.clear();
        p.fail_write_at = Some(2);
        assert_eq!(code(&run(&mut f, &mut p, &argv())), 72);
        assert_eq!(p.status.len(), 1, "only start was written");
        assert_eq!(p.log.iter().filter(|l| *l == "write").count(), 2, "one attempt at the record, no retry");
        // The start write failing: 72, and no record is ever attempted.
        let (mut f, _, mut p) = world();
        p.fail_write_at = Some(1);
        assert_eq!(code(&run(&mut f, &mut p, &argv())), 72);
        assert_eq!(p.log.iter().filter(|l| *l == "write").count(), 1);
        assert!(!p.seen("read_go"));
    }

    /// The real wrappers that run unprivileged here (the setid, the capability drop and Landlock need root: the VM's).
    mod real {
        use super::*;
        use std::os::fd::AsRawFd;
        use std::os::unix::net::UnixStream;

        #[test]
        fn the_descriptor_checks_on_the_real_kernel() {
            let mut p = RealProc::default();
            let (r, w) = sys::pipe().unwrap();
            assert!(p.status_fd_ok(w.as_raw_fd()).unwrap(), "a pipe's write end");
            assert!(!p.status_fd_ok(r.as_raw_fd()).unwrap(), "its read end isn't");
            let (a, _b) = UnixStream::pair().unwrap();
            assert!(p.unix_stream(a.as_raw_fd()).unwrap(), "an AF_UNIX stream socket");
            assert!(!p.unix_stream(w.as_raw_fd()).unwrap(), "a pipe isn't");
            assert!(!p.status_fd_ok(a.as_raw_fd()).unwrap(), "a socket isn't a status pipe");
            assert!(p.status_fd_ok(1_000_000).is_err() && p.cloexec(1_000_000).is_err(), "an invalid descriptor");
            p.cloexec(w.as_raw_fd()).unwrap();
            // One record, read back whole.
            let rec = record_bytes(66, 2);
            assert_eq!(p.write(w.as_raw_fd(), &rec).unwrap(), rec.len());
            let mut buf = [0u8; 64];
            assert_eq!(p.read(r.as_raw_fd(), &mut buf).unwrap(), rec.len());
            assert_eq!(&buf[..rec.len()], &rec[..]);
        }

        #[test]
        fn the_id_read_backs_are_this_process() {
            use std::os::unix::fs::MetadataExt;
            let m = std::fs::metadata("/proc/self").unwrap();
            let mut p = RealProc::default();
            let (u, g, groups) = p.ids().unwrap();
            assert_eq!((u.1, g.1), (m.uid(), m.gid()), "the effective ids");
            assert!(groups.len() <= 65536);
            assert!(p.capget().is_ok() && p.bound_has(0).is_ok());
            assert_eq!(p.bound_has(200).err().and_then(|e| e.raw_os_error()), Some(libc::EINVAL), "past the kernel's last capability");
        }
    }
}
