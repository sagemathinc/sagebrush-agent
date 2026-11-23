//! Launcher contract amendment A2 r3.4 §3 steps 5-10: `restore-stage`'s child and the parent's wait.
//!
//! The child, before it execs the backup binary, in this order:
//! 1. dies with its parent (PR_SET_PDEATHSIG, then the parent pid re-checked);
//! 2. gets its own filesystem view: a private mount namespace, a 64 KiB tmpfs root holding only the binds (`/data` and
//!    `/cache` read-write; `/state`, `/secrets`, `/release` and the system set read-only; all nosuid,nodev; only
//!    `/release` without noexec), `pivot_root`, the old root detached, the root remounted read-only, and every
//!    in-namespace path re-opened and checked against the identity verified before the pivot;
//! 3. reduces the bounding, permitted and effective sets to exactly CHOWN, FOWNER and DAC_OVERRIDE, inheritable and
//!    ambient empty, and verifies the whole mask;
//! 4. sets no_new_privs, then Landlock (ABI 4+; every filesystem right handled; BIND_TCP handled with no rule);
//! 5. puts the request on fd 0 and its pipes on 1 and 2, marks every other descriptor close-on-exec;
//! 6. execveat()s the binary through the post-pivot `/release` handle with an empty environment.
//!
//! A failure at any step writes `{stage, errno}` (8 bytes) to the close-on-exec status pipe and _exits; the parent
//! maps the stage to a launcher code. EOF with no bytes means the exec happened, and from then on only the binary's
//! JSON classifies the outcome (A2 O6).
//!
//! The steps are generic over `ChildOps`, so the tests run them against a fake that models the capability sets, the
//! mounts and a failure at any call.

use crate::landlock::{self, FS_EXECUTE, FS_READ_FILE};
use std::io;

/// The three capabilities the restore child keeps (A2 r3.2): CHOWN (0), DAC_OVERRIDE (1), FOWNER (3).
pub const KEPT: u64 = (1 << 0) | (1 << 1) | (1 << 3);
/// The highest capability number probed: PR_CAPBSET_READ answers EINVAL past the kernel's last one.
const CAP_PROBE_MAX: u32 = 63;
/// Landlock ABI 4's net right BIND_TCP (linux/landlock.h, the same pinned header as landlock.rs).
pub const NET_BIND_TCP: u64 = 1 << 0;
/// The binary's name beneath the release directory.
pub const BINARY: &str = "sagebrush-agent-backup";

/// Where a pre-exec failure happened (A2 §3 step 6). Each maps to one launcher exit code (step 10).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    Pdeathsig = 1,
    Mountns = 2,
    Caps = 3,
    CapsVerify = 4,
    Nnp = 5,
    LandlockAbi = 6,
    Landlock = 7,
    Request = 8,
    Exec = 9,
}

impl Stage {
    pub fn from_u32(n: u32) -> Option<Stage> {
        use Stage::*;
        [Pdeathsig, Mountns, Caps, CapsVerify, Nnp, LandlockAbi, Landlock, Request, Exec].into_iter().find(|s| *s as u32 == n)
    }
    /// The launcher's code for this stage (A2 §3 step 10).
    pub fn fail(self) -> crate::err::Fail {
        use crate::err::Fail;
        match self {
            Stage::Caps | Stage::CapsVerify | Stage::Nnp | Stage::Landlock | Stage::Mountns => Fail::Landlock,
            Stage::LandlockAbi => Fail::LandlockAbi,
            Stage::Exec => Fail::Exec,
            Stage::Pdeathsig | Stage::Request => Fail::Internal,
        }
    }
}

/// One bind into the child's view: the verified source, its in-namespace path, and how it is mounted and ruled.
pub struct Bind<'a, H> {
    pub src: &'a H,
    /// The path inside the new root, relative ("data", "etc/ssl/certs", ...).
    pub at: &'static str,
    pub file: bool,
    pub write: bool,
    /// Only the release directory is mounted without noexec.
    pub exec: bool,
    /// Whether it is one of the five in-namespace paths re-checked after the pivot (data, cache, state, secrets,
    /// release); the system set is ruled through its pre-pivot handle.
    pub recheck: bool,
    /// The identity verified before the pivot: (dev, ino).
    pub id: ((u32, u32), u64),
}

/// Everything the child needs, prepared by the parent before the fork.
pub struct Plan<'a, H> {
    pub parent: i32,
    /// The attempt directory: the tmpfs is attached onto it inside the private namespace (never visible outside).
    pub attempt: &'a H,
    pub binds: Vec<Bind<'a, H>>,
    /// The release binary's identity verified at step 4: (dev, ino).
    pub binary: ((u32, u32), u64),
}

/// The handle operations the child needs. `RealChild` maps each to the syscall module.
pub trait ChildOps {
    type H;
    fn pdeathsig(&mut self) -> io::Result<()>;
    fn getppid(&mut self) -> i32;
    fn unshare(&mut self) -> io::Result<()>;
    fn make_private(&mut self) -> io::Result<()>;
    /// A detached tmpfs (size=64k, mode=0700, nosuid, nodev).
    fn tmpfs(&mut self) -> io::Result<Self::H>;
    /// Attach the mount `mnt` onto the directory `onto` (move_mount).
    fn attach(&mut self, mnt: &Self::H, onto: &Self::H) -> io::Result<()>;
    /// Make the mountpoint `rel` beneath `dir`: its parents as directories, then a directory or an empty file.
    fn mountpoint(&mut self, dir: &Self::H, rel: &str, file: bool) -> io::Result<Self::H>;
    /// Bind a clone of `src` onto `target` with the mount attributes `attrs` (MOUNT_ATTR_*).
    fn bind(&mut self, src: &Self::H, attrs: u64, target: &Self::H) -> io::Result<()>;
    /// fchdir into `root`, pivot_root(".", "."), detach the old root, chdir("/").
    fn enter(&mut self, root: &Self::H) -> io::Result<()>;
    /// The new root's own mount made read-only (nosuid, nodev), by its handle.
    fn remount_ro(&mut self, root: &Self::H) -> io::Result<()>;
    /// Open `rel` beneath the (new) root, O_PATH, without following any symlink.
    fn open(&mut self, rel: &str) -> io::Result<Self::H>;
    /// (dev, ino) of an opened handle.
    fn id(&mut self, h: &Self::H) -> io::Result<((u32, u32), u64)>;
    fn capbset_read(&mut self, cap: u32) -> io::Result<bool>;
    fn capbset_drop(&mut self, cap: u32) -> io::Result<()>;
    fn ambient_clear(&mut self) -> io::Result<()>;
    fn ambient_is_set(&mut self, cap: u32) -> io::Result<bool>;
    fn capget(&mut self) -> io::Result<(u64, u64, u64)>;
    fn capset(&mut self, e: u64, p: u64, i: u64) -> io::Result<()>;
    fn nnp(&mut self) -> io::Result<()>;
    fn landlock_abi(&mut self) -> io::Result<i64>;
    /// Create the ruleset (every ABI-4 filesystem right, `net` handled), add `rules`, restrict self.
    fn landlock(&mut self, rules: &[(&Self::H, u64)], net: u64) -> io::Result<()>;
    /// The request onto fd 0, stdout and stderr onto their pipes, SIGTERM unblocked, everything above 2 close-on-exec.
    fn stdio(&mut self) -> io::Result<()>;
    /// execveat(release, BINARY, argv, []): returns only on failure.
    fn exec(&mut self, release: &Self::H) -> io::Error;
}

fn errno(e: &io::Error) -> i32 {
    e.raw_os_error().unwrap_or(libc::EIO)
}

/// The child's steps, in order. Returns only on failure, with the stage and errno to report.
pub fn steps<C: ChildOps>(c: &mut C, plan: &Plan<'_, C::H>) -> (Stage, i32) {
    match run(c, plan) {
        Ok(never) => match never {},
        Err(e) => e,
    }
}

enum Never {}

fn run<C: ChildOps>(c: &mut C, plan: &Plan<'_, C::H>) -> Result<Never, (Stage, i32)> {
    let at = |stage: Stage| move |e: io::Error| (stage, errno(&e));
    // 1. Die with the parent; the re-check closes the race with a parent that already died.
    c.pdeathsig().map_err(at(Stage::Pdeathsig))?;
    if c.getppid() != plan.parent {
        return Err((Stage::Pdeathsig, libc::ESRCH));
    }

    // 2. Its own filesystem view (r3.2 P1, r3.3 Q1-Q5).
    let ns = Stage::Mountns;
    c.unshare().map_err(at(ns))?;
    c.make_private().map_err(at(ns))?;
    let root = c.tmpfs().map_err(at(ns))?;
    c.attach(&root, plan.attempt).map_err(at(ns))?;
    for b in &plan.binds {
        let target = c.mountpoint(&root, b.at, b.file).map_err(at(ns))?;
        let mut attrs = libc::MOUNT_ATTR_NOSUID | libc::MOUNT_ATTR_NODEV;
        if !b.write {
            attrs |= libc::MOUNT_ATTR_RDONLY;
        }
        if !b.exec {
            attrs |= libc::MOUNT_ATTR_NOEXEC;
        }
        c.bind(b.src, attrs, &target).map_err(at(ns))?;
    }
    c.enter(&root).map_err(at(ns))?;
    c.remount_ro(&root).map_err(at(ns))?;
    // Every in-namespace path re-opened and checked against the identity verified before the pivot.
    let mut inside = Vec::new();
    for b in plan.binds.iter().filter(|b| b.recheck) {
        let h = c.open(b.at).map_err(at(ns))?;
        if c.id(&h).map_err(at(ns))? != b.id {
            return Err((ns, libc::EXDEV));
        }
        inside.push((b, h));
    }
    let release = inside.iter().find(|(b, _)| b.exec).map(|(_, h)| h).ok_or((ns, libc::ENOENT))?;
    let binary = c.open(&format!("release/{BINARY}")).map_err(at(ns))?;
    if c.id(&binary).map_err(at(ns))? != plan.binary {
        return Err((ns, libc::EXDEV));
    }

    // 3. The capabilities, as a whole mask.
    let caps = Stage::Caps;
    let mut last = None;
    for cap in 0..=CAP_PROBE_MAX {
        match c.capbset_read(cap) {
            Ok(_) => last = Some(cap),
            Err(e) if e.raw_os_error() == Some(libc::EINVAL) => break,
            Err(e) => return Err((caps, errno(&e))),
        }
    }
    let last = last.ok_or((caps, libc::EINVAL))?;
    for cap in (0..=last).filter(|n| KEPT & (1 << n) == 0) {
        c.capbset_drop(cap).map_err(at(caps))?;
    }
    c.ambient_clear().map_err(at(caps))?;
    c.capset(KEPT, KEPT, 0).map_err(at(caps))?;
    // Verified over the whole mask: the three sets exactly the kept three, the bounding set exactly them, ambient empty.
    let verify = Stage::CapsVerify;
    if c.capget().map_err(at(verify))? != (KEPT, KEPT, 0) {
        return Err((verify, libc::EPERM));
    }
    for cap in 0..=last {
        if c.capbset_read(cap).map_err(at(verify))? != (KEPT & (1 << cap) != 0) {
            return Err((verify, libc::EPERM));
        }
        if c.ambient_is_set(cap).map_err(at(verify))? {
            return Err((verify, libc::EPERM));
        }
    }

    // 4. no_new_privs, then Landlock: a second layer inside the namespace.
    c.nnp().map_err(at(Stage::Nnp))?;
    match c.landlock_abi() {
        Ok(v) if v >= landlock::MIN_ABI => {}
        Ok(_) => return Err((Stage::LandlockAbi, libc::EOPNOTSUPP)),
        Err(e) => return Err((Stage::LandlockAbi, errno(&e))),
    }
    let mut rules: Vec<(&C::H, u64)> = Vec::new();
    for (b, h) in &inside {
        if b.exec {
            continue; // the release directory gets no rule of its own: only the one binary below
        }
        let access = if b.write { "rw" } else { "r" };
        rules.push((h, landlock::rights(access, !b.file).ok_or((Stage::Landlock, libc::EINVAL))?));
    }
    for b in plan.binds.iter().filter(|b| !b.recheck) {
        rules.push((b.src, landlock::rights("r", !b.file).ok_or((Stage::Landlock, libc::EINVAL))?));
    }
    rules.push((&binary, FS_EXECUTE | FS_READ_FILE));
    c.landlock(&rules, NET_BIND_TCP).map_err(at(Stage::Landlock))?;

    // 5-6. The request and the pipes, then the exec through the post-pivot release handle.
    c.stdio().map_err(at(Stage::Request))?;
    let e = c.exec(release);
    Err((Stage::Exec, errno(&e)))
}

// ---- the real child and the parent's wait

use crate::sys;
use std::ffi::CString;
use std::os::fd::{AsRawFd, OwnedFd};

fn c(s: &str) -> io::Result<CString> {
    CString::new(s).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))
}

/// The child's syscalls. Built by the parent before the fork, so nothing in the child needs to allocate before it
/// fails or execs (the launcher is single-threaded either way).
pub struct RealChild {
    req_r: OwnedFd,
    req_w: Option<OwnedFd>,
    out_w: OwnedFd,
    err_w: OwnedFd,
    request: Vec<u8>,
    argv: Vec<CString>,
}

impl ChildOps for RealChild {
    type H = OwnedFd;
    fn pdeathsig(&mut self) -> io::Result<()> {
        sys::pdeathsig_kill()
    }
    fn getppid(&mut self) -> i32 {
        sys::getppid()
    }
    fn unshare(&mut self) -> io::Result<()> {
        sys::unshare_mount_ns()
    }
    fn make_private(&mut self) -> io::Result<()> {
        sys::make_root_private()
    }
    fn tmpfs(&mut self) -> io::Result<OwnedFd> {
        sys::tmpfs(c"64k", c"0700")
    }
    fn attach(&mut self, mnt: &OwnedFd, onto: &OwnedFd) -> io::Result<()> {
        sys::move_mount(mnt, onto)
    }
    fn mountpoint(&mut self, dir: &OwnedFd, rel: &str, file: bool) -> io::Result<OwnedFd> {
        let parts: Vec<&str> = rel.split('/').collect();
        let mut cur = sys::openat2(dir, c".", libc::O_PATH | libc::O_DIRECTORY, 0)?;
        for (i, part) in parts.iter().enumerate() {
            let name = c(part)?;
            let last = i + 1 == parts.len();
            if last && file {
                drop(sys::create_excl(&cur, &name, 0o600)?);
                return sys::openat2(&cur, &name, libc::O_PATH, 0);
            }
            match sys::mkdirat(&cur, &name, 0o700) {
                Ok(()) => {}
                Err(e) if e.raw_os_error() == Some(libc::EEXIST) && !last => {}
                Err(e) => return Err(e),
            }
            cur = sys::openat2(&cur, &name, libc::O_PATH | libc::O_DIRECTORY, 0)?;
        }
        Ok(cur)
    }
    fn bind(&mut self, src: &OwnedFd, attrs: u64, target: &OwnedFd) -> io::Result<()> {
        let clone = sys::open_tree_clone(src)?;
        sys::mount_set(&clone, attrs)?;
        sys::move_mount(&clone, target)
    }
    fn enter(&mut self, root: &OwnedFd) -> io::Result<()> {
        sys::fchdir(root)?;
        sys::pivot_here()
    }
    fn remount_ro(&mut self, root: &OwnedFd) -> io::Result<()> {
        sys::mount_set(root, libc::MOUNT_ATTR_RDONLY | libc::MOUNT_ATTR_NOSUID | libc::MOUNT_ATTR_NODEV)
    }
    fn open(&mut self, rel: &str) -> io::Result<OwnedFd> {
        let root = sys::open_root()?;
        sys::openat2(&root, &c(rel)?, libc::O_PATH, 0)
    }
    fn id(&mut self, h: &OwnedFd) -> io::Result<((u32, u32), u64)> {
        let i = sys::ident(h)?;
        Ok((i.dev, i.ino))
    }
    fn capbset_read(&mut self, cap: u32) -> io::Result<bool> {
        sys::capbset_read(cap)
    }
    fn capbset_drop(&mut self, cap: u32) -> io::Result<()> {
        sys::capbset_drop(cap)
    }
    fn ambient_clear(&mut self) -> io::Result<()> {
        sys::ambient_clear()
    }
    fn ambient_is_set(&mut self, cap: u32) -> io::Result<bool> {
        sys::ambient_is_set(cap)
    }
    fn capget(&mut self) -> io::Result<(u64, u64, u64)> {
        sys::capget()
    }
    fn capset(&mut self, e: u64, p: u64, i: u64) -> io::Result<()> {
        sys::capset(e, p, i)
    }
    fn nnp(&mut self) -> io::Result<()> {
        sys::no_new_privs()
    }
    fn landlock_abi(&mut self) -> io::Result<i64> {
        sys::landlock_abi()
    }
    fn landlock(&mut self, rules: &[(&OwnedFd, u64)], net: u64) -> io::Result<()> {
        let attr = landlock::RulesetAttr { handled_access_fs: landlock::FS_HANDLED, handled_access_net: net };
        let ruleset = sys::landlock_create_ruleset(&attr)?;
        for (h, access) in rules {
            sys::landlock_add_path_rule(&ruleset, landlock::PathBeneathAttr { allowed_access: *access, parent_fd: h.as_raw_fd() })?;
        }
        sys::landlock_restrict_self(&ruleset)
    }
    fn stdio(&mut self) -> io::Result<()> {
        let w = self.req_w.take().ok_or(io::Error::from_raw_os_error(libc::EBADF))?;
        let mut off = 0;
        while off < self.request.len() {
            let n = sys::write(&w, &self.request[off..])?;
            if n == 0 {
                return Err(io::Error::from_raw_os_error(libc::EPIPE));
            }
            off += n;
        }
        drop(w); // the binary reads its request to EOF
        sys::dup2(&self.req_r, 0)?;
        sys::dup2(&self.out_w, 1)?;
        sys::dup2(&self.err_w, 2)?;
        sys::sigterm_mask(false)?;
        sys::cloexec_from_3()
    }
    fn exec(&mut self, release: &OwnedFd) -> io::Error {
        let argv: Vec<*const libc::c_char> = self.argv.iter().map(|a| a.as_ptr()).chain([core::ptr::null()]).collect();
        let envp = [core::ptr::null()];
        sys::execveat(release, &c(BINARY).unwrap_or_default(), &argv, &envp)
    }
}

/// The parent's wait (A2 §3 steps 5, 9): poll on the child's stdout, stderr and status pipe plus a signalfd for
/// SIGTERM (blocked in the parent, unblocked in the child before its exec), so the child never blocks on a full pipe.
/// stdout is kept up to MAX_OUT bytes: one more byte kills the child (`overflow`). stderr's first MAX_OUT bytes are
/// read and discarded (the launcher's own stderr is one fixed line by contract, so there is no channel to relay it). A SIGTERM is forwarded, then SIGKILL 10 s later. The transient scope bounds the whole.
pub struct RealRunner;

pub const MAX_OUT: usize = 64 * 1024;
const KILL_AFTER: std::time::Duration = std::time::Duration::from_secs(10);

/// What the parent saw: the status bytes (to EOF), stdout, whether it overflowed, and whether the wait was lost.
pub struct Seen {
    pub status: Vec<u8>,
    pub stdout: Vec<u8>,
    pub overflow: bool,
    pub lost: bool,
}

impl RealRunner {
    pub fn run(&mut self, plan: &mut Plan<'_, OwnedFd>, request: &[u8]) -> Option<Seen> {
        let ((st_r, st_w), (req_r, req_w), (out_r, out_w), (err_r, err_w)) = (sys::pipe().ok()?, sys::pipe().ok()?, sys::pipe().ok()?, sys::pipe().ok()?);
        sys::sigterm_mask(true).ok()?;
        let sig = sys::sigterm_fd().ok()?;
        // argv: the in-namespace paths only (A2 r3.3 Q1); the environment is empty.
        let argv = [BINARY, "--state", "/state", "--secrets", "/secrets", "--cache", "/cache"].iter().map(|a| c(a)).collect::<io::Result<Vec<CString>>>().ok()?;
        plan.parent = sys::getpid();
        let pid = sys::fork().ok()?;
        if pid == 0 {
            // The child: the status pipe's write end is close-on-exec, so EOF in the parent means the exec happened.
            let mut ch = RealChild { req_r, req_w: Some(req_w), out_w, err_w, request: request.to_vec(), argv };
            let (stage, errno) = steps(&mut ch, plan);
            let _ = sys::write(&st_w, &record(stage, errno));
            sys::exit_now(1);
        }
        drop((st_w, req_r, req_w, out_w, err_w));
        Some(wait(pid, &st_r, &out_r, &err_r, &sig))
    }
}

fn wait(pid: libc::pid_t, st: &OwnedFd, out: &OwnedFd, errp: &OwnedFd, sig: &OwnedFd) -> Seen {
    let mut seen = Seen { status: Vec::new(), stdout: Vec::new(), overflow: false, lost: false };
    let mut open = [true, true, true];
    let mut kill_at: Option<std::time::Instant> = None;
    let mut buf = vec![0u8; 16 * 1024];
    let fds = [st, out, errp];
    while open.iter().any(|o| *o) {
        let mut pfds: Vec<libc::pollfd> = Vec::new();
        let mut which = Vec::new();
        for (i, fd) in fds.iter().enumerate() {
            if open[i] {
                pfds.push(libc::pollfd { fd: fd.as_raw_fd(), events: libc::POLLIN, revents: 0 });
                which.push(i);
            }
        }
        pfds.push(libc::pollfd { fd: sig.as_raw_fd(), events: libc::POLLIN, revents: 0 });
        let timeout = kill_at.map_or(-1, |t| t.saturating_duration_since(std::time::Instant::now()).as_millis().min(i32::MAX as u128) as i32);
        match sys::poll(&mut pfds, timeout) {
            Ok(_) => {}
            Err(e) if e.raw_os_error() == Some(libc::EINTR) => continue,
            Err(_) => {
                seen.lost = true;
                let _ = sys::kill(pid, libc::SIGKILL);
                break;
            }
        }
        if kill_at.is_some_and(|t| std::time::Instant::now() >= t) {
            let _ = sys::kill(pid, libc::SIGKILL);
            kill_at = None;
        }
        if pfds.last().is_some_and(|p| p.revents & libc::POLLIN != 0) {
            let mut si = [0u8; 128];
            let _ = sys::read(sig, &mut si);
            let _ = sys::kill(pid, libc::SIGTERM);
            kill_at.get_or_insert(std::time::Instant::now() + KILL_AFTER);
        }
        for (k, i) in which.iter().enumerate() {
            if pfds[k].revents == 0 {
                continue;
            }
            match sys::read(fds[*i], &mut buf) {
                Ok(0) => open[*i] = false,
                Ok(n) => match i {
                    0 => {
                        if seen.status.len() + n > 16 {
                            seen.status.extend_from_slice(&[0; 9]); // unreadable: more than one record
                        } else {
                            seen.status.extend_from_slice(&buf[..n]);
                        }
                    }
                    1 => {
                        if seen.overflow || seen.stdout.len() + n > MAX_OUT {
                            if !seen.overflow {
                                let _ = sys::kill(pid, libc::SIGKILL);
                            }
                            seen.overflow = true;
                        } else {
                            seen.stdout.extend_from_slice(&buf[..n]);
                        }
                    }
                    _ => {} // stderr: read and discarded, never buffered
                },
                Err(e) if e.raw_os_error() == Some(libc::EINTR) || e.raw_os_error() == Some(libc::EAGAIN) => {}
                Err(_) => {
                    seen.lost = true;
                    let _ = sys::kill(pid, libc::SIGKILL);
                    open = [false; 3];
                }
            }
        }
    }
    let _ = sys::waitpid(pid, 0);
    seen
}

/// The status record the child writes: stage then errno, little-endian u32 and i32.
pub fn record(stage: Stage, errno: i32) -> [u8; 8] {
    let mut b = [0u8; 8];
    b[..4].copy_from_slice(&(stage as u32).to_le_bytes());
    b[4..].copy_from_slice(&errno.to_le_bytes());
    b
}

/// The status pipe's bytes, read to EOF: empty means the exec happened; exactly one record is a pre-exec failure;
/// anything else is unreadable (None).
pub fn read_record(bytes: &[u8]) -> Option<Option<(Stage, i32)>> {
    match bytes.len() {
        0 => Some(None),
        8 => {
            let stage = Stage::from_u32(u32::from_le_bytes(bytes[..4].try_into().ok()?))?;
            Some(Some((stage, i32::from_le_bytes(bytes[4..].try_into().ok()?))))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::landlock::{FS_HANDLED, FS_MAKE_REG, FS_WRITE_FILE};
    use std::collections::BTreeSet;

    const PARENT: i32 = 4242;
    const LAST_CAP: u32 = 40;

    /// A fake child: handles are numbers; the capability sets are modelled (bounding, effective, permitted,
    /// inheritable, ambient); `fail` makes the named call fail once it is reached; `leak` makes one set keep a
    /// capability the call should have removed.
    struct Fake {
        calls: Vec<String>,
        fail: Option<&'static str>,
        next: u32,
        bounding: u64,
        eff: u64,
        perm: u64,
        inh: u64,
        ambient: u64,
        leak: Option<(&'static str, u32)>,
        ppid: i32,
        abi: i64,
        /// (dev, ino) per handle; the post-pivot opens return these by path.
        ids: std::collections::BTreeMap<String, ((u32, u32), u64)>,
        rules: Vec<(u32, u64)>,
        net: u64,
        pivoted: bool,
        execed_with: Option<u32>,
    }

    fn all_caps() -> u64 {
        (1u64 << (LAST_CAP + 1)) - 1
    }

    impl Fake {
        fn new() -> Fake {
            let mut ids = std::collections::BTreeMap::new();
            for (p, ino) in [("data", 11), ("cache", 12), ("state", 13), ("secrets", 14), ("release", 15), (&*format!("release/{BINARY}"), 16)] {
                ids.insert(p.to_string(), ((8, 1), ino));
            }
            Fake {
                calls: vec![],
                fail: None,
                next: 100,
                bounding: all_caps(),
                eff: all_caps(),
                perm: all_caps(),
                inh: 0,
                ambient: 1 << 24,
                leak: None,
                ppid: PARENT,
                abi: 6,
                ids,
                rules: vec![],
                net: 0,
                pivoted: false,
                execed_with: None,
            }
        }
        fn call(&mut self, name: &str) -> io::Result<()> {
            self.calls.push(name.to_string());
            if self.fail.is_some_and(|f| name.starts_with(f)) {
                return Err(io::Error::from_raw_os_error(libc::EPERM));
            }
            Ok(())
        }
        fn h(&mut self) -> u32 {
            self.next += 1;
            self.next
        }
    }

    impl ChildOps for Fake {
        type H = u32;
        fn pdeathsig(&mut self) -> io::Result<()> {
            self.call("pdeathsig")
        }
        fn getppid(&mut self) -> i32 {
            self.ppid
        }
        fn unshare(&mut self) -> io::Result<()> {
            self.call("unshare")
        }
        fn make_private(&mut self) -> io::Result<()> {
            self.call("private")
        }
        fn tmpfs(&mut self) -> io::Result<u32> {
            self.call("tmpfs")?;
            Ok(self.h())
        }
        fn attach(&mut self, _mnt: &u32, _onto: &u32) -> io::Result<()> {
            self.call("attach")
        }
        fn mountpoint(&mut self, _dir: &u32, rel: &str, file: bool) -> io::Result<u32> {
            self.call(&format!("mountpoint {rel} {}", if file { "file" } else { "dir" }))?;
            Ok(self.h())
        }
        fn bind(&mut self, src: &u32, attrs: u64, _target: &u32) -> io::Result<()> {
            let ro = attrs & libc::MOUNT_ATTR_RDONLY != 0;
            let noexec = attrs & libc::MOUNT_ATTR_NOEXEC != 0;
            let nosuid_nodev = attrs & (libc::MOUNT_ATTR_NOSUID | libc::MOUNT_ATTR_NODEV) == (libc::MOUNT_ATTR_NOSUID | libc::MOUNT_ATTR_NODEV);
            self.call(&format!("bind {src} ro={ro} noexec={noexec} nosuid_nodev={nosuid_nodev}"))
        }
        fn enter(&mut self, _root: &u32) -> io::Result<()> {
            self.call("enter")?;
            self.pivoted = true;
            Ok(())
        }
        fn remount_ro(&mut self, _root: &u32) -> io::Result<()> {
            self.call("remount_ro")
        }
        fn open(&mut self, rel: &str) -> io::Result<u32> {
            self.call(&format!("open {rel}"))?;
            assert!(self.pivoted, "post-pivot opens only");
            let id = *self.ids.get(rel).ok_or(io::Error::from_raw_os_error(libc::ENOENT))?;
            let h = self.h();
            self.ids.insert(format!("#{h}"), id);
            Ok(h)
        }
        fn id(&mut self, h: &u32) -> io::Result<((u32, u32), u64)> {
            self.ids.get(&format!("#{h}")).copied().ok_or(io::Error::from_raw_os_error(libc::EBADF))
        }
        fn capbset_read(&mut self, cap: u32) -> io::Result<bool> {
            if cap > LAST_CAP {
                return Err(io::Error::from_raw_os_error(libc::EINVAL));
            }
            Ok(self.bounding & (1 << cap) != 0)
        }
        fn capbset_drop(&mut self, cap: u32) -> io::Result<()> {
            self.call(&format!("drop {cap}"))?;
            if self.leak != Some(("bounding", cap)) {
                self.bounding &= !(1 << cap);
            }
            Ok(())
        }
        fn ambient_clear(&mut self) -> io::Result<()> {
            self.call("ambient_clear")?;
            self.ambient = match self.leak {
                Some(("ambient", cap)) => 1 << cap,
                _ => 0,
            };
            Ok(())
        }
        fn ambient_is_set(&mut self, cap: u32) -> io::Result<bool> {
            Ok(self.ambient & (1 << cap) != 0)
        }
        fn capget(&mut self) -> io::Result<(u64, u64, u64)> {
            Ok((self.eff, self.perm, self.inh))
        }
        fn capset(&mut self, e: u64, p: u64, i: u64) -> io::Result<()> {
            self.call("capset")?;
            // capset can only reduce, as on Linux; a leak keeps one bit in one set.
            let keep = |set: &str| match self.leak {
                Some((s, cap)) if s == set => 1u64 << cap,
                _ => 0,
            };
            let (ke, kp, ki) = (keep("effective"), keep("permitted"), keep("inheritable"));
            self.eff = (e & self.perm) | ke;
            self.perm = (p & self.perm) | kp;
            self.inh = i | ki;
            Ok(())
        }
        fn nnp(&mut self) -> io::Result<()> {
            self.call("nnp")
        }
        fn landlock_abi(&mut self) -> io::Result<i64> {
            self.call("landlock_abi")?;
            Ok(self.abi)
        }
        fn landlock(&mut self, rules: &[(&u32, u64)], net: u64) -> io::Result<()> {
            self.call("ruleset")?;
            self.rules = rules.iter().map(|(h, r)| (**h, *r)).collect();
            self.net = net;
            Ok(())
        }
        fn stdio(&mut self) -> io::Result<()> {
            self.call("stdio")
        }
        fn exec(&mut self, release: &u32) -> io::Error {
            self.execed_with = Some(*release);
            match self.call("exec") {
                Err(e) => e,
                Ok(()) => io::Error::from_raw_os_error(libc::ENOEXEC), // the fake can't exec: it reports it reached here
            }
        }
    }

    /// The plan restore-stage builds: the five rechecked binds, then two system-set entries (a dir and a file).
    fn plan(srcs: &[u32; 7]) -> Plan<'_, u32> {
        let b = |i: usize, at: &'static str, file, write, exec, recheck, ino| Bind { src: &srcs[i], at, file, write, exec, recheck, id: ((8, 1), ino) };
        Plan {
            parent: PARENT,
            attempt: &srcs[0],
            binds: vec![
                b(0, "data", false, true, false, true, 11),
                b(1, "cache", false, true, false, true, 12),
                b(2, "state", false, false, false, true, 13),
                b(3, "secrets", false, false, false, true, 14),
                b(4, "release", false, false, true, true, 15),
                b(5, "etc/ssl/certs", false, false, false, false, 0),
                b(6, "etc/resolv.conf", true, false, false, false, 0),
            ],
            binary: ((8, 1), 16),
        }
    }
    const SRCS: [u32; 7] = [1, 2, 3, 4, 5, 6, 7];

    #[test]
    fn the_steps_in_order_then_the_exec_through_the_post_pivot_release_handle() {
        let mut f = Fake::new();
        let (stage, _) = steps(&mut f, &plan(&SRCS));
        assert_eq!(stage, Stage::Exec, "the fake reaches the exec");
        let pos = |name: &str| f.calls.iter().position(|c| c.starts_with(name)).unwrap_or_else(|| panic!("{name}: {:?}", f.calls));
        let order = ["pdeathsig", "unshare", "private", "tmpfs", "attach", "mountpoint data", "bind 1", "enter", "remount_ro", "open data", "open release/", "drop 2", "ambient_clear", "capset", "nnp", "landlock_abi", "ruleset", "stdio", "exec"];
        for w in order.windows(2) {
            assert!(pos(w[0]) < pos(w[1]), "{} before {}: {:?}", w[0], w[1], f.calls);
        }
        // The exec uses the handle opened for "release" AFTER the pivot, never a pre-pivot one.
        let release_h = f.ids.iter().find(|(k, v)| k.starts_with('#') && v.1 == 15).map(|(k, _)| k[1..].parse::<u32>().unwrap()).unwrap();
        assert_eq!(f.execed_with, Some(release_h));
        assert!(!SRCS.contains(&release_h));
    }

    #[test]
    fn every_bind_is_nosuid_nodev_only_release_without_noexec_only_data_and_cache_writable() {
        let mut f = Fake::new();
        steps(&mut f, &plan(&SRCS));
        let binds: Vec<&String> = f.calls.iter().filter(|c| c.starts_with("bind ")).collect();
        assert_eq!(binds.len(), 7);
        for (src, ro, noexec) in [(1, false, true), (2, false, true), (3, true, true), (4, true, true), (5, true, false), (6, true, true), (7, true, true)] {
            assert!(binds.contains(&&format!("bind {src} ro={ro} noexec={noexec} nosuid_nodev=true")), "{src}: {binds:?}");
        }
        // File mountpoints for file binds, directories for the rest; no /dev and no /proc ever (r3.3 Q3, Q4).
        assert!(f.calls.contains(&"mountpoint etc/resolv.conf file".to_string()));
        assert!(f.calls.contains(&"mountpoint data dir".to_string()));
        assert!(!f.calls.iter().any(|c| c.contains("dev") && c.starts_with("mountpoint") || c.contains("proc")));
    }

    #[test]
    fn the_whole_mask_is_exactly_the_kept_three_and_every_leak_in_any_set_is_68_before_anything_runs() {
        let mut f = Fake::new();
        steps(&mut f, &plan(&SRCS));
        assert_eq!((f.eff, f.perm, f.inh, f.ambient), (KEPT, KEPT, 0, 0));
        assert_eq!(f.bounding, KEPT, "the bounding set is exactly the kept three");
        let dropped: BTreeSet<u32> = f.calls.iter().filter_map(|c| c.strip_prefix("drop ")).map(|n| n.parse().unwrap()).collect();
        assert_eq!(dropped, (0..=LAST_CAP).filter(|n| KEPT & (1 << n) == 0).collect(), "every other capability up to the last");
        assert!(dropped.contains(&2) && dropped.contains(&21) && dropped.contains(&24), "DAC_READ_SEARCH, SYS_ADMIN, SYS_RESOURCE");
        // A capability left in any one of the five sets (SYS_RESOURCE, or SYS_ADMIN): caps_verify, 68, no exec.
        for set in ["bounding", "effective", "permitted", "inheritable", "ambient"] {
            for cap in [24, 21, 2] {
                let mut f = Fake::new();
                f.leak = Some((set, cap));
                let (stage, _) = steps(&mut f, &plan(&SRCS));
                assert_eq!(stage, Stage::CapsVerify, "{set} {cap}");
                assert_eq!(stage.fail().code(), 68);
                assert!(!f.calls.iter().any(|c| c == "nnp" || c == "ruleset" || c == "exec"), "{set} {cap}: {:?}", f.calls);
            }
        }
    }

    #[test]
    fn landlock_handles_every_fs_right_and_bind_and_grants_execute_only_on_the_one_binary() {
        let mut f = Fake::new();
        steps(&mut f, &plan(&SRCS));
        assert_eq!(f.net, NET_BIND_TCP, "BIND_TCP handled with no rule; CONNECT_TCP left to any port");
        let binary = f.ids.iter().find(|(k, v)| k.starts_with('#') && v.1 == 16).map(|(k, _)| k[1..].parse::<u32>().unwrap()).unwrap();
        for (h, r) in &f.rules {
            assert_eq!(r & !FS_HANDLED, 0);
            if *h == binary {
                assert_eq!(*r, FS_EXECUTE | FS_READ_FILE);
            } else {
                assert_eq!(r & FS_EXECUTE, 0, "nothing else executable: {h}");
            }
        }
        let data = f.ids.iter().find(|(k, v)| k.starts_with('#') && v.1 == 11).map(|(k, _)| k[1..].parse::<u32>().unwrap()).unwrap();
        let state = f.ids.iter().find(|(k, v)| k.starts_with('#') && v.1 == 13).map(|(k, _)| k[1..].parse::<u32>().unwrap()).unwrap();
        let rule = |h: u32| f.rules.iter().find(|(x, _)| *x == h).map(|(_, r)| *r).unwrap();
        assert_ne!(rule(data) & FS_MAKE_REG, 0, "data is writable (post-pivot handle)");
        assert_eq!(rule(state) & (FS_WRITE_FILE | FS_MAKE_REG), 0, "state is read-only");
        // The release directory itself has no rule; the system set is ruled through its verified pre-pivot handles.
        let release = f.ids.iter().find(|(k, v)| k.starts_with('#') && v.1 == 15).map(|(k, _)| k[1..].parse::<u32>().unwrap()).unwrap();
        assert!(!f.rules.iter().any(|(h, _)| *h == release));
        assert!(f.rules.iter().any(|(h, _)| *h == 6) && f.rules.iter().any(|(h, _)| *h == 7));
    }

    #[test]
    fn each_stage_failure_maps_to_its_code_and_nothing_after_it_runs() {
        for (call, stage, code) in [
            ("pdeathsig", Stage::Pdeathsig, 72),
            ("unshare", Stage::Mountns, 68),
            ("private", Stage::Mountns, 68),
            ("tmpfs", Stage::Mountns, 68),
            ("attach", Stage::Mountns, 68),
            ("mountpoint", Stage::Mountns, 68),
            ("bind", Stage::Mountns, 68),
            ("enter", Stage::Mountns, 68),
            ("remount_ro", Stage::Mountns, 68),
            ("open", Stage::Mountns, 68),
            ("drop", Stage::Caps, 68),
            ("ambient_clear", Stage::Caps, 68),
            ("capset", Stage::Caps, 68),
            ("nnp", Stage::Nnp, 68),
            ("landlock_abi", Stage::LandlockAbi, 67),
            ("ruleset", Stage::Landlock, 68),
            ("stdio", Stage::Request, 72),
            ("exec", Stage::Exec, 71),
        ] {
            let mut f = Fake::new();
            f.fail = Some(call);
            let (s, e) = steps(&mut f, &plan(&SRCS));
            assert_eq!((s, s.fail().code()), (stage, code), "{call}");
            assert_eq!(e, libc::EPERM, "{call}: the errno is the failing call's");
            let i = f.calls.iter().position(|c| c.starts_with(call)).unwrap();
            assert_eq!(i, f.calls.len() - 1, "{call}: nothing after the failure: {:?}", f.calls);
        }
        // A parent that already died: pdeathsig's re-check.
        let mut f = Fake::new();
        f.ppid = 1;
        assert_eq!(steps(&mut f, &plan(&SRCS)), (Stage::Pdeathsig, libc::ESRCH));
        assert!(!f.calls.contains(&"unshare".to_string()));
        // An ABI below 4.
        let mut f = Fake::new();
        f.abi = 3;
        assert_eq!(steps(&mut f, &plan(&SRCS)).0, Stage::LandlockAbi);
    }

    #[test]
    fn a_post_pivot_identity_mismatch_is_mountns_and_stops_before_the_caps() {
        for path in ["data", "cache", "state", "secrets", "release", "release/sagebrush-agent-backup"] {
            let mut f = Fake::new();
            f.ids.get_mut(path).unwrap().1 = 999;
            assert_eq!(steps(&mut f, &plan(&SRCS)), (Stage::Mountns, libc::EXDEV), "{path}");
            assert!(!f.calls.iter().any(|c| c.starts_with("drop") || c == "capset"), "{path}");
        }
    }

    #[test]
    fn the_status_record_round_trips_and_anything_else_is_unreadable() {
        for s in [Stage::Pdeathsig, Stage::Mountns, Stage::Caps, Stage::CapsVerify, Stage::Nnp, Stage::LandlockAbi, Stage::Landlock, Stage::Request, Stage::Exec] {
            assert_eq!(read_record(&record(s, libc::EACCES)), Some(Some((s, libc::EACCES))));
        }
        assert_eq!(read_record(&[]), Some(None), "EOF with no bytes: the exec happened");
        assert_eq!(read_record(&[1, 0, 0]), None);
        assert_eq!(read_record(&record(Stage::Exec, 1)[..7]), None);
        let mut bad = record(Stage::Exec, 1);
        bad[0] = 77;
        assert_eq!(read_record(&bad), None);
        assert_eq!(read_record(&[0u8; 16]), None);
    }
}
