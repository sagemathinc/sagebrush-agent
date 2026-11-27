//! `lease-check` (launcher contract amendment A3 r2): the execution lease's guard at the actual start boundary. Root
//! only; the unit runs it as `ExecStartPre=+` (outside the sandbox, inside the unit's cgroup, so inside the agent's
//! slice). It passes only while the agent holds a current lease, read under the agent's activation lock taken SHARED:
//! the published record exists, the tombstone's lg is below the record's, and now < expiry_tick - 30 s on
//! CLOCK_BOOTTIME, and the suspend gate (lease-on r1.5 §6.1) is open at exactly the record's `sg`. Otherwise it exits
//! 78 (`lease`) and nothing of the unit executes.
//!
//! File trust: the lease directory and every ancestor are under A1's anchor policy (root:root, no group or other write,
//! no access or default ACL), opened one component at a time without following a symlink. Each opened file is checked
//! on its own fd: a root regular file without group or other write and without an access ACL; the lock's mode is
//! exactly 0600. These checks see the file as it is now; they rest on the lease files being created only by the root
//! writer (lease.mjs), in this directory, with these modes.
//!
//! `hold` is the library form for a turn launch: it returns the locked lock fd, which is O_CLOEXEC, so the shared lock is
//! held until the turn's execve and released by it.

use crate::err::{err, Fail, Result};
use crate::json;
use crate::sys::{self, Ident};
use crate::tree::{c, kind_of, Kind};
use std::io;
use std::os::fd::OwnedFd;

/// The lease directory's components from "/".
const LEASE_DIR: [&str; 3] = ["run", "sagebrush", "lease"];
/// The effective end of a lease: the watchdog fires this long before expiry_tick (execution lease §2.1, SEC H1).
pub(crate) const MARGIN_MS: u64 = 30_000;
/// The shared lock is tried every POLL_MS for at most LOCK_WAIT_MS; it is never waited for unbounded.
pub(crate) const LOCK_WAIT_MS: u64 = 5_000;
const POLL_MS: u64 = 10;
/// A record or a tombstone is at most this many bytes.
const MAX_FILE: usize = 4096;
/// The largest lg, expiry_tick or tombstone: 2^53 - 1, the JSON-safe integer bound both writers share.
pub(crate) const MAX_SAFE: u64 = (1 << 53) - 1;
/// The highest suspend-gate generation that ever opens; MAX_SAFE itself is terminal (exhaustion: closed, T4).
pub(crate) const G_MAX: u64 = MAX_SAFE - 1;

const ACL_ACCESS: &std::ffi::CStr = c"system.posix_acl_access";
const ACL_DEFAULT: &std::ffi::CStr = c"system.posix_acl_default";

fn pre(msg: &'static str) -> crate::err::Error {
    err(Fail::Preflight, msg)
}
fn lease(msg: &'static str) -> crate::err::Error {
    err(Fail::Lease, msg)
}

/// The handle operations lease-check needs. `RealLease` maps each to one syscall wrapper in `sys`.
pub trait LeaseOps {
    type H;
    /// "/" opened O_RDONLY | O_DIRECTORY.
    fn top(&mut self) -> io::Result<Self::H>;
    /// One directory component under an open directory, O_RDONLY | O_DIRECTORY, never through a symlink.
    fn dir(&mut self, parent: &Self::H, name: &str) -> io::Result<Self::H>;
    /// The lock: O_RDWR | O_CREAT | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, mode 0600.
    fn lock_file(&mut self, dir: &Self::H, name: &str) -> io::Result<Self::H>;
    /// A record or tombstone: O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC.
    fn file(&mut self, dir: &Self::H, name: &str) -> io::Result<Self::H>;
    fn ident(&mut self, h: &Self::H) -> io::Result<Ident>;
    /// (an access ACL exists, a default ACL exists)
    fn acls(&mut self, h: &Self::H) -> io::Result<(bool, bool)>;
    /// flock(LOCK_SH | LOCK_NB): false when an exclusive holder has it.
    fn try_shared(&mut self, h: &Self::H) -> io::Result<bool>;
    /// The whole file, at most `max` bytes (EFBIG beyond).
    fn read(&mut self, h: &Self::H, max: usize) -> io::Result<Vec<u8>>;
    /// CLOCK_BOOTTIME as (tv_sec, tv_nsec).
    fn boottime(&mut self) -> io::Result<(i64, i64)>;
    fn sleep_ms(&mut self, ms: u64);
}

/// The real operations: the syscall module, nothing else.
pub struct RealLease;

impl LeaseOps for RealLease {
    type H = OwnedFd;
    fn top(&mut self) -> io::Result<OwnedFd> {
        let root = sys::open_root()?;
        sys::openat2(&root, c".", libc::O_RDONLY | libc::O_DIRECTORY, 0)
    }
    fn dir(&mut self, parent: &OwnedFd, name: &str) -> io::Result<OwnedFd> {
        sys::openat2(parent, &c(name)?, libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW, 0)
    }
    fn lock_file(&mut self, dir: &OwnedFd, name: &str) -> io::Result<OwnedFd> {
        sys::openat2(dir, &c(name)?, libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_NONBLOCK, 0o600)
    }
    fn file(&mut self, dir: &OwnedFd, name: &str) -> io::Result<OwnedFd> {
        sys::openat2(dir, &c(name)?, libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK, 0)
    }
    fn ident(&mut self, h: &OwnedFd) -> io::Result<Ident> {
        sys::ident(h)
    }
    fn acls(&mut self, h: &OwnedFd) -> io::Result<(bool, bool)> {
        Ok((sys::has_xattr(h, ACL_ACCESS)?, sys::has_xattr(h, ACL_DEFAULT)?))
    }
    fn try_shared(&mut self, h: &OwnedFd) -> io::Result<bool> {
        sys::flock_shared_nb(h)
    }
    fn read(&mut self, h: &OwnedFd, max: usize) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; max + 1];
        let mut n = 0;
        loop {
            let k = sys::pread(h, &mut buf[n..], n as u64)?;
            if k == 0 {
                break;
            }
            n += k;
            if n > max {
                return Err(io::Error::from_raw_os_error(libc::EFBIG));
            }
        }
        buf.truncate(n);
        Ok(buf)
    }
    fn boottime(&mut self) -> io::Result<(i64, i64)> {
        sys::clock_boottime()
    }
    fn sleep_ms(&mut self, ms: u64) {
        std::thread::sleep(std::time::Duration::from_millis(ms));
    }
}

/// A directory under A1's anchor policy: root:root, no group or other write, no access or default ACL.
fn trusted_dir<O: LeaseOps>(o: &mut O, h: &O::H) -> Result<()> {
    let id = o.ident(h).map_err(|_| pre("a lease directory can't be examined"))?;
    let (access, default) = o.acls(h).map_err(|_| pre("a lease directory's ACL can't be read"))?;
    if kind_of(&id) != Some(Kind::Dir) || id.uid != 0 || id.gid != 0 || id.mode & 0o022 != 0 || access || default {
        return Err(pre("a lease directory isn't root-only"));
    }
    Ok(())
}

/// A record or tombstone, if it exists: a root regular file without group or other write and without an access ACL,
/// at most MAX_FILE bytes, read in full from its own fd.
fn read_trusted<O: LeaseOps>(o: &mut O, dir: &O::H, name: &str) -> Result<Option<Vec<u8>>> {
    let h = match o.file(dir, name) {
        Ok(h) => h,
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => return Ok(None),
        Err(_) => return Err(pre("a lease file can't be opened")),
    };
    let id = o.ident(&h).map_err(|_| pre("a lease file can't be examined"))?;
    let (access, _) = o.acls(&h).map_err(|_| pre("a lease file's ACL can't be read"))?;
    if kind_of(&id) != Some(Kind::File) || id.uid != 0 || id.mode & 0o022 != 0 || access || id.size > MAX_FILE as u64 {
        return Err(pre("a lease file isn't a root-only regular file"));
    }
    o.read(&h, MAX_FILE).map(Some).map_err(|_| pre("a lease file can't be read"))
}

/// The record's (lg, expiry_tick, sg), if it has exactly the closed shape `{lease_id, lg, expiry_tick, gen, sg}` and
/// its ranges (A3 r3; lease-on r1.5 §6.2). `gen`, the lease's grant generation, is range-checked as part of the shape
/// and never compared (only the restore-resume helper compares it). `sg` is the suspend gate's generation the lease
/// was requested under: the lease is current only while the gate is open at exactly it.
pub(crate) fn parse_record(src: &[u8]) -> Option<(u64, u64, u64)> {
    let v = json::parse_with(src, 64)?;
    let f = v.exact(&["lease_id", "lg", "expiry_tick", "gen", "sg"])?;
    let id = f[0].str()?;
    if id.is_empty() || id.len() > 64 || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-') {
        return None;
    }
    let (lg, expiry, gen, sg) = (f[1].int()?, f[2].int()?, f[3].int()?, f[4].int()?);
    if !(1..=MAX_SAFE).contains(&lg) || expiry > MAX_SAFE || !(1..=MAX_SAFE).contains(&gen) || sg > MAX_SAFE {
        return None;
    }
    Some((lg, expiry, sg))
}

/// `sleep`'s closed shape `{gen, phase, pre_ok, pre_at}`: (gen >= 1, phase is "post", pre_at), or None. A `pre` record
/// parses as Some with post = false.
pub(crate) fn parse_sleep(src: &[u8]) -> Option<(u64, bool, u64)> {
    let v = json::parse_with(src, 16)?;
    let f = v.exact(&["gen", "phase", "pre_ok", "pre_at"])?;
    let (gen, at) = (f[0].int()?, f[3].int()?);
    let post = match f[1].str()? {
        "post" => true,
        "pre" => false,
        _ => return None,
    };
    if !matches!(f[2], json::Value::Bool(_)) || !(1..=MAX_SAFE).contains(&gen) || at > MAX_SAFE {
        return None;
    }
    Some((gen, post, at))
}

/// `reopen`'s closed shape `{gen}`: gen >= 1, or None.
pub(crate) fn parse_reopen(src: &[u8]) -> Option<u64> {
    let v = json::parse_with(src, 16)?;
    let f = v.exact(&["gen"])?;
    let gen = f[0].int()?;
    (1..=MAX_SAFE).contains(&gen).then_some(gen)
}

/// THE gate rule (lease-on r1.5 §6.1), the same table as lease.mjs `gateOf`, over the same fixture vectors: the
/// generation the gate is open at, or None (closed). Open only when both files are absent (0), or both are well
/// formed, `sleep` is at post with pre_at <= now, `reopen` equals `sleep`'s generation, and that is at most G_MAX.
pub(crate) fn gate_of(sleep: Option<&[u8]>, reopen: Option<&[u8]>, now: u64) -> Option<u64> {
    match (sleep, reopen) {
        (None, None) => Some(0),
        (Some(s), Some(r)) => {
            let (gen, post, at) = parse_sleep(s)?;
            let re = parse_reopen(r)?;
            (post && at <= now && re == gen && gen <= G_MAX).then_some(gen)
        }
        _ => None,
    }
}

/// The tombstone's lg: `0` or a decimal without leading zeros, at most 16 digits, at most MAX_SAFE, then one newline.
pub(crate) fn parse_tombstone(src: &[u8]) -> Option<u64> {
    let digits = src.strip_suffix(b"\n")?;
    if digits.is_empty() || digits.len() > 16 || !digits.iter().all(u8::is_ascii_digit) || (digits.len() > 1 && digits[0] == b'0') {
        return None;
    }
    let n = digits.iter().try_fold(0u64, |a, d| a.checked_mul(10)?.checked_add(u64::from(d - b'0')))?;
    (n <= MAX_SAFE).then_some(n)
}

/// CLOCK_BOOTTIME in whole ms, rounded UP (1 ns past a millisecond counts as the next one); None when out of range.
pub(crate) fn now_ms(sec: i64, nsec: i64) -> Option<u64> {
    if sec < 0 || !(0..1_000_000_000).contains(&nsec) {
        return None;
    }
    (sec as u64).checked_mul(1000)?.checked_add((nsec as u64).div_ceil(1_000_000))
}

/// The check itself (A3 §2 step 5). The guard comes before the subtraction, so it can't underflow.
pub(crate) fn current(spent: u64, lg: u64, expiry: u64, now: u64) -> bool {
    spent < lg && expiry > MARGIN_MS && now < expiry - MARGIN_MS
}

/// Steps 2-5: the trusted directory, the shared lock (at most `wait_ms`), then the record, the tombstone and the clock
/// under it. Returns the lock handle, still locked.
pub fn check<O: LeaseOps>(o: &mut O, agent: &str, wait_ms: u64) -> Result<O::H> {
    let mut d = o.top().map_err(|_| pre("the root can't be opened"))?;
    trusted_dir(o, &d)?;
    for (i, name) in LEASE_DIR.iter().enumerate() {
        let next = match o.dir(&d, name) {
            Ok(h) => h,
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) && i == LEASE_DIR.len() - 1 => return Err(lease("no lease was published")),
            Err(_) => return Err(pre("a lease directory can't be opened")),
        };
        trusted_dir(o, &next)?;
        d = next;
    }

    let lock = o.lock_file(&d, &format!("{agent}.lock")).map_err(|_| pre("the lease lock can't be opened"))?;
    let id = o.ident(&lock).map_err(|_| pre("the lease lock can't be examined"))?;
    let (access, _) = o.acls(&lock).map_err(|_| pre("the lease lock's ACL can't be read"))?;
    if kind_of(&id) != Some(Kind::File) || id.uid != 0 || id.mode & 0o7777 != 0o600 || access {
        return Err(pre("the lease lock isn't a root 0600 file"));
    }
    let mut waited = 0;
    loop {
        match o.try_shared(&lock) {
            Ok(true) => break,
            Ok(false) if waited < wait_ms => {
                o.sleep_ms(POLL_MS);
                waited += POLL_MS;
            }
            Ok(false) => return Err(lease("the lease lock is busy")),
            Err(_) => return Err(pre("the lease lock failed")),
        }
    }

    let rec = read_trusted(o, &d, agent)?.ok_or(lease("no lease record"))?;
    let (lg, expiry, sg) = parse_record(&rec).ok_or(lease("a malformed lease record"))?;
    let spent = match read_trusted(o, &d, &format!("{agent}.spent"))? {
        None => 0,
        Some(b) => parse_tombstone(&b).ok_or(lease("a malformed tombstone"))?,
    };
    let (sec, nsec) = o.boottime().map_err(|_| lease("no boot clock"))?;
    let now = now_ms(sec, nsec).ok_or(lease("the boot clock is out of range"))?;
    // The suspend gate, under the same shared lock (lease-on r1.5 §6.2): open at exactly the record's sg. An
    // untrusted gate file refuses through read_trusted; a malformed or closed gate refuses here.
    let sleep = read_trusted(o, &d, "sleep")?;
    let reopen = read_trusted(o, &d, "reopen")?;
    if gate_of(sleep.as_deref(), reopen.as_deref(), now) != Some(sg) {
        return Err(lease("the suspend gate isn't open at this lease's generation"));
    }
    if !current(spent, lg, expiry, now) {
        return Err(lease("no current lease"));
    }
    Ok(lock)
}

/// The library form (a turn launch): the checked, shared-locked, O_CLOEXEC lock fd, held until execve.
pub fn hold(agent: &str) -> Result<OwnedFd> {
    check(&mut RealLease, agent, LOCK_WAIT_MS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::{Path, PathBuf};

    const A: &str = "abcdefghijklmnopqrstuvwxya";

    /// The real operations under a temp "/" (which the test owns): the test's uid counts as root unless a name is in
    /// `foreign`; ACLs are the test layer's (`access`, `default` sets of names); the clock is fixed; sleeps run `hook`.
    struct T {
        top: PathBuf,
        me: u32,
        foreign: HashSet<String>,
        foreign_group: HashSet<String>,
        access: HashSet<String>,
        default: HashSet<String>,
        now: (i64, i64),
        sleeps: u64,
        hook: Option<Box<dyn FnMut(u64)>>,
    }
    type H = (OwnedFd, String);

    impl LeaseOps for T {
        type H = H;
        fn top(&mut self) -> io::Result<H> {
            Ok((fs::File::open(&self.top)?.into(), "/".into()))
        }
        fn dir(&mut self, p: &H, name: &str) -> io::Result<H> {
            Ok((RealLease.dir(&p.0, name)?, name.into()))
        }
        fn lock_file(&mut self, d: &H, name: &str) -> io::Result<H> {
            Ok((RealLease.lock_file(&d.0, name)?, name.into()))
        }
        fn file(&mut self, d: &H, name: &str) -> io::Result<H> {
            Ok((RealLease.file(&d.0, name)?, name.into()))
        }
        fn ident(&mut self, h: &H) -> io::Result<Ident> {
            let mut id = sys::ident(&h.0)?;
            if id.uid == self.me && !self.foreign.contains(&h.1) {
                id.uid = 0;
                id.gid = if self.foreign_group.contains(&h.1) { 1000 } else { 0 };
            }
            Ok(id)
        }
        /// The REAL adapter's answer (real xattrs), or'ed with the test layer's sets.
        fn acls(&mut self, h: &H) -> io::Result<(bool, bool)> {
            let (a, d) = RealLease.acls(&h.0)?;
            Ok((a || self.access.contains(&h.1), d || self.default.contains(&h.1)))
        }
        fn try_shared(&mut self, h: &H) -> io::Result<bool> {
            sys::flock_shared_nb(&h.0)
        }
        fn read(&mut self, h: &H, max: usize) -> io::Result<Vec<u8>> {
            RealLease.read(&h.0, max)
        }
        fn boottime(&mut self) -> io::Result<(i64, i64)> {
            Ok(self.now)
        }
        fn sleep_ms(&mut self, ms: u64) {
            self.sleeps += 1;
            if let Some(h) = self.hook.as_mut() {
                h(self.sleeps);
            }
            std::thread::sleep(std::time::Duration::from_millis(ms.min(1)));
        }
    }

    fn uid_of(p: &Path) -> u32 {
        use std::os::unix::fs::MetadataExt;
        fs::metadata(p).unwrap().uid()
    }

    /// A temp "/" with run/sagebrush/lease (0755), a current record (lg 5, expiry 100 000 ms), now 1 s.
    fn setup() -> (T, PathBuf) {
        let top = std::env::temp_dir().join(format!("sb-lease-{}-{}", std::process::id(), rand_suffix()));
        let lease = top.join("run/sagebrush/lease");
        fs::create_dir_all(&lease).unwrap();
        for p in [top.clone(), top.join("run"), top.join("run/sagebrush"), lease.clone()] {
            fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
        }
        write(&lease.join(A), br#"{"lease_id":"L1","lg":5,"expiry_tick":100000,"gen":3,"sg":0}"#, 0o644);
        let me = uid_of(&top);
        (T { top, me, foreign: HashSet::new(), foreign_group: HashSet::new(), access: HashSet::new(), default: HashSet::new(), now: (1, 0), sleeps: 0, hook: None }, lease)
    }

    fn rand_suffix() -> u64 {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        N.fetch_add(1, Ordering::SeqCst)
    }

    fn write(p: &Path, b: &[u8], mode: u32) {
        let _ = fs::remove_file(p);
        fs::write(p, b).unwrap();
        fs::set_permissions(p, fs::Permissions::from_mode(mode)).unwrap();
    }

    fn code(t: &mut T) -> i32 {
        match check(t, A, 50) {
            Ok(_) => 0,
            Err(e) => e.fail.code(),
        }
    }

    #[test]
    fn a_current_lease_passes_with_no_tombstone_and_with_one_below_lg() {
        let (mut t, lease) = setup();
        assert_eq!(code(&mut t), 0);
        let m = fs::metadata(lease.join(format!("{A}.lock"))).unwrap();
        assert_eq!(m.permissions().mode() & 0o7777, 0o600, "the lock is created 0600");
        write(&lease.join(format!("{A}.spent")), b"4\n", 0o644);
        assert_eq!(code(&mut t), 0);
    }

    #[test]
    fn no_directory_no_record_and_a_spent_lg_are_78() {
        let (mut t, lease) = setup();
        write(&lease.join(format!("{A}.spent")), b"5\n", 0o644);
        assert_eq!(code(&mut t), 78, "tombstone at lg");
        write(&lease.join(format!("{A}.spent")), b"6\n", 0o644);
        assert_eq!(code(&mut t), 78, "tombstone above lg");
        fs::remove_file(lease.join(format!("{A}.spent"))).unwrap();
        fs::remove_file(lease.join(A)).unwrap();
        assert_eq!(code(&mut t), 78, "no record");
        fs::remove_dir_all(&lease).unwrap();
        assert_eq!(code(&mut t), 78, "no lease directory");
        fs::remove_dir_all(t.top.join("run/sagebrush")).unwrap();
        assert_eq!(code(&mut t), 66, "a missing ancestor");
    }

    #[test]
    fn a_malformed_record_is_78_and_an_oversize_one_66() {
        for bad in [
            &br#"{"lease_id":"L1","lg":5}"#[..],
            br#"{"lease_id":"L1","lg":5,"expiry_tick":100000,"gen":3,"x":1}"#,
            br#"{"lease_id":"","lg":5,"expiry_tick":100000,"gen":3}"#,
            br#"{"lease_id":"a b","lg":5,"expiry_tick":100000,"gen":3}"#,
            br#"{"lease_id":"L1","lg":0,"expiry_tick":100000,"gen":3}"#,
            br#"{"lease_id":"L1","lg":9007199254740992,"expiry_tick":100000,"gen":3}"#,
            br#"{"lease_id":"L1","lg":5,"expiry_tick":9007199254740992,"gen":3}"#,
            br#"{"lease_id":"L1","lg":"5","expiry_tick":100000,"gen":3}"#,
            br#"{"lease_id":"L1","lg":5,"expiry_tick":-1,"gen":3}"#,
            b"not json",
            // gen (A3 r3): the old three-key shape, out of range, not an integer, duplicated
            br#"{"lease_id":"L1","lg":5,"expiry_tick":100000}"#,
            br#"{"lease_id":"L1","lg":5,"expiry_tick":100000,"gen":0}"#,
            br#"{"lease_id":"L1","lg":5,"expiry_tick":100000,"gen":9007199254740992}"#,
            br#"{"lease_id":"L1","lg":5,"expiry_tick":100000,"gen":"3"}"#,
            br#"{"lease_id":"L1","lg":5,"expiry_tick":100000,"gen":-1}"#,
            br#"{"lease_id":"L1","lg":5,"expiry_tick":100000,"gen":1.5}"#,
            br#"{"lease_id":"L1","lg":5,"expiry_tick":100000,"gen":null}"#,
            br#"{"lease_id":"L1","lg":5,"expiry_tick":100000,"gen":3,"gen":3}"#,
        ] {
            let (mut t, lease) = setup();
            write(&lease.join(A), bad, 0o644);
            assert_eq!(code(&mut t), 78, "{}", String::from_utf8_lossy(bad));
        }
        let long = format!(r#"{{"lease_id":"{}","lg":5,"expiry_tick":100000,"gen":3}}"#, "x".repeat(65));
        let (mut t, lease) = setup();
        write(&lease.join(A), long.as_bytes(), 0o644);
        assert_eq!(code(&mut t), 78, "a 65-character lease id");
        write(&lease.join(A), &vec![b' '; 5000], 0o644);
        assert_eq!(code(&mut t), 66, "oversize");
    }

    #[test]
    fn the_records_gen_is_range_checked_and_never_changes_an_outcome() {
        // Its bounds pass.
        for g in ["1", "9007199254740991"] {
            let (mut t, lease) = setup();
            write(&lease.join(A), format!(r#"{{"lease_id":"L1","lg":5,"expiry_tick":100000,"gen":{g},"sg":0}}"#).as_bytes(), 0o644);
            assert_eq!(code(&mut t), 0, "gen {g}");
        }
        // The same record with each of two gens: the same outcome, passing, spent and expired alike.
        for gen in [1u64, 7] {
            let rec = format!(r#"{{"lease_id":"L1","lg":5,"expiry_tick":100000,"gen":{gen},"sg":0}}"#);
            let (mut t, lease) = setup();
            write(&lease.join(A), rec.as_bytes(), 0o644);
            assert_eq!(code(&mut t), 0, "passing, gen {gen}");
            write(&lease.join(format!("{A}.spent")), b"5\n", 0o644);
            assert_eq!(code(&mut t), 78, "spent, gen {gen}");
            let (mut t, lease) = setup();
            write(&lease.join(A), rec.as_bytes(), 0o644);
            t.now = (70, 0); // 70 000 ms: past the effective end, 100 000 - 30 000
            assert_eq!(code(&mut t), 78, "expired, gen {gen}");
        }
    }

    #[test]
    fn tombstone_grammar_and_range() {
        assert_eq!(parse_tombstone(b"0\n"), Some(0));
        assert_eq!(parse_tombstone(b"9007199254740991\n"), Some(MAX_SAFE));
        for bad in [&b"9007199254740992\n"[..], b"10000000000000000\n", b"01\n", b"1", b"\n", b"1\n\n", b"a\n", b" 1\n", b"-1\n"] {
            assert_eq!(parse_tombstone(bad), None, "{:?}", String::from_utf8_lossy(bad));
        }
        let (mut t, lease) = setup();
        write(&lease.join(format!("{A}.spent")), b"9007199254740991\n", 0o644);
        assert_eq!(code(&mut t), 78, "the largest tombstone is refused against any lg");
        write(&lease.join(format!("{A}.spent")), b"07\n", 0o644);
        assert_eq!(code(&mut t), 78, "malformed");
    }

    #[test]
    fn symlinks_are_refused_and_never_followed() {
        for which in ["record", "tombstone", "lock", "dir"] {
            let (mut t, lease) = setup();
            let target = t.top.join("elsewhere");
            match which {
                "record" => { fs::rename(lease.join(A), &target).unwrap(); symlink(&target, lease.join(A)).unwrap(); }
                "tombstone" => { write(&target, b"0\n", 0o644); symlink(&target, lease.join(format!("{A}.spent"))).unwrap(); }
                "lock" => { write(&target, b"", 0o600); symlink(&target, lease.join(format!("{A}.lock"))).unwrap(); }
                _ => { fs::rename(&lease, &target).unwrap(); symlink(&target, &lease).unwrap(); }
            }
            assert_eq!(code(&mut t), 66, "{which}");
        }
    }

    #[test]
    fn file_trust_owner_mode_and_acl_are_66() {
        let names = |a: &str| a.to_string();
        // owner (a non-root owner, through the test layer)
        for name in ["/", "run", "sagebrush", "lease", A, &format!("{A}.spent"), &format!("{A}.lock")] {
            let (mut t, lease) = setup();
            write(&lease.join(format!("{A}.spent")), b"0\n", 0o644);
            t.foreign.insert(names(name));
            assert_eq!(code(&mut t), 66, "foreign {name}");
        }
        // a root-owned directory or ancestor whose group isn't root (A1: root:root)
        for name in ["/", "run", "sagebrush", "lease"] {
            let (mut t, _) = setup();
            t.foreign_group.insert(names(name));
            assert_eq!(code(&mut t), 66, "group of {name}");
        }
        // group or other write on a directory or an ancestor
        for (rel, mode) in [("", 0o775), ("run", 0o757), ("run/sagebrush", 0o775), ("run/sagebrush/lease", 0o777), ("run/sagebrush/lease", 0o1777)] {
            let (mut t, _) = setup();
            fs::set_permissions(t.top.join(rel), fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(code(&mut t), 66, "{rel} {mode:o}");
        }
        // an access or default ACL on a directory or an ancestor
        for name in ["/", "run", "sagebrush", "lease"] {
            for default in [false, true] {
                let (mut t, _) = setup();
                if default { t.default.insert(names(name)); } else { t.access.insert(names(name)); }
                assert_eq!(code(&mut t), 66, "{name} default={default}");
            }
        }
        // a writable record or tombstone, or one with an access ACL
        for file in [A.to_string(), format!("{A}.spent")] {
            for mode in [0o664, 0o646, 0o666] {
                let (mut t, lease) = setup();
                write(&lease.join(format!("{A}.spent")), b"0\n", 0o644);
                fs::set_permissions(lease.join(&file), fs::Permissions::from_mode(mode)).unwrap();
                assert_eq!(code(&mut t), 66, "{file} {mode:o}");
            }
            let (mut t, lease) = setup();
            write(&lease.join(format!("{A}.spent")), b"0\n", 0o644);
            t.access.insert(file.clone());
            assert_eq!(code(&mut t), 66, "{file} acl");
        }
        // the lock: exactly 0600, no access ACL
        for mode in [0o644, 0o660, 0o606, 0o400, 0o4600] {
            let (mut t, lease) = setup();
            write(&lease.join(format!("{A}.lock")), b"", mode);
            assert_eq!(code(&mut t), 66, "lock {mode:o}");
        }
        let (mut t, _) = setup();
        t.access.insert(format!("{A}.lock"));
        assert_eq!(code(&mut t), 66, "lock acl");
    }

    #[test]
    fn the_effective_end_with_checked_arithmetic() {
        // expiry 0, 29 999 and 30 000 refuse at any now; 30 001 passes only at now 0.
        for e in [0, 29_999, 30_000] {
            for now in [0, 1, u64::MAX] {
                assert!(!current(0, 1, e, now), "{e} {now}");
            }
        }
        assert!(current(0, 1, 30_001, 0));
        assert!(!current(0, 1, 30_001, 1));
        // exactly at the effective end refuses; one ms before passes
        assert!(!current(0, 1, 100_000, 70_000));
        assert!(current(0, 1, 100_000, 69_999));
        // the extremes
        assert!(current(0, MAX_SAFE, MAX_SAFE, 0));
        assert!(current(MAX_SAFE - 1, MAX_SAFE, MAX_SAFE, MAX_SAFE - MARGIN_MS - 1));
        assert!(!current(MAX_SAFE, MAX_SAFE, MAX_SAFE, 0));
        assert!(current(0, 1, MAX_SAFE, 0));
        // through the file: now exactly at the end, and 1 ms before
        let (mut t, _) = setup();
        t.now = (70, 0);
        assert_eq!(code(&mut t), 78);
        t.now = (69, 999_000_000);
        assert_eq!(code(&mut t), 0);
        t.now = (69, 999_000_001);
        assert_eq!(code(&mut t), 78, "1 ns past 69 999 ms rounds up to the end");
    }

    #[test]
    fn the_clock_rounds_up_and_refuses_out_of_range() {
        assert_eq!(now_ms(0, 0), Some(0));
        assert_eq!(now_ms(0, 1), Some(1));
        assert_eq!(now_ms(0, 999_999), Some(1));
        assert_eq!(now_ms(0, 1_000_000), Some(1));
        assert_eq!(now_ms(0, 1_000_001), Some(2));
        assert_eq!(now_ms(7, 999_999_999), Some(8000), "rolls into the next second");
        assert_eq!(now_ms(-1, 0), None);
        assert_eq!(now_ms(0, -1), None);
        assert_eq!(now_ms(0, 1_000_000_000), None);
        assert_eq!(now_ms(i64::MAX, 0), None, "overflow refuses");
        let (mut t, _) = setup();
        t.now = (i64::MAX, 0);
        assert_eq!(code(&mut t), 78);
    }

    #[test]
    fn the_shared_lock_waits_bounded_for_an_exclusive_holder_and_coexists_with_shared_ones() {
        let (mut t, lease) = setup();
        let path = lease.join(format!("{A}.lock"));
        write(&path, b"", 0o600);
        // an exclusive holder (another open file description): bounded wait, then 78
        let x = fs::File::open(&path).unwrap();
        x.lock().unwrap();
        assert_eq!(code(&mut t), 78);
        assert_eq!(t.sleeps, 5, "50 ms in 10 ms polls, then refused");
        drop(x);
        // shared holders don't block it
        let s1 = fs::File::open(&path).unwrap();
        s1.lock_shared().unwrap();
        let s2 = fs::File::open(&path).unwrap();
        s2.lock_shared().unwrap();
        assert_eq!(code(&mut t), 0);
        drop((s1, s2));
        // an exclusive holder that releases within the bound: it passes
        let x = std::cell::RefCell::new(Some(fs::File::open(&path).unwrap()));
        x.borrow().as_ref().unwrap().lock().unwrap();
        let shared = std::rc::Rc::new(x);
        let h = shared.clone();
        t.sleeps = 0;
        t.hook = Some(Box::new(move |n| if n == 2 { h.borrow_mut().take(); }));
        assert_eq!(code(&mut t), 0);
        assert_eq!(t.sleeps, 2);
    }

    /// Set a real POSIX ACL xattr (python3's os.setxattr: no unsafe code and no setfacl needed). The ACL names one
    /// extra user with no rights, and its mask and the group and other entries are empty, so the file's mode bits stay
    /// as they were (`user_obj` = the owner's rights): only the ACL itself differs. False when the filesystem or the
    /// host can't set one (ENOTSUP, or no python3): the caller then says it fell back.
    fn set_real_acl(p: &Path, default: bool, user_obj: u16) -> bool {
        let entries: [(u16, u16, u32); 5] = [(0x01, user_obj, u32::MAX), (0x02, 0, 65534), (0x04, 0, u32::MAX), (0x10, 0, u32::MAX), (0x20, 0, u32::MAX)];
        let mut blob = 2u32.to_le_bytes().to_vec();
        for (tag, perm, id) in entries {
            blob.extend(tag.to_le_bytes());
            blob.extend(perm.to_le_bytes());
            blob.extend(id.to_le_bytes());
        }
        let hex: String = blob.iter().map(|b| format!("{b:02x}")).collect();
        let name = if default { "system.posix_acl_default" } else { "system.posix_acl_access" };
        std::process::Command::new("python3")
            .args(["-c", "import os,sys; os.setxattr(sys.argv[1], sys.argv[2], bytes.fromhex(sys.argv[3]))"])
            .arg(p).arg(name).arg(hex)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    #[test]
    fn real_acls_through_the_real_adapter() {
        // RealLease.acls itself: none, an access ACL on a file, a default ACL on a directory.
        let (t, lease) = setup();
        let f = lease.join("probe");
        write(&f, b"", 0o600);
        let open = |p: &Path| -> OwnedFd { fs::File::open(p).unwrap().into() };
        assert_eq!(RealLease.acls(&open(&f)).unwrap(), (false, false));
        assert_eq!(RealLease.acls(&open(&lease)).unwrap(), (false, false));
        if !set_real_acl(&f, false, 6) {
            eprintln!("fell back: this filesystem (or host) can't set a real POSIX ACL; the test-layer ACL rows still run");
            return;
        }
        assert_eq!(fs::metadata(&f).unwrap().permissions().mode() & 0o7777, 0o600, "the mode is unchanged");
        assert_eq!(RealLease.acls(&open(&f)).unwrap(), (true, false));
        assert!(set_real_acl(&lease, true, 7));
        assert_eq!(RealLease.acls(&open(&lease)).unwrap(), (false, true));
        drop(t);
        // End to end, with no test-layer ACL: a real ACL on the record, the tombstone, the lock, the lease directory
        // (access or default) or an ancestor refuses with 66; the same tree without it passes.
        for (which, default) in [("record", false), ("tombstone", false), ("lock", false), ("lease", false), ("lease", true), ("sagebrush", true)] {
            let (mut t, lease) = setup();
            write(&lease.join(format!("{A}.spent")), b"0\n", 0o600);
            write(&lease.join(format!("{A}.lock")), b"", 0o600);
            fs::set_permissions(lease.join(A), fs::Permissions::from_mode(0o600)).unwrap();
            assert_eq!(code(&mut t), 0, "{which}: control");
            let (p, user_obj) = match which {
                "record" => (lease.join(A), 6),
                "tombstone" => (lease.join(format!("{A}.spent")), 6),
                "lock" => (lease.join(format!("{A}.lock")), 6),
                "lease" => (lease.clone(), 7),
                _ => (t.top.join("run/sagebrush"), 7),
            };
            let before = fs::metadata(&p).unwrap().permissions().mode() & 0o7777;
            assert!(set_real_acl(&p, default, user_obj), "{which}");
            if !default {
                // an access ACL's mask becomes the group bits: with these entries, the mode loses only group/other bits
                assert_eq!(fs::metadata(&p).unwrap().permissions().mode() & 0o7777 & !0o077, before & !0o077, "{which}");
            }
            assert_eq!(code(&mut t), 66, "{which} default={default}");
        }
    }

    #[test]
    fn the_real_clock_is_boottime_not_the_wall_clock() {
        let up = fs::read_to_string("/proc/uptime").unwrap();
        let secs: f64 = up.split_whitespace().next().unwrap().parse().unwrap();
        let (s, ns) = RealLease.boottime().unwrap();
        let ours = s as f64 + ns as f64 / 1e9;
        assert!((ours - secs).abs() < 2.0, "{ours} vs /proc/uptime {secs}");
    }

    #[test]
    fn the_suspend_gate_must_be_open_at_the_records_sg() {
        let sleep = |gen: u64, phase: &str| format!(r#"{{"gen":{gen},"phase":"{phase}","pre_ok":true,"pre_at":0}}"#);
        let reopen = |gen: u64| format!(r#"{{"gen":{gen}}}"#);
        let rec = |sg: u64| format!(r#"{{"lease_id":"L1","lg":5,"expiry_tick":100000,"gen":3,"sg":{sg}}}"#);
        // No gate files: open at 0, a record at sg 0 passes; one at sg 2 doesn't.
        let (mut t, lease) = setup();
        assert_eq!(code(&mut t), 0, "both absent, sg 0");
        write(&lease.join(A), rec(2).as_bytes(), 0o644);
        assert_eq!(code(&mut t), 78, "both absent, sg 2");
        // Open at 2: sg 2 passes, sg 0 (a lease from before the suspend) doesn't.
        write(&lease.join("sleep"), sleep(2, "post").as_bytes(), 0o644);
        write(&lease.join("reopen"), reopen(2).as_bytes(), 0o644);
        assert_eq!(code(&mut t), 0, "open at 2, sg 2");
        write(&lease.join(A), rec(0).as_bytes(), 0o644);
        assert_eq!(code(&mut t), 78, "open at 2, sg 0");
        // Closed: a PRE (sleep at pre), an unacknowledged post, a one-sided file, a reopen ahead.
        write(&lease.join(A), rec(3).as_bytes(), 0o644);
        for (s, r, why) in [(sleep(3, "pre"), Some(reopen(2)), "pre"), (sleep(3, "post"), Some(reopen(2)), "unacknowledged"),
                            (sleep(3, "post"), None, "one-sided"), (sleep(3, "post"), Some(reopen(4)), "reopen ahead")] {
            write(&lease.join("sleep"), s.as_bytes(), 0o644);
            let _ = fs::remove_file(lease.join("reopen"));
            if let Some(r) = r { write(&lease.join("reopen"), r.as_bytes(), 0o644); }
            assert_eq!(code(&mut t), 78, "{why}");
        }
        // The terminal generation never opens, even acknowledged.
        write(&lease.join(A), rec(MAX_SAFE).as_bytes(), 0o644);
        write(&lease.join("sleep"), sleep(MAX_SAFE, "post").as_bytes(), 0o644);
        write(&lease.join("reopen"), reopen(MAX_SAFE).as_bytes(), 0o644);
        assert_eq!(code(&mut t), 78, "terminal");
        // An untrusted gate file (group-writable) refuses through the file-trust path.
        write(&lease.join(A), rec(2).as_bytes(), 0o644);
        write(&lease.join("sleep"), sleep(2, "post").as_bytes(), 0o664);
        write(&lease.join("reopen"), reopen(2).as_bytes(), 0o644);
        assert_ne!(code(&mut t), 0, "group-writable sleep");
    }

    #[test]
    fn cross_language_fixture_rust_column() {
        let fx = json::parse_with(include_bytes!("../../test/fixtures/host/lease-files.json"), 1024).unwrap();
        let get = |k: &str| match &fx {
            json::Value::Obj(f) => f.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone()).unwrap(),
            _ => unreachable!(),
        };
        for row in get("tombstones").arr().unwrap() {
            let f = row.exact(&["text", "js", "rust"]).unwrap();
            let want = match f[2] { json::Value::Null => None, v => Some(v.int().unwrap()) };
            assert_eq!(parse_tombstone(f[0].str().unwrap().as_bytes()), want, "{:?}", f[0]);
        }
        for row in get("records").arr().unwrap() {
            let f = row.exact(&["text", "js", "rust"]).unwrap();
            let want = matches!(f[2], json::Value::Bool(true));
            assert_eq!(parse_record(f[0].str().unwrap().as_bytes()).is_some(), want, "{:?}", f[0]);
        }
        let rows = get("gate");
        assert!(rows.arr().unwrap().len() >= 20);
        for row in rows.arr().unwrap() {
            let f = row.exact(&["name", "sleep", "reopen", "now", "js", "rust"]).unwrap();
            let text = |v: &json::Value| match v { json::Value::Null => None, v => Some(v.str().unwrap().as_bytes().to_vec()) };
            let want = match f[5] { json::Value::Null => None, v => Some(v.int().unwrap()) };
            let (s, r) = (text(f[1]), text(f[2]));
            assert_eq!(gate_of(s.as_deref(), r.as_deref(), f[3].int().unwrap()), want, "{:?}", f[0]);
        }
    }

    #[test]
    fn the_held_fd_keeps_the_shared_lock_is_cloexec_and_releases_on_close() {
        let (mut t, lease) = setup();
        let held = check(&mut t, A, 50).unwrap();
        let path = lease.join(format!("{A}.lock"));
        let other = fs::File::open(&path).unwrap();
        assert!(other.try_lock().is_err(), "an exclusive try fails while the fd is open");
        use std::os::fd::AsRawFd;
        let info = fs::read_to_string(format!("/proc/self/fdinfo/{}", held.0.as_raw_fd())).unwrap();
        let flags = info.lines().find_map(|l| l.strip_prefix("flags:")).map(|v| u32::from_str_radix(v.trim(), 8).unwrap()).unwrap();
        assert_ne!(flags & libc::O_CLOEXEC as u32, 0, "O_CLOEXEC: execve releases it");
        drop(held);
        // The lock belongs to the open file description. Another test thread's fork in this
        // window gives its child a copy, held until that child execs (O_CLOEXEC) or exits; so
        // the release is waited for, with a deadline, rather than read at once.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while other.try_lock().is_err() {
            assert!(std::time::Instant::now() < deadline, "released once the fd is closed");
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
}
