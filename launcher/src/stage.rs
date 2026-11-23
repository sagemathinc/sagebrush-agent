//! `stage-bind` (contract §3, §3.1): open a granted path by handle, clone it onto the agent's fresh, root-only
//! staging mountpoint, check the identity, and publish a durable record; on a failure after the mount, roll back.
//!
//! The sequence is generic over `Ops` (the handle operations it needs): `RealOps` is the syscall module, and the
//! tests run every branch against a fake handle table (contract §8), since a CI runner can't call open_tree.

use crate::args::{dirent_names, is_id, rel};
use crate::err::{err, Error, Fail, Result};
use crate::json::quote;
use crate::sys::{self, Stat};
use std::ffi::CString;
use std::io;
use std::os::fd::OwnedFd;

const BINDS: &str = "run/sagebrush/binds";
const EMPTY_CHECK_CALLS: usize = 8;
const S_IFMT: u16 = 0o170000;
const S_IFDIR: u16 = 0o040000;

pub struct Args<'a> {
    pub agent: &'a str,
    pub index: u8,
    pub mode: &'a str,
    pub path: &'a str,
}

pub fn parse<'a>(v: &[&'a str]) -> Result<Args<'a>> {
    let bad = err(Fail::Usage, "bad arguments");
    let [agent, index, mode, path, record] = v else { return Err(bad) };
    let index: u8 = match index.parse::<u8>() {
        Ok(n) if n <= 63 && index.as_bytes()[0] != b'+' && (index.len() == 1 || !index.starts_with('0')) => n,
        _ => return Err(bad),
    };
    if !is_id(agent) || !["rw", "ro"].contains(mode) || rel(path).is_none() {
        return Err(bad);
    }
    // The record is exactly the agent's binds directory's "<index>.record" (so it is derived, never taken).
    if *record != format!("/{BINDS}/{agent}/{index}.record") {
        return Err(bad);
    }
    Ok(Args { agent, index, mode, path })
}

/// How a handle is opened (all relative to a handle, never by absolute path).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Open {
    /// O_PATH
    Path,
    /// O_RDONLY | O_DIRECTORY (listable, fsync-able)
    Dir,
    /// O_PATH | O_DIRECTORY
    DirPath,
    /// O_CREAT | O_EXCL | O_WRONLY, mode 0600
    CreateExcl,
}

/// The handle operations stage-bind needs. `RealOps` maps each to one syscall wrapper in `sys`.
pub trait Ops {
    type H;
    fn root(&mut self) -> io::Result<Self::H>;
    fn open(&mut self, dir: &Self::H, rel: &str, how: Open) -> io::Result<Self::H>;
    fn stat(&mut self, h: &Self::H) -> io::Result<Stat>;
    fn getdents(&mut self, h: &Self::H, buf: &mut [u8]) -> io::Result<usize>;
    fn clone_tree(&mut self, h: &Self::H) -> io::Result<Self::H>;
    fn set_readonly(&mut self, clone: &Self::H) -> io::Result<()>;
    fn move_mount(&mut self, clone: &Self::H, onto: &Self::H) -> io::Result<()>;
    fn umount_detach(&mut self, abs_path: &str) -> io::Result<()>;
    /// Write the whole record into a just-created file and sync it (std's File: write_all, then sync_all).
    fn write_record(&mut self, file: Self::H, data: &[u8]) -> io::Result<()>;
    /// fsync a directory handle.
    fn fsync_dir(&mut self, dir: &Self::H) -> io::Result<()>;
    fn rename_noreplace(&mut self, dir: &Self::H, from: &str, to: &str) -> io::Result<()>;
    fn unlink(&mut self, dir: &Self::H, name: &str) -> io::Result<()>;
}

fn c(s: &str) -> io::Result<CString> {
    CString::new(s).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))
}

/// The real handle operations: the syscall module, nothing else.
pub struct RealOps;

impl Ops for RealOps {
    type H = OwnedFd;
    fn root(&mut self) -> io::Result<OwnedFd> {
        sys::open_root()
    }
    fn open(&mut self, dir: &OwnedFd, rel: &str, how: Open) -> io::Result<OwnedFd> {
        let (flags, mode) = match how {
            Open::Path => (libc::O_PATH, 0),
            Open::Dir => (libc::O_RDONLY | libc::O_DIRECTORY, 0),
            Open::DirPath => (libc::O_PATH | libc::O_DIRECTORY, 0),
            Open::CreateExcl => (libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY, 0o600),
        };
        sys::openat2(dir, &c(rel)?, flags, mode)
    }
    fn stat(&mut self, h: &OwnedFd) -> io::Result<Stat> {
        sys::statx(h)
    }
    fn getdents(&mut self, h: &OwnedFd, buf: &mut [u8]) -> io::Result<usize> {
        sys::getdents64(h, buf)
    }
    fn clone_tree(&mut self, h: &OwnedFd) -> io::Result<OwnedFd> {
        sys::open_tree_clone(h)
    }
    fn set_readonly(&mut self, clone: &OwnedFd) -> io::Result<()> {
        sys::mount_setattr_rdonly(clone)
    }
    fn move_mount(&mut self, clone: &OwnedFd, onto: &OwnedFd) -> io::Result<()> {
        sys::move_mount(clone, onto)
    }
    fn umount_detach(&mut self, abs_path: &str) -> io::Result<()> {
        sys::umount2_detach(&c(abs_path)?)
    }
    fn write_record(&mut self, file: OwnedFd, data: &[u8]) -> io::Result<()> {
        use std::io::Write;
        let mut f = std::fs::File::from(file); // safe: OwnedFd -> File
        f.write_all(data)?;
        f.sync_all()
    }
    fn fsync_dir(&mut self, dir: &OwnedFd) -> io::Result<()> {
        sys::fsync_dir(dir)
    }
    fn rename_noreplace(&mut self, dir: &OwnedFd, from: &str, to: &str) -> io::Result<()> {
        sys::rename_noreplace(dir, &c(from)?, &c(to)?)
    }
    fn unlink(&mut self, dir: &OwnedFd, name: &str) -> io::Result<()> {
        sys::unlinkat(dir, &c(name)?)
    }
}

fn pre(msg: &'static str) -> impl Fn(io::Error) -> Error {
    move |_| err(Fail::Preflight, msg)
}

/// The empty-directory check (contract §3, §6): getdents64 to EOF with one fixed 4 KiB buffer, at most 8 calls; any
/// entry but "." and ".." refuses.
fn is_empty_dir<O: Ops>(o: &mut O, h: &O::H) -> Result<()> {
    let mut buf = [0u8; 4096];
    for _ in 0..EMPTY_CHECK_CALLS {
        let n = o.getdents(h, &mut buf).map_err(pre("the mountpoint can't be listed"))?;
        if n == 0 {
            return Ok(());
        }
        let names = dirent_names(&buf, n).ok_or(err(Fail::Preflight, "the mountpoint can't be listed"))?;
        if names.iter().any(|nm| nm != b"." && nm != b"..") {
            return Err(err(Fail::Preflight, "the mountpoint is not empty"));
        }
    }
    Err(err(Fail::Preflight, "the mountpoint can't be listed"))
}

/// What the rollback needs to detach exactly the mount this call created (contract §3.1).
struct Recorded {
    parent: Stat,
    mountpoint: Stat,
    new_mnt: u64,
}

pub fn run(a: &Args) -> Result<()> {
    run_with(&mut RealOps, a)
}

pub fn run_with<O: Ops>(o: &mut O, a: &Args) -> Result<()> {
    let root = o.root().map_err(pre("the root can't be opened"))?;
    // 1-2. The granted path, by handle, and its identity.
    let src = o.open(&root, rel(a.path).unwrap(), Open::Path).map_err(pre("the granted path can't be opened"))?;
    let src_st = o.stat(&src).map_err(pre("the granted path can't be read"))?;
    // 3. The parent (the agent's binds directory) and the mountpoint: root-owned, 0700 directories; the mountpoint
    //    empty and not itself a mountpoint.
    let parent_rel = format!("{BINDS}/{}", a.agent);
    let mp_rel = format!("{parent_rel}/{}", a.index);
    let parent = o.open(&root, &parent_rel, Open::Dir).map_err(pre("the staging directory can't be opened"))?;
    let p_st = o.stat(&parent).map_err(pre("the staging directory can't be read"))?;
    let mp = o.open(&root, &mp_rel, Open::Dir).map_err(pre("the mountpoint can't be opened"))?;
    let m_st = o.stat(&mp).map_err(pre("the mountpoint can't be read"))?;
    for st in [&p_st, &m_st] {
        if st.mode & S_IFMT != S_IFDIR || st.uid != 0 || st.mode & 0o7777 != 0o700 {
            return Err(err(Fail::Preflight, "the staging directories aren't root-only"));
        }
    }
    if m_st.attributes & libc::STATX_ATTR_MOUNT_ROOT as u64 != 0 || m_st.mnt_id != p_st.mnt_id {
        return Err(err(Fail::Preflight, "the mountpoint is already a mount"));
    }
    is_empty_dir(o, &mp)?;
    // The final record must not exist (contract §3; RENAME_NOREPLACE stays the backstop).
    match o.open(&parent, &format!("{}.record", a.index), Open::Path) {
        Ok(_) => return Err(err(Fail::Record, "a record already exists")),
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {}
        Err(_) => return Err(err(Fail::Preflight, "the staging directory can't be read")),
    }
    // 4-6. Clone, read-only for "ro", and move it onto the mountpoint, both ends by handle.
    let clone = o.clone_tree(&src).map_err(pre("the granted path can't be cloned"))?;
    if a.mode == "ro" {
        o.set_readonly(&clone).map_err(pre("the clone can't be made read-only"))?;
    }
    o.move_mount(&clone, &mp).map_err(pre("the clone can't be mounted"))?;
    // Right after the mount: the id of the mount this call installed (contract §3.1). If even that can't be read,
    // nothing can be proven about the rollback either.
    let new_mnt = match o.open(&root, &mp_rel, Open::Path).and_then(|h| o.stat(&h)) {
        Ok(st) => st.mnt_id,
        Err(_) => return Err(err(Fail::Record, "rollback failed")),
    };
    let rec = Recorded { parent: p_st, mountpoint: m_st, new_mnt };
    // From here on, a failure rolls back what this call created.
    let mut published = false;
    match finish(o, a, &root, &parent, &mp_rel, &src_st, &mut published) {
        Ok(()) => Ok(()),
        Err(e) => rollback(o, a, &root, &parent, &mp_rel, &rec, published).map(|()| Err(e))?,
    }
}

/// 7-8. Check the staged identity, then publish the record durably.
fn finish<O: Ops>(o: &mut O, a: &Args, root: &O::H, parent: &O::H, mp_rel: &str, src_st: &Stat, published: &mut bool) -> Result<()> {
    let staged = o.open(root, mp_rel, Open::Path).map_err(pre("the staging mount can't be opened"))?;
    let st = o.stat(&staged).map_err(pre("the staging mount can't be read"))?;
    if st.dev != src_st.dev || st.ino != src_st.ino {
        return Err(err(Fail::Preflight, "the staged identity differs"));
    }
    let record = format!(
        "{{\"path\":{},\"mode\":{},\"dev\":[{},{}],\"ino\":{},\"uid\":{},\"staging\":{}}}\n",
        quote(a.path),
        quote(a.mode),
        src_st.dev.0,
        src_st.dev.1,
        src_st.ino,
        src_st.uid,
        quote(&format!("/{mp_rel}"))
    );
    let rec_fail = |_| err(Fail::Record, "the record can't be written");
    let tmp = format!("{}.record.tmp", a.index);
    let fin = format!("{}.record", a.index);
    let f = o.open(parent, &tmp, Open::CreateExcl).map_err(rec_fail)?;
    o.write_record(f, record.as_bytes()).map_err(rec_fail)?;
    o.rename_noreplace(parent, &tmp, &fin).map_err(rec_fail)?;
    *published = true;
    o.fsync_dir(parent).map_err(rec_fail)?;
    Ok(())
}

/// Contract §3.1: detach exactly the mount this call created, then remove the temp and (if published) the final
/// record, and fsync the directory. Any failure here is 70, "rollback failed".
fn rollback<O: Ops>(o: &mut O, a: &Args, root: &O::H, parent: &O::H, mp_rel: &str, r: &Recorded, published: bool) -> Result<()> {
    let failed = || err(Fail::Record, "rollback failed");
    // Re-check: the parent is the recorded one, and the mountpoint carries exactly the mount recorded right after
    // move_mount (not merely "some other mount").
    let p2 = o.open(root, &mp_rel[..mp_rel.rfind('/').unwrap()], Open::DirPath).map_err(|_| failed())?;
    let p2_st = o.stat(&p2).map_err(|_| failed())?;
    if p2_st.dev != r.parent.dev || p2_st.ino != r.parent.ino || p2_st.mnt_id != r.parent.mnt_id {
        return Err(failed());
    }
    let m2 = o.open(root, mp_rel, Open::Path).map_err(|_| failed())?;
    let now = o.stat(&m2).map_err(|_| failed())?.mnt_id;
    drop(m2);
    if now != r.new_mnt || now == r.parent.mnt_id {
        return Err(failed());
    }
    o.umount_detach(&format!("/{mp_rel}")).map_err(|_| failed())?;
    // Confirm: the mountpoint is back on the parent's mount, with its original identity.
    let m3 = o.open(root, mp_rel, Open::Path).map_err(|_| failed())?;
    let m3_st = o.stat(&m3).map_err(|_| failed())?;
    if m3_st.mnt_id != r.parent.mnt_id || m3_st.dev != r.mountpoint.dev || m3_st.ino != r.mountpoint.ino {
        return Err(failed());
    }
    match o.unlink(parent, &format!("{}.record.tmp", a.index)) {
        Ok(()) => {}
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {}
        Err(_) => return Err(failed()),
    }
    if published {
        o.unlink(parent, &format!("{}.record", a.index)).map_err(|_| failed())?;
    }
    o.fsync_dir(parent).map_err(|_| failed())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    const A: &str = "abcdefghijklmnopqrstuvwxya";

    #[test]
    fn arguments_are_closed() {
        let rec = format!("/run/sagebrush/binds/{A}/3.record");
        assert!(parse(&[A, "3", "rw", "/data/x", &rec]).is_ok());
        for (i, m, p, r) in [
            ("64", "rw", "/data/x", rec.clone()),
            ("03", "rw", "/data/x", rec.clone()),
            ("+3", "rw", "/data/x", rec.clone()),
            ("3", "rx", "/data/x", rec.clone()),
            ("3", "rw", "/data/x/", rec.clone()),
            ("3", "rw", "/data/x", format!("/run/sagebrush/binds/{A}/4.record")),
            ("3", "rw", "/data/x", format!("/tmp/{A}/3.record")),
        ] {
            assert_eq!(parse(&[A, i, m, p, &r]).err().map(|e| e.fail), Some(Fail::Usage), "{i} {m} {p} {r}");
        }
        assert!(parse(&["not-an-id", "3", "rw", "/data/x", &rec]).is_err());
    }

    // ---- the fake handle table (contract §8)

    fn st(dev: u32, ino: u64, uid: u32, mode: u16, mnt: u64) -> Stat {
        Stat { mask: 0, attributes: 0, attributes_mask: 0, dev: (dev, 0), ino, uid, mode, mnt_id: mnt }
    }

    /// Paths are keyed relative to the root (no leading '/'). A node is the stat a handle on it reports; `mounts` maps
    /// a mountpoint path to the mounted tree's stat (what it reports while mounted). Faults: `fail` names an op that
    /// errors; the lies change what a later stat reports.
    #[derive(Default)]
    struct Fake {
        nodes: BTreeMap<String, Stat>,
        entries: BTreeMap<String, Vec<&'static str>>,
        mounts: BTreeMap<String, Stat>,
        files: BTreeMap<String, Vec<u8>>,
        next_mnt: u64,
        fail: Option<&'static str>,
        identity_lie: bool,
        umount_noop: bool,
        remounted_by_someone: bool,
        mounted_stats: usize,
        log: Vec<String>,
    }

    #[derive(Clone)]
    enum H {
        Root,
        Node(String),
        Clone(Stat, bool),
        File(String),
    }

    impl Fake {
        fn host(mp_mode: u16) -> Fake {
            let mut f = Fake { next_mnt: 100, ..Default::default() };
            f.nodes.insert("data/x".into(), st(8, 42, 1000, 0o040755, 1));
            f.nodes.insert(format!("{BINDS}/{A}"), st(9, 500, 0, 0o040700, 2));
            f.nodes.insert(format!("{BINDS}/{A}/0"), st(9, 501, 0, mp_mode, 2));
            f.entries.insert(format!("{BINDS}/{A}/0"), vec![".", ".."]);
            f
        }
        fn guard(&mut self, op: &'static str) -> io::Result<()> {
            self.log.push(op.into());
            if self.fail == Some(op) { Err(io::Error::from_raw_os_error(libc::EIO)) } else { Ok(()) }
        }
        fn path(&self, dir: &H, rel: &str) -> String {
            match dir {
                H::Root => rel.to_string(),
                H::Node(p) => format!("{p}/{rel}"),
                _ => unreachable!(),
            }
        }
    }

    impl Ops for Fake {
        type H = H;
        fn root(&mut self) -> io::Result<H> {
            self.guard("root").map(|_| H::Root)
        }
        fn open(&mut self, dir: &H, rel: &str, how: Open) -> io::Result<H> {
            self.guard("open")?;
            let p = self.path(dir, rel);
            if how == Open::CreateExcl {
                self.guard("create")?;
                if self.files.contains_key(&p) {
                    return Err(io::Error::from_raw_os_error(libc::EEXIST));
                }
                self.files.insert(p.clone(), Vec::new());
                return Ok(H::File(p));
            }
            if self.nodes.contains_key(&p) || self.mounts.contains_key(&p) { Ok(H::Node(p)) } else { Err(io::Error::from_raw_os_error(libc::ENOENT)) }
        }
        fn stat(&mut self, h: &H) -> io::Result<Stat> {
            self.guard("stat")?;
            match h {
                H::Node(p) => {
                    if let Some(m) = self.mounts.get(p) {
                        let mut s = *m;
                        self.mounted_stats += 1;
                        if self.identity_lie {
                            s.ino += 1000;
                        }
                        // Stat 1 records the installed mount id, stat 2 is the identity check; from stat 3 (the
                        // rollback's check) on, "someone else" has mounted over it.
                        if self.remounted_by_someone && self.mounted_stats >= 3 {
                            s.mnt_id += 7;
                        }
                        return Ok(s);
                    }
                    Ok(self.nodes[p])
                }
                _ => Err(io::Error::from_raw_os_error(libc::EBADF)),
            }
        }
        fn getdents(&mut self, h: &H, buf: &mut [u8]) -> io::Result<usize> {
            self.guard("getdents")?;
            let H::Node(p) = h else { return Err(io::Error::from_raw_os_error(libc::ENOTDIR)) };
            let names = self.entries.insert(p.clone(), vec![]).unwrap_or_default(); // listed once, then EOF
            let mut off = 0;
            for n in names {
                let reclen = 24usize;
                buf[off + 16..off + 18].copy_from_slice(&(reclen as u16).to_ne_bytes());
                buf[off + 19..off + 19 + n.len()].copy_from_slice(n.as_bytes());
                buf[off + 19 + n.len()] = 0;
                off += reclen;
            }
            Ok(off)
        }
        fn clone_tree(&mut self, h: &H) -> io::Result<H> {
            self.guard("clone")?;
            let s = self.stat(h)?;
            Ok(H::Clone(s, false))
        }
        fn set_readonly(&mut self, _c: &H) -> io::Result<()> {
            self.guard("setattr")
        }
        fn move_mount(&mut self, clone: &H, onto: &H) -> io::Result<()> {
            self.guard("move_mount")?;
            let (H::Clone(s, _), H::Node(p)) = (clone, onto) else { unreachable!() };
            let mut m = *s;
            m.mnt_id = self.next_mnt;
            self.next_mnt += 1;
            self.mounts.insert(p.clone(), m);
            Ok(())
        }
        fn umount_detach(&mut self, abs: &str) -> io::Result<()> {
            self.guard("umount")?;
            if !self.umount_noop {
                self.mounts.remove(abs.trim_start_matches('/'));
            }
            Ok(())
        }
        fn write_record(&mut self, h: H, buf: &[u8]) -> io::Result<()> {
            self.guard("write")?;
            let H::File(p) = h else { unreachable!() };
            self.files.get_mut(&p).unwrap().extend_from_slice(buf);
            self.guard("fsync_file")
        }
        fn fsync_dir(&mut self, _h: &H) -> io::Result<()> {
            self.guard("fsync_dir")
        }
        fn rename_noreplace(&mut self, dir: &H, from: &str, to: &str) -> io::Result<()> {
            self.guard("rename")?;
            let (f, t) = (self.path(dir, from), self.path(dir, to));
            if self.files.contains_key(&t) {
                return Err(io::Error::from_raw_os_error(libc::EEXIST));
            }
            let v = self.files.remove(&f).ok_or(io::Error::from_raw_os_error(libc::ENOENT))?;
            self.files.insert(t, v);
            Ok(())
        }
        fn unlink(&mut self, dir: &H, name: &str) -> io::Result<()> {
            self.guard("unlink")?;
            let p = self.path(dir, name);
            self.files.remove(&p).map(|_| ()).ok_or(io::Error::from_raw_os_error(libc::ENOENT))
        }
    }

    fn args() -> Args<'static> {
        Args { agent: A, index: 0, mode: "rw", path: "/data/x" }
    }
    const MP: &str = "run/sagebrush/binds/abcdefghijklmnopqrstuvwxya/0";
    const REC: &str = "run/sagebrush/binds/abcdefghijklmnopqrstuvwxya/0.record";
    const TMP: &str = "run/sagebrush/binds/abcdefghijklmnopqrstuvwxya/0.record.tmp";

    fn code(r: Result<()>) -> Option<(Fail, &'static str)> {
        r.err().map(|e| (e.fail, e.msg))
    }

    #[test]
    fn the_happy_path_mounts_and_publishes_the_record() {
        let mut f = Fake::host(0o040700);
        assert!(run_with(&mut f, &args()).is_ok());
        assert_eq!(f.mounts[MP].ino, 42);
        let rec = String::from_utf8(f.files[REC].clone()).unwrap();
        assert_eq!(rec, format!("{{\"path\":\"/data/x\",\"mode\":\"rw\",\"dev\":[8,0],\"ino\":42,\"uid\":1000,\"staging\":\"/{MP}\"}}\n"));
        assert!(!f.files.contains_key(TMP));
        let i = |op: &str| f.log.iter().position(|x| x == op).unwrap();
        assert!(i("fsync_file") < i("rename") && i("rename") < i("fsync_dir"), "fsync the file, rename, fsync the directory");
        let ro = { let mut g = Fake::host(0o040700); run_with(&mut g, &Args { mode: "ro", ..args() }).unwrap(); g.log };
        assert!(ro.contains(&"setattr".to_string()), "ro is made read-only");
    }

    #[test]
    fn refusals_before_any_mount_are_66_and_mount_nothing() {
        // Not root-only.
        let mut f = Fake::host(0o040755);
        assert_eq!(code(run_with(&mut f, &args())), Some((Fail::Preflight, "the staging directories aren't root-only")));
        // Not empty.
        let mut f = Fake::host(0o040700);
        f.entries.insert(MP.into(), vec![".", "..", "left"]);
        assert_eq!(code(run_with(&mut f, &args())), Some((Fail::Preflight, "the mountpoint is not empty")));
        // Already a mount (its mount id differs from its parent's).
        let mut f = Fake::host(0o040700);
        f.nodes.get_mut(MP).unwrap().mnt_id = 77;
        assert_eq!(code(run_with(&mut f, &args())), Some((Fail::Preflight, "the mountpoint is already a mount")));
        // Already a mount (STATX_ATTR_MOUNT_ROOT).
        let mut f = Fake::host(0o040700);
        f.nodes.get_mut(MP).unwrap().attributes = libc::STATX_ATTR_MOUNT_ROOT as u64;
        assert_eq!(code(run_with(&mut f, &args())), Some((Fail::Preflight, "the mountpoint is already a mount")));
        // Any handle operation failing before the mount.
        for op in ["root", "open", "stat", "getdents", "clone", "move_mount"] {
            let mut f = Fake::host(0o040700);
            f.fail = Some(op);
            assert_eq!(code(run_with(&mut f, &args())).map(|c| c.0), Some(Fail::Preflight), "{op}");
            assert!(f.mounts.is_empty(), "{op}: nothing mounted");
        }
        let mut f = Fake::host(0o040700);
        f.fail = Some("setattr");
        assert_eq!(code(run_with(&mut f, &Args { mode: "ro", ..args() })).map(|c| c.0), Some(Fail::Preflight));
        assert!(f.mounts.is_empty());
    }

    #[test]
    fn a_staged_identity_mismatch_rolls_back_and_is_66() {
        let mut f = Fake::host(0o040700);
        f.identity_lie = true;
        assert_eq!(code(run_with(&mut f, &args())), Some((Fail::Preflight, "the staged identity differs")));
        assert!(f.mounts.is_empty(), "detached");
        assert!(f.files.is_empty(), "no record");
    }

    #[test]
    fn a_record_failure_rolls_back_and_is_70() {
        for op in ["create", "write", "fsync_file", "rename"] {
            let mut f = Fake::host(0o040700);
            f.fail = Some(op);
            assert_eq!(code(run_with(&mut f, &args())), Some((Fail::Record, "the record can't be written")), "{op}");
            assert!(f.mounts.is_empty(), "{op}: detached");
            assert!(!f.files.contains_key(TMP) && !f.files.contains_key(REC), "{op}: no record left");
        }
        // An existing final record: refused BEFORE any mount (70), and it stays as it was.
        let mut f = Fake::host(0o040700);
        f.nodes.insert(REC.into(), st(9, 502, 0, 0o100600, 2));
        assert_eq!(code(run_with(&mut f, &args())), Some((Fail::Record, "a record already exists")));
        assert!(f.mounts.is_empty() && !f.log.iter().any(|x| x == "move_mount"), "nothing mounted");
        // RENAME_NOREPLACE is the backstop if one appears after the check: 70, rolled back, never replaced.
        let mut f = Fake::host(0o040700);
        f.files.insert(REC.into(), b"old".to_vec());
        assert_eq!(code(run_with(&mut f, &args())), Some((Fail::Record, "the record can't be written")));
        assert!(f.mounts.is_empty());
        assert_eq!(f.files[REC], b"old".to_vec(), "never replaced");
    }

    #[test]
    fn a_failure_after_publication_also_removes_the_published_record() {
        // The directory fsync after the rename fails: the record WAS published, and the rollback unlinks it.
        let mut f = Fake::host(0o040700);
        let mut fsyncs = 0;
        // Fail only the first directory fsync (the one after rename); the rollback's own fsync must succeed.
        struct Once<'a>(&'a mut Fake, &'a mut i32);
        impl Ops for Once<'_> {
            type H = H;
            fn root(&mut self) -> io::Result<H> { self.0.root() }
            fn open(&mut self, d: &H, r: &str, h: Open) -> io::Result<H> { self.0.open(d, r, h) }
            fn stat(&mut self, h: &H) -> io::Result<Stat> { self.0.stat(h) }
            fn getdents(&mut self, h: &H, b: &mut [u8]) -> io::Result<usize> { self.0.getdents(h, b) }
            fn clone_tree(&mut self, h: &H) -> io::Result<H> { self.0.clone_tree(h) }
            fn set_readonly(&mut self, c: &H) -> io::Result<()> { self.0.set_readonly(c) }
            fn move_mount(&mut self, c: &H, o: &H) -> io::Result<()> { self.0.move_mount(c, o) }
            fn umount_detach(&mut self, a: &str) -> io::Result<()> { self.0.umount_detach(a) }
            fn write_record(&mut self, h: H, b: &[u8]) -> io::Result<()> { self.0.write_record(h, b) }
            fn fsync_dir(&mut self, h: &H) -> io::Result<()> {
                *self.1 += 1;
                if *self.1 == 1 { return Err(io::Error::from_raw_os_error(libc::EIO)); }
                self.0.fsync_dir(h)
            }
            fn rename_noreplace(&mut self, d: &H, a: &str, b: &str) -> io::Result<()> { self.0.rename_noreplace(d, a, b) }
            fn unlink(&mut self, d: &H, n: &str) -> io::Result<()> { self.0.unlink(d, n) }
        }
        assert_eq!(code(run_with(&mut Once(&mut f, &mut fsyncs), &args())), Some((Fail::Record, "the record can't be written")));
        assert!(!f.files.contains_key(REC), "the published record is removed");
        assert!(f.mounts.is_empty());
        assert_eq!(fsyncs, 2, "the rollback fsynced the directory again");
    }

    #[test]
    fn a_rollback_that_cant_prove_its_mount_is_70_and_never_unmounts_another() {
        // Someone else's mount now sits on the mountpoint: its id is not the one recorded right after move_mount.
        let mut f = Fake::host(0o040700);
        f.identity_lie = true; // forces a rollback
        f.remounted_by_someone = true;
        assert_eq!(code(run_with(&mut f, &args())), Some((Fail::Record, "rollback failed")));
        assert!(!f.log.iter().any(|x| x == "umount"), "no umount of a mount we can't prove is ours");
    }

    #[test]
    fn a_failed_or_unconfirmed_detach_is_70() {
        let mut f = Fake::host(0o040700);
        f.identity_lie = true;
        f.fail = Some("umount");
        assert_eq!(code(run_with(&mut f, &args())), Some((Fail::Record, "rollback failed")));
        let mut f = Fake::host(0o040700);
        f.identity_lie = true;
        f.umount_noop = true; // the detach "succeeds" but the mount is still there
        assert_eq!(code(run_with(&mut f, &args())), Some((Fail::Record, "rollback failed")));
        let mut f = Fake::host(0o040700);
        f.identity_lie = true;
        f.fail = Some("unlink");
        // ENOENT on the temp is tolerated, any other unlink error is not.
        assert_eq!(code(run_with(&mut f, &args())), Some((Fail::Record, "rollback failed")));
    }
}
