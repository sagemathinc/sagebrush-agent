//! Launcher contract amendment A1 (deprovision): `identify`, `inspect-home`, `archive-home` and `remove-tree`. Root
//! only, run by the supervisor outside any unit. Every object is reached by `openat2` one component at a time beneath
//! an opened parent, with RESOLVE_NO_XDEV, and checked by its opened descriptor (identity, mount, generation, project).
//!
//! The logic is generic over `Ops` (the handle operations): `RealOps` is the syscall module, and the tests run every
//! branch against a fake tree with mounts, links and fault hooks (A1 §7).

use crate::args::{dirent_names, is_id, is_path};
use crate::err::{err, Error, Fail, Result};
use crate::json::{self, Value};
use crate::sys::{self, Ident};
use std::ffi::CString;
use std::io;
use std::os::fd::OwnedFd;

pub const MAX_OBJECTS: usize = 2_000_000;
pub const MAX_DEPTH: usize = 256;
pub const MAX_GENERATIONS: usize = 16;
const MAX_EXPECT: usize = 64 * 1024;
const MAX_CURRENT: u64 = 64;
const SRV: &str = "/srv/sagebrush";

const S_IFMT: u16 = 0o170000;
const S_IFDIR: u16 = 0o040000;
const S_IFREG: u16 = 0o100000;
const S_IFLNK: u16 = 0o120000;

/// The compiled anchor table (A1 §1): an anchor path and the form of the one name beneath it.
pub const ANCHORS: [(&str, &str); 9] = [
    ("/run/sagebrush/binds", ""),
    ("/run/sagebrush/broker", ""),
    ("/var/lib/sagebrush/creds", ""),
    ("/var/lib/sagebrush/contract", ".json"),
    ("/var/lib/sagebrush/resolv", ".conf"),
    ("/var/lib/sagebrush/managed", ""),
    ("/srv/sagebrush/archive", ""),
    ("/srv/sagebrush/archive-config", ""),
    ("/var/lib/sagebrush/secrets", ""),
];

/// Whether `name` is `<id><suffix>` for the anchor's suffix.
pub fn anchor_name_ok(anchor: &str, name: &str) -> bool {
    ANCHORS.iter().any(|(a, suffix)| *a == anchor && name.strip_suffix(suffix).is_some_and(is_id))
}

/// How a child is opened beneath its parent (always with RESOLVE_NO_XDEV).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum At {
    /// O_PATH: identity only.
    Path,
    /// O_RDONLY | O_DIRECTORY: list, fsync, ioctl, fchmod.
    Dir,
    /// O_RDONLY | O_NONBLOCK | O_NOFOLLOW: a regular file's ioctls (never blocks on a FIFO: only opened after statx
    /// shows a regular file).
    File,
}

/// The handle operations A1 needs. `RealOps` maps each to one syscall wrapper in `sys`.
pub trait Ops {
    type H;
    fn root(&mut self) -> io::Result<Self::H>;
    /// openat2 from the trusted root (BENEATH | NO_SYMLINKS | NO_MAGICLINKS), O_RDONLY | O_DIRECTORY; "" is the root.
    fn dir_from_root(&mut self, root: &Self::H, rel: &str) -> io::Result<Self::H>;
    fn at(&mut self, dir: &Self::H, name: &str, how: At) -> io::Result<Self::H>;
    fn ident(&mut self, h: &Self::H) -> io::Result<Ident>;
    fn ident_at(&mut self, dir: &Self::H, name: &str) -> io::Result<Ident>;
    fn generation(&mut self, h: &Self::H) -> io::Result<u32>;
    fn project(&mut self, h: &Self::H) -> io::Result<(u32, bool)>;
    fn fsid(&mut self, h: &Self::H) -> io::Result<u64>;
    /// Every name in the directory but "." and "..".
    fn list(&mut self, dir: &Self::H) -> io::Result<Vec<String>>;
    fn has_acl(&mut self, dir: &Self::H) -> io::Result<bool>;
    fn chmod(&mut self, dir: &Self::H, mode: u16) -> io::Result<()>;
    fn drop_acls(&mut self, dir: &Self::H) -> io::Result<()>;
    fn unlink(&mut self, dir: &Self::H, name: &str, is_dir: bool) -> io::Result<()>;
    fn rename(&mut self, from: &Self::H, to: &Self::H, name: &str) -> io::Result<()>;
    fn fsync(&mut self, dir: &Self::H) -> io::Result<()>;
    /// A small file read through the trusted root (at most `max` bytes, else EFBIG).
    fn read(&mut self, root: &Self::H, rel: &str, max: usize) -> io::Result<Vec<u8>>;
}

fn c(s: &str) -> io::Result<CString> {
    CString::new(s).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))
}

/// The real handle operations: the syscall module, nothing else.
pub struct RealOps;

const ACL_ACCESS: &std::ffi::CStr = c"system.posix_acl_access";
const ACL_DEFAULT: &std::ffi::CStr = c"system.posix_acl_default";

impl Ops for RealOps {
    type H = OwnedFd;
    fn root(&mut self) -> io::Result<OwnedFd> {
        sys::open_root()
    }
    fn dir_from_root(&mut self, root: &OwnedFd, rel: &str) -> io::Result<OwnedFd> {
        sys::openat2(root, &c(if rel.is_empty() { "." } else { rel })?, libc::O_RDONLY | libc::O_DIRECTORY, 0)
    }
    fn at(&mut self, dir: &OwnedFd, name: &str, how: At) -> io::Result<OwnedFd> {
        let flags = match how {
            At::Path => libc::O_PATH,
            At::Dir => libc::O_RDONLY | libc::O_DIRECTORY,
            At::File => libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW,
        };
        sys::openat2_xdev(dir, &c(name)?, flags)
    }
    fn ident(&mut self, h: &OwnedFd) -> io::Result<Ident> {
        sys::ident(h)
    }
    fn ident_at(&mut self, dir: &OwnedFd, name: &str) -> io::Result<Ident> {
        sys::ident_at_nofollow(dir, &c(name)?)
    }
    fn generation(&mut self, h: &OwnedFd) -> io::Result<u32> {
        sys::inode_generation(h)
    }
    fn project(&mut self, h: &OwnedFd) -> io::Result<(u32, bool)> {
        sys::project(h)
    }
    fn fsid(&mut self, h: &OwnedFd) -> io::Result<u64> {
        sys::fsid(h)
    }
    fn list(&mut self, dir: &OwnedFd) -> io::Result<Vec<String>> {
        let mut buf = vec![0u8; 32 * 1024];
        let mut out = Vec::new();
        loop {
            let n = sys::getdents64(dir, &mut buf)?;
            if n == 0 {
                return Ok(out);
            }
            let names = dirent_names(&buf, n).ok_or_else(|| io::Error::from_raw_os_error(libc::EIO))?;
            for nm in names {
                if nm == b"." || nm == b".." {
                    continue;
                }
                // A name that isn't UTF-8 is refused by the caller as foreign (it can't be any name we made).
                out.push(String::from_utf8(nm).map_err(|_| io::Error::from_raw_os_error(libc::EILSEQ))?);
                if out.len() > MAX_OBJECTS {
                    return Err(io::Error::from_raw_os_error(libc::E2BIG));
                }
            }
        }
    }
    fn has_acl(&mut self, dir: &OwnedFd) -> io::Result<bool> {
        Ok(sys::has_xattr(dir, ACL_ACCESS)? || sys::has_xattr(dir, ACL_DEFAULT)?)
    }
    fn chmod(&mut self, dir: &OwnedFd, mode: u16) -> io::Result<()> {
        sys::fchmod(dir, mode as libc::mode_t)
    }
    fn drop_acls(&mut self, dir: &OwnedFd) -> io::Result<()> {
        sys::remove_xattr(dir, ACL_ACCESS)?;
        sys::remove_xattr(dir, ACL_DEFAULT)
    }
    fn unlink(&mut self, dir: &OwnedFd, name: &str, is_dir: bool) -> io::Result<()> {
        if is_dir { sys::rmdirat(dir, &c(name)?) } else { sys::unlinkat(dir, &c(name)?) }
    }
    fn rename(&mut self, from: &OwnedFd, to: &OwnedFd, name: &str) -> io::Result<()> {
        let n = c(name)?;
        sys::rename_noreplace_between(from, &n, to, &n)
    }
    fn fsync(&mut self, dir: &OwnedFd) -> io::Result<()> {
        sys::fsync_dir(dir)
    }
    fn read(&mut self, root: &OwnedFd, rel: &str, max: usize) -> io::Result<Vec<u8>> {
        use std::io::Read;
        let fd = sys::openat2(root, &c(rel)?, libc::O_RDONLY | libc::O_NONBLOCK, 0)?;
        let mut f = std::fs::File::from(fd); // safe: OwnedFd -> File
        let mut out = Vec::new();
        f.by_ref().take(max as u64 + 1).read_to_end(&mut out)?;
        if out.len() > max {
            return Err(io::Error::from_raw_os_error(libc::EFBIG));
        }
        Ok(out)
    }
}

// ---- identities

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Dir,
    File,
    Symlink,
}

/// One object's identity (A1 §1): durable (kind, mode, owners, ino, gen, projid, inherit) and live (dev, mnt_id).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Obj {
    pub kind: Kind,
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
    pub dev: (u32, u32),
    pub ino: u64,
    pub gen: Option<u32>,
    pub mnt_id: u64,
    pub projid: Option<u32>,
    pub inherit: Option<bool>,
}

/// The epoch the live fields belong to (deprovision r3.2 §3.6): the boot and the anchor mount's id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Epoch {
    pub boot_id: String,
    pub mnt_id: u64,
}

fn identity(msg: &'static str) -> Error {
    err(Fail::Identity, msg)
}
fn pre(msg: &'static str) -> Error {
    err(Fail::Preflight, msg)
}

/// Map an open/stat error: a mount crossing is an identity refusal (73); unsupported metadata, and anything else, is
/// preflight_missing (66). Nothing has been changed when either is returned.
fn open_err(e: io::Error) -> Error {
    match e.raw_os_error() {
        Some(libc::EXDEV) => identity("a mount below the anchor"),
        _ => pre("an object can't be opened or read"),
    }
}

fn kind_of(id: &Ident) -> Option<Kind> {
    match id.mode & S_IFMT {
        S_IFDIR => Some(Kind::Dir),
        S_IFREG => Some(Kind::File),
        S_IFLNK => Some(Kind::Symlink),
        _ => None,
    }
}

/// The child `name` of `dir`, fully identified. Ok(None) if it doesn't exist. For a directory, also its O_RDONLY
/// handle (to descend). A symlink is identified by name (never followed); a device, socket or FIFO is refused (73)
/// without ever being opened for reading.
fn child<O: Ops>(o: &mut O, dir: &O::H, name: &str, anchor_mnt: u64) -> Result<Option<(Obj, Option<O::H>)>> {
    let id = match o.at(dir, name, At::Path) {
        Ok(h) => o.ident(&h).map_err(open_err)?,
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => return Ok(None),
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {
            let id = o.ident_at(dir, name).map_err(open_err)?;
            if kind_of(&id) != Some(Kind::Symlink) {
                return Err(identity("a changed object"));
            }
            id
        }
        Err(e) => return Err(open_err(e)),
    };
    let kind = kind_of(&id).ok_or(identity("a device, socket or FIFO"))?;
    if id.mnt_id != anchor_mnt {
        return Err(identity("another mount below the anchor"));
    }
    let mut obj = Obj { kind, mode: id.mode & 0o7777, uid: id.uid, gid: id.gid, dev: id.dev, ino: id.ino, gen: None, mnt_id: id.mnt_id, projid: None, inherit: None };
    let handle = match kind {
        Kind::Symlink => return Ok(Some((obj, None))),
        Kind::Dir => o.at(dir, name, At::Dir).map_err(open_err)?,
        Kind::File => o.at(dir, name, At::File).map_err(open_err)?,
    };
    let again = o.ident(&handle).map_err(open_err)?;
    if again.dev != id.dev || again.ino != id.ino {
        return Err(identity("a changed object"));
    }
    obj.gen = Some(o.generation(&handle).map_err(|_| pre("no inode generation"))?);
    let (p, inh) = o.project(&handle).map_err(|_| pre("no project id"))?;
    obj.projid = Some(p);
    obj.inherit = Some(inh);
    Ok(Some((obj, if kind == Kind::Dir { Some(handle) } else { None })))
}

// ---- the anchor policy (A1 §1)

/// Each component from "/" down to `path`: a root:root directory without group or other write and without an ACL.
fn anchor_policy<O: Ops>(o: &mut O, root: &O::H, path: &str) -> Result<O::H> {
    let rel = &path[1..];
    let mut prefixes = vec![String::new()];
    let mut acc = String::new();
    for seg in rel.split('/').filter(|s| !s.is_empty()) {
        if !acc.is_empty() {
            acc.push('/');
        }
        acc.push_str(seg);
        prefixes.push(acc.clone());
    }
    let mut last = None;
    for p in prefixes {
        let h = o.dir_from_root(root, &p).map_err(|_| pre("an anchor or an ancestor can't be opened"))?;
        let id = o.ident(&h).map_err(open_err)?;
        let acl = o.has_acl(&h).map_err(|_| pre("an anchor's ACL can't be read"))?;
        if kind_of(&id) != Some(Kind::Dir) || id.uid != 0 || id.gid != 0 || id.mode & 0o022 != 0 || acl {
            return Err(pre("an anchor or an ancestor isn't root-only"));
        }
        last = Some(h);
    }
    last.ok_or(pre("no anchor"))
}

fn epoch_now<O: Ops>(o: &mut O, root: &O::H, anchor: &O::H) -> Result<(Epoch, u64)> {
    let raw = o.read(root, "proc/sys/kernel/random/boot_id", 64).map_err(|_| pre("no boot id"))?;
    let boot_id = core::str::from_utf8(&raw).ok().and_then(|s| s.strip_suffix('\n')).filter(|s| is_uuid(s)).ok_or(pre("a malformed boot id"))?;
    let mnt_id = o.ident(anchor).map_err(open_err)?.mnt_id;
    let fsid = o.fsid(anchor).map_err(|_| pre("no filesystem id"))?;
    if fsid == 0 {
        return Err(pre("a zero filesystem id"));
    }
    Ok((Epoch { boot_id: boot_id.to_string(), mnt_id }, fsid))
}

fn is_uuid(s: &str) -> bool {
    s.len() == 36
        && s.bytes().enumerate().all(|(i, b)| if [8, 13, 18, 23].contains(&i) { b == b'-' } else { b.is_ascii_hexdigit() && !b.is_ascii_uppercase() })
}

// ---- JSON in and out

fn obj_json(x: &Obj) -> String {
    let k = match x.kind {
        Kind::Dir => "dir",
        Kind::File => "file",
        Kind::Symlink => "symlink",
    };
    let opt = |v: Option<u64>| v.map_or("null".to_string(), |n| n.to_string());
    format!(
        "{{\"type\":\"{k}\",\"mode\":{},\"uid\":{},\"gid\":{},\"dev\":[{},{}],\"ino\":{},\"gen\":{},\"mnt_id\":{},\"projid\":{},\"inherit\":{}}}",
        x.mode,
        x.uid,
        x.gid,
        x.dev.0,
        x.dev.1,
        x.ino,
        opt(x.gen.map(u64::from)),
        x.mnt_id,
        opt(x.projid.map(u64::from)),
        x.inherit.map_or("null".to_string(), |b| b.to_string())
    )
}

fn head_json(e: &Epoch, fsid: u64) -> String {
    format!("\"epoch\":{{\"boot_id\":{},\"mnt_id\":{}}},\"fsid\":\"{fsid:016x}\"", json::quote(&e.boot_id), e.mnt_id)
}

fn bad_expect() -> Error {
    err(Fail::Contract, "the expected identity isn't the closed shape")
}

fn u32_of(v: &Value) -> Result<u32> {
    v.int().and_then(|n| u32::try_from(n).ok()).ok_or(bad_expect())
}

fn obj_of(v: &Value) -> Result<Obj> {
    let f = v.exact(&["type", "mode", "uid", "gid", "dev", "ino", "gen", "mnt_id", "projid", "inherit"]).ok_or(bad_expect())?;
    let kind = match f[0].str() {
        Some("dir") => Kind::Dir,
        Some("file") => Kind::File,
        Some("symlink") => Kind::Symlink,
        _ => return Err(bad_expect()),
    };
    let dev = f[4].arr().filter(|a| a.len() == 2).ok_or(bad_expect())?;
    let mode = u32_of(f[1])?;
    let opt_u32 = |v: &Value| if *v == Value::Null { Ok(None) } else { u32_of(v).map(Some) };
    let inherit = match f[9] {
        Value::Null => None,
        Value::Bool(b) => Some(*b),
        _ => return Err(bad_expect()),
    };
    let x = Obj {
        kind,
        mode: u16::try_from(mode).ok().filter(|m| *m <= 0o7777).ok_or(bad_expect())?,
        uid: u32_of(f[2])?,
        gid: u32_of(f[3])?,
        dev: (u32_of(&dev[0])?, u32_of(&dev[1])?),
        ino: f[5].int().ok_or(bad_expect())?,
        gen: opt_u32(f[6])?,
        mnt_id: f[7].int().ok_or(bad_expect())?,
        projid: opt_u32(f[8])?,
        inherit,
    };
    // A symlink has no generation or project; every other kind has both.
    let none = x.gen.is_none() && x.projid.is_none() && x.inherit.is_none();
    let all = x.gen.is_some() && x.projid.is_some() && x.inherit.is_some();
    if (x.kind == Kind::Symlink && !none) || (x.kind != Kind::Symlink && !all) {
        return Err(bad_expect());
    }
    Ok(x)
}

fn epoch_of(v: &Value) -> Result<Epoch> {
    let f = v.exact(&["boot_id", "mnt_id"]).ok_or(bad_expect())?;
    let boot_id = f[0].str().filter(|s| is_uuid(s)).ok_or(bad_expect())?.to_string();
    Ok(Epoch { boot_id, mnt_id: f[1].int().ok_or(bad_expect())? })
}

fn fsid_of(v: &Value) -> Result<u64> {
    let s = v.str().filter(|s| s.len() == 16 && s.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())).ok_or(bad_expect())?;
    u64::from_str_radix(s, 16).map_err(|_| bad_expect())
}

fn read_expect<O: Ops>(o: &mut O, root: &O::H, path: &str) -> Result<Value> {
    let rel = crate::args::rel(path).ok_or(err(Fail::Usage, "bad arguments"))?;
    let raw = o.read(root, rel, MAX_EXPECT).map_err(|_| err(Fail::Contract, "the expected identity can't be read"))?;
    json::parse(&raw).ok_or(bad_expect())
}

// ---- identify (A1 §2)

pub fn identify<O: Ops>(o: &mut O, anchor: &str, name: &str) -> Result<String> {
    if !anchor_name_ok(anchor, name) {
        return Err(err(Fail::Usage, "bad arguments"));
    }
    let root = o.root().map_err(|_| pre("the root can't be opened"))?;
    let a = anchor_policy(o, &root, anchor)?;
    let (epoch, fsid) = epoch_now(o, &root, &a)?;
    let obj = child(o, &a, name, epoch.mnt_id)?;
    Ok(format!("{{{},\"object\":{}}}\n", head_json(&epoch, fsid), obj.map_or("null".to_string(), |(x, _)| obj_json(&x))))
}

// ---- inspect-home (A1 §3, L1)

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tree {
    Home,
    Config,
}

/// The parent directory's name under /srv/sagebrush for a tree, live or archived.
fn parent_name(tree: Tree, archive: bool) -> &'static str {
    match (tree, archive) {
        (Tree::Home, false) => "agents",
        (Tree::Home, true) => "archive",
        (Tree::Config, false) => "agent-config",
        (Tree::Config, true) => "archive-config",
    }
}

/// `n` of "gen-<n>" or ".gen-<n>.tmp": a canonical decimal of at most 8 digits.
fn gen_number(s: &str) -> bool {
    !s.is_empty() && s.len() <= 8 && s.bytes().all(|b| b.is_ascii_digit()) && (s == "0" || !s.starts_with('0'))
}

/// The tree's exact shape (deprovision r3.2 §3.6 for home; L1 and A1 r2.1 §3 for config).
fn check_shape(tree: Tree, uid: u32, entries: &[(String, Obj)]) -> Result<()> {
    match tree {
        Tree::Home => {
            let mut names: Vec<&str> = entries.iter().map(|(n, _)| n.as_str()).collect();
            names.sort_unstable();
            if names != ["home", "sessions", "var-tmp"] {
                return Err(identity("home: the agent directory isn't exactly home, var-tmp and sessions"));
            }
            // With project quotas every entry carries project id = uid with the inherit flag; on a host without quotas
            // none does (project 0, no inherit). Never a mix; 8a compares which with the host's quota setting.
            let labelled = entries.first().is_some_and(|(_, x)| x.projid == Some(uid));
            let (pid, inh) = if labelled { (uid, true) } else { (0, false) };
            for (_, x) in entries {
                if x.kind != Kind::Dir || x.uid != uid || x.gid != uid || x.mode != 0o700 || x.projid != Some(pid) || x.inherit != Some(inh) {
                    return Err(identity("home: an entry's owner, mode or project differs"));
                }
            }
        }
        Tree::Config => {
            let (mut gens, mut current, mut tmp) = (0usize, 0usize, 0usize);
            for (n, x) in entries {
                let root_owned = x.uid == 0 && x.gid == 0;
                if n.strip_prefix("gen-").is_some_and(gen_number) {
                    gens += 1;
                    if x.kind != Kind::Dir || !root_owned || x.mode & 0o022 != 0 {
                        return Err(identity("config: a generation isn't a root-only directory"));
                    }
                } else if n.strip_prefix(".gen-").and_then(|r| r.strip_suffix(".tmp")).is_some_and(gen_number) {
                    tmp += 1;
                    if x.kind != Kind::Dir || !root_owned || x.mode & 0o022 != 0 {
                        return Err(identity("config: a temporary generation isn't a root-only directory"));
                    }
                } else if n == "current" {
                    current += 1;
                    if x.kind != Kind::File || !root_owned || x.mode != 0o600 {
                        return Err(identity("config: current isn't a root 0600 file"));
                    }
                } else {
                    return Err(identity("config: an unknown entry"));
                }
            }
            if gens > MAX_GENERATIONS || current > 1 || tmp > 1 {
                return Err(identity("config: too many generations, currents or temporaries"));
            }
        }
    }
    Ok(())
}

/// What inspect-home reads: the epoch, the fsid, the tree's directory, its entries, and the opened handles
/// (A = the parent of the tree, R = the other parent: archive when live, live when archived).
struct Inspected<H> {
    epoch: Epoch,
    fsid: u64,
    dir: Obj,
    entries: Vec<(String, Obj)>,
    parent: H,
}

/// The relative components from the quota mount to /srv/sagebrush: the mount must be "/" or a prefix of it.
fn srv_components(mount: &str) -> Result<Vec<&'static str>> {
    let bad = err(Fail::Usage, "bad arguments");
    let rest = if mount == "/" {
        &SRV[1..]
    } else {
        if !is_path(mount) {
            return Err(bad);
        }
        let r = SRV.strip_prefix(mount).ok_or(bad)?;
        if r.is_empty() {
            r
        } else {
            r.strip_prefix('/').ok_or(err(Fail::Usage, "bad arguments"))?
        }
    };
    Ok(rest.split('/').filter(|s| !s.is_empty()).collect())
}

/// Open the quota mount (its root, A1 §3) and the parent directory of the tree; with `expect`, refuse a stale epoch
/// BEFORE opening anything below the mount (A1 §1).
fn open_parent<O: Ops>(o: &mut O, root: &O::H, mount: &str, name: &str, expect: Option<&Epoch>) -> Result<(Epoch, u64, O::H)> {
    let comps = srv_components(mount)?;
    let m = anchor_policy(o, root, mount)?;
    let mid = o.ident(&m).map_err(open_err)?;
    if mid.attributes & libc::STATX_ATTR_MOUNT_ROOT as u64 == 0 {
        return Err(pre("the quota mount isn't a mount root"));
    }
    let (epoch, fsid) = epoch_now(o, root, &m)?;
    if let Some(e) = expect {
        if *e != epoch {
            return Err(identity("a stale epoch: requalify first"));
        }
    }
    let mut cur = m;
    for seg in comps.into_iter().chain([name]) {
        let next = o.at(&cur, seg, At::Dir).map_err(open_err)?;
        let id = o.ident(&next).map_err(open_err)?;
        if id.mnt_id != epoch.mnt_id || id.uid != 0 || id.gid != 0 || id.mode & 0o022 != 0 || kind_of(&id) != Some(Kind::Dir) {
            return Err(identity("a parent isn't a root-only directory on the quota mount"));
        }
        cur = next;
    }
    Ok((epoch, fsid, cur))
}

fn inspect<O: Ops>(o: &mut O, root: &O::H, mount: &str, agent: &str, tree: Tree, archive: bool, uid: Option<u32>, expect: Option<&Epoch>) -> Result<Option<Inspected<O::H>>> {
    let (epoch, fsid, parent) = open_parent(o, root, mount, parent_name(tree, archive), expect)?;
    let Some((dir, Some(h))) = child(o, &parent, agent, epoch.mnt_id)? else {
        return Ok(None);
    };
    if dir.kind != Kind::Dir {
        return Err(identity("the tree isn't a directory"));
    }
    let names = o.list(&h).map_err(open_err)?;
    if names.len() > MAX_GENERATIONS + 2 {
        return Err(identity("too many entries"));
    }
    let mut entries = Vec::with_capacity(names.len());
    for n in names {
        let (x, _) = child(o, &h, &n, epoch.mnt_id)?.ok_or(identity("an entry vanished"))?;
        entries.push((n, x));
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    // Home's owner is the directory's own entries' uid (8a compares it with the registry); config's is root.
    let owner = match tree {
        Tree::Home => uid.or_else(|| entries.first().map(|(_, x)| x.uid)).unwrap_or(u32::MAX),
        Tree::Config => 0,
    };
    check_shape(tree, owner, &entries)?;
    // Config's `current`: one link, at most MAX_CURRENT bytes (A1 r2 §3).
    if tree == Tree::Config && entries.iter().any(|(n, _)| n == "current") {
        let cur = o.at(&h, "current", At::Path).map_err(open_err)?;
        let id = o.ident(&cur).map_err(open_err)?;
        if id.nlink != 1 || id.size > MAX_CURRENT {
            return Err(identity("config: current has another link or is too large"));
        }
    }
    Ok(Some(Inspected { epoch, fsid, dir, entries, parent }))
}

fn inspected_json<H>(i: &Inspected<H>) -> String {
    let entries: Vec<String> = i.entries.iter().map(|(n, x)| format!("{}:{}", json::quote(n), obj_json(x))).collect();
    format!("{{{},\"dir\":{},\"entries\":{{{}}}}}\n", head_json(&i.epoch, i.fsid), obj_json(&i.dir), entries.join(","))
}

pub fn inspect_home<O: Ops>(o: &mut O, mount: &str, agent: &str, tree: Tree, archive: bool) -> Result<String> {
    if !is_id(agent) {
        return Err(err(Fail::Usage, "bad arguments"));
    }
    let root = o.root().map_err(|_| pre("the root can't be opened"))?;
    match inspect(o, &root, mount, agent, tree, archive, None, None)? {
        Some(i) => Ok(inspected_json(&i)),
        None => Err(identity("the tree is absent")),
    }
}

// ---- archive-home (A1 §4, L1 step 6b)

struct Expected {
    epoch: Epoch,
    fsid: u64,
    dir: Obj,
    entries: Vec<(String, Obj)>,
}

fn expected_tree(v: &Value) -> Result<Expected> {
    let f = v.exact(&["epoch", "fsid", "dir", "entries"]).ok_or(bad_expect())?;
    let Value::Obj(es) = f[3] else { return Err(bad_expect()) };
    let mut entries = Vec::with_capacity(es.len());
    for (n, x) in es {
        entries.push((n.clone(), obj_of(x)?));
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(Expected { epoch: epoch_of(f[0])?, fsid: fsid_of(f[1])?, dir: obj_of(f[2])?, entries })
}

fn same<H>(i: &Inspected<H>, e: &Expected) -> bool {
    i.epoch == e.epoch && i.fsid == e.fsid && i.dir == e.dir && i.entries == e.entries
}

pub fn archive_home<O: Ops>(o: &mut O, mount: &str, agent: &str, tree: Tree, expect_path: &str) -> Result<()> {
    if !is_id(agent) {
        return Err(err(Fail::Usage, "bad arguments"));
    }
    let root = o.root().map_err(|_| pre("the root can't be opened"))?;
    let e = expected_tree(&read_expect(o, &root, expect_path)?)?;
    let uid = e.entries.first().map(|(_, x)| x.uid);
    // 1-2. The source, every field checked on the opened descriptors (the epoch first, before any descent).
    let src = inspect(o, &root, mount, agent, tree, false, uid, Some(&e.epoch))?.ok_or(identity("the source is absent"))?;
    if !same(&src, &e) {
        return Err(identity("the source differs from the expected identity"));
    }
    let (_, _, dest_parent) = open_parent(o, &root, mount, parent_name(tree, true), Some(&e.epoch))?;
    let rid = o.ident(&dest_parent).map_err(open_err)?;
    if rid.mode & 0o7777 != 0o700 {
        return Err(identity("the archive parent isn't root 0700"));
    }
    // 3. An existing destination, even an empty directory: nothing happens.
    match o.at(&dest_parent, agent, At::Path) {
        Ok(_) => return Err(err(Fail::Exists, "the archive destination exists")),
        Err(x) if x.raw_os_error() == Some(libc::ENOENT) => {}
        Err(x) => return Err(open_err(x)),
    }
    // 4. The move, atomic, never over an existing name.
    match o.rename(&src.parent, &dest_parent, agent) {
        Ok(()) => {}
        Err(x) if x.raw_os_error() == Some(libc::EEXIST) => return Err(err(Fail::Exists, "the archive destination exists")),
        Err(_) => return Err(identity("the move failed; nothing moved")),
    }
    // 5-6. From here on an effect happened: any failure is partial (75), and 8a's retry table decides.
    let partial = |_| err(Fail::Partial, "moved; not yet confirmed durable");
    o.fsync(&dest_parent).map_err(partial)?;
    o.fsync(&src.parent).map_err(partial)?;
    match inspect(o, &root, mount, agent, tree, true, uid, Some(&e.epoch)) {
        Ok(Some(d)) if same(&d, &e) => Ok(()),
        _ => Err(err(Fail::Partial, "moved; the destination doesn't match")),
    }
}

// ---- remove-tree (A1 §5, r2: anchor policy, lockdown, two passes)

struct Walk {
    limit: usize,
    anchor_mnt: u64,
    owners: Vec<u32>,
    objects: usize,
    removed: usize,
}

impl Walk {
    fn owner_ok(&self, uid: u32) -> bool {
        self.owners.contains(&uid)
    }
    /// Before the first unlink, a refusal is "nothing removed" (73); after it, any failure is partial (75).
    fn fail(&self, msg: &'static str) -> Error {
        if self.removed == 0 { identity(msg) } else { err(Fail::Partial, msg) }
    }
}

/// Pass 1: top-down; each directory is LOCKED DOWN (group and other write removed, ACLs removed) before it is
/// listed, then every entry is checked. Removes nothing.
fn pass1<O: Ops>(o: &mut O, w: &mut Walk, dir: &O::H, depth: usize) -> Result<()> {
    if depth > MAX_DEPTH {
        return Err(identity("the tree is too deep"));
    }
    let id = o.ident(dir).map_err(open_err)?;
    if kind_of(&id) != Some(Kind::Dir) || id.mnt_id != w.anchor_mnt || !w.owner_ok(id.uid) {
        return Err(identity("a foreign directory"));
    }
    let tight = id.mode & 0o7777 & !0o022;
    if id.mode & 0o022 != 0 {
        o.chmod(dir, tight).map_err(|_| pre("a directory can't be locked down"))?;
    }
    o.drop_acls(dir).map_err(|_| pre("a directory's ACL can't be removed"))?;
    for name in o.list(dir).map_err(open_err)? {
        w.objects += 1;
        if w.objects > w.limit {
            return Err(identity("the tree is too large"));
        }
        let (x, h) = child(o, dir, &name, w.anchor_mnt)?.ok_or(identity("an entry vanished"))?;
        if !w.owner_ok(x.uid) {
            return Err(identity("an object owned by a foreign uid"));
        }
        if let Some(h) = h {
            pass1(o, w, &h, depth + 1)?;
        }
    }
    Ok(())
}

/// Pass 2: bottom-up; every object's predicates are checked again (mount, owner, kind, and for a directory its
/// locked-down mode and absent ACL) before it is unlinked by name from its checked parent.
fn pass2<O: Ops>(o: &mut O, w: &mut Walk, dir: &O::H, depth: usize) -> Result<()> {
    if depth > MAX_DEPTH {
        return Err(w.fail("the tree is too deep"));
    }
    let names = o.list(dir).map_err(|_| w.fail("a directory can't be listed"))?;
    for name in names {
        let (x, h) = match child(o, dir, &name, w.anchor_mnt) {
            Ok(Some(v)) => v,
            Ok(None) => return Err(w.fail("an entry vanished")),
            Err(_) => return Err(w.fail("an object changed between the passes")),
        };
        if !w.owner_ok(x.uid) {
            return Err(w.fail("an object owned by a foreign uid"));
        }
        if let Some(h) = h {
            let acl = o.has_acl(&h).map_err(|_| w.fail("an ACL can't be read"))?;
            if x.mode & 0o022 != 0 || acl {
                return Err(w.fail("a directory isn't locked down"));
            }
            pass2(o, w, &h, depth + 1)?;
            drop(h);
        }
        o.unlink(dir, &name, x.kind == Kind::Dir).map_err(|_| w.fail("an unlink failed"))?;
        w.removed += 1;
    }
    Ok(())
}

pub fn remove_tree<O: Ops>(o: &mut O, anchor: &str, name: &str, expect_path: &str) -> Result<()> {
    remove_tree_limited(o, anchor, name, expect_path, MAX_OBJECTS)
}

fn remove_tree_limited<O: Ops>(o: &mut O, anchor: &str, name: &str, expect_path: &str, limit: usize) -> Result<()> {
    if !anchor_name_ok(anchor, name) {
        return Err(err(Fail::Usage, "bad arguments"));
    }
    let root = o.root().map_err(|_| pre("the root can't be opened"))?;
    let v = read_expect(o, &root, expect_path)?;
    let f = v.exact(&["epoch", "fsid", "root", "owners"]).ok_or(bad_expect())?;
    let (e_epoch, e_fsid, e_root) = (epoch_of(f[0])?, fsid_of(f[1])?, obj_of(f[2])?);
    let owners = f[3].arr().filter(|a| !a.is_empty() && a.len() <= 4).ok_or(bad_expect())?.iter().map(u32_of).collect::<Result<Vec<u32>>>()?;
    let a = anchor_policy(o, &root, anchor)?;
    // The epoch FIRST, even when the target is absent (A1 r2 §1, TESTS T1).
    let (epoch, fsid) = epoch_now(o, &root, &a)?;
    if epoch != e_epoch {
        return Err(identity("a stale epoch: requalify first"));
    }
    if fsid != e_fsid {
        return Err(identity("another filesystem"));
    }
    let Some((x, h)) = child(o, &a, name, epoch.mnt_id)? else { return Ok(()) }; // already gone
    if x != e_root {
        return Err(identity("the target differs from the expected identity"));
    }
    let mut w = Walk { limit, anchor_mnt: epoch.mnt_id, owners, objects: 1, removed: 0 };
    if !w.owner_ok(x.uid) {
        return Err(identity("the target is owned by a foreign uid"));
    }
    if let Some(h) = &h {
        pass1(o, &mut w, h, 1)?;
        pass2(o, &mut w, h, 1)?;
    }
    drop(h);
    o.unlink(&a, name, x.kind == Kind::Dir).map_err(|_| w.fail("the target can't be unlinked"))?;
    w.removed += 1;
    o.fsync(&a).map_err(|_| err(Fail::Partial, "removed; not yet confirmed durable"))?;
    Ok(())
}

// ---- argument parsing for main.rs

pub fn parse_tree(s: &str) -> Result<Tree> {
    match s {
        "home" => Ok(Tree::Home),
        "config" => Ok(Tree::Config),
        _ => Err(err(Fail::Usage, "bad arguments")),
    }
}

pub fn parse_mount(s: &str) -> Result<&str> {
    srv_components(s).map(|_| s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    const A: &str = "abcdefghijklmnopqrstuvwxya";
    const BOOT: &str = "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0";
    const MNT: u64 = 20;
    const UID: u32 = 70001;

    #[derive(Clone, Debug)]
    struct Node {
        id: Ident,
        gen: u32,
        proj: u32,
        inherit: bool,
        acl: bool,
    }

    type Hook = fn(&mut Fake);

    /// A fake tree: paths relative to the root ("" is the root). A node whose mnt_id differs from its parent's is a
    /// mount: opening it with NO_XDEV fails EXDEV. Symlinks fail ELOOP. `hook` runs once, when op `.0` has been called
    /// `.1` times; `fail` makes one op fail.
    struct Fake {
        nodes: BTreeMap<String, Node>,
        files: BTreeMap<String, Vec<u8>>,
        fsid: u64,
        next_ino: u64,
        counts: BTreeMap<&'static str, usize>,
        hook: Option<(&'static str, usize, Hook)>,
        fail: Option<&'static str>,
        /// A kernel that reports a different mount without failing the open (the mnt_id postcondition must refuse).
        no_exdev: bool,
        log: Vec<String>,
    }

    fn join(dir: &str, name: &str) -> String {
        if dir.is_empty() { name.to_string() } else { format!("{dir}/{name}") }
    }
    fn parent(p: &str) -> &str {
        p.rfind('/').map_or("", |i| &p[..i])
    }
    fn e(n: i32) -> io::Error {
        io::Error::from_raw_os_error(n)
    }

    impl Fake {
        fn new() -> Fake {
            let mut f = Fake { nodes: BTreeMap::new(), files: BTreeMap::new(), fsid: 0xabcd_0000_1234, next_ino: 2, counts: BTreeMap::new(), hook: None, fail: None, no_exdev: false, log: vec![] };
            f.add("", S_IFDIR | 0o755, 0, 0);
            f.nodes.get_mut("").unwrap().id.attributes = libc::STATX_ATTR_MOUNT_ROOT as u64;
            for d in ["run", "run/sagebrush", "run/sagebrush/binds", "var", "var/lib", "var/lib/sagebrush", "var/lib/sagebrush/contract", "srv", "srv/sagebrush", "srv/sagebrush/agents", "srv/sagebrush/agent-config"] {
                f.add(d, S_IFDIR | 0o755, 0, 0);
            }
            for d in ["srv/sagebrush/archive", "srv/sagebrush/archive-config"] {
                f.add(d, S_IFDIR | 0o700, 0, 0);
            }
            f.files.insert("proc/sys/kernel/random/boot_id".into(), format!("{BOOT}\n").into_bytes());
            f
        }
        fn add(&mut self, p: &str, mode: u16, uid: u32, gid: u32) {
            self.next_ino += 1;
            let id = Ident { attributes: 0, dev: (8, 1), ino: self.next_ino, uid, gid, mode, mnt_id: MNT, nlink: 1, size: 0 };
            self.nodes.insert(p.to_string(), Node { id, gen: 7, proj: 0, inherit: false, acl: false });
        }
        fn dir(&mut self, p: &str, uid: u32, mode: u16) {
            self.add(p, S_IFDIR | mode, uid, uid);
        }
        fn file(&mut self, p: &str, uid: u32, mode: u16) {
            self.add(p, S_IFREG | mode, uid, uid);
        }
        fn node(&mut self, p: &str) -> &mut Node {
            self.nodes.get_mut(p).unwrap()
        }
        /// An agent home tree as provisioned: exactly home, var-tmp and sessions, each the agent's, 0700, project = uid.
        fn agent(&mut self, base: &str) {
            let d = format!("{base}/{A}");
            self.dir(&d, 0, 0o755);
            for n in ["home", "var-tmp", "sessions"] {
                let p = format!("{d}/{n}");
                self.dir(&p, UID, 0o700);
                let x = self.node(&p);
                x.proj = UID;
                x.inherit = true;
            }
        }
        fn children(&self, dir: &str) -> Vec<String> {
            let pre = if dir.is_empty() { String::new() } else { format!("{dir}/") };
            self.nodes.keys().filter(|k| !k.is_empty() && k.starts_with(&pre) && !k[pre.len()..].contains('/')).map(|k| k[pre.len()..].to_string()).collect()
        }
        fn tick(&mut self, op: &'static str) -> io::Result<()> {
            let n = self.counts.entry(op).or_insert(0);
            *n += 1;
            let n = *n;
            if let Some((h, at, f)) = self.hook {
                if h == op && at == n {
                    self.hook = None;
                    f(self);
                }
            }
            if self.fail == Some(op) { Err(e(libc::EIO)) } else { Ok(()) }
        }
        fn count(&self, op: &str) -> usize {
            self.counts.get(op).copied().unwrap_or(0)
        }
    }

    impl Ops for Fake {
        type H = String;
        fn root(&mut self) -> io::Result<String> {
            Ok(String::new())
        }
        fn dir_from_root(&mut self, _root: &String, rel: &str) -> io::Result<String> {
            let n = self.nodes.get(rel).ok_or(e(libc::ENOENT))?;
            if n.id.mode & S_IFMT != S_IFDIR { Err(e(libc::ENOTDIR)) } else { Ok(rel.to_string()) }
        }
        fn at(&mut self, dir: &String, name: &str, how: At) -> io::Result<String> {
            self.tick("at")?;
            let p = join(dir, name);
            let n = self.nodes.get(&p).ok_or(e(libc::ENOENT))?;
            if n.id.mnt_id != self.nodes[dir].id.mnt_id && !self.no_exdev {
                return Err(e(libc::EXDEV));
            }
            if n.id.mode & S_IFMT == S_IFLNK {
                return Err(e(libc::ELOOP));
            }
            if how == At::Dir && n.id.mode & S_IFMT != S_IFDIR {
                return Err(e(libc::ENOTDIR));
            }
            Ok(p)
        }
        fn ident(&mut self, h: &String) -> io::Result<Ident> {
            self.nodes.get(h).map(|n| n.id).ok_or(e(libc::ENOENT))
        }
        fn ident_at(&mut self, dir: &String, name: &str) -> io::Result<Ident> {
            self.nodes.get(&join(dir, name)).map(|n| n.id).ok_or(e(libc::ENOENT))
        }
        fn generation(&mut self, h: &String) -> io::Result<u32> {
            self.tick("generation")?;
            Ok(self.nodes[h].gen)
        }
        fn project(&mut self, h: &String) -> io::Result<(u32, bool)> {
            Ok((self.nodes[h].proj, self.nodes[h].inherit))
        }
        fn fsid(&mut self, _h: &String) -> io::Result<u64> {
            Ok(self.fsid)
        }
        fn list(&mut self, dir: &String) -> io::Result<Vec<String>> {
            self.tick("list")?;
            self.log.push(format!("list {dir}"));
            Ok(self.children(dir))
        }
        fn has_acl(&mut self, h: &String) -> io::Result<bool> {
            Ok(self.nodes[h].acl)
        }
        fn chmod(&mut self, h: &String, mode: u16) -> io::Result<()> {
            self.log.push(format!("chmod {h} {mode:o}"));
            let n = self.node(h);
            n.id.mode = (n.id.mode & S_IFMT) | mode;
            Ok(())
        }
        fn drop_acls(&mut self, h: &String) -> io::Result<()> {
            self.node(h).acl = false;
            Ok(())
        }
        fn unlink(&mut self, dir: &String, name: &str, is_dir: bool) -> io::Result<()> {
            self.tick("unlink")?;
            let p = join(dir, name);
            let n = self.nodes.get(&p).ok_or(e(libc::ENOENT))?;
            if is_dir != (n.id.mode & S_IFMT == S_IFDIR) {
                return Err(e(if is_dir { libc::ENOTDIR } else { libc::EISDIR }));
            }
            if is_dir && !self.children(&p).is_empty() {
                return Err(e(libc::ENOTEMPTY));
            }
            self.nodes.remove(&p);
            self.log.push(format!("unlink {p}"));
            Ok(())
        }
        fn rename(&mut self, from: &String, to: &String, name: &str) -> io::Result<()> {
            self.tick("rename")?;
            let (src, dst) = (join(from, name), join(to, name));
            if self.nodes.contains_key(&dst) {
                return Err(e(libc::EEXIST));
            }
            let keys: Vec<String> = self.nodes.keys().filter(|k| **k == src || k.starts_with(&format!("{src}/"))).cloned().collect();
            for k in keys {
                let n = self.nodes.remove(&k).unwrap();
                self.nodes.insert(format!("{dst}{}", &k[src.len()..]), n);
            }
            self.log.push(format!("rename {src} {dst}"));
            Ok(())
        }
        fn fsync(&mut self, h: &String) -> io::Result<()> {
            self.tick("fsync")?;
            self.log.push(format!("fsync {h}"));
            Ok(())
        }
        fn read(&mut self, _root: &String, rel: &str, max: usize) -> io::Result<Vec<u8>> {
            let b = self.files.get(rel).ok_or(e(libc::ENOENT))?;
            if b.len() > max { Err(e(libc::EFBIG)) } else { Ok(b.clone()) }
        }
    }

    fn code<T: std::fmt::Debug>(r: Result<T>) -> i32 {
        match r {
            Ok(_) => 0,
            Err(x) => x.fail.code(),
        }
    }

    fn expect_file(f: &mut Fake, name: &str, json: String) -> String {
        f.files.insert(format!("run/sagebrush/expect/{name}"), json.into_bytes());
        format!("/run/sagebrush/expect/{name}")
    }

    // ---- identify and the anchor policy

    #[test]
    fn identify_reports_the_object_or_null_with_the_epoch_and_fsid() {
        let mut f = Fake::new();
        let out = identify(&mut f, "/var/lib/sagebrush/contract", &format!("{A}.json")).unwrap();
        assert!(out.contains(&format!("\"boot_id\":\"{BOOT}\"")) && out.contains("\"object\":null") && out.contains("\"fsid\":\"0000abcd00001234\""), "{out}");
        f.file(&format!("var/lib/sagebrush/contract/{A}.json"), 0, 0o644);
        let out = identify(&mut f, "/var/lib/sagebrush/contract", &format!("{A}.json")).unwrap();
        assert!(out.contains("\"type\":\"file\",\"mode\":420,\"uid\":0") && out.contains("\"gen\":7"), "{out}");
        // A device is refused without being opened for reading.
        f.add(&format!("var/lib/sagebrush/contract/{A}.json"), 0o020000 | 0o600, 0, 0);
        assert_eq!(code(identify(&mut f, "/var/lib/sagebrush/contract", &format!("{A}.json"))), 73);
    }

    #[test]
    fn only_the_compiled_anchors_and_their_name_forms() {
        let mut f = Fake::new();
        for (anchor, name) in [("/var/lib/sagebrush/contract", A.to_string()), ("/var/lib/sagebrush/contract", format!("{A}.conf")), ("/etc", A.to_string()), ("/srv/sagebrush/agents", A.to_string()), ("/run/sagebrush/binds", "x".into())] {
            assert_eq!(code(identify(&mut f, anchor, &name)), 64, "{anchor} {name}");
        }
        assert!(anchor_name_ok("/srv/sagebrush/archive-config", A) && anchor_name_ok("/var/lib/sagebrush/secrets", A));
    }

    #[test]
    fn the_anchor_policy_refuses_writable_foreign_or_acl_ancestors() {
        for (path, how) in [("var/lib", "g+w"), ("var/lib/sagebrush", "owner"), ("var/lib/sagebrush/contract", "acl"), ("", "o+w")] {
            let mut f = Fake::new();
            let n = f.node(path);
            match how {
                "g+w" => n.id.mode |= 0o020,
                "o+w" => n.id.mode |= 0o002,
                "owner" => n.id.uid = UID,
                _ => n.acl = true,
            }
            assert_eq!(code(identify(&mut f, "/var/lib/sagebrush/contract", &format!("{A}.json"))), 66, "{path} {how}");
        }
    }

    // ---- inspect-home

    #[test]
    fn inspect_home_reads_exactly_the_three_entries() {
        let mut f = Fake::new();
        f.agent("srv/sagebrush/agents");
        let out = inspect_home(&mut f, "/", A, Tree::Home, false).unwrap();
        for n in ["home", "sessions", "var-tmp"] {
            assert!(out.contains(&format!("\"{n}\":{{\"type\":\"dir\",\"mode\":448,\"uid\":{UID}")), "{out}");
        }
        assert!(out.contains(&format!("\"projid\":{UID},\"inherit\":true")));
        // A host without project quotas: no entry is labelled, consistently.
        let mut u = Fake::new();
        u.agent("srv/sagebrush/agents");
        for n in ["home", "var-tmp", "sessions"] {
            let x = u.node(&format!("srv/sagebrush/agents/{A}/{n}"));
            x.proj = 0;
            x.inherit = false;
        }
        assert!(inspect_home(&mut u, "/", A, Tree::Home, false).is_ok());
        // The same from a mount at /srv.
        let mut g = Fake::new();
        g.agent("srv/sagebrush/agents");
        g.node("srv").id.attributes = libc::STATX_ATTR_MOUNT_ROOT as u64;
        assert!(inspect_home(&mut g, "/srv", A, Tree::Home, false).is_ok());
        assert_eq!(code(inspect_home(&mut g, "/srv/sagebrush", A, Tree::Home, false)), 66, "not a mount root");
        assert_eq!(code(inspect_home(&mut g, "/etc", A, Tree::Home, false)), 64, "not a prefix of /srv/sagebrush");
    }

    #[test]
    fn inspect_home_refuses_every_shape_or_identity_difference() {
        let cases: [(&str, fn(&mut Fake)); 8] = [
            ("a fourth entry", |f| f.dir(&format!("srv/sagebrush/agents/{A}/extra"), UID, 0o700)),
            ("a missing sessions", |f| { f.nodes.remove(&format!("srv/sagebrush/agents/{A}/sessions")); }),
            ("another project id", |f| f.node(&format!("srv/sagebrush/agents/{A}/home")).proj = UID + 1),
            ("a lost inherit flag", |f| f.node(&format!("srv/sagebrush/agents/{A}/var-tmp")).inherit = false),
            ("a mix of labelled and unlabelled", |f| { let x = f.node(&format!("srv/sagebrush/agents/{A}/sessions")); x.proj = 0; x.inherit = false; }),
            ("a bind over the agent dir", |f| f.node(&format!("srv/sagebrush/agents/{A}")).id.mnt_id = MNT + 1),
            ("a bind over an entry", |f| f.node(&format!("srv/sagebrush/agents/{A}/home")).id.mnt_id = MNT + 1),
            ("another mode", |f| f.node(&format!("srv/sagebrush/agents/{A}/sessions")).id.mode = S_IFDIR | 0o750),
        ];
        for (name, mutate) in cases {
            let mut f = Fake::new();
            f.agent("srv/sagebrush/agents");
            mutate(&mut f);
            assert_eq!(code(inspect_home(&mut f, "/", A, Tree::Home, false)), 73, "{name}");
        }
    }

    fn config(f: &mut Fake) -> String {
        let d = format!("srv/sagebrush/agent-config/{A}");
        f.add(&d, S_IFDIR | 0o700, 0, 0);
        d
    }

    #[test]
    fn config_write_states_are_valid_shapes() {
        let states: [fn(&mut Fake, &str); 4] = [
            |_, _| {},                                                     // empty, as provisioned
            |f, d| f.add(&format!("{d}/.gen-1.tmp"), S_IFDIR | 0o755, 0, 0), // a first write killed
            |f, d| f.add(&format!("{d}/gen-1"), S_IFDIR | 0o755, 0, 0),      // published, before current
            |f, d| {
                f.add(&format!("{d}/gen-1"), S_IFDIR | 0o755, 0, 0);
                f.add(&format!("{d}/current"), S_IFREG | 0o600, 0, 0);
            },
        ];
        for (i, s) in states.iter().enumerate() {
            let mut f = Fake::new();
            let d = config(&mut f);
            s(&mut f, &d);
            assert!(inspect_home(&mut f, "/", A, Tree::Config, false).is_ok(), "state {i}");
        }
    }

    #[test]
    fn config_refuses_bad_shapes() {
        let cases: [(&str, fn(&mut Fake, &str)); 8] = [
            ("17 generations", |f, d| for g in 1..=17 { f.add(&format!("{d}/gen-{g}"), S_IFDIR | 0o755, 0, 0) }),
            ("a 9-digit generation", |f, d| f.add(&format!("{d}/gen-123456789"), S_IFDIR | 0o755, 0, 0)),
            ("two temporaries", |f, d| for g in 1..=2 { f.add(&format!("{d}/.gen-{g}.tmp"), S_IFDIR | 0o755, 0, 0) }),
            ("a non-root generation", |f, d| f.add(&format!("{d}/gen-1"), S_IFDIR | 0o755, UID, UID)),
            ("an unknown entry", |f, d| f.add(&format!("{d}/notes"), S_IFREG | 0o600, 0, 0)),
            ("current with two links", |f, d| { f.add(&format!("{d}/current"), S_IFREG | 0o600, 0, 0); f.node(&format!("{d}/current")).id.nlink = 2 }),
            ("current over 64 bytes", |f, d| { f.add(&format!("{d}/current"), S_IFREG | 0o600, 0, 0); f.node(&format!("{d}/current")).id.size = 65 }),
            ("current a symlink", |f, d| f.add(&format!("{d}/current"), S_IFLNK | 0o777, 0, 0)),
        ];
        for (name, mutate) in cases {
            let mut f = Fake::new();
            let d = config(&mut f);
            mutate(&mut f, &d);
            assert_eq!(code(inspect_home(&mut f, "/", A, Tree::Config, false)), 73, "{name}");
        }
    }

    // ---- archive-home

    fn archived_expect(f: &mut Fake, tree: Tree) -> String {
        let json = inspect_home(f, "/", A, tree, false).unwrap();
        expect_file(f, "home.json", json)
    }

    #[test]
    fn archive_home_moves_exactly_the_expected_tree_then_syncs_and_rechecks() {
        let mut f = Fake::new();
        f.agent("srv/sagebrush/agents");
        let x = archived_expect(&mut f, Tree::Home);
        archive_home(&mut f, "/", A, Tree::Home, &x).unwrap();
        assert!(f.nodes.contains_key(&format!("srv/sagebrush/archive/{A}/home")) && !f.nodes.contains_key(&format!("srv/sagebrush/agents/{A}")));
        let tail: Vec<&String> = f.log.iter().filter(|l| l.starts_with("rename") || l.starts_with("fsync")).collect();
        assert_eq!(tail, [&format!("rename srv/sagebrush/agents/{A} srv/sagebrush/archive/{A}"), &"fsync srv/sagebrush/archive".to_string(), &"fsync srv/sagebrush/agents".to_string()]);
        // And the config tree, to archive-config (L1 step 6b).
        let mut g = Fake::new();
        let d = config(&mut g);
        g.add(&format!("{d}/gen-1"), S_IFDIR | 0o755, 0, 0);
        let x = archived_expect(&mut g, Tree::Config);
        archive_home(&mut g, "/", A, Tree::Config, &x).unwrap();
        assert!(g.nodes.contains_key(&format!("srv/sagebrush/archive-config/{A}/gen-1")));
    }

    #[test]
    fn archive_home_refuses_with_zero_effects() {
        let cases: [(&str, fn(&mut Fake), i32); 6] = [
            ("a stale boot", |f| { f.files.insert("proc/sys/kernel/random/boot_id".into(), b"11111111-2222-3333-4444-555555555555\n".to_vec()); }, 73),
            ("a remount (another mount id)", |f| for n in f.nodes.values_mut() { n.id.mnt_id = MNT + 5 }, 73),
            ("a reused inode (another generation)", |f| f.node(&format!("srv/sagebrush/agents/{A}/home")).gen = 8, 73),
            ("a same-shaped substitute (another ino)", |f| f.node(&format!("srv/sagebrush/agents/{A}")).id.ino = 999, 73),
            ("an existing destination", |f| f.add(&format!("srv/sagebrush/archive/{A}"), S_IFDIR | 0o700, 0, 0), 74),
            ("an archive parent that isn't 0700", |f| f.node("srv/sagebrush/archive").id.mode = S_IFDIR | 0o755, 73),
        ];
        for (name, mutate, want) in cases {
            let mut f = Fake::new();
            f.agent("srv/sagebrush/agents");
            let x = archived_expect(&mut f, Tree::Home);
            mutate(&mut f);
            assert_eq!(code(archive_home(&mut f, "/", A, Tree::Home, &x)), want, "{name}");
            assert_eq!(f.count("rename"), 0, "{name}: nothing moved");
        }
    }

    #[test]
    fn archive_home_after_the_move_any_failure_is_partial() {
        let mut f = Fake::new();
        f.agent("srv/sagebrush/agents");
        let x = archived_expect(&mut f, Tree::Home);
        f.fail = Some("fsync");
        assert_eq!(code(archive_home(&mut f, "/", A, Tree::Home, &x)), 75);
        assert_eq!(f.count("rename"), 1);
    }

    // ---- remove-tree

    /// /srv/sagebrush/archive/<A> holding a small agent tree, and its expect file.
    fn archive_tree(f: &mut Fake) -> String {
        f.agent("srv/sagebrush/archive");
        let h = format!("srv/sagebrush/archive/{A}/home");
        f.dir(&format!("{h}/proj"), UID, 0o755);
        f.file(&format!("{h}/proj/a.txt"), UID, 0o644);
        f.file(&format!("{h}/b.txt"), UID, 0o600);
        f.add(&format!("{h}/link"), S_IFLNK | 0o777, UID, UID);
        let out = identify(f, "/srv/sagebrush/archive", A).unwrap();
        let v = json::parse(out.as_bytes()).unwrap();
        let g = v.exact(&["epoch", "fsid", "object"]).unwrap();
        let rootj = match g[2] {
            Value::Obj(_) => {
                let start = out.find("\"object\":").unwrap() + 9;
                out[start..out.len() - 2].to_string()
            }
            _ => panic!(),
        };
        let head = &out[1..out.find(",\"object\"").unwrap()];
        expect_file(f, "rm.json", format!("{{{head},\"root\":{rootj},\"owners\":[0,{UID}]}}"))
    }

    #[test]
    fn remove_tree_removes_everything_bottom_up_after_a_full_inspection() {
        let mut f = Fake::new();
        let x = archive_tree(&mut f);
        remove_tree(&mut f, "/srv/sagebrush/archive", A, &x).unwrap();
        assert!(!f.nodes.keys().any(|k| k.starts_with(&format!("srv/sagebrush/archive/{A}"))));
        // Pass 1 listed everything before the first unlink, and the anchor is synced last.
        let first_unlink = f.log.iter().position(|l| l.starts_with("unlink")).unwrap();
        assert!(f.log[..first_unlink].iter().any(|l| l == &format!("list srv/sagebrush/archive/{A}/home/proj")));
        assert_eq!(f.log.last().unwrap(), "fsync srv/sagebrush/archive");
        // The symlink was unlinked as itself.
        assert!(f.log.contains(&format!("unlink srv/sagebrush/archive/{A}/home/link")));
    }

    #[test]
    fn remove_tree_the_epoch_first_even_when_the_target_is_absent() {
        let mut f = Fake::new();
        let x = archive_tree(&mut f);
        f.files.insert("proc/sys/kernel/random/boot_id".into(), b"11111111-2222-3333-4444-555555555555\n".to_vec());
        assert_eq!(code(remove_tree(&mut f, "/srv/sagebrush/archive", A, &x)), 73);
        assert_eq!(f.count("unlink"), 0);
        let keys: Vec<String> = f.nodes.keys().filter(|k| k.starts_with(&format!("srv/sagebrush/archive/{A}"))).cloned().collect();
        for k in keys {
            f.nodes.remove(&k);
        }
        assert_eq!(code(remove_tree(&mut f, "/srv/sagebrush/archive", A, &x)), 73, "stale epoch, target absent: still parked");
        f.files.insert("proc/sys/kernel/random/boot_id".into(), format!("{BOOT}\n").into_bytes());
        assert_eq!(code(remove_tree(&mut f, "/srv/sagebrush/archive", A, &x)), 0, "current epoch, target absent: already gone");
    }

    #[test]
    fn remove_tree_refuses_with_zero_unlinks() {
        let h = format!("srv/sagebrush/archive/{A}/home");
        let cases: [(&str, fn(&mut Fake, &str)); 7] = [
            ("a bind on a nested directory", |f, h| f.node(&format!("{h}/proj")).id.mnt_id = MNT + 1),
            ("a bind on a file leaf", |f, h| f.node(&format!("{h}/b.txt")).id.mnt_id = MNT + 1),
            ("a foreign owner", |f, h| f.node(&format!("{h}/proj/a.txt")).id.uid = UID + 1),
            ("a device", |f, h| f.add(&format!("{h}/dev"), 0o020000 | 0o600, UID, UID)),
            ("a FIFO", |f, h| f.add(&format!("{h}/fifo"), 0o010000 | 0o600, UID, UID)),
            ("another filesystem id", |f, _| f.fsid += 1),
            ("a changed root identity", |f, _| f.node(&format!("srv/sagebrush/archive/{A}")).gen = 99),
        ];
        for (name, mutate) in cases {
            let mut f = Fake::new();
            let x = archive_tree(&mut f);
            mutate(&mut f, &h);
            assert_eq!(code(remove_tree(&mut f, "/srv/sagebrush/archive", A, &x)), 73, "{name}");
            assert_eq!(f.count("unlink"), 0, "{name}");
        }
        // The anchor policy, and the bounds.
        let mut f = Fake::new();
        let x = archive_tree(&mut f);
        f.node("srv/sagebrush/archive").acl = true;
        assert_eq!(code(remove_tree(&mut f, "/srv/sagebrush/archive", A, &x)), 66);
        let mut f = Fake::new();
        let x = archive_tree(&mut f);
        assert_eq!(code(remove_tree_limited(&mut f, "/srv/sagebrush/archive", A, &x, 3)), 73, "too many objects");
        assert_eq!(f.count("unlink"), 0);
        let mut f = Fake::new();
        let x = archive_tree(&mut f);
        let mut p = h.clone();
        for _ in 0..MAX_DEPTH {
            p.push_str("/d");
            f.dir(&p, UID, 0o700);
        }
        assert_eq!(code(remove_tree(&mut f, "/srv/sagebrush/archive", A, &x)), 73, "too deep");
        assert_eq!(f.count("unlink"), 0);
    }

    #[test]
    fn the_mnt_id_postcondition_refuses_on_its_own() {
        let mut f = Fake::new();
        let x = archive_tree(&mut f);
        f.no_exdev = true;
        f.node(&format!("srv/sagebrush/archive/{A}/home/proj")).id.mnt_id = MNT + 1;
        assert_eq!(code(remove_tree(&mut f, "/srv/sagebrush/archive", A, &x)), 73);
        assert_eq!(f.count("unlink"), 0);
        let mut g = Fake::new();
        g.agent("srv/sagebrush/agents");
        g.no_exdev = true;
        g.node(&format!("srv/sagebrush/agents/{A}/home")).id.mnt_id = MNT + 1;
        assert_eq!(code(inspect_home(&mut g, "/", A, Tree::Home, false)), 73);
    }

    #[test]
    fn remove_tree_locks_down_each_directory_before_listing_it() {
        let mut f = Fake::new();
        let x = archive_tree(&mut f);
        let proj = format!("srv/sagebrush/archive/{A}/home/proj");
        f.node(&proj).id.mode = S_IFDIR | 0o777;
        f.node(&proj).acl = true;
        // A retained descriptor of another uid can't add a name after the lockdown; one added before it is listed.
        remove_tree(&mut f, "/srv/sagebrush/archive", A, &x).unwrap();
        let chmod = f.log.iter().position(|l| l == &format!("chmod {proj} 755")).expect("locked down");
        let list = f.log.iter().position(|l| l == &format!("list {proj}")).unwrap();
        assert!(chmod < list, "the lockdown precedes the listing");
    }

    #[test]
    fn remove_tree_after_the_first_unlink_any_failure_is_partial_and_a_retry_converges() {
        // A mount appears after the first unlink: 75, only checked objects removed.
        let mut f = Fake::new();
        let x = archive_tree(&mut f);
        f.hook = Some(("unlink", 1, |f| {
            let k = f.nodes.keys().find(|k| k.ends_with("/home")).cloned().unwrap();
            f.node(&k).id.mnt_id = MNT + 1;
        }));
        assert_eq!(code(remove_tree(&mut f, "/srv/sagebrush/archive", A, &x)), 75);
        // A failure in pass 2 BEFORE the first unlink is 73.
        let mut f = Fake::new();
        let x = archive_tree(&mut f);
        // Pass 1 lists the five directories (the tree root, home, proj, sessions, var-tmp); the sixth listing, which
        // fails, is pass 2's first, before any unlink.
        f.hook = Some(("list", 6, |f| f.fail = Some("list")));
        assert_eq!(code(remove_tree(&mut f, "/srv/sagebrush/archive", A, &x)), 73);
        assert_eq!(f.count("unlink"), 0);
        // The final fsync failing after everything was removed: 75; a retry then finds the target gone.
        let mut f = Fake::new();
        let x = archive_tree(&mut f);
        f.fail = Some("fsync");
        assert_eq!(code(remove_tree(&mut f, "/srv/sagebrush/archive", A, &x)), 75);
        f.fail = None;
        assert_eq!(code(remove_tree(&mut f, "/srv/sagebrush/archive", A, &x)), 0);
    }

    #[test]
    fn expect_files_are_closed() {
        let mut f = Fake::new();
        let x = archive_tree(&mut f);
        let good = String::from_utf8(f.files[&x[1..]].clone()).unwrap();
        for bad in [
            good.replace("\"owners\":[0,", "\"owners\":[0,1,2,3,"),
            good.replace("\"owners\"", "\"extra\":1,\"owners\""),
            good.replace("\"type\":\"dir\"", "\"type\":\"fifo\""),
            good.replace("\"gen\":7", "\"gen\":null"),
            good.replace("\"fsid\":\"", "\"fsid\":\"X"),
        ] {
            let p = expect_file(&mut f, "bad.json", bad.clone());
            assert_eq!(code(remove_tree(&mut f, "/srv/sagebrush/archive", A, &p)), 65, "{bad}");
        }
    }
}
