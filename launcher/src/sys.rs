//! Every syscall this binary makes (contract §6). Each function wraps exactly ONE syscall in ONE small `unsafe` block,
//! and a descriptor-returning call is followed by exactly one `OwnedFd::from_raw_fd` in its own block (contract §6,
//! non-syscall conversion 1). Nothing outside this module (and the zeroing `Drop` in secret.rs) is unsafe.
//!
//! Paths: `open_root` opens "/" (the only absolute path opened); every other open is `openat2` relative to a handle,
//! with RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS. `umount2` takes the fixed, re-checked staging
//! path (contract §3.1) and `execve` the CLI path; nothing else takes a path.

use crate::landlock::{PathBeneathAttr, RulesetAttr};
use std::ffi::CStr;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

/// struct open_how (linux/openat2.h): three u64s. Defined here as plain data because libc's is #[non_exhaustive]
/// (it can't be built without unsafe zeroing); asserted against the uapi layout at compile time.
#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}
const _: () = assert!(core::mem::size_of::<OpenHow>() == 24 && core::mem::align_of::<OpenHow>() == 8);
const _: () = assert!(core::mem::offset_of!(OpenHow, flags) == 0 && core::mem::offset_of!(OpenHow, mode) == 8);
const _: () = assert!(core::mem::offset_of!(OpenHow, resolve) == 16);
const _: () = assert!(core::mem::size_of::<OpenHow>() == core::mem::size_of::<libc::open_how>());

/// struct mount_attr (linux/mount.h, MOUNT_ATTR_SIZE_VER0): four u64s, likewise plain data.
#[repr(C)]
struct MountAttr {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
    userns_fd: u64,
}
const _: () = assert!(core::mem::size_of::<MountAttr>() == 32 && core::mem::align_of::<MountAttr>() == 8);
const _: () = assert!(core::mem::size_of::<MountAttr>() == core::mem::size_of::<libc::mount_attr>());

fn last() -> io::Error {
    io::Error::last_os_error()
}

/// Wrap a descriptor a syscall just returned (non-negative), giving it exactly one owner.
fn own(fd: libc::c_long) -> io::Result<OwnedFd> {
    if fd < 0 {
        return Err(last());
    }
    let fd = fd as libc::c_int;
    // SAFETY (§6 conversion 1): `fd` was just returned by the kernel to this process, is open, and has no other owner.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// openat(AT_FDCWD, "/", O_PATH | O_DIRECTORY | O_CLOEXEC): the trusted root handle.
pub fn open_root() -> io::Result<OwnedFd> {
    // SAFETY: the path is a valid NUL-terminated literal; the flags are constants.
    let fd = unsafe { libc::openat(libc::AT_FDCWD, c"/".as_ptr(), libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) };
    own(fd as libc::c_long)
}

/// openat2(dir, rel, { flags | O_CLOEXEC, mode, RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS }).
pub fn openat2(dir: &OwnedFd, rel: &CStr, flags: libc::c_int, mode: libc::mode_t) -> io::Result<OwnedFd> {
    let how = OpenHow {
        flags: (flags | libc::O_CLOEXEC) as u64,
        mode: mode as u64,
        resolve: libc::RESOLVE_BENEATH | libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_MAGICLINKS,
    };
    // SAFETY: `dir` is an open descriptor, `rel` is NUL-terminated, `how` lives across the call and its size is passed.
    let fd = unsafe {
        libc::syscall(libc::SYS_openat2, dir.as_raw_fd(), rel.as_ptr(), &how as *const OpenHow, core::mem::size_of::<OpenHow>())
    };
    own(fd)
}

/// The statx fields this binary reads (contract §3.1, §6): only after a 0 return, and only fields `mask` reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stat {
    pub mask: u32,
    pub attributes: u64,
    pub attributes_mask: u64,
    pub dev: (u32, u32),
    pub ino: u64,
    pub uid: u32,
    pub mode: u16,
    pub mnt_id: u64,
}

/// statx(fd, "", AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW, TYPE | MODE | UID | INO | MNT_ID).
pub fn statx(fd: &OwnedFd) -> io::Result<Stat> {
    let mut buf = core::mem::MaybeUninit::<libc::statx>::uninit();
    let want = libc::STATX_TYPE | libc::STATX_MODE | libc::STATX_UID | libc::STATX_INO | libc::STATX_MNT_ID;
    // SAFETY: `fd` is open, the path is an empty NUL-terminated literal, and `buf` is writable for a whole statx.
    let r = unsafe { libc::statx(fd.as_raw_fd(), c"".as_ptr(), libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW, want, buf.as_mut_ptr()) };
    if r != 0 {
        return Err(last());
    }
    // SAFETY (§6 conversion 2): statx returned 0, so the kernel initialized the whole struct.
    let s = unsafe { buf.assume_init() };
    let need = want;
    if s.stx_mask & need != need {
        return Err(io::Error::from_raw_os_error(libc::ENOTSUP));
    }
    Ok(Stat {
        mask: s.stx_mask,
        attributes: s.stx_attributes,
        attributes_mask: s.stx_attributes_mask,
        dev: (s.stx_dev_major, s.stx_dev_minor),
        ino: s.stx_ino,
        uid: s.stx_uid,
        mode: s.stx_mode,
        mnt_id: s.stx_mnt_id,
    })
}

/// getdents64(fd, buf): bytes read into `buf` (0 at EOF).
pub fn getdents64(fd: &OwnedFd, buf: &mut [u8]) -> io::Result<usize> {
    // SAFETY: `fd` is an open directory, `buf` is writable for its length.
    let n = unsafe { libc::syscall(libc::SYS_getdents64, fd.as_raw_fd(), buf.as_mut_ptr(), buf.len()) };
    if n < 0 { Err(last()) } else { Ok(n as usize) }
}

/// open_tree(fd, "", OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC | AT_EMPTY_PATH): a detached clone of the opened path.
pub fn open_tree_clone(fd: &OwnedFd) -> io::Result<OwnedFd> {
    let flags = libc::OPEN_TREE_CLONE | libc::OPEN_TREE_CLOEXEC | libc::AT_EMPTY_PATH as libc::c_uint;
    // SAFETY: `fd` is open; the path is an empty NUL-terminated literal.
    let fd = unsafe { libc::syscall(libc::SYS_open_tree, fd.as_raw_fd(), c"".as_ptr(), flags) };
    own(fd)
}

/// mount_setattr(clone, "", AT_EMPTY_PATH, { attr_set: MOUNT_ATTR_RDONLY }).
pub fn mount_setattr_rdonly(clone: &OwnedFd) -> io::Result<()> {
    let attr = MountAttr { attr_set: libc::MOUNT_ATTR_RDONLY, attr_clr: 0, propagation: 0, userns_fd: 0 };
    // SAFETY: `clone` is an open mount fd; `attr` lives across the call and its size is passed.
    let r = unsafe {
        libc::syscall(libc::SYS_mount_setattr, clone.as_raw_fd(), c"".as_ptr(), libc::AT_EMPTY_PATH, &attr as *const MountAttr, core::mem::size_of::<MountAttr>())
    };
    if r != 0 { Err(last()) } else { Ok(()) }
}

/// move_mount(from, "", to, "", MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH): both ends by handle.
pub fn move_mount(from: &OwnedFd, to: &OwnedFd) -> io::Result<()> {
    let flags = libc::MOVE_MOUNT_F_EMPTY_PATH | libc::MOVE_MOUNT_T_EMPTY_PATH;
    // SAFETY: both descriptors are open; both paths are empty NUL-terminated literals.
    let r = unsafe { libc::syscall(libc::SYS_move_mount, from.as_raw_fd(), c"".as_ptr(), to.as_raw_fd(), c"".as_ptr(), flags) };
    if r != 0 { Err(last()) } else { Ok(()) }
}

/// umount2(path, MNT_DETACH | UMOUNT_NOFOLLOW): rollback only, on the fixed staging path checked as in §3.1.
pub fn umount2_detach(path: &CStr) -> io::Result<()> {
    // SAFETY: `path` is NUL-terminated; the flags are constants.
    let r = unsafe { libc::umount2(path.as_ptr(), libc::MNT_DETACH | libc::UMOUNT_NOFOLLOW) };
    if r != 0 { Err(last()) } else { Ok(()) }
}

/// renameat2(dir, from, dir, to, RENAME_NOREPLACE).
pub fn rename_noreplace(dir: &OwnedFd, from: &CStr, to: &CStr) -> io::Result<()> {
    // SAFETY: `dir` is open; both names are NUL-terminated.
    let r = unsafe { libc::renameat2(dir.as_raw_fd(), from.as_ptr(), dir.as_raw_fd(), to.as_ptr(), libc::RENAME_NOREPLACE) };
    if r != 0 { Err(last()) } else { Ok(()) }
}

/// unlinkat(dir, name, 0).
pub fn unlinkat(dir: &OwnedFd, name: &CStr) -> io::Result<()> {
    // SAFETY: `dir` is open; `name` is NUL-terminated.
    let r = unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) };
    if r != 0 { Err(last()) } else { Ok(()) }
}

/// fsync(dir): a DIRECTORY handle only (contract §6). Files are written and synced through std's File (safe).
pub fn fsync_dir(dir: &OwnedFd) -> io::Result<()> {
    // SAFETY: `dir` is open.
    let r = unsafe { libc::fsync(dir.as_raw_fd()) };
    if r != 0 { Err(last()) } else { Ok(()) }
}

/// prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0).
pub fn no_new_privs() -> io::Result<()> {
    // SAFETY: constant arguments.
    let r = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1 as libc::c_ulong, 0 as libc::c_ulong, 0 as libc::c_ulong, 0 as libc::c_ulong) };
    if r != 0 { Err(last()) } else { Ok(()) }
}

/// close_range(3, ~0U, 0).
pub fn close_range_from_3() -> io::Result<()> {
    // SAFETY: constant arguments; no descriptor above 2 is owned by an OwnedFd when this runs (the caller drops them all).
    let r = unsafe { libc::syscall(libc::SYS_close_range, 3 as libc::c_uint, libc::c_uint::MAX, 0 as libc::c_uint) };
    if r != 0 { Err(last()) } else { Ok(()) }
}

/// close(fd) on a raw descriptor number (the close_range ENOSYS fallback only; no OwnedFd owns it by then).
pub fn close_raw(fd: libc::c_int) -> io::Result<()> {
    // SAFETY: called only after every OwnedFd was dropped, on numbers listed in proc/<pid>/fd; EBADF is tolerated by
    // the caller.
    let r = unsafe { libc::close(fd) };
    if r != 0 { Err(last()) } else { Ok(()) }
}

/// landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION): the kernel's Landlock ABI version.
pub fn landlock_abi() -> io::Result<i64> {
    // SAFETY: a NULL attr with size 0 and the VERSION flag is the documented ABI query.
    let v = unsafe {
        libc::syscall(libc::SYS_landlock_create_ruleset, core::ptr::null::<RulesetAttr>(), 0usize, crate::landlock::CREATE_RULESET_VERSION)
    };
    if v < 0 { Err(last()) } else { Ok(v) }
}

/// landlock_create_ruleset(&attr, sizeof attr, 0): a ruleset descriptor.
pub fn landlock_create_ruleset(attr: &RulesetAttr) -> io::Result<OwnedFd> {
    // SAFETY: `attr` lives across the call and its exact size is passed.
    let fd = unsafe { libc::syscall(libc::SYS_landlock_create_ruleset, attr as *const RulesetAttr, core::mem::size_of::<RulesetAttr>(), 0u32) };
    own(fd)
}

/// landlock_add_rule(ruleset, LANDLOCK_RULE_PATH_BENEATH, &rule, 0). `rule` is passed by value and pointed to as a
/// whole: no reference to its packed fields is ever formed.
pub fn landlock_add_path_rule(ruleset: &OwnedFd, rule: PathBeneathAttr) -> io::Result<()> {
    let p: *const PathBeneathAttr = &rule;
    // SAFETY: `rule` lives across the call; the kernel reads exactly the packed uapi struct at `p`.
    let r = unsafe { libc::syscall(libc::SYS_landlock_add_rule, ruleset.as_raw_fd(), crate::landlock::RULE_PATH_BENEATH, p, 0u32) };
    if r != 0 { Err(last()) } else { Ok(()) }
}

/// landlock_restrict_self(ruleset, 0).
pub fn landlock_restrict_self(ruleset: &OwnedFd) -> io::Result<()> {
    // SAFETY: `ruleset` is an open ruleset descriptor.
    let r = unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset.as_raw_fd(), 0u32) };
    if r != 0 { Err(last()) } else { Ok(()) }
}

/// execve(path, argv, envp). Returns only on failure. `argv` and `envp` are NULL-terminated arrays of pointers to
/// NUL-terminated strings that the caller keeps alive across the call.
pub fn execve(path: &CStr, argv: &[*const libc::c_char], envp: &[*const libc::c_char]) -> io::Error {
    debug_assert!(argv.last() == Some(&core::ptr::null()) && envp.last() == Some(&core::ptr::null()));
    // SAFETY: `path` is NUL-terminated; both arrays end with NULL and point to live NUL-terminated strings.
    unsafe { libc::execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr()) };
    last()
}

// ---- launcher contract amendment A1 (deprovision): identify, inspect-home, archive-home, remove-tree.

/// openat2(dir, name, { flags | O_CLOEXEC, 0, RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS |
/// RESOLVE_NO_XDEV }): one component beneath an opened directory, never crossing a mount (A1 §1).
pub fn openat2_xdev(dir: &OwnedFd, name: &CStr, flags: libc::c_int) -> io::Result<OwnedFd> {
    let how = OpenHow {
        flags: (flags | libc::O_CLOEXEC) as u64,
        mode: 0,
        resolve: libc::RESOLVE_BENEATH | libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_MAGICLINKS | libc::RESOLVE_NO_XDEV,
    };
    // SAFETY: `dir` is an open descriptor, `name` is NUL-terminated, `how` lives across the call and its size is passed.
    let fd = unsafe {
        libc::syscall(libc::SYS_openat2, dir.as_raw_fd(), name.as_ptr(), &how as *const OpenHow, core::mem::size_of::<OpenHow>())
    };
    own(fd)
}

/// The statx fields A1 reads: type and mode, owners, identity and the mount (only fields `stx_mask` reports).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ident {
    pub attributes: u64,
    pub dev: (u32, u32),
    pub ino: u64,
    pub uid: u32,
    pub gid: u32,
    pub mode: u16,
    /// The UNIQUE mount id (STATX_MNT_ID_UNIQUE): never reused while the system runs.
    pub mnt_id: u64,
    pub nlink: u32,
    pub size: u64,
}

/// STATX_MNT_ID_UNIQUE, not STATX_MNT_ID: the plain mount id is reused (a remount can get the same number back), so
/// an epoch or a mount-identity check on it could take a remounted filesystem for the same mount. The unique id
/// (Linux 6.8+) is never reused while the system runs; a kernel without it fails closed (66).
const IDENT_MASK: u32 = libc::STATX_TYPE
    | libc::STATX_MODE
    | libc::STATX_UID
    | libc::STATX_GID
    | libc::STATX_INO
    | libc::STATX_MNT_ID_UNIQUE
    | libc::STATX_NLINK
    | libc::STATX_SIZE;

fn ident_of(r: libc::c_int, buf: core::mem::MaybeUninit<libc::statx>) -> io::Result<Ident> {
    if r != 0 {
        return Err(last());
    }
    // SAFETY (§6 conversion 2): statx returned 0, so the kernel initialized the whole struct.
    let s = unsafe { buf.assume_init() };
    if s.stx_mask & IDENT_MASK != IDENT_MASK || s.stx_attributes_mask & libc::STATX_ATTR_MOUNT_ROOT as u64 == 0 {
        return Err(io::Error::from_raw_os_error(libc::ENOTSUP)); // unsupported metadata fails closed (66)
    }
    Ok(Ident {
        attributes: s.stx_attributes,
        dev: (s.stx_dev_major, s.stx_dev_minor),
        ino: s.stx_ino,
        uid: s.stx_uid,
        gid: s.stx_gid,
        mode: s.stx_mode,
        mnt_id: s.stx_mnt_id,
        nlink: s.stx_nlink,
        size: s.stx_size,
    })
}

/// statx(fd, "", AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW, IDENT_MASK): an opened object's identity.
pub fn ident(fd: &OwnedFd) -> io::Result<Ident> {
    let mut buf = core::mem::MaybeUninit::<libc::statx>::uninit();
    // SAFETY: `fd` is open, the path is an empty NUL-terminated literal, and `buf` is writable for a whole statx.
    let r = unsafe { libc::statx(fd.as_raw_fd(), c"".as_ptr(), libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW, IDENT_MASK, buf.as_mut_ptr()) };
    ident_of(r, buf)
}

/// statx(dir, name, AT_SYMLINK_NOFOLLOW, IDENT_MASK): a symlink leaf by name relative to its opened parent (A1 §5).
pub fn ident_at_nofollow(dir: &OwnedFd, name: &CStr) -> io::Result<Ident> {
    let mut buf = core::mem::MaybeUninit::<libc::statx>::uninit();
    // SAFETY: `dir` is open, `name` is NUL-terminated, and `buf` is writable for a whole statx.
    let r = unsafe { libc::statx(dir.as_raw_fd(), name.as_ptr(), libc::AT_SYMLINK_NOFOLLOW, IDENT_MASK, buf.as_mut_ptr()) };
    ident_of(r, buf)
}

/// struct statfs (x86_64 and aarch64 glibc layout): only `f_fsid` (two ints at offset 56) is read. libc's `fsid_t`
/// keeps its field private, so this is plain data asserted against libc's size.
#[repr(C)]
struct StatFs {
    head: [u64; 7],
    fsid: [i32; 2],
    tail: [u64; 7],
}
const _: () = assert!(core::mem::size_of::<StatFs>() == core::mem::size_of::<libc::statfs>());
const _: () = assert!(core::mem::offset_of!(StatFs, fsid) == 56);

/// fstatfs(fd): the filesystem's `f_fsid` (A1 §1). A zero fsid is unsupported metadata (the caller refuses).
pub fn fsid(fd: &OwnedFd) -> io::Result<u64> {
    let mut buf = StatFs { head: [0; 7], fsid: [0; 2], tail: [0; 7] };
    // SAFETY: `fd` is open; `buf` is writable for a whole struct statfs (asserted above).
    let r = unsafe { libc::syscall(libc::SYS_fstatfs, fd.as_raw_fd(), &mut buf as *mut StatFs) };
    if r != 0 {
        return Err(last());
    }
    Ok(((buf.fsid[0] as u32 as u64) << 32) | buf.fsid[1] as u32 as u64)
}

/// ioctl(fd, FS_IOC_GETVERSION): the inode generation (an O_RDONLY fd; A1 §1).
pub fn inode_generation(fd: &OwnedFd) -> io::Result<u32> {
    let mut v: libc::c_long = 0;
    // SAFETY: `fd` is open; the kernel writes one int into `v`, which is writable for a long.
    let r = unsafe { libc::ioctl(fd.as_raw_fd(), libc::FS_IOC_GETVERSION, &mut v as *mut libc::c_long) };
    if r != 0 { Err(last()) } else { Ok(v as u32) }
}

/// struct fsxattr (linux/fs.h), 28 bytes: plain data, zeroed before the call.
#[repr(C)]
struct FsXattr {
    xflags: u32,
    extsize: u32,
    nextents: u32,
    projid: u32,
    cowextsize: u32,
    pad: [u8; 8],
}
const _: () = assert!(core::mem::size_of::<FsXattr>() == 28);
/// _IOR('X', 31, struct fsxattr): not in libc 0.2.191.
const FS_IOC_FSGETXATTR: libc::Ioctl = 0x801c_581f;
const FS_XFLAG_PROJINHERIT: u32 = 0x0000_0200;

/// ioctl(fd, FS_IOC_FSGETXATTR): (project id, project-inherit flag) (an O_RDONLY fd; A1 §1).
pub fn project(fd: &OwnedFd) -> io::Result<(u32, bool)> {
    let mut x = FsXattr { xflags: 0, extsize: 0, nextents: 0, projid: 0, cowextsize: 0, pad: [0; 8] };
    // SAFETY: `fd` is open; `x` is writable for a whole struct fsxattr.
    let r = unsafe { libc::ioctl(fd.as_raw_fd(), FS_IOC_FSGETXATTR, &mut x as *mut FsXattr) };
    if r != 0 { Err(last()) } else { Ok((x.projid, x.xflags & FS_XFLAG_PROJINHERIT != 0)) }
}

/// fchmod(dir, mode): remove-tree's lockdown (A1 §5).
pub fn fchmod(fd: &OwnedFd, mode: libc::mode_t) -> io::Result<()> {
    // SAFETY: `fd` is open.
    let r = unsafe { libc::fchmod(fd.as_raw_fd(), mode) };
    if r != 0 { Err(last()) } else { Ok(()) }
}

/// Whether a POSIX ACL attribute exists: fgetxattr(fd, name, NULL, 0) (A1 §1's anchor policy).
pub fn has_xattr(fd: &OwnedFd, name: &CStr) -> io::Result<bool> {
    // SAFETY: `fd` is open, `name` is NUL-terminated; a NULL buffer with size 0 only asks for the value's size.
    let r = unsafe { libc::fgetxattr(fd.as_raw_fd(), name.as_ptr(), core::ptr::null_mut(), 0) };
    if r >= 0 {
        return Ok(true);
    }
    let e = last();
    if e.raw_os_error() == Some(libc::ENODATA) { Ok(false) } else { Err(e) }
}

/// fremovexattr(fd, name), with ENODATA (absent) treated as done: remove-tree's lockdown (A1 §5).
pub fn remove_xattr(fd: &OwnedFd, name: &CStr) -> io::Result<()> {
    // SAFETY: `fd` is open, `name` is NUL-terminated.
    let r = unsafe { libc::fremovexattr(fd.as_raw_fd(), name.as_ptr()) };
    if r == 0 {
        return Ok(());
    }
    let e = last();
    if e.raw_os_error() == Some(libc::ENODATA) { Ok(()) } else { Err(e) }
}

/// unlinkat(dir, name, AT_REMOVEDIR): remove-tree's pass 2 for a directory.
pub fn rmdirat(dir: &OwnedFd, name: &CStr) -> io::Result<()> {
    // SAFETY: `dir` is open; `name` is NUL-terminated.
    let r = unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) };
    if r != 0 { Err(last()) } else { Ok(()) }
}

/// renameat2(from_dir, name, to_dir, name, RENAME_NOREPLACE): archive-home's move between two opened parents.
pub fn rename_noreplace_between(from_dir: &OwnedFd, from: &CStr, to_dir: &OwnedFd, to: &CStr) -> io::Result<()> {
    // SAFETY: both directories are open; both names are NUL-terminated.
    let r = unsafe { libc::renameat2(from_dir.as_raw_fd(), from.as_ptr(), to_dir.as_raw_fd(), to.as_ptr(), libc::RENAME_NOREPLACE) };
    if r != 0 { Err(last()) } else { Ok(()) }
}

/// geteuid(): the A1 subcommands run as root only (an explicit guard; root is their sole qualified caller).
pub fn is_root() -> bool {
    // SAFETY: geteuid takes no arguments and cannot fail.
    unsafe { libc::geteuid() == 0 }
}
