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

/// The renameat2 system call itself: musl's static libc (the shipped build, lease-on r1.7 §2.2) has no wrapper for it,
/// and glibc's wrapper is this same call. Returns the call's result (-1 with errno set on failure).
unsafe fn renameat2(olddir: libc::c_int, old: *const libc::c_char, newdir: libc::c_int, new: *const libc::c_char, flags: libc::c_uint) -> libc::c_int {
    // SAFETY: the caller's: both directory descriptors are open and both names NUL-terminated.
    unsafe { libc::syscall(libc::SYS_renameat2, olddir, old, newdir, new, flags) as libc::c_int }
}

/// renameat2(dir, from, dir, to, RENAME_NOREPLACE).
pub fn rename_noreplace(dir: &OwnedFd, from: &CStr, to: &CStr) -> io::Result<()> {
    // SAFETY: `dir` is open; both names are NUL-terminated.
    let r = unsafe { renameat2(dir.as_raw_fd(), from.as_ptr(), dir.as_raw_fd(), to.as_ptr(), libc::RENAME_NOREPLACE) };
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
// (from u32: musl's Ioctl is i32, where the request's top bit wraps to the same 32 bits the kernel reads as unsigned)
const FS_IOC_FSGETXATTR: libc::Ioctl = 0x801c_581f_u32 as libc::Ioctl;
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
    let r = unsafe { renameat2(from_dir.as_raw_fd(), from.as_ptr(), to_dir.as_raw_fd(), to.as_ptr(), libc::RENAME_NOREPLACE) };
    if r != 0 { Err(last()) } else { Ok(()) }
}

/// geteuid(): the A1 subcommands run as root only (an explicit guard; root is their sole qualified caller).
pub fn is_root() -> bool {
    // SAFETY: geteuid takes no arguments and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

// ---- launcher contract amendment A2 (backup restore): restore-stage and fill-home.

/// A2 constants libc 0.2.191 doesn't export for every target: from the uapi headers (linux/mount.h, linux/quota.h,
/// linux/fs.h, linux/capability.h).
pub const FSCONFIG_SET_STRING: libc::c_uint = 1;
pub const FSCONFIG_CMD_CREATE: libc::c_uint = 6;
pub const PRJQUOTA: libc::c_int = 2;
pub const Q_GETQUOTA: libc::c_int = 0x800007;
pub const QIF_BLIMITS: u32 = 1;
pub const QIF_SPACE: u32 = 2;
pub const QIF_ILIMITS: u32 = 4;
pub const QIF_INODES: u32 = 8;
pub const QIF_BTIME: u32 = 16;
pub const QIF_ITIME: u32 = 32;
/// _IOW('X', 32, struct fsxattr).
const FS_IOC_FSSETXATTR: libc::Ioctl = 0x401c_5820;
const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

/// mkdirat(dir, name, mode).
pub fn mkdirat(dir: &OwnedFd, name: &CStr, mode: libc::mode_t) -> io::Result<()> {
    // SAFETY: `dir` is open; `name` is NUL-terminated.
    let r = unsafe { libc::mkdirat(dir.as_raw_fd(), name.as_ptr(), mode) };
    if r != 0 { Err(last()) } else { Ok(()) }
}

/// ioctl(fd, FS_IOC_FSSETXATTR): read the current fsxattr, set the project id and the inherit flag, write it back.
pub fn set_project(fd: &OwnedFd, projid: u32, inherit: bool) -> io::Result<()> {
    let mut x = FsXattr { xflags: 0, extsize: 0, nextents: 0, projid: 0, cowextsize: 0, pad: [0; 8] };
    // SAFETY: `fd` is open; `x` is writable for a whole struct fsxattr.
    let r = unsafe { libc::ioctl(fd.as_raw_fd(), FS_IOC_FSGETXATTR, &mut x as *mut FsXattr) };
    if r != 0 {
        return Err(last());
    }
    x.projid = projid;
    x.xflags = if inherit { x.xflags | FS_XFLAG_PROJINHERIT } else { x.xflags & !FS_XFLAG_PROJINHERIT };
    // SAFETY: `fd` is open; `x` is a whole struct fsxattr, read by the kernel.
    let r = unsafe { libc::ioctl(fd.as_raw_fd(), FS_IOC_FSSETXATTR, &x as *const FsXattr) };
    if r != 0 { Err(last()) } else { Ok(()) }
}

/// The ext4 immutable flag in `fsx_xflags` (launcher amendment A4 §3).
pub const FS_XFLAG_IMMUTABLE: u32 = 0x0000_0008;

/// `xflags` with only FS_XFLAG_IMMUTABLE set or cleared; every other bit kept.
pub const fn with_immutable(xflags: u32, on: bool) -> u32 {
    if on { xflags | FS_XFLAG_IMMUTABLE } else { xflags & !FS_XFLAG_IMMUTABLE }
}

/// ioctl(fd, FS_IOC_FSGETXATTR): the extended flags (`fsx_xflags`) (an O_RDONLY fd; A4 §3).
pub fn xflags(fd: &OwnedFd) -> io::Result<u32> {
    let mut x = FsXattr { xflags: 0, extsize: 0, nextents: 0, projid: 0, cowextsize: 0, pad: [0; 8] };
    // SAFETY: `fd` is open; `x` is writable for a whole struct fsxattr.
    let r = unsafe { libc::ioctl(fd.as_raw_fd(), FS_IOC_FSGETXATTR, &mut x as *mut FsXattr) };
    if r != 0 { Err(last()) } else { Ok(x.xflags) }
}

/// ioctl(fd, FS_IOC_FSSETXATTR): read the current fsxattr, set or clear ONLY FS_XFLAG_IMMUTABLE, write it back (every
/// other flag, the project id and the rest unchanged) (A4 §3; needs CAP_LINUX_IMMUTABLE).
pub fn set_immutable(fd: &OwnedFd, on: bool) -> io::Result<()> {
    let mut x = FsXattr { xflags: 0, extsize: 0, nextents: 0, projid: 0, cowextsize: 0, pad: [0; 8] };
    // SAFETY: `fd` is open; `x` is writable for a whole struct fsxattr.
    let r = unsafe { libc::ioctl(fd.as_raw_fd(), FS_IOC_FSGETXATTR, &mut x as *mut FsXattr) };
    if r != 0 {
        return Err(last());
    }
    x.xflags = with_immutable(x.xflags, on);
    // SAFETY: `fd` is open; `x` is a whole struct fsxattr, read by the kernel.
    let r = unsafe { libc::ioctl(fd.as_raw_fd(), FS_IOC_FSSETXATTR, &x as *const FsXattr) };
    if r != 0 { Err(last()) } else { Ok(()) }
}

/// fchown(fd, uid, gid).
pub fn fchown(fd: &OwnedFd, uid: u32, gid: u32) -> io::Result<()> {
    // SAFETY: `fd` is open.
    let r = unsafe { libc::fchown(fd.as_raw_fd(), uid, gid) };
    if r != 0 { Err(last()) } else { Ok(()) }
}

/// flistxattr(fd, buf): the NUL-separated attribute names, into a caller's fixed buffer.
pub fn list_xattrs(fd: &OwnedFd, buf: &mut [u8]) -> io::Result<usize> {
    // SAFETY: `fd` is open; `buf` is writable for its length.
    let n = unsafe { libc::flistxattr(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
    if n < 0 { Err(last()) } else { Ok(n as usize) }
}

/// fsync(fd) on any descriptor (A2: the fill's placed files, and the marker).
pub fn fsync_fd(fd: &OwnedFd) -> io::Result<()> {
    // SAFETY: `fd` is open.
    let r = unsafe { libc::fsync(fd.as_raw_fd()) };
    if r != 0 { Err(last()) } else { Ok(()) }
}

/// openat2(dir, name, { O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW | O_CLOEXEC, mode, BENEATH | NO_SYMLINKS |
/// NO_MAGICLINKS | NO_XDEV }): a new file, created exclusively (the completion marker).
pub fn create_excl(dir: &OwnedFd, name: &CStr, mode: libc::mode_t) -> io::Result<OwnedFd> {
    let how = OpenHow {
        flags: (libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC) as u64,
        mode: mode as u64,
        resolve: libc::RESOLVE_BENEATH | libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_MAGICLINKS | libc::RESOLVE_NO_XDEV,
    };
    // SAFETY: `dir` is open, `name` is NUL-terminated, `how` lives across the call and its size is passed.
    let fd = unsafe {
        libc::syscall(libc::SYS_openat2, dir.as_raw_fd(), name.as_ptr(), &how as *const OpenHow, core::mem::size_of::<OpenHow>())
    };
    own(fd)
}

/// openat2(root, rel, { flags | O_CLOEXEC, 0, RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS }): the restore child's closed
/// system set only (A2 §3 step 6). Ordinary symlinks are followed INSIDE the root (a distro's /etc/resolv.conf is
/// often one); magic links never are. RESOLVE_NO_XDEV is deliberately NOT used: resolv.conf may end on /run. The
/// caller checks the opened object (its kind, root ownership, no group or other write).
pub fn open_system(root: &OwnedFd, rel: &CStr, flags: libc::c_int) -> io::Result<OwnedFd> {
    let how = OpenHow { flags: (flags | libc::O_CLOEXEC) as u64, mode: 0, resolve: libc::RESOLVE_IN_ROOT | libc::RESOLVE_NO_MAGICLINKS };
    // SAFETY: `root` is open, `rel` is NUL-terminated, `how` lives across the call and its size is passed.
    let fd = unsafe {
        libc::syscall(libc::SYS_openat2, root.as_raw_fd(), rel.as_ptr(), &how as *const OpenHow, core::mem::size_of::<OpenHow>())
    };
    own(fd)
}

/// readlinkat(dir, name, buf): a link's target text, at most buf.len() bytes (A2: proc/self/exe through the root).
pub fn readlinkat(dir: &OwnedFd, name: &CStr, buf: &mut [u8]) -> io::Result<usize> {
    // SAFETY: `dir` is open, `name` is NUL-terminated, `buf` is writable for its length.
    let n = unsafe { libc::readlinkat(dir.as_raw_fd(), name.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
    if n < 0 { Err(last()) } else { Ok(n as usize) }
}

/// pread(fd, buf, off): bounded reads of the release binary's ELF headers (A2 S-a).
pub fn pread(fd: &OwnedFd, buf: &mut [u8], off: u64) -> io::Result<usize> {
    // SAFETY: `fd` is open; `buf` is writable for its length.
    let n = unsafe { libc::pread(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), off as libc::off_t) };
    if n < 0 { Err(last()) } else { Ok(n as usize) }
}

/// syncfs(fd): everything written on the filesystem, made durable (A2 O1, before the marker).
pub fn syncfs(fd: &OwnedFd) -> io::Result<()> {
    // SAFETY: `fd` is open.
    let r = unsafe { libc::syncfs(fd.as_raw_fd()) };
    if r != 0 { Err(last()) } else { Ok(()) }
}

/// The project-quota fields A2 §3.1 reads, copied out of `struct if_dqblk`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Quota {
    pub bhard: u64,
    pub bsoft: u64,
    pub curspace: u64,
    pub ihard: u64,
    pub isoft: u64,
    pub curinodes: u64,
    pub btime: u64,
    pub itime: u64,
    pub valid: u32,
}

/// quotactl_fd(fd, QCMD(Q_GETQUOTA, PRJQUOTA), projid, &dqblk) (Linux 5.14+).
pub fn project_quota(fd: &OwnedFd, projid: u32) -> io::Result<Quota> {
    let mut q = libc::dqblk {
        dqb_bhardlimit: 0,
        dqb_bsoftlimit: 0,
        dqb_curspace: 0,
        dqb_ihardlimit: 0,
        dqb_isoftlimit: 0,
        dqb_curinodes: 0,
        dqb_btime: 0,
        dqb_itime: 0,
        dqb_valid: 0,
    };
    let cmd = (Q_GETQUOTA << 8) | (PRJQUOTA & 0xff);
    // SAFETY: `fd` is open; `q` is a whole, zeroed struct if_dqblk the kernel fills.
    let r = unsafe { libc::syscall(libc::SYS_quotactl_fd, fd.as_raw_fd(), cmd as libc::c_uint, projid as libc::c_uint, &mut q as *mut libc::dqblk) };
    if r != 0 {
        return Err(last());
    }
    Ok(Quota {
        bhard: q.dqb_bhardlimit,
        bsoft: q.dqb_bsoftlimit,
        curspace: q.dqb_curspace,
        ihard: q.dqb_ihardlimit,
        isoft: q.dqb_isoftlimit,
        curinodes: q.dqb_curinodes,
        btime: q.dqb_btime,
        itime: q.dqb_itime,
        valid: q.dqb_valid,
    })
}

/// fstatfs(fd): (f_bavail, f_ffree), the filesystem half of A2 §3.1.
pub fn space_left(fd: &OwnedFd) -> io::Result<(u64, u64)> {
    let mut buf = StatFs { head: [0; 7], fsid: [0; 2], tail: [0; 7] };
    // SAFETY: `fd` is open; `buf` is writable for a whole struct statfs (asserted above).
    let r = unsafe { libc::syscall(libc::SYS_fstatfs, fd.as_raw_fd(), &mut buf as *mut StatFs) };
    if r != 0 {
        return Err(last());
    }
    // struct statfs (64-bit): f_type, f_bsize, f_blocks, f_bfree, f_bavail, f_files, f_ffree, then f_fsid.
    Ok((buf.head[4], buf.head[6]))
}

/// The current time in seconds since the epoch (A2 §3.1's grace comparison).
pub fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

// ---- A2: restore-stage's child process.

/// pipe2(O_CLOEXEC): (read end, write end).
pub fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `fds` is writable for two ints.
    let r = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    if r != 0 {
        return Err(last());
    }
    Ok((own(fds[0] as libc::c_long)?, own(fds[1] as libc::c_long)?))
}

/// fork(): Ok(0) in the child, Ok(pid) in the parent. The launcher has one thread, so the child may allocate.
pub fn fork() -> io::Result<libc::pid_t> {
    // SAFETY: the process is single-threaded (no thread is ever spawned), so the child inherits a consistent state.
    let pid = unsafe { libc::fork() };
    if pid < 0 { Err(last()) } else { Ok(pid) }
}

/// waitpid(pid, &status, flags): (pid or 0, status).
pub fn waitpid(pid: libc::pid_t, flags: libc::c_int) -> io::Result<(libc::pid_t, libc::c_int)> {
    let mut status: libc::c_int = 0;
    // SAFETY: `status` is writable for an int.
    let r = unsafe { libc::waitpid(pid, &mut status, flags) };
    if r < 0 { Err(last()) } else { Ok((r, status)) }
}

/// kill(pid, sig).
pub fn kill(pid: libc::pid_t, sig: libc::c_int) -> io::Result<()> {
    // SAFETY: plain integer arguments.
    let r = unsafe { libc::kill(pid, sig) };
    if r != 0 { Err(last()) } else { Ok(()) }
}

/// getpid() and getppid().
pub fn getpid() -> libc::pid_t {
    // SAFETY: no arguments; cannot fail.
    unsafe { libc::getpid() }
}
pub fn getppid() -> libc::pid_t {
    // SAFETY: no arguments; cannot fail.
    unsafe { libc::getppid() }
}

/// sigprocmask(how, {SIGTERM}, NULL): block SIGTERM in the parent (read through a signalfd), unblock it in the child.
pub fn sigterm_mask(block: bool) -> io::Result<()> {
    let mut set = core::mem::MaybeUninit::<libc::sigset_t>::uninit();
    // SAFETY: `set` is writable for a sigset_t; sigemptyset initializes it, then sigaddset adds one valid signal.
    let r = unsafe { libc::sigemptyset(set.as_mut_ptr()) };
    if r != 0 {
        return Err(last());
    }
    // SAFETY (§6 conversion 2): sigemptyset returned 0, so the set is initialized.
    let mut set = unsafe { set.assume_init() };
    // SAFETY: `set` is an initialized sigset_t; SIGTERM is a valid signal.
    let r = unsafe { libc::sigaddset(&mut set, libc::SIGTERM) };
    if r != 0 {
        return Err(last());
    }
    let how = if block { libc::SIG_BLOCK } else { libc::SIG_UNBLOCK };
    // SAFETY: `set` is initialized; the old set isn't asked for.
    let r = unsafe { libc::sigprocmask(how, &set, core::ptr::null_mut()) };
    if r != 0 { Err(last()) } else { Ok(()) }
}

/// signalfd(-1, {SIGTERM}, SFD_CLOEXEC | SFD_NONBLOCK): the parent's forwarded SIGTERM, read in its poll loop.
pub fn sigterm_fd() -> io::Result<OwnedFd> {
    let mut set = core::mem::MaybeUninit::<libc::sigset_t>::uninit();
    // SAFETY: as in sigterm_mask.
    let r = unsafe { libc::sigemptyset(set.as_mut_ptr()) };
    if r != 0 {
        return Err(last());
    }
    // SAFETY (§6 conversion 2): sigemptyset returned 0.
    let mut set = unsafe { set.assume_init() };
    // SAFETY: `set` is initialized; SIGTERM is valid.
    let r = unsafe { libc::sigaddset(&mut set, libc::SIGTERM) };
    if r != 0 {
        return Err(last());
    }
    // SAFETY: `set` is initialized; -1 asks for a new descriptor.
    let fd = unsafe { libc::signalfd(-1, &set, libc::SFD_CLOEXEC | libc::SFD_NONBLOCK) };
    own(fd as libc::c_long)
}

/// poll(fds, timeout_ms): the parent's one wait (A2 S-b).
pub fn poll(fds: &mut [libc::pollfd], timeout_ms: libc::c_int) -> io::Result<usize> {
    // SAFETY: `fds` is a writable slice of pollfd of the length passed.
    let n = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout_ms) };
    if n < 0 { Err(last()) } else { Ok(n as usize) }
}

/// read(fd, buf).
pub fn read(fd: &OwnedFd, buf: &mut [u8]) -> io::Result<usize> {
    // SAFETY: `fd` is open; `buf` is writable for its length.
    let n = unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
    if n < 0 { Err(last()) } else { Ok(n as usize) }
}

/// write(fd, buf): bytes written.
pub fn write(fd: &OwnedFd, buf: &[u8]) -> io::Result<usize> {
    // SAFETY: `fd` is open; `buf` is readable for its length.
    let n = unsafe { libc::write(fd.as_raw_fd(), buf.as_ptr().cast(), buf.len()) };
    if n < 0 { Err(last()) } else { Ok(n as usize) }
}

/// dup2(from, to) onto a raw slot (0, 1 or 2) in the child.
pub fn dup2(from: &OwnedFd, to: libc::c_int) -> io::Result<()> {
    // SAFETY: `from` is open; `to` is one of the three standard slots.
    let r = unsafe { libc::dup2(from.as_raw_fd(), to) };
    if r < 0 { Err(last()) } else { Ok(()) }
}

/// close_range(3, ~0U, CLOSE_RANGE_CLOEXEC): every descriptor above 2 marked close-on-exec, DELIBERATELY not closed
/// (A2 r3.2 P3): execveat still needs the release fd, and the status pipe must close at the exec itself.
pub fn cloexec_from_3() -> io::Result<()> {
    // SAFETY: constant arguments; marking descriptors close-on-exec closes nothing now.
    let r = unsafe { libc::syscall(libc::SYS_close_range, 3 as libc::c_uint, libc::c_uint::MAX, libc::CLOSE_RANGE_CLOEXEC as libc::c_uint) };
    if r != 0 { Err(last()) } else { Ok(()) }
}

/// _exit(code): the child's end on any pre-exec failure (no destructors, no stdio flush).
pub fn exit_now(code: libc::c_int) -> ! {
    // SAFETY: _exit never returns and takes a plain int.
    unsafe { libc::_exit(code) }
}

/// prctl(PR_SET_PDEATHSIG, SIGKILL).
pub fn pdeathsig_kill() -> io::Result<()> {
    // SAFETY: constant arguments.
    let r = unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL as libc::c_ulong, 0 as libc::c_ulong, 0 as libc::c_ulong, 0 as libc::c_ulong) };
    if r != 0 { Err(last()) } else { Ok(()) }
}

/// unshare(CLONE_NEWNS).
pub fn unshare_mount_ns() -> io::Result<()> {
    // SAFETY: a constant flag.
    let r = unsafe { libc::unshare(libc::CLONE_NEWNS) };
    if r != 0 { Err(last()) } else { Ok(()) }
}

/// mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL): nothing this namespace mounts propagates back.
pub fn make_root_private() -> io::Result<()> {
    // SAFETY: the path is a NUL-terminated literal; the other pointers are NULL as the call allows.
    let r = unsafe { libc::mount(core::ptr::null(), c"/".as_ptr(), core::ptr::null(), libc::MS_REC | libc::MS_PRIVATE, core::ptr::null()) };
    if r != 0 { Err(last()) } else { Ok(()) }
}

/// A detached tmpfs: fsopen("tmpfs"), fsconfig(size, mode), FSCONFIG_CMD_CREATE, fsmount(nosuid, nodev).
pub fn tmpfs(size: &CStr, mode: &CStr) -> io::Result<OwnedFd> {
    // SAFETY: the name is a NUL-terminated literal.
    let fs = own(unsafe { libc::syscall(libc::SYS_fsopen, c"tmpfs".as_ptr(), libc::FSOPEN_CLOEXEC) })?;
    for (k, v) in [(c"size", size), (c"mode", mode)] {
        // SAFETY: `fs` is an open fs context; key and value are NUL-terminated.
        let r = unsafe { libc::syscall(libc::SYS_fsconfig, fs.as_raw_fd(), FSCONFIG_SET_STRING, k.as_ptr(), v.as_ptr(), 0) };
        if r != 0 {
            return Err(last());
        }
    }
    // SAFETY: `fs` is open; CMD_CREATE takes no key or value.
    let r = unsafe { libc::syscall(libc::SYS_fsconfig, fs.as_raw_fd(), FSCONFIG_CMD_CREATE, core::ptr::null::<libc::c_char>(), core::ptr::null::<libc::c_void>(), 0) };
    if r != 0 {
        return Err(last());
    }
    let attrs = libc::MOUNT_ATTR_NOSUID | libc::MOUNT_ATTR_NODEV;
    // SAFETY: `fs` is an open, created fs context.
    own(unsafe { libc::syscall(libc::SYS_fsmount, fs.as_raw_fd(), libc::FSMOUNT_CLOEXEC, attrs) })
}

/// mount_setattr(mnt, "", AT_EMPTY_PATH, { attr_set }): read-only, nosuid, nodev, noexec as asked.
pub fn mount_set(mnt: &OwnedFd, attr_set: u64) -> io::Result<()> {
    let attr = MountAttr { attr_set, attr_clr: 0, propagation: 0, userns_fd: 0 };
    // SAFETY: `mnt` is an open mount fd; `attr` lives across the call and its size is passed.
    let r = unsafe {
        libc::syscall(libc::SYS_mount_setattr, mnt.as_raw_fd(), c"".as_ptr(), libc::AT_EMPTY_PATH, &attr as *const MountAttr, core::mem::size_of::<MountAttr>())
    };
    if r != 0 { Err(last()) } else { Ok(()) }
}

/// fchdir(fd).
pub fn fchdir(fd: &OwnedFd) -> io::Result<()> {
    // SAFETY: `fd` is open.
    let r = unsafe { libc::fchdir(fd.as_raw_fd()) };
    if r != 0 { Err(last()) } else { Ok(()) }
}

/// pivot_root(".", "."), then umount2(".", MNT_DETACH), then chdir("/"): the old root stacked under the new one is
/// detached, and only the new root remains in this namespace.
pub fn pivot_here() -> io::Result<()> {
    // SAFETY: both paths are NUL-terminated literals.
    let r = unsafe { libc::syscall(libc::SYS_pivot_root, c".".as_ptr(), c".".as_ptr()) };
    if r != 0 {
        return Err(last());
    }
    // SAFETY: a NUL-terminated literal; constant flags.
    let r = unsafe { libc::umount2(c".".as_ptr(), libc::MNT_DETACH) };
    if r != 0 {
        return Err(last());
    }
    // SAFETY: a NUL-terminated literal.
    let r = unsafe { libc::chdir(c"/".as_ptr()) };
    if r != 0 { Err(last()) } else { Ok(()) }
}

/// umask(0): A2 sets every created mode explicitly (r3, O9).
pub fn umask0() {
    // SAFETY: a plain integer argument; umask cannot fail.
    unsafe { libc::umask(0) };
}

/// The capability header and two data words for version 3 (linux/capability.h): plain data.
#[repr(C)]
struct CapHeader {
    version: u32,
    pid: libc::c_int,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}
const _: () = assert!(core::mem::size_of::<CapHeader>() == 8 && core::mem::size_of::<CapData>() == 12);

/// capget for this process: (effective, permitted, inheritable), each a 64-bit mask.
pub fn capget() -> io::Result<(u64, u64, u64)> {
    let mut h = CapHeader { version: LINUX_CAPABILITY_VERSION_3, pid: 0 };
    let mut d = [CapData::default(); 2];
    // SAFETY: `h` is a valid header; `d` has room for exactly the two words version 3 writes.
    let r = unsafe { libc::syscall(libc::SYS_capget, &mut h as *mut CapHeader, d.as_mut_ptr()) };
    if r != 0 || h.version != LINUX_CAPABILITY_VERSION_3 {
        return Err(if r != 0 { last() } else { io::Error::from_raw_os_error(libc::EINVAL) });
    }
    let join = |lo: u32, hi: u32| (lo as u64) | ((hi as u64) << 32);
    Ok((join(d[0].effective, d[1].effective), join(d[0].permitted, d[1].permitted), join(d[0].inheritable, d[1].inheritable)))
}

/// capset for this process: (effective, permitted, inheritable).
pub fn capset(effective: u64, permitted: u64, inheritable: u64) -> io::Result<()> {
    let mut h = CapHeader { version: LINUX_CAPABILITY_VERSION_3, pid: 0 };
    let d = [
        CapData { effective: effective as u32, permitted: permitted as u32, inheritable: inheritable as u32 },
        CapData { effective: (effective >> 32) as u32, permitted: (permitted >> 32) as u32, inheritable: (inheritable >> 32) as u32 },
    ];
    // SAFETY: `h` is a valid header; `d` holds exactly the two words version 3 reads.
    let r = unsafe { libc::syscall(libc::SYS_capset, &mut h as *mut CapHeader, d.as_ptr()) };
    if r != 0 { Err(last()) } else { Ok(()) }
}

/// prctl(PR_CAPBSET_READ, cap): Ok(true/false), or EINVAL past the kernel's last capability.
pub fn capbset_read(cap: u32) -> io::Result<bool> {
    // SAFETY: plain integer arguments.
    let r = unsafe { libc::prctl(libc::PR_CAPBSET_READ, cap as libc::c_ulong, 0 as libc::c_ulong, 0 as libc::c_ulong, 0 as libc::c_ulong) };
    if r < 0 { Err(last()) } else { Ok(r == 1) }
}

/// prctl(PR_CAPBSET_DROP, cap).
pub fn capbset_drop(cap: u32) -> io::Result<()> {
    // SAFETY: plain integer arguments.
    let r = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap as libc::c_ulong, 0 as libc::c_ulong, 0 as libc::c_ulong, 0 as libc::c_ulong) };
    if r != 0 { Err(last()) } else { Ok(()) }
}

/// prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL).
pub fn ambient_clear() -> io::Result<()> {
    // SAFETY: constant arguments.
    let r = unsafe { libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_CLEAR_ALL as libc::c_ulong, 0 as libc::c_ulong, 0 as libc::c_ulong, 0 as libc::c_ulong) };
    if r != 0 { Err(last()) } else { Ok(()) }
}

/// prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, cap).
pub fn ambient_is_set(cap: u32) -> io::Result<bool> {
    // SAFETY: plain integer arguments.
    let r = unsafe { libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_IS_SET as libc::c_ulong, cap as libc::c_ulong, 0 as libc::c_ulong, 0 as libc::c_ulong) };
    if r < 0 { Err(last()) } else { Ok(r == 1) }
}

// landlock_add_rule for a NET_PORT rule is never needed: the restore ruleset handles only BIND_TCP (no rule allows a
// bind), and CONNECT_TCP is left unhandled, which is "connect on any port" (Landlock's net rules are per port).

/// execveat(dir, name, argv, envp, 0). Returns only on failure.
pub fn execveat(dir: &OwnedFd, name: &CStr, argv: &[*const libc::c_char], envp: &[*const libc::c_char]) -> io::Error {
    debug_assert!(argv.last() == Some(&core::ptr::null()) && envp.last() == Some(&core::ptr::null()));
    // SAFETY: `dir` is open; `name` is NUL-terminated; both arrays end with NULL and point to live strings.
    unsafe { libc::syscall(libc::SYS_execveat, dir.as_raw_fd(), name.as_ptr(), argv.as_ptr(), envp.as_ptr(), 0) };
    last()
}

/// pidfd_open(pid, 0): a descriptor that polls readable when the child exits (A2 §3 step 9: the parent's one loop).
pub fn pidfd_open(pid: libc::pid_t) -> io::Result<OwnedFd> {
    // SAFETY: plain integer arguments.
    own(unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0 as libc::c_uint) })
}

/// openat2(root, rel, { O_PATH | O_DIRECTORY | O_CLOEXEC, 0, RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS |
/// RESOLVE_NO_MAGICLINKS }): a directory by its path from the root, crossing mounts (A2: the restore child re-opens
/// the attempt inside its new mount namespace; the caller checks its identity).
pub fn open_path_dir(root: &OwnedFd, rel: &CStr) -> io::Result<OwnedFd> {
    openat2(root, rel, libc::O_PATH | libc::O_DIRECTORY, 0)
}

/// flock(fd, LOCK_SH | LOCK_NB) (A3 §2 step 3): Ok(true) when taken, Ok(false) when another description holds it
/// exclusive (EWOULDBLOCK); any other error is returned.
pub fn flock_shared_nb(fd: &OwnedFd) -> io::Result<bool> {
    // SAFETY: `fd` is an open descriptor; the operation is a constant.
    let r = unsafe { libc::flock(fd.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) };
    if r == 0 {
        return Ok(true);
    }
    let e = last();
    if e.raw_os_error() == Some(libc::EWOULDBLOCK) { Ok(false) } else { Err(e) }
}

/// clock_gettime(CLOCK_BOOTTIME) (A3 §2 step 5): (tv_sec, tv_nsec), counting time spent in suspend.
pub fn clock_boottime() -> io::Result<(i64, i64)> {
    let mut ts = core::mem::MaybeUninit::<libc::timespec>::uninit();
    // SAFETY: `ts` is writable for a whole timespec; the clock id is a constant.
    let r = unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, ts.as_mut_ptr()) };
    if r != 0 {
        return Err(last());
    }
    // SAFETY: clock_gettime returned 0, so the kernel initialized the timespec.
    let ts = unsafe { ts.assume_init() };
    Ok((ts.tv_sec as i64, ts.tv_nsec as i64))
}

// ---- launcher contract amendment A5 (turn): the unit's namespaces, the user namespace, the idmapped mount.

/// pidfd_send_signal(pidfd, 0, NULL, 0): Ok if the process the pidfd names is still alive (ESRCH once it's gone).
pub fn pidfd_alive(pidfd: &OwnedFd) -> io::Result<()> {
    // SAFETY: `pidfd` is open; signal 0 delivers nothing; the info pointer is NULL as the call allows.
    let r = unsafe { libc::syscall(libc::SYS_pidfd_send_signal, pidfd.as_raw_fd(), 0, core::ptr::null::<libc::siginfo_t>(), 0 as libc::c_uint) };
    if r != 0 { Err(last()) } else { Ok(()) }
}

/// setns(pidfd, nstype): join the namespaces `nstype` names, of the process the pidfd names (Linux 5.8+).
pub fn setns(pidfd: &OwnedFd, nstype: libc::c_int) -> io::Result<()> {
    // SAFETY: `pidfd` is open; `nstype` is a set of CLONE_NEW* constants.
    let r = unsafe { libc::setns(pidfd.as_raw_fd(), nstype) };
    if r != 0 { Err(last()) } else { Ok(()) }
}

/// unshare(CLONE_NEWUSER): only in the user-namespace child, which then waits to be reaped.
pub fn unshare_user() -> io::Result<()> {
    // SAFETY: a constant flag.
    let r = unsafe { libc::unshare(libc::CLONE_NEWUSER) };
    if r != 0 { Err(last()) } else { Ok(()) }
}

/// openat(nsdir, name, O_RDONLY | O_CLOEXEC | O_NOCTTY): ONE namespace entry beneath an opened `/proc/<pid>/ns`
/// handle. Those entries are magic links, which openat2's RESOLVE_BENEATH and RESOLVE_NO_SYMLINKS refuse by design,
/// so this is the one plain openat: one fixed component, relative to a handle the caller opened with openat2 and
/// checked, and the caller checks the result's namespace type (A5 r4.6 step 6).
pub fn open_ns_entry(nsdir: &OwnedFd, name: &CStr) -> io::Result<OwnedFd> {
    // SAFETY: `nsdir` is open; `name` is NUL-terminated; the flags are constants.
    let fd = unsafe { libc::openat(nsdir.as_raw_fd(), name.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOCTTY) };
    own(fd as libc::c_long)
}

/// ioctl(fd, NS_GET_NSTYPE): the CLONE_NEW* type of the namespace a namespace descriptor names.
pub fn ns_type(fd: &OwnedFd) -> io::Result<libc::c_int> {
    // SAFETY: `fd` is open; NS_GET_NSTYPE takes no argument and returns the type.
    let r = unsafe { libc::ioctl(fd.as_raw_fd(), libc::NS_GET_NSTYPE) };
    if r < 0 { Err(last()) } else { Ok(r) }
}

/// mount_setattr(clone, "", AT_EMPTY_PATH, { attr_set: MOUNT_ATTR_IDMAP, userns_fd }): idmap a detached clone.
pub fn mount_setattr_idmap(clone: &OwnedFd, userns: &OwnedFd) -> io::Result<()> {
    let attr = MountAttr { attr_set: libc::MOUNT_ATTR_IDMAP, attr_clr: 0, propagation: 0, userns_fd: userns.as_raw_fd() as u64 };
    // SAFETY: `clone` is an open mount fd and `userns` an open user-namespace fd; `attr` lives across the call and
    // its size is passed.
    let r = unsafe {
        libc::syscall(libc::SYS_mount_setattr, clone.as_raw_fd(), c"".as_ptr(), libc::AT_EMPTY_PATH, &attr as *const MountAttr, core::mem::size_of::<MountAttr>())
    };
    if r != 0 { Err(last()) } else { Ok(()) }
}

// ---- A5 (turn): the status and go pipes, the stdio check, the setid and its read-back.

/// fcntl(fd, F_SETFD, FD_CLOEXEC) on an inherited descriptor number (fds 3 and 4, §1's first action).
pub fn fd_cloexec(fd: libc::c_int) -> io::Result<()> {
    // SAFETY: plain integer arguments; an invalid fd is EBADF.
    let r = unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
    if r != 0 { Err(last()) } else { Ok(()) }
}

/// Whether `fd` is a pipe opened write-only (fstat S_IFIFO, then F_GETFL's access mode).
pub fn fd_is_pipe_writer(fd: libc::c_int) -> io::Result<bool> {
    let mut st = core::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `st` is writable for a whole stat; an invalid fd is EBADF.
    let r = unsafe { libc::fstat(fd, st.as_mut_ptr()) };
    if r != 0 {
        return Err(last());
    }
    // SAFETY (§6 conversion 2): fstat returned 0, so the kernel initialized the whole struct.
    let st = unsafe { st.assume_init() };
    // SAFETY: plain integer arguments.
    let fl = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if fl < 0 {
        return Err(last());
    }
    Ok(st.st_mode & libc::S_IFMT == libc::S_IFIFO && fl & libc::O_ACCMODE == libc::O_WRONLY)
}

/// Whether `fd` is an AF_UNIX SOCK_STREAM socket (fstat S_IFSOCK, then SO_DOMAIN and SO_TYPE).
pub fn fd_is_unix_stream(fd: libc::c_int) -> io::Result<bool> {
    let mut st = core::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `st` is writable for a whole stat; an invalid fd is EBADF.
    let r = unsafe { libc::fstat(fd, st.as_mut_ptr()) };
    if r != 0 {
        return Err(last());
    }
    // SAFETY (§6 conversion 2): fstat returned 0, so the kernel initialized the whole struct.
    let st = unsafe { st.assume_init() };
    if st.st_mode & libc::S_IFMT != libc::S_IFSOCK {
        return Ok(false);
    }
    let opt = |name: libc::c_int| -> io::Result<libc::c_int> {
        let mut v: libc::c_int = 0;
        let mut len = core::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: `v` and `len` are writable and `len` holds v's size.
        let r = unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, name, (&mut v as *mut libc::c_int).cast(), &mut len) };
        if r != 0 { Err(last()) } else { Ok(v) }
    };
    Ok(opt(libc::SO_DOMAIN)? == libc::AF_UNIX && opt(libc::SO_TYPE)? == libc::SOCK_STREAM)
}

/// close_range(from, ~0U, 0): every descriptor from `from` up.
pub fn close_range_from(from: libc::c_uint) -> io::Result<()> {
    // SAFETY: plain integer arguments; no OwnedFd the caller still holds is at or above `from` (the caller's duty).
    let r = unsafe { libc::syscall(libc::SYS_close_range, from, libc::c_uint::MAX, 0 as libc::c_uint) };
    if r != 0 { Err(last()) } else { Ok(()) }
}

/// write(fd, buf) on an inherited descriptor number (the status pipe, fd 3).
pub fn write_raw(fd: libc::c_int, buf: &[u8]) -> io::Result<usize> {
    // SAFETY: `buf` is readable for its length; an invalid fd is EBADF.
    let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
    if n < 0 { Err(last()) } else { Ok(n as usize) }
}

/// read(fd, buf) on an inherited descriptor number (the go pipe, fd 4).
pub fn read_raw(fd: libc::c_int, buf: &mut [u8]) -> io::Result<usize> {
    // SAFETY: `buf` is writable for its length; an invalid fd is EBADF.
    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    if n < 0 { Err(last()) } else { Ok(n as usize) }
}

/// setgroups(gids).
pub fn setgroups(gids: &[u32]) -> io::Result<()> {
    // SAFETY: `gids` is readable for its length (gid_t is u32 on Linux).
    let r = unsafe { libc::setgroups(gids.len(), gids.as_ptr()) };
    if r != 0 { Err(last()) } else { Ok(()) }
}

/// setresgid(g, g, g).
pub fn setresgid(g: u32) -> io::Result<()> {
    // SAFETY: plain integer arguments.
    let r = unsafe { libc::setresgid(g, g, g) };
    if r != 0 { Err(last()) } else { Ok(()) }
}

/// setresuid(u, u, u).
pub fn setresuid(u: u32) -> io::Result<()> {
    // SAFETY: plain integer arguments.
    let r = unsafe { libc::setresuid(u, u, u) };
    if r != 0 { Err(last()) } else { Ok(()) }
}

/// getresuid(): (real, effective, saved).
pub fn getresuid() -> io::Result<(u32, u32, u32)> {
    let (mut r, mut e, mut s) = (0, 0, 0);
    // SAFETY: the three are writable.
    let x = unsafe { libc::getresuid(&mut r, &mut e, &mut s) };
    if x != 0 { Err(last()) } else { Ok((r, e, s)) }
}

/// getresgid(): (real, effective, saved).
pub fn getresgid() -> io::Result<(u32, u32, u32)> {
    let (mut r, mut e, mut s) = (0, 0, 0);
    // SAFETY: the three are writable.
    let x = unsafe { libc::getresgid(&mut r, &mut e, &mut s) };
    if x != 0 { Err(last()) } else { Ok((r, e, s)) }
}

/// getgroups(): the supplementary groups (at most 65536).
pub fn getgroups() -> io::Result<Vec<u32>> {
    let mut v = vec![0u32; 65536];
    // SAFETY: `v` is writable for its length.
    let n = unsafe { libc::getgroups(v.len() as libc::c_int, v.as_mut_ptr()) };
    if n < 0 {
        return Err(last());
    }
    v.truncate(n as usize);
    Ok(v)
}

/// fcntl(fd, F_GETFD): a descriptor's flags (tests only: they read back FD_CLOEXEC).
#[cfg(test)]
pub fn fd_flags(fd: libc::c_int) -> io::Result<libc::c_int> {
    // SAFETY: plain integer arguments; an invalid fd is EBADF.
    let r = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if r < 0 { Err(last()) } else { Ok(r) }
}

/// dup(fd): a new, inheritable descriptor (no FD_CLOEXEC), the lowest free number (tests only).
#[cfg(test)]
pub fn dup_inheritable(from: &OwnedFd) -> io::Result<libc::c_int> {
    // SAFETY: `from` is open; dup takes a plain integer and returns a new descriptor or -1.
    let r = unsafe { libc::dup(from.as_raw_fd()) };
    if r < 0 { Err(last()) } else { Ok(r) }
}
