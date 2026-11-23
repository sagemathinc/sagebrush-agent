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
