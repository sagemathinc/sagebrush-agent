//! The Landlock uapi this binary needs, ABI 4, copied field for field from ONE pinned upstream header:
//!
//!   https://raw.githubusercontent.com/torvalds/linux/v6.8/include/uapi/linux/landlock.h
//!   revision: tag v6.8 (Linux 6.8, Ubuntu 24.04's kernel series); sha256 of the file:
//!   edd4f072270e389cb5cd7ab8ca34753640e58089464bfdf48cb594912ee6b61e
//!
//! Plain #[repr(C)] data and constants; no unsafe here. Every size, alignment, offset and value used is asserted at
//! compile time below. A packed field is never referenced: a `PathBeneathAttr` is built by value and passed by raw
//! pointer to the whole struct.

/// struct landlock_ruleset_attr: exactly the ABI-4 fields handled_access_fs and handled_access_net (16 bytes).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct RulesetAttr {
    pub handled_access_fs: u64,
    pub handled_access_net: u64,
}

/// struct landlock_path_beneath_attr: `__attribute__((packed))` upstream, so #[repr(C, packed)] (12 bytes). No
/// Debug or other derive that could take a reference to a field.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct PathBeneathAttr {
    pub allowed_access: u64,
    pub parent_fd: i32,
}

pub const CREATE_RULESET_VERSION: u32 = 1 << 0;
pub const RULE_PATH_BENEATH: u32 = 1;

pub const FS_EXECUTE: u64 = 1 << 0;
pub const FS_WRITE_FILE: u64 = 1 << 1;
pub const FS_READ_FILE: u64 = 1 << 2;
pub const FS_READ_DIR: u64 = 1 << 3;
pub const FS_REMOVE_DIR: u64 = 1 << 4;
pub const FS_REMOVE_FILE: u64 = 1 << 5;
pub const FS_MAKE_CHAR: u64 = 1 << 6;
pub const FS_MAKE_DIR: u64 = 1 << 7;
pub const FS_MAKE_REG: u64 = 1 << 8;
pub const FS_MAKE_SOCK: u64 = 1 << 9;
pub const FS_MAKE_FIFO: u64 = 1 << 10;
pub const FS_MAKE_BLOCK: u64 = 1 << 11;
pub const FS_MAKE_SYM: u64 = 1 << 12;
pub const FS_REFER: u64 = 1 << 13;
pub const FS_TRUNCATE: u64 = 1 << 14;

/// handled_access_fs: every filesystem right through TRUNCATE (bit 14). ABI 5's IOCTL_DEV (bit 15) is excluded.
pub const FS_HANDLED: u64 = (FS_TRUNCATE << 1) - 1;

/// handled_access_net: EMPTY (contract §4 step 4: neither BIND_TCP nor CONNECT_TCP is handled).
pub const NET_HANDLED: u64 = 0;

/// The minimum ABI this binary accepts (contract §4 step 3).
pub const MIN_ABI: i64 = 4;

// ---- compile-time checks against the pinned header

const _: () = assert!(core::mem::size_of::<RulesetAttr>() == 16);
const _: () = assert!(core::mem::align_of::<RulesetAttr>() == 8);
const _: () = assert!(core::mem::offset_of!(RulesetAttr, handled_access_fs) == 0);
const _: () = assert!(core::mem::offset_of!(RulesetAttr, handled_access_net) == 8);
const _: () = assert!(core::mem::size_of::<PathBeneathAttr>() == 12);
const _: () = assert!(core::mem::align_of::<PathBeneathAttr>() == 1);
const _: () = assert!(core::mem::offset_of!(PathBeneathAttr, allowed_access) == 0);
const _: () = assert!(core::mem::offset_of!(PathBeneathAttr, parent_fd) == 8);
const _: () = assert!(CREATE_RULESET_VERSION == 1);
const _: () = assert!(RULE_PATH_BENEATH == 1);
const _: () = assert!(FS_EXECUTE == 0x1 && FS_WRITE_FILE == 0x2 && FS_READ_FILE == 0x4 && FS_READ_DIR == 0x8);
const _: () = assert!(FS_REMOVE_DIR == 0x10 && FS_REMOVE_FILE == 0x20 && FS_MAKE_CHAR == 0x40 && FS_MAKE_DIR == 0x80);
const _: () = assert!(FS_MAKE_REG == 0x100 && FS_MAKE_SOCK == 0x200 && FS_MAKE_FIFO == 0x400 && FS_MAKE_BLOCK == 0x800);
const _: () = assert!(FS_MAKE_SYM == 0x1000 && FS_REFER == 0x2000 && FS_TRUNCATE == 0x4000);
const _: () = assert!(FS_HANDLED == 0x7fff);
const _: () = assert!(NET_HANDLED == 0);

/// Rights for one contract row's access string: exactly "r", "rx", "rw" or "rwx". A non-directory gets only the
/// rights Landlock allows on a file (execute, read, write, truncate).
pub fn rights(access: &str, is_dir: bool) -> Option<u64> {
    let read = FS_READ_FILE | if is_dir { FS_READ_DIR } else { 0 };
    let write = FS_WRITE_FILE
        | FS_TRUNCATE
        | if is_dir {
            FS_REMOVE_DIR | FS_REMOVE_FILE | FS_MAKE_DIR | FS_MAKE_REG | FS_MAKE_SOCK | FS_MAKE_FIFO | FS_MAKE_SYM | FS_REFER
        } else {
            0
        };
    match access {
        "r" => Some(read),
        "rx" => Some(read | FS_EXECUTE),
        "rw" => Some(read | write),
        "rwx" => Some(read | write | FS_EXECUTE),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rights_are_closed_and_never_grant_device_nodes() {
        for a in ["r", "rx", "rw", "rwx"] {
            for d in [false, true] {
                let r = rights(a, d).unwrap();
                assert_eq!(r & (FS_MAKE_CHAR | FS_MAKE_BLOCK), 0);
                assert_eq!(r & !FS_HANDLED, 0);
            }
        }
        for bad in ["x", "w", "rwx ", "", "RWX"] {
            assert_eq!(rights(bad, true), None);
        }
        assert_eq!(rights("r", false).unwrap() & FS_EXECUTE, 0);
        assert_ne!(rights("rx", false).unwrap() & FS_EXECUTE, 0);
        assert_eq!(rights("rx", true).unwrap() & FS_WRITE_FILE, 0);
        // A file row carries only file rights.
        let file_rights = FS_EXECUTE | FS_WRITE_FILE | FS_READ_FILE | FS_TRUNCATE;
        assert_eq!(rights("rwx", false).unwrap() & !file_rights, 0);
    }
}
