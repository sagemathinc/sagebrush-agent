//! `profile-mounts` (launcher contract amendment A4 r2.3 §3): the immutable session mountpoints inside a host harness
//! profile directory, `/srv/sagebrush/claude-profiles/<pid>` (profiles piece 2; the advisor delta r3.2 §8).
//!
//! - `--op create`, at profile creation (the record `creating`, before any login or turn): each declared top-level
//!   subpath becomes an EMPTY directory, root:root 0555, with the ext4 immutable flag set, read back and fsynced. The
//!   output is `[{name, ino, gen}]`, which the supervisor records before the profile is `bound`. On a rerun, an entry
//!   already exactly made is accepted, and so is the one bounded crash residue: the same empty root:root 0555 directory
//!   WITHOUT the flag (a crash between the mkdir and the flag), which this run flags. Anything else is 73.
//! - `--op clear`, at retirement (after the supervisor's drain, login stop and storage-uid proof, A4 §2, and before
//!   `identify` and `remove-tree`): each recorded mountpoint that is present must be its recorded ino and generation, a
//!   root:root directory, empty; its flag is cleared, read back and fsynced. An absent entry is skipped; an already
//!   clear one is a no-op, so retries converge. A mismatch is 73 and no later entry is touched.
//!
//! Both first check the profile directory against the caller's expected identity (`identify`'s own output): the epoch
//! and fsid, then the whole object, a directory with mode 0700 and the project inherit flag. Exits: 0, 64, 66, 73, and
//! 75 once any flag (or a mountpoint) has been changed and something then fails. Every flag change needs
//! CAP_LINUX_IMMUTABLE, which the launcher has as root outside any unit and no agent, turn, login unit or storage uid has.

use crate::args;
use crate::err::{err, Fail, Result};
use crate::json::{self, Value};
use crate::sys;
use crate::tree::{anchor_policy, bad_expect, c, child, epoch_now, epoch_of, fsid_of, identity, obj_of, pre, read_expect, Epoch, Kind, Obj, Ops, RealOps};
use std::io;
use std::os::fd::OwnedFd;

/// The profiles anchor (A4 §1).
pub const PROFILES: &str = "/srv/sagebrush/claude-profiles";
/// At most this many mountpoints per profile (A4 §3).
pub const MAX_SUBPATHS: usize = 16;

/// The four handle operations A4 adds to A1's. `RealOps` maps each to one syscall wrapper in `sys`.
pub trait ProfileOps: Ops {
    /// umask(0), so a new mountpoint's mode is exactly the requested 0555 whatever the caller's umask (an inherited
    /// 0077 would make it 0500), and a crash right after the mkdir leaves exactly the bounded residue.
    fn clear_umask(&mut self);
    fn mkdir(&mut self, dir: &Self::H, name: &str, mode: u16) -> io::Result<()>;
    fn chown(&mut self, h: &Self::H, uid: u32, gid: u32) -> io::Result<()>;
    fn immutable(&mut self, h: &Self::H) -> io::Result<bool>;
    fn set_immutable(&mut self, h: &Self::H, on: bool) -> io::Result<()>;
}

impl ProfileOps for RealOps {
    fn clear_umask(&mut self) {
        sys::umask0();
    }
    fn mkdir(&mut self, dir: &OwnedFd, name: &str, mode: u16) -> io::Result<()> {
        sys::mkdirat(dir, &c(name)?, mode as libc::mode_t)
    }
    fn chown(&mut self, h: &OwnedFd, uid: u32, gid: u32) -> io::Result<()> {
        sys::fchown(h, uid, gid)
    }
    fn immutable(&mut self, h: &OwnedFd) -> io::Result<bool> {
        Ok(sys::xflags(h)? & sys::FS_XFLAG_IMMUTABLE != 0)
    }
    fn set_immutable(&mut self, h: &OwnedFd, on: bool) -> io::Result<()> {
        sys::set_immutable(h, on)
    }
}

/// One top-level component: 1-64 of [A-Za-z0-9._-], not "." or "..".
pub fn subpath_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s != "." && s != ".." && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
}

/// The operation and its arguments, parsed and checked (64 for anything else).
#[derive(Debug, PartialEq, Eq)]
pub enum Op {
    Create { pid: String, subpaths: Vec<String>, expect_dir: String },
    Clear { pid: String, expect: String },
}

/// `--name <pid> --op create --subpath <name>... --expect-dir <file>` or `--name <pid> --op clear --expect <file>`.
pub fn parse(rest: &[String]) -> Result<Op> {
    let bad = || err(Fail::Usage, "bad arguments");
    if rest.len() % 2 != 0 {
        return Err(bad());
    }
    let (mut pid, mut op, mut expect, mut expect_dir, mut subpaths) = (None, None, None, None, Vec::new());
    for pair in rest.chunks(2) {
        let v = pair[1].clone();
        let slot = match pair[0].as_str() {
            "--name" => &mut pid,
            "--op" => &mut op,
            "--expect" => &mut expect,
            "--expect-dir" => &mut expect_dir,
            "--subpath" => {
                if !subpath_ok(&v) || subpaths.contains(&v) || subpaths.len() == MAX_SUBPATHS {
                    return Err(bad());
                }
                subpaths.push(v);
                continue;
            }
            _ => return Err(bad()),
        };
        if slot.is_some() {
            return Err(bad());
        }
        *slot = Some(v);
    }
    let pid = pid.filter(|p| args::is_id(p)).ok_or_else(bad)?;
    let path_ok = |p: &Option<String>| p.as_deref().is_some_and(|p| args::rel(p).is_some());
    match op.as_deref() {
        Some("create") if !subpaths.is_empty() && expect.is_none() && path_ok(&expect_dir) => {
            Ok(Op::Create { pid, subpaths, expect_dir: expect_dir.unwrap() })
        }
        Some("clear") if subpaths.is_empty() && expect_dir.is_none() && path_ok(&expect) => Ok(Op::Clear { pid, expect: expect.unwrap() }),
        _ => Err(bad()),
    }
}

/// The expected profile directory: `identify`'s own output, `{epoch, fsid, object}`, with a non-null object.
fn dir_expect(v: &Value) -> Result<(Epoch, u64, Obj)> {
    let f = v.exact(&["epoch", "fsid", "object"]).ok_or(bad_expect())?;
    Ok((epoch_of(f[0])?, fsid_of(f[1])?, obj_of(f[2])?))
}

/// Open the profile directory and check it is exactly the expected one. Returns its handle and the anchor's mount id.
fn open_profile<O: ProfileOps>(o: &mut O, pid: &str, want: &(Epoch, u64, Obj)) -> Result<(O::H, u64)> {
    let root = o.root().map_err(|_| pre("the root can't be opened"))?;
    let a = anchor_policy(o, &root, PROFILES)?;
    let (epoch, fsid) = epoch_now(o, &root, &a)?;
    if epoch != want.0 {
        return Err(identity("a stale epoch"));
    }
    if fsid != want.1 {
        return Err(identity("another filesystem"));
    }
    match child(o, &a, pid, epoch.mnt_id)? {
        Some((x, Some(h))) if x == want.2 && x.kind == Kind::Dir && x.mode == 0o700 && x.inherit == Some(true) => Ok((h, epoch.mnt_id)),
        _ => Err(identity("the profile directory isn't the expected one")),
    }
}

fn is_empty<O: Ops>(o: &mut O, h: &O::H) -> Result<bool> {
    Ok(o.batch(h).map_err(|_| pre("a mountpoint can't be listed"))?.is_empty())
}

/// 73 before any change, 75 after one.
fn fail(changed: bool, msg: &'static str) -> crate::err::Error {
    if changed { err(Fail::Partial, msg) } else { identity(msg) }
}

/// `--op create` (A4 §3). Returns the closed JSON array, with a trailing newline.
pub fn create<O: ProfileOps>(o: &mut O, pid: &str, subpaths: &[String], expect_dir: &str) -> Result<String> {
    let root = o.root().map_err(|_| pre("the root can't be opened"))?;
    let want = dir_expect(&read_expect(o, &root, expect_dir)?)?;
    let (p, mnt) = open_profile(o, pid, &want)?;
    o.clear_umask();
    let mut changed = false;
    let mut out = Vec::with_capacity(subpaths.len());
    for name in subpaths {
        let found = child(o, &p, name, mnt).map_err(|e| if changed { err(Fail::Partial, "a mountpoint can't be examined") } else { e })?;
        let (x, h) = match found {
            None => {
                o.mkdir(&p, name, 0o555).map_err(|_| fail(changed, "a mountpoint can't be made"))?;
                changed = true;
                let Some((_, Some(h))) = child(o, &p, name, mnt).map_err(|_| fail(true, "a new mountpoint can't be examined"))? else {
                    return Err(fail(true, "a new mountpoint vanished"));
                };
                o.chown(&h, 0, 0).map_err(|_| fail(true, "a new mountpoint can't be owned by root"))?;
                drop(h);
                match child(o, &p, name, mnt).map_err(|_| fail(true, "a new mountpoint can't be examined"))? {
                    Some((x, Some(h))) => (x, h),
                    _ => return Err(fail(true, "a new mountpoint vanished")),
                }
            }
            Some((x, Some(h))) => (x, h),
            Some(_) => return Err(fail(changed, "a mountpoint name holds a symlink")),
        };
        // Exactly what this step makes (immutable already, or the one bounded residue without the flag): a directory,
        // root:root, 0555, empty, with exactly two links (no subdirectory, and nothing hard-linked in).
        let empty = is_empty(o, &h).map_err(|e| if changed { err(Fail::Partial, "a mountpoint can't be listed") } else { e })?;
        let nlink = o.ident(&h).map_err(|_| fail(changed, "a mountpoint can't be examined"))?.nlink;
        if x.kind != Kind::Dir || x.uid != 0 || x.gid != 0 || x.mode != 0o555 || !empty || nlink != 2 {
            return Err(fail(changed, "a mountpoint name holds something else"));
        }
        let flagged = o.immutable(&h).map_err(|_| fail(changed, "a mountpoint's flags can't be read"))?;
        if !flagged {
            o.set_immutable(&h, true).map_err(|_| fail(changed, "a mountpoint can't be made immutable"))?;
            changed = true;
        }
        if !o.immutable(&h).map_err(|_| fail(changed, "a mountpoint's flags can't be read back"))? {
            return Err(fail(changed, "the immutable flag didn't stick"));
        }
        o.fsync(&h).map_err(|_| fail(changed, "a mountpoint can't be made durable"))?;
        out.push(format!("{{\"name\":{},\"ino\":{},\"gen\":{}}}", json::quote(name), x.ino, x.gen.unwrap_or(0)));
    }
    o.fsync(&p).map_err(|_| fail(changed, "the profile directory can't be made durable"))?;
    Ok(format!("[{}]\n", out.join(",")))
}

/// `--op clear` (A4 §3).
pub fn clear<O: ProfileOps>(o: &mut O, pid: &str, expect: &str) -> Result<()> {
    let root = o.root().map_err(|_| pre("the root can't be opened"))?;
    let v = read_expect(o, &root, expect)?;
    let f = v.exact(&["dir", "mountpoints"]).ok_or(bad_expect())?;
    let want = dir_expect(f[0])?;
    let rows = f[1].arr().filter(|a| a.len() <= MAX_SUBPATHS).ok_or(bad_expect())?;
    let mut mps: Vec<(String, u64, u32)> = Vec::with_capacity(rows.len());
    for r in rows {
        let g = r.exact(&["name", "ino", "gen"]).ok_or(bad_expect())?;
        let name = g[0].str().filter(|s| subpath_ok(s)).ok_or(bad_expect())?.to_string();
        if mps.iter().any(|m| m.0 == name) {
            return Err(bad_expect());
        }
        let gen = g[2].int().and_then(|n| u32::try_from(n).ok()).ok_or(bad_expect())?;
        mps.push((name, g[1].int().ok_or(bad_expect())?, gen));
    }
    let (p, mnt) = open_profile(o, pid, &want)?;
    let mut changed = false;
    for (name, ino, gen) in &mps {
        let found = child(o, &p, name, mnt).map_err(|e| if changed { err(Fail::Partial, "a mountpoint can't be examined") } else { e })?;
        let h = match found {
            None => continue, // a retry after remove-tree already unlinked it
            Some((x, Some(h))) if x.kind == Kind::Dir && x.uid == 0 && x.gid == 0 && x.ino == *ino && x.gen == Some(*gen) => h,
            _ => return Err(fail(changed, "a mountpoint isn't the recorded one")),
        };
        let empty = is_empty(o, &h).map_err(|e| if changed { err(Fail::Partial, "a mountpoint can't be listed") } else { e })?;
        if !empty {
            return Err(fail(changed, "a mountpoint isn't empty"));
        }
        if o.immutable(&h).map_err(|_| fail(changed, "a mountpoint's flags can't be read"))? {
            o.set_immutable(&h, false).map_err(|_| fail(changed, "a mountpoint's flag can't be cleared"))?;
            changed = true;
        }
        if o.immutable(&h).map_err(|_| fail(changed, "a mountpoint's flags can't be read back"))? {
            return Err(fail(changed, "the immutable flag didn't clear"));
        }
        o.fsync(&h).map_err(|_| fail(changed, "a mountpoint can't be made durable"))?;
    }
    Ok(())
}

/// The subcommand: arguments (64), the root guard (66), then the operation on the real handles.
pub fn run(rest: &[String]) -> Result<String> {
    let op = parse(rest)?;
    if !sys::is_root() {
        return Err(pre("root only"));
    }
    let mut o = RealOps;
    match op {
        Op::Create { pid, subpaths, expect_dir } => create(&mut o, &pid, &subpaths, &expect_dir),
        Op::Clear { pid, expect } => clear(&mut o, &pid, &expect).map(|()| String::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::tests::{code, e, expect_file, join, Fake, FH, A, BOOT, MNT};
    use crate::tree::{identify, remove_tree, ANCHORS, check_parents, anchor_name_ok};
    use crate::tree::S_IFDIR;

    const SUID: u32 = 90001;
    const PROJ: u32 = 100001;
    const PDIR: &str = "srv/sagebrush/claude-profiles/abcdefghijklmnopqrstuvwxya";

    impl ProfileOps for Fake {
        /// A test knob, "<umask>" holding the octal umask the launcher inherited; clear_umask removes it.
        fn clear_umask(&mut self) {
            self.xattrs.remove("<umask>");
        }
        fn mkdir(&mut self, dir: &FH, name: &str, mode: u16) -> io::Result<()> {
            self.tick("mkdir")?;
            let p = join(&dir.p, name);
            if self.nodes.contains_key(&p) {
                return Err(e(libc::EEXIST));
            }
            let umask = self.xattrs.get("<umask>").and_then(|v| v.first()).map_or(0, |s| u16::from_str_radix(s, 8).unwrap());
            self.add(&p, S_IFDIR | (mode & !umask), 0, 0);
            self.node(&p).id.nlink = 2; // a new, empty directory
            self.log.push(format!("mkdir {p}"));
            Ok(())
        }
        fn chown(&mut self, h: &FH, uid: u32, gid: u32) -> io::Result<()> {
            self.tick("chown")?;
            let n = self.node(&h.p);
            n.id.uid = uid;
            n.id.gid = gid;
            Ok(())
        }
        fn immutable(&mut self, h: &FH) -> io::Result<bool> {
            self.tick("xflags")?;
            Ok(self.nodes[&h.p].immutable)
        }
        fn set_immutable(&mut self, h: &FH, on: bool) -> io::Result<()> {
            self.tick("set_immutable")?;
            self.log.push(format!("immutable {} {on}", h.p));
            // A test knob: a kernel that accepts the ioctl but doesn't keep the flag (the read-back must catch it).
            if !self.xattrs.contains_key("<flag-does-not-stick>") {
                self.node(&h.p).immutable = on;
            }
            Ok(())
        }
    }

    /// A fake host with one profile directory, the storage uid's, 0700, its project with inherit.
    fn fixture() -> Fake {
        let mut f = Fake::new();
        f.dir(PDIR, SUID, 0o700);
        let n = f.node(PDIR);
        n.proj = PROJ;
        n.inherit = true;
        f
    }

    fn dir_file(f: &mut Fake) -> String {
        let id = identify(f, PROFILES, A).unwrap();
        expect_file(f, "dir.json", id.trim_end().to_string())
    }

    /// An existing entry at `p`: a directory gets nlink 2 (empty), as on the kernel.
    fn entry(f: &mut Fake, p: &str, mode: u16, uid: u32, gid: u32) {
        f.add(p, mode, uid, gid);
        if mode & 0o170000 == S_IFDIR {
            f.node(p).id.nlink = 2;
        }
    }

    fn subs(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    fn mp(f: &Fake, name: &str) -> String {
        let n = &f.nodes[&format!("{PDIR}/{name}")];
        format!("{{\"name\":\"{name}\",\"ino\":{},\"gen\":{}}}", n.id.ino, n.gen)
    }

    fn clear_file(f: &mut Fake, rows: &[String]) -> String {
        let dir = identify(f, PROFILES, A).unwrap();
        expect_file(f, "clear.json", format!("{{\"dir\":{},\"mountpoints\":[{}]}}", dir.trim_end(), rows.join(",")))
    }

    #[test]
    fn the_anchor_table_and_check_parents_carry_the_profiles_root() {
        assert_eq!(ANCHORS.len(), 10);
        assert!(anchor_name_ok(PROFILES, A));
        for bad in [".locks", "x/y", "..", "", "ABC", "abcdefghijklmnopqrstuvwxyz"] {
            assert!(!anchor_name_ok(PROFILES, bad), "{bad}");
        }
        let base = || { let mut f = fixture(); f.dir("srv/sagebrush/tags", 0, 0o755); f };
        let mut f = base();
        assert_eq!(code(check_parents(&mut f, "/", false)), 0);
        f.nodes.retain(|k, _| !k.starts_with("srv/sagebrush/claude-profiles"));
        assert_eq!(code(check_parents(&mut f, "/", true)), 0, "missing, allowed");
        assert_eq!(code(check_parents(&mut f, "/", false)), 66, "missing, required");
        for how in ["g+w", "owner", "acl"] {
            let mut f = base();
            let n = f.node("srv/sagebrush/claude-profiles");
            match how {
                "g+w" => n.id.mode |= 0o020,
                "owner" => n.id.uid = SUID,
                _ => n.acl = true,
            }
            assert_eq!(code(check_parents(&mut f, "/", false)), 73, "{how}");
        }
    }

    #[test]
    fn create_makes_each_mountpoint_root_0555_immutable_and_reports_ino_and_gen() {
        let mut f = fixture();
        let d = dir_file(&mut f);
        let out = create(&mut f, A, &subs(&["projects", "todos"]), &d).unwrap();
        for name in ["projects", "todos"] {
            let n = &f.nodes[&format!("{PDIR}/{name}")];
            assert_eq!((n.id.mode & 0o7777, n.id.uid, n.id.gid, n.immutable), (0o555, 0, 0, true), "{name}");
        }
        assert_eq!(out, format!("[{},{}]\n", mp(&f, "projects"), mp(&f, "todos")));
        assert!(f.log.iter().any(|l| l == &format!("fsync {PDIR}")), "the profile directory is synced");
        // A rerun (Node crashed before recording the output): accepted as already made, the same output, no change.
        let (mk, imm) = (f.count("mkdir"), f.count("set_immutable"));
        assert_eq!(create(&mut f, A, &subs(&["projects", "todos"]), &d).unwrap(), out);
        assert_eq!((f.count("mkdir"), f.count("set_immutable")), (mk, imm));
    }

    #[test]
    fn an_inherited_umask_doesnt_change_the_mountpoint_mode() {
        // Under an inherited 0077, mkdirat(0555) alone would make 0500, and create would refuse its own entry.
        let mut f = fixture();
        f.xattrs.insert("<umask>".into(), vec!["077".into()]);
        let d = dir_file(&mut f);
        create(&mut f, A, &subs(&["projects"]), &d).unwrap();
        assert_eq!(f.nodes[&format!("{PDIR}/projects")].id.mode & 0o7777, 0o555);
    }

    #[test]
    fn create_accepts_the_one_bounded_residue_and_flags_it() {
        // A crash between the mkdir and the flag: an empty root:root 0555 directory without the flag.
        let mut f = fixture();
        entry(&mut f, &format!("{PDIR}/projects"), S_IFDIR | 0o555, 0, 0);
        let d = dir_file(&mut f);
        create(&mut f, A, &subs(&["projects"]), &d).unwrap();
        assert!(f.nodes[&format!("{PDIR}/projects")].immutable);
        assert_eq!(f.count("mkdir"), 0);
    }

    #[test]
    fn create_refuses_an_existing_entry_that_differs_with_nothing_changed_or_75_after_a_change() {
        type Spoil = fn(&mut Fake, &str);
        let cases: [(&str, Spoil); 7] = [
            ("owner", |f, p| entry(f, p, S_IFDIR | 0o555, SUID, SUID)),
            ("mode", |f, p| entry(f, p, S_IFDIR | 0o755, 0, 0)),
            ("non-empty", |f, p| { entry(f, p, S_IFDIR | 0o555, 0, 0); f.file(&format!("{p}/x"), SUID, 0o600); }),
            ("a file", |f, p| f.file(p, 0, 0o555)),
            ("a symlink", |f, p| f.add(p, libc::S_IFLNK as u16 | 0o777, 0, 0)),
            ("unflagged but group 1", |f, p| entry(f, p, S_IFDIR | 0o555, 0, 1)),
            ("nlink 3", |f, p| { entry(f, p, S_IFDIR | 0o555, 0, 0); f.node(p).id.nlink = 3; }),
        ];
        for (label, spoil) in cases {
            let mut f = fixture();
            spoil(&mut f, &format!("{PDIR}/projects"));
            let d = dir_file(&mut f);
            assert_eq!(code(create(&mut f, A, &subs(&["projects"]), &d)), 73, "{label}");
            assert_eq!((f.count("mkdir"), f.count("set_immutable")), (0, 0), "{label}: nothing changed");
            // The same entry second, after a first one was made: 75.
            let mut f = fixture();
            spoil(&mut f, &format!("{PDIR}/todos"));
            let d = dir_file(&mut f);
            assert_eq!(code(create(&mut f, A, &subs(&["projects", "todos"]), &d)), 75, "{label} second");
        }
    }

    #[test]
    fn create_and_clear_refuse_a_profile_directory_other_than_the_expected_one() {
        type Spoil = fn(&mut Fake);
        let cases: [(&str, Spoil); 5] = [
            ("another inode", |f| { let n = f.node(PDIR); n.id.ino += 1000; }),
            ("mode 0750", |f| { f.node(PDIR).id.mode = S_IFDIR | 0o750; }),
            ("no inherit", |f| { f.node(PDIR).inherit = false; }),
            ("another fsid", |f| { f.fsid += 1; }),
            ("another boot", |f| { f.files.insert("proc/sys/kernel/random/boot_id".into(), b"11111111-2222-3333-4444-555555555555\n".to_vec()); }),
        ];
        for (label, spoil) in cases {
            let mut f = fixture();
            let d = dir_file(&mut f);
            let c = clear_file(&mut f, &[]);
            spoil(&mut f);
            assert_eq!(code(create(&mut f, A, &subs(&["projects"]), &d)), 73, "{label} create");
            assert_eq!(code(clear(&mut f, A, &c)), 73, "{label} clear");
            assert_eq!(f.count("mkdir") + f.count("set_immutable"), 0, "{label}");
        }
        let _ = (BOOT, MNT);
    }

    #[test]
    fn clear_clears_recorded_entries_skips_absent_ones_and_converges() {
        let mut f = fixture();
        let d = dir_file(&mut f);
        create(&mut f, A, &subs(&["projects", "todos", "history"]), &d).unwrap();
        let rows = vec![mp(&f, "projects"), mp(&f, "todos"), mp(&f, "history")];
        f.node(&format!("{PDIR}/todos")).immutable = false; // already clear: a no-op
        f.nodes.retain(|k, _| k != &format!("{PDIR}/history")); // already removed: skipped
        let c = clear_file(&mut f, &rows);
        clear(&mut f, A, &c).unwrap();
        assert!(!f.nodes[&format!("{PDIR}/projects")].immutable);
        assert!(!f.nodes[&format!("{PDIR}/todos")].immutable);
        let n = f.count("set_immutable");
        clear(&mut f, A, &c).unwrap();
        assert_eq!(f.count("set_immutable"), n, "a rerun changes nothing");
    }

    #[test]
    fn clear_refuses_a_mismatch_and_touches_no_later_entry() {
        type Spoil = fn(&mut Fake, &str);
        let cases: [(&str, Spoil); 4] = [
            ("another generation", |f, p| { f.node(p).gen += 1; }),
            ("non-empty", |f, p| { f.node(p).immutable = false; f.file(&format!("{p}/x"), SUID, 0o600); }),
            ("foreign owner", |f, p| { f.node(p).id.uid = SUID; }),
            ("replaced", |f, p| { f.nodes.remove(p); entry(f, p, S_IFDIR | 0o555, 0, 0); }),
        ];
        for (label, spoil) in cases {
            for (first, code_want) in [(true, 73), (false, 75)] {
                let mut f = fixture();
                let d = dir_file(&mut f);
                create(&mut f, A, &subs(&["projects", "todos"]), &d).unwrap();
                let rows = vec![mp(&f, "projects"), mp(&f, "todos")];
                let (bad, other) = if first { ("projects", "todos") } else { ("todos", "projects") };
                let c = clear_file(&mut f, &rows);
                spoil(&mut f, &format!("{PDIR}/{bad}"));
                assert_eq!(code(clear(&mut f, A, &c)), code_want, "{label} first={first}");
                if first {
                    assert!(f.nodes[&format!("{PDIR}/{other}")].immutable, "{label}: the later entry is untouched");
                }
            }
        }
    }

    #[test]
    fn a_failed_flag_change_is_66_before_any_change_and_75_after() {
        let mut f = fixture();
        let d = dir_file(&mut f);
        entry(&mut f, &format!("{PDIR}/projects"), S_IFDIR | 0o555, 0, 0); // the residue: needs only the flag
        f.errno_at = Some(("set_immutable", 1, libc::EPERM));
        assert_eq!(code(create(&mut f, A, &subs(&["projects"]), &d)), 73);
        let mut f = fixture();
        let d = dir_file(&mut f);
        f.errno_at = Some(("set_immutable", 2, libc::EPERM));
        assert_eq!(code(create(&mut f, A, &subs(&["projects", "todos"]), &d)), 75);
    }

    #[test]
    fn remove_tree_fails_at_an_immutable_mountpoint_and_succeeds_after_clear() {
        let mut f = fixture();
        let d = dir_file(&mut f);
        create(&mut f, A, &subs(&["projects"]), &d).unwrap();
        f.file(&format!("{PDIR}/.credentials.json"), SUID, 0o600);
        let rows = vec![mp(&f, "projects")];
        let id = identify(&mut f, PROFILES, A).unwrap();
        let head = id.trim_end().trim_start_matches('{');
        let (pre_obj, obj) = head.split_once(",\"object\":").unwrap();
        let rm = expect_file(&mut f, "rm.json", format!("{{{pre_obj},\"root\":{},\"owners\":[0,{SUID}]}}", obj.trim_end_matches('}').to_string() + "}"));
        assert_ne!(code(remove_tree(&mut f, PROFILES, A, &rm)), 0, "clear omitted: the immutable entry stops remove-tree");
        assert!(f.nodes.contains_key(&format!("{PDIR}/projects")));
        let c = clear_file(&mut f, &rows);
        clear(&mut f, A, &c).unwrap();
        let id = identify(&mut f, PROFILES, A).unwrap();
        let head = id.trim_end().trim_start_matches('{');
        let (pre_obj, obj) = head.split_once(",\"object\":").unwrap();
        let rm = expect_file(&mut f, "rm.json", format!("{{{pre_obj},\"root\":{},\"owners\":[0,{SUID}]}}", obj.trim_end_matches('}').to_string() + "}"));
        assert_eq!(code(remove_tree(&mut f, PROFILES, A, &rm)), 0);
        assert!(!f.nodes.contains_key(PDIR));
    }

    #[test]
    fn an_orphan_with_a_root_owned_entry_is_refused_intact_with_owners_storage_uid_only() {
        let mut f = fixture();
        let d = dir_file(&mut f);
        create(&mut f, A, &subs(&["projects"]), &d).unwrap();
        f.file(&format!("{PDIR}/settings.json"), SUID, 0o600);
        let id = identify(&mut f, PROFILES, A).unwrap();
        let head = id.trim_end().trim_start_matches('{');
        let (pre_obj, obj) = head.split_once(",\"object\":").unwrap();
        let rm = expect_file(&mut f, "rm.json", format!("{{{pre_obj},\"root\":{},\"owners\":[{SUID}]}}", obj.trim_end_matches('}').to_string() + "}"));
        assert_eq!(code(remove_tree(&mut f, PROFILES, A, &rm)), 73);
        assert_eq!(f.count("unlink"), 0, "zero unlinks");
        assert!(f.nodes.contains_key(&format!("{PDIR}/settings.json")));
    }

    #[test]
    fn a_flag_that_does_not_stick_is_caught_by_the_read_back() {
        let mut f = fixture();
        let d = dir_file(&mut f);
        f.xattrs.insert("<flag-does-not-stick>".into(), vec![]);
        assert_eq!(code(create(&mut f, A, &subs(&["projects"]), &d)), 75, "create");
        let mut f = fixture();
        let d = dir_file(&mut f);
        create(&mut f, A, &subs(&["projects"]), &d).unwrap();
        let row = mp(&f, "projects");
        let c = clear_file(&mut f, &[row]);
        f.xattrs.insert("<flag-does-not-stick>".into(), vec![]);
        assert_eq!(code(clear(&mut f, A, &c)), 75, "clear");
    }

    #[test]
    fn an_expected_identity_that_is_not_0700_or_without_inherit_is_refused_too() {
        // The expect itself carries the bad mode or inherit (identify taken after the change): the explicit checks refuse.
        for spoil in [|f: &mut Fake| f.node(PDIR).id.mode = S_IFDIR | 0o750, |f: &mut Fake| f.node(PDIR).inherit = false] {
            let mut f = fixture();
            spoil(&mut f);
            let d = dir_file(&mut f);
            assert_eq!(code(create(&mut f, A, &subs(&["projects"]), &d)), 73);
            assert_eq!(f.count("mkdir"), 0);
        }
    }

    #[test]
    fn set_immutable_changes_only_the_immutable_bit() {
        for x in [0u32, 0x200, 0xffff_ffff, 0x0000_0208, 0x8000_0001] {
            assert_eq!(sys::with_immutable(x, true), x | 0x8);
            assert_eq!(sys::with_immutable(x, false), x & !0x8);
        }
        assert_eq!(sys::FS_XFLAG_IMMUTABLE, 0x8);
    }

    #[test]
    fn arguments_are_closed() {
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(parse(&a(&["--name", A, "--op", "create", "--subpath", "projects", "--expect-dir", "/x/d.json"])).unwrap(),
            Op::Create { pid: A.into(), subpaths: vec!["projects".into()], expect_dir: "/x/d.json".into() });
        assert_eq!(parse(&a(&["--op", "clear", "--expect", "/x/c.json", "--name", A])).unwrap(), Op::Clear { pid: A.into(), expect: "/x/c.json".into() });
        let many: Vec<String> = (0..17).flat_map(|i| ["--subpath".to_string(), format!("s{i}")]).collect();
        let mut over = a(&["--name", A, "--op", "create", "--expect-dir", "/x"]);
        over.extend(many);
        for bad in [
            a(&["--name", A, "--op", "create", "--expect-dir", "/x"]),
            a(&["--name", A, "--op", "create", "--subpath", "p", "--subpath", "p", "--expect-dir", "/x"]),
            a(&["--name", A, "--op", "create", "--subpath", "..", "--expect-dir", "/x"]),
            a(&["--name", A, "--op", "create", "--subpath", "a/b", "--expect-dir", "/x"]),
            a(&["--name", A, "--op", "create", "--subpath", "p", "--expect", "/x"]),
            a(&["--name", A, "--op", "clear", "--subpath", "p", "--expect", "/x"]),
            a(&["--name", A, "--op", "clear", "--expect-dir", "/x"]),
            a(&["--name", A, "--op", "clear", "--expect", "rel"]),
            a(&["--name", "bad", "--op", "clear", "--expect", "/x"]),
            a(&["--name", A, "--op", "wipe", "--expect", "/x"]),
            a(&["--name", A, "--name", A, "--op", "clear", "--expect", "/x"]),
            a(&["--name", A, "--op", "clear", "--expect"]),
            over,
        ] {
            assert_eq!(code(parse(&bad)), 64, "{bad:?}");
        }
    }
}
