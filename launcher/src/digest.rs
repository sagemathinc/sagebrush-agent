//! `tree-digest` (contract amendment A2 r3.8.1 §4a, §4b, §17–§19): a filled destination, listed and hashed, read-only.
//! Restore validation (B4d-1) compares this listing with the backup binary's `data/digests.json`.
//!
//! - The destination is resolved exactly as fill-home resolves it: the anchor policy, the epoch, and the closed expect.
//! - The walk is fd-relative (openat2 BENEATH | NO_SYMLINKS | NO_MAGICLINKS | NO_XDEV), every entry identified on its
//!   own handle; a symlink is read, never followed; a regular file is read through its handle and hashed; a special
//!   file or a foreign mount is listed as `unexpected` and never opened for reading or entered.
//! - Modes are reported as they ARE (`st_mode & 0o7777`, set-id included): the expected list carries fill's intended
//!   mode, so an unstripped set-id shows as a mismatch.
//! - Names are filesystem bytes: written with §4b's lossless codec (valid UTF-8 as itself, `%` as `%25`, any other
//!   byte as `%XX`), sorted by the RAW bytes.
//! - Nothing is printed unless the whole listing is built: past `MAX_OBJECTS`, `MAX_DEPTH`, `MAX_LISTING` or on an
//!   allocation failure it's `limit` (64) with no output.
//! - `--copy-sqlite --run <run>` (sessions only): each SQLite main (by its header) and each sidecar `X-wal`/`X-journal`
//!   of a main is copied, in the very read pass that hashes it, into a fresh `<run>/<owner>` beneath
//!   `/var/lib/sagebrush/validate`, as `<h>.db`, `<h>.db-wal`, `<h>.db-journal` (h: the first 32 hex digits of SHA-256
//!   over the main's raw path bytes). Sidecars are copied speculatively (`t<k>`) and kept by rename only if their
//!   main was identified.

use crate::err::{err, Error, Fail, Result};
use crate::restore::{dest_anchor, staging_dir, Class, RestoreOps, MAX_LISTING};
use crate::sha256::{hex, Sha256};
use crate::sys::Ident;
use crate::tree::{self, anchor_policy, child as tchild, epoch_now, identity, kind_of, obj_of, open_err, At, Kind, S_IFMT};
use std::io;

/// The copy-out's anchor (A2 r3.7 S1): root:root 0700 on the root filesystem, never the quota mount.
pub const VALIDATE: &str = "/var/lib/sagebrush/validate";
/// At most this many bytes copied in all (A2 r3.7).
pub const MAX_COPY: u64 = 8 << 30;
const CHUNK: usize = 1 << 20;
/// A path's longest form, in raw bytes, relative to the class root (A2 §4b).
pub const MAX_PATH: usize = 4096;
const SQLITE_MAGIC: &[u8; 16] = b"SQLite format 3\0";

/// The operations `tree-digest` adds to restore's: names as raw bytes, and the copy-out's writes.
pub trait DigestOps: RestoreOps {
    /// Every name in the directory (not `.`/`..`), as raw bytes, from this handle's position.
    fn names_raw(&mut self, dir: &Self::H) -> io::Result<Vec<Vec<u8>>>;
    fn at_raw(&mut self, dir: &Self::H, name: &[u8], how: At) -> io::Result<Self::H>;
    fn ident_at_raw(&mut self, dir: &Self::H, name: &[u8]) -> io::Result<Ident>;
    /// A handle on the symlink ITSELF: `openat2(dir, name, O_PATH | O_NOFOLLOW, RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS |
    /// RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV)`, which for a trailing symlink returns the link, never its target.
    fn link_at_raw(&mut self, dir: &Self::H, name: &[u8]) -> io::Result<Self::H>;
    /// The link's target, read through its own handle (`readlinkat(fd, "")`, never followed).
    fn readlink_handle(&mut self, h: &Self::H) -> io::Result<Vec<u8>>;
    /// `O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW | O_CLOEXEC`, 0600.
    fn create_copy(&mut self, dir: &Self::H, name: &str) -> io::Result<Self::H>;
    fn write_all(&mut self, h: &Self::H, data: &[u8]) -> io::Result<()>;
    /// `renameat2(dir, from, dir, to, RENAME_NOREPLACE)`.
    fn rename_in(&mut self, dir: &Self::H, from: &str, to: &str) -> io::Result<()>;
}

pub struct DigestArgs<'a> {
    pub mount: &'a str,
    /// The owner (`a-<id>` or `t-<id>`) and the class, as restore names them.
    pub owner: &'a str,
    pub class: &'a str,
    pub expect: &'a str,
    /// `--copy-sqlite --run <run>`.
    pub copy_run: Option<&'a str>,
}

/// The limits, in one place so the tests can shrink them.
#[derive(Clone, Copy)]
pub struct Limits {
    pub objects: usize,
    pub depth: usize,
    pub listing: u64,
    pub copy: u64,
}

pub const LIMITS: Limits = Limits { objects: tree::MAX_OBJECTS, depth: tree::MAX_DEPTH, listing: MAX_LISTING, copy: MAX_COPY };

/// remove-tree's name beneath the validate anchor: `<run>/<owner>`, each validated as restore validates it.
pub fn copy_name_ok(name: &str) -> bool {
    match name.split_once('/') {
        Some((run, owner)) => crate::restore::Name::parse(run, owner, "sessions", "1").is_some(),
        None => false,
    }
}

fn limit() -> Error {
    err(Fail::Usage, "limit")
}
fn partial(msg: &'static str) -> Error {
    err(Fail::Partial, msg)
}

/// §4b's path codec: each maximal run of valid UTF-8 as itself, except `%` as `%25`; every other byte as `%XX`.
pub fn encode(raw: &[u8]) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while !rest.is_empty() {
        match std::str::from_utf8(rest) {
            Ok(s) => {
                push_valid(&mut out, s);
                break;
            }
            Err(e) => {
                let (good, bad) = rest.split_at(e.valid_up_to());
                push_valid(&mut out, std::str::from_utf8(good).unwrap_or_default());
                let n = e.error_len().unwrap_or(bad.len()).max(1);
                for b in &bad[..n] {
                    out.push_str(&format!("%{b:02X}"));
                }
                rest = &bad[n..];
            }
        }
    }
    out
}
fn push_valid(out: &mut String, s: &str) {
    for ch in s.chars() {
        if ch == '%' {
            out.push_str("%25");
        } else {
            out.push(ch);
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ty {
    Dir,
    File,
    Symlink,
}

struct Entry {
    path: Vec<u8>,
    /// Some(type) for an `unexpected` line.
    unexpected: Option<&'static str>,
    ty: Ty,
    size: u64,
    mode: u16,
    sha: Option<[u8; 32]>,
    target: Option<Vec<u8>>,
    copy: Option<String>,
}

impl Entry {
    fn render(&self) -> String {
        let p = crate::json::quote(&encode(&self.path));
        if let Some(t) = self.unexpected {
            return format!("{{\"unexpected\":{p},\"type\":\"{t}\"}}\n");
        }
        match self.ty {
            Ty::Dir => format!("{{\"path\":{p},\"type\":\"dir\",\"size\":0,\"mode\":{}}}\n", self.mode),
            Ty::Symlink => {
                let t = crate::json::quote(&encode(self.target.as_deref().unwrap_or_default()));
                format!("{{\"path\":{p},\"type\":\"symlink\",\"size\":{},\"mode\":511,\"target\":{t}}}\n", self.size)
            }
            Ty::File => {
                let mut s = format!("{{\"path\":{p},\"type\":\"file\",\"size\":{},\"mode\":{},\"sha256\":\"{}\"", self.size, self.mode, hex(&self.sha.unwrap_or_default()));
                if let Some(c) = &self.copy {
                    s.push_str(&format!(",\"copy\":\"{c}\""));
                }
                s.push_str("}\n");
                s
            }
        }
    }
}

/// The copy-out's state during the walk.
struct Copy<H> {
    dir: H,
    total: u64,
    /// Identified mains: their raw paths and copy names.
    mains: Vec<(Vec<u8>, String)>,
    /// Speculative sidecar copies: (temp name, the main's raw path, suffix, entry index).
    side: Vec<(String, Vec<u8>, &'static str, usize)>,
    next: usize,
}

fn h_of(main: &[u8]) -> String {
    let mut s = Sha256::new();
    s.update(main);
    hex(&s.finish())[..32].to_string()
}

fn sidecar_of(path: &[u8]) -> Option<(&[u8], &'static str)> {
    if let Some(m) = path.strip_suffix(b"-wal") {
        return Some((m, "-wal"));
    }
    path.strip_suffix(b"-journal").map(|m| (m, "-journal"))
}

fn join_raw(dir: &[u8], name: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(dir.len() + 1 + name.len());
    if !dir.is_empty() {
        p.extend_from_slice(dir);
        p.push(b'/');
    }
    p.extend_from_slice(name);
    p
}

pub fn tree_digest<O: DigestOps>(o: &mut O, a: &DigestArgs) -> Result<String> {
    tree_digest_limited(o, a, LIMITS)
}

pub fn tree_digest_limited<O: DigestOps>(o: &mut O, a: &DigestArgs, lim: Limits) -> Result<String> {
    // Arguments (64): the owner and class as restore names them; --copy-sqlite only for sessions.
    let n = crate::restore::Name::parse(a.copy_run.unwrap_or("aaaaaaaaaaaaaaaa"), a.owner, a.class, "1").ok_or(err(Fail::Usage, "bad arguments"))?;
    // (`config` and `hoststore` are staged only, never filled: nothing to list, A2 r3.13 §5, r3.14 §1)
    if (a.copy_run.is_some() && n.class != Class::Sessions) || n.class.stage_only() {
        return Err(err(Fail::Usage, "bad arguments"));
    }
    let root = o.root().map_err(|_| tree::pre("the root can't be opened"))?;
    // The destination, as fill-home resolves it (§4 steps 1 and 4, without the attempt and without "empty").
    let v = tree::read_expect(o, &root, a.expect)?;
    let f = v.exact(&["epoch", "fsid", "dest", "uids", "gid", "projid"]).ok_or(tree::bad_expect())?;
    let (e_epoch, e_fsid, e_dest) = (tree::epoch_of(f[0])?, tree::fsid_of(f[1])?, obj_of(f[2])?);
    let uids = f[3].arr().filter(|u| !u.is_empty() && u.len() <= 64).ok_or(tree::bad_expect())?.iter().map(tree::u32_of).collect::<Result<Vec<u32>>>()?;
    let (gid, projid) = (tree::u32_of(f[4])?, tree::u32_of(f[5])?);
    if (n.class != Class::Tag && uids.len() != 1) || !n.projid_ok(projid) || !crate::restore::owners_ok(n.class, &uids, gid) {
        return Err(tree::bad_expect());
    }
    let _ = tree::parse_mount(a.mount)?;
    let da = anchor_policy(o, &root, dest_anchor(n.class))?;
    let (epoch, fsid) = epoch_now(o, &root, &da)?;
    if epoch != e_epoch {
        return Err(identity("a stale epoch: requalify first"));
    }
    if fsid != e_fsid {
        return Err(identity("another filesystem"));
    }
    let mnt = epoch.mnt_id;
    let leaf: &str = match n.class {
        Class::Home => "home",
        Class::Sessions => "sessions",
        Class::Archive | Class::Tag | Class::ArchiveConfig | Class::Config | Class::HostStore => &n.id,
    };
    let dest_parent = match n.class {
        Class::Home | Class::Sessions => tchild(o, &da, &n.id, mnt)?.and_then(|(_, h)| h).ok_or(identity("no agent directory"))?,
        Class::Archive | Class::Tag | Class::ArchiveConfig | Class::Config | Class::HostStore => da,
    };
    let (dx, _) = tchild(o, &dest_parent, leaf, mnt)?.ok_or(identity("no destination"))?;
    if dx != e_dest {
        return Err(identity("the destination differs from its recorded identity"));
    }
    if dx.projid != Some(projid) || dx.inherit != Some(true) {
        return Err(identity("the destination isn't in the class's project"));
    }
    let dst = o.at(&dest_parent, leaf, At::Dir).map_err(open_err)?;
    let di = o.ident(&dst).map_err(open_err)?;
    if (di.dev, di.ino) != (dx.dev, dx.ino) {
        return Err(identity("the destination changed"));
    }

    // The copy-out's directory: <run>/<owner> beneath the validate anchor, exclusive, verified by handle.
    let mut copy = match a.copy_run {
        None => None,
        Some(run) => {
            let va = anchor_policy(o, &root, VALIDATE)?;
            let vm = o.ident(&va).map_err(open_err)?.mnt_id;
            // On the ROOT filesystem's own mount (SEC S2 on 99b4b391): not the quota mount, and not any third one.
            let rm = o.ident(&root).map_err(open_err)?.mnt_id;
            if vm == mnt || vm != rm {
                return Err(identity("the validate anchor isn't on the root filesystem"));
            }
            let run_h = staging_dir(o, &va, run, vm, projid)?;
            match o.mkdir(&run_h, a.owner, 0o700) {
                Ok(()) => {}
                Err(e) if e.raw_os_error() == Some(libc::EEXIST) => return Err(err(Fail::Exists, "the copy directory exists")),
                Err(_) => return Err(tree::pre("the copy directory can't be made")),
            }
            let (x, h) = tchild(o, &run_h, a.owner, vm)?.ok_or(identity("the copy directory vanished"))?;
            let h = h.ok_or(identity("the copy directory isn't a directory"))?;
            o.chmod(&h, 0o700).map_err(|_| identity("the copy directory's mode can't be set"))?;
            let again = o.ident(&h).map_err(open_err)?;
            if x.uid != 0 || x.gid != 0 || (again.dev, again.ino) != (x.dev, x.ino) || again.mode & 0o7777 != 0o700 || !o.batch(&h).map_err(open_err)?.is_empty() {
                return Err(identity("the copy directory isn't a fresh, empty root 0700 directory"));
            }
            Some((Copy { dir: h, total: 0, mains: Vec::new(), side: Vec::new(), next: 0 }, run_h))
        }
    };

    // The walk.
    let mut entries: Vec<Entry> = Vec::new();
    let mut listed: u64 = 0;
    let mut stack: Vec<(O::H, Vec<u8>, usize)> = vec![(dst, Vec::new(), 1)];
    while let Some((dir, base, depth)) = stack.pop() {
        if depth > lim.depth {
            return Err(limit());
        }
        let mut names = Vec::new();
        loop {
            let batch = o.names_raw(&dir).map_err(|_| partial("a directory can't be listed"))?;
            if batch.is_empty() {
                break;
            }
            names.extend(batch);
        }
        for name in names {
            let path = join_raw(&base, &name);
            if path.len() > MAX_PATH {
                return Err(limit()); // §4b: at most 4096 raw bytes (TESTS H2 on 99b4b391)
            }
            if entries.len() >= lim.objects {
                return Err(limit());
            }
            entries.try_reserve(1).map_err(|_| limit())?;
            let e = visit(o, &dir, &name, &path, mnt, &mut copy, entries.len(), lim, &mut stack, depth)?;
            listed += e.render().len() as u64;
            if listed > lim.listing {
                return Err(limit());
            }
            entries.push(e);
        }
    }

    // The sidecars: kept by rename only if their main was identified; a non-regular sibling of a main refuses.
    if let Some((c, run_h)) = copy.as_mut() {
        for (main, _) in &c.mains {
            for suf in ["-wal", "-journal"] {
                let mut p = main.clone();
                p.extend_from_slice(suf.as_bytes());
                if let Some(e) = entries.iter().find(|e| e.path == p) {
                    if e.unexpected.is_some() || e.ty != Ty::File {
                        return Err(identity("a main database's sidecar isn't a regular file"));
                    }
                }
            }
        }
        let side = std::mem::take(&mut c.side);
        for (tmp, main, suf, idx) in side {
            match c.mains.iter().find(|(m, _)| *m == main) {
                Some((_, name)) => {
                    let to = format!("{name}{suf}");
                    match o.rename_in(&c.dir, &tmp, &to) {
                        Ok(()) => entries[idx].copy = Some(to),
                        Err(e) if e.raw_os_error() == Some(libc::EEXIST) => return Err(identity("a copy name collides")),
                        Err(_) => return Err(partial("a copy can't be renamed")),
                    }
                }
                None => o.unlink(&c.dir, &tmp, false).map_err(|_| partial("a speculative copy can't be removed"))?,
            }
        }
        o.fsync(&c.dir).map_err(|_| partial("the copies can't be made durable"))?;
        o.fsync(run_h).map_err(|_| partial("the copies can't be made durable"))?;
    }

    // Render: sorted by raw path bytes, then the trailer. Built whole before anything is printed.
    entries.sort_by(|x, y| x.path.cmp(&y.path));
    let count = entries.iter().filter(|e| e.unexpected.is_none()).count();
    let total: u64 = entries.iter().filter(|e| e.unexpected.is_none() && e.ty == Ty::File).map(|e| e.size).sum();
    let mut out = String::new();
    out.try_reserve(listed as usize + 64).map_err(|_| limit())?;
    out.push_str("{\"v\":1}\n");
    for e in &entries {
        out.push_str(&e.render());
    }
    out.push_str(&format!("{{\"count\":{count},\"total_bytes\":{total}}}\n"));
    if out.len() as u64 > lim.listing {
        return Err(limit());
    }
    Ok(out)
}

/// One entry: identified on its own handle; a directory is queued, a file read and hashed (and maybe copied).
#[allow(clippy::too_many_arguments)]
fn visit<O: DigestOps>(o: &mut O, dir: &O::H, name: &[u8], path: &[u8], mnt: u64, copy: &mut Option<(Copy<O::H>, O::H)>, idx: usize, lim: Limits, stack: &mut Vec<(O::H, Vec<u8>, usize)>, depth: usize) -> Result<Entry> {
    let mut e = Entry { path: path.to_vec(), unexpected: None, ty: Ty::File, size: 0, mode: 0, sha: None, target: None, copy: None };
    // Identity by O_PATH handle; a symlink (ELOOP under NO_SYMLINKS) by name, never followed.
    let id = match o.at_raw(dir, name, At::Path) {
        Ok(h) => o.ident(&h).map_err(|_| partial("an entry can't be identified"))?,
        Err(x) if x.raw_os_error() == Some(libc::ELOOP) => {
            let id = o.ident_at_raw(dir, name).map_err(|_| partial("an entry can't be identified"))?;
            if kind_of(&id) != Some(Kind::Symlink) {
                return Err(identity("a changed entry"));
            }
            id
        }
        Err(x) if x.raw_os_error() == Some(libc::EXDEV) => {
            e.unexpected = Some("mount");
            return Ok(e);
        }
        Err(_) => return Err(partial("an entry can't be opened")),
    };
    if id.mnt_id != mnt {
        e.unexpected = Some("mount");
        return Ok(e);
    }
    e.mode = id.mode & 0o7777;
    match kind_of(&id) {
        None => {
            e.unexpected = Some(match id.mode & S_IFMT {
                0o010000 => "fifo",
                0o140000 => "socket",
                0o020000 => "char",
                _ => "block",
            });
            Ok(e)
        }
        Some(Kind::Symlink) => {
            // A2 W1 (SEC S1 on 99b4b391): the link's identity and its target both through ONE handle on the link
            // itself, then the name re-read: an entry replaced at any point of this is 73, never a mixed pair.
            e.ty = Ty::Symlink;
            let lh = o.link_at_raw(dir, name).map_err(|_| partial("a symlink can't be opened"))?;
            let li = o.ident(&lh).map_err(|_| partial("a symlink can't be identified"))?;
            if kind_of(&li) != Some(Kind::Symlink) || (li.dev, li.ino) != (id.dev, id.ino) || li.mnt_id != mnt {
                return Err(identity("a changed entry"));
            }
            let t = o.readlink_handle(&lh).map_err(|_| partial("a symlink can't be read"))?;
            let after = o.ident_at_raw(dir, name).map_err(|_| identity("a changed entry"))?;
            if (after.dev, after.ino) != (li.dev, li.ino) {
                return Err(identity("a changed entry"));
            }
            e.size = t.len() as u64;
            e.target = Some(t);
            Ok(e)
        }
        Some(Kind::Dir) => {
            e.ty = Ty::Dir;
            let h = o.at_raw(dir, name, At::Dir).map_err(|_| partial("a directory can't be opened"))?;
            let again = o.ident(&h).map_err(|_| partial("a directory can't be identified"))?;
            if (again.dev, again.ino) != (id.dev, id.ino) {
                return Err(identity("a changed entry"));
            }
            stack.push((h, path.to_vec(), depth + 1));
            Ok(e)
        }
        Some(Kind::File) => {
            let h = o.at_raw(dir, name, At::File).map_err(|_| partial("a file can't be opened"))?;
            let again = o.ident(&h).map_err(|_| partial("a file can't be identified"))?;
            if (again.dev, again.ino) != (id.dev, id.ino) || kind_of(&again) != Some(Kind::File) {
                return Err(identity("a changed entry"));
            }
            e.size = again.size;
            // A speculative sidecar copy is decided by name, BEFORE the read, so an empty sidecar is copied too (TESTS
            // H1 on 99b4b391); a main by its first bytes.
            let side = copy.as_ref().and_then(|_| sidecar_of(path));
            let mut sum = Sha256::new();
            let mut off = 0u64;
            let mut out: Option<O::H> = None;
            if let (Some((main, suf)), Some((c, _))) = (side, copy.as_mut()) {
                let n = format!("t{}", c.next);
                c.next += 1;
                c.side.push((n.clone(), main.to_vec(), suf, idx));
                out = Some(o.create_copy(&c.dir, &n).map_err(|x| if x.raw_os_error() == Some(libc::EEXIST) { identity("a copy name collides") } else { partial("a copy can't be made") })?);
            }
            loop {
                let chunk = o.pread(&h, CHUNK, off).map_err(|_| partial("a file can't be read"))?;
                if chunk.is_empty() {
                    break;
                }
                if off == 0 {
                    if let Some((c, _)) = copy.as_mut() {
                        let name = if chunk.len() >= 16 && chunk[..16] == SQLITE_MAGIC[..] && side.is_none() {
                            let n = format!("{}.db", h_of(path));
                            c.mains.push((path.to_vec(), n.clone()));
                            e.copy = Some(n.clone());
                            Some(n)
                        } else {
                            None
                        };
                        if let Some(n) = name {
                            out = Some(o.create_copy(&c.dir, &n).map_err(|x| if x.raw_os_error() == Some(libc::EEXIST) { identity("a copy name collides") } else { partial("a copy can't be made") })?);
                        }
                    }
                }
                off += chunk.len() as u64;
                sum.update(&chunk);
                if let (Some(w), Some((c, _))) = (out.as_ref(), copy.as_mut()) {
                    c.total += chunk.len() as u64;
                    if c.total > lim.copy {
                        return Err(limit());
                    }
                    o.write_all(w, &chunk).map_err(|_| partial("a copy can't be written"))?;
                }
            }
            if off != e.size {
                return Err(partial("a file changed while it was read"));
            }
            if let Some(w) = out {
                o.fsync_file(&w).map_err(|_| partial("a copy can't be made durable"))?;
            }
            e.sha = Some(sum.finish());
            Ok(e)
        }
    }
}

// ---- the real operations

use crate::sys;
use std::ffi::CString;
use std::os::fd::OwnedFd;

fn cs(b: &[u8]) -> io::Result<CString> {
    CString::new(b).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))
}

impl DigestOps for tree::RealOps {
    fn names_raw(&mut self, dir: &OwnedFd) -> io::Result<Vec<Vec<u8>>> {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = sys::getdents64(dir, &mut buf)?;
            if n == 0 {
                return Ok(Vec::new());
            }
            let names = crate::args::dirent_names(&buf, n).ok_or_else(|| io::Error::from_raw_os_error(libc::EIO))?;
            let out: Vec<Vec<u8>> = names.into_iter().filter(|nm| nm != b"." && nm != b"..").collect();
            if !out.is_empty() {
                return Ok(out);
            }
        }
    }
    fn at_raw(&mut self, dir: &OwnedFd, name: &[u8], how: At) -> io::Result<OwnedFd> {
        let flags = match how {
            At::Path => libc::O_PATH,
            At::Dir => libc::O_RDONLY | libc::O_DIRECTORY,
            At::File => libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW,
        };
        sys::openat2_xdev(dir, &cs(name)?, flags)
    }
    fn ident_at_raw(&mut self, dir: &OwnedFd, name: &[u8]) -> io::Result<Ident> {
        sys::ident_at_nofollow(dir, &cs(name)?)
    }
    fn link_at_raw(&mut self, dir: &OwnedFd, name: &[u8]) -> io::Result<OwnedFd> {
        sys::openat2_xdev(dir, &cs(name)?, libc::O_PATH | libc::O_NOFOLLOW)
    }
    fn readlink_handle(&mut self, h: &OwnedFd) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; 4097];
        let n = sys::readlinkat(h, c"", &mut buf)?;
        if n >= buf.len() {
            return Err(io::Error::from_raw_os_error(libc::ENAMETOOLONG));
        }
        buf.truncate(n);
        Ok(buf)
    }
    fn create_copy(&mut self, dir: &OwnedFd, name: &str) -> io::Result<OwnedFd> {
        sys::create_excl(dir, &cs(name.as_bytes())?, 0o600)
    }
    fn write_all(&mut self, h: &OwnedFd, mut data: &[u8]) -> io::Result<()> {
        while !data.is_empty() {
            let n = sys::write(h, data)?;
            if n == 0 {
                return Err(io::Error::from_raw_os_error(libc::EIO));
            }
            data = &data[n..];
        }
        Ok(())
    }
    fn rename_in(&mut self, dir: &OwnedFd, from: &str, to: &str) -> io::Result<()> {
        sys::rename_noreplace(dir, &cs(from.as_bytes())?, &cs(to.as_bytes())?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::tests::{e, expect_file, join, Fake, FH, A, BOOT, MNT, UID};
    use crate::tree::{obj_json, Ops, S_IFDIR, S_IFLNK, S_IFMT, S_IFREG};

    impl DigestOps for Fake {
        fn names_raw(&mut self, dir: &FH) -> io::Result<Vec<Vec<u8>>> {
            self.batch(dir)
        }
        fn at_raw(&mut self, dir: &FH, name: &[u8], how: At) -> io::Result<FH> {
            self.at(dir, name, how)
        }
        fn ident_at_raw(&mut self, dir: &FH, name: &[u8]) -> io::Result<Ident> {
            self.ident_at(dir, name)
        }
        fn link_at_raw(&mut self, dir: &FH, name: &[u8]) -> io::Result<FH> {
            self.tick("link_at")?;
            let p = join(&dir.p, &crate::tree::tests::key(name));
            if self.nodes.get(&p).ok_or(e(libc::ENOENT))?.id.mode & S_IFMT != S_IFLNK {
                return Err(e(libc::ENOTDIR));
            }
            Ok(self.handle(p))
        }
        fn readlink_handle(&mut self, h: &FH) -> io::Result<Vec<u8>> {
            self.tick("readlink")?;
            Ok(self.files.get(&h.p).cloned().unwrap_or_default())
        }
        fn create_copy(&mut self, dir: &FH, name: &str) -> io::Result<FH> {
            self.tick("create_copy")?;
            let p = join(&dir.p, name);
            if self.nodes.contains_key(&p) {
                return Err(e(libc::EEXIST));
            }
            let mnt = self.nodes[&dir.p].id.mnt_id;
            self.add(&p, S_IFREG | 0o600, 0, 0);
            self.node(&p).id.mnt_id = mnt;
            self.files.insert(p.clone(), Vec::new());
            self.log.push(format!("create {p}"));
            Ok(self.handle(p))
        }
        fn write_all(&mut self, h: &FH, data: &[u8]) -> io::Result<()> {
            self.tick("write")?;
            self.files.get_mut(&h.p).unwrap().extend_from_slice(data);
            let n = self.files[&h.p].len() as u64;
            self.node(&h.p).id.size = n;
            Ok(())
        }
        fn rename_in(&mut self, dir: &FH, from: &str, to: &str) -> io::Result<()> {
            self.tick("rename_in")?;
            let (pf, pt) = (join(&dir.p, from), join(&dir.p, to));
            if self.nodes.contains_key(&pt) {
                return Err(e(libc::EEXIST));
            }
            let n = self.nodes.remove(&pf).ok_or(e(libc::ENOENT))?;
            self.nodes.insert(pt.clone(), n);
            if let Some(b) = self.files.remove(&pf) {
                self.files.insert(pt.clone(), b);
            }
            self.log.push(format!("rename {pf} {pt}"));
            Ok(())
        }
    }

    trait CloneFake {
        fn clone_fake(&self) -> Fake;
    }
    impl CloneFake for Fake {
        /// The same tree, with fresh counters, log and read cursors.
        fn clone_fake(&self) -> Fake {
            let mut g = self.clone();
            g.counts.clear();
            g.log.clear();
            g.cursors.clear();
            g
        }
    }

    const RUN: &str = "abcdefghijklmnop";
    fn owner() -> String {
        format!("a-{A}")
    }
    fn dest() -> String {
        format!("srv/sagebrush/agents/{A}/sessions")
    }

    /// The host: the agent provisioned, its sessions holding a small tree; the validate anchor on another mount.
    fn host() -> Fake {
        let mut f = Fake::new();
        for d in ["srv/sagebrush/tags", "var", "var/lib", "var/lib/sagebrush"] {
            if !f.nodes.contains_key(d) {
                f.dir(d, 0, 0o755);
            }
        }
        f.dir(VALIDATE.trim_start_matches('/'), 0, 0o700);
        // The root filesystem's own mount: the root and the validate anchor; srv/sagebrush stays the quota mount.
        for p in ["", "var", "var/lib", "var/lib/sagebrush", VALIDATE.trim_start_matches('/')] {
            f.node(p).id.mnt_id = MNT + 50;
        }
        f.agent("srv/sagebrush/agents");
        f
    }
    fn put(f: &mut Fake, rel: &str, mode: u16, body: &[u8]) {
        let p = format!("{}/{rel}", dest());
        f.add(&p, S_IFREG | mode, UID, UID);
        f.node(&p).id.size = body.len() as u64;
        f.files.insert(p, body.to_vec());
    }
    fn dir(f: &mut Fake, rel: &str, mode: u16) {
        let p = format!("{}/{rel}", dest());
        f.add(&p, S_IFDIR | mode, UID, UID);
    }
    fn link(f: &mut Fake, rel: &str, target: &[u8]) {
        let p = format!("{}/{rel}", dest());
        f.add(&p, S_IFLNK | 0o777, UID, UID);
        f.node(&p).id.size = target.len() as u64;
        f.files.insert(p, target.to_vec());
    }
    fn expect(f: &mut Fake) -> String {
        let root = f.root().unwrap();
        let ag = f.dir_from_root(&root, &format!("srv/sagebrush/agents/{A}")).unwrap();
        let (x, _) = crate::tree::child(f, &ag, "sessions", MNT).unwrap().unwrap();
        expect_file(f, "td.json", format!("{{\"epoch\":{{\"boot_id\":\"{BOOT}\",\"mnt_id\":{MNT}}},\"fsid\":\"0000abcd00001234\",\"dest\":{},\"uids\":[{UID}],\"gid\":{UID},\"projid\":{UID}}}", obj_json(&x)))
    }
    fn args(x: &str, copy: bool) -> DigestArgs<'static> {
        let o: &'static str = Box::leak(owner().into_boxed_str());
        DigestArgs { mount: "/srv/sagebrush", owner: o, class: "sessions", expect: Box::leak(x.to_string().into_boxed_str()), copy_run: if copy { Some(RUN) } else { None } }
    }
    fn sha(b: &[u8]) -> String {
        let mut s = Sha256::new();
        s.update(b);
        hex(&s.finish())
    }
    fn code<T>(r: Result<T>) -> i32 {
        match r {
            Ok(_) => 0,
            Err(e) => e.fail.code(),
        }
    }

    #[test]
    fn the_listing_is_byte_exact_sorted_by_raw_bytes_with_real_modes() {
        let mut f = host();
        dir(&mut f, "a", 0o700);
        put(&mut f, "a/f", 0o644, b"hi");
        link(&mut f, "l", b"a/f");
        put(&mut f, "%25x", 0o600, b""); // the raw name `%x` (the fake keys names encoded)
        dir(&mut f, "b", 0o2775); // setgid directory: reported as it is
        put(&mut f, "s", 0o4755, b"x"); // setuid file: reported as it is (TESTS M1, SEC S4)
        put(&mut f, ".hidden", 0o600, b"z");
        let x = expect(&mut f);
        let out = tree_digest(&mut f, &args(&x, false)).unwrap();
        let want = format!(
            "{{\"v\":1}}\n\
{{\"path\":\"%25x\",\"type\":\"file\",\"size\":0,\"mode\":384,\"sha256\":\"{e0}\"}}\n\
{{\"path\":\".hidden\",\"type\":\"file\",\"size\":1,\"mode\":384,\"sha256\":\"{ez}\"}}\n\
{{\"path\":\"a\",\"type\":\"dir\",\"size\":0,\"mode\":448}}\n\
{{\"path\":\"a/f\",\"type\":\"file\",\"size\":2,\"mode\":420,\"sha256\":\"{ehi}\"}}\n\
{{\"path\":\"b\",\"type\":\"dir\",\"size\":0,\"mode\":1533}}\n\
{{\"path\":\"l\",\"type\":\"symlink\",\"size\":3,\"mode\":511,\"target\":\"a/f\"}}\n\
{{\"path\":\"s\",\"type\":\"file\",\"size\":1,\"mode\":2541,\"sha256\":\"{ex}\"}}\n\
{{\"count\":7,\"total_bytes\":4}}\n",
            e0 = sha(b""),
            ez = sha(b"z"),
            ehi = sha(b"hi"),
            ex = sha(b"x")
        );
        assert_eq!(out, want);
        // Read-only: nothing in the destination was made, changed or removed.
        assert!(!f.log.iter().any(|l| ["mkdir ", "chmod ", "unlink ", "rename ", "create "].iter().any(|p| l.starts_with(p))), "{:?}", f.log);
        // A symlink is read, never opened: no pread of it.
        assert!(!f.log.iter().any(|l| l == &format!("pread {}/l", dest())));
    }

    #[test]
    fn specials_and_mounts_are_unexpected_and_never_opened_or_entered() {
        let mut f = host();
        let p = format!("{}/fifo", dest());
        f.add(&p, 0o010000 | 0o600, UID, UID);
        let s = format!("{}/sock", dest());
        f.add(&s, 0o140000 | 0o600, UID, UID);
        let c = format!("{}/dev", dest());
        f.add(&c, 0o020000 | 0o600, 0, 0);
        dir(&mut f, "m", 0o700);
        f.node(&format!("{}/m", dest())).id.mnt_id = MNT + 9;
        put(&mut f, "m/inside", 0o600, b"no");
        let x = expect(&mut f);
        let out = tree_digest(&mut f, &args(&x, false)).unwrap();
        for (n, t) in [("dev", "char"), ("fifo", "fifo"), ("m", "mount"), ("sock", "socket")] {
            assert!(out.contains(&format!("{{\"unexpected\":\"{n}\",\"type\":\"{t}\"}}")), "{n}: {out}");
        }
        assert!(!out.contains("inside"), "a mount isn't entered");
        assert!(out.ends_with("{\"count\":0,\"total_bytes\":0}\n"));
        assert!(!f.log.iter().any(|l| l.starts_with("pread ")), "nothing read");
    }

    #[test]
    fn a_kernel_that_reports_another_mount_without_failing_still_gives_unexpected() {
        // The mnt_id postcondition holds on its own (A1): with the fake's no_exdev, the open succeeds into the mount.
        let mut f = host();
        dir(&mut f, "m", 0o700);
        f.node(&format!("{}/m", dest())).id.mnt_id = MNT + 9;
        put(&mut f, "m/inside", 0o600, b"no");
        let x = expect(&mut f);
        f.no_exdev = true;
        let out = tree_digest(&mut f, &args(&x, false)).unwrap();
        assert!(out.contains("{\"unexpected\":\"m\",\"type\":\"mount\"}"), "{out}");
        assert!(!out.contains("inside"));
    }

    #[test]
    fn the_listing_bound_stops_the_walk_early_not_only_at_the_end() {
        let mut f = host();
        for i in 0..20 {
            put(&mut f, &format!("f{i:02}"), 0o600, b"x");
        }
        let x = expect(&mut f);
        assert_eq!(code(tree_digest_limited(&mut f, &args(&x, false), Limits { listing: 150, ..LIMITS })), 64);
        let reads = f.log.iter().filter(|l| l.starts_with("pread ")).count();
        assert!(reads < 5, "the walk stopped at the bound ({reads} files read of 20)");
    }

    fn swap_link(f: &mut Fake) {
        // Another link at the name, after the handle was opened and before the target is read.
        let p = format!("{}/l", dest());
        f.node(&p).id.ino += 4000;
        f.files.insert(p, b"elsewhere".to_vec());
    }

    #[test]
    fn a_symlink_replaced_at_the_read_seam_is_73_never_a_mixed_pair() {
        // SEC S1 on 99b4b391: the identity and the target come through one handle on the link, and the name is
        // re-read after; a replacement between them refuses.
        let mut f = host();
        link(&mut f, "l", b"a/f");
        let x = expect(&mut f);
        f.hook = Some(("readlink", 1, swap_link));
        assert_eq!(code(tree_digest(&mut f, &args(&x, false))), 73);
        // Replaced between the identification and the handle's open: 73 too.
        let mut f = host();
        link(&mut f, "l", b"a/f");
        let x = expect(&mut f);
        f.hook = Some(("link_at", 1, swap_link));
        assert_eq!(code(tree_digest(&mut f, &args(&x, false))), 73);
    }

    #[test]
    fn identity_mismatches_are_73_with_nothing_printed() {
        // Another destination object than the recorded one.
        let mut f = host();
        let x = expect(&mut f);
        f.node(&dest()).id.ino += 1000;
        assert_eq!(code(tree_digest(&mut f, &args(&x, false))), 73);
        // A stale epoch.
        let mut f = host();
        let x = expect_file(&mut f, "stale.json", {
            let mut f2 = host();
            let good = expect(&mut f2);
            String::from_utf8(f2.files[&good[1..]].clone()).unwrap().replace(&format!("\"mnt_id\":{MNT}}}"), "\"mnt_id\":1}")
        });
        assert_eq!(code(tree_digest(&mut f, &args(&x, false))), 73);
        // Not in the class's project.
        let mut f = host();
        let x = expect(&mut f);
        f.node(&dest()).proj = UID + 1;
        assert!(matches!(code(tree_digest(&mut f, &args(&x, false))), 73));
    }

    #[test]
    fn every_bound_is_limit_64_with_nothing_printed() {
        let mut f = host();
        for i in 0..5 {
            put(&mut f, &format!("f{i}"), 0o600, b"x");
        }
        dir(&mut f, "d1", 0o700);
        dir(&mut f, "d1/d2", 0o700);
        let x = expect(&mut f);
        let a = args(&x, false);
        assert!(tree_digest_limited(&mut f.clone_fake(), &a, LIMITS).is_ok());
        assert_eq!(code(tree_digest_limited(&mut f.clone_fake(), &a, Limits { objects: 6, ..LIMITS })), 64, "one past the objects");
        assert_eq!(code(tree_digest_limited(&mut f.clone_fake(), &a, Limits { depth: 2, ..LIMITS })), 64, "one past the depth");
        let full = tree_digest(&mut f.clone_fake(), &a).unwrap();
        assert_eq!(code(tree_digest_limited(&mut f.clone_fake(), &a, Limits { listing: full.len() as u64 - 1, ..LIMITS })), 64, "one byte past");
        assert!(tree_digest_limited(&mut f.clone_fake(), &a, Limits { listing: full.len() as u64, ..LIMITS }).is_ok(), "exactly at the bound");
    }

    #[test]
    fn a_read_error_mid_walk_is_75_and_a_changed_file_changes_only_its_line() {
        let mut f = host();
        put(&mut f, "a", 0o600, b"one");
        put(&mut f, "b", 0o600, b"two");
        let x = expect(&mut f);
        let before = tree_digest(&mut f.clone_fake(), &args(&x, false)).unwrap();
        let mut g = f.clone_fake();
        g.errno_at = Some(("pread", 2, libc::EIO));
        assert_eq!(code(tree_digest(&mut g, &args(&x, false))), 75);
        // A file that's shorter than its size (changed under the read) is 75 too.
        let mut g = f.clone_fake();
        g.node(&format!("{}/a", dest())).id.size = 4;
        assert_eq!(code(tree_digest(&mut g, &args(&x, false))), 75);
        // One file's bytes changed: exactly its line differs.
        f.files.insert(format!("{}/b", dest()), b"TWO".to_vec());
        let after = tree_digest(&mut f, &args(&x, false)).unwrap();
        let diff: Vec<(&str, &str)> = before.lines().zip(after.lines()).filter(|(a, b)| a != b).collect();
        assert_eq!(diff.len(), 1);
        assert!(diff[0].0.contains("\"path\":\"b\""));
    }

    const MAIN: &[u8] = b"SQLite format 3\0rest of a database page";

    #[test]
    fn copy_sqlite_copies_mains_and_their_sidecars_whatever_their_header_in_the_hashing_pass() {
        let mut f = host();
        put(&mut f, "db", 0o600, MAIN);
        put(&mut f, "db-wal", 0o600, b"garbage, not a WAL header"); // copied whatever its magic (SEC S1a)
        put(&mut f, "x-wal", 0o600, b"an orphan sidecar"); // no main x: hashed and listed, its copy removed
        put(&mut f, "notwal", 0o600, &[0x37, 0x7f, 0x06, 0x82, 1, 2]); // WAL bytes, misnamed: an ordinary file
        let x = expect(&mut f);
        let out = tree_digest(&mut f, &args(&x, true)).unwrap();
        let h = h_of(b"db");
        let cdir = format!("{}/{RUN}/{}", VALIDATE.trim_start_matches('/'), owner());
        assert_eq!(f.files[&format!("{cdir}/{h}.db")], MAIN, "the copy IS the hashed bytes");
        assert_eq!(f.files[&format!("{cdir}/{h}.db-wal")], b"garbage, not a WAL header");
        let left: Vec<String> = f.children(&cdir);
        assert_eq!(left.len(), 2, "only the main and its sidecar remain: {left:?}");
        assert!(out.contains(&format!("\"path\":\"db\",\"type\":\"file\",\"size\":{},\"mode\":384,\"sha256\":\"{}\",\"copy\":\"{h}.db\"", MAIN.len(), sha(MAIN))));
        assert!(out.contains(&format!(",\"copy\":\"{h}.db-wal\"")));
        assert!(!out.lines().any(|l| l.contains("\"path\":\"x-wal\"") && l.contains("copy")), "the orphan has no copy key");
        assert!(!out.lines().any(|l| l.contains("\"path\":\"notwal\"") && l.contains("copy")));
        // fsync of the copies, the copy directory and its parent.
        assert!(f.log.iter().any(|l| l == &format!("fsync_file {cdir}/{h}.db")));
        assert!(f.log.iter().any(|l| l == &format!("fsync {cdir}")));
        // Nothing written outside the copy directory.
        assert!(!f.log.iter().any(|l| (l.starts_with("create ") || l.starts_with("rename ")) && !l.contains(&cdir)));
    }

    #[test]
    fn an_empty_sidecar_of_a_main_is_copied_and_bound_too() {
        // TESTS H1 on 99b4b391: a zero-byte db-wal or db-journal is copied (empty), fsynced and bound by its copy key;
        // an absent one makes no copy; an empty orphan is listed without a copy.
        for suf in ["-wal", "-journal"] {
            let mut f = host();
            put(&mut f, "db", 0o600, MAIN);
            put(&mut f, &format!("db{suf}"), 0o600, b"");
            put(&mut f, &format!("y{suf}"), 0o600, b"");
            let x = expect(&mut f);
            let out = tree_digest(&mut f, &args(&x, true)).unwrap();
            let h = h_of(b"db");
            let cdir = format!("{}/{RUN}/{}", VALIDATE.trim_start_matches('/'), owner());
            assert_eq!(f.files[&format!("{cdir}/{h}.db{suf}")], b"", "{suf}");
            assert!(f.log.iter().any(|l| l == &format!("fsync_file {cdir}/t0") || l == &format!("fsync_file {cdir}/t1")), "{suf}: fsynced");
            assert!(out.contains(&format!("\"path\":\"db{suf}\",\"type\":\"file\",\"size\":0,\"mode\":384,\"sha256\":\"{}\",\"copy\":\"{h}.db{suf}\"", sha(b""))), "{suf}: {out}");
            assert!(!out.lines().any(|l| l.contains(&format!("\"path\":\"y{suf}\"")) && l.contains("copy")), "{suf}: the orphan");
            assert_eq!(f.children(&cdir).len(), 2, "{suf}: the main and its sidecar only");
        }
        // Absent: no sidecar copy at all.
        let mut f = host();
        put(&mut f, "db", 0o600, MAIN);
        let x = expect(&mut f);
        tree_digest(&mut f, &args(&x, true)).unwrap();
        let cdir = format!("{}/{RUN}/{}", VALIDATE.trim_start_matches('/'), owner());
        assert_eq!(f.children(&cdir).len(), 1);
    }

    #[test]
    fn a_path_over_4096_raw_bytes_is_limit_with_nothing_printed() {
        // TESTS H2 on 99b4b391: exactly 4096 bytes passes, 4097 is limit; depth is far below its own bound.
        let comp = "c".repeat(240);
        let build = |f: &mut Fake, last: usize| {
            let mut rel = String::new();
            for _ in 0..16 {
                rel = if rel.is_empty() { comp.clone() } else { format!("{rel}/{comp}") };
                dir(f, &rel, 0o700);
            }
            // 16 components of 240 and 15 slashes: 3855 bytes; then a file named to reach `last` bytes in all.
            let name = "f".repeat(last - rel.len() - 1);
            put(f, &format!("{rel}/{name}"), 0o600, b"x");
        };
        let mut f = host();
        build(&mut f, MAX_PATH);
        let x = expect(&mut f);
        assert!(tree_digest(&mut f, &args(&x, false)).is_ok(), "exactly 4096");
        let mut f = host();
        build(&mut f, MAX_PATH + 1);
        let x = expect(&mut f);
        assert_eq!(code(tree_digest(&mut f, &args(&x, false))), 64, "4097");
    }

    #[test]
    fn r314_hoststore_is_never_listed() {
        let mut f = host();
        let x = expect(&mut f);
        let mut a = args(&x, false);
        a.owner = "host";
        a.class = "hoststore";
        let before = f.log.len();
        assert_eq!(code(tree_digest(&mut f, &a)), 64);
        assert_eq!(f.log.len(), before, "nothing read");
    }

    #[test]
    fn r313_config_is_never_listed_and_root_owners_only_for_archive_config() {
        // `config` is staged only: tree-digest of it is usage, before the expect is read.
        let mut f = host();
        let x = expect(&mut f);
        let mut a = args(&x, false);
        a.class = "config";
        let before = f.log.len();
        assert_eq!(code(tree_digest(&mut f, &a)), 64);
        assert_eq!(f.log.len(), before, "nothing read");
        // A sessions listing whose expect names root as an owner: the closed shape refuses (no other class lists root).
        let mut f = host();
        let root = f.root().unwrap();
        let ag = f.dir_from_root(&root, &format!("srv/sagebrush/agents/{A}")).unwrap();
        let (sx, _) = crate::tree::child(&mut f, &ag, "sessions", MNT).unwrap().unwrap();
        let x = expect_file(&mut f, "root-owners.json", format!("{{\"epoch\":{{\"boot_id\":\"{BOOT}\",\"mnt_id\":{MNT}}},\"fsid\":\"0000abcd00001234\",\"dest\":{},\"uids\":[0],\"gid\":0,\"projid\":{UID}}}", obj_json(&sx)));
        assert_eq!(code(tree_digest(&mut f, &args(&x, false))), crate::tree::bad_expect().fail.code(), "the expect's closed shape");
    }

    #[test]
    fn copy_sqlite_refusals() {
        // Another class than sessions: usage.
        let mut f = host();
        let x = expect(&mut f);
        let mut a = args(&x, true);
        a.class = "home";
        assert_eq!(code(tree_digest(&mut f, &a)), 64);
        // An existing <run>/<owner>: 74.
        let mut f = host();
        let x = expect(&mut f);
        let v = VALIDATE.trim_start_matches('/');
        f.dir(&format!("{v}/{RUN}"), 0, 0o700);
        f.node(&format!("{v}/{RUN}")).id.mnt_id = MNT + 50;
        f.dir(&format!("{v}/{RUN}/{}", owner()), 0, 0o700);
        f.node(&format!("{v}/{RUN}/{}", owner())).id.mnt_id = MNT + 50;
        assert_eq!(code(tree_digest(&mut f, &args(&x, true))), 74);
        // A <run> parent that isn't root 0700: 73.
        let mut f = host();
        let x = expect(&mut f);
        f.dir(&format!("{v}/{RUN}"), 0, 0o755);
        f.node(&format!("{v}/{RUN}")).id.mnt_id = MNT + 50;
        assert_eq!(code(tree_digest(&mut f, &args(&x, true))), 73);
        // The validate anchor on the quota mount: 73.
        let mut f = host();
        let x = expect(&mut f);
        f.node(v).id.mnt_id = MNT;
        assert_eq!(code(tree_digest(&mut f, &args(&x, true))), 73);
        // A host whose root filesystem IS the quota mount: the validate anchor, on the root's mount, is then on the quota
        // mount too, and still refused (73).
        let mut f = host();
        let x = expect(&mut f);
        for p in ["", "var", "var/lib", "var/lib/sagebrush", v] {
            f.node(p).id.mnt_id = MNT;
        }
        assert_eq!(code(tree_digest(&mut f, &args(&x, true))), 73);
        // The validate anchor on a third mount (neither the root's nor the quota's): 73 (SEC S2).
        let mut f = host();
        let x = expect(&mut f);
        f.node(v).id.mnt_id = MNT + 77;
        assert_eq!(code(tree_digest(&mut f, &args(&x, true))), 73);
        // A main's -wal sibling that is a directory: 73.
        let mut f = host();
        put(&mut f, "db", 0o600, MAIN);
        dir(&mut f, "db-wal", 0o700);
        let x = expect(&mut f);
        assert_eq!(code(tree_digest(&mut f, &args(&x, true))), 73);
        // A main's -journal sibling that is a symlink: 73.
        let mut f = host();
        put(&mut f, "db", 0o600, MAIN);
        link(&mut f, "db-journal", b"elsewhere");
        let x = expect(&mut f);
        assert_eq!(code(tree_digest(&mut f, &args(&x, true))), 73);
        // Past the copy cap: limit.
        let mut f = host();
        put(&mut f, "db", 0o600, MAIN);
        let x = expect(&mut f);
        assert_eq!(code(tree_digest_limited(&mut f, &args(&x, true), Limits { copy: MAIN.len() as u64 - 1, ..LIMITS })), 64);
    }

    #[test]
    fn the_path_codec_is_lossless_and_sorting_uses_raw_bytes() {
        assert_eq!(encode(b"plain/name"), "plain/name");
        assert_eq!(encode(b"a%b"), "a%25b");
        assert_eq!(encode(&[b'a', 0xff, b'b']), "a%FFb");
        assert_eq!(encode("é/日本".as_bytes()), "é/日本");
        assert_eq!(encode(&[0xc3]), "%C3", "a truncated multibyte sequence");
        assert_eq!(encode(&[0xe6, 0x97, b'x']), "%E6%97x");
        // Distinct raw names never encode alike.
        assert_ne!(encode(b"%FF"), encode(&[0xff]));
        // Raw-byte order: 'Z' (0x5a) < 'a' < 0xc3 (é's first byte).
        let mut v: Vec<Vec<u8>> = vec!["é".into(), b"a".to_vec(), b"Z".to_vec()];
        v.sort();
        assert_eq!(v, vec![b"Z".to_vec(), b"a".to_vec(), "é".as_bytes().to_vec()]);
    }

    #[test]
    fn remove_tree_accepts_the_copy_directory_name_beneath_the_validate_anchor() {
        assert!(crate::tree::anchor_name_ok(VALIDATE, &format!("{RUN}/{}", owner())));
        assert!(!crate::tree::anchor_name_ok(VALIDATE, &owner()));
        assert!(!crate::tree::anchor_name_ok(VALIDATE, &format!("{RUN}/{}/x", owner())));
        assert!(!crate::tree::anchor_name_ok(VALIDATE, &format!("short/{}", owner())));
    }

    /// The shared listing corpus (test/fixtures/listing-corpus.json, the restore validator's own fixture): each row's
    /// raw bytes rendered by tree-digest must be its exact line, byte for byte (A2 r3.9 §7). The row marked invalid (a
    /// symlink with an empty target, which no kernel lets the walker see) is the reader's to refuse: render doesn't
    /// judge, so it isn't compared.
    #[test]
    fn the_shared_listing_corpus_renders_byte_for_byte() {
        let raw = include_bytes!("../../test/fixtures/listing-corpus.json");
        let v = crate::json::parse(raw).expect("the corpus parses");
        let get = |o: &crate::json::Value, k: &str| -> Option<crate::json::Value> {
            match o {
                crate::json::Value::Obj(kv) => kv.iter().find(|(x, _)| x == k).map(|(_, v)| v.clone()),
                _ => None,
            }
        };
        let hex = |s: &str| -> Vec<u8> { (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect() };
        let rows = get(&v, "rows").unwrap();
        let rows = rows.arr().unwrap();
        assert_eq!(rows.len(), 20, "the corpus has its 20 rows");
        let mut checked = 0;
        for r in rows {
            let s = |k: &str| get(r, k).and_then(|x| x.str().map(str::to_string));
            let name = s("name").unwrap();
            if get(r, "valid") == Some(crate::json::Value::Bool(false)) {
                continue;
            }
            let ty = match s("type").unwrap().as_str() {
                "file" => Ty::File,
                "dir" => Ty::Dir,
                "symlink" => Ty::Symlink,
                t => panic!("{name}: type {t}"),
            };
            let sha = s("sha256").map(|h| <[u8; 32]>::try_from(hex(&h)).unwrap());
            let e = Entry {
                path: hex(&s("raw_path_hex").unwrap()),
                unexpected: None,
                ty,
                size: get(r, "size").unwrap().int().unwrap(),
                mode: get(r, "mode").unwrap().int().unwrap() as u16,
                sha,
                target: s("raw_target_hex").map(|h| hex(&h)),
                copy: None,
            };
            assert_eq!(e.render(), format!("{}\n", s("line").unwrap()), "{name}");
            checked += 1;
        }
        assert_eq!(checked, 19, "every valid row");
    }
}
