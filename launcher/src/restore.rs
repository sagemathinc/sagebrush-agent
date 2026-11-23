//! Launcher contract amendment A2 r3.4 (backup restore): `restore-stage` and `fill-home`. Root only, run by the
//! supervisor outside any unit, on A1's shared rules (the anchor policy, openat2 one component at a time with
//! RESOLVE_NO_XDEV, identity from opened handles, the epoch and the unique mount id).
//!
//! - `restore-stage` makes one staging attempt of one class (`<run>/<owner>/<class>/<attempt>` under
//!   /srv/sagebrush/.restore, charged to the class's project), runs the backup binary's restore into its `data/` in a
//!   contained child (child.rs), and only after the data is durable writes the completion marker itself.
//! - `fill-home` consumes an attempt (the marker is unlinked first), drops CAP_SYS_RESOURCE, and moves the staged
//!   class into its empty, provisioned destination: owners checked, specials never placed, every file stripped
//!   (setuid, setgid, every extended attribute) and synced in staging BEFORE its rename, then a durability barrier.
//! - Quota and no-space failures are attributed by the kernel's own numbers (§3.1): 76 `quota`, 77 `no_space`.
//!
//! The logic is generic over `RestoreOps` (A1's `Ops` plus what A2 adds) and `Runner` (the child process), so the
//! tests run every branch against fakes.

use crate::args::is_id;
use crate::child::{Bind, Plan, Stage, BINARY};
use crate::err::{err, Error, Fail, Result};
use crate::json::{self, Value};
use crate::sys::{self, Ident, Quota};
use crate::tree::{self, anchor_policy, child as tchild, epoch_now, identity, kind_of, obj_of, open_err, pre, At, Kind, Ops, S_IFMT};
use std::ffi::CString;
use std::io;

pub const RESTORE: &str = "/srv/sagebrush/.restore";
pub const STATE: &str = "/var/lib/sagebrush/backup/state";
pub const SECRETS: &str = "/var/lib/sagebrush/host-secrets";
pub const CACHE: &str = "/var/cache/sagebrush-backup";
/// The closed system set (A2 r3.3 §3 step 6): the TLS roots and musl's resolver files, read-only; nothing else.
pub const SYSTEM: [(&str, bool); 4] = [("etc/ssl/certs", false), ("etc/ca-certificates", false), ("etc/resolv.conf", true), ("etc/hosts", true)];
/// The request's encoded bound (A2 r3.2): at most this many bytes as JSON, else usage.
pub const MAX_REQUEST: usize = 4096;
/// The child's stdout and kept stderr (A2 S-b).
pub const MAX_OUT: usize = 64 * 1024;
const MAX_LIST: usize = 1000;
const MAX_MARKER: usize = 64;
const MAX_UIDS: usize = 64;
const MARKER: &str = ".complete";
const MAX_ELF_PHNUM: usize = 64;
/// A system-set file may be owned by root or by a system service account below this uid: on a stock Ubuntu 24.04
/// host, /etc/resolv.conf resolves to systemd-resolved's stub file, owned by `systemd-resolve`. Agents (70000+) and
/// people (1000+) never own one. The bind is read-only to the child either way.
const SYSTEM_OWNER_MAX: u32 = 1000;
/// CAP_SYS_RESOURCE.
const SYS_RESOURCE: u32 = 24;

// ---- names (A2 §2)

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    Home,
    Sessions,
    Archive,
    Tag,
}

/// One attempt's name: `<run>/<owner>/<class>/<attempt>`, every part validated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Name {
    pub run: String,
    pub owner: String,
    /// The owner's fleet id (an agent's or a tag's).
    pub id: String,
    pub class: Class,
    pub attempt: u32,
}

impl Name {
    pub fn parse(run: &str, owner: &str, class: &str, attempt: &str) -> Option<Name> {
        if run.len() != 16 || !run.bytes().all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b)) {
            return None;
        }
        let (agent, id) = match owner.split_at_checked(2)? {
            ("a-", id) if is_id(id) => (true, id),
            ("t-", id) if is_id(id) => (false, id),
            _ => return None,
        };
        let class = match (class, agent) {
            ("home", true) => Class::Home,
            ("sessions", true) => Class::Sessions,
            ("archive", true) => Class::Archive,
            ("tag", false) => Class::Tag,
            _ => return None,
        };
        if attempt.is_empty() || attempt.len() > 6 || attempt.starts_with('0') || !attempt.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        Some(Name { run: run.to_string(), owner: owner.to_string(), id: id.to_string(), class, attempt: attempt.parse().ok()? })
    }
    fn class_str(&self) -> &'static str {
        match self.class {
            Class::Home => "home",
            Class::Sessions => "sessions",
            Class::Archive => "archive",
            Class::Tag => "tag",
        }
    }
    /// The name beneath the anchor, and the marker's exact content.
    pub fn path(&self) -> String {
        format!("{}/{}/{}/{}", self.run, self.owner, self.class_str(), self.attempt)
    }
    pub fn parts(&self) -> [String; 4] {
        [self.run.clone(), self.owner.clone(), self.class_str().to_string(), self.attempt.to_string()]
    }
    /// The project id range for the owner (agents 70000-79999, tags 80000-89999).
    pub fn projid_ok(&self, projid: u32) -> bool {
        if self.class == Class::Tag { (80000..=89999).contains(&projid) } else { (70000..=79999).contains(&projid) }
    }
}

/// `<run>/<owner>/<class>/<attempt>` as one string (remove-tree's `--name` beneath `.restore`).
pub fn name_of(s: &str) -> Option<Name> {
    let p: Vec<&str> = s.split('/').collect();
    if p.len() != 4 {
        return None;
    }
    Name::parse(p[0], p[1], p[2], p[3])
}

/// A normalized relative path: no leading or trailing '/', no empty, "." or ".." segment, no NUL. Its length is
/// bounded by the encoded request, not here (A2 r3.2).
pub fn rel_ok(s: &str) -> bool {
    !s.is_empty() && !s.contains('\0') && s.split('/').all(|seg| !seg.is_empty() && seg != "." && seg != "..")
}

fn snapshot_ok(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// The closed request, built here and bounded AS ENCODED (A2 r3.2): a control character escapes to six bytes, so the
/// raw path length proves nothing.
pub fn request(snapshot: &str, path: &str) -> Result<Vec<u8>> {
    if !snapshot_ok(snapshot) || !rel_ok(path) {
        return Err(err(Fail::Usage, "bad arguments"));
    }
    let r = format!("{{\"op\":\"restore\",\"snapshot\":{},\"path\":{},\"dest\":\"/data\"}}", json::quote(snapshot), json::quote(path));
    if r.len() > MAX_REQUEST {
        return Err(err(Fail::Usage, "the request is too large"));
    }
    Ok(r.into_bytes())
}

// ---- the operations A2 adds to A1's

pub trait RestoreOps: Ops {
    fn mkdir(&mut self, dir: &Self::H, name: &str, mode: u16) -> io::Result<()>;
    fn set_project(&mut self, h: &Self::H, projid: u32) -> io::Result<()>;
    fn chown(&mut self, h: &Self::H, uid: u32, gid: u32) -> io::Result<()>;
    /// Every extended attribute's name.
    fn xattrs(&mut self, h: &Self::H) -> io::Result<Vec<CString>>;
    /// Remove one (ENODATA is done).
    fn remove_xattr(&mut self, h: &Self::H, name: &CString) -> io::Result<()>;
    fn fsync_file(&mut self, h: &Self::H) -> io::Result<()>;
    /// Create `name` exclusively (0600), write `body` whole, fsync it.
    fn create_marker(&mut self, dir: &Self::H, name: &str, body: &[u8]) -> io::Result<()>;
    /// Read an opened regular file whole, at most `max` bytes (else EFBIG).
    fn read_small(&mut self, h: &Self::H, max: usize) -> io::Result<Vec<u8>>;
    fn syncfs(&mut self, h: &Self::H) -> io::Result<()>;
    fn quota(&mut self, h: &Self::H, projid: u32) -> io::Result<Quota>;
    /// (f_bavail, f_ffree).
    fn space(&mut self, h: &Self::H) -> io::Result<(u64, u64)>;
    fn now(&mut self) -> u64;
    /// proc/self/exe's target text, read through the root (never followed).
    fn exe_target(&mut self, root: &Self::H) -> io::Result<String>;
    fn pread(&mut self, h: &Self::H, len: usize, off: u64) -> io::Result<Vec<u8>>;
    /// One closed system-set entry, opened O_PATH inside the root (ordinary symlinks followed, magic links never).
    fn open_system(&mut self, root: &Self::H, rel: &str) -> io::Result<Self::H>;
    /// CAP_SYS_RESOURCE dropped from all five sets of THIS process, and verified (fill-home, A2 §4 step 3).
    fn drop_sys_resource(&mut self) -> io::Result<()>;
}

// ---- §3.1: whose limit was hit

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Limit {
    Quota,
    QuotaUnknown,
    NoSpace,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Side {
    Reached,
    NotReached,
    Unknown,
}

fn side(valid: bool, cur: u64, hard: Option<u64>, soft: Option<u64>, time: u64, now: u64) -> Side {
    if !valid {
        return Side::Unknown;
    }
    // A limit of 0 is none; an overflowed conversion (None) is a limit beyond any reachable usage.
    let hard_hit = matches!(hard, Some(h) if h != 0 && cur >= h);
    let soft_hit = matches!(soft, Some(s) if s != 0 && cur > s) && time != 0 && time <= now;
    if hard_hit || soft_hit { Side::Reached } else { Side::NotReached }
}

/// The rule of A2 r3.1 §3.1, in the kernel's units: `dqb_curspace` is bytes, block limits are 1024-byte quota blocks
/// (checked_mul), inode fields are counts; `dqb_valid` gates each side; soft limits count only past grace.
pub fn classify(q: io::Result<Quota>, space: io::Result<(u64, u64)>, now: u64) -> Limit {
    let Ok(q) = q else { return Limit::QuotaUnknown };
    let bits = |m: u32| q.valid & m == m;
    let blocks_valid = bits(sys::QIF_SPACE | sys::QIF_BLIMITS | sys::QIF_BTIME);
    let inodes_valid = bits(sys::QIF_INODES | sys::QIF_ILIMITS | sys::QIF_ITIME);
    // A zero limit stays zero (none); a non-zero one that overflows becomes None (never reached).
    let bytes = |blocks: u64| if blocks == 0 { Some(0) } else { blocks.checked_mul(1024) };
    let b = side(blocks_valid, q.curspace, bytes(q.bhard), bytes(q.bsoft), q.btime, now);
    let i = side(inodes_valid, q.curinodes, Some(q.ihard), Some(q.isoft), q.itime, now);
    if b == Side::Reached || i == Side::Reached {
        return Limit::Quota;
    }
    if b == Side::Unknown || i == Side::Unknown {
        return Limit::QuotaUnknown;
    }
    match space {
        Ok((bavail, ffree)) if bavail == 0 || ffree == 0 => Limit::NoSpace,
        // Neither (an EDQUOT just under the hard limit included, on purpose): never retried automatically.
        _ => Limit::QuotaUnknown,
    }
}

fn limit_error(l: Limit) -> Error {
    match l {
        Limit::Quota => err(Fail::Quota, "quota"),
        Limit::QuotaUnknown => err(Fail::Quota, "quota_unknown"),
        Limit::NoSpace => err(Fail::NoSpace, "the filesystem is out of blocks or inodes"),
    }
}

fn is_space_error(e: &io::Error) -> bool {
    matches!(e.raw_os_error(), Some(libc::EDQUOT) | Some(libc::ENOSPC))
}

// ---- the backup binary's result (A2 S-b)

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reply {
    /// The snapshot the binary restored (its full id) and how many specials it skipped.
    Ok(String, u64),
    Failed(String),
}

/// Exactly one JSON object on one line, then EOF, of the closed shape; anything else is None (`bad_result`).
pub fn reply(out: &[u8]) -> Option<Reply> {
    let body = out.strip_suffix(b"\n")?;
    if body.first() != Some(&b'{') || body.contains(&b'\n') {
        return None;
    }
    let v = json::parse_with(body, MAX_OUT)?;
    if let Some(f) = v.exact(&["ok", "snapshot", "skipped_special"]) {
        if f[0] != &Value::Bool(true) {
            return None;
        }
        let snap = f[1].str().filter(|s| snapshot_ok(s))?;
        // A non-negative integer: the reader refuses signs, fractions and exponents.
        return Some(Reply::Ok(snap.to_string(), f[2].int()?));
    }
    let f = v.exact(&["ok", "error"])?;
    if f[0] != &Value::Bool(false) {
        return None;
    }
    let e = f[1].exact(&["code", "message"])?;
    e[1].str()?;
    Some(Reply::Failed(e[0].str()?.to_string()))
}

// ---- the child process, abstracted for the tests

/// What the child did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ran {
    /// Nothing was started (a pipe or the fork failed).
    NotStarted,
    /// A pre-exec stage failed: its record from the status pipe.
    PreExec(Stage, i32),
    /// The binary ran: its stdout (at most MAX_OUT bytes), and whether it tried to write more (then it was killed).
    Exited { stdout: Vec<u8>, overflow: bool },
    /// The parent lost track (a poll or read failure, an unreadable status record): the child was killed.
    Lost,
}

pub trait Runner<H> {
    /// Fork the child for `plan` (its `parent` is filled in by the runner), put `request` on its stdin, and wait.
    fn run(&mut self, plan: &mut Plan<'_, H>, request: &[u8]) -> Ran;
}

// ---- restore-stage (A2 §3)

pub struct StageArgs<'a> {
    pub mount: &'a str,
    pub name: Name,
    pub projid: u32,
    pub snapshot: &'a str,
    pub path: &'a str,
}

/// The result: what to print on stdout (the binary's line on success, or relayed on a 75), and the outcome.
pub struct Done {
    pub out: Vec<u8>,
    pub result: Result<()>,
}

fn done(r: Result<()>) -> Done {
    Done { out: Vec::new(), result: r }
}

/// A staging parent (`<run>`, `<owner>`, `<class>`): opened, or made 0700 when absent; root:root 0700 on the anchor's
/// mount, else 73.
fn staging_dir<O: RestoreOps>(o: &mut O, parent: &O::H, name: &str, mnt: u64) -> Result<O::H> {
    if tchild(o, parent, name, mnt)?.is_none() {
        match o.mkdir(parent, name, 0o700) {
            Ok(()) => {
                if let Some((_, Some(h))) = tchild(o, parent, name, mnt)? {
                    o.chmod(&h, 0o700).map_err(|_| pre("a staging directory's mode can't be set"))?;
                }
            }
            Err(e) if e.raw_os_error() == Some(libc::EEXIST) => {}
            Err(_) => return Err(pre("a staging directory can't be made")),
        }
    }
    match tchild(o, parent, name, mnt)? {
        Some((x, Some(h))) if x.kind == Kind::Dir && x.uid == 0 && x.gid == 0 && x.mode == 0o700 => Ok(h),
        _ => Err(identity("a staging directory isn't root:root 0700")),
    }
}

/// The release binary (A2 §3 step 4): the launcher's own directory, from proc/self/exe; the binary beneath it a
/// regular, root-owned, not group- or other-writable file with one link; statically linked (no PT_INTERP).
fn release<O: RestoreOps>(o: &mut O, root: &O::H) -> Result<(O::H, Ident)> {
    let target = o.exe_target(root).map_err(|_| pre("the launcher's path can't be read"))?;
    if target.ends_with(" (deleted)") || !target.starts_with('/') {
        return Err(pre("the launcher's release was replaced"));
    }
    let dir = &target[..target.rfind('/').unwrap_or(0)];
    let rel = crate::args::rel(dir).ok_or(pre("the launcher's directory isn't a plain path"))?;
    let d = o.dir_from_root(root, rel).map_err(|_| pre("the release directory can't be opened"))?;
    let di = o.ident(&d).map_err(open_err)?;
    if kind_of(&di) != Some(Kind::Dir) || di.uid != 0 || di.mode & 0o022 != 0 {
        return Err(pre("the release directory isn't root-only"));
    }
    let p = o.at(&d, BINARY, At::Path).map_err(|_| pre("the backup binary is missing"))?;
    let bi = o.ident(&p).map_err(open_err)?;
    if kind_of(&bi) != Some(Kind::File) || bi.uid != 0 || bi.mode & 0o022 != 0 || bi.nlink != 1 {
        return Err(pre("the backup binary isn't a root-only regular file with one link"));
    }
    let f = o.at(&d, BINARY, At::File).map_err(|_| pre("the backup binary can't be opened"))?;
    let again = o.ident(&f).map_err(open_err)?;
    if (again.dev, again.ino) != (bi.dev, bi.ino) {
        return Err(pre("the backup binary changed"));
    }
    if !elf_static(|len, off| o.pread(&f, len, off))? {
        return Err(pre("the backup binary isn't statically linked"));
    }
    Ok((d, bi))
}

/// A closed ELF64 little-endian header parse with bounded reads: Ok(false) if any program header is PT_INTERP (a
/// dynamic loader). That alone decides it (A2 r3.2 P2): a static-pie binary has PT_DYNAMIC but no PT_INTERP.
/// Anything malformed or truncated refuses (66).
pub fn elf_static(mut read: impl FnMut(usize, u64) -> io::Result<Vec<u8>>) -> Result<bool> {
    let bad = || pre("the backup binary isn't a well-formed ELF64 file");
    let h = read(64, 0).map_err(|_| bad())?;
    if h.len() != 64 || h[..4] != [0x7f, b'E', b'L', b'F'] || h[4] != 2 || h[5] != 1 {
        return Err(bad());
    }
    let u16_at = |b: &[u8], i: usize| u16::from_le_bytes([b[i], b[i + 1]]);
    let phoff = u64::from_le_bytes(h[32..40].try_into().map_err(|_| bad())?);
    let (phentsize, phnum) = (u16_at(&h, 54) as usize, u16_at(&h, 56) as usize);
    if phentsize != 56 || phnum == 0 || phnum > MAX_ELF_PHNUM {
        return Err(bad());
    }
    let ph = read(phentsize * phnum, phoff).map_err(|_| bad())?;
    if ph.len() != phentsize * phnum {
        return Err(bad());
    }
    const PT_INTERP: u32 = 3;
    Ok(!(0..phnum).any(|i| u32::from_le_bytes(ph[i * 56..i * 56 + 4].try_into().unwrap_or([0; 4])) == PT_INTERP))
}

pub fn restore_stage<O: RestoreOps, R: Runner<O::H>>(o: &mut O, r: &mut R, a: &StageArgs) -> Done {
    let n = &a.name;
    // 1. Arguments (64): the request is built and bounded as encoded before any effect.
    let req = match request(a.snapshot, a.path) {
        Ok(v) => v,
        Err(e) => return done(Err(e)),
    };
    if !n.projid_ok(a.projid) {
        return done(Err(err(Fail::Usage, "bad arguments")));
    }
    match stage_inner(o, r, a, &req) {
        Ok(d) => d,
        Err(e) => done(Err(e)),
    }
}

fn stage_inner<O: RestoreOps, R: Runner<O::H>>(o: &mut O, r: &mut R, a: &StageArgs, req: &[u8]) -> Result<Done> {
    let n = &a.name;
    let root = o.root().map_err(|_| pre("the root can't be opened"))?;
    // 2. The anchors and the mount.
    let ra = anchor_policy(o, &root, RESTORE)?;
    let mnt = o.ident(&ra).map_err(open_err)?.mnt_id;
    let m = anchor_policy(o, &root, tree::parse_mount(a.mount)?)?;
    if o.ident(&m).map_err(open_err)?.mnt_id != mnt {
        return Err(pre("the restore anchor isn't on the quota mount"));
    }
    let state = anchor_policy(o, &root, STATE)?;
    let secrets = anchor_policy(o, &root, SECRETS)?;
    let cache = anchor_policy(o, &root, CACHE)?;
    // The closed system set: each present entry owned by root or a system service account, not group- or
    // other-writable, of its expected kind.
    let mut system = Vec::new();
    for (rel, file) in SYSTEM {
        let h = match o.open_system(&root, rel) {
            Ok(h) => h,
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => continue,
            Err(_) => return Err(pre("a system file can't be opened")),
        };
        let id = o.ident(&h).map_err(open_err)?;
        let want = if file { Kind::File } else { Kind::Dir };
        if kind_of(&id) != Some(want) || id.uid >= SYSTEM_OWNER_MAX || id.mode & 0o022 != 0 {
            return Err(pre("a system file isn't owned by root or a system account, or is writable by others"));
        }
        system.push((rel, file, h, id));
    }
    // 4 (before any effect). The release binary, by handle.
    let (rel_dir, bin) = release(o, &root)?;

    // 3. The attempt directory, and data beneath it.
    let [run, owner, class, attempt] = n.parts();
    let run_h = staging_dir(o, &ra, &run, mnt)?;
    let owner_h = staging_dir(o, &run_h, &owner, mnt)?;
    let class_h = staging_dir(o, &owner_h, &class, mnt)?;
    match o.mkdir(&class_h, &attempt, 0o700) {
        Ok(()) => {}
        Err(e) if e.raw_os_error() == Some(libc::EEXIST) => return Err(err(Fail::Exists, "the attempt exists")),
        Err(_) => return Err(pre("the attempt can't be made")),
    }
    let (ax, ah) = tchild(o, &class_h, &attempt, mnt)?.ok_or(identity("the attempt vanished"))?;
    let att = ah.ok_or(identity("the attempt isn't a directory"))?;
    o.chmod(&att, 0o700).map_err(|_| identity("the attempt's mode can't be set"))?;
    if ax.uid != 0 || ax.gid != 0 || !o.batch(&att).map_err(open_err)?.is_empty() {
        return Err(identity("the attempt isn't a fresh, empty root directory"));
    }
    o.set_project(&att, a.projid).map_err(|_| identity("the attempt's project id can't be set"))?;
    let att_x = tchild(o, &class_h, &attempt, mnt)?.ok_or(identity("the attempt vanished"))?.0;
    if att_x.projid != Some(a.projid) || att_x.inherit != Some(true) || att_x.mode != 0o700 {
        return Err(identity("the attempt's project id didn't read back"));
    }
    o.mkdir(&att, "data", 0o700).map_err(|_| identity("data can't be made"))?;
    let (_, dh) = tchild(o, &att, "data", mnt)?.ok_or(identity("data vanished"))?;
    let data = dh.ok_or(identity("data isn't a directory"))?;
    o.chmod(&data, 0o700).map_err(|_| identity("data's mode can't be set"))?;
    let dx = tchild(o, &att, "data", mnt)?.ok_or(identity("data vanished"))?.0;
    if dx.uid != 0 || dx.gid != 0 || dx.mode != 0o700 || dx.projid != Some(a.projid) || dx.inherit != Some(true) {
        return Err(identity("data isn't a root 0700 directory of the class's project"));
    }
    for h in [&data, &att, &class_h] {
        o.fsync(h).map_err(|_| err(Fail::Partial, "the attempt can't be synced"))?;
    }

    // 5-10. The child, contained; the parent waits, bounded.
    let ids = |o: &mut O, h: &O::H| -> Result<((u32, u32), u64)> {
        let i = o.ident(h).map_err(open_err)?;
        Ok((i.dev, i.ino))
    };
    let (data_id, cache_id, state_id, secrets_id, rel_id) = (ids(o, &data)?, ids(o, &cache)?, ids(o, &state)?, ids(o, &secrets)?, ids(o, &rel_dir)?);
    let mut binds = vec![
        Bind { src: &data, at: "data", file: false, write: true, exec: false, recheck: true, id: data_id },
        Bind { src: &cache, at: "cache", file: false, write: true, exec: false, recheck: true, id: cache_id },
        Bind { src: &state, at: "state", file: false, write: false, exec: false, recheck: true, id: state_id },
        Bind { src: &secrets, at: "secrets", file: false, write: false, exec: false, recheck: true, id: secrets_id },
        Bind { src: &rel_dir, at: "release", file: false, write: false, exec: true, recheck: true, id: rel_id },
    ];
    for (rel, file, h, id) in &system {
        binds.push(Bind { src: h, at: rel, file: *file, write: false, exec: false, recheck: false, id: (id.dev, id.ino) });
    }
    let ai = o.ident(&att).map_err(open_err)?;
    let attempt_path = format!("{}/{}", &RESTORE[1..], n.path());
    let mut plan = Plan { parent: 0, attempt: &att, attempt_path, attempt_id: (ai.dev, ai.ino), binds, binary: (bin.dev, bin.ino) };
    let ran = r.run(&mut plan, req);
    let stdout = match ran {
        Ran::NotStarted => return Err(err(Fail::Internal, "the restore child can't be started")),
        Ran::PreExec(stage, _) => return Err(err(stage.fail(), "the restore child failed before the exec")),
        Ran::Lost => return Err(err(Fail::Partial, "the restore child was lost")),
        Ran::Exited { overflow: true, .. } => return Err(err(Fail::Partial, "bad_result")),
        Ran::Exited { stdout, overflow: false } => stdout,
    };
    match reply(&stdout) {
        None => Err(err(Fail::Partial, "bad_result")),
        Some(Reply::Failed(code)) if code == "quota_exceeded" || code == "no_space" => {
            let (q, s, now) = (o.quota(&att, a.projid), o.space(&att), o.now());
            Err(limit_error(classify(q, s, now)))
        }
        Some(Reply::Failed(_)) => Ok(Done { out: stdout, result: Err(err(Fail::Partial, "the restore failed")) }),
        Some(Reply::Ok(snap, _)) if snap != a.snapshot => Err(err(Fail::Partial, "the restored snapshot isn't the requested one")),
        Some(Reply::Ok(..)) => {
            // 11. The marker, written by the launcher only, once the data is durable (O1, O2).
            o.syncfs(&att).map_err(|_| err(Fail::Partial, "the staged data can't be made durable"))?;
            o.create_marker(&att, MARKER, n.path().as_bytes()).map_err(|_| err(Fail::Partial, "the marker can't be written"))?;
            o.fsync(&att).map_err(|_| err(Fail::Partial, "the marker can't be made durable"))?;
            Ok(Done { out: stdout, result: Ok(()) })
        }
    }
}

// ---- fill-home (A2 §4)

pub struct FillArgs<'a> {
    pub mount: &'a str,
    pub name: Name,
    pub source: &'a str,
    pub expect: &'a str,
}

fn dest_anchor(c: Class) -> &'static str {
    match c {
        Class::Home | Class::Sessions => "/srv/sagebrush/agents",
        Class::Archive => "/srv/sagebrush/archive",
        Class::Tag => "/srv/sagebrush/tags",
    }
}

struct Fill {
    uids: Vec<u32>,
    gid: u32,
    projid: u32,
    mnt: u64,
    /// The object bound (A1's 2,000,000; smaller in a test).
    limit: usize,
    effects: usize,
    dirs: u64,
    files: u64,
    symlinks: u64,
    refused: Vec<(String, u32, u32, u64)>,
    unexpected: Vec<(String, &'static str)>,
    truncated: bool,
}

impl Fill {
    /// Before the first effect, a refusal is 73; after it, 75.
    fn fail(&self, msg: &'static str) -> Error {
        if self.effects == 0 { identity(msg) } else { err(Fail::Partial, msg) }
    }
    fn refuse(&mut self, path: String, uid: u32, gid: u32, entries: u64) {
        if self.refused.len() < MAX_LIST { self.refused.push((path, uid, gid, entries)) } else { self.truncated = true }
    }
    fn odd(&mut self, path: String, t: &'static str) {
        if self.unexpected.len() < MAX_LIST { self.unexpected.push((path, t)) } else { self.truncated = true }
    }
}

/// An I/O failure during the fill: EDQUOT or ENOSPC classified by §3.1 against the destination; anything else 73/75.
fn io_fail<O: RestoreOps>(o: &mut O, w: &Fill, dest: &O::H, e: io::Error, msg: &'static str) -> Error {
    if is_space_error(&e) {
        let (q, s, now) = (o.quota(dest, w.projid), o.space(dest), o.now());
        limit_error(classify(q, s, now))
    } else {
        w.fail(msg)
    }
}

fn special_name(mode: u16) -> &'static str {
    match mode & S_IFMT {
        0o020000 => "char",
        0o060000 => "block",
        0o010000 => "fifo",
        0o140000 => "socket",
        _ => "other",
    }
}

/// An entry of a staging directory, identified without opening it for reading: (identity, its kind or None for a
/// special). A symlink is identified by name.
fn entry<O: RestoreOps>(o: &mut O, w: &Fill, dir: &O::H, name: &str) -> Result<(Ident, Option<Kind>)> {
    let id = match o.at(dir, name, At::Path) {
        Ok(h) => o.ident(&h).map_err(|_| w.fail("an entry can't be identified"))?,
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {
            let id = o.ident_at(dir, name).map_err(|_| w.fail("an entry can't be identified"))?;
            if kind_of(&id) != Some(Kind::Symlink) {
                return Err(w.fail("a changed entry"));
            }
            id
        }
        Err(e) if e.raw_os_error() == Some(libc::EXDEV) => return Err(w.fail("a mount below the staging")),
        Err(_) => return Err(w.fail("an entry vanished")),
    };
    if id.mnt_id != w.mnt {
        return Err(w.fail("another mount below the staging"));
    }
    Ok((id, kind_of(&id)))
}

/// The dry pass (before any effect): bounds (2,000,000 objects, depth 256) and types only. Returns the count.
fn scan<O: RestoreOps>(o: &mut O, w: &Fill, dir: &O::H, depth: usize, count: &mut usize) -> Result<()> {
    if depth > tree::MAX_DEPTH {
        return Err(w.fail("the staged class is too deep"));
    }
    loop {
        let names = o.batch(dir).map_err(|_| w.fail("a staging directory can't be listed"))?;
        if names.is_empty() {
            return Ok(());
        }
        for name in names {
            *count += 1;
            if *count > w.limit {
                return Err(w.fail("the staged class is too large"));
            }
            if let (_, Some(Kind::Dir)) = entry(o, w, dir, &name)? {
                let h = o.at(dir, &name, At::Dir).map_err(|_| w.fail("a staging directory can't be opened"))?;
                scan(o, w, &h, depth + 1, count)?;
            }
        }
    }
}

fn join(rel: &str, name: &str) -> String {
    if rel.is_empty() { name.to_string() } else { format!("{rel}/{name}") }
}

/// The walk, top-down (A2 §4 step 5), for the staging directory `sname` beneath `sp` (identity `sid`) into `dst`.
/// Entries are moved out while the directory is read, so it is read in ROUNDS, each through a freshly opened handle,
/// until a round finds nothing new (as A1's remove-tree pass 2): a listing may skip a name while names leave, never
/// invent one. Only the names that stay in staging (refused, unexpected) are remembered between rounds.
#[allow(clippy::too_many_arguments)]
fn walk<O: RestoreOps>(o: &mut O, w: &mut Fill, sp: &O::H, sname: &str, sid: ((u32, u32), u64), dst: &O::H, rel: &str, depth: usize) -> Result<()> {
    if depth > tree::MAX_DEPTH {
        return Err(w.fail("the staged class is too deep"));
    }
    let mut kept = std::collections::BTreeSet::new();
    let mut rounds = 0usize;
    loop {
        rounds += 1;
        if rounds > w.limit {
            return Err(w.fail("the staged class is too large"));
        }
        let src = o.at(sp, sname, At::Dir).map_err(|_| w.fail("a staging directory can't be opened"))?;
        let si = o.ident(&src).map_err(|_| w.fail("a staging directory can't be identified"))?;
        if (si.dev, si.ino) != sid {
            return Err(w.fail("a staging directory changed"));
        }
        if !walk_round(o, w, &src, dst, rel, depth, &mut kept)? {
            return Ok(());
        }
    }
}

/// One round over a freshly opened staging directory: Ok(true) if it handled at least one new entry.
fn walk_round<O: RestoreOps>(o: &mut O, w: &mut Fill, src: &O::H, dst: &O::H, rel: &str, depth: usize, kept: &mut std::collections::BTreeSet<String>) -> Result<bool> {
    let mut progress = false;
    loop {
        let names = o.batch(src).map_err(|_| w.fail("a staging directory can't be listed"))?;
        if names.is_empty() {
            return Ok(progress);
        }
        for name in names {
            if kept.contains(&name) {
                continue;
            }
            progress = true;
            let p = join(rel, &name);
            let (id, kind) = entry(o, w, src, &name)?;
            let Some(kind) = kind else {
                w.odd(p, special_name(id.mode));
                kept.insert(name);
                continue;
            };
            if !(w.uids.contains(&id.uid) && id.gid == w.gid) {
                // Not placed; a refused directory's whole subtree is neither walked nor placed, reported once.
                let mut n = 0usize;
                if kind == Kind::Dir {
                    let h = o.at(src, &name, At::Dir).map_err(|_| w.fail("a staging directory can't be opened"))?;
                    scan(o, w, &h, depth + 1, &mut n)?;
                }
                w.refuse(p, id.uid, id.gid, n as u64);
                kept.insert(name);
                continue;
            }
            match kind {
                Kind::Dir => {
                    o.mkdir(dst, &name, 0o700).map_err(|e| io_fail(o, w, dst, e, "a directory can't be made"))?;
                    w.effects += 1;
                    let dh = o.at(dst, &name, At::Dir).map_err(|_| w.fail("a made directory can't be opened"))?;
                    let di = o.ident(&dh).map_err(|_| w.fail("a made directory can't be identified"))?;
                    if kind_of(&di) != Some(Kind::Dir) || di.uid != 0 || di.mnt_id != w.mnt {
                        return Err(w.fail("a made directory isn't ours"));
                    }
                    o.chmod(&dh, id.mode & 0o7777 & !0o6000).map_err(|e| io_fail(o, w, dst, e, "a directory's mode can't be set"))?;
                    o.chown(&dh, id.uid, id.gid).map_err(|e| io_fail(o, w, dst, e, "a directory's owner can't be set"))?;
                    if o.project(&dh).map_err(|_| w.fail("a project id can't be read"))? != (w.projid, true) {
                        return Err(w.fail("a made directory isn't in the class's project"));
                    }
                    walk(o, w, src, &name, (id.dev, id.ino), &dh, &p, depth + 1)?;
                    // The directory stays in staging (its entries moved out); it is not walked again.
                    kept.insert(name.clone());
                    o.fsync(&dh).map_err(|_| err(Fail::Partial, "a directory can't be synced"))?;
                    w.dirs += 1;
                }
                Kind::File => {
                    // Stripped and synced IN STAGING first (r3 O7), then renamed, then re-verified.
                    let fh = o.at(src, &name, At::File).map_err(|_| w.fail("a staged file can't be opened"))?;
                    let fi = o.ident(&fh).map_err(|_| w.fail("a staged file can't be identified"))?;
                    if (fi.dev, fi.ino) != (id.dev, id.ino) {
                        return Err(w.fail("a staged file changed"));
                    }
                    o.chmod(&fh, id.mode & 0o7777 & !0o6000).map_err(|e| io_fail(o, w, dst, e, "a file's mode can't be set"))?;
                    w.effects += 1;
                    for x in o.xattrs(&fh).map_err(|_| err(Fail::Partial, "a file's attributes can't be listed"))? {
                        o.remove_xattr(&fh, &x).map_err(|_| err(Fail::Partial, "an extended attribute can't be removed"))?;
                    }
                    o.fsync_file(&fh).map_err(|_| err(Fail::Partial, "a file can't be synced"))?;
                    o.rename(src, dst, &name).map_err(|e| io_fail(o, w, dst, e, "a file can't be moved"))?;
                    let nh = o.at(dst, &name, At::File).map_err(|_| err(Fail::Partial, "a moved file can't be opened"))?;
                    let ni = o.ident(&nh).map_err(|_| err(Fail::Partial, "a moved file can't be identified"))?;
                    let clean = o.xattrs(&nh).map_err(|_| err(Fail::Partial, "a moved file's attributes can't be listed"))?.is_empty();
                    let proj = o.project(&nh).map_err(|_| err(Fail::Partial, "a project id can't be read"))?.0;
                    if (ni.dev, ni.ino) != (id.dev, id.ino) || ni.mode & 0o6000 != 0 || !clean || proj != w.projid {
                        return Err(err(Fail::Partial, "a moved file isn't the stripped file"));
                    }
                    w.files += 1;
                }
                Kind::Symlink => {
                    o.rename(src, dst, &name).map_err(|e| io_fail(o, w, dst, e, "a symlink can't be moved"))?;
                    w.effects += 1;
                    let ni = o.ident_at(dst, &name).map_err(|_| err(Fail::Partial, "a moved symlink can't be identified"))?;
                    if kind_of(&ni) != Some(Kind::Symlink) || ni.ino != id.ino {
                        return Err(err(Fail::Partial, "a moved symlink changed"));
                    }
                    w.symlinks += 1;
                }
            }
        }
    }
}

fn fill_report(w: &Fill) -> String {
    let refused: Vec<String> = w
        .refused
        .iter()
        .map(|(p, u, g, n)| format!("{{\"path\":{},\"uid\":{u},\"gid\":{g},\"entries\":{n}}}", json::quote(p)))
        .collect();
    let unexpected: Vec<String> = w.unexpected.iter().map(|(p, t)| format!("{{\"path\":{},\"type\":\"{t}\"}}", json::quote(p))).collect();
    format!(
        "{{\"placed\":{{\"dirs\":{},\"files\":{},\"symlinks\":{}}},\"refused\":[{}],\"unexpected\":[{}],\"truncated\":{}}}\n",
        w.dirs,
        w.files,
        w.symlinks,
        refused.join(","),
        unexpected.join(","),
        w.truncated
    )
}

pub fn fill_home<O: RestoreOps>(o: &mut O, a: &FillArgs) -> Result<String> {
    fill_limited(o, a, tree::MAX_OBJECTS)
}

fn fill_limited<O: RestoreOps>(o: &mut O, a: &FillArgs, limit: usize) -> Result<String> {
    let n = &a.name;
    if !a.source.starts_with("data/") || !rel_ok(a.source) {
        return Err(err(Fail::Usage, "bad arguments"));
    }
    let root = o.root().map_err(|_| pre("the root can't be opened"))?;
    // 1. The epoch, and the anchor policy for both anchors.
    let v = tree::read_expect(o, &root, a.expect)?;
    let f = v.exact(&["epoch", "fsid", "dest", "uids", "gid", "projid"]).ok_or(tree::bad_expect())?;
    let (e_epoch, e_fsid, e_dest) = (tree::epoch_of(f[0])?, tree::fsid_of(f[1])?, obj_of(f[2])?);
    let uids = f[3].arr().filter(|u| !u.is_empty() && u.len() <= MAX_UIDS).ok_or(tree::bad_expect())?.iter().map(tree::u32_of).collect::<Result<Vec<u32>>>()?;
    let (gid, projid) = (tree::u32_of(f[4])?, tree::u32_of(f[5])?);
    if (n.class != Class::Tag && uids.len() != 1) || !n.projid_ok(projid) {
        return Err(tree::bad_expect());
    }
    let _ = tree::parse_mount(a.mount)?;
    let ra = anchor_policy(o, &root, RESTORE)?;
    let da = anchor_policy(o, &root, dest_anchor(n.class))?;
    let (epoch, fsid) = epoch_now(o, &root, &da)?;
    if epoch != e_epoch {
        return Err(identity("a stale epoch: requalify first"));
    }
    if fsid != e_fsid {
        return Err(identity("another filesystem"));
    }
    let mnt = epoch.mnt_id;
    if o.ident(&ra).map_err(open_err)?.mnt_id != mnt {
        return Err(identity("the staging isn't on the destination's mount"));
    }
    // The attempt: each staging directory root:root 0700 on the mount.
    let mut h = None;
    for part in n.parts() {
        let parent = h.as_ref().unwrap_or(&ra);
        let (x, ch) = tchild(o, parent, &part, mnt)?.ok_or(identity("no such attempt"))?;
        match ch {
            Some(ch) if x.uid == 0 && x.gid == 0 && x.mode == 0o700 => h = Some(ch),
            _ => return Err(identity("a staging directory isn't root:root 0700")),
        }
    }
    let att = h.ok_or(identity("no such attempt"))?;

    // 2. Invalidate the marker first (T5): from here on the attempt is consumed whatever happens.
    let mh = match o.at(&att, MARKER, At::Path) {
        Ok(_) => o.at(&att, MARKER, At::File).map_err(|_| identity("the marker can't be opened"))?,
        Err(_) => return Err(identity("no completion marker: a consumed or unfinished attempt")),
    };
    let mi = o.ident(&mh).map_err(open_err)?;
    let body = o.read_small(&mh, MAX_MARKER).map_err(|_| identity("the marker can't be read"))?;
    if kind_of(&mi) != Some(Kind::File) || mi.uid != 0 || mi.gid != 0 || mi.mode & 0o7777 != 0o600 || mi.nlink != 1 || mi.mnt_id != mnt || body != n.path().as_bytes() {
        return Err(identity("the marker isn't this attempt's"));
    }
    drop(mh);
    o.unlink(&att, MARKER, false).map_err(|_| identity("the marker can't be removed"))?;
    o.fsync(&att).map_err(|_| err(Fail::Partial, "the marker's removal can't be made durable"))?;

    // 3. CAP_SYS_RESOURCE gone from all five sets before the first destination write.
    o.drop_sys_resource().map_err(|_| err(Fail::Landlock, "CAP_SYS_RESOURCE can't be dropped"))?;

    // 4. The destination: its recorded identity, and empty.
    let leaf: &str = match n.class {
        Class::Home => "home",
        Class::Sessions => "sessions",
        Class::Archive | Class::Tag => &n.id,
    };
    let dest_parent = match n.class {
        Class::Home | Class::Sessions => tchild(o, &da, &n.id, mnt)?.and_then(|(_, h)| h).ok_or(identity("no agent directory"))?,
        Class::Archive | Class::Tag => da,
    };
    let (dx, probe) = tchild(o, &dest_parent, leaf, mnt)?.ok_or(identity("no destination"))?;
    if dx != e_dest {
        return Err(identity("the destination differs from its recorded identity"));
    }
    let probe = probe.ok_or(identity("the destination isn't a directory"))?;
    if !o.batch(&probe).map_err(open_err)?.is_empty() {
        return Err(identity("the destination isn't empty"));
    }
    drop(probe);
    let dst = o.at(&dest_parent, leaf, At::Dir).map_err(open_err)?;
    let di = o.ident(&dst).map_err(open_err)?;
    if (di.dev, di.ino) != (dx.dev, dx.ino) {
        return Err(identity("the destination changed"));
    }
    if dx.projid != Some(projid) || dx.inherit != Some(true) {
        return Err(identity("the destination isn't in the class's project"));
    }

    // The source: data/... beneath the attempt, every component a directory on the mount.
    let mut w = Fill { uids, gid, projid, mnt, limit, effects: 0, dirs: 0, files: 0, symlinks: 0, refused: vec![], unexpected: vec![], truncated: false };
    let mut src = None;
    for part in a.source.split('/') {
        let parent = src.as_ref().unwrap_or(&att);
        let (_, ch) = tchild(o, parent, part, mnt)?.ok_or(identity("no such source"))?;
        src = Some(ch.ok_or(identity("the source isn't a directory"))?);
    }
    let src = src.ok_or(identity("no such source"))?;
    // 5. The dry pass, then the walk on fresh handles.
    let mut count = 0usize;
    scan(o, &w, &src, 1, &mut count)?;
    let si = o.ident(&src).map_err(open_err)?;
    drop(src);
    let (parent_rel, leaf) = a.source.rsplit_once('/').ok_or(identity("no such source"))?;
    let mut sp = None;
    for part in parent_rel.split('/') {
        let parent = sp.as_ref().unwrap_or(&att);
        sp = Some(tchild(o, parent, part, mnt)?.and_then(|(_, h)| h).ok_or(identity("no such source"))?);
    }
    let sp = sp.ok_or(identity("no such source"))?;
    walk(o, &mut w, &sp, leaf, (si.dev, si.ino), &dst, "", 1)?;
    // The durability barrier: every written directory was synced bottom-up in the walk; then the destination and its
    // parent. Exit 0 only after the whole barrier.
    o.fsync(&dst).map_err(|_| err(Fail::Partial, "the destination can't be synced"))?;
    o.fsync(&dest_parent).map_err(|_| err(Fail::Partial, "the destination's parent can't be synced"))?;
    Ok(fill_report(&w))
}

// ---- the real operations

use std::os::fd::OwnedFd;

impl Runner<OwnedFd> for crate::child::RealRunner {
    fn run(&mut self, plan: &mut Plan<'_, OwnedFd>, request: &[u8]) -> Ran {
        let Some(seen) = crate::child::RealRunner::run(self, plan, request) else { return Ran::NotStarted };
        if seen.lost {
            return Ran::Lost;
        }
        match crate::child::read_record(&seen.status) {
            None => Ran::Lost,
            Some(Some((stage, errno))) => Ran::PreExec(stage, errno),
            Some(None) => Ran::Exited { stdout: seen.stdout, overflow: seen.overflow },
        }
    }
}

fn cs(s: &str) -> io::Result<CString> {
    CString::new(s).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))
}

impl RestoreOps for tree::RealOps {
    fn mkdir(&mut self, dir: &OwnedFd, name: &str, mode: u16) -> io::Result<()> {
        sys::mkdirat(dir, &cs(name)?, mode as libc::mode_t)
    }
    fn set_project(&mut self, h: &OwnedFd, projid: u32) -> io::Result<()> {
        sys::set_project(h, projid, true)
    }
    fn chown(&mut self, h: &OwnedFd, uid: u32, gid: u32) -> io::Result<()> {
        sys::fchown(h, uid, gid)
    }
    fn xattrs(&mut self, h: &OwnedFd) -> io::Result<Vec<CString>> {
        let mut buf = vec![0u8; 64 * 1024];
        let n = sys::list_xattrs(h, &mut buf)?;
        Ok(buf[..n].split(|b| *b == 0).filter(|s| !s.is_empty()).filter_map(|s| CString::new(s).ok()).collect())
    }
    fn remove_xattr(&mut self, h: &OwnedFd, name: &CString) -> io::Result<()> {
        sys::remove_xattr(h, name)
    }
    fn fsync_file(&mut self, h: &OwnedFd) -> io::Result<()> {
        sys::fsync_fd(h)
    }
    fn create_marker(&mut self, dir: &OwnedFd, name: &str, body: &[u8]) -> io::Result<()> {
        let fd = sys::create_excl(dir, &cs(name)?, 0o600)?;
        let mut off = 0;
        while off < body.len() {
            let n = sys::write(&fd, &body[off..])?;
            if n == 0 {
                return Err(io::Error::from_raw_os_error(libc::EIO));
            }
            off += n;
        }
        sys::fsync_fd(&fd)
    }
    fn read_small(&mut self, h: &OwnedFd, max: usize) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        let mut buf = vec![0u8; max + 1];
        loop {
            let n = sys::pread(h, &mut buf[..max + 1 - out.len().min(max + 1)], out.len() as u64)?;
            if n == 0 {
                return Ok(out);
            }
            out.extend_from_slice(&buf[..n]);
            if out.len() > max {
                return Err(io::Error::from_raw_os_error(libc::EFBIG));
            }
        }
    }
    fn syncfs(&mut self, h: &OwnedFd) -> io::Result<()> {
        sys::syncfs(h)
    }
    fn quota(&mut self, h: &OwnedFd, projid: u32) -> io::Result<Quota> {
        sys::project_quota(h, projid)
    }
    fn space(&mut self, h: &OwnedFd) -> io::Result<(u64, u64)> {
        sys::space_left(h)
    }
    fn now(&mut self) -> u64 {
        sys::now_secs()
    }
    fn exe_target(&mut self, root: &OwnedFd) -> io::Result<String> {
        let mut buf = vec![0u8; crate::args::MAX_PATH + 16];
        let n = sys::readlinkat(root, c"proc/self/exe", &mut buf)?;
        if n >= buf.len() {
            return Err(io::Error::from_raw_os_error(libc::ENAMETOOLONG));
        }
        String::from_utf8(buf[..n].to_vec()).map_err(|_| io::Error::from_raw_os_error(libc::EILSEQ))
    }
    fn pread(&mut self, h: &OwnedFd, len: usize, off: u64) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; len];
        let mut got = 0;
        while got < len {
            let n = sys::pread(h, &mut buf[got..], off + got as u64)?;
            if n == 0 {
                break;
            }
            got += n;
        }
        buf.truncate(got);
        Ok(buf)
    }
    fn open_system(&mut self, root: &OwnedFd, rel: &str) -> io::Result<OwnedFd> {
        sys::open_system(root, &cs(rel)?, libc::O_PATH)
    }
    fn drop_sys_resource(&mut self) -> io::Result<()> {
        let bit = 1u64 << SYS_RESOURCE;
        sys::capbset_drop(SYS_RESOURCE)?;
        sys::ambient_clear()?;
        let (e, p, i) = sys::capget()?;
        sys::capset(e & !bit, p & !bit, i & !bit)?;
        // Verified in all five sets.
        let (e, p, i) = sys::capget()?;
        if (e | p | i) & bit != 0 || sys::capbset_read(SYS_RESOURCE)? || sys::ambient_is_set(SYS_RESOURCE)? {
            return Err(io::Error::from_raw_os_error(libc::EPERM));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::tests::{code, e, expect_file, join, Fake, FH, A, BOOT, MNT, UID};
    use crate::tree::{obj_json, S_IFDIR, S_IFLNK, S_IFREG};

    const RUN: &str = "abcdefghijklmnop";
    const TAG: &str = "zyxwvutsrqponmlkjihgfedcba";
    const SNAP: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const BIN: &str = "opt/sagebrush/1/bin/sagebrush-agent-backup";

    impl RestoreOps for Fake {
        fn mkdir(&mut self, dir: &FH, name: &str, mode: u16) -> io::Result<()> {
            self.tick("mkdir")?;
            let p = join(&dir.p, name);
            if self.nodes.contains_key(&p) {
                return Err(e(libc::EEXIST));
            }
            let par = self.nodes[&dir.p].clone();
            self.add(&p, S_IFDIR | mode, 0, 0);
            let n = self.node(&p);
            n.id.mnt_id = par.id.mnt_id;
            if par.inherit {
                n.proj = par.proj;
                n.inherit = true;
            }
            self.log.push(format!("mkdir {p}"));
            Ok(())
        }
        fn set_project(&mut self, h: &FH, projid: u32) -> io::Result<()> {
            self.tick("set_project")?;
            let skew = self.proj_skew;
            let n = self.node(&h.p);
            n.proj = projid + skew;
            n.inherit = true;
            Ok(())
        }
        fn chown(&mut self, h: &FH, uid: u32, gid: u32) -> io::Result<()> {
            self.tick("chown")?;
            let n = self.node(&h.p);
            n.id.uid = uid;
            n.id.gid = gid;
            self.log.push(format!("chown {} {uid}:{gid}", h.p));
            Ok(())
        }
        fn xattrs(&mut self, h: &FH) -> io::Result<Vec<CString>> {
            self.tick("xattrs")?;
            Ok(self.xattrs.get(&h.p).cloned().unwrap_or_default().into_iter().map(|s| CString::new(s).unwrap()).collect())
        }
        fn remove_xattr(&mut self, h: &FH, name: &CString) -> io::Result<()> {
            self.tick("remove_xattr")?;
            let n = name.to_str().unwrap().to_string();
            if let Some(v) = self.xattrs.get_mut(&h.p) {
                v.retain(|x| *x != n);
            }
            self.log.push(format!("remove_xattr {} {n}", h.p));
            Ok(())
        }
        fn fsync_file(&mut self, h: &FH) -> io::Result<()> {
            self.tick("fsync_file")?;
            self.log.push(format!("fsync_file {}", h.p));
            Ok(())
        }
        fn create_marker(&mut self, dir: &FH, name: &str, body: &[u8]) -> io::Result<()> {
            self.tick("marker")?;
            let p = join(&dir.p, name);
            if self.nodes.contains_key(&p) {
                return Err(e(libc::EEXIST));
            }
            self.file(&p, 0, 0o600);
            self.files.insert(p.clone(), body.to_vec());
            self.log.push(format!("marker {p}"));
            Ok(())
        }
        fn read_small(&mut self, h: &FH, max: usize) -> io::Result<Vec<u8>> {
            let b = self.files.get(&h.p).cloned().unwrap_or_default();
            if b.len() > max { Err(e(libc::EFBIG)) } else { Ok(b) }
        }
        fn syncfs(&mut self, h: &FH) -> io::Result<()> {
            self.tick("syncfs")?;
            self.log.push(format!("syncfs {}", h.p));
            Ok(())
        }
        fn quota(&mut self, _h: &FH, _projid: u32) -> io::Result<Quota> {
            self.tick("quota")?;
            self.quota.ok_or(e(libc::EIO))
        }
        fn space(&mut self, _h: &FH) -> io::Result<(u64, u64)> {
            Ok(self.space)
        }
        fn now(&mut self) -> u64 {
            1000
        }
        fn exe_target(&mut self, _root: &FH) -> io::Result<String> {
            Ok(self.exe.clone())
        }
        fn pread(&mut self, h: &FH, len: usize, off: u64) -> io::Result<Vec<u8>> {
            let b = self.files.get(&h.p).cloned().unwrap_or_default();
            let s = (off as usize).min(b.len());
            Ok(b[s..(s + len).min(b.len())].to_vec())
        }
        fn open_system(&mut self, _root: &FH, rel: &str) -> io::Result<FH> {
            if self.nodes.contains_key(rel) { Ok(self.handle(rel.to_string())) } else { Err(e(libc::ENOENT)) }
        }
        fn drop_sys_resource(&mut self) -> io::Result<()> {
            self.tick("drop_caps")?;
            self.log.push("drop_caps".into());
            if self.caps_fail { Err(e(libc::EPERM)) } else { Ok(()) }
        }
    }

    /// A 64-bit little-endian ELF header with two program headers: PT_LOAD and PT_DYNAMIC (static-pie), or PT_LOAD and
    /// PT_INTERP (dynamic).
    fn elf(interp: bool) -> Vec<u8> {
        let mut b = vec![0u8; 64 + 2 * 56];
        b[..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        b[4] = 2;
        b[5] = 1;
        b[32..40].copy_from_slice(&64u64.to_le_bytes());
        b[54..56].copy_from_slice(&56u16.to_le_bytes());
        b[56..58].copy_from_slice(&2u16.to_le_bytes());
        b[64..68].copy_from_slice(&1u32.to_le_bytes());
        b[120..124].copy_from_slice(&(if interp { 3u32 } else { 2u32 }).to_le_bytes());
        b
    }

    /// The host: A1's fake plus the restore anchor, the backup anchors, part of the system set and the release.
    fn host() -> Fake {
        let mut f = Fake::new();
        for d in ["srv/sagebrush/tags", "var/lib/sagebrush/backup", "var/lib/sagebrush/backup/state", "var/lib/sagebrush/host-secrets", "var/cache", "var/cache/sagebrush-backup", "etc", "etc/ssl", "etc/ssl/certs", "opt", "opt/sagebrush", "opt/sagebrush/1", "opt/sagebrush/1/bin"] {
            f.dir(d, 0, 0o755);
        }
        f.dir("srv/sagebrush/.restore", 0, 0o700);
        f.file("etc/resolv.conf", 0, 0o644);
        f.file(BIN, 0, 0o755);
        f.files.insert(BIN.into(), elf(false));
        f.exe = "/opt/sagebrush/1/bin/sagebrush-agent-launch".into();
        f
    }

    fn owner() -> String {
        format!("a-{A}")
    }
    fn name(class: &str) -> Name {
        Name::parse(RUN, &owner(), class, "1").unwrap()
    }
    fn attempt_path(class: &str) -> String {
        format!("srv/sagebrush/.restore/{RUN}/{}/{class}/1", owner())
    }

    type SeenBinds = Vec<(&'static str, bool, bool, bool, bool)>;

    /// What the runner was given, and what it answers.
    struct Run {
        ran: Ran,
        seen: Option<(SeenBinds, ((u32, u32), u64), Vec<u8>, String)>,
    }
    impl Runner<FH> for Run {
        fn run(&mut self, plan: &mut Plan<'_, FH>, request: &[u8]) -> Ran {
            let binds = plan.binds.iter().map(|b| (b.at, b.file, b.write, b.exec, b.recheck)).collect();
            self.seen = Some((binds, plan.binary, request.to_vec(), plan.attempt.p.clone()));
            self.ran.clone()
        }
    }
    fn ok_reply() -> Vec<u8> {
        format!("{{\"snapshot\":\"{SNAP}\",\"skipped_special\":0,\"ok\":true}}\n").into_bytes()
    }
    fn failed(code: &str) -> Vec<u8> {
        format!("{{\"ok\":false,\"error\":{{\"code\":\"{code}\",\"message\":\"x\"}}}}\n").into_bytes()
    }
    fn exited(out: Vec<u8>) -> Run {
        Run { ran: Ran::Exited { stdout: out, overflow: false }, seen: None }
    }
    fn stage_args(class: &str) -> StageArgs<'static> {
        StageArgs { mount: "/srv/sagebrush", name: name(class), projid: UID, snapshot: SNAP, path: "srv/sagebrush/agents/x/home" }
    }
    fn rcode(d: &Done) -> i32 {
        match d.result {
            Ok(()) => 0,
            Err(e) => e.fail.code(),
        }
    }

    // ---- arguments (64)

    #[test]
    fn the_request_is_bounded_as_encoded_exact_and_one_past_and_escape_heavy() {
        let base = request(SNAP, "x").unwrap().len() - 1;
        let exact = "a".repeat(MAX_REQUEST - base);
        assert_eq!(request(SNAP, &exact).unwrap().len(), MAX_REQUEST, "exactly 4096 encoded bytes are accepted");
        assert_eq!(code(request(SNAP, &format!("{exact}a"))), 64, "4097 is usage");
        // 1003 raw bytes of control characters (four 250-byte components): far over 4096 once encoded.
        let ctl = "\u{1}".repeat(250);
        let heavy = [ctl.as_str(); 4].join("/");
        assert_eq!(heavy.len(), 1003);
        assert_eq!(code(request(SNAP, &heavy)), 64);
        // A plain 1025-byte path that fits is accepted (the bound is the encoding, not the raw length).
        assert!(request(SNAP, &"b".repeat(1025)).is_ok());
        let r = String::from_utf8(request(SNAP, "srv/x").unwrap()).unwrap();
        assert_eq!(r, format!("{{\"op\":\"restore\",\"snapshot\":\"{SNAP}\",\"path\":\"srv/x\",\"dest\":\"/data\"}}"));
        for bad in ["", "/srv", "srv/", "srv//x", "srv/./x", "srv/../x", "a\0b"] {
            assert_eq!(code(request(SNAP, bad)), 64, "{bad:?}");
        }
        assert_eq!(code(request(&SNAP.to_uppercase(), "x")), 64);
        assert_eq!(code(request(&SNAP[1..], "x")), 64);
    }

    #[test]
    fn names_classes_attempts_and_project_ranges_are_closed() {
        let a = owner();
        let t = format!("t-{TAG}");
        assert!(Name::parse(RUN, &a, "home", "1").is_some());
        assert!(Name::parse(RUN, &a, "sessions", "999999").is_some());
        assert!(Name::parse(RUN, &t, "tag", "12").is_some());
        for (run, own, class, att) in [
            ("abcdefghijklmno", a.as_str(), "home", "1"),
            ("abcdefghijklmnoP", a.as_str(), "home", "1"),
            ("abcdefghijklmno1", a.as_str(), "home", "1"),
            (RUN, A, "home", "1"),
            (RUN, a.as_str(), "tag", "1"),
            (RUN, t.as_str(), "home", "1"),
            (RUN, a.as_str(), "config", "1"),
            (RUN, a.as_str(), "home", "0"),
            (RUN, a.as_str(), "home", "01"),
            (RUN, a.as_str(), "home", "1000000"),
            (RUN, a.as_str(), "home", "-1"),
        ] {
            assert!(Name::parse(run, own, class, att).is_none(), "{run} {own} {class} {att}");
        }
        let n = name("home");
        assert!(n.projid_ok(70000) && n.projid_ok(79999) && !n.projid_ok(80000) && !n.projid_ok(69999));
        let tn = Name::parse(RUN, &t, "tag", "1").unwrap();
        assert!(tn.projid_ok(80000) && !tn.projid_ok(79999));
        assert_eq!(name_of(&n.path()), Some(n.clone()));
        assert!(name_of(&format!("{RUN}/{a}/home")).is_none());
        let mut f = host();
        let d = restore_stage(&mut f, &mut exited(ok_reply()), &StageArgs { projid: 80001, ..stage_args("home") });
        assert_eq!(rcode(&d), 64);
        assert_eq!(f.count("mkdir"), 0);
    }

    // ---- §3.1 (r3.1): the units

    fn q(curspace: u64, bhard: u64, curinodes: u64, ihard: u64) -> Quota {
        Quota { bhard, bsoft: 0, curspace, ihard, isoft: 0, curinodes, btime: 0, itime: 0, valid: 0x3f }
    }
    const GIB_BLOCKS: u64 = 1_048_576;
    const GIB: u64 = 1 << 30;
    fn room() -> io::Result<(u64, u64)> {
        Ok((100, 100))
    }

    #[test]
    fn blocks_are_compared_in_bytes_below_at_and_above_the_hard_limit() {
        assert_eq!(classify(Ok(q(2 << 20, GIB_BLOCKS, 0, 0)), room(), 1000), Limit::QuotaUnknown, "2 MiB of 1 GiB is not reached");
        assert_eq!(classify(Ok(q(GIB - 1, GIB_BLOCKS, 0, 0)), room(), 1000), Limit::QuotaUnknown, "1 GiB - 1 byte is not reached");
        assert_eq!(classify(Ok(q(GIB, GIB_BLOCKS, 0, 0)), room(), 1000), Limit::Quota, "exactly 1 GiB is reached");
        assert_eq!(classify(Ok(q(GIB + 1, GIB_BLOCKS, 0, 0)), room(), 1000), Limit::Quota);
        // Inodes are counts.
        assert_eq!(classify(Ok(q(0, 0, 99, 100)), room(), 1000), Limit::QuotaUnknown);
        assert_eq!(classify(Ok(q(0, 0, 100, 100)), room(), 1000), Limit::Quota);
        assert_eq!(classify(Ok(q(0, 0, 101, 100)), room(), 1000), Limit::Quota);
        // ENOSPC with free root blocks but the project at its inode limit: 76, never 77.
        assert_eq!(classify(Ok(q(0, 0, 100, 100)), Ok((0, 5)), 1000), Limit::Quota);
    }

    #[test]
    fn soft_limits_count_only_past_grace_zero_is_no_limit_and_an_overflow_is_never_reached() {
        let soft = |cur, t| Quota { bsoft: 1, curspace: cur, btime: t, valid: 0x3f, ..Quota::default() };
        assert_eq!(classify(Ok(soft(2048, 2000)), room(), 1000), Limit::QuotaUnknown, "over the soft limit inside the grace");
        assert_eq!(classify(Ok(soft(2048, 999)), room(), 1000), Limit::Quota, "past the grace");
        assert_eq!(classify(Ok(soft(2048, 1000)), room(), 1000), Limit::Quota, "the grace ends at now");
        assert_eq!(classify(Ok(soft(2048, 0)), room(), 1000), Limit::QuotaUnknown, "btime 0: no grace running");
        assert_eq!(classify(Ok(soft(1024, 999)), room(), 1000), Limit::QuotaUnknown, "at the soft limit is not over it");
        let isoft = Quota { isoft: 10, curinodes: 11, itime: 999, valid: 0x3f, ..Quota::default() };
        assert_eq!(classify(Ok(isoft), room(), 1000), Limit::Quota);
        assert_eq!(classify(Ok(q(u64::MAX, 0, 0, 0)), room(), 1000), Limit::QuotaUnknown, "a limit of 0 is none");
        assert_eq!(classify(Ok(q(u64::MAX, u64::MAX, 0, 0)), room(), 1000), Limit::QuotaUnknown, "checked_mul overflows: not reached, no panic");
        assert_eq!(classify(Ok(q(u64::MAX, u64::MAX / 1024 + 1, 0, 0)), room(), 1000), Limit::QuotaUnknown);
    }

    #[test]
    fn each_valid_bit_gates_its_side_the_query_failing_is_unknown_and_the_global_full_control_is_77() {
        for bit in [sys::QIF_SPACE, sys::QIF_BLIMITS, sys::QIF_BTIME, sys::QIF_INODES, sys::QIF_ILIMITS, sys::QIF_ITIME] {
            let x = Quota { valid: 0x3f & !bit, ..q(2 << 20, GIB_BLOCKS, 5, 100) };
            assert_eq!(classify(Ok(x), Ok((0, 0)), 1000), Limit::QuotaUnknown, "bit {bit}: that side is unknown");
        }
        // A reached side still decides even when the other is unknown.
        let x = Quota { valid: 0x3f & !sys::QIF_INODES, ..q(GIB, GIB_BLOCKS, 0, 0) };
        assert_eq!(classify(Ok(x), room(), 1000), Limit::Quota);
        assert_eq!(classify(Err(e(libc::ENOSYS)), Ok((0, 0)), 1000), Limit::QuotaUnknown, "the query failing");
        // The global-full control: the project far under its limits while the filesystem is out of inodes, or blocks.
        assert_eq!(classify(Ok(q(2 << 20, GIB_BLOCKS, 5, 100)), Ok((100, 0)), 1000), Limit::NoSpace);
        assert_eq!(classify(Ok(q(2 << 20, GIB_BLOCKS, 5, 100)), Ok((0, 100)), 1000), Limit::NoSpace);
        assert_eq!(classify(Ok(q(2 << 20, GIB_BLOCKS, 5, 100)), Err(e(libc::EIO)), 1000), Limit::QuotaUnknown);
        assert_eq!((limit_error(Limit::Quota).fail.code(), limit_error(Limit::QuotaUnknown).msg), (76, "quota_unknown"));
        assert_eq!(limit_error(Limit::NoSpace).fail.code(), 77);
    }

    // ---- the binary's result (S-b)

    #[test]
    fn exactly_one_closed_json_object_on_one_line() {
        assert_eq!(reply(&ok_reply()), Some(Reply::Ok(SNAP.into(), 0)));
        assert_eq!(reply(&failed("quota_exceeded")), Some(Reply::Failed("quota_exceeded".into())));
        let long = format!("{{\"ok\":false,\"error\":{{\"code\":\"no_space\",\"message\":\"{}\"}}}}\n", "m".repeat(10_000));
        assert_eq!(reply(long.as_bytes()), Some(Reply::Failed("no_space".into())), "a long message still classifies");
        let two = [ok_reply(), ok_reply()].concat();
        let nonl = ok_reply()[..ok_reply().len() - 1].to_vec();
        for bad in [
            &two[..],
            &nonl[..],
            b" {\"ok\":true}\n",
            b"[1]\n",
            b"\n",
            b"",
            b"{\"ok\":true}\n",
            b"{\"ok\":false,\"error\":{\"code\":\"x\"}}\n",
            b"{\"ok\":true,\"error\":{\"code\":\"x\",\"message\":\"y\"}}\n",
        ] {
            assert_eq!(reply(bad), None, "{:?}", String::from_utf8_lossy(bad));
        }
        let extra = format!("{{\"snapshot\":\"{SNAP}\",\"skipped_special\":0,\"ok\":true,\"x\":1}}\n");
        assert_eq!(reply(extra.as_bytes()), None);
        for skipped in ["-1", "1.5", "1e3", "\"3\"", "null"] {
            let r = format!("{{\"snapshot\":\"{SNAP}\",\"skipped_special\":{skipped},\"ok\":true}}\n");
            assert_eq!(reply(r.as_bytes()), None, "{skipped}");
        }
    }

    // ---- the release binary (S-a, O8)

    fn reader(b: Vec<u8>) -> impl FnMut(usize, u64) -> io::Result<Vec<u8>> {
        move |len: usize, off: u64| {
            let s = (off as usize).min(b.len());
            Ok(b[s..(s + len).min(b.len())].to_vec())
        }
    }

    #[test]
    fn only_a_static_elf64_is_admitted_and_anything_malformed_refuses() {
        assert_eq!(elf_static(reader(elf(false))), Ok(true), "static-pie: PT_DYNAMIC, no PT_INTERP");
        assert_eq!(elf_static(reader(elf(true))), Ok(false), "PT_INTERP: a dynamic loader");
        let mut trunc = elf(false);
        trunc.truncate(100);
        assert_eq!(code(elf_static(reader(trunc))), 66);
        assert_eq!(code(elf_static(reader(elf(false)[..40].to_vec()))), 66);
        for (at, v) in [(0usize, 0u8), (4, 1), (5, 2), (56, 0), (56, 65), (54, 32)] {
            let mut b = elf(false);
            b[at] = v;
            assert_eq!(code(elf_static(reader(b))), 66, "byte {at} = {v}");
        }
    }

    #[test]
    fn the_release_binary_refusals_are_66_before_any_effect() {
        let cases: Vec<(&str, Box<dyn Fn(&mut Fake)>)> = vec![
            ("deleted", Box::new(|f: &mut Fake| f.exe = "/opt/sagebrush/1/bin/sagebrush-agent-launch (deleted)".into())),
            ("group-writable", Box::new(|f: &mut Fake| f.node(BIN).id.mode = S_IFREG | 0o775)),
            ("not root", Box::new(|f: &mut Fake| f.node(BIN).id.uid = 1)),
            ("two links", Box::new(|f: &mut Fake| f.node(BIN).id.nlink = 2)),
            ("dynamic", Box::new(|f: &mut Fake| {
                f.files.insert(BIN.into(), elf(true));
            })),
            ("release dir writable", Box::new(|f: &mut Fake| f.node("opt/sagebrush/1/bin").id.mode = S_IFDIR | 0o775)),
            ("missing", Box::new(|f: &mut Fake| {
                f.nodes.remove(BIN);
            })),
        ];
        for (what, mutate) in cases {
            let mut f = host();
            mutate(&mut f);
            let mut r = exited(ok_reply());
            let d = restore_stage(&mut f, &mut r, &stage_args("home"));
            assert_eq!(rcode(&d), 66, "{what}");
            assert!(r.seen.is_none() && f.count("mkdir") == 0, "{what}: zero effects");
        }
    }

    // ---- restore-stage

    #[test]
    fn restore_stage_makes_the_attempt_runs_the_child_and_writes_the_marker_only_after_syncfs() {
        let mut f = host();
        let mut r = exited(ok_reply());
        let d = restore_stage(&mut f, &mut r, &stage_args("home"));
        assert_eq!(rcode(&d), 0, "{:?}", d.result);
        assert_eq!(d.out, ok_reply(), "the binary's line is printed");
        let att = attempt_path("home");
        for p in [format!("srv/sagebrush/.restore/{RUN}"), format!("srv/sagebrush/.restore/{RUN}/{}", owner()), format!("srv/sagebrush/.restore/{RUN}/{}/home", owner()), att.clone()] {
            let n = &f.nodes[&p];
            assert_eq!((n.id.uid, n.id.gid, n.id.mode & 0o7777), (0, 0, 0o700), "{p}");
        }
        let (a, dd) = (f.nodes[&att].clone(), f.nodes[&format!("{att}/data")].clone());
        assert_eq!((a.proj, a.inherit, dd.proj, dd.inherit), (UID, true, UID, true), "charged to the class's project");
        assert_eq!(f.files[&format!("{att}/.complete")], name("home").path().into_bytes());
        let pos = |s: &str| f.log.iter().position(|l| l == s).unwrap_or_else(|| panic!("{s}: {:?}", f.log));
        assert!(pos(&format!("syncfs {att}")) < pos(&format!("marker {att}/.complete")), "durable data before the marker");
        assert_eq!(f.log.last().unwrap(), &format!("fsync {att}"), "the marker's directory synced last");
        let (binds, binary, req, attempt) = r.seen.unwrap();
        assert_eq!(attempt, att, "the tmpfs is attached onto the attempt");
        assert_eq!(
            binds,
            vec![
                ("data", false, true, false, true),
                ("cache", false, true, false, true),
                ("state", false, false, false, true),
                ("secrets", false, false, false, true),
                ("release", false, false, true, true),
                ("etc/ssl/certs", false, false, false, false),
                ("etc/resolv.conf", true, false, false, false),
            ],
            "absent system entries (ca-certificates, hosts) are skipped"
        );
        assert_eq!(binary.1, f.nodes[BIN].id.ino);
        assert_eq!(req, request(SNAP, "srv/sagebrush/agents/x/home").unwrap());
    }

    #[test]
    fn an_existing_attempt_is_74_and_a_foreign_staging_parent_is_73_with_nothing_run() {
        let mut f = host();
        restore_stage(&mut f, &mut exited(ok_reply()), &stage_args("home"));
        let mut r = exited(ok_reply());
        let d = restore_stage(&mut f, &mut r, &stage_args("home"));
        assert_eq!(rcode(&d), 74);
        assert!(r.seen.is_none());
        for (what, uid, mode) in [("mode", 0u32, 0o755u16), ("owner", 5, 0o700)] {
            let mut f = host();
            f.dir(&format!("srv/sagebrush/.restore/{RUN}"), uid, mode);
            let mut r = exited(ok_reply());
            assert_eq!(rcode(&restore_stage(&mut f, &mut r, &stage_args("home"))), 73, "{what}");
            assert!(r.seen.is_none());
        }
    }

    #[test]
    fn a_project_id_that_does_not_read_back_is_73_and_nothing_runs() {
        let mut f = host();
        f.proj_skew = 1;
        let mut r = exited(ok_reply());
        assert_eq!(rcode(&restore_stage(&mut f, &mut r, &stage_args("home"))), 73);
        assert!(r.seen.is_none());
    }

    #[test]
    fn pre_exec_failures_map_to_their_codes_and_leave_no_marker() {
        for (stage, c) in [(Stage::Caps, 68), (Stage::CapsVerify, 68), (Stage::Mountns, 68), (Stage::Landlock, 68), (Stage::Nnp, 68), (Stage::LandlockAbi, 67), (Stage::Exec, 71), (Stage::Pdeathsig, 72), (Stage::Request, 72)] {
            let mut f = host();
            let d = restore_stage(&mut f, &mut Run { ran: Ran::PreExec(stage, libc::EPERM), seen: None }, &stage_args("home"));
            assert_eq!(rcode(&d), c, "{stage:?}");
            assert!(d.out.is_empty() && f.count("marker") == 0, "{stage:?}");
        }
        let mut f = host();
        assert_eq!(rcode(&restore_stage(&mut f, &mut Run { ran: Ran::NotStarted, seen: None }, &stage_args("home"))), 72);
        assert_eq!(rcode(&restore_stage(&mut host(), &mut Run { ran: Ran::Lost, seen: None }, &stage_args("home"))), 75);
    }

    #[test]
    fn a_bad_result_is_75_with_no_marker_and_a_binary_exiting_68_is_read_through_its_json() {
        let two = [ok_reply(), ok_reply()].concat();
        for (what, ran) in [
            ("overflow", Ran::Exited { stdout: ok_reply(), overflow: true }),
            ("two lines", Ran::Exited { stdout: two, overflow: false }),
            ("garbage first", Ran::Exited { stdout: b"x{}\n".to_vec(), overflow: false }),
            ("non-object", Ran::Exited { stdout: b"1\n".to_vec(), overflow: false }),
            ("no newline", Ran::Exited { stdout: ok_reply()[..ok_reply().len() - 1].to_vec(), overflow: false }),
        ] {
            let mut f = host();
            let d = restore_stage(&mut f, &mut Run { ran, seen: None }, &stage_args("home"));
            assert_eq!((rcode(&d), d.result.unwrap_err().msg), (75, "bad_result"), "{what}");
            assert_eq!(f.count("marker"), 0, "{what}");
        }
        // The binary's own failure (whatever its exit number) is 75 with its JSON relayed, never a launcher code.
        let mut f = host();
        let d = restore_stage(&mut f, &mut exited(failed("capability_refused")), &stage_args("home"));
        assert_eq!(rcode(&d), 75);
        assert_eq!(d.out, failed("capability_refused"));
        assert_eq!(f.count("marker"), 0);
    }

    #[test]
    fn only_the_requested_snapshot_completes_the_attempt() {
        // SEC H2: the binary reports which snapshot it restored; a different full id is never marked complete.
        let other = format!("{{\"snapshot\":\"{}\",\"skipped_special\":0,\"ok\":true}}\n", "f".repeat(64));
        let mut f = host();
        let d = restore_stage(&mut f, &mut exited(other.into_bytes()), &stage_args("home"));
        assert_eq!(rcode(&d), 75);
        assert!(f.count("syncfs") == 0 && f.count("marker") == 0, "neither synced as complete nor marked");
        let mut f = host();
        let d = restore_stage(&mut f, &mut exited(ok_reply()), &stage_args("home"));
        assert_eq!(rcode(&d), 0, "the exact requested id completes");
        assert_eq!(f.count("marker"), 1);
    }

    #[test]
    fn staging_quota_and_no_space_are_attributed_by_the_kernel_numbers() {
        let mut f = host();
        f.quota = Some(q(GIB, GIB_BLOCKS, 0, 0));
        let d = restore_stage(&mut f, &mut exited(failed("quota_exceeded")), &stage_args("home"));
        assert_eq!((rcode(&d), d.result.unwrap_err().msg), (76, "quota"));
        let mut f = host();
        let d = restore_stage(&mut f, &mut exited(failed("quota_exceeded")), &stage_args("home"));
        assert_eq!((rcode(&d), d.result.unwrap_err().msg), (76, "quota_unknown"), "the query failing");
        let mut f = host();
        f.quota = Some(q(2 << 20, GIB_BLOCKS, 5, 100));
        f.space = (0, 7);
        let d = restore_stage(&mut f, &mut exited(failed("no_space")), &stage_args("home"));
        assert_eq!(rcode(&d), 77);
        assert_eq!(f.count("marker"), 0);
    }

    #[test]
    fn a_syncfs_or_marker_failure_is_75_and_leaves_no_marker() {
        let mut f = host();
        f.errno_at = Some(("syncfs", 1, libc::EIO));
        assert_eq!(rcode(&restore_stage(&mut f, &mut exited(ok_reply()), &stage_args("home"))), 75);
        assert!(!f.nodes.contains_key(&format!("{}/.complete", attempt_path("home"))));
        let mut f = host();
        f.fail = Some("marker");
        assert_eq!(rcode(&restore_stage(&mut f, &mut exited(ok_reply()), &stage_args("home"))), 75);
        assert!(!f.nodes.contains_key(&format!("{}/.complete", attempt_path("home"))));
    }

    #[test]
    fn a_system_file_may_belong_to_a_system_account_never_to_a_person_or_agent_nor_be_writable_by_others() {
        // systemd-resolved's stub resolv.conf (uid 991 on Ubuntu 24.04) is accepted; the bind is read-only either way.
        let mut f = host();
        f.node("etc/resolv.conf").id.uid = 991;
        assert_eq!(rcode(&restore_stage(&mut f, &mut exited(ok_reply()), &stage_args("home"))), 0);
        for (what, uid, mode) in [("a person's", 1000u32, 0o644u16), ("an agent's", UID, 0o644), ("group-writable", 0, 0o664), ("other-writable", 991, 0o646)] {
            let mut f = host();
            f.node("etc/resolv.conf").id.uid = uid;
            f.node("etc/resolv.conf").id.mode = S_IFREG | mode;
            let mut r = exited(ok_reply());
            assert_eq!(rcode(&restore_stage(&mut f, &mut r, &stage_args("home"))), 66, "{what}");
            assert!(r.seen.is_none() && f.count("mkdir") == 0, "{what}: zero effects");
        }
    }

    #[test]
    fn the_restore_anchor_off_the_quota_mount_is_66() {
        let mut f = host();
        f.node("srv/sagebrush/.restore").id.mnt_id = MNT + 1;
        assert_eq!(rcode(&restore_stage(&mut f, &mut exited(ok_reply()), &stage_args("home"))), 66);
        assert_eq!(f.count("mkdir"), 0);
    }

    // ---- fill-home

    /// A staged home class with a marker: setuid file with xattrs, a setgid directory, a symlink, a root-owned file, a
    /// foreign directory with two entries, a FIFO; the destination provisioned and empty.
    fn staged(class: &str) -> (Fake, String) {
        let mut f = host();
        restore_stage(&mut f, &mut exited(ok_reply()), &stage_args(class));
        let att = attempt_path(class);
        let src = format!("{att}/data/srv/sagebrush/agents/{A}/{class}");
        let mut p = format!("{att}/data");
        for d in ["srv", "sagebrush", "agents", A] {
            p = join(&p, d);
            f.dir(&p, 0, 0o755);
        }
        f.dir(&src, UID, 0o700);
        let put = |f: &mut Fake, rel: &str, mode: u16, uid: u32| {
            let path = format!("{src}/{rel}");
            f.add(&path, mode, uid, uid);
            let n = f.node(&path);
            n.proj = UID;
            n.inherit = true;
        };
        put(&mut f, "a.txt", S_IFREG | 0o4755, UID);
        put(&mut f, "sub", S_IFDIR | 0o2755, UID);
        put(&mut f, "sub/b.txt", S_IFREG | 0o644, UID);
        put(&mut f, "link", S_IFLNK | 0o777, UID);
        put(&mut f, "root.txt", S_IFREG | 0o644, 0);
        put(&mut f, "other", S_IFDIR | 0o700, 70002);
        put(&mut f, "other/x", S_IFREG | 0o600, 70002);
        put(&mut f, "other/y", S_IFREG | 0o600, 70002);
        put(&mut f, "fifo", 0o010000 | 0o600, UID);
        f.xattrs.insert(format!("{src}/a.txt"), vec!["user.x".into(), "security.capability".into()]);
        f.agent("srv/sagebrush/agents");
        (f, src)
    }

    fn fill_expect(f: &mut Fake, class: &str) -> String {
        let root = f.root().unwrap();
        let ag = f.dir_from_root(&root, &format!("srv/sagebrush/agents/{A}")).unwrap();
        let (x, _) = crate::tree::child(f, &ag, class, MNT).unwrap().unwrap();
        expect_file(f, "fill.json", format!("{{\"epoch\":{{\"boot_id\":\"{BOOT}\",\"mnt_id\":{MNT}}},\"fsid\":\"0000abcd00001234\",\"dest\":{},\"uids\":[{UID}],\"gid\":{UID},\"projid\":{UID}}}", obj_json(&x)))
    }

    fn fill_args(class: &str, expect: String) -> FillArgs<'static> {
        let source: &'static str = Box::leak(format!("data/srv/sagebrush/agents/{A}/{class}").into_boxed_str());
        FillArgs { mount: "/srv/sagebrush", name: name(class), source, expect: Box::leak(expect.into_boxed_str()) }
    }

    #[test]
    fn fill_home_places_the_owned_entries_stripped_and_reports_the_rest() {
        let (mut f, src) = staged("home");
        let x = fill_expect(&mut f, "home");
        let out = fill_home(&mut f, &fill_args("home", x)).unwrap();
        assert_eq!(
            out,
            "{\"placed\":{\"dirs\":1,\"files\":2,\"symlinks\":1},\"refused\":[{\"path\":\"other\",\"uid\":70002,\"gid\":70002,\"entries\":2},{\"path\":\"root.txt\",\"uid\":0,\"gid\":0,\"entries\":0}],\"unexpected\":[{\"path\":\"fifo\",\"type\":\"fifo\"}],\"truncated\":false}\n"
        );
        let dest = format!("srv/sagebrush/agents/{A}/home");
        let a = &f.nodes[&format!("{dest}/a.txt")];
        assert_eq!(a.id.mode & 0o7777, 0o755, "setuid stripped");
        assert!(f.xattrs[&format!("{src}/a.txt")].is_empty(), "stripped in staging, before the move");
        let sub = &f.nodes[&format!("{dest}/sub")];
        assert_eq!((sub.id.mode & 0o7777, sub.id.uid, sub.id.gid, sub.proj), (0o755, UID, UID, UID), "setgid stripped, chowned, in the project");
        assert!(f.nodes.contains_key(&format!("{dest}/sub/b.txt")) && f.nodes.contains_key(&format!("{dest}/link")));
        for left in ["root.txt", "other", "other/x", "fifo"] {
            assert!(f.nodes.contains_key(&format!("{src}/{left}")), "{left} stays in staging");
            assert!(!f.nodes.contains_key(&format!("{dest}/{left}")), "{left} isn't placed");
        }
        let att = attempt_path("home");
        assert!(!f.nodes.contains_key(&format!("{att}/.complete")), "consumed");
        let pos = |s: &str| f.log.iter().position(|l| l == s).unwrap_or_else(|| panic!("{s}: {:?}", f.log));
        assert!(pos(&format!("unlink {att}/.complete")) < pos("drop_caps"));
        assert!(pos("drop_caps") < pos(&format!("mkdir {dest}/sub")), "CAP_SYS_RESOURCE gone before the first destination write");
        assert!(pos(&format!("chmod {src}/a.txt 755")) < pos(&format!("remove_xattr {src}/a.txt user.x")));
        assert!(pos(&format!("remove_xattr {src}/a.txt security.capability")) < pos(&format!("fsync_file {src}/a.txt")));
        assert!(pos(&format!("fsync_file {src}/a.txt")) < pos(&format!("rename {src}/a.txt {dest}/a.txt")), "strip and sync before the rename");
        assert!(pos(&format!("fsync {dest}/sub")) < pos(&format!("fsync {dest}")), "bottom-up");
        assert!(pos(&format!("fsync {dest}")) < pos(&format!("fsync srv/sagebrush/agents/{A}")), "then the destination's parent");
        assert_eq!(f.log.last().unwrap(), &format!("fsync srv/sagebrush/agents/{A}"), "the barrier is the last thing before the exit");
    }

    #[test]
    fn the_marker_is_required_exact_and_consumed_and_a_second_fill_is_73() {
        let (mut f, _) = staged("home");
        let x = fill_expect(&mut f, "home");
        let att = attempt_path("home");
        f.files.insert(format!("{att}/.complete"), b"another".to_vec());
        assert_eq!(code(fill_home(&mut f, &fill_args("home", x.clone()))), 73);
        assert!(f.nodes.contains_key(&format!("{att}/.complete")), "a wrong marker isn't consumed");
        f.files.insert(format!("{att}/.complete"), name("home").path().into_bytes());
        f.node(&format!("{att}/.complete")).id.mode = S_IFREG | 0o644;
        assert_eq!(code(fill_home(&mut f, &fill_args("home", x.clone()))), 73, "a marker that isn't root 0600");
        f.node(&format!("{att}/.complete")).id.mode = S_IFREG | 0o600;
        assert_eq!(code(fill_home(&mut f, &fill_args("home", x.clone()))), 0);
        assert_eq!(code(fill_home(&mut f, &fill_args("home", x))), 73, "a second fill of the same attempt");
        let (mut f, _) = staged("home");
        f.nodes.remove(&format!("{att}/.complete"));
        let x = fill_expect(&mut f, "home");
        let before = f.count("mkdir");
        assert_eq!(code(fill_home(&mut f, &fill_args("home", x))), 73, "no marker");
        assert_eq!(f.count("mkdir"), before, "nothing made");
    }

    #[test]
    fn a_crash_after_the_marker_removal_leaves_the_attempt_consumed_and_a_rerun_is_73() {
        let (mut f, _) = staged("home");
        let x = fill_expect(&mut f, "home");
        f.caps_fail = true;
        assert_eq!(code(fill_home(&mut f, &fill_args("home", x.clone()))), 68, "the cap drop failing is 68");
        assert!(!f.log.iter().any(|l| l.starts_with(&format!("mkdir srv/sagebrush/agents/{A}"))), "nothing reached the destination");
        f.caps_fail = false;
        assert_eq!(code(fill_home(&mut f, &fill_args("home", x))), 73, "consumed: the supervisor re-stages");
    }

    #[test]
    fn the_destination_must_be_the_recorded_identity_and_empty() {
        let (mut f, _) = staged("home");
        let x = fill_expect(&mut f, "home");
        f.file(&format!("srv/sagebrush/agents/{A}/home/leftover"), UID, 0o600);
        assert_eq!(code(fill_home(&mut f, &fill_args("home", x))), 73);
        assert!(!f.log.iter().any(|l| l.starts_with("rename")));
        let (mut f, _) = staged("home");
        let x = fill_expect(&mut f, "home");
        f.node(&format!("srv/sagebrush/agents/{A}/home")).gen = 99;
        assert_eq!(code(fill_home(&mut f, &fill_args("home", x))), 73);
    }

    #[test]
    fn edquot_and_enospc_in_the_fill_are_classified_and_other_failures_are_73_before_and_75_after() {
        // EDQUOT at a mkdir and at a rename, with the project at its limit: 76.
        for op in ["mkdir", "rename"] {
            let (mut f, _) = staged("home");
            let x = fill_expect(&mut f, "home");
            f.quota = Some(q(GIB, GIB_BLOCKS, 0, 0));
            let n = f.count(op) + 1;
            f.errno_at = Some((op, n, libc::EDQUOT));
            assert_eq!(code(fill_home(&mut f, &fill_args("home", x))), 76, "{op}");
        }
        // ENOSPC with the filesystem full and the project under its limits: 77.
        let (mut f, _) = staged("home");
        let x = fill_expect(&mut f, "home");
        f.quota = Some(q(2 << 20, GIB_BLOCKS, 5, 100));
        f.space = (0, 9);
        let n = f.count("rename") + 1;
        f.errno_at = Some(("rename", n, libc::ENOSPC));
        assert_eq!(code(fill_home(&mut f, &fill_args("home", x))), 77);
        // Another failure after the first move: 75.
        let (mut f, _) = staged("home");
        let x = fill_expect(&mut f, "home");
        let n = f.count("rename") + 2;
        f.errno_at = Some(("rename", n, libc::EIO));
        assert_eq!(code(fill_home(&mut f, &fill_args("home", x))), 75);
        // A failure before the first effect (the dry pass can't list): 73, nothing moved or stripped.
        let (mut f, src) = staged("home");
        let x = fill_expect(&mut f, "home");
        let n = f.count("list") + 3;
        f.errno_at = Some(("list", n, libc::EIO));
        assert_eq!(code(fill_home(&mut f, &fill_args("home", x))), 73);
        assert!(!f.log.iter().any(|l| l.starts_with("rename") || l.starts_with(&format!("chmod {src}"))), "{:?}", f.log);
    }

    #[test]
    fn an_xattr_removal_or_any_fsync_failure_is_75_never_exit_0() {
        for op in ["remove_xattr", "fsync_file"] {
            let (mut f, _) = staged("home");
            let x = fill_expect(&mut f, "home");
            let n = f.count(op) + 1;
            f.errno_at = Some((op, n, libc::EIO));
            assert_eq!(code(fill_home(&mut f, &fill_args("home", x))), 75, "{op}");
        }
        // The directory fsyncs after the marker's: the placed directory, the destination, its parent.
        for k in 2..=4 {
            let (mut f, _) = staged("home");
            let x = fill_expect(&mut f, "home");
            let n = f.count("fsync") + k;
            f.errno_at = Some(("fsync", n, libc::EIO));
            assert_eq!(code(fill_home(&mut f, &fill_args("home", x))), 75, "fsync {k}");
        }
    }

    #[test]
    fn the_bounds_refuse_with_zero_effects() {
        let (mut f, src) = staged("home");
        let x = fill_expect(&mut f, "home");
        let mut p = src.clone();
        for i in 0..=tree::MAX_DEPTH {
            p = format!("{p}/d{i}");
            f.add(&p, S_IFDIR | 0o700, UID, UID);
        }
        assert_eq!(code(fill_home(&mut f, &fill_args("home", x))), 73, "depth 257");
        assert!(!f.log.iter().any(|l| l.starts_with("mkdir srv/sagebrush/agents") || l.starts_with("rename")));
        let (mut f, _) = staged("home");
        let x = fill_expect(&mut f, "home");
        assert_eq!(code(fill_limited(&mut f, &fill_args("home", x), 5)), 73, "one past the object bound");
        assert!(!f.log.iter().any(|l| l.starts_with("rename")));
    }

    #[test]
    fn a_tag_class_places_members_and_the_tag_gid_only() {
        let mut f = host();
        let t = format!("t-{TAG}");
        let tn = Name::parse(RUN, &t, "tag", "1").unwrap();
        let args = StageArgs { mount: "/srv/sagebrush", name: tn.clone(), projid: 80001, snapshot: SNAP, path: "srv/sagebrush/tags/x" };
        assert_eq!(rcode(&restore_stage(&mut f, &mut exited(ok_reply()), &args)), 0);
        let att = format!("srv/sagebrush/.restore/{RUN}/{t}/tag/1");
        let src = format!("{att}/data/t");
        f.dir(&src, 0, 0o755);
        for (n, uid, gid) in [("m1", 70001u32, 80001u32), ("m2", 70002, 80001), ("stranger", 70003, 80001), ("own-group", 70001, 70001)] {
            let p = format!("{src}/{n}");
            f.add(&p, S_IFREG | 0o640, uid, gid);
            let x = f.node(&p);
            x.proj = 80001;
            x.inherit = true;
        }
        let dest = format!("srv/sagebrush/tags/{TAG}");
        f.dir(&dest, 0, 0o2770);
        f.node(&dest).proj = 80001;
        f.node(&dest).inherit = true;
        let root = f.root().unwrap();
        let tags = f.dir_from_root(&root, "srv/sagebrush/tags").unwrap();
        let (dx, _) = crate::tree::child(&mut f, &tags, TAG, MNT).unwrap().unwrap();
        let x = expect_file(&mut f, "tag.json", format!("{{\"epoch\":{{\"boot_id\":\"{BOOT}\",\"mnt_id\":{MNT}}},\"fsid\":\"0000abcd00001234\",\"dest\":{},\"uids\":[70001,70002],\"gid\":80001,\"projid\":80001}}", obj_json(&dx)));
        let out = fill_home(&mut f, &FillArgs { mount: "/srv/sagebrush", name: tn, source: "data/t", expect: Box::leak(x.into_boxed_str()) }).unwrap();
        assert!(out.contains("\"files\":2") && out.contains("\"path\":\"stranger\"") && out.contains("\"path\":\"own-group\""), "{out}");
        assert!(f.nodes.contains_key(&format!("{dest}/m1")) && f.nodes.contains_key(&format!("{dest}/m2")));
        assert!(!f.nodes.contains_key(&format!("{dest}/stranger")));
    }

    // ---- remove-tree beneath .restore (A2 §1)

    #[test]
    fn remove_tree_removes_one_attempt_beneath_restore_and_its_parents_must_be_root_0700() {
        assert!(tree::anchor_name_ok(RESTORE, &name("home").path()));
        assert!(!tree::anchor_name_ok(RESTORE, &format!("{RUN}/{}/home", owner())));
        assert!(!tree::anchor_name_ok(RESTORE, A));
        let (mut f, _) = staged("home");
        let att = attempt_path("home");
        let root = f.root().unwrap();
        let class = f.dir_from_root(&root, &format!("srv/sagebrush/.restore/{RUN}/{}/home", owner())).unwrap();
        let (x, _) = crate::tree::child(&mut f, &class, "1", MNT).unwrap().unwrap();
        let owners: Vec<String> = std::iter::once(0).chain(70001..70065).map(|u: u32| u.to_string()).collect();
        assert_eq!(owners.len(), 65);
        let ex = expect_file(&mut f, "rm.json", format!("{{\"epoch\":{{\"boot_id\":\"{BOOT}\",\"mnt_id\":{MNT}}},\"fsid\":\"0000abcd00001234\",\"root\":{},\"owners\":[{}]}}", obj_json(&x), owners.join(",")));
        // remove-tree refuses a FIFO (A1 §5): drop it from this staging.
        f.nodes.remove(&format!("{att}/data/srv/sagebrush/agents/{A}/home/fifo"));
        assert_eq!(code(tree::remove_tree(&mut f, RESTORE, &name("home").path(), &ex)), 0);
        assert!(!f.nodes.contains_key(&att) && f.nodes.contains_key(&format!("srv/sagebrush/.restore/{RUN}/{}/home", owner())));
        // Already gone, and a missing staging parent: success after syncing the deepest existing parent.
        assert_eq!(code(tree::remove_tree(&mut f, RESTORE, &name("home").path(), &ex)), 0);
        let gone = Name::parse(RUN, &owner(), "sessions", "1").unwrap().path();
        assert_eq!(code(tree::remove_tree(&mut f, RESTORE, &gone, &ex)), 0);
        // A staging parent that isn't root:root 0700 refuses, with everything else removable (owners, no FIFO).
        for (uid, mode) in [(0u32, 0o755u16), (5, 0o700)] {
            let (mut f, _) = staged("home");
            f.nodes.remove(&format!("{att}/data/srv/sagebrush/agents/{A}/home/fifo"));
            let run = format!("srv/sagebrush/.restore/{RUN}");
            f.node(&run).id.mode = S_IFDIR | mode;
            f.node(&run).id.uid = uid;
            let ex = expect_file(&mut f, "rm.json", format!("{{\"epoch\":{{\"boot_id\":\"{BOOT}\",\"mnt_id\":{MNT}}},\"fsid\":\"0000abcd00001234\",\"root\":{},\"owners\":[{}]}}", obj_json(&x), owners.join(",")));
            assert_eq!(code(tree::remove_tree(&mut f, RESTORE, &name("home").path(), &ex)), 73, "{uid} {mode:o}");
            assert!(f.nodes.contains_key(&att), "nothing removed");
        }
    }
}
