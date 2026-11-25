//! Launcher contract amendment A2 r3.4 (backup restore): `restore-stage` and `fill-home`. Root only, run by the
//! supervisor outside any unit, on A1's shared rules (the anchor policy, openat2 one component at a time with
//! RESOLVE_NO_XDEV, identity from opened handles, the epoch and the unique mount id).
//!
//! - `restore-stage` makes one staging attempt of one class (`<run>/<owner>/<class>/<attempt>` under
//!   /srv/sagebrush/.restore, charged to the class's project), runs the backup binary's restore into its `data/<leaf>`
//!   (r3.5: the last segment of `--path`; the binary restores the CONTENTS of `path`, so each class is staged alone) in a
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
/// Each entry: its path from the root, whether it is a file (else a directory), and whether a system service account
/// may own it (only resolv.conf: systemd-resolved's stub file; every other entry stays root-owned).
pub const SYSTEM: [(&str, bool, bool); 4] = [("etc/ssl/certs", false, false), ("etc/ca-certificates", false, false), ("etc/resolv.conf", true, true), ("etc/hosts", true, false)];
/// The request's encoded bound (A2 r3.2): at most this many bytes as JSON, else usage.
pub const MAX_REQUEST: usize = 4096;
/// The child's stdout and kept stderr (A2 S-b).
pub const MAX_OUT: usize = 64 * 1024;
const MAX_LIST: usize = 1000;
const MAX_MARKER: usize = 64;
const MAX_UIDS: usize = 64;
const MARKER: &str = ".complete";
/// The digest list's fixed name beside the class (A2 r3.6 §4b), in the attempt's `data/`. A class leaf can't take it.
pub const DIGESTS: &str = "digests.json";
/// The longest listing (A2 r3.6 §4b): `digests.json`, and `tree-digest`'s output.
pub const MAX_LISTING: u64 = 512 << 20;
const MAX_ELF_PHNUM: usize = 64;
/// resolv.conf (and only it) may be owned by a system service account below this uid: on a stock Ubuntu 24.04 host,
/// /etc/resolv.conf resolves to systemd-resolved's stub file, owned by `systemd-resolve`. Agents (70000+) and people
/// (1000+) never own one. Every other system-set entry must be owned by root. The bind is read-only either way.
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

/// The class's own staging directory beneath `data/` (A2 r3.5): the last segment of `--path`. The binary restores the
/// CONTENTS of `path` into `dest`, so each class is staged alone, in `data/<leaf>`. `path` must be `rel_ok`.
pub fn leaf(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// The closed request, built here and bounded AS ENCODED (A2 r3.2): a control character escapes to six bytes, so the
/// raw path length proves nothing. `dest` is `/data/<leaf>` (A2 r3.5), counted in the bound.
pub fn request(snapshot: &str, path: &str) -> Result<Vec<u8>> {
    if !snapshot_ok(snapshot) || !rel_ok(path) {
        return Err(err(Fail::Usage, "bad arguments"));
    }
    // r3.6: the leaf `digests.json` is reserved for the digest list beside the class.
    if leaf(path) == DIGESTS {
        return Err(err(Fail::Usage, "bad arguments"));
    }
    let dest = format!("/data/{}", leaf(path));
    let digests = format!("/data/{DIGESTS}");
    let r = format!(
        "{{\"op\":\"restore\",\"snapshot\":{},\"path\":{},\"dest\":{},\"digests\":{}}}",
        json::quote(snapshot),
        json::quote(path),
        json::quote(&dest),
        json::quote(&digests)
    );
    if r.len() > MAX_REQUEST {
        return Err(err(Fail::Usage, "the request is too large"));
    }
    Ok(r.into_bytes())
}

// ---- the operations A2 adds to A1's

pub trait RestoreOps: Ops {
    fn mkdir(&mut self, dir: &Self::H, name: impl AsRef<[u8]>, mode: u16) -> io::Result<()>;
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

/// restore-stage's own mkdirs hitting EDQUOT or ENOSPC (a full filesystem before the binary even runs): attributed by
/// §3.1 like the binary's own quota_exceeded or no_space, never a preflight refusal.
fn stage_space<O: RestoreOps>(o: &mut O, at: &O::H, projid: u32) -> Error {
    let (q, s, now) = (o.quota(at, projid), o.space(at), o.now());
    limit_error(classify(q, s, now))
}

fn is_space_error(e: &io::Error) -> bool {
    matches!(e.raw_os_error(), Some(libc::EDQUOT) | Some(libc::ENOSPC))
}

// ---- the backup binary's result (A2 S-b)

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reply {
    /// The snapshot the binary restored (its full id), how many specials it skipped, and the SHA-256 (64 lowercase hex)
    /// of the digest list it wrote (A2 r3.6).
    Ok(String, u64, String),
    Failed(String),
}

/// Exactly one JSON object on one line, then EOF, of the closed shape; anything else is None (`bad_result`).
pub fn reply(out: &[u8]) -> Option<Reply> {
    let body = out.strip_suffix(b"\n")?;
    if body.first() != Some(&b'{') || body.contains(&b'\n') {
        return None;
    }
    let v = json::parse_with(body, MAX_OUT)?;
    if let Some(f) = v.exact(&["ok", "snapshot", "skipped_special", "digests_sha256"]) {
        if f[0] != &Value::Bool(true) {
            return None;
        }
        let snap = f[1].str().filter(|s| snapshot_ok(s))?;
        let digests = f[3].str().filter(|s| crate::sha256::is_hex64(s))?;
        // A non-negative integer: the reader refuses signs, fractions and exponents.
        return Some(Reply::Ok(snap.to_string(), f[2].int()?, digests.to_string()));
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
pub(crate) fn staging_dir<O: RestoreOps>(o: &mut O, parent: &O::H, name: &str, mnt: u64, projid: u32) -> Result<O::H> {
    if tchild(o, parent, name, mnt)?.is_none() {
        match o.mkdir(parent, name, 0o700) {
            Ok(()) => {
                if let Some((_, Some(h))) = tchild(o, parent, name, mnt)? {
                    o.chmod(&h, 0o700).map_err(|_| pre("a staging directory's mode can't be set"))?;
                }
            }
            Err(e) if e.raw_os_error() == Some(libc::EEXIST) => {}
            Err(e) if is_space_error(&e) => return Err(stage_space(o, parent, projid)),
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
    // The closed system set: each present entry of its expected kind, not group- or other-writable, and owned by root
    // (resolv.conf alone may instead belong to a system service account, below uid 1000).
    let mut system = Vec::new();
    for (rel, file, service_owned) in SYSTEM {
        let h = match o.open_system(&root, rel) {
            Ok(h) => h,
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => continue,
            Err(_) => return Err(pre("a system file can't be opened")),
        };
        let id = o.ident(&h).map_err(open_err)?;
        let want = if file { Kind::File } else { Kind::Dir };
        let owner_ok = id.uid == 0 || (service_owned && id.uid < SYSTEM_OWNER_MAX);
        if kind_of(&id) != Some(want) || !owner_ok || id.mode & 0o022 != 0 {
            return Err(pre("a system file has the wrong kind or owner, or is writable by others"));
        }
        system.push((rel, file, h, id));
    }
    // 4 (before any effect). The release binary, by handle.
    let (rel_dir, bin) = release(o, &root)?;

    // 3. The attempt directory, and data beneath it.
    let [run, owner, class, attempt] = n.parts();
    let run_h = staging_dir(o, &ra, &run, mnt, a.projid)?;
    let owner_h = staging_dir(o, &run_h, &owner, mnt, a.projid)?;
    let class_h = staging_dir(o, &owner_h, &class, mnt, a.projid)?;
    match o.mkdir(&class_h, &attempt, 0o700) {
        Ok(()) => {}
        Err(e) if e.raw_os_error() == Some(libc::EEXIST) => return Err(err(Fail::Exists, "the attempt exists")),
        Err(e) if is_space_error(&e) => return Err(stage_space(o, &class_h, a.projid)),
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
    if let Err(e) = o.mkdir(&att, "data", 0o700) {
        return Err(if is_space_error(&e) { stage_space(o, &att, a.projid) } else { identity("data can't be made") });
    }
    let (_, dh) = tchild(o, &att, "data", mnt)?.ok_or(identity("data vanished"))?;
    let data = dh.ok_or(identity("data isn't a directory"))?;
    o.chmod(&data, 0o700).map_err(|_| identity("data's mode can't be set"))?;
    let dx = tchild(o, &att, "data", mnt)?.ok_or(identity("data vanished"))?.0;
    let di = o.ident(&data).map_err(open_err)?;
    // The name re-read must be the very directory opened and chmodded (a replacement with equal attributes refuses).
    if (dx.dev, dx.ino) != (di.dev, di.ino) || dx.uid != 0 || dx.gid != 0 || dx.mode != 0o700 || dx.projid != Some(a.projid) || dx.inherit != Some(true) {
        return Err(identity("data isn't a root 0700 directory of the class's project"));
    }
    // The class's own directory, data/<leaf> (A2 r3.5): the binary's dest, fresh, empty, root 0700, in the project.
    let lf = leaf(a.path);
    if let Err(e) = o.mkdir(&data, lf, 0o700) {
        return Err(if is_space_error(&e) { stage_space(o, &data, a.projid) } else { identity("the class's directory can't be made") });
    }
    let (_, lh) = tchild(o, &data, lf, mnt)?.ok_or(identity("the class's directory vanished"))?;
    let leaf_h = lh.ok_or(identity("the class's directory isn't a directory"))?;
    o.chmod(&leaf_h, 0o700).map_err(|_| identity("the class's directory's mode can't be set"))?;
    let lx = tchild(o, &data, lf, mnt)?.ok_or(identity("the class's directory vanished"))?.0;
    let li = o.ident(&leaf_h).map_err(open_err)?;
    if (lx.dev, lx.ino) != (li.dev, li.ino) || lx.uid != 0 || lx.gid != 0 || lx.mode != 0o700 || lx.projid != Some(a.projid) || lx.inherit != Some(true) || !o.batch(&leaf_h).map_err(open_err)?.is_empty() {
        return Err(identity("the class's directory isn't a fresh, empty root 0700 directory of the class's project"));
    }
    for h in [&leaf_h, &data, &att, &class_h] {
        o.fsync(h).map_err(|_| err(Fail::Partial, "the attempt can't be synced"))?;
    }
    // Still the same directory at the name after the syncs: the child's dest is that path.
    let again = tchild(o, &data, lf, mnt)?.ok_or(identity("the class's directory vanished"))?.0;
    if (again.dev, again.ino) != (li.dev, li.ino) {
        return Err(identity("the class's directory was replaced"));
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
        // A2 r3.8.3: the binary's own §4b bounds (entries, a path, the listing) are permanent: 64 `limit`, no marker,
        // never the retried 75. Its JSON is relayed as for any other failure.
        Some(Reply::Failed(code)) if code == "limit" => Ok(Done { out: stdout, result: Err(err(Fail::Usage, "limit")) }),
        Some(Reply::Failed(_)) => Ok(Done { out: stdout, result: Err(err(Fail::Partial, "the restore failed")) }),
        Some(Reply::Ok(snap, ..)) if snap != a.snapshot => Err(err(Fail::Partial, "the restored snapshot isn't the requested one")),
        Some(Reply::Ok(_, _, digests)) => {
            // 11. The marker, written by the launcher only, once the data is durable (O1, O2).
            o.syncfs(&att).map_err(|_| err(Fail::Partial, "the staged data can't be made durable"))?;
            // 11.1a (r3.6): the digest list is the one the binary reported, before any marker.
            digests_bound(o, &data, mnt, &digests)?;
            o.create_marker(&att, MARKER, n.path().as_bytes()).map_err(|_| err(Fail::Partial, "the marker can't be written"))?;
            o.fsync(&att).map_err(|_| err(Fail::Partial, "the marker can't be made durable"))?;
            Ok(Done { out: stdout, result: Ok(()) })
        }
    }
}

/// A2 r3.6 §3 step 11.1a: `data/digests.json` beneath `data` (no symlink, no other mount), a regular root-owned file
/// with one link and at most MAX_LISTING bytes, read through its own handle and hashed; the hash must be the binary's
/// reported `digests_sha256`. Anything else is 75 `bad_result`, and no marker is written.
fn digests_bound<O: RestoreOps>(o: &mut O, data: &O::H, mnt: u64, want: &str) -> Result<()> {
    let bad = || err(Fail::Partial, "bad_result");
    let ok = |id: &Ident| kind_of(id) == Some(Kind::File) && id.nlink == 1 && id.uid == 0 && id.size <= MAX_LISTING && id.mnt_id == mnt;
    let id = match o.at(data, DIGESTS, At::Path) {
        Ok(h) => o.ident(&h).map_err(|_| bad())?,
        Err(_) => return Err(bad()),
    };
    if !ok(&id) {
        return Err(bad());
    }
    let h = o.at(data, DIGESTS, At::File).map_err(|_| bad())?;
    let again = o.ident(&h).map_err(|_| bad())?;
    if (again.dev, again.ino) != (id.dev, id.ino) || !ok(&again) {
        return Err(bad());
    }
    let mut sum = crate::sha256::Sha256::new();
    let mut off = 0u64;
    loop {
        let chunk = o.pread(&h, 1 << 20, off).map_err(|_| bad())?;
        if chunk.is_empty() {
            break;
        }
        off += chunk.len() as u64;
        if off > MAX_LISTING {
            return Err(bad());
        }
        sum.update(&chunk);
    }
    if off != again.size || crate::sha256::hex(&sum.finish()) != want {
        return Err(bad());
    }
    Ok(())
}

// ---- fill-home (A2 §4)

pub struct FillArgs<'a> {
    pub mount: &'a str,
    pub name: Name,
    pub source: &'a str,
    pub expect: &'a str,
}

pub(crate) fn dest_anchor(c: Class) -> &'static str {
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
    /// Raw relative paths (A2 r3.9): encoded with §4b's codec only in the report.
    refused: Vec<(Vec<u8>, u32, u32, u64)>,
    unexpected: Vec<(Vec<u8>, &'static str)>,
    truncated: bool,
}

impl Fill {
    /// Before the first effect, a refusal is 73; after it, 75.
    fn fail(&self, msg: &'static str) -> Error {
        if self.effects == 0 { identity(msg) } else { err(Fail::Partial, msg) }
    }
    fn refuse(&mut self, path: Vec<u8>, uid: u32, gid: u32, entries: u64) {
        if self.refused.len() < MAX_LIST { self.refused.push((path, uid, gid, entries)) } else { self.truncated = true }
    }
    fn odd(&mut self, path: Vec<u8>, t: &'static str) {
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
fn entry<O: RestoreOps>(o: &mut O, w: &Fill, dir: &O::H, name: &[u8]) -> Result<(Ident, Option<Kind>)> {
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

/// The dry pass (before any effect): bounds (2,000,000 objects, depth 256, and a relative path of at most 4096 raw
/// bytes, A2 r3.9) and types only. `plen` is `dir`'s own relative path length in raw bytes (0 at the class root).
/// Adds the entries it sees to `count`.
fn scan<O: RestoreOps>(o: &mut O, w: &Fill, dir: &O::H, plen: usize, depth: usize, count: &mut usize) -> Result<()> {
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
            let len = if plen == 0 { name.len() } else { plen + 1 + name.len() };
            if len > crate::digest::MAX_PATH {
                return Err(w.fail("a staged path is too long"));
            }
            if let (_, Some(Kind::Dir)) = entry(o, w, dir, &name)? {
                let h = o.at(dir, &name, At::Dir).map_err(|_| w.fail("a staging directory can't be opened"))?;
                scan(o, w, &h, len, depth + 1, count)?;
            }
        }
    }
}

/// A relative path's raw bytes: `rel/name`, or `name` at the class root.
fn join(rel: &[u8], name: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(rel.len() + 1 + name.len());
    if !rel.is_empty() {
        p.extend_from_slice(rel);
        p.push(b'/');
    }
    p.extend_from_slice(name);
    p
}

/// The walk, top-down (A2 §4 step 5), for the staging directory `sname` beneath `sp` (identity `sid`) into `dst`.
/// Entries are moved out while the directory is read, so it is read in ROUNDS, each through a freshly opened handle,
/// until a round finds nothing new (as A1's remove-tree pass 2): a listing may skip a name while names leave, never
/// invent one. Only the names that stay in staging (refused, unexpected) are remembered between rounds.
#[allow(clippy::too_many_arguments)]
fn walk<O: RestoreOps>(o: &mut O, w: &mut Fill, sp: &O::H, sname: &[u8], sid: ((u32, u32), u64), dst: &O::H, rel: &[u8], depth: usize) -> Result<()> {
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
fn walk_round<O: RestoreOps>(o: &mut O, w: &mut Fill, src: &O::H, dst: &O::H, rel: &[u8], depth: usize, kept: &mut std::collections::BTreeSet<Vec<u8>>) -> Result<bool> {
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
                // Not placed; a refused directory's whole subtree is neither walked nor placed, reported once. Its
                // `entries` counts the refused object itself plus, for a directory, everything beneath it (A2 r3.9):
                // exactly the listing entries validation removes for it.
                let mut n = 1usize;
                if kind == Kind::Dir {
                    let h = o.at(src, &name, At::Dir).map_err(|_| w.fail("a staging directory can't be opened"))?;
                    scan(o, w, &h, p.len(), depth + 1, &mut n)?;
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
    // Every path through §4b's codec, then its JSON form (A2 r3.9): one encoding for every path written.
    let path = |p: &[u8]| json::quote(&crate::digest::encode(p));
    let refused: Vec<String> = w
        .refused
        .iter()
        .map(|(p, u, g, n)| format!("{{\"path\":{},\"uid\":{u},\"gid\":{g},\"entries\":{n}}}", path(p)))
        .collect();
    let unexpected: Vec<String> = w.unexpected.iter().map(|(p, t)| format!("{{\"path\":{},\"type\":\"{t}\"}}", path(p))).collect();
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
    scan(o, &w, &src, 0, 1, &mut count)?;
    let si = o.ident(&src).map_err(open_err)?;
    drop(src);
    let (parent_rel, leaf) = a.source.rsplit_once('/').ok_or(identity("no such source"))?;
    let mut sp = None;
    for part in parent_rel.split('/') {
        let parent = sp.as_ref().unwrap_or(&att);
        sp = Some(tchild(o, parent, part, mnt)?.and_then(|(_, h)| h).ok_or(identity("no such source"))?);
    }
    let sp = sp.ok_or(identity("no such source"))?;
    walk(o, &mut w, &sp, leaf.as_bytes(), (si.dev, si.ino), &dst, b"", 1)?;
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
    fn mkdir(&mut self, dir: &OwnedFd, name: impl AsRef<[u8]>, mode: u16) -> io::Result<()> {
        sys::mkdirat(dir, &tree::cb(name.as_ref())?, mode as libc::mode_t)
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
    use crate::tree::tests::{code, e, expect_file, join, Fake, Hook, FH, A, BOOT, MNT, UID};
    use crate::tree::{obj_json, S_IFDIR, S_IFLNK, S_IFREG};

    const RUN: &str = "abcdefghijklmnop";
    const TAG: &str = "zyxwvutsrqponmlkjihgfedcba";
    const SNAP: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const BIN: &str = "opt/sagebrush/1/bin/sagebrush-agent-backup";

    impl RestoreOps for Fake {
        fn mkdir(&mut self, dir: &FH, name: impl AsRef<[u8]>, mode: u16) -> io::Result<()> {
            self.tick("mkdir")?;
            let p = join(&dir.p, &crate::tree::tests::key(name.as_ref()));
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
            self.tick("pread")?;
            self.log.push(format!("pread {}", h.p));
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
        // The fake binary's digest list (A2 r3.6): planted in the attempt's data just before the launcher's syncfs.
        f.hook = Some(("syncfs", 1, plant_digests));
        f
    }

    const DIG: &[u8] = b"{\"v\":1}\n{\"count\":0,\"total_bytes\":0}\n";
    fn dig_hex(b: &[u8]) -> String {
        let mut s = crate::sha256::Sha256::new();
        s.update(b);
        crate::sha256::hex(&s.finish())
    }
    /// The attempt's data directory: the last `mkdir .../data` the fake logged.
    fn data_dir(f: &Fake) -> String {
        f.log.iter().rev().find_map(|l| l.strip_prefix("mkdir ").filter(|p| p.ends_with("/data")).map(str::to_string)).expect("a data dir was made")
    }
    fn put_digests(f: &mut Fake, body: &[u8]) {
        let p = format!("{}/{DIGESTS}", data_dir(f));
        f.nodes.remove(&p);
        f.add(&p, S_IFREG | 0o600, 0, 0);
        f.node(&p).id.size = body.len() as u64;
        f.files.insert(p, body.to_vec());
    }
    fn plant_digests(f: &mut Fake) {
        put_digests(f, DIG);
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
        ok_reply_with(&dig_hex(DIG))
    }
    fn ok_reply_with(digests: &str) -> Vec<u8> {
        format!("{{\"snapshot\":\"{SNAP}\",\"skipped_special\":0,\"ok\":true,\"digests_sha256\":\"{digests}\"}}\n").into_bytes()
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
        // A fixed one-byte leaf, so only the first segment grows (dest repeats the leaf, A2 r3.5).
        let base = request(SNAP, "a/z").unwrap().len() - 1;
        let exact = format!("{}/z", "a".repeat(MAX_REQUEST - base));
        assert_eq!(request(SNAP, &exact).unwrap().len(), MAX_REQUEST, "exactly 4096 encoded bytes are accepted");
        assert_eq!(code(request(SNAP, &format!("a{exact}"))), 64, "4097 is usage");
        // 1003 raw bytes of control characters (four 250-byte components): far over 4096 once encoded.
        let ctl = "\u{1}".repeat(250);
        let heavy = [ctl.as_str(); 4].join("/");
        assert_eq!(heavy.len(), 1003);
        assert_eq!(code(request(SNAP, &heavy)), 64);
        // A plain 1025-byte path that fits is accepted (the bound is the encoding, not the raw length).
        assert!(request(SNAP, &"b".repeat(1025)).is_ok());
        let r = String::from_utf8(request(SNAP, "srv/x").unwrap()).unwrap();
        assert_eq!(r, format!("{{\"op\":\"restore\",\"snapshot\":\"{SNAP}\",\"path\":\"srv/x\",\"dest\":\"/data/x\",\"digests\":\"/data/digests.json\"}}"));
        // r3.6: the leaf `digests.json` is reserved beside the class.
        assert_eq!(code(request(SNAP, "srv/sagebrush/agents/x/digests.json")), 64);
        assert!(request(SNAP, "srv/sagebrush/agents/x/digests.json.d").is_ok());
        // R1: dest is exactly /data/<leaf> for each class's path, and the bound counts it: a path whose request is 4097
        // bytes only because of the leaf repeated in dest is usage.
        for (path, want) in [("srv/sagebrush/agents/x/home", "home"), ("srv/sagebrush/agents/x/sessions", "sessions"), ("srv/sagebrush/archive/x", "x"), ("srv/sagebrush/tags/t", "t"), ("solo", "solo")] {
            assert_eq!(leaf(path), want);
            let r = String::from_utf8(request(SNAP, path).unwrap()).unwrap();
            assert!(r.ends_with(&format!(",\"dest\":\"/data/{want}\",\"digests\":\"/data/digests.json\"}}")), "{r}");
        }
        let p = |k: usize| format!("a/{}", "b".repeat(k));
        let k = (1..MAX_REQUEST).take_while(|k| request(SNAP, &p(*k)).is_ok()).last().unwrap();
        let len = request(SNAP, &p(k)).unwrap().len();
        assert!(len >= MAX_REQUEST - 1, "the largest accepted is at the bound: {len}");
        assert_eq!(code(request(SNAP, &p(k + 1))), 64);
        // One more `b` adds two bytes (the path and dest's leaf); without dest's leaf the request would still fit.
        assert!(len + 2 - (k + 1) - 1 < MAX_REQUEST, "over the bound only because dest repeats the leaf");
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
        assert_eq!(reply(&ok_reply()), Some(Reply::Ok(SNAP.into(), 0, dig_hex(DIG))));
        // r3.6: digests_sha256 is required, exact (64 lowercase hex), and no other key is allowed.
        let without = format!("{{\"snapshot\":\"{SNAP}\",\"skipped_special\":0,\"ok\":true}}\n");
        let extra = format!("{{\"snapshot\":\"{SNAP}\",\"skipped_special\":0,\"ok\":true,\"digests_sha256\":\"{}\",\"x\":1}}\n", dig_hex(DIG));
        for bad in [without, extra, String::from_utf8(ok_reply_with(&"A".repeat(64))).unwrap(), String::from_utf8(ok_reply_with(&"a".repeat(63))).unwrap(), String::from_utf8(ok_reply_with(&"g".repeat(64))).unwrap()] {
            assert_eq!(reply(bad.as_bytes()), None, "{bad}");
        }
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
        // R2: data/<leaf>, the binary's dest, root:root 0700 in the class's project, synced before the child ran.
        let lf = f.nodes[&format!("{att}/data/home")].clone();
        assert_eq!((lf.id.uid, lf.id.gid, lf.id.mode & 0o7777, lf.proj, lf.inherit), (0, 0, 0o700, UID, true));
        assert!(pos(&format!("fsync {att}/data/home")) < pos(&format!("fsync {att}/data")), "the leaf, then data, synced");

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

    fn leaf_path() -> String {
        format!("{}/data/home", attempt_path("home"))
    }

    #[test]
    fn the_class_directory_is_fresh_empty_root_0700_in_the_project_else_73_with_nothing_run() {
        // R2 (A2 r3.5): data/<leaf> is made by the launcher; anything else at the name, or a made one that isn't
        // exactly that, is 73 and the child never runs. Hooks run before the nth call of an op: the 6th mkdir is the
        // leaf's, the 6th chmod the leaf's.
        fn premade(f: &mut Fake) {
            f.dir(&leaf_path(), 0, 0o700);
        }
        fn foreign(f: &mut Fake) {
            f.node(&leaf_path()).id.uid = 5;
        }
        fn group(f: &mut Fake) {
            f.node(&leaf_path()).id.gid = 5;
        }
        fn populated(f: &mut Fake) {
            f.add(&format!("{}/x", leaf_path()), S_IFREG | 0o600, 0, 0);
        }
        fn project(f: &mut Fake) {
            f.node(&leaf_path()).proj = UID + 1;
        }
        fn no_inherit(f: &mut Fake) {
            f.node(&leaf_path()).inherit = false;
        }
        fn file(f: &mut Fake) {
            f.nodes.remove(&leaf_path());
            f.add(&leaf_path(), S_IFREG | 0o700, 0, 0);
        }
        fn replaced(f: &mut Fake) {
            f.node(&leaf_path()).id.ino = 99_999; // same owner, mode, project, inherit and emptiness: another inode
        }
        fn data_replaced(f: &mut Fake) {
            f.node(&format!("{}/data", attempt_path("home"))).id.ino = 99_998;
        }
        let rows: [(&str, &'static str, Hook); 7] = [
            ("pre-made", "mkdir", premade),
            ("another owner", "chmod", foreign),
            ("another group", "chmod", group),
            ("not empty", "chmod", populated),
            ("another project", "chmod", project),
            ("no inherit", "chmod", no_inherit),
            ("a file", "chmod", file),
        ];
        for (what, op, hook) in rows {
            let mut f = host();
            f.hook = Some((op, 6, hook));
            let mut r = exited(ok_reply());
            assert_eq!(rcode(&restore_stage(&mut f, &mut r, &stage_args("home"))), 73, "{what}");
            assert!(r.seen.is_none(), "{what}: nothing ran");
            assert!(f.hook.is_none(), "{what}: the hook fired");
        }
        // An actual inode replacement with every attribute equal, after the open and before the re-read: of the leaf
        // (the 6th chmod is the leaf's) and of data (the 5th is data's).
        for (what, n, hook) in [("the leaf replaced", 6usize, replaced as Hook), ("data replaced", 5, data_replaced)] {
            let mut f = host();
            f.hook = Some(("chmod", n, hook));
            let mut r = exited(ok_reply());
            assert_eq!(rcode(&restore_stage(&mut f, &mut r, &stage_args("home"))), 73, "{what}");
            assert!(r.seen.is_none() && f.hook.is_none(), "{what}");
            assert!(!f.log.iter().any(|l| l.starts_with("fsync ")), "{what}: refused at the re-read, before any sync");
        }
        // Replaced after its own sync (before data's): the re-read after the syncs refuses.
        let mut f = host();
        restore_stage(&mut f, &mut exited(ok_reply()), &stage_args("home"));
        let k = f.log.iter().filter(|l| l.starts_with("fsync ")).position(|l| *l == format!("fsync {}", leaf_path())).unwrap() + 1;
        let mut f = host();
        f.hook = Some(("fsync", k + 1, replaced));
        let mut r = exited(ok_reply());
        assert_eq!(rcode(&restore_stage(&mut f, &mut r, &stage_args("home"))), 73, "replaced after the sync");
        assert!(r.seen.is_none() && f.hook.is_none());
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
    fn restore_stage_own_mkdirs_out_of_space_are_attributed_not_preflight() {
        // Found on a real host: a filesystem out of inodes fails restore-stage's own mkdirs, before the binary runs.
        // Every one of them (the run, owner and class parents, the attempt, data, data/<leaf>), with either errno, attributed by
        // §3.1: the project at its limit is 76; the project under it on a full filesystem is 77.
        let names = ["run", "owner", "class", "attempt", "data", "data/<leaf>"];
        for (n, name) in names.iter().enumerate() {
            for errno in [libc::ENOSPC, libc::EDQUOT] {
                for (quota, space, want) in [(q(0, 0, 100, 100), (100u64, 100u64), 76), (q(2 << 20, GIB_BLOCKS, 5, 100), (100, 0), 77)] {
                    let mut f = host();
                    f.quota = Some(quota);
                    f.space = space;
                    f.errno_at = Some(("mkdir", n + 1, errno));
                    let mut r = exited(ok_reply());
                    assert_eq!(rcode(&restore_stage(&mut f, &mut r, &stage_args("home"))), want, "{name} mkdir, errno {errno}");
                    assert!(r.seen.is_none(), "{name}: nothing ran");
                }
            }
        }
    }

    // ---- the digest list's binding (A2 r3.6 §3 step 11.1a)

    fn plant_none(_f: &mut Fake) {}
    fn plant_symlink(f: &mut Fake) {
        let p = format!("{}/{DIGESTS}", data_dir(f));
        f.add(&p, S_IFLNK | 0o777, 0, 0);
    }
    fn plant_dir(f: &mut Fake) {
        let p = format!("{}/{DIGESTS}", data_dir(f));
        f.dir(&p, 0, 0o700);
    }
    fn plant_two_links(f: &mut Fake) {
        plant_digests(f);
        let p = format!("{}/{DIGESTS}", data_dir(f));
        f.node(&p).id.nlink = 2;
    }
    fn plant_foreign(f: &mut Fake) {
        plant_digests(f);
        let p = format!("{}/{DIGESTS}", data_dir(f));
        f.node(&p).id.uid = UID;
    }
    fn plant_huge(f: &mut Fake) {
        plant_digests(f);
        let p = format!("{}/{DIGESTS}", data_dir(f));
        f.node(&p).id.size = MAX_LISTING + 1;
    }
    fn plant_other(f: &mut Fake) {
        put_digests(f, b"{\"v\":1}\n{\"count\":1,\"total_bytes\":0}\n");
    }
    fn plant_short(f: &mut Fake) {
        plant_digests(f);
        let p = format!("{}/{DIGESTS}", data_dir(f));
        f.node(&p).id.size = DIG.len() as u64 + 1; // the bytes read don't reach the size statx reported
    }

    #[test]
    fn the_digest_list_must_be_the_reported_one_before_any_marker() {
        // The match: the marker is written, after the syncfs, and the printed line carries the hash.
        let mut f = host();
        let d = restore_stage(&mut f, &mut exited(ok_reply()), &stage_args("home"));
        assert_eq!(rcode(&d), 0, "{:?}", d.result);
        assert!(String::from_utf8(d.out.clone()).unwrap().contains(&dig_hex(DIG)));
        let att = attempt_path("home");
        assert!(f.nodes.contains_key(&format!("{att}/.complete")));
        // Each other list (or none): 75 bad_result, and NO marker.
        let rows: [(&str, Hook); 8] = [
            ("missing", plant_none),
            ("a symlink", plant_symlink),
            ("a directory", plant_dir),
            ("two links", plant_two_links),
            ("not root's", plant_foreign),
            ("over 512 MiB", plant_huge),
            ("another list (a hash mismatch)", plant_other),
            ("shorter than its size", plant_short),
        ];
        for (what, plant) in rows {
            let mut f = host();
            f.hook = Some(("syncfs", 1, plant));
            let d = restore_stage(&mut f, &mut exited(ok_reply()), &stage_args("home"));
            assert_eq!(rcode(&d), 75, "{what}");
            assert!(!f.nodes.contains_key(&format!("{}/.complete", attempt_path("home"))), "{what}: no marker");
            assert!(!f.log.iter().any(|l| l.starts_with("marker ")), "{what}");
            // Refused before a single byte is read: the cap, the kind, the links and the owner are checked first.
            if !what.starts_with("another list") && !what.starts_with("shorter") {
                assert!(!f.log.iter().any(|l| l.starts_with("pread ") && l.ends_with(DIGESTS)), "{what}: nothing read");
            }
        }
        // A reply naming another hash than the list's: 75, no marker.
        let mut f = host();
        let d = restore_stage(&mut f, &mut exited(ok_reply_with(&"0".repeat(64))), &stage_args("home"));
        assert_eq!(rcode(&d), 75);
        assert!(!f.log.iter().any(|l| l.starts_with("marker ")));
        // A reply without the hash is bad_result before the syncfs.
        let mut f = host();
        let without = format!("{{\"snapshot\":\"{SNAP}\",\"skipped_special\":0,\"ok\":true}}\n").into_bytes();
        assert_eq!(rcode(&restore_stage(&mut f, &mut exited(without), &stage_args("home"))), 75);
        assert_eq!(f.count("syncfs"), 0);
    }

    #[test]
    fn fill_home_never_moves_the_digest_list() {
        let (mut f, _) = staged("home");
        let p = format!("{}/data/{DIGESTS}", attempt_path("home"));
        let before = (f.nodes[&p].id.ino, f.files[&p].clone());
        let x = fill_expect(&mut f, "home");
        fill_home(&mut f, &fill_args("home", x)).unwrap();
        assert_eq!((f.nodes[&p].id.ino, f.files[&p].clone()), before, "the list stays, the same inode and bytes");
    }

    #[test]
    fn the_binary_s_limit_is_a_permanent_64_and_other_failures_keep_their_codes() {
        // A2 r3.8.3: `limit` is 64 with no syncfs and no marker; the binary's line is relayed.
        let mut f = host();
        let d = restore_stage(&mut f, &mut exited(failed("limit")), &stage_args("home"));
        assert_eq!(rcode(&d), 64);
        assert_eq!(d.result.unwrap_err().msg, "limit");
        assert_eq!(d.out, failed("limit"), "the binary's JSON is relayed");
        assert_eq!(f.count("syncfs"), 0);
        assert!(!f.log.iter().any(|l| l.starts_with("marker ")));
        // Another unknown code stays 75; no_space stays §3.1's (77 with the filesystem full and the project under).
        let mut f = host();
        assert_eq!(rcode(&restore_stage(&mut f, &mut exited(failed("other")), &stage_args("home"))), 75);
        let mut f = host();
        f.quota = Some(q(2 << 20, GIB_BLOCKS, 5, 100));
        f.space = (0, 9);
        assert_eq!(rcode(&restore_stage(&mut f, &mut exited(failed("no_space")), &stage_args("home"))), 77);
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
    fn only_resolv_conf_may_belong_to_a_system_account_and_no_system_entry_to_a_person_or_agent_or_be_writable() {
        // Every SYSTEM entry present, as on a stock host.
        let full = || {
            let mut f = host();
            f.dir("etc/ca-certificates", 0, 0o755);
            f.file("etc/hosts", 0, 0o644);
            f
        };
        assert_eq!(rcode(&restore_stage(&mut full(), &mut exited(ok_reply()), &stage_args("home"))), 0, "all root-owned");
        // systemd-resolved's stub resolv.conf (uid 991 on Ubuntu 24.04) is accepted.
        let mut f = full();
        f.node("etc/resolv.conf").id.uid = 991;
        assert_eq!(rcode(&restore_stage(&mut f, &mut exited(ok_reply()), &stage_args("home"))), 0, "resolv.conf owned by 991");
        // uid 991 on any OTHER system entry is refused, with zero effects.
        for (rel, _, service) in SYSTEM.iter().filter(|e| !e.2) {
            assert!(!service);
            let mut f = full();
            f.node(rel).id.uid = 991;
            let mut r = exited(ok_reply());
            assert_eq!(rcode(&restore_stage(&mut f, &mut r, &stage_args("home"))), 66, "{rel} owned by 991");
            assert!(r.seen.is_none() && f.count("mkdir") == 0, "{rel}: zero effects");
        }
        // resolv.conf owned by a person or an agent, or any entry writable by group or other: refused.
        for (rel, uid, mode) in [("etc/resolv.conf", 1000u32, None), ("etc/resolv.conf", UID, None), ("etc/resolv.conf", 0, Some(0o664u16)), ("etc/resolv.conf", 991, Some(0o646)), ("etc/hosts", 0, Some(0o664)), ("etc/ssl/certs", 0, Some(0o775)), ("etc/ca-certificates", 0, Some(0o757))] {
            let mut f = full();
            f.node(rel).id.uid = uid;
            if let Some(m) = mode {
                let t = f.node(rel).id.mode & crate::tree::S_IFMT;
                f.node(rel).id.mode = t | m;
            }
            let mut r = exited(ok_reply());
            assert_eq!(rcode(&restore_stage(&mut f, &mut r, &stage_args("home"))), 66, "{rel} uid {uid} mode {mode:?}");
            assert!(r.seen.is_none() && f.count("mkdir") == 0, "{rel}: zero effects");
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
        // R3 (A2 r3.5): the class's contents land in data/<leaf>, the launcher's own root 0700 directory; nothing else
        // (no sibling class) is staged.
        let src = format!("{att}/data/{}", leaf(stage_args(class).path));
        // r3.6: beside it, only the binary's digest list.
        let digests = format!("{att}/data/{DIGESTS}");
        let mut want = vec![&digests, &src];
        want.sort();
        assert_eq!(f.nodes.keys().filter(|k| k.starts_with(&format!("{att}/data/"))).collect::<Vec<_>>(), want);
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
        let source: &'static str = Box::leak(format!("data/{}", leaf(stage_args(class).path)).into_boxed_str());
        FillArgs { mount: "/srv/sagebrush", name: name(class), source, expect: Box::leak(expect.into_boxed_str()) }
    }

    #[test]
    fn fill_home_places_the_owned_entries_stripped_and_reports_the_rest() {
        let (mut f, src) = staged("home");
        let x = fill_expect(&mut f, "home");
        let out = fill_home(&mut f, &fill_args("home", x)).unwrap();
        assert_eq!(
            out,
            "{\"placed\":{\"dirs\":1,\"files\":2,\"symlinks\":1},\"refused\":[{\"path\":\"other\",\"uid\":70002,\"gid\":70002,\"entries\":3},{\"path\":\"root.txt\",\"uid\":0,\"gid\":0,\"entries\":1}],\"unexpected\":[{\"path\":\"fifo\",\"type\":\"fifo\"}],\"truncated\":false}\n"
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
        let n = f.count("list") + 2; // in the dry pass, before any effect (the first listing is a precondition's: 66)
        f.errno_at = Some(("list", n, libc::EIO));
        f.log.clear(); // restore-stage's own chmod of data/<leaf> isn't the fill's
        assert_eq!(code(fill_home(&mut f, &fill_args("home", x))), 73);
        assert!(!f.log.iter().any(|l| l.starts_with("rename") || l.starts_with(&format!("chmod {src}"))), "{:?}", f.log);
    }

    #[test]
    fn a_restored_complete_lands_inside_the_class_and_the_fill_consumes_only_the_real_marker() {
        // R4 (A2 r3.5): the marker sits beside data, never inside it; a restored top-level `.complete` is an ordinary
        // entry of data/<leaf>, placed like any other file of the class.
        let (mut f, src) = staged("home");
        let att = attempt_path("home");
        let fake = format!("{src}/.complete");
        f.add(&fake, S_IFREG | 0o600, UID, UID);
        f.node(&fake).proj = UID;
        f.node(&fake).inherit = true;
        assert!(f.nodes.contains_key(&format!("{att}/.complete")), "the real marker, beside data");
        let x = fill_expect(&mut f, "home");
        let out = fill_home(&mut f, &fill_args("home", x)).unwrap();
        assert!(out.contains("\"files\":3"), "{out}");
        assert!(!f.nodes.contains_key(&format!("{att}/.complete")), "the real marker consumed");
        assert!(f.nodes.contains_key(&format!("srv/sagebrush/agents/{A}/home/.complete")), "the restored one placed");
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
        let src = format!("{att}/data/x"); // the launcher's data/<leaf> for srv/sagebrush/tags/x
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
        let out = fill_home(&mut f, &FillArgs { mount: "/srv/sagebrush", name: tn, source: "data/x", expect: Box::leak(x.into_boxed_str()) }).unwrap();
        assert!(out.contains("\"files\":2") && out.contains("\"path\":\"stranger\"") && out.contains("\"path\":\"own-group\""), "{out}");
        assert!(f.nodes.contains_key(&format!("{dest}/m1")) && f.nodes.contains_key(&format!("{dest}/m2")));
        assert!(!f.nodes.contains_key(&format!("{dest}/stranger")));
    }

    // ---- names that aren't UTF-8 (A2 r3.9, A1 r2.5)

    /// `staged`'s class plus names that aren't UTF-8 (the fake keys names encoded: `%FF` is the byte 0xFF), all the
    /// agent's: a file named 0xFF, a directory named 0xE2 0x82 (a truncated sequence) holding a file, and a symlink
    /// named 0xC0 0x80 (an overlong encoding) whose target is `t`. The FIFO is dropped so remove-tree can follow.
    fn staged_odd() -> (Fake, String) {
        let (mut f, src) = staged("home");
        f.nodes.remove(&format!("{src}/fifo"));
        for (rel, mode) in [("%FF", S_IFREG | 0o600), ("%E2%82", S_IFDIR | 0o700), ("%E2%82/in", S_IFREG | 0o600), ("%C0%80", S_IFLNK | 0o777)] {
            let p = format!("{src}/{rel}");
            f.add(&p, mode, UID, UID);
            f.node(&p).proj = UID;
            f.node(&p).inherit = true;
        }
        f.files.insert(format!("{src}/%C0%80"), b"t".to_vec());
        f.node(&format!("{src}/%C0%80")).id.size = 1;
        (f, src)
    }

    #[test]
    fn names_that_are_not_utf8_are_placed_listed_by_the_codec_and_their_attempt_removed() {
        let (mut f, src) = staged_odd();
        let x = fill_expect(&mut f, "home");
        let out = fill_home(&mut f, &fill_args("home", x.clone())).unwrap();
        assert!(out.starts_with("{\"placed\":{\"dirs\":2,\"files\":4,\"symlinks\":2}"), "{out}");
        let dest = format!("srv/sagebrush/agents/{A}/home");
        // Placed under their exact bytes: the fake finds a node only by the encoding of the bytes it is given.
        for l in [format!("mkdir {dest}/%E2%82"), format!("rename {src}/%FF {dest}/%FF"), format!("rename {src}/%E2%82/in {dest}/%E2%82/in"), format!("rename {src}/%C0%80 {dest}/%C0%80")] {
            assert!(f.log.contains(&l), "{l}: {:?}", f.log);
        }
        // tree-digest lists them through §4b's codec, exactly as the expected lines.
        let o: &'static str = Box::leak(owner().into_boxed_str());
        let listing = crate::digest::tree_digest(&mut f, &crate::digest::DigestArgs { mount: "/srv/sagebrush", owner: o, class: "home", expect: Box::leak(x.into_boxed_str()), copy_run: None }).unwrap();
        let empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        for line in [
            "{\"path\":\"%C0%80\",\"type\":\"symlink\",\"size\":1,\"mode\":511,\"target\":\"t\"}".to_string(),
            "{\"path\":\"%E2%82\",\"type\":\"dir\",\"size\":0,\"mode\":448}".to_string(),
            format!("{{\"path\":\"%E2%82/in\",\"type\":\"file\",\"size\":0,\"mode\":384,\"sha256\":\"{empty}\"}}"),
            format!("{{\"path\":\"%FF\",\"type\":\"file\",\"size\":0,\"mode\":384,\"sha256\":\"{empty}\"}}"),
        ] {
            assert!(listing.contains(&format!("\n{line}\n")), "{line}\n{listing}");
        }
        // Sorted by raw bytes: 0xC0 < 0xE2 < 0xFF, all after the ASCII names.
        let at = |p: &str| listing.find(&format!("\"path\":\"{p}\"")).unwrap();
        assert!(at("sub/b.txt") < at("%C0%80") && at("%C0%80") < at("%E2%82") && at("%E2%82/in") < at("%FF"));
        // The consumed attempt, refused entries included, is removed.
        let root = f.root().unwrap();
        let class = f.dir_from_root(&root, &format!("srv/sagebrush/.restore/{RUN}/{}/home", owner())).unwrap();
        let (ax, _) = crate::tree::child(&mut f, &class, "1", MNT).unwrap().unwrap();
        let owners: Vec<String> = std::iter::once(0).chain(70001..70004).map(|u: u32| u.to_string()).collect();
        let ex = expect_file(&mut f, "rm.json", format!("{{\"epoch\":{{\"boot_id\":\"{BOOT}\",\"mnt_id\":{MNT}}},\"fsid\":\"0000abcd00001234\",\"root\":{},\"owners\":[{}]}}", obj_json(&ax), owners.join(",")));
        assert_eq!(code(tree::remove_tree(&mut f, RESTORE, &name("home").path(), &ex)), 0);
        assert!(!f.nodes.contains_key(&attempt_path("home")));
    }

    #[test]
    fn a_refused_entry_counts_itself_and_its_path_is_encoded() {
        let (mut f, src) = staged("home");
        // The raw name `x%` then 0xFF, foreign, holding two files; a raw-name neighbour `x%` 0xFF `y`, the agent's.
        for (rel, mode, uid) in [("x%25%FF", S_IFDIR | 0o700, 70002), ("x%25%FF/p", S_IFREG | 0o600, 70002), ("x%25%FF/q", S_IFREG | 0o600, 70002), ("x%25%FFy", S_IFREG | 0o600, UID), ("empty", S_IFDIR | 0o700, 70002), ("sub/%FEz", S_IFREG | 0o600, 0), ("sub/fifo", 0o010000 | 0o600, UID)] {
            let p = format!("{src}/{rel}");
            f.add(&p, mode, uid, uid);
            f.node(&p).proj = UID;
            f.node(&p).inherit = true;
        }
        let x = fill_expect(&mut f, "home");
        let out = fill_home(&mut f, &fill_args("home", x)).unwrap();
        for want in [
            "{\"path\":\"x%25%FF\",\"uid\":70002,\"gid\":70002,\"entries\":3}",
            "{\"path\":\"empty\",\"uid\":70002,\"gid\":70002,\"entries\":1}",
            "{\"path\":\"root.txt\",\"uid\":0,\"gid\":0,\"entries\":1}",
            "{\"path\":\"other\",\"uid\":70002,\"gid\":70002,\"entries\":3}",
            // Below the class root: the relative path, joined at '/' and encoded.
            "{\"path\":\"sub/%FEz\",\"uid\":0,\"gid\":0,\"entries\":1}",
            "{\"path\":\"sub/fifo\",\"type\":\"fifo\"}",
        ] {
            assert!(out.contains(want), "{want}\n{out}");
        }
        assert!(!out.contains("x%25%FFy"), "the neighbour is placed, not refused: {out}");
        // The codec commutes with joining at '/' (A2 r3.9 §4b): the refused files' encoded paths are the reported path
        // plus '/', and the neighbour's is not, though it shares the encoded prefix.
        let e = crate::digest::encode;
        assert_eq!(e(b"x%\xff/p"), format!("{}/{}", e(b"x%\xff"), e(b"p")));
        assert!(e(b"x%\xff/q").starts_with("x%25%FF/") && !e(b"x%\xffy").starts_with("x%25%FF/") && e(b"x%\xffy").starts_with("x%25%FF"));
        for (a, b) in [(&b"\xe2\x82"[..], &b"in"[..]), (b"\xc3", b"\xa9"), (b"a\xf0\x9f", b"\x98\x80z"), (b"%", b"%25")] {
            let mut j = a.to_vec();
            j.push(b'/');
            j.extend_from_slice(b);
            assert_eq!(e(&j), format!("{}/{}", e(a), e(b)), "{a:?} / {b:?}");
        }
    }

    #[test]
    fn a_staged_path_over_4096_raw_bytes_is_73_in_the_dry_pass_and_4096_is_placed() {
        for (last, want) in [(254usize, 0), (255, 73)] {
            let (mut f, src) = staged("home");
            // 15 directories of 255 bytes and one of `last`, each beneath the previous, then a file `x`: the file's
            // relative path is 15 * 255 + last + 16 separators and `x`: 4096 bytes with last = 254, 4097 with 255.
            let mut p = src.clone();
            let mut len = 0usize;
            for i in 0..16 {
                let n = if i == 15 { "d".repeat(last) } else { "d".repeat(255) };
                p = format!("{p}/{n}");
                len += n.len() + usize::from(i > 0);
                f.add(&p, S_IFDIR | 0o700, UID, UID);
                f.node(&p).proj = UID;
                f.node(&p).inherit = true;
            }
            f.add(&format!("{p}/x"), S_IFREG | 0o600, UID, UID);
            f.node(&format!("{p}/x")).proj = UID;
            assert_eq!(len + 2, if last == 254 { 4096 } else { 4097 });
            let x = fill_expect(&mut f, "home");
            let r = fill_home(&mut f, &fill_args("home", x));
            assert_eq!(code(r), want, "last {last}");
            if want != 0 {
                assert!(!f.log.iter().any(|l| l.starts_with(&format!("mkdir srv/sagebrush/agents/{A}")) || l.starts_with("rename ")), "zero effects");
            }
        }
    }

    #[test]
    fn the_report_lists_exactly_1000_and_truncates_at_1001() {
        for (n, truncated) in [(999usize, false), (1000, true)] {
            // root.txt is already one refused entry: n more makes 1000 or 1001.
            let (mut f, src) = staged("home");
            f.nodes.remove(&format!("{src}/other"));
            f.nodes.retain(|k, _| !k.starts_with(&format!("{src}/other/")));
            for i in 0..n {
                f.add(&format!("{src}/r{i:04}"), S_IFREG | 0o600, 0, 0);
            }
            let x = fill_expect(&mut f, "home");
            let out = fill_home(&mut f, &fill_args("home", x)).unwrap();
            assert_eq!(out.matches("\"entries\":").count(), 1000, "{n}");
            assert!(out.ends_with(&format!("\"truncated\":{truncated}}}\n")), "{n}: {}", &out[out.len() - 40..]);
        }
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
        f.nodes.remove(&format!("{att}/data/home/fifo"));
        assert_eq!(code(tree::remove_tree(&mut f, RESTORE, &name("home").path(), &ex)), 0);
        assert!(!f.nodes.contains_key(&att) && f.nodes.contains_key(&format!("srv/sagebrush/.restore/{RUN}/{}/home", owner())));
        // Already gone, and a missing staging parent: success after syncing the deepest existing parent.
        assert_eq!(code(tree::remove_tree(&mut f, RESTORE, &name("home").path(), &ex)), 0);
        let gone = Name::parse(RUN, &owner(), "sessions", "1").unwrap().path();
        assert_eq!(code(tree::remove_tree(&mut f, RESTORE, &gone, &ex)), 0);
        // A staging parent that isn't root:root 0700 refuses, with everything else removable (owners, no FIFO).
        for (uid, mode) in [(0u32, 0o755u16), (5, 0o700)] {
            let (mut f, _) = staged("home");
            f.nodes.remove(&format!("{att}/data/home/fifo"));
            let run = format!("srv/sagebrush/.restore/{RUN}");
            f.node(&run).id.mode = S_IFDIR | mode;
            f.node(&run).id.uid = uid;
            let ex = expect_file(&mut f, "rm.json", format!("{{\"epoch\":{{\"boot_id\":\"{BOOT}\",\"mnt_id\":{MNT}}},\"fsid\":\"0000abcd00001234\",\"root\":{},\"owners\":[{}]}}", obj_json(&x), owners.join(",")));
            assert_eq!(code(tree::remove_tree(&mut f, RESTORE, &name("home").path(), &ex)), 73, "{uid} {mode:o}");
            assert!(f.nodes.contains_key(&att), "nothing removed");
        }
    }
}
