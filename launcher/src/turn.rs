//! `turn` (launcher contract amendment A5 r4.6, profiles piece 3): one turn with ONE profile. Steps 2–7 here (the
//! unit, the namespaces, the profile's and its mountpoints' identity on trusted handles, the idmapped profile mount and
//! the session binds), generic over `TurnOps` and tested against the fake; part 3b adds the real operations, the
//! confinement (steps 8–12, §3's filter) and the entry point.
//!
//! - The argv carries only the opaque turn id; everything else comes from the root-only turn file (§1, AUDIT H2).
//! - Two roots, in this order (r4.5, r4.6). Through the HOST root: step 2 (the unit by pidfd: its cgroup, all four
//!   uids and gids, its groups, alive); step 4 (the profile directory on its trusted handle); step 5 (each recorded
//!   mountpoint, all before anything is mounted); step 6's detached profile clone, its user namespace (the map line
//!   `<storage_uid> <agent_uid> 1`, r4.4) and the idmap; step 7's store checks and detached clones. Then step 3 (join
//!   the unit's namespaces, a private copy) and the TURN root. Through the turn root only: step 6's fixed mountpoint
//!   and the move; step 7's re-reads and binds. After step 3 nothing is looked up through a host handle.
//! - A refusal at step 4, 5 or 7 is 73 (66 for a missing store or a failed operation); every other is 66.

// Part 3a: nothing outside the tests calls this until part 3b adds the real operations and the entry point.
#![allow(dead_code)]

use crate::args::is_id;
use crate::err::{err, Error, Fail, Result};
use crate::json::{self, Value};
use crate::profile::{ProfileOps, MAX_SUBPATHS, PROFILES};
use crate::tree::{anchor_policy, child as tchild, identity, kind_of, open_err, pre, At, Kind, Obj};
use crate::{sys, tree};
use std::io;
use std::os::fd::OwnedFd;

/// The staged profile's fixed path in the turn's view (r2.1 §7.1; advisor §5).
pub const STAGED: &str = "/run/sagebrush/claude-profile";
/// The turn file's directory, `<TURNS>/<turn>/turn.json`.
pub const TURNS: &str = "/run/sagebrush/turns";
const MAX_TURN_FILE: usize = 8192;
const MAX_ARGS: usize = 64;
const MAX_GIDS: usize = 64;

/// The harnesses `turn` knows, each with its sessions subtree name (v1: claude only).
const HARNESSES: [&str; 1] = ["claude"];

/// The validated turn file (A5 §1, r4.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TurnFile {
    pub turn: String,
    pub op: String,
    pub agent: String,
    pub agent_uid: u32,
    pub gids: Vec<u32>,
    pub unit_pid: u32,
    pub harness: String,
    pub profile: String,
    pub storage_uid: u32,
    pub projid: u32,
    pub mountpoints: Vec<(String, u64, u32)>,
    pub cli: String,
    pub args: Vec<String>,
}

fn contract() -> Error {
    err(Fail::Contract, "the turn file isn't the closed shape")
}

fn hex32(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn segment_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= 255 && s != "." && s != ".." && !s.contains('/') && !s.contains('\0')
}

fn in_range(v: &Value, lo: u64, hi: u64) -> Result<u32> {
    let n = v.int().ok_or_else(contract)?;
    if n < lo || n > hi {
        return Err(contract());
    }
    u32::try_from(n).map_err(|_| contract())
}

/// Parse and check the turn file's closed shape. Anything else is 65 (`contract`).
pub fn parse_turn_file(raw: &[u8], turn: &str) -> Result<TurnFile> {
    let v = json::parse(raw).ok_or_else(contract)?;
    let f = v
        .exact(&["v", "turn", "op", "agent", "agent_uid", "gids", "unit_pid", "harness", "profile", "storage_uid", "projid", "mountpoints", "cli", "args"])
        .ok_or_else(contract)?;
    if f[0].int() != Some(1) {
        return Err(contract());
    }
    let t = f[1].str().filter(|s| hex32(s) && *s == turn).ok_or_else(contract)?;
    let op = f[2].str().filter(|s| hex32(s)).ok_or_else(contract)?;
    let agent = f[3].str().filter(|s| is_id(s)).ok_or_else(contract)?;
    let agent_uid = in_range(f[4], 70000, 79999)?;
    let gl = f[5].arr().filter(|a| a.len() <= MAX_GIDS).ok_or_else(contract)?;
    let gids = gl.iter().map(|g| in_range(g, 80000, 89999)).collect::<Result<Vec<u32>>>()?;
    if gids.windows(2).any(|w| w[0] >= w[1]) {
        return Err(contract()); // sorted and unique
    }
    let unit_pid = in_range(f[6], 2, 4_194_304)?;
    let harness = f[7].str().filter(|s| HARNESSES.contains(s)).ok_or_else(contract)?;
    let profile = f[8].str().filter(|s| is_id(s)).ok_or_else(contract)?;
    let storage_uid = in_range(f[9], 90000, 99999)?;
    let projid = in_range(f[10], 100000, 109999)?;
    let ml = f[11].arr().filter(|a| a.len() <= MAX_SUBPATHS).ok_or_else(contract)?;
    let mut mountpoints = Vec::with_capacity(ml.len());
    for m in ml {
        let g = m.exact(&["name", "ino", "gen"]).ok_or_else(contract)?;
        let name = g[0].str().filter(|s| segment_ok(s)).ok_or_else(contract)?;
        if mountpoints.iter().any(|(n, _, _): &(String, u64, u32)| n == name) {
            return Err(contract());
        }
        let ino = g[1].int().filter(|i| *i > 0).ok_or_else(contract)?;
        let gen = g[2].int().and_then(|n| u32::try_from(n).ok()).ok_or_else(contract)?;
        mountpoints.push((name.to_string(), ino, gen));
    }
    let cli = f[12].str().filter(|s| crate::args::rel(s).is_some()).ok_or_else(contract)?;
    let al = f[13].arr().filter(|a| a.len() <= MAX_ARGS).ok_or_else(contract)?;
    let args = al.iter().map(|a| a.str().filter(|s| s.len() <= 4096 && !s.contains('\0')).map(str::to_string).ok_or_else(contract)).collect::<Result<Vec<String>>>()?;
    Ok(TurnFile {
        turn: t.to_string(),
        op: op.to_string(),
        agent: agent.to_string(),
        agent_uid,
        gids,
        unit_pid,
        harness: harness.to_string(),
        profile: profile.to_string(),
        storage_uid,
        projid,
        mountpoints,
        cli: cli.to_string(),
        args,
    })
}

/// One `uid_map`/`gid_map` line (A5 r4.4): `<inside> <outside> <count>`, where an idmapped mount matches a file's
/// ON-DISK id against the inside column and shows the outside one. So `<on_disk> <seen_as> 1`.
pub fn map_line(seen_as: u32, on_disk: u32) -> String {
    format!("{on_disk} {seen_as} 1\n")
}

/// The operations `turn`'s steps 2–7 add to A4's.
pub trait TurnOps: ProfileOps {
    /// A process handle (a pidfd).
    type P;
    fn pidfd(&mut self, pid: u32) -> io::Result<Self::P>;
    /// Still the same, live process (`pidfd_send_signal(pidfd, 0)`).
    fn alive(&mut self, p: &Self::P) -> io::Result<bool>;
    /// `setns(pidfd, CLONE_NEWNET | CLONE_NEWNS)`.
    fn join_ns(&mut self, p: &Self::P) -> io::Result<()>;
    /// `unshare(CLONE_NEWNS)`, then private propagation for the whole view.
    fn unshare_private(&mut self) -> io::Result<()>;
    /// Read a root-only file by its handle, at most `max` bytes.
    fn read_handle(&mut self, h: &Self::H, max: usize) -> io::Result<Vec<u8>>;
    /// `open_tree(h, "", OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC | AT_EMPTY_PATH)`.
    fn clone_tree(&mut self, h: &Self::H) -> io::Result<Self::H>;
    /// The turn's own root, `/` opened `O_PATH | O_DIRECTORY` after step 3 (A5 r4.5): the only handle later lookups use.
    fn turn_root(&mut self) -> io::Result<Self::H>;
    /// A user-namespace handle whose `uid_map` and `gid_map` are each exactly `map_line(seen_as, on_disk)` (A5 r4.4):
    /// an idmapped mount shows a file owned by `on_disk` as `seen_as`. Made by a child, through the HOST root and the
    /// child's pidfd, before step 3 (r4.6); the child is reaped before this returns.
    fn userns(&mut self, host: &Self::H, seen_as: u32, on_disk: u32) -> io::Result<Self::H>;
    /// `mount_setattr(clone, "", AT_EMPTY_PATH, { MOUNT_ATTR_IDMAP, userns })`.
    fn idmap(&mut self, clone: &Self::H, userns: &Self::H) -> io::Result<()>;
    /// `move_mount(clone, "", target, "", MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH)`.
    fn move_onto(&mut self, clone: &Self::H, target: &Self::H) -> io::Result<()>;
    /// An `O_PATH` open beneath `dir` WITHOUT `RESOLVE_NO_XDEV` (still no symlinks or magic links): only for re-reading
    /// a mount this turn itself just made.
    fn at_mounted(&mut self, dir: &Self::H, name: &str) -> io::Result<Self::H>;
}

/// What steps 2–7 leave: the staged profile's handle (for step 8's Landlock rule).
#[derive(Debug)]
/// What steps 2–7 leave: handles in the turn's namespace only (A5 r4.6). Every host handle, the host root's
/// included, is closed when `stage` returns.
pub struct Staged<H> {
    pub profile: H,
    pub root: H,
}

fn ns(msg: &'static str) -> Error {
    pre(msg)
}

/// The agent unit's cgroup, as `/proc/<pid>/cgroup` writes it (cgroup v2: one line, `0::<path>`).
pub fn unit_cgroup(agent: &str) -> String {
    format!("0::/sagebrush.slice/sagebrush-agents.slice/sagebrush-agents-{agent}.slice/sagebrush-agent-{agent}.service\n")
}

/// One `/proc/<pid>/status` line's numbers (exactly one line starting with the key and its colon, e.g. `Uid:` or
/// `Groups:`); a line with the bare key and no colon is no such line.
fn status_numbers(status: &[u8], key: &str) -> Option<Vec<u32>> {
    let text = std::str::from_utf8(status).ok()?;
    let mut lines = text.lines().filter_map(|l| l.strip_prefix(key));
    let rest = lines.next()?;
    if lines.next().is_some() {
        return None;
    }
    rest.split_whitespace().map(|x| x.parse().ok()).collect()
}

/// The unit's identity as A5 r4.3 requires it: all four uids and all four gids `agent_uid` (gid = uid for every
/// agent's private group), and its supplementary groups, as a set, exactly the turn file's `gids`.
fn unit_identity_ok(status: &[u8], tf: &TurnFile) -> bool {
    let four = |key| status_numbers(status, key).is_some_and(|v| v.len() == 4 && v.iter().all(|x| *x == tf.agent_uid));
    let groups = status_numbers(status, "Groups:").map(|mut g| {
        g.sort_unstable();
        g.dedup();
        g
    });
    four("Uid:") && four("Gid:") && groups.as_deref() == Some(&tf.gids[..])
}

/// Read the turn file: `<TURNS>/<turn>/turn.json`, the directory root 0700, the file a regular root file of exactly
/// 0600 (no special bits) and one link, read through its own handle (A1's expect rules). Then its closed shape.
pub fn read_turn_file<O: TurnOps>(o: &mut O, root: &O::H, turn: &str) -> Result<TurnFile> {
    if !hex32(turn) {
        return Err(err(Fail::Usage, "bad arguments"));
    }
    let dir = o.dir_from_root(root, &format!("{}/{turn}", &TURNS[1..])).map_err(|_| contract())?;
    let di = o.ident(&dir).map_err(|_| contract())?;
    if kind_of(&di) != Some(Kind::Dir) || di.uid != 0 || di.gid != 0 || di.mode & 0o7777 != 0o700 {
        return Err(contract());
    }
    let h = o.at(&dir, "turn.json", At::File).map_err(|_| contract())?;
    let fi = o.ident(&h).map_err(|_| contract())?;
    if kind_of(&fi) != Some(Kind::File) || fi.uid != 0 || fi.gid != 0 || fi.mode & 0o7777 != 0o600 || fi.nlink != 1 {
        return Err(contract());
    }
    let raw = o.read_handle(&h, MAX_TURN_FILE).map_err(|_| contract())?;
    parse_turn_file(&raw, turn)
}

/// Steps 2–7 (A5 r4.6 §2), in their execution order: through the HOST root, steps 2, 4, 5, step 6's profile clone,
/// user namespace and idmap, and step 7's store checks and clones; then step 3 (the switch) and the TURN root; then
/// step 6's target and move and step 7's re-reads and binds, through the turn root only. After step 3 nothing is looked
/// up through a host handle: the detached clones are used only as move sources, and step 5's identities only as
/// recorded values. `step` is the step running, for the failure record (§1). Every refusal is returned before any later
/// operation runs.
pub fn stage<O: TurnOps>(o: &mut O, host: O::H, tf: &TurnFile, step: &mut u8) -> Result<Staged<O::H>> {
    let root = &host;
    // 2. The unit, by pidfd: its cgroup, its uids, and still alive after both reads.
    *step = 2;
    let p = o.pidfd(tf.unit_pid).map_err(|_| ns("the unit's process can't be opened"))?;
    let cg = o.read(root, &format!("proc/{}/cgroup", tf.unit_pid), 4096).map_err(|_| ns("the unit's cgroup can't be read"))?;
    if cg != unit_cgroup(&tf.agent).as_bytes() {
        return Err(ns("the process isn't the agent's unit"));
    }
    let st = o.read(root, &format!("proc/{}/status", tf.unit_pid), 16384).map_err(|_| ns("the unit's status can't be read"))?;
    if !unit_identity_ok(&st, tf) {
        return Err(ns("the unit's process isn't the agent's uid, gid or groups"));
    }
    if !o.alive(&p).map_err(|_| ns("the unit's process can't be checked"))? {
        return Err(ns("the unit's process is gone"));
    }

    // 4. The profile directory on its trusted handle.
    *step = 4;
    let host_mnt = o.ident(root).map_err(open_err)?.mnt_id;
    let pa = anchor_policy(o, root, PROFILES)?;
    let pmnt = o.ident(&pa).map_err(open_err)?.mnt_id;
    let (px, ph) = tchild(o, &pa, &tf.profile, pmnt)?.ok_or(identity("the profile directory is missing"))?;
    let ph = ph.ok_or(identity("the profile isn't a directory"))?;
    let pi = o.ident(&ph).map_err(open_err)?;
    if px.kind != Kind::Dir
        || px.uid != tf.storage_uid
        || px.gid != tf.storage_uid
        || px.mode != 0o700
        || px.projid != Some(tf.projid)
        || px.inherit != Some(true)
        || pi.attributes & libc::STATX_ATTR_MOUNT_ROOT as u64 != 0
        || (pi.dev, pi.ino) != (px.dev, px.ino)
    {
        return Err(identity("the profile directory isn't the recorded one"));
    }

    // 5. Every mountpoint, checked before anything is mounted; kept as recorded identities.
    *step = 5;
    let mut mps: Vec<(String, Obj)> = Vec::with_capacity(tf.mountpoints.len());
    for (name, ino, gen) in &tf.mountpoints {
        let (x, h) = tchild(o, &ph, name, pmnt)?.ok_or(identity("a mountpoint is missing"))?;
        let h = h.ok_or(identity("a mountpoint isn't a directory"))?;
        if x.kind != Kind::Dir || x.ino != *ino || x.gen != Some(*gen) || x.uid != 0 || x.gid != 0 || x.mode != 0o555 {
            return Err(identity("a mountpoint isn't the recorded one"));
        }
        if !o.immutable(&h).map_err(|_| identity("a mountpoint's flags can't be read"))? {
            return Err(identity("a mountpoint isn't immutable"));
        }
        if !o.batch(&h).map_err(open_err)?.is_empty() {
            return Err(identity("a mountpoint isn't empty"));
        }
        mps.push((name.clone(), x));
    }

    // 6, before the switch: the profile's detached clone, the user namespace, the idmap.
    *step = 6;
    let clone = o.clone_tree(&ph).map_err(|_| ns("the profile can't be cloned"))?;
    let userns = o.userns(root, tf.agent_uid, tf.storage_uid).map_err(|_| ns("the user namespace can't be made"))?;
    o.idmap(&clone, &userns).map_err(|_| ns("the idmap can't be set"))?;
    drop(userns);
    drop(ph);
    drop(pa);

    // 7, before the switch: each store, checked and cloned (detached).
    *step = 7;
    let mut stores: Vec<(String, Obj, Obj, O::H)> = Vec::with_capacity(mps.len());
    if !mps.is_empty() {
        let aa = anchor_policy(o, root, "/srv/sagebrush/agents")?;
        let amnt = o.ident(&aa).map_err(open_err)?.mnt_id;
        let mut cur = tchild(o, &aa, &tf.agent, amnt)?.and_then(|(_, h)| h).ok_or(ns("the agent directory is missing"))?;
        for part in ["sessions", tf.harness.as_str()] {
            cur = tchild(o, &cur, part, amnt)?.and_then(|(_, h)| h).ok_or(ns("the session store is missing"))?;
        }
        for (name, x) in mps {
            let (sx, sh) = tchild(o, &cur, &name, amnt)?.ok_or(ns("a session store directory is missing"))?;
            let sh = sh.ok_or(identity("a session store entry isn't a directory"))?;
            if sx.uid != tf.agent_uid || sx.gid != tf.agent_uid || sx.mode != 0o700 || sx.projid != Some(tf.agent_uid) || sx.inherit != Some(true) {
                return Err(identity("a session store directory isn't the agent's"));
            }
            let sclone = o.clone_tree(&sh).map_err(|_| ns("a session store can't be cloned"))?;
            stores.push((name, x, sx, sclone));
        }
    }

    // 3. The switch: the unit's namespaces, a private copy, and the turn's own root.
    *step = 3;
    o.join_ns(&p).map_err(|_| ns("the unit's namespaces can't be joined"))?;
    drop(p);
    drop(host); // From here on, no lookup goes through a host handle (r4.6).
    o.unshare_private().map_err(|_| ns("a private mount namespace can't be made"))?;
    let turn = o.turn_root().map_err(|_| ns("the turn's root can't be opened"))?;
    let tr = o.ident(&turn).map_err(open_err)?;
    if kind_of(&tr) != Some(Kind::Dir) || tr.mnt_id == host_mnt {
        return Err(ns("the turn's root isn't a private copy"));
    }

    // 6. The fixed, empty, root 0700 mountpoint in the turn's view; the idmapped profile moved onto it.
    *step = 6;
    let target_rel = &STAGED[1..];
    let (tparent_rel, tname) = target_rel.rsplit_once('/').unwrap_or(("", target_rel));
    let tparent = o.dir_from_root(&turn, tparent_rel).map_err(|_| ns("the staging mountpoint's parent is missing"))?;
    let tpi = o.ident(&tparent).map_err(open_err)?;
    let target = o.at(&tparent, tname, At::Dir).map_err(|_| ns("the staging mountpoint is missing"))?;
    let ti = o.ident(&target).map_err(open_err)?;
    if kind_of(&ti) != Some(Kind::Dir) || ti.uid != 0 || ti.gid != 0 || ti.mode & 0o7777 != 0o700 || ti.attributes & libc::STATX_ATTR_MOUNT_ROOT as u64 != 0 || ti.mnt_id != tpi.mnt_id {
        return Err(ns("the staging mountpoint isn't a fresh root 0700 directory"));
    }
    if !o.batch(&target).map_err(open_err)?.is_empty() {
        return Err(ns("the staging mountpoint isn't empty"));
    }
    o.move_onto(&clone, &target).map_err(|_| ns("the profile can't be mounted"))?;
    drop(clone);

    // 7. The staged profile re-read: the same object, the agent's through the idmap, on a new mount.
    *step = 7;
    let staged = o.at_mounted(&tparent, tname).map_err(|_| identity("the staged profile can't be opened"))?;
    let si = o.ident(&staged).map_err(open_err)?;
    if (si.dev, si.ino) != (px.dev, px.ino) || kind_of(&si) != Some(Kind::Dir) || si.mode & 0o7777 != 0o700 || si.uid != tf.agent_uid || si.gid != tf.agent_uid || si.mnt_id == tpi.mnt_id {
        return Err(identity("the staged profile isn't the checked one"));
    }
    // The session binds: each staged mountpoint matched to step 5's identity, the store's clone moved over it, re-read.
    for (name, x, sx, sclone) in stores {
        let at = o.at(&staged, &name, At::Path).map_err(|_| identity("a staged mountpoint can't be opened"))?;
        let ai = o.ident(&at).map_err(open_err)?;
        if (ai.dev, ai.ino) != (x.dev, x.ino) {
            return Err(identity("a staged mountpoint isn't the checked one"));
        }
        o.move_onto(&sclone, &at).map_err(|_| ns("a session store can't be bound"))?;
        let back = o.at_mounted(&staged, &name).map_err(|_| identity("a session bind can't be re-read"))?;
        let bi = o.ident(&back).map_err(open_err)?;
        if (bi.dev, bi.ino) != (sx.dev, sx.ino) || bi.mnt_id == si.mnt_id {
            return Err(identity("a session bind isn't the agent's store"));
        }
    }
    Ok(Staged { profile: staged, root: turn })
}

// ---- the real operations (A5 r4.6)

/// The user-namespace child (step 6): it unshares a user namespace, says so with one byte, and waits. Dropping this
/// closes its go pipe (it exits) and reaps it, on every path, so no child outlives `userns`.
struct NsChild {
    pid: libc::pid_t,
    go: Option<OwnedFd>,
}

impl Drop for NsChild {
    fn drop(&mut self) {
        drop(self.go.take());
        loop {
            match sys::waitpid(self.pid, 0) {
                Err(e) if e.raw_os_error() == Some(libc::EINTR) => continue,
                _ => break,
            }
        }
    }
}

/// Write `data` to `name` beneath the child's /proc directory in ONE write (the kernel takes a map whole).
fn write_proc(dir: &OwnedFd, name: &std::ffi::CStr, data: &[u8]) -> io::Result<()> {
    let f = sys::openat2(dir, name, libc::O_WRONLY, 0)?;
    if sys::write(&f, data)? != data.len() {
        return Err(io::Error::from_raw_os_error(libc::EIO));
    }
    Ok(())
}

/// The namespace entry `name` beneath an opened `/proc/<pid>/ns`, required to be a USER namespace (EINVAL otherwise).
fn user_ns_entry(nsdir: &OwnedFd, name: &std::ffi::CStr) -> io::Result<OwnedFd> {
    let ns = sys::open_ns_entry(nsdir, name)?;
    if sys::ns_type(&ns)? != libc::CLONE_NEWUSER {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    Ok(ns)
}

fn make_userns(host: &OwnedFd, seen_as: u32, on_disk: u32) -> io::Result<OwnedFd> {
    let (ready_r, ready_w) = sys::pipe()?;
    let (go_r, go_w) = sys::pipe()?;
    let pid = sys::fork()?;
    if pid == 0 {
        // The child: raw syscalls only, then _exit; it never returns into the launcher.
        drop(ready_r);
        drop(go_w);
        let ok = sys::unshare_user().is_ok();
        if ok {
            let _ = sys::write(&ready_w, b"U");
        }
        drop(ready_w); // on a failure the parent reads EOF, never waits on a child that waits on it
        let mut b = [0u8; 1];
        let _ = sys::read(&go_r, &mut b); // until the parent closes the go pipe
        sys::exit_now(if ok { 0 } else { 1 });
    }
    drop(ready_w);
    drop(go_r);
    let child = NsChild { pid, go: Some(go_w) };
    let pidfd = sys::pidfd_open(child.pid)?;
    let mut b = [0u8; 1];
    if sys::read(&ready_r, &mut b)? != 1 || b[0] != b'U' {
        return Err(io::Error::from_raw_os_error(libc::EPERM)); // the child couldn't make its namespace
    }
    // Every path through the HOST root, before the switch (r4.6); the child is unreaped, so its pid is its own.
    let dir = sys::openat2(host, &tree::c(&format!("proc/{}", child.pid))?, libc::O_PATH | libc::O_DIRECTORY, 0)?;
    write_proc(&dir, c"setgroups", b"deny")?;
    let line = map_line(seen_as, on_disk);
    write_proc(&dir, c"uid_map", line.as_bytes())?;
    write_proc(&dir, c"gid_map", line.as_bytes())?;
    let nsdir = sys::openat2(&dir, c"ns", libc::O_PATH | libc::O_DIRECTORY, 0)?;
    let ns = user_ns_entry(&nsdir, c"user")?;
    sys::pidfd_alive(&pidfd)?; // still our child after the opens
    drop(child); // reaped
    Ok(ns)
}

impl TurnOps for tree::RealOps {
    type P = OwnedFd;
    fn pidfd(&mut self, pid: u32) -> io::Result<OwnedFd> {
        sys::pidfd_open(pid as libc::pid_t)
    }
    fn alive(&mut self, p: &OwnedFd) -> io::Result<bool> {
        match sys::pidfd_alive(p) {
            Ok(()) => Ok(true),
            Err(e) if e.raw_os_error() == Some(libc::ESRCH) => Ok(false),
            Err(e) => Err(e),
        }
    }
    fn join_ns(&mut self, p: &OwnedFd) -> io::Result<()> {
        sys::setns(p, libc::CLONE_NEWNET | libc::CLONE_NEWNS)
    }
    fn unshare_private(&mut self) -> io::Result<()> {
        sys::unshare_mount_ns()?;
        sys::make_root_private()
    }
    fn turn_root(&mut self) -> io::Result<OwnedFd> {
        sys::open_root()
    }
    fn read_handle(&mut self, h: &OwnedFd, max: usize) -> io::Result<Vec<u8>> {
        let mut out = vec![0u8; max + 1];
        let mut n = 0;
        loop {
            let k = sys::pread(h, &mut out[n..], n as u64)?;
            if k == 0 {
                break;
            }
            n += k;
            if n > max {
                return Err(io::Error::from_raw_os_error(libc::EFBIG));
            }
        }
        out.truncate(n);
        Ok(out)
    }
    fn clone_tree(&mut self, h: &OwnedFd) -> io::Result<OwnedFd> {
        sys::open_tree_clone(h)
    }
    fn userns(&mut self, host: &OwnedFd, seen_as: u32, on_disk: u32) -> io::Result<OwnedFd> {
        make_userns(host, seen_as, on_disk)
    }
    fn idmap(&mut self, clone: &OwnedFd, userns: &OwnedFd) -> io::Result<()> {
        sys::mount_setattr_idmap(clone, userns)
    }
    fn move_onto(&mut self, clone: &OwnedFd, target: &OwnedFd) -> io::Result<()> {
        sys::move_mount(clone, target)
    }
    fn at_mounted(&mut self, dir: &OwnedFd, name: &str) -> io::Result<OwnedFd> {
        // Only for the re-reads of a mount this turn just made, and only ONE validated component (SEC on part 3a): never
        // general path resolution. BENEATH | NO_SYMLINKS | NO_MAGICLINKS still hold; only NO_XDEV is absent.
        if !segment_ok(name) {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        sys::openat2(dir, &tree::c(name)?, libc::O_PATH, 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::tests::{code, e, join, Fake, FH, A, MNT};
    use crate::tree::{Ops, S_IFDIR, S_IFREG};

    const TURN: &str = "0123456789abcdef0123456789abcdef";
    const OP: &str = "fedcba9876543210fedcba9876543210";
    const PID: &str = "bcdefghijklmnopqrstuvwxyza";
    const AUID: u32 = 70001;
    const SUID: u32 = 90003;
    const PROJ: u32 = 100003;
    const UNIT: u32 = 4242;

    impl TurnOps for Fake {
        type P = u32;
        fn pidfd(&mut self, pid: u32) -> io::Result<u32> {
            self.tick("pidfd")?;
            if self.files.contains_key(&format!("proc/{pid}/cgroup")) { Ok(pid) } else { Err(e(libc::ESRCH)) }
        }
        fn alive(&mut self, p: &u32) -> io::Result<bool> {
            self.tick("alive")?;
            Ok(!self.files.contains_key(&format!("proc/{p}/dead")))
        }
        fn join_ns(&mut self, p: &u32) -> io::Result<()> {
            self.tick("join_ns")?;
            self.log.push(format!("setns {p}"));
            self.joined = true; // the switch: host handles are sealed from here on
            Ok(())
        }
        fn unshare_private(&mut self) -> io::Result<()> {
            self.tick("unshare")?;
            self.log.push("unshare".into());
            Ok(())
        }
        fn turn_root(&mut self) -> io::Result<FH> {
            self.tick("turn_root")?;
            let mut h = self.handle(String::new());
            h.turn = true;
            Ok(h)
        }
        fn read_handle(&mut self, h: &FH, max: usize) -> io::Result<Vec<u8>> {
            self.sealed("read", h)?;
            self.log.push(format!("read {}", h.p));
            let b = self.files.get(&h.p).cloned().ok_or(e(libc::ENOENT))?;
            if b.len() > max { Err(e(libc::EFBIG)) } else { Ok(b) }
        }
        fn clone_tree(&mut self, h: &FH) -> io::Result<FH> {
            self.tick("clone")?;
            self.sealed("clone", h)?;
            self.log.push(format!("clone {}", h.p));
            Ok(self.handle(h.p.clone()))
        }
        fn userns(&mut self, host: &FH, seen_as: u32, on_disk: u32) -> io::Result<FH> {
            // The child's /proc lookups go through the host root: sealed after the switch, like any other lookup.
            self.tick("userns")?;
            self.sealed("proc", host)?;
            self.log.push(format!("userns {seen_as} {on_disk}"));
            Ok(self.handle(format!("userns:{seen_as}:{on_disk}")))
        }
        fn idmap(&mut self, clone: &FH, userns: &FH) -> io::Result<()> {
            self.tick("idmap")?;
            self.log.push(format!("idmap {} {}", clone.p, userns.p));
            self.files.insert(format!("idmap:{}", clone.p), userns.p.clone().into_bytes());
            Ok(())
        }
        fn move_onto(&mut self, clone: &FH, target: &FH) -> io::Result<()> {
            self.tick("move")?;
            // A move's target must be in the caller's namespace (move_mount); the detached source may be a host clone.
            if !target.turn {
                self.log.push(format!("NOT-TURN-TARGET {}", target.p));
                return Err(e(libc::EINVAL));
            }
            self.log.push(format!("mount {} {}", clone.p, target.p));
            // The clone's tree appears at the target, on a new mount; an idmap maps the outside uid to the inside one
            // and every other owner to the overflow uid.
            let map = self.files.get(&format!("idmap:{}", clone.p)).map(|b| {
                let s = String::from_utf8(b.clone()).unwrap();
                let v: Vec<u32> = s.split(':').skip(1).map(|x| x.parse().unwrap()).collect();
                (v[0], v[1])
            });
            self.next_ino += 1;
            let mnt = 1000 + self.next_ino;
            let src: Vec<(String, crate::tree::tests::Node)> = self
                .nodes
                .iter()
                .filter(|(k, _)| **k == clone.p || k.starts_with(&format!("{}/", clone.p)))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            self.nodes.retain(|k, _| !(*k == target.p || k.starts_with(&format!("{}/", target.p))));
            for (k, mut n) in src {
                let p = format!("{}{}", target.p, &k[clone.p.len()..]);
                if let Some((inside, outside)) = map {
                    n.id.uid = if n.id.uid == outside { inside } else { 65534 };
                    n.id.gid = if n.id.gid == outside { inside } else { 65534 };
                }
                n.id.mnt_id = mnt;
                self.nodes.insert(p, n);
            }
            Ok(())
        }
        fn at_mounted(&mut self, dir: &FH, name: &str) -> io::Result<FH> {
            self.tick("at_mounted")?;
            self.sealed("at_mounted", dir)?;
            let p = join(&dir.p, name);
            if !self.nodes.contains_key(&p) {
                return Err(e(libc::ENOENT));
            }
            Ok(self.handle_in(p, dir))
        }
    }

    fn status(uids: &[u32], gids: &[u32], groups: &str) -> Vec<u8> {
        let j = |v: &[u32]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>().join("\t");
        format!("Name:\tx\nUid:\t{}\nGid:\t{}\nGroups:\t{groups} \n", j(uids), j(gids)).into_bytes()
    }

    fn pdir() -> String {
        format!("srv/sagebrush/claude-profiles/{PID}")
    }

    /// A host with the agent's unit running, a bound profile with two mountpoints, and the agent's session store.
    fn host(mps: &[&str]) -> (Fake, TurnFile) {
        let mut f = Fake::new();
        for d in ["run", "run/sagebrush", "run/sagebrush/turns"] {
            if !f.nodes.contains_key(d) {
                f.dir(d, 0, 0o755);
            }
        }
        f.dir("run/sagebrush/claude-profile", 0, 0o700);
        f.files.insert(format!("proc/{UNIT}/cgroup"), unit_cgroup(A).into_bytes());
        f.files.insert(format!("proc/{UNIT}/status"), status(&[AUID; 4], &[AUID; 4], "80001"));
        let p = pdir();
        f.dir(&p, SUID, 0o700);
        f.node(&p).proj = PROJ;
        f.node(&p).inherit = true;
        let mut rows = Vec::new();
        for name in mps {
            let mp = format!("{p}/{name}");
            f.dir(&mp, 0, 0o555);
            f.node(&mp).immutable = true;
            f.node(&mp).gen = 11;
            rows.push((name.to_string(), f.nodes[&mp].id.ino, 11u32));
        }
        // The agent's store: srv/sagebrush/agents/<A>/sessions/claude/<name>, the agent's, 0700, its project.
        f.dir(&format!("srv/sagebrush/agents/{A}"), 0, 0o755);
        for d in [format!("srv/sagebrush/agents/{A}/sessions"), format!("srv/sagebrush/agents/{A}/sessions/claude")] {
            f.dir(&d, AUID, 0o700);
            f.node(&d).proj = AUID;
            f.node(&d).inherit = true;
        }
        for name in mps {
            let d = format!("srv/sagebrush/agents/{A}/sessions/claude/{name}");
            f.dir(&d, AUID, 0o700);
            f.node(&d).proj = AUID;
            f.node(&d).inherit = true;
        }
        let tf = TurnFile {
            turn: TURN.into(),
            op: OP.into(),
            agent: A.into(),
            agent_uid: AUID,
            gids: vec![80001],
            unit_pid: UNIT,
            harness: "claude".into(),
            profile: PID.into(),
            storage_uid: SUID,
            projid: PROJ,
            mountpoints: rows,
            cli: "/opt/sagebrush/1/bin/claude".into(),
            args: vec!["--print".into()],
        };
        (f, tf)
    }

    fn turn_json(tf: &TurnFile) -> String {
        let mps: Vec<String> = tf.mountpoints.iter().map(|(n, i, g)| format!("{{\"name\":{},\"ino\":{i},\"gen\":{g}}}", json::quote(n))).collect();
        let gids: Vec<String> = tf.gids.iter().map(|g| g.to_string()).collect();
        let args: Vec<String> = tf.args.iter().map(|a| json::quote(a)).collect();
        format!(
            "{{\"v\":1,\"turn\":\"{}\",\"op\":\"{}\",\"agent\":\"{}\",\"agent_uid\":{},\"gids\":[{}],\"unit_pid\":{},\"harness\":\"{}\",\"profile\":\"{}\",\"storage_uid\":{},\"projid\":{},\"mountpoints\":[{}],\"cli\":{},\"args\":[{}]}}",
            tf.turn, tf.op, tf.agent, tf.agent_uid, gids.join(","), tf.unit_pid, tf.harness, tf.profile, tf.storage_uid, tf.projid, mps.join(","), json::quote(&tf.cli), args.join(",")
        )
    }

    /// Steps 2–7 from the host root. Every run, whatever its outcome, asserts that no lookup went through a host
    /// handle after the switch (A5 r4.6: the fake seals them at `setns`).
    fn run(f: &mut Fake, tf: &TurnFile) -> Result<Staged<FH>> {
        run_step(f, tf).0
    }
    fn run_step(f: &mut Fake, tf: &TurnFile) -> (Result<Staged<FH>>, u8) {
        let root = f.root().unwrap();
        let mut step = 0;
        let r = stage(f, root, tf, &mut step);
        assert!(!f.log.iter().any(|l| l.starts_with("SEALED") || l.starts_with("NOT-TURN-TARGET")), "a host lookup after the switch: {:?}", f.log);
        if let Ok(s) = &r {
            assert!(s.profile.turn && s.root.turn, "only turn handles leave stage");
        }
        (r, step)
    }

    fn mounts(f: &Fake) -> usize {
        f.log.iter().filter(|l| l.starts_with("mount ")).count()
    }
    fn joined(f: &Fake) -> bool {
        f.log.iter().any(|l| l.starts_with("setns") || l == "unshare")
    }

    /// Calls the fake logged after the failing step: none may be a later step's.
    fn later_effects(f: &Fake) -> Vec<String> {
        f.log.iter().filter(|l| l.starts_with("clone ") || l.starts_with("userns ") || l.starts_with("idmap ") || l.starts_with("mount ")).cloned().collect()
    }

    #[test]
    fn the_whole_staging_mounts_exactly_the_checked_profile_and_binds_each_store() {
        let (mut f, tf) = host(&["projects", "todos"]);
        let s = run(&mut f, &tf).unwrap();
        let st = f.ident(&s.profile).unwrap();
        assert_eq!((st.uid, st.gid, st.mode & 0o7777), (AUID, AUID, 0o700), "the agent's through the idmap");
        // The order (A5 r4.6): through the host root, the profile's clone, the userns, the idmap and each store's
        // clone; then the switch; then, in the turn, the profile's mount and each store's.
        let seq: Vec<&String> = f.log.iter().filter(|l| ["setns", "unshare", "clone", "userns", "idmap", "mount"].iter().any(|p| l.starts_with(p))).collect();
        let want = vec![
            format!("clone {}", pdir()),
            format!("userns {AUID} {SUID}"),
            format!("idmap {} userns:{AUID}:{SUID}", pdir()),
            format!("clone srv/sagebrush/agents/{A}/sessions/claude/projects"),
            format!("clone srv/sagebrush/agents/{A}/sessions/claude/todos"),
            format!("setns {UNIT}"),
            "unshare".to_string(),
            format!("mount {} run/sagebrush/claude-profile", pdir()),
            format!("mount srv/sagebrush/agents/{A}/sessions/claude/projects run/sagebrush/claude-profile/projects"),
            format!("mount srv/sagebrush/agents/{A}/sessions/claude/todos run/sagebrush/claude-profile/todos"),
        ];
        assert_eq!(seq, want.iter().collect::<Vec<_>>());
        // The staged mountpoints are the agent's stores now.
        let b = f.nodes[&format!("run/sagebrush/claude-profile/projects")].id;
        assert_eq!(b.uid, AUID);
    }

    #[test]
    fn the_map_line_is_storage_inside_and_agent_outside() {
        // A5 r4.4: `<inside> <outside> 1` with the on-disk owner inside. The real writer formats exactly this.
        assert_eq!(map_line(AUID, SUID), format!("{SUID} {AUID} 1\n"));
        assert_eq!(map_line(70001, 90001), "90001 70001 1\n");
    }

    #[test]
    fn host_handles_are_sealed_at_the_switch_and_host_paths_are_not_in_the_turns_view() {
        // The fake's own seal, tested directly: after setns, a child-proc lookup through the host root is refused.
        let (mut f, _) = host(&["projects"]);
        let h = f.root().unwrap();
        assert!(f.read(&h, &format!("proc/{UNIT}/status"), 4096).is_ok(), "before the switch");
        f.join_ns(&UNIT).unwrap();
        assert!(f.read(&h, "proc/123/uid_map", 4096).is_err());
        assert!(f.userns(&h, AUID, SUID).is_err(), "the userns child's /proc lookups through the host root");
        assert!(f.dir_from_root(&h, "srv/sagebrush/claude-profiles").is_err());
        assert_eq!(f.log.iter().filter(|l| l.starts_with("SEALED")).count(), 3, "{:?}", f.log);
        // From the turn's root, the host's paths don't exist; the unit's view does.
        let t = f.turn_root().unwrap();
        for hidden in ["srv/sagebrush/claude-profiles", "srv/sagebrush/agents"] {
            assert_eq!(f.dir_from_root(&t, hidden).err().and_then(|e| e.raw_os_error()), Some(libc::ENOENT), "{hidden}");
        }
        assert!(f.read(&t, &format!("proc/{UNIT}/status"), 4096).is_err(), "the host's /proc isn't the turn's");
        assert!(f.dir_from_root(&t, "run/sagebrush").is_ok());
        // A move onto a host handle is refused: the target must be in the caller's namespace.
        let c = f.handle("x".into());
        let host_target = f.handle("run/sagebrush/claude-profile".into());
        assert!(f.move_onto(&c, &host_target).is_err());
    }

    #[test]
    fn the_turn_root_must_be_a_private_copy_of_the_root_mount() {
        let (mut f, tf) = host(&["projects"]);
        f.turn_root_mnt = MNT;
        let (r, step) = run_step(&mut f, &tf);
        assert_eq!((code(r), step), (66, 3));
        assert_eq!(mounts(&f), 0);
        let (mut f, tf) = host(&["projects"]);
        f.errno_at = Some(("turn_root", 1, libc::EACCES));
        let (r, step) = run_step(&mut f, &tf);
        assert_eq!((code(r), step), (66, 3));
        assert_eq!(mounts(&f), 0);
    }

    #[test]
    fn continuity_none_stages_the_profile_and_binds_nothing() {
        let (mut f, tf) = host(&[]);
        run(&mut f, &tf).unwrap();
        assert_eq!(f.log.iter().filter(|l| l.starts_with("mount ")).count(), 1);
    }

    type Spoil = fn(&mut Fake, &mut TurnFile);

    #[test]
    fn step_2_and_3_refusals_are_66_before_anything_is_joined_or_mounted() {
        let rows: Vec<(&str, Spoil)> = vec![
            ("no such process", |_, t| t.unit_pid = 999),
            ("another unit's cgroup", |f, _| { f.files.insert(format!("proc/{UNIT}/cgroup"), b"0::/sagebrush.slice/other.service\n".to_vec()); }),
            ("a sibling turn's scope", |f, _| { f.files.insert(format!("proc/{UNIT}/cgroup"), format!("0::/sagebrush.slice/sagebrush-agents.slice/sagebrush-agents-{A}.slice/sagebrush-turn-{A}-x.scope\n").into_bytes()); }),
            ("another real uid", |f, _| { f.files.insert(format!("proc/{UNIT}/status"), status(&[0, AUID, AUID, AUID], &[AUID; 4], "80001")); }),
            ("another effective uid", |f, _| { f.files.insert(format!("proc/{UNIT}/status"), status(&[AUID, 0, AUID, AUID], &[AUID; 4], "80001")); }),
            ("another saved uid", |f, _| { f.files.insert(format!("proc/{UNIT}/status"), status(&[AUID, AUID, 0, AUID], &[AUID; 4], "80001")); }),
            ("another fs uid", |f, _| { f.files.insert(format!("proc/{UNIT}/status"), status(&[AUID, AUID, AUID, 5], &[AUID; 4], "80001")); }),
            ("another real gid", |f, _| { f.files.insert(format!("proc/{UNIT}/status"), status(&[AUID; 4], &[0, AUID, AUID, AUID], "80001")); }),
            ("another effective gid", |f, _| { f.files.insert(format!("proc/{UNIT}/status"), status(&[AUID; 4], &[AUID, 0, AUID, AUID], "80001")); }),
            ("another saved gid", |f, _| { f.files.insert(format!("proc/{UNIT}/status"), status(&[AUID; 4], &[AUID, AUID, 0, AUID], "80001")); }),
            ("another fs gid", |f, _| { f.files.insert(format!("proc/{UNIT}/status"), status(&[AUID; 4], &[AUID, AUID, AUID, 5], "80001")); }),
            ("a group extra", |f, _| { f.files.insert(format!("proc/{UNIT}/status"), status(&[AUID; 4], &[AUID; 4], "80001 80002")); }),
            ("a group missing", |f, _| { f.files.insert(format!("proc/{UNIT}/status"), status(&[AUID; 4], &[AUID; 4], "")); }),
            ("another group", |f, _| { f.files.insert(format!("proc/{UNIT}/status"), status(&[AUID; 4], &[AUID; 4], "80009")); }),
            ("three uids", |f, _| { f.files.insert(format!("proc/{UNIT}/status"), status(&[AUID; 3], &[AUID; 4], "80001")); }),
            ("no Gid line", |f, _| { f.files.insert(format!("proc/{UNIT}/status"), format!("Uid:\t{AUID}\t{AUID}\t{AUID}\t{AUID}\nGroups:\t80001\n").into_bytes()); }),
            ("no Groups line", |f, _| { f.files.insert(format!("proc/{UNIT}/status"), format!("Uid:\t{AUID}\t{AUID}\t{AUID}\t{AUID}\nGid:\t{AUID}\t{AUID}\t{AUID}\t{AUID}\n").into_bytes()); }),
            ("a malformed Groups line", |f, _| { f.files.insert(format!("proc/{UNIT}/status"), status(&[AUID; 4], &[AUID; 4], "80001 x")); }),
            ("a bare Uid line", |f, _| { f.files.insert(format!("proc/{UNIT}/status"), format!("Name:\tx\nUid\nGid:\t{AUID}\t{AUID}\t{AUID}\t{AUID}\nGroups:\t80001\n").into_bytes()); }),
            ("a bare Gid line", |f, _| { f.files.insert(format!("proc/{UNIT}/status"), format!("Name:\tx\nUid:\t{AUID}\t{AUID}\t{AUID}\t{AUID}\nGid\nGroups:\t80001\n").into_bytes()); }),
            ("a bare Groups line", |f, _| { f.files.insert(format!("proc/{UNIT}/status"), format!("Name:\tx\nUid:\t{AUID}\t{AUID}\t{AUID}\t{AUID}\nGid:\t{AUID}\t{AUID}\t{AUID}\t{AUID}\nGroups\n").into_bytes()); }),
            ("two Uid lines", |f, _| { let mut b = status(&[AUID; 4], &[AUID; 4], "80001"); b.extend_from_slice(format!("Uid:\t0\t0\t0\t0\n").as_bytes()); f.files.insert(format!("proc/{UNIT}/status"), b); }),
            ("a recycled pid (dead after the reads)", |f, _| { f.files.insert(format!("proc/{UNIT}/dead"), vec![]); }),
        ];
        for (what, spoil) in rows {
            let (mut f, mut tf) = host(&["projects"]);
            spoil(&mut f, &mut tf);
            let (r, step) = run_step(&mut f, &tf);
            assert_eq!((code(r), step), (66, 2), "{what}");
            assert!(!joined(&f), "{what}: nothing joined");
            assert!(later_effects(&f).is_empty(), "{what}");
        }
        for op in ["join_ns", "unshare"] {
            let (mut f, tf) = host(&["projects"]);
            f.errno_at = Some((op, 1, libc::EPERM));
            let (r, step) = run_step(&mut f, &tf);
            assert_eq!((code(r), step), (66, 3), "{op}");
            assert_eq!(mounts(&f), 0, "{op}: nothing mounted (the detached clones are never attached)");
        }
    }

    #[test]
    fn the_groups_are_compared_as_a_set_and_empty_matches_empty() {
        // Reordered and duplicated (as the kernel may list them): the same set, accepted.
        let (mut f, mut tf) = host(&["projects"]);
        tf.gids = vec![80001, 80005];
        f.files.insert(format!("proc/{UNIT}/status"), status(&[AUID; 4], &[AUID; 4], "80005 80001"));
        assert!(run(&mut f, &tf).is_ok());
        // Both empty: accepted.
        let (mut f, mut tf) = host(&["projects"]);
        tf.gids = vec![];
        f.files.insert(format!("proc/{UNIT}/status"), status(&[AUID; 4], &[AUID; 4], ""));
        assert!(run(&mut f, &tf).is_ok());
        // An empty unit set against non-empty gids: 66.
        let (mut f, mut tf) = host(&["projects"]);
        tf.gids = vec![80001];
        f.files.insert(format!("proc/{UNIT}/status"), status(&[AUID; 4], &[AUID; 4], ""));
        assert_eq!(code(run(&mut f, &tf)), 66);
        // A bare Groups line (no colon) is no Groups line, even against empty gids: 66, nothing joined.
        let (mut f, mut tf) = host(&["projects"]);
        tf.gids = vec![];
        f.files.insert(format!("proc/{UNIT}/status"), format!("Uid:\t{AUID}\t{AUID}\t{AUID}\t{AUID}\nGid:\t{AUID}\t{AUID}\t{AUID}\t{AUID}\nGroups\n").into_bytes());
        assert_eq!(code(run(&mut f, &tf)), 66);
        assert!(!f.log.iter().any(|l| l.starts_with("setns") || l == "unshare"));
        assert!(later_effects(&f).is_empty());
        // The positive propagation control: the gid map and the idmap's inside id are agent_uid itself.
        let (mut f, tf) = host(&["projects"]);
        run(&mut f, &tf).unwrap();
        assert!(f.log.contains(&format!("userns {AUID} {SUID}")));
    }

    #[test]
    fn step_4_profile_identity_refusals_are_73_with_zero_mounts() {
        let rows: Vec<(&str, Spoil)> = vec![
            ("another owner", |f, _| f.node(&pdir()).id.uid = SUID + 1),
            ("another group", |f, _| f.node(&pdir()).id.gid = SUID + 1),
            ("mode 0755", |f, _| f.node(&pdir()).id.mode = S_IFDIR | 0o755),
            ("mode 0750", |f, _| f.node(&pdir()).id.mode = S_IFDIR | 0o750),
            ("a file", |f, _| f.node(&pdir()).id.mode = S_IFREG | 0o700),
            ("another project", |f, _| f.node(&pdir()).proj = PROJ + 1),
            ("no inherit", |f, _| f.node(&pdir()).inherit = false),
            ("another mount", |f, _| f.node(&pdir()).id.mnt_id = MNT + 7),
            ("a mount root", |f, _| f.node(&pdir()).id.attributes = libc::STATX_ATTR_MOUNT_ROOT as u64),
            ("missing", |f, _| { f.nodes.retain(|k, _| !k.starts_with(&pdir())); }),
        ];
        for (what, spoil) in rows {
            let (mut f, mut tf) = host(&["projects"]);
            spoil(&mut f, &mut tf);
            let (r, step) = run_step(&mut f, &tf);
            assert_eq!((code(r), step), (73, 4), "{what}");
            assert!(later_effects(&f).is_empty(), "{what}: zero mounts");
            assert!(!joined(&f), "{what}: refused before the switch");
        }
    }

    #[test]
    fn step_5_mountpoint_refusals_are_73_with_zero_mounts_even_at_the_last_of_many() {
        let names: Vec<String> = (0..16).map(|i| format!("m{i:02}")).collect();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let last = format!("{}/m15", pdir());
        let first = format!("{}/m00", pdir());
        let rows: Vec<(&str, String, fn(&mut Fake, &str))> = vec![
            ("another ino", last.clone(), |f, p| f.node(p).id.ino += 1000),
            ("another gen", last.clone(), |f, p| f.node(p).gen = 12),
            ("the flag cleared", last.clone(), |f, p| f.node(p).immutable = false),
            ("mode 0755", last.clone(), |f, p| f.node(p).id.mode = S_IFDIR | 0o755),
            ("not root's", last.clone(), |f, p| f.node(p).id.uid = AUID),
            ("not empty", last.clone(), |f, p| f.file(&format!("{p}/x"), 0, 0o600)),
            ("a mount", last.clone(), |f, p| f.node(p).id.mnt_id = MNT + 7),
            ("missing", last.clone(), |f, p| { f.nodes.remove(p); }),
            ("the first wrong", first.clone(), |f, p| f.node(p).gen = 12),
        ];
        for (what, path, spoil) in rows {
            let (mut f, tf) = host(&refs);
            spoil(&mut f, &path);
            let (r, step) = run_step(&mut f, &tf);
            assert_eq!((code(r), step), (73, 5), "{what}");
            assert!(later_effects(&f).is_empty(), "{what}: zero mounts");
            assert!(!joined(&f), "{what}: refused before the switch");
        }
    }

    #[test]
    fn step_6_refusals_are_66_with_no_mount_and_failures_stop_there() {
        let rows: Vec<(&str, Spoil)> = vec![
            ("the mountpoint missing", |f, _| { f.nodes.remove("run/sagebrush/claude-profile"); }),
            ("the mountpoint 0755", |f, _| f.node("run/sagebrush/claude-profile").id.mode = S_IFDIR | 0o755),
            ("the mountpoint not root's", |f, _| f.node("run/sagebrush/claude-profile").id.uid = AUID),
            ("the mountpoint a mount root", |f, _| f.node("run/sagebrush/claude-profile").id.attributes = libc::STATX_ATTR_MOUNT_ROOT as u64),
            ("the mountpoint not empty", |f, _| f.file("run/sagebrush/claude-profile/x", 0, 0o600)),
        ];
        for (what, spoil) in rows {
            let (mut f, mut tf) = host(&["projects"]);
            spoil(&mut f, &mut tf);
            let (r, step) = run_step(&mut f, &tf);
            assert_eq!((code(r), step), (66, 6), "{what}");
            assert_eq!(mounts(&f), 0, "{what}: nothing mounted");
        }
        // The profile's clone, the userns and the idmap run before the switch: a failure joins nothing.
        for op in ["clone", "userns", "idmap"] {
            let (mut f, tf) = host(&["projects"]);
            f.errno_at = Some((op, 1, libc::EPERM));
            let (r, step) = run_step(&mut f, &tf);
            assert_eq!((code(r), step), (66, 6), "{op}");
            assert!(!joined(&f), "{op}: zero setns");
        }
        let (mut f, tf) = host(&["projects"]);
        f.errno_at = Some(("move", 1, libc::EPERM));
        let (r, step) = run_step(&mut f, &tf);
        assert_eq!((code(r), step), (66, 6));
        assert_eq!(mounts(&f), 0, "move: nothing mounted");
    }

    #[test]
    fn step_7_a_late_failure_is_73_and_stays_in_the_turns_own_namespace() {
        // The second bind's re-check fails (another store object appears at the name): 73, no later bind.
        let (mut f, tf) = host(&["a", "b", "c"]);
        f.hook = Some(("move", 3, |f: &mut Fake| {
            let p = format!("srv/sagebrush/agents/{A}/sessions/claude/b");
            f.node(&p).id.ino += 5000;
        }));
        assert_eq!(code(run(&mut f, &tf)), 73);
        assert_eq!(f.log.iter().filter(|l| l.starts_with("mount ")).count(), 3, "the profile, a, then b's bind; never c's");
        // Every mount happened after the unshare: they're the turn's alone (the fake's namespace is this process's).
        let u = f.log.iter().position(|l| l == "unshare").unwrap();
        assert!(f.log.iter().enumerate().filter(|(_, l)| l.starts_with("mount ")).all(|(i, _)| i > u));
    }

    #[test]
    fn step_7_the_staged_profile_and_each_staged_mountpoint_must_be_the_checked_ones() {
        // A store that isn't the agent's: 73 before its bind.
        let (mut f, tf) = host(&["projects"]);
        f.node(&format!("srv/sagebrush/agents/{A}/sessions/claude/projects")).id.uid = AUID + 1;
        let (r, step) = run_step(&mut f, &tf);
        assert_eq!((code(r), step), (73, 7));
        assert!(mounts(&f) == 0 && !joined(&f), "checked before the switch: nothing joined or mounted");
        // A store in another project: 73.
        let (mut f, tf) = host(&["projects"]);
        f.node(&format!("srv/sagebrush/agents/{A}/sessions/claude/projects")).proj = AUID + 1;
        assert_eq!(code(run(&mut f, &tf)), 73);
        // A missing store: 66.
        let (mut f, tf) = host(&["projects"]);
        f.nodes.remove(&format!("srv/sagebrush/agents/{A}/sessions/claude/projects"));
        let (r, step) = run_step(&mut f, &tf);
        assert_eq!((code(r), step), (66, 7));
        assert!(!joined(&f));
        // The staged profile isn't the agent's (an idmap that didn't take): 73.
        let (mut f, tf) = host(&["projects"]);
        f.hook = Some(("move", 1, |f: &mut Fake| {
            f.files.retain(|k, _| !k.starts_with("idmap:"));
        }));
        assert_eq!(code(run(&mut f, &tf)), 73);
        assert_eq!(f.log.iter().filter(|l| l.starts_with("mount ")).count(), 1);
    }

    #[test]
    fn step_7_a_swap_at_either_seam_is_73() {
        // The profile replaced between its checks and its mount: the staged object isn't the checked one.
        let (mut f, tf) = host(&["projects"]);
        f.hook = Some(("move", 1, |f: &mut Fake| {
            let p = pdir();
            f.node(&p).id.ino += 7000;
        }));
        assert_eq!(code(run(&mut f, &tf)), 73);
        assert_eq!(f.log.iter().filter(|l| l.starts_with("mount ")).count(), 1, "no session bind");
        // A staged mountpoint replaced before its bind (after the store was cloned): 73, nothing bound over it.
        let (mut f, tf) = host(&["projects"]);
        f.hook = Some(("at_mounted", 1, |f: &mut Fake| {
            f.node("run/sagebrush/claude-profile/projects").id.ino += 7000;
        }));
        assert_eq!(code(run(&mut f, &tf)), 73);
        assert_eq!(f.log.iter().filter(|l| l.starts_with("mount ")).count(), 1, "the profile only");
    }

    #[test]
    fn the_turn_file_is_the_closed_shape_and_root_only() {
        let (mut f, tf) = host(&["projects"]);
        let good = turn_json(&tf);
        assert_eq!(parse_turn_file(good.as_bytes(), TURN).unwrap(), tf);
        // Read through its handle, under a root 0700 directory, a root file of exactly 0600.
        f.dir(&format!("run/sagebrush/turns/{TURN}"), 0, 0o700);
        let p = format!("run/sagebrush/turns/{TURN}/turn.json");
        f.file(&p, 0, 0o600);
        f.files.insert(p.clone(), good.clone().into_bytes());
        let root = f.root().unwrap();
        assert_eq!(read_turn_file(&mut f, &root, TURN).unwrap(), tf);
        for (what, spoil) in [
            ("group-readable", (|f: &mut Fake, p: &str| f.node(p).id.mode = S_IFREG | 0o640) as fn(&mut Fake, &str)),
            ("owner read-only 0400", |f, p| f.node(p).id.mode = S_IFREG | 0o400),
            ("owner-executable 0700", |f, p| f.node(p).id.mode = S_IFREG | 0o700),
            ("setuid 4600", |f, p| f.node(p).id.mode = S_IFREG | 0o4600),
            ("setgid 2600", |f, p| f.node(p).id.mode = S_IFREG | 0o2600),
            ("sticky 1600", |f, p| f.node(p).id.mode = S_IFREG | 0o1600),
            ("not root's", |f, p| f.node(p).id.uid = AUID),
            ("two links", |f, p| f.node(p).id.nlink = 2),
            ("the directory 0755", |f, _| f.node(&format!("run/sagebrush/turns/{TURN}")).id.mode = S_IFDIR | 0o755),
        ] {
            let mut g = f.clone();
            g.log.clear();
            spoil(&mut g, &p);
            let root = g.root().unwrap();
            assert_eq!(code(read_turn_file(&mut g, &root, TURN)), 65, "{what}");
            assert!(!g.log.iter().any(|l| l.starts_with("read ")), "{what}: not read");
        }
        assert_eq!(code(read_turn_file(&mut f, &root, "NOTHEX")), 64);
        // The closed shape: each field's form and range.
        let bad = |from: &str, to: &str| good.replacen(from, to, 1);
        let rows = [
            bad("\"v\":1", "\"v\":2"),
            bad(TURN, "11111111111111111111111111111111"),
            bad(OP, "nothex"),
            bad(&format!("\"agent_uid\":{AUID}"), "\"agent_uid\":0"),
            bad(&format!("\"agent_uid\":{AUID}"), "\"agent_uid\":80000"),
            bad("\"gids\":[80001]", "\"gids\":[80002,80001]"),
            bad("\"gids\":[80001]", "\"gids\":[80001,80001]"),
            bad("\"gids\":[80001]", "\"gids\":[70001]"),
            bad("\"harness\":\"claude\"", "\"harness\":\"codex\""),
            bad(&format!("\"storage_uid\":{SUID}"), "\"storage_uid\":70001"),
            bad(&format!("\"projid\":{PROJ}"), "\"projid\":70001"),
            bad("\"name\":\"projects\"", "\"name\":\"a/b\""),
            bad("\"name\":\"projects\"", "\"name\":\"..\""),
            bad("\"cli\":\"/opt", "\"cli\":\"opt"),
            bad("\"args\":[", "\"extra\":1,\"args\":["),
            good.replace("\"gen\":11", "\"gen\":4294967296"),
        ];
        for r in rows {
            assert_eq!(code(parse_turn_file(r.as_bytes(), TURN)), 65, "{r}");
        }
        let many: Vec<String> = (0..65).map(|i| (80001 + i).to_string()).collect();
        assert_eq!(code(parse_turn_file(bad("\"gids\":[80001]", &format!("\"gids\":[{}]", many.join(","))).as_bytes(), TURN)), 65, "65 gids");
        let dup = good.replace("\"mountpoints\":[{", "\"mountpoints\":[{\"name\":\"projects\",\"ino\":1,\"gen\":1},{");
        assert_eq!(code(parse_turn_file(dup.as_bytes(), TURN)), 65, "a duplicate mountpoint name");
    }

    /// The real operations that run unprivileged on this kernel (the rest need root and are the VM's rows).
    mod real {
        use super::*;

        fn my_ids() -> (u32, u32) {
            use std::os::unix::fs::MetadataExt;
            let m = std::fs::metadata("/proc/self").unwrap();
            (m.uid(), m.gid())
        }

        #[test]
        fn the_userns_child_makes_a_user_namespace_and_is_reaped() {
            let (uid, gid) = my_ids();
            if uid != gid {
                eprintln!("SKIPPED: uid {uid} != gid {gid}: an unprivileged gid_map can map only the caller's own gid");
                return;
            }
            let mut o = tree::RealOps;
            let host = o.root().unwrap();
            // This thread's own children (each test runs on its own thread): none may be left over, not even a zombie.
            let children = || std::fs::read_to_string("/proc/thread-self/children").ok();
            match o.userns(&host, uid, uid) {
                Ok(ns) => {
                    assert_eq!(sys::ns_type(&ns).unwrap(), libc::CLONE_NEWUSER);
                    match children() {
                        Some(c) => assert_eq!(c.trim(), "", "the child is reaped"),
                        None => eprintln!("SKIPPED (reap check): no /proc/thread-self/children on this kernel"),
                    }
                }
                Err(e) if e.raw_os_error() == Some(libc::EPERM) || e.raw_os_error() == Some(libc::EACCES) => {
                    eprintln!("SKIPPED: this kernel or container refuses an unprivileged user namespace ({e})");
                }
                Err(e) => panic!("{e}"),
            }
        }

        #[test]
        fn only_a_user_namespace_entry_is_taken() {
            let mut o = tree::RealOps;
            let root = o.root().unwrap();
            let nsdir = sys::openat2(&root, &tree::c(&format!("proc/{}/ns", std::process::id())).unwrap(), libc::O_PATH | libc::O_DIRECTORY, 0).unwrap();
            assert!(user_ns_entry(&nsdir, c"user").is_ok());
            assert_eq!(user_ns_entry(&nsdir, c"net").err().and_then(|e| e.raw_os_error()), Some(libc::EINVAL), "a network namespace isn't one");
        }

        #[test]
        fn at_mounted_takes_one_validated_component_only() {
            let mut o = tree::RealOps;
            let root = o.root().unwrap();
            let tmp = o.dir_from_root(&root, "tmp").unwrap();
            for bad in ["a/b", "..", ".", "", "x\u{0}y"] {
                assert_eq!(o.at_mounted(&tmp, bad).err().and_then(|e| e.raw_os_error()), Some(libc::EINVAL), "{bad:?}");
            }
        }

        #[test]
        fn read_handle_is_bounded_and_alive_sees_this_process() {
            let d = std::env::temp_dir().join(format!("sbl-turn-{}", std::process::id()));
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join("f"), b"12345").unwrap();
            let mut o = tree::RealOps;
            let root = o.root().unwrap();
            let dir = o.dir_from_root(&root, &d.to_str().unwrap()[1..]).unwrap();
            let h = o.at(&dir, "f", At::File).unwrap();
            assert_eq!(o.read_handle(&h, 5).unwrap(), b"12345");
            let h = o.at(&dir, "f", At::File).unwrap();
            assert_eq!(o.read_handle(&h, 4).err().and_then(|e| e.raw_os_error()), Some(libc::EFBIG));
            std::fs::remove_dir_all(&d).unwrap();
            let me = o.pidfd(std::process::id()).unwrap();
            assert!(o.alive(&me).unwrap());
        }
    }
}
