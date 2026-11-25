//! `turn` (launcher contract amendment A5 r4.2, profiles piece 3): one turn with ONE profile. This module is part 3a:
//! the turn file and steps 2–7 (the unit, the namespaces, the profile's and its mountpoints' identity on trusted
//! handles, the idmapped profile mount and the session binds), generic over `TurnOps` and tested against the fake.
//! Part 3b adds the real operations, the confinement (steps 8–12, §3's filter) and the entry point; until then nothing
//! calls this.
//!
//! - The argv carries only the opaque turn id; everything else comes from the root-only turn file (§1, AUDIT H2).
//! - Step 2: the unit's main process by pidfd, its cgroup exactly the agent unit's, alive, and all four of its uids the
//!   turn file's `agent_uid` (r4.2).
//! - Step 3: join its network and mount namespaces, then a private copy (unshare + private propagation).
//! - Step 4: the profile directory on its trusted handle: the storage uid's, 0700, a directory, the anchor's mount, not
//!   a mount root, in the profile's project with inherit (r2.1 §7.1). A mismatch is 73.
//! - Step 5: each recorded mountpoint beneath that handle: its ino and generation, root:root 0555, immutable, empty,
//!   all checked before anything is mounted (SEC's condition on profiles piece 2). A mismatch is 73.
//! - Step 6: the profile cloned and idmapped `<agent_uid> <storage_uid> 1`, moved onto the fixed, empty, root 0700
//!   `/run/sagebrush/claude-profile`.
//! - Step 7: the staged profile re-read (same dev and ino, the agent's through the idmap, a new mount); then each
//!   session store bound over its staged mountpoint, matched to step 5's handle first and re-read after.

// Part 3a: nothing outside the tests calls this until part 3b adds the real operations and the entry point.
#![allow(dead_code)]

use crate::args::is_id;
use crate::err::{err, Error, Fail, Result};
use crate::json::{self, Value};
use crate::profile::{ProfileOps, MAX_SUBPATHS, PROFILES};
use crate::tree::{anchor_policy, child as tchild, identity, kind_of, open_err, pre, At, Kind, Obj};
use std::io;

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
    /// A user-namespace handle mapping exactly `<inside> <outside> 1` for uids and gids (a reaped child's).
    fn userns(&mut self, inside: u32, outside: u32) -> io::Result<Self::H>;
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
pub struct Staged<H> {
    pub profile: H,
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

/// Steps 2–7 (A5 §2). Every refusal is returned before any later step runs.
pub fn stage<O: TurnOps>(o: &mut O, root: &O::H, tf: &TurnFile) -> Result<Staged<O::H>> {
    // 2. The unit, by pidfd: its cgroup, its uids, and still alive after both reads.
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
    // 3. Its namespaces, then a private copy.
    o.join_ns(&p).map_err(|_| ns("the unit's namespaces can't be joined"))?;
    o.unshare_private().map_err(|_| ns("a private mount namespace can't be made"))?;

    // 4. The profile directory on its trusted handle.
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

    // 5. Every mountpoint, checked before anything is mounted.
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

    // 6. The idmapped profile mount onto the fixed, empty, root 0700 mountpoint.
    let target_rel = &STAGED[1..];
    let (tparent_rel, tname) = target_rel.rsplit_once('/').unwrap_or(("", target_rel));
    let tparent = o.dir_from_root(root, tparent_rel).map_err(|_| ns("the staging mountpoint's parent is missing"))?;
    let tpi = o.ident(&tparent).map_err(open_err)?;
    let target = o.at(&tparent, tname, At::Dir).map_err(|_| ns("the staging mountpoint is missing"))?;
    let ti = o.ident(&target).map_err(open_err)?;
    if kind_of(&ti) != Some(Kind::Dir) || ti.uid != 0 || ti.gid != 0 || ti.mode & 0o7777 != 0o700 || ti.attributes & libc::STATX_ATTR_MOUNT_ROOT as u64 != 0 || ti.mnt_id != tpi.mnt_id {
        return Err(ns("the staging mountpoint isn't a fresh root 0700 directory"));
    }
    if !o.batch(&target).map_err(open_err)?.is_empty() {
        return Err(ns("the staging mountpoint isn't empty"));
    }
    let clone = o.clone_tree(&ph).map_err(|_| ns("the profile can't be cloned"))?;
    let userns = o.userns(tf.agent_uid, tf.storage_uid).map_err(|_| ns("the user namespace can't be made"))?;
    o.idmap(&clone, &userns).map_err(|_| ns("the idmap can't be set"))?;
    o.move_onto(&clone, &target).map_err(|_| ns("the profile can't be mounted"))?;

    // 7. The staged profile re-read: the same object, the agent's through the idmap, on a new mount.
    let staged = o.at_mounted(&tparent, tname).map_err(|_| identity("the staged profile can't be opened"))?;
    let si = o.ident(&staged).map_err(open_err)?;
    if (si.dev, si.ino) != (px.dev, px.ino) || kind_of(&si) != Some(Kind::Dir) || si.mode & 0o7777 != 0o700 || si.uid != tf.agent_uid || si.gid != tf.agent_uid || si.mnt_id == tpi.mnt_id {
        return Err(identity("the staged profile isn't the checked one"));
    }
    // The session binds: each store directory over its staged mountpoint, matched first, re-read after.
    if !tf.mountpoints.is_empty() {
        let aa = anchor_policy(o, root, "/srv/sagebrush/agents")?;
        let amnt = o.ident(&aa).map_err(open_err)?.mnt_id;
        let mut cur = tchild(o, &aa, &tf.agent, amnt)?.and_then(|(_, h)| h).ok_or(ns("the agent directory is missing"))?;
        for part in ["sessions", tf.harness.as_str()] {
            cur = tchild(o, &cur, part, amnt)?.and_then(|(_, h)| h).ok_or(ns("the session store is missing"))?;
        }
        for (name, x) in &mps {
            let (sx, sh) = tchild(o, &cur, name, amnt)?.ok_or(ns("a session store directory is missing"))?;
            let sh = sh.ok_or(identity("a session store entry isn't a directory"))?;
            if sx.uid != tf.agent_uid || sx.gid != tf.agent_uid || sx.mode != 0o700 || sx.projid != Some(tf.agent_uid) || sx.inherit != Some(true) {
                return Err(identity("a session store directory isn't the agent's"));
            }
            let sclone = o.clone_tree(&sh).map_err(|_| ns("a session store can't be cloned"))?;
            let at = o.at(&staged, name, At::Path).map_err(|_| identity("a staged mountpoint can't be opened"))?;
            let ai = o.ident(&at).map_err(open_err)?;
            if (ai.dev, ai.ino) != (x.dev, x.ino) {
                return Err(identity("a staged mountpoint isn't the checked one"));
            }
            o.move_onto(&sclone, &at).map_err(|_| ns("a session store can't be bound"))?;
            let back = o.at_mounted(&staged, name).map_err(|_| identity("a session bind can't be re-read"))?;
            let bi = o.ident(&back).map_err(open_err)?;
            if (bi.dev, bi.ino) != (sx.dev, sx.ino) || bi.mnt_id == si.mnt_id {
                return Err(identity("a session bind isn't the agent's store"));
            }
        }
    }
    Ok(Staged { profile: staged })
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
            Ok(())
        }
        fn unshare_private(&mut self) -> io::Result<()> {
            self.tick("unshare")?;
            self.log.push("unshare".into());
            Ok(())
        }
        fn read_handle(&mut self, h: &FH, max: usize) -> io::Result<Vec<u8>> {
            self.log.push(format!("read {}", h.p));
            let b = self.files.get(&h.p).cloned().ok_or(e(libc::ENOENT))?;
            if b.len() > max { Err(e(libc::EFBIG)) } else { Ok(b) }
        }
        fn clone_tree(&mut self, h: &FH) -> io::Result<FH> {
            self.tick("clone")?;
            self.log.push(format!("clone {}", h.p));
            Ok(self.handle(h.p.clone()))
        }
        fn userns(&mut self, inside: u32, outside: u32) -> io::Result<FH> {
            self.tick("userns")?;
            self.log.push(format!("userns {inside} {outside}"));
            Ok(self.handle(format!("userns:{inside}:{outside}")))
        }
        fn idmap(&mut self, clone: &FH, userns: &FH) -> io::Result<()> {
            self.tick("idmap")?;
            self.log.push(format!("idmap {} {}", clone.p, userns.p));
            self.files.insert(format!("idmap:{}", clone.p), userns.p.clone().into_bytes());
            Ok(())
        }
        fn move_onto(&mut self, clone: &FH, target: &FH) -> io::Result<()> {
            self.tick("move")?;
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
            let p = join(&dir.p, name);
            if !self.nodes.contains_key(&p) {
                return Err(e(libc::ENOENT));
            }
            Ok(self.handle(p))
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

    fn run(f: &mut Fake, tf: &TurnFile) -> Result<Staged<FH>> {
        let root = f.root().unwrap();
        stage(f, &root, tf)
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
        // Order: setns, unshare, then the profile clone, the userns, the idmap, its mount, then each store's.
        let mounts: Vec<&String> = f.log.iter().filter(|l| ["setns", "unshare", "clone", "userns", "idmap", "mount"].iter().any(|p| l.starts_with(p))).collect();
        assert_eq!(mounts[0], &format!("setns {UNIT}"));
        assert_eq!(mounts[1], "unshare");
        assert_eq!(mounts[2], &format!("clone {}", pdir()));
        assert_eq!(mounts[3], &format!("userns {AUID} {SUID}"));
        assert!(mounts[4].starts_with("idmap "));
        assert_eq!(mounts[5], &format!("mount {} run/sagebrush/claude-profile", pdir()));
        for (i, n) in ["projects", "todos"].iter().enumerate() {
            assert_eq!(mounts[6 + 2 * i], &format!("clone srv/sagebrush/agents/{A}/sessions/claude/{n}"));
            assert_eq!(mounts[7 + 2 * i], &format!("mount srv/sagebrush/agents/{A}/sessions/claude/{n} run/sagebrush/claude-profile/{n}"));
        }
        // The staged mountpoints are the agent's stores now.
        let b = f.nodes[&format!("run/sagebrush/claude-profile/projects")].id;
        assert_eq!(b.uid, AUID);
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
            assert_eq!(code(run(&mut f, &tf)), 66, "{what}");
            assert!(!f.log.iter().any(|l| l.starts_with("setns") || l == "unshare"), "{what}: nothing joined");
            assert!(later_effects(&f).is_empty(), "{what}");
        }
        for op in ["join_ns", "unshare"] {
            let (mut f, tf) = host(&["projects"]);
            f.errno_at = Some((op, 1, libc::EPERM));
            assert_eq!(code(run(&mut f, &tf)), 66, "{op}");
            assert!(later_effects(&f).is_empty(), "{op}: no staging");
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
            assert_eq!(code(run(&mut f, &tf)), 73, "{what}");
            assert!(later_effects(&f).is_empty(), "{what}: zero mounts");
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
            assert_eq!(code(run(&mut f, &tf)), 73, "{what}");
            assert!(later_effects(&f).is_empty(), "{what}: zero mounts");
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
            assert_eq!(code(run(&mut f, &tf)), 66, "{what}");
            assert!(later_effects(&f).is_empty(), "{what}");
        }
        for op in ["clone", "userns", "idmap", "move"] {
            let (mut f, tf) = host(&["projects"]);
            f.errno_at = Some((op, 1, libc::EPERM));
            assert_eq!(code(run(&mut f, &tf)), 66, "{op}");
            assert!(!f.log.iter().any(|l| l.starts_with("mount ")), "{op}: nothing mounted");
        }
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
        assert_eq!(code(run(&mut f, &tf)), 73);
        assert_eq!(f.log.iter().filter(|l| l.starts_with("mount ")).count(), 1, "only the profile");
        // A store in another project: 73.
        let (mut f, tf) = host(&["projects"]);
        f.node(&format!("srv/sagebrush/agents/{A}/sessions/claude/projects")).proj = AUID + 1;
        assert_eq!(code(run(&mut f, &tf)), 73);
        // A missing store: 66.
        let (mut f, tf) = host(&["projects"]);
        f.nodes.remove(&format!("srv/sagebrush/agents/{A}/sessions/claude/projects"));
        assert_eq!(code(run(&mut f, &tf)), 66);
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
        f.hook = Some(("clone", 2, |f: &mut Fake| {
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
}
