//! `stage-bind` (contract §3, §3.1): open a granted path by handle, clone it onto the agent's fresh, root-only
//! staging mountpoint, check the identity, and publish a durable record; on a failure after the mount, roll back.

use crate::args::{dirent_names, is_id, rel};
use crate::err::{err, Error, Fail, Result};
use crate::json::quote;
use crate::sys;
use std::ffi::CString;
use std::os::fd::OwnedFd;

const BINDS: &str = "run/sagebrush/binds";
const EMPTY_CHECK_CALLS: usize = 8;

pub struct Args<'a> {
    pub agent: &'a str,
    pub index: u8,
    pub mode: &'a str,
    pub path: &'a str,
}

pub fn parse<'a>(v: &[&'a str]) -> Result<Args<'a>> {
    let bad = err(Fail::Usage, "bad arguments");
    let [agent, index, mode, path, record] = v else { return Err(bad) };
    let index: u8 = match index.parse::<u8>() {
        Ok(n) if n <= 63 && index.as_bytes()[0] != b'+' && (index.len() == 1 || !index.starts_with('0')) => n,
        _ => return Err(bad),
    };
    if !is_id(agent) || !["rw", "ro"].contains(mode) || rel(path).is_none() {
        return Err(bad);
    }
    // The record is exactly the agent's binds directory's "<index>.record" (so it is derived, never taken).
    if *record != format!("/{BINDS}/{agent}/{index}.record") {
        return Err(bad);
    }
    Ok(Args { agent, index, mode, path })
}

fn cstr(s: &str) -> Result<CString> {
    CString::new(s).map_err(|_| err(Fail::Usage, "bad arguments"))
}

fn pre(msg: &'static str) -> impl Fn(std::io::Error) -> Error {
    move |_| err(Fail::Preflight, msg)
}

const S_IFMT: u16 = 0o170000;
const S_IFDIR: u16 = 0o040000;

/// The empty-directory check (contract §3, §6): getdents64 to EOF with one fixed 4 KiB buffer, at most 8 calls; any
/// entry but "." and ".." refuses.
fn is_empty_dir(fd: &OwnedFd) -> Result<()> {
    let mut buf = [0u8; 4096];
    for _ in 0..EMPTY_CHECK_CALLS {
        let n = sys::getdents64(fd, &mut buf).map_err(pre("the mountpoint can't be listed"))?;
        if n == 0 {
            return Ok(());
        }
        let names = dirent_names(&buf, n).ok_or(err(Fail::Preflight, "the mountpoint can't be listed"))?;
        if names.iter().any(|nm| nm != b"." && nm != b"..") {
            return Err(err(Fail::Preflight, "the mountpoint is not empty"));
        }
    }
    Err(err(Fail::Preflight, "the mountpoint can't be listed"))
}

pub fn run(a: &Args) -> Result<()> {
    let root = sys::open_root().map_err(pre("the root can't be opened"))?;
    // 1-2. The granted path, by handle, and its identity.
    let src = sys::openat2(&root, &cstr(rel(a.path).unwrap())?, libc::O_PATH, 0).map_err(pre("the granted path can't be opened"))?;
    let src_st = sys::statx(&src).map_err(pre("the granted path can't be read"))?;
    // 3. The parent (the agent's binds directory) and the mountpoint: root-owned, 0700 directories; the mountpoint
    //    empty and not itself a mountpoint.
    let parent_rel = format!("{BINDS}/{}", a.agent);
    let mp_rel = format!("{parent_rel}/{}", a.index);
    let parent = sys::openat2(&root, &cstr(&parent_rel)?, libc::O_RDONLY | libc::O_DIRECTORY, 0).map_err(pre("the staging directory can't be opened"))?;
    let p_st = sys::statx(&parent).map_err(pre("the staging directory can't be read"))?;
    let mp = sys::openat2(&root, &cstr(&mp_rel)?, libc::O_RDONLY | libc::O_DIRECTORY, 0).map_err(pre("the mountpoint can't be opened"))?;
    let m_st = sys::statx(&mp).map_err(pre("the mountpoint can't be read"))?;
    for st in [&p_st, &m_st] {
        if st.mode & S_IFMT != S_IFDIR || st.uid != 0 || st.mode & 0o7777 != 0o700 {
            return Err(err(Fail::Preflight, "the staging directories aren't root-only"));
        }
    }
    if m_st.attributes_mask & libc::STATX_ATTR_MOUNT_ROOT as u64 == 0 && m_st.mask & libc::STATX_MNT_ID == 0 {
        return Err(err(Fail::Preflight, "mountpoints can't be detected on this kernel"));
    }
    if m_st.attributes & libc::STATX_ATTR_MOUNT_ROOT as u64 != 0 || m_st.mnt_id != p_st.mnt_id {
        return Err(err(Fail::Preflight, "the mountpoint is already a mount"));
    }
    is_empty_dir(&mp)?;
    // 4-6. Clone, read-only for "ro", and move it onto the mountpoint, both ends by handle.
    let clone = sys::open_tree_clone(&src).map_err(pre("the granted path can't be cloned"))?;
    if a.mode == "ro" {
        sys::mount_setattr_rdonly(&clone).map_err(pre("the clone can't be made read-only"))?;
    }
    sys::move_mount(&clone, &mp).map_err(pre("the clone can't be mounted"))?;
    // From here on, a failure rolls back what this call created.
    let mut published = false;
    match finish(a, &root, &parent, &mp_rel, &src_st, &mut published) {
        Ok(()) => Ok(()),
        Err(e) => match rollback(a, &root, &parent, &mp_rel, &p_st, &m_st, published) {
            Ok(()) => Err(e),
            Err(r) => Err(r),
        },
    }
}

/// 7-8. Check the staged identity, then publish the record durably.
fn finish(a: &Args, root: &OwnedFd, parent: &OwnedFd, mp_rel: &str, src_st: &sys::Stat, published: &mut bool) -> Result<()> {
    let staged = sys::openat2(root, &cstr(mp_rel)?, libc::O_PATH, 0).map_err(pre("the staging mount can't be opened"))?;
    let st = sys::statx(&staged).map_err(pre("the staging mount can't be read"))?;
    if st.dev != src_st.dev || st.ino != src_st.ino {
        return Err(err(Fail::Preflight, "the staged identity differs"));
    }
    let record = format!(
        "{{\"path\":{},\"mode\":{},\"dev\":[{},{}],\"ino\":{},\"uid\":{},\"staging\":{}}}\n",
        quote(a.path),
        quote(a.mode),
        src_st.dev.0,
        src_st.dev.1,
        src_st.ino,
        src_st.uid,
        quote(&format!("/{mp_rel}"))
    );
    let rec_fail = |_| err(Fail::Record, "the record can't be written");
    let tmp = cstr(&format!("{}.record.tmp", a.index))?;
    let fin = cstr(&format!("{}.record", a.index))?;
    let f = sys::openat2(parent, &tmp, libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY, 0o600).map_err(rec_fail)?;
    let mut off = 0;
    while off < record.len() {
        let n = sys::write(&f, &record.as_bytes()[off..]).map_err(rec_fail)?;
        if n == 0 {
            return Err(err(Fail::Record, "the record can't be written"));
        }
        off += n;
    }
    sys::fsync(&f).map_err(rec_fail)?;
    drop(f);
    sys::rename_noreplace(parent, &tmp, &fin).map_err(rec_fail)?;
    *published = true;
    sys::fsync(parent).map_err(rec_fail)?;
    Ok(())
}

/// Contract §3.1: detach exactly the mount this call created, then remove the temp and (if published) the final
/// record, and fsync the directory. Any failure here is 70, "rollback failed".
fn rollback(a: &Args, root: &OwnedFd, parent: &OwnedFd, mp_rel: &str, p_st: &sys::Stat, m_st: &sys::Stat, published: bool) -> Result<()> {
    let failed = || err(Fail::Record, "rollback failed");
    // Re-check: the parent is the recorded one, and the mountpoint now carries a different (the new) mount.
    let p2 = sys::openat2(root, &cstr(&mp_rel[..mp_rel.rfind('/').unwrap()])?, libc::O_PATH | libc::O_DIRECTORY, 0).map_err(|_| failed())?;
    let p2_st = sys::statx(&p2).map_err(|_| failed())?;
    if p2_st.dev != p_st.dev || p2_st.ino != p_st.ino || p2_st.mnt_id != p_st.mnt_id {
        return Err(failed());
    }
    let m2 = sys::openat2(root, &cstr(mp_rel)?, libc::O_PATH, 0).map_err(|_| failed())?;
    let new_mnt = sys::statx(&m2).map_err(|_| failed())?.mnt_id;
    if new_mnt == p_st.mnt_id {
        return Err(failed()); // nothing of ours is mounted there
    }
    drop(m2);
    sys::umount2_detach(&cstr(&format!("/{mp_rel}"))?).map_err(|_| failed())?;
    // Confirm: the mountpoint is back on the parent's mount, with its original identity.
    let m3 = sys::openat2(root, &cstr(mp_rel)?, libc::O_PATH, 0).map_err(|_| failed())?;
    let m3_st = sys::statx(&m3).map_err(|_| failed())?;
    if m3_st.mnt_id != p_st.mnt_id || m3_st.dev != m_st.dev || m3_st.ino != m_st.ino {
        return Err(failed());
    }
    let tmp = cstr(&format!("{}.record.tmp", a.index))?;
    match sys::unlinkat(parent, &tmp) {
        Ok(()) => {}
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {}
        Err(_) => return Err(failed()),
    }
    if published {
        sys::unlinkat(parent, &cstr(&format!("{}.record", a.index))?).map_err(|_| failed())?;
    }
    sys::fsync(parent).map_err(|_| failed())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "abcdefghijklmnopqrstuvwxya";

    #[test]
    fn arguments_are_closed() {
        let rec = format!("/run/sagebrush/binds/{A}/3.record");
        assert!(parse(&[A, "3", "rw", "/data/x", &rec]).is_ok());
        for (i, m, p, r) in [
            ("64", "rw", "/data/x", rec.clone()),
            ("03", "rw", "/data/x", rec.clone()),
            ("+3", "rw", "/data/x", rec.clone()),
            ("3", "rx", "/data/x", rec.clone()),
            ("3", "rw", "/data/x/", rec.clone()),
            ("3", "rw", "/data/x", format!("/run/sagebrush/binds/{A}/4.record")),
            ("3", "rw", "/data/x", format!("/tmp/{A}/3.record")),
        ] {
            assert_eq!(parse(&[A, i, m, p, &r]).err().map(|e| e.fail), Some(Fail::Usage), "{i} {m} {p} {r}");
        }
        assert!(parse(&["not-an-id", "3", "rw", "/data/x", &rec]).is_err());
    }
}
