//! The digest list a restore writes beside its staged data (launcher contract A2 r3.8.2 §4b): every entry of the
//! restored tree, as this process wrote it from the repository's MAC-verified plaintext, in the one listing format the
//! launcher's `tree-digest` also gives for the filled destination. Validation compares the two line for line, so
//! every byte here is fixed by §4b:
//! - JSON Lines: a `{"v":1}` header, one line per entry sorted by its RAW path bytes (no duplicates), then
//!   `{"count":C,"total_bytes":B}`;
//! - entries: `{"path":P,"type":"file","size":N,"mode":M,"sha256":H}`, `{"path":P,"type":"dir","size":0,"mode":M}`,
//!   `{"path":P,"type":"symlink","size":N,"mode":511,"target":T}`, keys in that order, no whitespace;
//! - the EXPECTED mode: `st_mode & 0o7777` with the set-id bits cleared (what fill must leave);
//! - paths and symlink targets in the lossless codec (valid UTF-8 as itself but `%` as `%25`, any other byte `%XX`),
//!   then quoted with only `"` and `\` escaped and every character below U+0020 as `\u00xx`; a symlink's `size` is
//!   its target's raw byte length;
//! - at most `MAX_ENTRIES` entries, `MAX_PATH` raw bytes per relative path and `MAX_LISTING` bytes: past any of
//!   them, the restore fails (`limit`), and nothing is written.
//!
//! The tree is walked without following any link (lstat, `O_NOFOLLOW`), and never leaves its filesystem; it is this
//! process's own fresh staging, under the launcher's sandbox, so nothing else writes it meanwhile. Only directories,
//! regular files and symlinks can be there (the restore creates nothing else); anything else fails the restore.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::error::{Fail, Result};

/// The most entries a listing holds: fill's object bound.
pub const MAX_ENTRIES: usize = 2_000_000;
/// The longest relative path, in raw bytes (§4b).
pub const MAX_PATH: usize = 4096;
/// The longest listing (§4b `MAX_LISTING`).
pub const MAX_LISTING: usize = 512 * 1024 * 1024;

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

/// §4b's one quoting: only `"` and `\` escaped, every character below U+0020 as `\u00xx`, every other as itself.
pub fn quote(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

/// A directory's line (with its newline), for the raw path `raw`.
pub fn line_dir(raw: &[u8], mode: u32) -> String {
    format!("{{\"path\":{},\"type\":\"dir\",\"size\":0,\"mode\":{mode}}}\n", quote(&encode(raw)))
}

/// A regular file's line.
pub fn line_file(raw: &[u8], size: u64, mode: u32, sha: &[u8; 32]) -> String {
    format!("{{\"path\":{},\"type\":\"file\",\"size\":{size},\"mode\":{mode},\"sha256\":\"{}\"}}\n", quote(&encode(raw)), hex(sha))
}

/// A symlink's line: its target in the codec, its size the target's raw byte length.
pub fn line_symlink(raw: &[u8], target: &[u8]) -> String {
    format!("{{\"path\":{},\"type\":\"symlink\",\"size\":{},\"mode\":511,\"target\":{}}}\n", quote(&encode(raw)), target.len(), quote(&encode(target)))
}

/// One entry of the listing, already rendered: its raw path bytes (the sort key: §4b sorts the filesystem's bytes,
/// never the encoded text, whose `%XX` would order differently) and its line.
struct Line {
    key: Vec<u8>,
    text: String,
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A file's SHA-256, read through a handle opened without following a link.
fn sha256_of(path: &Path) -> std::io::Result<[u8; 32]> {
    let mut f: File = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().into())
}

fn fail(msg: String) -> Fail {
    Fail::new("restore_failed", msg)
}

/// The listing of the tree at `root` (not itself an entry), as §4b's bytes.
pub fn listing(root: &Path) -> Result<Vec<u8>> {
    listing_bounded(root, MAX_PATH)
}

fn listing_bounded(root: &Path, max_path: usize) -> Result<Vec<u8>> {
    let top = fs::symlink_metadata(root).map_err(|e| fail(format!("digests: the restored tree: {e}")))?;
    if !top.is_dir() {
        return Err(fail("digests: the restored tree isn't a directory".into()));
    }
    let dev = top.dev();
    let mut lines: Vec<Line> = Vec::new();
    let mut total: u64 = 0;
    // (an explicit stack of (relative raw path, absolute path); no recursion, so no depth limit is needed beyond fill's)
    let mut stack: Vec<(Vec<u8>, std::path::PathBuf)> = vec![(Vec::new(), root.to_path_buf())];
    while let Some((rel, abs)) = stack.pop() {
        let mut names: Vec<std::ffi::OsString> = Vec::new();
        for e in fs::read_dir(&abs).map_err(|e| fail(format!("digests: reading a directory: {e}")))? {
            names.push(e.map_err(|e| fail(format!("digests: reading a directory: {e}")))?.file_name());
        }
        for name in names {
            let mut path = rel.clone();
            if !path.is_empty() {
                path.push(b'/');
            }
            path.extend_from_slice(name.as_bytes());
            if path.len() > max_path {
                return Err(Fail::new("limit", "digests: a path longer than a listing takes"));
            }
            let child = abs.join(&name);
            let m = fs::symlink_metadata(&child).map_err(|e| fail(format!("digests: stat: {e}")))?;
            if m.dev() != dev {
                return Err(fail("digests: a mount inside the restored tree".into()));
            }
            let key = path.clone();
            let mode = m.mode() & 0o7777 & !0o6000;
            let ft = m.file_type();
            let text = if ft.is_dir() {
                let t = line_dir(&path, mode);
                stack.push((path, child));
                t
            } else if ft.is_file() {
                let sha = sha256_of(&child).map_err(|e| fail(format!("digests: reading a file: {e}")))?;
                total += m.size();
                line_file(&path, m.size(), mode, &sha)
            } else if ft.is_symlink() {
                let t = fs::read_link(&child).map_err(|e| fail(format!("digests: reading a symlink: {e}")))?;
                line_symlink(&path, t.as_os_str().as_bytes())
            } else {
                return Err(fail("digests: a special file in the restored tree".into()));
            };
            lines.push(Line { key, text });
            if lines.len() > MAX_ENTRIES {
                return Err(Fail::new("limit", "digests: more entries than a restore takes"));
            }
        }
    }
    lines.sort_by(|a, b| a.key.cmp(&b.key));
    if lines.windows(2).any(|w| w[0].key == w[1].key) {
        return Err(fail("digests: two entries with one path".into()));
    }
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(b"{\"v\":1}\n");
    for l in &lines {
        out.extend_from_slice(l.text.as_bytes());
        if out.len() > MAX_LISTING {
            return Err(Fail::new("limit", "digests: a listing longer than a restore takes"));
        }
    }
    out.extend_from_slice(format!("{{\"count\":{},\"total_bytes\":{total}}}\n", lines.len()).as_bytes());
    if out.len() > MAX_LISTING {
        return Err(Fail::new("limit", "digests: a listing longer than a restore takes"));
    }
    Ok(out)
}

/// Write `bytes` at `path` atomically and durably, never over an existing file: an exclusive temporary file beside
/// it, a full write and fsync, a rename that refuses to replace, then the directory's fsync. Returns its SHA-256 (hex).
pub fn write_new(path: &Path, bytes: &[u8]) -> Result<String> {
    let dir = path.parent().ok_or_else(|| fail("digests: no directory".into()))?;
    let name = path.file_name().ok_or_else(|| fail("digests: no file name".into()))?;
    let tmp = dir.join(format!(".{}.tmp-{}", name.to_string_lossy(), std::process::id()));
    // (a quota or a full filesystem while writing keeps its own code: the restore's quota rule applies to the list too)
    let io = |_what: &str, e: std::io::Error| Fail::from_lib("restore_failed", &e);
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&tmp)
            .map_err(|e| io("creating", e))?;
        f.write_all(bytes).map_err(|e| io("writing", e))?;
        f.sync_all().map_err(|e| io("syncing", e))?;
    }
    let from = std::ffi::CString::new(tmp.as_os_str().as_bytes()).map_err(|_| fail("digests: a NUL in a path".into()))?;
    let to = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| fail("digests: a NUL in a path".into()))?;
    // By the system call itself: musl (the shipped static build) has no renameat2 wrapper.
    // SAFETY: both are valid NUL-terminated strings; AT_FDCWD with absolute paths.
    let r = unsafe {
        libc::syscall(libc::SYS_renameat2, libc::AT_FDCWD, from.as_ptr(), libc::AT_FDCWD, to.as_ptr(), libc::RENAME_NOREPLACE)
    };
    if r != 0 {
        let e = std::io::Error::last_os_error();
        let _ = fs::remove_file(&tmp);
        return Err(io("placing", e));
    }
    File::open(dir).and_then(|d| d.sync_all()).map_err(|e| io("syncing its directory", e))?;
    Ok(hex(&Sha256::digest(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("sb-digests-{tag}-{}-{:?}", std::process::id(), std::thread::current().id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn the_codec_and_the_quoting() {
        assert_eq!(encode(b"a%b"), "a%25b");
        assert_eq!(encode(b"a\xffb"), "a%FFb");
        assert_eq!(encode(b"\xe2\x82"), "%E2%82");
        assert_eq!(encode("é😀".as_bytes()), "é😀");
        assert_eq!(quote("a\nb\"\\\u{1f}\u{7f}\u{2028}é"), "\"a\\u000ab\\\"\\\\\\u001f\u{7f}\u{2028}é\"");
    }

    #[test]
    fn a_listing_is_sorted_canonical_and_exact() {
        let d = tmpdir("list");
        fs::create_dir(d.join("b")).unwrap();
        fs::write(d.join("b/x"), b"hello").unwrap();
        fs::write(d.join("a"), b"").unwrap();
        fs::set_permissions(d.join("a"), fs::Permissions::from_mode(0o4755)).unwrap(); // set-id is never expected
        fs::set_permissions(d.join("b"), fs::Permissions::from_mode(0o2750)).unwrap();
        symlink("../a", d.join("b/l")).unwrap();
        let out = String::from_utf8(listing(&d).unwrap()).unwrap();
        let e = hex(&Sha256::digest(b""));
        let h = hex(&Sha256::digest(b"hello"));
        let xm = fs::metadata(d.join("b/x")).unwrap().mode() & 0o7777 & !0o6000;
        let want = [
            "{\"v\":1}".to_string(),
            format!("{{\"path\":\"a\",\"type\":\"file\",\"size\":0,\"mode\":493,\"sha256\":\"{e}\"}}"),
            "{\"path\":\"b\",\"type\":\"dir\",\"size\":0,\"mode\":488}".to_string(),
            "{\"path\":\"b/l\",\"type\":\"symlink\",\"size\":4,\"mode\":511,\"target\":\"../a\"}".to_string(),
            format!("{{\"path\":\"b/x\",\"type\":\"file\",\"size\":5,\"mode\":{xm},\"sha256\":\"{h}\"}}"),
            "{\"count\":4,\"total_bytes\":5}".to_string(),
        ];
        assert_eq!(out, want.join("\n") + "\n");
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn entries_are_sorted_by_their_raw_bytes_never_their_encoded_text() {
        // Raw order: "%" (0x25) < "d" < "d/%x" < "d/\xff" < "z" < "é" (0xc3) < "\xe2\x82" < "\xff". Sorting the encoded
        // text instead would put "%25", "%E2%82" and "%FF" first, and "é" last.
        let d = tmpdir("order");
        use std::os::unix::ffi::OsStrExt;
        let os = |b: &[u8]| std::ffi::OsStr::from_bytes(b).to_os_string();
        for n in [&b"%"[..], b"z", "é".as_bytes(), b"\xe2\x82", b"\xff"] {
            fs::write(d.join(os(n)), b"").unwrap();
        }
        fs::create_dir(d.join("d")).unwrap();
        fs::write(d.join("d").join(os(b"\xff")), b"").unwrap();
        fs::write(d.join("d").join("%x"), b"").unwrap();
        let out = String::from_utf8(listing(&d).unwrap()).unwrap();
        let paths: Vec<&str> = out.lines().filter_map(|l| l.strip_prefix("{\"path\":\"")).map(|l| &l[..l.find('"').unwrap()]).collect();
        assert_eq!(paths, ["%25", "d", "d/%25x", "d/%FF", "z", "é", "%E2%82", "%FF"], "{out}");
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn names_that_need_the_codec_and_the_quoting() {
        let d = tmpdir("names");
        use std::os::unix::ffi::OsStrExt;
        let odd = std::ffi::OsStr::from_bytes(b"x\xff%\n");
        fs::write(d.join(odd), b"1").unwrap();
        symlink(std::ffi::OsStr::from_bytes(b"t\xfe"), d.join("s")).unwrap();
        let out = String::from_utf8(listing(&d).unwrap()).unwrap();
        assert!(out.contains("{\"path\":\"s\",\"type\":\"symlink\",\"size\":2,\"mode\":511,\"target\":\"t%FE\"}\n"), "{out}");
        assert!(out.contains("{\"path\":\"x%FF%25\\u000a\",\"type\":\"file\",\"size\":1,"), "{out}");
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn specials_and_bounds_fail() {
        let d = tmpdir("special");
        let p = std::ffi::CString::new(d.join("f").as_os_str().as_bytes()).unwrap();
        // SAFETY: a valid path; mkfifo needs no privilege.
        assert_eq!(unsafe { libc::mkfifo(p.as_ptr(), 0o600) }, 0);
        assert_eq!(listing(&d).unwrap_err().code, "restore_failed");
        fs::remove_dir_all(&d).unwrap();
        assert_eq!(listing(Path::new("/nonexistent-sb-digests")).unwrap_err().code, "restore_failed");
    }

    #[test]
    fn written_once_atomically() {
        let d = tmpdir("write");
        let p = d.join("digests.json");
        let h = write_new(&p, b"{\"v\":1}\n{\"count\":0,\"total_bytes\":0}\n").unwrap();
        assert_eq!(h, hex(&Sha256::digest(b"{\"v\":1}\n{\"count\":0,\"total_bytes\":0}\n")));
        assert_eq!(fs::read(&p).unwrap(), b"{\"v\":1}\n{\"count\":0,\"total_bytes\":0}\n");
        // never over an existing file, and no temporary left behind
        assert!(write_new(&p, b"x").is_err());
        assert_eq!(fs::read_dir(&d).unwrap().count(), 1);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn a_path_at_the_raw_byte_bound_is_listed_and_one_more_is_a_limit() {
        assert_eq!(MAX_PATH, 4096);
        // (the bound is checked on the relative path's RAW bytes: "é" is two, "%25" in the codec is one "%")
        for (name, ok) in [("x".repeat(13), true), ("x".repeat(14), false), ("é".repeat(6) + "x", true), ("%".repeat(14), false)] {
            let d = tmpdir("bound");
            fs::create_dir(d.join("abc")).unwrap();
            fs::write(d.join("abc").join(&name), b"1").unwrap();
            // "abc/" + name: 4 + 13 = 17 raw bytes is the bound here
            let r = listing_bounded(&d, 17);
            assert_eq!(r.is_ok(), ok, "{name:?}: {:?}", r.as_ref().err().map(|e| e.code));
            if !ok {
                assert_eq!(r.unwrap_err().code, "limit");
            }
            fs::remove_dir_all(&d).unwrap();
        }
    }

    /// The shared corpus (test/fixtures/listing-corpus.json): every row's line, rendered here, byte for byte.
    #[test]
    fn the_shared_listing_corpus() {
        let text = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../test/fixtures/listing-corpus.json"));
        let rows: serde_json::Value = serde_json::from_str(text).unwrap();
        let unhex = |h: &str| (0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect::<Vec<u8>>();
        let mut n = 0;
        for r in rows["rows"].as_array().unwrap() {
            let raw = unhex(r["raw_path_hex"].as_str().unwrap());
            let mode = r["mode"].as_u64().unwrap() as u32;
            let line = match r["type"].as_str().unwrap() {
                "dir" => line_dir(&raw, mode),
                "file" => {
                    let sha: [u8; 32] = unhex(r["sha256"].as_str().unwrap()).try_into().unwrap();
                    line_file(&raw, r["size"].as_u64().unwrap(), mode, &sha)
                }
                "symlink" => line_symlink(&raw, &unhex(r["raw_target_hex"].as_str().unwrap())),
                t => panic!("type {t}"),
            };
            assert_eq!(line, format!("{}\n", r["line"].as_str().unwrap()), "row {}", r["name"]);
            n += 1;
        }
        assert!(n >= 16, "{n} rows");
    }

}
