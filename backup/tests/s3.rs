//! The backup binary against a real S3 server: SeaweedFS `weed mini` on loopback with throwaway credentials (the
//! same pinned 4.53 the portable tests use; `scripts/fetch-test-s3.sh`). Set SB_TEST_WEED to its path; with
//! SB_TEST_REQUIRE_WEED=1 (CI) a missing server fails the run instead of skipping it. Build with
//! `--features test-loopback-http`: the release build refuses plain http.
//!
//! These are the qualification rows as tests, plus the implementation gates the reviews asked for: no automatic
//! init, refused destinations, no redirect followed, a fragmented and unaligned sparse file, a change that keeps size
//! and mtime, an inode swap, a missing pack failing read-back (with a full cache too), prune's delayed deletion,
//! a second key slot and the manifest dump.

use std::{
    fs,
    io::{Read, Seek, SeekFrom, Write},
    net::{TcpListener, TcpStream},
    os::unix::fs::{FileExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicU16, AtomicUsize, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use serde_json::{json, Value};

const BIN: &str = env!("CARGO_BIN_EXE_sagebrush-agent-backup");

fn weed() -> Option<PathBuf> {
    match std::env::var_os("SB_TEST_WEED") {
        Some(p) => Some(PathBuf::from(p)),
        None => {
            assert!(std::env::var_os("SB_TEST_REQUIRE_WEED").is_none(), "SB_TEST_WEED is required (SB_TEST_REQUIRE_WEED is set)");
            eprintln!("skipping: SB_TEST_WEED is not set");
            None
        }
    }
}

fn tmpdir(tag: &str) -> PathBuf {
    let n = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let d = std::env::temp_dir().join(format!("sbb-{tag}-{}-{n}", std::process::id()));
    fs::create_dir_all(&d).unwrap();
    d
}

/// A restore's place, as the launcher lays out an attempt: `<attempt>/data` to restore into, and the digest list's
/// `<attempt>/digests.json` beside it (launcher contract A2 r3.8.2).
fn staged(tag: &str) -> (PathBuf, PathBuf) {
    let base = tmpdir(tag);
    let dst = base.join("data");
    fs::create_dir(&dst).unwrap();
    (dst, base.join("digests.json"))
}

/// The digest list a restore wrote: present, and the very file its result names by SHA-256.
fn digests_of(r: &Value, dig: &Path) -> String {
    let bytes = fs::read(dig).expect("the digest list is written");
    let h: String = sha2_hex(&bytes);
    assert_eq!(r["digests_sha256"].as_str(), Some(h.as_str()), "the result names the file's hash: {r}");
    String::from_utf8(bytes).unwrap()
}

fn sha2_hex(b: &[u8]) -> String {
    let out = Command::new("sha256sum").stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).spawn().and_then(|mut c| {
        use std::io::Write as _;
        c.stdin.take().unwrap().write_all(b)?;
        c.wait_with_output()
    }).unwrap();
    String::from_utf8(out.stdout).unwrap().split_whitespace().next().unwrap().to_string()
}

fn write_private(p: &Path, data: &str) {
    fs::write(p, data).unwrap();
    fs::set_permissions(p, fs::Permissions::from_mode(0o600)).unwrap();
}

/// weed binds each port + 10000 for gRPC. Every such port stays below the kernel's ephemeral floor (32768), where no
/// outgoing connection can take it before weed binds it.
const GRPC_SAFE_LIMIT: u16 = 32768 - 10000;

/// Five consecutive loopback ports for one server, each with its +10000 (SeaweedFS's gRPC offset) free too, all below
/// the ephemeral range. Blocks are handed out from one counter, so servers started in parallel never share a port.
fn port_block() -> [u16; 5] {
    static NEXT: AtomicU16 = AtomicU16::new(0);
    let base = 10000 + (std::process::id() % 200) as u16 * 40;
    for _ in 0..400 {
        let start = base + NEXT.fetch_add(5, Ordering::SeqCst) % 4000;
        let free = |p: u16| TcpListener::bind(("127.0.0.1", p)).is_ok() && TcpListener::bind(("127.0.0.1", p + 10000)).is_ok();
        if start + 5 < GRPC_SAFE_LIMIT && (start..start + 5).all(free) {
            return [start, start + 1, start + 2, start + 3, start + 4];
        }
    }
    panic!("no free port block");
}

struct Weed {
    child: Child,
    s3: u16,
    filer: u16,
    key: String,
    secret: String,
    _dir: PathBuf,
}

impl Drop for Weed {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Starts weed on a fresh port block. Another process can still take a port between `port_block`'s check and weed's
/// bind, and weed then exits at startup; that is retried on a new block. Any other failure to become ready is not.
fn start_weed(bin: &Path) -> Weed {
    for attempt in 1..=3 {
        match try_start_weed(bin) {
            Ok(w) => return w,
            Err(why) if attempt < 3 => eprintln!("weed exited at startup (attempt {attempt}), retrying on new ports: {why}"),
            Err(why) => panic!("weed exited at startup three times; the last: {why}"),
        }
    }
    unreachable!()
}

/// The weed log's fatal lines (glog's `F` prefix) and its last lines, for a failure message.
fn weed_log_summary(dir: &Path) -> String {
    let log = fs::read_to_string(dir.join("weed.log")).unwrap_or_default();
    let fatal: Vec<&str> = log.lines().filter(|l| l.starts_with('F') || l.contains("address already in use")).take(5).collect();
    let tail: Vec<&str> = log.lines().rev().take(15).collect();
    format!("fatal lines:\n{}\nlast lines first:\n{}", fatal.join("\n"), tail.join("\n"))
}

fn try_start_weed(bin: &Path) -> std::result::Result<Weed, String> {
    let dir = tmpdir("weed");
    let ports = port_block();
    let log = fs::File::create(dir.join("weed.log")).unwrap();
    let key = format!("test{}", std::process::id());
    let secret = format!("s{:x}", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos());
    let child = Command::new(bin)
        .args([
            "mini".to_string(),
            "-bucket=qual".into(),
            format!("-dir={}", dir.display()),
            "-ip=127.0.0.1".into(),
            "-ip.bind=127.0.0.1".into(),
            format!("-master.port={}", ports[0]),
            format!("-volume.port={}", ports[1]),
            format!("-filer.port={}", ports[2]),
            format!("-s3.port={}", ports[3]),
            format!("-admin.port={}", ports[4]),
            "-admin.ui=false".into(),
            "-master.telemetry=false".into(),
            "-webdav=false".into(),
            "-volume.max=16".into(),
            "-master.volumeSizeLimitMB=64".into(),
        ])
        .env_remove("DEBUG")
        .env("AWS_ACCESS_KEY_ID", &key)
        .env("AWS_SECRET_ACCESS_KEY", &secret)
        .stdout(Stdio::null())
        .stderr(log)
        .spawn()
        .expect("weed starts");
    let mut w = Weed { child, s3: ports[3], filer: ports[2], key, secret, _dir: dir.clone() };
    let deadline = Instant::now() + Duration::from_secs(90);
    while Instant::now() < deadline {
        if http_status(w.filer, "GET", "/buckets/qual/") == Some(200) && http_status(w.s3, "GET", "/").is_some() {
            return Ok(w);
        }
        if let Ok(Some(status)) = w.child.try_wait() {
            return Err(format!("ports {ports:?}, {status}; {}", weed_log_summary(&dir)));
        }
        thread::sleep(Duration::from_millis(300));
    }
    panic!("weed didn't become ready on ports {ports:?}; {}", weed_log_summary(&dir));
}

/// A minimal HTTP/1.0 request to the filer (1.0, so the body is never chunked) (list, stat, delete objects); returns the status code.
fn http_status(port: u16, method: &str, path: &str) -> Option<u16> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(10))).ok()?;
    write!(s, "{method} {path} HTTP/1.0\r\nHost: 127.0.0.1\r\nAccept: application/json\r\nConnection: close\r\n\r\n").ok()?;
    let mut buf = String::new();
    let _ = s.read_to_string(&mut buf);
    buf.split_whitespace().nth(1)?.parse().ok()
}

fn http_body(port: u16, path: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    write!(s, "GET {path} HTTP/1.0\r\nHost: 127.0.0.1\r\nAccept: application/json\r\nConnection: close\r\n\r\n").unwrap();
    let mut buf = String::new();
    s.read_to_string(&mut buf).unwrap();
    buf.split_once("\r\n\r\n").map(|(_, b)| b.to_string()).unwrap_or_default()
}

/// A raw object read from the filer (bytes).
fn http_get_bytes(port: u16, path: &str) -> Vec<u8> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    write!(s, "GET {path} HTTP/1.0\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n").unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).unwrap();
    let at = buf.windows(4).position(|w| w == b"\r\n\r\n").expect("an HTTP header") + 4;
    buf[at..].to_vec()
}

/// A raw object written through the filer; returns the status code.
fn http_put(port: u16, path: &str, body: &[u8]) -> u16 {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    write!(s, "PUT {path} HTTP/1.0\r\nHost: 127.0.0.1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
    s.write_all(body).unwrap();
    let mut buf = String::new();
    let _ = s.read_to_string(&mut buf);
    buf.split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0)
}

/// A host's backup state: dest.json, the credential handle's file and host.key, all 0600.
#[derive(Clone)]
struct Host {
    state: PathBuf,
    secrets: PathBuf,
    cache: PathBuf,
    prefix: String,
}

fn host(w: &Weed, prefix: &str) -> Host {
    let base = tmpdir("host");
    let (state, secrets, cache) = (base.join("state"), base.join("secrets"), base.join("cache"));
    for d in [&state, &secrets, &cache] {
        fs::create_dir_all(d).unwrap();
    }
    let dest = json!({
        "type": "s3", "endpoint": format!("http://127.0.0.1:{}", w.s3), "bucket": "qual",
        "prefix": prefix, "region": "us-east-1", "credential": { "secret": "dest-1" }
    });
    write_private(&state.join("dest.json"), &dest.to_string());
    write_private(&secrets.join("dest-1"), &json!({ "access_key_id": w.key, "secret_access_key": w.secret }).to_string());
    write_private(&state.join("host.key"), &format!("hostpw-{prefix}\n"));
    Host { state, secrets, cache, prefix: prefix.to_string() }
}

fn run(h: &Host, req: Value) -> Value {
    run_args(h, req, &[])
}

/// Whether this process's bounding set holds CAP_SYS_RESOURCE (bit 24). Some containers already lack it; a CI runner
/// has it.
fn sys_resource_in_bounding() -> bool {
    let status = fs::read_to_string("/proc/self/status").unwrap();
    let mask = status.lines().find_map(|l| l.strip_prefix("CapBnd:")).map(str::trim).unwrap();
    u64::from_str_radix(mask, 16).unwrap() & (1 << 24) != 0
}

/// How a restore runs here: directly where the capability is already gone, else through `sudo -n setpriv`, which removes
/// CAP_SYS_RESOURCE from the bounding and inheritable sets and returns to this same unprivileged user (so the permitted,
/// effective and ambient sets are empty too). This is the launcher's restore runner's job in production; the binary only checks.
fn restore_prefix() -> Vec<String> {
    if !sys_resource_in_bounding() {
        return Vec::new();
    }
    let sudo_ok = Command::new("sudo").args(["-n", "true"]).stdout(Stdio::null()).stderr(Stdio::null()).status().map(|s| s.success()).unwrap_or(false);
    assert!(sudo_ok, "CAP_SYS_RESOURCE is in the bounding set and there is no passwordless sudo to remove it for the restore rows");
    // SAFETY: getuid and getgid have no preconditions.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    // (--pdeathsig SIGKILL: the binary's parent there is sudo, so it is bound as the launcher's stage binds it, by an
    //  inherited SIGKILL death signal, not by --parent-pid)
    ["sudo", "-n", "setpriv", &format!("--reuid={uid}"), &format!("--regid={gid}"), "--clear-groups", "--bounding-set=-sys_resource", "--inh-caps=-sys_resource", "--pdeathsig", "SIGKILL", "--"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

fn run_args(h: &Host, req: Value, extra: &[&str]) -> Value {
    let prefix = if req["op"] == "restore" { restore_prefix() } else { Vec::new() };
    match prefix.split_first() {
        Some((prog, rest)) => {
            let mut c = Command::new(prog);
            c.args(rest).arg(BIN);
            run_cmd(&mut c, h, req, extra)
        }
        None => run_bound(h, req, extra),
    }
}

/// The binary run directly (this test process its parent), bound by `--parent-pid`, as Node's spawns run it.
fn run_bound(h: &Host, req: Value, extra: &[&str]) -> Value {
    let pid = std::process::id().to_string();
    let mut all: Vec<&str> = vec!["--parent-pid", &pid];
    all.extend_from_slice(extra);
    run_cmd(&mut Command::new(BIN), h, req, &all)
}

/// The binary run directly, with whatever capabilities this process has.
fn run_direct(h: &Host, req: Value) -> Value {
    run_bound(h, req, &[])
}

fn run_cmd(cmd: &mut Command, h: &Host, req: Value, extra: &[&str]) -> Value {
    let mut c = cmd
        .args(["--state", h.state.to_str().unwrap(), "--secrets", h.secrets.to_str().unwrap(), "--cache", h.cache.to_str().unwrap()])
        .args(extra)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    c.stdin.take().unwrap().write_all(req.to_string().as_bytes()).unwrap();
    let out = c.wait_with_output().unwrap();
    let v: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|_| {
        panic!("stdout is one JSON value: {}; stderr: {}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr))
    });
    assert_eq!(out.status.success(), v["ok"] == true, "exit status matches ok: {v}");
    v
}

fn code(v: &Value) -> &str {
    v["error"]["code"].as_str().unwrap_or("")
}

fn snapshot_id(v: &Value) -> String {
    v["snapshot"]["id"].as_str().unwrap().to_string()
}

/// The data extents of a file (SEEK_DATA / SEEK_HOLE).
fn extents(p: &Path) -> Vec<(u64, u64)> {
    let f = fs::File::open(p).unwrap();
    let len = f.metadata().unwrap().len();
    let fd = std::os::unix::io::AsRawFd::as_raw_fd(&f);
    let mut out = Vec::new();
    let mut off = 0i64;
    while (off as u64) < len {
        // SAFETY: lseek on an open fd.
        let d = unsafe { libc::lseek(fd, off, libc::SEEK_DATA) };
        if d < 0 {
            break;
        }
        // SAFETY: as above.
        let h = unsafe { libc::lseek(fd, d, libc::SEEK_HOLE) };
        out.push((d as u64, h as u64));
        off = h;
    }
    out
}

fn allocated(p: &Path) -> u64 {
    use std::os::unix::fs::MetadataExt;
    fs::metadata(p).unwrap().blocks() * 512
}

#[test]
fn rows() {
    let Some(bin) = weed() else { return };
    let w = start_weed(&bin);

    // --- no automatic init; refused destinations; bad file modes ---
    let h = host(&w, "rows");
    let src = tmpdir("src");
    fs::write(src.join("a"), b"hello").unwrap();
    let v = run(&h, json!({ "op": "backup", "sources": [src], "host": "h1" }));
    assert_eq!(code(&v), "repository_missing", "backup never creates a repository: {v}");
    assert_eq!(run(&h, json!({ "op": "init" }))["ok"], true);
    assert_eq!(code(&run(&h, json!({ "op": "init" }))), "repository_exists");

    let bad = host(&w, "bad");
    let dest = fs::read_to_string(bad.state.join("dest.json")).unwrap();
    for (from, to, want) in [
        ("\"type\":\"s3\"", "\"type\":\"sftp\"", "destination_refused"),
        ("http://127.0.0.1", "http://10.0.0.1", "destination_refused"),
        ("http://127.0.0.1", "ftp://127.0.0.1", "destination_refused"),
    ] {
        write_private(&bad.state.join("dest.json"), &dest.replace(from, to));
        assert_eq!(code(&run(&bad, json!({ "op": "init" }))), want, "{from} -> {to}");
    }
    write_private(&bad.state.join("dest.json"), &dest);
    fs::set_permissions(bad.secrets.join("dest-1"), fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(code(&run(&bad, json!({ "op": "init" }))), "config_invalid", "a readable credential file is refused");
    // argv carries no secrets: an unknown flag is a usage error
    assert_eq!(code(&run_args(&h, json!({ "op": "snapshots" }), &["--password", "/x"])), "usage");

    // --- a size+mtime-preserving rewrite and an inode swap are re-read (ctime/inode compared) ---
    let ru = tmpdir("reuse");
    for n in ["a", "b", "c"] {
        fs::write(ru.join(n), vec![n.as_bytes()[0]; 100_000]).unwrap();
    }
    let s1 = run(&h, json!({ "op": "backup", "sources": [ru], "host": "h1", "tags": ["sb-state=good"] }));
    assert_eq!(s1["ok"], true, "{s1}");
    thread::sleep(Duration::from_millis(1100));
    let set_mtime = |p: &Path, t: SystemTime| fs::File::options().write(true).open(p).unwrap().set_modified(t).unwrap();
    let ma = fs::metadata(ru.join("a")).unwrap().modified().unwrap();
    fs::File::options().write(true).open(ru.join("a")).unwrap().write_all_at(&vec![b'z'; 100_000], 0).unwrap();
    set_mtime(&ru.join("a"), ma);
    let mb = fs::metadata(ru.join("b")).unwrap().modified().unwrap();
    fs::write(ru.join("b.tmp"), vec![b'y'; 100_000]).unwrap();
    set_mtime(&ru.join("b.tmp"), mb);
    fs::rename(ru.join("b.tmp"), ru.join("b")).unwrap();
    let s2 = run(&h, json!({ "op": "backup", "sources": [ru], "host": "h1", "parent": snapshot_id(&s1) }));
    assert_eq!(s2["snapshot"]["summary"]["files_changed"], 2, "both are re-read: {s2}");
    assert_eq!(s2["snapshot"]["summary"]["files_unmodified"], 1);

    // --- a fragmented, unaligned sparse file: identical bytes, holes kept, allocation within one block per extent ---
    let sp = tmpdir("sparse");
    let f = sp.join("s.bin");
    {
        let file = fs::File::create(&f).unwrap();
        file.set_len(1 << 30).unwrap();
        for (off, len) in [(12_345u64, 4_097usize), (5_000_003, 100_000), (700_000_001, 1), (1_073_000_000, 70_000)] {
            file.write_all_at(&vec![0xa5; len], off).unwrap();
        }
    }
    let src_ext = extents(&f);
    let sb = run(&h, json!({ "op": "backup", "sources": [sp], "host": "h1" }));
    assert!(sb["snapshot"]["summary"]["data_added_packed"].as_u64().unwrap() < 1 << 20, "holes aren't stored: {sb}");
    let (dst, dig) = staged("restore");
    let r = run(&h, json!({ "op": "restore", "snapshot": snapshot_id(&sb), "dest": dst, "digests": dig }));
    assert_eq!(r["ok"], true, "{r}");
    let list = digests_of(&r, &dig);
    assert!(list.starts_with("{\"v\":1}\n") && list.contains("s.bin\",\"type\":\"file\",\"size\":1073741824,"), "the sparse file is listed by its full size");
    let got = fs::read_dir(&dst).unwrap().count();
    assert!(got > 0);
    let restored = walk_find(&dst, "s.bin").expect("s.bin restored");
    assert_eq!(fs::metadata(&restored).unwrap().len(), 1 << 30);
    let dst_ext = extents(&restored);
    for (a, b) in &src_ext {
        assert!(dst_ext.iter().any(|(c, d)| c <= a && b <= d), "source extent {a}..{b} is data in the restore: {dst_ext:?}");
    }
    let block = 4096;
    assert!(allocated(&restored) <= allocated(&f) + block * src_ext.len() as u64, "at most one extra block per extent");
    let (mut x, mut y) = (fs::File::open(&f).unwrap(), fs::File::open(&restored).unwrap());
    for (a, b) in &src_ext {
        let mut u = vec![0u8; (b - a) as usize];
        let mut v = u.clone();
        x.seek(SeekFrom::Start(*a)).unwrap();
        y.seek(SeekFrom::Start(*a)).unwrap();
        x.read_exact(&mut u).unwrap();
        y.read_exact(&mut v).unwrap();
        assert_eq!(u, v, "the data at {a}..{b} matches");
    }

    // --- a second key slot opens the repository ---
    let pw2 = h.state.join("code.key");
    write_private(&pw2, "backup-code-test\n");
    assert_eq!(run(&h, json!({ "op": "add-key", "password_file": pw2 }))["ok"], true);
    let original = fs::read_to_string(h.state.join("host.key")).unwrap();
    write_private(&h.state.join("host.key"), "backup-code-test\n");
    assert_eq!(run(&h, json!({ "op": "snapshots" }))["ok"], true, "the new slot opens it");
    write_private(&h.state.join("host.key"), "wrong\n");
    assert_eq!(code(&run(&h, json!({ "op": "snapshots" }))), "open_failed", "a wrong password doesn't");
    write_private(&h.state.join("host.key"), &original);

    // --- the manifest is read back with dump ---
    let mf = tmpdir("manifest");
    fs::write(mf.join("manifest.json"), r#"{"v":1}"#).unwrap();
    let sm = run(&h, json!({ "op": "backup", "sources": [mf], "host": "h1", "tags": ["sb-kind=manifest"] }));
    let path = format!("{}/manifest.json", mf.display());
    let d = run(&h, json!({ "op": "dump", "snapshot": snapshot_id(&sm), "path": path }));
    assert_eq!(d["text"], r#"{"v":1}"#, "{d}");

    // --- read-back passes, then fails when a pack is gone; a full cache doesn't hide it ---
    assert_eq!(run(&h, json!({ "op": "readback", "snapshot": snapshot_id(&sm) }))["ok"], true);
    let ro = tmpdir("rocache");
    fs::set_permissions(&ro, fs::Permissions::from_mode(0o500)).unwrap();
    let cf = run_args(&h, json!({ "op": "backup", "sources": [ru], "host": "h1" }), &[]);
    assert_eq!(cf["ok"], true);
    let pack = first_pack(&w, &h.prefix);
    assert_eq!(http_status(w.filer, "DELETE", &format!("/buckets/qual/{}/data/{}/{}", h.prefix, &pack[..2], pack)), Some(204));
    let rb = run(&h, json!({ "op": "readback", "snapshot": snapshot_id(&sm) }));
    assert_eq!(code(&rb), "readback_failed", "a missing pack fails read-back: {rb}");
    let full = Host { state: h.state.clone(), secrets: h.secrets.clone(), cache: ro.join("unwritable"), prefix: h.prefix.clone() };
    let rbf = run(&full, json!({ "op": "readback", "snapshot": snapshot_id(&sm) }));
    assert_eq!(code(&rbf), "readback_failed", "also with an unusable cache: {rbf}");
    assert_eq!(code(&run(&h, json!({ "op": "check-data", "part": 1, "of": 1 }))), "check_failed");
}

/// The cache can't be written: the backup completes, says cache_full, and read-back still decides.
#[test]
fn cache_full_is_a_warning() {
    let Some(bin) = weed() else { return };
    let w = start_weed(&bin);
    let mut h = host(&w, "cachefull");
    assert_eq!(run(&h, json!({ "op": "init" }))["ok"], true);
    // a cache directory that exists but can't be written (the test doesn't run as root in CI)
    let ro = tmpdir("ro");
    fs::set_permissions(&ro, fs::Permissions::from_mode(0o500)).unwrap();
    h.cache = ro.clone();
    let src = tmpdir("cfsrc");
    for i in 0..50 {
        fs::write(src.join(format!("f{i}")), vec![i as u8; 50_000]).unwrap();
    }
    let b = run(&h, json!({ "op": "backup", "sources": [src], "host": "h1" }));
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("running as root: an unwritable cache can't be made with modes; cache_full={}", b["cache_full"]);
    } else {
        assert_eq!(b["ok"], true, "the backup completes: {b}");
        assert_eq!(b["cache_full"], true, "and reports cache_full: {b}");
    }
    assert_eq!(run(&h, json!({ "op": "readback", "snapshot": snapshot_id(&b) }))["ok"], true);
    let pack = first_pack(&w, &h.prefix);
    assert_eq!(http_status(w.filer, "DELETE", &format!("/buckets/qual/{}/data/{}/{}", h.prefix, &pack[..2], pack)), Some(204));
    assert_eq!(code(&run(&h, json!({ "op": "readback", "snapshot": snapshot_id(&b) }))), "readback_failed");
}

/// Prune keeps the packs a forgotten snapshot freed (delayed deletion): every pack that existed before prune is still
/// in the store afterwards (prune may add a repacked one), and check stays OK.
#[test]
fn prune_delays_deletion() {
    let Some(bin) = weed() else { return };
    let w = start_weed(&bin);
    let h = host(&w, "prune");
    assert_eq!(run(&h, json!({ "op": "init" }))["ok"], true);
    let (x, y) = (tmpdir("px"), tmpdir("py"));
    for i in 0..10 {
        fs::write(x.join(format!("f{i}")), vec![(i * 7) as u8; 1 << 20]).unwrap();
        fs::write(y.join(format!("f{i}")), vec![(i * 11 + 1) as u8; 1 << 20]).unwrap();
    }
    let sx = run(&h, json!({ "op": "backup", "sources": [x], "host": "h1" }));
    let _sy = run(&h, json!({ "op": "backup", "sources": [y], "host": "h1" }));
    let before = pack_entries(&w, &h.prefix);
    assert!(!before.is_empty());
    assert_eq!(run(&h, json!({ "op": "forget", "snapshots": [snapshot_id(&sx)] }))["forgotten"], 1);
    let p = run(&h, json!({ "op": "prune" }));
    assert_eq!(p["ok"], true, "{p}");
    let after = pack_entries(&w, &h.prefix);
    let gone: Vec<&String> = before.iter().filter(|p| !after.contains(p)).collect();
    assert!(gone.is_empty(), "packs deleted before keep_delete passed: {gone:?}");
    assert_eq!(run(&h, json!({ "op": "check-data", "part": 1, "of": 1 }))["ok"], true);
}

/// Two snapshots whose ids share their first 8 hex digits: dump and restore by a full id keep the selected snapshot (an
/// abbreviated id would be ambiguous). The second id is made by storing snapshot B's object again under A's 8-digit
/// prefix, so the two prefix-twins hold different trees.
#[test]
fn full_ids_survive_a_shared_prefix() {
    let Some(bin) = weed() else { return };
    let w = start_weed(&bin);
    let h = host(&w, "prefix");
    assert_eq!(run(&h, json!({ "op": "init" }))["ok"], true);
    let (a, b) = (tmpdir("pa"), tmpdir("pb"));
    fs::write(a.join("which"), b"snapshot A").unwrap();
    fs::write(b.join("which"), b"snapshot B").unwrap();
    let sa = snapshot_id(&run(&h, json!({ "op": "backup", "sources": [a], "host": "h1" })));
    let sb = snapshot_id(&run(&h, json!({ "op": "backup", "sources": [b], "host": "h1" })));
    // B's object under a name that shares A's first 8 hex digits
    let twin = format!("{}{}", &sa[..8], if &sb[8..] == &sa[8..] { "0".repeat(56) } else { sb[8..].to_string() });
    assert_ne!(twin, sa);
    let body = http_get_bytes(w.filer, &format!("/buckets/qual/{}/snapshots/{sb}", h.prefix));
    assert!(!body.is_empty());
    let put = http_put(w.filer, &format!("/buckets/qual/{}/snapshots/{twin}", h.prefix), &body);
    assert!((200..300).contains(&put), "stored the prefix twin: http {put}");
    let listed = run(&h, json!({ "op": "snapshots" }));
    let ids: Vec<&str> = listed["snapshots"].as_array().unwrap().iter().map(|s| s["id"].as_str().unwrap()).collect();
    assert_eq!(ids.iter().filter(|i| i.starts_with(&sa[..8])).count(), 2, "two ids share the prefix: {ids:?}");
    let path_a = format!("{}/which", a.to_str().unwrap().trim_start_matches('/'));
    let d = run(&h, json!({ "op": "dump", "snapshot": sa, "path": path_a }));
    assert_eq!(d["text"], "snapshot A", "dump keeps A: {d}");
    let (dst, dig) = staged("prefix-dst");
    let r = run(&h, json!({ "op": "restore", "snapshot": sa, "dest": dst, "digests": dig }));
    assert_eq!(r["ok"], true, "restore of A by its full id: {r}");
    assert_eq!(fs::read(walk_find(&dst, "which").unwrap()).unwrap(), b"snapshot A", "restore keeps A");
    // and the twin, by its own full id, is B's tree
    let path_b = format!("{}/which", b.to_str().unwrap().trim_start_matches('/'));
    let dt = run(&h, json!({ "op": "dump", "snapshot": twin, "path": path_b }));
    assert_eq!(dt["text"], "snapshot B", "dump of the twin keeps B: {dt}");
}

/// A restore never creates a FIFO or a socket (or a device node: the same filter), and never writes an extended
/// attribute: the snapshot records them, the restore skips and counts the special files, and the regular file comes
/// back with its bytes and without the attribute.
#[test]
fn restore_skips_specials_and_attributes() {
    let Some(bin) = weed() else { return };
    let w = start_weed(&bin);
    let h = host(&w, "special");
    assert_eq!(run(&h, json!({ "op": "init" }))["ok"], true);
    let src = tmpdir("special-src");
    fs::write(src.join("plain"), b"plain bytes").unwrap();
    let fifo = std::ffi::CString::new(src.join("pipe").to_str().unwrap()).unwrap();
    // SAFETY: mkfifo with a valid NUL-terminated path.
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o644) }, 0, "mkfifo");
    let _sock = std::os::unix::net::UnixListener::bind(src.join("sock")).unwrap();
    let path = std::ffi::CString::new(src.join("plain").to_str().unwrap()).unwrap();
    let (name, value) = (std::ffi::CString::new("user.sb-test").unwrap(), b"v");
    // SAFETY: setxattr with valid NUL-terminated strings and a live buffer.
    let set = unsafe { libc::setxattr(path.as_ptr(), name.as_ptr(), value.as_ptr().cast(), value.len(), 0) };
    if set != 0 {
        eprintln!("note: this filesystem refuses user xattrs; the attribute half of this row runs where they work");
    }
    let b = run(&h, json!({ "op": "backup", "sources": [src], "host": "h1" }));
    assert_eq!(b["ok"], true, "{b}");
    let (dst, dig) = staged("special-dst");
    let r = run(&h, json!({ "op": "restore", "snapshot": snapshot_id(&b), "dest": dst, "digests": dig }));
    assert_eq!(r["ok"], true, "{r}");
    let list = digests_of(&r, &dig);
    assert!(!list.contains("pipe") && !list.contains("sock"), "the skipped specials aren't listed: {list}");
    assert_eq!(r["skipped_special"], 2, "the FIFO and the socket: {r}");
    assert!(walk_find(&dst, "pipe").is_none() && walk_find(&dst, "sock").is_none(), "no special file restored");
    let plain = walk_find(&dst, "plain").expect("the regular file is restored");
    assert_eq!(fs::read(&plain).unwrap(), b"plain bytes");
    if set == 0 {
        let p = std::ffi::CString::new(plain.to_str().unwrap()).unwrap();
        let mut buf = [0u8; 256];
        // SAFETY: listxattr into a live buffer of the given length.
        let n = unsafe { libc::listxattr(p.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
        assert_eq!(n, 0, "no extended attribute restored: {:?}", String::from_utf8_lossy(&buf[..n.max(0) as usize]));
    }
}

/// usage: the exact entry and inode counts and an upper bound on blocks, from the tree's metadata alone; a restore of
/// the same path, measured on this filesystem, never needs more blocks than the bound or more inodes than counted.
#[test]
fn usage_bounds_a_restore() {
    use std::os::unix::fs::MetadataExt;
    let Some(bin) = weed() else { return };
    let w = start_weed(&bin);
    let h = host(&w, "usage");
    assert_eq!(run(&h, json!({ "op": "init" }))["ok"], true);
    let src = tmpdir("usage-src");
    // A 1 GiB sparse file with a few data runs; a hard-linked pair; symlinks of 59 and 60 bytes; a FIFO (never
    // restored); a directory of 300 entries.
    let sparse = fs::File::create(src.join("sparse.bin")).unwrap();
    sparse.set_len(1 << 30).unwrap();
    for (off, len) in [(0u64, 10_000usize), (300_000_001, 70_000), (1_073_000_000, 4_097)] {
        sparse.write_all_at(&vec![0x5a; len], off).unwrap();
    }
    fs::write(src.join("a"), vec![1u8; 9_000]).unwrap();
    fs::hard_link(src.join("a"), src.join("a-link")).unwrap();
    std::os::unix::fs::symlink("t".repeat(59), src.join("s59")).unwrap();
    std::os::unix::fs::symlink("t".repeat(60), src.join("s60")).unwrap();
    let fifo = std::ffi::CString::new(src.join("pipe").to_str().unwrap()).unwrap();
    // SAFETY: mkfifo with a valid NUL-terminated path.
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o644) }, 0, "mkfifo");
    fs::create_dir(src.join("many")).unwrap();
    for i in 0..300 {
        fs::write(src.join("many").join(format!("entry-number-{i:05}")), b"x").unwrap();
    }
    let b = run(&h, json!({ "op": "backup", "sources": [src], "host": "h1" }));
    assert_eq!(b["ok"], true, "{b}");
    let path = src.to_str().unwrap()[1..].to_string();
    let u = run(&h, json!({ "op": "usage", "snapshot": snapshot_id(&b), "path": path }));
    assert_eq!(u["ok"], true, "{u}");
    assert_eq!(u["snapshot"], b["snapshot"]["id"], "{u}");
    assert_eq!(u["block_size"], 4096);
    // sparse.bin, a, a-link, s59, s60, many, 300 entries; the FIFO isn't restored.
    assert_eq!(u["entries"], 306, "{u}");
    assert_eq!(u["inodes"], 305, "a and a-link are one inode: {u}");
    let bound = u["blocks_upper"].as_u64().unwrap();
    // At the peak of a fill the directory exists twice (made anew; the staged copy stays); files and symlinks are moved.
    assert_eq!(u["peak_inodes"], 305 + 1, "{u}");
    assert!(u["peak_blocks_upper"].as_u64().unwrap() > bound, "{u}");
    // Without reading data it can't know the holes: the bound covers the whole 1 GiB.
    assert!(bound >= (1 << 30) / 4096, "{u}");
    // The restore of the same path, measured.
    let (dst, dig) = staged("usage-dst");
    let r = run(&h, json!({ "op": "restore", "snapshot": snapshot_id(&b), "path": path, "dest": dst, "digests": dig }));
    assert_eq!(r["ok"], true, "{r}");
    let (mut blocks, mut inodes, mut seen) = (0u64, 0u64, std::collections::HashSet::new());
    let mut stack = vec![dst.clone()];
    blocks += fs::symlink_metadata(&dst).unwrap().blocks() * 512 / 4096; // the destination directory itself
    while let Some(d) = stack.pop() {
        for e in fs::read_dir(&d).unwrap().flatten() {
            let m = fs::symlink_metadata(e.path()).unwrap();
            if m.nlink() > 1 && !m.is_dir() && !seen.insert(m.ino()) {
                continue;
            }
            inodes += 1;
            blocks += (m.blocks() * 512).div_ceil(4096);
            if m.is_dir() {
                stack.push(e.path());
            }
        }
    }
    assert_eq!(inodes, 305, "the inode count is exact");
    assert!(blocks <= bound, "the restore used {blocks} blocks, the bound is {bound}");
    // A missing path is an error, never zero.
    let bad = run(&h, json!({ "op": "usage", "snapshot": snapshot_id(&b), "path": "no/such/path" }));
    assert_eq!(code(&bad), "usage_failed", "{bad}");
}

/// Whether this environment can run the rows that need their own mount namespace (`sudo unshare -m`, which needs sudo
/// with CAP_SYS_ADMIN: CI). Where it can't, those rows skip, unless SB_TEST_REQUIRE_NOPROC=1 (set by CI), which makes
/// every such row required.
fn sudo_unshare() -> bool {
    let can = Command::new("sudo").args(["-n", "unshare", "-m", "true"]).stdout(Stdio::null()).stderr(Stdio::null()).status().map(|s| s.success()).unwrap_or(false);
    if !can {
        assert!(std::env::var_os("SB_TEST_REQUIRE_NOPROC").is_none(), "sudo unshare -m is required (SB_TEST_REQUIRE_NOPROC is set)");
        eprintln!("skipping: no sudo unshare -m here");
    }
    can
}

/// Runs a restore in its own mount namespace: `setup` (a shell fragment, run as root) first, then the binary as this
/// user without CAP_SYS_RESOURCE.
fn restore_in_namespace(h: &Host, setup: &str, req: Value) -> Value {
    // SAFETY: getuid and getgid have no preconditions.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    let script = format!(
        "{setup} && \
         exec setpriv --reuid={uid} --regid={gid} --clear-groups --bounding-set=-sys_resource --inh-caps=-sys_resource --pdeathsig SIGKILL -- \"$0\" \"$@\""
    );
    let mut cmd = Command::new("sudo");
    cmd.args(["-n", "unshare", "-m", "--propagation", "private", "--", "sh", "-c", &script, BIN]);
    run_cmd(&mut cmd, h, req, &[])
}

/// The restore's view has no procfs, so the capability check asks the kernel directly. This row runs the restore in its
/// own mount namespace with an empty read-only tmpfs over `/proc`, then without CAP_SYS_RESOURCE.
#[test]
fn restore_runs_without_proc() {
    let Some(bin) = weed() else { return };
    if !sudo_unshare() {
        return;
    }
    let w = start_weed(&bin);
    let h = host(&w, "noproc");
    assert_eq!(run(&h, json!({ "op": "init" }))["ok"], true);
    let src = tmpdir("noproc-src");
    fs::write(src.join("f"), b"no proc").unwrap();
    let b = run(&h, json!({ "op": "backup", "sources": [src], "host": "h1" }));
    assert_eq!(b["ok"], true, "{b}");
    let (dst, dig) = staged("noproc-dst");
    let setup = "mount -t tmpfs -o ro,nosuid,nodev,noexec,size=4k none /proc";
    let r = restore_in_namespace(&h, setup, json!({ "op": "restore", "snapshot": snapshot_id(&b), "dest": dst, "digests": dig }));
    assert_eq!(r["ok"], true, "{r}");
    assert_eq!(fs::read(walk_find(&dst, "f").expect("restored")).unwrap(), b"no proc");
}

/// A restore that runs out of room says which kind: a full filesystem is `no_space` (ENOSPC) and a quota hit is
/// `quota_exceeded` (EDQUOT), so the host can tell a transient failure from a permanent refusal (host backup design
/// r3.3 §5.7). Both are real: the destination is a tmpfs mounted in the restore's own namespace, 256 KiB in all for
/// the first, and with a 256 KiB per-user block quota for the second (tmpfs quotas: Linux 6.6 and later). The
/// snapshot holds 2 MiB.
#[test]
fn restore_reports_a_full_or_quota_limited_target() {
    let Some(bin) = weed() else { return };
    if !sudo_unshare() {
        return;
    }
    let w = start_weed(&bin);
    let h = host(&w, "space");
    assert_eq!(run(&h, json!({ "op": "init" }))["ok"], true);
    let src = tmpdir("space-src");
    let data: Vec<u8> = (0..2u32 << 20).map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8 | 1).collect();
    fs::write(src.join("big"), &data).unwrap();
    let b = run(&h, json!({ "op": "backup", "sources": [src], "host": "h1" }));
    assert_eq!(b["ok"], true, "{b}");
    for (options, want) in [("size=256k", "no_space"), ("size=64m,usrquota,usrquota_block_hardlimit=256k", "quota_exceeded")] {
        let (dst, dig) = staged("space-dst");
        let setup = format!("mount -t tmpfs -o mode=0777,nosuid,nodev,{options} none '{}'", dst.display());
        let r = restore_in_namespace(&h, &setup, json!({ "op": "restore", "snapshot": snapshot_id(&b), "dest": dst, "digests": dig }));
        assert_eq!(r["ok"], false, "{options}: {r}");
        assert_eq!(code(&r), want, "{options}: {r}");
    }
}

/// A restore that still holds CAP_SYS_RESOURCE is refused before anything is read or written (host backup design r3.3 §5.7). Where
/// this environment has already dropped it from the bounding set, the refusal is covered by the unit tests (`caps`)
/// and by CI, whose runner holds it.
#[test]
fn restore_refused_with_sys_resource() {
    if !sys_resource_in_bounding() {
        eprintln!("note: CAP_SYS_RESOURCE isn't in this environment's bounding set; the refusal row runs on CI");
        return;
    }
    let (dst, dig) = staged("capdst");
    let base = tmpdir("caphost");
    let r = run_direct(
        &Host { state: base.clone(), secrets: base.clone(), cache: base.join("c"), prefix: "unused".into() },
        json!({ "op": "restore", "snapshot": "a".repeat(64), "dest": dst, "digests": dig }),
    );
    assert_eq!(code(&r), "capability_refused", "{r}");
    assert!(r["error"]["message"].as_str().unwrap().contains("CapBnd"), "{r}");
    assert_eq!(fs::read_dir(&dst).unwrap().count(), 0, "nothing written");
}

/// No redirect is followed: an endpoint answering 307 to another host fails, and that host sees no request.
#[test]
fn redirects_are_refused() {
    let other = TcpListener::bind("127.0.0.1:0").unwrap();
    let other_port = other.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    {
        let hits = hits.clone();
        other.set_nonblocking(true).unwrap();
        thread::spawn(move || loop {
            if other.accept().is_ok() {
                hits.fetch_add(1, Ordering::SeqCst);
            }
            thread::sleep(Duration::from_millis(5));
        });
    }
    let redirector = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = redirector.local_addr().unwrap().port();
    thread::spawn(move || {
        for s in redirector.incoming().flatten() {
            let mut s = s;
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf);
            let _ = write!(s, "HTTP/1.1 307 Temporary Redirect\r\nLocation: http://127.0.0.1:{other_port}/x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        }
    });
    let base = tmpdir("redir");
    let h = Host { state: base.join("state"), secrets: base.join("secrets"), cache: base.join("cache"), prefix: "r".into() };
    for d in [&h.state, &h.secrets, &h.cache] {
        fs::create_dir_all(d).unwrap();
    }
    write_private(
        &h.state.join("dest.json"),
        &json!({ "type": "s3", "endpoint": format!("http://127.0.0.1:{port}"), "bucket": "qual", "prefix": "r",
                 "region": "us-east-1", "credential": { "secret": "d" } })
        .to_string(),
    );
    write_private(&h.secrets.join("d"), r#"{"access_key_id":"k","secret_access_key":"s"}"#);
    write_private(&h.state.join("host.key"), "pw\n");
    let v = run(&h, json!({ "op": "init" }));
    assert_eq!(v["ok"], false, "{v}");
    thread::sleep(Duration::from_millis(200));
    assert_eq!(hits.load(Ordering::SeqCst), 0, "the redirect target got no connection");
}

fn walk_find(dir: &Path, name: &str) -> Option<PathBuf> {
    for e in fs::read_dir(dir).ok()?.flatten() {
        let p = e.path();
        if p.file_name().map(|n| n == name).unwrap_or(false) {
            return Some(p);
        }
        if e.file_type().ok()?.is_dir() {
            if let Some(f) = walk_find(&p, name) {
                return Some(f);
            }
        }
    }
    None
}

fn pack_entries(w: &Weed, prefix: &str) -> Vec<String> {
    let mut out = Vec::new();
    let top: Value = serde_json::from_str(&http_body(w.filer, &format!("/buckets/qual/{prefix}/data/?limit=1000"))).unwrap_or(Value::Null);
    for e in top["Entries"].as_array().cloned().unwrap_or_default() {
        let sub = e["FullPath"].as_str().unwrap_or("").rsplit('/').next().unwrap_or("").to_string();
        let inner: Value = serde_json::from_str(&http_body(w.filer, &format!("/buckets/qual/{prefix}/data/{sub}/?limit=1000"))).unwrap_or(Value::Null);
        for f in inner["Entries"].as_array().cloned().unwrap_or_default() {
            if let Some(name) = f["FullPath"].as_str().and_then(|p| p.rsplit('/').next()) {
                if name.len() == 64 {
                    out.push(name.to_string());
                }
            }
        }
    }
    out
}

fn first_pack(w: &Weed, prefix: &str) -> String {
    pack_entries(w, prefix).into_iter().next().expect("a pack exists")
}

/// Every page of `tree` from the start, checked for continuity as the host does (config tree design d2r2 §A).
fn tree_all(h: &Host, snapshot: &str, path: &str) -> (Vec<Value>, usize) {
    let (mut all, mut pages, mut cursor) = (Vec::new(), 0usize, Value::Null);
    loop {
        let p = run(h, json!({ "op": "tree", "snapshot": snapshot, "path": path, "cursor": cursor }));
        assert_eq!(p["ok"], true, "{p}");
        let entries = p["entries"].as_array().unwrap();
        assert!(!entries.is_empty(), "never an empty page");
        for e in entries {
            assert_eq!(e["index"].as_u64().unwrap() as usize, all.len(), "index = previous + 1");
            all.push(e.clone());
        }
        pages += 1;
        if p["next"].is_null() {
            return (all, pages);
        }
        let next = p["next"].as_str().unwrap();
        assert!(next.ends_with(&format!(":{}", all.len())), "next names the entry after the page's last: {next}");
        cursor = p["next"].clone();
    }
}

/// tree: the exact listing of a saved subtree (types, modes, owners, link counts, sizes, digests), the requested
/// path's node first; a root-level `.gen-<n>.tmp` emitted but never descended (whatever it holds), a deeper one
/// walked; and the structural refusals (tree_refused).
#[test]
fn tree_lists_a_saved_tree() {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let Some(bin) = weed() else { return };
    let w = start_weed(&bin);
    let h = host(&w, "tree");
    assert_eq!(run(&h, json!({ "op": "init" }))["ok"], true);
    let src = tmpdir("tree-src");
    let set = |p: &Path, m: u32| fs::set_permissions(p, fs::Permissions::from_mode(m)).unwrap();
    set(&src, 0o700);
    fs::create_dir(src.join("d")).unwrap();
    set(&src.join("d"), 0o700);
    fs::write(src.join("d/f600"), b"six hundred\n").unwrap();
    set(&src.join("d/f600"), 0o600);
    fs::write(src.join("f644"), b"x").unwrap();
    set(&src.join("f644"), 0o644);
    // Special bits are stored in Go's high bits: listed as the restore sets them, never dropped.
    fs::write(src.join("suid"), b"s").unwrap();
    set(&src.join("suid"), 0o4600);
    fs::create_dir(src.join("sgid")).unwrap();
    set(&src.join("sgid"), 0o2700);
    fs::create_dir(src.join("sticky")).unwrap();
    set(&src.join("sticky"), 0o1700);
    fs::hard_link(src.join("f644"), src.join("f644-link")).unwrap();
    std::os::unix::fs::symlink("d/f600", src.join("ln")).unwrap();
    let fifo = std::ffi::CString::new(src.join("pipe").to_str().unwrap()).unwrap();
    // SAFETY: mkfifo with a valid NUL-terminated path.
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0, "mkfifo");
    // A root-level leftover holding what the restore's reader never reads: a large sparse file, a deep chain, a
    // non-UTF-8 name. And a DEEPER `.gen-<n>.tmp`, which is an ordinary directory and is walked.
    fs::create_dir(src.join(".gen-3.tmp")).unwrap();
    let big = fs::File::create(src.join(".gen-3.tmp/big")).unwrap();
    big.set_len(300 << 20).unwrap();
    let mut deep = src.join(".gen-3.tmp");
    for _ in 0..80 {
        deep = deep.join("deep-level");
        fs::create_dir(&deep).unwrap();
    }
    fs::write(src.join(".gen-3.tmp").join(std::ffi::OsStr::from_bytes(b"bad-\xff")), b"y").unwrap();
    fs::create_dir(src.join("d/.gen-1.tmp")).unwrap();
    fs::write(src.join("d/.gen-1.tmp/inner"), b"z").unwrap();
    let b = run(&h, json!({ "op": "backup", "sources": [src], "host": "h1" }));
    assert_eq!(b["ok"], true, "{b}");
    let snap = snapshot_id(&b);
    let path = src.to_str().unwrap()[1..].to_string();
    let (all, pages) = tree_all(&h, &snap, &path);
    assert_eq!(pages, 1);
    let by: std::collections::HashMap<String, Value> = all.iter().map(|e| (e["path"].as_str().unwrap().to_string(), e.clone())).collect();
    let mut names: Vec<&String> = by.keys().collect();
    names.sort();
    assert_eq!(names, vec!["", ".gen-3.tmp", "d", "d/.gen-1.tmp", "d/.gen-1.tmp/inner", "d/f600", "f644", "f644-link", "ln", "pipe", "sgid", "sticky", "suid"],
        "the leftover's contents never listed; the deeper one walked");
    assert_eq!(all[0]["path"], "", "the path's own node first");
    let me = fs::metadata(&src).unwrap();
    for e in &all[1..] {
        assert_eq!(e["uid"], me.uid(), "{e}");
        assert_eq!(e["gid"], me.gid(), "{e}");
    }
    // The requested path is a backup SOURCE, and the archiver stores a source's own node with synthesized metadata
    // (no owner, mode 0755), whatever the directory was (here 0700). A restore restores only what's beneath it into
    // its own staged directory, so this node's stored metadata is never used; the config proof checks only its type.
    assert_eq!((by[""]["type"].clone(), by[""]["mode"].clone(), by[""]["uid"].clone(), by[""]["gid"].clone()), (json!("dir"), json!(0o755), Value::Null, Value::Null));
    assert_eq!((by["d/f600"]["type"].clone(), by["d/f600"]["mode"].clone(), by["d/f600"]["size"].clone()), (json!("file"), json!(0o600), json!(12)));
    assert_eq!(by["d/f600"]["sha256"], sha2_hex(b"six hundred\n"));
    assert_eq!((by["f644"]["mode"].clone(), by["f644"]["nlink"].clone(), by["f644-link"]["nlink"].clone()), (json!(0o644), json!(2), json!(2)));
    assert_eq!(by["d/f600"]["nlink"], 1);
    assert_eq!((by["suid"]["mode"].clone(), by["sgid"]["mode"].clone(), by["sticky"]["mode"].clone()), (json!(0o4600), json!(0o2700), json!(0o1700)));
    assert_eq!((by["ln"]["type"].clone(), by["ln"]["sha256"].clone()), (json!("symlink"), Value::Null));
    assert_eq!((by["pipe"]["type"].clone(), by["pipe"]["sha256"].clone()), (json!("other"), Value::Null));
    assert_eq!((by[".gen-3.tmp"]["type"].clone(), by[".gen-3.tmp"]["sha256"].clone()), (json!("dir"), Value::Null));
    // The structural refusals.
    let tree = |path: &str, cursor: Value| run(&h, json!({ "op": "tree", "snapshot": snap, "path": path, "cursor": cursor }));
    assert_eq!(code(&tree("no/such/path", Value::Null)), "tree_absent", "a path not in the snapshot: its own code (d2r7)");
    assert_eq!(code(&tree(&format!("{path}/f644/below"), Value::Null)), "tree_absent", "a component beneath a file");
    let digest = sha2_hex(path.as_bytes());
    assert_eq!(code(&tree(&path, json!(format!("{snap}:{digest}:99")))), "tree_refused", "an index past the end");
    assert_eq!(code(&tree(&path, json!(format!("{}:{digest}:1", "0".repeat(64))))), "tree_refused", "another snapshot");
    assert_eq!(code(&tree(&path, json!(format!("{snap}:{}:1", "0".repeat(64))))), "tree_refused", "another path");
    for bad in ["x", "a:b", &format!("{snap}:{digest}:01"), &format!("{snap}:{digest}:-1"), &format!("{snap}:{digest}:")] {
        assert_eq!(code(&tree(&path, json!(bad))), "tree_refused", "malformed: {bad}");
    }
    // A non-UTF-8 name in a WALKED part is structural.
    let bad_src = tmpdir("tree-bad");
    fs::write(bad_src.join(std::ffi::OsStr::from_bytes(b"bad-\xff")), b"y").unwrap();
    let b2 = run(&h, json!({ "op": "backup", "sources": [bad_src], "host": "h1" }));
    let p2 = run(&h, json!({ "op": "tree", "snapshot": snapshot_id(&b2), "path": &bad_src.to_str().unwrap()[1..], "cursor": null }));
    assert_eq!(code(&p2), "tree_refused", "{p2}");
}

/// tree's pages: the entry bound (2048), the byte bound (4 MiB of serialized entries) and the hash bound (256 MiB
/// of contents) each end a page right before the entry that would pass it; every page continues with no gap or
/// duplicate. N1 (with the test-tree-counters feature): a page served from a cursor reads no contents before its index.
#[test]
fn tree_pages_and_bounds() {
    let Some(bin) = weed() else { return };
    let w = start_weed(&bin);
    let h = host(&w, "tree-pages");
    assert_eq!(run(&h, json!({ "op": "init" }))["ok"], true);
    // The entry bound: the node and 2049 files make 2050 entries: 2048, then 2.
    let src = tmpdir("tree-entries");
    for i in 0..2049 {
        fs::write(src.join(format!("f{i:05}")), b"x").unwrap();
    }
    let b = run(&h, json!({ "op": "backup", "sources": [src], "host": "h1" }));
    let p1 = run(&h, json!({ "op": "tree", "snapshot": snapshot_id(&b), "path": &src.to_str().unwrap()[1..], "cursor": null }));
    assert_eq!(p1["entries"].as_array().unwrap().len(), 2048, "exactly the entry bound");
    let (all, pages) = tree_all(&h, &snapshot_id(&b), &src.to_str().unwrap()[1..]);
    assert_eq!((all.len(), pages), (2050, 2));
    // The byte bound: long paths (about 4 KiB each) end a page by its serialized bytes, well before 2048 entries.
    let src = tmpdir("tree-bytes");
    let mut deep = src.clone();
    for _ in 0..15 {
        deep = deep.join("d".repeat(250));
        fs::create_dir(&deep).unwrap();
    }
    for i in 0..1200 {
        fs::write(deep.join(format!("{i:05}{}", "n".repeat(240))), b"x").unwrap();
    }
    let b = run(&h, json!({ "op": "backup", "sources": [src], "host": "h1" }));
    let path = src.to_str().unwrap()[1..].to_string();
    let p1 = run(&h, json!({ "op": "tree", "snapshot": snapshot_id(&b), "path": &path, "cursor": null }));
    let e1 = p1["entries"].as_array().unwrap();
    let bytes: usize = e1.iter().map(|e| e.to_string().len() + 1).sum();
    assert!(e1.len() < 2048 && bytes <= 4 << 20, "{} entries, {bytes} bytes", e1.len());
    let p2 = run(&h, json!({ "op": "tree", "snapshot": snapshot_id(&b), "path": &path, "cursor": p1["next"] }));
    let first2 = &p2["entries"].as_array().unwrap()[0];
    assert!(bytes + first2.to_string().len() + 1 > 4 << 20, "the next entry would have passed the byte bound");
    let (all, _) = tree_all(&h, &snapshot_id(&b), &path);
    assert_eq!(all.len(), 1 + 15 + 1200);
    // The hash bound, and N1: two 150 MiB files (sparse in the source; their contents still read in full).
    let src = tmpdir("tree-hash");
    for n in ["a", "b"] {
        fs::File::create(src.join(n)).unwrap().set_len(150 << 20).unwrap();
    }
    let b = run(&h, json!({ "op": "backup", "sources": [src], "host": "h1" }));
    let path = src.to_str().unwrap()[1..].to_string();
    let p1 = run(&h, json!({ "op": "tree", "snapshot": snapshot_id(&b), "path": &path, "cursor": null }));
    let names: Vec<&str> = p1["entries"].as_array().unwrap().iter().map(|e| e["path"].as_str().unwrap()).collect();
    assert_eq!(names, vec!["", "a"], "b would pass the hash bound: next page");
    let p2 = run(&h, json!({ "op": "tree", "snapshot": snapshot_id(&b), "path": &path, "cursor": p1["next"] }));
    let names: Vec<&str> = p2["entries"].as_array().unwrap().iter().map(|e| e["path"].as_str().unwrap()).collect();
    assert_eq!((names, p2["next"].clone()), (vec!["b"], Value::Null));
    #[cfg(feature = "test-tree-counters")]
    {
        assert_eq!(p1["content_bytes_read"], 150u64 << 20, "the first page reads a");
        assert_eq!(p2["content_bytes_read"], 150u64 << 20, "a resumed page reads only its own: never a's contents (N1)");
    }
}

/// The config proof against the restore, both real (tree design d2r6's rows): a config tree saved by a real backup,
/// listed by the real `tree` (across pages), proven by the JS proof (proveConfig over these very answers), and restored
/// by the real `restore` then read by agent-config's reader as the restore's config import reads it. The proof's entry
/// equals the restored tree's hash; an invalid descendant and a root that isn't a directory are refused by both.
#[test]
fn tree_proof_matches_the_restore() {
    let Some(bin) = weed() else { return };
    let w = start_weed(&bin);
    let h = host(&w, "tree-proof");
    assert_eq!(run(&h, json!({ "op": "init" }))["ok"], true);
    // SAFETY: getuid has no preconditions.
    let uid = unsafe { libc::getuid() };
    let empty = sha2_hex(b"{\"v\":1,\"entries\":[]}\n");
    let set = |p: &Path, m: u32| fs::set_permissions(p, fs::Permissions::from_mode(m)).unwrap();
    let mkdir = |p: &Path| {
        fs::create_dir(p).unwrap();
        set(p, 0o700);
    };
    let file = |p: &Path, data: &[u8]| {
        fs::write(p, data).unwrap();
        set(p, 0o600);
    };
    // A config tree at <base>/agent-config/<id>: (what it holds).
    let tree = |tag: &str, fill: &dyn Fn(&Path)| -> PathBuf {
        let base = tmpdir(tag);
        set(&base, 0o700);
        mkdir(&base.join("agent-config"));
        let root = base.join("agent-config").join("a".repeat(26));
        mkdir(&root);
        fill(&root);
        root
    };
    let configured = |root: &Path| {
        for g in ["gen-1", "gen-2"] {
            mkdir(&root.join(g));
            file(&root.join(g).join("manifest.json"), format!("{{\"v\":1,\"g\":\"{g}\"}}\n").as_bytes());
            mkdir(&root.join(g).join("skills"));
            mkdir(&root.join(g).join("skills/a"));
            file(&root.join(g).join("skills/a/SKILL.md"), b"x");
            file(&root.join(g).join("a-b"), b"order");
        }
        mkdir(&root.join("gen-2/many"));
        for i in 0..2100 {
            file(&root.join(format!("gen-2/many/f{i:05}")), format!("{i}").as_bytes());
        }
        file(&root.join("current"), b"gen-2\n");
        // The leftovers: a generation in progress (holding what the reader never reads) and a .current.tmp link.
        mkdir(&root.join(".gen-3.tmp"));
        fs::write(root.join(".gen-3.tmp/loose"), b"y").unwrap();
        set(&root.join(".gen-3.tmp/loose"), 0o644);
        std::os::unix::fs::symlink("gen-2\n", root.join(".current.tmp")).unwrap();
    };
    let check_env = |tag: &str, root: &Path, env: &[(&str, &str)]| -> Value {
        let b = run_env(&h, json!({ "op": "backup", "sources": [root], "host": "h1" }), env);
        assert_eq!(b["ok"], true, "{b}");
        let snap = snapshot_id(&b);
        let rel = root.to_str().unwrap()[1..].to_string();
        let mut pages = serde_json::Map::new();
        let mut cursor = Value::Null;
        loop {
            let p = run(&h, json!({ "op": "tree", "snapshot": snap, "path": rel, "cursor": cursor }));
            pages.insert(if cursor.is_null() { "null".to_string() } else { cursor.as_str().unwrap().to_string() }, Value::String(p.to_string()));
            if p["ok"] != true || p["next"].is_null() {
                break;
            }
            cursor = p["next"].clone();
        }
        let dump = run(&h, json!({ "op": "dump", "snapshot": snap, "path": format!("{rel}/current") }));
        let list = run(&h, json!({ "op": "snapshots" }));
        let record = list["snapshots"].as_array().unwrap().iter().find(|s| s["id"] == snap.as_str()).unwrap().clone();
        // As the launcher's restore stage requests it: the saved path's contents into its own fresh 0700 directory.
        // An absent source (an empty one, d2r8 §5) restores nothing there: the stage's directory stays as it is.
        let (data, _) = staged(&format!("{tag}-restore"));
        let restored = data.join("a".repeat(26));
        mkdir(&restored);
        let r = run(&h, json!({ "op": "restore", "snapshot": snap, "path": rel, "dest": restored, "digests": data.join("digests.json") }));
        let first: Value = serde_json::from_str(pages["null"].as_str().unwrap()).unwrap();
        if code(&first) == "tree_absent" {
            assert_eq!(code(&r), "restore_failed", "{tag}: the binary can't restore an absent path: {r}");
        } else {
            assert_eq!(r["ok"], true, "{tag}: {r}");
        }
        let input = tmpdir(&format!("{tag}-input")).join("in.json");
        fs::write(&input, json!({ "snapshot": snap, "root": root, "uid": uid, "record": record, "pages": pages, "dump": dump.to_string(), "restored": restored }).to_string()).unwrap();
        let driver = Path::new(env!("CARGO_MANIFEST_DIR")).join("../test/fixtures/host/tree-proof-check.mjs");
        let out = Command::new("node").arg(driver).arg(&input).output().expect("node runs");
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        let mut v: Value = serde_json::from_slice(&out.stdout).unwrap();
        v["pages"] = json!(pages.len());
        v["first"] = json!(code(&first));
        v["root_mode"] = json!(fs::symlink_metadata(&restored).unwrap().permissions().mode() & 0o7777);
        v
    };
    let check = |tag: &str, root: &Path| check_env(tag, root, &[]);
    // Configured, across pages: the proof's entry is the restored tree's hash (gen-2's), never empty.
    let v = check("proof-configured", &tree("proof-configured", &configured));
    assert!(v["pages"].as_u64().unwrap() >= 2, "{v}");
    assert_eq!(v["root_mode"], 0o700, "the restore keeps the stage's own root: the saved root's synthesized metadata is never applied");
    assert_eq!(v["proof"], v["restored"], "{v}");
    assert!(v["proof"].as_str().unwrap().len() == 64 && v["proof"] != empty.as_str(), "{v}");
    // Never configured: the empty source isn't saved (tree_absent); the strict snapshot naming it proves EMPTY_CONFIG_HASH,
    // and the stage's empty directory reads the same.
    let v = check("proof-empty", &tree("proof-empty", &|_| {}));
    assert_eq!((v["first"].clone(), v["proof"].clone(), v["restored"].clone()), (json!("tree_absent"), json!(empty), json!(empty)), "{v}");
    // The same from a non-strict snapshot (the test-only hook): nothing proves it empty.
    let v = check_env("proof-empty-lax", &tree("proof-empty-lax", &|_| {}), &[("SB_TEST_NONSTRICT", "1")]);
    assert_eq!((v["first"].clone(), v["proof"].clone()), (json!("tree_absent"), json!("code:config_unbound")), "{v}");
    // Invalid descendants: each refused by both (the proof's config_unbound, the reader's refusal).
    let spoils: [(&str, &dyn Fn(&Path)); 4] = [
        ("proof-mode", &|r: &Path| set(&r.join("gen-2/skills/a/SKILL.md"), 0o644)),
        ("proof-suid", &|r: &Path| set(&r.join("gen-2/manifest.json"), 0o4600)),
        ("proof-link", &|r: &Path| std::os::unix::fs::symlink("manifest.json", r.join("gen-2/ln")).unwrap()),
        ("proof-foreign", &|r: &Path| file(&r.join("notes"), b"n")),
    ];
    for (tag, spoil) in spoils {
        let root = tree(tag, &configured);
        spoil(&root);
        let v = check(tag, &root);
        assert_eq!(v["proof"], "code:config_unbound", "{tag}: {v}");
        assert!(v["restored"].as_str().unwrap().starts_with("refused"), "{tag}: {v}");
    }
    // The root not a directory: the saved node is a file.
    let base = tmpdir("proof-file-root");
    let root = base.join("cfg");
    file(&root, b"gen-1\n");
    let v = check("proof-file-root", &root);
    assert_eq!(v["proof"], "code:config_unbound", "{v}");
    assert!(v["restored"].as_str().unwrap().starts_with("refused"), "{v}");
}

/// The binary run with extra environment (the test-only hooks), bound like Node's spawns.
fn run_env(h: &Host, req: Value, env: &[(&str, &str)]) -> Value {
    let pid = std::process::id().to_string();
    let mut c = Command::new(BIN);
    for (k, v) in env {
        c.env(k, v);
    }
    run_cmd(&mut c, h, req, &["--parent-pid", &pid])
}

fn snapshot_ids(h: &Host) -> Vec<String> {
    let l = run(h, json!({ "op": "snapshots" }));
    assert_eq!(l["ok"], true, "{l}");
    let mut ids: Vec<String> = l["snapshots"].as_array().unwrap().iter().map(|s| s["id"].as_str().unwrap().to_string()).collect();
    ids.sort();
    ids
}

/// A backup through the test-only gate: `change` runs between the sources' canonicalization and the walk.
fn backup_gated(h: &Host, sources: &[&Path], change: &dyn Fn()) -> Value {
    let gate = tmpdir("gate");
    let (h2, g2) = (h.clone(), gate.clone());
    let srcs: Vec<PathBuf> = sources.iter().map(|p| p.to_path_buf()).collect();
    let t = thread::spawn(move || run_env(&h2, json!({ "op": "backup", "sources": srcs, "host": "h1" }), &[("SB_TEST_SANITIZED_GATE", g2.to_str().unwrap())]));
    let t0 = std::time::Instant::now();
    while !gate.join("ready").exists() {
        assert!(t0.elapsed() < Duration::from_secs(120), "the binary never reached the gate");
        thread::sleep(Duration::from_millis(20));
    }
    change();
    fs::write(gate.join("go"), b"").unwrap();
    t.join().unwrap()
}

/// Strict backups (config tree d2r8, S1): every error while walking a source fails the WHOLE backup, with a closed
/// code and no snapshot committed; a genuinely empty source is a good, marked snapshot that holds no node for it; the
/// mark is the binary's own. (The strict=false control is the SB_TEST_NONSTRICT row: the same unreadable source then
/// commits a snapshot with it silently left out.)
#[test]
fn strict_backups_leave_nothing_out() {
    let Some(bin) = weed() else { return };
    let w = start_weed(&bin);
    let h = host(&w, "strict");
    assert_eq!(run(&h, json!({ "op": "init" }))["ok"], true);
    let set = |p: &Path, m: u32| fs::set_permissions(p, fs::Permissions::from_mode(m)).unwrap();
    let rel = |p: &Path| p.to_str().unwrap()[1..].to_string();
    // A config-like source with content, and another source beside it.
    let source = |tag: &str| -> (PathBuf, PathBuf) {
        let base = tmpdir(tag);
        let other = base.join("home");
        fs::create_dir(&other).unwrap();
        fs::write(other.join("notes"), b"n").unwrap();
        let cfg = base.join("cfg");
        fs::create_dir(&cfg).unwrap();
        fs::create_dir(cfg.join("gen-1")).unwrap();
        fs::write(cfg.join("gen-1/manifest.json"), b"{}").unwrap();
        fs::write(cfg.join("current"), b"gen-1\n").unwrap();
        (other, cfg)
    };
    let failed = |what: &str, r: &Value, before: &[String]| {
        assert_eq!((r["ok"].clone(), code(r)), (json!(false), "backup_failed"), "{what}: {r}");
        assert_eq!(snapshot_ids(&h), before, "{what}: no snapshot committed");
    };
    // SAFETY: getuid has no preconditions.
    let root = unsafe { libc::getuid() } == 0; // (root reads a 0000 file: those rows need an ordinary user, as CI is)

    // The good case first: a marked snapshot.
    let (home, cfg) = source("strict-good");
    let ok = run(&h, json!({ "op": "backup", "sources": [home, cfg], "host": "h1", "tags": ["sb-state=good"] }));
    assert_eq!(ok["ok"], true, "{ok}");
    let mut t: Vec<String> = ok["snapshot"]["tags"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
    t.sort();
    assert_eq!(t, ["sagebrush.walk=strict", "sb-state=good"], "the caller's tags and the binary's mark (stored sorted)");
    // The mark is never a caller's.
    for tag in ["sagebrush.walk=strict", "sagebrush.walk=lax"] {
        let r = run(&h, json!({ "op": "backup", "sources": [home], "host": "h1", "tags": [tag] }));
        assert_eq!(code(&r), "request_invalid", "{tag}: {r}");
    }
    // T4: 63 caller tags, and the mark makes 64; 64 caller tags leave no room for it.
    let tags: Vec<String> = (0..64).map(|i| format!("t{i}=x")).collect();
    assert_eq!(code(&run(&h, json!({ "op": "backup", "sources": [home], "host": "h1", "tags": tags }))), "request_invalid", "64 caller tags leave no room for the mark");
    let r = run(&h, json!({ "op": "backup", "sources": [home], "host": "h1", "tags": tags[..63] }));
    assert_eq!(r["ok"], true, "{r}");
    let got = r["snapshot"]["tags"].as_array().unwrap();
    assert_eq!((got.len(), got.contains(&json!("sagebrush.walk=strict"))), (64, true), "63 tags and the mark");
    // T5: tags are case-sensitive: another case is an ordinary caller tag, and the mark is still added.
    let r = run(&h, json!({ "op": "backup", "sources": [home], "host": "h1", "tags": ["SAGEBRUSH.WALK=strict"] }));
    let got = r["snapshot"]["tags"].as_array().unwrap();
    assert!(got.len() == 2 && got.contains(&json!("SAGEBRUSH.WALK=strict")) && got.contains(&json!("sagebrush.walk=strict")), "{r}");

    // (a) The source removed after canonicalization, before the walk.
    let (home, cfg) = source("strict-vanish");
    let before = snapshot_ids(&h);
    let r = backup_gated(&h, &[&home, &cfg], &|| fs::remove_dir_all(&cfg).unwrap());
    failed("a vanished source", &r, &before);
    // (b) The source replaced by a link or by a file after canonicalization: refused, or stored as what replaced it
    // (present, never absent: the config proof refuses a root that isn't a directory, and no empty source is read).
    for (what, swap) in [("a link", true), ("a file", false)] {
        let (home, cfg) = source(&format!("strict-swap-{}", if swap { "link" } else { "file" }));
        let elsewhere = cfg.with_file_name("elsewhere");
        let before = snapshot_ids(&h);
        let r = backup_gated(&h, &[&home, &cfg], &|| {
            fs::rename(&cfg, &elsewhere).unwrap();
            if swap { std::os::unix::fs::symlink(&elsewhere, &cfg).unwrap() } else { fs::write(&cfg, b"x").unwrap() }
        });
        if r["ok"] == true {
            let p = run(&h, json!({ "op": "tree", "snapshot": snapshot_id(&r), "path": rel(&cfg), "cursor": null }));
            assert_eq!(p["ok"], true, "{what}: the swapped path is present: {p}");
            let kind = p["entries"][0]["type"].as_str().unwrap().to_string();
            assert_eq!(kind, if swap { "symlink" } else { "file" }, "{what}: stored as what replaced it");
            println!("swap {what}: stored as a {kind} node");
        } else {
            failed(what, &r, &before);
            println!("swap {what}: refused");
        }
    }
    if !root {
        // (c) A 0000 `current` file beneath the source; a 0000 directory beneath it.
        let (home, cfg) = source("strict-current");
        set(&cfg.join("current"), 0o000);
        let before = snapshot_ids(&h);
        failed("a 0000 current", &run(&h, json!({ "op": "backup", "sources": [home, cfg], "host": "h1" })), &before);
        let (home, cfg) = source("strict-dir");
        set(&cfg.join("gen-1"), 0o000);
        failed("a 0000 directory", &run(&h, json!({ "op": "backup", "sources": [home, cfg.clone()], "host": "h1" })), &before);
        // The control (strict off, through the test-only hook): the same source commits a snapshot with the
        // directory silently left out, and unmarked.
        let r = run_env(&h, json!({ "op": "backup", "sources": [home, cfg.clone()], "host": "h1" }), &[("SB_TEST_NONSTRICT", "1")]);
        assert_eq!(r["ok"], true, "{r}");
        assert_eq!(r["snapshot"]["tags"], json!([]), "a non-strict snapshot carries no mark");
        let p = run(&h, json!({ "op": "tree", "snapshot": snapshot_id(&r), "path": rel(&cfg), "cursor": null }));
        let paths: Vec<&str> = p["entries"].as_array().unwrap().iter().map(|e| e["path"].as_str().unwrap()).collect();
        assert!(!paths.contains(&"gen-1/manifest.json"), "left out without strict: {paths:?}");
        set(&cfg.join("gen-1"), 0o755);
    }
    // A genuinely empty source: a good, marked snapshot that names it and holds no node for it (tree_absent).
    let (home, cfg) = source("strict-empty");
    fs::remove_dir_all(&cfg).unwrap();
    fs::create_dir(&cfg).unwrap();
    let r = run(&h, json!({ "op": "backup", "sources": [home, cfg], "host": "h1" }));
    assert_eq!(r["ok"], true, "{r}");
    assert!(r["snapshot"]["tags"].as_array().unwrap().contains(&json!("sagebrush.walk=strict")));
    assert!(r["snapshot"]["paths"].as_array().unwrap().contains(&json!(cfg)), "{r}");
    let p = run(&h, json!({ "op": "tree", "snapshot": snapshot_id(&r), "path": rel(&cfg), "cursor": null }));
    assert_eq!(code(&p), "tree_absent", "{p}");
}

/// T6 (config tree d2r10): strict and the mark for every class's shape of sources: an agent's three, an archive's two,
/// a tag folder, the host store's copy. Each with a 0000 descendant fails with no snapshot committed; each good run's
/// snapshot carries the mark. (The binary has one backup path; this pins that no class's shape escapes it.)
#[test]
fn strict_for_every_class() {
    let Some(bin) = weed() else { return };
    // SAFETY: getuid has no preconditions.
    if unsafe { libc::getuid() } == 0 {
        return; // (root reads a 0000 file; CI runs as an ordinary user)
    }
    let w = start_weed(&bin);
    let h = host(&w, "classes");
    assert_eq!(run(&h, json!({ "op": "init" }))["ok"], true);
    let set = |p: &Path, m: u32| fs::set_permissions(p, fs::Permissions::from_mode(m)).unwrap();
    for (class, n) in [("agent", 3), ("archive", 2), ("tag", 1), ("hoststore", 1)] {
        let base = tmpdir(&format!("class-{class}"));
        let sources: Vec<PathBuf> = (0..n).map(|i| {
            let d = base.join(format!("s{i}"));
            fs::create_dir_all(d.join("sub")).unwrap();
            fs::write(d.join("sub/f"), b"x").unwrap();
            d
        }).collect();
        let tags = json!([format!("sb-kind={class}")]);
        let ok = run(&h, json!({ "op": "backup", "sources": sources, "host": "h1", "tags": tags }));
        assert_eq!(ok["ok"], true, "{class}: {ok}");
        assert!(ok["snapshot"]["tags"].as_array().unwrap().contains(&json!("sagebrush.walk=strict")), "{class}: marked: {ok}");
        let before = snapshot_ids(&h);
        let last = sources.last().unwrap();
        set(&last.join("sub"), 0o000);
        let r = run(&h, json!({ "op": "backup", "sources": sources, "host": "h1", "tags": tags }));
        set(&last.join("sub"), 0o755);
        assert_eq!((r["ok"].clone(), code(&r)), (json!(false), "backup_failed"), "{class}: {r}");
        assert_eq!(snapshot_ids(&h), before, "{class}: no snapshot committed");
    }
}

/// P2 (config tree d2r10): a parent never hides a rewrite. A file rewritten after a good snapshot A with its size and
/// mtime put back (`touch -d`) is re-read by a backup B whose parent is A (ctime and inode are always compared), and
/// restoring B gives the new content.
#[test]
fn a_parent_never_hides_a_rewrite() {
    let Some(bin) = weed() else { return };
    let w = start_weed(&bin);
    let h = host(&w, "parent");
    assert_eq!(run(&h, json!({ "op": "init" }))["ok"], true);
    let src = tmpdir("parent-src");
    let f = src.join("f");
    fs::write(&f, b"old content\n").unwrap();
    let a = run(&h, json!({ "op": "backup", "sources": [src], "host": "h1" }));
    assert_eq!(a["ok"], true, "{a}");
    let mtime = fs::metadata(&f).unwrap().modified().unwrap();
    thread::sleep(Duration::from_millis(1100));
    fs::write(&f, b"new content\n").unwrap(); // (the same size)
    fs::File::options().write(true).open(&f).unwrap().set_modified(mtime).unwrap(); // (touch -d: the old mtime)
    assert_eq!(fs::metadata(&f).unwrap().modified().unwrap(), mtime);
    let b = run(&h, json!({ "op": "backup", "sources": [src], "host": "h1", "parent": snapshot_id(&a) }));
    assert_eq!(b["ok"], true, "{b}");
    assert_eq!(b["snapshot"]["summary"]["files_changed"], 1, "re-read, not reused from the parent: {b}");
    let rel = src.to_str().unwrap()[1..].to_string();
    let (data, _) = staged("parent-restore");
    let dest = data.join("d");
    fs::create_dir(&dest).unwrap();
    let r = run(&h, json!({ "op": "restore", "snapshot": snapshot_id(&b), "path": rel, "dest": dest, "digests": data.join("digests.json") }));
    assert_eq!(r["ok"], true, "{r}");
    assert_eq!(fs::read(dest.join("f")).unwrap(), b"new content\n");
}
