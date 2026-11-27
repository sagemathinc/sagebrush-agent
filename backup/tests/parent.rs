//! The binary's parent binding (host backup init/run d3 §5.3): `--parent-pid`, checked before and after
//! PR_SET_PDEATHSIG(SIGKILL); without it, only an inherited SIGKILL death signal; neither refuses before any work. No S3
//! server: every row stops at or just past the binding (a missing state directory is the first thing after it).

use std::{
    fs,
    io::Write,
    os::unix::process::CommandExt,
    path::PathBuf,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_sagebrush-agent-backup");

/// A fresh directory whose path is plain (letters, digits, '-', '/'), so a shell row can use it unquoted.
fn tmpdir(tag: &str) -> PathBuf {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let d = std::env::temp_dir().join(format!("sb-parent-{tag}-{}-{n}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

/// Runs the binary with `extra` args (and `pre` before exec), the request on stdin; returns the error code (or "ok").
fn code_of(extra: &[&str], pre: Option<libc::c_int>) -> String {
    let d = tmpdir("run");
    let mut cmd = Command::new(BIN);
    cmd.args(["--state", d.join("no-state").to_str().unwrap(), "--secrets", d.join("no-secrets").to_str().unwrap()]).args(extra);
    if let Some(sig) = pre {
        // SAFETY: prctl is async-signal-safe; it only sets this child's death signal before exec.
        unsafe {
            cmd.pre_exec(move || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, sig as libc::c_ulong, 0 as libc::c_ulong, 0 as libc::c_ulong, 0 as libc::c_ulong) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    let mut c = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    c.stdin.take().unwrap().write_all(br#"{"op":"snapshots"}"#).unwrap();
    let out = c.wait_with_output().unwrap();
    let v: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|_| panic!("one JSON line: {}", String::from_utf8_lossy(&out.stdout)));
    if v["ok"] == true { "ok".into() } else { v["error"]["code"].as_str().unwrap_or("").to_string() }
}

/// Past the binding: the run goes on to its configuration, which is missing here.
fn past_binding(code: &str) -> bool {
    !["usage", "parent_gone"].contains(&code)
}

#[test]
fn with_the_flag_the_parent_must_be_the_one_named() {
    let me = std::process::id().to_string();
    assert!(past_binding(&code_of(&["--parent-pid", &me], None)), "this process is the parent: bound");
    assert_eq!(code_of(&["--parent-pid", "1"], None), "parent_gone", "another pid: refused before any work");
    for bad in ["0", "-5", "+5", "05", "x", "", "99999999999", "2147483648"] {
        assert_eq!(code_of(&["--parent-pid", bad], None), "usage", "{bad:?} isn't a process id");
    }
    assert_eq!(code_of(&["--parent-pid", &me, "--parent-pid", &me], None), "usage", "once");
}

#[test]
fn without_the_flag_only_an_inherited_sigkill_death_signal() {
    assert_eq!(code_of(&[], None), "usage", "neither: refused before any work");
    assert!(past_binding(&code_of(&[], Some(libc::SIGKILL))), "the launcher's stage: inherited SIGKILL");
    assert_eq!(code_of(&[], Some(libc::SIGTERM)), "usage", "another death signal isn't enough");
}

/// Whether `pid` has exited (gone, or a zombie waiting for its reaper).
fn exited(pid: i32) -> bool {
    match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Err(_) => true,
        Ok(s) => s.rsplit_once(") ").map(|(_, rest)| rest.starts_with('Z') || rest.starts_with('X')).unwrap_or(true),
    }
}

#[test]
fn a_parent_killed_mid_run_takes_the_binary_with_it() {
    // sh is the parent (--parent-pid $$), the binary its direct child; the binary blocks reading a request that never
    // ends (a FIFO sh holds open read-write, so there is always a writer and never data).
    let d = tmpdir("kill");
    let pidfile = d.join("pid");
    let script = format!(
        "mkfifo '{f}'; exec 3<>'{f}'; \"$0\" --state '{s}' --secrets '{s}' --parent-pid $$ <&3 & echo $! > '{p}'; wait",
        f = d.join("fifo").display(),
        s = d.join("none").display(),
        p = pidfile.display()
    );
    let mut sh = Command::new("sh").args(["-c", &script, BIN]).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    let t0 = Instant::now();
    let pid: i32 = loop {
        if let Ok(t) = fs::read_to_string(&pidfile) {
            if let Ok(p) = t.trim().parse() {
                break p;
            }
        }
        assert!(t0.elapsed() < Duration::from_secs(10), "the binary started");
        thread::sleep(Duration::from_millis(20));
    };
    thread::sleep(Duration::from_millis(300)); // (bound by now: it is blocked on its request)
    assert!(!exited(pid), "the binary runs while its parent lives");
    sh.kill().unwrap(); // SIGKILL
    let _ = sh.wait();
    let t1 = Instant::now();
    while !exited(pid) {
        assert!(t1.elapsed() < Duration::from_secs(5), "the binary died with its parent");
        thread::sleep(Duration::from_millis(20));
    }
}

/// The deterministic row: the parent exits BEFORE the binary's first check (the test feature's pause holds it there),
/// so every getppid() sees the reaper. The binary refuses, having done nothing.
#[cfg(feature = "test-pause-before-start")]
#[test]
fn a_parent_dead_before_the_first_check_is_caught() {
    let d = tmpdir("early");
    let out = d.join("out");
    let script = format!(
        "SB_TEST_PAUSE_MS=700 \"$0\" --state '{s}' --secrets '{s}' --parent-pid $$ < /dev/null > '{o}' 2>/dev/null & exit 0",
        s = d.join("none").display(),
        o = out.display()
    );
    let st = Command::new("sh").args(["-c", &script, BIN]).status().unwrap();
    assert!(st.success());
    let t0 = Instant::now();
    loop {
        if let Ok(t) = fs::read_to_string(&out) {
            if !t.is_empty() {
                let v: Value = serde_json::from_str(t.trim()).unwrap();
                assert_eq!(v["error"]["code"], "parent_gone", "{v}");
                break;
            }
        }
        assert!(t0.elapsed() < Duration::from_secs(10), "the binary answered");
        thread::sleep(Duration::from_millis(50));
    }
}
