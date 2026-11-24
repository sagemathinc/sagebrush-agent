//! The real binary, spawned: every exit code reachable without privilege, and (where the kernel has Landlock ABI 4)
//! an end-to-end `exec` under Landlock. `stage-bind`'s mount path needs root: it is qualified on the VM (contract §8).

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

const A: &str = "abcdefghijklmnopqrstuvwxya";
const BIN: &str = env!("CARGO_BIN_EXE_sagebrush-agent-launch");

static SEQ: AtomicUsize = AtomicUsize::new(0);

/// A fresh directory per call (tests run in parallel: never shared).
fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("sbl-test-{}-{name}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::SeqCst)));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(d.join("work")).unwrap();
    fs::create_dir_all(d.join("creds")).unwrap();
    // A stray old Claude placeholder file: the launcher must neither need nor pass it on.
    fs::write(d.join("creds/broker-placeholder"), "placeholder-123").unwrap();
    fs::write(d.join("creds/workspace-capability"), "cap-456").unwrap();
    d
}

fn contract(d: &Path, staged: &str) -> PathBuf {
    let rules = format!(
        r#"{{"path":"/usr","access":"rx"}},{{"path":"/etc","access":"r"}},{{"path":"/proc","access":"r"}},{{"path":"{w}","access":"rwx"}},{{"path":"{c}","access":"r"}}"#,
        w = d.join("work").display(),
        c = d.join("creds").display()
    );
    let p = d.join("contract.json");
    fs::write(&p, format!(r#"{{"v":1,"agent":"{A}","rules":[{rules}],"staged":[{staged}],"env":[["PATH","/usr/bin"]]}}"#)).unwrap();
    p
}

fn exec(d: &Path, contract: &Path, cli: &str, args: &[&str]) -> Output {
    let mut c = Command::new(BIN);
    c.env_clear().env("CREDENTIALS_DIRECTORY", d.join("creds"));
    c.args(["exec", "--agent", A, "--contract", contract.to_str().unwrap(), "--cli", cli, "--"]);
    c.args(args);
    c.output().unwrap()
}

fn code(o: &Output) -> i32 {
    o.status.code().unwrap_or(-1)
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// The kernel's Landlock ABI, asked INDEPENDENTLY of the launcher under test: landlock_create_ruleset(NULL, 0,
/// LANDLOCK_CREATE_RULESET_VERSION) straight from this test (test code, not part of the binary's inventory).
fn kernel_abi() -> i64 {
    // SAFETY: the documented ABI query; a NULL attr with size 0 and the VERSION flag reads nothing.
    unsafe { libc::syscall(libc::SYS_landlock_create_ruleset, std::ptr::null::<u8>(), 0usize, 1u32) }
}

/// Where the kernel supports ABI 4, the launcher's positive control MUST succeed: a skip there is a failure.
fn landlock_abi4() -> bool {
    if kernel_abi() < 4 {
        eprintln!("this kernel has no Landlock ABI 4 (independent query): the Landlock rows run on the VM");
        return false;
    }
    let d = tmp("probe");
    let o = exec(&d, &contract(&d, ""), "/usr/bin/true", &[]);
    let _ = fs::remove_dir_all(&d);
    assert_eq!(code(&o), 0, "the kernel has ABI 4, so the launcher's positive control must succeed: {}", stderr(&o));
    true
}

#[test]
fn the_positive_control_succeeds_wherever_the_kernel_has_abi_4() {
    if kernel_abi() >= 4 {
        assert!(landlock_abi4());
    }
}

#[test]
fn usage_is_64_with_a_fixed_line() {
    for args in [vec![], vec!["bogus"], vec!["exec", "--agent", A], vec!["stage-bind", "--agent", "x"]] {
        let o = Command::new(BIN).args(&args).env_clear().output().unwrap();
        assert_eq!(code(&o), 64, "{args:?}");
        assert_eq!(stderr(&o), "sagebrush-agent-launch: usage: bad arguments\n");
    }
}

#[test]
fn a_bad_contract_is_65() {
    let d = tmp("c65");
    let c = d.join("contract.json");
    for bad in ["{".to_string(), r#"{"v":2}"#.to_string(), format!(r#"{{"v":1,"agent":"{A}","rules":[],"staged":[],"env":[]}}"#)] {
        fs::write(&c, &bad).unwrap();
        let o = exec(&d, &c, "/usr/bin/true", &[]);
        assert_eq!(code(&o), 65, "{bad}: {}", stderr(&o));
        assert!(!stderr(&o).contains(&*d.to_string_lossy()), "never echoes a path");
    }
    let _ = fs::remove_dir_all(&d);
}

#[test]
fn a_staged_identity_mismatch_is_66_before_any_landlock() {
    let d = tmp("s66");
    let work = d.join("work");
    let m = fs::metadata(&work).unwrap();
    // Any dev with ino + 1 is a mismatch.
    let staged = format!(r#"{{"index":0,"path":"{}","mode":"rw","dev":[0,0],"ino":{}}}"#, work.display(), m.ino() + 1);
    let o = exec(&d, &contract(&d, &staged), "/usr/bin/true", &[]);
    assert_eq!(code(&o), 66, "{}", stderr(&o));
    let _ = fs::remove_dir_all(&d);
}

#[test]
fn a_symlinked_contract_path_is_66() {
    // RESOLVE_NO_SYMLINKS: /bin is a symlink on merged-usr systems, and a rule naming it is refused, never followed.
    if !fs::symlink_metadata("/bin").map(|m| m.file_type().is_symlink()).unwrap_or(false) {
        return;
    }
    let d = tmp("sym66");
    let p = d.join("contract.json");
    fs::write(&p, format!(r#"{{"v":1,"agent":"{A}","rules":[{{"path":"/bin","access":"rx"}}],"staged":[],"env":[]}}"#)).unwrap();
    if landlock_abi4() {
        let o = exec(&d, &p, "/usr/bin/true", &[]);
        assert_eq!(code(&o), 66, "{}", stderr(&o));
    }
    let _ = fs::remove_dir_all(&d);
}

#[test]
fn credentials_missing_empty_or_too_large_are_69() {
    let d = tmp("c69");
    let c = contract(&d, "");
    let mut o = Command::new(BIN)
        .env_clear()
        .args(["exec", "--agent", A, "--contract", c.to_str().unwrap(), "--cli", "/usr/bin/true"])
        .output()
        .unwrap();
    assert_eq!(code(&o), 69, "no CREDENTIALS_DIRECTORY");
    if landlock_abi4() {
        fs::write(d.join("creds/workspace-capability"), "").unwrap();
        o = exec(&d, &c, "/usr/bin/true", &[]);
        assert_eq!(code(&o), 69, "empty: {}", stderr(&o));
        fs::write(d.join("creds/workspace-capability"), vec![b'x'; 16 * 1024 + 1]).unwrap();
        o = exec(&d, &c, "/usr/bin/true", &[]);
        assert_eq!(code(&o), 69, "too large: {}", stderr(&o));
        fs::write(d.join("creds/workspace-capability"), vec![b'x'; 16 * 1024]).unwrap();
        o = exec(&d, &c, "/usr/bin/true", &[]);
        assert_eq!(code(&o), 0, "exactly 16 KiB is accepted: {}", stderr(&o));
    }
    let _ = fs::remove_dir_all(&d);
}

#[test]
fn an_exec_failure_is_71() {
    if !landlock_abi4() {
        eprintln!("skipped: this kernel has no Landlock ABI 4 (qualified on the VM)");
        return;
    }
    let d = tmp("e71");
    let o = exec(&d, &contract(&d, ""), "/usr/bin/no-such-cli", &[]);
    assert_eq!(code(&o), 71, "{}", stderr(&o));
    let _ = fs::remove_dir_all(&d);
}

#[test]
fn exec_end_to_end_under_landlock() {
    if !landlock_abi4() {
        eprintln!("skipped: this kernel has no Landlock ABI 4 (qualified on the VM)");
        return;
    }
    let d = tmp("e2e");
    fs::write(d.join("work/f.txt"), "hello").unwrap();
    let script = format!(
        r#"echo "p=${{SAGEBRUSH_BROKER_PLACEHOLDER-unset}} c=$SAGEBRUSH_WORKSPACE_CAPABILITY d=${{CREDENTIALS_DIRECTORY-unset}}"
cat {w}/f.txt; echo; echo ok > {w}/g.txt && echo work-rw
ls /home >/dev/null 2>&1 && echo home-visible || echo home-denied
(echo x > /tmp/sbl-escape-{pid}) 2>/dev/null && echo tmp-written || echo tmp-denied
echo "fds=$(ls /proc/self/fd | tr '\n' ' ')"
grep '^NoNewPrivs' /proc/self/status
env | cut -d= -f1 | sort | tr '\n' ' '"#,
        w = d.join("work").display(),
        pid = std::process::id()
    );
    // Spawned through a shell that opens a NON-CLOEXEC descriptor 42 first, which the launcher inherits: it must be
    // closed before the CLI runs.
    let mut cmd = Command::new("/usr/bin/bash"); // (dash only redirects single-digit descriptors)
    cmd.env_clear().env("CREDENTIALS_DIRECTORY", d.join("creds"));
    cmd.args(["-c", "exec 42</usr/bin/true; exec \"$0\" \"$@\"", BIN, "exec", "--agent", A, "--contract"]);
    cmd.arg(contract(&d, "")).args(["--cli", "/usr/bin/sh", "--", "-c"]).arg(format!("[ -e /proc/self/fd/42 ] && echo fd42-leaked || echo fd42-closed\n{script}"));
    let o = cmd.output().unwrap();
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(out.contains("fd42-closed"), "an inherited descriptor 42 is closed before exec: {out}");
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(out.contains("p=unset c=cap-456 d=unset"), "no Claude placeholder, the capability, no credentials dir: {out}");
    assert!(out.contains("hello") && out.contains("work-rw"), "{out}");
    assert!(out.contains("home-denied"), "{out}");
    assert!(out.contains("tmp-denied"), "{out}");
    assert!(out.contains("fds=0 1 2 3 "), "only stdio (and ls's own listing) survive: {out}");
    assert!(out.contains("NoNewPrivs:\t1"), "{out}");
    assert!(out.contains("PATH PWD SAGEBRUSH_WORKSPACE_CAPABILITY"), "a fresh environment: {out}");
    assert!(!out.contains("PLACEHOLDER"), "no Claude placeholder variable at all: {out}");
    assert!(!Path::new(&format!("/tmp/sbl-escape-{}", std::process::id())).exists());
    let _ = fs::remove_dir_all(&d);
}

#[test]
fn a_panic_prints_only_the_fixed_72_line_and_every_secret_is_zeroed() {
    if !cfg!(debug_assertions) || !landlock_abi4() {
        return; // the injection hook exists only in debug builds; the credentials are read after the Landlock steps
    }
    let d = tmp("panic");
    // The log lives in the granted rw work dir: anywhere else, Landlock would deny the Drop's write after restrict_self.
    let log = d.join("work/drops.log");
    assert!(!log.exists());
    let o = Command::new(BIN)
        .env_clear()
        .env("CREDENTIALS_DIRECTORY", d.join("creds"))
        .env("SAGEBRUSH_LAUNCH_TEST_PANIC", "1")
        .env("SAGEBRUSH_LAUNCH_TEST_DROPLOG", &log)
        .args(["exec", "--agent", A, "--contract", contract(&d, "").to_str().unwrap(), "--cli", "/usr/bin/true"])
        .output()
        .unwrap();
    assert_eq!(code(&o), 72);
    assert_eq!(stderr(&o), "sagebrush-agent-launch: internal: internal error\n", "nothing but the fixed line");
    assert!(o.stdout.is_empty());
    // Exactly the two Secrets, in drop order, each zeroed: the input buffer (CREDENTIAL_MAX + 1 bytes, dropped in the
    // loop), then the env entry ("NAME=value\0", dropped while the panic unwinds).
    let drops = fs::read_to_string(&log).expect("the Drop log must exist: every Secret drop writes one line");
    let entry = |name: &str, value: &str| name.len() + 1 + value.len() + 1;
    let want: Vec<String> = [
        16 * 1024 + 1,
        entry("SAGEBRUSH_WORKSPACE_CAPABILITY", "cap-456"),
    ]
    .iter()
    .map(|cap| format!("dropped zeroed=true cap={cap}"))
    .collect();
    assert_eq!(drops.lines().collect::<Vec<_>>(), want, "{drops}");
    let _ = fs::remove_dir_all(&d);
}

/// Launcher contract amendment A1: the four deprovision subcommands' argument contract, and a missing anchor.
#[test]
fn a1_subcommands_refuse_bad_arguments_and_a_missing_anchor() {
    let run = |args: &[&str]| Command::new(BIN).env_clear().args(args).output().unwrap();
    let json = format!("{A}.json");
    for bad in [
        vec!["identify", "--anchor", "/etc", "--name", A],
        vec!["identify", "--anchor", "/var/lib/sagebrush/contract", "--name", A], // the contract anchor wants <id>.json
        vec!["identify", "--anchor", "/srv/sagebrush/agents", "--name", A],       // a live tree is never an anchor
        vec!["identify", "--anchor", "/run/sagebrush/binds"],
        vec!["inspect-home", "--mount", "/etc", "--agent", A, "--tree", "home"],
        vec!["inspect-home", "--mount", "/", "--agent", A, "--tree", "other"],
        vec!["inspect-home", "--mount", "/", "--agent", A, "--tree", "home", "--archive", "--archive"],
        vec!["inspect-home", "--mount", "/", "--agent", "nope", "--tree", "home"],
        vec!["archive-home", "--mount", "/", "--agent", A, "--tree", "home"],
        vec!["archive-home", "--mount", "/", "--agent", A, "--tree", "home", "--expect", "/x", "--finish", "--finish"],
        vec!["check-parents", "--mount", "/etc"],
        vec!["check-parents", "--mount", "/", "--allow-missing", "--allow-missing"],
        vec!["check-parents"],
        vec!["remove-tree", "--anchor", "/srv/sagebrush/archive", "--name", A, "--expect", "relative.json"],
        vec!["remove-tree", "--anchor", "/srv/sagebrush/archive", "--name", A, "--expect", "/x", "--", "y"],
    ] {
        let o = run(&bad);
        assert_eq!(code(&o), 64, "{bad:?}: {}", stderr(&o));
        assert!(o.stdout.is_empty());
    }
    // Well-formed arguments as a non-root user: the root guard refuses (66) before anything is opened; as root (the
    // qualification VM), a missing anchor refuses the same way.
    let o = run(&["identify", "--anchor", "/var/lib/sagebrush/contract", "--name", &json]);
    assert_eq!(code(&o), 66, "{}", stderr(&o));
    assert_eq!(stderr(&o).lines().count(), 1);
    assert!(o.stdout.is_empty());
}

#[test]
fn a2_subcommands_refuse_bad_arguments_then_the_root_guard() {
    let run = |args: &[&str]| Command::new(BIN).env_clear().args(args).output().unwrap();
    let owner = format!("a-{A}");
    let snap = "0123456789abcdef".repeat(4);
    let stage = |over: &[(&str, &str)]| -> Vec<String> {
        let mut v = vec![("mount", "/srv/sagebrush"), ("owner", owner.as_str()), ("class", "home"), ("run", "abcdefghijklmnop"), ("attempt", "1"), ("projid", "70001"), ("snapshot", snap.as_str()), ("path", "srv/x")];
        for (k, val) in over {
            v.iter_mut().find(|(n, _)| n == k).unwrap().1 = val;
        }
        std::iter::once("restore-stage".to_string()).chain(v.iter().flat_map(|(k, val)| [format!("--{k}"), val.to_string()])).collect()
    };
    let ctl = "\u{1}".repeat(250);
    let heavy = [ctl.as_str(); 4].join("/");
    for over in [
        vec![("class", "tag")],
        vec![("owner", A)],
        vec![("run", "short")],
        vec![("attempt", "0")],
        vec![("projid", "80001")],
        vec![("projid", "070001")],
        vec![("snapshot", "XYZ")],
        vec![("path", "/abs")],
        vec![("path", "a/../b")],
        vec![("path", heavy.as_str())], // over 4096 bytes once encoded
        vec![("mount", "/etc")],
    ] {
        let a = stage(&over);
        let o = run(&a.iter().map(String::as_str).collect::<Vec<_>>());
        assert_eq!(code(&o), 64, "{over:?}: {}", stderr(&o));
        assert!(o.stdout.is_empty());
    }
    for bad in [
        vec!["fill-home", "--mount", "/srv/sagebrush", "--owner", &owner, "--class", "home", "--run", "abcdefghijklmnop", "--attempt", "1", "--source", "srv/x", "--expect", "/x"],
        vec!["fill-home", "--mount", "/srv/sagebrush", "--owner", &owner, "--class", "home", "--run", "abcdefghijklmnop", "--attempt", "1", "--source", "data/x", "--expect", "x"],
        vec!["fill-home", "--mount", "/srv/sagebrush", "--owner", &owner, "--class", "home", "--run", "abcdefghijklmnop", "--attempt", "1", "--source", "data/x"],
    ] {
        let o = run(&bad);
        assert_eq!(code(&o), 64, "{bad:?}: {}", stderr(&o));
    }
    // Well-formed arguments as a non-root user: the root guard (66), one fixed line, nothing on stdout.
    let a = stage(&[]);
    let o = run(&a.iter().map(String::as_str).collect::<Vec<_>>());
    assert_eq!(code(&o), 66, "{}", stderr(&o));
    assert_eq!(stderr(&o).lines().count(), 1);
    assert!(o.stdout.is_empty());
}

#[test]
fn a3_lease_check_refuses_bad_arguments_then_the_root_guard() {
    let run = |args: &[&str]| Command::new(BIN).env_clear().args(args).output().unwrap();
    for bad in [
        vec!["lease-check"],
        vec!["lease-check", "--agent"],
        vec!["lease-check", "--agent", "not-an-id"],
        vec!["lease-check", "--agent", A, "--agent", A],
        vec!["lease-check", "--agent", A, "--extra", "x"],
        vec!["lease-check", "--agent", A, "--", "x"],
    ] {
        let o = run(&bad);
        assert_eq!(code(&o), 64, "{bad:?}: {}", stderr(&o));
        assert!(o.stdout.is_empty());
    }
    // Well-formed as a non-root user: the root guard (66), one fixed line, nothing on stdout.
    let o = run(&["lease-check", "--agent", A]);
    assert_eq!(code(&o), 66, "{}", stderr(&o));
    assert_eq!(stderr(&o), "sagebrush-agent-launch: preflight_missing: root only\n");
    assert!(o.stdout.is_empty());
}
