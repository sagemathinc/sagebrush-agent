//! The real binary, spawned: every exit code reachable without privilege, and (where the kernel has Landlock ABI 4)
//! an end-to-end `exec` under Landlock. `stage-bind`'s mount path needs root: it is qualified on the VM (contract §8).

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const A: &str = "abcdefghijklmnopqrstuvwxya";
const BIN: &str = env!("CARGO_BIN_EXE_sagebrush-agent-launch");

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("sbl-test-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(d.join("work")).unwrap();
    fs::create_dir_all(d.join("creds")).unwrap();
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

fn landlock_abi4() -> bool {
    // The binary itself is the probe: a valid exec of /usr/bin/true exits 0 only with ABI 4.
    let d = tmp("probe");
    let c = contract(&d, "");
    let o = exec(&d, &c, "/usr/bin/true", &[]);
    let _ = fs::remove_dir_all(&d);
    code(&o) == 0
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
        fs::write(d.join("creds/broker-placeholder"), "").unwrap();
        o = exec(&d, &c, "/usr/bin/true", &[]);
        assert_eq!(code(&o), 69, "empty: {}", stderr(&o));
        fs::write(d.join("creds/broker-placeholder"), vec![b'x'; 16 * 1024 + 1]).unwrap();
        o = exec(&d, &c, "/usr/bin/true", &[]);
        assert_eq!(code(&o), 69, "too large: {}", stderr(&o));
        fs::write(d.join("creds/broker-placeholder"), vec![b'x'; 16 * 1024]).unwrap();
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
        r#"echo "p=$SAGEBRUSH_BROKER_PLACEHOLDER c=$SAGEBRUSH_WORKSPACE_CAPABILITY d=${{CREDENTIALS_DIRECTORY-unset}}"
cat {w}/f.txt; echo; echo ok > {w}/g.txt && echo work-rw
ls /home >/dev/null 2>&1 && echo home-visible || echo home-denied
(echo x > /tmp/sbl-escape-{pid}) 2>/dev/null && echo tmp-written || echo tmp-denied
echo "fds=$(ls /proc/self/fd | tr '\n' ' ')"
grep '^NoNewPrivs' /proc/self/status
env | cut -d= -f1 | sort | tr '\n' ' '"#,
        w = d.join("work").display(),
        pid = std::process::id()
    );
    let o = exec(&d, &contract(&d, ""), "/usr/bin/sh", &["-c", &script]);
    let out = String::from_utf8_lossy(&o.stdout);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(out.contains("p=placeholder-123 c=cap-456 d=unset"), "{out}");
    assert!(out.contains("hello") && out.contains("work-rw"), "{out}");
    assert!(out.contains("home-denied"), "{out}");
    assert!(out.contains("tmp-denied"), "{out}");
    assert!(out.contains("fds=0 1 2 3 "), "only stdio (and ls's own listing) survive: {out}");
    assert!(out.contains("NoNewPrivs:\t1"), "{out}");
    assert!(out.contains("PATH PWD SAGEBRUSH_BROKER_PLACEHOLDER SAGEBRUSH_WORKSPACE_CAPABILITY"), "a fresh environment: {out}");
    assert!(!Path::new(&format!("/tmp/sbl-escape-{}", std::process::id())).exists());
    let _ = fs::remove_dir_all(&d);
}
