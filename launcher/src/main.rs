//! sagebrush-agent-launch: stages granted paths by handle (`stage-bind`) and execs an agent's CLI under Landlock
//! (`exec`), exactly as in the host launcher contract (sha256 147ec4e3616a42680cc351b20b9259150d61df0f359f86624473eff118510b3b),
//! under the host supervisor freeze r3.1. It fails closed: every failure is a typed exit code with one fixed stderr
//! line, and nothing is exec'd after a failure.
//!
//! Amendment A1 (deprovision) adds four root-only subcommands run by the supervisor outside any unit: `identify`,
//! `inspect-home`, `archive-home` and `remove-tree` (tree.rs).
//!
//! Amendment A2 (backup restore) adds two more, also root-only and outside any unit: `restore-stage` and `fill-home`
//! (restore.rs, child.rs).
//!
//! Amendment A4 (profiles) adds `profile-mounts`, root-only, outside any unit (profile.rs), and the profiles root to A1's
//! anchor table and check-parents.
//!
//! Amendment A3 (execution lease) adds `lease-check`, root-only, run as the unit's `ExecStartPre=+` (lease.rs).
//!
//! Amendment A5 (profiles piece 3) adds `turn`, root-only, run by the supervisor in the turn's scope (turn.rs,
//! turn_exec.rs). It stays off (64) until the syscall filter lands.

// Unsafe code is refused everywhere except the syscall module and the secret's zeroing Drop (contract §6).
#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

mod args;
mod child;
mod restore;
mod contract;
mod digest;
mod err;
mod exec;
mod json;
mod landlock;
mod lease;
mod profile;
mod secret;
mod sha256;
mod stage;
mod tree;
mod turn;
mod turn_exec;
#[allow(unsafe_code)]
mod sys;

use err::{err, Fail};
use std::io::Write;

fn run() -> err::Result<()> {
    if !args::env_within_bounds() {
        return Err(err(Fail::Usage, "the environment is too large"));
    }
    let raw: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let (before, after) = args::split(raw)?;
    let Some((cmd, rest)) = before.split_first() else { return Err(err(Fail::Usage, "bad arguments")) };
    match cmd.as_str() {
        "stage-bind" => {
            if !after.is_empty() {
                return Err(err(Fail::Usage, "bad arguments"));
            }
            let v = args::flags(rest, &["agent", "index", "mode", "path", "record"])?;
            stage::run(&stage::parse(&v)?)
        }
        // Launcher contract amendment A1 (deprovision): root only, outside any unit.
        "identify" | "inspect-home" | "archive-home" | "remove-tree" | "check-parents" => {
            if !after.is_empty() {
                return Err(err(Fail::Usage, "bad arguments"));
            }
            a1(cmd, rest)
        }
        // Launcher contract amendment A2 (backup restore): root only, outside any unit.
        "tree-digest" => {
            if !after.is_empty() {
                return Err(err(Fail::Usage, "bad arguments"));
            }
            tree_digest(rest)
        }
        "restore-stage" | "fill-home" => {
            if !after.is_empty() {
                return Err(err(Fail::Usage, "bad arguments"));
            }
            a2(cmd, rest)
        }
        // Launcher contract amendment A4 (profiles): root only, outside any unit.
        "profile-mounts" => {
            if !after.is_empty() {
                return Err(err(Fail::Usage, "bad arguments"));
            }
            let out = profile::run(rest)?;
            std::io::stdout().write_all(out.as_bytes()).map_err(|_| err(Fail::Internal, "internal error"))
        }
        // Launcher contract amendment A3 (execution lease): root only, the unit's ExecStartPre.
        "lease-check" => {
            if !after.is_empty() {
                return Err(err(Fail::Usage, "bad arguments"));
            }
            let v = args::flags(rest, &["agent"])?;
            if !args::is_id(v[0]) {
                return Err(err(Fail::Usage, "bad arguments"));
            }
            if !sys::is_root() {
                return Err(err(Fail::Preflight, "root only"));
            }
            lease::hold(v[0]).map(drop) // the fd closes here: the shared lock is released before ExecStart
        }
        // Launcher contract amendment A5 (turn): root only, the supervisor's turn scope. Off until part 3b-ii adds the
        // syscall filter: it refuses before touching any descriptor.
        "turn" => {
            if !turn_exec::TURN_ENABLED || !after.is_empty() {
                return Err(err(Fail::Usage, "bad arguments"));
            }
            turn_exec::run(&mut tree::RealOps, &mut turn_exec::RealProc::default(), rest)
        }
        "exec" => {
            let v = args::flags(rest, &["agent", "contract", "cli"])?;
            let e = exec::run(&exec::parse(&v)?, &after)?;
            Err(e) // exec only returns when execve failed
        }
        _ => Err(err(Fail::Usage, "bad arguments")),
    }
}

fn a1(cmd: &str, rest: &[String]) -> err::Result<()> {
    let mut o = tree::RealOps;
    // The arguments first (64), then the root guard (66): the supervisor is the only caller, as root.
    let guard = || if sys::is_root() { Ok(()) } else { Err(err(Fail::Preflight, "root only")) };
    let out = match cmd {
        "identify" => {
            let v = args::flags(rest, &["anchor", "name"])?;
            if !tree::anchor_name_ok(v[0], v[1]) {
                return Err(err(Fail::Usage, "bad arguments"));
            }
            guard()?;
            tree::identify(&mut o, v[0], v[1])?
        }
        "inspect-home" => {
            // `--archive` takes no value: strip it, then the rest are exact flags.
            let archive = rest.iter().filter(|a| *a == "--archive").count();
            if archive > 1 {
                return Err(err(Fail::Usage, "bad arguments"));
            }
            let kept: Vec<String> = rest.iter().filter(|a| *a != "--archive").cloned().collect();
            let v = args::flags(&kept, &["mount", "agent", "tree"])?;
            let (mount, t) = (tree::parse_mount(v[0])?, tree::parse_tree(v[2])?);
            if !args::is_id(v[1]) {
                return Err(err(Fail::Usage, "bad arguments"));
            }
            guard()?;
            tree::inspect_home(&mut o, mount, v[1], t, archive == 1)?
        }
        "check-parents" => {
            // `--allow-missing` takes no value, like inspect-home's `--archive`.
            let allow = rest.iter().filter(|a| *a == "--allow-missing").count();
            if allow > 1 {
                return Err(err(Fail::Usage, "bad arguments"));
            }
            let kept: Vec<String> = rest.iter().filter(|a| *a != "--allow-missing").cloned().collect();
            let v = args::flags(&kept, &["mount"])?;
            let mount = tree::parse_mount(v[0])?;
            guard()?;
            tree::check_parents(&mut o, mount, allow == 1)?;
            String::new()
        }
        "archive-home" => {
            // `--finish` takes no value (A1 r2.4 §4a), like inspect-home's `--archive`.
            let finish = rest.iter().filter(|a| *a == "--finish").count();
            if finish > 1 {
                return Err(err(Fail::Usage, "bad arguments"));
            }
            let kept: Vec<String> = rest.iter().filter(|a| *a != "--finish").cloned().collect();
            let v = args::flags(&kept, &["mount", "agent", "tree", "expect"])?;
            let (mount, t) = (tree::parse_mount(v[0])?, tree::parse_tree(v[2])?);
            if !args::is_id(v[1]) || args::rel(v[3]).is_none() {
                return Err(err(Fail::Usage, "bad arguments"));
            }
            guard()?;
            tree::archive_home(&mut o, mount, v[1], t, v[3], finish == 1)?;
            String::new()
        }
        _ => {
            let v = args::flags(rest, &["anchor", "name", "expect"])?;
            if !tree::anchor_name_ok(v[0], v[1]) || args::rel(v[2]).is_none() {
                return Err(err(Fail::Usage, "bad arguments"));
            }
            guard()?;
            tree::remove_tree(&mut o, v[0], v[1], v[2])?;
            String::new()
        }
    };
    std::io::stdout().write_all(out.as_bytes()).map_err(|_| err(Fail::Internal, "internal error"))
}

/// A2 r3.8.1 §4a: `tree-digest --mount <m> --owner <o> --class <c> --expect <file> [--copy-sqlite --run <run>]`.
fn tree_digest(rest: &[String]) -> err::Result<()> {
    let bad = || err(Fail::Usage, "bad arguments");
    let copies = rest.iter().filter(|a| *a == "--copy-sqlite").count();
    if copies > 1 {
        return Err(bad());
    }
    let kept: Vec<String> = rest.iter().filter(|a| *a != "--copy-sqlite").cloned().collect();
    let (v, run) = if copies == 1 {
        let v = args::flags(&kept, &["mount", "owner", "class", "expect", "run"])?;
        let run = v[4];
        (v, Some(run))
    } else {
        (args::flags(&kept, &["mount", "owner", "class", "expect"])?, None)
    };
    tree::parse_mount(v[0])?;
    if args::rel(v[3]).is_none() {
        return Err(bad());
    }
    if !sys::is_root() {
        return Err(err(Fail::Preflight, "root only"));
    }
    sys::umask0();
    let a = digest::DigestArgs { mount: v[0], owner: v[1], class: v[2], expect: v[3], copy_run: run };
    let out = digest::tree_digest(&mut tree::RealOps, &a)?;
    std::io::stdout().write_all(out.as_bytes()).map_err(|_| err(Fail::Internal, "internal error"))
}

fn a2(cmd: &str, rest: &[String]) -> err::Result<()> {
    let bad = || err(Fail::Usage, "bad arguments");
    let mut o = tree::RealOps;
    let done = if cmd == "restore-stage" {
        let v = args::flags(rest, &["mount", "owner", "class", "run", "attempt", "projid", "snapshot", "path"])?;
        let name = restore::Name::parse(v[3], v[1], v[2], v[4]).ok_or_else(bad)?;
        let projid: u32 = v[5].parse().ok().filter(|_| !v[5].starts_with('0') && v[5].bytes().all(|b| b.is_ascii_digit())).ok_or_else(bad)?;
        if !name.projid_ok(projid) {
            return Err(bad());
        }
        tree::parse_mount(v[0])?;
        let a = restore::StageArgs { mount: v[0], name, projid, snapshot: v[6], path: v[7] };
        // The request is built and bounded (64) before the root guard (66), like every other argument.
        restore::request(a.snapshot, a.path)?;
        if !sys::is_root() {
            return Err(err(Fail::Preflight, "root only"));
        }
        sys::umask0();
        restore::restore_stage(&mut o, &mut child::RealRunner, &a)
    } else {
        let v = args::flags(rest, &["mount", "owner", "class", "run", "attempt", "source", "expect"])?;
        let name = restore::Name::parse(v[3], v[1], v[2], v[4]).ok_or_else(bad)?;
        tree::parse_mount(v[0])?;
        if !v[5].starts_with("data/") || !restore::rel_ok(v[5]) || args::rel(v[6]).is_none() {
            return Err(bad());
        }
        if !sys::is_root() {
            return Err(err(Fail::Preflight, "root only"));
        }
        sys::umask0();
        let a = restore::FillArgs { mount: v[0], name, source: v[5], expect: v[6] };
        match restore::fill_home(&mut o, &a) {
            Ok(out) => restore::Done { out: out.into_bytes(), result: Ok(()) },
            Err(e) => restore::Done { out: Vec::new(), result: Err(e) },
        }
    };
    std::io::stdout().write_all(&done.out).map_err(|_| err(Fail::Internal, "internal error"))?;
    done.result
}

fn main() {
    // A panic prints NOTHING of its own (no message, location or value): only the fixed 72 line below. It unwinds, so
    // every Drop (the secret zeroing included) runs first.
    std::panic::set_hook(Box::new(|_| {}));
    let outcome = std::panic::catch_unwind(run).unwrap_or(Err(err(Fail::Internal, "internal error")));
    match outcome {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "{}", e.line());
            std::process::exit(e.fail.code());
        }
    }
}
