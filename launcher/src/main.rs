//! sagebrush-agent-launch: stages granted paths by handle (`stage-bind`) and execs an agent's CLI under Landlock
//! (`exec`), exactly as in the host launcher contract (sha256 147ec4e3616a42680cc351b20b9259150d61df0f359f86624473eff118510b3b),
//! under the host supervisor freeze r3.1. It fails closed: every failure is a typed exit code with one fixed stderr
//! line, and nothing is exec'd after a failure.
//!
//! Amendment A1 (deprovision) adds four root-only subcommands run by the supervisor outside any unit: `identify`,
//! `inspect-home`, `archive-home` and `remove-tree` (tree.rs).

// Unsafe code is refused everywhere except the syscall module and the secret's zeroing Drop (contract §6).
#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

mod args;
mod contract;
mod err;
mod exec;
mod json;
mod landlock;
mod secret;
mod stage;
mod tree;
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
        "identify" | "inspect-home" | "archive-home" | "remove-tree" => {
            if !after.is_empty() {
                return Err(err(Fail::Usage, "bad arguments"));
            }
            a1(cmd, rest)
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
        "archive-home" => {
            let v = args::flags(rest, &["mount", "agent", "tree", "expect"])?;
            let (mount, t) = (tree::parse_mount(v[0])?, tree::parse_tree(v[2])?);
            if !args::is_id(v[1]) || args::rel(v[3]).is_none() {
                return Err(err(Fail::Usage, "bad arguments"));
            }
            guard()?;
            tree::archive_home(&mut o, mount, v[1], t, v[3])?;
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
