//! sagebrush-agent-launch: stages granted paths by handle (`stage-bind`) and execs an agent's CLI under Landlock
//! (`exec`), exactly as in the host launcher contract (sha256 147ec4e3616a42680cc351b20b9259150d61df0f359f86624473eff118510b3b),
//! under the host supervisor freeze r3.1. It fails closed: every failure is a typed exit code with one fixed stderr
//! line, and nothing is exec'd after a failure.

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
        "exec" => {
            let v = args::flags(rest, &["agent", "contract", "cli"])?;
            let e = exec::run(&exec::parse(&v)?, &after)?;
            Err(e) // exec only returns when execve failed
        }
        _ => Err(err(Fail::Usage, "bad arguments")),
    }
}

fn main() {
    // A panic unwinds (every Drop, the secret zeroing included, runs) and is mapped to 72.
    let outcome = std::panic::catch_unwind(run).unwrap_or(Err(err(Fail::Internal, "internal error")));
    match outcome {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "{}", e.line());
            std::process::exit(e.fail.code());
        }
    }
}
