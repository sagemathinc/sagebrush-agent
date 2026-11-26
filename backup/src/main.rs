//! `sagebrush-agent-backup`: the host's backup engine (host backup design r3.3).
//!
//!     sagebrush-agent-backup --state <dir> --secrets <dir> [--cache <dir>] [--parent-pid <pid>]  < request.json  > result.json
//!
//! One JSON request on stdin (at most 64 KiB), one JSON result on stdout: `{"ok":true,...}` with exit 0, or
//! `{"ok":false,"error":{"code","message"}}` with exit 1. Argv carries only directories; the destination, its
//! credential and the repository password are read from root-owned files by handle, never from argv or the
//! environment. The process binds itself to its parent first (parent.rs): `--parent-pid`, or a SIGKILL death signal its
//! parent already set (the launcher's restore stage).

mod caps;
mod config;
mod digests;
mod error;
mod logcap;
mod ops;
mod parent;
mod s3;

use std::{
    io::{Read, Write},
    path::PathBuf,
    process::ExitCode,
};

use error::{Fail, Result};
use serde_json::{json, Value};

const MAX_REQUEST: u64 = 64 * 1024;

struct Args {
    state: PathBuf,
    secrets: PathBuf,
    cache: Option<PathBuf>,
    parent_pid: Option<i32>,
}

fn args() -> Result<Args> {
    let mut it = std::env::args_os().skip(1);
    let (mut state, mut secrets, mut cache, mut parent_pid) = (None, None, None, None);
    while let Some(flag) = it.next() {
        if flag.to_str() == Some("--parent-pid") {
            // A closed decimal process id, once: 1 to i32::MAX, no sign, no leading zero.
            let v = it.next().and_then(|v| v.into_string().ok());
            match v.as_deref() {
                Some(d) if parent_pid.is_none() && !d.is_empty() && d.len() <= 10 && d.bytes().all(|b| b.is_ascii_digit()) && !d.starts_with('0') => {
                    parent_pid = Some(d.parse::<i32>().map_err(|_| Fail::new("usage", "--parent-pid takes one process id, once"))?);
                }
                _ => return Err(Fail::new("usage", "--parent-pid takes one process id, once")),
            }
            continue;
        }
        let value = it.next().map(PathBuf::from);
        let slot = match flag.to_str() {
            Some("--state") => &mut state,
            Some("--secrets") => &mut secrets,
            Some("--cache") => &mut cache,
            _ => return Err(Fail::new("usage", "usage: sagebrush-agent-backup --state DIR --secrets DIR [--cache DIR] [--parent-pid PID] < request.json")),
        };
        match value {
            Some(v) if v.is_absolute() && slot.is_none() => *slot = Some(v),
            _ => return Err(Fail::new("usage", "each flag takes one absolute directory, once")),
        }
    }
    match (state, secrets) {
        (Some(state), Some(secrets)) => Ok(Args { state, secrets, cache, parent_pid }),
        _ => Err(Fail::new("usage", "--state and --secrets are required")),
    }
}

fn main_inner() -> Result<Value> {
    let a = args()?;
    // Bound to the parent before anything else is read or done.
    parent::bind(a.parent_pid)?;
    let mut raw = Vec::new();
    std::io::stdin()
        .take(MAX_REQUEST + 1)
        .read_to_end(&mut raw)
        .map_err(|e| Fail::new("request_invalid", format!("stdin: {e}")))?;
    if raw.len() as u64 > MAX_REQUEST {
        return Err(Fail::new("request_invalid", "the request is larger than 64 KiB"));
    }
    let req: ops::Request = serde_json::from_slice(&raw).map_err(|e| Fail::new("request_invalid", e.to_string()))?;
    let ctx = ops::Ctx { state: config::State::new(&a.state, &a.secrets), cache: a.cache };
    ops::run(&ctx, req)
}

fn main() -> ExitCode {
    logcap::init();
    let (out, code) = match main_inner() {
        Ok(mut v) => {
            if let Value::Object(m) = &mut v {
                m.insert("ok".into(), Value::Bool(true));
            }
            (v, ExitCode::SUCCESS)
        }
        Err(f) => (json!({ "ok": false, "error": { "code": f.code, "message": f.message } }), ExitCode::FAILURE),
    };
    let mut stdout = std::io::stdout().lock();
    let _ = writeln!(stdout, "{out}");
    let _ = stdout.flush();
    code
}
