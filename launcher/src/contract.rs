//! The contract file `exec` reads (contract §4 step 1): closed, bounded JSON written by the host generator.
//!
//! {
//!   "v": 1,
//!   "agent": "<id>",
//!   "rules":  [ { "path": "<absolute path>", "access": "r" | "rx" | "rw" | "rwx" }, … ],          1..=64
//!   "staged": [ { "index": 0..=63, "path": "<absolute path>", "mode": "rw" | "ro",
//!                 "dev": [<major>, <minor>], "ino": <n> }, … ],                                  0..=64
//!   "env":    [ [ "<NAME>", "<value>" ], … ]                                                     0..=16
//! }
//!
//! Rules: the file is at most 256 KiB; no two rules share a path; no two staged rows share a path, an index (and so a
//! staging path); every staged row's path is also a rule's path; env names are only the fixed set below, each once.
//! The credentials are never in this file: `exec` reads them from $CREDENTIALS_DIRECTORY.

use crate::args::{is_id, is_path};
use crate::json::{parse, Value};

pub const MAX_BYTES: usize = 256 * 1024;
pub const MAX_RULES: usize = 64;
pub const MAX_STAGED: usize = 64;
pub const MAX_ENV: usize = 16;
/// The only environment variables the contract may set (fixed; the proxy ones only for an allowlist agent).
pub const ENV_NAMES: [&str; 8] = ["HOME", "PATH", "LANG", "TZ", "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "SAGEBRUSH_AGENT"];

#[derive(Debug, Clone, PartialEq)]
pub struct Rule {
    pub path: String,
    pub access: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Staged {
    pub index: u8,
    pub path: String,
    pub mode: String,
    pub dev: (u32, u32),
    pub ino: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Contract {
    pub agent: String,
    pub rules: Vec<Rule>,
    pub staged: Vec<Staged>,
    pub env: Vec<(String, String)>,
}

pub fn read(bytes: &[u8], agent: &str) -> Option<Contract> {
    if bytes.len() > MAX_BYTES {
        return None;
    }
    let v = parse(bytes)?;
    let f = v.exact(&["v", "agent", "rules", "staged", "env"])?;
    if f[0].int()? != 1 || f[1].str()? != agent || !is_id(agent) {
        return None;
    }
    let mut rules = Vec::new();
    for r in f[2].arr()? {
        let g = r.exact(&["path", "access"])?;
        let (path, access) = (g[0].str()?, g[1].str()?);
        if !is_path(path) || !["r", "rx", "rw", "rwx"].contains(&access) || rules.iter().any(|x: &Rule| x.path == path) {
            return None;
        }
        rules.push(Rule { path: path.into(), access: access.into() });
    }
    if rules.is_empty() || rules.len() > MAX_RULES {
        return None;
    }
    let mut staged: Vec<Staged> = Vec::new();
    for s in f[3].arr()? {
        let g = s.exact(&["index", "path", "mode", "dev", "ino"])?;
        let index = g[0].int()?;
        let (path, mode) = (g[1].str()?, g[2].str()?);
        let dev = g[3].arr()?;
        if dev.len() != 2 {
            return None;
        }
        let (maj, min) = (dev[0].int()?, dev[1].int()?);
        if index > 63 || !is_path(path) || !["rw", "ro"].contains(&mode) || maj > u32::MAX as u64 || min > u32::MAX as u64 {
            return None;
        }
        if staged.iter().any(|x| x.path == path || x.index as u64 == index) || !rules.iter().any(|r| r.path == path) {
            return None;
        }
        staged.push(Staged { index: index as u8, path: path.into(), mode: mode.into(), dev: (maj as u32, min as u32), ino: g[4].int()? });
    }
    if staged.len() > MAX_STAGED {
        return None;
    }
    let mut env: Vec<(String, String)> = Vec::new();
    for e in f[4].arr()? {
        let pair = e.arr()?;
        if pair.len() != 2 {
            return None;
        }
        let (k, val) = (pair[0].str()?, pair[1].str()?);
        if !ENV_NAMES.contains(&k) || env.iter().any(|(n, _)| n == k) || val.len() > 4096 {
            return None;
        }
        env.push((k.into(), val.into()));
    }
    if env.len() > MAX_ENV {
        return None;
    }
    let _: &Value = &v;
    Some(Contract { agent: agent.into(), rules, staged, env })
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "abcdefghijklmnopqrstuvwxya";

    fn doc(rules: &str, staged: &str, env: &str) -> String {
        format!(r#"{{"v":1,"agent":"{A}","rules":[{rules}],"staged":[{staged}],"env":[{env}]}}"#)
    }

    #[test]
    fn a_valid_contract() {
        let c = read(doc(r#"{"path":"/usr","access":"rx"},{"path":"/data/x","access":"rwx"}"#,
            r#"{"index":0,"path":"/data/x","mode":"rw","dev":[8,1],"ino":42}"#, r#"["HOME","/srv/sagebrush/agents/x/home"]"#).as_bytes(), A).unwrap();
        assert_eq!(c.rules.len(), 2);
        assert_eq!(c.staged[0], Staged { index: 0, path: "/data/x".into(), mode: "rw".into(), dev: (8, 1), ino: 42 });
    }

    #[test]
    fn the_host_generators_output_parses() {
        // Written by lib/fleet/host/unit.mjs launcherContract() (regenerate it when the generator changes).
        let bytes = include_bytes!("../tests/fixtures/generated-contract.json");
        let c = read(bytes, A).expect("the generator's contract is the closed shape");
        assert_eq!(c.staged.len(), 2);
        assert!(c.rules.iter().any(|r| r.path == "/usr" && r.access == "rx"));
        assert!(!c.rules.iter().any(|r| ["/bin", "/sbin", "/lib", "/lib64"].contains(&r.path.as_str())));
        assert!(c.env.iter().any(|(k, _)| k == "HTTPS_PROXY"));
    }

    #[test]
    fn closed_and_bounded() {
        let ok_rules = r#"{"path":"/usr","access":"rx"},{"path":"/data/x","access":"rwx"}"#;
        let st = r#"{"index":0,"path":"/data/x","mode":"rw","dev":[8,1],"ino":42}"#;
        let bad = [
            doc("", "", ""),                                                              // no rules
            doc(r#"{"path":"/usr","access":"rx"},{"path":"/usr","access":"r"}"#, "", ""),   // duplicate rule path
            doc(r#"{"path":"/usr","access":"x"}"#, "", ""),                                 // unknown access
            doc(r#"{"path":"/usr/","access":"rx"}"#, "", ""),                               // not normalized
            doc(r#"{"path":"/usr","access":"rx","extra":1}"#, "", ""),                      // extra field
            doc(ok_rules, &format!("{st},{st}"), ""),                                        // duplicate staged
            doc(ok_rules, r#"{"index":0,"path":"/data/x","mode":"rw","dev":[8,1],"ino":42},{"index":0,"path":"/usr","mode":"ro","dev":[8,1],"ino":1}"#, ""), // duplicate index
            doc(ok_rules, r#"{"index":64,"path":"/data/x","mode":"rw","dev":[8,1],"ino":42}"#, ""), // index bound
            doc(ok_rules, r#"{"index":0,"path":"/data/y","mode":"rw","dev":[8,1],"ino":42}"#, ""),  // staged without a rule
            doc(ok_rules, r#"{"index":0,"path":"/data/x","mode":"rx","dev":[8,1],"ino":42}"#, ""),  // bad mode
            doc(ok_rules, r#"{"index":0,"path":"/data/x","mode":"rw","dev":[8],"ino":42}"#, ""),    // bad dev
            doc(ok_rules, "", r#"["LD_PRELOAD","/x.so"]"#),                                  // env name outside the set
            doc(ok_rules, "", r#"["HOME","a"],["HOME","b"]"#),                               // duplicate env
        ];
        for b in bad {
            assert!(read(b.as_bytes(), A).is_none(), "{b}");
        }
        let other = doc(ok_rules, "", "").replace(A, "bbbbbbbbbbbbbbbbbbbbbbbbbe");
        assert!(read(other.as_bytes(), A).is_none(), "another agent's contract");
        let many: Vec<String> = (0..=MAX_RULES).map(|i| format!(r#"{{"path":"/p{i}","access":"r"}}"#)).collect();
        assert!(read(doc(&many.join(","), "", "").as_bytes(), A).is_none());
        assert!(read(&vec![b' '; MAX_BYTES + 1], A).is_none());
    }
}
