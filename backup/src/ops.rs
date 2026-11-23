//! The operations: init, add-key, backup, readback, check-data, snapshots, dump, restore, forget and
//! prune. The host supervisor decides when; this binary only does each one exactly, and refuses what the design
//! forbids: it never initializes a repository except on `init`, never skips the ctime or inode comparison, and never
//! restores with CAP_SYS_RESOURCE.

use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use rustic_core::{
    repofile::{Node, NodeType, SnapshotFile}, BackupOptions, CheckOptions, ConfigOptions, Credentials, Excludes, FileType, KeyOptions,
    LocalDestination, LocalSourceFilterOptions, LsOptions, OpenStatus, ParentOptions, PathList, PruneOptions,
    ReadSubsetOption, Repository, RepositoryBackends, RepositoryOptions, RestoreOptions, SnapshotOptions,
    SparseRestore,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    caps,
    config::{password_file, State},
    error::{lib, Fail, Result},
    logcap,
    s3::S3Backend,
};

/// A dump (the manifest is read this way) is at most this big.
const MAX_DUMP: u64 = 16 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "kebab-case", deny_unknown_fields)]
/// (Variants without fields are written `Name {}`: serde's deny_unknown_fields doesn't cover unit variants of an
/// internally tagged enum, and a request with an unknown field must be refused.)
pub enum Request {
    Init {},
    AddKey {
        password_file: PathBuf,
    },
    Backup {
        sources: Vec<PathBuf>,
        host: String,
        #[serde(default)]
        tags: Vec<String>,
        #[serde(default)]
        parent: Option<String>,
        #[serde(default)]
        excludes: Vec<String>,
    },
    Readback {
        snapshot: String,
    },
    CheckData {
        part: u32,
        of: u32,
    },
    Snapshots {},
    Dump {
        snapshot: String,
        path: String,
    },
    Restore {
        snapshot: String,
        #[serde(default)]
        path: Option<String>,
        dest: PathBuf,
    },
    Forget {
        snapshots: Vec<String>,
    },
    Prune {},
}

pub struct Ctx {
    pub state: State,
    pub cache: Option<PathBuf>,
}

impl Ctx {
    fn backends(&self) -> Result<(RepositoryBackends, Arc<S3Backend>)> {
        let d = self.state.destination()?;
        let be = Arc::new(S3Backend::new(&d)?);
        Ok((RepositoryBackends::new(be.clone(), None), be))
    }

    /// With `cached`, the cache directory is used if it can be written; if not, the run goes on uncached and reports
    /// `cache_full` (host backup design r3.3 §6: a warning, not an abort).
    fn options(&self, cached: bool) -> RepositoryOptions {
        match (&self.cache, cached) {
            (Some(dir), true) if cache_usable(dir) => RepositoryOptions::default().cache_dir(dir.clone()),
            (Some(_), true) => {
                logcap::mark_cache_full();
                RepositoryOptions::default().no_cache(true)
            }
            _ => RepositoryOptions::default().no_cache(true),
        }
    }

    /// Open an existing repository. A missing one is an error here, never created: only `init` creates one, so a
    /// mistyped destination can't silently start a new, empty repository (design §8).
    fn open(&self, cached: bool) -> Result<Repository<OpenStatus>> {
        let (backends, be) = self.backends()?;
        if !has_config(&be)? {
            return Err(Fail::new("repository_missing", "there is no repository at this destination (only `init` creates one)"));
        }
        let pass = self.state.host_password()?;
        Repository::new(&self.options(cached), &backends)
            .map_err(lib("destination_unavailable"))?
            .open(&Credentials::password(pass))
            .map_err(lib("open_failed"))
    }
}

/// The cache directory exists (or can be made) and takes a write.
fn cache_usable(dir: &Path) -> bool {
    let probe = dir.join(format!(".sb-probe-{}", std::process::id()));
    let ok = fs::create_dir_all(dir).is_ok() && fs::write(&probe, b"x").is_ok();
    let _ = fs::remove_file(&probe);
    ok
}

fn has_config(be: &S3Backend) -> Result<bool> {
    use rustic_core::ReadBackend;
    Ok(!be.list_with_size(FileType::Config).map_err(lib("destination_unavailable"))?.is_empty())
}

pub fn run(ctx: &Ctx, req: Request) -> Result<Value> {
    match req {
        Request::Init {} => init(ctx),
        Request::AddKey { password_file: p } => add_key(ctx, &p),
        Request::Backup { sources, host, tags, parent, excludes } => backup(ctx, &sources, &host, &tags, parent.as_deref(), &excludes),
        Request::Readback { snapshot } => readback(ctx, &snapshot),
        Request::CheckData { part, of } => check_data(ctx, part, of),
        Request::Snapshots {} => snapshots(ctx),
        Request::Dump { snapshot, path } => dump(ctx, &snapshot, &path),
        Request::Restore { snapshot, path, dest } => restore(ctx, &snapshot, path.as_deref(), &dest),
        Request::Forget { snapshots } => forget(ctx, &snapshots),
        Request::Prune {} => prune(ctx),
    }
}

fn init(ctx: &Ctx) -> Result<Value> {
    let (backends, be) = ctx.backends()?;
    if has_config(&be)? {
        return Err(Fail::new("repository_exists", "a repository already exists at this destination"));
    }
    let pass = ctx.state.host_password()?;
    Repository::new(&ctx.options(false), &backends)
        .map_err(lib("destination_unavailable"))?
        .init(&Credentials::password(pass), &KeyOptions::default(), &ConfigOptions::default())
        .map_err(lib("init_failed"))?;
    Ok(json!({ "initialized": true }))
}

fn add_key(ctx: &Ctx, path: &Path) -> Result<Value> {
    let new = password_file(path)?;
    let repo = ctx.open(false)?;
    let id = repo.add_key(&new, &KeyOptions::default()).map_err(lib("add_key_failed"))?;
    Ok(json!({ "key": id.to_string() }))
}

/// A tag is `name=value` of [A-Za-z0-9._:-] (no comma: rustic splits tag lists on commas).
fn check_tag(t: &str) -> Result<()> {
    let ok = !t.is_empty() && t.len() <= 128 && t.contains('=') && t.bytes().all(|b| b.is_ascii_alphanumeric() || b"._:=-".contains(&b));
    if ok {
        Ok(())
    } else {
        Err(Fail::new("request_invalid", format!("bad tag {t:?}")))
    }
}

fn backup(ctx: &Ctx, sources: &[PathBuf], host: &str, tags: &[String], parent: Option<&str>, excludes: &[String]) -> Result<Value> {
    if sources.is_empty() || sources.iter().any(|p| !p.is_absolute()) {
        return Err(Fail::new("request_invalid", "sources must be absolute paths, at least one"));
    }
    if host.is_empty() || host.len() > 64 || !host.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return Err(Fail::new("request_invalid", "host must be 1-64 of [A-Za-z0-9-]"));
    }
    for t in tags {
        check_tag(t)?;
    }
    if let Some(p) = parent {
        check_id(p)?;
    }
    let repo = ctx.open(true)?.to_indexed_ids().map_err(lib("index_failed"))?;
    let mut snap = SnapshotOptions::default().host(host.to_string());
    if !tags.is_empty() {
        snap = snap.add_tags(&tags.join(",")).map_err(lib("request_invalid"))?;
    }
    let snap = snap.to_snapshot().map_err(lib("request_invalid"))?;
    // ctime and inode are always compared (design §4): ParentOptions' ignore_ctime and ignore_inode stay false.
    let mut parent_opts = ParentOptions::default();
    if let Some(p) = parent {
        parent_opts.parents = vec![p.to_string()];
    }
    assert!(!parent_opts.ignore_ctime && !parent_opts.ignore_inode);
    let mut filter = LocalSourceFilterOptions::default();
    filter.one_file_system = true;
    let mut ex = Excludes::default();
    ex.globs = excludes.iter().map(|g| format!("!{g}")).collect();
    let mut opts = BackupOptions::default();
    opts.parent_opts = parent_opts;
    opts.ignore_filter_opts = filter;
    opts.excludes = ex;
    let source = sources.iter().cloned().collect::<PathList>().sanitize().map_err(|e| Fail::new("request_invalid", e.to_string()))?;
    let made = repo.backup(&opts, &source, snap).map_err(lib("backup_failed"))?;
    Ok(json!({ "snapshot": snapshot_json(&made), "cache_full": logcap::cache_full() }))
}

/// An id as all 64 hex digits (rustic's Display shortens it to 8).
fn full(id: rustic_core::Id) -> String {
    id.to_hex().to_string()
}

fn snapshot_json(s: &SnapshotFile) -> Value {
    let summary = s.summary.as_ref().map(|m| {
        json!({
            "files_new": m.files_new,
            "files_changed": m.files_changed,
            "files_unmodified": m.files_unmodified,
            "total_files_processed": m.total_files_processed,
            "total_bytes_processed": m.total_bytes_processed,
            "data_added_packed": m.data_added_packed,
        })
    });
    json!({
        "id": full(*s.id),
        "time": s.time.to_string(),
        "tree": full(*s.tree),
        "host": s.hostname,
        "paths": s.paths.iter().collect::<Vec<_>>(),
        "tags": s.tags.iter().collect::<Vec<_>>(),
        "summary": summary,
    })
}

/// Read-back (design §6): opened through the backend with no cache, the snapshot's tree loaded, and every pack the
/// index references required to exist. Any finding of error level fails it.
fn readback(ctx: &Ctx, snapshot: &str) -> Result<Value> {
    let repo = ctx.open(false)?;
    let snap = one_snapshot(&repo, snapshot)?;
    let results = repo
        .check_with_trees(CheckOptions::default().trust_cache(false), vec![snap.tree])
        .map_err(lib("readback_failed"))?;
    results.is_ok().map_err(|_| Fail::new("readback_failed", findings(&results.0)))?;
    Ok(json!({ "snapshot": snapshot_json(&snap), "findings": results.0.len() }))
}

fn findings<T: std::fmt::Debug>(f: &[T]) -> String {
    let mut s = f.iter().take(5).map(|x| format!("{x:?}")).collect::<Vec<_>>().join("; ");
    s.truncate(2000);
    s
}

/// One rotating part of a full data check (design §6: a rotating 1/30 a day).
fn check_data(ctx: &Ctx, part: u32, of: u32) -> Result<Value> {
    if of == 0 || part == 0 || part > of {
        return Err(Fail::new("request_invalid", "part must be in 1..=of"));
    }
    let repo = ctx.open(false)?;
    let opts = CheckOptions::default()
        .trust_cache(false)
        .read_data(true)
        .read_data_subset(ReadSubsetOption::IdSubSet((part, of)));
    let results = repo.check(opts).map_err(lib("check_failed"))?;
    results.is_ok().map_err(|_| Fail::new("check_failed", findings(&results.0)))?;
    Ok(json!({ "part": part, "of": of, "findings": results.0.len() }))
}

fn check_id(id: &str) -> Result<()> {
    if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Fail::new("request_invalid", "a snapshot id is 64 hex digits (no prefixes, no `latest`)"));
    }
    Ok(())
}

fn one_snapshot(repo: &Repository<OpenStatus>, id: &str) -> Result<SnapshotFile> {
    check_id(id)?;
    let mut v = repo.get_snapshots(&[id]).map_err(lib("snapshot_missing"))?;
    v.pop().ok_or_else(|| Fail::new("snapshot_missing", "no such snapshot"))
}

fn snapshots(ctx: &Ctx) -> Result<Value> {
    let repo = ctx.open(false)?;
    let all = repo.get_all_snapshots().map_err(lib("list_failed"))?;
    Ok(json!({ "snapshots": all.iter().map(snapshot_json).collect::<Vec<_>>() }))
}

/// One small file from a snapshot, as UTF-8 text (the host manifest is read this way).
fn dump(ctx: &Ctx, snapshot: &str, path: &str) -> Result<Value> {
    let repo = ctx.open(false)?;
    let snap = one_snapshot(&repo, snapshot)?;
    let repo = repo.to_indexed().map_err(lib("index_failed"))?;
    // The node is found from the snapshot already resolved by its full id, never by re-parsing an id string (an
    // abbreviated id would be ambiguous once two snapshots share its prefix).
    let node = repo.node_from_snapshot_and_path(&snap, path).map_err(lib("dump_failed"))?;
    if !node.is_file() {
        return Err(Fail::new("dump_failed", "not a regular file"));
    }
    if node.meta.size > MAX_DUMP {
        return Err(Fail::new("dump_failed", "the file is larger than 16 MiB"));
    }
    let mut buf = Vec::new();
    repo.dump(&node, &mut buf).map_err(lib("dump_failed"))?;
    let text = String::from_utf8(buf).map_err(|_| Fail::new("dump_failed", "the file isn't UTF-8"))?;
    Ok(json!({ "text": text }))
}

/// Restore into an existing, empty staging directory (host backup design r3.3 §5.7-§5.8): refused unless CAP_SYS_RESOURCE is gone
/// from all five sets, under no_new_privs, so the agent's project quota is enforced by the kernel. Sparse files are
/// restored sparse or not at all; numeric ids; nothing in the destination is deleted.
///
/// Device nodes, FIFOs and sockets are never created, and no extended attribute is ever written (ACLs and file
/// capabilities are extended attributes): the node stream is filtered before the library sees it, and the result
/// counts what was skipped. The fill re-checks both before anything reaches an agent's tree.
fn restore(ctx: &Ctx, snapshot: &str, path: Option<&str>, dest: &Path) -> Result<Value> {
    caps::require_no_sys_resource()?;
    if !dest.is_absolute() {
        return Err(Fail::new("request_invalid", "dest must be absolute"));
    }
    let meta = fs::symlink_metadata(dest).map_err(|e| Fail::new("request_invalid", format!("dest: {e}")))?;
    if !meta.is_dir() {
        return Err(Fail::new("request_invalid", "dest must be an existing directory (not a symlink)"));
    }
    if fs::read_dir(dest).map_err(|e| Fail::new("request_invalid", format!("dest: {e}")))?.next().is_some() {
        return Err(Fail::new("request_invalid", "dest must be empty"));
    }
    let repo = ctx.open(false)?;
    let snap = one_snapshot(&repo, snapshot)?;
    let repo = repo.to_indexed().map_err(lib("index_failed"))?;
    let node = repo.node_from_snapshot_and_path(&snap, path.unwrap_or("")).map_err(lib("restore_failed"))?;
    let special = |n: &Node| matches!(n.node_type, NodeType::Dev { .. } | NodeType::Chardev { .. } | NodeType::Fifo | NodeType::Socket);
    let ls = repo
        .ls(&node, &LsOptions::default())
        .map_err(lib("restore_failed"))?
        .filter(move |r| !matches!(r, Ok((_, n)) if special(n)))
        .map(|r| {
            r.map(|(path, mut n)| {
                n.meta.extended_attributes.clear();
                (path, n)
            })
        });
    let mut skipped = 0u64;
    for r in repo.ls(&node, &LsOptions::default()).map_err(lib("restore_failed"))? {
        if matches!(r, Ok((_, ref n)) if special(n)) {
            skipped += 1;
        }
    }
    let dest_str = dest.to_str().ok_or_else(|| Fail::new("request_invalid", "dest must be UTF-8"))?;
    let dest = LocalDestination::new(&format!("{dest_str}/"), false, !node.is_dir()).map_err(lib("restore_failed"))?;
    let mut opts = RestoreOptions::default();
    opts.numeric_id = true;
    opts.sparse = Some(SparseRestore::ByContentRequired);
    let plan = repo.prepare_restore(&opts, ls.clone(), &dest, false).map_err(lib("restore_failed"))?;
    repo.restore(plan, &opts, ls, &dest).map_err(lib("restore_failed"))?;
    Ok(json!({ "snapshot": full(*snap.id), "skipped_special": skipped }))
}

fn forget(ctx: &Ctx, ids: &[String]) -> Result<Value> {
    if ids.is_empty() {
        return Err(Fail::new("request_invalid", "no snapshots given"));
    }
    let repo = ctx.open(true)?;
    let mut found = Vec::new();
    for id in ids {
        found.push(one_snapshot(&repo, id)?.id);
    }
    repo.delete_snapshots(&found).map_err(lib("forget_failed"))?;
    Ok(json!({ "forgotten": found.len() }))
}

/// Prune with rustic's delayed pack deletion (keep_delete, 23 h by default); never instant.
fn prune(ctx: &Ctx) -> Result<Value> {
    let repo = ctx.open(true)?;
    let opts = PruneOptions::default();
    assert!(!opts.instant_delete);
    let plan = repo.prune_plan(&opts).map_err(lib("prune_failed"))?;
    let mut stats = format!("{:?}", plan.stats);
    stats.truncate(4000);
    repo.prune(&opts, plan).map_err(lib("prune_failed"))?;
    Ok(json!({ "stats": stats }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags() {
        assert!(check_tag("sb-state=good").is_ok());
        assert!(check_tag("agent=abc123").is_ok());
        for bad in ["", "nokey", "a=b,c=d", "a=b c", "a=b\n"] {
            assert!(check_tag(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn ids() {
        assert!(check_id(&"a".repeat(64)).is_ok());
        for bad in ["latest", "abcd", &"g".repeat(64)] {
            assert!(check_id(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn requests_are_closed() {
        assert!(serde_json::from_str::<Request>(r#"{"op":"prune"}"#).is_ok());
        assert!(serde_json::from_str::<Request>(r#"{"op":"prune","instant":true}"#).is_err());
        assert!(serde_json::from_str::<Request>(r#"{"op":"backup","sources":["/a"],"host":"h","ignore_ctime":true}"#).is_err());
        assert!(serde_json::from_str::<Request>(r#"{"op":"auto-init"}"#).is_err());
        assert!(serde_json::from_str::<Request>(r#"{"op":"init","force":true}"#).is_err());
        assert!(serde_json::from_str::<Request>(r#"{"op":"snapshots"}"#).is_ok());
        assert!(serde_json::from_str::<Request>(r#"{"op":"restore","snapshot":"x","dest":"/d","no_cap_check":true}"#).is_err());
    }
}
