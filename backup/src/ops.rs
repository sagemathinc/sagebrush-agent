//! The operations: init, add-key, backup, readback, check-data, snapshots, dump, restore, forget, prune, usage and
//! tree. The host supervisor decides when; this binary only does each one exactly, and refuses what the design
//! forbids: it never initializes a repository except on `init`, never skips the ctime or inode comparison, and never
//! restores with CAP_SYS_RESOURCE.

use std::os::unix::ffi::OsStrExt;
use std::{
    collections::{HashMap, HashSet},
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
use sha2::{Digest, Sha256};
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
        /// Where the digest list goes (A2 r3.8.2 §4b): beside `dest`, never inside it.
        digests: PathBuf,
    },
    Forget {
        snapshots: Vec<String>,
    },
    Prune {},
    Usage {
        snapshot: String,
        #[serde(default)]
        path: Option<String>,
    },
    Tree {
        snapshot: String,
        path: String,
        #[serde(default)]
        cursor: Option<String>,
    },
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
        Request::Restore { snapshot, path, dest, digests } => restore(ctx, &snapshot, path.as_deref(), &dest, &digests),
        Request::Forget { snapshots } => forget(ctx, &snapshots),
        Request::Prune {} => prune(ctx),
        Request::Usage { snapshot, path } => usage(ctx, &snapshot, path.as_deref()),
        Request::Tree { snapshot, path, cursor } => tree(ctx, &snapshot, &path, cursor.as_deref()),
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
/// The tag this binary adds to every snapshot it makes, all of them strict (config tree d2r8): any error while walking
/// a source fails the backup with no snapshot, so a source in a marked snapshot's `paths` but absent from its tree was
/// empty. Never a caller's: a request tag starting `sagebrush.walk=` is refused.
pub(crate) const STRICT_MARK: &str = "sagebrush.walk=strict";
/// A request's tags, at most: the mark makes one more, and a snapshot carries at most 64.
const MAX_TAGS: usize = 63;

fn check_tag(t: &str) -> Result<()> {
    let ok = !t.is_empty() && t.len() <= 128 && t.contains('=') && !t.starts_with("sagebrush.walk=")
        && t.bytes().all(|b| b.is_ascii_alphanumeric() || b"._:=-".contains(&b));
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
    if tags.len() > MAX_TAGS {
        return Err(Fail::new("request_invalid", "at most 63 tags"));
    }
    for t in tags {
        check_tag(t)?;
    }
    // Tests only (never in a release build: backup-build.sh enables no feature, and CI checks the pinned build holds no
    // trace of these names): one non-strict, unmarked snapshot, for the rows that show such a snapshot proves nothing.
    #[cfg(feature = "test-walk-hooks")]
    let strict = std::env::var("SB_TEST_NONSTRICT").as_deref() != Ok("1");
    #[cfg(not(feature = "test-walk-hooks"))]
    let strict = true;
    let mut tags = tags.to_vec();
    if strict {
        tags.push(STRICT_MARK.to_string());
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
    // Strict, always (d2r8): any error from the source walk, the size scan or a file's processing fails the backup
    // before its snapshot is written (rustic_core archiver.rs), so a source is never silently left out.
    opts.strict = strict;
    opts.parent_opts = parent_opts;
    opts.ignore_filter_opts = filter;
    opts.excludes = ex;
    let source = sources.iter().cloned().collect::<PathList>().sanitize().map_err(|e| Fail::new("request_invalid", e.to_string()))?;
    // Tests only, like the above: a gate between the sources' canonicalization and the walk, so a row can change a
    // source there deterministically (`<dir>/ready` written, then at most 60 s for `<dir>/go`).
    #[cfg(feature = "test-walk-hooks")]
    if let Ok(dir) = std::env::var("SB_TEST_SANITIZED_GATE") {
        let dir = PathBuf::from(dir);
        let _ = fs::write(dir.join("ready"), b"");
        let t0 = std::time::Instant::now();
        while !dir.join("go").exists() && t0.elapsed() < std::time::Duration::from_secs(60) {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }
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
/// The digest list's place (launcher contract A2 r3.8.2 §4b): `digests.json` beside `dest` (never inside it, so
/// fill-home never moves it), absolute, and not there yet.
fn check_digests_place(dest: &Path, digests: &Path) -> Result<()> {
    if !digests.is_absolute() || digests.file_name().map(|n| n.as_bytes()) != Some(b"digests.json".as_slice()) || digests.parent() != dest.parent() {
        return Err(Fail::new("request_invalid", "digests must be digests.json beside dest"));
    }
    if fs::symlink_metadata(digests).is_ok() {
        return Err(Fail::new("request_invalid", "digests must not exist yet"));
    }
    Ok(())
}

fn restore(ctx: &Ctx, snapshot: &str, path: Option<&str>, dest: &Path, digests: &Path) -> Result<Value> {
    caps::require_no_sys_resource()?;
    if !dest.is_absolute() {
        return Err(Fail::new("request_invalid", "dest must be absolute"));
    }
    check_digests_place(dest, digests)?;
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
    let node = match path {
        None => repo.node_from_snapshot_and_path(&snap, "").map_err(lib("restore_failed"))?,
        Some(p) => match resolve(snap.tree, p, |id| repo.get_tree(id).map(|t| t.nodes).map_err(lib("restore_failed")))? {
            Resolved::Node(n) => n,
            // An EMPTY source (restore empty-source d1): absent from the tree of a strict snapshot (the binary's own mark,
            // matched exactly) whose `paths` names exactly this source. Nothing is written into `dest` (the stage's own
            // fresh directory stays as it is); the digest list is an empty destination's. Anything else is refused.
            Resolved::Absent if proves_empty(snap.tags.iter(), snap.paths.iter(), p) => {
                let bytes = crate::digests::listing(dest)?;
                let digests_sha256 = crate::digests::write_new(digests, &bytes)?;
                return Ok(json!({ "snapshot": full(*snap.id), "skipped_special": 0, "digests_sha256": digests_sha256 }));
            }
            Resolved::Absent => return Err(Fail::new("restore_absent", "restore: the path isn't in the snapshot, and the snapshot doesn't prove it was empty")),
            Resolved::NotADirectory => return Err(Fail::new("restore_absent", "restore: an ancestor of the path isn't a directory")),
        },
    };
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
    // The digest list of exactly what was written (from the MAC-verified plaintext), then its hash for the launcher.
    let bytes = crate::digests::listing(Path::new(dest_str))?;
    let digests_sha256 = crate::digests::write_new(digests, &bytes)?;
    Ok(json!({ "snapshot": full(*snap.id), "skipped_special": skipped, "digests_sha256": digests_sha256 }))
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

/// The space a restore of `path` from a snapshot can need, from the tree's metadata only (no data is read): an UPPER
/// bound on the ext4 blocks it charges, and the exact number of inodes (host backup design r3.3 §5.7; the proof is
/// on `Tally`). The restore's own filter applies: device nodes, FIFOs and sockets are never created, so not counted.
fn usage(ctx: &Ctx, snapshot: &str, path: Option<&str>) -> Result<Value> {
    let repo = ctx.open(false)?;
    let snap = one_snapshot(&repo, snapshot)?;
    let repo = repo.to_indexed_ids().map_err(lib("index_failed"))?;
    let node = repo.node_from_snapshot_and_path(&snap, path.unwrap_or("")).map_err(lib("usage_failed"))?;
    let mut t = Tally::default();
    for r in repo.ls(&node, &LsOptions::default()).map_err(lib("usage_failed"))? {
        let (p, n) = r.map_err(lib("usage_failed"))?;
        t.add(&p, &n);
    }
    let u = t.finish();
    Ok(json!({
        "snapshot": full(*snap.id), "entries": u.entries, "inodes": u.inodes, "blocks_upper": u.blocks,
        "peak_inodes": u.peak_inodes, "peak_blocks_upper": u.peak_blocks, "block_size": BLOCK,
    }))
}

/// Bounds of one `tree` page (config tree design d2r1 §0.3): a page ends before the entry that would pass any of them,
/// and always holds at least one entry, so every page stays far under the host runner's output cap.
const TREE_PAGE_ENTRIES: usize = 2048;
const TREE_PAGE_BYTES: usize = 4 * 1024 * 1024;
const TREE_PAGE_HASH_BYTES: u64 = 256 * 1024 * 1024;

/// Is `name` agent-config's leftover generation, `.gen-<n>.tmp` (n canonical decimal, at most 8 digits)? The same rule
/// as agent-config.mjs GEN_TMP (`^\.gen-(0|[1-9][0-9]{0,7})\.tmp$`); a census row keeps the two equal.
fn is_gen_tmp(name: &str) -> bool {
    let Some(n) = name.strip_prefix(".gen-").and_then(|r| r.strip_suffix(".tmp")) else { return false };
    n == "0" || (!n.is_empty() && n.len() <= 8 && !n.starts_with('0') && n.bytes().all(|b| b.is_ascii_digit()))
}

/// A stored mode (Go's encoding, as the archiver saves it) as the POSIX permission and special bits the restore sets:
/// the low 9 bits, and setuid, setgid and sticky from Go's high bits (never dropped, so a setuid file is never 0600).
fn posix_mode(go: u32) -> u32 {
    let mut m = go & 0o777;
    if go & (1 << 23) != 0 { m |= 0o4000; }
    if go & (1 << 22) != 0 { m |= 0o2000; }
    if go & (1 << 20) != 0 { m |= 0o1000; }
    m
}

/// Where a requested path is in a snapshot (shared by `tree` and `restore`; restore empty-source d1, SEC S1).
enum Resolved {
    /// The path's own node.
    Node(Node),
    /// A component is missing from a directory that WAS read: what an empty source looks like (the archiver keeps no
    /// node for one, d2r7). The only case that may ever prove "empty", and only from a strict snapshot naming it.
    Absent,
    /// An ancestor isn't a directory: structural, never "absent" (so never read as an empty source).
    NotADirectory,
}

/// Resolve `path` (relative, normalized) from the snapshot's root tree `root`, component by component. `get(id)` reads
/// one tree's nodes; its failure is a read failure (the caller's code), never "absent".
fn resolve(root: rustic_core::TreeId, path: &str, get: impl Fn(&rustic_core::TreeId) -> Result<Vec<Node>>) -> Result<Resolved> {
    let mut subtree = Some(root);
    let mut node: Option<Node> = None;
    for comp in path.split('/') {
        let Some(id) = subtree else { return Ok(Resolved::NotADirectory) };
        let Some(found) = get(&id)?.into_iter().find(|n| n.name().as_bytes() == comp.as_bytes()) else { return Ok(Resolved::Absent) };
        if !found.is_dir() && found.subtree.is_some() {
            return Ok(Resolved::NotADirectory);
        }
        subtree = if found.is_dir() { found.subtree } else { None };
        node = Some(found);
    }
    Ok(node.map_or(Resolved::Absent, Resolved::Node))
}

/// Whether a snapshot's own record proves the absent `path` was an EMPTY source (restore empty-source d1): the
/// binary's strict mark among its tags, matched as a whole tag (SEC S2), and `"/" + path` exactly among its paths.
fn proves_empty<'a>(mut tags: impl Iterator<Item = &'a String>, mut paths: impl Iterator<Item = &'a String>, path: &str) -> bool {
    let want = format!("/{path}");
    tags.any(|t| t == STRICT_MARK) && paths.any(|q| *q == want)
}

/// The requested path isn't in the snapshot (d2r7): structural, and distinct, because an EMPTY source is never stored
/// (the archiver keeps no node for it), which a strict snapshot naming the source in its `paths` proves (d2r8).
fn absent() -> Fail {
    Fail::new("tree_absent", "tree: the path isn't in the snapshot")
}

/// A structural answer about this snapshot and request (design d2r5 E2): the backup run reads it as "not provable".
fn refused(why: &str) -> Fail {
    Fail::new("tree_refused", why)
}

/// `tree`: the BACKUP RUN'S CONFIG PROOF's listing of a saved subtree (config tree design d2r1, d2r2, d2r5), one page at
/// a time. It is that proof's op, not a general listing: it never descends into a DIRECT child of `path` named
/// `.gen-<n>.tmp`, because the restore's reader of agent-config never reads inside one (it emits that node only).
/// - The walk: `path`'s own node first (index 0, path ""), then depth first, each directory's nodes in stored order.
///   Stored metadata only; a regular file's contents are read (and hashed) only for the entries of the page served,
///   never for the entries skipped to reach a cursor's index (N1: hashing over a whole tree is linear).
/// - The cursor: `<snapshot id>:<sha256(path) hex>:<index>`, refused (`tree_refused`) for another snapshot or path.
/// - `tree_failed`: a read failure while serving (transient). `tree_absent`: the path isn't in the snapshot (d2r7).
///   `tree_refused`: a non-UTF-8 name in a walked part, a foreign or malformed cursor, an index past the end.
fn tree(ctx: &Ctx, snapshot: &str, path: &str, cursor: Option<&str>) -> Result<Value> {
    if path.is_empty() || path.starts_with('/') || path.split('/').any(|c| c.is_empty() || c == "." || c == "..") {
        return Err(Fail::new("request_invalid", "tree: the path must be relative and normalized"));
    }
    let repo = ctx.open(false)?;
    let snap = one_snapshot(&repo, snapshot)?;
    let snap_id = full(*snap.id);
    let digest = crate::digests::hex(&Sha256::digest(path.as_bytes()));
    let start: u64 = match cursor {
        None => 0,
        Some(c) => {
            let parts: Vec<&str> = c.split(':').collect();
            let canonical = |i: &str| !i.is_empty() && i.len() <= 19 && (i == "0" || !i.starts_with('0')) && i.bytes().all(|b| b.is_ascii_digit());
            if parts.len() != 3 || parts[0] != snap_id || parts[1] != digest || !canonical(parts[2]) {
                return Err(refused("tree: the cursor isn't this snapshot's and path's"));
            }
            parts[2].parse().map_err(|_| refused("tree: a malformed cursor"))?
        }
    };
    let repo = repo.to_indexed().map_err(lib("index_failed"))?;
    // The path, resolved component by component: a component missing from a tree that WAS read is structural; a
    // tree that can't be read is a read failure.
    let root = match resolve(snap.tree, path, |id| repo.get_tree(id).map(|t| t.nodes).map_err(lib("tree_failed")))? {
        Resolved::Node(n) => n,
        Resolved::Absent => return Err(absent()),
        Resolved::NotADirectory => return Err(refused("tree: an ancestor of the path isn't a directory")),
    };

    // The walk: (relative path, depth, node), depth first. A stack of (a directory's relative path, its children's
    // depth, its remaining nodes). The requested path's own node is depth 0; its direct children are depth 1.
    let mut stack: Vec<(String, usize, std::vec::IntoIter<Node>)> = Vec::new();
    let mut cur: Option<(String, usize, Node)> = Some((String::new(), 0, root));
    let mut index: u64 = 0;
    let mut entries: Vec<Value> = Vec::new();
    let (mut page_bytes, mut page_hash) = (0usize, 0u64);
    let mut next: Option<u64> = None;
    #[cfg(feature = "test-tree-counters")]
    let mut content_bytes_read: u64 = 0;
    while let Some((rel, depth, n)) = cur.take() {
        let this = index;
        index += 1;
        if this >= start {
            let is_file = matches!(n.node_type, NodeType::File);
            if entries.len() >= TREE_PAGE_ENTRIES || (is_file && !entries.is_empty() && page_hash + n.meta.size > TREE_PAGE_HASH_BYTES) {
                next = Some(this);
                break;
            }
            let sha = if is_file {
                let mut h = HashWriter(Sha256::new(), 0);
                repo.dump(&n, &mut h).map_err(lib("tree_failed"))?;
                // The restore writes the contents, so the listed size is theirs: a stored size that differs is refused.
                if h.1 != n.meta.size {
                    return Err(refused("tree: a file's contents aren't its stored size"));
                }
                page_hash += h.1;
                #[cfg(feature = "test-tree-counters")]
                {
                    content_bytes_read += h.1;
                }
                Value::String(crate::digests::hex(&h.0.finalize()))
            } else {
                Value::Null
            };
            let kind = match n.node_type { NodeType::Dir => "dir", NodeType::File => "file", NodeType::Symlink { .. } => "symlink", _ => "other" };
            let entry = json!({
                "index": this, "path": rel, "type": kind, "mode": n.meta.mode.map(posix_mode), "uid": n.meta.uid, "gid": n.meta.gid,
                "nlink": if n.meta.links == 0 { Value::Null } else { json!(n.meta.links) }, "size": n.meta.size, "sha256": sha,
            });
            let len = entry.to_string().len() + 1;
            if !entries.is_empty() && page_bytes + len > TREE_PAGE_BYTES {
                next = Some(this);
                break;
            }
            page_bytes += len;
            entries.push(entry);
        }
        // Descend (metadata only), never into a direct child `.gen-<n>.tmp` of the requested path.
        let leftover = depth == 1 && is_gen_tmp(rel.rsplit('/').next().unwrap_or(""));
        if n.is_dir() && !leftover {
            if let Some(id) = n.subtree {
                let t = repo.get_tree(&id).map_err(lib("tree_failed"))?;
                stack.push((rel.clone(), depth + 1, t.nodes.into_iter()));
            }
        }
        // The next entry in walk order.
        cur = loop {
            let Some((prefix, d, it)) = stack.last_mut() else { break None };
            match it.next() {
                Some(child) => {
                    let name = child.name();
                    let name = name.to_str().ok_or_else(|| refused("tree: a name isn't UTF-8"))?;
                    let rel = if prefix.is_empty() { name.to_string() } else { format!("{prefix}/{name}") };
                    break Some((rel, *d, child));
                }
                None => {
                    stack.pop();
                }
            }
        };
    }
    if start > 0 && start >= index && entries.is_empty() {
        return Err(refused("tree: the cursor's index is past the end"));
    }
    let next = next.map(|i| format!("{snap_id}:{digest}:{i}"));
    #[cfg(feature = "test-tree-counters")]
    return Ok(json!({ "entries": entries, "next": next, "content_bytes_read": content_bytes_read }));
    #[cfg(not(feature = "test-tree-counters"))]
    Ok(json!({ "entries": entries, "next": next }))
}

/// A `Write` that only hashes and counts (a file's contents, read through the repository).
struct HashWriter(Sha256, u64);
impl std::io::Write for HashWriter {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.update(b);
        self.1 += b.len() as u64;
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// ext4's block size here (the quota filesystem is made with 4 KiB blocks).
const BLOCK: u64 = 4096;
/// The longest initialized ext4 extent, in blocks (128 MiB of 4 KiB blocks).
const EXTENT_MAX: u64 = 32768;
/// Extents an inode holds itself; a file with more needs extent tree blocks.
const INLINE_EXTENTS: u64 = 4;
/// Extents per extent tree block ((4096 - 12) / 12).
const EXTENTS_PER_BLOCK: u64 = 340;
/// The longest symlink target an inode holds itself ("fast" symlink); a longer one takes a block.
const FAST_SYMLINK: usize = 59;
/// Index entries per htree index block (a conservative floor of (4096 - 8) / 8).
const DX_PER_BLOCK: u64 = 500;

/// The bound, per restored object (each is created fresh, into an empty destination):
/// - a regular file of `s` bytes, written dense, takes B = ceil(s / 4096) data blocks in E0 = ceil(s / 128 MiB)
///   extents. The restore is sparse (zero runs of at least 4096 bytes are punched): a punch frees at least one whole
///   block whenever it splits an extent, so it adds at most one extent per block it frees, and the extents can never
///   outnumber E0 + B. The design's measured rule charges one extra block per extent (an extent may end a block later).
///   So the file needs at most B + E0 blocks for its data and extents (a punch that adds an extent has freed the block
///   paying for it), plus its extent tree: none while E0 + B fits in the inode (4 extents), else at most
///   ceil((E0 + B) / 340) leaf blocks and one more for the index. Extended attributes are never restored.
/// - a hard link: the inode and its blocks once, exactly when the restorer links it (`hardlink_key`: a regular file,
///   links > 1, nonzero device and inode); every name is a directory entry.
/// - a directory: its entries take 8 + the name's length rounded up to 4 bytes each, plus 24 for "." and "..". Its
///   leaves can be as little as half full after htree splits, so at most 2 * ceil(bytes / 4096) leaf blocks, plus the
///   index root and one index block per 500 leaves. The destination directory itself exists; its entries are counted.
/// - a symlink: a block when its target is longer than 59 bytes, else none (held in the inode).
/// - every entry but the specials: one inode (hard links once). This count is exact, not a bound.
///
/// The PEAK, while a class is filled from its staging (launcher amendment A2 §4): fill-home renames files and symlinks
/// (their inodes move) but makes every directory anew in the destination, while the staged directories stay until the
/// staging is discarded. So at its end every directory exists twice: the peak adds their inodes (exact) and their blocks
/// (the directory bound, the destination's own entries included, since data/<leaf> held them too) once more. The launcher's own staging objects (the attempt, data, data/<leaf>, the marker, the parents) are the
/// space check's to add (restore-space.mjs), not the tree's.
#[derive(Default)]
struct Tally {
    entries: u64,
    inodes: u64,
    blocks: u64,
    /// Directories (made anew by the fill, so twice at the peak).
    twice_inodes: u64,
    /// Directory entry bytes per directory (by its path; "" is the destination itself).
    dirs: HashMap<PathBuf, u64>,
    links: HashSet<(u64, u64)>,
}

impl Tally {
    fn add(&mut self, path: &Path, node: &Node) {
        if matches!(node.node_type, NodeType::Dev { .. } | NodeType::Chardev { .. } | NodeType::Fifo | NodeType::Socket) {
            return; // never restored
        }
        self.entries += 1;
        let parent = path.parent().map(Path::to_path_buf).unwrap_or_default();
        let name = path.file_name().map_or(0, |n| n.len() as u64);
        *self.dirs.entry(parent).or_insert(0) += 8 + name.div_ceil(4) * 4;
        if let Some(key) = hardlink_key(node) {
            if !self.links.insert(key) {
                return; // another name of an inode already counted
            }
        }
        self.inodes += 1;
        match &node.node_type {
            NodeType::Dir => {
                self.twice_inodes += 1;
                self.dirs.entry(path.to_path_buf()).or_insert(0);
            }
            NodeType::Symlink { .. } => {
                if node.node_type.to_link().as_os_str().len() > FAST_SYMLINK {
                    self.blocks += 1;
                }
            }
            _ => self.blocks += file_blocks(node.meta.size),
        }
    }

    fn finish(&self) -> Usage {
        // The destination's own directory (data/<leaf> while staged) is always counted, even with no entry.
        let root = if self.dirs.contains_key(Path::new("")) { 0 } else { dir_blocks(24) };
        let dirs: u64 = root + self.dirs.values().map(|bytes| dir_blocks(bytes + 24)).sum::<u64>();
        Usage {
            entries: self.entries,
            inodes: self.inodes,
            blocks: self.blocks + dirs,
            peak_inodes: self.inodes + self.twice_inodes,
            peak_blocks: self.blocks + dirs + dirs,
        }
    }
}

/// What a restore of a path needs: after the fill (`inodes`, `blocks`) and at its peak, before the staging is
/// discarded (`peak_*`). Inodes are exact; blocks are upper bounds.
#[derive(Debug, PartialEq)]
struct Usage {
    entries: u64,
    inodes: u64,
    blocks: u64,
    peak_inodes: u64,
    peak_blocks: u64,
}

/// The restorer's own rule for which names are one inode (rustic_core 51115c47, commands/restore.rs `hardlink_key`):
/// a regular file with more than one link and a nonzero device and inode. Anything else (a symlink, a zero id) is
/// restored as its own inode, so counted as one.
fn hardlink_key(node: &Node) -> Option<(u64, u64)> {
    (matches!(node.node_type, NodeType::File) && node.meta.links > 1 && node.meta.device_id != 0 && node.meta.inode != 0)
        .then_some((node.meta.device_id, node.meta.inode))
}

/// A regular file's bound (see `Tally`).
fn file_blocks(size: u64) -> u64 {
    let data = size.div_ceil(BLOCK);
    let extents = size.div_ceil(BLOCK * EXTENT_MAX);
    let worst = extents + data;
    let tree = if worst <= INLINE_EXTENTS { 0 } else { worst.div_ceil(EXTENTS_PER_BLOCK) + 1 };
    data + extents + tree
}

/// A directory's bound (see `Tally`).
fn dir_blocks(bytes: u64) -> u64 {
    let leaves = 2 * bytes.div_ceil(BLOCK);
    1 + leaves + leaves.div_ceil(DX_PER_BLOCK)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags() {
        assert!(check_tag("sb-state=good").is_ok());
        assert!(check_tag("agent=abc123").is_ok());
        for bad in ["", "nokey", "a=b,c=d", "a=b c", "a=b\n", STRICT_MARK, "sagebrush.walk=lax", "sagebrush.walk="] {
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
        assert!(serde_json::from_str::<Request>(r#"{"op":"restore","snapshot":"x","dest":"/a/d","digests":"/a/digests.json","no_cap_check":true}"#).is_err());
        assert!(serde_json::from_str::<Request>(r#"{"op":"usage","snapshot":"x"}"#).is_ok());
        assert!(serde_json::from_str::<Request>(r#"{"op":"usage","snapshot":"x","path":"srv/a"}"#).is_ok());
        assert!(serde_json::from_str::<Request>(r#"{"op":"usage","snapshot":"x","exact":true}"#).is_err());
    }

    use rustic_core::repofile::Metadata;
    use std::ffi::OsStr;

    fn file(size: u64) -> Node {
        Node::new_node(OsStr::new("f"), NodeType::File, Metadata { size, links: 1, ..Default::default() })
    }

    #[test]
    fn a_file_bound() {
        // Empty: no data, no extent, no tree.
        assert_eq!(file_blocks(0), 0);
        // One byte: one block in one extent, plus that extent's block.
        assert_eq!(file_blocks(1), 2);
        assert_eq!(file_blocks(4096), 2);
        assert_eq!(file_blocks(4097), 3);
        // Three blocks: 3 data + 1 extent, the worst case 4 extents fits in the inode: no tree.
        assert_eq!(file_blocks(3 * 4096), 4);
        // Four blocks: the worst case is 5 extents (every block its own, plus one): a tree leaf and its index.
        assert_eq!(file_blocks(4 * 4096), 4 + 1 + 2);
    }

    #[test]
    fn a_sparse_file_is_bounded_by_its_dense_size() {
        // 1 GiB, mostly holes or not: the bound never depends on the content, only the size, and covers the dense
        // write (every block) with its 8 extents, plus a tree for the worst split into one extent per block.
        let s = 1u64 << 30;
        let data = s / 4096; // 262144
        let extents = 8; // 1 GiB / 128 MiB
        let tree = (data + extents).div_ceil(340) + 1;
        assert_eq!(file_blocks(s), data + extents + tree);
        // Every punched hole frees a block and adds at most one extent: the worst split (each block its own extent)
        // still fits under the bound, data + extents of the split never above data + extents dense.
        for punched in [0, 1, 1000, data / 2, data - 1] {
            let left = data - punched;
            let split = extents + punched; // at most one more extent per freed block
            assert!(left + split + (left + split).div_ceil(340) + 1 <= file_blocks(s), "{punched}");
        }
    }

    #[test]
    fn extents_split_at_the_ext4_maximum() {
        let m = EXTENT_MAX * BLOCK; // 128 MiB
        assert_eq!(file_blocks(m) - file_blocks(m - 4096), 1, "the same extent count");
        assert_eq!(file_blocks(m + 1), m / 4096 + 1 + 2 + (m / 4096 + 1 + 2).div_ceil(340) + 1, "a second extent");
    }

    #[test]
    fn a_tally() {
        let mut t = Tally::default();
        t.add(Path::new("a"), &file(10_000)); // 3 blocks + 1 extent
        let dir = Node::new_node(OsStr::new("d"), NodeType::Dir, Metadata { links: 2, ..Default::default() });
        t.add(Path::new("d"), &dir);
        // Hard links: the inode and its blocks once, every name an entry.
        let linked = |name: &str| Node::new_node(OsStr::new(name), NodeType::File, Metadata { size: 8192, links: 2, inode: 77, device_id: 3, ..Default::default() });
        t.add(Path::new("d/x"), &linked("x"));
        t.add(Path::new("d/y"), &linked("y"));
        // A link of another inode with the same number on another device is another inode.
        t.add(Path::new("d/z"), &Node::new_node(OsStr::new("z"), NodeType::File, Metadata { size: 8192, links: 2, inode: 77, device_id: 4, ..Default::default() }));
        // Symlinks: 59 bytes in the inode, 60 take a block.
        t.add(Path::new("s59"), &Node::new_node(OsStr::new("s59"), NodeType::from_link(Path::new(&"t".repeat(59))), Metadata::default()));
        t.add(Path::new("s60"), &Node::new_node(OsStr::new("s60"), NodeType::from_link(Path::new(&"t".repeat(60))), Metadata::default()));
        // Specials are never restored: not counted at all.
        t.add(Path::new("fifo"), &Node::new_node(OsStr::new("fifo"), NodeType::Fifo, Metadata::default()));
        let u = t.finish();
        let (entries, inodes, blocks) = (u.entries, u.inodes, u.blocks);
        assert_eq!(entries, 7, "a, d, x, y, z, s59, s60");
        assert_eq!(inodes, 6, "x and y are one inode");
        // Files: a 3+1, x 2+1 (once), z 2+1; s60 1; dirs: the destination (a, d, s59, s60) and d (x, y, z).
        let root = dir_blocks(24 + (8 + 4) + (8 + 4) + (8 + 4) + (8 + 4));
        let d = dir_blocks(24 + 3 * (8 + 4));
        assert_eq!(blocks, 4 + 3 + 3 + 1 + root + d);
        // The peak: only d exists twice (made anew by the fill), and every directory's blocks (the destination's entries
        // included) once more. Files and symlinks are renamed: once.
        assert_eq!(u.peak_inodes, 6 + 1);
        assert_eq!(u.peak_blocks, blocks + root + d);
    }

    #[test]
    fn hard_links_exactly_as_the_restorer_makes_them() {
        let node = |t: NodeType, links, device_id, inode| Node::new_node(OsStr::new("n"), t, Metadata { size: 100, links, device_id, inode, ..Default::default() });
        let count = |nodes: &[Node]| {
            let mut t = Tally::default();
            for (i, n) in nodes.iter().enumerate() {
                t.add(&PathBuf::from(format!("n{i}")), n);
            }
            t.finish().inodes
        };
        // Regular files with links > 1 and nonzero ids: one inode.
        assert_eq!(count(&[node(NodeType::File, 2, 3, 77), node(NodeType::File, 2, 3, 77)]), 1);
        // A hard-linked symlink pair: the restorer makes two symlinks.
        let link = || node(NodeType::from_link(Path::new("target")), 2, 3, 78);
        assert_eq!(count(&[link(), link()]), 2);
        // Zero device or zero inode: never linked by the restorer, so two inodes.
        assert_eq!(count(&[node(NodeType::File, 2, 0, 79), node(NodeType::File, 2, 0, 79)]), 2);
        assert_eq!(count(&[node(NodeType::File, 2, 3, 0), node(NodeType::File, 2, 3, 0)]), 2);
        // links == 1 with equal ids: two.
        assert_eq!(count(&[node(NodeType::File, 1, 3, 80), node(NodeType::File, 1, 3, 80)]), 2);
        assert_eq!(hardlink_key(&node(NodeType::File, 2, 3, 77)), Some((3, 77)));
        assert_eq!(hardlink_key(&link()), None);
    }

    #[test]
    fn symlinks_are_moved_not_made_anew() {
        // One long symlink: a block and an inode, once, at the end and at the peak (the fill renames it).
        let mut t = Tally::default();
        t.add(Path::new("l"), &Node::new_node(OsStr::new("l"), NodeType::from_link(Path::new(&"t".repeat(200))), Metadata::default()));
        let u = t.finish();
        let root = dir_blocks(24 + 8 + 4);
        assert_eq!((u.inodes, u.blocks), (1, 1 + root));
        assert_eq!((u.peak_inodes, u.peak_blocks), (1, 1 + 2 * root), "only the destination directory's blocks twice");
    }

    #[test]
    fn an_empty_class() {
        let u = Tally::default().finish();
        // Nothing restored, but the destination's (empty) directory bound still counts once, and twice at the peak.
        assert_eq!(u, Usage { entries: 0, inodes: 0, blocks: dir_blocks(24), peak_inodes: 0, peak_blocks: 2 * dir_blocks(24) });
    }

    #[test]
    fn a_directory_bound() {
        assert_eq!(dir_blocks(24), 1 + 2 + 1);
        // 100,000 entries of 20-byte names (28 bytes each): ~684 blocks full, at most twice that in leaves.
        let bytes: u64 = 24 + 100_000 * 28;
        let leaves = 2 * bytes.div_ceil(4096);
        assert_eq!(dir_blocks(bytes), 1 + leaves + leaves.div_ceil(500));
        // Name lengths round up to 4.
        let mut t = Tally::default();
        t.add(Path::new("abcde"), &file(0));
        assert_eq!(t.dirs[Path::new("")], 8 + 8);
        // "." and ".." (24 bytes) count: 255 entries of 8-byte names are 4080 bytes, 4104 with them, so two blocks of
        // entries, four leaves at worst.
        let mut t = Tally::default();
        for i in 0..255 {
            t.add(&PathBuf::from(format!("n{i:07}")), &file(0));
        }
        assert_eq!(t.dirs[Path::new("")], 4080);
        assert_eq!(t.finish().blocks, 1 + 4 + 1, "the dot entries push the directory into a second block");
    }

    #[test]
    fn the_digest_list_goes_beside_dest_once() {
        let base = std::env::temp_dir().join(format!("sbb-dplace-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(base.join("data")).unwrap();
        let dest = base.join("data");
        assert!(check_digests_place(&dest, &base.join("digests.json")).is_ok());
        for bad in [base.join("data/digests.json"), base.join("other.json"), PathBuf::from("digests.json"), std::env::temp_dir().join("digests.json")] {
            assert_eq!(check_digests_place(&dest, &bad).unwrap_err().code, "request_invalid", "{bad:?}");
        }
        fs::write(base.join("digests.json"), b"x").unwrap();
        assert_eq!(check_digests_place(&dest, &base.join("digests.json")).unwrap_err().code, "request_invalid", "already there");
        // a request without digests isn't a restore request
        assert!(serde_json::from_str::<Request>(r#"{"op":"restore","snapshot":"x","dest":"/a/d"}"#).is_err());
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn the_leftover_name_is_agent_configs() {
        // The census shared with agent-config.mjs's GEN_TMP (a JS row reads the same table).
        let t: Value = serde_json::from_str(include_str!("../tests/gen-tmp-cases.json")).unwrap();
        let cases = t["cases"].as_array().unwrap();
        assert!(cases.len() >= 30);
        for c in cases {
            let name = c["name"].as_str().unwrap();
            assert_eq!(is_gen_tmp(name), c["leftover"].as_bool().unwrap(), "{name:?}");
        }
    }

    #[test]
    fn only_the_whole_mark_and_the_exact_path_prove_an_empty_source() {
        let v = |xs: &[&str]| xs.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        let yes = |tags: &[&str], paths: &[&str], p: &str| proves_empty(v(tags).iter(), v(paths).iter(), p);
        assert!(yes(&["sb-state=good", STRICT_MARK], &["/srv/a", "/srv/cfg"], "srv/cfg"));
        for (what, tags) in [("no mark", vec!["sb-state=good"]), ("a suffix", vec!["sagebrush.walk=strictX"]), ("a prefix of it", vec!["sagebrush.walk=stric"]),
            ("another case", vec!["SAGEBRUSH.WALK=strict"]), ("inside a longer tag", vec!["x.sagebrush.walk=strict"]), ("split across two tags", vec!["sagebrush.walk=", "strict"])] {
            assert!(!yes(&tags, &["/srv/cfg"], "srv/cfg"), "{what}");
        }
        for (what, p) in [("a descendant", "srv/cfg/child"), ("a suffix", "srv/cfgx"), ("a parent", "srv"), ("another", "srv/b")] {
            assert!(!yes(&[STRICT_MARK], &["/srv/cfg"], p), "{what}");
        }
        assert!(!yes(&[STRICT_MARK], &["/srv/cfg/"], "srv/cfg"), "a trailing slash isn't the path");
    }

    #[test]
    fn the_resolver_tells_absent_from_not_a_directory() {
        use rustic_core::{Id, TreeId};
        use std::{collections::HashMap, ffi::OsStr};
        let (root, d) = (TreeId::from(Id::random()), TreeId::from(Id::random()));
        let mut dir = Node::new_node(OsStr::new("d"), NodeType::Dir, Default::default());
        dir.subtree = Some(d);
        let file = Node::new_node(OsStr::new("f"), NodeType::File, Default::default());
        let inner = Node::new_node(OsStr::new("x"), NodeType::File, Default::default());
        let trees: HashMap<TreeId, Vec<Node>> = [(root, vec![dir, file]), (d, vec![inner])].into_iter().collect();
        let get = |id: &TreeId| trees.get(id).cloned().ok_or_else(|| Fail::new("restore_failed", "unreadable"));
        let what = |p: &str| match resolve(root, p, get) {
            Ok(Resolved::Node(n)) => format!("node {}", n.name().to_string_lossy()),
            Ok(Resolved::Absent) => "absent".into(),
            Ok(Resolved::NotADirectory) => "not a directory".into(),
            Err(e) => e.code.to_string(),
        };
        assert_eq!(what("d/x"), "node x");
        assert_eq!(what("f"), "node f");
        assert_eq!(what("y"), "absent", "missing from a directory that was read");
        assert_eq!(what("d/y"), "absent");
        assert_eq!(what("f/below"), "not a directory", "a file at an ancestor is structural, never absent (SEC S1)");
        assert_eq!(what("d/x/below"), "not a directory");
        // A tree that can't be read is a read failure, never absent (TESTS T2's unit half).
        let lost: HashMap<TreeId, Vec<Node>> = [(root, trees[&root].clone())].into_iter().collect();
        assert_eq!(match resolve(root, "d/x", |id: &TreeId| lost.get(id).cloned().ok_or_else(|| Fail::new("restore_failed", "unreadable"))) {
            Err(e) => e.code.to_string(),
            Ok(_) => "resolved".into(),
        }, "restore_failed");
    }

    #[test]
    fn a_stored_mode_keeps_its_special_bits() {
        assert_eq!(posix_mode(0o600), 0o600);
        assert_eq!(posix_mode((1 << 31) | 0o755), 0o755, "the type bits aren't permissions");
        assert_eq!(posix_mode((1 << 23) | 0o600), 0o4600);
        assert_eq!(posix_mode((1 << 22) | 0o700), 0o2700);
        assert_eq!(posix_mode((1 << 31) | (1 << 20) | 0o700), 0o1700);
    }
}
