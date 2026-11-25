//! The operations: init, add-key, backup, readback, check-data, snapshots, dump, restore, forget, prune and
//! usage. The host supervisor decides when; this binary only does each one exactly, and refuses what the design
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
        "listing_bytes_upper": u.listing_bytes,
    }))
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
///
/// The DIGEST LIST the restore writes beside the class (data/digests.json, launcher amendment A2 §4b) is one more file
/// in staging, from the stage until the attempt is discarded: `listing_bytes` bounds its length, from the same lines
/// the list is made of (digests.rs), every name its own line (hard links included), each mode at its widest (4 digits:
/// set-id is never listed), every size exact. The space check charges it as a file of that many bytes.
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
    /// The digest list's entry lines so far (bytes), and its files' sizes (its trailer's total).
    listing: u64,
    total: u64,
}

impl Tally {
    fn add(&mut self, path: &Path, node: &Node) {
        if matches!(node.node_type, NodeType::Dev { .. } | NodeType::Chardev { .. } | NodeType::Fifo | NodeType::Socket) {
            return; // never restored
        }
        self.entries += 1;
        // The list's line of this name: mode 1023 (0o1777) is the widest a listed mode can be.
        let raw = path.as_os_str().as_bytes();
        self.listing += match &node.node_type {
            NodeType::Dir => crate::digests::line_dir(raw, 1023).len(),
            NodeType::Symlink { .. } => crate::digests::line_symlink(raw, node.node_type.to_link().as_os_str().as_bytes()).len(),
            _ => {
                self.total += node.meta.size;
                crate::digests::line_file(raw, node.meta.size, 1023, &[0; 32]).len()
            }
        } as u64;
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
            listing_bytes: (b"{\"v\":1}\n".len() + format!("{{\"count\":{},\"total_bytes\":{}}}\n", self.entries, self.total).len()) as u64 + self.listing,
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
    /// The digest list's length at most (exact but for the modes' widths).
    listing_bytes: u64,
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
        let list = "{\"v\":1}\n{\"count\":0,\"total_bytes\":0}\n".len() as u64;
        assert_eq!(u, Usage { entries: 0, inodes: 0, blocks: dir_blocks(24), peak_inodes: 0, peak_blocks: 2 * dir_blocks(24), listing_bytes: list });
    }

    #[test]
    fn the_listing_bound_is_at_least_the_list_the_restore_writes() {
        // A real tree, listed by digests.rs, against the tally of the same names: at least, and only by the modes' widths.
        let d = std::env::temp_dir().join(format!("sb-usage-list-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("dir/sub")).unwrap();
        std::fs::write(d.join("a"), b"hello").unwrap();
        std::fs::write(d.join("dir/%x\u{1}"), b"").unwrap();
        std::os::unix::fs::symlink("../a\u{e9}", d.join("dir/l")).unwrap();
        std::fs::write(d.join(OsStr::from_bytes(b"\xff")), b"12").unwrap();
        let list = crate::digests::listing(&d).unwrap();
        let mut t = Tally::default();
        let meta = |size| Metadata { size, links: 1, ..Default::default() };
        t.add(Path::new("a"), &Node::new_node(OsStr::new("a"), NodeType::File, meta(5)));
        t.add(Path::new("dir"), &Node::new_node(OsStr::new("dir"), NodeType::Dir, meta(0)));
        t.add(Path::new("dir/sub"), &Node::new_node(OsStr::new("sub"), NodeType::Dir, meta(0)));
        t.add(Path::new("dir/%x\u{1}"), &Node::new_node(OsStr::new("%x\u{1}"), NodeType::File, meta(0)));
        t.add(Path::new("dir/l"), &Node::new_node(OsStr::new("l"), NodeType::from_link(Path::new("../a\u{e9}")), meta(0)));
        t.add(Path::new(OsStr::from_bytes(b"\xff")), &Node::new_node(OsStr::from_bytes(b"\xff"), NodeType::File, meta(2)));
        let u = t.finish();
        assert!(u.listing_bytes >= list.len() as u64, "{} < {}", u.listing_bytes, list.len());
        // Over only by the mode digits: at most one per line here (every real mode has 3 digits), 5 mode-bearing lines.
        assert!(u.listing_bytes - list.len() as u64 <= 6, "{} vs {}", u.listing_bytes, list.len());
        std::fs::remove_dir_all(&d).unwrap();
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

}
