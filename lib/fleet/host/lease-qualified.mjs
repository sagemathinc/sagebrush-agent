// The execution lease's qualification check (lease-on design r1.6 §2): `execution_lease: "on"` is usable only when the
// release carries a qualification record whose binding holds on this host, computed once at the daemon's start. There
// is no constant, environment variable or override. The record (schema/fleet/lease-qualification.json) is written by
// the VM run and committed after review; with none, every host is unqualified and "on" refuses lease_unqualified.
//
// It binds three things, each checked here:
// - the source (§2.1): the manifest regenerated from the release tree has the record's exact member set, each member
//   with the record's sha256 (never a subset the record declares about itself);
// - the executed bytes (§2.2, §2.5): the launcher at <release>/bin/sagebrush-agent-launch, root's, 0755, its sha256 the
//   record's; <release>/bin/sagebrush-agent a link to exactly sagebrush-agent.mjs; the installed sleep hook root's,
//   0755, byte-equal to sleepHook(release) and its sha256 the record's;
// - the environment (§2.3): systemd's pinned major (the start's preflight already holds the host to it), Node's major,
//   the kernel's major.minor EQUAL to the run's (C5), cgroup v2 at /sys/fs/cgroup with the agents slice's kill, freeze
//   and events files, and /proc/uptime readable.
// And the record's subcases are exactly lease-qual-subcases.mjs's list, every one "pass" (§2.4).
// And the boundary (§2.6) is the installed one: the checker outside the release byte-equal to the release's, the unit
// file the rendered one, and systemd's EFFECTIVE unit exactly it (no drop-in, no reload pending, the exact command
// lines). That only confirms this start went through the boundary; the protection is release-install's sequence.
//
// The tree's trust is PROVEN, not assumed (§2.5, SEC H1): top-down, by lstat and never following a link, every
// component from / through the release root to every member, the launcher and the hook is root's, of its real type
// (a directory, or a regular file), with no group or other write; bin/sagebrush-agent is the one link. Each member is
// proven before it is read. A proven directory's entries can be changed only by root, and so can its children's
// attributes: by induction, no non-root principal can replace what was hashed before the later import, exec or read.
//
// The answer is { ok: true } or { ok: false, why }: `why` is a fixed token naming the failing item (no path or value),
// for the refusal's message. Nothing here throws: any failure to read or check is unqualified.

import * as fs from "node:fs";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { release as osRelease } from "node:os";
import { dirname, isAbsolute, normalize } from "node:path";
import { canonText, parseCanonical } from "../core/canonical.mjs";
import { QUALIFIED_MAJOR } from "./host-preflight.mjs";
import { sleepHook } from "./lease.mjs";
import { leaseManifest } from "./lease-manifest.mjs";
import { SUBCASES } from "./lease-qual-subcases.mjs";
import { AGENT_SLICE } from "./names.mjs";

/** The record, relative to the release. */
export const RECORD = "schema/fleet/lease-qualification.json";
/** Where systemd runs system-sleep hooks (§6). */
export const HOOK_PATH = "/usr/lib/systemd/system-sleep/sagebrush-lease";
/** The trust boundary's checker, installed outside the release, and the supervisor's unit file (§2.6). */
export const CHECKER_PATH = "/usr/lib/sagebrush/release-trust";
export const UNIT_NAME = "sagebrush-supervisor.service";
export const UNIT_PATH = `/etc/systemd/system/${UNIT_NAME}`;
const UNIT_PROPS = ["FragmentPath", "DropInPaths", "NeedDaemonReload", "ExecStartPre", "ExecStart"];
/** systemd's effective unit: { FragmentPath, DropInPaths, NeedDaemonReload, ExecStartPre, ExecStart } as `systemctl show` prints them. */
export function realUnitShow() {
  const out = execFileSync("/usr/bin/systemctl", ["show", UNIT_NAME, ...UNIT_PROPS.flatMap((p) => ["-p", p])], { encoding: "utf8", timeout: 10000 });
  const props = {};
  for (const line of out.split("\n")) { const i = line.indexOf("="); if (i > 0) props[line.slice(0, i)] = line.slice(i + 1); }
  return props;
}
/** One Exec property's single command line, or null when it doesn't hold exactly one. */
export function argvOf(value) {
  if (typeof value !== "string" || (value.match(/\{ path=/g) ?? []).length !== 1) return null;
  const m = /argv\[\]=([^;]*) ;/.exec(value);
  return m ? m[1] : null;
}
const unitTemplate = () => fs.readFileSync(new URL("./units/sagebrush-supervisor.service", import.meta.url), "utf8");
/** The record's size bound. */
export const RECORD_MAX = 1024 * 1024;

const HEX64 = /^[0-9a-f]{64}$/, HEX40 = /^[0-9a-f]{40}$/, SERIES = /^(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})$/;
const ISO = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,3})?Z$/;
const sha256 = (buf) => createHash("sha256").update(buf).digest("hex");
const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const exact = (v, keys) => isObj(v) && Object.keys(v).length === keys.length && keys.every((k) => Object.hasOwn(v, k));
const str = (v, max = 256) => typeof v === "string" && v.length >= 1 && v.length <= max;
const nat = (v) => Number.isSafeInteger(v) && v >= 1 && v <= 10000;
const seriesOf = (kernel) => { const m = /^([0-9]+)\.([0-9]+)(?![0-9])/.exec(String(kernel)); return m ? `${Number(m[1])}.${Number(m[2])}` : null; };

/** The record's closed shape (§2.4), or null. Its subcases must be exactly `subcases`, each "pass". */
export function checkRecord(r, { subcases = SUBCASES } = {}) {
  if (!exact(r, ["v", "release", "files", "artifacts", "env", "subcases", "evidence"]) || r.v !== 1) return null;
  if (!exact(r.release, ["commit", "manifest_sha256"]) || typeof r.release.commit !== "string" || !HEX40.test(r.release.commit)
    || typeof r.release.manifest_sha256 !== "string" || !HEX64.test(r.release.manifest_sha256)) return null;
  if (!isObj(r.files) || Object.keys(r.files).length === 0) return null;
  for (const [p, h] of Object.entries(r.files)) if (!str(p, 512) || typeof h !== "string" || !HEX64.test(h)) return null;
  if (!exact(r.artifacts, ["launcher", "sleep_hook"]) || !Object.values(r.artifacts).every((h) => typeof h === "string" && HEX64.test(h))) return null;
  const e = r.env;
  if (!exact(e, ["systemd_major", "node_major", "kernel_series", "kernel", "cgroup"]) || !nat(e.systemd_major) || !nat(e.node_major)
    || typeof e.kernel_series !== "string" || !SERIES.test(e.kernel_series) || !str(e.kernel) || seriesOf(e.kernel) !== e.kernel_series
    || e.cgroup !== "v2") return null;
  if (!exact(r.subcases, subcases) || !subcases.every((k) => r.subcases[k] === "pass")) return null;
  if (!exact(r.evidence, ["log_sha256", "vm", "run_at"]) || typeof r.evidence.log_sha256 !== "string" || !HEX64.test(r.evidence.log_sha256)
    || !str(r.evidence.vm) || typeof r.evidence.run_at !== "string" || !ISO.test(r.evidence.run_at)) return null;
  // the manifest digest names exactly the files and artifacts the record carries
  if (sha256(canonText({ files: r.files, artifacts: r.artifacts }, RECORD_MAX)) !== r.release.manifest_sha256) return null;
  return r;
}

class Untrusted extends Error {}

/**
 * The trust proof's walker (§2.5): `dir(abs)` proves every component of an absolute directory path, top-down, from /;
 * `file(abs, mode)` proves its parent chain, then the file (a regular file, root's, no group or other write, and mode
 * exactly `mode` when given) and returns its stat. Each throws Untrusted. Proven directories are cached for this
 * check only.
 */
export function trustWalker({ fsx = fs, rootUid = 0 } = {}) {
  const proven = new Set();
  const trusted = (st) => st.uid === rootUid && (st.mode & 0o022) === 0;
  const dir = (abs) => {
    if (!isAbsolute(abs) || normalize(abs) !== abs) throw new Untrusted();
    if (proven.has(abs)) return;
    const parent = dirname(abs);
    if (parent !== abs) dir(parent);
    let st;
    try { st = fsx.lstatSync(abs); } catch { throw new Untrusted(); }
    if (!st.isDirectory() || !trusted(st)) throw new Untrusted();
    proven.add(abs);
  };
  const file = (abs, mode) => {
    if (!isAbsolute(abs) || normalize(abs) !== abs) throw new Untrusted();
    dir(dirname(abs));
    let st;
    try { st = fsx.lstatSync(abs); } catch { throw new Untrusted(); }
    if (!st.isFile() || !trusted(st) || (mode !== undefined && (st.mode & 0o7777) !== mode)) throw new Untrusted();
    return st;
  };
  return { dir, file };
}

/** The kernel and cgroup preflight (§2.3): null, or the failing item. */
function envRefusal(rec, { fsx, kernel, nodeVersion, cgroupRoot }) {
  if (rec.env.systemd_major !== QUALIFIED_MAJOR) return "systemd_major";
  if (Number(String(nodeVersion).split(".")[0]) !== rec.env.node_major) return "node_major";
  if (seriesOf(kernel) !== rec.env.kernel_series) return "kernel_series";
  let mounts;
  try { mounts = fsx.readFileSync("/proc/self/mountinfo", "utf8"); } catch { return "cgroup"; }
  // mountinfo: "<id> <parent> <maj:min> <root> <mount point> <options> [optional...] - <fstype> <source> <super options>"
  const v2 = mounts.split("\n").some((l) => { const f = l.split(" "), dash = f.indexOf("-"); return f[4] === cgroupRoot && dash > 0 && f[dash + 1] === "cgroup2"; });
  if (!v2) return "cgroup";
  for (const f of ["cgroup.kill", "cgroup.freeze", "cgroup.events"]) {
    try { if (!fsx.statSync(`${cgroupRoot}/sagebrush.slice/${AGENT_SLICE}/${f}`).isFile()) return "cgroup"; } catch { return "cgroup"; }
  }
  try { fsx.readFileSync("/proc/uptime", "utf8"); } catch { return "uptime"; }
  return null;
}

/**
 * Is this release qualified for the lease on this host? `release`: the absolute release root (host-main's). Test seams:
 * { fsx, kernel (uname -r), nodeVersion, cgroupRoot, hookPath, rootUid, subcases, manifest }.
 */
export function leaseQualified(release, { fsx = fs, kernel = osRelease(), nodeVersion = process.versions.node, cgroupRoot = "/sys/fs/cgroup",
  hookPath = HOOK_PATH, rootUid = 0, subcases = SUBCASES, manifest = (root, prove) => leaseManifest(root, { fsx, prove }),
  checkerPath = CHECKER_PATH, unitPath = UNIT_PATH, unitShow = realUnitShow } = {}) {
  const no = (why) => ({ ok: false, why });
  const walk = trustWalker({ fsx, rootUid });
  const sha256Of = (abs) => sha256(fsx.readFileSync(abs));
  try {
    // the anchor: the release root and every component above it
    try { walk.dir(release); } catch (e) { if (e instanceof Untrusted) return no("layout"); throw e; }
    // the record (proven like a member before it is read)
    const recPath = `${release}/${RECORD}`;
    let recSt;
    try { recSt = walk.file(recPath); } catch (e) { if (e instanceof Untrusted) return no("record"); throw e; }
    if (recSt.size > RECORD_MAX) return no("record");
    const file = { bytes: fsx.readFileSync(recPath) };
    if (file.bytes.length > RECORD_MAX) return no("record");
    let rec;
    try { rec = checkRecord(parseCanonical(new Uint8Array(file.bytes), RECORD_MAX), { subcases }); } catch { rec = null; }
    if (rec === null) return no("record");
    // the source: the exact set, every hash
    // each member proven (its chain and itself) before the generator reads it
    let files, untrusted = false;
    const prove = (p) => { try { walk.file(`${release}/${p}`); } catch (e) { if (e instanceof Untrusted) untrusted = true; throw e; } };
    try { files = manifest(release, prove).files; } catch { return no(untrusted ? "layout" : "manifest"); }
    const want = Object.keys(rec.files), have = Object.keys(files);
    if (want.length !== have.length || !have.every((p) => Object.hasOwn(rec.files, p) && rec.files[p] === files[p])) return no("manifest");
    // the executed bytes
    const launcherPath = `${release}/bin/sagebrush-agent-launch`;
    try { walk.file(launcherPath, 0o755); } catch (e) { if (e instanceof Untrusted) return no("launcher"); throw e; }
    if (sha256Of(launcherPath) !== rec.artifacts.launcher) return no("launcher");
    // the one link: its exact target, its parent proven, its target a proven member
    const linkPath = `${release}/bin/sagebrush-agent`;
    let link;
    try { walk.dir(`${release}/bin`); link = fsx.lstatSync(linkPath).isSymbolicLink() ? fsx.readlinkSync(linkPath) : null; } catch { link = null; }
    if (link !== "sagebrush-agent.mjs" || !Object.hasOwn(files, "bin/sagebrush-agent.mjs")) return no("layout");
    try { walk.file(hookPath, 0o755); } catch (e) { if (e instanceof Untrusted) return no("sleep_hook"); throw e; }
    const hook = fsx.readFileSync(hookPath);
    if (hook.toString("utf8") !== sleepHook(release) || sha256(hook) !== rec.artifacts.sleep_hook) return no("sleep_hook");
    // the boundary (§2.6): the installed checker and unit, and what systemd will actually run
    try { walk.file(checkerPath, 0o755); } catch (e) { if (e instanceof Untrusted) return no("boundary"); throw e; }
    if (!fsx.readFileSync(checkerPath).equals(fsx.readFileSync(`${release}/scripts/release-trust.sh`))) return no("boundary");
    try { walk.file(unitPath); } catch (e) { if (e instanceof Untrusted) return no("boundary"); throw e; }
    if (fsx.readFileSync(unitPath, "utf8") !== unitTemplate().replaceAll("@RELEASE@", release)) return no("boundary");
    let u;
    try { u = unitShow(); } catch { return no("boundary"); }
    if (u?.FragmentPath !== unitPath || u.DropInPaths !== "" || u.NeedDaemonReload !== "no"
      || argvOf(u.ExecStartPre) !== `${checkerPath} ${release}` || argvOf(u.ExecStart) !== `/usr/bin/node ${release}/bin/sagebrush-agent.mjs host run`) return no("boundary");
    // the environment
    const env = envRefusal(rec, { fsx, kernel, nodeVersion, cgroupRoot });
    if (env !== null) return no(env);
    return { ok: true };
  } catch {
    return no("unreadable");
  }
}
