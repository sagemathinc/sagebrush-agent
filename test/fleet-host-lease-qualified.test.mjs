// The execution lease's qualification (lease-on design r1.7 §2, §7): the generated manifest, the record, the executed
// bytes, the release tree's trust proof (SEC H1) and the environment. Every row runs over a real temporary release
// built from this tree's own members, with the test's own uid as "root" (the rootUid seam) and the components above
// the temporary release, the cgroup files and mountinfo supplied by an fs seam.

import assert from "node:assert/strict";
import * as fs from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "./host-linux-only.mjs";
import { canonText } from "../lib/fleet/core/canonical.mjs";
import { QUALIFIED_MAJOR } from "../lib/fleet/host/host-preflight.mjs";
import { sleepHook } from "../lib/fleet/host/lease.mjs";
import { DECLARED, EXPLICIT, ROOTS, leaseManifest, lex, loadsOf } from "../lib/fleet/host/lease-manifest.mjs";
import { RECORD, argvOf, leaseQualified } from "../lib/fleet/host/lease-qualified.mjs";
import { SUBCASES } from "../lib/fleet/host/lease-qual-subcases.mjs";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const UID = process.getuid?.() ?? 0;
const sha = (b) => createHash("sha256").update(b).digest("hex");
const tmp = (p) => fs.mkdtempSync(join(tmpdir(), `sb-qual-${p}-`));
const CG = "/cg";
const MOUNTINFO = "24 1 0:22 / / rw - ext4 /dev/root rw\n30 24 0:26 / /cg rw,nosuid - cgroup2 cgroup2 rw\n";
const KERNEL = "6.8.0-45-generic";
const trustedDir = Object.freeze({ isDirectory: () => true, isFile: () => false, isSymbolicLink: () => false, uid: UID, mode: 0o40755 });

/** Is `p` a strict ancestor of `top`? */
const above = (p, top) => p !== top && (p === "/" ? top.startsWith("/") : top.startsWith(`${p}/`));

/**
 * A qualified release: every manifest member of this tree copied in, a launcher, the dispatcher link, the hook (in its
 * own directory), and a record over all of it. `w.over.lstat(p)` may answer lstat for a path (a seam for owners);
 * `w.over.mounts` and `w.over.cg` replace mountinfo and the cgroup files.
 */
function release() {
  const top = tmp("rel"), rel = join(top, "release"), hookDir = join(top, "hook");
  const members = Object.keys(leaseManifest(REPO).files);
  for (const m of members) {
    fs.mkdirSync(dirname(join(rel, m)), { recursive: true, mode: 0o755 });
    fs.copyFileSync(join(REPO, m), join(rel, m));
    fs.chmodSync(join(rel, m), 0o644);
  }
  fs.writeFileSync(join(rel, "bin/sagebrush-agent-launch"), "launcher bytes\n", { mode: 0o755 });
  fs.chmodSync(join(rel, "bin/sagebrush-agent-launch"), 0o755);
  fs.symlinkSync("sagebrush-agent.mjs", join(rel, "bin/sagebrush-agent"));
  fs.mkdirSync(hookDir, { mode: 0o755 });
  // the boundary (§2.6): the checker outside the release, the unit file, and systemd's effective unit (a seam)
  const checker = join(hookDir, "release-trust"), unit = join(hookDir, "sagebrush-supervisor.service");
  fs.copyFileSync(join(rel, "scripts/release-trust.sh"), checker);
  fs.chmodSync(checker, 0o755);
  fs.writeFileSync(unit, fs.readFileSync(join(REPO, "lib/fleet/host/units/sagebrush-supervisor.service"), "utf8").replaceAll("@RELEASE@", rel));
  fs.chmodSync(unit, 0o644);
  const exec = (argv) => `{ path=${argv.split(" ")[0]} ; argv[]=${argv} ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }`;
  const hook = join(hookDir, "sagebrush-lease");
  fs.writeFileSync(hook, sleepHook(rel));
  fs.chmodSync(hook, 0o755);
  // every directory 0755 (mkdtemp makes 0700, which is fine for trust but normalize it)
  for (const d of [top, rel, hookDir]) fs.chmodSync(d, 0o755);
  const w = { top, rel, hook, checker, unit, members, over: {} };
  w.show = { FragmentPath: unit, DropInPaths: "", NeedDaemonReload: "no", ExecStartPre: exec(`${checker} ${rel}`),
    ExecStart: exec(`/usr/bin/node ${rel}/bin/sagebrush-agent.mjs host run`) };
  w.fsx = {
    ...fs,
    lstatSync: (p, ...a) => {
      const o = w.over.lstat?.(p);
      if (o) return o;
      if (above(p, top) || p === dirname(top)) return trustedDir;
      return fs.lstatSync(p, ...a);
    },
    readFileSync: (p, ...a) => (p === "/proc/self/mountinfo" ? (w.over.mounts ?? MOUNTINFO) : fs.readFileSync(p, ...a)),
    statSync: (p, ...a) => {
      if (String(p).startsWith(`${CG}/`)) {
        if (w.over.cg && !w.over.cg(p)) throw Object.assign(new Error("ENOENT"), { code: "ENOENT" });
        return { isFile: () => true };
      }
      return fs.statSync(p, ...a);
    },
  };
  w.record = (edit = (r) => r) => {
    const files = leaseManifest(rel, { fsx: w.fsx }).files;
    const artifacts = { launcher: sha(fs.readFileSync(join(rel, "bin/sagebrush-agent-launch"))), sleep_hook: sha(fs.readFileSync(hook)) };
    let r = { v: 1, release: { commit: "a".repeat(40), manifest_sha256: sha(canonText({ files, artifacts }, 1 << 20)) }, files, artifacts,
      env: { systemd_major: QUALIFIED_MAJOR, node_major: Number(process.versions.node.split(".")[0]), kernel_series: "6.8", kernel: KERNEL, cgroup: "v2" },
      subcases: Object.fromEntries(SUBCASES.map((k) => [k, "pass"])),
      evidence: { log_sha256: "b".repeat(64), vm: "e2-standard-4 ubuntu-2404-noble us-west1-b", run_at: "2026-11-25T12:00:00Z" } };
    r = edit(r);
    return r;
  };
  w.write = (r, { rehash = true } = {}) => {
    if (rehash && r?.files && r?.artifacts && r?.release) r.release.manifest_sha256 = sha(canonText({ files: r.files, artifacts: r.artifacts }, 1 << 20));
    const text = typeof r === "string" ? r : canonText(r, 1 << 20);
    fs.writeFileSync(join(rel, RECORD), text);
    fs.chmodSync(join(rel, RECORD), 0o644);
  };
  w.q = (o = {}) => leaseQualified(rel, { fsx: w.fsx, kernel: "6.8.12-3-generic", nodeVersion: process.versions.node, cgroupRoot: CG, hookPath: hook, rootUid: UID,
    checkerPath: checker, unitPath: unit, unitShow: () => ({ ...w.show }), ...o });
  w.write(w.record());
  w.done = () => fs.rmSync(top, { recursive: true, force: true });
  return w;
}

/** Run `fn` with `path` temporarily changed by `change`, restored by `restore`. */
function around(change, restore, fn) { change(); try { return fn(); } finally { restore(); } }

// ---- the generator (§2.1) ----------------------------------------------------------------------------------------

test("the generator: deterministic, and on this tree its member set equals the checked-in expected list", () => {
  const a = leaseManifest(REPO), b = leaseManifest(REPO);
  assert.equal(JSON.stringify(a), JSON.stringify(b));
  const expected = JSON.parse(fs.readFileSync(join(REPO, "test/fixtures/host/lease-manifest-members.json"), "utf8"));
  assert.deepEqual(Object.keys(a.files), expected);
  for (const r of ROOTS) assert.ok(Object.hasOwn(a.files, r), r);
  assert.ok(!Object.hasOwn(a.files, "bin/sagebrush-agent-chat.mjs"), "the chat branch isn't followed");
  assert.ok(Object.keys(a.files).every((p) => !p.startsWith("test/")), "A2's machinery joins with A2");
});

/** The repo scripts a build recipe names (`$root/scripts/<f>` or a bare `scripts/<f>`): each is part of the recipe. */
const scriptsNamedBy = (src) => [...new Set([...src.matchAll(/(?:\$\{?root\}?\/|(?<![\w./-]))scripts\/([A-Za-z0-9._-]+)/g)].map((m) => `scripts/${m[1]}`))].sort();
/** Every scripts/*-build.sh is an explicit member, and so is every script it names; returns the missing ones. */
function buildRecipeGaps(explicit, files) {
  const gaps = [];
  for (const [path, src] of files) {
    if (!explicit.includes(path)) gaps.push(`${path} (a build recipe)`);
    for (const s of scriptsNamedBy(src)) if (!explicit.includes(s)) gaps.push(`${s} (named by ${path})`);
  }
  return gaps;
}

test("the generator: every build recipe (scripts/*-build.sh) and every script it runs are explicit members", () => {
  const builds = fs.readdirSync(join(REPO, "scripts")).filter((f) => f.endsWith("-build.sh")).sort().map((f) => `scripts/${f}`);
  assert.ok(builds.includes("scripts/launcher-build.sh"), "the launcher's recipe is found by the scan");
  const files = builds.map((p) => [p, fs.readFileSync(join(REPO, p), "utf8")]);
  assert.ok(scriptsNamedBy(files.find(([p]) => p === "scripts/launcher-build.sh")[1]).includes("scripts/backup-static-check.sh"), "the scan sees the static check");
  assert.deepEqual(buildRecipeGaps(EXPLICIT, files), []);
  // Controls: the static check dropped from EXPLICIT, a recipe naming an unlisted script, and an unlisted recipe.
  assert.deepEqual(buildRecipeGaps(EXPLICIT.filter((p) => p !== "scripts/backup-static-check.sh"), files),
    files.filter(([, s]) => s.includes("scripts/backup-static-check.sh")).map(([p]) => `scripts/backup-static-check.sh (named by ${p})`));
  assert.deepEqual(buildRecipeGaps(EXPLICIT, [["scripts/launcher-build.sh", 'bash "$root/scripts/other-check.sh" x\n']]), ["scripts/other-check.sh (named by scripts/launcher-build.sh)"]);
  assert.deepEqual(buildRecipeGaps(EXPLICIT, [["scripts/new-build.sh", "true\n"]]), ["scripts/new-build.sh (a build recipe)"]);
});

test("the generator: each of the ten declarations matches exactly one flagged line of this tree", () => {
  assert.equal(DECLARED.length, 10);
  for (const d of DECLARED) {
    const lines = fs.readFileSync(join(REPO, d.file), "utf8").split("\n").map((l) => l.trim());
    assert.equal(lines.filter((l) => l === d.line).length, 1, `${d.file}: ${d.line}`);
  }
});

/** A fixture tree: { "<path>": "<source>" }; generated from root a.mjs with the given declarations. */
function gen(files, { declared = [], explicit = [], links = {} } = {}) {
  const root = tmp("gen");
  try {
    for (const [p, src] of Object.entries(files)) { fs.mkdirSync(dirname(join(root, p)), { recursive: true }); fs.writeFileSync(join(root, p), src); }
    for (const [p, to] of Object.entries(links)) fs.symlinkSync(to, join(root, p));
    return Object.keys(leaseManifest(root, { roots: ["a.mjs"], declared, explicit, explicitDirs: [] }).files);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
}
const genFails = (files, opts, why) => assert.throws(() => gen(files, opts), (e) => e.code === "bad_form" && /lease manifest/.test(e.message), why);

test("the generator follows relative static imports, export-from, literal import() and literal new URL(…, import.meta.url)", () => {
  assert.deepEqual(gen({
    "a.mjs": 'import { x } from "./b.mjs";\nexport * from "./c.mjs";\nimport "./d.mjs";\nconst e = await import("./e.mjs");\nconst t = await import(`./t.mjs`);\nconst u = new URL("./data.json", import.meta.url);\nimport fs from "node:fs";\n',
    "b.mjs": "export const x = 1;\n", "c.mjs": 'export { y } from "./sub/y.mjs";\n', "sub/y.mjs": "export const y = 2;\n", "d.mjs": "", "e.mjs": "", "t.mjs": "", "data.json": "{}",
  }), ["a.mjs", "b.mjs", "c.mjs", "d.mjs", "data.json", "e.mjs", "sub/y.mjs", "t.mjs"]);
});

test("the generator REFUSES every undeclared way to name a release file, and anything it can't follow", () => {
  const cases = {
    "import.meta.url": "const u = import.meta.url;\n",
    "import.meta.dirname": "const d = import.meta.dirname;\n",
    "import.meta.filename": "const f = import.meta.filename;\n",
    "import.meta alone": "const m = import.meta;\n",
    "process.argv[1]": "const p = process.argv[1];\n",
    createRequire: 'import { createRequire } from "node:module";\nconst r = createRequire(x);\n',
    require: 'const m = require("./b.cjs");\n',
    "require.resolve": 'const p = require.resolve("./b.cjs");\n',
    __dirname: "const d = __dirname;\n",
    __filename: "const f = __filename;\n",
    "a non-literal import()": 'const m = await import("./" + name);\n',
    "a template import() with a substitution": "const m = await import(`./${name}.mjs`);\n",
    "a non-literal new URL": "const u = new URL(name, import.meta.url);\n",
    "a bare import": 'import x from "left-pad";\n',
    "a bare dynamic import": 'const x = await import("left-pad");\n',
    "a target outside the tree": 'import x from "../outside.mjs";\n',
    "a missing target": 'import x from "./missing.mjs";\n',
    "an unterminated string": 'const s = "abc;\n',
    "an unterminated template": "const s = `abc;\n",
    "an unterminated comment": "/* abc\n",
    "an unterminated regular expression": "const r = /abc;\n",
    "an unbalanced brace": "function f() {\n",
  };
  for (const [why, src] of Object.entries(cases)) genFails({ "a.mjs": src }, {}, why);
  // a member that is a link, even to identical bytes
  genFails({ "a.mjs": 'import "./b.mjs";\n', "real.mjs": "" }, { links: { "b.mjs": "real.mjs" } }, "a linked member");
});

test("declarations: exact line, exactly once; an edited line or an unused declaration refuses", () => {
  const line = "const u = import.meta.url;";
  assert.deepEqual(gen({ "a.mjs": `${line}\n` }, { declared: [{ file: "a.mjs", line, targets: [] }] }), ["a.mjs"]);
  assert.deepEqual(gen({ "a.mjs": `${line}\n`, "r.json": "{}" }, { declared: [{ file: "a.mjs", line, targets: ["r.json"] }] }), ["a.mjs", "r.json"]);
  genFails({ "a.mjs": "const u  = import.meta.url;\n" }, { declared: [{ file: "a.mjs", line, targets: [] }] }, "one character edited");
  genFails({ "a.mjs": "" }, { declared: [{ file: "a.mjs", line, targets: [] }] }, "unused");
  genFails({ "a.mjs": `${line}\n` }, { declared: [{ file: "a.mjs", line, targets: ["missing.json"] }] }, "a missing declared target");
});

test("the lexer: a division isn't a regular expression; import inside a string, comment, template or regex isn't a load; ${} nests", () => {
  assert.deepEqual(gen({
    "a.mjs": [
      "const a = 4 / 2 / 1;",
      "const r = /import(\"x\")|\\/[a]/g;",
      "const s = 'import(\"./no.mjs\")';",
      "// import(\"./no.mjs\")",
      "/* import \"./no.mjs\" */",
      "const t = `import(\"./no.mjs\") ${ `${ { a: 1 }.a }` } done`;",
      "const q = (x) / 2; const z = [1] / 1;",
      "if (a) /x/.test(s);",
      'import "./b.mjs";',
    ].join("\n"),
    "b.mjs": "",
  }), ["a.mjs", "b.mjs"]);
  assert.equal(lex("x = a / b").filter((t) => t.t === "re").length, 0);
  assert.equal(lex("x = (a) / b / c").filter((t) => t.t === "re").length, 0);
  assert.equal(lex("return /a/").filter((t) => t.t === "re").length, 1);
});

test("leaseQualified's own module graph imports no test module and not node:test", () => {
  const seen = new Set(), queue = ["lib/fleet/host/lease-qualified.mjs"];
  const specs = [];
  while (queue.length) {
    const f = queue.shift();
    if (seen.has(f)) continue;
    seen.add(f);
    for (const l of loadsOf(fs.readFileSync(join(REPO, f), "utf8")).follow) {
      specs.push(l.spec);
      if (l.spec.startsWith(".") && /\.mjs$/.test(l.spec)) queue.push(join(dirname(f), l.spec).split("\\").join("/"));
    }
  }
  assert.ok(seen.size > 10, "the whole graph was walked");
  assert.ok(!specs.includes("node:test"));
  assert.ok([...seen].every((f) => !f.startsWith("test/")), [...seen].filter((f) => f.startsWith("test/")).join(" "));
});

// ---- leaseQualified (§2.2–§2.5) ----------------------------------------------------------------------------------

test("a qualified release over this tree's members: qualified (the positive control every row below changes one thing of)", () => {
  const w = release();
  try { assert.deepEqual(w.q(), { ok: true }); } finally { w.done(); }
});

test("EVERY member: one byte changed, or the file removed: unqualified (manifest)", () => {
  const w = release();
  try {
    assert.ok(w.members.length > 90);
    for (const m of w.members) {
      const p = join(w.rel, m), bytes = fs.readFileSync(p);
      const changed = Buffer.from(bytes); changed[changed.length - 1] ^= 0x01;
      around(() => fs.writeFileSync(p, changed), () => fs.writeFileSync(p, bytes), () => assert.equal(w.q().ok, false, `changed ${m}`));
      around(() => fs.renameSync(p, `${p}.away`), () => fs.renameSync(`${p}.away`, p), () => assert.deepEqual(w.q(), { ok: false, why: "manifest" }, `removed ${m}`));
    }
    assert.deepEqual(w.q(), { ok: true });
  } finally { w.done(); }
});

test("the record's member set: one dropped, one extra: unqualified; a new relative import or a non-literal import() in a root: unqualified", () => {
  const w = release();
  try {
    for (const m of [w.members[0], w.members.at(-1), "lib/fleet/host/lease.mjs"]) {
      w.write(w.record((r) => { delete r.files[m]; return r; }));
      assert.deepEqual(w.q(), { ok: false, why: "manifest" }, `dropped ${m}`);
    }
    w.write(w.record((r) => { r.files["lib/fleet/host/extra.mjs"] = "c".repeat(64); return r; }));
    assert.deepEqual(w.q(), { ok: false, why: "manifest" });
    w.write(w.record());
    const root = join(w.rel, "lib/fleet/host/lease-main.mjs"), src = fs.readFileSync(root, "utf8");
    fs.writeFileSync(join(w.rel, "lib/fleet/host/grown.mjs"), "export const g = 1;\n");
    around(() => fs.writeFileSync(root, `import "./grown.mjs";\n${src}`), () => fs.writeFileSync(root, src), () => assert.deepEqual(w.q(), { ok: false, why: "manifest" }));
    around(() => fs.writeFileSync(root, `${src}\nawait import(globalThis.x);\n`), () => fs.writeFileSync(root, src), () => assert.deepEqual(w.q(), { ok: false, why: "manifest" }));
    assert.deepEqual(w.q(), { ok: true });
  } finally { w.done(); }
});

test("the launcher: another digest, missing, another mode, group- or other-writable, another owner: unqualified (launcher)", () => {
  const w = release();
  try {
    const p = join(w.rel, "bin/sagebrush-agent-launch"), bytes = fs.readFileSync(p);
    around(() => fs.writeFileSync(p, "launcher bytez\n"), () => fs.writeFileSync(p, bytes), () => assert.deepEqual(w.q(), { ok: false, why: "launcher" }));
    around(() => fs.renameSync(p, `${p}.x`), () => fs.renameSync(`${p}.x`, p), () => assert.deepEqual(w.q(), { ok: false, why: "launcher" }));
    for (const mode of [0o700, 0o775, 0o757, 0o4755]) {
      around(() => fs.chmodSync(p, mode), () => fs.chmodSync(p, 0o755), () => assert.deepEqual(w.q(), { ok: false, why: "launcher" }, mode.toString(8)));
    }
    w.over.lstat = (q) => (q === p ? { ...fs.lstatSync(q), isFile: () => true, isDirectory: () => false, isSymbolicLink: () => false, uid: UID + 1 } : null);
    assert.deepEqual(w.q(), { ok: false, why: "launcher" });
    w.over = {};
    assert.deepEqual(w.q(), { ok: true });
  } finally { w.done(); }
});

test("the dispatcher link: missing, a regular file, linked elsewhere, linked absolutely: unqualified (layout)", () => {
  const w = release();
  try {
    const p = join(w.rel, "bin/sagebrush-agent");
    const relink = (to) => { fs.rmSync(p, { force: true }); if (to !== null) fs.symlinkSync(to, p); };
    for (const [why, change] of [
      ["missing", () => relink(null)], ["regular", () => { relink(null); fs.writeFileSync(p, "x"); }],
      ["elsewhere", () => relink("sagebrush-agent-chat.mjs")], ["absolute", () => relink(join(w.rel, "bin/sagebrush-agent.mjs"))],
      ["dotted", () => relink("./sagebrush-agent.mjs")],
    ]) {
      around(change, () => relink("sagebrush-agent.mjs"), () => assert.deepEqual(w.q(), { ok: false, why: "layout" }, why));
    }
    assert.deepEqual(w.q(), { ok: true });
  } finally { w.done(); }
});

test("the hook: missing, other bytes, another mode, another owner, its directory writable: unqualified (sleep_hook)", () => {
  const w = release();
  try {
    const bytes = fs.readFileSync(w.hook);
    around(() => fs.writeFileSync(w.hook, sleepHook("/opt/other")), () => fs.writeFileSync(w.hook, bytes), () => assert.deepEqual(w.q(), { ok: false, why: "sleep_hook" }));
    around(() => fs.renameSync(w.hook, `${w.hook}.x`), () => fs.renameSync(`${w.hook}.x`, w.hook), () => assert.deepEqual(w.q(), { ok: false, why: "sleep_hook" }));
    for (const mode of [0o644, 0o775, 0o757]) around(() => fs.chmodSync(w.hook, mode), () => fs.chmodSync(w.hook, 0o755), () => assert.deepEqual(w.q(), { ok: false, why: "sleep_hook" }));
    around(() => fs.chmodSync(dirname(w.hook), 0o775), () => fs.chmodSync(dirname(w.hook), 0o755), () => assert.deepEqual(w.q(), { ok: false, why: "sleep_hook" }));
    w.over.lstat = (q) => (q === w.hook ? { ...fs.lstatSync(q), isFile: () => true, isDirectory: () => false, isSymbolicLink: () => false, uid: UID + 1 } : null);
    assert.deepEqual(w.q(), { ok: false, why: "sleep_hook" });
    w.over = {};
    // a hook that's a link to identical bytes
    around(() => { fs.renameSync(w.hook, `${w.hook}.real`); fs.symlinkSync(`${w.hook}.real`, w.hook); }, () => { fs.rmSync(w.hook); fs.renameSync(`${w.hook}.real`, w.hook); },
      () => assert.deepEqual(w.q(), { ok: false, why: "sleep_hook" }));
    assert.deepEqual(w.q(), { ok: true });
  } finally { w.done(); }
});

// ---- the tree's trust (§2.5, SEC H1) -----------------------------------------------------------------------------

const foreign = (path) => (q) => (q === path ? { ...fs.lstatSync(q), isFile: () => fs.lstatSync(q).isFile(), isDirectory: () => fs.lstatSync(q).isDirectory(), isSymbolicLink: () => false, uid: UID + 1 } : null);

test("EVERY member: group-writable, other-writable, another owner, or a link to identical bytes: unqualified (layout)", () => {
  const w = release();
  try {
    for (const m of w.members) {
      const p = join(w.rel, m);
      for (const mode of [0o664, 0o646]) around(() => fs.chmodSync(p, mode), () => fs.chmodSync(p, 0o644), () => assert.deepEqual(w.q(), { ok: false, why: "layout" }, `${m} ${mode.toString(8)}`));
      w.over.lstat = foreign(p);
      assert.deepEqual(w.q(), { ok: false, why: "layout" }, `${m} foreign`);
      w.over = {};
      around(() => { fs.renameSync(p, `${p}.real`); fs.symlinkSync(`${p}.real`, p); }, () => { fs.rmSync(p); fs.renameSync(`${p}.real`, p); },
        () => assert.deepEqual(w.q(), { ok: false, why: "layout" }, `${m} linked`));
    }
    assert.deepEqual(w.q(), { ok: true });
  } finally { w.done(); }
});

test("EVERY member directory, and the release root: group- or other-writable, another owner, or a link to an identical directory: unqualified (layout)", () => {
  const w = release();
  try {
    const dirs = [...new Set(w.members.flatMap((m) => { const out = []; for (let d = dirname(m); d !== "."; d = dirname(d)) out.push(d); return out; }))].sort();
    assert.ok(dirs.includes("lib/fleet/host") && dirs.includes("launcher/src") && dirs.includes("schema/fleet"));
    for (const d of ["", ...dirs]) {
      const p = d === "" ? w.rel : join(w.rel, d);
      for (const mode of [0o775, 0o757, 0o1777]) around(() => fs.chmodSync(p, mode), () => fs.chmodSync(p, 0o755), () => assert.equal(w.q().ok, false, `${d} ${mode.toString(8)}`));
      w.over.lstat = foreign(p);
      assert.equal(w.q().ok, false, `${d} foreign`);
      w.over = {};
      if (d !== "") {
        around(() => { fs.renameSync(p, `${p}.real`); fs.symlinkSync(`${p}.real`, p); }, () => { fs.rmSync(p); fs.renameSync(`${p}.real`, p); },
          () => assert.equal(w.q().ok, false, `${d} linked`));
      }
    }
    assert.deepEqual(w.q(), { ok: true });
  } finally { w.done(); }
});

test("a component ABOVE the release root: writable, another owner, or a link: unqualified (layout)", () => {
  const w = release();
  try {
    for (const p of ["/", dirname(w.top), w.top]) {
      for (const [why, st] of [
        ["group-writable", { ...trustedDir, mode: 0o40775 }], ["other-writable sticky", { ...trustedDir, mode: 0o41777 }],
        ["foreign", { ...trustedDir, uid: UID + 1 }], ["a link", { ...trustedDir, isDirectory: () => false, isSymbolicLink: () => true }],
      ]) {
        w.over.lstat = (q) => (q === p ? st : null);
        assert.deepEqual(w.q(), { ok: false, why: "layout" }, `${p} ${why}`);
      }
    }
    w.over = {};
    assert.deepEqual(w.q(), { ok: true });
  } finally { w.done(); }
});

test("after qualification, a writable parent refuses before anything is hashed, whether or not the bytes were changed (SEC H1 controls)", () => {
  const w = release();
  try {
    assert.deepEqual(w.q(), { ok: true });
    const dir = join(w.rel, "lib/fleet/host"), member = join(dir, "lease.mjs"), bytes = fs.readFileSync(member);
    // (a) a writable parent, and the member under it replaced through it
    let hashedAfter = false;
    const realRead = w.fsx.readFileSync;
    w.fsx.readFileSync = (p, ...a) => { if (p === member) hashedAfter = true; return realRead(p, ...a); };
    around(() => { fs.chmodSync(dir, 0o777); fs.writeFileSync(member, `${bytes}\n// replaced\n`); }, () => { fs.writeFileSync(member, bytes); fs.chmodSync(dir, 0o755); }, () => {
      assert.deepEqual(w.q(), { ok: false, why: "layout" });
      assert.equal(hashedAfter, false, "the replaced member was never read");
    });
    // (b) the parent writable, the bytes untouched: still refused (the proof is who CAN write)
    around(() => fs.chmodSync(dir, 0o775), () => fs.chmodSync(dir, 0o755), () => assert.deepEqual(w.q(), { ok: false, why: "layout" }));
    w.fsx.readFileSync = realRead;
    assert.deepEqual(w.q(), { ok: true });
  } finally { w.done(); }
});

// ---- the boundary (§2.6): the installed checker and unit, and systemd's effective unit -----------------------------

test("the boundary: the checker missing, other bytes, another mode or owner; the unit file other bytes; each effective-unit fact off: unqualified (boundary)", () => {
  const w = release();
  try {
    assert.deepEqual(w.q(), { ok: true });
    const bytes = fs.readFileSync(w.checker), unitText = fs.readFileSync(w.unit);
    around(() => fs.rmSync(w.checker), () => { fs.writeFileSync(w.checker, bytes); fs.chmodSync(w.checker, 0o755); }, () => assert.deepEqual(w.q(), { ok: false, why: "boundary" }, "missing"));
    around(() => fs.appendFileSync(w.checker, "#\n"), () => fs.writeFileSync(w.checker, bytes), () => assert.deepEqual(w.q(), { ok: false, why: "boundary" }, "other bytes"));
    for (const mode of [0o644, 0o775, 0o757]) around(() => fs.chmodSync(w.checker, mode), () => fs.chmodSync(w.checker, 0o755), () => assert.deepEqual(w.q(), { ok: false, why: "boundary" }, mode.toString(8)));
    w.over.lstat = foreign(w.checker);
    assert.deepEqual(w.q(), { ok: false, why: "boundary" }, "foreign checker");
    w.over = {};
    const noPre = String(unitText).replace(/^ExecStartPre=.*\n/m, "");
    around(() => fs.writeFileSync(w.unit, noPre), () => fs.writeFileSync(w.unit, unitText), () => assert.deepEqual(w.q(), { ok: false, why: "boundary" }, "a unit file without ExecStartPre"));
    around(() => fs.chmodSync(w.unit, 0o664), () => fs.chmodSync(w.unit, 0o644), () => assert.deepEqual(w.q(), { ok: false, why: "boundary" }, "a writable unit file"));
    const good = { ...w.show };
    for (const [why, change] of [
      ["another fragment", { FragmentPath: "/etc/systemd/system.control/sagebrush-supervisor.service" }],
      ["a drop-in", { DropInPaths: "/run/systemd/system/sagebrush-supervisor.service.d/override.conf" }],
      ["a reload pending", { NeedDaemonReload: "yes" }],
      ["no ExecStartPre", { ExecStartPre: "" }],
      ["two ExecStartPre", { ExecStartPre: `${good.ExecStartPre} ${good.ExecStartPre}` }],
      ["another checker", { ExecStartPre: good.ExecStartPre.replaceAll(w.checker, "/usr/lib/sagebrush/other") }],
      ["the checker for another release", { ExecStartPre: good.ExecStartPre.replaceAll(` ${w.rel} `, ` ${w.rel}x `) }],
      ["an extra argument", { ExecStartPre: good.ExecStartPre.replace(` ${w.rel} ;`, ` ${w.rel} x ;`) }],
      ["ExecStart through env", { ExecStart: good.ExecStart.replaceAll("/usr/bin/node", "/usr/bin/env node") }],
      ["ExecStart another release", { ExecStart: good.ExecStart.replaceAll(w.rel, "/opt/other") }],
    ]) {
      w.show = { ...good, ...change };
      assert.deepEqual(w.q(), { ok: false, why: "boundary" }, why);
    }
    w.show = good;
    assert.deepEqual(w.q({ unitShow: () => { throw new Error("systemctl failed"); } }), { ok: false, why: "boundary" }, "show failing");
    assert.deepEqual(w.q(), { ok: true });
  } finally { w.done(); }
});

test("argvOf: exactly one command line, else null", () => {
  const one = "{ path=/usr/bin/node ; argv[]=/usr/bin/node /r/bin/sagebrush-agent.mjs host run ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }";
  assert.equal(argvOf(one), "/usr/bin/node /r/bin/sagebrush-agent.mjs host run");
  assert.equal(argvOf(`${one} ${one}`), null);
  assert.equal(argvOf(""), null);
  assert.equal(argvOf(undefined), null);
});

// ---- the record (§2.4) -------------------------------------------------------------------------------------------

test("the record, malformed: absent, not JSON, not canonical (a duplicate key), each level's keys, v, hex, digest: unqualified (record)", () => {
  const w = release();
  try {
    const recPath = join(w.rel, RECORD);
    const good = w.record();
    const text = canonText(good, 1 << 20);
    const bad = (why, value, opts) => { w.write(value, opts); assert.deepEqual(w.q(), { ok: false, why: "record" }, why); };
    around(() => fs.renameSync(recPath, `${recPath}.x`), () => fs.renameSync(`${recPath}.x`, recPath), () => assert.deepEqual(w.q(), { ok: false, why: "record" }, "absent"));
    bad("not JSON", "{");
    bad("not canonical (spaces)", JSON.stringify(good, null, 1));
    bad("a duplicate key", text.replace('{"artifacts":', '{"v":1,"artifacts":'));
    const clone = () => JSON.parse(text);
    for (const k of Object.keys(good)) {
      bad(`missing ${k}`, (() => { const r = clone(); delete r[k]; return r; })(), { rehash: false });
      for (const sub of ["release", "artifacts", "env", "evidence"]) {
        if (k !== sub) continue;
        for (const kk of Object.keys(good[sub])) bad(`missing ${sub}.${kk}`, (() => { const r = clone(); delete r[sub][kk]; return r; })(), { rehash: sub !== "release" && sub !== "artifacts" });
        bad(`unknown ${sub} key`, (() => { const r = clone(); r[sub].x = 1; return r; })(), { rehash: false });
      }
    }
    bad("an unknown top key", (() => { const r = clone(); r.x = 1; return r; })());
    bad("v 2", (() => { const r = clone(); r.v = 2; return r; })());
    bad("a bad commit", (() => { const r = clone(); r.release.commit = "A".repeat(40); return r; })());
    bad("a bad file hash", (() => { const r = clone(); r.files[w.members[0]] = "g".repeat(64); return r; })());
    bad("a bad launcher hash", (() => { const r = clone(); r.artifacts.launcher = "0".repeat(63); return r; })());
    bad("manifest_sha256 not the files and artifacts", (() => { const r = clone(); r.release.manifest_sha256 = "0".repeat(64); return r; })(), { rehash: false });
    bad("a kernel_series that isn't the kernel's", (() => { const r = clone(); r.env.kernel_series = "6.9"; return r; })());
    bad("cgroup v1", (() => { const r = clone(); r.env.cgroup = "v1"; return r; })());
    bad("a bad run_at", (() => { const r = clone(); r.evidence.run_at = "yesterday"; return r; })());
    w.write(good);
    assert.deepEqual(w.q(), { ok: true });
  } finally { w.done(); }
});

test("EVERY expected subcase: missing, or not \"pass\"; an extra subcase: unqualified (record)", () => {
  const w = release();
  try {
    assert.equal(new Set(SUBCASES).size, SUBCASES.length);
    for (const k of SUBCASES) {
      w.write(w.record((r) => { delete r.subcases[k]; return r; }));
      assert.deepEqual(w.q(), { ok: false, why: "record" }, `missing ${k}`);
      w.write(w.record((r) => { r.subcases[k] = "fail"; return r; }));
      assert.deepEqual(w.q(), { ok: false, why: "record" }, `not pass ${k}`);
    }
    w.write(w.record((r) => { r.subcases["R13.a another"] = "pass"; return r; }));
    assert.deepEqual(w.q(), { ok: false, why: "record" });
    w.write(w.record());
    assert.deepEqual(w.q(), { ok: true });
  } finally { w.done(); }
});

// ---- the environment (§2.3) --------------------------------------------------------------------------------------

test("the environment: systemd major, Node major, no cgroup v2, a missing cgroup file, /proc/uptime, and a kernel series below and above: unqualified", () => {
  const w = release();
  try {
    w.write(w.record((r) => { r.env.systemd_major = QUALIFIED_MAJOR + 1; return r; }));
    assert.deepEqual(w.q(), { ok: false, why: "systemd_major" });
    w.write(w.record());
    const major = Number(process.versions.node.split(".")[0]);
    assert.deepEqual(w.q({ nodeVersion: `${major + 1}.0.0` }), { ok: false, why: "node_major" });
    assert.deepEqual(w.q({ nodeVersion: `${major - 1}.9.9` }), { ok: false, why: "node_major" });
    assert.deepEqual(w.q({ nodeVersion: `${major}.99.0` }), { ok: true }, "a minor update passes");
    assert.deepEqual(w.q({ kernel: "6.7.12-generic" }), { ok: false, why: "kernel_series" }, "below");
    assert.deepEqual(w.q({ kernel: "6.9.0-1-generic" }), { ok: false, why: "kernel_series" }, "above");
    assert.deepEqual(w.q({ kernel: "6.80.0" }), { ok: false, why: "kernel_series" }, "not a prefix match");
    assert.deepEqual(w.q({ kernel: "6.8.99-1" }), { ok: true }, "a patch release passes");
    w.over.mounts = "30 24 0:26 / /cg rw - cgroup cgroup rw,memory\n";
    assert.deepEqual(w.q(), { ok: false, why: "cgroup" }, "v1");
    w.over.mounts = "30 24 0:26 / /sys/fs/cgroup rw - cgroup2 cgroup2 rw\n";
    assert.deepEqual(w.q(), { ok: false, why: "cgroup" }, "elsewhere");
    w.over = {};
    for (const f of ["cgroup.kill", "cgroup.freeze", "cgroup.events"]) {
      w.over.cg = (p) => !p.endsWith(`/${f}`);
      assert.deepEqual(w.q(), { ok: false, why: "cgroup" }, f);
    }
    w.over = {};
    const realRead = w.fsx.readFileSync;
    w.fsx.readFileSync = (p, ...a) => { if (p === "/proc/uptime") throw new Error("EACCES"); return realRead(p, ...a); };
    assert.deepEqual(w.q(), { ok: false, why: "uptime" });
    w.fsx.readFileSync = realRead;
    assert.deepEqual(w.q(), { ok: true });
  } finally { w.done(); }
});

test("no record in this tree: every host is unqualified (A1 is inert)", () => {
  assert.equal(fs.existsSync(join(REPO, RECORD)), false);
  assert.deepEqual(leaseQualified(REPO).ok, false);
});
