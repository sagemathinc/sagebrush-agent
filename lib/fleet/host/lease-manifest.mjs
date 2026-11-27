// The execution lease's qualification: the closed manifest of what the qualified path runs (lease-on design r1.5 §2.1,
// SEC C4). Generated, never hand-listed: from the ROOTS, every relative static import and export-from, every literal
// import("./...") and every literal new URL("...", import.meta.url) is followed; a target that isn't code is a resource
// member and must exist. Anything else that can name a release file (import.meta otherwise, process.argv[1],
// createRequire, require, require.resolve, a non-literal import(), __dirname, __filename) refuses generation unless the
// member and its exact source line are DECLARED below with their finite targets. Bare package imports refuse too: the
// lease path loads nothing outside the release tree but Node's builtins. So no new load can escape the manifest: it
// breaks the generator until a reviewed change declares it.
//
// The source is read by a small lexer of its own (comments, strings, template literals with ${} nesting, regular
// expression literals). It fails closed: anything unterminated or ambiguous throws, so generation fails.

import * as fs from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join, normalize, relative, resolve, sep } from "node:path";
import { refuse } from "../bytes.mjs";

/** The roots of the qualified path (§2.1). The dispatcher is followed only by its static import and its host branch. */
export const ROOTS = Object.freeze([
  "bin/sagebrush-agent.mjs",
  "lib/fleet/host/host-main.mjs",
  "lib/fleet/host/lease-main.mjs",
  "lib/fleet/host/restore-resume-main.mjs",
]);

/**
 * The declared release-relative loads (C4): { file, line (the exact source line, trimmed), targets (repo paths; [] when
 * the expression names no release file, or a branch off the lease path) }. Each must match exactly one flagged
 * occurrence, and each flagged occurrence must match one declaration: an unused or a missing one refuses.
 */
export const DECLARED = Object.freeze([
  { file: "bin/sagebrush-agent.mjs", line: 'else await import("./sagebrush-agent-chat.mjs");', targets: [], why: "the chat branch, off the lease path" },
  { file: "lib/fleet/host/host-main.mjs", line: 'const text = fs.readFileSync(new URL(`./units/${SUPERVISOR_UNIT}`, import.meta.url), "utf8");',
    targets: ["lib/fleet/host/units/sagebrush-supervisor.service"], why: "the supervisor's unit file" },
  { file: "lib/fleet/host/host-main.mjs", line: 'const release = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");',
    targets: [], why: "the release root: its executed artifacts (the launcher, the sleep hook) are bound by digest, §2.2" },
  { file: "lib/fleet/host/lease-main.mjs", line: "if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) await main();",
    targets: [], why: "the main-module guard: no load" },
  { file: "lib/fleet/host/restore-resume-main.mjs", line: "if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) await main();",
    targets: [], why: "the main-module guard: no load" },
  { file: "lib/fleet/host/restore-worker-main.mjs", line: "if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) await main();",
    targets: [], why: "the main-module guard: no load" },
  { file: "lib/fleet/host/restore-worker-main.mjs", line: 'const release = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");',
    targets: [], why: "the release root: the launcher it runs is bound by digest, §2.2" },
  { file: "lib/fleet/host/restore-cli.mjs", line: 'const release = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");',
    targets: [], why: "the release root of the restore commands: the launcher (checked against the release's pin before its first launch) and the backup binary they run" },
  { file: "lib/fleet/host/grant.mjs", line: 'const readJson = (rel) => JSON.parse(readFileSync(new URL(rel, import.meta.url), "utf8"));',
    targets: ["schema/fleet/fleet.schema.json", "schema/fleet/host-config.schema.json"], why: "its two callers' literal paths" },
  { file: "lib/fleet/schemas.mjs", line: 'const load = (f) => JSON.parse(readFileSync(new URL(`../../schema/fleet/${f}`, import.meta.url), "utf8"));',
    targets: ["schema/fleet/fleet.schema.json", "schema/fleet/reasons.json"], why: "the core loader asks for exactly these two" },
]);

/**
 * Members that no import names (§2.1): the launcher's crate and build recipe (with every script it runs), the release layout, the sleep hook's source,
 * node-check's package.json, and the qualification machinery. (The VM test, its runner and scripts/lease-qual-vm/ join
 * with the change that adds them: no record can exist before their run.)
 */
export const EXPLICIT = Object.freeze([
  "launcher/Cargo.toml", "launcher/Cargo.lock", "scripts/launcher-build.sh", "scripts/backup-static-check.sh", "scripts/release-install.sh", "scripts/release-trust.sh", "lib/fleet/host/launcher.sha256",
  "backup/Cargo.toml", "backup/Cargo.lock", "scripts/backup-build.sh", "lib/fleet/host/backup.sha256",
  "lib/fleet/host/units/sagebrush-lease-sleep", "package.json",
  "lib/fleet/host/lease-qualified.mjs", "lib/fleet/host/lease-manifest.mjs", "lib/fleet/host/lease-qual-subcases.mjs",
]);
/** Directories whose every regular file is a member (by listing, so a new file is a new member). */
export const EXPLICIT_DIRS = Object.freeze(["launcher/src", "backup/src"]);

const fail = (what) => refuse("bad_form", `lease manifest: ${what}`);
const CODE = /\.(mjs|js)$/;

// ---- the lexer: tokens { t: "id"|"str"|"tpl"|"num"|"re"|"p", v, line } ----------------------------------------------

const ID_START = /[A-Za-z_$\u0080-￿]/, ID_PART = /[A-Za-z0-9_$\u0080-￿]/;
const KEYWORDS_BEFORE_EXPR = new Set(["return", "typeof", "instanceof", "in", "of", "new", "delete", "void", "throw", "case", "do", "else", "yield", "await"]);

export function lex(src) {
  const out = [];
  let i = 0, line = 1;
  const braces = []; // for each open {: "tpl" if it opened a template ${, else "block"
  const prevAllowsRegex = () => {
    const p = out[out.length - 1];
    if (!p) return true;
    if (p.t === "num" || p.t === "str" || p.t === "tpl" || p.t === "re") return false;
    if (p.t === "id") return KEYWORDS_BEFORE_EXPR.has(p.v);
    return !(p.v === ")" || p.v === "]" || p.v === "}");
  };
  const readTemplate = (startLine) => {
    // at a ` or a } that resumes a template: read raw text until ` (end) or ${ (an expression)
    let raw = "";
    for (;;) {
      if (i >= src.length) fail(`an unterminated template literal (line ${startLine})`);
      const c = src[i];
      if (c === "\\") { raw += src.slice(i, i + 2); i += 2; continue; }
      if (c === "`") { i++; return { raw, open: false }; }
      if (c === "$" && src[i + 1] === "{") { i += 2; braces.push("tpl"); return { raw, open: true }; }
      if (c === "\n") line++;
      raw += c; i++;
    }
  };
  while (i < src.length) {
    const c = src[i];
    if (c === "\n") { line++; i++; continue; }
    if (c === " " || c === "\t" || c === "\r") { i++; continue; }
    if (c === "/" && src[i + 1] === "/") { while (i < src.length && src[i] !== "\n") i++; continue; }
    if (c === "/" && src[i + 1] === "*") {
      const end = src.indexOf("*/", i + 2);
      if (end < 0) fail(`an unterminated comment (line ${line})`);
      for (let k = i; k < end; k++) if (src[k] === "\n") line++;
      i = end + 2; continue;
    }
    if (c === "#" && i === 0 && src[1] === "!") { while (i < src.length && src[i] !== "\n") i++; continue; }
    if (c === '"' || c === "'") {
      const q = c, l = line; let v = ""; i++;
      for (;;) {
        if (i >= src.length || src[i] === "\n") fail(`an unterminated string (line ${l})`);
        const d = src[i];
        if (d === "\\") { v += src.slice(i, i + 2); i += 2; continue; }
        if (d === q) { i++; break; }
        v += d; i++;
      }
      out.push({ t: "str", v, raw: v.includes("\\") , line: l }); continue;
    }
    if (c === "`") {
      const l = line; i++;
      const r = readTemplate(l);
      out.push({ t: "tpl", v: r.raw, open: r.open, line: l }); continue;
    }
    if (c === "}" && braces[braces.length - 1] === "tpl") {
      braces.pop(); i++;
      const r = readTemplate(line);
      out.push({ t: "tpl", v: r.raw, open: r.open, cont: true, line }); continue;
    }
    if (c === "{") { braces.push("block"); out.push({ t: "p", v: c, line }); i++; continue; }
    if (c === "}") { if (braces.pop() === undefined) fail(`an unbalanced } (line ${line})`); out.push({ t: "p", v: c, line }); i++; continue; }
    if (c === "/" && prevAllowsRegex()) {
      const l = line; let k = i + 1, cls = false;
      for (;;) {
        if (k >= src.length || src[k] === "\n") fail(`an unterminated regular expression (line ${l})`);
        const d = src[k];
        if (d === "\\") { k += 2; continue; }
        if (d === "[") cls = true; else if (d === "]") cls = false; else if (d === "/" && !cls) break;
        k++;
      }
      k++;
      while (k < src.length && /[a-z]/.test(src[k])) k++;
      out.push({ t: "re", v: src.slice(i, k), line: l }); i = k; continue;
    }
    if (/[0-9]/.test(c) || (c === "." && /[0-9]/.test(src[i + 1]))) {
      let k = i + 1; while (k < src.length && /[0-9A-Za-z_.]/.test(src[k])) k++;
      out.push({ t: "num", v: src.slice(i, k), line }); i = k; continue;
    }
    if (ID_START.test(c)) {
      let k = i + 1; while (k < src.length && ID_PART.test(src[k])) k++;
      out.push({ t: "id", v: src.slice(i, k), line }); i = k; continue;
    }
    out.push({ t: "p", v: c, line }); i++;
  }
  if (braces.length) fail("unbalanced braces at the end");
  return out;
}

const isLit = (tk) => tk && ((tk.t === "str" && !tk.raw) || (tk.t === "tpl" && !tk.open && !tk.cont && !tk.v.includes("\\")));

/**
 * One member's loads: { follow: [specifier, ...] relative imports and literal targets, flagged: [{ line, what }] }.
 * A literal new URL("x", import.meta.url) is followed; every other import.meta and the other forms are flagged.
 */
export function loadsOf(src) {
  const tk = lex(src);
  const follow = [], flagged = [];
  const at = (k, v) => tk[k] && tk[k].v === v && (tk[k].t === "p" || tk[k].t === "id");
  for (let k = 0; k < tk.length; k++) {
    const x = tk[k];
    if (x.t !== "id") continue;
    if (x.v === "from" && tk[k + 1]?.t === "str" && !tk[k + 1].raw) { follow.push({ spec: tk[k + 1].v, line: x.line, kind: "static" }); continue; }
    if (x.v === "import" && tk[k + 1]?.t === "str" && !tk[k + 1].raw && !at(k - 1, ".")) { follow.push({ spec: tk[k + 1].v, line: x.line, kind: "static" }); continue; }
    if (x.v === "import" && at(k + 1, "(")) {
      if (isLit(tk[k + 2]) && at(k + 3, ")")) follow.push({ spec: tk[k + 2].v, line: x.line, kind: "dynamic" });
      else flagged.push({ line: x.line, what: "a non-literal import()" });
      continue;
    }
    if (x.v === "import" && at(k + 1, ".") && tk[k + 2]?.v === "meta") {
      // allowed only as new URL(<literal>, import.meta.url)
      const ok = tk[k - 5]?.v === "new" && tk[k - 4]?.v === "URL" && at(k - 3, "(") && isLit(tk[k - 2]) && at(k - 1, ",")
        && at(k + 3, ".") && tk[k + 4]?.v === "url" && at(k + 5, ")");
      if (ok) follow.push({ spec: tk[k - 2].v, line: x.line, kind: "url" });
      else flagged.push({ line: x.line, what: "import.meta" });
      continue;
    }
    if (x.v === "process" && at(k + 1, ".") && tk[k + 2]?.v === "argv" && at(k + 3, "[") && tk[k + 4]?.v === "1") { flagged.push({ line: x.line, what: "process.argv[1]" }); continue; }
    if (["createRequire", "__dirname", "__filename"].includes(x.v) && !at(k - 1, ".")) { flagged.push({ line: x.line, what: x.v }); continue; }
    if (x.v === "require" && !at(k - 1, ".") && (at(k + 1, "(") || at(k + 1, "."))) { flagged.push({ line: x.line, what: "require" }); continue; }
  }
  return { follow, flagged };
}

const sha256 = (buf) => createHash("sha256").update(buf).digest("hex");
const posix = (p) => p.split(sep).join("/");

/**
 * Generate the manifest of the tree at `root`: { files: { "<repo path>": "<sha256>" } } sorted, the exact member set.
 * Refuses (bad_form) on an undeclared load, an unused declaration, a missing member, a bare package import, a member
 * outside the tree, or a lexer failure. `prove(repoPath)` runs before any member is read (leaseQualified's trust proof,
 * which throws to refuse); the others are test seams: { roots, declared, explicit, explicitDirs, fsx }.
 */
export function leaseManifest(root, { roots = ROOTS, declared = DECLARED, explicit = EXPLICIT, explicitDirs = EXPLICIT_DIRS, fsx = fs, prove = () => {} } = {}) {
  const abs = (p) => resolve(root, p);
  const rel = (p) => { const r = posix(relative(root, p)); if (r.startsWith("../") || r === "..") fail(`a member outside the tree: ${r}`); return r; };
  const regular = (p) => { let st; try { st = fsx.lstatSync(abs(p)); } catch { fail(`a missing member: ${p}`); } prove(p); if (!st.isFile()) fail(`not a regular file: ${p}`); return p; };
  // Explicit JS members are walked like roots: their own loads are members too.
  const members = new Set(), used = new Set(), queue = [...roots, ...explicit.filter((p) => CODE.test(p))];
  while (queue.length) {
    const file = regular(queue.shift());
    if (members.has(file)) continue;
    members.add(file);
    if (!CODE.test(file)) continue;
    const src = fsx.readFileSync(abs(file), "utf8");
    const lines = src.split("\n");
    let loads;
    try { loads = loadsOf(src); } catch (e) { fail(`${file}: ${e.message}`); }
    // The flagged forms: each needs its declaration (file + exact line), whose targets become members.
    for (const f of loads.flagged) {
      const text = lines[f.line - 1].trim();
      const d = declared.findIndex((x) => x.file === file && x.line === text);
      if (d < 0) fail(`${file}:${f.line}: ${f.what} isn't declared ("${text}")`);
      used.add(d);
      for (const t of declared[d].targets) queue.push(regular(t));
    }
    for (const l of loads.follow) {
      if (l.spec.startsWith("node:")) continue; // a builtin
      // A literal that a declared line also names is the same occurrence as its flagged form (template-free lines only).
      if (!l.spec.startsWith("./") && !l.spec.startsWith("../")) {
        const text = lines[l.line - 1].trim();
        const d = declared.findIndex((x) => x.file === file && x.line === text);
        if (d >= 0) { used.add(d); for (const t of declared[d].targets) queue.push(regular(t)); continue; }
        fail(`${file}:${l.line}: a bare import "${l.spec}" (nothing outside the release tree)`);
      }
      // the dispatcher's chat branch is declared: skip a followed target whose line is declared with no targets
      const text = lines[l.line - 1].trim();
      const d = declared.findIndex((x) => x.file === file && x.line === text);
      if (d >= 0) { used.add(d); for (const t of declared[d].targets) queue.push(regular(t)); continue; }
      queue.push(regular(rel(normalize(join(dirname(abs(file)), l.spec)))));
    }
  }
  for (const p of explicit) if (!CODE.test(p)) members.add(regular(p));
  for (const d of explicitDirs) {
    let names;
    try { names = fsx.readdirSync(abs(d)).sort(); } catch { fail(`a missing member directory: ${d}`); }
    for (const n of names) members.add(regular(`${d}/${n}`));
  }
  declared.forEach((x, k) => { if (!used.has(k)) fail(`an unused declaration: ${x.file}: ${x.line}`); });
  const files = {};
  for (const p of [...members].sort()) files[p] = sha256(fsx.readFileSync(abs(p)));
  return { files };
}
