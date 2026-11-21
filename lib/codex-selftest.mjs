// The Codex self-test: before a conversation starts, is the Codex on this computer one sagebrush-agent can drive?
// It asks that Codex for its own app-server protocol (`codex app-server generate-json-schema --experimental`, no model
// call, no login used) and checks every method, field and value the agent relies on (lib/codex-contract.json) is
// there. A missing or renamed one, a new required parameter or a decision value Codex no longer takes fails it, and
// nothing runs; a Codex that only adds (an optional field, a new method or notification) passes.
//
// This checks compatibility, not behavior: it can't tell whether a Codex acts without asking first.

import { treeSpawn } from "./win-job.mjs";
import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

export const CONTRACT = JSON.parse(readFileSync(new URL("./codex-contract.json", import.meta.url), "utf8"));
const GENERATE_MS = 20 * 1000; // generating the schema (a second or two; longer means something's wrong)
const SCHEMA_FILES = ["codex_app_server_protocol.schemas.json", "codex_app_server_protocol.v2.schemas.json"];

/** Every definition Codex generated, by name: the two bundles, then each file's own definitions and the file itself
 *  under its title (some types, a request's nested ones, appear only there). A name already taken is kept. */
export function loadSchemas(dir) {
  const defs = {};
  const add = (name, s) => { if (name && s && !(name in defs)) defs[name] = s; };
  for (const f of SCHEMA_FILES) {
    for (const [k, v] of Object.entries(JSON.parse(readFileSync(join(dir, f), "utf8")).definitions ?? {})) {
      // (the first bundle nests the v2 types under definitions.v2, referred to as #/definitions/v2/<Name>)
      if (k === "v2" && v && !v.type && !v.properties && !v.$ref) for (const [k2, v2] of Object.entries(v)) add(k2, v2);
      else add(k, v);
    }
  }
  for (const sub of ["", "v2"]) {
    let names = [];
    try { names = readdirSync(join(dir, sub)).filter((n) => n.endsWith(".json") && !SCHEMA_FILES.includes(n)); } catch {}
    for (const n of names.sort()) {
      const s = JSON.parse(readFileSync(join(dir, sub, n), "utf8"));
      for (const [k, v] of Object.entries(s.definitions ?? {})) add(k, v);
      add(s.title ?? n.replace(/\.json$/, ""), s);
    }
  }
  return defs;
}

// ---- reading the schema

function deref(defs, s, seen = new Set()) {
  while (s && typeof s.$ref === "string") {
    const name = s.$ref.split("/").pop(); // (#/definitions/<Name> or #/definitions/v2/<Name>)
    if (seen.has(name)) return null;
    seen.add(name);
    s = defs[name];
  }
  return s ?? null;
}

// (a schema and every alternative it may be: anyOf/oneOf/allOf branches, $refs followed)
function branches(defs, s, out = [], seen = new Set()) {
  s = deref(defs, s);
  if (!s || seen.has(s)) return out;
  seen.add(s);
  out.push(s);
  for (const k of ["anyOf", "oneOf", "allOf"]) for (const b of s[k] ?? []) branches(defs, b, out, seen);
  return out;
}

/** The schema of field `path` ("a.b.c") in schema `s`, in any alternative, or null. */
export function fieldOf(defs, s, path) {
  let cur = [s];
  for (const key of path.split(".")) {
    const next = [];
    for (const c of cur) for (const b of branches(defs, c)) if (b.properties && key in b.properties) next.push(b.properties[key]);
    if (!next.length) return null;
    cur = next;
  }
  return cur[0];
}

// (every string a schema allows exactly: enum and const values, in any alternative)
function allowedValues(defs, s) {
  const out = new Set();
  for (const b of branches(defs, s)) {
    for (const v of b.enum ?? []) if (typeof v === "string") out.add(v);
    if (typeof b.const === "string") out.add(b.const);
  }
  return out;
}

// (the branch of a method union (ClientRequest, ServerRequest, ServerNotification) for one method, or null)
function methodBranch(defs, unionName, method) {
  for (const b of branches(defs, defs[unionName])) {
    const m = b.properties?.method;
    if (m && allowedValues(defs, m).has(method)) return b;
  }
  return null;
}

/** What doesn't hold of `contract` in these definitions: a list of short reasons (empty: compatible). */
export function checkContract(defs, contract = CONTRACT) {
  const problems = [];
  const need = (ok, why) => { if (!ok) problems.push(why); };
  for (const [method, sent] of Object.entries(contract.clientRequests)) {
    const b = methodBranch(defs, "ClientRequest", method);
    if (!b) { problems.push(`no request ${method}`); continue; }
    const params = deref(defs, b.properties.params);
    if (!params) { need(!sent.length, `${method} takes no parameters`); continue; }
    for (const f of sent) need(fieldOf(defs, params, f), `${method} has no parameter ${f}`);
    for (const r of params.required ?? []) need(sent.includes(r), `${method} needs a parameter ${r}`);
  }
  for (const [type, fields] of Object.entries({ ...contract.responses, ...contract.answers })) {
    const t = defs[type];
    if (!t) { problems.push(`no ${type}`); continue; }
    for (const f of fields) need(fieldOf(defs, t, f), `${type} has no ${f}`);
  }
  for (const [union, list] of [["ServerNotification", contract.notifications], ["ServerRequest", contract.serverRequests]]) {
    for (const [method, fields] of Object.entries(list)) {
      const b = methodBranch(defs, union, method);
      if (!b) { problems.push(`no ${union === "ServerRequest" ? "request" : "notification"} ${method}`); continue; }
      for (const f of fields) need(fieldOf(defs, b.properties.params, f), `${method} has no ${f}`);
    }
  }
  const items = branches(defs, defs.ThreadItem);
  for (const [type, fields] of Object.entries(contract.items)) {
    const b = items.find((x) => x.properties?.type && allowedValues(defs, x.properties.type).has(type));
    if (!b) { problems.push(`no ${type} item`); continue; }
    for (const f of fields) need(fieldOf(defs, b, f), `the ${type} item has no ${f}`);
  }
  for (const { type, values } of contract.values) {
    const allowed = defs[type] ? allowedValues(defs, defs[type]) : null;
    if (!allowed) { problems.push(`no ${type}`); continue; }
    for (const v of values) need(allowed.has(v), `${type} has no "${v}"`);
  }
  return problems;
}

/** Codex's own schema, generated into a private temp dir and loaded; the dir is removed. `command`: how to ask for it,
 *  e.g. ["codex", "app-server", "generate-json-schema", "--experimental"]; "--out <dir>" is added. */
export async function generateSchemas(command, { env = process.env, cwd, spawnFn = treeSpawn, ms = GENERATE_MS, signal } = {}) {
  const dir = mkdtempSync(join(env.TMPDIR || tmpdir(), "sagebrush-codex-schema-"));
  try {
    await new Promise((resolve, reject) => {
      const [bin, ...args] = command;
      // (its own process group: a timeout or the agent stopping ends it and anything it started)
      const child = spawnFn(bin, [...args, "--out", dir], { cwd, env, stdio: ["ignore", "ignore", "ignore"], detached: true });
      const kill = () => { try { process.kill(-child.pid, "SIGKILL"); } catch { try { child.kill("SIGKILL"); } catch {} } };
      const onStop = () => { kill(); };
      signal?.addEventListener("abort", onStop, { once: true });
      if (signal?.aborted) onStop();
      const timer = setTimeout(() => { kill(); reject(new Error("it took too long")); }, ms);
      // (what fails is said in fixed words only: never Codex's own output, which may quote the person's settings)
      child.on("error", (e) => { clearTimeout(timer); reject(new Error(e?.code === "ENOENT" ? "it wasn't found" : "it couldn't start")); });
      child.on("close", (code, sig) => { clearTimeout(timer); signal?.removeEventListener("abort", onStop); code === 0 ? resolve() : reject(new Error(sig ? `stopped by ${sig}` : `exit ${code}`)); });
    });
    try { return loadSchemas(dir); } catch { throw new Error("its protocol couldn't be read"); }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
