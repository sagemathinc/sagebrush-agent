// Host supervisor (design: agent-autonomous-host-supervisor-freeze-r3.1.md §6.1): a grant agent's `config` under
// config_schema 1. The closed schema (schema/fleet/host-config.schema.json) fixes the shape; this file adds the rules
// one field imposes on another and the path refusals, so the supervisor refuses a grant before applying anything.
// Every refusal is FleetError("bad_form") naming the rule, never echoing the value.
//
// What this does not decide: whether a path's ancestors are writable by an agent, and what a path resolves to. Those
// are checked on the real host at preflight, by handle (§4.6), because only the host knows its filesystem.

import { readFileSync } from "node:fs";
import { isIPv4, isIPv6 } from "node:net";
import { refuse } from "../bytes.mjs";
import { compile } from "../schema.mjs";

export const HOST_FREEZE = Object.freeze({
  revision: "r3.1",
  sha256: "7f51ec735ca27968ebbb50dd3f21f765c9f203e04827fe3d50e8e3cb8fef1a12",
});
export const CONFIG_SCHEMA = 1;

const schemaDoc = JSON.parse(readFileSync(new URL("../../../schema/fleet/host-config.schema.json", import.meta.url), "utf8"));
const validateShape = compile(schemaDoc);

const no = (rule) => refuse("bad_form", `config: ${rule}`);

// ---- paths

/** Subtrees no grant may name or reach into; matched by whole path segments (§6.1). `/` itself is refused exactly. */
export const PROTECTED = Object.freeze(["/etc", "/proc", "/sys", "/dev", "/run", "/boot", "/root", "/opt/sagebrush", "/srv/sagebrush"]);

const under = (path, p) => path === p || path.startsWith(`${p}/`);

/** Refuses a granted path that is not normalized or lies in a protected subtree. Returns the path. */
export function checkGrantPath(path) {
  if (typeof path !== "string" || !path.startsWith("/") || path === "/") no("a path must be absolute and not /");
  const segs = path.slice(1).split("/");
  if (segs.some((s) => s === "" || s === "." || s === "..")) no("a path must be normalized");
  if (PROTECTED.some((p) => under(path, p))) no("a path may not be in a protected subtree");
  if (segs[0] === "var" && segs[1] === "lib" && segs.length >= 3 && segs[2].startsWith("sagebrush")) no("a path may not be in /var/lib/sagebrush*");
  return path;
}

// ---- addresses

function v4(s) {
  if (!isIPv4(s)) return null;
  return s.split(".").reduce((n, o) => (n << 8n) | BigInt(Number(o)), 0n);
}

function v6(s) {
  if (!isIPv6(s) || s.includes(".")) return null; // (no embedded IPv4 forms in a grant)
  const [head, tail] = s.includes("::") ? s.split("::") : [s, null];
  const h = head ? head.split(":") : [];
  const t = tail === null ? [] : tail ? tail.split(":") : [];
  const fill = tail === null ? 0 : 8 - h.length - t.length;
  if (fill < 0 || (tail === null && h.length !== 8)) return null;
  const groups = [...h, ...Array(fill).fill("0"), ...t];
  return groups.reduce((n, g) => (n << 16n) | BigInt(parseInt(g, 16)), 0n);
}

const PRIVATE = Object.freeze({
  4: [["10.0.0.0", 8], ["172.16.0.0", 12], ["192.168.0.0", 16]].map(([a, l]) => [v4(a), l]),
  6: [[v6("fc00::"), 7]],
});

/** A `lan_allow` CIDR must be canonical (no host bits set) and lie inside a private range (§5.1, §6.1). */
export function checkLanCidr(cidr) {
  const [addr, lenText] = String(cidr).split("/");
  const fam = isIPv4(addr) ? 4 : isIPv6(addr) ? 6 : 0;
  if (!fam || !/^(0|[1-9][0-9]{0,2})$/.test(lenText ?? "")) no("lan_allow must be a CIDR");
  if (fam === 6) no("lan_allow: v1 has no IPv6 egress, so no IPv6 exception"); // ruled; refused at activation
  const bits = fam === 4 ? 32 : 128, len = Number(lenText);
  if (len > bits) no("lan_allow must be a CIDR");
  const n = fam === 4 ? v4(addr) : v6(addr);
  if (n === null) no("lan_allow must be a CIDR");
  const hostMask = (1n << BigInt(bits - len)) - 1n;
  if ((n & hostMask) !== 0n) no("lan_allow must not set host bits");
  const inside = PRIVATE[fam].some(([net, l]) => len >= l && ((n ^ net) >> BigInt(bits - l)) === 0n);
  if (!inside) no("lan_allow must be inside a private range");
  return cidr;
}

/** An `allow` entry: an exact host name, optional port 1–65535 (the schema fixes the grammar). */
function checkAllow(entry) {
  const m = /:([0-9]+)$/.exec(entry);
  if (m && (Number(m[1]) < 1 || Number(m[1]) > 65535)) no("allow port out of range");
  return entry;
}

// ---- the whole config

/**
 * Validate one agent's config. `host` gives what only the host knows: `ramMb` and `cpus`; when given, the memory and
 * CPU quota bounds are checked against them. Returns true, or throws FleetError("bad_form").
 */
export function validateConfig(config, host = {}) {
  validateShape(config);
  for (const p of [...config.files.rw, ...config.files.ro]) checkGrantPath(p);
  if (config.files.rw.some((p) => config.files.ro.includes(p))) no("a path may not be both rw and ro");

  const { mode, allow, lan_allow } = config.network;
  if (mode !== "allowlist" && allow.length) no("allow is only for allowlist");
  if (mode !== "full" && lan_allow.length) no("lan_allow is only for full");
  allow.forEach(checkAllow);
  lan_allow.forEach(checkLanCidr);

  if (config.programs === "no-shell" && !Array.isArray(config.mcp_allow)) no("no-shell needs an mcp_allow list");
  if (Array.isArray(config.mcp_allow)) {
    const names = config.mcp_allow.map((m) => m.name);
    if (new Set(names).size !== names.length) no("mcp_allow names must be unique");
    for (const m of config.mcp_allow) checkGrantPath(m.argv[0]);
  }

  const r = config.resources;
  if (Number.isSafeInteger(host.ramMb) && r.memory_max_mb > host.ramMb) no("memory_max_mb above the host's memory");
  if (Number.isSafeInteger(host.cpus) && r.cpu_quota_pct !== null && r.cpu_quota_pct > 100 * host.cpus) no("cpu_quota_pct above the host's CPUs");
  return true;
}
