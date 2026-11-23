// Fleet protocol, the browser lane (O11 §5): which addresses the net sidecar's proxy may connect to. Only public ones,
// and "public" means positively global, failing closed:
//   - IPv4: not in the IANA IPv4 Special-Purpose Address Registry, nor in 0.0.0.0/8, 224.0.0.0/4 or 240.0.0.0/4;
//   - IPv6: in 2000::/3 and not in the IANA IPv6 Special-Purpose Address Registry. That refuses IPv4-mapped (::ffff/96),
//     NAT64 (64:ff9b::/96, 64:ff9b:1::/48), 6to4 (2002::/16), Teredo (2001::/32) and everything outside 2000::/3.
// Every registry entry is refused, whatever its "globally reachable" column says. The registries are the IANA CSV
// files pinned in schema/fleet/browser/iana/ (SPECIAL.sources has their sha256s), compiled into
// schema/fleet/browser/special-addresses.json; test/fleet-addresses.test.mjs recompiles it from them. A later registry
// entry needs a new release to be allowed.
//
// The rule (§5): resolve the name here, refuse the whole answer if any address in it isn't public, and connect to an
// address that was checked, with no second lookup. resolvePublic() does the first two and returns that address.

import { readFileSync } from "node:fs";
import { isIPv4, isIPv6 } from "node:net";

export const SPECIAL = Object.freeze(JSON.parse(readFileSync(new URL("../../../schema/fleet/browser/special-addresses.json", import.meta.url), "utf8")));

/** An address as { v: 4 | 6, n: BigInt }, or null if it isn't one exact address (brackets allowed around IPv6). */
export function parseAddress(text) {
  if (typeof text !== "string") return null;
  const bracketed = text.startsWith("[") && text.endsWith("]");
  const s = bracketed ? text.slice(1, -1) : text;
  if (isIPv4(s) && !bracketed) return { v: 4, n: s.split(".").reduce((n, x) => (n << 8n) | BigInt(Number(x)), 0n) };
  if (!isIPv6(s) || s.includes("%")) return null; // (no zone ids)
  // (the URL parser's form: lowercase hex groups, no dotted IPv4 tail, at most one "::")
  const hex = new URL(`http://[${s}]/`).hostname.slice(1, -1);
  const [head, rest] = hex.includes("::") ? hex.split("::") : [hex, null];
  const h = head ? head.split(":") : [];
  const r = rest ? rest.split(":") : [];
  const groups = rest === null ? h : [...h, ...Array(8 - h.length - r.length).fill("0"), ...r];
  if (groups.length !== 8) return null;
  return { v: 6, n: groups.reduce((n, g) => (n << 16n) | BigInt(parseInt(g, 16)), 0n) };
}

/** A CIDR block as { v, base, bits }; throws on anything else (the registry data must be exact). */
export function parseCidr(text) {
  const m = /^([^/]+)\/(\d{1,3})$/.exec(text);
  const a = m && parseAddress(m[1]);
  const bits = m ? Number(m[2]) : -1;
  if (!a || bits > (a.v === 4 ? 32 : 128)) throw new Error("not a CIDR block");
  const width = a.v === 4 ? 32n : 128n;
  const mask = ((1n << width) - 1n) ^ ((1n << (width - BigInt(bits))) - 1n);
  if ((a.n & mask) !== a.n) throw new Error("a CIDR block with host bits set");
  return Object.freeze({ v: a.v, base: a.n, bits, mask });
}

const inBlock = (a, b) => a.v === b.v && (a.n & b.mask) === b.base;
const BLOCKS = Object.freeze({
  4: Object.freeze([...SPECIAL.ipv4, ...SPECIAL.ipv4_also].map(parseCidr)),
  6: Object.freeze(SPECIAL.ipv6.map(parseCidr)),
});
const GLOBAL6 = parseCidr("2000::/3");

/** Whether an address (text or parsed) is public by §5's rule. Anything that isn't one exact address isn't. */
export function isPublic(addr) {
  const a = typeof addr === "string" ? parseAddress(addr) : addr;
  if (!a || (a.v !== 4 && a.v !== 6) || typeof a.n !== "bigint") return false;
  if (a.v === 6 && !inBlock(a, GLOBAL6)) return false;
  return !BLOCKS[a.v].some((b) => inBlock(a, b));
}

/**
 * Resolve a host (a name, or an IP literal as the gate normalized it) to one public address to connect to.
 * `lookup(host)` resolves a name to all its addresses ([{ address, family }], as dns.promises.lookup with
 * { all: true, verbatim: true }). Returns { ok: true, address, family } or { ok: false, why }: "private" if any address
 * isn't public (the whole answer is refused), "resolve" if the name didn't resolve, "empty" if it resolved to nothing.
 */
export async function resolvePublic(host, lookup) {
  const literal = parseAddress(host);
  if (literal) return isPublic(literal) ? { ok: true, address: host.replace(/^\[|\]$/g, ""), family: literal.v } : { ok: false, why: "private" };
  let answers;
  try { answers = await lookup(host); } catch { return { ok: false, why: "resolve" }; }
  if (!Array.isArray(answers) || answers.length === 0) return { ok: false, why: "empty" };
  for (const x of answers) if (!x || typeof x.address !== "string" || !isPublic(x.address)) return { ok: false, why: "private" };
  const first = answers[0];
  return { ok: true, address: first.address, family: parseAddress(first.address).v };
}

// ---- the registry data, compiled from IANA's CSV files (used by the test that pins special-addresses.json)

/** Rows of a CSV text (RFC 4180: quoted fields, doubled quotes, CRLF). */
function csvRows(text) {
  const rows = [];
  let row = [], field = "", q = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) {
      if (c === '"' && text[i + 1] === '"') { field += '"'; i++; } else if (c === '"') q = false; else field += c;
    } else if (c === '"') q = true;
    else if (c === ",") { row.push(field); field = ""; } else if (c === "\n") { row.push(field.replace(/\r$/, "")); rows.push(row); row = []; field = ""; } else field += c;
  }
  if (field !== "" || row.length) { row.push(field.replace(/\r$/, "")); rows.push(row); }
  return rows;
}

/** The address blocks of one IANA special-purpose registry CSV (its first column; footnote marks dropped). */
export function registryBlocks(text) {
  const rows = csvRows(text);
  if (rows[0]?.[0] !== "Address Block") throw new Error("not an IANA special-purpose registry");
  return rows.slice(1).filter((r) => r[0]).flatMap((r) => r[0].split(",").map((x) => x.replace(/\[\d+\]/g, "").trim())).map((b) => (parseCidr(b), b));
}
