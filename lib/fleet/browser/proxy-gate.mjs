// Fleet protocol, the browser lane (O11 §5, §6 and the Nov 23 ruling (d)): the gate in front of the net sidecar's
// local HTTP proxy, the one choke point for every connection Chrome makes. Pure: it reads one request head and decides,
// before any name is resolved or any byte goes upstream.
//   - The head: strict HTTP/1.1, at most LIMITS.headBytes, CRLF only, ASCII only, no folded lines, no duplicate Host,
//     Proxy-Authorization, Content-Length or Transfer-Encoding, and never both of the last two.
//   - Caller binding (§5): Proxy-Authorization must be exactly the session's Basic credentials; otherwise 407.
//   - The destination: a CONNECT's authority (host:port, nothing else), or an http absolute-form URL whose Host header
//     names the same host and port. https is only ever a CONNECT. A destination the gate can't identify is refused.
//   - The account-origin layer (§6 layer 2; with ruling (d), the mandatory one for workers until §9 shows Fetch there):
//     the host, normalized as the Filter's urls.mjs does (lowercase, IDNA to A-labels, IPv4 forms, the trailing dot),
//     refused if it is an account origin or under one, at any port.
//   - Ports 80 and 443 only (exceptions stay off until §9 test 8 qualifies them).
// What it returns for an allowed request is the normalized host and port to resolve; §5's resolve-check-connect rule
// (public addresses only, no second lookup) is the proxy's next step, not this module's.
// Refusals carry a fixed `why`, plus the matched list entry for an account origin (shown as "blocked: account site").

import { timingSafeEqual, createHash } from "node:crypto";
import { normalHost } from "./urls.mjs";

export const LIMITS = Object.freeze({ headBytes: 16 * 1024, headerLines: 64 });
export const PORTS = Object.freeze([80, 443]);
const METHODS = new Set(["CONNECT", "GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"]);
const SINGLE = new Set(["host", "proxy-authorization", "content-length", "transfer-encoding"]);
const TOKEN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;

/** Where the head ends in `buf` (the index after its blank line), -1 if not yet, or throws once it is too long. */
export function headEnd(buf) {
  const i = buf.indexOf("\r\n\r\n");
  if (i !== -1) return i + 4 <= LIMITS.headBytes ? i + 4 : Infinity; // (Infinity: over the limit, refuse with 431)
  return buf.length >= LIMITS.headBytes ? Infinity : -1;
}

const bad = (why, status = 400) => ({ ok: false, status, why });

/** Parse one request head (the bytes up to and including its blank line). { ok, method, target, headers } or a refusal. */
export function parseHead(bytes) {
  if (bytes.length > LIMITS.headBytes) return bad("too large", 431);
  for (const b of bytes) if (b > 0x7e || (b < 0x20 && b !== 0x0d && b !== 0x0a && b !== 0x09)) return bad("not ASCII");
  const text = Buffer.from(bytes).toString("latin1");
  if (!text.endsWith("\r\n\r\n")) return bad("no end");
  const lines = text.slice(0, -4).split("\r\n");
  if (lines.some((l) => l.includes("\n") || l.includes("\r"))) return bad("bare line feed");
  if (lines.length - 1 > LIMITS.headerLines) return bad("too many headers", 431);
  const m = /^([A-Z]+) ([^ \t]+) HTTP\/1\.1$/.exec(lines[0]);
  if (!m) return bad("request line");
  if (!METHODS.has(m[1])) return bad("method", 405);
  const headers = new Map();
  for (const line of lines.slice(1)) {
    if (line.startsWith(" ") || line.startsWith("\t")) return bad("folded header");
    const c = line.indexOf(":");
    const name = c > 0 ? line.slice(0, c) : "";
    if (!TOKEN.test(name)) return bad("header name");
    const key = name.toLowerCase();
    const value = line.slice(c + 1).replace(/^[ \t]+|[ \t]+$/g, "");
    if (headers.has(key)) {
      if (SINGLE.has(key)) return bad("duplicate header");
      headers.set(key, `${headers.get(key)}, ${value}`);
    } else headers.set(key, value);
  }
  if (headers.has("content-length") && headers.has("transfer-encoding")) return bad("both lengths");
  return { ok: true, method: m[1], target: m[2], headers };
}

const digest = (s) => createHash("sha256").update(s, "latin1").digest();

/** Whether a Proxy-Authorization value is exactly the session's Basic credentials (compared in constant time). */
export function authorized(value, { username, password }) {
  if (typeof value !== "string") return false;
  const want = `Basic ${Buffer.from(`${username}:${password}`, "utf8").toString("base64")}`;
  return timingSafeEqual(digest(value), digest(want));
}

/** host:port of a URL the parser made: the normalized host ("" if it can't be compared) and the port as a number. */
function place(u) {
  const host = normalHost(u.hostname);
  const port = u.port === "" ? (u.protocol === "https:" ? 443 : 80) : Number(u.port);
  return { host, port };
}

// An authority: a host (a name, or a bracketed IPv6 literal) and a port; no user info, path, query or fragment.
const AUTHORITY = /^(\[[0-9A-Fa-f:.]+\]|[^\s/?#@:[\]\\]+):([0-9]{1,5})$/;

/**
 * Decide one parsed head. `session`: { username, password, origins } (origins from urls.mjs accountOrigins).
 * Returns { ok: true, connect, host, port } or { ok: false, status, why, origin? }.
 */
export function decide(head, session) {
  if (!authorized(head.headers.get("proxy-authorization"), session)) return { ok: false, status: 407, why: "proxy credentials" };
  let dest;
  if (head.method === "CONNECT") {
    const m = AUTHORITY.exec(head.target);
    if (!m) return bad("authority");
    let u;
    try { u = new URL(`https://${head.target}/`); } catch { return bad("authority"); }
    dest = place(u);
    if (Number(m[2]) !== dest.port) return bad("authority");
    if (head.headers.has("host") && !sameHost(head.headers.get("host"), dest, 443)) return bad("host mismatch");
  } else {
    let u;
    try { u = new URL(head.target); } catch { return bad("target"); }
    // (absolute-form http only: https always comes as a CONNECT; no user info; the target exactly as the parser keeps it)
    if (u.protocol !== "http:" || u.username !== "" || u.password !== "" || !/^http:\/\//i.test(head.target)) return bad("target");
    dest = place(u);
    if (!head.headers.has("host") || !sameHost(head.headers.get("host"), dest, 80)) return bad("host mismatch");
  }
  if (!dest.host) return bad("host");
  const origin = accountOf(dest.host, session.origins);
  if (origin) return { ok: false, status: 403, why: "account", origin };
  if (!PORTS.includes(dest.port)) return { ok: false, status: 403, why: "port" };
  return { ok: true, connect: head.method === "CONNECT", host: dest.host, port: dest.port };
}

function sameHost(value, dest, defaultPort) {
  let u;
  try { u = new URL(`${defaultPort === 443 ? "https" : "http"}://${value}/`); } catch { return false; }
  if (u.username !== "" || u.password !== "" || u.pathname !== "/" || u.search !== "" || u.hash !== "") return false;
  const p = place(u);
  return p.host !== "" && p.host === dest.host && p.port === dest.port;
}

/** The account-origin entry a host is, or is under; null if none. */
export function accountOf(host, origins) {
  if (host.startsWith("[")) return null;
  for (const o of origins) if (host === o || host.endsWith(`.${o}`)) return o;
  return null;
}

/** The proxy's answer to a refusal: a fixed status line and headers, no body. */
export function refusalBytes(status) {
  const text = { 400: "Bad Request", 403: "Forbidden", 405: "Method Not Allowed", 407: "Proxy Authentication Required", 431: "Request Header Fields Too Large" }[status] ?? "Bad Request";
  const auth = status === 407 ? 'Proxy-Authenticate: Basic realm="sagebrush"\r\n' : "";
  return Buffer.from(`HTTP/1.1 ${status} ${text}\r\n${auth}Content-Length: 0\r\nConnection: close\r\n\r\n`, "latin1");
}
