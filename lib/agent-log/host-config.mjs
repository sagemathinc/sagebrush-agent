// A small host config export (the transcript-and-context design note r0.8 §7, SEC H3): `/.agents/hosts/<host-id>/
// config.json`, so a lost host can be rebuilt quickly. It complements host backup and doesn't replace it.
//
// The export is BUILT from a closed allowlist of non-secret fields, never by serializing the host's runtime config
// and removing known secrets. `hostConfigExport` reads exactly the fields below from its input and nothing else, so
// any other field of the input (a credential, a key, a token, the environment, a field added later) can't reach the
// output:
//   host                     the host id (as the path names it)
//   name                     1 to 128 characters, no control characters
//   tags                     at most 32, each [A-Za-z0-9._:-]{1,64}
//   versions.daemon, .launcher   each [0-9A-Za-z.+-]{1,64}
//   backup.sources           at most 256 absolute, normalized paths, each at most 1024 bytes, no control characters
//   backup.daily_at          "HH:MM", host-local
//   network.proxy            a URL string, or { url, ... }: exported as { scheme, host, port } only. A proxy with
//                            any credential (URL userinfo, a query string, or any field beside `url`, such as
//                            headers, a password or a token) is exported as { needs_credential: true } alone
//   agents                   at most 256 of { id, name }, each id once
// A value that doesn't fit is left out and recorded as a health note { field, rule }, which never echoes the value.
// Pure: the caller maps its host state to this input and writes the bytes (with the agent log's other files).

import { lineText } from "./context.mjs";

const te = new TextEncoder();
const CTRL = /[\u0000-\u001f\u007f-\u009f]/;
const HOST_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const TAG_RE = /^[A-Za-z0-9._:-]{1,64}$/;
const VERSION_RE = /^[0-9A-Za-z.+-]{1,64}$/;
const TIME_RE = /^([01][0-9]|2[0-3]):[0-5][0-9]$/;
const SCHEMES = Object.freeze({ "http:": 80, "https:": 443, "socks5:": 1080 });
const own = (o, k) => o !== null && typeof o === "object" && Object.prototype.hasOwnProperty.call(o, k);

// (an array with every index its own: Array.prototype.every skips holes, and a hole would reach the export)
const dense = (a, max) => Array.isArray(a) && a.length <= max && Array.from({ length: a.length }, (_, k) => k).every((k) => Object.prototype.hasOwnProperty.call(a, k));
const text128 = (v) => typeof v === "string" && v.length >= 1 && v.length <= 128 && !CTRL.test(v);
function absPath(p) {
  if (typeof p !== "string" || !p.startsWith("/") || CTRL.test(p) || te.encode(p).length > 1024) return false;
  if (p === "/") return true;
  return p.slice(1).split("/").every((s) => s !== "" && s !== "." && s !== "..");
}

/** The proxy: { scheme, host, port }, { needs_credential: true }, or null (it doesn't fit). */
function proxyOf(v) {
  const url = typeof v === "string" ? v : own(v, "url") && typeof v.url === "string" ? v.url : null;
  if (url === null || url.length > 2048 || CTRL.test(url)) return null;
  let u;
  try { u = new URL(url); } catch { return null; }
  if (!own(SCHEMES, u.protocol) || !u.hostname) return null; // (socks5 isn't a special scheme: its host may parse empty)
  if (u.hash || url.includes("#") || (u.pathname !== "" && u.pathname !== "/")) return null;
  // (a credential anywhere: userinfo, even an empty one, a query string, or any field of the input beside `url`)
  const authority = url.slice(url.indexOf("//") + 2).split(/[/?#]/, 1)[0];
  const extra = typeof v === "object" && Object.keys(v).some((k) => k !== "url");
  if (authority.includes("@") || u.username || u.password || url.includes("?") || extra) return { needs_credential: true };
  const port = u.port === "" ? SCHEMES[u.protocol] : Number(u.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
  return { scheme: u.protocol.slice(0, -1), host: u.hostname, port };
}

/**
 * The export: { bytes (one canonical JSON line and its newline), notes ([{ field, rule }]) }. Refuses (throws) only
 * when `host` isn't an id: without it there is no path to write.
 */
export function hostConfigExport(input) {
  if (!own(input, "host") || typeof input.host !== "string" || !HOST_RE.test(input.host)) throw new RangeError("host: an id");
  const notes = [];
  const note = (field, rule) => notes.push({ field, rule });
  const out = { v: 1, type: "sb.host-config.v1", host: input.host };

  if (own(input, "name")) { if (text128(input.name)) out.name = input.name; else note("name", "1 to 128 characters, no control characters"); }
  if (own(input, "tags")) {
    const t = input.tags;
    if (dense(t, 32) && t.every((x) => typeof x === "string" && TAG_RE.test(x))) out.tags = [...new Set(t)];
    else note("tags", "at most 32 tags, each [A-Za-z0-9._:-]{1,64}");
  }
  if (own(input, "versions")) {
    const versions = {};
    for (const k of ["daemon", "launcher"]) {
      if (!own(input.versions, k)) continue;
      if (typeof input.versions[k] === "string" && VERSION_RE.test(input.versions[k])) versions[k] = input.versions[k];
      else note(`versions.${k}`, "[0-9A-Za-z.+-]{1,64}");
    }
    if (Object.keys(versions).length) out.versions = versions;
  }
  if (own(input, "backup")) {
    const backup = {};
    if (own(input.backup, "sources")) {
      const s = input.backup.sources;
      if (dense(s, 256) && s.every(absPath)) backup.sources = [...new Set(s)];
      else note("backup.sources", "at most 256 absolute, normalized paths");
    }
    if (own(input.backup, "daily_at")) {
      if (typeof input.backup.daily_at === "string" && TIME_RE.test(input.backup.daily_at)) backup.daily_at = input.backup.daily_at;
      else note("backup.daily_at", "HH:MM");
    }
    if (Object.keys(backup).length) out.backup = backup;
  }
  if (own(input, "network") && own(input.network, "proxy")) {
    const p = proxyOf(input.network.proxy);
    if (p) out.network = { proxy: p };
    else note("network.proxy", "an http, https or socks5 URL: scheme, host and port");
  }
  if (own(input, "agents")) {
    const a = input.agents;
    const fits = (x) => own(x, "id") && typeof x.id === "string" && HOST_RE.test(x.id) && own(x, "name") && text128(x.name);
    if (dense(a, 256) && a.every(fits) && new Set(a.map((x) => x.id)).size === a.length) out.agents = a.map((x) => ({ id: x.id, name: x.name }));
    else note("agents", "at most 256 of { id, name }, each id once");
  }
  return { bytes: te.encode(lineText(out) + "\n"), notes };
}
