// The agent's own network reads (step 4, plan r5 §5, SEC pins S1–S6): one safe transport for repo_read, repo_list,
// sagebrush_docs and web_fetch, the canonical origin of a URL, and the display form a card shows. Nothing here
// decides whether a request may go: the caller does (a cardless verb's fixed shape, or the turn's egress grant).
//
// The transport (S1, S2, S4):
// - https only, to a name (never an IP literal), every address it resolves to public, the connection made to a checked
//   address while TLS (SNI, certificate) and Host use the name;
// - no proxy from the environment, no client certificate, no cookies, fixed headers only;
// - no redirect followed by itself: one to the same origin (or within a fixed host set) is followed after the same
//   checks, at most 3; one anywhere else is returned as its origin alone, never its path or query;
// - no compression (identity only: any other Content-Encoding is refused), so the bytes read are the bytes kept;
//   bounded before they're kept, and the socket is destroyed at every cap;
// - one deadline over everything: DNS, connect, TLS, redirects, the body, and turning HTML into text.
import https from "node:https";
import dns from "node:dns";
import net from "node:net";

export const UA = "sagebrush-agent (https://sagebrush.space/agents/connect/)";
const MAX_REDIRECTS = 3;

// Not public (S1): IPv4 special-use blocks (RFC 6890 and the IANA registry), and for IPv6 anything outside global
// unicast 2000::/3 plus the special-use blocks inside it.
const V4_BLOCKED = [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16], ["172.16.0.0", 12],
  ["192.0.0.0", 24], ["192.0.2.0", 24], ["192.31.196.0", 24], ["192.52.193.0", 24], ["192.88.99.0", 24],
  ["192.168.0.0", 16], ["192.175.48.0", 24], ["198.18.0.0", 15], ["198.51.100.0", 24], ["203.0.113.0", 24],
  ["224.0.0.0", 4], ["240.0.0.0", 4],
];
const V6_BLOCKED_IN_GLOBAL = [["2001::", 23], ["2001:db8::", 32], ["2002::", 16], ["3fff::", 20]];
const blocked4 = new net.BlockList();
for (const [a, p] of V4_BLOCKED) blocked4.addSubnet(a, p, "ipv4");
const global6 = new net.BlockList();
global6.addSubnet("2000::", 3, "ipv6");
const blocked6 = new net.BlockList();
for (const [a, p] of V6_BLOCKED_IN_GLOBAL) blocked6.addSubnet(a, p, "ipv6");

/** Whether an address (as DNS gave it) is a public one this agent may connect to. */
export function isPublicAddress(address, family) {
  if (typeof address !== "string" || address.includes("%")) return false; // (a zone id: link-local by nature)
  const f = family === 6 || family === "IPv6" ? 6 : family === 4 || family === "IPv4" ? 4 : net.isIP(address);
  if (f === 4) return net.isIPv4(address) && !blocked4.check(address, "ipv4");
  if (f === 6) return net.isIPv6(address) && global6.check(address, "ipv6") && !blocked6.check(address, "ipv6");
  return false;
}

const HOST = /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;
const BAD_ESCAPE = /%(?![0-9A-Fa-f]{2})/;
// (C0 and C1 controls, DEL, and the bidi and other invisible format characters)
const CONTROL_OR_BIDI = /[\u0000-\u001f\u007f-\u009f\u061c\u200b-\u200f\u2028-\u202e\u2060-\u2069\ufeff]/;

// ---- A-labels (RFC 3492 Punycode, RFC 5891), the page's own rule (#1411, web/workspace/agent-egress.ts hostOk), the
// same on both sides: a label "xn--…" is one only if it decodes to a name with a non-ASCII character and encodes back
// to exactly itself, and the whole name, written in Unicode, parses back to exactly this host; any other "??--" label
// is reserved (SEC 5).
const BASE = 36, TMIN = 1, TMAX = 26, SKEW = 38, DAMP = 700, INITIAL_BIAS = 72, INITIAL_N = 128;
function adapt(delta, points, first) {
  delta = first ? Math.floor(delta / DAMP) : delta >> 1;
  delta += Math.floor(delta / points);
  let k = 0;
  for (; delta > ((BASE - TMIN) * TMAX) >> 1; k += BASE) delta = Math.floor(delta / (BASE - TMIN));
  return k + Math.floor(((BASE - TMIN + 1) * delta) / (delta + SKEW));
}
const digitOf = (c) => (c >= 48 && c <= 57 ? c - 22 : c >= 97 && c <= 122 ? c - 97 : -1); // (lowercase only)
const charOf = (d) => String.fromCharCode(d < 26 ? d + 97 : d + 22);
function punyDecode(s) {
  const out = [];
  const last = s.lastIndexOf("-");
  for (let j = 0; j < Math.max(last, 0); j++) out.push(s.charCodeAt(j));
  let n = INITIAL_N, bias = INITIAL_BIAS, i = 0;
  for (let at = last > 0 ? last + 1 : 0; at < s.length; ) {
    const old = i;
    for (let w = 1, k = BASE; ; k += BASE) {
      if (at >= s.length) return null;
      const d = digitOf(s.charCodeAt(at++));
      if (d < 0 || d > Math.floor((0x7fffffff - i) / w)) return null;
      i += d * w;
      const t = k <= bias ? TMIN : k >= bias + TMAX ? TMAX : k - bias;
      if (d < t) break;
      if (w > Math.floor(0x7fffffff / (BASE - t))) return null;
      w *= BASE - t;
    }
    bias = adapt(i - old, out.length + 1, old === 0);
    if (Math.floor(i / (out.length + 1)) > 0x10ffff - n) return null;
    n += Math.floor(i / (out.length + 1));
    i %= out.length + 1;
    if (n > 0x10ffff || (n >= 0xd800 && n <= 0xdfff)) return null;
    out.splice(i++, 0, n);
  }
  return out;
}
function punyEncode(cps) {
  let out = cps.filter((c) => c < 128).map((c) => String.fromCharCode(c)).join("");
  const b = out.length;
  let h = b, n = INITIAL_N, delta = 0, bias = INITIAL_BIAS;
  if (b > 0) out += "-";
  while (h < cps.length) {
    const m = Math.min(...cps.filter((c) => c >= n));
    delta += (m - n) * (h + 1);
    n = m;
    for (const c of cps) {
      if (c < n) delta++;
      if (c !== n) continue;
      let q = delta;
      for (let k = BASE; ; k += BASE) {
        const t = k <= bias ? TMIN : k >= bias + TMAX ? TMAX : k - bias;
        if (q < t) break;
        out += charOf(t + ((q - t) % (BASE - t)));
        q = Math.floor((q - t) / (BASE - t));
      }
      out += charOf(q);
      bias = adapt(delta, h + 1, h === b);
      delta = 0;
      h++;
    }
    delta++;
    n++;
  }
  return out;
}
/** A host as the page takes it: each "xn--" label a true A-label, decoding to a name with a non-ASCII character and
 *  encoding back to itself, and the whole name, written in Unicode, parsed by the platform's URL parser (its IDNA:
 *  UTS 46's mapping and validity) back to exactly this host; no other "??--" label (reserved). */
function hostOk(host) {
  let idn = false;
  const uni = [];
  for (const label of host.split(".")) {
    if (!label.startsWith("xn--")) { if (/^..--/.test(label)) return false; uni.push(label); continue; }
    const cps = punyDecode(label.slice(4));
    if (!cps || !cps.some((c) => c >= 128) || punyEncode(cps) !== label.slice(4)) return false;
    uni.push(String.fromCodePoint(...cps));
    idn = true;
  }
  if (!idn) return true;
  try { return new URL("https://" + uni.join(".") + "/").hostname === host; } catch { return false; }
}

/** A URL's canonical https origin and request target (S5), or null: https only; no userinfo; the default port only;
 *  a name, never an IP literal (any form: the URL parser turns decimal, octal and hex hosts into dotted ones, which are
 *  then refused as literals); no trailing dot; no invalid escape, control or bidi character anywhere; the fragment is
 *  never sent. `target` is the path and query as serialized (the exact request), kept only by the runner. */
export function canonicalUrl(raw) {
  if (typeof raw !== "string" || raw.length === 0 || raw.length > 4096 || CONTROL_OR_BIDI.test(raw) || /\s/.test(raw) || BAD_ESCAPE.test(raw)) return null;
  let u;
  try { u = new URL(raw); } catch { return null; }
  if (u.protocol !== "https:" || u.username || u.password || u.port !== "") return null;
  const host = u.hostname;
  if (!host || host.endsWith(".") || host.startsWith("[") || net.isIP(host) || !HOST.test(host)) return null;
  // (an all-numeric last label is an IPv4 form the parser left alone: refused)
  if (/^\d+$/.test(host.split(".").pop())) return null;
  if (!hostOk(host)) return null;
  const pathname = u.pathname || "/";
  return { origin: `https://${host}`, host, pathname, target: pathname + u.search, hasQuery: u.search.length > 1 };
}

/** The path a card shows (wire pins, 2): the serialized pathname, ASCII with its escapes kept, at most 200 bytes
 *  without splitting a %HH, then "…". Never the query; display only. */
export function displayPath(pathname) {
  let p = typeof pathname === "string" && pathname.startsWith("/") ? pathname : "/";
  p = p.replace(/[^\x21-\x7e]/g, (c) => encodeURIComponent(c)).replace(/[?#]/g, (c) => encodeURIComponent(c));
  if (p.length <= 200) return p;
  let cut = 200;
  if (p[cut - 1] === "%") cut -= 1;
  else if (p[cut - 2] === "%") cut -= 2;
  return p.slice(0, cut) + "…";
}

/** The model's reason as a card shows it (wire pins, 1): plain text, at most 200 Unicode scalars, controls and bidi
 *  escaped visibly; a fixed one instead if it carries the request's query. Never derived from the URL. */
export function displayReason(reason, query = "") {
  if (typeof reason !== "string") return "";
  // (SEC 2: a request with a query never shows the model's reason, whatever it says; no attempt to spot the query in it)
  if (query.length > 1) return "(not shown for a request with a query)";
  // (escaped visibly, then cut so the whole wire string, its ellipsis included, is at most 200 Unicode scalars, never
  //  inside an escape)
  const pieces = [...reason].map((c) => (CONTROL_OR_BIDI.test(c) ? `\\u{${c.codePointAt(0).toString(16)}}` : c));
  let out = "", n = 0;
  const total = pieces.reduce((a, p) => a + [...p].length, 0);
  if (total <= 200) return pieces.join("");
  for (const p of pieces) {
    const len = [...p].length;
    if (n + len > 199) break;
    out += p;
    n += len;
  }
  return out + "…";
}

export class EgressError extends Error {}

const deadlineError = () => new EgressError("it took longer than 20 seconds");

/** Resolve a name to its addresses, all of them public, or refuse (S1). */
async function resolvePublic(host, { lookup, signal }) {
  const answers = await raceAbort(lookup(host), signal);
  if (!Array.isArray(answers) || answers.length === 0) throw new EgressError(`${host} has no address`);
  if (!answers.every((a) => isPublicAddress(a.address, a.family))) throw new EgressError(`${host} has an address that isn't public, so it isn't contacted`);
  return answers;
}
const defaultLookup = (host) => dns.promises.lookup(host, { all: true, verbatim: true });
function raceAbort(p, signal) {
  if (!signal) return p;
  if (signal.aborted) return Promise.reject(signal.reason ?? deadlineError());
  return new Promise((resolve, reject) => {
    const onAbort = () => reject(signal.reason ?? deadlineError());
    signal.addEventListener("abort", onAbort, { once: true });
    p.then((v) => { signal.removeEventListener("abort", onAbort); resolve(v); }, (e) => { signal.removeEventListener("abort", onAbort); reject(e); });
  });
}

/**
 * One GET through the safe transport. `url` is canonicalUrl()'s result. Options:
 * - `hosts`: for a fixed-host verb, the hosts a redirect may go to; without it, only the same origin;
 * - `accept`: the Accept header; `types`: the allowed media types (lowercase, before ";");
 * - `maxBytes`: the body's cap; `deadline`: an AbortSignal for the whole call (20 s: the caller makes it);
 * - `lookup`, `connectTo` and `tls` (tests only, never reachable from the wire: a resolver, the address the socket
 *   goes to once the resolved ones passed the check, and a test CA).
 * Resolves {status, type, body: Buffer} for a 2xx, {redirect: origin} for a redirect it doesn't follow, {status} for
 * anything else; throws EgressError when a rule refuses it.
 */
export async function safeGet(url, { hosts = null, accept = "*/*", types, maxBytes, signal, lookup = defaultLookup, connectTo = null, tls = {} } = {}) {
  let current = url;
  for (let hop = 0; ; hop++) {
    const answers = await resolvePublic(current.host, { lookup, signal });
    const res = await raceAbort(request(current, connectTo ?? answers[0], { accept, signal, tls }), signal);
    if (res.statusCode >= 300 && res.statusCode < 400 && res.statusCode !== 304) {
      res.destroy();
      const loc = res.headers.location;
      let next = null;
      try { next = typeof loc === "string" ? canonicalUrl(new URL(loc, `${current.origin}${current.target}`).href) : null; } catch { next = null; }
      if (!next) throw new EgressError("it redirected somewhere that can't be fetched");
      const allowed = hosts ? hosts.includes(next.host) : next.origin === url.origin;
      if (!allowed) {
        if (hosts) throw new EgressError(`it redirected outside ${hosts.join(", ")}`);
        return { redirect: next.origin };
      }
      if (hop + 1 > MAX_REDIRECTS) throw new EgressError("too many redirects");
      current = next;
      continue;
    }
    if (res.statusCode < 200 || res.statusCode >= 300) { res.destroy(); return { status: res.statusCode }; }
    const enc = String(res.headers["content-encoding"] ?? "identity").toLowerCase();
    if (enc !== "identity") { res.destroy(); throw new EgressError("it came compressed, which isn't read here"); }
    const type = String(res.headers["content-type"] ?? "").split(";")[0].trim().toLowerCase();
    if (types && !types.includes(type)) { res.destroy(); throw new EgressError(`it is ${type || "of no stated type"}, which isn't read here`); }
    const declared = Number(res.headers["content-length"]);
    if (Number.isFinite(declared) && declared > maxBytes) { res.destroy(); throw new EgressError(`it is ${declared} bytes, over the ${maxBytes} read here`); }
    const body = await raceAbort(readCapped(res, maxBytes), signal);
    return { status: res.statusCode, type, body };
  }
}

function request(url, answer, { accept, signal, tls }) {
  return new Promise((resolve, reject) => {
    const req = https.request({
      host: url.host,
      servername: url.host,
      path: url.target,
      method: "GET",
      headers: { host: url.host, "user-agent": UA, accept, "accept-encoding": "identity" },
      // (a fresh agent: never the global one, so no proxy from the environment, no kept connections)
      agent: new https.Agent({ keepAlive: false, maxSockets: 1 }),
      // (connect to the checked address; TLS and Host still use the name)
      lookup: (_h, opts, cb) => (opts?.all ? cb(null, [{ address: answer.address, family: answer.family }]) : cb(null, answer.address, answer.family)),
      signal,
      ...tls,
    }, resolve);
    req.on("error", (e) => reject(e instanceof EgressError ? e : new EgressError(signal?.aborted ? "it took longer than 20 seconds" : "the connection failed")));
    req.end();
  });
}

function readCapped(res, maxBytes) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let n = 0;
    res.on("data", (c) => {
      n += c.length;
      // (the reason first, then the socket: destroying it fires its error handler at once)
      if (n > maxBytes) { reject(new EgressError(`it is over the ${maxBytes} bytes read here`)); res.destroy(); return; }
      chunks.push(c);
    });
    res.on("end", () => resolve(Buffer.concat(chunks, n)));
    res.on("error", () => reject(new EgressError("the connection failed")));
    res.on("aborted", () => reject(new EgressError("the connection failed")));
  });
}

/** Text, or an EgressError when the bytes aren't text (S4: by the bytes as well as the type): a NUL byte, or invalid UTF-8. */
export function asText(body) {
  if (body.includes(0)) throw new EgressError(`it is binary (${body.length} bytes), which isn't read here`);
  try { return new TextDecoder("utf-8", { fatal: true }).decode(body); } catch { throw new EgressError(`it is binary (${body.length} bytes), which isn't read here`); }
}

/** HTML as plain text (S4): one linear pass, nothing fetched, script and style dropped, at most `maxTags` tags read. */
export function htmlToText(html, maxTags = 50_000) {
  let out = "", i = 0, tags = 0;
  const lower = html.toLowerCase();
  while (i < html.length) {
    const lt = html.indexOf("<", i);
    if (lt < 0) { out += html.slice(i); break; }
    out += html.slice(i, lt);
    if (++tags > maxTags) break;
    const gt = html.indexOf(">", lt + 1);
    if (gt < 0) break;
    const name = /^<\/?\s*([a-z0-9]+)/.exec(lower.slice(lt, Math.min(gt + 1, lt + 40)))?.[1] ?? "";
    if ((name === "script" || name === "style") && lower[lt + 1] !== "/") {
      const close = lower.indexOf(`</${name}`, gt + 1);
      i = close < 0 ? html.length : close;
      continue;
    }
    if (/^(p|div|br|li|tr|h[1-6]|pre|section|article|table|ul|ol)$/.test(name)) out += "\n";
    i = gt + 1;
  }
  const entities = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " " };
  return out
    .replace(/&(amp|lt|gt|quot|apos|nbsp);/g, (_, e) => entities[e])
    .replace(/&#(\d{1,7});/g, (m, d) => { const c = Number(d); return c > 0 && c < 0x110000 ? String.fromCodePoint(c) : m; })
    .replace(/[ \t\r\f\v]+/g, " ")
    .replace(/\n\s*\n\s*/g, "\n\n")
    .trim();
}

/** A deadline over a whole call (S4): an AbortSignal that fires after `ms`, and its cancel. */
export function deadline(ms = 20_000) {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(deadlineError()), ms);
  return { signal: ac.signal, done: () => clearTimeout(t) };
}
