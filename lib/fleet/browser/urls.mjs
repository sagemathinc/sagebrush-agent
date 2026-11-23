// Fleet protocol, the browser lane (O11 draft 5 §4.2 named denials, §6): the URL policy for the agent's navigate and
// createTarget (the filter's layer of the account-origin policy; the browser's blocked URLs and the proxy are the
// other two). A URL is allowed only if it's absolute http or https, or exactly "about:blank", and its host isn't an
// account origin or under one. Hosts are compared after the WHATWG URL parser (lowercase, IDNA to A-labels,
// percent-decoding, IPv4 forms) and with one trailing dot removed; a port never matters.

import { domainToASCII } from "node:url";

/** O11 §6's default list (the signed manifest adds the configured WorkOS AuthKit domain or domains). */
export const DEFAULT_ACCOUNT_ORIGINS = Object.freeze([
  "sagebrush.space", "sagebrush.cloud", "api.workos.com",
  "claude.ai", "console.anthropic.com", "chatgpt.com", "auth.openai.com", "platform.openai.com",
]);

/** A host as the policy compares it: the parser's host, without its trailing dot; "" if it isn't a name we can compare. */
export function normalHost(host) {
  if (typeof host !== "string") return "";
  let h = host.endsWith(".") ? host.slice(0, -1) : host;
  if (h.startsWith("[")) return h; // (an IPv6 literal, already canonical from the parser)
  h = domainToASCII(h);
  return h === "" || h.endsWith(".") || h.includes("..") ? "" : h;
}

/** The account-origin list, each entry normalized as a host; an entry that isn't a host name is an error. */
export function accountOrigins(list) {
  return Object.freeze(list.map((o) => {
    const h = normalHost(o);
    if (!h || h.startsWith("[") || /^[0-9.]+$/.test(h)) throw new Error("an account origin must be a host name");
    return h;
  }));
}

/** The account origin `host` (already normalHost'd) is, or is under; null if none. The one check every layer uses. */
export function accountOriginOf(host, origins) {
  for (const o of origins) if (host === o || host.endsWith(`.${o}`)) return o;
  return null;
}

/**
 * Check a URL the agent asked to open. Returns { ok: true, url } (the parser's serialization, which is what goes to
 * Chrome), or { ok: false, why } with why "scheme" (not http(s), not exactly about:blank, or unparseable), "host"
 * (a host the policy can't compare) or "account", with `origin` the matched list entry.
 */
export function checkUrl(text, origins) {
  if (text === "about:blank") return { ok: true, url: text };
  let u;
  try { u = new URL(text); } catch { return { ok: false, why: "scheme" }; }
  if (u.protocol !== "http:" && u.protocol !== "https:") return { ok: false, why: "scheme" };
  const h = normalHost(u.hostname);
  if (!h) return { ok: false, why: "host" };
  const o = accountOriginOf(h, origins);
  return o === null ? { ok: true, url: u.href } : { ok: false, why: "account", origin: o };
}
