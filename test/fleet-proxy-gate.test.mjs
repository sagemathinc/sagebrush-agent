// The browser lane's proxy gate (O11 §5, §6 layer 2, and the Nov 23 ruling (d): the proxy's CONNECT/Host denial is the
// mandatory account-origin layer for workers). Every row is a request head as Chrome (or anything else on the machine)
// could send it, and the gate's decision before any name is resolved.

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseHead, decide, headEnd, authorized, accountOf, refusalBytes, LIMITS } from "../lib/fleet/browser/proxy-gate.mjs";
import { accountOrigins, DEFAULT_ACCOUNT_ORIGINS } from "../lib/fleet/browser/urls.mjs";

const session = { username: "u-9f2c", password: "p".repeat(22), origins: accountOrigins([...DEFAULT_ACCOUNT_ORIGINS, "auth.workos.example"]) };
const AUTH = `Proxy-Authorization: Basic ${Buffer.from(`${session.username}:${session.password}`).toString("base64")}`;
const req = (line, ...headers) => Buffer.from(`${line}\r\n${headers.map((h) => h + "\r\n").join("")}\r\n`, "latin1");
const connect = (authority, ...more) => req(`CONNECT ${authority} HTTP/1.1`, `Host: ${authority}`, AUTH, ...more);
const get = (url, host, ...more) => req(`GET ${url} HTTP/1.1`, `Host: ${host}`, AUTH, ...more);
/** The gate's whole answer for one head: parse, then decide. */
function gate(bytes) {
  const h = parseHead(bytes);
  if (!h.ok) return h;
  return decide(h, session);
}
const why = (bytes) => { const r = gate(bytes); return r.ok ? "ok" : r.why; };

test("proxy gate: an allowed CONNECT and an allowed absolute-form GET give the normalized destination", () => {
  assert.deepEqual(gate(connect("example.com:443")), { ok: true, connect: true, host: "example.com", port: 443 });
  assert.deepEqual(gate(get("http://Example.COM./a?b", "example.com")), { ok: true, connect: false, host: "example.com", port: 80 });
  assert.deepEqual(gate(get("http://example.com:443/", "example.com:443")), { ok: true, connect: false, host: "example.com", port: 443 });
  assert.deepEqual(gate(connect("[2606:4700::1111]:443")), { ok: true, connect: true, host: "[2606:4700::1111]", port: 443 });
  // (IPv4 written another way comes out in its one dotted form, for §5's address check)
  assert.equal(gate(connect("0x01.0x01.0x01.0x01:443")).host, "1.1.1.1");
  assert.equal(gate(connect("16843009:443")).host, "1.1.1.1");
});

test("proxy gate: caller binding: no credentials, wrong ones or another spelling of them get 407", () => {
  const noAuth = (line, ...h) => req(line, ...h);
  for (const bytes of [
    noAuth("CONNECT example.com:443 HTTP/1.1", "Host: example.com:443"),
    noAuth("CONNECT example.com:443 HTTP/1.1", "Host: example.com:443", "Proxy-Authorization: Basic " + Buffer.from(`${session.username}:wrong`).toString("base64")),
    noAuth("CONNECT example.com:443 HTTP/1.1", "Host: example.com:443", AUTH.replace("Basic", "basic")),
    noAuth("CONNECT example.com:443 HTTP/1.1", "Host: example.com:443", AUTH.replace("Basic ", "Basic  ")),
    noAuth("CONNECT example.com:443 HTTP/1.1", "Host: example.com:443", AUTH.replace(/=*$/, "")),
    noAuth("CONNECT example.com:443 HTTP/1.1", "Host: example.com:443", AUTH.replace("Basic", "Bearer")),
    noAuth("CONNECT example.com:443 HTTP/1.1", "Host: example.com:443", "Authorization: " + AUTH.split(": ")[1]),
  ]) {
    const r = gate(bytes);
    assert.equal(r.status, 407, bytes.toString());
  }
  assert.equal(authorized(undefined, session), false);
  assert.ok(refusalBytes(407).toString().includes('Proxy-Authenticate: Basic realm="sagebrush"'));
  // (credentials are checked before the destination: an unauthenticated caller learns nothing about the policy)
  assert.equal(gate(req("CONNECT claude.ai:443 HTTP/1.1", "Host: claude.ai:443")).status, 407);
});

test("proxy gate: account origins and every subdomain are refused at any port, however the host is written", () => {
  for (const [authority, origin] of [
    ["claude.ai:443", "claude.ai"], ["a.claude.ai:443", "claude.ai"], ["x.y.claude.ai:443", "claude.ai"],
    ["CLAUDE.AI:443", "claude.ai"], ["claude.ai.:443", "claude.ai"], ["Claude.AI.:443", "claude.ai"],
    ["claude.ai:8443", "claude.ai"], ["claude.ai:80", "claude.ai"], ["sub.chatgpt.com:443", "chatgpt.com"],
    ["api.workos.com:443", "api.workos.com"], ["x.auth.workos.example:443", "auth.workos.example"],
  ]) {
    const r = gate(connect(authority));
    assert.deepEqual([r.status, r.why, r.origin], [403, "account", origin], authority);
  }
  for (const [url, host] of [["http://claude.ai/", "claude.ai"], ["http://a.claude.ai:8080/x", "a.claude.ai:8080"], ["http://claude.ai./", "claude.ai"]]) {
    const r = gate(get(url, host));
    assert.deepEqual([r.status, r.why, r.origin], [403, "account", "claude.ai"], url);
  }
  // (not under an origin: a lookalike or a suffix match on a label boundary only)
  for (const authority of ["notclaude.ai:443", "claude.ai.example.com:443", "claudeai:443", "xn--clude-dva.ai:443"]) assert.equal(why(connect(authority)), "ok", authority);
  assert.equal(accountOf("[::1]", session.origins), null);
});

test("proxy gate: ports 80 and 443 only", () => {
  for (const p of [22, 25, 8080, 8443, 1, 65535]) assert.equal(why(connect(`example.com:${p}`)), "port", String(p));
  assert.equal(why(get("http://example.com:8080/", "example.com:8080")), "port");
});

test("proxy gate: a destination it can't identify is refused", () => {
  for (const authority of ["example.com", "example.com:", "example.com:443/x", "user@example.com:443", "example.com:443?x", "[::1:443", "example.com:99999", ":443", "exa mple.com:443", "example.com:0x1bb", "a..b:443", "example.com:443#f"]) {
    const h = parseHead(req(`CONNECT ${authority} HTTP/1.1`, AUTH));
    const r = h.ok ? decide(h, session) : h;
    assert.equal(r.ok, false, authority);
    assert.equal(r.status === 400 || r.status === 403, true, authority);
  }
  // (origin-form, https or another scheme in absolute form, user info, no Host or another Host)
  for (const [target, host] of [["/x", "example.com"], ["https://example.com/", "example.com"], ["ftp://example.com/", "example.com"], ["http://u:p@example.com/", "example.com"], ["http://example.com/", "other.com"], ["http://example.com/", "example.com:8080"], ["http://example.com/", "example.com/x"], ["http://example.com/", "u@example.com"]]) {
    assert.equal(gate(get(target, host)).ok, false, `${target} ${host}`);
  }
  assert.equal(gate(req("GET http://example.com/ HTTP/1.1", AUTH)).why, "host mismatch");
  // (a CONNECT whose Host names another place)
  assert.equal(gate(req("CONNECT example.com:443 HTTP/1.1", "Host: claude.ai:443", AUTH)).why, "host mismatch");
  assert.equal(gate(req("CONNECT example.com:443 HTTP/1.1", "Host: example.com:80", AUTH)).why, "host mismatch");
  // (a Host that only resolves to the same name after normalization is the same host)
  assert.equal(gate(req("CONNECT example.com:443 HTTP/1.1", "Host: EXAMPLE.com.:443", AUTH)).ok, true);
  assert.equal(gate(req("CONNECT example.com:443 HTTP/1.1", AUTH)).ok, true, "a CONNECT may omit Host");
});

test("proxy gate: the head is strict HTTP/1.1", () => {
  const ok = connect("example.com:443");
  assert.equal(why(ok), "ok");
  const raw = (s) => Buffer.from(s, "latin1");
  for (const [bytes, expect] of [
    [raw(`CONNECT example.com:443 HTTP/1.0\r\n${AUTH}\r\n\r\n`), "request line"],
    [raw(`CONNECT  example.com:443 HTTP/1.1\r\n${AUTH}\r\n\r\n`), "request line"],
    [raw(`connect example.com:443 HTTP/1.1\r\n${AUTH}\r\n\r\n`), "request line"],
    [raw(`TRACE http://example.com/ HTTP/1.1\r\n${AUTH}\r\n\r\n`), "method"],
    [raw(`CONNECT example.com:443 HTTP/1.1\n${AUTH}\r\n\r\n`), "bare line feed"],
    [raw(`CONNECT example.com:443 HTTP/1.1\r\n${AUTH}\nX: y\r\n\r\n`), "bare line feed"],
    [raw(`CONNECT example.com:443 HTTP/1.1\r\n${AUTH}\r\n folded\r\n\r\n`), "folded header"],
    [raw(`CONNECT example.com:443 HTTP/1.1\r\n${AUTH}\r\nBad Name: x\r\n\r\n`), "header name"],
    [raw(`CONNECT example.com:443 HTTP/1.1\r\n${AUTH}\r\n: x\r\n\r\n`), "header name"],
    [raw(`CONNECT example.com:443 HTTP/1.1\r\n${AUTH}\r\n${AUTH}\r\n\r\n`), "duplicate header"],
    [raw(`CONNECT example.com:443 HTTP/1.1\r\nHost: a.com:443\r\nhost: example.com:443\r\n${AUTH}\r\n\r\n`), "duplicate header"],
    [raw(`POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\n${AUTH}\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n`), "both lengths"],
    [raw(`POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\n${AUTH}\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n`), "duplicate header"],
    [Buffer.concat([raw(`CONNECT example.com:443 HTTP/1.1\r\n${AUTH}\r\nX: `), Buffer.from([0xc3, 0xa9]), raw("\r\n\r\n")]), "not ASCII"],
    [raw(`CONNECT example.com:443 HTTP/1.1\r\n${AUTH}\r\nX: a\u0000b\r\n\r\n`), "not ASCII"],
    [raw(`CONNECT example.com:443 HTTP/1.1\r\n${AUTH}\r\n`), "no end"],
  ]) assert.equal(why(bytes), expect, JSON.stringify(bytes.toString("latin1")));
  // (repeated ordinary headers are joined, not refused)
  assert.equal(why(req("GET http://example.com/ HTTP/1.1", "Host: example.com", AUTH, "Accept: a", "Accept: b")), "ok");
  // (bounds: header count and head size)
  const many = Array.from({ length: LIMITS.headerLines }, (_, i) => `X-${i}: v`);
  assert.equal(why(req("CONNECT example.com:443 HTTP/1.1", AUTH, ...many.slice(1))), "ok");
  assert.equal(gate(req("CONNECT example.com:443 HTTP/1.1", AUTH, ...many)).status, 431);
  assert.equal(gate(req("CONNECT example.com:443 HTTP/1.1", AUTH, `X: ${"a".repeat(LIMITS.headBytes)}`)).status, 431);
});

test("proxy gate: headEnd finds the head's end, and refuses a head that grows past the limit without one", () => {
  const h = connect("example.com:443");
  assert.equal(headEnd(Buffer.concat([h, Buffer.from("tunnel bytes")])), h.length);
  assert.equal(headEnd(h.subarray(0, h.length - 1)), -1);
  assert.equal(headEnd(Buffer.alloc(LIMITS.headBytes - 1, 0x61)), -1);
  assert.equal(headEnd(Buffer.alloc(LIMITS.headBytes, 0x61)), Infinity);
  const late = Buffer.concat([Buffer.alloc(LIMITS.headBytes, 0x61), Buffer.from("\r\n\r\n")]);
  assert.equal(headEnd(late), Infinity);
});

test("proxy gate: refusals are fixed answers, and no refusal echoes the request", () => {
  for (const s of [400, 403, 405, 407, 431]) {
    const t = refusalBytes(s).toString("latin1");
    assert.match(t, new RegExp(`^HTTP/1\\.1 ${s} [A-Za-z ]+\\r\\n`));
    assert.ok(t.endsWith("Content-Length: 0\r\nConnection: close\r\n\r\n"));
  }
  const r = gate(connect("secret-REAL.claude.ai:443"));
  assert.equal(r.why, "account");
  assert.ok(!JSON.stringify(r).includes("REAL"));
});
