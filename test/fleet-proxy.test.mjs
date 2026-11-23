// The browser lane's proxy (O11 §5, §6 layer 2) end to end on loopback: the gate, the public-address rule and the
// relay together. Upstreams are local servers; the proxy is given a lookup that answers public test addresses and a
// connect that maps each checked public address to its local server, so every row shows which address was connected
// to (always one that was checked) and that refused requests connect to nothing.

import assert from "node:assert/strict";
import { test } from "node:test";
import { createServer as httpServer } from "node:http";
import { createServer as tcpServer, connect as tcpConnect } from "node:net";
import { networkInterfaces } from "node:os";
import { createProxy } from "../lib/fleet/browser/proxy.mjs";
import { accountOrigins, DEFAULT_ACCOUNT_ORIGINS } from "../lib/fleet/browser/urls.mjs";

const session = { username: "u-9f2c", password: "p".repeat(22), origins: accountOrigins(DEFAULT_ACCOUNT_ORIGINS) };
const AUTH = `Proxy-Authorization: Basic ${Buffer.from(`${session.username}:${session.password}`).toString("base64")}`;
const PUBLIC = "93.184.215.14", PUBLIC6 = "2606:2800:220:1::1";

async function setup({ limits, connectHang = false } = {}) {
  // (an http upstream that records requests, and a tcp echo upstream for tunnels)
  const requests = [];
  const http = httpServer((rq, rs) => {
    const chunks = [];
    rq.on("data", (c) => chunks.push(c));
    rq.on("end", () => { requests.push({ method: rq.method, url: rq.url, headers: rq.headers, body: Buffer.concat(chunks).toString() }); rs.end("hello from upstream"); });
  });
  const echo = tcpServer((s) => s.pipe(s));
  // (a raw upstream that records every byte it gets and answers 300 ms after the first)
  const raw = { bytes: Buffer.alloc(0), first: null };
  raw.got = new Promise((r) => { raw.first = r; });
  const rawServer = tcpServer((s) => {
    s.on("data", (c) => { raw.bytes = Buffer.concat([raw.bytes, c]); raw.first(); });
    s.on("error", () => {});
    setTimeout(() => s.end("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"), 300);
  });
  await new Promise((r) => rawServer.listen(0, "127.0.0.1", r));
  await new Promise((r) => http.listen(0, "127.0.0.1", r));
  await new Promise((r) => echo.listen(0, "127.0.0.1", r));
  const ports = { 80: http.address().port, 443: echo.address().port };
  const lookups = [], connects = [], logs = [];
  const table = {
    "example.test": [{ address: PUBLIC, family: 4 }],
    "six.test": [{ address: PUBLIC6, family: 6 }],
    "private.test": [{ address: "10.0.0.5", family: 4 }],
    "mixed.test": [{ address: PUBLIC, family: 4 }, { address: "127.0.0.1", family: 4 }],
    "down.test": [{ address: "93.184.215.15", family: 4 }],
    "raw.test": [{ address: "93.184.215.16", family: 4 }],
  };
  const lookup = async (host) => {
    lookups.push(host);
    if (host === "hang.test") return new Promise(() => {}); // (a lookup that never settles)
    if (host === "late.test") return new Promise((r) => setTimeout(() => r([{ address: PUBLIC, family: 4 }]), 600)); // (settles after the deadline)
    if (host === "slow.test") return new Promise((r) => setTimeout(() => r([{ address: PUBLIC, family: 4 }]), 400)); // (settles after closeAll)
    if (!(host in table)) throw new Error("ENOTFOUND");
    return table[host];
  };
  const connect = ({ host, port }) => {
    connects.push(`${host}:${port}`);
    if (connectHang) return tcpConnect({ host: "10.255.255.1", port: 9 }); // (never answers: a connect timeout)
    if (host === "93.184.215.15") return tcpConnect({ host: "127.0.0.1", port: 1 }); // (refused)
    if (host === "93.184.215.16") return tcpConnect({ host: "127.0.0.1", port: rawServer.address().port });
    return tcpConnect({ host: "127.0.0.1", port: ports[port] });
  };
  const proxy = createProxy({ session, lookup, connect, log: (e) => logs.push(e), limits });
  const port = await proxy.listen();
  const close = async () => { await proxy.close(); await new Promise((r) => http.close(r)); await new Promise((r) => echo.close(r)); rawServer.close(); };
  return { proxy, port, requests, lookups, connects, logs, raw, close };
}

/** Open a client connection to the proxy, send `bytes`, collect everything until it closes (or `until` matches). */
function client(port, bytes, { until, then } = {}) {
  return new Promise((resolve) => {
    const s = tcpConnect(port, "127.0.0.1", () => s.write(bytes));
    let got = Buffer.alloc(0);
    let fired = false;
    s.on("data", (c) => {
      got = Buffer.concat([got, c]);
      if (until && !fired && until.test(got.toString("latin1"))) { fired = true; then?.(s, got); }
    });
    s.on("error", () => {});
    s.on("close", () => resolve(got.toString("latin1")));
  });
}
/** Wait until `cond()` holds (sockets open and close a little later on Windows), or fail after `ms`. */
async function until(cond, what, ms = 5000) {
  for (const end = Date.now() + ms; !cond(); ) {
    if (Date.now() > end) assert.fail(`timed out waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 10));
  }
}
const req = (line, ...headers) => Buffer.from(`${line}\r\n${headers.map((h) => h + "\r\n").join("")}\r\n`, "latin1");

test("proxy: listens on loopback only: the machine's other addresses don't reach it", { timeout: 20000 }, async (t0) => {
  const t = await setup();
  try {
    const reach = (host) => new Promise((resolve) => { const x = tcpConnect(t.port, host, () => { x.destroy(); resolve("connected"); }); x.on("error", () => resolve("refused")); });
    assert.equal(await reach("127.0.0.1"), "connected");
    const other = Object.values(networkInterfaces()).flat().find((i) => i && !i.internal && i.family === "IPv4");
    if (!other) return t0.skip("no non-loopback IPv4 address on this machine");
    assert.equal(await reach(other.address), "refused", other.address);
  } finally { await t.close(); }
});

test("proxy: a CONNECT to a public name: 200, then an opaque tunnel to the checked address", { timeout: 20000 }, async () => {
  const t = await setup();
  try {
    const out = await client(t.port, req("CONNECT example.test:443 HTTP/1.1", "Host: example.test:443", AUTH), {
      until: /200 Connection Established\r\n\r\n/, then: (s) => { s.write("tunnel bytes"); setTimeout(() => s.end(), 200); },
    });
    assert.equal(out, "HTTP/1.1 200 Connection Established\r\n\r\ntunnel bytes");
    assert.deepEqual(t.lookups, ["example.test"]);
    assert.deepEqual(t.connects, [`${PUBLIC}:443`]);
    const six = await client(t.port, req("CONNECT six.test:443 HTTP/1.1", AUTH), { until: /\r\n\r\n/, then: (s) => s.end() });
    assert.match(six, /^HTTP\/1\.1 200/);
    assert.equal(t.connects[1], `${PUBLIC6}:443`);
  } finally { await t.close(); }
});

test("proxy: an http request: exactly the gate's upstream bytes, the response streamed back, then closed", { timeout: 20000 }, async () => {
  const t = await setup();
  try {
    const out = await client(t.port, Buffer.concat([req("POST http://example.test/form?a=1 HTTP/1.1", "Host: example.test", AUTH, "Content-Length: 5", "Proxy-Connection: keep-alive"), Buffer.from("hello")]));
    assert.match(out, /^HTTP\/1\.1 200 OK\r\n/);
    assert.ok(out.endsWith("hello from upstream"));
    assert.equal(t.requests.length, 1);
    const r = t.requests[0];
    assert.deepEqual([r.method, r.url, r.headers.host, r.headers.connection, r.body], ["POST", "/form?a=1", "example.test", "close", "hello"]);
    assert.equal(r.headers["proxy-authorization"], undefined);
    assert.equal(r.headers["proxy-connection"], undefined);
    assert.deepEqual(t.connects, [`${PUBLIC}:80`]);
  } finally { await t.close(); }
});

test("proxy: refusals connect to nothing: credentials, account origins, private and mixed names, pipelining", { timeout: 20000 }, async () => {
  const t = await setup();
  try {
    const cases = [
      [req("CONNECT example.test:443 HTTP/1.1"), /^HTTP\/1\.1 407 /],
      [req("CONNECT claude.ai:443 HTTP/1.1", AUTH), /^HTTP\/1\.1 403 /],
      [req("CONNECT a.chatgpt.com:8443 HTTP/1.1", AUTH), /^HTTP\/1\.1 403 /],
      [req("CONNECT private.test:443 HTTP/1.1", AUTH), /^HTTP\/1\.1 403 /],
      [req("CONNECT mixed.test:443 HTTP/1.1", AUTH), /^HTTP\/1\.1 403 /],
      [req("CONNECT 127.0.0.1:443 HTTP/1.1", AUTH), /^HTTP\/1\.1 403 /],
      [req("CONNECT [::ffff:127.0.0.1]:443 HTTP/1.1", AUTH), /^HTTP\/1\.1 403 /],
      [req("CONNECT 169.254.169.254:80 HTTP/1.1", AUTH), /^HTTP\/1\.1 403 /],
      [req("CONNECT example.test:22 HTTP/1.1", AUTH), /^HTTP\/1\.1 403 /],
      [Buffer.concat([req("GET http://example.test/ HTTP/1.1", "Host: example.test", AUTH), req("GET http://claude.ai/ HTTP/1.1", "Host: claude.ai", AUTH)]), /^HTTP\/1\.1 400 /],
      [Buffer.concat([req("CONNECT example.test:443 HTTP/1.1", AUTH), Buffer.from([0x16, 0x03, 0x01])]), /^HTTP\/1\.1 400 /],
    ];
    for (const [bytes, expect] of cases) assert.match(await client(t.port, bytes), expect, bytes.toString("latin1").split("\r\n")[0]);
    assert.deepEqual(t.connects, [], "nothing connected");
    assert.equal(t.requests.length, 0);
    // (the private and mixed names were looked up once each; literals and gate refusals never)
    assert.deepEqual(t.lookups, ["private.test", "mixed.test"]);
    // (logs: the why, and host names only for refusals; never credentials)
    assert.ok(t.logs.every((e) => e.event === "refused"));
    assert.ok(t.logs.some((e) => e.why === "account" && e.host === "claude.ai"));
    assert.ok(t.logs.some((e) => e.why === "private" && e.host === "private.test"));
    assert.ok(!JSON.stringify(t.logs).includes(session.password) && !JSON.stringify(t.logs).includes("Basic"));
  } finally { await t.close(); }
});

test("proxy: a name that doesn't resolve, or an upstream that refuses, gets 502; one that never answers, 504", { timeout: 20000 }, async () => {
  let t = await setup();
  try {
    assert.match(await client(t.port, req("CONNECT nx.test:443 HTTP/1.1", AUTH)), /^HTTP\/1\.1 502 /);
    assert.deepEqual(t.connects, []);
    assert.match(await client(t.port, req("CONNECT down.test:443 HTTP/1.1", AUTH)), /^HTTP\/1\.1 502 /);
  } finally { await t.close(); }
  t = await setup({ connectHang: true, limits: { upstreamMs: 300 } });
  try {
    assert.match(await client(t.port, req("CONNECT example.test:443 HTTP/1.1", AUTH)), /^HTTP\/1\.1 504 /);
    assert.deepEqual(t.proxy.stats().upstreamTimeouts, { resolve: 0, connect: 1 });
  } finally { await t.close(); }
});

test("proxy: bytes after an http request close both sides, and nothing more goes upstream", { timeout: 20000 }, async () => {
  const t = await setup();
  try {
    const first = req("GET http://raw.test/slow HTTP/1.1", "Host: raw.test", AUTH);
    const second = req("GET http://claude.ai/ HTTP/1.1", "Host: claude.ai", AUTH);
    const out = new Promise((resolve) => {
      const s = tcpConnect(t.port, "127.0.0.1", () => s.write(first));
      let got = "";
      s.on("data", (c) => { got += c.toString("latin1"); });
      s.on("error", () => {});
      s.on("close", () => resolve(got));
      // (once the request is upstream, and before the answer, the client sends a second request)
      t.raw.got.then(() => setTimeout(() => s.write(second), 50));
    });
    await out;
    await new Promise((r) => setTimeout(r, 400));
    assert.equal(t.raw.bytes.toString("latin1"), "GET /slow HTTP/1.1\r\nHost: raw.test\r\nConnection: close\r\n\r\n");
    assert.ok(t.logs.some((e) => e.why === "more than one request"));
  } finally { await t.close(); }
});

test("proxy: a request that never completes is closed with nothing forwarded; the connection cap holds", { timeout: 20000 }, async () => {
  const t = await setup({ limits: { requestMs: 300, connections: 2 } });
  try {
    const start = Date.now();
    const out = await client(t.port, Buffer.from("CONNECT example.test:443 HTTP/1.1\r\n", "latin1"));
    assert.match(out, /^HTTP\/1\.1 408 /);
    assert.ok(Date.now() - start >= 250);
    assert.deepEqual(t.connects, []);
    // (two connections held open; a third is closed at once)
    await until(() => t.proxy.stats().open === 0, "the timed-out connection to close");
    const held = [0, 1].map(() => tcpConnect(t.port, "127.0.0.1"));
    await until(() => t.proxy.stats().open === 2, "both held connections to be accepted");
    const third = await client(t.port, Buffer.from("x"));
    assert.equal(third, "");
    assert.equal(t.proxy.stats().busy, 1);
    for (const h of held) h.destroy();
  } finally { await t.close(); }
});

test("proxy: closeAll ends every open tunnel at once", { timeout: 20000 }, async () => {
  const t = await setup();
  try {
    let closed = false;
    const done = client(t.port, req("CONNECT example.test:443 HTTP/1.1", AUTH), { until: /200 Connection Established/, then: () => { t.proxy.closeAll(); } });
    const out = await done;
    closed = true;
    assert.match(out, /^HTTP\/1\.1 200/);
    assert.ok(closed);
    await until(() => t.proxy.stats().open === 0, "every connection to close");
  } finally { await t.close(); }
});

test("proxy: one deadline spans resolve and connect: a lookup that never settles, or settles late, connects to nothing", { timeout: 20000 }, async () => {
  const t = await setup({ limits: { upstreamMs: 300, connections: 1 } });
  try {
    assert.match(await client(t.port, req("CONNECT hang.test:443 HTTP/1.1", AUTH)), /^HTTP\/1\.1 504 /);
    assert.ok(t.logs.some((e) => e.event === "timeout" && e.stage === "resolve"));
    // (the slot is free again: with a cap of one, the next request goes through)
    await new Promise((r) => setTimeout(r, 50));
    assert.equal(t.proxy.stats().open, 0);
    const next = await client(t.port, req("CONNECT example.test:443 HTTP/1.1", AUTH), { until: /\r\n\r\n/, then: (s) => s.end() });
    assert.match(next, /^HTTP\/1\.1 200/);
    assert.deepEqual(t.connects, [`${PUBLIC}:443`], "only the second request connected");
    // (a lookup that succeeds after the deadline: 504, and no connect even once it settles)
    assert.match(await client(t.port, req("CONNECT late.test:443 HTTP/1.1", AUTH)), /^HTTP\/1\.1 504 /);
    await new Promise((r) => setTimeout(r, 700));
    assert.deepEqual(t.connects, [`${PUBLIC}:443`], "the late answer connected nothing");
    assert.deepEqual(t.proxy.stats().upstreamTimeouts, { resolve: 2, connect: 0 });
    assert.equal(t.proxy.stats().open, 0);
  } finally { await t.close(); }
});

test("proxy: closeAll during a lookup releases the slot and the socket, and the answer that comes later connects nothing", { timeout: 20000 }, async () => {
  const t = await setup({ limits: { upstreamMs: 5000, connections: 1 } });
  try {
    const out = client(t.port, req("CONNECT slow.test:443 HTTP/1.1", AUTH));
    await new Promise((r) => setTimeout(r, 100));
    assert.deepEqual(t.lookups, ["slow.test"]);
    assert.equal(t.proxy.stats().open, 1);
    t.proxy.closeAll();
    assert.equal(await out, "", "the client was closed");
    await new Promise((r) => setTimeout(r, 50));
    assert.equal(t.proxy.stats().open, 0, "the slot is free");
    await new Promise((r) => setTimeout(r, 500));
    assert.deepEqual(t.connects, [], "the lookup settled after closeAll and connected nothing");
    // (and with a cap of one, the freed slot takes the next request)
    const next = await client(t.port, req("CONNECT example.test:443 HTTP/1.1", AUTH), { until: /\r\n\r\n/, then: (s) => s.end() });
    assert.match(next, /^HTTP\/1\.1 200/);
  } finally { await t.close(); }
});
