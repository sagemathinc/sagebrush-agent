// Step 4, the safe transport and the network verbs (lib/egress.mjs, lib/netverbs.mjs): the SEC pins S1–S6 and their
// negative rows (S9). A local TLS server with a throwaway certificate for "example.test" stands in for the web; the
// resolver is injected, and `connectTo` sends the socket to it only after the resolved addresses passed the check.
import assert from "node:assert/strict";
import { test, before, after } from "node:test";
import https from "node:https";
import { execFileSync, spawn } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { isPublicAddress, canonicalUrl, displayPath, displayReason, safeGet, asText, htmlToText, EgressError } from "../lib/egress.mjs";
import { repoTarget, CardlessBudget, CARDLESS_CALLS, netVerbs, DOCS_PATHS } from "../lib/netverbs.mjs";

let dir, cert, key, server, port;
const routes = new Map(); // path -> (req, res) => void
const seen = []; // {host, path} of every request the server got
before(async () => {
  dir = mkdtempSync(join(tmpdir(), "step4-tls-"));
  execFileSync("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "2", "-subj", "/CN=example.test", "-addext", "subjectAltName=DNS:example.test", "-keyout", join(dir, "k.pem"), "-out", join(dir, "c.pem")], { stdio: "ignore" });
  cert = readFileSync(join(dir, "c.pem"));
  key = readFileSync(join(dir, "k.pem"));
  server = https.createServer({ cert, key }, (req, res) => {
    seen.push({ host: req.headers.host, path: req.url, ua: req.headers["user-agent"], cookie: req.headers.cookie, auth: req.headers.authorization, enc: req.headers["accept-encoding"] });
    const r = routes.get(req.url.split("?")[0]);
    if (r) return r(req, res);
    res.writeHead(404).end();
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  port = server.address().port;
});
after(() => server?.close());

const PUBLIC = "93.184.216.34";
const lookupPublic = async () => [{ address: PUBLIC, family: 4 }];
// (the test's transport: example.test resolves to a public address, the socket goes to the local server, and TLS
//  checks the certificate for the name against the throwaway CA)
const T = (extra = {}) => ({ lookup: lookupPublic, connectTo: { address: "127.0.0.1", family: 4 }, tls: { ca: cert, port }, maxBytes: 4096, types: ["text/plain", "text/html", "application/json"], ...extra });
const url = (u) => canonicalUrl(u);
const text = (body, type = "text/plain", headers = {}) => (req, res) => { res.writeHead(200, { "content-type": type, ...headers }); res.end(body); };

test("egress: every special-use address family is refused; public ones pass (S1)", () => {
  const bad = ["0.0.0.0", "10.1.2.3", "100.64.0.1", "127.0.0.1", "169.254.169.254", "172.16.5.4", "192.0.0.8", "192.0.2.1", "192.88.99.1", "192.168.1.1", "198.18.0.1", "198.51.100.7", "203.0.113.9", "224.0.0.1", "240.0.0.1", "255.255.255.255",
    "::", "::1", "::ffff:127.0.0.1", "::ffff:8.8.8.8", "64:ff9b::808:808", "100::1", "2001:db8::1", "2001::1", "2002:c000:0204::1", "fc00::1", "fd12::1", "fe80::1", "fe80::1%eth0", "fec0::1", "ff02::1", "3fff::1", "not-an-ip", ""];
  for (const a of bad) assert.equal(isPublicAddress(a), false, a);
  for (const a of ["8.8.8.8", "93.184.216.34", "1.1.1.1", "2606:4700:4700::1111", "2a00:1450:4001:80b::200e"]) assert.equal(isPublicAddress(a), true, a);
});

test("egress: the canonical URL: https to a name on the default port, nothing else (S5)", () => {
  assert.deepEqual(url("https://Example.TEST/a/b?q=1#frag"), { origin: "https://example.test", host: "example.test", pathname: "/a/b", target: "/a/b?q=1", hasQuery: true });
  assert.equal(url("https://bücher.example/x").origin, "https://xn--bcher-kva.example", "IDNA ASCII");
  for (const u of ["http://example.test/", "https://user:pw@example.test/", "https://example.test:8443/", "https://example.test:443x/", "https://example.test./", "https://127.0.0.1/", "https://2130706433/", "https://0177.0.0.1/",
    "https://0x7f.1/", "https://[::1]/", "https://1.2.3.4/", "https://example.test/%zz", "https://example.test/a‮b", "https://example.test/a\nb", "https://example.test/a b", "ftp://example.test/", "javascript:alert(1)", "https://localhost/", "https://-bad.example/", "", 5])
    assert.equal(url(u), null, String(u));
});

test("egress: the display path and reason: no query, escapes kept, 200 bytes without splitting %HH; reason fixed if it holds the query (wire pins 1–2)", () => {
  assert.equal(displayPath("/a%20b/c"), "/a%20b/c");
  const long = "/" + "%41".repeat(100);
  const d = displayPath(long);
  assert.ok(d.endsWith("…") && !/%.?…$/.test(d) && d.length <= 201, d);
  assert.equal(displayPath("/x"), "/x");
  assert.equal(displayReason("look up the docs"), "look up the docs");
  // (SEC 2: any query drops the reason, whatever it says: encoded, decoded, value only, another case)
  for (const reason of ["send token=hunter2 please", "hunter2", "hunter 2", "HUNTER2", "unrelated"]) for (const q of ["?token=hunter2&x=1", "?x=hunter2", "?q=hunter%202", "?a"])
    assert.equal(displayReason(reason, q), "(not shown for a request with a query)", `${reason} ${q}`);
  assert.equal(displayReason("read it", ""), "read it");
  assert.equal(displayReason("read it", "?"), "read it", "an empty query is none");
  for (const r of ["x".repeat(201), "x".repeat(198) + "\u202e", "é".repeat(300), "\u202e".repeat(60)]) assert.ok([...displayReason(r)].length <= 200, `≤200 scalars, ellipsis included: ${[...displayReason(r)].length}`);
  assert.equal(displayReason("a‮b\u0000c"), "a\\u{202e}b\\u{0}c");
  assert.equal([...displayReason("é".repeat(300))].length, 200, "≤200 scalars with its ellipsis (the page admits at most 200)");
});

test("egress: a name with any non-public answer is refused, with no connection made (mixed DNS answers, S1)", async () => {
  const n = seen.length;
  await assert.rejects(safeGet(url("https://example.test/x"), T({ lookup: async () => [{ address: PUBLIC, family: 4 }, { address: "10.0.0.1", family: 4 }] })), (e) => e instanceof EgressError && /isn't public/.test(e.message));
  await assert.rejects(safeGet(url("https://example.test/x"), T({ lookup: async () => [{ address: "::ffff:127.0.0.1", family: 6 }] })), EgressError);
  assert.equal(seen.length, n, "nothing reached the server");
});

test("egress: the socket goes to the checked address while TLS checks the name; a certificate for another name fails (S1)", async () => {
  routes.set("/hello", text("hi"));
  const r = await safeGet(url("https://example.test/hello"), T());
  assert.equal(asText(r.body), "hi");
  const last = seen.at(-1);
  assert.equal(last.host, "example.test");
  assert.equal(last.enc, "identity");
  assert.ok(last.ua.startsWith("sagebrush-agent") && !last.cookie && !last.auth, "fixed headers only, no credentials");
  await assert.rejects(safeGet(url("https://other.test/hello"), T()), EgressError, "a certificate for example.test doesn't serve other.test");
});

test("egress: HTTP(S)_PROXY and NODE_USE_ENV_PROXY in the environment are never honored (S1)", async () => {
  routes.set("/proxy", text("direct"));
  const script = `
    import { safeGet, canonicalUrl } from ${JSON.stringify(new URL("../lib/egress.mjs", import.meta.url).href)};
    const r = await safeGet(canonicalUrl("https://example.test/proxy"), { lookup: async () => [{ address: "93.184.216.34", family: 4 }], connectTo: { address: "127.0.0.1", family: 4 }, tls: { ca: ${JSON.stringify(cert.toString())}, port: ${port} }, maxBytes: 100 });
    process.stdout.write(Buffer.from(r.body).toString());`;
  const f = join(dir, "proxy.mjs");
  writeFileSync(f, script);
  // (asynchronously: this process serves the request)
  const child = spawn(process.execPath, [f], { env: { ...process.env, HTTPS_PROXY: "http://127.0.0.1:9", HTTP_PROXY: "http://127.0.0.1:9", ALL_PROXY: "http://127.0.0.1:9", NODE_USE_ENV_PROXY: "1" } });
  let out = "", err = "";
  child.stdout.on("data", (d) => (out += d));
  child.stderr.on("data", (d) => (err += d));
  await new Promise((r) => child.on("close", r));
  assert.equal(out, "direct", err);
});

test("egress: redirects: same origin followed (at most 3), another origin never contacted and returned as its origin alone (S2)", async () => {
  routes.set("/r1", (q, s) => { s.writeHead(302, { location: "/r2" }); s.end(); });
  routes.set("/r2", text("arrived"));
  assert.equal(asText((await safeGet(url("https://example.test/r1"), T())).body), "arrived");
  for (let i = 0; i < 5; i++) routes.set(`/loop${i}`, (q, s) => { s.writeHead(302, { location: `/loop${i + 1}` }); s.end(); });
  await assert.rejects(safeGet(url("https://example.test/loop0"), T()), /too many redirects/);
  routes.set("/away", (q, s) => { s.writeHead(301, { location: "https://elsewhere.example/secret/path?token=hunter2" }); s.end(); });
  const n = seen.length;
  const r = await safeGet(url("https://example.test/away"), T());
  assert.deepEqual(r, { redirect: "https://elsewhere.example" }, "the new origin alone, never its path or query");
  assert.equal(seen.length, n + 1, "the other origin wasn't contacted");
  await assert.rejects(safeGet(url("https://example.test/away"), T({ hosts: ["example.test"] })), /redirected outside example.test/, "a fixed-host verb never leaves its hosts");
});

test("egress: caps: a declared or streamed body over the cap, compression, a type not allowed, binary bytes; the deadline (S4)", async () => {
  routes.set("/big", text("x".repeat(5000)));
  await assert.rejects(safeGet(url("https://example.test/big"), T()), /over the 4096/);
  routes.set("/stream", (q, s) => { s.writeHead(200, { "content-type": "text/plain" }); for (let i = 0; i < 10; i++) s.write("y".repeat(1000)); s.end(); });
  await assert.rejects(safeGet(url("https://example.test/stream"), T()), /over the 4096/);
  routes.set("/gz", text("zz", "text/plain", { "content-encoding": "gzip" }));
  await assert.rejects(safeGet(url("https://example.test/gz"), T()), /compressed/);
  routes.set("/img", text("PNG", "image/png"));
  await assert.rejects(safeGet(url("https://example.test/img"), T()), /isn't read here/);
  assert.throws(() => asText(Buffer.from([0x61, 0x00, 0x62])), /binary/);
  assert.throws(() => asText(Buffer.from([0xff, 0xfe, 0x41])), /binary/);
  routes.set("/slow", (q, s) => { s.writeHead(200, { "content-type": "text/plain" }); s.write("a"); });
  const ac = new AbortController();
  setTimeout(() => ac.abort(new EgressError("it took longer than 20 seconds")), 300);
  await assert.rejects(safeGet(url("https://example.test/slow"), T({ signal: ac.signal })), /longer than/);
});

test("egress: HTML as text: script and style dropped, nothing fetched, bounded work on hostile input (S4)", () => {
  assert.equal(htmlToText('<p>Hello <b>world</b></p><script>fetch("x")</script><style>p{}</style><img src="https://t.example/i.png">&amp; more'), "Hello world\n& more");
  const bomb = "<div>".repeat(200000) + "end";
  const t0 = Date.now();
  htmlToText(bomb);
  assert.ok(Date.now() - t0 < 2000, "linear, and cut at the tag cap");
});

test("egress: repo verbs' grammar: owner, repo, ref, path; a ref's slash can't be read as path (S3)", () => {
  const ok = repoTarget({ owner: "sagemathinc", repo: "sagebrush", ref: "feature/x", path: "docs/a b.md" });
  assert.equal(ok.url.target, "/repos/sagemathinc/sagebrush/contents/docs/a%20b.md?ref=feature%2Fx");
  assert.equal(ok.url.host, "api.github.com");
  for (const a of [{ owner: "-x", repo: "r", path: "a" }, { owner: "o", repo: "..", path: "a" }, { owner: "o", repo: "r", path: "/abs" }, { owner: "o", repo: "r", path: "a/../b" }, { owner: "o", repo: "r", path: "a/./b" },
    { owner: "o", repo: "r", path: "a//b" }, { owner: "o", repo: "r", path: "a\u0000b" }, { owner: "o", repo: "r", ref: "../x", path: "a" }, { owner: "o", repo: "r", ref: "a b", path: "a" }, { owner: "o", repo: "r", path: Array(33).fill("a").join("/") }, { owner: "o", repo: "r" }])
    assert.ok(repoTarget(a).refused, JSON.stringify(a));
  assert.ok(!repoTarget({ owner: "o", repo: "r" }, { list: true }).refused, "a listing of the top needs no path");
});

test("egress: the cardless verbs' per-turn budget: calls and outbound bytes; the 10-call scenario fits (S3)", () => {
  const b = new CardlessBudget();
  for (let i = 0; i < 10; i++) assert.ok(b.take("sagemathinc/sagebrush//docs/file" + i + ".md"));
  const c = new CardlessBudget();
  let n = 0;
  while (c.take("o/r//p")) n++;
  assert.equal(n, CARDLESS_CALLS);
  const d = new CardlessBudget();
  assert.ok(!d.take("x".repeat(17 * 1024)), "a single choice over the byte budget");
});

test("egress: repo_read and repo_list: fixed-shape results only, labeled untrusted outside the content", async () => {
  const fake = (body) => async () => ({ status: 200, type: "application/json", body: Buffer.from(JSON.stringify(body)) });
  const v = (body) => netVerbs({ budget: new CardlessBudget(), get: fake(body) });
  const file = await v({ type: "file", encoding: "base64", size: 5, content: Buffer.from("hello").toString("base64") }).repo_read({ owner: "o", repo: "r", path: "a.md" });
  assert.equal(file.content.length, 2);
  assert.match(file.content[0].text, /^Untrusted content from https:\/\/github\.com/);
  assert.equal(file.content[1].text, "hello");
  const list = await v([{ name: "a", type: "file", size: 3, sha: "x", url: "https://evil", download_url: "https://evil/dl", target: "/etc", submodule_git_url: "git://x" }, { name: "s", type: "symlink", size: 0, target: "../../x" }]).repo_list({ owner: "o", repo: "r" });
  assert.deepEqual(JSON.parse(list.content[1].text), { entries: [{ name: "a", type: "file", size: 3 }, { name: "s", type: "symlink", size: 0 }] }, "name, type and size only");
  assert.ok(!list.content[1].text.includes("evil") && !list.content[1].text.includes("/etc"));
  assert.ok((await v([]).repo_read({ owner: "o", repo: "r", path: "dir" })).isError, "a directory to repo_read");
  assert.ok((await v({ type: "file", content: "" }).repo_list({ owner: "o", repo: "r", path: "a" })).isError, "a file to repo_list");
  assert.ok((await v({ type: "symlink", target: "x" }).repo_read({ owner: "o", repo: "r", path: "l" })).isError, "a symlink");
  assert.ok((await v({ type: "submodule" }).repo_read({ owner: "o", repo: "r", path: "m" })).isError, "a submodule");
  assert.ok((await v({ type: "file", encoding: "base64", size: 3, content: Buffer.from([0x50, 0x00, 0x47]).toString("base64") }).repo_read({ owner: "o", repo: "r", path: "x.png" })).isError, "binary by its bytes");
  assert.ok((await v({ type: "file", encoding: "base64", size: 2_000_000, content: "" }).repo_read({ owner: "o", repo: "r", path: "big" })).isError, "over 1 MiB");
});

test("egress: sagebrush_docs: only the allowlist, only sagebrush.space, never a redirect elsewhere", async () => {
  const calls = [];
  const get = async (u, o) => { calls.push({ u, o }); return { status: 200, type: "text/markdown", body: Buffer.from("# doc") }; };
  const v = netVerbs({ budget: new CardlessBudget(), get });
  assert.ok((await v.sagebrush_docs({ path: "/version.json" })).isError);
  assert.ok((await v.sagebrush_docs({ path: "https://evil.example/llms.txt" })).isError);
  assert.equal(calls.length, 0, "refused before any request");
  for (const p of DOCS_PATHS) {
    const r = await v.sagebrush_docs({ path: p });
    assert.equal(r.content[1].text, "# doc");
  }
  assert.ok(calls.every(({ u, o }) => u.origin === "https://sagebrush.space" && JSON.stringify(o.hosts) === '["sagebrush.space"]'));
  assert.deepEqual(DOCS_PATHS, ["/llms.txt", "/board-format.md", "/board-host-protocol.md", "/capabilities.md", "/agents/connect.md", "/atlas/llms.txt"]);
});

test("egress: web_fetch through the transport: HTML as text, labeled with its origin; a cross-origin redirect said as its origin alone", async () => {
  routes.set("/page", text("<h1>Title</h1><p>Body</p>", "text/html"));
  const get = (u, o) => safeGet(u, { ...o, ...T({ maxBytes: o.maxBytes, types: o.types }) });
  const v = netVerbs({ budget: new CardlessBudget(), get });
  const r = await v.web_fetch({ url: "https://example.test/page?x=1" });
  assert.match(r.content[0].text, /^Untrusted content from https:\/\/example\.test\./);
  assert.equal(r.content[1].text, "Title\n\nBody");
  const red = await v.web_fetch({ url: "https://example.test/away" });
  assert.equal(red.content[0].text, "It redirected to https://elsewhere.example, another site: fetch a URL there to ask for it.");
  assert.ok(!JSON.stringify(red).includes("hunter2") && !JSON.stringify(red).includes("/secret"));
});

test("egress: A-labels as the page takes them: decode, encode back to itself, round-trip; other ??-- labels reserved (SEC 5)", () => {
  const hosts = { "xn--bcher-kva.com": true, "xn--bcher-kvaa.com": true, "xn--ls8h.la": true, "xn--bcher-kva.xn--p1ai": true, "github.com": true, "xn--a.com": false, "xn--abc.com": false, "xn--zz.com": false, "xn--.com": false, "ab--c.com": false };
  for (const [h, ok] of Object.entries(hosts)) assert.equal(!!canonicalUrl(`https://${h}/`), ok, h);
});
