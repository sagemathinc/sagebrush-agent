// The host config export (lib/agent-log; the transcript-and-context design note r0.8 §7), row 10 (SEC H3): built
// from a closed allowlist, so a sentinel secret in every secret-bearing position of the input never reaches it.
import assert from "node:assert/strict";
import { test } from "node:test";
import { hostConfigExport } from "../lib/agent-log/index.mjs";

const td = new TextDecoder();
const S = "SENTINEL-7f3a9c";
const parsed = (r) => JSON.parse(td.decode(r.bytes));

/** A host's runtime config with the sentinel in EVERY secret-bearing position, beside the fields that are exported. */
function runtime(proxy = `http://user:${S}@proxy.example:3128/?token=${S}`) {
  return {
    host: "host-1",
    name: "the lab box",
    tags: ["gpu", "lab:west"],
    versions: { daemon: "0.9.1", launcher: "0.9.1+build.7", helper: S },
    backup: {
      sources: ["/home/alice/work", "/srv/data"],
      daily_at: "03:00",
      store: { endpoint: `https://${S}.r2.example`, access_key: S, secret_key: S },
      password: S,
    },
    network: {
      proxy: { url: proxy, headers: { "Proxy-Authorization": `Bearer ${S}` } },
      dns: S,
    },
    agents: [{ id: "agent-a", name: "Alice's agent", token: S }, { id: "agent-b", name: "Builder" }],
    private_key: `-----BEGIN PRIVATE KEY-----${S}`,
    token: S,
    unknown_field: S,
    env: { HOME: "/root", SECRET: S, PATH: S },
  };
}

test("row 10: the export is exactly the allowlisted reconstruction, with none of the sentinels", () => {
  const r = hostConfigExport(runtime());
  assert.ok(!td.decode(r.bytes).includes(S), "no sentinel in the export");
  assert.ok(!JSON.stringify(r.notes).includes(S), "nor in its notes");
  assert.deepEqual(parsed(r), {
    v: 1, type: "sb.host-config.v1", host: "host-1",
    name: "the lab box",
    tags: ["gpu", "lab:west"],
    versions: { daemon: "0.9.1", launcher: "0.9.1+build.7" },
    backup: { sources: ["/home/alice/work", "/srv/data"], daily_at: "03:00" },
    network: { proxy: { needs_credential: true } },
    agents: [{ id: "agent-a", name: "Alice's agent" }, { id: "agent-b", name: "Builder" }],
  });
  assert.deepEqual(r.notes, []);
  assert.equal(td.decode(r.bytes).at(-1), "\n");
  assert.equal(td.decode(r.bytes).split("\n").length, 2, "one line");
});

test("row 10: each credential-bearing proxy alone exports { needs_credential: true }", () => {
  for (const proxy of [
    `http://user:${S}@p.example:3128`, `http://${S}@p.example:3128`, `http://:${S}@p.example`, "http://@p.example:3128",
    `http://p.example:3128/?k=${S}`, "http://p.example:3128/?", `https://p.example/?a=1`,
    { url: "http://p.example:3128", headers: { Authorization: `Basic ${S}` } },
    { url: "http://p.example:3128", password: S }, { url: "http://p.example:3128", token: S }, { url: "http://p.example:3128", anything: 1 },
  ]) {
    const r = hostConfigExport({ host: "h", network: { proxy } });
    assert.deepEqual(parsed(r).network, { proxy: { needs_credential: true } }, JSON.stringify(proxy));
    assert.ok(!td.decode(r.bytes).includes(S));
  }
});

test("a proxy without a credential is its scheme, host and port only", () => {
  const cases = [
    ["http://Proxy.Example:3128", { scheme: "http", host: "proxy.example", port: 3128 }],
    ["http://proxy.example:3128/", { scheme: "http", host: "proxy.example", port: 3128 }],
    ["https://p.example", { scheme: "https", host: "p.example", port: 443 }],
    ["http://p.example", { scheme: "http", host: "p.example", port: 80 }],
    ["socks5://10.0.0.2:1080", { scheme: "socks5", host: "10.0.0.2", port: 1080 }],
    ["http://[fd00::1]:8080", { scheme: "http", host: "[fd00::1]", port: 8080 }],
    [{ url: "http://p.example:9" }, { scheme: "http", host: "p.example", port: 9 }],
  ];
  for (const [proxy, want] of cases) assert.deepEqual(parsed(hostConfigExport({ host: "h", network: { proxy } })).network, { proxy: want }, JSON.stringify(proxy));
  // (what doesn't fit is left out, with a note that doesn't echo it)
  for (const proxy of [`ftp://p.example/${S}`, "ftp://p.example:2121", "ws://p.example:8080", "gopher://p.example:7070", "file:///etc/x", `http://p.example/${S}`, `http://p.example#${S}`, "http://p.example:0", "not a url", 5, null, { headers: {} }, { url: 7 },
    `http://p.example/\u0007`]) {
    const r = hostConfigExport({ host: "h", network: { proxy } });
    assert.equal(parsed(r).network, undefined, JSON.stringify(proxy));
    assert.deepEqual(r.notes, [{ field: "network.proxy", rule: "an http, https or socks5 URL: scheme, host and port" }]);
    assert.ok(!td.decode(r.bytes).includes(S) && !JSON.stringify(r.notes).includes(S));
  }
});

test("row 10 control: serializing the runtime config and removing known secrets leaks a sentinel, and the row catches it", () => {
  // (the approach the design forbids: copy everything, then strip the secrets someone thought of)
  const KNOWN = new Set(["password", "token", "private_key", "secret_key", "access_key", "headers"]);
  const strip = (v) => (Array.isArray(v) ? v.map(strip) : v && typeof v === "object" ? Object.fromEntries(Object.entries(v).filter(([k]) => !KNOWN.has(k)).map(([k, x]) => [k, strip(x)])) : v);
  const leaked = new TextEncoder().encode(JSON.stringify(strip(runtime())) + "\n");
  const noSentinel = (bytes) => !td.decode(bytes).includes(S);
  assert.equal(noSentinel(leaked), false, "the control leaks at least one sentinel");
  assert.equal(noSentinel(hostConfigExport(runtime()).bytes), true);
});

test("each field that doesn't fit is left out with its own note, never echoing the value", () => {
  const r = hostConfigExport({
    host: "h",
    name: `x\u0000${S}`,
    tags: ["ok", `bad tag ${S}`],
    versions: { daemon: `1.0 ${S}`, launcher: "2.0" },
    backup: { sources: ["/ok", `relative/${S}`], daily_at: `25:00${S}` },
    agents: [{ id: "a", name: "A" }, { id: `../${S}`, name: "B" }],
  });
  assert.deepEqual(parsed(r), { v: 1, type: "sb.host-config.v1", host: "h", versions: { launcher: "2.0" } });
  assert.deepEqual(r.notes.map((n) => n.field), ["name", "tags", "versions.daemon", "backup.sources", "backup.daily_at", "agents"]);
  assert.ok(!JSON.stringify(r.notes).includes(S));
});

test("the bounds and forms of each field", () => {
  const one = (input) => hostConfigExport({ host: "h", ...input });
  // name
  assert.equal(parsed(one({ name: "n".repeat(128) })).name.length, 128);
  assert.equal(parsed(one({ name: "n".repeat(129) })).name, undefined);
  assert.equal(parsed(one({ name: "" })).name, undefined);
  assert.equal(parsed(one({ name: "tab\there" })).name, undefined);
  assert.equal(parsed(one({ name: "é😀 ok" })).name, "é😀 ok");
  // tags
  assert.equal(parsed(one({ tags: Array.from({ length: 32 }, (_, k) => `t${k}`) })).tags.length, 32);
  assert.equal(parsed(one({ tags: Array.from({ length: 33 }, (_, k) => `t${k}`) })).tags, undefined);
  assert.equal(parsed(one({ tags: ["t".repeat(65)] })).tags, undefined);
  assert.deepEqual(parsed(one({ tags: ["a", "a", "b"] })).tags, ["a", "b"]);
  assert.equal(parsed(one({ tags: "gpu" })).tags, undefined);
  // versions
  assert.equal(parsed(one({ versions: { daemon: "v".repeat(65) } })).versions, undefined);
  assert.deepEqual(parsed(one({ versions: { daemon: "1.2.3-rc.1+x" } })).versions, { daemon: "1.2.3-rc.1+x" });
  // backup
  const paths = (n) => Array.from({ length: n }, (_, k) => `/p/${k}`);
  assert.equal(parsed(one({ backup: { sources: paths(256) } })).backup.sources.length, 256);
  assert.equal(parsed(one({ backup: { sources: paths(257) } })).backup, undefined);
  for (const bad of ["/a//b", "/a/./b", "/a/../b", "/a/", "a", "", "/x\n", `/${"p".repeat(1024)}`]) assert.equal(parsed(one({ backup: { sources: [bad] } })).backup, undefined, bad);
  assert.deepEqual(parsed(one({ backup: { sources: ["/", `/${"p".repeat(1023)}`] } })).backup.sources.length, 2);
  for (const t of ["00:00", "23:59"]) assert.equal(parsed(one({ backup: { daily_at: t } })).backup.daily_at, t);
  for (const t of ["24:00", "3:00", "03:60", "03:00:00"]) assert.equal(parsed(one({ backup: { daily_at: t } })).backup, undefined, t);
  // agents
  const ags = (n) => Array.from({ length: n }, (_, k) => ({ id: `a${k}`, name: `A${k}` }));
  assert.equal(parsed(one({ agents: ags(256) })).agents.length, 256);
  assert.equal(parsed(one({ agents: ags(257) })).agents, undefined);
  assert.equal(parsed(one({ agents: [{ id: "a" }] })).agents, undefined);
  assert.equal(parsed(one({ agents: [{ id: "a", name: "A" }, { id: "a", name: "B" }] })).agents, undefined, "a repeated agent id");
  // (an absent field: no note; an inherited one isn't read)
  assert.deepEqual(one({}).notes, []);
  assert.equal(parsed(hostConfigExport(Object.assign(Object.create({ name: S }), { host: "h" }))).name, undefined);
});

test("the host id is required: without it there is no path", () => {
  for (const bad of [{}, { host: "" }, { host: "a/b" }, { host: `../${S}` }, { host: 5 }, null]) assert.throws(() => hostConfigExport(bad), RangeError);
});
