// The browser lane's address rule (O11 §5): public means positively global, the IANA special-purpose registries pinned
// as IANA's own CSV files, and a name refused whole if any of its addresses isn't public. The private targets are §9
// test 6's, each with a public control.

import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { SPECIAL, parseAddress, parseCidr, isPublic, resolvePublic, registryBlocks } from "../lib/fleet/browser/addresses.mjs";
import { parseHead, decide } from "../lib/fleet/browser/proxy-gate.mjs";

const root = new URL("..", import.meta.url);
const bytes = (f) => readFileSync(new URL(f, root));

test("addresses: special-addresses.json is exactly the pinned IANA files, compiled, plus §5's three IPv4 blocks", () => {
  assert.equal(SPECIAL.sources.length, 2);
  for (const s of SPECIAL.sources) assert.equal(createHash("sha256").update(bytes(s.file)).digest("hex"), s.sha256, s.file);
  assert.deepEqual(SPECIAL.ipv4, registryBlocks(bytes(SPECIAL.sources[0].file).toString("utf8")));
  assert.deepEqual(SPECIAL.ipv6, registryBlocks(bytes(SPECIAL.sources[1].file).toString("utf8")));
  assert.deepEqual(SPECIAL.ipv4_also, ["0.0.0.0/8", "224.0.0.0/4", "240.0.0.0/4"]);
  // (the rows the compiler must not miss: two blocks in one row, and footnote marks)
  assert.ok(SPECIAL.ipv4.includes("192.0.0.170/32") && SPECIAL.ipv4.includes("192.0.0.171/32"));
  assert.ok(SPECIAL.ipv4.includes("192.0.0.0/24") && SPECIAL.ipv6.includes("2002::/16"));
  for (const b of [...SPECIAL.ipv4, ...SPECIAL.ipv6]) assert.doesNotThrow(() => parseCidr(b), b);
});

test("addresses: §9 test 6's private targets are never public; each has a public control", () => {
  const priv = ["127.0.0.1", "127.255.255.254", "10.0.0.1", "10.255.255.255", "169.254.169.254", "0.0.0.0", "0.1.2.3", "::1", "::", "::ffff:127.0.0.1", "::ffff:8.8.8.8", "64:ff9b::808:808", "64:ff9b:1::1", "2002:c000:0201::1", "2001::1", "2001:0:4136:e378::1", "fc00::1", "fd12:3456::1", "fe80::1", "100.64.0.1", "172.16.0.1", "192.168.1.1", "192.0.2.1", "198.18.0.1", "224.0.0.251", "239.255.255.250", "240.0.0.1", "255.255.255.255", "ff02::1", "2001:db8::1", "3fff::1", "5f00::1", "100::1"];
  for (const a of priv) assert.equal(isPublic(a), false, a);
  for (const a of ["8.8.8.8", "1.1.1.1", "93.184.215.14", "2606:4700::1111", "2001:4860:4860::8888", "2a00:1450::1"]) assert.equal(isPublic(a), true, a);
  // (decimal, octal, hex and short IPv4 forms and the bracketed IPv6 forms reach this module as the gate normalized them)
  const session = { username: "u", password: "p", origins: [] };
  const auth = `Proxy-Authorization: Basic ${Buffer.from("u:p").toString("base64")}`;
  for (const [authority, address] of [["2130706433:443", "127.0.0.1"], ["0177.0.0.1:443", "127.0.0.1"], ["0x7f.1:443", "127.0.0.1"], ["127.1:443", "127.0.0.1"], ["[::ffff:127.0.0.1]:443", "[::ffff:7f00:1]"], ["[0:0:0:0:0:0:0:1]:443", "[::1]"]]) {
    const d = decide(parseHead(Buffer.from(`CONNECT ${authority} HTTP/1.1\r\n${auth}\r\n\r\n`, "latin1")), session);
    assert.equal(d.host, address, authority);
    assert.equal(isPublic(d.host), false, authority);
  }
});

test("addresses: block edges, both sides", () => {
  for (const [a, pub] of [
    ["172.15.255.255", true], ["172.16.0.0", false], ["172.31.255.255", false], ["172.32.0.0", true],
    ["100.63.255.255", true], ["100.64.0.0", false], ["100.127.255.255", false], ["100.128.0.0", true],
    ["223.255.255.255", true], ["224.0.0.0", false], ["9.255.255.255", true], ["11.0.0.0", true],
    ["1fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", false], ["2000::", true], ["3fff:0fff::1", false], ["3fff:1000::1", true],
    ["3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true], ["4000::", false], ["2001:1ff:ffff::1", false], ["2001:200::1", true],
  ]) assert.equal(isPublic(a), pub, a);
});

test("addresses: only one exact address parses: no zone ids, no short or padded IPv4, nothing else", () => {
  for (const bad of ["fe80::1%en0", "1.2.3", "01.2.3.4", "1.2.3.256", "1.2.3.4 ", " 1.2.3.4", "::1::", "", "example.com", "[1.2.3.4]", "[::1", null, 5, "1:2:3:4:5:6:7:8:9"]) {
    assert.equal(parseAddress(bad), null, String(bad));
    assert.equal(isPublic(bad), false, String(bad));
  }
  assert.deepEqual(parseAddress("[::1]"), { v: 6, n: 1n });
  assert.deepEqual(parseAddress("::ffff:1.2.3.4"), { v: 6, n: (0xffffn << 32n) | 0x01020304n });
  assert.deepEqual(parseAddress("1.2.3.4"), { v: 4, n: 0x01020304n });
  for (const bad of ["10.0.0.1/8", "10.0.0.0/33", "::/129", "10.0.0.0", "x/8"]) assert.throws(() => parseCidr(bad), bad);
});

test("addresses: resolvePublic refuses a name whole if any answer isn't public, and returns the address it checked", async () => {
  let calls = 0;
  const dns = (table) => async (host) => { calls++; if (!(host in table)) throw new Error("ENOTFOUND"); return table[host]; };
  const lookup = dns({
    "public.test": [{ address: "93.184.215.14", family: 4 }, { address: "2606:2800:220:1::1", family: 6 }],
    "mixed.test": [{ address: "93.184.215.14", family: 4 }, { address: "10.0.0.5", family: 4 }],
    "mixed6.test": [{ address: "2606:2800:220:1::1", family: 6 }, { address: "::ffff:10.0.0.5", family: 6 }],
    "private.test": [{ address: "127.0.0.1", family: 4 }],
    "empty.test": [],
    "odd.test": [{ address: "93.184.215.14" }, { ip: "1.1.1.1" }],
  });
  assert.deepEqual(await resolvePublic("public.test", lookup), { ok: true, address: "93.184.215.14", family: 4 });
  assert.equal(calls, 1, "one lookup");
  for (const [host, why] of [["mixed.test", "private"], ["mixed6.test", "private"], ["private.test", "private"], ["empty.test", "empty"], ["odd.test", "private"], ["nx.test", "resolve"]]) {
    assert.deepEqual(await resolvePublic(host, lookup), { ok: false, why }, host);
  }
  // (a literal is checked as it is, without a lookup)
  calls = 0;
  assert.deepEqual(await resolvePublic("8.8.8.8", lookup), { ok: true, address: "8.8.8.8", family: 4 });
  assert.deepEqual(await resolvePublic("[2606:4700::1111]", lookup), { ok: true, address: "2606:4700::1111", family: 6 });
  assert.deepEqual(await resolvePublic("[::ffff:7f00:1]", lookup), { ok: false, why: "private" });
  assert.deepEqual(await resolvePublic("169.254.169.254", lookup), { ok: false, why: "private" });
  assert.equal(calls, 0);
});
