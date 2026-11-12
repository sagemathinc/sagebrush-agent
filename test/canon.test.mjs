// canon.mjs against test/canon-fixtures.json (the page's copy runs against the same file), plus what fixtures in JSON
// can't carry: getters, symbols, holes, prototypes, and inputs too large to write down.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { canon, permissionDigest, CANON_MAX, CANON_DEPTH } from "../lib/canon.mjs";

const F = JSON.parse(readFileSync(new URL("./canon-fixtures.json", import.meta.url), "utf8"));

test("canon: every fixture, its text and its digest", () => {
  assert.equal(F.max, CANON_MAX);
  assert.equal(F.depth, CANON_DEPTH);
  for (const c of F.cases) {
    const r = canon(JSON.parse(c.input));
    assert.equal(r.ok, c.ok, `${c.class}: ${c.name}`);
    if (!c.ok) continue;
    assert.equal(r.text, c.canon, `${c.class}: ${c.name}`);
    assert.equal(r.bytes, Buffer.byteLength(c.canon), `${c.class}: ${c.name} (bytes)`);
    assert.equal(permissionDigest({ ...F.ids, input: JSON.parse(c.input) }), c.digest, `${c.class}: ${c.name} (digest)`);
  }
});

test("canon fixtures: every listed class is present, so an edit can't quietly drop one", () => {
  const has = (cls, re) => F.cases.some((c) => c.class === cls && re.test(c.name));
  const need = [
    ["key-order", /astral/], ["key-order", /non-ASCII/], ["key-order", /nested/],
    ["escape", /^quote$/], ["escape", /backslash/], ["escape", /short escapes/], ["escape", /NUL/], ["escape", /DEL/],
    ["surrogate", /lone high/], ["surrogate", /lone low/], ["surrogate", /reversed/],
    ["integer", /^2\^53 - 1$/], ["integer", /^-\(2\^53 - 1\)$/], ["integer", /^2\^53 refused/], ["integer", /^-2\^53 refused/],
    ["refused-value", /fraction refused/], ["refused-value", /-0/], ["refused-value", /Infinity/],
    ["depth", /32 nested.*accepted/], ["depth", /33 nested.*refused/],
    ["size", /exactly 16 KiB accepted/], ["size", /16 KiB \+ 1 refused/], ["size", /crosses the edge/],
  ];
  for (const [cls, re] of need) assert.ok(has(cls, re), `the fixtures lack ${cls} ${re}`);
});

test("canon: values JSON can't carry are refused", () => {
  for (const [v, why] of [
    [undefined, "undefined"], [() => 1, "a function"], [1n, "a bigint"], [Symbol("s"), "a symbol"],
    [new Date(0), "a Date"], [new Map(), "a Map"], [Object.create({ a: 1 }), "an object with another prototype"],
    [{ get a() { return 1; } }, "a getter"], [{ [Symbol("k")]: 1 }, "a symbol key"], [[1, , 3], "an array hole"], // eslint-disable-line no-sparse-arrays
    [Object.defineProperty({}, "h", { value: 1, enumerable: false }), "a hidden property"], [NaN, "NaN"],
  ]) assert.equal(canon(v).ok, false, why);
  assert.equal(canon(Object.create(null)).ok, true, "a null-prototype object is plain");
});

test("canon: a huge input is refused without being copied whole", () => {
  const big = {};
  for (let i = 0; i < 1e5; i++) big["k" + i] = 0;
  assert.equal(canon(big).ok, false);
  assert.equal(canon(new Array(1e6).fill(0)).ok, false);
  assert.equal(canon("y".repeat(10 * 1024 * 1024)).ok, false);
});

test("canon: the snapshot is inert plain data, and later changes to the input don't reach it", () => {
  const input = { url: "https://example.org", list: [1, { a: "b" }] };
  const r = canon(input);
  input.url = "https://elsewhere.example"; input.list[1].a = "changed";
  assert.equal(r.value.url, "https://example.org");
  assert.equal(r.value.list[1].a, "b");
  assert.equal(canon(r.value).text, r.text);
});

test("permissionDigest: each field of the identity changes it; a refused input has none", () => {
  const base = { child: "c1", conversation: "v1", request: "r1", tool: "WebFetch", input: { url: "https://x.example" } };
  const d = permissionDigest(base);
  for (const k of ["child", "conversation", "request", "tool"]) assert.notEqual(permissionDigest({ ...base, [k]: base[k] + "x" }), d, k);
  assert.notEqual(permissionDigest({ ...base, input: { url: "https://y.example" } }), d);
  assert.equal(permissionDigest({ ...base, input: 1.5 }), null);
});

test("jsonBytes: equals JSON.stringify's UTF-8 length, refuses one byte under it, and never copies a huge string", async () => {
  const { jsonBytes } = await import("../lib/canon.mjs");
  let rnd = 999;
  const r = (n) => (rnd = (rnd * 1103515245 + 12345) % 2147483648) % n;
  const chars = ["a", '"', "\\", "\n", "\u0001", "é", "€", "😀", "\ud800", "\udc00"];
  const str = () => Array.from({ length: r(8) }, () => chars[r(chars.length)]).join("");
  const gen = (d) => {
    const k = r(d > 3 ? 5 : 8);
    if (k === 0) return null;
    if (k === 1) return r(2) === 0;
    if (k === 2) return [1.5, -0, NaN, Infinity, 3e21, 7][r(6)];
    if (k === 3) return str();
    if (k === 4) return undefined;
    if (k === 5) return Array.from({ length: r(4) }, () => gen(d + 1));
    const o = {};
    for (let i = r(4); i > 0; i--) o[str()] = gen(d + 1);
    return o;
  };
  for (let i = 0; i < 5000; i++) {
    const v = { jsonrpc: "2.0", params: gen(0) };
    const want = Buffer.byteLength(JSON.stringify(v));
    assert.equal(jsonBytes(v, 1 << 20), want);
    assert.equal(jsonBytes(v, want), want, "exactly at the limit");
    assert.equal(jsonBytes(v, want - 1), -1, "one byte under it");
  }
  assert.equal(jsonBytes({ text: '"'.repeat(7 << 20) }, 4 << 20), -1);
});
