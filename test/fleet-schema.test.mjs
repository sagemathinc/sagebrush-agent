// The fleet protocol's closed schema validator (lib/fleet/schema.mjs): every implemented keyword, refusal of any
// other keyword at load time, and agent #23's tags schema compiled and checked with it.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { compile, FleetError, newId, FREEZE } from "../lib/fleet/index.mjs";

const bad = (fn) => { try { fn(); } catch (e) { if (e instanceof FleetError) return e.code; throw e; } return "ok"; };

test("closed validator: object shape, types, enum/const, pattern, lengths in code points, numbers, arrays", () => {
  const v = compile({
    type: "object", additionalProperties: false, required: ["a", "b"],
    properties: {
      a: { type: "string", pattern: "^[a-z]+$", minLength: 1, maxLength: 3 },
      b: { type: "integer", minimum: 0, maximum: 10 },
      c: { enum: ["x", "y"] }, d: { const: true },
      e: { type: "array", minItems: 1, maxItems: 2, uniqueItems: true, items: { type: "string" } },
      f: { type: "string", maxLength: 2 },
      g: { type: "array", prefixItems: [{ type: "integer" }], items: false },
    },
  });
  assert.equal(v({ a: "ab", b: 3 }), true);
  assert.equal(v({ a: "ab", b: 0, c: "y", d: true, e: ["q", "r"], f: "😀😀", g: [1] }), true, "two code points");
  for (const x of [{ a: "ab" }, { a: "AB", b: 1 }, { a: "abcd", b: 1 }, { a: "", b: 1 }, { a: "a", b: 11 }, { a: "a", b: -1 },
    { a: "a", b: 1.5 }, { a: "a", b: "1" }, { a: "a", b: 1, c: "z" }, { a: "a", b: 1, d: false }, { a: "a", b: 1, e: [] },
    { a: "a", b: 1, e: ["q", "q"] }, { a: "a", b: 1, e: ["q", 1] }, { a: "a", b: 1, f: "😀😀😀" }, { a: "a", b: 1, g: [1, 2] },
    { a: "a", b: 1, g: ["x"] }, { a: "a", b: 1, z: 1 }, null, [], "s"])
    assert.equal(bad(() => v(x)), "bad_form", JSON.stringify(x));
});

test("closed validator: $ref, oneOf (exactly one), not", () => {
  const v = compile({
    $defs: { id: { type: "string", pattern: "^[a-z2-7]{25}[aeimquy4]$" }, n: { type: "integer" } },
    oneOf: [{ $ref: "#/$defs/id" }, { $ref: "#/$defs/n" }],
    not: { const: 0 },
  });
  assert.equal(v(newId()), true);
  assert.equal(v(5), true);
  assert.equal(bad(() => v(0)), "bad_form");
  assert.equal(bad(() => v("nope")), "bad_form");
  const both = compile({ oneOf: [{ type: "integer" }, { minimum: 0 }] });
  assert.equal(bad(() => both(3)), "bad_form", "matches two");
});

test("closed validator: an unimplemented keyword, an open object or an outside ref refuses the schema itself", () => {
  for (const s of [{ format: "email" }, { type: "object", additionalProperties: true }, { $ref: "https://x/y" },
    { type: "float" }, { type: ["integer", "null"] }, { anyOf: [] }, { patternProperties: {} }, { properties: { a: { dependentRequired: {} } } }, { $ref: "#/$defs/missing" }])
    assert.throws(() => compile(s), /schema/, JSON.stringify(s));
});

test("agent #23's tags schema compiles under the closed validator, and agrees with lib/tags.mjs", async () => {
  const doc = JSON.parse(readFileSync(new URL("../schema/tags.schema.json", import.meta.url), "utf8"));
  const v = compile(doc);
  const { validTagName } = await import("../lib/tags.mjs");
  const id = newId();
  assert.equal(v({ id, name: "course-1" }), true);
  assert.equal(v({ tags: [] }), true);
  for (const name of ["own", "con", "Upper", "-x", "a".repeat(33), "lpt9"]) {
    assert.equal(bad(() => v({ id, name })), "bad_form", name);
    assert.equal(validTagName(name), false);
  }
  assert.equal(FREEZE.revision, "r2.5");
});

test("closed validator: number is any finite number, integers included; integer is unchanged", () => {
  const num = compile({ type: "number" });
  for (const v of [0, -0, 1.5, -100000, 2 ** 53]) assert.equal(bad(() => num(v)), "ok", String(v));
  for (const v of ["1", null, NaN, Infinity, -Infinity]) assert.equal(bad(() => num(v)), "bad_form", String(v)); // (NaN and Infinity built in JS: JSON can't carry them)
  const scale = compile({ type: "number", minimum: 0.1, maximum: 3 });
  for (const v of [0.1, 1, 2.5, 3]) assert.equal(bad(() => scale(v)), "ok", String(v));
  for (const v of [0.09999, 0, 3.0001, -1]) assert.equal(bad(() => scale(v)), "bad_form", String(v));
  const int = compile({ type: "integer" });
  assert.equal(bad(() => int(1.5)), "bad_form");
  assert.equal(bad(() => int(2 ** 53)), "bad_form"); // (not a safe integer, as before)
  assert.equal(bad(() => int(7)), "ok");
});

test("signed fleet bodies stay integer-only: fleet.schema.json has no number type anywhere", () => {
  const doc = JSON.parse(readFileSync(new URL("../schema/fleet/fleet.schema.json", import.meta.url), "utf8"));
  const found = [];
  const walk = (v, at) => {
    if (Array.isArray(v)) v.forEach((x, i) => walk(x, `${at}/${i}`));
    else if (v && typeof v === "object") for (const [k, x] of Object.entries(v)) { if (k === "type" && (x === "number" || (Array.isArray(x) && x.includes("number")))) found.push(at); walk(x, `${at}/${k}`); }
  };
  walk(doc, "#");
  assert.deepEqual(found, []);
});

test("closed validator: enum, const and uniqueItems compare numbers by value; a non-canonical enum or const member refuses the schema", () => {
  assert.equal(bad(() => compile({ type: "number", const: 2 })(2.5)), "bad_form");
  assert.equal(bad(() => compile({ type: "number", enum: [1, 2] })(1.5)), "bad_form");
  assert.equal(bad(() => compile({ type: "number", enum: [1, 2] })(2)), "ok");
  for (const s of [{ type: "number", const: 1.5 }, { type: "number", enum: [0.5] }, { enum: [1, 0.5] }, { const: { a: 1.5 } }])
    assert.throws(() => compile(s), /enum\/const values must be canonical/, JSON.stringify(s));
  const uniq = compile({ type: "array", items: { type: "number" }, uniqueItems: true });
  assert.equal(bad(() => uniq([1.5, 2.5])), "ok");
  assert.equal(bad(() => uniq([1.5, 1.5])), "bad_form");
  assert.equal(bad(() => uniq([0, -0])), "bad_form"); // (JSON Schema: -0 equals 0)
  assert.equal(bad(() => uniq([1, 1.5, 2])), "ok");
  const any = compile({ type: "array", uniqueItems: true });
  assert.equal(bad(() => any([{ a: 1, b: [2] }, { b: [2], a: 1 }])), "bad_form"); // (key order doesn't matter)
  assert.equal(bad(() => any([{ a: 1 }, { a: "1" }, [1], ["1"], null, "null", true, "true"])), "ok");
});

test("closed validator: uniqueItems stops at canon's depth (32 nested containers) with bad_form, never a stack overflow", () => {
  const any = compile({ type: "array", uniqueItems: true });
  assert.equal(bad(() => any(JSON.parse("[" + "[".repeat(100000) + "0" + "]".repeat(100000) + ",1]"))), "bad_form");
  const nest = (n, x) => { for (let i = 0; i < n; i++) x = i % 2 ? { k: x } : [x]; return x; };
  assert.equal(bad(() => any([nest(32, 0), 1])), "ok");
  assert.equal(bad(() => any([nest(33, 0), 1])), "bad_form");
  assert.equal(bad(() => any([nest(32, 0), nest(32, 0)])), "bad_form"); // (still compared, at the limit)
});
