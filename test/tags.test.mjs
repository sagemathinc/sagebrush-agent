import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync } from "node:fs";
import { validTagId, validTagName, parseTag, parseEnabledTags, parseMemoryGrant, encodeTag, encodeMemoryGrant, encodeBoundedGrant, GLOBAL_TAG_NAME, TAG_LIMITS } from "../lib/tags.mjs";

const ids = Array.from({ length: 17 }, (_, i) => i.toString(16).padStart(32, "0"));
const refuses = (f) => assert.throws(f, /invalid tags v1 value/);
test("opaque IDs and display slugs are separate; global is only an opt-in name", () => {
  assert.equal(validTagId("global"), false);
  assert.equal(validTagId(ids[0].toUpperCase()), true); // all digits: case-independent by accident
  assert.equal(validTagId("a".repeat(31) + "A"), false);
  assert.equal(validTagId("a".repeat(32) + "\n"), false);
  assert.equal(validTagName("global"), true);
  assert.equal(GLOBAL_TAG_NAME, "global");
  assert.deepEqual(parseMemoryGrant({ tags: [] }), { tags: [] });
  refuses(() => parseMemoryGrant({ tags: ["global"] }));
  refuses(() => parseTag({ id: "my-project", name: ids[0] }));
  const original = parseTag({ id: ids[0], name: "global" });
  assert.equal(parseTag({ ...original, name: "renamed" }).id, original.id);
  assert.notEqual(parseTag({ id: ids[1], name: "global" }).id, original.id);
});
test("slug grammar and reserved names are platform-independent", () => {
  for (const name of ["a", "course-1", "a".repeat(32), "global"]) assert.equal(validTagName(name), true);
  for (const name of ["", "a".repeat(33), "../x", "-x", "Upper", "a_b", "é", "x\n", "own", "con", "prn", "aux", "nul", "com1", "lpt9"]) assert.equal(validTagName(name), false, name);
});
test("closed values, sorted unique enabled IDs, no widening by normalization", () => {
  assert.deepEqual(parseEnabledTags(ids.slice(0, 16)), ids.slice(0, 16));
  for (const value of [ids, [ids[1], ids[0]], [ids[0], ids[0]], ["global"], "", [null]]) refuses(() => parseEnabledTags(value));
  for (const value of [{}, { tags: [], global: true }, { tags: [], names: [] }, null]) refuses(() => parseMemoryGrant(value));
  refuses(() => parseTag({ id: ids[0], name: "valid", extra: 1 }));
  let touched = false;
  refuses(() => parseTag({ get id() { touched = true; return ids[0]; }, name: "valid" }));
  assert.equal(touched, false);
  refuses(() => parseEnabledTags(new Array(1)));
  const input = { tags: [ids[0]] }, result = parseMemoryGrant(input);
  input.tags[0] = ids[1];
  assert.equal(result.tags[0], ids[0]);
  assert.ok(Object.isFrozen(result) && Object.isFrozen(result.tags));
});
test("canonical encoding and the complete 4 KiB record bound", () => {
  assert.equal(encodeTag({ name: "global", id: ids[0] }), `{"id":"${ids[0]}","name":"global"}`);
  const memory = { tags: ids.slice(0, 16) };
  const encoded = encodeMemoryGrant(memory);
  assert.equal(Buffer.byteLength(encoded), 570);
  assert.ok(Buffer.byteLength(`{"memory":${encoded}}`) < 700);
  const record = { grant: { memory }, padding: "" };
  record.padding = "x".repeat(4096 - Buffer.byteLength(encodeBoundedGrant(record)));
  assert.equal(Buffer.byteLength(encodeBoundedGrant(record)), 4096);
  record.padding += "x";
  refuses(() => encodeBoundedGrant(record));
  record.padding = "é".repeat(4096);
  refuses(() => encodeBoundedGrant(record));
});
test("self-contained schema agrees with runtime bounds and reserved names", () => {
  const s = JSON.parse(readFileSync(new URL("../schema/tags.schema.json", import.meta.url)));
  assert.equal(s.$defs.enabled.maxItems, TAG_LIMITS.enabled);
  assert.equal(s.$defs.name.maxLength, TAG_LIMITS.name);
  assert.equal(s.$defs.tag.additionalProperties, false);
  assert.equal(s.$defs.memory.additionalProperties, false);
  assert.equal(s.$defs.enabled.uniqueItems, true);
  for (const name of s.$defs.name.not.enum) assert.equal(validTagName(name), false);
  assert.ok(!JSON.stringify(s).match(/"\$ref":"(?!#)/));
});
