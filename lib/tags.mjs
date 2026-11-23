// Memory and Autonomous use this identity contract. No persistence or authorization is performed here.
// The page mirrors schema/tags.schema.json byte-for-byte. Names never enter a grant's enabled-ID list.
import { readFileSync } from "node:fs";
import { canon } from "./canon.mjs";

const schema = JSON.parse(readFileSync(new URL("../schema/tags.schema.json", import.meta.url), "utf8"));
export const TAG_LIMITS = Object.freeze({ enabled: schema.$defs.enabled.maxItems, name: schema.$defs.name.maxLength, grantBytes: 4096 });
export const GLOBAL_TAG_NAME = "global";
const idPattern = new RegExp(schema.$defs.id.pattern);
const namePattern = new RegExp(schema.$defs.name.pattern);
const reserved = new Set(schema.$defs.name.not.enum);
const bad = () => { throw new TypeError("invalid tags v1 value"); }; // Never echo an untrusted field.
export const validTagId = (v) => typeof v === "string" && v.length === schema.$defs.id.maxLength && idPattern.test(v);
export const validTagName = (v) => typeof v === "string" && v.length <= TAG_LIMITS.name && namePattern.test(v) && !reserved.has(v);

// canon rejects getters, holes, symbols and non-data objects without invoking their values.
function snapshot(v) {
  const r = canon(v, TAG_LIMITS.grantBytes);
  if (!r.ok) bad();
  return r.value;
}
function keys(v, required) {
  if (!v || typeof v !== "object" || Array.isArray(v) || Object.keys(v).length !== required.length || !required.every((k) => Object.hasOwn(v, k))) bad();
}
export function parseTag(value) {
  const v = snapshot(value);
  keys(v, ["id", "name"]);
  if (!validTagId(v.id) || !validTagName(v.name)) bad();
  return Object.freeze({ id: v.id, name: v.name });
}
export function parseEnabledTags(value) {
  const v = snapshot(value);
  if (!Array.isArray(v) || v.length > TAG_LIMITS.enabled) bad();
  for (let i = 0; i < v.length; i++) if (!validTagId(v[i]) || (i && v[i - 1] >= v[i])) bad();
  return Object.freeze(v);
}
export function parseMemoryGrant(value) {
  const v = snapshot(value);
  keys(v, ["tags"]);
  return Object.freeze({ tags: parseEnabledTags(v.tags) });
}
export function encodeTag(value) { return canon(parseTag(value)).text; }
export function encodeMemoryGrant(value) { return canon(parseMemoryGrant(value)).text; }

// Call on the COMPLETE grant/reload record, not just memory. This only bounds/encodes it;
// the caller still validates its closed enclosing protocol and feature/grant authority.
export function encodeBoundedGrant(value) {
  const r = canon(value, TAG_LIMITS.grantBytes);
  if (!r.ok) bad();
  return r.text;
}
