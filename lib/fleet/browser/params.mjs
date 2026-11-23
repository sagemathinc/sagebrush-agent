// Fleet protocol, the browser lane (O11 draft 5 §4.2; schema/fleet/browser/o11-cdp.json "commands"): the agent's
// command parameters. Each allowed command's parameters, written in the spec's short form, become one closed JSON
// Schema, compiled by the fleet validator (lib/fleet/schema.mjs). What JSON Schema can't say is checked after it, from
// the same spec: string bounds in UTF-8 bytes, the size and depth of a callFunctionOn argument's value, URLs (left to
// the caller's policy), and every vid, which is mapped to its real id in the command's target.
//
// The short form: a name ("url", "boolean", a defs entry, or "vid:<kind>"), with "?" for optional; or an object with
// "type" and "min"/"max"/"minBytes"/"maxBytes", "enum", "object" (a closed nested object) or "array" (maxItems and
// items), with "optional"; a command's "exactlyOneOf" lists parameters of which exactly one must be present.

import { compile, refuse, FleetError } from "../index.mjs";
import { VID } from "./vids.mjs";

const JSON_VALUE_BYTES = 65536, JSON_VALUE_DEPTH = 32; // (the spec's "json, encoded ≤ 65536 bytes, depth ≤ 32")

/** Compile every command of `spec`: { [method]: { validate, checks, virtual, deadline, maxBytes } }. Throws on a form it doesn't know. */
export function compileCommands(spec) {
  const out = {};
  for (const [method, c] of Object.entries(spec.commands)) {
    const checks = [];
    const schema = objectSchema(spec, c.params ?? {}, [], checks, method);
    if (c.exactlyOneOf) {
      for (const k of c.exactlyOneOf) if (!Object.hasOwn(c.params, k)) throw new Error(`${method}: exactlyOneOf names an unknown parameter`);
      schema.oneOf = c.exactlyOneOf.map((k) => ({ required: [k] }));
    }
    out[method] = Object.freeze({ validate: compile(schema), checks: Object.freeze(checks), virtual: c.virtual === true, deadline: Boolean(c.deadline), maxBytes: c.result.maxBytes });
  }
  return Object.freeze(out);
}

function objectSchema(spec, params, at, checks, where) {
  const properties = {}, required = [];
  for (const [name, form] of Object.entries(params)) {
    const { schema, optional } = fieldSchema(spec, form, [...at, name], checks, `${where}.${name}`);
    properties[name] = schema;
    if (!optional) required.push(name);
  }
  return { type: "object", properties, required, additionalProperties: false };
}

function fieldSchema(spec, form, at, checks, where) {
  if (typeof form === "string" && form.startsWith("json,")) { // (a callFunctionOn argument's value: any JSON, bounded below)
    checks.push({ at, json: true });
    return { schema: true, optional: false };
  }
  if (typeof form === "string") {
    const optional = form.endsWith("?"), name = optional ? form.slice(0, -1) : form;
    if (name === "boolean") return { schema: { type: "boolean" }, optional };
    if (name.startsWith("vid:")) {
      checks.push({ at, vid: name.slice(4) });
      return { schema: { type: "string", pattern: VID.source }, optional };
    }
    const def = spec.defs[name];
    if (!def) throw new Error(`${where}: unknown form ${name}`);
    if (name === "url") checks.push({ at, url: true });
    return { schema: typed(def, at, checks, where), optional };
  }
  if (!form || typeof form !== "object") throw new Error(`${where}: not a form`);
  const optional = form.optional === true;
  if (form.enum) return { schema: { enum: form.enum }, optional };
  if (form.object) return { schema: objectSchema(spec, form.object, at, checks, where), optional };
  if (form.array) {
    const a = form.array, item = [...at, "[]"];
    let items;
    if (a.items?.oneOf) items = { oneOf: a.items.oneOf.map((alt) => objectSchema(spec, alt, item, checks, `${where}[]`)) };
    else items = fieldSchema(spec, a.items, item, checks, `${where}[]`).schema;
    return { schema: { type: "array", maxItems: a.maxItems, items }, optional };
  }
  if (form.type) return { schema: typed(form, at, checks, where), optional };
  throw new Error(`${where}: unknown form`);
}

// A typed leaf: string bounds in bytes go to checks (with the code-point bound they imply), numbers to minimum/maximum.
function typed(def, at, checks, where) {
  const s = { type: def.type };
  if (def.pattern) s.pattern = def.pattern;
  if (def.type === "string") {
    if (def.maxBytes !== undefined) {
      s.maxLength = def.maxBytes; // (a code point is at least one byte: necessary, and the exact bound is below)
      checks.push({ at, minBytes: def.minBytes ?? 0, maxBytes: def.maxBytes });
    } else if (!/^\^.*\{\d+,\d+\}\$$/.test(def.pattern ?? "")) throw new Error(`${where}: a string bounded by neither maxBytes nor an anchored, counted pattern`);
  } else if (def.type === "integer" || def.type === "number") {
    if (def.min === undefined || def.max === undefined) throw new Error(`${where}: a number without both bounds`);
    s.minimum = def.min; s.maximum = def.max;
  } else throw new Error(`${where}: unknown type ${def.type}`);
  return s;
}

/** The values at `at` in `v` (an "[]" segment visits every element), as [holder, key] pairs. */
function* sites(v, at, i = 0) {
  if (i === at.length) return;
  const seg = at[i];
  if (seg === "[]") {
    if (!Array.isArray(v)) return;
    for (let k = 0; k < v.length; k++) {
      if (i === at.length - 1) yield [v, k];
      else yield* sites(v[k], at, i + 1);
    }
    return;
  }
  if (v === null || typeof v !== "object" || Array.isArray(v) || !Object.hasOwn(v, seg)) return;
  if (i === at.length - 1) yield [v, seg];
  else yield* sites(v[seg], at, i + 1);
}

function depth(v) {
  let max = 0;
  const stack = [[v, 1]];
  while (stack.length) {
    const [x, d] = stack.pop();
    if (x === null || typeof x !== "object") continue;
    if (d > max) max = d;
    if (max > JSON_VALUE_DEPTH) return max;
    for (const y of Array.isArray(x) ? x : Object.values(x)) stack.push([y, d + 1]);
  }
  return max;
}

/**
 * Check `params` (parsed JSON) for `method` and return a copy with every vid replaced by its real id, as `vids` knows
 * it in `scope` (the command's target). Throws FleetError: `bad_params` for anything the schema or a bound refuses,
 * `stale_handle` (from vids) for a vid that isn't live there, `handle_budget` once the session is spent. URLs are
 * returned to the caller unchecked, in `urls` (the policy is the filter's).
 */
export function realParams(cmd, params, vids, scope) {
  try { cmd.validate(params); } catch (e) { if (e instanceof FleetError && e.code === "bad_form") refuse("bad_params", "a parameter is missing, extra, of the wrong type or out of range"); throw e; }
  const real = structuredClone(params);
  const urls = [];
  for (const c of cmd.checks) {
    for (const [holder, key] of sites(real, c.at)) {
      const v = holder[key];
      if (c.maxBytes !== undefined) {
        const n = Buffer.byteLength(v, "utf8");
        if (n < c.minBytes || n > c.maxBytes) refuse("bad_params", "a string is out of its byte bounds");
      } else if (c.json) {
        if (Buffer.byteLength(JSON.stringify(v), "utf8") > JSON_VALUE_BYTES || depth(v) > JSON_VALUE_DEPTH) refuse("bad_params", "an argument value is too large or too deep");
      } else if (c.url) urls.push([holder, key]);
      else if (c.vid) holder[key] = vids.in(c.vid, v, c.vid === "pg" ? undefined : scope);
    }
  }
  return { params: real, urls };
}
