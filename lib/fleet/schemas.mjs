// The fleet schema set, loaded once (schema/fleet/fleet.schema.json, reasons.json), and a validator per body type.

import { readFileSync } from "node:fs";
import { compile } from "./schema.mjs";

const load = (f) => JSON.parse(readFileSync(new URL(`../../schema/fleet/${f}`, import.meta.url), "utf8"));
export const FLEET_SCHEMA = load("fleet.schema.json");
export const REASONS = Object.freeze(load("reasons.json").reasons.map((r) => r.name));

const cache = new Map();
/** The validator for one $defs entry (a body type such as "host-grant"). */
export function bodyValidator(name) {
  if (!Object.hasOwn(FLEET_SCHEMA.$defs, name)) throw new Error(`no fleet schema ${name}`);
  if (!cache.has(name)) cache.set(name, compile({ $defs: FLEET_SCHEMA.$defs, $ref: `#/$defs/${name}` }));
  return cache.get(name);
}
