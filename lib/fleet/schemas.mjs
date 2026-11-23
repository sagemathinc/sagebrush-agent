// The fleet schema set from disk (schema/fleet/), installed into the core's loader when this module loads.

import { readFileSync } from "node:fs";
import { bodyValidator, fleetSchema, reasonNames, useSchemas } from "./core/schemas.mjs";

const load = (f) => JSON.parse(readFileSync(new URL(`../../schema/fleet/${f}`, import.meta.url), "utf8"));
useSchemas(load);

export const FLEET_SCHEMA = fleetSchema();
export const REASONS = reasonNames();
export { bodyValidator };
