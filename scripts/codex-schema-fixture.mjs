#!/usr/bin/env node
// A test fixture from a Codex's generated schema: only the definitions the contract reaches (the method unions, the
// types read, the items, the values), so the self-test's rows run on real Codex output, small enough to keep.
//   node scripts/codex-schema-fixture.mjs <generated schema dir> <out.json>
import { writeFileSync } from "node:fs";
import { CONTRACT, loadSchemas } from "../lib/codex-selftest.mjs";
const [dir, out] = process.argv.slice(2);
const defs = loadSchemas(dir);
const keep = {};
const visit = (name) => {
  if (name in keep || !(name in defs)) return;
  keep[name] = defs[name];
  for (const m of JSON.stringify(defs[name]).matchAll(/"\$ref":"#\/definitions\/(?:v2\/)?([^"]+)"/g)) visit(m[1]);
};
const roots = ["ClientRequest", "ServerRequest", "ServerNotification", "ThreadItem", ...Object.keys(CONTRACT.responses), ...Object.keys(CONTRACT.answers), ...CONTRACT.values.map((v) => v.type)];
roots.forEach(visit);
writeFileSync(out, JSON.stringify({ comment: `Definitions from \`codex app-server generate-json-schema --experimental\`, reduced by scripts/codex-schema-fixture.mjs`, definitions: keep }) + "\n");
console.log(Object.keys(keep).length, "definitions");
