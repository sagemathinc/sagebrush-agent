// A child for test/source-lock-race.test.mjs: one process that takes the source cache's lock, says so, and holds it
// until told to end (or until it is killed while holding it).
import { existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { SourceCache } from "../../lib/source-cache.mjs";

const [dir, role] = process.argv.slice(2);
if (!dir || !role) process.exit(0); // (run on its own, as a whole-folder node --test does: nothing to do)
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const c = new SourceCache({ root: join(dir, "cache") });
writeFileSync(join(dir, `${role}-trying`), "");
await c.withLock(async () => {
  writeFileSync(join(dir, `${role}-held`), "");
  while (!existsSync(join(dir, `${role}-end`))) await sleep(10);
  writeFileSync(join(dir, `${role}-leaving`), "");
});
writeFileSync(join(dir, `${role}-done`), "");
