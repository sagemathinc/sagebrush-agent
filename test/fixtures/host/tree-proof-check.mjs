// The config proof against the real binary's own answers (backup/tests/s3.rs tree_proof_matches_the_restore): the
// argument is a JSON file { snapshot, root, uid, record (the snapshot as the binary's `snapshots` lists it),
// pages: { "<cursor>" | "null": the binary's stdout line },
// dump: current's dump line | null, restored: the restored tree's path }. Prints one line: the proof's answer (the
// config entry, or the error's code) and the restore's (configHash over the restored tree, read by agent-config's
// reader as the restore's config import reads it, or "refused: <why>").
import { readFileSync } from "node:fs";
import { configHash, readConfigTree } from "../../../lib/fleet/host/agent-config.mjs";
import { proveConfig } from "../../../lib/fleet/host/backup-config.mjs";
import { checkRequest, parseResult } from "../../../lib/fleet/host/backup-binary.mjs";

const x = JSON.parse(readFileSync(process.argv[2], "utf8"));
const binary = async (req) => {
  checkRequest(req);
  const line = req.op === "tree" ? x.pages[String(req.cursor ?? null)] : req.op === "dump" ? x.dump : undefined;
  if (typeof line !== "string") return { ok: false, code: "request_invalid" };
  const v = JSON.parse(line);
  delete v.content_bytes_read; // (the test build's counter: never in a release build's result)
  return parseResult(JSON.stringify(v) + "\n", v.ok ? 0 : 1, null, "", req.op);
};
let proof, restored;
try { proof = await proveConfig("x", x.snapshot, { binary, record: x.record, root: x.root, uid: x.uid }); } catch (e) { proof = `code:${e.code}`; }
try { restored = configHash(readConfigTree(x.restored, { uid: x.uid })); } catch (e) { restored = `refused: ${e.message}`; }
process.stdout.write(JSON.stringify({ proof, restored }) + "\n");
