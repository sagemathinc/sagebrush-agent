// The canonical JSON encoder (lib/fleet/core/canon.mjs, pure: the fleet protocol's signed bytes use it too) and the
// permission digest, which hashes with Node's crypto. The page has its own copy of both; they are checked against
// test/canon-fixtures.json.

import { createHash } from "node:crypto";
import { canon } from "./fleet/core/canon.mjs";

export { canon, jsonBytes, CANON_MAX, CANON_DEPTH } from "./fleet/core/canon.mjs";
export const DIGEST_DOMAIN = "sb-agent-permission/1\n";

// The digest of one permission question: the page computes it from the action it shows, the agent from the action it
// asked about. {child, conversation, request, tool} are strings; input is the action's arguments, held to canon's
// limits itself (the wrapper below adds no depth or size to what the person reviews). The text is canon's form of
// {child, conversation, input, request, tool}: those keys in that (sorted) order.
export function permissionDigest({ child, conversation, request, tool, input }) {
  const c = canon(input);
  if (!c.ok) return null;
  const ids = [child, conversation, request, tool].map((s) => (typeof s === "string" ? canon(s, 1024) : { ok: false }));
  if (!ids.every((r) => r.ok)) return null;
  const [ch, cv, rq, tl] = ids.map((r) => r.text);
  const text = `{"child":${ch},"conversation":${cv},"input":${c.text},"request":${rq},"tool":${tl}}`;
  return createHash("sha256").update(DIGEST_DOMAIN + text, "utf8").digest("base64url");
}
