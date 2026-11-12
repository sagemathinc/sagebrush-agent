// Writes test/canon-fixtures.json: the cases both copies of canon (this agent's lib/canon.mjs and the page's) must
// agree on. Each accepted case's expected text comes from JSON.stringify of the input with its keys sorted, not from
// canon itself, and its digest from that text. Run: node test/make-canon-fixtures.mjs
import { createHash } from "node:crypto";
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const DOMAIN = "sb-agent-permission/1\n";
const IDS = { child: "child-fixture", conversation: "conversation-fixture", request: "perm-fixture", tool: "WebFetch" };
const sortDeep = (v) => Array.isArray(v) ? v.map(sortDeep)
  : v && typeof v === "object" ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, sortDeep(v[k])])) : v;
const nest = (n) => { let t = "0"; for (let i = 0; i < n; i++) t = `[${t}]`; return t; };

// [class, name, input as JSON text, accepted?]
const cases = [
  ["key-order", "ascii keys sorted", '{"b":1,"a":2,"C":3,"_":4}', true],
  ["key-order", "non-ASCII keys by UTF-16 unit", '{"é":1,"z":2,"€":3,"Z":4}', true],
  ["key-order", "an astral key sorts before U+FFFF (UTF-16 units, not code points)", '{"\\uffff":1,"\\ud83d\\ude00":2,"a":3}', true],
  ["key-order", "nested objects sorted at each level", '{"y":{"b":1,"a":[{"d":1,"c":2}]},"x":null}', true],
  ["key-order", "the empty key first", '{"a":1,"":2}', true],
  ["escape", "quote", '"say \\"hi\\""', true],
  ["escape", "backslash", '"a\\\\b"', true],
  ["escape", "the short escapes b f n r t", '"\\b\\f\\n\\r\\t"', true],
  ["escape", "NUL and U+001F as lower-case \\u00xx", '"\\u0000\\u001f\\u000b"', true],
  ["escape", "DEL, U+2028 and solidus written as they are", '"\\u007f\\u2028/"', true],
  ["escape", "non-ASCII and astral written as they are", '"é€\\ud83d\\ude00"', true],
  ["escape", "escapes inside keys", '{"a\\"b\\n":1}', true],
  ["surrogate", "a lone high surrogate", '"x\\ud800y"', true],
  ["surrogate", "a lone low surrogate", '"\\udc00"', true],
  ["surrogate", "a reversed pair", '"\\ude00\\ud83d"', true],
  ["surrogate", "a high surrogate at the end", '"ab\\udbff"', true],
  ["integer", "2^53 - 1", "9007199254740991", true],
  ["integer", "-(2^53 - 1)", "-9007199254740991", true],
  ["integer", "zero", "0", true],
  ["integer", "2^53 refused", "9007199254740992", false],
  ["integer", "-2^53 refused", "-9007199254740992", false],
  ["refused-value", "a fraction refused", "1.5", false],
  ["refused-value", "-0 refused", "-0", false],
  ["refused-value", "an overflow to Infinity refused", "1e400", false],
  ["refused-value", "a fraction inside an object refused", '{"a":[1,2.5]}', false],
  ["literal", "null, true, false, empty containers", '[null,true,false,[],{}]', true],
  ["depth", "32 nested containers accepted", nest(32), true],
  ["depth", "33 nested containers refused", nest(33), false],
  ["size", "exactly 16 KiB accepted", JSON.stringify("x".repeat(16 * 1024 - 2)), true],
  ["size", "16 KiB + 1 refused", JSON.stringify("x".repeat(16 * 1024 - 1)), false],
  ["size", "16 KiB of 3-byte characters, exactly", JSON.stringify("€".repeat((16 * 1024 - 2) / 3 | 0) + "x".repeat((16 * 1024 - 2) % 3)), true],
  ["size", "an escape that crosses the edge refused", JSON.stringify("x".repeat(16 * 1024 - 3) + "\n"), false],
];

const out = cases.map(([cls, name, input, ok]) => {
  const c = { class: cls, name, input, ok };
  if (ok) {
    c.canon = JSON.stringify(sortDeep(JSON.parse(input)));
    // (the digest object's canonical text: its five keys in order child, conversation, input, request, tool)
    const text = `{"child":${JSON.stringify(IDS.child)},"conversation":${JSON.stringify(IDS.conversation)},"input":${c.canon},"request":${JSON.stringify(IDS.request)},"tool":${JSON.stringify(IDS.tool)}}`;
    c.digest = createHash("sha256").update(DOMAIN + text, "utf8").digest("base64url");
  }
  return c;
});
const file = fileURLToPath(new URL("./canon-fixtures.json", import.meta.url));
writeFileSync(file, JSON.stringify({ domain: DOMAIN, ids: IDS, max: 16 * 1024, depth: 32, cases: out }, null, 1) + "\n");
console.log(`${out.length} cases written to ${file}`);
