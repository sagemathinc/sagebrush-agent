// Fleet protocol, the browser lane (O11 draft 5 §4.3): the rewrite. It applies the compiled program
// (schema/fleet/browser/o11-program.json, made by resolve.mjs from the pinned protocol and checked by its test) to a
// CDP result or event before the agent sees it: every handle becomes a vid, every dropped id is removed, and nothing
// else is looked at. A value whose shape doesn't match the program (an array where the protocol has an object, a
// handle that isn't a string or safe integer) throws `unmappable`: the caller drops the event or fails the command,
// and never forwards it unrewritten.

import { refuse, sha256 } from "../index.mjs";

/** The program, refused unless its bytes have the pinned hash (hex). */
export function loadProgram(bytes, sha256hex) {
  const got = Buffer.from(sha256(bytes)).toString("hex");
  if (got !== sha256hex) refuse("program_mismatch", "the rewrite program isn't the reviewed one");
  const p = JSON.parse(Buffer.from(bytes).toString("utf8"));
  if (!p.owners || !p.types) refuse("program_mismatch", "not a rewrite program");
  return p;
}

const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

/** Rewrite `value` (a result or an event's params, changed in place, and returned) for `owner`, e.g. "DOM.getDocument result". */
export function rewrite(program, owner, value, vids) {
  const rows = program.owners[owner];
  if (!rows) refuse("unknown_owner", "no program for this result or event");
  apply(program, rows, value, vids);
  return value;
}

function apply(program, rows, target, vids) {
  if (!isObj(target)) refuse("unmappable", "expected an object");
  for (const r of rows) walk(program, target, r.path.split("."), 0, r.action, vids);
}

function walk(program, holder, segs, i, action, vids) {
  const seg = segs[i], many = seg.endsWith("[]"), name = many ? seg.slice(0, -2) : seg;
  if (!Object.hasOwn(holder, name) || holder[name] === undefined) return; // (an optional field that isn't there)
  const last = i === segs.length - 1;
  if (many) {
    const arr = holder[name];
    if (!Array.isArray(arr)) refuse("unmappable", "expected an array");
    if (last && action === "drop") { delete holder[name]; return; }
    for (let k = 0; k < arr.length; k++) {
      if (last) arr[k] = leaf(program, arr[k], action, vids);
      else { if (!isObj(arr[k])) refuse("unmappable", "expected an object"); walk(program, arr[k], segs, i + 1, action, vids); }
    }
    return;
  }
  if (last) {
    if (action === "drop") { delete holder[name]; return; }
    holder[name] = leaf(program, holder[name], action, vids);
    return;
  }
  if (!isObj(holder[name])) refuse("unmappable", "expected an object");
  walk(program, holder[name], segs, i + 1, action, vids);
}

function leaf(program, value, action, vids) {
  if (action.startsWith("map:")) return vids.out(action.slice(4), value);
  if (action.startsWith("type:")) {
    const rows = program.types[action.slice(5)];
    if (!rows) refuse("unmappable", "no program for a type");
    apply(program, rows, value, vids);
    return value;
  }
  refuse("unmappable", "unknown action");
}
