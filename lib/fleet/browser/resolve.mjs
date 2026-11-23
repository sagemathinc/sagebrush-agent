// Fleet protocol, the browser lane (agent-autonomous-browser-o11.md, draft 5 §4.3, frozen at doc sha256 509eb04e):
// the resolver. It walks the pinned Chrome for Testing protocol from every allowed command's result and every
// forwarded event (schema/fleet/browser/o11-cdp.json) and compiles the type-driven rewrite rules into a program:
//   owners: for "<Domain.method> result" and "<Domain.event> event", the rows at their top level;
//   types:  for each named protocol type that holds a handle somewhere, its rows.
// A row is { path, action }: path is dot-separated field names, "[]" after a name meaning every element of that
// array; action is "map:<kind>" (replace with a virtual handle), "drop" (remove the field) or "type:<Domain.Type>"
// (apply that type's rows there: the only way the program recurses, so recursive types stay finite). Kept fields
// (page content and non-handle data) get no row: the rewrite never looks inside them.
// Classification is total and fails closed. These are problems, and a program with problems is never used:
// - an id-typed field, an id-named plain field (at the top level too) or an opaque object (no declared properties, or
//   "any") without a rule;
// - an allowed method missing from the protocol;
// - a vid parameter whose kind isn't the one its protocol type maps to.
// Pure: no I/O, no clock.

const qualify = (ref, domain) => (ref.includes(".") ? ref : `${domain}.${ref}`);
const isOpaque = (n) => !n.$ref && ((n.type === "object" && !n.properties) || n.type === "any");
const isIdNamed = (p) => !p.$ref && (p.type === "string" || p.type === "integer") && /^(id|.*Id|.*ID)$/.test(p.name);
const looksLikeIdType = (q) => /(Id|ID|Identifier)$/.test(q.split(".")[1]);
// (a rule key's base: the named type, or the owner, that a field belongs to; an inline object inherits it)
const baseOf = (key) => key.split(".").slice(0, 2).join(".");

/** Compile `spec` against the pinned protocol `proto` (both parsed JSON): { program, flat, problems }. */
export function resolve(proto, spec) {
  const types = new Map(), commands = new Map(), events = new Map();
  for (const d of proto.domains) {
    for (const t of d.types ?? []) types.set(`${d.domain}.${t.id}`, { ...t, domain: d.domain });
    for (const c of d.commands ?? []) commands.set(`${d.domain}.${c.name}`, { ...c, domain: d.domain });
    for (const e of d.events ?? []) events.set(`${d.domain}.${e.name}`, { ...e, domain: d.domain });
  }
  const rules = spec.rewrite;
  const idTypes = rules.idTypes, drop = new Set(rules.dropIdTypes), untyped = rules.untypedIds;
  const opaque = Object.fromEntries(Object.entries(rules.opaque ?? {}).filter(([k]) => k !== "$comment"));
  const problems = [];
  for (const q of [...Object.keys(idTypes), ...drop]) if (!types.has(q)) problems.push(`a rule names ${q}, which the pinned protocol doesn't have`);

  const typeRows = {};
  function opaqueRow(key, path, rows, where) {
    const r = opaque[key];
    if (!r) return problems.push(`${where}: ${path} (${key}) is an opaque protocol object with no rule`);
    if (r.action === "drop" || r.action === "keep") return rows.push({ path, action: r.action });
    problems.push(`${where}: ${path} (${key}) has an opaque rule that is neither drop nor keep`);
  }
  // (one classification for every field, at the top level and at any depth)
  function field(p, domain, path, key, rows, where) {
    if (isIdNamed(p)) {
      const r = untyped[key];
      if (!r) return problems.push(`${where}: ${path} (${key}) is an untyped id-like ${p.type} with no rule`);
      return rows.push({ path, action: r.startsWith("keep") ? "keep" : r });
    }
    if (isOpaque(p)) return opaqueRow(key, path, rows, where);
    if (p.type === "array" && p.items && isOpaque(p.items)) return opaqueRow(`${key}[]`, `${path}[]`, rows, where);
    node(p, domain, path, key, rows, where);
  }
  function node(n, domain, path, key, rows, where) {
    if (n.$ref) {
      const q = qualify(n.$ref, domain);
      if (idTypes[q]) return rows.push({ path, action: `map:${idTypes[q]}` });
      if (drop.has(q)) return rows.push({ path, action: "drop" });
      if (looksLikeIdType(q)) return problems.push(`${where}: ${path} holds ${q}, an id type with no rule`);
      const t = types.get(q);
      if (!t) return problems.push(`${where}: ${path} refers to unknown ${q}`);
      if (isOpaque(t)) return opaqueRow(q, path, rows, where);
      compileType(q);
      return rows.push({ path, action: `type:${q}` });
    }
    if (n.type === "array" && n.items) {
      if (isOpaque(n.items)) return opaqueRow(`${key}[]`, `${path}[]`, rows, where);
      return node(n.items, domain, `${path}[]`, key, rows, where);
    }
    if (n.type === "object" && n.properties)
      for (const p of n.properties) field(p, domain, path ? `${path}.${p.name}` : p.name, `${baseOf(key)}.${p.name}`, rows, where);
  }
  function compileType(q) {
    if (q in typeRows) return;
    typeRows[q] = []; // (in progress: a recursive reference is just a type: row)
    const t = types.get(q), rows = [];
    if (t.type === "object" && t.properties) for (const p of t.properties) field(p, t.domain, p.name, `${q}.${p.name}`, rows, q);
    else if (t.type === "array" && t.items) node(t.items, t.domain, "[]", q, rows, q);
    typeRows[q] = rows;
  }

  // (the owners: every allowed command's result, every forwarded event; and the vid parameters' kinds)
  const ownerRows = {};
  for (const [name, c] of Object.entries(spec.commands)) {
    if (c.virtual) continue;
    const pc = commands.get(name);
    if (!pc) { problems.push(`allowed command ${name} isn't in the pinned protocol`); continue; }
    const rows = [];
    for (const r of pc.returns ?? []) field(r, pc.domain, r.name, `${name}.${r.name}`, rows, `${name} result`);
    ownerRows[`${name} result`] = rows;
    for (const [pname, ptype] of Object.entries(c.params ?? {})) {
      const pp = (pc.parameters ?? []).find((x) => x.name === pname);
      if (!pp) { problems.push(`${name}: parameter ${pname} isn't in the pinned protocol`); continue; }
      const m = typeof ptype === "string" && /^vid:([a-z]+)\??$/.exec(ptype);
      if (!m) continue;
      const q = pp.$ref ? qualify(pp.$ref, pc.domain) : null;
      const u = untyped[`${name}.${pname}`];
      const want = q ? idTypes[q] : u?.startsWith("map:") ? u.slice(4) : undefined;
      if (want !== m[1]) problems.push(`${name}: parameter ${pname} is vid:${m[1]} but its protocol type ${q ?? "(untyped)"} maps to ${want ?? "nothing"}`);
    }
  }
  for (const [name, e] of Object.entries(spec.events)) {
    if (e.virtual) continue;
    const pe = events.get(name);
    if (!pe) { problems.push(`forwarded event ${name} isn't in the pinned protocol`); continue; }
    const rows = [];
    for (const p of pe.parameters ?? []) field(p, pe.domain, p.name, `${name}.${p.name}`, rows, `${name} event`);
    ownerRows[`${name} event`] = rows;
  }

  // (prune: a type whose rows hold no map or drop anywhere below it does nothing; keep rows are no-ops)
  const empty = new Set();
  const live = (rows) => rows.filter((r) => r.action !== "keep" && !(r.action.startsWith("type:") && empty.has(r.action.slice(5))));
  for (let changed = true; changed; ) {
    changed = false;
    for (const [q, rows] of Object.entries(typeRows)) if (!empty.has(q) && live(rows).length === 0) { empty.add(q); changed = true; }
  }
  const program = { owners: {}, types: {} };
  for (const [o, rows] of Object.entries(ownerRows).sort()) program.owners[o] = live(rows);
  for (const [q, rows] of Object.entries(typeRows).sort()) if (!empty.has(q)) program.types[q] = live(rows);

  // (the flat listing, for review: every concrete path, with "recurse:<Type>" where a path re-enters a type)
  const flat = [];
  const expand = (rows, prefix, seen, owner) => {
    for (const r of rows) {
      const path = prefix && r.path ? `${prefix}.${r.path}` : prefix + r.path;
      if (!r.action.startsWith("type:")) { flat.push({ owner, path, action: r.action }); continue; }
      const q = r.action.slice(5);
      if (seen.includes(q)) { flat.push({ owner, path, action: `recurse:${q}` }); continue; }
      expand(typeRows[q] ?? [], path, [...seen, q], owner);
    }
  };
  for (const [o, rows] of Object.entries(ownerRows).sort()) expand(rows, "", [], o);
  return { program, flat, problems };
}
