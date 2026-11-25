// The turn's syscall policy (launcher contract amendment A5 §3, part 3b-ii a): the ONE source both the agent unit
// (unit.mjs) and the launcher's `turn` read, as a checked-in, fully expanded artifact,
// schema/fleet/agent-seccomp-policy.json. This module is pure: it parses the pinned systemd's own group tables
// (`systemd-analyze syscall-filter`) and the pinned kernel headers' x86_64 numbers, expands the unit's filter, writes
// the artifact's bytes, and checks a host's systemd against the pin. scripts/seccomp-policy.mjs runs it; CI runs the
// pinned tools offline and requires the same bytes.

/** The pinned systemd's named groups, exactly, in the order it prints them (A5 §3: 30 tables, @known included). */
export const GROUPS = Object.freeze([
  "@default", "@aio", "@basic-io", "@chown", "@clock", "@cpu-emulation", "@debug", "@file-system", "@io-event", "@ipc",
  "@keyring", "@memlock", "@module", "@mount", "@network-io", "@obsolete", "@pkey", "@privileged", "@process",
  "@raw-io", "@reboot", "@resources", "@sandbox", "@setuid", "@signal", "@swap", "@sync", "@system-service", "@timer",
  "@known",
]);

/** The unit's filter (unit.mjs): an allow list of `@system-service`, less these groups. */
export const FILTER = Object.freeze({ allow: "@system-service", deny: Object.freeze(["@mount", "@swap", "@reboot", "@raw-io", "@module", "@obsolete", "@cpu-emulation", "@privileged"]) });

// The two comment sections `systemd-analyze syscall-filter` prints after the groups (src/analyze/analyze-syscall-filter.c
// v255.4). "Ungrouped" is systemd's own static list; "Unlisted" comes from the RUNNING kernel, so it differs between
// machines and is the only thing ignored.
const UNGROUPED = "# Ungrouped System Calls (known but not included in any of the groups except @known):";
const UNLISTED = "# Unlisted System Calls (supported by the local kernel, but not included in any of the groups listed above):";

const fail = (why) => { throw new Error(`seccomp policy: ${why}`); };

/**
 * The named group tables from `systemd-analyze syscall-filter`'s standard output: Map(name -> members, in order). Its
 * colour escapes are removed. Exactly the 30 named groups, each once; members are syscall names or `@group`
 * references, each once per group. The two known comment sections are accepted (Ungrouped returned, Unlisted
 * dropped); any other block, line or group is refused.
 */
export function parseSyscallFilter(text) {
  const clean = String(text).replace(/\x1b\[[0-9;]*m/g, "");
  const blocks = clean.split("\n\n").map((b) => b.replace(/^\n+|\n+$/g, "")).filter((b) => b !== "");
  const groups = new Map();
  let ungrouped = null;
  for (const b of blocks) {
    const lines = b.split("\n");
    if (lines[0] === UNGROUPED || lines[0] === UNLISTED) {
      const names = lines.slice(1).map((l) => (/^#   ([a-z0-9_]+)$/.exec(l) ?? fail(`a malformed line in a comment section: ${JSON.stringify(l)}`))[1]);
      if (lines[0] === UNGROUPED) {
        if (ungrouped !== null) fail("two Ungrouped sections");
        ungrouped = names;
      }
      continue;
    }
    if (!/^@[a-z-]+$/.test(lines[0])) fail(`an unknown block: ${JSON.stringify(lines[0])}`);
    const name = lines[0];
    if (!GROUPS.includes(name)) fail(`an extra group: ${name}`);
    if (groups.has(name)) fail(`a duplicate group: ${name}`);
    if (!/^    # \S/.test(lines[1] ?? "")) fail(`${name}: no description line`);
    const members = [];
    for (const l of lines.slice(2)) {
      const m = /^    (@?[a-z0-9_-]+)$/.exec(l) ?? fail(`${name}: a malformed member line: ${JSON.stringify(l)}`);
      if (members.includes(m[1])) fail(`${name}: ${m[1]} twice`);
      members.push(m[1]);
    }
    groups.set(name, members);
  }
  for (const g of GROUPS) if (!groups.has(g)) fail(`a missing group: ${g}`);
  if (ungrouped === null) fail("no Ungrouped section");
  return { groups, ungrouped };
}

/**
 * The output's machine-independent HEAD: everything through the Ungrouped section's last line. What follows depends
 * only on the running kernel, and is exactly one of the three tails analyze-syscall-filter.c v255.4 prints: one empty
 * line (it couldn't read the kernel's list), nothing (the kernel lists nothing more), or the Unlisted section (its
 * header, then `#   <name>` lines). Any other tail is refused, so only that section can differ between machines.
 */
export function canonicalOutput(raw) {
  const text = Buffer.from(raw).toString("latin1");
  const strip = (l) => l.replace(/\x1b\[[0-9;]*m/g, "");
  const lines = text.split("\n");
  const at = lines.findIndex((l) => strip(l) === UNGROUPED);
  if (at < 0) fail("no Ungrouped section");
  let end = at + 1;
  while (end < lines.length && /^#   [a-z0-9_]+$/.test(strip(lines[end]))) end++;
  const head = lines.slice(0, end).join("\n") + "\n";
  const tail = text.slice(head.length);
  if (tail !== "" && tail !== "\n") {
    const t = tail.split("\n");
    const ok = t[0] === "" && strip(t[1] ?? "") === UNLISTED && t.at(-1) === "" && t.length >= 4 && t.slice(2, -1).every((l) => /^#   [a-z0-9_]+$/.test(strip(l)));
    if (!ok) fail("the output's tail is not one of the three the pinned systemd prints");
  }
  return Buffer.from(head, "latin1");
}

/** The x86_64 syscall numbers from the pinned `asm/unistd_64.h`: Map(name -> number); every name once. */
export function parseUnistd(text) {
  const out = new Map();
  for (const l of String(text).split("\n")) {
    const m = /^#define __NR_([a-z0-9_]+) ([0-9]+)$/.exec(l);
    if (!m) continue;
    if (out.has(m[1])) fail(`__NR_${m[1]} twice`);
    out.set(m[1], Number(m[2]));
  }
  if (out.size < 300) fail("too few syscall numbers: not the pinned header");
  return out;
}

/** Every syscall name a group stands for, its `@` references followed (a cycle or an unknown group is refused). */
export function expand(groups, name, seen = []) {
  if (seen.includes(name)) fail(`a cycle through ${name}`);
  const members = groups.get(name) ?? fail(`an unknown group: ${name}`);
  const out = new Set();
  for (const m of members) {
    if (m.startsWith("@")) for (const x of expand(groups, m, [...seen, name])) out.add(x);
    else out.add(m);
  }
  return out;
}

const byBytes = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

/**
 * The artifact, as an object with its keys in their fixed order: the pin (as given), the filter, the 30 tables, the
 * Ungrouped list, and the expansion with x86_64 numbers (names without one listed apart).
 */
export function buildPolicy({ filterText, numbersText, pin }) {
  const { groups, ungrouped } = parseSyscallFilter(filterText);
  const numbers = parseNumbers(numbersText);
  const allowed = expand(groups, FILTER.allow);
  for (const d of FILTER.deny) for (const x of expand(groups, d)) allowed.delete(x);
  const names = [...allowed].sort(byBytes);
  return {
    $comment: "GENERATED by scripts/seccomp-policy.mjs from the pinned systemd's own group tables and the pinned kernel headers' x86_64 numbers (launcher contract amendment A5 §3). Do not edit: change the pin and regenerate, in a reviewed change.",
    v: 1,
    pin,
    arch: "x86_64",
    filter: { allow: FILTER.allow, deny: [...FILTER.deny] },
    groups: Object.fromEntries(GROUPS.map((g) => [g, groups.get(g)])),
    ungrouped,
    allow: names.filter((n) => numbers.has(n)).map((n) => [n, numbers.get(n)]),
    not_on_arch: names.filter((n) => !numbers.has(n)),
  };
}

/** The x86_64 numbers file the fixtures and CI share: one `name number` per line, sorted by name. */
export function numbersFile(unistdText) {
  return [...parseUnistd(unistdText)].sort((a, b) => byBytes(a[0], b[0])).map(([n, x]) => `${n} ${x}\n`).join("");
}

function parseNumbers(text) {
  const out = new Map();
  for (const l of String(text).split("\n")) {
    if (l === "") continue;
    const m = /^([a-z0-9_]+) ([0-9]+)$/.exec(l) ?? fail(`a malformed numbers line: ${JSON.stringify(l)}`);
    if (out.has(m[1])) fail(`${m[1]} twice in the numbers`);
    out.set(m[1], Number(m[2]));
  }
  if (out.size < 300) fail("too few syscall numbers");
  return out;
}

/** The artifact's exact bytes: two-space JSON, the keys in buildPolicy's order, one trailing newline. */
export function serializePolicy(policy) {
  return `${JSON.stringify(policy, null, 2)}\n`;
}

/**
 * A host's systemd against the pin (SEC's ruling: a HARD refusal). `versionText` is `systemctl --version`'s output;
 * its first line must read `systemd <major> (<version>)`. Returns null when the major is exactly the pin's, else the
 * fixed reason: "unreadable" (no such first line) or "mismatch" (another major).
 */
export function systemdMajorRefusal(versionText, major) {
  const first = String(versionText ?? "").split("\n")[0];
  const m = /^systemd ([1-9][0-9]{0,5}) \([^()\s]+\)$/.exec(first);
  if (!m) return "unreadable";
  return Number(m[1]) === major ? null : "mismatch";
}
