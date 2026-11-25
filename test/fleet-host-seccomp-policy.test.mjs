// The turn's syscall policy artifact (launcher contract amendment A5 §3, part 3b-ii a): generated from the pinned
// systemd's own group tables and the pinned headers' x86_64 numbers. CI reproduces the fixtures from the pinned tools,
// offline (scripts/seccomp-policy-ci.sh); these rows pin everything else.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { buildPolicy, expand, FILTER, GROUPS, numbersFile, parseSyscallFilter, serializePolicy, systemdMajorRefusal } from "../lib/fleet/host/seccomp-policy.mjs";
import { ARTIFACT, check, debLines, FILTER_FIXTURE, generated, NUMBERS_FIXTURE, readPin } from "../scripts/seccomp-policy.mjs";

const filterText = readFileSync(FILTER_FIXTURE, "latin1");
const numbersText = readFileSync(NUMBERS_FIXTURE, "utf8");
const artifact = readFileSync(ARTIFACT, "utf8");
const pin = readPin();
const build = (f = filterText, n = numbersText) => serializePolicy(buildPolicy({ filterText: f, numbersText: n, pin }));

// A synthetic unistd_64.h carrying exactly the fixture's numbers (the GPL header itself isn't in the repository).
const unistd = numbersText.trim().split("\n").map((l) => { const [n, x] = l.split(" "); return `#define __NR_${n} ${x}`; }).join("\n") + "\n";

test("the committed artifact is byte for byte what the committed fixtures generate", () => {
  assert.equal(generated(), artifact);
  assert.equal(build(), artifact);
});

test("exactly the 30 named groups, each once, in the pinned order; anything else is refused", () => {
  const { groups } = parseSyscallFilter(filterText);
  assert.deepEqual([...groups.keys()], [...GROUPS]);
  assert.equal(GROUPS.length, 30);
  // (a group's own block: its name at the start of a line, through the blank line after it)
  const block = (name) => { const i = filterText.indexOf(`\n${name}\n`) + 1; return filterText.slice(i, filterText.indexOf("\n\n", i) + 2); };
  const timer = block("@timer");
  assert.throws(() => parseSyscallFilter(filterText.replace(timer, "")), /a missing group: @timer/);
  assert.throws(() => parseSyscallFilter(filterText.replace(timer, timer + timer)), /a duplicate group: @timer/);
  assert.throws(() => parseSyscallFilter(filterText.replace(timer, timer + "@made-up\n    # x\n    read\n\n")), /an extra group: @made-up/);
  assert.throws(() => parseSyscallFilter(filterText.replace(timer, timer + "something else\n\n")), /an unknown block/);
  assert.throws(() => parseSyscallFilter(filterText.replace("    times\n", "    times x\n")), /a malformed member line/);
  assert.throws(() => parseSyscallFilter(filterText.replace("    times\n", "    times\n    times\n")), /times twice/);
  assert.throws(() => parseSyscallFilter(filterText.replace("#   arc_gettls\n", "#   arc gettls\n")), /a malformed line in a comment section/);
  assert.throws(() => parseSyscallFilter(filterText.slice(0, filterText.indexOf("# Ungrouped"))), /no Ungrouped section/);
});

test("the running kernel's Unlisted section can't change the artifact; the same names in a group do", () => {
  const unlisted = "\n# Unlisted System Calls (supported by the local kernel, but not included in any of the groups listed above):\n#   host_only_call\n#   another_one\n\n";
  assert.equal(build(filterText + unlisted), artifact, "ignored");
  // The control: a member changed in a named group changes the artifact.
  assert.notEqual(build(filterText.replace("    accept4\n", "    host_only_call\n")), artifact);
  assert.notEqual(build(filterText.replace("    times\n", "")), artifact, "a member removed");
});

test("the expansion: @system-service less the eight groups, numbered for x86_64", () => {
  const p = JSON.parse(artifact);
  assert.deepEqual(p.filter, { allow: "@system-service", deny: ["@mount", "@swap", "@reboot", "@raw-io", "@module", "@obsolete", "@cpu-emulation", "@privileged"] });
  assert.deepEqual(FILTER.deny, p.filter.deny);
  // The pinned counts, as literals.
  assert.equal(p.allow.length, 288);
  assert.equal(p.not_on_arch.length, 69);
  const allow = new Map(p.allow);
  for (const [n, x] of [["read", 0], ["openat", 257], ["openat2", 437], ["clone3", 435], ["setns", 308], ["personality", 135], ["sched_setattr", 314], ["socket", 41]]) assert.equal(allow.get(n), x, n);
  for (const n of ["mount", "umount2", "swapon", "reboot", "iopl", "init_module", "kexec_load", "ptrace", "bpf", "syslog", "sethostname", "_sysctl", "clock_settime"]) assert.ok(!allow.has(n), `${n} is outside the allow list`);
  // Sorted by name, each once; numbers unique.
  const names = p.allow.map(([n]) => n);
  assert.deepEqual(names, [...names].sort());
  assert.equal(new Set(p.allow.map(([, x]) => x)).size, p.allow.length);
  // Independently: every allowed name is in @system-service's expansion and in no deny group's.
  const { groups } = parseSyscallFilter(filterText);
  const svc = expand(groups, "@system-service");
  const denied = new Set(FILTER.deny.flatMap((d) => [...expand(groups, d)]));
  for (const n of [...names, ...p.not_on_arch]) assert.ok(svc.has(n) && !denied.has(n), n);
  for (const n of svc) assert.ok(denied.has(n) || names.includes(n) || p.not_on_arch.includes(n), n);
});

test("colour escapes are removed; a cycle or an unknown reference is refused", () => {
  assert.ok(filterText.includes("\x1b[0m@"), "the fixture is the raw output, escapes included");
  const { groups } = parseSyscallFilter(filterText);
  assert.ok(groups.get("@system-service").includes("@aio"));
  const g = new Map([["@a", ["@b"]], ["@b", ["@a"]]]);
  assert.throws(() => expand(g, "@a"), /a cycle/);
  assert.throws(() => expand(new Map([["@a", ["@nope"]]]), "@a"), /an unknown group: @nope/);
});

test("the pin's provenance: the image by its linux/amd64 manifest, five snapshot .debs, the numbers apart from the groups", () => {
  const hex = /^sha256:[0-9a-f]{64}$/;
  assert.equal(pin.image.tag, "ubuntu:24.04");
  assert.match(pin.image.index, hex);
  assert.match(pin.image.linux_amd64, hex);
  assert.match(pin.snapshot, /^https:\/\/snapshot\.ubuntu\.com\/ubuntu\/[0-9]{8}T[0-9]{6}Z$/);
  assert.equal(pin.groups_from.systemd_version, "systemd 255 (255.4-1ubuntu8.19)");
  assert.equal(pin.groups_from.systemd_major, 255);
  assert.deepEqual(pin.groups_from.debs.map((d) => d.package), ["systemd", "libsystemd-shared", "libapparmor1", "libkmod2"]);
  assert.deepEqual(pin.numbers_from.debs.map((d) => d.package), ["linux-libc-dev"]);
  for (const d of [...pin.groups_from.debs, ...pin.numbers_from.debs]) {
    assert.match(d.sha256, /^[0-9a-f]{64}$/, d.package);
    assert.equal(d.architecture, "amd64");
    assert.ok(d.path.startsWith("pool/main/") && d.path.endsWith(`/${d.package}_${d.version}_${d.architecture}.deb`), d.path);
  }
  const lines = debLines().trim().split("\n");
  assert.equal(lines.length, 5);
  assert.match(lines[0], /^https:\/\/snapshot\.ubuntu\.com\/ubuntu\/\S+\/pool\/main\/s\/systemd\/systemd_255\.4-1ubuntu8\.19_amd64\.deb [0-9a-f]{64} systemd 255\.4-1ubuntu8\.19 amd64 systemd_255\.4-1ubuntu8\.19_amd64\.deb$/);
});

test("CI's comparison: the pinned tools' raw outputs must equal the fixtures, and the version the pin's", () => {
  const version = "systemd 255 (255.4-1ubuntu8.19)\n+PAM +AUDIT\n";
  assert.equal(numbersFile(unistd), numbersText);
  assert.deepEqual(check(Buffer.from(filterText, "latin1"), unistd, version), []);
  assert.match(check(Buffer.from(filterText, "latin1"), unistd, "systemd 255 (255.4-1ubuntu8.18)\n").join(), /the systemd version/);
  assert.match(check(Buffer.from(filterText.replace("    times\n", "    times \n"), "latin1"), unistd, version).join(), /syscall-filter output differs/);
  assert.match(check(Buffer.from(filterText + "#\n", "latin1"), unistd, version).join(), /syscall-filter output differs/);
  assert.match(check(Buffer.from(filterText, "latin1"), unistd.replace("#define __NR_read 0", "#define __NR_read 1000"), version).join(), /numbers differ/);
  // A changed pin (another .deb hash) no longer generates the committed artifact.
  const other = structuredClone(pin);
  other.groups_from.debs[0].sha256 = "0".repeat(64);
  assert.match(check(Buffer.from(filterText, "latin1"), unistd, version, other).join(), /the artifact isn't what the fixtures generate/);
});

test("the host's systemd: exactly the pinned major, else a hard refusal (unreadable or mismatch)", () => {
  const ok = ["systemd 255 (255.4-1ubuntu8.19)\n+PAM", "systemd 255 (255.4-1ubuntu8.6)", "systemd 255 (255.4)"];
  for (const v of ok) assert.equal(systemdMajorRefusal(v, 255), null, v);
  for (const v of ["systemd 256 (256.1-1)", "systemd 254 (254.5-1)", "systemd 2550 (2550)", "systemd 25 (25)", "systemd 259 (259.5-0ubuntu3)"]) assert.equal(systemdMajorRefusal(v, 255), "mismatch", v);
  for (const v of ["", undefined, null, "systemd", "systemd 255", "systemd  255 (x)", "Systemd 255 (x)", "systemd 0255 (x)", "systemd 255 (a b)", "systemd 255 (x) extra", "garbage\nsystemd 255 (255.4)", " systemd 255 (255.4)"]) assert.equal(systemdMajorRefusal(v, 255), "unreadable", String(v));
});
