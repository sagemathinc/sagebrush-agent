#!/usr/bin/env node
// The turn's syscall policy artifact (launcher contract amendment A5 §3, part 3b-ii a): schema/fleet/agent-seccomp-policy.json,
// generated from two committed fixtures, which CI reproduces from the PINNED tools (scripts/seccomp-policy-ci.sh):
//   test/fixtures/seccomp/syscall-filter.txt   `systemd-analyze syscall-filter`'s exact standard output
//   test/fixtures/seccomp/x86_64-numbers.txt   the x86_64 numbers from the pinned `asm/unistd_64.h`, one `name number`
//                                              per line (derived: the GPL header itself isn't copied)
//
//   node scripts/seccomp-policy.mjs generate               write the artifact from the fixtures (a reviewed change)
//   node scripts/seccomp-policy.mjs check <filter> <unistd_64.h> <version>
//        the pinned tools' raw outputs: the version line must be the pin's, the filter output byte for byte the
//        fixture except its machine-dependent tail (the running kernel's Unlisted section, canonicalOutput), the
//        numbers the fixture's, and the artifact byte for byte what the fixtures generate
//   node scripts/seccomp-policy.mjs debs                   the pin's .debs, one `url sha256 package version arch file` per line

import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { buildPolicy, canonicalOutput, numbersFile, serializePolicy } from "../lib/fleet/host/seccomp-policy.mjs";

const at = (p) => fileURLToPath(new URL(`../${p}`, import.meta.url));
export const ARTIFACT = at("schema/fleet/agent-seccomp-policy.json");
export const FILTER_FIXTURE = at("test/fixtures/seccomp/syscall-filter.txt");
export const NUMBERS_FIXTURE = at("test/fixtures/seccomp/x86_64-numbers.txt");

/** The pin: the one hand-edited part of the artifact, kept by `generate`. */
export function readPin() {
  return JSON.parse(readFileSync(ARTIFACT, "utf8")).pin;
}

export function generated(pin = readPin()) {
  return serializePolicy(buildPolicy({ filterText: readFileSync(FILTER_FIXTURE, "latin1"), numbersText: readFileSync(NUMBERS_FIXTURE, "utf8"), pin }));
}

/** CI's comparison of the pinned tools' raw outputs; returns the list of differences (empty when all agree). */
export function check(filterRaw, unistdText, versionText, pin = readPin()) {
  const bad = [];
  const first = String(versionText).split("\n")[0];
  if (first !== pin.groups_from.systemd_version) bad.push(`the systemd version is ${JSON.stringify(first)}, not the pin's`);
  // Byte for byte, except the one machine-dependent tail (the running kernel's Unlisted section), cut on BOTH sides.
  let same = false;
  try {
    same = canonicalOutput(filterRaw).equals(canonicalOutput(readFileSync(FILTER_FIXTURE)));
  } catch (e) {
    bad.push(e.message);
  }
  if (!same) bad.push("the syscall-filter output differs from the fixture");
  if (numbersFile(unistdText) !== readFileSync(NUMBERS_FIXTURE, "utf8")) bad.push("the x86_64 numbers differ from the fixture");
  if (generated(pin) !== readFileSync(ARTIFACT, "utf8")) bad.push("the artifact isn't what the fixtures generate");
  return bad;
}

export function debLines(pin = readPin()) {
  return [...pin.groups_from.debs, ...pin.numbers_from.debs].map((d) => `${pin.snapshot}/${d.path} ${d.sha256} ${d.package} ${d.version} ${d.architecture} ${d.path.split("/").pop()}\n`).join("");
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const [cmd, ...a] = process.argv.slice(2);
  if (cmd === "generate" && a.length === 0) {
    writeFileSync(ARTIFACT, generated());
  } else if (cmd === "check" && a.length === 3) {
    const bad = check(readFileSync(a[0]), readFileSync(a[1], "utf8"), readFileSync(a[2], "utf8"));
    for (const b of bad) console.error(`seccomp policy: ${b}`);
    process.exit(bad.length ? 1 : 0);
  } else if (cmd === "debs" && a.length === 0) {
    process.stdout.write(debLines());
  } else {
    console.error("usage: seccomp-policy.mjs generate | check <filter> <unistd_64.h> <version> | debs");
    process.exit(64);
  }
}
