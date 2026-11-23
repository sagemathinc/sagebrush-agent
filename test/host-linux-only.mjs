// The host supervisor is Linux-only by design (systemd, flock, Landlock, cgroups): its tests run on Linux and are
// skipped, with this reason, everywhere else. A host test imports `test` from here instead of from node:test.
import { test as nodeTest } from "node:test";

export const LINUX_ONLY = process.platform !== "linux" && "host supervisor is Linux-only";

/** node:test's `test(name[, options], fn)`, skipped off Linux. */
export function test(name, options, fn) {
  if (typeof options === "function") { fn = options; options = {}; }
  return nodeTest(name, { ...options, skip: LINUX_ONLY || options?.skip }, fn);
}
