// Host supervisor: the host's systemd against the one its syscall policy was expanded from (launcher contract amendment
// A5 §3; the ruling on 3b-ii a's install check). The agent unit's seccomp is the pinned systemd's own group expansion
// (schema/fleet/agent-seccomp-policy.json), so a host whose systemd major differs runs units under an unreviewed group
// definition. Before EVERY agent start (and in the future host install), `systemctl --version` is asked again, bounded
// and argv-only, never cached; anything but exactly the pinned major refuses: an unreadable version, a failed command,
// malformed output or another major. A refusal invalidates the host's qualification, latched (qualification.mjs).

import { readFileSync } from "node:fs";
import { systemdMajorRefusal } from "./seccomp-policy.mjs";

/** The pinned systemd major, from the policy artifact's pin. */
export const QUALIFIED_MAJOR = JSON.parse(readFileSync(new URL("../../../schema/fleet/agent-seccomp-policy.json", import.meta.url), "utf8")).pin.groups_from.systemd_major;

/**
 * Ask the host's systemd its version (`systemdVersion(ms, signal)`, the effect) and check it against the pin, within
 * `ms`: an answer after it is a refusal and the signal aborts, whether or not the timer has fired. Returns null when
 * it is exactly the pinned major, else "qualify_required". A failing or slow command is a refusal, never a pass. The
 * version itself is never returned or recorded.
 */
export async function hostSystemdPreflight(systemdVersion, ms, major = QUALIFIED_MAJOR) {
  const ac = new AbortController();
  // The deadline, monotonic, taken before asking. The answer's arrival decides: one that settles after it is refused
  // and the effect aborted, even when a busy event loop hasn't yet run the timer. The timer only ends the wait for an
  // answer that never comes (LATE; it can't fire before the deadline, so the clock check refuses it too).
  const end = performance.now() + ms;
  let timer;
  const late = new Promise((r) => { timer = setTimeout(() => r(LATE), ms); });
  try {
    const out = await Promise.race([Promise.resolve().then(() => systemdVersion(ms, ac.signal)), late]);
    if (out === LATE || performance.now() > end) {
      ac.abort();
      return "qualify_required";
    }
    return typeof out === "string" && systemdMajorRefusal(out, major) === null ? null : "qualify_required";
  } catch {
    return "qualify_required";
  } finally {
    clearTimeout(timer);
  }
}

const LATE = Symbol("late");
