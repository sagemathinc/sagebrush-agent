// The browser channel's broker session (design agent-autonomous-browser-channel.md r4.2 §6; O11 §7.4–§7.6 as r4.2
// amends them): the host's side of one browser session, across its transports (links). It sends the agent's
// commands and gives each one exactly one outcome:
//   - a result, delivered to the agent once;
//   - not_run: the first fragment was never sent, or the app refused it explicitly (ctl refused);
//   - unknown: every other sent command, once the session is lost (not resumed within 60 s, or ended by a protocol
//     error), and an abandoned one; never retried.
// The rules (r4.2):
//   - a result's seq is its command's; one terminal outcome per command. An outcome for a seq never sent, or one that
//     would settle n while a lower sent command is unresolved and not refused, ends the session;
//   - rack is the contiguous terminal-outcome mark: every command <= rack has its outcome here;
//   - each outcome's fingerprint (session, seq, kind; the canonical body's length and SHA-256, or the refusal's
//     reason) is recorded before its first delivery. On a new transport, an exact duplicate only re-acknowledges; a
//     changed outcome, a second outcome on the same transport, or one whose fingerprint has been evicted ends the
//     session;
//   - on a new transport the broker's first frame is ctl ping carrying rack; then it resends its unadmitted commands
//     (seq > the app's last recv) from their first fragment;
//   - at most 32 commands outstanding (sent, without an outcome), and at most 1 MiB of unadmitted command bytes.

import { createHash } from "node:crypto";
import { refuse } from "../bytes.mjs";
import { encodeBody } from "./frames.mjs";
import { link as makeLink } from "./link.mjs";

export const CREDITS = 32;
export const COMMAND_BYTES = 1024 * 1024;
export const RESUME_MS = 60_000;
export const PING_MS = 10_000;
export const STALL_MISSES = 3;
export const FINGERPRINTS = 64;

const sha256 = (b) => createHash("sha256").update(b).digest("base64url");

/**
 * clock: { now(), setTimeout(fn, ms), clearTimeout(id) }. onEvent(e): an event from the app ({ event } or
 * { events_lost: n }). onHealth({ state, rtt? }): "ok" or "stalled". fingerprints: how many recent outcomes keep
 * their fingerprint.
 */
export function brokerSession({ clock = globalThis, onEvent = () => {}, onHealth = () => {}, credits = CREDITS, commandBytes = COMMAND_BYTES, resumeMs = RESUME_MS, pingMs = PING_MS, fingerprints = FINGERPRINTS, linkOptions = {} } = {}) {
  const cmds = new Map(); // seq -> { seq, body, size, sent, outcome, settle, linkId }
  const prints = new Map(); // seq -> { linkId, key } (the last `fingerprints` outcomes)
  let nextSeq = 1, maxSent = 0, recvHW = 0, rack = 0, ended = null;
  let cur = null, linkId = 0, ctlSeq = 0, lostTimer = null, pingTimer = null, missed = 0, ackQueued = false;

  const outstanding = () => { let n = 0; for (const c of cmds.values()) if (c.sent && !c.outcome) n++; return n; };
  const unadmittedBytes = () => { let n = 0; for (const c of cmds.values()) if (c.sent && !c.outcome && c.seq > recvHW) n += c.size; return n; };
  const ack = () => ({ recv: 0, rack });

  function settle(c, outcome) {
    c.outcome = outcome;
    c.settle(outcome);
  }

  function end(reason) {
    if (ended) return;
    ended = reason;
    clock.clearTimeout(lostTimer);
    clock.clearTimeout(pingTimer);
    if (cur && !cur.l.ended) cur.l.fail(reason);
    cur = null;
    for (const c of [...cmds.values()].sort((a, b) => a.seq - b.seq)) {
      if (c.outcome) continue;
      settle(c, c.sent ? { outcome: "unknown", reason } : { outcome: "not_run", reason });
    }
  }

  function sendCtl(value) {
    if (!cur || cur.l.ended) return false;
    return cur.l.send("ctl", ++cur.ctl, value, ack());
  }

  function sendCmd(c) {
    if (!cur.l.send("cmd", c.seq, c.body, ack())) return false;
    c.sent = true;
    if (c.seq > maxSent) maxSent = c.seq;
    return true;
  }

  // New commands, in seq order, within the credits and the unadmitted-bytes bound.
  function pump() {
    if (!cur || ended) return;
    for (let seq = maxSent + 1; seq < nextSeq; seq++) {
      const c = cmds.get(seq);
      if (outstanding() >= credits || unadmittedBytes() + c.size > commandBytes) return;
      if (!sendCmd(c)) return;
    }
  }

  function queueAck() {
    if (ackQueued) return;
    ackQueued = true;
    queueMicrotask(() => { ackQueued = false; if (cur && !ended) sendCtl({ ctl: "ping", t: clock.now() }); });
  }

  // One terminal outcome for seq n (kind "res" with its bytes and value, or "refused" with its reason).
  function outcome(n, kind, payload, from) {
    const c = cmds.get(n);
    if (!c || !c.sent) refuse("bad_form", `an outcome for command ${n}, never sent`);
    const key = kind === "res" ? `res:${payload.bytes.length}:${sha256(payload.bytes)}` : `refused:${payload.reason}`;
    if (c.outcome) {
      // (a second outcome: only an exact replay on a new transport is harmless)
      const fp = prints.get(n);
      if (!fp) refuse("bad_form", `a second outcome for command ${n}, its fingerprint gone`);
      if (fp.linkId === from) refuse("bad_form", `a second outcome for command ${n} on the same transport`);
      if (fp.key !== key) refuse("bad_form", `a conflicting second outcome for command ${n}`);
      queueAck();
      return;
    }
    if (n !== rack + 1) refuse("bad_form", `an outcome for command ${n} while command ${rack + 1} is unresolved`);
    prints.set(n, { linkId: from, key });
    for (const s of prints.keys()) if (prints.size > fingerprints) prints.delete(s); else break;
    rack = n;
    if (kind === "res") {
      const v = payload.value;
      settle(c, v.answer !== undefined ? { outcome: "result", answer: v.answer } : { outcome: "unknown", reason: v.reason });
    } else {
      settle(c, { outcome: "not_run", reason: payload.reason });
    }
    queueAck();
    pump();
  }

  function onMessage(m, from) {
    if (ended) return;
    recvHW = cur.l.highWater;
    if (m.kind === "res") return outcome(m.seq, "res", { bytes: m.bytes, value: m.value }, from);
    if (m.kind === "evt") return onEvent({ event: m.value.event });
    const v = m.value;
    switch (v.ctl) {
      case "refused": return outcome(v.seq, "refused", { reason: v.reason }, from);
      case "ping": sendCtl({ ctl: "pong", t: v.t }); return pump();
      case "pong": missed = 0; onHealth({ state: "ok", rtt: Math.max(0, clock.now() - v.t) }); return pump();
      case "events_lost": return onEvent({ events_lost: v.n });
      case "paused": return onEvent({ paused: true });
    }
  }

  function healthTick(id) {
    if (!cur || cur.id !== id || ended) return;
    if (++missed >= STALL_MISSES) onHealth({ state: "stalled" });
    sendCtl({ ctl: "ping", t: clock.now() });
    pingTimer = clock.setTimeout(() => healthTick(id), pingMs);
  }

  return Object.freeze({
    get ended() { return ended; },
    get rack() { return rack; },
    get recv() { return recvHW; },
    get outstanding() { return outstanding(); },
    /** Send a command; the promise settles with its one outcome. */
    submit(command) {
      const body = encodeBody("cmd", { command });
      if (ended) return Promise.resolve({ outcome: "not_run", reason: ended });
      const seq = nextSeq++;
      const p = new Promise((resolve) => cmds.set(seq, { seq, body: { command }, size: body.length, sent: false, outcome: null, settle: resolve }));
      pump();
      return p;
    },
    /**
     * A new transport after its handshake (the first, or a resume): { cipher, sink }. Returns its link, whose
     * deliver(ct) the transport calls with each Noise message and lost() when it closes.
     */
    attach({ cipher, sink }) {
      if (ended) throw new Error("this session has ended");
      if (cur) cur.l.lost("replaced");
      clock.clearTimeout(lostTimer);
      clock.clearTimeout(pingTimer);
      const id = ++linkId;
      const entry = { id, ctl: 0, l: null };
      entry.l = makeLink({
        role: "broker", cipher, sink, clock, ...linkOptions,
        ackLimit: () => maxSent,
        highWater: recvHW,
        onMessage: (m) => onMessage(m, id),
        onEnd: (reason, fatal) => {
          if (!cur || cur.id !== id) return;
          cur = null;
          clock.clearTimeout(pingTimer);
          if (fatal) end(reason);
          else lostTimer = clock.setTimeout(() => end("not resumed"), resumeMs);
        },
      });
      cur = entry;
      missed = 0;
      // (the first frame on a transport: ctl ping carrying rack, which the app applies before any replay)
      sendCtl({ ctl: "ping", t: clock.now() });
      // (then the unadmitted commands, from their first fragment, in seq order: all of them unresolved)
      for (let seq = recvHW + 1; seq <= maxSent && cur === entry; seq++) {
        const c = cmds.get(seq);
        if (c.outcome) continue;
        sendCmd(c);
      }
      pump();
      if (cur === entry) pingTimer = clock.setTimeout(() => healthTick(id), pingMs);
      return entry.l;
    },
    /** End the session (the host's decision): every unanswered command gets its outcome now. */
    end(reason = "ended") { end(reason); },
  });
}
