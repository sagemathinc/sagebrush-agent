// The browser channel's app session (design agent-autonomous-browser-channel.md r4.2 §6; O11 §7.4–§7.6 and §8.1 as
// r4.2 amends them): the person's app's side of one browser session, across its transports (links). It admits the
// broker's commands, runs each at most once, one at a time and in seq order, and gives each exactly one terminal
// outcome: a result (res, seq = the command's) or an explicit refusal (ctl refused, before any execution).
// The rules (r4.2):
//   - a command arrives as seq = recv + 1 (admitted or refused, raising recv), or as a duplicate (seq <= recv, same h:
//     a done or refused one gets its outcome again, an admitted or executing one nothing); a different h, a skipped
//     seq, or a command already covered by rack ends the session;
//   - outcomes go out in seq order; each is retained until the broker's rack covers it (at most 8 MiB or 64
//     outcomes; past that, new commands are refused "credits", and past 32 such refusals the session ends), and
//     replayed on a resume;
//   - on a new transport the app applies the broker's first frame (its rack) before replaying anything, and sends
//     only ctl until then; after a resume it sends ctl events_lost;
//   - takeover: pause() refuses every new or resent command ("paused") and turns every admitted command that never
//     started into a "takeover" refusal; a started one either finishes or is abandon()ed, which gives it the
//     in-session result { outcome: "unknown", reason: "abandoned" }, never a refusal. A late answer after that is
//     discarded.

import { createHash } from "node:crypto";
import { refuse } from "../bytes.mjs";
import { encodeBody } from "./frames.mjs";
import { link as makeLink } from "./link.mjs";

export const RETAIN_BYTES = 8 * 1024 * 1024;
export const RETAIN_COUNT = 64;
export const CREDITS = 32;
export const RESUME_MS = 60_000;
export const PING_MS = 10_000;
export const STALL_MISSES = 3;

const sha256 = (b) => createHash("sha256").update(b).digest("base64url");
const ABANDONED = Object.freeze({ outcome: "unknown", reason: "abandoned" });

/**
 * execute(command, { seq }) -> Promise<answer object>: runs one command (a rejection is the command path's own
 * unknown). validate(command) -> boolean: false refuses it "bad" before any execution. clock: { now, setTimeout,
 * clearTimeout }. onState(s): "ended" (with its reason), "stalled", "ok".
 */
export function appSession({ execute, validate = () => true, clock = globalThis, onState = () => {}, retainBytes = RETAIN_BYTES, retainCount = RETAIN_COUNT, credits = CREDITS, resumeMs = RESUME_MS, pingMs = PING_MS, linkOptions = {} }) {
  const cmds = new Map(); // seq -> { h, state: admitted | executing | done | refused, out: { kind, value, size } }
  const queue = []; // admitted, not started, in seq order
  let recv = 0, rackHW = 0, maxOut = 0, executing = null, paused = false, ended = null, attached = 0, lostEvents = 0;
  let cur = null, lostTimer = null, pingTimer = null, missed = 0;

  const retained = () => {
    let bytes = 0, count = 0;
    for (const c of cmds.values()) if (c.out) { bytes += c.out.size; count++; }
    return { bytes, count };
  };
  const unresolved = () => { let n = 0; for (const c of cmds.values()) if (c.state === "admitted" || c.state === "executing") n++; return n; };
  const ack = () => ({ recv, rack: 0 });

  function end(reason) {
    if (ended) return;
    ended = reason;
    clock.clearTimeout(lostTimer);
    clock.clearTimeout(pingTimer);
    if (cur && !cur.l.ended) cur.l.fail(reason);
    cur = null;
    queue.length = 0;
    onState({ state: "ended", reason });
  }

  // The outcomes not yet sent on this link, in seq order, stopping at the first command still without one.
  function flush() {
    if (!cur || cur.awaiting || ended) return;
    for (let seq = cur.emitted + 1; seq <= recv; seq++) {
      const c = cmds.get(seq);
      if (!c || !c.out) return;
      const ok = c.out.kind === "res"
        ? cur.l.send("res", seq, c.out.value, ack())
        : cur.l.send("ctl", ++cur.ctl, { ctl: "refused", seq, reason: c.out.value.reason }, ack());
      if (!ok) return;
      cur.emitted = seq;
      if (seq > maxOut) maxOut = seq;
    }
  }

  function setOutcome(seq, kind, value) {
    const c = cmds.get(seq);
    const size = kind === "res" ? encodeBody("res", value).length : 64;
    c.out = { kind, value, size };
    c.state = kind === "res" ? "done" : "refused";
    flush();
  }

  // Release every outcome the broker's rack covers.
  function applyRack(r) {
    rackHW = r;
    for (const s of [...cmds.keys()]) if (s <= rackHW) cmds.delete(s);
  }

  function run() {
    if (executing !== null || ended) return;
    const seq = queue.shift();
    if (seq === undefined) return;
    const c = cmds.get(seq);
    c.state = "executing";
    executing = seq;
    let p;
    try { p = Promise.resolve(execute(c.command, { seq })); } catch (e) { p = Promise.reject(e); }
    p.then(
      (answer) => finish(seq, c, { answer }),
      () => finish(seq, c, ABANDONED), // (the command path's own unknown)
    );
  }
  function finish(seq, c, value) {
    // (a late answer: the command was abandoned, or the session ended; discarded, never forwarded)
    if (ended || executing !== seq || cmds.get(seq) !== c || c.state !== "executing") return;
    executing = null;
    if (value.answer !== undefined && (value.answer === null || typeof value.answer !== "object" || Array.isArray(value.answer))) value = ABANDONED;
    setOutcome(seq, "res", value);
    run();
  }

  function onCommand(seq, bytes, command) {
    const h = sha256(bytes);
    if (seq <= rackHW) refuse("bad_form", `command ${seq} again, after rack covered it`);
    if (seq <= recv) {
      const c = cmds.get(seq);
      if (c.h !== h) refuse("bad_form", `command ${seq} again, with another body`);
      // (a duplicate: an admitted or executing one gets nothing; a done or refused one gets its retained outcome,
      // which this transport's in-order replay sends once, never twice on one transport)
      return;
    }
    if (seq !== recv + 1) refuse("bad_form", `command ${seq} skips past ${recv + 1}`);
    const r = retained();
    // (past the retention bound new commands are refused "credits", and those refusals are retained too: a broker
    // that keeps sending without acknowledging passes the bound by at most `credits` of them, then the session ends)
    if (r.count >= retainCount + credits) refuse("limit", "retained outcomes past their bound");
    recv = seq;
    const reason = paused ? "paused"
      : unresolved() >= credits || r.bytes >= retainBytes || r.count >= retainCount ? "credits"
      : !validate(command) ? "bad"
      : null;
    cmds.set(seq, { h, command, state: "admitted", out: null });
    if (reason) return setOutcome(seq, "refused", { reason });
    queue.push(seq);
    run();
  }

  function onMessage(m, entry) {
    if (ended) return;
    if (entry.awaiting) {
      // (the broker's first frame on this transport: apply its rack before replaying anything)
      entry.awaiting = false;
      applyRack(entry.l.highWater);
      entry.emitted = rackHW;
    } else {
      applyRack(entry.l.highWater);
    }
    if (m.kind === "cmd") onCommand(m.seq, m.bytes, m.value.command);
    else if (m.value.ctl === "ping") entry.l.send("ctl", ++entry.ctl, { ctl: "pong", t: m.value.t }, ack());
    else if (m.value.ctl === "pong") { missed = 0; onState({ state: "ok", rtt: Math.max(0, clock.now() - m.value.t) }); }
    flush();
  }

  function healthTick(entry) {
    if (cur !== entry || ended) return;
    if (++missed >= STALL_MISSES) onState({ state: "stalled" });
    entry.l.send("ctl", ++entry.ctl, { ctl: "ping", t: clock.now() }, ack());
    pingTimer = clock.setTimeout(() => healthTick(entry), pingMs);
  }

  return Object.freeze({
    get ended() { return ended; },
    get recv() { return recv; },
    get rack() { return rackHW; },
    get paused() { return paused; },
    get retained() { return retained(); },
    /** A new transport after its handshake: { cipher, sink }. Returns its link (deliver(ct), lost()). */
    attach({ cipher, sink }) {
      if (ended) throw new Error("this session has ended");
      if (cur) cur.l.lost("replaced");
      clock.clearTimeout(lostTimer);
      clock.clearTimeout(pingTimer);
      const entry = { ctl: 0, emitted: rackHW, awaiting: true, evt: 0, l: null };
      entry.l = makeLink({
        role: "app", cipher, sink, clock, ...linkOptions,
        ackLimit: () => maxOut,
        highWater: rackHW,
        onMessage: (m) => onMessage(m, entry),
        onEnd: (reason, fatal) => {
          if (cur !== entry) return;
          cur = null;
          clock.clearTimeout(pingTimer);
          if (fatal) end(reason);
          else lostTimer = clock.setTimeout(() => end("not resumed"), resumeMs);
        },
      });
      cur = entry;
      missed = 0;
      if (attached++ > 0) { entry.l.send("ctl", ++entry.ctl, { ctl: "events_lost", n: lostEvents }, ack()); lostEvents = 0; }
      if (cur === entry) pingTimer = clock.setTimeout(() => healthTick(entry), pingMs);
      return entry.l;
    },
    /** An event from the page: forwarded best effort, never while paused or before the broker's first frame. */
    event(event) {
      if (!cur || cur.awaiting || paused || ended || !cur.l.send("evt", ++cur.evt, { event }, ack())) lostEvents++;
    },
    /** Takeover: refuse every new command, and every admitted one that never started ("takeover"). */
    pause() {
      if (paused || ended) return;
      paused = true;
      for (const seq of queue.splice(0)) setOutcome(seq, "refused", { reason: "takeover" });
      if (cur && !cur.awaiting) cur.l.send("ctl", ++cur.ctl, { ctl: "paused" }, ack());
    },
    /** Handback: admit commands again. */
    unpause() { paused = false; },
    /** The drain gave up on the started command: its result is unknown (abandoned), never a refusal. */
    abandon(seq) {
      const c = cmds.get(seq);
      if (executing !== seq || !c || c.state !== "executing") return false;
      executing = null;
      setOutcome(seq, "res", ABANDONED);
      run();
      return true;
    },
    get executing() { return executing; },
    end(reason = "ended") { end(reason); },
  });
}
