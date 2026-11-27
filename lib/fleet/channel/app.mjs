// The browser channel's app session (design agent-autonomous-browser-channel.md r4.2 §6; O11 §7.4–§7.6 and §8.1 as
// r4.2 amends them): the person's app's side of one browser session, across its transports (links). It admits the
// broker's commands, runs each at most once, one at a time and in seq order, and gives each exactly one terminal
// outcome: a result (res, seq = the command's) or an explicit refusal (ctl refused, before any execution).
// The rules (r4.2):
//   - a command arrives as seq = recv + 1 (admitted or refused, raising recv), or as a duplicate (seq <= recv, same h:
//     a done or refused one gets its outcome again, an admitted or executing one nothing); a different h, a skipped
//     seq, or a command already covered by rack ends the session;
//   - outcomes go out in seq order; each is retained until the broker's rack covers it, and replayed on a resume.
//     Two separate, strict bounds hold them:
//       result slots (retainCount, 64): an admitted command takes one at admission and keeps it until rack covers its
//       outcome, which is its result, abandoned, or a takeover refusal (an admitted command's refusal uses its own
//       slot). Result bytes (retainBytes, 8 MiB): a command starts only when the retained results' bytes plus the
//       largest result (resultBytes) fit, so a result can never pass the bound; rack restarts a waiting queue;
//       the arrival-refusal reserve (refusals, 32): a command refused on arrival ("paused", "credits", "bad") takes
//       one of these, never a result slot; one more while all are held ends the session ("limit");
//   - an answer that isn't a valid result, or is over resultBytes, gives the in-session { outcome: "unknown",
//     reason: "abandoned" } (its effect may have happened); a validator that throws ends the session (bad_form);
//   - on a new transport the app applies the broker's first frame (its rack) before replaying anything, and sends
//     only ctl until then; after a resume it sends ctl events_lost;
//   - takeover: pause() refuses every new or resent command ("paused") and turns every admitted command that never
//     started into a "takeover" refusal; a started one either finishes or is abandon()ed, which gives it the
//     in-session result { outcome: "unknown", reason: "abandoned" }, never a refusal. A late answer after that is
//     discarded. The one exception: a started command the executor proves never reached the page (its transport
//     refused it before sending anything) is refuseUnsent()ed: "takeover" while paused, or "bad"; a refusal in its own
//     result slot, and a late answer is discarded as after an abandon.

import { createHash } from "node:crypto";
import { refuse, FleetError } from "../bytes.mjs";
import { encodeBody, LIMITS } from "./frames.mjs";
import { link as makeLink, SYSTEM_CLOCK } from "./link.mjs";

export const RETAIN_BYTES = 8 * 1024 * 1024;
export const RETAIN_COUNT = 64;
export const CREDITS = 32;
export const REFUSALS = 32;
export const RESULT_BYTES = LIMITS.res.bytes;
export const RESUME_MS = 60_000;
export const PING_MS = 10_000;
export const STALL_MISSES = 3;

const sha256 = (b) => createHash("sha256").update(b).digest("base64url");
const ABANDONED = Object.freeze({ outcome: "unknown", reason: "abandoned" });
export const ABANDONED_SIZE = encodeBody("res", ABANDONED).length;
const REFUSAL_SIZE = 64; // (a refusal's retained size: fixed, as the refusal records are small and counted)

/**
 * execute(command, { seq }) -> Promise<answer object>: runs one command (a rejection is the command path's own
 * unknown). validate(command) -> boolean: false refuses it "bad" before any execution. clock: { now, setTimeout,
 * clearTimeout }. onState(s): "ended" (with its reason), "stalled", "ok". retainCount, retainBytes, resultBytes,
 * refusals: the bounds above (ABANDONED_SIZE <= resultBytes <= retainBytes).
 */
export function appSession({ execute, validate = () => true, clock = SYSTEM_CLOCK, onState = () => {}, retainBytes = RETAIN_BYTES, retainCount = RETAIN_COUNT, resultBytes = RESULT_BYTES, refusals = REFUSALS, credits = CREDITS, resumeMs = RESUME_MS, pingMs = PING_MS, linkOptions = {} }) {
  // (exact bounds, and the abandoned outcome, which every started command may end with, fits the reservation)
  for (const n of [retainBytes, resultBytes, retainCount, refusals, credits]) if (!Number.isSafeInteger(n) || n < 0) throw new Error("the bounds are exact counts");
  if (!(ABANDONED_SIZE <= resultBytes && resultBytes <= retainBytes)) throw new Error("the largest result must fit the retention bound, and the abandoned outcome within it");
  const cmds = new Map(); // seq -> { h, arrival, state: admitted | executing | done | refused, out: { kind, value, size } }
  const queue = []; // admitted, not started, in seq order
  let recv = 0, rackHW = 0, maxOut = 0, executing = null, paused = false, ended = null, attached = 0, lostEvents = 0;
  let cur = null, lostTimer = null, pingTimer = null, missed = 0;

  // (the result slots: admitted commands, with or without their outcome yet; and the arrival-refusal reserve)
  const held = () => {
    let slots = 0, resultBytes = 0, arrivals = 0;
    for (const c of cmds.values()) {
      if (c.arrival) { arrivals++; continue; }
      slots++;
      if (c.out && c.out.kind === "res") resultBytes += c.out.size; // (a takeover refusal: its slot, no bytes)
    }
    return { slots, resultBytes, arrivals };
  };
  const retained = () => {
    let bytes = 0, count = 0, refused = 0;
    for (const c of cmds.values()) if (c.out) { bytes += c.out.size; count++; if (c.arrival) refused++; }
    return { bytes, count, arrivalRefusals: refused };
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

  function setOutcome(seq, kind, value, size = REFUSAL_SIZE) {
    const c = cmds.get(seq);
    c.out = { kind, value, size };
    c.state = kind === "res" ? "done" : "refused";
    flush();
  }

  // Release every outcome the broker's rack covers.
  function applyRack(r) {
    if (r <= rackHW) return;
    rackHW = r;
    for (const s of [...cmds.keys()]) if (s <= rackHW) cmds.delete(s);
    run(); // (released bytes may let a waiting command start)
  }

  function run() {
    if (executing !== null || ended || !queue.length) return;
    // (start only if its largest result fits beside the retained ones; else wait for rack)
    if (held().resultBytes + resultBytes > retainBytes) return;
    const seq = queue.shift();
    const c = cmds.get(seq);
    c.state = "executing";
    executing = seq;
    let p;
    const command = c.command;
    c.command = null;
    try { p = Promise.resolve(execute(command, { seq })); } catch (e) { p = Promise.reject(e); }
    p.then(
      (answer) => finish(seq, c, answer),
      () => finish(seq, c, undefined), // (the command path's own unknown)
    ).catch((e) => end(e instanceof FleetError ? e.code : "bad_form")); // (never reached; fail closed if it is)
  }
  function finish(seq, c, answer) {
    // (a late answer: the command was abandoned, or the session ended; discarded, never forwarded)
    if (ended || executing !== seq || cmds.get(seq) !== c || c.state !== "executing") return;
    executing = null;
    // (anything but an answer object that encodes within resultBytes is unknown: its effect may have happened)
    let value = ABANDONED, size = ABANDONED_SIZE;
    if (answer !== null && typeof answer === "object" && !Array.isArray(answer)) {
      try {
        // (the canonical bytes, decoded once: the retained outcome is the session's own copy, which the executor's
        // object, changed later, can't touch)
        const bytes = encodeBody("res", { answer });
        if (bytes.length <= resultBytes) { value = JSON.parse(new TextDecoder().decode(bytes)); size = bytes.length; }
      } catch { /* (outside the schema or the frame bound: unknown) */ }
    }
    const h = held();
    if (h.resultBytes + size > retainBytes) return end("limit"); // (unreachable: run() reserved resultBytes)
    setOutcome(seq, "res", value, size);
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
    const r = held();
    let reason = paused ? "paused" : unresolved() >= credits || r.slots >= retainCount ? "credits" : null;
    if (!reason) {
      let ok;
      try { ok = validate(command); } catch { refuse("bad_form", "the command validator failed"); }
      if (!ok) reason = "bad";
    }
    // (an arrival refusal takes the separate reserve; one more while all of it is held ends the session)
    if (reason && r.arrivals >= refusals) refuse("limit", "arrival refusals past their reserve");
    recv = seq;
    cmds.set(seq, { h, command: reason ? null : command, arrival: !!reason, state: "admitted", out: null });
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
    /** The two bounds' use: result slots and result bytes, and the arrival refusals held. */
    get held() { return held(); },
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
      setOutcome(seq, "res", ABANDONED, ABANDONED_SIZE);
      run();
      return true;
    },
    /**
     * The started command never reached the page (the executor's transport refused it before sending anything): it is
     * refused, not run, with `reason` "takeover" (only while paused) or "bad". Only the command executing now; else
     * false, and nothing changes. When that isn't certain, abandon(seq) instead.
     */
    refuseUnsent(seq, reason) {
      const c = cmds.get(seq);
      if (ended || executing !== seq || !c || c.state !== "executing") return false;
      if (reason !== "bad" && !(reason === "takeover" && paused)) return false;
      executing = null;
      setOutcome(seq, "refused", { reason });
      run();
      return true;
    },
    get executing() { return executing; },
    end(reason = "ended") { end(reason); },
  });
}
