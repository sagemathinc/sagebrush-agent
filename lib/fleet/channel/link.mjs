// The browser channel's link (design agent-autonomous-browser-channel.md r4.1 §6, "the transport is a stream with
// back-pressure"; O11 §7.3, §7.6): one transport of a session, after its handshake. It encrypts each frame as one Noise
// transport message, decrypts and reads the peer's frames (frames.mjs's reader), and writes to a sink with
// back-pressure:
//   - one writer per direction: every frame goes through this link's one sink, in order;
//   - a byte cap on what is queued (written, its callback not yet called), with a reserve kept for one terminal frame:
//     an ordinary message that would pass cap - reserve ends the session at once, before any of it is written;
//   - reading stops while the writer needs to drain (onReadPause(true) when the sink says so, false at its drain);
//   - the close is bounded: the sink is ended, and destroyed if it hasn't finished within closeMs.
// A frame the reader refuses, or a Noise message that doesn't decrypt (a gap, a reorder, a forgery), ends the link
// as fatal: the session it carries is over. The sink closing is not fatal: the session may resume on a new link.

import { refuse, FleetError } from "../bytes.mjs";
import { encodeBody, fragment, reader } from "./frames.mjs";

const EMPTY = new Uint8Array(0);
const TAG = 16;
// (the cap holds the largest message, an 8 MiB result in 140 fragments with their Noise tags, with room to spare)
export const CAP = 10 * 1024 * 1024;
export const RESERVE = 2048;
export const CLOSE_MS = 2000;
/** The system clock, each session's and link's default: { now, setTimeout, clearTimeout }. */
export const SYSTEM_CLOCK = Object.freeze({ now: () => Date.now(), setTimeout: (fn, ms) => setTimeout(fn, ms), clearTimeout: (id) => clearTimeout(id) });

/**
 * role: "broker" or "app" (whose frames this link sends). cipher: { send, receive }, the handshake's transport halves.
 * sink: { write(bytes, cb) -> boolean, once("drain", fn), end(), destroy() }. ackLimit(): the most the peer may
 * acknowledge now. highWater: the peer's acknowledgement already applied in this session (the last link's
 * reader.highWater), or 0. onMessage(m): a completed message from the peer. onEnd(reason, fatal): once.
 * clock: { setTimeout, clearTimeout }. onSend(kind, seq, value): each message as it is written (a trace for tests).
 */
export function link({ role, cipher, sink, ackLimit, highWater = 0, onMessage, onEnd, onReadPause = () => {}, onSend = () => {}, clock = SYSTEM_CLOCK, cap = CAP, reserve = RESERVE, closeMs = CLOSE_MS }) {
  if (role !== "broker" && role !== "app") throw new Error("a link sends the broker's or the app's frames");
  if (!(reserve > 0 && reserve < cap)) throw new Error("a reserve below the cap");
  const rd = reader({ from: role === "broker" ? "app" : "broker", ackLimit, highWater });
  let queued = 0, paused = false, ended = false, closeTimer = null;

  const end = (reason, fatal) => {
    if (ended) return;
    ended = true;
    if (paused) { paused = false; onReadPause(false); }
    // (the bounded close: end the sink, then destroy it if it hasn't finished by closeMs)
    try { sink.end(); } catch { /* (already gone) */ }
    closeTimer = clock.setTimeout(() => { try { sink.destroy(); } catch { /* (already gone) */ } }, closeMs);
    onEnd(reason, fatal);
  };

  const write = (frames) => {
    for (const f of frames) {
      const ct = cipher.send.encrypt(EMPTY, f);
      queued += ct.length;
      const more = sink.write(ct, () => { queued -= ct.length; });
      if (!more && !paused) {
        paused = true;
        onReadPause(true);
        sink.once("drain", () => { if (paused && !ended) { paused = false; onReadPause(false); } });
      }
    }
  };
  const size = (frames) => frames.reduce((n, f) => n + f.length + TAG, 0);

  return Object.freeze({
    get ended() { return ended; },
    get queued() { return queued; },
    get readPaused() { return paused; },
    /** The peer's acknowledgement applied so far: the next link of this session starts its reader here. */
    get highWater() { return rd.highWater; },
    /**
     * Send one message (all its fragments, or none of it). Returns false, having ended the session synchronously,
     * if it would take the queue past cap - reserve.
     */
    send(kind, seq, value, ack) {
      if (ended) return false;
      const frames = fragment(kind, seq, encodeBody(kind, value), ack);
      if (queued + size(frames) > cap - reserve) {
        end("limit", true);
        return false;
      }
      write(frames);
      onSend(kind, seq, value);
      return true;
    },
    /** The one terminal frame (a ctl), which may use the reserve; nothing is sent after it, and the link ends. */
    sendTerminal(seq, value, ack, reason = "closed") {
      if (ended) return false;
      const frames = fragment("ctl", seq, encodeBody("ctl", value), ack);
      if (queued + size(frames) <= cap) write(frames);
      end(reason, false);
      return true;
    },
    /** A Noise message from the peer. A refusal of any kind ends the link as fatal. */
    deliver(ct) {
      if (ended) return;
      let m;
      try {
        m = rd.push(cipher.receive.decrypt(EMPTY, ct));
      } catch (e) {
        if (!(e instanceof FleetError)) throw e;
        end(e.code, true);
        return;
      }
      if (m) {
        try {
          onMessage(m);
        } catch (e) {
          if (!(e instanceof FleetError)) throw e;
          end(e.code, true);
        }
      }
    },
    /** The transport closed under the link (the relay or the network): the session may resume. */
    lost(reason = "lost") { end(reason, false); },
    /** End the link as fatal for the session (a protocol error found above the frames). */
    fail(code) { end(code, true); },
    /** (tests) the bounded close's timer, once the link has ended */
    get closeTimer() { return closeTimer; },
  });
}

export { refuse };
