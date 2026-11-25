// Fleet protocol, the browser lane (design agent-autonomous-browser-channel.md r4.2 §1, §5.3, §6): the net sidecar's
// makeChannel, a thin adapter between NetSidecar (sidecar-net.mjs) and the channel (lib/fleet/channel/): the Noise
// initiator, the app session's state machine and its link. Nothing protocol-level is decided here.
//
// What it does, per session:
//   - reads the signed record's own fields (fleet, aud, session, host, agent, browser_gen, host_gen) for the prologue
//     and the relay open's query: the record is the app's own, made and signed by Rust, and the host verifies it;
//   - opens one authenticated WebSocket per transport (§5.1, §5.3): role=app, the record's exact bytes in
//     Sagebrush-Browser-Record, a fresh 128-bit Sagebrush-Request id, and the relay token for exactly that open in
//     Sagebrush-Relay-Token (authToken(open), awaited: the token is bound to the open's tuple and request id, one per
//     open; the wrapper builds every header itself); binary only, no compression, frames at most 65,535 bytes;
//   - opens only to the relay of the record's own audience (wss://<the aud's host>/, §5.3), checked before any token
//     is asked for, and with no token, or one not in its form, opens nothing;
//   - runs the handshake on it (message 1 out with the record as its payload, message 2 in), then attaches the
//     transport to the one app session as its link, whose writer is the socket (wsSink: one Noise message per
//     WebSocket message, with back-pressure from the socket's own write callbacks);
//   - when a transport is lost, resumes on a new one (§6), until the session's own resume window ends it. An attempt
//     that never sent message 1 can't have been committed by the host, so the next one keeps its resume_n (with a new
//     request id and token); once message 1 has gone out, the next attempt is resume_n + 1 (§3.3's lost-reply rule);
//   - maps NetSidecar's calls onto the session: a command the session runs goes out through onCommand(seq, bytes)
//     and is answered by result(seq, body) or refused(seq, reason); takeover() pauses; resume() is the handback.
// A "takeover" or "bad" refusal of the command the session has handed out (net.refused before any send to Chrome)
// becomes the session's refuseUnsent(seq, reason) (ctl refused: not run); where the session refuses that call (not
// paused for a takeover, or no such call in this build), abandon(seq) instead (unknown, never a wrong "not run").

import { EventEmitter } from "node:events";
import { randomBytes } from "node:crypto";
import { appSession } from "../channel/app.mjs";
import { initiator, x25519Key, MAX_MESSAGE } from "../channel/noise.mjs";
import { prologueBytes } from "../channel/accept.mjs";
import { openTarget } from "../core/relay.mjs";
import { canonBytes } from "../canonical.mjs";
import { SYSTEM_CLOCK } from "../channel/link.mjs";
import { COMMAND_BYTES } from "./sidecar-net.mjs";
import { AUDIENCES } from "../core/envelope.mjs";

export const HANDSHAKE_MS = 15_000;
export const RETRY_MS = 1_000;
export const SINK_HIGH_WATER = 1024 * 1024; // (the relay keeps at most 1 MiB queued per direction, §5.4)
const RECORD_FIELDS = ["fleet", "aud", "session", "host", "agent", "browser_gen", "host_gen"];
/** The app-open relay token's one form (A1): rt1. and 32 CSPRNG bytes, base64url without padding. */
export const RELAY_TOKEN = /^rt1\.[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/;
const LOOPBACK = /^ws:\/\/127\.0\.0\.1:[1-9][0-9]{0,4}\/?$/;

/**
 * The relay origin for an audience: wss:// and the audience's host (§5.3), for a trusted audience only (audiences:
 * the configured list, AUDIENCES by default).
 */
export function relayOrigin(aud, audiences = AUDIENCES) {
  if (typeof aud !== "string" || !audiences.includes(aud)) throw new Error("the record's audience isn't a trusted one");
  const u = new URL(aud);
  if (u.protocol !== "https:" || u.username || u.password || u.port || u.search || u.hash || u.pathname !== "/" || aud !== u.origin) throw new Error("the record's audience isn't a trusted one");
  return `wss://${u.host}`;
}

/**
 * The relay base URL for a session: relayUrl must be exactly the audience's relay origin (with or without a final
 * "/"): no other host, port, path, query, fragment or userinfo. With allowLoopback (tests only), ws://127.0.0.1:<port>
 * (the audience must still be a trusted one).
 */
export function relayBase(relayUrl, aud, { audiences = AUDIENCES, allowLoopback = false } = {}) {
  const origin = relayOrigin(aud, audiences);
  if (typeof relayUrl !== "string") throw new Error("the relay isn't the record's audience's");
  if (allowLoopback && LOOPBACK.test(relayUrl)) return new URL(relayUrl);
  if (relayUrl !== origin && relayUrl !== `${origin}/`) throw new Error("the relay isn't the record's audience's");
  return new URL(`${origin}/`);
}

/**
 * A sink for link.mjs over one WebSocket: each write is one binary message. write returns false once the bytes the
 * socket hasn't confirmed written reach highWater; "drain" is emitted when they fall below it again. The callbacks
 * are the socket's own (ws's send callback runs when the frame has gone to the OS), so a peer that stops reading
 * blocks them, and with them the link's queue.
 */
export function wsSink(ws, { highWater = SINK_HIGH_WATER } = {}) {
  const em = new EventEmitter();
  let unconfirmed = 0, wantDrain = false;
  const sink = {
    write(bytes, cb) {
      unconfirmed += bytes.length;
      ws.send(bytes, { binary: true, compress: false }, () => {
        unconfirmed -= bytes.length;
        try { cb?.(); } finally {
          if (wantDrain && unconfirmed < highWater) { wantDrain = false; em.emit("drain"); }
        }
      });
      if (unconfirmed < highWater) return true;
      wantDrain = true;
      return false;
    },
    once: (ev, fn) => { em.once(ev, fn); return sink; },
    end() { try { ws.close(1000); } catch { /* (already closing) */ } },
    destroy() { try { ws.terminate(); } catch { /* (already gone) */ } },
    get unconfirmed() { return unconfirmed; },
  };
  return sink;
}

/** The record's own fields (the envelope's body), or a refusal: the record must be the signed session record. */
export function recordFields(record) {
  let env;
  try { env = JSON.parse(Buffer.from(record).toString("utf8")); } catch { throw new Error("the record isn't JSON"); }
  const body = env?.body;
  if (!body || typeof body !== "object") throw new Error("the record has no body");
  const f = {};
  for (const k of RECORD_FIELDS) {
    if (body[k] === undefined) throw new Error(`the record has no ${k}`);
    f[k] = body[k];
  }
  return Object.freeze(f);
}

/** A fresh request id: 128 random bits, base64url (22 characters). */
export const requestId = () => randomBytes(16).toString("base64url");

/**
 * The default transport: a WebSocket to the relay with the open's headers and §5.4's limits. ws is imported here, when
 * a transport is opened, so this module loads with no dependency (as every lib/fleet module does).
 */
export async function wsOpen(url, headers) {
  const { default: WebSocket } = await import("ws");
  return new WebSocket(url, { headers, perMessageDeflate: false, maxPayload: MAX_MESSAGE, handshakeTimeout: HANDSHAKE_MS });
}

/**
 * makeChannel for NetSidecar. authToken(open) -> the relay token (or a promise of it), required: the token for one
 * relay open (§5.3, A1), given the open's tuple and request id ({ fleet, host, agent, browser_gen, session, host_gen,
 * resume_n, request }). A rejection, or anything but one token in RELAY_TOKEN's form, ends the session with no socket
 * opened; the token goes only into that open's Sagebrush-Relay-Token header, never into a trace, error or URL.
 * Without authToken there is no channel: a build without the relay token opens nothing. audiences: the trusted
 * audiences (AUDIENCES by default); the relay is the record's audience's (relayBase). open(url, headers): a WebSocket
 * or a promise of one (tests inject theirs). clock: timers. sessionOptions: passed to appSession (bounds, linkOptions; tests make them
 * small). allowLoopback: tests only, a ws://127.0.0.1 relay. makeSession: appSession (tests wrap it). onTrace(e): a
 * trace for tests.
 */
export function netChannel({ authToken, audiences = AUDIENCES, open = wsOpen, clock = SYSTEM_CLOCK, sessionOptions = {}, handshakeMs = HANDSHAKE_MS, retryMs = RETRY_MS, sinkHighWater = SINK_HIGH_WATER, allowLoopback = false, makeSession = appSession, onTrace = () => {} } = {}) {
  if (typeof authToken !== "function") throw new Error("no relay token source: no channel");
  return function makeChannel({ start, record, key, onCommand, onState }) {
    const fields = recordFields(record);
    const rs = Buffer.from(String(start?.hostStaticPub ?? ""), "base64url");
    if (rs.length !== 32) throw new Error("the host's key isn't 32 bytes");
    if (fields.session !== start.session || fields.browser_gen !== start.browserGen) throw new Error("the record isn't this session's");
    const s = x25519Key(key.privateKey);
    const recordB64 = Buffer.from(record).toString("base64url");
    const base = relayBase(start.relayUrl, fields.aud, { audiences, allowLoopback });

    const answers = new Map(); // seq -> resolve: commands handed out through onCommand, not yet answered
    let closed = false, resumeN = -1, nextN = 0, ws = null, attachedLink = null, retryTimer = null, handshakeTimer = null, opened = false;

    const session = makeSession({
      ...sessionOptions,
      clock,
      validate: (command) => command !== null && typeof command === "object" && !Array.isArray(command),
      execute: (command, { seq }) => new Promise((resolve, reject) => {
        let bytes;
        try { bytes = canonBytes(command, COMMAND_BYTES); } catch { return reject(new Error("the command doesn't encode")); }
        answers.set(seq, { resolve, reject });
        onCommand(seq, bytes);
      }),
      onState: (st) => {
        if (st?.state === "ended") shut(st.reason ?? "ended");
        onTrace({ session: st });
      },
      linkOptions: {
        ...(sessionOptions.linkOptions ?? {}),
        onReadPause: (paused) => { try { paused ? ws?.pause() : ws?.resume(); } catch { /* (the socket is gone) */ } },
      },
    });

    function shut(reason) {
      if (closed) return;
      closed = true;
      clock.clearTimeout(retryTimer);
      clock.clearTimeout(handshakeTimer);
      for (const a of answers.values()) a.reject(new Error("closed"));
      answers.clear();
      const w = ws;
      ws = null;
      try { w?.terminate(); } catch { /* (already gone) */ }
      onState("ended", reason);
    }

    function lost(why) {
      if (closed) return;
      clock.clearTimeout(handshakeTimer);
      const l = attachedLink;
      attachedLink = null;
      const w = ws;
      ws = null;
      try { w?.terminate(); } catch { /* (already gone) */ }
      if (l) l.lost(why);
      if (session.ended) return shut(session.ended);
      if (opened) onState("resuming");
      clock.clearTimeout(retryTimer);
      retryTimer = clock.setTimeout(attempt, retryMs);
    }

    async function attempt() {
      if (closed || session.ended) return;
      resumeN = nextN;
      const n = resumeN;
      const request = requestId();
      let I, url, socket, token;
      try {
        const prologue = prologueBytes({ ...fields, resume_n: n });
        I = initiator({ s, rs, prologue });
        url = new URL(openTarget({ role: "app", fleet: fields.fleet, session: fields.session, agent: fields.agent, browser_gen: fields.browser_gen, host_gen: fields.host_gen, resume_n: n }), base).toString();
        token = await authToken(Object.freeze({ fleet: fields.fleet, host: fields.host, agent: fields.agent, browser_gen: fields.browser_gen, session: fields.session, host_gen: fields.host_gen, resume_n: n, request }));
      } catch {
        return shut("the relay open couldn't be made");
      }
      if (closed || session.ended) return; // (closed while the token was fetched)
      if (typeof token !== "string" || !RELAY_TOKEN.test(token)) return shut("the relay token isn't valid");
      try {
        socket = await open(url, { "Sagebrush-Relay-Token": token, "Sagebrush-Browser-Record": recordB64, "Sagebrush-Request": request });
      } catch {
        return shut("the relay open couldn't be made");
      }
      if (closed || session.ended) { try { socket?.terminate(); } catch { /* (already gone) */ } return; } // (closed while it opened)
      ws = socket;
      onTrace({ attempt: n, url });
      let phase = "handshake";
      handshakeTimer = clock.setTimeout(() => { if (ws === socket && phase === "handshake") lost("handshake timeout"); }, handshakeMs);
      socket.on("open", () => {
        if (ws !== socket) return;
        let m1;
        try { m1 = I.writeMessage1(record); } catch { return lost("message 1"); }
        // (a send that throws never handed message 1 over: the host can't have committed n, so the next attempt keeps it)
        try { socket.send(m1, { binary: true, compress: false }); } catch { return lost("message 1"); }
        // (from here the host may commit n: whatever happens next, the next attempt is n + 1)
        nextN = n + 1;
      });
      socket.on("message", (data, isBinary) => {
        if (ws !== socket) return;
        if (!isBinary) return lost("a text message");
        const bytes = data instanceof Buffer ? new Uint8Array(data.buffer, data.byteOffset, data.length) : new Uint8Array(data);
        if (phase === "handshake") {
          let h;
          try { h = I.readMessage2(bytes); } catch { return lost("message 2"); }
          phase = "attached";
          clock.clearTimeout(handshakeTimer);
          try {
            attachedLink = session.attach({ cipher: { send: h.send, receive: h.receive }, sink: wsSink(socket, { highWater: sinkHighWater }) });
          } catch { return shut(session.ended ?? "ended"); }
          opened = true;
          onState("open");
          return;
        }
        attachedLink?.deliver(bytes);
      });
      socket.on("close", () => { if (ws === socket) lost("closed"); });
      socket.on("error", () => { if (ws === socket) lost("transport error"); });
    }

    // (the first attempt on the next tick: NetSidecar keeps the channel only once makeChannel returns)
    retryTimer = clock.setTimeout(attempt, 0);

    return Object.freeze({
      result(seq, body) {
        const a = answers.get(seq);
        if (!a) return; // (late, or for a command already abandoned: discarded, never forwarded)
        answers.delete(seq);
        let answer;
        try { answer = JSON.parse(Buffer.from(body ?? []).toString("utf8")); } catch { return a.reject(new Error("the answer isn't JSON")); }
        a.resolve(answer);
      },
      refused(seq, reason) {
        // ("abandoned": sent to Chrome and possibly run, so unknown. "takeover" and "bad": NetSidecar's net.refused
        //  came before any send to Chrome, so not run, through refuseUnsent; if the session refuses that call, unknown)
        const a = answers.get(seq);
        answers.delete(seq);
        if (reason !== "abandoned" && typeof session.refuseUnsent === "function" && session.refuseUnsent(seq, reason)) return;
        if (!session.abandon(seq) && a) a.reject(new Error(`refused: ${reason}`));
      },
      event(body) {
        let event;
        try { event = JSON.parse(Buffer.from(body ?? []).toString("utf8")); } catch { return; }
        session.event(event);
      },
      takeover() { session.pause(); },
      resume() { session.unpause(); },
      close() {
        if (closed) return;
        closed = true;
        clock.clearTimeout(retryTimer);
        clock.clearTimeout(handshakeTimer);
        answers.clear();
        try { session.end("closed"); } catch { /* (ending either way) */ }
        const w = ws;
        ws = null;
        try { w?.terminate(); } catch { /* (already gone) */ }
      },
      /** (tests) the session and the transport */
      get session() { return session; },
      get socket() { return ws; },
      get resumeN() { return resumeN; },
    });
  };
}
