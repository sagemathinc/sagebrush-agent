// Fleet protocol, the browser lane: the net sidecar's process. The app (Rust) starts it on its pinned Node, one per
// browser session, with frames on stdin and stdout (./frames.mjs). It takes no configuration from its environment or
// arguments, makes its own channel key and proxy credentials, listens for Chrome on 127.0.0.1, and ends when the
// session does.
//
// - stdin: decoded strictly as frames to net; any frame error, or stdin ending (inside a frame or not), ends it.
// - stdout: one writer for every frame (the #46 ruling). Every frame may fill the output up to LIMITS.outBytes of
//   unwritten bytes; only the terminal frame (rust.net_state ended) may also use LIMITS.reserveBytes beyond it, so
//   "ended" can always be said. A frame that doesn't fit ends the sidecar at once ("the app isn't reading"). While
//   stdout needs to drain, stdin is paused: no more frames are taken from the app until the app reads.
// - The stall deadline (the ruling on #46 and #48): LIMITS.stallMs (30 s) from the moment a write first has to wait,
//   cleared when stdout drains or the sidecar ends first. When it passes, the sidecar ends at once ("the app stopped
//   reading"): no more admissions, events, channel or proxy, one terminal frame attempted, then the flush deadline.
//   A drain after the end does nothing.
// - When it ends it flushes stdout and exits 0, within LIMITS.flushMs whether or not the app read it all. If stdout
//   breaks (Rust is gone), it ends the same way.
// - stderr: the proxy's log events, one JSON line each (counts and refusals; host names only for refusals); Rust
//   caps stderr and never forwards it.
//
//   node lib/fleet/browser/sidecar-net-main.mjs

import { fileURLToPath } from "node:url";
import { createDecoder, createEncoder, FrameError } from "./frames.mjs";
import { NetSidecar } from "./sidecar-net.mjs";
import { createProxy } from "./proxy.mjs";
import { accountOrigins, DEFAULT_ACCOUNT_ORIGINS } from "./urls.mjs";

export const LIMITS = Object.freeze({ outBytes: 8 * 1024 * 1024, reserveBytes: 64 * 1024, flushMs: 2000, stallMs: 30000 });

/**
 * The one writer: frames go out in order; a frame that would pass its bound isn't written (false), and the caller
 * ends. `onFull()` is called when stdout asks the writer to wait (its write returned false), `onDrain()` when it has
 * drained again.
 */
export function createWriter(stdout, limits = LIMITS, { onFull = () => {}, onDrain = () => {} } = {}) {
  let waiting = false;
  return (frame, { terminal = false } = {}) => {
    const room = limits.outBytes + (terminal ? limits.reserveBytes : 0);
    if ((stdout.writableLength ?? 0) + frame.length > room) return false;
    if (!stdout.write(frame) && !waiting) {
      waiting = true;
      onFull();
      stdout.once?.("drain", () => { waiting = false; onDrain(); });
    }
    return true;
  };
}

/**
 * Run one net sidecar. Injectable for tests, in code only: `stdin`, `stdout`, `stderr`, `exit`, `makeProxy`,
 * `makeChannel` (auth's channel, when it exists), `limits`, `timers` ({ setTimeout, clearTimeout }). Returns the
 * sidecar, started.
 */
export function main({
  stdin = process.stdin,
  stdout = process.stdout,
  stderr = process.stderr,
  exit = (code) => process.exit(code),
  makeChannel = null,
  makeProxy = null,
  limits = LIMITS,
  timers = globalThis,
} = {}) {
  limits = { ...LIMITS, ...limits }; // (a test may set some bounds; the rest keep their values)
  const origins = accountOrigins(DEFAULT_ACCOUNT_ORIGINS);
  const encode = createEncoder({ from: "net" });
  const decoder = createDecoder({ to: "net" });
  let sidecar, ended = false, exited = false, stall = null;
  const clearStall = () => { if (stall !== null) { timers.clearTimeout(stall); stall = null; } };
  const write = createWriter(stdout, limits, {
    onFull: () => {
      stdin.pause?.(); // (no more frames from the app until it reads ours)
      if (!ended && stall === null) stall = timers.setTimeout(() => { stall = null; if (!ended) sidecar.fail("the app stopped reading"); }, limits.stallMs);
    },
    onDrain: () => { clearStall(); if (!ended) stdin.resume?.(); }, // (a drain after the end does nothing)
  });
  const leave = () => { if (!exited) { exited = true; exit(0); } };

  // (true, or the reason the frame didn't go out; NetSidecar ends at once on a reason)
  const send = (head, body, { terminal = false } = {}) => {
    if (ended) return "ended";
    let frame;
    try { frame = encode(head, body); } catch (e) {
      if (e instanceof FrameError) return "an unencodable frame";
      throw e;
    }
    return write(frame, { terminal: terminal && head.kind === "rust.net_state" && head.state === "ended" }) || "the app isn't reading";
  };
  const onEnd = () => {
    if (ended) return;
    ended = true;
    clearStall();
    stdin.pause?.();
    timers.setTimeout(leave, limits.flushMs); // (the flush deadline: exit even if the app never reads the rest)
    stdout.end(leave);
  };
  const defaultProxy = async ({ username, password }) => {
    const proxy = createProxy({ session: { username, password, origins }, log: (e) => stderr.write(JSON.stringify({ proxy: e }) + "\n") });
    const port = await proxy.listen();
    return { port, close: () => proxy.close() };
  };
  sidecar = new NetSidecar({ send, makeProxy: makeProxy ?? defaultProxy, makeChannel, onEnd });

  stdin.on("data", (chunk) => {
    if (ended) return;
    let frames;
    try { frames = decoder.push(chunk); } catch (e) {
      if (e instanceof FrameError) return sidecar.fail("a bad frame from the app");
      throw e;
    }
    for (const f of frames) { if (ended) break; sidecar.frame(f.head, f.body); }
  });
  stdin.on("end", () => {
    if (ended) return;
    try { decoder.end(); } catch { return sidecar.fail("the app's channel ended inside a frame"); }
    sidecar.fail("the app closed the channel");
  });
  stdin.on("error", () => { if (!ended) sidecar.fail("the app's channel failed"); });
  stdout.on("error", () => { if (!ended) sidecar.fail("the app's channel failed"); }); // (EPIPE: Rust is gone)
  sidecar.begin();
  return sidecar;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main();
