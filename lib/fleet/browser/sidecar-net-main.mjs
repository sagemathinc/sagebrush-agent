// Fleet protocol, the browser lane: the net sidecar's process. The app (Rust) starts it on its pinned Node, one per
// browser session, with frames on stdin and stdout (./frames.mjs). It takes no configuration from its environment or
// arguments, makes its own channel key and proxy credentials, listens for Chrome on 127.0.0.1, and ends when the
// session does.
//
// - stdin: decoded strictly as frames to net; any frame error, or stdin ending (inside a frame or not), ends it.
// - stdout: one writer for every frame (the #46 ruling). Data frames (cdp.command) may fill the output up to
//   LIMITS.outBytes of unwritten bytes; state frames (rust.net_hello, rust.net_state) may also use LIMITS.reserveBytes
//   beyond it, so "ended" can always be said. A frame that doesn't fit ends the sidecar ("the app isn't reading").
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

export const LIMITS = Object.freeze({ outBytes: 8 * 1024 * 1024, reserveBytes: 64 * 1024, flushMs: 2000 });

/** The one writer: frames go out in order; a frame that would pass its bound isn't written, and the caller ends. */
export function createWriter(stdout, limits = LIMITS) {
  return (frame, { control = false } = {}) => {
    const room = limits.outBytes + (control ? limits.reserveBytes : 0);
    if ((stdout.writableLength ?? 0) + frame.length > room) return false;
    stdout.write(frame);
    return true;
  };
}

/**
 * Run one net sidecar. Injectable for tests, in code only: `stdin`, `stdout`, `stderr`, `exit`, `makeProxy`,
 * `makeChannel` (auth's channel, when it exists), `limits`. Returns the sidecar, started.
 */
export function main({
  stdin = process.stdin,
  stdout = process.stdout,
  stderr = process.stderr,
  exit = (code) => process.exit(code),
  makeChannel = null,
  makeProxy = null,
  limits = LIMITS,
} = {}) {
  const origins = accountOrigins(DEFAULT_ACCOUNT_ORIGINS);
  const encode = createEncoder({ from: "net" });
  const decoder = createDecoder({ to: "net" });
  const write = createWriter(stdout, limits);
  let sidecar, ended = false, exited = false;
  const leave = () => { if (!exited) { exited = true; exit(0); } };

  const send = (head, body, { control = false } = {}) => {
    if (ended && !(control && head.kind === "rust.net_state")) return;
    let frame;
    try { frame = encode(head, body); } catch (e) {
      if (e instanceof FrameError) { if (!ended) queueMicrotask(() => sidecar.fail("an unencodable frame")); return; }
      throw e;
    }
    if (!write(frame, { control }) && !ended) queueMicrotask(() => sidecar.fail("the app isn't reading"));
  };
  const onEnd = () => {
    if (ended) return;
    ended = true;
    stdin.pause?.();
    setTimeout(leave, limits.flushMs); // (the flush deadline: exit even if the app never reads the rest)
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
