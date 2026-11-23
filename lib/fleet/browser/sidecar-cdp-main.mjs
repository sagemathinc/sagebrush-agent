// Fleet protocol, the browser lane: the cdp sidecar's process. The app (Rust) starts it on its pinned Node, one per
// browser session, with Chrome's debugging pipe at fds 3 (Chrome reads it: the sidecar writes) and 4 (Chrome writes
// it: the sidecar reads), and frames on stdin and stdout (./frames.mjs). It has no network, takes no configuration
// from its environment or arguments, and ends when the session does.
//
// - stdin: decoded strictly as frames to cdp; any frame error, or stdin ending (inside a frame or not), ends the
//   sidecar.
// - stdout: every frame the sidecar sends (answers, events and its state alike), encoded strictly as from cdp, through
//   one bounded writer. A frame the encoder refuses (a bug) ends it.
//   - Backpressure: while stdout wants a drain, stdin isn't read, so no new commands come in.
//   - The cap: at most OUT_MAX bytes written and not yet taken by the app. OUT_RESERVE of it is kept for the terminal
//     frame (rust.cdp_state ended), so the end reason can always be written. A frame that wouldn't fit ends the
//     sidecar ("the app isn't reading its channel"): from then on only the terminal frame goes out, and no command or
//     Chrome event is taken.
// - The session: a BrowserSession over a Filter, hardened (./harden.mjs) with the proxy credentials from
//   cdp.proxy_auth and the permission list pinned for the running Chrome build (PINS.permissions).
// - When the sidecar ends it flushes stdout and exits 0; Rust sees rust.cdp_state ended with the reason first. If
//   stdout breaks (Rust is gone), the session retires and it exits 0 without flushing. A flush that hasn't finished
//   FLUSH_MS after the end is abandoned: one fixed line on stderr, and it exits 0 all the same.
//
//   node lib/fleet/browser/sidecar-cdp-main.mjs

import { Socket } from "node:net";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { createDecoder, createEncoder, FrameError, LIMITS } from "./frames.mjs";
import { openPipe } from "./pipe.mjs";
import { CdpSidecar, sessionFactory } from "./sidecar-cdp.mjs";
import { pinnedPermissions } from "./harden.mjs";
import { loadProgram } from "./rewrite.mjs";
import { compileCommands } from "./params.mjs";
import { accountOrigins, DEFAULT_ACCOUNT_ORIGINS } from "./urls.mjs";
import { PINS } from "./pins.mjs";

const read = (f) => readFileSync(new URL(`../../../${f}`, import.meta.url));

/** Output bytes written and not yet taken by the app, at most: two of the largest answers the spec allows (8 MiB
 * each, with their heads), and the reserve. */
export const OUT_MAX = 17 * 1024 * 1024;
/** Kept inside OUT_MAX for the terminal frame: a frame with a head and no body is at most this. */
export const OUT_RESERVE = 8 + LIMITS.headBytes;
/** How long the final flush may take before the process exits regardless. */
export const FLUSH_MS = 5000;
const REAL_CLOCK = Object.freeze({ setTimeout: (f, ms) => setTimeout(f, ms), clearTimeout: (h) => clearTimeout(h) });
const terminal = (head) => head?.to === "rust" && head.kind === "rust.cdp_state" && head.state === "ended";

/**
 * Run one cdp sidecar. Everything is injectable for tests (in code only: the process itself takes nothing): `stdin`,
 * `stdout`, Chrome's pipe ends (`chromeRead`, `chromeWrite`), `pinned` (the permission pins) or `permissions` (build -> list), `exit`,
 * `log` (stderr), `clock`, and `outMax` (OUT_MAX).
 * Returns the sidecar, wired.
 */
export function main({
  stdin = process.stdin,
  stdout = process.stdout,
  chromeRead = () => new Socket({ fd: 4, readable: true, writable: false }),
  chromeWrite = () => new Socket({ fd: 3, readable: false, writable: true }),
  pinned = PINS.permissions,
  permissions = (build) => pinnedPermissions(build, { pinned }),
  exit = (code) => process.exit(code),
  log = (line) => { try { process.stderr.write(`${line}\n`); } catch { /* (exiting regardless) */ } },
  clock = REAL_CLOCK,
  outMax = OUT_MAX,
} = {}) {
  const spec = JSON.parse(read(PINS.spec.file));
  const program = loadProgram(read(PINS.program.file), PINS.program.sha256);
  const commands = compileCommands(spec);
  const origins = accountOrigins(DEFAULT_ACCOUNT_ORIGINS);
  const encode = createEncoder({ from: "cdp" });
  const decoder = createDecoder({ to: "cdp" });
  let sidecar, ended = false, full = false, pending = 0, waiting = false;
  const notReading = () => { full = true; stdin.pause?.(); sidecar.fail("the app isn't reading its channel"); };

  // The one writer: every frame goes out here, counted until the app has taken it.
  const send = (head, body) => {
    const last = terminal(head);
    if (full && !last) return; // (past the cap only the terminal frame goes out)
    let frame;
    try { frame = encode(head, body); } catch (e) {
      if (e instanceof FrameError && !ended) return void queueMicrotask(() => sidecar.fail("an unencodable frame"));
      if (e instanceof FrameError) return; // (already ending: nothing more goes out)
      throw e;
    }
    if (pending + frame.length > (last ? outMax : outMax - OUT_RESERVE)) {
      if (last) return; // (can't happen: the reserve holds it)
      full = true;
      stdin.pause?.();
      return void queueMicrotask(notReading);
    }
    pending += frame.length;
    const n = frame.length;
    if (stdout.write(frame, () => { pending -= n; }) || waiting) return;
    waiting = true;
    stdin.pause?.();
    stdout.once("drain", () => { waiting = false; if (!ended && !full) stdin.resume?.(); });
  };
  const onEnd = () => {
    if (ended) return;
    ended = true;
    stdin.pause?.();
    let done = false;
    const finish = () => { if (done) return; done = true; clock.clearTimeout(timer); exit(0); };
    const timer = clock.setTimeout(() => { if (!done) log("cdp sidecar: the final flush didn't finish in time"); finish(); }, FLUSH_MS);
    stdout.end(finish); // (called on a broken output too, with its error)
  };
  sidecar = new CdpSidecar({
    send,
    openPipe: ({ pid }) => openPipe({ read: chromeRead(), write: chromeWrite(), pid }),
    makeSession: sessionFactory({ spec, program, commands, origins, permissions }),
    onEnd,
  });

  stdin.on("data", (chunk) => {
    if (ended || full) return;
    let frames;
    try { frames = decoder.push(chunk); } catch (e) {
      if (e instanceof FrameError) return sidecar.fail("a bad frame from the app");
      throw e;
    }
    for (const f of frames) { if (ended || full) break; sidecar.frame(f.head, f.body); }
  });
  stdin.on("end", () => {
    if (ended) return;
    try { decoder.end(); } catch { return sidecar.fail("the app's channel ended inside a frame"); }
    sidecar.fail("the app closed the channel");
  });
  stdin.on("error", () => { if (!ended) sidecar.fail("the app's channel failed"); });
  stdout.on("error", () => { if (!ended) sidecar.fail("the app's channel failed"); }); // (EPIPE: Rust is gone)
  return sidecar;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main();
