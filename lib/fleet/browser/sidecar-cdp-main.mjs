// Fleet protocol, the browser lane: the cdp sidecar's process. The app (Rust) starts it on its pinned Node, one per
// browser session, with Chrome's debugging pipe at fds 3 (Chrome reads it: the sidecar writes) and 4 (Chrome writes
// it: the sidecar reads), and frames on stdin and stdout (./frames.mjs). It has no network, takes no configuration
// from its environment or arguments, and ends when the session does.
//
// - stdin: decoded strictly as frames to cdp; any frame error, or stdin ending (inside a frame or not), ends the
//   sidecar.
// - stdout: every frame the sidecar sends, encoded strictly as from cdp; a frame the encoder refuses (a bug) ends it.
// - The session: a BrowserSession over a Filter, hardened (./harden.mjs) with the proxy credentials from
//   cdp.proxy_auth and the permission list pinned for the running Chrome build (PINS.permissions).
// - When the sidecar ends it flushes stdout and exits 0; Rust sees rust.cdp_state ended with the reason first. If
//   stdout breaks (Rust is gone), the session retires and it exits 0 without flushing.
//
//   node lib/fleet/browser/sidecar-cdp-main.mjs

import { Socket } from "node:net";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { createDecoder, createEncoder, FrameError } from "./frames.mjs";
import { openPipe } from "./pipe.mjs";
import { CdpSidecar, sessionFactory } from "./sidecar-cdp.mjs";
import { pinnedPermissions } from "./harden.mjs";
import { loadProgram } from "./rewrite.mjs";
import { compileCommands } from "./params.mjs";
import { accountOrigins, DEFAULT_ACCOUNT_ORIGINS } from "./urls.mjs";
import { PINS } from "./pins.mjs";

const read = (f) => readFileSync(new URL(`../../../${f}`, import.meta.url));

/**
 * Run one cdp sidecar. Everything is injectable for tests (in code only: the process itself takes nothing): `stdin`,
 * `stdout`, Chrome's pipe ends (`chromeRead`, `chromeWrite`), `pinned` (the permission pins) or `permissions` (build -> list), `exit`.
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
} = {}) {
  const spec = JSON.parse(read(PINS.spec.file));
  const program = loadProgram(read(PINS.program.file), PINS.program.sha256);
  const commands = compileCommands(spec);
  const origins = accountOrigins(DEFAULT_ACCOUNT_ORIGINS);
  const encode = createEncoder({ from: "cdp" });
  const decoder = createDecoder({ to: "cdp" });
  let sidecar, ended = false;

  const send = (head, body) => {
    let frame;
    try { frame = encode(head, body); } catch (e) {
      if (e instanceof FrameError && !ended) return void queueMicrotask(() => sidecar.fail("an unencodable frame"));
      if (e instanceof FrameError) return; // (already ending: nothing more goes out)
      throw e;
    }
    stdout.write(frame);
  };
  const onEnd = () => {
    if (ended) return;
    ended = true;
    stdin.pause?.();
    stdout.end(() => exit(0)); // (called on a broken output too, with its error)
  };
  sidecar = new CdpSidecar({
    send,
    openPipe: ({ pid }) => openPipe({ read: chromeRead(), write: chromeWrite(), pid }),
    makeSession: sessionFactory({ spec, program, commands, origins, permissions }),
    onEnd,
  });

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
  return sidecar;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main();
