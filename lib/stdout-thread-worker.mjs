// The worker thread behind ThreadStdout (stdout-thread.mjs): writes each chunk it is given to the file descriptor,
// in order, with blocking writes, and says when each is done. A pipe set non-blocking by someone else (EAGAIN) is
// retried after a short wait; any other error is reported once and nothing more is written.

import { parentPort, workerData } from "node:worker_threads";
import { writeSync } from "node:fs";

const { fd } = workerData;
const nap = new Int32Array(new SharedArrayBuffer(4));
let failed = false;

parentPort.on("message", ({ id, bytes }) => {
  if (failed) return;
  try {
    let at = 0;
    while (at < bytes.length) {
      try {
        at += writeSync(fd, bytes, at, bytes.length - at);
      } catch (e) {
        if (e?.code !== "EAGAIN") throw e;
        Atomics.wait(nap, 0, 0, 5);
      }
    }
    parentPort.postMessage({ id });
  } catch (e) {
    failed = true;
    parentPort.postMessage({ id, error: String(e?.code ?? e?.message ?? e) });
  }
});
