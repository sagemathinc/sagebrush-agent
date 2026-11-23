// The extraction of one source archive, in a worker thread (#1663, design r3 §3): the gunzip and the tar sink never
// run on the agent's own event loop, and the parent terminates this worker at its deadline. In: workerData
// { archive: Uint8Array (the downloaded .tar.gz), dir: the empty staging folder, commit }. Out: one message,
// { ok: true, index } or { ok: false, why } (fixed words from the sink; never another error's own text).
import { parentPort, workerData } from "node:worker_threads";
import { createGunzip } from "node:zlib";
import { SourceArchiveError, sourceTarSink } from "./source-tar.mjs";

const { archive, dir, commit } = workerData;
const say = (m) => { parentPort.postMessage(m); };
let sink;
try { sink = sourceTarSink(dir, commit); } catch (e) { say({ ok: false, why: e instanceof SourceArchiveError ? e.message : "the source archive couldn't be read" }); }
if (sink) {
  const gz = createGunzip({ chunkSize: 64 * 1024 });
  let failed = false;
  const fail = (e) => {
    if (failed) return;
    failed = true;
    say({ ok: false, why: e instanceof SourceArchiveError ? e.message : "the source archive isn't a readable gzip" });
    gz.destroy();
  };
  gz.on("data", (c) => { if (!failed) { try { sink.write(c); } catch (e) { fail(e); } } });
  gz.on("error", (e) => fail(e));
  gz.on("end", () => { if (failed) return; try { say({ ok: true, index: sink.end() }); } catch (e) { fail(e); } });
  gz.end(Buffer.from(archive.buffer, archive.byteOffset, archive.byteLength));
}
