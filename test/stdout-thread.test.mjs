// ThreadStdout (lib/stdout-thread.mjs): a child writes through it while its parent stops reading the pipe. The shape
// is the Windows probe that found the problem (40 writes of 64 KiB, the reader paused): here no write call may block,
// the event loop keeps running while the reader is stalled, write returns false at the high-water mark, and every
// byte arrives, in order, with every callback called.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const LIB = fileURLToPath(new URL("../lib/stdout-thread.mjs", import.meta.url));
const N = 40, SIZE = 64 * 1024;

const child = (body) => spawn(process.execPath, ["--input-type=module", "-e", `
import { pathToFileURL } from "node:url";
const { ThreadStdout } = await import(pathToFileURL(${JSON.stringify(LIB)}).href);
${body}`], { stdio: ["ignore", "pipe", "pipe"] });

test("stdout thread: a stalled reader blocks no write and no timer; false at the high-water mark; all bytes, in order", async () => {
  const c = child(`
    const out = new ThreadStdout();
    let ticks = 0, calls = 0, falses = 0, maxLen = 0, longest = 0;
    const iv = setInterval(() => ticks++, 10);
    for (let i = 0; i < ${N}; i++) {
      const t = performance.now();
      const ok = out.write(Buffer.alloc(${SIZE}, 65 + (i % 26)), () => calls++);
      longest = Math.max(longest, performance.now() - t);
      maxLen = Math.max(maxLen, out.writableLength);
      if (!ok) { falses++; await new Promise((r) => out.once("drain", r)); }
    }
    await out.flush(30000);
    clearInterval(iv);
    process.stderr.write(JSON.stringify({ ticks, calls, falses, maxLen, longest, left: out.writableLength }));
  `);
  const got = [];
  let err = "";
  c.stderr.on("data", (d) => (err += d));
  c.stdout.pause();
  await new Promise((r) => setTimeout(r, 1500)); // (the reader stalls; the verdict comes from the child's counts)
  c.stdout.on("data", (d) => got.push(d));
  c.stdout.resume();
  const code = await new Promise((r) => c.on("exit", r));
  assert.equal(code, 0, err);
  const r = JSON.parse(err);
  assert.ok(r.longest < 100, `no write call blocks (longest ${r.longest} ms)`);
  assert.ok(r.ticks >= 50, `the event loop ran while the reader was stalled (${r.ticks} ticks of 10 ms)`);
  assert.ok(r.falses >= 1, "write returned false at the high-water mark");
  assert.ok(r.maxLen <= 128 * 1024, `the copies handed over stay within 128 KiB (${r.maxLen})`);
  assert.equal(r.calls, N, "every callback was called");
  assert.equal(r.left, 0);
  const all = Buffer.concat(got);
  assert.equal(all.length, N * SIZE);
  for (let i = 0; i < N; i++) assert.equal(all[i * SIZE], 65 + (i % 26), `chunk ${i} in its place`);
});

test("stdout thread: a reader that goes away: \"error\" then \"close\", every callback called with the error, later writes refused", async () => {
  const c = child(`
    const out = new ThreadStdout();
    const seen = [];
    let errs = 0;
    out.on("error", (e) => seen.push("error:" + e.code));
    out.on("close", () => seen.push("close"));
    const big = Buffer.alloc(${SIZE}, 120);
    // (keep writing until the pipe breaks; each callback reports whether it got the error)
    for (let i = 0; i < 400 && !seen.length; i++) {
      out.write(big, (e) => { if (e) errs++; });
      await new Promise((r) => setTimeout(r, 5));
    }
    const after = out.write(big);
    process.stderr.write(JSON.stringify({ seen, errs, after, left: out.writableLength }));
  `);
  let err = "";
  c.stderr.on("data", (d) => (err += d));
  await new Promise((r) => c.stdout.once("data", r));
  c.stdout.destroy(); // (the runner closes its end)
  const code = await new Promise((r) => c.on("exit", r));
  assert.equal(code, 0, err);
  const r = JSON.parse(err);
  assert.equal(r.seen[0].startsWith("error:"), true, `error first: ${r.seen}`);
  assert.equal(r.seen[1], "close");
  assert.ok(r.errs >= 1, "the chunks not written had their callbacks called with the error");
  assert.equal(r.after, false, "a write after the end is refused");
  assert.equal(r.left, 0);
});
