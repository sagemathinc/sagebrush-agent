// The net sidecar's relay token for each open (net-token frames r4): it asks Rust with rust.token_request
// { request, resume_n }, one at a time, and takes Rust's net.token (the token as the body) or net.token_refused,
// matched by request, within TOKEN_MS. A token or refusal for no outstanding request ends the sidecar. Driven through
// the process entry over real encoded frames; in the last row, the real net channel asks through it.

import assert from "node:assert/strict";
import { test } from "node:test";
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { randomBytes } from "node:crypto";
import { createEncoder, createDecoder } from "../lib/fleet/browser/frames.mjs";
import { main } from "../lib/fleet/browser/sidecar-net-main.mjs";
import { TOKEN_MS } from "../lib/fleet/browser/sidecar-net.mjs";

const fromRust = createEncoder({ from: "rust" });
const tick = () => new Promise((r) => setImmediate(r));
const req = () => randomBytes(16).toString("base64url");
const token = () => `rt1.${randomBytes(32).toString("base64url")}`;

function fakeStdout() {
  const out = new EventEmitter();
  out.chunks = [];
  out.writableLength = 0;
  out.write = (b) => { out.chunks.push(Buffer.from(b)); return true; };
  out.end = (cb) => { out.ended = true; setImmediate(cb); };
  out.frames = () => {
    const all = Buffer.concat(out.chunks), frames = [];
    for (let i = 0; i < all.length; ) {
      const n = 4 + all.readUInt32BE(i);
      frames.push(...createDecoder({ to: "rust", from: "net" }).push(all.subarray(i, i + n)));
      i += n;
    }
    return frames;
  };
  return out;
}

/** A manual clock: setTimeout keeps the callback; advance(ms) runs what falls due. */
function manualTimers() {
  let now = 0, id = 0;
  const due = new Map();
  return {
    setTimeout: (fn, ms) => { due.set(++id, { at: now + ms, fn }); return id; },
    clearTimeout: (i) => { due.delete(i); },
    advance(ms) {
      now += ms;
      for (const [i, t] of [...due]) if (t.at <= now) { due.delete(i); t.fn(); }
    },
  };
}

/** A live net sidecar (started, record in) with a fake channel, on fake stdio and a manual clock. */
async function live({ real = false } = {}) {
  const stdin = new PassThrough(), stdout = fakeStdout(), timers = manualTimers(), exits = [];
  const made = [];
  const sidecar = main({
    stdin, stdout, stderr: { write() {} }, exit: (c) => exits.push(c), timers,
    // (real: no makeChannel at all, so the process makes its own net channel)
    ...(real ? {} : { makeChannel: (args) => { made.push(args); return { result() {}, refused() {}, event() {}, takeover() {}, resume() {}, close() {} }; } }),
    makeProxy: async () => ({ port: 50300, close() {} }),
  });
  await tick();
  const push = async (head, body) => { stdin.write(fromRust(head, body)); await tick(); };
  return { sidecar, stdin, stdout, timers, exits, made, push, ended: () => stdout.frames().filter((f) => f.head.kind === "rust.net_state" && f.head.state === "ended").map((f) => f.head.reason) };
}
const START = (relay = "wss://relay.example/s") => ({ to: "net", kind: "net.start", session: "s-1", browser_gen: 2, host_static_pub: "h".repeat(43), relay_url: relay });
async function started(opts) {
  const t = await live(opts);
  await t.push(START());
  await t.push({ to: "net", kind: "net.record" }, Buffer.from("r"));
  return t;
}
/** A promise's state after a turn: "pending", "resolved" or "rejected" (without leaving a rejection unhandled). */
async function stateOf(p) {
  let st = "pending";
  p.then(() => { st = "resolved"; }, () => { st = "rejected"; });
  await tick();
  return st;
}
const asks = (t) => t.stdout.frames().filter((f) => f.head.kind === "rust.token_request").map((f) => ({ request: f.head.request, resume_n: f.head.resume_n }));

test("a token request goes to Rust as rust.token_request; Rust's net.token for that request resolves it", { timeout: 5000 }, async () => {
  const t = await started();
  const r = req(), tk = token();
  const p = t.sidecar.requestToken({ request: r, resume_n: 4 });
  await tick();
  assert.deepEqual(asks(t), [{ request: r, resume_n: 4 }]);
  await t.push({ to: "net", kind: "net.token", request: r }, Buffer.from(tk, "latin1"));
  assert.equal(await p, tk);
  // (the next request is allowed once the first is answered)
  const r2 = req(), p2 = t.sidecar.requestToken({ request: r2, resume_n: 4 });
  const refused = assert.rejects(p2, /token refused: rate/);
  await t.push({ to: "net", kind: "net.token_refused", request: r2, reason: "rate" });
  await refused;
  assert.deepEqual(t.ended(), [], "the sidecar goes on");
});

test("one outstanding request at a time: a second is refused and sends nothing", { timeout: 5000 }, async () => {
  const t = await started();
  const r = req();
  const p = t.sidecar.requestToken({ request: r, resume_n: 0 });
  const second = t.sidecar.requestToken({ request: req(), resume_n: 0 });
  second.catch(() => {}); // (checked below; never left unhandled)
  await tick();
  assert.equal(asks(t).length, 1, "only the first went to Rust");
  assert.equal(await stateOf(second), "rejected");
  await assert.rejects(second, /already outstanding/);
  await t.push({ to: "net", kind: "net.token", request: r }, Buffer.from(token(), "latin1"));
  await p;
});

test("no answer within TOKEN_MS rejects the request; an answer after that ends the sidecar", { timeout: 5000 }, async () => {
  const t = await started();
  const r = req();
  const p = t.sidecar.requestToken({ request: r, resume_n: 1 });
  t.timers.advance(TOKEN_MS - 1);
  await tick();
  let settled = false;
  p.then(() => { settled = true; }, () => { settled = true; });
  await tick();
  assert.equal(settled, false, "still waiting one millisecond before the deadline");
  t.timers.advance(1);
  assert.equal(await stateOf(p), "rejected", "rejected at the deadline");
  await assert.rejects(p, /no token in time/);
  await t.push({ to: "net", kind: "net.token", request: r }, Buffer.from(token(), "latin1"));
  assert.deepEqual(t.ended(), ["a token answer for no outstanding request"]);
});

test("a token or a refusal for no outstanding request, or for another request, ends the sidecar", { timeout: 5000 }, async () => {
  for (const [what, act] of [
    ["a token with nothing asked", (t) => t.push({ to: "net", kind: "net.token", request: req() }, Buffer.from(token(), "latin1"))],
    ["a refusal with nothing asked", (t) => t.push({ to: "net", kind: "net.token_refused", request: req(), reason: "ended" })],
    ["a token for another request", async (t) => { t.sidecar.requestToken({ request: req(), resume_n: 0 }).catch(() => {}); await tick(); await t.push({ to: "net", kind: "net.token", request: req() }, Buffer.from(token(), "latin1")); }],
  ]) {
    const t = await started();
    await act(t);
    assert.deepEqual(t.ended(), ["a token answer for no outstanding request"], what);
  }
});

test("no request before the session is live, and the sidecar's end rejects an outstanding one", { timeout: 5000 }, async () => {
  const t = await live();
  await t.push(START());
  await assert.rejects(t.sidecar.requestToken({ request: req(), resume_n: 0 }), /no live session/);
  assert.equal(asks(t).length, 0);
  await t.push({ to: "net", kind: "net.record" }, Buffer.from("r"));
  const q = t.sidecar.requestToken({ request: req(), resume_n: 0 });
  const p = assert.rejects(q, /the sidecar ended/);
  await t.push({ to: "net", kind: "net.retire" });
  assert.equal(await stateOf(q), "rejected", "the end rejects it");
  await p;
});

test("the token travels only in net.token's body: in no frame the sidecar writes, and in none of its end reasons", { timeout: 5000 }, async () => {
  const t = await started();
  const r = req(), tk = token();
  const p = t.sidecar.requestToken({ request: r, resume_n: 0 });
  await t.push({ to: "net", kind: "net.token", request: r }, Buffer.from(tk, "latin1"));
  await p;
  await t.push({ to: "net", kind: "net.retire" });
  const out = Buffer.concat(t.stdout.chunks).toString("latin1");
  assert.ok(!out.includes(tk.slice(4)), "no token in the sidecar's output");
});

test("wired: the process's own net channel asks Rust for each open's token, and a refusal ends the session with no socket", { timeout: 5000 }, async () => {
  // (no makeChannel: the real net channel; the record is the session's, for a trusted audience's relay)
  const t = await live({ real: true });
  const fields = { fleet: "f".repeat(22), aud: "https://sagebrush.space", session: "s-1", host: "o".repeat(22), agent: "a".repeat(22), browser_gen: 2, host_gen: 1 };
  await t.push({ ...START("wss://sagebrush.space"), host_static_pub: Buffer.alloc(32, 7).toString("base64url") });
  await t.push({ to: "net", kind: "net.record" }, Buffer.from(JSON.stringify({ v: 1, body: fields })));
  // (the channel's first attempt is on its own clock: wait for it, in real time, bounded)
  for (let i = 0; i < 200 && asks(t).length === 0 && t.ended().length === 0; i++) await new Promise((r) => setTimeout(r, 10));
  assert.deepEqual(t.ended(), [], "the channel didn't end before asking");
  const [a] = asks(t);
  assert.equal(a?.resume_n, 0, "the first open asks for resume_n 0");
  assert.match(a.request, /^[A-Za-z0-9_-]{21}[AQgw]$/);
  await t.push({ to: "net", kind: "net.token_refused", request: a.request, reason: "unauthenticated" });
  for (let i = 0; i < 200 && t.ended().length === 0; i++) await new Promise((r) => setTimeout(r, 10));
  assert.deepEqual(t.ended(), ["the channel ended"]);
  assert.equal(asks(t).length, 1, "no second ask after the refusal");
});
