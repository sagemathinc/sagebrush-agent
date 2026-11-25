// The net sidecar's makeChannel (lib/fleet/browser/channel-net.mjs) resuming against a host that runs the real
// acceptance (lib/fleet/channel/accept.mjs: the signed record, Noise, and the durable compare-and-set, which takes a
// resume only at the stored resume_n + 1). A stand-in host that answers any resume_n can't catch an app that skips
// one; this one refuses it, as a host does.
//
// The rule (channel §3.3 and its addendum A2): resume_n moves only on an authenticated message 2. Accepted: the next
// is resume_n + 1. Refused (the host already has this record live at resume_n, because its reply was lost): the next
// is resume_n + 1. With no valid message 2 (message 1 never sent, or sent and nothing came back) the next attempt keeps
// resume_n, with a new request id and token.

import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { WebSocketServer } from "ws";
import { test } from "./host-linux-only.mjs";
import { b64, newId, keyFromSeed, seal, applyChainEntry as apply, hostFingerprint, verifyHostCert, FleetError } from "../lib/fleet/index.mjs";
import { lockDir } from "../lib/fleet/host/store.mjs";
import { acceptMessage1, openChannelStore } from "../lib/fleet/channel/accept.mjs";
import { parseOpenTarget } from "../lib/fleet/core/relay.mjs";
import { x25519Generate } from "../lib/fleet/channel/noise.mjs";
import { netChannel, wsOpen } from "../lib/fleet/browser/channel-net.mjs";
import { channelKey } from "../lib/fleet/browser/sidecar-net.mjs";

const AUD = "https://dev.sagebrush.space";
const tick = (ms = 0) => new Promise((r) => setTimeout(r, ms));
async function until(cond, ms = 4000, what = "the condition") {
  const end = Date.now() + ms;
  while (!cond()) { if (Date.now() > end) throw new Error(`timed out waiting for ${what}`); await tick(5); }
}
const token = () => `rt1.${randomBytes(32).toString("base64url")}`;
function loopbackOpen(url, headers) {
  if (!/^ws:\/\/127\.0\.0\.1:[0-9]+\//.test(url)) throw new Error("a test open outside loopback");
  return wsOpen(url, headers);
}

let seed = 60;
const key = () => keyFromSeed(new Uint8Array(32).fill(seed++));

/**
 * A fleet (a native device's chain), a host (its certified X25519 key, its channel store) and a session record for
 * the app's channel key; then a local server standing in for the relay and the host. `plan` says what each attempt
 * meets, in order: "reject" (the upgrade refused with 403), "reset" (the connection reset during the upgrade),
 * "drop" (the socket closed right after the upgrade, before the host reads message 1), "accept" (the real acceptance
 * and its message 2, kept open), "accept-close" (accepted, then the transport lost), "commit-drop" (accepted and
 * committed, then the socket closed with no message 2: a lost reply), "refuse-drop" (the host's refusal not delivered).
 * Whenever the real acceptance answers with its refusal (the record already live at that counter), the host sends it
 * as message 2 and closes the socket, unless the step is "refuse-drop".
 */
async function world(t, plan, { wrapOpen = (o) => o } = {}) {
  const fleet = newId(), host = newId(), agent = newId(), ctx = { aud: AUD, fleet };
  const N = key(), nId = newId(), rec = key();
  const sN = { kind: "device", id: nId, alg: "ed25519", key: N.key };
  const chain = (await apply(null, seal("sb.device-chain.v1", sN, { fleet, aud: AUD, seq: 0, prev: "", op: "genesis", at_ms: 1, auth_time_ms: 1,
    device: { id: nId, alg: "ed25519", key: b64(N.raw), name: "mac", tier: "native" }, recovery_key: { alg: "ed25519", key: b64(rec.raw) } }, N), ctx)).state;
  const H = key(), encKey = x25519Generate();
  const fp = await hostFingerprint(host, H.raw, encKey.raw);
  const cert = await verifyHostCert(seal("sb.host-cert.v1", sN, { fleet, aud: AUD, chain_seq: 0, host, sign_key: b64(H.raw), enc_key: b64(encKey.raw), fingerprint: b64(fp), name: "box", at_ms: 1 }, N), { ...ctx, chain });
  const dir = mkdtempSync(join(tmpdir(), "net-channel-resume-"));
  const lock = await lockDir(dir);
  const store = openChannelStore(dir, lock);
  const app = channelKey();
  const now = Date.now();
  const body = { fleet, aud: AUD, at_ms: now - 1000, not_before_ms: now - 1000, not_after_ms: now + 3_600_000, session: newId(), host, agent,
    browser_gen: 1, host_gen: 3, chain_seq: 0, app_session_pub: app.pub, account_origins_manifest_sha256: b64(new Uint8Array(32).fill(1)),
    exceptions_sha256: b64(new Uint8Array(32).fill(2)) };
  const record = seal("sb.browser-session.v1", sN, body, N);

  const h = { opens: [], accepted: [], refused: [], refusals: [], sockets: [], asks: [] };
  let attempt = 0;
  const step = () => plan[Math.min(attempt, plan.length - 1)];
  const wss = new WebSocketServer({
    host: "127.0.0.1", port: 0, perMessageDeflate: false,
    verifyClient: (info, done) => {
      h.opens.push(parseOpenTarget(info.req.url).resume_n);
      if (step() === "reject") { attempt++; return done(false, 403); }
      if (step() === "reset") { attempt++; info.req.socket.destroy(); return; }
      done(true);
    },
  });
  await new Promise((r) => wss.once("listening", r));
  wss.on("connection", (socket, req) => {
    const what = step();
    attempt++;
    h.sockets.push(socket);
    const n = parseOpenTarget(req.url).resume_n;
    if (what === "drop") return socket.terminate();
    socket.once("message", async (data) => {
      const prologue = { fleet, aud: AUD, session: body.session, host, agent, browser_gen: body.browser_gen, host_gen: 3, resume_n: n };
      let a;
      try {
        a = await acceptMessage1(new Uint8Array(data), { self: { host, aud: AUD, fleet }, prologue, encKey, cert, chain, store, now: Date.now(), live: () => {} });
      } catch (e) {
        h.refused.push({ n, code: e instanceof FleetError ? e.code : String(e) });
        return socket.terminate();
      }
      if (a.refused) {
        h.refusals.push(a.refused.resume_n);
        if (what === "refuse-drop") return socket.terminate();
        socket.send(a.reply().message, { binary: true });
        return setTimeout(() => socket.terminate(), 30); // (the host closes its candidate after the refusal)
      }
      h.accepted.push(n);
      if (what === "commit-drop") return socket.terminate();
      socket.send(a.reply().message, { binary: true });
      if (what === "accept-close") setTimeout(() => socket.terminate(), 30);
    });
  });
  const url = `ws://127.0.0.1:${wss.address().port}/`;
  const states = [];
  const make = netChannel({ allowLoopback: true, open: wrapOpen(loopbackOpen), authToken: async (o) => { const tk = token(); h.asks.push({ resume_n: o.resume_n, request: o.request, token: tk }); return tk; }, retryMs: 20, handshakeMs: 2000 });
  const c = make({
    start: { session: body.session, browserGen: 1, hostStaticPub: Buffer.from(encKey.raw).toString("base64url"), relayUrl: url },
    record, key: app, policy: { exceptions: [] }, onCommand() {}, onState: (s, reason) => states.push(reason ? `${s}:${reason}` : s),
  });
  t.after(async () => {
    c.close();
    for (const s of h.sockets) s.terminate();
    await new Promise((r) => wss.close(() => r()));
    await lock.release();
    rmSync(dir, { recursive: true, force: true });
  });
  return { h, c, states, opens: () => states.filter((s) => s === "open").length };
}

test("a connection reset before the upgrade completes (so message 1 was never sent) is retried at the same resume_n, and the host takes it", async (t) => {
  const { h, opens } = await world(t, ["accept-close", "reset", "reset", "accept"]);
  await until(() => opens() === 2, 4000, "the second open");
  assert.deepEqual(h.opens, [0, 1, 1, 1], "0, then 1 for each attempt that never sent message 1");
  assert.deepEqual(h.accepted, [0, 1]);
  assert.deepEqual(h.refused, [], "the host refused nothing");
});

test("an upgrade the relay refuses keeps the resume_n, at the start and when resuming", async (t) => {
  const { h, opens } = await world(t, ["reject", "accept-close", "reject", "reject", "accept"]);
  await until(() => opens() === 2, 4000, "the second open");
  assert.deepEqual(h.opens, [0, 0, 1, 1, 1]);
  assert.deepEqual(h.accepted, [0, 1]);
  assert.deepEqual(h.refused, []);
});

test("once message 1 has gone out and the host committed, the next attempt is resume_n + 1", async (t) => {
  const { h, opens } = await world(t, ["accept-close", "accept-close", "accept"]);
  await until(() => opens() === 3, 4000, "the third open");
  assert.deepEqual(h.opens, [0, 1, 2]);
  assert.deepEqual(h.accepted, [0, 1, 2]);
  assert.deepEqual(h.refused, []);
});

test("an opened socket whose first send throws never handed message 1 over: the next attempt keeps the resume_n, with a fresh request and token", async (t) => {
  let sockets = 0, thrown = 0;
  // (the second transport's first send throws, as a socket closing under the send does)
  const wrapOpen = (open) => async (url, headers) => {
    const ws = await open(url, headers);
    if (++sockets === 2) {
      const send = ws.send.bind(ws);
      let first = true;
      ws.send = (...a) => { if (first) { first = false; thrown++; throw new Error("send failed"); } return send(...a); };
    }
    return ws;
  };
  const { h, opens } = await world(t, ["accept-close", "accept", "accept"], { wrapOpen });
  await until(() => opens() === 2, 4000, "the second open");
  assert.equal(thrown, 1, "the send threw once");
  assert.deepEqual(h.opens, [0, 1, 1], "the attempt after the throw keeps resume_n 1");
  assert.deepEqual(h.accepted, [0, 1]);
  assert.deepEqual(h.refused, []);
  assert.deepEqual(h.asks.map((a) => a.resume_n), [0, 1, 1]);
  assert.notEqual(h.asks[1].request, h.asks[2].request, "a fresh request id");
  assert.notEqual(h.asks[1].token, h.asks[2].token, "a fresh token");
});

test("a fresh session's reply lost after the commit: the retry at 0 gets the host's refusal naming 0, then 1 is accepted", async (t) => {
  const { h, opens } = await world(t, ["commit-drop", "accept"]);
  // (the wire first: the third attempt's counter is what the refusal decides)
  await until(() => h.opens.length >= 3, 4000, "three attempts");
  assert.deepEqual(h.opens.slice(0, 3), [0, 0, 1], "after the refusal naming 0, the next attempt is 1");
  await until(() => opens() === 1, 4000, "the open");
  assert.deepEqual(h.opens, [0, 0, 1]);
  assert.deepEqual(h.accepted, [0, 1], "0 committed once, then 1");
  assert.deepEqual(h.refusals, [0], "the retry at 0 met the authenticated refusal");
  assert.deepEqual(h.refused, [], "no silent refusal");
});

test("a resume's reply lost after the commit: the retry at the same resume_n is refused by the host, and the next is accepted", async (t) => {
  const { h, opens } = await world(t, ["accept-close", "commit-drop", "accept"]);
  await until(() => opens() === 2, 4000, "the second open");
  assert.deepEqual(h.opens, [0, 1, 1, 2]);
  assert.deepEqual(h.accepted, [0, 1, 2]);
  assert.deepEqual(h.refusals, [1]);
  assert.deepEqual(h.refused, []);
});

test("the refusal itself lost: the app keeps resume_n until a refusal arrives, then moves on", async (t) => {
  const { h, opens } = await world(t, ["commit-drop", "refuse-drop", "refuse-drop", "accept"]);
  await until(() => opens() === 1, 4000, "the open");
  assert.deepEqual(h.opens, [0, 0, 0, 0, 1]);
  assert.deepEqual(h.refusals, [0, 0, 0], "each retry at 0 was refused; two refusals were lost");
  assert.deepEqual(h.accepted, [0, 1]);
  assert.deepEqual(h.refused, []);
});

test("the socket closed right after the upgrade, before the host read message 1: the app keeps resume_n, and recovers", async (t) => {
  const { h, opens } = await world(t, ["accept-close", "drop", "drop", "accept"]);
  await until(() => opens() === 2, 4000, "the second open");
  assert.deepEqual(h.opens, [0, 1, 1, 1], "no climbing counter");
  assert.deepEqual(h.accepted, [0, 1]);
  assert.deepEqual(h.refusals, []);
  assert.deepEqual(h.refused, []);
});
