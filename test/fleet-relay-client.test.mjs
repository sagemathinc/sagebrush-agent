// The browser relay's control-plane client (lib/fleet/relay/control.mjs) over the core's contract
// (lib/fleet/core/control.mjs): each call accepts one answer, verified for that call only; an answer replayed from
// another call, an unsigned or non-200 answer, or one under another key is a failed call; the Worker consumes each
// service call id once. And the real HTTPS transport (verified TLS, no redirects, deadlines, the answer's size cap)
// against a local TLS server whose certificate is made for the test (skipped where openssl isn't installed).

import assert from "node:assert/strict";
import { test } from "node:test";
import { createServer } from "node:https";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { controlClient, httpsTransport, CONTROL, ControlError } from "../lib/fleet/relay/control.mjs";
import { controlKey, ANSWER_MAX, AUTH_HEADER } from "../lib/fleet/core/control.mjs";
import { FakeWorker, ids, KEY_TEXT, rid } from "./fleet-relay-harness.mjs";

const KEY = controlKey(KEY_TEXT());
const rejects = (p, code, what) => assert.rejects(p, (e) => e instanceof ControlError && e.code === code, what);
const hostOpen = (t) => ({ kind: "host", target: `/api/fleet/v1/relay/browser?role=host&fleet=${t.fleet}&session=${t.session}&agent=${t.agent}&browser_gen=1&host_gen=1&resume_n=0`, sig: `host=${t.host};gen=1;nonce=${rid()}` });

test("an admit call: the verified facts come back; a refusal comes back as a refusal with its closed code", async () => {
  const worker = new FakeWorker(KEY), t = ids();
  const client = controlClient({ transport: worker.transport, key: KEY });
  const a = await client.admit(hostOpen(t));
  assert.equal(a.result, "ok");
  assert.equal(a.role, "host");
  assert.equal(a.agent, t.agent);
  worker.decide = () => ({ result: "refused", code: "not_granted" });
  assert.equal((await client.admit(hostOpen(t))).code, "not_granted");
  worker.decide = () => ({ result: "refused", code: "replay" }); // (not in the closed list: the Worker can't even sign it)
  await rejects(client.admit(hostOpen(t)), "transport");
});

test("each call accepts only its own answer: one replayed from another call, an unsigned or non-200 answer, or one under another key is a failed call", async () => {
  const worker = new FakeWorker(KEY), t = ids();
  let captured = null;
  const capture = async (req) => { const r = await worker.transport(req); captured ??= r; return r; };
  const client = (transport, key = KEY) => controlClient({ transport, key });
  await client(capture).admit(hostOpen(t));
  await rejects(client(async () => captured).admit(hostOpen(t)), "answer", "a replayed answer");
  await rejects(client(async (req) => ({ ...(await worker.transport(req)), headers: {} })).admit(hostOpen(t)), "answer", "unsigned");
  await rejects(client(async () => ({ status: 401, headers: {}, body: new Uint8Array(0) })).admit(hostOpen(t)), "status", "a bare 401");
  await rejects(client(async (req) => { const r = await worker.transport(req); return { ...r, body: Uint8Array.from([...r.body, 32]) }; }).admit(hostOpen(t)), "answer", "another body");
  const other = new FakeWorker(controlKey(KEY_TEXT()));
  await rejects(client(other.transport).admit(hostOpen(t)), "status", "another key: the Worker refuses the call");
  await rejects(client(worker.transport, controlKey(KEY_TEXT())).admit(hostOpen(t)), "status");
});

test("the Worker consumes each service call id once: a replayed call is refused unsigned", async () => {
  const worker = new FakeWorker(KEY), t = ids();
  let last = null;
  const client = controlClient({ transport: async (req) => { last = req; return worker.transport(req); }, key: KEY });
  await client.admit(hostOpen(t));
  const again = await worker.transport(last);
  assert.equal(again.status, 401);
  assert.equal(again.headers["sagebrush-relay-answer"], undefined);
  assert.equal(worker.calls.refusedAuth, 1);
  assert.ok(last.headers[AUTH_HEADER].startsWith("v1 ts="));
});

// ---- the real transport, over TLS

function tlsMaterial() {
  try { execFileSync("openssl", ["version"], { stdio: "ignore" }); } catch { return null; }
  const dir = mkdtempSync(join(tmpdir(), "relay-tls-"));
  try {
    execFileSync("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", join(dir, "k.pem"), "-out", join(dir, "c.pem"),
      "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost"], { stdio: "ignore" });
    return { key: readFileSync(join(dir, "k.pem")), cert: readFileSync(join(dir, "c.pem")) };
  } finally { rmSync(dir, { recursive: true, force: true }); }
}
const tls = tlsMaterial();

test("the HTTPS transport: verified TLS to the pinned origin; a redirect isn't followed; an oversized answer is cut; deadlines abort; an untrusted certificate fails", { skip: tls ? false : "openssl isn't installed" }, async () => {
  const worker = new FakeWorker(KEY), t = ids();
  let mode = "ok";
  const server = createServer({ key: tls.key, cert: tls.cert }, (req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", async () => {
      if (mode === "redirect") return res.writeHead(302, { location: "https://example.com/" }).end();
      if (mode === "big") return res.writeHead(200).end(Buffer.alloc(ANSWER_MAX + 1));
      if (mode === "slow") return;
      const r = await worker.transport({ method: req.method, target: req.url, headers: { [AUTH_HEADER]: req.headers[AUTH_HEADER] }, body: new Uint8Array(Buffer.concat(chunks)) });
      res.writeHead(r.status, r.headers).end(Buffer.from(r.body));
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const origin = `https://localhost:${server.address().port}`;
  try {
    const client = controlClient({ transport: httpsTransport({ origin, ca: tls.cert }), key: KEY });
    assert.equal((await client.admit(hostOpen(t))).result, "ok");
    assert.equal((await client.epochs(0)).result, "ok", "the feed's GET");
    mode = "redirect"; await rejects(client.admit(hostOpen(t)), "status");
    mode = "big"; await rejects(client.admit(hostOpen(t)), "too_large");
    mode = "slow";
    const t0 = Date.now();
    await rejects(client.admit(hostOpen(t)), "deadline");
    assert.ok(Date.now() - t0 < CONTROL.headersMs + 1000, "the response-headers deadline");
    const ac = new AbortController();
    const p = client.epochs(0, ac.signal);
    ac.abort();
    await rejects(p, "deadline");
    mode = "ok";
    await rejects(controlClient({ transport: httpsTransport({ origin }), key: KEY }).admit(hostOpen(t)), "transport", "an untrusted certificate");
  } finally { server.closeAllConnections(); await new Promise((r) => server.close(r)); }
  assert.throws(() => httpsTransport({ origin: "http://localhost" }));
  assert.throws(() => httpsTransport({ origin: "https://localhost/path" }));
});
