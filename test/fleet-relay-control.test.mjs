// The relay's control plane (lib/fleet/core/control.mjs; agent-autonomous-browser-relay.md r2.1 §3 and §5): the
// service-key MACs both ways, checked against an independent computation from the documented strings (node:crypto's
// HMAC, not the backend's), the 60 s window, each signed part, the answer bound to its one call, and the closed
// schemas of the admit request, its answers and the feed, with the feed's cursor and duplicate rules.
import assert from "node:assert/strict";
import { createHash, createHmac, randomBytes } from "node:crypto";
import { test } from "node:test";
import { FleetError, b64, enc, newId } from "../lib/fleet/index.mjs";
import { canonText } from "../lib/fleet/core/canonical.mjs";
import { COMMIT_ROUTE, RECORD_HEADER_MAX } from "../lib/fleet/core/relay.mjs";
import {
  ADMIT_ROUTE, ANSWER_MAX, EPOCHS_ROUTE, FEED_MAX, REQUEST_MAX, controlKey, epochsTarget, parseAdmitRequest, parseControlAuth, parseEpochsTarget,
  signControlAnswer, signControlRequest, verifyControlAnswer, verifyControlRequest,
} from "../lib/fleet/core/control.mjs";

const NOW = 1_800_000_000_000;
const code = async (fn) => { try { await fn(); return "ok"; } catch (e) { if (e instanceof FleetError) return e.code; throw e; } };
const id22 = () => b64(randomBytes(16));
const KEY = new Uint8Array(32).map((_, i) => i + 1);
const OTHER = new Uint8Array(32).fill(7);
const sha = (b) => createHash("sha256").update(b).digest("base64url");
const oracle = (key, text) => createHmac("sha256", key).update(text).digest("base64url");

test("the request MAC is exactly the documented string's HMAC-SHA256 (an independent computation)", async () => {
  const body = enc('{"v":1}'), id = id22();
  const h = await signControlRequest({ key: KEY, method: "POST", target: ADMIT_ROUTE, body, ts: NOW, id });
  const want = oracle(KEY, `sagebrush.relay-control.request.v1\nPOST\n${ADMIT_ROUTE}\n${sha(body)}\n${NOW}\n${id}`);
  assert.equal(h, `v1 ts=${NOW}; id=${id}; mac=${want}`);
  const empty = await signControlRequest({ key: KEY, method: "GET", target: epochsTarget(5), ts: NOW, id });
  assert.equal(empty, `v1 ts=${NOW}; id=${id}; mac=${oracle(KEY, `sagebrush.relay-control.request.v1\nGET\n${EPOCHS_ROUTE}?since=5\n${sha(new Uint8Array(0))}\n${NOW}\n${id}`)}`);
});

test("a request verifies only as signed: each part, the key, the 60 s window both ways, the header's form", async () => {
  const body = enc('{"v":1}'), id = id22();
  const h = await signControlRequest({ key: KEY, method: "POST", target: ADMIT_ROUTE, body, ts: NOW, id });
  const v = (o = {}, ctx = {}) => verifyControlRequest({ header: h, method: "POST", target: ADMIT_ROUTE, body, ...o }, { key: KEY, now: NOW, ...ctx });
  assert.deepEqual(await v(), { id, ts: NOW, digest: sha(body) });
  assert.equal(await code(() => v({ method: "GET" })), "bad_signature", "method");
  assert.equal(await code(() => v({ target: `${ADMIT_ROUTE}?x` })), "bad_signature", "target");
  assert.equal(await code(() => v({ body: enc('{"v":2}') })), "bad_signature", "body");
  assert.equal(await code(() => v({}, { key: OTHER })), "bad_signature", "another key");
  assert.equal(await code(() => v({ header: h.replace(`id=${id}`, `id=${id22()}`) })), "bad_signature", "another id");
  const at = async (ts, now) => code(async () => verifyControlRequest({ header: await signControlRequest({ key: KEY, method: "GET", target: epochsTarget(0), ts, id }), method: "GET", target: epochsTarget(0) }, { key: KEY, now }));
  assert.equal(await at(NOW - 60_000, NOW), "ok", "60 s behind");
  assert.equal(await at(NOW + 60_000, NOW), "ok", "60 s ahead");
  assert.equal(await at(NOW - 60_001, NOW), "clock_skew", "past 60 s behind");
  assert.equal(await at(NOW + 60_001, NOW), "clock_skew", "past 60 s ahead");
  assert.equal(await code(() => v({ header: h.replace(`ts=${NOW}`, `ts=${NOW + 1}`) })), "bad_signature", "ts is signed");
  const mac = h.slice(-43);
  const lastBad = mac.slice(0, 42) + (mac[42] === "B" ? "C" : "B"); // (a non-canonical last character when the canonical one is A/E/I...)
  for (const bad of [h.replace("v1 ", "v2 "), h.replace("; id=", ";  id="), h.replace(`ts=${NOW}`, `ts=0${NOW}`), `${h}; x=1`, h.replace(`id=${id}`, "id=x"),
    h.slice(0, -1), undefined, "v1 " + "x".repeat(200)])
    assert.equal(await code(() => v({ header: bad })), "bad_form", String(bad).slice(0, 40));
  // (a MAC wrong only in its last byte: the comparison covers every byte)
  const flipLast = (m) => { const x = Buffer.from(m, "base64url"); x[31] ^= 1; return x.toString("base64url"); };
  assert.equal(await code(() => v({ header: h.slice(0, -43) + flipLast(mac) })), "bad_signature", "the last byte");
  if (!/[AEIMQUYcgkosw048]$/.test(lastBad)) assert.equal(await code(() => parseControlAuth(h.slice(0, -43) + lastBad)), "bad_form", "a non-canonical MAC encoding");
});

test("the service key: exactly 32 bytes in canonical base64url, never all zeros", async () => {
  assert.deepEqual(controlKey(b64(KEY)), KEY);
  for (const bad of [b64(KEY).slice(0, 42), b64(KEY) + "A", b64(new Uint8Array(32)), b64(KEY).slice(0, 42) + "B", undefined, 5])
    assert.equal(await code(() => controlKey(bad)), "bad_form", String(bad));
});

// (answers of each shape the schemas allow)
const fleet = newId(), host = newId(), agent = newId(), session = newId();
const TUPLE = { fleet, host, agent, browser_gen: 2, session, host_gen: 3, resume_n: 0 };
const EPOCHS = { account: 4, agent: 5, host: 6 };
const ANSWERS = {
  refused: { result: "refused", code: "not_granted" },
  host: { result: "ok", role: "host", ...TUPLE, nonce: id22(), account: "acct-1", not_after_ms: NOW + 1000, epochs: EPOCHS },
  app: { result: "ok", role: "app", ...TUPLE, request: id22(), account: "acct-1", account_session: "s-1", account_session_expires_ms: NOW + 5000, signer: newId(),
    chain_seq: 0, not_after_ms: NOW + 1000, epochs: EPOCHS },
  commit: { result: "ok", role: "commit", ...TUPLE, nonce: id22(), host_nonce: id22(), app_request: id22(), account: "acct-1", epochs: EPOCHS },
};
const FEED = { since: 7, cursor: 8, at_ms: NOW, more: false, agents: [{ id: agent, epoch: 5 }], accounts: [{ id: "acct-1", epoch: 4 }], hosts: [] };

test("answers: the MAC over status and body (an independent computation), bound to the one call, closed", async () => {
  const call = { id: id22(), digest: sha(enc("x")) };
  for (const [name, fields] of Object.entries(ANSWERS)) {
    const a = await signControlAnswer({ key: KEY, call, answer: "admit", fields });
    assert.equal(a.header, `v1 mac=${oracle(KEY, `sagebrush.relay-control.answer.v1\n200\n${sha(a.body)}`)}`, name);
    assert.equal(new TextDecoder().decode(a.body), canonText({ v: 1, answer: "admit", call: call.id, call_sha256: call.digest, ...fields }), name);
    const got = await verifyControlAnswer(a, { key: KEY, call, answer: "admit" });
    assert.equal(got.call, call.id);
    assert.equal(await code(() => verifyControlAnswer(a, { key: KEY, call: { ...call, id: id22() }, answer: "admit" })), "bad_form", `another call's id: ${name}`);
    assert.equal(await code(() => verifyControlAnswer(a, { key: KEY, call: { ...call, digest: sha(enc("y")) }, answer: "admit" })), "bad_form", `another body's digest: ${name}`);
    assert.equal(await code(() => verifyControlAnswer({ ...a, status: 403 }, { key: KEY, call, answer: "admit" })), "bad_signature", `another status: ${name}`);
    assert.equal(await code(() => verifyControlAnswer(a, { key: OTHER, call, answer: "admit" })), "bad_signature", `another key: ${name}`);
    assert.equal(await code(() => verifyControlAnswer(a, { key: KEY, call, answer: "epochs" })), "bad_form", `as the other answer: ${name}`);
    const lastByte = (() => { const x = Buffer.from(a.header.slice(7), "base64url"); x[31] ^= 1; return `v1 mac=${x.toString("base64url")}`; })();
    assert.equal(await code(() => verifyControlAnswer({ ...a, header: lastByte }, { key: KEY, call, answer: "admit" })), "bad_signature", `the MAC's last byte: ${name}`);
    const tampered = Uint8Array.from(a.body); tampered[tampered.length - 2] ^= 1;
    assert.equal(await code(() => verifyControlAnswer({ ...a, body: tampered }, { key: KEY, call, answer: "admit" })), "bad_signature", `tampered: ${name}`);
  }
  // (a correctly MACed answer that isn't canonical, or isn't closed, still refuses: the MAC isn't the only check)
  const resign = async (text) => { const body = enc(text); return { status: 200, body, header: `v1 mac=${oracle(KEY, `sagebrush.relay-control.answer.v1\n200\n${sha(body)}`)}` }; };
  const base = { v: 1, answer: "admit", call: call.id, call_sha256: call.digest, ...ANSWERS.host };
  assert.equal(await code(async () => verifyControlAnswer(await resign(canonText(base)), { key: KEY, call, answer: "admit" })), "ok", "the positive control");
  assert.equal(await code(async () => verifyControlAnswer(await resign(JSON.stringify(base, null, 1)), { key: KEY, call, answer: "admit" })), "bad_form", "not canonical");
  for (const [why, v] of [["an extra fact", { ...base, extra: 1 }], ["a missing fact", { ...base, epochs: undefined }], ["a host answer with an app's facts", { ...base, account_session: "s" }],
    ["a malformed fact", { ...base, browser_gen: 0 }], ["epochs missing one", { ...base, epochs: { account: 1, agent: 1 } }], ["result ok without a role", { ...base, role: undefined }],
    ["a refusal with facts", { v: 1, answer: "admit", call: call.id, call_sha256: call.digest, ...ANSWERS.refused, fleet }], ["another version", { ...base, v: 2 }]])
    assert.equal(await code(async () => verifyControlAnswer(await resign(canonText(JSON.parse(JSON.stringify(v)))), { key: KEY, call, answer: "admit" })), "bad_form", why);
  assert.equal(await code(() => signControlAnswer({ key: KEY, call, answer: "admit", fields: { ...ANSWERS.host, extra: 1 } })), "bad_form", "the Worker can't send one either");
  const big = { status: 200, body: new Uint8Array(ANSWER_MAX + 1), header: "v1 mac=" + "A".repeat(43) };
  assert.equal(await code(() => verifyControlAnswer(big, { key: KEY, call, answer: "admit" })), "limit", "over 16 KiB, before the MAC");
  assert.equal(await code(() => verifyControlAnswer({ ...big, body: enc("{}"), header: "v2 mac=x" }, { key: KEY, call, answer: "admit" })), "bad_form", "the answer header's form");
});

test("the feed's answer: a cursor ahead of since, each identity once per list, at most 80 a list, and full lists fit in 16 KiB", async () => {
  const call = { id: id22(), digest: sha(new Uint8Array(0)) };
  const ok = (fields) => code(() => signControlAnswer({ key: KEY, call, answer: "epochs", fields }));
  assert.equal(await ok(FEED), "ok");
  assert.equal(await ok({ ...FEED, agents: [], accounts: [], hosts: [] }), "ok", "an empty answer (it still advances)");
  assert.equal(await ok({ ...FEED, cursor: 7 }), "bad_form", "a cursor equal to since");
  assert.equal(await ok({ ...FEED, cursor: 6 }), "bad_form", "a cursor behind since");
  assert.equal(await ok({ ...FEED, cursor: 0, since: 0 }), "bad_form", "cursor 0");
  assert.equal(await ok({ ...FEED, agents: [{ id: agent, epoch: 5 }, { id: agent, epoch: 6 }] }), "bad_form", "an agent twice");
  assert.equal(await ok({ ...FEED, accounts: [{ id: "a", epoch: 1 }, { id: "a", epoch: 1 }] }), "bad_form", "an account twice");
  assert.equal(await ok({ ...FEED, hosts: [{ id: host, epoch: 1 }, { id: host, epoch: 2 }] }), "bad_form", "a host twice");
  assert.equal(await ok({ ...FEED, agents: [{ id: "x", epoch: 1 }] }), "bad_form", "an agent id out of form");
  assert.equal(await ok({ ...FEED, more: undefined }), "bad_form", "more missing");
  const full = (k) => Array.from({ length: k }, () => ({ id: newId(), epoch: Number.MAX_SAFE_INTEGER }));
  const accounts = Array.from({ length: FEED_MAX }, () => ({ id: "x".repeat(26), epoch: Number.MAX_SAFE_INTEGER }));
  assert.equal(await ok({ ...FEED, agents: full(FEED_MAX + 1) }), "bad_form", "81 agents");
  const max = await signControlAnswer({ key: KEY, call, answer: "epochs", fields: { ...FEED, since: Number.MAX_SAFE_INTEGER - 1, cursor: Number.MAX_SAFE_INTEGER, at_ms: Number.MAX_SAFE_INTEGER,
    agents: full(FEED_MAX), accounts: accounts.map((a, i) => ({ ...a, id: `${i}`.padStart(26, "x") })), hosts: full(FEED_MAX) } });
  assert.ok(max.body.length <= ANSWER_MAX, `three full lists of 26-character ids: ${max.body.length} bytes`);
  assert.ok(max.body.length > ANSWER_MAX - 2048, `and FEED_MAX isn't needlessly small: ${max.body.length} bytes`);
  // (account ids may be 128 characters: full lists of those pass the count but not the byte cap, which the Worker's
  // pagination must respect; the signing side refuses rather than send one)
  const long = Array.from({ length: FEED_MAX }, (_, i) => ({ id: `${i}`.padStart(128, "a"), epoch: 1 }));
  assert.equal(await ok({ ...FEED, accounts: long, agents: full(FEED_MAX), hosts: full(FEED_MAX) }), "limit", "over 16 KiB by bytes, not count");
  // (the relay's side refuses the same, even correctly MACed)
  const body = enc(canonText({ v: 1, answer: "epochs", call: call.id, call_sha256: call.digest, ...FEED, cursor: 7 }));
  const forged = { status: 200, body, header: `v1 mac=${oracle(KEY, `sagebrush.relay-control.answer.v1\n200\n${sha(body)}`)}` };
  assert.equal(await code(() => verifyControlAnswer(forged, { key: KEY, call, answer: "epochs" })), "bad_form", "the relay refuses a cursor not ahead");
});

test("the admit request: closed per kind, canonical, at most 128 KiB; the epochs target exact", async () => {
  const req = (v) => code(() => parseAdmitRequest(enc(canonText(v, REQUEST_MAX))));
  const host = { v: 1, kind: "host", target: "/t", sig: "v1 x" };
  const app = { v: 1, kind: "app", target: "/t", record: "AAAA", request: id22(), cookie: "abc" };
  const commit = { v: 1, kind: "commit", target: COMMIT_ROUTE, sig: "v1 x", body: "e30" };
  for (const v of [host, app, commit]) assert.equal(await req(v), "ok", v.kind);
  for (const [why, v] of [["a host request with a record", { ...host, record: "AAAA" }], ["an app request without its cookie", { ...app, cookie: undefined }],
    ["a commit at another target", { ...commit, target: "/other" }], ["a cookie with a space", { ...app, cookie: "a b" }], ["a cookie over 4,096", { ...app, cookie: "a".repeat(4097) }],
    ["a record over 87,252", { ...app, record: "A".repeat(RECORD_HEADER_MAX + 1) }], ["a record that isn't base64url", { ...app, record: "a+b" }],
    ["another kind", { ...host, kind: "other" }], ["another version", { ...host, v: 2 }], ["a commit body over 1,024 bytes", { ...commit, body: "A".repeat(1367) }],
    ["a target over 512", { ...host, target: "/".repeat(513) }], ["an app request id out of form", { ...app, request: "x" }]])
    assert.equal(await req(JSON.parse(JSON.stringify(v))), "bad_form", why);
  assert.equal(await req({ ...app, record: "A".repeat(RECORD_HEADER_MAX) }), "ok", "a record of exactly 87,252");
  assert.equal(await code(() => parseAdmitRequest(enc(JSON.stringify(host, null, 1)))), "bad_form", "not canonical");
  assert.equal(await code(() => parseAdmitRequest(enc('{"v":1,"v":1,"kind":"host","target":"/t","sig":"v1 x"}'))), "bad_form", "a duplicate key");
  assert.equal(await code(() => parseAdmitRequest(new Uint8Array(REQUEST_MAX + 1))), "limit", "over 128 KiB");
  assert.equal(parseEpochsTarget(epochsTarget(0)), 0);
  assert.equal(parseEpochsTarget(epochsTarget(Number.MAX_SAFE_INTEGER)), Number.MAX_SAFE_INTEGER);
  for (const bad of [`${EPOCHS_ROUTE}?since=01`, `${EPOCHS_ROUTE}?since=-1`, `${EPOCHS_ROUTE}?since=1&x=1`, `${EPOCHS_ROUTE}?since=`, `${EPOCHS_ROUTE}?cursor=1`, `${ADMIT_ROUTE}?since=1`,
    `${EPOCHS_ROUTE}?since=9007199254740992`, `${EPOCHS_ROUTE.slice(0, -1)}z?since=1`, `/x${EPOCHS_ROUTE}?since=1`])
    assert.equal(await code(() => parseEpochsTarget(bad)), "bad_form", bad);
});
