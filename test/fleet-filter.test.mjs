// The browser lane's filter core (O11 draft 5 §4, §6, §8.1): the URL policy, the command parameters (every allowed
// command and every bound, generated from the spec), and the filter itself on synthetic CDP traffic. Real ids are
// planted as REAL-… strings and integers ≥ 900000; nothing the filter forwards may carry one outside page content.

import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync } from "node:fs";
import { FleetError } from "../lib/fleet/index.mjs";
import { loadProgram } from "../lib/fleet/browser/rewrite.mjs";
import { Vids, VID } from "../lib/fleet/browser/vids.mjs";
import { PINS } from "../lib/fleet/browser/pins.mjs";
import { compileCommands, realParams } from "../lib/fleet/browser/params.mjs";
import { checkUrl, accountOrigins, normalHost, DEFAULT_ACCOUNT_ORIGINS } from "../lib/fleet/browser/urls.mjs";
import { Filter, LIMITS, GROUP_PREFIX } from "../lib/fleet/browser/filter.mjs";

const root = new URL("..", import.meta.url);
const bytes = (f) => readFileSync(new URL(f, root));
const spec = JSON.parse(bytes(PINS.spec.file));
const program = loadProgram(bytes(PINS.program.file), PINS.program.sha256);
const commands = compileCommands(spec);
const origins = accountOrigins([...DEFAULT_ACCOUNT_ORIGINS, "auth.workos.example"]);
const code = (fn) => { try { fn(); } catch (e) { if (e instanceof FleetError) return e.code; throw e; } return "ok"; };

// Real ids anywhere in a value: REAL-… strings and integers ≥ 900000, outside the paths given (page content).
function leaks(v, keep = [], at = "") {
  if (keep.includes(at)) return [];
  if (typeof v === "string") return v.includes("REAL-") ? [at] : [];
  if (typeof v === "number") return v >= 900000 ? [at] : [];
  if (Array.isArray(v)) return v.flatMap((x, i) => leaks(x, keep, `${at}[${i}]`));
  if (v && typeof v === "object") return Object.entries(v).flatMap(([k, x]) => leaks(x, keep, at ? `${at}.${k}` : k));
  return [];
}

// ---- the URL policy ----

test("URLs: http, https and exactly about:blank; every other scheme is refused", () => {
  for (const u of ["https://example.test/", "http://example.test:8080/a?b#c", "about:blank", "https://github.com/x", "https://claude.ai.evil.test/", "https://notclaude.ai/", "http://127.0.0.1/"])
    assert.equal(checkUrl(u, origins).ok, true, u);
  for (const u of ["javascript:alert(1)", "file:///etc/passwd", "data:text/html,x", "about:blank#x", "about:srcdoc", "ftp://example.test/", "chrome://settings", "blob:https://example.test/x", "view-source:https://example.test/", "not a url", ""])
    assert.equal(checkUrl(u, origins).why, "scheme", u);
  assert.equal(checkUrl("HTTPS://Example.TEST/a", origins).url, "https://example.test/a"); // (the parser's form goes to Chrome)
});

test("URLs: account origins and their subdomains, after lowercase, IDNA, percent-decoding and the trailing dot; a port never matters", () => {
  for (const u of ["https://claude.ai/", "https://CLAUDE.AI./x", "https://claude.ai:8443/", "https://sub.claude.ai/", "https://ＣＬＡＵＤＥ.ai/", "https://claude.ai%2e/", "http://chatgpt.com/", "https://x.sagebrush.cloud/", "https://auth.workos.example/login", "https://user:pw@console.anthropic.com/"]) {
    const r = checkUrl(u, origins);
    assert.equal(r.why, "account", u);
  }
  assert.equal(checkUrl("https://a.b.claude.ai/", origins).origin, "claude.ai");
  assert.equal(checkUrl("https://claude.ai../", origins).why, "host"); // (not a name the policy can compare: refused)
  assert.equal(normalHost("Faß.DE."), "xn--fa-hia.de");
  assert.throws(() => accountOrigins(["127.0.0.1"]));
  assert.throws(() => accountOrigins([""]));
  assert.deepEqual(accountOrigins(["Claude.AI."]), ["claude.ai"]);
});

// ---- the command parameters, generated from the spec ----

const T = "SESS-A-REAL";
function liveVids() {
  const v = new Vids();
  const real = { pg: "REAL-T1", fr: "REAL-F1", cx: 900001, nd: 900002, bn: 900003, ob: "REAL-O1", rq: "REAL-R1", he: 900004 };
  const vid = Object.fromEntries(Object.entries(real).map(([k, r]) => [k, v.out(k, r, k === "pg" ? undefined : T)]));
  return { v, vid, real };
}

// A minimal valid value for a form, and its bound cases: [value, ok].
function forms(form, vid) {
  if (typeof form === "string" && form.startsWith("json,")) return { min: 1, cases: [] };
  if (typeof form === "string") {
    const name = form.replace(/\?$/, "");
    if (name === "boolean") return { min: true, cases: [["yes", false]] };
    if (name.startsWith("vid:")) { const k = name.slice(4); return { min: vid[k], cases: [["REAL-X", false]] }; }
    return forms(spec.defs[name], vid);
  }
  if (form.enum) return { min: form.enum[0], cases: [["no-such-value", false]] };
  if (form.object) return { min: minimal(form.object, [], vid), cases: [] };
  if (form.array) return { min: [], cases: [] };
  if (form.type === "string") {
    if (form.maxBytes === undefined) return { min: "g", cases: [["g".repeat(64), true], ["g".repeat(65), false], ["g h", false]] };
    const base = form.scheme ? "https://example.test/" : "";
    const fill = (n) => base + "a".repeat(Math.max(0, n - base.length));
    const lo = Math.max(form.minBytes ?? 0, base.length);
    const cases = [[fill(form.maxBytes), true], [fill(form.maxBytes + 1), false]];
    if (!base && form.maxBytes >= 2) cases.push(["é" + "a".repeat(form.maxBytes - 2), true], ["é" + "a".repeat(form.maxBytes - 1), false]); // (one byte over, within the code-point bound)
    if ((form.minBytes ?? 0) > 0 && !base) cases.push([fill(form.minBytes - 1), false]);
    return { min: fill(lo || (form.minBytes ?? 0)), cases };
  }
  const step = form.type === "integer" ? 1 : 0.5;
  return { min: form.min, cases: [[form.min, true], [form.max, true], [form.min - step, false], [form.max + step, false], ...(form.type === "integer" ? [[form.min + 0.5, false]] : [])] };
}
function minimal(params, oneOf, vid) {
  const out = {};
  for (const [k, f] of Object.entries(params)) {
    const optional = (typeof f === "string" && f.endsWith("?")) || f.optional === true;
    if (oneOf.length ? (oneOf[0] === k || (!optional && !oneOf.includes(k))) : !optional) out[k] = forms(f, vid).min;
  }
  return out;
}

test("every allowed command: its minimal call passes; an extra, missing or out-of-bounds parameter is refused at the limit and one past", () => {
  assert.equal(Object.keys(commands).length, 42);
  let cases = 0;
  for (const [method, c] of Object.entries(spec.commands)) {
    const { v, vid } = liveVids();
    const cmd = commands[method];
    const base = minimal(c.params, c.exactlyOneOf ?? [], vid);
    const run = (p) => code(() => (cmd.virtual ? cmd.validate(p) : realParams(cmd, p, v, T)));
    const ok = (p) => ["ok"].includes(run(p));
    assert.ok(ok(base), `${method}: minimal ${JSON.stringify(base)} → ${run(base)}`);
    assert.ok(!ok({ ...base, zzExtra: 1 }), `${method}: extra`);
    for (const k of Object.keys(base)) if (!(c.exactlyOneOf ?? []).includes(k)) { const p = { ...base }; delete p[k]; assert.ok(!ok(p), `${method}: missing ${k}`); }
    for (const [k, f] of Object.entries(c.params)) {
      for (const [val, good] of forms(f, vid).cases) {
        cases++;
        const p = { ...base, [k]: val };
        if (c.exactlyOneOf?.includes(k)) for (const o of c.exactlyOneOf) if (o !== k) delete p[o];
        assert.equal(ok(p), good, `${method}.${k} = ${JSON.stringify(val).slice(0, 40)}: ${run(p)}`);
      }
    }
    if (c.exactlyOneOf) {
      const none = { ...base }; for (const k of c.exactlyOneOf) delete none[k];
      assert.ok(!ok(none), `${method}: none of ${c.exactlyOneOf}`);
      const both = { ...base }; for (const k of c.exactlyOneOf) both[k] = forms(c.params[k], vid).min;
      assert.ok(!ok(both), `${method}: all of ${c.exactlyOneOf}`);
    }
  }
  assert.ok(cases > 150, String(cases));
});

test("parameters: vids map to real ids in the command's target, and are refused in another target, of another kind, or as a raw id", () => {
  const { v, vid, real } = liveVids();
  const q = commands["DOM.querySelector"];
  assert.deepEqual(realParams(q, { nodeId: vid.nd, selector: "a" }, v, T).params, { nodeId: real.nd, selector: "a" });
  assert.equal(code(() => realParams(q, { nodeId: vid.nd, selector: "a" }, v, "SESS-B-REAL")), "stale_handle");
  assert.equal(code(() => realParams(q, { nodeId: vid.bn, selector: "a" }, v, T)), "stale_handle");
  assert.equal(code(() => realParams(q, { nodeId: 900002, selector: "a" }, v, T)), "bad_params");
  assert.equal(code(() => realParams(q, { nodeId: "nd_0000000000000000", selector: "a" }, v, T)), "stale_handle");
  const call = commands["Runtime.callFunctionOn"];
  const args = [{ value: { a: [1] } }, { objectId: vid.ob }, { unserializableValue: "-0" }];
  assert.deepEqual(realParams(call, { functionDeclaration: "f", objectId: vid.ob, arguments: args }, v, T).params.arguments[1], { objectId: real.ob });
  assert.equal(code(() => realParams(call, { functionDeclaration: "f", objectId: vid.ob, arguments: [{ value: 1, objectId: vid.ob }] }, v, T)), "bad_params");
  const big = (n) => "x".repeat(n - 2); // (JSON.stringify adds the two quotes)
  assert.equal(code(() => realParams(call, { functionDeclaration: "f", objectId: vid.ob, arguments: [{ value: big(65536) }] }, v, T)), "ok");
  assert.equal(code(() => realParams(call, { functionDeclaration: "f", objectId: vid.ob, arguments: [{ value: big(65537) }] }, v, T)), "bad_params");
  const nest = (n) => { let x = 0; for (let i = 0; i < n; i++) x = [x]; return x; };
  assert.equal(code(() => realParams(call, { functionDeclaration: "f", objectId: vid.ob, arguments: [{ value: nest(32) }] }, v, T)), "ok");
  assert.equal(code(() => realParams(call, { functionDeclaration: "f", objectId: vid.ob, arguments: [{ value: nest(33) }] }, v, T)), "bad_params");
  assert.equal(code(() => realParams(call, { functionDeclaration: "f", objectId: vid.ob, arguments: new Array(33).fill({ value: 1 }) }, v, T)), "bad_params");
  assert.equal(code(() => realParams(commands["Input.dispatchKeyEvent"], { type: "char", text: "é".repeat(8) }, v, T)), "ok"); // (16 bytes)
  assert.equal(code(() => realParams(commands["Input.dispatchKeyEvent"], { type: "char", text: "é".repeat(9) }, v, T)), "bad_params");
});

// ---- the filter ----

const A = { targetId: "REAL-TA", sessionId: "SESS-A-REAL", url: "https://example.test/", title: "A" };
const B = { targetId: "REAL-TB", sessionId: "SESS-B-REAL", url: "https://other.test/", title: "B" };
function setup({ budget, clock } = {}) {
  let t = 1000;
  const now = clock ?? (() => t);
  const f = new Filter({ spec, program, commands, origins, vids: budget ? new Vids(undefined, budget) : new Vids(), now });
  const ca = f.pageAttached(A), cb = f.pageAttached(B);
  return { f, pa: ca.params.targetInfo.targetId, pb: cb.params.targetInfo.targetId, advance: (ms) => { t += ms; } };
}
// A command that goes to CDP, and CDP's answer.
function roundTrip(f, cmd, raw) {
  const r = f.command(cmd);
  assert.ok(r.send, JSON.stringify(r));
  return { sent: r.send, out: f.result(r.token, raw), r };
}

test("filter: pages appear as virtual targets; getTargets lists only vids; a command goes to the page's real session with real ids", () => {
  const { f, pa, pb } = setup();
  assert.ok(VID.test(pa) && pa.startsWith("pg_") && pa !== pb);
  const list = f.command({ method: "Target.getTargets" });
  assert.deepEqual(list.result.targetInfos.map((x) => x.targetId), [pa, pb]);
  assert.deepEqual(leaks(list), []);
  const doc = roundTrip(f, { method: "DOM.getDocument", params: {}, sessionId: pa }, { root: { nodeId: 900001, backendNodeId: 900002, nodeType: 9, nodeName: "#document", localName: "", nodeValue: "" } });
  assert.equal(doc.sent.sessionId, A.sessionId);
  const nd = doc.out.result.root.nodeId;
  const q = roundTrip(f, { method: "DOM.querySelector", params: { nodeId: nd, selector: "#go" }, sessionId: pa }, { nodeId: 900009 });
  assert.deepEqual(q.sent, { sessionId: A.sessionId, method: "DOM.querySelector", params: { nodeId: 900001, selector: "#go" } });
  assert.ok(q.out.result.nodeId.startsWith("nd_"));
  assert.deepEqual(f.command({ method: "DOM.querySelector", params: { nodeId: nd, selector: "a" }, sessionId: pb }), { error: { code: -32000, message: "stale handle" } }); // (A's node, sent to B)
  assert.deepEqual(f.command({ method: "DOM.querySelector", params: { nodeId: nd, selector: "a" } }), { error: { code: -32602, message: "invalid parameters" } });
  assert.deepEqual(f.command({ method: "DOM.querySelector", params: { nodeId: nd, selector: "a" }, sessionId: "pg_0000000000000000" }).error.message, "stale handle");
  assert.equal(f.command({ method: "Browser.getVersion", sessionId: pa }).error.code, -32601);
  assert.equal(f.command({ method: "DOM.setFileInputFiles", params: {}, sessionId: pa }).error.code, -32601);
  assert.equal(f.command({ method: "__proto__", sessionId: pa }).error.code, -32601);
});

test("filter: evaluate always carries a timeout; agent object groups are prefixed; evaluate and callFunctionOn carry the 30 s deadline", () => {
  const { f, pa } = setup();
  const e = f.command({ method: "Runtime.evaluate", params: { expression: "1" }, sessionId: pa });
  assert.equal(e.send.params.timeout, 30000);
  assert.equal(e.send.params.objectGroup, `${GROUP_PREFIX}default`);
  assert.equal(e.deadlineMs, LIMITS.deadlineMs);
  const e2 = f.command({ method: "Runtime.evaluate", params: { expression: "1", timeout: 5, objectGroup: "mine" }, sessionId: pa });
  assert.equal(e2.send.params.timeout, 5);
  assert.equal(e2.send.params.objectGroup, `${GROUP_PREFIX}mine`);
  assert.equal(f.command({ method: "Runtime.evaluate", params: { expression: "1", timeout: 30001 }, sessionId: pa }).error.code, -32602);
  const rg = f.command({ method: "Runtime.releaseObjectGroup", params: { objectGroup: "mine" }, sessionId: pa });
  assert.equal(rg.send.params.objectGroup, `${GROUP_PREFIX}mine`);
  assert.equal(f.command({ method: "DOM.getDocument", params: {}, sessionId: pa }).deadlineMs, undefined);
  assert.deepEqual(f.takeover().releaseGroups.sort(), [`${GROUP_PREFIX}default`, `${GROUP_PREFIX}mine`]);
});

test("filter: navigation and new pages follow the URL policy; at most 16 pages; activate and close name the real target", () => {
  const { f, pa, pb } = setup();
  assert.equal(f.command({ method: "Page.navigate", params: { url: "https://example.test/x" }, sessionId: pa }).send.params.url, "https://example.test/x");
  assert.deepEqual(f.command({ method: "Page.navigate", params: { url: "https://Claude.AI./" }, sessionId: pa }), { error: { code: -32000, message: "blocked: account site (claude.ai)" } });
  assert.equal(f.command({ method: "Page.navigate", params: { url: "javascript:1" }, sessionId: pa }).error.code, -32602);
  assert.equal(f.command({ method: "Target.createTarget", params: { url: "file:///etc/passwd" } }).error.code, -32602);
  assert.equal(f.command({ method: "Target.createTarget", params: { url: "https://chatgpt.com/" } }).error.message, "blocked: account site (chatgpt.com)");
  const c = f.command({ method: "Target.createTarget", params: { url: "https://example.test/new" } });
  assert.deepEqual(c.app, { op: "createTarget", url: "https://example.test/new", background: false });
  f.pageAttached({ targetId: "REAL-TC", sessionId: "SESS-C-REAL", url: "https://example.test/new" });
  const made = f.result(c.token, { targetId: "REAL-TC" });
  assert.ok(made.result.targetId.startsWith("pg_"));
  for (let i = 3; i < 16; i++) assert.ok(f.command({ method: "Target.createTarget", params: { url: "about:blank" } }).app, String(i));
  assert.equal(f.command({ method: "Target.createTarget", params: { url: "about:blank" } }).error.message, "too many pages");
  assert.deepEqual(f.command({ method: "Target.activateTarget", params: { targetId: pb } }).app, { op: "activateTarget", targetId: "REAL-TB" });
  assert.deepEqual(f.command({ method: "Target.closeTarget", params: { targetId: pa } }).app, { op: "closeTarget", targetId: "REAL-TA" });
  assert.equal(f.command({ method: "Target.closeTarget", params: { targetId: "REAL-TA" } }).error.code, -32602);
  assert.equal(f.command({ method: "Target.closeTarget", params: { targetId: pa }, sessionId: pa }).error.code, -32602);
});

test("filter: results are rewritten in the page's scope, capped, and never forwarded when they can't be", () => {
  const { f, pa } = setup();
  const big = roundTrip(f, { method: "DOM.getOuterHTML", params: { backendNodeId: (() => { const r = roundTrip(f, { method: "DOM.describeNode", params: { nodeId: roundTrip(f, { method: "DOM.getDocument", params: {}, sessionId: pa }, { root: { nodeId: 900001, backendNodeId: 900002, nodeType: 9, nodeName: "#document", localName: "", nodeValue: "" } }).out.result.root.nodeId }, sessionId: pa }, { node: { nodeId: 900001, backendNodeId: 900002, nodeType: 9, nodeName: "#document", localName: "", nodeValue: "" } }); return r.out.result.node.backendNodeId; })() }, sessionId: pa }, { outerHTML: "x".repeat(4194304) });
  assert.deepEqual(big.out, { error: { code: -32000, message: "result too large" } });
  const shape = roundTrip(f, { method: "Page.navigate", params: { url: "https://example.test/" }, sessionId: pa }, { frameId: ["REAL-F1"] });
  assert.deepEqual(shape.out, { error: { code: -32000, message: "result can't be shown to the agent" } });
  const nav = roundTrip(f, { method: "Page.navigate", params: { url: "https://example.test/" }, sessionId: pa }, { frameId: "REAL-F1", loaderId: "REAL-L1" });
  assert.deepEqual(leaks(nav.out), []);
  const r = f.command({ method: "Page.reload", params: {}, sessionId: pa });
  assert.deepEqual(f.failed(r.token), { error: { code: -32000, message: "the browser refused the command" } });
});

test("filter: events are allowed by name, redacted, rewritten, capped, and never carry a real id", () => {
  const { f, pa } = setup();
  assert.equal(f.event(A.sessionId, "Debugger.scriptParsed", { scriptId: "REAL-S1" }), null);
  assert.equal(f.event(A.sessionId, "Target.targetCreated", { targetInfo: { targetId: "REAL-TX" } }), null); // (the filter's own)
  assert.equal(f.event("SESS-UNKNOWN", "Page.loadEventFired", { timestamp: 1 }), null);
  const load = f.event(A.sessionId, "Page.loadEventFired", { timestamp: 1 });
  assert.deepEqual(load, { method: "Page.loadEventFired", params: { timestamp: 1 }, sessionId: pa });
  const req = {
    requestId: "REAL-R1", loaderId: "REAL-L1", documentURL: "https://example.test/", frameId: "REAL-F1", type: "XHR", timestamp: 1, wallTime: 1, redirectHasExtraInfo: true,
    request: { url: "https://example.test/api", method: "POST", headers: { Cookie: "s=REAL-SECRET", AUTHORIZATION: "Bearer REAL-SECRET", Accept: "*/*" }, postData: "pw=REAL-SECRET", postDataEntries: [{ bytes: "REAL-SECRET" }], hasPostData: true, initialPriority: "High", referrerPolicy: "no-referrer" },
    redirectResponse: { url: "https://example.test/old", status: 302, statusText: "Found", headers: { "Set-Cookie": "a=REAL-SECRET\nb=REAL-SECRET", "www-authenticate": "REAL-SECRET", Location: "/api" }, headersText: "HTTP/1.1 302 Found\r\nSet-Cookie: a=REAL-SECRET\r\n  folded=REAL-SECRET\r\nset-cookie: b=REAL-SECRET\r\nLocation: /api\r\n", mimeType: "", connectionReused: false, connectionId: 1, encodedDataLength: 0, securityState: "secure", charset: "" },
    initiator: { type: "other" },
  };
  const ev = f.event(A.sessionId, "Network.requestWillBeSent", req);
  assert.deepEqual(leaks(ev), []);
  assert.equal(ev.params.request.headers.Cookie, "[redacted]");
  assert.equal(ev.params.request.headers.AUTHORIZATION, "[redacted]");
  assert.equal(ev.params.request.headers.Accept, "*/*");
  assert.equal(ev.params.request.postData, undefined);
  assert.equal(ev.params.request.postDataEntries, undefined);
  assert.equal(ev.params.request.hasPostData, true);
  assert.equal(ev.params.redirectResponse.headers.Location, "/api");
  assert.match(ev.params.redirectResponse.headersText, /^HTTP\/1\.1 302 Found\r\nSet-Cookie: \[redacted\]\r\nset-cookie: \[redacted\]\r\nLocation: \/api\r\n$/);
  assert.equal(req.request.headers.Cookie, "s=REAL-SECRET"); // (the app's copy is untouched)
  const resp = f.event(A.sessionId, "Network.responseReceived", { requestId: "REAL-R1", loaderId: "REAL-L1", timestamp: 1, type: "XHR", frameId: "REAL-F1", hasExtraInfo: false, response: { url: "https://example.test/api", status: 200, statusText: "OK", headers: { "Proxy-Authenticate": "REAL-SECRET" }, requestHeaders: { "Proxy-Authorization": "REAL-SECRET", cookie: "REAL-SECRET" }, requestHeadersText: "GET / HTTP/1.1\nCookie: REAL-SECRET\nHost: x", mimeType: "text/plain", connectionReused: false, connectionId: 1, encodedDataLength: 1, securityState: "secure", charset: "" }, associatedCookies: [{ cookie: "REAL-SECRET" }] });
  assert.deepEqual(leaks(resp), []);
  assert.equal(resp.params.associatedCookies, undefined);
  assert.equal(resp.params.response.requestHeadersText, "GET / HTTP/1.1\r\nCookie: [redacted]\r\nHost: x");
  const cap = spec.events["Page.frameStartedLoading"].maxBytes; // (the forwarded params, rewritten, at most this many bytes)
  const fill = cap - JSON.stringify({ frameId: "fr_0000000000000000", pad: "" }).length;
  assert.equal(JSON.stringify(f.event(A.sessionId, "Page.frameStartedLoading", { frameId: "REAL-F1", pad: "x".repeat(fill) }).params).length, cap);
  assert.equal(f.event(A.sessionId, "Page.frameStartedLoading", { frameId: "REAL-F1", pad: "x".repeat(fill + 1) }), null); // (one byte over: dropped)
  assert.equal(f.event(A.sessionId, "Page.navigate", { frameId: ["REAL-F1"] }), null);
});

test("filter: handles end by CDP's rules: document updates, main-frame navigation, destroyed contexts, detached frames and pages", () => {
  const { f, pa, pb } = setup();
  const doc = { root: { nodeId: 900001, backendNodeId: 900002, nodeType: 9, nodeName: "#document", localName: "", nodeValue: "", frameId: "REAL-F1" } };
  const getDoc = () => roundTrip(f, { method: "DOM.getDocument", params: {}, sessionId: pa }, structuredClone(doc)).out.result.root;
  const q = (nodeId) => f.command({ method: "DOM.querySelector", params: { nodeId, selector: "a" }, sessionId: pa });
  let root = getDoc();
  assert.ok(q(root.nodeId).send);
  f.event(A.sessionId, "DOM.documentUpdated", {});
  assert.equal(q(root.nodeId).error.message, "stale handle");
  root = getDoc();
  const ctx = f.event(A.sessionId, "Runtime.executionContextCreated", { context: { id: 900010, origin: "https://example.test", name: "", uniqueId: "REAL-U1", auxData: { frameId: "REAL-F1" } } }).params.context.id;
  const child = f.event(A.sessionId, "Page.frameAttached", { frameId: "REAL-F2", parentFrameId: "REAL-F1" }); // (not forwarded, but the app sees it)
  assert.equal(child, null);
  const frames = roundTrip(f, { method: "Page.getFrameTree", params: {}, sessionId: pa }, { frameTree: { frame: { id: "REAL-F1", loaderId: "REAL-L1", url: "https://example.test/", domainAndRegistry: "", securityOrigin: "https://example.test", mimeType: "text/html", secureContextType: "Secure", crossOriginIsolatedContextType: "NotIsolated", gatedAPIFeatures: [] }, childFrames: [{ frame: { id: "REAL-F2", parentId: "REAL-F1", loaderId: "REAL-L2", url: "https://example.test/c", domainAndRegistry: "", securityOrigin: "https://example.test", mimeType: "text/html", secureContextType: "Secure", crossOriginIsolatedContextType: "NotIsolated", gatedAPIFeatures: [] } }] } }).out.result.frameTree;
  const mainFr = frames.frame.id, childFr = frames.childFrames[0].frame.id;
  const nav = (fid) => f.command({ method: "Page.navigate", params: { url: "https://example.test/", frameId: fid }, sessionId: pa });
  assert.ok(nav(childFr).send);
  f.event(A.sessionId, "Page.frameDetached", { frameId: "REAL-F2", reason: "remove" });
  assert.equal(nav(childFr).error.message, "stale handle");
  const destroyed = f.event(A.sessionId, "Runtime.executionContextDestroyed", { executionContextId: 900010, executionContextUniqueId: "REAL-U1" });
  assert.deepEqual(destroyed.params, { executionContextId: ctx }); // (forwarded with the handle it's ending)
  assert.equal(f.command({ method: "Runtime.evaluate", params: { expression: "1", contextId: ctx }, sessionId: pa }).error.message, "stale handle");
  const navigated = f.event(A.sessionId, "Page.frameNavigated", { frame: { id: "REAL-F1", loaderId: "REAL-L9", url: "https://example.test/next", domainAndRegistry: "", securityOrigin: "https://example.test", mimeType: "text/html", secureContextType: "Secure", crossOriginIsolatedContextType: "NotIsolated", gatedAPIFeatures: [] }, type: "Navigation" });
  assert.equal(navigated.params.frame.id, mainFr); // (the main frame keeps its handle)
  assert.equal(q(root.nodeId).error.message, "stale handle");
  assert.ok(nav(mainFr).send);
  const gone = f.pageDetached(A.sessionId);
  assert.deepEqual(gone, { method: "Target.targetDestroyed", params: { targetId: pa } });
  assert.equal(nav(mainFr).error.message, "stale handle");
  assert.equal(f.event(A.sessionId, "Page.loadEventFired", { timestamp: 1 }), null);
  assert.ok(f.command({ method: "Page.reload", params: {}, sessionId: pb }).send); // (the other page is untouched)
  const again = f.pageAttached({ ...A, sessionId: "SESS-A2-REAL" }); // (the same target, attached again: a new page handle)
  assert.notEqual(again.params.targetInfo.targetId, pa);
  assert.equal(f.command({ method: "Page.reload", params: {}, sessionId: pa }).error.message, "stale handle");
});

test("filter: accessibility trees replace each other; a released object's handle ends; requests end 120 s after loading; console objects after 60 s", () => {
  const { f, pa, advance } = setup();
  const ax = () => roundTrip(f, { method: "Accessibility.getFullAXTree", params: {}, sessionId: pa }, { nodes: [{ nodeId: "REAL-AX1", ignored: false }] }).out.result.nodes[0].nodeId;
  const a1 = ax(), a2 = ax();
  assert.notEqual(a1, a2);
  const ev = roundTrip(f, { method: "Runtime.evaluate", params: { expression: "document" }, sessionId: pa }, { result: { type: "object", objectId: "REAL-O1" } });
  const ob = ev.out.result.result.objectId;
  const props = { method: "Runtime.getProperties", params: { objectId: ob }, sessionId: pa };
  assert.ok(f.command(props).send);
  roundTrip(f, { method: "Runtime.releaseObject", params: { objectId: ob }, sessionId: pa }, {});
  assert.equal(f.command(props).error.message, "stale handle");
  const rq = f.event(A.sessionId, "Network.loadingFinished", { requestId: "REAL-R1", timestamp: 1, encodedDataLength: 1 }).params.requestId;
  const body = { method: "Network.getResponseBody", params: { requestId: rq }, sessionId: pa };
  advance(LIMITS.requestMs - 1); f.expire();
  assert.ok(f.command(body).send);
  advance(1); f.expire();
  assert.equal(f.command(body).error.message, "stale handle");
  const con = f.event(A.sessionId, "Runtime.consoleAPICalled", { type: "log", args: [{ type: "object", objectId: "REAL-O7" }, { type: "string", value: "hi" }], executionContextId: 900010, timestamp: 1 });
  assert.deepEqual(leaks(con), []);
  const cob = con.params.args[0].objectId;
  assert.ok(f.command({ method: "Runtime.getProperties", params: { objectId: cob }, sessionId: pa }).send);
  advance(LIMITS.consoleMs);
  assert.deepEqual(f.expire(), [{ sessionId: A.sessionId, objectId: "REAL-O7" }]);
  assert.equal(f.command({ method: "Runtime.getProperties", params: { objectId: cob }, sessionId: pa }).error.message, "stale handle");
});

test("filter: takeover pauses everything, revokes every handle, and a late answer is never forwarded, even after handback", () => {
  const { f, pa, pb } = setup();
  const doc = roundTrip(f, { method: "DOM.getDocument", params: {}, sessionId: pa }, { root: { nodeId: 900001, backendNodeId: 900002, nodeType: 9, nodeName: "#document", localName: "", nodeValue: "" } }).out.result.root;
  const inflight = f.command({ method: "Runtime.evaluate", params: { expression: "new Promise(()=>{})", awaitPromise: true }, sessionId: pa });
  const t = f.takeover();
  assert.deepEqual(t.sessions, [A.sessionId, B.sessionId]);
  assert.ok(t.releaseGroups.includes(`${GROUP_PREFIX}default`));
  assert.ok(f.paused);
  assert.deepEqual(f.command({ method: "Page.reload", params: {}, sessionId: pa }), { error: { code: -32000, message: "paused: takeover" } });
  assert.deepEqual(f.command({ method: "Target.getTargets" }), { error: { code: -32000, message: "paused: takeover" } });
  assert.equal(f.event(A.sessionId, "Page.loadEventFired", { timestamp: 1 }), null);
  assert.deepEqual(f.result(inflight.token, { result: { type: "number", value: 1 } }), { discard: true });
  assert.equal(f.pageAttached({ targetId: "REAL-TD", sessionId: "SESS-D-REAL" }), null); // (not shown while paused)
  const back = f.handback();
  assert.equal(back.length, 3);
  const [na, nb] = back.map((e) => e.params.targetInfo.targetId);
  assert.ok(na !== pa && nb !== pb);
  assert.deepEqual(leaks(back), []);
  assert.deepEqual(f.result(inflight.token, { result: { type: "number", value: 1 } }), { discard: true }); // (still abandoned after handback)
  assert.deepEqual(f.failed(inflight.token), { discard: true });
  assert.equal(f.command({ method: "Page.reload", params: {}, sessionId: pa }).error.message, "stale handle");
  assert.equal(f.command({ method: "DOM.querySelector", params: { nodeId: doc.nodeId, selector: "a" }, sessionId: na }).error.message, "stale handle");
  assert.ok(f.command({ method: "Page.reload", params: {}, sessionId: na }).send);
});

test("filter: the handle budget: the result that crosses it isn't forwarded, the session retires, and everything after is refused", () => {
  const { f, pa } = setup({ budget: 4 }); // (2 pages, then 2 more handles)
  const r = f.command({ method: "Accessibility.getFullAXTree", params: {}, sessionId: pa });
  const out = f.result(r.token, { nodes: [{ nodeId: "REAL-AX1", ignored: false }, { nodeId: "REAL-AX2", ignored: false }, { nodeId: "REAL-AX3", ignored: false }] });
  assert.deepEqual(out, { error: { code: -32000, message: "session retired" } });
  assert.ok(f.retired);
  assert.deepEqual(f.command({ method: "Page.reload", params: {}, sessionId: pa }), { error: { code: -32000, message: "session retired" } });
  assert.deepEqual(f.command({ method: "Target.getTargets" }), { error: { code: -32000, message: "session retired" } });
  assert.equal(f.event(A.sessionId, "Page.loadEventFired", { timestamp: 1 }), null);
  assert.equal(f.pageAttached({ targetId: "REAL-TE", sessionId: "SESS-E-REAL" }), null);
  assert.deepEqual(f.handback(), []);
  const g = setup({ budget: 3 });
  assert.equal(g.f.event(A.sessionId, "Runtime.consoleAPICalled", { type: "log", args: [{ type: "object", objectId: "REAL-O1" }, { type: "object", objectId: "REAL-O2" }], executionContextId: 900001, timestamp: 1 }), null);
  assert.ok(g.f.retired); // (an event that crosses it: dropped, and the session retires)
});
