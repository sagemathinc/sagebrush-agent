// The browser session driver (lib/fleet/browser/session.mjs) against a fake CDP pipe with the exact interface of
// macapp's pipe client (send, on, closed, close, pid). Nothing waits on real time: every CDP answer is a barrier the
// test releases (or an automatic reply for setup calls), and timers run on a manual clock.

import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync } from "node:fs";
import { loadProgram } from "../lib/fleet/browser/rewrite.mjs";
import { Vids } from "../lib/fleet/browser/vids.mjs";
import { PINS } from "../lib/fleet/browser/pins.mjs";
import { compileCommands } from "../lib/fleet/browser/params.mjs";
import { accountOrigins, DEFAULT_ACCOUNT_ORIGINS } from "../lib/fleet/browser/urls.mjs";
import { Filter, GROUP_PREFIX } from "../lib/fleet/browser/filter.mjs";
import { BrowserSession, DRAIN } from "../lib/fleet/browser/session.mjs";

const root = new URL("..", import.meta.url);
const bytes = (f) => readFileSync(new URL(f, root));
const spec = JSON.parse(bytes(PINS.spec.file));
const program = loadProgram(bytes(PINS.program.file), PINS.program.sha256);
const commands = compileCommands(spec);
const origins = accountOrigins(DEFAULT_ACCOUNT_ORIGINS);
const flush = () => new Promise((r) => setImmediate(r));
const settle = async (n = 5) => { for (let i = 0; i < n; i++) await flush(); };

class CdpError extends Error { constructor(code, message) { super(message); this.code = code; } }
class CdpClosed extends Error { constructor(reason) { super(reason); this.reason = reason; } }

// The fake pipe. `auto[method]` answers a call at once; every other call waits for the test (call.ok / call.fail).
class FakeCdp {
  calls = [];
  listeners = new Set();
  pid = 4242;
  closeCalls = 0;
  auto = {
    "Target.createBrowserContext": () => ({ browserContextId: "REAL-CTX" }),
    "Target.setDiscoverTargets": () => ({}),
    "Target.setAutoAttach": () => ({}),
    "Runtime.runIfWaitingForDebugger": () => ({}),
    "Target.closeTarget": () => ({ success: true }),
    "Runtime.releaseObjectGroup": () => ({}),
    "Runtime.releaseObject": () => ({}),
  };
  constructor() { this.closed = new Promise((r) => { this.#closeNow = r; }); }
  #closeNow;
  send(method, params = {}, sessionId) {
    const call = { method, params, sessionId };
    call.promise = new Promise((res, rej) => { call.ok = res; call.fail = rej; });
    this.calls.push(call);
    if (this.dead) call.fail(new CdpClosed("closed"));
    else if (this.auto[method]) Promise.resolve().then(() => { try { call.ok(this.auto[method](params, sessionId)); } catch (e) { call.fail(e); } });
    return call.promise;
  }
  on(listener) { this.listeners.add(listener); return () => this.listeners.delete(listener); }
  emit(method, params, sessionId) { for (const l of [...this.listeners]) l({ method, params, ...(sessionId ? { sessionId } : {}) }); }
  async close() { this.closeCalls++; this.die("closed by the session"); }
  die(reason) { if (this.dead) return; this.dead = true; for (const c of this.calls) c.fail?.(new CdpClosed(reason)); this.#closeNow({ reason, exitCode: 0, signal: null }); }
  find(method, sessionId) { return this.calls.filter((c) => c.method === method && (sessionId === undefined || c.sessionId === sessionId)); }
  last(method) { return this.find(method).at(-1); }
}

// The manual clock: timers fire only when the test advances it.
class Clock {
  now = 0; #timers = []; #next = 1;
  setTimeout(fn, ms) { const h = this.#next++; this.#timers.push({ h, at: this.now + ms, fn }); return h; }
  clearTimeout(h) { this.#timers = this.#timers.filter((t) => t.h !== h); }
  async advance(ms) {
    const end = this.now + ms;
    for (;;) {
      await settle();
      const due = this.#timers.filter((t) => t.at <= end).sort((a, b) => a.at - b.at)[0];
      if (!due) break;
      this.#timers = this.#timers.filter((t) => t !== due);
      this.now = due.at;
      due.fn();
    }
    this.now = end;
    await settle();
  }
}

async function setup({ harden = async () => {}, budget } = {}) {
  const cdp = new FakeCdp(), clock = new Clock(), seen = [], retired = [], privileged = [];
  const filter = new Filter({ spec, program, commands, origins, vids: budget ? new Vids(undefined, budget) : new Vids(), now: () => clock.now });
  const hardened = [];
  const session = new BrowserSession({
    cdp, filter, clock,
    hooks: { harden: async (a) => { hardened.push(a.kind + (a.sessionId ? `:${a.sessionId}` : "")); await harden(a); }, privileged: (ev) => privileged.push(ev.method) },
    sink: { event: (ev) => seen.push(ev), retired: (r) => retired.push(r) },
  });
  const started = await session.start();
  return { cdp, clock, filter, session, seen, retired, hardened, privileged, started };
}
// A target attaching, as Chrome announces it (paused until runIfWaitingForDebugger).
async function attach(cdp, { sessionId, targetId, type = "page", url = "about:blank", context = "REAL-CTX", parent }) {
  cdp.emit("Target.attachedToTarget", { sessionId, targetInfo: { targetId, type, title: "", url, attached: true, canAccessOpener: false, browserContextId: context }, waitingForDebugger: true }, parent);
  await settle();
}
const pageVid = (seen, i = 0) => seen.filter((e) => e.method === "Target.targetCreated")[i].params.targetInfo.targetId;

test("start: the agent's context is created and hardened before anything attaches; a failure retires the session", async () => {
  const { cdp, session, hardened, started } = await setup();
  assert.equal(started, true);
  assert.deepEqual({ ...DRAIN }, { waitMs: 2000, terminateMs: 3000, tickMs: 1000, attachMs: 30000, closeMs: 5000 }); // (O11 §8.1's ruled 2 s + 3 s; §4.4's 30 s; §2's 5 s close)
  const before = cdp.calls.length;
  assert.equal(session.handback(), false); // (no takeover to hand back from: nothing happens)
  assert.equal(cdp.calls.length, before);
  assert.equal(session.state, "running");
  assert.deepEqual(cdp.calls.map((c) => c.method), ["Target.createBrowserContext", "Target.setDiscoverTargets", "Target.setAutoAttach"]);
  assert.deepEqual(cdp.last("Target.setAutoAttach").params, { autoAttach: true, waitForDebuggerOnStart: true, flatten: true });
  assert.deepEqual(hardened, ["browser_context"]);
  const bad = await setup({ harden: async (a) => { if (a.kind === "browser_context") throw new Error("no"); } });
  assert.equal(bad.started, false);
  assert.equal(bad.session.state, "retired");
  assert.equal(bad.retired.length, 1);
  assert.equal(bad.cdp.closeCalls, 1);
  assert.equal(bad.cdp.find("Target.setAutoAttach").length, 0); // (nothing attaches to an unhardened context)
});

test("attach: a page is hardened, set to auto-attach its children and shown to the agent before it runs", async () => {
  const { cdp, seen, hardened } = await setup();
  await attach(cdp, { sessionId: "SESS-A", targetId: "REAL-TA" });
  const order = cdp.calls.filter((c) => c.sessionId === "SESS-A").map((c) => c.method);
  assert.deepEqual(order, ["Target.setAutoAttach", "Runtime.runIfWaitingForDebugger"]);
  assert.deepEqual(hardened, ["browser_context", "page:SESS-A"]);
  assert.equal(seen.length, 1);
  assert.equal(seen[0].method, "Target.targetCreated");
  assert.ok(seen[0].params.targetInfo.targetId.startsWith("pg_"));
  assert.ok(!JSON.stringify(seen).includes("REAL-"));
});

test("attach: a failed hardening closes the target (a worker's page); a worker with no page retires; nothing runs unhardened", async () => {
  const failOn = new Set(["SESS-BAD", "SESS-IF", "SESS-W"]);
  const { cdp, seen, session, retired } = await setup({ harden: async (a) => { if (failOn.has(a.sessionId)) throw new Error("no"); } });
  await attach(cdp, { sessionId: "SESS-BAD", targetId: "REAL-TBAD" });
  assert.deepEqual(cdp.last("Target.closeTarget").params, { targetId: "REAL-TBAD" });
  assert.equal(cdp.find("Runtime.runIfWaitingForDebugger", "SESS-BAD").length, 0);
  assert.equal(seen.length, 0);
  await attach(cdp, { sessionId: "SESS-A", targetId: "REAL-TA" });
  await attach(cdp, { sessionId: "SESS-IF", targetId: "REAL-TIF", type: "iframe", parent: "SESS-A" });
  assert.deepEqual(cdp.last("Target.closeTarget").params, { targetId: "REAL-TIF" });
  await attach(cdp, { sessionId: "SESS-W", targetId: "REAL-TW", type: "worker", parent: "SESS-A" });
  assert.deepEqual(cdp.last("Target.closeTarget").params, { targetId: "REAL-TA" }); // (a worker's page is closed)
  assert.equal(session.state, "running");
  failOn.add("SESS-SW");
  await attach(cdp, { sessionId: "SESS-SW", targetId: "REAL-TSW", type: "service_worker" });
  assert.equal(session.state, "retired"); // (no page to close)
  assert.equal(retired.length, 1);
});

test("attach: workers, out-of-process iframes and other contexts' pages are hardened and run, but never shown", async () => {
  const { cdp, seen, hardened } = await setup();
  await attach(cdp, { sessionId: "SESS-A", targetId: "REAL-TA" });
  await attach(cdp, { sessionId: "SESS-IF", targetId: "REAL-TIF", type: "iframe", parent: "SESS-A" });
  await attach(cdp, { sessionId: "SESS-W", targetId: "REAL-TW", type: "worker", parent: "SESS-A" });
  await attach(cdp, { sessionId: "SESS-SIGNIN", targetId: "REAL-TS", context: "REAL-CLEAN-CTX" }); // (the clean sign-in context)
  assert.deepEqual(hardened.slice(1), ["page:SESS-A", "iframe:SESS-IF", "worker:SESS-W", "page:SESS-SIGNIN"]);
  for (const s of ["SESS-IF", "SESS-W", "SESS-SIGNIN"]) assert.equal(cdp.find("Runtime.runIfWaitingForDebugger", s).length, 1, s);
  assert.equal(seen.length, 1); // (only the agent's page)
  for (const s of ["SESS-IF", "SESS-W", "SESS-SIGNIN"]) cdp.emit("Page.loadEventFired", { timestamp: 1 }, s);
  cdp.emit("Page.loadEventFired", { timestamp: 1 });
  assert.equal(seen.length, 1);
  cdp.emit("Page.loadEventFired", { timestamp: 1 }, "SESS-A");
  assert.equal(seen.length, 2);
});

test("attach: a page the agent didn't open is shown only if it's http(s) or about:blank, and only up to 16 pages", async () => {
  const { cdp, seen } = await setup();
  await attach(cdp, { sessionId: "SESS-P1", targetId: "REAL-TP1", url: "javascript:alert(1)" });
  assert.deepEqual(cdp.last("Target.closeTarget").params, { targetId: "REAL-TP1" });
  await attach(cdp, { sessionId: "SESS-P2", targetId: "REAL-TP2", url: "chrome://settings" });
  assert.equal(seen.length, 0);
  for (let i = 0; i < 16; i++) await attach(cdp, { sessionId: `SESS-${i}`, targetId: `REAL-T${i}`, url: i % 2 ? "https://example.test/" : "" });
  assert.equal(seen.length, 16);
  await attach(cdp, { sessionId: "SESS-17", targetId: "REAL-T17" });
  assert.equal(seen.length, 16);
  assert.deepEqual(cdp.last("Target.closeTarget").params, { targetId: "REAL-T17" });
  cdp.emit("Target.detachedFromTarget", { sessionId: "SESS-0" });
  assert.equal(seen.at(-1).method, "Target.targetDestroyed");
  await attach(cdp, { sessionId: "SESS-18", targetId: "REAL-T18" });
  assert.equal(seen.at(-1).method, "Target.targetCreated"); // (a place freed by a closed page)
});

test("commands: sent on the page's real session with real ids; CDP's errors get a fixed message; a closed pipe is unknown and retires", async () => {
  const { cdp, seen, session, retired } = await setup();
  await attach(cdp, { sessionId: "SESS-A", targetId: "REAL-TA" });
  const pa = pageVid(seen);
  const doc = session.command({ method: "DOM.getDocument", params: {}, sessionId: pa });
  await settle();
  const sent = cdp.last("DOM.getDocument");
  assert.equal(sent.sessionId, "SESS-A");
  sent.ok({ root: { nodeId: 900001, backendNodeId: 900002, nodeType: 9, nodeName: "#document", localName: "", nodeValue: "" } });
  const r = await doc;
  assert.ok(r.result.root.nodeId.startsWith("nd_"));
  const q = session.command({ method: "DOM.querySelector", params: { nodeId: r.result.root.nodeId, selector: "a" }, sessionId: pa });
  await settle();
  assert.deepEqual(cdp.last("DOM.querySelector").params, { nodeId: 900001, selector: "a" });
  cdp.last("DOM.querySelector").fail(new CdpError(-32000, "Could not find node with given id REAL-900001"));
  assert.deepEqual(await q, { error: { code: -32000, message: "the browser refused the command" } });
  assert.equal((await session.command({ method: "Browser.close", params: {}, sessionId: pa })).error.code, -32601);
  assert.equal(cdp.find("Browser.close").length, 0);
  const lost = session.command({ method: "Page.reload", params: {}, sessionId: pa });
  await settle();
  cdp.die("crash");
  assert.deepEqual(await lost, { unknown: true });
  await settle();
  assert.equal(session.state, "retired");
  assert.equal(retired.length, 1);
});

test("deadline: a call still running at 30 s is answered 'timed out', its script terminated, its group released; its late answer is never used", async () => {
  const { cdp, seen, session, clock } = await setup();
  await attach(cdp, { sessionId: "SESS-A", targetId: "REAL-TA" });
  const pa = pageVid(seen);
  const ev = session.command({ method: "Runtime.evaluate", params: { expression: "x", objectGroup: "g" }, sessionId: pa });
  await settle();
  cdp.last("Runtime.evaluate").ok({ result: { type: "object", objectId: "REAL-O1" } });
  const ob = (await ev).result.result.objectId;
  const call = session.command({ method: "Runtime.callFunctionOn", params: { functionDeclaration: "() => new Promise(() => {})", objectId: ob, awaitPromise: true, objectGroup: "g" }, sessionId: pa });
  await clock.advance(DRAIN.tickMs * 29 + 999); // (29.999 s)
  assert.equal(cdp.find("Runtime.terminateExecution").length, 0);
  await clock.advance(1);
  assert.deepEqual(await call, { error: { code: -32000, message: "timed out" } });
  assert.equal(cdp.last("Runtime.terminateExecution").sessionId, "SESS-A");
  assert.deepEqual(cdp.last("Runtime.releaseObjectGroup").params, { objectGroup: `${GROUP_PREFIX}g` });
  assert.equal((await session.command({ method: "Runtime.getProperties", params: { objectId: ob }, sessionId: pa })).error.message, "stale handle"); // (its group's objects end)
  cdp.find("Runtime.callFunctionOn")[0].ok({ result: { type: "object", objectId: "REAL-LATE" } }); // (the late answer: nothing happens)
  await settle();
  assert.ok(!JSON.stringify(seen).includes("REAL-"));
  const plain = session.command({ method: "DOM.getDocument", params: {}, sessionId: pa });
  await clock.advance(60000); // (a command without the deadline isn't cut)
  cdp.last("DOM.getDocument").ok({ root: { nodeId: 900005, backendNodeId: 900006, nodeType: 9, nodeName: "#document", localName: "", nodeValue: "" } });
  assert.ok((await plain).result);
});

test("createTarget: the page opens in the agent's context and the answer waits until it's hardened and shown, either order", async () => {
  const { cdp, seen, session } = await setup();
  const c1 = session.command({ method: "Target.createTarget", params: { url: "https://example.test/a" } });
  await settle();
  const sent = cdp.last("Target.createTarget");
  assert.deepEqual(sent.params, { url: "https://example.test/a", browserContextId: "REAL-CTX", background: false });
  sent.ok({ targetId: "REAL-TN1" }); // (the answer before the attach)
  await settle();
  await attach(cdp, { sessionId: "SESS-N1", targetId: "REAL-TN1", url: "https://example.test/a" });
  const r1 = await c1;
  assert.equal(r1.result.targetId, pageVid(seen, 0));
  const c2 = session.command({ method: "Target.createTarget", params: { url: "about:blank", background: true } });
  await settle();
  await attach(cdp, { sessionId: "SESS-N2", targetId: "REAL-TN2" }); // (the attach before the answer)
  cdp.last("Target.createTarget").ok({ targetId: "REAL-TN2" });
  assert.equal((await c2).result.targetId, pageVid(seen, 1));
  assert.equal((await session.command({ method: "Target.createTarget", params: { url: "https://claude.ai/" } })).error.message, "blocked: account site (claude.ai)");
  const close = session.command({ method: "Target.closeTarget", params: { targetId: pageVid(seen, 0) } });
  await settle();
  assert.deepEqual(cdp.last("Target.closeTarget").params, { targetId: "REAL-TN1" });
  assert.deepEqual(await close, { result: { success: true } });
});

test("takeover: nothing in flight: no script is terminated, the agent's groups are released with their own sessions, then paused", async () => {
  const { cdp, seen, session } = await setup();
  await attach(cdp, { sessionId: "SESS-A", targetId: "REAL-TA" });
  await attach(cdp, { sessionId: "SESS-B", targetId: "REAL-TB" });
  for (const [i, s] of [[0, "SESS-A"], [1, "SESS-B"]]) {
    const ev = session.command({ method: "Runtime.evaluate", params: { expression: "x", objectGroup: "shared" }, sessionId: pageVid(seen, i) });
    await settle(); cdp.last("Runtime.evaluate").ok({ result: { type: "object", objectId: `REAL-O-${s}` } }); await ev;
  }
  assert.deepEqual(await session.takeover(), { paused: true });
  assert.equal(cdp.find("Runtime.terminateExecution").length, 0); // (terminate would hit the page's own next script)
  assert.deepEqual(cdp.find("Runtime.releaseObjectGroup").map((c) => [c.sessionId, c.params.objectGroup]).sort(), [["SESS-A", `${GROUP_PREFIX}shared`], ["SESS-B", `${GROUP_PREFIX}shared`]]);
  assert.equal((await session.command({ method: "Page.reload", params: {}, sessionId: pageVid(seen, 0) })).error.message, "paused: takeover");
  cdp.emit("Page.loadEventFired", { timestamp: 1 }, "SESS-A");
  assert.equal(seen.filter((e) => e.method === "Page.loadEventFired").length, 0);
  const shown = seen.length;
  assert.equal(session.handback(), true);
  assert.equal(seen.length, shown + 2);
  assert.equal(session.handback(), false); // (twice: the pages aren't announced again)
  assert.equal(seen.length, shown + 2);
  const back = seen.slice(-2).map((e) => e.params.targetInfo.targetId);
  assert.ok(back.every((v) => v.startsWith("pg_")) && !back.includes(pageVid(seen, 0)));
  const reload = session.command({ method: "Page.reload", params: {}, sessionId: back[0] });
  await settle();
  assert.equal(cdp.last("Page.reload").sessionId, "SESS-A");
  cdp.last("Page.reload").ok({});
  assert.deepEqual(await reload, { result: {} });
});

test("takeover: a command still running after 2 s: its page alone gets terminate; its answer is never forwarded; paused", async () => {
  const { cdp, seen, session, clock } = await setup();
  await attach(cdp, { sessionId: "SESS-A", targetId: "REAL-TA" });
  await attach(cdp, { sessionId: "SESS-B", targetId: "REAL-TB" });
  const loop = session.command({ method: "Runtime.evaluate", params: { expression: "for(;;){}" }, sessionId: pageVid(seen, 0) });
  await settle();
  const t = session.takeover();
  await clock.advance(DRAIN.waitMs - 1);
  assert.equal(cdp.find("Runtime.terminateExecution").length, 0);
  await clock.advance(1);
  assert.deepEqual(cdp.find("Runtime.terminateExecution").map((c) => c.sessionId), ["SESS-A"]);
  cdp.last("Runtime.terminateExecution").ok({});
  cdp.last("Runtime.evaluate").ok({ result: { type: "object", objectId: "REAL-AFTER" }, exceptionDetails: { exceptionId: 1, text: "terminated", lineNumber: 0, columnNumber: 0 } });
  assert.deepEqual(await t, { paused: true });
  assert.deepEqual(await loop, { unknown: true });
  assert.ok(!JSON.stringify(seen).includes("REAL-"));
});

test("takeover: a promise that never settles is abandoned (unknown) and its late answer after handback is never used", async () => {
  const { cdp, seen, session, clock } = await setup();
  await attach(cdp, { sessionId: "SESS-A", targetId: "REAL-TA" });
  const pa = pageVid(seen);
  const never = session.command({ method: "Runtime.evaluate", params: { expression: "new Promise(()=>{})", awaitPromise: true }, sessionId: pa });
  await settle();
  const t = session.takeover();
  await clock.advance(DRAIN.waitMs);
  cdp.last("Runtime.terminateExecution").ok({}); // (terminate answers; the promise still never settles)
  await clock.advance(DRAIN.terminateMs);
  assert.deepEqual(await t, { paused: true });
  assert.equal(session.state, "paused");
  session.handback();
  cdp.last("Runtime.evaluate").ok({ result: { type: "object", objectId: "REAL-LATE" } });
  assert.deepEqual(await never, { unknown: true });
  assert.ok(!JSON.stringify(seen).includes("REAL-"));
});

test("takeover: terminate that doesn't answer within 3 s, or fails, retires the session", async () => {
  for (const mode of ["silent", "fails"]) {
    const { cdp, seen, session, clock, retired } = await setup();
    await attach(cdp, { sessionId: "SESS-A", targetId: "REAL-TA" });
    session.command({ method: "Runtime.evaluate", params: { expression: "for(;;){}" }, sessionId: pageVid(seen) });
    await settle();
    const t = session.takeover();
    await clock.advance(DRAIN.waitMs);
    if (mode === "fails") cdp.last("Runtime.terminateExecution").fail(new CdpError(-32000, "no"));
    else await clock.advance(DRAIN.terminateMs - 1);
    if (mode === "silent") assert.equal(session.state, "paused", mode);
    await clock.advance(mode === "silent" ? 1 : 0);
    assert.deepEqual(await t, { retired: true }, mode);
    assert.equal(session.state, "retired", mode);
    assert.equal(retired.length, 1, mode);
    assert.equal(cdp.closeCalls, 1, mode);
  }
});

test("time: console objects are released by the app after 60 s; events go to macapp's hook first, Fetch never to the agent", async () => {
  const { cdp, seen, session, clock, privileged } = await setup();
  await attach(cdp, { sessionId: "SESS-A", targetId: "REAL-TA" });
  cdp.emit("Runtime.consoleAPICalled", { type: "log", args: [{ type: "object", objectId: "REAL-CO" }], executionContextId: 900001, timestamp: 1 }, "SESS-A");
  const cob = seen.at(-1).params.args[0].objectId;
  await clock.advance(59000);
  assert.equal(cdp.find("Runtime.releaseObject").length, 0);
  await clock.advance(1000);
  assert.deepEqual(cdp.last("Runtime.releaseObject").params, { objectId: "REAL-CO" });
  assert.equal(cdp.last("Runtime.releaseObject").sessionId, "SESS-A");
  assert.equal((await session.command({ method: "Runtime.getProperties", params: { objectId: cob }, sessionId: pageVid(seen) })).error.message, "stale handle");
  const before = seen.length;
  cdp.emit("Fetch.authRequired", { requestId: "REAL-F", request: { url: "https://example.test/" }, frameId: "REAL-F1", resourceType: "Document", authChallenge: { source: "Proxy", origin: "http://127.0.0.1:1", scheme: "basic", realm: "" } }, "SESS-A");
  assert.equal(seen.length, before);
  assert.ok(privileged.includes("Fetch.authRequired"));
  assert.equal(privileged[0], "Target.attachedToTarget");
});

test("retirement: a spent handle budget retires the session and closes the browser; nothing more reaches the agent", async () => {
  const { cdp, seen, session, retired } = await setup({ budget: 3 });
  await attach(cdp, { sessionId: "SESS-A", targetId: "REAL-TA" });
  const ax = session.command({ method: "Accessibility.getFullAXTree", params: {}, sessionId: pageVid(seen) });
  await settle();
  cdp.last("Accessibility.getFullAXTree").ok({ nodes: [{ nodeId: "REAL-1", ignored: false }, { nodeId: "REAL-2", ignored: false }, { nodeId: "REAL-3", ignored: false }] });
  assert.deepEqual(await ax, { error: { code: -32000, message: "session retired" } });
  assert.equal(session.state, "retired");
  assert.equal(retired.length, 1);
  assert.equal(cdp.closeCalls, 1);
  const n = seen.length;
  cdp.emit("Page.loadEventFired", { timestamp: 1 }, "SESS-A");
  assert.equal(seen.length, n);
  assert.deepEqual(await session.takeover(), { retired: true });
  const { cdp: c2, session: s2, retired: r2 } = await setup();
  c2.die("crashed");
  await settle();
  assert.equal(s2.state, "retired");
  assert.equal(r2.length, 1);
});

test("takeover: a command the drain abandons settles as unknown then, leaves the in-flight set, and a second takeover doesn't terminate its page again", async () => {
  const { cdp, seen, session, clock } = await setup();
  await attach(cdp, { sessionId: "SESS-A", targetId: "REAL-TA" });
  let outcome = "pending";
  session.command({ method: "DOM.getDocument", params: {}, sessionId: pageVid(seen) }).then((r) => { outcome = r; }); // (no deadline of its own; CDP never answers)
  await settle();
  const t = session.takeover();
  await clock.advance(DRAIN.waitMs);
  cdp.last("Runtime.terminateExecution").ok({});
  await clock.advance(DRAIN.terminateMs);
  assert.deepEqual(await t, { paused: true });
  await settle();
  assert.deepEqual(outcome, { unknown: true }); // (settled when the drain gave it up, not left pending)
  session.handback();
  const terminates = cdp.find("Runtime.terminateExecution").length;
  const t2 = session.takeover();
  await clock.advance(DRAIN.waitMs + DRAIN.terminateMs);
  assert.deepEqual(await t2, { paused: true });
  assert.equal(cdp.find("Runtime.terminateExecution").length, terminates); // (nothing in flight: no terminate)
  cdp.find("DOM.getDocument")[0].ok({ root: { nodeId: 900001, backendNodeId: 900002, nodeType: 9, nodeName: "#document", localName: "", nodeValue: "" } });
  await settle();
  assert.ok(!JSON.stringify(seen).includes("REAL-"));
});

test("createTarget: one 30 s bound over the answer and the attach: answered at 29 s, never attached, it's 'timed out' at 30 s and frees its place", async () => {
  const { cdp, seen, session, clock } = await setup();
  let outcome = "pending";
  session.command({ method: "Target.createTarget", params: { url: "about:blank" } }).then((r) => { outcome = r; });
  await clock.advance(29000);
  cdp.last("Target.createTarget").ok({ targetId: "REAL-TLATE" });
  await clock.advance(999);
  assert.equal(outcome, "pending");
  await clock.advance(1);
  assert.deepEqual(outcome, { error: { code: -32000, message: "timed out" } });
  for (let i = 0; i < 16; i++) { // (the timed-out one no longer holds one of the 16 places)
    const c = session.command({ method: "Target.createTarget", params: { url: "about:blank" } });
    await settle();
    cdp.last("Target.createTarget").ok({ targetId: `REAL-TN${i}` });
    await attach(cdp, { sessionId: `SESS-N${i}`, targetId: `REAL-TN${i}` });
    assert.ok((await c).result, String(i));
  }
  const never = session.command({ method: "Target.createTarget", params: { url: "about:blank" } });
  assert.equal((await never).error.message, "too many pages");
  assert.equal(seen.filter((e) => e.method === "Target.targetCreated").length, 16);
  const silent = await setup();
  let o2 = "pending";
  silent.session.command({ method: "Target.createTarget", params: { url: "about:blank" } }).then((r) => { o2 = r; });
  await silent.clock.advance(DRAIN.attachMs);
  assert.deepEqual(o2, { error: { code: -32000, message: "timed out" } }); // (CDP never answering at all: the same bound)
});

test("closing for safety: only { success: true } within 5 s counts; a refused, unsuccessful or silent close retires the session", async () => {
  for (const mode of ["success-false", "rejected", "silent"]) {
    const { cdp, seen, session, clock, retired } = await setup({ harden: async (a) => { if (a.sessionId === "SESS-W") throw new Error("no"); } });
    await attach(cdp, { sessionId: "SESS-A", targetId: "REAL-TA" });
    const pa = pageVid(seen);
    if (mode === "success-false") cdp.auto["Target.closeTarget"] = () => ({ success: false });
    if (mode === "rejected") cdp.auto["Target.closeTarget"] = () => { throw new CdpError(-32000, "no"); };
    if (mode === "silent") delete cdp.auto["Target.closeTarget"];
    await attach(cdp, { sessionId: "SESS-W", targetId: "REAL-TW", type: "worker", parent: "SESS-A" });
    assert.deepEqual(cdp.last("Target.closeTarget").params, { targetId: "REAL-TA" }, mode);
    if (mode === "silent") { await clock.advance(DRAIN.closeMs - 1); assert.equal(session.state, "running", mode); await clock.advance(1); }
    assert.equal(session.state, "retired", mode);
    assert.equal(retired.length, 1, mode);
    assert.equal(cdp.find("Runtime.runIfWaitingForDebugger", "SESS-W").length, 0, mode);
    assert.deepEqual(await session.command({ method: "Page.reload", params: {}, sessionId: pa }), { error: { code: -32000, message: "session retired" } }, mode);
  }
  for (const mode of ["success-false", "silent"]) { // (a popup that may not be shown, and won't close: the same helper, the same end)
    const p = await setup();
    if (mode === "success-false") p.cdp.auto["Target.closeTarget"] = () => ({ success: false });
    else delete p.cdp.auto["Target.closeTarget"];
    await attach(p.cdp, { sessionId: "SESS-P", targetId: "REAL-TP", url: "javascript:1" });
    if (mode === "silent") { assert.equal(p.session.state, "running"); await p.clock.advance(DRAIN.closeMs); }
    assert.equal(p.session.state, "retired", mode);
    assert.equal(p.cdp.find("Runtime.runIfWaitingForDebugger", "SESS-P").length, 0, mode);
    assert.equal(p.seen.length, 0, mode);
  }
  const over = await setup(); // (the 17th page, over the limit, and its close refused)
  for (let i = 0; i < 16; i++) await attach(over.cdp, { sessionId: `SESS-${i}`, targetId: `REAL-T${i}` });
  over.cdp.auto["Target.closeTarget"] = () => ({ success: false });
  await attach(over.cdp, { sessionId: "SESS-17", targetId: "REAL-T17" });
  assert.equal(over.session.state, "retired");
  const ok = await setup({ harden: async (a) => { if (a.sessionId === "SESS-W") throw new Error("no"); } });
  await attach(ok.cdp, { sessionId: "SESS-A", targetId: "REAL-TA" });
  await attach(ok.cdp, { sessionId: "SESS-W", targetId: "REAL-TW", type: "worker", parent: "SESS-A" });
  assert.equal(ok.session.state, "running"); // (a confirmed close: the session goes on)
});

test("takeover: a deadline command abandoned by the drain never fires its deadline later (no terminate, no 'timed out' after handback)", async () => {
  const { cdp, seen, session, clock } = await setup();
  await attach(cdp, { sessionId: "SESS-A", targetId: "REAL-TA" });
  let outcome = "pending";
  session.command({ method: "Runtime.evaluate", params: { expression: "new Promise(()=>{})", awaitPromise: true }, sessionId: pageVid(seen) }).then((r) => { outcome = r; });
  await clock.advance(10000);
  const t = session.takeover();
  await clock.advance(DRAIN.waitMs);
  cdp.last("Runtime.terminateExecution").ok({});
  await clock.advance(DRAIN.terminateMs);
  assert.deepEqual(await t, { paused: true });
  assert.deepEqual(outcome, { unknown: true });
  session.handback();
  const terminates = cdp.find("Runtime.terminateExecution").length, releases = cdp.find("Runtime.releaseObjectGroup").length;
  await clock.advance(30000); // (past the old command's 30 s)
  assert.equal(cdp.find("Runtime.terminateExecution").length, terminates);
  assert.equal(cdp.find("Runtime.releaseObjectGroup").length, releases);
  assert.deepEqual(outcome, { unknown: true });
});

test("createTarget: CDP's answer arriving after the 30 s registers nothing, however many times (no waiter is left behind)", async () => {
  const { cdp, session, clock } = await setup();
  for (let i = 0; i < 5; i++) {
    let outcome = "pending";
    session.command({ method: "Target.createTarget", params: { url: "about:blank" } }).then((r) => { outcome = r; });
    await clock.advance(DRAIN.attachMs);
    assert.deepEqual(outcome, { error: { code: -32000, message: "timed out" } }, String(i));
    cdp.last("Target.createTarget").ok({ targetId: `REAL-LATE${i}` }); // (the late answer; that page never attaches)
    await settle();
    assert.equal(session.waitingTargets, 0, String(i));
  }
  let outcome = "pending"; // (still answered at 29 s and then waiting for its attach: one waiter, removed at 30 s)
  session.command({ method: "Target.createTarget", params: { url: "about:blank" } }).then((r) => { outcome = r; });
  await clock.advance(29000);
  cdp.last("Target.createTarget").ok({ targetId: "REAL-SLOW" });
  await settle();
  assert.equal(session.waitingTargets, 1);
  await clock.advance(1000);
  assert.deepEqual(outcome, { error: { code: -32000, message: "timed out" } });
  assert.equal(session.waitingTargets, 0);
});

test("a command given up at its own 30 s leaves tracking then: an idle takeover terminates nothing, and its late answer is discarded", async () => {
  const { cdp, seen, session, clock } = await setup();
  await attach(cdp, { sessionId: "SESS-A", targetId: "REAL-TA" });
  const pa = pageVid(seen);
  let outcome = "pending";
  session.command({ method: "Runtime.evaluate", params: { expression: "new Promise(()=>{})", awaitPromise: true }, sessionId: pa }).then((r) => { outcome = r; });
  await settle();
  assert.equal(session.inflight, 1);
  await clock.advance(30000);
  assert.deepEqual(outcome, { error: { code: -32000, message: "timed out" } });
  assert.equal(session.inflight, 0); // (given up now, not when CDP someday answers)
  cdp.last("Runtime.terminateExecution").ok({});
  const terminates = cdp.find("Runtime.terminateExecution").length;
  const t = session.takeover();
  await clock.advance(DRAIN.waitMs + DRAIN.terminateMs);
  assert.deepEqual(await t, { paused: true });
  assert.equal(cdp.find("Runtime.terminateExecution").length, terminates); // (idle: no second terminate)
  session.handback();
  cdp.find("Runtime.evaluate")[0].ok({ result: { type: "object", objectId: "REAL-LATE" } }); // (the late answer)
  await settle();
  assert.deepEqual(outcome, { error: { code: -32000, message: "timed out" } });
  assert.ok(!JSON.stringify(seen).includes("REAL-"));
  for (let i = 0; i < 5; i++) { // (repeated deadlines: nothing accumulates)
    session.command({ method: "Runtime.callFunctionOn", params: { functionDeclaration: "() => new Promise(() => {})", executionContextId: (() => { cdp.emit("Runtime.executionContextCreated", { context: { id: 900100 + i, origin: "", name: "", uniqueId: `REAL-U${i}`, auxData: { frameId: "REAL-F1", isDefault: false } } }, "SESS-A"); return seen.at(-1).params.context.id; })(), awaitPromise: true }, sessionId: pa });
    await clock.advance(30000);
  }
  assert.equal(session.inflight, 0);
  const { cdp: c2, session: s2, clock: k2 } = await setup(); // (createTarget's own timeout: the same)
  s2.command({ method: "Target.createTarget", params: { url: "about:blank" } });
  await k2.advance(DRAIN.attachMs);
  assert.equal(s2.inflight, 0);
  assert.equal(c2.find("Runtime.terminateExecution").length, 0);
});

test("createTarget waiting for an attach that never comes: a takeover's abandon (or retirement) removes its waiter too, every time", async () => {
  const { cdp, session, clock } = await setup();
  for (let i = 0; i < 5; i++) {
    let outcome = "pending";
    session.command({ method: "Target.createTarget", params: { url: "about:blank" } }).then((r) => { outcome = r; });
    await settle();
    cdp.last("Target.createTarget").ok({ targetId: `REAL-NOATTACH${i}` }); // (answered at once; the page never attaches)
    await settle();
    assert.equal(session.waitingTargets, 1, String(i));
    const t = session.takeover();
    await clock.advance(DRAIN.waitMs);
    await clock.advance(DRAIN.terminateMs);
    assert.deepEqual(await t, { paused: true }, String(i));
    assert.deepEqual(outcome, { unknown: true }, String(i));
    assert.equal(session.inflight, 0, String(i));
    assert.equal(session.waitingTargets, 0, String(i));
    session.handback();
  }
  await clock.advance(60000);
  assert.equal(session.waitingTargets, 0);
  const r = await setup(); // (retirement: the same)
  r.session.command({ method: "Target.createTarget", params: { url: "about:blank" } });
  await settle();
  r.cdp.last("Target.createTarget").ok({ targetId: "REAL-NOATTACH" });
  await settle();
  assert.equal(r.session.waitingTargets, 1);
  r.cdp.die("crash");
  await settle();
  assert.equal(r.session.waitingTargets, 0);
});
