// The cdp sidecar's process (lib/fleet/browser/sidecar-cdp-main.mjs), wired end to end: Rust's frames on stdin and
// stdout through the real codec (./frames.mjs), Chrome's pipe through the real pipe client (./pipe.mjs), the real
// session driver, Filter and hardening. In-process with injected streams, and once as a spawned process on real fds.

import assert from "node:assert/strict";
import { test } from "node:test";
import { PassThrough } from "node:stream";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { createEncoder } from "../lib/fleet/browser/frames.mjs";
import { main } from "../lib/fleet/browser/sidecar-cdp-main.mjs";
import { pinnedPermissions } from "../lib/fleet/browser/harden.mjs";
import { PINS } from "../lib/fleet/browser/pins.mjs";

const settle = async (n = 20) => { for (let i = 0; i < n; i++) await new Promise((r) => setImmediate(r)); };
const fromRust = createEncoder({ from: "rust" }), fromNet = createEncoder({ from: "net" });
const BUILD = "158.0.8127.36";
const LIST = { build: BUILD, descriptors: [{ name: "geolocation" }] };
const auth = () => fromRust({ to: "cdp", kind: "cdp.proxy_auth", username: "sess-user", password: "sess-pass", proxy_port: 40123 });
const start = () => fromRust({ to: "cdp", kind: "cdp.start", chrome_pid: 4242 });
const command = (seq, cmd) => fromNet({ to: "cdp", kind: "cdp.command", seq }, Buffer.from(JSON.stringify(cmd)));

// A minimal reader of what cdp writes (both its Rust and its net frames), for the test only.
function frameReader(stream) {
  const frames = [];
  let buf = Buffer.alloc(0);
  stream.on("data", (c) => {
    buf = Buffer.concat([buf, c]);
    while (buf.length >= 4) {
      const total = buf.readUInt32BE(0);
      if (buf.length < 4 + total) break;
      const h = buf.readUInt32BE(4);
      frames.push({ head: JSON.parse(buf.subarray(8, 8 + h).toString("utf8")), body: buf.subarray(8 + h, 4 + total).toString("utf8") });
      buf = buf.subarray(4 + total);
    }
  });
  return frames;
}
// A fake Chrome on two in-memory streams: answers every command, and lets the test send events.
function fakeChrome({ build = BUILD } = {}) {
  const toChrome = new PassThrough(), fromChrome = new PassThrough(), seen = [];
  let buf = Buffer.alloc(0);
  const out = (m) => fromChrome.write(JSON.stringify(m) + "\0");
  toChrome.on("data", (c) => {
    buf = Buffer.concat([buf, c]);
    for (let i; (i = buf.indexOf(0)) !== -1; buf = buf.subarray(i + 1)) {
      const m = JSON.parse(buf.subarray(0, i).toString("utf8"));
      seen.push(m);
      const result = m.method === "Browser.getVersion" ? { product: `HeadlessChrome/${build}`, protocolVersion: "1.3" }
        : m.method === "Target.createBrowserContext" ? { browserContextId: "REAL-CTX" }
        : m.method === "Target.closeTarget" ? { success: true } : {};
      out(m.sessionId ? { id: m.id, result, sessionId: m.sessionId } : { id: m.id, result });
    }
  });
  return { chromeRead: () => fromChrome, chromeWrite: () => toChrome, seen, event: (method, params, sessionId) => out({ method, params, ...(sessionId ? { sessionId } : {}) }) };
}
function run(opts = {}) {
  const stdin = new PassThrough(), stdout = new PassThrough(), chrome = fakeChrome(opts.chrome), exits = [];
  const frames = frameReader(stdout);
  const sidecar = main({ stdin, stdout, chromeRead: chrome.chromeRead, chromeWrite: chrome.chromeWrite, permissions: opts.permissions ?? (() => LIST), exit: (c) => exits.push(c) });
  return { stdin, stdout, frames, chrome, exits, sidecar };
}
const states = (frames) => frames.filter((f) => f.head.kind === "rust.cdp_state").map((f) => f.head.state + (f.head.reason ? `:${f.head.reason}` : ""));

test("wired end to end: credentials and start over real frames; Chrome's pipe opens and the context is hardened; a command's answer and a page's event go to net; retire ends and exits 0", async () => {
  const t = run();
  t.stdin.write(Buffer.concat([auth(), start()]));
  await settle();
  assert.deepEqual(states(t.frames), ["starting", "ready"]);
  const methods = t.chrome.seen.map((m) => m.method);
  assert.deepEqual(methods.slice(0, 4), ["Browser.getVersion", "Target.createBrowserContext", "Browser.getVersion", "Browser.setDownloadBehavior"]);
  assert.ok(methods.includes("Browser.setPermission") && methods.includes("Target.setAutoAttach"));
  t.chrome.event("Target.attachedToTarget", { sessionId: "SESS-A", targetInfo: { targetId: "REAL-TA", type: "page", title: "", url: "about:blank", attached: true, browserContextId: "REAL-CTX" }, waitingForDebugger: true });
  await settle();
  const created = t.frames.find((f) => f.head.kind === "net.event");
  assert.equal(JSON.parse(created.body).method, "Target.targetCreated");
  assert.ok(t.chrome.seen.some((m) => m.method === "Fetch.enable" && m.sessionId === "SESS-A"));
  t.stdin.write(command(1, { method: "Target.getTargets" }));
  await settle();
  const r = t.frames.find((f) => f.head.kind === "net.result" && f.head.seq === 1);
  assert.equal(JSON.parse(r.body).result.targetInfos.length, 1);
  assert.ok(!JSON.stringify(t.frames).includes("REAL-") && !JSON.stringify(t.frames).includes("sess-pass"));
  t.stdin.write(fromRust({ to: "cdp", kind: "cdp.retire" }));
  await settle();
  assert.equal(states(t.frames).at(-1), "ended:retired by the app");
  assert.deepEqual(t.exits, [0]);
});

test("the app's channel: a bad frame, a stream that ends inside a frame, or a plain end all end the sidecar (and nothing after)", async () => {
  for (const [what, feed, reason] of [
    ["garbage", (s) => s.write(Buffer.from([0, 0, 0, 3, 0, 0, 0])), "a bad frame from the app"],
    ["a frame for net", (s) => s.write(fromRust({ to: "net", kind: "net.retire" })), "a bad frame from the app"],
    ["a truncated frame", (s) => { const f = auth(); s.write(f.subarray(0, f.length - 3)); s.end(); }, "the app's channel ended inside a frame"],
    ["a plain end", (s) => s.end(), "the app closed the channel"],
  ]) {
    const t = run();
    feed(t.stdin);
    await settle();
    assert.equal(states(t.frames).at(-1), `ended:${reason}`, what);
    assert.deepEqual(t.exits, [0], what);
    const n = t.frames.length;
    if (!t.stdin.writableEnded) t.stdin.write(Buffer.concat([auth(), start()]));
    await settle();
    assert.equal(t.frames.length, n, what);
  }
});

test("the app's output: if stdout breaks (Rust is gone), the session retires and the process exits 0, once", async () => {
  const t = run();
  t.stdin.write(Buffer.concat([auth(), start()]));
  await settle();
  assert.deepEqual(states(t.frames), ["starting", "ready"]);
  t.stdout.destroy(Object.assign(new Error("write EPIPE"), { code: "EPIPE" }));
  await settle();
  assert.equal(t.sidecar.state, "ended");
  assert.deepEqual(t.exits, [0]);
  t.stdin.write(command(1, { method: "Target.getTargets" }));
  await settle();
  assert.ok(!t.chrome.seen.some((m) => m.method === "Target.getTargets"));
});

test("the permission list must be the pinned one for the running build: none pinned (today's PINS), another build or tampered bytes end the session before anything attaches", async () => {
  assert.deepEqual(PINS.permissions, {}); // (until §9.1 adds 158's list)
  const none = run({ permissions: (b) => pinnedPermissions(b) });
  none.stdin.write(Buffer.concat([auth(), start()]));
  await settle();
  assert.equal(states(none.frames).at(-1), "ended:the browser context couldn't be set up and hardened");
  assert.ok(!none.chrome.seen.some((m) => m.method === "Target.setAutoAttach"));
  const bytes = Buffer.from(JSON.stringify(LIST));
  const sha = (await import("node:crypto")).createHash("sha256").update(bytes).digest("hex");
  assert.deepEqual(pinnedPermissions(BUILD, { pinned: { [BUILD]: sha }, read: () => bytes }), LIST);
  assert.throws(() => pinnedPermissions(BUILD, { pinned: { [BUILD]: sha }, read: () => Buffer.from(JSON.stringify({ ...LIST, descriptors: [] })) }), /isn't the pinned one/); // (a shortened list)
  assert.throws(() => pinnedPermissions("149.0.7827.196", { pinned: { [BUILD]: sha }, read: () => bytes }), /no pinned permission list/);
  assert.throws(() => pinnedPermissions(undefined, { pinned: { [BUILD]: sha }, read: () => bytes }), /no pinned permission list/);
  const wrong = Buffer.from(JSON.stringify({ ...LIST, build: "149.0.7827.196" }));
  const wsha = (await import("node:crypto")).createHash("sha256").update(wrong).digest("hex");
  assert.throws(() => pinnedPermissions(BUILD, { pinned: { [BUILD]: wsha }, read: () => wrong }), /for another build/);
});

test("as a process on real fds: Chrome's pipe on fds 3 and 4, frames on stdin and stdout; with no pinned list it ends the session and exits 0", async () => {
  const child = spawn(process.execPath, [fileURLToPath(new URL("../lib/fleet/browser/sidecar-cdp-main.mjs", import.meta.url))], { stdio: ["pipe", "pipe", "inherit", "pipe", "pipe"] });
  const frames = frameReader(child.stdout);
  const seen = [];
  let buf = Buffer.alloc(0);
  for (const s of [child.stdio[3], child.stdio[4], child.stdin]) s.on("error", () => {}); // (the pipes reset when the child exits)
  child.stdio[3].on("data", (c) => { // (the sidecar writes fd 3: what Chrome reads)
    buf = Buffer.concat([buf, c]);
    for (let i; (i = buf.indexOf(0)) !== -1; buf = buf.subarray(i + 1)) {
      const m = JSON.parse(buf.subarray(0, i).toString("utf8"));
      seen.push(m.method);
      const result = m.method === "Browser.getVersion" ? { product: `HeadlessChrome/${BUILD}` } : m.method === "Target.createBrowserContext" ? { browserContextId: "C" } : {};
      child.stdio[4].write(JSON.stringify({ id: m.id, result }) + "\0"); // (Chrome writes fd 4)
    }
  });
  const exited = new Promise((r) => child.on("exit", (code) => r(code)));
  child.stdin.write(Buffer.concat([auth(), start()]));
  let timer;
  const code = await Promise.race([exited, new Promise((r) => { timer = setTimeout(() => r("timeout"), 15000); })]);
  clearTimeout(timer);
  if (code === "timeout") child.kill("SIGKILL");
  assert.equal(code, 0);
  assert.deepEqual(states(frames), ["starting", "ended:the browser context couldn't be set up and hardened"]);
  assert.ok(seen.includes("Browser.getVersion") && !seen.includes("Target.setAutoAttach"));
});
