// The fleet core with the WebCrypto backend in a real browser: headless Chromium (BoringSSL's Ed25519, not Node's
// OpenSSL) loads lib/fleet/core/ as it is, over http://127.0.0.1 (a secure context), and runs every shared vector
// through test/fleet-fixture-cases.mjs, plus the recovery known answer the Node tests pin. Skipped where there is no
// Chromium or Chrome on PATH (or SAGEBRUSH_CHROME), and off Linux. One bounded run: the browser is killed at the
// deadline and when this process exits.
//
// Two deadlines, one per stage. A launch gets ASK_MS to ask for the page. A launch that never asks (the CI flake: a
// Chromium stuck at start, under load) is killed and retried ONCE, with a fresh profile. Once the page is asked for,
// nothing is retried: the page gets RESULT_MS to report, and whatever it reports, a WebCrypto failure included,
// decides the test.
//
// The page reports its result by POSTing it to this test's loopback server; the test ends the moment it arrives. It
// doesn't rely on Chromium's --dump-dom (printed only when Chromium decides it's done) or on virtual time, which
// pauses while fetches are pending: a CI run once ended with Chromium silent for the whole deadline. A failure says
// which stage was reached (Chromium never asked for the page, or the page loaded and never reported), with the
// requests the server saw and the end of Chromium's stderr.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import path, { posix } from "node:path";
import { test } from "node:test";

const ROOT = new URL("..", import.meta.url);
// (per launch: until Chromium asks for the page; SAGEBRUSH_CHROME_ASK_MS shortens it for the relaunch controls)
const ASK_MS = Number(process.env.SAGEBRUSH_CHROME_ASK_MS) > 0 ? Number(process.env.SAGEBRUSH_CHROME_ASK_MS) : 90_000;
const LAUNCHES = 2; // (the first, and one relaunch after a launch that never asked)
const RESULT_MS = 60_000; // (from the page's request: until the page reports)
const SLOW_MS = 3000; // (a page asked for later than this, though the test passes, prints how Chromium started)
const RECOVERY_KNOWN = ["QIgcRL3kWMdpVNtbHP7lkw", "8f8Zi-ibteyHFwp-PnAVfGC6-_75Je6BNI9mNkG6PM0"];

// (Google Chrome before Chromium, whichever PATH directory each is in: names outside, directories inside. On Ubuntu
// runners /usr/bin/chromium is the snap's wrapper, whose own start-up took 24 s under load before Chromium printed
// anything, and the runners also carry Google Chrome. SAGEBRUSH_CHROME, when set, decides. `paths` is the platform's
// path module by default; the selection row passes posix, so it reads the same on every runner.)
const BROWSERS = ["google-chrome-stable", "google-chrome", "chromium", "chromium-browser"];
export function findChrome(env = process.env, exists = existsSync, paths = path) {
  if (env.SAGEBRUSH_CHROME) return env.SAGEBRUSH_CHROME;
  const dirs = (env.PATH ?? "").split(paths.delimiter).filter(Boolean);
  for (const name of BROWSERS)
    for (const dir of dirs)
      if (exists(paths.join(dir, name))) return paths.join(dir, name);
  return null;
}
const chrome = process.platform === "linux" ? findChrome() : null;

const HARNESS = `<!doctype html><meta charset="utf-8">
<script type="module">
import * as core from "/lib/fleet/core/index.mjs";
import { checkFixtures, checkHpkeFixtures, checkHpkeVector } from "/test/fleet-fixture-cases.mjs";
const report = (r) => fetch("/result", { method: "POST", body: JSON.stringify(r) });
try {
  const get = async (p) => (await fetch(p)).json();
  const [F, fleet, reasons] = await Promise.all([get("/test/fixtures/fleet-fixtures.json"), get("/schema/fleet/fleet.schema.json"), get("/schema/fleet/reasons.json")]);
  core.useCrypto(core.webCrypto());
  core.useSchemas((n) => (n === "fleet.schema.json" ? fleet : reasons));
  const r = await checkFixtures(core, F);
  const hv = await checkHpkeVector(core, (await get("/test/fixtures/hpke-x25519-sha256-aes256gcm.json")).vector);
  const hf = await checkHpkeFixtures(core, await get("/test/fixtures/fleet-hpke-fixtures.json"));
  const k = await core.recoveryKey(core.idOfBytes(new Uint8Array(16).fill(7)), F.ids.fleet);
  // signing: RFC 8032 test 1 (its seed signs the empty message), and a sealed envelope that opens
  const hex = (h) => Uint8Array.from(h.match(/../g), (x) => parseInt(x, 16));
  const rfc = await core.keyFromSeed(hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"));
  const rfcSig = core.b64(await rfc.sign(new Uint8Array(0)));
  const signer = { kind: "device", id: F.ids.fleet, alg: "ed25519", key: rfc.key };
  const body = { fleet: F.ids.fleet, aud: F.aud, chain_seq: 0, what: "host", id: F.ids.fleet, host: F.ids.fleet, gen: 1, at_ms: 1 };
  const sealed = await core.seal("sb.revocation.v1", signer, body, rfc);
  const opened = (await core.open(sealed, { aud: F.aud, fleet: F.ids.fleet, resolveKey: () => rfc.raw })).body.gen;
  await report({ ...r, recovery: [k.key, core.b64(k.raw)], rfcPublic: core.b64(rfc.raw), rfcSig, opened, hpke: { vector: hv, fleet: hf }, ua: navigator.userAgent });
} catch (e) {
  await report({ error: String((e && e.stack) || e) });
}
</script>
<script>
// (a module that fails to load never runs the try above: report that too)
addEventListener("error", (e) => { fetch("/result", { method: "POST", body: JSON.stringify({ error: "load: " + (e.message || (e.target && e.target.src) || "an error") }) }); }, true);
</script>`;

// (only these files are served: the pure core, the shared checker, the vectors and the schemas)
const SERVED = /^\/(lib\/fleet\/core\/[a-z0-9-]+\.mjs|test\/fleet-fixture-cases\.mjs|test\/fixtures\/(fleet-fixtures|fleet-hpke-fixtures|hpke-x25519-sha256-aes256gcm)\.json|schema\/fleet\/(fleet\.schema|reasons)\.json)$/;
const TYPES = { mjs: "text/javascript", json: "application/json" };

test("headless Chromium: the core with the WebCrypto backend passes every shared vector", { skip: !chrome && "no Chromium or Chrome on PATH (Linux only)" }, async () => {
  let seen = [];
  let asked = null; // (resolves when the current launch asks for the page)
  let resolveResult;
  const result = new Promise((ok) => { resolveResult = ok; });
  const server = createServer((req, res) => {
    const path = new URL(req.url, "http://x").pathname;
    if (seen.length < 64) seen.push(`${req.method} ${path}`);
    if (req.method === "POST" && path === "/result") {
      let body = "";
      req.setEncoding("utf8");
      req.on("data", (d) => { if (body.length < 1 << 20) body += d; });
      req.on("end", () => { res.writeHead(204).end(); resolveResult(body); });
      return;
    }
    if (path === "/harness.html") {
      asked?.();
      return res.writeHead(200, { "content-type": "text/html" }).end(HARNESS);
    }
    if (!SERVED.test(path)) return res.writeHead(404).end();
    res.writeHead(200, { "content-type": TYPES[path.split(".").pop()] }).end(readFileSync(new URL("." + path, ROOT)));
  });
  await new Promise((ok) => server.listen(0, "127.0.0.1", ok));
  const url = `http://127.0.0.1:${server.address().port}/harness.html`;
  // (D-Bus at addresses that fail at once: Chromium waits on a bus that accepts and doesn't answer (seen with a silent
  // socket). The page needs nothing from either bus. --password-store=basic keeps Chromium off the desktop keyring,
  // which it reaches over D-Bus at start; the other flags skip start-up work the page doesn't need)
  const env = { ...process.env, DBUS_SYSTEM_BUS_ADDRESS: "unix:path=/nonexistent/dbus", DBUS_SESSION_BUS_ADDRESS: "unix:path=/nonexistent/dbus" };
  const launches = [];
  /** One launch with its own profile and process group; stop() kills it and waits, bounded, then removes the profile. */
  const launch = () => {
    const profile = mkdtempSync(path.join(tmpdir(), "fleet-webcrypto-"));
    // (--no-sandbox: containers and Ubuntu 24.04 runners refuse the namespaces Chromium's sandbox needs, and the page
    // loads nothing but the files above, from this loopback server)
    const args = ["--headless=new", "--no-sandbox", "--disable-gpu", "--no-first-run", "--no-default-browser-check", "--password-store=basic",
      "--disable-extensions", "--disable-background-networking", "--disable-component-update", "--disable-sync", `--user-data-dir=${profile}`, url];
    const started = performance.now();
    // (its own process group, so that the whole of Chromium, helpers included, is killed together)
    const child = spawn(chrome, args, { stdio: ["ignore", "ignore", "pipe"], detached: true, env });
    const L = { started, head: "", stderr: "", closed: null, kill: null };
    // (its stderr's start and end, each chunk stamped with the ms since the spawn: a failure says what it did, and when)
    child.stderr.on("data", (d) => { const t = `[+${Math.round(performance.now() - started)} ms] ${d}`; if (L.head.length < 4096) L.head += t; L.stderr = (L.stderr + t).slice(-4096); });
    L.kill = () => { try { process.kill(-child.pid, "SIGKILL"); } catch {} try { child.kill("SIGKILL"); } catch {} };
    process.once("exit", L.kill);
    L.closed = new Promise((ok) => child.once("close", (code, signal) => ok({ exited: `${code ?? signal}` })));
    L.stop = async () => {
      L.kill();
      // (wait, bounded, for Chromium to be gone before its profile is removed; a cleanup failure never fails the test)
      await Promise.race([L.closed, new Promise((ok) => setTimeout(ok, 5000).unref())]);
      process.removeListener("exit", L.kill);
      try { rmSync(profile, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }); } catch (e) { console.log(`# the profile directory stays: ${e.code}`); }
    };
    launches.push(L);
    return L;
  };
  const describe = (L, what) => `${what}; requests: ${seen.join(", ") || "none"}; ${chrome}; stderr's start: ${L.head.slice(0, 1500)}; its end: ${L.stderr.slice(-1500)}`;
  let timer;
  const wait = (ms, value) => new Promise((ok) => { timer = setTimeout(() => ok(value), ms); });
  try {
    let L = null, pageMs = null;
    // stage 1: until a launch asks for the page; a launch that doesn't is killed and retried, once
    for (let i = 1; i <= LAUNCHES && pageMs === null; i++) {
      if (L) { console.log(`# launch ${i - 1} never asked for the page; relaunching. ${describe(L, "the stuck launch")}`); await L.stop(); seen = []; }
      const askedP = new Promise((ok) => { asked = ok; });
      L = launch();
      const got = await Promise.race([askedP.then(() => ({ asked: true })), L.closed, wait(ASK_MS, { deadline: true })]);
      clearTimeout(timer);
      if (got.asked) pageMs = Math.round(performance.now() - L.started);
      else if (got.exited !== undefined && i === LAUNCHES) assert.fail(describe(L, `Chromium never asked for the page (it exited: ${got.exited}, launch ${i} of ${LAUNCHES})`));
    }
    if (pageMs === null) assert.fail(describe(L, `Chromium never asked for the page (${ASK_MS} ms, in each of ${LAUNCHES} launches)`));
    // stage 2: the page asked for: it reports, or the test fails; never retried
    const got = await Promise.race([result.then((body) => ({ body })), L.closed, wait(RESULT_MS, { deadline: true })]);
    if (got.body === undefined) assert.fail(describe(L, `the page loaded but never reported (${got.deadline ? `deadline ${RESULT_MS} ms` : `Chromium exited: ${got.exited}`})`));
    const r = JSON.parse(got.body);
    assert.equal(r.error, undefined, r.error);
    assert.deepEqual(r.bad, []);
    assert.ok(r.n > 80, `${r.n} cases`);
    assert.deepEqual(r.recovery, RECOVERY_KNOWN);
    assert.equal(r.rfcPublic, "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo");
    assert.equal(r.rfcSig, "5VZDAMNgrHKQhuLMgG6CioSHfx645dl02HPgZSJJAVVfuIIVkKM7rMYeOXAc-bRr0lv18FlbviRlUUFDjnoQCw");
    assert.equal(r.opened, 1);
    assert.deepEqual(r.hpke.vector.bad, []);
    assert.equal(r.hpke.vector.n, 260);
    assert.deepEqual(r.hpke.fleet.bad, []);
    assert.ok(r.hpke.fleet.n > 25, `${r.hpke.fleet.n} HPKE cases`);
    console.log(`# ${r.n} cases, HPKE ${r.hpke.vector.n} + ${r.hpke.fleet.n}, in ${r.ua}; ${chrome} asked for the page after ${pageMs} ms (launch ${launches.length})`);
    // (a slow start, though it passed: the stamped start of Chromium's stderr, to say where the seconds went)
    if (pageMs > SLOW_MS) console.log(`# slow: over ${SLOW_MS} ms; Chromium's stderr from its start:\n` + L.head.slice(0, 2000).split("\n").map((l) => `#   ${l}`).join("\n"));
  } finally {
    clearTimeout(timer);
    for (const L of launches) await L.stop();
    server.close();
    server.closeAllConnections?.();
  }
});

test("the browser's selection: Google Chrome before Chromium across PATH directories, the override first, none found", () => {
  const P = (...d) => d.join(posix.delimiter);
  const at = (...files) => (p) => files.includes(p);
  const find = (env, exists) => findChrome(env, exists, posix);
  // (Chromium in an earlier directory, Google Chrome in a later one: Chrome)
  assert.equal(find({ PATH: P("/early", "/late") }, at("/early/chromium", "/late/google-chrome-stable")), "/late/google-chrome-stable");
  assert.equal(find({ PATH: P("/early", "/late") }, at("/early/chromium-browser", "/late/google-chrome")), "/late/google-chrome");
  // (within one name, the first PATH directory wins)
  assert.equal(find({ PATH: P("/a", "/b") }, at("/a/google-chrome", "/b/google-chrome")), "/a/google-chrome");
  assert.equal(find({ PATH: P("/a", "/b") }, at("/b/google-chrome-stable", "/a/google-chrome")), "/b/google-chrome-stable");
  // (only Chromium: Chromium)
  assert.equal(find({ PATH: P("/a") }, at("/a/chromium")), "/a/chromium");
  // (the override decides, whatever PATH holds)
  assert.equal(find({ SAGEBRUSH_CHROME: "/opt/c", PATH: P("/a") }, at("/a/google-chrome-stable")), "/opt/c");
  // (nothing, or an empty PATH)
  assert.equal(find({ PATH: P("/a") }, at()), null);
  assert.equal(find({}, at("/google-chrome")), null);
});
