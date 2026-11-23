// The fleet core with the WebCrypto backend in a real browser: headless Chromium (BoringSSL's Ed25519, not Node's
// OpenSSL) loads lib/fleet/core/ as it is, over http://127.0.0.1 (a secure context), and runs every shared vector
// through test/fleet-fixture-cases.mjs, plus the recovery known answer the Node tests pin. Skipped where there is no
// Chromium or Chrome on PATH (or SAGEBRUSH_CHROME), and off Linux. One bounded run: the browser is killed at the
// deadline and when this process exits.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { test } from "node:test";

const ROOT = new URL("..", import.meta.url);
const DEADLINE_MS = 60_000;
const RECOVERY_KNOWN = ["QIgcRL3kWMdpVNtbHP7lkw", "8f8Zi-ibteyHFwp-PnAVfGC6-_75Je6BNI9mNkG6PM0"];

function findChrome() {
  if (process.env.SAGEBRUSH_CHROME) return process.env.SAGEBRUSH_CHROME;
  for (const dir of (process.env.PATH ?? "").split(delimiter))
    for (const name of ["chromium", "chromium-browser", "google-chrome", "google-chrome-stable"])
      if (dir && existsSync(join(dir, name))) return join(dir, name);
  return null;
}
const chrome = process.platform === "linux" ? findChrome() : null;

const HARNESS = `<!doctype html><meta charset="utf-8"><pre id="out">PENDING</pre>
<script type="module">
import * as core from "/lib/fleet/core/index.mjs";
import { checkFixtures, checkHpkeFixtures, checkHpkeVector } from "/test/fleet-fixture-cases.mjs";
const out = document.getElementById("out");
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
  out.textContent = "RESULT " + JSON.stringify({ ...r, recovery: [k.key, core.b64(k.raw)], rfcPublic: core.b64(rfc.raw), rfcSig, opened, hpke: { vector: hv, fleet: hf }, ua: navigator.userAgent });
} catch (e) {
  out.textContent = "RESULT " + JSON.stringify({ error: String((e && e.stack) || e) });
}
</script>`;

// (only these files are served: the pure core, the shared checker, the vectors and the schemas)
const SERVED = /^\/(lib\/fleet\/core\/[a-z0-9-]+\.mjs|test\/fleet-fixture-cases\.mjs|test\/fixtures\/(fleet-fixtures|fleet-hpke-fixtures|hpke-x25519-sha256-aes256gcm)\.json|schema\/fleet\/(fleet\.schema|reasons)\.json)$/;
const TYPES = { mjs: "text/javascript", json: "application/json" };

test("headless Chromium: the core with the WebCrypto backend passes every shared vector", { skip: !chrome && "no Chromium or Chrome on PATH (Linux only)" }, async () => {
  const server = createServer((req, res) => {
    const path = new URL(req.url, "http://x").pathname;
    if (path === "/harness.html") return res.writeHead(200, { "content-type": "text/html" }).end(HARNESS);
    if (!SERVED.test(path)) return res.writeHead(404).end();
    res.writeHead(200, { "content-type": TYPES[path.split(".").pop()] }).end(readFileSync(new URL("." + path, ROOT)));
  });
  await new Promise((ok) => server.listen(0, "127.0.0.1", ok));
  const profile = mkdtempSync(join(tmpdir(), "fleet-webcrypto-"));
  // (--no-sandbox: containers and Ubuntu 24.04 runners refuse the namespaces Chromium's sandbox needs, and the page
  // loads nothing but the files above, from this loopback server)
  const args = ["--headless=new", "--no-sandbox", "--disable-gpu", "--no-first-run", "--no-default-browser-check", `--user-data-dir=${profile}`,
    "--virtual-time-budget=30000", "--dump-dom", `http://127.0.0.1:${server.address().port}/harness.html`];
  const child = spawn(chrome, args, { stdio: ["ignore", "pipe", "ignore"] });
  const kill = () => { try { child.kill("SIGKILL"); } catch {} };
  process.once("exit", kill);
  try {
    let dom = "";
    child.stdout.on("data", (d) => { if (dom.length < 1 << 20) dom += d; });
    const timer = setTimeout(kill, DEADLINE_MS);
    await new Promise((ok) => child.once("close", ok));
    clearTimeout(timer);
    const m = /RESULT (\{.*\})<\/pre>/s.exec(dom);
    assert.ok(m, `no result from the page: ${dom.slice(0, 300)}`);
    const r = JSON.parse(m[1].replace(/&quot;/g, '"').replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&"));
    assert.equal(r.error, undefined, r.error);
    assert.deepEqual(r.bad, []);
    assert.ok(r.n > 80, `${r.n} cases`);
    assert.deepEqual(r.recovery, RECOVERY_KNOWN);
    assert.equal(r.rfcPublic, "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo");
    assert.equal(r.rfcSig, "5VZDAMNgrHKQhuLMgG6CioSHfx645dl02HPgZSJJAVVfuIIVkKM7rMYeOXAc-bRr0lv18FlbviRlUUFDjnoQCw");
    assert.equal(r.opened, 1);
    assert.deepEqual(r.hpke.vector.bad, []);
    assert.equal(r.hpke.vector.n, 257);
    assert.deepEqual(r.hpke.fleet.bad, []);
    assert.ok(r.hpke.fleet.n > 25, `${r.hpke.fleet.n} HPKE cases`);
    console.log(`# ${r.n} cases, HPKE ${r.hpke.vector.n} + ${r.hpke.fleet.n}, in ${r.ua}`);
  } finally {
    kill();
    process.removeListener("exit", kill);
    server.close();
    rmSync(profile, { recursive: true, force: true });
  }
});
