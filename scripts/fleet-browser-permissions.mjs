// Make the browser lane's permission list for one exact Chrome build (O11 draft 5.1 §2, §9.1): every W3C permission
// descriptor that build accepts for Browser.setPermission, from a closed mapping of the pinned protocol's
// Browser.PermissionType values. It drives the given Chrome over its debugging pipe and writes
// schema/fleet/browser/permissions-<build>.json. A PermissionType value missing from the mapping fails the run, so a new
// type can't go unlisted.
//   node scripts/fleet-browser-permissions.mjs <chrome binary> [--check]       (CHROME_FLAGS adds launch flags)
// --check compares with the checked-in file instead of writing it (§9.1: regenerate on the pinned build and compare).

import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PINS } from "../lib/fleet/browser/pins.mjs";

// PermissionType -> the descriptors that cover it (several for "sensors"; options as Chrome requires them).
export const DESCRIPTORS = Object.freeze({
  ar: [{ name: "ar" }], audioCapture: [{ name: "microphone" }], automaticFullscreen: [{ name: "fullscreen", allowWithoutGesture: true }],
  backgroundFetch: [{ name: "background-fetch" }], backgroundSync: [{ name: "background-sync" }], cameraPanTiltZoom: [{ name: "camera", panTiltZoom: true }],
  capturedSurfaceControl: [{ name: "captured-surface-control" }], clipboardReadWrite: [{ name: "clipboard-read" }], clipboardSanitizedWrite: [{ name: "clipboard-write" }],
  displayCapture: [{ name: "display-capture" }], durableStorage: [{ name: "persistent-storage" }], geolocation: [{ name: "geolocation" }],
  handTracking: [{ name: "hand-tracking" }], idleDetection: [{ name: "idle-detection" }], keyboardLock: [{ name: "keyboard-lock" }],
  localFonts: [{ name: "local-fonts" }], localNetwork: [{ name: "local-network" }], localNetworkAccess: [{ name: "local-network-access" }],
  loopbackNetwork: [{ name: "loopback-network" }], midi: [{ name: "midi" }], midiSysex: [{ name: "midi", sysex: true }], nfc: [{ name: "nfc" }],
  notifications: [{ name: "notifications" }], paymentHandler: [{ name: "payment-handler" }], periodicBackgroundSync: [{ name: "periodic-background-sync" }],
  pointerLock: [{ name: "pointer-lock" }], protectedMediaIdentifier: [{ name: "protected-media-identifier" }],
  sensors: [{ name: "accelerometer" }, { name: "gyroscope" }, { name: "magnetometer" }, { name: "ambient-light-sensor" }],
  smartCard: [{ name: "smart-card" }], speakerSelection: [{ name: "speaker-selection" }], storageAccess: [{ name: "storage-access" }],
  topLevelStorageAccess: [{ name: "top-level-storage-access" }], videoCapture: [{ name: "camera" }], vr: [{ name: "vr" }],
  wakeLockScreen: [{ name: "screen-wake-lock" }], wakeLockSystem: [{ name: "system-wake-lock" }], webAppInstallation: [{ name: "web-app-installation" }],
  webPrinting: [{ name: "web-printing" }], windowManagement: [{ name: "window-management" }],
});

const key = (d) => JSON.stringify(Object.fromEntries(Object.entries(d).sort()));

if (import.meta.url === `file://${process.argv[1]}`) {
  const [binary, flag] = process.argv.slice(2);
  if (!binary) { console.error("usage: node scripts/fleet-browser-permissions.mjs <chrome binary> [--check]"); process.exit(2); }
  const root = new URL("..", import.meta.url);
  const proto = JSON.parse(readFileSync(new URL(PINS.protocol.file, root)));
  const types = proto.domains.find((d) => d.domain === "Browser").types.find((t) => t.id === "PermissionType").enum;
  const missing = types.filter((t) => !Object.hasOwn(DESCRIPTORS, t));
  const extra = Object.keys(DESCRIPTORS).filter((t) => !types.includes(t));
  if (missing.length || extra.length) { console.error(`the mapping doesn't match the pinned PermissionType: missing ${missing}, extra ${extra}`); process.exit(1); }

  const profile = mkdtempSync(join(tmpdir(), "fleet-permissions-"));
  const extraFlags = (process.env.CHROME_FLAGS ?? "").split(/\s+/).filter(Boolean); // (e.g. --no-sandbox in a container)
  const chrome = spawn(binary, ["--headless", "--remote-debugging-pipe", `--user-data-dir=${profile}`, "--no-first-run", ...extraFlags, "about:blank"], { stdio: ["ignore", "ignore", "ignore", "pipe", "pipe"] });
  chrome.stdio[4].on("error", () => { console.error("the browser closed its pipe"); process.exit(1); });
  process.on("exit", () => { chrome.kill("SIGKILL"); rmSync(profile, { recursive: true, force: true }); });
  const out = chrome.stdio[3], inp = chrome.stdio[4];
  let id = 0, buf = Buffer.alloc(0);
  const pending = new Map();
  inp.on("data", (b) => {
    buf = Buffer.concat([buf, b]);
    for (let i; (i = buf.indexOf(0)) >= 0; buf = buf.subarray(i + 1)) { const m = JSON.parse(buf.subarray(0, i).toString("utf8")); if (pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); } }
  });
  const send = (method, params = {}) => new Promise((r) => { const i = ++id; pending.set(i, r); out.write(JSON.stringify({ id: i, method, params }) + "\0"); });
  const build = /\/(\d+\.\d+\.\d+\.\d+)$/.exec((await send("Browser.getVersion")).result.product)[1];
  const { result: { browserContextId } } = await send("Target.createBrowserContext", {});
  const accepted = [], refused = [], seen = new Set();
  for (const t of types) for (const d of DESCRIPTORS[t]) {
    if (seen.has(key(d))) continue;
    seen.add(key(d));
    const r = await send("Browser.setPermission", { permission: d, setting: "denied", browserContextId });
    (r.error ? refused : accepted).push(d);
  }
  const doc = { $comment: `GENERATED by scripts/fleet-browser-permissions.mjs on Chrome ${build}: the W3C permission descriptors this build accepts for Browser.setPermission, each denied at hardening (O11 draft 5.1 §2). "refused": the descriptors for pinned PermissionType values this build doesn't accept.`, build, descriptors: accepted, refused };
  const text = JSON.stringify(doc, null, 1) + "\n";
  const file = new URL(`schema/fleet/browser/permissions-${build}.json`, root);
  if (flag === "--check") {
    let have = null;
    try { have = readFileSync(file, "utf8"); } catch {}
    console.log(have === text ? `permissions-${build}.json matches` : `permissions-${build}.json DIFFERS (or is missing)`);
    process.exit(have === text ? 0 : 1);
  }
  writeFileSync(file, text);
  console.log(`wrote permissions-${build}.json: ${accepted.length} accepted, ${refused.length} refused (${refused.map((d) => d.name).join(", ")})`);
  process.exit(0);
}
