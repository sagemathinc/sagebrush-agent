// Fleet protocol, the browser lane: what the reviewed freeze pins (O11 draft 5.1, doc sha256 66755f3a; O6/O7 r2.3).
// test/fleet-browser.test.mjs checks each file against its hash and regenerates the program from the other two.
export const PINS = Object.freeze({
  o11Doc: "66755f3a1a97d060981c69daebcb5a8b3d95a6e47617a9d327f48515a32c519e",
  protocol: { file: "schema/fleet/browser/cft-158.0.8127.36-protocol.json", chrome: "158.0.8127.36", revision: 1727472, sha256: "abc8592fa073e87d8ace0ff81e1df0984583d713b422cad61e6f039e54b19c0c" },
  spec: { file: "schema/fleet/browser/o11-cdp.json", version: "o11-cdp-3.4", sha256: "f2c215b010c66128f720b31c3519f169ac15dec6ec540f988bbff26d96c265d0" },
  // The reviewed permission list per exact Chrome build (scripts/fleet-browser-permissions.mjs, O11 §9.1): build ->
  // sha256 of schema/fleet/browser/permissions-<build>.json. Only the pinned release build belongs here; it's empty
  // until §9.1 makes 158's list on 158, and until then every session fails hardening (closed).
  permissions: Object.freeze({}),
  program: { file: "schema/fleet/browser/o11-program.json", sha256: "dcb5627ebacdbe197dbe47d419e3c9778b4920656300d83f69b28ee3587687ee" },
});
