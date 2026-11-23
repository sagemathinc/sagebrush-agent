// Fleet protocol, the browser lane: what the reviewed freeze pins (O11 draft 5, doc sha256 509eb04e; O6/O7 r2.3).
// test/fleet-browser.test.mjs checks each file against its hash and regenerates the program from the other two.
export const PINS = Object.freeze({
  o11Doc: "509eb04e816deab2fc284923cc242d5560c31e4b566862d235067e90e3580d34",
  protocol: { file: "schema/fleet/browser/cft-158.0.8127.36-protocol.json", chrome: "158.0.8127.36", revision: 1727472, sha256: "abc8592fa073e87d8ace0ff81e1df0984583d713b422cad61e6f039e54b19c0c" },
  spec: { file: "schema/fleet/browser/o11-cdp.json", version: "o11-cdp-3.3", sha256: "09309230a615bb78691a6b4c7d8d298c38c8b90faa214649603b9fb5ae48bb7e" },
  program: { file: "schema/fleet/browser/o11-program.json", sha256: "9c96f1329a4633783f74b14a04b06ea7bb07400a55d5475b9014b88b7f2e375c" },
});
