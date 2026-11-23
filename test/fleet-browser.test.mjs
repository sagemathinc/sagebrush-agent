// Fleet protocol, the browser lane (O11 draft 5, frozen at doc sha256 509eb04e): the pinned inputs, the resolver and
// its mutants, the program loader, the virtual handles, and the rewrite on synthetic CDP results and events shaped as
// the pinned protocol declares them. Real ids are planted as "REAL-…" strings and integers ≥ 900000; after a rewrite
// none may remain outside kept page content, which must come through untouched.
import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { FleetError } from "../lib/fleet/index.mjs";
import { resolve } from "../lib/fleet/browser/resolve.mjs";
import { rewrite, loadProgram } from "../lib/fleet/browser/rewrite.mjs";
import { Vids, VID, KINDS } from "../lib/fleet/browser/vids.mjs";
import { PINS } from "../lib/fleet/browser/pins.mjs";

const root = new URL("..", import.meta.url);
const bytes = (f) => readFileSync(new URL(f, root));
const hex = (b) => createHash("sha256").update(b).digest("hex");
const proto = JSON.parse(bytes(PINS.protocol.file)), spec = JSON.parse(bytes(PINS.spec.file));
const programBytes = bytes(PINS.program.file);
const program = loadProgram(programBytes, PINS.program.sha256);
const code = (fn) => { try { fn(); } catch (e) { if (e instanceof FleetError) return e.code; throw e; } return "ok"; };
const clone = (v) => JSON.parse(JSON.stringify(v));

// (every planted real id still present outside the kept subtrees `keep` (paths into `v`))
function leaks(v, keep = []) {
  const found = [];
  const visit = (x, path) => {
    if (keep.includes(path)) return;
    if (typeof x === "string" && x.startsWith("REAL-")) found.push(`${path}=${x}`);
    else if (typeof x === "number" && x >= 900000) found.push(`${path}=${x}`);
    else if (Array.isArray(x)) x.forEach((y, i) => visit(y, `${path}[${i}]`));
    else if (x && typeof x === "object") for (const [k, y] of Object.entries(x)) visit(y, path ? `${path}.${k}` : k);
  };
  visit(v, "");
  return found;
}

test("the pinned inputs and the program: every file has its pinned hash, and the program is exactly what the resolver makes", () => {
  assert.equal(hex(bytes(PINS.protocol.file)), PINS.protocol.sha256);
  assert.equal(hex(bytes(PINS.spec.file)), PINS.spec.sha256);
  assert.equal(hex(programBytes), PINS.program.sha256);
  assert.equal(proto.domains.length, 59);
  assert.equal(spec.version, PINS.spec.version);
  const { program: made, flat, problems } = resolve(proto, spec);
  assert.deepEqual(problems, []);
  assert.deepEqual(made.owners, program.owners);
  assert.deepEqual(made.types, program.types);
  const c = (a) => flat.filter((r) => r.action.startsWith(a)).length;
  // (the counts the freeze's reviewers reproduced: 318 locations)
  assert.deepEqual([flat.length, c("map"), c("drop"), c("keep"), c("recurse")], [318, 101, 65, 43, 109]);
  // (both of astra4's draft-4 findings are explicit drop rows)
  assert.ok(flat.some((r) => r.owner === "Runtime.executionContextDestroyed event" && r.path === "executionContextUniqueId" && r.action === "drop"));
  assert.ok(flat.some((r) => r.owner === "Runtime.executionContextCreated event" && r.path === "context.auxData" && r.action === "drop"));
});

test("the resolver fails closed: removing or weakening any one rule is a problem", () => {
  const mutants = {
    "no DOM.NodeId mapping": (s) => { delete s.rewrite.idTypes["DOM.NodeId"]; },
    "no ScriptId drop": (s) => { s.rewrite.dropIdTypes = s.rewrite.dropIdTypes.filter((q) => q !== "Runtime.ScriptId"); },
    "no history-id rule": (s) => { delete s.rewrite.untypedIds["Page.NavigationEntry.id"]; },
    "no top-level executionContextUniqueId rule": (s) => { delete s.rewrite.untypedIds["Runtime.executionContextDestroyed.executionContextUniqueId"]; },
    "no auxData rule": (s) => { delete s.rewrite.opaque["Runtime.ExecutionContextDescription.auxData"]; },
    "headers forwarded without a decision": (s) => { s.rewrite.opaque["Network.Headers"] = { action: "forward" }; },
    "DOM.focus nodeId as a backend node": (s) => { s.commands["DOM.focus"].params.nodeId = "vid:bn?"; },
    "an allowed command the protocol lacks": (s) => { s.commands["Page.noSuchMethod"] = { params: {}, result: { maxBytes: 64 } }; },
  };
  for (const [name, mutate] of Object.entries(mutants)) {
    const s = clone(spec);
    mutate(s);
    assert.ok(resolve(proto, s).problems.length > 0, name);
  }
});

test("the program loader refuses bytes that aren't the reviewed program", () => {
  const tampered = Buffer.from(programBytes.toString("utf8").replace('"map:nd"', '"map:bn"'));
  assert.equal(code(() => loadProgram(tampered, PINS.program.sha256)), "program_mismatch");
  assert.equal(code(() => loadProgram(programBytes, "0".repeat(64))), "program_mismatch");
});

test("virtual handles: their form, one per live real id, never reused, and refused when stale or of another kind", () => {
  const v = new Vids();
  const a = v.out("fr", "REAL-F1"), b = v.out("fr", "REAL-F1"), c = v.out("ld", "REAL-F1"), d = v.out("nd", 900001);
  assert.ok(VID.test(a) && a.startsWith("fr_") && c.startsWith("ld_") && d.startsWith("nd_"), [a, c, d].join());
  assert.equal(a, b);
  assert.notEqual(a, c);
  assert.equal(v.in("fr", a), "REAL-F1");
  assert.equal(v.in("nd", d), 900001);
  assert.equal(code(() => v.in("ld", a)), "stale_handle"); // (another kind)
  assert.equal(code(() => v.in("fr", "fr_0000000000000000")), "stale_handle");
  assert.equal(code(() => v.in("fr", "REAL-F1")), "stale_handle"); // (a real id is never accepted as a handle)
  assert.equal(v.revoke((k) => k === "fr"), 1);
  assert.equal(code(() => v.in("fr", a)), "stale_handle");
  const a2 = v.out("fr", "REAL-F1");
  assert.notEqual(a2, a); // (a revoked vid never maps to the real id again)
  assert.equal(v.in("ld", c), "REAL-F1");
  assert.equal(code(() => v.out("zz", "x")), "bad_kind");
  assert.equal(code(() => v.out("fr", { x: 1 })), "unmappable");
  assert.equal(code(() => v.out("nd", 2 ** 60)), "unmappable");
  const seen = new Set();
  for (let i = 0; i < 5000; i++) { const x = v.out("ob", `REAL-O${i}`); assert.ok(!seen.has(x)); seen.add(x); }
  v.revoke();
  assert.equal(v.size, 0);
  for (let i = 0; i < 100; i++) assert.ok(!seen.has(v.out("ob", `REAL-O${i}`)));
  assert.deepEqual(KINDS, ["pg", "fr", "ld", "cx", "nd", "bn", "ax", "ob", "rq", "he"]);
});

test("rewrite: a frame tree, three deep, with the same frame named as a parent", () => {
  const v = new Vids();
  const frame = (id, parent, n) => ({ id, ...(parent ? { parentId: parent } : {}), loaderId: `REAL-L${n}`, url: "https://example.test/", domainAndRegistry: "example.test", securityOrigin: "https://example.test", mimeType: "text/html", secureContextType: "Secure", crossOriginIsolatedContextType: "Isolated", gatedAPIFeatures: [] });
  const r = { frameTree: { frame: frame("REAL-F1", null, 1), childFrames: [{ frame: frame("REAL-F2", "REAL-F1", 2), childFrames: [{ frame: frame("REAL-F3", "REAL-F2", 3) }] }] } };
  rewrite(program, "Page.getFrameTree result", r, v);
  assert.deepEqual(leaks(r), []);
  const f1 = r.frameTree.frame.id, f2 = r.frameTree.childFrames[0].frame;
  assert.equal(f2.parentId, f1);
  assert.equal(r.frameTree.childFrames[0].childFrames[0].frame.parentId, f2.id);
  assert.ok(f2.loaderId.startsWith("ld_"));
});

test("rewrite: a DOM tree with children, shadow roots, a content document, distributed nodes and a slot", () => {
  const v = new Vids();
  let n = 900001;
  const node = (extra = {}) => ({ nodeId: n++, backendNodeId: n++, nodeType: 1, nodeName: "DIV", localName: "div", nodeValue: "", ...extra });
  const doc = { root: node({ children: [node({ frameId: "REAL-F1", contentDocument: node({ children: [node()] }), shadowRoots: [node({ children: [node({ assignedSlot: { nodeType: 1, nodeName: "SLOT", backendNodeId: 950001 } })] })], distributedNodes: [{ nodeType: 1, nodeName: "P", backendNodeId: 950002 }], pseudoElements: [node()] })] }) };
  rewrite(program, "DOM.getDocument result", doc, v);
  assert.deepEqual(leaks(doc), []);
  assert.ok(doc.root.nodeId.startsWith("nd_") && doc.root.backendNodeId.startsWith("bn_"));
  assert.ok(doc.root.children[0].contentDocument.children[0].nodeId.startsWith("nd_"));
  assert.ok(doc.root.children[0].shadowRoots[0].children[0].assignedSlot.backendNodeId.startsWith("bn_"));
});

test("rewrite: Runtime results keep page values untouched and drop script, exception and deep-serialization ids", () => {
  const v = new Vids();
  const pageValue = { objectId: "REAL-CONTENT-not-a-handle", nodeId: 900500, nested: ["REAL-CONTENT"] };
  const stack = { callFrames: [{ functionName: "f", scriptId: "REAL-S1", url: "", lineNumber: 1, columnNumber: 2 }], parent: { callFrames: [{ functionName: "g", scriptId: "REAL-S2", url: "", lineNumber: 3, columnNumber: 4 }], parentId: { id: "REAL-STACK", debuggerId: "REAL-DBG" } } };
  const r = {
    result: { type: "object", objectId: "REAL-O1", value: pageValue, deepSerializedValue: { type: "object", value: { x: 1 }, objectId: "REAL-O2" }, preview: { type: "object", overflow: false, properties: [] } },
    exceptionDetails: { exceptionId: 900600, text: "x", lineNumber: 0, columnNumber: 0, scriptId: "REAL-S3", stackTrace: stack, exception: { type: "object", objectId: "REAL-O3" }, executionContextId: 900700, exceptionMetaData: { anything: "REAL-META" } },
  };
  rewrite(program, "Runtime.evaluate result", r, v);
  assert.deepEqual(leaks(r, ["result.value"]), []);
  assert.deepEqual(r.result.value, pageValue); // (page content: forwarded as is, never scanned)
  assert.ok(r.result.objectId.startsWith("ob_") && r.exceptionDetails.exception.objectId.startsWith("ob_") && r.exceptionDetails.executionContextId.startsWith("cx_"));
  assert.equal(r.result.deepSerializedValue.objectId, undefined);
  assert.equal(r.exceptionDetails.exceptionMetaData, undefined);
  assert.equal(r.exceptionDetails.stackTrace.parent.callFrames[0].scriptId, undefined); // (recursion: a stack's parent)
});

test("rewrite: execution contexts lose their embedder data and unique ids", () => {
  const v = new Vids();
  const created = { context: { id: 900001, origin: "https://example.test", name: "", uniqueId: "REAL-U1", auxData: { frameId: "REAL-F1", isDefault: true, type: "default" } } };
  rewrite(program, "Runtime.executionContextCreated event", created, v);
  assert.deepEqual(leaks(created), []);
  assert.deepEqual(Object.keys(created.context).sort(), ["id", "name", "origin"]);
  const destroyed = { executionContextId: 900001, executionContextUniqueId: "REAL-U1" };
  rewrite(program, "Runtime.executionContextDestroyed event", destroyed, v);
  assert.deepEqual(destroyed, { executionContextId: created.context.id });
});

test("rewrite: accessibility trees, network events and navigation history", () => {
  const v = new Vids();
  const ax = { nodes: [{ nodeId: "REAL-AX1", ignored: false, childIds: ["REAL-AX2"], backendDOMNodeId: 900001, frameId: "REAL-F1", name: { type: "computedString", value: "REAL-CONTENT name", relatedNodes: [{ backendDOMNodeId: 900002 }] } }, { nodeId: "REAL-AX2", parentId: "REAL-AX1", ignored: true }] };
  rewrite(program, "Accessibility.getFullAXTree result", ax, v);
  assert.deepEqual(leaks(ax, ["nodes[0].name.value"]), []);
  assert.equal(ax.nodes[0].childIds[0], ax.nodes[1].nodeId);
  assert.equal(ax.nodes[1].parentId, ax.nodes[0].nodeId);
  assert.equal(ax.nodes[0].name.value, "REAL-CONTENT name");
  const ev = { requestId: "REAL-R1", loaderId: "REAL-L1", documentURL: "https://example.test/", frameId: "REAL-F1", type: "Document", timestamp: 1, wallTime: 1, request: { url: "https://example.test/", method: "GET", headers: { Accept: "*/*" }, initialPriority: "High", referrerPolicy: "no-referrer" }, initiator: { type: "script", requestId: "REAL-R0", stack: { callFrames: [{ functionName: "", scriptId: "REAL-S1", url: "", lineNumber: 0, columnNumber: 0 }] } }, redirectHasExtraInfo: false };
  rewrite(program, "Network.requestWillBeSent event", ev, v);
  assert.deepEqual(leaks(ev), []);
  assert.ok(ev.requestId.startsWith("rq_") && ev.initiator.requestId.startsWith("rq_") && ev.frameId.startsWith("fr_"));
  assert.equal(ev.frameId, v.out("fr", "REAL-F1")); // (the same frame, seen in two results, is one handle)
  const hist = { currentIndex: 0, entries: [{ id: 900001, url: "https://example.test/", userTypedURL: "", title: "t", transitionType: "link" }] };
  rewrite(program, "Page.getNavigationHistory result", hist, v);
  assert.ok(hist.entries[0].id.startsWith("he_"));
  assert.equal(v.in("he", hist.entries[0].id), 900001);
});

test("rewrite fails closed: an unexpected shape or an unknown owner is refused, never forwarded", () => {
  const v = new Vids();
  assert.equal(code(() => rewrite(program, "DOM.getDocument result", { root: { nodeId: 1, backendNodeId: 2, children: "not an array" } }, v)), "unmappable");
  assert.equal(code(() => rewrite(program, "DOM.getDocument result", { root: { nodeId: { x: 1 }, backendNodeId: 2 } }, v)), "unmappable");
  assert.equal(code(() => rewrite(program, "Page.navigate result", { frameId: ["REAL-F1"] }, v)), "unmappable");
  assert.equal(code(() => rewrite(program, "Browser.getVersion result", {}, v)), "unknown_owner");
  assert.equal(code(() => rewrite(program, "Page.navigate result", null, v)), "unmappable");
});

test("the engine itself, on a small hand-written program: arrays, drops of whole arrays, nested types and recursion", () => {
  const prog = { owners: { "T.m result": [{ path: "ids[]", action: "map:nd" }, { path: "gone[]", action: "drop" }, { path: "x.y", action: "drop" }, { path: "tree", action: "type:T.Tree" }] },
    types: { "T.Tree": [{ path: "id", action: "map:fr" }, { path: "kids[]", action: "type:T.Tree" }] } };
  const v = new Vids();
  const r = { ids: [900001, 900002], gone: ["REAL-A", "REAL-B"], x: { y: "REAL-Y", z: 1 }, tree: { id: "REAL-T1", kids: [{ id: "REAL-T2", kids: [{ id: "REAL-T3", kids: [] }] }] }, other: "kept" };
  rewrite(prog, "T.m result", r, v);
  assert.deepEqual(leaks(r), []);
  assert.equal(r.gone, undefined); // (a dropped array is removed whole)
  assert.deepEqual(r.x, { z: 1 });
  assert.ok(r.ids.every((x) => x.startsWith("nd_")));
  assert.ok(r.tree.kids[0].kids[0].id.startsWith("fr_"));
  assert.equal(r.other, "kept");
});

test("virtual handles stay unique even when the random source repeats itself", () => {
  let calls = 0;
  const same = new Uint8Array(24).fill(7), other = new Uint8Array(24).fill(11);
  const v = new Vids((n) => (calls++ < 2 ? same : other).slice(0, n)); // (the first two draws are identical)
  const a = v.out("fr", "REAL-F1"), b = v.out("fr", "REAL-F2");
  assert.notEqual(a, b);
  assert.equal(v.in("fr", a), "REAL-F1");
  assert.equal(v.in("fr", b), "REAL-F2");
});
