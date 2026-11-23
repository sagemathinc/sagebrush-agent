// #1791 step 1: an image file read from the workspace reaches Claude as the picture, checked here first from its bytes
// alone (type by magic numbers, size from the header, caps on bytes, sides and area, canonical base64), and refused
// with a fixed reason otherwise; the bytes are never in an error, a log or the tool's card. A fake page; no Anthropic.
import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import WebSocket from "ws";
import { z } from "zod";
import { claudeBinary, cliCreateServer, cliQuery } from "../lib/claude-cli.mjs";
import { Turn } from "../lib/turns.mjs";
import { fakeAnthropic } from "./fake-anthropic.mjs";
import { fakeCreateServer, fakeQuery } from "../lib/fake.mjs";
import { IMAGE_AREA_MAX, IMAGE_BYTES_MAX, IMAGE_REASONS, IMAGE_REJECTED_TEXT, checkImage, imageHeader, imageRejected } from "../lib/image.mjs";
import { AgentServer, FEATURES } from "../lib/server.mjs";

const u32be = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
const u16be = (n) => { const b = Buffer.alloc(2); b.writeUInt16BE(n); return b; };
const u16le = (n) => { const b = Buffer.alloc(2); b.writeUInt16LE(n); return b; };
const u32le = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n); return b; };
const u24le = (n) => Buffer.from([n & 255, (n >> 8) & 255, (n >> 16) & 255]);

export const png = (w, h, { len = 13, type = "IHDR" } = {}) => Buffer.concat([
  Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), u32be(len), Buffer.from(type), u32be(w), u32be(h), Buffer.from([8, 2, 0, 0, 0]), u32be(0),
]);
const gif = (w, h, v = "GIF89a") => Buffer.concat([Buffer.from(v), u16le(w), u16le(h), Buffer.from([0, 0, 0]), Buffer.from(";")]);
const jpeg = (w, h, { sof = 0xc0, before = [] } = {}) => Buffer.concat([
  Buffer.from([0xff, 0xd8]),
  ...before,
  Buffer.from([0xff, 0xe0]), u16be(16), Buffer.from("JFIF\0"), Buffer.alloc(9),
  Buffer.from([0xff, sof]), u16be(17), Buffer.from([8]), u16be(h), u16be(w), Buffer.from([3]), Buffer.alloc(9),
  Buffer.from([0xff, 0xd9]),
]);
const riff = (chunk, data) => { const body = Buffer.concat([Buffer.from("WEBP"), Buffer.from(chunk), u32le(data.length), data]); return Buffer.concat([Buffer.from("RIFF"), u32le(body.length), body]); };
const vp8 = (w, h) => riff("VP8 ", Buffer.concat([Buffer.from([0, 0, 0, 0x9d, 0x01, 0x2a]), u16le(w), u16le(h)]));
const vp8l = (w, h) => { const v = ((w - 1) & 0x3fff) | (((h - 1) & 0x3fff) << 14); return riff("VP8L", Buffer.concat([Buffer.from([0x2f]), u32le(v >>> 0)])); };
const vp8x = (w, h) => riff("VP8X", Buffer.concat([Buffer.alloc(4), u24le(w - 1), u24le(h - 1)]));
const b64 = (b) => ({ base64: b.toString("base64") });

test("image: the four types, from their bytes alone, with their pixel size from the header", () => {
  for (const [b, mimeType, width, height] of [
    [png(640, 480), "image/png", 640, 480],
    [gif(10, 20), "image/gif", 10, 20],
    [gif(3, 4, "GIF87a"), "image/gif", 3, 4],
    [jpeg(1024, 768), "image/jpeg", 1024, 768],
    [jpeg(5, 6, { sof: 0xc2 }), "image/jpeg", 5, 6], // (progressive)
    [jpeg(7, 8, { before: [Buffer.from([0xff, 0xff, 0xff])] }), "image/jpeg", 7, 8], // (fill bytes before a marker)
    [vp8(300, 200), "image/webp", 300, 200],
    [vp8l(16, 9), "image/webp", 16, 9],
    [vp8x(4000, 3000), "image/webp", 4000, 3000],
  ]) {
    const r = checkImage(b64(b));
    assert.deepEqual(r, { ok: true, data: b.toString("base64"), mimeType, width, height }, mimeType);
  }
});

test("image: refused with a fixed reason: not one of the four (SVG too), a cut or wrong header, a size out of bounds", () => {
  const reason = (b) => checkImage(b64(b)).reason;
  assert.equal(reason(Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"/>')), "type");
  assert.equal(reason(Buffer.from("%PDF-1.7")), "type");
  assert.equal(reason(Buffer.from("BM\0\0")), "type");
  assert.equal(reason(png(1, 1).subarray(0, 20)), "truncated");
  assert.equal(reason(png(1, 1, { len: 14 })), "header");
  assert.equal(reason(png(1, 1, { type: "IDAT" })), "header");
  assert.equal(reason(gif(1, 1).subarray(0, 8)), "truncated");
  assert.equal(reason(Buffer.from("GIF90a\x01\0\x01\0")), "type");
  assert.equal(reason(jpeg(1, 1).subarray(0, 26)), "truncated"); // (cut inside the frame header)
  assert.equal(reason(jpeg(1, 1).subarray(0, 31)), "truncated"); // (cut after the dimensions, inside the frame header's declared length)
  assert.equal(reason(Buffer.from([0xff, 0xd8, 0xff, 0xc0, 0, 17, 8, 0, 1, 0, 1])), "truncated"); // (a frame header declaring 17 bytes, 9 there)
  assert.equal(reason(Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xc0]), u16be(200), Buffer.from([8, 0, 1, 0, 1, 3]), Buffer.alloc(20)])), "truncated"); // (its length past the end)
  assert.equal(reason(Buffer.from([0xff, 0xd8, 0xff, 0xda, 0, 8])), "header"); // (a scan before any frame header)
  assert.equal(reason(Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0, 1])), "header"); // (a length under 2)
  assert.equal(reason(Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0xff, 0xff, 0, 0])), "truncated"); // (a length past the end)
  assert.equal(reason(Buffer.concat([Buffer.from([0xff, 0xd8]), ...Array(5000).fill(Buffer.from([0xff, 0xe1, 0, 2]))])), "header"); // (too many markers)
  assert.equal(reason(Buffer.concat([vp8(10, 10).subarray(0, 4), u32le(9999), vp8(10, 10).subarray(8)])), "header"); // (RIFF longer than the file)
  assert.equal(reason(riff("VP8 ", Buffer.from([0, 0, 0, 0x9d, 0x01, 0x2b, 1, 0, 1, 0]))), "header");
  assert.equal(reason(riff("ALPH", Buffer.alloc(10))), "header");
  assert.equal(reason(Buffer.from("RIFF\x04\0\0\0WEBP")), "truncated");
  for (const b of [png(0, 10), png(10, 0), gif(0, 5), jpeg(0, 9), vp8(0, 3), png(8001, 10), png(10, 8001), png(2 ** 31, 1), vp8x(8001, 1)]) assert.equal(reason(b), "size");
  // (each side within 8000, the area not: 6000 x 5000 is 30 million pixels)
  assert.ok(6000 * 5000 > IMAGE_AREA_MAX);
  assert.equal(reason(png(6000, 5000)), "size");
  assert.equal(checkImage(b64(png(5000, 5000))).ok, true);
  for (const r of ["type", "truncated", "header", "size"]) assert.ok(IMAGE_REASONS.includes(r));
});

test("image: only { base64 }, canonical and padded, its bytes within 3.75 MB before anything is parsed", () => {
  const ok = Buffer.concat([png(2, 2), Buffer.from([0])]).toString("base64"); // (34 bytes: padded with "==")
  assert.ok(ok.endsWith("=="));
  assert.equal(checkImage({ base64: ok }).ok, true);
  for (const bad of [null, "x", [ok], {}, { base64: 7 }, { base64: ok, mimeType: "image/png" }, { base64: ok, width: 2 }, { data: ok }, { base64: ok, encoding: "base64" }]) {
    assert.equal(checkImage(bad).reason, "shape", JSON.stringify(bad)?.slice(0, 60));
  }
  for (const bad of ["", ok.replace(/=+$/, ""), ok.slice(0, 10) + "\n" + ok.slice(10), ok.replace(/\+/g, "-") + "-", "QQ=A", "QR=="]) {
    assert.equal(checkImage({ base64: bad }).reason, "base64", JSON.stringify(bad).slice(0, 40));
  }
  // ("QR==" decodes as "A" but re-encodes as "QQ==": not canonical)
  const big = Buffer.concat([png(10, 10), Buffer.alloc(IMAGE_BYTES_MAX - png(10, 10).length + 1)]);
  assert.equal(checkImage(b64(big)).reason, "too_large");
  assert.equal(checkImage(b64(big.subarray(0, IMAGE_BYTES_MAX))).ok, true);
  assert.equal(checkImage({ base64: "A".repeat(6_000_000) }).reason, "too_large"); // (refused by its length, before decoding)
  // (the cap is exactly 5,000,000 base64 characters)
  assert.equal(IMAGE_BYTES_MAX, 3_750_000);
  assert.equal(b64(big.subarray(0, IMAGE_BYTES_MAX)).base64.length, 5_000_000);
  assert.equal(imageHeader(Buffer.alloc(0)).reason, "type");
});

// A fake page whose workspace.read gives `reply` for every path.
async function paired(reply) {
  const server = new AgentServer({ query: fakeQuery, log: (...a) => logged.push(a.join(" ")) });
  const logged = [];
  server.createServer = fakeCreateServer;
  const port = await server.listen();
  const code = server.newCode();
  const ws = new WebSocket(`ws://127.0.0.1:${port}/sagebrush`, { origin: "https://agents.sagebrush.cloud" });
  let hello;
  ws.on("message", (d) => {
    const m = JSON.parse(d.toString());
    if (m.id === "p1") return hello?.(m);
    if (typeof m.id !== "string" || !m.method) return;
    if (m.method === "workspace.read") return ws.send(JSON.stringify({ jsonrpc: "2.0", id: m.id, result: reply(m.params.path) }));
    ws.send(JSON.stringify({ jsonrpc: "2.0", id: m.id, result: {} }));
  });
  await new Promise((r, j) => { ws.on("open", r); ws.on("error", j); });
  const h = await new Promise((resolve) => { hello = resolve; ws.send(JSON.stringify({ jsonrpc: "2.0", id: "p1", method: "hello", params: { protocol: 1, code, page: { origin: "https://agents.sagebrush.cloud", path: "/agents/" } } })); });
  ws.send(JSON.stringify({ jsonrpc: "2.0", method: "grant.changed", params: { folders: ["/"], write: false, expires: null } }));
  const t0 = Date.now();
  while (!server.binding?.grant) { if (Date.now() - t0 > 5000) throw new Error("timed out"); await new Promise((r) => setTimeout(r, 20)); }
  const tools = server.workspaceTools("c1", {}, server.binding, undefined);
  return { server, hello: h, logged, read: (path) => tools.handlers.workspace_read({ path }), close: async () => { ws.close(); await server.close(); } };
}

test("workspace_read of an image: the picture, then one line of what it is; refused with a reason, its bytes nowhere else", async () => {
  const pic = png(320, 200);
  const corrupt = Buffer.concat([png(1, 1).subarray(0, 12), Buffer.from("IDAT"), Buffer.alloc(13)]);
  const files = {
    "/plots/a.png": { entry: { path: "/plots/a.png" }, rev: 3, image: b64(pic) },
    "/x.jpg": { entry: { path: "/x.jpg" }, rev: 1, image: b64(corrupt) },
    "/typed.png": { entry: { path: "/typed.png" }, rev: 1, image: { ...b64(pic), mimeType: "image/png" } },
    "/both.png": { entry: { path: "/both.png" }, rev: 1, image: b64(pic), content: "x" },
    "/norev.png": { entry: { path: "/norev.png" }, image: b64(pic) },
    "/notes.md": { entry: { path: "/notes.md" }, rev: 2, content: "# hi" },
  };
  const p = await paired((path) => files[path]);
  try {
    assert.ok(p.hello.result.features.includes("workspace.image"));
    assert.ok(FEATURES.includes("workspace.image"));
    const r = await p.read("/plots/a.png");
    assert.equal(r.isError, undefined);
    assert.deepEqual(r.content, [
      { type: "image", data: pic.toString("base64"), mimeType: "image/png" },
      { type: "text", text: "/plots/a.png: PNG image, 320x200 pixels, rev 3" },
    ]);
    for (const [path, reason] of [["/x.jpg", "header"], ["/typed.png", "shape"], ["/both.png", "shape"], ["/norev.png", "shape"]]) {
      const e = await p.read(path);
      assert.deepEqual(e, { content: [{ type: "text", text: `refused: not a readable image (${reason})` }], isError: true }, path);
    }
    // (a file that isn't an image: as before)
    assert.deepEqual(await p.read("/notes.md"), { content: [{ type: "text", text: JSON.stringify(files["/notes.md"]) }] });
    // (the bytes never in this agent's log)
    const all = p.logged.join("\n");
    for (const f of Object.values(files)) if (f.image?.base64) assert.ok(!all.includes(f.image.base64.slice(0, 24)));
  } finally {
    await p.close();
  }
});

// (with the pinned Claude Code itself, against a fake Messages API: our tool's image block reaches the model as an image,
//  and the turn's events, the tool card's body included, carry its type and size, never its bytes)
test("cli: the pinned Claude Code gives our tool's image to the model as an image; the turn's events never carry its bytes", { skip: !claudeBinary() || process.platform === "win32" ? "no pinned Claude Code binary here" : false, timeout: 90_000 }, async () => {
  const pic = Buffer.concat([png(64, 48), Buffer.alloc(200, 7)]);
  const data = pic.toString("base64");
  const seen = [];
  const api = await fakeAnthropic((body) => {
    const last = body.messages.at(-1);
    const result = Array.isArray(last?.content) ? last.content.find((c) => c.type === "tool_result") : null;
    if (result) { seen.push(result.content); return [{ type: "text", text: "a picture" }]; }
    return (body.tools ?? []).some((t) => t.name === "mcp__sagebrush__view") ? [{ type: "tool_use", name: "mcp__sagebrush__view", input: { path: "/a.png" } }] : [{ type: "text", text: "ok" }];
  });
  const home = mkdtempSync(join(tmpdir(), "sb-img-home-"));
  const env = { PATH: process.env.PATH, HOME: home, CLAUDE_CONFIG_DIR: join(home, ".claude"), ANTHROPIC_API_KEY: "test-key-not-a-credential", ANTHROPIC_BASE_URL: api.url, DISABLE_AUTOUPDATER: "1", CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1" };
  const server = cliCreateServer({ name: "sagebrush", version: "1", tools: [["view", "View an image", { path: z.string() }, async () => ({ content: [{ type: "image", data, mimeType: "image/png" }, { type: "text", text: "/a.png: PNG image, 64x48 pixels, rev 1" }] })]] });
  const q = cliQuery({ prompt: "look", options: { includePartialMessages: true, settingSources: [], strictMcpConfig: true, tools: [], permissionMode: "default", persistSession: false, cwd: home, mcpServers: { sagebrush: server }, canUseTool: async (_n, input) => ({ behavior: "allow", updatedInput: input }) } }, { env, bin: claudeBinary() });
  const msgs = [];
  for await (const m of q) msgs.push(m);
  await api.close();
  assert.equal(seen.length, 1);
  const blocks = Array.isArray(seen[0]) ? seen[0] : [];
  const img = blocks.find((b) => b.type === "image");
  assert.ok(img, `an image block reached the model: ${JSON.stringify(blocks.map((b) => b.type))}`);
  assert.equal(img.source?.type, "base64");
  assert.match(img.source?.media_type ?? "", /^image\/(png|jpeg|webp)$/);
  assert.ok(blocks.some((b) => b.type === "text" && /64x48 pixels/.test(b.text)));
  const turn = new Turn("t");
  const events = [turn.start?.() ?? [], ...msgs.map((m) => turn.feed(m))].flat();
  const flat = JSON.stringify(events);
  assert.ok(!flat.includes(data.slice(0, 40)), "the image's bytes are in no event");
  const card = events.find((e) => e.type === "tool_call_finished");
  assert.ok(card && /64x48 pixels/.test(card.body ?? ""), JSON.stringify(card));
});

// (SEC 5: a header-valid image can still be refused by the API. The pinned Claude Code then ends the turn with one of
//  its own texts, read from a run against a stand-in API answering 400; the turn ends with one closed reason in our
//  words, and the conversation goes on: Claude Code removed the image itself)
test("image: an image the API refused ends the turn with image_unreadable, in our words; any other error is as before", () => {
  for (const said of [
    "API Error: an image in the conversation could not be processed and was removed. Re-read the file with a different approach if you still need it.",
    "Image was too large. Try resizing the image or using a different approach.",
  ]) {
    const t = new Turn("i"); t.start();
    const ev = [
      ...t.feed({ type: "assistant", error: "invalid_request", message: { content: [{ type: "text", text: said }] } }),
      ...t.feed({ type: "result", subtype: "success", is_error: true, result: said }),
    ];
    assert.deepEqual(ev.filter((e) => e.type === "turn_error"), [{ type: "turn_error", code: "image_unreadable", message: IMAGE_REJECTED_TEXT }]);
    // (the frame alone says nothing: Claude Code may go on without the image)
    const f = new Turn("f"); f.start();
    assert.deepEqual(f.feed({ type: "assistant", error: "invalid_request", message: { content: [{ type: "text", text: said }] } }).filter((e) => e.type === "turn_error"), []);
    assert.equal(ev.find((e) => e.type === "turn_finished").code, "image_unreadable");
    assert.ok(!JSON.stringify(ev).includes(said));
  }
  assert.equal(imageRejected("Image was too large for the frame."), null);
  assert.equal(imageRejected("Could not process the image cache"), null);
  const t = new Turn("j"); t.start();
  const ev = t.feed({ type: "result", subtype: "success", is_error: true, result: "The tool could not process images." });
  assert.ok(ev.some((e) => e.type === "text_delta" && e.text === "The tool could not process images."));
  assert.equal(ev.find((e) => e.type === "turn_finished").code, "is_error");
});

// (SEC 5, with the pinned Claude Code: the API refuses the image (400). Claude Code removes it and asks again by itself,
//  so the model is answered without it and the turn ends normally; the next message in the conversation works, and the
//  refused image is never sent again. Only if Claude Code gives up does the turn end, with image_unreadable (above))
test("cli: after the API refuses an image, Claude Code drops it and the turn goes on; the conversation's next message works without it", { skip: !claudeBinary() || process.platform === "win32" ? "no pinned Claude Code binary here" : false, timeout: 120_000 }, async () => {
  const pic = png(8, 8);
  const bodies = [];
  const { createServer } = await import("node:http");
  const srv = createServer((req, res) => {
    let s = ""; req.on("data", (d) => (s += d)); req.on("end", () => {
      if (!/\/v1\/messages(\?|$)/.test(req.url)) { res.writeHead(200, { "content-type": "application/json" }); return res.end(req.url.includes("count_tokens") ? '{"input_tokens":10}' : "{}"); }
      const body = JSON.parse(s); bodies.push(body);
      const text = JSON.stringify(body.messages);
      if (text.includes('"type":"image"')) { res.writeHead(400, { "content-type": "application/json" }); return res.end(JSON.stringify({ type: "error", error: { type: "invalid_request_error", message: "Could not process image" } })); }
      const second = text.includes("again please");
      const answered = text.includes('"type":"tool_result"');
      res.writeHead(200, { "content-type": "text/event-stream" });
      const ev = (type, data) => res.write(`event: ${type}\ndata: ${JSON.stringify({ type, ...data })}\n\n`);
      ev("message_start", { message: { id: `m${bodies.length}`, type: "message", role: "assistant", model: body.model, content: [], stop_reason: null, stop_sequence: null, usage: { input_tokens: 1, output_tokens: 1 } } });
      if (second || answered) {
        ev("content_block_start", { index: 0, content_block: { type: "text", text: "" } });
        ev("content_block_delta", { index: 0, delta: { type: "text_delta", text: second ? "fine now" : "no picture" } });
      } else {
        ev("content_block_start", { index: 0, content_block: { type: "tool_use", id: "toolu_1", name: "mcp__sagebrush__view", input: {} } });
        ev("content_block_delta", { index: 0, delta: { type: "input_json_delta", partial_json: '{"path":"/a.png"}' } });
      }
      ev("content_block_stop", { index: 0 });
      ev("message_delta", { delta: { stop_reason: second || answered ? "end_turn" : "tool_use", stop_sequence: null }, usage: { output_tokens: 1 } });
      ev("message_stop", {}); res.end();
    });
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const home = mkdtempSync(join(tmpdir(), "sb-img-rej-"));
  const env = { PATH: process.env.PATH, HOME: home, CLAUDE_CONFIG_DIR: join(home, ".claude"), ANTHROPIC_API_KEY: "test-key-not-a-credential", ANTHROPIC_BASE_URL: `http://127.0.0.1:${srv.address().port}`, DISABLE_AUTOUPDATER: "1", CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1", CLAUDE_CODE_MAX_RETRIES: "0" };
  const server = () => cliCreateServer({ name: "sagebrush", version: "1", tools: [["view", "View an image", { path: z.string() }, async () => ({ content: [{ type: "image", data: pic.toString("base64"), mimeType: "image/png" }] })]] });
  const opts = (extra) => ({ includePartialMessages: false, settingSources: [], strictMcpConfig: true, tools: [], permissionMode: "default", persistSession: true, cwd: home, mcpServers: { sagebrush: server() }, canUseTool: async (_n, input) => ({ behavior: "allow", updatedInput: input }), ...extra });
  try {
    const first = [];
    for await (const m of cliQuery({ prompt: "look", options: opts({}) }, { env, bin: claudeBinary() })) first.push(m);
    const turn = new Turn("r"); turn.start();
    const ev = first.flatMap((m) => turn.feed(m));
    assert.deepEqual(ev.filter((e) => e.type === "turn_error"), []);
    assert.equal(first.find((m) => m.type === "result")?.result, "no picture");
    const refused = bodies.findIndex((b) => JSON.stringify(b.messages).includes('"type":"image"'));
    assert.ok(refused >= 0 && bodies.slice(refused + 1).every((b) => !JSON.stringify(b.messages).includes('"type":"image"')), "sent once, refused, never again");
    const sessionId = first.find((m) => m.type === "result")?.session_id;
    assert.ok(sessionId);
    const second = [];
    for await (const m of cliQuery({ prompt: "again please", options: opts({ resume: sessionId }) }, { env, bin: claudeBinary() })) second.push(m);
    const result = second.find((m) => m.type === "result");
    assert.equal(result.is_error, false);
    assert.equal(result.result, "fine now");
    assert.ok(!JSON.stringify(bodies.at(-1).messages).includes('"type":"image"'), "the refused image isn't sent again");
  } finally {
    srv.close();
  }
});
