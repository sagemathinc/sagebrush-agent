// A fake Anthropic Messages API on 127.0.0.1, for the CLI-mode tests only (never in the package): the real pinned
// Claude Code is pointed at it by the test's own environment (ANTHROPIC_BASE_URL), which the release entry refuses.
// `script(body, n)` gives each Messages request's reply as content blocks ({type: "text", text} or {type: "tool_use",
// name, input}); every request is recorded (its body, and when it came).
import { createServer } from "node:http";
import { randomBytes } from "node:crypto";

export async function fakeAnthropic(script, { onRequest = () => {} } = {}) {
  const requests = []; // (Messages requests only)
  const other = []; // (anything else asked of it)
  const srv = createServer((req, res) => {
    let s = "";
    req.on("data", (d) => (s += d));
    req.on("end", async () => {
      if (req.method !== "POST" || !/^\/v1\/messages(\?|$)/.test(req.url)) {
        other.push({ method: req.method, url: req.url });
        res.writeHead(200, { "content-type": "application/json" });
        return res.end(req.url.includes("count_tokens") ? '{"input_tokens":10}' : "{}");
      }
      let body;
      try { body = JSON.parse(s); } catch { res.writeHead(400); return res.end(); }
      const n = requests.length;
      requests.push({ at: Date.now(), body, headers: req.headers });
      await onRequest(body, n);
      let blocks = await script(body, n);
      if (!Array.isArray(blocks) || !blocks.length) blocks = [{ type: "text", text: "ok" }];
      blocks = blocks.map((b) => (b.type === "tool_use" ? { id: `toolu_${randomBytes(8).toString("hex")}`, ...b } : b));
      res.writeHead(200, { "content-type": "text/event-stream" });
      const ev = (type, data) => res.write(`event: ${type}\ndata: ${JSON.stringify({ type, ...data })}\n\n`);
      ev("message_start", { message: { id: `msg_${n}`, type: "message", role: "assistant", model: body.model, content: [], stop_reason: null, stop_sequence: null, usage: { input_tokens: 10, output_tokens: 1 } } });
      blocks.forEach((b, i) => {
        if (b.type === "text") {
          ev("content_block_start", { index: i, content_block: { type: "text", text: "" } });
          ev("content_block_delta", { index: i, delta: { type: "text_delta", text: b.text } });
        } else {
          ev("content_block_start", { index: i, content_block: { type: "tool_use", id: b.id, name: b.name, input: {} } });
          ev("content_block_delta", { index: i, delta: { type: "input_json_delta", partial_json: JSON.stringify(b.input ?? {}) } });
        }
        ev("content_block_stop", { index: i });
      });
      ev("message_delta", { delta: { stop_reason: blocks.some((b) => b.type === "tool_use") ? "tool_use" : "end_turn", stop_sequence: null }, usage: { output_tokens: 5 } });
      ev("message_stop", {});
      res.end();
    });
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  return { url: `http://127.0.0.1:${srv.address().port}`, port: srv.address().port, requests, other, close: () => new Promise((r) => { srv.close(() => r()); srv.closeAllConnections?.(); }) };
}

// The last user turn's tool results, as text, in a request body.
export function toolResults(body) {
  const last = body.messages?.at(-1);
  if (!Array.isArray(last?.content)) return [];
  return last.content.filter((c) => c.type === "tool_result").map((c) => ({ id: c.tool_use_id, error: !!c.is_error, text: typeof c.content === "string" ? c.content : (c.content ?? []).map((x) => x.text ?? "").join("") }));
}
