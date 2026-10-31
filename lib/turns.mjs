// Claude Agent SDK messages -> Sagebrush turn events (web/agents/events.ts).
// Pure: one Turn object per turn, fed every SDK message in order; it returns
// the event drafts to send (the page numbers them).

const BODY_MAX = 64 * 1024;
const SUMMARY_MAX = 300;

const cut = (s, n) => (s.length > n ? s.slice(0, n) + "…" : s);

// The workspace tools, as the page shows them.
const TOOL_KIND = {
  workspace_list: "file",
  workspace_read: "file",
  workspace_write: "edit",
  workspace_write_notebook: "edit",
  workspace_mkdir: "file",
  workspace_rename: "file",
  workspace_remove: "file",
  WebSearch: "web",
  WebFetch: "web",
};

function shortName(name) {
  const m = /^mcp__sagebrush__(.+)$/.exec(name);
  return m ? m[1] : name;
}

function summaryOf(name, input) {
  const n = shortName(name);
  if (!input || typeof input !== "object") return undefined;
  if (n === "workspace_rename") return `${input.from} → ${input.to}`;
  if (typeof input.path === "string") return input.path;
  if (typeof input.folder === "string") return input.folder;
  if (typeof input.query === "string") return cut(input.query, SUMMARY_MAX);
  if (typeof input.url === "string") return cut(input.url, SUMMARY_MAX);
  return cut(JSON.stringify(input), SUMMARY_MAX);
}

function artifactKind(path) {
  if (/\.(md|markdown)$/i.test(path)) return { kind: "markdown" };
  const m = /\.([A-Za-z0-9]+)$/.exec(path);
  const lang = m ? m[1].toLowerCase() : undefined;
  return { kind: "code", lang };
}

function resultText(content) {
  if (typeof content === "string") return content;
  if (Array.isArray(content)) return content.map((c) => (c && c.type === "text" ? c.text : "")).join("");
  return "";
}

export class Turn {
  constructor(turnId, now = Date.now) {
    this.turnId = turnId;
    this.now = now;
    this.blocks = new Map(); // stream block index -> {type, id?, call?, name?, json}
    this.messages = 0;
    this.calls = new Map(); // tool_use id -> {name, input, started}
    this.finished = false;
  }

  start() {
    return [{ type: "turn_started" }];
  }

  // One SDK message: the drafts it gives.
  feed(m) {
    const out = [];
    if (!m || this.finished) return out;
    if (m.type === "stream_event" && !m.parent_tool_use_id) {
      const e = m.event;
      if (e.type === "content_block_start") {
        const b = e.content_block;
        if (b.type === "text") {
          const id = `${this.turnId}:m${this.messages++}`;
          this.blocks.set(e.index, { type: "text", id });
          out.push({ type: "message_revised", message: id, revision: 1 });
          if (b.text) out.push({ type: "text_delta", message: id, revision: 1, text: b.text });
        } else if (b.type === "thinking") {
          this.blocks.set(e.index, { type: "thinking" });
        } else if (b.type === "tool_use" || b.type === "server_tool_use") {
          this.blocks.set(e.index, { type: "tool_use", call: b.id, name: b.name, json: "" });
        }
      } else if (e.type === "content_block_delta") {
        const blk = this.blocks.get(e.index);
        const d = e.delta;
        if (!blk) return out;
        if (d.type === "text_delta" && blk.type === "text") out.push({ type: "text_delta", message: blk.id, revision: 1, text: d.text });
        else if (d.type === "thinking_delta" && blk.type === "thinking") out.push({ type: "thinking_delta", text: d.thinking });
        else if (d.type === "input_json_delta" && blk.type === "tool_use") blk.json += d.partial_json;
      } else if (e.type === "content_block_stop") {
        const blk = this.blocks.get(e.index);
        this.blocks.delete(e.index);
        if (blk?.type === "tool_use") {
          let input = {};
          try { input = blk.json ? JSON.parse(blk.json) : {}; } catch { input = {}; }
          this.calls.set(blk.call, { name: blk.name, input, started: this.now() });
          const n = shortName(blk.name);
          out.push({ type: "tool_call_started", call: blk.call, tool: TOOL_KIND[n] ?? "tool", name: n, summary: summaryOf(blk.name, input) });
        }
      }
      return out;
    }
    if (m.type === "assistant" && !m.parent_tool_use_id && m.error) {
      // (the model couldn't answer: say why, in words the person can act on)
      const hint = {
        authentication_failed: "Claude isn't logged in on this computer: run `claude` once in a terminal and log in, then start sagebrush-agent again.",
        oauth_org_not_allowed: "Your Claude organization doesn't allow this login.",
        billing_error: "Claude reported a billing problem with your account.",
        rate_limit: "Claude's rate limit was reached: wait a little and try again.",
        overloaded: "Claude is overloaded right now: try again in a moment.",
      }[m.error];
      out.push({ type: "turn_error", code: String(m.error), message: hint ?? `Claude reported: ${m.error}` });
      return out;
    }
    if (m.type === "user" && !m.parent_tool_use_id && Array.isArray(m.message?.content)) {
      for (const c of m.message.content) {
        if (c?.type !== "tool_result") continue;
        const call = this.calls.get(c.tool_use_id);
        if (!call) continue;
        const text = resultText(c.content);
        const n = shortName(call.name);
        out.push({
          type: "tool_call_finished",
          call: c.tool_use_id,
          status: c.is_error ? "error" : "ok",
          duration_ms: Math.max(0, this.now() - call.started),
          ...(text ? { body: cut(text, BODY_MAX), ...(text.length > BODY_MAX ? { body_cut: true } : {}) } : {}),
        });
        // A file the agent wrote is an artifact: shown beside the chat, kept in the workspace.
        if (!c.is_error && n === "workspace_write_notebook" && typeof call.input.path === "string") {
          // (a notebook: the page opens the file itself; the body is a short summary)
          const p = call.input.path;
          const cells = Array.isArray(call.input.cells) ? call.input.cells.length : 0;
          out.push({ type: "artifact", id: p, kind: "notebook", title: p.split("/").pop(), path: p, body: `${cells} cells (${call.input.mode ?? "python"})` });
        }
        if (!c.is_error && n === "workspace_write" && typeof call.input.path === "string" && typeof call.input.text === "string") {
          const p = call.input.path;
          out.push({ type: "artifact", id: p, ...artifactKind(p), title: p.split("/").pop(), path: p, body: call.input.text });
        }
      }
      return out;
    }
    if (m.type === "result") {
      this.finished = true;
      const u = m.usage ?? {};
      out.push({ type: "turn_usage", usage: { input_tokens: Number(u.input_tokens ?? 0), output_tokens: Number(u.output_tokens ?? 0) } });
      if (m.subtype !== "success" || m.is_error) {
        const message = m.subtype === "success" ? cut(String(m.result ?? "error"), 500) : m.subtype;
        out.push({ type: "turn_error", code: String(m.subtype), message });
        out.push({ type: "turn_finished", outcome: "error", code: String(m.subtype) });
      } else {
        out.push({ type: "turn_finished", outcome: "completed" });
      }
    }
    return out;
  }

  interrupted() {
    if (this.finished) return [];
    this.finished = true;
    return [{ type: "turn_finished", outcome: "interrupted" }];
  }

  failed(message) {
    if (this.finished) return [];
    this.finished = true;
    return [
      { type: "turn_error", code: "agent_error", message: cut(String(message), 500) },
      { type: "turn_finished", outcome: "error", code: "agent_error" },
    ];
  }
}
