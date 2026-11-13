// Codex app-server notifications -> Sagebrush turn events (web/agents/events.ts).
// Pure, like turns.mjs: one CodexTurn per turn, fed the notifications of its
// thread in order; it returns the event drafts to send (the page numbers them).

import { BODY_MAX, TOOL_KIND, artifactKind, cut, summaryOf } from "./turns.mjs";
import { PIN } from "./codex-fetch.mjs";

// What a Codex error means, in words the person can act on (TurnError.codexErrorInfo).
export const HINTS = {
  // (the pinned Codex's own login, without installing anything)
  unauthorized: `Codex isn't logged in on this computer: run \`npx -y @openai/codex@${PIN.version} login --device-auth\` there in a terminal, then send your message again. If it says device-code sign-in is off, turn it on in your ChatGPT security settings first.`,
  usageLimitExceeded: "Your Codex usage limit was reached.",
  rateLimitExceeded: "Codex's rate limit was reached: wait a little and try again.",
  serverOverloaded: "Codex is overloaded right now: try again in a moment.",
  contextWindowExceeded: "The conversation is too long for Codex: start a new chat.",
  modelNotFound: "Codex couldn't find its model: check your Codex settings on this computer.",
};

function errorInfo(error) {
  const info = error?.codexErrorInfo;
  const code = typeof info === "string" ? info : info && typeof info === "object" ? Object.keys(info)[0] : undefined;
  const message = (code && HINTS[code]) || cut(String(error?.message ?? "Codex stopped with an error"), 500);
  return { code: code ?? "codex_error", message };
}

function contentText(items) {
  return Array.isArray(items) ? items.map((c) => (c?.type === "inputText" ? String(c.text ?? "") : "")).join("") : "";
}

// (a file change, as the chat shows it: each path with what happens to it, then the diffs)
export function changesText(changes) {
  if (!Array.isArray(changes)) return "";
  return changes.map((c) => {
    const kind = c?.kind?.type === "update" && c.kind.move_path ? `move to ${c.kind.move_path}` : String(c?.kind?.type ?? "change");
    return `${c?.path} (${kind})\n${String(c?.diff ?? "")}`;
  }).join("\n");
}

export class CodexTurn {
  constructor(turnId, now = Date.now) {
    this.turnId = turnId;
    this.now = now;
    this.messages = 0;
    this.texts = new Map(); // Codex item id -> {id: our message id, streamed}
    this.calls = new Map(); // Codex item id -> {name, input, started}
    this.usage = { input_tokens: 0, output_tokens: 0 };
    this.lastError = null;
    this.finished = false;
  }

  start() {
    return [{ type: "turn_started" }];
  }

  text(itemId) {
    let t = this.texts.get(itemId);
    const out = [];
    if (!t) {
      t = { id: `${this.turnId}:m${this.messages++}`, streamed: false };
      this.texts.set(itemId, t);
      out.push({ type: "message_revised", message: t.id, revision: 1 });
    }
    return [t, out];
  }

  // One notification of this turn's thread: the drafts it gives.
  feed(method, p) {
    if (this.finished || !p) return [];
    const item = p.item;
    if (method === "item/started" && item?.type === "agentMessage") return this.text(item.id)[1];
    if (method === "item/agentMessage/delta") {
      const [t, out] = this.text(p.itemId);
      t.streamed = true;
      if (p.delta) out.push({ type: "text_delta", message: t.id, revision: 1, text: String(p.delta) });
      return out;
    }
    if (method === "item/completed" && item?.type === "agentMessage") {
      const [t, out] = this.text(item.id);
      if (!t.streamed && item.text) out.push({ type: "text_delta", message: t.id, revision: 1, text: String(item.text) });
      t.streamed = true;
      return out;
    }
    if (method === "item/reasoning/summaryTextDelta" && p.delta) return [{ type: "thinking_delta", text: String(p.delta) }];
    if (method === "item/started" && item && this.callOf(item)) {
      const { name, kind, input } = this.callOf(item);
      if (this.calls.has(item.id)) return [];
      this.calls.set(item.id, { name, input, started: this.now() });
      return [{ type: "tool_call_started", call: item.id, tool: kind, name, summary: summaryOf(name, input) }];
    }
    if (method === "item/completed" && item && this.callOf(item)) {
      const out = [];
      if (!this.calls.has(item.id)) out.push(...this.feed("item/started", p));
      const call = this.calls.get(item.id);
      const { ok, text } = this.resultOf(item);
      out.push({
        type: "tool_call_finished",
        call: item.id,
        status: ok ? "ok" : "error",
        duration_ms: Number.isFinite(item.durationMs) ? item.durationMs : Math.max(0, this.now() - call.started),
        ...(text ? { body: cut(text, BODY_MAX), ...(text.length > BODY_MAX ? { body_cut: true } : {}) } : {}),
      });
      // A file the agent wrote in the workspace is an artifact: shown beside the chat, kept in the workspace.
      const a = call.input;
      if (ok && call.name === "workspace_write" && typeof a?.path === "string" && typeof a?.text === "string") {
        out.push({ type: "artifact", id: a.path, ...artifactKind(a.path), title: a.path.split("/").pop(), path: a.path, body: a.text });
      }
      if (ok && call.name === "workspace_write_notebook" && typeof a?.path === "string") {
        const cells = Array.isArray(a.cells) ? a.cells.length : 0;
        out.push({ type: "artifact", id: a.path, kind: "notebook", title: a.path.split("/").pop(), path: a.path, body: `${cells} cells (${a.mode ?? "python"})` });
      }
      return out;
    }
    if (method === "thread/tokenUsage/updated") {
      const last = p.tokenUsage?.last;
      if (last) {
        this.usage.input_tokens += Number(last.inputTokens ?? 0) || 0;
        this.usage.output_tokens += Number(last.outputTokens ?? 0) || 0;
      }
      return [];
    }
    if (method === "error") {
      if (!p.willRetry) this.lastError = p.error;
      return [];
    }
    if (method === "turn/completed") return this.completed(p.turn);
    return [];
  }

  // The tool calls the chat shows: the workspace tools, and Codex's own on this computer.
  callOf(item) {
    switch (item.type) {
      case "dynamicToolCall": return { name: String(item.tool), kind: TOOL_KIND[item.tool] ?? "tool", input: item.arguments ?? {} };
      case "commandExecution": return { name: "command", kind: "terminal", input: { command: item.command } };
      case "fileChange": {
        const paths = Array.isArray(item.changes) ? item.changes.map((c) => c?.path).filter((x) => typeof x === "string") : [];
        return { name: "file change", kind: "edit", input: { path: paths.join(", ") } };
      }
      case "webSearch": return { name: "web search", kind: "web", input: { query: item.query } };
      case "mcpToolCall": return { name: `${item.server}.${item.tool}`, kind: "tool", input: item.arguments ?? {} };
      default: return null;
    }
  }

  resultOf(item) {
    switch (item.type) {
      case "dynamicToolCall": return { ok: item.success === true, text: contentText(item.contentItems) };
      case "commandExecution": return { ok: item.status === "completed" && item.exitCode === 0, text: item.aggregatedOutput ?? String(item.status ?? "") };
      case "fileChange": return { ok: item.status === "completed", text: item.status === "completed" ? changesText(item.changes) : String(item.status ?? "") };
      case "mcpToolCall": return { ok: !item.error && item.status !== "failed", text: item.error?.message ?? "" };
      default: return { ok: item.status !== "failed", text: "" };
    }
  }

  completed(turn) {
    if (this.finished) return [];
    this.finished = true;
    const out = [{ type: "turn_usage", usage: { ...this.usage } }];
    const status = turn?.status;
    if (status === "completed") out.push({ type: "turn_finished", outcome: "completed" });
    else if (status === "interrupted") out.push({ type: "turn_finished", outcome: "interrupted" });
    else {
      const { code, message } = errorInfo(turn?.error ?? this.lastError);
      out.push({ type: "turn_error", code, message }, { type: "turn_finished", outcome: "error", code });
    }
    return out;
  }

  interrupted() {
    if (this.finished) return [];
    this.finished = true;
    return [{ type: "turn_finished", outcome: "interrupted" }];
  }

  failed(message, code = "agent_error") {
    if (this.finished) return [];
    this.finished = true;
    return [
      { type: "turn_error", code, message: cut(String(message), 500) },
      { type: "turn_finished", outcome: "error", code },
    ];
  }
}
