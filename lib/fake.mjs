// A fake model, for testing without Anthropic: it yields the SDK's message
// shapes (stream events, tool use, tool results, a result), and calls the
// real workspace tools, so a page round trip is exercised end to end.
// Used only with SAGEBRUSH_AGENT_FAKE=1.

const sleep = (ms, signal) =>
  new Promise((resolve, reject) => {
    const t = setTimeout(resolve, ms);
    signal?.addEventListener("abort", () => { clearTimeout(t); reject(Object.assign(new Error("aborted"), { name: "AbortError" })); }, { once: true });
  });

// The fake createSdkMcpServer: keeps the handlers, for the fake model to call.
export function fakeCreateServer(spec) {
  return { type: "fake", name: spec.name, handlers: Object.fromEntries(spec.tools.map(([name, , , h]) => [name, h])) };
}

export function fakeQuery({ prompt, options }) {
  const signal = options.abortController?.signal;
  const tools = options.mcpServers.sagebrush.handlers;
  const session = options.resume ?? `fake-${Math.random().toString(36).slice(2)}`;
  let index = 0;
  async function* text(t) {
    const i = index++;
    yield { type: "stream_event", parent_tool_use_id: null, event: { type: "content_block_start", index: i, content_block: { type: "text", text: "" } } };
    for (const w of t.match(/\S+\s*/g) ?? []) {
      await sleep(15, signal);
      yield { type: "stream_event", parent_tool_use_id: null, event: { type: "content_block_delta", index: i, delta: { type: "text_delta", text: w } } };
    }
    yield { type: "stream_event", parent_tool_use_id: null, event: { type: "content_block_stop", index: i } };
  }
  async function* use(name, input) {
    const i = index++;
    const id = `toolu_${Math.random().toString(36).slice(2, 12)}`;
    yield { type: "stream_event", parent_tool_use_id: null, event: { type: "content_block_start", index: i, content_block: { type: "tool_use", id, name: `mcp__sagebrush__${name}`, input: {} } } };
    yield { type: "stream_event", parent_tool_use_id: null, event: { type: "content_block_delta", index: i, delta: { type: "input_json_delta", partial_json: JSON.stringify(input) } } };
    yield { type: "stream_event", parent_tool_use_id: null, event: { type: "content_block_stop", index: i } };
    const r = await tools[name](input);
    yield { type: "user", parent_tool_use_id: null, message: { role: "user", content: [{ type: "tool_result", tool_use_id: id, content: r.content, is_error: !!r.isError }] } };
  }
  async function* run() {
    yield { type: "system", subtype: "init", session_id: session, model: "fake", tools: [] };
    yield* text(`(fake model) You said: "${prompt.slice(0, 200)}". I'll write that into a note.`);
    yield* use("workspace_write", { path: "/notes/fake-note.md", text: `# A note\n\nYou said:\n\n> ${prompt.replace(/\n/g, "\n> ")}\n\nAnd some math: $e^{i\\pi} + 1 = 0$.\n` });
    yield* use("workspace_list", { folder: "/", recursive: true });
    if (/search/i.test(prompt)) {
      const verdict = await options.canUseTool("WebSearch", { query: prompt }, { signal });
      yield* text(verdict.behavior === "allow" ? "You allowed the search (the fake model doesn't search)." : "You said no to the search.");
    }
    if (/remove/i.test(prompt)) {
      const verdict = await options.canUseTool("mcp__sagebrush__workspace_remove", { path: "/notes/fake-note.md" }, { signal });
      if (verdict.behavior === "allow") yield* use("workspace_remove", { path: "/notes/fake-note.md" });
      else yield* text("You said no to removing it.");
    }
    yield* text("Done: the note is open beside the chat.");
    yield { type: "result", subtype: "success", is_error: false, result: "done", usage: { input_tokens: 1200, output_tokens: 90 }, session_id: session };
  }
  return run();
}
