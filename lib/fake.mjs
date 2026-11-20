// A fake model, for testing without Anthropic: it yields the SDK's message
// shapes (stream events, tool use, tool results, a result), and calls the
// real workspace tools, so a page round trip is exercised end to end.
// Used only with SAGEBRUSH_AGENT_FAKE=1.

const sleep = (ms, signal) =>
  new Promise((resolve, reject) => {
    const t = setTimeout(resolve, ms);
    signal?.addEventListener("abort", () => { clearTimeout(t); reject(Object.assign(new Error("aborted"), { name: "AbortError" })); }, { once: true });
  });

// A turn's prompt as text: the agent gives the model a stream of user messages (its first one, then any steers);
// the fake reads the first one's text.
export async function promptText(prompt) {
  if (typeof prompt === "string") return prompt;
  const { value } = await prompt[Symbol.asyncIterator]().next();
  const c = value?.message?.content;
  return typeof c === "string" ? c : Array.isArray(c) ? c.map((b) => b.text ?? "").join("") : "";
}

// The fake createSdkMcpServer: keeps the handlers, for the fake model to call.
export function fakeCreateServer(spec) {
  return { type: "fake", name: spec.name, handlers: Object.fromEntries(spec.tools.map(([name, , , h]) => [name, h])), shapes: Object.fromEntries(spec.tools.map(([name, , shape]) => [name, shape])) };
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
    prompt = await promptText(prompt);
    yield { type: "system", subtype: "init", session_id: session, model: "fake", tools: [] };
    // (controllable output, for byte-exact tests: "big N" writes a file of exactly N bytes; "slow" streams for a long
    // time; "flood N" sends N text events of 32 KiB each, as fast as it can)
    const big = /^big (\d+)$/.exec(prompt), flood = /^flood (\d+)$/.exec(prompt);
    if (big) {
      yield* use("workspace_write", { path: "/big.txt", text: "b".repeat(Number(big[1])) });
      yield { type: "result", subtype: "success", is_error: false, result: "done", usage: { input_tokens: 1, output_tokens: 1 }, session_id: session };
      return;
    }
    if (/^slow/.test(prompt)) {
      yield* text("word ".repeat(4000));
      yield { type: "result", subtype: "success", is_error: false, result: "done", usage: { input_tokens: 1, output_tokens: 1 }, session_id: session };
      return;
    }
    if (flood) {
      const i = index++;
      yield { type: "stream_event", parent_tool_use_id: null, event: { type: "content_block_start", index: i, content_block: { type: "text", text: "" } } };
      for (let k = 0; k < Number(flood[1]); k++) {
        if (signal?.aborted) return;
        yield { type: "stream_event", parent_tool_use_id: null, event: { type: "content_block_delta", index: i, delta: { type: "text_delta", text: "f".repeat(32 * 1024) } } };
        await new Promise((r) => setImmediate(r));
      }
      yield { type: "result", subtype: "success", is_error: false, result: "done", usage: { input_tokens: 1, output_tokens: 1 }, session_id: session };
      return;
    }
    // (the options this turn runs with, said back, for rows on native mode: "options?"; and a native tool asked about:
    //  "tool Bash <command>", "tool Edit", "tool AskUserQuestion", each through the agent's canUseTool as the SDK would)
    if (/^options\?$/.test(prompt)) {
      const o = options;
      const said = { tools: o.tools, settingSources: o.settingSources, permissionMode: o.permissionMode, strictMcpConfig: o.strictMcpConfig ?? null, systemPrompt: typeof o.systemPrompt === "string" ? "sagebrush" : o.systemPrompt?.preset ?? null, settings: o.settings ? "set" : null, cwd: o.cwd, resumed: !!o.resume };
      yield* text("OPTIONS " + JSON.stringify(said));
      yield { type: "result", subtype: "success", is_error: false, result: "done", usage: { input_tokens: 1, output_tokens: 1 }, session_id: session };
      return;
    }
    // ("touch NAME": a file by a relative name in the turn's working folder, as a native tool would write it)
    const touch = /^touch ([\w.-]+)$/.exec(prompt);
    if (touch) {
      const { writeFileSync } = await import("node:fs");
      const { join } = await import("node:path");
      writeFileSync(join(options.cwd, touch[1]), "made by the fake model\n");
      yield* text(`TOUCHED ${touch[1]}`);
      yield { type: "result", subtype: "success", is_error: false, result: "done", usage: { input_tokens: 1, output_tokens: 1 }, session_id: session };
      return;
    }
    // ("direct remove PATH": the workspace tool called without the permission callback, as Claude Code does when the
    //  person's own allow rules let it through)
    const direct = /^direct remove (\S+)$/.exec(prompt);
    if (direct) {
      const r = await tools.workspace_remove({ path: direct[1] });
      yield* text(`DIRECT ${r.isError ? "refused" : "done"}: ${r.content?.[0]?.text ?? ""}`);
      yield { type: "result", subtype: "success", is_error: false, result: "done", usage: { input_tokens: 1, output_tokens: 1 }, session_id: session };
      return;
    }
    const tool = /^tool (\w+)(?: (.+))?$/s.exec(prompt);
    if (tool) {
      const name = tool[1], arg = tool[2] ?? "";
      const input = name === "Bash" ? { command: arg || "ls", description: "List files" }
        : name === "Edit" ? { file_path: "/home/user/a.py", old_string: "x = 1", new_string: "x = 2" }
        : name === "AskUserQuestion" ? { questions: [{ question: "Which?", options: [{ label: "A" }, { label: "B" }] }] }
        : { value: arg };
      const verdict = await options.canUseTool(name, input, { signal });
      yield* text(`VERDICT ${name} ${verdict.behavior}${verdict.behavior === "deny" ? ": " + verdict.message : ""}`);
      yield { type: "result", subtype: "success", is_error: false, result: "done", usage: { input_tokens: 1, output_tokens: 1 }, session_id: session };
      return;
    }
    if (/^branch and run$/.test(prompt)) {
      // (the branch and run tools, each once, for an end-to-end row through the runner: the page answers them)
      yield* use("workspace_git_branch", { name: "fake-work" });
      yield* use("workspace_git_commit", { name: "fake-work", message: "Fake work\n\nfrom the fake model", review: true });
      yield* use("workspace_run_file", { path: "/Branches/fake-work/hello.py", timeout_s: 30 });
      yield* use("workspace_latex_build", { path: "/Branches/fake-work/main.tex", pages: [1, 2] });
      yield* text("Done: a branch, a commit, a run and a build.");
      yield { type: "result", subtype: "success", is_error: false, result: "done", usage: { input_tokens: 1, output_tokens: 1 }, session_id: session };
      return;
    }
    if (/notebook/i.test(prompt)) {
      // (a notebook: written, then read back, as the real model would to look at the outputs)
      yield* text("(fake model) I'll write a notebook with a plot.");
      yield* use("workspace_write_notebook", { path: "/notes/plot.ipynb", mode: "python", cells: [
        { type: "markdown", source: "# Partial sums\n\n$\\sum_{k=1}^n 1/k^2$" },
        { type: "code", source: "import matplotlib.pyplot as plt\ns = [sum(1/k**2 for k in range(1, n+1)) for n in range(1, 50)]\nplt.plot(s)" },
      ] });
      yield* use("workspace_read", { path: "/notes/plot.ipynb" });
      yield* text("Done: run the cells beside the chat.");
      yield { type: "result", subtype: "success", is_error: false, result: "done", usage: { input_tokens: 900, output_tokens: 60 }, session_id: session };
      return;
    }
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
