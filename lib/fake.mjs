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

// (an Ask for changes: the person's note, exactly as task-turns.mjs puts it between its two marker lines; else null)
const ASKED = /----- the person's request ([0-9a-f]{16}) -----\n([\s\S]*?)\n----- end of the person's request \1 -----/;
export function askedNote(prompt) {
  const m = ASKED.exec(String(prompt ?? ""));
  return m ? m[2] : null;
}
// (how many pictures a read's text carries as data: base64 under an image MIME type, the way an .ipynb holds them)
export const inlinedImages = (t) => (String(t).match(/"image\/(?:png|jpeg|gif|webp)"\s*:\s*\[?\s*"[A-Za-z0-9+/=]{64,}/g) ?? []).length;
// (a note on one line, for a .tex: its line breaks and runs of space become one space)
const oneLine = (s) => s.replace(/\s+/g, " ").trim();
// (text set as LaTeX: its special characters escaped, so the preview builds whatever the note says)
const TEX = { "\\": "\\textbackslash{}", "{": "\\{", "}": "\\}", "$": "\\$", "&": "\\&", "#": "\\#", "^": "\\textasciicircum{}", "_": "\\_", "%": "\\%", "~": "\\textasciitilde{}" };
export const texText = (s) => s.replace(/[\\{}$&#^_%~]/g, (c) => TEX[c]);
// (lines put before the document's last \end{document}, or at its end if it has none)
function beforeEnd(src, lines) {
  const at = src.lastIndexOf("\\end{document}");
  if (at < 0) return `${src}${src.endsWith("\n") || !src ? "" : "\n"}${lines}`;
  return `${src.slice(0, at)}${lines}${src.slice(at)}`;
}

// (what the person said in each fake chat session, in order, for a brief's draft to read: at most SAID_SESSIONS
//  sessions (the oldest goes) and SAID_MESSAGES messages each)
const SAID_SESSIONS = 64, SAID_MESSAGES = 32;
const said = new Map();
function remember(session, text) {
  const list = said.get(session) ?? [];
  said.delete(session);
  said.set(session, [...list, text].slice(-SAID_MESSAGES));
  while (said.size > SAID_SESSIONS) said.delete(said.keys().next().value);
}

// A brief's draft (chat.brief): a fork of a chat's session with no tools at all, as lib/brief.mjs makes it. The fake
// writes the outline from what the person said in that session: the Goal is their first message, each line of theirs
// that begins "Decision:" is a Decisions line, and every /path.ext they named is under Files. In their first message,
// "draft slowly" waits 3 s first (so a page can cancel it), and "draft without outline" answers plain text.
export function fakeBrief(session) {
  const lines = said.get(session) ?? [];
  const goal = lines[0] ?? "(nothing was said yet)";
  const all = lines.join("\n");
  const decisions = all.split("\n").map((l) => l.trim()).filter((l) => /^Decision:/i.test(l)).map((l) => `- ${l.replace(/^Decision:\s*/i, "")}`);
  const files = [...new Set(all.match(/\/[\w./-]+\.\w+/g) ?? [])].map((f) => `- ${f}`);
  if (/draft without outline/i.test(goal)) return `A task from the chat: ${goal}`;
  return `Title: ${goal.split("\n")[0].slice(0, 80)}\n\n## Goal\n${goal}\n\n## Decisions made\n${decisions.join("\n") || "None."}\n\n## Files\n${files.join("\n") || "None."}\n\n## Done when\nThe person says the task is done.`;
}

export function fakeQuery({ prompt, options }) {
  const signal = options.abortController?.signal;
  if (options.forkSession === true && Array.isArray(options.tools) && options.tools.length === 0) {
    return (async function* () {
      yield { type: "system", subtype: "init", session_id: options.sessionId, model: "fake", tools: [] };
      if (/draft slowly/i.test(said.get(options.resume)?.[0] ?? "")) await sleep(3000, signal);
      const text = fakeBrief(options.resume);
      yield { type: "assistant", parent_tool_use_id: null, message: { role: "assistant", content: [{ type: "text", text }] } };
      yield { type: "result", subtype: "success", is_error: false, result: text, usage: { input_tokens: 1, output_tokens: 1 }, session_id: options.sessionId };
    })();
  }
  // (a delegated task's turn has its own tool server, sagebrush_task, and no page; a chat turn has the page's)
  const taskTurn = !!options.mcpServers.sagebrush_task;
  const server = taskTurn ? "sagebrush_task" : "sagebrush_page";
  const tools = options.mcpServers[server].handlers;
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
    yield { type: "stream_event", parent_tool_use_id: null, event: { type: "content_block_start", index: i, content_block: { type: "tool_use", id, name: `mcp__${server}__${name}`, input: {} } } };
    yield { type: "stream_event", parent_tool_use_id: null, event: { type: "content_block_delta", index: i, delta: { type: "input_json_delta", partial_json: JSON.stringify(input) } } };
    yield { type: "stream_event", parent_tool_use_id: null, event: { type: "content_block_stop", index: i } };
    // (the handler's extra, as the pinned Claude Code passes it: the call's tool_use id in _meta)
    const r = await tools[name](input, { _meta: { "claudecode/toolUseId": id } });
    yield { type: "user", parent_tool_use_id: null, message: { role: "user", content: [{ type: "tool_result", tool_use_id: id, content: r.content, is_error: !!r.isError }] } };
    return r;
  }
  async function* run() {
    prompt = await promptText(prompt);
    if (!taskTurn) remember(session, prompt);
    yield { type: "system", subtype: "init", session_id: session, model: "fake", tools: [] };
    if (taskTurn) {
      // (a delegated task: look at the copy; on the first round add a closing note to its first notebook (a Markdown
      //  cell at the end), else to its first .tex (a line before \end{document}), else write a note. On an Ask for
      //  changes, the person's note (from the turn's prompt, between its marker lines) goes into the same file as
      //  "Asked: <note>", so a test can see that round 2 carries it. Then propose. "slowly" in the task waits 3 s
      //  first, so a page can go away meanwhile)
      yield* text("(fake model) Working on the task in my copy.");
      if (/slowly/i.test(prompt)) await sleep(3000, signal);
      const asked = askedNote(prompt);
      const listed = yield* use("workspace_list", {});
      let files = [];
      try { files = JSON.parse(listed.content[0].text).map((f) => f.path); } catch {}
      const nb = files.find((f) => /\.ipynb$/i.test(f));
      const tex = nb ? null : files.find((f) => /\.tex$/i.test(f));
      if (nb) {
        // (what the read returned, said as a text event, so a test sees a notebook read that inlines pictures; then the
        //  note appended after the last cell, by cell, through the read's ids and past any cells the read left out)
        const read = yield* use("workspace_read", { path: nb });
        const got = read.content[0].text;
        yield* text(`(fake model) read ${nb}: ${Buffer.byteLength(got)} bytes, ${inlinedImages(got)} images inlined.`);
        let r = JSON.parse(got), last = r.cells?.at(-1)?.id ?? null, more;
        while ((more = /not shown: read them with \{path, from: (\d+)\}/.exec(r.note ?? ""))) {
          r = JSON.parse((yield* use("workspace_read", { path: nb, from: Number(more[1]) })).content[0].text);
          last = r.cells?.at(-1)?.id ?? last;
        }
        yield* use("workspace_edit_notebook", { path: nb, insert: [{ after: last, type: "markdown", source: asked === null ? "Done by the fake model, for this task." : `Asked: ${asked}` }] });
      } else if (tex) {
        const read = yield* use("workspace_read", { path: tex });
        const lines = asked === null ? "Done by the fake model, for this task.\n" : `% Asked: ${oneLine(asked)}\nAsked: ${texText(oneLine(asked))}\n`;
        yield* use("workspace_write", { path: tex, text: beforeEnd(read.content[0].text, lines) });
      } else {
        yield* use("workspace_write", { path: "fake-delegate.md", text: asked === null ? "# Done by the fake model, for this task\n" : `# Done by the fake model, for this task\n\nAsked: ${asked}\n` });
      }
      const where = nb ?? tex ?? "fake-delegate.md";
      yield* use("propose", { summary: asked !== null ? `Wrote the request into ${where}.` : nb ? `Added a closing note to ${nb}.` : tex ? `Added a closing line to ${tex}.` : "Wrote fake-delegate.md." });
      yield* text("Proposed: review it beside the task.");
      yield { type: "result", subtype: "success", is_error: false, result: "done", usage: { input_tokens: 1, output_tokens: 1 }, session_id: session };
      return;
    }
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
      const verdict = await options.canUseTool("mcp__sagebrush_page__workspace_remove", { path: "/notes/fake-note.md" }, { signal });
      if (verdict.behavior === "allow") yield* use("workspace_remove", { path: "/notes/fake-note.md" });
      else yield* text("You said no to removing it.");
    }
    yield* text("Done: the note is open beside the chat.");
    yield { type: "result", subtype: "success", is_error: false, result: "done", usage: { input_tokens: 1200, output_tokens: 90 }, session_id: session };
  }
  return run();
}
