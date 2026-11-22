// Delegate briefs (chat.brief): when the person clicks Delegate in a Pair chat, the chat's own Claude session drafts
// the task's brief from the conversation. The draft runs in a fork of that session, with an id of ours, no tools of
// any kind and one turn; the Pair session itself is never extended. Here: the feature's name, its fixed prompts (the
// same for every person and page: nothing from the page goes into them), the draft turn's options (a fresh object,
// never the Pair turn's options spread in) and the answer's shape and caps.

export const BRIEF_FEATURE = "chat.brief";
export const BRIEF_LIMITS = Object.freeze({
  title: 200, // characters (tasks.start's title limit)
  brief: 8 * 1024, // UTF-8 bytes, the cut marker included
  ms: 60 * 1000, // the whole draft, from the request to its answer
  read: 64 * 1024, // characters of the model's answer kept while it comes; the rest is never held
});
export const BRIEF_CUT = "\n\n[brief cut at 8 KiB]";
export const BRIEF_UNTITLED = "Task from the chat";
export const OUTLINE = Object.freeze(["## Goal", "## Decisions made", "## Files", "## Done when"]);

// The draft's one prompt, fixed: the same for every person and page, nothing from the page in it. It is a user message:
// a resumed or forked session keeps the system prompt it started with (the Pair session's own; checked with the
// pinned CLI: a systemPrompt passed with resume or forkSession isn't sent), so the outline is asked for here.
export const BRIEF_PROMPT = `Write the brief for a task that another agent will do alone, from our conversation so far. That agent sees only your brief and copies of the person's documents: none of this conversation. You have no tools in this turn, and you need none: write from the conversation alone. Name files by the paths said in the conversation; never guess at their contents.

Answer with exactly this outline, and nothing before or after it:

Title: <the task in a few words, on one line>

## Goal
<what the task is for, in the person's terms>

## Decisions made
- <each decision the person made in the conversation, as they said it; "None." if there were none>

## Files
- <each workspace path named in the conversation; "None." if there were none>

## Done when
<how the person will know the task is done>`;

// The draft turn's options: built fresh here for every draft, so nothing of a Pair turn's options (its tools, MCP
// servers, the person's settings in native mode, hooks) can come along.
// - resume + forkSession + sessionId: a fork of the Pair session, under an id the agent made; the Pair session is
//   only read. persistSession false: the fork isn't written to disk (the agent still deletes its id when the draft
//   ends, whatever the ending).
// - No tools at all: no built-in tools, no MCP servers (and no others from any configuration), no settings sources,
//   no plugins, no hooks, hooks and the status line disabled, no auto memory; and canUseTool refuses every call.
// - One turn, the fixed prompt. No systemPrompt: the fork keeps the Pair session's own (a fixed one too).
export function briefOptions({ resume, forkId, cwd, abortController }) {
  return {
    resume,
    forkSession: true,
    sessionId: forkId,
    persistSession: false,
    cwd,
    tools: [],
    mcpServers: {},
    strictMcpConfig: true,
    settingSources: [],
    plugins: [],
    hooks: {},
    maxTurns: 1,
    permissionMode: "default",
    settings: {
      disableAllHooks: true,
      autoMemoryEnabled: false,
      permissions: { defaultMode: "default", disableAutoMode: "disable", disableBypassPermissionsMode: "disable" },
    },
    canUseTool: async () => ({ behavior: "deny", message: "A brief is written without tools." }),
    abortController,
  };
}

const enc = new TextEncoder();
const LONE = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/g;
const bytesOf = (s) => enc.encode(s).length;

// `s` cut to at most `max` UTF-8 bytes, at a character boundary (a code point is never split).
export function cutBytes(s, max) {
  if (bytesOf(s) <= max) return s;
  let n = 0, end = 0;
  for (const ch of s) {
    const b = bytesOf(ch);
    if (n + b > max) break;
    n += b;
    end += ch.length;
  }
  return s.slice(0, end);
}

// A title: one line, no control characters, at most BRIEF_LIMITS.title characters (code points); empty if nothing is
// left.
function titleOf(s) {
  const t = [...String(s).replace(/[\u0000-\u001f\u007f]+/g, " ").replace(/\s+/g, " ").trim()];
  return t.slice(0, BRIEF_LIMITS.title).join("").trim();
}

// Whether a body follows the outline: it starts with the first heading, and has every heading on a line of its own,
// in order.
function followsOutline(body) {
  if (!body.startsWith(OUTLINE[0] + "\n")) return false;
  let at = 0;
  for (const h of OUTLINE) {
    const re = new RegExp(`(^|\\n)${h.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}[ \\t]*(\\n|$)`, "g");
    re.lastIndex = at;
    const m = re.exec(body);
    if (!m) return false;
    at = m.index + m[0].length;
  }
  return true;
}

// The model's answer as the page gets it: {title, brief, bytes, cut}, or null if there is nothing to brief.
// - The outline followed (a "Title:" line, then the headings in order): its title, and the rest as the brief.
// - Otherwise: the whole answer is the brief, and the title is its first line (without a "Title:" or heading mark),
//   or BRIEF_UNTITLED.
// - The brief is at most BRIEF_LIMITS.brief UTF-8 bytes: past it, it is cut at a character boundary and ends with
//   BRIEF_CUT, and `cut` says so. `bytes` is the brief's own size as sent.
export function shapeBrief(answer) {
  // (well-formed text, as tasks.start requires of a title and a prompt: no U+0000, and a lone surrogate as U+FFFD)
  const text = String(answer ?? "").replace(/\u0000/g, "").replace(LONE, "�").replace(/\r\n?/g, "\n").trim();
  if (!text) return null;
  const m = /^Title:[ \t]*([^\n]*)\n+([\s\S]*)$/.exec(text);
  let title, brief;
  if (m && followsOutline(m[2].trim())) {
    title = titleOf(m[1]);
    brief = m[2].trim();
  } else {
    brief = text;
    title = titleOf(text.split("\n").find((l) => l.trim()).replace(/^(Title:|#+)\s*/, ""));
  }
  if (!title) title = BRIEF_UNTITLED;
  let cut = false;
  if (bytesOf(brief) > BRIEF_LIMITS.brief) {
    brief = cutBytes(brief, BRIEF_LIMITS.brief - bytesOf(BRIEF_CUT)).trimEnd() + BRIEF_CUT;
    cut = true;
  }
  return { title, brief, bytes: bytesOf(brief), cut };
}
