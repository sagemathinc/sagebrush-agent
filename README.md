# sagebrush-agent

Chat with Claude in [Sagebrush](https://sagebrush.space), with Claude running on your own computer.

```
npx -y <the tarball's URL>
```

It prints a link. Open it in Chrome or Firefox, and allow the folders Claude may use. Then chat.

## What it does

- It starts Claude through Anthropic's [Claude Agent SDK](https://www.npmjs.com/package/@anthropic-ai/claude-agent-sdk), with **your own Claude login**. It uses the same login as Claude Code: if you have used Claude Code on this computer, you are logged in. Otherwise run `claude` once and log in.
- It listens **only on 127.0.0.1** (the loopback address). It accepts a connection only:
  - from the Sagebrush page's origin;
  - with the one-time code it prints, valid once, for 5 minutes;
  - and only one page at a time. Before the hello, a connection may send at most 16 KiB in total and must say hello within 10 seconds; at most 4 wait at once.
- **One page, one grant:** everything Claude does belongs to the page that is paired and the access it granted. If the page disconnects or the grant changes, the running turn stops, queued messages are dropped (the page is told), and open questions count as "no". Nothing started under one grant runs under another. A page that comes back with its session (a reload) keeps the conversation, but not the stopped work.
- **Notebooks:** Claude can write a Sagebrush notebook (`workspace_write_notebook`: Python or Sage, code and Markdown cells). It opens beside the chat; **you** run its cells, unless you allowed Claude to run code (below). When Claude reads a notebook back, it sees every cell's source whole, but the outputs are shortened: at most 8 KiB of text per output, pictures and metadata named by size, and 256 KiB of outputs in all, after which it is told which cells' outputs it doesn't see. The file itself is unchanged.
- **Files:** Claude's only file tools are the Sagebrush workspace's (`workspace_list`, `workspace_read`, `workspace_write`, …). Each call goes to the page, which checks it against the folders and permissions you granted, and does it in the workspace in your browser.
  - Claude gets no shell, no files of this computer and no settings: the SDK runs with no setting sources, in an empty temporary folder. (Through `sagebrush remote`, the person can turn on shell and files on that computer: see below.)
- **Branches and runs**, on pages that offer them: Claude can make its own branch of your workspace (`workspace_git_branch`), commit it and ask you to review it (`workspace_git_commit`), see where it stands or wait for your decision (`workspace_git_status`, `workspace_git_wait`). While "May run code" is on for the page (you choose it when you grant access, and can turn it off at any time), it can also run a notebook or a .py/.sage file (`workspace_run_notebook`, `workspace_run_file`), build a .tex (`workspace_latex_build`) and stop its run (`workspace_run_stop`).
  - The code runs in Sagebrush's sandbox in your browser, never on this computer.
  - These calls don't ask you each time: the page allows only what your grant allows. A branch is only Claude's own, and only you accept its changes, on the review page.
  - If the turn is stopped or a run's time runs out, sagebrush-agent asks the page once to stop that run.
- **What asks you first, in the chat:** each web search or fetch (`WebSearch`, `WebFetch`), and each move, rename or removal of a workspace file. The question shows the address, query or path, and all of the call's arguments; your answer covers exactly those. Claude never decides on its own: the SDK runs in its manual permission mode (no auto mode, no bypass), only our MCP server is loaded, and any other tool is refused.
- **What leaves your computer:** the conversation goes to Anthropic, through the SDK, as with any Claude session. A web search or fetch you allow goes to that search or address (Anthropic runs the search; a fetch may go from this computer).
- **What is kept on disk:** like Claude Code, the SDK saves each conversation's transcript (your messages, Claude's replies, and the tools' results, including file contents Claude read) under `~/.claude/projects/`, in a folder named after the daemon's empty working folder. That is how a conversation goes on from one message to the next. When you stop sagebrush-agent with Ctrl+C, it waits (up to 10 seconds) for running turns to stop, then deletes this run's transcripts and the working folder, and says so; if it can't delete something, it says what and where it is. If it is killed or crashes, they stay there until you delete them. The SDK may also keep its usual logs under `~/.claude/`.

Options: `--port N` (default: a free port) and `--origin ORIGIN` (another allowed page origin, exact: like `https://example.org`, no path or wildcard). The environment variable `SAGEBRUSH_AGENT_PAGE` changes only the printed link, never which pages may connect.

Press Ctrl+C to stop.

## With `sagebrush remote`

`sagebrush remote --serve-agents --agent-cmd "npx -y <the tarball's URL> --stdio"` runs it as the runner's child. The page reaches it through the runner, one message per line on stdin and stdout, so it listens on no port and prints no link.
- The runner's Stop stops the running turns. Stopping the runner stops the agent: it waits up to 1 second for turns to stop, then deletes this run's transcripts, as above.
- No message is over the runner's limit, about 4 MB. A bigger file write fails as an ordinary error that Claude sees.
- An Allow counts only when the page's answer carries the hash of exactly the action that was asked about.

**Shell and files on that computer.** When the page's grant says so (the person's switch "Allow shell and files on <computer>", on by default for their own computer), Claude runs there much as it does when they type `claude`:
- its own tools (Bash, Read, Edit, Write, …) and system prompt, plus the Sagebrush workspace tools;
- in the runner's working folder (where `sagebrush remote` was started), with the person's own settings: `~/.claude` and that folder's `.claude` and `CLAUDE.md` (their allow, ask and deny rules, their MCP servers). Files Claude writes there stay; only the empty folder of the tools-only mode is removed when the agent stops;
- the permission mode their settings choose there, as Claude Code resolves it; with none set, the default mode, as an interactive `claude` starts. A bypassPermissions setting isn't taken up either: it runs in the default mode, and the agent's log says so (one set only in the folder's own `.claude/settings.json` is dropped without a log line, as below). If the mode can't be read, the reply doesn't start. Anything Claude Code asks about comes to the page as a card, with the exact command, path or edit, and an Allow counts only for that action. Nothing is written to the settings.
- A mode set only in the folder's own `.claude/settings.json` that asks less than the default (acceptEdits, auto or bypassPermissions) isn't taken up: the default mode is used, where an interactive `claude` there might use that mode. An administrator's policyHelper isn't run when the mode is read.
- Moving or removing a file in the Sagebrush workspace is always asked, even when the person's own rules would allow it.
- With the switch off, it's the Sagebrush-tools-only mode above. Over the loopback address, it's always that mode, whatever the page asks.
- The mode is decided once per reply. Turning the switch changes the grant, so, as with any grant change, a running reply stops and waiting messages are dropped. The next reply runs in the new mode, as a new Claude session: Claude hasn't seen that chat's earlier turns.

In both modes, at most 4 chats run at once (a fifth waits its turn) and at most 16 messages wait; a seventeenth is refused, and the page says so. `SAGEBRUSH_AGENT_FAKE=1`, set where you start it, runs a scripted fake model instead of Claude, for tests.

Release: the tarball is published at an immutable, versioned URL with its SHA-256; a change means a new version and a new review.
