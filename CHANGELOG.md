# sagebrush-agent changes

## 0.8.11

**A Delegate proposal no longer looks unfinished, and a task's changes are proposed even when Claude doesn't propose them.** Running code in Delegate is still not enabled in this version.

- **After "Proposal ready":** the task view no longer shows the propose call still running or "Working…". The proposal now comes with the propose call's answer and the turn's end, saved together.
- **A turn that ends with changes but no proposal:** when Claude's turn completes and the task's copy has changes, the agent proposes the copy itself, and the summary says it was proposed automatically. A turn with no changes, or one that was stopped, failed or ran past a limit, still leaves the task interrupted, saying why.

## 0.8.10

**The printed link opens the page you named with --origin.** Running code in Delegate is still not enabled in this version.

- **One --origin, its own link:** started with exactly one `--origin`, such as `--origin https://dev.sagebrush.space`, the agent now prints a link to that site's Agents page (`<origin>/agents/`). Before, it always printed a sagebrush.space link unless `SAGEBRUSH_AGENT_PAGE` was set.
- **What stays the same:** `SAGEBRUSH_AGENT_PAGE` still sets the link's page when it is set. With no `--origin`, or more than one, the link opens sagebrush.space; with more than one, the agent also says how to choose the page. Neither the link nor `SAGEBRUSH_AGENT_PAGE` changes which pages may connect.

## 0.8.9

**A brief asked right after a turn waits for it.** Running code in Delegate is still not enabled in this version.

- **Drafting a brief just after a turn:** a turn shows as finished when Claude's answer arrives, but it can take a moment more to close. A brief asked in that moment used to be refused as busy; now it waits for the turn to close, then drafts. While it waits, that chat takes no new message. A brief asked while a turn is still under way is still refused as busy.
- **Its limits, as in 0.8.7:** the 60 seconds include the time spent waiting for the previous turn to close. After 60 seconds, or when the person stops drafting, the draft is cancelled and no brief is returned. If its Claude Code work doesn't end, the agent reports that and keeps it counted against its limits.

## 0.8.8

**A Pair turn that hangs now ends for the page.** Running code in Delegate is still not enabled in this version.

- **Stop ends a turn, even a stuck one:** if Claude Code stops answering in the middle of a Pair turn, the person's Stop (or the workspace access ending, a turn's time limit, or the agent stopping) now ends the turn for the page at once, and the chat can go on. Before, such a turn showed as running for good, and Stop didn't end it.
- **What stays counted:** if that turn's Claude Code work doesn't end, the agent reports that, and the turn keeps its place among the turns the agent runs at once (at most 4) until the work ends. So a stuck turn never lets the agent start more than its limits allow.

## 0.8.7

**A Delegate task's brief, drafted from the Pair chat.** Running code in Delegate is still not enabled in this version.

- **Drafting a brief (`chat.brief`):** when the person delegates from a Pair chat, the Agents page can ask the agent to draft the task's brief from that conversation: a title, then the Goal, the Decisions made, the Files named and when it's Done. The person edits it before starting the task. The task itself still starts fresh, with only the brief and its documents.
- **How it is drafted:** by the chat's own Claude session, in a copy of it that has no tools of any kind and one turn. The chat itself is unchanged, nothing shows in it, and the copy isn't kept. It needs the Delegate switch on, and a chat Claude runs (not Codex).
- **Its limits:** a title of at most 200 characters and a brief of at most 8 KiB (a longer one is cut, and says so). After 60 seconds, or when the person stops drafting, the draft is cancelled and no brief is returned. If its Claude Code work doesn't end, the agent reports that and keeps it counted against its limits. While one is being written that chat takes no new message. A draft counts against the agent's limit on turns running at once.

## 0.8.6

**A launch for the Sagebrush desktop app.** Nothing changes for `npx` or `sagebrush remote`: without the new option, the agent starts, pairs and runs as before. Running code in Delegate is still not enabled in this version.

- **`--pair-stdin`:** the desktop app can start the agent itself, as `sagebrush-agent --pair-stdin --origin http://127.0.0.1:<port> --port 0`. The app makes the one-time pairing code and hands it over the agent's standard input, so no code or link is printed. The agent accepts only the app's own page (that one local address, never the usual Sagebrush sites), picks a free port and reports it as one line, and stops when the app is gone. A malformed, oversized or late first line refuses the launch without echoing it; the code works once.
- **What the app's agent can reach:** only what the Agents page offers: its workspace, and web requests and web search the person allows for a turn. Claude's built-in tools that reach the computer (the shell, reading and writing its files, Claude's own web fetch, subagents and the like) are refused by name, no plugins load, and none of the person's Claude Code settings, hooks, MCP servers or CLAUDE.md files are loaded. A test runs the real pinned Claude Code against hostile settings of each kind and checks that none of them runs.

## 0.8.5

**A task can delete any file or folder in its copy.** Running code in Delegate is still not enabled in this version.

- **Deleting in a task:** a task (Delegate) can now delete any file in its copy, including the documents it started with, and a folder with everything in it. So a task like "consolidate tmp1.py and tmp2.py into lib.py" can finish the job. The deletion is part of the task's proposal, which the person reviews before anything changes in their own files, and the task's history (git) keeps the documents it started with. Before, a task could delete only a file it had created.
- **What stays refused:** a path outside the task's copy, and a link, or a path through one. A folder holding a link, or anything that isn't a plain file or folder, is refused whole, with nothing deleted.

## 0.8.4

**Delegate reads notebooks with plots, and both modes read notebooks the same way.** Running code in Delegate is still not enabled in this version: `notebook_run` refuses, saying so.

- **Reading a notebook:** a task (Delegate) and a chat (Pair) now read a notebook the same way: its cells, with each output summarized. A picture or other data is never sent to the model, only its type and size; text outputs are cut at 400 bytes, said so. A whole answer is at most 48 KB; cells past that are named, with how to read them, and one cell can be read in full. Before, a task read a notebook's whole file, pictures included, and a notebook with a plot could be too large for the model to read at all.
- **Changing one cell in a task:** a task can now change a notebook by cell (change a cell's source or type, insert a cell, remove a cell), and every other cell keeps its outputs and its id. Before, a task could only rewrite a notebook whole.
- **Deleting a file in a task:** a task can delete a file it created in its copy. The change is part of its proposal, which the person reviews.
- **Files that are cut:** a long text file a task reads says how long it is and how much a read returns, in numbers.

## 0.8.3

**For tests: the fake model carries an Ask for changes into its next proposal.** Nothing changes for Claude or Codex. The fake model runs only with `SAGEBRUSH_AGENT_FAKE=1`, which the end-to-end tests set. Running code in Delegate is still not enabled in this version: `notebook_run` refuses, saying so.

- **Ask for changes:** on a Delegate task's next round, the fake model writes the person's note into the file it works on, as "Asked: <note>":
  - a notebook gets a Markdown cell at the end, with the note exactly as sent;
  - a LaTeX file gets a comment line and a visible line before `\end{document}`, the note on one line, with LaTeX's special characters escaped so the note is treated as text.
  So a test can see that round 2 carries what was asked.
- **A LaTeX file:** on a task whose copy has a .tex file and no notebook, the fake model's first round now adds a line to the .tex ("Done by the fake model, for this task."), so its proposal has a rendered change to preview.

## 0.8.2

**Newer Codex and Claude Code, one collision key for task paths, and the groundwork for Windows.** Running code in Delegate is still not enabled in this version: `notebook_run` refuses, saying so.

- **Codex 0.171.0 and Claude Code 2.1.330:** the Codex this agent downloads and checks is now 0.171.0, on every platform, and the Claude Agent SDK is 0.3.330 (Claude Code 2.1.330). Each release of this agent now pins the latest Codex and Claude Code.
- **Names that differ only in case or Unicode form:** task paths now use one collision key across platforms, whatever the volume: a letter written composed or decomposed is one name (é as one character, or as e plus its accent), and so are "ß", "ẞ", "SS" and "ss", as well as names that differ only in case. Such names are refused together wherever a task's set of paths is checked: its documents at the start, a write during a turn, and the working copy when it is proposed. Nothing the earlier rule refused is let through.
- **Windows, groundwork:**
  - The Codex download is checked and kept private by owner and access list, since Windows has no POSIX modes: the cache's folders and every folder and file in the download. A folder or file without a usable access list is never taken as private. It lives under `%LOCALAPPDATA%\sagebrush-agent`.
  - The processes this agent starts run in a Windows job object, so stopping them also ends anything they started, including processes whose parent has already gone.
  - A runner on Windows can stop the running turns with a control line, since it can't send a signal there.
  - A few file paths are now built in a way that works on Windows.
  - Delegate stays off on Windows in this version, and says why.
  - Codex itself is still refused on Windows in this version ("Codex on Windows isn't supported here."). It is downloaded and checked there, then refused as soon as it answers its first request; no turn runs.
  - Known on Windows: Node writes the agent's output to its runner synchronously there, so a runner that stops reading holds up the whole agent until it reads again. On other systems only that turn is stopped.
- **Tests:** the suite passes on Windows: 438 rows pass and none fail. 127 are declared skips with their reasons: 101 are Delegate's (off on Windows in this version), 13 don't apply there (POSIX modes, signals, /proc, and the known output limit). The remaining 13 skip process lookup for runs (2), POSIX shell stand-ins (5), or TLS tests needing OpenSSL, which was absent on this VM (6).

## 0.8.1

**macOS: the Delegate runner's environment, and tests that pass on a Mac.** Running code in Delegate is still not enabled in this version: `notebook_run` refuses, saying so.

- **The runner's environment on macOS:** a run's environment is replaced whole, and on macOS it now also holds `__CF_USER_TEXT_ENCODING`, set by the runner from this account's uid (never taken from this agent's environment). Without it, macOS could add that variable inside a run by itself, so a run saw a variable the runner never gave it, some of the time.
- **Names that differ only in case:** where a task's copy is on a volume that tells them apart, two such names are still refused when the task is proposed. On a volume that doesn't (macOS's default), the copy can only ever hold one of them, and that one file is what is proposed.
- **Tests:** the suite now passes on macOS as well as on Linux. Three assumptions in the tests are fixed, none of them in the agent itself: a test waits until the agent has seen a page go before going on, a stand-in's process id is written whole before it is read, and the case test asks the volume rather than the platform.

## 0.8.0

**Delegate: give Claude a task, close the tab, and review its proposal later.** It works over the loopback address only, and only while the page's grant has Delegate on, which is the person's own switch.

- **A task** is a title, what to do, and a copy of the documents chosen for it. Claude works on that copy on this computer, with no page and no workspace calls, then proposes the result. Closing the tab, or reopening the page and pairing again, leaves the tasks running; turning the switch off, or revoking the pairing, interrupts them.
- **The page and this agent:** with this version, the Agents page has the Delegate switch (and, when turning it off, the option to close the tasks). There, the person starts tasks, follows them, and sees a proposal as a difference from what Claude started with. This agent also supports, through the protocol, Merge, Close, Ask for changes (Claude's next turn gets the request exactly as written), Stop, Resume and Revoke; the page offers them in a later version. A merge is done in the page: the agent only records what the page reports.
- **Where tasks live:** each task is a private folder under `~/.sagebrush/tasks/`, with its own local git history, its events and its state. The task's grant is fixed when it starts and recorded in its first commit. After a crash or restart, an interrupted operation is finished or undone where its records allow it; where they don't, the task is left failed and untouched for the person. A task that was working is left interrupted until the person resumes it.
- **Limits:**
  - at most 4 tasks working at once (16 more waiting), and 24 hours per turn;
  - 512 MB per task (the copy at most 256 MB and 2,000 files);
  - 64 tasks and 4 GB in all;
  - a free-disk check before and during each turn.
- **What Claude can do in a task:** list, read and write the files of its copy, write notebooks, and propose. Nothing else: no shell, no files of this computer, no web, no settings.
- **Running code in Delegate is not enabled in this version.** `notebook_run` refuses, saying so. The runner it will use is included but switched off: a pinned Deno, the engine confined to the task's copy, a fresh scratch folder per run, and a kill and undo on Stop or a limit. It needs an engine release with confinement and its own review before it is turned on.
- **Events:** each chat event a task records is made to fit what the page can show. Long text is split, long labels are cut, and ids are made stable.
- The README's Delegate and Running code sections describe all of this, including what is kept on disk and what leaves your computer.

Nothing changes for chat or for Codex.

## Earlier versions

See the tags `v0.7.2` to `v0.7.8` in this repository, each with its commit message.
