# sagebrush-agent changes

## 0.8.2

**Newer Codex and Claude Code, names that are one name on a Mac, and the groundwork for Windows.** Running code in Delegate is still not enabled in this version: `notebook_run` refuses, saying so.

- **Codex 0.171.0 and Claude Code 2.1.330:** the Codex this agent downloads and checks is now 0.171.0, on every platform, and the Claude Agent SDK is 0.3.330 (Claude Code 2.1.330). Each release of this agent now pins the latest Codex and Claude Code.
- **Names that differ only in case or Unicode form:** a volume that ignores case also treats a letter written composed or decomposed as one name (é as one character, or as e plus its accent), and "ß", "ẞ", "SS" and "ss" as one. Such names are now refused together wherever a task's set of paths is checked: its documents at the start, a write during a turn, and the working copy when it is proposed. Nothing the earlier rule refused is let through.
- **Windows, groundwork:**
  - The Codex download is checked and kept private by the folder's owner and access list, since Windows has no POSIX modes. It lives under `%LOCALAPPDATA%\sagebrush-agent`.
  - The processes this agent starts run in a Windows job object, so stopping them also ends anything they started, including processes whose parent has already gone.
  - A runner on Windows can stop the running turns with a control line, since it can't send a signal there.
  - A few file paths are now built in a way that works on Windows.
  - Delegate stays off on Windows in this version, and says why.
- **Tests (pending Windows confirmation):** the suite is made to run on Windows. The rows that can't apply there (Delegate, POSIX modes, signals) are declared skips with their reasons, never silent passes.

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
