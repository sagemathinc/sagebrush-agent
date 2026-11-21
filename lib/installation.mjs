// This installation's id: the scope a Delegate task's grant is bound to (design/workspace-agent-protocol.md §6.2),
// made once, kept in ~/.sagebrush/installation (private, 32 hex), and read without following a link.
import { randomBytes } from "node:crypto";
import { closeSync, constants, fsyncSync, mkdirSync, openSync, renameSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { readPlain, syncDir, writeAll } from "./task-git.mjs";
import { privateDirProblem } from "./task-paths.mjs";

const ID = /^[0-9a-f]{32}$/;

/** The id, made the first time; throws where ~/.sagebrush isn't private and ours, or the file isn't one of ours. */
export function installationId(home = homedir()) {
  const dir = join(home, ".sagebrush"), path = join(dir, "installation");
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const why = privateDirProblem(dir);
  if (why) throw new Error(`~/.sagebrush can't be used: ${why}`);
  try {
    const t = readPlain(path, 64).toString("utf8").trim();
    if (!ID.test(t)) throw new Error("~/.sagebrush/installation isn't an installation id");
    return t;
  } catch (e) {
    if (e?.code !== "ENOENT") throw e;
  }
  const id = randomBytes(16).toString("hex"), tmp = `${path}.${process.pid}.tmp`;
  const fd = openSync(tmp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0), 0o600);
  try { writeAll(fd, id + "\n"); fsyncSync(fd); } finally { closeSync(fd); }
  renameSync(tmp, path);
  syncDir(dir);
  return id;
}
