// A release file's bytes checked against the release's pin before the file is first run as root: the launcher
// (lib/fleet/host/launcher.sha256) and the backup binary (lib/fleet/host/backup.sha256). One check, shared.

import * as fs from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join } from "node:path";
import { refuse } from "../bytes.mjs";

const PIN_MAX = 4096;
const BIN_MAX = 256 * 1024 * 1024;

/**
 * `<release>/<rel>` against `<release>/<pinRel>`. Each file is lstat'd no-follow, a regular file of `rootUid` in a
 * directory of `rootUid` that only it may write; the binary exactly 0755, the pin not group- or world-writable; each
 * read through a no-follow handle proven to be the lstat'd object (dev, ino, size), bounded (the pin's bound before
 * any open). The pin is exactly one line, `<64 lowercase hex>  <name>`, an optional final newline. Anything else
 * refuses not_granted (`what` names the file in the reason). Returns nothing; refuses or returns.
 */
export function checkPinned(release, { rel, pinRel, name, what }, { rootUid = 0, fsx = fs } = {}) {
  const no = (why) => refuse("not_granted", `${what} isn't the release's pinned one (${why})`);
  const read = (r, exactMode, max) => {
    const p = join(release, r);
    let d, st;
    try { d = fsx.lstatSync(dirname(p)); st = fsx.lstatSync(p); } catch { no(`${r} is missing`); }
    if (!d.isDirectory() || d.uid !== rootUid || (d.mode & 0o022) !== 0) no(`${r}'s directory isn't root's alone`);
    if (!st.isFile() || st.uid !== rootUid || (exactMode !== null ? (st.mode & 0o7777) !== exactMode : (st.mode & 0o022) !== 0)) no(`${r} isn't root's with its mode`);
    if (st.size > max) no(`${r} is too large`);
    let fd;
    try { fd = fsx.openSync(p, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW); } catch { no(`${r} can't be opened`); }
    try {
      const f = fsx.fstatSync(fd);
      if (!f.isFile() || f.dev !== st.dev || f.ino !== st.ino || f.size !== st.size) no(`${r} was replaced while it was read`);
      const buf = Buffer.alloc(f.size);
      for (let off = 0; off < buf.length;) {
        const n = fsx.readSync(fd, buf, off, buf.length - off, off);
        if (n <= 0) no(`${r} was cut short while it was read`);
        off += n;
      }
      return buf;
    } finally { fsx.closeSync(fd); }
  };
  const esc = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const m = new RegExp(`^([0-9a-f]{64}) {2}${esc}\\n?$`).exec(read(pinRel, null, PIN_MAX).toString("utf8"));
  if (!m) no("the pin is malformed");
  const have = createHash("sha256").update(read(rel, 0o755, BIN_MAX)).digest("hex");
  if (have !== m[1]) no("its sha256 differs from the pin");
}

/**
 * A run function guarded by checkPinned: the check runs before the FIRST call (once per runner); a refusal holds for
 * every later call, so a file put right mid-command still isn't run. `run(...args)` is called only after a pass.
 */
export function pinnedOnce(check, run) {
  let checked = null; // (null: not yet; true: passed; an error: refused, for good)
  return (...args) => {
    if (checked === null) { try { check(); checked = true; } catch (e) { checked = e; } }
    if (checked !== true) throw checked;
    return run(...args);
  };
}
