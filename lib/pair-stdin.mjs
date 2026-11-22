// `sagebrush-agent --pair-stdin --origin http://127.0.0.1:<port> --port 0`: the desktop app's launch (design/app-agent-host.md
// §5). The app, not the agent, makes the one-time pairing code, and hands it over the child's stdin, the first line:
//
//   {"v":1,"pair":"<base64url, no padding, of 32 random bytes>"}\n
//
// The agent prints no link and no code. It then writes exactly one line to stdout, {"v":1,"listening":<port>}\n, before
// anything else. After the first line stdin stays open as the liveness pipe: its end means the app is gone, and the
// agent stops (its task cleanup, as on SIGTERM); any further byte on it is a broken launch, and stops it too.
//
// Bounds: the first line is at most PAIR_LINE_MAX bytes, and must come within PAIR_WAIT_MS; anything else (a longer or
// malformed line, other keys, bytes after the newline in the same read, the end of stdin first) refuses the launch,
// with a message that never contains what was read.

export const PAIR_LINE_MAX = 256;
export const PAIR_WAIT_MS = 15_000;
const CODE_FORM = /^[A-Za-z0-9_-]{43}$/; // (32 bytes in base64url without padding: 43 characters, the last one's low bits 0)

// The app page's exact origin: http://127.0.0.1:<port>, port 1-65535, written canonically (no localhost, no other host,
// no default-port form, no path), or null.
export function pairOrigin(s) {
  const m = /^http:\/\/127\.0\.0\.1:([1-9][0-9]{0,4})$/.exec(String(s));
  if (!m) return null;
  const port = Number(m[1]);
  if (port > 65535) return null;
  let u;
  try { u = new URL(s); } catch { return null; }
  return u.origin === s && u.port === m[1] ? s : null;
}

// The code in a first line (a Buffer, without its newline), or null.
export function parsePairLine(line) {
  if (!Buffer.isBuffer(line) || line.length > PAIR_LINE_MAX) return null;
  let msg;
  try { msg = JSON.parse(line.toString("utf8")); } catch { return null; }
  if (!msg || typeof msg !== "object" || Array.isArray(msg)) return null;
  const keys = Object.keys(msg).sort();
  if (keys.length !== 2 || keys[0] !== "pair" || keys[1] !== "v" || msg.v !== 1) return null;
  if (typeof msg.pair !== "string" || !CODE_FORM.test(msg.pair)) return null;
  const raw = Buffer.from(msg.pair, "base64url");
  if (raw.length !== 32 || raw.toString("base64url") !== msg.pair) return null; // (canonical: no stray low bits)
  return msg.pair;
}

// Read the first line from `stream` (process.stdin): resolves with the code, or rejects with a fixed message. Afterwards
// `onAfter` is called once, with "end" when the stream ends or "data" when anything more arrives, so the caller can stop.
export function readPairLine(stream, { waitMs = PAIR_WAIT_MS, onAfter = () => {} } = {}) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let length = 0;
    let state = "first"; // first | after | done
    const fail = (why) => {
      if (state !== "first") return;
      state = "done";
      clearTimeout(timer);
      chunks.length = 0;
      reject(new Error(why));
    };
    const timer = setTimeout(() => fail("no pairing line on stdin in time"), waitMs);
    const after = (why) => {
      if (state !== "after") return;
      state = "done";
      onAfter(why);
    };
    stream.on("data", (b) => {
      if (state === "after") return after("data");
      if (state !== "first") return;
      const nl = b.indexOf(10);
      if (nl === -1) {
        length += b.length;
        if (length > PAIR_LINE_MAX) return fail("the pairing line is too long");
        chunks.push(b);
        return;
      }
      if (length + nl > PAIR_LINE_MAX) return fail("the pairing line is too long");
      if (nl !== b.length - 1) return fail("input on stdin after the pairing line");
      chunks.push(b.subarray(0, nl));
      const line = Buffer.concat(chunks);
      chunks.length = 0;
      const code = parsePairLine(line);
      line.fill(0);
      if (!code) return fail("the pairing line is not a valid one");
      state = "after";
      clearTimeout(timer);
      resolve(code);
    });
    for (const e of ["end", "close"]) stream.on(e, () => { if (state === "first") fail("stdin ended before the pairing line"); else after("end"); });
    stream.on("error", () => { if (state === "first") fail("stdin failed before the pairing line"); else after("end"); });
  });
}
