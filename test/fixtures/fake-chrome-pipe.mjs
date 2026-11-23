// A fake Chrome for test/fleet-pipe.test.mjs: it speaks CDP on fds 3 (it reads) and 4 (it writes), as
// --remote-debugging-pipe does, NUL-delimited. argv[2] picks the behavior:
// - "echo": answers Browser.getVersion, answers every other command with { echo: method }, sends Test.event after each
//   reply, and exits on Browser.close;
// - "garbage": answers Browser.getVersion, then writes a message that isn't JSON;
// - "exit": exits at once, before answering anything.
import { Socket } from "node:net";

const mode = process.argv[2];
if (mode === "exit") process.exit(0);
// (sockets, not fs streams: a blocking fs read on fd 3 would keep process.exit waiting)
const input = new Socket({ fd: 3, readable: true, writable: false });
const output = new Socket({ fd: 4, readable: false, writable: true });
const out = (m) => output.write(JSON.stringify(m) + "\0");
let buf = Buffer.alloc(0);
input.on("data", (chunk) => {
  buf = Buffer.concat([buf, chunk]);
  for (let i; (i = buf.indexOf(0)) !== -1; ) {
    const msg = JSON.parse(buf.subarray(0, i).toString("utf8"));
    buf = buf.subarray(i + 1);
    if (msg.method === "Browser.getVersion") {
      out({ id: msg.id, result: { product: "HeadlessChrome/158.0.8127.36", protocolVersion: "1.3" } });
      if (mode === "garbage") output.write("{not json\0");
    } else if (msg.method === "Browser.close") {
      out({ id: msg.id, result: {} });
      output.end(() => process.exit(0));
    } else {
      out(msg.sessionId ? { id: msg.id, result: { echo: msg.method }, sessionId: msg.sessionId } : { id: msg.id, result: { echo: msg.method } });
      out({ method: "Test.event", params: { after: msg.id } });
    }
  }
});
