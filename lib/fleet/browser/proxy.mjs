// Fleet protocol, the browser lane (O11 §5, §6 layer 2): the net sidecar's local HTTP proxy, the one choke point for
// every connection Chrome makes. It listens on 127.0.0.1 only. For each client connection, one request (proxy-gate.mjs):
//   1. Hold the client's bytes until gateRequest() decides; a refusal gets its fixed answer and the connection closes.
//      Nothing is resolved or connected before the gate allows the request.
//   2. resolvePublic() (addresses.mjs): a literal or one lookup, refused whole if any answer isn't public.
//   3. Connect to the address that was checked (no second lookup). Resolving and connecting share one deadline,
//      LIMITS.upstreamMs: when it passes, the client gets 504 and the connection closes, whichever stage it was in, and
//      a lookup that settles later never connects.
//   4. A CONNECT gets "200 Connection Established" and becomes an opaque tunnel. An http request gets exactly the
//      gate's upstream bytes; the response streams back; any further client byte closes both sides.
// Every connection is bounded: the head and body within LIMITS.requestMs, resolve and connect within LIMITS.upstreamMs, then
// LIMITS.idleMs without traffic either way; at most LIMITS.connections at once (the next one is closed at once).
// Logs (§5): counts per outcome; host names only for refusals (the gate's account-origin entry, or the host refused as
// private). Never credentials, paths or bytes.

import { createServer, connect as tcpConnect } from "node:net";
import { promises as dns } from "node:dns";
import { gateRequest, refusalBytes } from "./proxy-gate.mjs";
import { resolvePublic } from "./addresses.mjs";

export const LIMITS = Object.freeze({ connections: 256, requestMs: 10000, upstreamMs: 10000, idleMs: 300000 });

const ESTABLISHED = Buffer.from("HTTP/1.1 200 Connection Established\r\n\r\n", "latin1");
const answer = (status, text) => Buffer.from(`HTTP/1.1 ${status} ${text}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n`, "latin1");
const BAD_GATEWAY = answer(502, "Bad Gateway");
const GATEWAY_TIMEOUT = answer(504, "Gateway Timeout");
const REQUEST_TIMEOUT = answer(408, "Request Timeout");

const defaultLookup = (host) => dns.lookup(host, { all: true, verbatim: true });

/**
 * The proxy for one session. `session`: { username, password, origins } (the gate's). Injectable for tests: `lookup`
 * (host -> [{ address, family }]), `connect` ({ host, port } -> net.Socket, like net.connect), `log(event)`, `limits`.
 * Returns { listen() -> Promise<port>, close() -> Promise, closeAll(), stats() }.
 */
export function createProxy({ session, lookup = defaultLookup, connect = tcpConnect, log = () => {}, limits = {} }) {
  const L = { ...LIMITS, ...limits };
  const sockets = new Set();
  const counts = { accepted: 0, busy: 0, tunnels: 0, requests: 0, refused: 0, timeouts: 0, upstreamFailed: 0, upstreamTimeouts: { resolve: 0, connect: 0 } };
  const track = (s) => { sockets.add(s); s.on("close", () => sockets.delete(s)); return s; };
  let open = 0;

  const server = createServer({ allowHalfOpen: false, pauseOnConnect: false }, (client) => {
    if (open >= L.connections) { counts.busy++; client.destroy(); return; }
    open++;
    counts.accepted++;
    track(client);
    client.on("close", () => { open--; });
    client.on("error", () => {});
    let buf = Buffer.alloc(0);
    let done = false; // (the gate has decided: no more of the client's bytes are read as a request)
    let upstream = null;
    const end = (bytes) => { done = true; if (bytes) client.end(bytes); else client.destroy(); setTimeout(() => client.destroy(), 1000).unref(); upstream?.destroy(); };
    const requestTimer = setTimeout(() => { counts.timeouts++; log({ event: "timeout", stage: "request" }); end(REQUEST_TIMEOUT); }, L.requestMs);
    requestTimer.unref();
    client.on("close", () => clearTimeout(requestTimer));

    const onData = async (chunk) => {
      if (done) return;
      buf = Buffer.concat([buf, chunk]);
      const r = gateRequest(buf, session);
      if (r.need) return;
      done = true;
      clearTimeout(requestTimer);
      client.off("data", onData);
      client.pause();
      if (!r.ok) {
        counts.refused++;
        log({ event: "refused", why: r.why, ...(r.origin ? { host: r.origin } : {}) });
        return end(refusalBytes(r.status));
      }
      const d = r.decision;
      // (one deadline from here until the upstream connects: the lookup and the connect both)
      let stage = "resolve", expired = false;
      const upstreamTimer = setTimeout(() => { expired = true; counts.upstreamFailed++; counts.upstreamTimeouts[stage]++; log({ event: "timeout", stage }); end(GATEWAY_TIMEOUT); }, L.upstreamMs);
      upstreamTimer.unref();
      client.on("close", () => clearTimeout(upstreamTimer));
      const where = await resolvePublic(d.host, lookup);
      if (expired || client.destroyed) return; // (a lookup that settles after the deadline never connects)
      stage = "connect";
      if (!where.ok) {
        counts.refused++;
        log({ event: "refused", why: where.why, ...(where.why === "private" ? { host: d.host } : {}) });
        clearTimeout(upstreamTimer);
        return end(where.why === "private" ? refusalBytes(403) : BAD_GATEWAY);
      }
      // (any client byte while connecting: refused, as the gate would)
      const early = () => { counts.refused++; log({ event: "refused", why: "more than one request" }); end(refusalBytes(400)); };
      client.once("data", early);
      client.resume();
      let up;
      try { up = connect({ host: where.address, port: d.port, family: where.family }); } catch { clearTimeout(upstreamTimer); counts.upstreamFailed++; return end(BAD_GATEWAY); }
      upstream = track(up);
      let connected = false;
      up.on("error", () => { clearTimeout(upstreamTimer); if (!client.destroyed) { counts.upstreamFailed++; end(connected ? null : BAD_GATEWAY); } });
      up.on("close", () => client.destroy());
      client.on("close", () => up.destroy());
      up.on("connect", () => {
        clearTimeout(upstreamTimer);
        if (expired) return up.destroy();
        connected = true;
        client.off("data", early);
        if (client.destroyed) return up.destroy();
        for (const s of [client, up]) s.setTimeout(L.idleMs, () => { counts.timeouts++; client.destroy(); up.destroy(); });
        if (d.framing.kind === "tunnel") {
          counts.tunnels++;
          client.write(ESTABLISHED);
          client.pipe(up);
          up.pipe(client);
        } else {
          counts.requests++;
          up.write(r.upstream);
          up.pipe(client);
          // (one request per connection: any further client byte closes both sides, and nothing more goes upstream)
          client.on("data", () => { counts.refused++; log({ event: "refused", why: "more than one request" }); client.destroy(); up.destroy(); });
        }
      });
    };
    client.on("data", onData);
  });

  return Object.freeze({
    /** Listen on 127.0.0.1 (port 0: any free port); resolves with the port. */
    listen(port = 0) {
      return new Promise((resolve, reject) => {
        server.once("error", reject);
        server.listen(port, "127.0.0.1", () => { server.off("error", reject); resolve(server.address().port); });
      });
    },
    /** Close every open connection at once (a session ending, or an exception removed). */
    closeAll() { for (const s of sockets) s.destroy(); },
    /** Stop listening and close everything. */
    close() { this.closeAll(); return new Promise((r) => server.close(() => r())); },
    stats() { return { ...counts, upstreamTimeouts: { ...counts.upstreamTimeouts }, open }; },
  });
}
