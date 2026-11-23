// Fleet protocol, the browser relay (design agent-autonomous-browser-relay.md r2.1): the process. systemd starts it as
// user `relay` on the relay VM, behind Caddy, with one argument: its reviewed configuration file.
//   { "listen": { "host": "127.0.0.1", "port": 8788 }, "origin": "https://<the fleet Worker's origin>",
//     "keyFile": "/etc/sagebrush-relay/control.key", "dbPath": "/var/lib/sagebrush-relay/relay.sqlite", "caFile"?: "..." }
// The key file holds the relay-only control-plane key: 43 base64url characters (32 bytes, the core's controlKey());
// it's never printed or logged.
// Nothing comes from the environment.
//
//   node lib/fleet/relay/main.mjs /etc/sagebrush-relay/relay.json

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { performance } from "node:perf_hooks";
import { openStore } from "./store.mjs";
import { controlClient, httpsTransport } from "./control.mjs";
import { controlKey } from "../core/control.mjs";
import { Slots } from "./slots.mjs";
import { Feed } from "./feed.mjs";
import { createRelayServer } from "./service.mjs";

/** The real monotonic clock. */
export const REAL_CLOCK = Object.freeze({ now: () => performance.now(), setTimeout: (f, ms) => setTimeout(f, ms), clearTimeout: (h) => clearTimeout(h) });

const LISTEN_HOSTS = new Set(["127.0.0.1", "::1"]);

/** Read and check the configuration; throws with a fixed message (never a value from the file). */
export function readConfig(path) {
  let c;
  try { c = JSON.parse(readFileSync(path, "utf8")); } catch { throw new Error("the relay's configuration can't be read"); }
  const keys = Object.keys(c ?? {}).sort().join(",");
  if (keys !== "dbPath,keyFile,listen,origin" && keys !== "caFile,dbPath,keyFile,listen,origin") throw new Error("the relay's configuration has exactly its fields");
  if (!LISTEN_HOSTS.has(c.listen?.host) || !Number.isSafeInteger(c.listen?.port) || c.listen.port < 1024 || c.listen.port > 65535) throw new Error("the relay listens on loopback only");
  let text;
  try { text = readFileSync(c.keyFile, "utf8").trim(); } catch { throw new Error("the control-plane key can't be read"); }
  let key;
  try { key = controlKey(text); } catch { throw new Error("the control-plane key isn't 43 base64url characters"); }
  return { listen: c.listen, origin: c.origin, key, dbPath: c.dbPath, ca: c.caFile ? readFileSync(c.caFile) : undefined };
}

/** Start the relay from a checked configuration. Resolves { server, stop() }. */
export async function start(config, { log = (o) => console.log(JSON.stringify({ t: new Date().toISOString(), ...o })) } = {}) {
  const { WebSocketServer } = await import("ws"); // (only here: every other relay module loads with no dependency)
  const store = openStore(config.dbPath);
  const control = controlClient({ transport: httpsTransport({ origin: config.origin, ca: config.ca }), key: config.key });
  const slots = new Slots({ clock: REAL_CLOCK, log });
  const feed = new Feed({ control, store, slots, clock: REAL_CLOCK, log });
  const { server, prune } = createRelayServer({ control, store, slots, feed, clock: REAL_CLOCK, log, WebSocketServer });
  const pruning = setInterval(() => { try { prune(); } catch { log({ event: "prune_failed" }); } }, 60_000);
  feed.start();
  server.listen(config.listen.port, config.listen.host);
  return {
    server,
    stop() { clearInterval(pruning); feed.stop(); slots.closeAll(1001, "the relay is stopping"); server.close(); store.close(); },
  };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const relay = await start(readConfig(process.argv[2]));
  for (const sig of ["SIGTERM", "SIGINT"]) process.once(sig, () => { relay.stop(); setTimeout(() => process.exit(0), 2000).unref(); });
}
